//! Duplicate trait and pattern detection.
//!
//! This module detects various types of duplicates and redundancies in trait definitions:
//!
//! - **Atomic trait duplicates**: Traits with identical search parameters (if, platforms, for, not, unless)
//! - **Composite rule duplicates**: Rules with identical condition sets
//! - **String pattern duplicates**: Same normalized pattern appearing in multiple files with overlapping file types
//! - **Regex overlaps**: Regex patterns with shared alternatives or substring matches overlapping with exact patterns
//! - **Type conflicts**: Same pattern appearing as different condition types (string vs symbol vs raw)
//! - **String/raw collisions**: Pattern appearing as both string and raw conditions with same criticality
//! - **For-only duplicates**: Traits identical except for the `for:` field, indicating mergeable rules
//! - **Atomic logic duplicates**: Traits with the same matcher but different metadata
//!   (crit/conf/platforms/unless/downgrade) — candidates for one trait with a downgrade
//! - **Alternation merge candidates**: Regex patterns differing only in first token case that could be combined

use super::shared::{MatchSignature, PatternLocation};
use crate::composite_rules::{
    Arch, CompositeTrait, Condition, DowngradeConditions, FileType as RuleFileType, KvQuery,
    Platform, TraitDefinition, condition::EncodingSpec, evaluators::build_regex,
};
use crate::composite_rules::{
    EncodedQuery, LiteralQuery, PathQuery, RawQuery, SectionQuery, SymbolQuery, TextQuery,
    TreeSitterQuery,
};
use crate::types::Criticality;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{BTreeMap, HashMap, HashSet};

mod logic_duplicates;
#[allow(clippy::wildcard_imports)]
pub(crate) use logic_duplicates::*;

mod regex_overlap;
#[allow(clippy::wildcard_imports)]
pub(crate) use regex_overlap::*;

mod string_overlap;
#[allow(clippy::wildcard_imports)]
pub(crate) use string_overlap::*;

mod alternation;
#[allow(clippy::wildcard_imports)]
pub(crate) use alternation::*;

/// The tree caps a single trait at four platforms; a wider union is a
/// deliberate per-platform split, not a duplicate.
const MAX_TRAIT_PLATFORMS: usize = 4;

const RELAXED_DATA_TEXT_ALTERNATION_LIMIT: usize = 6;

fn is_micro_behavior_data_text_path(path: &str) -> bool {
    path.split(['/', '\\'])
        .collect::<Vec<_>>()
        .windows(3)
        .any(|parts| parts == ["micro-behaviors", "data", "text"])
}

/// Normalize criticality for overlap checking purposes.
/// `Component`, `Baseline`, and `Filtered` are all treated as equivalent "inert" levels
/// since they represent low-signal building blocks rather than meaningful findings.
fn criticality_for_overlap(crit: Criticality) -> Criticality {
    match crit {
        Criticality::Filtered | Criticality::Component | Criticality::Baseline => {
            Criticality::Baseline
        }
        other => other,
    }
}

/// Check if two criticalities are equivalent for overlap purposes.
/// Component, Baseline, and Filtered are all treated as the same level.
pub(crate) fn criticalities_equivalent(a: Criticality, b: Criticality) -> bool {
    criticality_for_overlap(a) == criticality_for_overlap(b)
}

/// Combined: ~100-500x faster than original mutex-based implementation.
pub(crate) fn find_duplicate_traits_and_composites(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    warnings: &mut Vec<String>,
) {
    find_duplicate_atomic_traits(trait_definitions, warnings);
    find_duplicate_composite_rules(composite_rules, warnings);
}

pub(crate) fn find_duplicate_atomic_traits(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    use rayon::prelude::*;

    let start = std::time::Instant::now();

    if trait_definitions.is_empty() {
        return;
    }

    tracing::debug!(
        "Starting atomic trait duplicate detection for {} traits",
        trait_definitions.len()
    );
    let serialize_start = std::time::Instant::now();

    // Process in parallel chunks (no locks needed)
    let chunk_size = (trait_definitions.len() / rayon::current_num_threads()).max(1000);
    let trait_maps: Vec<HashMap<u64, Vec<String>>> = trait_definitions
        .par_chunks(chunk_size)
        .map(|chunk| {
            let mut local_map: HashMap<u64, Vec<String>> = HashMap::with_capacity(chunk.len());
            // An override has no predicate to duplicate.
            for t in chunk.iter().filter(|t| !t.is_override()) {
                // Share effective predicate normalization with scope-only checks.
                let signature = atomic_predicate_signature(t, true);
                use std::collections::hash_map::DefaultHasher;
                use std::hash::{Hash, Hasher};
                let mut hasher = DefaultHasher::new();
                signature.hash(&mut hasher);
                local_map
                    .entry(hasher.finish())
                    .or_default()
                    .push(t.id.clone());
            }
            local_map
        })
        .collect();

    tracing::debug!(
        "Atomic trait parallel hashing took {:?}",
        serialize_start.elapsed()
    );

    // Merge maps sequentially (fast since we have few chunks)
    let merge_start = std::time::Instant::now();
    let mut final_map: HashMap<u64, Vec<String>> = HashMap::new();
    for map in trait_maps {
        for (k, mut v) in map {
            final_map.entry(k).or_default().append(&mut v);
        }
    }
    tracing::debug!("Atomic trait merge took {:?}", merge_start.elapsed());

    let check_start = std::time::Instant::now();
    for (_hash, ids) in final_map {
        if ids.len() > 1 {
            warnings.push(format!(
                "Duplicate atomic traits detected (same search parameters): {}",
                ids.join(", ")
            ));
        }
    }
    tracing::debug!(
        "Atomic trait duplicate check took {:?}",
        check_start.elapsed()
    );
    tracing::debug!(
        "Total atomic trait processing took {:?}",
        serialize_start.elapsed()
    );
    tracing::debug!(
        "Total duplicate atomic detection took {:?}",
        start.elapsed()
    );
}

pub(crate) fn find_duplicate_composite_rules(
    composite_rules: &[CompositeTrait],
    warnings: &mut Vec<String>,
) {
    use rayon::prelude::*;

    let start = std::time::Instant::now();

    if composite_rules.is_empty() {
        return;
    }

    // OPTIMIZATION: Uses u64 hash as key (50x faster than Vec<u8> comparisons)
    tracing::debug!(
        "Starting composite rule duplicate detection for {} rules",
        composite_rules.len()
    );
    let composite_start = std::time::Instant::now();

    // Process in parallel chunks (no locks needed)
    let chunk_size = (composite_rules.len() / rayon::current_num_threads()).max(1000);
    let composite_maps: Vec<HashMap<u64, Vec<String>>> = composite_rules
        .par_chunks(chunk_size)
        .map(|chunk| {
            let mut local_map: HashMap<u64, Vec<String>> = HashMap::with_capacity(chunk.len());
            for r in chunk {
                // Skip rules with no conditions
                if r.all.is_none() && r.any.is_none() && r.unless.is_none() {
                    continue;
                }

                // Serialize the rule's unique characteristics
                if let Ok(serialized) = bincode::serde::encode_to_vec(
                    (
                        &r.all,
                        &r.any,
                        &r.unless,
                        &r.needs,
                        &r.r#for,
                        &r.platforms,
                        &r.size_min,
                        &r.size_max,
                    ),
                    bincode::config::standard(),
                ) {
                    // Hash the serialized data to get a u64 key
                    use std::collections::hash_map::DefaultHasher;
                    use std::hash::{Hash, Hasher};

                    let mut hasher = DefaultHasher::new();
                    serialized.hash(&mut hasher);
                    let hash_key = hasher.finish();

                    local_map.entry(hash_key).or_default().push(r.id.clone());
                }
            }
            local_map
        })
        .collect();

    tracing::debug!(
        "Composite rule parallel hashing took {:?}",
        composite_start.elapsed()
    );

    // Merge maps sequentially
    let merge_start = std::time::Instant::now();
    let mut final_map: HashMap<u64, Vec<String>> = HashMap::new();
    for map in composite_maps {
        for (k, mut v) in map {
            final_map.entry(k).or_default().append(&mut v);
        }
    }
    tracing::debug!("Composite rule merge took {:?}", merge_start.elapsed());

    let composite_check_start = std::time::Instant::now();
    for (_hash, ids) in final_map {
        if ids.len() > 1 {
            warnings.push(format!(
                "Duplicate composite rules detected (same conditions): {}",
                ids.join(", ")
            ));
        }
    }
    tracing::debug!(
        "Composite rule duplicate check took {:?}",
        composite_check_start.elapsed()
    );
    tracing::debug!(
        "Total composite rule processing took {:?}",
        composite_start.elapsed()
    );
    tracing::debug!(
        "Total duplicate composite detection took {:?}",
        start.elapsed()
    );
}

/// Extract a `(condition_type, match_type, normalized_value)` from a single
/// inline condition (as used inside `unless:` arrays). Returns `None` for
/// `Condition::Trait` (already an `- id:` reference) and for non-string
/// conditions (Section/Hex/Metrics/Syscall/Kv/Ast) that aren't reusable as a
/// shared string atom. Mirrors the per-variant extraction in
/// [`extract_patterns`].
fn inline_condition_value(cond: &Condition) -> Option<(&'static str, &'static str, String)> {
    let (ct, mt, raw): (&'static str, &'static str, &String) = match cond {
        Condition::Symbol(SymbolQuery { exact: Some(v), .. }) => ("symbol", "exact", v),
        Condition::Symbol(SymbolQuery {
            substr: Some(v), ..
        }) => ("symbol", "substr", v),
        Condition::Symbol(SymbolQuery { regex: Some(v), .. }) => ("symbol", "regex", v),
        Condition::Raw(RawQuery { exact: Some(v), .. }) => ("raw", "exact", v),
        Condition::Raw(RawQuery {
            substr: Some(v), ..
        }) => ("raw", "substr", v),
        Condition::Raw(RawQuery { word: Some(v), .. }) => ("raw", "word", v),
        Condition::Raw(RawQuery { regex: Some(v), .. }) => ("raw", "regex", v),
        Condition::Text(TextQuery { exact: Some(v), .. }) => ("text", "exact", v),
        Condition::Text(TextQuery {
            substr: Some(v), ..
        }) => ("text", "substr", v),
        Condition::Text(TextQuery { word: Some(v), .. }) => ("text", "word", v),
        Condition::Text(TextQuery { regex: Some(v), .. }) => ("text", "regex", v),
        Condition::Literal(LiteralQuery { exact: Some(v), .. }) => ("string_literal", "exact", v),
        Condition::Literal(LiteralQuery {
            substr: Some(v), ..
        }) => ("string_literal", "substr", v),
        Condition::Literal(LiteralQuery { word: Some(v), .. }) => ("string_literal", "word", v),
        Condition::Literal(LiteralQuery { regex: Some(v), .. }) => ("string_literal", "regex", v),
        Condition::Path(PathQuery { exact: Some(v), .. }) => ("basename", "exact", v),
        Condition::Path(PathQuery {
            substr: Some(v), ..
        }) => ("basename", "substr", v),
        Condition::Path(PathQuery { regex: Some(v), .. }) => ("basename", "regex", v),
        Condition::Encoded(EncodedQuery { exact: Some(v), .. }) => ("encoded", "exact", v),
        Condition::Encoded(EncodedQuery {
            substr: Some(v), ..
        }) => ("encoded", "substr", v),
        Condition::Encoded(EncodedQuery { word: Some(v), .. }) => ("encoded", "word", v),
        Condition::Encoded(EncodedQuery { regex: Some(v), .. }) => ("encoded", "regex", v),
        _ => return None,
    };
    let normalized = normalize_pattern_for_comparison(raw, mt == "regex");
    // Skip very-short / low-signal values — they're rarely worth a shared atom
    // and would be noisy to flag.
    if normalized.chars().filter(|c| c.is_alphanumeric()).count() < 3 {
        return None;
    }
    Some((ct, mt, normalized))
}

/// Whole-file content matchers: kinds whose pattern is compared against the
/// file's own content, so the same literal means the same thing regardless of
/// which rule holds it. Positional variants (`section:`, `offset:`, …) are
/// excluded by [`content_condition_is_positional`], since a pattern pinned to a
/// section is not equivalent to the same pattern searched file-wide.
const CONTENT_MATCHER_KINDS: &[&str] = &["text", "raw", "string_literal", "encoded"];

/// True when a content condition is pinned to a section or offset, making its
/// pattern non-equivalent to the same pattern matched across the whole file.
fn content_condition_is_positional(cond: &Condition) -> bool {
    macro_rules! positional {
        ($q:expr) => {
            $q.section.is_some()
                || $q.offset.is_some()
                || $q.offset_range.is_some()
                || $q.section_offset.is_some()
                || $q.section_offset_range.is_some()
        };
    }
    match cond {
        Condition::Text(q) => positional!(q),
        Condition::Raw(q) => positional!(q),
        Condition::Literal(q) => positional!(q),
        Condition::Encoded(q) => positional!(q),
        _ => false,
    }
}

/// Inline conditions in `unless:`/`downgrade:` that duplicate a whole-file
/// content matcher which already exists — either as a named atomic trait, or as
/// the same inline repeated in another file.
///
/// An inline content matcher is invisible to every other duplicate check, so a
/// literal can be spelled once as a named trait and again inline in a
/// suppression, and nothing notices the two must move together. Both shapes are
/// reported:
///
/// - **duplicates a named trait** — reference it by `- id:` instead. This needs
///   no repetition threshold: one inline copy of an existing trait is already a
///   drift hazard, and it hides the relationship from anyone reading either side.
/// - **repeated inline in two or more files** — promote it to a named trait in
///   the directory that describes what it finds, then reference that.
///
/// `not:` is out of scope: it negates against the host matcher's *matched span*
/// rather than the file, so an identical literal there is not the same
/// assertion. `metrics:`/`value:` are also out of scope — a threshold or a
/// structured field lookup carries its meaning locally.
///
/// Returns `(owner_rule_id, clause, description, advice)`.
#[must_use]
pub(crate) fn find_inline_content_duplicates(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, &'static str, String, String)> {
    // Signature -> the named trait that already owns this matcher, plus the
    // file types it applies to. Suggesting a reference is only sound when the
    // owner's `for:` covers the consumer's: referencing a `for: [powershell]`
    // trait from a JavaScript rule silently switches the exclusion off.
    let mut named: HashMap<(&'static str, &'static str, String), (String, Vec<RuleFileType>)> =
        HashMap::new();
    for t in trait_definitions {
        if content_condition_is_positional(&t.r#if) {
            continue;
        }
        if let Some(sig) = inline_condition_value(&t.r#if)
            && CONTENT_MATCHER_KINDS.contains(&sig.0)
        {
            named
                .entry(sig)
                .or_insert_with(|| (t.id.clone(), t.r#for.clone()));
        }
    }

    // Collect every inline occurrence, keyed by signature.
    type Occurrence = (String, &'static str, String, Vec<RuleFileType>);
    let mut seen: HashMap<(&'static str, &'static str, String), Vec<Occurrence>> = HashMap::new();
    let collect = |id: &str,
                   file: &std::path::Path,
                   clause: &'static str,
                   for_types: &[RuleFileType],
                   conds: &[Condition],
                   seen: &mut HashMap<_, Vec<Occurrence>>| {
        for cond in conds {
            if content_condition_is_positional(cond) {
                continue;
            }
            if let Some(sig) = inline_condition_value(cond)
                && CONTENT_MATCHER_KINDS.contains(&sig.0)
            {
                seen.entry(sig).or_default().push((
                    id.to_string(),
                    clause,
                    file.to_string_lossy().to_string(),
                    for_types.to_vec(),
                ));
            }
        }
    };
    for t in trait_definitions {
        if let Some(u) = &t.unless {
            collect(&t.id, &t.defined_in, "unless", &t.r#for, u, &mut seen);
        }
        if let Some(d) = &t.downgrade {
            for (clause, set) in [("downgrade", &d.any), ("downgrade", &d.all)] {
                if let Some(c) = set {
                    collect(&t.id, &t.defined_in, clause, &t.r#for, c, &mut seen);
                }
            }
        }
    }
    for r in composite_rules {
        if let Some(u) = &r.unless {
            collect(&r.id, &r.defined_in, "unless", &r.r#for, u, &mut seen);
        }
        if let Some(d) = &r.downgrade {
            for (clause, set) in [("downgrade", &d.any), ("downgrade", &d.all)] {
                if let Some(c) = set {
                    collect(&r.id, &r.defined_in, clause, &r.r#for, c, &mut seen);
                }
            }
        }
    }

    let mut out = Vec::new();
    for (sig, occurrences) in seen {
        let (kind, matcher, value) = &sig;
        let shown: String = value.chars().take(60).collect();
        // An owner only helps when its `for:` covers the consumer's. An empty
        // `for:` means every type, so it covers anything.
        let covered_by = |owner_for: &[RuleFileType], user_for: &[RuleFileType]| {
            owner_for.is_empty() || user_for.iter().all(|f| owner_for.contains(f))
        };
        let mut unreferenceable = Vec::new();
        if let Some((owner, owner_for)) = named.get(&sig) {
            for (id, clause, file, user_for) in &occurrences {
                if id == owner {
                    continue; // a trait may legitimately restate its own matcher
                }
                if !covered_by(owner_for, user_for) {
                    // Same matcher, incompatible scope — referencing it would
                    // quietly drop the exclusion for the types it omits.
                    unreferenceable.push((id.clone(), *clause, file.clone(), user_for.clone()));
                    continue;
                }
                out.push((
                    id.clone(),
                    *clause,
                    format!("inline {kind} {matcher}: {shown:?}"),
                    format!("already defined as '{owner}' — reference it with `- id: {owner}`"),
                ));
            }
            for (id, clause, _file, _) in &unreferenceable {
                out.push((
                    id.clone(),
                    *clause,
                    format!("inline {kind} {matcher}: {shown:?}"),
                    format!(
                        "'{owner}' has the same matcher but its `for:` does not cover this rule —                          promote a scope-neutral trait rather than referencing it"
                    ),
                ));
            }
            continue;
        }
        let files: std::collections::BTreeSet<&String> =
            occurrences.iter().map(|(_, _, f, _)| f).collect();
        if files.len() >= 2 {
            for (id, clause, _file, _) in &occurrences {
                out.push((
                    id.clone(),
                    *clause,
                    format!("inline {kind} {matcher}: {shown:?}"),
                    format!(
                        "the same inline matcher appears in {} files — promote it to a named trait and reference that",
                        files.len()
                    ),
                ));
            }
        }
    }
    out.sort();
    out
}

/// Detect the same inline `unless:` exclusion condition repeated across many
/// files. Inline conditions inside `unless:` arrays are not atomic traits, so
/// neither [`find_duplicate_atomic_traits`] nor [`find_string_pattern_duplicates`]
/// sees them — a copy-pasted exclusion can therefore proliferate and silently
/// drift (fix it in one file, miss the rest). When the same
/// `(type, match, value)` appears inline in at least
/// `INLINE_EXCLUSION_FILE_THRESHOLD` distinct files it should be a single shared
/// atom referenced by `- id:` (or deleted, if the matched file type is never
/// processed). `not:`/`NotException` is intentionally out of scope.
pub(crate) fn find_duplicate_inline_exclusions(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    warnings: &mut Vec<String>,
) {
    use std::collections::BTreeSet;
    const INLINE_EXCLUSION_FILE_THRESHOLD: usize = 4;

    // key ("type|match|value") -> (human-readable display, distinct source files)
    let mut index: HashMap<String, (String, BTreeSet<String>)> = HashMap::new();

    let mut record = |unless: &Option<Vec<Condition>>, file: &std::path::Path| {
        let Some(conds) = unless else { return };
        for cond in conds {
            if let Some((ct, mt, val)) = inline_condition_value(cond) {
                let key = format!("{ct}|{mt}|{val}");
                index
                    .entry(key)
                    .or_insert_with(|| (format!("{ct} {mt}: {val}"), BTreeSet::new()))
                    .1
                    .insert(file.to_string_lossy().to_string());
            }
        }
    };

    for t in trait_definitions {
        record(&t.unless, &t.defined_in);
    }
    for r in composite_rules {
        record(&r.unless, &r.defined_in);
    }

    let mut flagged: Vec<&(String, BTreeSet<String>)> = index
        .values()
        .filter(|(_, files)| files.len() >= INLINE_EXCLUSION_FILE_THRESHOLD)
        .collect();
    flagged.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));

    for (display, files) in flagged {
        let sample: Vec<&str> = files.iter().take(5).map(String::as_str).collect();
        let more = files.len().saturating_sub(sample.len());
        let suffix = if more > 0 {
            format!("\n   (+{more} more)")
        } else {
            String::new()
        };
        warnings.push(format!(
            "Inline unless: exclusion '{}' is duplicated across {} files:\n   {}{}\n   → Action: define one shared atom (e.g. under metadata/file/extension/) and reference it via `- id:` in each unless block — or delete the guard if the matched file type is never processed (e.g. unknown extensions cleave skips).",
            display,
            files.len(),
            sample.join("\n   "),
            suffix,
        ));
    }
}

fn canonical_encoding_scope(encoding: &Option<EncodingSpec>) -> Option<Vec<String>> {
    match encoding {
        None => None,
        Some(EncodingSpec::Single(enc)) => Some(vec![enc.to_ascii_lowercase()]),
        Some(EncodingSpec::Multiple(encodings)) => {
            let mut values: Vec<String> =
                encodings.iter().map(|e| e.to_ascii_lowercase()).collect();
            values.sort();
            values.dedup();
            Some(values)
        }
    }
}

fn is_non_reusable_atom(condition_type: &str, match_type: &str, normalized: &str) -> bool {
    if match_type != "regex" {
        return false;
    }

    // Match-all regexes are often used as carriers for size, density, or parser
    // metrics. They are not meaningful reusable atoms and sharing them would
    // erase the actual technique signal.
    matches!(condition_type, "basename" | "encoded") && matches!(normalized, "." | ".*")
}

fn matcher_context_reusable_as_is(a: &PatternLocation, b: &PatternLocation) -> bool {
    if a.condition_type != b.condition_type || a.match_type != b.match_type {
        return false;
    }
    if !section_scope_equivalent(a.section.as_deref(), b.section.as_deref()) {
        return false;
    }
    if a.condition_type != "encoded" {
        return true;
    }
    a.encoding == b.encoding
}

fn section_scope_equivalent(a: Option<&str>, b: Option<&str>) -> bool {
    match (a, b) {
        (None, None) => true,
        (None, Some(_)) | (Some(_), None) => false,
        (Some(a), Some(b)) => {
            let a = canonical_section_scope(a);
            let b = canonical_section_scope(b);
            a == b || (is_rodata_scope(&a) && is_rodata_scope(&b))
        }
    }
}

fn canonical_section_scope(section: &str) -> String {
    let section = section.trim().to_ascii_lowercase();
    match section.trim_start_matches('.') {
        "text" | "__text,__text" => "text",
        "data" | "__data,__data" => "data",
        "rdata" | "rodata" | "__text,__const" | "__data,__const" => "rdata",
        "rsrc" => "rsrc",
        other => other,
    }
    .to_string()
}

fn is_rodata_scope(section: &str) -> bool {
    section == "rdata"
}

fn condition_label(location: &PatternLocation) -> String {
    if location.condition_type == "encoded"
        && let Some(encodings) = &location.encoding
    {
        return format!("encoded[{}]", encodings.join("|"));
    }
    location.condition_type.clone()
}

/// Check if two pattern locations have overlapping file type coverage
///
/// Handles:
/// - Empty sets (no restrictions) = overlaps with everything
/// - "all" in either set = overlaps with everything
/// - Regular intersection check for specific file types
fn has_filetype_overlap(loc_a: &PatternLocation, loc_b: &PatternLocation) -> bool {
    has_filetype_overlap_case(&loc_a.for_types, &loc_b.for_types)
}

fn has_same_count_density_filters(loc_a: &PatternLocation, loc_b: &PatternLocation) -> bool {
    normalized_count_min(loc_a.count_min) == normalized_count_min(loc_b.count_min)
        && loc_a.count_max == loc_b.count_max
        && loc_a.per_kb_min == loc_b.per_kb_min
        && loc_a.per_kb_max == loc_b.per_kb_max
}

/// Detect duplicate string patterns across trait files
/// Only detects exact matches of normalized patterns (regex anchors stripped)
/// Checks string, symbol, and raw condition types (not encoded)
pub(crate) fn find_string_pattern_duplicates(
    patterns: &ExtractedPatterns,
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();

    // Build index: normalized_pattern -> Vec<PatternLocation>
    let mut pattern_index: HashMap<&str, Vec<&PatternLocation>> = HashMap::new();

    for (normalized, location) in &patterns.0 {
        pattern_index.entry(normalized).or_default().push(location);
    }

    // Find duplicates: same normalized pattern in multiple files with overlapping file types
    let total_patterns = pattern_index.len();
    let initial_warning_count = warnings.len();

    for (normalized_pattern, locations) in pattern_index {
        if locations.len() <= 1 {
            continue;
        }

        // Group by file
        let mut by_file: HashMap<String, Vec<&PatternLocation>> = HashMap::new();
        for loc in &locations {
            by_file.entry(loc.file_path.clone()).or_default().push(loc);
        }

        // Only warn about cross-file duplicates
        if by_file.len() <= 1 {
            continue;
        }

        // Check if any pair has overlapping file type coverage for the same matcher
        // kind. Cross-type duplicates are handled by the cross-type validator.
        let mut has_overlap = false;
        'outer: for i in 0..locations.len() {
            for j in (i + 1)..locations.len() {
                if locations[i].file_path != locations[j].file_path
                    && matcher_context_reusable_as_is(locations[i], locations[j])
                    && has_same_count_density_filters(locations[i], locations[j])
                    && has_filetype_overlap(locations[i], locations[j])
                {
                    has_overlap = true;
                    break 'outer;
                }
            }
        }

        if !has_overlap {
            continue;
        }

        // Check carveout: if all pairs differ by >2 chars AND (conf differs by >=0.2 OR crit differs)
        let mut all_pairs_meet_carveout = true;
        let mut checked_any_pair = false;
        'carveout_check: for i in 0..locations.len() {
            for j in (i + 1)..locations.len() {
                let loc_a = &locations[i];
                let loc_b = &locations[j];

                // Skip same file (already filtered above, but double-check)
                if loc_a.file_path == loc_b.file_path {
                    continue;
                }
                if !matcher_context_reusable_as_is(loc_a, loc_b)
                    || !has_same_count_density_filters(loc_a, loc_b)
                {
                    continue;
                }

                checked_any_pair = true;

                // Check if patterns differ by >2 characters
                let len_diff =
                    (loc_a.original_value.len() as i32 - loc_b.original_value.len() as i32).abs();
                let patterns_differ = len_diff > 2;

                // Check if confidence differs by >=0.2 OR criticality differs
                // Note: Component/Baseline/Filtered are treated as equivalent "inert" levels
                let conf_diff = (loc_a.confidence - loc_b.confidence).abs();
                let conf_or_crit_differs = conf_diff >= 0.2
                    || !criticalities_equivalent(loc_a.criticality, loc_b.criticality);

                // If this pair doesn't meet carveout criteria, bail out
                if !(patterns_differ && conf_or_crit_differs) {
                    all_pairs_meet_carveout = false;
                    break 'carveout_check;
                }
            }
        }

        // If we didn't check any pairs (shouldn't happen), don't apply carveout
        if !checked_any_pair {
            all_pairs_meet_carveout = false;
        }

        // If all pairs meet carveout criteria, log at INFO and skip warning
        if all_pairs_meet_carveout {
            let location_details: Vec<String> = locations
                .iter()
                .map(|l| {
                    let for_str = if l.for_types.is_empty() {
                        "all types".to_string()
                    } else {
                        let mut types: Vec<_> = l.for_types.iter().cloned().collect();
                        types.sort();
                        format!("[{}]", types.join(", "))
                    };
                    format!(
                        "   {}: {} ({} {}: '{}', for: {}, conf: {:.2}, crit: {:?})",
                        l.file_path,
                        l.trait_id,
                        condition_label(l),
                        l.match_type,
                        l.original_value,
                        for_str,
                        l.confidence,
                        l.criticality
                    )
                })
                .collect();

            tracing::info!(
                "Duplicate pattern '{}' allowed due to carveout (>2 char diff + conf/crit differs):\n{}",
                normalized_pattern,
                location_details.join("\n")
            );
            continue;
        }

        // Check for tier violations (objectives duplicating micro-behaviors)
        use super::helpers::extract_tier;

        let mut reusable_ids: Vec<String> = Vec::new();
        let mut higher_tier_ids: Vec<String> = Vec::new();
        let mut tiers: Vec<&str> = Vec::new();

        for loc in &locations {
            if let Some(tier) = extract_tier(&loc.trait_id) {
                tiers.push(tier);
                match tier {
                    "metadata" | "micro-behaviors" => {
                        reusable_ids.push(loc.trait_id.clone());
                    }
                    "objectives" | "well-known" => {
                        higher_tier_ids.push(loc.trait_id.clone());
                    }
                    _ => {}
                }
            }
        }
        reusable_ids.sort();
        reusable_ids.dedup();
        higher_tier_ids.sort();
        higher_tier_ids.dedup();
        tiers.sort();
        tiers.dedup();

        // Format warning message
        let location_details: Vec<String> = locations
            .iter()
            .map(|l| {
                let for_str = if l.for_types.is_empty() {
                    "all types".to_string()
                } else {
                    let mut types: Vec<_> = l.for_types.iter().cloned().collect();
                    types.sort();
                    format!("[{}]", types.join(", "))
                };
                format!(
                    "   {}: {} ({} {}: '{}', for: {})",
                    l.file_path,
                    l.trait_id,
                    condition_label(l),
                    l.match_type,
                    l.original_value,
                    for_str
                )
            })
            .collect();

        let action = if !reusable_ids.is_empty() && !higher_tier_ids.is_empty() {
            format!(
                "Reference reusable atom(s) [{}] from higher-tier traits [{}] instead of repeating the same atom.",
                reusable_ids.join(", "),
                higher_tier_ids.join(", ")
            )
        } else if reusable_ids.is_empty()
            && tiers
                .iter()
                .any(|tier| matches!(*tier, "objectives" | "well-known"))
        {
            "Move the shared atom to the lowest accurate reusable tier (metadata/ or micro-behaviors/) and reference it from each higher-tier trait.".to_string()
        } else {
            "Keep one atom in the best taxonomy location and reference it from the other traits."
                .to_string()
        };

        warnings.push(format!(
            "Duplicate reusable atom '{}' appears in {} files with overlapping file type coverage:\n{}\n   → Action: {}",
            normalized_pattern,
            by_file.len(),
            location_details.join("\n"),
            action
        ));
    }

    let duplicates_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "String pattern duplicate detection completed in {:?} ({} patterns checked, {} duplicates found)",
        start.elapsed(),
        total_patterns,
        duplicates_found
    );
}

/// Validate that regex traits don't overlap with existing substr/exact matches
///
/// Reports ambiguous cases where the same pattern could be detected by multiple traits
/// with the same criticality level and overlapping file types. This indicates redundancy
/// where one trait should be removed to avoid confusion and duplicate detections.
///
/// The solution is to remove one of the conflicting traits - typically the regex version
/// should be removed in favor of the simpler substr/exact match, unless the regex
/// provides additional matching capabilities.
#[cfg(test)]
pub(crate) fn validate_regex_overlap_with_literal(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    use crate::types::Criticality;

    // Build a map of literal (exact/substr) patterns with their context
    let mut literal_patterns: Vec<(String, String, String, Criticality, Vec<RuleFileType>)> =
        Vec::new();

    for t in trait_definitions {
        match &t.r#if {
            Condition::Symbol(SymbolQuery { exact: Some(s), .. })
            | Condition::Raw(RawQuery { exact: Some(s), .. })
            | Condition::Text(TextQuery { exact: Some(s), .. })
            | Condition::Literal(LiteralQuery { exact: Some(s), .. })
            | Condition::Path(PathQuery { exact: Some(s), .. })
            | Condition::Encoded(EncodedQuery { exact: Some(s), .. }) => {
                literal_patterns.push((
                    s.clone(),
                    "exact".to_string(),
                    t.id.clone(),
                    t.crit,
                    t.r#for.clone(),
                ));
            }
            Condition::Symbol(SymbolQuery {
                substr: Some(s), ..
            })
            | Condition::Raw(RawQuery {
                substr: Some(s), ..
            })
            | Condition::Text(TextQuery {
                substr: Some(s), ..
            })
            | Condition::Literal(LiteralQuery {
                substr: Some(s), ..
            })
            | Condition::Path(PathQuery {
                substr: Some(s), ..
            })
            | Condition::Encoded(EncodedQuery {
                substr: Some(s), ..
            }) => {
                literal_patterns.push((
                    s.clone(),
                    "substr".to_string(),
                    t.id.clone(),
                    t.crit,
                    t.r#for.clone(),
                ));
            }
            _ => {}
        }
    }

    // Check regex patterns against literal patterns
    for t in trait_definitions {
        let regex_pattern = match &t.r#if {
            Condition::Symbol(SymbolQuery { regex: Some(r), .. })
            | Condition::Raw(RawQuery { regex: Some(r), .. })
            | Condition::Text(TextQuery { regex: Some(r), .. })
            | Condition::Literal(LiteralQuery { regex: Some(r), .. })
            | Condition::Path(PathQuery { regex: Some(r), .. })
            | Condition::Encoded(EncodedQuery { regex: Some(r), .. }) => Some(r),
            _ => None,
        };

        if let Some(regex) = regex_pattern {
            for (literal, match_type, literal_id, literal_crit, literal_types) in &literal_patterns
            {
                // Check if criticality matches
                // Note: Component/Baseline/Filtered are treated as equivalent "inert" levels
                if !criticalities_equivalent(t.crit, *literal_crit) {
                    continue;
                }

                // Check if file types overlap
                if !file_types_overlap(&t.r#for, literal_types) {
                    continue;
                }

                // Check if regex could match the literal
                if regex_could_match_literal(regex, literal) {
                    // Allow overlaps when patterns differ significantly in length (>33%)
                    // AND regex has no alternation (|) AND literal is not a prefix/suffix
                    // of the regex. This permits different specificity levels like ".exe"
                    // vs "7z.exe" while catching true duplicates like "foo" vs "foo.*".
                    let max_len = regex.len().max(literal.len());
                    let len_diff_pct = if max_len > 0 {
                        (regex.len() as f32 - literal.len() as f32).abs() / max_len as f32
                    } else {
                        0.0
                    };
                    let has_alternation = regex.contains('|');

                    // Check if literal appears in the regex with only metacharacters as prefix/suffix
                    // "foo" vs "foo.*" -> block (literal + metacharacters)
                    // ".exe" vs ".*\.exe" -> block (metacharacters + escaped literal)
                    // ".exe" vs "7z\.exe" -> allow (actual content + escaped literal)
                    let escaped_literal = regex::escape(literal);
                    let is_trivial_extension = if regex.starts_with(&escaped_literal) {
                        // Literal is a prefix - check if remainder is just metacharacters/anchors
                        let remainder = &regex[escaped_literal.len()..];
                        remainder
                            .chars()
                            .all(|c| matches!(c, '.' | '*' | '+' | '?' | '$' | '^' | '\\'))
                    } else if regex.ends_with(&escaped_literal) {
                        // Literal is a suffix - check if prefix is just metacharacters/anchors
                        let prefix = &regex[..regex.len() - escaped_literal.len()];
                        prefix
                            .chars()
                            .all(|c| matches!(c, '.' | '*' | '+' | '?' | '$' | '^' | '\\'))
                    } else if regex.contains(&escaped_literal) {
                        // Literal appears in the middle - check if surrounding chars are metacharacters
                        if let Some(idx) = regex.find(&escaped_literal) {
                            let before = &regex[..idx];
                            let after = &regex[idx + escaped_literal.len()..];
                            before
                                .chars()
                                .all(|c| matches!(c, '.' | '*' | '+' | '?' | '$' | '^' | '\\'))
                                && after
                                    .chars()
                                    .all(|c| matches!(c, '.' | '*' | '+' | '?' | '$' | '^' | '\\'))
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    // Skip if significantly different length, no alternation, AND not a trivial extension
                    if len_diff_pct > 0.33 && !has_alternation && !is_trivial_extension {
                        continue;
                    }

                    warnings.push(format!(
                        "Ambiguous regex overlap: trait '{}' (regex: '{}') could match same pattern as '{}' ({}: '{}'). Consider removing one.",
                        t.id, regex, literal_id, match_type, literal
                    ));
                }
            }
        }
    }
}

/// Find traits where both `type: text` and `type: raw` exist for the same pattern.
/// These should be merged to just `raw` (which is broader). The matcher signatures
/// are byte-identical here (literally the same string), so criticality is NOT part
/// of the key — a `text`/`raw` twin is a duplicate regardless of criticality.
/// Returns: Vec<(string_trait_id, raw_trait_id, pattern_description)>
#[must_use]
pub(crate) fn find_string_content_collisions(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, String, String)> {
    let mut collisions = Vec::new();

    // Group traits by (signature, for, platforms). Criticality is intentionally
    // excluded: identical matchers are duplicates regardless of crit.
    // Key: (signature, for, platforms) -> Vec<(trait_id, is_string_type)>
    type SignatureGroup = HashMap<(MatchSignature, String, String), Vec<(String, bool)>>;
    let mut groups: SignatureGroup = HashMap::new();

    for t in trait_definitions {
        if let Some((is_string, sig)) = extract_match_signature(&t.r#if) {
            let for_key = format!("{:?}", t.r#for);
            let platforms_key = format!("{:?}", t.platforms);
            let key = (sig, for_key, platforms_key);

            groups
                .entry(key)
                .or_default()
                .push((t.id.clone(), is_string));
        }
    }

    // Find groups with both string and content types
    for ((sig, _for, _platforms), traits) in groups {
        let string_traits: Vec<_> = traits.iter().filter(|(_, is_str)| *is_str).collect();
        let content_traits: Vec<_> = traits.iter().filter(|(_, is_str)| !*is_str).collect();

        if !string_traits.is_empty() && !content_traits.is_empty() {
            // Describe the pattern for the warning
            let pattern_desc = if let Some(ref s) = sig.exact {
                format!("exact: \"{}\"", s)
            } else if let Some(ref s) = sig.substr {
                format!("substr: \"{}\"", s)
            } else if let Some(ref s) = sig.regex {
                format!("regex: \"{}\"", s)
            } else if let Some(ref s) = sig.word {
                format!("word: \"{}\"", s)
            } else {
                "unknown pattern".to_string()
            };

            for (string_id, _) in &string_traits {
                for (content_id, _) in &content_traits {
                    collisions.push((string_id.clone(), content_id.clone(), pattern_desc.clone()));
                }
            }
        }
    }

    collisions
}

/// Find traits that are identical except for the `for:` field.
/// These should be merged into a single trait with combined file types.
/// Returns: Vec<(trait_ids, shared_pattern_description)>
#[must_use]
pub(crate) fn find_for_only_duplicates(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(Vec<String>, String)> {
    let mut duplicates = Vec::new();

    // Create signature excluding `for:` field but including everything else
    // Key: (if, crit, conf, platforms, size_min, size_max, not, unless) -> Vec<(trait_id, for)>
    let mut groups: HashMap<String, Vec<(&TraitDefinition, Vec<RuleFileType>, Vec<Platform>)>> =
        HashMap::new();

    for t in trait_definitions {
        // Neither `for:` nor `platforms:` belongs in the key. Keying on
        // platforms meant only a `for:` difference could ever be reported, so
        // two traits identical but for their platform list stayed invisible --
        // the same blind spot `overlapping-scope-duplicate` closed for
        // composites.
        let signature = format!(
            "{}:{:?}:{}",
            atomic_predicate_signature(t, false),
            t.crit,
            t.conf.to_bits(),
        );
        groups
            .entry(signature)
            .or_default()
            .push((t, t.r#for.clone(), t.platforms.clone()));
    }

    // Report a group when its members differ in `for:`, in `platforms:`, or both.
    for (sig, traits) in groups {
        if traits.len() > 1 {
            let unique_fors: HashSet<String> = traits
                .iter()
                .map(|(_, f, _)| format!("{:?}", normalized_scope(f)))
                .collect();
            let unique_platforms: HashSet<String> = traits
                .iter()
                .map(|(_, _, p)| format!("{:?}", normalized_scope(p)))
                .collect();
            // A platform-only difference is only worth reporting when merging is
            // actually available: this tree separately caps a trait at four
            // platforms, so a union that would breach that cap is not a
            // duplicate to collapse but a deliberate per-platform split. A
            // File-type scopes are also subject to matcher-specific caps.
            let union_platforms: HashSet<String> = traits
                .iter()
                .flat_map(|(_, _, p)| p.iter().map(|x| format!("{x:?}")))
                .collect();
            let mergeable_platforms = union_platforms.len() < MAX_TRAIT_PLATFORMS;
            // Report only what can actually be merged. A group whose platform
            // union would breach the cap is a deliberate per-platform split --
            // reporting it would ask the author to trade one validation error
            // for another.
            let disjoint_fors = traits.iter().enumerate().all(|(i, (_, a, _))| {
                !a.is_empty()
                    && !a.contains(&RuleFileType::All)
                    && traits.iter().skip(i + 1).all(|(_, b, _)| {
                        !b.is_empty()
                            && !b.contains(&RuleFileType::All)
                            && !a.iter().any(|f| b.contains(f))
                    })
            });
            let mut merged = traits[0].0.clone();
            merged.r#for.clear();
            for (_, types, _) in &traits {
                for ty in types {
                    if !merged.r#for.contains(ty) {
                        merged.r#for.push(*ty);
                    }
                }
            }
            // A merge can be placed in any of the source files. Reuse the actual
            // file-type validator, including its source-specific exceptions.
            let mergeable_filetypes = traits.iter().any(|(t, _, _)| {
                merged.id.clone_from(&t.id);
                super::taxonomy::find_broad_filetype_traits(
                    std::slice::from_ref(&merged),
                    rule_source_files,
                )
                .is_empty()
            });
            if mergeable_platforms
                && (unique_fors.len() > 1 || unique_platforms.len() > 1)
                && (!disjoint_fors || mergeable_filetypes)
            {
                let trait_ids: Vec<String> =
                    traits.into_iter().map(|(t, _, _)| t.id.clone()).collect();

                // Extract a brief pattern description from the signature
                let pattern_desc = if sig.len() > 100 {
                    format!("{}...", &sig[..sig.floor_char_boundary(100)])
                } else {
                    sig
                };

                duplicates.push((trait_ids, pattern_desc));
            }
        }
    }

    duplicates
}

/// Whether a matcher is a bare field-existence gate — a `type: value` condition that
/// only navigates to a path with no value assertion, so it matches every file that has
/// that field (e.g. `value path: metadata-version` = "is a PKG-INFO file"). Traits that
/// share such a gate carry their real meaning in `unless:`, so differing criticality
/// across them (missing description = notable, missing author = component) is a
/// legitimate per-field severity, not an inconsistency.
fn is_existence_gate(cond: &Condition) -> bool {
    matches!(
        cond,
        Condition::Kv(kv)
            if kv.exact.is_none()
                && kv.substr.is_none()
                && kv.regex.is_none()
                && kv.eq.is_none()
                && kv.ne.is_none()
                && kv.length_min.is_none()
                && kv.length_max.is_none()
                && kv.exists != Some(false)
    )
}

/// Whether platform declarations cover each other. Coverage is directional:
/// Unix includes BSD, so Linux/macOS cannot stand in for the Unix umbrella.
/// An empty declaration, like All, imposes no platform restriction.
fn platforms_equivalent(a: &[Platform], b: &[Platform]) -> bool {
    let a_all = a.is_empty() || a.contains(&Platform::All);
    let b_all = b.is_empty() || b.contains(&Platform::All);
    if a_all || b_all {
        return a_all && b_all;
    }
    let covered_by = |xs: &[Platform], ys: &[Platform]| {
        xs.iter().all(|x| {
            ys.iter().any(|y| {
                x == y
                    || (*y == Platform::Unix && x.is_unix_family())
                    || (*y == Platform::Appliance && x.is_appliance_family())
            })
        })
    };
    covered_by(a, b) && covered_by(b, a)
}

/// True when two platform lists can both apply to the same file.
///
/// Mirrors the engine's `composite_rules::types::platforms_intersect`: an empty
/// list means "all platforms", and umbrella platforms match their family
/// members. Equality is the wrong test for duplicate detection — `[windows]`
/// and `[windows, unix]` never compare equal yet both fire on a PE.
fn platforms_overlap(a: &[Platform], b: &[Platform]) -> bool {
    if a.is_empty() || b.is_empty() {
        return true;
    }
    a.iter().any(|x| b.iter().any(|y| x.matches_filter(y)))
}

/// True when two `(min, max)` bounds describe overlapping ranges, treating an
/// absent bound as unbounded — the same way the engine applies `size_min`/
/// `size_max`/`entropy_*` gates at match time.
///
/// A band is *scope*, not identity: two traits with the same matcher and
/// overlapping bands both fire on a file in the shared window, so the band must
/// not be part of the grouping key. Where a band genuinely needs to change a
/// verdict, that is one trait with a `downgrade:`, not two traits.
fn ranges_overlap<T: PartialOrd + Copy>(
    a: (Option<T>, Option<T>),
    b: (Option<T>, Option<T>),
) -> bool {
    let lo_le_hi = |lo: Option<T>, hi: Option<T>| match (lo, hi) {
        (Some(l), Some(h)) => l <= h,
        _ => true,
    };
    lo_le_hi(a.0, b.1) && lo_le_hi(b.0, a.1)
}

/// Matcher signature with trivially-equivalent spellings folded together.
///
/// `type: value` with a bare `path:` and no predicate already means "the path
/// resolves", so an explicit `exists: true` is the same assertion written the
/// long way. Hashing the Debug form directly treats the two spellings as
/// different matchers and hides the duplicate.
fn matcher_signature(cond: &Condition) -> String {
    match cond {
        Condition::Kv(q) if q.exists == Some(true) => {
            let mut normalized = q.clone();
            normalized.exists = None;
            format!("{:?}", Condition::Kv(normalized))
        }
        other => format!("{other:?}"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod overlapping_scope_duplicate_tests;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cloned_ref_to_slice_refs
)]
mod literal_regex_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod canonical_atomic_duplicate_tests;
