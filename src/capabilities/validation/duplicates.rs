//! Duplicate trait and pattern detection.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
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
//! - **Atomic logic duplicates**: Traits with same matching logic but different metadata (crit/conf/platforms)
//! - **Alternation merge candidates**: Regex patterns differing only in first token case that could be combined

use super::shared::{MatchSignature, PatternLocation};
use crate::composite_rules::{
    evaluators::build_regex, CompositeTrait, Condition, FileType as RuleFileType, TraitDefinition,
};
use crate::types::Criticality;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// Get or compile a regex pattern using the shared evaluator cache.
/// Returns None if the pattern is invalid.
fn get_cached_regex(pattern: &str) -> Option<regex::Regex> {
    build_regex(pattern, false).ok()
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
    use rayon::prelude::*;

    let start = std::time::Instant::now();

    // Pass 1: Detect duplicate atomic traits using hash-based deduplication
    // OPTIMIZATION: Uses u64 hash as key (50x faster than Vec<u8> comparisons)
    if !trait_definitions.is_empty() {
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
                for t in chunk {
                    // Serialize the trait's unique characteristics including filter fields
                    if let Ok(serialized) = bincode::serde::encode_to_vec(
                        (
                            &t.r#if,
                            &t.platforms,
                            &t.r#for,
                            &t.not,
                            &t.unless,
                            &t.size_min,
                            &t.size_max,
                            &t.count_min,
                            &t.count_max,
                            &t.per_kb_min,
                            &t.per_kb_max,
                            &t.entropy_min,
                            &t.entropy_max,
                        ),
                        bincode::config::standard(),
                    ) {
                        // Hash the serialized data to get a u64 key (much faster HashMap operations)
                        use std::collections::hash_map::DefaultHasher;
                        use std::hash::{Hash, Hasher};

                        let mut hasher = DefaultHasher::new();
                        serialized.hash(&mut hasher);
                        let hash_key = hasher.finish();

                        local_map.entry(hash_key).or_default().push(t.id.clone());
                    }
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
    }

    // Pass 2: Detect duplicate composite rules using hash-based deduplication
    // OPTIMIZATION: Uses u64 hash as key (50x faster than Vec<u8> comparisons)
    if !composite_rules.is_empty() {
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
                    if r.all.is_none() && r.any.is_none() && r.none.is_none() && r.unless.is_none()
                    {
                        continue;
                    }

                    // Serialize the rule's unique characteristics
                    if let Ok(serialized) = bincode::serde::encode_to_vec(
                        (
                            &r.all,
                            &r.any,
                            &r.none,
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
    }

    tracing::debug!("Total duplicate detection took {:?}", start.elapsed());
}

/// Split a regex pattern on top-level `|` only — not inside parentheses or brackets.
/// This avoids false positives from patterns like `(?:foo|bar)baz` being split into
/// `(?:foo` and `bar)baz`.
fn split_top_level_alternation(pattern: &str) -> Vec<&str> {
    // Check if the entire pattern is wrapped in a single group like (a|b|c)
    // If so, unwrap it first
    let unwrapped = if pattern.starts_with('(') && pattern.ends_with(')') {
        // Check if the opening paren matches the closing paren
        let mut depth = 0;
        let mut in_char_class = false;
        let bytes = pattern.as_bytes();
        let mut matches_at_end = false;

        for i in 0..bytes.len() {
            // Count consecutive preceding backslashes; odd count means escaped
            let mut backslash_count = 0;
            let mut j = i;
            while j > 0 && bytes[j - 1] == b'\\' {
                backslash_count += 1;
                j -= 1;
            }
            if backslash_count % 2 != 0 {
                continue; // escaped character
            }
            match bytes[i] {
                b'[' if !in_char_class => in_char_class = true,
                b']' if in_char_class => in_char_class = false,
                b'(' if !in_char_class => {
                    depth += 1;
                    if i == 0 {
                        // This is the opening paren
                        continue;
                    }
                }
                b')' if !in_char_class => {
                    depth -= 1;
                    if depth == 0 && i == bytes.len() - 1 {
                        matches_at_end = true;
                    }
                }
                _ => {}
            }
        }

        if matches_at_end {
            let mut start = 1;
            // Also skip non-capturing group prefix (?:)
            if pattern[start..].starts_with("?:") {
                start += 2;
            }
            &pattern[start..pattern.len() - 1]
        } else {
            pattern
        }
    } else {
        pattern
    };

    let mut depth = 0i32;
    let mut in_char_class = false;
    let mut last = 0;
    let mut result = Vec::new();
    let bytes = unwrapped.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 2; // skip escaped character
                continue;
            }
            b'[' if !in_char_class => {
                in_char_class = true;
            }
            b']' if in_char_class => {
                in_char_class = false;
            }
            b'(' if !in_char_class => {
                depth += 1;
            }
            b')' if !in_char_class => {
                depth -= 1;
            }
            b'|' if !in_char_class && depth == 0 => {
                result.push(&unwrapped[last..i]);
                last = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    result.push(&unwrapped[last..]);
    result
}

/// Decode common hex escapes in patterns (\xNN → character)
/// This allows detecting duplicates like '\x27' vs "'"
pub(super) fn decode_hex_escapes(pattern: &str) -> String {
    let mut result = String::new();
    let mut chars = pattern.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(&'x') = chars.peek() {
                chars.next(); // consume 'x'

                // Try to read 2 hex digits
                let hex_str: String = chars.by_ref().take(2).collect();
                if hex_str.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                        // Valid hex escape - decode it
                        result.push(byte as char);
                        continue;
                    }
                }
                // Invalid hex escape - keep original
                result.push('\\');
                result.push('x');
                result.push_str(&hex_str);
            } else {
                // Other escape sequence - keep it
                result.push(ch);
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Normalize a regex pattern by stripping anchors (^ and $)
fn normalize_regex(pattern: &str) -> String {
    let mut normalized = pattern.to_string();
    if normalized.starts_with('^') {
        normalized = normalized[1..].to_string();
    }
    if normalized.ends_with('$') && !normalized.ends_with("\\$") {
        normalized.truncate(normalized.len() - 1);
    }
    normalized
}

/// Normalize pattern for duplicate detection
/// - Decode hex escapes: \x27 → '
/// - For regex: strip anchors
fn normalize_pattern_for_comparison(pattern: &str, is_regex: bool) -> String {
    let mut normalized = decode_hex_escapes(pattern);

    // For regex, also strip anchors
    if is_regex {
        normalized = normalize_regex(&normalized);
    }

    normalized
}

/// Extract all searchable patterns from a trait definition
/// Returns: Vec<(normalized_value, PatternLocation)>
fn extract_patterns(trait_def: &TraitDefinition) -> Vec<(String, PatternLocation)> {
    let mut patterns = Vec::new();

    let for_types: HashSet<String> = trait_def
        .r#for
        .iter()
        .map(|ft| format!("{:?}", ft).to_lowercase())
        .collect();

    let file_path = trait_def.defined_in.to_string_lossy().to_string();

    // Helper to add a pattern
    let mut add_pattern =
        |condition_type: &str, match_type: &str, value: String, section: Option<String>| {
            let is_regex = match_type == "regex";
            let normalized = normalize_pattern_for_comparison(&value, is_regex);

            patterns.push((
                normalized,
                PatternLocation {
                    trait_id: trait_def.id.clone(),
                    file_path: file_path.clone(),
                    condition_type: condition_type.to_string(),
                    match_type: match_type.to_string(),
                    original_value: value,
                    for_types: for_types.clone(),
                    section,
                    count_min: trait_def.count_min,
                    count_max: trait_def.count_max,
                    per_kb_min: trait_def.per_kb_min,
                    per_kb_max: trait_def.per_kb_max,
                    confidence: trait_def.conf,
                    criticality: trait_def.crit,
                },
            ));
        };

    // Extract patterns from String, Symbol, and Raw conditions
    match &trait_def.r#if {
        Condition::StringValue {
            exact,
            substr,
            word,
            regex,
            section,
            ..
        } => {
            let sec = section.clone();
            if let Some(v) = exact {
                add_pattern("string_value", "exact", v.clone(), sec.clone());
            }
            if let Some(v) = substr {
                add_pattern("string_value", "substr", v.clone(), sec.clone());
            }
            if let Some(v) = word {
                add_pattern("string_value", "word", v.clone(), sec.clone());
            }
            if let Some(v) = regex {
                add_pattern("string_value", "regex", v.clone(), sec.clone());
            }
        }
        Condition::Symbol {
            exact,
            substr,
            regex,
            ..
        } => {
            if let Some(v) = exact {
                add_pattern("symbol", "exact", v.clone(), None);
            }
            if let Some(v) = substr {
                add_pattern("symbol", "substr", v.clone(), None);
            }
            if let Some(v) = regex {
                add_pattern("symbol", "regex", v.clone(), None);
            }
        }
        Condition::Raw {
            exact,
            substr,
            word,
            regex,
            section,
            ..
        } => {
            let sec = section.clone();
            if let Some(v) = exact {
                add_pattern("raw", "exact", v.clone(), sec.clone());
            }
            if let Some(v) = substr {
                add_pattern("raw", "substr", v.clone(), sec.clone());
            }
            if let Some(v) = word {
                add_pattern("raw", "word", v.clone(), sec.clone());
            }
            if let Some(v) = regex {
                add_pattern("raw", "regex", v.clone(), sec.clone());
            }
        }
        _ => {} // Skip Encoded, Yara, etc.
    }

    patterns
}

/// Check if two pattern locations have overlapping file type coverage
///
/// Handles:
/// - Empty sets (no restrictions) = overlaps with everything
/// - "all" in either set = overlaps with everything
/// - Regular intersection check for specific file types
fn has_filetype_overlap(loc_a: &PatternLocation, loc_b: &PatternLocation) -> bool {
    // Both have no restrictions -> overlap
    if loc_a.for_types.is_empty() && loc_b.for_types.is_empty() {
        return true;
    }

    // One has no restrictions -> overlaps with everything
    if loc_a.for_types.is_empty() || loc_b.for_types.is_empty() {
        return true;
    }

    // If either contains "all", they overlap with everything
    // (parse_file_types returns vec![All] when for: [all] has no exclusions)
    if loc_a.for_types.contains("all") || loc_b.for_types.contains("all") {
        return true;
    }

    // Check intersection of specific file types
    !loc_a.for_types.is_disjoint(&loc_b.for_types)
}

fn has_same_count_density_filters(loc_a: &PatternLocation, loc_b: &PatternLocation) -> bool {
    loc_a.count_min == loc_b.count_min
        && loc_a.count_max == loc_b.count_max
        && loc_a.per_kb_min == loc_b.per_kb_min
        && loc_a.per_kb_max == loc_b.per_kb_max
}

/// Detect duplicate string patterns across trait files
/// Only detects exact matches of normalized patterns (regex anchors stripped)
/// Checks string, symbol, and raw condition types (not encoded)
pub(crate) fn find_string_pattern_duplicates(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();

    // Build index: normalized_pattern -> Vec<PatternLocation>
    let mut pattern_index: HashMap<String, Vec<PatternLocation>> = HashMap::new();

    for trait_def in trait_definitions {
        for (normalized, location) in extract_patterns(trait_def) {
            pattern_index.entry(normalized).or_default().push(location);
        }
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

        // Check if any pair has overlapping file type coverage
        let mut has_overlap = false;
        'outer: for i in 0..locations.len() {
            for j in (i + 1)..locations.len() {
                if locations[i].file_path != locations[j].file_path
                    && has_filetype_overlap(&locations[i], &locations[j])
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
                        l.condition_type,
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

        let mut has_micro_behavior = false;
        let mut has_objective = false;
        let mut micro_behavior_ids: Vec<String> = Vec::new();
        let mut objective_ids: Vec<String> = Vec::new();

        for loc in &locations {
            if let Some(tier) = extract_tier(&loc.trait_id) {
                match tier {
                    "micro-behaviors" => {
                        has_micro_behavior = true;
                        micro_behavior_ids.push(loc.trait_id.clone());
                    }
                    "objectives" | "well-known" => {
                        has_objective = true;
                        objective_ids.push(loc.trait_id.clone());
                    }
                    _ => {}
                }
            }
        }

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
                    l.condition_type,
                    l.match_type,
                    l.original_value,
                    for_str
                )
            })
            .collect();

        // Add tier violation note if applicable
        let tier_note = if has_micro_behavior && has_objective {
            format!(
                "\n   ⚠️  TIER VIOLATION: objectives/ should REFERENCE micro-behaviors/, not duplicate patterns\n   → Action: Remove pattern from {} and use 'needs: [{}]' instead",
                objective_ids.join(", "),
                micro_behavior_ids.join(", ")
            )
        } else {
            String::new()
        };

        warnings.push(format!(
            "Duplicate pattern '{}' appears in {} files with overlapping file type coverage:\n{}{}",
            normalized_pattern,
            by_file.len(),
            location_details.join("\n"),
            tier_note
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

/// Check for regex patterns with | (OR) that overlap with standalone exact/word/substr patterns.
pub(crate) fn check_regex_or_overlapping_exact(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // First pass: collect all regex patterns with | (OR operators)
    let mut regex_patterns: Vec<(String, PatternLocation)> = Vec::new();

    for trait_def in trait_definitions {
        let patterns = extract_patterns(trait_def);
        for (_, location) in patterns {
            if location.match_type == "regex" && location.original_value.contains('|') {
                regex_patterns.push((location.original_value.clone(), location));
            }
        }
    }

    // Second pass: collect all exact/word/substr patterns
    let mut literal_patterns: HashMap<String, Vec<PatternLocation>> = HashMap::new();

    for trait_def in trait_definitions {
        let patterns = extract_patterns(trait_def);
        for (normalized, location) in patterns {
            if location.match_type != "regex" {
                literal_patterns
                    .entry(normalized)
                    .or_default()
                    .push(location);
            }
        }
    }

    // Check each regex OR pattern against all literals
    for (regex_value, regex_loc) in regex_patterns {
        // Split the regex on top-level | only (not inside parentheses/brackets)
        let alternatives: Vec<&str> = split_top_level_alternation(&regex_value);

        let mut overlapping_literals: Vec<(String, Vec<String>)> = Vec::new();

        for alternative in alternatives {
            // Normalize the alternative (strip anchors)
            let normalized_alt = normalize_regex(alternative);

            // Check if this alternative exists as a literal pattern elsewhere
            if let Some(literal_locs) = literal_patterns.get(&normalized_alt) {
                // Only report if the literal is in a different file AND has file type overlap
                let overlapping_files: Vec<String> = literal_locs
                    .iter()
                    .filter(|loc| {
                        loc.file_path != regex_loc.file_path
                            && has_filetype_overlap(loc, &regex_loc)
                    })
                    .map(|loc| format!("{}::{}", loc.file_path, loc.trait_id))
                    .collect();

                if !overlapping_files.is_empty() {
                    overlapping_literals.push((normalized_alt, overlapping_files));
                }
            }
        }

        if !overlapping_literals.is_empty() {
            let details: Vec<String> = overlapping_literals
                .iter()
                .map(|(pattern, files)| format!("   '{}' found in: {}", pattern, files.join(", ")))
                .collect();

            warnings.push(format!(
                "Regex OR pattern overlaps with exact/word/substr patterns:\n   Regex: {} (in {}::{})\n{}",
                regex_value,
                regex_loc.file_path,
                regex_loc.trait_id,
                details.join("\n")
            ));
        }
    }

    let overlaps_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Regex OR overlap detection completed in {:?} ({} overlaps found)",
        start.elapsed(),
        overlaps_found
    );
}

/// Check for overlapping regex patterns across traits with overlapping file type coverage.
///
/// This bans regex-to-regex overlap where alternatives are shared, which usually indicates
/// a monolithic rule layout and should be split into atomic traits.
///
/// OPTIMIZATION: Uses an inverted index to reduce O(n²) comparisons to O(n * avg_collisions).
/// Instead of comparing every pair of patterns, we pre-compute normalized alternatives for
/// each pattern and only compare patterns that share at least one alternative.
pub(crate) fn check_overlapping_regex_patterns(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // Collect all regex patterns with their pre-computed alternatives
    struct RegexWithAlternatives {
        location: PatternLocation,
        alternatives: FxHashSet<String>,
        has_alternation: bool,
    }

    let mut regex_patterns: Vec<RegexWithAlternatives> = Vec::new();
    for trait_def in trait_definitions {
        let patterns = extract_patterns(trait_def);
        for (_, location) in patterns {
            if location.match_type == "regex" {
                // Pre-compute normalized alternatives for this pattern
                let alts: FxHashSet<String> = split_top_level_alternation(&location.original_value)
                    .into_iter()
                    .map(|s| normalize_regex(s.trim()))
                    .filter(|s| !s.is_empty())
                    .collect();

                // If no alternatives, use the whole normalized pattern
                let alternatives = if alts.is_empty() {
                    let normalized = normalize_regex(location.original_value.trim());
                    if normalized.is_empty() {
                        FxHashSet::default()
                    } else {
                        let mut set = FxHashSet::default();
                        set.insert(normalized);
                        set
                    }
                } else {
                    alts
                };

                let has_alternation = location.original_value.contains('|');
                regex_patterns.push(RegexWithAlternatives {
                    location,
                    alternatives,
                    has_alternation,
                });
            }
        }
    }

    // Build inverted index: alternative -> list of pattern indices
    // This allows us to only compare patterns that share at least one alternative
    let mut inverted_index: FxHashMap<String, Vec<usize>> = FxHashMap::default();
    for (idx, pat) in regex_patterns.iter().enumerate() {
        for alt in &pat.alternatives {
            inverted_index.entry(alt.clone()).or_default().push(idx);
        }
    }

    // Find candidate pairs (patterns that share at least one alternative)
    let mut candidate_pairs: FxHashSet<(usize, usize)> = FxHashSet::default();
    for indices in inverted_index.values() {
        if indices.len() > 1 {
            // All pairs in this bucket are candidates
            for (i, &idx_a) in indices.iter().enumerate() {
                for &idx_b in &indices[i + 1..] {
                    let pair = if idx_a < idx_b {
                        (idx_a, idx_b)
                    } else {
                        (idx_b, idx_a)
                    };
                    candidate_pairs.insert(pair);
                }
            }
        }
    }

    tracing::debug!(
        "Regex overlap: {} patterns, {} candidate pairs (from inverted index with {} buckets)",
        regex_patterns.len(),
        candidate_pairs.len(),
        inverted_index.len()
    );

    let mut seen_pairs: FxHashSet<(String, String)> = FxHashSet::default();

    // Only check candidate pairs instead of all O(n²) pairs
    for (i, j) in candidate_pairs {
        let a = &regex_patterns[i];
        let b = &regex_patterns[j];

        // Skip same trait instance.
        if a.location.trait_id == b.location.trait_id
            && a.location.file_path == b.location.file_path
        {
            continue;
        }

        // Different section scopes are not duplicates (e.g. same pattern in .rsrc vs .rdata).
        if a.location.section.is_some()
            && b.location.section.is_some()
            && a.location.section != b.location.section
        {
            continue;
        }

        // Must overlap in filetype scope to be a real conflict.
        if !has_filetype_overlap(&a.location, &b.location) {
            continue;
        }

        // Different count/per-kb thresholds are intentionally layered evidence.
        if !has_same_count_density_filters(&a.location, &b.location) {
            continue;
        }

        // Compute shared alternatives (fast since we have pre-computed sets)
        let shared: Vec<String> = a
            .alternatives
            .intersection(&b.alternatives)
            .cloned()
            .collect();
        if shared.is_empty() {
            continue;
        }

        // Allow overlaps when patterns differ significantly in length (>33%)
        // AND at least one regex has no alternation (|). This permits different
        // specificity levels like "\.exe$" vs "7z\.exe" while catching duplicates.
        let max_len = a
            .location
            .original_value
            .len()
            .max(b.location.original_value.len());
        let len_diff_pct = if max_len > 0 {
            (a.location.original_value.len() as f32 - b.location.original_value.len() as f32).abs()
                / max_len as f32
        } else {
            0.0
        };

        // Skip if significantly different length and at least one has no alternation
        if len_diff_pct > 0.33 && (!a.has_alternation || !b.has_alternation) {
            continue;
        }

        let key_a = format!("{}::{}", a.location.file_path, a.location.trait_id);
        let key_b = format!("{}::{}", b.location.file_path, b.location.trait_id);
        let key = if key_a <= key_b {
            (key_a.clone(), key_b.clone())
        } else {
            (key_b.clone(), key_a.clone())
        };

        if !seen_pairs.insert(key) {
            continue;
        }

        let mut shared_preview = shared;
        shared_preview.sort();
        if shared_preview.len() > 5 {
            shared_preview.truncate(5);
        }

        warnings.push(format!(
            "Overlapping regex patterns with same file type coverage:\n   {}::{} => {}\n   {}::{} => {}\n   shared alternatives: {}",
            a.location.file_path,
            a.location.trait_id,
            a.location.original_value,
            b.location.file_path,
            b.location.trait_id,
            b.location.original_value,
            shared_preview.join(", ")
        ));
    }

    let overlaps_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Regex-to-regex overlap detection completed in {:?} ({} overlaps found)",
        start.elapsed(),
        overlaps_found
    );
}

/// Check for regex patterns that are just ^word$ and should use exact instead
/// Regex should only be used when there are actual variations or special characters
pub(crate) fn check_regex_should_be_exact(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    for trait_def in trait_definitions {
        let patterns = extract_patterns(trait_def);

        for (_, location) in patterns {
            if location.match_type != "regex" {
                continue;
            }

            let regex_value = &location.original_value;

            // Check if this is a simple anchored pattern: ^word$
            // Allow common variations like ? * + but flag pure anchored words
            if regex_value.starts_with('^') && regex_value.ends_with('$') {
                let inner = &regex_value[1..regex_value.len() - 1];

                // Check if inner contains only word characters (no regex operators)
                // Allow backslash escaping but flag if there are no actual regex features
                let has_regex_operators = inner.chars().any(|c| {
                    matches!(
                        c,
                        '?' | '*' | '+' | '|' | '[' | ']' | '(' | ')' | '{' | '}' | '.'
                    )
                });

                if !has_regex_operators {
                    // Additional check: if it's just a simple word or escaped word, flag it
                    let is_simple_word = inner.chars().all(|c| c.is_alphanumeric() || c == '_');
                    let is_escaped_word = inner
                        .replace("\\\\", "")
                        .chars()
                        .filter(|&c| c == '\\')
                        .count()
                        <= 2;

                    if is_simple_word || (is_escaped_word && inner.len() < 50) {
                        warnings.push(format!(
                            "Regex pattern '{}' is just ^word$ and should use exact: '{}' instead ({}::{})",
                            regex_value,
                            inner,
                            location.file_path,
                            location.trait_id
                        ));
                    }
                }
            }
        }
    }

    let simple_regexes_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Simple regex detection completed in {:?} ({} simple regexes found)",
        start.elapsed(),
        simple_regexes_found
    );
}

/// Check for the same pattern appearing with different types across {string, symbol, raw}
/// This indicates poor organization - pick one canonical type and extend language support
pub(crate) fn check_same_string_different_types(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // Build index: normalized_pattern -> Vec<PatternLocation> grouped by type
    let mut pattern_by_type: HashMap<String, HashMap<String, Vec<PatternLocation>>> =
        HashMap::new();

    for trait_def in trait_definitions {
        let patterns = extract_patterns(trait_def);

        for (normalized, location) in patterns {
            // Only check string, symbol, and raw types
            if !matches!(
                location.condition_type.as_str(),
                "string_value" | "symbol" | "raw"
            ) {
                continue;
            }

            pattern_by_type
                .entry(normalized)
                .or_default()
                .entry(location.condition_type.clone())
                .or_default()
                .push(location);
        }
    }

    // Find patterns that appear with multiple types
    for (pattern, types_map) in pattern_by_type {
        if types_map.len() < 2 {
            continue; // Only one type, no issue
        }

        // Check if any pair of different types has file type overlap
        let all_locations: Vec<&PatternLocation> = types_map.values().flatten().collect();

        let mut has_overlap = false;
        'outer: for i in 0..all_locations.len() {
            for j in (i + 1)..all_locations.len() {
                // Only check if they have different condition types
                if all_locations[i].condition_type != all_locations[j].condition_type
                    && has_filetype_overlap(all_locations[i], all_locations[j])
                {
                    has_overlap = true;
                    break 'outer;
                }
            }
        }

        if !has_overlap {
            continue; // No file type overlap, patterns won't conflict
        }

        // We have the same pattern with different types AND file type overlap
        let type_details: Vec<String> = types_map
            .iter()
            .map(|(type_name, locations)| {
                let location_strs: Vec<String> = locations
                    .iter()
                    .map(|loc| {
                        let for_str = if loc.for_types.is_empty() {
                            "all".to_string()
                        } else {
                            let mut types: Vec<_> = loc.for_types.iter().cloned().collect();
                            types.sort();
                            types.join(", ")
                        };
                        format!("{}::{} (for: {})", loc.file_path, loc.trait_id, for_str)
                    })
                    .collect();
                format!("   type: {} in: {}", type_name, location_strs.join(", "))
            })
            .collect();

        warnings.push(format!(
            "Pattern '{}' appears with multiple types and overlapping file type coverage (choose one canonical type):\n{}",
            pattern,
            type_details.join("\n")
        ));
    }

    let type_conflicts_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Type conflict detection completed in {:?} ({} conflicts found)",
        start.elapsed(),
        type_conflicts_found
    );
}

/// Detect exact patterns that are redundant because a substr pattern with the SAME string exists
///
/// Examples:
///   - exact="/dev/kmem" + substr="/dev/kmem" → exact is redundant (substr catches it)
///   - exact="GetProcAddress" + substr="GetProcAddress" → exact is redundant
///
/// Important: Patterns must match exactly (after hex escape decoding).
///   "os.rename " ≠ "os.rename" (trailing space means different pattern)
pub(crate) fn check_exact_contained_by_substr(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    use super::helpers::extract_tier;

    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // Build indexes with normalized strings (hex escapes decoded)
    let mut exact_patterns: HashMap<String, Vec<PatternLocation>> = HashMap::new();
    let mut substr_patterns: HashMap<String, Vec<PatternLocation>> = HashMap::new();

    for trait_def in trait_definitions {
        for (normalized, location) in extract_patterns(trait_def) {
            match location.match_type.as_str() {
                "exact" => exact_patterns.entry(normalized).or_default().push(location),
                "substr" => substr_patterns
                    .entry(normalized)
                    .or_default()
                    .push(location),
                _ => {}
            }
        }
    }

    // Check for exact string match between exact and substr
    for (exact_pattern, exact_locs) in exact_patterns {
        if let Some(substr_locs) = substr_patterns.get(&exact_pattern) {
            for exact_loc in &exact_locs {
                for substr_loc in substr_locs {
                    // Check file type overlap
                    if !has_filetype_overlap(exact_loc, substr_loc) {
                        continue;
                    }

                    // Check tier
                    let exact_tier = extract_tier(&exact_loc.trait_id);
                    let substr_tier = extract_tier(&substr_loc.trait_id);

                    let tier_note = match (exact_tier, substr_tier) {
                        (Some(e), Some(s)) if e == s => format!(" (same tier: {e})"),
                        (Some(e), Some(s)) => format!(" (cross-tier: {e} → {s})"),
                        _ => String::new(),
                    };

                    let for_exact = if exact_loc.for_types.is_empty() {
                        "all".to_string()
                    } else {
                        let mut types: Vec<_> = exact_loc.for_types.iter().cloned().collect();
                        types.sort();
                        types.join(", ")
                    };

                    let for_substr = if substr_loc.for_types.is_empty() {
                        "all".to_string()
                    } else {
                        let mut types: Vec<_> = substr_loc.for_types.iter().cloned().collect();
                        types.sort();
                        types.join(", ")
                    };

                    warnings.push(format!(
                        "REDUNDANT: exact pattern '{}' is already matched by substr pattern{}
   Exact:  {}::{} (for: {})
   Substr: {}::{} (for: {})
   → Action: Remove exact pattern (substr already catches this)",
                        exact_pattern,
                        tier_note,
                        exact_loc.file_path,
                        exact_loc.trait_id,
                        for_exact,
                        substr_loc.file_path,
                        substr_loc.trait_id,
                        for_substr,
                    ));
                }
            }
        }
    }

    let redundancies_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Exact ⊂ substr containment detection completed in {:?} ({} redundancies found)",
        start.elapsed(),
        redundancies_found
    );
}

/// Detect patterns where case_insensitive=true subsumes case_insensitive=false
///
/// Examples of overlaps to detect:
///   - exact="GetProcAddress" case_insensitive=false + exact="getprocaddress" case_insensitive=true
///     → case_insensitive=true subsumes the case_sensitive pattern
///   - substr="PASSWORD" case_insensitive=false + substr="password" case_insensitive=true
///     → case_insensitive=true subsumes the case_sensitive pattern
///   - exact="test" case_insensitive=true + exact="TEST" case_insensitive=true
///     → Both case_insensitive, differ only in case → duplicate
///
/// Important: Does NOT flag patterns that differ in content:
///   - "GetProcAddress" ≠ "GetProcAddressA" (different strings)
pub(crate) fn check_case_insensitive_overlaps(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // Helper structure to track pattern with case info
    #[derive(Debug)]
    struct CasePattern {
        original: String,
        normalized: String, // After hex decode
        lowercase: String,  // Normalized + lowercased
        case_insensitive: bool,
        condition_type: String,
        match_type: String,
        trait_id: String,
        file_path: String,
        for_types: HashSet<String>,
    }

    // Extract patterns with case sensitivity info
    let mut patterns: Vec<CasePattern> = Vec::new();

    for trait_def in trait_definitions {
        let for_types: HashSet<String> = trait_def
            .r#for
            .iter()
            .map(|ft| format!("{:?}", ft).to_lowercase())
            .collect();
        let file_path = trait_def.defined_in.to_string_lossy().to_string();

        let mut add_case_pattern =
            |condition_type: &str, match_type: &str, value: String, case_insensitive: bool| {
                let is_regex = match_type == "regex";
                let normalized = normalize_pattern_for_comparison(&value, is_regex);
                let lowercase = normalized.to_lowercase();

                patterns.push(CasePattern {
                    original: value,
                    normalized,
                    lowercase,
                    case_insensitive,
                    condition_type: condition_type.to_string(),
                    match_type: match_type.to_string(),
                    trait_id: trait_def.id.clone(),
                    file_path: file_path.clone(),
                    for_types: for_types.clone(),
                });
            };

        // Extract patterns from conditions that support case_insensitive
        match &trait_def.r#if {
            Condition::StringValue {
                exact,
                substr,
                word,
                regex,
                case_insensitive,
                ..
            } => {
                if let Some(v) = exact {
                    add_case_pattern("string_value", "exact", v.clone(), *case_insensitive);
                }
                if let Some(v) = substr {
                    add_case_pattern("string_value", "substr", v.clone(), *case_insensitive);
                }
                if let Some(v) = word {
                    add_case_pattern("string_value", "word", v.clone(), *case_insensitive);
                }
                if let Some(v) = regex {
                    add_case_pattern("string_value", "regex", v.clone(), *case_insensitive);
                }
            }
            Condition::Raw {
                exact,
                substr,
                word,
                regex,
                case_insensitive,
                ..
            } => {
                if let Some(v) = exact {
                    add_case_pattern("raw", "exact", v.clone(), *case_insensitive);
                }
                if let Some(v) = substr {
                    add_case_pattern("raw", "substr", v.clone(), *case_insensitive);
                }
                if let Some(v) = word {
                    add_case_pattern("raw", "word", v.clone(), *case_insensitive);
                }
                if let Some(v) = regex {
                    add_case_pattern("raw", "regex", v.clone(), *case_insensitive);
                }
            }
            _ => {} // Symbol doesn't have case_insensitive; others not relevant for this check
        }
    }

    // Group patterns by lowercase normalized value
    let mut lowercase_groups: HashMap<String, Vec<&CasePattern>> = HashMap::new();
    for pattern in &patterns {
        lowercase_groups
            .entry(pattern.lowercase.clone())
            .or_default()
            .push(pattern);
    }

    // Check each group for case-related issues
    for (_lowercase_pattern, group) in lowercase_groups {
        if group.len() < 2 {
            continue;
        }

        // Check all pairs within the group
        for i in 0..group.len() {
            for j in (i + 1)..group.len() {
                let p1 = group[i];
                let p2 = group[j];

                // Skip same file
                if p1.file_path == p2.file_path {
                    continue;
                }

                // Skip different match types (exact vs substr is a different kind of issue)
                if p1.match_type != p2.match_type {
                    continue;
                }

                // Check file type overlap
                if !has_filetype_overlap_case(&p1.for_types, &p2.for_types) {
                    continue;
                }

                // Case 1: case_insensitive=true subsumes case_insensitive=false (when normalized differs)
                if p1.case_insensitive && !p2.case_insensitive && p1.normalized != p2.normalized {
                    let tier_note = make_tier_note(&p1.trait_id, &p2.trait_id);
                    warnings.push(format!(
                        "CASE SUBSUMPTION{}: case_insensitive pattern subsumes case_sensitive pattern
   Case-insensitive: '{}' ({} {}) in {}::{}
   Subsumes: '{}' ({} {}) in {}::{}
   → Action: Remove case_sensitive pattern (case_insensitive already catches this)",
                        tier_note,
                        p1.original,
                        p1.condition_type,
                        p1.match_type,
                        p1.file_path,
                        p1.trait_id,
                        p2.original,
                        p2.condition_type,
                        p2.match_type,
                        p2.file_path,
                        p2.trait_id,
                    ));
                } else if !p1.case_insensitive
                    && p2.case_insensitive
                    && p1.normalized != p2.normalized
                {
                    let tier_note = make_tier_note(&p1.trait_id, &p2.trait_id);
                    warnings.push(format!(
                        "CASE SUBSUMPTION{}: case_insensitive pattern subsumes case_sensitive pattern
   Case-insensitive: '{}' ({} {}) in {}::{}
   Subsumes: '{}' ({} {}) in {}::{}
   → Action: Remove case_sensitive pattern (case_insensitive already catches this)",
                        tier_note,
                        p2.original,
                        p2.condition_type,
                        p2.match_type,
                        p2.file_path,
                        p2.trait_id,
                        p1.original,
                        p1.condition_type,
                        p1.match_type,
                        p1.file_path,
                        p1.trait_id,
                    ));
                }
                // Case 2: Both case_insensitive=true, differ only in case (duplicate)
                else if p1.case_insensitive
                    && p2.case_insensitive
                    && p1.normalized != p2.normalized
                {
                    let tier_note = make_tier_note(&p1.trait_id, &p2.trait_id);
                    warnings.push(format!(
                        "DUPLICATE (case only){}: Both case_insensitive, differ only in case
   Pattern 1: '{}' ({} {}) in {}::{}
   Pattern 2: '{}' ({} {}) in {}::{}
   → Action: Choose one canonical form (they match identically)",
                        tier_note,
                        p1.original,
                        p1.condition_type,
                        p1.match_type,
                        p1.file_path,
                        p1.trait_id,
                        p2.original,
                        p2.condition_type,
                        p2.match_type,
                        p2.file_path,
                        p2.trait_id,
                    ));
                }
            }
        }
    }

    let overlaps_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Case-insensitive overlap detection completed in {:?} ({} overlaps found)",
        start.elapsed(),
        overlaps_found
    );
}

/// Helper to check file type overlap for case patterns
fn has_filetype_overlap_case(types_a: &HashSet<String>, types_b: &HashSet<String>) -> bool {
    // No restrictions -> overlap
    if types_a.is_empty() || types_b.is_empty() {
        return true;
    }

    // If either contains "all", they overlap
    if types_a.contains("all") || types_b.contains("all") {
        return true;
    }

    // Check intersection
    types_a.intersection(types_b).next().is_some()
}

/// Helper to create tier note for warnings
fn make_tier_note(trait_id_1: &str, trait_id_2: &str) -> String {
    use super::helpers::extract_tier;

    let tier1 = extract_tier(trait_id_1);
    let tier2 = extract_tier(trait_id_2);

    match (tier1, tier2) {
        (Some(t1), Some(t2)) if t1 == t2 => format!(" (same tier: {t1})"),
        (Some(t1), Some(t2)) => format!(" (cross-tier: {t1} ↔ {t2})"),
        _ => String::new(),
    }
}

/// Check if ANY regex pattern overlaps with exact/substr/word literals
///
/// This catches cases the existing check misses:
/// - symbol exact: "GetProcAddress" vs raw regex: "GetProcAddress" (cross-type)
/// - symbol exact: "foo" vs raw regex: "foo.*" (regex contains literal)
/// - string substr: "subprocess" vs raw regex: "subprocess\\." (regex contains literal)
///
/// Existing check_regex_or_overlapping_exact only checks regexes with "|"
/// This checks ALL regexes for containment/overlap with literals
pub(crate) fn check_regex_contains_literal(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // Helper structure for regex patterns
    #[derive(Debug)]
    struct RegexPattern {
        pattern: String,
        normalized: String,
        condition_type: String,
        trait_id: String,
        file_path: String,
        for_types: HashSet<String>,
        crit: Criticality,
    }

    // Helper structure for literal patterns
    #[derive(Debug)]
    struct LiteralPattern {
        pattern: String,
        normalized: String,
        match_type: String, // exact, substr, word
        condition_type: String,
        trait_id: String,
        file_path: String,
        for_types: HashSet<String>,
        crit: Criticality,
    }

    // Collect all regex patterns (ANY regex, not just those with |)
    let mut regex_patterns: Vec<RegexPattern> = Vec::new();

    for trait_def in trait_definitions {
        let for_types: HashSet<String> = trait_def
            .r#for
            .iter()
            .map(|ft| format!("{:?}", ft).to_lowercase())
            .collect();
        let file_path = trait_def.defined_in.to_string_lossy().to_string();

        let mut add_regex = |condition_type: &str, pattern: String| {
            let normalized = normalize_pattern_for_comparison(&pattern, true);
            regex_patterns.push(RegexPattern {
                pattern,
                normalized,
                condition_type: condition_type.to_string(),
                trait_id: trait_def.id.clone(),
                file_path: file_path.clone(),
                for_types: for_types.clone(),
                crit: trait_def.crit,
            });
        };

        match &trait_def.r#if {
            Condition::StringValue { regex: Some(r), .. } => add_regex("string_value", r.clone()),
            Condition::Symbol { regex: Some(r), .. } => add_regex("symbol", r.clone()),
            Condition::Raw { regex: Some(r), .. } => add_regex("raw", r.clone()),
            _ => {}
        }
    }

    // Collect all exact/substr/word patterns
    let mut literal_patterns: Vec<LiteralPattern> = Vec::new();

    for trait_def in trait_definitions {
        let for_types: HashSet<String> = trait_def
            .r#for
            .iter()
            .map(|ft| format!("{:?}", ft).to_lowercase())
            .collect();
        let file_path = trait_def.defined_in.to_string_lossy().to_string();

        let mut add_literal = |condition_type: &str, match_type: &str, pattern: String| {
            let normalized = normalize_pattern_for_comparison(&pattern, false);
            literal_patterns.push(LiteralPattern {
                pattern,
                normalized,
                match_type: match_type.to_string(),
                condition_type: condition_type.to_string(),
                trait_id: trait_def.id.clone(),
                file_path: file_path.clone(),
                for_types: for_types.clone(),
                crit: trait_def.crit,
            });
        };

        match &trait_def.r#if {
            Condition::StringValue {
                exact,
                substr,
                word,
                ..
            } => {
                if let Some(e) = exact {
                    add_literal("string_value", "exact", e.clone());
                }
                if let Some(s) = substr {
                    add_literal("string_value", "substr", s.clone());
                }
                if let Some(w) = word {
                    add_literal("string_value", "word", w.clone());
                }
            }
            Condition::Symbol { exact, substr, .. } => {
                if let Some(e) = exact {
                    add_literal("symbol", "exact", e.clone());
                }
                if let Some(s) = substr {
                    add_literal("symbol", "substr", s.clone());
                }
            }
            Condition::Raw {
                exact,
                substr,
                word,
                ..
            } => {
                if let Some(e) = exact {
                    add_literal("raw", "exact", e.clone());
                }
                if let Some(s) = substr {
                    add_literal("raw", "substr", s.clone());
                }
                if let Some(w) = word {
                    add_literal("raw", "word", w.clone());
                }
            }
            _ => {}
        }
    }

    // Check each regex against literals (parallelized for performance)
    use rayon::prelude::*;

    let new_warnings: Vec<String> = regex_patterns
        .par_iter()
        .flat_map(|regex_pat| {
            // Try to compile regex to test matches (using cache)
            let Some(re) = get_cached_regex(&regex_pat.pattern) else {
                return Vec::new();
            };

            let mut local_warnings = Vec::new();
            for literal_pat in &literal_patterns {
                // Skip if criticalities are different (intentional layering)
                // Note: Component/Baseline/Filtered are treated as equivalent "inert" levels
                if !criticalities_equivalent(regex_pat.crit, literal_pat.crit) {
                    continue;
                }

                // Skip same file
                if literal_pat.file_path == regex_pat.file_path {
                    continue;
                }

                // Check file type overlap
                if !has_filetype_overlap_case(&literal_pat.for_types, &regex_pat.for_types) {
                    continue;
                }

                // Check if regex matches the literal
                if !re.is_match(&literal_pat.normalized) {
                    continue;
                }

                // Allow overlaps when patterns differ significantly in length (>33%)
                // AND regex has no alternation (|) AND literal is not a prefix/suffix
                // of the regex. This permits different specificity levels like ".exe"
                // vs "mimikatz.exe" while catching true duplicates like "foo" vs "foo.*".
                let max_len = regex_pat.pattern.len().max(literal_pat.pattern.len());
                let len_diff_pct = if max_len > 0 {
                    (regex_pat.pattern.len() as f32 - literal_pat.pattern.len() as f32).abs()
                        / max_len as f32
                } else {
                    0.0
                };
                let has_alternation = regex_pat.pattern.contains('|');

                // Check if literal appears in the regex with only metacharacters as prefix/suffix
                // "foo" vs "foo.*" -> block (literal + metacharacters)
                // ".exe" vs ".*\.exe" -> block (metacharacters + escaped literal)
                // ".exe" vs "7z\.exe" -> allow (actual content + escaped literal)
                let escaped_literal = regex::escape(&literal_pat.pattern);
                let is_trivial_extension = if regex_pat.pattern.starts_with(&escaped_literal) {
                    // Literal is a prefix - check if remainder is just metacharacters/anchors
                    let remainder = &regex_pat.pattern[escaped_literal.len()..];
                    remainder
                        .chars()
                        .all(|c| matches!(c, '.' | '*' | '+' | '?' | '$' | '^' | '\\'))
                } else if regex_pat.pattern.ends_with(&escaped_literal) {
                    // Literal is a suffix - check if prefix is just metacharacters/anchors
                    let prefix =
                        &regex_pat.pattern[..regex_pat.pattern.len() - escaped_literal.len()];
                    prefix
                        .chars()
                        .all(|c| matches!(c, '.' | '*' | '+' | '?' | '$' | '^' | '\\'))
                } else if regex_pat.pattern.contains(&escaped_literal) {
                    // Literal appears in the middle - check if surrounding chars are metacharacters
                    if let Some(idx) = regex_pat.pattern.find(&escaped_literal) {
                        let before = &regex_pat.pattern[..idx];
                        let after = &regex_pat.pattern[idx + escaped_literal.len()..];
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

                // Check if this is a simple case (regex == literal after normalization)
                let is_exact_match = regex_pat.normalized == literal_pat.normalized;

                // Check condition types (cross-type means different string/symbol/raw)
                let cross_type = literal_pat.condition_type != regex_pat.condition_type;

                if is_exact_match {
                    // Exact match: regex pattern is functionally same as literal
                    let tier_note = make_tier_note(&regex_pat.trait_id, &literal_pat.trait_id);
                    local_warnings.push(format!(
                        "REGEX vs LITERAL DUPLICATE{}: Same pattern, different match types{}
   Regex: '{}' ({} regex) in {}::{}
   Literal: '{}' ({} {}) in {}::{}
   → Action: Choose one canonical form (prefer {} for simpler pattern)",
                        tier_note,
                        if cross_type { " (cross-type)" } else { "" },
                        regex_pat.pattern,
                        regex_pat.condition_type,
                        regex_pat.file_path,
                        regex_pat.trait_id,
                        literal_pat.pattern,
                        literal_pat.condition_type,
                        literal_pat.match_type,
                        literal_pat.file_path,
                        literal_pat.trait_id,
                        literal_pat.match_type, // Prefer exact/substr over regex for simple patterns
                    ));
                } else if !cross_type {
                    // Same condition type — check if cross-tier (intentional layering)
                    let regex_tier = super::helpers::extract_tier(&regex_pat.trait_id);
                    let literal_tier = super::helpers::extract_tier(&literal_pat.trait_id);
                    let cross_tier = regex_tier != literal_tier;

                    if !cross_tier {
                        // Same tier, same type: likely redundant
                        let tier_note = make_tier_note(&regex_pat.trait_id, &literal_pat.trait_id);
                        local_warnings.push(format!(
                            "REGEX CONTAINS LITERAL{}: Regex pattern matches literal
   Regex: '{}' ({} regex) in {}::{}
   Matches: '{}' ({} {}) in {}::{}
   → Review: Is this intentional layering or redundant detection?",
                            tier_note,
                            regex_pat.pattern,
                            regex_pat.condition_type,
                            regex_pat.file_path,
                            regex_pat.trait_id,
                            literal_pat.pattern,
                            literal_pat.condition_type,
                            literal_pat.match_type,
                            literal_pat.file_path,
                            literal_pat.trait_id,
                        ));
                    }
                    // Cross-tier containment (e.g., micro-behaviors regex `.dll\b`
                    // matching objectives literal `ntdll.dll`) is intentional layering:
                    // broader lower-tier patterns naturally subsume specific higher-tier ones.
                }
                // Skip cross-type overlaps (e.g., symbol regex vs string exact) —
                // different data sources make this intentional layering, not redundancy.
            }
            local_warnings
        })
        .collect();

    warnings.extend(new_warnings);

    let overlaps_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Regex vs literal overlap detection completed in {:?} ({} overlaps found)",
        start.elapsed(),
        overlaps_found
    );
}

/// Check if regex patterns with alternatives have subset relationships
///
/// Detects when one regex's alternatives are a subset of another's:
/// - "(foo|bar)" vs "(foo|bar|baz)" → first is subset of second
/// - "(read|write)" vs "(read|write|execute)" → first is subset of second
///
/// Also detects case-insensitive regex overlaps:
/// - "(?i)password" vs "PASSWORD" → case-insensitive subsumes case-sensitive
pub(crate) fn check_regex_alternative_subsets(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // Helper structure for regex with alternatives
    #[derive(Debug)]
    struct RegexWithAlternatives {
        pattern: String,
        alternatives: Vec<String>, // Normalized alternatives
        condition_type: String,
        trait_id: String,
        file_path: String,
        for_types: HashSet<String>,
        case_insensitive: bool,
    }

    let mut regex_patterns: Vec<RegexWithAlternatives> = Vec::new();

    for trait_def in trait_definitions {
        let for_types: HashSet<String> = trait_def
            .r#for
            .iter()
            .map(|ft| format!("{:?}", ft).to_lowercase())
            .collect();
        let file_path = trait_def.defined_in.to_string_lossy().to_string();

        let mut add_regex = |condition_type: &str, pattern: String, case_insensitive: bool| {
            // Check if pattern has top-level alternation
            let alternatives = split_top_level_alternation(&pattern);

            // Only track patterns with multiple alternatives
            if alternatives.len() > 1 {
                // Normalize each alternative (decode hex, sort)
                let normalized_alts: Vec<String> = alternatives
                    .iter()
                    .map(|alt| decode_hex_escapes(alt))
                    .collect();

                regex_patterns.push(RegexWithAlternatives {
                    pattern,
                    alternatives: normalized_alts,
                    condition_type: condition_type.to_string(),
                    trait_id: trait_def.id.clone(),
                    file_path: file_path.clone(),
                    for_types: for_types.clone(),
                    case_insensitive,
                });
            }
        };

        match &trait_def.r#if {
            Condition::StringValue {
                regex: Some(r),
                case_insensitive,
                ..
            } => add_regex("string_value", r.clone(), *case_insensitive),
            Condition::Symbol { regex: Some(r), .. } => {
                // Symbol doesn't have case_insensitive flag, always case-sensitive
                add_regex("symbol", r.clone(), false);
            }
            Condition::Raw {
                regex: Some(r),
                case_insensitive,
                ..
            } => add_regex("raw", r.clone(), *case_insensitive),
            _ => {}
        }
    }

    // Check each pair for subset relationships
    for i in 0..regex_patterns.len() {
        for j in (i + 1)..regex_patterns.len() {
            let p1 = &regex_patterns[i];
            let p2 = &regex_patterns[j];

            // Skip same file
            if p1.file_path == p2.file_path {
                continue;
            }

            // Check file type overlap
            if !has_filetype_overlap_case(&p1.for_types, &p2.for_types) {
                continue;
            }

            // Convert to sets for subset comparison
            let set1: HashSet<&String> = p1.alternatives.iter().collect();
            let set2: HashSet<&String> = p2.alternatives.iter().collect();

            // Check if one is a subset of the other
            let p1_subset_of_p2 = set1.is_subset(&set2) && set1.len() < set2.len();
            let p2_subset_of_p1 = set2.is_subset(&set1) && set2.len() < set1.len();

            if p1_subset_of_p2 {
                let tier_note = make_tier_note(&p1.trait_id, &p2.trait_id);
                warnings.push(format!(
                    "REGEX ALTERNATIVE SUBSET{}: First pattern's alternatives are subset of second
   Subset: '{}' ({}) in {}::{}
   Superset: '{}' ({}) in {}::{}
   → Review: First pattern is redundant if both traits serve same purpose",
                    tier_note,
                    p1.pattern,
                    p1.condition_type,
                    p1.file_path,
                    p1.trait_id,
                    p2.pattern,
                    p2.condition_type,
                    p2.file_path,
                    p2.trait_id,
                ));
            } else if p2_subset_of_p1 {
                let tier_note = make_tier_note(&p1.trait_id, &p2.trait_id);
                warnings.push(format!(
                    "REGEX ALTERNATIVE SUBSET{}: Second pattern's alternatives are subset of first
   Superset: '{}' ({}) in {}::{}
   Subset: '{}' ({}) in {}::{}
   → Review: Second pattern is redundant if both traits serve same purpose",
                    tier_note,
                    p1.pattern,
                    p1.condition_type,
                    p1.file_path,
                    p1.trait_id,
                    p2.pattern,
                    p2.condition_type,
                    p2.file_path,
                    p2.trait_id,
                ));
            }

            // Check for case-insensitive subsumption
            // If patterns have same alternatives but different case_insensitive flags
            if p1.case_insensitive != p2.case_insensitive {
                // Normalize both to lowercase for comparison
                let set1_lower: HashSet<String> =
                    p1.alternatives.iter().map(|a| a.to_lowercase()).collect();
                let set2_lower: HashSet<String> =
                    p2.alternatives.iter().map(|a| a.to_lowercase()).collect();

                if set1_lower == set2_lower {
                    let (case_insensitive_pat, case_sensitive_pat) = if p1.case_insensitive {
                        (p1, p2)
                    } else {
                        (p2, p1)
                    };

                    let tier_note = make_tier_note(
                        &case_insensitive_pat.trait_id,
                        &case_sensitive_pat.trait_id,
                    );
                    warnings.push(format!(
                        "REGEX CASE SUBSUMPTION{}: case_insensitive regex subsumes case_sensitive
   Case-insensitive: '{}' ({}) in {}::{}
   Subsumes: '{}' ({}) in {}::{}
   → Action: Remove case_sensitive pattern (case_insensitive already catches this)",
                        tier_note,
                        case_insensitive_pat.pattern,
                        case_insensitive_pat.condition_type,
                        case_insensitive_pat.file_path,
                        case_insensitive_pat.trait_id,
                        case_sensitive_pat.pattern,
                        case_sensitive_pat.condition_type,
                        case_sensitive_pat.file_path,
                        case_sensitive_pat.trait_id,
                    ));
                }
            }
        }
    }

    let subsets_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Regex alternative subset detection completed in {:?} ({} subsets found)",
        start.elapsed(),
        subsets_found
    );
}

/// Helper function to check if two file type lists have any overlap
fn file_types_overlap(types1: &[RuleFileType], types2: &[RuleFileType]) -> bool {
    // If either contains All, they overlap
    if types1.contains(&RuleFileType::All) || types2.contains(&RuleFileType::All) {
        return true;
    }
    // Check if any concrete types match
    types1.iter().any(|t1| types2.contains(t1))
}

/// Helper function to check if a regex pattern could match a literal string
/// First tries a fast heuristic (string matching), then falls back to actually
/// compiling and testing the regex for accuracy.
#[cfg(test)]
fn regex_could_match_literal(regex: &str, literal: &str) -> bool {
    // Fast path: check if the literal text appears in the regex directly
    if regex.contains(literal) {
        return true;
    }

    // Fast path: check if the literal appears with common regex escaping
    let escaped_literal: String = literal
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_string()
            } else {
                format!("\\{}", c)
            }
        })
        .collect();

    if regex.contains(&escaped_literal) {
        return true;
    }

    // Slow path: actually compile and test the regex (using cache)
    // This catches cases like "c?mod" matching "chmod"
    if let Some(re) = get_cached_regex(regex) {
        if re.is_match(literal) {
            return true;
        }
    }

    false
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
            Condition::StringValue { exact: Some(s), .. }
            | Condition::Symbol { exact: Some(s), .. } => {
                literal_patterns.push((
                    s.clone(),
                    "exact".to_string(),
                    t.id.clone(),
                    t.crit,
                    t.r#for.clone(),
                ));
            }
            Condition::StringValue {
                substr: Some(s), ..
            }
            | Condition::Symbol {
                substr: Some(s), ..
            } => {
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
            Condition::StringValue { regex: Some(r), .. }
            | Condition::Symbol { regex: Some(r), .. } => Some(r),
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

/// Find traits where both `type: string` and `type: raw` exist for the same pattern
/// at the same criticality. These should be merged to just `raw` (which is broader).
/// Returns: Vec<(string_trait_id, raw_trait_id, pattern_description)>
#[must_use]
pub(crate) fn find_string_content_collisions(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, String, String)> {
    let mut collisions = Vec::new();

    // Group traits by (signature, criticality, for, platforms)
    // Key: (signature, crit, for, platforms) -> Vec<(trait_id, is_string_type)>
    type SignatureGroup = HashMap<(MatchSignature, String, String, String), Vec<(String, bool)>>;
    let mut groups: SignatureGroup = HashMap::new();

    for t in trait_definitions {
        if let Some((is_string, sig)) = extract_match_signature(&t.r#if) {
            // Create a key that includes criticality, for, and platforms
            let crit_key = format!("{:?}", t.crit);
            let for_key = format!("{:?}", t.r#for);
            let platforms_key = format!("{:?}", t.platforms);
            let key = (sig, crit_key, for_key, platforms_key);

            groups
                .entry(key)
                .or_default()
                .push((t.id.clone(), is_string));
        }
    }

    // Find groups with both string and content types
    for ((sig, _crit, _for, _platforms), traits) in groups {
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
) -> Vec<(Vec<String>, String)> {
    let mut duplicates = Vec::new();

    // Create signature excluding `for:` field but including everything else
    // Key: (if, crit, conf, platforms, size_min, size_max, not, unless) -> Vec<(trait_id, for)>
    let mut groups: HashMap<String, Vec<(String, Vec<RuleFileType>)>> = HashMap::new();

    for t in trait_definitions {
        let signature = format!(
            "{:?}:{:?}:{:.2}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}",
            t.r#if,
            t.crit,
            t.conf,
            t.platforms,
            t.size_min,
            t.size_max,
            t.count_min,
            t.count_max,
            t.per_kb_min,
            t.per_kb_max,
            t.entropy_min,
            t.entropy_max,
            t.not,
            t.unless,
        );
        groups
            .entry(signature)
            .or_default()
            .push((t.id.clone(), t.r#for.clone()));
    }

    // Find groups with multiple traits (different `for:` values)
    for (sig, traits) in groups {
        if traits.len() > 1 {
            // Check that they actually have different `for:` values
            let unique_fors: HashSet<String> =
                traits.iter().map(|(_, f)| format!("{:?}", f)).collect();
            if unique_fors.len() > 1 {
                let trait_ids: Vec<String> = traits.into_iter().map(|(id, _)| id).collect();

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

/// Find traits with identical matching logic but different metadata.
/// These represent potential inconsistencies - same detection with conflicting criticality/confidence.
/// Only flags pairs with overlapping file types (so they'd actually fire on the same files).
/// Returns: Vec<(trait_id_a, trait_id_b, description)>
#[must_use]
pub(crate) fn find_atomic_logic_duplicates(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, String, String)> {
    let mut duplicates = Vec::new();

    // Group traits by matching logic signature (if + not + unless)
    // This excludes metadata: crit, conf, desc, attack, ref, platforms, etc.
    // Key: matching signature -> Vec<trait>
    let mut groups: HashMap<String, Vec<&TraitDefinition>> = HashMap::new();

    for t in trait_definitions {
        // Create signature from matching logic including filter fields
        let signature = format!(
            "{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}",
            t.r#if,
            t.not,
            t.unless,
            t.size_min,
            t.size_max,
            t.count_min,
            t.count_max,
            t.per_kb_min,
            t.per_kb_max,
            t.entropy_min,
            t.entropy_max,
        );
        groups.entry(signature).or_default().push(t);
    }

    // Check groups with multiple traits for overlapping file types
    for (_sig, traits) in groups {
        if traits.len() < 2 {
            continue;
        }

        // Check each pair for overlapping file types and differing metadata
        for i in 0..traits.len() {
            for j in (i + 1)..traits.len() {
                let a = traits[i];
                let b = traits[j];

                // Check if file types overlap
                if !file_types_overlap(&a.r#for, &b.r#for) {
                    continue;
                }

                // Check if metadata differs (crit, conf, or platforms)
                // Use the equivalence check for criticality
                let crit_differs = !criticalities_equivalent(a.crit, b.crit);
                let conf_differs = (a.conf - b.conf).abs() >= 0.1;
                let platforms_differ = a.platforms != b.platforms;

                if !crit_differs && !conf_differs && !platforms_differ {
                    // Metadata is effectively the same, not interesting
                    continue;
                }

                // Build description of the difference
                let mut diffs = Vec::new();
                if crit_differs {
                    diffs.push(format!("crit: {:?} vs {:?}", a.crit, b.crit));
                }
                if conf_differs {
                    diffs.push(format!("conf: {:.2} vs {:.2}", a.conf, b.conf));
                }
                if platforms_differ {
                    diffs.push(format!("platforms: {:?} vs {:?}", a.platforms, b.platforms));
                }

                let for_a: Vec<_> = a.r#for.iter().map(|f| format!("{f:?}")).collect();
                let for_b: Vec<_> = b.r#for.iter().map(|f| format!("{f:?}")).collect();
                let desc = format!(
                    "Same matching logic, overlapping types ({}∩{}), but: {}",
                    for_a.join(","),
                    for_b.join(","),
                    diffs.join(", ")
                );

                duplicates.push((a.id.clone(), b.id.clone(), desc));
            }
        }
    }

    duplicates
}

/// Find traits with regex patterns where the first token differs only in case (alternation candidates).
/// For example: `nc\s+-e` and `NC\s+-e` should become `(nc|NC)\s+-e`
/// Returns: Vec<(trait_ids, common_suffix, suggested_prefix_alternation)>
///
/// NOTE: This check only flags patterns where the same word appears with different cases.
/// Patterns with different words (like `nc` vs `ncat`) are NOT flagged, as they represent
/// genuinely different behaviors.
#[must_use]
pub(crate) fn find_alternation_merge_candidates(
    trait_definitions: &[TraitDefinition],
    source_files: &HashMap<String, String>,
) -> Vec<(Vec<String>, String, String)> {
    let mut candidates = Vec::new();

    // Extract regex patterns with their metadata
    // Group by (directory, crit, for, platforms, all other condition params except regex)
    let mut groups: HashMap<String, Vec<(String, String)>> = HashMap::new(); // key -> [(trait_id, regex)]

    for t in trait_definitions {
        let regex_pattern = match &t.r#if {
            Condition::StringValue { regex: Some(r), .. }
            | Condition::Raw { regex: Some(r), .. } => Some(r.clone()),
            _ => None,
        };

        if let Some(regex) = regex_pattern {
            // Get the directory of the source file for this trait
            let directory = source_files
                .get(&t.id)
                .and_then(|path| std::path::Path::new(path).parent().and_then(|p| p.to_str()))
                .unwrap_or("");

            // Create key including directory so we only group traits from the same directory
            let key = format!(
                "{}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}:{:?}",
                directory, t.crit, t.r#for, t.platforms, t.size_min, t.size_max, t.not, t.unless
            );
            groups.entry(key).or_default().push((t.id.clone(), regex));
        }
    }

    // Regex to extract prefix (first word-like token) and suffix
    // Match patterns like: ^word or ^word\s or ^word[^a-z]
    let prefix_regex = prefix_regex();

    // For each group, find patterns that share a common suffix
    for (_key, traits) in groups {
        if traits.len() < 2 {
            continue;
        }

        // Try to find common suffix by splitting on first non-word pattern
        // Look for patterns like: `word\s+rest` or `word-rest` or `word_rest`
        let mut suffix_groups: HashMap<String, Vec<(String, String)>> = HashMap::new();

        for (trait_id, regex) in &traits {
            // Try to extract prefix (first word-like token) and suffix
            if let Some(captures) = prefix_regex.captures(regex) {
                let caret = captures.get(1).map(|m| m.as_str()).unwrap_or("");
                let prefix = captures.get(2).map(|m| m.as_str()).unwrap_or("");
                let suffix = captures.get(3).map(|m| m.as_str()).unwrap_or("");

                // Only group if suffix is non-trivial (at least a few chars)
                if suffix.len() >= 3 {
                    let suffix_key = format!("{}{}", caret, suffix);
                    suffix_groups
                        .entry(suffix_key)
                        .or_default()
                        .push((trait_id.clone(), prefix.to_string()));
                }
            }
        }

        // Find suffix groups with 2+ traits that differ only in case
        for (suffix, prefix_traits) in suffix_groups {
            if prefix_traits.len() >= 2 {
                // Group by lowercase prefix to find case-only differences
                let mut case_groups: HashMap<String, Vec<(String, String)>> = HashMap::new();
                for (trait_id, prefix) in &prefix_traits {
                    case_groups
                        .entry(prefix.to_lowercase())
                        .or_default()
                        .push((trait_id.clone(), prefix.clone()));
                }

                // Only flag groups where the same prefix appears with different cases
                for (_, case_variants) in case_groups {
                    if case_variants.len() >= 2 {
                        // Check if they actually differ in case (not just duplicates)
                        let unique_cases: std::collections::HashSet<_> =
                            case_variants.iter().map(|(_, p)| p.as_str()).collect();

                        if unique_cases.len() >= 2 {
                            let trait_ids: Vec<String> =
                                case_variants.iter().map(|(id, _)| id.clone()).collect();
                            let prefixes: Vec<String> =
                                case_variants.iter().map(|(_, p)| p.clone()).collect();

                            // Build suggested alternation
                            let suggested = format!("({}){}", prefixes.join("|"), suffix);

                            candidates.push((trait_ids, suffix.clone(), suggested));
                        }
                    }
                }
            }
        }
    }

    candidates
}

/// Extract matching signature from a Condition (for string/raw collision detection)
fn extract_match_signature(condition: &Condition) -> Option<(bool, MatchSignature)> {
    match condition {
        Condition::StringValue {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            is_check,
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            ..
        } => Some((
            true, // is_string_type
            MatchSignature {
                exact: exact.clone(),
                substr: substr.clone(),
                regex: regex.clone(),
                word: word.clone(),
                case_insensitive: *case_insensitive,
                is_check: *is_check,
                section: section.clone(),
                offset: *offset,
                offset_range: *offset_range,
                section_offset: *section_offset,
                section_offset_range: *section_offset_range,
            },
        )),
        Condition::Raw {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            is_check,
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            ..
        } => Some((
            false, // is_content_type
            MatchSignature {
                exact: exact.clone(),
                substr: substr.clone(),
                regex: regex.clone(),
                word: word.clone(),
                case_insensitive: *case_insensitive,
                is_check: *is_check,
                section: section.clone(),
                offset: *offset,
                offset_range: *offset_range,
                section_offset: *section_offset,
                section_offset_range: *section_offset_range,
            },
        )),
        _ => None,
    }
}

#[allow(clippy::expect_used)] // Static regex pattern is hardcoded and valid
fn prefix_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"^(\^?)([a-zA-Z_][a-zA-Z0-9_-]*)(.*)$").expect("valid regex")
    })
}

/// Check for duplicate basename patterns in atomic traits
///
/// Detects:
/// - Duplicate exact patterns (same value, same case_insensitive)
/// - Duplicate substr patterns (same value, same case_insensitive)
/// - Duplicate regex patterns (same pattern)
/// - Regex patterns that should be exact (^literal$ with no metacharacters)
pub(crate) fn check_basename_pattern_duplicates(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // Helper structure for basename patterns
    #[derive(Debug)]
    struct BasenamePattern {
        trait_id: String,
        file_path: String,
        exact: Option<String>,
        substr: Option<String>,
        regex: Option<String>,
        case_insensitive: bool,
    }

    // Extract all basename patterns from atomic traits
    let mut basename_patterns: Vec<BasenamePattern> = Vec::new();

    for trait_def in trait_definitions {
        // Only process basename conditions
        if let Condition::Basename {
            exact,
            substr,
            regex,
            case_insensitive,
            ..
        } = &trait_def.r#if
        {
            // Skip basename conditions that don't actually have any patterns
            // (These can occur when a trait only has size constraints)
            if exact.is_none() && substr.is_none() && regex.is_none() {
                continue;
            }

            // Skip bogus regex patterns that are likely deserialization artifacts
            // A regex of just "." is meaningless (matches any basename with 1+ chars)
            if exact.is_none() && substr.is_none() && regex.as_deref() == Some(".") {
                continue;
            }

            basename_patterns.push(BasenamePattern {
                trait_id: trait_def.id.clone(),
                file_path: trait_def.defined_in.to_string_lossy().to_string(),
                exact: exact.clone(),
                substr: substr.clone(),
                regex: regex.clone(),
                case_insensitive: *case_insensitive,
            });
        }
    }

    if basename_patterns.is_empty() {
        return;
    }

    // Group by match type and pattern
    let mut exact_groups: HashMap<(String, bool), Vec<&BasenamePattern>> = HashMap::new();
    let mut substr_groups: HashMap<(String, bool), Vec<&BasenamePattern>> = HashMap::new();
    let mut regex_groups: HashMap<String, Vec<&BasenamePattern>> = HashMap::new();

    for pattern in &basename_patterns {
        if let Some(exact) = &pattern.exact {
            let key = (exact.clone(), pattern.case_insensitive);
            exact_groups.entry(key).or_default().push(pattern);
        }
        if let Some(substr) = &pattern.substr {
            let key = (substr.clone(), pattern.case_insensitive);
            substr_groups.entry(key).or_default().push(pattern);
        }
        if let Some(regex) = &pattern.regex {
            regex_groups.entry(regex.clone()).or_default().push(pattern);
        }
    }

    // Check for exact duplicates
    for ((pattern, case_insensitive), patterns) in exact_groups {
        if patterns.len() > 1 {
            let trait_details: Vec<String> = patterns
                .iter()
                .map(|p| format!("   {}: {}", p.file_path, p.trait_id))
                .collect();

            warnings.push(format!(
                "Duplicate basename exact pattern '{}' (case_insensitive: {}) appears in {} traits:\n{}",
                pattern,
                case_insensitive,
                patterns.len(),
                trait_details.join("\n")
            ));
        }
    }

    // Check for substr duplicates
    for ((pattern, case_insensitive), patterns) in substr_groups {
        if patterns.len() > 1 {
            let trait_details: Vec<String> = patterns
                .iter()
                .map(|p| format!("   {}: {}", p.file_path, p.trait_id))
                .collect();

            warnings.push(format!(
                "Duplicate basename substr pattern '{}' (case_insensitive: {}) appears in {} traits:\n{}",
                pattern,
                case_insensitive,
                patterns.len(),
                trait_details.join("\n")
            ));
        }
    }

    // Check for regex duplicates
    for (pattern, patterns) in regex_groups {
        if patterns.len() > 1 {
            let trait_details: Vec<String> = patterns
                .iter()
                .map(|p| format!("   {}: {}", p.file_path, p.trait_id))
                .collect();

            warnings.push(format!(
                "Duplicate basename regex pattern '{}' appears in {} traits:\n{}",
                pattern,
                patterns.len(),
                trait_details.join("\n")
            ));
        }
    }

    // Check for regex patterns that should be exact
    for pattern in &basename_patterns {
        if let Some(regex) = &pattern.regex {
            // Handle case-insensitive prefix
            let mut pattern_to_check = regex.as_str();
            let has_case_insensitive_flag = pattern_to_check.starts_with("(?i)");
            if has_case_insensitive_flag {
                pattern_to_check = &pattern_to_check[4..];
            }

            // Check if it's anchored on both sides: ^literal$
            if pattern_to_check.starts_with('^') && pattern_to_check.ends_with('$') {
                let pattern_body = &pattern_to_check[1..pattern_to_check.len() - 1];

                // Check if the pattern body has any regex metacharacters
                // We'll consider it simple if it only has escaped characters
                let mut test_pattern = pattern_body.to_string();
                // Remove escaped characters that are just literal representations
                test_pattern = test_pattern.replace("\\.", "X");
                test_pattern = test_pattern.replace("\\\\", "X");
                test_pattern = test_pattern.replace("\\/", "X");
                test_pattern = test_pattern.replace("\\-", "X");
                test_pattern = test_pattern.replace("\\_", "X");

                // Check for actual regex metacharacters
                let has_alternation = test_pattern.contains('|');
                let has_char_class = test_pattern.contains('[') || test_pattern.contains(']');
                let has_quantifiers = test_pattern.contains('*')
                    || test_pattern.contains('+')
                    || test_pattern.contains('?')
                    || test_pattern.contains('{');
                let has_groups = test_pattern.contains('(');
                let has_wildcards = test_pattern.contains('.');

                let is_simple = !has_alternation
                    && !has_char_class
                    && !has_quantifiers
                    && !has_groups
                    && !has_wildcards;

                if is_simple {
                    // Suggest converting to exact
                    let suggested = pattern_body
                        .replace("\\.", ".")
                        .replace("\\\\", "\\")
                        .replace("\\/", "/")
                        .replace("\\-", "-")
                        .replace("\\_", "_");

                    let case_note = if has_case_insensitive_flag || pattern.case_insensitive {
                        ", case_insensitive: true"
                    } else {
                        ""
                    };

                    warnings.push(format!(
                        "Basename regex pattern '{}' is just ^literal$ and should use exact: '{}'{} ({}::{})",
                        regex, suggested, case_note, pattern.file_path, pattern.trait_id
                    ));
                }
            }
        }
    }

    let duplicates_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Basename pattern duplicate detection completed in {:?} ({} duplicates found)",
        start.elapsed(),
        duplicates_found
    );
}
