//! Regex/literal overlap and alternative-subset checks.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Detect exact patterns that are redundant because a substr pattern with the SAME string exists
///
/// Examples:
///   - exact="/dev/kmem" + substr="/dev/kmem" → exact is redundant (substr catches it)
///   - exact="GetProcAddress" + substr="GetProcAddress" → exact is redundant
///
/// Important: Patterns must match exactly (after hex escape decoding).
///   "os.rename " ≠ "os.rename" (trailing space means different pattern)
pub(crate) fn check_exact_contained_by_substr(
    patterns: &ExtractedPatterns,
    warnings: &mut Vec<String>,
) {
    use super::super::helpers::extract_tier;

    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // Build indexes with normalized strings (hex escapes decoded)
    let mut exact_patterns: HashMap<&str, Vec<&PatternLocation>> = HashMap::new();
    let mut substr_patterns: HashMap<&str, Vec<&PatternLocation>> = HashMap::new();

    for (normalized, location) in &patterns.0 {
        match location.match_type.as_str() {
            "exact" => exact_patterns.entry(normalized).or_default().push(location),
            "substr" => substr_patterns
                .entry(normalized)
                .or_default()
                .push(location),
            _ => {}
        }
    }

    // Check for exact string match between exact and substr
    for (exact_pattern, exact_locs) in exact_patterns {
        if let Some(substr_locs) = substr_patterns.get(exact_pattern) {
            for exact_loc in &exact_locs {
                for substr_loc in substr_locs {
                    // Check file type overlap
                    if !has_filetype_overlap(exact_loc, substr_loc) {
                        continue;
                    }
                    if !exact_substr_context_reusable_as_is(exact_loc, substr_loc) {
                        continue;
                    }

                    // Check tier
                    let exact_tier = extract_tier(&exact_loc.trait_id);
                    let substr_tier = extract_tier(&substr_loc.trait_id);
                    let cross_tier = exact_tier != substr_tier;
                    let reusable_cross_tier = match (exact_tier, substr_tier) {
                        (Some(e), Some(s)) if e != s => is_reusable_tier(e) || is_reusable_tier(s),
                        _ => false,
                    };
                    if cross_tier && !reusable_cross_tier {
                        continue;
                    }
                    if !cross_tier
                        && trait_dir(&exact_loc.trait_id) != trait_dir(&substr_loc.trait_id)
                    {
                        continue;
                    }
                    if is_low_signal_lexicon_atom(exact_pattern, exact_loc)
                        || is_low_signal_lexicon_atom(exact_pattern, substr_loc)
                    {
                        continue;
                    }
                    if !cross_tier
                        && trait_dir(&exact_loc.trait_id) != trait_dir(&substr_loc.trait_id)
                        && is_low_value_exact_substr_atom(exact_pattern)
                    {
                        continue;
                    }

                    let tier_note = match (exact_tier, substr_tier) {
                        (Some(e), Some(s)) if e == s => format!(" (same tier: {e})"),
                        (Some(e), Some(s)) => format!(" (cross-tier: {e} → {s})"),
                        _ => String::new(),
                    };
                    let action = match (exact_tier, substr_tier) {
                        (Some(e), Some(s)) if e != s && is_reusable_tier(e) => {
                            "Remove higher-tier substr pattern and reference the exact reusable atom"
                        }
                        (Some(e), Some(s)) if e != s && is_reusable_tier(s) => {
                            "Remove higher-tier exact pattern and reference the reusable substr atom"
                        }
                        _ => "Keep one matcher in the best taxonomy location and reference it",
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
                        "Exact pattern '{}' is also matched by substr pattern{}
   Exact:  {}::{} (for: {})
   Substr: {}::{} (for: {})
   → Action: {}",
                        exact_pattern,
                        tier_note,
                        exact_loc.file_path,
                        exact_loc.trait_id,
                        for_exact,
                        substr_loc.file_path,
                        substr_loc.trait_id,
                        for_substr,
                        action,
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

pub(super) fn trait_dir(id: &str) -> &str {
    id.split_once("::").map_or(id, |(dir, _)| dir)
}

pub(super) fn is_low_value_exact_substr_atom(pattern: &str) -> bool {
    let len = pattern.chars().count();
    len <= 8
        && pattern
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub(super) fn is_low_signal_lexicon_atom(pattern: &str, location: &PatternLocation) -> bool {
    is_low_value_exact_substr_atom(pattern)
        && trait_dir(&location.trait_id) == "micro-behaviors/data/text/keywords/lexicon"
}

pub(super) fn exact_substr_context_reusable_as_is(
    a: &PatternLocation,
    b: &PatternLocation,
) -> bool {
    if a.condition_type != b.condition_type {
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
#[cfg(test)]
pub(crate) fn check_case_insensitive_overlaps(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    warnings.extend(
        find_case_insensitive_overlap_issues(trait_definitions)
            .into_iter()
            .map(|(_, message)| message),
    );
}

pub(crate) fn find_case_insensitive_overlap_issues(
    trait_definitions: &[TraitDefinition],
) -> Vec<(&'static str, String)> {
    let start = std::time::Instant::now();
    let mut issues = Vec::new();

    collect_case_insensitive_overlap_issues(trait_definitions, &mut issues);

    tracing::debug!(
        "Case-insensitive overlap detection completed in {:?} ({} overlaps found)",
        start.elapsed(),
        issues.len()
    );
    issues
}

pub(super) fn collect_case_insensitive_overlap_issues(
    trait_definitions: &[TraitDefinition],
    issues: &mut Vec<(&'static str, String)>,
) {
    let start = std::time::Instant::now();
    let initial_issue_count = issues.len();

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

    fn trait_dir(id: &str) -> &str {
        id.split_once("::").map_or(id, |(dir, _)| dir)
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

        // Extract patterns from every condition variant that carries a
        // `case_insensitive` flag. Symbol is excluded (no such flag — symbol
        // matching is always case-sensitive).
        match &trait_def.r#if {
            Condition::Raw(RawQuery {
                exact,
                substr,
                word,
                regex,
                case_insensitive,
                ..
            }) => {
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
            Condition::Text(TextQuery {
                exact,
                substr,
                word,
                regex,
                case_insensitive,
                ..
            }) => {
                if let Some(v) = exact {
                    add_case_pattern("text", "exact", v.clone(), *case_insensitive);
                }
                if let Some(v) = substr {
                    add_case_pattern("text", "substr", v.clone(), *case_insensitive);
                }
                if let Some(v) = word {
                    add_case_pattern("text", "word", v.clone(), *case_insensitive);
                }
                if let Some(v) = regex {
                    add_case_pattern("text", "regex", v.clone(), *case_insensitive);
                }
            }
            Condition::Literal(LiteralQuery {
                exact,
                substr,
                word,
                regex,
                case_insensitive,
                ..
            }) => {
                if let Some(v) = exact {
                    add_case_pattern("string_literal", "exact", v.clone(), *case_insensitive);
                }
                if let Some(v) = substr {
                    add_case_pattern("string_literal", "substr", v.clone(), *case_insensitive);
                }
                if let Some(v) = word {
                    add_case_pattern("string_literal", "word", v.clone(), *case_insensitive);
                }
                if let Some(v) = regex {
                    add_case_pattern("string_literal", "regex", v.clone(), *case_insensitive);
                }
            }
            Condition::Encoded(EncodedQuery {
                exact,
                substr,
                word,
                regex,
                case_insensitive,
                ..
            }) => {
                if let Some(v) = exact {
                    add_case_pattern("encoded", "exact", v.clone(), *case_insensitive);
                }
                if let Some(v) = substr {
                    add_case_pattern("encoded", "substr", v.clone(), *case_insensitive);
                }
                if let Some(v) = word {
                    add_case_pattern("encoded", "word", v.clone(), *case_insensitive);
                }
                if let Some(v) = regex {
                    add_case_pattern("encoded", "regex", v.clone(), *case_insensitive);
                }
            }
            Condition::Path(PathQuery {
                exact,
                substr,
                regex,
                case_insensitive,
                ..
            }) => {
                if let Some(v) = exact {
                    add_case_pattern("basename", "exact", v.clone(), *case_insensitive);
                }
                if let Some(v) = substr {
                    add_case_pattern("basename", "substr", v.clone(), *case_insensitive);
                }
                if let Some(v) = regex {
                    add_case_pattern("basename", "regex", v.clone(), *case_insensitive);
                }
            }
            Condition::Section(SectionQuery {
                exact,
                substr,
                word,
                regex,
                case_insensitive,
                ..
            }) => {
                if let Some(v) = exact {
                    add_case_pattern("section", "exact", v.clone(), *case_insensitive);
                }
                if let Some(v) = substr {
                    add_case_pattern("section", "substr", v.clone(), *case_insensitive);
                }
                if let Some(v) = word {
                    add_case_pattern("section", "word", v.clone(), *case_insensitive);
                }
                if let Some(v) = regex {
                    add_case_pattern("section", "regex", v.clone(), *case_insensitive);
                }
            }
            Condition::Kv(KvQuery {
                exact,
                substr,
                regex,
                case_insensitive,
                ..
            }) => {
                if let Some(v) = exact {
                    add_case_pattern("value", "exact", v.clone(), *case_insensitive);
                }
                if let Some(v) = substr {
                    add_case_pattern("value", "substr", v.clone(), *case_insensitive);
                }
                if let Some(v) = regex {
                    add_case_pattern("value", "regex", v.clone(), *case_insensitive);
                }
            }
            Condition::TreeSitter(TreeSitterQuery {
                exact,
                substr,
                regex,
                case_insensitive,
                ..
            }) => {
                if let Some(v) = exact {
                    add_case_pattern("tree-sitter", "exact", v.clone(), *case_insensitive);
                }
                if let Some(v) = substr {
                    add_case_pattern("tree-sitter", "substr", v.clone(), *case_insensitive);
                }
                if let Some(v) = regex {
                    add_case_pattern("tree-sitter", "regex", v.clone(), *case_insensitive);
                }
            }
            _ => {}
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

                // Case-only spelling checks are local hygiene. Cross-directory
                // reuse is handled by the broader duplicate-pattern validators;
                // applying this globally produces poor advice for generic atoms.
                if trait_dir(&p1.trait_id) != trait_dir(&p2.trait_id) {
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
                    let validator_id = if p1.match_type == "regex" {
                        "regex-case-subsumption"
                    } else {
                        "case-subsumption"
                    };
                    issues.push((validator_id, format!(
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
                    )));
                } else if !p1.case_insensitive
                    && p2.case_insensitive
                    && p1.normalized != p2.normalized
                {
                    let tier_note = make_tier_note(&p1.trait_id, &p2.trait_id);
                    let validator_id = if p1.match_type == "regex" {
                        "regex-case-subsumption"
                    } else {
                        "case-subsumption"
                    };
                    issues.push((validator_id, format!(
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
                    )));
                }
                // Case 2: Both case_insensitive=true, differ only in case (duplicate)
                else if p1.case_insensitive
                    && p2.case_insensitive
                    && p1.normalized != p2.normalized
                {
                    let tier_note = make_tier_note(&p1.trait_id, &p2.trait_id);
                    issues.push((
                        "duplicate-case-only",
                        format!(
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
                        ),
                    ));
                }
            }
        }
    }

    let overlaps_found = issues.len() - initial_issue_count;
    tracing::debug!(
        "Case-insensitive overlap detection completed in {:?} ({} overlaps found)",
        start.elapsed(),
        overlaps_found
    );
}

/// Helper to check file type overlap for case patterns
/// Whether two `for:` sets can see the same file: either one is unrestricted
/// (empty, or `all` -- `parse_file_types` returns `[All]` for `for: [all]`
/// with no exclusions), or they share a type. It is asked of every candidate
/// pair, and the sets hold a handful of types, so comparing them directly is
/// much cheaper than hashing each probe.
pub(super) fn has_filetype_overlap_case(
    types_a: &HashSet<String>,
    types_b: &HashSet<String>,
) -> bool {
    let unrestricted =
        |types: &HashSet<String>| types.is_empty() || types.iter().any(|t| t == "all");
    unrestricted(types_a)
        || unrestricted(types_b)
        || types_a.iter().any(|a| types_b.iter().any(|b| a == b))
}

/// Helper to create tier note for warnings
pub(super) fn make_tier_note(trait_id_1: &str, trait_id_2: &str) -> String {
    use super::super::helpers::extract_tier;

    let tier1 = extract_tier(trait_id_1);
    let tier2 = extract_tier(trait_id_2);

    match (tier1, tier2) {
        (Some(t1), Some(t2)) if t1 == t2 => format!(" (same tier: {t1})"),
        (Some(t1), Some(t2)) => format!(" (cross-tier: {t1} ↔ {t2})"),
        _ => String::new(),
    }
}

pub(super) fn is_reusable_tier(tier: &str) -> bool {
    matches!(tier, "metadata" | "micro-behaviors")
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
#[cfg(test)]
pub(crate) fn check_regex_contains_literal(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    warnings.extend(
        find_regex_literal_overlap_issues(trait_definitions)
            .into_iter()
            .map(|(_, message)| message),
    );
}

/// Regex metacharacters that may surround a literal in a trivial extension
/// (`foo` → `foo.*`, `.exe` → `.*\.exe`).
pub(super) fn is_extension_meta(c: char) -> bool {
    matches!(c, '.' | '*' | '+' | '?' | '$' | '^' | '\\')
}

/// Whether `regex` is `escaped_literal` with nothing but metacharacters around
/// it (`foo` → `foo.*`, `\.exe` → `.*\.exe`), so the regex adds no content of
/// its own. The first occurrence decides: as a prefix, then as a suffix, then
/// anywhere.
pub(in super::super) fn trivially_extends(regex: &str, escaped_literal: &str) -> bool {
    let all_meta = |s: &str| s.chars().all(is_extension_meta);
    if let Some(rest) = regex.strip_prefix(escaped_literal) {
        all_meta(rest)
    } else if let Some(rest) = regex.strip_suffix(escaped_literal) {
        all_meta(rest)
    } else if let Some(idx) = regex.find(escaped_literal) {
        all_meta(&regex[..idx]) && all_meta(&regex[idx + escaped_literal.len()..])
    } else {
        false
    }
}

/// The literals a regex can possibly be reported against, as ascending
/// indices: those with the regex's normalized form, and those whose escaped
/// form is the regex minus leading and trailing metacharacters. Every pair
/// `find_regex_literal_overlap_issues` reports is one of these; the caller
/// still applies the full test to each.
pub(in super::super) fn regex_literal_candidates(
    pattern: &str,
    normalized: &str,
    by_normalized: &HashMap<&str, Vec<usize>>,
    by_escaped: &HashMap<String, Vec<usize>>,
) -> Vec<usize> {
    let mut candidates: Vec<usize> = by_normalized.get(normalized).cloned().unwrap_or_default();
    // Metacharacters are ASCII, so every offset inside either run is a char
    // boundary.
    let lead = pattern.len() - pattern.trim_start_matches(is_extension_meta).len();
    let trail = pattern.len() - pattern.trim_end_matches(is_extension_meta).len();
    for start in 0..=lead {
        for end in (pattern.len() - trail).max(start)..=pattern.len() {
            if let Some(found) = pattern
                .get(start..end)
                .and_then(|core| by_escaped.get(core))
            {
                candidates.extend_from_slice(found);
            }
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

pub(crate) fn find_regex_literal_overlap_issues(
    trait_definitions: &[TraitDefinition],
) -> Vec<(&'static str, String)> {
    let start = std::time::Instant::now();

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
        argument_key: String,
        symbol_kind: Option<crate::composite_rules::condition::SymbolKind>,
        symbol_has_arguments: bool,
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
        argument_key: String,
        symbol_kind: Option<crate::composite_rules::condition::SymbolKind>,
        symbol_has_arguments: bool,
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
        let argument_key = match &trait_def.r#if {
            Condition::Symbol(query) => {
                symbol_argument_discriminator(query.arg.as_ref(), query.args.as_deref())
            }
            _ => String::new(),
        };

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
                argument_key: argument_key.clone(),
                symbol_kind: match &trait_def.r#if {
                    Condition::Symbol(query) => query.kind,
                    _ => None,
                },
                symbol_has_arguments: matches!(&trait_def.r#if,
                    Condition::Symbol(query) if query.arg.is_some() || query.args.is_some()),
            });
        };

        match &trait_def.r#if {
            Condition::Symbol(SymbolQuery { regex: Some(r), .. }) => add_regex("symbol", r.clone()),
            Condition::Raw(RawQuery { regex: Some(r), .. }) => add_regex("raw", r.clone()),
            Condition::Text(TextQuery { regex: Some(r), .. }) => add_regex("text", r.clone()),
            Condition::Literal(LiteralQuery { regex: Some(r), .. }) => {
                add_regex("string_literal", r.clone())
            }
            Condition::Path(PathQuery { regex: Some(r), .. }) => add_regex("basename", r.clone()),
            Condition::Encoded(EncodedQuery { regex: Some(r), .. }) => {
                add_regex("encoded", r.clone())
            }
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
        let argument_key = match &trait_def.r#if {
            Condition::Symbol(query) => {
                symbol_argument_discriminator(query.arg.as_ref(), query.args.as_deref())
            }
            _ => String::new(),
        };

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
                argument_key: argument_key.clone(),
                symbol_kind: match &trait_def.r#if {
                    Condition::Symbol(query) => query.kind,
                    _ => None,
                },
                symbol_has_arguments: matches!(&trait_def.r#if,
                    Condition::Symbol(query) if query.arg.is_some() || query.args.is_some()),
            });
        };

        match &trait_def.r#if {
            Condition::Symbol(SymbolQuery { exact, substr, .. }) => {
                if let Some(e) = exact {
                    add_literal("symbol", "exact", e.clone());
                }
                if let Some(s) = substr {
                    add_literal("symbol", "substr", s.clone());
                }
            }
            Condition::Raw(RawQuery {
                exact,
                substr,
                word,
                ..
            }) => {
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
            Condition::Text(TextQuery {
                exact,
                substr,
                word,
                ..
            }) => {
                if let Some(e) = exact {
                    add_literal("text", "exact", e.clone());
                }
                if let Some(s) = substr {
                    add_literal("text", "substr", s.clone());
                }
                if let Some(w) = word {
                    add_literal("text", "word", w.clone());
                }
            }
            Condition::Literal(LiteralQuery {
                exact,
                substr,
                word,
                ..
            }) => {
                if let Some(e) = exact {
                    add_literal("string_literal", "exact", e.clone());
                }
                if let Some(s) = substr {
                    add_literal("string_literal", "substr", s.clone());
                }
                if let Some(w) = word {
                    add_literal("string_literal", "word", w.clone());
                }
            }
            Condition::Path(PathQuery { exact, substr, .. }) => {
                if let Some(e) = exact {
                    add_literal("basename", "exact", e.clone());
                }
                if let Some(s) = substr {
                    add_literal("basename", "substr", s.clone());
                }
            }
            Condition::Encoded(EncodedQuery {
                exact,
                substr,
                word,
                ..
            }) => {
                if let Some(e) = exact {
                    add_literal("encoded", "exact", e.clone());
                }
                if let Some(s) = substr {
                    add_literal("encoded", "substr", s.clone());
                }
                if let Some(w) = word {
                    add_literal("encoded", "word", w.clone());
                }
            }
            _ => {}
        }
    }

    // Only two outcomes below produce a warning, and each names its literals
    // directly: an exact duplicate shares the regex's normalized form, and a
    // trivial extension is the regex minus metacharacters at either end. So
    // each regex is checked against just those literals rather than all of
    // them -- the full cross product was hundreds of millions of matches, and
    // most of `cleave validate`'s CPU.
    let mut by_normalized: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut by_escaped: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, literal_pat) in literal_patterns.iter().enumerate() {
        by_normalized
            .entry(literal_pat.normalized.as_str())
            .or_default()
            .push(idx);
        by_escaped
            .entry(regex::escape(&literal_pat.pattern))
            .or_default()
            .push(idx);
    }

    // Check each regex against literals (parallelized for performance)
    use rayon::prelude::*;

    let new_warnings: Vec<(&'static str, String)> = regex_patterns
        .par_iter()
        .flat_map(|regex_pat| {
            let candidates = regex_literal_candidates(
                &regex_pat.pattern,
                &regex_pat.normalized,
                &by_normalized,
                &by_escaped,
            );
            if candidates.is_empty() {
                return Vec::new();
            }
            // Try to compile regex to test matches (using cache)
            let Some(re) = build_regex(&regex_pat.pattern, false).ok() else {
                return Vec::new();
            };

            let mut local_warnings = Vec::new();
            for literal_pat in candidates.iter().map(|&idx| &literal_patterns[idx]) {
                // Skip if criticalities are different (intentional layering)
                // Note: Component/Baseline/Filtered are treated as equivalent "inert" levels
                if !criticalities_equivalent(regex_pat.crit, literal_pat.crit) {
                    continue;
                }

                // An import, call, and declaration are different observations.
                // An unspecified kind still overlaps every explicit kind.
                if let (Some(a), Some(b)) = (regex_pat.symbol_kind, literal_pat.symbol_kind)
                    && a != b
                {
                    continue;
                }

                // Argument-constrained calls and unconstrained API-name
                // observations are distinct even when their names overlap.
                if regex_pat.condition_type == "symbol"
                    && literal_pat.condition_type == "symbol"
                    && regex_pat.symbol_has_arguments != literal_pat.symbol_has_arguments
                {
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

                // Check if regex matches the literal. A match alone is not
                // enough to give useful reuse advice: broad regexes such as
                // `\b(foo|bar)\b` or `[A-Z]{8,12}` naturally match many
                // literals that should remain separate traits.
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
                let is_trivial_extension =
                    trivially_extends(&regex_pat.pattern, &regex::escape(&literal_pat.pattern));

                // Skip if significantly different length, no alternation, AND not a trivial extension
                if len_diff_pct > 0.33 && !has_alternation && !is_trivial_extension {
                    continue;
                }

                // Compare the actual argument predicates. These collectors
                // keep raw symbol patterns; extract_patterns' #arg markers
                // are never present here. A mode-filtered fopen call is a
                // distinct fact from a generic fopen API reference.
                if regex_pat.argument_key != literal_pat.argument_key {
                    continue;
                }

                // Check if this is a simple case (regex == literal after normalization)
                let is_exact_match = regex_pat.normalized == literal_pat.normalized;

                // Check condition types (cross-type means different string/symbol/raw)
                let cross_type = literal_pat.condition_type != regex_pat.condition_type;

                // Some cross-type pairs search genuinely different surfaces and
                // are NOT semantic duplicates even when their byte patterns match:
                //  - `basename` (the file's name) vs any content matcher: "this
                //    file IS X.dll" is a different fact from "this code REFERENCES
                //    X.dll".
                //  - `encoded` (decoded-string corpus) vs any other surface: an
                //    encoded match means the literal was hidden in an encoding,
                //    which carries different intent than a plain occurrence.
                // `symbol` vs `text`/`raw` is NOT considered complementary —
                // stripped binaries can lose one surface while keeping the other,
                // so authors generally want them unified into a single composite
                // (`any:` of both) rather than maintained as parallel atoms.
                let surfaces_are_complementary = cross_type && {
                    let a = regex_pat.condition_type.as_str();
                    let b = literal_pat.condition_type.as_str();
                    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
                    matches!(
                        (lo, hi),
                        ("basename", "raw")
                            | ("basename", "string_literal")
                            | ("basename", "symbol")
                            | ("basename", "text")
                            | ("basename", "encoded")
                            | ("encoded", "raw")
                            | ("encoded", "string_literal")
                            | ("encoded", "symbol")
                            | ("encoded", "text")
                    )
                };

                if is_exact_match && surfaces_are_complementary {
                    continue;
                }

                if is_exact_match {
                    // Exact match: regex pattern is functionally same as literal
                    let tier_note = make_tier_note(&regex_pat.trait_id, &literal_pat.trait_id);
                    local_warnings.push((
                        "regex-vs-literal-duplicate",
                        format!(
                            "Same pattern, different match types{}{}
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
                        ),
                    ));
                } else if !cross_type && is_trivial_extension {
                    // Same condition type — check if cross-tier (intentional layering)
                    let regex_tier = super::super::helpers::extract_tier(&regex_pat.trait_id);
                    let literal_tier = super::super::helpers::extract_tier(&literal_pat.trait_id);
                    let cross_tier = regex_tier != literal_tier;

                    if !cross_tier {
                        // Same tier, same type: likely redundant
                        let tier_note = make_tier_note(&regex_pat.trait_id, &literal_pat.trait_id);
                        local_warnings.push((
                            "regex-contains-literal",
                            format!(
                                "Regex pattern matches literal{}
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
                            ),
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

    let overlaps_found = new_warnings.len();
    tracing::debug!(
        "Regex vs literal overlap detection completed in {:?} ({} overlaps found)",
        start.elapsed(),
        overlaps_found
    );
    new_warnings
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
    use rayon::prelude::*;

    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // Helper structure for regex with alternatives
    #[derive(Debug)]
    struct RegexWithAlternatives {
        pattern: String,
        alternatives: Vec<String>, // Normalized alternatives
        grouped_alternatives: Option<(String, Vec<String>, String)>,
        condition_type: String,
        trait_id: String,
        file_path: String,
        for_types: HashSet<String>,
        case_insensitive: bool,
    }

    let relaxed_data_text_superset = |pattern: &RegexWithAlternatives| -> bool {
        if !is_micro_behavior_data_text_path(&pattern.file_path) {
            return false;
        }
        let alternation_count = if let Some((_, alts, _)) = &pattern.grouped_alternatives {
            alts.len().saturating_sub(1)
        } else {
            pattern.alternatives.len().saturating_sub(1)
        };
        alternation_count <= RELAXED_DATA_TEXT_ALTERNATION_LIMIT
    };

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
                    .map(|alternative| decode_hex_escapes(alternative))
                    .collect();

                regex_patterns.push(RegexWithAlternatives {
                    pattern,
                    alternatives: normalized_alts,
                    grouped_alternatives: None,
                    condition_type: condition_type.to_string(),
                    trait_id: trait_def.id.clone(),
                    file_path: file_path.clone(),
                    for_types: for_types.clone(),
                    case_insensitive,
                });
            } else if let Some((prefix, alts, suffix)) = extract_single_group_alternation(&pattern)
            {
                regex_patterns.push(RegexWithAlternatives {
                    pattern,
                    alternatives: Vec::new(),
                    grouped_alternatives: Some((prefix, alts, suffix)),
                    condition_type: condition_type.to_string(),
                    trait_id: trait_def.id.clone(),
                    file_path: file_path.clone(),
                    for_types: for_types.clone(),
                    case_insensitive,
                });
            }
        };

        match &trait_def.r#if {
            Condition::Symbol(SymbolQuery { regex: Some(r), .. }) => {
                // Symbol doesn't have case_insensitive flag, always case-sensitive
                add_regex("symbol", r.clone(), false);
            }
            Condition::Raw(RawQuery {
                regex: Some(r),
                case_insensitive,
                ..
            }) => add_regex("raw", r.clone(), *case_insensitive),
            Condition::Text(TextQuery {
                regex: Some(r),
                case_insensitive,
                ..
            }) => add_regex("text", r.clone(), *case_insensitive),
            Condition::Literal(LiteralQuery {
                regex: Some(r),
                case_insensitive,
                ..
            }) => add_regex("string_literal", r.clone(), *case_insensitive),
            Condition::Path(PathQuery {
                regex: Some(r),
                case_insensitive,
                ..
            }) => add_regex("basename", r.clone(), *case_insensitive),
            Condition::Encoded(EncodedQuery {
                regex: Some(r),
                case_insensitive,
                ..
            }) => add_regex("encoded", r.clone(), *case_insensitive),
            _ => {}
        }
    }

    // Alternative-subset reuse only makes sense for the same matcher surface.
    // Cross-type cases such as decoded `encoded` strings vs source `text`, or
    // `symbol` vs decoded content, are intentionally separate extractor
    // semantics. And a pair is reported only when the two share an alternative
    // ignoring case -- a subset shares all of its smaller side's, and case
    // variants have the same ones lowercased -- so each pattern is compared
    // only with the later patterns of its type that share one, found through
    // an index, using alternative sets built once per pattern. One pattern per
    // task; the findings are joined back in the original pair order.
    let alternative_sets: Vec<(HashSet<&str>, HashSet<String>)> = regex_patterns
        .iter()
        .map(|pattern| {
            let alternatives = match &pattern.grouped_alternatives {
                Some((_, alternatives, _)) => alternatives,
                None => &pattern.alternatives,
            };
            (
                alternatives.iter().map(String::as_str).collect(),
                alternatives.iter().map(|a| a.to_lowercase()).collect(),
            )
        })
        .collect();
    let mut sharing: HashMap<(&str, &str), Vec<usize>> = HashMap::new();
    for (i, (pattern, (_, lowered))) in regex_patterns.iter().zip(&alternative_sets).enumerate() {
        for alternative in lowered {
            sharing
                .entry((pattern.condition_type.as_str(), alternative.as_str()))
                .or_default()
                .push(i);
        }
    }
    let findings: Vec<Vec<String>> = (0..regex_patterns.len())
        .into_par_iter()
        .map(|i| {
            let mut warnings = Vec::new();
            let p1 = &regex_patterns[i];
            let (set1, set1_lower) = &alternative_sets[i];
            let mut peers: Vec<usize> = set1_lower
                .iter()
                .filter_map(|alternative| {
                    sharing.get(&(p1.condition_type.as_str(), alternative.as_str()))
                })
                .flatten()
                .copied()
                .filter(|&j| j > i)
                .collect();
            peers.sort_unstable();
            peers.dedup();
            for j in peers {
                let p2 = &regex_patterns[j];
                let (set2, set2_lower) = &alternative_sets[j];

                // Skip same file
                if p1.file_path == p2.file_path {
                    continue;
                }

                // Check file type overlap
                if !has_filetype_overlap_case(&p1.for_types, &p2.for_types) {
                    continue;
                }

                // Alternatives compare only within one shape: two top-level
                // alternations, or two single groups with the same text around
                // them.
                let comparable = match (&p1.grouped_alternatives, &p2.grouped_alternatives) {
                    (None, None) => true,
                    (Some((prefix1, _, suffix1)), Some((prefix2, _, suffix2))) => {
                        prefix1 == prefix2 && suffix1 == suffix2
                    }
                    _ => false,
                };
                let p1_subset_of_p2 = comparable && set1.len() < set2.len() && set1.is_subset(set2);
                let p2_subset_of_p1 = comparable && set2.len() < set1.len() && set2.is_subset(set1);

                if (p1_subset_of_p2 && relaxed_data_text_superset(p2))
                    || (p2_subset_of_p1 && relaxed_data_text_superset(p1))
                {
                    continue;
                }

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
                    let alternatives_same_ignoring_case =
                        match (&p1.grouped_alternatives, &p2.grouped_alternatives) {
                            (None, None) => set1_lower == set2_lower,
                            (Some((prefix1, _, suffix1)), Some((prefix2, _, suffix2))) => {
                                prefix1.eq_ignore_ascii_case(prefix2)
                                    && suffix1.eq_ignore_ascii_case(suffix2)
                                    && set1_lower == set2_lower
                            }
                            _ => false,
                        };

                    if alternatives_same_ignoring_case {
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
            warnings
        })
        .collect();
    warnings.extend(findings.into_iter().flatten());

    let subsets_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Regex alternative subset detection completed in {:?} ({} subsets found)",
        start.elapsed(),
        subsets_found
    );
}

/// Helper function to check if two file type lists have any overlap
pub(super) fn file_types_overlap(types1: &[RuleFileType], types2: &[RuleFileType]) -> bool {
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
pub(super) fn regex_could_match_literal(regex: &str, literal: &str) -> bool {
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
    if let Some(re) = build_regex(regex, false).ok()
        && re.is_match(literal)
    {
        return true;
    }

    false
}
