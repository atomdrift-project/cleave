//! Same-logic, basename and structural duplicates across rules.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Scope lists are sets; their spelling order must not create another rule.
pub(super) fn normalized_scope<T: std::fmt::Debug>(scope: &[T]) -> Vec<String> {
    let mut values: Vec<_> = scope.iter().map(|v| format!("{v:?}")).collect();
    values.sort();
    values.dedup();
    values
}

pub(super) fn normalized_count_min(value: Option<usize>) -> Option<usize> {
    value.filter(|&n| n != 1)
}

/// Shared predicate representation for exact and scope-only duplicate passes.
/// Inputs have already inherited defaults and expanded file-type groups.
/// Preserve ordered query data and conditional verdicts; normalize only known
/// equivalent spellings. Scope-only grouping omits file types and platforms,
/// but keeps architectures so disjoint CPU-specific rules are never merged.
pub(super) fn atomic_predicate_signature(t: &TraitDefinition, include_scope: bool) -> String {
    format!(
        "{:?}",
        (
            matcher_signature(&t.r#if),
            include_scope.then(|| (normalized_scope(&t.r#for), normalized_scope(&t.platforms))),
            normalized_scope(&t.arch),
            (
                t.size_min,
                t.size_max,
                normalized_count_min(t.count_min),
                t.count_max
            ),
            (t.per_kb_min, t.per_kb_max, t.entropy_min, t.entropy_max),
            (&t.not, &t.unless, &t.downgrade),
        )
    )
}

pub(super) fn architectures_overlap(a: &[Arch], b: &[Arch]) -> bool {
    a.is_empty()
        || b.is_empty()
        || a.contains(&Arch::All)
        || b.contains(&Arch::All)
        || a.iter().any(|arch| b.contains(arch))
}

/// Find shared matchers with overlapping scopes and differing constraints or verdicts.
///
/// Group by normalized `if`, independently of confidence. Then compare effective
/// file/platform/architecture scopes, exclusions, quantitative bounds and verdicts.
/// A shared matcher is a review candidate, not proof that a union of scopes or a
/// downgrade preserves both predicates. Different quantitative observations are
/// retained. Exact and scope-only checks share matcher/default normalization.
///
/// One exception avoids a false positive: the metadata field-presence idiom, where a
/// gate matcher is discriminated purely by `unless:` (e.g. `pkginfo-no-author` vs
/// `pkginfo-no-author-email`). A pair is NOT flagged when both traits are under
/// `metadata/`, they differ only in `unless:`/`downgrade:`, and their local ids differ.
/// Crit/conf/platform mismatches and the same local id duplicated across directories
/// are still flagged, even within `metadata/`.
///
/// Returns: Vec<(trait_id_a, trait_id_b, description)>
#[must_use]
pub(crate) fn find_atomic_logic_duplicates(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, String, String)> {
    let mut duplicates = Vec::new();

    // Group traits by matcher signature only — `crit`, `conf`, `platforms`, `unless`,
    // and `downgrade` are excluded so same-matcher traits group regardless of those.
    let mut groups: HashMap<String, Vec<&TraitDefinition>> = HashMap::new();

    for t in trait_definitions {
        // Matcher only. Size/count/density/entropy bands are scope, not identity:
        // including them split the buckets so that any band difference hid the
        // duplicate entirely (e.g. an identical PE ProductName matcher, one copy
        // size-gated to the real app's range and one not).
        // `not:` is excluded for the same reason as `unless:` — it is a
        // carve-out, not the assertion. Keeping it in the key meant an author
        // who wrote exclusions inline (`not:`) instead of as references
        // (`unless:`) made their trait invisible to this check.
        let signature = matcher_signature(&t.r#if);
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

                // Both must be able to fire on one file: every scope dimension has
                // to overlap. Disjoint scope means two targets, not a duplicate.
                if !file_types_overlap(&a.r#for, &b.r#for) {
                    continue;
                }
                if !architectures_overlap(&a.arch, &b.arch) {
                    continue;
                }
                if !platforms_overlap(&a.platforms, &b.platforms) {
                    continue;
                }
                if !ranges_overlap((a.size_min, a.size_max), (b.size_min, b.size_max)) {
                    continue;
                }
                if !ranges_overlap(
                    (a.entropy_min, a.entropy_max),
                    (b.entropy_min, b.entropy_max),
                ) {
                    continue;
                }
                if !ranges_overlap((a.count_min, a.count_max), (b.count_min, b.count_max)) {
                    continue;
                }
                if !ranges_overlap((a.per_kb_min, a.per_kb_max), (b.per_kb_min, b.per_kb_max)) {
                    continue;
                }

                // Quantitative filters define the observation's precision. A broad
                // matcher and a thresholded matcher may overlap in their accepted
                // values, but they are intentionally different features (for example,
                // "contains a PE resource" versus "contains at least three PE
                // resources"). Forcing those into one trait plus a downgrade would
                // erase the threshold and reduce both analyst and ML signal. Only
                // compare metadata when the complete quantitative scope is identical.
                // `count_min: 1` is the default and carries no additional precision,
                // so normalize that spelling before comparing scopes.
                let a_count_min = normalized_count_min(a.count_min);
                let b_count_min = normalized_count_min(b.count_min);
                let bands_differ = a.size_min != b.size_min
                    || a.size_max != b.size_max
                    || a_count_min != b_count_min
                    || a.count_max != b.count_max
                    || a.per_kb_min != b.per_kb_min
                    || a.per_kb_max != b.per_kb_max
                    || a.entropy_min != b.entropy_min
                    || a.entropy_max != b.entropy_max;
                if bands_differ {
                    continue;
                }

                let crit_differs = !criticalities_equivalent(a.crit, b.crit);
                // A `not:` difference with a different `crit:` is a deliberate
                // specialization — a generic matcher beside a narrowed one that
                // says something stronger. Only a `not:` difference at the SAME
                // criticality is two spellings of one assertion.
                let not_differs = format!("{:?}", a.not) != format!("{:?}", b.not);
                if not_differs && crit_differs {
                    continue;
                }
                let conf_differs = a.conf != b.conf;
                let file_types_differ = normalized_scope(&a.r#for) != normalized_scope(&b.r#for);
                let arch_differs = normalized_scope(&a.arch) != normalized_scope(&b.arch);
                let platforms_differ = !platforms_equivalent(&a.platforms, &b.platforms);
                let unless_differs = format!("{:?}", a.unless) != format!("{:?}", b.unless);
                let downgrade_differs =
                    format!("{:?}", a.downgrade) != format!("{:?}", b.downgrade);
                if !crit_differs
                    && !not_differs
                    && !conf_differs
                    && !file_types_differ
                    && !arch_differs
                    && !platforms_differ
                    && !unless_differs
                    && !downgrade_differs
                    && !bands_differ
                {
                    // Everything outside the matcher is the same too — an exact
                    // duplicate handled by the exact-duplicate checks, not this one.
                    continue;
                }

                // The metadata field-presence idiom: distinct metadata traits sharing a
                // matcher, discriminated purely by `unless:` field checks —
                // `pkginfo-no-author` (`unless: author present`) vs
                // `pkginfo-no-author-email` (`unless: author-email present`). Those are
                // distinct detections, not duplicates, so skip a metadata pair with
                // distinct local ids that differs in `unless:`/`downgrade:`. When the
                // shared matcher is a bare existence gate (matches the whole file class),
                // criticality may legitimately vary per field, so tolerate crit/conf/
                // platform differences too; otherwise require them to match (so a real
                // inconsistency like `textrel` vs `text-relocations` still flags). The
                // same local id across directories is always a copy-paste — never skipped.
                let exceptions_differ = unless_differs || downgrade_differs;
                let only_exceptions_differ = exceptions_differ
                    && !crit_differs
                    && !conf_differs
                    && !file_types_differ
                    && !arch_differs
                    && !platforms_differ
                    && !bands_differ;
                let both_metadata = a.id.starts_with("metadata/") && b.id.starts_with("metadata/");
                let same_local_id = a.id.rsplit("::").next() == b.id.rsplit("::").next();
                // A bare existence-gate matcher discriminated by `unless:` is the
                // field-presence idiom wherever it is filed, so its per-field crit
                // variation is legitimate. The looser metadata-only allowance (skip when
                // only `unless:`/`downgrade:` differs) still requires both under metadata/.
                if !same_local_id
                    && exceptions_differ
                    && (is_existence_gate(&a.r#if) || (both_metadata && only_exceptions_differ))
                {
                    continue;
                }

                // Build description of the difference
                let mut diffs = Vec::new();
                if crit_differs {
                    diffs.push(format!("crit: {:?} vs {:?}", a.crit, b.crit));
                }
                if conf_differs {
                    diffs.push(format!("conf: {} vs {}", a.conf, b.conf));
                }
                if file_types_differ {
                    diffs.push(format!("for: {:?} vs {:?}", a.r#for, b.r#for));
                }
                if arch_differs {
                    diffs.push(format!("arch: {:?} vs {:?}", a.arch, b.arch));
                }
                if platforms_differ {
                    diffs.push(format!("platforms: {:?} vs {:?}", a.platforms, b.platforms));
                }
                if bands_differ {
                    let mut bands = Vec::new();
                    if a.size_min != b.size_min || a.size_max != b.size_max {
                        bands.push(format!(
                            "size {:?}..{:?} vs {:?}..{:?}",
                            a.size_min, a.size_max, b.size_min, b.size_max
                        ));
                    }
                    if a.count_min != b.count_min || a.count_max != b.count_max {
                        bands.push(format!(
                            "count {:?}..{:?} vs {:?}..{:?}",
                            a.count_min, a.count_max, b.count_min, b.count_max
                        ));
                    }
                    if a.per_kb_min != b.per_kb_min || a.per_kb_max != b.per_kb_max {
                        bands.push(format!(
                            "per_kb {:?}..{:?} vs {:?}..{:?}",
                            a.per_kb_min, a.per_kb_max, b.per_kb_min, b.per_kb_max
                        ));
                    }
                    if a.entropy_min != b.entropy_min || a.entropy_max != b.entropy_max {
                        bands.push(format!(
                            "entropy {:?}..{:?} vs {:?}..{:?}",
                            a.entropy_min, a.entropy_max, b.entropy_min, b.entropy_max
                        ));
                    }
                    diffs.push(format!("overlapping bands — {}", bands.join("; ")));
                }
                if not_differs {
                    // Same criticality, so this is one assertion with drifted
                    // carve-outs rather than a deliberate narrowing.
                    diffs.push("not: differs at the same crit:".to_string());
                }
                if unless_differs {
                    diffs.push("unless: differs".to_string());
                }
                if downgrade_differs {
                    diffs.push("downgrade: differs".to_string());
                }

                // When the only differences are criticality and/or exceptions, the pair
                // is a single detection split in two — recommend collapsing it.
                let mergeable_via_downgrade =
                    crit_differs || unless_differs || downgrade_differs || bands_differ;
                let recommendation = if mergeable_via_downgrade {
                    " — review consolidation; preserve exclusions and conditional downgrade: behavior"
                } else {
                    ""
                };

                let for_a: Vec<_> = a.r#for.iter().map(|f| format!("{f:?}")).collect();
                let for_b: Vec<_> = b.r#for.iter().map(|f| format!("{f:?}")).collect();
                let desc = format!(
                    "Same normalized matcher, overlapping types ({}∩{}), but: {}{}",
                    for_a.join(","),
                    for_b.join(","),
                    diffs.join(", "),
                    recommendation
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
            Condition::Raw(RawQuery { regex: Some(r), .. })
            | Condition::Symbol(SymbolQuery { regex: Some(r), .. })
            | Condition::Text(TextQuery { regex: Some(r), .. })
            | Condition::Literal(LiteralQuery { regex: Some(r), .. })
            | Condition::Path(PathQuery { regex: Some(r), .. })
            | Condition::Encoded(EncodedQuery { regex: Some(r), .. }) => Some(r.clone()),
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
    let Some(prefix_regex) = prefix_regex() else {
        return vec![];
    };

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
pub(super) fn extract_match_signature(condition: &Condition) -> Option<(bool, MatchSignature)> {
    match condition {
        Condition::Text(TextQuery {
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
        }) => Some((
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
        Condition::Raw(RawQuery {
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
        }) => Some((
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

pub(super) fn prefix_regex() -> Option<&'static regex::Regex> {
    static_regex!(r"^(\^?)([a-zA-Z_][a-zA-Z0-9_-]*)(.*)$")
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
        if let Condition::Path(PathQuery {
            exact,
            substr,
            regex,
            case_insensitive,
            ..
        }) = &trait_def.r#if
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

/// Reduce a regex to its structural shape: replace each character class with a
/// canonical `[CC]` (positive) or `[NCC]` (negative) placeholder so two patterns
/// that differ only in the contents of a character class collapse to the same
/// string. Escapes are preserved verbatim, everything else is left alone.
pub(super) fn structural_shape(pattern: &str) -> String {
    let bytes = pattern.as_bytes();
    let mut out = String::with_capacity(pattern.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'\\' && i + 1 < bytes.len() {
            out.push('\\');
            out.push(bytes[i + 1] as char);
            i += 2;
            continue;
        }
        if b == b'[' {
            // Walk forward to the matching unescaped ']'.
            let mut j = i + 1;
            let negative = j < bytes.len() && bytes[j] == b'^';
            while j < bytes.len() && bytes[j] != b']' {
                if bytes[j] == b'\\' && j + 1 < bytes.len() {
                    j += 2;
                } else {
                    j += 1;
                }
            }
            if j >= bytes.len() {
                // Unterminated class — bail and keep original.
                return pattern.to_string();
            }
            out.push_str(if negative { "[NCC]" } else { "[CC]" });
            i = j + 1;
            continue;
        }
        out.push(b as char);
        i += 1;
    }
    out
}

/// Strip a trivial leading boundary guard from a structurally-shaped pattern
/// so `\beval`, `(^|[NCC])eval`, `(?:^|\s)eval` and friends all collapse to
/// just `eval` for shape comparison.
pub(super) fn strip_leading_boundary(s: &str) -> &str {
    // Matches: \b | ^ | (^|X) | (?:^|X)
    // X is a single char class placeholder, escape, or literal up to 8 chars
    // (long enough to cover [NCC]/[CC]/\s/\W/\b/[!/]/etc., short enough to
    // avoid eating real content).
    if let Some(re) = static_regex!(r"^(?:\\b|\^|\(\?:\^\|[^()]{1,8}\)|\(\^\|[^()]{1,8}\))")
        && let Some(m) = re.find(s)
    {
        return &s[m.end()..];
    }
    s
}

/// Strip a leading inline-flag block like `(?i)`, `(?is)`, `(?-i)` so flag-only
/// differences don't prevent shape collapse.
pub(super) fn strip_leading_flags(s: &str) -> &str {
    let re = static_regex!(r"^\(\?[a-zA-Z\-]{1,8}\)");
    if let Some(re) = re
        && let Some(m) = re.find(s)
    {
        return &s[m.end()..];
    }
    s
}

/// Detect atomic regex traits whose patterns are structurally identical except
/// for the inside of a character class — almost certainly the same intent
/// expressed twice.
///
/// Catches cases like:
///   - `(^|[^\w$])eval\s*\(` vs `(^|[^\w$.])eval\s*\(` — leading guard differs
///     by one character; both fire on the same `eval(` calls.
///   - `eval\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)` vs the `_dup` variant
///     without `$` in the identifier class — same shape.
///
/// Only same-tier (criticality_for_overlap), overlapping-for-types pairs are
/// flagged. Component/Baseline/Filtered are skipped because those are
/// deliberately reusable building blocks.
pub(crate) fn find_structural_regex_duplicates(
    trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    /// Body scope: text and string_literal collapse together (the latter is a
    /// strict subset of the former for matching purposes), raw is binary, and
    /// symbol matches in the symbol table.
    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    enum Scope {
        Body,
        Raw,
        Symbol,
    }

    struct Entry {
        location: PatternLocation,
        scope: Scope,
    }

    let mut entries: Vec<Entry> = Vec::new();

    for trait_def in trait_definitions {
        // Skip building-block tiers — they're meant to be reused.
        if matches!(
            criticality_for_overlap(trait_def.crit),
            Criticality::Baseline
        ) {
            continue;
        }

        let (regex_opt, scope, condition_type) = match &trait_def.r#if {
            Condition::Text(TextQuery { regex, .. }) => (regex.as_ref(), Scope::Body, "text"),
            Condition::Literal(LiteralQuery { regex, .. }) => {
                (regex.as_ref(), Scope::Body, "string_literal")
            }
            Condition::Raw(RawQuery { regex, .. }) => (regex.as_ref(), Scope::Raw, "raw"),
            Condition::Symbol(SymbolQuery { regex, .. }) => {
                (regex.as_ref(), Scope::Symbol, "symbol")
            }
            _ => continue,
        };
        let Some(regex) = regex_opt else { continue };

        let for_types: HashSet<String> = trait_def
            .r#for
            .iter()
            .map(|ft| format!("{:?}", ft).to_lowercase())
            .collect();

        let section = if let Condition::Raw(RawQuery { section, .. }) = &trait_def.r#if {
            section.clone()
        } else {
            None
        };

        entries.push(Entry {
            location: PatternLocation {
                trait_id: trait_def.id.clone(),
                file_path: trait_def.defined_in.to_string_lossy().to_string(),
                condition_type: condition_type.to_string(),
                match_type: "regex".to_string(),
                encoding: None,
                original_value: regex.clone(),
                // The callee regex and its structured predicates name a fact.
                // Reuse the same discriminator as the other duplicate checks.
                discriminator: if scope == Scope::Symbol {
                    extract_patterns(trait_def)
                        .into_iter()
                        .find(|(_, p)| p.condition_type == "symbol" && p.match_type == "regex")
                        .map(|(_, p)| p.discriminator)
                        .unwrap_or_default()
                } else {
                    String::new()
                },
                bare_normalized: regex.clone(),
                suppressed_by: Vec::new(),
                for_types,
                section,
                count_min: trait_def.count_min,
                count_max: trait_def.count_max,
                per_kb_min: trait_def.per_kb_min,
                per_kb_max: trait_def.per_kb_max,
                confidence: trait_def.conf,
                criticality: trait_def.crit,
            },
            scope,
        });
    }

    // Compute the canonical shape for each entry.
    let shapes: Vec<String> = entries
        .iter()
        .map(|e| {
            let raw = structural_shape(&e.location.original_value);
            let no_flags = strip_leading_flags(&raw);
            let no_lead = strip_leading_boundary(no_flags);
            // Trailing trivial anchors / boundaries.
            let no_trail_anchor = if no_lead.ends_with('$') && !no_lead.ends_with("\\$") {
                &no_lead[..no_lead.len() - 1]
            } else {
                no_lead
            };
            let no_trail = no_trail_anchor
                .strip_suffix("\\b")
                .unwrap_or(no_trail_anchor);
            no_trail.to_string()
        })
        .collect();

    // Group by (shape, scope, crit_tier). Skip groups whose shape is too short
    // to be a meaningful structural match.
    let mut groups: HashMap<(String, Scope, String), Vec<usize>> = HashMap::new();
    for (idx, e) in entries.iter().enumerate() {
        let shape = &shapes[idx];
        // Count alphanumeric/underscore bytes outside `[...]` placeholders and
        // outside `\<x>` escape sequences. Two patterns sharing only the
        // placeholders produce trivial collisions, so require real literal
        // anchoring to bucket.
        let mut literal_bytes = 0usize;
        let bytes = shape.as_bytes();
        let mut k = 0;
        while k < bytes.len() {
            let b = bytes[k];
            if b == b'\\' && k + 1 < bytes.len() {
                k += 2;
                continue;
            }
            if b == b'[' {
                while k < bytes.len() && bytes[k] != b']' {
                    k += 1;
                }
                if k < bytes.len() {
                    k += 1;
                }
                continue;
            }
            if b.is_ascii_alphanumeric() || b == b'_' {
                literal_bytes += 1;
            }
            k += 1;
        }
        if literal_bytes < 4 {
            continue;
        }
        let crit_key = format!("{:?}", criticality_for_overlap(e.location.criticality));
        let key = (shape.clone(), e.scope, crit_key);
        groups.entry(key).or_default().push(idx);
    }

    let mut seen: FxHashSet<(String, String)> = FxHashSet::default();
    for ((shape, _scope, _tier), indices) in groups {
        if indices.len() < 2 {
            continue;
        }
        for i in 0..indices.len() {
            for j in (i + 1)..indices.len() {
                let a = &entries[indices[i]].location;
                let b = &entries[indices[j]].location;

                if a.discriminator != b.discriminator {
                    continue;
                }
                if a.original_value == b.original_value {
                    // Already caught by find_duplicate_traits_and_composites.
                    continue;
                }
                if !has_filetype_overlap(a, b) {
                    continue;
                }
                if a.section.is_some() && b.section.is_some() && a.section != b.section {
                    continue;
                }
                if !has_same_count_density_filters(a, b) {
                    continue;
                }

                let key_a = format!("{}::{}", a.file_path, a.trait_id);
                let key_b = format!("{}::{}", b.file_path, b.trait_id);
                let key = if key_a <= key_b {
                    (key_a.clone(), key_b.clone())
                } else {
                    (key_b.clone(), key_a.clone())
                };
                if !seen.insert(key) {
                    continue;
                }

                warnings.push(format!(
                    "Structurally duplicate regex (same shape, same crit tier, overlapping file types):\n   {}::{} ({}) => {}\n   {}::{} ({}) => {}\n   shape: {}\n   → Action: keep one or split the intent into orthogonal patterns",
                    a.file_path,
                    a.trait_id,
                    a.condition_type,
                    a.original_value,
                    b.file_path,
                    b.trait_id,
                    b.condition_type,
                    b.original_value,
                    shape,
                ));
            }
        }
    }

    let dups_found = warnings.len() - initial_warning_count;
    tracing::debug!(
        "Structural regex duplicate detection completed in {:?} ({} duplicates found)",
        start.elapsed(),
        dups_found
    );
}

/// Composites with identical evidence whose scopes overlap.
///
/// `for-only-duplicates` covers traits, and keys on `platforms:`, so it can only
/// ever report a `for:` difference on an atomic. Neither limit is principled:
/// two *composites* built from the same legs, differing only in `for:` or
/// `platforms:`, both fire on any file in the intersection.
///
/// Whether their criticalities agree decides what the author is being told:
///
/// - same `crit:` — one finding reported twice, so merge the scopes.
/// - different `crit:` — the same evidence convicts at two tiers, and which one
///   a reader sees depends on which rule they happen to look at.
///   `reverse-shell-mkfifo` (hostile) and `mkfifo-netcat-shell` (suspicious)
///   share all three legs and both match a unix shell script.
///
/// Returns `(id a, id b, crit a, crit b, same_crit)`.
pub(crate) fn find_overlapping_scope_duplicates(
    composite_rules: &[CompositeTrait],
) -> Vec<(String, String, String, String, bool)> {
    let mut groups: HashMap<String, Vec<&CompositeTrait>> = HashMap::new();
    for rule in composite_rules {
        let legs = |conds: Option<&Vec<Condition>>| -> Vec<String> {
            let mut v: Vec<String> = conds
                .into_iter()
                .flatten()
                .map(|c| format!("{c:?}"))
                .collect();
            v.sort();
            v
        };
        // Evidence only: what the rule looks for, and what suppresses it.
        // `scope`, `downgrade`, `near_bytes`/`near_lines` and `size_min`/
        // `size_max` all change what "the same evidence" means: two rules
        // sharing every leg but pooling from a different scope draw on
        // different evidence (`pkgsrc-maintainer-archive-context`,
        // `scope: outer`, is not a duplicate of a file-scoped sibling that
        // happens to share legs), a `downgrade:` changes the verdict the
        // shared evidence produces (`excessive-line-length-large-pe` vs
        // `...-protobuf-text` differ only in this), and a proximity or size
        // gate narrows which files the shared legs actually convict.
        let downgrade_sig = |d: Option<&DowngradeConditions>| {
            d.map(|dg| {
                format!(
                    "{:?}|{:?}|{:?}",
                    legs(dg.all.as_ref()),
                    legs(dg.any.as_ref()),
                    dg.needs,
                )
            })
        };
        let signature = format!(
            "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
            legs(rule.all.as_ref()),
            legs(rule.any.as_ref()),
            rule.needs,
            legs(rule.unless.as_ref()),
            rule.not,
            rule.scope,
            downgrade_sig(rule.downgrade.as_ref()),
            rule.near_bytes,
            rule.near_lines,
            (rule.size_min, rule.size_max),
        );
        if rule.all.is_none() && rule.any.is_none() {
            continue;
        }
        groups.entry(signature).or_default().push(rule);
    }

    let mut found = Vec::new();
    for rules in groups.values() {
        for (i, a) in rules.iter().enumerate() {
            for b in &rules[i + 1..] {
                if !platforms_overlap(&a.platforms, &b.platforms)
                    || !file_types_overlap(&a.r#for, &b.r#for)
                {
                    continue;
                }
                // An exception is a suppressor, not a finding -- it never
                // surfaces on its own, so "two findings report the same
                // evidence" is false whenever either side is one.
                if a.crit == Criticality::Exception || b.crit == Criticality::Exception {
                    continue;
                }
                found.push((
                    a.id.clone(),
                    b.id.clone(),
                    format!("{:?}", a.crit).to_lowercase(),
                    format!("{:?}", b.crit).to_lowercase(),
                    a.crit == b.crit,
                ));
            }
        }
    }
    found
}
