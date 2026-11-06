//! Overlap checks between the patterns of one matcher type.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Check for regex patterns with | (OR) that overlap with standalone exact/word/substr patterns.
pub(crate) fn check_regex_or_overlapping_exact(
    patterns: &ExtractedPatterns,
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    fn trait_dir(id: &str) -> &str {
        id.split_once("::").map_or(id, |(dir, _)| dir)
    }

    // Collect all regex patterns with | (OR operators), and all
    // exact/word/substr patterns.
    let mut regex_patterns: Vec<&PatternLocation> = Vec::new();
    let mut literal_patterns: HashMap<&str, Vec<&PatternLocation>> = HashMap::new();

    for (normalized, location) in &patterns.0 {
        if location.match_type != "regex" {
            literal_patterns
                .entry(normalized)
                .or_default()
                .push(location);
        } else if location.original_value.contains('|') {
            regex_patterns.push(location);
        }
    }

    // Check each regex OR pattern against all literals
    for regex_loc in regex_patterns {
        let regex_value = &regex_loc.original_value;
        // Split the regex on top-level | only (not inside parentheses/brackets)
        let alternatives: Vec<&str> = split_top_level_alternation(regex_value);

        let mut overlapping_literals: Vec<(String, Vec<String>)> = Vec::new();

        for alternative in alternatives {
            // Normalize the alternative (strip anchors)
            let normalized_alt = normalize_regex(alternative);
            if normalized_alt.len() < 8 {
                continue;
            }

            // Check if this alternative exists as a literal pattern elsewhere
            if let Some(literal_locs) = literal_patterns.get(normalized_alt.as_str()) {
                // Only report local taxonomy overlap. Cross-directory literal
                // reuse is handled by broader duplicate-pattern validators; this
                // check is for alternatives that should be split/reused inside
                // the same trait directory.
                let overlapping_files: Vec<String> = literal_locs
                    .iter()
                    .filter(|loc| {
                        loc.file_path != regex_loc.file_path
                            && trait_dir(&loc.trait_id) == trait_dir(&regex_loc.trait_id)
                            && has_filetype_overlap(loc, regex_loc)
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
    patterns: &ExtractedPatterns,
    warnings: &mut Vec<String>,
) {
    use rayon::prelude::*;

    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // Collect all regex patterns with their pre-computed alternatives
    struct RegexWithAlternatives<'a> {
        location: &'a PatternLocation,
        source_len: usize,
        alternatives: FxHashSet<String>,
        /// HIR-canonical form of the whole pattern (`None` if it does not parse).
        /// Equal canonical forms mean the two regexes match the same language.
        canonical: Option<String>,
        has_alternation: bool,
    }

    // Comparison key for one top-level alternative: its HIR-canonical form when
    // the branch parses on its own, else the textually-normalized fallback. Two
    // branches that mean the same thing (`\d{3}` and `[0-9]{3}`) share a key.
    // A branch that is the whole pattern takes the pattern's own form rather
    // than parsing it again.
    let alternative_key = |branch: &str, whole: &str, whole_form: &Option<String>| {
        let branch = branch.trim();
        let normalized = normalize_regex(branch);
        if !meaningful_regex_alternative(&normalized) {
            return None;
        }
        let form = if branch == whole {
            whole_form.clone()
        } else {
            canonical_regex_form(branch)
        };
        Some(form.unwrap_or(normalized))
    };

    // Parsing every regex is most of this check, and each one parses on its
    // own, so they are done in parallel; `collect` keeps them in trait order.
    let regex_patterns: Vec<RegexWithAlternatives<'_>> = patterns
        .0
        .par_iter()
        .map(|(_, location)| location)
        .filter(|location| location.match_type == "regex")
        .map(|location| {
            let whole = location
                .original_value
                .strip_suffix(&location.discriminator)
                .unwrap_or(&location.original_value)
                .trim();
            let canonical = canonical_regex_form(whole);
            let key = |branch: &str| alternative_key(branch, whole, &canonical);

            // Pre-compute canonical keys for each meaningful alternative.
            let alts: FxHashSet<String> = split_top_level_alternation(whole)
                .into_iter()
                .filter_map(key)
                .collect();

            // If no alternatives, key on the whole pattern instead.
            let alternatives = if alts.is_empty() {
                let mut set = FxHashSet::default();
                if let Some(key) = key(whole) {
                    set.insert(key);
                }
                set
            } else {
                alts
            };

            let has_alternation = whole.contains('|');
            RegexWithAlternatives {
                location,
                source_len: whole.len(),
                alternatives,
                canonical,
                has_alternation,
            }
        })
        .collect();

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

        // Regex overlap is only actionable when both patterns search the same
        // extractor surface. A decoded `encoded` regex and a `text` regex can
        // share syntax without being duplicate work.
        if a.location.condition_type != b.location.condition_type {
            continue;
        }

        if a.location.discriminator != b.location.discriminator {
            continue;
        }

        if a.location.encoding.is_some()
            && b.location.encoding.is_some()
            && a.location.encoding != b.location.encoding
        {
            continue;
        }

        // Must overlap in filetype scope to be a real conflict.
        if !has_filetype_overlap(a.location, b.location) {
            continue;
        }

        // Different count/per-kb thresholds are intentionally layered evidence.
        if !has_same_count_density_filters(a.location, b.location) {
            continue;
        }

        // Dedup key for this trait pair, shared by both overlap signals below.
        let key_a = format!("{}::{}", a.location.file_path, a.location.trait_id);
        let key_b = format!("{}::{}", b.location.file_path, b.location.trait_id);
        let key = if key_a <= key_b {
            (key_a, key_b)
        } else {
            (key_b, key_a)
        };

        // Strongest signal: the two regexes describe the same language written
        // differently (`\d{3}` vs `[0-9]{3}`, `gr[ae]y` vs `gr[ea]y`). Their HIR
        // canonical forms are equal, so this is a genuine duplicate regardless of
        // textual length — the different-specificity length allowance applied to
        // partial overlaps below does not apply here.
        if let (Some(ca), Some(cb)) = (a.canonical.as_deref(), b.canonical.as_deref())
            && ca == cb
        {
            if seen_pairs.insert(key) {
                warnings.push(format!(
                    "Structurally identical regex patterns (same match, different spelling) with overlapping file types:\n   {}::{} => {}\n   {}::{} => {}\n   canonical form: {}",
                    a.location.file_path,
                    a.location.trait_id,
                    a.location.original_value,
                    b.location.file_path,
                    b.location.trait_id,
                    b.location.original_value,
                    ca
                ));
            }
            continue;
        }

        // Otherwise look for a partial overlap: a shared meaningful alternative.
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
        let max_len = a.source_len.max(b.source_len);
        let len_diff_pct = if max_len > 0 {
            (a.source_len as f32 - b.source_len as f32).abs() / max_len as f32
        } else {
            0.0
        };

        // Skip if significantly different length and at least one has no alternation
        if len_diff_pct > 0.33 && (!a.has_alternation || !b.has_alternation) {
            continue;
        }

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
    patterns: &ExtractedPatterns,
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    for (_, location) in &patterns.0 {
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
    patterns: &ExtractedPatterns,
    warnings: &mut Vec<String>,
) {
    let start = std::time::Instant::now();
    let initial_warning_count = warnings.len();

    // Build index: normalized_pattern -> Vec<PatternLocation> grouped by type
    let mut pattern_by_type: HashMap<&str, HashMap<&str, Vec<&PatternLocation>>> = HashMap::new();

    for (_normalized, location) in &patterns.0 {
        // Only compare matcher families that can reasonably be canonicalized
        // as alternate spellings of the same search surface. `encoded` and
        // `basename` are intentionally different scopes.
        if !is_cross_type_canonicalization_candidate(location.condition_type.as_str()) {
            continue;
        }

        // Bucket on the literal alone. Keying on the full pattern hid every
        // symbol matcher that sets `kind:`/`arg:` from its text and raw
        // counterparts: `symbol {kind: call, exact: file_put_contents}` was
        // keyed as `file_put_contents#kind:call` and so never shared a
        // bucket with `text {word: file_put_contents}`.
        pattern_by_type
            .entry(&location.bare_normalized)
            .or_default()
            .entry(&location.condition_type)
            .or_default()
            .push(location);
    }

    // Find patterns that appear with multiple types
    for (pattern, types_map) in pattern_by_type {
        if types_map.len() < 2 {
            continue; // Only one type, no issue
        }

        // Check if any pair of different types has file type overlap
        let all_locations: Vec<&PatternLocation> = types_map.values().flatten().copied().collect();

        let mut has_overlap = false;
        'outer: for i in 0..all_locations.len() {
            for j in (i + 1)..all_locations.len() {
                // Same literal searched two different ways (e.g. `raw` vs `text`,
                // or `text` vs `symbol`) with overlapping file types is a
                // duplicate the analyst must collapse — regardless of which file
                // each trait lives in. Gate on file-type overlap AND section
                // scope: a section-scoped matcher (e.g. text in `.rdata`) is not
                // interchangeable with an unscoped one, per the same
                // `section_scope_equivalent` convention used by
                // matcher_context_reusable_as_is / exact_substr_context_reusable_as_is.
                if all_locations[i].condition_type != all_locations[j].condition_type
                    && !either_suppresses_the_other(all_locations[i], all_locations[j])
                    && literal_reach_is_equivalent(
                        &all_locations[i].match_type,
                        &all_locations[j].match_type,
                    )
                    && section_scope_equivalent(
                        all_locations[i].section.as_deref(),
                        all_locations[j].section.as_deref(),
                    )
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
                        format!(
                            "{}::{} ({} {}, for: {})",
                            loc.file_path,
                            loc.trait_id,
                            loc.condition_type,
                            loc.match_type,
                            for_str
                        )
                    })
                    .collect();
                format!("   type: {} in: {}", type_name, location_strs.join(", "))
            })
            .collect();

        // Prefer the more precise surface: a symbol or a language literal says
        // the token was *used*, where text and raw only say the bytes appear.
        // Collapsing to the precise atom is the Single-Trait Rule applied to
        // matchers. The exception is real coverage: a stripped binary keeps the
        // string and loses the symbol, and a `for:` list can name types the
        // precise surface cannot parse -- there, both atoms earn their place as
        // `component` legs of one `any:` composite, which counts the evidence
        // once and leaves a single ML feature.
        warnings.push(format!(
            "Pattern '{}' is searched on multiple surfaces with overlapping file type coverage — keep the more precise surface (symbol or literal over text or raw) and reference it; keep both only when each surface reaches files the other cannot, as `component` legs of one `any:` composite:\n{}",
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

/// A phrase this many same-context, same-tier regexes also match is reported.
///
/// Four is where the observed distribution turns over: sampling `text`/`notable`
/// phrases, coverage runs 9, 5, 5, 4, 4, 4, 4 and then falls straight to 3, so a
/// lower bound catches the ordinary case of two or three rules legitimately
/// sharing a token, while a higher one drops the knee.
pub(super) const MAX_REGEXES_COVERING_A_LITERAL: usize = 4;

/// Patterns per combined automaton before the first attempt. Chosen as the
/// widest batch that compiles across this tree's buckets; a batch that still
/// overflows is halved, so this is a starting point rather than a limit.
pub(super) const REGEX_SET_START_WIDTH: usize = 256;

/// Compiled-size ceiling for one combined automaton. The set is split in half
/// and retried whenever a batch exceeds it, so this bounds peak memory rather
/// than deciding how many patterns go in a set.
pub(super) const REGEX_SET_SIZE_LIMIT: usize = 64 * 1024 * 1024;

/// Report literal phrases that several regexes in the same matcher context and
/// criticality tier already match.
///
/// When four or more regexes match a `word`/`exact`/`substr` phrase, the rule
/// set has grown around the same evidence from both directions: the phrase is
/// covered several times over, and whichever side is redundant, the file is
/// paying for all of it. Which side to keep is a taxonomy question — sometimes
/// the literal is the canonical atom and the regexes are an over-split
/// alternation, sometimes the reverse — so the report names both and leaves the
/// direction to the author.
///
/// Cost: the naive shape is every regex against every phrase, which is ~291M
/// executions over this tree. Compiling each bucket into one `RegexSet` and
/// running each phrase through it once makes it one pass per distinct phrase
/// (~28k), because `matches` returns every hit in a single scan. The crate's
/// own Aho-Corasick prefilter over required literals does the skipping, so
/// there is no hand-rolled prefilter here.
///
/// Deliberately conservative: the phrase is tested as written, wrapped in
/// newlines so `(?m)^…$` anchors behave. A regex needing context the phrase
/// does not carry (`\bfoo\b[^\n]{0,80}bar`) is not counted even though both
/// rules would fire on a real file, and a case-insensitive literal is not
/// lowercased to meet a case-sensitive regex. Both would trade a real reading
/// for a guess.
pub(crate) fn find_literals_covered_by_regexes(
    patterns: &ExtractedPatterns,
    warnings: &mut Vec<String>,
) {
    use rayon::prelude::*;

    let start = std::time::Instant::now();

    // Bucket by (matcher context, overlap tier): a regex can only stand in for a
    // literal if it searches the same surface at the same signal strength.
    let mut regexes: BTreeMap<(&str, Criticality), Vec<&PatternLocation>> = BTreeMap::new();
    let mut literals: BTreeMap<(&str, Criticality), BTreeMap<&str, Vec<&PatternLocation>>> =
        BTreeMap::new();

    for (_, location) in &patterns.0 {
        let key = (
            location.condition_type.as_str(),
            criticality_for_overlap(location.criticality),
        );
        match location.match_type.as_str() {
            "regex" => regexes.entry(key).or_default().push(location),
            "exact" | "word" | "substr" => literals
                .entry(key)
                .or_default()
                .entry(&location.original_value)
                .or_default()
                .push(location),
            _ => {}
        }
    }

    // Buckets are independent and the findings are sorted before they are
    // reported, so the buckets run in parallel.
    let mut findings: Vec<String> = literals
        .par_iter()
        .flat_map_iter(|(key, phrase_map)| match regexes.get(key) {
            Some(bucket) if bucket.len() >= MAX_REGEXES_COVERING_A_LITERAL => {
                literal_coverage_in_bucket(key, phrase_map, bucket)
            }
            _ => Vec::new(),
        })
        .collect();

    findings.sort();
    warnings.extend(findings);

    tracing::debug!(
        "Literal-coverage detection completed in {:?}",
        start.elapsed()
    );
}

/// Literal-coverage findings for one (matcher context, tier) bucket.
pub(super) fn literal_coverage_in_bucket(
    key: &(&str, Criticality),
    phrase_map: &BTreeMap<&str, Vec<&PatternLocation>>,
    bucket: &[&PatternLocation],
) -> Vec<String> {
    use rayon::prelude::*;

    let mut findings: Vec<String> = Vec::new();

    // Gate on mandatory atoms instead of running every regex against every
    // phrase. `mandatory_atom_set` returns literals such that any match is
    // guaranteed to contain at least one of them, so an Aho-Corasick pass
    // over the phrase names the only regexes that can possibly match it.
    // Patterns the engine rejects (lookaround, backreferences) are already
    // reported by `incompatible-regex`; skipping them keeps this check from
    // failing on a problem that has its own message.
    // Parse the HIR rather than compiling: this only needs to know whether
    // the engine accepts the pattern, and compiling every pattern in the
    // bucket to throw the result away costs more than the rest of the check.
    // Whether the engine accepts a pattern depends on the pattern alone, and
    // whether a regex matches a phrase (below) on the two alone, so during a
    // full validation an earlier run's verdicts stand (see `facts_cache`):
    // parsing again, mostly case-folding `(?i)` classes, was most of a warm
    // run's cost.
    let facts = super::super::facts_cache::active();
    let compilable: Vec<&PatternLocation> = bucket
        .par_iter()
        .copied()
        .filter(|location| {
            let pattern = &location.original_value;
            let parses = || {
                regex_syntax::ParserBuilder::new()
                    .build()
                    .parse(pattern)
                    .is_ok()
            };
            match &facts {
                Some(facts) => facts.memoized(
                    super::super::facts_cache::key("regex-parses", &[pattern.as_bytes()]),
                    parses,
                ),
                None => parses(),
            }
        })
        .collect();

    let mut atoms: Vec<String> = Vec::new();
    let mut atom_owners: Vec<Vec<usize>> = Vec::new();
    let mut ci_atoms: Vec<String> = Vec::new();
    let mut ci_owners: Vec<Vec<usize>> = Vec::new();
    let mut ungated: Vec<usize> = Vec::new();
    let mut by_atom: HashMap<(String, bool), usize> = HashMap::new();
    let atom_sets: Vec<Option<Vec<(String, bool)>>> = compilable
        .par_iter()
        .map(|location| {
            crate::capabilities::derivation_memo::mandatory_atom_set(&location.original_value)
        })
        .collect();
    for (idx, atom_set) in atom_sets.into_iter().enumerate() {
        match atom_set {
            Some(set) if !set.is_empty() => {
                for (atom, case_insensitive) in set {
                    let slot = *by_atom
                        .entry((atom.clone(), case_insensitive))
                        .or_insert_with(|| {
                            if case_insensitive {
                                ci_atoms.push(atom.clone());
                                ci_owners.push(Vec::new());
                                ci_owners.len() - 1
                            } else {
                                atoms.push(atom.clone());
                                atom_owners.push(Vec::new());
                                atom_owners.len() - 1
                            }
                        });
                    if case_insensitive {
                        ci_owners[slot].push(idx);
                    } else {
                        atom_owners[slot].push(idx);
                    }
                }
            }
            // No guaranteed atom (a leading `.*`, an inextractable branch):
            // this one has to be tried against every phrase.
            _ => ungated.push(idx),
        }
    }

    let literal_gate = aho_corasick::AhoCorasick::new(&atoms).ok();
    let ci_gate = aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(&ci_atoms)
        .ok();

    // Gate every phrase first -- two Aho-Corasick passes each -- then turn
    // the candidate lists around, so each regex is compiled once and run by
    // one thread over just the phrases that can hold it. Matching phrase by
    // phrase ran each candidate from whichever thread held the phrase, and a
    // thread's first use of a regex builds its own lazy-DFA cache: over this
    // tree's ~15k text phrases that was most of the check.
    let phrases: Vec<(&str, &Vec<&PatternLocation>)> = phrase_map
        .iter()
        .map(|(phrase, holders)| (*phrase, holders))
        .collect();
    // Newlines let multiline anchors see a line boundary without adding any
    // content the phrase did not have.
    let haystacks: Vec<String> = phrases
        .iter()
        .map(|(phrase, _)| format!("\n{phrase}\n"))
        .collect();
    let gated: Vec<Vec<usize>> = haystacks
        .par_iter()
        .map(|haystack| {
            let mut candidates: Vec<usize> = Vec::new();
            if let Some(gate) = &literal_gate {
                for hit in gate.find_overlapping_iter(haystack) {
                    candidates.extend_from_slice(&atom_owners[hit.pattern().as_usize()]);
                }
            }
            if let Some(gate) = &ci_gate {
                for hit in gate.find_overlapping_iter(haystack) {
                    candidates.extend_from_slice(&ci_owners[hit.pattern().as_usize()]);
                }
            }
            candidates.sort_unstable();
            candidates.dedup();
            candidates
        })
        .collect();

    // The ungated remainder is small enough to stay a combined automaton,
    // split in half whenever a batch overflows the size ceiling. Chunks are
    // independent, so each is matched on its own and in parallel: a phrase's
    // matches in a chunk come from an earlier run when every pattern of the
    // chunk and the phrase are unchanged, and the chunk's automata are built
    // only when some phrase has none. Matches are kept in the order the single
    // work stack used to produce them -- the last chunk first, each chunk's
    // own windows ascending -- because a phrase's hits are collected in it.
    let chunks: Vec<&[usize]> = ungated.chunks(REGEX_SET_START_WIDTH).collect();
    let chunk_matches: Vec<Vec<Vec<usize>>> = chunks
        .par_iter()
        .map(|chunk| ungated_matches(chunk, &compilable, &haystacks, facts.as_deref()))
        .collect();

    let mut phrases_of: Vec<Vec<usize>> = vec![Vec::new(); compilable.len()];
    for (phrase_idx, candidates) in gated.iter().enumerate() {
        for &idx in candidates {
            phrases_of[idx].push(phrase_idx);
        }
    }
    let gated_hits: Vec<(usize, usize)> = phrases_of
        .par_iter()
        .enumerate()
        .flat_map_iter(|(idx, phrase_idxs)| {
            let source = &compilable[idx].original_value;
            // Compiled only when some phrase has no stored verdict.
            let mut compiled: Option<Option<regex::Regex>> = None;
            phrase_idxs
                .iter()
                .copied()
                .filter(|&phrase_idx| {
                    let haystack = &haystacks[phrase_idx];
                    let fact = facts.as_ref().map(|facts| {
                        let key = super::super::facts_cache::key(
                            "literal-coverage",
                            &[source.as_bytes(), haystack.as_bytes()],
                        );
                        (facts, key)
                    });
                    if let Some(known) = fact
                        .as_ref()
                        .and_then(|(facts, key)| facts.get::<bool>(key))
                    {
                        return known;
                    }
                    let matched = compiled
                        .get_or_insert_with(|| regex::Regex::new(source).ok())
                        .as_ref()
                        .is_some_and(|pattern| pattern.is_match(haystack));
                    if let Some((facts, key)) = fact {
                        facts.put(key, &matched);
                    }
                    matched
                })
                .map(|phrase_idx| (phrase_idx, idx))
                .collect::<Vec<_>>()
        })
        .collect();
    let mut hits_of: Vec<Vec<usize>> = vec![Vec::new(); phrases.len()];
    for (phrase_idx, idx) in gated_hits {
        hits_of[phrase_idx].push(idx);
    }

    let covering: BTreeMap<&str, Vec<&PatternLocation>> = phrases
        .par_iter()
        .zip(hits_of.into_par_iter())
        .enumerate()
        .filter_map(|(phrase_idx, (&(phrase, holders), mut hits))| {
            for matches in chunk_matches.iter().rev() {
                hits.extend_from_slice(&matches[phrase_idx]);
            }

            // A regex scoped to file types the literal never sees is not
            // covering it. Filtering the hits rather than the candidates
            // keeps the gate doing the cheap work.
            let covered_by: Vec<&PatternLocation> = hits
                .into_iter()
                .map(|idx| compilable[idx])
                .filter(|location| {
                    holders
                        .iter()
                        .any(|holder| has_filetype_overlap(holder, location))
                })
                .collect();
            (!covered_by.is_empty()).then_some((phrase, covered_by))
        })
        .collect();
    for (phrase, mut covering) in covering {
        let holders = &phrase_map[phrase];
        covering.sort_by(|a, b| a.trait_id.cmp(&b.trait_id));
        covering.dedup_by(|a, b| a.trait_id == b.trait_id);
        if covering.len() < MAX_REGEXES_COVERING_A_LITERAL {
            continue;
        }

        let shown: Vec<String> = covering
            .iter()
            .take(6)
            .map(|location| {
                format!(
                    "      {}::{} => {}",
                    location.file_path, location.trait_id, location.original_value
                )
            })
            .collect();
        let more = covering.len().saturating_sub(shown.len());
        let holder_names: Vec<String> = holders
            .iter()
            .take(3)
            .map(|holder| format!("{}::{}", holder.file_path, holder.trait_id))
            .collect();
        findings.push(format!(
                "Literal {:?} ({} {}) is also matched by {} regexes in the same context and tier:\n   held by: {}\n{}{}\n   → Action: Look for opportunities to consolidate the regular expressions and/or literals in a way that adheres to TAXONOMY.md",
                phrase,
                key.0,
                format!("{:?}", key.1).to_lowercase(),
                covering.len(),
                holder_names.join(", "),
                shown.join("\n"),
                if more > 0 {
                    format!("\n      … and {more} more")
                } else {
                    String::new()
                },
            ));
    }
    findings
}

/// Which patterns of one chunk of ungated patterns match each haystack, as
/// indices into `compilable`, ascending within the chunk. A haystack's matches
/// are stored under the chunk's patterns and the haystack, so an unchanged
/// chunk and phrase reuse an earlier run's; the chunk's automata are built only
/// when some haystack has no stored matches.
pub(super) fn ungated_matches(
    chunk: &[usize],
    compilable: &[&PatternLocation],
    haystacks: &[String],
    facts: Option<&super::super::facts_cache::FactsCache>,
) -> Vec<Vec<usize>> {
    use rayon::prelude::*;

    let patterns: Vec<&[u8]> = chunk
        .iter()
        .map(|&i| compilable[i].original_value.as_bytes())
        .collect();
    let chunk_key = super::super::facts_cache::key("literal-coverage-chunk", &patterns);
    let keys: Vec<super::super::facts_cache::FactKey> = haystacks
        .par_iter()
        .map(|haystack| {
            super::super::facts_cache::key(
                "literal-coverage-set",
                &[&chunk_key, haystack.as_bytes()],
            )
        })
        .collect();
    // Offsets into the chunk, so a stored match names a pattern by its place
    // among exactly these patterns.
    let known: Vec<Option<Vec<u32>>> = keys
        .par_iter()
        .map(|key| facts.and_then(|facts| facts.get(key)))
        .collect();
    let sets = if known.iter().any(Option::is_none) {
        regex_sets_for_chunk(chunk, compilable)
    } else {
        Vec::new()
    };
    // Phrases are matched in parallel: a chunk of the largest bucket holds
    // ~15k of them.
    haystacks
        .par_iter()
        .zip(known)
        .zip(keys)
        .map(|((haystack, known), key)| {
            let offsets = known.unwrap_or_else(|| {
                let offsets: Vec<u32> = sets
                    .iter()
                    .flat_map(|(window, set)| {
                        set.matches(haystack).into_iter().map(|hit| window[hit])
                    })
                    .filter_map(|idx| chunk.binary_search(&idx).ok())
                    .filter_map(|offset| u32::try_from(offset).ok())
                    .collect();
                if let Some(facts) = facts {
                    facts.put(key, &offsets);
                }
                offsets
            });
            offsets
                .into_iter()
                .filter_map(|offset| chunk.get(offset as usize).copied())
                .collect()
        })
        .collect()
}

/// Build the combined automata for one chunk of ungated patterns, halving a
/// window whenever it overflows the size ceiling. Windows come back in the
/// order a depth-first split visits them, which is ascending.
pub(super) fn regex_sets_for_chunk(
    chunk: &[usize],
    compilable: &[&PatternLocation],
) -> Vec<(Vec<usize>, regex::RegexSet)> {
    let mut sets = Vec::new();
    let mut pending: Vec<Vec<usize>> = vec![chunk.to_vec()];
    while let Some(window) = pending.pop() {
        if window.is_empty() {
            continue;
        }
        let pats: Vec<&str> = window
            .iter()
            .map(|&i| compilable[i].original_value.as_str())
            .collect();
        match regex::RegexSetBuilder::new(&pats)
            .size_limit(REGEX_SET_SIZE_LIMIT)
            .build()
        {
            Ok(set) => sets.push((window, set)),
            Err(err) => {
                if window.len() > 1 {
                    let half = window.len() / 2;
                    pending.push(window[half..].to_vec());
                    pending.push(window[..half].to_vec());
                } else {
                    tracing::debug!(
                        "literal-coverage: skipping oversized pattern {}: {err}",
                        compilable[window[0]].trait_id
                    );
                }
            }
        }
    }
    sets
}

/// Whether one of the pair stands down wherever the other fires.
///
/// A text matcher for an API name and a symbol matcher for the same name look
/// like one fact read twice — until the text trait carries
/// `unless: [<the symbol trait>]`. Then it means "the name is present but it is
/// *not* imported", which is the runtime-resolution case and genuinely distinct
/// evidence. The pair partitions the surface instead of sharing it, so reporting
/// it as a duplicate would push an author to delete the half carrying the more
/// interesting signal.
pub(super) fn either_suppresses_the_other(a: &PatternLocation, b: &PatternLocation) -> bool {
    let names = |loc: &PatternLocation, other: &PatternLocation| {
        loc.suppressed_by.iter().any(|id| {
            // Suppressors are written fully qualified (`dir::id`) or bare when
            // the two traits share a directory.
            id == &other.trait_id || other.trait_id.ends_with(&format!("::{id}"))
        })
    };
    names(a, b) || names(b, a)
}

/// Whether two matchers select the same set of occurrences of a literal, so a
/// cross-surface pair is the same fact searched twice rather than two different
/// questions.
///
/// `exact` and `word` both demand the whole token, so they are interchangeable
/// across surfaces even though they are spelled differently — this is the shape
/// nearly every duplicated atom takes (`text {word: fputs}` beside
/// `symbol {kind: call, exact: fputs}`). `substr` is deliberately not equivalent
/// to either: it also matches inside longer tokens (`WriteFile` inside
/// `WriteFileEx`), so pairing it with a whole-token matcher would report two
/// matchers with genuinely different reach as duplicates and invite an author to
/// drop the broader one. Identical match types stay equivalent to themselves, so
/// `substr`/`substr` is still compared.
pub(super) fn literal_reach_is_equivalent(a: &str, b: &str) -> bool {
    const WHOLE_TOKEN: [&str; 2] = ["exact", "word"];
    a == b || (WHOLE_TOKEN.contains(&a) && WHOLE_TOKEN.contains(&b))
}

pub(super) fn is_cross_type_canonicalization_candidate(condition_type: &str) -> bool {
    // `raw` and `symbol` are included alongside `text`/`string_literal` so the
    // same literal searched two different ways is caught: `raw` is reserved for
    // bytes that text extraction would miss (never plain extractable text), and
    // `symbol` is a distinct AST surface. Searching one string as both — with
    // overlapping file types — is a duplicate the analyst must collapse.
    matches!(condition_type, "text" | "string_literal" | "raw" | "symbol")
}
