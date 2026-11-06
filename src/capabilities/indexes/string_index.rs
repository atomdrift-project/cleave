//! Exact and substring index over string patterns.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Index for fast batched string matching using HashSet for exact matches.
/// Uses O(1) HashSet lookups instead of Aho-Corasick for exact string matching,
/// with parallel processing for large string sets.
#[derive(Clone, Default, Debug)]
pub(crate) struct StringMatchIndex {
    // ===== Experiment 1: HashSet for O(1) exact matching =====
    /// Case-sensitive exact pattern -> trait indices
    pub(super) exact_patterns: FxHashMap<String, Vec<usize>>,
    /// Case-insensitive exact pattern (lowercase) -> (original pattern, trait indices)
    pub(super) ci_exact_patterns: FxHashMap<String, (String, Vec<usize>)>,

    // ===== Experiment 3: Minimum pattern length for early filtering =====
    /// Minimum length among all patterns (strings shorter than this can be skipped)
    pub(super) min_pattern_length: usize,
    /// Minimum length among case-insensitive patterns
    pub(super) ci_min_pattern_length: usize,

    // ===== Experiment 4: Aho-Corasick for substr matching =====
    /// Aho-Corasick automaton for case-sensitive substr patterns
    pub(super) substr_automaton: Option<AhoCorasick>,
    /// Maps substr pattern index -> (pattern string, trait indices)
    pub(super) substr_to_traits: Vec<(String, Vec<usize>)>,
    /// Aho-Corasick automaton for case-insensitive substr patterns (patterns lowercased)
    pub(super) ci_substr_automaton: Option<AhoCorasick>,
    /// Maps CI substr pattern index -> (original pattern, trait indices)
    pub(super) ci_substr_to_traits: Vec<(String, Vec<usize>)>,
    /// Set of trait indices with substr patterns (for quick lookup)
    pub(super) substr_trait_indices: FxHashSet<usize>,
    /// Set of trait indices with exact patterns (for quick lookup)
    pub(super) exact_trait_indices: FxHashSet<usize>,

    /// Exact needles as a substring automaton. Used only by the source
    /// raw-haystack prefilter. `eval_raw` `exact:` is per-line equality, so
    /// "needle appears somewhere" is a conservative skip: a needle absent
    /// from the file cannot equal a line. The extracted-string path still
    /// uses `exact_patterns` HashMap lookup — do not feed this AC into that
    /// path or PE exact traits will false-positive on substrings.
    pub(super) exact_automaton: Option<AhoCorasick>,
    /// AC pattern index → trait indices for `exact_automaton`.
    pub(super) exact_ac_to_traits: Vec<Vec<usize>>,
    /// Case-insensitive exact needles as a substring automaton (same role).
    pub(super) ci_exact_automaton: Option<AhoCorasick>,
    /// AC pattern index → trait indices for `ci_exact_automaton`.
    pub(super) ci_exact_ac_to_traits: Vec<Vec<usize>>,

    /// Set of all trait indices with regex patterns (for lookup)
    pub(super) regex_trait_indices: FxHashSet<usize>,
    /// Mandatory any-of atoms (see `mandatory_atom_set`) of the regex and
    /// `word:` `type: text` traits that `eval_text` sweeps over extracted
    /// strings: one case-sensitive and one ASCII-case-insensitive automaton,
    /// each pattern mapped to the traits it belongs to. A string can only
    /// match such a trait if it holds one of the trait's atoms.
    pub(super) atom_cs_automaton: Option<AhoCorasick>,
    pub(super) atom_cs_to_traits: Vec<Vec<usize>>,
    pub(super) atom_ci_automaton: Option<AhoCorasick>,
    pub(super) atom_ci_to_traits: Vec<Vec<usize>>,
    /// Regex traits with no atom set: always candidates, full sweep.
    pub(super) regex_traits_without_atoms: Vec<usize>,
    /// Total number of traits with exact string patterns
    pub(crate) total_patterns: usize,
}

impl StringMatchIndex {
    /// Extract a literal prefix from a regex pattern using proper regex parsing.
    ///
    /// Uses `regex_syntax` to correctly handle all regex syntax including:
    /// - Optional characters (`s?` extracts nothing for `s`)
    /// - Character classes (`[abc]` extracts nothing)
    /// - Alternations (`foo|bar` extracts nothing)
    /// - Escaped metacharacters (`\.` extracts `.`)
    ///
    /// Returns None if no useful literal (>= 3 chars) can be extracted.
    pub(crate) fn extract_regex_literal(pattern: &str) -> Option<String> {
        use regex_syntax::Parser;
        use regex_syntax::hir::literal::{ExtractKind, Extractor};

        // Parse the regex pattern into HIR (High-level Intermediate Representation)
        let hir = Parser::new().parse(pattern).ok()?;

        // Extract prefix literals (guaranteed to appear at the start of any match)
        let mut extractor = Extractor::new();
        extractor.kind(ExtractKind::Prefix);
        let seq = extractor.extract(&hir);

        // Get the literals - if extraction failed or is infinite, return None
        let literals = seq.literals()?;

        if literals.is_empty() {
            return None;
        }

        // Find the longest common prefix among all possible literal prefixes.
        // This is the guaranteed prefix that must appear in any match.
        let first = literals.first()?;
        let mut common_prefix_len = first.as_bytes().len();

        for lit in literals.iter().skip(1) {
            let bytes = lit.as_bytes();
            common_prefix_len = common_prefix_len.min(bytes.len());
            for (i, (a, b)) in first.as_bytes().iter().zip(bytes.iter()).enumerate() {
                if a != b {
                    common_prefix_len = common_prefix_len.min(i);
                    break;
                }
            }
        }

        // The common prefix can end inside a multi-byte character (`[éê]`
        // shares only the lead byte C3). Keep the whole characters before it:
        // a lossy U+FFFD stand-in would name bytes no match contains.
        let prefix_bytes = &first.as_bytes()[..common_prefix_len];
        let prefix = match std::str::from_utf8(prefix_bytes) {
            Ok(s) => s,
            Err(e) => std::str::from_utf8(&prefix_bytes[..e.valid_up_to()]).ok()?,
        };

        (prefix.len() >= 3).then(|| prefix.to_owned())
    }

    /// Build the string match index from trait definitions.
    /// Uses HashSet for O(1) exact matching instead of Aho-Corasick.
    /// Build index from trait definitions (all platforms).
    #[cfg(test)] // non-filtered convenience; production builds go through build_filtered
    pub(crate) fn build(traits: &[TraitDefinition]) -> Self {
        Self::build_filtered(traits, &[Platform::All])
    }

    /// Build index, keeping only traits whose platform set intersects `platforms`.
    /// Off-platform traits keep their absolute index slot but contribute no patterns.
    pub(crate) fn build_filtered(traits: &[TraitDefinition], platforms: &[Platform]) -> Self {
        // Pre-allocate capacity based on trait count to reduce reallocations
        let estimated_patterns = traits.len() / 2;

        // Experiment 1: Use HashMaps for O(1) exact matching
        let mut exact_patterns: FxHashMap<String, Vec<usize>> =
            FxHashMap::with_capacity_and_hasher(estimated_patterns, Default::default());
        let mut ci_exact_patterns: FxHashMap<String, (String, Vec<usize>)> =
            FxHashMap::with_capacity_and_hasher(estimated_patterns, Default::default());

        // Experiment 3: Track minimum pattern lengths
        let mut min_pattern_length = usize::MAX;
        let mut ci_min_pattern_length = usize::MAX;

        // Experiment 4: Collect substr patterns for Aho-Corasick
        let mut substr_patterns: Vec<String> = Vec::with_capacity(estimated_patterns);
        let mut substr_pattern_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut substr_to_traits: Vec<(String, Vec<usize>)> =
            Vec::with_capacity(estimated_patterns);
        let mut ci_substr_patterns: Vec<String> = Vec::with_capacity(estimated_patterns);
        let mut ci_substr_pattern_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut ci_substr_to_traits: Vec<(String, Vec<usize>)> =
            Vec::with_capacity(estimated_patterns);
        let mut substr_trait_indices: FxHashSet<usize> = FxHashSet::default();

        let mut regex_trait_indices: FxHashSet<usize> = FxHashSet::default();
        let mut exact_trait_indices: FxHashSet<usize> = FxHashSet::default();

        // Atom extraction parses each pattern into regex_syntax HIR — the
        // dominant serial cost of this build (profiled: ~330ms of a ~370ms
        // build for the prefix-literal predecessor). It is a pure (memoized)
        // function of the pattern string, so compute every regex trait's
        // atoms across all cores up front; the order-dependent dedup loop
        // below just looks the result up.
        let t_extract = std::time::Instant::now();
        type Atoms = Option<Vec<(String, bool)>>;
        let atoms_by_trait: FxHashMap<usize, Atoms> = traits
            .par_iter()
            .enumerate()
            .filter_map(|(trait_idx, trait_def)| {
                if !platforms_intersect(&trait_def.platforms, platforms) {
                    return None;
                }
                match &trait_def.r#if {
                    Condition::Text(TextQuery {
                        regex: Some(regex_str),
                        exact,
                        substr,
                        word,
                        case_insensitive,
                        ..
                    }) => {
                        // Atoms describe the regex `StringMatcher::resolve`
                        // compiles: only when no exact/substr/word takes
                        // precedence, and on the `(?i)`-prefixed text a
                        // `case_insensitive:` condition really runs, so the
                        // extractor's own Unicode-folding rules apply.
                        let atoms = if exact.is_none() && substr.is_none() && word.is_none() {
                            if *case_insensitive {
                                super::super::derivation_memo::mandatory_atom_set(&format!(
                                    "(?i){regex_str}"
                                ))
                            } else {
                                super::super::derivation_memo::mandatory_atom_set(regex_str)
                            }
                        } else {
                            None
                        };
                        Some((trait_idx, atoms))
                    }
                    _ => None,
                }
            })
            .collect();

        let mut atom_cs_patterns: Vec<String> = Vec::new();
        let mut atom_cs_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut atom_cs_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut atom_ci_patterns: Vec<String> = Vec::new();
        let mut atom_ci_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut atom_ci_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut atom_traits: FxHashSet<usize> = FxHashSet::default();
        let mut add_atom = |trait_idx: usize, atom: &str, ci: bool| {
            let (map, patterns, to_traits) = if ci {
                (
                    &mut atom_ci_map,
                    &mut atom_ci_patterns,
                    &mut atom_ci_to_traits,
                )
            } else {
                (
                    &mut atom_cs_map,
                    &mut atom_cs_patterns,
                    &mut atom_cs_to_traits,
                )
            };
            let key = if ci {
                atom.to_ascii_lowercase()
            } else {
                atom.to_owned()
            };
            if let Some(&pattern_idx) = map.get(&key) {
                to_traits[pattern_idx].push(trait_idx);
            } else {
                map.insert(key.clone(), patterns.len());
                patterns.push(key);
                to_traits.push(vec![trait_idx]);
            }
            atom_traits.insert(trait_idx);
        };
        let extract_ms = t_extract.elapsed().as_millis() as u64;
        let t_rest = std::time::Instant::now();

        for (trait_idx, trait_def) in traits.iter().enumerate() {
            if !platforms_intersect(&trait_def.platforms, platforms) {
                continue;
            }
            match &trait_def.r#if {
                // Exact string patterns
                Condition::Text(TextQuery {
                    exact: Some(exact_str),
                    case_insensitive,
                    ..
                }) => {
                    exact_trait_indices.insert(trait_idx);
                    if *case_insensitive {
                        let lower = exact_str.to_lowercase();
                        ci_min_pattern_length = ci_min_pattern_length.min(lower.len());
                        ci_exact_patterns
                            .entry(lower)
                            .or_insert_with(|| (exact_str.clone(), Vec::new()))
                            .1
                            .push(trait_idx);
                    } else {
                        min_pattern_length = min_pattern_length.min(exact_str.len());
                        exact_patterns
                            .entry(exact_str.clone())
                            .or_default()
                            .push(trait_idx);
                    }
                }
                // Substr string patterns - add to Aho-Corasick index
                Condition::Text(TextQuery {
                    substr: Some(substr_str),
                    case_insensitive,
                    // Skip patterns with location constraints - they need special handling
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    ..
                }) => {
                    substr_trait_indices.insert(trait_idx);
                    if *case_insensitive {
                        let lower = substr_str.to_lowercase();
                        if let Some(&pattern_idx) = ci_substr_pattern_map.get(&lower) {
                            ci_substr_to_traits[pattern_idx].1.push(trait_idx);
                        } else {
                            let pattern_idx = ci_substr_patterns.len();
                            ci_substr_pattern_map.insert(lower.clone(), pattern_idx);
                            ci_substr_patterns.push(lower);
                            ci_substr_to_traits.push((substr_str.clone(), vec![trait_idx]));
                        }
                    } else if let Some(&pattern_idx) = substr_pattern_map.get(substr_str) {
                        substr_to_traits[pattern_idx].1.push(trait_idx);
                    } else {
                        let pattern_idx = substr_patterns.len();
                        substr_pattern_map.insert(substr_str.clone(), pattern_idx);
                        substr_patterns.push(substr_str.clone());
                        substr_to_traits.push((substr_str.clone(), vec![trait_idx]));
                    }
                }
                // `word:` resolves ahead of `regex:` and needs its needle as a
                // substring: the needle is the trait's one atom. Its CI search
                // is an ASCII-case-insensitive automaton, as is the atom one.
                Condition::Text(TextQuery {
                    word: Some(word_str),
                    exact: None,
                    substr: None,
                    case_insensitive,
                    ..
                }) if !word_str.is_empty() && (!*case_insensitive || word_str.is_ascii()) => {
                    add_atom(trait_idx, word_str, *case_insensitive);
                }
                // Regex string patterns: gate on their mandatory atoms.
                Condition::Text(TextQuery { regex: Some(_), .. }) => {
                    regex_trait_indices.insert(trait_idx);
                    if let Some(Some(atoms)) = atoms_by_trait.get(&trait_idx) {
                        for (atom, ci) in atoms {
                            add_atom(trait_idx, atom, *ci);
                        }
                    }
                }
                _ => {}
            }
        }

        let total_patterns = exact_patterns.len()
            + ci_exact_patterns.len()
            + substr_to_traits.len()
            + ci_substr_to_traits.len();

        // Set defaults if no patterns found
        if min_pattern_length == usize::MAX {
            min_pattern_length = 0;
        }
        if ci_min_pattern_length == usize::MAX {
            ci_min_pattern_length = 0;
        }

        // Build Aho-Corasick automaton for substr patterns (Experiment 4)
        // Use Standard match kind to support find_overlapping_iter.
        // This ensures ALL matching patterns are found, even when a shorter
        // pattern (e.g., "output") is embedded within a longer one
        // (e.g., "set volume output muted true").
        let substr_automaton = if !substr_patterns.is_empty() {
            build_index_automaton(&substr_patterns, false)
        } else {
            None
        };

        let ci_substr_automaton = if !ci_substr_patterns.is_empty() {
            build_index_automaton(&ci_substr_patterns, true)
        } else {
            None
        };

        let mut atom_cs_automaton = build_index_automaton(&atom_cs_patterns, false);
        let mut atom_ci_automaton = build_index_automaton(&atom_ci_patterns, true);
        // A failed automaton must not silence its traits: without both
        // automata, no trait is atom-gated and every regex sweeps in full.
        if (atom_cs_automaton.is_none() && !atom_cs_patterns.is_empty())
            || (atom_ci_automaton.is_none() && !atom_ci_patterns.is_empty())
        {
            atom_cs_automaton = None;
            atom_ci_automaton = None;
            atom_cs_to_traits.clear();
            atom_ci_to_traits.clear();
            atom_traits.clear();
        }
        let regex_traits_without_atoms: Vec<usize> = regex_trait_indices
            .iter()
            .copied()
            .filter(|idx| !atom_traits.contains(idx))
            .collect();

        // Source raw-haystack prefilter: exact needles as substring ACs.
        // HashMap iteration order only has to match `*_ac_to_traits`.
        let (exact_automaton, exact_ac_to_traits) = {
            let mut patterns = Vec::with_capacity(exact_patterns.len());
            let mut to_traits = Vec::with_capacity(exact_patterns.len());
            for (pat, traits) in &exact_patterns {
                if pat.is_empty() {
                    continue;
                }
                patterns.push(pat.as_str());
                to_traits.push(traits.clone());
            }
            let automaton = if patterns.is_empty() {
                None
            } else {
                build_index_automaton(&patterns, false)
            };
            (automaton, to_traits)
        };
        let (ci_exact_automaton, ci_exact_ac_to_traits) = {
            let mut patterns = Vec::with_capacity(ci_exact_patterns.len());
            let mut to_traits = Vec::with_capacity(ci_exact_patterns.len());
            for (lower, (_orig, traits)) in &ci_exact_patterns {
                if lower.is_empty() {
                    continue;
                }
                patterns.push(lower.as_str());
                to_traits.push(traits.clone());
            }
            let automaton = if patterns.is_empty() {
                None
            } else {
                build_index_automaton(&patterns, true)
            };
            (automaton, to_traits)
        };

        let index = Self {
            exact_patterns,
            ci_exact_patterns,
            min_pattern_length,
            ci_min_pattern_length,
            substr_automaton,
            substr_to_traits,
            ci_substr_automaton,
            ci_substr_to_traits,
            substr_trait_indices,
            exact_trait_indices,
            exact_automaton,
            exact_ac_to_traits,
            ci_exact_automaton,
            ci_exact_ac_to_traits,
            regex_trait_indices,
            atom_cs_automaton,
            atom_cs_to_traits,
            atom_ci_automaton,
            atom_ci_to_traits,
            regex_traits_without_atoms,
            total_patterns,
        };
        tracing::debug!(
            extract_ms,
            rest_ms = t_rest.elapsed().as_millis() as u64,
            "string match index phase timing"
        );
        tracing::debug!(
            "Built StringMatchIndex: {} exact, {} ci_exact, {} substr, {} ci_substr, {} cs atoms, {} ci atoms",
            index.exact_patterns.len(),
            index.ci_exact_patterns.len(),
            index.substr_to_traits.len(),
            index.ci_substr_to_traits.len(),
            index.atom_cs_to_traits.len(),
            index.atom_ci_to_traits.len()
        );
        index
    }

    /// Returns true if the index has patterns to match
    pub(crate) fn has_patterns(&self) -> bool {
        self.total_patterns > 0
    }

    /// Find matching traits with cached evidence.
    /// Returns trait indices AND the evidence (matched patterns + offsets) for each.
    /// This avoids re-iterating strings during trait evaluation.
    ///
    /// Optimizations applied:
    /// - Experiment 1: O(1) HashSet lookup instead of Aho-Corasick
    /// - Experiment 2: Parallel processing with rayon for large string sets
    /// - Experiment 3: Skip strings shorter than minimum pattern length
    pub(crate) fn find_matches_with_evidence(
        &self,
        strings: &[&StringInfo],
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>) {
        // Experiment 2: Use parallel processing for large string sets (>1000 strings)
        const PARALLEL_THRESHOLD: usize = 1000;

        if strings.len() >= PARALLEL_THRESHOLD && crate::rayon_nest::inner_work_parallel() {
            self.find_matches_parallel(strings)
        } else {
            self.find_matches_sequential(strings)
        }
    }

    /// Sequential matching for small string sets
    pub(super) fn find_matches_sequential(
        &self,
        strings: &[&StringInfo],
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>) {
        let mut matching_traits = FxHashSet::default();
        let mut trait_evidence: FxHashMap<usize, Vec<Evidence>> = FxHashMap::default();
        let has_ci_patterns = !self.ci_exact_patterns.is_empty();
        let mut lower_buf = String::new();

        for &string_info in strings {
            let len = string_info.value.len();
            // Format the evidence offset at most once per string, shared across
            // every trait that records evidence for it — a hot substring can hit
            // many traits, and the formatted location is identical for all of them.
            let mut cached_location: Option<Option<String>> = None;

            // Experiment 1 + 3: O(1) HashSet lookup with length pre-filter
            // Case-sensitive exact matching
            if len >= self.min_pattern_length
                && let Some(trait_indices) = self.exact_patterns.get(string_info.value.as_str())
            {
                for &trait_idx in trait_indices {
                    matching_traits.insert(trait_idx);
                    let entry = trait_evidence.entry(trait_idx).or_default();
                    if entry.len() < MAX_EVIDENCE_PER_TRAIT
                        && let Some(location) = cached_location
                            .get_or_insert_with(|| string_evidence_location(string_info))
                            .clone()
                    {
                        entry.push(Evidence {
                            method: "string".to_string(),
                            source: "string_extractor".to_string(),
                            value: truncate_evidence(&string_info.value, 120),
                            location: Some(location),
                            // Exact match: the whole string is the match. The
                            // span is its full byte length — `value` above may be
                            // truncated with an ellipsis for display.
                            offsets: string_info.offset.map(|o| vec![o]).unwrap_or_default(),
                            match_len: Some(string_info.value.len() as u64),
                            ..Default::default()
                        });
                    }
                }
            }

            // Case-insensitive exact matching — skip entirely when no CI patterns exist
            if has_ci_patterns && len >= self.ci_min_pattern_length {
                lower_buf.clear();
                lower_buf.extend(string_info.value.chars().flat_map(char::to_lowercase));
                if let Some((original_pattern, trait_indices)) =
                    self.ci_exact_patterns.get(lower_buf.as_str())
                {
                    for &trait_idx in trait_indices {
                        matching_traits.insert(trait_idx);
                        let entry = trait_evidence.entry(trait_idx).or_default();
                        if entry.len() < MAX_EVIDENCE_PER_TRAIT
                            && let Some(location) = cached_location
                                .get_or_insert_with(|| string_evidence_location(string_info))
                                .clone()
                        {
                            entry.push(Evidence {
                                method: "string".to_string(),
                                source: "string_extractor".to_string(),
                                value: original_pattern.clone(),
                                location: Some(location),
                                // Case-insensitive exact match: the whole string
                                // matched. Span its actual byte length (not the
                                // pattern's, which can differ under case folding).
                                offsets: string_info.offset.map(|o| vec![o]).unwrap_or_default(),
                                match_len: Some(string_info.value.len() as u64),
                                ..Default::default()
                            });
                        }
                    }
                }
            }

            // Experiment 4: Aho-Corasick substr matching (case-sensitive)
            if let Some(ref ac) = self.substr_automaton {
                for mat in ac.find_overlapping_iter(string_info.value.as_str()) {
                    let pattern_idx = mat.pattern().as_usize();
                    if let Some((_pattern_str, trait_indices)) =
                        self.substr_to_traits.get(pattern_idx)
                    {
                        for &trait_idx in trait_indices {
                            matching_traits.insert(trait_idx);
                            let entry = trait_evidence.entry(trait_idx).or_default();
                            if entry.len() < MAX_EVIDENCE_PER_TRAIT
                                && let Some(location) = cached_location
                                    .get_or_insert_with(|| string_evidence_location(string_info))
                                    .clone()
                            {
                                entry.push(Evidence {
                                    method: "string".to_string(),
                                    source: "string_extractor".to_string(),
                                    value: match_window(
                                        &string_info.value,
                                        mat.start(),
                                        mat.end(),
                                        24,
                                    ),
                                    location: Some(location),
                                    // Anchor the span at the match within the
                                    // string, with its true byte length — the
                                    // `value` above is a windowed display string
                                    // (ellipses + surrounding context), so its
                                    // length is not the match's.
                                    offsets: string_info
                                        .offset
                                        .map(|o| vec![o + mat.start() as u64])
                                        .unwrap_or_default(),
                                    match_len: Some((mat.end() - mat.start()) as u64),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }

            // Experiment 4: Aho-Corasick substr matching (case-insensitive)
            if let Some(ref ac) = self.ci_substr_automaton {
                for mat in ac.find_overlapping_iter(string_info.value.as_str()) {
                    let pattern_idx = mat.pattern().as_usize();
                    if let Some((_original_pattern, trait_indices)) =
                        self.ci_substr_to_traits.get(pattern_idx)
                    {
                        for &trait_idx in trait_indices {
                            matching_traits.insert(trait_idx);
                            let entry = trait_evidence.entry(trait_idx).or_default();
                            if entry.len() < MAX_EVIDENCE_PER_TRAIT
                                && let Some(location) = cached_location
                                    .get_or_insert_with(|| string_evidence_location(string_info))
                                    .clone()
                            {
                                entry.push(Evidence {
                                    method: "string".to_string(),
                                    source: "string_extractor".to_string(),
                                    value: match_window(
                                        &string_info.value,
                                        mat.start(),
                                        mat.end(),
                                        24,
                                    ),
                                    location: Some(location),
                                    // Anchor the span at the match within the
                                    // string, with its true byte length — the
                                    // `value` above is a windowed display string
                                    // (ellipses + surrounding context), so its
                                    // length is not the match's.
                                    offsets: string_info
                                        .offset
                                        .map(|o| vec![o + mat.start() as u64])
                                        .unwrap_or_default(),
                                    match_len: Some((mat.end() - mat.start()) as u64),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }
        }

        // Deduplicate evidence for each trait
        let trait_evidence: FxHashMap<usize, Vec<Evidence>> = trait_evidence
            .into_iter()
            .map(|(k, v)| (k, deduplicate_evidence(v)))
            .collect();

        (matching_traits, trait_evidence)
    }

    /// Parallel matching for large string sets (Experiment 2)
    pub(super) fn find_matches_parallel(
        &self,
        strings: &[&StringInfo],
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>) {
        // Process strings in parallel chunks, delegating each chunk to the
        // sequential matcher (single source of truth) and merging per-chunk.
        const CHUNK_SIZE: usize = 2000;

        let chunk_results: Vec<(FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>)> = strings
            .par_chunks(CHUNK_SIZE)
            .map(|chunk| self.find_matches_sequential(chunk))
            .collect();

        // Merge results from all chunks
        let mut final_traits = FxHashSet::default();
        let mut final_evidence: FxHashMap<usize, Vec<Evidence>> = FxHashMap::default();

        for (traits, evidence) in chunk_results {
            for trait_idx in traits {
                final_traits.insert(trait_idx);
            }
            for (trait_idx, ev_list) in evidence {
                let entry = final_evidence.entry(trait_idx).or_default();
                entry.extend(ev_list);
            }
        }

        // Deduplicate evidence for each trait and truncate
        let final_evidence: FxHashMap<usize, Vec<Evidence>> = final_evidence
            .into_iter()
            .map(|(k, v)| {
                let mut deduped = deduplicate_evidence(v);
                deduped.truncate(MAX_EVIDENCE_PER_TRAIT);
                (k, deduped)
            })
            .collect();

        (final_traits, final_evidence)
    }

    /// Regex-trait candidates over extracted strings, plus per-trait
    /// candidate string lists. Every regex/`word:` trait with a mandatory
    /// atom set (see `mandatory_atom_set`) can only match a string holding
    /// one of its atoms, so the trait is a candidate only if some string
    /// does, and `eval_text` sweeps only the ascending indices (among the
    /// first `native_len` of `strings`) of those strings — reaching the same
    /// evidence, in the same order, as the full sweep. Regex traits without
    /// atoms are always candidates and get no list (full sweep); a trait
    /// whose atoms appear solely past `native_len` (pseudo entries) gets an
    /// empty list. A list that would hold more than half the strings is
    /// dropped — the indirection would cost more than the regex calls saved.
    pub(crate) fn find_regex_candidate_strings(
        &self,
        strings: &[&StringInfo],
        native_len: usize,
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<u32>>) {
        let mut candidates = FxHashSet::default();
        let mut lists: FxHashMap<usize, Vec<u32>> = FxHashMap::default();
        let mut full: FxHashSet<usize> = FxHashSet::default();
        let cap = native_len / 2 + 64;

        let automata = [
            (self.atom_cs_automaton.as_ref(), &self.atom_cs_to_traits),
            (self.atom_ci_automaton.as_ref(), &self.atom_ci_to_traits),
        ];
        if automata.iter().any(|(ac, _)| ac.is_some()) {
            // One pattern can hit many times inside one string (every URL
            // carries `http`): remember the last string each pattern was
            // seen in and map it to its traits once per string.
            let mut last_seen: [Vec<u32>; 2] = [
                vec![u32::MAX; self.atom_cs_to_traits.len()],
                vec![u32::MAX; self.atom_ci_to_traits.len()],
            ];
            for (i, &string_info) in strings.iter().enumerate() {
                let value = string_info.value.as_str();
                for (k, (ac, to_traits)) in automata.iter().enumerate() {
                    let Some(ac) = ac else { continue };
                    let seen = &mut last_seen[k];
                    for mat in ac.find_overlapping_iter(value) {
                        let pattern_idx = mat.pattern().as_usize();
                        if seen[pattern_idx] == i as u32 {
                            continue;
                        }
                        seen[pattern_idx] = i as u32;
                        for &trait_idx in &to_traits[pattern_idx] {
                            if full.contains(&trait_idx) {
                                continue;
                            }
                            let list = match lists.entry(trait_idx) {
                                std::collections::hash_map::Entry::Vacant(v) => {
                                    candidates.insert(trait_idx);
                                    v.insert(Vec::new())
                                }
                                std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
                            };
                            if i < native_len && list.last() != Some(&(i as u32)) {
                                list.push(i as u32);
                                if list.len() > cap {
                                    lists.remove(&trait_idx);
                                    full.insert(trait_idx);
                                }
                            }
                        }
                    }
                }
            }
        }

        candidates.extend(self.regex_traits_without_atoms.iter().copied());
        (candidates, lists)
    }

    /// Floor for the source exact-as-substr skip. Independent of the 256 B
    /// `eval_raw` window floor: extra exact automata on sub-16 KiB members cost
    /// more than they save. Windowing uses `MIN_HAYSTACK_TO_WINDOW`.
    pub(crate) const MIN_SOURCE_TEXT_PREFILTER_BYTES: usize = 16 * 1024;
    pub(crate) const MAX_SOURCE_TEXT_PREFILTER_BYTES: usize = 3 << 20;

    /// Presence scan of exact / substr / regex-prefix needles in one UTF-8
    /// source file. `None` means "do not enable string-index skips" — size
    /// cap, invalid UTF-8, or a required exact AC failed to build.
    ///
    /// Exact needles use the dedicated substring ACs, not `exact_patterns`
    /// HashMap lookup: the haystack is the whole file. Containment is only
    /// a skip predicate (`eval_raw` exact is per-line equality).
    pub(crate) fn find_matches_in_raw_source(
        &self,
        binary_data: &[u8],
    ) -> Option<(FxHashSet<usize>, FxHashSet<usize>)> {
        if binary_data.len() < Self::MIN_SOURCE_TEXT_PREFILTER_BYTES
            || binary_data.len() > Self::MAX_SOURCE_TEXT_PREFILTER_BYTES
        {
            return None;
        }
        let haystack = std::str::from_utf8(binary_data).ok()?;
        if !self.exact_patterns.is_empty() && self.exact_automaton.is_none() {
            return None;
        }
        if !self.ci_exact_patterns.is_empty() && self.ci_exact_automaton.is_none() {
            return None;
        }
        Some(self.find_matches_in_raw(haystack))
    }

    pub(super) fn find_matches_in_raw(
        &self,
        haystack: &str,
    ) -> (FxHashSet<usize>, FxHashSet<usize>) {
        let mut matched = FxHashSet::default();

        // Exact-only. Substr/regex `type: text` stay ungated here: regex/word
        // already have the raw-content atom gate, and extra whole-file AC
        // scans of those automata were a wash on dscodegpt/S2. Exact
        // `eval_raw` is a per-line walk; skipping absent PE needles is the
        // skip this prefilter is for. Second tuple slot is unused (regex
        // candidates are not produced on this path).
        if let Some(ref ac) = self.exact_automaton {
            for mat in ac.find_overlapping_iter(haystack) {
                if let Some(traits) = self.exact_ac_to_traits.get(mat.pattern().as_usize()) {
                    matched.extend(traits.iter().copied());
                }
            }
        }
        if let Some(ref ac) = self.ci_exact_automaton {
            for mat in ac.find_overlapping_iter(haystack) {
                if let Some(traits) = self.ci_exact_ac_to_traits.get(mat.pattern().as_usize()) {
                    matched.extend(traits.iter().copied());
                }
            }
        }
        (matched, FxHashSet::default())
    }

    /// Check if a trait has a regex string pattern
    pub(crate) fn is_regex_trait(&self, trait_idx: usize) -> bool {
        self.regex_trait_indices.contains(&trait_idx)
    }

    /// Check if a trait has a substr string pattern that's indexed
    pub(crate) fn is_substr_trait(&self, trait_idx: usize) -> bool {
        self.substr_trait_indices.contains(&trait_idx)
    }

    /// Check if a trait has an exact string pattern that's indexed
    pub(crate) fn is_exact_trait(&self, trait_idx: usize) -> bool {
        self.exact_trait_indices.contains(&trait_idx)
    }
}
