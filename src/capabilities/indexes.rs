//! Performance optimization indices for fast trait matching.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//!
//! This module provides specialized indices for efficient trait lookup and matching:
//! - `TraitIndex`: Fast trait lookup by file type
//! - `StringMatchIndex`: Batched string matching using Aho-Corasick automaton
//! - `RawContentRegexIndex`: Batched regex matching for binary content

use crate::composite_rules::{Condition, FileType as RuleFileType, TraitDefinition};
use crate::types::{deduplicate_evidence, Evidence, StringInfo, MAX_EVIDENCE_PER_TRAIT};
use aho_corasick::AhoCorasick;
use rayon::prelude::*;
use regex::{RegexSet, RegexSetBuilder};
use rustc_hash::{FxHashMap, FxHashSet};

/// Index of trait indices by file type for fast lookup.
/// Maps FileType -> Vec of indices into trait_definitions.
#[derive(Clone, Default, Debug)]
pub(crate) struct TraitIndex {
    /// Traits that apply to each specific file type
    by_file_type: FxHashMap<RuleFileType, Vec<usize>>,
    /// Traits that apply to all file types (Platform::All)
    universal: Vec<usize>,
}

impl TraitIndex {
    pub(crate) fn new() -> Self {
        Self {
            by_file_type: FxHashMap::default(),
            universal: Vec::new(),
        }
    }

    /// Build index from trait definitions
    pub(crate) fn build(traits: &[TraitDefinition]) -> Self {
        let mut index = Self::new();

        for (i, trait_def) in traits.iter().enumerate() {
            let has_all = trait_def.r#for.contains(&RuleFileType::All);

            if has_all {
                // Trait applies to all file types
                index.universal.push(i);
            } else {
                // Trait applies to specific file types
                for ft in &trait_def.r#for {
                    index.by_file_type.entry(*ft).or_default().push(i);
                }
            }
        }

        index
    }

    /// Get trait indices applicable to a given file type
    pub(crate) fn get_applicable(
        &self,
        file_type: &RuleFileType,
    ) -> impl Iterator<Item = usize> + '_ {
        // Universal traits + specific file type traits
        let specific = self
            .by_file_type
            .get(file_type)
            .map(std::vec::Vec::as_slice)
            .unwrap_or(&[]);

        self.universal
            .iter()
            .copied()
            .chain(specific.iter().copied())
    }
}

/// Index for fast batched string matching using HashSet for exact matches.
/// Uses O(1) HashSet lookups instead of Aho-Corasick for exact string matching,
/// with parallel processing for large string sets.
#[derive(Clone, Default, Debug)]
pub(crate) struct StringMatchIndex {
    // ===== Experiment 1: HashSet for O(1) exact matching =====
    /// Case-sensitive exact pattern -> trait indices
    exact_patterns: FxHashMap<String, Vec<usize>>,
    /// Case-insensitive exact pattern (lowercase) -> (original pattern, trait indices)
    ci_exact_patterns: FxHashMap<String, (String, Vec<usize>)>,

    // ===== Experiment 3: Minimum pattern length for early filtering =====
    /// Minimum length among all patterns (strings shorter than this can be skipped)
    min_pattern_length: usize,
    /// Minimum length among case-insensitive patterns
    ci_min_pattern_length: usize,

    // ===== Experiment 4: Aho-Corasick for substr matching =====
    /// Aho-Corasick automaton for case-sensitive substr patterns
    substr_automaton: Option<AhoCorasick>,
    /// Maps substr pattern index -> (pattern string, trait indices)
    substr_to_traits: Vec<(String, Vec<usize>)>,
    /// Aho-Corasick automaton for case-insensitive substr patterns (patterns lowercased)
    ci_substr_automaton: Option<AhoCorasick>,
    /// Maps CI substr pattern index -> (original pattern, trait indices)
    ci_substr_to_traits: Vec<(String, Vec<usize>)>,
    /// Set of trait indices with substr patterns (for quick lookup)
    substr_trait_indices: FxHashSet<usize>,

    // ===== Kept for regex literal pre-filtering (unchanged) =====
    /// Aho-Corasick automaton for regex literal prefixes (for pre-filtering)
    regex_literal_automaton: Option<AhoCorasick>,
    /// Maps regex literal index -> trait indices
    regex_literal_to_traits: Vec<Vec<usize>>,
    /// Set of all trait indices with regex patterns (for lookup)
    regex_trait_indices: FxHashSet<usize>,
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
        use regex_syntax::hir::literal::{ExtractKind, Extractor};
        use regex_syntax::Parser;

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

        if common_prefix_len < 3 {
            return None;
        }

        // Convert to string (regex-syntax guarantees valid UTF-8 for string patterns)
        let prefix_bytes = &first.as_bytes()[..common_prefix_len];
        let prefix = String::from_utf8_lossy(prefix_bytes);

        if prefix.len() >= 3 {
            Some(prefix.into_owned())
        } else {
            None
        }
    }

    /// Build the string match index from trait definitions.
    /// Uses HashSet for O(1) exact matching instead of Aho-Corasick.
    pub(crate) fn build(traits: &[TraitDefinition]) -> Self {
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

        let mut regex_literals: Vec<String> = Vec::with_capacity(estimated_patterns);
        let mut regex_literal_to_traits: Vec<Vec<usize>> = Vec::with_capacity(estimated_patterns);
        let mut regex_literal_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut regex_trait_indices: FxHashSet<usize> = FxHashSet::default();

        for (trait_idx, trait_def) in traits.iter().enumerate() {
            match &trait_def.r#if {
                // Exact string patterns
                Condition::String {
                    exact: Some(ref exact_str),
                    case_insensitive,
                    ..
                } => {
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
                Condition::String {
                    substr: Some(ref substr_str),
                    case_insensitive,
                    // Skip patterns with location constraints - they need special handling
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    ..
                } => {
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
                // Regex string patterns - extract literal prefix for pre-filtering
                Condition::String {
                    regex: Some(ref regex_str),
                    ..
                } => {
                    regex_trait_indices.insert(trait_idx);
                    if let Some(literal) = Self::extract_regex_literal(regex_str) {
                        if let Some(&pattern_idx) = regex_literal_map.get(&literal) {
                            regex_literal_to_traits[pattern_idx].push(trait_idx);
                        } else {
                            let pattern_idx = regex_literals.len();
                            regex_literal_map.insert(literal.clone(), pattern_idx);
                            regex_literals.push(literal);
                            regex_literal_to_traits.push(vec![trait_idx]);
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
        let substr_automaton = if !substr_patterns.is_empty() {
            AhoCorasick::builder()
                .ascii_case_insensitive(false)
                .build(&substr_patterns)
                .ok()
        } else {
            None
        };

        let ci_substr_automaton = if !ci_substr_patterns.is_empty() {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&ci_substr_patterns)
                .ok()
        } else {
            None
        };

        // Build regex literal automaton for pre-filtering (kept as Aho-Corasick)
        let regex_literal_automaton = if !regex_literals.is_empty() {
            AhoCorasick::builder()
                .ascii_case_insensitive(false)
                .build(&regex_literals)
                .ok()
        } else {
            None
        };

        Self {
            exact_patterns,
            ci_exact_patterns,
            min_pattern_length,
            ci_min_pattern_length,
            substr_automaton,
            substr_to_traits,
            ci_substr_automaton,
            ci_substr_to_traits,
            substr_trait_indices,
            regex_literal_automaton,
            regex_literal_to_traits,
            regex_trait_indices,
            total_patterns,
        }
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
        strings: &[StringInfo],
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>) {
        // Experiment 2: Use parallel processing for large string sets (>1000 strings)
        const PARALLEL_THRESHOLD: usize = 1000;

        if strings.len() >= PARALLEL_THRESHOLD {
            self.find_matches_parallel(strings)
        } else {
            self.find_matches_sequential(strings)
        }
    }

    /// Sequential matching for small string sets
    fn find_matches_sequential(
        &self,
        strings: &[StringInfo],
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>) {
        let mut matching_traits = FxHashSet::default();
        let mut trait_evidence: FxHashMap<usize, Vec<Evidence>> = FxHashMap::default();

        for string_info in strings {
            let len = string_info.value.len();

            // Experiment 1 + 3: O(1) HashSet lookup with length pre-filter
            // Case-sensitive exact matching
            if len >= self.min_pattern_length {
                if let Some(trait_indices) = self.exact_patterns.get(&string_info.value) {
                    for &trait_idx in trait_indices {
                        matching_traits.insert(trait_idx);
                        let entry = trait_evidence.entry(trait_idx).or_default();
                        if entry.len() < MAX_EVIDENCE_PER_TRAIT {
                            entry.push(Evidence {
                                method: "string".to_string(),
                                source: "string_extractor".to_string(),
                                value: string_info.value.clone(),
                                location: string_info.offset.map(|o| format!("{:#x}", o)),
                                ..Default::default()
                            });
                        }
                    }
                }
            }

            // Case-insensitive exact matching
            if len >= self.ci_min_pattern_length {
                let lower = string_info.value.to_lowercase();
                if let Some((original_pattern, trait_indices)) = self.ci_exact_patterns.get(&lower)
                {
                    for &trait_idx in trait_indices {
                        matching_traits.insert(trait_idx);
                        let entry = trait_evidence.entry(trait_idx).or_default();
                        if entry.len() < MAX_EVIDENCE_PER_TRAIT {
                            entry.push(Evidence {
                                method: "string".to_string(),
                                source: "string_extractor".to_string(),
                                value: original_pattern.clone(),
                                location: string_info.offset.map(|o| format!("{:#x}", o)),
                                ..Default::default()
                            });
                        }
                    }
                }
            }

            // Experiment 4: Aho-Corasick substr matching (case-sensitive)
            if let Some(ref ac) = self.substr_automaton {
                for mat in ac.find_iter(&string_info.value) {
                    let pattern_idx = mat.pattern().as_usize();
                    if let Some((pattern_str, trait_indices)) =
                        self.substr_to_traits.get(pattern_idx)
                    {
                        for &trait_idx in trait_indices {
                            matching_traits.insert(trait_idx);
                            let entry = trait_evidence.entry(trait_idx).or_default();
                            if entry.len() < MAX_EVIDENCE_PER_TRAIT {
                                entry.push(Evidence {
                                    method: "string".to_string(),
                                    source: "string_extractor".to_string(),
                                    value: format!(
                                        "{} (contains: {})",
                                        string_info.value.chars().take(80).collect::<String>(),
                                        pattern_str
                                    ),
                                    location: string_info.offset.map(|o| format!("{:#x}", o)),
                                    ..Default::default()
                                });
                            }
                        }
                    }
                }
            }

            // Experiment 4: Aho-Corasick substr matching (case-insensitive)
            if let Some(ref ac) = self.ci_substr_automaton {
                for mat in ac.find_iter(&string_info.value) {
                    let pattern_idx = mat.pattern().as_usize();
                    if let Some((original_pattern, trait_indices)) =
                        self.ci_substr_to_traits.get(pattern_idx)
                    {
                        for &trait_idx in trait_indices {
                            matching_traits.insert(trait_idx);
                            let entry = trait_evidence.entry(trait_idx).or_default();
                            if entry.len() < MAX_EVIDENCE_PER_TRAIT {
                                entry.push(Evidence {
                                    method: "string".to_string(),
                                    source: "string_extractor".to_string(),
                                    value: format!(
                                        "{} (contains: {})",
                                        string_info.value.chars().take(80).collect::<String>(),
                                        original_pattern
                                    ),
                                    location: string_info.offset.map(|o| format!("{:#x}", o)),
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
    fn find_matches_parallel(
        &self,
        strings: &[StringInfo],
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>) {
        // Process strings in parallel chunks
        const CHUNK_SIZE: usize = 2000;

        let chunk_results: Vec<(FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>)> = strings
            .par_chunks(CHUNK_SIZE)
            .map(|chunk| {
                let mut matching_traits = FxHashSet::default();
                let mut trait_evidence: FxHashMap<usize, Vec<Evidence>> = FxHashMap::default();

                for string_info in chunk {
                    let len = string_info.value.len();

                    // Case-sensitive exact matching with length pre-filter
                    if len >= self.min_pattern_length {
                        if let Some(trait_indices) = self.exact_patterns.get(&string_info.value) {
                            for &trait_idx in trait_indices {
                                matching_traits.insert(trait_idx);
                                let entry = trait_evidence.entry(trait_idx).or_default();
                                if entry.len() < MAX_EVIDENCE_PER_TRAIT {
                                    entry.push(Evidence {
                                        method: "string".to_string(),
                                        source: "string_extractor".to_string(),
                                        value: string_info.value.clone(),
                                        location: string_info.offset.map(|o| format!("{:#x}", o)),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }

                    // Case-insensitive exact matching with length pre-filter
                    if len >= self.ci_min_pattern_length {
                        let lower = string_info.value.to_lowercase();
                        if let Some((original_pattern, trait_indices)) =
                            self.ci_exact_patterns.get(&lower)
                        {
                            for &trait_idx in trait_indices {
                                matching_traits.insert(trait_idx);
                                let entry = trait_evidence.entry(trait_idx).or_default();
                                if entry.len() < MAX_EVIDENCE_PER_TRAIT {
                                    entry.push(Evidence {
                                        method: "string".to_string(),
                                        source: "string_extractor".to_string(),
                                        value: original_pattern.clone(),
                                        location: string_info.offset.map(|o| format!("{:#x}", o)),
                                        ..Default::default()
                                    });
                                }
                            }
                        }
                    }

                    // Experiment 4: Aho-Corasick substr matching (case-sensitive)
                    if let Some(ref ac) = self.substr_automaton {
                        for mat in ac.find_iter(&string_info.value) {
                            let pattern_idx = mat.pattern().as_usize();
                            if let Some((pattern_str, trait_indices)) =
                                self.substr_to_traits.get(pattern_idx)
                            {
                                for &trait_idx in trait_indices {
                                    matching_traits.insert(trait_idx);
                                    let entry = trait_evidence.entry(trait_idx).or_default();
                                    if entry.len() < MAX_EVIDENCE_PER_TRAIT {
                                        entry.push(Evidence {
                                            method: "string".to_string(),
                                            source: "string_extractor".to_string(),
                                            value: format!(
                                                "{} (contains: {})",
                                                string_info
                                                    .value
                                                    .chars()
                                                    .take(80)
                                                    .collect::<String>(),
                                                pattern_str
                                            ),
                                            location: string_info
                                                .offset
                                                .map(|o| format!("{:#x}", o)),
                                            ..Default::default()
                                        });
                                    }
                                }
                            }
                        }
                    }

                    // Experiment 4: Aho-Corasick substr matching (case-insensitive)
                    if let Some(ref ac) = self.ci_substr_automaton {
                        for mat in ac.find_iter(&string_info.value) {
                            let pattern_idx = mat.pattern().as_usize();
                            if let Some((original_pattern, trait_indices)) =
                                self.ci_substr_to_traits.get(pattern_idx)
                            {
                                for &trait_idx in trait_indices {
                                    matching_traits.insert(trait_idx);
                                    let entry = trait_evidence.entry(trait_idx).or_default();
                                    if entry.len() < MAX_EVIDENCE_PER_TRAIT {
                                        entry.push(Evidence {
                                            method: "string".to_string(),
                                            source: "string_extractor".to_string(),
                                            value: format!(
                                                "{} (contains: {})",
                                                string_info
                                                    .value
                                                    .chars()
                                                    .take(80)
                                                    .collect::<String>(),
                                                original_pattern
                                            ),
                                            location: string_info
                                                .offset
                                                .map(|o| format!("{:#x}", o)),
                                            ..Default::default()
                                        });
                                    }
                                }
                            }
                        }
                    }
                }

                (matching_traits, trait_evidence)
            })
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

    /// Find regex traits that MIGHT match based on literal prefix matching.
    /// Returns trait indices whose regex patterns had their literal prefix found.
    /// Traits not in this set can be skipped without running the full regex.
    pub(crate) fn find_regex_candidates(&self, strings: &[StringInfo]) -> FxHashSet<usize> {
        let mut candidates = FxHashSet::default();

        if let Some(ref ac) = self.regex_literal_automaton {
            for string_info in strings {
                for mat in ac.find_iter(&string_info.value) {
                    let pattern_idx = mat.pattern().as_usize();
                    if let Some(trait_indices) = self.regex_literal_to_traits.get(pattern_idx) {
                        for &trait_idx in trait_indices {
                            candidates.insert(trait_idx);
                        }
                    }
                }
            }
        }

        // Traits without extractable literals can't be pre-filtered, so include them
        for &trait_idx in &self.regex_trait_indices {
            // If this trait isn't in any literal bucket, include it as candidate
            let has_literal = self
                .regex_literal_to_traits
                .iter()
                .any(|traits| traits.contains(&trait_idx));
            if !has_literal {
                candidates.insert(trait_idx);
            }
        }

        candidates
    }

    /// Check if a trait has a regex string pattern
    pub(crate) fn is_regex_trait(&self, trait_idx: usize) -> bool {
        self.regex_trait_indices.contains(&trait_idx)
    }

    /// Check if a trait has a substr string pattern that's indexed
    pub(crate) fn is_substr_trait(&self, trait_idx: usize) -> bool {
        self.substr_trait_indices.contains(&trait_idx)
    }

    /// Get statistics about indexed patterns
    #[allow(dead_code)]
    pub(crate) fn stats(&self) -> (usize, usize, usize, usize) {
        (
            self.exact_patterns.len(),
            self.ci_exact_patterns.len(),
            self.substr_to_traits.len(),
            self.ci_substr_to_traits.len(),
        )
    }
}

/// Index for regex patterns from `type: raw` conditions.
/// Builds per-file-type RegexSets to avoid running irrelevant patterns.
#[derive(Clone, Default, Debug)]
pub(crate) struct RawContentRegexIndex {
    /// Per-file-type regex sets for targeted matching
    by_file_type: FxHashMap<RuleFileType, FileTypeRegexSet>,
    /// Universal patterns that apply to all file types
    universal: Option<FileTypeRegexSet>,
    /// Set of all trait indices that have content regex patterns (for quick lookup)
    indexed_traits: FxHashSet<usize>,
    /// Total number of traits with raw content regex patterns
    pub(crate) total_patterns: usize,
}

/// Regex set for a specific file type
#[derive(Clone)]
struct FileTypeRegexSet {
    /// Full regex set (kept for fallback, but rarely used)
    #[allow(dead_code)]
    regex_set: RegexSet,
    pattern_to_traits: Vec<Vec<usize>>,
    /// Original pattern strings for debugging/profiling
    patterns: Vec<String>,
    /// Individual compiled regexes for patterns WITH extractable literals
    individual_regexes: Vec<Option<regex::Regex>>,
    /// Smaller RegexSet for ONLY patterns without extractable literals
    no_literal_regex_set: Option<RegexSet>,
    /// Maps no_literal_regex_set index -> original pattern index
    no_literal_to_original: Vec<usize>,
    /// Aho-Corasick automaton for CASE-SENSITIVE literal prefix pre-filtering
    cs_literal_prefilter: Option<AhoCorasick>,
    /// Maps case-sensitive literal index -> pattern indices
    cs_literal_to_patterns: Vec<Vec<usize>>,
    /// Aho-Corasick automaton for CASE-INSENSITIVE literal prefix pre-filtering
    ci_literal_prefilter: Option<AhoCorasick>,
    /// Maps case-insensitive literal index -> pattern indices
    ci_literal_to_patterns: Vec<Vec<usize>>,
    /// Pattern indices that have no extractable literal prefix
    patterns_without_literals: Vec<usize>,
}

impl std::fmt::Debug for FileTypeRegexSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileTypeRegexSet")
            .field("pattern_count", &self.patterns.len())
            .field("patterns", &self.patterns)
            .finish()
    }
}

impl FileTypeRegexSet {
    /// Find matching traits using hybrid literal pre-filtering strategy:
    /// 1. Run case-sensitive Aho-Corasick for case-sensitive patterns
    /// 2. Run case-insensitive Aho-Corasick for case-insensitive patterns
    /// 3. Run individual regexes for patterns with matching literals
    /// 4. Run smaller RegexSet for patterns without literals (unavoidable)
    fn find_matches(&self, content: &str) -> Vec<usize> {
        let mut matching_trait_indices = Vec::new();
        let mut literal_candidates: FxHashSet<usize> = FxHashSet::default();

        // Step 1a: Find case-sensitive patterns with matching literals
        if let Some(ref ac) = self.cs_literal_prefilter {
            for mat in ac.find_iter(content) {
                let literal_idx = mat.pattern().as_usize();
                if let Some(pattern_indices) = self.cs_literal_to_patterns.get(literal_idx) {
                    for &pattern_idx in pattern_indices {
                        literal_candidates.insert(pattern_idx);
                    }
                }
            }
        }

        // Step 1b: Find case-insensitive patterns with matching literals
        // The CI automaton was built with lowercased literals and ascii_case_insensitive=true
        if let Some(ref ac) = self.ci_literal_prefilter {
            for mat in ac.find_iter(content) {
                let literal_idx = mat.pattern().as_usize();
                if let Some(pattern_indices) = self.ci_literal_to_patterns.get(literal_idx) {
                    for &pattern_idx in pattern_indices {
                        literal_candidates.insert(pattern_idx);
                    }
                }
            }
        }

        tracing::trace!(
            "Hybrid prefilter: {} literal candidates, {} no-literal patterns",
            literal_candidates.len(),
            self.patterns_without_literals.len()
        );

        // Step 2: Run individual regexes for patterns with matching literals
        for &pattern_idx in &literal_candidates {
            if let Some(Some(ref regex)) = self.individual_regexes.get(pattern_idx) {
                if regex.is_match(content) {
                    if let Some(trait_indices) = self.pattern_to_traits.get(pattern_idx) {
                        matching_trait_indices.extend(trait_indices.iter().copied());
                    }
                }
            }
        }

        // Step 3: Run smaller RegexSet for patterns without extractable literals
        if let Some(ref no_lit_set) = self.no_literal_regex_set {
            for no_lit_idx in no_lit_set.matches(content).iter() {
                // Map back to original pattern index
                if let Some(&original_idx) = self.no_literal_to_original.get(no_lit_idx) {
                    if let Some(trait_indices) = self.pattern_to_traits.get(original_idx) {
                        matching_trait_indices.extend(trait_indices.iter().copied());
                    }
                }
            }
        }

        matching_trait_indices
    }
}

impl RawContentRegexIndex {
    pub(crate) fn build(traits: &[TraitDefinition]) -> Result<Self, Vec<String>> {
        // Group patterns by file type
        let mut by_file_type_patterns: FxHashMap<RuleFileType, Vec<(String, usize)>> =
            FxHashMap::default();
        let mut universal_patterns: Vec<(String, usize)> = Vec::new();
        let mut errors = Vec::new();

        for (trait_idx, trait_def) in traits.iter().enumerate() {
            // Extract regex patterns from Content traits
            let pattern_opt = match &trait_def.r#if {
                Condition::Raw {
                    regex: Some(ref regex_str),
                    case_insensitive,
                    ..
                } => Some(if *case_insensitive {
                    format!("(?i){}", regex_str)
                } else {
                    regex_str.clone()
                }),
                Condition::Raw {
                    word: Some(ref word_str),
                    case_insensitive,
                    ..
                } => Some(if *case_insensitive {
                    format!("(?i)\\b{}\\b", regex::escape(word_str))
                } else {
                    format!("\\b{}\\b", regex::escape(word_str))
                }),
                _ => None,
            };

            if let Some(pattern) = pattern_opt {
                if trait_def.r#for.contains(&RuleFileType::All) {
                    universal_patterns.push((pattern, trait_idx));
                } else {
                    for ft in &trait_def.r#for {
                        by_file_type_patterns
                            .entry(*ft)
                            .or_default()
                            .push((pattern.clone(), trait_idx));
                    }
                }
            }
        }

        // Build regex sets for each file type in parallel, collecting errors
        let ft_patterns_vec: Vec<_> = by_file_type_patterns.into_iter().collect();
        let results: Vec<_> = ft_patterns_vec
            .into_par_iter()
            .map(|(ft, patterns)| (ft, Self::build_regex_set(patterns, traits)))
            .collect();

        let mut by_file_type = FxHashMap::default();
        for (ft, result) in results {
            match result {
                Ok(Some(set)) => {
                    by_file_type.insert(ft, set);
                }
                Ok(None) => {}
                Err(mut e) => errors.append(&mut e),
            }
        }

        // Build universal patterns (can run in parallel with file-type-specific building
        // but kept separate for clarity)
        let universal = match Self::build_regex_set(universal_patterns, traits) {
            Ok(set) => set,
            Err(mut e) => {
                errors.append(&mut e);
                None
            }
        };

        if !errors.is_empty() {
            return Err(errors);
        }

        // Track only traits/patterns that were successfully indexed for pre-filtering.
        let mut indexed_traits = FxHashSet::default();
        let mut total_patterns = 0usize;

        for ft_set in by_file_type.values() {
            total_patterns += ft_set.pattern_to_traits.len();
            for trait_indices in &ft_set.pattern_to_traits {
                for &trait_idx in trait_indices {
                    indexed_traits.insert(trait_idx);
                }
            }
        }
        if let Some(ref universal_set) = universal {
            total_patterns += universal_set.pattern_to_traits.len();
            for trait_indices in &universal_set.pattern_to_traits {
                for &trait_idx in trait_indices {
                    indexed_traits.insert(trait_idx);
                }
            }
        }

        Ok(Self {
            by_file_type,
            universal,
            indexed_traits,
            total_patterns,
        })
    }

    fn build_regex_set(
        patterns: Vec<(String, usize)>,
        traits: &[TraitDefinition],
    ) -> Result<Option<FileTypeRegexSet>, Vec<String>> {
        if patterns.is_empty() {
            return Ok(None);
        }

        // Group traits by unique pattern to avoid redundancy
        let mut pattern_map: FxHashMap<String, Vec<usize>> = FxHashMap::default();
        for (pattern, trait_idx) in patterns {
            pattern_map.entry(pattern).or_default().push(trait_idx);
        }

        let pattern_strs: Vec<String> = pattern_map.keys().cloned().collect();
        let pattern_to_traits: Vec<Vec<usize>> = pattern_strs
            .iter()
            .filter_map(|p| pattern_map.get(p).cloned())
            .collect();

        // Extract literal prefixes for Aho-Corasick pre-filtering
        // Separate case-sensitive and case-insensitive patterns
        let mut cs_literal_prefixes: Vec<String> = Vec::new();
        let mut cs_literal_to_patterns: Vec<Vec<usize>> = Vec::new();
        let mut cs_literal_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut ci_literal_prefixes: Vec<String> = Vec::new();
        let mut ci_literal_to_patterns: Vec<Vec<usize>> = Vec::new();
        let mut ci_literal_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut patterns_without_literals: Vec<usize> = Vec::new();

        for (pattern_idx, pattern) in pattern_strs.iter().enumerate() {
            // Check if pattern is case-insensitive (starts with (?i))
            let is_case_insensitive = pattern.starts_with("(?i)");

            if let Some(literal) = StringMatchIndex::extract_regex_literal(pattern) {
                if is_case_insensitive {
                    // Case-insensitive: lowercase the literal for matching
                    let lower_literal = literal.to_lowercase();
                    if let Some(&literal_idx) = ci_literal_map.get(&lower_literal) {
                        ci_literal_to_patterns[literal_idx].push(pattern_idx);
                    } else {
                        let literal_idx = ci_literal_prefixes.len();
                        ci_literal_map.insert(lower_literal.clone(), literal_idx);
                        ci_literal_prefixes.push(lower_literal);
                        ci_literal_to_patterns.push(vec![pattern_idx]);
                    }
                } else {
                    // Case-sensitive: use literal as-is
                    if let Some(&literal_idx) = cs_literal_map.get(&literal) {
                        cs_literal_to_patterns[literal_idx].push(pattern_idx);
                    } else {
                        let literal_idx = cs_literal_prefixes.len();
                        cs_literal_map.insert(literal.clone(), literal_idx);
                        cs_literal_prefixes.push(literal);
                        cs_literal_to_patterns.push(vec![pattern_idx]);
                    }
                }
            } else {
                // No extractable literal - must always run this pattern
                patterns_without_literals.push(pattern_idx);
            }
        }

        // Build case-sensitive Aho-Corasick automaton
        let cs_literal_prefilter = if !cs_literal_prefixes.is_empty() {
            AhoCorasick::builder()
                .ascii_case_insensitive(false)
                .build(&cs_literal_prefixes)
                .ok()
        } else {
            None
        };

        // Build case-insensitive Aho-Corasick automaton
        let ci_literal_prefilter = if !ci_literal_prefixes.is_empty() {
            AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(&ci_literal_prefixes)
                .ok()
        } else {
            None
        };

        // Pre-compile individual regexes for patterns WITH literals (used after Aho-Corasick match)
        let individual_regexes: Vec<Option<regex::Regex>> = pattern_strs
            .iter()
            .map(|p| regex::Regex::new(p).ok())
            .collect();

        // Build smaller RegexSet for ONLY patterns without extractable literals
        let no_literal_patterns: Vec<&str> = patterns_without_literals
            .iter()
            .filter_map(|&idx| pattern_strs.get(idx).map(String::as_str))
            .collect();
        let no_literal_to_original: Vec<usize> = patterns_without_literals.clone();
        let no_literal_regex_set = if !no_literal_patterns.is_empty() {
            RegexSetBuilder::new(&no_literal_patterns)
                .size_limit(100 * 1024 * 1024)
                .build()
                .ok()
        } else {
            None
        };

        // Try to build the full regex set (kept for fallback).
        match RegexSetBuilder::new(&pattern_strs)
            .size_limit(100 * 1024 * 1024)
            .build()
        {
            Ok(regex_set) => Ok(Some(FileTypeRegexSet {
                regex_set,
                pattern_to_traits: pattern_to_traits.clone(),
                patterns: pattern_strs,
                individual_regexes,
                no_literal_regex_set,
                no_literal_to_original,
                cs_literal_prefilter,
                cs_literal_to_patterns,
                ci_literal_prefilter,
                ci_literal_to_patterns,
                patterns_without_literals,
            })),
            Err(e) => {
                // RegexSet creation failed. Find invalid patterns and report them as errors.
                let mut errors = Vec::new();
                for (i, pattern) in pattern_strs.iter().enumerate() {
                    if let Err(re_err) = regex::Regex::new(pattern) {
                        for trait_idx in &pattern_to_traits[i] {
                            let trait_def = &traits[*trait_idx];
                            errors.push(format!(
                                "trait '{}' in \"{}\": invalid regex pattern: '{}' ({})",
                                trait_def.id,
                                trait_def.defined_in.display(),
                                pattern,
                                re_err
                            ));
                        }
                    }
                }

                if errors.is_empty() {
                    // This can happen if the set is too large but individual regexes are valid.
                    errors.push(format!("Failed to compile regex set: {}", e));
                }

                Err(errors)
            }
        }
    }

    pub(crate) fn has_patterns(&self) -> bool {
        self.total_patterns > 0
    }

    /// Check if any of the given trait indices have content regex patterns
    pub(crate) fn has_applicable_patterns(&self, applicable: &[usize]) -> bool {
        applicable
            .iter()
            .any(|idx| self.indexed_traits.contains(idx))
    }

    /// Check whether a trait is indexed in a compiled regex set.
    pub(crate) fn is_indexed_trait(&self, trait_idx: usize) -> bool {
        self.indexed_traits.contains(&trait_idx)
    }

    /// Find matches using only patterns applicable to the given file type.
    /// Uses Aho-Corasick literal prefix pre-filtering to skip RegexSet when possible.
    pub(crate) fn find_matches(
        &self,
        binary_data: &[u8],
        file_type: &RuleFileType,
    ) -> FxHashSet<usize> {
        let mut matching_traits = FxHashSet::default();

        // Convert to string once (this is expensive for large files)
        let content = String::from_utf8_lossy(binary_data);

        // Match universal patterns (with literal pre-filtering)
        if let Some(ref universal) = self.universal {
            for trait_idx in universal.find_matches(&content) {
                matching_traits.insert(trait_idx);
            }
        }

        // Match file-type-specific patterns (with literal pre-filtering)
        if let Some(ft_set) = self.by_file_type.get(file_type) {
            for trait_idx in ft_set.find_matches(&content) {
                matching_traits.insert(trait_idx);
            }
        }

        matching_traits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composite_rules::Platform;

    // ==================== TraitIndex Tests ====================

    #[test]
    fn test_trait_index_new() {
        let index = TraitIndex::new();
        assert!(index.universal.is_empty());
        assert!(index.by_file_type.is_empty());
    }

    #[test]
    fn test_trait_index_get_applicable_empty() {
        let index = TraitIndex::new();
        let applicable: Vec<usize> = index.get_applicable(&RuleFileType::All).collect();
        assert!(applicable.is_empty());
    }

    // ==================== StringMatchIndex Tests ====================

    #[test]
    fn test_extract_regex_literal_simple() {
        // Simple alphanumeric prefix
        // .* is a wildcard (matches any chars), so we stop before the .
        assert_eq!(
            StringMatchIndex::extract_regex_literal("hello.*world"),
            Some("hello".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_with_special_chars() {
        // regex_syntax correctly handles escaped \. as literal dot
        assert_eq!(
            StringMatchIndex::extract_regex_literal("http://example\\.com/.*"),
            Some("http://example.com/".to_string())
        );
        // Unescaped . is a metachar (matches any char), so stops before it
        assert_eq!(
            StringMatchIndex::extract_regex_literal("example/path/file.txt"),
            Some("example/path/file".to_string())
        );
        // With escaped dot, full literal is extracted
        assert_eq!(
            StringMatchIndex::extract_regex_literal(r"example/path/file\.txt"),
            Some("example/path/file.txt".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_too_short() {
        // "ab" is only 2 chars, too short for useful prefiltering
        assert_eq!(StringMatchIndex::extract_regex_literal("ab.*"), None);
        // Prefix extraction only - .* at start means no guaranteed prefix
        assert_eq!(StringMatchIndex::extract_regex_literal(".*test"), None);
        // Truly no literal
        assert_eq!(StringMatchIndex::extract_regex_literal(".*"), None);
        assert_eq!(StringMatchIndex::extract_regex_literal(".*.*"), None);
    }

    #[test]
    fn test_extract_regex_literal_escaped() {
        // Escaped metacharacters
        assert_eq!(
            StringMatchIndex::extract_regex_literal(r"test\.\*\+"),
            Some("test.*+".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_meta_escape() {
        // \d, \w, etc. should stop extraction
        assert_eq!(
            StringMatchIndex::extract_regex_literal(r"test\d+"),
            Some("test".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_with_path_chars() {
        // Unix path-like patterns - .* is a wildcard, so stop before the .
        assert_eq!(
            StringMatchIndex::extract_regex_literal("/usr/bin/.*"),
            Some("/usr/bin/".to_string())
        );
        // regex_syntax correctly handles \\ as escaped backslash, : as literal
        assert_eq!(
            StringMatchIndex::extract_regex_literal(r"C:\\Windows\\.*"),
            Some("C:\\Windows\\".to_string())
        );
        // Windows paths without drive letter
        assert_eq!(
            StringMatchIndex::extract_regex_literal(r"\\Windows\\System32\\.*"),
            Some("\\Windows\\System32\\".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_with_underscore() {
        // Underscores are allowed - .* is a wildcard, so stop before the .
        assert_eq!(
            StringMatchIndex::extract_regex_literal("some_function_name.*"),
            Some("some_function_name".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_with_hyphen() {
        // Hyphens are allowed - .* is a wildcard, so stop before the .
        assert_eq!(
            StringMatchIndex::extract_regex_literal("my-app-name-.*"),
            Some("my-app-name-".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_starts_with_metachar() {
        // Prefix extraction - .* at start means no guaranteed prefix
        assert_eq!(StringMatchIndex::extract_regex_literal(".*hello"), None);
        // Pattern starting with other metachars returns None
        assert_eq!(StringMatchIndex::extract_regex_literal("[a-z]+"), None);
        assert_eq!(StringMatchIndex::extract_regex_literal("(foo|bar)"), None);
    }

    #[test]
    fn test_extract_regex_literal_empty() {
        assert_eq!(StringMatchIndex::extract_regex_literal(""), None);
    }

    #[test]
    fn test_extract_regex_literal_only_metachar() {
        assert_eq!(StringMatchIndex::extract_regex_literal(".*"), None);
        assert_eq!(StringMatchIndex::extract_regex_literal(".+"), None);
        assert_eq!(StringMatchIndex::extract_regex_literal("\\d+"), None);
    }

    #[test]
    fn test_extract_regex_literal_alternation() {
        // Alternation with no common prefix returns None
        assert_eq!(StringMatchIndex::extract_regex_literal("foo|bar"), None);
        // Alternation with common prefix extracts it
        assert_eq!(
            StringMatchIndex::extract_regex_literal("hello_foo|hello_bar"),
            Some("hello_".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_question_mark() {
        // ? makes preceding char optional - common prefix is "hell" (without optional 'o')
        assert_eq!(
            StringMatchIndex::extract_regex_literal("hello?world"),
            Some("hell".to_string())
        );
        // https? matches http:// or https:// - common prefix is "http" (this is the bug we fixed!)
        assert_eq!(
            StringMatchIndex::extract_regex_literal("https?://"),
            Some("http".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_plus() {
        // + means one or more - at least one 'o' is guaranteed
        assert_eq!(
            StringMatchIndex::extract_regex_literal("hello+world"),
            Some("hello".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_bracket() {
        // Bracket should stop extraction
        assert_eq!(
            StringMatchIndex::extract_regex_literal("hello[0-9]"),
            Some("hello".to_string())
        );
    }

    #[test]
    fn test_string_match_index_build_empty() {
        let index = StringMatchIndex::build(&[]);

        assert!(!index.has_patterns());
        assert_eq!(index.total_patterns, 0);
        assert!(index.exact_patterns.is_empty());
        assert!(index.ci_exact_patterns.is_empty());
    }

    #[test]
    fn test_string_match_index_is_regex_trait_empty() {
        let index = StringMatchIndex::build(&[]);
        assert!(!index.is_regex_trait(0));
        assert!(!index.is_regex_trait(100));
    }

    // ==================== RawContentRegexIndex Tests ====================

    #[test]
    fn test_raw_content_regex_index_build_empty() {
        let index = RawContentRegexIndex::build(&[]).unwrap();

        assert!(!index.has_patterns());
        assert_eq!(index.total_patterns, 0);
    }

    #[test]
    fn test_raw_content_regex_index_has_applicable_patterns_empty() {
        let index = RawContentRegexIndex::build(&[]).unwrap();

        assert!(!index.has_applicable_patterns(&[]));
        assert!(!index.has_applicable_patterns(&[0, 1, 2]));
    }

    #[test]
    fn test_raw_content_regex_index_is_indexed_trait_empty() {
        let index = RawContentRegexIndex::build(&[]).unwrap();

        assert!(!index.is_indexed_trait(0));
        assert!(!index.is_indexed_trait(100));
    }

    #[test]
    fn test_raw_content_regex_index_find_matches_empty() {
        let index = RawContentRegexIndex::build(&[]).unwrap();
        let content = b"some content";

        let matches = index.find_matches(content, &RuleFileType::All);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_raw_content_regex_index_find_matches_invalid_utf8() {
        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Baseline,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            r#for: vec![RuleFileType::All],
            r#if: Condition::Raw {
                exact: None,
                substr: None,
                regex: Some("test".to_string()),
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
                },
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            size_min: None,
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        };

        let index = RawContentRegexIndex::build(&[trait_def]).unwrap();
        // Content with invalid UTF-8 and the target string
        let content = &[0xFF, b't', b'e', b's', b't', 0xFE];

        let matches = index.find_matches(content, &RuleFileType::All);
        // Should handle invalid UTF-8 gracefully and find the match
        assert!(!matches.is_empty());
    }
}
