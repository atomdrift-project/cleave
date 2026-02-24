//! Performance optimization indices for fast trait matching.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//!
//! This module provides specialized indices for efficient trait lookup and matching:
//! - `TraitIndex`: Fast trait lookup by file type
//! - `StringMatchIndex`: Batched string matching using Aho-Corasick automaton
//! - `RawContentRegexIndex`: Batched regex matching for binary content

use crate::composite_rules::{Condition, FileType as RuleFileType, TraitDefinition};
use crate::types::{Evidence, StringInfo, MAX_EVIDENCE_PER_TRAIT};
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
    /// Extract the literal prefix from a regex pattern.
    /// Returns None if no useful literal can be extracted (pattern starts with metachar).
    fn extract_regex_literal(pattern: &str) -> Option<String> {
        let mut literal = String::new();
        let chars = pattern.chars().peekable();
        let mut in_escape = false;

        for c in chars {
            if in_escape {
                // Handle escaped characters
                match c {
                    // Common escapes that represent literals
                    's' | 'S' | 'd' | 'D' | 'w' | 'W' | 'b' | 'B' => break, // meta escapes
                    '.' | '*' | '+' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|' | '^' | '$'
                    | '\\' => {
                        literal.push(c);
                    }
                    _ => literal.push(c),
                }
                in_escape = false;
            } else if c == '\\' {
                in_escape = true;
            } else if c.is_alphanumeric() || c == '_' || c == '-' || c == '/' || c == '.' {
                literal.push(c);
            } else {
                // Hit a metacharacter, stop
                break;
            }
        }

        // Return literal if it's at least 3 chars (useful for filtering)
        if literal.len() >= 3 {
            Some(literal)
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

        let mut regex_literals: Vec<String> = Vec::with_capacity(estimated_patterns);
        let mut regex_literal_to_traits: Vec<Vec<usize>> = Vec::with_capacity(estimated_patterns);
        let mut regex_literal_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut regex_trait_indices: FxHashSet<usize> = FxHashSet::default();

        for (trait_idx, trait_def) in traits.iter().enumerate() {
            match &trait_def.r#if.condition {
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

        let total_patterns = exact_patterns.len() + ci_exact_patterns.len();

        // Set defaults if no patterns found
        if min_pattern_length == usize::MAX {
            min_pattern_length = 0;
        }
        if ci_min_pattern_length == usize::MAX {
            ci_min_pattern_length = 0;
        }

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
                            });
                        }
                    }
                }
            }
        }

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
                                    });
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
            for (trait_idx, mut ev_list) in evidence {
                let entry = final_evidence.entry(trait_idx).or_default();
                // Respect MAX_EVIDENCE_PER_TRAIT when merging
                let remaining = MAX_EVIDENCE_PER_TRAIT.saturating_sub(entry.len());
                entry.extend(ev_list.drain(..remaining.min(ev_list.len())));
            }
        }

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
    regex_set: RegexSet,
    pattern_to_traits: Vec<Vec<usize>>,
    /// Original pattern strings for debugging/profiling
    patterns: Vec<String>,
}

impl std::fmt::Debug for FileTypeRegexSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileTypeRegexSet")
            .field("pattern_count", &self.patterns.len())
            .field("patterns", &self.patterns)
            .finish()
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
            let pattern_opt = match &trait_def.r#if.condition {
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

        // Try to build the regex set.
        match RegexSetBuilder::new(&pattern_strs)
            .size_limit(100 * 1024 * 1024)
            .build()
        {
            Ok(regex_set) => Ok(Some(FileTypeRegexSet {
                regex_set,
                pattern_to_traits: pattern_to_traits.clone(),
                patterns: pattern_strs,
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

    /// Find matches using only patterns applicable to the given file type
    pub(crate) fn find_matches(
        &self,
        binary_data: &[u8],
        file_type: &RuleFileType,
    ) -> FxHashSet<usize> {
        let mut matching_traits = FxHashSet::default();

        let content = String::from_utf8_lossy(binary_data);

        // Match universal patterns
        if let Some(ref universal) = self.universal {
            for pattern_idx in universal.regex_set.matches(&content).iter() {
                if let Some(trait_indices) = universal.pattern_to_traits.get(pattern_idx) {
                    for &trait_idx in trait_indices {
                        matching_traits.insert(trait_idx);
                    }
                }
            }
        }

        // Match file-type-specific patterns
        if let Some(ft_set) = self.by_file_type.get(file_type) {
            for pattern_idx in ft_set.regex_set.matches(&content).iter() {
                if let Some(trait_indices) = ft_set.pattern_to_traits.get(pattern_idx) {
                    for &trait_idx in trait_indices {
                        matching_traits.insert(trait_idx);
                    }
                }
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
        // Simple alphanumeric prefix - note that . is allowed as a literal char
        // The * is what stops extraction, so "hello." is included
        assert_eq!(
            StringMatchIndex::extract_regex_literal("hello.*world"),
            Some("hello.".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_with_special_chars() {
        // ':' is not an allowed char, so stops at "http"
        assert_eq!(
            StringMatchIndex::extract_regex_literal("http://example\\.com/.*"),
            Some("http".to_string())
        );
        // Without colon, should work (. / - _ are allowed)
        assert_eq!(
            StringMatchIndex::extract_regex_literal("example/path/file.txt"),
            Some("example/path/file.txt".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_too_short() {
        // "ab." is 3 chars, which is the minimum - returns Some
        assert_eq!(
            StringMatchIndex::extract_regex_literal("ab.*"),
            Some("ab.".to_string())
        );
        // Starts with metachar, returns None
        assert_eq!(StringMatchIndex::extract_regex_literal(".*test"), None);
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
        // Unix path-like patterns - . is a literal char
        assert_eq!(
            StringMatchIndex::extract_regex_literal("/usr/bin/.*"),
            Some("/usr/bin/.".to_string())
        );
        // Windows paths with drive letters use : which stops extraction
        // So C:\\ extracts just "C" which is too short (< 3 chars)
        assert_eq!(
            StringMatchIndex::extract_regex_literal(r"C:\\Windows\\.*"),
            None
        );
        // But without the drive letter, Windows paths work
        assert_eq!(
            StringMatchIndex::extract_regex_literal(r"\\Windows\\System32\\.*"),
            Some("\\Windows\\System32\\.".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_with_underscore() {
        // Underscores are allowed - . before * is included
        assert_eq!(
            StringMatchIndex::extract_regex_literal("some_function_name.*"),
            Some("some_function_name.".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_with_hyphen() {
        // Hyphens are allowed - . before * is included
        assert_eq!(
            StringMatchIndex::extract_regex_literal("my-app-name-.*"),
            Some("my-app-name-.".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_starts_with_metachar() {
        // Pattern starting with metachar should return None
        assert_eq!(StringMatchIndex::extract_regex_literal(".*hello"), None);
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
        // Alternation | should stop extraction
        assert_eq!(
            StringMatchIndex::extract_regex_literal("foo|bar"),
            Some("foo".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_question_mark() {
        // Question mark should stop extraction
        assert_eq!(
            StringMatchIndex::extract_regex_literal("hello?world"),
            Some("hello".to_string())
        );
    }

    #[test]
    fn test_extract_regex_literal_plus() {
        // Plus should stop extraction
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
            r#if: crate::composite_rules::traits::ConditionWithFilters {
                condition: Condition::Raw {
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
                size_min: None,
                size_max: None,
                count_min: None,
                count_max: None,
                per_kb_min: None,
                per_kb_max: None,
            },
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
