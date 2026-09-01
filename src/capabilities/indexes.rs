//! Performance optimization indices for fast trait matching.
//!
//! This module provides specialized indices for efficient trait lookup and matching:
//! - `TraitIndex`: Fast trait lookup by file type
//! - `StringMatchIndex`: Batched string matching using Aho-Corasick automaton
//! - `RawContentRegexIndex`: Batched regex matching for binary content

use crate::composite_rules::evaluators::{MIN_HAYSTACK_TO_WINDOW, match_window, truncate_evidence};
use crate::composite_rules::{
    Condition, FileType as RuleFileType, Platform, TraitDefinition, platforms_intersect,
};
use crate::composite_rules::{RawQuery, SymbolQuery, TextQuery};
use crate::types::binary::normalize_symbol;
use crate::types::{Evidence, MAX_EVIDENCE_PER_TRAIT, StringInfo, deduplicate_evidence};
use aho_corasick::AhoCorasick;

/// Automaton kind for the index prefilters. Default (`None`) lets aho-corasick
/// auto-pick — a contiguous DFA at these pattern counts, the fastest and
/// largest form (~115 MB across the four indexes). `CLEAVE_AC_NFA=1` forces
/// the contiguous NFA (5-10x smaller, slower per scan) for memory experiments;
/// the prefilters are among the hottest CPU paths, so the DFA stays the
/// default unless interleaved wall runs prove the NFA neutral.
fn ac_kind() -> Option<aho_corasick::AhoCorasickKind> {
    static KIND: std::sync::OnceLock<Option<aho_corasick::AhoCorasickKind>> =
        std::sync::OnceLock::new();
    *KIND.get_or_init(|| {
        std::env::var("CLEAVE_AC_NFA")
            .is_ok_and(|v| v == "1")
            .then_some(aho_corasick::AhoCorasickKind::ContiguousNFA)
    })
}
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::{Arc, OnceLock, RwLock};

fn archive_family_types(file_type: &RuleFileType) -> &'static [RuleFileType] {
    if file_type == &RuleFileType::All || file_type.is_archive() {
        RuleFileType::archive_family_types()
    } else {
        &[]
    }
}

fn string_evidence_location(string_info: &StringInfo) -> Option<String> {
    string_info.offset.map(|o| format!("{:#x}", o))
}

/// Index of trait indices by file type for fast lookup.
/// Maps FileType -> Bitset of indices into trait_definitions.
#[derive(Clone, Default, Debug)]
pub(crate) struct TraitIndex {
    /// Traits that apply to each specific file type (raw, not including universal/families)
    by_file_type: FxHashMap<RuleFileType, TraitBitSet>,
    /// Traits that apply to all file types (Platform::All)
    universal: TraitBitSet,
    /// Lazy-initialized combined bitsets (universal + specific + families)
    combined_cache: Arc<RwLock<FxHashMap<RuleFileType, TraitBitSet>>>,
}

impl TraitIndex {
    #[cfg(test)] // production builds an empty index via `Default`
    pub(crate) fn new() -> Self {
        Self {
            by_file_type: FxHashMap::default(),
            universal: TraitBitSet::default(),
            combined_cache: Arc::new(RwLock::new(FxHashMap::default())),
        }
    }

    /// Build index, keeping only traits whose platform set intersects `platforms`.
    ///
    /// Off-platform traits retain their absolute index slot but contribute no
    /// file-type buckets, so `get_applicable` never selects them for standalone
    /// evaluation. `trait_definitions` itself is left intact, so composite rules
    /// that reference these traits by id still resolve.
    pub(crate) fn build_filtered(traits: &[TraitDefinition], platforms: &[Platform]) -> Self {
        let mut by_type: FxHashMap<RuleFileType, TraitBitSet> = FxHashMap::default();
        let num_traits = traits.len();
        let mut universal = TraitBitSet::with_capacity(num_traits);

        for (i, trait_def) in traits.iter().enumerate() {
            if !platforms_intersect(&trait_def.platforms, platforms) {
                continue;
            }
            let has_all = trait_def.r#for.contains(&RuleFileType::All);

            if has_all {
                universal.insert(i);
            } else {
                for ft in &trait_def.r#for {
                    by_type
                        .entry(*ft)
                        .or_insert_with(|| TraitBitSet::with_capacity(num_traits))
                        .insert(i);
                }
            }
        }

        Self {
            by_file_type: by_type,
            universal,
            combined_cache: Arc::new(RwLock::new(FxHashMap::default())),
        }
    }

    /// Get trait indices applicable to a given file type
    pub(crate) fn get_applicable(&self, file_type: &RuleFileType) -> TraitBitSet {
        // 1. Check cache first (fast path)
        if let Ok(cache) = self.combined_cache.read()
            && let Some(bitset) = cache.get(file_type)
        {
            return bitset.clone();
        }

        // 2. Compute and cache (slow path)
        let mut combined = self.universal.clone();
        if let Some(specific) = self.by_file_type.get(file_type) {
            combined.union(specific);
        }

        for family_type in archive_family_types(file_type) {
            if let Some(family_traits) = self.by_file_type.get(family_type) {
                combined.union(family_traits);
            }
        }

        if let Ok(mut cache) = self.combined_cache.write() {
            cache.insert(*file_type, combined.clone());
        }

        combined
    }
}

/// Bitset for tracking which atomic traits have been matched.
/// Used to quickly prune composite rules whose dependencies are missing.
#[derive(Clone, Default, Debug)]
pub(crate) struct TraitBitSet {
    bits: Vec<u64>,
}

impl TraitBitSet {
    /// Create a new bitset with enough capacity for the given number of traits
    pub(crate) fn with_capacity(num_traits: usize) -> Self {
        let num_u64s = num_traits.div_ceil(64);
        Self {
            bits: vec![0; num_u64s],
        }
    }

    /// Mark a trait as matched
    pub(crate) fn insert(&mut self, trait_idx: usize) {
        let u64_idx = trait_idx / 64;
        let bit_idx = trait_idx % 64;
        if u64_idx < self.bits.len() {
            self.bits[u64_idx] |= 1 << bit_idx;
        }
    }

    /// Union another bitset into this one.
    pub(crate) fn union(&mut self, other: &Self) {
        for (i, &other_bits) in other.bits.iter().enumerate() {
            if i < self.bits.len() {
                self.bits[i] |= other_bits;
            } else {
                self.bits.push(other_bits);
            }
        }
    }

    /// Check if a trait has been matched
    pub(crate) fn contains(&self, trait_idx: usize) -> bool {
        let u64_idx = trait_idx / 64;
        let bit_idx = trait_idx % 64;
        if u64_idx < self.bits.len() {
            (self.bits[u64_idx] & (1 << bit_idx)) != 0
        } else {
            false
        }
    }

    /// Check if ALL required trait indices are present in this bitset.
    /// Returns true if indices is empty.
    pub(crate) fn contains_all(&self, indices: &[usize]) -> bool {
        for &idx in indices {
            if !self.contains(idx) {
                return false;
            }
        }
        true
    }

    /// Returns an iterator over all set bit indices in this bitset (static version).
    #[allow(dead_code)]
    pub(crate) fn to_indices_static(&self) -> impl Iterator<Item = usize> + '_ {
        let mut next_u_idx = 0;
        let mut current_u_idx = 0;
        let mut current_val = 0u64;
        let bits = &self.bits;

        std::iter::from_fn(move || {
            loop {
                if current_val != 0 {
                    let bit_idx = current_val.trailing_zeros() as usize;
                    current_val &= !(1 << bit_idx);
                    return Some(current_u_idx * 64 + bit_idx);
                }
                if next_u_idx >= bits.len() {
                    return None;
                }
                current_u_idx = next_u_idx;
                current_val = bits[current_u_idx];
                next_u_idx += 1;
            }
        })
    }

    /// Returns an iterator over all set bit indices in this bitset (owned version).
    pub(crate) fn into_indices_static(self) -> impl Iterator<Item = usize> {
        let mut next_u_idx = 0;
        let mut current_u_idx = 0;
        let mut current_val = 0u64;
        let bitset = self;

        std::iter::from_fn(move || {
            loop {
                if current_val != 0 {
                    let bit_idx = current_val.trailing_zeros() as usize;
                    current_val &= !(1 << bit_idx);
                    return Some(current_u_idx * 64 + bit_idx);
                }
                if next_u_idx >= bitset.bits.len() {
                    return None;
                }
                current_u_idx = next_u_idx;
                current_val = bitset.bits[current_u_idx];
                next_u_idx += 1;
            }
        })
    }

    /// Returns an iterator over all set bit indices in this bitset.
    #[allow(dead_code)]
    pub(crate) fn to_indices(&self) -> impl Iterator<Item = usize> + '_ {
        self.bits.iter().enumerate().flat_map(|(u_idx, &val)| {
            let mut current_val = val;
            std::iter::from_fn(move || {
                if current_val == 0 {
                    None
                } else {
                    let bit_idx = current_val.trailing_zeros() as usize;
                    current_val &= !(1 << bit_idx);
                    Some(u_idx * 64 + bit_idx)
                }
            })
        })
    }
}

/// Index for fast symbol matching.
///
/// Batches three pattern kinds across traits in a single pass per symbol:
/// - `exact`: hashmap lookup (O(1) per symbol per pattern).
/// - `substr`: Aho-Corasick automaton (O(symbol_len) per symbol, all patterns at once).
/// - `regex`: literal-prefix Aho-Corasick prefilter + full-regex verification on candidates.
///   Regexes with no extractable literal are batched into a single `RegexSet` so the
///   fallback path is O(symbol_len × set_cost) instead of O(symbols × patterns).
#[derive(Clone, Default, Debug)]
pub(crate) struct SymbolMatchIndex {
    /// Case-sensitive exact symbol -> trait indices
    exact_symbols: FxHashMap<String, Vec<usize>>,
    /// Set of all trait indices with symbol patterns (for lookup)
    symbol_trait_indices: FxHashSet<usize>,

    /// Aho-Corasick automaton for substr symbol patterns (normalized).
    substr_automaton: Option<AhoCorasick>,
    /// Maps AC pattern index -> trait indices.
    substr_to_traits: Vec<Vec<usize>>,

    /// Aho-Corasick automaton over regex literal prefixes (normalized).
    regex_literal_automaton: Option<AhoCorasick>,
    /// Maps AC pattern index -> trait indices that share that literal.
    regex_literal_to_traits: Vec<Vec<usize>>,
    /// Per-trait compiled regex for verification after literal-prefilter hit.
    /// Dense Vec indexed by trait_idx (None = not a regex trait). Vec lookup is
    /// ~3× faster than a hashmap here because trait_idx is a dense usize range.
    trait_regex: Vec<Option<std::sync::Arc<crate::composite_rules::condition::TraitRegex>>>,

    /// Regex traits with no extractable literal prefix, compiled individually
    /// (str-based, unlike the bytes-based raw-content regexes elsewhere in
    /// this module). A `RegexSet` here ran the PikeVM with every pattern live
    /// on every symbol; per-pattern `is_match` uses the lazy DFA and, looped
    /// pattern-major, reuses its cache across the whole symbol list.
    /// `regex_fallback_traits[i]` is the trait index for pattern `i`; a
    /// pattern that fails to compile is dropped from both (warned at build).
    regex_fallback_regexes: Vec<regex::Regex>,
    regex_fallback_traits: Vec<usize>,
}

impl SymbolMatchIndex {
    /// Build index, keeping only traits whose platform set intersects `platforms`.
    /// Off-platform traits keep their absolute index slot but contribute no patterns.
    pub(crate) fn build_filtered(traits: &[TraitDefinition], platforms: &[Platform]) -> Self {
        let num_traits = traits.len();
        let mut exact_symbols: FxHashMap<String, Vec<usize>> = FxHashMap::default();
        let mut symbol_trait_indices: FxHashSet<usize> = FxHashSet::default();

        // Substr collection — de-dupe patterns so multiple traits sharing the
        // same substr share one AC slot.
        let mut substr_patterns: Vec<String> = Vec::new();
        let mut substr_pattern_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut substr_to_traits: Vec<Vec<usize>> = Vec::new();

        // Regex-literal-prefix collection
        let mut regex_literals: Vec<String> = Vec::new();
        let mut regex_literal_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut regex_literal_to_traits: Vec<Vec<usize>> = Vec::new();

        // Dense Vec for per-trait regex lookup.
        let mut trait_regex: Vec<
            Option<std::sync::Arc<crate::composite_rules::condition::TraitRegex>>,
        > = vec![None; num_traits];

        let mut regex_fallback_traits: Vec<usize> = Vec::new();
        let mut regex_fallback_patterns: Vec<String> = Vec::new();

        for (trait_idx, trait_def) in traits.iter().enumerate() {
            if !platforms_intersect(&trait_def.platforms, platforms) {
                continue;
            }
            match &trait_def.r#if {
                Condition::Symbol(SymbolQuery {
                    exact: Some(exact_str),
                    substr: None,
                    regex: None,
                    ..
                }) => {
                    exact_symbols
                        .entry(normalize_symbol(exact_str))
                        .or_default()
                        .push(trait_idx);
                    symbol_trait_indices.insert(trait_idx);
                }
                Condition::Symbol(SymbolQuery {
                    exact: None,
                    substr: Some(substr_str),
                    regex: None,
                    ..
                }) => {
                    let normalized = normalize_symbol(substr_str);
                    if normalized.is_empty() {
                        continue;
                    }
                    symbol_trait_indices.insert(trait_idx);
                    if let Some(&idx) = substr_pattern_map.get(&normalized) {
                        substr_to_traits[idx].push(trait_idx);
                    } else {
                        let idx = substr_patterns.len();
                        substr_pattern_map.insert(normalized.clone(), idx);
                        substr_patterns.push(normalized);
                        substr_to_traits.push(vec![trait_idx]);
                    }
                }
                Condition::Symbol(SymbolQuery {
                    exact: None,
                    substr: None,
                    regex: Some(regex_str),
                    ..
                }) => {
                    symbol_trait_indices.insert(trait_idx);
                    // Symbol regex is no longer precompiled per condition; resolve
                    // it from the shared lazy cache. The index owns one engine per
                    // symbol-regex trait (built once, bounded by trait count), so
                    // clone it out of the shared `Arc` here.
                    trait_regex[trait_idx] =
                        crate::composite_rules::condition::cached_regex(regex_str);
                    // Prefer the longest *mandatory* literal anywhere in the
                    // pattern (not just a prefix). A prefix-only extractor dumps
                    // most symbol regexes into the no-literal `RegexSet`, whose
                    // per-symbol PikeVM `which_overlapping` scan was the single
                    // biggest CPU hotspot (profiled). An inner-literal atom lets
                    // the cheap Aho-Corasick prefilter cover them instead.
                    let atom = super::derivation_memo::mandatory_atom_utf8(regex_str);
                    match atom {
                        Some(literal) => {
                            let normalized = normalize_symbol(&literal);
                            if normalized.len() >= 3 {
                                if let Some(&idx) = regex_literal_map.get(&normalized) {
                                    regex_literal_to_traits[idx].push(trait_idx);
                                } else {
                                    let idx = regex_literals.len();
                                    regex_literal_map.insert(normalized.clone(), idx);
                                    regex_literals.push(normalized);
                                    regex_literal_to_traits.push(vec![trait_idx]);
                                }
                            } else {
                                regex_fallback_traits.push(trait_idx);
                                regex_fallback_patterns.push(regex_str.clone());
                            }
                        }
                        None => {
                            regex_fallback_traits.push(trait_idx);
                            regex_fallback_patterns.push(regex_str.clone());
                        }
                    }
                }
                _ => {}
            }
        }

        let substr_automaton = (!substr_patterns.is_empty())
            .then(|| {
                AhoCorasick::builder()
                    .kind(ac_kind())
                    .ascii_case_insensitive(false)
                    .build(&substr_patterns)
                    .ok()
            })
            .flatten();

        let regex_literal_automaton = (!regex_literals.is_empty())
            .then(|| {
                AhoCorasick::builder()
                    .kind(ac_kind())
                    .ascii_case_insensitive(false)
                    .build(&regex_literals)
                    .ok()
            })
            .flatten();

        let mut regex_fallback_regexes: Vec<regex::Regex> = Vec::new();
        let mut kept_fallback_traits: Vec<usize> = Vec::new();
        for (pattern, &trait_idx) in regex_fallback_patterns.iter().zip(&regex_fallback_traits) {
            match regex::Regex::new(pattern) {
                Ok(re) => {
                    regex_fallback_regexes.push(re);
                    kept_fallback_traits.push(trait_idx);
                }
                Err(e) => {
                    tracing::warn!(pattern, error = %e, "symbol fallback pattern failed to compile; skipping");
                }
            }
        }
        let regex_fallback_traits = kept_fallback_traits;

        tracing::debug!(
            "Built SymbolMatchIndex: {} exact, {} substr, {} regex-literal, {} regex-fallback",
            exact_symbols.len(),
            substr_to_traits.len(),
            regex_literal_to_traits.len(),
            regex_fallback_traits.len(),
        );

        Self {
            exact_symbols,
            symbol_trait_indices,
            substr_automaton,
            substr_to_traits,
            regex_literal_automaton,
            regex_literal_to_traits,
            trait_regex,
            regex_fallback_regexes,
            regex_fallback_traits,
        }
    }

    /// Legacy entry point — returns only the matched trait indices.
    /// Prefer `find_matches_with_evidence`.
    pub(crate) fn find_matches(&self, symbols: &[&str]) -> FxHashSet<usize> {
        self.find_matches_with_evidence(symbols).0
    }

    /// Emit one Evidence for (trait_idx, symbol) into `evidence`, respecting the
    /// per-trait MAX cap. Pulls the entry once per (trait, symbol) pair — cheaper
    /// than `entry().or_default()` when a trait matches many symbols.
    #[inline(always)]
    fn push_evidence(
        evidence: &mut FxHashMap<usize, Vec<Evidence>>,
        trait_idx: usize,
        symbol: &str,
    ) {
        let entry = evidence.entry(trait_idx).or_default();
        if entry.len() >= MAX_EVIDENCE_PER_TRAIT {
            return;
        }
        entry.push(Evidence {
            method: "symbol".to_string(),
            source: "symbol_index".to_string(),
            value: symbol.to_string(),
            location: None,
            ..Default::default()
        });
    }

    /// Single pass over `symbols`: simultaneously evaluates exact, substr-AC,
    /// regex-literal-prefilter, and regex fallback RegexSet. For each hit,
    /// records evidence so trait evaluation can reuse it via the
    /// `cached_evidence` fast path.
    pub(crate) fn find_matches_with_evidence(
        &self,
        symbols: &[&str],
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>) {
        // Parallel path threshold matches StringMatchIndex.
        const PARALLEL_THRESHOLD: usize = 4096;
        if symbols.len() >= PARALLEL_THRESHOLD
            && crate::rayon_nest::inner_work_parallel()
            && (self.substr_automaton.is_some()
                || self.regex_literal_automaton.is_some()
                || !self.regex_fallback_regexes.is_empty())
        {
            return self.find_matches_parallel(symbols);
        }
        self.find_matches_sequential(symbols)
    }

    fn find_matches_sequential(
        &self,
        symbols: &[&str],
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>) {
        let mut matched: FxHashSet<usize> = FxHashSet::default();
        let mut evidence: FxHashMap<usize, Vec<Evidence>> = FxHashMap::default();
        // Reused across symbols to avoid per-symbol allocation.
        let mut seen_candidates: FxHashSet<usize> = FxHashSet::default();

        // Rule loading strips up to two leading underscores. Report symbols
        // are normally pre-normalized, but normalize here for edge cases.
        // A named fn because the fallback pass below iterates pattern-major.
        fn normalize(symbol: &str) -> &str {
            let n = symbol.strip_prefix('_').unwrap_or(symbol);
            n.strip_prefix('_').unwrap_or(n)
        }

        for &symbol in symbols {
            let normalized = normalize(symbol);
            if normalized.is_empty() {
                continue;
            }

            // Exact: O(1) hashmap lookup.
            if let Some(trait_indices) = self.exact_symbols.get(normalized) {
                for &trait_idx in trait_indices {
                    matched.insert(trait_idx);
                    Self::push_evidence(&mut evidence, trait_idx, symbol);
                }
            }

            // Substr: one AC pass covers all substr patterns at once.
            if let Some(ref ac) = self.substr_automaton {
                for mat in ac.find_overlapping_iter(normalized) {
                    let idx = mat.pattern().as_usize();
                    // Safety: idx from AC always < substr_to_traits.len().
                    for &trait_idx in &self.substr_to_traits[idx] {
                        matched.insert(trait_idx);
                        Self::push_evidence(&mut evidence, trait_idx, symbol);
                    }
                }
            }

            // Regex literal prefilter + per-trait verification.
            if let Some(ref ac) = self.regex_literal_automaton {
                seen_candidates.clear();
                for mat in ac.find_overlapping_iter(normalized) {
                    let idx = mat.pattern().as_usize();
                    for &trait_idx in &self.regex_literal_to_traits[idx] {
                        if !seen_candidates.insert(trait_idx) {
                            continue;
                        }
                        if let Some(Some(re)) = self.trait_regex.get(trait_idx)
                            && re.is_match(normalized)
                        {
                            matched.insert(trait_idx);
                            Self::push_evidence(&mut evidence, trait_idx, symbol);
                        }
                    }
                }
            }
        }

        // Regex fallback (no-literal patterns), pattern-major: each regex's
        // lazy-DFA cache stays hot across the whole symbol list instead of
        // being re-entered per symbol.
        if !self.regex_fallback_regexes.is_empty() {
            for (re, &trait_idx) in self
                .regex_fallback_regexes
                .iter()
                .zip(&self.regex_fallback_traits)
            {
                for &symbol in symbols {
                    let normalized = normalize(symbol);
                    if !normalized.is_empty() && re.is_match(normalized) {
                        matched.insert(trait_idx);
                        Self::push_evidence(&mut evidence, trait_idx, symbol);
                    }
                }
            }
        }

        let evidence: FxHashMap<usize, Vec<Evidence>> = evidence
            .into_iter()
            .map(|(k, v)| (k, deduplicate_evidence(v)))
            .collect();

        (matched, evidence)
    }

    /// Parallel scan: chunks the symbol list across rayon workers and merges
    /// per-chunk (matched, evidence) results. Only used when the symbol set is
    /// large enough to amortize the merge cost.
    fn find_matches_parallel(
        &self,
        symbols: &[&str],
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>) {
        let chunk_size = (symbols.len() / rayon::current_num_threads().max(1)).max(512);
        let results: Vec<(FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>)> = symbols
            .par_chunks(chunk_size)
            .map(|chunk| self.find_matches_sequential(chunk))
            .collect();

        let mut merged_matched: FxHashSet<usize> = FxHashSet::default();
        let mut merged_evidence: FxHashMap<usize, Vec<Evidence>> = FxHashMap::default();
        for (m, e) in results {
            merged_matched.extend(m);
            for (trait_idx, evs) in e {
                let entry = merged_evidence.entry(trait_idx).or_default();
                for ev in evs {
                    if entry.len() >= MAX_EVIDENCE_PER_TRAIT {
                        break;
                    }
                    entry.push(ev);
                }
            }
        }
        let merged_evidence: FxHashMap<usize, Vec<Evidence>> = merged_evidence
            .into_iter()
            .map(|(k, v)| (k, deduplicate_evidence(v)))
            .collect();
        (merged_matched, merged_evidence)
    }

    pub(crate) fn is_symbol_trait(&self, trait_idx: usize) -> bool {
        self.symbol_trait_indices.contains(&trait_idx)
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn has_fallback(&self) -> bool {
        !self.regex_fallback_regexes.is_empty()
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
    /// Set of trait indices with exact patterns (for quick lookup)
    exact_trait_indices: FxHashSet<usize>,

    /// Exact needles as a substring automaton. Used only by the source
    /// raw-haystack prefilter. `eval_raw` `exact:` is per-line equality, so
    /// "needle appears somewhere" is a conservative skip: a needle absent
    /// from the file cannot equal a line. The extracted-string path still
    /// uses `exact_patterns` HashMap lookup — do not feed this AC into that
    /// path or PE exact traits will false-positive on substrings.
    exact_automaton: Option<AhoCorasick>,
    /// AC pattern index → trait indices for `exact_automaton`.
    exact_ac_to_traits: Vec<Vec<usize>>,
    /// Case-insensitive exact needles as a substring automaton (same role).
    ci_exact_automaton: Option<AhoCorasick>,
    /// AC pattern index → trait indices for `ci_exact_automaton`.
    ci_exact_ac_to_traits: Vec<Vec<usize>>,

    // ===== Kept for regex literal pre-filtering (unchanged) =====
    /// Aho-Corasick automaton for regex literal prefixes (for pre-filtering)
    regex_literal_automaton: Option<AhoCorasick>,
    /// Maps regex literal index -> trait indices
    regex_literal_to_traits: Vec<Vec<usize>>,
    /// Set of all trait indices with regex patterns (for lookup)
    regex_trait_indices: FxHashSet<usize>,
    /// Regex traits with no extractable literal prefix, so they can't be
    /// pre-filtered and are always candidates. Precomputed once at build time
    /// — this set depends only on the index, not the input strings, and the
    /// `find_regex_candidates` hot path runs once per analyzed file.
    regex_traits_without_literals: Vec<usize>,
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

        let mut regex_literals: Vec<String> = Vec::with_capacity(estimated_patterns);
        let mut regex_literal_to_traits: Vec<Vec<usize>> = Vec::with_capacity(estimated_patterns);
        let mut regex_literal_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut regex_trait_indices: FxHashSet<usize> = FxHashSet::default();
        let mut exact_trait_indices: FxHashSet<usize> = FxHashSet::default();

        // Regex-literal extraction parses each pattern into regex_syntax HIR — the
        // dominant serial cost of this build (profiled: ~330ms of a ~370ms build).
        // It is a pure function of the pattern string, so compute every regex
        // trait's literal across all cores up front; the order-dependent dedup
        // loop below just looks the result up. Behavior-identical to calling
        // extract_regex_literal inline, only parallelized off the serial path.
        let t_extract = std::time::Instant::now();
        let regex_literal_by_trait: FxHashMap<usize, Option<String>> = traits
            .par_iter()
            .enumerate()
            .filter_map(|(trait_idx, trait_def)| {
                if !platforms_intersect(&trait_def.platforms, platforms) {
                    return None;
                }
                match &trait_def.r#if {
                    Condition::Text(TextQuery {
                        regex: Some(regex_str),
                        ..
                    }) => Some((trait_idx, super::derivation_memo::prefix_literal(regex_str))),
                    _ => None,
                }
            })
            .collect();
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
                // Regex string patterns - extract literal prefix for pre-filtering
                Condition::Text(TextQuery { regex: Some(_), .. }) => {
                    regex_trait_indices.insert(trait_idx);
                    let literal = regex_literal_by_trait.get(&trait_idx).cloned().flatten();
                    if let Some(literal) = literal {
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
        // Use Standard match kind to support find_overlapping_iter.
        // This ensures ALL matching patterns are found, even when a shorter
        // pattern (e.g., "output") is embedded within a longer one
        // (e.g., "set volume output muted true").
        let substr_automaton = if !substr_patterns.is_empty() {
            AhoCorasick::builder()
                .kind(ac_kind())
                .ascii_case_insensitive(false)
                .build(&substr_patterns)
                .ok()
        } else {
            None
        };

        let ci_substr_automaton = if !ci_substr_patterns.is_empty() {
            AhoCorasick::builder()
                .kind(ac_kind())
                .ascii_case_insensitive(true)
                .build(&ci_substr_patterns)
                .ok()
        } else {
            None
        };

        // Build regex literal automaton for pre-filtering (kept as Aho-Corasick)
        // Stay case-sensitive. `ascii_case_insensitive(true)` here reproduced
        // the B1h/B1s Zencoder cascade (lost microsoft-corp-marker / many-imports).
        // Source `type: text` regex is not skipped by this automaton (exact-only
        // raw-haystack prefilter); CI source regexes still run through eval_raw.
        let regex_literal_automaton = if !regex_literals.is_empty() {
            AhoCorasick::builder()
                .kind(ac_kind())
                .ascii_case_insensitive(false)
                .build(&regex_literals)
                .ok()
        } else {
            None
        };

        // Precompute the regex traits that have no extractable literal and so
        // can never be pre-filtered. `find_regex_candidates` always adds these,
        // and it runs once per analyzed file — recomputing this O(traits ×
        // buckets) scan per call was a dominant cost on archives with many
        // members (e.g. a Go-source zip with thousands of files).
        let traits_with_literal: FxHashSet<usize> = regex_literal_to_traits
            .iter()
            .flat_map(|traits| traits.iter().copied())
            .collect();
        let regex_traits_without_literals: Vec<usize> = regex_trait_indices
            .iter()
            .copied()
            .filter(|idx| !traits_with_literal.contains(idx))
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
                AhoCorasick::builder()
                    .kind(ac_kind())
                    .ascii_case_insensitive(false)
                    .build(&patterns)
                    .ok()
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
                AhoCorasick::builder()
                    .kind(ac_kind())
                    .ascii_case_insensitive(true)
                    .build(&patterns)
                    .ok()
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
            regex_literal_automaton,
            regex_literal_to_traits,
            regex_trait_indices,
            regex_traits_without_literals,
            total_patterns,
        };
        tracing::debug!(
            extract_ms,
            rest_ms = t_rest.elapsed().as_millis() as u64,
            "string match index phase timing"
        );
        tracing::debug!(
            "Built StringMatchIndex: {} exact, {} ci_exact, {} substr, {} ci_substr, {} regex literals",
            index.exact_patterns.len(),
            index.ci_exact_patterns.len(),
            index.substr_to_traits.len(),
            index.ci_substr_to_traits.len(),
            index.regex_literal_to_traits.len()
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
    fn find_matches_sequential(
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
    fn find_matches_parallel(
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

    /// Find regex traits that MIGHT match based on literal prefix matching.
    /// Returns trait indices whose regex patterns had their literal prefix found.
    /// Traits not in this set can be skipped without running the full regex.
    pub(crate) fn find_regex_candidates(&self, strings: &[&StringInfo]) -> FxHashSet<usize> {
        let mut candidates = FxHashSet::default();

        if let Some(ref ac) = self.regex_literal_automaton {
            let total_patterns = self.regex_literal_to_traits.len();
            let mut seen_patterns: FxHashSet<usize> = FxHashSet::default();
            'outer: for &string_info in strings {
                for mat in ac.find_overlapping_iter(string_info.value.as_str()) {
                    let pattern_idx = mat.pattern().as_usize();
                    if seen_patterns.insert(pattern_idx) {
                        if let Some(trait_indices) = self.regex_literal_to_traits.get(pattern_idx) {
                            for &trait_idx in trait_indices {
                                candidates.insert(trait_idx);
                            }
                        }
                        if seen_patterns.len() == total_patterns {
                            break 'outer;
                        }
                    }
                }
            }
        }

        // Traits without extractable literals can't be pre-filtered, so they
        // are always candidates. Precomputed at build time (see constructor).
        candidates.extend(self.regex_traits_without_literals.iter().copied());

        candidates
    }

    /// Floor for the source exact-as-substr skip. Independent of the 256 B
    /// `eval_raw` window floor: extra exact ACs on sub-16 KiB members were a
    /// tax (S2n / five-AC trial). Windowing uses `MIN_HAYSTACK_TO_WINDOW`.
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

    fn find_matches_in_raw(&self, haystack: &str) -> (FxHashSet<usize>, FxHashSet<usize>) {
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

/// Presence set plus reusable atom-hit offsets from one raw-content gate pass.
///
/// Offsets are complete for a trait only when that trait is in `atom_offsets`.
/// Overflowed / no-literal / unrecorded traits are absent — `eval_raw` must
/// full-scan those. Decoded-layer candidate unions must not write offsets
/// (those positions are not in the raw file).
#[derive(Clone, Debug, Default)]
pub(crate) struct RawGateHits {
    pub traits: FxHashSet<usize>,
    pub atom_offsets: FxHashMap<usize, Vec<u32>>,
}

/// First-N atom starts per trait during a gate scan. Hitting the cap drops
/// the trait (common atoms are cheaper as one full `eval_raw` than as
/// hundreds of windows).
/// 512, up from 64: on overflow the recorder DROPS the trait's offsets, which
/// forces `eval_raw` back to a full-content scan — and a common atom ("curl",
/// "http") overflows precisely in the large members where the full scan is
/// most expensive. Measured on the poppy-q worker benchmark (2026-08-31),
/// full scans walked 117 GB per run vs 3.5 GB windowed, with `no_atoms`
/// (this overflow among its causes) the top fallback at 3.3M evaluations.
/// Windows are merged after sorting, so a dense atom degrades toward one big
/// window — i.e. toward today's full scan — never past it.
const MAX_ATOM_OFFSETS: usize = 512;

struct OffsetRecorder {
    map: FxHashMap<usize, Vec<u32>>,
    overflowed: FxHashSet<usize>,
}

impl OffsetRecorder {
    fn new() -> Self {
        Self {
            map: FxHashMap::default(),
            overflowed: FxHashSet::default(),
        }
    }

    fn overflowed(&self, trait_idx: usize) -> bool {
        self.overflowed.contains(&trait_idx)
    }

    fn hit_traits(&mut self, traits: &[usize], offset: u32) {
        for &t in traits {
            self.hit(t, offset);
        }
    }

    fn hit(&mut self, trait_idx: usize, offset: u32) {
        if self.overflowed.contains(&trait_idx) {
            return;
        }
        let entry = self.map.entry(trait_idx).or_default();
        if entry.last() == Some(&offset) {
            return;
        }
        if entry.len() >= MAX_ATOM_OFFSETS {
            self.map.remove(&trait_idx);
            self.overflowed.insert(trait_idx);
            return;
        }
        entry.push(offset);
    }

    fn finish(mut self) -> FxHashMap<usize, Vec<u32>> {
        for v in self.map.values_mut() {
            v.sort_unstable();
            v.dedup();
        }
        self.map
    }
}

fn record_mapped(
    rec: &mut OffsetRecorder,
    mapped: &[usize],
    via_patterns: Option<&[Vec<usize>]>,
    offset: u32,
) {
    if let Some(pattern_to_traits) = via_patterns {
        for &pattern_idx in mapped {
            if let Some(traits) = pattern_to_traits.get(pattern_idx) {
                rec.hit_traits(traits, offset);
            }
        }
    } else {
        rec.hit_traits(mapped, offset);
    }
}

/// Regex set for a specific file type
#[derive(Clone)]
struct FileTypeRegexSet {
    pattern_to_traits: Vec<Vec<usize>>,
    /// Original pattern strings for debugging/profiling
    patterns: Vec<String>,
    /// Per-pattern verifier regexes, compiled on first atom hit. Eagerly
    /// compiling every raw pattern cost ~300 ms per process start; only
    /// patterns whose literal atoms actually appear in scanned content are
    /// ever needed. A pattern that fails to compile stays `None` (warned
    /// once) — strictly better than the old behavior, where one bad pattern
    /// discarded the whole index.
    individual_regexes: Vec<OnceLock<Option<Arc<regex::bytes::Regex>>>>,
    /// Individually-compiled regexes for ONLY patterns without extractable
    /// literals (see `no_literal_pass` for why not one `RegexSet`). Parallel
    /// to `no_literal_to_original`; patterns that fail to compile are dropped
    /// from both (warned once at build).
    no_literal_regexes: Vec<regex::bytes::Regex>,
    /// Maps no_literal_regexes index -> original pattern index
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
    /// Aho-Corasick automaton for case-sensitive word boundary patterns
    cs_word_automaton: Option<AhoCorasick>,
    /// Maps case-sensitive word pattern index -> trait indices
    cs_word_to_traits: Vec<Vec<usize>>,
    /// Aho-Corasick automaton for case-insensitive word boundary patterns
    ci_word_automaton: Option<AhoCorasick>,
    /// Maps case-insensitive word pattern index -> trait indices
    ci_word_to_traits: Vec<Vec<usize>>,
    /// Candidate-only substring atoms for `type: text`-on-source traits. Unlike
    /// `*_literal_*` (raw patterns, verified by `individual_regexes`), an atom hit
    /// here marks the trait a candidate **without** an in-index regex verify — the
    /// PikeVM in `eval_raw` is the authority. This gates text traits (so PikeVM
    /// runs only when the atom is present) without compiling a meta-engine per
    /// text pattern, which is what made `type: text` the RSS hog. No word-boundary
    /// check (text regex atoms aren't necessarily token-bounded).
    cs_substr_automaton: Option<AhoCorasick>,
    /// Maps case-sensitive substring-atom index -> trait indices.
    cs_substr_to_traits: Vec<Vec<usize>>,
    /// Aho-Corasick for case-insensitive substring atoms.
    ci_substr_automaton: Option<AhoCorasick>,
    /// Maps case-insensitive substring-atom index -> trait indices.
    ci_substr_to_traits: Vec<Vec<usize>>,
    /// The atom strings behind each automaton, kept for the exact memmem
    /// path (`find_matches_memmem`) used on small content, where per-atom
    /// SIMD substring search beats an AC scan and — unlike non-overlapping
    /// AC iteration — cannot shadow one atom's occurrence with another's.
    /// `ci_*` atoms are stored lowercased (matched against ASCII-lowercased
    /// content, mirroring the automatons' `ascii_case_insensitive`).
    cs_literal_atoms: Vec<String>,
    ci_literal_atoms: Vec<String>,
    cs_word_atoms: Vec<String>,
    ci_word_atoms: Vec<String>,
    cs_substr_atoms: Vec<String>,
    ci_substr_atoms: Vec<String>,
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
    /// 1a. Run case-sensitive Aho-Corasick for case-sensitive literal patterns
    /// 1b. Run case-insensitive Aho-Corasick for case-insensitive literal patterns
    /// 1c. Run word boundary Aho-Corasick + byte boundary checks (replaces \b regex)
    /// 1d. Run substring-atom Aho-Corasick for `type: text` trait candidates
    /// 2. Run individual regexes for patterns with matching literals
    /// 3. Run smaller RegexSet for patterns without literals (unavoidable)
    ///
    /// Every sub-pass is an independent full scan over `content` whose results
    /// merge as set unions, so on large inputs (a container's raw bytes, a big
    /// binary) the passes run as parallel rayon tasks — each pass is
    /// byte-identical to its serial run; parallelism is across passes, never
    /// across content chunks, so match semantics cannot change. Small inputs
    /// keep the serial path: archive members already saturate the pool via the
    /// member fan-out, and fork/join overhead would dominate a small scan.
    /// Candidate-only counterpart of [`Self::find_matches`]: every atom pass
    /// plus the no-literal RegexSet, but literal-bucket candidates map to
    /// their traits without the full-content `verify_literal_candidates`
    /// step. Serves the gate's decoded-layer union, where over-approximation
    /// is sound and verification cost is not worth paying.
    fn find_candidates(&self, content: &[u8]) -> FxHashSet<usize> {
        let mut out: FxHashSet<usize> = FxHashSet::default();
        let mut literal_candidates: FxHashSet<usize> = FxHashSet::default();
        literal_candidates.extend(Self::ac_first_occurrence_pass(
            self.cs_literal_prefilter.as_ref(),
            &self.cs_literal_to_patterns,
            content,
        ));
        literal_candidates.extend(Self::ac_first_occurrence_pass(
            self.ci_literal_prefilter.as_ref(),
            &self.ci_literal_to_patterns,
            content,
        ));
        for pattern_idx in literal_candidates {
            if let Some(trait_indices) = self.pattern_to_traits.get(pattern_idx) {
                out.extend(trait_indices.iter().copied());
            }
        }
        out.extend(Self::ac_word_boundary_pass(
            self.cs_word_automaton.as_ref(),
            &self.cs_word_to_traits,
            content,
        ));
        out.extend(Self::ac_word_boundary_pass(
            self.ci_word_automaton.as_ref(),
            &self.ci_word_to_traits,
            content,
        ));
        out.extend(Self::ac_first_occurrence_pass(
            self.cs_substr_automaton.as_ref(),
            &self.cs_substr_to_traits,
            content,
        ));
        out.extend(Self::ac_first_occurrence_pass(
            self.ci_substr_automaton.as_ref(),
            &self.ci_substr_to_traits,
            content,
        ));
        out.extend(self.no_literal_pass(content));
        out
    }

    /// Merge word / substr / type:raw verify / no-literal / type:text verify
    /// into `(traits, verified)`. Words and type:raw hits are already decided;
    /// substr atom hits are confirmed or dropped by `verify_text_regex_candidates`.
    fn assemble_matches(
        &self,
        words: FxHashSet<usize>,
        substr: FxHashSet<usize>,
        literal_candidates: &FxHashSet<usize>,
        no_lit: &FxHashSet<usize>,
        content: &[u8],
    ) -> (FxHashSet<usize>, FxHashSet<usize>) {
        let verified = words;
        let mut traits = verified.clone();
        traits.extend(substr);

        let mut raw_hits = FxHashSet::default();
        self.verify_literal_candidates(literal_candidates, &mut raw_hits, content);
        traits.extend(&raw_hits);
        // type:raw verifiers use `compile_engine_mirrored`, not LeanRegex+(?m).
        // They stay candidates; marking them verified made `eval_raw` skip a
        // disagreeing second scan.

        traits.extend(no_lit);

        (traits, verified)
    }

    fn find_matches_classified(&self, content: &[u8]) -> (FxHashSet<usize>, FxHashSet<usize>) {
        const PARALLEL_MIN_BYTES: usize = 4 << 20;
        // Below this, per-atom SIMD memmem beats an AC scan and is exact
        // (per-atom search can't shadow overlapping occurrences the way a
        // shared non-overlapping automaton walk can). Covers scripts and
        // archive members — the content this gate exists for.
        const MEMMEM_MAX_BYTES: usize = 256 << 10;

        if content.len() <= MEMMEM_MAX_BYTES {
            return self.find_matches_memmem_classified(content);
        }

        let mut literal_candidates: FxHashSet<usize> = FxHashSet::default();

        if content.len() >= PARALLEL_MIN_BYTES && crate::rayon_nest::inner_work_parallel() {
            let (((cand_cs, cand_ci), (word_cs, word_ci)), ((sub_cs, sub_ci), no_lit)) =
                rayon::join(
                    || {
                        rayon::join(
                            || {
                                rayon::join(
                                    || {
                                        Self::ac_first_occurrence_pass(
                                            self.cs_literal_prefilter.as_ref(),
                                            &self.cs_literal_to_patterns,
                                            content,
                                        )
                                    },
                                    || {
                                        Self::ac_first_occurrence_pass(
                                            self.ci_literal_prefilter.as_ref(),
                                            &self.ci_literal_to_patterns,
                                            content,
                                        )
                                    },
                                )
                            },
                            || {
                                rayon::join(
                                    || {
                                        Self::ac_word_boundary_pass(
                                            self.cs_word_automaton.as_ref(),
                                            &self.cs_word_to_traits,
                                            content,
                                        )
                                    },
                                    || {
                                        Self::ac_word_boundary_pass(
                                            self.ci_word_automaton.as_ref(),
                                            &self.ci_word_to_traits,
                                            content,
                                        )
                                    },
                                )
                            },
                        )
                    },
                    || {
                        rayon::join(
                            || {
                                rayon::join(
                                    || {
                                        Self::ac_first_occurrence_pass(
                                            self.cs_substr_automaton.as_ref(),
                                            &self.cs_substr_to_traits,
                                            content,
                                        )
                                    },
                                    || {
                                        Self::ac_first_occurrence_pass(
                                            self.ci_substr_automaton.as_ref(),
                                            &self.ci_substr_to_traits,
                                            content,
                                        )
                                    },
                                )
                            },
                            || self.no_literal_pass(content),
                        )
                    },
                );
            literal_candidates.extend(cand_cs);
            literal_candidates.extend(cand_ci);
            let mut words = word_cs;
            words.extend(word_ci);
            let mut substr = sub_cs;
            substr.extend(sub_ci);
            return self.assemble_matches(words, substr, &literal_candidates, &no_lit, content);
        }

        // Step 1a/1b: patterns with matching case-sensitive / case-insensitive
        // literals (the CI automaton was built with lowercased literals and
        // ascii_case_insensitive=true).
        literal_candidates.extend(Self::ac_first_occurrence_pass(
            self.cs_literal_prefilter.as_ref(),
            &self.cs_literal_to_patterns,
            content,
        ));
        literal_candidates.extend(Self::ac_first_occurrence_pass(
            self.ci_literal_prefilter.as_ref(),
            &self.ci_literal_to_patterns,
            content,
        ));

        // Step 1c: word boundary patterns via Aho-Corasick + cheap byte checks
        let mut words = Self::ac_word_boundary_pass(
            self.cs_word_automaton.as_ref(),
            &self.cs_word_to_traits,
            content,
        );
        words.extend(Self::ac_word_boundary_pass(
            self.ci_word_automaton.as_ref(),
            &self.ci_word_to_traits,
            content,
        ));

        // Step 1d: substring atoms for `type: text` traits. Atom hit is
        // candidate-only until `assemble_matches` verifies the real regex.
        let mut substr = Self::ac_first_occurrence_pass(
            self.cs_substr_automaton.as_ref(),
            &self.cs_substr_to_traits,
            content,
        );
        substr.extend(Self::ac_first_occurrence_pass(
            self.ci_substr_automaton.as_ref(),
            &self.ci_substr_to_traits,
            content,
        ));

        tracing::trace!(
            "Hybrid prefilter: {} literal candidates, {} no-literal patterns",
            literal_candidates.len(),
            self.patterns_without_literals.len()
        );

        self.assemble_matches(
            words,
            substr,
            &literal_candidates,
            &self.no_literal_pass(content),
            content,
        )
    }

    /// Same presence semantics as [`Self::find_matches`], but records every
    /// atom start (up to [`MAX_ATOM_OFFSETS`] per trait) for windowed
    /// `eval_raw`. Serial only — the gate's 3 MiB cap never hits the 4 MiB
    /// parallel join, and chunked AC would need offset rebasing.
    fn find_matches_recording(
        &self,
        content: &[u8],
        rec: &mut OffsetRecorder,
    ) -> (FxHashSet<usize>, FxHashSet<usize>) {
        if content.len() <= 256 << 10 {
            return self.find_matches_memmem_recording(content, rec);
        }

        let mut words: FxHashSet<usize> = FxHashSet::default();
        let mut substr: FxHashSet<usize> = FxHashSet::default();
        let mut literal_candidates: FxHashSet<usize> = FxHashSet::default();

        if let Some(ac) = self.cs_literal_prefilter.as_ref() {
            literal_candidates.extend(Self::ac_record_offsets(
                ac,
                &self.cs_literal_to_patterns,
                content,
                rec,
                Some(&self.pattern_to_traits),
            ));
        }
        if let Some(ac) = self.ci_literal_prefilter.as_ref() {
            literal_candidates.extend(Self::ac_record_offsets(
                ac,
                &self.ci_literal_to_patterns,
                content,
                rec,
                Some(&self.pattern_to_traits),
            ));
        }
        if let Some(ac) = self.cs_word_automaton.as_ref() {
            words.extend(Self::ac_record_word_offsets(
                ac,
                &self.cs_word_to_traits,
                content,
                rec,
            ));
        }
        if let Some(ac) = self.ci_word_automaton.as_ref() {
            words.extend(Self::ac_record_word_offsets(
                ac,
                &self.ci_word_to_traits,
                content,
                rec,
            ));
        }
        if let Some(ac) = self.cs_substr_automaton.as_ref() {
            substr.extend(Self::ac_record_offsets(
                ac,
                &self.cs_substr_to_traits,
                content,
                rec,
                None,
            ));
        }
        if let Some(ac) = self.ci_substr_automaton.as_ref() {
            substr.extend(Self::ac_record_offsets(
                ac,
                &self.ci_substr_to_traits,
                content,
                rec,
                None,
            ));
        }

        self.assemble_matches(
            words,
            substr,
            &literal_candidates,
            &self.no_literal_pass(content),
            content,
        )
    }

    fn ac_record_offsets(
        ac: &AhoCorasick,
        index_map: &[Vec<usize>],
        content: &[u8],
        rec: &mut OffsetRecorder,
        via_patterns: Option<&[Vec<usize>]>,
    ) -> FxHashSet<usize> {
        let mut out = FxHashSet::default();
        for mat in ac.find_overlapping_iter(content) {
            let idx = mat.pattern().as_usize();
            let Some(mapped) = index_map.get(idx) else {
                continue;
            };
            out.extend(mapped.iter().copied());
            record_mapped(rec, mapped, via_patterns, mat.start() as u32);
        }
        out
    }

    fn ac_record_word_offsets(
        ac: &AhoCorasick,
        word_to_traits: &[Vec<usize>],
        content: &[u8],
        rec: &mut OffsetRecorder,
    ) -> FxHashSet<usize> {
        let mut out = FxHashSet::default();
        let content_len = content.len();
        for mat in ac.find_overlapping_iter(content) {
            let idx = mat.pattern().as_usize();
            let start = mat.start();
            let end = mat.end();
            let before_ok = start == 0
                || !content[start - 1].is_ascii_alphanumeric() && content[start - 1] != b'_';
            let after_ok =
                end == content_len || !content[end].is_ascii_alphanumeric() && content[end] != b'_';
            if before_ok
                && after_ok
                && let Some(trait_indices) = word_to_traits.get(idx)
            {
                out.extend(trait_indices.iter().copied());
                rec.hit_traits(trait_indices, start as u32);
            }
        }
        out
    }

    fn find_matches_memmem_recording(
        &self,
        content: &[u8],
        rec: &mut OffsetRecorder,
    ) -> (FxHashSet<usize>, FxHashSet<usize>) {
        use crate::composite_rules::condition::cached_finder;

        let mut words: FxHashSet<usize> = FxHashSet::default();
        let mut substr: FxHashSet<usize> = FxHashSet::default();
        let mut literal_candidates: FxHashSet<usize> = FxHashSet::default();

        let lowered: Option<Vec<u8>> = (!self.ci_literal_atoms.is_empty()
            || !self.ci_word_atoms.is_empty()
            || !self.ci_substr_atoms.is_empty())
        .then(|| content.to_ascii_lowercase());

        let record_finds = |atoms: &[String],
                            map: &[Vec<usize>],
                            haystack: &[u8],
                            rec: &mut OffsetRecorder,
                            into: &mut FxHashSet<usize>,
                            via_patterns: Option<&[Vec<usize>]>| {
            for (i, atom) in atoms.iter().enumerate() {
                let Some(mapped) = map.get(i) else {
                    continue;
                };
                let mut any = false;
                for start in cached_finder(atom).find_iter(haystack) {
                    record_mapped(rec, mapped, via_patterns, start as u32);
                    any = true;
                    let done = if let Some(pt) = via_patterns {
                        mapped.iter().all(|&p| {
                            pt.get(p)
                                .is_none_or(|ts| ts.iter().all(|&t| rec.overflowed(t)))
                        })
                    } else {
                        mapped.iter().all(|&t| rec.overflowed(t))
                    };
                    if done {
                        break;
                    }
                }
                if any {
                    into.extend(mapped.iter().copied());
                }
            }
        };

        record_finds(
            &self.cs_literal_atoms,
            &self.cs_literal_to_patterns,
            content,
            rec,
            &mut literal_candidates,
            Some(&self.pattern_to_traits),
        );
        if let Some(lowered) = lowered.as_deref() {
            record_finds(
                &self.ci_literal_atoms,
                &self.ci_literal_to_patterns,
                lowered,
                rec,
                &mut literal_candidates,
                Some(&self.pattern_to_traits),
            );
        }

        let word_pass = |atoms: &[String],
                         word_to_traits: &[Vec<usize>],
                         haystack: &[u8],
                         rec: &mut OffsetRecorder,
                         matched: &mut FxHashSet<usize>| {
            let content_len = haystack.len();
            for (i, atom) in atoms.iter().enumerate() {
                let Some(trait_indices) = word_to_traits.get(i) else {
                    continue;
                };
                for start in cached_finder(atom).find_iter(haystack) {
                    let end = start + atom.len();
                    let before_ok = start == 0
                        || !haystack[start - 1].is_ascii_alphanumeric()
                            && haystack[start - 1] != b'_';
                    let after_ok = end == content_len
                        || !haystack[end].is_ascii_alphanumeric() && haystack[end] != b'_';
                    if before_ok && after_ok {
                        rec.hit_traits(trait_indices, start as u32);
                        matched.extend(trait_indices.iter().copied());
                        if trait_indices.iter().all(|&t| rec.overflowed(t)) {
                            break;
                        }
                    }
                }
            }
        };
        word_pass(
            &self.cs_word_atoms,
            &self.cs_word_to_traits,
            content,
            rec,
            &mut words,
        );
        if let Some(lowered) = lowered.as_deref() {
            word_pass(
                &self.ci_word_atoms,
                &self.ci_word_to_traits,
                lowered,
                rec,
                &mut words,
            );
        }

        record_finds(
            &self.cs_substr_atoms,
            &self.cs_substr_to_traits,
            content,
            rec,
            &mut substr,
            None,
        );
        if let Some(lowered) = lowered.as_deref() {
            record_finds(
                &self.ci_substr_atoms,
                &self.ci_substr_to_traits,
                lowered,
                rec,
                &mut substr,
                None,
            );
        }

        self.assemble_matches(
            words,
            substr,
            &literal_candidates,
            &self.no_literal_pass(content),
            content,
        )
    }

    /// One Aho-Corasick pass collecting the mapped indices of every distinct
    /// automaton pattern that occurs in `content`, with early exit once all
    /// patterns have been seen. Serves steps 1a/1b (literal → candidate
    /// pattern indices) and 1d (substring atom → trait indices) — both only
    /// care about first occurrence.
    /// Minimum content size for chunk-parallel AC sweeps. Below this a single
    /// serial pass wins; above it the slowest pass otherwise runs alone at one
    /// core for the whole blob (container-scope sweeps over tens of MB were a
    /// measured 1-core wall window).
    const AC_CHUNK_BYTES: usize = 8 << 20;

    /// Near-equal chunk ranges over `len` bytes, each extended by `overlap`
    /// (= longest pattern − 1): any match starting inside a chunk lies fully
    /// within that chunk's window, so a presence-only union over chunks is
    /// exact.
    fn ac_chunk_ranges(len: usize, overlap: usize) -> Vec<(usize, usize)> {
        let chunks = len.div_ceil(Self::AC_CHUNK_BYTES);
        let base = len.div_ceil(chunks);
        (0..chunks)
            .map(|i| {
                let lo = i * base;
                (lo, ((i + 1) * base + overlap).min(len))
            })
            .collect()
    }

    fn ac_first_occurrence_pass(
        ac: Option<&AhoCorasick>,
        index_map: &[Vec<usize>],
        content: &[u8],
    ) -> FxHashSet<usize> {
        let Some(ac) = ac else {
            return FxHashSet::default();
        };
        if content.len() >= 2 * Self::AC_CHUNK_BYTES && crate::rayon_nest::inner_work_parallel() {
            use rayon::prelude::*;
            return Self::ac_chunk_ranges(content.len(), ac.max_pattern_len().saturating_sub(1))
                .par_iter()
                .map(|&(lo, hi)| Self::ac_first_occurrence_serial(ac, index_map, &content[lo..hi]))
                .reduce(FxHashSet::default, |mut a, b| {
                    a.extend(b);
                    a
                });
        }
        Self::ac_first_occurrence_serial(ac, index_map, content)
    }

    fn ac_first_occurrence_serial(
        ac: &AhoCorasick,
        index_map: &[Vec<usize>],
        content: &[u8],
    ) -> FxHashSet<usize> {
        let mut out = FxHashSet::default();
        let total = index_map.len();
        let mut seen: FxHashSet<usize> = FxHashSet::default();
        // Overlapping iteration is required for correctness: `find_iter` is
        // non-overlapping, so when one pattern's match spans another's (e.g.
        // atoms "fs.readdirSync" and ".readdirSync" from different traits),
        // the contained pattern is silently consumed and its traits never
        // marked — which turns the atom gate into a false-negative machine.
        // The per-pattern dedup plus the all-seen early exit keep the extra
        // match volume bounded.
        for mat in ac.find_overlapping_iter(content) {
            let idx = mat.pattern().as_usize();
            if seen.insert(idx) {
                if let Some(mapped) = index_map.get(idx) {
                    out.extend(mapped.iter().copied());
                }
                if seen.len() == total {
                    break;
                }
            }
        }
        out
    }

    /// Step 1c: word patterns via Aho-Corasick, keeping only occurrences with
    /// non-word bytes (or content edges) on both sides.
    fn ac_word_boundary_pass(
        ac: Option<&AhoCorasick>,
        word_to_traits: &[Vec<usize>],
        content: &[u8],
    ) -> FxHashSet<usize> {
        let Some(ac) = ac else {
            return FxHashSet::default();
        };
        if content.len() >= 2 * Self::AC_CHUNK_BYTES && crate::rayon_nest::inner_work_parallel() {
            use rayon::prelude::*;
            return Self::ac_chunk_ranges(content.len(), ac.max_pattern_len().saturating_sub(1))
                .par_iter()
                .map(|&(lo, hi)| Self::ac_word_boundary_serial(ac, word_to_traits, content, lo, hi))
                .reduce(FxHashSet::default, |mut a, b| {
                    a.extend(b);
                    a
                });
        }
        Self::ac_word_boundary_serial(ac, word_to_traits, content, 0, content.len())
    }

    /// Serial word-boundary sweep over `content[lo..hi]`. Boundary bytes are
    /// read from the FULL content at the match's global offsets, so chunk
    /// edges cannot fabricate or lose a boundary.
    fn ac_word_boundary_serial(
        ac: &AhoCorasick,
        word_to_traits: &[Vec<usize>],
        content: &[u8],
        lo: usize,
        hi: usize,
    ) -> FxHashSet<usize> {
        let mut out = FxHashSet::default();
        let content_len = content.len();
        let total = word_to_traits.len();
        // Overlapping iteration for the same reason as
        // `ac_first_occurrence_pass`: a word contained in a longer word's
        // match span must still get its own boundary check. `satisfied` skips
        // re-checking words that already passed, and exits once every word
        // has.
        let mut satisfied: FxHashSet<usize> = FxHashSet::default();
        for mat in ac.find_overlapping_iter(&content[lo..hi]) {
            let idx = mat.pattern().as_usize();
            if satisfied.contains(&idx) {
                continue;
            }
            let start = lo + mat.start();
            let end = lo + mat.end();
            let before_ok = start == 0
                || !content[start - 1].is_ascii_alphanumeric() && content[start - 1] != b'_';
            let after_ok =
                end == content_len || !content[end].is_ascii_alphanumeric() && content[end] != b'_';
            if before_ok
                && after_ok
                && let Some(trait_indices) = word_to_traits.get(idx)
            {
                out.extend(trait_indices.iter().copied());
                satisfied.insert(idx);
                if satisfied.len() == total {
                    break;
                }
            }
        }
        out
    }

    /// Exact small-content pass: per-atom SIMD substring search via the
    /// shared `cached_finder` pool. Semantics match the automaton path
    /// exactly (same atom sets, same word-boundary rule, same verify and
    /// no-literal steps), but every atom is searched independently, so one
    /// atom's occurrence can never shadow another's.
    fn find_matches_memmem_classified(
        &self,
        content: &[u8],
    ) -> (FxHashSet<usize>, FxHashSet<usize>) {
        use crate::composite_rules::condition::cached_finder;

        let mut words: FxHashSet<usize> = FxHashSet::default();
        let mut substr: FxHashSet<usize> = FxHashSet::default();
        let mut literal_candidates: FxHashSet<usize> = FxHashSet::default();

        // One ASCII-lowercased copy serves every ci atom (offsets preserved).
        let lowered: Option<Vec<u8>> = (!self.ci_literal_atoms.is_empty()
            || !self.ci_word_atoms.is_empty()
            || !self.ci_substr_atoms.is_empty())
        .then(|| content.to_ascii_lowercase());

        for (i, atom) in self.cs_literal_atoms.iter().enumerate() {
            if cached_finder(atom).find(content).is_some()
                && let Some(patterns) = self.cs_literal_to_patterns.get(i)
            {
                literal_candidates.extend(patterns.iter().copied());
            }
        }
        if let Some(lowered) = lowered.as_deref() {
            for (i, atom) in self.ci_literal_atoms.iter().enumerate() {
                if cached_finder(atom).find(lowered).is_some()
                    && let Some(patterns) = self.ci_literal_to_patterns.get(i)
                {
                    literal_candidates.extend(patterns.iter().copied());
                }
            }
        }

        let word_pass = |atoms: &[String],
                         word_to_traits: &[Vec<usize>],
                         haystack: &[u8],
                         matched: &mut FxHashSet<usize>| {
            let content_len = haystack.len();
            for (i, atom) in atoms.iter().enumerate() {
                for start in cached_finder(atom).find_iter(haystack) {
                    let end = start + atom.len();
                    let before_ok = start == 0
                        || !haystack[start - 1].is_ascii_alphanumeric()
                            && haystack[start - 1] != b'_';
                    let after_ok = end == content_len
                        || !haystack[end].is_ascii_alphanumeric() && haystack[end] != b'_';
                    if before_ok && after_ok {
                        if let Some(trait_indices) = word_to_traits.get(i) {
                            matched.extend(trait_indices.iter().copied());
                        }
                        break;
                    }
                }
            }
        };
        word_pass(
            &self.cs_word_atoms,
            &self.cs_word_to_traits,
            content,
            &mut words,
        );
        if let Some(lowered) = lowered.as_deref() {
            word_pass(
                &self.ci_word_atoms,
                &self.ci_word_to_traits,
                lowered,
                &mut words,
            );
        }

        for (i, atom) in self.cs_substr_atoms.iter().enumerate() {
            if cached_finder(atom).find(content).is_some()
                && let Some(trait_indices) = self.cs_substr_to_traits.get(i)
            {
                substr.extend(trait_indices.iter().copied());
            }
        }
        if let Some(lowered) = lowered.as_deref() {
            for (i, atom) in self.ci_substr_atoms.iter().enumerate() {
                if cached_finder(atom).find(lowered).is_some()
                    && let Some(trait_indices) = self.ci_substr_to_traits.get(i)
                {
                    substr.extend(trait_indices.iter().copied());
                }
            }
        }

        self.assemble_matches(
            words,
            substr,
            &literal_candidates,
            &self.no_literal_pass(content),
            content,
        )
    }

    /// Step 2: run individual regexes for candidate patterns, folding their
    /// traits into `matched_traits`. Candidates whose traits are all already
    /// matched are skipped — a work-saving check only; the result is the same
    /// union either way.
    fn verify_literal_candidates(
        &self,
        literal_candidates: &FxHashSet<usize>,
        matched_traits: &mut FxHashSet<usize>,
        content: &[u8],
    ) {
        // Each candidate verifies against the WHOLE content, so on a large
        // input every one is a full scan and they add up to a single-threaded
        // tail. They are independent — the already-matched skip below is a
        // work-saving check, not a dependency (the docstring's "same union
        // either way") — so a read-only snapshot of `matched_traits` is a
        // sound basis for it and the verifies can run concurrently.
        const PARALLEL_MIN_BYTES: usize = 1 << 20;
        let verify = |&pattern_idx: &usize| -> Option<&[usize]> {
            let trait_indices = self.pattern_to_traits.get(pattern_idx)?;
            if trait_indices.iter().all(|t| matched_traits.contains(t)) {
                return None;
            }
            // Race-don't-block: concurrent first users each compile and the
            // first `set` wins. `get_or_init` would serialize the pile-up of
            // rayon workers hitting a popular pattern during warmup — the
            // same idled-cores trap the bytes-regex cache documents (its
            // per-key OnceLock experiment raised wall ~35%).
            let slot = &self.individual_regexes[pattern_idx];
            if slot.get().is_none() {
                let pattern = &self.patterns[pattern_idx];
                let compiled = match compile_engine_mirrored(pattern) {
                    Ok(re) => Some(Arc::new(re)),
                    Err(e) => {
                        tracing::warn!(pattern, error = %e, "raw content pattern failed to compile; skipping");
                        None
                    }
                };
                let _ = slot.set(compiled);
            }
            match slot.get() {
                Some(Some(regex)) if regex.is_match(content) => Some(trait_indices),
                _ => None,
            }
        };

        if content.len() >= PARALLEL_MIN_BYTES
            && literal_candidates.len() > 1
            && crate::rayon_nest::inner_work_parallel()
        {
            use rayon::prelude::*;
            let hits: Vec<&[usize]> = literal_candidates.par_iter().filter_map(verify).collect();
            matched_traits.extend(hits.into_iter().flatten().copied());
        } else {
            let hits: Vec<&[usize]> = literal_candidates.iter().filter_map(verify).collect();
            matched_traits.extend(hits.into_iter().flatten().copied());
        }
    }

    /// Step 3: patterns without extractable literals (unavoidable full scans).
    ///
    /// Evaluated per pattern rather than as one multi-pattern `RegexSet`: the
    /// set's `matches()` runs the PikeVM over every byte with all patterns
    /// live (no prefilters, no early exit) and was the dominant leaf on
    /// many-member archives. Individual `Regex::is_match` gives each pattern
    /// the full meta-engine stack — lazy DFA, regex-automata's own inner
    /// literal prefilters (more permissive than our atom extractor) — plus
    /// first-match early exit, and large content fans the patterns across
    /// the pool. Presence-per-pattern semantics are identical.
    fn no_literal_pass(&self, content: &[u8]) -> FxHashSet<usize> {
        const PARALLEL_MIN_BYTES: usize = 1 << 20;
        let mut out = FxHashSet::default();
        if self.no_literal_regexes.is_empty() {
            return out;
        }
        let matched: Vec<usize> = if content.len() >= PARALLEL_MIN_BYTES
            && self.no_literal_regexes.len() > 1
            && crate::rayon_nest::inner_work_parallel()
        {
            use rayon::prelude::*;
            self.no_literal_regexes
                .par_iter()
                .zip(self.no_literal_to_original.par_iter())
                .filter_map(|(re, &idx)| re.is_match(content).then_some(idx))
                .collect()
        } else {
            self.no_literal_regexes
                .iter()
                .zip(self.no_literal_to_original.iter())
                .filter_map(|(re, &idx)| re.is_match(content).then_some(idx))
                .collect()
        };
        for original_idx in matched {
            if let Some(trait_indices) = self.pattern_to_traits.get(original_idx) {
                out.extend(trait_indices.iter().copied());
            }
        }
        out
    }
}

/// Compile a raw-content pattern with the same parse mode the trait engines
/// use (`condition.rs::TraitRegex::compile`): byte-mode classes for ASCII
/// patterns with a codepoint fallback, codepoint mode for non-ASCII patterns
/// (and under `CLEAVE_REGEX_UNICODE=1`). The gate's verifiers must mirror the
/// engine's parse mode or the two diverge — Unicode-mode verifiers here were
/// also the reason gate sweeps ran the PikeVM (Unicode `\b` quits the lazy
/// DFA on non-ASCII bytes) instead of the DFA the engines use.
fn compile_engine_mirrored(pattern: &str) -> Result<regex::bytes::Regex, regex::Error> {
    const SIZE_LIMIT: usize = 100 * 1024 * 1024;
    if pattern.is_ascii()
        && !crate::composite_rules::evaluators::regex_unicode_override()
        && let Ok(re) = regex::bytes::RegexBuilder::new(pattern)
            .size_limit(SIZE_LIMIT)
            .unicode(false)
            .build()
    {
        return Ok(re);
    }
    // `\p{..}` classes are ASCII source but only parse in codepoint mode.
    regex::bytes::RegexBuilder::new(pattern)
        .size_limit(SIZE_LIMIT)
        .build()
}

/// A word pattern: the literal word and whether it's case-insensitive
struct WordPattern {
    word: String,
    case_insensitive: bool,
    trait_idx: usize,
}

impl RawContentRegexIndex {
    /// Build index from trait definitions (all platforms).
    #[cfg(test)] // non-filtered convenience; production builds go through build_filtered
    pub(crate) fn build(traits: &[TraitDefinition]) -> Self {
        Self::build_filtered(traits, &[Platform::All])
    }

    /// Build index, keeping only traits whose platform set intersects `platforms`.
    /// Off-platform traits keep their absolute index slot but contribute no patterns.
    pub(crate) fn build_filtered(traits: &[TraitDefinition], platforms: &[Platform]) -> Self {
        // Group patterns by file type
        let mut by_file_type_patterns: FxHashMap<RuleFileType, Vec<(String, usize)>> =
            FxHashMap::default();
        let mut universal_patterns: Vec<(String, usize)> = Vec::new();
        // Word patterns separated for Aho-Corasick batch matching
        let mut by_file_type_words: FxHashMap<RuleFileType, Vec<WordPattern>> =
            FxHashMap::default();
        let mut universal_words: Vec<WordPattern> = Vec::new();
        // Candidate-only substring atoms from `type: text`-on-source regex traits.
        let mut by_file_type_substr: FxHashMap<RuleFileType, Vec<WordPattern>> =
            FxHashMap::default();
        let mut universal_substr: Vec<WordPattern> = Vec::new();

        for (trait_idx, trait_def) in traits.iter().enumerate() {
            if !platforms_intersect(&trait_def.platforms, platforms) {
                continue;
            }
            // Extract regex patterns from Content traits
            // Word patterns are routed to a dedicated Aho-Corasick automaton
            match &trait_def.r#if {
                Condition::Raw(RawQuery {
                    regex: Some(regex_str),
                    case_insensitive,
                    ..
                }) => {
                    let pattern = if *case_insensitive {
                        format!("(?i){}", regex_str)
                    } else {
                        regex_str.clone()
                    };
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
                Condition::Raw(RawQuery {
                    word: Some(word_str),
                    case_insensitive,
                    ..
                }) => {
                    let wp = WordPattern {
                        word: word_str.clone(),
                        case_insensitive: *case_insensitive,
                        trait_idx,
                    };
                    if trait_def.r#for.contains(&RuleFileType::All) {
                        universal_words.push(wp);
                    } else {
                        for ft in &trait_def.r#for {
                            by_file_type_words
                                .entry(*ft)
                                .or_default()
                                .push(WordPattern {
                                    word: word_str.clone(),
                                    case_insensitive: *case_insensitive,
                                    trait_idx,
                                });
                        }
                    }
                }
                // `type: text` on source delegates to `eval_raw` (raw content);
                // gate it via cheap atom prefilters so its PikeVM runs only when an
                // atom is present — but candidate-only, with no compiled verifier
                // (eval_raw verifies). `word:` reuses the boundary-checked word path;
                // `regex:` contributes its mandatory literal (if extractable) to the
                // substring path. A regex with no extractable literal stays unindexed
                // (ungated; eval_raw scans it as before — correctness over speed).
                Condition::Text(TextQuery {
                    word: Some(word_str),
                    case_insensitive,
                    ..
                }) => {
                    let make = || WordPattern {
                        word: word_str.clone(),
                        case_insensitive: *case_insensitive,
                        trait_idx,
                    };
                    if trait_def.r#for.contains(&RuleFileType::All) {
                        universal_words.push(make());
                    } else {
                        for ft in &trait_def.r#for {
                            by_file_type_words.entry(*ft).or_default().push(make());
                        }
                    }
                }
                Condition::Text(TextQuery {
                    regex: Some(regex_str),
                    case_insensitive,
                    ..
                }) => {
                    // Gate on a mandatory *any-of* atom set (alternation-aware,
                    // `(?i)`-aware — see `mandatory_atom_set`), not just a
                    // prefix — otherwise ~half of `type: text` patterns are
                    // ungated and re-scan every source file. Multiple entries
                    // sharing a trait_idx give any-of semantics for free: a hit
                    // on any atom marks the trait a candidate. Non-UTF-8 or
                    // inextractable sets stay ungated (eval_raw scans directly).
                    if let Some(atoms) = super::derivation_memo::mandatory_atom_set(regex_str) {
                        for (literal, atom_ci) in &atoms {
                            let make = || WordPattern {
                                word: literal.clone(),
                                case_insensitive: *case_insensitive || *atom_ci,
                                trait_idx,
                            };
                            if trait_def.r#for.contains(&RuleFileType::All) {
                                universal_substr.push(make());
                            } else {
                                for ft in &trait_def.r#for {
                                    by_file_type_substr.entry(*ft).or_default().push(make());
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Verifier regexes are no longer pre-compiled here — each
        // `FileTypeRegexSet` slot compiles lazily on its first atom hit (see
        // `verify_literal_candidates`), so a scan pays only for the patterns
        // its content actually triggers.
        let t_fts = std::time::Instant::now();

        // Build regex sets for each file type in parallel
        // Collect all file types that need building
        let all_file_types: FxHashSet<RuleFileType> = by_file_type_patterns
            .keys()
            .chain(by_file_type_words.keys())
            .chain(by_file_type_substr.keys())
            .copied()
            .collect();
        let ft_data: Vec<_> = all_file_types
            .into_iter()
            .map(|ft| {
                let patterns = by_file_type_patterns.remove(&ft).unwrap_or_default();
                let words = by_file_type_words.remove(&ft).unwrap_or_default();
                let substr = by_file_type_substr.remove(&ft).unwrap_or_default();
                (ft, patterns, words, substr)
            })
            .collect();
        let results: Vec<_> = ft_data
            .into_par_iter()
            .map(|(ft, patterns, words, substr)| {
                (ft, Self::build_regex_set(&patterns, &words, &substr))
            })
            .collect();

        let mut by_file_type = FxHashMap::default();
        for (ft, result) in results {
            if let Some(set) = result {
                by_file_type.insert(ft, set);
            }
        }
        let fts_ms = t_fts.elapsed().as_millis() as u64;
        let t_universal = std::time::Instant::now();

        // Build universal patterns (can run in parallel with file-type-specific building
        // but kept separate for clarity)
        let universal =
            Self::build_regex_set(&universal_patterns, &universal_words, &universal_substr);
        tracing::debug!(
            fts_ms,
            universal_ms = t_universal.elapsed().as_millis() as u64,
            file_types = by_file_type.len(),
            "raw-content regex index built"
        );

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
            // Count word patterns
            for trait_indices in &ft_set.cs_word_to_traits {
                total_patterns += 1;
                for &trait_idx in trait_indices {
                    indexed_traits.insert(trait_idx);
                }
            }
            for trait_indices in &ft_set.ci_word_to_traits {
                total_patterns += 1;
                for &trait_idx in trait_indices {
                    indexed_traits.insert(trait_idx);
                }
            }
            for trait_indices in ft_set
                .cs_substr_to_traits
                .iter()
                .chain(&ft_set.ci_substr_to_traits)
            {
                total_patterns += 1;
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
            for trait_indices in &universal_set.cs_word_to_traits {
                total_patterns += 1;
                for &trait_idx in trait_indices {
                    indexed_traits.insert(trait_idx);
                }
            }
            for trait_indices in &universal_set.ci_word_to_traits {
                total_patterns += 1;
                for &trait_idx in trait_indices {
                    indexed_traits.insert(trait_idx);
                }
            }
            for trait_indices in universal_set
                .cs_substr_to_traits
                .iter()
                .chain(&universal_set.ci_substr_to_traits)
            {
                total_patterns += 1;
                for &trait_idx in trait_indices {
                    indexed_traits.insert(trait_idx);
                }
            }
        }

        Self {
            by_file_type,
            universal,
            indexed_traits,
            total_patterns,
        }
    }

    fn build_regex_set(
        patterns: &[(String, usize)],
        words: &[WordPattern],
        substr: &[WordPattern],
    ) -> Option<FileTypeRegexSet> {
        if patterns.is_empty() && words.is_empty() && substr.is_empty() {
            return None;
        }

        // Group traits by unique pattern to avoid redundancy
        let mut pattern_map: FxHashMap<String, Vec<usize>> = FxHashMap::default();
        for (pattern, trait_idx) in patterns {
            pattern_map
                .entry(pattern.clone())
                .or_default()
                .push(*trait_idx);
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

            if let Some(literal) = super::derivation_memo::prefix_literal(pattern) {
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
                .kind(ac_kind())
                .ascii_case_insensitive(false)
                .build(&cs_literal_prefixes)
                .ok()
        } else {
            None
        };

        // Build case-insensitive Aho-Corasick automaton
        let ci_literal_prefilter = if !ci_literal_prefixes.is_empty() {
            AhoCorasick::builder()
                .kind(ac_kind())
                .ascii_case_insensitive(true)
                .build(&ci_literal_prefixes)
                .ok()
        } else {
            None
        };

        // Verifier regexes compile lazily on first atom hit (see
        // `verify_literal_candidates`); allocate the empty slots.
        let individual_regexes: Vec<OnceLock<Option<Arc<regex::bytes::Regex>>>> =
            (0..pattern_strs.len()).map(|_| OnceLock::new()).collect();

        // Compile the no-extractable-literal patterns individually (see
        // `no_literal_pass`). A pattern that fails to compile is dropped with
        // a warning — strictly better than the old single-RegexSet build,
        // where one bad pattern discarded every no-literal pattern.
        let mut no_literal_regexes: Vec<regex::bytes::Regex> = Vec::new();
        let mut no_literal_to_original: Vec<usize> = Vec::new();
        for &idx in &patterns_without_literals {
            let Some(pattern) = pattern_strs.get(idx) else {
                continue;
            };
            match compile_engine_mirrored(pattern) {
                Ok(re) => {
                    no_literal_regexes.push(re);
                    no_literal_to_original.push(idx);
                }
                Err(e) => {
                    tracing::warn!(pattern, error = %e, "no-literal pattern failed to compile; skipping");
                }
            }
        }

        // Build word boundary Aho-Corasick automatons
        // Separate case-sensitive and case-insensitive words
        let mut cs_words: Vec<String> = Vec::new();
        let mut cs_word_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut cs_word_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut ci_words: Vec<String> = Vec::new();
        let mut ci_word_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut ci_word_map: FxHashMap<String, usize> = FxHashMap::default();

        for wp in words {
            if wp.case_insensitive {
                let lower = wp.word.to_lowercase();
                if let Some(&idx) = ci_word_map.get(&lower) {
                    ci_word_to_traits[idx].push(wp.trait_idx);
                } else {
                    let idx = ci_words.len();
                    ci_word_map.insert(lower.clone(), idx);
                    ci_words.push(lower);
                    ci_word_to_traits.push(vec![wp.trait_idx]);
                }
            } else if let Some(&idx) = cs_word_map.get(&wp.word) {
                cs_word_to_traits[idx].push(wp.trait_idx);
            } else {
                let idx = cs_words.len();
                cs_word_map.insert(wp.word.clone(), idx);
                cs_words.push(wp.word.clone());
                cs_word_to_traits.push(vec![wp.trait_idx]);
            }
        }

        let cs_word_automaton = if !cs_words.is_empty() {
            AhoCorasick::builder()
                .kind(ac_kind())
                .ascii_case_insensitive(false)
                .build(&cs_words)
                .ok()
        } else {
            None
        };

        let ci_word_automaton = if !ci_words.is_empty() {
            AhoCorasick::builder()
                .kind(ac_kind())
                .ascii_case_insensitive(true)
                .build(&ci_words)
                .ok()
        } else {
            None
        };

        // Substring-atom automata (candidate-only, no boundary check) for text traits.
        let mut cs_substr: Vec<String> = Vec::new();
        let mut cs_substr_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut cs_substr_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut ci_substr: Vec<String> = Vec::new();
        let mut ci_substr_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut ci_substr_map: FxHashMap<String, usize> = FxHashMap::default();
        for sp in substr {
            if sp.case_insensitive {
                let lower = sp.word.to_lowercase();
                if let Some(&idx) = ci_substr_map.get(&lower) {
                    ci_substr_to_traits[idx].push(sp.trait_idx);
                } else {
                    let idx = ci_substr.len();
                    ci_substr_map.insert(lower.clone(), idx);
                    ci_substr.push(lower);
                    ci_substr_to_traits.push(vec![sp.trait_idx]);
                }
            } else if let Some(&idx) = cs_substr_map.get(&sp.word) {
                cs_substr_to_traits[idx].push(sp.trait_idx);
            } else {
                let idx = cs_substr.len();
                cs_substr_map.insert(sp.word.clone(), idx);
                cs_substr.push(sp.word.clone());
                cs_substr_to_traits.push(vec![sp.trait_idx]);
            }
        }
        let cs_substr_automaton = if !cs_substr.is_empty() {
            AhoCorasick::builder()
                .kind(ac_kind())
                .ascii_case_insensitive(false)
                .build(&cs_substr)
                .ok()
        } else {
            None
        };
        let ci_substr_automaton = if !ci_substr.is_empty() {
            AhoCorasick::builder()
                .kind(ac_kind())
                .ascii_case_insensitive(true)
                .build(&ci_substr)
                .ok()
        } else {
            None
        };

        // If there are no regex patterns (only word/substr patterns), build a minimal set
        if pattern_strs.is_empty() {
            return Some(FileTypeRegexSet {
                pattern_to_traits: Vec::new(),
                patterns: Vec::new(),
                individual_regexes: Vec::new(),
                no_literal_regexes: Vec::new(),
                no_literal_to_original: Vec::new(),
                cs_literal_prefilter: None,
                cs_literal_to_patterns: Vec::new(),
                ci_literal_prefilter: None,
                ci_literal_to_patterns: Vec::new(),
                patterns_without_literals: Vec::new(),
                cs_word_automaton,
                cs_word_to_traits,
                ci_word_automaton,
                ci_word_to_traits,
                cs_substr_automaton,
                cs_substr_to_traits,
                ci_substr_automaton,
                ci_substr_to_traits,
                cs_literal_atoms: Vec::new(),
                ci_literal_atoms: Vec::new(),
                cs_word_atoms: cs_words,
                ci_word_atoms: ci_words,
                cs_substr_atoms: cs_substr,
                ci_substr_atoms: ci_substr,
            });
        }

        // Pattern validity is no longer checked here. Verifiers compile
        // lazily; an invalid pattern warns and skips itself at eval time
        // instead of (as before) failing this build and silently degrading
        // the ENTIRE raw-content index to empty. Author-grade validation
        // belongs to `cleave validate`.
        Some(FileTypeRegexSet {
            pattern_to_traits,
            patterns: pattern_strs,
            individual_regexes,
            no_literal_regexes,
            no_literal_to_original,
            cs_literal_prefilter,
            cs_literal_to_patterns,
            ci_literal_prefilter,
            ci_literal_to_patterns,
            patterns_without_literals,
            cs_word_automaton,
            cs_word_to_traits,
            ci_word_automaton,
            ci_word_to_traits,
            cs_substr_automaton,
            cs_substr_to_traits,
            ci_substr_automaton,
            ci_substr_to_traits,
            cs_literal_atoms: cs_literal_prefixes,
            ci_literal_atoms: ci_literal_prefixes,
            cs_word_atoms: cs_words,
            ci_word_atoms: ci_words,
            cs_substr_atoms: cs_substr,
            ci_substr_atoms: ci_substr,
        })
    }

    pub(crate) fn has_patterns(&self) -> bool {
        self.total_patterns > 0
    }

    /// Check if any of the provided trait indices are indexed in the raw content regex index.
    #[allow(dead_code)]
    pub(crate) fn has_applicable_patterns(&self, trait_indices: &[usize]) -> bool {
        trait_indices.iter().any(|&idx| self.is_indexed_trait(idx))
    }

    /// Check whether a trait is indexed in a compiled regex set.
    pub(crate) fn is_indexed_trait(&self, trait_idx: usize) -> bool {
        self.indexed_traits.contains(&trait_idx)
    }

    /// Debug helper: every bucket that holds `trait_idx`, with the sub-index it
    /// sits in. For diagnosing gate/bucket mismatches.
    #[allow(dead_code)]
    pub(crate) fn debug_trait_buckets(&self, trait_idx: usize) -> String {
        let mut out = Vec::new();
        let mut check = |name: String, s: &FileTypeRegexSet| {
            if s.pattern_to_traits.iter().any(|v| v.contains(&trait_idx)) {
                out.push(format!("{name}:pattern"));
            }
            if s.cs_word_to_traits
                .iter()
                .chain(&s.ci_word_to_traits)
                .any(|v| v.contains(&trait_idx))
            {
                out.push(format!("{name}:word"));
            }
            if s.cs_substr_to_traits
                .iter()
                .chain(&s.ci_substr_to_traits)
                .any(|v| v.contains(&trait_idx))
            {
                out.push(format!("{name}:substr"));
            }
        };
        if let Some(u) = &self.universal {
            check("universal".to_string(), u);
        }
        for (ft, s) in &self.by_file_type {
            check(format!("{ft:?}"), s);
        }
        out.join(",")
    }

    /// Find matches using only patterns applicable to the given file type.
    /// Uses Aho-Corasick literal prefix pre-filtering to skip RegexSet when possible.
    ///
    /// The universal set, the file-type set and the archive-family sets are
    /// independent scans over the same bytes whose results are unioned, so on
    /// large content they run concurrently. Each set already fans its own
    /// sub-passes out (see [`FileTypeRegexSet::find_matches`]), but those
    /// fan-outs were serialized behind one another: a container's raw bytes
    /// (hundreds of MB) paid every set's slowest pass end to end.
    #[cfg(test)]
    pub(crate) fn find_matches(
        &self,
        binary_data: &[u8],
        file_type: &RuleFileType,
    ) -> FxHashSet<usize> {
        self.find_matches_classified(binary_data, file_type).0
    }

    fn find_matches_classified(
        &self,
        binary_data: &[u8],
        file_type: &RuleFileType,
    ) -> (FxHashSet<usize>, FxHashSet<usize>) {
        const PARALLEL_MIN_BYTES: usize = 4 << 20;

        let sets: Vec<&FileTypeRegexSet> = self
            .universal
            .iter()
            .chain(self.by_file_type.get(file_type))
            .chain(
                archive_family_types(file_type)
                    .iter()
                    .filter_map(|ft| self.by_file_type.get(ft)),
            )
            .collect();

        if binary_data.len() >= PARALLEL_MIN_BYTES
            && sets.len() > 1
            && crate::rayon_nest::inner_work_parallel()
        {
            use rayon::prelude::*;
            return sets
                .par_iter()
                .map(|set| set.find_matches_classified(binary_data))
                .reduce(
                    || (FxHashSet::default(), FxHashSet::default()),
                    |mut a, b| {
                        a.0.extend(b.0);
                        a.1.extend(b.1);
                        a
                    },
                );
        }

        let mut traits = FxHashSet::default();
        let mut verified = FxHashSet::default();
        for set in sets {
            let (t, v) = set.find_matches_classified(binary_data);
            traits.extend(t);
            verified.extend(v);
        }
        (traits, verified)
    }

    /// Like [`Self::find_matches`], optionally recording atom-hit offsets for
    /// source-only windowed `eval_raw`. Presence semantics are identical.
    pub(crate) fn find_matches_detailed(
        &self,
        binary_data: &[u8],
        file_type: &RuleFileType,
        record_offsets: bool,
    ) -> RawGateHits {
        // Windowing is disabled below [`MIN_HAYSTACK_TO_WINDOW`]. Recording
        // every atom occurrence on sub-floor stubs is extra gate work that
        // `eval_raw` would never use (S2n). The floor is 256 B so 256 B–1 KiB
        // source members can window bounded regexes.
        if !record_offsets || binary_data.len() < MIN_HAYSTACK_TO_WINDOW {
            let (traits, _) = self.find_matches_classified(binary_data, file_type);
            return RawGateHits {
                traits,
                atom_offsets: FxHashMap::default(),
            };
        }
        let sets: Vec<&FileTypeRegexSet> = self
            .universal
            .iter()
            .chain(self.by_file_type.get(file_type))
            .chain(
                archive_family_types(file_type)
                    .iter()
                    .filter_map(|ft| self.by_file_type.get(ft)),
            )
            .collect();
        let mut rec = OffsetRecorder::new();
        let mut traits = FxHashSet::default();
        for set in sets {
            let (t, _) = set.find_matches_recording(binary_data, &mut rec);
            traits.extend(t);
        }
        RawGateHits {
            traits,
            atom_offsets: rec.finish(),
        }
    }

    /// Candidate-only sweep for small secondary haystacks (the decoded string
    /// layers unioned into the gate). Unlike [`Self::find_matches`], the
    /// pattern-bucket literal candidates map straight to their traits without
    /// full-content regex verification — an over-approximation, which is
    /// exactly what a gate union wants (the trait evaluator verifies for
    /// real), and it keeps this pass cheap on decode-heavy members where the
    /// verify step measured as a wall regression.
    pub(crate) fn find_candidates(
        &self,
        content: &[u8],
        file_type: &RuleFileType,
    ) -> FxHashSet<usize> {
        let mut out = FxHashSet::default();
        for set in self
            .universal
            .iter()
            .chain(self.by_file_type.get(file_type))
            .chain(
                archive_family_types(file_type)
                    .iter()
                    .filter_map(|ft| self.by_file_type.get(ft)),
            )
        {
            out.extend(set.find_candidates(content));
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::composite_rules::{Arch, Platform};

    // ==================== TraitIndex Tests ====================

    #[test]
    fn test_trait_index_new() {
        let index = TraitIndex::new();
        assert!(index.universal.bits.is_empty());
        assert!(index.by_file_type.is_empty());
    }

    #[test]
    fn test_trait_index_get_applicable_empty() {
        let index = TraitIndex::new();
        let applicable: Vec<usize> = index
            .get_applicable(&RuleFileType::All)
            .into_indices_static()
            .collect();
        assert!(applicable.is_empty());
    }

    #[test]
    fn test_trait_bitset_into_indices_static_advances_words() {
        let mut bitset = TraitBitSet::with_capacity(130);
        bitset.insert(1);
        bitset.insert(65);
        bitset.insert(129);

        let indices: Vec<usize> = bitset.into_indices_static().collect();
        assert_eq!(indices, vec![1, 65, 129]);
    }

    #[test]
    fn test_trait_bitset_to_indices_static_advances_words() {
        let mut bitset = TraitBitSet::with_capacity(130);
        bitset.insert(0);
        bitset.insert(64);
        bitset.insert(127);

        let indices: Vec<usize> = bitset.to_indices_static().collect();
        assert_eq!(indices, vec![0, 64, 127]);
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
        let index = RawContentRegexIndex::build(&[]);

        assert!(!index.has_patterns());
        assert_eq!(index.total_patterns, 0);
    }

    #[test]
    fn test_raw_content_regex_index_has_applicable_patterns_empty() {
        let index = RawContentRegexIndex::build(&[]);

        assert!(!index.has_applicable_patterns(&[]));
        assert!(!index.has_applicable_patterns(&[0, 1, 2]));
    }

    #[test]
    fn test_raw_content_regex_index_is_indexed_trait_empty() {
        let index = RawContentRegexIndex::build(&[]);

        assert!(!index.is_indexed_trait(0));
        assert!(!index.is_indexed_trait(100));
    }

    #[test]
    fn test_raw_content_regex_index_find_matches_empty() {
        let index = RawContentRegexIndex::build(&[]);
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
            arch: vec![Arch::All],
            r#for: vec![RuleFileType::All],
            for_from_groups: false,
            r#if: Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: None,
                substr: None,
                regex: Some("test".to_string()),
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
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
            ..Default::default()
        };

        let index = RawContentRegexIndex::build(&[trait_def]);
        // Content with invalid UTF-8 and the target string
        let content = &[0xFF, b't', b'e', b's', b't', 0xFE];

        let matches = index.find_matches(content, &RuleFileType::All);
        // Direct binary matching handles invalid UTF-8 naturally
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_raw_content_regex_index_lazy_verifiers_match_per_bucket() {
        let make_raw_regex_trait = |id: &str, file_type: RuleFileType| TraitDefinition {
            id: id.to_string(),
            desc: id.to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Baseline,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![file_type],
            for_from_groups: false,
            r#if: Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: None,
                substr: None,
                regex: Some("test".to_string()),
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
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
            ..Default::default()
        };

        let index = RawContentRegexIndex::build(&[
            make_raw_regex_trait("js", RuleFileType::JavaScript),
            make_raw_regex_trait("py", RuleFileType::Python),
        ]);

        // Verifier regexes are lazy: slots start empty and compile on first
        // atom hit (formerly they were eagerly compiled and Arc-shared across
        // buckets — the eager pass cost ~300 ms of every process start).
        let js_set = index.by_file_type.get(&RuleFileType::JavaScript).unwrap();
        let py_set = index.by_file_type.get(&RuleFileType::Python).unwrap();
        assert!(js_set.individual_regexes[0].get().is_none());
        assert!(py_set.individual_regexes[0].get().is_none());

        // A find_matches pass over content containing the literal atom must
        // trigger compilation and match in each bucket independently.
        let js_matches = index.find_matches(b"some test content", &RuleFileType::JavaScript);
        let py_matches = index.find_matches(b"some test content", &RuleFileType::Python);
        assert!(!js_matches.is_empty());
        assert!(!py_matches.is_empty());
        assert!(js_set.individual_regexes[0].get().is_some());
        assert!(py_set.individual_regexes[0].get().is_some());
    }

    // ==================== Overlapping Substr Match Tests ====================

    /// Helper: build a TraitDefinition with a substr Text condition
    fn make_substr_trait(id: &str, substr: &str) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: id.to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![RuleFileType::All],
            for_from_groups: false,
            r#if: Condition::Text(TextQuery {
                length_min: None,
                length_max: None,
                exact: None,
                substr: Some(substr.to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                not: None,
                platforms: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
            }),
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
            ..Default::default()
        }
    }

    /// Helper: build a StringInfo with a value
    fn make_string(value: &str) -> StringInfo {
        StringInfo {
            value: (value.to_string()).into(),
            offset: None,
            encoding: "utf-8".to_string(),
            string_type: None,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        }
    }

    fn make_text_regex_trait(id: &str, regex: &str) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: id.to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![RuleFileType::All],
            for_from_groups: false,
            r#if: Condition::Text(TextQuery {
                length_min: None,
                length_max: None,
                exact: None,
                substr: None,
                regex: Some(regex.to_string()),
                word: None,
                case_insensitive: false,
                is_check: None,
                not: None,
                platforms: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
            }),
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
            ..Default::default()
        }
    }

    /// A regex trait whose literal prefix IS extractable (`\bfetch\s+...` →
    /// "fetch") must still surface as a candidate via the literal prefilter.
    /// Guards the precomputed `regex_traits_without_literals` hoist: the
    /// candidate set must match the old per-call computation exactly.
    #[test]
    fn test_regex_candidate_with_extractable_literal() {
        let pat = r"\bfetch\s+(-|https?://|ftp://)";
        assert_eq!(
            StringMatchIndex::extract_regex_literal(pat).as_deref(),
            Some("fetch"),
            "literal prefix should be extractable"
        );
        let traits = vec![make_text_regex_trait("fetch-cmd", pat)];
        let index = StringMatchIndex::build(&traits);
        // Trait has a literal, so it is NOT in the always-candidate set; it must
        // be found by the literal prefilter when a matching string is present.
        assert!(index.regex_traits_without_literals.is_empty());
        let hit = index.find_regex_candidates(&[&make_string("fetch http://evil.example/x")]);
        assert!(
            hit.contains(&0),
            "fetch-cmd must be a candidate when 'fetch' is present"
        );
        let miss = index.find_regex_candidates(&[&make_string("nothing relevant here")]);
        assert!(
            !miss.contains(&0),
            "fetch-cmd must NOT be a candidate without its literal"
        );
    }

    /// A regex trait with NO extractable literal must always be a candidate
    /// (it can't be prefiltered). This is the case the precompute must never drop.
    #[test]
    fn test_regex_candidate_without_extractable_literal() {
        let pat = r"\d{3}-\d{4}"; // no >=3-char literal prefix
        assert_eq!(StringMatchIndex::extract_regex_literal(pat), None);
        let traits = vec![make_text_regex_trait("no-literal", pat)];
        let index = StringMatchIndex::build(&traits);
        assert_eq!(index.regex_traits_without_literals, vec![0]);
        // Always a candidate, regardless of input strings.
        assert!(
            index
                .find_regex_candidates(&[&make_string("xyz")])
                .contains(&0)
        );
        assert!(index.find_regex_candidates(&[]).contains(&0));
    }

    /// Regression test: a longer substr pattern must match even when a shorter
    /// pattern is embedded within it. Before the fix, Aho-Corasick's
    /// non-overlapping `find_iter` would match "output" (from another trait)
    /// and skip "set volume output muted true" entirely.
    #[test]
    fn test_substr_overlapping_short_pattern_inside_long() {
        let traits = vec![
            make_substr_trait("short-trait", "output"),
            make_substr_trait("long-trait", "set volume output muted true"),
        ];
        let index = StringMatchIndex::build(&traits);

        let strings = [make_string("set volume output muted true")];
        let (matched, evidence) =
            index.find_matches_with_evidence(&strings.iter().collect::<Vec<_>>());

        // Both traits must match: the short "output" AND the long full string
        assert!(
            matched.contains(&0),
            "short-trait (idx=0, pattern='output') should match"
        );
        assert!(
            matched.contains(&1),
            "long-trait (idx=1, pattern='set volume output muted true') should match"
        );
        assert!(
            evidence.contains_key(&0),
            "short-trait should have evidence"
        );
        assert!(evidence.contains_key(&1), "long-trait should have evidence");
    }

    /// Same test but with patterns in reverse order (long before short)
    #[test]
    fn test_substr_overlapping_long_pattern_before_short() {
        let traits = vec![
            make_substr_trait("long-trait", "set volume output muted true"),
            make_substr_trait("short-trait", "output"),
        ];
        let index = StringMatchIndex::build(&traits);

        let strings = [make_string("set volume output muted true")];
        let (matched, _) = index.find_matches_with_evidence(&strings.iter().collect::<Vec<_>>());

        assert!(matched.contains(&0), "long-trait should match");
        assert!(matched.contains(&1), "short-trait should match");
    }

    /// Multiple overlapping patterns at different positions
    #[test]
    fn test_substr_multiple_overlapping_patterns() {
        let traits = vec![
            make_substr_trait("trait-a", "curl"),
            make_substr_trait("trait-b", "curl_easy"),
            make_substr_trait("trait-c", "curl_easy_setopt"),
        ];
        let index = StringMatchIndex::build(&traits);

        let strings = [make_string("curl_easy_setopt")];
        let (matched, _) = index.find_matches_with_evidence(&strings.iter().collect::<Vec<_>>());

        assert!(matched.contains(&0), "'curl' should match");
        assert!(matched.contains(&1), "'curl_easy' should match");
        assert!(matched.contains(&2), "'curl_easy_setopt' should match");
    }

    /// Parallel path: same overlapping test but with enough strings to trigger parallel
    #[test]
    fn test_substr_overlapping_parallel_path() {
        let traits = vec![
            make_substr_trait("short-trait", "output"),
            make_substr_trait("long-trait", "set volume output muted true"),
        ];
        let index = StringMatchIndex::build(&traits);

        // Build >1000 strings to trigger parallel path
        let mut strings: Vec<StringInfo> = (0..1001)
            .map(|i| make_string(&format!("filler string {i}")))
            .collect();
        strings.push(make_string("set volume output muted true"));

        let (matched, _) = index.find_matches_with_evidence(&strings.iter().collect::<Vec<_>>());

        assert!(
            matched.contains(&0),
            "short-trait should match in parallel path"
        );
        assert!(
            matched.contains(&1),
            "long-trait should match in parallel path"
        );
    }

    /// Case-insensitive overlapping patterns
    #[test]
    fn test_substr_overlapping_case_insensitive() {
        let make_ci_substr_trait = |id: &str, substr: &str| -> TraitDefinition {
            let mut t = make_substr_trait(id, substr);
            if let Condition::Text(TextQuery {
                ref mut case_insensitive,
                ..
            }) = t.r#if
            {
                *case_insensitive = true;
            }
            t
        };

        let traits = vec![
            make_ci_substr_trait("short-ci", "output"),
            make_ci_substr_trait("long-ci", "set volume output muted true"),
        ];
        let index = StringMatchIndex::build(&traits);

        let strings = [make_string("Set Volume Output Muted True")];
        let (matched, _) = index.find_matches_with_evidence(&strings.iter().collect::<Vec<_>>());

        assert!(
            matched.contains(&0),
            "case-insensitive short pattern should match"
        );
        assert!(
            matched.contains(&1),
            "case-insensitive long pattern should match"
        );
    }

    fn make_exact_trait(id: &str, exact: &str) -> TraitDefinition {
        let mut t = make_substr_trait(id, "unused");
        t.r#if = Condition::Text(TextQuery {
            exact: Some(exact.to_string()),
            ..Default::default()
        });
        t
    }

    #[test]
    fn raw_source_prefilter_exact_is_substring_not_whole_file() {
        let traits = vec![
            make_exact_trait("has-eval", "eval"),
            make_exact_trait("pe-api", "VirtualAlloc"),
        ];
        let index = StringMatchIndex::build(&traits);
        let mut src = String::from("const x = 1;\neval('x');\n");
        while src.len() < StringMatchIndex::MIN_SOURCE_TEXT_PREFILTER_BYTES {
            src.push_str("// pad\n");
        }
        let (matched, _regex) = index
            .find_matches_in_raw_source(src.as_bytes())
            .expect("UTF-8 source in the prefilter window");
        assert!(
            matched.contains(&0),
            "exact eval is a substring of the file"
        );
        assert!(
            !matched.contains(&1),
            "absent PE exact must not be a candidate"
        );
    }

    #[test]
    fn raw_source_prefilter_rejects_tiny_huge_and_non_utf8() {
        let index = StringMatchIndex::build(&[make_exact_trait("eval", "eval")]);
        assert!(index.find_matches_in_raw_source(&[b'x'; 50]).is_none());
        assert!(
            index
                .find_matches_in_raw_source(&vec![
                    b'x';
                    StringMatchIndex::MAX_SOURCE_TEXT_PREFILTER_BYTES
                        + 1
                ])
                .is_none()
        );
        let mut bad = vec![b'x'; StringMatchIndex::MIN_SOURCE_TEXT_PREFILTER_BYTES];
        bad[10] = 0xff;
        assert!(index.find_matches_in_raw_source(&bad).is_none());
        assert!(
            index
                .find_matches_in_raw_source(&vec![
                    b'x';
                    StringMatchIndex::MIN_SOURCE_TEXT_PREFILTER_BYTES
                ])
                .is_some()
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod gate_repro_tests {
    use super::*;
    use crate::composite_rules::condition::TextQuery;
    use crate::composite_rules::{Arch, Platform};

    #[test]
    fn text_regex_atom_gates_correctly_for_js() {
        let trait_def = TraitDefinition {
            id: "node-readdir-sync-call".to_string(),
            desc: "x".to_string(),
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![RuleFileType::JavaScript],
            r#if: Condition::Text(TextQuery {
                regex: Some(r"\bfs[\w$]{0,3}\.readdirSync\s*\(".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let index = RawContentRegexIndex::build(&[trait_def]);
        assert!(index.is_indexed_trait(0), "trait should be atom-indexed");
        let hits = index.find_matches(b"const e = fs.readdirSync(dir);", &RuleFileType::JavaScript);
        assert!(
            hits.contains(&0),
            "atom present in content must produce a match"
        );
        let miss = index.find_matches(b"nothing relevant here", &RuleFileType::JavaScript);
        assert!(!miss.contains(&0));
    }

    /// Source-file CSS gate lives on `RawContentRegexIndex`, not the PE
    /// extracted-string index (that path caused the Zencoder FN).
    #[test]
    fn css_font_family_raw_index_gates() {
        let trait_def = TraitDefinition {
            id: "css-font-family".to_string(),
            desc: "x".to_string(),
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![RuleFileType::All],
            r#if: Condition::Text(TextQuery {
                regex: Some(r"(?i)(^|})[^@{}]{0,80}\{[^}]{0,160}font-family\s*:".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let index = RawContentRegexIndex::build(&[trait_def]);
        assert!(index.is_indexed_trait(0));
        assert!(
            !index
                .find_matches(b"no css here", &RuleFileType::JavaScript)
                .contains(&0)
        );
        assert!(
            index
                .find_matches(b"h1 { font-family: serif }", &RuleFileType::JavaScript)
                .contains(&0)
        );
        assert!(
            index
                .find_matches(b"h1 { FONT-FAMILY: serif }", &RuleFileType::JavaScript)
                .contains(&0)
        );
    }

    #[test]
    fn css_font_family_records_atom_offset_on_source() {
        let trait_def = TraitDefinition {
            id: "css-font-family".to_string(),
            desc: "x".to_string(),
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![RuleFileType::All],
            r#if: Condition::Text(TextQuery {
                regex: Some(r"(?i)(^|})[^@{}]{0,80}\{[^}]{0,160}font-family\s*:".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let index = RawContentRegexIndex::build(&[trait_def]);
        let mut content = vec![b'x'; 16 * 1024];
        let atom_at = content.len();
        // `(^|})` cannot see `{` across 16 KiB of padding; a preceding `}`
        // is a real match, not an atom-only candidate.
        content.extend_from_slice(b"}h1 { font-family: serif }");
        let hits = index.find_matches_detailed(&content, &RuleFileType::JavaScript, true);
        assert!(hits.traits.contains(&0));
        #[allow(clippy::expect_used)]
        let offs = hits
            .atom_offsets
            .get(&0)
            .expect("source gate records offset");
        assert_eq!(offs.len(), 1);
        let start = offs[0] as usize;
        assert_eq!(&content[start..start + 11], b"font-family");
        assert_eq!(start, atom_at + 6);
        let miss = index.find_matches_detailed(b"no css here", &RuleFileType::JavaScript, true);
        assert!(!miss.traits.contains(&0));
        assert!(!miss.atom_offsets.contains_key(&0));
    }

    fn css_font_family_index() -> RawContentRegexIndex {
        RawContentRegexIndex::build(&[TraitDefinition {
            id: "css-font-family".to_string(),
            desc: "x".to_string(),
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![RuleFileType::All],
            r#if: Condition::Text(TextQuery {
                regex: Some(r"(?i)(^|})[^@{}]{0,80}\{[^}]{0,160}font-family\s*:".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }])
    }

    /// 400 B sits above the 256 B window floor: offsets must be recorded
    /// so `eval_raw` can window.
    #[test]
    fn records_atom_offsets_above_window_floor() {
        let index = css_font_family_index();
        let mut content = vec![b'x'; 2 * 1024];
        let atom_at = content.len();
        content.extend_from_slice(b"}h1 { font-family: serif }");
        let hits = index.find_matches_detailed(&content, &RuleFileType::JavaScript, true);
        assert!(hits.traits.contains(&0));
        #[allow(clippy::expect_used)]
        let offs = hits
            .atom_offsets
            .get(&0)
            .expect("400 B+ source must record offsets");
        let start = offs[0] as usize;
        assert_eq!(&content[start..start + 11], b"font-family");
        assert_eq!(start, atom_at + 6);
    }

    /// `(?i)font-family` must still see mixed-case `FONT-FAMILY` on a small
    /// source member (CI gate, whether via lowercase-memmem or CI AC).
    #[test]
    fn small_file_ci_literal_gate_finds_mixed_case() {
        let index = css_font_family_index();
        let mut content = vec![b'x'; 2 * 1024];
        let atom_at = content.len();
        content.extend_from_slice(b"}h1 { FONT-FAMILY: serif }");
        let hits = index.find_matches_detailed(&content, &RuleFileType::JavaScript, true);
        assert!(hits.traits.contains(&0), "CI atom must match FONT-FAMILY");
        #[allow(clippy::expect_used)]
        let offs = hits
            .atom_offsets
            .get(&0)
            .expect("2 KiB source must record offsets");
        let start = offs[0] as usize;
        assert_eq!(&content[start..start + 11], b"FONT-FAMILY");
        assert_eq!(start, atom_at + 6);
    }

    /// Sub-floor stubs still gate on presence, but skip offset recording
    /// (S2n: offsets without windowing were a tax).
    #[test]
    fn does_not_record_atom_offsets_below_window_floor() {
        let index = css_font_family_index();
        let mut content = vec![b'x'; 200];
        content.extend_from_slice(b"}h1 { font-family: serif }");
        assert!(content.len() < super::MIN_HAYSTACK_TO_WINDOW);
        let hits = index.find_matches_detailed(&content, &RuleFileType::JavaScript, true);
        assert!(hits.traits.contains(&0), "presence still gates");
        assert!(
            hits.atom_offsets.is_empty(),
            "sub-floor stubs must not record offsets"
        );
    }
}
