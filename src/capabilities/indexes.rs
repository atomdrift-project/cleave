//! Performance optimization indices for fast trait matching.
//!
//! This module provides specialized indices for efficient trait lookup and matching:
//! - `TraitIndex`: Fast trait lookup by file type
//! - `StringMatchIndex`: Batched string matching using Aho-Corasick automaton
//! - `RawContentRegexIndex`: Batched regex matching for binary content

use crate::composite_rules::condition::{TraitRegex, cached_regex};
use crate::composite_rules::evaluators::{MIN_HAYSTACK_TO_WINDOW, match_window, truncate_evidence};
use crate::composite_rules::{
    Condition, FileType as RuleFileType, Platform, TraitDefinition, platforms_intersect,
};
use crate::composite_rules::{RawQuery, SymbolQuery, TextQuery};
use crate::types::binary::normalize_symbol;
use crate::types::{Evidence, MAX_EVIDENCE_PER_TRAIT, StringInfo, deduplicate_evidence};
use aho_corasick::AhoCorasick;

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::{Arc, OnceLock, RwLock};

mod raw_index;
#[allow(clippy::wildcard_imports)]
pub(crate) use raw_index::*;

mod string_index;
#[allow(clippy::wildcard_imports)]
pub(crate) use string_index::*;

mod symbol_index;
#[allow(clippy::wildcard_imports)]
pub(crate) use symbol_index::*;

/// Build an index prefilter over `patterns`, or `None` when there are none.
///
/// A trait an index gates is evaluated only when the prefilter hits, so an
/// automaton that fails to build silently disables every trait behind it; a
/// failure is logged as an error instead of being dropped. aho-corasick picks
/// the automaton kind (a contiguous DFA at these pattern counts).
fn build_index_automaton<P: AsRef<[u8]>>(
    patterns: &[P],
    ascii_case_insensitive: bool,
) -> Option<AhoCorasick> {
    if patterns.is_empty() {
        return None;
    }
    match AhoCorasick::builder()
        .ascii_case_insensitive(ascii_case_insensitive)
        .build(patterns)
    {
        Ok(automaton) => Some(automaton),
        Err(err) => {
            tracing::error!(
                patterns = patterns.len(),
                error = %err,
                "index automaton failed to build; the traits it gates will not fire"
            );
            None
        }
    }
}

/// The other `for:` buckets a node of `file_type` draws traits from -- its
/// generic container (a JAR reads the `zip` bucket), never the whole archive
/// family. Must agree with the gate in `RuleFileType::rule_applies_to`.
fn archive_family_types(file_type: &RuleFileType) -> &'static [RuleFileType] {
    file_type.admitted_rule_types()
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
    /// file-type buckets, so `applicable` never selects them for standalone
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
    pub(crate) fn applicable(&self, file_type: &RuleFileType) -> TraitBitSet {
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
}

/// A `regex::Regex`-equivalent engine whose search scratch comes from
/// cleave's per-thread pool ([`crate::composite_rules::regex_scratch`])
/// instead of the regex crate's own per-regex pool. Same meta engine, same
/// default configuration as `regex::Regex::new`, so matches are identical;
/// only where the scratch lives differs. That matters here because the
/// no-literal symbol fallbacks run pattern-major over every symbol of every
/// member on every worker at once, and the crate's pool has one owner
/// thread — every other worker takes its mutex on each `is_match`. Measured
/// on a scan server: 3% of all CPU in that pool's `get`, 87% of
/// it from this loop.
#[derive(Clone, Debug)]
pub(crate) struct ScratchRegex {
    meta: regex_automata::meta::Regex,
    id: u64,
}

impl ScratchRegex {
    fn new(pattern: &str) -> Result<Self, Box<regex_automata::meta::BuildError>> {
        Ok(Self {
            meta: regex_automata::meta::Regex::new(pattern).map_err(Box::new)?,
            id: crate::composite_rules::regex_scratch::next_regex_id(),
        })
    }

    /// Lease one scratch cache for a batch of `regex::Regex::is_match`-style
    /// earliest-match searches on the same engine. The fallback
    /// sweep runs one pattern over every symbol of a member; checking the
    /// cache out and back in per symbol was ~31 s of a benign corpus run
    /// (`regex_scratch::finish` + `global_take`), more than many searches.
    pub(crate) fn with_matcher<R>(&self, f: impl FnOnce(&mut dyn FnMut(&str) -> bool) -> R) -> R {
        crate::composite_rules::regex_scratch::with_batch_cache(self.id, &self.meta, |cache| {
            let mut is_match = |haystack: &str| {
                self.meta
                    .search_half_with(cache, &regex_automata::Input::new(haystack).earliest(true))
                    .is_some()
            };
            f(&mut is_match)
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod gate_repro_tests;
