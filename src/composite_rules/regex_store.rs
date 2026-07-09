//! Byte-budgeted LRU stores for compiled trait regexes.
//!
//! The two process-global regex caches were count-capped (16,384 entries
//! each), but compiled engines range from ~2 KB (a literal-ish pattern) to
//! multiple MB (Unicode classes under counted repetitions), so the count cap
//! admitted a multi-GB worst case. These stores bound *bytes*, measured per
//! entry via `meta::Regex::memory_usage()` at insert.
//!
//! Eviction is always safe: consumers hold the compiled regex behind an
//! `Arc`, so an entry evicted mid-evaluation stays alive until its user
//! drops it — eviction only means the next `resolve` of that pattern pays a
//! recompile. Each pattern is resolved once per (condition, file) evaluation,
//! so a budget above the hot working set costs nothing, and one below it
//! degrades to bounded recompile churn rather than wrong results.

use std::borrow::Borrow;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::OnceLock;

/// A byte-budgeted LRU of `Arc`-shared compiled regexes. The count cap is a
/// secondary bound; the byte budget is the real limit.
pub(crate) struct BudgetedStore<K: Hash + Eq, V> {
    map: lru::LruCache<K, (Arc<V>, usize), rustc_hash::FxBuildHasher>,
    bytes: usize,
    budget: usize,
}

impl<K: Hash + Eq, V> BudgetedStore<K, V> {
    pub(crate) fn new(count_cap: NonZeroUsize, budget: usize) -> Self {
        Self {
            map: lru::LruCache::with_hasher(count_cap, rustc_hash::FxBuildHasher),
            bytes: 0,
            budget,
        }
    }

    /// Look up without bumping recency — lookups vastly outnumber inserts and
    /// a recency update needs the write lock (measured at ~25% CPU in lock
    /// wait when the caches did it). Eviction order is therefore
    /// insertion-ordered, which matches the per-file working-set pattern.
    pub(crate) fn peek<Q>(&self, key: &Q) -> Option<&Arc<V>>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.map.peek(key).map(|(v, _)| v)
    }

    /// Insert under the byte budget, evicting oldest entries past it.
    pub(crate) fn put(&mut self, key: K, value: Arc<V>, size: usize) {
        if let Some((_, evicted)) = self.map.push(key, (value, size)) {
            // push() returns the displaced LRU entry (or the replaced value).
            self.bytes = self.bytes.saturating_sub(evicted.1);
        }
        self.bytes += size;
        while self.bytes > self.budget && self.map.len() > 1 {
            match self.map.pop_lru() {
                Some((_, (_, evicted))) => self.bytes = self.bytes.saturating_sub(evicted),
                None => break,
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    /// Total bytes of compiled engines currently held.
    pub(crate) fn bytes(&self) -> usize {
        self.bytes
    }

    pub(crate) fn cap(&self) -> NonZeroUsize {
        self.map.cap()
    }

    pub(crate) fn clear(&mut self) {
        self.map.clear();
        self.bytes = 0;
    }
}

impl<K: Hash + Eq, V> std::fmt::Debug for BudgetedStore<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BudgetedStore")
            .field("entries", &self.map.len())
            .field("bytes", &self.bytes)
            .field("budget", &self.budget)
            .finish()
    }
}

fn env_mb(var: &str, default_mb: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default_mb)
        * 1024
        * 1024
}

/// Budget for the extracted-string (unicode `TraitRegex`) store.
/// `CLEAVE_REGEX_STR_MB` overrides.
pub(crate) fn str_budget_bytes() -> usize {
    static BYTES: OnceLock<usize> = OnceLock::new();
    *BYTES.get_or_init(|| env_mb("CLEAVE_REGEX_STR_MB", 512))
}

/// Budget for the raw-content (`LeanRegex` byte engine) store.
/// `CLEAVE_REGEX_RAW_MB` overrides.
pub(crate) fn raw_budget_bytes() -> usize {
    static BYTES: OnceLock<usize> = OnceLock::new();
    *BYTES.get_or_init(|| env_mb("CLEAVE_REGEX_RAW_MB", 256))
}

/// Budget for the shared lazy Unicode engine store (the Unicode twins of
/// ASCII-compatible patterns, built only when a non-ASCII haystack arrives —
/// JS-heavy corpora materialize most of them). `CLEAVE_REGEX_UNI_MB`
/// overrides.
pub(crate) fn unicode_budget_bytes() -> usize {
    static BYTES: OnceLock<usize> = OnceLock::new();
    *BYTES.get_or_init(|| env_mb("CLEAVE_REGEX_UNI_MB", 384))
}
