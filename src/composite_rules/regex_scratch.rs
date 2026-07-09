//! Per-thread, byte-budgeted pool of regex scratch caches.
//!
//! The `regex` crate keeps one lazily-created `Cache` per regex *per thread
//! that ever searched with it*, inside a pool owned by the `Regex` — so a
//! process-global LRU of thousands of compiled trait regexes retains
//! `threads × regexes` caches forever. A cache is worst-case O(NFA states)
//! (the PikeVM's sparse sets plus the lazy DFA's eager minimum), which
//! measured in the gigabytes on binary-heavy scans.
//!
//! This pool inverts the ownership: the compiled `meta::Regex` carries no
//! scratch at all (only the explicit-cache `search_with` APIs are used), and
//! each thread holds a small LRU of caches keyed by regex identity, bounded
//! by *bytes*. Hot patterns keep their warm lazy-DFA cache; cold ones are
//! dropped and re-created on demand (cache creation is cheap relative to a
//! search that needs it). Nested use of the same regex on one thread — e.g. a
//! `not:` exception evaluated inside a match callback — simply builds a
//! second transient cache for the inner call and keeps the newer one.

use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use regex_automata::meta;

/// Secondary bound on entries per thread; the byte budget is the real limit.
const SCRATCH_COUNT_CAP: NonZeroUsize = {
    #[allow(clippy::expect_used)]
    NonZeroUsize::new(1024).expect("cap is non-zero")
};

/// Per-thread scratch budget in bytes. `CLEAVE_REGEX_SCRATCH_MB` overrides
/// (default 24 MiB — comfortably above the per-file working set measured on
/// trait-heavy scans, so steady-state eviction is rare).
fn budget_bytes() -> usize {
    static BYTES: OnceLock<usize> = OnceLock::new();
    *BYTES.get_or_init(|| {
        std::env::var("CLEAVE_REGEX_SCRATCH_MB")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map_or(24 * 1024 * 1024, |mb| mb * 1024 * 1024)
    })
}

/// Allocate a process-unique identity for one compiled regex, used as the
/// scratch-pool key.
pub(crate) fn next_regex_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// A parked cache with staleness-tolerant size accounting: `size` is
/// re-measured only every [`REMEASURE_EVERY`] parks (a cache's usage only
/// moves when the lazy DFA learns new transitions, which tapers off fast on
/// a warm cache), so the common park is a hash insert with no traversal.
struct Entry {
    cache: meta::Cache,
    size: usize,
    parks: u32,
}

/// How many parks between `memory_usage()` re-measurements.
const REMEASURE_EVERY: u32 = 32;

struct Pool {
    /// Identity of the cache in the hot slot (or last held there);
    /// `u64::MAX` = never set.
    hot_id: u64,
    /// One-entry fast path: trait evaluation searches with the same regex
    /// many times in a row (one pattern across a file's strings), and the
    /// hot slot turns those into a compare + `Option::take` instead of LRU
    /// hashing plus `memory_usage()` accounting — which measured as a ~40%
    /// user-CPU regression when paid per search. The hot cache is exempt
    /// from the byte budget while it sits here (a single cache, bounded by
    /// the per-regex hybrid capacity).
    hot: Option<Entry>,
    caches: lru::LruCache<u64, Entry, rustc_hash::FxBuildHasher>,
    bytes: usize,
}

impl Pool {
    fn new() -> Self {
        Self {
            hot_id: u64::MAX,
            hot: None,
            caches: lru::LruCache::with_hasher(SCRATCH_COUNT_CAP, rustc_hash::FxBuildHasher),
            bytes: 0,
        }
    }

    fn take(&mut self, id: u64) -> Option<Entry> {
        let entry = self.caches.pop(&id)?;
        self.bytes = self.bytes.saturating_sub(entry.size);
        Some(entry)
    }

    /// Park a cache in the LRU under the byte budget.
    fn park(&mut self, id: u64, mut entry: Entry) {
        entry.parks = entry.parks.wrapping_add(1);
        if entry.parks.is_multiple_of(REMEASURE_EVERY) || entry.size == 0 {
            entry.size = entry.cache.memory_usage();
        }
        let size = entry.size;
        if let Some(evicted) = self.caches.push(id, entry) {
            // push() returns the displaced LRU entry (or the replaced value).
            self.bytes = self.bytes.saturating_sub(evicted.1.size);
        }
        self.bytes += size;
        while self.bytes > budget_bytes() && self.caches.len() > 1 {
            match self.caches.pop_lru() {
                Some((_, evicted)) => self.bytes = self.bytes.saturating_sub(evicted.size),
                None => break,
            }
        }
    }

    /// Return a finished cache: back into the hot slot when it is still ours
    /// and free, otherwise into the LRU (nested/interleaved use).
    fn finish(&mut self, id: u64, entry: Entry) {
        if self.hot_id == id && self.hot.is_none() {
            self.hot = Some(entry);
        } else {
            self.park(id, entry);
        }
    }
}

thread_local! {
    static POOL: RefCell<Pool> = RefCell::new(Pool::new());
}

/// Run `f` with a scratch cache for regex `id`, reusing this thread's parked
/// cache when present and parking it (subject to the byte budget) afterwards.
pub(crate) fn with_cache<R>(id: u64, re: &meta::Regex, f: impl FnOnce(&mut meta::Cache) -> R) -> R {
    // Fast path: repeat use of this thread's most recent regex.
    let hot = POOL.with(|p| {
        let mut p = p.borrow_mut();
        if p.hot_id == id { p.hot.take() } else { None }
    });
    if let Some(mut entry) = hot {
        let result = f(&mut entry.cache);
        POOL.with(|p| p.borrow_mut().finish(id, entry));
        return result;
    }
    // Slow path: demote the current hot cache to the LRU and promote this id.
    let mut entry = POOL
        .with(|p| {
            let mut p = p.borrow_mut();
            if let Some(prev) = p.hot.take() {
                let prev_id = p.hot_id;
                p.park(prev_id, prev);
            }
            p.hot_id = id;
            p.take(id)
        })
        .unwrap_or_else(|| Entry {
            cache: re.create_cache(),
            size: 0,
            parks: 0,
        });
    let result = f(&mut entry.cache);
    POOL.with(|p| p.borrow_mut().finish(id, entry));
    result
}
