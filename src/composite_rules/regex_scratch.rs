//! Byte-budgeted regex scratch caches: a lock-free per-thread hot slot over a
//! global, sharded parking pool.
//!
//! The `regex` crate keeps one lazily-created `Cache` per regex *per thread
//! that ever searched with it*, inside a pool owned by the `Regex` — so a
//! process-global LRU of thousands of compiled trait regexes retains
//! `threads × regexes` caches forever. A cache is worst-case O(NFA states)
//! (the PikeVM's sparse sets plus the lazy DFA's eager minimum), which
//! measured in the gigabytes on binary-heavy scans.
//!
//! An earlier revision inverted that ownership into a per-thread byte-budgeted
//! LRU. That bounded memory, but kept creation per *(thread, regex)*: on a
//! 64-thread pool evaluating thousands of trait regexes, `create_cache` alone
//! measured 16% of a JS-heavy scan's CPU, and no per-thread budget helps —
//! each thread's working set is the whole trait corpus, while the
//! *simultaneous* demand for any one regex is a handful of threads.
//!
//! So the pool is global: each thread keeps only a one-entry hot slot (repeat
//! searches with the same regex stay lock-free), and on a regex switch the
//! demoted cache parks in a sharded global pool keyed by regex identity. A
//! thread that needs a regex steals a parked cache before creating one, so
//! live cache count tracks concurrent use, not thread count. Shard locks are
//! held for a hash probe plus a `Vec` push/pop; threads contend only when
//! they switch onto the same shard at the same instant. Nested use of the
//! same regex on one thread — e.g. a `not:` exception evaluated inside a
//! match callback — simply builds a second transient cache for the inner
//! call and keeps the newer one.

use std::cell::RefCell;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use parking_lot::Mutex;
use regex_automata::meta;
use rustc_hash::FxHashMap;

/// Global pool budget in bytes: a flat 512 MiB on 64-bit hosts (64 MiB on a
/// 32-bit address space, where scratch must not crowd the scanner's working
/// set). An explicit `CLEAVE_REGEX_SCRATCH_MB` (per-thread MiB, times
/// available parallelism) is honored literally.
///
/// This replaced a machine-scaled default (1/32 of physical RAM clamped to
/// [512 MiB, 4 GiB]) after measurement showed the pool should be sized by
/// the *workload*, not the host: on a 64 GB box the old default held 2 GiB
/// of scratch, and on the 57k-member MiniMax archive the sweep read
/// 2 GiB → 12,817 MiB peak / 505.9 s; 512 MiB → 11,575 / 468.0 (wall
/// *faster* — smaller pool, better locality); 128 MiB → 10,850 / 579.2
/// (+14% wall, the create_cache churn the pool exists to avoid). 512 MiB is
/// the knee, and it matches the earlier finding that 512 MiB recovers about
/// two-thirds of a JS-heavy scan's `create_cache` CPU — the remaining third
/// was not worth 1.2 GB of RSS on any measured sample.
fn global_budget_bytes() -> usize {
    static BYTES: OnceLock<usize> = OnceLock::new();
    *BYTES.get_or_init(|| {
        const DEFAULT: usize = if usize::BITS >= 64 {
            512 * 1024 * 1024
        } else {
            64 * 1024 * 1024
        };
        let threads = std::thread::available_parallelism().map_or(8, std::num::NonZero::get);
        match std::env::var("CLEAVE_REGEX_SCRATCH_MB")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
        {
            Some(mb) => mb.saturating_mul(1024 * 1024).saturating_mul(threads),
            None => DEFAULT,
        }
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
/// a warm cache), so the common park is a hash probe with no traversal.
struct Entry {
    cache: meta::Cache,
    size: usize,
    parks: u32,
}

/// How many parks between `memory_usage()` re-measurements.
const REMEASURE_EVERY: u32 = 32;

/// Shard count for the global pool: enough that a wide rayon pool rarely
/// collides on one lock.
const GLOBAL_SHARDS: usize = 64;

/// Parked caches one regex may hold. Live cache count per regex tracks its
/// peak concurrent use; beyond this cap a returning cache is dropped rather
/// than parked (creation covers the rare wider burst).
const PER_REGEX_CAP: usize = 8;

/// Bytes currently parked across all shards. Checked-out caches are
/// unaccounted, exactly as the previous design's hot slot was.
static GLOBAL_BYTES: AtomicUsize = AtomicUsize::new(0);

type Shard = Mutex<FxHashMap<u64, Vec<Entry>>>;

fn shards() -> &'static [Shard; GLOBAL_SHARDS] {
    static SHARDS: OnceLock<[Shard; GLOBAL_SHARDS]> = OnceLock::new();
    SHARDS.get_or_init(|| std::array::from_fn(|_| Mutex::new(FxHashMap::default())))
}

#[allow(clippy::cast_possible_truncation)]
fn shard_for(id: u64) -> &'static Shard {
    &shards()[id as usize % GLOBAL_SHARDS]
}

/// Steal a parked cache for `id`, if any thread left one.
fn global_take(id: u64) -> Option<Entry> {
    // The shard lock covers the stacks only; the byte counter is a separate
    // atomic, so it is updated after the guard drops to keep the critical
    // section a bare probe + pop.
    let entry = {
        let mut shard = shard_for(id).lock();
        shard.get_mut(&id)?.pop()?
    };
    GLOBAL_BYTES.fetch_sub(entry.size, Ordering::Relaxed);
    Some(entry)
}

/// Park a finished cache for other threads, subject to the global byte budget
/// and the per-regex cap; over either limit the cache is simply dropped.
fn global_park(id: u64, mut entry: Entry) {
    entry.parks = entry.parks.wrapping_add(1);
    if entry.parks.is_multiple_of(REMEASURE_EVERY) || entry.size == 0 {
        entry.size = entry.cache.memory_usage();
    }
    if GLOBAL_BYTES
        .load(Ordering::Relaxed)
        .saturating_add(entry.size)
        > global_budget_bytes()
    {
        return;
    }
    let size = entry.size;
    let mut shard = shard_for(id).lock();
    let stack = shard.entry(id).or_default();
    let parked = stack.len() < PER_REGEX_CAP;
    if parked {
        stack.push(entry);
    }
    // Release before touching the global counter: the shard guard protects the
    // stacks, and the counter is a separate atomic.
    drop(shard);
    if parked {
        GLOBAL_BYTES.fetch_add(size, Ordering::Relaxed);
    }
}

/// This thread's most recent (regex id, cache): repeat searches with one
/// regex — the overwhelmingly common pattern in trait evaluation — never
/// touch a lock.
struct HotSlot {
    id: u64,
    entry: Option<Entry>,
}

thread_local! {
    static HOT: RefCell<HotSlot> = const {
        RefCell::new(HotSlot {
            id: u64::MAX,
            entry: None,
        })
    };
}

/// Run `f` with a scratch cache for regex `id`: this thread's hot cache when
/// the id matches, else a cache stolen from the global pool, else a fresh one.
/// The demoted hot cache parks globally so another thread can steal it.
pub(crate) fn with_cache<R>(id: u64, re: &meta::Regex, f: impl FnOnce(&mut meta::Cache) -> R) -> R {
    // Fast path: repeat use of this thread's most recent regex.
    let hot = HOT.with(|h| {
        let mut h = h.borrow_mut();
        if h.id == id { h.entry.take() } else { None }
    });
    if let Some(mut entry) = hot {
        let result = f(&mut entry.cache);
        finish(id, entry);
        return result;
    }
    // Slow path: demote the current hot cache to the global pool, then steal
    // or create one for this id.
    let stolen = HOT.with(|h| {
        let mut h = h.borrow_mut();
        if let Some(prev) = h.entry.take() {
            let prev_id = h.id;
            global_park(prev_id, prev);
        }
        h.id = id;
        global_take(id)
    });
    let mut entry = stolen.unwrap_or_else(|| Entry {
        cache: re.create_cache(),
        size: 0,
        parks: 0,
    });
    let result = f(&mut entry.cache);
    finish(id, entry);
    result
}

/// Return a finished cache: back into the hot slot when it is still ours and
/// free, otherwise into the global pool (nested/interleaved use of the same
/// regex on one thread built a transient second cache; the newer one wins
/// the slot).
fn finish(id: u64, entry: Entry) {
    let parked = HOT.with(|h| {
        let mut h = h.borrow_mut();
        if h.id == id && h.entry.is_none() {
            h.entry = Some(entry);
            None
        } else {
            Some(entry)
        }
    });
    if let Some(entry) = parked {
        global_park(id, entry);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn engine(pattern: &str) -> meta::Regex {
        meta::Regex::new(pattern).unwrap()
    }

    #[test]
    fn hot_slot_reuses_and_switch_parks_globally() {
        let a = engine("foo[a-z]+");
        let b = engine("bar[0-9]+");
        let (ida, idb) = (next_regex_id(), next_regex_id());
        // Repeat use of one regex, then a switch, then back: every call must
        // see a working cache regardless of which layer supplied it.
        assert!(with_cache(ida, &a, |c| a
            .search_half_with(c, &regex_automata::Input::new("foobar"))
            .is_some()));
        assert!(with_cache(ida, &a, |c| a
            .search_half_with(c, &regex_automata::Input::new("foox"))
            .is_some()));
        assert!(with_cache(idb, &b, |c| b
            .search_half_with(c, &regex_automata::Input::new("bar12"))
            .is_some()));
        assert!(with_cache(ida, &a, |c| a
            .search_half_with(c, &regex_automata::Input::new("fooy"))
            .is_some()));
        // After the switches at least one demoted cache is parked for
        // stealing (this thread's hot slot holds `ida`; `idb` was demoted).
        assert!(global_take(idb).is_some());
    }

    #[test]
    fn nested_same_regex_use_builds_a_transient_cache() {
        let a = engine("qu+x");
        let id = next_regex_id();
        let hit = with_cache(id, &a, |outer| {
            let outer_hit = a
                .search_half_with(outer, &regex_automata::Input::new("quux"))
                .is_some();
            // Nested call with the hot slot's cache checked out.
            let inner_hit = with_cache(id, &a, |inner| {
                a.search_half_with(inner, &regex_automata::Input::new("qux"))
                    .is_some()
            });
            outer_hit && inner_hit
        });
        assert!(hit);
    }
}
