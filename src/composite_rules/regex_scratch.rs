//! Byte-budgeted regex scratch caches: a lock-free per-thread hot slot over a
//! global, sharded parking pool. Both tiers share one process-wide byte budget.
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

/// Global pool budget in bytes: 32 MiB per hardware thread, clamped to
/// 512 MiB..=4 GiB on 64-bit hosts (64 MiB on a 32-bit address space, where
/// scratch must not crowd the scanner's working set). An explicit
/// `CLEAVE_REGEX_SCRATCH_MB` (per-thread MiB, times available parallelism) is
/// honored literally.
///
/// The budget follows parallel demand rather than physical RAM. On the
/// 128-core FreeBSD gauntlet hard-tail fixture, 16 nested owners with a 4 GiB
/// ceiling completed in 294.09 s at 16,400,232 KiB max RSS. A 2 GiB ceiling
/// took 326.32 s (+11.0%) and *increased* max RSS to 17,257,512 KiB as cache
/// eviction/relearning inflated the rest of the heap. Retained scratch peaked
/// at 1,862 MiB with the 4 GiB ceiling and 1,937 MiB with the 2 GiB ceiling;
/// concurrent checkout growth needs the headroom even though the settled
/// retained total stays below 2 GiB. The 4 GiB clamp prevents wider hosts from
/// turning that throughput allowance into unbounded retention.
fn global_budget_bytes() -> usize {
    static BYTES: OnceLock<usize> = OnceLock::new();
    *BYTES.get_or_init(|| {
        const MIB: usize = 1024 * 1024;
        const FOUR_GIB: usize = 4usize.saturating_mul(1024 * MIB);
        let threads = std::thread::available_parallelism().map_or(8, std::num::NonZero::get);
        let default = if usize::BITS >= 64 {
            threads.saturating_mul(32 * MIB).clamp(512 * MIB, FOUR_GIB)
        } else {
            64 * MIB
        };
        match std::env::var("CLEAVE_REGEX_SCRATCH_MB")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
        {
            Some(mb) => mb.saturating_mul(MIB).saturating_mul(threads),
            None => default,
        }
    })
}

/// Allocate a process-unique identity for one compiled regex, used as the
/// scratch-pool key.
pub(crate) fn next_regex_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// A cached regex scratch allocation. `size` is refreshed whenever the cache
/// returns from a search, before either the hot slot or global pool retains it.
/// This is deliberately exact: lazy DFAs can grow substantially while staying
/// on one thread, which made the old unmeasured hot tier an unbounded
/// `rayon_threads × cache_size` retention path.
/// Always handled as `Box<Entry>`: `meta::Cache` is a large inline struct,
/// and the hot-slot/pool choreography moves an entry several times per
/// checkout — by-value moves measured as the process's hottest memmove
/// (~8% of total CPU on the 34-archive mix). Boxing makes every move
/// pointer-sized.
struct Entry {
    cache: meta::Cache,
    size: usize,
}

/// Releases a checked-out entry's retained-byte reservation if its search
/// unwinds. Archive member analysis catches panics at its boundary, so without
/// this guard one bad evaluator could leave a phantom reservation behind for
/// the lifetime of the worker.
struct CheckoutReservation<'a> {
    bytes: usize,
    counter: &'a AtomicUsize,
}

impl CheckoutReservation<'_> {
    fn disarm(&mut self) {
        self.bytes = 0;
    }
}

impl Drop for CheckoutReservation<'_> {
    fn drop(&mut self) {
        release_counter(self.counter, self.bytes);
    }
}

/// Shard count for the global pool: enough that a wide rayon pool rarely
/// collides on one lock.
const GLOBAL_SHARDS: usize = 64;

/// Parked caches one regex may hold. Live cache count per regex tracks its
/// peak concurrent use; beyond this cap a returning cache is dropped rather
/// than parked (creation covers the rare wider burst). 16 was tried on the
/// C:\data\sample mix (suspecting parked-cache misses drove lazy-DFA
/// relearn) and measured wall-neutral with a slight go-solo cost; 8 stays.
const PER_REGEX_CAP: usize = 8;

/// Bytes retained in both cache tiers, including caches temporarily checked
/// out for a search. A checked-out cache keeps its existing reservation; on
/// return only growth or shrinkage adjusts this counter. This avoids two
/// globally-contended atomic updates on every hot-cache search while keeping
/// the retained-memory bound exact after each search.
static CACHED_BYTES: AtomicUsize = AtomicUsize::new(0);

fn reserve_cached(bytes: usize) -> bool {
    let budget = global_budget_bytes();
    let mut used = CACHED_BYTES.load(Ordering::Acquire);
    loop {
        let Some(next) = used.checked_add(bytes) else {
            return false;
        };
        if next > budget {
            return false;
        }
        match CACHED_BYTES.compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => used = actual,
        }
    }
}

fn release_cached(bytes: usize) {
    release_counter(&CACHED_BYTES, bytes);
}

fn release_counter(counter: &AtomicUsize, bytes: usize) {
    if bytes == 0 {
        return;
    }
    let previous = counter.fetch_sub(bytes, Ordering::AcqRel);
    debug_assert!(previous >= bytes, "regex scratch byte accounting underflow");
}

type Shard = Mutex<FxHashMap<u64, Vec<Box<Entry>>>>;

fn shards() -> &'static [Shard; GLOBAL_SHARDS] {
    static SHARDS: OnceLock<[Shard; GLOBAL_SHARDS]> = OnceLock::new();
    SHARDS.get_or_init(|| std::array::from_fn(|_| Mutex::new(FxHashMap::default())))
}

#[allow(clippy::cast_possible_truncation)]
fn shard_for(id: u64) -> &'static Shard {
    &shards()[id as usize % GLOBAL_SHARDS]
}

/// Steal a parked cache for `id`, if any thread left one.
fn global_take(id: u64) -> Option<Box<Entry>> {
    // A checked-out entry keeps its byte reservation, so the common
    // take/search/return path does not bounce the process-wide counter's cache
    // line between every Rayon worker.
    let mut shard = shard_for(id).lock();
    let stack = shard.get_mut(&id)?;
    let entry = stack.pop();
    if stack.is_empty() {
        // Do not leave an empty stack behind: ids are minted per compiled
        // engine, so over a long run the key set only ever grows.
        shard.remove(&id);
    }
    entry
}

/// Drop every cache parked under `id` and release its bytes. Called when the
/// engine that owns `id` is dropped: without this, a regex evicted from its
/// budgeted store and later recompiled (under a fresh id) leaves its old parked
/// caches unreachable — nobody holds the dead id — yet still counted against
/// the budget. Over a long run those orphans fill the pool, live regexes then
/// fail `reserve_cached` and churn on cache creation while retained bytes sit
/// pinned at the ceiling.
pub(crate) fn forget(id: u64) {
    let freed = {
        let mut shard = shard_for(id).lock();
        shard
            .remove(&id)
            .map_or(0, |stack| stack.iter().map(|e| e.size).sum::<usize>())
    };
    release_cached(freed);
}

/// Park an already-reserved cache for other threads. The byte budget was
/// settled by [`finish`] (or retained across checkout); only the per-regex cap
/// can reject it here.
fn global_park(id: u64, entry: Box<Entry>) {
    let size = entry.size;
    let mut shard = shard_for(id).lock();
    let stack = shard.entry(id).or_default();
    let parked = stack.len() < PER_REGEX_CAP;
    if parked {
        stack.push(entry);
    }
    drop(shard);
    if !parked {
        release_cached(size);
    }
}

/// Drop the globally parked tier. Thread-local hot slots cannot be reached
/// from an arbitrary pressure-monitor thread, but they are included in the
/// shared budget and are evicted naturally on their next regex switch.
pub(crate) fn clear_parked() {
    let mut freed = 0usize;
    for shard in shards() {
        let mut shard = shard.lock();
        for entries in shard.values() {
            freed = freed.saturating_add(entries.iter().map(|entry| entry.size).sum::<usize>());
        }
        shard.clear();
    }
    release_cached(freed);
}

/// Live retained scratch bytes and the configured process-wide budget.
/// Reading this is one atomic load and is intended for worker heartbeats.
pub(crate) fn usage() -> (usize, usize) {
    (CACHED_BYTES.load(Ordering::Acquire), global_budget_bytes())
}

/// This thread's most recent (regex id, cache): repeat searches with one
/// regex — the overwhelmingly common pattern in trait evaluation — never
/// touch a lock.
struct HotSlot {
    id: u64,
    entry: Option<Box<Entry>>,
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
        let mut reservation = CheckoutReservation {
            bytes: entry.size,
            counter: &CACHED_BYTES,
        };
        let result = f(&mut entry.cache);
        reservation.disarm();
        finish(id, entry, true);
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
    let was_reserved = stolen.is_some();
    let mut entry = stolen.unwrap_or_else(|| {
        Box::new(Entry {
            cache: re.create_cache(),
            size: 0,
        })
    });
    let mut reservation = CheckoutReservation {
        bytes: if was_reserved { entry.size } else { 0 },
        counter: &CACHED_BYTES,
    };
    let result = f(&mut entry.cache);
    reservation.disarm();
    finish(id, entry, was_reserved);
    result
}

/// Return a finished cache: back into the hot slot when it is still ours and
/// free, otherwise into the global pool (nested/interleaved use of the same
/// regex on one thread built a transient second cache; the newer one wins
/// the slot).
fn finish(id: u64, mut entry: Box<Entry>, was_reserved: bool) {
    let old_size = entry.size;
    let new_size = entry.cache.memory_usage();
    let retained = if was_reserved && new_size > old_size {
        reserve_cached(new_size - old_size)
    } else if was_reserved {
        if new_size < old_size {
            release_cached(old_size - new_size);
        }
        true
    } else {
        reserve_cached(new_size)
    };
    if !retained {
        // A previously-reserved cache still owns its old-size reservation when
        // charging growth fails. Release that reservation before dropping it.
        if was_reserved {
            release_cached(old_size);
        }
        return;
    }
    entry.size = new_size;
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn engine(pattern: &str) -> meta::Regex {
        meta::Regex::new(pattern).unwrap()
    }

    #[test]
    fn hot_slot_reuses_and_switch_parks_globally() {
        let _lock = test_lock();
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
        let _lock = test_lock();
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

    #[test]
    fn panicking_hot_search_drops_the_checkout_and_its_reservation() {
        let _lock = test_lock();
        clear_parked();
        HOT.with(|h| {
            if let Some(entry) = h.borrow_mut().entry.take() {
                release_cached(entry.size);
            }
        });
        let re = engine("panic-[a-z]{8,64}");
        let id = next_regex_id();
        let _ = with_cache(id, &re, |cache| {
            re.search_half_with(cache, &regex_automata::Input::new("panic-abcdefgh"))
        });
        let reserved = HOT.with(|h| h.borrow().entry.as_ref().unwrap().size);
        assert!(reserved > 0);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            with_cache(id, &re, |_cache| panic!("synthetic evaluator panic"));
        }));
        assert!(panic.is_err());
        assert!(HOT.with(|h| h.borrow().entry.is_none()));

        // Verify the reservation guard's accounting against a private counter,
        // not the process-global total that unrelated regex tests legitimately
        // mutate in parallel.
        let counter = AtomicUsize::new(reserved);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _reservation = CheckoutReservation {
                bytes: reserved,
                counter: &counter,
            };
            panic!("synthetic checkout panic");
        }));
        assert!(panic.is_err());
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }

    #[test]
    fn parked_cache_preserves_the_hot_cache_reservation() {
        let _lock = test_lock();
        clear_parked();
        HOT.with(|h| {
            if let Some(entry) = h.borrow_mut().entry.take() {
                release_cached(entry.size);
            }
        });
        // Force the lazy hybrid DFA path; simple literal-heavy patterns can
        // complete through a zero-heap strategy and legitimately report a
        // zero-byte cache, which would make this accounting test vacuous.
        let re = meta::Regex::builder()
            .configure(
                meta::Config::new()
                    .dfa(false)
                    .onepass(false)
                    .backtrack(false),
            )
            .build(r"(?:[A-Za-z0-9_]{1,32}[./:-]){4,16}(?:powershell|cmd|https?)")
            .unwrap();
        let id = next_regex_id();
        assert!(with_cache(id, &re, |cache| re
            .search_half_with(
                cache,
                &regex_automata::Input::new("abc/def/ghi/jkl/powershell"),
            )
            .is_some()));
        let hot_bytes = HOT.with(|h| h.borrow().entry.as_ref().unwrap().size);
        assert!(hot_bytes > 0);
        HOT.with(|h| {
            let mut h = h.borrow_mut();
            let entry = h.entry.take().unwrap();
            global_park(h.id, entry);
        });
        let parked = global_take(id).expect("demoted hot cache should be parked");
        assert_eq!(parked.size, hot_bytes);
        // Return the still-reserved entry before clearing it so this test leaves
        // the global accounting balanced.
        global_park(id, parked);
        clear_parked();
    }
}
