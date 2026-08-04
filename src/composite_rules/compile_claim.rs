//! Claim-based dedup for racing lazy regex compiles.
//!
//! The three shared regex stores (bytes engines, str `TraitRegex`, Unicode
//! twins) fill lazily on first use. During an archive scan's warmup every
//! rayon worker misses the same hot patterns near-simultaneously, and each
//! compiles its own copy — measured at ~50k duplicated compiles (~79% of all
//! bytes-store inserts) on a 1,580-member archive, worth hundreds of CPU-s
//! plus allocator contention.
//!
//! The fix keeps the deliberate race as the *fallback* (correctness must
//! never depend on another thread finishing): the first claimant of a key
//! compiles; racers poll the store briefly (bounded, ~10 ms) and only compile
//! themselves if the winner hasn't delivered by then. A typical compile is
//! 2-8 ms, so racers usually pick up the winner's engine after roughly the
//! same wall time their own compile would have cost — wall-neutral, CPU
//! saved.
//!
//! Claims are lock-free: a fixed open-addressed array of `AtomicU64` slots.
//! No mutex means no lock-ordering interactions with the stores, rayon, or
//! the allocator — a claim is one CAS, a release is one store. A hash
//! collision (either 64-bit key collision or slot contention between two
//! distinct keys) merely sends one thread down the racer path, where the
//! bounded poll expires and it compiles anyway — bounded waste, never
//! wrongness.

use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

/// Slot count per registry. Claims live only for one compile (~ms), so the
/// live population is bounded by the worker count; 512 slots keeps the
/// same-slot collision rate negligible at 16 workers.
const SLOTS: usize = 512;

pub(crate) struct ClaimSet {
    slots: [AtomicU64; SLOTS],
}

impl ClaimSet {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [const { AtomicU64::new(0) }; SLOTS],
        }
    }

    pub(crate) fn hash_key<K: Hash>(key: &K) -> u64 {
        let mut h = rustc_hash::FxHasher::default();
        key.hash(&mut h);
        // Reserve 0 as the empty-slot marker.
        h.finish() | 1
    }

    /// Try to become the compiler for `key_hash`. On success, drop the guard
    /// after inserting into the store (release is panic-safe via Drop).
    pub(crate) fn try_claim(&self, key_hash: u64) -> Option<ClaimGuard<'_>> {
        let slot = &self.slots[(key_hash as usize) % SLOTS];
        slot.compare_exchange(0, key_hash, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then_some(ClaimGuard { slot })
    }

    /// Racer path: poll `peek` for the winner's value, bounded (~10 ms).
    /// `None` means the caller should compile itself (winner slow, failed, or
    /// this was a collision with an unrelated key).
    pub(crate) fn wait_for<T>(&self, mut peek: impl FnMut() -> Option<T>) -> Option<T> {
        for i in 0..40 {
            if i < 4 {
                std::thread::yield_now();
            } else {
                std::thread::sleep(std::time::Duration::from_micros(250));
            }
            if let Some(v) = peek() {
                return Some(v);
            }
        }
        None
    }
}

/// Clears the claim slot on drop — including on panic, so a failed compile
/// can never wedge future claimants (racers only ever wait the bounded poll
/// anyway).
pub(crate) struct ClaimGuard<'a> {
    slot: &'a AtomicU64,
}

impl Drop for ClaimGuard<'_> {
    fn drop(&mut self) {
        self.slot.store(0, Ordering::Release);
    }
}
