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
        // Construct the guard only after winning: dropping a guard clears
        // the slot. `then_some` would clear another compiler's claim on failure.
        slot.compare_exchange(0, key_hash, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
            .then(|| ClaimGuard { slot })
    }

    /// Racer path: poll `peek` for the winner's value, bounded (~10 ms).
    /// `None` means the caller should compile itself. A slot collision with
    /// an unrelated key, or a completed/failed owner, must not pay the timeout.
    pub(crate) fn wait_for<T>(
        &self,
        key_hash: u64,
        mut peek: impl FnMut() -> Option<T>,
    ) -> Option<T> {
        let slot = &self.slots[(key_hash as usize) % SLOTS];
        for i in 0..40 {
            if let Some(v) = peek() {
                return Some(v);
            }
            if slot.load(Ordering::Acquire) != key_hash {
                // The owner can publish between the lookup and the slot read.
                return peek();
            }
            if i < 4 {
                std::thread::yield_now();
            } else {
                std::thread::sleep(std::time::Duration::from_micros(250));
            }
        }
        peek()
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn regex_compile_claim_failed_attempt_preserves_owner() {
        let claims = ClaimSet::new();
        let owner = claims.try_claim(7).expect("first claimant owns the slot");
        for _ in 0..10 {
            assert!(claims.try_claim(7).is_none());
            // A colliding key must not clear the first key's claim either.
            assert!(claims.try_claim(7 + SLOTS as u64).is_none());
        }
        drop(owner);
        assert!(claims.try_claim(7).is_some());
    }

    #[test]
    fn regex_compile_claim_collision_does_not_wait_for_unrelated_key() {
        let claims = ClaimSet::new();
        let _owner = claims.try_claim(7).expect("claim");
        let mut checks = 0;
        let value: Option<()> = claims.wait_for(7 + SLOTS as u64, || {
            checks += 1;
            None
        });
        assert!(value.is_none());
        assert_eq!(
            checks, 2,
            "unrelated collisions must bypass the polling loop"
        );
        assert!(
            claims.try_claim(7).is_none(),
            "the original owner remains claimed"
        );
    }

    #[test]
    fn regex_compile_claim_observes_completed_publication() {
        let claims = ClaimSet::new();
        let mut owner = Some(claims.try_claim(7).expect("claim"));
        let mut checks = 0;
        let value = claims.wait_for(7, || {
            checks += 1;
            if checks == 1 {
                drop(owner.take());
                None
            } else {
                Some(42)
            }
        });
        assert_eq!(value, Some(42));
        assert_eq!(checks, 2);
    }

    #[test]
    fn regex_compile_claim_release_is_panic_safe() {
        let claims = ClaimSet::new();
        let result = std::panic::catch_unwind(|| {
            let _owner = claims.try_claim(11).expect("claim");
            panic!("simulate failed compile");
        });
        assert!(result.is_err());
        assert!(claims.try_claim(11).is_some());
    }
}
