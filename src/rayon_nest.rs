//! Adaptive nested Rayon: bound how many analyses may fan out at each level.
//!
//! Archive analysis fans members out at depth 0 (that is how a lone zip
//! finishes in ~66 s). Each member then nests again — Aho-Corasick chunks,
//! YARA buckets, trait eval, composite rules. Under a directory scan those
//! inner joins steal workers from sibling archives and inflate member wall
//! 5–17× (S3/S4/S2w on `C:\data\faster`). A bounded number of top-level
//! owners retain member fan-out while their siblings make serial progress on
//! independent blocking threads. Nested Rayon workers do not inherit
//! ownership, so one tree cannot multiply recursively. All public single-file
//! entry points enter the counter at their shared resource-aware boundary;
//! this is essential for long-lived workers whose independent callers do not
//! pass through the directory-scan wrappers.
//!
//! `CLEAVE_SERIAL_TRAITS=1` still forces the old always-serial inner path.

use std::cell::Cell;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static TOPLEVEL_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static NEXT_TOPLEVEL_ID: AtomicU64 = AtomicU64::new(1);
static INNER_PARALLEL_OWNERS: AtomicUsize = AtomicUsize::new(0);
static NESTED_MEMBER_OWNERS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static TOPLEVEL_ID: Cell<u64> = const { Cell::new(0) };
    static OWNS_INNER_PARALLELISM: Cell<bool> = const { Cell::new(false) };
    static NESTED_MEMBER_PARALLELISM: Cell<bool> = const { Cell::new(false) };
}

pub(crate) struct ToplevelInFlightGuard {
    previous_id: u64,
    previous_owned: bool,
}

impl Drop for ToplevelInFlightGuard {
    fn drop(&mut self) {
        let owned = OWNS_INNER_PARALLELISM.with(|value| value.replace(self.previous_owned));
        if owned {
            INNER_PARALLEL_OWNERS.fetch_sub(1, Ordering::Release);
        }
        TOPLEVEL_ID.with(|value| value.set(self.previous_id));
        TOPLEVEL_IN_FLIGHT.fetch_sub(1, Ordering::Release);
    }
}

pub(crate) fn enter_toplevel_analysis() -> ToplevelInFlightGuard {
    let id = NEXT_TOPLEVEL_ID.fetch_add(1, Ordering::Relaxed);
    let previous_id = TOPLEVEL_ID.with(|value| value.replace(id));
    let previous_owned = OWNS_INNER_PARALLELISM.with(|value| value.replace(false));
    TOPLEVEL_IN_FLIGHT.fetch_add(1, Ordering::AcqRel);
    ToplevelInFlightGuard {
        previous_id,
        previous_owned,
    }
}

fn serial_traits_forced() -> bool {
    static FLAG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FLAG.get_or_init(|| std::env::var_os("CLEAVE_SERIAL_TRAITS").is_some())
}

fn max_inner_parallel_owners() -> usize {
    static MAX: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *MAX.get_or_init(|| {
        std::env::var("CLEAVE_INNER_PARALLEL_OWNERS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| (rayon::current_num_threads() / 32).clamp(1, 16))
    })
}

fn max_nested_member_owners() -> usize {
    static MAX: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *MAX.get_or_init(|| {
        std::env::var("CLEAVE_NESTED_MEMBER_PARALLEL_OWNERS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| (rayon::current_num_threads() / 8).clamp(1, 16))
    })
}

fn nested_member_parallel_min_bytes() -> usize {
    static MIN: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *MIN.get_or_init(|| {
        std::env::var("CLEAVE_NESTED_MEMBER_PARALLEL_MIN_BYTES")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0)
    })
}

pub(crate) struct NestedMemberParallelGuard {
    previous: bool,
}

impl Drop for NestedMemberParallelGuard {
    fn drop(&mut self) {
        let owned = NESTED_MEMBER_PARALLELISM.with(|value| value.replace(self.previous));
        if owned && !self.previous {
            NESTED_MEMBER_OWNERS.fetch_sub(1, Ordering::Release);
        }
    }
}

fn try_claim_nested_member_owner() -> bool {
    if NESTED_MEMBER_PARALLELISM.with(Cell::get) {
        return true;
    }
    let limit = max_nested_member_owners();
    let mut current = NESTED_MEMBER_OWNERS.load(Ordering::Acquire);
    while current < limit {
        match NESTED_MEMBER_OWNERS.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                NESTED_MEMBER_PARALLELISM.with(|value| value.set(true));
                return true;
            }
            Err(observed) => current = observed,
        }
    }
    false
}

/// Give a bounded number of archive members access to nested Rayon work.
///
/// The member itself must already be running on a Rayon worker. Its children
/// do not inherit this thread-local flag, so this permits one extra level of
/// fan-out without recreating unbounded recursive trees.
pub(crate) fn try_enter_nested_member_parallelism(
    size_bytes: usize,
) -> Option<NestedMemberParallelGuard> {
    if rayon::current_thread_index().is_none()
        || size_bytes < nested_member_parallel_min_bytes()
        || serial_traits_forced()
    {
        return None;
    }
    let previous = NESTED_MEMBER_PARALLELISM.with(Cell::get);
    if previous {
        return Some(NestedMemberParallelGuard { previous });
    }
    if try_claim_nested_member_owner() {
        return Some(NestedMemberParallelGuard { previous });
    }
    None
}

/// Whether this top-level analysis owns one of the bounded inner-parallel slots.
///
/// With sibling files in flight, the first analysis to reach parallel work
/// claims an owner slot for the rest of its analysis. Other top-level files
/// keep making serial progress on their own blocking threads. Rayon children
/// deliberately do not inherit the thread-local ownership, preventing a
/// parallel member walk from recursively multiplying into another tree.
pub(crate) fn inner_work_parallel() -> bool {
    if serial_traits_forced() {
        return false;
    }
    if TOPLEVEL_IN_FLIGHT.load(Ordering::Acquire) <= 1 {
        return true;
    }
    if NESTED_MEMBER_PARALLELISM.with(Cell::get) {
        return true;
    }
    if TOPLEVEL_ID.with(Cell::get) == 0 {
        return false;
    }
    if OWNS_INNER_PARALLELISM.with(Cell::get) {
        return true;
    }

    let limit = max_inner_parallel_owners();
    let mut current = INNER_PARALLEL_OWNERS.load(Ordering::Acquire);
    while current < limit {
        match INNER_PARALLEL_OWNERS.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                OWNS_INNER_PARALLELISM.with(|value| value.set(true));
                return true;
            }
            Err(observed) => current = observed,
        }
    }
    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn inner_parallel_with_zero_or_one_toplevel() {
        let _lock = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(inner_work_parallel());
        let one = enter_toplevel_analysis();
        assert!(inner_work_parallel());
        drop(one);
        assert!(inner_work_parallel());
    }

    #[test]
    fn one_of_two_toplevels_owns_inner_parallelism() {
        let _lock = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let a = enter_toplevel_analysis();
        let b = enter_toplevel_analysis();
        assert!(inner_work_parallel());
        assert!(!std::thread::spawn(inner_work_parallel).join().unwrap());
        drop(b);
        assert!(inner_work_parallel());
        drop(a);
        assert!(inner_work_parallel());
    }
}
