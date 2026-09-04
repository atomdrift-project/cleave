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
/// Top-level paths a directory scan has not yet admitted (`usize::MAX` when
/// no ordered scan is running). Once fewer remain than there are pool
/// threads the lanes are about to idle, and the bounded-owner rule that
/// keeps sibling archives serial no longer buys anything: every in-flight
/// analysis may fan out. Without this the scan's tail is one whale walking
/// its members one by one on one thread while fifteen workers sleep —
/// overdrive-db's two ELF libraries (24 s + 9 s of rizin) back to back were
/// a 49 s critical path in a 51 s scan.
static TOPLEVEL_PENDING: AtomicUsize = AtomicUsize::new(usize::MAX);

pub(crate) fn set_toplevel_pending(n: usize) {
    TOPLEVEL_PENDING.store(n, Ordering::Release);
}

/// The directory scan is draining: too few top-level paths remain to keep
/// every pool thread busy at the top level.
pub(crate) fn toplevel_draining() -> bool {
    TOPLEVEL_PENDING.load(Ordering::Acquire) < rayon::current_num_threads()
}
static NEXT_TOPLEVEL_ID: AtomicU64 = AtomicU64::new(1);

/// Work a lane can do instead of idling in a single-flight wait: the next
/// top-level path of the ordered scan queue. Installed by `for_each_ordered`
/// for the duration of the scan (`None` outside it). Callers take the lock,
/// copy the hook and bump `WAIT_WORK_ACTIVE` *before* unlocking; the
/// uninstaller clears the slot under the lock and then waits for
/// `WAIT_WORK_ACTIVE` to drain, so the borrowed closure never outlives its
/// scope.
static WAIT_WORK: std::sync::Mutex<Option<&'static (dyn Fn() -> bool + Sync)>> =
    std::sync::Mutex::new(None);
static WAIT_WORK_ACTIVE: AtomicUsize = AtomicUsize::new(0);
static WAIT_WORK_RUNS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    /// Depth of scan paths this thread is analyzing *inside* a single-flight
    /// wait. A nested path never pulls further work (bounded stack, no wait
    /// chains through this thread).
    static WAIT_WORK_DEPTH: Cell<usize> = const { Cell::new(0) };
}

pub(crate) struct WaitWorkGuard(());

impl Drop for WaitWorkGuard {
    fn drop(&mut self) {
        *WAIT_WORK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        while WAIT_WORK_ACTIVE.load(Ordering::Acquire) != 0 {
            std::thread::yield_now();
        }
    }
}

/// Install `hook` as the wait-time work source until the guard drops.
///
/// `hook` returns `true` when it ran a job (the caller re-checks its wait
/// condition) and `false` when the queue is exhausted.
pub(crate) fn install_wait_work(hook: &(dyn Fn() -> bool + Sync)) -> WaitWorkGuard {
    // SAFETY: the guard clears the slot and drains every in-progress call
    // before it drops, and the caller keeps `hook` alive until then.
    let hook: &'static (dyn Fn() -> bool + Sync) = unsafe { std::mem::transmute(hook) };
    *WAIT_WORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
    WaitWorkGuard(())
}

/// Run one queued scan path on this thread, if any is installed and this
/// thread is not already inside such a job. Returns whether a job ran.
pub(crate) fn run_wait_work() -> bool {
    if WAIT_WORK_DEPTH.with(Cell::get) > 0 {
        return false;
    }
    let slot = WAIT_WORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(hook) = *slot else { return false };
    // Bump under the lock so the uninstaller's drain sees this call.
    WAIT_WORK_ACTIVE.fetch_add(1, Ordering::AcqRel);
    drop(slot);
    struct Active;
    impl Drop for Active {
        fn drop(&mut self) {
            WAIT_WORK_DEPTH.with(|d| d.set(d.get() - 1));
            WAIT_WORK_ACTIVE.fetch_sub(1, Ordering::AcqRel);
        }
    }
    WAIT_WORK_DEPTH.with(|d| d.set(d.get() + 1));
    let _active = Active;
    let ran = hook();
    if ran {
        WAIT_WORK_RUNS.fetch_add(1, Ordering::Relaxed);
    }
    ran
}

/// Whether this thread is analyzing a scan path pulled during a
/// single-flight wait.
pub(crate) fn in_wait_work() -> bool {
    WAIT_WORK_DEPTH.with(Cell::get) > 0
}

/// Archive members analyzed independently because their single-flight was
/// busy and this thread could not wait (scan statistics).
static INDEPENDENT_MEMBER_ANALYSES: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn note_independent_member_analysis() {
    INDEPENDENT_MEMBER_ANALYSES.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn independent_member_analyses() -> usize {
    INDEPENDENT_MEMBER_ANALYSES.load(Ordering::Relaxed)
}

/// Scan paths analyzed by lanes that would otherwise have idled in a
/// single-flight wait (scan statistics).
pub(crate) fn wait_work_runs() -> usize {
    WAIT_WORK_RUNS.load(Ordering::Relaxed)
}
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

/// Whether the pool has room for a caller's *own* fan-out of top-level
/// analyses.
///
/// This is the same headroom test `inner_work_parallel` opens with, exposed
/// for callers outside this crate that dispatch cleave analyses themselves.
/// The bounded-owner rule below assumes non-owner analyses make serial
/// progress **on their own blocking threads** — a caller that instead fans
/// them across the Rayon pool defeats it, because a throttled analysis then
/// occupies a pool worker rather than freeing one, and the `par_iter` that
/// dispatched it leaves its caller blocked-and-stealing. Such a caller should
/// fan out only while this returns true, and run its analyses inline
/// otherwise.
pub(crate) fn pool_has_headroom() -> bool {
    TOPLEVEL_IN_FLIGHT.load(Ordering::Acquire) <= 1 || toplevel_draining()
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
    if TOPLEVEL_IN_FLIGHT.load(Ordering::Acquire) <= 1 || toplevel_draining() {
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

    #[test]
    fn wait_work_runs_queued_jobs_once_each_and_never_nests() {
        let _lock = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(!run_wait_work(), "nothing installed");
        let queue = AtomicUsize::new(0);
        let nested_ran = AtomicUsize::new(0);
        let hook = || -> bool {
            if queue.fetch_add(1, Ordering::Relaxed) >= 3 {
                return false;
            }
            // A job that itself waits must not pull another job.
            if run_wait_work() {
                nested_ran.fetch_add(1, Ordering::Relaxed);
            }
            true
        };
        let guard = install_wait_work(&hook);
        let before = wait_work_runs();
        assert!(run_wait_work());
        assert!(run_wait_work());
        assert!(run_wait_work());
        assert!(!run_wait_work(), "queue exhausted");
        assert_eq!(wait_work_runs() - before, 3);
        assert_eq!(nested_ran.load(Ordering::Relaxed), 0);
        drop(guard);
        assert!(!run_wait_work(), "uninstalled");
    }
}
