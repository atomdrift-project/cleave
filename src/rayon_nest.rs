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

/// The in-flight counter for the calling thread.
///
/// Production always reads the process-global one. Tests may install a
/// private set (see [`isolate_counters`]) so their assertions are not moved
/// by an unrelated test that happens to be running an analysis: these
/// counters are global by design — every analysis in the process shares them
/// — so a unit test asserting `TOPLEVEL_IN_FLIGHT == 0` was really asserting
/// something about the whole test binary.
#[inline]
fn toplevel_in_flight() -> &'static AtomicUsize {
    #[cfg(test)]
    {
        if let Some(counters) = ISOLATED_COUNTERS.with(Cell::get) {
            return &counters.toplevel_in_flight;
        }
    }
    &TOPLEVEL_IN_FLIGHT
}

#[inline]
fn foreground_inner_owners() -> &'static AtomicUsize {
    #[cfg(test)]
    {
        if let Some(counters) = ISOLATED_COUNTERS.with(Cell::get) {
            return &counters.inner_owners;
        }
    }
    &INNER_PARALLEL_OWNERS
}

#[inline]
fn background_inner_owners() -> &'static AtomicUsize {
    #[cfg(test)]
    {
        if let Some(counters) = ISOLATED_COUNTERS.with(Cell::get) {
            return &counters.background_inner_owners;
        }
    }
    &BACKGROUND_INNER_PARALLEL_OWNERS
}

/// A private counter set for one test.
#[cfg(test)]
pub(crate) struct IsolatedCounters {
    toplevel_in_flight: AtomicUsize,
    inner_owners: AtomicUsize,
    background_inner_owners: AtomicUsize,
}

#[cfg(test)]
impl IsolatedCounters {
    pub(crate) fn toplevel_in_flight(&self) -> usize {
        self.toplevel_in_flight.load(Ordering::Acquire)
    }
    pub(crate) fn inner_owners(&self) -> usize {
        self.inner_owners.load(Ordering::Acquire)
    }
    pub(crate) fn background_inner_owners(&self) -> usize {
        self.background_inner_owners.load(Ordering::Acquire)
    }
}

#[cfg(test)]
thread_local! {
    static ISOLATED_COUNTERS: Cell<Option<&'static IsolatedCounters>> = const { Cell::new(None) };
}

/// Install a fresh private counter set on this thread and return it.
///
/// Leaked on purpose: the handle is `'static` so a test can hand it to the
/// threads it spawns (via [`adopt_isolation`]), and a test binary exits long
/// before a few dozen leaked triples matter.
#[cfg(test)]
pub(crate) fn isolate_counters() -> &'static IsolatedCounters {
    let counters: &'static IsolatedCounters = Box::leak(Box::new(IsolatedCounters {
        toplevel_in_flight: AtomicUsize::new(0),
        inner_owners: AtomicUsize::new(0),
        background_inner_owners: AtomicUsize::new(0),
    }));
    adopt_isolation(counters);
    counters
}

/// Join a thread to a test's private counter set. Every thread a test spawns
/// must call this, or it will fall through to the process-global counters.
#[cfg(test)]
pub(crate) fn adopt_isolation(counters: &'static IsolatedCounters) {
    ISOLATED_COUNTERS.with(|slot| slot.set(Some(counters)));
}

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
// Owner slots come in two classes, foreground and background, with a counter
// and a cap each. A thread marked background — a host's idle pull worker, see
// [`mark_thread_background`] — claims from the background pair only, so pull
// work can never hold the slots an interactive analysis needs. Before this
// split there was one pair for the whole process, and on a 16-thread server
// the inner-parallel cap is one: the idle worker held it, and the server's
// own archive analyses ran serial behind it (measured 2026-09-05: 173s waits
// on the gate; a 341s interactive analysis of a repository that took 30s on
// an idle host).
static INNER_PARALLEL_OWNERS: AtomicUsize = AtomicUsize::new(0);
static NESTED_MEMBER_OWNERS: AtomicUsize = AtomicUsize::new(0);
static BACKGROUND_INNER_PARALLEL_OWNERS: AtomicUsize = AtomicUsize::new(0);
static BACKGROUND_NESTED_MEMBER_OWNERS: AtomicUsize = AtomicUsize::new(0);
/// Explicit caps, set by [`set_parallel_owner_caps`]; zero means "not set",
/// and the lazy defaults below apply.
static FOREGROUND_INNER_CAP: AtomicUsize = AtomicUsize::new(0);
static FOREGROUND_NESTED_CAP: AtomicUsize = AtomicUsize::new(0);
static BACKGROUND_INNER_CAP: AtomicUsize = AtomicUsize::new(0);
static BACKGROUND_NESTED_CAP: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static TOPLEVEL_ID: Cell<u64> = const { Cell::new(0) };
    static OWNS_INNER_PARALLELISM: Cell<bool> = const { Cell::new(false) };
    static NESTED_MEMBER_PARALLELISM: Cell<bool> = const { Cell::new(false) };
    /// The top-level analysis on this thread runs on a pool of its own
    /// (`AnalysisOptions::dedicated_pool`): exempt from the shared-pool
    /// bounded-owner rule, and invisible to it.
    static DEDICATED_POOL: Cell<bool> = const { Cell::new(false) };
    static BACKGROUND_THREAD: Cell<bool> = const { Cell::new(false) };
}

/// Mark the calling thread as background work: every owner slot it claims from
/// here on comes from the background class. Meant for a rayon pool's start
/// handler, so a host's pull-queue analyses fan out on their own pool and
/// draw on their own slots, leaving the foreground caps whole for the
/// analyses a caller is waiting on. Rayon children do not inherit the mark
/// and do not need to: a pool's workers are all marked at start.
pub fn mark_thread_background() {
    BACKGROUND_THREAD.with(|value| value.set(true));
}

/// Size the owner caps for each class from the thread count of the pool it
/// runs on: the same formulas the lazy defaults use (`threads / 32` inner
/// owners, `threads / 8` nested-member owners, each clamped to 1..=16), but
/// per pool rather than from whichever pool happened to call first. A host
/// with two pools must call this, or the foreground cap may be derived from
/// the background pool's size. The `CLEAVE_*_OWNERS` environment overrides
/// still win for the foreground class.
pub fn set_parallel_owner_caps(foreground_threads: usize, background_threads: usize) {
    FOREGROUND_INNER_CAP.store(inner_cap_for(foreground_threads), Ordering::Release);
    FOREGROUND_NESTED_CAP.store(nested_cap_for(foreground_threads), Ordering::Release);
    BACKGROUND_INNER_CAP.store(inner_cap_for(background_threads), Ordering::Release);
    BACKGROUND_NESTED_CAP.store(nested_cap_for(background_threads), Ordering::Release);
}

fn inner_cap_for(threads: usize) -> usize {
    (threads / 32).clamp(1, 16)
}

fn nested_cap_for(threads: usize) -> usize {
    (threads / 8).clamp(1, 16)
}

fn background_thread() -> bool {
    BACKGROUND_THREAD.with(Cell::get)
}

/// The inner-parallel owner counter and cap for the calling thread's class.
fn inner_owner_slots() -> (&'static AtomicUsize, usize) {
    if background_thread() {
        let cap = match BACKGROUND_INNER_CAP.load(Ordering::Acquire) {
            0 => 1,
            cap => cap,
        };
        (background_inner_owners(), cap)
    } else {
        (foreground_inner_owners(), max_inner_parallel_owners())
    }
}

/// The nested-member owner counter and cap for the calling thread's class.
fn nested_owner_slots() -> (&'static AtomicUsize, usize) {
    if background_thread() {
        let cap = match BACKGROUND_NESTED_CAP.load(Ordering::Acquire) {
            0 => 1,
            cap => cap,
        };
        (&BACKGROUND_NESTED_MEMBER_OWNERS, cap)
    } else {
        (&NESTED_MEMBER_OWNERS, max_nested_member_owners())
    }
}

pub(crate) struct ToplevelInFlightGuard {
    previous_id: u64,
    previous_owned: bool,
    previous_dedicated: bool,
    dedicated: bool,
    /// Which class's counter an owned slot came from. Recorded at entry so the
    /// release matches the claim even if the mark were to change underneath.
    background: bool,
}

impl Drop for ToplevelInFlightGuard {
    fn drop(&mut self) {
        let owned = OWNS_INNER_PARALLELISM.with(|value| value.replace(self.previous_owned));
        if owned {
            let owners = if self.background {
                background_inner_owners()
            } else {
                foreground_inner_owners()
            };
            owners.fetch_sub(1, Ordering::Release);
        }
        TOPLEVEL_ID.with(|value| value.set(self.previous_id));
        DEDICATED_POOL.with(|value| value.set(self.previous_dedicated));
        if !self.dedicated {
            toplevel_in_flight().fetch_sub(1, Ordering::Release);
        }
    }
}

/// Register a top-level analysis. `dedicated_pool` says the caller runs it on
/// a rayon pool of its own: it then always gets inner parallelism (its pool
/// has nobody else to starve) and is not counted among the shared pool's
/// in-flight analyses, so a long whale on a private pool neither takes one of
/// the bounded owner slots nor makes the shared pool's small analyses go
/// serial for its duration. Measured 2026-09-05 on a 128-thread scan server:
/// four 36–254 MB wheels on private pools held all four owner slots for
/// 30 s each, and every 1–5 MB package that arrived meanwhile analyzed its
/// members serially, 2.5× slower than alone.
pub(crate) fn enter_toplevel_analysis_on(dedicated_pool: bool) -> ToplevelInFlightGuard {
    let id = NEXT_TOPLEVEL_ID.fetch_add(1, Ordering::Relaxed);
    let previous_id = TOPLEVEL_ID.with(|value| value.replace(id));
    let previous_owned = OWNS_INNER_PARALLELISM.with(|value| value.replace(false));
    let previous_dedicated = DEDICATED_POOL.with(|value| value.replace(dedicated_pool));
    if !dedicated_pool {
        toplevel_in_flight().fetch_add(1, Ordering::AcqRel);
    }
    ToplevelInFlightGuard {
        previous_id,
        previous_owned,
        previous_dedicated,
        dedicated: dedicated_pool,
        background: background_thread(),
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
            .unwrap_or_else(|| match FOREGROUND_INNER_CAP.load(Ordering::Acquire) {
                0 => inner_cap_for(rayon::current_num_threads()),
                cap => cap,
            })
    })
}

fn max_nested_member_owners() -> usize {
    static MAX: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *MAX.get_or_init(|| {
        std::env::var("CLEAVE_NESTED_MEMBER_PARALLEL_OWNERS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| match FOREGROUND_NESTED_CAP.load(Ordering::Acquire) {
                0 => nested_cap_for(rayon::current_num_threads()),
                cap => cap,
            })
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
    background: bool,
}

impl Drop for NestedMemberParallelGuard {
    fn drop(&mut self) {
        let owned = NESTED_MEMBER_PARALLELISM.with(|value| value.replace(self.previous));
        if owned && !self.previous {
            let owners = if self.background {
                &BACKGROUND_NESTED_MEMBER_OWNERS
            } else {
                &NESTED_MEMBER_OWNERS
            };
            owners.fetch_sub(1, Ordering::Release);
        }
    }
}

fn try_claim_nested_member_owner() -> bool {
    if NESTED_MEMBER_PARALLELISM.with(Cell::get) {
        return true;
    }
    let (owners, limit) = nested_owner_slots();
    let mut current = owners.load(Ordering::Acquire);
    while current < limit {
        match owners.compare_exchange_weak(
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
    let background = background_thread();
    if previous {
        return Some(NestedMemberParallelGuard {
            previous,
            background,
        });
    }
    if try_claim_nested_member_owner() {
        return Some(NestedMemberParallelGuard {
            previous,
            background,
        });
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
    toplevel_in_flight().load(Ordering::Acquire) <= 1 || toplevel_draining()
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
    if DEDICATED_POOL.with(Cell::get) {
        return true;
    }
    if toplevel_in_flight().load(Ordering::Acquire) <= 1 || toplevel_draining() {
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

    let (owners, limit) = inner_owner_slots();
    let mut current = owners.load(Ordering::Acquire);
    while current < limit {
        match owners.compare_exchange_weak(
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

    /// A dedicated-pool analysis is parallel regardless of the owner cap and
    /// does not count as in flight for the shared pool.
    #[test]
    fn dedicated_pool_analysis_is_exempt_and_invisible() {
        let _lock = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let counters = isolate_counters();
        let _shared_a = enter_toplevel_analysis_on(false);
        let shared_b = std::thread::spawn(move || {
            adopt_isolation(counters);
            let _g = enter_toplevel_analysis_on(false);
            std::thread::sleep(std::time::Duration::from_millis(30));
        });
        let dedicated = std::thread::spawn(move || {
            adopt_isolation(counters);
            let _g = enter_toplevel_analysis_on(true);
            assert!(inner_work_parallel(), "dedicated pool always parallel");
            counters.toplevel_in_flight()
        })
        .join()
        .unwrap();
        assert!(
            dedicated <= 2,
            "dedicated analysis must not count as in flight"
        );
        shared_b.join().unwrap();
        drop(_shared_a);
        assert_eq!(counters.toplevel_in_flight(), 0);
        assert!(!DEDICATED_POOL.with(Cell::get));
    }

    /// The counters these tests assert on are process-global: every analysis
    /// in the binary moves them. Before the tests took a private set, an
    /// unrelated test running an analysis at the wrong moment made them fail
    /// — the observed symptom was `assert_eq!(TOPLEVEL_IN_FLIGHT, before)`
    /// reporting 1, and `inner_work_parallel()` returning false at what the
    /// test believed was zero in-flight. This reproduces that interference
    /// deliberately and shows isolation holds against it.
    #[test]
    fn isolated_counters_ignore_concurrent_global_analyses() {
        let _lock = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let counters = isolate_counters();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_writer = std::sync::Arc::clone(&stop);
        // A stand-in for any other test in this binary running an analysis:
        // it enters and leaves the *global* counter continuously.
        let noise = std::thread::spawn(move || {
            while !stop_writer.load(Ordering::Acquire) {
                let _g = enter_toplevel_analysis_on(false);
                std::thread::yield_now();
            }
        });
        for _ in 0..2000 {
            assert_eq!(counters.toplevel_in_flight(), 0);
            assert!(inner_work_parallel(), "no analysis in flight on this set");
            let one = enter_toplevel_analysis_on(false);
            assert_eq!(counters.toplevel_in_flight(), 1);
            drop(one);
        }
        stop.store(true, Ordering::Release);
        noise.join().unwrap();
        assert_eq!(counters.toplevel_in_flight(), 0);
        assert!(
            TOPLEVEL_IN_FLIGHT.load(Ordering::Acquire) == 0,
            "the noise thread balanced its own global entries"
        );
    }

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn inner_parallel_with_zero_or_one_toplevel() {
        let _lock = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _counters = isolate_counters();
        assert!(inner_work_parallel());
        let one = enter_toplevel_analysis_on(false);
        assert!(inner_work_parallel());
        drop(one);
        assert!(inner_work_parallel());
    }

    #[test]
    fn one_of_two_toplevels_owns_inner_parallelism() {
        let _lock = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let counters = isolate_counters();
        let a = enter_toplevel_analysis_on(false);
        let b = enter_toplevel_analysis_on(false);
        assert!(inner_work_parallel());
        assert!(
            !std::thread::spawn(move || {
                adopt_isolation(counters);
                inner_work_parallel()
            })
            .join()
            .unwrap()
        );
        drop(b);
        assert!(inner_work_parallel());
        drop(a);
        assert!(inner_work_parallel());
    }

    /// A background thread's owner slot is not the foreground's. With one
    /// foreground slot and a background analysis holding a background one,
    /// a foreground analysis beside another still gets its own.
    #[test]
    fn background_owners_never_take_foreground_slots() {
        let _lock = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let counters = isolate_counters();
        set_parallel_owner_caps(16, 8);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let background = std::thread::spawn(move || {
            adopt_isolation(counters);
            mark_thread_background();
            let _a = enter_toplevel_analysis_on(false);
            let _b = enter_toplevel_analysis_on(false);
            assert!(inner_work_parallel(), "background claims its own slot");
            assert_eq!(counters.background_inner_owners(), 1);
            ready_tx.send(()).unwrap();
            done_rx.recv().unwrap();
        });
        ready_rx.recv().unwrap();
        // Two foreground top-levels beside the two background ones: the
        // foreground slot is untouched, so the first foreground claim wins.
        let a = enter_toplevel_analysis_on(false);
        let b = enter_toplevel_analysis_on(false);
        assert_eq!(counters.inner_owners(), 0);
        assert!(
            inner_work_parallel(),
            "foreground slot was not consumed by background work"
        );
        assert_eq!(counters.inner_owners(), 1);
        drop(b);
        drop(a);
        done_tx.send(()).unwrap();
        background.join().unwrap();
        assert_eq!(counters.background_inner_owners(), 0);
        assert_eq!(counters.inner_owners(), 0);
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
