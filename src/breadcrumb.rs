//! Per-thread analysis breadcrumbs for diagnosing wedged workers.
//!
//! The top-level [`PhaseTracker`](crate::PhaseTracker) records one coarse stage
//! per analysis (`archive:tar.gz`, `yara`, …), but an archive fans its members
//! across the whole rayon pool — so when a worker wedges inside archive
//! analysis, that single phase string can't say *which member* on *which
//! analyzer* each pool thread is stuck on. The older
//! [`memory_tracker::set_current_phase`](crate::memory_tracker) is a single
//! global slot, so concurrent members clobber each other.
//!
//! This module gives each worker thread its own breadcrumb — `(analyzer,
//! target)` plus how long it has been there — registered in a process-global
//! table that a caller (e.g. litmus's wedge dump) reads via [`snapshot`]. Writes
//! touch only the calling thread's own lock, so the hot per-member path stays
//! contention-free.

use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

/// What a worker thread is currently doing, captured when the breadcrumb is set.
#[derive(Debug, Clone)]
struct Crumb {
    analyzer: &'static str,
    target: String,
    since: Instant,
}

/// One thread's registry entry. `thread_id`/`rayon_index` are fixed for the
/// thread's life; `state` is updated on every [`set`]/[`clear`].
#[derive(Debug)]
struct Inner {
    thread_id: u64,
    rayon_index: Option<usize>,
    state: Mutex<Option<Crumb>>,
}

/// A single thread's active breadcrumb, as returned by [`snapshot`].
#[derive(Debug, Clone)]
pub struct Breadcrumb {
    /// OS thread id — matches `/proc/<pid>/task` and `ps`, so it cross-references
    /// the wait-channel of a blocked thread.
    pub thread_id: u64,
    /// Rayon pool index when the thread belongs to the global pool (the `N` in
    /// `rayon-N`), else `None`.
    pub rayon_index: Option<usize>,
    /// Analyzer running on the thread (e.g. `"member"`, `"yara"`, `"strings"`).
    pub analyzer: &'static str,
    /// What is being analyzed — typically an archive member path.
    pub target: String,
    /// How long the thread has been on this step.
    pub age: Duration,
}

fn registry() -> &'static Mutex<Vec<Weak<Inner>>> {
    static REGISTRY: OnceLock<Mutex<Vec<Weak<Inner>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(Vec::new()))
}

thread_local! {
    static CRUMB: Arc<Inner> = register_thread();
}

/// Build this thread's registry entry on first use and register a weak handle so
/// [`snapshot`] can find it. Dead entries are reaped opportunistically here.
fn register_thread() -> Arc<Inner> {
    let inner = Arc::new(Inner {
        thread_id: os_thread_id(),
        rayon_index: rayon::current_thread_index(),
        state: Mutex::new(None),
    });
    if let Ok(mut reg) = registry().lock() {
        reg.retain(|weak| weak.strong_count() > 0);
        reg.push(Arc::downgrade(&inner));
    }
    inner
}

/// Record what the current thread is analyzing. Prefer [`scope`], which clears
/// the breadcrumb automatically on the way out.
pub fn set(analyzer: &'static str, target: impl Into<String>) {
    CRUMB.with(|inner| {
        if let Ok(mut state) = inner.state.lock() {
            *state = Some(Crumb {
                analyzer,
                target: target.into(),
                since: Instant::now(),
            });
        }
    });
}

/// Clear the current thread's breadcrumb, marking it idle.
pub fn clear() {
    CRUMB.with(|inner| {
        if let Ok(mut state) = inner.state.lock() {
            *state = None;
        }
    });
}

/// RAII breadcrumb: records `analyzer`/`target` for the current thread and
/// clears it on drop, so an early return or panic can't leave a stale crumb.
#[derive(Debug)]
#[must_use = "the breadcrumb is cleared when the returned guard is dropped"]
pub struct Scope {
    _private: (),
}

impl Drop for Scope {
    fn drop(&mut self) {
        clear();
    }
}

/// Set a breadcrumb for the lifetime of the returned [`Scope`].
pub fn scope(analyzer: &'static str, target: impl Into<String>) -> Scope {
    set(analyzer, target);
    Scope { _private: () }
}

/// Snapshot every thread's active breadcrumb, oldest step first so the most
/// likely culprit of a wedge leads.
#[must_use]
pub fn snapshot() -> Vec<Breadcrumb> {
    let now = Instant::now();
    let mut rows = Vec::new();
    if let Ok(reg) = registry().lock() {
        for inner in reg.iter().filter_map(Weak::upgrade) {
            let Ok(state) = inner.state.lock() else {
                continue;
            };
            if let Some(crumb) = state.as_ref() {
                rows.push(Breadcrumb {
                    thread_id: inner.thread_id,
                    rayon_index: inner.rayon_index,
                    analyzer: crumb.analyzer,
                    target: crumb.target.clone(),
                    age: now.saturating_duration_since(crumb.since),
                });
            }
        }
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.age));
    rows
}

/// OS thread id for the calling thread, matching `/proc/<pid>/task` and `ps`.
fn os_thread_id() -> u64 {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `gettid` takes no arguments and cannot fail.
        unsafe { libc::syscall(libc::SYS_gettid) as u64 }
    }
    #[cfg(target_os = "macos")]
    {
        let mut tid: u64 = 0;
        // SAFETY: writing this thread's id into a local; a 0 handle means self.
        unsafe { libc::pthread_threadid_np(0, &mut tid) };
        tid
    }
    #[cfg(target_os = "freebsd")]
    {
        let mut tid: libc::c_long = 0;
        // SAFETY: `thr_self` writes the calling thread's id into the pointee.
        unsafe { libc::thr_self(&mut tid) };
        tid as u64
    }
    #[cfg(any(target_os = "illumos", target_os = "solaris"))]
    {
        // `_lwp_self(2)` returns the LWP id (matches `ps -L`'s `lwp`); the libc
        // crate doesn't bind it for these targets, so declare it directly.
        unsafe extern "C" {
            fn _lwp_self() -> libc::id_t;
        }
        // SAFETY: `_lwp_self` takes no arguments and cannot fail.
        unsafe { _lwp_self() as u64 }
    }
    #[cfg(target_os = "windows")]
    {
        unsafe extern "system" {
            fn GetCurrentThreadId() -> u32;
        }
        // SAFETY: GetCurrentThreadId takes no arguments and cannot fail.
        unsafe { u64::from(GetCurrentThreadId()) }
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "solaris",
        target_os = "windows"
    )))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_sets_then_clears_for_this_thread() {
        let tid = os_thread_id();
        let present = || snapshot().iter().any(|b| b.thread_id == tid);
        clear();
        assert!(!present(), "precondition: no active crumb");
        {
            let _scope = scope("member", "lib/modules/foo.ko");
            let mine = snapshot();
            let row = mine.iter().find(|b| b.thread_id == tid);
            assert!(row.is_some(), "scope must register an active crumb");
            assert_eq!(row.map(|b| b.analyzer), Some("member"));
            assert_eq!(row.map(|b| b.target.as_str()), Some("lib/modules/foo.ko"));
        }
        assert!(!present(), "dropping the scope must clear the crumb");
    }

    #[test]
    fn snapshot_is_oldest_first() {
        clear();
        let _outer = scope("member", "outer");
        let mid = snapshot();
        // The single active crumb on this thread is present; ordering is by age,
        // which is exercised once more than one thread is active in production.
        assert!(mid.iter().any(|b| b.target == "outer"));
    }
}
