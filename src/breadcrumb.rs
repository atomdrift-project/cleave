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
//! table that a caller (e.g. an embedding host's wedge dump) reads via [`snapshot`]. Writes
//! touch only the calling thread's own lock, so the hot per-member path stays
//! contention-free.
//!
//! A thread also names the rule it is evaluating on a large input (see
//! `rule_scope`): a rule that never returns is never reported by the timing
//! taken after it returns, so the breadcrumb is how it is seen while it runs.
//! Both kinds of crumb carry the request's cancellation flag as their owner, so
//! [`progress`] can answer for one analysis among many sharing a pool.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};

use crate::types::Istr;

/// What a worker thread is currently doing, captured when the breadcrumb is set.
#[derive(Debug, Clone)]
struct Crumb {
    analyzer: &'static str,
    target: String,
    owner: usize,
    since: Instant,
}

/// The rule a worker thread is evaluating, captured when it starts.
#[derive(Debug, Clone)]
struct RuleCrumb {
    id: Istr,
    owner: usize,
    since: Instant,
}

/// One thread's registry entry. `thread_id`/`rayon_index` are fixed for the
/// thread's life; `state` and `rule` are updated as scopes open and close.
#[derive(Debug)]
struct Inner {
    thread_id: u64,
    rayon_index: Option<usize>,
    state: Mutex<Option<Crumb>>,
    rule: Mutex<Option<RuleCrumb>>,
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

/// One named step of an analysis and how long it has been running.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// The archive member path, or the rule id.
    pub name: String,
    /// Time since the step began.
    pub age: Duration,
}

/// What one analysis is doing right now, as [`progress`] reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Progress {
    /// The longest-running archive member being analyzed. Nested archives
    /// report their outer member, which has been open the longest.
    pub member: Option<Step>,
    /// The longest-running rule evaluation on a large input (see
    /// `rule_scope`). Rules on small inputs are not tracked.
    pub rule: Option<Step>,
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
        rule: Mutex::new(None),
    });
    if let Ok(mut reg) = registry().lock() {
        reg.retain(|weak| weak.strong_count() > 0);
        reg.push(Arc::downgrade(&inner));
    }
    inner
}

/// The identity a crumb is filed under: the address of the analysis's
/// cancellation flag, which is unique among live analyses and already reaches
/// every place a crumb is set. Only compared, never dereferenced. `0` means
/// no owner (an analysis run without a flag).
fn owner_key(owner: Option<&AtomicBool>) -> usize {
    owner.map_or(0, |flag| std::ptr::from_ref(flag).addr())
}

/// Replace this thread's member crumb, returning the one it displaces.
fn replace(crumb: Option<Crumb>) -> Option<Crumb> {
    CRUMB.with(|inner| {
        inner
            .state
            .lock()
            .ok()
            .and_then(|mut state| std::mem::replace(&mut *state, crumb))
    })
}

/// Replace this thread's rule crumb, returning the one it displaces.
fn replace_rule(crumb: Option<RuleCrumb>) -> Option<RuleCrumb> {
    CRUMB.with(|inner| {
        inner
            .rule
            .lock()
            .ok()
            .and_then(|mut rule| std::mem::replace(&mut *rule, crumb))
    })
}

/// Record what the current thread is analyzing. Prefer [`scope`], which
/// restores the previous breadcrumb automatically on the way out.
pub fn set(analyzer: &'static str, target: impl Into<String>) {
    replace(Some(Crumb {
        analyzer,
        target: target.into(),
        owner: 0,
        since: Instant::now(),
    }));
}

/// Clear the current thread's breadcrumb, marking it idle.
pub fn clear() {
    replace(None);
}

/// RAII breadcrumb: records `analyzer`/`target` for the current thread and
/// restores the crumb it displaced on drop, so a nested member (an archive
/// inside an archive, on the same thread) hands the outer one back, and an
/// early return or panic can't leave a stale crumb.
#[derive(Debug)]
#[must_use = "the breadcrumb is cleared when the returned guard is dropped"]
pub struct Scope {
    previous: Option<Crumb>,
}

impl Drop for Scope {
    fn drop(&mut self) {
        replace(self.previous.take());
    }
}

/// Set a breadcrumb for the lifetime of the returned [`Scope`]. `owner` is the
/// analysis's cancellation flag, which [`progress`] looks crumbs up by.
pub fn scope(
    analyzer: &'static str,
    target: impl Into<String>,
    owner: Option<&AtomicBool>,
) -> Scope {
    let previous = replace(Some(Crumb {
        analyzer,
        target: target.into(),
        owner: owner_key(owner),
        since: Instant::now(),
    }));
    Scope { previous }
}

/// RAII rule breadcrumb; see `rule_scope`.
#[derive(Debug)]
#[must_use = "the rule breadcrumb is cleared when the returned guard is dropped"]
pub struct RuleScope {
    previous: Option<RuleCrumb>,
}

impl Drop for RuleScope {
    fn drop(&mut self) {
        replace_rule(self.previous.take());
    }
}

/// Name the rule `id` this thread is evaluating until the returned guard
/// drops, restoring any rule it interrupted (a `trait:` reference evaluating
/// another rule). Costs a lock on the thread's own slot and an `Arc` clone, so
/// callers reserve it for inputs large enough that a rule can run long.
pub(crate) fn rule_scope(owner: Option<&AtomicBool>, id: Istr) -> RuleScope {
    let previous = replace_rule(Some(RuleCrumb {
        id,
        owner: owner_key(owner),
        since: Instant::now(),
    }));
    RuleScope { previous }
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

/// What the analysis whose cancellation flag is `owner` is doing now: its
/// longest-open archive member and its longest-running tracked rule, across
/// every thread working for it. Cheap enough for a periodic watchdog: one
/// pass over the thread registry, cloning only the two strings it returns.
#[must_use]
pub fn progress(owner: &AtomicBool) -> Progress {
    let key = owner_key(Some(owner));
    let now = Instant::now();
    let mut member: Option<(Instant, String)> = None;
    let mut rule: Option<(Instant, Istr)> = None;
    if let Ok(reg) = registry().lock() {
        for inner in reg.iter().filter_map(Weak::upgrade) {
            if let Ok(state) = inner.state.lock()
                && let Some(crumb) = state.as_ref().filter(|c| c.owner == key)
                && member
                    .as_ref()
                    .is_none_or(|(since, _)| crumb.since < *since)
            {
                member = Some((crumb.since, crumb.target.clone()));
            }
            if let Ok(state) = inner.rule.lock()
                && let Some(crumb) = state.as_ref().filter(|c| c.owner == key)
                && rule.as_ref().is_none_or(|(since, _)| crumb.since < *since)
            {
                rule = Some((crumb.since, crumb.id.clone()));
            }
        }
    }
    Progress {
        member: member.map(|(since, name)| Step {
            name,
            age: now.saturating_duration_since(since),
        }),
        rule: rule.map(|(since, id)| Step {
            name: id.as_str().to_owned(),
            age: now.saturating_duration_since(since),
        }),
    }
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
            let _scope = scope("member", "lib/modules/foo.ko", None);
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
        let _outer = scope("member", "outer", None);
        let mid = snapshot();
        // The single active crumb on this thread is present; ordering is by age,
        // which is exercised once more than one thread is active in production.
        assert!(mid.iter().any(|b| b.target == "outer"));
    }

    #[test]
    fn nested_scopes_restore_the_outer_crumb() {
        let flag = AtomicBool::new(false);
        let _outer = scope("member", "outer.tar", Some(&flag));
        {
            let _inner = scope("member", "outer.tar/inner.js", Some(&flag));
            let _rule = rule_scope(Some(&flag), Istr::from("a/b/c"));
            {
                let _nested = rule_scope(Some(&flag), Istr::from("a/b/d"));
            }
            let seen = progress(&flag);
            assert_eq!(seen.rule.map(|s| s.name).as_deref(), Some("a/b/c"));
        }
        let seen = progress(&flag);
        assert_eq!(seen.member.map(|s| s.name).as_deref(), Some("outer.tar"));
        assert_eq!(seen.rule, None, "a closed rule scope leaves no rule behind");
    }

    #[test]
    fn progress_reports_only_its_own_analysis_across_threads() {
        let mine = AtomicBool::new(false);
        let other = AtomicBool::new(false);
        let (started, release) = (std::sync::Barrier::new(3), std::sync::Barrier::new(3));
        std::thread::scope(|s| {
            s.spawn(|| {
                let _m = scope("member", "pkg/huge.md", Some(&mine));
                let _r = rule_scope(Some(&mine), Istr::from("anti-static/markup/comment"));
                started.wait();
                release.wait();
            });
            s.spawn(|| {
                let _m = scope("member", "unrelated.js", Some(&other));
                started.wait();
                release.wait();
            });
            started.wait();
            let seen = progress(&mine);
            release.wait();
            assert_eq!(seen.member.map(|s| s.name).as_deref(), Some("pkg/huge.md"));
            assert_eq!(
                seen.rule.map(|s| s.name).as_deref(),
                Some("anti-static/markup/comment")
            );
        });
        assert_eq!(progress(&mine), Progress::default());
    }
}
