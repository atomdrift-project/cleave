//! Iterative AST traversal utilities
//!
//! Provides stack-safe alternatives to recursive AST walking.
//! This prevents stack overflow on deeply nested code (minified JS, malicious files).

use std::time::{Duration, Instant};
use tree_sitter::{Node, TreeCursor};

/// Maximum depth to prevent runaway traversal on malformed ASTs
pub(crate) const MAX_AST_DEPTH: usize = 10_000;

/// Per-traversal CPU-time budget. Bounds a single AST walk's *CPU* consumption,
/// so a genuinely runaway traversal (pathological input) can't burn minutes —
/// while a thread merely descheduled under oversubscription is never cut off (it
/// accrues ~no CPU). A wall-clock budget conflates the two and silently drops
/// AST detections on starved threads; CPU time does not. See the archive
/// finding-drop investigation.
pub(crate) const AST_QUERY_CPU_BUDGET: Duration = Duration::from_secs(30);

/// CPU time consumed by the calling thread (immune to descheduling under load).
#[cfg(unix)]
pub(crate) fn thread_cpu_time() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable `timespec`; `CLOCK_THREAD_CPUTIME_ID` is
    // POSIX (Linux/macOS/FreeBSD — cleave's server targets). On error we report
    // zero (fail-open: never cut analysis short because the clock read failed).
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    if rc == 0 {
        #[allow(clippy::cast_sign_loss)] // tv_sec/tv_nsec are non-negative CPU time
        Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
    } else {
        Duration::ZERO
    }
}

/// Non-unix fallback: report zero, which disables the CPU budget. Acceptable
/// because the starvation bug only manifests under server-class oversubscription
/// (all unix); desktop/Windows runs aren't oversubscribed.
#[cfg(not(unix))]
pub(crate) fn thread_cpu_time() -> Duration {
    Duration::ZERO
}

/// Result of AST traversal with limit detection
#[derive(Debug, Clone, Default)]
pub(crate) struct WalkStats {
    /// Whether the depth limit was reached (potential anti-analysis)
    pub depth_limit_hit: bool,
    /// Maximum depth actually reached
    pub max_depth_reached: usize,
    /// Whether the deadline was exceeded
    pub deadline_exceeded: bool,
}

/// Like walk_tree but returns stats including whether depth limits were hit.
/// Use this when you need to detect potential anti-analysis techniques.
/// An optional deadline allows bailing out early if evaluation takes too long.
pub(crate) fn walk_tree_with_stats<'a, F>(
    cursor: &mut TreeCursor<'a>,
    deadline: Option<Instant>,
    mut visitor: F,
) -> WalkStats
where
    F: FnMut(Node<'a>, usize) -> bool,
{
    let mut stats = WalkStats::default();
    let mut depth = 0usize;
    let mut node_count = 0u32;

    // `deadline` is used only as a presence flag: when a rule-eval deadline is
    // active we bound this walk by CPU time (not the wall-clock instant), so a
    // thread starved under oversubscription is never cut off mid-walk.
    let cpu_budget = deadline.map(|_| AST_QUERY_CPU_BUDGET);
    let cpu_start = thread_cpu_time();

    loop {
        if depth > stats.max_depth_reached {
            stats.max_depth_reached = depth;
        }

        if depth > MAX_AST_DEPTH {
            stats.depth_limit_hit = true;
            return stats; // Safety limit reached
        }

        // Check the CPU budget every 4096 nodes to avoid syscall overhead.
        node_count += 1;
        if node_count & 0xFFF == 0
            && let Some(budget) = cpu_budget
            && thread_cpu_time().saturating_sub(cpu_start) > budget
        {
            stats.deadline_exceeded = true;
            return stats;
        }

        let node = cursor.node();
        let should_descend = visitor(node, depth);

        // Try to descend if visitor allows
        if should_descend && cursor.goto_first_child() {
            depth += 1;
            continue;
        }

        // Try to go to sibling
        if cursor.goto_next_sibling() {
            continue;
        }

        // Go back up until we can go sideways or reach root
        loop {
            if !cursor.goto_parent() {
                return stats; // Reached root, done
            }
            depth = depth.saturating_sub(1);
            if cursor.goto_next_sibling() {
                break; // Found a sibling, continue outer loop
            }
        }
    }
}
