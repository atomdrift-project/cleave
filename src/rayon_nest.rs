//! Adaptive nested rayon: keep member-inner `par_iter` only when one
//! top-level file owns the pool.
//!
//! Archive analysis fans members out at depth 0 (that is how a lone zip
//! finishes in ~66 s). Each member then nests again — Aho-Corasick chunks,
//! YARA buckets, trait eval, composite rules. Under a directory scan those
//! inner joins steal workers from sibling archives and inflate member wall
//! 5–17× (S3/S4/S2w on `C:\data\faster`). Serializing the inner joins when
//! two or more top-level files are in flight leaves member steal intact and
//! keeps a single-file scan on the fast path (`analyze_file` never enters
//! the counter, so `in_flight == 0`).
//!
//! `CLEAVE_SERIAL_TRAITS=1` still forces the old always-serial inner path.

use std::sync::atomic::{AtomicUsize, Ordering};

static TOPLEVEL_IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct ToplevelInFlightGuard;

impl Drop for ToplevelInFlightGuard {
    fn drop(&mut self) {
        TOPLEVEL_IN_FLIGHT.fetch_sub(1, Ordering::Release);
    }
}

pub(crate) fn enter_toplevel_analysis() -> ToplevelInFlightGuard {
    TOPLEVEL_IN_FLIGHT.fetch_add(1, Ordering::AcqRel);
    ToplevelInFlightGuard
}

fn serial_traits_forced() -> bool {
    static FLAG: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *FLAG.get_or_init(|| std::env::var_os("CLEAVE_SERIAL_TRAITS").is_some())
}

/// Whether member-inner work (AC chunks, YARA tiers, traits, composites)
/// should `par_iter`. False when sibling top-level files share the pool.
pub(crate) fn inner_work_parallel() -> bool {
    if serial_traits_forced() {
        return false;
    }
    TOPLEVEL_IN_FLIGHT.load(Ordering::Acquire) <= 1
}

#[cfg(test)]
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
    fn inner_serial_when_two_toplevel() {
        let _lock = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let a = enter_toplevel_analysis();
        let b = enter_toplevel_analysis();
        assert!(!inner_work_parallel());
        drop(b);
        assert!(inner_work_parallel());
        drop(a);
        assert!(inner_work_parallel());
    }
}
