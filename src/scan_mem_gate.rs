//! Memory-aware admission for parallel file scanning.
//!
//! `scan_files`/`scan_directory` analyse files on a rayon pool. Slot count says
//! nothing about *memory*: a slot analysing a multi-gigabyte archive holds the
//! archive plus its expanded members resident, while a slot on a 4 KB script
//! holds almost nothing. A burst of large archives co-residing exhausts RAM and
//! OOM-kills the host.
//!
//! This gate caps the aggregate estimated footprint of concurrently-analysed
//! files. Each file reserves `size × EXPANSION` (floored, capped at the budget);
//! a file is admitted only when its reservation leaves the configured headroom
//! in **live available memory** — so large archives serialise while small files
//! still fill the pool, and, because availability is read live, concurrent
//! processes (e.g. several `litmus` instances) leave room for each other rather
//! than each assuming it owns the whole box. A lone file always makes progress
//! (immediately if it fits, otherwise after a bounded wait).

use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Fraction of total RAM used as the aggregate-reservation ceiling when live
/// available memory can't be read (the only-thing-to-go-by fallback).
const BUDGET_FRACTION: f64 = 0.75;
/// On-disk size multiplier estimating an archive's peak resident footprint.
const EXPANSION: u64 = 8;
/// Floor so thousands of tiny files still register aggregate pressure.
const MIN_ESTIMATE_BYTES: usize = 8 * 1024 * 1024;
/// Headroom kept free when admitting a lone file against live available memory.
const LONE_HEADROOM_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Re-check interval while a worker waits for budget.
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// A lone file that never fits live memory is force-admitted after this long,
/// so the scan can't wedge forever on one oversized file.
const FORCE_ADMIT_AFTER: Duration = Duration::from_secs(300);

/// Aggregate byte-budget admission gate over concurrently-analysed files.
pub(crate) struct ScanMemGate {
    /// Aggregate reservation ceiling (fallback when available memory is unknown).
    budget_bytes: usize,
    /// Live available memory to keep free when admitting; `total − budget`.
    free_floor_bytes: u64,
    reserved: Mutex<usize>,
    released: Condvar,
    /// Live available-memory source; a field so tests can inject a fixed value.
    available_fn: fn() -> Option<u64>,
}

impl ScanMemGate {
    pub(crate) fn new() -> Self {
        Self::with_available(crate::memory_tracker::available_memory)
    }

    fn with_available(available_fn: fn() -> Option<u64>) -> Self {
        let (budget_bytes, free_floor_bytes) = match crate::memory_tracker::total_memory() {
            #[allow(
                clippy::cast_precision_loss,
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss
            )]
            Some(total) if total > 0 => {
                let budget = (total as f64 * BUDGET_FRACTION) as usize;
                (budget, total.saturating_sub(budget as u64))
            }
            _ => (usize::MAX, 0),
        };
        Self {
            budget_bytes,
            free_floor_bytes,
            reserved: Mutex::new(0),
            released: Condvar::new(),
            available_fn,
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn estimate(&self, size: u64) -> usize {
        let raw = usize::try_from(size.saturating_mul(EXPANSION)).unwrap_or(usize::MAX);
        raw.max(MIN_ESTIMATE_BYTES).min(self.budget_bytes)
    }

    /// Block until `size`'s estimated footprint fits, then reserve it. The guard
    /// releases the reservation on drop.
    pub(crate) fn acquire(&self, size: u64) -> ScanMemPermit<'_> {
        let est = self.estimate(size);
        let started = Instant::now();
        let mut reserved = self.reserved.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if self.fits(*reserved, est, started.elapsed() >= FORCE_ADMIT_AFTER) {
                *reserved += est;
                return ScanMemPermit { gate: self, est };
            }
            let (guard, _) = self
                .released
                .wait_timeout(reserved, POLL_INTERVAL)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            reserved = guard;
        }
    }

    /// Whether reserving `est` on top of `reserved` is allowed right now.
    #[allow(clippy::cast_possible_truncation)]
    fn fits(&self, reserved: usize, est: usize, force_lone: bool) -> bool {
        let available = (self.available_fn)();
        // Lone file: admit if it fits live memory with headroom, so a single
        // large archive makes progress. Unknown memory or a long wait admits
        // unconditionally — the bounded escape hatch.
        if reserved == 0 {
            let fits = match available {
                Some(avail) => (est as u64).saturating_add(LONE_HEADROOM_BYTES) <= avail,
                None => true,
            };
            return fits || force_lone;
        }
        // Aggregate ceiling caps commitments before their allocations land.
        if reserved.saturating_add(est) > self.budget_bytes {
            return false;
        }
        // Cross-process live gate: leave free_floor available after admitting.
        match available {
            Some(avail) => (est as u64).saturating_add(self.free_floor_bytes) <= avail,
            None => true,
        }
    }

    fn release(&self, est: usize) {
        let mut reserved = self.reserved.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        *reserved = reserved.saturating_sub(est);
        self.released.notify_all();
    }
}

/// RAII reservation; dropping it frees the budget and wakes waiters.
pub(crate) struct ScanMemPermit<'a> {
    gate: &'a ScanMemGate,
    est: usize,
}

impl Drop for ScanMemPermit<'_> {
    fn drop(&mut self) {
        self.gate.release(self.est);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: u64 = 1024 * 1024;

    fn no_available() -> Option<u64> {
        None
    }
    fn avail_200mb() -> Option<u64> {
        Some(200 * MB)
    }

    fn gate(budget: usize, free_floor: u64, available_fn: fn() -> Option<u64>) -> ScanMemGate {
        ScanMemGate {
            budget_bytes: budget,
            free_floor_bytes: free_floor,
            reserved: Mutex::new(0),
            released: Condvar::new(),
            available_fn,
        }
    }

    #[test]
    fn unknown_available_falls_back_to_budget() {
        let g = gate(100 * MB as usize, 0, no_available);
        // Lone admits regardless.
        assert!(g.fits(0, 80 * MB as usize, false));
        // Non-lone: budget ceiling applies.
        assert!(g.fits(50 * MB as usize, 40 * MB as usize, false)); // 90 ≤ 100
        assert!(!g.fits(80 * MB as usize, 40 * MB as usize, false)); // 120 > 100
    }

    #[test]
    fn live_gate_serialises_large_jobs() {
        let g = gate(10_000 * MB as usize, 100 * MB, avail_200mb);
        // 150 MB job + 100 MB floor = 250 MB > 200 available → denied.
        assert!(!g.fits(50 * MB as usize, 150 * MB as usize, false));
        // 50 MB job + 100 MB floor = 150 MB ≤ 200 available → admitted.
        assert!(g.fits(50 * MB as usize, 50 * MB as usize, false));
    }

    #[test]
    fn lone_job_waits_until_forced_when_it_exceeds_available() {
        let g = gate(10_000 * MB as usize, 0, avail_200mb);
        // 100 MB + 2 GiB headroom > 200 MB available → not yet.
        assert!(!g.fits(0, 100 * MB as usize, false));
        // Forced after the bounded wait → admits (escape hatch).
        assert!(g.fits(0, 100 * MB as usize, true));
    }
}
