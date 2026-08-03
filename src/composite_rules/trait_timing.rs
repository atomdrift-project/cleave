//! Env-gated per-trait evaluation-time aggregation.
//!
//! The slow-rule warnings only catch single evaluations over 500 ms, but the
//! cost that dominates archive scans is death-by-repetition: a rule that takes
//! 10 ms and runs against every one of thousands of members. With
//! `CLEAVE_TRAIT_TIMING=1`, every trait evaluation adds its duration here and
//! [`report`] logs the top aggregate consumers at end of scan. Off (the
//! default), [`record`] is a single branch on a cached bool.

use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use std::sync::OnceLock;
use std::time::Duration;

fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("CLEAVE_TRAIT_TIMING").is_ok_and(|v| v == "1"))
}

/// (total nanos, evaluation count) per trait id.
static TIMES: OnceLock<Mutex<FxHashMap<String, (u64, u64)>>> = OnceLock::new();

/// Add one evaluation's duration for `trait_id`. No-op unless
/// `CLEAVE_TRAIT_TIMING=1`.
pub(crate) fn record(trait_id: &str, duration: Duration) {
    if !enabled() {
        return;
    }
    let map = TIMES.get_or_init(|| Mutex::new(FxHashMap::default()));
    let mut guard = map.lock();
    if let Some(entry) = guard.get_mut(trait_id) {
        entry.0 += duration.as_nanos() as u64;
        entry.1 += 1;
    } else {
        guard.insert(trait_id.to_owned(), (duration.as_nanos() as u64, 1));
    }
}

/// Log the top-`n` traits by aggregate evaluation time. No-op when disabled or
/// nothing was recorded.
pub(crate) fn report(n: usize) {
    let Some(map) = TIMES.get() else { return };
    let guard = map.lock();
    let mut rows: Vec<_> = guard
        .iter()
        .map(|(id, &(ns, count))| (id.clone(), ns, count))
        .collect();
    drop(guard);
    rows.sort_by_key(|&(_, ns, _)| std::cmp::Reverse(ns));
    for (id, ns, count) in rows.into_iter().take(n) {
        tracing::info!(
            trait_id = %id,
            total_ms = ns / 1_000_000,
            evals = count,
            "trait time aggregate"
        );
    }
}
