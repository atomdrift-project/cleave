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

/// Cheap per-evaluation timer for the slow-rule / hard-timeout checks.
///
/// Every trait and composite evaluation brackets itself with a timer; with
/// hundreds of evaluations per member and tens of thousands of members,
/// `Instant::now`'s `QueryPerformanceCounter` pair was ~2% of total scan CPU.
/// On x86_64 this reads the invariant TSC instead (a few ns) and converts
/// ticks to wall time with a rate calibrated once against `Instant` after the
/// first ~50 ms of process lifetime; until calibration settles — and on other
/// architectures — it simply uses `Instant`. The consumers compare against
/// thresholds of seconds, so calibration error at the percent level is
/// irrelevant; correctness of the comparisons is preserved either way.
#[cfg(target_arch = "x86_64")]
mod eval_clock {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    fn tsc() -> u64 {
        // SAFETY: RDTSC is unprivileged and always available on x86_64.
        unsafe { core::arch::x86_64::_rdtsc() }
    }

    struct Base {
        tsc0: u64,
        instant0: Instant,
    }

    fn base() -> &'static Base {
        static BASE: OnceLock<Base> = OnceLock::new();
        BASE.get_or_init(|| Base {
            tsc0: tsc(),
            instant0: Instant::now(),
        })
    }

    /// Picoseconds per tick, 0 while uncalibrated.
    static PS_PER_TICK: AtomicU64 = AtomicU64::new(0);

    fn ps_per_tick() -> u64 {
        let cached = PS_PER_TICK.load(Ordering::Relaxed);
        if cached != 0 {
            return cached;
        }
        let base = base();
        let dt_ticks = tsc().saturating_sub(base.tsc0);
        let dt_wall = base.instant0.elapsed();
        // Wait for a long-enough baseline that scheduling noise is <1%.
        if dt_wall < Duration::from_millis(50) || dt_ticks == 0 {
            return 0;
        }
        #[allow(clippy::cast_possible_truncation)]
        let ps = ((dt_wall.as_nanos() * 1000) / u128::from(dt_ticks)) as u64;
        let ps = ps.max(1);
        PS_PER_TICK.store(ps, Ordering::Relaxed);
        ps
    }

    pub(crate) enum EvalTimer {
        Tsc(u64),
        Precise(Instant),
    }

    impl EvalTimer {
        #[inline]
        pub(crate) fn start() -> Self {
            if PS_PER_TICK.load(Ordering::Relaxed) != 0 || ps_per_tick() != 0 {
                EvalTimer::Tsc(tsc())
            } else {
                EvalTimer::Precise(Instant::now())
            }
        }

        #[inline]
        pub(crate) fn elapsed(&self) -> Duration {
            match self {
                EvalTimer::Tsc(t0) => {
                    let dt = tsc().saturating_sub(*t0);
                    let ps = PS_PER_TICK.load(Ordering::Relaxed).max(1);
                    Duration::from_nanos((u128::from(dt) * u128::from(ps) / 1000) as u64)
                }
                EvalTimer::Precise(i0) => i0.elapsed(),
            }
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod eval_clock {
    use std::time::{Duration, Instant};

    pub(crate) enum EvalTimer {
        Precise(Instant),
    }

    impl EvalTimer {
        #[inline]
        pub(crate) fn start() -> Self {
            EvalTimer::Precise(Instant::now())
        }

        #[inline]
        pub(crate) fn elapsed(&self) -> Duration {
            match self {
                EvalTimer::Precise(i0) => i0.elapsed(),
            }
        }
    }
}

pub(crate) use eval_clock::EvalTimer;
