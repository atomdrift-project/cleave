//! Env-gated per-trait evaluation-time aggregation.
//!
//! The slow-rule warnings only catch single evaluations over 500 ms, but the
//! cost that dominates archive scans is death-by-repetition: a rule that takes
//! 10 ms and runs against every one of thousands of members. With
//! `CLEAVE_TRAIT_TIMING=1` (or after [`enable`], as `cleave validate
//! --slow-rules` does), every trait evaluation adds its duration here and
//! [`report`] logs the top aggregate consumers at end of scan. Off (the
//! default), [`record`] is a single branch on a cached flag.

use parking_lot::Mutex;
use rustc_hash::FxHashMap;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

/// 0: not decided, 1: off, 2: on.
static STATE: AtomicU8 = AtomicU8::new(0);

fn enabled() -> bool {
    match STATE.load(Ordering::Relaxed) {
        2 => true,
        1 => false,
        _ => {
            let on = crate::env::flag("CLEAVE_TRAIT_TIMING");
            STATE.store(if on { 2 } else { 1 }, Ordering::Relaxed);
            on
        }
    }
}

/// Record every trait evaluation from now on, whatever the environment says.
#[cfg(feature = "lint")]
pub(crate) fn enable() {
    STATE.store(2, Ordering::Relaxed);
}

/// Per trait id: total nanos, evaluation count, slowest single evaluation
/// in nanos.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct Total {
    pub(crate) nanos: u64,
    pub(crate) evals: u64,
    pub(crate) max_nanos: u64,
}

type Times = FxHashMap<String, Total>;
type Shard = Arc<Mutex<Times>>;

#[derive(Default)]
struct Timings {
    shards: Mutex<Vec<Shard>>,
}

impl Timings {
    fn register(&self) -> Shard {
        let shard = Arc::new(Mutex::new(Times::default()));
        self.shards.lock().push(shard.clone());
        shard
    }

    fn totals(&self) -> Times {
        // Retain finished threads' totals, and allow workers to keep recording
        // during a progress report. Never hold the registry while reading a shard.
        let shards = self.shards.lock().clone();
        let mut totals = Times::default();
        for shard in shards {
            for (id, total) in shard.lock().iter() {
                let entry = totals.entry(id.clone()).or_default();
                entry.nanos += total.nanos;
                entry.evals += total.evals;
                entry.max_nanos = entry.max_nanos.max(total.max_nanos);
            }
        }
        totals
    }
}

static TIMES: OnceLock<Timings> = OnceLock::new();
thread_local! {
    // The hot path only locks this thread's map. The registry lock is taken
    // once per thread, instead of making every trait evaluation contend.
    static LOCAL_TIMES: Shard = TIMES.get_or_init(Timings::default).register();
}

fn add(map: &mut Times, trait_id: &str, duration: Duration) {
    let nanos = duration.as_nanos() as u64;
    if let Some(entry) = map.get_mut(trait_id) {
        entry.nanos += nanos;
        entry.evals += 1;
        entry.max_nanos = entry.max_nanos.max(nanos);
    } else {
        map.insert(
            trait_id.to_owned(),
            Total {
                nanos,
                evals: 1,
                max_nanos: nanos,
            },
        );
    }
}

/// Add one evaluation's duration for `trait_id`. No-op unless
/// `CLEAVE_TRAIT_TIMING=1`.
pub(crate) fn record(trait_id: &str, duration: Duration) {
    if enabled() {
        LOCAL_TIMES.with(|shard| add(&mut shard.lock(), trait_id, duration));
    }
}

/// Records the time from its creation to its drop for one rule, whichever
/// way the evaluation returns. Reads no clock while timing is off.
pub(crate) struct Recorder<'a> {
    id: &'a str,
    started: Option<std::time::Instant>,
}

impl<'a> Recorder<'a> {
    pub(crate) fn start(id: &'a str) -> Self {
        Self {
            id,
            started: enabled().then(std::time::Instant::now),
        }
    }
}

impl Drop for Recorder<'_> {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            record(self.id, started.elapsed());
        }
    }
}

/// Every recorded trait with its totals, slowest aggregate first. Empty when
/// disabled or nothing was recorded.
pub(crate) fn totals() -> Vec<(String, Total)> {
    let Some(times) = TIMES.get() else {
        return Vec::new();
    };
    let mut rows: Vec<_> = times.totals().into_iter().collect();
    rows.sort_by(|(a_id, a), (b_id, b)| b.nanos.cmp(&a.nanos).then_with(|| a_id.cmp(b_id)));
    rows
}

/// Log the top-`n` traits by aggregate evaluation time. No-op when disabled or
/// nothing was recorded.
pub(crate) fn report(n: usize) {
    for (id, total) in totals().into_iter().take(n) {
        tracing::info!(
            trait_id = %id,
            total_ms = total.nanos / 1_000_000,
            evals = total.evals,
            max_ms = total.max_nanos / 1_000_000,
            "trait time aggregate"
        );
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn trait_timing_combines_live_and_finished_threads() {
    let times = Arc::new(Timings::default());
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let times = times.clone();
            std::thread::spawn(move || {
                let shard = times.register();
                for _ in 0..1000 {
                    add(&mut shard.lock(), "shared", Duration::from_nanos(7));
                }
            })
        })
        .collect();
    // Reporting while workers run must not consume or lose their counts.
    let _ = times.totals();
    for thread in threads {
        thread.join().unwrap();
    }
    let expected = Total {
        nanos: 28_000,
        evals: 4_000,
        max_nanos: 7,
    };
    assert_eq!(times.totals()["shared"], expected);
    assert_eq!(times.totals()["shared"], expected);
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
