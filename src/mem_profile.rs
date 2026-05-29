//! Phase-tagged heap-growth accounting (feature `memprofile`).
//!
//! Symbol-free, deterministic attribution of *where the live heap grows*
//! during analysis. Instead of profiling allocation call stacks (unreliable
//! on the frame-pointer-stripped tree-sitter/grammar C runtime), this reads
//! jemalloc's per-thread `thread.allocated` / `thread.deallocated` counters at
//! phase boundaries and charges the net delta to the phase that was active.
//!
//! - **net_live**: bytes allocated minus freed while a phase was active,
//!   summed across all worker threads. A phase with a large positive total is
//!   where live memory accumulates (the thing that drives peak RSS). The sum
//!   over all phases tracks jemalloc's total `allocated`.
//! - **gross_alloc**: bytes allocated while a phase was active — allocation
//!   *churn*, regardless of whether it was freed again.
//!
//! There is no custom global allocator and no per-allocation overhead: each
//! [`phase`] boundary is two pointer reads and a couple of atomic adds. When
//! the `memprofile` feature is off, [`phase`] is a no-op returning a
//! zero-sized guard and [`report`] does nothing.

/// Coarse analysis stages worth attributing heap growth to. Kept deliberately
/// few — the question we need answered is "extraction vs per-member analysis
/// vs aggregation", not a fine call-stack breakdown.
#[derive(Debug, Clone, Copy)]
pub enum Phase {
    /// Anything outside an explicitly-marked region.
    Other,
    /// Archive member decompression / reading bytes into memory.
    Extract,
    /// Per-member analysis (parse, YARA, finding evaluation).
    Analyze,
    /// Report aggregation / finalization across members.
    Aggregate,
}

#[cfg_attr(not(feature = "memprofile"), allow(dead_code))]
impl Phase {
    const COUNT: usize = 4;
    const NAMES: [&'static str; Self::COUNT] = ["other", "extract", "analyze", "aggregate"];
}

#[cfg(feature = "memprofile")]
pub use imp::{PhaseGuard, phase, report, start_sampler};

#[cfg(feature = "memprofile")]
mod imp {
    use super::Phase;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicI64, Ordering};
    use tikv_jemalloc_ctl::thread::{ThreadLocal, allocatedp, deallocatedp};

    static NET_LIVE: [AtomicI64; Phase::COUNT] = [const { AtomicI64::new(0) }; Phase::COUNT];
    static GROSS_ALLOC: [AtomicI64; Phase::COUNT] = [const { AtomicI64::new(0) }; Phase::COUNT];

    /// Running net live heap across all phases (relative to the first
    /// checkpoint, so it excludes the rule/trait engine loaded at startup) and
    /// its high-water mark — the peak *transient* growth driven by analysis.
    static CURRENT_NET: AtomicI64 = AtomicI64::new(0);
    static PEAK_NET: AtomicI64 = AtomicI64::new(0);

    /// High-water marks sampled on a wall-clock timer (captures intra-phase
    /// spikes that checkpoint-based [`CURRENT_NET`] misses): jemalloc's total
    /// live `allocated` and OS `resident`.
    static PEAK_ALLOC: AtomicI64 = AtomicI64::new(0);
    static PEAK_RESIDENT: AtomicI64 = AtomicI64::new(0);

    /// Per-thread accounting state. `alloc`/`dealloc` are cached pointers into
    /// jemalloc's per-thread counters — reading them is a plain load.
    struct Ctx {
        phase: Phase,
        last_alloc: u64,
        last_dealloc: u64,
        alloc: ThreadLocal<u64>,
        dealloc: ThreadLocal<u64>,
    }

    thread_local! {
        static CTX: RefCell<Option<Ctx>> = const { RefCell::new(None) };
    }

    /// Charge the allocation delta since the last checkpoint to `ctx.phase`,
    /// then reset the checkpoint to "now". Called on every phase transition.
    fn checkpoint(ctx: &mut Ctx) {
        let a = ctx.alloc.get();
        let d = ctx.dealloc.get();
        let da = a.wrapping_sub(ctx.last_alloc) as i64;
        let dd = d.wrapping_sub(ctx.last_dealloc) as i64;
        let idx = ctx.phase as usize;
        let delta = da - dd;
        NET_LIVE[idx].fetch_add(delta, Ordering::Relaxed);
        GROSS_ALLOC[idx].fetch_add(da, Ordering::Relaxed);
        let cur = CURRENT_NET.fetch_add(delta, Ordering::Relaxed) + delta;
        PEAK_NET.fetch_max(cur, Ordering::Relaxed);
        ctx.last_alloc = a;
        ctx.last_dealloc = d;
    }

    fn with_ctx<R>(f: impl FnOnce(&mut Ctx) -> R) -> Option<R> {
        CTX.with(|cell| {
            let mut slot = cell.borrow_mut();
            if slot.is_none() {
                let alloc = allocatedp::mib().ok()?.read().ok()?;
                let dealloc = deallocatedp::mib().ok()?.read().ok()?;
                *slot = Some(Ctx {
                    phase: Phase::Other,
                    last_alloc: alloc.get(),
                    last_dealloc: dealloc.get(),
                    alloc,
                    dealloc,
                });
            }
            slot.as_mut().map(f)
        })
    }

    /// Restores the previous phase when dropped.
    #[derive(Debug)]
    pub struct PhaseGuard {
        prev: Phase,
    }

    /// Enter `p` for the lifetime of the returned guard. Heap growth between
    /// here and the guard's drop is charged to `p`; nested phases correctly
    /// re-charge their own windows.
    #[must_use]
    pub fn phase(p: Phase) -> PhaseGuard {
        let prev = with_ctx(|ctx| {
            checkpoint(ctx);
            let prev = ctx.phase;
            ctx.phase = p;
            prev
        })
        .unwrap_or(Phase::Other);
        PhaseGuard { prev }
    }

    impl Drop for PhaseGuard {
        fn drop(&mut self) {
            with_ctx(|ctx| {
                checkpoint(ctx);
                ctx.phase = self.prev;
            });
        }
    }

    /// Spawn a wall-clock sampler that records peak jemalloc `allocated` and
    /// `resident`. Captures the true transient high-water that the
    /// checkpoint-based per-phase net misses. Call once at scan start.
    pub fn start_sampler() {
        use tikv_jemalloc_ctl::{epoch, stats};
        let _ = std::thread::Builder::new()
            .name("memprofile-sampler".into())
            .spawn(|| {
                let (Ok(e), Ok(alloc), Ok(res)) = (
                    epoch::mib(),
                    stats::allocated::mib(),
                    stats::resident::mib(),
                ) else {
                    return;
                };
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    let _ = e.advance();
                    if let Ok(a) = alloc.read() {
                        PEAK_ALLOC.fetch_max(a as i64, Ordering::Relaxed);
                    }
                    if let Ok(r) = res.read() {
                        PEAK_RESIDENT.fetch_max(r as i64, Ordering::Relaxed);
                    }
                }
            });
    }

    /// Log the per-phase net-live and gross-allocation totals. Call once at the
    /// end of a scan.
    pub fn report() {
        let mut total_net = 0_i64;
        for i in 0..Phase::COUNT {
            let net = NET_LIVE[i].load(Ordering::Relaxed);
            let gross = GROSS_ALLOC[i].load(Ordering::Relaxed);
            total_net += net;
            tracing::info!(
                phase = Phase::NAMES[i],
                net_live_mb = net / (1024 * 1024),
                gross_alloc_mb = gross / (1024 * 1024),
                "memprofile phase totals"
            );
        }
        tracing::info!(
            total_net_live_mb = total_net / (1024 * 1024),
            peak_net_live_mb = PEAK_NET.load(Ordering::Relaxed) / (1024 * 1024),
            peak_jemalloc_allocated_mb = PEAK_ALLOC.load(Ordering::Relaxed) / (1024 * 1024),
            peak_jemalloc_resident_mb = PEAK_RESIDENT.load(Ordering::Relaxed) / (1024 * 1024),
            "memprofile totals (net excludes startup rule engine)"
        );
    }
}

#[cfg(not(feature = "memprofile"))]
pub use noop::{PhaseGuard, phase, report, start_sampler};

#[cfg(not(feature = "memprofile"))]
mod noop {
    use super::Phase;

    /// Zero-sized no-op guard when `memprofile` is disabled.
    #[derive(Debug)]
    pub struct PhaseGuard;

    /// No-op phase marker when `memprofile` is disabled.
    #[inline]
    #[must_use]
    pub fn phase(_p: Phase) -> PhaseGuard {
        PhaseGuard
    }

    /// No-op when `memprofile` is disabled.
    #[inline]
    pub fn start_sampler() {}

    /// No-op when `memprofile` is disabled.
    #[inline]
    pub fn report() {}
}
