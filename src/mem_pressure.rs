//! Live host-memory pressure gate for archive member fan-out.
//!
//! `scan_mem_gate` admits *top-level* files against a reservation budget, and
//! the worker's admission gate does the same per job — but neither sees the
//! parallel member walk inside one archive. On the generic disk-walk path
//! nothing bounds how many members analyze at once: a tarball of a dozen
//! bundled binaries and JS bundles fans every member across the rayon pool,
//! and each member can hold hundreds of MB of transient analysis state. On a
//! host that is already near its limit that fan-out is what tips it into
//! swap or the OOM killer.
//!
//! This gate does not estimate anything. It reads what the kernel reports as
//! available physical memory and, while that sits below a floor, the member
//! walk runs its next chunk serially instead of fanning out — the peak stops
//! climbing. The moment memory frees the walk goes parallel again. Sampling is throttled so a 100k-member archive does not
//! pay a syscall per member. Hosts without a live signal (`available_memory`
//! is `None`) are never throttled: a gate that guesses is worse than none.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// How long one `available_memory` reading stays authoritative.
const SAMPLE_TTL: Duration = Duration::from_millis(100);

/// Below this much available host memory, member analysis serializes.
/// Default: 10% of RAM, at least 1 GiB. `CLEAVE_MEMBER_PRESSURE_FLOOR_MB`
/// overrides (0 disables the gate).
fn floor_bytes() -> u64 {
    static FLOOR: OnceLock<u64> = OnceLock::new();
    *FLOOR.get_or_init(|| {
        if let Some(mb) = std::env::var("CLEAVE_MEMBER_PRESSURE_FLOOR_MB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            return mb.saturating_mul(MIB);
        }
        let total = crate::memory_tracker::total_memory().unwrap_or(16 * GIB);
        (total / 10).max(GIB)
    })
}

/// Process start reference for the sample timestamp.
fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

static LAST_SAMPLE_MS: AtomicU64 = AtomicU64::new(u64::MAX);
static PRESSURED: AtomicBool = AtomicBool::new(false);
static EPISODE_LOGGED: AtomicBool = AtomicBool::new(false);

/// Latest pressure verdict, refreshing the sample when the TTL has lapsed.
pub(crate) fn under_pressure() -> bool {
    let floor = floor_bytes();
    if floor == 0 {
        return false;
    }
    let now_ms = u64::try_from(epoch().elapsed().as_millis()).unwrap_or(u64::MAX);
    let last = LAST_SAMPLE_MS.load(Ordering::Relaxed);
    if last != u64::MAX && now_ms.saturating_sub(last) < SAMPLE_TTL.as_millis() as u64 {
        return PRESSURED.load(Ordering::Relaxed);
    }
    // Several threads may resample at once; the reading is idempotent so a
    // duplicate syscall costs nothing but the syscall.
    LAST_SAMPLE_MS.store(now_ms, Ordering::Relaxed);
    let Some(available) = crate::memory_tracker::available_memory() else {
        PRESSURED.store(false, Ordering::Relaxed);
        return false;
    };
    let pressured = available < floor;
    PRESSURED.store(pressured, Ordering::Relaxed);
    if pressured {
        if !EPISODE_LOGGED.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                available_mb = available / MIB,
                floor_mb = floor / MIB,
                "host memory below pressure floor: archive member analysis \
                 serialized until memory frees"
            );
        }
    } else if EPISODE_LOGGED.swap(false, Ordering::Relaxed) {
        tracing::info!(
            available_mb = available / MIB,
            floor_mb = floor / MIB,
            "host memory back above pressure floor: member analysis parallel again"
        );
    }
    pressured
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdict_is_stable_within_ttl() {
        let first = under_pressure();
        assert_eq!(under_pressure(), first);
    }

    #[test]
    fn floor_has_a_sane_default() {
        let floor = floor_bytes();
        assert!(floor == 0 || floor >= GIB);
    }
}
