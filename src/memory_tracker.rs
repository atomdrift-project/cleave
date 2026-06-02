//! Memory usage tracking and logging for OOM diagnosis.
//!
//! Provides utilities to track and log memory usage during analysis to help
//! diagnose OOM issues in production, especially during trait-basher runs.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// Global tracker for the currently-running analysis phase.
///
/// Set this before slow operations (rizin, stng, YARA) so the periodic
/// memory-check log line can tell you exactly what cleave is doing instead
/// of silently incrementing a counter.
static CURRENT_PHASE: parking_lot::Mutex<Option<String>> = parking_lot::const_mutex(None);

/// Record what the current analysis phase is (e.g. "rizin: aa; aflj on foo.exe").
/// The string is included in every subsequent periodic memory-check log line.
pub(crate) fn set_current_phase(phase: impl Into<String>) {
    *CURRENT_PHASE.lock() = Some(phase.into());
}

/// Clear the current phase (call when the slow operation finishes).
pub(crate) fn clear_current_phase() {
    *CURRENT_PHASE.lock() = None;
}

fn current_phase_snapshot() -> Option<String> {
    CURRENT_PHASE.lock().clone()
}

/// Global memory statistics tracker
#[derive(Debug)]
pub struct MemoryTracker {
    /// Total bytes allocated for file reads
    total_bytes_read: AtomicU64,
    /// Peak memory usage observed (RSS)
    peak_rss_bytes: AtomicU64,
    /// Number of files processed
    files_processed: AtomicUsize,
    /// Number of large files (>250MB) processed
    large_files_processed: AtomicUsize,
    /// Start time
    start_time: Instant,
    /// Last log time
    last_log: parking_lot::Mutex<Instant>,
}

impl Default for MemoryTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryTracker {
    /// Create a new memory tracker
    #[must_use]
    pub fn new() -> Self {
        Self {
            total_bytes_read: AtomicU64::new(0),
            peak_rss_bytes: AtomicU64::new(0),
            files_processed: AtomicUsize::new(0),
            large_files_processed: AtomicUsize::new(0),
            start_time: Instant::now(),
            last_log: parking_lot::Mutex::new(Instant::now()),
        }
    }

    /// Record a file being read into memory
    pub fn record_file_read(&self, bytes: u64, file_path: &str) {
        self.total_bytes_read.fetch_add(bytes, Ordering::Relaxed);
        self.files_processed.fetch_add(1, Ordering::Relaxed);

        const LARGE_FILE_THRESHOLD: u64 = 250 * 1024 * 1024; // 250MB
        if bytes > LARGE_FILE_THRESHOLD {
            self.large_files_processed.fetch_add(1, Ordering::Relaxed);
            warn!(
                file_path = file_path,
                size_mb = bytes / 1024 / 1024,
                "Processing large file"
            );
        }

        // Update peak memory usage atomically
        if let Some(current_rss) = current_rss() {
            self.peak_rss_bytes
                .fetch_max(current_rss, Ordering::Relaxed);

            if current_rss > sysmem::warning_threshold() {
                warn!(
                    current_rss_mb = current_rss / 1024 / 1024,
                    peak_rss_mb = self.peak_rss_bytes.load(Ordering::Relaxed) / 1024 / 1024,
                    limit_mb = sysmem::memory_limit() / 1024 / 1024,
                    file_path = file_path,
                    file_size_mb = bytes / 1024 / 1024,
                    "High memory usage detected"
                );
            }
        }

        // Periodic logging (every 10 seconds)
        let should_log = {
            let mut last_log = self.last_log.lock();
            if last_log.elapsed() > Duration::from_secs(10) {
                *last_log = Instant::now();
                true
            } else {
                false
            }
        };

        if should_log {
            self.log_stats();
        }
    }

    /// Log current memory statistics
    pub fn log_stats(&self) {
        let current_rss = current_rss();
        let peak_rss = self.peak_rss_bytes.load(Ordering::Relaxed);
        let total_read = self.total_bytes_read.load(Ordering::Relaxed);
        let files = self.files_processed.load(Ordering::Relaxed);
        let large_files = self.large_files_processed.load(Ordering::Relaxed);
        let elapsed = self.start_time.elapsed();

        let jemalloc = jemalloc_stats();
        info!(
            elapsed_secs = elapsed.as_secs(),
            files_processed = files,
            large_files = large_files,
            total_read_mb = total_read / 1024 / 1024,
            current_rss_mb = current_rss.map(|r| r / 1024 / 1024),
            peak_rss_mb = peak_rss / 1024 / 1024,
            jemalloc_allocated_mb = jemalloc.as_ref().map(|s| s.allocated / 1024 / 1024),
            jemalloc_active_mb = jemalloc.as_ref().map(|s| s.active / 1024 / 1024),
            jemalloc_resident_mb = jemalloc.as_ref().map(|s| s.resident / 1024 / 1024),
            avg_file_size_mb = if files > 0 {
                (total_read / files as u64) / 1024 / 1024
            } else {
                0
            },
            "Memory usage statistics"
        );
    }

    /// Get total bytes read
    pub fn total_bytes_read(&self) -> u64 {
        self.total_bytes_read.load(Ordering::Relaxed)
    }

    /// Get peak RSS
    pub fn peak_rss(&self) -> u64 {
        self.peak_rss_bytes.load(Ordering::Relaxed)
    }

    /// Get files processed count
    pub fn files_processed(&self) -> usize {
        self.files_processed.load(Ordering::Relaxed)
    }
}

/// Get current RSS (Resident Set Size) in bytes.
///
/// Delegates to the `sysmem` crate for cross-platform support.
#[must_use]
pub fn current_rss() -> Option<u64> {
    sysmem::current_rss()
}

/// Total physical memory in bytes, or `None` on unsupported platforms.
///
/// Delegates to the `sysmem` crate for cross-platform support
/// (Linux, macOS, FreeBSD, OpenBSD, NetBSD, Windows).
#[must_use]
pub fn total_memory() -> Option<u64> {
    sysmem::total_memory()
}

/// Number of CPUs available to this process, or `None` if undetectable.
///
/// Delegates to the `sysmem` crate, which handles illumos/Solaris where
/// `std::thread::available_parallelism` is unsupported and would otherwise
/// drive a silent thread-pool downgrade on many-core hosts.
#[must_use]
pub fn cpu_count() -> Option<usize> {
    sysmem::cpu_count()
}

/// Number of *physical* CPU cores (excluding SMT/hyperthread siblings), or
/// `None` where the platform exposes no reliable source.
///
/// Delegates to the `sysmem` crate. cleave's CPU-bound archive workload peaks
/// at the physical-core count, so this is the basis for the default rayon pool
/// size; see [`sysmem::physical_cpu_count`] for the per-platform detection.
#[must_use]
pub fn physical_cpu_count() -> Option<usize> {
    sysmem::physical_cpu_count()
}

/// Memory limit: `min(50% RAM, 32 GiB)`.
///
/// Use this as the default `limit` argument to [`start_periodic_logging`] and
/// as the fallback when no explicit `--max-rss-gb` flag is given.
#[must_use]
pub fn memory_limit() -> u64 {
    sysmem::memory_limit()
}

/// Log memory usage before processing a file
pub fn log_before_file_processing(file_path: &str, file_size: u64) {
    let current_rss = current_rss();

    debug!(
        file_path = file_path,
        file_size_mb = file_size / 1024 / 1024,
        current_rss_mb = current_rss.map(|r| r / 1024 / 1024),
        "Starting file analysis"
    );

    // Warn if file is suspiciously large
    const SUSPICIOUS_SIZE: u64 = 500 * 1024 * 1024; // 500MB
    if file_size > SUSPICIOUS_SIZE {
        warn!(
            file_path = file_path,
            file_size_mb = file_size / 1024 / 1024,
            "File size exceeds typical malware size - possible OOM risk"
        );
    }
}

/// Previous RSS value for delta tracking across files.
static PREV_RSS: AtomicU64 = AtomicU64::new(0);

/// Log memory usage after processing a file, including RSS delta since previous file.
pub fn log_after_file_processing(file_path: &str, file_size: u64, duration: Duration) {
    let current_rss = current_rss();

    let delta_mb = current_rss.map(|rss| {
        let prev = PREV_RSS.swap(rss, Ordering::Relaxed);
        if prev == 0 {
            return 0i64;
        }
        (rss as i64 - prev as i64) / 1024 / 1024
    });

    let jemalloc = jemalloc_stats();

    debug!(
        file_path = file_path,
        file_size_mb = file_size / 1024 / 1024,
        duration_ms = duration.as_millis(),
        current_rss_mb = current_rss.map(|r| r / 1024 / 1024),
        rss_delta_mb = delta_mb,
        jemalloc_allocated_mb = jemalloc.as_ref().map(|s| s.allocated / 1024 / 1024),
        jemalloc_resident_mb = jemalloc.as_ref().map(|s| s.resident / 1024 / 1024),
        "Completed file analysis"
    );
}

/// Handle for controlling a periodic memory logging thread.
/// Call `stop()` or drop to signal the thread to shut down gracefully.
#[derive(Debug)]
pub struct MemoryLoggerHandle {
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl MemoryLoggerHandle {
    /// Signal the logging thread to stop and wait for it to finish.
    pub fn stop(&mut self) {
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for MemoryLoggerHandle {
    fn drop(&mut self) {
        // Signal shutdown but don't block on join (process may be exiting)
        self.shutdown
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Interval between jemalloc purge+report ticks, in seconds.
///
/// Every 5 minutes the watchdog runs `arena.<all>.purge` and reports how many
/// bytes jemalloc returned to the OS. This replaced the older per-tick RSS
/// info log — the purge delta is a more actionable signal (it separates true
/// allocation growth from retained-but-idle pages) and the cadence is long
/// enough that the purge's own CPU cost is negligible.
const PURGE_INTERVAL_SECS: u64 = 300;

/// Start a periodic memory watchdog thread.
/// Returns a handle that can be used to stop the thread gracefully.
///
/// `limit` is the RSS cap in bytes; pass `sysmem::memory_limit()` for the
/// standard `min(50% RAM, 32 GiB)` value, or the server's configured
/// `max_rss_bytes` so the watchdog and the per-request check enforce the
/// same threshold.
///
/// The watchdog monitors RSS every `interval` and:
/// 1. Warning threshold crossed → log warning + full memory stats
/// 2. Critical threshold crossed → attempt cache clear, log error + full stats
/// 3. Critical threshold sustained for >30s → `process::exit(1)`
/// 4. Every 5 minutes (`PURGE_INTERVAL_SECS`) → run jemalloc arena purge,
///    log RSS before/after and the reclaimed delta.
///
/// This is the primary enforcement mechanism. The per-request check in
/// `server::handlers::check_memory_pressure` provides early 503 rejection,
/// but this thread is the backstop that ticks on wall clock regardless of
/// request traffic or in-flight analysis blocking.
#[must_use]
pub fn start_periodic_logging(interval: Duration, limit: u64) -> MemoryLoggerHandle {
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    let handle = std::thread::spawn(move || {
        let mut overloaded_since: Option<Instant> = None;
        let mut last_purge = Instant::now();
        let warning = limit.saturating_sub(512 * 1024 * 1024);
        let purge_interval = Duration::from_secs(PURGE_INTERVAL_SECS);

        while !shutdown_clone.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(interval);

            if shutdown_clone.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            let Some(rss) = current_rss() else {
                continue;
            };

            let rss_mb = rss / 1024 / 1024;

            if rss > limit {
                // Try to reclaim memory before escalating
                crate::clear_all_thread_caches();

                // Re-check after cache clear
                let rss_after = current_rss().unwrap_or(rss);
                let rss_after_mb = rss_after / 1024 / 1024;

                if rss_after <= limit {
                    info!(
                        rss_before_mb = rss_mb,
                        rss_after_mb = rss_after_mb,
                        "Cache clear brought memory below cap"
                    );
                    overloaded_since = None;
                    continue;
                }

                // Still over cap — track duration
                let since = *overloaded_since.get_or_insert_with(Instant::now);
                let overloaded_secs = since.elapsed().as_secs();

                tracing::error!(
                    rss_mb = rss_after_mb,
                    limit_mb = limit / 1024 / 1024,
                    overloaded_secs = overloaded_secs,
                    "CRITICAL: Memory usage exceeds cap"
                );
                log_all_memory_stats();

                if overloaded_secs > 30 {
                    tracing::error!(
                        rss_mb = rss_after_mb,
                        limit_mb = limit / 1024 / 1024,
                        overloaded_secs = overloaded_secs,
                        "Memory cap exceeded for >30s, terminating to avoid OOM kill"
                    );
                    std::process::exit(1);
                }
            } else if rss > warning {
                // Below cap but approaching it — log but don't enforce
                overloaded_since = None;
                warn!(
                    rss_mb = rss_mb,
                    limit_mb = limit / 1024 / 1024,
                    headroom_mb = (limit - rss) / 1024 / 1024,
                    "WARNING: Memory approaching cap"
                );
                log_all_memory_stats();
            } else {
                // Healthy — reset overload timer
                overloaded_since = None;
            }

            // Periodic jemalloc purge + report. Runs on wall clock regardless
            // of RSS state so operators always have a recent baseline.
            if last_purge.elapsed() >= purge_interval {
                last_purge = Instant::now();
                let phase = current_phase_snapshot();
                match purge_jemalloc() {
                    Some(stats) => info!(
                        rss_mb = rss_mb,
                        resident_before_mb = stats.resident_before / 1024 / 1024,
                        resident_after_mb = stats.resident_after / 1024 / 1024,
                        reclaimed_mb = stats.reclaimed / 1024 / 1024,
                        current_op = phase.as_deref().unwrap_or("idle"),
                        "jemalloc purge"
                    ),
                    None => info!(
                        rss_mb = rss_mb,
                        current_op = phase.as_deref().unwrap_or("idle"),
                        "periodic memory check (jemalloc not active; purge skipped)"
                    ),
                }
            }
        }
    });

    MemoryLoggerHandle {
        shutdown,
        handle: Some(handle),
    }
}

/// Log all memory-related statistics for post-mortem analysis.
/// This consolidates stats from various subsystems that can cause memory issues.
/// Mirrors the detail level of the `/_/memory` server endpoint.
pub fn log_all_memory_stats() {
    // Log current RSS
    if let Some(rss) = current_rss() {
        info!(
            rss_mb = rss / 1024 / 1024,
            rss_gb = rss / 1024 / 1024 / 1024,
            "Memory stats snapshot - RSS"
        );
    }

    // Jemalloc allocator breakdown — the most useful OOM diagnostic.
    // allocated vs RSS gap reveals whether memory is in jemalloc or elsewhere (mmap, YARA, etc.)
    if let Some(s) = jemalloc_stats() {
        info!(
            allocated_mb = s.allocated / 1024 / 1024,
            active_mb = s.active / 1024 / 1024,
            metadata_mb = s.metadata / 1024 / 1024,
            resident_mb = s.resident / 1024 / 1024,
            retained_mb = s.retained / 1024 / 1024,
            fragmentation_mb = s.active.saturating_sub(s.allocated) / 1024 / 1024,
            "Memory stats snapshot - jemalloc"
        );
    }

    // Bytes regex cache
    {
        let cache = crate::composite_rules::evaluators::bytes_regex_cache().read();
        info!(
            entries = cache.len(),
            max = cache.cap().get(),
            "Memory stats snapshot - bytes regex cache"
        );
    }

    // Capability mapper
    if let Some((traits, composites)) = crate::shared_resources::capability_mapper_stats() {
        info!(
            traits = traits,
            composites = composites,
            "Memory stats snapshot - capability mapper"
        );
    }

    // Thread pools
    info!(
        rayon_threads = rayon::current_num_threads(),
        "Memory stats snapshot - thread pools"
    );

    // Log archive analysis statistics
    crate::analyzers::archive::analyzers::log_archive_analysis_stats();

    // Log rizin subprocess statistics
    filefacts::rizin::log_stats();
}

/// Jemalloc allocator statistics — only available when compiled with `--features jemalloc`.
///
/// Key diagnostic ratios:
/// - `active - allocated` large → internal fragmentation (free holes jemalloc can't merge)
/// - `resident - active` large  → page-level fragmentation
/// - `rss - resident` large     → non-jemalloc memory (mmap'd files, stack, code segments)
#[derive(Debug)]
pub struct JemallocStats {
    /// Bytes currently live — actual in-use objects. The most useful leak indicator.
    pub allocated: u64,
    /// Bytes in active pages: `allocated` rounded up to page boundaries.
    pub active: u64,
    /// Bytes used by jemalloc's own internal bookkeeping structures.
    pub metadata: u64,
    /// Bytes in physically-resident pages — jemalloc's view of RSS.
    pub resident: u64,
    /// Virtual pages held by jemalloc but not currently resident (returned to OS lazily).
    pub retained: u64,
}

/// Query current jemalloc allocator stats. Returns `None` when jemalloc is not the allocator.
///
/// Advances the jemalloc epoch first so the returned values are fresh.
#[must_use]
pub fn jemalloc_stats() -> Option<JemallocStats> {
    #[cfg(all(
        unix,
        feature = "jemalloc",
        not(any(target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))
    ))]
    {
        use tikv_jemalloc_ctl::{epoch, stats};

        // Advance the epoch to refresh cached stats
        epoch::mib().ok()?.advance().ok()?;

        Some(JemallocStats {
            allocated: stats::allocated::mib().ok()?.read().ok()? as u64,
            active: stats::active::mib().ok()?.read().ok()? as u64,
            metadata: stats::metadata::mib().ok()?.read().ok()? as u64,
            resident: stats::resident::mib().ok()?.read().ok()? as u64,
            retained: stats::retained::mib().ok()?.read().ok()? as u64,
        })
    }

    #[cfg(not(all(
        unix,
        feature = "jemalloc",
        not(any(target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))
    )))]
    None
}

/// Result of a jemalloc arena purge: RSS before/after and the delta that
/// jemalloc returned to the OS. Populated only when jemalloc is the allocator.
#[derive(Debug, Clone, Copy)]
pub struct JemallocPurgeStats {
    /// Resident bytes reported by jemalloc before the purge ran.
    pub resident_before: u64,
    /// Resident bytes reported by jemalloc after the purge completed.
    pub resident_after: u64,
    /// `resident_before - resident_after`: bytes returned to the OS.
    pub reclaimed: u64,
}

/// Force jemalloc to decay and purge dirty pages across all arenas.
///
/// On long-lived servers jemalloc tends to retain dirty pages in the
/// "free-but-still-committed" state between bursts of work; `dirty_decay_ms=0`
/// biases it to return pages fast, but decay is only driven by allocation
/// activity, so a quiet period between bursts leaves pages resident. Calling
/// `arena.<all>.purge` on a wall-clock timer keeps RSS honest.
///
/// Returns `None` when jemalloc is not the active allocator (macOS, FreeBSD,
/// DragonFly, OpenBSD, or the `jemalloc` feature disabled).
#[must_use]
pub fn purge_jemalloc() -> Option<JemallocPurgeStats> {
    #[cfg(all(
        unix,
        feature = "jemalloc",
        not(any(target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))
    ))]
    {
        // MALLCTL_ARENAS_ALL is jemalloc's sentinel for "all arenas"; stable at
        // 4096 across jemalloc 5.x (what tikv-jemalloc-sys wraps).
        const MALLCTL_ARENAS_ALL: usize = 4096;

        let before = jemalloc_stats()?.resident;

        // `arena.<i>.purge` is a write-only command; `()` makes newlen=0 which
        // jemalloc treats as a pure trigger. Errors are logged but not fatal —
        // purge is a best-effort hygiene op, not correctness.
        // SAFETY: mallctl is thread-safe; the key is a valid null-terminated string.
        let purge_res = unsafe {
            tikv_jemalloc_ctl::raw::write(
                format!("arena.{MALLCTL_ARENAS_ALL}.purge\0").as_bytes(),
                (),
            )
        };
        if let Err(e) = purge_res {
            warn!(error = ?e, "jemalloc purge failed");
            return None;
        }

        let after = jemalloc_stats()?.resident;
        Some(JemallocPurgeStats {
            resident_before: before,
            resident_after: after,
            reclaimed: before.saturating_sub(after),
        })
    }

    #[cfg(not(all(
        unix,
        feature = "jemalloc",
        not(any(target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))
    )))]
    None
}

/// Configure jemalloc for aggressive page return to the OS.
///
/// Sets `dirty_decay_ms` and `muzzy_decay_ms` to 0, forcing jemalloc to immediately
/// return freed pages instead of holding them for reuse. This trades ~1-2% CPU for
/// dramatically lower RSS in long-running processes (server mode) where the
/// allocate-free cycle across thousands of analyses causes multi-GB fragmentation.
///
/// No-op when jemalloc is not the allocator.
pub fn configure_jemalloc_low_memory() {
    #[cfg(all(
        unix,
        feature = "jemalloc",
        not(any(target_os = "freebsd", target_os = "dragonfly", target_os = "openbsd"))
    ))]
    {
        // tikv-jemalloc-ctl 0.6 doesn't filefacts dirty_decay_ms/muzzy_decay_ms
        // as typed helpers, so use the raw mallctl interface.
        // SAFETY: ssize_t (isize) is the correct type for these settings per jemalloc docs.
        unsafe {
            let dirty = tikv_jemalloc_ctl::raw::write(b"arenas.dirty_decay_ms\0", 0_isize);
            let muzzy = tikv_jemalloc_ctl::raw::write(b"arenas.muzzy_decay_ms\0", 0_isize);
            match (dirty, muzzy) {
                (Ok(()), Ok(())) => {
                    info!(
                        "jemalloc: aggressive page return enabled (dirty_decay_ms=0, muzzy_decay_ms=0)"
                    );
                }
                (d, m) => {
                    warn!("jemalloc: failed to configure decay timers (dirty={d:?}, muzzy={m:?})");
                }
            }
        }
    }
}

/// Log startup diagnostics for OOM debugging.
///
/// Emits PID, system RAM, memory cap/warn thresholds, allocator, and OS
/// in a single structured log line so post-mortem analysis has everything
/// needed to understand the memory environment.
pub fn log_startup_diagnostics() {
    let total_mb = sysmem::total_memory().map(|m| m / 1024 / 1024);
    let limit_mb = sysmem::memory_limit() / 1024 / 1024;
    let warn_mb = sysmem::warning_threshold() / 1024 / 1024;
    let rss_mb = current_rss().map(|r| r / 1024 / 1024);

    let allocator = if cfg!(all(
        unix,
        feature = "jemalloc",
        not(any(
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd"
        ))
    )) {
        "jemalloc"
    } else {
        "system"
    };

    info!(
        pid = std::process::id(),
        version = env!("CARGO_PKG_VERSION"),
        os = std::env::consts::OS,
        arch = std::env::consts::ARCH,
        allocator = allocator,
        system_memory_mb = total_mb,
        memory_cap_mb = limit_mb,
        memory_warn_mb = warn_mb,
        initial_rss_mb = rss_mb,
        rayon_threads = rayon::current_num_threads(),
        "Startup diagnostics"
    );
}

/// Create a global memory tracker instance
pub fn global_tracker() -> &'static MemoryTracker {
    use std::sync::OnceLock;
    static TRACKER: OnceLock<MemoryTracker> = OnceLock::new();
    TRACKER.get_or_init(MemoryTracker::new)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_current_rss() {
        // Should be able to get RSS on supported platforms
        let rss = current_rss();

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            assert!(rss.is_some());
            let rss_bytes = rss.unwrap();
            assert!(rss_bytes > 0);
            println!("Current RSS: {} MB", rss_bytes / 1024 / 1024);
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            assert!(rss.is_none());
        }
    }

    #[test]
    fn test_memory_tracker() {
        let tracker = MemoryTracker::new();

        tracker.record_file_read(1024 * 1024, "test.exe"); // 1MB
        tracker.record_file_read(5 * 1024 * 1024, "test2.exe"); // 5MB

        assert_eq!(tracker.total_bytes_read(), 6 * 1024 * 1024);
        assert_eq!(tracker.files_processed(), 2);

        tracker.log_stats();
    }
}
