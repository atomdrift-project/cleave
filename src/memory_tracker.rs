//! Memory usage tracking and logging for OOM diagnosis.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//!
//! Provides utilities to track and log memory usage during analysis to help
//! diagnose OOM issues in production, especially during trait-basher runs.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// Global memory statistics tracker
#[derive(Debug)]
pub struct MemoryTracker {
    /// Total bytes allocated for file reads
    total_bytes_read: AtomicU64,
    /// Peak memory usage observed (RSS)
    peak_rss_bytes: AtomicU64,
    /// Number of files processed
    files_processed: AtomicUsize,
    /// Number of large files (>100MB) processed
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

        const LARGE_FILE_THRESHOLD: u64 = 100 * 1024 * 1024; // 100MB
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

            // Log if memory usage is high
            const HIGH_MEMORY_THRESHOLD: u64 = 2 * 1024 * 1024 * 1024; // 2GB
            if current_rss > HIGH_MEMORY_THRESHOLD {
                warn!(
                    current_rss_mb = current_rss / 1024 / 1024,
                    peak_rss_mb = self.peak_rss_bytes.load(Ordering::Relaxed) / 1024 / 1024,
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

        info!(
            elapsed_secs = elapsed.as_secs(),
            files_processed = files,
            large_files = large_files,
            total_read_mb = total_read / 1024 / 1024,
            current_rss_mb = current_rss.map(|r| r / 1024 / 1024),
            peak_rss_mb = peak_rss / 1024 / 1024,
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

/// Get current RSS (Resident Set Size) in bytes
/// Returns None if unable to determine
#[must_use]
pub fn current_rss() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        rss_linux()
    }

    #[cfg(target_os = "macos")]
    {
        rss_macos()
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn rss_linux() -> Option<u64> {
    use std::fs;

    // Read /proc/self/status
    let status = fs::read_to_string("/proc/self/status").ok()?;

    // Find VmRSS line
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            // Format: "VmRSS:      123456 kB"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let kb: u64 = parts[1].parse().ok()?;
                return Some(kb * 1024); // Convert to bytes
            }
        }
    }

    None
}

#[cfg(target_os = "macos")]
fn rss_macos() -> Option<u64> {
    use std::mem;

    // Mach task info structures
    #[repr(C)]
    #[derive(Debug, Copy, Clone)]
    struct time_value_t {
        seconds: i32,
        microseconds: i32,
    }

    #[repr(C)]
    struct mach_task_basic_info {
        virtual_size: u64,
        resident_size: u64,
        resident_size_max: u64,
        user_time: time_value_t,
        system_time: time_value_t,
        policy: i32,
        suspend_count: i32,
    }

    // Mach constants
    const MACH_TASK_BASIC_INFO: i32 = 20;
    const MACH_TASK_BASIC_INFO_COUNT: u32 =
        (mem::size_of::<mach_task_basic_info>() / mem::size_of::<i32>()) as u32;

    // External functions from libSystem
    extern "C" {
        fn mach_task_self() -> u32;
        fn task_info(
            target_task: u32,
            flavor: i32,
            task_info_out: *mut i32,
            task_info_outCnt: *mut u32,
        ) -> i32;
    }

    unsafe {
        let task = mach_task_self();
        let mut info: mach_task_basic_info = mem::zeroed();
        let mut count = MACH_TASK_BASIC_INFO_COUNT;

        let kr = task_info(
            task,
            MACH_TASK_BASIC_INFO,
            &mut info as *mut _ as *mut i32,
            &mut count,
        );

        if kr == 0 {
            Some(info.resident_size)
        } else {
            None
        }
    }
}

/// Log memory usage before processing a file
pub fn log_before_file_processing(file_path: &str, file_size: u64) {
    let current_rss = current_rss();

    info!(
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

/// Log memory usage after processing a file
pub fn log_after_file_processing(file_path: &str, file_size: u64, duration: Duration) {
    let current_rss = current_rss();

    info!(
        file_path = file_path,
        file_size_mb = file_size / 1024 / 1024,
        duration_ms = duration.as_millis(),
        current_rss_mb = current_rss.map(|r| r / 1024 / 1024),
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

/// Start a periodic memory logging task.
/// Returns a handle that can be used to stop the thread gracefully.
///
/// This enhanced version also logs:
/// - Orphaned analysis thread statistics
/// - Rizin subprocess statistics
/// - YARA scanner cache statistics
#[must_use]
pub fn start_periodic_logging(interval: Duration) -> MemoryLoggerHandle {
    let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    let handle = std::thread::spawn(move || {
        let mut iteration = 0u64;

        while !shutdown_clone.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(interval);

            // Check shutdown again after sleep
            if shutdown_clone.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            iteration += 1;

            if let Some(rss) = current_rss() {
                let rss_mb = rss / 1024 / 1024;
                let rss_gb = rss / 1024 / 1024 / 1024;

                info!(
                    rss_mb = rss_mb,
                    rss_gb = rss_gb,
                    iteration = iteration,
                    "Periodic memory check"
                );

                // Warn if memory is very high
                const WARNING_THRESHOLD: u64 = 4 * 1024 * 1024 * 1024; // 4GB
                const CRITICAL_THRESHOLD: u64 = 8 * 1024 * 1024 * 1024; // 8GB

                if rss > CRITICAL_THRESHOLD {
                    tracing::error!(
                        rss_gb = rss_gb,
                        "CRITICAL: Memory usage extremely high - OOM imminent"
                    );
                    // Log all statistics for post-mortem analysis
                    log_all_memory_stats();
                } else if rss > WARNING_THRESHOLD {
                    warn!(rss_gb = rss_gb, "WARNING: High memory usage detected");
                    // Log stats when memory is high for debugging
                    log_all_memory_stats();
                }

                // Log full stats every 6 iterations (once per minute at 10s interval)
                // for post-mortem analysis even when memory is normal
                if iteration.is_multiple_of(6) {
                    log_all_memory_stats();
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
pub(crate) fn log_all_memory_stats() {
    // Log current RSS
    if let Some(rss) = current_rss() {
        info!(
            rss_mb = rss / 1024 / 1024,
            rss_gb = rss / 1024 / 1024 / 1024,
            "Memory stats snapshot - RSS"
        );
    }

    // Log archive analysis statistics
    crate::analyzers::archive::analyzers::log_archive_analysis_stats();

    // Log rizin subprocess statistics
    crate::radare2::log_rizin_stats();

    // Note: Scanner cache stats are thread-local and can't be easily aggregated,
    // but they are logged when evictions occur.
}

/// Create a global memory tracker instance
pub fn global_tracker() -> &'static MemoryTracker {
    use std::sync::OnceLock;
    static TRACKER: OnceLock<MemoryTracker> = OnceLock::new();
    TRACKER.get_or_init(MemoryTracker::new)
}

#[cfg(test)]
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
