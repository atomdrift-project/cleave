//! Radare2/rizin integration for binary analysis.
//!
//! This module provides deep binary analysis using radare2/rizin, including:
//! - Function extraction with control flow metrics
//! - String extraction
//! - Symbol/import/export analysis
//! - Syscall detection
//! - Section analysis with entropy calculation
//! - Batched analysis for performance
//!
//! # Architecture
//! - `models`: Data structures for R2 output and conversions
//! - `parsing`: Parsing utilities for disassembly and search results
//! - `cache`: Filesystem caching with zstd compression
//!
//! # Performance Optimizations
//! - Single r2 session for batched analysis (extract_batched)
//! - Zstd-compressed caching by file SHA256
//! - Skip expensive analysis for large binaries (>20MB)
//! - Architecture-aware syscall detection
//!
//! # Memory Safety
//!
//! All rizin subprocess calls now have timeouts to prevent hung processes
//! from accumulating and causing memory exhaustion.

mod cache;
mod models;
mod parsing;

// Re-export public types from models
pub(crate) use models::{R2Export, R2Function, R2Import, R2Section, R2String, R2Symbol};

#[cfg(test)]
use crate::types::binary::SyscallInfo;
use crate::types::BinaryMetrics;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use tracing::{debug, trace, warn};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Default timeout for rizin subprocess execution (900 seconds / 15 minutes).
/// This prevents hung processes from accumulating during archive analysis.
const RIZIN_DEFAULT_TIMEOUT_SECS: u64 = 1200;

/// Global disable counter for radare2 analysis.
///
/// A positive value means radare2 is disabled. This supports both permanent
/// process-wide disables and scoped guards used by library calls.
static RADARE2_DISABLED: AtomicUsize = AtomicUsize::new(0);

/// Cached result of radare2 availability check (avoids subprocess per file)
static RADARE2_AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Statistics for rizin subprocess execution
static RIZIN_TOTAL_CALLS: AtomicU64 = AtomicU64::new(0);
static RIZIN_TIMEOUTS: AtomicU64 = AtomicU64::new(0);
static RIZIN_FAILURES: AtomicU64 = AtomicU64::new(0);
static RIZIN_SUCCESSES: AtomicU64 = AtomicU64::new(0);

/// Disable radare2 analysis globally
#[allow(dead_code)] // Used by the CLI binary target for process-wide disables
pub(crate) fn disable_radare2() {
    RADARE2_DISABLED.fetch_add(1, Ordering::SeqCst);
}

/// Guard that disables radare2 for the lifetime of the value.
#[allow(dead_code)] // Used by the library target; the binary recompiles modules separately
pub(crate) struct ScopedRadare2Disable;

impl Drop for ScopedRadare2Disable {
    fn drop(&mut self) {
        RADARE2_DISABLED.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Disable radare2 for the lifetime of the returned guard.
#[allow(dead_code)] // Used by the library target; the binary recompiles modules separately
pub(crate) fn scoped_disable_radare2() -> ScopedRadare2Disable {
    RADARE2_DISABLED.fetch_add(1, Ordering::SeqCst);
    ScopedRadare2Disable
}

/// Check if radare2 is disabled
pub(crate) fn is_disabled() -> bool {
    RADARE2_DISABLED.load(Ordering::SeqCst) > 0
}

/// Get rizin execution statistics for debugging.
#[allow(dead_code)]
pub(crate) fn rizin_stats() -> (u64, u64, u64, u64) {
    (
        RIZIN_TOTAL_CALLS.load(Ordering::Relaxed),
        RIZIN_SUCCESSES.load(Ordering::Relaxed),
        RIZIN_TIMEOUTS.load(Ordering::Relaxed),
        RIZIN_FAILURES.load(Ordering::Relaxed),
    )
}

/// Log rizin statistics for post-mortem analysis.
pub(crate) fn log_rizin_stats() {
    let (total, successes, timeouts, failures) = rizin_stats();
    if total > 0 {
        tracing::info!(
            total_calls = total,
            successes = successes,
            timeouts = timeouts,
            failures = failures,
            timeout_rate_pct = (timeouts as f64 / total as f64) * 100.0,
            failure_rate_pct = (failures as f64 / total as f64) * 100.0,
            "Rizin subprocess statistics"
        );
    }
}

/// Execute a rizin command with timeout protection.
///
/// This prevents hung rizin processes from accumulating during archive analysis,
/// which was a major cause of memory exhaustion.
///
/// # Arguments
/// * `args` - Command line arguments for rizin
/// * `timeout` - Maximum time to wait for the process
/// * `cancellation` - Optional flag to abort execution
///
/// # Returns
/// * `Ok(Output)` - The process output
/// * `Err` - If the process times out or fails to execute
fn execute_rizin_with_timeout(
    args: &[&str],
    timeout: Duration,
    cancellation: Option<&Arc<AtomicBool>>,
) -> Result<std::process::Output> {
    use std::io::Read;
    use std::sync::mpsc;

    // Final check before spawning
    if cancellation.is_some_and(|c| c.load(Ordering::Acquire)) {
        return Err(anyhow::anyhow!("Rizin execution cancelled before spawn"));
    }

    RIZIN_TOTAL_CALLS.fetch_add(1, Ordering::Relaxed);

    let start = std::time::Instant::now();
    let args_str = args.join(" ");

    trace!(
        command = %format!("rizin {}", args_str),
        timeout_secs = timeout.as_secs(),
        "Executing rizin with timeout"
    );

    let mut cmd = Command::new("rizin");
    // stdin must be /dev/null: process_group(0) places rizin in a background
    // process group, so any terminal read attempt triggers SIGTTIN and suspends
    // the process indefinitely. Redirecting to null prevents that entirely.
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = cmd.spawn().context("Failed to spawn rizin process")?;

    // Read stdout/stderr in background threads to prevent pipe buffer deadlock
    // This is critical - if stdout fills up, rizin blocks and we timeout
    let stdout_handle = child.stdout.take();
    let stderr_handle = child.stderr.take();

    let (stdout_tx, stdout_rx) = mpsc::channel();
    let (stderr_tx, stderr_rx) = mpsc::channel();

    // Spawn thread to read stdout (capped at 100MB to prevent OOM from
    // malicious/runaway subprocesses).
    const MAX_SUBPROCESS_OUTPUT: usize = 100 * 1024 * 1024;
    let stdout_thread = std::thread::spawn(move || {
        let mut stdout = Vec::new();
        if let Some(mut handle) = stdout_handle {
            let _ = (&mut handle)
                .take(MAX_SUBPROCESS_OUTPUT as u64)
                .read_to_end(&mut stdout);
        }
        let _ = stdout_tx.send(stdout);
    });

    // Spawn thread to read stderr (same cap)
    let stderr_thread = std::thread::spawn(move || {
        let mut stderr = Vec::new();
        if let Some(mut handle) = stderr_handle {
            let _ = (&mut handle)
                .take(MAX_SUBPROCESS_OUTPUT as u64)
                .read_to_end(&mut stderr);
        }
        let _ = stderr_tx.send(stderr);
    });

    // Wait for process completion with timeout.
    // Uses a dedicated thread for child.wait() + recv_timeout to avoid
    // the 100ms poll-sleep loop that wastes rayon worker thread time.
    let child_id = child.id();
    tracing::info!(pid = child_id, command = %args_str, "Rizin process spawned");
    let (wait_tx, wait_rx) = mpsc::channel();
    let wait_thread = std::thread::spawn(move || {
        let status = child.wait();
        tracing::info!(
            pid = child_id,
            exit_code = status.as_ref().ok().and_then(std::process::ExitStatus::code),
            "Rizin process exited; killing process group to release pipes"
        );
        // After the rizin process exits, kill its entire process group to
        // release any stdout/stderr pipe handles held by child processes
        // rizin may have spawned (e.g. during `aa` analysis). Without this,
        // read_to_end() in the stdout/stderr threads blocks indefinitely
        // because orphaned grandchildren still hold the write-end of the pipes.
        #[cfg(unix)]
        unsafe {
            libc::kill(-(child_id as libc::pid_t), libc::SIGKILL);
        }
        tracing::info!(pid = child_id, "Process group killed; waiting for pipe drain");
        let _ = wait_tx.send(status);
    });

    // Use a loop to check for cancellation while waiting for the process to exit
    let deadline = start + timeout;
    let result = loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            break Err(mpsc::RecvTimeoutError::Timeout);
        }

        if cancellation.is_some_and(|c| c.load(Ordering::Acquire)) {
            break Err(mpsc::RecvTimeoutError::Disconnected); // Re-use Disconnected to signal cancellation
        }

        let wait_time = (deadline - now).min(Duration::from_millis(500));
        match wait_rx.recv_timeout(wait_time) {
            Ok(res) => break Ok(res),
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err(mpsc::RecvTimeoutError::Disconnected)
            }
        }
    };

    match result {
        Ok(Ok(status)) => {
            let elapsed = start.elapsed();
            let _ = wait_thread.join();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            let stdout = stdout_rx.recv().unwrap_or_default();
            let stderr = stderr_rx.recv().unwrap_or_default();
            tracing::info!(
                pid = child_id,
                elapsed_ms = elapsed.as_millis(),
                stdout_bytes = stdout.len(),
                "Rizin pipe drain complete"
            );

            let output = std::process::Output {
                status,
                stdout,
                stderr,
            };

            if status.success() {
                RIZIN_SUCCESSES.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    elapsed_ms = elapsed.as_millis(),
                    stdout_bytes = output.stdout.len(),
                    "Rizin completed successfully"
                );
            } else {
                RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
                let stderr_str = String::from_utf8_lossy(&output.stderr);
                warn!(
                    elapsed_ms = elapsed.as_millis(),
                    exit_code = ?status.code(),
                    stderr = %stderr_str,
                    "Rizin exited with error"
                );
            }

            Ok(output)
        }
        Ok(Err(e)) => {
            RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);
            let _ = wait_thread.join();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();
            Err(anyhow::anyhow!("Failed to wait for rizin process: {}", e))
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            // Either cancelled or wait_thread crashed
            RIZIN_FAILURES.fetch_add(1, Ordering::Relaxed);

            let is_cancelled = cancellation.is_some_and(|c| c.load(Ordering::Acquire));
            if is_cancelled {
                warn!(command = %format!("rizin {}", args_str), "Rizin process cancelled - killing");
            } else {
                warn!(command = %format!("rizin {}", args_str), "Rizin wait thread disconnected unexpectedly");
            }

            #[cfg(unix)]
            {
                // Kill the whole process group
                let _ = unsafe { libc::kill(-(child_id as i32), libc::SIGKILL) };
            }
            #[cfg(not(unix))]
            let _ = child_id;

            let _ = wait_thread.join();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();

            if is_cancelled {
                anyhow::bail!("Rizin execution cancelled")
            } else {
                anyhow::bail!("Rizin wait thread disconnected unexpectedly")
            }
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            RIZIN_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            warn!(
                timeout_secs = timeout.as_secs(),
                command = %format!("rizin {}", args_str),
                "Rizin process timed out - killing"
            );

            #[cfg(unix)]
            {
                // Kill the whole process group
                let _ = unsafe { libc::kill(-(child_id as i32), libc::SIGKILL) };
            }
            #[cfg(not(unix))]
            let _ = child_id;

            let _ = wait_thread.join();
            let _ = stdout_thread.join();
            let _ = stderr_thread.join();

            log_rizin_stats();
            anyhow::bail!("Rizin process timed out after {}s", timeout.as_secs())
        }
    }
}

struct EffectiveInputPath {
    temp_file: Option<tempfile::NamedTempFile>,
}

impl EffectiveInputPath {
    fn new(file_path: &Path, fallback_data: Option<&[u8]>) -> Result<Self> {
        let Some(data) = fallback_data.filter(|_| !file_path.exists()) else {
            return Ok(Self { temp_file: None });
        };
        debug!(
            path = %file_path.display(),
            bytes = data.len(),
            "writing in-memory bytes to temp file for rizin"
        );

        let mut tmp =
            tempfile::NamedTempFile::new().context("failed to create rizin temp file")?;
        {
            use std::io::Write as _;
            tmp.write_all(data)
                .context("failed to write bytes to rizin temp file")?;
        }

        Ok(Self {
            temp_file: Some(tmp),
        })
    }

    fn path<'a>(&'a self, file_path: &'a Path) -> &'a Path {
        self.temp_file.as_ref().map_or(file_path, tempfile::NamedTempFile::path)
    }
}

/// Batched analysis result containing all data from a single r2 session
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct BatchedAnalysis {
    pub functions: Vec<R2Function>,
    pub sections: Vec<R2Section>,
    pub strings: Vec<R2String>,
    #[serde(default = "default_true")]
    pub strings_extracted: bool,
    #[serde(default)]
    pub imports: Vec<R2Import>,
    /// True if rizin analysis timed out and returned no batched results.
    #[serde(default)]
    pub timed_out: bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Clone, Copy, Debug)]
enum RizinMode {
    MetadataOnly,
    StringsOnly,
    FunctionsOnly,
    Full,
}

impl RizinMode {
    const fn label(self) -> &'static str {
        match self {
            Self::MetadataOnly => "metadata-only",
            Self::StringsOnly => "strings-only",
            Self::FunctionsOnly => "functions-only",
            Self::Full => "full",
        }
    }
}

/// Radare2 integration for deep binary analysis
#[derive(Debug)]
pub(crate) struct Radare2Analyzer {}

impl Radare2Analyzer {
    pub(crate) fn new() -> Self {
        Self {}
    }

    /// Check if radare2 is available (and not disabled)
    /// Result is cached after first check to avoid subprocess spawn per file.
    pub(crate) fn is_available() -> bool {
        if is_disabled() {
            return false;
        }
        *RADARE2_AVAILABLE.get_or_init(|| Command::new("rizin").arg("-v").output().is_ok())
    }

    /// Extract all symbols (imports, exports, and internal symbols) in a single session.
    /// Uses timeout protection to prevent hung processes.
    #[allow(dead_code)] // Used by main.rs binary
    pub(crate) fn extract_all_symbols(
        &self,
        file_path: &Path,
        cancellation: Option<&Arc<AtomicBool>>,
    ) -> Result<(Vec<R2Import>, Vec<R2Export>, Vec<R2Symbol>)> {
        let file_path_str = file_path.to_string_lossy();
        let timeout = Duration::from_secs(RIZIN_DEFAULT_TIMEOUT_SECS);

        let output = execute_rizin_with_timeout(
            &[
                "-NN",
                "-q",
                "-e",
                "scr.color=0",
                "-e",
                "log.level=0",
                "-c",
                "iij; echo SEPARATOR; iEj; echo SEPARATOR; isj",
                &file_path_str,
            ],
            timeout,
            cancellation,
        )?;

        if !output.status.success() {
            return Ok((Vec::new(), Vec::new(), Vec::new()));
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = output_str.split("SEPARATOR").collect();

        let imports = parts
            .first()
            .and_then(|p| {
                let json_start = p.find('[')?;
                serde_json::from_str(&p[json_start..]).ok()
            })
            .unwrap_or_default();

        let exports = parts
            .get(1)
            .and_then(|p| {
                let json_start = p.find('[')?;
                serde_json::from_str(&p[json_start..]).ok()
            })
            .unwrap_or_default();

        let symbols = parts
            .get(2)
            .and_then(|p| {
                let json_start = p.find('[')?;
                serde_json::from_str(&p[json_start..]).ok()
            })
            .unwrap_or_default();

        Ok((imports, exports, symbols))
    }

    /// Extract functions, sections, strings, and imports in a SINGLE r2 session.
    /// This significantly reduces overhead compared to calling each method separately.
    /// Results are cached by SHA256 with zstd compression.
    ///
    /// Uses timeout protection to prevent hung processes from accumulating.
    ///
    /// `has_symbols`: when false (stripped binary), function analysis (`aa; aflj`) is skipped.
    /// Stripped binaries yield only heuristically-guessed unnamed functions of limited value,
    /// so sections and strings alone are extracted instead — much faster and equally useful.
    ///
    /// `goblin_success`: when true, redundant structural analysis (`iSj`, `iij`) is skipped
    /// in rizin, as goblin has already successfully provided this data.
    ///
    /// `include_strings`: when false, `izj` is skipped and callers are expected to rely on
    /// pre-extracted `stng` strings instead.
    pub(crate) fn extract_batched(
        &self,
        file_path: &Path,
        has_symbols: bool,
        goblin_success: bool,
        include_strings: bool,
        precomputed_sha256: Option<String>,
        cancellation: Option<&Arc<AtomicBool>>,
        fallback_data: Option<&[u8]>,
    ) -> Result<BatchedAnalysis> {
        let t_start = std::time::Instant::now();

        // If the logical path does not exist on disk and in-memory bytes are provided,
        // write them to a temporary file. rizin requires a real filesystem path.
        let effective_input = EffectiveInputPath::new(file_path, fallback_data)?;
        // effective_path is the real on-disk path passed to rizin and metadata checks.
        // file_path is kept for log messages so they show the logical (original) name.
        let effective_path = effective_input.path(file_path);

        // Use precomputed SHA256 for cache lookup if available
        let sha256 = precomputed_sha256.or_else(|| Self::compute_file_sha256(effective_path));

        // Check file size - skip expensive function analysis for large binaries
        // Binaries >20MB take minutes to analyze with 'aa'
        const MAX_SIZE_FOR_FULL_ANALYSIS: u64 = 20 * 1024 * 1024; // 20MB
        const MAX_SIZE_FOR_DEEP_ANALYSIS: u64 = 5 * 1024 * 1024; // 5MB

        let file_size = std::fs::metadata(effective_path).map(|m| m.len()).unwrap_or(0);
        let skip_function_analysis = file_size > MAX_SIZE_FOR_FULL_ANALYSIS || !has_symbols;

        // Use a lighter analysis for medium-sized files
        let use_light_analysis = file_size > MAX_SIZE_FOR_DEEP_ANALYSIS;

        let mode = match (!skip_function_analysis, include_strings) {
            (false, false) => RizinMode::MetadataOnly,
            (false, true) => RizinMode::StringsOnly,
            (true, false) => RizinMode::FunctionsOnly,
            (true, true) => RizinMode::Full,
        };
        let function_reason = if file_size > MAX_SIZE_FOR_FULL_ANALYSIS {
            format!(
                "function analysis disabled: file {} MB exceeds {} MB threshold",
                file_size / 1024 / 1024,
                MAX_SIZE_FOR_FULL_ANALYSIS / 1024 / 1024
            )
        } else if !has_symbols {
            "function analysis disabled: no symbols/imports/sections discovered pre-rizin"
                .to_string()
        } else if use_light_analysis {
            format!(
                "light function analysis enabled (aas; aap): file {} MB exceeds {} MB deep analysis threshold",
                file_size / 1024 / 1024,
                MAX_SIZE_FOR_DEEP_ANALYSIS / 1024 / 1024
            )
        } else {
            "full function analysis enabled (aa): symbol/structure hints suggest aflj is worthwhile"
                .to_string()
        };
        let string_reason = if include_strings {
            "string extraction enabled: no pre-extracted stng strings available".to_string()
        } else {
            "string extraction disabled: using existing stng strings".to_string()
        };

        debug!(
            path = %file_path.display(),
            mode = mode.label(),
            goblin_success,
            has_symbols,
            include_strings,
            file_size_mb = file_size / 1024 / 1024,
            function_reason = %function_reason,
            string_reason = %string_reason,
            "Running radare2 batched analysis"
        );

        if matches!(mode, RizinMode::MetadataOnly) {
            debug!(
                path = %file_path.display(),
                mode = mode.label(),
                reason = "goblin already supplied metadata and strings were pre-extracted",
                "Skipping radare2 subprocess"
            );
            return Ok(BatchedAnalysis {
                strings_extracted: false,
                timed_out: false,
                ..Default::default()
            });
        }

        // Check cache first (skipped in debug builds or when CLEAVE_SKIP_CACHE is set)
        let skip_cache = crate::cache::skip_cache();
        if !skip_cache {
            if let Some(ref hash) = sha256 {
                if let Some(cached) = Self::load_from_cache(hash) {
                    if !include_strings || cached.strings_extracted {
                        debug!(
                            path = %file_path.display(),
                            mode = mode.label(),
                            cached_strings = cached.strings_extracted,
                            "radare2 cache hit"
                        );
                        return Ok(cached);
                    }
                    trace!(
                        path = %file_path.display(),
                        mode = mode.label(),
                        "radare2 cache entry missing requested strings"
                    );
                } else {
                    trace!(path = %file_path.display(), mode = mode.label(), "radare2 cache miss");
                }
            }
        }

        if file_size > MAX_SIZE_FOR_FULL_ANALYSIS {
            debug!(
                "File size {} MB > 5 MB, skipping function analysis",
                file_size / 1024 / 1024
            );
        } else if !has_symbols {
            debug!("Stripped binary, skipping function analysis (aa/aflj)");
        }

        let file_path_str = effective_path.to_string_lossy().to_string();

        // Helper to parse JSON from a SEP-delimited part
        let parse_json_part = |part: Option<&&str>| -> Option<String> {
            part.and_then(|p| {
                let start = p.find('[')?;
                let end = p.rfind(']')?;
                Some(p[start..=end].to_string())
            })
        };

        // SINGLE r2 spawn with ALL data extraction
        // Commands separated by "echo SEP" for parsing:
        // - aa: full analysis (only for unstripped binaries under 5MB)
        // - aas; aap: light analysis (for binaries 5MB-20MB)
        // - aflj: functions as JSON
        // - iSj: sections as JSON (skipped if goblin_success)
        // - izj: strings as JSON
        // - iij: imports as JSON (skipped if goblin_success)
        let mut commands = Vec::new();
        if !skip_function_analysis {
            if use_light_analysis {
                commands.push("aas; aap; aflj");
            } else {
                commands.push("aa; aflj");
            }
        }
        if !goblin_success {
            commands.push("iSj");
        }
        if include_strings {
            commands.push("izj");
        }
        if !goblin_success {
            commands.push("iij");
        }

        let command = commands.join("; echo SEP; ");

        trace!(command = command, "Executing rizin batched analysis");

        // Use a bounded timeout so one slow file does not stall the whole scan.
        let timeout = Duration::from_secs(RIZIN_DEFAULT_TIMEOUT_SECS);

        let phase_label = format!(
            "rizin ({}) on {}",
            mode.label(),
            file_path.file_name().unwrap_or(file_path.as_os_str()).to_string_lossy()
        );
        crate::memory_tracker::set_current_phase(&phase_label);
        let output = execute_rizin_with_timeout(
            &[
                "-NN",
                "-q",
                "-e",
                "scr.color=0",
                "-e",
                "log.level=0",
                "-c",
                &command,
                &file_path_str,
            ],
            timeout,
            cancellation,
        );
        crate::memory_tracker::clear_current_phase();

        // Handle timeout as a tool limitation; callers may choose how to surface it.
        let output = match output {
            Ok(out) => out,
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("timed out") {
                    warn!(
                        path = %file_path.display(),
                        mode = mode.label(),
                        timeout_secs = timeout.as_secs(),
                        "Rizin analysis timed out; continuing without batched rizin data"
                    );
                    // Return result with timed_out flag set - consumers can add finding
                    return Ok(BatchedAnalysis {
                        strings_extracted: include_strings,
                        timed_out: true,
                        ..Default::default()
                    });
                }
                return Err(e);
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(status = %output.status, stderr = %stderr, "radare2 exited with error");
            anyhow::bail!("radare2 failed with status {}: {}", output.status, stderr);
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = output_str.split("SEP").collect();

        let mut part_idx = 0;
        let functions = if !skip_function_analysis {
            let f = parse_json_part(parts.get(part_idx))
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
            part_idx += 1;
            f
        } else {
            Vec::new()
        };

        let sections = if !goblin_success {
            let s = parse_json_part(parts.get(part_idx))
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
            part_idx += 1;
            s
        } else {
            Vec::new()
        };

        let strings: Vec<R2String> = if include_strings {
            let parsed = parse_json_part(parts.get(part_idx))
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default();
            part_idx += 1;
            parsed
        } else {
            Vec::new()
        };

        let imports = if !goblin_success {
            parse_json_part(parts.get(part_idx))
                .and_then(|j| serde_json::from_str(&j).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        debug!(
            path = %file_path.display(),
            mode = mode.label(),
            elapsed_ms = t_start.elapsed().as_millis(),
            functions = functions.len(),
            sections = sections.len(),
            strings = strings.len(),
            imports = imports.len(),
            "radare2 batched analysis completed"
        );

        let result = BatchedAnalysis {
            functions,
            sections,
            strings,
            strings_extracted: include_strings,
            imports,
            timed_out: false,
        };

        // Save to cache (unless CLEAVE_SKIP_CACHE is set)
        if !skip_cache {
            if let Some(ref hash) = sha256 {
                Self::save_to_cache(hash, &result);
            }
        }

        Ok(result)
    }

    /// Compute binary metrics from pre-extracted batched analysis
    /// Much faster than compute_binary_metrics as it doesn't spawn new r2 processes
    pub(crate) fn compute_metrics_from_batched(
        &self,
        batched: &BatchedAnalysis,
        file_size: u64,
        file_type: &str,
    ) -> BinaryMetrics {
        use parsing::calculate_char_entropy;

        let mut metrics = BinaryMetrics {
            section_count: batched.sections.len() as u32,
            file_size, // Use actual file size from caller
            ..Default::default()
        };
        let mut entropies: Vec<f32> = Vec::new();
        let mut total_size: u64 = 0;
        let mut largest_size: u64 = 0;
        let mut section_name_chars: Vec<char> = Vec::new();
        let mut code_size: u64 = 0;

        for section in &batched.sections {
            // Cap section size at file_size — tampered PEs can declare sizes beyond EOF
            let section_size = section.size.min(file_size);

            let entropy = section.entropy as f32;
            entropies.push(entropy);
            total_size += section_size;

            if section_size > largest_size {
                largest_size = section_size;
            }

            if crate::analyzers::metrics_utils::is_nonstandard_section_name(
                file_type,
                &section.name,
            ) {
                metrics.nonstandard_section_name_count += 1;
            }

            if let Some(ref perm) = section.perm {
                // Workaround for radare2 bug: __const sections are marked as r-x but should not be counted as code
                // Extract just the section name (after the last dot)
                let section_name = section.name.rsplit('.').next().unwrap_or(&section.name);
                let is_data_only = section_name == "__const"
                    || section_name == "__cstring"
                    || section_name == "__gcc_except_tab"
                    || section_name == "__unwind_info"
                    || section_name == "__eh_frame"
                    || section_name == "__rodata";

                if perm.contains('x') && !is_data_only {
                    metrics.executable_sections += 1;
                    code_size += section_size;
                }
                if perm.contains('w') {
                    metrics.writable_sections += 1;
                }
                if perm.contains('x') && perm.contains('w') {
                    metrics.wx_sections += 1;
                }
            }

            if entropy > 7.5 {
                metrics.high_entropy_regions += 1;
            }

            section_name_chars.extend(section.name.chars());

            if section.name == ".text" || section.name.contains("code") {
                metrics.code_entropy = entropy;
            }
            if section.name == ".data" || section.name == ".rodata" {
                metrics.data_entropy = entropy;
            }
        }

        if !entropies.is_empty() {
            metrics.overall_entropy = entropies.iter().sum::<f32>() / entropies.len() as f32;
            let mean = metrics.overall_entropy;
            let variance: f32 =
                entropies.iter().map(|e| (e - mean).powi(2)).sum::<f32>() / entropies.len() as f32;
            metrics.entropy_variance = variance.sqrt();
        }

        if !section_name_chars.is_empty() {
            metrics.section_name_entropy = calculate_char_entropy(&section_name_chars);
        }

        if total_size > 0 {
            metrics.largest_section_ratio = largest_size as f32 / total_size as f32;
        }

        // Size metrics (file_size already set from parameter)
        metrics.code_size = code_size;
        if total_size > 0 {
            let data_size = total_size.saturating_sub(code_size);
            if data_size > 0 {
                metrics.code_to_data_ratio = code_size as f32 / data_size as f32;
            }
        }

        // Average section size
        if !batched.sections.is_empty() {
            metrics.avg_section_size = total_size as f32 / batched.sections.len() as f32;
        }

        // Import metrics
        metrics.import_count = batched.imports.len() as u32;

        // String metrics
        metrics.string_count = batched.strings.len() as u32;
        if !batched.strings.is_empty() {
            let mut total_length: u64 = 0;
            let mut max_length: u32 = 0;
            let mut wide_count: u32 = 0;
            let mut sentence_like_count: u32 = 0;
            let mut lengths: Vec<f32> = Vec::with_capacity(batched.strings.len());

            for s in &batched.strings {
                let len = s.string.len() as u32;
                total_length += len as u64;
                lengths.push(len as f32);
                if len > max_length {
                    max_length = len;
                }
                // Check if wide string (type contains "wide" or "utf16")
                if s.string_type.to_lowercase().contains("wide")
                    || s.string_type.to_lowercase().contains("utf16")
                {
                    wide_count += 1;
                }
                if crate::analyzers::metrics_utils::is_sentence_like_string(&s.string) {
                    sentence_like_count += 1;
                }
            }

            metrics.avg_string_length = total_length as f32 / batched.strings.len() as f32;
            metrics.max_string_length = max_length;
            metrics.wide_string_count = wide_count;
            metrics.sentence_string_count = sentence_like_count;
            if lengths.len() > 1 {
                let mean = metrics.avg_string_length;
                let variance =
                    lengths.iter().map(|l| (l - mean).powi(2)).sum::<f32>() / lengths.len() as f32;
                metrics.string_length_stddev = variance.sqrt();
            }
        }

        if metrics.string_count > 0 {
            metrics.sentence_string_ratio =
                metrics.sentence_string_count as f32 / metrics.string_count as f32;
        }

        if metrics.import_count > 0 {
            let behavioral_imports = batched
                .imports
                .iter()
                .filter(|i| crate::analyzers::metrics_utils::is_behavioral_import(&i.name))
                .count() as f32;
            metrics.behavioral_import_ratio = behavioral_imports / metrics.import_count as f32;
        }

        // Function metrics
        metrics.function_count = batched.functions.len() as u32;

        let mut complexities: Vec<u32> = Vec::new();
        let mut bb_counts: Vec<u32> = Vec::new();
        let mut edge_counts: Vec<u32> = Vec::new();

        for func in &batched.functions {
            if let Some(cc) = func.complexity {
                complexities.push(cc);
            }
            if let Some(nbbs) = func.nbbs {
                bb_counts.push(nbbs);
            }
            if let Some(edges) = func.edges {
                edge_counts.push(edges);
            }
        }

        if !complexities.is_empty() {
            metrics.avg_complexity =
                complexities.iter().sum::<u32>() as f32 / complexities.len() as f32;
            metrics.max_complexity = *complexities.iter().max().unwrap_or(&0);
        }

        if !bb_counts.is_empty() {
            metrics.avg_basic_blocks =
                bb_counts.iter().sum::<u32>() as f32 / bb_counts.len() as f32;
            metrics.total_basic_blocks = bb_counts.iter().sum::<u32>();
        }

        // Note: edge_counts collected but not used (no avg_cfg_edges field in BinaryMetrics)
        let _ = edge_counts;

        // Compute ratio metrics (these depend on multiple fields)
        Self::compute_ratio_metrics(&mut metrics);

        metrics
    }

    /// Compute ratio and normalized metrics from already-populated base metrics
    /// This should be called after all base counters are set
    pub(crate) fn compute_ratio_metrics(metrics: &mut BinaryMetrics) {
        let code_kb = metrics.code_size as f32 / 1024.0;

        // Density ratios (per KB of code)
        if code_kb > 0.0 {
            metrics.import_density = metrics.import_count as f32 / code_kb;
            metrics.string_density = metrics.string_count as f32 / code_kb;
            metrics.function_density = metrics.function_count as f32 / code_kb;
            metrics.relocation_density = metrics.relocation_count as f32 / code_kb;
            metrics.complexity_per_kb = metrics.avg_complexity * 1024.0 / metrics.code_size as f32;
        }

        // Export to import ratio
        if metrics.import_count > 0 {
            metrics.export_to_import_ratio =
                metrics.export_count as f32 / metrics.import_count as f32;
        }

        // Normalized metrics (size-independent)
        if metrics.file_size > 0 {
            let file_size_sqrt = (metrics.file_size as f32).sqrt();
            metrics.normalized_import_count = metrics.import_count as f32 / file_size_sqrt;
            metrics.normalized_export_count = metrics.export_count as f32 / file_size_sqrt;

            let file_size_log = (metrics.file_size as f32).log2();
            if file_size_log > 0.0 {
                metrics.normalized_section_count = metrics.section_count as f32 / file_size_log;
            }
        }

        if metrics.code_size > 0 {
            let code_size_sqrt = (metrics.code_size as f32).sqrt();
            metrics.normalized_string_count = metrics.string_count as f32 / code_size_sqrt;
        }

        // Code section ratio
        if metrics.section_count > 0 {
            metrics.code_section_ratio =
                metrics.executable_sections as f32 / metrics.section_count as f32;
        }
    }
}

impl Default for Radare2Analyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_syscall_info_serialize() {
        let info = SyscallInfo {
            address: 0x1000,
            number: 1,
            name: "write".to_string(),
            desc: "Write to file descriptor".to_string(),
            arch: "x86_64".to_string(),
        };

        let json = serde_json::to_string(&info).unwrap();
        assert!(json.contains("write"));
        assert!(json.contains("0x1000") || json.contains("4096")); // address can be in different formats

        let deserialized: SyscallInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.number, 1);
        assert_eq!(deserialized.name, "write");
    }

    #[test]
    fn test_compute_metrics_sets_file_size() {
        use crate::radare2::models::R2Section;

        let analyzer = Radare2Analyzer::new();

        // Create batched analysis with sections of known sizes
        let batched = BatchedAnalysis {
            functions: vec![],
            sections: vec![
                R2Section {
                    name: ".text".to_string(),
                    size: 1000,
                    vsize: Some(1000),
                    perm: Some("r-x".to_string()),
                    entropy: 6.5,
                },
                R2Section {
                    name: ".data".to_string(),
                    size: 500,
                    vsize: Some(500),
                    perm: Some("rw-".to_string()),
                    entropy: 4.0,
                },
                R2Section {
                    name: ".rodata".to_string(),
                    size: 300,
                    vsize: Some(300),
                    perm: Some("r--".to_string()),
                    entropy: 5.0,
                },
            ],
            strings: vec![],
            ..Default::default()
        };

        let file_size = 1800u64;
        let metrics = analyzer.compute_metrics_from_batched(&batched, file_size, "macho");

        // file_size should match what was passed in
        assert_eq!(
            metrics.file_size, file_size,
            "file_size should equal the passed parameter"
        );

        // code_size should be the size of executable sections only
        assert_eq!(
            metrics.code_size, 1000,
            "code_size should equal size of .text section"
        );

        // code_size should never exceed file_size
        assert!(
            metrics.code_size <= metrics.file_size,
            "code_size ({}) should never exceed file_size ({})",
            metrics.code_size,
            metrics.file_size
        );
    }

    #[test]
    fn test_scoped_disable_restores_previous_state() {
        let was_disabled = is_disabled();
        let before = RADARE2_DISABLED.load(Ordering::SeqCst);

        {
            let _guard = scoped_disable_radare2();
            assert!(is_disabled());
            assert_eq!(RADARE2_DISABLED.load(Ordering::SeqCst), before + 1);
        }

        assert_eq!(RADARE2_DISABLED.load(Ordering::SeqCst), before);
        assert_eq!(is_disabled(), was_disabled);
    }

    #[test]
    fn test_effective_input_path_uses_original_when_file_exists() {
        let tmp = tempfile::NamedTempFile::new().expect("create temp file");
        fs::write(tmp.path(), b"disk").expect("write temp file");

        let resolved =
            EffectiveInputPath::new(tmp.path(), Some(b"fallback")).expect("resolve input path");

        assert_eq!(resolved.path(tmp.path()), tmp.path());
    }

    #[test]
    fn test_effective_input_path_writes_temp_file_for_missing_path() {
        let missing = std::env::temp_dir().join(format!(
            "cleave-rizin-missing-{}",
            std::process::id()
        ));
        let data = b"in-memory bytes";

        let resolved =
            EffectiveInputPath::new(&missing, Some(data)).expect("resolve missing input path");
        let effective_path = resolved.path(&missing);

        assert_ne!(effective_path, missing.as_path());
        assert!(effective_path.exists());
        assert_eq!(fs::read(effective_path).expect("read temp file"), data);
    }

    #[test]
    fn test_effective_input_path_keeps_missing_path_without_fallback_bytes() {
        let missing = std::env::temp_dir().join(format!(
            "cleave-rizin-missing-no-fallback-{}",
            std::process::id()
        ));

        let resolved = EffectiveInputPath::new(&missing, None).expect("resolve input path");

        assert_eq!(resolved.path(&missing), missing.as_path());
        assert!(!resolved.path(&missing).exists());
    }

    /// Regression test: subprocess spawned with process_group(0) must not hang.
    ///
    /// process_group(0) places the child in its own (background) process group.
    /// Any stdin read attempt from that group triggers SIGTTIN, suspending the
    /// process indefinitely — which is what happened to rizin in practice.
    /// Redirecting stdin to /dev/null (Stdio::null()) prevents the read and lets
    /// the process exit normally.
    ///
    /// `cat` with no arguments reads stdin until EOF, making it a reliable probe:
    /// with an inherited terminal stdin in a background group it suspends;
    /// with Stdio::null() it sees EOF immediately and exits cleanly.
    #[cfg(unix)]
    #[test]
    fn test_background_process_group_stdin_null_prevents_sigttin() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        let mut child = Command::new("cat")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .expect("failed to spawn cat");

        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            match child.try_wait().expect("try_wait failed") {
                Some(s) => break s,
                None if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!(
                        "subprocess did not exit within 5s — likely suspended by SIGTTIN. \
                         Ensure stdin(Stdio::null()) is set whenever process_group(0) is used."
                    );
                }
                None => std::thread::sleep(Duration::from_millis(5)),
            }
        };

        assert!(status.success(), "cat should exit 0 when stdin is /dev/null");
    }
}
