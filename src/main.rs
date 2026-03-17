//! cleave - Deep Inspection of Suspicious Software for Evaluation and Classification of Threats
//!
//! cleave is a comprehensive malware analysis tool that performs deep static analysis
//! of binaries, scripts, and archives to identify malicious behavior patterns and capabilities.
//!
//! # Architecture
//!
//! - **Analyzers**: Format-specific analysis engines (ELF, PE, MachO, scripts, archives)
//! - **Capabilities**: Trait-based capability detection from YAML rules
//! - **Composite Rules**: Boolean logic for combining multiple indicators
//! - **YARA Integration**: Pattern matching with community and custom rules
//! - **Radare2/Rizin**: Binary analysis and disassembly
//!
//! # Usage
//!
//! ```text
//! cleave <file> [options]
//! cleave diff <file1> <file2>  # Compare two versions
//! ```
//!
//! # Output
//!
//! Analysis results are output as JSON containing:
//! - Detected capabilities and traits
//! - Findings with criticality levels
//! - Binary metrics and code structure
//! - YARA matches and syscalls
//! - Archive contents (if applicable)

// The binary re-declares library source modules as private `mod` for internal access.
// Items that are `pub` in those modules appear unreachable from the binary's perspective
// even though they ARE reachable via the library crate. Suppress this false positive.
#![allow(unreachable_pub)]

// Use jemalloc for better memory management in long-running sessions.
// This prevents memory fragmentation from repeated wasmtime VM allocations (YARA scanning).
// Enable with: cargo build --release --features jemalloc
#[cfg(all(unix, feature = "jemalloc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod analyzers;
mod archive_utils;
mod cache;
mod capabilities;
mod cli;
mod commands;
mod composite_rules;
mod diff;
mod entropy;
mod env_mapper;
mod extractors;
mod ip_validator;
mod malecule_bridge;
mod output;
mod path_mapper;
mod radare2;
mod rtf;
// mod radare2_extended;  // Removed: integrated into radare2.rs
mod strings;
mod test_rules;
#[cfg(test)]
mod test_rules_filters_test;
mod third_party_config;
mod third_party_yara;
mod traits_repo;
mod types;
mod upx;
mod yara_engine;

use anyhow::{Context, Result};
use clap::Parser;
use commands::{
    analyze_command, diff_command, expand_paths, test_match, test_rules, validate_command,
    AnalyzeConfig,
};
use std::fs;
use tracing_subscriber::EnvFilter;

/// Get the parent process ID for debugging subprocess relationships.
fn get_parent_pid() -> u32 {
    // On Linux, read from /proc/self/stat
    #[cfg(target_os = "linux")]
    {
        if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
            // Format: pid (comm) state ppid ...
            // We need to find the closing paren of comm, then parse ppid
            if let Some(close_paren) = stat.rfind(')') {
                let after_comm = &stat[close_paren + 1..];
                let fields: Vec<&str> = after_comm.split_whitespace().collect();
                // fields[0] is state, fields[1] is ppid
                if fields.len() > 1 {
                    if let Ok(ppid) = fields[1].parse::<u32>() {
                        return ppid;
                    }
                }
            }
        }
        0
    }

    // On macOS, use sysctl or ps (simpler to just use ps)
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ps")
            .args(["-o", "ppid=", "-p", &std::process::id().to_string()])
            .output()
        {
            if output.status.success() {
                let ppid_str = String::from_utf8_lossy(&output.stdout);
                if let Ok(ppid) = ppid_str.trim().parse::<u32>() {
                    return ppid;
                }
            }
        }
        0
    }

    // On other platforms, return 0
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        0
    }
}

/// Determine the file log level from environment variables.
///
/// Returns the level name (e.g. "warn", "debug") used for both the EnvFilter
/// and the log filename: `cleave.<pid>.<level>.log`.
///
/// Priority: `CLEAVE_LOG_LEVEL` env var > default ("warn").
fn file_log_level() -> &'static str {
    if let Ok(level) = std::env::var("CLEAVE_LOG_LEVEL") {
        match level.to_lowercase().as_str() {
            "trace" => return "trace",
            "debug" => return "debug",
            "info" => return "info",
            "warn" | "warning" => return "warn",
            "error" => return "error",
            _ => {}
        }
    }
    "warn"
}

/// Build an `EnvFilter` directive that scopes a level to cleave and stng crates only,
/// preventing noisy TRACE/DEBUG output from third-party dependencies.
fn scoped_filter(level: &str) -> String {
    format!("cleave={level},stng={level}")
}

/// Determine the log file path for this cleave process.
///
/// File logging is always enabled by default at warn level. Every cleave invocation
/// writes a log file so that OOM kills, crashes, and unexpected behavior can be
/// diagnosed after the fact.
///
/// The log directory is chosen in this order:
/// 1. `CLEAVE_LOGS_DIR` env var (set by cyclotron to its session log dir)
/// 2. OS-appropriate cache directory:
///    - macOS: ~/Library/Caches/cleave/logs/
///    - Linux: ~/.cache/cleave/logs/
///    - Windows: %LOCALAPPDATA%\cleave\logs\
/// 3. Fallback: $TMPDIR/cleave-logs/
///
/// The file log level defaults to warn and can be raised via `CLEAVE_LOG_LEVEL`.
///
/// Log filename format: `cleave.<pid>.<level>.log`
fn determine_default_log_file() -> Option<String> {
    // Determine the logs directory: CLEAVE_LOGS_DIR > OS cache dir > temp fallback
    let logs_dir = if let Ok(dir) = std::env::var("CLEAVE_LOGS_DIR") {
        if dir.is_empty() {
            return None; // Explicitly empty = disable file logging
        }
        std::path::PathBuf::from(dir)
    } else if let Ok(cache_dir) = cache::cache_dir() {
        cache_dir.join("logs")
    } else if let Some(cache_base) = dirs::cache_dir() {
        cache_base.join("cleave").join("logs")
    } else {
        std::env::temp_dir().join("cleave-logs")
    };

    if let Err(e) = std::fs::create_dir_all(&logs_dir) {
        eprintln!(
            "cleave: failed to create logs directory {:?}: {}",
            logs_dir, e
        );
        return None;
    }

    let pid = std::process::id();
    let level = file_log_level();
    let log_path = logs_dir.join(format!("cleave.{pid}.{level}.log"));

    Some(log_path.to_string_lossy().into_owned())
}

fn main() -> Result<()> {
    // Parse args early to get verbose flag for logging initialization
    let args = cli::Args::parse();
    if args.verbose {
        std::env::set_var("CLEAVE_VERBOSE", "1");
    }

    // Check if running server command (needs info-level logging by default)
    let is_server = matches!(args.command, Some(cli::Command::Serve { .. }));

    // Determine output format early so we can use it for conditional status messages
    let format = args.format();

    // Always-on file logging: every cleave invocation writes a log file so that
    // OOM kills, crashes, and unexpected behavior can be diagnosed after the fact.
    // --log-file flag overrides the automatic path; CLEAVE_LOG_LEVEL controls verbosity.
    let default_log_file = determine_default_log_file();
    let effective_log_file = args.log_file.clone().or(default_log_file);

    if let Some(ref log_file) = effective_log_file {
        use std::fs::OpenOptions;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::Layer;

        // Determine log levels:
        // - stderr: warn (quiet) unless verbose/server/RUST_LOG
        // - file: from CLEAVE_LOG_LEVEL (default warn), or verbose/server overrides
        let (stderr_filter, file_filter) = if std::env::var("RUST_LOG").is_ok() {
            (EnvFilter::from_default_env(), EnvFilter::from_default_env())
        } else if args.verbose {
            (
                EnvFilter::new(scoped_filter("trace")),
                EnvFilter::new(scoped_filter("trace")),
            )
        } else if is_server {
            (
                EnvFilter::new(scoped_filter("info")),
                EnvFilter::new(scoped_filter(file_log_level())),
            )
        } else {
            (
                EnvFilter::new(scoped_filter("warn")),
                EnvFilter::new(scoped_filter(file_log_level())),
            )
        };

        let file = Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(log_file)
                .unwrap_or_else(|e| {
                    eprintln!("Failed to open log file {}: {}", log_file, e);
                    std::process::exit(1);
                }),
        ));

        if format == cli::OutputFormat::Terminal {
            eprintln!("Logging to: {}", log_file);
        }

        use tracing_subscriber::fmt::MakeWriter;
        struct LogFile(Arc<Mutex<std::fs::File>>);
        impl<'a> MakeWriter<'a> for LogFile {
            type Writer = LogFileWriter;
            fn make_writer(&'a self) -> Self::Writer {
                LogFileWriter(self.0.clone())
            }
        }
        struct LogFileWriter(Arc<Mutex<std::fs::File>>);
        impl std::io::Write for LogFileWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let mut file = self
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let result = file.write(buf);
                // Flush after every write to ensure logs survive OOM kills
                let _ = file.flush();
                result
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .flush()
            }
        }

        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_line_number(true)
            .with_writer(std::io::stderr)
            .with_filter(stderr_filter);

        let file_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_line_number(true)
            .with_ansi(false)
            .with_writer(LogFile(file))
            .with_filter(file_filter);

        tracing_subscriber::registry()
            .with(stderr_layer)
            .with(file_layer)
            .init();
    } else {
        // File logging disabled (CLEAVE_LOGS_DIR="") — stderr only
        let env_filter = if std::env::var("RUST_LOG").is_ok() {
            EnvFilter::from_default_env()
        } else if args.verbose {
            EnvFilter::new(scoped_filter("trace"))
        } else if is_server {
            EnvFilter::new(scoped_filter("info"))
        } else {
            EnvFilter::new(scoped_filter("warn"))
        };
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_thread_ids(false)
            .with_line_number(true)
            .with_writer(std::io::stderr)
            .init();
    }

    #[cfg(debug_assertions)]
    tracing::warn!(
        "DEBUG binary — cleave will be very slow; use `make release` for production builds"
    );

    // Log command line and initialization with PID and parent PID for debugging
    // subprocess relationships (especially useful for trait-basher debugging)
    let pid = std::process::id();
    let ppid = get_parent_pid();
    tracing::info!(
        pid = pid,
        ppid = ppid,
        log_file = effective_log_file.as_deref().unwrap_or("none"),
        "cleave started: {}",
        std::env::args().collect::<Vec<_>>().join(" ")
    );
    tracing::debug!(
        pid = pid,
        ppid = ppid,
        verbose = args.verbose,
        validate = std::env::var("CLEAVE_VALIDATE").ok(),
        logs_dir = std::env::var("CLEAVE_LOGS_DIR").ok(),
        log_level = std::env::var("CLEAVE_LOG_LEVEL").ok(),
        "Process context"
    );
    tracing::trace!("Logging initialized (verbose={})", args.verbose);

    // Configure rayon thread pool with larger stack size to handle deeply nested ASTs
    // (e.g., minified JavaScript, malicious files with extreme nesting)
    // Default is ~2MB which can overflow on files with 1000+ nesting levels.
    // Thread count defaults to available_parallelism; override with CLEAVE_RAYON_THREADS.
    let mut builder = rayon::ThreadPoolBuilder::new().stack_size(8 * 1024 * 1024); // 8MB per thread
    if let Some(threads) = std::env::var("CLEAVE_RAYON_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
    {
        builder = builder.num_threads(threads);
    }
    builder.build_global().ok(); // Ignore error if pool already initialized (e.g., in tests)

    // Get disabled components
    let disabled = args.disabled_components();

    // Apply custom traits directory if specified (must be before any trait loading)
    if let Some(ref traits_dir) = args.traits_dir {
        std::env::set_var("CLEAVE_TRAITS_DIR", traits_dir);
    }

    // Apply global disables for radare2 and upx
    if disabled.radare2 {
        radare2::disable_radare2();
    }
    if disabled.upx {
        upx::disable_upx();
    }

    // Print version banner to stderr (status info never goes to stdout) - only in terminal mode
    if format == cli::OutputFormat::Terminal {
        let traits_ver = traits_repo::version()
            .map(|v| format!(" (traits: {v})"))
            .unwrap_or_default();
        eprintln!("cleave v{}{traits_ver}\n", env!("CARGO_PKG_VERSION"));
    }

    // Default passwords for encrypted zip files
    let zip_passwords: Vec<String> = cli::DEFAULT_ZIP_PASSWORDS
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    // Determine third_party setting (can come from top-level or subcommand)
    // Third-party YARA is enabled by default; disable with --disable third-party
    let enable_third_party_global = !disabled.third_party;

    // Create extraction config if --extract-dir is specified
    let sample_extraction = args.extract_dir.as_ref().map(|dir| {
        let path = std::path::PathBuf::from(dir);
        // Ensure directory exists
        if let Err(e) = std::fs::create_dir_all(&path) {
            eprintln!("Warning: could not create extract directory {}: {}", dir, e);
        }
        types::SampleExtractionConfig::new(path)
    });

    // Parse platforms once before match (avoids borrow issues in match arms)
    let platforms = args.platforms();

    // Convert max_file_mem from MB to bytes
    let max_memory_file_size = args.max_file_mem * 1024 * 1024;
    // Convert max_file_size from MB to bytes (0 = no limit)
    let max_scan_file_size = args.max_file_size * 1024 * 1024;

    // Start periodic memory logging whenever file logging is active (always-on
    // by default) or when verbose mode is enabled.
    let _memory_logger = if args.verbose || effective_log_file.is_some() {
        use cleave::memory_tracker;
        Some(memory_tracker::start_periodic_logging(
            std::time::Duration::from_secs(10),
        ))
    } else {
        None
    };

    // Log startup diagnostics for OOM post-mortem analysis
    cleave::memory_tracker::log_startup_diagnostics();

    let result = match args.command {
        Some(cli::Command::Analyze { targets }) => {
            let expanded = expand_paths(targets, &format);
            if expanded.is_empty() {
                anyhow::bail!("No valid paths found (stdin was empty or contained only comments)");
            }
            // Process each target through analyze_command
            let mut results = Vec::new();
            for target in &expanded {
                results.push(analyze_command(&AnalyzeConfig {
                    target,
                    enable_third_party: enable_third_party_global,
                    format: &format,
                    zip_passwords: &zip_passwords,
                    disabled: &disabled,
                    all_files: args.all_files,
                    sample_extraction: sample_extraction.as_ref(),
                    platforms: &platforms,
                    min_hostile_precision: 3.5,
                    min_suspicious_precision: 2.0,
                    max_memory_file_size,
                    enable_full_validation: false,
                    slow_rule_ms: args.slow_rule_ms,
                    output_to_file: args.output.is_some(),
                    max_scan_file_size,
                    scan_threads: args.scan_threads.unwrap_or(0),
                })?);
            }
            results.join("")
        }
        Some(cli::Command::Validate) => {
            validate_command()?;
            return Ok(());
        }
        Some(cli::Command::Diff { old, new }) => diff_command(&old, &new, &format)?,
        Some(cli::Command::Strings {
            target,
            min_length,
            layer,
        }) => commands::extract::strings::run(&target, min_length, layer.as_deref(), &format)?,
        Some(cli::Command::Symbols { target, layer }) => {
            commands::extract::symbols::run(&target, layer.as_deref(), &format)?
        }
        Some(cli::Command::Sections { target, layer }) => {
            commands::extract::sections::run(&target, layer.as_deref(), &format)?
        }
        Some(cli::Command::Metrics { target, layer }) => {
            commands::extract::metrics::run(&target, layer.as_deref(), &format, &disabled)?
        }
        Some(cli::Command::TestRules { target, rules }) => {
            test_rules(&target, &rules, &disabled, platforms.clone(), 3.5, 2.0)?
        }
        Some(cli::Command::TestMatch {
            target,
            r#type,
            method,
            pattern,
            kv_path,
            exists,
            size_min,
            size_max,
            file_type,
            count_min,
            count_max,
            per_kb_min,
            per_kb_max,
            case_insensitive,
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            external_ip,
            encoding,
            entropy_min,
            entropy_max,
            length_min,
            length_max,
            value_min,
            value_max,
            min_size,
            max_size,
        }) => test_match(
            &target,
            r#type,
            method,
            pattern.as_deref(),
            kv_path.as_deref(),
            exists,
            size_min,
            size_max,
            file_type,
            count_min,
            count_max,
            per_kb_min,
            per_kb_max,
            case_insensitive,
            section.as_deref(),
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            external_ip,
            encoding.as_deref(),
            entropy_min,
            entropy_max,
            length_min,
            length_max,
            value_min,
            value_max,
            min_size,
            max_size,
            &disabled,
            platforms.clone(),
            3.5,
            2.0,
        )?,
        Some(cli::Command::UpdateRules { force, check, pin }) => {
            if let Some(commit) = pin {
                traits_repo::pin(&commit).unwrap_or_else(|e| {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                });
            } else if check {
                traits_repo::check_updates().unwrap_or_else(|e| {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                });
            } else {
                traits_repo::update(force).unwrap_or_else(|e| {
                    eprintln!("Error: {e}");
                    std::process::exit(1);
                });
            }
            return Ok(());
        }
        Some(cli::Command::Serve {
            bind,
            qps,
            timeout,
            max_size_mb,
            max_rss_gb,
            dangerous_local_file_paths,
            extract_dir,
        }) => {
            let bind_addr: std::net::SocketAddr = bind.parse().context(format!(
                "Invalid bind address '{}'. Expected format: IP:PORT (e.g., 127.0.0.1:8080)",
                bind
            ))?;
            // Parse comma-separated directories into canonicalized PathBufs
            let mut allowed_local_paths: Vec<std::path::PathBuf> = dangerous_local_file_paths
                .map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|p| !p.is_empty())
                        .map(|p| {
                            std::path::Path::new(p)
                                .canonicalize()
                                .unwrap_or_else(|_| std::path::PathBuf::from(p))
                        })
                        .collect()
                })
                .unwrap_or_default();

            // Handle extract_dir: canonicalize and add to allowed paths
            let extract_dir_path = extract_dir.map(|p| {
                let path = std::path::PathBuf::from(&p);
                // Create the directory if it doesn't exist
                if !path.exists() {
                    std::fs::create_dir_all(&path).ok();
                }
                path.canonicalize().unwrap_or(path)
            });

            // Auto-add extract_dir to allowed paths
            if let Some(ref extract_path) = extract_dir_path {
                if !allowed_local_paths.contains(extract_path) {
                    allowed_local_paths.push(extract_path.clone());
                }
            }

            let config = cleave::server::ServerConfig {
                bind: bind_addr,
                qps,
                timeout_secs: timeout,
                max_body_size: (max_size_mb * 1024 * 1024) as usize,
                max_rss_bytes: max_rss_gb
                    .map(|gb| gb * 1024 * 1024 * 1024)
                    .unwrap_or_else(sysmem::memory_limit),
                allowed_local_paths,
                extract_dir: extract_dir_path,
            };
            // Run the async server
            let rt = tokio::runtime::Runtime::new().context("Failed to create tokio runtime")?;
            rt.block_on(cleave::server::run(config))?;
            return Ok(());
        }
        None => {
            // No subcommand - use paths from top-level args
            if args.paths.is_empty() {
                anyhow::bail!("No paths specified. Usage: cleave <path>... or cleave <command>");
            }
            let expanded = expand_paths(args.paths, &format);
            if expanded.is_empty() {
                anyhow::bail!("No valid paths found (stdin was empty or contained only comments)");
            }
            // Process each target through analyze_command
            let mut results = Vec::new();
            for target in &expanded {
                results.push(analyze_command(&AnalyzeConfig {
                    target,
                    enable_third_party: enable_third_party_global,
                    format: &format,
                    zip_passwords: &zip_passwords,
                    disabled: &disabled,
                    all_files: args.all_files,
                    sample_extraction: sample_extraction.as_ref(),
                    platforms: &platforms,
                    min_hostile_precision: 3.5,
                    min_suspicious_precision: 2.0,
                    max_memory_file_size,
                    enable_full_validation: false,
                    slow_rule_ms: args.slow_rule_ms,
                    output_to_file: args.output.is_some(),
                    max_scan_file_size,
                    scan_threads: args.scan_threads.unwrap_or(0),
                })?);
            }
            results.join("")
        }
    };

    // Output results
    if let Some(output_path) = args.output {
        fs::write(&output_path, &result)
            .context(format!("Failed to write output to {}", output_path))?;
        if format == cli::OutputFormat::Terminal {
            eprintln!("Results written to: {}", output_path);
        }
    } else {
        // Results go to stdout
        print!("{}", result);
        use std::io::Write;
        if let Err(e) = std::io::stdout().flush() {
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                tracing::info!("stdout pipe closed");
                // Fall through to exit summary logging below
            }
        }
    }

    // Always log exit summary with PID and peak RSS for post-mortem correlation
    {
        use cleave::memory_tracker;
        memory_tracker::global_tracker().log_stats();
        memory_tracker::log_all_memory_stats();
        let total_files = memory_tracker::global_tracker().files_processed();
        let peak_rss = memory_tracker::global_tracker().peak_rss();
        tracing::info!(
            pid = std::process::id(),
            total_files = total_files,
            peak_rss_mb = peak_rss / 1024 / 1024,
            "cleave exiting"
        );
    }

    Ok(())
}
