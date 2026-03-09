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
mod map;
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
    analyze_command, diff_command, expand_paths, profile_command, test_match, test_rules,
    validate_command,
};
use std::fs;
use std::path::Path;
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

/// Determine if CLEAVE_FILE_LOGGING is set and create a log file path.
///
/// When CLEAVE_FILE_LOGGING is set to any non-empty value (e.g., "1", "true", "debug"),
/// this function creates a log file in the OS-appropriate cache directory:
/// - macOS: ~/Library/Caches/cleave/logs/
/// - Linux: ~/.cache/cleave/logs/
/// - Windows: %LOCALAPPDATA%\cleave\logs\
///
/// The log filename includes the PID and timestamp for easy correlation:
/// `cleave-{pid}-{timestamp}.log`
///
/// This is particularly useful for:
/// - Debugging subprocesses launched by trait-basher
/// - Debugging cleave instances launched via LLMs
/// - Post-mortem analysis of OOM or crash scenarios
fn determine_env_log_file() -> Option<String> {
    let env_value = std::env::var("CLEAVE_FILE_LOGGING").ok()?;

    // Only proceed if the env var is set to a non-empty value
    if env_value.is_empty() || env_value == "0" || env_value.eq_ignore_ascii_case("false") {
        return None;
    }

    // Determine the logs directory
    let logs_dir = if let Ok(cache_dir) = cache::cache_dir() {
        cache_dir.join("logs")
    } else if let Some(cache_base) = dirs::cache_dir() {
        cache_base.join("cleave").join("logs")
    } else {
        // Fallback to temp directory
        std::env::temp_dir().join("cleave-logs")
    };

    // Create the logs directory if it doesn't exist
    if let Err(e) = std::fs::create_dir_all(&logs_dir) {
        eprintln!(
            "CLEAVE_FILE_LOGGING: Failed to create logs directory {:?}: {}",
            logs_dir, e
        );
        return None;
    }

    // Generate a unique log filename with PID and timestamp
    let pid = std::process::id();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let log_filename = format!("cleave-{}-{}.log", pid, timestamp);
    let log_path = logs_dir.join(log_filename);

    // Convert to string for the existing log file handling code
    let log_path_str = log_path.to_string_lossy().to_string();

    // Print to stderr so the user knows where logs are going
    // (only in terminal mode, checked later, but we can't know format here yet)
    eprintln!("CLEAVE_FILE_LOGGING: Logging to {}", log_path_str);

    Some(log_path_str)
}

fn main() -> Result<()> {
    // Parse args early to get verbose flag for logging initialization
    let args = cli::Args::parse();
    if args.verbose {
        std::env::set_var("CLEAVE_VERBOSE", "1");
    }

    // Check if running server command (needs info-level logging by default)
    let is_server = matches!(args.command, Some(cli::Command::Server { .. }));

    // Determine output format early so we can use it for conditional status messages
    let format = args.format();

    // Check for CLEAVE_FILE_LOGGING environment variable
    // When set (to any non-empty value), creates a log file in the OS cache directory
    // with debug-level logging. This is useful for debugging subprocesses launched by
    // trait-basher or LLMs where you can't pass --log-file directly.
    let env_log_file = determine_env_log_file();
    let using_env_logging = env_log_file.is_some();

    // Set up logging with optional file output
    // Priority: --log-file flag > CLEAVE_FILE_LOGGING env var
    // When file logging is enabled, use different log levels:
    // - stderr: warn level (quiet, unless --verbose)
    // - file: debug level for CLEAVE_FILE_LOGGING, info level for --log-file
    let effective_log_file = args.log_file.clone().or(env_log_file);

    if let Some(ref log_file) = effective_log_file {
        use std::fs::OpenOptions;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::Layer;

        // Determine log levels
        // CLEAVE_FILE_LOGGING uses debug level by default for comprehensive post-mortem analysis
        let (stderr_filter, file_filter) = if std::env::var("RUST_LOG").is_ok() {
            // RUST_LOG overrides everything
            (EnvFilter::from_default_env(), EnvFilter::from_default_env())
        } else if args.verbose {
            // Verbose: trace to both
            (
                EnvFilter::new("cleave=trace"),
                EnvFilter::new("cleave=trace"),
            )
        } else if is_server {
            // Server mode: info to stderr for request logging, debug to file
            (
                EnvFilter::new("cleave=info"),
                EnvFilter::new("cleave=debug"),
            )
        } else if using_env_logging {
            // CLEAVE_FILE_LOGGING: warn to stderr, debug to file for comprehensive logging
            (
                EnvFilter::new("cleave=warn"),
                EnvFilter::new("cleave=debug"),
            )
        } else {
            // --log-file flag: warn to stderr, info to file
            (EnvFilter::new("cleave=warn"), EnvFilter::new("cleave=info"))
        };

        // Create or append to log file
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

        // Create a MakeWriter implementation for our file
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
                // This has a performance cost but is critical for debugging crashes
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

        // Create layers with separate filters
        let stderr_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_line_number(true)
            .with_writer(std::io::stderr)
            .with_filter(stderr_filter);

        let file_layer = tracing_subscriber::fmt::layer()
            .with_target(true)
            .with_line_number(true)
            .with_ansi(false) // No color codes in file
            .with_writer(LogFile(file))
            .with_filter(file_filter);

        tracing_subscriber::registry()
            .with(stderr_layer)
            .with(file_layer)
            .init();
    } else {
        // No log file - use single filter for stderr only
        let env_filter = if std::env::var("RUST_LOG").is_ok() {
            EnvFilter::from_default_env()
        } else if args.verbose {
            EnvFilter::new("cleave=trace")
        } else if is_server {
            // Server mode defaults to info level for request logging
            EnvFilter::new("cleave=info")
        } else {
            EnvFilter::new("cleave=warn")
        };
        // No log file, just stderr
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_thread_ids(false)
            .with_line_number(true)
            .with_writer(std::io::stderr)
            .init();
    }

    #[cfg(debug_assertions)]
    tracing::warn!("DEBUG binary — cleave will be very slow; use `make release` for production builds");

    // Log command line and initialization with PID and parent PID for debugging
    // subprocess relationships (especially useful for trait-basher debugging)
    let pid = std::process::id();
    let ppid = get_parent_pid();
    tracing::info!(
        pid = pid,
        ppid = ppid,
        env_logging = using_env_logging,
        "cleave started: {}",
        std::env::args().collect::<Vec<_>>().join(" ")
    );
    tracing::debug!(
        pid = pid,
        ppid = ppid,
        verbose = args.verbose,
        validate = std::env::var("CLEAVE_VALIDATE").ok(),
        file_logging = std::env::var("CLEAVE_FILE_LOGGING").ok(),
        "Process context"
    );
    tracing::trace!("Logging initialized (verbose={})", args.verbose);

    // Configure rayon thread pool with larger stack size to handle deeply nested ASTs
    // (e.g., minified JavaScript, malicious files with extreme nesting)
    // Default is ~2MB which can overflow on files with 1000+ nesting levels
    rayon::ThreadPoolBuilder::new()
        .stack_size(8 * 1024 * 1024) // 8MB per thread
        .build_global()
        .ok(); // Ignore error if pool already initialized (e.g., in tests)

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

    // Collect zip passwords (default + custom, unless disabled)
    let zip_passwords: Vec<String> = if args.no_zip_passwords {
        Vec::new()
    } else {
        let mut passwords: Vec<String> = cli::DEFAULT_ZIP_PASSWORDS
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        passwords.extend(args.zip_passwords.clone());
        passwords
    };

    // Determine third_party setting (can come from top-level or subcommand)
    // Third-party YARA is enabled by default; disable with --disable third-party
    let enable_third_party_global = !disabled.third_party;

    // Collect error_if levels for criticality checking
    let error_if_levels = args.error_if_levels();

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

    // Start periodic memory logging when a log file is configured (always-on for
    // post-mortem OOM analysis) or when verbose mode is enabled.
    // This includes both --log-file and CLEAVE_FILE_LOGGING.
    let _memory_logger = if args.verbose || args.log_file.is_some() || using_env_logging {
        use cleave::memory_tracker;
        Some(memory_tracker::start_periodic_logging(
            std::time::Duration::from_secs(10),
        ))
    } else {
        None
    };

    let result = match args.command {
        Some(cli::Command::Analyze { targets }) => {
            let expanded = expand_paths(targets, &format);
            if expanded.is_empty() {
                anyhow::bail!("No valid paths found (stdin was empty or contained only comments)");
            }
            // Process each target through analyze_command
            let mut results = Vec::new();
            for target in &expanded {
                results.push(analyze_command(
                    target,
                    enable_third_party_global,
                    &format,
                    &zip_passwords,
                    &disabled,
                    error_if_levels.as_deref(),
                    args.all_files,
                    args.shuffle,
                    sample_extraction.as_ref(),
                    &platforms,
                    args.min_hostile_precision,
                    args.min_suspicious_precision,
                    max_memory_file_size,
                    false,
                    args.mol.as_deref(),
                    args.mol_layout,
                )?);
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
        Some(cli::Command::TestRules { target, rules }) => test_rules(
            &target,
            &rules,
            &disabled,
            platforms.clone(),
            args.min_hostile_precision,
            args.min_suspicious_precision,
        )?,
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
            args.min_hostile_precision,
            args.min_suspicious_precision,
        )?,
        Some(cli::Command::Map {
            depth,
            output,
            min_refs,
            namespaces,
            from_findings,
            format,
            min_crit,
            show_low_value,
        }) => {
            if let Some(input) = from_findings {
                // Findings mode
                map::generate_findings_map(
                    &input,
                    depth,
                    output.as_deref(),
                    min_refs,
                    namespaces.as_deref(),
                    format,
                    &min_crit,
                    show_low_value,
                )?
            } else {
                // Definition mode (existing behavior)
                map::generate_trait_map(depth, output.as_deref(), min_refs, namespaces.as_deref())?
            }
        }
        Some(cli::Command::YaraProfile { target, min_ms }) => {
            return profile_command(Path::new(&target), min_ms);
        }
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
        Some(cli::Command::Server {
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
                max_rss_bytes: max_rss_gb * 1024 * 1024 * 1024,
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
                results.push(analyze_command(
                    target,
                    enable_third_party_global,
                    &format,
                    &zip_passwords,
                    &disabled,
                    error_if_levels.as_deref(),
                    args.all_files,
                    args.shuffle,
                    sample_extraction.as_ref(),
                    &platforms,
                    args.min_hostile_precision,
                    args.min_suspicious_precision,
                    max_memory_file_size,
                    false,
                    args.mol.as_deref(),
                    args.mol_layout,
                )?);
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
        if args.verbose {
            memory_tracker::global_tracker().log_stats();
        }
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
