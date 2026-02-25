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
mod types;
mod upx;
mod yara_engine;

use anyhow::{Context, Result};
use clap::Parser;
use commands::{
    analyze_command, diff_command, expand_paths, profile_command, test_match, test_rules,
};
use std::fs;
use std::path::Path;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    // Parse args early to get verbose flag for logging initialization
    let args = cli::Args::parse();
    if args.verbose {
        std::env::set_var("cleave_VERBOSE", "1");
    }

    // Determine output format early so we can use it for conditional status messages
    let format = args.format();

    // Set up logging with optional file output
    // When --log-file is specified, use different log levels:
    // - stderr: warn level (quiet, unless --verbose)
    // - file: info level (useful for debugging, unless --verbose then trace)
    if let Some(ref log_file) = args.log_file {
        use std::fs::OpenOptions;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;
        use tracing_subscriber::Layer;

        // Determine log levels
        let (stderr_filter, file_filter) = if std::env::var("RUST_LOG").is_ok() {
            // RUST_LOG overrides everything
            (EnvFilter::from_default_env(), EnvFilter::from_default_env())
        } else if args.verbose {
            // Verbose: trace to both
            (
                EnvFilter::new("cleave=trace"),
                EnvFilter::new("cleave=trace"),
            )
        } else {
            // Default: warn to stderr, info to file
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

    // Log command line and initialization
    tracing::info!(
        "cleave started: {}",
        std::env::args().collect::<Vec<_>>().join(" ")
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
        std::env::set_var("cleave_TRAITS_PATH", traits_dir);
        std::env::set_var("cleave_CAPABILITIES", traits_dir);
    }

    // Apply global disables for radare2 and upx
    if disabled.radare2 {
        radare2::disable_radare2();
    }
    if disabled.upx {
        upx::disable_upx();
    }

    // Print banner to stderr (status info never goes to stdout) - only in terminal mode
    if format == cli::OutputFormat::Terminal {
        // Try to show combined rule count from all sources (YARA + traits + composites)
        let enable_third_party = !disabled.third_party;
        let yara_count = yara_engine::peek_cache_rule_count(enable_third_party).unwrap_or(0);
        let (trait_count, composite_count) = cache::peek_rule_stats().unwrap_or((0, 0));
        let total_rules = yara_count + trait_count + composite_count;

        if total_rules > 0 {
            eprintln!(
                "cleave v{} • {} rules\n",
                env!("CARGO_PKG_VERSION"),
                total_rules
            );
        } else {
            eprintln!(
                "cleave v{} • Deep static analysis tool\n",
                env!("CARGO_PKG_VERSION")
            );
        }
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

    // Start periodic memory logging if verbose mode is enabled
    let _memory_logger = if args.verbose {
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
                    args.verbose,
                    args.all_files,
                    args.shuffle,
                    sample_extraction.as_ref(),
                    &platforms,
                    args.min_hostile_precision,
                    args.min_suspicious_precision,
                    max_memory_file_size,
                    args.validate,
                    args.mol.as_deref(),
                    args.mol_layout,
                )?);
            }
            results.join("")
        }
        Some(cli::Command::Diff { old, new }) => diff_command(&old, &new, &format)?,
        Some(cli::Command::Strings { target, min_length }) => {
            commands::extract::strings::run(&target, min_length, &format)?
        }
        Some(cli::Command::Symbols { target }) => {
            commands::extract::symbols::run(&target, &format)?
        }
        Some(cli::Command::Sections { target }) => {
            commands::extract::sections::run(&target, &format)?
        }
        Some(cli::Command::Metrics { target }) => {
            commands::extract::metrics::run(&target, &format, &disabled)?
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
                    args.verbose,
                    args.all_files,
                    args.shuffle,
                    sample_extraction.as_ref(),
                    &platforms,
                    args.min_hostile_precision,
                    args.min_suspicious_precision,
                    max_memory_file_size,
                    args.validate,
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
    }

    // Log final memory statistics if verbose
    if args.verbose {
        use cleave::memory_tracker;
        memory_tracker::global_tracker().log_stats();
        let total_files = memory_tracker::global_tracker().files_processed();
        let peak_rss = memory_tracker::global_tracker().peak_rss();
        tracing::info!(
            total_files = total_files,
            peak_rss_gb = peak_rss / 1024 / 1024 / 1024,
            "Analysis complete"
        );
    }

    Ok(())
}
