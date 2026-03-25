//! cleave - Deep Inspection of Suspicious Software for Evaluation and Classification of Threats
//!
//! cleave is a comprehensive malware analysis tool that performs deep static analysis
//! of binaries, scripts, and archives to identify malicious behavior patterns and capabilities.

#![allow(unreachable_pub)]

#[cfg(all(
    unix,
    feature = "jemalloc",
    not(any(target_os = "freebsd", target_os = "dragonfly"))
))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

mod cli_bootstrap;
mod cli_dispatch;

use anyhow::Result;
use clap::Parser;
use cleave::cli;
use cli_bootstrap::{
    apply_runtime_overrides, build_sample_extraction, configure_rayon_thread_pool,
    default_zip_passwords, determine_default_log_file, init_logging, log_exit_summary, log_startup,
    log_startup_diagnostics, print_version_banner, start_memory_logger,
};
use cli_dispatch::{build_dispatch_context, dispatch_command, write_output};

fn main() -> Result<()> {
    let args = cli::Args::parse();
    if args.verbose {
        std::env::set_var("CLEAVE_VERBOSE", "1");
    }

    let is_server = matches!(args.command, Some(cli::Command::Serve { .. }));
    let format = args.format();
    let default_log_file = determine_default_log_file();
    let effective_log_file = args.log_file.clone().or(default_log_file);

    init_logging(args.verbose, is_server, format, effective_log_file.as_ref());
    log_startup(effective_log_file.as_ref(), args.verbose);
    configure_rayon_thread_pool();

    let disabled = args.disabled_components();
    apply_runtime_overrides(args.traits_dir.as_ref(), &disabled);
    if !matches!(args.command, Some(cli::Command::Version)) {
        print_version_banner(format);
    }

    let zip_passwords = default_zip_passwords();
    let sample_extraction = build_sample_extraction(args.extract_dir.as_ref());
    let platforms = args.platforms();
    let max_memory_file_size = args.max_file_mem * 1024 * 1024;
    let max_scan_file_size = args.max_file_size * 1024 * 1024;
    let _memory_logger = start_memory_logger(args.verbose, effective_log_file.as_ref());
    log_startup_diagnostics();

    let dispatch_ctx = build_dispatch_context(&cli_dispatch::DispatchOptions {
        format: &format,
        disabled: &disabled,
        zip_passwords: &zip_passwords,
        sample_extraction: sample_extraction.as_ref(),
        platforms: &platforms,
        slow_rule_ms: args.slow_rule_ms,
        output_to_file: args.output.is_some(),
        max_memory_file_size,
        max_scan_file_size,
        scan_threads: args.scan_threads.unwrap_or(0),
        min_crit: args.min_crit,
        max_crit: args.max_crit,
        min_file_crit: args.min_file_crit,
        max_file_crit: args.max_file_crit,
        all_files: args.all_files,
    });
    let output_path = args.output.clone();

    let Some(result) = dispatch_command(args, &dispatch_ctx)? else {
        return Ok(());
    };

    write_output(&result, output_path, format)?;
    log_exit_summary();
    Ok(())
}
