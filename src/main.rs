//! cleave - Deep Inspection of Suspicious Software for Evaluation and Classification of Threats
//!
//! cleave is a comprehensive malware analysis tool that performs deep static analysis
//! of binaries, scripts, and archives to identify malicious behavior patterns and capabilities.

#![allow(unreachable_pub)]

/// jemalloc, plus the compile-time tuning it reads at initialization.
///
/// Allocator and configuration share one `cfg` so they cannot drift apart: a
/// build that swaps in the system allocator must not leave a `_rjem_malloc_conf`
/// symbol behind, and one that uses jemalloc must never be left unconfigured.
/// The excluded targets match atomscan's, and are the platforms where this
/// crate does not link tikv-jemallocator; on FreeBSD the *system* malloc is
/// jemalloc, but it reads the unprefixed `MALLOC_CONF` / `/etc/malloc.conf`, so
/// this symbol would not reach it anyway.
///
/// See [`cleave::JEMALLOC_CONF`] for what each option buys. In short: on 64-bit
/// Linux jemalloc defaults `retain` to true, which fragments the address space
/// until `mmap` returns `ENOMEM` and the process aborts with RSS nowhere near
/// any limit. `iter-files` and a long `scan` hit that the same way a worker
/// does, so the CLI needs the tuning too.
///
/// Runtime configuration still wins: jemalloc applies its compiled-in string
/// first, then `/etc/malloc.conf`, then the environment, with later sources
/// overriding earlier ones per key. The environment variable is
/// `_RJEM_MALLOC_CONF` — `tikv-jemallocator` builds jemalloc with the `_rjem_`
/// prefix, so plain `MALLOC_CONF` is silently ignored.
#[cfg(all(
    unix,
    feature = "jemalloc",
    not(feature = "memprofile-win"),
    not(any(
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "illumos",
        target_os = "solaris",
    ))
))]
mod jemalloc {
    #[global_allocator]
    static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

    /// A `Sync` wrapper so a raw `*const c_char` can live in a static;
    /// jemalloc reads the pointer, it is never written after link time.
    #[repr(transparent)]
    struct SyncPtr(*const std::os::raw::c_char);
    // SAFETY: the pointer targets a NUL-terminated 'static CStr and is never
    // mutated, so sharing it across threads is sound.
    unsafe impl Sync for SyncPtr {}

    #[allow(non_upper_case_globals)]
    #[unsafe(no_mangle)]
    static _rjem_malloc_conf: SyncPtr = SyncPtr(cleave::JEMALLOC_CONF.as_ptr());
}

#[cfg(feature = "memprofile-win")]
mod memprofile_win_alloc {
    #[global_allocator]
    static GLOBAL: cleave::mem_profile::CountingAlloc = cleave::mem_profile::CountingAlloc;
}

mod cli_bootstrap;
mod cli_dispatch;

use anyhow::Result;
// Only the `#[cfg(unix)]` SIGUSR1 backtrace thread calls `.context()`, so on
// Windows this import is unused — and `unused_imports = "deny"` makes that a
// build failure rather than a warning. That is what kept Windows binaries out
// of every release through 2.7.1.
#[cfg(unix)]
use anyhow::Context;
use clap::Parser;
use cleave::cli;
#[cfg(feature = "deadlock-detection")]
use cli_bootstrap::start_deadlock_detector;
use cli_bootstrap::{
    apply_runtime_overrides, build_sample_extraction, configure_rayon_thread_pool,
    determine_default_log_file, init_logging, log_exit_summary, log_startup, print_version_banner,
    start_memory_logger,
};
use cli_dispatch::{build_dispatch_context, dispatch_command, write_output};

fn main() -> Result<()> {
    // Block SIGUSR1 process-wide before spawning any threads so they all inherit
    // the blocked mask; the dedicated sigusr1 thread below consumes it via sigwait.
    #[cfg(unix)]
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGUSR1);
        libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());
    }
    // Allow a forked debugger to ptrace us under yama.ptrace_scope=1.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY, 0, 0, 0);
    }

    let args = cli::Args::parse();

    let is_server = matches!(args.command, Some(cli::Command::Serve { .. }));

    // CLI scans run on rayon with no tokio runtime, so tokio::signal isn't
    // available. Install a libc signal handler that flips a global
    // cancellation flag on SIGINT/SIGTERM so long scans drain cleanly on
    // Ctrl-C (second Ctrl-C forces exit). Skip for server mode — tokio
    // installs its own handlers and would clobber ours.
    if !is_server {
        cleave::cancellation::install_signal_handlers();
    }

    // Dump all thread backtraces on SIGUSR1 (Linux equivalent of BSD SIGINFO / Ctrl-T).
    // Attaches lldb/gdb to ourselves so every thread is reported with symbols.
    #[cfg(unix)]
    std::thread::Builder::new()
        .name("sigusr1".into())
        .spawn(|| {
            use std::io::Write;
            use std::process::{Command, Stdio};
            let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&mut mask);
                libc::sigaddset(&mut mask, libc::SIGUSR1);
            }
            loop {
                let mut sig: libc::c_int = 0;
                if unsafe { libc::sigwait(&mask, &mut sig) } != 0 {
                    continue;
                }
                let pid = std::process::id().to_string();
                let _ = writeln!(
                    std::io::stderr(),
                    "\n--- SIGUSR1 all-thread backtrace (pid {pid}) ---"
                );
                let lldb = Command::new("lldb")
                    .args([
                        "--batch",
                        "-p",
                        &pid,
                        "-o",
                        "thread backtrace all",
                        "-o",
                        "detach",
                        "-o",
                        "quit",
                    ])
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .status();
                if !matches!(lldb, Ok(s) if s.success()) {
                    let _ = Command::new("gdb")
                        .args([
                            "-batch",
                            "-nx",
                            "-p",
                            &pid,
                            "-ex",
                            "thread apply all bt",
                            "-ex",
                            "detach",
                            "-ex",
                            "quit",
                        ])
                        .stdout(Stdio::inherit())
                        .stderr(Stdio::inherit())
                        .status();
                }
                let _ = writeln!(std::io::stderr(), "--- end backtrace ---\n");
            }
        })
        .context("failed to spawn SIGUSR1 thread")?;

    let format = args.format();
    // Only create a default log file in server mode — CLI runs at warn level
    // typically produce empty 0-byte log files that just accumulate.
    let default_log_file = if is_server {
        determine_default_log_file()
    } else {
        None
    };
    let effective_log_file = args.log_file.clone().or(default_log_file);

    // `cleave validate` is meant to print a single summary line on success, so
    // suppress the global `warn` tracing floor (e.g. goblin's benign fat-Mach-O
    // offset warnings on testdata fixtures) unless `--verbose` is requested.
    let is_validate_command = matches!(args.command, Some(cli::Command::Validate { .. }));

    init_logging(
        args.verbose,
        is_server,
        is_validate_command,
        format,
        effective_log_file.as_deref(),
    );
    log_startup(effective_log_file.as_deref(), args.verbose);

    // Limit concurrency to reduce peak RSS (especially during archive analysis).
    // Configured via rayon::ThreadPoolBuilder in cli_bootstrap.
    configure_rayon_thread_pool();

    #[cfg(feature = "deadlock-detection")]
    start_deadlock_detector();

    let disabled = args.disabled_components();
    apply_runtime_overrides(args.traits_dir.as_deref(), &disabled);
    // `cleave validate` runs deterministic fixture scoring with YARA disabled,
    // so skip the ~4 s (release) / ~18 s (debug) compile of 14 k+ inline YARA
    // rules that the prefetch triggers. Trait-structure validation doesn't
    // require YARA to have compiled either — mapper loading is independent.
    if !disabled.yara && !is_validate_command {
        cleave::prefetch_yara_engine(!disabled.third_party);
    }
    // `Version` prints its own banner; `Validate` emits a single summary line
    // and suppresses the banner to stay terse on success.
    if !matches!(
        args.command,
        Some(cli::Command::Version) | Some(cli::Command::Validate { .. })
    ) {
        print_version_banner(format);
    }

    // Interactive runs get a once-a-day, zero-telemetry update notice. The
    // long-running server is excluded — it refreshes on restart and shouldn't
    // print transient notices into its logs.
    if !is_server {
        cleave::update_check::maybe_notify(args.no_update_check);
    }

    let zip_passwords = args.archive_passwords();
    let sample_extraction = build_sample_extraction(args.extract_dir.as_deref());
    let platforms = args.platforms();
    let max_memory_file_size = args.max_file_mem * 1024 * 1024;
    let max_scan_file_size = args.max_file_size * 1024 * 1024;
    let _memory_logger = start_memory_logger(args.verbose, effective_log_file.as_deref());
    cleave::memory_tracker::log_startup_diagnostics();

    let output_path = args.output.clone();
    let dispatch_ctx = build_dispatch_context(&cli_dispatch::DispatchOptions {
        format: &format,
        disabled: &disabled,
        zip_passwords: &zip_passwords,
        sample_extraction: sample_extraction.as_ref(),
        platforms: &platforms,
        slow_rule_ms: args.slow_rule_ms,
        output_to_file: args.output.is_some(),
        output_path: output_path.as_deref(),
        max_memory_file_size,
        max_scan_file_size,
        min_crit: args.min_crit,
        max_crit: args.max_crit,
        min_file_crit: args.min_file_crit,
        max_file_crit: args.max_file_crit,
        all_files: args.all_files,
    });

    let Some(result) = dispatch_command(args, &dispatch_ctx)? else {
        return Ok(());
    };

    write_output(&result, output_path, format)?;
    log_exit_summary();
    Ok(())
}
