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
    apply_runtime_overrides, configure_rayon_thread_pool, init_logging, log_exit_summary,
    log_startup, print_version_banner, start_memory_logger,
};
use cli_dispatch::{build_dispatch_context, dispatch_command, write_output};

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            let rendered = format!("Error: {error:#}\n");
            eprint!("{}", cleave::output::sanitize_terminal_output(&rendered));
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    // Self-debugging hooks are opt-in with `CLEAVE_DEBUG_BACKTRACE=1`: they let
    // any same-user process ptrace this one and make SIGUSR1 run lldb/gdb from
    // `PATH`. A tool that reads hostile files should not weaken its own process
    // isolation by default.
    #[cfg(unix)]
    let debug_backtraces = std::env::var_os("CLEAVE_DEBUG_BACKTRACE").is_some_and(|v| v == "1");

    // Block SIGUSR1 process-wide before spawning any threads so they all inherit
    // the blocked mask. With backtraces enabled the sigusr1 thread below consumes
    // it via sigwait; without, a stray SIGUSR1 stays pending instead of taking
    // its default action, which is to terminate the process.
    #[cfg(unix)]
    // SAFETY: `sigset_t` is plain data, so a zeroed value is valid and
    // `sigemptyset` initializes it; every pointer is to this local or null.
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGUSR1);
        libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());
    }
    // Allow a forked debugger to ptrace us under yama.ptrace_scope=1.
    #[cfg(target_os = "linux")]
    if debug_backtraces {
        // SAFETY: `prctl(PR_SET_PTRACER, ...)` takes integers and touches no memory of ours.
        unsafe {
            libc::prctl(libc::PR_SET_PTRACER, libc::PR_SET_PTRACER_ANY, 0, 0, 0);
        }
    }

    let args = cli::Args::parse();

    // Offline rendering must not initialize analysis, update rules, or touch
    // the original sample. Keep this before all analysis bootstrap work.
    if let Some(cli::Command::Render { args: render_args }) = &args.command {
        let format = args.format();
        anyhow::ensure!(
            !(args.model_facts || args.share_analyses)
                || matches!(format, cli::OutputFormat::Json | cli::OutputFormat::Jsonl),
            "--model-facts and --share-analyses require render --format json or jsonl"
        );
        let rendered = cleave::report_input::run(render_args, |loaded| {
            if matches!(
                format,
                cli::OutputFormat::Json | cli::OutputFormat::Jsonl | cli::OutputFormat::Snapshot
            ) {
                anyhow::ensure!(
                    loaded.warnings.is_empty(),
                    "replayable JSON requires an annotated snapshot; capture with --format snapshot instead of rewriting reconstructed input"
                );
            }
            if args.trim_context {
                anyhow::ensure!(
                    cleave::output::TinyOpts::tiny().lean_rows,
                    "--trim-context requires the default lean tiny renderer; unset CLEAVE_TINY_LEGACY_WINDOWS"
                );
                cleave::context_retention::trim(&mut loaded.report);
            }
            let report = &loaded.report;
            match format {
                cli::OutputFormat::Json | cli::OutputFormat::Jsonl => {
                    let mut wire = if args.model_facts {
                        cleave::file_wire::Report::for_model(report)?
                    } else {
                        cleave::file_wire::Report::from_analysis(report)?
                    };
                    wire.fetched = loaded.fetched.clone();
                    wire.rev = loaded.traits_version.clone();
                    if !args.model_facts {
                        wire.fp = loaded.fact_profile.clone();
                    }
                    let mut json = if args.share_analyses {
                        serde_json::to_string(&wire.into_shared()?)?
                    } else {
                        serde_json::to_string(&wire)?
                    };
                    json.push('\n');
                    return Ok(json);
                }
                cli::OutputFormat::Snapshot => {
                    anyhow::ensure!(
                        loaded.fact_profile.is_none(),
                        "retained facts require diagnostic JSON, not a full raw snapshot"
                    );
                    return Ok(serde_json::to_string(report)? + "\n");
                }
                _ => {}
            }
            let opts = match format {
                cli::OutputFormat::Tiny => cleave::output::TinyOpts::tiny(),
                cli::OutputFormat::Terminal => cleave::output::TinyOpts::terminal(),
                _ => anyhow::bail!("render supports --format terminal or tiny"),
            };
            Ok(cleave::output::format_context(report, &opts))
        })?;
        return write_output(&rendered, args.output, format);
    }
    anyhow::ensure!(
        !args.trim_context && !args.model_facts && !args.share_analyses,
        "--trim-context, --model-facts and --share-analyses are supported by the render command only"
    );

    // CLI scans run on rayon with no tokio runtime, so tokio::signal isn't
    // available. Install a libc signal handler that flips a global
    // cancellation flag on SIGINT/SIGTERM so long scans drain cleanly on
    // Ctrl-C (second Ctrl-C forces exit).
    cleave::cancellation::install_signal_handlers();

    // Dump all thread backtraces on SIGUSR1 (Linux equivalent of BSD SIGINFO / Ctrl-T).
    // Attaches lldb/gdb to ourselves so every thread is reported with symbols.
    #[cfg(unix)]
    if debug_backtraces {
        std::thread::Builder::new()
            .name("sigusr1".into())
            .spawn(|| {
                use std::io::Write;
                use std::process::{Command, Stdio};
                // SAFETY: `sigset_t` is plain data, so a zeroed value is valid.
                let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
                // SAFETY: both calls write only to the local `mask`.
                unsafe {
                    libc::sigemptyset(&mut mask);
                    libc::sigaddset(&mut mask, libc::SIGUSR1);
                }
                loop {
                    let mut sig: libc::c_int = 0;
                    // SAFETY: `sigwait` reads the local `mask` and writes the local `sig`.
                    if unsafe { libc::sigwait(&mask, &mut sig) } != 0 {
                        continue;
                    }
                    let pid = std::process::id().to_string();
                    let _ = writeln!(
                        std::io::stderr(),
                        "\n--- SIGUSR1 all-thread backtrace (pid {pid}) ---"
                    );
                    // Resolved to absolute paths, never searched for on a
                    // PATH that may name the working directory.
                    let lldb_ok = filefacts::tools::resolve("lldb").is_some_and(|lldb| {
                        Command::new(lldb)
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
                            .status()
                            .is_ok_and(|s| s.success())
                    });
                    if !lldb_ok && let Some(gdb) = filefacts::tools::resolve("gdb") {
                        let _ = Command::new(gdb)
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
    }

    // Facts always returns JSON, even without --format. Applying the terminal
    // sanitizer to it replaces raw DEL/C1/bidi characters with non-JSON \u{...}
    // escapes and corrupts the authoring data stream.
    let format = if matches!(args.command, Some(cli::Command::Facts { .. })) {
        cli::OutputFormat::Json
    } else {
        args.format()
    };
    let effective_log_file = args.log_file.clone();

    // `cleave validate` is meant to print a single summary line on success, so
    // suppress the global `warn` tracing floor (e.g. goblin's benign fat-Mach-O
    // offset warnings on testdata fixtures) unless `--verbose` is requested.
    let is_validate_command = matches!(args.command, Some(cli::Command::Validate { .. }));

    init_logging(
        args.verbose,
        is_validate_command,
        format,
        effective_log_file.as_deref(),
    );
    log_startup(effective_log_file.as_deref(), args.verbose);

    // Limit concurrency to reduce peak RSS (especially during archive analysis).
    // Configured via rayon::ThreadPoolBuilder in cli_bootstrap.
    configure_rayon_thread_pool(is_validate_command);

    #[cfg(feature = "deadlock-detection")]
    start_deadlock_detector();

    let disabled = args.disabled_components();
    apply_runtime_overrides(args.traits_dir.as_deref(), args.enriched, &disabled);
    // `cleave validate` defaults to deterministic scoring with YARA disabled;
    // explicitly enabled fixtures load it lazily.
    // Skip the ~4 s (release) / ~18 s (debug) compile of 14 k+ inline YARA
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

    // Interactive runs get a once-a-day, zero-telemetry update notice.
    cleave::update_check::maybe_notify(args.no_update_check);

    let zip_passwords = args.archive_passwords();
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
