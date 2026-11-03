use cleave::cli;
use tracing_subscriber::EnvFilter;

pub(crate) fn parent_pid() -> u32 {
    // The parent pid is one syscall; this used to spawn `ps` on macOS, looked
    // up on PATH, where a planted `./ps` could run at startup.
    #[cfg(unix)]
    {
        std::os::unix::process::parent_id()
    }

    #[cfg(not(unix))]
    {
        0
    }
}

/// The log level `CLEAVE_LOG_LEVEL` names, when it names one.
fn env_log_level() -> Option<&'static str> {
    match std::env::var("CLEAVE_LOG_LEVEL")
        .ok()?
        .to_lowercase()
        .as_str()
    {
        "trace" => Some("trace"),
        "debug" => Some("debug"),
        "info" => Some("info"),
        "warn" | "warning" => Some("warn"),
        "error" => Some("error"),
        _ => None,
    }
}

fn scoped_filter(level: &str) -> String {
    format!("cleave={level},stng={level}")
}

/// Field formatter that escapes terminal control characters in every event
/// field, not just the message. Wrapped in `.delimited(" ")` at each use:
/// a custom field formatter writes fields back to back unless told otherwise.
///
/// tracing-subscriber's default formatter escapes the `message` field and
/// error values, but writes named fields (e.g. `path = %display`) raw — and
/// cleave logs hostile-derived file names and paths in exactly those. An
/// escape sequence inside one can rewrite an operator's terminal or poison a
/// log file. This applies the same escaping to every field's rendered value.
fn sanitized_field(
    writer: &mut tracing_subscriber::fmt::format::Writer<'_>,
    field: &tracing::field::Field,
    value: &dyn std::fmt::Debug,
) -> std::fmt::Result {
    use std::fmt::Write;

    let mut rendered = String::new();
    write!(rendered, "{value:?}")?;
    let rendered = cleave::output::escape_log_field(&rendered);

    // Same shape as the default formatter: the message field prints bare,
    // `r#` names drop the prefix, everything else prints `name=value`.
    let name = field.name();
    if name == "message" {
        write!(writer, "{rendered}")
    } else {
        let name = name.strip_prefix("r#").unwrap_or(name);
        write!(writer, "{name}={rendered}")
    }
}

pub(crate) fn apply_runtime_overrides(traits_dir: Option<&str>) {
    if let Some(traits_dir) = traits_dir {
        cleave::traits_repo::set_override_dir(Some(std::path::PathBuf::from(traits_dir)));
    }
}

pub(crate) fn init_logging(verbose: bool, is_validate: bool) {
    let env_filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else if verbose {
        EnvFilter::new(scoped_filter("trace"))
    } else if let Some(level) = env_log_level() {
        EnvFilter::new(scoped_filter(level))
    } else if is_validate {
        // `validate` prints a single summary line on success; drop the
        // global `warn` floor so benign third-party warnings (e.g. goblin's
        // fat-Mach-O offset warnings on testdata fixtures) stay silent.
        EnvFilter::new("error")
    } else {
        // Global `warn` floor rather than a cleave-scoped one: a target-scoped
        // `cleave=warn` directive was swallowing `cleave::context` errors (and
        // any other crate's warnings) on stderr, so genuine problems went
        // unseen at the default verbosity.
        EnvFilter::new("warn")
    };
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_line_number(true)
        .with_writer(std::io::stderr)
        .fmt_fields({
            use tracing_subscriber::field::MakeExt;
            tracing_subscriber::fmt::format::debug_fn(sanitized_field).delimited(" ")
        })
        .init();
}

/// Flip the library's cancellation flag on SIGINT/SIGTERM so long scans drain
/// cleanly; a second signal exits. Runs on the `ctrlc` dispatch thread.
pub(crate) fn install_signal_handlers() {
    let flag = cleave::cancellation::global_flag();
    let result = ctrlc::set_handler(move || {
        if flag.swap(true, std::sync::atomic::Ordering::SeqCst) {
            eprintln!("\n[cleave] second interrupt, forcing exit");
            std::process::exit(130);
        }
        eprintln!("\n[cleave] interrupt received, draining workers (Ctrl-C again to force exit)");
    });
    if let Err(error) = result {
        tracing::warn!(%error, "could not install cancellation signal handler");
    }
}

pub(crate) fn log_startup(verbose: bool) {
    #[cfg(debug_assertions)]
    tracing::warn!(
        "DEBUG binary — cleave will be very slow; use `make release` for production builds"
    );

    let pid = std::process::id();
    let ppid = parent_pid();
    tracing::info!(
        pid = pid,
        ppid = ppid,
        "cleave started: {}",
        std::env::args().collect::<Vec<_>>().join(" ")
    );
    tracing::debug!(
        pid = pid,
        ppid = ppid,
        verbose = verbose,
        validate = std::env::var("CLEAVE_VALIDATE").ok(),
        log_level = std::env::var("CLEAVE_LOG_LEVEL").ok(),
        "Process context"
    );
    tracing::trace!("Logging initialized (verbose={})", verbose);
}

fn preferred_core_count(
    physical: Option<usize>,
    logical: Option<usize>,
    validating: bool,
) -> Option<usize> {
    // Apple Silicon has no SMT. Independent validation fixtures also use the
    // efficiency cores profitably; single-archive scans retain their measured
    // performance-core default. Explicit CLEAVE_RAYON_THREADS still wins.
    if validating && cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        logical.or(physical)
    } else {
        physical
    }
}

pub(crate) fn configure_rayon_thread_pool(validating: bool) {
    // Archive analysis nests `par_iter` up to 2 levels deep (outer member
    // walk + JAR class-file YARA scan). With fewer than ~4 workers the
    // inner par_iter can commit every thread and the outer join has no
    // reaper — a true nested-join deadlock that work-stealing cannot
    // escape.
    //
    // The default pool sizes to the *physical*-core count, which is where this
    // CPU-bound, archive-heavy workload peaks. Evidence on two layouts:
    //   • Apple Silicon (12 P-cores): a 9-point sweep (6..16) put the wall
    //     optimum at the full P-core count once members analyze in parallel
    //     (wall fell monotonically 6→12, par 4.7x→7.5x); the efficiency cores
    //     only regressed (14/16 ~+7%).
    //   • AMD Threadripper (64 cores / 128 threads, x86-64 Linux + SMT): a
    //     ternary sweep on [32,128] over the realworld benchmark put the wall
    //     optimum at 64 (= physical cores). 96 cost +13%, and the full-SMT end
    //     was worse still — the hyperthread siblings only add scheduler
    //     contention once every core is fed.
    // So past the physical-core count the extra (SMT) workers don't help and
    // can hurt; sysmem::physical_cpu_count() is the basis everywhere it can be
    // detected. Override via CLEAVE_RAYON_THREADS when in doubt.
    const MIN_SAFE_THREADS: usize = 4;

    let mut builder = rayon::ThreadPoolBuilder::new().stack_size(8 * 1024 * 1024);
    let explicit = std::env::var("CLEAVE_RAYON_THREADS")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok());

    if let Some(threads) = explicit {
        if threads < MIN_SAFE_THREADS {
            tracing::warn!(
                threads,
                min_safe = MIN_SAFE_THREADS,
                "CLEAVE_RAYON_THREADS below minimum safe value; archive analysis \
                 may deadlock on nested par_iter. Set CLEAVE_RAYON_THREADS >= {} \
                 unless you know what you're doing.",
                MIN_SAFE_THREADS,
            );
        }
        builder = builder.num_threads(threads);
    } else {
        // `logical` is affinity-aware (respects cgroup quotas / processor
        // sets); `physical` reflects host topology. Prefer physical, but never
        // exceed logical — in a CPU-capped container sysfs still sees every
        // host core, and oversubscribing the allotment would only thrash.
        let logical = cleave::memory_tracker::cpu_count();
        let physical = preferred_core_count(
            cleave::memory_tracker::physical_cpu_count(),
            logical,
            validating,
        );

        let threads = match (physical, logical) {
            (Some(p), Some(l)) => p.min(l).max(MIN_SAFE_THREADS),
            (Some(p), None) => p.max(MIN_SAFE_THREADS),
            // Physical undetectable but logical known: assume SMT and halve.
            // A heuristic — it under-subscribes a non-SMT host — so warn and
            // point at the override.
            (None, Some(l)) => {
                tracing::warn!(
                    logical_cpus = l,
                    "physical-core count undetectable on this platform; defaulting the \
                     rayon pool to logical/2 (SMT heuristic). Set CLEAVE_RAYON_THREADS \
                     to your physical-core count for best throughput.",
                );
                (l / 2).max(MIN_SAFE_THREADS)
            }
            // Nothing detectable at all — a genuinely undetermined host.
            (None, None) => {
                tracing::warn!(
                    fallback = MIN_SAFE_THREADS,
                    "CPU count undetectable; rayon pool DOWNGRADED to {MIN_SAFE_THREADS} \
                     threads. On a many-core host this throttles throughput — set \
                     CLEAVE_RAYON_THREADS to your physical-core count.",
                );
                MIN_SAFE_THREADS
            }
        };
        builder = builder.num_threads(threads);
    }

    // build_global fails if a pool is already installed (e.g. by a parent
    // binary like an embedding host). That's the desired behaviour — we only configure
    // the pool when cleave owns it.
    let installed = builder.build_global().is_ok();
    let active = rayon::current_num_threads();
    tracing::info!(
        installed_by_cleave = installed,
        threads = active,
        "rayon pool ready"
    );
}

pub(crate) fn print_version_banner(format: cli::OutputFormat) {
    if format != cli::OutputFormat::Json {
        let traits_ver = cleave::traits_repo::version()
            .map(|v| format!(": {v}"))
            .unwrap_or_default();
        eprintln!(
            "cleave v{} ({} traits{traits_ver})\n",
            env!("CARGO_PKG_VERSION"),
            cleave::traits_repo::Edition::current().styled()
        );
    }
}

pub(crate) fn start_memory_logger(
    verbose: bool,
) -> Option<cleave::memory_tracker::MemoryLoggerHandle> {
    if verbose {
        use cleave::memory_tracker;
        Some(memory_tracker::start_periodic_logging(
            std::time::Duration::from_secs(10),
            sysmem::memory_limit(),
            || {
                eprintln!("[cleave] memory cap exceeded for >30s, exiting to avoid an OOM kill");
                std::process::exit(1);
            },
        ))
    } else {
        None
    }
}

/// Spawn a background thread that periodically checks for `parking_lot` lock cycles.
///
/// Only compiled with the `deadlock-detection` feature (which pulls in
/// `parking_lot/deadlock_detection`). Off by default — that feature taxes every
/// lock op. Logs a tracing error with thread IDs and backtrace on a lock cycle.
#[cfg(feature = "deadlock-detection")]
pub(crate) fn start_deadlock_detector() {
    let result = std::thread::Builder::new()
        .name("deadlock-detector".into())
        .spawn(|| {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let deadlocks = parking_lot::deadlock::check_deadlock();
                if deadlocks.is_empty() {
                    continue;
                }
                tracing::error!(
                    count = deadlocks.len(),
                    "parking_lot deadlock detected — threads involved:"
                );
                for (i, threads) in deadlocks.iter().enumerate() {
                    for t in threads {
                        tracing::error!(
                            cycle = i,
                            thread_id = ?t.thread_id(),
                            backtrace = ?t.backtrace(),
                            "deadlocked thread"
                        );
                    }
                }
            }
        });
    if let Err(e) = result {
        tracing::warn!(error = %e, "Failed to spawn deadlock-detector thread");
    }
}

pub(crate) fn log_exit_summary() {
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

#[test]
fn validation_pool_core_preference() {
    assert_eq!(preferred_core_count(Some(12), Some(36), false), Some(12));
    assert_eq!(preferred_core_count(Some(12), None, true), Some(12));
    assert_eq!(preferred_core_count(None, None, true), None);
    let expected = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some(36)
    } else {
        Some(12)
    };
    assert_eq!(preferred_core_count(Some(12), Some(36), true), expected);
}
