use cleave::cli;
use tracing_subscriber::EnvFilter;

pub(crate) fn get_parent_pid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(stat) = std::fs::read_to_string("/proc/self/stat")
            && let Some(close_paren) = stat.rfind(')')
        {
            let after_comm = &stat[close_paren + 1..];
            let fields: Vec<&str> = after_comm.split_whitespace().collect();
            if fields.len() > 1
                && let Ok(ppid) = fields[1].parse::<u32>()
            {
                return ppid;
            }
        }
        0
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("ps")
            .args(["-o", "ppid=", "-p", &std::process::id().to_string()])
            .output()
            && output.status.success()
        {
            let ppid_str = String::from_utf8_lossy(&output.stdout);
            if let Ok(ppid) = ppid_str.trim().parse::<u32>() {
                return ppid;
            }
        }
        0
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        0
    }
}

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

fn scoped_filter(level: &str) -> String {
    format!("cleave={level},stng={level}")
}

pub(crate) fn determine_default_log_file() -> Option<String> {
    let logs_dir = if let Ok(dir) = std::env::var("CLEAVE_LOGS_DIR") {
        if dir.is_empty() {
            return None;
        }
        std::path::PathBuf::from(dir)
    } else if let Some(state_dir) = dirs::state_dir() {
        // XDG_STATE_HOME (~/.local/state) is the correct place for logs,
        // not XDG_CACHE_HOME (~/.cache) which is for disposable data.
        state_dir.join("atomdrift").join("cleave").join("logs")
    } else if let Some(cache_base) = dirs::cache_dir() {
        // macOS/Windows: no XDG state dir, fall back to cache
        cache_base.join("atomdrift").join("cleave").join("logs")
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

pub(crate) fn apply_runtime_overrides(
    traits_dir: Option<&str>,
    disabled: &cli::DisabledComponents,
) {
    if let Some(traits_dir) = traits_dir {
        cleave::traits_repo::set_override_dir(Some(std::path::PathBuf::from(traits_dir)));
    }

    if disabled.radare2 {
        filefacts::rizin::disable();
    }
    if disabled.upx {
        cleave::disable_upx();
    }
}

pub(crate) fn default_zip_passwords() -> Vec<String> {
    cli::DEFAULT_ZIP_PASSWORDS
        .iter()
        .copied()
        .map(str::to_string)
        .collect()
}

pub(crate) fn build_sample_extraction(
    extract_dir: Option<&str>,
) -> Option<cleave::SampleExtractionConfig> {
    extract_dir.map(|dir| {
        let path = std::path::PathBuf::from(dir);
        if let Err(e) = std::fs::create_dir_all(&path) {
            eprintln!("Warning: could not create extract directory {}: {}", dir, e);
        }
        cleave::SampleExtractionConfig::new(path)
    })
}

pub(crate) fn init_logging(
    verbose: bool,
    is_server: bool,
    format: cli::OutputFormat,
    effective_log_file: Option<&str>,
) {
    if let Some(log_file) = effective_log_file {
        use std::fs::OpenOptions;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::Layer;
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let (stderr_filter, file_filter) = if std::env::var("RUST_LOG").is_ok() {
            (EnvFilter::from_default_env(), EnvFilter::from_default_env())
        } else if verbose {
            (
                EnvFilter::new(scoped_filter("debug")),
                EnvFilter::new(scoped_filter("debug")),
            )
        } else if is_server {
            (
                EnvFilter::new(scoped_filter("info")),
                EnvFilter::new(scoped_filter(file_log_level())),
            )
        } else {
            // Global `warn` floor rather than a cleave-scoped one: a
            // target-scoped `cleave=warn` directive was swallowing
            // `cleave::context` errors (and any other crate's warnings) on
            // stderr, so genuine problems went unseen at the default verbosity.
            // The file layer stays scoped to keep the persistent log focused.
            (
                EnvFilter::new("warn"),
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

        if is_server && format == cli::OutputFormat::Terminal {
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
        let env_filter = if std::env::var("RUST_LOG").is_ok() {
            EnvFilter::from_default_env()
        } else if verbose {
            EnvFilter::new(scoped_filter("trace"))
        } else if is_server {
            EnvFilter::new(scoped_filter("info"))
        } else {
            // Global `warn` floor — see the stderr-filter note above; surfaces
            // warnings/errors from every crate when there's no log file.
            EnvFilter::new("warn")
        };
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_thread_ids(false)
            .with_line_number(true)
            .with_writer(std::io::stderr)
            .init();
    }
}

pub(crate) fn log_startup(effective_log_file: Option<&str>, verbose: bool) {
    #[cfg(debug_assertions)]
    tracing::warn!(
        "DEBUG binary — cleave will be very slow; use `make release` for production builds"
    );

    let pid = std::process::id();
    let ppid = get_parent_pid();
    tracing::info!(
        pid = pid,
        ppid = ppid,
        log_file = effective_log_file.unwrap_or("none"),
        "cleave started: {}",
        std::env::args().collect::<Vec<_>>().join(" ")
    );
    tracing::debug!(
        pid = pid,
        ppid = ppid,
        verbose = verbose,
        validate = std::env::var("CLEAVE_VALIDATE").ok(),
        logs_dir = std::env::var("CLEAVE_LOGS_DIR").ok(),
        log_level = std::env::var("CLEAVE_LOG_LEVEL").ok(),
        "Process context"
    );
    tracing::trace!("Logging initialized (verbose={})", verbose);
}

pub(crate) fn configure_rayon_thread_pool() {
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
        .and_then(|s| s.parse().ok());

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
        let physical = cleave::memory_tracker::physical_cpu_count();

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
    // binary like litmus). That's the desired behaviour — we only configure
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
    if format == cli::OutputFormat::Terminal {
        let traits_ver = cleave::traits_repo::version()
            .map(|v| format!(" (traits: {v})"))
            .unwrap_or_default();
        eprintln!("cleave v{}{traits_ver}\n", env!("CARGO_PKG_VERSION"));
    }
}

pub(crate) fn start_memory_logger(
    verbose: bool,
    effective_log_file: Option<&str>,
) -> Option<cleave::memory_tracker::MemoryLoggerHandle> {
    if verbose || effective_log_file.is_some() {
        use cleave::memory_tracker;
        Some(memory_tracker::start_periodic_logging(
            std::time::Duration::from_secs(10),
            sysmem::memory_limit(),
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
