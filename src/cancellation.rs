//! Process-wide cancellation flag driven by SIGINT / SIGTERM.
//!
//! The CLI scan path runs entirely on rayon workers with no tokio runtime, so
//! `tokio::signal` isn't available. A dedicated signal thread flips a
//! `OnceLock<Arc<AtomicBool>>`; the scan worker closure checks
//! the flag before pulling the next file.
//!
//! Cancellation is observed *between* units of work, never inside one. cleave's
//! own analyzers take the `AnalysisOptions.cancellation` `Arc` through
//! `with_cancellation` and poll it at their phase boundaries, and the YARA
//! prefetch declines to start a scan once the flag is set. The three
//! long-running leaf workers, however, do not observe it while running:
//!
//! - **tree-sitter** — *does* observe it. `AnalysisContext::with_cancellation`
//!   hands the flag to filefacts, whose parse polls it and abandons the tree,
//!   degrading to a `source.ast_unavailable.parse_cancelled` diagnostic. A
//!   15 s wall budget backs it up when no flag is supplied.
//! - **rizin** — does not. cleave's `radare2/mod.rs` propagated cancellation,
//!   but it was retired in the filefacts migration and `filefacts::rizin` has
//!   not picked it up (tracked there as #75c). Bounded instead by its own hard
//!   timeout and process-group kill, so it stops on its own; the flag just
//!   doesn't make it stop *sooner*.
//! - **YARA** — an in-flight scan runs to yara-x's cooperative `set_timeout`
//!   (20 min); the flag only prevents a scan that hasn't begun.
//!
//! So a cancelled run stops scheduling promptly and abandons the one leaf that
//! could otherwise run long in-process, but a rizin child or an in-flight YARA
//! scan still costs its own timeout.
//!
//! The library never installs signal handlers: the host sets the flag. The
//! `cleave` binary does so on SIGINT/SIGTERM and force-exits on the second.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Get (or lazily initialize) the global cancellation flag.
#[must_use]
pub fn global_flag() -> Arc<AtomicBool> {
    FLAG.get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone()
}

/// True if a SIGINT/SIGTERM has been observed.
#[must_use]
pub fn is_cancelled() -> bool {
    FLAG.get().is_some_and(|f| f.load(Ordering::Relaxed))
}
