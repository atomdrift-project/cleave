//! Process-wide cancellation flag driven by SIGINT / SIGTERM.
//!
//! The CLI scan path runs entirely on rayon workers with no tokio runtime, so
//! `tokio::signal` isn't available. We install a tiny `libc::signal` handler
//! that flips a `OnceLock<Arc<AtomicBool>>`; the scan worker closure checks
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
//! scan still costs its own timeout. The CLI's second SIGINT force-exits; a
//! server has no such escape and pays that timeout.
//!
//! Server mode uses `tokio::signal::ctrl_c()` separately and should not call
//! `install_signal_handlers()` — tokio would clobber our handler anyway.

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

/// Install SIGINT + SIGTERM handlers that flip the global flag on first
/// signal and force-exit on second. Call this once during CLI startup.
///
/// Must not be called in server mode — tokio's own signal machinery would
/// replace our handler.
pub fn install_signal_handlers() {
    #[cfg(unix)]
    {
        // Eagerly initialize the flag so the signal handler sees a ready
        // OnceLock (OnceLock::get() without a prior set() returns None).
        let _ = global_flag();
        // SAFETY: `libc::signal` is the standard POSIX entry point; the
        // handler itself only uses async-signal-safe primitives (atomic
        // swap, `libc::write`, `libc::_exit`). The function-pointer cast
        // goes through `*const ()` to appease the function_casts_as_integer
        // lint without changing the ABI.
        unsafe {
            libc::signal(libc::SIGINT, handler as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, handler as *const () as libc::sighandler_t);
        }
    }
}

#[cfg(unix)]
extern "C" fn handler(_signo: libc::c_int) {
    // OnceLock::get() on an already-initialized cell is a plain atomic load —
    // safe from a signal handler. install_signal_handlers() guarantees init.
    let Some(flag) = FLAG.get() else {
        return;
    };

    // First signal: request drain. Second: force-exit. swap returns the prior
    // value, so a prior `true` means this is the second hit.
    if flag.swap(true, Ordering::SeqCst) {
        const MSG: &[u8] = b"\n[cleave] second interrupt, forcing exit\n";
        // SAFETY: write(2) and _exit are both on the POSIX async-signal-safe
        // list. Exit code 130 = 128 + SIGINT (the shell convention).
        unsafe {
            libc::write(2, MSG.as_ptr().cast(), MSG.len());
            libc::_exit(130);
        }
    }

    const MSG: &[u8] =
        b"\n[cleave] interrupt received, draining workers (Ctrl-C again to force exit)\n";
    // SAFETY: write(2) is async-signal-safe; ignoring the return is fine here
    // because the message is advisory.
    unsafe {
        libc::write(2, MSG.as_ptr().cast(), MSG.len());
    }
}
