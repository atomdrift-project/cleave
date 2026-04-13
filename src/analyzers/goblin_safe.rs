//! Panic-safe wrappers around the [`goblin`] crate's binary parsers.
//!
//! `goblin` is fast but has a long history of panicking on malformed inputs
//! (out-of-range slice indexing in PE resource walkers, fat-header arithmetic
//! overflow in Mach-O, malformed dynamic sections in ELF, etc.). Letting any
//! of those panics escape into a tokio task aborts the whole HTTP request and
//! makes litmus look broken to its callers.
//!
//! This module is the *single chokepoint* through which cleave talks to
//! goblin. Every entry point catches `std::panic::catch_unwind` and converts
//! a caught panic into a `goblin::error::Error::Malformed("…panicked…")` so
//! callers can keep their existing `Result`-based error paths (which already
//! fall back to rizin where applicable) instead of growing a parallel
//! "did goblin panic?" branch at every call site.
//!
//! ## When to use what
//!
//! | Operation                                          | Helper                          |
//! |----------------------------------------------------|---------------------------------|
//! | `PE::parse(...)` / `parse_with_opts(...)`          | [`parse_pe`]                    |
//! | `Elf::parse(...)`                                  | [`parse_elf`]                   |
//! | `Mach::parse(...)`                                 | [`parse_mach`]                  |
//! | A `Result<T, goblin::error::Error>` you call later | [`catch`]                       |
//! | A non-`Result` lazy access (e.g. `pe.resource_data.entries()`) | [`catch_infallible`] |
//!
//! Both `parse_pe` and `parse_mach` already do the strict→permissive /
//! single-binary→fat dance internally, so callers should not reach for
//! `goblin::pe::PE::parse_with_opts` or `goblin::mach::Mach::parse` directly.

use goblin::elf::Elf;
use goblin::error::Error as GoblinError;
use goblin::mach::Mach;
use goblin::pe::PE;
use std::panic::{self, PanicHookInfo};
use std::sync::{Mutex, OnceLock};

/// Result of a goblin operation that distinguishes between a normal `Err`
/// return and a caught panic.
///
/// The two failure variants are *both* failures from the caller's perspective —
/// they should fall back to rizin and set `has_malformed_structure` either way —
/// but distinguishing them lets log lines and error metadata explain *how*
/// goblin gave up, which is useful when triaging future goblin bugs.
#[derive(Debug)]
pub(crate) enum GoblinOutcome<T> {
    /// goblin succeeded and produced a value.
    Ok(T),
    /// goblin returned a normal `Err` (e.g. truncated header, bad magic).
    Failed(GoblinError),
    /// goblin panicked while parsing/walking; payload is the extracted message.
    Panicked(String),
}

impl<T> GoblinOutcome<T> {
    /// Returns the value if successful, otherwise `None`.
    pub(crate) fn ok(self) -> Option<T> {
        match self {
            Self::Ok(t) => Some(t),
            _ => None,
        }
    }

    /// Returns true if goblin produced a clean value.
    pub(crate) fn is_ok(&self) -> bool {
        matches!(self, Self::Ok(_))
    }

    /// Returns a `GoblinFailureInfo` describing the failure, or `None` if
    /// the outcome is `Ok`. This is the canonical way to thread "what went
    /// wrong" through analyzer code without coupling them to either
    /// `goblin::error::Error` or the `GoblinOutcome` enum.
    pub(crate) fn failure_info(&self) -> Option<GoblinFailureInfo> {
        match self {
            Self::Ok(_) => None,
            Self::Failed(e) => Some(GoblinFailureInfo {
                message: e.to_string(),
                panicked: false,
            }),
            Self::Panicked(m) => Some(GoblinFailureInfo {
                message: format!("panicked: {m}"),
                panicked: true,
            }),
        }
    }
}

/// Concrete description of a goblin failure for analyzers to thread through
/// their error-handling paths.
#[derive(Debug, Clone)]
pub(crate) struct GoblinFailureInfo {
    /// Human-readable failure message; safe to log and to push into
    /// `report.metadata.errors`.
    pub message: String,
    /// Whether the failure was a *panic* caught by `catch_unwind` rather
    /// than a normal `Err` return. Useful for triaging future goblin bugs;
    /// callers should generally treat both cases the same way (mark
    /// `has_malformed_structure` and fall back to rizin).
    pub panicked: bool,
}

/// Best-effort extraction of a panic payload's message string for logging.
///
/// `catch_unwind` returns the payload as `Box<dyn Any + Send>`, which in
/// practice is almost always either `&'static str` (from `panic!("literal")`)
/// or `String` (from `panic!("{}", x)` / `assert!`). Anything else gets a
/// generic placeholder so we never lose the fact that *something* panicked.
pub(crate) fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

fn goblin_panic_hook_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn run_with_suppressed_panic_hook<T, F>(f: F) -> std::thread::Result<T>
where
    F: FnOnce() -> T,
{
    let _guard = goblin_panic_hook_lock()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let previous_hook = panic::take_hook();
    panic::set_hook(Box::new(|_info: &PanicHookInfo<'_>| {}));
    let result = panic::catch_unwind(panic::AssertUnwindSafe(f));
    panic::set_hook(previous_hook);
    result
}

/// Run a goblin call that returns `Result<T, GoblinError>`, returning a
/// typed `GoblinOutcome` that distinguishes a normal `Err` from a caught
/// panic.
pub(crate) fn catch<T, F>(f: F) -> GoblinOutcome<T>
where
    F: FnOnce() -> Result<T, GoblinError>,
{
    match run_with_suppressed_panic_hook(f) {
        Ok(Ok(value)) => GoblinOutcome::Ok(value),
        Ok(Err(e)) => GoblinOutcome::Failed(e),
        Err(payload) => GoblinOutcome::Panicked(panic_message(&*payload)),
    }
}

/// Run an arbitrary goblin operation that does *not* return a `Result`,
/// catching any panic.
///
/// This is the right choice for goblin's lazy field accessors — e.g.
/// `pe.resource_data.as_ref().map(|r| r.count())` — which slice into the
/// underlying file with header-supplied offsets and panic on bounds
/// violations. There is no `Result` for goblin to populate, so the only
/// failure mode is a panic; we surface it as `Panicked`.
pub(crate) fn catch_infallible<T, F>(f: F) -> GoblinOutcome<T>
where
    F: FnOnce() -> T,
{
    match run_with_suppressed_panic_hook(f) {
        Ok(value) => GoblinOutcome::Ok(value),
        Err(payload) => GoblinOutcome::Panicked(panic_message(&*payload)),
    }
}

/// Parse a PE file, panic-safe and with built-in permissive fallback.
///
/// Tries strict mode first (the default goblin behaviour). If that fails
/// — whether by returning an error *or* by panicking — falls back to
/// permissive mode. The returned outcome carries the *most informative*
/// failure: a permissive-mode error if both attempts cleanly failed, or
/// the panic message if either attempt crashed.
pub(crate) fn parse_pe(data: &[u8]) -> GoblinOutcome<PE<'_>> {
    let strict = catch(|| PE::parse(data));
    if matches!(strict, GoblinOutcome::Ok(_)) {
        return strict;
    }

    let opts = goblin::pe::options::ParseOptions::default()
        .with_parse_mode(goblin::options::ParseMode::Permissive);
    let permissive = catch(|| PE::parse_with_opts(data, &opts));

    // If permissive panicked but strict gave a clean Err, prefer the strict error
    // message — it's more informative than a panic payload. In all other cases,
    // return permissive (either its Ok/Err result, or its panic if strict also panicked).
    match (&strict, &permissive) {
        (GoblinOutcome::Failed(_), GoblinOutcome::Panicked(_)) => strict,
        _ => permissive,
    }
}

/// Parse an ELF file, panic-safe.
pub(crate) fn parse_elf(data: &[u8]) -> GoblinOutcome<Elf<'_>> {
    catch(|| Elf::parse(data))
}

/// Parse a Mach-O file (single binary or fat archive), panic-safe.
pub(crate) fn parse_mach(data: &[u8]) -> GoblinOutcome<Mach<'_>> {
    catch(|| Mach::parse(data))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn catch_propagates_ok() {
        let outcome: GoblinOutcome<u32> = catch(|| Ok(42));
        assert_eq!(outcome.ok(), Some(42));
    }

    #[test]
    fn catch_surfaces_err_as_failed() {
        let outcome: GoblinOutcome<u32> = catch(|| Err(GoblinError::Malformed("nope".into())));
        let info = outcome.failure_info().expect("expected failure");
        assert!(!info.panicked);
        assert!(info.message.contains("nope"));
    }

    #[test]
    fn catch_surfaces_panic_as_panicked() {
        let outcome: GoblinOutcome<u32> = catch(|| {
            panic!("synthetic boom");
        });
        let info = outcome.failure_info().expect("expected failure");
        assert!(info.panicked);
        assert!(info.message.contains("synthetic boom"));
    }

    #[test]
    fn catch_infallible_surfaces_panic_as_panicked() {
        let outcome: GoblinOutcome<u8> = catch_infallible(|| {
            let v: Vec<u8> = vec![1, 2, 3];
            v[10] // out-of-bounds, panics
        });
        let info = outcome.failure_info().expect("expected failure");
        assert!(info.panicked);
    }

    #[test]
    fn catch_infallible_propagates_value() {
        let outcome: GoblinOutcome<u32> = catch_infallible(|| 99);
        assert_eq!(outcome.ok(), Some(99));
    }

    #[test]
    fn parse_pe_rejects_garbage_without_panicking() {
        let outcome = parse_pe(b"this is not a PE");
        assert!(!outcome.is_ok());
    }

    #[test]
    fn parse_elf_rejects_garbage_without_panicking() {
        let outcome = parse_elf(b"this is not an ELF");
        assert!(!outcome.is_ok());
    }

    #[test]
    fn parse_mach_rejects_garbage_without_panicking() {
        let outcome = parse_mach(b"this is not a Mach-O");
        assert!(!outcome.is_ok());
    }
}
