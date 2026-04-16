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
    /// the outcome is `Ok`.
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
    pub message: String,
    pub panicked: bool,
}

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
pub(crate) fn parse_pe(data: &[u8]) -> GoblinOutcome<PE<'_>> {
    // Fast path: validate header health to prevent hangs/memory explosion in goblin
    if let Err(e) = validate_pe_header(data) {
        return GoblinOutcome::Failed(GoblinError::Malformed(e));
    }

    let strict = catch(|| PE::parse(data));
    if matches!(strict, GoblinOutcome::Ok(_)) {
        return strict;
    }

    let opts = goblin::pe::options::ParseOptions::default()
        .with_parse_mode(goblin::options::ParseMode::Permissive);
    let permissive = catch(|| PE::parse_with_opts(data, &opts));

    match (&strict, &permissive) {
        (GoblinOutcome::Failed(_), GoblinOutcome::Panicked(_)) => strict,
        _ => permissive,
    }
}

/// Perform basic structural validation of PE headers to prevent known goblin
/// vulnerabilities (e.g. infinite loops or massive allocations on malformed tables).
fn validate_pe_header(data: &[u8]) -> Result<(), String> {
    if data.len() < 64 {
        return Ok(());
    }

    // MZ header
    if data[0] != b'M' || data[1] != b'Z' {
        return Ok(());
    }

    // PE pointer
    let pe_ptr_offset = 0x3C;
    let pe_offset = u32::from_le_bytes([
        data[pe_ptr_offset],
        data[pe_ptr_offset + 1],
        data[pe_ptr_offset + 2],
        data[pe_ptr_offset + 3],
    ]) as usize;

    if pe_offset + 24 > data.len() {
        return Ok(());
    }

    // PE signature
    if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Ok(());
    }

    let coff_offset = pe_offset + 4;
    let n_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]);
    if n_sections > 192 {
        // Windows allows up to 96 usually, but some tools allow more. 192 is a safe upper bound.
        return Err(format!("too many sections ({n_sections})"));
    }

    let opt_offset = coff_offset + 20;
    if opt_offset + 2 > data.len() {
        return Ok(());
    }

    let magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    let (data_dir_count_offset, data_dir_offset) = match magic {
        0x010b => (92, 96), // PE32
        0x020b => (108, 112), // PE32+
        _ => return Ok(()),
    };

    let dir_count_ptr = opt_offset + data_dir_count_offset;
    if dir_count_ptr + 4 > data.len() {
        return Ok(());
    }

    let n_dirs = u32::from_le_bytes([
        data[dir_count_ptr],
        data[dir_count_ptr + 1],
        data[dir_count_ptr + 2],
        data[dir_count_ptr + 3],
    ]);

    if n_dirs > 16 {
        return Err(format!("too many data directories ({n_dirs})"));
    }

    // Check Data Directories (Imports=1, Resources=2)
    for i in 1..=2 {
        if n_dirs > i as u32 {
            let dir_ptr = opt_offset + data_dir_offset + (i * 8);
            if dir_ptr + 8 <= data.len() {
                let size = u32::from_le_bytes([
                    data[dir_ptr + 4],
                    data[dir_ptr + 5],
                    data[dir_ptr + 6],
                    data[dir_ptr + 7],
                ]);

                // Limit tables to 10MB or file size. A 14MB malware file
                // shouldn't have a 100MB import table.
                if size > 10 * 1024 * 1024 || size as usize > data.len() {
                    let name = if i == 1 { "import" } else { "resource" };
                    return Err(format!("malformed {name} table size ({size} bytes)"));
                }
            }
        }
    }

    Ok(())
}

pub(crate) fn parse_elf(data: &[u8]) -> GoblinOutcome<Elf<'_>> {
    catch(|| Elf::parse(data))
}

pub(crate) fn parse_mach(data: &[u8]) -> GoblinOutcome<Mach<'_>> {
    catch(|| Mach::parse(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_pe_header_too_many_sections() {
        let mut data = vec![0u8; 1024];
        data[0] = b'M'; data[1] = b'Z';
        data[0x3C] = 0x40; // PE at 0x40
        data[0x40] = b'P'; data[0x41] = b'E';
        data[0x44 + 2] = 0xFF; // n_sections = 255 (too many)
        assert!(validate_pe_header(&data).is_err());
    }

    #[test]
    fn test_validate_pe_header_malformed_imports() {
        let mut data = vec![0u8; 1024];
        data[0] = b'M'; data[1] = b'Z';
        data[0x3C] = 0x40; // PE at 0x40
        data[0x40] = b'P'; data[0x41] = b'E';
        data[0x44 + 2] = 1; // n_sections = 1
        data[0x40 + 24] = 0x0B; data[0x41 + 24] = 0x01; // PE32
        data[0x40 + 24 + 92] = 16; // 16 dirs
        // Import dir size (at opt + 96 + 8 + 4)
        let import_size_ptr = 0x40 + 24 + 96 + 8 + 4;
        data[import_size_ptr] = 0x00;
        data[import_size_ptr + 1] = 0x00;
        data[import_size_ptr + 2] = 0x00;
        data[import_size_ptr + 3] = 0x01; // 16MB (too big)
        assert!(validate_pe_header(&data).is_err());
    }
}
