//! UPX executable unpacking.
//!
//! This module detects and unpacks UPX-compressed binaries for analysis.

use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use tempfile::NamedTempFile;
use thiserror::Error;

/// Global disable counter for UPX decompression.
///
/// A positive value means UPX support is disabled. This supports both permanent
/// process-wide disables and scoped guards used by library calls.
static UPX_DISABLED: AtomicUsize = AtomicUsize::new(0);

/// Disable UPX decompression globally
#[allow(dead_code)] // Used by the CLI binary target for process-wide disables
pub(crate) fn disable_upx() {
    UPX_DISABLED.fetch_add(1, Ordering::SeqCst);
}

/// Guard that disables UPX support for the lifetime of the value.
#[allow(dead_code)] // Used by the library target; the binary recompiles modules separately
pub(crate) struct ScopedUpxDisable;

impl Drop for ScopedUpxDisable {
    fn drop(&mut self) {
        UPX_DISABLED.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Disable UPX support for the lifetime of the returned guard.
#[allow(dead_code)] // Used by the library target; the binary recompiles modules separately
pub(crate) fn scoped_disable_upx() -> ScopedUpxDisable {
    UPX_DISABLED.fetch_add(1, Ordering::SeqCst);
    ScopedUpxDisable
}

/// Check if UPX is disabled
pub(crate) fn is_disabled() -> bool {
    UPX_DISABLED.load(Ordering::SeqCst) > 0
}

#[derive(Debug, Error)]
pub(crate) enum UPXError {
    #[error("UPX binary not installed or not in PATH")]
    NotInstalled,
    #[error("UPX decompression failed: {0}")]
    DecompressionFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

pub(crate) struct UPXDecompressor;

impl UPXDecompressor {
    /// Check if data appears to be UPX-packed by looking for "UPX!" or similar
    /// tampered magic strings ([A-Z]PX!) near the executable headers.
    pub(crate) fn is_upx_packed(data: &[u8]) -> bool {
        // UPX PE section tables often place the "UPX!" marker after the DOS,
        // PE, and section headers. 512 bytes misses valid small PE samples with
        // three sections; 4 KiB keeps detection header-scoped while covering the
        // normal UPX header area.
        let search_range = data.len().min(4096);
        let search_data = &data[..search_range];

        // Look for "[A-Z]PX!" pattern
        for window in search_data.windows(4) {
            if window.len() == 4
                && window[0] >= b'A'
                && window[0] <= b'Z'
                && &window[1..4] == b"PX!"
            {
                return true;
            }
        }

        false
    }

    /// Check if the upx binary is available in PATH (and not disabled).
    pub(crate) fn is_available() -> bool {
        if is_disabled() {
            return false;
        }
        Command::new("upx")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success())
    }

    fn copy_to_writable_temp(file_path: &Path) -> Result<NamedTempFile, UPXError> {
        let temp_file = NamedTempFile::new()?;
        let temp_path = temp_file.path();

        // UPX decompresses in place. `fs::copy` preserves read-only mode from
        // source samples on Unix, so force the private temp copy writable.
        std::fs::copy(file_path, temp_path)?;

        let metadata = std::fs::metadata(temp_path)?;
        let mut permissions = metadata.permissions();
        if permissions.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            permissions.set_readonly(false);
            std::fs::set_permissions(temp_path, permissions)?;
        }

        Ok(temp_file)
    }

    /// Decompress a UPX-packed file and return the decompressed data.
    /// The input file_path points to the original packed file.
    pub(crate) fn decompress(file_path: &Path) -> Result<Vec<u8>, UPXError> {
        if !Self::is_available() {
            return Err(UPXError::NotInstalled);
        }

        // Create a temporary file to hold a copy for decompression
        // (upx -d modifies the file in place, so we work on a copy)
        let temp_file = Self::copy_to_writable_temp(file_path)?;
        let temp_path = temp_file.path();

        // Run upx -d on the temporary copy with a timeout.
        // stdout → null: -q mode produces nothing useful; null avoids a drain thread.
        // stderr → piped: captured for error messages on failure.
        let mut child = Command::new("upx")
            .arg("-d")
            .arg("-q") // Quiet mode
            .arg(temp_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("UPX process stderr pipe was not captured"))?;
        let (stderr_tx, stderr_rx) = std::sync::mpsc::channel();
        let stderr_thread = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let mut stderr = stderr;
            let _ = stderr.read_to_end(&mut buf);
            let _ = stderr_tx.send(buf);
        });

        let timeout = std::time::Duration::from_secs(120);
        let start = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if start.elapsed() > timeout {
                if let Err(e) = child.kill() {
                    tracing::debug!("UPX kill failed (may have already exited): {}", e);
                }
                if let Err(e) = child.wait() {
                    tracing::debug!("UPX wait after kill failed: {}", e);
                }
                let _ = stderr_thread.join();
                return Err(UPXError::DecompressionFailed(
                    "UPX decompression timed out".to_string(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };

        let _ = stderr_thread.join();
        let stderr = stderr_rx.recv().unwrap_or_default();

        if !status.success() {
            let stderr_str = String::from_utf8_lossy(&stderr);
            return Err(UPXError::DecompressionFailed(stderr_str.to_string()));
        }

        // Read back the decompressed data with size limit (100 MB)
        let metadata = std::fs::metadata(temp_path)?;
        let size = metadata.len();
        const MAX_UPX_DECOMPRESSED_SIZE: u64 = 100 * 1024 * 1024;

        if size > MAX_UPX_DECOMPRESSED_SIZE {
            return Err(UPXError::DecompressionFailed(format!(
                "Decompressed UPX size exceeds limit ({} > {})",
                size, MAX_UPX_DECOMPRESSED_SIZE
            )));
        }

        let decompressed = std::fs::read(temp_path)?;
        Ok(decompressed)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;

    // =========================================================================
    // is_upx_packed tests
    // =========================================================================

    #[test]
    fn test_is_upx_packed_with_magic_after_elf_header() {
        // UPX! magic typically appears after ELF header
        let data_with_magic = b"\x7fELF\x00\x00\x00\x00UPX!\x00\x00";
        assert!(UPXDecompressor::is_upx_packed(data_with_magic));
    }

    #[test]
    fn test_is_upx_packed_without_magic() {
        // Regular ELF header without UPX magic
        let data_without_magic = b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(!UPXDecompressor::is_upx_packed(data_without_magic));
    }

    #[test]
    fn test_is_upx_packed_empty() {
        let empty: &[u8] = &[];
        assert!(!UPXDecompressor::is_upx_packed(empty));
    }

    #[test]
    fn test_is_upx_packed_magic_at_start() {
        let data = b"UPX!\x00\x00\x00\x00";
        assert!(UPXDecompressor::is_upx_packed(data));
    }

    #[test]
    fn test_is_upx_packed_magic_at_end_of_search_range() {
        // Magic at byte 4088 (just within 4 KiB search range)
        let mut data = vec![0u8; 4096];
        data[4088..4092].copy_from_slice(b"UPX!");
        assert!(UPXDecompressor::is_upx_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_pe_magic_after_section_table() {
        // Valid PE UPX samples can carry UPX! around byte 992, after the
        // section table, while still being unpackable by upx -d.
        let mut data = vec![0u8; 1200];
        data[0..2].copy_from_slice(b"MZ");
        data[992..996].copy_from_slice(b"UPX!");
        assert!(UPXDecompressor::is_upx_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_magic_at_exactly_512_boundary() {
        // Magic starting at byte 512 IS detected.
        let mut data = vec![0u8; 520];
        data[512..516].copy_from_slice(b"UPX!");
        assert!(UPXDecompressor::is_upx_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_magic_beyond_header_search() {
        // Magic starting beyond 4 KiB should not drive UPX unpacking.
        let mut data = vec![0u8; 4200];
        data[4097..4101].copy_from_slice(b"UPX!");
        assert!(!UPXDecompressor::is_upx_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_partial_magic() {
        // Partial magic "UPX" without "!" should not match
        let data = b"\x7fELF\x00\x00\x00\x00UPX\x00\x00\x00";
        assert!(!UPXDecompressor::is_upx_packed(data));
    }

    #[test]
    fn test_is_upx_packed_similar_but_wrong_magic() {
        // Similar strings that are NOT UPX magic
        let data1 = b"\x7fELF\x00\x00\x00\x00upx!\x00\x00"; // lowercase
        assert!(!UPXDecompressor::is_upx_packed(data1));

        let data2 = b"\x7fELF\x00\x00\x00\x00UPX?\x00\x00"; // wrong char
        assert!(!UPXDecompressor::is_upx_packed(data2));

        let data3 = b"\x7fELF\x00\x00\x00\x00 UPX!\x00\x00"; // space before
        assert!(UPXDecompressor::is_upx_packed(data3)); // should still match
    }

    #[test]
    fn test_is_upx_packed_multiple_occurrences() {
        // Multiple UPX! strings - should still return true
        let mut data = vec![0u8; 100];
        data[10..14].copy_from_slice(b"UPX!");
        data[50..54].copy_from_slice(b"UPX!");
        assert!(UPXDecompressor::is_upx_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_small_file() {
        // File smaller than 512 bytes with magic
        let data = b"UPX!";
        assert!(UPXDecompressor::is_upx_packed(data));
    }

    #[test]
    fn test_is_upx_packed_exactly_4_bytes() {
        // Exactly 4 bytes matching magic
        assert!(UPXDecompressor::is_upx_packed(b"UPX!"));
    }

    #[test]
    fn test_is_upx_packed_3_bytes() {
        // Only 3 bytes - cannot contain full magic
        assert!(!UPXDecompressor::is_upx_packed(b"UPX"));
    }

    #[test]
    fn test_is_upx_packed_binary_data_with_magic() {
        // Binary data with UPX magic embedded
        let mut data = vec![0xffu8; 256];
        data[100..104].copy_from_slice(b"UPX!");
        assert!(UPXDecompressor::is_upx_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_real_elf_header_pattern() {
        // Realistic ELF header followed by UPX magic (typical UPX-packed ELF)
        let mut data = vec![0u8; 256];
        // ELF magic
        data[0..4].copy_from_slice(b"\x7fELF");
        // 64-bit, little-endian
        data[4] = 2; // 64-bit
        data[5] = 1; // little-endian
        data[6] = 1; // ELF version
        // UPX magic typically appears in the packed data section
        data[100..104].copy_from_slice(b"UPX!");
        assert!(UPXDecompressor::is_upx_packed(&data));
    }

    // =========================================================================
    // UPXError tests
    // =========================================================================

    #[test]
    fn test_upx_error_not_installed_display() {
        let err = UPXError::NotInstalled;
        assert_eq!(err.to_string(), "UPX binary not installed or not in PATH");
    }

    #[test]
    fn test_upx_error_decompression_failed_display() {
        let err = UPXError::DecompressionFailed("corrupt file".to_string());
        assert_eq!(err.to_string(), "UPX decompression failed: corrupt file");
    }

    #[test]
    fn test_upx_error_io_error_display() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = UPXError::IoError(io_err);
        assert!(err.to_string().contains("IO error"));
    }

    #[test]
    fn test_upx_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let upx_err: UPXError = io_err.into();
        matches!(upx_err, UPXError::IoError(_));
    }

    // =========================================================================
    // decompress tests (require UPX binary or handle its absence)
    // =========================================================================

    #[test]
    fn test_decompress_nonexistent_file() {
        // Decompressing a nonexistent file should return an error
        let result = UPXDecompressor::decompress(Path::new("/nonexistent/file/path.elf"));
        assert!(result.is_err());
    }

    #[test]
    fn test_decompress_non_upx_file() {
        // Create a temp file that is NOT UPX-packed
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file
            .write_all(b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
            .unwrap();
        temp_file.flush().unwrap();

        let result = UPXDecompressor::decompress(temp_file.path());

        // Should fail if UPX is available (file is not UPX-packed)
        // or return NotInstalled if UPX is not available
        assert!(result.is_err());
        match result {
            Err(UPXError::NotInstalled | UPXError::DecompressionFailed(_)) => {
                // Either UPX not installed (acceptable) or file is not UPX-packed (expected)
            }
            _ => panic!("Expected NotInstalled or DecompressionFailed error"),
        }
    }

    #[test]
    #[allow(clippy::permissions_set_readonly_false)]
    fn test_copy_to_writable_temp_from_readonly_source() {
        let mut source = NamedTempFile::new().unwrap();
        source.write_all(b"UPX! readonly sample").unwrap();
        source.flush().unwrap();

        let mut permissions = std::fs::metadata(source.path()).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(source.path(), permissions).unwrap();

        let copied = UPXDecompressor::copy_to_writable_temp(source.path()).unwrap();
        assert!(
            !std::fs::metadata(copied.path())
                .unwrap()
                .permissions()
                .readonly()
        );

        // Restore permissions so the temporary source can be cleaned up on all platforms.
        let mut permissions = std::fs::metadata(source.path()).unwrap().permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(source.path(), permissions).unwrap();
    }

    // =========================================================================
    // is_available tests
    // =========================================================================

    #[test]
    fn test_is_available_returns_bool() {
        // Just verify it returns a boolean without crashing
        let _available = UPXDecompressor::is_available();
        // We can't assert true/false since it depends on the system
    }

    #[test]
    fn test_scoped_disable_restores_previous_state() {
        let was_disabled = is_disabled();
        let before = UPX_DISABLED.load(Ordering::SeqCst);

        {
            let _guard = scoped_disable_upx();
            assert!(is_disabled());
            assert_eq!(UPX_DISABLED.load(Ordering::SeqCst), before + 1);
        }

        assert_eq!(UPX_DISABLED.load(Ordering::SeqCst), before);
        assert_eq!(is_disabled(), was_disabled);
    }
}
