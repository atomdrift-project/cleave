//! UPX executable unpacking.
//!
//! This module detects and unpacks UPX-compressed binaries for analysis.

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
    /// tampered magic strings ([A-Z]PX!) in the first 512 bytes of the file.
    pub(crate) fn is_upx_packed(data: &[u8]) -> bool {
        // Search slightly past 512 to catch UPX! placed right at the boundary.
        let search_range = data.len().min(520);
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

    /// Decompress a UPX-packed file and return the decompressed data.
    /// The input file_path points to the original packed file.
    pub(crate) fn decompress(file_path: &Path) -> Result<Vec<u8>, UPXError> {
        if !Self::is_available() {
            return Err(UPXError::NotInstalled);
        }

        // Create a temporary file to hold a copy for decompression
        // (upx -d modifies the file in place, so we work on a copy)
        let temp_file = NamedTempFile::new()?;
        let temp_path = temp_file.path();

        // Use fs::copy instead of read + write to avoid buffering original in memory
        std::fs::copy(file_path, temp_path)?;

        // Run upx -d on the temporary copy with a timeout
        let mut child = Command::new("upx")
            .arg("-d")
            .arg("-q") // Quiet mode
            .arg(temp_path)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("UPX process stdout pipe was not captured"))?;
        let _stdout_rx = {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut stdout = stdout;
                let mut buf = Vec::new();
                let _ = std::io::Read::read_to_end(&mut stdout, &mut buf);
                let _ = tx.send(buf);
            });
            rx
        };
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| std::io::Error::other("UPX process stderr pipe was not captured"))?;
        let stderr_rx = {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut stderr = stderr;
                let mut buf = Vec::new();
                let _ = std::io::Read::read_to_end(&mut stderr, &mut buf);
                let _ = tx.send(buf);
            });
            rx
        };

        let timeout = std::time::Duration::from_secs(60);
        let start = std::time::Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if start.elapsed() > timeout {
                let _ = child.kill();
                let _ = child.wait();
                return Err(UPXError::DecompressionFailed(
                    "UPX decompression timed out".to_string(),
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        };

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
        // Magic at byte 508 (just within 512 byte search range)
        let mut data = vec![0u8; 520];
        data[508..512].copy_from_slice(b"UPX!");
        assert!(UPXDecompressor::is_upx_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_magic_beyond_512() {
        // Magic string beyond 512 bytes should not be detected
        let mut data = vec![0u8; 600];
        data[520..524].copy_from_slice(b"UPX!");
        assert!(!UPXDecompressor::is_upx_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_magic_at_exactly_512_boundary() {
        // Magic starting at byte 512 IS detected (search range is 520 to catch boundary cases)
        let mut data = vec![0u8; 520];
        data[512..516].copy_from_slice(b"UPX!");
        assert!(UPXDecompressor::is_upx_packed(&data));
    }

    #[test]
    fn test_is_upx_packed_magic_beyond_520() {
        // Magic starting at byte 521 should NOT be detected (outside search range)
        let mut data = vec![0u8; 530];
        data[521..525].copy_from_slice(b"UPX!");
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
