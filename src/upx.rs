//! UPX executable unpacking.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//!
//! This module detects and unpacks UPX-compressed binaries for analysis.

use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use tempfile::NamedTempFile;
use thiserror::Error;

/// Global flag to disable UPX decompression
static UPX_DISABLED: AtomicBool = AtomicBool::new(false);

/// Disable UPX decompression globally
pub(crate) fn disable_upx() {
    UPX_DISABLED.store(true, Ordering::SeqCst);
}

/// Check if UPX is disabled
pub(crate) fn is_disabled() -> bool {
    UPX_DISABLED.load(Ordering::SeqCst)
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
        let search_range = data.len().min(512);
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
        let mut temp_file = NamedTempFile::new()?;
        let original_data = std::fs::read(file_path)?;
        temp_file.write_all(&original_data)?;
        temp_file.flush()?;

        let temp_path = temp_file.path();

        // Run upx -d on the temporary copy
        let output = Command::new("upx")
            .arg("-d")
            .arg("-q") // Quiet mode
            .arg(temp_path)
            .output()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(UPXError::DecompressionFailed(stderr.to_string()));
        }

        // Read back the decompressed data
        let decompressed = std::fs::read(temp_path)?;
        Ok(decompressed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Magic starting at byte 512 should NOT be detected (outside range)
        let mut data = vec![0u8; 520];
        data[512..516].copy_from_slice(b"UPX!");
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
}
