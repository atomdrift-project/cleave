//! UPX executable unpacking.
//!
//! This module detects and unpacks UPX-compressed binaries for analysis.

use std::io::Write;
use std::process::Command;
use tempfile::NamedTempFile;
use thiserror::Error;

/// How long one `upx -d` may run.
const UPX_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

#[derive(Debug, Error)]
pub(crate) enum UPXError {
    #[error("UPX binary not installed or not in PATH")]
    NotInstalled,
    #[error("UPX decompression failed: {0}")]
    DecompressionFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// A stable description of why UPX decompression failed.
///
/// `upx` reports errors against the temporary file it was handed, so its stderr
/// carries a path that differs on every run:
///
/// ```text
/// upx: /tmp/.tmpJYEaZH: Exception: checksum error
/// ```
///
/// Findings use this fixed vocabulary instead, so two reports of one file
/// diff cleanly; the raw stderr goes to the debug log.
pub(crate) struct UpxFailure {
    /// Fixed text, safe to compare across runs and machines.
    pub description: &'static str,
    /// Exact integrity failures are suspicious artifact evidence, distinct
    /// from environmental recovery limits.
    pub checksum_mismatch: bool,
    /// A claimed UPX image is structurally invalid or rejected as unpacked.
    pub invalid_image: bool,
}

/// Triage policy: a file-specific refusal by standard UPX is hostile even
/// when a later repair recovers its contents. Missing tools, I/O failures,
/// timeouts and local size ceilings are limitations of the analysis run.
pub(crate) fn standard_unpack_refusal(err: &UPXError) -> Option<crate::types::Finding> {
    let failure = classify_failure(err);
    if !matches!(err, UPXError::DecompressionFailed(_))
        || matches!(
            failure.description,
            "UPX decompression timed out"
                | "UPX payload exceeds decompression size limit"
                | "UPX could not read the image"
        )
    {
        return None;
    }
    Some(
        crate::types::Finding::structural(
            "objectives/anti-static/pack/upx::standard-unpack-refused".to_string(),
            "UPX image resists standard unpacking".to_string(),
            1.0,
        )
        .with_criticality(crate::types::Criticality::Hostile),
    )
}

/// Map a decompression error onto one of a fixed set of reasons.
///
/// Matching is done on substrings of `upx`'s own exception names, which are
/// stable across releases (`ChecksumException`, `CantUnpackException`,
/// `NotPackedException`, `IOException`). Checksum failures are distinguished
/// from environmental limits and ordinary tool refusals.
pub(crate) fn classify_failure(err: &UPXError) -> UpxFailure {
    let mut checksum_mismatch = false;
    let mut invalid_image = false;
    let description = match err {
        UPXError::NotInstalled => "UPX tool not available to unpack",
        UPXError::IoError(_) => "UPX decompression I/O error",
        UPXError::DecompressionFailed(msg) => {
            let m = msg.to_ascii_lowercase();
            if m.contains("timed out") {
                "UPX decompression timed out"
            } else if m.contains("exceeds limit") {
                "UPX payload exceeds decompression size limit"
            } else if m.contains("checksum error") || m.contains("checksumexception") {
                checksum_mismatch = true;
                "UPX header checksum does not match payload"
            } else if m.contains("notpacked") || m.contains("not packed") {
                invalid_image = true;
                "UPX markers present but image is not packed"
            } else if m.contains("corrupt")
                || m.contains("invalid header")
                || m.contains("invalid packed data")
                || m.contains("unexpected end of file")
            {
                invalid_image = true;
                "UPX packed-image structure is invalid"
            } else if m.contains("cantunpack") || m.contains("cantpack") {
                "UPX image refuses to unpack"
            } else if m.contains("ioexception") {
                "UPX could not read the image"
            } else {
                "UPX decompression failed"
            }
        }
    };
    UpxFailure {
        description,
        checksum_mismatch,
        invalid_image,
    }
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

    /// Repair checksums only on an analysis copy of a recognized PE32 NRV2B
    /// stream. A bounded data decoder recovers the bytes without executing the
    /// specimen. The caller must retain the original integrity finding, and
    /// ordinary UPX must still accept the repaired copy before it is analyzed.
    pub(crate) fn repair_nrv2b_checksums(data: &[u8]) -> Option<Vec<u8>> {
        const LIMIT: usize = 64 * 1024 * 1024;
        if data.len() > LIMIT || !data.starts_with(b"MZ") {
            return None;
        }
        let at = data
            .get(..data.len().min(4096))?
            .windows(4)
            .position(|v| v == b"UPX!")?;
        let h = data.get(at..at.checked_add(32)?)?;
        if !(10..=13).contains(&h[4])
            || h[5] != 9
            || h[6] != 2
            || h[31] != (h[4..31].iter().map(|v| u32::from(*v)).sum::<u32>() % 251) as u8
        {
            return None;
        }
        let ulen = u32::from_le_bytes(h[16..20].try_into().ok()?) as usize;
        let clen = u32::from_le_bytes(h[20..24].try_into().ok()?) as usize;
        if ulen == 0 || ulen > LIMIT || clen == 0 || clen > LIMIT {
            return None;
        }
        let start = at.checked_add(32)?;
        let compressed = data.get(start..start.checked_add(clen)?)?;
        let decoded = crate::extractors::nrv32::decode(compressed, ulen).ok()?;
        if decoded.len() != ulen {
            return None;
        }
        fn adler(bytes: &[u8]) -> u32 {
            let (mut a, mut b) = (1u32, 0u32);
            for chunk in bytes.chunks(5552) {
                for byte in chunk {
                    a += u32::from(*byte);
                    b += a;
                }
                a %= 65521;
                b %= 65521;
            }
            (b << 16) | a
        }
        let mut copy = data.to_vec();
        copy[at + 8..at + 12].copy_from_slice(&adler(&decoded).to_le_bytes());
        copy[at + 12..at + 16].copy_from_slice(&adler(compressed).to_le_bytes());
        copy[at + 31] = (copy[at + 4..at + 31]
            .iter()
            .map(|v| u32::from(*v))
            .sum::<u32>()
            % 251) as u8;
        Some(copy)
    }

    /// The `upx` binary, probed once.
    fn command() -> Option<std::path::PathBuf> {
        static UPX: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        crate::subprocess::probed_tool(&UPX, &["upx"], &["--version"])
    }

    /// Check if the upx binary is available.
    pub(crate) fn is_available() -> bool {
        Self::command().is_some()
    }

    fn copy_to_writable_temp(data: &[u8]) -> Result<NamedTempFile, UPXError> {
        // UPX decompresses in place, so it needs a private writable copy. Copy
        // the bytes only: `fs::copy` would also carry the sample's mode bits
        // (setuid, world-writable) onto a file in shared temp space, while
        // `NamedTempFile` creates it owner-only.
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(data)?;
        temp_file.flush()?;
        Ok(temp_file)
    }

    /// Decompress a UPX-packed file and return the decompressed data.
    /// Use the same byte snapshot as the analyzer. Archive members may have
    /// only a virtual path and no reopenable filesystem backing.
    pub(crate) fn decompress(data: &[u8]) -> Result<Vec<u8>, UPXError> {
        let Some(upx) = Self::command() else {
            return Err(UPXError::NotInstalled);
        };

        // upx -d rewrites the file in place, so it works on a private copy.
        let temp_file = Self::copy_to_writable_temp(data)?;
        let temp_path = temp_file.path();

        let mut command = Command::new(upx);
        command
            .arg("-d")
            .arg("-q")
            .arg(temp_path)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        crate::subprocess::scrub_env(&mut command);
        let Some(output) = crate::subprocess::output_with_timeout(&mut command, UPX_TIMEOUT)?
        else {
            return Err(UPXError::DecompressionFailed(
                "UPX decompression timed out".to_string(),
            ));
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(UPXError::DecompressionFailed(stderr.to_string()));
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

    // =========================================================================
    // Failure classification
    // =========================================================================

    /// The reason a finding exists must not depend on which temp file `upx`
    /// happened to be handed: two scans of one sample have to produce the same
    /// description, or the reports cannot be diffed.
    #[test]
    fn standard_unpack_policy_separates_refusal_from_environment() {
        for message in [
            "checksum error",
            "CantUnpackException: unsupported format",
            "NotPackedException: not packed",
            "corrupt file",
        ] {
            let finding = standard_unpack_refusal(&UPXError::DecompressionFailed(message.into()));
            assert!(finding.is_some_and(|f| f.crit == crate::types::Criticality::Hostile));
        }
        for err in [
            UPXError::NotInstalled,
            UPXError::IoError(std::io::Error::other("unavailable input")),
            UPXError::DecompressionFailed("UPX decompression timed out".into()),
            UPXError::DecompressionFailed("Decompressed UPX size exceeds limit".into()),
            UPXError::DecompressionFailed("IOException".into()),
        ] {
            assert!(standard_unpack_refusal(&err).is_none());
        }
    }

    #[test]
    fn test_classify_failure_is_stable_across_temp_paths() {
        let a = classify_failure(&UPXError::DecompressionFailed(
            "upx: /tmp/.tmpJYEaZH: Exception: checksum error\n".to_string(),
        ));
        let b = classify_failure(&UPXError::DecompressionFailed(
            "upx: /tmp/.tmpQYT9GU: Exception: checksum error\n".to_string(),
        ));
        assert_eq!(a.description, b.description);
        assert!(a.checksum_mismatch && b.checksum_mismatch);
        assert!(!a.description.contains("/tmp"));
        assert_eq!(a.description, "UPX header checksum does not match payload");
    }

    /// A timeout, our own size ceiling, or a missing `upx` are facts about the
    /// run. Grading those as evidence against the sample reported our own
    /// environment as hostile.
    #[test]
    fn test_classify_failure_environmental_reasons_are_specific() {
        for err in [
            UPXError::DecompressionFailed("UPX decompression timed out".to_string()),
            UPXError::DecompressionFailed(
                "Decompressed UPX size exceeds limit (200 > 100)".to_string(),
            ),
            UPXError::NotInstalled,
        ] {
            let f = classify_failure(&err);
            assert!(!f.description.is_empty());
            assert!(!f.checksum_mismatch);
            assert!(!f.invalid_image);
            assert_ne!(f.description, "UPX decompression failed");
        }
    }

    /// Unknown errors retain a stable generic recovery diagnostic.
    #[test]
    fn test_classify_failure_unknown_stderr_is_generic() {
        let f = classify_failure(&UPXError::DecompressionFailed(
            "upx: something new went wrong".to_string(),
        ));
        assert_eq!(f.description, "UPX decompression failed");
        assert!(!f.checksum_mismatch);
    }

    #[test]
    fn checksum_in_path_is_not_a_checksum_failure() {
        for message in [
            "upx: /tmp/checksum.exe: NotPackedException: not packed",
            "upx: /tmp/test.exe: CantUnpackException: unsupported format",
        ] {
            assert!(
                !classify_failure(&UPXError::DecompressionFailed(message.into())).checksum_mismatch
            );
        }
        assert!(
            classify_failure(&UPXError::DecompressionFailed("ChecksumException".into()))
                .checksum_mismatch
        );
    }

    #[test]
    fn invalid_images_are_distinct_from_unsupported_formats() {
        for message in [
            "NotPackedException: not packed",
            "CantUnpackException: invalid header",
            "corrupted input",
        ] {
            assert!(classify_failure(&UPXError::DecompressionFailed(message.into())).invalid_image);
        }
        for message in [
            "CantUnpackException: unsupported format",
            "UPX decompression timed out",
            "IOexception",
        ] {
            assert!(
                !classify_failure(&UPXError::DecompressionFailed(message.into())).invalid_image
            );
        }
    }

    #[test]
    fn bounded_checksum_repair_recovers_literal_stream_without_touching_input() {
        // NRV2B literals "Hi", followed by the end marker.
        let stream = [0, 0, 0, 192, 72, 105, 0, 32, 1, 0, 255];
        let mut data = vec![0u8; 64 + 32];
        data[..2].copy_from_slice(b"MZ");
        data[64..72].copy_from_slice(&[b'U', b'P', b'X', b'!', 13, 9, 2, 1]);
        data[80..84].copy_from_slice(&2u32.to_le_bytes());
        data[84..88].copy_from_slice(&(stream.len() as u32).to_le_bytes());
        data[95] = (data[68..95].iter().map(|v| u32::from(*v)).sum::<u32>() % 251) as u8;
        data.extend_from_slice(&stream);
        let original = data.clone();
        let fixed = UPXDecompressor::repair_nrv2b_checksums(&data).unwrap();
        assert_eq!(data, original);
        assert_eq!(&fixed[96..], &stream);
        assert_eq!(
            u32::from_le_bytes(fixed[72..76].try_into().unwrap()),
            0x00fb00b2
        );
        assert_eq!(
            fixed[95],
            (fixed[68..95].iter().map(|v| u32::from(*v)).sum::<u32>() % 251) as u8
        );
        for len in 0..data.len() {
            assert!(UPXDecompressor::repair_nrv2b_checksums(&data[..len]).is_none());
        }
        data[80..84].copy_from_slice(&u32::MAX.to_le_bytes());
        data[95] = (data[68..95].iter().map(|v| u32::from(*v)).sum::<u32>() % 251) as u8;
        assert!(UPXDecompressor::repair_nrv2b_checksums(&data).is_none());
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
    fn test_decompress_empty_snapshot() {
        // An empty in-memory snapshot should be rejected.
        let result = UPXDecompressor::decompress(&[]);
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

        let result = UPXDecompressor::decompress(&std::fs::read(temp_file.path()).unwrap());

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

        let copied =
            UPXDecompressor::copy_to_writable_temp(&std::fs::read(source.path()).unwrap()).unwrap();
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

    #[cfg(unix)]
    #[test]
    fn test_copy_to_writable_temp_drops_source_mode_bits() {
        use std::os::unix::fs::PermissionsExt;

        let mut source = NamedTempFile::new().unwrap();
        source.write_all(b"UPX! setuid sample").unwrap();
        source.flush().unwrap();
        std::fs::set_permissions(source.path(), std::fs::Permissions::from_mode(0o4777)).unwrap();

        let copied =
            UPXDecompressor::copy_to_writable_temp(&std::fs::read(source.path()).unwrap()).unwrap();
        let mode = std::fs::metadata(copied.path())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o7777, 0o600, "mode {mode:o}");
        assert_eq!(std::fs::read(copied.path()).unwrap(), b"UPX! setuid sample");
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
