//! UPX executable unpacking: runs the `upx` tool on a private copy.
//!
//! What a refusal means and the checksum repair live in `unpack::upx`; this
//! module owns the subprocess, its limits, and the triage policy.

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
    /// `upx` refused the image; its stderr.
    #[error("UPX decompression failed: {0}")]
    DecompressionFailed(String),
    #[error("UPX decompression timed out")]
    TimedOut,
    #[error("Decompressed UPX size exceeds limit ({0} > {MAX_UPX_DECOMPRESSED_SIZE})")]
    TooLarge(u64),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

/// Largest image `upx -d` may write back.
const MAX_UPX_DECOMPRESSED_SIZE: u64 = 100 * 1024 * 1024;

/// Whether `upx` itself rejected the image, as opposed to a limit of this
/// run: a missing tool, an I/O failure, a timeout, a size ceiling or an
/// unreadable input say nothing about the file. Only the fact is recorded
/// (`upx.refused`); what a refusal means is a trait's judgment.
pub(crate) fn refused_by_tool(err: &UPXError) -> bool {
    let UPXError::DecompressionFailed(stderr) = err else {
        return false;
    };
    unpack::upx::classify(stderr).description != "UPX could not read the image"
}

/// Record outcome metrics (each `1`) on `report` for traits to judge. They
/// are set while the report is still being structured, before the rule
/// engine runs.
fn set_metrics(report: &mut crate::types::AnalysisReport, names: &[&str]) {
    let metrics = report
        .filefacts_metrics
        .get_or_insert_with(Default::default);
    for name in names {
        metrics.insert(format!("upx.{name}"), 1.0);
    }
}

/// Whether `report` carries the `upx.<name>` outcome metric.
#[cfg(test)]
pub(crate) fn recorded(report: &crate::types::AnalysisReport, name: &str) -> bool {
    report
        .filefacts_metrics
        .as_ref()
        .is_some_and(|metrics| metrics.get(&format!("upx.{name}")) == Some(&1.0))
}

/// The file carries UPX's packing marker.
pub(crate) fn record_packed(report: &mut crate::types::AnalysisReport) {
    set_metrics(report, &["packed"]);
}

/// The unpacked image was not analyzed because UPX is disabled or missing.
pub(crate) fn record_tool_missing(report: &mut crate::types::AnalysisReport) {
    set_metrics(report, &["tool_missing"]);
}

/// `upx -d` failed with `err`: `upx.refused` when the tool itself rejected
/// the image, even if a later repair recovers it.
pub(crate) fn record_attempt_failure(report: &mut crate::types::AnalysisReport, err: &UPXError) {
    if refused_by_tool(err) {
        set_metrics(report, &["refused"]);
    }
}

/// The image only unpacked after its checksums were repaired on an
/// analysis copy.
pub(crate) fn record_checksum_repaired(report: &mut crate::types::AnalysisReport) {
    set_metrics(report, &["checksum_mismatch", "checksum_repaired"]);
}

/// The final failure to unpack: `upx.decompression_failed`, the reason in
/// the fixed vocabulary of [`classify_failure`] as the `upx.failure` value,
/// and `upx.invalid_image` / `upx.checksum_mismatch` when the image itself
/// is at fault.
pub(crate) fn record_failure(report: &mut crate::types::AnalysisReport, err: &UPXError) {
    let failure = classify_failure(err);
    set_metrics(report, &["decompression_failed"]);
    if failure.invalid_image {
        set_metrics(report, &["invalid_image"]);
    }
    if failure.checksum_mismatch {
        set_metrics(report, &["checksum_mismatch"]);
    }
    report.merge_kv_subtree("upx", serde_json::json!({"failure": failure.description}));
}

/// Why decompression failed, in a fixed vocabulary that diffs cleanly
/// across runs; the raw stderr goes to the debug log. Conditions of the run
/// (no tool, I/O, timeout, size ceiling) are never evidence about the image.
pub(crate) fn classify_failure(err: &UPXError) -> unpack::upx::Refusal {
    let run = |description| unpack::upx::Refusal {
        description,
        checksum_mismatch: false,
        invalid_image: false,
    };
    match err {
        UPXError::NotInstalled => run("UPX tool not available to unpack"),
        UPXError::IoError(_) => run("UPX decompression I/O error"),
        UPXError::TimedOut => run("UPX decompression timed out"),
        UPXError::TooLarge(_) => run("UPX payload exceeds decompression size limit"),
        UPXError::DecompressionFailed(stderr) => unpack::upx::classify(stderr),
    }
}

pub(crate) struct UPXDecompressor;

impl UPXDecompressor {
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
        //
        // `upx -d` writes through a temp file named by swapping the input's
        // last extension for `.upx`. The default `.tmpXXXXXX` name is all
        // extension, so every unpack in the temp dir raced for `.upx` and
        // the losers failed with "File exists"; a real extension gives each
        // copy its own temp name.
        let mut temp_file = tempfile::Builder::new()
            .prefix("cleave-upx-")
            .suffix(".bin")
            .tempfile()?;
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
            return Err(UPXError::TimedOut);
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(UPXError::DecompressionFailed(stderr.to_string()));
        }

        let size = std::fs::metadata(temp_path)?.len();
        if size > MAX_UPX_DECOMPRESSED_SIZE {
            return Err(UPXError::TooLarge(size));
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
    fn tool_refusal_is_separated_from_environment() {
        for message in [
            "checksum error",
            "CantUnpackException: unsupported format",
            "NotPackedException: not packed",
            "corrupt file",
        ] {
            assert!(refused_by_tool(&UPXError::DecompressionFailed(
                message.into()
            )));
        }
        for err in [
            UPXError::NotInstalled,
            UPXError::IoError(std::io::Error::other("unavailable input")),
            UPXError::TimedOut,
            UPXError::TooLarge(200),
            UPXError::DecompressionFailed("IOException".into()),
        ] {
            assert!(!refused_by_tool(&err));
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
            UPXError::TimedOut,
            UPXError::TooLarge(200),
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

    /// Concurrent unpacks must not share upx's temp name, which it derives
    /// as the file name up to its last `.`, then `.upx`.
    #[test]
    fn writable_temp_copies_give_upx_distinct_temp_names() {
        let upx_temp = |copy: &NamedTempFile| {
            let name = copy.path().file_name().unwrap().to_str().unwrap();
            let stem = name.rfind('.').map_or(name, |dot| &name[..dot]);
            copy.path().with_file_name(format!("{stem}.upx"))
        };
        let a = UPXDecompressor::copy_to_writable_temp(b"UPX! a").unwrap();
        let b = UPXDecompressor::copy_to_writable_temp(b"UPX! b").unwrap();
        assert_ne!(upx_temp(&a), upx_temp(&b));
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
