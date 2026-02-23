//! Overlay data analyzer for binaries with appended archives.
//!
//! Many self-extracting archives (SFX) work by appending a ZIP/7z/RAR archive
//! to a PE/ELF/Mach-O stub. This module detects and analyzes such overlays.

use crate::analyzers::archive::ArchiveAnalyzer;
use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use std::sync::Arc;

/// Detect if data looks like an archive based on magic bytes.
/// Returns the archive type if detected, None otherwise.
#[must_use]
pub(crate) fn detect_archive_from_bytes(data: &[u8]) -> Option<&'static str> {
    if data.len() < 4 {
        return None;
    }

    // Check common archive magic bytes
    match &data[0..4] {
        // ZIP: PK\x03\x04
        [0x50, 0x4B, 0x03, 0x04] => Some("zip"),
        // 7z: 7z\xBC\xAF\x27\x1C
        [0x37, 0x7A, 0xBC, 0xAF] if data.len() >= 6 && data[4..6] == [0x27, 0x1C] => Some("7z"),
        // RAR: Rar!\x1A\x07
        [0x52, 0x61, 0x72, 0x21] if data.len() >= 6 && data[4..6] == [0x1A, 0x07] => Some("rar"),
        // RAR5: Rar!\x1A\x07\x01\x00
        [0x52, 0x61, 0x72, 0x21] if data.len() >= 8 && data[4..8] == [0x1A, 0x07, 0x01, 0x00] => {
            Some("rar")
        }
        // Gzip: \x1F\x8B
        [0x1F, 0x8B, _, _] => Some("gz"),
        // XZ: \xFD7zXZ\x00
        [0xFD, 0x37, 0x7A, 0x58] if data.len() >= 6 && data[4..6] == [0x5A, 0x00] => Some("xz"),
        // Zstd: \x28\xB5\x2F\xFD
        [0x28, 0xB5, 0x2F, 0xFD] => Some("zst"),
        // Bzip2: BZ
        [0x42, 0x5A, 0x68, _] => Some("bz2"),
        _ => None,
    }
}

/// Analyze overlay data appended to a binary.
///
/// This function:
/// 1. Checks if overlay data contains an archive (magic byte detection)
/// 2. Extracts overlay to a temporary file
/// 3. Analyzes it with ArchiveAnalyzer if it's an archive
/// 4. Returns findings to merge into the parent report
///
/// # Arguments
/// * `overlay_data` - The raw overlay bytes (data after binary image ends)
/// * `binary_path` - Original binary path (for error messages)
/// * `capability_mapper` - Shared capability mapper (optional)
/// * `yara_engine` - Shared YARA engine (optional)
///
/// # Returns
/// * `Some(OverlayAnalysis)` - If overlay contains an archive
/// * `None` - If overlay is not an archive (signature, resources, etc.)
pub(crate) fn analyze_overlay(
    overlay_data: &[u8],
    binary_path: &str,
    capability_mapper: Option<Arc<CapabilityMapper>>,
    yara_engine: Option<Arc<YaraEngine>>,
) -> Result<Option<OverlayAnalysis>> {
    // Check if overlay contains an archive
    let Some(archive_type) = detect_archive_from_bytes(overlay_data) else {
        return Ok(None); // Not an archive - might be signature, resources, etc.
    };

    eprintln!(
        "  Detected {} archive in overlay ({} bytes)",
        archive_type,
        overlay_data.len()
    );

    // Write overlay to temporary file with correct extension for ArchiveAnalyzer
    // The ArchiveAnalyzer uses file extension to determine archive type
    let temp_file = tempfile::Builder::new()
        .suffix(&format!(".{}", archive_type))
        .tempfile()
        .context("Failed to create temp file for overlay")?;

    std::fs::write(temp_file.path(), overlay_data)
        .context("Failed to write overlay to temp file")?;

    // Analyze the archive
    let mut analyzer = ArchiveAnalyzer::new();

    if let Some(mapper) = capability_mapper {
        analyzer = analyzer.with_capability_mapper_arc(mapper);
    }

    if let Some(engine) = yara_engine {
        analyzer = analyzer.with_yara_arc(engine);
    }

    match analyzer.analyze(temp_file.path()) {
        Ok(archive_report) => {
            // Create finding for the SFX overlay itself
            let sfx_finding = Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: format!("file/archive/self-extracting/{}", archive_type),
                desc: format!("Self-extracting archive ({})", archive_type.to_uppercase()),
                conf: 1.0, // We're certain based on magic bytes
                crit: Criticality::Notable,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "magic_bytes".to_string(),
                    source: "overlay_analyzer".to_string(),
                    value: format!("archive_type:{}", archive_type),
                    location: Some(format!("overlay:{}bytes", overlay_data.len())),
                }],
                source_file: Some(binary_path.to_string()),
            };

            Ok(Some(OverlayAnalysis {
                sfx_finding,
                archive_report,
            }))
        }
        Err(e) => {
            // Archive extraction failed - still emit a finding about the SFX
            eprintln!("  WARNING: Failed to extract overlay archive: {}", e);

            let sfx_finding = Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: format!(
                    "file/archive/self-extracting/{}/extraction-failed",
                    archive_type
                ),
                desc: format!(
                    "Self-extracting archive ({}) - extraction failed",
                    archive_type.to_uppercase()
                ),
                conf: 0.9,
                crit: Criticality::Suspicious, // Failed extraction is suspicious
                mbc: None,
                attack: None,
                evidence: vec![
                    Evidence {
                        method: "magic_bytes".to_string(),
                        source: "overlay_analyzer".to_string(),
                        value: format!("archive_type:{}", archive_type),
                        location: Some(format!("overlay:{}bytes", overlay_data.len())),
                    },
                    Evidence {
                        method: "extraction_error".to_string(),
                        source: "overlay_analyzer".to_string(),
                        value: format!("{}", e),
                        location: None,
                    },
                ],
                source_file: Some(binary_path.to_string()),
            };

            Ok(Some(OverlayAnalysis {
                sfx_finding,
                archive_report: AnalysisReport::new(TargetInfo {
                    path: format!("{}:overlay", binary_path),
                    file_type: archive_type.to_string(),
                    size_bytes: overlay_data.len() as u64,
                    sha256: crate::analyzers::utils::calculate_sha256(overlay_data),
                    architectures: None,
                }),
            }))
        }
    }
}

/// Result of overlay analysis
#[derive(Debug)]
pub(crate) struct OverlayAnalysis {
    /// Finding describing the SFX overlay itself
    pub sfx_finding: Finding,
    /// Full analysis report from the embedded archive
    pub archive_report: AnalysisReport,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_archive_from_bytes_zip() {
        let zip_magic = b"PK\x03\x04\x00\x00\x00\x00";
        assert_eq!(detect_archive_from_bytes(zip_magic), Some("zip"));
    }

    #[test]
    fn test_detect_archive_from_bytes_7z() {
        let sevenzip_magic = b"7z\xBC\xAF\x27\x1C\x00\x00";
        assert_eq!(detect_archive_from_bytes(sevenzip_magic), Some("7z"));
    }

    #[test]
    fn test_detect_archive_from_bytes_rar() {
        let rar_magic = b"Rar!\x1A\x07\x00\x00";
        assert_eq!(detect_archive_from_bytes(rar_magic), Some("rar"));
    }

    #[test]
    fn test_detect_archive_from_bytes_rar5() {
        let rar5_magic = b"Rar!\x1A\x07\x01\x00";
        assert_eq!(detect_archive_from_bytes(rar5_magic), Some("rar"));
    }

    #[test]
    fn test_detect_archive_from_bytes_gzip() {
        let gzip_magic = b"\x1F\x8B\x08\x00\x00\x00\x00\x00";
        assert_eq!(detect_archive_from_bytes(gzip_magic), Some("gz"));
    }

    #[test]
    fn test_detect_archive_from_bytes_xz() {
        let xz_magic = b"\xFD7zXZ\x00\x00\x00";
        assert_eq!(detect_archive_from_bytes(xz_magic), Some("xz"));
    }

    #[test]
    fn test_detect_archive_from_bytes_zstd() {
        let zstd_magic = b"\x28\xB5\x2F\xFD\x00\x00\x00\x00";
        assert_eq!(detect_archive_from_bytes(zstd_magic), Some("zst"));
    }

    #[test]
    fn test_detect_archive_from_bytes_bzip2() {
        let bzip2_magic = b"BZh9\x00\x00\x00\x00";
        assert_eq!(detect_archive_from_bytes(bzip2_magic), Some("bz2"));
    }

    #[test]
    fn test_detect_archive_from_bytes_not_archive() {
        let not_archive = b"\x00\x00\x00\x00\x00\x00\x00\x00";
        assert_eq!(detect_archive_from_bytes(not_archive), None);
    }

    #[test]
    fn test_detect_archive_from_bytes_pkcs7_signature() {
        // PKCS7 signatures start with 0x30 (ASN.1 SEQUENCE)
        let signature = b"\x30\x82\x05\xA0\x06\x09\x2A\x86";
        assert_eq!(detect_archive_from_bytes(signature), None);
    }

    #[test]
    fn test_detect_archive_from_bytes_too_short() {
        let too_short = b"PK\x03";
        assert_eq!(detect_archive_from_bytes(too_short), None);
    }

    #[test]
    fn test_detect_archive_from_bytes_empty() {
        let empty = b"";
        assert_eq!(detect_archive_from_bytes(empty), None);
    }

    #[test]
    fn test_detect_archive_from_bytes_partial_7z() {
        // 7z magic is 6 bytes, but we only have 4
        let partial = b"7z\xBC\xAF";
        assert_eq!(detect_archive_from_bytes(partial), None);
    }
}
