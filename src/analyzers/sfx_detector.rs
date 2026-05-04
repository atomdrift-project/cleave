//! SFX installer format detection for NSIS and Inno Setup.
//!
//! Detects self-extracting installer formats that are heavily used in malware
//! distribution. Unlike simple overlay archives (handled by overlay.rs), these
//! formats use proprietary data blocks embedded within the PE body itself.
//!
//! # Extraction
//!
//! Extraction is attempted via system tools (`7zz`/`7z`, `innoextract`) when available.
//! A detection finding is always emitted even if extraction fails or tooling is absent.

use crate::analyzers::archive::ArchiveAnalyzer;
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use crate::yara_engine::YaraEngine;
use memchr::memmem;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

/// NSIS installer marker (little-endian 0xDEADBEEF).
const NSIS_DEADBEEF: &[u8] = &[0xEF, 0xBE, 0xAD, 0xDE];

/// Inno Setup data header string.
const INNO_MARKER: &[u8] = b"Inno Setup Setup Data";

/// PyInstaller cookie magic.
const PYINST_MAGIC: &[u8] = b"MEI\x0c\x0b\x0a\x0b\x0e";
const NSIS_VERSION_BANNER: &[u8] = b"Nullsoft Install System";
const NSIS_ERROR_TITLE: &[u8] = b"NSIS Error";
const NSIS_ERROR_URL: &[u8] = b"nsis.sf.net/NSIS_Error";
const NSIS_NCRC_SWITCH: &[u8] = b"/NCRC";

/// Known SFX installer kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SfxKind {
    Nsis,
    InnoSetup,
    PyInstaller,
}

impl SfxKind {
    fn finding_id(self) -> &'static str {
        match self {
            SfxKind::Nsis => "file/sfx/nsis",
            SfxKind::InnoSetup => "file/sfx/inno-setup",
            SfxKind::PyInstaller => "file/sfx/pyinstaller",
        }
    }

    fn description(self) -> &'static str {
        match self {
            SfxKind::Nsis => "NSIS self-extracting installer",
            SfxKind::InnoSetup => "Inno Setup self-extracting installer",
            SfxKind::PyInstaller => "PyInstaller-bundled Python executable",
        }
    }

    fn name(self) -> &'static str {
        match self {
            SfxKind::Nsis => "NSIS",
            SfxKind::InnoSetup => "Inno Setup",
            SfxKind::PyInstaller => "PyInstaller",
        }
    }
}

/// Result of an SFX analysis attempt.
pub(crate) struct SfxResult {
    /// Finding describing the detected SFX format.
    pub sfx_finding: Finding,
    /// Analysis report from extracted contents, if extraction succeeded.
    pub archive_report: Option<AnalysisReport>,
}

/// Detect NSIS or Inno Setup SFX markers in raw PE data.
///
/// Returns `None` if neither marker is found.
#[must_use]
pub(crate) fn detect_sfx(data: &[u8]) -> Option<SfxKind> {
    if memmem::find(data, INNO_MARKER).is_some() {
        return Some(SfxKind::InnoSetup);
    }
    if has_strong_nsis_markers(data) {
        return Some(SfxKind::Nsis);
    }
    if memmem::rfind(data, PYINST_MAGIC).is_some() {
        return Some(SfxKind::PyInstaller);
    }
    None
}

fn has_strong_nsis_markers(data: &[u8]) -> bool {
    if memmem::find(data, NSIS_DEADBEEF).is_none() {
        return false;
    }

    [
        NSIS_VERSION_BANNER,
        NSIS_ERROR_TITLE,
        NSIS_ERROR_URL,
        NSIS_NCRC_SWITCH,
    ]
    .iter()
    .any(|marker| memmem::find(data, marker).is_some())
}

/// Attempt to extract a detected SFX installer and analyze its contents.
///
/// Always returns an [`SfxResult`] with a detection finding. Extraction is
/// attempted via system tools and is best-effort — missing tools degrade
/// gracefully to detection-only mode.
pub(crate) fn analyze_sfx(
    file_path: &Path,
    kind: SfxKind,
    data: &[u8],
    capability_mapper: Option<Arc<CapabilityMapper>>,
    yara_engine: Option<Arc<YaraEngine>>,
) -> SfxResult {
    let marker = match kind {
        SfxKind::Nsis => NSIS_DEADBEEF,
        SfxKind::InnoSetup => INNO_MARKER,
        SfxKind::PyInstaller => PYINST_MAGIC,
    };
    let marker_offset = memmem::find(data, marker);

    let archive_report = try_extract(file_path, data, kind, capability_mapper, yara_engine);
    let extracted = archive_report.is_some();

    SfxResult {
        sfx_finding: build_finding(kind, extracted, marker_offset),
        archive_report,
    }
}

fn build_finding(kind: SfxKind, extracted: bool, marker_offset: Option<usize>) -> Finding {
    Finding {
        kind: FindingKind::Capability,
        id: kind.finding_id().to_string(),
        desc: kind.description().to_string(),
        conf: if extracted { 1.0 } else { 0.9 },
        crit: Criticality::Notable,
        mbc: None,
        attack: Some("T1059".to_string()),
        evidence: vec![Evidence {
            method: "marker_detection".to_string(),
            source: "sfx_detector".to_string(),
            value: format!(
                "{} marker found{}",
                kind.name(),
                if extracted { ", extracted" } else { "" }
            ),
            location: marker_offset.map(|o| format!("offset:{:#x}", o)),
            ..Default::default()
        }],
        match_count: 1,
        trait_refs: vec![],
        source_file: None,
    }
}

/// Try to extract the SFX contents using system tools.
fn try_extract(
    file_path: &Path,
    data: &[u8],
    kind: SfxKind,
    capability_mapper: Option<Arc<CapabilityMapper>>,
    yara_engine: Option<Arc<YaraEngine>>,
) -> Option<AnalysisReport> {
    let tmp = tempfile::tempdir().ok()?;
    let extracted = match kind {
        SfxKind::Nsis => run_7z(file_path, tmp.path()),
        SfxKind::InnoSetup => {
            if tool_available("innoextract") {
                run_innoextract(file_path, tmp.path())
            } else {
                false
            }
        }
        SfxKind::PyInstaller => run_pyinstx(data, tmp.path()),
    };

    if !extracted {
        return None;
    }

    analyze_dir(tmp.path(), file_path, capability_mapper, yara_engine)
}

fn tool_available(name: &str) -> bool {
    std::process::Command::new(name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn sevenzip_cmd() -> &'static str {
    // 0 = unresolved, 1 = 7zz, 2 = 7z
    static CHOICE: AtomicU8 = AtomicU8::new(0);
    match CHOICE.load(Ordering::Relaxed) {
        1 => "7zz",
        2 => "7z",
        _ => {
            let cmd = if std::process::Command::new("7zz")
                .arg("i")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok()
            {
                CHOICE.store(1, Ordering::Relaxed);
                "7zz"
            } else {
                CHOICE.store(2, Ordering::Relaxed);
                "7z"
            };
            cmd
        }
    }
}

fn run_7z(src: &Path, out: &Path) -> bool {
    std::process::Command::new(sevenzip_cmd())
        .args(["x", "-y", &format!("-o{}", out.display()), "--"])
        .arg(src)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_pyinstx(data: &[u8], out: &Path) -> bool {
    match pyinstx::extract(data, out) {
        Ok(stats) => stats.files_written > 0,
        Err(e) => {
            tracing::debug!("pyinstx extraction failed: {e}");
            false
        }
    }
}

fn run_innoextract(src: &Path, out: &Path) -> bool {
    std::process::Command::new("innoextract")
        .args(["--extract", "--output-dir"])
        .arg(out)
        .arg(src)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Analyze the extracted directory directly with ArchiveAnalyzer.
fn analyze_dir(
    dir: &Path,
    original_path: &Path,
    capability_mapper: Option<Arc<CapabilityMapper>>,
    yara_engine: Option<Arc<YaraEngine>>,
) -> Option<AnalysisReport> {
    let mut analyzer = ArchiveAnalyzer::new();
    if let Some(mapper) = capability_mapper {
        analyzer = analyzer.with_capability_mapper_arc(mapper);
    }
    if let Some(engine) = yara_engine {
        analyzer = analyzer.with_yara_arc(engine);
    }

    analyzer
        .analyze_extracted_directory(dir, original_path)
        .ok()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_stub() -> Vec<u8> {
        // Minimal 256-byte buffer with MZ header (enough for marker scanning)
        let mut buf = vec![0u8; 256];
        buf[0] = 0x4D; // M
        buf[1] = 0x5A; // Z
        buf
    }

    #[test]
    fn test_detect_nsis_deadbeef() {
        let mut data = pe_stub();
        data.extend_from_slice(NSIS_DEADBEEF);
        assert_eq!(detect_sfx(&data), None);
    }

    #[test]
    fn test_detect_nsis_with_secondary_marker() {
        let mut data = pe_stub();
        data.extend_from_slice(NSIS_DEADBEEF);
        data.extend_from_slice(NSIS_ERROR_TITLE);
        assert_eq!(detect_sfx(&data), Some(SfxKind::Nsis));
    }

    #[test]
    fn test_detect_inno_marker() {
        let mut data = pe_stub();
        data.extend_from_slice(INNO_MARKER);
        assert_eq!(detect_sfx(&data), Some(SfxKind::InnoSetup));
    }

    #[test]
    fn test_inno_takes_precedence_over_weak_nsis_marker() {
        let mut data = pe_stub();
        data.extend_from_slice(INNO_MARKER);
        data.extend_from_slice(NSIS_DEADBEEF);
        assert_eq!(detect_sfx(&data), Some(SfxKind::InnoSetup));
    }

    #[test]
    fn test_detect_none_on_benign_data() {
        let data = b"This is a normal binary without any installer markers.".to_vec();
        assert_eq!(detect_sfx(&data), None);
    }

    #[test]
    fn test_detect_none_on_empty() {
        assert_eq!(detect_sfx(&[]), None);
    }

    #[test]
    fn test_finding_nsis_no_extract() {
        let finding = build_finding(SfxKind::Nsis, false, Some(0x3136C));
        assert_eq!(finding.id, "file/sfx/nsis");
        assert_eq!(finding.crit, Criticality::Notable);
        assert!((finding.conf - 0.9).abs() < f32::EPSILON);
        assert_eq!(
            finding.evidence[0].location.as_deref(),
            Some("offset:0x3136c")
        );
    }

    #[test]
    fn test_finding_inno_with_extract() {
        let finding = build_finding(SfxKind::InnoSetup, true, None);
        assert_eq!(finding.id, "file/sfx/inno-setup");
        assert!((finding.conf - 1.0).abs() < f32::EPSILON);
        assert!(finding.evidence[0].location.is_none());
    }
}
