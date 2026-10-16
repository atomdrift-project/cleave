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

use crate::analyzers::archive::{ArchiveAnalyzer, ArchiveAnalyzerConfig};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use crate::yara_engine::YaraEngine;
use memchr::memmem;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::OnceLock;

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
    Nuitka,
}

impl SfxKind {
    fn finding_id(self) -> &'static str {
        match self {
            SfxKind::Nsis => "file/sfx/nsis",
            SfxKind::InnoSetup => "file/sfx/inno-setup",
            SfxKind::PyInstaller => "file/sfx/pyinstaller",
            SfxKind::Nuitka => "file/sfx/nuitka",
        }
    }

    fn description(self) -> &'static str {
        match self {
            SfxKind::Nsis => "NSIS self-extracting installer",
            SfxKind::InnoSetup => "Inno Setup self-extracting installer",
            SfxKind::PyInstaller => "PyInstaller-bundled Python executable",
            SfxKind::Nuitka => "Nuitka compressed one-file Python bundle",
        }
    }

    fn name(self) -> &'static str {
        match self {
            SfxKind::Nsis => "NSIS",
            SfxKind::InnoSetup => "Inno Setup",
            SfxKind::PyInstaller => "PyInstaller",
            SfxKind::Nuitka => "Nuitka",
        }
    }
}

/// Result of an SFX analysis attempt.
pub(crate) struct SfxResult {
    /// Finding describing the detected SFX format.
    pub sfx_finding: Finding,
    /// Findings describing extraction/parser diagnostics from external tools.
    pub extraction_findings: Vec<Finding>,
    /// Analysis report from extracted contents, if extraction succeeded.
    pub archive_report: Option<AnalysisReport>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InnoExtractDiagnosticKind {
    UnexpectedLoaderRevision,
    LoaderChecksumMismatch,
    SetupDataVersionUndetermined,
    #[cfg_attr(
        not(all(target_os = "linux", target_arch = "x86_64")),
        allow(
            dead_code,
            reason = "only the Linux x86_64 long-path fallback constructs it"
        )
    )]
    LongMemberPathRemapped,
    GenericFailure,
}

impl InnoExtractDiagnosticKind {
    fn id(self) -> &'static str {
        match self {
            Self::UnexpectedLoaderRevision => {
                "file/sfx/inno-setup/extraction/unexpected-loader-revision"
            }
            Self::LoaderChecksumMismatch => {
                "file/sfx/inno-setup/extraction/loader-checksum-mismatch"
            }
            Self::LongMemberPathRemapped => {
                "file/sfx/inno-setup/extraction/long-member-path-remapped"
            }
            Self::SetupDataVersionUndetermined => {
                "file/sfx/inno-setup/extraction/setup-data-version-undetermined"
            }
            Self::GenericFailure => "file/sfx/inno-setup/extraction-failed",
        }
    }

    fn desc(self) -> &'static str {
        match self {
            Self::UnexpectedLoaderRevision => "Innoextract found unexpected setup loader revision",
            Self::LoaderChecksumMismatch => "Innoextract found setup loader checksum mismatch",
            Self::LongMemberPathRemapped => {
                "Inno Setup member path exceeded the filesystem limit and was shortened for analysis"
            }
            Self::SetupDataVersionUndetermined => {
                "Innoextract could not determine setup data version"
            }
            Self::GenericFailure => "Inno Setup extraction failed",
        }
    }

    fn crit(self) -> Criticality {
        match self {
            Self::UnexpectedLoaderRevision | Self::LoaderChecksumMismatch => {
                Criticality::Suspicious
            }
            Self::LongMemberPathRemapped
            | Self::SetupDataVersionUndetermined
            | Self::GenericFailure => Criticality::Notable,
        }
    }

    fn conf(self) -> f32 {
        match self {
            Self::LongMemberPathRemapped => 0.99,
            Self::GenericFailure => 0.86,
            _ => 0.95,
        }
    }

    fn attack(self) -> Option<&'static str> {
        match self {
            Self::LongMemberPathRemapped => None,
            _ => Some("T1027.009"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InnoExtractDiagnostic {
    kind: InnoExtractDiagnosticKind,
    message: String,
}

/// Detect SFX markers in the host bytes, excluding markers inside validated
/// embedded binaries that are analyzed separately.
#[must_use]
pub(crate) fn detect_sfx(
    data: &[u8],
    embedded_binaries: &[crate::analyzers::embedded_binary_detector::EmbeddedBinary],
) -> Option<SfxKind> {
    if marker_outside_embedded_binary(data, INNO_MARKER, embedded_binaries).is_some() {
        return Some(SfxKind::InnoSetup);
    }
    if has_strong_nsis_markers(data, embedded_binaries) {
        return Some(SfxKind::Nsis);
    }
    if marker_outside_embedded_binary(data, PYINST_MAGIC, embedded_binaries).is_some() {
        return Some(SfxKind::PyInstaller);
    }
    if marker_outside_embedded_binary(data, b"NUITKA_ONEFILE_", embedded_binaries).is_some()
        && marker_outside_embedded_binary(data, NUITKA_COMPRESSED, embedded_binaries).is_some()
    {
        return Some(SfxKind::Nuitka);
    }
    None
}

fn marker_outside_embedded_binary(
    data: &[u8],
    marker: &[u8],
    embedded_binaries: &[crate::analyzers::embedded_binary_detector::EmbeddedBinary],
) -> Option<usize> {
    memmem::find_iter(data, marker).find(|&offset| {
        !embedded_binaries.iter().any(|binary| {
            binary.encoding.is_none()
                && offset >= binary.offset
                && offset < binary.offset.saturating_add(binary.estimated_size)
        })
    })
}

fn has_strong_nsis_markers(
    data: &[u8],
    embedded_binaries: &[crate::analyzers::embedded_binary_detector::EmbeddedBinary],
) -> bool {
    marker_outside_embedded_binary(data, NSIS_DEADBEEF, embedded_binaries).is_some()
        && [
            NSIS_VERSION_BANNER,
            NSIS_ERROR_TITLE,
            NSIS_ERROR_URL,
            NSIS_NCRC_SWITCH,
        ]
        .iter()
        .any(|marker| marker_outside_embedded_binary(data, marker, embedded_binaries).is_some())
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
    engine: &crate::Engine,
    yara_engine: Option<Arc<YaraEngine>>,
    archive_config: Option<&ArchiveAnalyzerConfig>,
    embedded_binaries: &[crate::analyzers::embedded_binary_detector::EmbeddedBinary],
) -> SfxResult {
    let marker = match kind {
        SfxKind::Nsis => NSIS_DEADBEEF,
        SfxKind::InnoSetup => INNO_MARKER,
        SfxKind::PyInstaller => PYINST_MAGIC,
        SfxKind::Nuitka => NUITKA_COMPRESSED,
    };
    let marker_offset = marker_outside_embedded_binary(data, marker, embedded_binaries);

    let extraction = try_extract(
        file_path,
        data,
        kind,
        engine,
        yara_engine,
        archive_config,
        marker_offset,
    );
    let extracted = extraction.archive_report.is_some();

    let extraction_findings = extraction
        .inno_diagnostics
        .iter()
        .map(build_innoextract_finding)
        .collect();

    SfxResult {
        sfx_finding: build_finding(kind, extracted, marker_offset),
        extraction_findings,
        archive_report: extraction.archive_report,
    }
}

struct SfxExtraction {
    archive_report: Option<AnalysisReport>,
    inno_diagnostics: Vec<InnoExtractDiagnostic>,
}

fn build_finding(kind: SfxKind, extracted: bool, marker_offset: Option<usize>) -> Finding {
    Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        id: kind.finding_id().to_string().into(),
        desc: kind.description().to_string().into(),
        conf: if extracted { 1.0 } else { 0.9 },
        crit: Criticality::Notable,
        mbc: None,
        attack: Some("T1059".into()),
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
        downgraded: false,
    }
}

fn build_innoextract_finding(diagnostic: &InnoExtractDiagnostic) -> Finding {
    Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        id: diagnostic.kind.id().to_string().into(),
        desc: diagnostic.kind.desc().to_string().into(),
        conf: diagnostic.kind.conf(),
        crit: diagnostic.kind.crit(),
        mbc: None,
        attack: diagnostic.kind.attack().map(Into::into),
        evidence: vec![Evidence {
            method: "innoextract".to_string(),
            source: "sfx_detector".to_string(),
            value: diagnostic.message.clone(),
            ..Default::default()
        }],
        match_count: 1,
        trait_refs: vec![],
        source_file: None,
        downgraded: false,
    }
}

/// Try to extract the SFX contents using system tools.
fn try_extract(
    file_path: &Path,
    data: &[u8],
    kind: SfxKind,
    engine: &crate::Engine,
    yara_engine: Option<Arc<YaraEngine>>,
    archive_config: Option<&ArchiveAnalyzerConfig>,
    marker_offset: Option<usize>,
) -> SfxExtraction {
    // Bound nested Nuitka bundles, including those reached through encoded PEs.
    if kind == SfxKind::Nuitka && file_path.to_string_lossy().matches("!!").count() >= 8 {
        return SfxExtraction {
            archive_report: None,
            inno_diagnostics: vec![],
        };
    }
    // PyInstaller path: extract + analyze entirely in memory, no tmpdir.
    if kind == SfxKind::PyInstaller {
        return SfxExtraction {
            archive_report: analyze_pyinstaller_in_memory(
                data,
                file_path,
                engine,
                yara_engine,
                archive_config,
            ),
            inno_diagnostics: vec![],
        };
    }

    // Distinct prefix from the archive extractor's: both sites strand dirs on
    // an abnormal exit, and identical names would make the two leaks
    // indistinguishable on disk. See archive/mod.rs for the full reasoning.
    let Some(tmp) = tempfile::Builder::new()
        .prefix("cleave-sfx-")
        .tempdir()
        .ok()
    else {
        return SfxExtraction {
            archive_report: None,
            inno_diagnostics: vec![],
        };
    };

    // Always give the external extractor a private copy of the bytes Cleave
    // actually analyzed. Archive members commonly carry only a logical path,
    // and trusting a same-sized file at that path can make an attacker-selected
    // member redirect extraction to an unrelated file in Cleave's working
    // directory.
    let Ok(materialized_input) = materialize_extraction_input(data) else {
        return SfxExtraction {
            archive_report: None,
            inno_diagnostics: vec![],
        };
    };
    let extraction_path = materialized_input.path();

    let mut inno_diagnostics = vec![];
    let extracted = match kind {
        SfxKind::Nsis => run_7z(extraction_path, tmp.path()),
        SfxKind::Nuitka => {
            marker_offset.is_some_and(|offset| extract_nuitka_at(data, offset, tmp.path()).is_ok())
        }
        SfxKind::InnoSetup => {
            if let Some(innoextract) = innoextract_cmd() {
                let result = run_innoextract(&innoextract, extraction_path, tmp.path());
                inno_diagnostics = result.diagnostics;
                result.extracted
            } else {
                // Say why, rather than reporting a bare extraction failure.
                inno_diagnostics.push(InnoExtractDiagnostic {
                    kind: InnoExtractDiagnosticKind::GenericFailure,
                    message: "innoextract is not available".to_string(),
                });
                false
            }
        }
        SfxKind::PyInstaller => {
            // Early return above ensures this is unreachable.
            return SfxExtraction {
                archive_report: None,
                inno_diagnostics: vec![],
            };
        }
    };

    if !extracted {
        return SfxExtraction {
            archive_report: None,
            inno_diagnostics,
        };
    }

    SfxExtraction {
        archive_report: analyze_dir(tmp.path(), file_path, engine, yara_engine, archive_config),
        inno_diagnostics,
    }
}

/// Return a private, extractor-readable copy of the exact bytes being analyzed.
fn materialize_extraction_input(data: &[u8]) -> std::io::Result<tempfile::NamedTempFile> {
    let mut materialized = tempfile::Builder::new().suffix(".exe").tempfile()?;
    materialized.write_all(data)?;
    materialized.flush()?;
    Ok(materialized)
}

fn analyze_pyinstaller_in_memory(
    data: &[u8],
    file_path: &Path,
    engine: &crate::Engine,
    yara_engine: Option<Arc<YaraEngine>>,
    archive_config: Option<&ArchiveAnalyzerConfig>,
) -> Option<AnalysisReport> {
    let mut analyzer = ArchiveAnalyzer::new();
    if let Some(config) = archive_config {
        analyzer = config.apply(analyzer);
    }
    analyzer = analyzer.with_all_files_members();
    analyzer = analyzer.with_engine(engine.clone());
    if let Some(engine) = yara_engine {
        analyzer = analyzer.with_yara_arc(engine);
    }
    match analyzer.analyze_pyinstaller_bytes(data, file_path) {
        Ok(report) => Some(report),
        Err(e) => {
            tracing::debug!("pyinstx in-memory analysis failed: {e}");
            None
        }
    }
}

/// The path of the first of `names` that resolves and passes `probe_args`.
///
/// Only a success is remembered (in `cached`). A probe can fail for a moment:
/// a spawn refused while the machine is short of processes or threads, a
/// start slower than [`crate::subprocess::PROBE_TIMEOUT`] under load. Caching
/// that failure turned the tool off for the rest of the process, so a
/// long-running server silently stopped extracting every archive that needed
/// it. A failed probe is logged and retried by the next caller instead.
fn probed_tool(
    cached: &'static OnceLock<std::path::PathBuf>,
    names: &[&str],
    probe_args: &[&str],
) -> Option<std::path::PathBuf> {
    if let Some(path) = cached.get() {
        return Some(path.clone());
    }
    for name in names {
        let Some(path) = filefacts::tools::resolve(name) else {
            continue;
        };
        let mut probe = std::process::Command::new(&path);
        probe
            .args(probe_args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        crate::subprocess::scrub_env(&mut probe);
        match crate::subprocess::output_with_timeout(&mut probe, crate::subprocess::PROBE_TIMEOUT) {
            Ok(Some(_)) => return Some(cached.get_or_init(|| path).clone()),
            Ok(None) => tracing::warn!(
                tool = %path.display(),
                timeout_secs = crate::subprocess::PROBE_TIMEOUT.as_secs(),
                "tool probe timed out; skipping it for this file"
            ),
            Err(error) => tracing::warn!(
                tool = %path.display(),
                %error,
                "tool probe failed to run; skipping it for this file"
            ),
        }
    }
    None
}

fn innoextract_cmd() -> Option<std::path::PathBuf> {
    static CHOICE: OnceLock<std::path::PathBuf> = OnceLock::new();
    probed_tool(&CHOICE, &["innoextract"], &["--version"])
}

pub(crate) fn sevenzip_cmd() -> Option<std::path::PathBuf> {
    static CHOICE: OnceLock<std::path::PathBuf> = OnceLock::new();
    probed_tool(&CHOICE, &["7zz", "7z", "7za", "7zr"], &["i"])
}

pub(crate) fn run_7z(src: &Path, out: &Path) -> bool {
    let Some(command) = sevenzip_cmd() else {
        return false;
    };
    let mut command = std::process::Command::new(command);
    command
        .args(["x", "-y", &format!("-o{}", out.display()), "--"])
        .arg(src)
        // No stdin: an encrypted archive would otherwise wait at a password
        // prompt until the timeout.
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    crate::subprocess::scrub_env(&mut command);
    crate::subprocess::output_with_timeout(&mut command, crate::subprocess::EXTRACT_TIMEOUT)
        .is_ok_and(|output| output.is_some_and(|o| o.status.success()))
}

struct InnoExtractResult {
    extracted: bool,
    diagnostics: Vec<InnoExtractDiagnostic>,
}

fn run_innoextract(command: &Path, src: &Path, out: &Path) -> InnoExtractResult {
    let args = [
        std::ffi::OsStr::new("--extract"),
        std::ffi::OsStr::new("--output-dir"),
        out.as_os_str(),
        std::ffi::OsStr::new("--"),
        src.as_os_str(),
    ];
    let mut extract = std::process::Command::new(command);
    extract
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    crate::subprocess::scrub_env(&mut extract);
    match crate::subprocess::output_with_timeout(&mut extract, crate::subprocess::EXTRACT_TIMEOUT) {
        Ok(None) => InnoExtractResult {
            extracted: false,
            diagnostics: vec![InnoExtractDiagnostic {
                kind: InnoExtractDiagnosticKind::GenericFailure,
                message: format!(
                    "innoextract killed after {}s",
                    crate::subprocess::EXTRACT_TIMEOUT.as_secs()
                ),
            }],
        },
        Ok(Some(output)) => {
            #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
            if !output.status.success()
                && crate::analyzers::inno_long_path::reports_overlong_output(&output.stderr)
                && clear_extraction_directory(out).is_ok()
            {
                match crate::analyzers::inno_long_path::run(command.as_os_str(), &args) {
                    Ok((status, _stderr, remapped))
                        if libc::WIFEXITED(status)
                            && libc::WEXITSTATUS(status) == 0
                            && remapped > 0 =>
                    {
                        return InnoExtractResult {
                            extracted: true,
                            diagnostics: vec![InnoExtractDiagnostic {
                                kind: InnoExtractDiagnosticKind::LongMemberPathRemapped,
                                message: format!(
                                    "shortened {remapped} overlong Inno Setup output path(s) for analysis"
                                ),
                            }],
                        };
                    }
                    _ => {}
                }
            }

            let stderr = String::from_utf8_lossy(&output.stderr);
            InnoExtractResult {
                extracted: output.status.success(),
                diagnostics: classify_innoextract_diagnostics(&stderr),
            }
        }
        Err(e) => InnoExtractResult {
            extracted: false,
            diagnostics: vec![InnoExtractDiagnostic {
                kind: InnoExtractDiagnosticKind::GenericFailure,
                message: format!("failed to run innoextract: {e}"),
            }],
        },
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn clear_extraction_directory(path: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            std::fs::remove_dir_all(entry.path())?;
        } else {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

fn classify_innoextract_diagnostics(output: &str) -> Vec<InnoExtractDiagnostic> {
    let mut diagnostics = vec![];
    let lower = output.to_ascii_lowercase();

    for (needle, kind) in [
        (
            "unexpected setup loader revision",
            InnoExtractDiagnosticKind::UnexpectedLoaderRevision,
        ),
        (
            "setup loader checksum mismatch",
            InnoExtractDiagnosticKind::LoaderChecksumMismatch,
        ),
        (
            "could not determine setup data version",
            InnoExtractDiagnosticKind::SetupDataVersionUndetermined,
        ),
    ] {
        if let Some(message) = matching_diagnostic_line(output, &lower, needle) {
            diagnostics.push(InnoExtractDiagnostic { kind, message });
        }
    }

    if diagnostics.is_empty() && !output.trim().is_empty() {
        diagnostics.push(InnoExtractDiagnostic {
            kind: InnoExtractDiagnosticKind::GenericFailure,
            message: truncate_diagnostic(output.trim()),
        });
    }

    diagnostics
}

fn matching_diagnostic_line(output: &str, lower_output: &str, needle: &str) -> Option<String> {
    let start = lower_output.find(needle)?;
    let line_start = output[..start].rfind('\n').map_or(0, |pos| pos + 1);
    let line_end = output[start..]
        .find('\n')
        .map_or(output.len(), |pos| start + pos);
    Some(truncate_diagnostic(output[line_start..line_end].trim()))
}

fn truncate_diagnostic(message: &str) -> String {
    const MAX_DIAGNOSTIC_LEN: usize = 240;
    if message.len() <= MAX_DIAGNOSTIC_LEN {
        return message.to_string();
    }

    let mut end = MAX_DIAGNOSTIC_LEN;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &message[..end])
}

/// Analyze the extracted directory directly with ArchiveAnalyzer.
fn analyze_dir(
    dir: &Path,
    original_path: &Path,
    engine: &crate::Engine,
    yara_engine: Option<Arc<YaraEngine>>,
    archive_config: Option<&ArchiveAnalyzerConfig>,
) -> Option<AnalysisReport> {
    let mut analyzer = ArchiveAnalyzer::new();
    if let Some(config) = archive_config {
        analyzer = config.apply(analyzer);
    }
    analyzer = analyzer.with_all_files_members();
    analyzer = analyzer.with_engine(engine.clone());
    if let Some(engine) = yara_engine {
        analyzer = analyzer.with_yara_arc(engine);
    }

    analyzer
        .analyze_extracted_directory(dir, original_path)
        .ok()
}

// The Windows one-file payload starts with KA + Y (compressed), followed by
// one Zstandard frame. Its decoded records are NUL-terminated UTF-16LE names,
// u64 little-endian sizes and exact member bytes; an empty name ends the list.
const NUITKA_COMPRESSED: &[u8] = b"KAY\x28\xb5\x2f\xfd";
const NUITKA_MAX_TOTAL: u64 = 1024 * 1024 * 1024;
const NUITKA_MAX_MEMBER: u64 = 512 * 1024 * 1024;

fn nuitka_member_path(name: &str) -> std::io::Result<std::path::PathBuf> {
    let name = name.replace('\\', "/");
    if name.starts_with('/')
        || name.contains(':')
        || name
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
    {
        return Err(std::io::Error::other("unsafe Nuitka member name"));
    }
    Ok(std::path::PathBuf::from(name))
}

fn read_nuitka_name(reader: &mut impl std::io::Read) -> std::io::Result<String> {
    let mut units = Vec::new();
    for _ in 0..4096 {
        let mut pair = [0u8; 2];
        reader.read_exact(&mut pair)?;
        let unit = u16::from_le_bytes(pair);
        if unit == 0 {
            return String::from_utf16(&units)
                .map_err(|_| std::io::Error::other("invalid Nuitka UTF-16 name"));
        }
        units.push(unit);
    }
    Err(std::io::Error::other("Nuitka member name too long"))
}

#[cfg(test)]
fn extract_nuitka(data: &[u8], out: &Path) -> std::io::Result<()> {
    let offset = memmem::find(data, NUITKA_COMPRESSED)
        .ok_or_else(|| std::io::Error::other("missing Nuitka frame"))?;
    extract_nuitka_at(data, offset, out)
}

fn extract_nuitka_at(data: &[u8], offset: usize, out: &Path) -> std::io::Result<()> {
    use std::io::Read;
    let decoder = zstd::stream::read::Decoder::new(&data[offset + 3..])?.single_frame();
    // Cap both output and record overhead, even when the frame omits its size.
    let mut reader = decoder.take(NUITKA_MAX_TOTAL + 1);
    let mut total = 0u64;
    let mut names = std::collections::HashSet::new();
    for count in 0..4096 {
        let name = read_nuitka_name(&mut reader)?;
        if name.is_empty() {
            let mut trailing = [0];
            if count == 0 || reader.read(&mut trailing)? != 0 {
                return Err(std::io::Error::other("invalid Nuitka record terminator"));
            }
            return Ok(());
        }
        let relative = nuitka_member_path(&name)?;
        if !names.insert(relative.to_string_lossy().to_lowercase()) {
            return Err(std::io::Error::other("duplicate Nuitka member"));
        }
        let mut size = [0u8; 8];
        reader.read_exact(&mut size)?;
        let size = u64::from_le_bytes(size);
        total = total
            .checked_add(size)
            .ok_or_else(|| std::io::Error::other("Nuitka member size overflow"))?;
        if size > NUITKA_MAX_MEMBER || total > NUITKA_MAX_TOTAL {
            return Err(std::io::Error::other("Nuitka extraction byte limit"));
        }
        let path = out.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        if std::io::copy(&mut reader.by_ref().take(size), &mut file)? != size {
            return Err(std::io::Error::other("truncated Nuitka member"));
        }
    }
    Err(std::io::Error::other("Nuitka member count limit"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn nuitka_bundle(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut records = Vec::new();
        for (name, content) in entries {
            for unit in name.encode_utf16().chain(std::iter::once(0)) {
                records.extend_from_slice(&unit.to_le_bytes());
            }
            records.extend_from_slice(&(content.len() as u64).to_le_bytes());
            records.extend_from_slice(content);
        }
        records.extend_from_slice(&[0, 0]);
        let mut host = pe_stub();
        host.extend_from_slice(b"NUITKA_ONEFILE_PARENT\0KAY");
        host.extend(zstd::stream::encode_all(records.as_slice(), 1).unwrap());
        host.extend_from_slice(b"host section trailer");
        host
    }

    #[test]
    fn nuitka_extracts_unicode_and_nested_members_without_consuming_host_trailer() {
        let data = nuitka_bundle(&[("main.dll", b"MZdemo"), ("lib\\caf\u{e9}.txt", b"text")]);
        assert_eq!(detect_sfx(&data, &[]), Some(SfxKind::Nuitka));
        let out = tempfile::tempdir().unwrap();
        extract_nuitka(&data, out.path()).unwrap();
        assert_eq!(
            std::fs::read(out.path().join("main.dll")).unwrap(),
            b"MZdemo"
        );
        assert_eq!(
            std::fs::read(out.path().join("lib/caf\u{e9}.txt")).unwrap(),
            b"text"
        );
    }

    #[test]
    fn nuitka_rejects_unsafe_duplicate_and_truncated_members() {
        for name in [
            "../escape",
            "a\\..\\escape",
            "/absolute",
            "C:\\absolute",
            "a//b",
        ] {
            let out = tempfile::tempdir().unwrap();
            assert!(extract_nuitka(&nuitka_bundle(&[(name, b"x")]), out.path()).is_err());
        }
        let out = tempfile::tempdir().unwrap();
        assert!(extract_nuitka(&nuitka_bundle(&[("a", b"x"), ("A", b"y")]), out.path()).is_err());
        let mut data = nuitka_bundle(&[("main.dll", b"MZdemo")]);
        data.truncate(data.len() - 25);
        assert!(extract_nuitka(&data, out.path()).is_err());
    }

    #[test]
    fn nuitka_requires_both_runtime_and_frame_outside_embedded_images() {
        let data = nuitka_bundle(&[("main.dll", b"MZdemo")]);
        let frame = memmem::find(&data, NUITKA_COMPRESSED).unwrap();
        let embedded = [crate::analyzers::embedded_binary_detector::EmbeddedBinary {
            offset: frame,
            kind: crate::analyzers::embedded_binary_detector::EmbeddedKind::Pe64,
            estimated_size: data.len() - frame,
            encoding: None,
            format_hint: None,
        }];
        assert_eq!(detect_sfx(&data, &embedded), None);
        assert_eq!(detect_sfx(b"MZNUITKA_ONEFILE_PARENT", &[]), None);
    }

    fn pe_stub() -> Vec<u8> {
        // Minimal 256-byte buffer with MZ header (enough for marker scanning)
        let mut buf = vec![0u8; 256];
        buf[0] = 0x4D; // M
        buf[1] = 0x5A; // Z
        buf
    }

    fn make_synthetic_pe(buf: &mut Vec<u8>, offset: usize) {
        while buf.len() < offset + 4096 {
            buf.push(0);
        }
        buf[offset..offset + 2].copy_from_slice(b"MZ");
        buf[offset + 0x3C..offset + 0x40].copy_from_slice(&0x80u32.to_le_bytes());
        let pe = offset + 0x80;
        buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
        buf[pe + 4..pe + 6].copy_from_slice(&0x014Cu16.to_le_bytes());
        buf[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
        buf[pe + 20..pe + 22].copy_from_slice(&0x00E0u16.to_le_bytes());
        buf[pe + 24..pe + 26].copy_from_slice(&0x010Bu16.to_le_bytes());
        buf[pe + 80..pe + 84].copy_from_slice(&4096u32.to_le_bytes());
        let section = pe + 24 + 0xE0;
        buf[section + 16..section + 20].copy_from_slice(&512u32.to_le_bytes());
        buf[section + 20..section + 24].copy_from_slice(&512u32.to_le_bytes());
    }

    #[test]
    fn test_detect_nsis_deadbeef() {
        let mut data = pe_stub();
        data.extend_from_slice(NSIS_DEADBEEF);
        assert_eq!(detect_sfx(&data, &[]), None);
    }

    #[test]
    fn test_detect_nsis_with_secondary_marker() {
        let mut data = pe_stub();
        data.extend_from_slice(NSIS_DEADBEEF);
        data.extend_from_slice(NSIS_ERROR_TITLE);
        assert_eq!(detect_sfx(&data, &[]), Some(SfxKind::Nsis));
    }

    #[test]
    fn test_detect_inno_marker() {
        let mut data = pe_stub();
        data.extend_from_slice(INNO_MARKER);
        assert_eq!(detect_sfx(&data, &[]), Some(SfxKind::InnoSetup));
    }

    #[test]
    fn ignores_inno_marker_inside_validated_embedded_pe() {
        use crate::analyzers::embedded_binary_detector::{EmbeddedBinary, EmbeddedKind};

        let mut data = vec![0u8; 1024];
        data[..2].copy_from_slice(b"MZ");
        let offset = 512;
        data[offset..offset + 2].copy_from_slice(b"MZ");
        data[offset + 64..offset + 64 + INNO_MARKER.len()].copy_from_slice(INNO_MARKER);
        let embedded = [EmbeddedBinary {
            offset,
            kind: EmbeddedKind::Pe32,
            estimated_size: 512,
            encoding: None,
            format_hint: Some("inno"),
        }];

        assert_eq!(detect_sfx(&data, &embedded), None);
    }

    #[test]
    fn embedded_scanner_span_prevents_nested_inno_host_classification() {
        let mut data = vec![0u8; 8192];
        data[..2].copy_from_slice(b"MZ");
        let offset = 512;
        make_synthetic_pe(&mut data, offset);
        data[offset + 1024..offset + 1024 + INNO_MARKER.len()].copy_from_slice(INNO_MARKER);

        let embedded =
            crate::analyzers::embedded_binary_detector::scan_for_embedded_binaries(&data, None);
        assert!(
            embedded
                .iter()
                .any(|binary| { binary.offset == offset && binary.format_hint == Some("inno") })
        );
        assert_eq!(detect_sfx(&data, &embedded), None);
    }

    #[test]
    fn root_inno_marker_still_detected_alongside_nested_inno() {
        use crate::analyzers::embedded_binary_detector::{EmbeddedBinary, EmbeddedKind};

        let mut data = vec![0u8; 1024];
        data[..2].copy_from_slice(b"MZ");
        data[256..256 + INNO_MARKER.len()].copy_from_slice(INNO_MARKER);
        let offset = 512;
        data[offset..offset + 2].copy_from_slice(b"MZ");
        data[offset + 64..offset + 64 + INNO_MARKER.len()].copy_from_slice(INNO_MARKER);
        let embedded = [EmbeddedBinary {
            offset,
            kind: EmbeddedKind::Pe32,
            estimated_size: 512,
            encoding: None,
            format_hint: Some("inno"),
        }];

        assert_eq!(detect_sfx(&data, &embedded), Some(SfxKind::InnoSetup));
        assert_eq!(
            marker_outside_embedded_binary(&data, INNO_MARKER, &embedded),
            Some(256)
        );
    }

    #[test]
    fn ignores_nsis_markers_inside_validated_embedded_pe() {
        use crate::analyzers::embedded_binary_detector::{EmbeddedBinary, EmbeddedKind};

        let mut data = vec![0u8; 1024];
        data[..2].copy_from_slice(b"MZ");
        let offset = 512;
        data[offset..offset + 2].copy_from_slice(b"MZ");
        data[offset + 64..offset + 64 + NSIS_DEADBEEF.len()].copy_from_slice(NSIS_DEADBEEF);
        data[offset + 96..offset + 96 + NSIS_ERROR_TITLE.len()].copy_from_slice(NSIS_ERROR_TITLE);
        let embedded = [EmbeddedBinary {
            offset,
            kind: EmbeddedKind::Pe32,
            estimated_size: 512,
            encoding: None,
            format_hint: Some("nsis"),
        }];

        assert_eq!(detect_sfx(&data, &embedded), None);
    }

    #[test]
    fn test_inno_takes_precedence_over_weak_nsis_marker() {
        let mut data = pe_stub();
        data.extend_from_slice(INNO_MARKER);
        data.extend_from_slice(NSIS_DEADBEEF);
        assert_eq!(detect_sfx(&data, &[]), Some(SfxKind::InnoSetup));
    }

    #[test]
    fn test_detect_none_on_benign_data() {
        let data = b"This is a normal binary without any installer markers.".to_vec();
        assert_eq!(detect_sfx(&data, &[]), None);
    }

    #[test]
    fn test_detect_none_on_empty() {
        assert_eq!(detect_sfx(&[], &[]), None);
    }

    #[test]
    fn materializes_exact_analyzed_bytes_for_external_extractor() -> std::io::Result<()> {
        let data = b"installer bytes that only exist in memory";
        let materialized = materialize_extraction_input(data)?;

        assert_eq!(std::fs::read(materialized.path())?, data);
        assert_eq!(
            materialized.path().extension().and_then(|ext| ext.to_str()),
            Some("exe")
        );
        Ok(())
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

    #[test]
    fn test_classify_innoextract_known_failures() {
        let diagnostics = classify_innoextract_diagnostics(
            "Warning: unexpected setup loader revision: 2\n\
             Warning: setup loader checksum mismatch\n\
             Error: could not determine setup data version\n",
        );

        let kinds: Vec<_> = diagnostics
            .iter()
            .map(|diagnostic| diagnostic.kind)
            .collect();
        assert_eq!(
            kinds,
            vec![
                InnoExtractDiagnosticKind::UnexpectedLoaderRevision,
                InnoExtractDiagnosticKind::LoaderChecksumMismatch,
                InnoExtractDiagnosticKind::SetupDataVersionUndetermined,
            ]
        );
    }

    #[test]
    fn test_classify_innoextract_generic_failure() {
        let diagnostics = classify_innoextract_diagnostics("Error: unsupported Inno stream\n");

        assert_eq!(diagnostics.len(), 1);
        assert_eq!(
            diagnostics[0].kind,
            InnoExtractDiagnosticKind::GenericFailure
        );
        assert_eq!(diagnostics[0].message, "Error: unsupported Inno stream");
    }

    #[test]
    fn test_build_innoextract_finding_criticality() {
        let finding = build_innoextract_finding(&InnoExtractDiagnostic {
            kind: InnoExtractDiagnosticKind::LoaderChecksumMismatch,
            message: "setup loader checksum mismatch".to_string(),
        });

        assert_eq!(
            finding.id,
            "file/sfx/inno-setup/extraction/loader-checksum-mismatch"
        );
        assert_eq!(finding.crit, Criticality::Suspicious);
        assert_eq!(finding.evidence[0].value, "setup loader checksum mismatch");
    }

    #[test]
    fn test_build_inno_long_member_path_finding_is_not_malware_attribution() {
        let finding = build_innoextract_finding(&InnoExtractDiagnostic {
            kind: InnoExtractDiagnosticKind::LongMemberPathRemapped,
            message: "shortened 1 overlong Inno Setup output path(s) for analysis".to_string(),
        });

        assert_eq!(
            finding.id,
            "file/sfx/inno-setup/extraction/long-member-path-remapped"
        );
        assert_eq!(finding.crit, Criticality::Notable);
        assert_eq!(finding.attack, None);
    }
}
