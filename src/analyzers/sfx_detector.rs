//! SFX installer format detection for NSIS, Inno Setup and InstallShield.
//!
//! Detects self-extracting installer formats that are heavily used in malware
//! distribution. Unlike simple overlay archives (handled by overlay.rs), these
//! formats use proprietary data blocks embedded within the PE body itself.
//!
//! # Extraction
//!
//! Extraction is attempted via system tools (`7zz`/`7z`, `innoextract`) when
//! available. InstallShield `ISSetupStream` launchers and NSIS install
//! scripts are decoded by filefacts; [`installer_members`] writes what it
//! decodes as members. A detection finding is always emitted even if
//! extraction fails or tooling is absent.

use crate::analyzers::archive::{ArchiveAnalyzer, ArchiveAnalyzerConfig};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use crate::yara_engine::YaraEngine;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
use std::sync::OnceLock;

/// Known SFX installer kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SfxKind {
    Nsis,
    InnoSetup,
    PyInstaller,
    Nuitka,
    IExpress,
    /// An InstallShield launcher carrying an `ISSetupStream`.
    InstallShield,
}

mod installer_members;

/// The installer filefacts identified in a PE (`binary.installer`) and the
/// offset its data starts at, moved back by `prefix` bytes of junk before
/// the PE the caller analyzes.
pub(crate) fn installer_from_values(
    values: &filefacts::Values,
    prefix: usize,
) -> Option<(SfxKind, Option<usize>)> {
    let kind = match values.get("binary.installer.kind")?.as_str()? {
        "nsis" => SfxKind::Nsis,
        "inno" => SfxKind::InnoSetup,
        "pyinstaller" => SfxKind::PyInstaller,
        "nuitka" => SfxKind::Nuitka,
        "iexpress" => SfxKind::IExpress,
        "installshield" => SfxKind::InstallShield,
        _ => return None,
    };
    let marker_offset = values
        .get("binary.installer.marker_offset")
        .and_then(serde_json::Value::as_u64)
        .and_then(|offset| usize::try_from(offset).ok())
        .and_then(|offset| offset.checked_sub(prefix));
    Some((kind, marker_offset))
}

/// Result of an SFX analysis attempt.
pub(crate) struct SfxResult {
    /// Findings describing extraction/parser diagnostics from external tools.
    pub extraction_findings: Vec<Finding>,
    /// Analysis report from extracted contents, if extraction succeeded.
    pub archive_report: Option<AnalysisReport>,
}

pub(crate) const UNEXPECTED_LOADER_REVISION_ID: &str =
    "metadata/file/format/installer::inno-setup-unexpected-loader-revision";
pub(crate) const LOADER_CHECKSUM_MISMATCH_ID: &str =
    "metadata/file/format/installer::inno-setup-loader-checksum-mismatch";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InnoExtractDiagnosticKind {
    UnexpectedLoaderRevision,
    LoaderChecksumMismatch,
}

impl InnoExtractDiagnosticKind {
    fn id(self) -> &'static str {
        match self {
            Self::UnexpectedLoaderRevision => UNEXPECTED_LOADER_REVISION_ID,
            Self::LoaderChecksumMismatch => LOADER_CHECKSUM_MISMATCH_ID,
        }
    }

    fn desc(self) -> &'static str {
        match self {
            Self::UnexpectedLoaderRevision => "Unexpected setup loader revision",
            Self::LoaderChecksumMismatch => "Setup loader checksum mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InnoExtractDiagnostic {
    kind: InnoExtractDiagnosticKind,
    message: String,
}

/// Attempt to extract a detected SFX installer and analyze its contents.
///
/// Always returns an [`SfxResult`] with a detection finding. Extraction is
/// attempted via system tools and is best-effort — missing tools degrade
/// gracefully to detection-only mode.
pub(crate) fn analyze_sfx(
    file_path: &Path,
    kind: SfxKind,
    marker_offset: Option<usize>,
    data: &[u8],
    engine: &crate::Engine,
    yara_engine: Option<Arc<YaraEngine>>,
    archive_config: Option<&ArchiveAnalyzerConfig>,
) -> SfxResult {
    let extraction = try_extract(
        file_path,
        data,
        kind,
        engine,
        yara_engine,
        archive_config,
        marker_offset,
    );
    let extraction_findings: Vec<Finding> = extraction
        .inno_diagnostics
        .iter()
        .map(build_innoextract_finding)
        .collect();

    SfxResult {
        extraction_findings,
        archive_report: extraction.archive_report,
    }
}

struct SfxExtraction {
    archive_report: Option<AnalysisReport>,
    inno_diagnostics: Vec<InnoExtractDiagnostic>,
}

fn build_innoextract_finding(diagnostic: &InnoExtractDiagnostic) -> Finding {
    Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        id: diagnostic.kind.id().to_string().into(),
        desc: diagnostic.kind.desc().to_string().into(),
        conf: 0.95,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: Some("T1027.009".into()),
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
    if kind == SfxKind::Nuitka
        && (file_path.to_string_lossy().matches("!!").count() >= 8
            || archive_config.is_some_and(|config| config.depth() >= 3))
    {
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

    // Always give an external extractor a private copy of the bytes Cleave
    // actually analyzed. Archive members commonly carry only a logical path,
    // and trusting a same-sized file at that path can make an attacker-selected
    // member redirect extraction to an unrelated file in Cleave's working
    // directory. Native extractors read `data` directly.
    let materialized_input = match kind {
        SfxKind::Nsis | SfxKind::IExpress | SfxKind::InnoSetup => {
            match materialize_extraction_input(data) {
                Ok(input) => Some(input),
                Err(_) => {
                    return SfxExtraction {
                        archive_report: None,
                        inno_diagnostics: vec![],
                    };
                }
            }
        }
        SfxKind::Nuitka | SfxKind::InstallShield | SfxKind::PyInstaller => None,
    };
    let extraction_path = materialized_input
        .as_ref()
        .map(tempfile::NamedTempFile::path);

    let mut inno_diagnostics = vec![];
    let extracted = match kind {
        SfxKind::Nsis => {
            // The files come from 7-Zip; the install script, which 7-Zip
            // leaves out, is decoded natively from the header.
            let files = extraction_path.is_some_and(|input| run_7z(input, tmp.path()));
            let script = installer_members::write_nsis_script(data, file_path, tmp.path());
            files || script
        }
        SfxKind::IExpress => extraction_path.is_some_and(|input| run_7z(input, tmp.path())),
        SfxKind::Nuitka => {
            marker_offset.is_some_and(|offset| extract_nuitka_to(data, offset, tmp.path()).is_ok())
        }
        SfxKind::InstallShield => marker_offset
            .and_then(|offset| data.get(offset..))
            .is_some_and(|stream| {
                let members = installer_members::extract_installshield(stream, file_path, tmp.path());
                tracing::info!(path = %file_path.display(), members, "extracted InstallShield ISSetupStream");
                members > 0
            }),
        SfxKind::InnoSetup => match (innoextract_cmd(), extraction_path) {
            (Some(innoextract), Some(input)) => {
                let result = run_innoextract(&innoextract, input, tmp.path());
                inno_diagnostics = result.diagnostics;
                result.extracted
            }
            _ => false,
        },
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
            tracing::debug!("PyInstaller in-memory analysis failed: {e}");
            None
        }
    }
}

fn innoextract_cmd() -> Option<std::path::PathBuf> {
    static CHOICE: OnceLock<std::path::PathBuf> = OnceLock::new();
    crate::subprocess::probed_tool(&CHOICE, &["innoextract"], &["--version"])
}

pub(crate) fn sevenzip_cmd() -> Option<std::path::PathBuf> {
    static CHOICE: OnceLock<std::path::PathBuf> = OnceLock::new();
    crate::subprocess::probed_tool(&CHOICE, &["7zz", "7z", "7za", "7zr"], &["i"])
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
    crate::subprocess::extract_with_timeout(
        &mut command,
        crate::subprocess::EXTRACT_TIMEOUT,
        out,
        crate::analyzers::archive::MAX_TOTAL_SIZE,
    )
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
    match crate::subprocess::extract_with_timeout(
        &mut extract,
        crate::subprocess::EXTRACT_TIMEOUT,
        out,
        crate::analyzers::archive::MAX_TOTAL_SIZE,
    ) {
        Ok(Some(output)) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            InnoExtractResult {
                extracted: output.status.success(),
                diagnostics: classify_innoextract_diagnostics(&stderr),
            }
        }
        // Killed past its budget, or failed to start: no diagnostics to judge.
        Ok(None) | Err(_) => InnoExtractResult {
            extracted: false,
            diagnostics: vec![],
        },
    }
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
    ] {
        if let Some(message) = matching_diagnostic_line(output, &lower, needle) {
            diagnostics.push(InnoExtractDiagnostic { kind, message });
        }
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

/// Extract the Nuitka payload whose marker starts `offset` bytes into
/// `data` into `out`, one new file per member. `unpack::nuitka` validates
/// every name and bounds the output; members stream straight to disk.
fn extract_nuitka_to(data: &[u8], offset: usize, out: &Path) -> std::io::Result<()> {
    unpack::nuitka::extract(data, offset, |relative, member| {
        let path = out.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        std::io::copy(member, &mut file).map(drop)
    })
    .map(drop)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
