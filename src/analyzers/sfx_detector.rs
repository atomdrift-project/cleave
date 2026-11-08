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
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InnoExtractDiagnosticKind {
    UnexpectedLoaderRevision,
    LoaderChecksumMismatch,
    SetupDataVersionUndetermined,
    LongMemberPath,
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
            Self::LongMemberPath => "file/sfx/inno-setup/extraction/long-member-path",
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
            Self::LongMemberPath => {
                "Inno Setup member name exceeds the filesystem limit; that member was not extracted"
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
            Self::LongMemberPath | Self::SetupDataVersionUndetermined | Self::GenericFailure => {
                Criticality::Notable
            }
        }
    }

    fn conf(self) -> f32 {
        match self {
            Self::LongMemberPath => 0.99,
            Self::GenericFailure => 0.86,
            _ => 0.95,
        }
    }

    fn attack(self) -> Option<&'static str> {
        match self {
            Self::LongMemberPath => None,
            _ => Some("T1027.009"),
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
    let extracted = extraction.archive_report.is_some();

    let mut extraction_findings: Vec<Finding> = extraction
        .inno_diagnostics
        .iter()
        .map(build_innoextract_finding)
        .collect();
    if kind == SfxKind::Nuitka && !extracted {
        extraction_findings.push(
            Finding::structural(
                "metadata/file/format/nuitka::extraction-incomplete".to_string(),
                "Nuitka payload was not extracted".to_string(),
                1.0,
            )
            .with_criticality(Criticality::Notable),
        );
    }

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
        SfxKind::Nsis | SfxKind::IExpress => run_7z(extraction_path, tmp.path()),
        SfxKind::Nuitka => marker_offset.is_some_and(|offset| {
            if data.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
                || data.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
            {
                extract_nuitka_posix_cached_at(data, offset, tmp.path()).is_ok()
            } else {
                extract_nuitka_at(data, offset, tmp.path()).is_ok()
            }
        }),
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
        Ok(None) => InnoExtractResult {
            extracted: false,
            diagnostics: vec![InnoExtractDiagnostic {
                kind: InnoExtractDiagnosticKind::GenericFailure,
                message: format!(
                    "innoextract killed: ran past {}s or wrote over {} bytes",
                    crate::subprocess::EXTRACT_TIMEOUT.as_secs(),
                    crate::analyzers::archive::MAX_TOTAL_SIZE,
                ),
            }],
        },
        Ok(Some(output)) => {
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

/// Whether an innoextract error line reports an output file it could not
/// create because one path component is longer than the 255-byte name limit
/// of common filesystems.
fn names_overlong_output_file(line: &str) -> bool {
    if !line.to_ascii_lowercase().contains("open output file") {
        return false;
    }
    let (Some(start), Some(end)) = (line.find('"'), line.rfind('"')) else {
        return false;
    };
    end > start
        && line[start + 1..end]
            .split(['/', '\\'])
            .any(|component| component.len() > 255)
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
    if let Some(line) = output.lines().find(|line| names_overlong_output_file(line)) {
        diagnostics.push(InnoExtractDiagnostic {
            kind: InnoExtractDiagnosticKind::LongMemberPath,
            message: truncate_diagnostic(line.trim()),
        });
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
            return String::from_utf16(&units).map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    anyhow::Error::new(err).context("invalid Nuitka UTF-16 name"),
                )
            });
        }
        units.push(unit);
    }
    Err(std::io::Error::other("Nuitka member name too long"))
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

/// Cached POSIX Nuitka stream: UTF-8 name, flags, little-endian size,
/// CRC32, then bytes. Reject links rather than creating filesystem links.
/// Uncached and newer table-of-contents layouts are intentionally rejected;
/// failing extraction must not be mistaken for complete coverage.
fn extract_nuitka_posix_cached_at(data: &[u8], offset: usize, out: &Path) -> std::io::Result<()> {
    use std::io::{Read, Write};
    let frame = offset
        .checked_add(3)
        .and_then(|start| data.get(start..))
        .ok_or_else(|| std::io::Error::other("invalid Nuitka frame offset"))?;
    let decoder = zstd::stream::read::Decoder::new(frame)?.single_frame();
    let mut reader = decoder.take(NUITKA_MAX_TOTAL + 1);
    let mut total = 0u64;
    let mut names = std::collections::HashSet::new();
    for count in 0..4096 {
        let mut name = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte)?;
            if byte[0] == 0 {
                break;
            }
            if name.len() >= 4096 {
                return Err(std::io::Error::other("Nuitka member name too long"));
            }
            name.push(byte[0]);
        }
        if name.is_empty() {
            let mut trailing = [0u8; 1];
            if count == 0 || reader.read(&mut trailing)? != 0 {
                return Err(std::io::Error::other("invalid Nuitka record terminator"));
            }
            return Ok(());
        }
        let name = std::str::from_utf8(&name).map_err(|err| {
            std::io::Error::other(format!("invalid Nuitka UTF-8 member name: {err}"))
        })?;
        let relative = nuitka_member_path(name)?;
        if !names.insert(relative.to_string_lossy().to_lowercase()) {
            return Err(std::io::Error::other("duplicate Nuitka member"));
        }
        let mut flag = [0u8; 1];
        reader.read_exact(&mut flag)?;
        if flag[0] & !1 != 0 {
            return Err(std::io::Error::other("unsupported Nuitka member flags"));
        }
        let mut size_bytes = [0u8; 8];
        let mut crc_bytes = [0u8; 4];
        reader.read_exact(&mut size_bytes)?;
        reader.read_exact(&mut crc_bytes)?;
        let size = u64::from_le_bytes(size_bytes);
        let expected_crc = u32::from_le_bytes(crc_bytes);
        total = total
            .checked_add(size)
            .ok_or_else(|| std::io::Error::other("Nuitka size overflow"))?;
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
        let mut checksum = crc32fast::Hasher::new();
        let mut remaining = size;
        let mut buffer = [0u8; 32768];
        while remaining > 0 {
            let take = remaining.min(buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..take])?;
            checksum.update(&buffer[..take]);
            file.write_all(&buffer[..take])?;
            remaining -= take as u64;
        }
        let actual = checksum.finalize();
        if expected_crc != actual.max(1) {
            return Err(std::io::Error::other("Nuitka member CRC mismatch"));
        }
    }
    Err(std::io::Error::other("Nuitka member count limit"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
