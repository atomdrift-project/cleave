//! Archive analyzer for various archive formats.

pub(crate) mod analyzers;
mod asar;
mod cpio;
mod dotnet_bundle;
mod guards;
#[cfg(test)]
mod guards_test;
mod iso;
mod member_data;
mod rpa;
mod source_context;
mod squashfs;
mod system_packages;
mod tar;
pub(crate) mod utils;
pub(crate) mod zip;

pub(crate) use guards::MAX_ZIP_ENTRIES;
pub(crate) use guards::{
    HostileArchiveReason, MAX_COMPRESSION_RATIO, MIN_ZIP_BOMB_UNCOMPRESSED_SIZE,
};

use crate::analyzers::{AnalysisInput, Analyzer, FileType, FileTypeExt};
#[cfg(test)]
use crate::types::FileAnalysis;
use crate::types::{
    AnalysisReport, ArchiveEntry, Criticality, Evidence, Finding, FindingKind, StructuralFeature,
    TargetInfo,
};
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use std::fs::{self};
use std::path::Path;
use std::sync::Arc;

use crate::composite_rules::SectionMap;
pub(crate) use guards::MAX_TOTAL_SIZE;
use guards::{
    ExtractedMemberMetadata, ExtractionGuard, MAX_FILE_COUNT, MAX_FILE_SIZE, escaped_relative_path,
    names_extraction_root,
};
use utils::calculate_sha256;

mod decompress;
#[allow(clippy::wildcard_imports)]
use decompress::*;

mod findings;
#[allow(clippy::wildcard_imports)]
use findings::*;

mod consistency;
#[allow(clippy::wildcard_imports)]
use consistency::*;

/// Default maximum file size to keep in memory (100 MB)
pub(crate) const DEFAULT_MAX_MEMORY_FILE_SIZE: u64 = 100 * 1024 * 1024;
const MAX_ARCHIVE_PATH_TRAVERSAL_EVIDENCE: usize = 10;
/// Extraction notes attached as evidence to the incomplete-archive finding.
/// The rest still reach `metadata.errors`; this only bounds the rendered set.
const MAX_INCOMPLETE_ARCHIVE_EVIDENCE: usize = 5;

/// Give container-owned findings an explicit archive-root location. An
/// absent/value/offset-only location otherwise becomes the empty scope key,
/// which can let `scope: archive` join it to evidence from unrelated members.
fn locate_archive_root_findings(findings: &mut [Finding]) {
    for finding in findings {
        for evidence in &mut finding.evidence {
            match evidence.location.as_deref() {
                Some(location) if location.starts_with("archive:") => {}
                Some(location) => evidence.location = Some(format!("archive:{location}")),
                None => evidence.location = Some("archive:".to_string()),
            }
        }
    }
}

/// Return a member path relative to this archive, using the single `!`
/// separator expected by `Evidence.location` and archive-scope bucketing.
fn archive_member_relative_path(container_path: &str, member_path: &str) -> String {
    let prefix = format!("{container_path}!!");
    let relative = member_path
        .strip_prefix(&prefix)
        .or_else(|| {
            member_path
                .strip_prefix(container_path)
                .map(|p| p.trim_start_matches('!'))
        })
        .unwrap_or(member_path);
    relative.replace("!!", "!")
}

/// Attribute evidence from an analyzed member to its containing archive path.
/// This preserves byte/value detail while making the nearest archive visible
/// to `scope: archive` composites.
fn locate_archive_member_finding(finding: &mut Finding, relative_path: &str) {
    for evidence in &mut finding.evidence {
        let location = match evidence.location.as_deref() {
            Some(location) if location.starts_with("archive:") => {
                let expected = format!("archive:{relative_path}");
                if location == expected
                    || location.starts_with(&format!("{expected}:"))
                    || location.starts_with(&format!("{expected}!"))
                {
                    continue;
                }
                let owner = relative_path
                    .rsplit_once('!')
                    .map_or(relative_path, |(archive, _)| archive);
                format!(
                    "archive:{owner}!{}",
                    location.trim_start_matches("archive:")
                )
            }
            Some(location) => format!("archive:{relative_path}:{location}"),
            None => format!("archive:{relative_path}"),
        };
        evidence.location = Some(location);
    }
}

fn is_zip_container(file_type: FileType) -> bool {
    matches!(
        file_type,
        FileType::Zip
            | FileType::GoModule
            | FileType::Composer
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

/// Whether an extracted zip actually carries Java bytecode.
///
/// `is_zip_container` is true of every zip-shaped format — wheels, VSIXes,
/// nupkgs, npm tarballs repacked as zips, plain zips — but `analyze_jar_archive`
/// exists to separate `.class` members from the resources sitting around them.
/// Handing it a package with no bytecode makes the entire payload "resources"
/// and subjects it to a sampling cap meant for icons and properties files, so
/// an npm package large enough to exceed the cap can lose its `package.json`
/// and, with it, every install-hook and dependency trait it should have had.
///
/// Deciding on content rather than extension cuts both ways on purpose: a Java
/// application shipped as a plain `.zip` still reaches the JAR analyzer, and a
/// `.jar` that turns out to hold no bytecode does not.
fn contains_java_members(temp_dir: &Path) -> bool {
    walkdir::WalkDir::new(temp_dir)
        .min_depth(1)
        .max_depth(guards::MAX_ARCHIVE_MEMBER_DEPTH)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_type().is_file())
        .any(|e| {
            let path = e.path();
            path.extension().is_some_and(|ext| {
                ext.eq_ignore_ascii_case("class") || ext.eq_ignore_ascii_case("dex")
            }) || path
                .file_name()
                .is_some_and(|n| n.eq_ignore_ascii_case("MANIFEST.MF"))
        })
}

/// Drop symlink-escape findings from a container that [`carries_system_symlinks`]:
/// its own, and those of every member folded into it (a container image's
/// layer tarballs are separate nested archives that report their own).
fn drop_system_container_symlink_escapes(report: &mut AnalysisReport) {
    let is_escape = |finding: &Finding| finding.id == "anti-analysis/archive/symlink-escape";
    report.findings.retain(|finding| !is_escape(finding));
    for file in &mut report.files {
        file.findings.retain(|finding| !is_escape(finding));
    }
}

/// Whether this archive's path-traversal (zip-slip) findings are expected: an
/// OS package, whose format names members by absolute path. Judged from the
/// detected type and member list, never from the archive's path, which for a
/// nested archive is a member name rather than a file on disk.
fn should_suppress_path_traversal_findings(
    archive_type: FileType,
    contents: &[ArchiveEntry],
    hostile_reasons: &[HostileArchiveReason],
) -> bool {
    if !hostile_reasons
        .iter()
        .any(|reason| matches!(reason, HostileArchiveReason::PathTraversal(_)))
    {
        return false;
    }
    is_system_package(archive_type, contents)
}

/// Analyzes archive files (zip, tar, 7z, etc.) by extracting and analyzing each member
#[derive(Debug)]
pub(crate) struct ArchiveAnalyzer {
    max_depth: usize,
    current_depth: usize,
    /// Rayon thread that began this (top-level) archive's analysis — its
    /// lane. A member job running elsewhere was stolen; see
    /// `analyze_extracted_member` for why only lane-executed members may
    /// wait on a busy single-flight.
    lane_thread: std::sync::atomic::AtomicUsize,
    /// Path prefix for nested archives (e.g., "inner.tar.gz" becomes "outer.zip!inner.tar.gz")
    archive_path_prefix: Option<String>,
    engine: crate::Engine,
    yara_engine: Option<Arc<YaraEngine>>,
    /// Passwords to try for encrypted zip files
    zip_passwords: Arc<[String]>,
    /// Maximum file size to keep in memory during extraction.
    /// Files larger than this are written to temp files.
    max_memory_file_size: u64,
    /// Per-request cancellation flag — checked in streaming loops.
    cancelled: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Analysis options for member-level cache lookups.
    analysis_options: Option<Arc<crate::AnalysisOptions>>,
    /// Extraction limits shared with every archive nested inside this one.
    budget: Arc<guards::ExtractionBudget>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ArchiveAnalyzerConfig {
    current_depth: usize,
    max_memory_file_size: Option<u64>,
    analysis_options: Option<Arc<crate::AnalysisOptions>>,
    cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// The enclosing archive's extraction budget, when there is one.
    budget: Option<Arc<guards::ExtractionBudget>>,
}

impl ArchiveAnalyzerConfig {
    #[must_use]
    pub(crate) fn with_depth(mut self, depth: usize) -> Self {
        self.current_depth = depth;
        self
    }

    pub(crate) fn depth(&self) -> usize {
        self.current_depth
    }

    #[must_use]
    pub(crate) fn from_analysis_options(options: &crate::AnalysisOptions) -> Self {
        Self {
            current_depth: 0,
            max_memory_file_size: Some(options.max_memory_file_size),
            analysis_options: Some(Arc::new(options.clone())),
            cancellation: options.cancellation.clone(),
            budget: None,
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
        analyzer = analyzer.with_depth(self.current_depth);
        if let Some(size) = self.max_memory_file_size {
            analyzer = analyzer.with_max_memory_file_size(size);
        }
        if let Some(options) = &self.analysis_options {
            analyzer = analyzer.with_analysis_options(options.clone());
        }
        if let Some(flag) = &self.cancellation {
            analyzer = analyzer.with_cancellation(flag.clone());
        }
        if let Some(budget) = &self.budget {
            analyzer.budget = budget.clone();
        }
        analyzer
    }
}

impl ArchiveAnalyzer {
    /// Create a new archive analyzer with default settings
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            max_depth: 3,
            current_depth: 0,
            lane_thread: std::sync::atomic::AtomicUsize::new(usize::MAX),
            archive_path_prefix: None,
            engine: crate::Engine::empty(),
            yara_engine: None,
            zip_passwords: Arc::from([]),
            max_memory_file_size: DEFAULT_MAX_MEMORY_FILE_SIZE,
            cancelled: None,
            analysis_options: None,
            budget: Arc::default(),
        }
    }

    /// Returns true if the caller has signalled cancellation for this request.
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled
            .as_ref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Acquire))
    }

    /// Set the maximum file size to keep in memory during extraction.
    /// Files larger than this are written to temp files.
    #[must_use]
    pub(crate) fn with_max_memory_file_size(mut self, size_bytes: u64) -> Self {
        self.max_memory_file_size = size_bytes;
        self
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
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_capability_mapper(
        mut self,
        mapper: crate::capabilities::CapabilityMapper,
    ) -> Self {
        self.engine = crate::Engine::from_rules(Arc::new(mapper));
        self
    }

    /// Analyze under `engine`: its rules and settings.
    #[must_use]
    pub(crate) fn with_engine(mut self, engine: crate::Engine) -> Self {
        self.engine = engine;
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
            current_depth: self.current_depth + 1,
            max_memory_file_size: Some(self.max_memory_file_size),
            analysis_options: self.analysis_options.clone(),
            cancellation: self.cancelled.clone(),
            budget: Some(self.budget.clone()),
        }
    }

    /// Copy this analyzer with independent lane tracking for member analysis.
    #[must_use]
    pub(crate) fn clone_for_member_analysis(&self) -> Self {
        Self {
            max_depth: self.max_depth,
            current_depth: self.current_depth,
            lane_thread: std::sync::atomic::AtomicUsize::new(usize::MAX),
            archive_path_prefix: self.archive_path_prefix.clone(),
            engine: self.engine.clone(),
            yara_engine: self.yara_engine.clone(),
            zip_passwords: self.zip_passwords.clone(),
            max_memory_file_size: self.max_memory_file_size,
            cancelled: self.cancelled.clone(),
            analysis_options: self.analysis_options.clone(),
            budget: self.budget.clone(),
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
        if self.current_depth == 0 {
            self.lane_thread.store(
                rayon::current_thread_index().unwrap_or(usize::MAX),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        let start = std::time::Instant::now();

        if self.current_depth >= self.max_depth {
            anyhow::bail!("Maximum archive depth ({}) exceeded", self.max_depth);
        }

        if self.is_cancelled() {
            anyhow::bail!("Analysis cancelled before archive extraction");
        }

        let guard = ExtractionGuard::with_budget(self.cancelled.clone(), self.budget.clone());
        // One detection pass for both cleave's type and the filefacts context
        // below: `from_path_and_bytes` is `detect` plus the extension-mismatch
        // carve-outs, and `detect` on a gzip tar inflates up to 64 MiB of it.
        let fileid = filefacts::FileId::from_path_and_bytes(archive_path, data);
        let file_type = crate::analyzers::detect_file_type_from_detected(
            archive_path,
            data,
            Some(fileid.file_type()).filter(|ft| *ft != FileType::Unknown),
        );
        let archive_type_str = file_type.report_file_type();

        let target = TargetInfo {
            path: archive_path.display().to_string(),
            file_type: archive_type_str.clone(),
            size_bytes: data.len() as u64,
            sha256: calculate_sha256(data),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        let filefacts_archive_entries: Vec<ArchiveEntry>;

        // Open filefacts once on the host archive bytes and merge its
        // typed values/metrics into the report. The capability
        // mapper's `evaluate_and_merge_findings_with_precomputed`
        // does this for PE/ELF/Mach-O but archives evaluate via
        // `evaluate_container_findings`, which doesn't go through
        // that path — so we plumb the merge in here. This is what
        // makes `chm.itsf.*` / `rpm.*` / `crx.*` etc. reachable via
        // both `report.values_tree` (host-level kv) and
        // `report.filefacts_metrics` (host-level metrics).
        {
            let ctx = crate::analysis_context::AnalysisContext::open_with(
                self.engine.filefacts_options().fileid(fileid),
                archive_path,
                data,
            );
            report.filefacts = Some(crate::types::FilefactsView::of(
                &ctx,
                self.engine.compact_members(),
            ));
            report.identity = ctx.identity();
            filefacts_archive_entries = ctx.archive_entries();
            crate::capabilities::merge_filefacts_context(&mut report, &ctx);
            if matches!(file_type, FileType::Rpm) {
                // Header-declared scripts are independent of payload decoding.
                // Reuse the existing bounded source adapter, never execute RPM.
                {
                    super::declared_sources::append(
                        &ctx.parsed,
                        &self.engine,
                        &mut report,
                        self.cancelled.as_ref(),
                    );
                }
                for error in ctx.parsed.errors() {
                    guard.add_extraction_note(format!(
                        "RPM header evidence incomplete: {}",
                        error.message
                    ));
                }
            }
        }

        // Seed the member list from filefacts. For an image this is the only
        // complete view of what it holds: a member cleave cannot identify is
        // dropped from the report, so a name-matching rule would never see the
        // lure that named it. The extraction pass merges its own per-member
        // metadata onto these entries by path rather than appending duplicates.
        if is_zip_container(file_type)
            || matches!(
                file_type,
                FileType::Iso | FileType::Cpio | FileType::Phar | FileType::Rpa
            )
        {
            report.archive_contents.extend(
                filefacts_archive_entries
                    .iter()
                    .filter(|entry| entry.entry_type.as_deref() != Some("directory"))
                    .cloned(),
            );
        }

        if matches!(file_type, FileType::Cpio) {
            let indexed_every_member = report
                .filefacts
                .as_ref()
                .and_then(|ff| ff.values.get("cpio"))
                .and_then(|cpio| cpio.get("complete"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if !indexed_every_member {
                guard.add_extraction_note(
                    "CPIO index is incomplete; only validated member extents are analyzed"
                        .to_string(),
                );
            }
        }

        if matches!(file_type, FileType::Chm) {
            self.analyze_chm_archive_in_memory(data, archive_path, &mut report, start, &guard)?;
            drain_extraction_notes(&mut report, &guard);
            let hostile_reasons = guard.take_reasons();
            let suppress_path_traversal = should_suppress_path_traversal_findings(
                file_type,
                &report.archive_contents,
                &hostile_reasons,
            );
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
            self.evaluate_container_findings(&mut report, data, file_type);
            return Ok(report);
        }

        if matches!(file_type, FileType::Asar | FileType::Phar) {
            if file_type == FileType::Phar {
                self.analyze_phar_archive_in_memory(
                    data,
                    &mut report,
                    start,
                    &guard,
                    &filefacts_archive_entries,
                )?;
            } else {
                self.analyze_asar_archive_in_memory(
                    data,
                    archive_path,
                    &mut report,
                    start,
                    &guard,
                )?;
            }
            let member_metadata = guard.take_member_metadata();
            if !member_metadata.is_empty() {
                merge_archive_member_metadata(&mut report, member_metadata);
            }
            drain_extraction_notes(&mut report, &guard);
            let hostile_reasons = guard.take_reasons();
            let suppress_path_traversal = should_suppress_path_traversal_findings(
                file_type,
                &report.archive_contents,
                &hostile_reasons,
            );
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
            self.evaluate_container_findings(&mut report, data, file_type);
            return Ok(report);
        }

        let archive_fits_memory = data.len() as u64 <= self.max_memory_file_size;
        let zip_family_in_memory = is_zip_container(file_type)
            && archive_fits_memory
            && (!filefacts_archive_entries
                .iter()
                .any(|entry| entry.encrypted)
                || (file_type == FileType::ApkAndroid
                    && zip::only_plaintext_encryption_flags(data, &filefacts_archive_entries)));
        // Tar family (plain and gzip/bzip2/xz/zstd compressed, and the
        // packages built on them) streams through the same in-memory member
        // window as zips when the archive fits in memory.
        let tar_family_in_memory = archive_fits_memory
            && matches!(
                file_type,
                FileType::Tar
                    | FileType::TarGz
                    | FileType::Npm
                    | FileType::Crate
                    | FileType::PythonSdist
                    | FileType::TarBz2
                    | FileType::TarXz
                    | FileType::TarZst
            );
        if zip_family_in_memory || tar_family_in_memory {
            if tar_family_in_memory {
                use std::io::Cursor;
                let label = "tar archive";
                match file_type {
                    FileType::Tar => self.analyze_tar_archive_in_memory(
                        Cursor::new(data),
                        &mut report,
                        start,
                        &guard,
                        label,
                    )?,
                    FileType::TarBz2 => self.analyze_tar_archive_in_memory(
                        bzip2::read::BzDecoder::new(Cursor::new(data)),
                        &mut report,
                        start,
                        &guard,
                        label,
                    )?,
                    FileType::TarXz => self.analyze_tar_archive_in_memory(
                        xz2::read::XzDecoder::new(Cursor::new(data)),
                        &mut report,
                        start,
                        &guard,
                        label,
                    )?,
                    FileType::TarZst => self.analyze_tar_archive_in_memory(
                        zstd::stream::read::Decoder::new(Cursor::new(data))
                            .context("Failed to create zstd decoder")?,
                        &mut report,
                        start,
                        &guard,
                        label,
                    )?,
                    _ => self.analyze_tar_archive_in_memory(
                        flate2::read::GzDecoder::new(Cursor::new(data)),
                        &mut report,
                        start,
                        &guard,
                        label,
                    )?,
                }
            } else if matches!(file_type, FileType::Crx) {
                let zip_offset = zip::crx_zip_offset(data)?;
                self.analyze_zip_archive_in_memory(
                    &data[zip_offset..],
                    archive_path,
                    &mut report,
                    start,
                    &guard,
                    &[],
                    false,
                )?;
            } else if let Err(e) = self.analyze_zip_archive_in_memory(
                data,
                archive_path,
                &mut report,
                start,
                &guard,
                &filefacts_archive_entries,
                file_type == FileType::Jar,
            ) {
                // A ZIP no library will open is often built that way on
                // purpose: concatenated archives or a damaged EOCD that
                // Explorer tolerates but scanners reject. Failing the whole
                // analysis would report nothing for exactly that file, so
                // keep the container-level facts and byte rules, and record
                // why no member was read.
                if self.is_cancelled() {
                    return Err(e);
                }
                report.metadata.errors.push(format!(
                    "ZIP members unreadable; container analyzed only: {e:#}"
                ));
            }
            let member_metadata = guard.take_member_metadata();
            if !member_metadata.is_empty() {
                merge_archive_member_metadata(&mut report, member_metadata);
            }
            drain_extraction_notes(&mut report, &guard);
            let hostile_reasons = guard.take_reasons();
            let suppress_path_traversal = should_suppress_path_traversal_findings(
                file_type,
                &report.archive_contents,
                &hostile_reasons,
            );
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
            self.evaluate_container_findings(&mut report, data, file_type);
            return Ok(report);
        }

        // Explicit prefix, not tempfile's default. A bare `tempdir()` is named
        // `.tmpXXXXXX`, which is indistinguishable from every other crate's
        // scratch and attributable to cleave only by inspecting its contents.
        // These dirs outlive the process whenever the caller dies without
        // unwinding — a watchdog `process::exit`, an abort, a SIGKILL — so the
        // name is the only handle an operator or a reaper has on them.
        let temp_dir = tempfile::Builder::new()
            .prefix("cleave-archive-")
            .tempdir()
            .context("Failed to create temporary directory")?;
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
                && let Ok(entries) = system_packages::list_7z_entries(data)
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
            // RPM headers remain useful when an unsupported or damaged CPIO
            // payload cannot be opened. Keep those parsed facts and explicitly
            // report the missing traversal instead of losing the whole result.
            let preserved_rpm_facts = matches!(file_type, FileType::Rpm)
                && report
                    .filefacts
                    .as_ref()
                    .is_some_and(|ff| ff.values.get("rpm").is_some());
            if preserved_rpm_facts {
                guard.add_extraction_note(format!("RPM payload extraction incomplete: {e}"));
            }
            let preserved_rpa_facts = matches!(file_type, FileType::Rpa)
                && report
                    .filefacts
                    .as_ref()
                    .is_some_and(|ff| ff.values.get("rpa").is_some());
            if preserved_rpa_facts {
                merge_filefacts_archive_listing(&mut report, &filefacts_archive_entries);
                guard.add_extraction_note(format!("RPA member extraction incomplete: {e}"));
            }

            // RAR payloads are often encrypted while the headers stay in the
            // clear. Keep the filefacts member table rather than dropping the
            // whole archive the way an unreadable ZIP central directory would.
            let preserved_rar_metadata = matches!(file_type, FileType::Rar)
                && filefacts_archive_entries
                    .iter()
                    .any(|entry| entry.entry_type.as_deref() != Some("directory"));
            if preserved_rar_metadata {
                merge_filefacts_archive_listing(&mut report, &filefacts_archive_entries);
                report.metadata.errors.push(format!(
                    "RAR extraction failed; preserved header listing: {e}"
                ));
            }
            // A ZIP whose every member is encrypted under an unknown password
            // still has a readable central directory: names, sizes and the
            // encryption flags are themselves evidence. Keep them rather than
            // reporting nothing for the archive.
            let preserved_zip_metadata = is_zip_container(file_type)
                && filefacts_archive_entries
                    .iter()
                    .any(|entry| entry.encrypted);
            if preserved_zip_metadata {
                merge_filefacts_archive_listing(&mut report, &filefacts_archive_entries);
                report.metadata.errors.push(format!(
                    "ZIP extraction failed; preserved central-directory listing: {e}"
                ));
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
                if preserved_7z_metadata
                    || preserved_iso_facts
                    || preserved_rpm_facts
                    || preserved_rpa_facts
                    || preserved_rar_metadata
                    || preserved_zip_metadata
                {
                    drain_extraction_notes(&mut report, &guard);
                    let suppress_path_traversal = should_suppress_path_traversal_findings(
                        file_type,
                        &report.archive_contents,
                        &hostile_reasons,
                    );
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
                    self.evaluate_container_findings(&mut report, data, file_type);
                    return Ok(report);
                }
                return Err(e);
            }
        }

        drain_extraction_notes(&mut report, &guard);

        let suppress_path_traversal = should_suppress_path_traversal_findings(
            file_type,
            &report.archive_contents,
            &hostile_reasons,
        );
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

        if is_zip_container(file_type) && contains_java_members(temp_dir.path()) {
            self.analyze_jar_archive(temp_dir.path(), &mut report, start);
        } else {
            self.analyze_generic_archive(temp_dir.path(), &mut report, start);
        }

        // All member readers and their mappings have finished. Container
        // evaluation below uses the report and the original archive bytes;
        // it never reopens extracted paths. Release their tmpfs pages before
        // building the container's final metadata and composite findings.
        drop(temp_dir);

        // Drain per-entry forensic metadata captured during extraction and
        // merge it into `report.archive_contents` by archive-relative path.
        // Aggregate kv-tree exposure (`archive.compression.*`,
        // `archive.timing.*`, …) is built later when the report is sealed.
        let member_metadata = guard.take_member_metadata();
        if !member_metadata.is_empty() {
            merge_archive_member_metadata(&mut report, member_metadata);
        }
        if matches!(file_type, FileType::Rar) {
            merge_filefacts_archive_listing(&mut report, &filefacts_archive_entries);
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
        self.evaluate_container_findings(&mut report, data, file_type);

        Ok(report)
    }

    /// Run container-level basename traits + composite rules and merge
    /// the results into `report.findings`. Shared between the in-memory
    /// and temp_dir analysis paths so both produce the same composites
    /// (e.g. `python-package-with-dll`).
    fn evaluate_container_findings(
        &self,
        report: &mut AnalysisReport,
        archive_data: &[u8],
        archive_type: FileType,
    ) {
        let timing = tracing::enabled!(tracing::Level::DEBUG).then(std::time::Instant::now);
        if carries_system_symlinks(archive_type, &report.archive_contents) {
            drop_system_container_symlink_escapes(report);
        }

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

        // A manifest that lists its own name as a dependency. Same placement
        // and the same reason: a cross-member judgement that no single file's
        // matcher can make.
        if let Some(count) = compute_self_dependency(report) {
            report
                .filefacts_metrics
                .get_or_insert_with(Default::default)
                .insert("consistency.self_dependency".to_string(), count as f64);
        }

        // A package that copied another project's identity and swapped only the
        // name. Same cross-member shape: the declared name lives in one member,
        // the advertised identity in the same and sibling members.
        if let Some(count) = compute_metadata_identity_mismatch(report) {
            report
                .filefacts_metrics
                .get_or_insert_with(Default::default)
                .insert(
                    "consistency.metadata_identity_mismatch".to_string(),
                    count as f64,
                );
        }

        // A distribution name one edit from a popular package. Name-only, but
        // placed with the other consistency metrics: a package-level judgement
        // the per-file matchers cannot make.
        if let Some(count) = compute_name_typosquat(report) {
            report
                .filefacts_metrics
                .get_or_insert_with(Default::default)
                .insert("consistency.name_typosquat".to_string(), count as f64);
        }

        // A full library republished under a different name -- the clone
        // advertises the target's distinctive summary while its own name is not
        // the target's. Metadata-only, placed with the other consistency
        // metrics for the same package-level reason.
        if let Some(count) = compute_cloned_summary(report) {
            report
                .filefacts_metrics
                .get_or_insert_with(Default::default)
                .insert("consistency.cloned_summary".to_string(), count as f64);
        }

        // `consistency.name_repo_mismatch` and
        // `consistency.publisher_repo_owner_mismatch` used to be recomputed
        // here from the manifest member's kv. Both are cross-field judgements
        // over one file's bytes, so filefacts emits them from its own
        // `package.json` parse (`formats::npm::emit`) — on the npm tarball
        // itself, and on a bare or in-archive manifest member.

        // How a VS Code extension pack is composed. Only a list of marketplace
        // ids, so nothing here is a behavior — but the ratio of borrowed
        // reputation to the publisher's own entries is what separates a curated
        // bundle from one assembled to carry something in.
        if let Some((size, own)) = extension_pack_counts(report) {
            let metrics = report
                .filefacts_metrics
                .get_or_insert_with(Default::default);
            metrics.insert("vsix.extension_pack_size".to_string(), size as f64);
            metrics.insert("vsix.extension_pack_self_entries".to_string(), own as f64);
        }

        // Context is input to atomic value traits as well as composites.
        // Attach it before either pass (library callers need not re-evaluate).
        source_context::attach(report);
        let mapper = self.engine.rules();
        // Archive-level inline YARA rules describe the original container
        // bytes (for example, relationships between tar headers). Member
        // analysis cannot supply those matches. Feed the same pre-scanned
        // inline evidence used by other analyzers into the atomic pass.
        let inline_yara = self
            .yara_engine
            .as_ref()
            .filter(|engine| engine.is_loaded())
            .and_then(|engine| {
                let filetypes = archive_type.yara_filetypes();
                match engine.scan_bytes(archive_data, Some(&filetypes)) {
                    Ok(scan) => Some(scan.inline_traits),
                    Err(error) => {
                        tracing::warn!(%error, "archive inline YARA scan failed");
                        report.metadata.errors.push(format!("yara: {error:#}"));
                        None
                    }
                }
            });
        let mut archive_atomic_findings =
            mapper.evaluate_traits_with_ast(report, archive_data, None, inline_yara.as_ref());
        locate_archive_root_findings(&mut archive_atomic_findings);
        report
            .findings
            .extend(archive_atomic_findings.iter().cloned());

        // Rank by reference, then clone only the survivors. A container's
        // members can carry far more than the 50k cap between them (63k
        // TypeScript members produce several hundred thousand), and cloning
        // every one — evidence vectors included — just to drop 90% of them at
        // the truncate was pure waste in the single-threaded finalize path.
        const MAX_NESTED_FINDINGS: usize = 50_000;

        // Where each finding came from, as a type mask keyed by finding id.
        // This is what makes `for:` mean "the file types this rule is about":
        // a composite's leg is satisfied only by a finding from a member whose
        // type it declared. Built here because this is the one place the
        // member and its findings are both in hand -- `Finding` itself carries
        // no usable origin (`source_file` is set only by the embedded-code and
        // overlay analyzers).
        let container_bit =
            crate::composite_rules::FileType::from_str(&report.target.file_type).type_bit();
        let mut finding_origins: rustc_hash::FxHashMap<String, crate::composite_rules::TypeMask> =
            rustc_hash::FxHashMap::default();
        for member in &report.files {
            let bit = crate::composite_rules::FileType::from_str(&member.file_type).type_bit();
            for finding in &member.findings {
                *finding_origins.entry(finding.id.to_string()).or_default() |= bit;
            }
        }
        // The container's own atomics, and the basename traits derived from its
        // entry list, are findings *of the container node* -- they belong to
        // its own type, not to any member.
        for finding in &archive_atomic_findings {
            *finding_origins.entry(finding.id.to_string()).or_default() |= container_bit;
        }

        let mut ranked: Vec<(&Finding, Option<&str>)> = report
            .files
            .iter()
            .flat_map(|file| {
                file.findings
                    .iter()
                    .map(move |finding| (finding, Some(file.path.as_str())))
            })
            .chain(
                archive_atomic_findings
                    .iter()
                    .map(|finding| (finding, None)),
            )
            .collect();
        ranked.sort_unstable_by(|(a, _), (b, _)| {
            b.crit.cmp(&a.crit).then_with(|| b.conf.total_cmp(&a.conf))
        });
        ranked.truncate(MAX_NESTED_FINDINGS);
        let mut nested_findings: Vec<Finding> = ranked
            .into_iter()
            .map(|(finding, member_path)| {
                let mut finding = finding.clone();
                if let Some(member_path) = member_path {
                    let relative_path =
                        archive_member_relative_path(&report.target.path, member_path);
                    locate_archive_member_finding(&mut finding, &relative_path);
                }
                finding
            })
            .collect();

        let entry_names: Vec<String> = report
            .archive_contents
            .iter()
            .map(|e| e.path.clone())
            .collect();
        if !entry_names.is_empty() {
            let mut basename_findings = mapper.evaluate_basename_traits_for_entries(&entry_names);
            locate_archive_root_findings(&mut basename_findings);
            for finding in &basename_findings {
                *finding_origins.entry(finding.id.to_string()).or_default() |= container_bit;
            }
            nested_findings.extend(basename_findings);
        }

        let container_findings = mapper.evaluate_container_composites(
            report,
            archive_data,
            &nested_findings,
            &report.target.file_type,
            Some(&finding_origins),
        );
        let container_suppression_targets: rustc_hash::FxHashSet<String> = archive_atomic_findings
            .iter()
            .chain(container_findings.iter())
            .map(|finding| finding.id.to_string())
            .collect();
        report.findings.extend(container_findings);

        // Cross-scope downgrade pass: per-file findings (in report.files[*])
        // were originally evaluated with only their own file's findings in
        // scope. Now that container composites have been added to
        // report.findings, give every per-file finding a second chance to
        // apply downgrades that reference container-level traits (e.g.
        // `metadata/file/format/browser-extension::mozilla-extension`). Pass empty bytes
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
        let reeval_file = |file: &mut crate::types::FileAnalysis| {
            if file.path.contains("##") {
                let path_findings =
                    mapper.evaluate_path_traits_for_file(&file.path, &file.file_type);
                if !path_findings.is_empty() {
                    for finding in path_findings {
                        if !file
                            .findings
                            .iter()
                            .any(|existing| existing.id == finding.id)
                        {
                            file.findings.push(finding);
                        }
                    }
                    mapper
                        .apply_retroactive_unless_suppression_to_findings(&mut file.findings, None);
                }
            }
            mapper.reeval_downgrades_cross_scope_at_path(
                &mut file.findings,
                &container_snapshot,
                report,
                &[],
                container_file_type,
                &empty_section_map,
                Some(&file.path),
            );
            if has_builtin_anti_analysis_finding(&file.findings) {
                // No sink: this pass runs at archive assembly over an aggregated
                // finding pool. Each member recorded its own suppressions when
                // it was analyzed.
                mapper.apply_retroactive_unless_suppression_to_findings(&mut file.findings, None);
            }
        };
        if crate::rayon_nest::inner_work_parallel() {
            use rayon::prelude::*;
            files.par_iter_mut().for_each(reeval_file);
        } else {
            files.iter_mut().for_each(reeval_file);
        }
        report.files = files;
        // The aggregate was copied before member downgrades. Refresh its
        // severity from every retained member, preserving the strongest one.
        // At the member retention ceiling an omitted contributor may still
        // justify the original tier, so leave aggregates conservative there.
        if report.files.len() < 100_000 {
            let mut member_criticality = rustc_hash::FxHashMap::default();
            for file in &report.files {
                for finding in &file.findings {
                    member_criticality
                        .entry(finding.id.as_str())
                        .and_modify(|state: &mut (Criticality, bool)| {
                            if finding.crit > state.0
                                || finding.crit == state.0 && !finding.downgraded
                            {
                                *state = (finding.crit, finding.downgraded);
                            }
                        })
                        .or_insert((finding.crit, finding.downgraded));
                }
            }
            for finding in &mut report.findings {
                // Container-owned detections have their own evidence and must
                // not be demoted to the tier of a similarly named member fact.
                if !container_suppression_targets.contains(finding.id.as_str())
                    && let Some(&(crit, downgraded)) = member_criticality.get(finding.id.as_str())
                {
                    finding.crit = crit;
                    finding.downgraded = downgraded;
                }
            }
        }
        // Container composites are assembled after the ordinary per-file
        // pipeline. Re-check their `unless:` legs now that every archive-level
        // finding is available; otherwise an exception composite discovered
        // in the same archive can arrive after its dependent finding and leave
        // that finding stale in the final report.
        // Aggregated member findings have already been suppressed in their
        // own scope. A sibling's build/test marker must not erase them here.
        mapper.apply_retroactive_unless_suppression_to_selected_findings(
            &mut report.findings,
            &container_suppression_targets,
        );
        if has_builtin_anti_analysis_finding(&report.findings) {
            mapper.apply_retroactive_unless_suppression_to_findings(&mut report.findings, None);
        }
        if let Some(timing) = timing {
            tracing::debug!(
                path = %report.target.path,
                elapsed_ms = timing.elapsed().as_millis() as u64,
                "archive container evaluation timing",
            );
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
            FileType::Cpio => cpio::extract_from_data(data, filefacts_members, dest_dir, guard),
            FileType::Rpa => rpa::extract_from_data(data, dest_dir, guard),
            // A gem is an uncompressed `ustar` tar (members: metadata.gz,
            // data.tar.gz, checksums.yaml.gz); recursion descends into
            // data.tar.gz for the installed files.
            FileType::Tar
            | FileType::Gem
            | FileType::Hex
            | FileType::OciImage
            | FileType::GentooBinpkg => {
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
            FileType::TarGz
            | FileType::Npm
            | FileType::Crate
            | FileType::PythonSdist
            | FileType::Pub
            | FileType::Cran
            | FileType::Cpan
            | FileType::Hackage => tar::extract_tar_entries_safe(
                flate2::read::GzDecoder::new(Cursor::new(data)),
                dest_dir,
                guard,
            ),
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
            FileType::Lzma => decompress_to_file(
                lzma_alone_decoder(Cursor::new(data))?,
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
            | FileType::GoModule
            | FileType::Composer
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
            FileType::Snap | FileType::SquashFs => {
                squashfs::extract_from_data(data, dest_dir, guard)
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
            FileType::Vhd => system_packages::extract_vhd_from_data(data, dest_dir, guard),
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
        // `input.data` is authoritative — the caller already read the file, and
        // `input.path` may be a label rather than a location (`analyze_bytes`, a
        // nested archive member). Re-reading the path here analyzed whatever
        // happened to sit at that name in the process's working directory
        // instead of the bytes handed in, and failed outright when the name
        // resolved to a directory.
        self.analyze_archive_with_data(input.data, input.path)
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        self.analyze_archive(file_path)
    }
}

/// Overlay a filefacts archive listing onto `report.archive_contents`.
///
/// Extracted members keep the sha256 and type the unpack pass learned; listing
/// fields the extractor never saw (encrypted, host OS, header offsets, packed
/// size) are filled in. Names that could not be unpacked — the usual encrypted
/// RAR case — are appended so path matchers still see them.
fn merge_filefacts_archive_listing(report: &mut AnalysisReport, listing: &[ArchiveEntry]) {
    use std::collections::HashMap;

    let mut by_path: HashMap<String, usize> = HashMap::new();
    for (i, entry) in report.archive_contents.iter().enumerate() {
        by_path.entry(entry.path.clone()).or_insert(i);
    }
    for entry in listing {
        if entry.entry_type.as_deref() == Some("directory") {
            continue;
        }
        if let Some(&i) = by_path.get(&entry.path) {
            let dest = &mut report.archive_contents[i];
            dest.encrypted |= entry.encrypted;
            if dest.mtime_unix.is_none() {
                dest.mtime_unix = entry.mtime_unix;
            }
            if dest.host_os.is_none() {
                dest.host_os = entry.host_os.clone();
            }
            if dest.compressed_size.is_none() {
                dest.compressed_size = entry.compressed_size;
            }
            if dest.compression_method.is_none() {
                dest.compression_method = entry.compression_method.clone();
            }
            if dest.crc32.is_none() {
                dest.crc32 = entry.crc32;
            }
            if dest.header_offset.is_none() {
                dest.header_offset = entry.header_offset;
            }
            if dest.data_offset.is_none() {
                dest.data_offset = entry.data_offset;
            }
            if dest.linkname.is_none() {
                dest.linkname = entry.linkname.clone();
            }
        } else {
            by_path.insert(entry.path.clone(), report.archive_contents.len());
            report.archive_contents.push(entry.clone());
        }
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

    // `archive_path` is the name recorded inside the archive; `entry.path`
    // below comes from walking the extracted tree, so the two differ whenever
    // the name had to be escaped to be representable on disk. Index both forms
    // so an escaped member still finds its own tar/ZIP header metadata instead
    // of silently losing it.
    let mut by_path: HashMap<String, ExtractedMemberMetadata> = HashMap::new();
    for meta in metadata {
        if let Some(escaped) = escaped_relative_path(&meta.archive_path)
            && escaped != meta.archive_path
        {
            by_path.insert(escaped, meta.clone());
        }
        by_path.insert(meta.archive_path.clone(), meta);
    }

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
mod tests;
