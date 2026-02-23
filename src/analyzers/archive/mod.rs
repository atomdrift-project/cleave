//! Archive analyzer for various archive formats.
//!
//! Note: This module uses unwrap/expect for internal invariants that are
//! guaranteed by the code structure (e.g., parsed paths, validated indices).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod analyzers;
mod guards;
// #[cfg(test)]
// mod guards_test;
pub(crate) mod streaming;
mod system_packages;
mod tar;
mod utils;
mod zip;

pub(crate) use guards::HostileArchiveReason;

use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use std::fs::{self};
// std::io imports removed
use std::path::Path;
use std::sync::Arc;

use guards::{ExtractionGuard, MAX_FILE_COUNT, MAX_FILE_SIZE, MAX_TOTAL_SIZE};
use utils::{calculate_sha256, detect_archive_type};

/// Default maximum file size to keep in memory (100 MB)
pub(crate) const DEFAULT_MAX_MEMORY_FILE_SIZE: u64 = 100 * 1024 * 1024;

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
        }
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
        use streaming::StreamingFileResult;

        // Log BEFORE processing archive to capture OOM crashes
        tracing::info!(
            "Starting archive analysis: {} (depth: {})",
            file_path.display(),
            self.current_depth
        );

        let start = std::time::Instant::now();

        // Prevent infinite recursion
        if self.current_depth >= self.max_depth {
            anyhow::bail!("Maximum archive depth ({}) exceeded", self.max_depth);
        }

        // Create target info
        tracing::debug!("Reading archive file: {}", file_path.display());
        let file_data = fs::read(file_path)?;
        tracing::debug!(
            "Archive file size: {} bytes for: {}",
            file_data.len(),
            file_path.display()
        );
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: detect_archive_type(file_path).to_string(),
            size_bytes: file_data.len() as u64,
            sha256: calculate_sha256(&file_data),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        report
            .metadata
            .tools_used
            .push("streaming_analyzer".to_string());

        // Track aggregate data incrementally (instead of accumulating all files)
        let files_analyzed = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let max_depth = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let max_risk = std::sync::Arc::new(std::sync::Mutex::new(Option::<Criticality>::None));
        let counts = std::sync::Arc::new(std::sync::Mutex::new(FindingCounts::default()));

        let files_analyzed_clone = files_analyzed.clone();
        let max_depth_clone = max_depth.clone();
        let max_risk_clone = max_risk.clone();
        let counts_clone = counts.clone();

        // Helper to update aggregates from a FileAnalysis
        let update_aggregates = |file: &FileAnalysis| {
            let current_max = max_depth_clone.load(std::sync::atomic::Ordering::Relaxed);
            if file.depth > current_max {
                max_depth_clone.store(file.depth, std::sync::atomic::Ordering::Relaxed);
            }

            if let Some(risk) = &file.risk {
                if let Ok(mut max_risk) = max_risk_clone.lock() {
                    *max_risk = Some(match *max_risk {
                        Some(current) if current > *risk => current,
                        _ => *risk,
                    });
                }
            }

            if let Some(file_counts) = &file.counts {
                if let Ok(mut counts) = counts_clone.lock() {
                    counts.hostile += file_counts.hostile;
                    counts.suspicious += file_counts.suspicious;
                    counts.notable += file_counts.notable;
                }
            }
        };

        // Determine archive type - use magic detection for ambiguous extensions
        let archive_type = utils::detect_archive_type_with_magic(file_path)
            .unwrap_or_else(|_| detect_archive_type(file_path));
        let summary = match archive_type {
            "tar" | "tar.gz" | "tgz" | "tar.bz2" | "tbz" | "tbz2" | "tar.xz" | "txz"
            | "tar.zst" | "tzst" => {
                self.analyze_tar_streaming(file_path, |result: StreamingFileResult| {
                    on_file(&result.file_analysis);

                    // Update aggregates incrementally (don't accumulate files)
                    files_analyzed_clone.fetch_add(
                        1 + result.nested_files.len() as u32,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    update_aggregates(&result.file_analysis);
                    for nested in &result.nested_files {
                        update_aggregates(nested);
                    }
                })?
            }
            "zip" | "jar" | "war" | "ear" | "aar" | "egg" | "whl" | "phar" | "nupkg" | "vsix"
            | "xpi" | "ipa" | "epub" => {
                self.analyze_zip_streaming(file_path, |result: StreamingFileResult| {
                    on_file(&result.file_analysis);

                    files_analyzed_clone.fetch_add(
                        1 + result.nested_files.len() as u32,
                        std::sync::atomic::Ordering::Relaxed,
                    );
                    update_aggregates(&result.file_analysis);
                    for nested in &result.nested_files {
                        update_aggregates(nested);
                    }
                })?
            }
            // Handle "apk" that wasn't resolved by magic (fallback to zip for Android)
            "apk" => self.analyze_zip_streaming(file_path, |result: StreamingFileResult| {
                on_file(&result.file_analysis);

                files_analyzed_clone.fetch_add(
                    1 + result.nested_files.len() as u32,
                    std::sync::atomic::Ordering::Relaxed,
                );
                update_aggregates(&result.file_analysis);
                for nested in &result.nested_files {
                    update_aggregates(nested);
                }
            })?,
            "deb" => self.analyze_deb_streaming(file_path, |result: StreamingFileResult| {
                on_file(&result.file_analysis);

                files_analyzed_clone.fetch_add(
                    1 + result.nested_files.len() as u32,
                    std::sync::atomic::Ordering::Relaxed,
                );
                update_aggregates(&result.file_analysis);
                for nested in &result.nested_files {
                    update_aggregates(nested);
                }
            })?,
            "rpm" => self.analyze_rpm_streaming(file_path, |result: StreamingFileResult| {
                on_file(&result.file_analysis);

                files_analyzed_clone.fetch_add(
                    1 + result.nested_files.len() as u32,
                    std::sync::atomic::Ordering::Relaxed,
                );
                update_aggregates(&result.file_analysis);
                for nested in &result.nested_files {
                    update_aggregates(nested);
                }
            })?,
            "7z" => self.analyze_7z_streaming(file_path, |result: StreamingFileResult| {
                on_file(&result.file_analysis);

                files_analyzed_clone.fetch_add(
                    1 + result.nested_files.len() as u32,
                    std::sync::atomic::Ordering::Relaxed,
                );
                update_aggregates(&result.file_analysis);
                for nested in &result.nested_files {
                    update_aggregates(nested);
                }
            })?,
            _ => {
                // Fall back to non-streaming for unsupported formats (rar, pkg)
                return self.analyze_archive(file_path);
            }
        };

        // Add hostile findings from extraction
        for reason in summary.hostile_reasons {
            let (id, desc, evidence_value) = match &reason {
                HostileArchiveReason::PathTraversal(path) => (
                    "anti-analysis/archive/path-traversal",
                    "Archive contains path traversal attempt (zip slip)",
                    format!("path:{}", path),
                ),
                HostileArchiveReason::ZipBomb {
                    compressed,
                    uncompressed,
                } => (
                    "anti-analysis/archive/zip-bomb",
                    "Archive has suspicious compression ratio (potential zip bomb)",
                    format!(
                        "ratio:{}:1 ({}B -> {}B)",
                        uncompressed / (*compressed).max(1),
                        compressed,
                        uncompressed
                    ),
                ),
                HostileArchiveReason::ExcessiveFileCount(count) => (
                    "anti-analysis/archive/excessive-files",
                    "Archive contains excessive number of files",
                    format!("count:{} (limit:{})", count, MAX_FILE_COUNT),
                ),
                HostileArchiveReason::ExcessiveTotalSize(size) => (
                    "anti-analysis/archive/excessive-size",
                    "Archive expands to excessive total size",
                    format!("size:{} bytes (limit:{})", size, MAX_TOTAL_SIZE),
                ),
                HostileArchiveReason::ExcessiveFileSize { file, size } => (
                    "anti-analysis/archive/large-file",
                    "Archive contains excessively large file",
                    format!("file:{} size:{} (limit:{})", file, size, MAX_FILE_SIZE),
                ),
                HostileArchiveReason::SymlinkEscape(path) => (
                    "anti-analysis/archive/symlink-escape",
                    "Archive contains symlink that may escape extraction directory",
                    format!("symlink:{}", path),
                ),
            };

            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: id.to_string(),
                desc: desc.to_string(),
                conf: 0.9,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "archive_extraction".to_string(),
                    source: "streaming_analyzer".to_string(),
                    value: evidence_value,
                    location: None,
                }],

                source_file: None,
            });
        }

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: format!("archive/{}", archive_type),
            desc: format!("{} archive", archive_type),
            evidence: vec![Evidence {
                method: "extension".to_string(),
                source: "streaming_analyzer".to_string(),
                value: file_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                location: None,
            }],
        });

        // Create summary from incrementally computed aggregates (no files accumulated)
        let final_counts = match std::sync::Arc::try_unwrap(counts) {
            Ok(mutex) => mutex
                .into_inner()
                .map_err(|e| anyhow::anyhow!("Failed to unwrap counts mutex: {}", e))?,
            Err(arc) => arc
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to lock counts: {}", e))?
                .clone(),
        };
        let final_max_risk = match std::sync::Arc::try_unwrap(max_risk) {
            Ok(mutex) => mutex
                .into_inner()
                .map_err(|e| anyhow::anyhow!("Failed to unwrap max_risk mutex: {}", e))?,
            Err(arc) => *arc
                .lock()
                .map_err(|e| anyhow::anyhow!("Failed to lock max_risk: {}", e))?,
        };

        report.summary = Some(ReportSummary {
            files_analyzed: files_analyzed.load(std::sync::atomic::Ordering::Relaxed),
            max_depth: max_depth.load(std::sync::atomic::Ordering::Relaxed),
            counts: final_counts,
            max_risk: final_max_risk,
        });
        // Keep files empty in streaming mode to save memory
        report.files = Vec::new();

        // Set timing
        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;

        Ok(report)
    }

    fn analyze_archive(&self, file_path: &Path) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        // Prevent infinite recursion
        if self.current_depth >= self.max_depth {
            anyhow::bail!("Maximum archive depth ({}) exceeded", self.max_depth);
        }

        // Create temporary directory for extraction
        let temp_dir = tempfile::tempdir().context("Failed to create temporary directory")?;

        // Create extraction guard to track limits and detect hostile patterns
        let guard = ExtractionGuard::new();

        // Extract archive with protection
        // For complete failures (wrong password, corrupt archive), propagate the error
        // For partial failures (some hostile files skipped), emit findings but continue
        let extraction_result = self.extract_archive_safe(file_path, temp_dir.path(), &guard);

        // Check if any files were extracted - if zero files and error, propagate error
        let hostile_reasons = guard.take_reasons();
        let _has_hostile_patterns = !hostile_reasons.is_empty();

        // If extraction completely failed (no files extracted), return the error
        // This handles cases like wrong password, corrupt archive, etc.
        if let Err(e) = extraction_result {
            // Check if we at least extracted some files (partial success)
            let extracted_count = walkdir::WalkDir::new(temp_dir.path())
                .min_depth(1)
                .into_iter()
                .filter_map(std::result::Result::ok)
                .count();

            if extracted_count == 0 {
                // Complete failure - return the error
                return Err(e);
            }
            // Partial failure - continue with what we extracted but record the error
        }

        // Create target info
        let file_data = fs::read(file_path)?;
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: detect_archive_type(file_path).to_string(),
            size_bytes: file_data.len() as u64,
            sha256: calculate_sha256(&file_data),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Emit findings for any hostile archive behaviors
        for reason in hostile_reasons {
            let (id, desc, evidence_value) = match &reason {
                HostileArchiveReason::PathTraversal(path) => (
                    "anti-analysis/archive/path-traversal",
                    "Archive contains path traversal attempt (zip slip)",
                    format!("path:{}", path),
                ),
                HostileArchiveReason::ZipBomb {
                    compressed,
                    uncompressed,
                } => (
                    "anti-analysis/archive/zip-bomb",
                    "Archive has suspicious compression ratio (potential zip bomb)",
                    format!(
                        "ratio:{}:1 ({}B -> {}B)",
                        uncompressed / (*compressed).max(1),
                        compressed,
                        uncompressed
                    ),
                ),
                HostileArchiveReason::ExcessiveFileCount(count) => (
                    "anti-analysis/archive/excessive-files",
                    "Archive contains excessive number of files",
                    format!("count:{} (limit:{})", count, MAX_FILE_COUNT),
                ),
                HostileArchiveReason::ExcessiveTotalSize(size) => (
                    "anti-analysis/archive/excessive-size",
                    "Archive expands to excessive total size",
                    format!("size:{} bytes (limit:{})", size, MAX_TOTAL_SIZE),
                ),
                HostileArchiveReason::ExcessiveFileSize { file, size } => (
                    "anti-analysis/archive/large-file",
                    "Archive contains excessively large file",
                    format!("file:{} size:{} (limit:{})", file, size, MAX_FILE_SIZE),
                ),
                HostileArchiveReason::SymlinkEscape(path) => (
                    "anti-analysis/archive/symlink-escape",
                    "Archive contains symlink that may escape extraction directory",
                    format!("symlink:{}", path),
                ),
            };

            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: id.to_string(),
                desc: desc.to_string(),
                conf: 0.9,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "archive_extraction".to_string(),
                    source: "archive_analyzer".to_string(),
                    value: evidence_value,
                    location: None,
                }],

                source_file: None,
            });
        }

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: format!("archive/{}", detect_archive_type(file_path)),
            desc: format!("{} archive", detect_archive_type(file_path)),
            evidence: vec![Evidence {
                method: "extension".to_string(),
                source: "archive_analyzer".to_string(),
                value: file_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("unknown")
                    .to_string(),
                location: None,
            }],
        });

        // Check if this is a JAR-like archive
        let is_jar = file_path.to_string_lossy().to_lowercase().ends_with(".jar")
            || file_path.to_string_lossy().to_lowercase().ends_with(".war")
            || file_path.to_string_lossy().to_lowercase().ends_with(".ear")
            || file_path.to_string_lossy().to_lowercase().ends_with(".apk")
            || file_path.to_string_lossy().to_lowercase().ends_with(".aar");

        if is_jar {
            self.analyze_jar_archive(temp_dir.path(), &mut report, start)?;
        } else {
            self.analyze_generic_archive(temp_dir.path(), &mut report, start)?;
        }

        Ok(report)
    }
    fn extract_archive_safe(
        &self,
        archive_path: &Path,
        dest_dir: &Path,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        // Use magic-based detection for ambiguous extensions (apk, pkg)
        let archive_type = utils::detect_archive_type_with_magic(archive_path)
            .unwrap_or_else(|_| detect_archive_type(archive_path));

        match archive_type {
            "crx" => zip::extract_crx_safe(archive_path, dest_dir, guard),
            "7z" => {
                system_packages::extract_7z_safe(archive_path, dest_dir, guard, &self.zip_passwords)
            }
            "tar" => tar::extract_tar_safe(archive_path, dest_dir, None, guard),
            "tar.gz" | "tgz" => tar::extract_tar_safe(archive_path, dest_dir, Some("gzip"), guard),
            "tar.bz2" | "tbz" | "tbz2" => {
                tar::extract_tar_safe(archive_path, dest_dir, Some("bzip2"), guard)
            }
            "tar.xz" | "txz" => tar::extract_tar_safe(archive_path, dest_dir, Some("xz"), guard),
            "tar.zst" | "tzst" => {
                tar::extract_tar_safe(archive_path, dest_dir, Some("zstd"), guard)
            }
            "xz" => system_packages::extract_compressed_safe(archive_path, dest_dir, "xz", guard),
            "gz" => system_packages::extract_compressed_safe(archive_path, dest_dir, "gzip", guard),
            "zst" => {
                system_packages::extract_compressed_safe(archive_path, dest_dir, "zstd", guard)
            }
            "bz2" => {
                system_packages::extract_compressed_safe(archive_path, dest_dir, "bzip2", guard)
            }
            "deb" => system_packages::extract_deb_safe(archive_path, dest_dir, guard),
            "rpm" => system_packages::extract_rpm(archive_path, dest_dir, guard),
            "pkg" => system_packages::extract_pkg_safe(archive_path, dest_dir, guard),
            "rar" => system_packages::extract_rar(archive_path, dest_dir, guard),
            // Handle zip and ambiguous "apk" that wasn't resolved by magic detection
            "zip" | "apk" => {
                zip::extract_zip_safe(archive_path, dest_dir, guard, &self.zip_passwords)
            }
            _ => anyhow::bail!("Unsupported archive type: {}", archive_type),
        }
    }
}

impl Default for ArchiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
impl Analyzer for ArchiveAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        self.analyze_archive(file_path)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        let path_str = file_path.to_string_lossy().to_lowercase();
        path_str.ends_with(".zip")
            || path_str.ends_with(".jar")
            || path_str.ends_with(".war")
            || path_str.ends_with(".ear")
            || path_str.ends_with(".apk") // Android APK or Alpine APK (detected by magic)
            || path_str.ends_with(".aar")
            || path_str.ends_with(".egg")
            || path_str.ends_with(".whl")
            || path_str.ends_with(".phar")
            || path_str.ends_with(".nupkg")
            || path_str.ends_with(".vsix")
            || path_str.ends_with(".xpi")
            || path_str.ends_with(".crx")
            || path_str.ends_with(".ipa")
            || path_str.ends_with(".epub")
            || path_str.ends_with(".gem")
            || path_str.ends_with(".crate")
            || path_str.ends_with(".tar")
            || path_str.ends_with(".tar.gz")
            || path_str.ends_with(".tgz")
            || path_str.ends_with(".tar.bz2")
            || path_str.ends_with(".tbz2")
            || path_str.ends_with(".tbz")
            || path_str.ends_with(".tar.xz")
            || path_str.ends_with(".txz")
            || path_str.ends_with(".tar.zst") // Zstd-compressed tar
            || path_str.ends_with(".tzst")
            || path_str.ends_with(".pkg.tar.zst") // Arch Linux packages
            || path_str.ends_with(".pkg.tar.xz")
            || path_str.ends_with(".pkg.tar.gz")
            || path_str.ends_with(".xbps") // Void Linux packages
            || (path_str.ends_with(".xz") && !path_str.ends_with(".tar.xz"))
            || (path_str.ends_with(".gz") && !path_str.ends_with(".tar.gz"))
            || (path_str.ends_with(".zst") && !path_str.ends_with(".tar.zst"))
            || (path_str.ends_with(".bz2") && !path_str.ends_with(".tar.bz2"))
            || path_str.ends_with(".deb")
            || path_str.ends_with(".rpm")
            || path_str.ends_with(".pkg") // macOS PKG or FreeBSD pkg (detected by magic)
            || path_str.ends_with(".rar")
            || path_str.ends_with(".7z")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guards::{sanitize_entry_path, ExtractionGuard, MAX_FILE_COUNT};
    use std::fs::File;
    use std::io::{Cursor, Write};

    // Import external crate types (our modules shadow these names)
    use ::tar;
    use ::zip;

    #[test]
    fn test_new() {
        let analyzer = ArchiveAnalyzer::new();
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
    fn test_can_analyze_zip() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.zip")));
        assert!(analyzer.can_analyze(Path::new("TEST.ZIP")));
    }

    #[test]
    fn test_can_analyze_jar() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.jar")));
        assert!(analyzer.can_analyze(Path::new("TEST.JAR")));
        assert!(analyzer.can_analyze(Path::new("test.war")));
        assert!(analyzer.can_analyze(Path::new("test.apk")));
    }

    #[test]
    fn test_detect_archive_type_jar() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("test.jar")), "zip");
        assert_eq!(detect_archive_type(Path::new("test.war")), "zip");
        // .apk returns "apk" for extension-based detection (needs magic for Android vs Alpine)
        assert_eq!(detect_archive_type(Path::new("test.apk")), "apk");
    }

    #[test]
    fn test_can_analyze_tar() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.tar")));
        assert!(analyzer.can_analyze(Path::new("test.tar.gz")));
        assert!(analyzer.can_analyze(Path::new("test.tgz")));
    }

    #[test]
    fn test_can_analyze_tar_bz2() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.tar.bz2")));
        assert!(analyzer.can_analyze(Path::new("test.tbz2")));
    }

    #[test]
    fn test_can_analyze_tar_xz() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.tar.xz")));
        assert!(analyzer.can_analyze(Path::new("test.txz")));
    }

    #[test]
    fn test_cannot_analyze_other() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(!analyzer.can_analyze(Path::new("test.txt")));
        assert!(!analyzer.can_analyze(Path::new("test.elf")));
    }

    #[test]
    fn test_detect_archive_type_zip() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("test.zip")), "zip");
    }

    #[test]
    fn test_detect_archive_type_tar() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("test.tar")), "tar");
    }

    #[test]
    fn test_detect_archive_type_tar_gz() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("test.tar.gz")), "tar.gz");
        assert_eq!(detect_archive_type(Path::new("test.tgz")), "tgz");
    }

    #[test]
    fn test_detect_archive_type_tar_bz2() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("test.tar.bz2")), "tar.bz2");
        assert_eq!(detect_archive_type(Path::new("test.tbz2")), "tbz");
        assert_eq!(detect_archive_type(Path::new("test.tbz")), "tbz");
    }

    #[test]
    fn test_detect_archive_type_tar_xz() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("test.tar.xz")), "tar.xz");
        assert_eq!(detect_archive_type(Path::new("test.txz")), "txz");
    }

    #[test]
    fn test_detect_archive_type_deb() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("test.deb")), "deb");
        assert_eq!(detect_archive_type(Path::new("package.deb")), "deb");
    }

    #[test]
    fn test_detect_archive_type_rpm() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("test.rpm")), "rpm");
        assert_eq!(detect_archive_type(Path::new("package.rpm")), "rpm");
    }

    #[test]
    fn test_detect_archive_type_rar() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("test.rar")), "rar");
        assert_eq!(detect_archive_type(Path::new("archive.rar")), "rar");
    }

    #[test]
    fn test_can_analyze_deb() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.deb")));
        assert!(analyzer.can_analyze(Path::new("TEST.DEB")));
    }

    #[test]
    fn test_can_analyze_rpm() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.rpm")));
        assert!(analyzer.can_analyze(Path::new("TEST.RPM")));
    }

    #[test]
    fn test_can_analyze_rar() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.rar")));
        assert!(analyzer.can_analyze(Path::new("TEST.RAR")));
    }

    #[test]
    fn test_can_analyze_python_packages() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("package.egg")));
        assert!(analyzer.can_analyze(Path::new("PACKAGE.EGG")));
        assert!(analyzer.can_analyze(Path::new("package.whl")));
        assert!(analyzer.can_analyze(Path::new("PACKAGE.WHL")));
    }

    #[test]
    fn test_detect_archive_type_python_packages() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("package.egg")), "zip");
        assert_eq!(detect_archive_type(Path::new("package.whl")), "zip");
    }

    #[test]
    fn test_can_analyze_ruby_gem() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("rails.gem")));
        assert!(analyzer.can_analyze(Path::new("RAILS.GEM")));
    }

    #[test]
    fn test_detect_archive_type_gem() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("rails.gem")), "tar");
    }

    #[test]
    fn test_can_analyze_php_phar() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("composer.phar")));
        assert!(analyzer.can_analyze(Path::new("COMPOSER.PHAR")));
    }

    #[test]
    fn test_detect_archive_type_phar() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("composer.phar")), "zip");
    }

    #[test]
    fn test_can_analyze_nuget() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("package.nupkg")));
        assert!(analyzer.can_analyze(Path::new("PACKAGE.NUPKG")));
    }

    #[test]
    fn test_detect_archive_type_nupkg() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("package.nupkg")), "zip");
    }

    #[test]
    fn test_can_analyze_rust_crate() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("serde.crate")));
        assert!(analyzer.can_analyze(Path::new("SERDE.CRATE")));
    }

    #[test]
    fn test_detect_archive_type_crate() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("serde.crate")), "tar.gz");
    }

    #[test]
    fn test_can_analyze_vscode_extensions() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("extension.vsix")));
        assert!(analyzer.can_analyze(Path::new("EXTENSION.VSIX")));
    }

    #[test]
    fn test_detect_archive_type_vsix() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("extension.vsix")), "zip");
    }

    #[test]
    fn test_can_analyze_firefox_extensions() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("addon.xpi")));
        assert!(analyzer.can_analyze(Path::new("ADDON.XPI")));
    }

    #[test]
    fn test_detect_archive_type_xpi() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("addon.xpi")), "zip");
    }

    #[test]
    fn test_can_analyze_chrome_extensions() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("extension.crx")));
        assert!(analyzer.can_analyze(Path::new("EXTENSION.CRX")));
    }

    #[test]
    fn test_detect_archive_type_crx() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("extension.crx")), "crx");
    }

    #[test]
    fn test_can_analyze_ios_apps() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("app.ipa")));
        assert!(analyzer.can_analyze(Path::new("APP.IPA")));
    }

    #[test]
    fn test_detect_archive_type_ipa() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("app.ipa")), "zip");
    }

    #[test]
    fn test_can_analyze_epub() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("book.epub")));
        assert!(analyzer.can_analyze(Path::new("BOOK.EPUB")));
    }

    #[test]
    fn test_detect_archive_type_epub() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("book.epub")), "zip");
    }

    #[test]
    fn test_can_analyze_7z() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("archive.7z")));
        assert!(analyzer.can_analyze(Path::new("ARCHIVE.7Z")));
    }

    #[test]
    fn test_detect_archive_type_7z() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("archive.7z")), "7z");
    }

    #[test]
    fn test_can_analyze_macos_pkg() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("installer.pkg")));
        assert!(analyzer.can_analyze(Path::new("INSTALLER.PKG")));
    }

    #[test]
    fn test_detect_archive_type_pkg() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("installer.pkg")), "pkg");
    }

    #[test]
    fn test_detect_archive_type_unknown() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("test.txt")), "unknown");
    }

    #[test]
    fn test_detect_archive_type_zstd_tar() {
        let _analyzer = ArchiveAnalyzer::new();
        assert_eq!(detect_archive_type(Path::new("test.tar.zst")), "tar.zst");
        assert_eq!(detect_archive_type(Path::new("test.tzst")), "tar.zst");
    }

    #[test]
    fn test_detect_archive_type_arch_packages() {
        let _analyzer = ArchiveAnalyzer::new();
        // Arch Linux packages
        assert_eq!(
            detect_archive_type(Path::new("linux-6.7-1-x86_64.pkg.tar.zst")),
            "tar.zst"
        );
        assert_eq!(
            detect_archive_type(Path::new("pacman-6.0-1-x86_64.pkg.tar.xz")),
            "tar.xz"
        );
        assert_eq!(
            detect_archive_type(Path::new("old-pkg-1.0-1.pkg.tar.gz")),
            "tar.gz"
        );
    }

    #[test]
    fn test_detect_archive_type_void_packages() {
        let _analyzer = ArchiveAnalyzer::new();
        // Void Linux packages (xbps)
        assert_eq!(
            detect_archive_type(Path::new("bash-5.2-1.x86_64.xbps")),
            "tar.zst"
        );
    }

    #[test]
    fn test_can_analyze_zstd_tar() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.tar.zst")));
        assert!(analyzer.can_analyze(Path::new("test.tzst")));
    }

    #[test]
    fn test_can_analyze_arch_packages() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("linux.pkg.tar.zst")));
        assert!(analyzer.can_analyze(Path::new("linux.pkg.tar.xz")));
        assert!(analyzer.can_analyze(Path::new("linux.pkg.tar.gz")));
    }

    #[test]
    fn test_can_analyze_void_packages() {
        let analyzer = ArchiveAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("bash.xbps")));
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
        assert!(report
            .structure
            .iter()
            .any(|s| s.id.starts_with("archive/")));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Maximum archive depth"));
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("tried 1 passwords"));
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
        assert!(reasons
            .iter()
            .any(|r| matches!(r, HostileArchiveReason::ExcessiveFileCount(_))));
    }

    #[test]
    fn test_compression_ratio_detection() {
        let guard = ExtractionGuard::new();

        // Normal ratio should pass
        assert!(guard.check_compression_ratio(1000, 2000)); // 2:1

        // Suspicious ratio should fail
        assert!(!guard.check_compression_ratio(100, 100_000)); // 1000:1

        let reasons = guard.take_reasons();
        assert!(reasons
            .iter()
            .any(|r| matches!(r, HostileArchiveReason::ZipBomb { .. })));
    }
    #[test]
    fn test_nested_archive_zip_containing_tar_gz() {
        use flate2::write::GzEncoder;
        use flate2::Compression;
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
        assert_eq!(report.target.file_type, "zip");
        assert!(!report.archive_contents.is_empty());

        // Verify files were extracted and analyzed
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("package.json")));
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("index.js")));
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
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("background.js")));
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
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("Info.plist")));
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

        // Write CRX file with header
        let mut crx_file = File::create(&crx_path).unwrap();

        // CRX3 header: "Cr24" + version (4 bytes) + pubkey_len (4 bytes) + sig_len (4 bytes)
        std::io::Write::write_all(&mut crx_file, b"Cr24").unwrap(); // Magic
        std::io::Write::write_all(&mut crx_file, &3u32.to_le_bytes()).unwrap(); // Version
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
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("manifest.json")));
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

        // Path traversal file should not be in archive_contents
        assert!(!report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("etc/evil")));

        // Should have detected path traversal
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "anti-analysis/archive/path-traversal"
                && f.desc.contains("path traversal")));
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
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("__init__.py")));
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
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("test.txt")));
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
        assert!(report
            .archive_contents
            .iter()
            .any(|e| e.path.contains("test.txt")));
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
        assert!(report
            .findings
            .iter()
            .any(|f| f.id == "anti-analysis/archive/large-file"
                && f.desc.contains("excessively large file")));
    }
}
