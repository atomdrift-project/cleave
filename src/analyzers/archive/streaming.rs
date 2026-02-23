//! Streaming archive analysis with in-memory extraction.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//!
//! This module provides streaming analysis of archives where files are extracted
//! to memory (for files under MAX_MEMORY_FILE_SIZE) and analyzed in parallel via
//! a producer-consumer pattern.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐   bounded channel    ┌─────────────────┐     ┌────────┐
//! │    Extractor    │ ── ExtractedFile ──→ │   Rayon Pool    │ ──→ │ Output │
//! │   (1 thread)    │    (32 capacity)     │  (N analyzers)  │     │        │
//! └─────────────────┘                      └─────────────────┘     └────────┘
//! ```
//!
//! Files under 256MB are extracted to memory buffers, avoiding disk I/O for 99%
//! of typical files. Larger files are extracted to temp files.

use crate::analyzers::{detect_file_type_from_path, Analyzer, FileType};
use crate::types::*;
use anyhow::Result;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::guards::{
    sanitize_entry_path, symlink_escapes, ExtractionGuard, HostileArchiveReason, LimitedReader,
    MAX_FILE_SIZE,
};
use super::utils::{calculate_file_sha256, calculate_sha256};
use super::ArchiveAnalyzer;

// Re-export the default from mod.rs for backwards compatibility
// MAX_MEMORY_FILE_SIZE was removed in favor of configurable max_memory_file_size parameter

/// Extracted file ready for analysis
#[allow(dead_code)] // Used by binary target via analyze_streaming
#[derive(Debug)]
pub(crate) enum ExtractedFile {
    /// File extracted to memory buffer (most files)
    InMemory {
        /// Relative path in archive (e.g., "lib/foo.so")
        path: String,
        /// File contents
        data: Vec<u8>,
        /// Detected file type
        file_type: FileType,
    },
    /// Large file or nested archive extracted to disk
    OnDisk {
        /// Relative path in archive
        path: String,
        /// Temp file location
        temp_path: PathBuf,
        /// Detected file type
        file_type: FileType,
    },
}

impl ExtractedFile {
    /// Get the relative path within the archive
    #[allow(dead_code)] // Used by binary target via analyze_streaming
    #[must_use]
    pub(crate) fn path(&self) -> &str {
        match self {
            ExtractedFile::InMemory { path, .. } | ExtractedFile::OnDisk { path, .. } => path,
        }
    }
}

/// Result of analyzing a single file within an archive
#[allow(dead_code)] // Used by binary target via analyze_streaming
#[derive(Debug)]
pub(crate) struct StreamingFileResult {
    /// File analysis converted to FileAnalysis for v2 schema
    pub file_analysis: FileAnalysis,
    /// Any nested files (from nested archives)
    pub nested_files: Vec<FileAnalysis>,
}

impl ArchiveAnalyzer {
    /// Analyze file from in-memory buffer (no disk I/O).
    ///
    /// This is the core analysis function for streaming. It operates entirely
    /// on the provided byte buffer, using YARA's scan_bytes, tree-sitter parsing
    /// on byte slices, and string extraction on raw bytes.
    #[allow(dead_code)] // Used by binary target
    pub(crate) fn analyze_in_memory(
        &self,
        relative_path: &str,
        data: &[u8],
        file_type: &FileType,
    ) -> Result<StreamingFileResult> {
        let sha256 = calculate_sha256(data);
        let size = data.len() as u64;

        // Create base FileAnalysis
        let mut file_analysis = FileAnalysis::new(
            0, // ID will be assigned later when aggregating
            self.format_entry_path(relative_path),
            format!("{:?}", file_type).to_lowercase(),
            sha256,
            size,
        );
        file_analysis.depth = (self.current_depth + 1) as u32;

        let mut nested_files = Vec::new();

        // Run YARA scan on bytes if engine is available
        if let Some(ref yara_engine) = self.yara_engine {
            match yara_engine.scan_bytes(data) {
                Ok(matches) => {
                    file_analysis.yara_matches = matches;
                }
                Err(e) => {
                    tracing::debug!("YARA scan failed for {}: {}", relative_path, e);
                }
            }
        }

        // Route to appropriate analyzer based on file type
        match file_type {
            // Source code files - use unified analyzer with in-memory parsing
            FileType::Shell
            | FileType::Batch
            | FileType::Python
            | FileType::JavaScript
            | FileType::TypeScript
            | FileType::Go
            | FileType::Rust
            | FileType::Java
            | FileType::Ruby
            | FileType::C
            | FileType::Php
            | FileType::Swift
            | FileType::ObjectiveC
            | FileType::Scala
            | FileType::Lua
            | FileType::Perl
            | FileType::PowerShell
            | FileType::CSharp
            | FileType::Groovy
            | FileType::Zig
            | FileType::Elixir
            | FileType::AppleScript
            | FileType::Rtf => {
                // Use the unified analyzer for source code
                if let Some(mapper) = &self.capability_mapper {
                    // Create a temporary file for analysis since unified analyzer needs a path
                    // TODO: Refactor unified analyzer to support in-memory analysis
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    if let Some(analyzer) = crate::analyzers::analyzer_for_file_type_arc(
                        file_type,
                        Some(mapper.clone()),
                    ) {
                        if let Ok(report) = analyzer.analyze(temp.path()) {
                            // Extract findings and other info from report
                            file_analysis.findings = report.findings;
                            file_analysis.strings = report.strings;
                            file_analysis.imports = report.imports;
                            file_analysis.exports = report.exports;
                            file_analysis.functions = report.functions;
                        }
                    }
                }
            }

            // Binary files - need temp file for goblin parsing
            FileType::Elf | FileType::MachO | FileType::Pe => {
                if let Some(mapper) = &self.capability_mapper {
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    if let Some(analyzer) = crate::analyzers::analyzer_for_file_type_arc(
                        file_type,
                        Some(mapper.clone()),
                    ) {
                        if let Ok(report) = analyzer.analyze(temp.path()) {
                            file_analysis.findings = report.findings;
                            file_analysis.strings = report.strings;
                            file_analysis.imports = report.imports;
                            file_analysis.exports = report.exports;
                            file_analysis.functions = report.functions;
                            file_analysis.sections = report.sections;
                            file_analysis.syscalls = report.syscalls;
                        }
                    }
                }
            }

            // Java class files
            FileType::JavaClass => {
                if let Some(mapper) = &self.capability_mapper {
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    let analyzer = crate::analyzers::java_class::JavaClassAnalyzer::new()
                        .with_capability_mapper_arc(mapper.clone());
                    if let Ok(report) = analyzer.analyze(temp.path()) {
                        file_analysis.findings = report.findings;
                        file_analysis.strings = report.strings;
                        file_analysis.imports = report.imports;
                    }
                }
            }

            // Nested archives - need recursive handling
            FileType::Archive | FileType::Jar => {
                if self.current_depth + 1 < self.max_depth {
                    // For nested archives, we need to write to temp and recurse
                    // In-memory parsing of archives is complex due to seeking requirements
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    let nested_prefix = match &self.archive_path_prefix {
                        Some(prefix) => format!("{}!{}", prefix, relative_path),
                        None => relative_path.to_string(),
                    };

                    let mut nested_analyzer = ArchiveAnalyzer::new()
                        .with_depth(self.current_depth + 1)
                        .with_archive_prefix(nested_prefix);

                    if let Some(ref mapper) = self.capability_mapper {
                        nested_analyzer =
                            nested_analyzer.with_capability_mapper_arc(mapper.clone());
                    }
                    if let Some(ref engine) = self.yara_engine {
                        nested_analyzer = nested_analyzer.with_yara_arc(engine.clone());
                    }
                    if !self.zip_passwords.is_empty() {
                        nested_analyzer =
                            nested_analyzer.with_zip_passwords_arc(self.zip_passwords.clone());
                    }
                    if let Some(ref config) = self.sample_extraction {
                        nested_analyzer = nested_analyzer.with_sample_extraction(config.clone());
                    }

                    if let Ok(report) = nested_analyzer.analyze(temp.path()) {
                        // Merge nested findings
                        file_analysis.findings = report.findings;

                        // Add nested files to results
                        for nested_file in report.files {
                            nested_files.push(nested_file);
                        }
                    }
                }
            }

            // Package manifests
            FileType::PackageJson => {
                if let Some(mapper) = &self.capability_mapper {
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    let analyzer = crate::analyzers::package_json::PackageJsonAnalyzer::new()
                        .with_capability_mapper_arc(mapper.clone());
                    if let Ok(report) = analyzer.analyze(temp.path()) {
                        file_analysis.findings = report.findings;
                    }
                }
            }

            FileType::VsixManifest => {
                if let Some(mapper) = &self.capability_mapper {
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    let analyzer = crate::analyzers::vsix_manifest::VsixManifestAnalyzer::new()
                        .with_capability_mapper_arc(mapper.clone());
                    if let Ok(report) = analyzer.analyze(temp.path()) {
                        file_analysis.findings = report.findings;
                    }
                }
            }

            FileType::ChromeManifest => {
                if let Some(mapper) = &self.capability_mapper {
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    let analyzer = crate::analyzers::chrome_manifest::ChromeManifestAnalyzer::new()
                        .with_capability_mapper_arc(mapper.clone());
                    if let Ok(report) = analyzer.analyze(temp.path()) {
                        file_analysis.findings = report.findings;
                    }
                }
            }

            // Python package metadata - use generic analyzer
            FileType::PkgInfo | FileType::Plist => {
                if let Some(mapper) = &self.capability_mapper {
                    let temp = tempfile::NamedTempFile::new()?;
                    std::fs::write(temp.path(), data)?;

                    if let Some(analyzer) = crate::analyzers::analyzer_for_file_type_arc(
                        file_type,
                        Some(mapper.clone()),
                    ) {
                        if let Ok(report) = analyzer.analyze(temp.path()) {
                            file_analysis.findings = report.findings;
                            file_analysis.strings = report.strings;
                        }
                    }
                }
            }

            // Manifest, image, certificate, and unknown files - no specific deep analysis beyond YARA/traits
            FileType::CargoToml
            | FileType::PyProjectToml
            | FileType::ComposerJson
            | FileType::GithubActions
            | FileType::Jpeg
            | FileType::Png
            | FileType::Certificate
            | FileType::Unknown => {}
        }

        // Compute summary
        file_analysis.compute_summary();

        // Extract file to disk if configured
        if let Some(ref config) = self.sample_extraction {
            // Build relative path preserving structure:
            // - For nested archives like "inner.tar.gz!lib/file.py", use "inner.tar.gz/lib/file.py"
            // - For simple paths like "lib/file.py", use as-is
            let extract_relative_path = match &self.archive_path_prefix {
                Some(prefix) => format!("{}/{}", prefix.replace('!', "/"), relative_path),
                None => relative_path.to_string(),
            };
            if let Some(extracted_path) =
                config.extract(&file_analysis.sha256, &extract_relative_path, data)
            {
                file_analysis.extracted_path = Some(extracted_path.display().to_string());
            }
        }

        Ok(StreamingFileResult {
            file_analysis,
            nested_files,
        })
    }

    /// Extract a TAR entry to memory, returning an ExtractedFile.
    ///
    /// If the entry is larger than `max_memory_file_size` or is a nested archive,
    /// it will be written to a temp file instead.
    #[allow(dead_code)] // Used by binary target
    pub(crate) fn extract_tar_entry_to_memory<'a, R: Read>(
        entry: &mut tar::Entry<'a, R>,
        entry_name: &str,
        temp_dir: &Path,
        guard: &ExtractionGuard,
        max_memory_file_size: u64,
    ) -> Result<Option<ExtractedFile>> {
        let size = entry.header().size()?;

        // Check file size limit
        if size > MAX_FILE_SIZE {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: entry_name.to_string(),
                size,
            });
            return Ok(None);
        }

        // Check if this is a directory or special file
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            return Ok(None);
        }
        if entry_type.is_symlink() || entry_type.is_hard_link() {
            // Check if symlink target escapes extraction directory
            if let Ok(Some(link_target)) = entry.link_name() {
                let target_str = link_target.to_string_lossy();
                let symlink_path = temp_dir.join(entry_name);
                if symlink_escapes(&symlink_path, &target_str, temp_dir) {
                    guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(format!(
                        "{} -> {}",
                        entry_name, target_str
                    )));
                }
            }
            return Ok(None);
        }
        if !entry_type.is_file() {
            return Ok(None);
        }

        // Detect file type from name (can't use detect_file_type since file doesn't exist on disk)
        let path = Path::new(entry_name);
        let file_type = detect_file_type_from_path(path);

        // Decide: in-memory or on-disk?
        let use_disk =
            size > max_memory_file_size || matches!(file_type, FileType::Archive | FileType::Jar);

        if use_disk {
            // Extract to temp file
            let Some(out_path) = sanitize_entry_path(entry_name, temp_dir) else {
                guard.add_hostile_reason(HostileArchiveReason::PathTraversal(
                    entry_name.to_string(),
                ));
                return Ok(None);
            };

            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut outfile = std::fs::File::create(&out_path)?;
            std::io::copy(entry, &mut outfile)?;

            // Track bytes
            if !guard.check_bytes(size, entry_name) {
                return Ok(None);
            }

            Ok(Some(ExtractedFile::OnDisk {
                path: entry_name.to_string(),
                temp_path: out_path,
                file_type,
            }))
        } else {
            // Extract to memory
            let mut data = Vec::with_capacity(size as usize);
            entry.read_to_end(&mut data)?;

            // Track bytes
            if !guard.check_bytes(data.len() as u64, entry_name) {
                return Ok(None);
            }

            // Re-detect file type with actual data (magic bytes)
            let actual_type = if data.len() >= 4 {
                detect_file_type_from_magic(&data).unwrap_or(file_type)
            } else {
                file_type
            };

            Ok(Some(ExtractedFile::InMemory {
                path: entry_name.to_string(),
                data,
                file_type: actual_type,
            }))
        }
    }

    /// Extract a ZIP entry to memory, returning an ExtractedFile.
    ///
    /// If the entry is larger than `max_memory_file_size` or is a nested archive,
    /// it will be written to a temp file instead.
    #[allow(dead_code)] // Used by binary target
    pub(crate) fn extract_zip_entry_to_memory<R: std::io::Read>(
        entry: &mut zip::read::ZipFile<'_, R>,
        temp_dir: &Path,
        guard: &ExtractionGuard,
        max_memory_file_size: u64,
    ) -> Result<Option<ExtractedFile>> {
        let entry_name = entry.name().to_string();
        let size = entry.size();

        // Check if directory
        if entry.is_dir() {
            return Ok(None);
        }

        // Check file size limit
        if size > MAX_FILE_SIZE {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: entry_name.clone(),
                size,
            });
            return Ok(None);
        }

        // Check for symlinks via unix mode
        if let Some(mode) = entry.unix_mode() {
            if mode & 0o170000 == 0o120000 {
                // Symlink target is stored as file content in ZIP
                let mut target_buf = Vec::new();
                if let Ok(read_size) = entry.read_to_end(&mut target_buf) {
                    if read_size > 0 && read_size < 4096 {
                        // Reasonable symlink path length
                        if let Ok(target_str) = String::from_utf8(target_buf) {
                            let symlink_path = temp_dir.join(&entry_name);
                            if symlink_escapes(&symlink_path, &target_str, temp_dir) {
                                guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(
                                    format!("{} -> {}", entry_name, target_str),
                                ));
                            }
                        }
                    }
                }
                return Ok(None);
            }
        }

        // Check compression ratio (zip bomb detection)
        let compressed = entry.compressed_size();
        if !guard.check_compression_ratio(compressed, size) {
            return Ok(None);
        }

        // Detect file type from name (can't use detect_file_type since file doesn't exist on disk)
        let path = Path::new(&entry_name);
        let file_type = detect_file_type_from_path(path);

        // Decide: in-memory or on-disk?
        let use_disk =
            size > max_memory_file_size || matches!(file_type, FileType::Archive | FileType::Jar);

        if use_disk {
            // Extract to temp file
            let Some(out_path) = sanitize_entry_path(&entry_name, temp_dir) else {
                guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_name.clone()));
                return Ok(None);
            };

            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut outfile = std::fs::File::create(&out_path)?;
            std::io::copy(entry, &mut outfile)?;

            // Track bytes
            if !guard.check_bytes(size, &entry_name) {
                return Ok(None);
            }

            Ok(Some(ExtractedFile::OnDisk {
                path: entry_name,
                temp_path: out_path,
                file_type,
            }))
        } else {
            // Extract to memory
            let mut data = Vec::with_capacity(size as usize);
            entry.read_to_end(&mut data)?;

            // Track bytes
            if !guard.check_bytes(data.len() as u64, &entry_name) {
                return Ok(None);
            }

            // Re-detect file type with actual data
            let actual_type = if data.len() >= 4 {
                detect_file_type_from_magic(&data).unwrap_or(file_type)
            } else {
                file_type
            };

            Ok(Some(ExtractedFile::InMemory {
                path: entry_name,
                data,
                file_type: actual_type,
            }))
        }
    }

    /// Analyze a TAR archive with streaming extraction and parallel analysis.
    ///
    /// Uses a producer-consumer pattern:
    /// - Producer thread: Reads TAR entries sequentially, extracts to memory
    /// - Consumer pool: Rayon parallel iterator analyzes files concurrently
    ///
    /// The callback `on_file` is invoked for each file as it completes analysis,
    /// enabling real-time streaming output.
    ///
    /// # Arguments
    /// * `archive_path` - Path to the TAR archive (may be compressed)
    /// * `on_file` - Callback invoked for each analyzed file
    ///
    /// # Returns
    /// An ArchiveSummary with aggregate statistics
    #[allow(dead_code)] // Used by binary target
    pub(crate) fn analyze_tar_streaming<F>(
        &self,
        archive_path: &Path,
        on_file: F,
    ) -> Result<ArchiveSummary>
    where
        F: Fn(StreamingFileResult) + Send + Sync,
    {
        use crossbeam_channel::bounded;
        use rayon::prelude::*;
        use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

        // Calculate archive SHA256 for extraction directory grouping
        // This ensures all files from the same archive end up in one directory
        let archive_sha256 =
            calculate_file_sha256(archive_path).unwrap_or_else(|_| "unknown".to_string());

        // Create analyzer with archive SHA256 set in extraction config
        let analyzer = self.with_extraction_archive_sha256(&archive_sha256);

        // Detect compression type
        let compression = super::utils::detect_tar_compression(archive_path);

        // Create temp dir for large files
        let temp_dir = tempfile::tempdir()?;

        // Create extraction guard
        let guard = ExtractionGuard::new();

        // Bounded channel (32 items) for backpressure
        let (tx, rx) = bounded::<ExtractedFile>(32);

        // Statistics
        let files_analyzed = AtomicU32::new(0);
        let hostile_count = AtomicU32::new(0);
        let suspicious_count = AtomicU32::new(0);
        let notable_count = AtomicU32::new(0);
        let total_bytes = AtomicU64::new(0);

        // Clone self for the producer thread
        let archive_path = archive_path.to_path_buf();
        let temp_dir_path = temp_dir.path().to_path_buf();
        let max_memory_file_size = analyzer.max_memory_file_size();

        // Spawn extractor thread
        let extractor_handle = std::thread::spawn(move || -> Result<Vec<HostileArchiveReason>> {
            let file = std::fs::File::open(&archive_path)?;

            let reader: Box<dyn Read + Send> = match compression.as_deref() {
                Some("gzip") => Box::new(flate2::read::MultiGzDecoder::new(file)),
                Some("bzip2") => Box::new(bzip2::read::BzDecoder::new(file)),
                Some("xz") => Box::new(xz2::read::XzDecoder::new(file)),
                Some("zstd") => Box::new(
                    zstd::stream::read::Decoder::new(file)
                        .map_err(|e| anyhow::anyhow!("Failed to create zstd decoder: {}", e))?,
                ),
                _ => Box::new(file),
            };

            let mut archive = tar::Archive::new(reader);

            let entries = archive.entries()?;
            for entry_result in entries {
                // Check file count limit
                if !guard.check_file_count() {
                    break;
                }

                let mut entry = match entry_result {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::debug!("Failed to read TAR entry: {}", e);
                        continue;
                    }
                };

                let entry_name = match entry.path() {
                    Ok(p) => p.to_string_lossy().to_string(),
                    Err(e) => {
                        tracing::debug!("Failed to get entry path: {}", e);
                        continue;
                    }
                };

                // Extract to memory or disk
                match ArchiveAnalyzer::extract_tar_entry_to_memory(
                    &mut entry,
                    &entry_name,
                    &temp_dir_path,
                    &guard,
                    max_memory_file_size,
                ) {
                    Ok(Some(extracted)) => {
                        // Send to analysis pool - if channel is full, this blocks (backpressure)
                        if tx.send(extracted).is_err() {
                            // Receiver dropped, stop extraction
                            break;
                        }
                    }
                    Ok(None) => {
                        // Skipped (directory, symlink, etc.)
                    }
                    Err(e) => {
                        tracing::debug!("Failed to extract {}: {}", entry_name, e);
                    }
                }
            }

            // Drop sender to signal completion
            drop(tx);

            Ok(guard.take_reasons())
        });

        // Analyze files in parallel using rayon
        let on_file_ref = &on_file;
        let files_analyzed_ref = &files_analyzed;
        let hostile_count_ref = &hostile_count;
        let suspicious_count_ref = &suspicious_count;
        let notable_count_ref = &notable_count;
        let total_bytes_ref = &total_bytes;
        let analyzer_ref = &analyzer;

        rx.into_iter().par_bridge().for_each(|file| {
            // Files will be re-analyzed with proper type detection from content/extension

            // Analyze the file
            let result = match &file {
                ExtractedFile::InMemory {
                    path,
                    data,
                    file_type,
                } => {
                    total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                    analyzer_ref.analyze_in_memory(path, data, file_type)
                }
                ExtractedFile::OnDisk {
                    path,
                    temp_path,
                    file_type,
                } => {
                    // Read from disk and analyze
                    match std::fs::read(temp_path) {
                        Ok(data) => {
                            total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                            analyzer_ref.analyze_in_memory(path, &data, file_type)
                        }
                        Err(e) => Err(anyhow::anyhow!("Failed to read temp file: {}", e)),
                    }
                }
            };

            match result {
                Ok(file_result) => {
                    files_analyzed_ref.fetch_add(1, Ordering::Relaxed);

                    // Update statistics from findings
                    if let Some(risk) = &file_result.file_analysis.risk {
                        match risk {
                            crate::types::Criticality::Hostile => {
                                hostile_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Suspicious => {
                                suspicious_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Notable => {
                                notable_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                    }

                    // Invoke callback for streaming output
                    on_file_ref(file_result);
                }
                Err(e) => {
                    tracing::debug!("Failed to analyze {}: {}", file.path(), e);
                }
            }
        });

        // Wait for extractor to finish and get hostile reasons
        let hostile_reasons = extractor_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Extractor thread panicked"))??;

        Ok(ArchiveSummary { hostile_reasons })
    }

    /// Analyze a ZIP archive with streaming extraction and parallel analysis.
    ///
    /// Uses the same producer-consumer pattern as TAR streaming.
    /// Note: ZIP requires reading the central directory first, so there's
    /// a small initial delay before streaming begins.
    #[allow(dead_code)] // Used by binary target
    pub(crate) fn analyze_zip_streaming<F>(
        &self,
        archive_path: &Path,
        on_file: F,
    ) -> Result<ArchiveSummary>
    where
        F: Fn(StreamingFileResult) + Send + Sync,
    {
        use crossbeam_channel::bounded;
        use rayon::prelude::*;
        use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

        // Calculate archive SHA256 for extraction directory grouping
        // This ensures all files from the same archive end up in one directory
        let archive_sha256 =
            calculate_file_sha256(archive_path).unwrap_or_else(|_| "unknown".to_string());

        // Create analyzer with archive SHA256 set in extraction config
        let analyzer = self.with_extraction_archive_sha256(&archive_sha256);

        // Create temp dir for large files
        let temp_dir = tempfile::tempdir()?;

        // Create extraction guard
        let guard = ExtractionGuard::new();

        // Bounded channel (32 items) for backpressure
        let (tx, rx) = bounded::<ExtractedFile>(32);

        // Statistics
        let files_analyzed = AtomicU32::new(0);
        let hostile_count = AtomicU32::new(0);
        let suspicious_count = AtomicU32::new(0);
        let notable_count = AtomicU32::new(0);
        let total_bytes = AtomicU64::new(0);

        // Clone for the producer thread
        let archive_path = archive_path.to_path_buf();
        let temp_dir_path = temp_dir.path().to_path_buf();
        let zip_passwords = self.zip_passwords.clone();
        let max_memory_file_size = analyzer.max_memory_file_size();

        // Spawn extractor thread
        let extractor_handle = std::thread::spawn(move || -> Result<Vec<HostileArchiveReason>> {
            let file = std::fs::File::open(&archive_path)?;
            let mut archive = zip::ZipArchive::new(file)?;

            // Check if the archive is encrypted by trying to read entries
            // If we get "Password required" error, the archive is encrypted
            tracing::info!("ZIP archive has {} entries", archive.len());
            let is_encrypted = if !archive.is_empty() {
                let mut found_encrypted = false;
                for i in 0..archive.len().min(10) {
                    match archive.by_index(i) {
                        Ok(_) => {
                            // Successfully read entry without password means not encrypted (or dir)
                            tracing::debug!("Entry {} read successfully without password", i);
                        }
                        Err(e) => {
                            // Check if it's a password error
                            let error_msg = e.to_string();
                            if error_msg.contains("Password") {
                                found_encrypted = true;
                                tracing::info!("Archive appears encrypted (password required)");
                                break;
                            }
                            // Other errors might be corruption or other issues
                            tracing::debug!("Error reading entry {}: {}", i, e);
                        }
                    }
                }
                tracing::info!("ZIP archive is_encrypted: {}", found_encrypted);
                found_encrypted
            } else {
                false
            };

            // If encrypted, try each password until one works
            let password_to_use = if is_encrypted {
                if zip_passwords.is_empty() {
                    anyhow::bail!("Archive is encrypted but no passwords configured");
                }

                let mut working_password: Option<String> = None;
                for password in zip_passwords.iter() {
                    tracing::debug!("Trying password for ZIP archive");
                    let file = std::fs::File::open(&archive_path)?;
                    let mut test_archive = zip::ZipArchive::new(file)?;

                    // Try to decrypt any file entry to test the password
                    let mut password_works = false;
                    for i in 0..test_archive.len() {
                        // Check if it's a directory without holding a borrow
                        let is_dir = test_archive
                            .by_index(i)
                            .ok()
                            .map(|e| e.is_dir())
                            .unwrap_or(false);
                        if !is_dir {
                            // Try to decrypt this file
                            if test_archive
                                .by_index_decrypt(i, password.as_bytes())
                                .is_ok()
                            {
                                password_works = true;
                            }
                            break;
                        }
                    }

                    if password_works {
                        tracing::info!("✓ Decrypted with password: {}", password);
                        eprintln!("  Decrypted with password: {}", password);
                        working_password = Some(password.clone());
                        break;
                    }
                }

                if let Some(pw) = working_password {
                    Some(pw)
                } else {
                    anyhow::bail!(
                        "Password required to decrypt file (tried {} passwords)",
                        zip_passwords.len()
                    );
                }
            } else {
                None
            };

            // Now re-open the archive for actual extraction with the password (if needed)
            let file = std::fs::File::open(&archive_path)?;
            archive = zip::ZipArchive::new(file)?;

            for i in 0..archive.len() {
                // Check file count limit
                if !guard.check_file_count() {
                    break;
                }

                let mut entry = match &password_to_use {
                    Some(pw) => match archive.by_index_decrypt(i, pw.as_bytes()) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::debug!("Failed to decrypt ZIP entry {}: {}", i, e);
                            continue;
                        }
                    },
                    None => match archive.by_index(i) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::debug!("Failed to read ZIP entry {}: {}", i, e);
                            continue;
                        }
                    },
                };

                // Extract to memory or disk
                match ArchiveAnalyzer::extract_zip_entry_to_memory(
                    &mut entry,
                    &temp_dir_path,
                    &guard,
                    max_memory_file_size,
                ) {
                    Ok(Some(extracted)) => {
                        if tx.send(extracted).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!("Failed to extract ZIP entry: {}", e);
                    }
                }
            }

            drop(tx);
            Ok(guard.take_reasons())
        });

        // Analyze files in parallel
        let on_file_ref = &on_file;
        let files_analyzed_ref = &files_analyzed;
        let hostile_count_ref = &hostile_count;
        let suspicious_count_ref = &suspicious_count;
        let notable_count_ref = &notable_count;
        let total_bytes_ref = &total_bytes;
        let analyzer_ref = &analyzer;

        rx.into_iter().par_bridge().for_each(|file| {
            // Files will be re-analyzed with proper type detection from content/extension

            let result = match &file {
                ExtractedFile::InMemory {
                    path,
                    data,
                    file_type,
                } => {
                    total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                    analyzer_ref.analyze_in_memory(path, data, file_type)
                }
                ExtractedFile::OnDisk {
                    path,
                    temp_path,
                    file_type,
                } => match std::fs::read(temp_path) {
                    Ok(data) => {
                        total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                        analyzer_ref.analyze_in_memory(path, &data, file_type)
                    }
                    Err(e) => Err(anyhow::anyhow!("Failed to read temp file: {}", e)),
                },
            };

            match result {
                Ok(file_result) => {
                    files_analyzed_ref.fetch_add(1, Ordering::Relaxed);

                    if let Some(risk) = &file_result.file_analysis.risk {
                        match risk {
                            crate::types::Criticality::Hostile => {
                                hostile_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Suspicious => {
                                suspicious_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Notable => {
                                notable_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                    }

                    on_file_ref(file_result);
                }
                Err(e) => {
                    tracing::debug!("Failed to analyze {}: {}", file.path(), e);
                }
            }
        });

        let hostile_reasons = extractor_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Extractor thread panicked"))??;

        Ok(ArchiveSummary { hostile_reasons })
    }

    /// Analyze a DEB package with streaming extraction and parallel analysis.
    ///
    /// DEB files are AR archives containing:
    /// - debian-binary (version)
    /// - control.tar.* (metadata)
    /// - data.tar.* (actual files)
    ///
    /// We stream the inner tar archives for parallel analysis.
    #[allow(dead_code)] // Used by binary target
    pub(crate) fn analyze_deb_streaming<F>(
        &self,
        archive_path: &Path,
        on_file: F,
    ) -> Result<ArchiveSummary>
    where
        F: Fn(StreamingFileResult) + Send + Sync,
    {
        use crossbeam_channel::bounded;
        use rayon::prelude::*;
        use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

        // Calculate archive SHA256 for extraction directory grouping
        let archive_sha256 =
            calculate_file_sha256(archive_path).unwrap_or_else(|_| "unknown".to_string());
        let analyzer = self.with_extraction_archive_sha256(&archive_sha256);

        // Create temp dir for large files
        let temp_dir = tempfile::tempdir()?;

        // Create extraction guard
        let guard = ExtractionGuard::new();

        // Bounded channel (32 items) for backpressure
        let (tx, rx) = bounded::<ExtractedFile>(32);

        // Statistics
        let files_analyzed = AtomicU32::new(0);
        let hostile_count = AtomicU32::new(0);
        let suspicious_count = AtomicU32::new(0);
        let notable_count = AtomicU32::new(0);
        let total_bytes = AtomicU64::new(0);

        let archive_path = archive_path.to_path_buf();
        let temp_dir_path = temp_dir.path().to_path_buf();
        let max_memory_file_size = analyzer.max_memory_file_size();

        // Spawn extractor thread
        let extractor_handle = std::thread::spawn(move || -> Result<Vec<HostileArchiveReason>> {
            let file = std::fs::File::open(&archive_path)?;
            let mut ar_archive = ar::Archive::new(file);

            while let Some(entry_result) = ar_archive.next_entry() {
                let entry = match entry_result {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::debug!("Failed to read AR entry: {}", e);
                        continue;
                    }
                };

                let name = String::from_utf8_lossy(entry.header().identifier()).to_string();

                // Process data.tar.* and control.tar.*
                if name.starts_with("data.tar") || name.starts_with("control.tar") {
                    let prefix = if name.starts_with("data.tar") {
                        "data"
                    } else {
                        "control"
                    };

                    // Determine compression
                    let reader: Box<dyn Read + Send> = if name.ends_with(".gz") {
                        Box::new(flate2::read::GzDecoder::new(entry))
                    } else if name.ends_with(".xz") {
                        Box::new(xz2::read::XzDecoder::new(entry))
                    } else if name.ends_with(".zst") {
                        match zstd::stream::read::Decoder::new(entry) {
                            Ok(d) => Box::new(d),
                            Err(e) => {
                                tracing::debug!("Failed to create zstd decoder: {}", e);
                                continue;
                            }
                        }
                    } else if name.ends_with(".bz2") {
                        Box::new(bzip2::read::BzDecoder::new(entry))
                    } else {
                        Box::new(entry)
                    };

                    // Process TAR entries
                    let mut tar = tar::Archive::new(reader);
                    for tar_entry_result in tar.entries()? {
                        if !guard.check_file_count() {
                            break;
                        }

                        let mut tar_entry = match tar_entry_result {
                            Ok(e) => e,
                            Err(e) => {
                                tracing::debug!("Failed to read TAR entry: {}", e);
                                continue;
                            }
                        };

                        let entry_name = match tar_entry.path() {
                            Ok(p) => format!("{}/{}", prefix, p.to_string_lossy()),
                            Err(_) => continue,
                        };

                        match ArchiveAnalyzer::extract_tar_entry_to_memory(
                            &mut tar_entry,
                            &entry_name,
                            &temp_dir_path,
                            &guard,
                            max_memory_file_size,
                        ) {
                            Ok(Some(extracted)) => {
                                if tx.send(extracted).is_err() {
                                    break;
                                }
                            }
                            Ok(None) => {}
                            Err(e) => {
                                tracing::debug!("Failed to extract {}: {}", entry_name, e);
                            }
                        }
                    }
                }
            }

            drop(tx);
            Ok(guard.take_reasons())
        });

        // Analyze files in parallel
        let on_file_ref = &on_file;
        let files_analyzed_ref = &files_analyzed;
        let hostile_count_ref = &hostile_count;
        let suspicious_count_ref = &suspicious_count;
        let notable_count_ref = &notable_count;
        let total_bytes_ref = &total_bytes;
        let analyzer_ref = &analyzer;

        rx.into_iter().par_bridge().for_each(|file| {
            // Files will be re-analyzed with proper type detection from content/extension

            let result = match &file {
                ExtractedFile::InMemory {
                    path,
                    data,
                    file_type,
                } => {
                    total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                    analyzer_ref.analyze_in_memory(path, data, file_type)
                }
                ExtractedFile::OnDisk {
                    path,
                    temp_path,
                    file_type,
                } => match std::fs::read(temp_path) {
                    Ok(data) => {
                        total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                        analyzer_ref.analyze_in_memory(path, &data, file_type)
                    }
                    Err(e) => Err(anyhow::anyhow!("Failed to read temp file: {}", e)),
                },
            };

            match result {
                Ok(file_result) => {
                    files_analyzed_ref.fetch_add(1, Ordering::Relaxed);

                    if let Some(risk) = &file_result.file_analysis.risk {
                        match risk {
                            crate::types::Criticality::Hostile => {
                                hostile_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Suspicious => {
                                suspicious_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Notable => {
                                notable_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                    }

                    on_file_ref(file_result);
                }
                Err(e) => {
                    tracing::debug!("Failed to analyze {}: {}", file.path(), e);
                }
            }
        });

        let hostile_reasons = extractor_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Extractor thread panicked"))??;

        Ok(ArchiveSummary { hostile_reasons })
    }

    /// Analyze an RPM package with streaming extraction and parallel analysis.
    ///
    /// RPM files contain a lead, signature header, main header, and CPIO payload.
    /// The CPIO payload may be compressed with gzip, xz, zstd, bzip2, or lzma.
    #[allow(dead_code)] // Used by binary target
    pub(crate) fn analyze_rpm_streaming<F>(
        &self,
        archive_path: &Path,
        on_file: F,
    ) -> Result<ArchiveSummary>
    where
        F: Fn(StreamingFileResult) + Send + Sync,
    {
        use crossbeam_channel::bounded;
        use rayon::prelude::*;
        use std::io::BufReader;
        use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

        // Calculate archive SHA256 for extraction directory grouping
        let archive_sha256 =
            calculate_file_sha256(archive_path).unwrap_or_else(|_| "unknown".to_string());
        let analyzer = self.with_extraction_archive_sha256(&archive_sha256);

        // Create temp dir for large files
        let temp_dir = tempfile::tempdir()?;

        // Create extraction guard
        let guard = ExtractionGuard::new();

        // Bounded channel (32 items) for backpressure
        let (tx, rx) = bounded::<ExtractedFile>(32);

        // Statistics
        let files_analyzed = AtomicU32::new(0);
        let hostile_count = AtomicU32::new(0);
        let suspicious_count = AtomicU32::new(0);
        let notable_count = AtomicU32::new(0);
        let total_bytes = AtomicU64::new(0);

        let archive_path = archive_path.to_path_buf();
        let temp_dir_path = temp_dir.path().to_path_buf();
        let max_memory_file_size = analyzer.max_memory_file_size();

        // Spawn extractor thread
        let extractor_handle = std::thread::spawn(move || -> Result<Vec<HostileArchiveReason>> {
            let file = std::fs::File::open(&archive_path)?;
            let mut reader = BufReader::new(file);

            // RPM magic: 0xedabeedb
            let mut magic = [0u8; 4];
            reader.read_exact(&mut magic)?;
            if magic != [0xed, 0xab, 0xee, 0xdb] {
                anyhow::bail!("Not a valid RPM file (invalid magic)");
            }

            // Read RPM lead (96 bytes total, we already read 4)
            let mut lead_rest = [0u8; 92];
            reader.read_exact(&mut lead_rest)?;

            // Skip signature header
            let sig_size = skip_rpm_header(&mut reader)?;

            // Align to 8-byte boundary
            let pos = sig_size;
            let padding = (8 - (pos % 8)) % 8;
            if padding > 0 {
                let mut pad = vec![0u8; padding];
                reader.read_exact(&mut pad)?;
            }

            // Skip main header
            skip_rpm_header(&mut reader)?;

            // Detect compression
            let mut peek = [0u8; 6];
            reader.read_exact(&mut peek)?;
            let peek_cursor = std::io::Cursor::new(peek.to_vec());
            let chained = peek_cursor.chain(reader);

            // Create decompressor based on magic
            let cpio_reader: Box<dyn Read + Send> = if peek[0..2] == [0x1f, 0x8b] {
                Box::new(flate2::read::GzDecoder::new(chained))
            } else if peek[0..3] == [0xfd, 0x37, 0x7a] {
                Box::new(xz2::read::XzDecoder::new(chained))
            } else if peek[0..4] == [0x28, 0xb5, 0x2f, 0xfd] {
                match zstd::stream::read::Decoder::new(chained) {
                    Ok(d) => Box::new(d),
                    Err(e) => anyhow::bail!("Failed to create zstd decoder: {}", e),
                }
            } else if peek[0..3] == [0x42, 0x5a, 0x68] {
                Box::new(bzip2::read::BzDecoder::new(chained))
            } else if peek[0..2] == [0x5d, 0x00] {
                Box::new(xz2::read::XzDecoder::new(chained))
            } else {
                Box::new(chained)
            };

            // Process CPIO entries
            extract_cpio_streaming(
                cpio_reader,
                &temp_dir_path,
                &guard,
                &tx,
                max_memory_file_size,
            )?;

            drop(tx);
            Ok(guard.take_reasons())
        });

        // Analyze files in parallel
        let on_file_ref = &on_file;
        let files_analyzed_ref = &files_analyzed;
        let hostile_count_ref = &hostile_count;
        let suspicious_count_ref = &suspicious_count;
        let notable_count_ref = &notable_count;
        let total_bytes_ref = &total_bytes;
        let analyzer_ref = &analyzer;

        rx.into_iter().par_bridge().for_each(|file| {
            // Files will be re-analyzed with proper type detection from content/extension

            let result = match &file {
                ExtractedFile::InMemory {
                    path,
                    data,
                    file_type,
                } => {
                    total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                    analyzer_ref.analyze_in_memory(path, data, file_type)
                }
                ExtractedFile::OnDisk {
                    path,
                    temp_path,
                    file_type,
                } => match std::fs::read(temp_path) {
                    Ok(data) => {
                        total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                        analyzer_ref.analyze_in_memory(path, &data, file_type)
                    }
                    Err(e) => Err(anyhow::anyhow!("Failed to read temp file: {}", e)),
                },
            };

            match result {
                Ok(file_result) => {
                    files_analyzed_ref.fetch_add(1, Ordering::Relaxed);

                    if let Some(risk) = &file_result.file_analysis.risk {
                        match risk {
                            crate::types::Criticality::Hostile => {
                                hostile_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Suspicious => {
                                suspicious_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Notable => {
                                notable_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                    }

                    on_file_ref(file_result);
                }
                Err(e) => {
                    tracing::debug!("Failed to analyze {}: {}", file.path(), e);
                }
            }
        });

        let hostile_reasons = extractor_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Extractor thread panicked"))??;

        Ok(ArchiveSummary { hostile_reasons })
    }
}

impl ArchiveAnalyzer {
    /// Analyze a 7z archive with sequential extraction and parallel analysis.
    ///
    /// 7z uses solid compression so extraction must be sequential, but we can
    /// analyze files in parallel as they're extracted.
    #[allow(dead_code)] // Used by binary target
    pub(crate) fn analyze_7z_streaming<F>(
        &self,
        archive_path: &Path,
        on_file: F,
    ) -> Result<ArchiveSummary>
    where
        F: Fn(StreamingFileResult) + Send + Sync,
    {
        use crossbeam_channel::bounded;
        use rayon::prelude::*;
        use sevenz_rust::{Password, SevenZReader};
        use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

        // Calculate archive SHA256 for extraction directory grouping
        let archive_sha256 =
            calculate_file_sha256(archive_path).unwrap_or_else(|_| "unknown".to_string());
        let analyzer = self.with_extraction_archive_sha256(&archive_sha256);

        // Create temp dir for large files
        let temp_dir = tempfile::tempdir()?;

        // Create extraction guard
        let guard = ExtractionGuard::new();

        // Bounded channel (32 items) for backpressure
        let (tx, rx) = bounded::<ExtractedFile>(32);

        // Statistics
        let files_analyzed = AtomicU32::new(0);
        let hostile_count = AtomicU32::new(0);
        let suspicious_count = AtomicU32::new(0);
        let notable_count = AtomicU32::new(0);
        let total_bytes = AtomicU64::new(0);

        let archive_path = archive_path.to_path_buf();
        let temp_dir_path = temp_dir.path().to_path_buf();
        let max_memory_file_size = analyzer.max_memory_file_size();

        // Spawn extractor thread (must be sequential due to solid compression)
        let extractor_handle = std::thread::spawn(move || -> Result<Vec<HostileArchiveReason>> {
            let file = std::fs::File::open(&archive_path)?;
            let file_len = file.metadata()?.len();

            let mut sz = SevenZReader::new(file, file_len, Password::empty())
                .map_err(|e| anyhow::anyhow!("Failed to read 7z: {}", e))?;

            sz.for_each_entries(|entry, reader| {
                if !guard.check_file_count() {
                    return Err(sevenz_rust::Error::other("Exceeded maximum file count"));
                }

                let name = entry.name().to_string();
                if name.is_empty() || entry.is_directory() {
                    return Ok(true);
                }

                // Sanitize path
                if sanitize_entry_path(&name, &temp_dir_path).is_none() {
                    guard.add_hostile_reason(HostileArchiveReason::PathTraversal(name.clone()));
                    return Ok(true);
                }

                let file_size = entry.size();
                if file_size > MAX_FILE_SIZE {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: name.clone(),
                        size: file_size,
                    });
                    return Ok(true);
                }

                // Detect file type from name (can't use detect_file_type since file doesn't exist on disk)
                let path = std::path::Path::new(&name);
                let file_type = detect_file_type_from_path(path);

                // Read to memory or disk
                let use_disk = file_size > max_memory_file_size
                    || matches!(file_type, FileType::Archive | FileType::Jar);

                if use_disk {
                    let out_path = temp_dir_path.join(&name);
                    if let Some(parent) = out_path.parent() {
                        std::fs::create_dir_all(parent).ok();
                    }

                    let mut limited = LimitedReader::new(reader, MAX_FILE_SIZE);
                    let Ok(mut outfile) = std::fs::File::create(&out_path) else {
                        return Ok(true);
                    };

                    if std::io::copy(&mut limited, &mut outfile).is_err() {
                        return Ok(true);
                    }

                    if !guard.check_bytes(file_size, &name) {
                        return Err(sevenz_rust::Error::other("Exceeded total size"));
                    }

                    if tx
                        .send(ExtractedFile::OnDisk {
                            path: name,
                            temp_path: out_path,
                            file_type,
                        })
                        .is_err()
                    {
                        return Err(sevenz_rust::Error::other("Channel closed"));
                    }
                } else {
                    let mut data = Vec::with_capacity(file_size as usize);
                    let mut limited = LimitedReader::new(reader, MAX_FILE_SIZE);
                    if std::io::Read::read_to_end(&mut limited, &mut data).is_err() {
                        return Ok(true);
                    }

                    if !guard.check_bytes(data.len() as u64, &name) {
                        return Err(sevenz_rust::Error::other("Exceeded total size"));
                    }

                    // Re-detect with magic
                    let actual_type = if data.len() >= 4 {
                        detect_file_type_from_magic(&data).unwrap_or(file_type)
                    } else {
                        file_type
                    };

                    if tx
                        .send(ExtractedFile::InMemory {
                            path: name,
                            data,
                            file_type: actual_type,
                        })
                        .is_err()
                    {
                        return Err(sevenz_rust::Error::other("Channel closed"));
                    }
                }

                Ok(true)
            })
            .map_err(|e| anyhow::anyhow!("7z extraction failed: {}", e))?;

            drop(tx);
            Ok(guard.take_reasons())
        });

        // Analyze files in parallel
        let on_file_ref = &on_file;
        let files_analyzed_ref = &files_analyzed;
        let hostile_count_ref = &hostile_count;
        let suspicious_count_ref = &suspicious_count;
        let notable_count_ref = &notable_count;
        let total_bytes_ref = &total_bytes;
        let analyzer_ref = &analyzer;

        rx.into_iter().par_bridge().for_each(|file| {
            // Files will be re-analyzed with proper type detection from content/extension

            let result = match &file {
                ExtractedFile::InMemory {
                    path,
                    data,
                    file_type,
                } => {
                    total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                    analyzer_ref.analyze_in_memory(path, data, file_type)
                }
                ExtractedFile::OnDisk {
                    path,
                    temp_path,
                    file_type,
                } => match std::fs::read(temp_path) {
                    Ok(data) => {
                        total_bytes_ref.fetch_add(data.len() as u64, Ordering::Relaxed);
                        analyzer_ref.analyze_in_memory(path, &data, file_type)
                    }
                    Err(e) => Err(anyhow::anyhow!("Failed to read temp file: {}", e)),
                },
            };

            match result {
                Ok(file_result) => {
                    files_analyzed_ref.fetch_add(1, Ordering::Relaxed);

                    if let Some(risk) = &file_result.file_analysis.risk {
                        match risk {
                            crate::types::Criticality::Hostile => {
                                hostile_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Suspicious => {
                                suspicious_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            crate::types::Criticality::Notable => {
                                notable_count_ref.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {}
                        }
                    }

                    on_file_ref(file_result);
                }
                Err(e) => {
                    tracing::debug!("Failed to analyze {}: {}", file.path(), e);
                }
            }
        });

        let hostile_reasons = extractor_handle
            .join()
            .map_err(|_| anyhow::anyhow!("Extractor thread panicked"))??;

        Ok(ArchiveSummary { hostile_reasons })
    }
}

/// Skip an RPM header and return its size
#[allow(dead_code)] // Used internally
fn skip_rpm_header<R: Read>(reader: &mut R) -> Result<usize> {
    let mut magic = [0u8; 3];
    reader.read_exact(&mut magic)?;
    if magic != [0x8e, 0xad, 0xe8] {
        anyhow::bail!("Invalid RPM header magic");
    }

    let mut version = [0u8; 1];
    reader.read_exact(&mut version)?;

    let mut reserved = [0u8; 4];
    reader.read_exact(&mut reserved)?;

    let mut nindex = [0u8; 4];
    reader.read_exact(&mut nindex)?;
    let nindex = u32::from_be_bytes(nindex);

    let mut hsize = [0u8; 4];
    reader.read_exact(&mut hsize)?;
    let hsize = u32::from_be_bytes(hsize);

    let index_size = nindex as usize * 16;
    let mut index_data = vec![0u8; index_size];
    reader.read_exact(&mut index_data)?;

    let mut data = vec![0u8; hsize as usize];
    reader.read_exact(&mut data)?;

    Ok(16 + index_size + hsize as usize)
}

/// Extract CPIO entries to memory and send to channel for parallel analysis
#[allow(dead_code)] // Used internally
fn extract_cpio_streaming<R: Read>(
    mut reader: R,
    temp_dir: &Path,
    guard: &ExtractionGuard,
    tx: &crossbeam_channel::Sender<ExtractedFile>,
    max_memory_file_size: u64,
) -> Result<()> {
    loop {
        if !guard.check_file_count() {
            break;
        }

        let entry_reader = match cpio::newc::Reader::new(&mut reader) {
            Ok(r) => r,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::InvalidData {
                    break;
                }
                return Err(e.into());
            }
        };

        let entry = entry_reader.entry();
        let name = entry.name().to_string();

        if name == "TRAILER!!!" {
            break;
        }

        if name.is_empty() || name == "." {
            let mut sink = std::io::sink();
            std::io::copy(&mut { entry_reader }, &mut sink).ok();
            continue;
        }

        let clean_name = name.trim_start_matches("./").trim_start_matches('/');
        if clean_name.is_empty() {
            let mut sink = std::io::sink();
            std::io::copy(&mut { entry_reader }, &mut sink).ok();
            continue;
        }

        let mode = entry.mode();
        let file_size = entry.file_size() as u64;

        // Skip directories and non-regular files
        if mode & 0o170000 != 0o100000 {
            if mode & 0o170000 == 0o120000 {
                // Symlink - target is stored as file data
                let mut target_buf = Vec::new();
                if file_size > 0 && file_size < 4096 {
                    // Reasonable symlink path length
                    let mut limited = LimitedReader::new(entry_reader, file_size.min(4096));
                    if limited.read_to_end(&mut target_buf).is_ok() {
                        if let Ok(target_str) = String::from_utf8(target_buf) {
                            let symlink_path = temp_dir.join(clean_name);
                            if symlink_escapes(&symlink_path, &target_str, temp_dir) {
                                guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(
                                    format!("{} -> {}", clean_name, target_str),
                                ));
                            }
                        }
                    }
                } else {
                    // Consume the entry data
                    let mut sink = std::io::sink();
                    std::io::copy(&mut { entry_reader }, &mut sink).ok();
                }
            } else {
                let mut sink = std::io::sink();
                std::io::copy(&mut { entry_reader }, &mut sink).ok();
            }
            continue;
        }

        // Check file size
        if file_size > MAX_FILE_SIZE {
            guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                file: clean_name.to_string(),
                size: file_size,
            });
            let mut sink = std::io::sink();
            std::io::copy(&mut { entry_reader }, &mut sink).ok();
            continue;
        }

        // Sanitize path
        let Some(out_path) = sanitize_entry_path(clean_name, temp_dir) else {
            guard.add_hostile_reason(HostileArchiveReason::PathTraversal(name.clone()));
            let mut sink = std::io::sink();
            std::io::copy(&mut { entry_reader }, &mut sink).ok();
            continue;
        };

        // Detect file type from name (can't use detect_file_type since file doesn't exist on disk)
        let path = std::path::Path::new(clean_name);
        let file_type = detect_file_type_from_path(path);

        // Decide: in-memory or on-disk?
        let use_disk = file_size > max_memory_file_size
            || matches!(file_type, FileType::Archive | FileType::Jar);

        if use_disk {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let mut outfile = std::fs::File::create(&out_path)?;
            std::io::copy(&mut { entry_reader }, &mut outfile)?;

            if !guard.check_bytes(file_size, clean_name) {
                break;
            }

            if tx
                .send(ExtractedFile::OnDisk {
                    path: clean_name.to_string(),
                    temp_path: out_path,
                    file_type,
                })
                .is_err()
            {
                break;
            }
        } else {
            let mut data = Vec::with_capacity(file_size as usize);
            std::io::Read::read_to_end(&mut { entry_reader }, &mut data)?;

            if !guard.check_bytes(data.len() as u64, clean_name) {
                break;
            }

            // Re-detect file type with magic bytes
            let actual_type = if data.len() >= 4 {
                detect_file_type_from_magic(&data).unwrap_or(file_type)
            } else {
                file_type
            };

            if tx
                .send(ExtractedFile::InMemory {
                    path: clean_name.to_string(),
                    data,
                    file_type: actual_type,
                })
                .is_err()
            {
                break;
            }
        }
    }

    Ok(())
}

/// Summary of streaming archive analysis
#[allow(dead_code)] // Used by binary target
#[derive(Debug)]
pub(crate) struct ArchiveSummary {
    /// Any hostile archive reasons detected during extraction
    pub hostile_reasons: Vec<HostileArchiveReason>,
}

/// Detect file type from magic bytes (first 4+ bytes of data)
#[allow(dead_code)] // Used internally
fn detect_file_type_from_magic(data: &[u8]) -> Option<FileType> {
    if data.len() < 4 {
        return None;
    }

    // Check magic bytes
    // Note: 0xCAFEBABE is used by both Java class files and Mach-O FAT binaries
    // Java class files have a major/minor version in bytes 6-7 that is non-zero
    // Mach-O FAT has the number of architectures in bytes 4-7
    if data.len() >= 8 && data[0..4] == [0xca, 0xfe, 0xba, 0xbe] {
        // Check if this looks like Java (version bytes are reasonable)
        let major = u16::from_be_bytes([data[6], data[7]]);
        // Java class files have major versions like 45-65 (Java 1.1 to Java 21)
        // Mach-O FAT would have very small values (number of architectures, typically 1-4)
        if (45..=70).contains(&major) {
            return Some(FileType::JavaClass);
        } else {
            return Some(FileType::MachO);
        }
    }

    match &data[0..4] {
        // ELF
        [0x7f, b'E', b'L', b'F'] => Some(FileType::Elf),
        // Mach-O (32-bit, 64-bit, FAT)
        [0xfe, 0xed, 0xfa, 0xce]
        | [0xce, 0xfa, 0xed, 0xfe]
        | [0xfe, 0xed, 0xfa, 0xcf]
        | [0xcf, 0xfa, 0xed, 0xfe]
        | [0xbe, 0xba, 0xfe, 0xca] => Some(FileType::MachO),
        // PE
        [b'M', b'Z', ..] => Some(FileType::Pe),
        // ZIP/JAR
        [b'P', b'K', 0x03, 0x04] | [b'P', b'K', 0x05, 0x06] => {
            // Could be ZIP or JAR - check extension or contents
            Some(FileType::Archive)
        }
        // Gzip / XZ / Bzip2
        [0x1f, 0x8b, ..] | [0xfd, b'7', b'z', b'X'] | [b'B', b'Z', b'h', ..] => {
            Some(FileType::Archive)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_file_type_from_magic() {
        // ELF
        let elf_data = [0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        assert_eq!(detect_file_type_from_magic(&elf_data), Some(FileType::Elf));

        // MachO 32-bit
        let macho32_data = [0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0];
        assert_eq!(
            detect_file_type_from_magic(&macho32_data),
            Some(FileType::MachO)
        );

        // PE
        let pe_data = [b'M', b'Z', 0, 0, 0, 0, 0, 0];
        assert_eq!(detect_file_type_from_magic(&pe_data), Some(FileType::Pe));

        // ZIP
        let zip_data = [b'P', b'K', 0x03, 0x04, 0, 0, 0, 0];
        assert_eq!(
            detect_file_type_from_magic(&zip_data),
            Some(FileType::Archive)
        );

        // Unknown
        let unknown_data = [0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(detect_file_type_from_magic(&unknown_data), None);
    }

    #[test]
    fn test_skip_rpm_header() {
        // Create a minimal RPM header
        let mut header = Vec::new();
        // Magic: 0x8eade8
        header.extend_from_slice(&[0x8e, 0xad, 0xe8]);
        // Version
        header.push(0x01);
        // Reserved (4 bytes)
        header.extend_from_slice(&[0, 0, 0, 0]);
        // nindex (1 entry)
        header.extend_from_slice(&[0, 0, 0, 1]);
        // hsize (16 bytes of data)
        header.extend_from_slice(&[0, 0, 0, 16]);
        // Index entry (16 bytes)
        header.extend_from_slice(&[0u8; 16]);
        // Data (16 bytes)
        header.extend_from_slice(&[0u8; 16]);

        let mut cursor = std::io::Cursor::new(header);
        let result = skip_rpm_header(&mut cursor);
        assert!(result.is_ok());
        // Size = 16 (header struct) + 16 (1 index entry) + 16 (data) = 48
        assert_eq!(result.unwrap(), 48);
    }

    #[test]
    fn test_skip_rpm_header_invalid_magic() {
        let header = vec![0x00, 0x00, 0x00]; // Wrong magic
        let mut cursor = std::io::Cursor::new(header);
        let result = skip_rpm_header(&mut cursor);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid RPM header magic"));
    }

    type StreamingAnalyzerFn =
        fn(&ArchiveAnalyzer, &Path, fn(StreamingFileResult)) -> Result<ArchiveSummary>;

    #[test]
    fn test_deb_streaming_creates_analyzer() {
        // Just test that the analyzer can be created and has the streaming method
        let analyzer = ArchiveAnalyzer::new();
        // This is a compile-time check that the method exists
        let _: StreamingAnalyzerFn = ArchiveAnalyzer::analyze_deb_streaming;
        assert!(analyzer.max_depth > 0);
    }

    #[test]
    fn test_rpm_streaming_creates_analyzer() {
        // Just test that the analyzer can be created and has the streaming method
        let analyzer = ArchiveAnalyzer::new();
        // This is a compile-time check that the method exists
        let _: StreamingAnalyzerFn = ArchiveAnalyzer::analyze_rpm_streaming;
        assert!(analyzer.max_depth > 0);
    }
}
