//! Archive content analysis functions.
//!
//! This module contains the core analysis logic for different archive types:
//! - JAR/WAR/APK archives (Java bytecode optimized)
//! - Generic archives (all other formats)
//! - Individual extracted file analysis
//! - File type routing to appropriate analyzers
//!
//! # JAR Analysis Optimization
//!
//! JAR archives often contain thousands of .class files. Decompiling all of them
//! is prohibitively expensive, so we use a three-phase approach:
//! 1. YARA scan ALL classes in parallel (fast, just pattern matching)
//! 2. Full analysis on interesting classes (main class, YARA hits, samples)
//! 3. Analyze non-class files (scripts, configs, manifests)
//!
//! This balances thoroughness with performance.
//!
//! # Parallelism
//!
//! Archive member analysis runs on a dedicated rayon thread pool, separate from
//! the global pool used by top-level analysis. This prevents archive extraction
//! (which can contain hundreds of files) from starving non-archive requests.

use super::utils::{calculate_sha256, find_main_class, is_benign_java_path};
use super::ArchiveAnalyzer;
use crate::analyzers::{detect_file_type, Analyzer};
use crate::types::*;
use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{debug, trace};

// Archive analysis now runs on the global rayon pool instead of a separate pool.
// This halves the number of YARA scanner cache instances (each ~50-100MB per wasmtime VM)
// since scanners are thread-local and a separate pool doubled the thread count.
// The global pool's work-stealing scheduler naturally balances archive and non-archive work.

/// Total number of successful archive member analyses (cumulative, for logging)
static SUCCESSFUL_ANALYSES: AtomicU64 = AtomicU64::new(0);

/// Total number of failed archive member analyses
static FAILED_ANALYSES: AtomicU64 = AtomicU64::new(0);

/// Log archive analysis statistics.
#[allow(dead_code)]
pub(crate) fn log_archive_analysis_stats() {
    let successful = SUCCESSFUL_ANALYSES.load(Ordering::Relaxed);
    let failed = FAILED_ANALYSES.load(Ordering::Relaxed);
    tracing::info!(
        successful_analyses = successful,
        failed_analyses = failed,
        "Archive analysis statistics"
    );
}

impl ArchiveAnalyzer {
    /// Analyze JAR-like archives (JAR, WAR, EAR, APK, AAR) with optimized class file handling.
    ///
    /// JAR analysis is optimized with a three-phase approach:
    /// 1. YARA scan ALL .class files in parallel (fast)
    /// 2. Full analysis on interesting classes (main class, YARA-flagged, sample)
    /// 3. Analyze non-class files (scripts, configs, manifests)
    ///
    /// This avoids full decompilation of thousands of benign library classes while
    /// ensuring suspicious classes are thoroughly analyzed.
    ///
    /// # Arguments
    /// * `temp_dir` - Extracted archive directory
    /// * `report` - Mutable report to aggregate findings into
    /// * `start` - Analysis start time for duration tracking
    pub(super) fn analyze_jar_archive(
        &self,
        temp_dir: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
    ) -> Result<()> {
        // Find main class from MANIFEST.MF
        let main_class = find_main_class(temp_dir);
        if let Some(ref mc) = main_class {
            debug!("Main-Class: {}", mc);
        }

        // Collect all files
        let all_files: Vec<_> = walkdir::WalkDir::new(temp_dir)
            .min_depth(1)
            .max_depth(10)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_file())
            .collect();

        // Separate class files from non-class files
        let (class_files, other_files): (Vec<_>, Vec<_>) = all_files
            .into_iter()
            .partition(|e| e.path().extension().is_some_and(|ext| ext == "class"));

        let total_class_files = class_files.len();
        debug!("Found {} .class files", total_class_files);

        // Phase 1: Run YARA on ALL class files in parallel (fast)
        let yara_flagged_classes = Arc::new(Mutex::new(HashSet::new()));
        let yara_matches = Arc::new(Mutex::new(Vec::with_capacity(50)));

        if let Some(ref yara_engine) = self.yara_engine {
            let yara_start = std::time::Instant::now();
            class_files.par_iter().for_each(|entry| {
                if self.is_cancelled() {
                    return;
                }
                if let Ok(matches) = yara_engine.scan_file(entry.path()) {
                    if !matches.is_empty() {
                        // This class triggered YARA rules - mark for full analysis
                        if let Ok(mut flagged) = yara_flagged_classes.lock() {
                            flagged.insert(entry.path().to_path_buf());
                        }

                        // Record the YARA matches
                        if let Ok(mut all_matches) = yara_matches.lock() {
                            for yara_match in matches {
                                if !all_matches
                                    .iter()
                                    .any(|m: &YaraMatch| m.rule == yara_match.rule)
                                {
                                    all_matches.push(yara_match);
                                }
                            }
                        }
                    }
                }
            });
            debug!(
                "YARA scan completed in {:.2}s",
                yara_start.elapsed().as_secs_f64()
            );
        }

        let flagged_classes = Arc::try_unwrap(yara_flagged_classes)
            .map_err(|_| anyhow::anyhow!("YARA scan Arc unwrap failed"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("YARA flagged classes lock poisoned"))?;
        let collected_yara_matches = Arc::try_unwrap(yara_matches)
            .map_err(|_| anyhow::anyhow!("YARA matches Arc unwrap failed"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("YARA matches lock poisoned"))?;

        // Add collected YARA matches to report
        for ym in collected_yara_matches {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }

        debug!("{} classes flagged by YARA", flagged_classes.len());

        // Phase 2: Run full JavaClassAnalyzer only on interesting classes
        // - Main class
        // - YARA-flagged classes
        // - Non-benign classes (limited sample)
        let interesting_classes: Vec<_> = class_files
            .iter()
            .filter(|e| {
                let path = e.path();
                let path_str = path.to_string_lossy();

                // Always analyze main class
                if let Some(ref mc) = main_class {
                    let class_path = mc.replace('.', "/") + ".class";
                    if path_str.ends_with(&class_path) {
                        return true;
                    }
                }

                // Always analyze YARA-flagged classes
                if flagged_classes.contains(path) {
                    return true;
                }

                // Skip benign library packages
                if is_benign_java_path(path) {
                    return false;
                }

                // For non-flagged, non-benign classes, just take a sample
                false
            })
            .collect();

        // Also include a small sample of non-benign, non-flagged classes
        let sample_classes: Vec<_> = class_files
            .iter()
            .filter(|e| !is_benign_java_path(e.path()) && !flagged_classes.contains(e.path()))
            .take(20) // Limit to 20 non-flagged classes
            .collect();

        let classes_to_analyze: Vec<_> = interesting_classes
            .into_iter()
            .chain(sample_classes)
            .collect();

        debug!("Full analysis on {} classes", classes_to_analyze.len());

        // Run full analysis on selected classes
        let files_analyzed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let total_capabilities = Arc::new(Mutex::new(HashSet::new()));
        let total_traits = Arc::new(Mutex::new(HashSet::new()));
        // Pre-allocate with conservative estimates; findings are deduplicated and only
        // URL/IP/Base64 strings are collected, so actual counts are much smaller than file count.
        let expected_count = classes_to_analyze.len();
        let collected_traits = Arc::new(Mutex::new(Vec::<Finding>::with_capacity(
            expected_count.min(500),
        )));
        let collected_yara = Arc::new(Mutex::new(Vec::<YaraMatch>::with_capacity(50)));
        let collected_strings = Arc::new(Mutex::new(Vec::<StringInfo>::with_capacity(
            (expected_count * 2).min(200),
        )));
        let collected_archive_entries = Arc::new(Mutex::new(Vec::<ArchiveEntry>::with_capacity(
            expected_count,
        )));
        let collected_files = Arc::new(Mutex::new(Vec::<FileAnalysis>::with_capacity(
            expected_count,
        )));

        classes_to_analyze.par_iter().for_each(|entry| {
            if self.is_cancelled() {
                return;
            }
            let relative_path = entry
                .path()
                .strip_prefix(temp_dir)
                .unwrap_or(entry.path())
                .display()
                .to_string();
            let entry_path = self.format_entry_path(&relative_path);
            let archive_location = self.format_evidence_location(&relative_path);

            // Collect archive entry metadata
            if let Ok(file_data) = std::fs::read(entry.path()) {
                let entry_metadata = ArchiveEntry {
                    path: entry_path.clone(),
                    file_type: detect_file_type(entry.path())
                        .map(|ft| ft.report_file_type())
                        .unwrap_or_else(|_| "unknown".to_string()),
                    sha256: calculate_sha256(&file_data),
                    size_bytes: file_data.len() as u64,
                };
                if let Ok(mut entries) = collected_archive_entries.lock() {
                    entries.push(entry_metadata);
                }
            }

            match self.analyze_extracted_file(entry.path()) {
                Err(e) => {
                    debug!("Failed to analyze archive member {}: {}", entry_path, e);
                }
                Ok(file_report) => {
                    files_analyzed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    trace!(
                        "Analyzed archive member {}: {} findings",
                        entry_path,
                        file_report.findings.len()
                    );

                    let (
                        Ok(mut caps),
                        Ok(mut traits),
                        Ok(mut all_traits),
                        Ok(mut all_yara),
                        Ok(mut all_strings),
                        Ok(mut all_archive_entries),
                        Ok(mut all_files),
                    ) = (
                        total_capabilities.lock(),
                        total_traits.lock(),
                        collected_traits.lock(),
                        collected_yara.lock(),
                        collected_strings.lock(),
                        collected_archive_entries.lock(),
                        collected_files.lock(),
                    )
                    else {
                        return; // Skip this file if any lock is poisoned
                    };

                    // Aggregate findings
                    for f in &file_report.findings {
                        traits.insert(f.id.clone());
                        caps.insert(f.id.clone());
                        if !all_traits.iter().any(|existing| existing.id == f.id) {
                            let mut new_finding = f.clone();
                            for evidence in &mut new_finding.evidence {
                                // Prefix location with archive path
                                // - If no location: set to archive path
                                // - If location starts with "archive:": already from nested, leave it
                                // - Otherwise: prefix with archive path (e.g., "line:3" -> "archive:file.sh:line:3")
                                match &evidence.location {
                                    None => {
                                        evidence.location = Some(archive_location.clone());
                                    }
                                    Some(loc) if !loc.starts_with("archive:") => {
                                        evidence.location =
                                            Some(format!("{}:{}", archive_location, loc));
                                    }
                                    _ => {} // Already has archive: prefix from nested analysis
                                }
                            }
                            all_traits.push(new_finding);
                        }
                    }

                    // Aggregate YARA matches
                    for yara_match in &file_report.yara_matches {
                        if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                            all_yara.push(yara_match.clone());
                        }
                    }

                    // Aggregate interesting strings
                    for string in &file_report.strings {
                        if matches!(
                            string.string_type,
                            Some(StringType::Url | StringType::IP | StringType::Base64)
                        ) {
                            all_strings.push(string.clone());
                        }
                    }

                    // Convert to FileAnalysis, consuming the report to avoid cloning
                    let (mut file_entry, nested_files, archive_contents) =
                        file_report.into_file_analysis(0);
                    file_entry.path = entry_path.clone();
                    file_entry.depth = 1; // Direct child of archive
                    file_entry.compute_summary();
                    all_files.push(file_entry);

                    // Merge archive_contents from nested archives
                    for nested_entry in archive_contents {
                        all_archive_entries.push(nested_entry);
                    }

                    // Handle nested archives - add their files with updated paths
                    for mut nested_file in nested_files {
                        if !nested_file.path.contains("!!") {
                            nested_file.path = encode_archive_path(&entry_path, &nested_file.path);
                        }
                        nested_file.depth += 1;
                        all_files.push(nested_file);
                    }
                }
            }
        });

        // Phase 3: Analyze non-class files (scripts, configs, etc.)
        let non_class_files: Vec<_> = other_files
            .into_iter()
            .filter(|e| !is_benign_java_path(e.path()))
            .filter(|e| {
                // Only analyze potentially interesting files
                let path_str = e.path().to_string_lossy().to_lowercase();
                !path_str.contains("meta-inf/")
                    || path_str.ends_with("manifest.mf")
                    || path_str.ends_with(".xml")
            })
            .take(100)
            .collect();

        non_class_files.par_iter().for_each(|entry| {
            if self.is_cancelled() {
                return;
            }
            let relative_path = entry
                .path()
                .strip_prefix(temp_dir)
                .unwrap_or(entry.path())
                .display()
                .to_string();
            let entry_path = self.format_entry_path(&relative_path);
            let archive_location = self.format_evidence_location(&relative_path);

            // Collect archive entry metadata
            if let Ok(file_data) = std::fs::read(entry.path()) {
                let entry_metadata = ArchiveEntry {
                    path: entry_path.clone(),
                    file_type: detect_file_type(entry.path())
                        .map(|ft| ft.report_file_type())
                        .unwrap_or_else(|_| "unknown".to_string()),
                    sha256: calculate_sha256(&file_data),
                    size_bytes: file_data.len() as u64,
                };
                if let Ok(mut entries) = collected_archive_entries.lock() {
                    entries.push(entry_metadata);
                }
            }

            // Run YARA on non-class files
            if let Some(ref yara_engine) = self.yara_engine {
                if let Ok(matches) = yara_engine.scan_file(entry.path()) {
                    if let Ok(mut all_yara) = collected_yara.lock() {
                        for yara_match in matches {
                            if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                                all_yara.push(yara_match);
                            }
                        }
                    }
                }
            }

            // Run file-type-specific analysis
            match self.analyze_extracted_file(entry.path()) {
                Err(e) => {
                    debug!("Failed to analyze archive member {}: {}", entry_path, e);
                }
                Ok(file_report) => {
                    files_analyzed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    trace!(
                        "Analyzed archive member {}: {} findings",
                        entry_path,
                        file_report.findings.len()
                    );

                    let (
                        Ok(mut caps),
                        Ok(mut traits),
                        Ok(mut all_traits),
                        Ok(mut all_yara),
                        Ok(mut all_strings),
                        Ok(mut all_archive_entries),
                        Ok(mut all_files),
                    ) = (
                        total_capabilities.lock(),
                        total_traits.lock(),
                        collected_traits.lock(),
                        collected_yara.lock(),
                        collected_strings.lock(),
                        collected_archive_entries.lock(),
                        collected_files.lock(),
                    )
                    else {
                        return; // Skip this file if any lock is poisoned
                    };

                    // Aggregate findings
                    for f in &file_report.findings {
                        traits.insert(f.id.clone());
                        caps.insert(f.id.clone());
                        if !all_traits.iter().any(|existing| existing.id == f.id) {
                            // LIMIT: Cap at 10,000 findings per archive analysis phase
                            if all_traits.len() < 10_000 {
                                let mut new_finding = f.clone();
                                for evidence in &mut new_finding.evidence {
                                    // Prefix location with archive path
                                    match &evidence.location {
                                        None => {
                                            evidence.location = Some(archive_location.clone());
                                        }
                                        Some(loc) if !loc.starts_with("archive:") => {
                                            evidence.location =
                                                Some(format!("{}:{}", archive_location, loc));
                                        }
                                        _ => {} // Already has archive: prefix from nested analysis
                                    }
                                }
                                all_traits.push(new_finding);
                            }
                        }
                    }

                    // Aggregate YARA matches
                    for yara_match in &file_report.yara_matches {
                        if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                            // LIMIT: Cap YARA matches at 1,000
                            if all_yara.len() < 1_000 {
                                all_yara.push(yara_match.clone());
                            }
                        }
                    }

                    // Aggregate interesting strings
                    for string in &file_report.strings {
                        if matches!(
                            string.string_type,
                            Some(StringType::Url | StringType::IP | StringType::Base64)
                        ) {
                            // LIMIT: Cap aggregated strings at 10,000
                            if all_strings.len() < 10_000 {
                                all_strings.push(string.clone());
                            }
                        }
                    }

                    // Convert to FileAnalysis, consuming the report to avoid cloning
                    let (mut file_entry, nested_files, archive_contents) =
                        file_report.into_file_analysis(0);
                    file_entry.path = entry_path.clone();
                    file_entry.depth = 1;
                    file_entry.compute_summary();

                    all_files.push(file_entry);

                    // Merge archive_contents from nested archives
                    for nested_entry in archive_contents {
                        all_archive_entries.push(nested_entry);
                    }

                    // Handle nested archives
                    for mut nested_file in nested_files {
                        if !nested_file.path.contains("!!") {
                            nested_file.path = encode_archive_path(&entry_path, &nested_file.path);
                        }
                        nested_file.depth += 1;
                        all_files.push(nested_file);
                    }
                }
            }
        });

        // Merge JAR collected results into the report
        let total_capabilities = Arc::try_unwrap(total_capabilities)
            .map_err(|_| anyhow::anyhow!("total_capabilities Arc unwrap failed"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("total_capabilities lock poisoned"))?;
        let total_traits = Arc::try_unwrap(total_traits)
            .map_err(|_| anyhow::anyhow!("total_traits Arc unwrap failed"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("total_traits lock poisoned"))?;
        let files_analyzed = files_analyzed.load(std::sync::atomic::Ordering::Relaxed);

        for t in Arc::try_unwrap(collected_traits)
            .map_err(|_| anyhow::anyhow!("collected_traits Arc unwrap failed"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("collected_traits lock poisoned"))?
        {
            if !report.findings.iter().any(|existing| existing.id == t.id) {
                report.findings.push(t);
            }
        }
        for ym in Arc::try_unwrap(collected_yara)
            .map_err(|_| anyhow::anyhow!("collected_yara Arc unwrap failed"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("collected_yara lock poisoned"))?
        {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }
        report.strings.extend(
            Arc::try_unwrap(collected_strings)
                .map_err(|_| anyhow::anyhow!("collected_strings Arc unwrap failed"))?
                .into_inner()
                .map_err(|_| anyhow::anyhow!("collected_strings lock poisoned"))?,
        );
        report.archive_contents.extend(
            Arc::try_unwrap(collected_archive_entries)
                .map_err(|_| anyhow::anyhow!("collected_archive_entries Arc unwrap failed"))?
                .into_inner()
                .map_err(|_| anyhow::anyhow!("collected_archive_entries lock poisoned"))?,
        );
        report.files.extend(
            Arc::try_unwrap(collected_files)
                .map_err(|_| anyhow::anyhow!("collected_files Arc unwrap failed"))?
                .into_inner()
                .map_err(|_| anyhow::anyhow!("collected_files lock poisoned"))?,
        );

        // Add metadata about archive contents
        report.metadata.errors.push(format!(
            "JAR archive: {} total classes, {} YARA-flagged, {} fully analyzed, {} traits and {} capabilities detected",
            total_class_files,
            flagged_classes.len(),
            files_analyzed,
            total_traits.len(),
            total_capabilities.len()
        ));

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec![
            "archive_analyzer".to_string(),
            "yara".to_string(),
            "java_class_analyzer".to_string(),
        ];

        Ok(())
    }

    /// Analyze generic archives (non-JAR formats).
    ///
    /// Performs comprehensive analysis of all extracted files including:
    /// - YARA scanning for known malicious patterns
    /// - File-type-specific analysis (scripts, binaries, configs)
    /// - Archive entry metadata collection
    /// - Nested archive handling
    ///
    /// Files are analyzed in parallel for performance, with progress tracking
    /// for large archives.
    ///
    /// # Arguments
    /// * `temp_dir` - Extracted archive directory
    /// * `report` - Mutable report to aggregate findings into
    /// * `start` - Analysis start time for duration tracking
    pub(super) fn analyze_generic_archive(
        &self,
        temp_dir: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
    ) -> Result<()> {
        debug!(
            "Analyzing generic archive, scanning temp dir: {:?}",
            temp_dir
        );

        // Collect all files to analyze
        let all_entries: Vec<_> = walkdir::WalkDir::new(temp_dir)
            .min_depth(1)
            .max_depth(10)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .collect();

        trace!("Found {} total entries in archive", all_entries.len());

        let files: Vec<_> = all_entries
            .into_iter()
            .filter(|e| {
                let is_file = e.file_type().is_file();
                if !is_file {
                    trace!("Skipping directory: {:?}", e.path());
                }
                is_file
            })
            .take(100_000)
            .collect();

        let total_files = files.len();
        debug!("Found {} files to analyze", total_files);

        // Create thread-safe containers for aggregated results
        let files_processed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let files_analyzed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let total_capabilities = Arc::new(Mutex::new(HashSet::new()));
        let total_traits = Arc::new(Mutex::new(HashSet::new()));
        // Pre-allocate with conservative estimates; findings are deduplicated and only
        // URL/IP/Base64 strings are collected, so actual counts are much smaller than file count.
        let collected_traits = Arc::new(Mutex::new(Vec::<Finding>::with_capacity(
            total_files.min(500),
        )));
        let collected_yara = Arc::new(Mutex::new(Vec::<YaraMatch>::with_capacity(100)));
        let collected_strings = Arc::new(Mutex::new(Vec::<StringInfo>::with_capacity(
            (total_files * 2).min(200),
        )));
        let collected_archive_entries =
            Arc::new(Mutex::new(Vec::<ArchiveEntry>::with_capacity(total_files)));
        let collected_files = Arc::new(Mutex::new(Vec::<FileAnalysis>::with_capacity(total_files)));
        let last_progress = Arc::new(Mutex::new(std::time::Instant::now()));

        // Analyze files in parallel
        files.par_iter().for_each(|entry| {
            if self.is_cancelled() {
                return;
            }
            // Track progress
            let processed = files_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if let Ok(mut last) = last_progress.try_lock() {
                if last.elapsed() > std::time::Duration::from_secs(1) {
                    let analyzed = files_analyzed.load(std::sync::atomic::Ordering::Relaxed);
                    debug!(
                        "Archive progress: {}/{} files processed, {} analyzed",
                        processed, total_files, analyzed
                    );
                    *last = std::time::Instant::now();
                }
            }

            let relative_path = entry
                .path()
                .strip_prefix(temp_dir)
                .unwrap_or(entry.path())
                .display()
                .to_string();
            let entry_path = self.format_entry_path(&relative_path);
            let archive_location = self.format_evidence_location(&relative_path);

            // Collect archive entry metadata
            if let Ok(file_data) = std::fs::read(entry.path()) {
                let entry_metadata = ArchiveEntry {
                    path: entry_path.clone(),
                    file_type: detect_file_type(entry.path())
                        .map(|ft| ft.report_file_type())
                        .unwrap_or_else(|_| "unknown".to_string()),
                    sha256: calculate_sha256(&file_data),
                    size_bytes: file_data.len() as u64,
                };
                if let Ok(mut entries) = collected_archive_entries.lock() {
                    entries.push(entry_metadata);
                }
            }

            // Run YARA scan on extracted file if engine is available
            if let Some(ref yara_engine) = self.yara_engine {
                if let Ok(matches) = yara_engine.scan_file(entry.path()) {
                    if let Ok(mut all_yara) = collected_yara.lock() {
                        for yara_match in matches {
                            if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                                all_yara.push(yara_match);
                            }
                        }
                    }
                }
            }

            match self.analyze_extracted_file(entry.path()) {
                Err(e) => {
                    debug!("Failed to analyze archive member {}: {}", entry_path, e);
                }
                Ok(file_report) => {
                    files_analyzed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    trace!(
                        "Analyzed archive member {}: {} findings",
                        entry_path,
                        file_report.findings.len()
                    );

                    let Ok(mut caps) = total_capabilities.lock() else {
                        return;
                    };
                    let Ok(mut traits) = total_traits.lock() else {
                        return;
                    };
                    let Ok(mut all_traits) = collected_traits.lock() else {
                        return;
                    };
                    let Ok(mut all_yara) = collected_yara.lock() else {
                        return;
                    };
                    let Ok(mut all_strings) = collected_strings.lock() else {
                        return;
                    };
                    let Ok(mut all_archive_entries) = collected_archive_entries.lock() else {
                        return;
                    };
                    let Ok(mut all_files) = collected_files.lock() else {
                        return;
                    };

                    // Convert to FileAnalysis, consuming the report to avoid cloning
                    let (mut file_entry, nested_files, archive_contents) =
                        file_report.into_file_analysis(0);
                    file_entry.path = entry_path.clone();
                    file_entry.depth = 1; // Direct child of archive
                    file_entry.compute_summary();

                    // Extract file to disk if configured (mirrors streaming.rs behavior)
                    if let Some(ref config) = self.sample_extraction {
                        if let Ok(file_data) = std::fs::read(entry.path()) {
                            let extract_relative_path = match &self.archive_path_prefix {
                                Some(prefix) => {
                                    format!("{}/{}", prefix.replace('!', "/"), relative_path)
                                }
                                None => relative_path.to_string(),
                            };
                            if let Some(extracted_path) = config.extract(
                                &file_entry.sha256,
                                &extract_relative_path,
                                &file_data,
                            ) {
                                file_entry.extracted_path =
                                    Some(extracted_path.display().to_string());
                            }
                        }
                    }

                    // Aggregate findings from the converted FileAnalysis
                    for f in &file_entry.findings {
                        traits.insert(f.id.clone());
                        caps.insert(f.id.clone());
                        if !all_traits.iter().any(|existing| existing.id == f.id) {
                            // LIMIT: Cap findings at 10,000
                            if all_traits.len() < 10_000 {
                                let mut new_finding = f.clone();
                                for evidence in &mut new_finding.evidence {
                                    // Prefix location with archive path
                                    match &evidence.location {
                                        None => {
                                            evidence.location = Some(archive_location.clone());
                                        }
                                        Some(loc) if !loc.starts_with("archive:") => {
                                            evidence.location =
                                                Some(format!("{}:{}", archive_location, loc));
                                        }
                                        _ => {} // Already has archive: prefix from nested analysis
                                    }
                                }
                                all_traits.push(new_finding);
                            }
                        }
                    }

                    // Aggregate YARA matches
                    for yara_match in &file_entry.yara_matches {
                        if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                            // LIMIT: Cap YARA matches at 1,000
                            if all_yara.len() < 1_000 {
                                all_yara.push(yara_match.clone());
                            }
                        }
                    }

                    // Aggregate interesting strings
                    for string in &file_entry.strings {
                        if matches!(
                            string.string_type,
                            Some(StringType::Url | StringType::IP | StringType::Base64)
                        ) {
                            // LIMIT: Cap aggregated strings at 10,000
                            if all_strings.len() < 10_000 {
                                all_strings.push(string.clone());
                            }
                        }
                    }

                    all_files.push(file_entry.clone());

                    // Merge archive_contents from nested archives
                    for nested_entry in archive_contents {
                        all_archive_entries.push(nested_entry);
                    }

                    // Handle nested archives - add their files with updated paths
                    for mut nested_file in nested_files {
                        // Update path to include our archive prefix
                        if !nested_file.path.contains("!!") {
                            nested_file.path = encode_archive_path(&entry_path, &nested_file.path);
                        }
                        nested_file.depth += 1; // Increment depth for nesting
                        all_files.push(nested_file);
                    }
                }
            }
        });

        // Sort files by highest severity first, then truncate to limit
        {
            let mut all_files = collected_files
                .lock()
                .map_err(|_| anyhow::anyhow!("collected_files lock poisoned"))?;
            all_files.sort_by(|a, b| {
                let max_crit =
                    |f: &FileAnalysis| f.findings.iter().map(|f| f.crit).max().unwrap_or_default();
                max_crit(b).cmp(&max_crit(a))
            });
            all_files.truncate(100_000);
        }

        // Merge collected results into the report
        let total_capabilities = Arc::try_unwrap(total_capabilities)
            .map_err(|_| anyhow::anyhow!("total_capabilities Arc unwrap failed"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("total_capabilities lock poisoned"))?;
        let total_traits = Arc::try_unwrap(total_traits)
            .map_err(|_| anyhow::anyhow!("total_traits Arc unwrap failed"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("total_traits lock poisoned"))?;
        let files_analyzed = files_analyzed.load(std::sync::atomic::Ordering::Relaxed);

        for t in Arc::try_unwrap(collected_traits)
            .map_err(|_| anyhow::anyhow!("collected_traits Arc unwrap failed"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("collected_traits lock poisoned"))?
        {
            if !report.findings.iter().any(|existing| existing.id == t.id) {
                report.findings.push(t);
            }
        }
        for ym in Arc::try_unwrap(collected_yara)
            .map_err(|_| anyhow::anyhow!("collected_yara Arc unwrap failed"))?
            .into_inner()
            .map_err(|_| anyhow::anyhow!("collected_yara lock poisoned"))?
        {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }
        report.strings.extend(
            Arc::try_unwrap(collected_strings)
                .map_err(|_| anyhow::anyhow!("collected_strings Arc unwrap failed"))?
                .into_inner()
                .map_err(|_| anyhow::anyhow!("collected_strings lock poisoned"))?,
        );
        report.archive_contents.extend(
            Arc::try_unwrap(collected_archive_entries)
                .map_err(|_| anyhow::anyhow!("collected_archive_entries Arc unwrap failed"))?
                .into_inner()
                .map_err(|_| anyhow::anyhow!("collected_archive_entries lock poisoned"))?,
        );
        report.files.extend(
            Arc::try_unwrap(collected_files)
                .map_err(|_| anyhow::anyhow!("collected_files Arc unwrap failed"))?
                .into_inner()
                .map_err(|_| anyhow::anyhow!("collected_files lock poisoned"))?,
        );

        // Add metadata about archive contents
        report.metadata.errors.push(format!(
            "Archive contains {} files analyzed, {} traits and {} capabilities detected",
            files_analyzed,
            total_traits.len(),
            total_capabilities.len()
        ));

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["archive_analyzer".to_string(), "walkdir".to_string()];

        Ok(())
    }

    /// Route an extracted file to the appropriate analyzer based on file type.
    ///
    /// Detects the file type and delegates to specialized analyzers:
    /// - MachO, ELF, PE: Binary analyzers
    /// - Shell, Python, JavaScript, etc.: Script analyzers
    /// - JavaClass: Bytecode analyzer
    /// - Archive: Recursive archive analysis (with depth limit)
    ///
    /// Passes along capability mapper and YARA engine to child analyzers.
    ///
    /// # Arguments
    /// * `file_path` - Path to the extracted file
    ///
    /// # Returns
    /// * `Ok(AnalysisReport)` - Analysis report from appropriate analyzer
    /// * `Err` - If file type unsupported or analysis fails
    pub(super) fn analyze_extracted_file(&self, file_path: &Path) -> Result<AnalysisReport> {
        if self.is_cancelled() {
            anyhow::bail!("Analysis cancelled");
        }

        // Detect file type
        let file_type = detect_file_type(file_path)?;

        // Handle nested archives specially (depth limits, prefix propagation)
        if file_type == crate::analyzers::FileType::Archive {
            if self.current_depth + 1 >= self.max_depth {
                return Err(anyhow::anyhow!(
                    "Nested archive at max depth ({})",
                    self.max_depth
                ));
            }

            // Build the prefix for nested paths
            let file_name = file_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("nested");
            let nested_prefix = match &self.archive_path_prefix {
                Some(prefix) => format!("{}!{}", prefix, file_name),
                None => file_name.to_string(),
            };

            // Create nested analyzer with incremented depth and path prefix
            let mut nested = ArchiveAnalyzer::new()
                .with_depth(self.current_depth + 1)
                .with_archive_prefix(nested_prefix);

            // Propagate configuration
            if let Some(ref mapper) = self.capability_mapper {
                nested = nested.with_capability_mapper_arc(mapper.clone());
            }
            if let Some(ref engine) = self.yara_engine {
                nested = nested.with_yara_arc(engine.clone());
            }
            if !self.zip_passwords.is_empty() {
                nested = nested.with_zip_passwords_arc(self.zip_passwords.clone());
            }
            if let Some(ref flag) = self.cancelled {
                nested = nested.with_cancellation(flag.clone());
            }

            // Spawn on a dedicated thread to guarantee a fresh stack —
            // recursive archive analysis can exhaust the rayon worker stack.
            let path = file_path.to_path_buf();
            let result = std::thread::Builder::new()
                .stack_size(8 * 1024 * 1024)
                .spawn(move || nested.analyze(&path))
                .map_err(|e| anyhow::anyhow!("Failed to spawn nested archive thread: {e}"))?
                .join()
                .map_err(|_| anyhow::anyhow!("Nested archive thread panicked"))?;
            return result;
        }

        // Use the centralized factory for all other file types
        let result = if let Some(analyzer) =
            crate::analyzers::analyzer_for_file_type_arc(&file_type, self.capability_mapper.clone())
        {
            analyzer.analyze(file_path)
        } else {
            Err(anyhow::anyhow!("Unsupported file type: {:?}", file_type))
        };

        match &result {
            Ok(_) => {
                SUCCESSFUL_ANALYSES.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                FAILED_ANALYSES.fetch_add(1, Ordering::Relaxed);
            }
        }
        result
    }
}
