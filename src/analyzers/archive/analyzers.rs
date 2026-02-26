//! Archive content analysis functions.
//!
//! This module contains the core analysis logic for different archive types:
//! - JAR/WAR/APK archives (Java bytecode optimized)
//! - Generic archives (all other formats)
//! - Individual extracted file analysis with timeout protection
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
//! # Memory Safety
//!
//! Analysis threads are tracked to prevent unbounded thread accumulation.
//! When threads timeout, they are tracked as "orphaned" and the system
//! blocks new analysis when too many orphans exist.

use super::utils::{calculate_sha256, find_main_class, is_benign_java_path};
use super::ArchiveAnalyzer;
use crate::analyzers::{detect_file_type, Analyzer};
use crate::types::*;
use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

const MAX_FILE_ANALYSIS_TIME_SECS: u64 = 10;

/// Maximum number of orphaned (timed-out) threads allowed before blocking new analysis.
/// Each orphaned thread holds ~8MB stack + analysis resources.
/// At 50 orphans = ~400MB+ of leaked memory, we start blocking.
const MAX_ORPHANED_THREADS: usize = 50;

/// Global tracking of orphaned analysis threads for memory leak prevention.
/// These are threads that timed out but are still running in the background.
static ORPHANED_THREAD_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Total number of threads that have been orphaned (cumulative, for logging)
static TOTAL_ORPHANED_THREADS: AtomicU64 = AtomicU64::new(0);

/// Total number of orphaned threads that have completed and been cleaned up
static ORPHANED_THREADS_COMPLETED: AtomicU64 = AtomicU64::new(0);

/// Total number of successful (non-timeout) analyses
static SUCCESSFUL_ANALYSES: AtomicU64 = AtomicU64::new(0);

/// Total number of timed-out analyses
static TIMEOUT_ANALYSES: AtomicU64 = AtomicU64::new(0);

/// Storage for orphaned thread handles to allow eventual cleanup
static ORPHANED_HANDLES: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());

/// Get current orphaned thread statistics for debugging.
#[allow(dead_code)]
pub(crate) fn orphaned_thread_stats() -> (usize, u64, u64, u64, u64) {
    (
        ORPHANED_THREAD_COUNT.load(Ordering::Relaxed),
        TOTAL_ORPHANED_THREADS.load(Ordering::Relaxed),
        ORPHANED_THREADS_COMPLETED.load(Ordering::Relaxed),
        SUCCESSFUL_ANALYSES.load(Ordering::Relaxed),
        TIMEOUT_ANALYSES.load(Ordering::Relaxed),
    )
}

/// Log orphaned thread statistics for post-mortem analysis.
pub(crate) fn log_orphaned_thread_stats() {
    let (current, total, completed, successful, timeouts) = orphaned_thread_stats();
    tracing::info!(
        current_orphaned = current,
        total_orphaned = total,
        orphans_completed = completed,
        successful_analyses = successful,
        timeout_analyses = timeouts,
        timeout_rate_pct = if successful + timeouts > 0 {
            (timeouts as f64 / (successful + timeouts) as f64) * 100.0
        } else {
            0.0
        },
        max_allowed_orphans = MAX_ORPHANED_THREADS,
        "Archive analysis thread statistics"
    );
}

/// Try to clean up any orphaned threads that have finished.
/// Call periodically to reclaim resources from threads that eventually completed.
pub(crate) fn cleanup_finished_orphans() {
    let mut handles = match ORPHANED_HANDLES.lock() {
        Ok(h) => h,
        Err(poisoned) => poisoned.into_inner(),
    };

    let initial_count = handles.len();
    handles.retain(|handle| !handle.is_finished());
    let removed = initial_count - handles.len();

    if removed > 0 {
        ORPHANED_THREAD_COUNT.fetch_sub(removed, Ordering::Relaxed);
        ORPHANED_THREADS_COMPLETED.fetch_add(removed as u64, Ordering::Relaxed);
        tracing::debug!(
            cleaned_up = removed,
            remaining_orphans = handles.len(),
            "Cleaned up finished orphaned analysis threads"
        );
    }
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
            eprintln!("  Main-Class: {}", mc);
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
        eprintln!("  Found {} .class files", total_class_files);

        // Phase 1: Run YARA on ALL class files in parallel (fast)
        let yara_flagged_classes = Arc::new(Mutex::new(HashSet::new()));
        let yara_matches = Arc::new(Mutex::new(Vec::with_capacity(50)));

        if let Some(ref yara_engine) = self.yara_engine {
            let yara_start = std::time::Instant::now();
            class_files.par_iter().for_each(|entry| {
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
            eprintln!(
                "  YARA scan completed in {:.2}s",
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

        eprintln!("  {} classes flagged by YARA", flagged_classes.len());

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

        eprintln!("  Full analysis on {} classes", classes_to_analyze.len());

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
                        .map(|ft| format!("{:?}", ft).to_lowercase())
                        .unwrap_or_else(|_| "unknown".to_string()),
                    sha256: calculate_sha256(&file_data),
                    size_bytes: file_data.len() as u64,
                };
                if let Ok(mut entries) = collected_archive_entries.lock() {
                    entries.push(entry_metadata);
                }
            }

            if let Ok(file_report) = self.analyze_extracted_file_with_timeout(entry.path()) {
                files_analyzed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

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
                        StringType::Url | StringType::IP | StringType::Base64
                    ) {
                        all_strings.push(string.clone());
                    }
                }

                // Convert to FileAnalysis, consuming the report to avoid cloning
                let (mut file_entry, nested_files, archive_contents) =
                    file_report.into_file_analysis(0, true);
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
                        .map(|ft| format!("{:?}", ft).to_lowercase())
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
            if let Ok(file_report) = self.analyze_extracted_file_with_timeout(entry.path()) {
                files_analyzed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

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
                        StringType::Url | StringType::IP | StringType::Base64
                    ) {
                        all_strings.push(string.clone());
                    }
                }

                // Convert to FileAnalysis, consuming the report to avoid cloning
                let (mut file_entry, nested_files, archive_contents) =
                    file_report.into_file_analysis(0, true);
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
        });

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
        use tracing::{debug, trace};

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
            .take(500)
            .collect();

        let total_files = files.len();
        debug!("Found {} files to analyze", total_files);
        eprintln!("  Analyzing {} files", total_files);

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
            // Track progress
            let processed = files_processed.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if let Ok(mut last) = last_progress.try_lock() {
                if last.elapsed() > std::time::Duration::from_secs(1) {
                    let analyzed = files_analyzed.load(std::sync::atomic::Ordering::Relaxed);
                    eprintln!(
                        "  Progress: {}/{} files processed, {} analyzed",
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
                        .map(|ft| format!("{:?}", ft).to_lowercase())
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

            if let Ok(file_report) = self.analyze_extracted_file_with_timeout(entry.path()) {
                files_analyzed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

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
                    file_report.into_file_analysis(0, true);
                file_entry.path = entry_path.clone();
                file_entry.depth = 1; // Direct child of archive
                file_entry.compute_summary();

                // Aggregate findings from the converted FileAnalysis
                for f in &file_entry.findings {
                    traits.insert(f.id.clone());
                    caps.insert(f.id.clone());
                    if !all_traits.iter().any(|existing| existing.id == f.id) {
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

                // Aggregate YARA matches
                for yara_match in &file_entry.yara_matches {
                    if !all_yara.iter().any(|m| m.rule == yara_match.rule) {
                        all_yara.push(yara_match.clone());
                    }
                }

                // Aggregate interesting strings
                for string in &file_entry.strings {
                    if matches!(
                        string.string_type,
                        StringType::Url | StringType::IP | StringType::Base64
                    ) {
                        all_strings.push(string.clone());
                    }
                }

                all_files.push(file_entry);

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
        });

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

    /// Analyze an extracted file with a timeout to prevent analysis hangs.
    ///
    /// Some files (especially obfuscated or malformed ones) can cause analysis
    /// to hang indefinitely. This wrapper spawns analysis in a thread with a
    /// 10-second timeout. If timeout occurs, returns a report with a timeout
    /// finding instead of hanging forever.
    ///
    /// # Memory Safety
    ///
    /// Timed-out threads are tracked as "orphaned" to prevent unbounded memory growth.
    /// When too many orphaned threads exist, new analysis is blocked until some complete.
    /// This prevents the OOM scenarios seen in long-running archive analysis.
    ///
    /// # Arguments
    /// * `file_path` - Path to the extracted file
    ///
    /// # Returns
    /// * `Ok(AnalysisReport)` - Normal analysis or timeout report
    /// * `Err` - If thread crashes or too many orphaned threads
    pub(super) fn analyze_extracted_file_with_timeout(
        &self,
        file_path: &Path,
    ) -> Result<AnalysisReport> {
        use std::sync::mpsc;
        use std::time::Duration;

        let file_path_str = file_path.display().to_string();

        // Periodically clean up finished orphaned threads
        cleanup_finished_orphans();

        // Check if we have too many orphaned threads - if so, block to prevent OOM
        let current_orphans = ORPHANED_THREAD_COUNT.load(Ordering::Relaxed);
        if current_orphans >= MAX_ORPHANED_THREADS {
            tracing::warn!(
                orphaned_threads = current_orphans,
                max_allowed = MAX_ORPHANED_THREADS,
                file_path = %file_path_str,
                "Too many orphaned analysis threads - blocking new analysis to prevent OOM"
            );

            // Wait for some orphans to complete before proceeding
            let wait_start = std::time::Instant::now();
            let max_wait = Duration::from_secs(30);
            while ORPHANED_THREAD_COUNT.load(Ordering::Relaxed) >= MAX_ORPHANED_THREADS {
                cleanup_finished_orphans();
                if wait_start.elapsed() > max_wait {
                    tracing::error!(
                        orphaned_threads = ORPHANED_THREAD_COUNT.load(Ordering::Relaxed),
                        waited_secs = max_wait.as_secs(),
                        file_path = %file_path_str,
                        "Timeout waiting for orphaned threads to complete - skipping file"
                    );
                    return Err(anyhow::anyhow!(
                        "Too many orphaned analysis threads ({}) - analysis blocked",
                        current_orphans
                    ));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            tracing::info!(
                waited_ms = wait_start.elapsed().as_millis(),
                remaining_orphans = ORPHANED_THREAD_COUNT.load(Ordering::Relaxed),
                "Orphaned thread count reduced - resuming analysis"
            );
        }

        let timeout = Duration::from_secs(MAX_FILE_ANALYSIS_TIME_SECS);
        let file_path_clone = file_path.to_path_buf();
        let file_path_for_log = file_path_str.clone();

        // Clone self for thread (we need to move capability_mapper and yara_engine)
        let capability_mapper = self.capability_mapper.clone();
        let yara_engine = self.yara_engine.clone();
        let zip_passwords = self.zip_passwords.clone();
        let sample_extraction = self.sample_extraction.clone();
        let current_depth = self.current_depth;
        let max_depth = self.max_depth;
        let archive_path_prefix = self.archive_path_prefix.clone();
        let max_memory_file_size = self.max_memory_file_size;

        let (tx, rx) = mpsc::channel();

        tracing::trace!(
            file_path = %file_path_str,
            timeout_secs = MAX_FILE_ANALYSIS_TIME_SECS,
            "Starting timed file analysis"
        );

        let analysis_start = std::time::Instant::now();

        let handle = std::thread::spawn(move || {
            // Recreate analyzer in thread
            let analyzer = ArchiveAnalyzer {
                max_depth,
                current_depth,
                archive_path_prefix,
                capability_mapper,
                yara_engine,
                zip_passwords,
                sample_extraction,
                max_memory_file_size,
            };

            let result = analyzer.analyze_extracted_file(&file_path_clone);
            let _ = tx.send(result);
        });

        match rx.recv_timeout(timeout) {
            Ok(result) => {
                let elapsed = analysis_start.elapsed();
                // Thread completed successfully, join to clean up resources
                let _ = handle.join();
                SUCCESSFUL_ANALYSES.fetch_add(1, Ordering::Relaxed);
                tracing::trace!(
                    file_path = %file_path_str,
                    elapsed_ms = elapsed.as_millis(),
                    success = result.is_ok(),
                    "File analysis completed within timeout"
                );
                result
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Thread timed out - track it as orphaned for memory management
                let orphan_count = ORPHANED_THREAD_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                TOTAL_ORPHANED_THREADS.fetch_add(1, Ordering::Relaxed);
                TIMEOUT_ANALYSES.fetch_add(1, Ordering::Relaxed);

                // Wrap the handle so we can track when it finishes
                let wrapped_handle = std::thread::spawn(move || {
                    // Wait for the actual analysis thread to complete
                    let _ = handle.join();
                    // Thread completed - decrement will happen in cleanup_finished_orphans
                    tracing::debug!(
                        file_path = %file_path_for_log,
                        "Orphaned analysis thread eventually completed"
                    );
                });

                // Store the wrapped handle for eventual cleanup
                if let Ok(mut handles) = ORPHANED_HANDLES.lock() {
                    handles.push(wrapped_handle);
                }

                tracing::warn!(
                    file_path = %file_path_str,
                    timeout_secs = MAX_FILE_ANALYSIS_TIME_SECS,
                    current_orphans = orphan_count,
                    total_orphaned = TOTAL_ORPHANED_THREADS.load(Ordering::Relaxed),
                    max_allowed = MAX_ORPHANED_THREADS,
                    "File analysis timed out - thread orphaned (potential memory leak)"
                );

                // Log statistics periodically when we see timeouts
                if orphan_count.is_multiple_of(10) {
                    log_orphaned_thread_stats();
                }

                // Analysis timed out - create a report with timeout finding
                let file_data = fs::read(file_path).unwrap_or_default();
                let target = TargetInfo {
                    path: file_path.display().to_string(),
                    file_type: detect_file_type(file_path)
                        .map(|ft| format!("{:?}", ft).to_lowercase())
                        .unwrap_or_else(|_| "unknown".to_string()),
                    size_bytes: file_data.len() as u64,
                    sha256: calculate_sha256(&file_data),
                    architectures: None,
                };

                let mut report = AnalysisReport::new(target);
                report.findings.push(Finding {
                    kind: FindingKind::Indicator,
                    trait_refs: vec![],
                    id: "anti-analysis/timeout/analysis-timeout".to_string(),
                    desc: format!(
                        "File analysis exceeded {}s timeout (possible anti-analysis). Orphaned threads: {}",
                        MAX_FILE_ANALYSIS_TIME_SECS, orphan_count
                    ),
                    conf: 0.8,
                    crit: Criticality::Baseline,
                    mbc: Some("B0001".to_string()),
                    attack: None,
                    evidence: vec![Evidence {
                        method: "timeout".to_string(),
                        source: "archive_analyzer".to_string(),
                        value: format!("timeout:{}s,orphans:{}", MAX_FILE_ANALYSIS_TIME_SECS, orphan_count),
                        location: Some(file_path.display().to_string()),
                        ..Default::default()
                    }],

                    match_count: 0,
                    source_file: None,
                });

                Ok(report)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                tracing::error!(
                    file_path = %file_path_str,
                    "Analysis thread crashed (channel disconnected)"
                );
                Err(anyhow::anyhow!("Analysis thread crashed"))
            }
        }
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

            return nested.analyze(file_path);
        }

        // Use the centralized factory for all other file types
        if let Some(analyzer) =
            crate::analyzers::analyzer_for_file_type_arc(&file_type, self.capability_mapper.clone())
        {
            analyzer.analyze(file_path)
        } else {
            Err(anyhow::anyhow!("Unsupported file type: {:?}", file_type))
        }
    }
}
