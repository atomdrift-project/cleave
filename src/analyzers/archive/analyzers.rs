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
//! Archive member analysis runs on the global rayon thread pool (previously a
//! separate pool — merged to halve YARA scanner cache memory). Multiple
//! concurrent archives compete for the same rayon threads, so individual
//! member analyses must be bounded to avoid stalling the entire pool.

use super::utils::{calculate_sha256, find_main_class, is_benign_java_path};
use super::ArchiveAnalyzer;
use crate::analyzers::{detect_file_type, AnalysisInput, Analyzer, FileType, FileTypeExt};
use crate::types::*;
use anyhow::Result;
use rayon::prelude::*;
use std::collections::HashSet;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, trace};

// Archive analysis now runs on the global rayon pool instead of a separate pool.
// This halves the number of YARA scanner cache instances (each ~50-100MB per wasmtime VM)
// since scanners are thread-local and a separate pool doubled the thread count.
// The global pool's work-stealing scheduler naturally balances archive and non-archive work.

/// Result of analyzing a single archive member, collected lock-free during par_iter
/// and aggregated single-threaded afterwards.
struct MemberAnalysisResult {
    entry_path: String,
    archive_location: String,
    relative_path: String,
    disk_path: std::path::PathBuf,
    entry_metadata: ArchiveEntry,
    report: Option<AnalysisReport>,
}

/// Total number of successful archive member analyses (cumulative, for logging)
static SUCCESSFUL_ANALYSES: AtomicU64 = AtomicU64::new(0);

/// Total number of failed archive member analyses
static FAILED_ANALYSES: AtomicU64 = AtomicU64::new(0);

const SLOW_ARCHIVE_MEMBER_YARA_MS: u128 = 500;

/// Warn when a single archive member analysis exceeds this threshold.
const SLOW_ARCHIVE_MEMBER_ANALYSIS_MS: u128 = 30_000;

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
    fn should_extract_archive_payloads(file_type: &FileType) -> bool {
        crate::analyzers::unified::UnifiedSourceAnalyzer::for_file_type(file_type).is_some()
    }

    fn archive_member_analysis_skip_reason(&self, file_type: &FileType) -> Option<&'static str> {
        if self
            .analysis_options
            .as_ref()
            .is_some_and(|opts| opts.all_files)
        {
            return None;
        }

        if !file_type.is_program() {
            return Some("non-program archive member and all_files is false");
        }

        None
    }

    fn archive_member_yara_skip_reason(
        relative_path: &str,
        file_type: &FileType,
        size_bytes: usize,
    ) -> Option<&'static str> {
        let lower_path = relative_path.to_ascii_lowercase();
        let file_name = Path::new(relative_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(relative_path)
            .to_ascii_lowercase();

        if lower_path.ends_with(".asar") {
            return Some("archive-like asar container");
        }

        if size_bytes >= 512 * 1024 && lower_path.ends_with(".map") {
            return Some("large source map");
        }

        let is_licenseish = file_name.starts_with("license")
            || file_name.starts_with("licenses")
            || file_name.starts_with("copying")
            || file_name.starts_with("notice");
        if size_bytes >= 128 * 1024
            && is_licenseish
            && matches!(
                file_type,
                FileType::Html | FileType::Markdown | FileType::Unknown
            )
        {
            return Some("large license/notice document");
        }

        None
    }

    fn archive_member_yara_filetypes(file_type: &FileType) -> Vec<&'static str> {
        file_type.yara_filetypes()
    }

    fn archive_member_rizin_skip_reason(
        relative_path: &str,
        file_type: &FileType,
    ) -> Option<&'static str> {
        if !matches!(file_type, FileType::Pe | FileType::Elf | FileType::MachO) {
            return None;
        }

        let lower_path = relative_path.to_ascii_lowercase();
        let is_vendored_node_native = lower_path.ends_with(".node")
            && lower_path.contains("node_modules/")
            && (lower_path.contains("/prebuilds/")
                || lower_path.contains("/build/release/")
                || lower_path.contains("app.asar.unpacked/"));

        if is_vendored_node_native {
            return Some("vendored node native module under archive dependency tree");
        }

        None
    }

    fn nested_archive_analyzer(&self, relative_path: &str) -> ArchiveAnalyzer {
        let nested_prefix = match &self.archive_path_prefix {
            Some(prefix) => format!("{}!{}", prefix, relative_path),
            None => relative_path.to_string(),
        };

        let mut nested = ArchiveAnalyzer::new()
            .with_depth(self.current_depth + 1)
            .with_archive_prefix(nested_prefix);

        if let Some(ref mapper) = self.capability_mapper {
            nested = nested.with_capability_mapper_arc(mapper.clone());
        }
        if let Some(ref engine) = self.yara_engine {
            nested = nested.with_yara_arc(engine.clone());
        }
        if !self.zip_passwords.is_empty() {
            nested = nested.with_zip_passwords_arc(self.zip_passwords.clone());
        }
        if let Some(ref config) = self.sample_extraction {
            nested = nested.with_sample_extraction(config.clone());
        }
        if let Some(ref flag) = self.cancelled {
            nested = nested.with_cancellation(flag.clone());
        }
        if let Some(ref opts) = self.analysis_options {
            nested = nested.with_analysis_options(opts.clone());
        }

        nested
    }

    fn analyze_extracted_member(
        &self,
        file_path: &Path,
        relative_path: &str,
        data: &[u8],
        file_type: &FileType,
        sha256: &str,
    ) -> Result<Option<AnalysisReport>> {
        if self.is_cancelled() {
            anyhow::bail!("Analysis cancelled");
        }

        if let Some(reason) = self.archive_member_analysis_skip_reason(file_type) {
            tracing::debug!(
                relative_path,
                file_type = %file_type.report_file_type(),
                reason,
                "Skipping archive member analysis"
            );
            return Ok(None);
        }

        let result = if file_type.is_archive() {
            if self.current_depth + 1 >= self.max_depth {
                Err(anyhow::anyhow!(
                    "Nested archive at max depth ({})",
                    self.max_depth
                ))
            } else {
                let nested = self.nested_archive_analyzer(relative_path);
                let path = file_path.to_path_buf();
                let nested_depth = self.current_depth + 1;

                // If we're already running on a rayon worker, run the nested
                // archive analysis directly on this thread. Rayon workers are
                // configured with a large stack by the caller (litmus installs
                // a 16 MB global pool), so we don't need the 8 MB std::thread
                // for stack headroom.
                //
                // Critically, spawning a std::thread and join()ing it from a
                // rayon worker causes a deadlock cycle: the rayon worker
                // blocks in pthread_join waiting for the std::thread, while
                // the std::thread calls par_iter inside cleave, which
                // submits work to the rayon pool via `in_worker_cold` and
                // blocks on a LockLatch waiting for a rayon worker to pick it
                // up — but every rayon worker is already blocked in join.
                //
                // Detecting the rayon context via `current_thread_index()` and
                // recursing in-place breaks the cycle. Off-pool callers (e.g.
                // the tokio blocking task that first enters classify_file for
                // a top-level archive) still spawn a dedicated std::thread so
                // they get the 8 MB stack that the original fix was added
                // for.
                if rayon::current_thread_index().is_some() {
                    tracing::debug!(
                        relative_path,
                        nested_depth,
                        file_size_bytes = data.len(),
                        "Analyzing nested archive in-place on rayon worker"
                    );
                    nested.analyze(&path).map(Some)
                } else {
                    // Truncate relative_path in the thread name so it fits in
                    // the 15-char pthread limit on Linux — but keep enough
                    // tail for the crash message to identify the offending
                    // member.
                    let thread_name = {
                        let tail: String = relative_path
                            .chars()
                            .rev()
                            .take(40)
                            .collect::<Vec<_>>()
                            .into_iter()
                            .rev()
                            .collect();
                        format!("nested-ar-d{nested_depth}-{tail}")
                    };
                    tracing::info!(
                        relative_path,
                        nested_depth,
                        file_size_bytes = data.len(),
                        thread_name = %thread_name,
                        "Spawning nested archive analyzer thread (off-pool caller)"
                    );
                    std::thread::Builder::new()
                        .name(thread_name)
                        .stack_size(8 * 1024 * 1024)
                        .spawn(move || nested.analyze(&path))
                        .map_err(|e| anyhow::anyhow!("Failed to spawn nested archive thread: {e}"))?
                        .join()
                        .map_err(|_| anyhow::anyhow!("Nested archive thread panicked"))?
                        .map(Some)
                }
            }
        } else if let Some(analyzer) =
            crate::analyzers::analyzer_for_file_type_arc(file_type, self.capability_mapper.clone())
        {
            let opts = crate::analyzers::stng_analysis_opts(4);
            let stng_strings = stng::extract_strings_with_options(data, &opts);
            let extract_payloads = Self::should_extract_archive_payloads(file_type);
            let skip_rizin_reason =
                Self::archive_member_rizin_skip_reason(relative_path, file_type);
            let payloads = if extract_payloads {
                crate::extractors::encoded_payload::extract_encoded_payloads(&stng_strings)
            } else {
                Vec::new()
            };
            let logical_path = Path::new(relative_path);
            let mut input = AnalysisInput::with_payloads(
                logical_path,
                data,
                &stng_strings,
                &payloads,
                *file_type,
            )
            .with_backing_path(file_path)
            .with_skip_rizin_if(skip_rizin_reason.is_some())
            .with_sha256(sha256.to_string())
            .at_depth((self.current_depth + 1) as u32);
            input.cancellation = self.cancelled.clone();

            tracing::debug!(
                relative_path,
                file_type = %file_type.report_file_type(),
                string_count = stng_strings.len(),
                payload_count = payloads.len(),
                rizin_mode = if skip_rizin_reason.is_some() { "skipped" } else { "enabled" },
                rizin_reason = skip_rizin_reason.unwrap_or("deep binary analysis allowed"),
                payload_mode = if extract_payloads { "enabled" } else { "skipped" },
                payload_reason = if extract_payloads {
                    "unified source analyzer consumes encoded payloads"
                } else {
                    "non-unified analyzer path does not consume encoded payloads"
                },
                "Analyzing archive member via unified AnalysisInput path"
            );

            let mut report = analyzer.analyze_input(&input)?;
            if let Some(ref yara_engine) = self.yara_engine {
                if let Some(reason) =
                    Self::archive_member_yara_skip_reason(relative_path, file_type, data.len())
                {
                    tracing::debug!(
                        relative_path,
                        file_type = %file_type.report_file_type(),
                        size_kb = data.len() / 1024,
                        reason,
                        "Skipping archive member YARA scan"
                    );
                } else {
                    let yara_filetypes = Self::archive_member_yara_filetypes(file_type);
                    let yara_filter = if yara_filetypes.is_empty() {
                        None
                    } else {
                        Some(yara_filetypes.as_slice())
                    };
                    tracing::debug!(
                        relative_path,
                        file_type = %file_type.report_file_type(),
                        size_kb = data.len() / 1024,
                        yara_mode = if yara_filter.is_some() {
                            "filtered"
                        } else {
                            "generic-only fallback"
                        },
                        yara_filters = ?yara_filetypes,
                        "Running archive member YARA scan"
                    );
                    let yara_start = std::time::Instant::now();
                    match yara_engine.scan_bytes_filtered(data, yara_filter) {
                        Ok(matches) => {
                            let elapsed_ms = yara_start.elapsed().as_millis();
                            if elapsed_ms > SLOW_ARCHIVE_MEMBER_YARA_MS {
                                tracing::warn!(
                                    relative_path,
                                    file_type = %file_type.report_file_type(),
                                    size_kb = data.len() / 1024,
                                    yara_mode = if yara_filter.is_some() {
                                        "filtered"
                                    } else {
                                        "generic-only fallback"
                                    },
                                    yara_filters = ?yara_filetypes,
                                    elapsed_ms = elapsed_ms as u64,
                                    matches = matches.len(),
                                    "Slow archive member YARA scan"
                                );
                            }
                            report.yara_matches = matches;
                        }
                        Err(e) => {
                            debug!("YARA scan failed for {}: {}", relative_path, e);
                        }
                    }
                }
            }
            Ok(Some(report))
        } else if self
            .analysis_options
            .as_ref()
            .is_some_and(|opts| opts.all_files)
        {
            // all_files=true: still track the file even without a dedicated analyzer.
            // This ensures extraction and path recording work for data/text types.
            let target = TargetInfo {
                path: relative_path.to_string(),
                file_type: file_type.report_file_type(),
                size_bytes: data.len() as u64,
                sha256: sha256.to_string(),
                architectures: None,
            };
            Ok(Some(AnalysisReport::new(target)))
        } else {
            Err(anyhow::anyhow!("Unsupported file type: {:?}", file_type))
        };

        match &result {
            Ok(Some(_)) => {
                SUCCESSFUL_ANALYSES.fetch_add(1, Ordering::Relaxed);
            }
            Ok(None) => {}
            Err(_) => {
                FAILED_ANALYSES.fetch_add(1, Ordering::Relaxed);
            }
        }

        result
    }

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

        // Phase 1: Run YARA on ALL class files in parallel (fast, lock-free)
        let (flagged_classes, collected_yara_matches) = if let Some(ref yara_engine) =
            self.yara_engine
        {
            let yara_start = std::time::Instant::now();
            let yara_results: Vec<_> = class_files
                .par_iter()
                .filter_map(|entry| {
                    if self.is_cancelled() {
                        return None;
                    }
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        yara_engine.scan_file(entry.path())
                    })) {
                        Ok(Ok(matches)) if !matches.is_empty() => {
                            Some((entry.path().to_path_buf(), matches))
                        }
                        Ok(Err(e)) => {
                            debug!("YARA scan failed for {}: {}", entry.path().display(), e);
                            None
                        }
                        Err(_panic) => {
                            tracing::error!(path = %entry.path().display(), "panic during YARA scan (caught)");
                            None
                        }
                        _ => None,
                    }
                })
                .collect();
            debug!(
                "YARA scan completed in {:.2}s",
                yara_start.elapsed().as_secs_f64()
            );

            // Single-threaded aggregation
            let mut flagged = HashSet::new();
            let mut matches = Vec::with_capacity(50);
            for (path, file_matches) in yara_results {
                flagged.insert(path);
                for ym in file_matches {
                    if !matches.iter().any(|m: &YaraMatch| m.rule == ym.rule) {
                        matches.push(ym);
                    }
                }
            }
            (flagged, matches)
        } else {
            (HashSet::new(), Vec::new())
        };

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

        // Run full analysis on selected classes — collect results lock-free,
        // then aggregate single-threaded to avoid Mutex contention deadlocks.
        let mut total_capabilities = HashSet::new();
        let mut total_traits = HashSet::new();
        let expected_count = classes_to_analyze.len();
        let mut collected_traits = Vec::<Finding>::with_capacity(expected_count.min(500));
        let mut collected_yara = Vec::<YaraMatch>::with_capacity(50);
        let mut collected_strings = Vec::<StringInfo>::with_capacity((expected_count * 2).min(200));
        let mut collected_archive_entries = Vec::<ArchiveEntry>::with_capacity(expected_count);
        let mut collected_files = Vec::<FileAnalysis>::with_capacity(expected_count);
        let mut files_analyzed: usize = 0;

        let member_results: Vec<MemberAnalysisResult> = classes_to_analyze
            .par_iter()
            .filter_map(|entry| {
                if self.is_cancelled() {
                    return None;
                }
                let relative_path = entry
                    .path()
                    .strip_prefix(temp_dir)
                    .unwrap_or(entry.path())
                    .display()
                    .to_string();
                let entry_path = self.format_entry_path(&relative_path);
                let archive_location = self.format_evidence_location(&relative_path);

                let file_data = match std::fs::read(entry.path()) {
                    Ok(data) => data,
                    Err(e) => {
                        debug!("Failed to read archive member {}: {}", entry_path, e);
                        return None;
                    }
                };
                let file_type =
                    crate::analyzers::detect_file_type_from_data(entry.path(), &file_data);
                let sha256 = calculate_sha256(&file_data);

                let entry_metadata = ArchiveEntry {
                    path: entry_path.clone(),
                    file_type: file_type.report_file_type(),
                    sha256: sha256.clone(),
                    size_bytes: file_data.len() as u64,
                };

                let member_start = std::time::Instant::now();
                let report = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.analyze_extracted_member(
                        entry.path(),
                        &relative_path,
                        &file_data,
                        &file_type,
                        &sha256,
                    )
                })) {
                    Ok(Ok(Some(r))) => Some(r),
                    Ok(Ok(None)) => None,
                    Ok(Err(e)) => {
                        debug!("Failed to analyze archive member {}: {}", entry_path, e);
                        None
                    }
                    Err(_panic) => {
                        tracing::error!(
                            path = %entry_path,
                            "panic during archive member analysis (caught)"
                        );
                        FAILED_ANALYSES.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                };

                let member_elapsed = member_start.elapsed();
                if member_elapsed.as_millis() > SLOW_ARCHIVE_MEMBER_ANALYSIS_MS {
                    tracing::warn!(
                        relative_path,
                        file_type = %file_type.report_file_type(),
                        size_bytes = file_data.len(),
                        elapsed_ms = member_elapsed.as_millis() as u64,
                        rayon_thread = ?rayon::current_thread_index(),
                        "Slow archive member analysis (JAR)",
                    );
                }

                Some(MemberAnalysisResult {
                    entry_path,
                    archive_location,
                    relative_path,
                    disk_path: entry.path().to_path_buf(),
                    entry_metadata,
                    report,
                })
            })
            .collect();

        // Single-threaded aggregation — no lock contention
        for result in member_results {
            collected_archive_entries.push(result.entry_metadata);

            let Some(file_report) = result.report else {
                continue;
            };
            files_analyzed += 1;
            trace!(
                "Analyzed archive member {}: {} findings",
                result.entry_path,
                file_report.findings.len()
            );

            // Aggregate findings
            for f in &file_report.findings {
                total_traits.insert(f.id.clone());
                total_capabilities.insert(f.id.clone());
                if !collected_traits.iter().any(|existing| existing.id == f.id)
                    && collected_traits.len() < 10_000
                {
                    let mut new_finding = f.clone();
                    for evidence in &mut new_finding.evidence {
                        match &evidence.location {
                            None => {
                                evidence.location = Some(result.archive_location.clone());
                            }
                            Some(loc) if !loc.starts_with("archive:") => {
                                evidence.location =
                                    Some(format!("{}:{}", result.archive_location, loc));
                            }
                            _ => {}
                        }
                    }
                    collected_traits.push(new_finding);
                }
            }

            // Aggregate YARA matches
            for yara_match in &file_report.yara_matches {
                if !collected_yara.iter().any(|m| m.rule == yara_match.rule)
                    && collected_yara.len() < 1_000
                {
                    collected_yara.push(yara_match.clone());
                }
            }

            // Aggregate interesting strings
            for string in &file_report.strings {
                if matches!(
                    string.string_type,
                    Some(StringType::Url | StringType::IP | StringType::Base64)
                ) && collected_strings.len() < 10_000
                {
                    collected_strings.push(string.clone());
                }
            }

            // Convert to FileAnalysis
            let (mut file_entry, nested_files, archive_contents) =
                file_report.into_file_analysis(0);
            file_entry.path = result.entry_path.clone();
            file_entry.depth = 1;
            file_entry.compute_summary();
            collected_files.push(file_entry);

            for nested_entry in archive_contents {
                collected_archive_entries.push(nested_entry);
            }
            for mut nested_file in nested_files {
                if !nested_file.path.contains("!!") {
                    nested_file.path = encode_archive_path(&result.entry_path, &nested_file.path);
                }
                nested_file.depth += 1;
                collected_files.push(nested_file);
            }
        }

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

        let non_class_results: Vec<MemberAnalysisResult> = non_class_files
            .par_iter()
            .filter_map(|entry| {
                if self.is_cancelled() {
                    return None;
                }
                let relative_path = entry
                    .path()
                    .strip_prefix(temp_dir)
                    .unwrap_or(entry.path())
                    .display()
                    .to_string();
                let entry_path = self.format_entry_path(&relative_path);
                let archive_location = self.format_evidence_location(&relative_path);

                let file_data = match std::fs::read(entry.path()) {
                    Ok(data) => data,
                    Err(e) => {
                        debug!("Failed to read archive member {}: {}", entry_path, e);
                        return None;
                    }
                };
                let file_type =
                    crate::analyzers::detect_file_type_from_data(entry.path(), &file_data);
                let sha256 = calculate_sha256(&file_data);

                let entry_metadata = ArchiveEntry {
                    path: entry_path.clone(),
                    file_type: file_type.report_file_type(),
                    sha256: sha256.clone(),
                    size_bytes: file_data.len() as u64,
                };

                let report = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.analyze_extracted_member(
                        entry.path(),
                        &relative_path,
                        &file_data,
                        &file_type,
                        &sha256,
                    )
                })) {
                    Ok(Ok(Some(r))) => Some(r),
                    Ok(Ok(None)) => None,
                    Ok(Err(e)) => {
                        debug!("Failed to analyze archive member {}: {}", entry_path, e);
                        None
                    }
                    Err(_panic) => {
                        tracing::error!(
                            path = %entry_path,
                            "panic during archive member analysis (caught)"
                        );
                        FAILED_ANALYSES.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                };

                Some(MemberAnalysisResult {
                    entry_path,
                    archive_location,
                    relative_path,
                    disk_path: entry.path().to_path_buf(),
                    entry_metadata,
                    report,
                })
            })
            .collect();

        // Aggregate non-class results
        for result in non_class_results {
            collected_archive_entries.push(result.entry_metadata);

            let Some(file_report) = result.report else {
                continue;
            };
            files_analyzed += 1;
            trace!(
                "Analyzed archive member {}: {} findings",
                result.entry_path,
                file_report.findings.len()
            );

            for f in &file_report.findings {
                total_traits.insert(f.id.clone());
                total_capabilities.insert(f.id.clone());
                if !collected_traits.iter().any(|existing| existing.id == f.id)
                    && collected_traits.len() < 10_000
                {
                    let mut new_finding = f.clone();
                    for evidence in &mut new_finding.evidence {
                        match &evidence.location {
                            None => {
                                evidence.location = Some(result.archive_location.clone());
                            }
                            Some(loc) if !loc.starts_with("archive:") => {
                                evidence.location =
                                    Some(format!("{}:{}", result.archive_location, loc));
                            }
                            _ => {}
                        }
                    }
                    collected_traits.push(new_finding);
                }
            }

            for yara_match in &file_report.yara_matches {
                if !collected_yara.iter().any(|m| m.rule == yara_match.rule)
                    && collected_yara.len() < 1_000
                {
                    collected_yara.push(yara_match.clone());
                }
            }

            for string in &file_report.strings {
                if matches!(
                    string.string_type,
                    Some(StringType::Url | StringType::IP | StringType::Base64)
                ) && collected_strings.len() < 10_000
                {
                    collected_strings.push(string.clone());
                }
            }

            let (mut file_entry, nested_files, archive_contents) =
                file_report.into_file_analysis(0);
            file_entry.path = result.entry_path.clone();
            file_entry.depth = 1;
            file_entry.compute_summary();
            collected_files.push(file_entry);

            for nested_entry in archive_contents {
                collected_archive_entries.push(nested_entry);
            }
            for mut nested_file in nested_files {
                if !nested_file.path.contains("!!") {
                    nested_file.path = encode_archive_path(&result.entry_path, &nested_file.path);
                }
                nested_file.depth += 1;
                collected_files.push(nested_file);
            }
        }

        // Merge JAR collected results into the report
        for t in collected_traits {
            if !report.findings.iter().any(|existing| existing.id == t.id) {
                report.findings.push(t);
            }
        }
        for ym in collected_yara {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }
        report.strings.extend(collected_strings);
        report.archive_contents.extend(collected_archive_entries);
        report.files.extend(collected_files);

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

        // Collect results lock-free, aggregate single-threaded afterwards
        let mut total_capabilities = HashSet::new();
        let mut total_traits = HashSet::new();
        let mut collected_traits = Vec::<Finding>::with_capacity(total_files.min(500));
        let mut collected_yara = Vec::<YaraMatch>::with_capacity(100);
        let mut collected_strings = Vec::<StringInfo>::with_capacity((total_files * 2).min(200));
        let mut collected_archive_entries = Vec::<ArchiveEntry>::with_capacity(total_files);
        let mut collected_files = Vec::<FileAnalysis>::with_capacity(total_files);
        let mut files_analyzed: usize = 0;

        // Analyze files in parallel — no shared Mutexes
        let generic_results: Vec<MemberAnalysisResult> = files
            .par_iter()
            .filter_map(|entry| {
                if self.is_cancelled() {
                    return None;
                }

                let relative_path = entry
                    .path()
                    .strip_prefix(temp_dir)
                    .unwrap_or(entry.path())
                    .display()
                    .to_string();
                let entry_path = self.format_entry_path(&relative_path);
                let archive_location = self.format_evidence_location(&relative_path);

                let file_data = match std::fs::read(entry.path()) {
                    Ok(data) => data,
                    Err(e) => {
                        debug!("Failed to read archive member {}: {}", entry_path, e);
                        return None;
                    }
                };
                let file_type =
                    crate::analyzers::detect_file_type_from_data(entry.path(), &file_data);
                let sha256 = calculate_sha256(&file_data);

                let entry_metadata = ArchiveEntry {
                    path: entry_path.clone(),
                    file_type: file_type.report_file_type(),
                    sha256: sha256.clone(),
                    size_bytes: file_data.len() as u64,
                };

                let member_start = std::time::Instant::now();
                let report = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.analyze_extracted_member(
                        entry.path(),
                        &relative_path,
                        &file_data,
                        &file_type,
                        &sha256,
                    )
                })) {
                    Ok(Ok(Some(r))) => Some(r),
                    Ok(Ok(None)) => None,
                    Ok(Err(e)) => {
                        debug!("Failed to analyze archive member {}: {}", entry_path, e);
                        None
                    }
                    Err(_panic) => {
                        tracing::error!(
                            path = %entry_path,
                            "panic during archive member analysis (caught)"
                        );
                        FAILED_ANALYSES.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                };

                let member_elapsed = member_start.elapsed();
                if member_elapsed.as_millis() > SLOW_ARCHIVE_MEMBER_ANALYSIS_MS {
                    tracing::warn!(
                        relative_path,
                        file_type = %file_type.report_file_type(),
                        size_bytes = file_data.len(),
                        elapsed_ms = member_elapsed.as_millis() as u64,
                        rayon_thread = ?rayon::current_thread_index(),
                        "Slow archive member analysis (generic)",
                    );
                }

                Some(MemberAnalysisResult {
                    entry_path,
                    archive_location,
                    relative_path,
                    disk_path: entry.path().to_path_buf(),
                    entry_metadata,
                    report,
                })
            })
            .collect();

        // Single-threaded aggregation
        for result in generic_results {
            collected_archive_entries.push(result.entry_metadata);

            let Some(file_report) = result.report else {
                continue;
            };
            files_analyzed += 1;
            trace!(
                "Analyzed archive member {}: {} findings",
                result.entry_path,
                file_report.findings.len()
            );

            let (mut file_entry, nested_files, archive_contents) =
                file_report.into_file_analysis(0);
            file_entry.path = result.entry_path.clone();
            file_entry.depth = 1;
            file_entry.compute_summary();

            // Extract file to disk if configured
            if let Some(ref config) = self.sample_extraction {
                if let Ok(file_data) = std::fs::read(&result.disk_path) {
                    let extract_relative_path = match &self.archive_path_prefix {
                        Some(prefix) => {
                            format!("{}/{}", prefix.replace('!', "/"), result.relative_path)
                        }
                        None => result.relative_path.clone(),
                    };
                    if let Some(extracted_path) =
                        config.extract(&file_entry.sha256, &extract_relative_path, &file_data)
                    {
                        file_entry.extracted_path = Some(extracted_path.display().to_string());
                    }
                }
            }

            // Aggregate findings
            for f in &file_entry.findings {
                total_traits.insert(f.id.clone());
                total_capabilities.insert(f.id.clone());
                if !collected_traits.iter().any(|existing| existing.id == f.id)
                    && collected_traits.len() < 10_000
                {
                    let mut new_finding = f.clone();
                    for evidence in &mut new_finding.evidence {
                        match &evidence.location {
                            None => {
                                evidence.location = Some(result.archive_location.clone());
                            }
                            Some(loc) if !loc.starts_with("archive:") => {
                                evidence.location =
                                    Some(format!("{}:{}", result.archive_location, loc));
                            }
                            _ => {}
                        }
                    }
                    collected_traits.push(new_finding);
                }
            }

            for yara_match in &file_entry.yara_matches {
                if !collected_yara.iter().any(|m| m.rule == yara_match.rule)
                    && collected_yara.len() < 1_000
                {
                    collected_yara.push(yara_match.clone());
                }
            }

            for string in &file_entry.strings {
                if matches!(
                    string.string_type,
                    Some(StringType::Url | StringType::IP | StringType::Base64)
                ) && collected_strings.len() < 10_000
                {
                    collected_strings.push(string.clone());
                }
            }

            collected_files.push(file_entry.clone());

            for nested_entry in archive_contents {
                collected_archive_entries.push(nested_entry);
            }
            for mut nested_file in nested_files {
                if !nested_file.path.contains("!!") {
                    nested_file.path = encode_archive_path(&result.entry_path, &nested_file.path);
                }
                nested_file.depth += 1;
                collected_files.push(nested_file);
            }
        }

        // Sort files by highest severity first, then truncate to limit
        collected_files.sort_by(|a, b| {
            let max_crit =
                |f: &FileAnalysis| f.findings.iter().map(|f| f.crit).max().unwrap_or_default();
            max_crit(b).cmp(&max_crit(a))
        });
        collected_files.truncate(100_000);

        // Merge collected results into the report
        for t in collected_traits {
            if !report.findings.iter().any(|existing| existing.id == t.id) {
                report.findings.push(t);
            }
        }
        for ym in collected_yara {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }
        report.strings.extend(collected_strings);
        report.archive_contents.extend(collected_archive_entries);
        report.files.extend(collected_files);

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
    #[allow(dead_code)] // Legacy shim while archive callers finish migrating to the shared member path
    pub(super) fn analyze_extracted_file(&self, file_path: &Path) -> Result<AnalysisReport> {
        if self.is_cancelled() {
            anyhow::bail!("Analysis cancelled");
        }

        let data = std::fs::read(file_path)?;
        let file_type = detect_file_type(file_path)?;
        let sha256 = calculate_sha256(&data);
        let relative_path = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("extracted")
            .to_string();
        match self.analyze_extracted_member(
            file_path,
            &relative_path,
            &data,
            &file_type,
            &sha256,
        )? {
            Some(report) => Ok(report),
            None => anyhow::bail!("Non-program file type, skipping: {}", file_path.display()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ArchiveAnalyzer;
    use crate::analyzers::FileType;
    use std::sync::Arc;

    #[test]
    fn archive_member_yara_filetypes_use_detected_binary_type() {
        assert_eq!(
            ArchiveAnalyzer::archive_member_yara_filetypes(&FileType::Elf),
            vec!["elf", "so", "ko"]
        );
        assert_eq!(
            ArchiveAnalyzer::archive_member_yara_filetypes(&FileType::Pe),
            vec!["pe", "exe", "dll", "bat", "ps1"]
        );
        assert!(ArchiveAnalyzer::archive_member_yara_filetypes(&FileType::Unknown).is_empty());
    }

    #[test]
    fn archive_member_analysis_skip_matches_all_files_policy() {
        let default_analyzer = ArchiveAnalyzer::new();
        assert_eq!(
            default_analyzer.archive_member_analysis_skip_reason(&FileType::Unknown),
            Some("non-program archive member and all_files is false")
        );
        assert_eq!(
            default_analyzer.archive_member_analysis_skip_reason(&FileType::Html),
            Some("non-program archive member and all_files is false")
        );
        assert_eq!(
            default_analyzer.archive_member_analysis_skip_reason(&FileType::Pe),
            None
        );

        let all_files_analyzer =
            ArchiveAnalyzer::new().with_analysis_options(Arc::new(crate::AnalysisOptions {
                all_files: true,
                ..crate::AnalysisOptions::default()
            }));
        assert_eq!(
            all_files_analyzer.archive_member_analysis_skip_reason(&FileType::Unknown),
            None
        );
        assert_eq!(
            all_files_analyzer.archive_member_analysis_skip_reason(&FileType::Html),
            None
        );
    }
}
