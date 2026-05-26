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

use super::guards::{
    sanitize_entry_path, symlink_escapes, CancellableReader, ExtractionGuard, HostileArchiveReason,
    LimitedReader, MAX_FILE_SIZE, MAX_PATH_COMPONENT_LEN,
};
use super::utils::{calculate_sha256, find_main_class, is_benign_java_path};
use super::ArchiveAnalyzer;
use crate::analyzers::{detect_file_type, AnalysisInput, FileType, FileTypeExt};
use crate::types::{
    encode_archive_path, AnalysisReport, ArchiveEntry, FileAnalysis, Finding, StringInfo,
    StringType, TargetInfo, YaraMatch,
};
use anyhow::Result;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, trace};

// Archive analysis now runs on the global rayon pool instead of a separate pool.
// This halves the number of YARA scanner cache instances (each ~50-100MB per wasmtime VM)
// since scanners are thread-local and a separate pool doubled the thread count.
// The global pool's work-stealing scheduler naturally balances archive and non-archive work.

/// Filter-map `items` in parallel when we're the outermost rayon context,
/// sequentially otherwise.
///
/// Archive expansion is nearly always reached from an outer rayon context
/// (`cleave scan` walks files with `par_bridge`, litmus worker installs each
/// analysis on a dedicated thread budget), in which case nesting a second
/// `par_iter` here just contends for the same threads. The outermost case
/// (`cleave analyze single.jar` with no outer scope) still fans out.
fn par_filter_map_if_outermost<T, U, F>(items: &[T], f: F) -> Vec<U>
where
    T: Sync,
    U: Send,
    F: Fn(&T) -> Option<U> + Sync + Send,
{
    if rayon::current_thread_index().is_some() {
        items.iter().filter_map(f).collect()
    } else {
        items.par_iter().filter_map(f).collect()
    }
}

/// Result of analyzing a single archive member, collected lock-free during par_iter
/// and aggregated single-threaded afterwards.
struct MemberAnalysisResult {
    entry_path: String,
    archive_location: String,
    entry_metadata: ArchiveEntry,
    extracted_path: Option<String>,
    report: Option<AnalysisReport>,
}

struct MemoryArchiveMember {
    relative_path: String,
    data: Vec<u8>,
    file_type: FileType,
    sha256: String,
}

fn find_main_class_in_members(members: &[MemoryArchiveMember]) -> Option<String> {
    let manifest = members
        .iter()
        .find(|m| m.relative_path.eq_ignore_ascii_case("META-INF/MANIFEST.MF"))?;
    let text = std::str::from_utf8(&manifest.data).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Main-Class:") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

fn is_interesting_jar_non_class(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    !lower.contains("meta-inf/") || lower.ends_with("manifest.mf") || lower.ends_with(".xml")
}

/// Total number of successful archive member analyses (cumulative, for logging)
static SUCCESSFUL_ANALYSES: AtomicU64 = AtomicU64::new(0);

/// Total number of failed archive member analyses
static FAILED_ANALYSES: AtomicU64 = AtomicU64::new(0);

const SLOW_ARCHIVE_MEMBER_YARA_MS: u128 = 500;

/// Warn when a single archive member analysis exceeds this threshold.
const SLOW_ARCHIVE_MEMBER_ANALYSIS_MS: u128 = 30_000;

/// Emit a progress log every N members or every T seconds, whichever comes
/// first. The atomic ensures only one thread emits per window, so the log is
/// safe to call from a `par_iter` body. Returns `true` if a log should fire.
fn should_log_progress(
    done: usize,
    total: usize,
    elapsed_ms: u64,
    last_log_ms: &AtomicU64,
) -> bool {
    const EVERY_N_MEMBERS: usize = 10;
    const EVERY_T_MS: u64 = 10_000;
    if done == total || done.is_multiple_of(EVERY_N_MEMBERS) {
        last_log_ms.store(elapsed_ms, Ordering::Relaxed);
        return true;
    }
    let last = last_log_ms.load(Ordering::Relaxed);
    if elapsed_ms.saturating_sub(last) >= EVERY_T_MS
        && last_log_ms
            .compare_exchange(last, elapsed_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        return true;
    }
    false
}

struct ThreadLocalCacheClearGuard;

impl Drop for ThreadLocalCacheClearGuard {
    fn drop(&mut self) {
        crate::composite_rules::evaluators::clear_thread_local_caches();
    }
}

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

        // Allow file types that carry identity-signal facts (Markdown
        // exposes `markdown.first_heading` / `markdown.github_repos[]`,
        // PkgInfo carries `Name:` / `Version:` headers). These are
        // technically `!is_program()` but the cross-file value
        // matchers depend on their values being reachable from
        // archive-scope evaluation.
        if matches!(file_type, FileType::Markdown | FileType::PkgInfo) {
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
            return Some("not a native binary file type");
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
                    nested.analyze_archive_with_data(data, &path).map(Some)
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
                    let nested_data = data.to_vec();
                    std::thread::Builder::new()
                        .name(thread_name)
                        .stack_size(8 * 1024 * 1024)
                        .spawn(move || nested.analyze_archive_with_data(&nested_data, &path))
                        .map_err(|e| anyhow::anyhow!("Failed to spawn nested archive thread: {e}"))?
                        .join()
                        .map_err(|e| {
                            let msg = e
                                .downcast_ref::<String>()
                                .map(String::as_str)
                                .or_else(|| e.downcast_ref::<&str>().copied())
                                .unwrap_or("unknown panic payload");
                            anyhow::anyhow!("Nested archive thread panicked: {msg}")
                        })?
                        .map(Some)
                }
            }
        } else if let Some(analyzer) =
            crate::analyzers::analyzer_for_file_type_arc(file_type, self.capability_mapper.clone())
        {
            let extract_payloads = Self::should_extract_archive_payloads(file_type);
            let skip_rizin_reason =
                Self::archive_member_rizin_skip_reason(relative_path, file_type);
            let _ = (file_path, sha256);

            // Per-format selection of stng's XOR scan: text/source
            // members skip it entirely. The historical "pre-launch
            // rizin" optimization was retired in Wave B — rizin now
            // runs inside `filefacts::open` on the member's bytes when
            // the per-analyzer parse fires; there's no separate
            // subprocess for the archive layer to overlap with.
            let stng_opts = if skip_rizin_reason.is_some() {
                crate::analyzers::stng_text_opts(4)
            } else {
                crate::analyzers::stng_analysis_opts(4)
            };
            crate::memory_tracker::set_current_phase(format!("stng on {relative_path}"));
            let stng_opts =
                crate::analyzers::attach_stng_cancellation(stng_opts, self.cancelled.as_ref());
            let stng_strings = stng::extract_strings_with_options(data, &stng_opts);
            crate::memory_tracker::clear_current_phase();
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
                    crate::memory_tracker::set_current_phase(format!("yara on {relative_path}"));
                    let yara_start = std::time::Instant::now();
                    match yara_engine.scan_bytes_filtered(data, yara_filter) {
                        Ok(matches) => {
                            let elapsed_ms = yara_start.elapsed().as_millis();
                            crate::memory_tracker::clear_current_phase();
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
                            crate::memory_tracker::clear_current_phase();
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

    fn analyze_zip_archive_from_filefacts_index(
        &self,
        data: &[u8],
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        guard: &ExtractionGuard,
        indexed_entries: &[ArchiveEntry],
    ) -> Result<bool> {
        if indexed_entries.is_empty() {
            return Ok(false);
        }
        if indexed_entries.len() > super::MAX_ZIP_ENTRIES {
            anyhow::bail!(
                "ZIP central directory claims {} entries (max {})",
                indexed_entries.len(),
                super::MAX_ZIP_ENTRIES
            );
        }

        for entry in indexed_entries {
            if entry.entry_type.as_deref() == Some("directory") {
                continue;
            }
            if entry.data_offset.is_none()
                || entry.compressed_size.is_none()
                || entry.compression_method.is_none()
            {
                return Ok(false);
            }
            if !matches!(
                entry.compression_method.as_deref(),
                Some("stored" | "deflate")
            ) {
                return Ok(false);
            }
        }

        let fake_root = Path::new("/__cleave_archive__");
        let stream_members = rayon::current_thread_index().is_some();
        let mut members = if stream_members {
            Vec::new()
        } else {
            Vec::with_capacity(indexed_entries.len().min(10_000))
        };
        let mut streamed_results: Vec<MemberAnalysisResult> = if stream_members {
            Vec::with_capacity(indexed_entries.len().min(10_000))
        } else {
            Vec::new()
        };
        let mut total_streamed: usize = 0;

        for entry in indexed_entries {
            if self.is_cancelled() {
                anyhow::bail!("Analysis cancelled during ZIP member read");
            }
            if !guard.check_file_count() {
                anyhow::bail!(
                    "Exceeded maximum file count ({})",
                    super::guards::MAX_FILE_COUNT
                );
            }

            let entry_name = entry.path.clone();
            if entry_name.len() > MAX_PATH_COMPONENT_LEN {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveEntryName {
                    len: entry_name.len(),
                    preview: entry_name.chars().take(80).collect(),
                });
            }

            let Some(outpath) = sanitize_entry_path(&entry_name, fake_root) else {
                guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_name));
                continue;
            };
            let relative_path = outpath
                .strip_prefix(fake_root)
                .unwrap_or(&outpath)
                .to_string_lossy()
                .replace('\\', "/");
            let entry_type_label = entry.entry_type.as_deref().unwrap_or("regular");

            if entry_type_label == "directory" {
                continue;
            }

            if entry.encrypted {
                anyhow::bail!("Password required to decrypt file");
            }

            if entry_type_label == "symlink" {
                let target = super::zip::read_indexed_zip_member(data, entry, 4096)
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok());
                if let Some(target_str) = target.as_deref() {
                    if symlink_escapes(&outpath, target_str, fake_root) {
                        guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(format!(
                            "{} -> {}",
                            entry_name, target_str
                        )));
                    }
                }
                guard.record_member_metadata(super::guards::ExtractedMemberMetadata {
                    archive_path: relative_path,
                    compressed_size: entry.compressed_size,
                    compression_method: entry.compression_method.clone(),
                    mtime_unix: entry.mtime_unix,
                    mode_octal: entry.mode_octal,
                    uid: entry.uid,
                    gid: entry.gid,
                    uname: entry.uname.clone(),
                    gname: entry.gname.clone(),
                    entry_type: Some(entry_type_label.to_string()),
                    linkname: target,
                    host_os: entry.host_os.clone(),
                });
                continue;
            }

            guard.record_member_metadata(super::guards::ExtractedMemberMetadata {
                archive_path: relative_path.clone(),
                compressed_size: entry.compressed_size,
                compression_method: entry.compression_method.clone(),
                mtime_unix: entry.mtime_unix,
                mode_octal: entry.mode_octal,
                uid: entry.uid,
                gid: entry.gid,
                uname: entry.uname.clone(),
                gname: entry.gname.clone(),
                entry_type: Some(entry_type_label.to_string()),
                linkname: entry.linkname.clone(),
                host_os: entry.host_os.clone(),
            });

            let compressed = entry.compressed_size.unwrap_or(0);
            let uncompressed = entry.size_bytes;
            if !guard.check_compression_ratio(compressed, uncompressed) {
                continue;
            }
            if uncompressed > MAX_FILE_SIZE {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                    file: entry_name,
                    size: uncompressed,
                });
                continue;
            }

            let Ok(file_data) = super::zip::read_indexed_zip_member(data, entry, MAX_FILE_SIZE)
            else {
                return Ok(false);
            };
            let written = file_data.len() as u64;
            if !guard.check_bytes(written, &relative_path) {
                anyhow::bail!("Exceeded maximum total extraction size");
            }

            let logical_path = Path::new(&relative_path);
            let file_type = crate::analyzers::detect_file_type_from_data(logical_path, &file_data);
            let sha256 = calculate_sha256(&file_data);
            let member = MemoryArchiveMember {
                relative_path,
                data: file_data,
                file_type,
                sha256,
            };
            if stream_members {
                if let Some(result) = self.analyze_one_member(&member, "filefacts ZIP index") {
                    streamed_results.push(result);
                }
                total_streamed += 1;
            } else {
                members.push(member);
            }
        }

        if stream_members {
            self.aggregate_member_results(
                streamed_results,
                report,
                start,
                "ZIP archive",
                vec![
                    "archive_analyzer".to_string(),
                    "filefacts_zip_index".to_string(),
                ],
                total_streamed,
            );
        } else if matches!(
            crate::analyzers::detect_file_type(archive_path),
            Ok(FileType::Jar)
        ) {
            self.analyze_jar_members_in_memory(&members, archive_path, report, start);
        } else {
            self.analyze_in_memory_members(
                &members,
                archive_path,
                report,
                start,
                "ZIP archive",
                "filefacts ZIP index",
                vec![
                    "archive_analyzer".to_string(),
                    "filefacts_zip_index".to_string(),
                ],
            );
        }
        Ok(true)
    }

    /// Analyze ZIP/JAR-style archives without materializing the whole archive
    /// tree under `/tmp`. Members are read into bounded in-memory buffers and
    /// handed to the same member analyzers used by the extracted-directory path.
    pub(super) fn analyze_zip_archive_in_memory(
        &self,
        data: &[u8],
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        guard: &ExtractionGuard,
        indexed_entries: &[ArchiveEntry],
    ) -> Result<()> {
        if self.analyze_zip_archive_from_filefacts_index(
            data,
            archive_path,
            report,
            start,
            guard,
            indexed_entries,
        )? {
            return Ok(());
        }

        let mut archive = ::zip::ZipArchive::new(std::io::Cursor::new(data))
            .map_err(|e| anyhow::anyhow!("Failed to read ZIP archive: {e}"))?;
        if archive.len() > super::MAX_ZIP_ENTRIES {
            anyhow::bail!(
                "ZIP central directory claims {} entries (max {})",
                archive.len(),
                super::MAX_ZIP_ENTRIES
            );
        }

        let fake_root = Path::new("/__cleave_archive__");

        // When we're already inside a rayon worker, the per-member work runs
        // sequentially anyway (`par_filter_map_if_outermost` skips the inner
        // par_iter to avoid contention). In that case we can stream: read one
        // member, analyze it, drop the buffer, before reading the next.
        // Caps in-flight decompressed-bytes per worker to a single member
        // instead of the whole archive.
        let stream_members = rayon::current_thread_index().is_some();
        let mut members = if stream_members {
            Vec::new()
        } else {
            Vec::with_capacity(archive.len().min(10_000))
        };
        let mut streamed_results: Vec<MemberAnalysisResult> = if stream_members {
            Vec::with_capacity(archive.len().min(10_000))
        } else {
            Vec::new()
        };
        let mut total_streamed: usize = 0;

        for i in 0..archive.len() {
            if self.is_cancelled() {
                anyhow::bail!("Analysis cancelled during ZIP member read");
            }
            if !guard.check_file_count() {
                anyhow::bail!(
                    "Exceeded maximum file count ({})",
                    super::guards::MAX_FILE_COUNT
                );
            }

            let mut entry = archive.by_index(i)?;
            let entry_name = entry.name().to_string();
            if entry_name.len() > MAX_PATH_COMPONENT_LEN {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveEntryName {
                    len: entry_name.len(),
                    preview: entry_name.chars().take(80).collect(),
                });
            }

            let Some(outpath) = sanitize_entry_path(&entry_name, fake_root) else {
                guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry_name));
                continue;
            };
            let relative_path = outpath
                .strip_prefix(fake_root)
                .unwrap_or(&outpath)
                .to_string_lossy()
                .replace('\\', "/");

            // Capture forensic metadata from the central-directory header
            // before any reads consume the entry. linkname is set in the
            // symlink branch below; non-symlink/non-dir entries record here.
            let entry_compressed_size = entry.compressed_size();
            let entry_compression = super::zip::format_zip_compression(entry.compression());
            let entry_mtime = entry
                .last_modified()
                .and_then(super::zip::zip_datetime_to_unix);
            let entry_mode_octal = entry.unix_mode();
            let entry_is_dir = entry.is_dir();
            let entry_is_symlink = entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000);
            let entry_type_label = if entry_is_dir {
                "directory"
            } else if entry_is_symlink {
                "symlink"
            } else {
                "regular"
            };

            if let Some(mode) = entry.unix_mode() {
                if mode & 0o170000 == 0o120000 {
                    let mut target_buf = Vec::new();
                    let mut limited = LimitedReader::new(&mut entry, 4096);
                    let mut linkname_capture: Option<String> = None;
                    if let Ok(read_size) = limited.read_to_end(&mut target_buf) {
                        if read_size > 0 && read_size < 4096 {
                            if let Ok(target_str) = String::from_utf8(target_buf) {
                                if symlink_escapes(&outpath, &target_str, fake_root) {
                                    guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(
                                        format!("{} -> {}", entry_name, target_str),
                                    ));
                                }
                                linkname_capture = Some(target_str);
                            }
                        }
                    }
                    guard.record_member_metadata(super::guards::ExtractedMemberMetadata {
                        archive_path: relative_path.clone(),
                        compressed_size: Some(entry_compressed_size),
                        compression_method: Some(entry_compression),
                        mtime_unix: entry_mtime,
                        mode_octal: entry_mode_octal,
                        uid: None,
                        gid: None,
                        uname: None,
                        gname: None,
                        entry_type: Some(entry_type_label.to_string()),
                        linkname: linkname_capture,
                        host_os: None,
                    });
                    continue;
                }
            }

            if entry.is_dir() {
                continue;
            }

            guard.record_member_metadata(super::guards::ExtractedMemberMetadata {
                archive_path: relative_path.clone(),
                compressed_size: Some(entry_compressed_size),
                compression_method: Some(entry_compression),
                mtime_unix: entry_mtime,
                mode_octal: entry_mode_octal,
                uid: None,
                gid: None,
                uname: None,
                gname: None,
                entry_type: Some(entry_type_label.to_string()),
                linkname: None,
                host_os: None,
            });
            if entry.encrypted() {
                anyhow::bail!("Password required to decrypt file");
            }

            let compressed = entry.compressed_size();
            let uncompressed = entry.size();
            if !guard.check_compression_ratio(compressed, uncompressed) {
                continue;
            }
            if uncompressed > MAX_FILE_SIZE {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                    file: entry_name,
                    size: uncompressed,
                });
                continue;
            }

            let mut file_data = Vec::with_capacity(uncompressed.min(16 * 1024 * 1024) as usize);
            let written = if let Some(c) = guard.cancellation() {
                let mut cancellable = CancellableReader::new(&mut entry, c);
                let mut limited = LimitedReader::new(&mut cancellable, MAX_FILE_SIZE);
                let n = limited.read_to_end(&mut file_data)? as u64;
                if limited.is_limited() {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: relative_path.clone(),
                        size: MAX_FILE_SIZE,
                    });
                    continue;
                }
                n
            } else {
                let mut limited = LimitedReader::new(&mut entry, MAX_FILE_SIZE);
                let n = limited.read_to_end(&mut file_data)? as u64;
                if limited.is_limited() {
                    guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                        file: relative_path.clone(),
                        size: MAX_FILE_SIZE,
                    });
                    continue;
                }
                n
            };
            if !guard.check_bytes(written, &relative_path) {
                anyhow::bail!("Exceeded maximum total extraction size");
            }

            let logical_path = Path::new(&relative_path);
            let file_type = crate::analyzers::detect_file_type_from_data(logical_path, &file_data);
            let sha256 = calculate_sha256(&file_data);
            let member = MemoryArchiveMember {
                relative_path,
                data: file_data,
                file_type,
                sha256,
            };
            if stream_members {
                if let Some(result) = self.analyze_one_member(&member, "memory ZIP") {
                    streamed_results.push(result);
                }
                total_streamed += 1;
                // `member` (with its decompressed `data: Vec<u8>`) drops here;
                // next loop iteration starts with a fresh allocation.
            } else {
                members.push(member);
            }
        }

        if stream_members {
            self.aggregate_member_results(
                streamed_results,
                report,
                start,
                "ZIP archive",
                vec!["archive_analyzer".to_string(), "in_memory_zip".to_string()],
                total_streamed,
            );
        } else if matches!(
            crate::analyzers::detect_file_type(archive_path),
            Ok(FileType::Jar)
        ) {
            self.analyze_jar_members_in_memory(&members, archive_path, report, start);
        } else {
            self.analyze_in_memory_members(
                &members,
                archive_path,
                report,
                start,
                "ZIP archive",
                "memory ZIP",
                vec!["archive_analyzer".to_string(), "in_memory_zip".to_string()],
            );
        }
        Ok(())
    }

    fn analyze_jar_members_in_memory(
        &self,
        members: &[MemoryArchiveMember],
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
    ) {
        let main_class = find_main_class_in_members(members);
        if let Some(ref mc) = main_class {
            debug!("Main-Class: {}", mc);
        }

        let class_members: Vec<&MemoryArchiveMember> = members
            .iter()
            .filter(|m| m.relative_path.ends_with(".class"))
            .collect();
        let total_class_files = class_members.len();

        let mut flagged_classes = HashSet::<String>::new();
        let mut collected_yara = Vec::<YaraMatch>::with_capacity(50);
        if let Some(ref yara_engine) = self.yara_engine {
            let yara_filetypes = FileType::JavaClass.yara_filetypes();
            let yara_filter = if yara_filetypes.is_empty() {
                None
            } else {
                Some(yara_filetypes.as_slice())
            };
            let yara_results = par_filter_map_if_outermost(&class_members, |member| {
                if self.is_cancelled() {
                    return None;
                }
                match yara_engine.scan_bytes_filtered(&member.data, yara_filter) {
                    Ok(matches) if !matches.is_empty() => {
                        Some((member.relative_path.clone(), matches))
                    }
                    Ok(_) => None,
                    Err(e) => {
                        debug!("YARA scan failed for {}: {}", member.relative_path, e);
                        None
                    }
                }
            });
            for (path, matches) in yara_results {
                flagged_classes.insert(path);
                for ym in matches {
                    if !collected_yara.iter().any(|m: &YaraMatch| m.rule == ym.rule) {
                        collected_yara.push(ym);
                    }
                }
            }
        }
        for ym in collected_yara {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }

        let main_class_path = main_class.map(|mc| mc.replace('.', "/") + ".class");
        let mut selected: Vec<&MemoryArchiveMember> = class_members
            .iter()
            .copied()
            .filter(|m| {
                main_class_path
                    .as_ref()
                    .is_some_and(|main| m.relative_path.ends_with(main))
                    || flagged_classes.contains(&m.relative_path)
            })
            .collect();

        let mut sample_count = 0usize;
        for member in class_members.iter().copied() {
            if sample_count >= 20 {
                break;
            }
            if is_benign_java_path(Path::new(&member.relative_path))
                || flagged_classes.contains(&member.relative_path)
                || selected
                    .iter()
                    .any(|selected| selected.relative_path == member.relative_path)
            {
                continue;
            }
            selected.push(member);
            sample_count += 1;
        }

        selected.extend(
            members
                .iter()
                .filter(|m| !m.relative_path.ends_with(".class"))
                .filter(|m| !is_benign_java_path(Path::new(&m.relative_path)))
                .filter(|m| is_interesting_jar_non_class(&m.relative_path))
                .take(100),
        );

        let selected_count = selected.len();
        self.analyze_in_memory_member_refs(
            &selected,
            archive_path,
            report,
            start,
            "JAR archive",
            "memory JAR",
            vec![
                "archive_analyzer".to_string(),
                "in_memory_jar".to_string(),
                "java_class_analyzer".to_string(),
            ],
        );
        report.metadata.errors.push(format!(
            "JAR archive: {} total classes, {} YARA-flagged, {} selected for full analysis",
            total_class_files,
            flagged_classes.len(),
            selected_count
        ));
    }

    /// Analyze a CHM container entirely in memory. Decodes every internal
    /// file (LZX-decompressing the `MSCompressed/Content` blob in one
    /// shot) and feeds each user-visible entry to the same per-member
    /// pipeline used for ZIP archives. No bytes are written to disk.
    ///
    /// CHM members are by definition help-page payloads — HTML topics,
    /// embedded scripts, sometimes images. cleave's default archive
    /// policy skips "non-program" members (HTML, markdown) unless
    /// `--all-files` is set, but for CHM that policy throws away
    /// exactly the content we need to scan for HTML-Help dropper
    /// patterns. We forward to a clone of `self` whose analysis
    /// options have `all_files = true` so every member gets analyzed.
    pub(super) fn analyze_chm_archive_in_memory(
        &self,
        data: &[u8],
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        let (raw_members, traversals) = crate::analyzers::chm::collect_members(data)?;

        for path in traversals {
            guard.add_hostile_reason(HostileArchiveReason::PathTraversal(path));
        }

        let mut members = Vec::with_capacity(raw_members.len());
        for m in raw_members {
            if !guard.check_file_count() {
                anyhow::bail!(
                    "Exceeded maximum file count ({})",
                    super::guards::MAX_FILE_COUNT
                );
            }
            if m.data.len() as u64 > super::guards::MAX_FILE_SIZE {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                    file: m.relative_path.clone(),
                    size: m.data.len() as u64,
                });
                continue;
            }
            if !guard.check_bytes(m.data.len() as u64, &m.relative_path) {
                anyhow::bail!("Exceeded maximum total extraction size");
            }
            let logical = Path::new(&m.relative_path);
            let file_type = crate::analyzers::detect_file_type_from_data(logical, &m.data);
            let sha256 = calculate_sha256(&m.data);
            members.push(MemoryArchiveMember {
                relative_path: m.relative_path,
                data: m.data,
                file_type,
                sha256,
            });
        }

        // Force `all_files = true` for CHM member analysis. This is the
        // only knob that changes; everything else (depth, mapper, yara,
        // cancellation) carries over via `with_*` chaining.
        let chm_options = match self.analysis_options.as_ref() {
            Some(opts) => crate::AnalysisOptions {
                all_files: true,
                ..(**opts).clone()
            },
            None => crate::AnalysisOptions {
                all_files: true,
                ..Default::default()
            },
        };
        let chm_analyzer = self
            .with_extraction_archive_sha256("")
            .with_analysis_options(std::sync::Arc::new(chm_options));

        chm_analyzer.analyze_in_memory_members(
            &members,
            archive_path,
            report,
            start,
            "CHM archive",
            "memory CHM",
            vec!["archive_analyzer".to_string(), "in_memory_chm".to_string()],
        );
        Ok(())
    }

    /// Run the par_iter analysis + aggregation over a prebuilt
    /// `Vec<MemoryArchiveMember>`. Used by both the ZIP and PyInstaller
    /// in-memory paths.
    fn analyze_in_memory_members(
        &self,
        members: &[MemoryArchiveMember],
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        archive_label: &'static str,
        slow_log_label: &'static str,
        tools_used: Vec<String>,
    ) {
        let total_files = members.len();
        tracing::debug!(
            archive = %archive_path.display(),
            file_count = total_files,
            archive_label,
            "Starting in-memory archive member analysis"
        );

        let results: Vec<MemberAnalysisResult> = par_filter_map_if_outermost(members, |member| {
            self.analyze_one_member(member, slow_log_label)
        });

        self.aggregate_member_results(
            results,
            report,
            start,
            archive_label,
            tools_used,
            total_files,
        );
    }

    fn analyze_in_memory_member_refs(
        &self,
        members: &[&MemoryArchiveMember],
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        archive_label: &'static str,
        slow_log_label: &'static str,
        tools_used: Vec<String>,
    ) {
        let total_files = members.len();
        tracing::debug!(
            archive = %archive_path.display(),
            file_count = total_files,
            archive_label,
            "Starting borrowed in-memory archive member analysis"
        );

        let results: Vec<MemberAnalysisResult> = par_filter_map_if_outermost(members, |member| {
            self.analyze_one_member(member, slow_log_label)
        });

        self.aggregate_member_results(
            results,
            report,
            start,
            archive_label,
            tools_used,
            total_files,
        );
    }

    /// Analyze a single decompressed archive member. Pure per-member work —
    /// no aggregation. Safe to call from `par_iter` or sequentially as
    /// members stream in.
    fn analyze_one_member(
        &self,
        member: &MemoryArchiveMember,
        slow_log_label: &'static str,
    ) -> Option<MemberAnalysisResult> {
        let _thread_local_cache_clear_guard = ThreadLocalCacheClearGuard;
        if self.is_cancelled() {
            return None;
        }

        let entry_path = self.format_entry_path(&member.relative_path);
        let archive_location = self.format_evidence_location(&member.relative_path);
        let entry_metadata = ArchiveEntry {
            path: entry_path.clone(),
            file_type: member.file_type.report_file_type(),
            sha256: member.sha256.clone(),
            size_bytes: member.data.len() as u64,
            ..ArchiveEntry::default()
        };
        let member_start = std::time::Instant::now();
        let logical_path = Path::new(&member.relative_path);

        let member_report = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.analyze_extracted_member(
                logical_path,
                &member.relative_path,
                &member.data,
                &member.file_type,
                &member.sha256,
            )
        })) {
            Ok(Ok(Some(r))) => Some(r),
            Ok(Ok(None)) => None,
            Ok(Err(e)) => {
                debug!("Failed to analyze archive member {}: {}", entry_path, e);
                None
            }
            Err(_) => {
                tracing::error!(path = %entry_path, "panic during archive member analysis (caught)");
                FAILED_ANALYSES.fetch_add(1, Ordering::Relaxed);
                None
            }
        };

        let elapsed = member_start.elapsed();
        if elapsed.as_millis() > SLOW_ARCHIVE_MEMBER_ANALYSIS_MS {
            tracing::warn!(
                relative_path = %member.relative_path,
                file_type = %member.file_type.report_file_type(),
                size_bytes = member.data.len(),
                elapsed_ms = elapsed.as_millis() as u64,
                rayon_thread = ?rayon::current_thread_index(),
                "Slow archive member analysis ({})",
                slow_log_label,
            );
        }

        let extracted_path = self.sample_extraction.as_ref().and_then(|config| {
            let extract_relative_path = match &self.archive_path_prefix {
                Some(prefix) => format!("{}/{}", prefix.replace('!', "/"), member.relative_path),
                None => member.relative_path.clone(),
            };
            config
                .extract(&member.sha256, &extract_relative_path, &member.data)
                .map(|path| path.display().to_string())
        });

        Some(MemberAnalysisResult {
            entry_path,
            archive_location,
            entry_metadata,
            extracted_path,
            report: member_report,
        })
    }

    /// Aggregate per-member analysis results into the parent archive report.
    /// Splits findings, yara matches, strings, and nested archive entries
    /// across the appropriate top-level fields.
    fn aggregate_member_results(
        &self,
        results: Vec<MemberAnalysisResult>,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        archive_label: &'static str,
        tools_used: Vec<String>,
        total_files: usize,
    ) {
        let mut total_capabilities = HashSet::new();
        let mut total_traits = HashSet::new();
        let mut collected_traits = HashMap::<String, Finding>::with_capacity(total_files.min(500));
        let mut collected_yara = Vec::<YaraMatch>::with_capacity(100);
        let mut collected_strings = Vec::<StringInfo>::with_capacity((total_files * 2).min(200));
        let mut collected_archive_entries = Vec::<ArchiveEntry>::with_capacity(total_files);
        let mut collected_files = Vec::<FileAnalysis>::with_capacity(total_files);
        let mut files_analyzed = 0usize;

        for result in results {
            collected_archive_entries.push(result.entry_metadata);
            let Some(file_report) = result.report else {
                continue;
            };
            files_analyzed += 1;

            let (mut file_entry, nested_files, archive_contents) =
                file_report.into_file_analysis(0);
            file_entry.path = result.entry_path.clone();
            file_entry.depth = 1;
            file_entry.compute_summary();
            file_entry.extracted_path = result.extracted_path.clone();

            for f in &file_entry.findings {
                total_traits.insert(f.id.clone());
                total_capabilities.insert(f.id.clone());
                let mut new_finding = f.clone();
                for evidence in &mut new_finding.evidence {
                    match &evidence.location {
                        None => evidence.location = Some(result.archive_location.clone()),
                        Some(loc) if !loc.starts_with("archive:") => {
                            evidence.location =
                                Some(format!("{}:{}", result.archive_location, loc));
                        }
                        _ => {}
                    }
                }
                collected_traits
                    .entry(new_finding.id.clone())
                    .and_modify(|existing| {
                        if (new_finding.crit, new_finding.conf.total_cmp(&existing.conf))
                            > (existing.crit, std::cmp::Ordering::Equal)
                        {
                            *existing = new_finding.clone();
                        }
                    })
                    .or_insert(new_finding);
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

            collected_files.push(file_entry);
            collected_archive_entries.extend(archive_contents);
            for mut nested_file in nested_files {
                if !nested_file.path.contains("!!") {
                    nested_file.path = encode_archive_path(&result.entry_path, &nested_file.path);
                }
                nested_file.depth += 1;
                collected_files.push(nested_file);
            }
        }

        for (_, t) in collected_traits {
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
        report.metadata.errors.push(format!(
            "{}: {} members, {} analyzed, {} traits and {} capabilities detected",
            archive_label,
            total_files,
            files_analyzed,
            total_traits.len(),
            total_capabilities.len()
        ));
        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;
    }

    /// Analyze a PyInstaller-bundled executable entirely in memory. Decodes
    /// every CArchive entry and PYZ contents via the `pyinstx` crate, then
    /// feeds each as a [`MemoryArchiveMember`] into the same per-member
    /// pipeline used for ZIP archives.
    pub(super) fn analyze_pyinstaller_archive_in_memory(
        &self,
        data: &[u8],
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
    ) -> Result<()> {
        let mem = pyinstx::extract_to_memory(data)
            .map_err(|e| anyhow::anyhow!("pyinstx extract: {e}"))?;

        let members: Vec<MemoryArchiveMember> = mem
            .entries
            .iter()
            .map(|entry| {
                let logical = Path::new(&entry.name);
                let file_type = crate::analyzers::detect_file_type_from_data(logical, &entry.data);
                let sha256 = calculate_sha256(&entry.data);
                MemoryArchiveMember {
                    relative_path: entry.name.clone(),
                    data: entry.data.clone(),
                    file_type,
                    sha256,
                }
            })
            .collect();

        // Find the SHA-256 of the bundled Python shared library, if present.
        // Identifies the exact CPython distribution (official, embeddable,
        // conda, custom rebuild) — strong "who built this" signal.
        let bundled_python_lib_sha256 = mem.provenance.python_lib.as_deref().and_then(|name| {
            members
                .iter()
                .find(|m| m.relative_path == name)
                .map(|m| m.sha256.clone())
        });

        self.analyze_in_memory_members(
            &members,
            archive_path,
            report,
            start,
            "PyInstaller archive",
            "memory PyInstaller",
            vec!["archive_analyzer".to_string(), "pyinstx".to_string()],
        );

        // Build the `pyinstaller.*` KV subtree. Surfaces every provenance
        // signal we recovered from the cookie + TOC: who (entry-point script
        // names, bundled python-lib sha), what (per-type counts, totals,
        // dependencies, splash flag), when (python version, cookie format
        // version), where (runtime options that hint at intent — e.g.
        // `pyi-hide-console`).
        let prov = &mem.provenance;
        let mut kv = serde_json::Map::new();
        if let Some((maj, min)) = prov.python_version {
            kv.insert(
                "python_version".into(),
                serde_json::Value::String(format!("{maj}.{min}")),
            );
        }
        if let Some(lib) = &prov.python_lib {
            kv.insert("python_lib".into(), serde_json::Value::String(lib.clone()));
        }
        if let Some(sha) = bundled_python_lib_sha256 {
            kv.insert("python_lib_sha256".into(), serde_json::Value::String(sha));
        }
        kv.insert(
            "cookie_version".into(),
            serde_json::Value::String(prov.cookie_version.to_string()),
        );
        kv.insert(
            "toc_entry_count".into(),
            serde_json::Value::from(prov.toc_entry_count),
        );
        kv.insert(
            "compressed_size".into(),
            serde_json::Value::from(prov.compressed_size),
        );
        kv.insert(
            "uncompressed_size".into(),
            serde_json::Value::from(prov.uncompressed_size),
        );
        if prov.uncompressed_size > 0 {
            let ratio = prov.compressed_size as f64 / prov.uncompressed_size as f64;
            kv.insert(
                "compression_ratio".into(),
                serde_json::Value::from((ratio * 1000.0).round() / 1000.0),
            );
        }
        kv.insert(
            "has_splash".into(),
            serde_json::Value::Bool(prov.has_splash),
        );
        if !prov.entry_points.is_empty() {
            kv.insert(
                "entry_points".into(),
                serde_json::Value::Array(
                    prov.entry_points
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
        }
        if !prov.runtime_options.is_empty() {
            kv.insert(
                "runtime_options".into(),
                serde_json::Value::Array(
                    prov.runtime_options
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
        }
        if !prov.dependencies.is_empty() {
            kv.insert(
                "dependencies".into(),
                serde_json::Value::Array(
                    prov.dependencies
                        .iter()
                        .map(|s| serde_json::Value::String(s.clone()))
                        .collect(),
                ),
            );
        }
        if !prov.type_counts.is_empty() {
            let mut counts = serde_json::Map::new();
            for (tb, n) in &prov.type_counts {
                let key = String::from_utf8_lossy(&[*tb]).into_owned();
                counts.insert(key, serde_json::Value::from(*n));
            }
            kv.insert("type_counts".into(), serde_json::Value::Object(counts));
        }
        report.merge_kv_subtree("pyinstaller", serde_json::Value::Object(kv));

        if let Some((maj, min)) = mem.py_version {
            report
                .metadata
                .errors
                .push(format!("PyInstaller bundle: Python {maj}.{min}"));
        }
        Ok(())
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
    ) {
        // Find main class from MANIFEST.MF
        let main_class = find_main_class(temp_dir);
        if let Some(ref mc) = main_class {
            debug!("Main-Class: {}", mc);
        }

        // `jar.*` kv comes from filefacts's dual emission in the
        // capability mapper — no temp-dir walk needed here.

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
            // Serialize when already inside a rayon context so nested-depth
            // stays ≤ 1 (outer archive-member walk is already at depth 1).
            // Running a second `par_iter` here when nested commits sibling
            // slot-pool workers to JAR YARA scans and can starve the outer
            // reaper on small pools.
            let yara_results = par_filter_map_if_outermost(&class_files, |entry| {
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
            });
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
        let mut collected_traits =
            HashMap::<String, Finding>::with_capacity(expected_count.min(500));
        let mut collected_yara = Vec::<YaraMatch>::with_capacity(50);
        let mut collected_strings = Vec::<StringInfo>::with_capacity((expected_count * 2).min(200));
        let mut collected_archive_entries = Vec::<ArchiveEntry>::with_capacity(expected_count);
        let mut collected_files = Vec::<FileAnalysis>::with_capacity(expected_count);
        let mut files_analyzed: usize = 0;

        let members_done = std::sync::atomic::AtomicUsize::new(0);
        let last_progress_ms = AtomicU64::new(0);
        let jar_display = self
            .archive_path_prefix
            .as_deref()
            .unwrap_or(report.target.path.as_str());

        let member_results: Vec<MemberAnalysisResult> =
            par_filter_map_if_outermost(&classes_to_analyze, |entry| {
                let _thread_local_cache_clear_guard = ThreadLocalCacheClearGuard;
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
                    ..ArchiveEntry::default()
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

                let done = members_done.fetch_add(1, Ordering::Relaxed) + 1;
                let elapsed_ms = start.elapsed().as_millis() as u64;
                if should_log_progress(done, expected_count, elapsed_ms, &last_progress_ms) {
                    tracing::info!(
                        archive = jar_display,
                        progress = %format!("{done}/{expected_count}"),
                        total_elapsed_ms = elapsed_ms,
                        "jar member analysis progress",
                    );
                }

                Some(MemberAnalysisResult {
                    entry_path,
                    archive_location,
                    entry_metadata,
                    extracted_path: None,
                    report,
                })
            });

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

            // Aggregate findings — keep highest (crit, conf) per trait ID
            for f in &file_report.findings {
                total_traits.insert(f.id.clone());
                total_capabilities.insert(f.id.clone());
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
                collected_traits
                    .entry(new_finding.id.clone())
                    .and_modify(|existing| {
                        if (new_finding.crit, new_finding.conf.total_cmp(&existing.conf))
                            > (existing.crit, std::cmp::Ordering::Equal)
                        {
                            *existing = new_finding.clone();
                        }
                    })
                    .or_insert(new_finding);
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

        let member_count = non_class_files.len();
        let members_done = std::sync::atomic::AtomicUsize::new(0);
        let last_progress_ms = AtomicU64::new(0);
        let analysis_start = std::time::Instant::now();

        let archive_display: &str = self
            .archive_path_prefix
            .as_deref()
            .unwrap_or(report.target.path.as_str());

        tracing::info!(
            archive = archive_display,
            members = member_count,
            depth = self.current_depth,
            "starting parallel archive member analysis",
        );

        let non_class_results: Vec<MemberAnalysisResult> =
            par_filter_map_if_outermost(&non_class_files, |entry| {
                let _thread_local_cache_clear_guard = ThreadLocalCacheClearGuard;
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
                    ..ArchiveEntry::default()
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

                let done = members_done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let member_ms = member_start.elapsed().as_millis();
                if member_ms > 5000 {
                    tracing::warn!(
                        archive = archive_display,
                        member = %entry_path,
                        file_type = %file_type.report_file_type(),
                        size_kb = file_data.len() / 1024,
                        elapsed_ms = member_ms,
                        progress = %format!("{done}/{member_count}"),
                        rayon_thread = rayon::current_thread_index().unwrap_or(usize::MAX),
                        "slow archive member analysis",
                    );
                } else {
                    let elapsed_ms = analysis_start.elapsed().as_millis() as u64;
                    if should_log_progress(done, member_count, elapsed_ms, &last_progress_ms) {
                        tracing::info!(
                            archive = archive_display,
                            progress = %format!("{done}/{member_count}"),
                            total_elapsed_ms = elapsed_ms,
                            "archive member analysis progress",
                        );
                    }
                }

                Some(MemberAnalysisResult {
                    entry_path,
                    archive_location,
                    entry_metadata,
                    extracted_path: None,
                    report,
                })
            });

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
                collected_traits
                    .entry(new_finding.id.clone())
                    .and_modify(|existing| {
                        if (new_finding.crit, new_finding.conf.total_cmp(&existing.conf))
                            > (existing.crit, std::cmp::Ordering::Equal)
                        {
                            *existing = new_finding.clone();
                        }
                    })
                    .or_insert(new_finding);
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
        for (_, t) in collected_traits {
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
    ) {
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
        let mut collected_traits = HashMap::<String, Finding>::with_capacity(total_files.min(500));
        let mut collected_yara = Vec::<YaraMatch>::with_capacity(100);
        let mut collected_strings = Vec::<StringInfo>::with_capacity((total_files * 2).min(200));
        let mut collected_archive_entries = Vec::<ArchiveEntry>::with_capacity(total_files);
        let mut collected_files = Vec::<FileAnalysis>::with_capacity(total_files);
        let mut files_analyzed: usize = 0;

        // Analyze files in parallel — no shared Mutexes. Nested rayon calls
        // (analyze_extracted_member → rayon::join, scan_bytes → par_iter) are
        // handled by work-stealing; the outer worker participates in inner tasks.
        tracing::debug!(
            file_count = total_files,
            on_rayon_thread = rayon::current_thread_index().is_some(),
            "Starting parallel archive member analysis"
        );
        let generic_results: Vec<MemberAnalysisResult> =
            par_filter_map_if_outermost(&files, |entry| {
                let _thread_local_cache_clear_guard = ThreadLocalCacheClearGuard;
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
                    ..ArchiveEntry::default()
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

                let extracted_path = self.sample_extraction.as_ref().and_then(|config| {
                    let extract_relative_path = match &self.archive_path_prefix {
                        Some(prefix) => {
                            format!("{}/{}", prefix.replace('!', "/"), relative_path)
                        }
                        None => relative_path.clone(),
                    };
                    config
                        .extract(&sha256, &extract_relative_path, &file_data)
                        .map(|path| path.display().to_string())
                });

                Some(MemberAnalysisResult {
                    entry_path,
                    archive_location,
                    entry_metadata,
                    extracted_path,
                    report,
                })
            });

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
            file_entry.extracted_path = result.extracted_path.clone();

            // Aggregate findings — keep highest (crit, conf) per trait ID
            for f in &file_entry.findings {
                total_traits.insert(f.id.clone());
                total_capabilities.insert(f.id.clone());
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
                collected_traits
                    .entry(new_finding.id.clone())
                    .and_modify(|existing| {
                        if (new_finding.crit, new_finding.conf.total_cmp(&existing.conf))
                            > (existing.crit, std::cmp::Ordering::Equal)
                        {
                            *existing = new_finding.clone();
                        }
                    })
                    .or_insert(new_finding);
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
        for (_, t) in collected_traits {
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

        // Emit the `archive.*` kv subtree (members + aggregates) so traits
        // can match on archive contents and shape. See
        // [`AnalysisReport::seal_archive_metadata_kv`] for the field layout.
        report.seal_archive_metadata_kv();

        // Add metadata about archive contents
        report.metadata.errors.push(format!(
            "Archive contains {} files analyzed, {} traits and {} capabilities detected",
            files_analyzed,
            total_traits.len(),
            total_capabilities.len()
        ));

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["archive_analyzer".to_string(), "walkdir".to_string()];
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
