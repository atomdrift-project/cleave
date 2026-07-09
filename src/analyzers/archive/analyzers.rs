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

use super::ArchiveAnalyzer;
use super::guards::{
    CancellableReader, ExtractionGuard, HostileArchiveReason, LimitedReader, MAX_FILE_SIZE,
    MAX_PATH_COMPONENT_LEN, sanitize_entry_path, symlink_escapes,
};
use super::utils::{calculate_sha256, find_main_class, is_benign_java_path};
use crate::analyzers::{
    AnalysisInput, FileType, FileTypeExt, detect_file_type, detect_file_type_from_path,
};
use crate::types::{
    AnalysisReport, ArchiveEntry, FileAnalysis, Finding, TargetInfo, YaraMatch, encode_archive_path,
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

/// Filter-map `items` in parallel for the top archive, sequentially for nested
/// archives.
///
/// `parallel` is [`ArchiveAnalyzer::members_run_parallel`]. The top archive fans its
/// members across the rayon pool so an idle worker can steal member work via
/// rayon's work-stealing — that is "parallel when slots are free, serial when
/// they're not", and it fills the long tail of a directory scan when only one
/// big archive remains (the other scan threads would otherwise sit idle). It
/// does *not* depend on being the outermost rayon context: under `cleave scan`'s
/// `par_bridge` walk (or a litmus slot pool) the top archive is already inside a
/// rayon thread, yet still benefits from fanning members out to drain the tail.
///
/// Nested archives (`depth >= 1`) stay serial: their members already run inside
/// a parallel member task, so a second fan-out level only deepens rayon nesting
/// — extra deadlock pressure on small pools (litmus runs 4-thread slots sized
/// precisely for the recursion chain) — without exposing usable parallelism.
fn par_filter_map_members<T, U, F>(items: &[T], parallel: bool, f: F) -> Vec<U>
where
    T: Sync,
    U: Send,
    F: Fn(&T) -> Option<U> + Sync + Send,
{
    // Stack-overflow guard: a rayon worker blocked in a nested join (e.g. a
    // member's scan_bytes par_iter) steals whatever task is pending — on a
    // shared pool that includes *other* in-flight analyses' member tasks — and
    // runs it on top of its current stack. Each stolen task can block and
    // steal again, so frames from independent deep analyses compound without
    // bound; no fixed thread stack survives that (litmus overflowed 64 MB
    // with 4 large archives in flight). maybe_grow moves the member task onto
    // a fresh heap-allocated stack segment whenever headroom is low, making
    // the compounding harmless. The red zone must cover one member's full
    // sequential chain (including in-place nested-archive recursion, capped at
    // depth 3) since the next check only happens at the next member boundary.
    // When headroom is fine the call is a thread-local read and a compare.
    const MEMBER_RED_ZONE: usize = 64 * 1024 * 1024;
    const MEMBER_GROWN_STACK: usize = 128 * 1024 * 1024;
    let f = |item: &T| stacker::maybe_grow(MEMBER_RED_ZONE, MEMBER_GROWN_STACK, || f(item));
    if parallel {
        items.par_iter().filter_map(f).collect()
    } else {
        items.iter().filter_map(f).collect()
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
    container_kind: Option<String>,
}

fn archive_entry_metadata(
    entry_path: String,
    logical_path: &Path,
    file_type: &FileType,
    sha256: String,
    data: &[u8],
    container_kind: Option<String>,
) -> ArchiveEntry {
    let declared_file_type = detect_file_type_from_path(logical_path);
    let declared_type =
        (declared_file_type != FileType::Unknown).then(|| declared_file_type.report_file_type());
    let extension_type_mismatch = declared_type.is_some() && declared_file_type != *file_type;

    ArchiveEntry {
        path: entry_path,
        file_type: file_type.report_file_type(),
        sha256,
        size_bytes: data.len() as u64,
        declared_type,
        extension_type_mismatch,
        entropy: byte_entropy(data),
        magic_prefix: magic_prefix(data),
        container_kind,
        ..ArchiveEntry::default()
    }
}

fn byte_entropy(data: &[u8]) -> Option<f64> {
    if data.is_empty() {
        return None;
    }

    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let entropy = counts
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum::<f64>();

    Some((entropy * 1000.0).round() / 1000.0)
}

fn magic_prefix(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    let mut out = String::with_capacity(data.len().min(8) * 2);
    for byte in data.iter().take(8) {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    Some(out)
}

fn pyinstaller_entry_kind(kind: pyinstx::EntryKind) -> &'static str {
    match kind {
        pyinstx::EntryKind::PySource => "py-source",
        pyinstx::EntryKind::PyModule => "py-module",
        pyinstx::EntryKind::PyzMember => "pyz-member",
        pyinstx::EntryKind::Splash => "splash",
        pyinstx::EntryKind::Binary => "binary",
    }
}

fn push_optional_string(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &Option<String>,
) {
    if let Some(value) = value {
        obj.insert(key.to_string(), serde_json::Value::String(value.clone()));
    }
}

fn archive_entry_json(entry: &ArchiveEntry) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("path".into(), serde_json::Value::String(entry.path.clone()));
    obj.insert(
        "type".into(),
        serde_json::Value::String(entry.file_type.clone()),
    );
    obj.insert(
        "sha256".into(),
        serde_json::Value::String(entry.sha256.clone()),
    );
    obj.insert(
        "size_bytes".into(),
        serde_json::Value::Number(entry.size_bytes.into()),
    );
    push_optional_string(&mut obj, "declared_type", &entry.declared_type);
    if entry.extension_type_mismatch {
        obj.insert(
            "extension_type_mismatch".into(),
            serde_json::Value::Bool(true),
        );
    }
    if let Some(entropy) = entry.entropy
        && let Some(number) = serde_json::Number::from_f64(entropy)
    {
        obj.insert("entropy".into(), serde_json::Value::Number(number));
    }
    push_optional_string(&mut obj, "magic_prefix", &entry.magic_prefix);
    push_optional_string(&mut obj, "container_kind", &entry.container_kind);
    serde_json::Value::Object(obj)
}

/// Streaming accumulator for per-member analysis results.
///
/// Folds each member's result into deduplicated aggregate state and drops the
/// (large) member `AnalysisReport` immediately. This lets an archive's members
/// be analyzed in bounded byte-windows without ever holding every member's
/// report resident at once — the dominant per-archive memory term on
/// member-heavy archives (e.g. a 4 MB wheel with thousands of members).
#[derive(Default)]
struct MemberAccumulator {
    /// Distinct finding ids seen across all members. Reported as both the trait
    /// and capability tally (the two are identical — every finding id counts as
    /// one of each), kept once rather than in two parallel sets.
    distinct_finding_ids: HashSet<String>,
    collected_traits: HashMap<String, Finding>,
    collected_yara: Vec<YaraMatch>,
    collected_archive_entries: Vec<ArchiveEntry>,
    collected_files: Vec<FileAnalysis>,
    files_analyzed: usize,
}

impl MemberAccumulator {
    /// Fold one member's result into the aggregate, consuming and dropping it.
    /// Member order is preserved because callers fold windows sequentially and
    /// each window's `par_iter` collect is index-ordered.
    fn fold(&mut self, result: MemberAnalysisResult) {
        self.collected_archive_entries.push(result.entry_metadata);
        let Some(file_report) = result.report else {
            return;
        };
        self.files_analyzed += 1;

        // Aggregate member YARA matches from the report *before* conversion:
        // `into_file_analysis` does not carry `yara_matches` onto the
        // FileAnalysis, so reading it post-conversion would silently see none.
        for yara_match in &file_report.yara_matches {
            if self.collected_yara.len() >= 1_000 {
                break;
            }
            if !self
                .collected_yara
                .iter()
                .any(|m| m.rule == yara_match.rule)
            {
                self.collected_yara.push(yara_match.clone());
            }
        }

        let (mut file_entry, nested_files, archive_contents) = file_report.into_file_analysis(0);
        file_entry.path = result.entry_path.clone();
        file_entry.depth = 1;
        file_entry.compute_summary();
        file_entry.extracted_path = result.extracted_path.clone();

        for f in &file_entry.findings {
            self.distinct_finding_ids.insert(f.id.clone());
            let mut new_finding = f.clone();
            for evidence in &mut new_finding.evidence {
                match &evidence.location {
                    None => evidence.location = Some(result.archive_location.clone()),
                    Some(loc) if !loc.starts_with("archive:") => {
                        evidence.location = Some(format!("{}:{}", result.archive_location, loc));
                    }
                    _ => {}
                }
            }
            self.collected_traits
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

        // Member strings (URLs/IPs/base64) are deliberately NOT hoisted onto the
        // parent. Each member keeps its own strings on its FileAnalysis record;
        // pulling them up made the parent's `type: text` trait evaluation re-match
        // member content with no way to attribute it back, producing findings on
        // the archive itself (e.g. a `jsonkeeper.com` URL decoded from a member)
        // with member-relative offsets meaningless in the archive's byte space.
        // Only traits roll up to the parent — carrying their member `from`.
        self.collected_files.push(file_entry);
        self.collected_archive_entries.extend(archive_contents);
        for mut nested_file in nested_files {
            if !nested_file.path.contains("!!") {
                nested_file.path = encode_archive_path(&result.entry_path, &nested_file.path);
            }
            nested_file.depth += 1;
            self.collected_files.push(nested_file);
        }
    }

    /// Sort the collected member files by descending peak severity, then cap the
    /// count. Generic archives surface their most severe members first under a
    /// hard ceiling; formats that keep insertion order simply don't call this.
    fn sort_files_by_severity(&mut self, limit: usize) {
        // `cached_key` computes each file's peak once rather than on every
        // comparison; `Reverse` gives descending order while staying stable.
        self.collected_files.sort_by_cached_key(|f| {
            std::cmp::Reverse(f.findings.iter().map(|f| f.crit).max().unwrap_or_default())
        });
        self.collected_files.truncate(limit);
    }

    /// Drain the deduplicated aggregate into the parent report, returning the
    /// tallies each archive type folds into its own summary line. Writes no
    /// metadata — callers append their format-specific summary and tools after.
    fn merge_into(self, report: &mut AnalysisReport) -> MemberCounts {
        let distinct = self.distinct_finding_ids.len();
        let counts = MemberCounts {
            files_analyzed: self.files_analyzed,
            trait_count: distinct,
            capability_count: distinct,
        };
        // Dedup against what the container already holds via sets, not a linear
        // rescan per item (archives can carry thousands of distinct findings).
        let mut seen_ids: HashSet<String> = report.findings.iter().map(|f| f.id.clone()).collect();
        for (_, t) in self.collected_traits {
            if seen_ids.insert(t.id.clone()) {
                report.findings.push(t);
            }
        }
        let mut seen_rules: HashSet<String> =
            report.yara_matches.iter().map(|m| m.rule.clone()).collect();
        for ym in self.collected_yara {
            if seen_rules.insert(ym.rule.clone()) {
                report.yara_matches.push(ym);
            }
        }
        report
            .archive_contents
            .extend(self.collected_archive_entries);
        report.files.extend(self.collected_files);
        counts
    }

    /// Merge the deduplicated aggregate into the parent report and write the
    /// generic archive-level metadata. Called once per archive after all members
    /// fold (the windowed ZIP/ASAR path); JAR and generic archives build their
    /// own summary lines from [`MemberAccumulator::merge_into`] instead.
    fn finalize(
        self,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        archive_label: &'static str,
        tools_used: Vec<String>,
        total_files: usize,
    ) {
        let MemberCounts {
            files_analyzed,
            trait_count,
            capability_count,
        } = self.merge_into(report);
        report.metadata.errors.push(format!(
            "{archive_label}: {total_files} members, {files_analyzed} analyzed, \
             {trait_count} traits and {capability_count} capabilities detected"
        ));
        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;
    }
}

/// Per-archive tallies returned by [`MemberAccumulator::merge_into`] — each
/// archive format folds these into its own summary line.
struct MemberCounts {
    files_analyzed: usize,
    trait_count: usize,
    capability_count: usize,
}

/// Resident-byte budget for one member window. Caps how much decompressed
/// member data co-resides; tunable via `CLEAVE_MEMBER_WINDOW_MB`.
fn member_window_bytes() -> usize {
    const DEFAULT_MB: usize = 32;
    std::env::var("CLEAVE_MEMBER_WINDOW_MB")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|mb| *mb > 0)
        .unwrap_or(DEFAULT_MB)
        .saturating_mul(1024 * 1024)
}

/// Minimum batch size at which a *nested* archive's members fan out across the
/// rayon pool; smaller batches run serially on the analysis's own task. The
/// member window caps batches at [`member_window_count`] (256), so member-heavy
/// nested archives hit this threshold window after window while small wheels
/// and condas never do. Tunable via `CLEAVE_NESTED_PARALLEL_MIN_MEMBERS`.
fn nested_parallel_min_members() -> usize {
    const DEFAULT: usize = 64;
    static MIN: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *MIN.get_or_init(|| {
        std::env::var("CLEAVE_NESTED_PARALLEL_MIN_MEMBERS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT)
    })
}

/// Maximum members held in one window. Caps the per-window report transient
/// (each window's `par_iter` collects this many full reports before folding)
/// independent of member size; tunable via `CLEAVE_MEMBER_WINDOW_COUNT`.
fn member_window_count() -> usize {
    const DEFAULT: usize = 256;
    std::env::var("CLEAVE_MEMBER_WINDOW_COUNT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT)
}

/// Byte-windowed member analysis driver.
///
/// Members are pushed in; when the resident window exceeds the byte budget or
/// the member-count cap, the window is analyzed in parallel, folded into the
/// accumulator, and dropped. This bounds both resident decompressed bytes and
/// the per-window report transient, replacing the old all-members-resident
/// depth-0 path (which held every member's data and report at once) and the
/// fully-serial depth>=1 path with one memory-bounded, parallel path.
struct MemberWindow<'a> {
    analyzer: &'a ArchiveAnalyzer,
    acc: MemberAccumulator,
    window: Vec<MemoryArchiveMember>,
    window_bytes: usize,
    budget_bytes: usize,
    max_count: usize,
    total: usize,
    slow_log_label: &'static str,
}

impl<'a> MemberWindow<'a> {
    fn new(analyzer: &'a ArchiveAnalyzer, slow_log_label: &'static str) -> Self {
        Self {
            analyzer,
            acc: MemberAccumulator::default(),
            window: Vec::new(),
            window_bytes: 0,
            budget_bytes: member_window_bytes(),
            max_count: member_window_count(),
            total: 0,
            slow_log_label,
        }
    }

    /// Add a member, flushing the window first if it is already full.
    fn push(&mut self, member: MemoryArchiveMember) {
        self.total += 1;
        self.window_bytes += member.data.len();
        self.window.push(member);
        if self.window_bytes >= self.budget_bytes || self.window.len() >= self.max_count {
            self.flush();
        }
    }

    /// Analyze the current window in parallel, fold results, drop the buffers.
    fn flush(&mut self) {
        if self.window.is_empty() {
            return;
        }
        let analyzer = self.analyzer;
        let label = self.slow_log_label;
        let parallel = analyzer.members_run_parallel(self.window.len());
        let results = par_filter_map_members(&self.window, parallel, |member| {
            analyzer.analyze_one_member(member, label)
        });
        for result in results {
            self.acc.fold(result);
        }
        self.window.clear();
        self.window_bytes = 0;
    }

    /// Flush any remainder and merge the aggregate into the parent report.
    fn finalize(
        mut self,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        archive_label: &'static str,
        tools_used: Vec<String>,
    ) {
        self.flush();
        self.acc
            .finalize(report, start, archive_label, tools_used, self.total);
    }
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

const SLOW_ARCHIVE_MEMBER_YARA_MS: u128 = 4_000;

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
        // Skip the YARA pass for any member with no filetype→tier mapping — an
        // unidentified blob, or a type with no targeted tier (lockfiles, Clojure,
        // Beam, ODF, …). Such a member would otherwise scan with a `None` filter
        // and hit EVERY tier, materializing all per-filetype rule sets into memory
        // (the cold-start blow-up) for little signal. The member's string / trait
        // / encoded-payload analysis still runs; only the YARA scan is skipped.
        // Mirrors the scan-side filter below, which also keys off
        // `archive_member_yara_filetypes` being empty.
        if Self::archive_member_yara_filetypes(file_type).is_empty() {
            return Some("no targeted YARA tier for file type");
        }

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

    /// Whether this archive's members should be analyzed in parallel.
    ///
    /// The top archive (`depth == 0`) fans its members across the rayon pool, so
    /// an idle scan worker steals member work via work-stealing — parallel when
    /// slots are free, effectively serial when they're not — which drains the
    /// long tail of a directory scan when only one big archive remains. Memory
    /// is not a reason to serialize here: a single top-level analysis has RAM to
    /// spare, and litmus bounds the memory of *concurrent* top-level analyses
    /// with its admission controller, not by streaming one member at a time.
    ///
    /// Whether a batch of `member_count` members runs parallel at this depth.
    ///
    /// Depth 0 always fans out. Nested archives (`depth >= 1`) fan out only for
    /// member-heavy batches; small ones stay serial. Both halves are measured:
    ///
    /// - Member-heavy nested archives are the real-world long poles — the most
    ///   member-dense packages are containers-in-containers (src.rpm → tar,
    ///   deb → data.tar, conda → tar.zst), and serial members ran a 10k-member
    ///   tar.xz inside an rpm on ONE thread for 477 s while >70 cores idled.
    ///   Worse, any thread that work-stole that indivisible serial chunk
    ///   stalled its own analysis for the full duration (LIFO stacking).
    ///   Fanning these out drains the long pole and shrinks the largest
    ///   stealable unit to one member.
    /// - Small nested archives (wheels, condas — dozens of members) gain
    ///   nothing from fan-out and pay for it: unconditional nested parallelism
    ///   measured +11% wall on the mixed realworld benchmark, consistent with
    ///   scheduling overhead plus per-thread YARA scanner-cache thrash when
    ///   mixed member types spread across every pool thread.
    ///
    /// The historical reason nested was *always* serial — deadlock pressure on
    /// litmus's tiny 4-thread per-slot pools — is gone: on the shared
    /// process-global pool work-stealing joins cannot deadlock, the `stacker`
    /// red-zone absorbs stolen-frame stack compounding, and the member window
    /// bounds in-flight bytes. `CLEAVE_NESTED_PARALLEL_MIN_MEMBERS` tunes the
    /// crossover; `CLEAVE_SERIAL_NESTED_MEMBERS=1` forces the old always-serial
    /// behavior for A/B runs.
    fn members_run_parallel(&self, member_count: usize) -> bool {
        if self.current_depth == 0 {
            return true;
        }
        static SERIAL_NESTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if *SERIAL_NESTED
            .get_or_init(|| std::env::var("CLEAVE_SERIAL_NESTED_MEMBERS").is_ok_and(|v| v == "1"))
        {
            return false;
        }
        member_count >= nested_parallel_min_members()
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

        // Breadcrumb so a wedge dump can name which member this pool thread is
        // analyzing. This is the universal per-member chokepoint (every archive
        // path and the nested-archive recursion routes through it), so the top
        // archive's members — fanned across the whole rayon pool — are all named.
        let _breadcrumb = crate::breadcrumb::scope("member", relative_path);

        if let Some(reason) = self.archive_member_analysis_skip_reason(file_type) {
            tracing::debug!(
                relative_path,
                file_type = %file_type.report_file_type(),
                reason,
                "Skipping archive member analysis"
            );
            return Ok(None);
        }

        if !file_type.is_archive()
            && let Some(ref yara_engine) = self.yara_engine
            && Self::archive_member_yara_skip_reason(relative_path, file_type, data.len()).is_none()
        {
            let yara_engine = yara_engine.clone();
            let yara_filetypes = Self::archive_member_yara_filetypes(file_type);
            rayon::spawn(move || {
                if yara_filetypes.is_empty() {
                    yara_engine.prewarm_filetypes(None);
                } else {
                    yara_engine.prewarm_filetypes(Some(&yara_filetypes));
                }
            });
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
                // a 256 MB global pool), and par_filter_map_members grows onto
                // a fresh heap segment when headroom runs low, so we don't
                // need the 8 MB std::thread for stack headroom.
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

            // Archive members get the SAME string-extraction treatment as a
            // standalone file (`lib.rs` uses `stng_analysis_opts` for every
            // non-archive input). The previous code downgraded text/script
            // members to `stng_text_opts`, which sets `FormatHint::Text` and
            // SKIPS stng's XOR scan — silently dropping XOR-obfuscated payload
            // detection on exactly the files attackers bury inside archives
            // (npm tarballs, zips, jars). XOR/base64 detection parity with the
            // standalone path matters far more than the per-member scan cost;
            // an inconsistency that weakens detection only for archived content
            // is a security hole. `skip_rizin_reason` still governs the rizin
            // (binary disassembly) skip below — that's correct for non-native
            // members — but it must NOT also gate string extraction.
            crate::memory_tracker::set_current_phase(format!("strings on {relative_path}"));
            // Normalize UTF-16 (LE/BE BOM) member content to UTF-8 before string
            // extraction and trait matching, mirroring the standalone path in
            // `lib.rs`. Without this a UTF-16 script inside an archive is
            // null-interleaved at the byte level (`E\0x\0e\0c\0...`) and no
            // `type: text` trait matches. The member SHA is computed separately
            // from the original bytes, so identity is unchanged.
            let normalized_member = crate::file_io::normalize_text_encoding(data);
            let data: &[u8] = normalized_member.as_ref();
            let logical_path = Path::new(relative_path);
            // filefacts is the string authority and the parser: open the
            // member once and thread it into the analyzer (below) so it is
            // parsed a single time, regardless of member type.
            let _rizin_disable = skip_rizin_reason.map(|_| filefacts::rizin::scoped_disable());
            let member_ctx =
                crate::analysis_context::AnalysisContext::open(logical_path, data).ok();
            let stng_strings: std::sync::Arc<[stng::ExtractedString]> = member_ctx
                .as_ref()
                .map(crate::analysis_context::AnalysisContext::text_rows)
                .unwrap_or_default();
            crate::memory_tracker::clear_current_phase();
            let payloads = if extract_payloads {
                crate::extractors::encoded_payload::extract_encoded_payloads(&stng_strings)
            } else {
                Vec::new()
            };
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
            if let Some(ctx) = member_ctx {
                input = input.with_parsed_ctx(ctx);
            }
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

            // Attach the filefacts view for any member analyzer that didn't,
            // reusing the member context opened above (no re-parse) — so a
            // member's declared references (e.g. a package.json's dependencies)
            // are never lost to an analyzer that forgets. Mirrors the standalone
            // safety net in `analyze`. Gated on `is_none` so analyzers that
            // already attach keep theirs.
            if report.filefacts.is_none()
                && let Some(ctx) = input.parsed_ctx.as_ref()
            {
                let view = crate::types::FilefactsView::from_ctx(ctx);
                if !view.is_empty() {
                    report.filefacts = Some(view);
                }
            }

            // Run the SAME encoded-payload analysis the standalone path runs
            // (`process_encoded_payloads` in lib.rs): emit the
            // `metadata/encoded-payload/*` finding for each payload and
            // recursively analyze the decoded bytes, merging decoded
            // traits/findings back. Without this an obfuscated payload inside an
            // archive member (npm tarball, zip, jar) silently lost its
            // encoded-payload finding and every trait derived from the decoded
            // content — detection that the same file gets when scanned
            // standalone. Guarded on the mapper + options the recursion needs;
            // `payloads` was extracted above (empty when extract_payloads=false,
            // making this a no-op). `payloads` is moved — `input` (which
            // borrowed it) is no longer used after `analyze_input` above.
            if !payloads.is_empty()
                && let (Some(mapper), Some(opts)) = (
                    self.capability_mapper.as_ref(),
                    self.analysis_options.as_ref(),
                )
            {
                crate::process_encoded_payloads(
                    payloads,
                    &mut report,
                    logical_path,
                    data,
                    *file_type,
                    (self.current_depth + 1) as u32,
                    opts,
                    mapper,
                    self.yara_engine.as_ref(),
                );
            }

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

            // Capture this member's context windows from its OWN bytes, mirroring
            // the standalone path (lib.rs, after dedupe). The member's evidence
            // offsets index these decompressed bytes, not the container's, so
            // without a per-member capture the member would carry findings but no
            // byte/line context. Rides up into `files[].context` via
            // `into_file_analysis`.
            report.dedupe_findings();
            crate::context::capture(&mut report, data, *file_type);
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
        // JAR main-class detection needs the full member list, so JARs keep the
        // all-resident path; everything else streams through a byte-windowed
        // accumulator that never holds more than one window of members resident.
        let is_jar = matches!(
            crate::analyzers::detect_file_type(archive_path),
            Ok(FileType::Jar)
        );
        let mut window = MemberWindow::new(self, "filefacts ZIP index");
        let mut jar_members: Vec<MemoryArchiveMember> = Vec::new();

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
                if let Some(target_str) = target.as_deref()
                    && symlink_escapes(&outpath, target_str, fake_root)
                {
                    guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(format!(
                        "{} -> {}",
                        entry_name, target_str
                    )));
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
                container_kind: None,
            };
            if is_jar {
                jar_members.push(member);
            } else {
                window.push(member);
            }
        }

        if is_jar {
            self.analyze_jar_members_in_memory(&jar_members, archive_path, report, start);
        } else {
            window.finalize(
                report,
                start,
                "ZIP archive",
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

        // Members stream through a byte-windowed accumulator: each window is
        // analyzed in parallel then dropped, so resident decompressed bytes and
        // the report transient stay bounded regardless of member count. JARs
        // need the full member list for main-class detection, so they keep the
        // all-resident path.
        let is_jar = matches!(
            crate::analyzers::detect_file_type(archive_path),
            Ok(FileType::Jar)
        );
        let mut window = MemberWindow::new(self, "memory ZIP");
        let mut jar_members: Vec<MemoryArchiveMember> = Vec::new();

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

            if let Some(mode) = entry.unix_mode()
                && mode & 0o170000 == 0o120000
            {
                let mut target_buf = Vec::new();
                let mut limited = LimitedReader::new(&mut entry, 4096);
                let mut linkname_capture: Option<String> = None;
                if let Ok(read_size) = limited.read_to_end(&mut target_buf)
                    && read_size > 0
                    && read_size < 4096
                    && let Ok(target_str) = String::from_utf8(target_buf)
                {
                    if symlink_escapes(&outpath, &target_str, fake_root) {
                        guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape(format!(
                            "{} -> {}",
                            entry_name, target_str
                        )));
                    }
                    linkname_capture = Some(target_str);
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
                container_kind: None,
            };
            if is_jar {
                jar_members.push(member);
            } else {
                window.push(member);
            }
        }

        if is_jar {
            self.analyze_jar_members_in_memory(&jar_members, archive_path, report, start);
        } else {
            window.finalize(
                report,
                start,
                "ZIP archive",
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
            let yara_results = par_filter_map_members(
                &class_members,
                self.members_run_parallel(class_members.len()),
                |member| {
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
                },
            );
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
                container_kind: None,
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

    /// Analyze an Electron ASAR container in memory. ASAR member data is
    /// stored uncompressed after the header, so each addressable member can be
    /// sliced directly and routed through normal file-type detection.
    pub(super) fn analyze_asar_archive_in_memory(
        &self,
        data: &[u8],
        _archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        guard: &ExtractionGuard,
    ) -> Result<()> {
        let entries = super::asar::collect_entries(data)?;
        let fake_root = Path::new("/__cleave_archive__");
        let mut window = MemberWindow::new(self, "memory ASAR");

        for entry in entries {
            if self.is_cancelled() {
                anyhow::bail!("Analysis cancelled during ASAR member read");
            }
            if !guard.check_file_count() {
                anyhow::bail!(
                    "Exceeded maximum file count ({})",
                    super::guards::MAX_FILE_COUNT
                );
            }
            if entry.path.len() > MAX_PATH_COMPONENT_LEN {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveEntryName {
                    len: entry.path.len(),
                    preview: entry.path.chars().take(80).collect(),
                });
            }

            let Some(outpath) = sanitize_entry_path(&entry.path, fake_root) else {
                guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry.path));
                continue;
            };
            let relative_path = outpath
                .strip_prefix(fake_root)
                .unwrap_or(&outpath)
                .to_string_lossy()
                .replace('\\', "/");

            if entry.size > MAX_FILE_SIZE {
                guard.add_hostile_reason(HostileArchiveReason::ExcessiveFileSize {
                    file: entry.path,
                    size: entry.size,
                });
                continue;
            }

            let start_offset = usize::try_from(entry.data_offset).map_err(|e| {
                anyhow::anyhow!("ASAR member offset exceeds addressable memory: {e}")
            })?;
            let member_size = usize::try_from(entry.size)
                .map_err(|e| anyhow::anyhow!("ASAR member size exceeds addressable memory: {e}"))?;
            let end_offset = start_offset
                .checked_add(member_size)
                .ok_or_else(|| anyhow::anyhow!("ASAR member range overflow"))?;
            let Some(file_data) = data.get(start_offset..end_offset) else {
                anyhow::bail!("ASAR member extends past end of file: {}", relative_path);
            };
            if !guard.check_bytes(file_data.len() as u64, &relative_path) {
                anyhow::bail!("Exceeded maximum total extraction size");
            }

            guard.record_member_metadata(super::guards::ExtractedMemberMetadata {
                archive_path: relative_path.clone(),
                compressed_size: Some(entry.size),
                compression_method: Some("stored".to_string()),
                mtime_unix: None,
                mode_octal: None,
                uid: None,
                gid: None,
                uname: None,
                gname: None,
                entry_type: Some("regular".to_string()),
                linkname: None,
                host_os: None,
            });

            let logical_path = Path::new(&relative_path);
            let file_type = crate::analyzers::detect_file_type_from_data(logical_path, file_data);
            let sha256 = calculate_sha256(file_data);
            let member = MemoryArchiveMember {
                relative_path,
                data: file_data.to_vec(),
                file_type,
                sha256,
                container_kind: None,
            };
            window.push(member);
        }

        window.finalize(
            report,
            start,
            "ASAR archive",
            vec!["archive_analyzer".to_string(), "in_memory_asar".to_string()],
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

        let results: Vec<MemberAnalysisResult> = par_filter_map_members(
            members,
            self.members_run_parallel(members.len()),
            |member| self.analyze_one_member(member, slow_log_label),
        );

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

        let results: Vec<MemberAnalysisResult> = par_filter_map_members(
            members,
            self.members_run_parallel(members.len()),
            |member| self.analyze_one_member(member, slow_log_label),
        );

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
        let member_start = std::time::Instant::now();
        let logical_path = Path::new(&member.relative_path);
        let entry_metadata = archive_entry_metadata(
            entry_path.clone(),
            logical_path,
            &member.file_type,
            member.sha256.clone(),
            &member.data,
            member.container_kind.clone(),
        );

        let member_report = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.analyze_extracted_member(
                logical_path,
                &member.relative_path,
                &member.data,
                &member.file_type,
                &member.sha256,
            )
        })) {
            Ok(Ok(Some(mut r))) => {
                // Matching is done; drop the fields nothing downstream reads so
                // they don't pile up across the archive's members.
                r.clear_unserialized_member_fields();
                Some(r)
            }
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
    ///
    /// Thin wrapper over [`MemberAccumulator`] for callers that already hold
    /// the full `results` vector. The byte-windowed ZIP path folds directly
    /// into a [`MemberAccumulator`] instead, so it never materializes every
    /// member's report at once.
    fn aggregate_member_results(
        &self,
        results: Vec<MemberAnalysisResult>,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        archive_label: &'static str,
        tools_used: Vec<String>,
        total_files: usize,
    ) {
        let mut acc = MemberAccumulator::default();
        for result in results {
            acc.fold(result);
        }
        acc.finalize(report, start, archive_label, tools_used, total_files);
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
                    container_kind: Some(pyinstaller_entry_kind(entry.kind).to_string()),
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
        if !members.is_empty() {
            kv.insert(
                "entries".into(),
                serde_json::Value::Array(
                    members
                        .iter()
                        .map(|member| {
                            let entry_path = self.format_entry_path(&member.relative_path);
                            let metadata = archive_entry_metadata(
                                entry_path,
                                Path::new(&member.relative_path),
                                &member.file_type,
                                member.sha256.clone(),
                                &member.data,
                                member.container_kind.clone(),
                            );
                            archive_entry_json(&metadata)
                        })
                        .collect(),
                ),
            );
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
            let yara_results = par_filter_map_members(
                &class_files,
                self.members_run_parallel(class_files.len()),
                |entry| {
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
                },
            );
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
        // then fold single-threaded to avoid Mutex contention deadlocks. Both
        // the class phase and the non-class phase below fold into one
        // accumulator so the JAR's tallies span every analyzed member.
        let expected_count = classes_to_analyze.len();
        let mut acc = MemberAccumulator::default();

        let members_done = std::sync::atomic::AtomicUsize::new(0);
        let last_progress_ms = AtomicU64::new(0);
        let jar_display = self
            .archive_path_prefix
            .as_deref()
            .unwrap_or(report.target.path.as_str());

        let member_results: Vec<MemberAnalysisResult> = par_filter_map_members(
            &classes_to_analyze,
            self.members_run_parallel(classes_to_analyze.len()),
            |entry| {
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

                let file_data = {
                    let _extract = crate::mem_profile::phase(crate::mem_profile::Phase::Extract);
                    match std::fs::read(entry.path()) {
                        Ok(data) => data,
                        Err(e) => {
                            debug!("Failed to read archive member {}: {}", entry_path, e);
                            return None;
                        }
                    }
                };
                let file_type =
                    crate::analyzers::detect_file_type_from_data(entry.path(), &file_data);
                let sha256 = calculate_sha256(&file_data);

                let entry_metadata = archive_entry_metadata(
                    entry_path.clone(),
                    Path::new(&relative_path),
                    &file_type,
                    sha256.clone(),
                    &file_data,
                    None,
                );

                let member_start = std::time::Instant::now();

                let _analyze = crate::mem_profile::phase(crate::mem_profile::Phase::Analyze);
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
            },
        );

        // Single-threaded fold — no lock contention
        for result in member_results {
            acc.fold(result);
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

        let non_class_results: Vec<MemberAnalysisResult> = par_filter_map_members(
            &non_class_files,
            self.members_run_parallel(non_class_files.len()),
            |entry| {
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

                let file_data = {
                    let _extract = crate::mem_profile::phase(crate::mem_profile::Phase::Extract);
                    match std::fs::read(entry.path()) {
                        Ok(data) => data,
                        Err(e) => {
                            debug!("Failed to read archive member {}: {}", entry_path, e);
                            return None;
                        }
                    }
                };
                let file_type =
                    crate::analyzers::detect_file_type_from_data(entry.path(), &file_data);
                let sha256 = calculate_sha256(&file_data);

                let entry_metadata = archive_entry_metadata(
                    entry_path.clone(),
                    Path::new(&relative_path),
                    &file_type,
                    sha256.clone(),
                    &file_data,
                    None,
                );

                let member_start = std::time::Instant::now();

                let _analyze = crate::mem_profile::phase(crate::mem_profile::Phase::Analyze);
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
            },
        );

        // Fold non-class results into the same accumulator
        for result in non_class_results {
            acc.fold(result);
        }

        // Merge JAR collected results into the report
        let MemberCounts {
            files_analyzed,
            trait_count,
            capability_count,
        } = acc.merge_into(report);

        // Add metadata about archive contents
        report.metadata.errors.push(format!(
            "JAR archive: {} total classes, {} YARA-flagged, {} fully analyzed, {} traits and {} capabilities detected",
            total_class_files,
            flagged_classes.len(),
            files_analyzed,
            trait_count,
            capability_count
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

        // Collect results lock-free, fold single-threaded afterwards
        let mut acc = MemberAccumulator::default();

        // Analyze files in parallel — no shared Mutexes. Nested rayon calls
        // (analyze_extracted_member → rayon::join, scan_bytes → par_iter) are
        // handled by work-stealing; the outer worker participates in inner tasks.
        tracing::debug!(
            file_count = total_files,
            on_rayon_thread = rayon::current_thread_index().is_some(),
            "Starting parallel archive member analysis"
        );
        let generic_results: Vec<MemberAnalysisResult> =
            par_filter_map_members(&files, self.members_run_parallel(files.len()), |entry| {
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

                let file_data = {
                    let _extract = crate::mem_profile::phase(crate::mem_profile::Phase::Extract);
                    match std::fs::read(entry.path()) {
                        Ok(data) => data,
                        Err(e) => {
                            debug!("Failed to read archive member {}: {}", entry_path, e);
                            return None;
                        }
                    }
                };
                let file_type =
                    crate::analyzers::detect_file_type_from_data(entry.path(), &file_data);
                let sha256 = calculate_sha256(&file_data);

                let entry_metadata = archive_entry_metadata(
                    entry_path.clone(),
                    Path::new(&relative_path),
                    &file_type,
                    sha256.clone(),
                    &file_data,
                    None,
                );

                let member_start = std::time::Instant::now();

                let _analyze = crate::mem_profile::phase(crate::mem_profile::Phase::Analyze);
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

        // Single-threaded fold
        let _aggregate = crate::mem_profile::phase(crate::mem_profile::Phase::Aggregate);
        for result in generic_results {
            acc.fold(result);
        }

        // Surface the most severe members first under a hard ceiling, then drain
        // the aggregate into the report.
        acc.sort_files_by_severity(100_000);
        let MemberCounts {
            files_analyzed,
            trait_count,
            capability_count,
        } = acc.merge_into(report);

        // Emit the `archive.*` kv subtree (members + aggregates) so traits
        // can match on archive contents and shape. See
        // [`AnalysisReport::seal_archive_metadata_kv`] for the field layout.
        report.seal_archive_metadata_kv();

        // Add metadata about archive contents
        report.metadata.errors.push(format!(
            "Archive contains {files_analyzed} files analyzed, {trait_count} traits and \
             {capability_count} capabilities detected"
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
    use super::{ArchiveAnalyzer, archive_entry_json, archive_entry_metadata};
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
    fn archive_member_yara_skip_skips_members_without_targeted_tier() {
        // Members with no filetype→tier mapping (unidentified blobs, lockfiles,
        // and types like Clojure/Beam/ODF that carry no targeted tier) would scan
        // against every tier, so the YARA pass is skipped — their string / trait /
        // payload analysis still runs. Members with a targeted tier are scanned.
        for ft in [
            FileType::Unknown,
            FileType::YarnLock,
            FileType::CargoLock,
            FileType::RequirementsTxt,
            FileType::Clojure,
        ] {
            assert_eq!(
                ArchiveAnalyzer::archive_member_yara_skip_reason("member", &ft, 1024),
                Some("no targeted YARA tier for file type"),
                "{ft:?} should skip YARA",
            );
        }
        for ft in [FileType::Python, FileType::Elf, FileType::Pe] {
            assert_eq!(
                ArchiveAnalyzer::archive_member_yara_skip_reason("member", &ft, 1024),
                None,
                "{ft:?} should be scanned",
            );
        }
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

    #[test]
    fn archive_entry_metadata_records_extension_type_mismatch() {
        let data = b"not a valid PE";
        let entry = archive_entry_metadata(
            "stage/uusd.exe".to_string(),
            std::path::Path::new("stage/uusd.exe"),
            &FileType::Unknown,
            "sha".to_string(),
            data,
            Some("binary".to_string()),
        );

        assert_eq!(entry.declared_type.as_deref(), Some("pe"));
        assert!(entry.extension_type_mismatch);
        assert_eq!(entry.magic_prefix.as_deref(), Some("6e6f742061207661"));
        assert_eq!(entry.container_kind.as_deref(), Some("binary"));
        assert!(entry.entropy.is_some());

        let value = archive_entry_json(&entry);
        assert_eq!(value["declared_type"], "pe");
        assert_eq!(value["extension_type_mismatch"], true);
        assert_eq!(value["container_kind"], "binary");
    }
}
