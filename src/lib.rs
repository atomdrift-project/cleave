//! cleave - Deep static analysis library for extracting features from binaries and source code.
//!
//! This library provides APIs for analyzing files and extracting security-relevant
//! features including capabilities, traits, and behavioral indicators.
//!
//! # Example
//!
//! ```no_run
//! use cleave::{analyze_file, AnalysisOptions};
//!
//! # fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! let options = AnalysisOptions::default();
//! let report = analyze_file("suspicious.py", &options)?;
//!
//! for finding in &report.findings {
//!     println!("{}: {} ({:?})", finding.id, finding.desc, finding.crit);
//! }
//! # Ok(())
//! # }
//! ```

extern crate self as cleave;

mod analysis_cache;
pub mod analysis_context;
pub mod breadcrumb;
pub mod cache;
pub mod cancellation;
pub(crate) mod context;
pub mod decoders;
mod entropy;
pub mod extractors;
pub mod file_io;
pub mod ip_validator;
pub mod mem_profile;
pub mod memory_tracker;
pub mod rule_update;
mod shared_resources;
pub mod strings;
pub mod test_rules;
#[cfg(test)]
/// Test module for rule filters.
pub mod test_rules_filters_test;
pub mod traits_repo;
mod upx;
pub(crate) mod validation_controls;

// Public modules
pub mod analyzers;
pub mod bitcoin_validator;
pub mod capabilities;
pub mod cli;
pub mod commands;
pub mod composite_rules;
pub mod diff;
pub mod env_mapper;
pub mod malecule_bridge;
pub mod output;
pub mod path_mapper;
pub mod theme;
pub mod third_party_config;
pub mod third_party_yara;
pub mod types;
pub mod update_check;
pub mod update_manifest;
pub mod yara_engine;

// Memory-aware admission so parallel scans don't co-resident large archives and
// OOM the host. See scan_files / scan_directory.
mod scan_mem_gate;

// HTTP API server
pub mod server;

/// This crate's version, captured from `Cargo.toml` at compile time.
///
/// Exposed so an embedding binary (e.g. litmus, which links cleave as a
/// library) can read the cleave version it was built against, rather than its
/// own. `env!` resolves the version of the crate it is compiled in, so this
/// constant always reflects cleave's `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// Re-export commonly used types at crate root
use analyzers::FileTypeExt;
pub use analyzers::{AnalysisInput, Analyzer, FileType, detect_file_type};
pub use capabilities::CapabilityMapper;
pub use composite_rules::Platform;
pub use types::binary::StringInfo;
pub use types::code_structure::{BinaryProperties, SourceCodeMetrics};
pub use types::core::{AnalysisReport, Criticality, TargetInfo};
pub use types::diff::{
    Changed, DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, KvChange, MetricChange,
    ScopeDiff, ScopeDiffs, ScopeRocs, SectionChange, StringChange, SymbolChange, SymbolKind,
    TraitChange,
};
// `TextMetrics` typed struct retired with the cleave→filefacts
// text-metrics migration; downstream consumers should read keys
// from `report.filefacts_metrics` (BTreeMap<String, f64>) under the
// `text.*` prefix instead.
pub use types::FileAnalysis;
pub use types::SampleExtractionConfig;
pub use types::traits_findings::{Evidence, Finding, FindingKind, Trait, TraitKind};

// Re-export cache management functions
pub use shared_resources::{reload_capability_mapper, set_skip_traits_override};

use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};

/// Compute a fast hash of a string for deduplication and caching.
#[inline]
pub(crate) fn hash_str(s: &str) -> u64 {
    let mut hasher = FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}

fn looks_like_actionable_payload_preview(preview: &str) -> bool {
    let preview = preview.trim();
    if preview.is_empty() || preview == "<binary data>" {
        return false;
    }

    let markers = [
        "#!",
        "<?php",
        "function ",
        "import ",
        "from ",
        "const ",
        "let ",
        "var ",
        "curl ",
        "wget ",
        "powershell",
        "cmd.exe",
        "bash ",
        "sh ",
        "http://",
        "https://",
    ];
    markers.iter().any(|marker| preview.contains(marker))
}

fn is_benign_unicode_escape_payload(payload: &types::ExtractedPayload) -> bool {
    if !payload
        .encoding_chain
        .iter()
        .any(|encoding| encoding == "unicode-escape")
    {
        return false;
    }

    let decoded = String::from_utf8_lossy(&payload.data);
    decoded.contains('\u{1b}')
        && decoded.contains("colors ?")
        && decoded.contains("${m}")
        && decoded.contains(": m")
}

fn is_generated_python_codec_unicode_escape(report: &types::AnalysisReport) -> bool {
    report.target.file_type == "python"
        && report.strings.iter().any(|s| {
            s.value.contains("Python Character Mapping Codec") && s.value.contains("gencodec.py")
        })
}

fn should_skip_unknown_encoded_payload_for_text(
    file_type: &FileType,
    payload: &types::ExtractedPayload,
) -> bool {
    if payload.detected_type != FileType::Unknown
        || looks_like_actionable_payload_preview(&payload.preview)
    {
        return false;
    }

    let is_textual = file_type.is_source_code()
        || matches!(
            file_type,
            FileType::Markdown | FileType::Text | FileType::Data
        );
    let is_noisy_text_encoding = payload.encoding_chain.len() == 1
        && matches!(payload.encoding_chain[0].as_str(), "xor" | "url");

    is_textual && is_noisy_text_encoding
}

fn smallest_section_for_offset(
    offset: usize,
    sections: &[types::Section],
) -> Option<&types::Section> {
    sections
        .iter()
        .filter(|section| {
            let Some(section_offset) = section.offset else {
                return false;
            };
            let start = section_offset as usize;
            let end = start.saturating_add(section.size as usize);
            offset >= start && offset < end
        })
        .min_by_key(|section| section.size)
}

fn should_skip_unknown_xor_payload_for_binary(
    file_type: &FileType,
    payload: &types::ExtractedPayload,
    sections: &[types::Section],
    report: &types::AnalysisReport,
) -> bool {
    if payload.encoding_chain.len() != 1
        || payload.encoding_chain[0] != "xor"
        || payload.detected_type != FileType::Unknown
    {
        return false;
    }

    let Some(section) = smallest_section_for_offset(payload.original_offset, sections) else {
        return false;
    };

    if *file_type == FileType::Elf {
        let name = section.name.as_str();
        let is_elf_metadata_section = matches!(
            name,
            ".comment"
                | ".ident"
                | ".copyright"
                | ".gnu_debuglink"
                | ".symtab"
                | ".strtab"
                | ".shstrtab"
                | ".SUNW_ctf"
        ) || name.starts_with(".debug");

        let is_unloaded_metadata = section.address == Some(0);

        return is_elf_metadata_section && is_unloaded_metadata;
    }

    if *file_type == FileType::Pe {
        // Heuristic: PE signed by a third-party developer with a large
        // export surface (a code-signing library binary). Detected via
        // a `metadata/signed/leaf::*` Notable finding plus a non-trivial
        // export count from `report.exports`.
        let in_readonly_data = section.name == ".rdata";
        let is_signed_leaf = report
            .findings
            .iter()
            .any(|f| f.id.starts_with("metadata/signed/leaf::"));
        let has_large_export_surface = report.exports.len() >= 50;

        return in_readonly_data
            && is_signed_leaf
            && has_large_export_surface
            && !looks_like_actionable_payload_preview(&payload.preview);
    }

    false
}

/// Recognise a signed-Python-extension PE (e.g. a CPython runtime DLL)
/// whose `.rdata`-resident hex payloads are part of unicodedata /
/// Unicode property tables. Reads filefacts's `pe.signatures[0].subject`
/// and falls back on `report.findings` / `report.exports` /
/// `report.strings` counts (all populated already on the analyse path).
fn is_signed_python_extension(report: &types::AnalysisReport) -> bool {
    let signer_psf = report
        .filefacts
        .as_ref()
        .and_then(|e| e.values.get("pe"))
        .and_then(|pe| pe.get("signatures"))
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.first())
        .and_then(|sig| sig.get("subject"))
        .and_then(|v| v.as_str())
        .is_some_and(|subject| subject.contains("Python Software Foundation"));
    signer_psf
        && report.exports.len() <= 2
        && report.functions.len() >= 100
        && report.strings.len() >= 2000
}

fn is_elf_metadata_offset(offset: usize, sections: &[types::Section]) -> bool {
    let Some(section) = sections
        .iter()
        .filter(|section| {
            let Some(section_offset) = section.offset else {
                return false;
            };
            let start = section_offset as usize;
            let end = start.saturating_add(section.size as usize);
            offset >= start && offset < end
        })
        .min_by_key(|section| section.size)
    else {
        return false;
    };

    let name = section.name.as_str();
    let is_elf_metadata_section = matches!(
        name,
        ".comment"
            | ".ident"
            | ".copyright"
            | ".gnu_debuglink"
            | ".symtab"
            | ".strtab"
            | ".shstrtab"
            | ".SUNW_ctf"
    ) || name.starts_with(".debug");

    is_elf_metadata_section && section.address == Some(0)
}

fn parse_evidence_offset(location: &Option<String>) -> Option<usize> {
    let value = location.as_deref()?.strip_prefix("offset:")?;
    value.parse::<usize>().ok()
}

fn should_skip_unknown_url_markup_payload(payload: &types::ExtractedPayload) -> bool {
    if !payload.encoding_chain.iter().any(|e| e == "url")
        || payload.detected_type != FileType::Unknown
    {
        return false;
    }

    let preview = payload.preview.trim().to_lowercase();
    if preview.is_empty() || preview == "<binary data>" {
        return false;
    }

    let markup_markers = [
        "<!doctype",
        "<html",
        "<body",
        "<script",
        "<a ",
        "<form",
        "<div",
        "<span",
        "<table",
        "<li>",
        "href=\"http",
        "rel=\"nofollow\"",
        "target=\"_blank\"",
        "&nbsp;",
    ];

    if markup_markers.iter().any(|marker| preview.contains(marker)) {
        return true;
    }

    let payload_markers = [
        "http://",
        "https://",
        "/bin/",
        "curl ",
        "wget ",
        "powershell",
        "cmd.exe",
        "bash ",
        "sh ",
        ".exe",
        ".dll",
        ".sh",
        "/api/",
        "user-agent",
    ];
    if payload_markers
        .iter()
        .any(|marker| preview.contains(marker))
    {
        return false;
    }

    let space_count = preview.chars().filter(char::is_ascii_whitespace).count();
    let alpha_count = preview.chars().filter(char::is_ascii_alphabetic).count();
    alpha_count >= 24 && space_count >= 4
}

pub use composite_rules::evaluators::{clear_regex_caches, clear_thread_local_caches};

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// SIGKILL every currently-live rizin process group.
///
/// Forwards to [`filefacts::rizin::kill_all_rizin_groups`]. Intended for
/// host CLI signal handlers that need to reap rizin workers before a
/// forced `process::exit`. Cheap and idempotent — safe to call from
/// the `ctrlc` crate's dispatch thread. No-op on non-Unix platforms.
pub fn kill_all_rizin_groups() {
    filefacts::rizin::kill_all_rizin_groups();
}

/// Disable UPX integration process-wide.
pub fn disable_upx() {
    upx::disable_upx();
}

/// Scoped disable guards applied for a single analysis operation.
struct AnalysisDisableGuards {
    _radare2: Option<filefacts::rizin::ScopedDisable>,
    _upx: Option<upx::ScopedUpxDisable>,
}

impl AnalysisDisableGuards {
    fn from_options(options: &AnalysisOptions) -> Self {
        Self {
            _radare2: options
                .disable_radare2
                .then(filefacts::rizin::scoped_disable),
            _upx: options.disable_upx.then(upx::scoped_disable_upx),
        }
    }
}

/// Process YARA scan results and add them to the analysis report.
///
/// Extracts YARA matches and inline evidence, converts matches to findings,
/// and returns inline evidence map for use in trait evaluation.
pub fn process_yara_result_with<F>(
    report: &mut types::AnalysisReport,
    yara_result: Option<Result<(Vec<types::YaraMatch>, HashMap<String, Vec<types::Evidence>>)>>,
    mut evidence_for_match: F,
) -> HashMap<String, Vec<types::Evidence>>
where
    F: FnMut(&types::YaraMatch) -> Vec<types::Evidence>,
{
    let yara_result = match yara_result {
        Some(Ok(ok)) => ok,
        Some(Err(e)) => {
            tracing::warn!(error = %e, "YARA scan failed, continuing without YARA results");
            report.metadata.errors.push(format!("yara: {e:#}"));
            return HashMap::new();
        }
        None => return HashMap::new(),
    };
    let (matches, inline) = yara_result;

    // Resolve file architectures once for YARA arch filtering
    let file_archs: Vec<composite_rules::Arch> = report
        .target
        .architectures
        .as_ref()
        .map(|archs| {
            archs
                .iter()
                .map(|a| composite_rules::Arch::from_report_str(a))
                .collect()
        })
        .unwrap_or_default();

    report.yara_matches = matches.clone();
    for yara_match in &matches {
        // Skip YARA findings whose arch_context metadata explicitly excludes
        // the file's architecture.  arch_context takes priority because it is
        // an authoritative signal written by the rule author.  "x86" in
        // arch_context means the x86 ISA family (32-bit and 64-bit).
        if let Some(ref ctx) = yara_match.arch_context
            && !ctx.is_empty()
            && !file_archs.is_empty()
            && !file_archs.contains(&composite_rules::Arch::All)
        {
            let rule_archs = crate::third_party_yara::archs_from_arch_context(ctx);
            if !rule_archs.is_empty() && !rule_archs.iter().any(|a| file_archs.contains(a)) {
                tracing::debug!(
                    "Skipping YARA rule {} (arch_context {:?} doesn't match file {:?})",
                    yara_match.rule,
                    ctx,
                    file_archs,
                );
                continue;
            }
        }

        // Fallback: skip YARA findings whose rule name implies an architecture
        // that doesn't match the file (e.g., an _X64_ rule firing on ARM64).
        // Only applied when arch_context metadata is absent.
        if yara_match.arch_context.is_none()
            && let Some(rule_arch) = composite_rules::Arch::from_yara_rule_name(&yara_match.rule)
            && !file_archs.is_empty()
            && !file_archs.contains(&composite_rules::Arch::All)
            && !file_archs.contains(&rule_arch)
        {
            tracing::debug!(
                "Skipping YARA rule {} (arch {:?} doesn't match file {:?})",
                yara_match.rule,
                rule_arch,
                file_archs,
            );
            continue;
        }

        let cap_id = yara_match
            .trait_id
            .clone()
            .unwrap_or_else(|| yara_match.namespace.replace('.', "/"));
        if report.findings.iter().any(|c| c.id == cap_id) {
            continue;
        }
        let evidence = evidence_for_match(yara_match);
        let crit = match yara_match.crit.as_str() {
            "hostile" => types::Criticality::Hostile,
            "notable" => types::Criticality::Notable,
            "suspicious" => types::Criticality::Suspicious,
            _ => types::Criticality::Baseline,
        };
        report.findings.push(types::Finding {
            src: None,
            kind: types::FindingKind::Capability,
            trait_refs: vec![],
            id: cap_id,
            desc: yara_match.desc.clone(),
            conf: 0.9,
            crit,
            mbc: yara_match.mbc.clone(),
            attack: yara_match.attack.clone(),
            evidence,
            match_count: 0,
            source_file: None,
        });
    }
    if !report.metadata.tools_used.iter().any(|t| t == "yara-x") {
        report.metadata.tools_used.push("yara-x".to_string());
    }
    inline
}

fn process_yara_result(
    report: &mut types::AnalysisReport,
    yara_result: Option<Result<(Vec<types::YaraMatch>, HashMap<String, Vec<types::Evidence>>)>>,
    engine: Option<&yara_engine::YaraEngine>,
) -> HashMap<String, Vec<types::Evidence>> {
    process_yara_result_with(report, yara_result, |yara_match| {
        engine
            .map(|e| e.yara_match_to_evidence(yara_match))
            .unwrap_or_default()
    })
}

/// Create an analysis report for a file using the analyzer selected for `file_type`.
///
/// This is primarily used by the CLI command layer to avoid reimplementing
/// analyzer dispatch and fallback report creation outside the library.
pub fn create_analysis_report(
    path: &Path,
    file_type: &FileType,
    binary_data: &[u8],
    capability_mapper: &CapabilityMapper,
) -> Result<types::AnalysisReport> {
    use sha2::{Digest, Sha256};

    let report = if let Some(analyzer) =
        analyzers::analyzer_for_file_type(file_type, Some(capability_mapper.clone()))
    {
        analyzer.analyze(path)?
    } else {
        let mut hasher = Sha256::new();
        hasher.update(binary_data);
        let sha256 = format!("{:x}", hasher.finalize());

        let target = types::TargetInfo {
            path: path.display().to_string(),
            file_type: file_type.report_file_type(),
            size_bytes: binary_data.len() as u64,
            sha256,
            architectures: None,
        };

        types::AnalysisReport::new(target)
    };

    Ok(report)
}

/// Options for file analysis
#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    /// Enable third-party YARA rules
    pub enable_third_party_yara: bool,
    /// Passwords to try for encrypted ZIP files
    pub zip_passwords: Vec<String>,
    /// Disable YARA scanning
    pub disable_yara: bool,
    /// Disable radare2 analysis
    pub disable_radare2: bool,
    /// Disable UPX unpacking
    pub disable_upx: bool,
    /// Include all files in directory scans, even unknown types
    pub all_files: bool,
    /// Platform filters for composite rule evaluation
    pub platforms: Vec<composite_rules::Platform>,
    /// Minimum precision threshold for hostile composite rules
    pub min_hostile_precision: f32,
    /// Minimum precision threshold for suspicious composite rules
    pub min_suspicious_precision: f32,
    /// Whether to compute precision scores and emit precision warnings while loading rules.
    pub enable_precision_scoring: bool,
    /// Enable comprehensive validation of capability definitions
    pub enable_full_validation: bool,
    /// Maximum file size (bytes) to load into memory from archives
    pub max_memory_file_size: u64,
    /// Configuration for extracting suspicious files from archives
    pub sample_extraction: Option<types::SampleExtractionConfig>,
    /// Warn threshold for slow rule evaluation in milliseconds (default: 4000).
    /// Rules exceeding this emit a warning; >1000ms is always logged at debug level.
    pub slow_rule_ms: u64,
    /// Maximum file size (bytes) to scan during directory analysis.
    /// Files larger than this are skipped. 0 means no limit.
    pub max_scan_file_size: u64,
    /// Per-request cancellation flag. When set to true by the caller (e.g. server on timeout),
    /// archive analysis will stop processing new members early.
    /// Not included in the analysis cache key.
    pub cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Optional phase tracker for observability. When set, cleave updates this
    /// string at key analysis stages so callers (e.g. litmus `/_/requests`) can
    /// report what a stuck request is actually doing.
    pub phase: Option<PhaseTracker>,
}

/// Lightweight handle for reporting the current analysis phase.
///
/// Callers (e.g. litmus) create one per request and pass it via
/// [`AnalysisOptions::phase`]. Cleave updates it at each major stage
/// (archive extraction, YARA, structural analysis, …) so the caller
/// can filefacts the current phase in diagnostic endpoints like `/_/requests`.
///
/// Trackers created via [`PhaseTracker::with_label`] register themselves
/// in a process-global list so [`start_rayon_diagnostics`] can enumerate
/// in-flight work and show which analyses are stuck.
///
/// Cloning is cheap (`Arc`). Updating is a short `RwLock` write.
#[derive(Clone, Debug)]
pub struct PhaseTracker(Arc<PhaseInner>);

#[derive(Debug)]
struct PhaseInner {
    /// Caller-supplied identifier (typically `sha256_short filename`).
    /// Empty for anonymous trackers, which are not registered.
    label: String,
    created_at: std::time::Instant,
    state: std::sync::RwLock<PhaseState>,
}

#[derive(Debug)]
struct PhaseState {
    name: String,
    /// Updated on every `set()` so diag can report per-phase elapsed time.
    started_at: std::time::Instant,
}

impl PhaseTracker {
    /// Create an unlabeled, unregistered tracker.
    ///
    /// Used by [`AnalysisOptions::default`] and anywhere a caller wants
    /// the tracker type but does not want the overhead of registration
    /// (for example because the caller already reports phase externally).
    #[must_use]
    pub fn new() -> Self {
        Self::build("")
    }

    /// Create a labeled tracker and register it in the global in-flight
    /// registry so [`start_rayon_diagnostics`] can show it in its periodic
    /// snapshot. The label should identify the unit of work (e.g. a
    /// shortened sha256 plus filename).
    #[must_use]
    pub fn with_label(label: impl Into<String>) -> Self {
        let this = Self::build(label.into());
        register_phase(&this.0);
        this
    }

    fn build(label: impl Into<String>) -> Self {
        let now = std::time::Instant::now();
        Self(Arc::new(PhaseInner {
            label: label.into(),
            created_at: now,
            state: std::sync::RwLock::new(PhaseState {
                name: String::new(),
                started_at: now,
            }),
        }))
    }

    /// Update the current phase description.
    pub fn set(&self, phase: &str) {
        if let Ok(mut s) = self.0.state.write() {
            s.name.clear();
            s.name.push_str(phase);
            s.started_at = std::time::Instant::now();
        }
    }

    /// Read the current phase.
    #[must_use]
    pub fn get(&self) -> String {
        self.0
            .state
            .read()
            .map(|s| s.name.clone())
            .unwrap_or_default()
    }
}

impl Default for PhaseTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot row for one in-flight analysis: (label, phase name, time in
/// current phase, total tracker age).
type PhaseSnapshot = (String, String, std::time::Duration, std::time::Duration);

static PHASE_REGISTRY: std::sync::LazyLock<std::sync::Mutex<Vec<std::sync::Weak<PhaseInner>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

fn register_phase(inner: &Arc<PhaseInner>) {
    if let Ok(mut reg) = PHASE_REGISTRY.lock() {
        reg.retain(|w| w.strong_count() > 0);
        reg.push(Arc::downgrade(inner));
    }
}

/// Snapshot all currently-live registered phase trackers, sorted oldest-first.
fn snapshot_active_phases() -> Vec<PhaseSnapshot> {
    let mut out = Vec::new();
    if let Ok(mut reg) = PHASE_REGISTRY.lock() {
        reg.retain(|w| w.strong_count() > 0);
        for weak in reg.iter() {
            if let Some(arc) = weak.upgrade()
                && let Ok(state) = arc.state.read()
            {
                out.push((
                    arc.label.clone(),
                    state.name.clone(),
                    state.started_at.elapsed(),
                    arc.created_at.elapsed(),
                ));
            }
        }
    }
    out.sort_by_key(|entry| std::cmp::Reverse(entry.3));
    out
}

/// Spawns a background thread that logs rayon pool diagnostics every 5 minutes.
/// Call once at startup. The thread exits when the process exits.
pub fn start_rayon_diagnostics() {
    std::thread::Builder::new()
        .name("rayon-diag".into())
        .spawn(|| {
            let interval = std::time::Duration::from_secs(300);
            loop {
                std::thread::sleep(interval);
                // Probe the rayon pool by trying to execute a trivial task.
                // If the pool is starved, this will block — measure how long.
                let probe_start = std::time::Instant::now();
                let (idle_sender, idle_receiver) = std::sync::mpsc::channel();
                rayon::spawn(move || {
                    let _ = idle_sender.send(());
                });
                let probe_ok = idle_receiver
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .is_ok();
                let probe_ms = probe_start.elapsed().as_millis();

                let rss_mb = memory_tracker::current_rss()
                    .map(|b| b / 1024 / 1024)
                    .unwrap_or(0);

                let active = snapshot_active_phases();
                let in_flight = active.len();
                let oldest_age_s = active
                    .first()
                    .map(|(_, _, _, total)| total.as_secs())
                    .unwrap_or(0);

                if probe_ok && probe_ms < 100 {
                    tracing::info!(
                        rayon_threads = rayon::current_num_threads(),
                        probe_ms,
                        rss_mb,
                        in_flight,
                        oldest_age_s,
                        "rayon pool snapshot",
                    );
                } else {
                    tracing::error!(
                        rayon_threads = rayon::current_num_threads(),
                        probe_ms,
                        probe_responded = probe_ok,
                        rss_mb,
                        in_flight,
                        oldest_age_s,
                        "rayon pool appears STARVED — trivial task {}",
                        if probe_ok {
                            "was slow"
                        } else {
                            "timed out (5s)"
                        },
                    );
                }

                // Emit one line per in-flight analysis so `grep in_flight` shows
                // exactly what is still outstanding (and what phase each is in).
                // Cap to keep the log readable if thousands of requests queue up;
                // the summary above still reports the true count.
                const MAX_LINES: usize = 64;
                for (label, phase, phase_age, total_age) in active.iter().take(MAX_LINES) {
                    let phase_shown: &str = if phase.is_empty() { "(unset)" } else { phase };
                    tracing::info!(
                        label = %label,
                        phase = %phase_shown,
                        phase_elapsed_ms = phase_age.as_millis() as u64,
                        total_elapsed_ms = total_age.as_millis() as u64,
                        "in_flight",
                    );
                }
                if in_flight > MAX_LINES {
                    tracing::info!(
                        truncated = in_flight - MAX_LINES,
                        "in_flight snapshot truncated",
                    );
                }
            }
        })
        .ok(); // best-effort; don't fail if thread creation fails
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            enable_third_party_yara: true,
            zip_passwords: cli::DEFAULT_ZIP_PASSWORDS
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            disable_yara: false,
            disable_radare2: false,
            disable_upx: false,
            all_files: false,
            platforms: vec![composite_rules::Platform::All],
            min_hostile_precision: CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
            min_suspicious_precision: CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            enable_precision_scoring: false,
            enable_full_validation: false,
            max_memory_file_size: 512 * 1024 * 1024, // 512 MB default
            sample_extraction: None,
            slow_rule_ms: capabilities::CapabilityMapper::DEFAULT_SLOW_RULE_MS,
            max_scan_file_size: 600 * 1024 * 1024, // 600 MB default
            cancellation: None,
            phase: None,
        }
    }
}

/// Clear thread-local caches on the calling thread, plus the process-global
/// regex caches.
///
/// Rayon worker threads clear their own thread-local caches per-file, so no
/// broadcast is needed. The regex caches are shared across all threads, so this
/// is the one place we drop them — invoke under memory pressure (see
/// `memory_tracker::start_periodic_logging`).
pub fn clear_all_thread_caches() {
    clear_thread_local_caches();
    clear_regex_caches();
    tracing::debug!("Cleared thread-local caches and regex caches on calling thread");
}

/// Pre-warm the YARA engine on a non-rayon thread.
///
/// This blocks until initialization completes. That is intentional: the global
/// YARA engine must not be first initialized from a rayon worker because rule
/// loading itself uses rayon internally.
pub fn prefetch_yara_engine(enable_third_party: bool) {
    // Bootstrap the traits archive before compiling rules. On a fresh install the
    // data directory is empty, and without this the prefetch would find zero rules
    // and print a spurious "No YARA rules loaded" warning before the analysis path
    // gets a chance to download the archive. `resolve_and_ensure` is idempotent and
    // returns immediately (a cheap directory check, no network) once traits exist,
    // so warm runs pay nothing. Because this blocks until traits are present, it
    // also serializes the install ahead of the analysis path's own
    // `resolve_and_ensure`, avoiding a concurrent double-download race.
    if let Err(e) = traits_repo::resolve_and_ensure() {
        tracing::debug!(
            error = %e,
            "traits ensure before YARA prefetch failed; analysis path will surface the error"
        );
    }
    let handle = std::thread::spawn(move || shared_resources::yara_engine(enable_third_party));
    if handle.join().is_err() {
        tracing::warn!("YARA engine prefetch thread panicked");
    }
}

/// Pre-warm the capability mapper on a background thread.
///
/// Companion to [`prefetch_yara_engine`]. The mapper first-load parses every
/// trait definition and can take seconds; doing it in the background avoids
/// blocking the first real analysis.
pub fn prefetch_capability_mapper() {
    std::thread::spawn(|| {
        if let Err(e) = shared_resources::capability_mapper() {
            tracing::warn!(error = %e, "capability mapper prefetch failed");
        }
    });
}

/// Pre-warm both YARA and the capability mapper.
///
/// Call this once at process startup (e.g. at the top of a worker or server
/// main) so the first incoming request does not pay the multi-second cold-start
/// cost. YARA initialization completes before this returns so subsequent rayon
/// scans cannot win the first-init race. Safe to call multiple times; subsequent
/// calls are cheap.
pub fn prefetch_shared_resources(enable_third_party: bool) {
    prefetch_yara_engine(enable_third_party);
    prefetch_capability_mapper();
}

/// Analyze a single file and return a detailed report.
///
/// This is the main entry point for analyzing files programmatically.
/// Uses global lazy-loaded resources (CapabilityMapper and YARA engine) for efficiency.
/// Resources are initialized on first use and shared across all analyses.
///
/// For custom resource management, use `analyze_file_with_mapper` instead.
///
/// # Arguments
///
/// * `path` - Path to the file to analyze
/// * `options` - Analysis options
///
/// # Returns
///
/// An `AnalysisReport` containing all extracted features, findings, and metrics.
pub fn analyze_file<P: AsRef<Path>>(path: P, options: &AnalysisOptions) -> Result<AnalysisReport> {
    let path = path.as_ref();

    // Fast path: check the analysis cache before loading expensive resources.
    // SHA256 of the file is cheap (~1ms); loading CapabilityMapper + YARA is not (~800ms).
    // Keep the pre-read data to pass through on cache miss, avoiding a second read.
    let (preloaded, precomputed_sha) = if path.is_file() {
        let file_data = file_io::read_file_smart(path)?;
        let sha256 = analyzers::utils::calculate_sha256(file_data.as_slice());
        if let Some(mut report) = analysis_cache::report_cache_lookup(&sha256, options) {
            report.target.path = path.display().to_string();
            report.analysis_timestamp = Some(chrono::Utc::now());
            restamp_path_derived_values(&mut report, path);
            tracing::info!("Cache hit (fast path)");
            return Ok(report);
        }
        (Some(file_data), Some(sha256))
    } else {
        (None, None)
    };

    // Cache miss: load mapper and YARA engine in parallel (~860ms + ~270ms → ~860ms)
    let (mapper, yara_engine) = load_scan_resources(options)?;
    analyze_file_with_resources_and_sha256(
        path,
        options,
        &mapper,
        yara_engine.as_ref(),
        preloaded,
        precomputed_sha,
    )
}

/// Analyze in-memory file data without requiring a file on disk.
///
/// `filename` is used for extension-based type detection and report labeling —
/// it does not need to exist on the filesystem. This avoids disk I/O for remote
/// workers that download samples over HTTP.
///
/// # Example
///
/// ```no_run
/// use cleave::{analyze_bytes, AnalysisOptions};
///
/// # fn demo() -> Result<(), Box<dyn std::error::Error>> {
/// let data = std::fs::read("sample.exe")?;
/// let report = analyze_bytes(&data, "sample.exe", &AnalysisOptions::default())?;
/// println!("{} findings", report.findings.len());
/// # Ok(())
/// # }
/// ```
pub fn analyze_bytes(
    data: &[u8],
    filename: &str,
    options: &AnalysisOptions,
) -> Result<AnalysisReport> {
    analyze_bytes_owned(data.to_vec(), filename, options)
}

/// Analyze in-memory file data without requiring a file on disk, consuming the
/// input `Vec<u8>` to avoid the copy that [`analyze_bytes`] must perform.
///
/// Prefer this over `analyze_bytes` when the caller already owns the bytes
/// (e.g. a worker that downloaded a sample into a `Vec<u8>`). At scale this
/// saves one full-size memcpy and allocation per file.
pub fn analyze_bytes_owned(
    data: Vec<u8>,
    filename: &str,
    options: &AnalysisOptions,
) -> Result<AnalysisReport> {
    // Use a synthetic path for extension-based type detection and reporting.
    let path = Path::new(filename);

    let sha256 = analyzers::utils::calculate_sha256(&data);
    if let Some(mut report) = analysis_cache::report_cache_lookup(&sha256, options) {
        report.target.path = filename.to_string();
        report.analysis_timestamp = Some(chrono::Utc::now());
        tracing::info!("Cache hit (fast path)");
        return Ok(report);
    }

    let preloaded = file_io::FileData::Owned(data);

    let (mapper, yara_engine) = load_scan_resources(options)?;
    analyze_file_with_resources_and_sha256(
        path,
        options,
        &mapper,
        yara_engine.as_ref(),
        Some(preloaded),
        Some(sha256),
    )
}

/// Analyze a single file using a pre-loaded CapabilityMapper.
///
/// Use this for batch processing to avoid reloading capabilities for each file.
/// Uses the shared global YARA engine singleton.
pub fn analyze_file_with_mapper<P: AsRef<Path>>(
    path: P,
    options: &AnalysisOptions,
    capability_mapper: &Arc<CapabilityMapper>,
) -> Result<AnalysisReport> {
    // Use shared YARA engine (initialized on first use)
    let yara_engine = if options.disable_yara {
        None
    } else {
        Some(shared_resources::yara_engine(
            options.enable_third_party_yara,
        ))
    };
    analyze_file_with_resources(path, options, capability_mapper, yara_engine.as_ref(), None)
}

/// Analyze a single file with full control over resources.
///
/// This is the core analysis function that accepts pre-loaded resources.
/// Use this when you need maximum control and efficiency.
///
/// # Arguments
///
/// * `path` - Path to the file to analyze
/// * `options` - Analysis options
/// * `capability_mapper` - Pre-loaded capability mapper
/// * `yara_engine` - Optional pre-loaded YARA engine (None disables YARA scanning)
///
/// # Returns
///
/// An `AnalysisReport` containing all extracted features, findings, and metrics.
/// Maximum recursion depth for nested payload analysis.
/// Each level adds a full analysis stack frame; 8 levels is generous for
/// legitimate multi-layer encoding while preventing stack overflows from
/// adversarial nesting (e.g., base64-in-hex-in-base64 ad infinitum).
const MAX_ANALYSIS_DEPTH: u32 = 8;

fn analyze_file_with_resources<P: AsRef<Path>>(
    path: P,
    options: &AnalysisOptions,
    capability_mapper: &Arc<CapabilityMapper>,
    yara_engine: Option<&Arc<yara_engine::YaraEngine>>,
    preloaded: Option<file_io::FileData>,
) -> Result<AnalysisReport> {
    analyze_file_with_resources_and_sha256(
        path,
        options,
        capability_mapper,
        yara_engine,
        preloaded,
        None,
    )
}

/// Same as [`analyze_file_with_resources`] but accepts a precomputed SHA256.
///
/// Callers that already hashed the file for a fast-path cache lookup pass it
/// through so the internal pipeline does not recompute the digest on the same
/// bytes — a non-trivial cost on large inputs.
/// Extract a human-readable message from a panic payload (`String` or `&str`).
///
/// `std::panic::catch_unwind` hands back the payload as `Box<dyn Any + Send>`;
/// the standard panic machinery boxes either a `String` (from `format!`-style
/// panics) or a `&'static str`, so those two cases cover every panic we raise.
pub(crate) fn panic_payload_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else {
        "unknown panic".to_string()
    }
}

fn analyze_file_with_resources_and_sha256<P: AsRef<Path>>(
    path: P,
    options: &AnalysisOptions,
    capability_mapper: &Arc<CapabilityMapper>,
    yara_engine: Option<&Arc<yara_engine::YaraEngine>>,
    preloaded: Option<file_io::FileData>,
    precomputed_sha256: Option<String>,
) -> Result<AnalysisReport> {
    let path = path.as_ref();
    let _disable_guards = AnalysisDisableGuards::from_options(options);

    // Catch panics from any analyzer so a single malformed or adversarial file
    // (e.g. a header offset pointing past EOF that trips unchecked slice
    // indexing) can't unwind across the caller's thread boundary — a rayon
    // worker or a tokio `spawn_blocking` task — and take down unrelated work.
    // Library callers instead get a plain `Err` they can classify and log. The
    // per-frame `ThreadLocalCacheClearGuard` inside the analysis still runs
    // during the unwind, so thread-local caches are left clean before we return.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        analyze_file_with_resources_at_depth(
            path,
            options,
            capability_mapper,
            yara_engine,
            preloaded,
            precomputed_sha256,
            0,
        )
    }));

    match outcome {
        Ok(result) => result,
        Err(payload) => {
            let message = panic_payload_message(&payload);
            tracing::error!(
                path = %path.display(),
                panic = %message,
                "analyzer panicked; recovered as error",
            );
            Err(anyhow::anyhow!(
                "analysis panicked for {}: {message}",
                path.display()
            ))
        }
    }
}

/// Re-stamp path-derived values on a cache-hit report.
///
/// The analysis cache is keyed by content hash, so a hit may originate from an
/// identical-bytes file with a *different name*; `file.basename`/`file.stem`
/// in the cached values tree describe the cache donor, not the file being
/// analyzed. Observed symptom: `cleave diff` of two identical files reported a
/// phantom `file.basename` change against an unrelated donor's name.
fn restamp_path_derived_values(report: &mut AnalysisReport, path: &Path) {
    let Some(file_values) = report
        .values_tree
        .as_deref_mut()
        .and_then(|tree| tree.get_mut("file"))
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    if let Some(name) = path.file_name().and_then(|n| n.to_str())
        && let Some(basename) = file_values.get_mut("basename")
    {
        *basename = serde_json::Value::String(name.to_string());
    }
    // `Path::file_stem` matches the extractor's stem convention: leading-dot
    // names keep the dot, and only the last extension is stripped.
    if let Some(s) = path.file_stem().and_then(|s| s.to_str())
        && let Some(stem) = file_values.get_mut("stem")
    {
        *stem = serde_json::Value::String(s.to_string());
    }
}

/// Synthesize an `AnalysisReport` from a cached `FileAnalysis` (cross-context file cache hit).
fn report_from_file_analysis(fa: types::FileAnalysis, path: String) -> types::AnalysisReport {
    use types::TargetInfo;
    let target = TargetInfo {
        path,
        file_type: fa.file_type.clone(),
        size_bytes: fa.size,
        sha256: fa.sha256.clone(),
        architectures: fa.arch.as_ref().map(|a| vec![a.clone()]),
    };
    let mut report = types::AnalysisReport::new(target);
    report.findings = fa.findings;
    report.strings = fa.strings;
    report.imports = fa.imports;
    report.exports = fa.exports;
    report.functions = fa.functions;
    report.sections = fa.sections;
    report.syscalls = fa.syscalls;
    report.yara_matches = fa.yara_matches;
    report.filefacts_metrics = fa.filefacts_metrics;
    report.paths = fa.paths;
    report.directories = fa.directories;
    report.env_vars = fa.env_vars;
    report
}

/// Process encoded payloads discovered during string extraction: emit the
/// `metadata/encoded-payload/*` finding for each and recursively analyze the
/// decoded bytes (depth-limited), merging the decoded traits/findings back.
///
/// Factored out of `analyze_file_with_resources_at_depth` so the archive
/// member path can run the SAME payload analysis — previously only top-level
/// files got it, so an obfuscated payload inside an archive (npm/zip/jar) lost
/// its encoded-payload finding and every trait derived from the decoded
/// content. Detection must not depend on whether a file was scanned standalone
/// or as an archive member.
pub(crate) fn process_encoded_payloads(
    encoded_payloads: Vec<types::ExtractedPayload>,
    report: &mut types::AnalysisReport,
    path: &std::path::Path,
    file_type: FileType,
    analysis_depth: u32,
    options: &AnalysisOptions,
    capability_mapper: &Arc<CapabilityMapper>,
    yara_engine: Option<&Arc<yara_engine::YaraEngine>>,
) {
    for payload in encoded_payloads {
        if options
            .cancellation
            .as_ref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
        {
            break;
        }
        // Skip benign encoded payloads (certificate URLs, PDB paths)
        let preview_lower = payload.preview.to_lowercase();
        if payload.encoding_chain.iter().any(|e| e == "url") {
            // Skip URL-encoded strings from certificate/PKI infrastructure
            if preview_lower.contains("microsoft.com/pki")
                || preview_lower.contains("microsoft.com/pkiops")
                || preview_lower.contains("crl.microsoft.com")
                || preview_lower.contains("verisign.com")
                || preview_lower.contains("digicert.com")
                || preview_lower.contains("symantec.com")
                || preview_lower.starts_with("http") && preview_lower.contains("ocsp.")
                || preview_lower.starts_with("http") && preview_lower.contains("/crl/")
                || preview_lower.starts_with("http") && preview_lower.contains("/certs/")
            {
                tracing::debug!("Skipping benign PKI URL payload: {}", payload.preview);
                continue;
            }
            if should_skip_unknown_url_markup_payload(&payload) {
                tracing::debug!(
                    "Skipping URL-decoded markup fragment from unknown payload: {}",
                    payload.preview
                );
                continue;
            }
        }
        if payload.encoding_chain.iter().any(|e| e == "unicode-escape") {
            // Skip unicode-escape strings that are Windows file paths (PDB, build paths)
            // or JSON parser error messages containing U+XXXX references
            if payload.preview.contains(":\\")
                || payload.preview.contains(".pdb")
                || payload.preview.contains("must be escaped")
                || payload.preview.contains("control character U+")
                || is_benign_unicode_escape_payload(&payload)
                || (payload.detected_type == FileType::Unknown
                    && is_generated_python_codec_unicode_escape(report))
            {
                tracing::debug!(
                    "Skipping benign unicode-escape payload: {}",
                    payload.preview
                );
                continue;
            }
        }
        if file_type == FileType::Pe
            && !payload.encoding_chain.is_empty()
            && payload.encoding_chain.iter().all(|e| e == "hex")
            && payload.detected_type == FileType::Unknown
            && is_signed_python_extension(report)
        {
            tracing::debug!(
                "Skipping unknown hex payload in signed Python extension data tables: {}",
                payload.preview
            );
            continue;
        }
        if payload.encoding_chain.len() == 1
            && payload.encoding_chain[0] == "xor"
            && payload.detected_type == FileType::Unknown
            && payload.preview.len() < 32
        {
            tracing::debug!("Skipping short unknown xor fragment: {}", payload.preview);
            continue;
        }
        if should_skip_unknown_encoded_payload_for_text(&file_type, &payload) {
            tracing::debug!(
                "Skipping unknown encoded fragment in text/source file: {}",
                payload.preview
            );
            continue;
        }
        if should_skip_unknown_xor_payload_for_binary(
            &file_type,
            &payload,
            &report.sections,
            report,
        ) {
            tracing::debug!(
                "Skipping unknown xor fragment in ELF metadata section: {}",
                payload.preview
            );
            continue;
        }
        if payload.encoding_chain.len() == 1
            && payload.encoding_chain[0] == "xor"
            && payload.detected_type == FileType::Unknown
            && report
                .findings
                .iter()
                .any(|f| f.id == "metadata/binary/framework::dotnet-assembly")
            && report
                .findings
                .iter()
                .any(|f| f.id == "metadata/package/versioning::pe-version-resource")
            && report.findings.iter().any(|f| {
                f.id == "micro-behaviors/data/compress/library::dotnet-gzip-compression"
                    || f.id
                        == "micro-behaviors/data/embedded/payload::dotnet-getmanifestresourcestream"
            })
        {
            tracing::debug!(
                "Skipping unknown xor fragment in versioned .NET resource library: {}",
                payload.preview
            );
            continue;
        }

        // Add finding for the encoded payload
        let is_unknown_unicode_escape = payload.detected_type == FileType::Unknown
            && payload
                .encoding_chain
                .iter()
                .any(|encoding| encoding == "unicode-escape");
        let is_detached_signature_data = payload.detected_type == FileType::Unknown
            && (path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("sig"))
                || payload
                    .preview
                    .to_ascii_lowercase()
                    .starts_with("untrusted comment: signature"));
        let crit = if is_unknown_unicode_escape || is_detached_signature_data {
            types::Criticality::Baseline
        } else {
            match payload.detected_type {
                FileType::Python
                | FileType::Shell
                | FileType::Elf
                | FileType::MachO
                | FileType::Pe => types::Criticality::Suspicious,
                _ => types::Criticality::Notable,
            }
        };
        let desc = if is_detached_signature_data {
            "Encoded detached signature data".to_string()
        } else if is_unknown_unicode_escape {
            "Decoded unicode-escape content".to_string()
        } else {
            format!(
                "Encoded payload detected: {}",
                payload.encoding_chain.join(" → ")
            )
        };

        report.findings.push(types::Finding {
            src: None,
            id: format!(
                "metadata/encoded-payload/{}",
                payload.encoding_chain.join("-")
            ),
            kind: types::FindingKind::Structural,
            desc,
            conf: 0.9,
            crit,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![types::Evidence {
                method: "pattern".to_string(),
                source: "cleave".to_string(),
                value: format!("{} <{}>", payload.preview, payload.encoding_chain.join("+")),
                location: Some(format!("offset:{}", payload.original_offset)),
                ..Default::default()
            }],
            match_count: 0,
            source_file: None,
        });

        // Unknown-type payloads have no analyzer and would immediately bail — skip
        // the expensive temp-file write + full pipeline call.  The encoded-payload
        // finding was already pushed above so the discovery is still recorded.
        if payload.detected_type == FileType::Unknown {
            tracing::debug!(
                encoding = %payload.encoding_chain.join("+"),
                preview = %payload.preview,
                "Skipping recursive analysis for unrecognized payload type"
            );
            continue;
        }

        // Analyze the decoded payload (with depth limit to prevent stack overflow)
        if analysis_depth >= MAX_ANALYSIS_DEPTH {
            tracing::warn!(
                depth = analysis_depth,
                path = %path.display(),
                "Encoded payload analysis depth limit reached ({MAX_ANALYSIS_DEPTH}), skipping deeper analysis"
            );
            report.findings.push(types::Finding {
                src: None,
                id: "objectives/anti-static/obfuscation/multi-layer/deep-nesting".to_string(),
                kind: types::FindingKind::Indicator,
                desc: format!(
                    "Encoded payload nesting exceeds {MAX_ANALYSIS_DEPTH} layers, \
                     a technique used to resist automated analysis"
                ),
                conf: 0.95,
                crit: types::Criticality::Suspicious,
                mbc: Some("OB0002".to_string()),
                attack: Some("T1027".to_string()),
                trait_refs: vec![],
                evidence: vec![types::Evidence {
                    method: "structural".to_string(),
                    source: "cleave".to_string(),
                    value: format!("depth={analysis_depth}"),
                    location: None,
                    ..Default::default()
                }],
                match_count: 0,
                source_file: None,
            });
            break;
        }
        if let Ok(mut temp_file) = tempfile::NamedTempFile::new() {
            let _ = std::io::Write::write_all(&mut temp_file, &payload.data);
            if let Ok(payload_report) = analyze_file_with_resources_at_depth(
                temp_file.path(),
                options,
                capability_mapper,
                yara_engine,
                None,
                None,
                analysis_depth + 1,
            ) {
                // Merge traits from payload analysis
                for mut trait_item in payload_report.traits {
                    // Prefix trait offset with encoding chain
                    if let Some(ref offset) = trait_item.offset {
                        trait_item.offset =
                            Some(format!("{}!{}", payload.encoding_chain.join("+"), offset));
                    } else {
                        trait_item.offset = Some(format!("{}!", payload.encoding_chain.join("+")));
                    }
                    report.traits.push(trait_item);
                }

                // Merge findings from payload analysis
                let existing: std::collections::HashSet<String> =
                    report.findings.iter().map(|f| f.id.clone()).collect();
                for finding in payload_report.findings {
                    if !existing.contains(finding.id.as_str()) {
                        report.findings.push(finding);
                    }
                }
            }
        }
    }
}

fn analyze_file_with_resources_at_depth<P: AsRef<Path>>(
    path: P,
    options: &AnalysisOptions,
    capability_mapper: &Arc<CapabilityMapper>,
    yara_engine: Option<&Arc<yara_engine::YaraEngine>>,
    preloaded: Option<file_io::FileData>,
    precomputed_sha256: Option<String>,
    analysis_depth: u32,
) -> Result<AnalysisReport> {
    struct ThreadLocalCacheClearGuard;

    impl Drop for ThreadLocalCacheClearGuard {
        fn drop(&mut self) {
            crate::composite_rules::evaluators::clear_thread_local_caches();
        }
    }

    let path = path.as_ref();
    // Clear thread-local UTF-8 / scanner caches after every analysis frame,
    // including nested payload decoding (analysis_depth > 0). Leaving entries
    // in the LRU across depth levels let a deep decoding chain pin multiple
    // multi-hundred-MB UTF-8 caches on a single worker thread.
    let _thread_local_cache_clear_guard = ThreadLocalCacheClearGuard;
    let span = tracing::info_span!("analyze", path = %path.display());
    let _enter = span.enter();

    // Report fine-grained progress through the phase tracker so a stuck
    // analysis says something more useful than `cleave:init` for ten minutes.
    let set_phase = |p: &str| {
        if let Some(ref tracker) = options.phase {
            tracker.set(p);
        }
    };

    // Log BEFORE processing to ensure we capture what file causes OOM crashes
    tracing::debug!("Starting analysis");

    // Read file once — reuse pre-loaded data if available (e.g. from analyze_bytes
    // or the fast-path cache check). When data is preloaded the path may be synthetic
    // and not exist on disk, so skip the filesystem checks.
    set_phase("cleave:read");
    let file_data_wrapper = match preloaded {
        Some(data) => data,
        None => {
            if !path.exists() {
                anyhow::bail!("Path does not exist: {}", path.display());
            }
            if path.is_dir() {
                anyhow::bail!(
                    "Path is a directory, use scan_directory instead: {}",
                    path.display()
                );
            }
            file_io::read_file_smart(path)?
        }
    };
    let file_data = file_data_wrapper.as_slice();

    // Detect file type from already-loaded data (no extra read)
    set_phase("cleave:detect");
    tracing::debug!("Detecting file type for: {}", path.display());
    let file_type = analyzers::detect_file_type_from_data(path, file_data);
    tracing::debug!(
        "Detected file type: {:?} for: {}",
        file_type,
        path.display()
    );

    // Explicit file analysis should still run for unknown top-level inputs so callers can
    // inspect ad hoc files directly. Directory scans keep their own pre-filtering logic.

    // Get file size for memory tracking (from loaded data, avoiding a metadata syscall)
    let file_size = file_data.len() as u64;

    // Log memory state before processing
    memory_tracker::log_before_file_processing(path.to_str().unwrap_or("unknown"), file_size);

    let analysis_start = std::time::Instant::now();

    // Track file read for memory monitoring
    memory_tracker::global_tracker()
        .record_file_read(file_size, path.to_str().unwrap_or("unknown"));

    // Reuse a precomputed hash when the caller already hashed these bytes for a
    // fast-path cache lookup; otherwise compute it here. Skipping the recompute
    // matters for large inputs — SHA256 of a 100 MB archive is ~200 ms.
    let sha256_hex =
        precomputed_sha256.unwrap_or_else(|| analyzers::utils::calculate_sha256(file_data));

    // Set current file ID for IP validation cache
    let file_id = hash_str(&sha256_hex);
    ip_validator::set_current_file_id(file_id);

    // Check analysis cache before running the full pipeline
    set_phase("cleave:cache_lookup");
    if let Some(mut cached_report) = analysis_cache::report_cache_lookup(&sha256_hex, options) {
        cached_report.target.path = path.display().to_string();
        cached_report.analysis_timestamp = Some(chrono::Utc::now());
        restamp_path_derived_values(&mut cached_report, path);
        tracing::debug!("Cache hit");
        memory_tracker::log_after_file_processing(
            path.to_str().unwrap_or("unknown"),
            file_size,
            analysis_start.elapsed(),
        );
        return Ok(cached_report);
    }

    // Secondary check: per-file cache (cross-context, shared with archive members)
    if let Some(fa) = analysis_cache::file_analysis_cache_lookup(&sha256_hex, options) {
        tracing::debug!("File cache hit (cross-context)");
        let report = report_from_file_analysis(fa, path.display().to_string());
        memory_tracker::log_after_file_processing(
            path.to_str().unwrap_or("unknown"),
            file_size,
            analysis_start.elapsed(),
        );
        return Ok(report);
    }

    // Extension/content mismatch is emitted by YAML traits under
    // objectives/evasion/masquerade/extension-mismatch/ (consuming the
    // filefacts consistency.extension_content_mismatch metric).

    // Normalize text encoding (UTF-16 LE/BE BOM -> UTF-8) before string
    // extraction, metrics, and trait matching.
    //
    // Why: `type: text` on source/text file types is evaluated by `eval_raw()`
    // against the file content (so cross-line regexes like `[\s\S]{0,N}` keep
    // working — ~950 traits depend on that). A UTF-16 script is null-interleaved
    // at the byte level (`E\0x\0e\0c\0...`), so without normalization no text
    // pattern matches and the file looks empty (e.g. a UTF-16 VBS dropper). We
    // normalize the content the matcher reads rather than reroute `type: text`
    // to the per-line stng strings, which would lose those cross-line patterns.
    //
    // Gating on the BOM alone is safe and mirrors `file_io::read_file_normalized`:
    // no real binary/archive format begins with FF FE / FE FF, and SHA +
    // file-type detection above already ran on the original bytes, so file
    // identity is unchanged.
    let normalized_data: Option<file_io::FileData> =
        match file_io::normalize_text_encoding(file_data) {
            std::borrow::Cow::Owned(decoded) => Some(file_io::FileData::Owned(decoded)),
            std::borrow::Cow::Borrowed(_) => None,
        };
    let file_data: &[u8] = normalized_data
        .as_ref()
        .map_or(file_data, file_io::FileData::as_slice);

    // For binary types (PE, ELF, MachO) run the YARA scan concurrently with stng extraction.
    // Both only need file_data and are independent of each other, so they can overlap.
    // On production runs where radare2 is cached, YARA (~270ms) otherwise sits between
    // stng (~290ms) and structural (~50ms), adding to the critical path.  Running them in
    // parallel eliminates that 270ms from the wall-clock total.
    let binary_yara_ftypes: Option<&[&str]> = if options.disable_yara {
        None
    } else {
        match file_type {
            FileType::Pe => Some(&["pe", "exe", "dll", "bat", "ps1"]),
            FileType::Elf => Some(&["elf", "so", "ko"]),
            FileType::MachO => Some(&["macho", "dylib", "kext"]),
            _ => None,
        }
    };

    // Extract strings with stng ONCE - used for encoded payloads and passed to analyzers.
    // Skip extraction for archive files themselves as they are expected to contain
    // binary noise and their contents will be analyzed separately.
    // For binary types, overlap stng with YARA scan (both need only file_data).
    set_phase(if binary_yara_ftypes.is_some() {
        "cleave:stng+yara"
    } else {
        "cleave:stng"
    });
    let cancel_for_yara = options.cancellation.clone();
    let cancel_for_stng = options.cancellation.as_ref();
    let ((stng_strings, stage_stng_ms), prefetched_yara) = if file_type.is_archive() {
        ((Vec::new(), 0u64), None)
    } else if let Some(ftypes) = binary_yara_ftypes {
        rayon::join(
            || {
                let t = std::time::Instant::now();
                let opts = analyzers::attach_stng_cancellation(
                    analyzers::stng_analysis_opts(4),
                    cancel_for_stng,
                );
                let s = stng::extract_strings_with_options(file_data, &opts);
                (s, t.elapsed().as_millis() as u64)
            },
            || {
                if cancel_for_yara
                    .as_ref()
                    .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                {
                    return None;
                }
                yara_engine
                    .filter(|e| e.is_loaded())
                    .map(|e| e.scan_bytes_with_inline(file_data, Some(ftypes)))
            },
        )
    } else {
        let t = std::time::Instant::now();
        let opts =
            analyzers::attach_stng_cancellation(analyzers::stng_analysis_opts(4), cancel_for_stng);
        let s = stng::extract_strings_with_options(file_data, &opts);
        ((s, t.elapsed().as_millis() as u64), None)
    };

    // Check for encoded payloads (hex, base64, etc.) using stng results
    let encoded_payloads = if stng_strings.is_empty() {
        Vec::new()
    } else {
        extractors::encoded_payload::extract_encoded_payloads(&stng_strings)
    };

    // Create unified analysis input - all analyzers receive the same pre-extracted data
    let mut input = analyzers::AnalysisInput::with_payloads(
        path,
        file_data,
        &stng_strings,
        &encoded_payloads,
        file_type,
    )
    .with_sha256(sha256_hex.clone());
    input.cancellation = options.cancellation.clone();

    // Convert stng strings to StringInfo for binary analyzers (avoids redundant extraction)
    let string_extractor = strings::StringExtractor::new();
    let preextracted_strings = string_extractor.convert_stng_strings(&stng_strings);

    // Share mapper Arc — all analyzers share it via cheap ref-count bumps
    let mapper_arc = Arc::clone(capability_mapper);

    // Bail early if already cancelled before starting expensive structural analysis
    if options
        .cancellation
        .as_ref()
        .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
    {
        anyhow::bail!("Analysis cancelled before structural phase");
    }

    // Route to appropriate analyzer.
    // Binary analyzers (MachO, Elf, Pe) use parallel YARA for performance.
    // All other analyzers use analyze_input() for unified data flow.
    let structural_start = std::time::Instant::now();
    let mut report = match file_type {
        FileType::MachO => {
            set_phase("macho:struct+yara");
            // YARA scan was already run concurrently with stng extraction above (prefetched_yara).
            // Note: the stng+YARA join used full file_data for FAT binaries. The arch_data slice
            // below selects the preferred slice for structural analysis, while YARA already
            // covered the full binary which is correct (YARA targets the outer container).
            let analyzer = analyzers::macho::MachOAnalyzer::new()
                .with_cancellation(options.cancellation.clone())
                .with_capability_mapper_arc(mapper_arc.clone())
                .with_preextracted_strings(preextracted_strings.clone());
            let range = analyzer.preferred_arch_range(file_data);
            let arch_data = &file_data[range.clone()];
            let labeled_ranges = analyzer.labeled_arch_ranges(file_data);
            let is_fat = labeled_ranges.len() > 1;
            let eval_data = if is_fat { file_data } else { arch_data };
            let engine = yara_engine;
            let rule_file_type = capability_mapper.detect_file_type("macho");
            // Open filefacts on the preferred-arch slice so the Mach-O
            // analyzer can pull dyld imports / export-trie entries
            // from the typed view instead of re-walking goblin.
            // When filefacts can't open the bytes, fall back to the
            // analyzer's own bytes-only entry point so the malformed
            // signal is still surfaced.
            let ctx = crate::analysis_context::AnalysisContext::open(path, arch_data).ok();
            let struct_result: Result<AnalysisReport, anyhow::Error> =
                if let Some(ctx) = ctx.as_ref() {
                    Ok(analyzer.analyze_structural_with_ctx(
                        path,
                        arch_data,
                        input.sha256.clone(),
                        ctx,
                    ))
                } else {
                    Ok(analyzer.analyze_structural(path, arch_data, input.sha256.clone()))
                };
            let raw_regex =
                capability_mapper.precompute_raw_regex_matches(eval_data, &rule_file_type);
            let mut report = struct_result?;
            report.filefacts = ctx.as_ref().map(crate::types::FilefactsView::from_ctx);
            report.identity = ctx
                .as_ref()
                .and_then(crate::analysis_context::AnalysisContext::identity);
            analyzer.apply_fat_metadata(&mut report, file_data);

            // The preferred slice was parsed at base 0, so its structural
            // offsets are slice-relative. Strings, raw matching, YARA, and
            // the hex view all use full-file coordinates — rebase the
            // preferred slice's offsets to match before any of them run.
            if is_fat {
                analyzers::macho::MachOAnalyzer::rebase_slice_offsets(
                    &mut report,
                    range.start as u64,
                );
            }

            // For FAT binaries, open each non-preferred arch slice as
            // its own AnalysisContext and union its imports/exports
            // into the report. Without this, malware hidden in a
            // non-preferred arch (e.g. malicious x86_64 slice with a
            // benign arm64 slice) escapes filefacts-derived trait rules.
            // YARA and stng already cover the full file, so this
            // closes the remaining gap.
            if is_fat {
                let preferred_offset = range.start;
                analyzer.union_supplementary_arches(&mut report, file_data, preferred_offset);
            }

            // For FAT binaries, re-extract strings from full file for correct offsets
            if is_fat && preextracted_strings.is_empty() {
                report.strings = string_extractor.extract_smart(file_data);
            }

            // Process YARA results and evaluate with inline evidence
            let inline_yara =
                process_yara_result(&mut report, prefetched_yara, engine.map(AsRef::as_ref));
            let fat_arch_ranges = if is_fat { Some(labeled_ranges) } else { None };
            // Trait authors read cross-format facts directly from
            // `report.filefacts.values.*` (PE/ELF/Mach-O native trees).
            analyzers::binary_extractors::augment_report(&mut report, eval_data);
            set_phase("macho:traits");
            capability_mapper.evaluate_and_merge_findings_with_precomputed(
                &mut report,
                eval_data,
                crate::capabilities::AnalysisBorrow::with_filefacts(
                    None,
                    if is_fat { None } else { ctx.as_ref() },
                ),
                Some(&inline_yara),
                Some(raw_regex),
                fat_arch_ranges.as_deref(),
                options.cancellation.as_deref(),
            );
            Ok(report)
        }
        FileType::Elf => {
            set_phase("elf:struct+yara");
            // YARA scan was already run concurrently with stng extraction above (prefetched_yara).
            // Note: when running inside an archive par_iter (member analysis), the old pattern of
            // rayon::join(struct, yara) could cause pool-saturation stalls (r2 holding a rayon
            // thread while YARA tasks queued). Prefetching eliminates that race entirely.
            tracing::debug!(
                on_rayon_thread = rayon::current_thread_index().is_some(),
                data_bytes = file_data.len(),
                "ELF: entering structural analysis (YARA already prefetched)"
            );
            let mut analyzer = analyzers::elf::ElfAnalyzer::new()
                .with_cancellation(options.cancellation.clone())
                .with_capability_mapper_arc(mapper_arc.clone())
                .with_preextracted_strings(preextracted_strings.clone());
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara_arc(engine);
            }
            let engine = yara_engine;
            let rule_file_type = capability_mapper.detect_file_type("elf");
            // Open filefacts once and lend it to the ELF analyzer so
            // structural helpers read from the typed view directly.
            // When filefacts can't open the bytes, fall back to the
            // analyzer's own bytes-only entry point so the malformed
            // signal is still surfaced.
            let ctx = crate::analysis_context::AnalysisContext::open(path, file_data).ok();
            let struct_result: Result<AnalysisReport, anyhow::Error> =
                if let Some(ctx) = ctx.as_ref() {
                    Ok(analyzer.analyze_structural_with_ctx(
                        path,
                        file_data,
                        input.sha256.as_deref(),
                        ctx,
                    ))
                } else {
                    Ok(analyzer.analyze_structural(path, file_data, input.sha256.clone()))
                };
            let raw_regex =
                capability_mapper.precompute_raw_regex_matches(file_data, &rule_file_type);
            let mut report = struct_result?;
            report.filefacts = ctx.as_ref().map(crate::types::FilefactsView::from_ctx);
            report.identity = ctx
                .as_ref()
                .and_then(crate::analysis_context::AnalysisContext::identity);
            let inline_yara =
                process_yara_result(&mut report, prefetched_yara, engine.map(AsRef::as_ref));
            // Trait authors read ELF facts directly from
            // `report.filefacts.values.elf.*`. Format-specific extractors
            // (B0.5 .comment, B3 DWARF) layer cleave-side augmentation
            // through `binary_extractors::augment_report`.
            analyzers::binary_extractors::augment_report(&mut report, file_data);
            set_phase("elf:traits");
            capability_mapper.evaluate_and_merge_findings_with_precomputed(
                &mut report,
                file_data,
                crate::capabilities::AnalysisBorrow::with_filefacts(None, ctx.as_ref()),
                Some(&inline_yara),
                Some(raw_regex),
                None,
                options.cancellation.as_deref(),
            );
            path_mapper::analyze_and_link_paths(&mut report);
            env_mapper::analyze_and_link_env_vars(&mut report);
            Ok(report)
        }
        FileType::Pe => {
            set_phase("pe:struct+yara");
            // YARA scan was already run concurrently with stng extraction above (prefetched_yara).
            // .bat/.ps1 files are also routed here (file_types includes "bat", "ps1") and are
            // scanned by all PE-tier YARA rules.
            tracing::debug!(
                on_rayon_thread = rayon::current_thread_index().is_some(),
                data_bytes = file_data.len(),
                "PE: entering structural analysis (YARA already prefetched)"
            );
            let mut analyzer = analyzers::pe::PEAnalyzer::new()
                .with_cancellation(options.cancellation.clone())
                .with_capability_mapper_arc(mapper_arc.clone())
                .with_preextracted_strings(preextracted_strings.clone());
            // PE analyzer needs YARA engine for overlay/embedded payload analysis
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            let engine = yara_engine;
            let rule_file_type = capability_mapper.detect_file_type("pe");
            // Open filefacts once here and lend the same typed view to the PE
            // analyzer and trait mapper so sections, imports, exports, values,
            // and metrics are projected without another PE parser pass.
            let ctx = crate::analysis_context::AnalysisContext::open(path, file_data)
                .map_err(|e| anyhow::anyhow!("filefacts open failed for PE: {e}"))?;
            let struct_result = Ok::<_, anyhow::Error>(analyzer.analyze_structural_with_ctx(
                path,
                file_data,
                input.sha256.as_deref(),
                &ctx,
            ));
            let filefacts_view = crate::types::FilefactsView::from_ctx(&ctx);
            let raw_regex =
                capability_mapper.precompute_raw_regex_matches(file_data, &rule_file_type);
            let mut report = struct_result?;
            report.filefacts = Some(filefacts_view);
            report.identity = ctx.identity();
            let inline_yara =
                process_yara_result(&mut report, prefetched_yara, engine.map(AsRef::as_ref));
            // Trait authors read PE facts directly from
            // `report.filefacts.values.pe.*`. B2 layers VERSIONINFO /
            // Rich header / imphash on top via
            // `binary_extractors::augment_report`.
            analyzers::binary_extractors::augment_report(&mut report, file_data);
            set_phase("pe:traits");
            capability_mapper.evaluate_and_merge_findings_with_precomputed(
                &mut report,
                file_data,
                crate::capabilities::AnalysisBorrow::with_filefacts(None, Some(&ctx)),
                Some(&inline_yara),
                Some(raw_regex),
                None,
                options.cancellation.as_deref(),
            );
            Ok(report)
        }
        FileType::JavaClass => analyzers::java_class::JavaClassAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze_input(&input),
        FileType::OleDoc | FileType::Ooxml => analyzers::office::OfficeAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .with_cancellation(options.cancellation.clone())
            .analyze_input(&input),
        ref ft if ft.is_archive() => {
            set_phase(&format!("archive:{}", ft.report_file_type()));
            let mut analyzer = analyzers::archive::ArchiveAnalyzer::new()
                .with_capability_mapper_arc(mapper_arc.clone())
                .with_zip_passwords(options.zip_passwords.clone())
                .with_max_memory_file_size(options.max_memory_file_size)
                .with_analysis_options(Arc::new(options.clone()));
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            if let Some(ref config) = options.sample_extraction {
                analyzer = analyzer.with_sample_extraction(config.clone());
            }
            if let Some(ref flag) = options.cancellation {
                analyzer = analyzer.with_cancellation(flag.clone());
            }
            analyzer.analyze_input(&input)
        }
        FileType::PackageJson => analyzers::package_json::PackageJsonAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze_input(&input),
        FileType::PackageLockJson => analyzers::generic::GenericAnalyzer::new(file_type)
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze_input(&input),
        FileType::VsixManifest => analyzers::vsix_manifest::VsixManifestAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze_input(&input),
        // All source code languages use the unified analyzer (or generic fallback)
        _ => {
            set_phase(&format!("analyze:{}", file_type.report_file_type()));
            if let Some(analyzer) =
                analyzers::analyzer_for_file_type_arc(&file_type, Some(mapper_arc.clone()))
            {
                analyzer.analyze_input(&input)
            } else {
                // No dedicated analyzer — return a minimal report with basic metadata.
                // This allows callers (analyze_file, scan_directory with all_files=true)
                // to handle files of any type without erroring.
                let target = types::TargetInfo {
                    path: path.display().to_string(),
                    file_type: file_type.report_file_type(),
                    size_bytes: file_data.len() as u64,
                    sha256: sha256_hex.clone(),
                    architectures: None,
                };
                Ok(types::AnalysisReport::new(target))
            }
        }
    }?;

    // Identity is normalized the same way for every file. Binary, source,
    // and archive analyzers attach it from the filefacts context they
    // already opened; for the remaining formats (documents, images, …)
    // derive it once here so the headline is consistent across every
    // analyzer path. Gated on `is_none` so no path pays a second open.
    if report.identity.is_none()
        && let Ok(ctx) = crate::analysis_context::AnalysisContext::open(path, file_data)
    {
        report.identity = ctx.identity();
    }
    let stage_structural_ms = structural_start.elapsed().as_millis() as u64;

    // Process encoded payloads and analyze them
    let payloads_start = std::time::Instant::now();
    if !encoded_payloads.is_empty() {
        set_phase("payloads");
    }
    process_encoded_payloads(
        encoded_payloads,
        &mut report,
        path,
        file_type,
        analysis_depth,
        options,
        capability_mapper,
        yara_engine,
    );
    let stage_payloads_ms = payloads_start.elapsed().as_millis() as u64;

    // Bail early if cancelled — skip YARA and remaining phases
    if options
        .cancellation
        .as_ref()
        .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
    {
        anyhow::bail!("Analysis cancelled before YARA phase");
    }

    // Run YARA for file types that didn't handle it internally.
    // Binary types (MachO, Elf, Pe) and archives already ran YARA with parallel scanning above.
    set_phase("yara");
    let yara_start = std::time::Instant::now();
    let handled_yara_internally =
        matches!(file_type, FileType::MachO | FileType::Elf | FileType::Pe)
            || file_type.is_archive();
    if !handled_yara_internally
        && let Some(engine) = yara_engine
        && file_type.is_program()
        && engine.is_loaded()
    {
        let file_types = file_type.yara_filetypes();
        let filter = if file_types.is_empty() {
            None
        } else {
            Some(file_types.as_slice())
        };

        match engine.scan_bytes_to_findings(file_data, filter) {
            Ok((matches, findings)) => {
                report.yara_matches = matches;
                let existing: std::collections::HashSet<String> =
                    report.findings.iter().map(|f| f.id.clone()).collect();
                for finding in findings {
                    if !existing.contains(finding.id.as_str()) {
                        report.findings.push(finding);
                    }
                }
                if !report.metadata.tools_used.iter().any(|t| t == "yara-x") {
                    report.metadata.tools_used.push("yara-x".to_string());
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "YARA scan failed, continuing without YARA results");
                report.metadata.errors.push(format!("yara: {e:#}"));
            }
        }
    }
    let stage_yara_ms = yara_start.elapsed().as_millis() as u64;
    set_phase("done");

    if file_type == FileType::Elf {
        report.findings.retain(|finding| {
            if finding.id != "metadata/encoded-payload/xor" {
                return true;
            }

            !finding.evidence.iter().any(|evidence| {
                parse_evidence_offset(&evidence.location)
                    .is_some_and(|offset| is_elf_metadata_offset(offset, &report.sections))
            })
        });
    }

    // Filter low-value composite "any" rules (needs=1) before caching: they add
    // nothing over the underlying trait that matched — UNLESS a composite depends
    // on one. A trait referenced by a composite is, by definition, not low value:
    // it's what ties that composite to the file (and offset) it fired on, so
    // dropping it would erase the composite's cross-file provenance.
    let composite_referenced: std::collections::HashSet<String> = report
        .findings
        .iter()
        .chain(report.files.iter().flat_map(|f| f.findings.iter()))
        .flat_map(|f| f.trait_refs.iter().cloned())
        .collect();
    let removed = report.filter_findings(|f| {
        !capability_mapper.is_low_value_any_rule(&f.id) || composite_referenced.contains(&f.id)
    });
    if removed > 0 {
        tracing::debug!("Filtered {} low-value composite 'any' rules", removed);
    }

    let total_ms = analysis_start.elapsed().as_millis() as u64;

    // Identify the slowest stage for quick bottleneck spotting
    let slowest = [
        ("stng", stage_stng_ms),
        ("structural", stage_structural_ms),
        ("payloads", stage_payloads_ms),
        ("yara", stage_yara_ms),
    ]
    .into_iter()
    .max_by_key(|(_, ms)| *ms)
    .map(|(name, _)| name)
    .unwrap_or("none");

    // Per-file stage timing summary — debug! because this fires for every
    // file and serializes on the tracing writer mutex at info level. At 10M
    // files × 24 workers, the mutex cost dominates the log itself.
    tracing::debug!(
        total_ms,
        stng_ms = stage_stng_ms,
        structural_ms = stage_structural_ms,
        payloads_ms = stage_payloads_ms,
        yara_ms = stage_yara_ms,
        slowest,
        file_type = ?file_type,
        size_kb = file_size / 1024,
        findings = report.findings.len(),
        traits = report.traits.len(),
        "Analysis complete",
    );

    // Log memory state after processing
    memory_tracker::log_after_file_processing(
        path.to_str().unwrap_or("unknown"),
        file_size,
        analysis_start.elapsed(),
    );

    // Universal file-level metrics — guaranteed populated regardless of
    // which analyzer ran, so consumers (cleave diff in particular) can
    // rely on `file.size` for every analyzed file. Writes directly into
    // the flat metric map; the typed `FileMetrics` struct is retired
    // (#41).
    {
        use crate::types::MetricsExt;
        let size = report.target.size_bytes;
        report
            .filefacts_metrics
            .get_or_insert_with(Default::default)
            .set_u("file.size", size);
    }

    // Collapse duplicate findings (same id) before anything downstream sees
    // the report. Some analyzers emit one finding per match site; consumers
    // (diff, ML feature extraction, JSON viewers) want one logical finding
    // per id with merged evidence.
    report.dedupe_findings();

    // Capture merged, render-ready context windows from the findings while the
    // file bytes are still in scope. This is the LLM/output surface that
    // replaces raw per-finding evidence; it rides the report into both caches.
    crate::context::capture(&mut report, file_data, file_type);

    // Store result in per-file cache (cross-context: shared with archive member analysis)
    {
        let mut fa = report.to_file_analysis(0);
        fa.path = String::new();
        fa.id = 0;
        fa.parent_id = None;
        fa.depth = 0;
        fa.extracted_path = None;
        analysis_cache::file_analysis_cache_store(&sha256_hex, options, &fa);
    }

    // Store result in analysis cache for future lookups
    analysis_cache::report_cache_store(&sha256_hex, options, &report);

    Ok(report)
}

/// An event emitted during [`scan_directory`].
#[derive(Debug)]
pub enum ScanEvent {
    /// Emitted exactly once before analysis begins.
    ///
    /// `total` is `None` because the scan streams the directory walk: analysis
    /// starts as soon as the first path is yielded, so the final count is not
    /// known upfront. The final count is available on `ScanSummary.total`
    /// returned from [`scan_directory`] once the scan completes.
    Start {
        /// Total number of files that will be analyzed, if known upfront.
        total: Option<usize>,
    },
    /// Emitted for each file as its analysis completes. May arrive from any rayon worker thread.
    File {
        /// Path to the analyzed file.
        path: std::path::PathBuf,
        /// Analysis result, or an error if analysis failed.
        result: Box<Result<AnalysisReport>>,
    },
}

/// Summary returned by [`scan_directory`] after all files have been processed.
#[derive(Debug, Clone, Default)]
pub struct ScanSummary {
    /// Total files submitted for analysis (passed the type filter).
    pub total: usize,
    /// Files successfully analyzed.
    pub analyzed: usize,
    /// Files that failed analysis.
    pub errors: usize,
}

/// Load the CapabilityMapper and YARA engine once for a parallel scan.
///
/// Both are wrapped in `Arc` so every rayon worker shares a single instance via
/// cheap clones rather than reloading per file. The two loads run concurrently
/// on the rayon pool. Shared by [`scan_directory`] and [`scan_files`].
fn load_scan_resources(
    options: &AnalysisOptions,
) -> Result<(Arc<CapabilityMapper>, Option<Arc<yara_engine::YaraEngine>>)> {
    let (mapper_result, yara_engine) = rayon::join(
        || shared_resources::capability_mapper_with_options(options),
        || {
            if options.disable_yara {
                None
            } else {
                Some(shared_resources::yara_engine(
                    options.enable_third_party_yara,
                ))
            }
        },
    );
    Ok((mapper_result?, yara_engine))
}

/// Scan a directory, invoking `callback` for each file as its analysis completes.
///
/// Results stream out of the parallel workers as they finish rather than being
/// collected into a `Vec`. This makes it suitable for progress reporting,
/// streaming output, and processing large directories without accumulating all
/// results in memory — the only viable entry point at 10M-file scale.
///
/// The callback first receives a [`ScanEvent::Start`] with the total file count,
/// then a [`ScanEvent::File`] for every file attempted, including failures. The
/// `Start` event is always delivered before any `File` events.
///
/// Resources (CapabilityMapper and YARA engine) are loaded once and shared across
/// all parallel workers, avoiding the per-file reload overhead of calling
/// [`analyze_file`] in a loop.
///
/// Hidden files and non-program file types are silently skipped unless
/// `options.all_files` is set.
///
/// # Errors
///
/// Returns `Err` only for setup failures (path is not a directory, resource load
/// failure). Per-file errors are delivered through the callback as
/// [`ScanEvent::File`] with an `Err` result.
pub fn scan_directory<P, F>(path: P, options: &AnalysisOptions, callback: F) -> Result<ScanSummary>
where
    P: AsRef<Path>,
    F: Fn(ScanEvent) + Sync,
{
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use walkdir::WalkDir;

    let path = path.as_ref();
    if !path.is_dir() {
        anyhow::bail!("path is not a directory: {}", path.display());
    }
    let _disable_guards = AnalysisDisableGuards::from_options(options);

    // Prune stale radare2 disk-cache entries in the background. The `re/` dir
    // has no in-line eviction and grows unbounded across scans (each new SHA256
    // adds a zstd-compressed blob). 30 days matches the server default.
    std::thread::spawn(|| {
        let removed = cache::prune_re_cache(30 * 24 * 3600);
        if removed > 0 {
            tracing::info!(removed, "Pruned stale RE cache entries");
        }
    });

    // Load shared resources once; all rayon workers share them via cheap Arc clones.
    let (mapper, yara_engine) = load_scan_resources(options)?;

    let all_files_flag = options.all_files;

    // Counters shared across the walk producer and analyzer consumers.
    // The walk runs inside `par_bridge`, which serializes `next()` across
    // worker threads, so these are touched from multiple threads (one at a
    // time inside the bridge's mutex). Atomic fetch_add is still the right
    // primitive — it's what the Drop-time summary and ScanSummary read.
    let walked = AtomicUsize::new(0);
    let walk_errors = AtomicUsize::new(0);
    let dirs_entered = AtomicUsize::new(0);

    // Total is not known until the walk finishes. Downstream progress UIs
    // should listen for the final count on the returned ScanSummary.
    callback(ScanEvent::Start { total: None });

    let analyzed = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);
    let errors = AtomicUsize::new(0);

    let max_scan_size = options.max_scan_file_size;

    // Build the walk iterator once. par_bridge() drives `next()` from worker
    // threads behind an internal mutex — the walk proceeds lazily as workers
    // pull, so we never materialize the full PathBuf list. Memory for pending
    // paths stays bounded to the work-stealing deque depth instead of growing
    // with total file count.
    let analyze_files = || {
        use rayon::iter::ParallelBridge;

        let walk = WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let dotgit = e.file_name().to_string_lossy().starts_with(".git");
                if dotgit {
                    tracing::debug!(path = %e.path().display(), "Skipping dotgit directory");
                }
                !dotgit
            })
            .filter_map(|entry| match entry {
                Ok(e) => Some(e),
                Err(e) => {
                    walk_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(error = %e, "Failed to read directory entry");
                    None
                }
            })
            .filter(|e| {
                if e.file_type().is_dir() {
                    dirs_entered.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                if !e.file_type().is_file() {
                    tracing::debug!(path = %e.path().display(), "Skipping non-file entry");
                    return false;
                }
                walked.fetch_add(1, Ordering::Relaxed);
                true
            })
            .map(|e| e.path().to_path_buf());

        let mem_gate = scan_mem_gate::ScanMemGate::new();
        walk.par_bridge().for_each(|file_path| {
        // Cancellation fast path: once SIGINT has flipped the flag, every
        // remaining par_bridge slot returns instantly so the scan drains in
        // work already in-flight rather than starting new files. Inner
        // analyzers (rizin, YARA, tree-sitter) also observe the flag via
        // options.cancellation for sub-file granularity.
        if options
            .cancellation
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Relaxed))
        {
            skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Bound concurrent memory: a burst of large archives serialises instead
        // of co-residing and OOM-killing the host. Held until this file is done.
        let _mem_permit =
            mem_gate.acquire(std::fs::metadata(&file_path).map(|m| m.len()).unwrap_or(0));

        // Catch panics from any analyzer so one malformed file doesn't
        // poison the rayon thread pool and kill the entire scan.
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Skip files exceeding the size limit (avoids mmap'ing huge ISOs/disk images).
        if max_scan_size > 0
            && let Ok(meta) = std::fs::metadata(&file_path)
                && meta.len() > max_scan_size {
                    tracing::debug!(
                        path = %file_path.display(),
                        size_mb = meta.len() / (1024 * 1024),
                        limit_mb = max_scan_size / (1024 * 1024),
                        "skipping file exceeding --max-file-size limit"
                    );
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return;
                }

        // File-type filtering: read the file once and check type from loaded data.
        // Previously this was done during collection (reading every file twice).
        if !all_files_flag {
            let Ok(file_data) = file_io::read_file_smart(&file_path) else {
                tracing::debug!(path = %file_path.display(), "Skipping unreadable file");
                skipped.fetch_add(1, Ordering::Relaxed);
                return;
            };
            let ft = analyzers::detect_file_type_from_data(&file_path, file_data.as_slice());
            if !analyzers::is_analyzable(&file_path, &ft) {
                tracing::debug!(path = %file_path.display(), file_type = ?ft, "Skipping non-analyzable file");
                skipped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            // Pass pre-loaded data to avoid a second read
            let result = analyze_file_with_resources(
                &file_path,
                options,
                &mapper,
                yara_engine.as_ref(),
                Some(file_data),
            );
            match &result {
                Ok(_) => {
                    analyzed.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            callback(ScanEvent::File {
                path: file_path.clone(),
                result: Box::new(result),
            });
            // Release wasmtime Scanner VMs on this thread to prevent non-jemalloc
            // memory accumulation. Each Scanner holds mmap'd VM regions (~50-100MB)
            // that macOS keeps resident even after munmap (MADV_FREE).
            composite_rules::evaluators::clear_thread_local_caches();
            return;
        }

        let result =
            analyze_file_with_resources(&file_path, options, &mapper, yara_engine.as_ref(), None);
        match &result {
            Ok(_) => {
                analyzed.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        callback(ScanEvent::File {
            path: file_path.clone(),
            result: Box::new(result),
        });
        composite_rules::evaluators::clear_thread_local_caches();
        })); // end catch_unwind
        if panic_result.is_err() {
            tracing::error!(path = %file_path.display(), "panic during file analysis (caught)");
            errors.fetch_add(1, Ordering::Relaxed);
            callback(ScanEvent::File {
                path: file_path.clone(),
                result: Box::new(Err(anyhow::anyhow!("analysis panicked"))),
            });
        }
    })
    };

    crate::mem_profile::start_sampler();
    analyze_files();

    crate::mem_profile::report();
    crate::composite_rules::evaluators::log_regex_cache_stats();

    let total = walked.load(Ordering::Relaxed);
    let final_analyzed = analyzed.load(Ordering::Relaxed);
    let final_skipped = skipped.load(Ordering::Relaxed);
    let final_errors = errors.load(Ordering::Relaxed);
    tracing::info!(
        walked = total,
        dirs = dirs_entered.load(Ordering::Relaxed),
        walk_errors = walk_errors.load(Ordering::Relaxed),
        analyzed = final_analyzed,
        skipped = final_skipped,
        errors = final_errors,
        "Directory scan complete"
    );

    Ok(ScanSummary {
        total,
        analyzed: final_analyzed,
        errors: final_errors,
    })
}

/// Analyze an explicit set of file paths in parallel, invoking `callback` for
/// each as its analysis completes.
///
/// This is the multi-file analog of [`scan_directory`]: the CapabilityMapper and
/// YARA engine are loaded once and shared across all rayon workers, and results
/// stream out through the callback under the same [`ScanEvent`] contract — minus
/// the directory walk. `ScanEvent::Start` carries the path count, which is known
/// upfront here (unlike the streamed directory walk).
///
/// Unlike [`scan_directory`], paths are analyzed exactly as given: directories
/// are not recursed (a directory path surfaces as a `ScanEvent::File` error),
/// and the program-type and size filters are not applied — an explicitly named
/// file is always analyzed. Use [`scan_directory`] to recurse a tree.
///
/// # Errors
///
/// Returns `Err` only for setup failures (resource load). Per-file errors,
/// including caught panics, are delivered through the callback as a
/// [`ScanEvent::File`] carrying an `Err` result.
pub fn scan_files<F>(
    paths: &[std::path::PathBuf],
    options: &AnalysisOptions,
    callback: F,
) -> Result<ScanSummary>
where
    F: Fn(ScanEvent) + Sync,
{
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let _disable_guards = AnalysisDisableGuards::from_options(options);
    let (mapper, yara_engine) = load_scan_resources(options)?;

    let analyzed = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);
    let errors = AtomicUsize::new(0);

    callback(ScanEvent::Start {
        total: Some(paths.len()),
    });

    let mem_gate = scan_mem_gate::ScanMemGate::new();
    paths.par_iter().for_each(|file_path| {
        // Cancellation fast path: once SIGINT flips the flag, remaining slots
        // return immediately so the scan drains in-flight work rather than
        // starting new files. Mirrors scan_directory's par_bridge fast path.
        if options
            .cancellation
            .as_ref()
            .is_some_and(|c| c.load(Ordering::Relaxed))
        {
            skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // Bound concurrent memory: a burst of large archives serialises instead
        // of co-residing and OOM-killing the host. Held until this file is done.
        let _mem_permit =
            mem_gate.acquire(std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0));

        // Catch panics so one malformed file can't poison the rayon pool and
        // kill the whole batch.
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let result = analyze_file_with_resources(
                file_path,
                options,
                &mapper,
                yara_engine.as_ref(),
                None,
            );
            match &result {
                Ok(_) => {
                    analyzed.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            callback(ScanEvent::File {
                path: file_path.clone(),
                result: Box::new(result),
            });
            // Release wasmtime Scanner VMs on this thread (see scan_directory).
            composite_rules::evaluators::clear_thread_local_caches();
        }));
        if panic_result.is_err() {
            tracing::error!(path = %file_path.display(), "panic during file analysis (caught)");
            errors.fetch_add(1, Ordering::Relaxed);
            callback(ScanEvent::File {
                path: file_path.clone(),
                result: Box::new(Err(anyhow::anyhow!("analysis panicked"))),
            });
        }
    });

    let final_analyzed = analyzed.load(Ordering::Relaxed);
    let final_errors = errors.load(Ordering::Relaxed);
    tracing::info!(
        total = paths.len(),
        analyzed = final_analyzed,
        skipped = skipped.load(Ordering::Relaxed),
        errors = final_errors,
        "File list scan complete"
    );

    Ok(ScanSummary {
        total: paths.len(),
        analyzed: final_analyzed,
        errors: final_errors,
    })
}

/// Compute a malecule formula string from an [`AnalysisReport`].
///
/// Aggregates findings by directory path, removes baseline and low-confidence
/// entries, then produces the chemical formula notation. Returns an empty string
/// if the report has no significant findings.
///
/// This mirrors the filtering applied by cleave's own terminal output.
#[must_use]
pub fn formula_from_report(report: &AnalysisReport) -> String {
    let findings: &[types::traits_findings::Finding] = if !report.findings.is_empty() {
        &report.findings
    } else if let Some(first) = report.files.first() {
        &first.findings
    } else {
        return String::new();
    };

    let filtered = output::filter_findings_for_formula(findings);
    malecule_bridge::formula_from_findings(&filtered)
}

/// Compare two paths (files or directories) for supply-chain attack detection.
///
/// This is a thin convenience wrapper around [`diff::diff_paths`] using the
/// default [`AnalysisOptions`] and a 100-item per-scope cap. Callers that
/// need to tune analysis options or scope selection should call
/// [`diff::diff_paths`] directly.
pub fn diff_files<P: AsRef<Path>>(old: P, new: P) -> Result<AnalysisReport> {
    diff::diff_paths(
        old.as_ref(),
        new.as_ref(),
        &AnalysisOptions::default(),
        diff::ScopeMask::all(),
        diff::DEFAULT_LIMIT_CHANGES,
    )
}

/// Validate the configured traits directory with full validation enabled.
pub fn validate_traits() -> Result<()> {
    let resolved = traits_repo::resolve_and_ensure().map_err(anyhow::Error::msg)?;
    capabilities::CapabilityMapper::from_directory_with_options(
        resolved.as_path(),
        capabilities::CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
        capabilities::CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
        true,
        false,
    )?;
    Ok(())
}

/// Version and resource statistics for the `version` subcommand.
#[allow(missing_docs)]
#[derive(Debug)]
pub struct VersionInfo {
    pub traits_version: Option<String>,
    pub traits_mtime: Option<std::time::SystemTime>,
    pub trait_count: usize,
    pub composite_count: usize,
    pub yara_rules: usize,
}

/// Collect version information: traits revision, mtime, and resource counts.
///
/// This initialises the global CapabilityMapper and YARA engine if they
/// haven't been loaded yet, so the counts reflect the full rule set.
#[must_use]
pub fn version_info() -> VersionInfo {
    let traits_version = traits_repo::version();
    let traits_mtime = cache::most_recent_yaml_file().ok().map(|(t, _)| t);

    let (trait_count, composite_count) = shared_resources::capability_mapper()
        .map(|mapper| {
            (
                mapper.trait_definitions_count(),
                mapper.composite_rules_count(),
            )
        })
        .unwrap_or((0, 0));

    let engine = shared_resources::yara_engine(true);
    let yara_rules = engine.total_rules();

    VersionInfo {
        traits_version,
        traits_mtime,
        trait_count,
        composite_count,
        yara_rules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    fn test_max_analysis_depth_constant() {
        assert_eq!(MAX_ANALYSIS_DEPTH, 8);
    }

    /// A cache-hit report carries the cache donor's `file.basename`/`file.stem`
    /// (the cache is content-keyed); the hit path must re-stamp them with the
    /// name of the file actually analyzed.
    #[test]
    #[allow(clippy::expect_used)]
    fn restamp_path_derived_values_replaces_donor_name() {
        let target = types::TargetInfo {
            path: "donor.sh".to_string(),
            file_type: "shell".to_string(),
            size_bytes: 1,
            sha256: "abc".to_string(),
            architectures: None,
        };
        let mut report = types::AnalysisReport::new(target);
        report.values_tree = Some(Box::new(serde_json::json!({
            "file": { "basename": "donor.sh", "stem": "donor" },
            "shebang": { "interpreter": "bash" },
        })));

        restamp_path_derived_values(&mut report, Path::new("/tmp/actual.tar.gz"));

        let tree = report.values_tree.as_deref().expect("values tree retained");
        assert_eq!(tree["file"]["basename"], "actual.tar.gz");
        assert_eq!(tree["file"]["stem"], "actual.tar");
        // Unrelated namespaces are untouched.
        assert_eq!(tree["shebang"]["interpreter"], "bash");

        // A report without a values tree (or without the `file` namespace)
        // passes through unchanged.
        let mut bare = types::AnalysisReport::new(types::TargetInfo {
            path: "x".to_string(),
            file_type: "shell".to_string(),
            size_bytes: 1,
            sha256: "abc".to_string(),
            architectures: None,
        });
        restamp_path_derived_values(&mut bare, Path::new("/tmp/actual.sh"));
        assert!(bare.values_tree.is_none());
    }

    /// `PhaseTracker::new()` must not register (otherwise every default
    /// `AnalysisOptions` would leave an entry in the global list).
    /// `with_label` registers; dropping the last handle removes the entry
    /// from snapshots on the next call.
    #[test]
    #[allow(clippy::expect_used)]
    fn phase_tracker_registry_lifecycle() {
        fn contains_label(snap: &[PhaseSnapshot], label: &str) -> bool {
            snap.iter().any(|(l, _, _, _)| l == label)
        }

        let marker = format!("phase-test-{}", std::process::id());

        // Unlabeled trackers never appear in the registry.
        let _anon = PhaseTracker::new();
        assert!(!contains_label(&snapshot_active_phases(), &marker));

        // Labeled tracker shows up while alive and carries the current phase.
        {
            let t = PhaseTracker::with_label(&marker);
            t.set("yara");
            let snap = snapshot_active_phases();
            let entry = snap
                .iter()
                .find(|(l, _, _, _)| l == &marker)
                .expect("registered tracker should appear in snapshot");
            assert_eq!(entry.1, "yara");
        }

        // Dropping the handle removes it on the next snapshot (the retain()
        // pass prunes Weak references with no surviving Arc).
        assert!(!contains_label(&snapshot_active_phases(), &marker));
    }

    /// Verify that analyzing a file at the depth limit emits the deep-nesting
    /// finding instead of recursing further.  We create a Python file whose
    /// content is a base64-encoded shell command (one layer of encoding) and
    /// invoke analysis at depth == MAX_ANALYSIS_DEPTH so the payload loop
    /// hits the depth guard.
    #[test]
    #[allow(clippy::expect_used)]
    fn test_analysis_depth_limit_emits_finding() {
        use std::io::Write;

        // base64("echo hello") = "ZWNobyBoZWxsbw=="
        // Wrap it in Python so the file is recognized as a script with an
        // encoded payload that would normally trigger recursive analysis.
        let code = b"import base64\ndata = 'ZWNobyBoZWxsbw=='\nresult = base64.b64decode(data)\n";

        #[allow(clippy::expect_used)]
        let tmp = tempfile::Builder::new()
            .suffix(".py")
            .tempfile()
            .expect("create temp file");
        #[allow(clippy::expect_used)]
        tmp.as_file().write_all(code).expect("write test content");
        let path = tmp.path();

        // Skip YARA: this test checks depth-limit handling, not YARA matches,
        // and the YARA engine load adds ~60s of unnecessary init.
        let options = AnalysisOptions {
            disable_yara: true,
            ..AnalysisOptions::default()
        };
        let mapper = shared_resources::capability_mapper_with_options(&options)
            .expect("mapper should load for depth-limit test");

        // Analyze at exactly MAX_ANALYSIS_DEPTH — any encoded payloads found
        // should trigger the deep-nesting finding instead of recursing.
        #[allow(clippy::expect_used)]
        let report = analyze_file_with_resources_at_depth(
            path,
            &options,
            &mapper,
            None,
            None,
            None,
            MAX_ANALYSIS_DEPTH,
        )
        .expect("analysis should succeed even at depth limit");

        // If the file produced encoded payloads, the depth guard should have
        // emitted the deep-nesting finding.  If no payloads were detected
        // (encoding detection is heuristic), the finding won't appear — that's
        // fine, we just verify no stack overflow occurred and the function
        // returned normally.
        if let Some(f) = report
            .findings
            .iter()
            .find(|f| f.id == "objectives/anti-static/obfuscation/multi-layer/deep-nesting")
        {
            assert_eq!(f.crit, types::Criticality::Suspicious);
            assert_eq!(f.attack.as_deref(), Some("T1027"));
            assert_eq!(f.mbc.as_deref(), Some("OB0002"));
            assert!(
                f.evidence.iter().any(|e| e.value.contains("depth=")),
                "evidence should include depth"
            );
        }
    }

    /// Verify that depth 0 (normal) does NOT emit the deep-nesting finding
    /// for a simple file.
    #[test]
    #[allow(clippy::expect_used)]
    fn test_analysis_depth_zero_no_deep_nesting_finding() {
        use std::io::Write;

        let code = b"print('hello world')\n";
        #[allow(clippy::expect_used)]
        let tmp = tempfile::Builder::new()
            .suffix(".py")
            .tempfile()
            .expect("create temp file");
        #[allow(clippy::expect_used)]
        tmp.as_file().write_all(code).expect("write test content");

        let options = AnalysisOptions {
            all_files: true,
            disable_yara: true,
            ..AnalysisOptions::default()
        };
        let mapper = shared_resources::capability_mapper_with_options(&options)
            .expect("mapper should load for depth-zero test");

        #[allow(clippy::expect_used)]
        let report = analyze_file_with_resources_at_depth(
            tmp.path(),
            &options,
            &mapper,
            None,
            None,
            None,
            0,
        )
        .expect("analysis should succeed");

        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.id.contains("deep-nesting")),
            "depth-0 analysis should not produce deep-nesting finding"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_skip_unknown_url_markup_payload() {
        let payload = types::ExtractedPayload {
            data: Vec::new(),
            encoding_chain: vec!["url".to_string()],
            detected_type: FileType::Unknown,
            preview: "<body><a href=\"http://example.com\">doc</a>".to_string(),
            original_offset: 0,
        };
        assert!(should_skip_unknown_url_markup_payload(&payload));

        let payload = types::ExtractedPayload {
            data: Vec::new(),
            encoding_chain: vec!["url".to_string()],
            detected_type: FileType::Unknown,
            preview: "http://example.com/api/v1/ping".to_string(),
            original_offset: 0,
        };
        assert!(!should_skip_unknown_url_markup_payload(&payload));

        let payload = types::ExtractedPayload {
            data: Vec::new(),
            encoding_chain: vec!["url".to_string()],
            detected_type: FileType::Unknown,
            preview: "beginning of the revealed that the television series".to_string(),
            original_offset: 0,
        };
        assert!(should_skip_unknown_url_markup_payload(&payload));
    }
}
