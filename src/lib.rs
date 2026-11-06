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

/// A regex literal compiled once per process; `None` if the literal does not
/// compile, which the caller's own tests catch.
macro_rules! static_regex {
    ($pattern:expr) => {{
        static RE: std::sync::OnceLock<Option<regex::Regex>> = std::sync::OnceLock::new();
        RE.get_or_init(|| regex::Regex::new($pattern).ok()).as_ref()
    }};
}

mod analysis_cache;
pub(crate) mod analysis_context;
mod archive_members;
pub mod breadcrumb;
pub mod cache;
pub mod cancellation;
pub mod context;
mod engine;
pub mod enriched;
mod entropy;
pub mod env;
pub(crate) mod extractors;
pub mod file_io;
pub(crate) mod ip_validator;
mod leaf_affinity;
pub mod mem_profile;
pub mod memory_tracker;
#[cfg(test)]
mod path_mapper_test;
pub(crate) mod rule_sources;
pub mod rule_update;
mod shared_resources;
pub(crate) mod strings;
#[cfg(test)]
mod strings_test;
mod subprocess;
#[cfg(feature = "lint")]
pub(crate) mod test_rules;
#[cfg(all(test, feature = "lint"))]
mod test_rules_filters_test;
#[cfg(test)]
mod test_samples;
pub(crate) mod traits_fingerprint;
pub mod traits_repo;
mod upx;
pub(crate) mod validation_controls;
pub(crate) mod validation_performance;

// Public modules
pub mod analyzers;
mod base64_validator;
pub(crate) mod bitcoin_validator;
pub mod capabilities;
/// The `cleave` binary's argument parsing; not a stable library API.
#[doc(hidden)]
pub mod cli;
/// The `cleave` binary's subcommands; not a stable library API.
#[doc(hidden)]
pub mod commands;
pub(crate) mod composite_rules;
pub mod diff;
pub(crate) mod env_mapper;
mod formula;
pub mod model_facts;
pub mod output;
pub(crate) mod path_mapper;
mod payload_filter;
mod plist_guard;
pub(crate) mod random_validator;
pub mod report_input;
pub mod theme;
pub(crate) mod third_party_config;
pub(crate) mod third_party_yara;
pub mod tool_resolution;
pub mod types;
pub mod update_check;
pub(crate) mod update_manifest;
mod yaml;
pub mod yara_engine;

// Live host-memory pressure gate for the archive member walk, which no
// top-level admission gate covers. See par_filter_fold_members.
mod mem_pressure;
// Memory-aware admission so parallel scans don't co-resident large archives and
// OOM the host. See scan_files / scan_directory.
mod scan_mem_gate;

// Adaptive nested rayon: serial member-inner joins when 2+ top-level files share the pool.
mod rayon_nest;

/// This crate's version, captured from `Cargo.toml` at compile time.
///
/// Exposed so a binary that links cleave as a library can read the cleave
/// version it was built against, rather than its own. `env!` resolves the version of the crate it is compiled in, so this
/// constant always reflects cleave's `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Recommended jemalloc configuration for any binary that runs cleave's
/// analysis over a sustained workload.
///
/// Without it, a long-running analysis exhausts `vm.max_map_count` and dies:
/// `mmap` starts returning `ENOMEM`, Rust's allocator gets a null back and
/// `handle_alloc_error` aborts with `memory allocation of N bytes failed` — a
/// message that reads like OOM but is not.
///
/// Two settings together bound the mapping count, and neither suffices alone:
///
/// - `retain:false`. jemalloc defaults it to `true` on 64-bit Linux, where a
///   freed extent keeps its address space and is decommitted with
///   `mprotect(PROT_NONE)` rather than unmapped. Every decommit splits a VMA.
/// - A long `muzzy_decay_ms`. With retain off, jemalloc unmaps freed extents
///   and re-mmaps small ones, so live extents scatter into separate VMAs
///   instead. Purging rarely lets them be reused in place.
///
/// Under sustained archive-heavy load an unconfigured worker reaches the
/// default 1,048,576-mapping ceiling within minutes. Never purging muzzy pages
/// (`-1`) keeps the count lowest but lets RSS climb toward the peak working
/// set; purging every minute reintroduces the unmap/remap churn. Ten minutes
/// holds the mapping count on a plateau with steady RSS. The plateau moves
/// with load, so size the ceiling for the busy case.
///
/// Four arenas suit a bounded analysis pool and avoid multiplying dirty extents
/// across jemalloc's CPU-scaled default; one-second dirty decay returns
/// transient allocations promptly.
///
/// A `malloc_conf` symbol is per-process, so a library cannot install this on a
/// host binary's behalf. Binaries opt in by pointing the allocator's config
/// symbol at this string — see cleave's own `main.rs` for the pattern. Runtime
/// configuration still wins: jemalloc applies its compiled-in string first,
/// then `/etc/malloc.conf`, then the environment, with later sources overriding
/// earlier ones per key. NB: `tikv-jemallocator` builds jemalloc with the
/// `_rjem_` prefix, so the environment variable is `_RJEM_MALLOC_CONF`; plain
/// `MALLOC_CONF` is read by the system allocator and silently ignored here.
/// `background_thread` is requested only off Apple: jemalloc compiles
/// `JEMALLOC_BACKGROUND_THREAD` for non-Mach-O ABIs only (`configure.ac`:
/// `abi != macho`), so on Apple targets asking for one writes `<jemalloc>:
/// option background_thread currently supports pthread only` to stderr before
/// `main` — above every run, and impossible to suppress from Rust.
#[cfg(target_vendor = "apple")]
pub const JEMALLOC_CONF: &std::ffi::CStr =
    c"narenas:4,dirty_decay_ms:1000,muzzy_decay_ms:600000,retain:false";
/// See the Apple-gated definition above.
#[cfg(not(target_vendor = "apple"))]
pub const JEMALLOC_CONF: &std::ffi::CStr =
    c"narenas:4,dirty_decay_ms:1000,muzzy_decay_ms:600000,retain:false,background_thread:true";

// Re-export commonly used types at crate root
use analyzers::FileTypeExt;
pub use analyzers::{AnalysisInput, Analyzer, FileType, detect_file_type};
pub use archive_members::{ArchiveMembers, extract_member};
pub use capabilities::{CapabilityMapper, LoadOptions};
pub use composite_rules::Platform;
pub use engine::Engine;
pub use rayon_nest::{mark_thread_background, set_parallel_owner_caps};
pub use types::FileAnalysis;
pub use types::binary::StringInfo;
pub use types::code_structure::{BinaryProperties, SourceCodeMetrics};
pub use types::core::{AnalysisReport, Criticality, TargetInfo};
pub use types::diff::{
    Changed, DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, KvChange, MetricChange,
    ScopeDiff, ScopeDiffs, ScopeRocs, SectionChange, StringChange, SymbolChange, SymbolKind,
    TraitChange,
};
pub use types::traits_findings::{Evidence, Finding, FindingKind, Trait, TraitKind};

// Re-export cache management functions
pub use shared_resources::{reload_capability_mapper, set_skip_traits_override};

mod scan;
#[allow(clippy::wildcard_imports)]
pub use scan::*;

mod pipeline;
#[allow(clippy::wildcard_imports)]
pub(crate) use pipeline::*;

mod graft;
#[allow(clippy::wildcard_imports)]
pub use graft::*;

/// Bring the local compiled-YARA cache up to date with the active rule
/// sources now, rather than on the first scan after: compiles only the buckets
/// whose sources (or engine) changed since they were last compiled. Returns
/// `(compiled, buckets)`.
#[must_use]
pub fn compile_yara_rules(enable_third_party: bool) -> (usize, usize) {
    let mut engine = yara_engine::YaraEngine::new();
    engine.load_all_rules(enable_third_party);
    engine.compile_missing()
}

use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};

/// Compute a fast hash of a string for deduplication and caching.
#[inline]
pub(crate) fn hash_str(s: &str) -> u64 {
    let mut hasher = FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}

pub use composite_rules::evaluators::{clear_regex_caches, clear_thread_local_caches};

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Process YARA scan results and add them to the analysis report.
///
/// Extracts YARA matches and inline evidence, converts matches to findings,
/// and returns inline evidence map for use in trait evaluation.
pub fn process_yara_result_with<F>(
    report: &mut types::AnalysisReport,
    yara_result: Option<Result<yara_engine::YaraScan>>,
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
    let yara_engine::YaraScan {
        matches,
        inline_traits,
    } = yara_result;

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

    report.yara_matches = matches;
    for yara_match in &report.yara_matches {
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
        let crit = yara_match.crit;
        report.findings.push(types::Finding {
            precomputed_spans: None,
            src: None,
            kind: types::FindingKind::Capability,
            trait_refs: vec![],
            id: cap_id.into(),
            desc: yara_match.desc.clone().into(),
            conf: 0.9,
            crit,
            mbc: yara_match.mbc.as_deref().map(Into::into),
            attack: yara_match.attack.as_deref().map(Into::into),
            evidence,
            match_count: 0,
            source_file: None,
            downgraded: false,
        });
    }
    if !report.metadata.tools_used.iter().any(|t| t == "yara-x") {
        report.metadata.tools_used.push("yara-x".to_string());
    }
    inline_traits
}

fn process_yara_result(
    report: &mut types::AnalysisReport,
    yara_result: Option<Result<yara_engine::YaraScan>>,
    engine: Option<&yara_engine::YaraEngine>,
) -> HashMap<String, Vec<types::Evidence>> {
    process_yara_result_with(report, yara_result, |yara_match| {
        engine
            .map(|e| e.yara_match_to_evidence(yara_match))
            .unwrap_or_default()
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod yara_result_tests;

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
        let sha256 = hex::encode(hasher.finalize());

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
///
/// The free functions ([`analyze_file`], [`analyze_bytes`], ...) read every
/// field. An [`Engine`] is built from the engine-level fields (YARA, UPX,
/// platforms, precision thresholds, validation) by
/// [`Engine::for_options`]; its `analyze_*` methods read only the per-call
/// ones and ignore the rest.
#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    /// Load the third-party YARA rules alongside the built-in ones.
    pub third_party_yara: bool,
    /// Passwords to try for encrypted ZIP files
    pub zip_passwords: Vec<String>,
    /// Scan with YARA.
    pub yara: bool,
    /// Unpack UPX-packed binaries and analyze the unpacked image.
    pub upx: bool,
    /// Fold archive members into their container keeping only what the
    /// compact projection renders: drop `kv` (except on files a rule reaches
    /// through a `<filename>::` path) and `filefacts.values`. For consumers
    /// that never emit the full v3 schema; on member-heavy archives those
    /// fields dominate memory.
    pub compact_members: bool,
    /// Include all files in directory scans, even unknown types
    pub all_files: bool,
    /// Platform filters for composite rule evaluation
    pub platforms: Vec<composite_rules::Platform>,
    /// Minimum precision threshold for hostile composite rules
    pub min_hostile_precision: f32,
    /// Minimum precision threshold for suspicious composite rules
    pub min_suspicious_precision: f32,
    /// Compute precision scores and emit precision warnings while loading rules.
    pub precision_scoring: bool,
    /// Run full validation of the rule definitions while loading them.
    pub full_validation: bool,
    /// Maximum file size (bytes) to load into memory from archives
    pub max_memory_file_size: u64,
    /// Warn threshold for slow rule evaluation in milliseconds (default: 4000).
    /// Rules exceeding this emit a warning; >1000ms is always logged at debug level.
    pub slow_rule_ms: u64,
    /// Maximum file size (bytes) to scan during directory analysis.
    /// Files larger than this are skipped. 0 means no limit.
    pub max_scan_file_size: u64,
    /// Per-request cancellation flag. When set to true by the caller (e.g. on timeout),
    /// archive analysis will stop processing new members early.
    /// Not included in the analysis cache key.
    pub cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Optional phase tracker for observability. When set, cleave updates this
    /// string at key analysis stages so a caller's diagnostics can report what
    /// a stuck request is actually doing.
    pub phase: Option<PhaseTracker>,
    /// This analysis runs on a rayon pool of its own (the caller `install`ed
    /// it there), so it neither competes with sibling analyses for the shared
    /// pool nor should it be throttled like one: it always gets its inner
    /// parallelism, and it does not count as an in-flight top-level analysis
    /// for the bounded-owner rule the shared pool applies (`rayon_nest`).
    /// Leave false for anything on the global pool.
    pub dedicated_pool: bool,
    /// Optional caller-supplied predicate, consulted with a file's sha256 hex
    /// and path after it is hashed but before any analysis. Returning `true`
    /// skips the expensive pipeline and yields a minimal report (target only).
    /// Lets a caller short-circuit files it already has a verdict for (e.g. a
    /// local known-good bloom filter) without cleave knowing why; the path is
    /// supplied so the predicate can consult filesystem metadata (e.g. skip a
    /// known-good file only while it is unchanged). Not part of the analysis
    /// cache key.
    pub skip_predicate: Option<SkipPredicate>,
}

/// Caller-supplied "skip analysis of this file" predicate (see
/// [`AnalysisOptions::skip_predicate`]). Called with the sha256 hex and the
/// file's path; `true` skips analysis. `Arc` so it is cheap to share across the
/// rayon fan-out. A newtype so [`AnalysisOptions`] can keep deriving `Debug`.
#[derive(Clone)]
pub struct SkipPredicate(pub Arc<dyn Fn(&str, &Path) -> bool + Send + Sync>);

impl std::fmt::Debug for SkipPredicate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SkipPredicate(..)")
    }
}

/// Lightweight handle for reporting the current analysis phase.
///
/// Callers (e.g. an embedding host) create one per request and pass it via
/// [`AnalysisOptions::phase`]. Cleave updates it at each major stage
/// (archive extraction, YARA, structural analysis, …) so the caller
/// can expose the current phase in its own diagnostics.
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
        if let Ok(mut registry) = PHASE_REGISTRY.lock() {
            registry.retain(|tracker| tracker.strong_count() > 0);
            registry.push(Arc::downgrade(&this.0));
        }
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

/// Whether the shared Rayon pool has headroom for a caller's own fan-out of
/// cleave analyses.
///
/// Cleave bounds how many analyses fan out at once, on the assumption that the
/// throttled ones make serial progress on independent blocking threads. A
/// caller that dispatches `analyze_*` from Rayon workers instead (a `par_iter`
/// over payloads, say) breaks that assumption: the throttled analysis occupies
/// a pool worker rather than freeing one, and its dispatcher sits blocked and
/// stealing, so the pool's stacks weave into one dependency chain. Gate such a
/// fan-out on this and run the analyses inline when it is false; the headroom
/// cases (a lone analysis, or a scan draining its queue) — the ones where
/// fanning out is what keeps the pool busy — still get it.
#[must_use]
pub fn pool_has_headroom() -> bool {
    rayon_nest::pool_has_headroom()
}

/// Spawns a background thread that logs rayon pool diagnostics every 5 minutes.
/// Call once at startup. The thread exits when the process exits.
pub fn start_rayon_diagnostics() {
    let spawned = std::thread::Builder::new()
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
        });
    if let Err(error) = spawned {
        tracing::warn!(%error, "could not start the rayon diagnostics thread");
    }
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            third_party_yara: true,
            zip_passwords: cli::DEFAULT_ZIP_PASSWORDS
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
            yara: true,
            upx: true,
            compact_members: false,
            all_files: false,
            platforms: vec![composite_rules::Platform::All],
            min_hostile_precision: CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
            min_suspicious_precision: CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            precision_scoring: false,
            full_validation: false,
            max_memory_file_size: 512 * 1024 * 1024, // 512 MB default
            slow_rule_ms: capabilities::CapabilityMapper::DEFAULT_SLOW_RULE_MS,
            max_scan_file_size: 600 * 1024 * 1024, // 600 MB default
            cancellation: None,
            phase: None,
            dedicated_pool: false,
            skip_predicate: None,
        }
    }
}

/// Drop the process-wide regex caches, the only caches that grow without a
/// per-file reset; call it under memory pressure from any thread.
///
/// Despite the name, other threads' thread-local caches are not touched: they
/// are small, bounded, and every analysis worker clears its own after each
/// file, so no broadcast is needed (and `rayon::broadcast` would block behind
/// workers inside long YARA scans). Only the calling thread's are cleared.
pub fn clear_all_thread_caches() {
    clear_thread_local_caches();
    clear_regex_caches();
    tracing::debug!("Cleared the shared regex caches and this thread's local caches");
}

/// Pre-warm the YARA engine on a non-rayon thread.
///
/// This blocks until initialization completes. That is intentional: it keeps
/// cold-start latency off rayon workers and avoids relying on the worker-safe
/// fallback path in rule loading.
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
    // A dedicated thread, even though we join it at once: the caller may be a
    // rayon worker, and first init must not run on one (see
    // `shared_resources::yara_engine`).
    let handle = std::thread::spawn(move || shared_resources::yara_engine(enable_third_party));
    if handle.join().is_err() {
        tracing::warn!("YARA engine prefetch thread panicked");
    }
}

/// Pre-warm the capability mapper, blocking until it is built and stored.
///
/// Companion to [`prefetch_yara_engine`], and blocking for the same reason: the
/// mapper's lock-free first-build (see `shared_resources::capability_mapper`)
/// lets multiple callers build concurrently and discard all but one. If this
/// returned before the build finished, the immediately-following directory scan
/// would race it from a rayon worker — both would parse the 32 MB cache and
/// recompile ~60k regexes, paying the multi-second build twice. Building here on
/// the calling (non-rayon) thread fills the global slot once, so subsequent
/// `capability_mapper()` calls hit the fast path.
pub fn prefetch_capability_mapper() {
    match shared_resources::capability_mapper() {
        // Force the (lazily-built) match indexes to build here, on this non-rayon
        // thread, so the pool does not spend N concurrent builds on the same
        // indexes when a directory scan fans out. `CapabilityMapper::match_indexes`
        // builds off the `OnceLock` and so is deadlock-free on its own — this is a
        // cold-start latency and duplicate-work optimization, not a safety
        // requirement. Callers that never fan out (a one-shot `pkg:`/`url` scan)
        // skip this prefetch, so a cache-hit scan never builds the indexes at all.
        Ok(mapper) => mapper.warm_indexes(),
        Err(e) => tracing::warn!(error = %e, "capability mapper prefetch failed"),
    }
}

/// Build every YARA bucket in the background, on a few plain threads, so a
/// long-lived worker's first archive does not pay the lazy per-bucket
/// deserialize + wasmtime JIT (the `pe` bucket alone is ~3 s on one thread)
/// inside its analysis. Returns immediately; the engine must already be
/// initialized (call after [`prefetch_yara_engine`]). Steady-state memory is
/// unchanged — the buckets are built on first use anyway and never dropped.
/// Uses a quarter of the available cores, between two and four threads.
pub fn prewarm_yara_buckets_background(enable_third_party: bool) {
    let threads = std::thread::available_parallelism().map_or(2, |n| (n.get() / 4).clamp(2, 4));
    let engine = shared_resources::yara_engine(enable_third_party);
    if let Err(e) = std::thread::Builder::new()
        .name("yara-prewarm".into())
        .spawn(move || engine.prewarm_all_cold_buckets(threads))
    {
        tracing::warn!(error = %e, "could not spawn YARA prewarm thread");
    }
}

/// Pre-warm both YARA and the capability mapper.
///
/// Call this once at process startup (e.g. at the top of a worker or server
/// main) so the first incoming request does not pay the multi-second cold-start
/// cost. Both YARA and the capability mapper complete before this returns, so a
/// subsequent rayon scan cannot win the first-init race and rebuild them. Safe
/// to call multiple times; subsequent calls are cheap.
pub fn prefetch_shared_resources(enable_third_party: bool) {
    prefetch_yara_engine(enable_third_party);
    prefetch_capability_mapper();
}

/// Log end-of-scan engine statistics at `info`: per-phase thread-time (and
/// heap totals under the `memprofile` feature) plus compiled-regex store
/// occupancy/churn. For embedders like scan whose single-payload path doesn't
/// go through cleave's own batch entry points, which log these themselves.
pub fn log_scan_stats() {
    crate::mem_profile::report_scan_stats();
    crate::composite_rules::evaluators::log_regex_cache_stats();
    crate::analysis_cache::log_analysis_memo_stats();
    crate::composite_rules::evaluators::raw_window_stats::log();
    crate::capabilities::log_raw_gate_stats();
    let top = crate::env::parse::<usize>("CLEAVE_TRAIT_TIMING_TOP").unwrap_or(40);
    crate::composite_rules::trait_timing::report(top);
    #[cfg(feature = "yara-profiling")]
    crate::yara_engine::yara_rule_timing::report(top);
}

/// Return `(retained_bytes, budget_bytes)` for the process-wide regex scratch
/// pool. Cheap enough for a periodic worker heartbeat and useful for
/// separating bounded regex retention from the rest of process RSS.
#[must_use]
pub fn regex_scratch_usage() -> (usize, usize) {
    crate::composite_rules::regex_scratch::usage()
}

/// Live occupancy of the two compiled-trait-regex stores, for a long-lived
/// process's periodic summary: `(entries, bytes, budget_bytes, evictions)` for
/// the `str` store and then the raw-bytes store. Evictions climbing between
/// summaries means the working set exceeds the budget and engines are being
/// recompiled (`CLEAVE_REGEX_STR_MB` / `CLEAVE_REGEX_RAW_MB`).
#[must_use]
pub fn regex_store_usage() -> [(usize, usize, usize, u64); 2] {
    let (str_len, str_bytes, _inserts, str_evictions, _repl, str_budget) =
        crate::composite_rules::condition::regex_store_stats();
    let (raw_len, raw_bytes, raw_evictions, raw_budget) =
        crate::composite_rules::evaluators::bytes_regex_store_stats();
    [
        (str_len, str_bytes, str_budget, str_evictions),
        (raw_len, raw_bytes, raw_budget, raw_evictions),
    ]
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
    analyze_path_under(path.as_ref(), options, &EngineFor::Options)
}

/// Where a single-file entry point gets its engine: one the caller holds, or
/// the shared one its `AnalysisOptions` describe, built only on a cache miss
/// (a hit needs no rules loaded, and loading them costs ~800ms cold).
pub(crate) enum EngineFor<'a> {
    Given(&'a Engine),
    Options,
}

impl EngineFor<'_> {
    /// The cache fast path: the report cached for these bytes, if any.
    fn cached(
        &self,
        data: &[u8],
        sha256: &str,
        path: &Path,
        label: &str,
        options: &AnalysisOptions,
    ) -> Option<AnalysisReport> {
        let file_type = analyzers::detect_file_type_from_data(path, data);
        let type_key = analysis_cache::report_type_key(file_type.label(), path);
        let mut report = match self {
            Self::Given(engine) => analysis_cache::report_cache_lookup(
                sha256,
                &type_key,
                options,
                engine.settings(),
                label,
                Some(engine.rules()),
            ),
            Self::Options => analysis_cache::report_cache_lookup(
                sha256,
                &type_key,
                options,
                &shared_resources::settings_for_options(options),
                label,
                shared_resources::loaded_capability_mapper().as_deref(),
            ),
        }?;
        report.target.path = label.to_string();
        report.analysis_timestamp = Some(chrono::Utc::now());
        report.cache_hit = true;
        report.engine = Some(match self {
            Self::Given(engine) => (*engine).clone(),
            Self::Options => {
                shared_resources::rendering_engine(shared_resources::settings_for_options(options))
            }
        });
        Some(report)
    }

    fn engine(&self, options: &AnalysisOptions) -> Result<Engine> {
        match self {
            Self::Given(engine) => Ok((*engine).clone()),
            Self::Options => load_scan_resources(options),
        }
    }
}

/// Analyze the file at `path`: a cache lookup on its bytes first, then the
/// full pipeline under the engine `source` provides.
pub(crate) fn analyze_path_under(
    path: &Path,
    options: &AnalysisOptions,
    source: &EngineFor<'_>,
) -> Result<AnalysisReport> {
    // Fast path: check the analysis cache before loading expensive resources.
    // SHA256 of the file is cheap (~1ms); loading CapabilityMapper + YARA is not (~800ms).
    // Keep the pre-read data to pass through on cache miss, avoiding a second read.
    let (preloaded, precomputed_sha) = if path.is_file() {
        let file_data = file_io::read_file_smart(path)?;
        let sha256 = analyzers::utils::calculate_sha256(file_data.as_slice());
        let label = path.display().to_string();
        if let Some(mut report) =
            source.cached(file_data.as_slice(), &sha256, path, &label, options)
        {
            restamp_path_derived_values(&mut report, path);
            tracing::debug!(%sha256, "analysis cache hit (fast path)");
            return Ok(report);
        }
        (Some(file_data), Some(sha256))
    } else {
        (None, None)
    };
    let engine = source.engine(options)?;
    engine.rules().warm_for_analysis();
    analyze_file_with_engine(path, options, &engine, preloaded, precomputed_sha)
}

/// Analyze in-memory `data` labeled `filename` (used for extension-based type
/// detection and reporting; it need not exist on disk).
pub(crate) fn analyze_data_under(
    data: file_io::FileData,
    filename: &str,
    options: &AnalysisOptions,
    source: &EngineFor<'_>,
) -> Result<AnalysisReport> {
    let path = Path::new(filename);
    let sha256 = analyzers::utils::calculate_sha256(data.as_slice());
    if let Some(report) = source.cached(data.as_slice(), &sha256, path, filename, options) {
        tracing::debug!(%sha256, "analysis cache hit (bytes fast path)");
        return Ok(report);
    }
    let engine = source.engine(options)?;
    analyze_file_with_engine(path, options, &engine, Some(data), Some(sha256))
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
    analyze_data_under(
        file_io::FileData::Owned(data),
        filename,
        options,
        &EngineFor::Options,
    )
}

/// Analyze in-memory file data backed by a refcounted [`bytes::Bytes`] buffer,
/// adopting it without a copy.
///
/// Prefer this over [`analyze_bytes_owned`] when the caller already holds the
/// bytes as `Bytes` (e.g. a worker handing over a body straight from an HTTP
/// client). It saves the `Bytes` → `Vec<u8>` copy that the owned path requires.
pub fn analyze_bytes_shared(
    data: bytes::Bytes,
    filename: &str,
    options: &AnalysisOptions,
) -> Result<AnalysisReport> {
    analyze_data_under(
        file_io::FileData::Shared(data),
        filename,
        options,
        &EngineFor::Options,
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
    let engine = shared_resources::engine_with_rules(options, capability_mapper.clone());
    analyze_file_with_engine(path, options, &engine, None, None)
}

#[cfg(test)]
mod scheduling_size_tests;

/// Compute the findings formula string for an [`AnalysisReport`].
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

    formula::of(findings).unwrap_or_default()
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
    let resolved = traits_repo::resolve_and_ensure()?;
    capabilities::CapabilityMapper::from_directory_with_options(
        resolved.as_path(),
        crate::LoadOptions {
            full_validation: true,
            ..crate::LoadOptions::default()
        },
    )?;
    Ok(())
}

/// Version and resource statistics for the `version` subcommand.
#[allow(missing_docs)]
#[derive(Debug)]
pub struct VersionInfo {
    pub traits_edition: traits_repo::Edition,
    pub traits_version: Option<String>,
    pub traits_mtime: Option<std::time::SystemTime>,
    pub trait_count: usize,
    pub composite_count: usize,
    pub yara_rules: usize,
}

/// Collect version information: traits edition and revision, mtime, and
/// resource counts.
///
/// This initialises the global CapabilityMapper and YARA engine if they
/// haven't been loaded yet, so the counts reflect the full rule set.
#[must_use]
pub fn version_info() -> VersionInfo {
    let traits_edition = traits_repo::Edition::current();
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
        traits_edition,
        traits_version,
        traits_mtime,
        trait_count,
        composite_count,
        yara_rules,
    }
}

/// The `version` text every atomdrift tool prints: the tool, the cleave it
/// embeds, and the rules it is using — edition before revision, because
/// "Uplink or open source?" is the first thing a support thread asks.
///
/// Loads the rule engines to count them, like [`version_info`].
#[must_use]
pub fn version_report(tool: &str, tool_version: &str) -> String {
    let info = version_info();
    let embeds = if tool == "cleave" {
        String::new()
    } else {
        format!("cleave  {}\n", env!("CARGO_PKG_VERSION"))
    };
    let built = info
        .traits_mtime
        .map(|t| {
            chrono::DateTime::<chrono::Utc>::from(t)
                .format(" (%Y-%m-%d %H:%M UTC)")
                .to_string()
        })
        .unwrap_or_default();
    let at = match &info.traits_edition {
        traits_repo::Edition::Checkout(dir) => format!("  {}", dir.display()),
        traits_repo::Edition::Enriched | traits_repo::Edition::OpenSource => String::new(),
    };
    format!(
        "{tool:<7} {tool_version}\n{embeds}traits  {}  {}{built}{at}\nrules   {} ({} atomic, {} composite, {} yara)",
        info.traits_edition.styled(),
        info.traits_version.as_deref().unwrap_or("not installed"),
        info.trait_count + info.composite_count + info.yara_rules,
        info.trait_count,
        info.composite_count,
        info.yara_rules
    )
}

/// Report whether `pattern` makes the lazy DFA explode on bundle-shaped text.
///
/// Same haystack and give-up thresholds as the `regex-explosion` validator, so
/// a pattern can be checked one at a time instead of by re-validating the tree.
#[cfg(feature = "lint")]
#[must_use]
pub fn regex_explodes(pattern: &str, case_insensitive: bool) -> bool {
    crate::capabilities::validation::regex_cost::explosion(pattern, case_insensitive)
        .is_some_and(capabilities::validation::regex_cost::Explosion::is_pathological)
}

#[cfg(test)]
mod tests;

/// Give optional background cache persistence up to one second to drain at CLI exit.
/// Call after analysis workers have joined; results are already available in memory.
pub fn flush_analysis_cache() {
    analysis_cache::flush_pending();
}
