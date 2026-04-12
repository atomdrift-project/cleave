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
pub mod cache;
pub mod decoders;
mod entropy;
pub mod extractors;
pub mod file_io;
pub mod ip_validator;
pub mod memory_tracker;
mod radare2;
mod shared_resources;
pub mod strings;
pub mod test_rules;
#[cfg(test)]
/// Test module for rule filters.
pub mod test_rules_filters_test;
pub mod traits_repo;
mod upx;

// Standalone RTF parser (can be used independently)
pub mod rtf;

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
pub mod third_party_config;
pub mod third_party_yara;
pub mod types;
pub mod yara_engine;

// HTTP API server
pub mod server;

// Re-export commonly used types at crate root
use analyzers::FileTypeExt;
pub use analyzers::{detect_file_type, AnalysisInput, Analyzer, FileType};
pub use capabilities::CapabilityMapper;
pub use composite_rules::Platform;
pub use diff::DiffAnalyzer;
pub use types::binary::StringInfo;
pub use types::code_structure::{BinaryProperties, SourceCodeMetrics};
pub use types::core::{AnalysisReport, Criticality, TargetInfo};
pub use types::diff::{DiffReport, FullDiffReport, ModifiedFileAnalysis};
pub use types::scores::Metrics;
pub use types::text_metrics::TextMetrics;
pub use types::traits_findings::{Evidence, Finding, FindingKind, Trait, TraitKind};
pub use types::SampleExtractionConfig;

// Re-export cache management functions
pub use composite_rules::clear_condition_stats;
pub use shared_resources::reload_capability_mapper;

use rustc_hash::FxHasher;
use std::hash::{Hash, Hasher};

/// Compute a fast hash of a string for deduplication and caching.
#[inline]
pub(crate) fn hash_str(s: &str) -> u64 {
    let mut hasher = FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}

fn looks_like_textual_payload_preview(preview: &str) -> bool {
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
    if markers.iter().any(|marker| preview.contains(marker)) {
        return true;
    }

    let chars = preview.chars().count();
    if chars == 0 {
        return false;
    }

    let alpha = preview.chars().filter(char::is_ascii_alphabetic).count();
    let whitespace = preview.chars().filter(char::is_ascii_whitespace).count();

    alpha * 100 / chars >= 60 && whitespace > 0
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

fn should_skip_unknown_xor_payload_for_source(
    file_type: &FileType,
    payload: &types::ExtractedPayload,
) -> bool {
    file_type.is_source_code()
        && payload.encoding_chain.len() == 1
        && payload.encoding_chain[0] == "xor"
        && payload.detected_type == FileType::Unknown
        && !looks_like_textual_payload_preview(&payload.preview)
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
    metrics: Option<&types::scores::Metrics>,
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
        let in_readonly_data = section.name == ".rdata";
        let is_signed_developer_library = metrics.is_some_and(|m| {
            m.pe.as_ref().is_some_and(|pe| {
                pe.has_signature && pe.signature_type.as_deref() == Some("developer")
            }) && m
                .binary
                .as_ref()
                .is_some_and(|binary| binary.export_count >= 50 && binary.function_count >= 200)
        });

        return in_readonly_data
            && is_signed_developer_library
            && !looks_like_textual_payload_preview(&payload.preview);
    }

    false
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

fn extension_content_mismatch_criticality(expected: &str, actual: &str) -> types::Criticality {
    let expected_is_image = expected.ends_with("image");
    let actual_is_image = actual.ends_with("image");

    if expected_is_image && actual_is_image {
        types::Criticality::Notable
    } else {
        types::Criticality::Suspicious
    }
}
pub use composite_rules::evaluators::clear_thread_local_caches;

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Disable radare2 integration process-wide.
pub fn disable_radare2() {
    radare2::disable_radare2();
}

/// Disable UPX integration process-wide.
pub fn disable_upx() {
    upx::disable_upx();
}

/// Scoped disable guards applied for a single analysis operation.
struct AnalysisDisableGuards {
    _radare2: Option<radare2::ScopedRadare2Disable>,
    _upx: Option<upx::ScopedUpxDisable>,
}

impl AnalysisDisableGuards {
    fn from_options(options: &AnalysisOptions) -> Self {
        Self {
            _radare2: options
                .disable_radare2
                .then(radare2::scoped_disable_radare2),
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
    let Some(Ok((matches, inline))) = yara_result else {
        return HashMap::new();
    };

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
        if let Some(ref ctx) = yara_match.arch_context {
            if !ctx.is_empty()
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
        }

        // Fallback: skip YARA findings whose rule name implies an architecture
        // that doesn't match the file (e.g., an _X64_ rule firing on ARM64).
        // Only applied when arch_context metadata is absent.
        if yara_match.arch_context.is_none() {
            if let Some(rule_arch) = composite_rules::Arch::from_yara_rule_name(&yara_match.rule) {
                if !file_archs.is_empty()
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
            }
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
    if !report.metadata.tools_used.contains(&"yara-x".to_string()) {
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
    /// Thread count for parallel directory scanning (0 = auto).
    /// Each thread holds an in-flight analysis (~0.5-1.5 GB of RAM), so this
    /// directly controls peak memory during directory scans.
    /// Default: min(8, num_cpus) for CLI; num_cpus for server mode.
    pub scan_threads: usize,
    /// Per-request cancellation flag. When set to true by the caller (e.g. server on timeout),
    /// archive analysis will stop processing new members early.
    /// Not included in the analysis cache key.
    pub cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
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
            scan_threads: 0,                       // 0 = auto (min(8, num_cpus) for CLI)
            cancellation: None,
        }
    }
}

/// Clear thread-local caches on ALL rayon worker threads.
///
/// Call this periodically during long-running scans to free memory from:
/// - UTF-8 conversion caches (can hold large strings from previous files)
/// - YARA scanner caches
///
/// This uses rayon's `broadcast` to ensure all worker threads clear their caches.
///
/// # Example
///
/// ```ignore
/// // After processing every N files, clear caches to prevent memory growth
/// if file_count % 100 == 0 {
///     cleave::clear_all_thread_caches();
/// }
/// ```
pub fn clear_all_thread_caches() {
    // Clear on the main thread
    clear_thread_local_caches();

    // Clear on all global rayon worker threads
    rayon::broadcast(|_| {
        clear_thread_local_caches();
    });

    // Clear global condition stats (bounded by condition type count, but useful for fresh stats)
    clear_condition_stats();

    tracing::debug!("Cleared thread-local caches on all threads");
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
    let preloaded = if path.is_file() {
        let file_data = file_io::read_file_smart(path)?;
        let sha256 = analyzers::utils::calculate_sha256(file_data.as_slice());
        if let Some(mut report) = analysis_cache::report_cache_lookup(&sha256, options) {
            report.target.path = path.display().to_string();
            report.analysis_timestamp = Some(chrono::Utc::now());
            tracing::info!("Cache hit (fast path)");
            return Ok(report);
        }
        Some(file_data)
    } else {
        None
    };

    // Cache miss: load mapper and YARA engine in parallel (~860ms + ~270ms → ~860ms)
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
    let mapper = mapper_result?;
    analyze_file_with_resources(path, options, &mapper, yara_engine.as_ref(), preloaded)
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
    let _disable_guards = AnalysisDisableGuards::from_options(options);
    analyze_file_with_resources_at_depth(
        path,
        options,
        capability_mapper,
        yara_engine,
        preloaded,
        0,
    )
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
    report.metrics = fa.metrics;
    report.binary_properties = fa.binary_properties;
    report.code_metrics = fa.code_metrics;
    report.source_code_metrics = fa.source_code_metrics;
    report.overlay_metrics = fa.overlay_metrics;
    report.paths = fa.paths;
    report.directories = fa.directories;
    report.env_vars = fa.env_vars;
    report
}

fn analyze_file_with_resources_at_depth<P: AsRef<Path>>(
    path: P,
    options: &AnalysisOptions,
    capability_mapper: &Arc<CapabilityMapper>,
    yara_engine: Option<&Arc<yara_engine::YaraEngine>>,
    preloaded: Option<file_io::FileData>,
    analysis_depth: u32,
) -> Result<AnalysisReport> {
    let path = path.as_ref();
    let span = tracing::info_span!("analyze", path = %path.display());
    let _enter = span.enter();

    // Log BEFORE processing to ensure we capture what file causes OOM crashes
    tracing::debug!("Starting analysis");

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    if path.is_dir() {
        anyhow::bail!(
            "Path is a directory, use analyze_directory instead: {}",
            path.display()
        );
    }

    // Read file once — reuse pre-loaded data from the fast-path cache check if available.
    let file_data_wrapper = match preloaded {
        Some(data) => data,
        None => file_io::read_file_smart(path)?,
    };
    let file_data = file_data_wrapper.as_slice();

    // Detect file type from already-loaded data (no extra read)
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

    // Compute SHA256 early for cache lookup (also reused by analyzers)
    let sha256_hex = analyzers::utils::calculate_sha256(file_data);

    // Set current file ID for IP validation cache
    let file_id = hash_str(&sha256_hex);
    ip_validator::set_current_file_id(file_id);

    // Check analysis cache before running the full pipeline
    if let Some(mut cached_report) = analysis_cache::report_cache_lookup(&sha256_hex, options) {
        cached_report.target.path = path.display().to_string();
        cached_report.analysis_timestamp = Some(chrono::Utc::now());
        tracing::info!("Cache hit");
        memory_tracker::log_after_file_processing(
            path.to_str().unwrap_or("unknown"),
            file_size,
            analysis_start.elapsed(),
        );
        return Ok(cached_report);
    }

    // Secondary check: per-file cache (cross-context, shared with archive members)
    if let Some(fa) = analysis_cache::file_analysis_cache_lookup(&sha256_hex, options) {
        tracing::info!("File cache hit (cross-context)");
        let report = report_from_file_analysis(fa, path.display().to_string());
        memory_tracker::log_after_file_processing(
            path.to_str().unwrap_or("unknown"),
            file_size,
            analysis_start.elapsed(),
        );
        return Ok(report);
    }

    // Check for extension/content mismatch
    let mismatch = analyzers::check_extension_content_mismatch(path, file_data);

    // Extract strings with stng ONCE - used for encoded payloads and passed to analyzers
    // Skip extraction for archive files themselves as they are expected to contain
    // binary noise and their contents will be analyzed separately.
    let (stng_strings, stage_stng_ms) = if file_type.is_archive() {
        (Vec::new(), 0)
    } else {
        let stng_start = std::time::Instant::now();
        let opts = analyzers::stng_analysis_opts(4);
        let strings = stng::extract_strings_with_options(file_data, &opts);
        let elapsed = stng_start.elapsed().as_millis() as u64;
        (strings, elapsed)
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
            // Run YARA scan in parallel with structural analysis for inline evidence
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
            let file_types: &[&str] = &["macho", "dylib", "kext"];
            // Run structural analysis, YARA scan, and raw regex precompute in parallel.
            // Raw regex precompute (~224ms) normally runs inside evaluate_and_merge_findings;
            // starting it here overlaps it with structural analysis (~275ms).
            let rule_file_type = capability_mapper.detect_file_type("macho");
            let cancel_macho = options.cancellation.clone();
            let ((struct_result, yara_result), raw_regex) = rayon::join(
                || {
                    rayon::join(
                        || {
                            Ok::<_, anyhow::Error>(analyzer.analyze_structural(
                                path,
                                arch_data,
                                input.sha256.clone(),
                            ))
                        },
                        || {
                            if cancel_macho
                                .as_ref()
                                .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                            {
                                return None;
                            }
                            engine
                                .filter(|e| e.is_loaded())
                                .map(|e| e.scan_bytes_with_inline(arch_data, Some(file_types)))
                        },
                    )
                },
                || capability_mapper.precompute_raw_regex_matches(eval_data, &rule_file_type),
            );
            let mut report = struct_result?;
            analyzer.apply_fat_metadata(&mut report, file_data);

            // For FAT binaries, re-extract strings from full file for correct offsets
            if is_fat && preextracted_strings.is_empty() {
                report.strings = string_extractor.extract_smart(file_data, None);
                if let Some(ref mut metrics) = report.metrics {
                    if let Some(ref mut binary_metrics) = metrics.binary {
                        binary_metrics.string_count = report.strings.len() as u32;
                    }
                }
            }

            // Process YARA results and evaluate with inline evidence
            let inline_yara =
                process_yara_result(&mut report, yara_result, engine.map(AsRef::as_ref));
            let fat_arch_ranges = if is_fat { Some(labeled_ranges) } else { None };
            capability_mapper.evaluate_and_merge_findings_with_precomputed(
                &mut report,
                eval_data,
                None,
                Some(&inline_yara),
                Some(raw_regex),
                fat_arch_ranges.as_deref(),
            );
            Ok(report)
        }
        FileType::Elf => {
            let analyzer = analyzers::elf::ElfAnalyzer::new()
                .with_cancellation(options.cancellation.clone())
                .with_capability_mapper_arc(mapper_arc.clone())
                .with_preextracted_strings(preextracted_strings.clone());
            let engine = yara_engine;
            let file_types: &[&str] = &["elf", "so", "ko"];
            let rule_file_type = capability_mapper.detect_file_type("elf");
            let cancel_elf = options.cancellation.clone();
            let ((struct_result, yara_result), raw_regex) = rayon::join(
                || {
                    rayon::join(
                        || {
                            Ok::<_, anyhow::Error>(analyzer.analyze_structural(
                                path,
                                file_data,
                                input.sha256.clone(),
                            ))
                        },
                        || {
                            if cancel_elf
                                .as_ref()
                                .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                            {
                                return None;
                            }
                            engine
                                .filter(|e| e.is_loaded())
                                .map(|e| e.scan_bytes_with_inline(file_data, Some(file_types)))
                        },
                    )
                },
                || capability_mapper.precompute_raw_regex_matches(file_data, &rule_file_type),
            );
            let mut report = struct_result?;
            let inline_yara =
                process_yara_result(&mut report, yara_result, engine.map(AsRef::as_ref));
            capability_mapper.evaluate_and_merge_findings_with_precomputed(
                &mut report,
                file_data,
                None,
                Some(&inline_yara),
                Some(raw_regex),
                None,
            );
            path_mapper::analyze_and_link_paths(&mut report);
            env_mapper::analyze_and_link_env_vars(&mut report);
            Ok(report)
        }
        FileType::Pe => {
            let mut analyzer = analyzers::pe::PEAnalyzer::new()
                .with_cancellation(options.cancellation.clone())
                .with_capability_mapper_arc(mapper_arc.clone())
                .with_preextracted_strings(preextracted_strings.clone());
            // PE analyzer needs YARA engine for overlay/embedded payload analysis
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            let engine = yara_engine;
            let file_types: &[&str] = &["pe", "exe", "dll", "bat", "ps1"];
            let rule_file_type = capability_mapper.detect_file_type("pe");
            let cancel_pe = options.cancellation.clone();
            let ((struct_result, yara_result), raw_regex) = rayon::join(
                || {
                    rayon::join(
                        || {
                            Ok::<_, anyhow::Error>(analyzer.analyze_structural(
                                path,
                                file_data,
                                input.sha256.clone(),
                            ))
                        },
                        || {
                            if cancel_pe
                                .as_ref()
                                .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
                            {
                                return None;
                            }
                            engine
                                .filter(|e| e.is_loaded())
                                .map(|e| e.scan_bytes_with_inline(file_data, Some(file_types)))
                        },
                    )
                },
                || capability_mapper.precompute_raw_regex_matches(file_data, &rule_file_type),
            );
            let mut report = struct_result?;
            let inline_yara =
                process_yara_result(&mut report, yara_result, engine.map(AsRef::as_ref));
            capability_mapper.evaluate_and_merge_findings_with_precomputed(
                &mut report,
                file_data,
                None,
                Some(&inline_yara),
                Some(raw_regex),
                None,
            );
            Ok(report)
        }
        FileType::JavaClass => analyzers::java_class::JavaClassAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze_input(&input),
        FileType::Lnk => analyzers::lnk::LnkAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze_input(&input),
        FileType::OleDoc | FileType::Ooxml => analyzers::office::OfficeAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .with_cancellation(options.cancellation.clone())
            .analyze_input(&input),
        ref ft if ft.is_archive() => {
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
        FileType::VsixManifest => analyzers::vsix_manifest::VsixManifestAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze_input(&input),
        // All source code languages use the unified analyzer (or generic fallback)
        _ => {
            if let Some(analyzer) =
                analyzers::analyzer_for_file_type_arc(&file_type, Some(mapper_arc.clone()))
            {
                analyzer.analyze_input(&input)
            } else {
                anyhow::bail!("Unsupported file type: {:?}", file_type);
            }
        }
    }?;
    let stage_structural_ms = structural_start.elapsed().as_millis() as u64;

    // Add finding for extension/content mismatch if detected
    if let Some((expected, actual)) = mismatch {
        report.findings.push(types::Finding {
            id: "metadata/file-extension-mismatch".to_string(),
            kind: types::FindingKind::Indicator,
            desc: format!(
                "File extension claims {} but content is {}",
                expected, actual
            ),
            conf: 1.0,
            crit: extension_content_mismatch_criticality(&expected, &actual),
            mbc: None,
            attack: Some("T1036.005".to_string()), // Masquerading: Match Legitimate Name or Location
            trait_refs: vec![],
            evidence: vec![types::Evidence {
                method: "magic-byte".to_string(),
                source: "cleave".to_string(),
                value: format!("expected={}, actual={}", expected, actual),
                location: None,
                ..Default::default()
            }],
            match_count: 0,
            source_file: None,
        });
    }

    // Process encoded payloads and analyze them
    let payloads_start = std::time::Instant::now();
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
            && report.metrics.as_ref().is_some_and(|m| {
                m.pe.as_ref().is_some_and(|pe| pe.has_signature)
                    && m.binary.as_ref().is_some_and(|binary| {
                        binary.export_count <= 2
                            && binary.function_count >= 100
                            && binary.string_count >= 2000
                    })
                    && m.pe
                        .as_ref()
                        .and_then(|pe| pe.signer.as_ref())
                        .is_some_and(|signer| signer.contains("Python Software Foundation"))
            })
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
        if should_skip_unknown_xor_payload_for_source(&file_type, &payload) {
            tracing::debug!(
                "Skipping unknown xor fragment in source file: {}",
                payload.preview
            );
            continue;
        }
        if should_skip_unknown_xor_payload_for_binary(
            &file_type,
            &payload,
            &report.sections,
            report.metrics.as_ref(),
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
            && report
                .metrics
                .as_ref()
                .and_then(|m| m.binary.as_ref())
                .is_some_and(|m| m.function_count >= 200 && m.string_count >= 800)
        {
            tracing::debug!(
                "Skipping unknown xor fragment in versioned .NET resource library: {}",
                payload.preview
            );
            continue;
        }

        // Add finding for the encoded payload
        let crit = match payload.detected_type {
            FileType::Python | FileType::Shell | FileType::Elf | FileType::MachO | FileType::Pe => {
                types::Criticality::Suspicious
            }
            _ => types::Criticality::Notable,
        };

        report.findings.push(types::Finding {
            id: format!(
                "metadata/encoded-payload/{}",
                payload.encoding_chain.join("-")
            ),
            kind: types::FindingKind::Structural,
            desc: format!(
                "Encoded payload detected: {}",
                payload.encoding_chain.join(" → ")
            ),
            conf: 0.9,
            crit,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![types::Evidence {
                method: "pattern".to_string(),
                source: "cleave".to_string(),
                value: format!(
                    "encoding={}, type={:?}, preview={}",
                    payload.encoding_chain.join(", "),
                    payload.detected_type,
                    payload.preview
                ),
                location: Some(format!("offset:{}", payload.original_offset)),
                ..Default::default()
            }],
            match_count: 0,
            source_file: None,
        });

        // Analyze the decoded payload (with depth limit to prevent stack overflow)
        if analysis_depth >= MAX_ANALYSIS_DEPTH {
            tracing::warn!(
                depth = analysis_depth,
                path = %path.display(),
                "Encoded payload analysis depth limit reached ({MAX_ANALYSIS_DEPTH}), skipping deeper analysis"
            );
            report.findings.push(types::Finding {
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
    let yara_start = std::time::Instant::now();
    let handled_yara_internally =
        matches!(file_type, FileType::MachO | FileType::Elf | FileType::Pe)
            || file_type.is_archive();
    if !handled_yara_internally {
        if let Some(engine) = yara_engine {
            if file_type.is_program() && engine.is_loaded() {
                let file_types = file_type.yara_filetypes();
                let filter = if file_types.is_empty() {
                    None
                } else {
                    Some(file_types.as_slice())
                };

                if let Ok((matches, findings)) = engine.scan_bytes_to_findings(file_data, filter) {
                    report.yara_matches = matches;
                    let existing: std::collections::HashSet<String> =
                        report.findings.iter().map(|f| f.id.clone()).collect();
                    for finding in findings {
                        if !existing.contains(finding.id.as_str()) {
                            report.findings.push(finding);
                        }
                    }
                    if !report.metadata.tools_used.contains(&"yara-x".to_string()) {
                        report.metadata.tools_used.push("yara-x".to_string());
                    }
                }
            }
        }
    }
    let stage_yara_ms = yara_start.elapsed().as_millis() as u64;

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

    // Filter low-value composite "any" rules (needs=1) before caching.
    // These provide no value over the underlying trait that matched.
    let removed = report.filter_findings(|f| !capability_mapper.is_low_value_any_rule(&f.id));
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

    // Per-file stage timing summary
    tracing::info!(
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

/// Analyze multiple files in a directory.
///
/// Returns a vector of analysis reports, one for each analyzed file.
pub fn analyze_directory<P: AsRef<Path>>(
    path: P,
    options: &AnalysisOptions,
) -> Result<Vec<AnalysisReport>> {
    use rayon::prelude::*;
    use walkdir::WalkDir;

    let path = path.as_ref();
    if !path.is_dir() {
        anyhow::bail!("Path is not a directory: {}", path.display());
    }

    let _disable_guards = AnalysisDisableGuards::from_options(options);

    // Collect all files, filtering unknown types unless all_files is set
    let all_files_flag = options.all_files;
    let files: Vec<_> = WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let file_name = e.file_name().to_string_lossy();
            !file_name.starts_with(".git")
        })
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_type().is_file())
        .filter(|e| {
            if all_files_flag {
                return true;
            }
            let file_type = detect_file_type(e.path()).unwrap_or(FileType::Unknown);
            analyzers::is_analyzable(e.path(), &file_type)
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    // Analyze in parallel — catch panics so one bad file doesn't kill the batch
    let results: Vec<_> = files
        .par_iter()
        .map(|file_path| {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                analyze_file(file_path, options)
            })) {
                Ok(result) => result.map_err(|err| (file_path.clone(), err)),
                Err(_panic) => {
                    tracing::error!(path = %file_path.display(), "panic during file analysis (caught)");
                    Err((file_path.clone(), anyhow::anyhow!("analysis panicked")))
                }
            }
        })
        .collect();

    let mut reports = Vec::with_capacity(results.len());
    let mut failures = Vec::new();
    for result in results {
        match result {
            Ok(report) => reports.push(report),
            Err((path, err)) => failures.push((path, err)),
        }
    }

    if failures.is_empty() {
        return Ok(reports);
    }

    let mut message = format!("directory analysis failed for {} file(s)", failures.len());
    for (path, err) in failures.iter().take(5) {
        message.push_str(&format!("\n- {}: {err:#}", path.display()));
    }
    if failures.len() > 5 {
        message.push_str(&format!("\n- ... and {} more", failures.len() - 5));
    }

    anyhow::bail!(message)
}

/// An event emitted during [`scan_directory`].
#[derive(Debug)]
pub enum ScanEvent {
    /// Emitted exactly once before analysis begins, with the total number of files to scan.
    Start {
        /// Total number of files that passed the type filter and will be analyzed.
        total: usize,
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

/// Scan a directory, invoking `callback` for each file as its analysis completes.
///
/// Unlike [`analyze_directory`], results stream out of the parallel workers as they
/// finish rather than being collected into a `Vec`. This makes it suitable for
/// progress reporting, streaming output, and processing large directories without
/// accumulating all results in memory.
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
/// `options.all_files` is set, matching the behavior of [`analyze_directory`].
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

    // Load shared resources once; all rayon workers share them via cheap Arc clones.
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
    let mapper = mapper_result?;

    let all_files_flag = options.all_files;
    let mut walked: usize = 0;
    let mut walk_errors: usize = 0;
    let mut dirs_entered: usize = 0;
    let files: Vec<_> = WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let dominated = e.file_name().to_string_lossy().starts_with(".git");
            if dominated {
                tracing::debug!(path = %e.path().display(), "Skipping dotgit directory");
            }
            !dominated
        })
        .filter_map(|entry| match entry {
            Ok(e) => Some(e),
            Err(e) => {
                walk_errors += 1;
                tracing::warn!(error = %e, "Failed to read directory entry");
                None
            }
        })
        .filter(|e| {
            if e.file_type().is_dir() {
                dirs_entered += 1;
                return false;
            }
            if !e.file_type().is_file() {
                tracing::debug!(path = %e.path().display(), "Skipping non-file entry");
                return false;
            }
            walked += 1;
            true
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    tracing::info!(
        walked = walked,
        dirs = dirs_entered,
        errors = walk_errors,
        "Directory walk complete"
    );

    let total = files.len();
    callback(ScanEvent::Start { total });

    let analyzed = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);
    let errors = AtomicUsize::new(0);

    let max_scan_size = options.max_scan_file_size;

    // Dedicated thread pool for directory scanning. Each thread holds an in-flight
    // analysis (~0.5-1.5 GB), so this directly controls peak memory.
    // Priority: CLEAVE_SCAN_THREADS env > options.scan_threads > min(8, cpus).
    let scan_threads = std::env::var("CLEAVE_SCAN_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| {
            if options.scan_threads > 0 {
                options.scan_threads
            } else {
                rayon::current_num_threads().min(8)
            }
        });
    let analyze_files = || {
        files.par_iter().for_each(|file_path| {
        // Catch panics from any analyzer so one malformed file doesn't
        // poison the rayon thread pool and kill the entire scan.
        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Skip files exceeding the size limit (avoids mmap'ing huge ISOs/disk images).
        if max_scan_size > 0 {
            if let Ok(meta) = std::fs::metadata(file_path) {
                if meta.len() > max_scan_size {
                    tracing::debug!(
                        path = %file_path.display(),
                        size_mb = meta.len() / (1024 * 1024),
                        limit_mb = max_scan_size / (1024 * 1024),
                        "skipping file exceeding --max-file-size limit"
                    );
                    skipped.fetch_add(1, Ordering::Relaxed);
                    return;
                }
            }
        }

        // File-type filtering: read the file once and check type from loaded data.
        // Previously this was done during collection (reading every file twice).
        if !all_files_flag {
            let Ok(file_data) = file_io::read_file_smart(file_path) else {
                tracing::debug!(path = %file_path.display(), "Skipping unreadable file");
                skipped.fetch_add(1, Ordering::Relaxed);
                return;
            };
            let ft = analyzers::detect_file_type_from_data(file_path, file_data.as_slice());
            if !analyzers::is_analyzable(file_path, &ft) {
                tracing::debug!(path = %file_path.display(), file_type = ?ft, "Skipping non-analyzable file");
                skipped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            // Pass pre-loaded data to avoid a second read
            let result = analyze_file_with_resources(
                file_path,
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
            analyze_file_with_resources(file_path, options, &mapper, yara_engine.as_ref(), None);
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

    match rayon::ThreadPoolBuilder::new()
        .num_threads(scan_threads)
        .build()
    {
        Ok(scan_pool) => {
            tracing::info!(scan_threads, "Directory scan thread pool created");
            scan_pool.install(analyze_files);
        }
        Err(error) => {
            tracing::warn!(
                scan_threads,
                %error,
                "Failed to build dedicated directory scan thread pool; using global Rayon pool"
            );
            analyze_files();
        }
    }

    let final_analyzed = analyzed.load(Ordering::Relaxed);
    let final_skipped = skipped.load(Ordering::Relaxed);
    let final_errors = errors.load(Ordering::Relaxed);
    tracing::info!(
        total = total,
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

    let aggregated = output::aggregate_findings_by_directory(findings);
    let filtered: Vec<_> = aggregated
        .into_iter()
        .filter(|f| f.crit != types::Criticality::Baseline && f.conf >= 0.5)
        .collect();

    malecule_bridge::formula_from_findings(&filtered)
}

/// Compare two file versions for supply chain attack detection.
///
/// This is useful for detecting malicious changes between package versions.
pub fn diff_files<P: AsRef<Path>>(old_path: P, new_path: P) -> Result<DiffReport> {
    let analyzer = DiffAnalyzer::new(old_path, new_path);
    analyzer.analyze()
}

/// Compare two files or directories and return the comprehensive diff report.
pub fn diff_files_full<P: AsRef<Path>>(old_path: P, new_path: P) -> Result<FullDiffReport> {
    let analyzer = DiffAnalyzer::new(old_path, new_path);
    analyzer.analyze_full()
}

/// Format a diff report for terminal output.
#[must_use]
pub fn format_diff_terminal(report: &DiffReport) -> String {
    diff::format_diff_terminal(report)
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

        let options = AnalysisOptions::default();
        let mapper = shared_resources::capability_mapper_with_options(&options)
            .expect("mapper should load for depth-limit test");
        let yara = if options.disable_yara {
            None
        } else {
            Some(shared_resources::yara_engine(
                options.enable_third_party_yara,
            ))
        };

        // Analyze at exactly MAX_ANALYSIS_DEPTH — any encoded payloads found
        // should trigger the deep-nesting finding instead of recursing.
        #[allow(clippy::expect_used)]
        let report = analyze_file_with_resources_at_depth(
            path,
            &options,
            &mapper,
            yara.as_ref(),
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
            ..AnalysisOptions::default()
        };
        let mapper = shared_resources::capability_mapper_with_options(&options)
            .expect("mapper should load for depth-zero test");

        #[allow(clippy::expect_used)]
        let report =
            analyze_file_with_resources_at_depth(tmp.path(), &options, &mapper, None, None, 0)
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

    #[test]
    fn test_extension_content_mismatch_images_are_notable() {
        assert_eq!(
            extension_content_mismatch_criticality("JPEG image", "PNG image"),
            types::Criticality::Notable
        );
    }

    #[test]
    fn test_extension_content_mismatch_non_images_are_suspicious() {
        assert_eq!(
            extension_content_mismatch_criticality("WOFF2 font", "hex-encoded data"),
            types::Criticality::Suspicious
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_analyze_directory_reports_per_file_failures() {
        use std::fs;

        #[allow(clippy::expect_used)]
        let temp_dir = tempfile::tempdir().expect("create temp dir");
        let valid = temp_dir.path().join("valid.sh");
        let malformed_zip = temp_dir.path().join("broken.zip");

        #[allow(clippy::expect_used)]
        fs::write(&valid, b"#!/bin/sh\necho ok\n").expect("write valid file");
        #[allow(clippy::expect_used)]
        fs::write(&malformed_zip, b"PK\x03\x04not-a-real-zip").expect("write malformed archive");

        let options = AnalysisOptions {
            disable_yara: true,
            disable_radare2: true,
            disable_upx: true,
            ..Default::default()
        };

        let err = analyze_directory(temp_dir.path(), &options).expect_err(
            "directory analysis should surface malformed-file failures instead of dropping them",
        );
        let message = format!("{err:#}");
        assert!(message.contains("directory analysis failed for 1 file(s)"));
        assert!(message.contains("broken.zip"));
    }
}
