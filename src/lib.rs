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
//! let options = AnalysisOptions::default();
//! let report = analyze_file("suspicious.py", &options).unwrap();
//!
//! for finding in &report.findings {
//!     println!("{}: {} ({:?})", finding.id, finding.desc, finding.crit);
//! }
//! ```

mod archive_utils;
mod cache;
pub mod decoders;
mod entropy;
pub mod extractors;
pub mod file_io;
pub mod ip_validator;
pub mod map;
pub mod memory_tracker;
mod radare2;
mod shared_resources;
mod strings;
mod upx;

// Standalone RTF parser (can be used independently)
pub mod rtf;

// Public modules
pub mod analyzers;
pub mod capabilities;
pub mod cli;
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

// Re-export commonly used types at crate root
pub use analyzers::{detect_file_type, Analyzer, FileType};
pub use capabilities::CapabilityMapper;
pub use diff::DiffAnalyzer;
pub use types::binary::StringInfo;
pub use types::code_structure::{BinaryProperties, SourceCodeMetrics};
pub use types::core::{AnalysisReport, Criticality, TargetInfo};
pub use types::diff::{DiffReport, ModifiedFileAnalysis};
pub use types::scores::Metrics;
pub use types::text_metrics::TextMetrics;
pub use types::traits_findings::{Evidence, Finding, FindingKind, Trait, TraitKind};

// Re-export cache management functions
pub use composite_rules::clear_condition_stats;
pub use composite_rules::evaluators::clear_thread_local_caches;

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;

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

    // Clear on all rayon worker threads using broadcast
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
    let mapper = shared_resources::capability_mapper();
    let yara_engine = if options.disable_yara {
        None
    } else {
        Some(shared_resources::yara_engine(
            options.enable_third_party_yara,
        ))
    };
    analyze_file_with_resources(path, options, &mapper, yara_engine.as_ref())
}

/// Analyze a single file using a pre-loaded CapabilityMapper.
///
/// Use this for batch processing to avoid reloading capabilities for each file.
/// Note: This function still creates a new YARA engine per call. For maximum efficiency
/// with YARA, use `analyze_file` which uses shared global resources.
///
/// # Arguments
///
/// * `path` - Path to the file to analyze
/// * `options` - Analysis options
/// * `capability_mapper` - Pre-loaded capability mapper
///
/// # Returns
///
/// An `AnalysisReport` containing all extracted features, findings, and metrics.
pub fn analyze_file_with_mapper<P: AsRef<Path>>(
    path: P,
    options: &AnalysisOptions,
    capability_mapper: &CapabilityMapper,
) -> Result<AnalysisReport> {
    // Use shared YARA engine (initialized on first use)
    let yara_engine = if options.disable_yara {
        None
    } else {
        Some(shared_resources::yara_engine(
            options.enable_third_party_yara,
        ))
    };
    analyze_file_with_resources(path, options, capability_mapper, yara_engine.as_ref())
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
fn analyze_file_with_resources<P: AsRef<Path>>(
    path: P,
    options: &AnalysisOptions,
    capability_mapper: &CapabilityMapper,
    yara_engine: Option<&Arc<yara_engine::YaraEngine>>,
) -> Result<AnalysisReport> {
    let path = path.as_ref();

    // Log BEFORE processing to ensure we capture what file causes OOM crashes
    tracing::info!("Starting analysis of file: {}", path.display());

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", path.display());
    }

    if path.is_dir() {
        anyhow::bail!(
            "Path is a directory, use analyze_directory instead: {}",
            path.display()
        );
    }

    // Apply global disables
    if options.disable_radare2 {
        radare2::disable_radare2();
    }
    if options.disable_upx {
        upx::disable_upx();
    }

    // Detect file type
    tracing::debug!("Detecting file type for: {}", path.display());
    let file_type = detect_file_type(path)?;
    tracing::debug!(
        "Detected file type: {:?} for: {}",
        file_type,
        path.display()
    );

    // Get file size for memory tracking
    let file_size = std::fs::metadata(path)?.len();

    // Log memory state before processing
    memory_tracker::log_before_file_processing(path.to_str().unwrap_or("unknown"), file_size);

    let analysis_start = std::time::Instant::now();

    // Read file for mismatch check and payload extraction
    // Use smart reading (memory-mapping for large files)
    let file_data_wrapper = file_io::read_file_smart(path)?;
    let file_data = file_data_wrapper.as_slice();

    // Track file read for memory monitoring
    memory_tracker::global_tracker()
        .record_file_read(file_size, path.to_str().unwrap_or("unknown"));

    // Check for extension/content mismatch
    let mismatch = analyzers::check_extension_content_mismatch(path, file_data);

    // Extract strings with stng ONCE
    let opts = stng::ExtractOptions::new(16).with_garbage_filter(true);
    let stng_strings = stng::extract_strings_with_options(file_data, &opts);

    // Check for encoded payloads (hex, base64, etc.) using stng results
    let encoded_payloads = extractors::encoded_payload::extract_encoded_payloads(&stng_strings);

    // Wrap mapper in Arc once — all analyzers share it via cheap ref-count bumps
    let mapper_arc = Arc::new(capability_mapper.clone());

    // Route to appropriate analyzer.
    // For ELF/MachO/PE the YARA engine is NOT passed to the analyzer; YARA scanning
    // happens in the post-analysis block below via scan_file_to_findings.
    let mut report = match file_type {
        FileType::MachO => analyzers::macho::MachOAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze(path)?,
        FileType::Elf => analyzers::elf::ElfAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze(path)?,
        FileType::Pe => analyzers::pe::PEAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze(path)?,
        FileType::JavaClass => analyzers::java_class::JavaClassAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze(path)?,
        FileType::Lnk => analyzers::lnk::LnkAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze(path)?,
        FileType::Jar | FileType::Archive => {
            let mut analyzer = analyzers::archive::ArchiveAnalyzer::new()
                .with_capability_mapper_arc(mapper_arc.clone())
                .with_zip_passwords(options.zip_passwords.clone());
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            analyzer.analyze(path)?
        }
        FileType::PackageJson => analyzers::package_json::PackageJsonAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze(path)?,
        FileType::VsixManifest => analyzers::vsix_manifest::VsixManifestAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze(path)?,
        // All source code languages use the unified analyzer (or generic fallback)
        _ => {
            if let Some(analyzer) =
                analyzers::analyzer_for_file_type_arc(&file_type, Some(mapper_arc.clone()))
            {
                analyzer.analyze(path)?
            } else {
                anyhow::bail!("Unsupported file type: {:?}", file_type);
            }
        }
    };

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
            crit: types::Criticality::Hostile,
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
    for payload in encoded_payloads {
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

        // Analyze the decoded payload
        if let Ok(payload_report) =
            analyze_file_with_mapper(&payload.temp_path, options, capability_mapper)
        {
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

    // Run YARA for file types that didn't handle it internally
    if let Some(engine) = yara_engine {
        if file_type.is_program() && engine.is_loaded() {
            let file_types = file_type.yara_filetypes();
            let filter = if file_types.is_empty() {
                None
            } else {
                Some(file_types.as_slice())
            };

            if let Ok((matches, findings)) = engine.scan_file_to_findings(path, filter) {
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

    // Log memory state after processing
    memory_tracker::log_after_file_processing(
        path.to_str().unwrap_or("unknown"),
        file_size,
        analysis_start.elapsed(),
    );

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

    // Apply global disables
    if options.disable_radare2 {
        radare2::disable_radare2();
    }
    if options.disable_upx {
        upx::disable_upx();
    }

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
        .filter(|e| !archive_utils::is_archive(e.path()))
        .filter(|e| {
            if all_files_flag {
                return true;
            }
            // Skip unknown file types by default
            let file_type = detect_file_type(e.path()).unwrap_or(FileType::Unknown);
            file_type.is_program()
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    // Analyze in parallel
    let reports: Vec<_> = files
        .par_iter()
        .filter_map(|file_path| analyze_file(file_path, options).ok())
        .collect();

    Ok(reports)
}

/// Compare two file versions for supply chain attack detection.
///
/// This is useful for detecting malicious changes between package versions.
pub fn diff_files<P: AsRef<Path>>(old_path: P, new_path: P) -> Result<DiffReport> {
    let analyzer = DiffAnalyzer::new(old_path, new_path);
    analyzer.analyze()
}
