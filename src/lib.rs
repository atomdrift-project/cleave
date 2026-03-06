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

mod analysis_cache;
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

// HTTP API server
pub mod server;

// Re-export commonly used types at crate root
pub use analyzers::{detect_file_type, AnalysisInput, Analyzer, FileType};
pub use capabilities::CapabilityMapper;
pub use composite_rules::Platform;
pub use diff::DiffAnalyzer;
pub use types::binary::StringInfo;
pub use types::code_structure::{BinaryProperties, SourceCodeMetrics};
pub use types::core::{AnalysisReport, Criticality, TargetInfo};
pub use types::diff::{DiffReport, ModifiedFileAnalysis};
pub use types::scores::Metrics;
pub use types::text_metrics::TextMetrics;
pub use types::traits_findings::{Evidence, Finding, FindingKind, Trait, TraitKind};
pub use types::SampleExtractionConfig;

// Re-export cache management functions
pub use composite_rules::clear_condition_stats;
pub use composite_rules::evaluators::clear_thread_local_caches;

use anyhow::Result;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Process YARA scan results and add them to the analysis report.
///
/// Extracts YARA matches and inline evidence, converts matches to findings,
/// and returns inline evidence map for use in trait evaluation.
fn process_yara_result(
    report: &mut types::AnalysisReport,
    yara_result: Option<Result<(Vec<types::YaraMatch>, HashMap<String, Vec<types::Evidence>>)>>,
    engine: Option<&yara_engine::YaraEngine>,
) -> HashMap<String, Vec<types::Evidence>> {
    let Some(Ok((matches, inline))) = yara_result else {
        return HashMap::new();
    };
    report.yara_matches = matches.clone();
    for yara_match in &matches {
        let cap_id = yara_match
            .trait_id
            .clone()
            .unwrap_or_else(|| yara_match.namespace.replace('.', "/"));
        if report.findings.iter().any(|c| c.id == cap_id) {
            continue;
        }
        let evidence = engine
            .map(|e| e.yara_match_to_evidence(yara_match))
            .unwrap_or_default();
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
    /// Enable comprehensive validation of capability definitions
    pub enable_full_validation: bool,
    /// Maximum file size (bytes) to load into memory from archives
    pub max_memory_file_size: u64,
    /// Configuration for extracting suspicious files from archives
    pub sample_extraction: Option<types::SampleExtractionConfig>,
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
            enable_full_validation: false,
            max_memory_file_size: 512 * 1024 * 1024, // 512 MB default
            sample_extraction: None,
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
    let path = path.as_ref();

    // Fast path: check the analysis cache before loading expensive resources.
    // SHA256 of the file is cheap (~1ms); loading CapabilityMapper + YARA is not (~800ms).
    if path.is_file() {
        let file_data = file_io::read_file_smart(path)?;
        let sha256 = analyzers::utils::calculate_sha256(file_data.as_slice());
        if let Some(mut report) = analysis_cache::cache_lookup(&sha256, options) {
            report.target.path = path.display().to_string();
            report.analysis_timestamp = chrono::Utc::now();
            tracing::info!("Cache hit (fast path)");
            return Ok(report);
        }
    }

    // Cache miss: load mapper and YARA engine in parallel (~860ms + ~270ms → ~860ms)
    let (mapper, yara_engine) = rayon::join(
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
    analyze_file_with_resources(path, options, &mapper, yara_engine.as_ref())
}

/// Analyze a single file using a pre-loaded CapabilityMapper.
///
/// Use this for batch processing to avoid reloading capabilities for each file.
/// Uses the shared global YARA engine singleton.
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
    // Wrap in Arc for the internal API (this is the less-common path;
    // callers with an Arc should use analyze_file_with_resources directly)
    let mapper_arc = Arc::new(capability_mapper.clone());
    analyze_file_with_resources(path, options, &mapper_arc, yara_engine.as_ref())
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
    capability_mapper: &Arc<CapabilityMapper>,
    yara_engine: Option<&Arc<yara_engine::YaraEngine>>,
) -> Result<AnalysisReport> {
    let path = path.as_ref();
    let span = tracing::info_span!("analyze", path = %path.display());
    let _enter = span.enter();

    // Log BEFORE processing to ensure we capture what file causes OOM crashes
    tracing::info!("Starting analysis");

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

    // Compute SHA256 early for cache lookup (also reused by analyzers)
    let sha256_hex = analyzers::utils::calculate_sha256(file_data);

    // Check analysis cache before running the full pipeline
    if let Some(mut cached_report) = analysis_cache::cache_lookup(&sha256_hex, options) {
        cached_report.target.path = path.display().to_string();
        cached_report.analysis_timestamp = chrono::Utc::now();
        tracing::info!("Cache hit");
        memory_tracker::log_after_file_processing(
            path.to_str().unwrap_or("unknown"),
            file_size,
            analysis_start.elapsed(),
        );
        return Ok(cached_report);
    }

    // Check for extension/content mismatch
    let mismatch = analyzers::check_extension_content_mismatch(path, file_data);

    // Extract strings with stng ONCE - used for encoded payloads and passed to analyzers
    let opts = stng::ExtractOptions::new(4).with_garbage_filter(true);
    let stng_strings = stng::extract_strings_with_options(file_data, &opts);

    // Check for encoded payloads (hex, base64, etc.) using stng results
    let encoded_payloads = extractors::encoded_payload::extract_encoded_payloads(&stng_strings);

    // Create unified analysis input - all analyzers receive the same pre-extracted data
    let input = analyzers::AnalysisInput::with_payloads(
        path,
        file_data,
        &stng_strings,
        &encoded_payloads,
        file_type.clone(),
    )
    .with_sha256(sha256_hex.clone());

    // Convert stng strings to StringInfo for binary analyzers (avoids redundant extraction)
    let string_extractor = strings::StringExtractor::new();
    let preextracted_strings = string_extractor.convert_stng_strings(&stng_strings);

    // Share mapper Arc — all analyzers share it via cheap ref-count bumps
    let mapper_arc = Arc::clone(capability_mapper);

    // Route to appropriate analyzer.
    // Binary analyzers (MachO, Elf, Pe) use parallel YARA for performance.
    // All other analyzers use analyze_input() for unified data flow.
    let mut report = match file_type {
        FileType::MachO => {
            // Run YARA scan in parallel with structural analysis for inline evidence
            let analyzer = analyzers::macho::MachOAnalyzer::new()
                .with_capability_mapper_arc(mapper_arc.clone())
                .with_preextracted_strings(preextracted_strings.clone());
            let range = analyzer.preferred_arch_range(file_data);
            let arch_data = &file_data[range.clone()];
            let is_fat = analyzer.all_arch_ranges(file_data).len() > 1;
            let eval_data = if is_fat { file_data } else { arch_data };
            let engine = yara_engine;
            let file_types: &[&str] = &["macho", "dylib", "kext"];
            // Run structural analysis, YARA scan, and raw regex precompute in parallel.
            // Raw regex precompute (~224ms) normally runs inside evaluate_and_merge_findings;
            // starting it here overlaps it with structural analysis (~275ms).
            let rule_file_type = capability_mapper.detect_file_type("macho");
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
            capability_mapper.evaluate_and_merge_findings_with_precomputed(
                &mut report,
                eval_data,
                None,
                Some(&inline_yara),
                Some(raw_regex),
            );
            Ok(report)
        }
        FileType::Elf => {
            let analyzer = analyzers::elf::ElfAnalyzer::new()
                .with_capability_mapper_arc(mapper_arc.clone())
                .with_preextracted_strings(preextracted_strings.clone());
            let engine = yara_engine;
            let file_types: &[&str] = &["elf", "so", "ko"];
            let rule_file_type = capability_mapper.detect_file_type("elf");
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
            );
            path_mapper::analyze_and_link_paths(&mut report);
            env_mapper::analyze_and_link_env_vars(&mut report);
            Ok(report)
        }
        FileType::Pe => {
            let mut analyzer = analyzers::pe::PEAnalyzer::new()
                .with_capability_mapper_arc(mapper_arc.clone())
                .with_preextracted_strings(preextracted_strings.clone());
            // PE analyzer needs YARA engine for overlay/embedded payload analysis
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            let engine = yara_engine;
            let file_types: &[&str] = &["pe", "exe", "dll", "bat", "ps1"];
            let rule_file_type = capability_mapper.detect_file_type("pe");
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
            );
            Ok(report)
        }
        FileType::JavaClass => analyzers::java_class::JavaClassAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze_input(&input),
        FileType::Lnk => analyzers::lnk::LnkAnalyzer::new()
            .with_capability_mapper_arc(mapper_arc.clone())
            .analyze_input(&input),
        FileType::Jar | FileType::Archive => {
            let mut analyzer = analyzers::archive::ArchiveAnalyzer::new()
                .with_capability_mapper_arc(mapper_arc.clone())
                .with_zip_passwords(options.zip_passwords.clone())
                .with_max_memory_file_size(options.max_memory_file_size);
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            if let Some(ref config) = options.sample_extraction {
                analyzer = analyzer.with_sample_extraction(config.clone());
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
            analyze_file_with_resources(&payload.temp_path, options, capability_mapper, yara_engine)
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

    // Run YARA for file types that didn't handle it internally.
    // Binary types (MachO, Elf, Pe) and archives already ran YARA with parallel scanning above.
    let handled_yara_internally = matches!(
        file_type,
        FileType::MachO | FileType::Elf | FileType::Pe | FileType::Archive | FileType::Jar
    );
    if !handled_yara_internally {
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
    }

    // Filter low-value composite "any" rules (needs=1) before caching.
    // These provide no value over the underlying trait that matched.
    let removed = report.filter_findings(|f| !capability_mapper.is_low_value_any_rule(&f.id));
    if removed > 0 {
        tracing::debug!("Filtered {} low-value composite 'any' rules", removed);
    }

    // Log memory state after processing
    memory_tracker::log_after_file_processing(
        path.to_str().unwrap_or("unknown"),
        file_size,
        analysis_start.elapsed(),
    );

    // Store result in analysis cache for future lookups
    analysis_cache::cache_store(&sha256_hex, options, &report);

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
