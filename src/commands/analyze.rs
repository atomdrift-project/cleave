//! Single file analysis command.
//!
//! This module implements the core file analysis functionality for cleave.
//! It performs comprehensive analysis of a single file or directory, including:
//!
//! - File type detection via magic bytes
//! - Format-specific structural analysis (ELF, PE, Mach-O, scripts, archives, etc.)
//! - YARA rule scanning with parallel loading
//! - Capability mapping and trait evaluation
//! - Composite rule evaluation
//! - Criticality assessment and filtering
//!
//! # Architecture
//!
//! The analysis process follows these steps:
//!
//! 1. **File Type Detection**: Fast magic byte inspection to determine file format
//! 2. **Parallel Initialization**: YARA rules and capability mapper load concurrently
//! 3. **Format Routing**: Files are routed to specialized analyzers based on type
//! 4. **Trait Evaluation**: Capability mapper processes findings and assigns traits
//! 5. **Output Formatting**: Results are formatted as Terminal or JSONL
//!
//! # Performance
//!
//! - YARA loading happens in parallel with capability mapper initialization
//! - Binary formats (ELF/PE/Mach-O) run structural analysis and YARA scans in parallel
//! - Archives support streaming JSONL output for progressive results
//! - Directory traversal loads YARA rules once and reuses for all files
//!
//! # Output Formats
//!
//! - **Terminal**: Human-readable summary with findings and metadata
//! - **JSONL**: Machine-readable JSON Lines format (one JSON object per line)

use crate::cli;
use crate::composite_rules;
use crate::output;
use crate::types;
use anyhow::Result;
use std::io::Write;
use std::path::Path;

/// All parameters needed by the analyze command.
pub(crate) struct AnalyzeConfig<'a> {
    pub target: &'a str,
    pub enable_third_party: bool,
    pub format: &'a cli::OutputFormat,
    pub zip_passwords: &'a [String],
    pub disabled: &'a cli::DisabledComponents,
    pub all_files: bool,
    pub sample_extraction: Option<&'a types::SampleExtractionConfig>,
    pub platforms: &'a [composite_rules::Platform],
    pub min_hostile_precision: f32,
    pub min_suspicious_precision: f32,
    pub max_memory_file_size: u64,
    pub enable_full_validation: bool,
    pub slow_rule_ms: u64,
    pub output_to_file: bool,
    pub max_scan_file_size: u64,
    pub scan_threads: usize,
}

/// Analyze a single file or directory with comprehensive malware detection.
pub(crate) fn run(config: &AnalyzeConfig<'_>) -> Result<String> {
    let path = Path::new(config.target);

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", config.target);
    }

    // Convert binary crate types to library crate types via serde round-trip
    // (necessary because main.rs re-declares modules, creating parallel type hierarchies).
    let platforms_lib: Vec<cleave::Platform> = if config.platforms.is_empty() {
        vec![cleave::Platform::All]
    } else {
        let json = serde_json::to_string(config.platforms).unwrap_or_default();
        serde_json::from_str(&json).unwrap_or_else(|_| vec![cleave::Platform::All])
    };
    let sample_lib: Option<cleave::SampleExtractionConfig> =
        config
            .sample_extraction
            .map(|s| cleave::SampleExtractionConfig {
                extract_dir: s.extract_dir.clone(),
                archive_sha256: s.archive_sha256.clone(),
            });
    let options = cleave::AnalysisOptions {
        enable_third_party_yara: config.enable_third_party && !config.disabled.third_party,
        zip_passwords: config.zip_passwords.to_vec(),
        disable_yara: config.disabled.yara,
        disable_radare2: config.disabled.radare2,
        disable_upx: config.disabled.upx,
        all_files: config.all_files,
        platforms: platforms_lib,
        min_hostile_precision: config.min_hostile_precision,
        min_suspicious_precision: config.min_suspicious_precision,
        enable_full_validation: config.enable_full_validation,
        max_memory_file_size: config.max_memory_file_size,
        sample_extraction: sample_lib,
        slow_rule_ms: config.slow_rule_ms,
        max_scan_file_size: config.max_scan_file_size,
        scan_threads: config.scan_threads,
    };

    // If target is a directory, process files recursively
    if path.is_dir() {
        let options_arc = std::sync::Arc::new(options);
        let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let results_clone = results.clone();
        let format_val = *config.format;
        let stream_stdout = !config.output_to_file;

        cleave::scan_directory(path, &options_arc, move |event| match event {
            cleave::ScanEvent::Start { total } => {
                tracing::info!(total = total, "Starting directory scan");
            }
            cleave::ScanEvent::File {
                path: file_path,
                result,
            } => {
                let file_path_str = file_path.to_string_lossy().to_string();
                let formatted = match result.as_ref() {
                    Ok(lib_report) => {
                        // Convert library types to binary-crate types via serde roundtrip.
                        let Ok(json) = serde_json::to_vec(lib_report) else {
                            return;
                        };
                        let Ok(mut report) = serde_json::from_slice::<types::AnalysisReport>(&json)
                        else {
                            return;
                        };

                        report.shrink_to_fit();
                        report.finalize();

                        let res = match format_val {
                            cli::OutputFormat::Json => {
                                serde_json::to_string(&report).unwrap_or_default()
                            }
                            cli::OutputFormat::Jsonl => {
                                output::format_jsonl(&report).unwrap_or_default()
                            }
                            cli::OutputFormat::Terminal => output::format_terminal(&report),
                            cli::OutputFormat::Tiny => output::format_tiny(&report),
                        };
                        if stream_stdout && !res.is_empty() {
                            print!("{}", res);
                            let _ = std::io::stdout().flush();
                        }
                        res
                    }
                    Err(e) => {
                        tracing::error!(path = %file_path_str, error = %e, "Analysis failed");
                        String::new()
                    }
                };
                if !stream_stdout && !formatted.is_empty() {
                    if let Ok(mut guard) = results_clone.lock() {
                        guard.push(formatted);
                    }
                }
            }
        })?;

        if config.output_to_file {
            let final_results = results
                .lock()
                .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
            return Ok(final_results.join(""));
        }
        // Results already streamed to stdout in the callback.
        return Ok(String::new());
    }

    // Single file analysis
    analyze_and_format(config.target, &options, config.format)
}

/// Analyze a single file and format the output.
///
/// Uses `cleave::analyze_file()` for the core analysis pipeline (with caching),
/// then converts the result to binary-crate types via serde roundtrip (necessary
/// because main.rs re-declares library modules, creating parallel type hierarchies).
/// Finally applies CLI-specific post-processing (encoding layer merging,
/// filtering, output formatting).
fn analyze_and_format(
    target: &str,
    options: &cleave::AnalysisOptions,
    format: &cli::OutputFormat,
) -> Result<String> {
    let path = Path::new(target);

    // Core analysis — single pipeline in lib.rs, with caching
    let lib_report = cleave::analyze_file(path, options)?;

    // Convert library types to binary-crate types via serde roundtrip.
    // The types are structurally identical but Rust treats them as distinct
    // because main.rs re-declares the library modules.
    let json = serde_json::to_vec(&lib_report)?;
    let mut report: types::AnalysisReport = serde_json::from_slice(&json)?;

    report.shrink_to_fit();
    report.finalize();

    // Merge encoding layers and recalculate composites.
    // The mapper is only needed when encoding layers are actually merged (rare for single files),
    // so we defer its expensive initialization to avoid ~800ms overhead on the common path.
    let merged_indices = report.merge_encoding_layers();
    if !merged_indices.is_empty() {
        let capability_mapper =
            crate::capabilities::CapabilityMapper::new_with_precision_thresholds(
                options.min_hostile_precision,
                options.min_suspicious_precision,
                options.enable_full_validation,
            );
        for &idx in &merged_indices {
            let file = &report.files[idx];
            let mut temp_report = types::AnalysisReport::new(types::TargetInfo {
                path: file.path.clone(),
                file_type: file.file_type.clone(),
                sha256: file.sha256.clone(),
                size_bytes: file.size,
                architectures: None,
            });
            temp_report.findings = file.findings.clone();

            let new_composites = capability_mapper.evaluate_container_composites(
                &temp_report,
                &file.findings,
                &file.file_type,
            );
            if !new_composites.is_empty() {
                let file = &mut report.files[idx];
                for finding in new_composites {
                    if !file.findings.iter().any(|f| f.id == finding.id) {
                        file.findings.push(finding);
                    }
                }
                file.compute_summary();
            }
        }
        tracing::debug!(
            "Merged encoding layers into {} parent file(s)",
            merged_indices.len()
        );
    }

    // Filter unmatched component traits for terminal output
    if *format == cli::OutputFormat::Terminal {
        let removed = report.filter_unmatched_components();
        if removed > 0 {
            tracing::debug!(
                "Filtered {} unmatched component traits from terminal output",
                removed
            );
        }
    }

    match format {
        cli::OutputFormat::Json => Ok(serde_json::to_string(&report)?),
        cli::OutputFormat::Jsonl => output::format_jsonl(&report),
        cli::OutputFormat::Terminal => Ok(output::format_terminal(&report)),
        cli::OutputFormat::Tiny => Ok(output::format_tiny(&report)),
    }
}
