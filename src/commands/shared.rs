//! Shared utilities for command implementations.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//!
//! This module contains common data structures, helper functions, and utilities
//! used across multiple command implementations in the DISSECT CLI.
//!
//! # Contents
//!
//! - **Data Structures**: Common types like `SectionInfo` and `SymbolInfo`
//! - **Input Handling**: Functions for reading and expanding paths from stdin
//! - **Analysis Helpers**: File analysis, YARA processing, and report creation
//! - **Utility Functions**: Type conversions, string extraction, and metric flattening

use crate::analyzers::{self, detect_file_type, AnalysisInput, Analyzer, FileType};
use crate::types;
use crate::yara_engine::YaraEngine;
use anyhow::Result;
use serde::Serialize;
use std::io::BufRead;
use std::path::Path;
use std::sync::Arc;

// ============================================================================
// Data Structures
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SectionInfo {
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) address: Option<String>,
    pub(crate) size: u64,
    pub(crate) entropy: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) permissions: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SymbolInfo {
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) library: Option<String>,
    pub(crate) symbol_type: String,
    pub(crate) source: String,
}

// ============================================================================
// Input Handling
// ============================================================================

/// Read paths from stdin, one per line.
/// Filters out empty lines and comments (lines starting with #).
pub(crate) fn read_paths_from_stdin() -> Vec<String> {
    let stdin = std::io::stdin();
    let reader = stdin.lock();
    reader
        .lines()
        .map_while(Result::ok)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

/// Expand paths, replacing "-" with paths read from stdin.
pub(crate) fn expand_paths(paths: Vec<String>, format: &crate::cli::OutputFormat) -> Vec<String> {
    let mut expanded = Vec::new();
    let mut stdin_read = false;

    for path in paths {
        if path == "-" {
            if !stdin_read {
                let stdin_paths = read_paths_from_stdin();
                if *format == crate::cli::OutputFormat::Terminal {
                    eprintln!("Read {} paths from stdin", stdin_paths.len());
                }
                expanded.extend(stdin_paths);
                stdin_read = true;
            }
            // If "-" appears multiple times, only read stdin once
        } else {
            expanded.push(path);
        }
    }

    expanded
}

/// Check if a report's highest criticality matches or exceeds any of the error_if levels
/// If so, exit with error
///
/// The check matches "level or higher" - e.g., --error-if=notable will trigger for
/// files with Notable, Suspicious, or Hostile criticality.
pub(crate) fn check_criticality_error(
    report: &types::AnalysisReport,
    error_if_levels: Option<&[types::Criticality]>,
) -> Result<()> {
    if let Some(levels) = error_if_levels {
        if let Some(highest_crit) = report.highest_criticality() {
            // Check if highest criticality >= any of the specified levels
            for &threshold in levels {
                if highest_crit >= threshold {
                    anyhow::bail!(
                        "File '{}' has highest criticality {:?} which matches --error-if criteria (threshold: {:?})",
                        report.target.path,
                        highest_crit,
                        threshold
                    );
                }
            }
        }
    }
    Ok(())
}

// ============================================================================
// YARA Processing
// ============================================================================

/// Process YARA scan results and add them to the analysis report.
///
/// This function extracts YARA matches and inline evidence, converts matches
/// to findings with appropriate criticality levels, and adds them to the report.
pub(crate) fn process_yara_result(
    report: &mut types::AnalysisReport,
    yara_result: Option<
        anyhow::Result<(
            Vec<types::YaraMatch>,
            std::collections::HashMap<String, Vec<types::Evidence>>,
        )>,
    >,
    engine: Option<&YaraEngine>,
) -> std::collections::HashMap<String, Vec<types::Evidence>> {
    let Some(Ok((matches, inline))) = yara_result else {
        return std::collections::HashMap::new();
    };
    report.yara_matches = matches.clone();
    for yara_match in &matches {
        // Prefer trait_id for third-party rules (e.g., "third_party/elastic/...")
        // Fall back to namespace conversion for built-in rules
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

// ============================================================================
// File Analysis
// ============================================================================

/// Analyze a file with a shared capability mapper and optional YARA engine.
///
/// This is the core analysis function used by the scan and analyze commands.
/// It performs comprehensive analysis including:
/// - File type detection
/// - Format-specific analysis (binary, script, archive, etc.)
/// - Extension/content mismatch detection
/// - Encoded payload extraction
/// - YARA scanning
/// - Criticality checking
#[allow(clippy::too_many_arguments, dead_code)]
pub(crate) fn analyze_file_with_shared_mapper(
    target: &str,
    capability_mapper: &Arc<crate::capabilities::CapabilityMapper>,
    shared_yara_engine: Option<&Arc<YaraEngine>>,
    zip_passwords: &[String],
    _disabled: &crate::cli::DisabledComponents,
    error_if_levels: Option<&[types::Criticality]>,
    verbose: bool,
    sample_extraction: Option<&types::SampleExtractionConfig>,
    max_memory_file_size: u64,
) -> Result<String> {
    // Log BEFORE processing to ensure we capture what file causes OOM crashes
    tracing::info!("Starting analysis of file: {}", target);

    let _t_start = std::time::Instant::now();
    let path = Path::new(target);

    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }
    let _t_detect = std::time::Instant::now();

    // Detect file type
    tracing::debug!("Detecting file type for: {}", target);
    let file_type = detect_file_type(path)?;
    tracing::debug!("Detected file type: {:?} for: {}", file_type, target);

    // Get file size for memory tracking
    let file_size = std::fs::metadata(path)?.len();

    // Log memory state before processing
    if verbose {
        use cleave::memory_tracker;
        memory_tracker::log_before_file_processing(target, file_size);
    }

    // Read file for mismatch check and payload extraction
    let file_data_wrapper = cleave::file_io::read_file_smart(path)?;
    let file_data = file_data_wrapper.as_slice();

    // Track file read for memory monitoring
    if verbose {
        use cleave::memory_tracker;
        memory_tracker::global_tracker().record_file_read(file_size, target);
    }

    // Check for extension/content mismatch
    let mismatch = analyzers::check_extension_content_mismatch(path, file_data);

    // Extract strings with stng ONCE (don't call I/O-bound functions multiple times)
    // Use these results for both encoded payload extraction AND analyzer string extraction
    tracing::info!("Extracting strings with stng");
    let opts = stng::ExtractOptions::new(4).with_garbage_filter(true); // Filter out garbage strings
                                                                       // NOTE: XOR disabled - causes performance issues on large files
    let t_stng = std::time::Instant::now();
    let stng_strings = stng::extract_strings_with_options(file_data, &opts);
    tracing::info!(
        "stng extraction completed in {:?} ({} strings)",
        t_stng.elapsed(),
        stng_strings.len()
    );

    // Check for encoded payloads (hex, base64, etc.) using the stng results
    let encoded_payloads =
        crate::extractors::encoded_payload::extract_encoded_payloads(&stng_strings);

    // Convert stng strings to StringInfo for reuse by binary analyzers (avoids redundant extraction)
    let string_extractor = crate::strings::StringExtractor::new();
    let preextracted_strings = string_extractor.convert_stng_strings(&stng_strings);

    // Create unified analysis input for analyzers using the new data flow
    let analysis_input =
        AnalysisInput::with_strings(path, file_data, &stng_strings, file_type.clone());

    let _t_analyze = std::time::Instant::now();

    // Route to appropriate analyzer
    // Binary analyzers (MachO, Elf, Pe, Archive, Jar) handle YARA internally with specialized filtering
    // All other analyzers get YARA scanning applied universally after analysis
    let mut report = match file_type {
        FileType::MachO => {
            // Run YARA scan in parallel with structural analysis to get inline results
            let analyzer = analyzers::macho::MachOAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone())
                .with_preextracted_strings(preextracted_strings.clone());
            let range = analyzer.preferred_arch_range(file_data);
            let arch_data = &file_data[range.clone()];
            let is_fat = analyzer.all_arch_ranges(file_data).len() > 1;
            let engine = shared_yara_engine.as_ref();
            let file_types: &[&str] = &["macho", "dylib", "kext"];
            let (struct_result, yara_result) = rayon::join(
                || analyzer.analyze_structural(path, arch_data),
                || {
                    engine
                        .filter(|e| e.is_loaded())
                        .map(|e| e.scan_bytes_with_inline(arch_data, Some(file_types)))
                },
            );
            let mut report = struct_result?;
            // Apply fat binary metadata
            analyzer.apply_fat_metadata(&mut report, file_data);

            // For FAT binaries, re-extract strings from the full file so offsets are file-relative.
            // This ensures offset_range constraints (like [-2200, -100]) work correctly.
            if is_fat && preextracted_strings.is_empty() {
                let string_extractor = crate::strings::StringExtractor::default();
                report.strings = string_extractor.extract_smart(file_data, None);
                // Update string count metric
                if let Some(ref mut metrics) = report.metrics {
                    if let Some(ref mut binary_metrics) = metrics.binary {
                        binary_metrics.string_count = report.strings.len() as u32;
                    }
                }
            }

            // Process YARA results and evaluate with inline YARA
            let inline_yara =
                process_yara_result(&mut report, yara_result, engine.as_ref().map(AsRef::as_ref));
            // For FAT binaries, evaluate against full file since strings have file-relative offsets
            let eval_data = if is_fat { file_data } else { arch_data };
            capability_mapper.evaluate_and_merge_findings(
                &mut report,
                eval_data,
                None,
                Some(&inline_yara),
            );
            report
        }
        FileType::Elf => {
            // Run YARA scan in parallel with structural analysis to get inline results
            let analyzer = analyzers::elf::ElfAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone())
                .with_preextracted_strings(preextracted_strings.clone());
            let engine = shared_yara_engine.as_ref();
            let file_types: &[&str] = &["elf", "so", "ko"];
            let (mut report, yara_result) = rayon::join(
                || analyzer.analyze_structural(path, file_data),
                || {
                    engine
                        .filter(|e| e.is_loaded())
                        .map(|e| e.scan_bytes_with_inline(file_data, Some(file_types)))
                },
            );
            // Process YARA results and evaluate with inline YARA
            let inline_yara =
                process_yara_result(&mut report, yara_result, engine.as_ref().map(AsRef::as_ref));
            capability_mapper.evaluate_and_merge_findings(
                &mut report,
                file_data,
                None,
                Some(&inline_yara),
            );
            crate::path_mapper::analyze_and_link_paths(&mut report);
            crate::env_mapper::analyze_and_link_env_vars(&mut report);
            report
        }
        FileType::Pe => {
            // Run YARA scan in parallel with structural analysis to get inline results
            let mut analyzer = analyzers::pe::PEAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone())
                .with_preextracted_strings(preextracted_strings.clone());
            // PE analyzer needs YARA engine for overlay/embedded payload analysis
            if let Some(engine) = shared_yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            let engine = shared_yara_engine.as_ref();
            let file_types: &[&str] = &["pe", "exe", "dll", "bat", "ps1"];
            let (struct_result, yara_result) = rayon::join(
                || analyzer.analyze_structural(path, file_data),
                || {
                    engine
                        .filter(|e| e.is_loaded())
                        .map(|e| e.scan_bytes_with_inline(file_data, Some(file_types)))
                },
            );
            let mut report = struct_result?;
            // Process YARA results and evaluate with inline YARA
            let inline_yara =
                process_yara_result(&mut report, yara_result, engine.as_ref().map(AsRef::as_ref));
            capability_mapper.evaluate_and_merge_findings(
                &mut report,
                file_data,
                None,
                Some(&inline_yara),
            );
            report
        }
        FileType::JavaClass => {
            let analyzer = analyzers::java_class::JavaClassAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone());
            analyzer.analyze_input(&analysis_input)?
        }
        FileType::Jar => {
            // JAR files are analyzed like archives but with Java-specific handling
            let mut analyzer = analyzers::archive::ArchiveAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone())
                .with_zip_passwords(zip_passwords.to_vec())
                .with_max_memory_file_size(max_memory_file_size);
            if let Some(engine) = shared_yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            if let Some(config) = sample_extraction {
                analyzer = analyzer.with_sample_extraction(config.clone());
            }
            analyzer.analyze(path)?
        }
        FileType::PackageJson => {
            let analyzer = analyzers::package_json::PackageJsonAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone());
            analyzer.analyze_input(&analysis_input)?
        }
        FileType::VsixManifest => {
            let analyzer = analyzers::vsix_manifest::VsixManifestAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone());
            analyzer.analyze_input(&analysis_input)?
        }
        FileType::AppleScript => {
            let analyzer = analyzers::applescript::AppleScriptAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone());
            analyzer.analyze_input(&analysis_input)?
        }
        FileType::Archive => {
            let mut analyzer = analyzers::archive::ArchiveAnalyzer::new()
                .with_capability_mapper_arc(capability_mapper.clone())
                .with_zip_passwords(zip_passwords.to_vec())
                .with_max_memory_file_size(max_memory_file_size);
            if let Some(engine) = shared_yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            if let Some(config) = sample_extraction {
                analyzer = analyzer.with_sample_extraction(config.clone());
            }
            analyzer.analyze(path)?
        }
        // All source code languages use the unified analyzer (or generic fallback)
        // Use analyze_input() for unified data flow - no duplicate file reads or string extraction
        _ => {
            if let Some(analyzer) =
                analyzers::analyzer_for_file_type_arc(&file_type, Some(capability_mapper.clone()))
            {
                analyzer.analyze_input(&analysis_input)?
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
                source: "dissect".to_string(),
                value: format!("expected={}, actual={}", expected, actual),
                location: None,
                ..Default::default()
            }],
            match_count: 1,
            source_file: None,
        });
    }

    // Add findings for encoded payloads
    for payload in encoded_payloads {
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
                source: "dissect".to_string(),
                value: format!(
                    "encoding={}, type={:?}, preview={}",
                    payload.encoding_chain.join(", "),
                    payload.detected_type,
                    payload.preview
                ),
                location: Some(format!("offset:{}", payload.original_offset)),
                ..Default::default()
            }],
            match_count: 1,
            source_file: None,
        });

        // TODO: Recursively analyze decoded payloads
        // This is currently only done in lib.rs::analyze_file_with_mapper
        // Consider refactoring to share this logic between CLI and library paths
    }

    // Run YARA for file types that didn't handle it internally.
    // Binary types (MachO, Elf, Pe) and archives already ran YARA with parallel scanning above.
    let handled_yara_internally = matches!(
        file_type,
        FileType::MachO | FileType::Elf | FileType::Pe | FileType::Archive | FileType::Jar
    );
    if !handled_yara_internally {
        if let Some(engine) = shared_yara_engine {
            if file_type.is_program() && engine.is_loaded() {
                let file_types = file_type.yara_filetypes();
                let filter = if file_types.is_empty() {
                    None
                } else {
                    Some(file_types.as_slice())
                };

                match engine.scan_file_to_findings(path, filter) {
                    Ok((matches, findings)) => {
                        // Add YARA matches to report
                        report.yara_matches = matches;

                        // Add findings that don't already exist
                        let existing: std::collections::HashSet<String> =
                            report.findings.iter().map(|f| f.id.clone()).collect();
                        for finding in findings {
                            if !existing.contains(finding.id.as_str()) {
                                report.findings.push(finding);
                            }
                        }

                        // Mark that we used YARA
                        if !report.metadata.tools_used.contains(&"yara-x".to_string()) {
                            report.metadata.tools_used.push("yara-x".to_string());
                        }
                    }
                    Err(e) => {
                        eprintln!("⚠️  YARA scan failed: {}", e);
                    }
                }
            }
        }
    }

    // Check if report's criticality matches --error-if criteria
    check_criticality_error(&report, error_if_levels)?;

    // Free excess capacity in all Vec fields to reduce memory footprint
    report.shrink_to_fit();

    // Convert to v2 schema (flat files array) and filter based on verbosity
    report.convert_to_v2(verbose);

    // Log memory state after processing
    if verbose {
        use cleave::memory_tracker;
        memory_tracker::log_after_file_processing(target, file_size, _t_start.elapsed());
    }

    // Filter out low-value composite "any" rules before output
    let removed = report.filter_findings(|f| !capability_mapper.is_low_value_any_rule(&f.id));
    if removed > 0 {
        tracing::debug!(
            "Filtered {} low-value composite 'any' rules from {}",
            removed,
            target
        );
    }

    // Note: Component filtering is NOT applied here because this outputs JSONL
    // which is used for ML pipelines. Component traits are kept in JSON for ML signal.
    // Filtering only applies to terminal output in analyze.rs.

    // Output as JSONL format for parallel scanning
    crate::output::format_jsonl(&report)
}

/// Analyze an archive with streaming JSONL output.
///
/// This function uses the streaming archive analyzer to emit results as they
/// become available, rather than waiting for the entire archive to be processed.
#[allow(dead_code)]
pub(crate) fn analyze_archive_streaming_jsonl(
    target: &str,
    capability_mapper: &Arc<crate::capabilities::CapabilityMapper>,
    shared_yara_engine: Option<&Arc<YaraEngine>>,
    zip_passwords: &[String],
    sample_extraction: Option<&types::SampleExtractionConfig>,
    max_memory_file_size: u64,
) -> Result<()> {
    let path = Path::new(target);
    let archive_path = target.to_string();

    let mut analyzer = analyzers::archive::ArchiveAnalyzer::new()
        .with_capability_mapper_arc(capability_mapper.clone())
        .with_zip_passwords(zip_passwords.to_vec())
        .with_max_memory_file_size(max_memory_file_size);

    if let Some(engine) = shared_yara_engine {
        analyzer = analyzer.with_yara_arc(engine.clone());
    }
    if let Some(config) = sample_extraction {
        analyzer = analyzer.with_sample_extraction(config.clone());
    }

    // Use streaming analysis - each file is emitted as a JSONL line via the callback
    // Prefix the archive path to each file's path so consumers can group by archive
    let report = analyzer.analyze_streaming(path, |file_analysis| {
        let mut fa = file_analysis.clone();
        fa.path = types::file_analysis::encode_archive_path(&archive_path, &fa.path);

        // Filter out low-value composite "any" rules before output
        fa.findings
            .retain(|f| !capability_mapper.is_low_value_any_rule(&f.id));

        if let Ok(line) = crate::output::format_jsonl_line(&fa) {
            println!("{}", line);
        }
    })?;

    // After all member files are emitted, emit an archive-level entry
    // This signals archive completion and provides aggregate risk for consumers
    // Format: same as file entries but path has no "!!" (no parent)

    // Get aggregates from summary (computed incrementally during streaming)
    let mut max_risk = report
        .summary
        .as_ref()
        .and_then(|s| s.max_risk)
        .unwrap_or(types::Criticality::Baseline);
    let mut counts = report
        .summary
        .as_ref()
        .map(|s| s.counts.clone())
        .unwrap_or_default();

    // Filter low-value composite "any" rules from archive-level findings
    let mut filtered_findings = report.findings.clone();
    filtered_findings.retain(|f| !capability_mapper.is_low_value_any_rule(&f.id));

    // Include archive-level findings (zip-bomb, path traversal, etc.)
    for finding in &filtered_findings {
        if finding.crit > max_risk {
            max_risk = finding.crit;
        }
        match finding.crit {
            types::Criticality::Hostile => counts.hostile += 1,
            types::Criticality::Suspicious => counts.suspicious += 1,
            types::Criticality::Notable => counts.notable += 1,
            _ => {}
        }
    }

    // Create archive-level FileAnalysis entry
    let archive_entry = types::FileAnalysis {
        id: 0,
        path: archive_path,
        parent_id: None, // No parent - this IS the archive
        depth: 0,
        file_type: report.target.file_type,
        sha256: report.target.sha256,
        size: report.target.size_bytes,
        risk: if max_risk > types::Criticality::Baseline {
            Some(max_risk)
        } else {
            None
        },
        counts: Some(counts),
        encoding: None,
        findings: filtered_findings,
        traits: Vec::new(),
        structure: report.structure,
        functions: Vec::new(),
        strings: Vec::new(),
        sections: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        yara_matches: Vec::new(),
        syscalls: Vec::new(),
        binary_properties: None,
        source_code_metrics: None,
        metrics: None,
        paths: Vec::new(),
        directories: Vec::new(),
        env_vars: Vec::new(),
        extracted_path: None,
        formula: None,
    };

    if let Ok(line) = crate::output::format_jsonl_line(&archive_entry) {
        println!("{}", line);
    }

    Ok(())
}

// ============================================================================
// Report Creation
// ============================================================================

/// Create an analysis report for a file.
///
/// Routes the file to the appropriate analyzer based on file type and
/// returns a comprehensive analysis report.
pub(crate) fn create_analysis_report(
    path: &Path,
    file_type: &FileType,
    binary_data: &[u8],
    capability_mapper: &crate::capabilities::CapabilityMapper,
) -> Result<types::AnalysisReport> {
    use sha2::{Digest, Sha256};

    // Route to appropriate analyzer to get a full report
    let report = if let Some(analyzer) =
        analyzers::analyzer_for_file_type(file_type, Some(capability_mapper.clone()))
    {
        analyzer.analyze(path)?
    } else {
        // Fallback: create minimal report for unsupported types
        let mut hasher = Sha256::new();
        hasher.update(binary_data);
        let sha256 = format!("{:x}", hasher.finalize());

        let target = types::TargetInfo {
            path: path.display().to_string(),
            file_type: format!("{:?}", file_type).to_lowercase(),
            size_bytes: binary_data.len() as u64,
            sha256,
            architectures: None,
        };

        types::AnalysisReport::new(target)
    };

    Ok(report)
}

/// Find similar rule IDs for suggestions.
///
/// Uses substring matching and Levenshtein distance to find rules
/// that are similar to the query string.
pub(crate) fn find_similar_rules(
    mapper: &crate::capabilities::CapabilityMapper,
    query: &str,
) -> Vec<String> {
    let query_lower = query.to_lowercase();
    let mut matches: Vec<(String, usize)> = Vec::new();

    // Check composite rules
    for rule in &mapper.composite_rules {
        let id_lower = rule.id.to_lowercase();
        if id_lower.contains(&query_lower) || query_lower.contains(&id_lower) {
            let score = strsim::levenshtein(&query_lower, &id_lower);
            matches.push((rule.id.clone(), score));
        } else {
            let score = strsim::levenshtein(&query_lower, &id_lower);
            if score < 15 {
                matches.push((rule.id.clone(), score));
            }
        }
    }

    // Check trait definitions
    for trait_def in mapper.trait_definitions() {
        let id_lower = trait_def.id.to_lowercase();
        if id_lower.contains(&query_lower) || query_lower.contains(&id_lower) {
            let score = strsim::levenshtein(&query_lower, &id_lower);
            matches.push((trait_def.id.clone(), score));
        } else {
            let score = strsim::levenshtein(&query_lower, &id_lower);
            if score < 15 {
                matches.push((trait_def.id.clone(), score));
            }
        }
    }

    // Sort by similarity score
    matches.sort_by_key(|(_, score)| *score);
    matches.into_iter().map(|(id, _)| id).collect()
}

/// Find all rules (traits and composites) that are in a given directory prefix.
pub(crate) fn find_rules_in_directory(
    mapper: &crate::capabilities::CapabilityMapper,
    directory: &str,
) -> Vec<String> {
    let prefix = format!("{}/", directory);
    let mut rules = Vec::new();

    // Check trait definitions
    for trait_def in mapper.trait_definitions() {
        if trait_def.id.starts_with(&prefix) {
            rules.push(trait_def.id.clone());
        }
    }

    // Check composite rules
    for rule in &mapper.composite_rules {
        if rule.id.starts_with(&prefix) {
            rules.push(rule.id.clone());
        }
    }

    // Sort alphabetically
    rules.sort();
    rules.dedup();
    rules
}

// ============================================================================
// Type Conversions
// ============================================================================

/// Convert CLI file type enum to internal FileType.
pub(crate) fn cli_file_type_to_internal(ft: crate::cli::DetectFileType) -> FileType {
    match ft {
        crate::cli::DetectFileType::Elf => FileType::Elf,
        crate::cli::DetectFileType::Pe => FileType::Pe,
        crate::cli::DetectFileType::Macho => FileType::MachO,
        crate::cli::DetectFileType::JavaScript => FileType::JavaScript,
        crate::cli::DetectFileType::Python => FileType::Python,
        crate::cli::DetectFileType::Go => FileType::Go,
        crate::cli::DetectFileType::Shell => FileType::Shell,
        crate::cli::DetectFileType::Raw => FileType::Unknown,
    }
}

// ============================================================================
// String Extraction
// ============================================================================

/// Extract strings from a file using AST-based analysis.
///
/// Routes the file to the appropriate analyzer and extracts strings from
/// the parsed AST, filtering by minimum length.
pub(crate) fn extract_strings_from_ast(
    path: &Path,
    file_type: &FileType,
    min_length: usize,
    format: &crate::cli::OutputFormat,
) -> Result<String> {
    // Analyze the file to extract strings via AST using unified analyzer
    let report = if let Some(analyzer) = analyzers::analyzer_for_file_type(file_type, None) {
        analyzer.analyze(path)?
    } else {
        anyhow::bail!("Unsupported file type for AST extraction: {:?}", file_type);
    };

    // Filter strings by min_length
    let filtered_strings: Vec<_> = report
        .strings
        .into_iter()
        .filter(|s| s.value.len() >= min_length)
        .collect();

    match format {
        crate::cli::OutputFormat::Jsonl => Ok(serde_json::to_string_pretty(&filtered_strings)?),
        crate::cli::OutputFormat::Terminal => {
            let mut output = String::new();
            output.push_str(&format!(
                "Extracted {} strings from {} (AST-based)\n\n",
                filtered_strings.len(),
                path.display()
            ));
            output.push_str(&format!(
                "{:<10} {:<14} {:<12} {}\n",
                "OFFSET", "TYPE", "ENCODING", "VALUE"
            ));
            output.push_str(&format!(
                "{:-<10} {:-<14} {:-<12} {:-<20}\n",
                "", "", "", ""
            ));
            for s in filtered_strings {
                let offset = s
                    .offset
                    .map(|o| format!("{:#x}", o))
                    .unwrap_or_else(|| "unknown".to_string());
                let stype_str = format!("{:?}", s.string_type);

                // Format encoding chain like binary strings output
                let encoding_str = if s.encoding_chain.is_empty() {
                    "-".to_string()
                } else {
                    s.encoding_chain.join("+")
                };

                output.push_str(&format!(
                    "{:<10} {:<14} {:<12} {}\n",
                    offset, stype_str, encoding_str, s.value
                ));
            }
            Ok(output)
        }
    }
}

// ============================================================================
// Metrics Utilities
// ============================================================================

/// Flatten a JSON value into a flat list of key-value pairs.
///
/// This is useful for extracting metrics from nested JSON structures
/// and converting them to a format suitable for ML/analysis.
pub(crate) fn flatten_json_to_metrics(
    value: &serde_json::Value,
    prefix: &str,
    result: &mut Vec<(String, serde_json::Value)>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let new_prefix = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", prefix, key)
                };
                flatten_json_to_metrics(val, &new_prefix, result);
            }
        }
        serde_json::Value::Null => {
            // Skip null values
        }
        _ => {
            // Leaf value - add to result
            if !prefix.is_empty() {
                result.push((prefix.to_string(), value.clone()));
            }
        }
    }
}
