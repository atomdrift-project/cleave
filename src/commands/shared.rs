//! Shared utilities for command implementations.
//!
//! This module contains common data structures, helper functions, and utilities
//! used across multiple command implementations in the DISSECT CLI.
//!
//! # Contents
//!
//! - **Data Structures**: Common types like `SectionInfo` and `SymbolInfo`
//! - **Input Handling**: Functions for reading and expanding paths from stdin
//! - **Analysis Helpers**: YARA processing and report creation
//! - **Utility Functions**: Type conversions, string extraction, and metric flattening

use crate::analyzers::{self, FileType, FileTypeExt};
use crate::types;
use crate::yara_engine::YaraEngine;
use anyhow::Result;
use serde::Serialize;
use std::io::BufRead;
use std::path::Path;

// ============================================================================
// Data Structures
// ============================================================================

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SectionInfo {
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) offset: Option<String>,
    pub(crate) size: u64,
    pub(crate) entropy: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) permissions: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct SymbolInfo {
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) library: Option<String>,
    pub(crate) symbol_type: String,
    /// For forwarded PE exports, the `DLL.symbol` target the loader follows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) forward_to: Option<String>,
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
#[must_use]
pub fn expand_paths(paths: Vec<String>, format: &crate::cli::OutputFormat) -> Vec<String> {
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
        });
    }
    if !report.metadata.tools_used.contains(&"yara-x".to_string()) {
        report.metadata.tools_used.push("yara-x".to_string());
    }
    inline
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
    for rule in mapper.composite_rules() {
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
    for rule in mapper.composite_rules() {
        if rule.id.starts_with(&prefix) {
            rules.push(rule.id.clone());
        }
    }

    // Sort alphabetically
    rules.sort_unstable();
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
        crate::cli::DetectFileType::Jcl => FileType::Jcl,
        crate::cli::DetectFileType::Makefile => FileType::Makefile,
        crate::cli::DetectFileType::SystemdService => FileType::SystemdService,
        crate::cli::DetectFileType::DesktopEntry => FileType::DesktopEntry,
        crate::cli::DetectFileType::Xml => FileType::Xml,
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
        crate::cli::OutputFormat::Json | crate::cli::OutputFormat::Jsonl => {
            Ok(serde_json::to_string_pretty(&filtered_strings)?)
        }
        crate::cli::OutputFormat::Terminal | crate::cli::OutputFormat::Tiny => {
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
