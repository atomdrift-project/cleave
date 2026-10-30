//! Shared utilities for command implementations.
//!
//! This module contains common data structures, helper functions, and utilities
//! used across multiple command implementations in the DISSECT CLI.
//!
//! # Contents
//!
//! - **Data Structures**: Common types like `SectionInfo` and `SymbolInfo`
//! - **Input Handling**: Functions for reading and expanding paths from stdin
//! - **Analysis Helpers**: Report creation and development-engine setup
//! - **Utility Functions**: Type conversions, string extraction, and metric flattening

use crate::analyzers::{self, FileType, FileTypeExt};
use crate::types;
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

/// Read paths from stdin, one per line, skipping empty lines and comments
/// (lines starting with `#`).
///
/// File names are attacker-controlled, so a line that is not UTF-8 is logged
/// and skipped; it never ends the list. Only a line ending (`\n` or `\r\n`)
/// is stripped: leading and trailing spaces are part of a file name.
pub(crate) fn read_paths_from_stdin() -> Vec<String> {
    paths_from_lines(std::io::stdin().lock())
}

fn paths_from_lines(reader: impl BufRead) -> Vec<String> {
    let mut paths = Vec::new();
    for line in reader.split(b'\n') {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                tracing::error!(error = %e, "failed to read paths from stdin");
                break;
            }
        };
        let line = line.strip_suffix(b"\r").unwrap_or(&line);
        match std::str::from_utf8(line) {
            Ok(path) if path.is_empty() || path.starts_with('#') => {}
            Ok(path) => paths.push(path.to_string()),
            Err(_) => tracing::warn!(
                path = %String::from_utf8_lossy(line).escape_debug(),
                "skipping non-UTF-8 path from stdin"
            ),
        }
    }
    paths
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
                if *format != crate::cli::OutputFormat::Json {
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
// Report Creation
// ============================================================================

/// The engine a dev command analyzes under: `rules`, with the default settings
/// less what `--disable` turned off.
pub(crate) fn dev_engine(
    rules: crate::capabilities::CapabilityMapper,
    disabled: &crate::cli::DisabledComponents,
) -> crate::Engine {
    let engine = crate::Engine::from_rules(std::sync::Arc::new(rules));
    let settings = crate::engine::Settings {
        upx: !disabled.upx,
        rizin: !disabled.rizin,
        ..engine.settings().clone()
    };
    engine.with_settings(settings)
}

/// Create an analysis report for a file.
///
/// Routes the file to the appropriate analyzer based on file type and
/// returns a comprehensive analysis report.
pub(crate) fn create_analysis_report(
    path: &Path,
    file_type: &FileType,
    binary_data: &[u8],
    engine: &crate::Engine,
) -> Result<types::AnalysisReport> {
    use sha2::{Digest, Sha256};

    // Route to appropriate analyzer to get a full report. Analyze the bytes
    // given, as `file_type`, the way the scan does: `Analyzer::analyze(path)`
    // re-reads the file from disk and re-detects its type, so a caller that
    // normalized the bytes (UTF-16 text -> UTF-8) or asked for another type
    // got a report built from neither, and its findings disagreed with the
    // ones evaluated beside it on the bytes it passed.
    let report = if let Some(analyzer) = analyzers::analyzer_for_file_type_arc(file_type, engine) {
        let ctx = crate::analysis_context::AnalysisContext::open(path, binary_data);
        let strings = ctx.text_rows();
        let input = analyzers::AnalysisInput::with_strings(path, binary_data, &strings, *file_type)
            .with_parsed_ctx(ctx);
        analyzer.analyze_input(&input)?
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
        crate::cli::OutputFormat::Json => Ok(serde_json::to_string_pretty(&filtered_strings)?),
        crate::cli::OutputFormat::Annotate | crate::cli::OutputFormat::Toc => {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_non_utf8_path_does_not_end_the_list() {
        let input: &[u8] = b"a.bin\r\n\xff\xfe.bin\n\n# note\n b c \nlast";
        assert_eq!(paths_from_lines(input), ["a.bin", " b c ", "last"]);
    }

    /// The report is built from the bytes the caller passes, not re-read from
    /// disk: `test-rules` passes UTF-16 text already normalized to UTF-8, and
    /// a report built from the raw file carried findings the scan never makes.
    #[test]
    fn create_analysis_report_analyzes_the_given_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let traits = dir.path().join("traits.yaml");
        std::fs::write(
            &traits,
            r#"
defaults:
  for: [python]
traits:
  - id: "test/report::on-disk"
    desc: "Marker only in the file on disk"
    crit: notable
    if:
      type: text
      substr: "ON_DISK_MARKER"
  - id: "test/report::given"
    desc: "Marker only in the bytes passed in"
    crit: notable
    if:
      type: text
      substr: "GIVEN_MARKER"
"#,
        )
        .unwrap();
        let mapper = crate::capabilities::CapabilityMapper::from_yaml(&traits).unwrap();
        let engine = crate::Engine::from_rules(std::sync::Arc::new(mapper));

        let script = dir.path().join("sample.py");
        std::fs::write(&script, "x = 'ON_DISK_MARKER'\n").unwrap();
        let report =
            create_analysis_report(&script, &FileType::Python, b"x = 'GIVEN_MARKER'\n", &engine)
                .unwrap();

        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"test/report::given"), "{ids:?}");
        assert!(!ids.contains(&"test/report::on-disk"), "{ids:?}");
    }
}
