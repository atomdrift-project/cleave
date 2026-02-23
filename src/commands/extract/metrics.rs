//! Metrics extraction command.
//!
//! Extracts all computed metrics from a file, including:
//! - Binary metrics (entropy, section sizes, import/export counts)
//! - Source code metrics (lines of code, cyclomatic complexity, etc.)
//! - Structural metrics (function counts, string statistics)

use crate::analyzers::{
    self, detect_file_type, elf::ElfAnalyzer, macho::MachOAnalyzer, pe::PEAnalyzer, Analyzer,
    FileType,
};
use crate::cli;
use crate::commands::shared::flatten_json_to_metrics;
use anyhow::Result;
use std::path::Path;

pub(crate) fn run(
    target: &str,
    format: &cli::OutputFormat,
    _disabled: &cli::DisabledComponents,
) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    // Detect file type
    let file_type = detect_file_type(path)?;

    // Create capability mapper (needed for analysis)
    let capability_mapper = crate::capabilities::CapabilityMapper::empty();

    // Analyze the file to compute metrics
    // Note: For metrics extraction, we use the empty capability mapper and rely on the
    // analyzers to compute metrics. Radare2 analysis can be slow, but it's controlled
    // by the --disable flag (already in disabled)
    let report = match file_type {
        FileType::Elf => ElfAnalyzer::new()
            .with_capability_mapper(capability_mapper)
            .analyze(path)?,
        FileType::MachO => MachOAnalyzer::new()
            .with_capability_mapper(capability_mapper)
            .analyze(path)?,
        FileType::Pe => PEAnalyzer::new()
            .with_capability_mapper(capability_mapper)
            .analyze(path)?,
        _ => {
            // Use the generic analyzer for source code
            if let Some(analyzer) = analyzers::analyzer_for_file_type(&file_type, None) {
                analyzer.analyze(path)?
            } else {
                anyhow::bail!(
                    "Unsupported file type for metrics extraction: {:?}",
                    file_type
                );
            }
        }
    };

    // Extract metrics from report and update binary metrics with report data
    let mut metrics = report.metrics.clone().ok_or_else(|| {
        anyhow::anyhow!("No metrics computed for file (file type may not support metrics)")
    })?;

    // Update binary metrics with counts from the report (these aren't populated by radare2)
    if let Some(ref mut binary) = metrics.binary {
        binary.import_count = report.imports.len() as u32;
        binary.export_count = report.exports.len() as u32;
        binary.string_count = report.strings.len() as u32;

        // Calculate string metrics
        if !report.strings.is_empty() {
            use crate::entropy::calculate_entropy;
            let entropies: Vec<f64> = report
                .strings
                .iter()
                .map(|s| calculate_entropy(s.value.as_bytes()))
                .collect();

            let total_entropy: f64 = entropies.iter().sum();
            binary.avg_string_entropy = (total_entropy / entropies.len() as f64) as f32;
            binary.high_entropy_strings = entropies.iter().filter(|&&e| e > 6.0).count() as u32;

            // Calculate string length metrics
            let mut total_length: u64 = 0;
            let mut max_length: u32 = 0;
            let mut wide_count: u32 = 0;

            for s in &report.strings {
                let len = s.value.len() as u32;
                total_length += len as u64;
                if len > max_length {
                    max_length = len;
                }
                // Check encoding chain for wide strings
                if s.encoding_chain.iter().any(|e| e == "wide") {
                    wide_count += 1;
                }
            }

            binary.avg_string_length = total_length as f32 / report.strings.len() as f32;
            binary.max_string_length = max_length;
            binary.wide_string_count = wide_count;
        }

        // Calculate binary entropy from sections if not already populated
        if binary.overall_entropy == 0.0 && !report.sections.is_empty() {
            use crate::entropy::calculate_entropy;

            let mut entropies = Vec::new();
            let mut code_entropies = Vec::new();
            let mut data_entropies = Vec::new();

            for section in &report.sections {
                let entropy = section.entropy as f32;
                entropies.push(entropy);

                // Track code vs data section entropy
                let name_lower = section.name.to_lowercase();
                let is_executable = section
                    .permissions
                    .as_ref()
                    .map(|p| p.contains('x'))
                    .unwrap_or(false);

                if name_lower.contains("text") || name_lower.contains("code") || is_executable {
                    code_entropies.push(entropy);
                } else if name_lower.contains("data") || name_lower.contains("rodata") {
                    data_entropies.push(entropy);
                }

                if entropy > 7.5 {
                    binary.high_entropy_regions += 1;
                }
            }

            if !entropies.is_empty() {
                binary.overall_entropy = entropies.iter().sum::<f32>() / entropies.len() as f32;

                let mean = binary.overall_entropy;
                let variance: f32 = entropies.iter().map(|e| (e - mean).powi(2)).sum::<f32>()
                    / entropies.len() as f32;
                binary.entropy_variance = variance.sqrt();
            }

            if !code_entropies.is_empty() {
                binary.code_entropy =
                    code_entropies.iter().sum::<f32>() / code_entropies.len() as f32;
            }

            if !data_entropies.is_empty() {
                binary.data_entropy =
                    data_entropies.iter().sum::<f32>() / data_entropies.len() as f32;
            }

            // If still zero, calculate from raw file data as fallback
            if binary.overall_entropy == 0.0 {
                let data = std::fs::read(path)?;
                binary.overall_entropy = calculate_entropy(&data) as f32;
            }
        }

        // Calculate size and section metrics if not already populated
        if binary.file_size == 0 {
            if let Ok(metadata) = std::fs::metadata(path) {
                binary.file_size = metadata.len();
            }
        }

        if binary.code_size == 0 && !report.sections.is_empty() {
            let mut code_size: u64 = 0;
            let mut total_size: u64 = 0;

            for section in &report.sections {
                total_size += section.size;
                if let Some(ref perm) = section.permissions {
                    if perm.contains('x') {
                        code_size += section.size;
                    }
                }
            }

            binary.code_size = code_size;
            if total_size > 0 {
                let data_size = total_size.saturating_sub(code_size);
                if data_size > 0 {
                    binary.code_to_data_ratio = code_size as f32 / data_size as f32;
                }
            }

            // Average section size
            if !report.sections.is_empty() {
                binary.avg_section_size = total_size as f32 / report.sections.len() as f32;
            }
        }
    }

    // Format output
    match format {
        cli::OutputFormat::Jsonl => {
            // JSON output - just serialize the metrics
            Ok(serde_json::to_string_pretty(&metrics)?)
        }
        cli::OutputFormat::Terminal => {
            // Convert metrics to JSON value, then flatten to get all field paths
            let json_value = serde_json::to_value(&metrics)?;
            let mut flattened = Vec::new();
            flatten_json_to_metrics(&json_value, "", &mut flattened);

            // Sort by field path
            flattened.sort_by(|a, b| a.0.cmp(&b.0));

            let mut output = String::new();
            output.push_str(&format!("Metrics for: {}\n", target));
            output.push_str(&format!("File type: {:?}\n\n", file_type));
            output.push_str("# Field paths for use in rules (type: metrics, field: <path>)\n\n");

            // Print all metrics in sorted order
            for (path, value) in flattened {
                // Format value based on type
                let formatted_value = match value {
                    serde_json::Value::Number(n) => {
                        if let Some(f) = n.as_f64() {
                            // Format floats with appropriate precision
                            if f.fract() == 0.0 {
                                format!("{}", f as i64)
                            } else if f.abs() < 100.0 {
                                format!("{:.2}", f)
                            } else {
                                format!("{:.1}", f)
                            }
                        } else {
                            n.to_string()
                        }
                    }
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => value.to_string(),
                };

                output.push_str(&format!("{}: {}\n", path, formatted_value));
            }

            Ok(output)
        }
    }
}
