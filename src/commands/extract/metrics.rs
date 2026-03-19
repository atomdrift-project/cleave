//! Metrics extraction command.
//!
//! Extracts all computed metrics from a file, including:
//! - Binary metrics (entropy, section sizes, import/export counts)
//! - Source code metrics (lines of code, cyclomatic complexity, etc.)
//! - Structural metrics (function counts, string statistics)
//! - Supports layer filtering (e.g., --layer upx@0 for UPX-unpacked content)

use crate::analyzers::{self, detect_file_type, FileType};
use crate::cli;
use crate::commands::extract::{analyze_binary_report, extract_layer_file_analysis};
use crate::commands::shared::flatten_json_to_metrics;
use anyhow::Result;
use std::path::Path;

pub(crate) fn run(
    target: &str,
    layer: Option<&str>,
    format: &cli::OutputFormat,
    _disabled: &cli::DisabledComponents,
) -> Result<String> {
    // If a layer is specified, we need to run full analysis to get that layer's data
    if let Some(layer_name) = layer {
        return run_with_layer(target, layer_name, format);
    }
    run_direct(target, format)
}

/// Run metrics extraction with layer filtering (requires full analysis)
fn run_with_layer(target: &str, layer: &str, format: &cli::OutputFormat) -> Result<String> {
    let file_analysis = extract_layer_file_analysis(target, layer)?;
    let file_type = detect_file_type(Path::new(target))?;

    // Extract metrics from the layer's FileAnalysis
    let metrics = file_analysis.metrics.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "No metrics available for layer '{}' (layer may not support metrics)",
            layer
        )
    })?;

    format_metrics_output(&metrics, target, &file_type, format)
}

/// Direct metrics extraction without layer filtering (fast path)
fn run_direct(target: &str, format: &cli::OutputFormat) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    // Detect file type
    let file_type = detect_file_type(path)?;

    // Analyze the file to compute metrics
    // Note: For metrics extraction, we use the empty capability mapper and rely on the
    // analyzers to compute metrics. Radare2 analysis can be slow, but it's controlled
    // by the --disable flag (already in disabled)
    let report = match file_type {
        FileType::Elf | FileType::MachO | FileType::Pe => analyze_binary_report(path, &file_type)?,
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

    // Refine metrics using common utility (this ensures metrics cmd and JSON report are consistent)
    let data = std::fs::read(path)?;
    let mut full_report = report.clone();
    crate::analyzers::metrics_utils::populate_binary_metrics(&mut full_report, &data);

    // Update our metrics object with the refined one
    if let Some(refined_metrics) = full_report.metrics {
        metrics = refined_metrics;
    }

    format_metrics_output(&metrics, target, &file_type, format)
}

/// Format metrics output for display
fn format_metrics_output(
    metrics: &crate::types::Metrics,
    target: &str,
    file_type: &FileType,
    format: &cli::OutputFormat,
) -> Result<String> {
    match format {
        cli::OutputFormat::Json | cli::OutputFormat::Jsonl => {
            Ok(serde_json::to_string_pretty(&metrics)?)
        }
        cli::OutputFormat::Terminal | cli::OutputFormat::Tiny => {
            // Convert metrics to JSON value, then flatten to get all field paths
            let json_value = serde_json::to_value(metrics)?;
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
