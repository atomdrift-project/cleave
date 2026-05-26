//! Metrics extraction command.
//!
//! Extracts all computed metrics from a file, including:
//! - Binary metrics (entropy, section sizes, import/export counts)
//! - Source code metrics (lines of code, cyclomatic complexity, etc.)
//! - Structural metrics (function counts, string statistics)
//! - Supports layer filtering (e.g., --layer upx@0 for UPX-unpacked content)

use crate::analyzers::{self, FileType, detect_file_type};
use crate::cli;
use crate::commands::extract::{analyze_binary_report, extract_layer_file_analysis};
use anyhow::Result;
use std::path::Path;

/// Extract computed metrics from a target, optionally from a named analysis layer.
pub fn run(
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

    let metrics = file_analysis.filefacts_metrics.clone().ok_or_else(|| {
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

    // Layer binary_extractors metric writes (e.g. .comment counts,
    // stripped-section inventory) so the metrics command sees the
    // same fields as a full `cleave analyze` run.
    let data = std::fs::read(path)?;
    let mut full_report = report.clone();
    if matches!(file_type, FileType::Elf | FileType::Pe | FileType::MachO) {
        crate::analyzers::binary_extractors::augment_report(&mut full_report, &data);
    }
    let metrics = full_report.filefacts_metrics.clone().unwrap_or_default();

    format_metrics_output(&metrics, target, &file_type, format)
}

/// Human-readable section label for a metric field prefix.
fn section_label(prefix: &str) -> &str {
    match prefix {
        "binary" => "BINARY",
        "pe" => "PE",
        "macho" => "MACHO",
        "elf" => "ELF",
        "consistency" => "CONSISTENCY",
        "text" => "TEXT",
        "identifiers" => "IDENTIFIERS",
        "strings" => "STRINGS",
        "comments" => "COMMENTS",
        "functions" => "FUNCTIONS",
        "statements" => "STATEMENTS",
        "imports" => "IMPORTS",
        "encoded" => "ENCODED",
        "python" => "PYTHON",
        "javascript" => "JAVASCRIPT",
        "powershell" => "POWERSHELL",
        "shell" => "SHELL",
        "php" => "PHP",
        "ruby" => "RUBY",
        "perl" => "PERL",
        "go_metrics" => "GO",
        "rust_metrics" => "RUST",
        "c_metrics" => "C",
        "java" => "JAVA",
        "java_class" => "JAVA CLASS",
        "lua" => "LUA",
        "csharp" => "C#",
        "archive" => "ARCHIVE",
        "package_json" => "PACKAGE JSON",
        "chm" => "CHM",
        "image" => "IMAGE",
        "png" => "PNG",
        "jpeg" => "JPEG",
        "lnk" => "LNK",
        "office" => "OFFICE",
        "obfuscation" => "OBFUSCATION",
        "packing" => "PACKING",
        "supply_chain" => "SUPPLY CHAIN",
        _ => prefix,
    }
}

fn format_metric_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Number(n) => {
            if let Some(f) = n.as_f64() {
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
    }
}

/// Format metrics output for display
fn format_metrics_output(
    metrics: &std::collections::BTreeMap<String, f64>,
    target: &str,
    file_type: &FileType,
    format: &cli::OutputFormat,
) -> Result<String> {
    match format {
        cli::OutputFormat::Json | cli::OutputFormat::Jsonl => {
            Ok(serde_json::to_string_pretty(&metrics)?)
        }
        cli::OutputFormat::Terminal | cli::OutputFormat::Tiny => {
            use colored::Colorize;
            use std::collections::BTreeMap;

            let descriptions = cleave::types::field_paths::all_metric_descriptions();
            let term_width = terminal_size::terminal_size()
                .map(|(w, _)| w.0 as usize)
                .unwrap_or(100);

            // Flat-map → sorted (path, formatted_value) pairs.
            let mut groups: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
            for (path, value) in metrics {
                let prefix = path.split('.').next().unwrap_or("").to_string();
                groups.entry(prefix).or_default().push((
                    path.clone(),
                    format_metric_value(&serde_json::Value::from(*value)),
                ));
            }

            // File header + rule — matches analyze style.
            let file_type_str = format!("{:?}", file_type).to_uppercase();
            let header = format!("{}  {}", target, file_type_str);
            let rule: String = cleave::theme::RULE_CHAR.to_string().repeat(term_width);
            let mut output = String::new();
            output.push_str(&header);
            output.push('\n');
            output.push_str(&cleave::theme::paint_rule(rule).to_string());
            output.push('\n');

            for (prefix, fields) in &groups {
                // Section pill — dark gray, bold white, same style as analyze metadata pill.
                let label = section_label(prefix);
                let pill = format!(" {} ", label)
                    .bold()
                    .white()
                    .on_truecolor(48, 48, 48);
                output.push('\n');
                output.push_str(&pill.to_string());
                output.push('\n');

                // Column widths for this section.
                let path_w = fields.iter().map(|(p, _)| p.len()).max().unwrap_or(0);
                let val_w = fields.iter().map(|(_, v)| v.len()).max().unwrap_or(0);
                // Description gets whatever remains after indent(2) + path + gap(2) + value + gap(2)
                let overhead = 2 + path_w + 2 + val_w + 2;
                let desc_w = term_width.saturating_sub(overhead);

                for (path, val) in fields {
                    let desc = descriptions.get(path.as_str()).copied().unwrap_or("");

                    // Color booleans: true → azure, false → dimmed.
                    let colored_val = match val.as_str() {
                        "true" => cleave::theme::paint_notable(val).to_string(),
                        "false" => val.dimmed().to_string(),
                        _ => val.clone(),
                    };

                    let truncated_desc = if desc.len() > desc_w && desc_w > 1 {
                        // Find the last char boundary that fits within desc_w bytes.
                        let mut end = desc_w.saturating_sub(1);
                        while !desc.is_char_boundary(end) && end > 0 {
                            end -= 1;
                        }
                        format!("{}…", &desc[..end])
                    } else {
                        desc.to_string()
                    };
                    let colored_desc = truncated_desc.dimmed();

                    output.push_str(&format!(
                        "  {:<path_w$}  {:<val_w$}  {}\n",
                        path,
                        colored_val,
                        colored_desc,
                        path_w = path_w,
                        val_w = val_w,
                    ));
                }
            }

            let violations = cleave::types::field_paths::metric_description_violations();
            if !violations.is_empty() {
                output.push('\n');
                let warn_header = format!(
                    " ⚠  {} description(s) outside 25–60 char target ",
                    violations.len()
                );
                output.push_str(
                    &warn_header
                        .bold()
                        .black()
                        .on_truecolor(180, 120, 0)
                        .to_string(),
                );
                output.push('\n');
                for (path, len, first) in &violations {
                    let row = format!("  {path}  ({len} chars)  \"{first}\"");
                    output.push_str(&row.dimmed().to_string());
                    output.push('\n');
                }
            }

            Ok(output)
        }
    }
}
