//! Section extraction command.
//!
//! Extracts section information from binary files (ELF, PE, Mach-O).
//! Provides section names, addresses, sizes, entropy, and permissions.
//! Supports layer filtering (e.g., --layer upx@0 for UPX-unpacked content).

use crate::analyzers::{detect_file_type, FileType};
use crate::cli;
use crate::commands::extract::{analyze_binary_report, extract_layer_file_analysis};
use crate::commands::shared::SectionInfo;
use anyhow::Result;
use std::path::Path;

pub(crate) fn run(target: &str, layer: Option<&str>, format: &cli::OutputFormat) -> Result<String> {
    // If a layer is specified, we need to run full analysis to get that layer's data
    if let Some(layer_name) = layer {
        return run_with_layer(target, layer_name, format);
    }
    run_direct(target, format)
}

/// Run section extraction with layer filtering (requires full analysis)
fn run_with_layer(target: &str, layer: &str, format: &cli::OutputFormat) -> Result<String> {
    let file_analysis = extract_layer_file_analysis(target, layer)?;

    // Convert FileAnalysis sections to SectionInfo
    let sections: Vec<SectionInfo> = file_analysis
        .sections
        .iter()
        .map(|s| SectionInfo {
            name: s.name.clone(),
            address: s.address.map(|addr| format!("0x{:x}", addr)),
            size: s.size,
            entropy: s.entropy,
            permissions: s.permissions.clone(),
        })
        .collect();

    format_sections_output(&sections, target, format)
}

/// Direct section extraction without layer filtering (fast path)
fn run_direct(target: &str, format: &cli::OutputFormat) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    let mut sections: Vec<SectionInfo> = Vec::new();

    // Detect file type
    if let Ok(file_type) = detect_file_type(path) {
        match file_type {
            FileType::Elf | FileType::MachO | FileType::Pe => {
                // Binary file - extract sections with addresses
                let report = analyze_binary_report(path, &file_type)?;

                // Convert sections to output format
                for section in report.sections {
                    sections.push(SectionInfo {
                        name: section.name,
                        address: section.address.map(|addr| format!("0x{:x}", addr)),
                        size: section.size,
                        entropy: section.entropy,
                        permissions: section.permissions,
                    });
                }
            }
            _ => {
                anyhow::bail!(
                    "Unsupported file type for section extraction: {:?}. Only ELF, PE, and Mach-O binaries are supported.",
                    file_type
                );
            }
        }
    } else {
        anyhow::bail!("Unable to detect file type for: {}", target);
    }

    format_sections_output(&sections, target, format)
}

/// Format sections output for display
fn format_sections_output(
    sections: &[SectionInfo],
    target: &str,
    format: &cli::OutputFormat,
) -> Result<String> {
    // Sort sections by address (if available), then by name
    let mut sections: Vec<_> = sections.to_vec();
    sections.sort_by(|a, b| {
        match (&a.address, &b.address) {
            (Some(addr_a), Some(addr_b)) => {
                // Parse hex addresses for proper numeric sorting
                let parse_addr =
                    |s: &str| -> u64 { s.trim_start_matches("0x").parse::<u64>().unwrap_or(0) };
                let num_a = parse_addr(addr_a);
                let num_b = parse_addr(addr_b);
                num_a.cmp(&num_b)
            }
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.name.cmp(&b.name),
        }
    });

    // Format output
    match format {
        cli::OutputFormat::Json | cli::OutputFormat::Jsonl => {
            Ok(serde_json::to_string_pretty(&sections)?)
        }
        cli::OutputFormat::Terminal | cli::OutputFormat::Tiny => {
            let mut output = String::new();
            output.push_str(&format!(
                "Extracted {} sections from {}\n\n",
                sections.len(),
                target
            ));
            output.push_str(&format!(
                "{:<18} {:<30} {:<12} {:<10} {}\n",
                "ADDRESS", "NAME", "SIZE", "ENTROPY", "PERMISSIONS"
            ));
            output.push_str(&format!(
                "{:-<18} {:-<30} {:-<12} {:-<10} {:-<15}\n",
                "", "", "", "", ""
            ));

            for section in &sections {
                let addr = section.address.as_deref().unwrap_or("-");
                let perms = section.permissions.as_deref().unwrap_or("-");
                output.push_str(&format!(
                    "{:<18} {:<30} {:<12} {:<10.2} {}\n",
                    addr, section.name, section.size, section.entropy, perms
                ));
            }

            Ok(output)
        }
    }
}
