//! Shared utilities for metric calculation across all analyzers.
//!
//! This module provides a unified way to compute and populate metrics
//! that are common across different file formats, ensuring consistency
//! between the `analyze` command (JSON output) and the `metrics` command.

use crate::entropy::calculate_entropy;
use crate::types::{AnalysisReport, Metrics};

/// Populate and refine binary metrics for a report.
///
/// This function calculates metrics that may not be fully populated by
/// the format-specific analyzers or the radare2 extractor, including:
/// - String metrics (entropy, lengths, counts)
/// - Overall binary entropy and variance
/// - Code-to-data ratios (if not already set)
/// - Section-based metrics
///
/// It should be called after format-specific analysis is complete but
/// before the report is returned to ensure all metrics are present in the JSON.
pub(crate) fn populate_binary_metrics(report: &mut AnalysisReport, data: &[u8]) {
    let file_type = report.target.file_type.clone();

    // If metrics container doesn't exist, create it
    if report.metrics.is_none() {
        report.metrics = Some(Metrics::default());
    }

    let metrics = report.metrics.as_mut().unwrap();

    // Ensure binary metrics section exists
    if metrics.binary.is_none() {
        metrics.binary = Some(Default::default());
    }

    let binary = metrics.binary.as_mut().unwrap();

    // Update basic counts from the report (only if not already set or if report has more data)
    binary.import_count = report.imports.len() as u32;
    binary.export_count = report.exports.len() as u32;
    binary.string_count = report.strings.len() as u32;
    binary.section_count = report.sections.len() as u32;

    // Count exports sharing an address (simple RVA check, only if not already set by analyzer)
    if binary.aliased_exports == 0 && report.exports.len() >= 2 {
        let mut addr_counts = std::collections::HashMap::new();
        for exp in &report.exports {
            if let Some(ref offset) = exp.offset {
                *addr_counts.entry(offset.as_str()).or_insert(0u32) += 1;
            }
        }
        binary.aliased_exports = addr_counts.values().filter(|&&c| c > 1).map(|c| *c).sum();
    }

    if binary.file_size == 0 {
        binary.file_size = data.len() as u64;
    }

    // Calculate string metrics
    if !report.strings.is_empty() {
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

    // Calculate binary entropy from sections
    if !report.sections.is_empty() {
        let mut entropies = Vec::new();
        let mut code_entropies = Vec::new();
        let mut data_entropies = Vec::new();

        for section in &report.sections {
            let entropy = section.entropy as f32;
            entropies.push(entropy);

            // Track code vs data section entropy
            let name_lower = section.name.to_lowercase();

            // Extract section name (e.g., "__text" from "__TEXT.____text")
            let section_name = section.name.rsplit('.').next().unwrap_or(&section.name);
            let section_name_clean = section_name.trim_start_matches("__");

            let is_exec_perm = section
                .permissions
                .as_ref()
                .map(|p| p.contains('x'))
                .unwrap_or(false);

            let is_exec = if file_type == "macho" {
                // In Mach-O, only specific sections contain code
                matches!(section_name_clean, "text" | "stubs" | "stub_helper") && is_exec_perm
            } else if file_type == "pe" {
                // In PE, sections with executable characteristic bit set (0x20000000)
                if let Some(ref perm) = section.permissions {
                    if let Ok(flags) = u32::from_str_radix(perm, 16) {
                        (flags & 0x20000000) != 0
                    } else {
                        is_exec_perm
                    }
                } else {
                    is_exec_perm
                }
            } else if file_type == "elf" {
                // In ELF, sections with SHF_EXECINSTR (0x4)
                if let Some(ref perm) = section.permissions {
                    if let Ok(flags) = u32::from_str_radix(perm, 16) {
                        (flags & 0x4) != 0
                    } else {
                        is_exec_perm
                    }
                } else {
                    is_exec_perm
                }
            } else {
                is_exec_perm || name_lower.contains("text") || name_lower.contains("code")
            };

            if is_exec {
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
            let variance: f32 =
                entropies.iter().map(|e| (e - mean).powi(2)).sum::<f32>() / entropies.len() as f32;
            binary.entropy_variance = variance.sqrt();
        }

        if !code_entropies.is_empty() {
            binary.code_entropy = code_entropies.iter().sum::<f32>() / code_entropies.len() as f32;
        }

        if !data_entropies.is_empty() {
            binary.data_entropy = data_entropies.iter().sum::<f32>() / data_entropies.len() as f32;
        }
    }

    // Fallback overall entropy from raw data if still zero
    if binary.overall_entropy == 0.0 && !data.is_empty() {
        binary.overall_entropy = calculate_entropy(data) as f32;
    }

    // Calculate code_size and ratios
    if !report.sections.is_empty() {
        let mut code_size: u64 = 0;
        let mut total_size: u64 = 0;
        let mut max_section_size: u64 = 0;

        for section in &report.sections {
            total_size += section.size;
            if section.size > max_section_size {
                max_section_size = section.size;
            }

            // Reuse logic from entropy section
            let section_name = section.name.rsplit('.').next().unwrap_or(&section.name);
            let section_name_clean = section_name.trim_start_matches("__");
            let is_exec_perm = section
                .permissions
                .as_ref()
                .map(|p| p.contains('x'))
                .unwrap_or(false);

            let is_exec = if file_type == "macho" {
                matches!(section_name_clean, "text" | "stubs" | "stub_helper") && is_exec_perm
            } else if file_type == "pe" {
                if let Some(ref perm) = section.permissions {
                    u32::from_str_radix(perm, 16)
                        .map(|f| (f & 0x20000000) != 0)
                        .unwrap_or(is_exec_perm)
                } else {
                    is_exec_perm
                }
            } else if file_type == "elf" {
                if let Some(ref perm) = section.permissions {
                    u32::from_str_radix(perm, 16)
                        .map(|f| (f & 0x4) != 0)
                        .unwrap_or(is_exec_perm)
                } else {
                    is_exec_perm
                }
            } else {
                is_exec_perm
            };

            if is_exec {
                code_size += section.size;
            }
        }

        binary.code_size = code_size;
        if total_size > 0 {
            let data_size = total_size.saturating_sub(code_size);
            if data_size > 0 {
                binary.code_to_data_ratio = code_size as f32 / data_size as f32;
            }
        }

        binary.avg_section_size = total_size as f32 / report.sections.len() as f32;
        if binary.file_size > 0 {
            binary.largest_section_ratio = max_section_size as f32 / binary.file_size as f32;
        }
    }

    // Calculate function-related metrics from report data
    if !report.functions.is_empty() {
        let total_size: u64 = report.functions.iter().map(|f| f.size.unwrap_or(0)).sum();
        if total_size > 0 {
            binary.avg_function_size = total_size as f32 / report.functions.len() as f32;
        }

        // Count high complexity functions (threshold: 50+ matches BinaryMetrics definition)
        binary.high_complexity_functions = report
            .functions
            .iter()
            .filter(|f| {
                f.control_flow
                    .as_ref()
                    .map(|cf| cf.cyclomatic_complexity > 50)
                    .unwrap_or(false)
            })
            .count() as u32;
    }

    // Calculate ratio-based density metrics (ML-oriented)
    let code_kb = binary.code_size as f32 / 1024.0;
    if code_kb > 0.0 {
        binary.import_density = binary.import_count as f32 / code_kb;
        binary.string_density = binary.string_count as f32 / code_kb;
        binary.function_density = binary.function_count as f32 / code_kb;
    }

    // Format-specific refinements
    if file_type == "macho" {
        if let Some(ref mut macho) = metrics.macho {
            // Count dylibs from imports
            let mut dylibs = std::collections::HashSet::new();
            for import in &report.imports {
                if let Some(lib) = &import.library {
                    dylibs.insert(lib.clone());
                }
            }
            macho.dylib_count = dylibs.len() as u32;

            // Check if this is a universal binary by looking at architectures
            if let Some(ref archs) = report.target.architectures {
                if archs.len() > 1 {
                    macho.is_universal = true;
                    macho.slice_count = archs.len() as u32;
                }
            }
        }
    }
}
