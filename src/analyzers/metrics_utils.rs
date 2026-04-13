//! Shared utilities for metric calculation across all analyzers.
//!
//! This module provides a unified way to compute and populate metrics
//! that are common across different file formats, ensuring consistency
//! between the `analyze` command (JSON output) and the `metrics` command.

use crate::entropy::calculate_entropy;
use crate::types::{AnalysisReport, Metrics};

pub(crate) fn is_sentence_like_string(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.len() < 12 || trimmed.matches(' ').count() < 2 {
        return false;
    }

    let mut token_count = 0u32;
    let mut alpha_like_tokens = 0u32;

    for token in trimmed.split_whitespace() {
        let cleaned = token.trim_matches(|c: char| c.is_ascii_punctuation());
        if cleaned.is_empty() {
            continue;
        }
        token_count += 1;
        if cleaned.chars().any(|c| c.is_ascii_alphabetic()) {
            alpha_like_tokens += 1;
        }
    }

    token_count >= 3 && alpha_like_tokens >= 2
}

pub(crate) fn is_behavioral_import(name: &str) -> bool {
    let normalized = name.trim_start_matches('_').to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "system"
            | "popen"
            | "execl"
            | "execle"
            | "execlp"
            | "execv"
            | "execve"
            | "execvp"
            | "posix_spawn"
            | "posix_spawnp"
            | "dlopen"
            | "dlsym"
            | "connect"
            | "socket"
            | "send"
            | "recv"
            | "fopen"
            | "fread"
            | "fwrite"
            | "fscanf"
            | "unlink"
            | "unlinkat"
            | "remove"
            | "rename"
            | "copyfile"
            | "ptrace"
            | "sysctl"
    ) || normalized.starts_with("createprocess")
        || normalized.starts_with("shellexecute")
        || normalized.starts_with("loadlibrary")
        || normalized.starts_with("getprocaddress")
        || normalized.starts_with("virtualalloc")
        || normalized.starts_with("virtualprotect")
        || normalized.starts_with("writeprocessmemory")
        || normalized.starts_with("createremotethread")
        || normalized.starts_with("internetopen")
        || normalized.starts_with("winhttp")
}

pub(crate) fn is_nonstandard_section_name(file_type: &str, section_name: &str) -> bool {
    let short = section_name
        .rsplit('.')
        .next()
        .unwrap_or(section_name)
        .trim_start_matches("__");
    let lower = short.to_ascii_lowercase();

    match file_type {
        "macho" => !matches!(
            lower.as_str(),
            "pagezero"
                | "text"
                | "stubs"
                | "stub_helper"
                | "const"
                | "cstring"
                | "unwind_info"
                | "eh_frame"
                | "data"
                | "bss"
                | "common"
                | "got"
                | "la_symbol_ptr"
                | "nl_symbol_ptr"
                | "mod_init_func"
                | "mod_term_func"
                | "objc_classname"
                | "objc_methname"
                | "objc_methtype"
                | "objc_classlist"
                | "objc_catlist"
                | "objc_const"
                | "objc_data"
                | "objc_selrefs"
                | "objc_superrefs"
                | "objc_ivar"
                | "swift5_types"
                | "swift5_proto"
                | "swift5_fieldmd"
                | "swift5_reflstr"
                | "swift5_assocty"
                | "swift5_builtin"
                | "linkedit"
        ),
        "pe" => !matches!(
            lower.as_str(),
            "text"
                | "rdata"
                | "data"
                | "pdata"
                | "rsrc"
                | "reloc"
                | "idata"
                | "edata"
                | "tls"
                | "bss"
                | "crt"
        ),
        "elf" => !matches!(
            lower.as_str(),
            "text"
                | "rodata"
                | "data"
                | "bss"
                | "plt"
                | "got"
                | "got.plt"
                | "dynsym"
                | "dynstr"
                | "rela.text"
                | "rela.plt"
                | "rela.dyn"
                | "rel.text"
                | "rel.plt"
                | "eh_frame"
                | "eh_frame_hdr"
                | "init"
                | "fini"
                | "init_array"
                | "fini_array"
                | "comment"
                | "note.gnu.build-id"
                | "gnu.hash"
                | "hash"
        ),
        _ => false,
    }
}

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

    let metrics = report.metrics.get_or_insert_with(Metrics::default);

    // Ensure binary metrics section exists
    let binary = metrics.binary.get_or_insert_with(Default::default);

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
        binary.aliased_exports = addr_counts.values().filter(|&&c| c > 1).copied().sum();
    }

    if binary.file_size == 0 {
        binary.file_size = data.len() as u64;
    }

    // Calculate string metrics
    if !report.strings.is_empty() {
        let mut total_entropy: f64 = 0.0;
        let mut high_entropy_count: u32 = 0;
        let mut total_length: u64 = 0;
        let mut max_length: u32 = 0;
        let mut wide_count: u32 = 0;
        let mut sentence_like_count: u32 = 0;
        let mut lengths: Vec<f32> = Vec::with_capacity(report.strings.len());

        for s in &report.strings {
            let e = calculate_entropy(s.value.as_bytes());
            total_entropy += e;
            if e > 6.0 {
                high_entropy_count += 1;
            }

            let len = s.value.len() as u32;
            total_length += len as u64;
            lengths.push(len as f32);
            if len > max_length {
                max_length = len;
            }
            // Check encoding chain for wide strings
            if s.encoding_chain.iter().any(|e| e == "wide") {
                wide_count += 1;
            }
            if is_sentence_like_string(&s.value) {
                sentence_like_count += 1;
            }
        }

        binary.avg_string_entropy = (total_entropy / report.strings.len() as f64) as f32;
        binary.high_entropy_strings = high_entropy_count;
        binary.avg_string_length = total_length as f32 / report.strings.len() as f32;
        binary.max_string_length = max_length;
        binary.wide_string_count = wide_count;
        binary.sentence_string_count = sentence_like_count;
        if lengths.len() > 1 {
            let mean = binary.avg_string_length;
            let variance =
                lengths.iter().map(|l| (l - mean).powi(2)).sum::<f32>() / lengths.len() as f32;
            binary.string_length_stddev = variance.sqrt();
        }
    }

    // Calculate binary entropy from sections
    if !report.sections.is_empty() {
        let mut total_entropy: f32 = 0.0;
        let mut sum_sq_entropy: f32 = 0.0;
        let mut count: usize = 0;

        let mut code_entropy_sum: f32 = 0.0;
        let mut code_entropy_count: usize = 0;
        let mut data_entropy_sum: f32 = 0.0;
        let mut data_entropy_count: usize = 0;

        for section in &report.sections {
            let entropy = section.entropy as f32;
            total_entropy += entropy;
            sum_sq_entropy += entropy * entropy;
            count += 1;

            // Track code vs data section entropy
            let name_lower = section.name.to_lowercase();
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
                    if let Ok(flags) = u32::from_str_radix(perm, 16) {
                        (flags & 0x20000000) != 0
                    } else {
                        is_exec_perm
                    }
                } else {
                    is_exec_perm
                }
            } else if file_type == "elf" {
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
                code_entropy_sum += entropy;
                code_entropy_count += 1;
            } else if name_lower.contains("data") || name_lower.contains("rodata") {
                data_entropy_sum += entropy;
                data_entropy_count += 1;
            }

            if entropy > 7.5 {
                binary.high_entropy_regions += 1;
            }
        }

        if count > 0 {
            let mean = total_entropy / count as f32;
            binary.overall_entropy = mean;
            // Variance = E[X^2] - (E[X])^2
            let variance = (sum_sq_entropy / count as f32) - (mean * mean);
            binary.entropy_variance = variance.max(0.0).sqrt();
        }

        if code_entropy_count > 0 {
            binary.code_entropy = code_entropy_sum / code_entropy_count as f32;
        }

        if data_entropy_count > 0 {
            binary.data_entropy = data_entropy_sum / data_entropy_count as f32;
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

            if is_nonstandard_section_name(&file_type, &section.name) {
                binary.nonstandard_section_name_count += 1;
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

    if binary.string_count > 0 {
        binary.sentence_string_ratio =
            binary.sentence_string_count as f32 / binary.string_count as f32;
    }

    if binary.import_count > 0 {
        let behavioral_imports = report
            .imports
            .iter()
            .filter(|i| is_behavioral_import(&i.symbol))
            .count() as f32;
        binary.behavioral_import_ratio = behavioral_imports / binary.import_count as f32;
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

            binary.entry_point = macho.entry_point;
            binary.dependency_count = macho.dylib_count;
            binary.runtime_search_path_count = macho.rpath_count;
            binary.provenance_id_present = macho.uuid_present;
            binary.provenance_id_length = if macho.uuid_present { 16 } else { 0 };
            binary.has_signature = macho.has_code_signature;
            binary.signature_valid = macho.signature_valid;
        }
    } else if file_type == "elf" {
        if let Some(ref elf) = metrics.elf {
            binary.entry_point = elf.entry_point;
            binary.entry_in_nonstandard_section = elf.entry_not_in_text;
            binary.dependency_count = elf.needed_libs;
            binary.runtime_search_path_count = elf.rpath_count + elf.runpath_count;
            binary.debug_reference_count =
                elf.debug_section_count + u32::from(elf.debuglink_present);
            binary.provenance_id_present = elf.build_id_present;
            binary.provenance_id_length = elf.build_id_length;
        }
    } else if file_type == "pe" {
        if let Some(ref pe) = metrics.pe {
            binary.entry_point = pe.entry_point_rva as u64;
            binary.entry_point_is_rva = true;
            binary.entry_in_nonstandard_section = pe.entry_in_nonstandard_section;
            binary.dependency_count = pe.import_dll_count;
            binary.debug_reference_count = pe.debug_directory_entries;
            binary.has_signature = pe.has_signature;
            binary.signature_valid = pe.signature_valid;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{is_nonstandard_section_name, is_sentence_like_string};

    #[test]
    fn sentence_like_requires_multiple_words() {
        assert!(is_sentence_like_string(
            "This looks like a normal error message"
        ));
        assert!(!is_sentence_like_string("two words"));
        assert!(is_sentence_like_string("https://example.com/path with space here"));
        assert!(is_sentence_like_string("/tmp/some path here"));
        assert!(!is_sentence_like_string("SingleTokenOnly"));
        assert!(!is_sentence_like_string("%s %d %x"));
    }

    #[test]
    fn nonstandard_section_names_are_format_aware() {
        assert!(!is_nonstandard_section_name("macho", "__text"));
        assert!(!is_nonstandard_section_name("macho", "__cstring"));
        assert!(is_nonstandard_section_name("macho", "__weird"));
        assert!(!is_nonstandard_section_name("pe", ".text"));
        assert!(is_nonstandard_section_name("pe", ".asdf"));
    }
}
