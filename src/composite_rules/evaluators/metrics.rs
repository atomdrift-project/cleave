//! Metrics-based condition evaluators.
//!
//! This module handles evaluation of computed metrics against thresholds:
//! - Text metrics (entropy, line lengths, whitespace)
//! - Identifier metrics (reuse, entropy, naming patterns)
//! - String metrics (entropy, length distributions)
//! - Comment metrics (ratio, density)
//! - Function metrics (complexity, nesting, parameters)
//! - Binary metrics (entropy, sections, imports, functions)
//! - Language-specific metrics (Go)

use crate::composite_rules::context::{ConditionResult, EvaluationContext};
use crate::types::Evidence;

/// Evaluate metrics condition - check computed metrics against thresholds
/// Field path examples: "identifiers.avg_entropy", "functions.density_per_100_lines"
#[must_use]
pub(crate) fn eval_metrics<'a>(
    field: &str,
    min: Option<f64>,
    max: Option<f64>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    // Check file size constraints first
    let file_size = ctx.report.target.size_bytes;
    if let Some(min_sz) = min_size {
        if file_size < min_sz {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                warnings: Vec::new(),
                precision: 0.0,
                matched_trait_ids: Vec::new(),
            };
        }
    }
    if let Some(max_sz) = max_size {
        if file_size > max_sz {
            return ConditionResult {
                matched: false,
                evidence: Vec::new(),
                warnings: Vec::new(),
                precision: 0.0,
                matched_trait_ids: Vec::new(),
            };
        }
    }

    let Some(metrics) = &ctx.report.metrics else {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            warnings: Vec::new(),
            precision: 0.0,
            matched_trait_ids: Vec::new(),
        };
    };

    // Parse field path and get value
    let value = match field {
        // Text metrics
        "text.char_entropy" => metrics.text.as_ref().map(|t| t.char_entropy as f64),
        "text.line_length_stddev" => metrics.text.as_ref().map(|t| t.line_length_stddev as f64),
        "text.avg_line_length" => metrics.text.as_ref().map(|t| t.avg_line_length as f64),
        "text.max_line_length" => metrics.text.as_ref().map(|t| t.max_line_length as f64),
        "text.empty_line_ratio" => metrics.text.as_ref().map(|t| t.empty_line_ratio as f64),
        "text.whitespace_ratio" => metrics.text.as_ref().map(|t| t.whitespace_ratio as f64),
        "text.digit_ratio" => metrics.text.as_ref().map(|t| t.digit_ratio as f64),

        // Identifier metrics
        "identifiers.total" => metrics.identifiers.as_ref().map(|i| i.total as f64),
        "identifiers.unique" => metrics.identifiers.as_ref().map(|i| i.unique_count as f64),
        "identifiers.reuse_ratio" => metrics.identifiers.as_ref().map(|i| i.reuse_ratio as f64),
        "identifiers.avg_length" => metrics.identifiers.as_ref().map(|i| i.avg_length as f64),
        "identifiers.avg_entropy" => metrics.identifiers.as_ref().map(|i| i.avg_entropy as f64),
        "identifiers.high_entropy_ratio" => metrics
            .identifiers
            .as_ref()
            .map(|i| i.high_entropy_ratio as f64),
        "identifiers.single_char_ratio" => metrics
            .identifiers
            .as_ref()
            .map(|i| i.single_char_ratio as f64),
        "identifiers.single_char_count" => metrics
            .identifiers
            .as_ref()
            .map(|i| i.single_char_count as f64),
        "identifiers.numeric_suffix_count" => metrics
            .identifiers
            .as_ref()
            .map(|i| i.numeric_suffix_count as f64),
        "identifiers.sequential_names" => metrics
            .identifiers
            .as_ref()
            .map(|i| i.sequential_names as f64),

        // String metrics
        "strings.total" => metrics.strings.as_ref().map(|s| s.total as f64),
        "strings.avg_entropy" => metrics.strings.as_ref().map(|s| s.avg_entropy as f64),
        "strings.entropy_stddev" => metrics.strings.as_ref().map(|s| s.entropy_stddev as f64),
        "strings.avg_length" => metrics.strings.as_ref().map(|s| s.avg_length as f64),

        // Comment metrics
        "comments.total" => metrics.comments.as_ref().map(|c| c.total as f64),
        "comments.to_code_ratio" => metrics.comments.as_ref().map(|c| c.to_code_ratio as f64),

        // Function metrics
        "functions.total" => metrics.functions.as_ref().map(|f| f.total as f64),
        "functions.anonymous" => metrics.functions.as_ref().map(|f| f.anonymous as f64),
        "functions.async_count" => metrics.functions.as_ref().map(|f| f.async_count as f64),
        "functions.avg_length_lines" => metrics
            .functions
            .as_ref()
            .map(|f| f.avg_length_lines as f64),
        "functions.max_length_lines" => metrics
            .functions
            .as_ref()
            .map(|f| f.max_length_lines as f64),
        "functions.length_stddev" => metrics.functions.as_ref().map(|f| f.length_stddev as f64),
        "functions.over_100_lines" => metrics.functions.as_ref().map(|f| f.over_100_lines as f64),
        "functions.over_500_lines" => metrics.functions.as_ref().map(|f| f.over_500_lines as f64),
        "functions.one_liners" => metrics.functions.as_ref().map(|f| f.one_liners as f64),
        "functions.avg_params" => metrics.functions.as_ref().map(|f| f.avg_params as f64),
        "functions.max_params" => metrics.functions.as_ref().map(|f| f.max_params as f64),
        "functions.many_params_count" => metrics
            .functions
            .as_ref()
            .map(|f| f.many_params_count as f64),
        "functions.single_char_names" => metrics
            .functions
            .as_ref()
            .map(|f| f.single_char_names as f64),
        "functions.high_entropy_names" => metrics
            .functions
            .as_ref()
            .map(|f| f.high_entropy_names as f64),
        "functions.numeric_suffix_names" => metrics
            .functions
            .as_ref()
            .map(|f| f.numeric_suffix_names as f64),
        "functions.max_nesting_depth" => metrics
            .functions
            .as_ref()
            .map(|f| f.max_nesting_depth as f64),
        "functions.avg_nesting_depth" => metrics
            .functions
            .as_ref()
            .map(|f| f.avg_nesting_depth as f64),
        "functions.nested_functions" => metrics
            .functions
            .as_ref()
            .map(|f| f.nested_functions as f64),
        "functions.density_per_100_lines" => metrics
            .functions
            .as_ref()
            .map(|f| f.density_per_100_lines as f64),
        "functions.code_in_functions_ratio" => metrics
            .functions
            .as_ref()
            .map(|f| f.code_in_functions_ratio as f64),
        "functions.single_char_params" => metrics
            .functions
            .as_ref()
            .map(|f| f.single_char_params as f64),
        "functions.avg_param_name_length" => metrics
            .functions
            .as_ref()
            .map(|f| f.avg_param_name_length as f64),

        // Binary metrics (from radare2 analysis)
        "binary.overall_entropy" => metrics.binary.as_ref().map(|b| b.overall_entropy as f64),
        "binary.code_entropy" => metrics.binary.as_ref().map(|b| b.code_entropy as f64),
        "binary.data_entropy" => metrics.binary.as_ref().map(|b| b.data_entropy as f64),
        "binary.entropy_variance" => metrics.binary.as_ref().map(|b| b.entropy_variance as f64),
        "binary.high_entropy_regions" => metrics
            .binary
            .as_ref()
            .map(|b| b.high_entropy_regions as f64),
        "binary.file_size" => metrics.binary.as_ref().map(|b| b.file_size as f64),
        "binary.code_size" => metrics.binary.as_ref().map(|b| b.code_size as f64),
        "binary.code_to_data_ratio" => metrics.binary.as_ref().map(|b| b.code_to_data_ratio as f64),
        "binary.has_debug_info" => {
            metrics
                .binary
                .as_ref()
                .map(|b| if b.has_debug_info { 1.0 } else { 0.0 })
        }
        "binary.is_stripped" => metrics
            .binary
            .as_ref()
            .map(|b| if b.is_stripped { 1.0 } else { 0.0 }),
        "binary.is_pie" => metrics
            .binary
            .as_ref()
            .map(|b| if b.is_pie { 1.0 } else { 0.0 }),
        "binary.relocation_count" => metrics.binary.as_ref().map(|b| b.relocation_count as f64),
        "binary.section_count" => metrics.binary.as_ref().map(|b| b.section_count as f64),
        "binary.segment_count" => metrics.binary.as_ref().map(|b| b.segment_count as f64),
        "binary.avg_section_size" => metrics.binary.as_ref().map(|b| b.avg_section_size as f64),
        "binary.executable_sections" => metrics
            .binary
            .as_ref()
            .map(|b| b.executable_sections as f64),
        "binary.writable_sections" => metrics.binary.as_ref().map(|b| b.writable_sections as f64),
        "binary.wx_sections" => metrics.binary.as_ref().map(|b| b.wx_sections as f64),
        "binary.section_name_entropy" => metrics
            .binary
            .as_ref()
            .map(|b| b.section_name_entropy as f64),
        "binary.largest_section_ratio" => metrics
            .binary
            .as_ref()
            .map(|b| b.largest_section_ratio as f64),
        "binary.import_count" => metrics.binary.as_ref().map(|b| b.import_count as f64),
        "binary.export_count" => metrics.binary.as_ref().map(|b| b.export_count as f64),
        "binary.import_entropy" => metrics.binary.as_ref().map(|b| b.import_entropy as f64),
        "binary.string_count" => metrics.binary.as_ref().map(|b| b.string_count as f64),
        "binary.wide_string_count" => metrics.binary.as_ref().map(|b| b.wide_string_count as f64),
        "binary.avg_string_length" => metrics.binary.as_ref().map(|b| b.avg_string_length as f64),
        "binary.max_string_length" => metrics.binary.as_ref().map(|b| b.max_string_length as f64),
        "binary.avg_string_entropy" => metrics.binary.as_ref().map(|b| b.avg_string_entropy as f64),
        "binary.high_entropy_strings" => metrics
            .binary
            .as_ref()
            .map(|b| b.high_entropy_strings as f64),
        "binary.function_count" => metrics.binary.as_ref().map(|b| b.function_count as f64),
        "binary.avg_function_size" => metrics.binary.as_ref().map(|b| b.avg_function_size as f64),
        "binary.tiny_functions" => metrics.binary.as_ref().map(|b| b.tiny_functions as f64),
        "binary.huge_functions" => metrics.binary.as_ref().map(|b| b.huge_functions as f64),
        "binary.complexity_per_kb" => metrics.binary.as_ref().map(|b| b.complexity_per_kb as f64),
        "binary.import_density" => metrics.binary.as_ref().map(|b| b.import_density as f64),
        "binary.function_density" => metrics.binary.as_ref().map(|b| b.function_density as f64),
        "binary.string_density" => metrics.binary.as_ref().map(|b| b.string_density as f64),
        "binary.normalized_string_count" => metrics
            .binary
            .as_ref()
            .map(|b| b.normalized_string_count as f64),
        "binary.normalized_import_count" => metrics
            .binary
            .as_ref()
            .map(|b| b.normalized_import_count as f64),
        "binary.normalized_export_count" => metrics
            .binary
            .as_ref()
            .map(|b| b.normalized_export_count as f64),
        "binary.export_to_import_ratio" => metrics
            .binary
            .as_ref()
            .map(|b| b.export_to_import_ratio as f64),
        "binary.has_overlay" => metrics
            .binary
            .as_ref()
            .map(|b| if b.has_overlay { 1.0 } else { 0.0 }),
        "binary.overlay_size" => metrics.binary.as_ref().map(|b| b.overlay_size as f64),
        "binary.overlay_ratio" => metrics.binary.as_ref().map(|b| b.overlay_ratio as f64),
        "binary.overlay_entropy" => metrics.binary.as_ref().map(|b| b.overlay_entropy as f64),

        // Mach-O specific
        "macho.file_type" => metrics.macho.as_ref().map(|m| m.file_type as f64),

        // ELF specific
        "elf.e_type" => metrics.elf.as_ref().map(|e| e.e_type as f64),
        "elf.load_segment_max_p_filesz" => metrics
            .elf
            .as_ref()
            .map(|e| e.load_segment_max_p_filesz as f64),
        "elf.load_segment_max_p_memsz" => metrics
            .elf
            .as_ref()
            .map(|e| e.load_segment_max_p_memsz as f64),

        // Complexity metrics
        "binary.avg_complexity" => metrics.binary.as_ref().map(|b| b.avg_complexity as f64),
        "binary.max_complexity" => metrics.binary.as_ref().map(|b| b.max_complexity as f64),
        "binary.high_complexity_functions" => metrics
            .binary
            .as_ref()
            .map(|b| b.high_complexity_functions as f64),
        "binary.very_high_complexity_functions" => metrics
            .binary
            .as_ref()
            .map(|b| b.very_high_complexity_functions as f64),

        // Control flow metrics
        "binary.total_basic_blocks" => metrics.binary.as_ref().map(|b| b.total_basic_blocks as f64),
        "binary.avg_basic_blocks" => metrics.binary.as_ref().map(|b| b.avg_basic_blocks as f64),
        "binary.linear_functions" => metrics.binary.as_ref().map(|b| b.linear_functions as f64),
        "binary.recursive_functions" => metrics
            .binary
            .as_ref()
            .map(|b| b.recursive_functions as f64),
        "binary.noreturn_functions" => metrics.binary.as_ref().map(|b| b.noreturn_functions as f64),
        "binary.leaf_functions" => metrics.binary.as_ref().map(|b| b.leaf_functions as f64),

        // Stack metrics
        "binary.avg_stack_frame" => metrics.binary.as_ref().map(|b| b.avg_stack_frame as f64),
        "binary.max_stack_frame" => metrics.binary.as_ref().map(|b| b.max_stack_frame as f64),
        "binary.large_stack_functions" => metrics
            .binary
            .as_ref()
            .map(|b| b.large_stack_functions as f64),

        // Go metrics (language-specific)
        "go_metrics.unsafe_usage" => metrics.go_metrics.as_ref().map(|g| g.unsafe_usage as f64),
        "go_metrics.reflect_usage" => metrics.go_metrics.as_ref().map(|g| g.reflect_usage as f64),
        "go_metrics.cgo_usage" => metrics.go_metrics.as_ref().map(|g| g.cgo_usage as f64),
        "go_metrics.plugin_usage" => metrics.go_metrics.as_ref().map(|g| g.plugin_usage as f64),
        "go_metrics.syscall_direct" => metrics.go_metrics.as_ref().map(|g| g.syscall_direct as f64),
        "go_metrics.exec_command_count" => metrics
            .go_metrics
            .as_ref()
            .map(|g| g.exec_command_count as f64),
        "go_metrics.os_startprocess_count" => metrics
            .go_metrics
            .as_ref()
            .map(|g| g.os_startprocess_count as f64),
        "go_metrics.net_dial_count" => metrics.go_metrics.as_ref().map(|g| g.net_dial_count as f64),
        "go_metrics.http_usage" => metrics.go_metrics.as_ref().map(|g| g.http_usage as f64),
        "go_metrics.raw_socket_count" => metrics
            .go_metrics
            .as_ref()
            .map(|g| g.raw_socket_count as f64),
        "go_metrics.embed_directive_count" => metrics
            .go_metrics
            .as_ref()
            .map(|g| g.embed_directive_count as f64),
        "go_metrics.linkname_count" => metrics.go_metrics.as_ref().map(|g| g.linkname_count as f64),
        "go_metrics.noescape_count" => metrics.go_metrics.as_ref().map(|g| g.noescape_count as f64),
        "go_metrics.cgo_directives" => metrics.go_metrics.as_ref().map(|g| g.cgo_directives as f64),
        "go_metrics.init_function_count" => metrics
            .go_metrics
            .as_ref()
            .map(|g| g.init_function_count as f64),
        "go_metrics.blank_import_count" => metrics
            .go_metrics
            .as_ref()
            .map(|g| g.blank_import_count as f64),

        _ => None,
    };

    let Some(value) = value else {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            warnings: Vec::new(),
            precision: 0.0,
            matched_trait_ids: Vec::new(),
        };
    };

    let min_ok = min.is_none_or(|m| value >= m);
    let max_ok = max.is_none_or(|m| value <= m);
    let matched = min_ok && max_ok;

    // Calculate precision: base 1.0 + 0.5 each for min/max/min_size/max_size
    let mut precision = 1.0f32;
    if min.is_some() {
        precision += 0.5;
    }
    if max.is_some() {
        precision += 0.5;
    }
    if min_size.is_some() {
        precision += 0.5;
    }
    if max_size.is_some() {
        precision += 0.5;
    }

    ConditionResult {
        matched,
        evidence: if matched {
            vec![Evidence {
                method: "metrics".to_string(),
                source: "analyzer".to_string(),
                value: format!("{} = {:.2}", field, value),
                location: None,
            }]
        } else {
            Vec::new()
        },
        warnings: Vec::new(),
        precision,
        matched_trait_ids: Vec::new(),
    }
}
