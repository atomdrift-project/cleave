//! Test and debug composite rules against sample files.
//!
//! This module provides the `test-rules` command implementation, which evaluates
//! specified rules against a target file and shows detailed evaluation traces.
//!
//! This command uses the exact same evaluation path as production: YARA pre-scan
//! followed by trait/composite evaluation with inline YARA results. The only
//! difference is the addition of debug tracing via `DebugCollector`.

use crate::analyzers::{detect_file_type, macho::MachOAnalyzer, FileType};
use crate::commands::shared::{
    create_analysis_report, find_rules_in_directory, find_similar_rules, process_yara_result,
};
use crate::yara_engine::YaraEngine;
use crate::{cli, composite_rules, test_rules};
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Test and debug composite rules against a sample file.
///
/// This function evaluates specified rules against a target file and provides
/// detailed diagnostics about why rules matched or didn't match.
///
/// # Arguments
///
/// * `target` - Path to the file to analyze
/// * `rules` - Comma-separated list of rule IDs to test
/// * `_disabled` - Disabled components configuration (unused)
/// * `platforms` - Platform filters for rule evaluation
/// * `min_hostile_precision` - Minimum precision for hostile rules
/// * `min_suspicious_precision` - Minimum precision for suspicious rules
///
/// # Returns
///
/// A formatted string containing the debug output showing rule evaluation results,
/// condition traces, and evidence.
pub(crate) fn run(
    target: &str,
    rules: &str,
    _disabled: &cli::DisabledComponents,
    platforms: Vec<composite_rules::Platform>,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    eprintln!("Analyzing: {}", target);

    // Parse rule IDs, stripping trailing slashes
    let rule_ids: Vec<String> = rules
        .split(',')
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .collect();
    eprintln!("Debugging {} rule(s): {:?}", rule_ids.len(), rule_ids);

    // Detect file type
    let file_type = detect_file_type(path)?;
    eprintln!("Detected file type: {:?}", file_type);

    // Load capability mapper with full validation (test-rules is a developer command)
    let capability_mapper = crate::capabilities::CapabilityMapper::new_with_precision_thresholds(
        min_hostile_precision,
        min_suspicious_precision,
        true, // Always enable full validation for test-rules
    )
    .with_platforms(platforms.clone());

    // Load YARA engine to match production path exactly
    let mut yara_engine = YaraEngine::new();
    let (builtin_count, _third_party_count) = yara_engine.load_all_rules(false);
    let yara_loaded = builtin_count > 0 && yara_engine.is_loaded();

    // Read file data
    let full_data = fs::read(path)?;

    // For Mach-O FAT binaries, we need to evaluate ALL architecture slices (like production).
    // This ensures findings from any arch are visible, preventing discrepancies where traits
    // match in x86_64 but not ARM64 (or vice versa).
    let (binary_data, arch_slices): (Vec<u8>, Vec<Vec<u8>>) = if file_type == FileType::MachO {
        let analyzer = MachOAnalyzer::new();
        let preferred_range = analyzer.preferred_arch_range(&full_data);
        let all_ranges = analyzer.all_arch_ranges(&full_data);

        if all_ranges.len() > 1 {
            eprintln!(
                "Note: FAT binary with {} architectures, evaluating all slices",
                all_ranges.len()
            );
        }

        let slices: Vec<Vec<u8>> = all_ranges
            .iter()
            .map(|r| full_data[r.clone()].to_vec())
            .collect();
        let preferred = full_data[preferred_range].to_vec();
        (preferred, slices)
    } else {
        (full_data.clone(), vec![full_data])
    };

    // Create a basic report by analyzing the file (uses preferred arch for structure)
    let mut report = create_analysis_report(path, &file_type, &binary_data, &capability_mapper)?;

    // Run YARA scan on preferred arch slice (matching production behavior)
    // This gives us inline YARA results for traits with `type: yara` conditions
    let file_type_filter: &[&str] = match file_type {
        FileType::MachO => &["macho", "dylib", "kext"],
        FileType::Elf => &["elf", "so", "ko"],
        FileType::Pe => &["pe", "exe", "dll", "sys"],
        _ => &[],
    };

    let inline_yara: HashMap<String, Vec<crate::types::Evidence>> = if yara_loaded {
        let yara_result = yara_engine.scan_bytes_with_inline(
            &binary_data,
            if file_type_filter.is_empty() {
                None
            } else {
                Some(file_type_filter)
            },
        );
        process_yara_result(&mut report, Some(yara_result), Some(&yara_engine))
    } else {
        HashMap::new()
    };

    // Evaluate traits against ALL architecture slices to match production behavior.
    // Findings are merged/deduplicated, so traits matching in any arch will be visible.
    let inline_yara_ref = if inline_yara.is_empty() {
        None
    } else {
        Some(&inline_yara)
    };
    for slice in &arch_slices {
        capability_mapper.evaluate_and_merge_findings(&mut report, slice, None, inline_yara_ref);
    }

    // Create debugger and debug each rule
    // Pass platforms from CLI for consistency with production evaluation
    // Pass inline_yara so debug evaluation uses the exact same context as production
    let debugger = test_rules::RuleDebugger::new(
        &capability_mapper,
        &report,
        &binary_data,
        &capability_mapper.composite_rules,
        capability_mapper.trait_definitions(),
        platforms,
        inline_yara_ref,
    );

    let mut results = Vec::new();
    for rule_id in &rule_ids {
        // First try exact match
        if let Some(result) = debugger.debug_rule(rule_id) {
            results.push(result);
        } else {
            // Check if this is a directory prefix - find all rules under it
            let rules_in_dir = find_rules_in_directory(&capability_mapper, rule_id);
            if !rules_in_dir.is_empty() {
                eprintln!(
                    "Warning: Rule '{}' not found, but found {} rules in directory:",
                    rule_id,
                    rules_in_dir.len()
                );
                for r in &rules_in_dir {
                    eprintln!("    - {}", r);
                }
                // Debug each rule in the directory
                for sub_rule_id in &rules_in_dir {
                    if let Some(result) = debugger.debug_rule(sub_rule_id) {
                        results.push(result);
                    }
                }
            } else {
                eprintln!("Warning: Rule '{}' not found", rule_id);
                // Search for similar rules
                let similar = find_similar_rules(&capability_mapper, rule_id);
                if !similar.is_empty() {
                    eprintln!("  Did you mean one of:");
                    for s in similar.iter().take(5) {
                        eprintln!("    - {}", s);
                    }
                }
            }
        }
    }

    // Format and return output
    Ok(test_rules::format_debug_output(&results))
}
