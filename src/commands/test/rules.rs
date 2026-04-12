//! Test and debug composite rules against sample files.
//!
//! This module provides the `test-rules` command implementation, which evaluates
//! specified rules against a target file and shows detailed evaluation traces.
//!
//! This command uses the exact same evaluation path as production: YARA pre-scan
//! followed by trait/composite evaluation with inline YARA results. The only
//! difference is the addition of debug tracing via `DebugCollector`.

use crate::analyzers::{detect_file_type, FileType};
use crate::commands::shared::{find_rules_in_directory, find_similar_rules, process_yara_result};
use crate::commands::test::{build_test_capability_mapper, evaluation_data, prepare_test_analysis};
use crate::yara_engine::YaraEngine;
use crate::{cli, composite_rules, test_rules};
use anyhow::Result;
use std::collections::HashMap;
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
pub fn run(
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

    // Load capability mapper with full validation (test-rules is a developer command).
    // Honor CLEAVE_SKIP_TRAITS the same way test-match does for faster focused runs.
    let capability_mapper = build_test_capability_mapper(
        platforms.clone(),
        min_hostile_precision,
        min_suspicious_precision,
    );

    // Load YARA engine to match production path exactly
    let mut yara_engine = YaraEngine::new();
    let (builtin_count, _third_party_count) = yara_engine.load_all_rules(false);
    let yara_loaded = builtin_count > 0 && yara_engine.is_loaded();

    let mut prepared = prepare_test_analysis(path, file_type, &capability_mapper)?;
    if prepared.is_fat_macho {
        eprintln!(
            "Note: FAT binary with {} architectures, evaluating full file",
            prepared.arch_count.unwrap_or(0)
        );
    }

    // Run YARA scan on preferred arch slice (matching production behavior)
    // This gives us inline YARA results for traits with `type: yara` conditions
    let file_type_filter: &[&str] = match prepared.file_type {
        FileType::MachO => &["macho", "dylib", "kext"],
        FileType::Elf => &["elf", "so", "ko"],
        FileType::Pe => &["pe", "exe", "dll", "sys"],
        _ => &[],
    };

    let inline_yara: HashMap<String, Vec<crate::types::Evidence>> = if yara_loaded {
        let yara_result = yara_engine.scan_bytes_with_inline(
            &prepared.preferred_binary_data,
            if file_type_filter.is_empty() {
                None
            } else {
                Some(file_type_filter)
            },
        );
        process_yara_result(&mut prepared.report, Some(yara_result), Some(&yara_engine))
    } else {
        HashMap::new()
    };

    // Evaluate traits against the binary data.
    // For FAT binaries, we use the full file so string offsets are file-relative.
    let inline_yara_ref = if inline_yara.is_empty() {
        None
    } else {
        Some(&inline_yara)
    };
    let eval_data = evaluation_data(
        &prepared.full_data,
        &prepared.preferred_binary_data,
        prepared.is_fat_macho,
    );
    capability_mapper.evaluate_and_merge_findings(
        &mut prepared.report,
        eval_data,
        None,
        inline_yara_ref,
    );

    // Create debugger and debug each rule
    // Pass platforms from CLI for consistency with production evaluation
    // Pass inline_yara so debug evaluation uses the exact same context as production
    // For FAT binaries, use full file so string offsets are file-relative
    let debugger = test_rules::RuleDebugger::new(
        &capability_mapper,
        &prepared.report,
        eval_data,
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
