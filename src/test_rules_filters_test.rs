//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Tests to ensure debug output matches evaluation output for all filter types
/// This prevents discrepancies where debug shows "matched" but evaluation returns None
use crate::composite_rules::condition::Condition;
use crate::composite_rules::debug::{EvaluationDebug, RuleType};
use crate::composite_rules::traits::{CompositeTrait, ConditionWithFilters, TraitDefinition};
use crate::composite_rules::{EvaluationContext, FileType as RuleFileType, Platform};
use crate::types::{AnalysisReport, TargetInfo};
use std::sync::{OnceLock, RwLock};

/// Helper to create a minimal report for testing
fn create_test_report(file_size: usize) -> AnalysisReport {
    AnalysisReport::new(TargetInfo {
        path: "/test/file".into(),
        file_type: "test".into(),
        size_bytes: file_size as u64,
        sha256: "0".repeat(64),
        architectures: None,
    })
}

#[test]
fn test_count_min_filter_matches_debug_and_eval() {
    // Create a test binary with the hex pattern "0F A2" (CPUID) appearing exactly 2 times
    let mut binary_data = vec![0u8; 1024];
    binary_data[100] = 0x0F;
    binary_data[101] = 0xA2;
    binary_data[500] = 0x0F;
    binary_data[501] = 0xA2;

    let report = create_test_report(1024);

    // Create trait with count_min: 3 (should NOT match - only 2 occurrences)
    let trait_def = TraitDefinition {
        id: "test/count-min".to_string(),
        desc: "Test count_min filter".to_string(),
        conf: 0.85,
        crit: crate::types::Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        r#if: ConditionWithFilters {
            condition: Condition::Hex {
                pattern: "0F A2".to_string(),
                offset: None,
                offset_range: None,
                section: None,
                section_offset: None,
                section_offset_range: None,
            },
            size_min: None,
            size_max: None,
            count_min: Some(3), // Require at least 3 matches
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
        },
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    // Test real evaluation
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &binary_data,
        file_type: RuleFileType::All,
        platforms: vec![Platform::All],
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: None,
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
    };

    let eval_result = trait_def.evaluate(&ctx);
    assert!(
        eval_result.is_none(),
        "Real evaluation should return None (count_min not satisfied: 2 < 3)"
    );

    // Test debug evaluation (with debug collector)
    let debug = RwLock::new(EvaluationDebug::new(&trait_def.id, RuleType::Trait));
    let debug_ctx = EvaluationContext {
        report: &report,
        binary_data: &binary_data,
        file_type: RuleFileType::All,
        platforms: vec![Platform::All],
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: Some(&debug),
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
    };

    let debug_result = trait_def.evaluate(&debug_ctx);
    assert!(
        debug_result.is_none(),
        "Debug evaluation should return None (count_min not satisfied: 2 < 3)"
    );

    // Check that skip reason was recorded
    let debug_info = debug.into_inner().unwrap();
    assert!(
        debug_info.skip_reason.is_some(),
        "Skip reason should be recorded"
    );
    let skip_reason = debug_info.skip_reason.unwrap().to_string();
    assert!(
        skip_reason.to_lowercase().contains("count")
            && skip_reason.contains("2")
            && skip_reason.contains("3"),
        "Skip reason should mention count constraint (expected 2 < 3), got: {}",
        skip_reason
    );
}

#[test]
fn test_per_kb_min_filter_matches_debug_and_eval() {
    // Create a 597 KB test binary (same size as the bug report)
    let file_size = 611_608; // 597 KB
    let mut binary_data = vec![0u8; file_size];

    // Add exactly 4 CPUID instructions (0F A2)
    binary_data[100] = 0x0F;
    binary_data[101] = 0xA2;
    binary_data[1000] = 0x0F;
    binary_data[1001] = 0xA2;
    binary_data[10000] = 0x0F;
    binary_data[10001] = 0xA2;
    binary_data[100000] = 0x0F;
    binary_data[100001] = 0xA2;

    let report = create_test_report(file_size);

    // Density: 4 matches / 597 KB = 0.0067 per KB
    // Trait requires: per_kb_min: 0.1 (should NOT match)
    let trait_def = TraitDefinition {
        id: "test/per-kb-min".to_string(),
        desc: "Test per_kb_min filter".to_string(),
        conf: 0.85,
        crit: crate::types::Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        r#if: ConditionWithFilters {
            condition: Condition::Hex {
                pattern: "0F A2".to_string(),
                offset: None,
                offset_range: None,
                section: None,
                section_offset: None,
                section_offset_range: None,
            },
            size_min: None,
            size_max: None,
            count_min: Some(3), // Count satisfied (4 >= 3)
            count_max: None,
            per_kb_min: Some(0.1), // Density NOT satisfied (0.0067 < 0.1)
            per_kb_max: None,
        },
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    // Test real evaluation
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &binary_data,
        file_type: RuleFileType::All,
        platforms: vec![Platform::All],
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: None,
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
    };

    let eval_result = trait_def.evaluate(&ctx);
    assert!(
        eval_result.is_none(),
        "Real evaluation should return None (per_kb_min not satisfied)"
    );

    // Test debug evaluation
    let debug = RwLock::new(EvaluationDebug::new(&trait_def.id, RuleType::Trait));
    let debug_ctx = EvaluationContext {
        report: &report,
        binary_data: &binary_data,
        file_type: RuleFileType::All,
        platforms: vec![Platform::All],
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: Some(&debug),
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
    };

    let debug_result = trait_def.evaluate(&debug_ctx);
    assert!(
        debug_result.is_none(),
        "Debug evaluation should return None (per_kb_min not satisfied)"
    );

    // Check that skip reason was recorded
    let debug_info = debug.into_inner().unwrap();
    assert!(
        debug_info.skip_reason.is_some(),
        "Skip reason should be recorded"
    );
    let skip_reason = debug_info.skip_reason.unwrap().to_string();
    assert!(
        skip_reason.contains("density") || skip_reason.contains("Density"),
        "Skip reason should mention density constraint, got: {}",
        skip_reason
    );
}

#[test]
fn test_size_min_filter_matches_debug_and_eval() {
    // Create a small 100-byte file
    let binary_data = vec![0x41; 100]; // 100 bytes of 'A'

    let report = create_test_report(100);

    // Trait requires size_min: 1024 (should NOT match)
    let trait_def = TraitDefinition {
        id: "test/size-min".to_string(),
        desc: "Test size_min filter".to_string(),
        conf: 0.85,
        crit: crate::types::Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        r#if: ConditionWithFilters {
            condition: Condition::Raw {
                exact: None,
                substr: Some("A".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                offset: None,
                offset_range: None,
                section: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
            },
            size_min: Some(1024), // Require at least 1 KB
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
        },
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    // Test real evaluation
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &binary_data,
        file_type: RuleFileType::All,
        platforms: vec![Platform::All],
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: None,
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
    };

    let eval_result = trait_def.evaluate(&ctx);
    assert!(
        eval_result.is_none(),
        "Real evaluation should return None (size_min not satisfied: 100 < 1024)"
    );

    // Test debug evaluation
    let debug = RwLock::new(EvaluationDebug::new(&trait_def.id, RuleType::Trait));
    let debug_ctx = EvaluationContext {
        report: &report,
        binary_data: &binary_data,
        file_type: RuleFileType::All,
        platforms: vec![Platform::All],
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: Some(&debug),
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
    };

    let debug_result = trait_def.evaluate(&debug_ctx);
    assert!(
        debug_result.is_none(),
        "Debug evaluation should return None (size_min not satisfied: 100 < 1024)"
    );

    // Check that skip reason was recorded
    let debug_info = debug.into_inner().unwrap();
    assert!(
        debug_info.skip_reason.is_some(),
        "Skip reason should be recorded"
    );
    let skip_reason = debug_info.skip_reason.unwrap().to_string();
    assert!(
        skip_reason.contains("too small") || skip_reason.contains("Size"),
        "Skip reason should mention size constraint, got: {}",
        skip_reason
    );
}

#[test]
fn test_composite_size_constraints_match_debug_and_eval() {
    // Create a small 500-byte file
    let binary_data = vec![0x41; 500];
    let report = create_test_report(500);

    // Composite with size_min: 1024 (should NOT match)
    let composite = CompositeTrait {
        id: "test/composite-size".to_string(),
        desc: "Test composite size filter".to_string(),
        conf: 0.9,
        crit: crate::types::Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        size_min: Some(1024), // Require at least 1 KB
        size_max: None,
        all: None,
        any: Some(vec![Condition::Raw {
            exact: None,
            substr: Some("A".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            external_ip: false,
            offset: None,
            offset_range: None,
            section: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
        }]),
        none: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    // Test real evaluation
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &binary_data,
        file_type: RuleFileType::All,
        platforms: vec![Platform::All],
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: None,
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
    };

    let eval_result = composite.evaluate(&ctx);
    assert!(
        eval_result.is_none(),
        "Real evaluation should return None (composite size_min not satisfied: 500 < 1024)"
    );

    // Test debug evaluation
    let debug = RwLock::new(EvaluationDebug::new(&composite.id, RuleType::Composite));
    let debug_ctx = EvaluationContext {
        report: &report,
        binary_data: &binary_data,
        file_type: RuleFileType::All,
        platforms: vec![Platform::All],
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: Some(&debug),
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
    };

    let debug_result = composite.evaluate(&debug_ctx);
    assert!(
        debug_result.is_none(),
        "Debug evaluation should return None (composite size_min not satisfied: 500 < 1024)"
    );

    // Check that skip reason was recorded
    let debug_info = debug.into_inner().unwrap();
    assert!(
        debug_info.skip_reason.is_some(),
        "Skip reason should be recorded for composite size constraint"
    );
}

#[test]
fn test_all_filters_match_when_satisfied() {
    // Create a large file (10 KB) with many pattern matches
    let file_size = 10_240; // 10 KB
    let mut binary_data = vec![0u8; file_size];

    // Add 200 occurrences of pattern "0F A2" (20 per KB)
    for i in 0..200 {
        let offset = i * 50;
        if offset + 1 < file_size {
            binary_data[offset] = 0x0F;
            binary_data[offset + 1] = 0xA2;
        }
    }

    let report = create_test_report(file_size);

    // All constraints satisfied:
    // - count_min: 3 (200 >= 3) ✓
    // - per_kb_min: 0.1 (20 >= 0.1) ✓
    // - size_min: 1024 (10240 >= 1024) ✓
    let trait_def = TraitDefinition {
        id: "test/all-satisfied".to_string(),
        desc: "Test all filters satisfied".to_string(),
        conf: 0.85,
        crit: crate::types::Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        r#if: ConditionWithFilters {
            condition: Condition::Hex {
                pattern: "0F A2".to_string(),
                offset: None,
                offset_range: None,
                section: None,
                section_offset: None,
                section_offset_range: None,
            },
            size_min: Some(1024),
            size_max: None,
            count_min: Some(3),
            count_max: None,
            per_kb_min: Some(0.1),
            per_kb_max: None,
        },
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    // Test real evaluation
    let ctx = EvaluationContext {
        report: &report,
        binary_data: &binary_data,
        file_type: RuleFileType::All,
        platforms: vec![Platform::All],
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: None,
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
    };

    let eval_result = trait_def.evaluate(&ctx);
    assert!(
        eval_result.is_some(),
        "Real evaluation should return Some (all filters satisfied)"
    );

    // Test debug evaluation
    let debug = RwLock::new(EvaluationDebug::new(&trait_def.id, RuleType::Trait));
    let debug_ctx = EvaluationContext {
        report: &report,
        binary_data: &binary_data,
        file_type: RuleFileType::All,
        platforms: vec![Platform::All],
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: Some(&debug),
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
    };

    let debug_result = trait_def.evaluate(&debug_ctx);
    assert!(
        debug_result.is_some(),
        "Debug evaluation should return Some (all filters satisfied)"
    );

    // Both should match
    assert_eq!(
        eval_result.is_some(),
        debug_result.is_some(),
        "Evaluation and debug should agree when all filters are satisfied"
    );
}
