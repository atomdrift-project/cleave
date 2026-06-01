use std::sync::RwLock;

use crate::composite_rules::context::EvaluationContext;
use crate::composite_rules::debug::RuleType;
use crate::composite_rules::types::FileType as RuleFileType;
use crate::composite_rules::types::{Arch, Platform};
use crate::composite_rules::{Condition, TraitDefinition};
use crate::types::Criticality;
use crate::types::{AnalysisReport, TargetInfo};

fn create_report_with_size(file_size: usize) -> AnalysisReport {
    AnalysisReport::new(TargetInfo {
        path: "/test/file".into(),
        file_type: "test".into(),
        size_bytes: file_size as u64,
        sha256: "0".repeat(64),
        architectures: None,
    })
}

#[test]
fn test_trait_filter_size_min() {
    let condition = Condition::Text {
        exact: Some("test_symbol".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        not: None,
        platforms: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    };

    let mut trait_def = TraitDefinition {
        id: "test/size-min".to_string(),
        desc: "Size min test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        size_min: Some(1024 * 1024), // 1 MB
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        not: None,
        r#if: condition,
        unless: None,
        downgrade: None,
        defined_in: "test".into(),
        precision: None,
        arch: vec![Arch::All],
        ..Default::default()
    };
    assert!(trait_def.precompile_regexes().is_ok());

    let binary_data = vec![0u8; 100];
    let mut report = create_report_with_size(100);
    report.strings.push(crate::types::StringInfo {
        value: ("test_symbol".to_string()).into(),
        offset: Some(0),
        string_type: None,
        encoding: "utf-8".to_string(),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });

    // File size (100 B) < size_min (1 MB) → must NOT match
    let ctx = EvaluationContext::test_only_new(&report, &binary_data, RuleFileType::All);

    let eval_result = trait_def.evaluate(&ctx);
    assert!(
        eval_result.is_none(),
        "Real evaluation should return None (size_min not satisfied: 100 < 1MB)"
    );

    // Test debug evaluation
    let debug = RwLock::new(crate::composite_rules::debug::EvaluationDebug::new(
        "test",
        RuleType::Trait,
    ));
    let debug_ctx = EvaluationContext::test_only_new(&report, &binary_data, RuleFileType::All);
    // Use a trick to set debug_collector for the test
    let mut debug_ctx = debug_ctx;
    debug_ctx.debug_collector = Some(&debug);

    let debug_result = trait_def.evaluate(&debug_ctx);
    assert!(
        debug_result.is_none(),
        "Debug evaluation should return None (size_min not satisfied)"
    );
}

#[test]
fn test_trait_filter_size_max() {
    let condition = Condition::Text {
        exact: Some("test_symbol".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        not: None,
        platforms: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    };

    let mut trait_def = TraitDefinition {
        id: "test/size-max".to_string(),
        desc: "Size max test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: Some(3 * 1024 * 1024), // 3 MB
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        not: None,
        r#if: condition,
        unless: None,
        downgrade: None,
        defined_in: "test".into(),
        precision: None,
        arch: vec![Arch::All],
        ..Default::default()
    };
    assert!(trait_def.precompile_regexes().is_ok());

    let binary_data = vec![0u8; 100];
    let mut small_report = create_report_with_size(1024);
    small_report.strings.push(crate::types::StringInfo {
        value: ("test_symbol".to_string()).into(),
        offset: Some(0),
        string_type: None,
        encoding: "utf-8".to_string(),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });

    let mut large_report = create_report_with_size(130 * 1024 * 1024);
    large_report.strings.push(crate::types::StringInfo {
        value: ("test_symbol".to_string()).into(),
        offset: Some(0),
        string_type: None,
        encoding: "utf-8".to_string(),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });

    // Small file: size_max satisfied → should match
    let small_ctx =
        EvaluationContext::test_only_new(&small_report, &binary_data, RuleFileType::All);
    assert!(
        trait_def.evaluate(&small_ctx).is_some(),
        "Should match: file size (1 KB) is within size_max (3 MB)"
    );

    // Large file: size_max exceeded → must NOT match
    let large_ctx =
        EvaluationContext::test_only_new(&large_report, &binary_data, RuleFileType::All);
    assert!(
        trait_def.evaluate(&large_ctx).is_none(),
        "Must not match: file size (130 MB) exceeds size_max (3 MB)"
    );
}
