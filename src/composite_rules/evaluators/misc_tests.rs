//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for miscellaneous condition evaluators.

use super::*;
use crate::composite_rules::context::EvaluationContext;
use crate::composite_rules::types::{FileType, Platform};
use crate::types::{
    AnalysisReport, Criticality, Evidence, Finding, FindingKind, StructuralFeature, TargetInfo,
};
use std::sync::OnceLock;

fn create_test_report(path: &str) -> AnalysisReport {
    let target = TargetInfo {
        path: path.to_string(),
        file_type: "elf".to_string(),
        size_bytes: 1024,
        sha256: "abc123".to_string(),
        architectures: Some(vec!["x86_64".to_string()]),
    };
    AnalysisReport::new(target)
}

fn create_test_context<'a>(
    report: &'a AnalysisReport,
    data: &'a [u8],
    additional_findings: Option<&'a [Finding]>,
) -> EvaluationContext<'a> {
    EvaluationContext {
        report,
        binary_data: data,
        file_type: FileType::Elf,
        platforms: vec![Platform::Linux],
        additional_findings,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: None,
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
    }
}

fn create_test_finding(id: &str) -> Finding {
    Finding {
        id: id.to_string(),
        kind: FindingKind::Capability,
        desc: format!("Test finding: {}", id),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        trait_refs: Vec::new(),
        evidence: vec![Evidence {
            method: "test".to_string(),
            source: "test".to_string(),
            value: "test evidence".to_string(),
            location: None,
        }],
        source_file: None,
    }
}

// =============================================================================
// eval_structure tests
// =============================================================================

#[test]
fn test_eval_structure_exact_match() {
    let mut report = create_test_report("/test/binary");
    report.structure.push(StructuralFeature {
        id: "pe/headers/dos".to_string(),
        desc: "DOS header".to_string(),
        evidence: vec![Evidence {
            method: "structure".to_string(),
            source: "binary".to_string(),
            value: "DOS header found".to_string(),
            location: Some("0x0".to_string()),
        }],
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data, None);

    let result = eval_structure("pe/headers/dos", None, &ctx);
    assert!(result.matched);
    assert!(!result.evidence.is_empty());
}

#[test]
fn test_eval_structure_prefix_match() {
    let mut report = create_test_report("/test/binary");
    report.structure.push(StructuralFeature {
        id: "pe/headers/rich".to_string(),
        desc: "Rich header".to_string(),
        evidence: vec![],
    });
    report.structure.push(StructuralFeature {
        id: "pe/headers/dos".to_string(),
        desc: "DOS header".to_string(),
        evidence: vec![],
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data, None);

    // Prefix should match both
    let result = eval_structure("pe/headers", None, &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_structure_min_sections() {
    let mut report = create_test_report("/test/binary");
    for i in 0..5 {
        report.structure.push(StructuralFeature {
            id: format!("elf/section/{}", i),
            desc: format!("Section {}", i),
            evidence: vec![],
        });
    }
    let data = vec![];
    let ctx = create_test_context(&report, &data, None);

    let result = eval_structure("elf/section", Some(3), &ctx);
    assert!(result.matched);

    let result = eval_structure("elf/section", Some(10), &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_structure_no_match() {
    let report = create_test_report("/test/binary");
    let data = vec![];
    let ctx = create_test_context(&report, &data, None);

    let result = eval_structure("pe/headers/dos", None, &ctx);
    assert!(!result.matched);
}

// =============================================================================
// eval_trait tests
// =============================================================================

#[test]
fn test_eval_trait_exact_match() {
    let mut report = create_test_report("/test/binary");
    report
        .findings
        .push(create_test_finding("execution/process/spawn"));
    let data = vec![];
    let ctx = EvaluationContext::new(
        &report,
        &data,
        FileType::Elf,
        vec![Platform::Linux],
        None,
        None,
    );

    let result = eval_trait("execution/process/spawn", &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_trait_suffix_match() {
    let mut report = create_test_report("/test/binary");
    report
        .findings
        .push(create_test_finding("execution/process/terminate"));
    let data = vec![];
    let ctx = EvaluationContext::new(
        &report,
        &data,
        FileType::Elf,
        vec![Platform::Linux],
        None,
        None,
    );

    // Short name should match via suffix
    let result = eval_trait("terminate", &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_trait_prefix_match() {
    let mut report = create_test_report("/test/binary");
    report.findings.push(create_test_finding(
        "anti-static/obfuscation/strings/hex-decode",
    ));
    report.findings.push(create_test_finding(
        "anti-static/obfuscation/strings/base64",
    ));
    let data = vec![];
    let ctx = EvaluationContext::new(
        &report,
        &data,
        FileType::Elf,
        vec![Platform::Linux],
        None,
        None,
    );

    // Directory path should match any trait within that directory
    let result = eval_trait("anti-static/obfuscation/strings", &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_trait_additional_findings() {
    let report = create_test_report("/test/binary");
    let additional = vec![create_test_finding("net/connect/tcp")];
    let data = vec![];
    let ctx = EvaluationContext::new(
        &report,
        &data,
        FileType::Elf,
        vec![Platform::Linux],
        Some(&additional),
        None,
    );

    let result = eval_trait("net/connect/tcp", &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_trait_no_match() {
    let mut report = create_test_report("/test/binary");
    report
        .findings
        .push(create_test_finding("execution/shell/bash"));
    let data = vec![];
    let ctx = EvaluationContext::new(
        &report,
        &data,
        FileType::Elf,
        vec![Platform::Linux],
        None,
        None,
    );

    let result = eval_trait("net/connect/tcp", &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_trait_evidence_propagation() {
    let mut report = create_test_report("/test/binary");
    let mut finding = create_test_finding("execution/process/spawn");
    finding.evidence = vec![
        Evidence {
            method: "symbol".to_string(),
            source: "import".to_string(),
            value: "execve".to_string(),
            location: Some("0x1000".to_string()),
        },
        Evidence {
            method: "string".to_string(),
            source: "binary".to_string(),
            value: "/bin/sh".to_string(),
            location: Some("0x2000".to_string()),
        },
    ];
    report.findings.push(finding);
    let data = vec![];
    let ctx = EvaluationContext::new(
        &report,
        &data,
        FileType::Elf,
        vec![Platform::Linux],
        None,
        None,
    );

    let result = eval_trait("execution/process/spawn", &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 2);
}

// =============================================================================
// eval_basename tests
// =============================================================================

#[test]
fn test_eval_basename_exact() {
    let report = create_test_report("/usr/bin/malware.exe");
    let data = vec![];
    let ctx = create_test_context(&report, &data, None);

    let result = eval_basename(Some(&"malware.exe".to_string()), None, None, false, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence[0].value, "malware.exe");
}

#[test]
fn test_eval_basename_exact_no_match() {
    let report = create_test_report("/usr/bin/safe.exe");
    let data = vec![];
    let ctx = create_test_context(&report, &data, None);

    let result = eval_basename(Some(&"malware.exe".to_string()), None, None, false, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_basename_substr() {
    let report = create_test_report("/tmp/dropper_v2.sh");
    let data = vec![];
    let ctx = create_test_context(&report, &data, None);

    let result = eval_basename(None, Some(&"dropper".to_string()), None, false, &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_basename_regex() {
    let report = create_test_report("/tmp/malware_12345.exe");
    let data = vec![];
    let ctx = create_test_context(&report, &data, None);

    let result = eval_basename(
        None,
        None,
        Some(&r"malware_\d+\.exe".to_string()),
        false,
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_eval_basename_case_insensitive_exact() {
    let report = create_test_report("/tmp/MALWARE.EXE");
    let data = vec![];
    let ctx = create_test_context(&report, &data, None);

    let result = eval_basename(
        Some(&"malware.exe".to_string()),
        None,
        None,
        true, // case insensitive
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_eval_basename_case_insensitive_substr() {
    let report = create_test_report("/tmp/DROPPER_script.sh");
    let data = vec![];
    let ctx = create_test_context(&report, &data, None);

    let result = eval_basename(None, Some(&"dropper".to_string()), None, true, &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_basename_case_insensitive_regex() {
    let report = create_test_report("/tmp/MALWARE_TEST.exe");
    let data = vec![];
    let ctx = create_test_context(&report, &data, None);

    let result = eval_basename(
        None,
        None,
        Some(&r"malware_.*\.exe".to_string()),
        true,
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_eval_basename_no_pattern() {
    let report = create_test_report("/tmp/test.exe");
    let data = vec![];
    let ctx = create_test_context(&report, &data, None);

    // No pattern specified - should not match
    let result = eval_basename(None, None, None, false, &ctx);
    assert!(!result.matched);
}
