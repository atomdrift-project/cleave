//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for YARA and hex pattern evaluators
//!
//! Comprehensive test coverage for:
//! - YARA rule matching (eval_yara_match)
//! - Inline YARA compilation and scanning (eval_yara_inline)
//! - Hex pattern parsing and matching (eval_hex)
//! - Wildcard and gap support
//! - Evidence collection

use super::yara::*;
use crate::composite_rules::context::EvaluationContext;
use crate::composite_rules::evaluators::ContentLocationParams;
use crate::composite_rules::types::{FileType, Platform};
use crate::types::{AnalysisReport, TargetInfo};
use std::sync::{Arc, OnceLock};

/// Helper: Create minimal evaluation context
fn create_test_context(
    report: AnalysisReport,
    binary_data: Vec<u8>,
) -> EvaluationContext<'static> {
    EvaluationContext {
        report: Box::leak(Box::new(report)),
        binary_data: Box::leak(binary_data.into_boxed_slice()),
        file_type: FileType::All,
        platforms: vec![Platform::All],
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: None,
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
    }
}

/// Helper: Create test report
fn create_test_report() -> AnalysisReport {
    AnalysisReport::new(TargetInfo {
        path: "test.bin".to_string(),
        file_type: "executable".to_string(),
        size_bytes: 1024,
        sha256: "test".to_string(),
        architectures: None,
    })
}

// ==================== Hex Pattern Parsing Tests ====================
// Note: parse_hex_pattern and HexSegment are internal implementation details.
// They are tested indirectly through eval_hex tests below.

// ==================== Hex Pattern Matching Tests ====================

#[test]
fn test_eval_hex_simple_match() {
    let binary_data = vec![0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams::default();
    let result = eval_hex("4D 5A 90 00", &location, &ctx);

    assert!(result.matched, "Should match PE/MZ magic");
    assert!(!result.evidence.is_empty());
}

#[test]
fn test_eval_hex_wildcard_match() {
    let binary_data = vec![0x48, 0x8B, 0xAA, 0xBB, 0xFF];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams::default();
    let result = eval_hex("48 8B ?? ?? FF", &location, &ctx);

    assert!(result.matched, "Should match with wildcards");
}

#[test]
fn test_eval_hex_gap_match() {
    let binary_data = vec![0x48, 0x8B, 0x11, 0x22, 0x33, 0xFF];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams::default();
    let result = eval_hex("48 8B [3] FF", &location, &ctx);

    assert!(result.matched, "Should match with fixed gap");
}

#[test]
fn test_eval_hex_variable_gap_match() {
    let binary_data = vec![0x48, 0x8B, 0x11, 0x22, 0xFF];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams::default();
    let result = eval_hex("48 8B [2-8] FF", &location, &ctx);

    assert!(result.matched, "Should match with variable gap");
}

#[test]
fn test_eval_hex_no_match() {
    let binary_data = vec![0x00, 0x01, 0x02, 0x03];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams::default();
    let result = eval_hex("FF FF FF FF", &location, &ctx);

    assert!(!result.matched, "Should not match non-existent pattern");
}

#[test]
fn test_eval_hex_multiple_matches() {
    let binary_data = vec![
        0x48, 0x8B, 0xFF, // First match
        0x00, 0x00,       // Filler
        0x48, 0x8B, 0xFF, // Second match
    ];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams::default();
    let result = eval_hex("48 8B FF", &location, &ctx);

    assert!(result.matched);
    // Should collect multiple matches
    assert!(result.evidence.len() >= 1);
}

#[test]
fn test_eval_hex_offset_constraint() {
    let binary_data = vec![0x00, 0x00, 0x4D, 0x5A]; // MZ at offset 2
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let mut location = ContentLocationParams::default();
    location.offset = Some(2);
    let result = eval_hex("4D 5A", &location, &ctx);

    assert!(result.matched, "Should match at specific offset");
}

#[test]
fn test_eval_hex_offset_no_match() {
    let binary_data = vec![0x4D, 0x5A, 0x00, 0x00];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let mut location = ContentLocationParams::default();
    location.offset = Some(2); // Wrong offset
    let result = eval_hex("4D 5A", &location, &ctx);

    assert!(!result.matched, "Should not match at wrong offset");
}

#[test]
fn test_eval_hex_range_constraint() {
    let binary_data = vec![0x00, 0x00, 0x4D, 0x5A, 0x00, 0x00];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let mut location = ContentLocationParams::default();
    location.offset_range = Some((0, Some(4))); // Search in first 4 bytes
    let result = eval_hex("4D 5A", &location, &ctx);

    assert!(result.matched, "Should match within range");
}

#[test]
fn test_eval_hex_shellcode_pattern() {
    // Common shellcode pattern: xor eax, eax; push eax
    let binary_data = vec![0x31, 0xC0, 0x50, 0x00, 0x00];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams::default();
    let result = eval_hex("31 C0 50", &location, &ctx);

    assert!(result.matched, "Should detect shellcode pattern");
}

#[test]
fn test_eval_hex_elf_magic() {
    let binary_data = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams::default();
    let result = eval_hex("7F 45 4C 46", &location, &ctx);

    assert!(result.matched, "Should detect ELF magic");
}

#[test]
fn test_eval_hex_mz_magic() {
    let binary_data = vec![0x4D, 0x5A, 0x90, 0x00];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams::default();
    let result = eval_hex("4D 5A", &location, &ctx);

    assert!(result.matched, "Should detect MZ/PE magic");
}

#[test]
fn test_eval_hex_invalid_pattern() {
    let binary_data = vec![0x00, 0x01, 0x02];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams::default();
    let result = eval_hex("INVALID", &location, &ctx);

    assert!(!result.matched, "Should not match invalid pattern");
    assert!(!result.evidence.is_empty(), "Should have error evidence");
    assert!(result.evidence[0].value.contains("invalid"));
}

#[test]
fn test_eval_hex_empty_pattern() {
    let binary_data = vec![0x00, 0x01];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams::default();
    let result = eval_hex("", &location, &ctx);

    assert!(!result.matched, "Empty pattern should not match");
}

#[test]
fn test_eval_hex_wildcards_at_edges() {
    let binary_data = vec![0xFF, 0x48, 0x8B, 0xFF];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams::default();
    let result = eval_hex("?? 48 8B ??", &location, &ctx);

    assert!(result.matched, "Should match with leading/trailing wildcards");
}

#[test]
fn test_eval_hex_complex_pattern() {
    // Pattern: fixed bytes, wildcard, gap, fixed bytes
    let binary_data = vec![0x48, 0x8B, 0xAA, 0x11, 0x22, 0x33, 0xFF, 0xD0];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams::default();
    let result = eval_hex("48 8B ?? [3] FF D0", &location, &ctx);

    assert!(result.matched, "Should match complex pattern");
}

// ==================== Inline YARA Tests ====================

#[test]
fn test_eval_yara_inline_simple() {
    let binary_data = b"This contains a SECRET password".to_vec();
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let rule = r#"
        rule test_rule {
            strings:
                $secret = "SECRET"
            condition:
                $secret
        }
    "#;

    let compiled = Arc::new(yara_x::compile(rule).unwrap());
    let result = eval_yara_inline(rule, Some(&compiled), &ctx);

    assert!(result.matched, "Should match inline YARA rule");
    assert!(!result.evidence.is_empty());
}

#[test]
fn test_eval_yara_inline_no_match() {
    let binary_data = b"Nothing suspicious here".to_vec();
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let rule = r#"
        rule test_rule {
            strings:
                $malware = "MALWARE"
            condition:
                $malware
        }
    "#;

    let compiled = Arc::new(yara_x::compile(rule).unwrap());
    let result = eval_yara_inline(rule, Some(&compiled), &ctx);

    assert!(!result.matched, "Should not match when pattern absent");
}

#[test]
fn test_eval_yara_inline_multiple_strings() {
    let binary_data = b"User: admin\nPassword: secret123".to_vec();
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let rule = r#"
        rule credentials {
            strings:
                $user = "admin"
                $pass = "secret"
            condition:
                all of them
        }
    "#;

    let compiled = Arc::new(yara_x::compile(rule).unwrap());
    let result = eval_yara_inline(rule, Some(&compiled), &ctx);

    assert!(result.matched, "Should match multiple strings");
}

#[test]
fn test_eval_yara_inline_hex_pattern() {
    let binary_data = vec![0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let rule = r#"
        rule pe_file {
            strings:
                $mz = { 4D 5A }
            condition:
                $mz at 0
        }
    "#;

    let compiled = Arc::new(yara_x::compile(rule).unwrap());
    let result = eval_yara_inline(rule, Some(&compiled), &ctx);

    assert!(result.matched, "Should match hex pattern in YARA");
}

#[test]
fn test_eval_yara_inline_compilation_error() {
    let binary_data = b"test".to_vec();
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let invalid_rule = "invalid yara syntax {{{";
    let result = eval_yara_inline(invalid_rule, None, &ctx);

    assert!(!result.matched, "Should not match on compilation error");
    // Should have warning or error evidence
}
