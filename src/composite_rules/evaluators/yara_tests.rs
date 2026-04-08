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
use crate::composite_rules::types::FileType;
use crate::types::{AnalysisReport, TargetInfo};
use std::sync::Arc;

/// Helper: Create minimal evaluation context
fn create_test_context(report: AnalysisReport, binary_data: Vec<u8>) -> EvaluationContext<'static> {
    let leaked_report = Box::leak(Box::new(report));
    let leaked_data = Box::leak(binary_data.into_boxed_slice());
    EvaluationContext::test_only_new(leaked_report, leaked_data, FileType::All)
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

/// Use a bounded range to exercise short hex patterns without triggering
/// unbounded-search rejection logic in eval_hex.
fn full_scan_location() -> ContentLocationParams {
    ContentLocationParams {
        offset_range: Some((0, None)),
        ..Default::default()
    }
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

    let location = full_scan_location();
    let result = eval_hex("4D 5A 90 00", &location, &ctx, None);

    assert!(result.matched, "Should match PE/MZ magic");
    assert!(!result.evidence.is_empty());
}

#[test]
fn test_eval_hex_wildcard_match() {
    let binary_data = vec![0x48, 0x8B, 0xAA, 0xBB, 0xFF];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("48 8B ?? ?? FF", &location, &ctx, None);

    assert!(result.matched, "Should match with wildcards");
}

#[test]
fn test_eval_hex_gap_match() {
    let binary_data = vec![0x48, 0x8B, 0x11, 0x22, 0x33, 0xFF];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("48 8B [3] FF", &location, &ctx, None);

    assert!(result.matched, "Should match with fixed gap");
}

#[test]
fn test_eval_hex_variable_gap_match() {
    let binary_data = vec![0x48, 0x8B, 0x11, 0x22, 0xFF];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("48 8B [2-8] FF", &location, &ctx, None);

    assert!(result.matched, "Should match with variable gap");
}

#[test]
fn test_eval_hex_no_match() {
    let binary_data = vec![0x00, 0x01, 0x02, 0x03];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("FF FF FF FF", &location, &ctx, None);

    assert!(!result.matched, "Should not match non-existent pattern");
}

#[test]
fn test_eval_hex_multiple_matches() {
    let binary_data = vec![
        0x48, 0x8B, 0xFF, // First match
        0x00, 0x00, // Filler
        0x48, 0x8B, 0xFF, // Second match
    ];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("48 8B FF", &location, &ctx, None);

    assert!(result.matched);
    // Should collect multiple matches
    assert!(!result.evidence.is_empty());
}

#[test]
fn test_eval_hex_offset_constraint() {
    let binary_data = vec![0x00, 0x00, 0x4D, 0x5A]; // MZ at offset 2
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams {
        offset: Some(2),
        ..Default::default()
    };
    let result = eval_hex("4D 5A", &location, &ctx, None);

    assert!(result.matched, "Should match at specific offset");
}

#[test]
fn test_eval_hex_offset_no_match() {
    let binary_data = vec![0x4D, 0x5A, 0x00, 0x00];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams {
        offset: Some(2), // Wrong offset
        ..Default::default()
    };
    let result = eval_hex("4D 5A", &location, &ctx, None);

    assert!(!result.matched, "Should not match at wrong offset");
}

#[test]
fn test_eval_hex_range_constraint() {
    let binary_data = vec![0x00, 0x00, 0x4D, 0x5A, 0x00, 0x00];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = ContentLocationParams {
        offset_range: Some((0, Some(4))), // Search in first 4 bytes
        ..Default::default()
    };
    let result = eval_hex("4D 5A", &location, &ctx, None);

    assert!(result.matched, "Should match within range");
}

#[test]
fn test_eval_hex_shellcode_pattern() {
    // Common shellcode pattern: xor eax, eax; push eax
    let binary_data = vec![0x31, 0xC0, 0x50, 0x00, 0x00];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("31 C0 50", &location, &ctx, None);

    assert!(result.matched, "Should detect shellcode pattern");
}

#[test]
fn test_eval_hex_elf_magic() {
    let binary_data = vec![0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("7F 45 4C 46", &location, &ctx, None);

    assert!(result.matched, "Should detect ELF magic");
}

#[test]
fn test_eval_hex_mz_magic() {
    let binary_data = vec![0x4D, 0x5A, 0x90, 0x00];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("4D 5A", &location, &ctx, None);

    assert!(result.matched, "Should detect MZ/PE magic");
}

#[test]
fn test_eval_hex_invalid_pattern() {
    let binary_data = vec![0x00, 0x01, 0x02];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("INVALID", &location, &ctx, None);

    assert!(!result.matched, "Should not match invalid pattern");
    assert!(!result.evidence.is_empty(), "Should have error evidence");
    assert!(result.evidence[0].value.contains("invalid"));
}

#[test]
fn test_eval_hex_empty_pattern() {
    let binary_data = vec![0x00, 0x01];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("", &location, &ctx, None);

    assert!(!result.matched, "Empty pattern should not match");
}

#[test]
fn test_eval_hex_wildcards_at_edges() {
    let binary_data = vec![0xFF, 0x48, 0x8B, 0xFF];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("?? 48 8B ??", &location, &ctx, None);

    assert!(
        result.matched,
        "Should match with leading/trailing wildcards"
    );
}

#[test]
fn test_eval_hex_complex_pattern() {
    // Pattern: fixed bytes, wildcard, gap, fixed bytes
    let binary_data = vec![0x48, 0x8B, 0xAA, 0x11, 0x22, 0x33, 0xFF, 0xD0];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("48 8B ?? [3] FF D0", &location, &ctx, None);

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
    let result = eval_yara_inline(rule, None, Some(&compiled), &ctx);

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
    let result = eval_yara_inline(rule, None, Some(&compiled), &ctx);

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
    let result = eval_yara_inline(rule, None, Some(&compiled), &ctx);

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
    let result = eval_yara_inline(rule, None, Some(&compiled), &ctx);

    assert!(result.matched, "Should match hex pattern in YARA");
}

#[test]
fn test_eval_yara_inline_compilation_error() {
    let binary_data = b"test".to_vec();
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let invalid_rule = "invalid yara syntax {{{";
    let result = eval_yara_inline(invalid_rule, None, None, &ctx);

    assert!(!result.matched, "Should not match on compilation error");
    // Should have warning or error evidence
}

// ==================== Match Count Tests ====================

#[test]
fn test_eval_hex_match_count_tracks_all_matches() {
    // Create data with many repeated patterns (more than MAX_STORED_MATCHES=16)
    let mut binary_data = Vec::new();
    for _ in 0..50 {
        binary_data.extend_from_slice(&[0xAA, 0xBB, 0x00]); // Pattern with filler
    }
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("AA BB", &location, &ctx, None);

    assert!(result.matched, "Should match repeated pattern");
    // Evidence should be capped at 16, but match_count should track all 50
    assert!(
        result.evidence.len() <= 16,
        "Evidence should be capped at 16, got {}",
        result.evidence.len()
    );
    assert_eq!(
        result.match_count, 50,
        "match_count should track all 50 matches"
    );
}

#[test]
fn test_eval_hex_match_count_equals_evidence_when_few_matches() {
    // With only a few matches, match_count should equal evidence.len()
    let binary_data = vec![0x48, 0x8B, 0xFF, 0x00, 0x48, 0x8B, 0xFF];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("48 8B FF", &location, &ctx, None);

    assert!(result.matched);
    assert_eq!(result.evidence.len(), 2, "Should have 2 evidence items");
    assert_eq!(
        result.match_count, 2,
        "match_count should equal evidence.len()"
    );
}

#[test]
fn test_eval_hex_no_match_count_zero() {
    let binary_data = vec![0x00, 0x01, 0x02, 0x03];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("FF FF FF", &location, &ctx, None);

    assert!(!result.matched);
    assert!(result.evidence.is_empty());
    assert_eq!(
        result.match_count, 0,
        "match_count should be 0 for no matches"
    );
}

#[test]
fn test_eval_hex_match_count_with_wildcards() {
    // Create data with many wildcard-matching patterns
    let mut binary_data = Vec::new();
    for i in 0..30u8 {
        binary_data.extend_from_slice(&[0x48, i, 0xFF]); // 0x48 ?? 0xFF
    }
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("48 ?? FF", &location, &ctx, None);

    assert!(result.matched);
    assert!(result.evidence.len() <= 16, "Evidence should be capped");
    assert_eq!(
        result.match_count, 30,
        "match_count should track all 30 wildcard matches"
    );
}

#[test]
fn test_eval_hex_match_count_with_gap() {
    // Create data with gap-matching patterns
    let mut binary_data = Vec::new();
    for _ in 0..25 {
        binary_data.extend_from_slice(&[0x48, 0x00, 0x00, 0xFF, 0x00]); // 0x48 [2] 0xFF
    }
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("48 [2] FF", &location, &ctx, None);

    assert!(result.matched);
    assert!(result.evidence.len() <= 16, "Evidence should be capped");
    assert_eq!(
        result.match_count, 25,
        "match_count should track all 25 gap matches"
    );
}

// ==================== Nibble Wildcard Tests ====================

#[test]
fn test_eval_hex_nibble_wildcard_high() {
    // Pattern "4?" matches any byte 0x40-0x4F
    let binary_data = vec![0x00, 0x4D, 0x5A, 0x90]; // 0x4D matches "4?"
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("4? 5A", &location, &ctx, None);
    assert!(result.matched, "4? should match 0x4D");
}

#[test]
fn test_eval_hex_nibble_wildcard_low() {
    // Pattern "?A" matches any byte with low nibble 0xA (0x0A, 0x1A, ..., 0xFA)
    let binary_data = vec![0x00, 0x3A, 0xFF]; // 0x3A matches "?A"
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("?A FF", &location, &ctx, None);
    assert!(result.matched, "?A should match 0x3A");
}

#[test]
fn test_eval_hex_nibble_wildcard_no_match() {
    // Pattern "4?" should NOT match 0x5D (high nibble is 5, not 4)
    let binary_data = vec![0x5D, 0x5A];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("4? 5A", &location, &ctx, None);
    assert!(!result.matched, "4? should not match 0x5D");
}

#[test]
fn test_eval_hex_nibble_mixed_pattern() {
    // Real-world pattern: Mozi XOR loop (31 ?? 88 ?? 4? 83 ?? ?? 7?)
    let binary_data = vec![
        0x31, 0xC0, // xor eax, eax (31 ??)
        0x88, 0x01, // mov [ecx], al (88 ??)
        0x40, // inc eax (4?)
        0x83, 0xF8, 0x10, // cmp eax, 0x10 (83 ?? ??)
        0x72, // jb short (7?)
    ];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("31 ?? 88 ?? 4? 83 ?? ?? 7?", &location, &ctx, None);
    assert!(result.matched, "Mozi XOR pattern should match");
}

// ==================== Byte Alternation Tests ====================

#[test]
fn test_eval_hex_alternation() {
    // Pattern "(4D|5A)" matches either 0x4D or 0x5A
    let binary_data = vec![0x00, 0x5A, 0x90]; // 0x5A matches
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("(4D|5A) 90", &location, &ctx, None);
    assert!(result.matched, "(4D|5A) should match 0x5A");
}

#[test]
fn test_eval_hex_alternation_no_match() {
    // Pattern "(4D|5A)" should NOT match 0xFF
    let binary_data = vec![0xFF, 0x90];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("(4D|5A) 90", &location, &ctx, None);
    assert!(!result.matched, "(4D|5A) should not match 0xFF");
}

#[test]
fn test_eval_hex_alternation_multi() {
    // Multi-alternative: (01|02|03|04|05)
    let binary_data = vec![0xAA, 0x03, 0xBB];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("(01|02|03|04|05) BB", &location, &ctx, None);
    assert!(result.matched, "Multi-alternative should match 0x03");
}

#[test]
fn test_eval_hex_lzma_pattern() {
    // LZMA compression header: 5D 00 00 (00|80) 00 (10|20) [7] ??
    let mut binary_data = vec![
        0x5D, 0x00, 0x00, // LZMA magic
        0x80, // (00|80)
        0x00, // 0x00
        0x20, // (10|20)
    ];
    binary_data.extend_from_slice(&[0x00; 7]); // [7] gap
    binary_data.push(0xFF); // ??

    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("5D 00 00 (00|80) 00 (10|20) [7] ??", &location, &ctx, None);
    assert!(
        result.matched,
        "LZMA pattern with alternation and gaps should match"
    );
}
