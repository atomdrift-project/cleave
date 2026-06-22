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
use crate::types::{AnalysisReport, Section, TargetInfo};
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

// Regression: when the LONGEST fixed run (the pre-filter atom) sits AFTER a
// variable gap, eval_hex used to back-align the candidate start by the gap's
// MINIMUM only. Any input whose real gap exceeded that minimum was silently
// dropped. `test_eval_hex_variable_gap_match` above does not exercise this
// because its atom (`48 8B`) precedes the gap.
#[test]
fn test_eval_hex_variable_gap_before_long_atom() {
    // gap of 5 bytes; longest atom (DE AD BE EF) is after the [0-8] gap.
    let binary_data = vec![
        0x48, 0x8B, 0x01, 0x02, 0x03, 0x04, 0x05, 0xDE, 0xAD, 0xBE, 0xEF,
    ];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("48 8B [0-8] DE AD BE EF", &location, &ctx, None);

    assert!(
        result.matched,
        "Should match when the longest atom follows a variable gap larger than its minimum"
    );
    assert_eq!(result.match_count, 1, "Should count exactly one match");
}

// The real-world shape that surfaced the bug: an x64 RWX VirtualAlloc arg setup
// `lea r9d,[rcx+0x40]` … `mov r8d,0x1000`, where the longest atom is the
// MEM_COMMIT constant after a 5-byte gap.
#[test]
fn test_eval_hex_variable_gap_x64_rwx_alloc_shape() {
    let binary_data = vec![
        0x44, 0x8D, 0x49, 0x40, // lea r9d,[rcx+0x40]
        0xBA, 0x59, 0xCE, 0x00, 0x00, // mov edx,0xce59  (the gap)
        0x41, 0xB8, 0x00, 0x10, 0x00, 0x00, // mov r8d,0x1000
    ];
    let report = create_test_report();
    let ctx = create_test_context(report, binary_data);

    let location = full_scan_location();
    let result = eval_hex("44 8D 49 40 [0-8] 41 B8 00 10 00 00", &location, &ctx, None);

    assert!(result.matched, "x64 RWX-commit shape should match");
    assert_eq!(result.match_count, 1);
}

// Boundary: gap == min (0) and gap == max (8), atom after the gap.
#[test]
fn test_eval_hex_variable_gap_before_atom_boundaries() {
    let report = create_test_report();

    // gap == min (0 bytes between 8B and the atom)
    let ctx0 = create_test_context(create_test_report(), vec![0x8B, 0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(
        eval_hex("8B [0-8] DE AD BE EF", &full_scan_location(), &ctx0, None).matched,
        "Should match at gap minimum (0)"
    );

    // gap == max (8 bytes)
    let mut data_max = vec![0x8B];
    data_max.extend_from_slice(&[0xAA; 8]);
    data_max.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let ctx8 = create_test_context(report, data_max);
    assert!(
        eval_hex("8B [0-8] DE AD BE EF", &full_scan_location(), &ctx8, None).matched,
        "Should match at gap maximum (8)"
    );
}

// A gap larger than the declared maximum must NOT match.
#[test]
fn test_eval_hex_variable_gap_before_atom_exceeds_max() {
    // 9-byte gap, but pattern allows only [0-8].
    let mut data = vec![0x8B];
    data.extend_from_slice(&[0xAA; 9]);
    data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let report = create_test_report();
    let ctx = create_test_context(report, data);

    let result = eval_hex("8B [0-8] DE AD BE EF", &full_scan_location(), &ctx, None);
    assert!(
        !result.matched,
        "Gap exceeding the declared maximum must not match"
    );
}

// Non-Bytes prefix segments (wildcard / nibble-mask / byte-set) before the atom
// each contribute 1 to the prefix length. These exercise the prefix-range
// accumulation for every HexSegment variant, not just plain Bytes + Gap.
#[test]
fn test_eval_hex_wildcard_prefix_before_atom() {
    // Two leading ?? wildcards, then the longest atom.
    let binary_data = vec![0x11, 0x22, 0xDE, 0xAD, 0xBE, 0xEF];
    let ctx = create_test_context(create_test_report(), binary_data);
    let result = eval_hex("?? ?? DE AD BE EF", &full_scan_location(), &ctx, None);
    assert!(
        result.matched,
        "Leading wildcards before the atom should align"
    );
    assert_eq!(result.match_count, 1);
}

#[test]
fn test_eval_hex_nibble_prefix_before_atom() {
    // 4? matches 0x40..0x4F; atom DE AD BE EF follows.
    let binary_data = vec![0x4C, 0xDE, 0xAD, 0xBE, 0xEF];
    let ctx = create_test_context(create_test_report(), binary_data);
    let result = eval_hex("4? DE AD BE EF", &full_scan_location(), &ctx, None);
    assert!(
        result.matched,
        "Nibble-mask prefix before the atom should align"
    );
}

#[test]
fn test_eval_hex_byteset_prefix_before_atom() {
    let binary_data = vec![0x49, 0xDE, 0xAD, 0xBE, 0xEF];
    let ctx = create_test_context(create_test_report(), binary_data);
    let result = eval_hex("(48|49) DE AD BE EF", &full_scan_location(), &ctx, None);
    assert!(
        result.matched,
        "Byte-set prefix before the atom should align"
    );
}

// Alignment hazard documented on extract_best_atom: the chosen atom byte-run
// appears MORE THAN ONCE in the pattern. The prefix length must be computed for
// the FIRST occurrence (where take_while stops), matching extract_best_atom's
// first-longest choice — otherwise the back-alignment is off.
#[test]
fn test_eval_hex_duplicate_atom_run() {
    // `DE AD BE EF` appears twice; a 2-byte gap between.
    let binary_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0xDE, 0xAD, 0xBE, 0xEF];
    let ctx = create_test_context(create_test_report(), binary_data);
    let result = eval_hex(
        "DE AD BE EF [2] DE AD BE EF",
        &full_scan_location(),
        &ctx,
        None,
    );
    assert!(
        result.matched,
        "Pattern with a repeated atom run should match"
    );
    assert_eq!(result.match_count, 1);
}

// Multiple gaps in one pattern (both before and after the atom).
#[test]
fn test_eval_hex_multiple_gaps() {
    let binary_data = vec![0x48, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x99, 0xFF];
    let ctx = create_test_context(create_test_report(), binary_data);
    let result = eval_hex(
        "48 [2] DE AD BE EF [0-3] FF",
        &full_scan_location(),
        &ctx,
        None,
    );
    assert!(
        result.matched,
        "Pattern with gaps before and after the atom should match"
    );
}

// Unbounded-search guard: a pattern with fewer than 3 concrete bytes and no
// pinpoint (offset/offset_range/section-offset) is rejected to avoid scanning the
// whole file for a near-ubiquitous short needle. A *truly* unbounded location
// (Default — note full_scan_location sets offset_range and so counts as pinned)
// must trip the guard; the same short pattern WITH a pinpoint is allowed.
#[test]
fn test_eval_hex_short_pattern_unbounded_rejected() {
    let binary_data = vec![0x48, 0x8B, 0x11, 0x48, 0x8B, 0x22];
    let ctx = create_test_context(create_test_report(), binary_data);

    let unbounded = ContentLocationParams::default();
    assert!(
        !eval_hex("48 8B", &unbounded, &ctx, None).matched,
        "Short (<3 concrete bytes) pattern with no pinpoint must be rejected"
    );

    // The same short pattern is allowed once the search is bounded.
    assert!(
        eval_hex("48 8B", &full_scan_location(), &ctx, None).matched,
        "Short pattern with an offset_range pinpoint should be allowed"
    );
}

// No fixed byte run anywhere in the pattern → extract_best_atom returns None and
// eval_hex falls back to a linear scan. All-nibble-mask patterns hit this path,
// which the atom-based tests never exercise.
#[test]
fn test_eval_hex_no_atom_linear_fallback() {
    // 4? 4? 4? matches three consecutive bytes in 0x40..=0x4F.
    let binary_data = vec![0x00, 0x41, 0x4C, 0x4F, 0x00];
    let ctx = create_test_context(create_test_report(), binary_data);
    let result = eval_hex("4? 4? 4?", &full_scan_location(), &ctx, None);
    assert!(
        result.matched,
        "All-nibble-mask pattern should match via linear fallback"
    );

    let ctx2 = create_test_context(create_test_report(), vec![0x41, 0x52, 0x43]);
    assert!(
        !eval_hex("4? 4? 4?", &full_scan_location(), &ctx2, None).matched,
        "Linear fallback should reject when a byte falls outside the nibble mask"
    );
}

/// Build a report whose `sections` drive the section/section_offset resolution
/// path in `resolve_effective_range` (used when no SectionMap is attached).
fn section(name: &str, offset: u64, size: u64) -> Section {
    Section {
        name: name.to_string(),
        address: None,
        offset: Some(offset),
        size,
        entropy: 0.0,
        permissions: None,
        flags: Vec::new(),
    }
}
fn report_with_sections(sections: Vec<Section>) -> AnalysisReport {
    let mut report = create_test_report();
    report.sections = sections;
    report
}

// A bare `section:` constraint scopes the search to that section's file range, so
// an identical byte run outside the section is not counted.
#[test]
fn test_eval_hex_section_constraint_scopes_search() {
    let data = vec![
        0x00, 0x00, 0x00, 0x00, // [0,4)
        0xDE, 0xAD, 0xBE, 0xEF, // [4,8)  inside .text
        0x00, 0x00, // [8,10)
        0xDE, 0xAD, 0xBE, 0xEF, // [10,14) outside .text
    ];
    let ctx = create_test_context(report_with_sections(vec![section(".text", 4, 4)]), data);
    let location = ContentLocationParams {
        section: Some(".text".to_string()),
        ..Default::default()
    };
    let result = eval_hex("DE AD BE EF", &location, &ctx, None);
    assert!(result.matched, "Should match inside the named section");
    assert_eq!(
        result.match_count, 1,
        "Only the in-section occurrence should count"
    );
}

// `section_offset_range` further narrows to a relative window within the section.
#[test]
fn test_eval_hex_section_offset_range_window() {
    let data = vec![
        0x00, 0x00, 0x00, 0x00, // [0,4)
        0xDE, 0xAD, 0xBE, 0xEF, // [4,8)   in section, before the window
        0x00, 0x00, // [8,10)
        0xDE, 0xAD, 0xBE, 0xEF, // [10,14) inside relative window [6,10)->abs [10,14)
        0x00, 0x00, 0x00, 0x00, // [14,18)
    ];
    let ctx = create_test_context(report_with_sections(vec![section(".text", 4, 14)]), data);
    let location = ContentLocationParams {
        section: Some(".text".to_string()),
        section_offset_range: Some((6, Some(10))),
        ..Default::default()
    };
    let result = eval_hex("DE AD BE EF", &location, &ctx, None);
    assert!(result.matched, "Should match inside the section sub-range");
    assert_eq!(
        result.match_count, 1,
        "Only the occurrence in the sub-range counts"
    );
}

// A section name that does not exist resolves to an empty range -> no match.
#[test]
fn test_eval_hex_unknown_section_no_match() {
    let ctx = create_test_context(
        report_with_sections(vec![section(".text", 0, 4)]),
        vec![0xDE, 0xAD, 0xBE, 0xEF],
    );
    let location = ContentLocationParams {
        section: Some(".nonexistent".to_string()),
        ..Default::default()
    };
    assert!(
        !eval_hex("DE AD BE EF", &location, &ctx, None).matched,
        "Unknown section must yield no match"
    );
}

// Counting stops at MAX_COUNT_MATCHES (16384): with more occurrences, match_count
// saturates at the cap rather than growing unbounded.
#[test]
fn test_eval_hex_count_capped_at_max() {
    let mut data = Vec::with_capacity(16_400 * 3);
    for _ in 0..16_400 {
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
    }
    let ctx = create_test_context(create_test_report(), data);
    let result = eval_hex("AA BB CC", &full_scan_location(), &ctx, None);
    assert!(result.matched);
    assert_eq!(
        result.match_count, 16_384,
        "match_count is capped at MAX_COUNT_MATCHES (16384)"
    );
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
