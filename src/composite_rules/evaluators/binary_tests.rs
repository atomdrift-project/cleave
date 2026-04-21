//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for binary analysis condition evaluators.

use super::*;
use crate::composite_rules::context::EvaluationContext;
use crate::composite_rules::types::FileType;
use crate::types::{AnalysisReport, Section, SyscallInfo, TargetInfo};

fn create_test_report() -> AnalysisReport {
    let target = TargetInfo {
        path: "/test/binary".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 1024,
        sha256: "abc123".to_string(),
        architectures: Some(vec!["x86_64".to_string()]),
    };
    AnalysisReport::new(target)
}

fn create_test_context<'a>(report: &'a AnalysisReport, data: &'a [u8]) -> EvaluationContext<'a> {
    EvaluationContext::test_only_new(report, data, FileType::All)
}

// =============================================================================
// eval_section tests
// =============================================================================

#[test]
fn test_eval_section_regex() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: "UPX0".to_string(),
        address: None,
        offset: None,
        size: 1000,
        entropy: 7.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let regex = r"^UPX".to_string();
    let result = eval_section(
        None,
        None,
        Some(&regex),
        None,
        false,
        None,
        None,
        None,
        None,
        None, // readable
        None, // writable
        None, // executable
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence[0].value, "UPX0");
}

#[test]
fn test_eval_section_contains() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".packed_data".to_string(),
        address: None,
        offset: None,
        size: 1000,
        entropy: 7.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let substr = "packed".to_string();
    let result = eval_section(
        None,
        Some(&substr),
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        None, // readable
        None, // writable
        None, // executable
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_eval_section_no_match() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: None,
        offset: None,
        size: 1000,
        entropy: 6.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let substr = "UPX".to_string();
    let result = eval_section(
        None,
        Some(&substr),
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        None, // readable
        None, // writable
        None, // executable
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(!result.matched);
}

#[test]
fn test_eval_section_multiple_matches() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: None,
        offset: None,
        size: 500,
        entropy: 6.5,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".text.plt".to_string(),
        address: None,
        offset: None,
        size: 100,
        entropy: 6.0,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let substr = ".text".to_string();
    let result = eval_section(
        None,
        Some(&substr),
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        None, // readable
        None, // writable
        None, // executable
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 2);
}

#[test]
fn test_eval_section_exact() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: None,
        offset: None,
        size: 500,
        entropy: 6.5,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".text.plt".to_string(),
        address: None,
        offset: None,
        size: 100,
        entropy: 6.0,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let exact = ".text".to_string();
    let result = eval_section(
        Some(&exact),
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        None, // readable
        None, // writable
        None, // executable
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1); // Only exact match, not .text.plt
}

#[test]
fn test_eval_section_case_insensitive() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".TEXT".to_string(),
        address: None,
        offset: None,
        size: 500,
        entropy: 6.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let substr = ".text".to_string();
    let result = eval_section(
        None,
        Some(&substr),
        None,
        None,
        true,
        None,
        None,
        None,
        None,
        None, // readable
        None, // writable
        None, // executable
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence[0].value, ".TEXT");
}

// =============================================================================
// eval_syscall tests
// =============================================================================

#[test]
fn test_eval_syscall_by_name() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "execve".to_string(),
        number: 59,
        address: 0x1000,
        desc: "Execute program".to_string(),
        arch: "x86_64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_syscall(Some(&vec!["execve".to_string()]), None, None, &ctx);
    assert!(result.matched);
    assert!(result.evidence[0].value.contains("execve"));
}

#[test]
fn test_eval_syscall_by_number() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "socket".to_string(),
        number: 41,
        address: 0x2000,
        desc: "Create socket".to_string(),
        arch: "x86_64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_syscall(None, Some(&vec![41]), None, &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_syscall_by_arch() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "exit".to_string(),
        number: 60,
        address: 0x3000,
        desc: "Exit process".to_string(),
        arch: "x86_64".to_string(),
    });
    report.syscalls.push(SyscallInfo {
        name: "exit".to_string(),
        number: 1,
        address: 0x4000,
        desc: "Exit process".to_string(),
        arch: "aarch64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_syscall(
        Some(&vec!["exit".to_string()]),
        None,
        Some(&vec!["x86_64".to_string()]),
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1); // Only x86_64 match
}

#[test]
fn test_eval_syscall_min_count() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "read".to_string(),
        number: 0,
        address: 0x1000,
        desc: "Read from file".to_string(),
        arch: "x86_64".to_string(),
    });
    report.syscalls.push(SyscallInfo {
        name: "read".to_string(),
        number: 0,
        address: 0x2000,
        desc: "Read from file".to_string(),
        arch: "x86_64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // With 2 read syscalls, should match
    let result = eval_syscall(Some(&vec!["read".to_string()]), None, None, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 2); // Both read syscalls matched
}

#[test]
fn test_eval_syscall_no_match() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "read".to_string(),
        number: 0,
        address: 0x1000,
        desc: "Read from file".to_string(),
        arch: "x86_64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_syscall(Some(&vec!["ptrace".to_string()]), None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_syscall_combined_filters() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "socket".to_string(),
        number: 41,
        address: 0x1000,
        desc: "Create socket".to_string(),
        arch: "x86_64".to_string(),
    });
    report.syscalls.push(SyscallInfo {
        name: "socket".to_string(),
        number: 198, // Different syscall number on aarch64
        address: 0x2000,
        desc: "Create socket".to_string(),
        arch: "aarch64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Match socket syscall #41 on x86_64
    let result = eval_syscall(
        Some(&vec!["socket".to_string()]),
        Some(&vec![41]),
        Some(&vec!["x86_64".to_string()]),
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
}

#[test]
fn test_eval_section_entropy_min() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: Some(0x1000),
        offset: None,
        size: 1000,
        entropy: 7.5,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".data".to_string(),
        address: Some(0x2000),
        offset: None,
        size: 500,
        entropy: 3.0,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Match sections with entropy >= 7.0
    let result = eval_section(
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        Some(7.0),
        None,
        None, // readable
        None, // writable
        None, // executable
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
    assert!(result.evidence[0].value.contains(".text"));
    assert!(result.evidence[0].value.contains("entropy: 7.50"));
}

#[test]
fn test_eval_section_entropy_max() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: Some(0x1000),
        offset: None,
        size: 1000,
        entropy: 7.5,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".data".to_string(),
        address: Some(0x2000),
        offset: None,
        size: 500,
        entropy: 3.0,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Match sections with entropy <= 4.0
    let result = eval_section(
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        Some(4.0),
        None, // readable
        None, // writable
        None, // executable
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
    assert!(result.evidence[0].value.contains(".data"));
}

#[test]
fn test_eval_section_combined_constraints() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: "UPX0".to_string(),
        address: Some(0x1000),
        offset: None,
        size: 5000,
        entropy: 7.9,
        permissions: None,
    });
    report.sections.push(Section {
        name: "UPX1".to_string(),
        address: Some(0x2000),
        offset: None,
        size: 500,
        entropy: 7.8,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".text".to_string(),
        address: Some(0x3000),
        offset: None,
        size: 10000,
        entropy: 6.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Match UPX sections with high entropy and size > 1000
    let regex = "^UPX".to_string();
    let result = eval_section(
        None,
        None,
        Some(&regex),
        None,
        false,
        Some(1000),
        None,
        Some(7.5),
        None,
        None, // readable
        None, // writable
        None, // executable
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
    assert!(result.evidence[0].value.contains("UPX0"));
    assert!(result.evidence[0].value.contains("size: 5000"));
    assert!(result.evidence[0].value.contains("entropy: 7.90"));
}

#[test]
fn test_eval_section_precision_scoring() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: Some(0x1000),
        offset: None,
        size: 1000,
        entropy: 6.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Exact match should have highest precision
    let exact = ".text".to_string();
    let result1 = eval_section(
        Some(&exact),
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        // readable
        None,
        // writable
        None,
        None,
        None,
        None,
        // executable
        &ctx,
    );
    assert_eq!(result1.precision, 2.0);

    // Regex should have lower precision
    let regex = r"\.text".to_string();
    let result2 = eval_section(
        None,
        None,
        Some(&regex),
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        // readable
        None,
        // writable
        None,
        None,
        None,
        None,
        // executable
        &ctx,
    );
    assert_eq!(result2.precision, 1.5);

    // Substr should have even lower precision
    let substr = "text".to_string();
    let result3 = eval_section(
        None,
        Some(&substr),
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        // readable
        None,
        // writable
        None,
        None,
        None,
        None,
        // executable
        &ctx,
    );
    assert_eq!(result3.precision, 1.0);

    // Adding entropy constraints should increase precision
    let result4 = eval_section(
        None,
        Some(&substr),
        None,
        None,
        false,
        None,
        None,
        Some(6.0),
        Some(7.0),
        None,
        // readable
        None,
        // writable
        None,
        None,
        None,
        None,
        // executable
        &ctx,
    );
    assert_eq!(result4.precision, 2.0); // 1.0 (substr) + 0.5 (entropy_min) + 0.5 (entropy_max)
}

#[test]
fn test_eval_syscall_arch_exact_match() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "exit".to_string(),
        number: 60,
        address: 0x1000,
        desc: "Exit process".to_string(),
        arch: "x86_64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // "x86_64" should match exactly
    let result = eval_syscall(
        Some(&vec!["exit".to_string()]),
        None,
        Some(&vec!["x86_64".to_string()]),
        &ctx,
    );
    assert!(result.matched, "Exact arch match should succeed");

    // "x86" should NOT match "x86_64" (no substring matching)
    let result = eval_syscall(
        Some(&vec!["exit".to_string()]),
        None,
        Some(&vec!["x86".to_string()]),
        &ctx,
    );
    assert!(
        !result.matched,
        "Substring arch 'x86' should NOT match 'x86_64'"
    );

    // "64" should NOT match "x86_64"
    let result = eval_syscall(
        Some(&vec!["exit".to_string()]),
        None,
        Some(&vec!["64".to_string()]),
        &ctx,
    );
    assert!(
        !result.matched,
        "Substring arch '64' should NOT match 'x86_64'"
    );
}

// =============================================================================
// Section length_min / length_max tests
// =============================================================================

#[test]
fn test_eval_section_length_min() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: Some(0x1000),
        offset: None,
        size: 5000,
        entropy: 6.5,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".data".to_string(),
        address: Some(0x2000),
        offset: None,
        size: 200,
        entropy: 4.0,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // length_min: 1000 — only .text (5000) should match
    let result = eval_section(
        None,
        None,
        None,
        None,
        false,
        Some(1000), // length_min
        None,       // length_max
        None,
        None,
        None,
        None,
        None,
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
    assert!(result.evidence[0].value.contains(".text"));
    assert!(result.evidence[0].value.contains("size: 5000"));
}

#[test]
fn test_eval_section_length_min_no_match() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: Some(0x1000),
        offset: None,
        size: 500,
        entropy: 6.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // length_min: 1000 — .text (500) too small
    let result = eval_section(
        None,
        None,
        None,
        None,
        false,
        Some(1000),
        None,
        None,
        None,
        None,
        None,
        None,
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(!result.matched);
}

#[test]
fn test_eval_section_length_max() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: Some(0x1000),
        offset: None,
        size: 5000,
        entropy: 6.5,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".data".to_string(),
        address: Some(0x2000),
        offset: None,
        size: 200,
        entropy: 4.0,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // length_max: 1000 — only .data (200) should match
    let result = eval_section(
        None,
        None,
        None,
        None,
        false,
        None,       // length_min
        Some(1000), // length_max
        None,
        None,
        None,
        None,
        None,
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
    assert!(result.evidence[0].value.contains(".data"));
    assert!(result.evidence[0].value.contains("size: 200"));
}

#[test]
fn test_eval_section_length_range() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".small".to_string(),
        address: None,
        offset: None,
        size: 50,
        entropy: 4.0,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".medium".to_string(),
        address: None,
        offset: None,
        size: 500,
        entropy: 5.0,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".large".to_string(),
        address: None,
        offset: None,
        size: 50000,
        entropy: 7.0,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // length_min: 100, length_max: 10000 — only .medium (500) should match
    let result = eval_section(
        None,
        None,
        None,
        None,
        false,
        Some(100),
        Some(10000),
        None,
        None,
        None,
        None,
        None,
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
    assert!(result.evidence[0].value.contains(".medium"));
}

#[test]
fn test_eval_section_length_with_name_pattern() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: "UPX0".to_string(),
        address: None,
        offset: None,
        size: 10000,
        entropy: 7.9,
        permissions: None,
    });
    report.sections.push(Section {
        name: "UPX1".to_string(),
        address: None,
        offset: None,
        size: 200,
        entropy: 7.8,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Match UPX sections with size >= 5000
    let regex = "^UPX".to_string();
    let result = eval_section(
        None,
        None,
        Some(&regex),
        None,
        false,
        Some(5000),
        None,
        None,
        None,
        None,
        None,
        None,
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
    assert!(result.evidence[0].value.contains("UPX0"));
}

#[test]
fn test_eval_section_length_precision_boost() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: None,
        offset: None,
        size: 1000,
        entropy: 6.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Substr alone: precision 1.0
    let substr = "text".to_string();
    let result_base = eval_section(
        None,
        Some(&substr),
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &ctx,
    );
    assert_eq!(result_base.precision, 1.0);

    // Substr + length_min: precision 1.5
    let result_min = eval_section(
        None,
        Some(&substr),
        None,
        None,
        false,
        Some(500),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &ctx,
    );
    assert_eq!(result_min.precision, 1.5);

    // Substr + length_min + length_max: precision 2.0
    let result_both = eval_section(
        None,
        Some(&substr),
        None,
        None,
        false,
        Some(500),
        Some(5000),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        &ctx,
    );
    assert_eq!(result_both.precision, 2.0);
}

// =============================================================================
// T8: Section permission flags
// =============================================================================

#[test]
fn test_eval_section_executable_flag() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: Some(0x1000),
        offset: None,
        size: 1000,
        entropy: 6.5,
        permissions: Some("rx".to_string()),
    });
    report.sections.push(Section {
        name: ".data".to_string(),
        address: Some(0x2000),
        offset: None,
        size: 500,
        entropy: 4.0,
        permissions: Some("rw".to_string()),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Match only executable sections
    let result = eval_section(
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        None,       // readable
        None,       // writable
        Some(true), // executable = true
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(
        result.matched,
        ".text with 'rx' perms should match executable=true"
    );
    assert_eq!(result.evidence.len(), 1);
    assert!(result.evidence[0].value.contains(".text"));

    // .data has "rw" — not executable
    let result = eval_section(
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        None,       // readable
        None,       // writable
        Some(true), // executable = true
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    // Only .text should match, not .data
    assert_eq!(result.evidence.len(), 1, "Only .text should be executable");
}

#[test]
fn test_eval_section_permission_no_match() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: Some(0x1000),
        offset: None,
        size: 1000,
        entropy: 6.5,
        permissions: None, // No permissions info
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Section without permissions should fail strict permission checks
    let result = eval_section(
        None,
        None,
        None,
        None,
        false,
        None,
        None,
        None,
        None,
        Some(true), // readable = true
        None,
        None,
        None, // compare_to
        None, // ratio_min
        None, // ratio_max
        &ctx,
    );
    assert!(
        !result.matched,
        "Section without permissions should fail readable=true check"
    );
}

// =============================================================================
// T10: Syscall validation edge cases
// =============================================================================

#[test]
fn test_eval_syscall_empty_lists_no_match() {
    let mut report = create_test_report();
    report.syscalls.push(SyscallInfo {
        name: "read".to_string(),
        number: 0,
        address: 0x1000,
        desc: "Read from file".to_string(),
        arch: "x86_64".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Empty name list — should not match anything
    let empty_names: Vec<String> = vec![];
    let result = eval_syscall(Some(&empty_names), None, None, &ctx);
    assert!(
        !result.matched,
        "Empty name list should not match any syscalls"
    );

    // Empty number list — should not match anything
    let empty_numbers: Vec<u32> = vec![];
    let result = eval_syscall(None, Some(&empty_numbers), None, &ctx);
    assert!(
        !result.matched,
        "Empty number list should not match any syscalls"
    );
}
