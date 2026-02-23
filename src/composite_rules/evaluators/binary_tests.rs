//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for binary analysis condition evaluators.

use super::*;
use crate::composite_rules::context::EvaluationContext;
use crate::composite_rules::types::{FileType, Platform};
use crate::types::{AnalysisReport, Export, Import, Section, SyscallInfo, TargetInfo};
use std::sync::OnceLock;

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
    EvaluationContext {
        report,
        binary_data: data,
        file_type: FileType::Elf,
        platforms: vec![Platform::Linux],
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

// =============================================================================
// eval_exports_count tests
// =============================================================================

#[test]
fn test_eval_exports_count_min() {
    let mut report = create_test_report();
    report.exports.push(Export {
        symbol: "init".to_string(),
        offset: Some("0x1000".to_string()),
        source: "elf".to_string(),
    });
    report.exports.push(Export {
        symbol: "main".to_string(),
        offset: Some("0x2000".to_string()),
        source: "elf".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_exports_count(Some(1), None, &ctx);
    assert!(result.matched);

    let result = eval_exports_count(Some(5), None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_exports_count_max() {
    let mut report = create_test_report();
    for i in 0..3 {
        report.exports.push(Export {
            symbol: format!("export_{}", i),
            offset: Some(format!("0x{:x}", i * 0x1000)),
            source: "elf".to_string(),
        });
    }
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_exports_count(None, Some(5), &ctx);
    assert!(result.matched);

    let result = eval_exports_count(None, Some(2), &ctx);
    assert!(!result.matched);
}

// =============================================================================
// eval_section_ratio tests
// =============================================================================

#[test]
fn test_eval_section_ratio_vs_total() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: None,
        size: 500,
        entropy: 6.5,
        permissions: Some("rx".to_string()),
    });
    report.sections.push(Section {
        name: ".data".to_string(),
        address: None,
        size: 300,
        entropy: 4.0,
        permissions: Some("rw".to_string()),
    });
    report.sections.push(Section {
        name: ".rodata".to_string(),
        address: None,
        size: 200,
        entropy: 5.0,
        permissions: Some("r".to_string()),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // .text is 500/1000 = 50% of total
    let result = eval_section_ratio(
        r"\.text",
        "total",
        Some(0.4), // min 40%
        Some(0.6), // max 60%
        &ctx,
    );
    assert!(result.matched);
    assert!(result.evidence[0].value.contains("50.0%"));
}

#[test]
fn test_eval_section_ratio_vs_another_section() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: None,
        size: 1000,
        entropy: 6.5,
        permissions: Some("rx".to_string()),
    });
    report.sections.push(Section {
        name: ".data".to_string(),
        address: None,
        size: 500,
        entropy: 4.0,
        permissions: Some("rw".to_string()),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // .text is 1000/500 = 2.0x .data
    let result = eval_section_ratio(r"\.text", r"\.data", Some(1.5), Some(2.5), &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_section_ratio_no_matching_section() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: None,
        size: 1000,
        entropy: 6.5,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_section_ratio(r"\.nonexistent", "total", Some(0.1), None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_section_ratio_invalid_regex() {
    let report = create_test_report();
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_section_ratio("[invalid regex", "total", Some(0.1), None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_section_ratio_multiple_matching_sections() {
    let mut report = create_test_report();
    report.sections.push(Section {
        name: ".text".to_string(),
        address: None,
        size: 400,
        entropy: 6.5,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".text2".to_string(),
        address: None,
        size: 100,
        entropy: 6.0,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".data".to_string(),
        address: None,
        size: 500,
        entropy: 4.0,
        permissions: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // .text + .text2 = 500 / 1000 = 50%
    let result = eval_section_ratio(
        r"\.text", // Matches both .text and .text2
        "total",
        Some(0.4),
        Some(0.6),
        &ctx,
    );
    assert!(result.matched);
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
        size: 500,
        entropy: 6.5,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".text.plt".to_string(),
        address: None,
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
        size: 500,
        entropy: 6.5,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".text.plt".to_string(),
        address: None,
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
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence[0].value, ".TEXT");
}

// =============================================================================
// eval_import_combination tests
// =============================================================================

#[test]
fn test_eval_import_combination_required_only() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "VirtualAlloc".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    report.imports.push(Import {
        symbol: "WriteProcessMemory".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let required = vec!["VirtualAlloc".to_string(), "WriteProcessMemory".to_string()];

    let result = eval_import_combination(Some(&required), None, None, None, &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_import_combination_required_missing() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "VirtualAlloc".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let required = vec![
        "VirtualAlloc".to_string(),
        "WriteProcessMemory".to_string(), // Missing!
    ];

    let result = eval_import_combination(Some(&required), None, None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_import_combination_suspicious() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "VirtualAlloc".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    report.imports.push(Import {
        symbol: "CreateRemoteThread".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let required = vec!["VirtualAlloc".to_string()];
    let suspicious = vec![
        "CreateRemoteThread".to_string(),
        "NtUnmapViewOfSection".to_string(),
    ];

    let result = eval_import_combination(
        Some(&required),
        Some(&suspicious),
        Some(1), // At least 1 suspicious
        None,
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_eval_import_combination_min_suspicious() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "VirtualAlloc".to_string(),
        library: None,
        source: "pe".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let required = vec!["VirtualAlloc".to_string()];
    let suspicious = vec![
        "CreateRemoteThread".to_string(),
        "NtUnmapViewOfSection".to_string(),
    ];

    // Require 1 suspicious but have 0
    let result = eval_import_combination(Some(&required), Some(&suspicious), Some(1), None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_import_combination_max_total() {
    let mut report = create_test_report();
    for i in 0..20 {
        report.imports.push(Import {
            symbol: format!("func_{}", i),
            library: None,
            source: "lib".to_string(),
        });
    }
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Max 10 imports but we have 20
    let result = eval_import_combination(None, None, None, Some(10), &ctx);
    assert!(!result.matched);

    // Max 30 imports
    let result = eval_import_combination(None, None, None, Some(30), &ctx);
    assert!(result.matched);
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
        size: 1000,
        entropy: 7.5,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".data".to_string(),
        address: Some(0x2000),
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
        size: 1000,
        entropy: 7.5,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".data".to_string(),
        address: Some(0x2000),
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
        size: 5000,
        entropy: 7.9,
        permissions: None,
    });
    report.sections.push(Section {
        name: "UPX1".to_string(),
        address: Some(0x2000),
        size: 500,
        entropy: 7.8,
        permissions: None,
    });
    report.sections.push(Section {
        name: ".text".to_string(),
        address: Some(0x3000),
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
        None, // readable
        None, // writable
        None, // executable
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
        None, // readable
        None, // writable
        None, // executable
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
        None, // readable
        None, // writable
        None, // executable
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
        None, // readable
        None, // writable
        None, // executable
        &ctx,
    );
    assert_eq!(result4.precision, 2.0); // 1.0 (substr) + 0.5 (entropy_min) + 0.5 (entropy_max)
}
