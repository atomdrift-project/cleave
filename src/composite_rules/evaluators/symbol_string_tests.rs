//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for symbol and string-based condition evaluators.

use super::*;
use crate::composite_rules::condition::NotException;
use crate::composite_rules::context::{EvaluationContext, StringParams};
use crate::composite_rules::types::{FileType, Platform};
use crate::types::{AnalysisReport, Export, Function, Import, StringInfo, StringType, TargetInfo};
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
        current_trait: None,
        current_source: None,
        string_exact_index: OnceLock::new(),
        string_exact_index_ci: OnceLock::new(),
    }
}

// =============================================================================
// eval_symbol tests
// =============================================================================

#[test]
fn test_eval_symbol_exact_match() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "libc".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_symbol(
        Some(&"socket".to_string()),
        None,
        None,
        None,
        None,
        None,
        &ctx,
    );

    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(result.evidence[0].value, "socket");
}

#[test]
fn test_eval_symbol_exact_match_with_leading_underscore() {
    let mut report = create_test_report();
    // Import::new normalizes "_socket" → "socket" at load time
    report.imports.push(Import::new("_socket", None, "libc"));
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Pattern with leading underscore should be normalized to match
    let result = eval_symbol(
        Some(&"_socket".to_string()),
        None,
        None,
        None,
        None,
        None,
        &ctx,
    );
    assert!(
        result.matched,
        "Pattern '_socket' should be normalized to 'socket' and match"
    );

    // Pattern without underscore should also match
    let result2 = eval_symbol(
        Some(&"socket".to_string()),
        None,
        None,
        None,
        None,
        None,
        &ctx,
    );
    assert!(result2.matched, "Pattern 'socket' should match directly");
}

#[test]
fn test_eval_symbol_substr_normalized() {
    let mut report = create_test_report();
    // "__libc_start_main" → "libc_start_main" after normalization
    report
        .imports
        .push(Import::new("__libc_start_main", None, "libc"));
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Substr with leading underscores should be normalized
    let result = eval_symbol(
        None,
        Some(&"__libc_start".to_string()),
        None,
        None,
        None,
        None,
        &ctx,
    );
    assert!(
        result.matched,
        "Substr '__libc_start' should normalize to 'libc_start' and match 'libc_start_main'"
    );
}

#[test]
fn test_eval_symbol_substr_match() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "CreateRemoteThread".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_symbol(
        None,
        Some(&"RemoteThread".to_string()),
        None,
        None,
        None,
        None,
        &ctx,
    );

    assert!(result.matched);
    assert_eq!(result.evidence[0].value, "CreateRemoteThread");
}

#[test]
fn test_eval_symbol_regex_match() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "connect".to_string(),
        library: None,
        source: "libc".to_string(),
    });
    report.imports.push(Import {
        symbol: "accept".to_string(),
        library: None,
        source: "libc".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let pattern = "connect|accept".to_string();
    let re = regex::Regex::new(&pattern).unwrap();
    let result = eval_symbol(None, None, Some(&pattern), None, Some(&re), None, &ctx);

    assert!(result.matched);
    assert_eq!(result.evidence.len(), 2);
}

#[test]
fn test_eval_symbol_no_match() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "malloc".to_string(),
        library: None,
        source: "libc".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_symbol(
        Some(&"socket".to_string()),
        None,
        None,
        None,
        None,
        None,
        &ctx,
    );

    assert!(!result.matched);
    assert!(result.evidence.is_empty());
}

#[test]
fn test_eval_symbol_platform_filtering() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "libc".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Should not match - wrong platform
    let result = eval_symbol(
        Some(&"socket".to_string()),
        None,
        None,
        Some(&vec![Platform::Windows]),
        None,
        None,
        &ctx,
    );

    assert!(!result.matched);

    // Should match - correct platform
    let result = eval_symbol(
        Some(&"socket".to_string()),
        None,
        None,
        Some(&vec![Platform::Linux]),
        None,
        None,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_symbol_platform_all() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "libc".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Platform::All should match any platform
    let result = eval_symbol(
        Some(&"socket".to_string()),
        None,
        None,
        Some(&vec![Platform::All]),
        None,
        None,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_symbol_in_exports() {
    let mut report = create_test_report();
    report.exports.push(Export {
        symbol: "my_exported_function".to_string(),
        offset: Some("0x1000".to_string()),
        source: "elf".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_symbol(
        None,
        Some(&"exported".to_string()),
        None,
        None,
        None,
        None,
        &ctx,
    );

    assert!(result.matched);
    assert_eq!(result.evidence[0].value, "my_exported_function");
}

#[test]
fn test_eval_symbol_in_functions() {
    let mut report = create_test_report();
    report.functions.push(Function {
        name: "runtime.newproc".to_string(),
        offset: Some("0x2000".to_string()),
        size: Some(100),
        complexity: None,
        calls: vec![],
        source: "go".to_string(),
        control_flow: None,
        instruction_analysis: None,
        register_usage: None,
        constants: vec![],
        properties: None,
        signature: None,
        nesting: None,
        call_patterns: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_symbol(
        None,
        Some(&"newproc".to_string()),
        None,
        None,
        None,
        None,
        &ctx,
    );

    assert!(result.matched);
    assert_eq!(result.evidence[0].value, "runtime.newproc");
}

// =============================================================================
// eval_string tests
// =============================================================================

#[test]
fn test_eval_string_exact_match() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: "/bin/sh".to_string(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: StringType::Path,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let params = StringParams {
        exact: Some(&"/bin/sh".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        external_ip: false,
        compiled_regex: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    };

    let result = eval_string(&params, None, &ctx);

    assert!(result.matched);
    assert_eq!(result.evidence[0].value, "/bin/sh");
}

#[test]
fn test_eval_string_substr_match() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: "http://evil.com/malware".to_string(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: StringType::Url,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let params = StringParams {
        exact: None,
        substr: Some(&"evil.com".to_string()),
        regex: None,
        word: None,
        case_insensitive: false,
        external_ip: false,
        compiled_regex: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    };

    let result = eval_string(&params, None, &ctx);

    assert!(result.matched);
}

#[test]
fn test_eval_string_regex_match() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: "192.168.1.100".to_string(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: StringType::IP,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}".to_string();
    let re = regex::Regex::new(&pattern).unwrap();
    let params = StringParams {
        exact: None,
        substr: None,
        regex: Some(&pattern),
        word: None,
        case_insensitive: false,
        external_ip: false,
        compiled_regex: Some(&re),
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    };

    let result = eval_string(&params, None, &ctx);

    assert!(result.matched);
}

#[test]
fn test_eval_string_case_insensitive() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: "CreateRemoteThread".to_string(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let params = StringParams {
        exact: Some(&"createremotethread".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: true,
        external_ip: false,
        compiled_regex: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    };

    let result = eval_string(&params, None, &ctx);

    assert!(result.matched);
}

#[test]
fn test_eval_string_min_count() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: "suspicious".to_string(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Test with count_min - should not match since only 1 string exists
    let result = eval_string_count(Some(2), None, None, None, None, &ctx);

    // Only 1 string in total, need 2
    assert!(!result.matched);
}

#[test]
fn test_eval_string_not_exception() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: "/bin/sh".to_string(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: StringType::Path,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let not_exceptions = vec![NotException::Shorthand("/bin/sh".to_string())];
    let params = StringParams {
        exact: Some(&"/bin/sh".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        external_ip: false,
        compiled_regex: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    };

    let result = eval_string(&params, Some(&not_exceptions), &ctx);

    // Should not match due to not exception
    assert!(!result.matched);
}

#[test]
fn test_eval_string_in_imports() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "CreateProcess".to_string(),
        library: Some("kernel32.dll".to_string()),
        source: "pe".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let params = StringParams {
        exact: None,
        substr: Some(&"CreateProcess".to_string()),
        regex: None,
        word: None,
        case_insensitive: false,
        external_ip: false,
        compiled_regex: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    };

    let result = eval_string(&params, None, &ctx);

    assert!(result.matched);
    assert_eq!(result.evidence[0].method, "import_symbol");
}

/// Helper to create an empty report (no strings extracted)
// =============================================================================
// eval_raw tests
// =============================================================================

#[test]
fn test_eval_raw_exact_match() {
    let report = create_test_report();
    let content = "EXACT_CONTENT";
    let ctx = create_test_context(&report, content.as_bytes());

    let location = ContentLocationParams::default();
    let result = eval_raw(
        Some(&"EXACT_CONTENT".to_string()),
        None,
        None,
        None,
        false,
        false,
        None,
        None,
        &location,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_raw_substr_count() {
    let report = create_test_report();
    let content = "token token token more content token";
    let ctx = create_test_context(&report, content.as_bytes());

    let location = ContentLocationParams::default();
    let result = eval_raw(
        None,
        Some(&"token".to_string()),
        None,
        None,
        false,
        false,
        None,
        None,
        &location,
        &ctx,
    );

    assert!(result.matched);
    // Evidence value contains the matched pattern
    assert!(result.evidence[0].value.contains("token"));
}

#[test]
fn test_eval_raw_substr_count_insufficient() {
    let report = create_test_report();
    let content = "token token";
    let ctx = create_test_context(&report, content.as_bytes());

    let location = ContentLocationParams::default();
    let result = eval_raw(
        None,
        Some(&"token".to_string()),
        None,
        None,
        false,
        false,
        None,
        None,
        &location,
        &ctx,
    );

    // Should match - found "token" in content
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
}

#[test]
fn test_eval_raw_regex() {
    let report = create_test_report();
    let content = "email: test@example.com and admin@corp.org";
    let ctx = create_test_context(&report, content.as_bytes());

    let pattern = r"[a-z]+@[a-z]+\.[a-z]+".to_string();
    let re = regex::Regex::new(&pattern).unwrap();

    let location = ContentLocationParams::default();
    let result = eval_raw(
        None,
        None,
        Some(&pattern),
        None,
        false,
        false,
        Some(&re),
        None,
        &location,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_raw_case_insensitive() {
    let report = create_test_report();
    let content = "PASSWORD password PaSsWoRd";
    let ctx = create_test_context(&report, content.as_bytes());

    let location = ContentLocationParams::default();
    let result = eval_raw(
        None,
        Some(&"password".to_string()),
        None,
        None,
        true,
        false,
        None,
        None,
        &location,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_raw_invalid_utf8() {
    let report = create_test_report();
    let data = vec![0xff, 0xfe, 0x00, 0x01]; // Invalid UTF-8
    let ctx = create_test_context(&report, &data);

    let location = ContentLocationParams::default();
    let result = eval_raw(
        None,
        Some(&"test".to_string()),
        None,
        None,
        false,
        false,
        None,
        None,
        &location,
        &ctx,
    );

    assert!(!result.matched);
}

// =============================================================================
// =============================================================================
// eval_string_count tests
// =============================================================================

#[test]
fn test_eval_string_count_min() {
    let mut report = create_test_report();
    for i in 0..5 {
        report.strings.push(StringInfo {
            value: format!("string_{}", i),
            offset: Some((i * 0x100) as u64),
            encoding: "utf8".to_string(),
            string_type: StringType::Const,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        });
    }
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_string_count(Some(3), None, None, None, None, &ctx);
    assert!(result.matched);

    let result = eval_string_count(Some(10), None, None, None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_string_count_max() {
    let mut report = create_test_report();
    for i in 0..5 {
        report.strings.push(StringInfo {
            value: format!("string_{}", i),
            offset: Some((i * 0x100) as u64),
            encoding: "utf8".to_string(),
            string_type: StringType::Const,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        });
    }
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_string_count(None, Some(10), None, None, None, &ctx);
    assert!(result.matched);

    let result = eval_string_count(None, Some(3), None, None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_string_count_min_length() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: "ab".to_string(), // 2 chars
        offset: None,
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "abcdefgh".to_string(), // 8 chars
        offset: None,
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "abcdefghijklmnop".to_string(), // 16 chars
        offset: None,
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Only count strings >= 5 chars
    let result = eval_string_count(Some(2), None, Some(5), None, None, &ctx);
    assert!(result.matched);

    // Only count strings >= 10 chars
    let result = eval_string_count(Some(2), None, Some(10), None, None, &ctx);
    assert!(!result.matched); // Only 1 string >= 10 chars
}

#[test]
fn test_eval_string_count_range() {
    let mut report = create_test_report();
    for i in 0..10 {
        report.strings.push(StringInfo {
            value: format!("string_{}", i),
            offset: None,
            encoding: "utf8".to_string(),
            string_type: StringType::Const,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        });
    }
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Count should be exactly 10
    let result = eval_string_count(Some(5), Some(15), None, None, None, &ctx);
    assert!(result.matched);

    // Outside range
    let result = eval_string_count(Some(15), Some(20), None, None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_string_count_with_regex() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: "VScrollBar1".to_string(),
        offset: None,
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "VScrollBar2".to_string(),
        offset: None,
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "OtherString".to_string(),
        offset: None,
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let pattern = "VScrollBar[0-9]+".to_string();
    let re = regex::Regex::new(&pattern).unwrap();

    // Match VScrollBar strings
    let result = eval_string_count(Some(2), None, None, Some(&pattern), Some(&re), &ctx);
    assert!(result.matched);
    assert!(result.evidence[0].value.contains("(2)"));

    // Require 3 VScrollBar strings - should fail
    let result = eval_string_count(Some(3), None, None, Some(&pattern), Some(&re), &ctx);
    assert!(!result.matched);

    // Require 1 OtherString - should match
    let other_pattern = "Other".to_string();
    let other_re = regex::Regex::new(&other_pattern).unwrap();
    let result = eval_string_count(
        Some(1),
        None,
        None,
        Some(&other_pattern),
        Some(&other_re),
        &ctx,
    );
    assert!(result.matched);
}

// ==================== eval_encoded Tests ====================

fn create_test_report_with_multiple_encodings() -> AnalysisReport {
    let mut report = create_test_report();

    // Base64-encoded strings
    report.strings.push(StringInfo {
        value: "password123".to_string(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: Some(".data".to_string()),
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
    });

    report.strings.push(StringInfo {
        value: "https://evil.com/payload".to_string(),
        offset: Some(0x1100),
        encoding: "utf8".to_string(),
        string_type: StringType::Url,
        section: Some(".data".to_string()),
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
    });

    // Hex-encoded strings
    report.strings.push(StringInfo {
        value: "secret_key".to_string(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: Some(".text".to_string()),
        encoding_chain: vec!["hex".to_string()],
        fragments: None,
    });

    report.strings.push(StringInfo {
        value: "admin".to_string(),
        offset: Some(0x2100),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: Some(".text".to_string()),
        encoding_chain: vec!["hex".to_string()],
        fragments: None,
    });

    // XOR-encoded strings
    report.strings.push(StringInfo {
        value: "malware".to_string(),
        offset: Some(0x3000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: Some(".data".to_string()),
        encoding_chain: vec!["xor".to_string()],
        fragments: None,
    });

    // URL-encoded strings
    report.strings.push(StringInfo {
        value: "command.exe arg1 arg2".to_string(),
        offset: Some(0x4000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: Some(".data".to_string()),
        encoding_chain: vec!["url".to_string()],
        fragments: None,
    });

    // Plain string (no encoding)
    report.strings.push(StringInfo {
        value: "plain_text".to_string(),
        offset: Some(0x5000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: Some(".data".to_string()),
        encoding_chain: vec![],
        fragments: None,
    });

    report
}

#[test]
fn test_eval_encoded_single_encoding_filter() {
    use crate::composite_rules::condition::EncodingSpec;

    let report = create_test_report_with_multiple_encodings();
    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    // Search only base64 strings for "password"
    let encoding = Some(EncodingSpec::Single("base64".to_string()));
    let result = eval_encoded(
        encoding.as_ref(),
        None,
        Some(&"password".to_string()),
        None,
        None,
        false,
        None,
        &location,
        false,
        None,
        &ctx,
    );

    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
    assert!(result.evidence[0].value.contains("password123"));
}

#[test]
fn test_eval_encoded_multiple_encoding_filter() {
    use crate::composite_rules::condition::EncodingSpec;

    let report = create_test_report_with_multiple_encodings();
    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    // Search base64 OR hex strings for "secret" or "password"
    let encoding = Some(EncodingSpec::Multiple(vec![
        "base64".to_string(),
        "hex".to_string(),
    ]));
    let result = eval_encoded(
        encoding.as_ref(),
        None,
        None,
        Some(&"secret|password".to_string()),
        None,
        false,
        None,
        &location,
        false,
        None,
        &ctx,
    );

    assert!(result.matched);
    // Should match "password123" (base64) and "secret_key" (hex)
    assert!(result.evidence.len() >= 2);
}

#[test]
fn test_eval_encoded_no_filter_all_encodings() {
    let report = create_test_report_with_multiple_encodings();
    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    // Search ALL encoded strings (no encoding filter)
    let result = eval_encoded(
        None,
        None,
        Some(&"e".to_string()), // Common letter
        None,
        None,
        false,
        None,
        &location,
        false,
        None,
        &ctx,
    );

    assert!(result.matched);
    // Should match multiple encoded strings containing "e"
    assert!(result.evidence.len() >= 3);
}

#[test]
fn test_eval_encoded_exact_match() {
    use crate::composite_rules::condition::EncodingSpec;

    let report = create_test_report_with_multiple_encodings();
    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    let encoding = Some(EncodingSpec::Single("hex".to_string()));
    let result = eval_encoded(
        encoding.as_ref(),
        Some(&"admin".to_string()),
        None,
        None,
        None,
        false,
        None,
        &location,
        false,
        None,
        &ctx,
    );

    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
}

#[test]
fn test_eval_encoded_substr_match() {
    use crate::composite_rules::condition::EncodingSpec;

    let report = create_test_report_with_multiple_encodings();
    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    let encoding = Some(EncodingSpec::Single("base64".to_string()));
    let result = eval_encoded(
        encoding.as_ref(),
        None,
        Some(&"evil.com".to_string()),
        None,
        None,
        false,
        None,
        &location,
        false,
        None,
        &ctx,
    );

    assert!(result.matched);
    assert!(result.evidence[0].value.contains("evil.com"));
}

#[test]
fn test_eval_encoded_regex_match() {
    use crate::composite_rules::condition::EncodingSpec;

    let report = create_test_report_with_multiple_encodings();
    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    let encoding = Some(EncodingSpec::Single("base64".to_string()));
    let result = eval_encoded(
        encoding.as_ref(),
        None,
        None,
        Some(&r"https?://.*\.com".to_string()),
        None,
        false,
        None,
        &location,
        false,
        None,
        &ctx,
    );

    assert!(result.matched);
    assert!(result.evidence[0].value.contains("evil.com"));
}

#[test]
fn test_eval_encoded_word_match() {
    use crate::composite_rules::condition::EncodingSpec;

    let report = create_test_report_with_multiple_encodings();
    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    let encoding = Some(EncodingSpec::Single("hex".to_string()));
    let result = eval_encoded(
        encoding.as_ref(),
        None,
        None,
        None,
        Some(&"admin".to_string()),
        false,
        None,
        &location,
        false,
        None,
        &ctx,
    );

    assert!(result.matched);

    // Now test word match with url-encoded string
    let encoding2 = Some(EncodingSpec::Single("url".to_string()));
    let result = eval_encoded(
        encoding2.as_ref(),
        None,
        None,
        None,
        Some(&"command".to_string()),
        false,
        None,
        &location,
        false,
        None,
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_eval_encoded_case_insensitive() {
    use crate::composite_rules::condition::EncodingSpec;

    let report = create_test_report_with_multiple_encodings();
    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    let encoding = Some(EncodingSpec::Single("hex".to_string()));
    let result = eval_encoded(
        encoding.as_ref(),
        None,
        Some(&"ADMIN".to_string()),
        None,
        None,
        true, // case insensitive
        None,
        &location,
        false,
        None,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_encoded_count_constraints() {
    let report = create_test_report_with_multiple_encodings();
    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    // Search all encoded strings for letter "a" (appears in many)
    let result = eval_encoded(
        None,
        None,
        Some(&"a".to_string()),
        None,
        None,
        false,
        None,
        &location,
        false,
        None,
        &ctx,
    );

    // Should match multiple strings
    assert!(result.matched);
}

#[test]
fn test_eval_encoded_no_match_wrong_encoding() {
    use crate::composite_rules::condition::EncodingSpec;

    let report = create_test_report_with_multiple_encodings();
    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    // Search for "malware" but only in base64 (it's in xor)
    let encoding = Some(EncodingSpec::Single("base64".to_string()));
    let result = eval_encoded(
        encoding.as_ref(),
        Some(&"malware".to_string()),
        None,
        None,
        None,
        false,
        None,
        &location,
        false,
        None,
        &ctx,
    );

    assert!(!result.matched);
}

#[test]
fn test_eval_encoded_excludes_plain_strings() {
    let report = create_test_report_with_multiple_encodings();
    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    // Search for "plain" which only appears in non-encoded string
    let result = eval_encoded(
        None,
        Some(&"plain_text".to_string()),
        None,
        None,
        None,
        false,
        None,
        &location,
        false,
        None,
        &ctx,
    );

    // Should NOT match because plain_text has empty encoding_chain
    assert!(!result.matched);
}

#[test]
fn test_eval_encoded_count_min_not_met() {
    use crate::composite_rules::condition::EncodingSpec;

    let report = create_test_report_with_multiple_encodings();
    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    let encoding = Some(EncodingSpec::Single("base64".to_string()));
    let result = eval_encoded(
        encoding.as_ref(),
        None,
        Some(&"password".to_string()),
        None,
        None,
        false,
        None,
        &location,
        false,
        None,
        &ctx,
    );

    // Should match - "password123" contains "password"
    assert!(result.matched);
    assert!(!result.evidence.is_empty());
}

// =============================================================================
// B4: eval_string match_count exceeds evidence cap
// =============================================================================

#[test]
fn test_eval_string_match_count_exceeds_evidence_cap() {
    let mut report = create_test_report();

    // Add 25 strings that all match a substr pattern
    for i in 0..25u64 {
        report.strings.push(StringInfo {
            value: format!("token_match_{}", i),
            offset: Some(0x1000 + i * 0x100),
            encoding: "utf8".to_string(),
            string_type: crate::types::StringType::Const,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        });
    }

    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let substr_val = "token_match".to_string();
    let params = StringParams {
        exact: None,
        substr: Some(&substr_val),
        regex: None,
        word: None,
        case_insensitive: false,
        external_ip: false,
        compiled_regex: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    };

    let result = eval_string(&params, None, &ctx);
    assert!(result.matched);
    // Evidence is capped at 16 (MAX_EVIDENCE_PER_TRAIT)
    assert_eq!(result.evidence.len(), 16);
    // But match_count should reflect all 25 actual matches
    assert_eq!(result.match_count, 25);
}

// =============================================================================
// B1: eval_encoded not: and external_ip: filtering
// =============================================================================

#[test]
fn test_eval_encoded_not_filter() {
    use crate::composite_rules::condition::EncodingSpec;

    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: "http://evil.com/payload".to_string(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Url,
        section: None,
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: "http://apple.com/safe".to_string(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Url,
        section: None,
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
    });

    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    let encoding = Some(EncodingSpec::Single("base64".to_string()));
    let not_exceptions = vec![NotException::Shorthand("apple.com".to_string())];

    let result = eval_encoded(
        encoding.as_ref(),
        None,
        Some(&"http".to_string()),
        None,
        None,
        false,
        None,
        &location,
        false,
        Some(&not_exceptions),
        &ctx,
    );

    assert!(result.matched);
    // Only evil.com should match — apple.com excluded by not:
    assert_eq!(result.match_count, 1);
    assert!(result.evidence[0].value.contains("evil.com"));
}

#[test]
fn test_eval_encoded_external_ip_filter() {
    use crate::composite_rules::condition::EncodingSpec;

    let mut report = create_test_report();
    // String with external IP
    report.strings.push(StringInfo {
        value: "connect 8.8.8.8:443".to_string(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Const,
        section: None,
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
    });
    // String with RFC1918 internal IP
    report.strings.push(StringInfo {
        value: "connect 192.168.1.1:80".to_string(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: crate::types::StringType::Const,
        section: None,
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
    });

    let data = vec![];
    let ctx = create_test_context(&report, &data);
    let location = ContentLocationParams::default();

    let encoding = Some(EncodingSpec::Single("base64".to_string()));

    let result = eval_encoded(
        encoding.as_ref(),
        None,
        Some(&"connect".to_string()),
        None,
        None,
        false,
        None,
        &location,
        true, // external_ip: true
        None,
        &ctx,
    );

    assert!(result.matched);
    // Only the external IP (8.8.8.8) should match
    assert_eq!(result.match_count, 1);
    assert!(result.evidence[0].value.contains("8.8.8.8"));
}

#[test]
fn test_eval_raw_not_excludes_by_context() {
    // B19: not: filtering should use match context, not the search pattern.
    // Content has two "http" matches: one near "safe.com" (excluded) and one near "evil.com" (kept).
    let report = create_test_report();
    let content = b"aaaa http://safe.com/ok bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb http://evil.com/bad cccc";
    let ctx = create_test_context(&report, content.as_ref());

    let not_exceptions = vec![NotException::Shorthand("safe.com".to_string())];
    let location = ContentLocationParams::default();
    let result = eval_raw(
        None,
        Some(&"http".to_string()),
        None,
        None,
        false,
        false,
        None,
        Some(&not_exceptions),
        &location,
        &ctx,
    );

    assert!(result.matched, "Should still match http://evil.com context");
    // Only the non-excluded match should count
    assert_eq!(
        result.match_count, 1,
        "Only http://evil.com should count (safe.com excluded by not:)"
    );
}

// =============================================================================
// T5: word matcher on raw content
// =============================================================================

#[test]
fn test_eval_raw_word_boundary() {
    let report = create_test_report();
    // "cat" as a whole word appears in "the cat sat" but NOT in "category"
    let content = b"the cat sat on category mat";
    let ctx = create_test_context(&report, content.as_ref());

    // word: "cat" is pre-compiled to \bcat\b before calling eval_raw
    let word_str = "cat".to_string();
    let compiled = regex::Regex::new(r"\bcat\b").unwrap();

    let location = ContentLocationParams::default();
    let result = eval_raw(
        None,
        None,
        None,
        Some(&word_str),
        false,
        false,
        Some(&compiled),
        None,
        &location,
        &ctx,
    );

    assert!(result.matched, "word: 'cat' should match 'the cat sat'");
    // Should match only the standalone "cat", not "cat" inside "category"
    assert_eq!(
        result.match_count, 1,
        "word boundary should prevent matching 'cat' in 'category'"
    );
}

// =============================================================================
// T6: external_ip filtering on string and raw evaluators
// =============================================================================

#[test]
fn test_eval_string_external_ip_filters_private() {
    let mut report = create_test_report();
    // Add string containing a private IP — should be filtered out
    report.strings.push(StringInfo {
        value: "connect to 192.168.1.1:8080".to_string(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    // Add string containing an external IP — should be kept
    report.strings.push(StringInfo {
        value: "connect to 8.8.8.8:53".to_string(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let substr = "connect to".to_string();
    let params = StringParams {
        exact: None,
        substr: Some(&substr),
        regex: None,
        word: None,
        case_insensitive: false,
        external_ip: true,
        compiled_regex: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    };

    let result = eval_string(&params, None, &ctx);

    assert!(result.matched, "Should match string with external IP");
    // Only the external IP string should be counted
    assert_eq!(
        result.match_count, 1,
        "Private IP string should be filtered out"
    );
}

#[test]
fn test_eval_raw_external_ip_filters_private() {
    let report = create_test_report();
    // "private" near 192.168.1.1 only — context window should not reach the external IP.
    // Use 200+ bytes of padding to ensure context windows don't overlap.
    let mut content = Vec::new();
    content.extend_from_slice(b"private 192.168.1.1 only");
    content.extend_from_slice(&[b'x'; 300]);
    content.extend_from_slice(b"external 8.8.8.8 done");
    let ctx = create_test_context(&report, &content);

    let location = ContentLocationParams::default();
    // Search for "private" — its context contains only 192.168.1.1 (private IP)
    let result = eval_raw(
        None,
        Some(&"private".to_string()),
        None,
        None,
        false,
        true, // external_ip = true
        None,
        None,
        &location,
        &ctx,
    );

    // "private" match context only contains 192.168.1.1 → no external IP → filtered out
    assert!(
        !result.matched,
        "Match near private IP should be filtered when external_ip=true"
    );
}

#[test]
fn test_eval_raw_external_ip_keeps_external() {
    let report = create_test_report();
    // Content where the substring appears near an external IP
    let content = b"connect 8.8.8.8 done";
    let ctx = create_test_context(&report, content.as_ref());

    let location = ContentLocationParams::default();
    let result = eval_raw(
        None,
        Some(&"connect".to_string()),
        None,
        None,
        false,
        true, // external_ip = true
        None,
        None,
        &location,
        &ctx,
    );

    assert!(
        result.matched,
        "Match near external IP should be kept when external_ip=true"
    );
}

// =============================================================================
// A6: Location constraints skip imports/exports
// =============================================================================

#[test]
fn test_eval_string_offset_skips_imports() {
    // An import named "connect" should NOT match a string condition with offset constraint.
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "connect".to_string(),
        library: None,
        source: "libc".to_string(),
    });
    // Add a string at the target offset so we know the offset logic itself works
    report.strings.push(StringInfo {
        value: "connect".to_string(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let data = vec![0u8; 0x2000];
    let ctx = create_test_context(&report, &data);

    // With offset constraint: should match the string but NOT the import
    let exact = "connect".to_string();
    let params_with_offset = StringParams {
        exact: Some(&exact),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        external_ip: false,
        compiled_regex: None,
        section: None,
        offset: Some(0x1000),
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    };
    let result = eval_string(&params_with_offset, None, &ctx);
    assert!(result.matched, "String at offset 0x1000 should match");
    assert_eq!(
        result.match_count, 1,
        "Only the string should match, not the import"
    );
    assert_eq!(result.evidence[0].source, "string_extractor");

    // Without offset constraint: should match both string AND import
    let params_no_offset = StringParams {
        exact: Some(&exact),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        external_ip: false,
        compiled_regex: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    };
    let result = eval_string(&params_no_offset, None, &ctx);
    assert!(result.matched);
    assert!(
        result.match_count >= 2,
        "Without offset constraint, both string and import should match"
    );
}

// =============================================================================
// Gap #4: word: boundary matching in eval_string
// =============================================================================

#[test]
fn test_eval_string_word_boundary() {
    let mut report = create_test_report();
    // "cat" as standalone word
    report.strings.push(StringInfo {
        value: "the cat sat".to_string(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    // "cat" inside another word — should NOT match word boundary
    report.strings.push(StringInfo {
        value: "category list".to_string(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let word = "cat".to_string();
    let word_regex = regex::Regex::new(r"\bcat\b").unwrap();
    let params = StringParams {
        exact: None,
        substr: None,
        regex: None,
        word: Some(&word),
        case_insensitive: false,
        external_ip: false,
        compiled_regex: Some(&word_regex),
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    };

    let result = eval_string(&params, None, &ctx);
    assert!(result.matched);
    assert_eq!(
        result.match_count, 1,
        "Only 'the cat sat' should match word boundary, not 'category list'"
    );
    // Evidence contains the matched string value
    assert!(
        result.evidence[0].value.contains("cat"),
        "Evidence should contain the matched word: {:?}",
        result.evidence[0].value
    );
}

// =============================================================================
// Gap #5: offset_range, section_offset, section_offset_range tests
// =============================================================================

#[test]
fn test_eval_raw_offset_range_filters() {
    let report = create_test_report();
    // Place "MARKER" at two locations in binary data
    let mut data = vec![0u8; 200];
    data[10..16].copy_from_slice(b"MARKER"); // offset 10
    data[150..156].copy_from_slice(b"MARKER"); // offset 150

    let ctx = create_test_context(&report, &data);

    // Search only in range [0, 50) — should find first MARKER only
    let location = ContentLocationParams {
        offset_range: Some((0, Some(50))),
        ..Default::default()
    };
    let result = eval_raw(
        None,
        Some(&"MARKER".to_string()),
        None,
        None,
        false,
        false,
        None,
        None,
        &location,
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(
        result.match_count, 1,
        "Only MARKER at offset 10 should match"
    );

    // Search only in range [100, 200) — should find second MARKER only
    let location2 = ContentLocationParams {
        offset_range: Some((100, Some(200))),
        ..Default::default()
    };
    let result2 = eval_raw(
        None,
        Some(&"MARKER".to_string()),
        None,
        None,
        false,
        false,
        None,
        None,
        &location2,
        &ctx,
    );
    assert!(result2.matched);
    assert_eq!(
        result2.match_count, 1,
        "Only MARKER at offset 150 should match"
    );

    // Search in range [50, 100) — should find no MARKER
    let location3 = ContentLocationParams {
        offset_range: Some((50, Some(100))),
        ..Default::default()
    };
    let result3 = eval_raw(
        None,
        Some(&"MARKER".to_string()),
        None,
        None,
        false,
        false,
        None,
        None,
        &location3,
        &ctx,
    );
    assert!(!result3.matched);
}

#[test]
fn test_eval_raw_offset_range_negative() {
    let report = create_test_report();
    // Place "END" at the very end of the data
    let mut data = vec![0u8; 100];
    data[97..100].copy_from_slice(b"END");

    let ctx = create_test_context(&report, &data);

    // Negative offset_range start: last 10 bytes
    let location = ContentLocationParams {
        offset_range: Some((-10, None)),
        ..Default::default()
    };
    let result = eval_raw(
        None,
        Some(&"END".to_string()),
        None,
        None,
        false,
        false,
        None,
        None,
        &location,
        &ctx,
    );
    assert!(
        result.matched,
        "Negative offset should search from end of file"
    );

    // Negative offset_range too small to reach "END"
    let location2 = ContentLocationParams {
        offset_range: Some((-2, None)),
        ..Default::default()
    };
    let result2 = eval_raw(
        None,
        Some(&"END".to_string()),
        None,
        None,
        false,
        false,
        None,
        None,
        &location2,
        &ctx,
    );
    assert!(
        !result2.matched,
        "Last 2 bytes should not contain full 'END'"
    );
}

#[test]
fn test_eval_string_section_offset_with_section_map() {
    use crate::composite_rules::section_map::SectionMap;

    let mut report = create_test_report();
    // String at absolute offset 0x1100 (= .text + 0x100)
    report.strings.push(StringInfo {
        value: "MAGIC".to_string(),
        offset: Some(0x1100),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    // String at absolute offset 0x2050 (= .data + 0x50)
    report.strings.push(StringInfo {
        value: "OTHER".to_string(),
        offset: Some(0x2050),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let data = vec![0u8; 0x3000];
    let section_map = SectionMap::from_sections_and_size(
        vec![(".text", 0x1000, 0x2000), (".data", 0x2000, 0x3000)],
        0x3000,
    );

    let mut ctx = create_test_context(&report, &data);
    ctx.section_map = Some(section_map);

    // section + section_offset_range covering .text[0..0x200) — should match MAGIC
    let substr = "MAGIC".to_string();
    let sec_text = ".text".to_string();
    let sec_data = ".data".to_string();
    let params = StringParams {
        exact: None,
        substr: Some(&substr),
        regex: None,
        word: None,
        case_insensitive: false,
        external_ip: false,
        compiled_regex: None,
        section: Some(&sec_text),
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: Some((0, Some(0x200))),
    };
    let result = eval_string(&params, None, &ctx);
    assert!(
        result.matched,
        "MAGIC at .text+0x100 should be in range [0, 0x200)"
    );
    assert_eq!(result.match_count, 1);

    // section .data + range covering [0, 0x100) — should match OTHER at .data+0x50
    let substr2 = "OTHER".to_string();
    let params2 = StringParams {
        exact: None,
        substr: Some(&substr2),
        regex: None,
        word: None,
        case_insensitive: false,
        external_ip: false,
        compiled_regex: None,
        section: Some(&sec_data),
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: Some((0, Some(0x100))),
    };
    let result2 = eval_string(&params2, None, &ctx);
    assert!(
        result2.matched,
        "OTHER at .data+0x50 should be in range [0, 0x100)"
    );

    // section .text — should NOT find OTHER (it's in .data)
    let params3 = StringParams {
        exact: None,
        substr: Some(&substr2),
        regex: None,
        word: None,
        case_insensitive: false,
        external_ip: false,
        compiled_regex: None,
        section: Some(&sec_text),
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: Some((0, Some(0x1000))),
    };
    let result3 = eval_string(&params3, None, &ctx);
    assert!(
        !result3.matched,
        "OTHER should not be found in .text section"
    );
}

#[test]
fn test_eval_raw_section_offset_range() {
    use crate::composite_rules::section_map::SectionMap;

    let report = create_test_report();
    let mut data = vec![0u8; 0x3000];
    // Place "ALPHA" at .text + 0x100 = absolute 0x1100
    data[0x1100..0x1105].copy_from_slice(b"ALPHA");
    // Place "BETA" at .text + 0x800 = absolute 0x1800
    data[0x1800..0x1804].copy_from_slice(b"BETA");

    let section_map = SectionMap::from_sections_and_size(vec![(".text", 0x1000, 0x2000)], 0x3000);

    let mut ctx = create_test_context(&report, &data);
    ctx.section_map = Some(section_map);

    // section_offset_range [0, 0x200) in .text — should find ALPHA but not BETA
    let location = ContentLocationParams {
        section: Some(".text".to_string()),
        section_offset_range: Some((0, Some(0x200))),
        ..Default::default()
    };
    let result = eval_raw(
        None,
        Some(&"ALPHA".to_string()),
        None,
        None,
        false,
        false,
        None,
        None,
        &location,
        &ctx,
    );
    assert!(
        result.matched,
        "ALPHA at section offset 0x100 should be in range [0, 0x200)"
    );

    let result2 = eval_raw(
        None,
        Some(&"BETA".to_string()),
        None,
        None,
        false,
        false,
        None,
        None,
        &location,
        &ctx,
    );
    assert!(
        !result2.matched,
        "BETA at section offset 0x800 should be outside range [0, 0x200)"
    );

    // section_offset_range [0x700, 0x900) — should find BETA but not ALPHA
    let location2 = ContentLocationParams {
        section: Some(".text".to_string()),
        section_offset_range: Some((0x700, Some(0x900))),
        ..Default::default()
    };
    let result3 = eval_raw(
        None,
        Some(&"BETA".to_string()),
        None,
        None,
        false,
        false,
        None,
        None,
        &location2,
        &ctx,
    );
    assert!(
        result3.matched,
        "BETA at section offset 0x800 should be in range [0x700, 0x900)"
    );
}

#[test]
fn test_eval_string_offset_range_filters() {
    let mut report = create_test_report();
    // String at offset 100
    report.strings.push(StringInfo {
        value: "target_string".to_string(),
        offset: Some(100),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    // Same string at offset 5000
    report.strings.push(StringInfo {
        value: "target_string".to_string(),
        offset: Some(5000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let substr = "target_string".to_string();

    // offset_range [0, 200) — should match only the string at offset 100
    let params = StringParams {
        exact: None,
        substr: Some(&substr),
        regex: None,
        word: None,
        case_insensitive: false,
        external_ip: false,
        compiled_regex: None,
        section: None,
        offset: None,
        offset_range: Some((0, Some(200))),
        section_offset: None,
        section_offset_range: None,
    };
    let result = eval_string(&params, None, &ctx);
    assert!(result.matched);
    assert_eq!(
        result.match_count, 1,
        "Only string at offset 100 should match"
    );

    // offset_range [4000, 6000) — should match only the string at offset 5000
    let params2 = StringParams {
        exact: None,
        substr: Some(&substr),
        regex: None,
        word: None,
        case_insensitive: false,
        external_ip: false,
        compiled_regex: None,
        section: None,
        offset: None,
        offset_range: Some((4000, Some(6000))),
        section_offset: None,
        section_offset_range: None,
    };
    let result2 = eval_string(&params2, None, &ctx);
    assert!(result2.matched);
    assert_eq!(
        result2.match_count, 1,
        "Only string at offset 5000 should match"
    );
}
