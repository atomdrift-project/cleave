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
    report.imports.push(Import {
        symbol: "_socket".to_string(),
        library: None,
        source: "libc".to_string(),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Should match with exact underscore-prefixed symbol
    let result = eval_symbol(
        Some(&"_socket".to_string()),
        None,
        None,
        None,
        None,
        None,
        &ctx,
    );

    assert!(result.matched);
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
    assert!(result.evidence[0].value.contains("4 occurrences"));
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
        &ctx,
    );

    // Should match - "password123" contains "password"
    assert!(result.matched);
    assert!(!result.evidence.is_empty());
}
