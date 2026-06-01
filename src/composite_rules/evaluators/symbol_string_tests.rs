//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for symbol and string-based condition evaluators.

use super::*;
use crate::composite_rules::condition::{NotException, SymbolKind};
use crate::composite_rules::context::{ConditionResult, EvaluationContext, StringParams};
use crate::composite_rules::types::{FileType, Platform};
use crate::types::{AnalysisReport, Export, Function, Import, StringInfo, StringType, TargetInfo};

fn eval_symbol<'a>(
    exact: Option<&String>,
    substr: Option<&String>,
    pattern: Option<&String>,
    platforms: Option<&Vec<Platform>>,
    _compiled_regex: Option<&regex::Regex>,
    not: Option<&Vec<NotException>>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    eval_symbol_with_kind(
        exact,
        substr,
        pattern,
        platforms,
        None,
        _compiled_regex,
        not,
        ctx,
    )
}

#[allow(clippy::too_many_arguments)]
fn eval_symbol_with_kind<'a>(
    exact: Option<&String>,
    substr: Option<&String>,
    pattern: Option<&String>,
    platforms: Option<&Vec<Platform>>,
    kind: Option<SymbolKind>,
    _compiled_regex: Option<&regex::Regex>,
    not: Option<&Vec<NotException>>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    super::eval_symbol(
        exact, substr, pattern, platforms, None, kind, not, None, ctx,
    )
}

#[allow(clippy::too_many_arguments)]
fn eval_raw<'a>(
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    word: Option<&String>,
    case_insensitive: bool,
    external_ip: bool,
    _compiled_regex: Option<&regex::Regex>,
    not: Option<&Vec<NotException>>,
    location: &ContentLocationParams,
    ctx: &EvaluationContext<'a>,
    trait_id: Option<&str>,
) -> ConditionResult {
    super::eval_raw(
        exact,
        substr,
        regex,
        word,
        case_insensitive,
        external_ip.then_some(crate::composite_rules::condition::StringValidator::ExternalIp),
        not,
        location,
        ctx,
        trait_id,
    )
}

#[allow(clippy::too_many_arguments)]
fn eval_encoded<'a>(
    encoding: Option<&crate::composite_rules::condition::EncodingSpec>,
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    word: Option<&String>,
    case_insensitive: bool,
    _compiled_regex: Option<&regex::Regex>,
    location: &ContentLocationParams,
    external_ip: bool,
    not: Option<&Vec<crate::composite_rules::condition::NotException>>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    super::eval_encoded(
        encoding,
        exact,
        substr,
        regex,
        word,
        case_insensitive,
        location,
        external_ip.then_some(crate::composite_rules::condition::StringValidator::ExternalIp),
        not,
        ctx,
    )
}

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
// eval_symbol tests
// =============================================================================

#[test]
fn test_eval_symbol_exact_match() {
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "libc".to_string(),
        offset: None,
        alias: None,
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
        offset: None,
        alias: None,
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
        offset: None,
        alias: None,
    });
    report.imports.push(Import {
        symbol: "accept".to_string(),
        library: None,
        source: "libc".to_string(),
        offset: None,
        alias: None,
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
        offset: None,
        alias: None,
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
fn test_eval_symbol_not_filters_substr_match() {
    // Two imports both contain "eval" — `eval` (a real call) and
    // `safe_eval_template` (a helper we want to exclude). A `not:` substring
    // exception on `template` must drop the helper but keep `eval`.
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "eval".to_string(),
        library: None,
        source: "builtin".to_string(),
        offset: None,
        alias: None,
    });
    report.imports.push(Import {
        symbol: "safe_eval_template".to_string(),
        library: None,
        source: "builtin".to_string(),
        offset: None,
        alias: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let pattern = "eval".to_string();
    let not = vec![NotException::Shorthand("template".to_string())];

    let result = eval_symbol(None, Some(&pattern), None, None, None, Some(&not), &ctx);

    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(result.evidence[0].value, "eval");
}

#[test]
fn test_eval_symbol_not_filters_all_matches() {
    // When every match is excluded by `not:`, the condition must report no
    // match — not silently report a hit with empty evidence.
    let mut report = create_test_report();
    report.imports.push(Import {
        symbol: "eval_template".to_string(),
        library: None,
        source: "builtin".to_string(),
        offset: None,
        alias: None,
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let pattern = "eval".to_string();
    let not = vec![NotException::Shorthand("template".to_string())];

    let result = eval_symbol(None, Some(&pattern), None, None, None, Some(&not), &ctx);

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
        offset: None,
        alias: None,
    });
    let data = vec![];
    let mut ctx = create_test_context(&report, &data);
    ctx.platforms = &[Platform::Linux];

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
        offset: None,
        alias: None,
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
        forward_to: None,
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
        register_usage: None,
        constants: vec![],
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
// eval_text tests (formerly eval_string)
// =============================================================================

#[test]
fn test_eval_string_exact_match() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: ("/bin/sh".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: Some(StringType::Path),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let params = StringParams {
        exact: Some(&"/bin/sh".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    };

    let result = eval_text(&params, None, &ctx, None);

    assert!(result.matched);
    assert_eq!(result.evidence[0].value, "/bin/sh");
}

#[test]
fn test_eval_string_substr_match() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: ("http://evil.com/malware".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: Some(StringType::Url),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let params = StringParams {
        exact: None,
        substr: Some(&"evil.com".to_string()),
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    };

    let result = eval_text(&params, None, &ctx, None);

    assert!(result.matched);
}

#[test]
fn test_eval_string_regex_match() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: ("192.168.1.100".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: Some(StringType::IP),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}".to_string();
    let params = StringParams {
        exact: None,
        substr: None,
        regex: Some(&pattern),
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    };

    let result = eval_text(&params, None, &ctx, None);

    assert!(result.matched);
}

#[test]
fn test_eval_string_case_insensitive() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: ("CreateRemoteThread".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let params = StringParams {
        exact: Some(&"createremotethread".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: true,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    };

    let result = eval_text(&params, None, &ctx, None);

    assert!(result.matched);
}

#[test]
fn test_eval_string_not_exception() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: ("/bin/sh".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: Some(StringType::Path),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
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
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    };

    let result = eval_text(&params, Some(&not_exceptions), &ctx, None);

    // Should not match due to not exception
    assert!(!result.matched);
}

#[test]
fn test_eval_text_uses_raw_search_for_source_files() {
    let report = create_test_report();
    let data = b"#!/bin/sh\n# password marker in comment\n".to_vec();
    let ctx = EvaluationContext::test_only_new(&report, &data, FileType::Shell);
    let pattern = "password marker".to_string();
    let params = StringParams {
        exact: None,
        substr: Some(&pattern),
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    };

    let result = eval_text(&params, None, &ctx, None);

    assert!(result.matched);
    assert_eq!(result.evidence[0].method, "raw");
}

#[test]
fn test_eval_string_literal_matches_only_ast_strings() {
    let mut report = create_test_report();
    report.strings.push(StringInfo {
        value: ("not_a_literal".to_string()).into(),
        offset: Some(0x100),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });
    report.strings.push(StringInfo {
        value: ("literal_value".to_string()).into(),
        offset: Some(0x200),
        encoding: "utf8".to_string(),
        string_type: None,
        section: Some("ast".to_string()),
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });
    let data = vec![];
    let ctx = EvaluationContext::test_only_new(&report, &data, FileType::Python);
    let pattern = "literal_value".to_string();
    let params = StringParams {
        exact: Some(&pattern),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    };

    let result = eval_string_literal(&params, None, &ctx);

    assert!(result.matched);
    assert_eq!(result.match_count, 1);
    assert_eq!(result.evidence[0].value, "literal_value");
    assert_eq!(result.evidence[0].source, "ast");
}

// Note: Legacy `eval_string` fused string-extractor lookup with import-symbol
// matching. `eval_text` only searches extracted strings — import matching now
// lives in `type: symbol`. The pre-migration test for that behavior was removed.

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
        None,
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
        None,
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
        None,
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
        None,
    );

    assert!(result.matched);
}

// Per-line regex anchor coverage. In raw-text mode (source files, manifests)
// trait authors expect `regex: '^foo'` to match `foo` at the start of any line,
// not only at the start of the file. The fix in eval_raw enables multi_line on
// both the ASCII byte-regex and the Unicode regex builders so `^` / `$` anchor
// at `\n` boundaries. Without these tests the next refactor of compile_bytes_regex
// or build_regex would silently regress every source-language regex trait that
// uses line anchors (the entire framework-context family added for Flowcrafter).

#[test]
fn test_eval_raw_regex_caret_matches_line_start_ascii() {
    let report = create_test_report();
    // Three lines; `namespace` appears on the third line, NOT line 1.
    let content = "<?php\n\nnamespace Wundii\\Flowcrafter\\Console;\n";
    let ctx = create_test_context(&report, content.as_bytes());

    let pattern = r"^namespace ".to_string();
    let re = regex::Regex::new(&format!("(?m){pattern}")).unwrap();

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
        None,
    );

    assert!(
        result.matched,
        "^namespace must match per-line in raw-text mode (multi_line flag); \
         this is the test that broke the framework-context trait family until eval_raw \
         enabled multi-line regex compilation"
    );
}

#[test]
fn test_eval_raw_regex_dollar_matches_line_end_ascii() {
    let report = create_test_report();
    // Each line ends with `;` — `;$` must match per-line, not just at file end.
    let content = "use Symfony\\Component\\Console\\Command\\Command;\nuse Foo\\Bar;\n";
    let ctx = create_test_context(&report, content.as_bytes());

    let pattern = r";$".to_string();
    let re = regex::Regex::new(&format!("(?m){pattern}")).unwrap();

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
        None,
    );

    assert!(
        result.matched,
        "`;$` must match end-of-line in raw-text mode"
    );
}

#[test]
fn test_eval_raw_regex_caret_unicode_path() {
    // Force the Unicode path with a non-ASCII pattern (so can_use_byte_matching
    // returns false and eval_raw falls into the unicode regex branch).
    let report = create_test_report();
    let content = "header\n\nnaïve_marker_at_line_start\nbody\n";
    let ctx = create_test_context(&report, content.as_bytes());

    let pattern = r"^naïve_marker".to_string();
    let re = regex::RegexBuilder::new(&pattern)
        .multi_line(true)
        .build()
        .unwrap();

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
        None,
    );

    assert!(
        result.matched,
        "Unicode-path regex must also honor per-line anchors so non-ASCII patterns \
         don't silently regress when multi_line is added only to the byte path"
    );
}

#[test]
fn test_eval_raw_regex_caret_not_at_line_start_does_not_match() {
    // Negative case: `^x` against `bar x foo` (no x at any line start) must NOT match,
    // even though `x` is present as a substring. Confirms the anchor is honored, not
    // ignored. Prevents a regression where someone "fixes" multi-line by simply
    // stripping anchors.
    let report = create_test_report();
    let content = "bar x foo\nbaz x qux\n";
    let ctx = create_test_context(&report, content.as_bytes());

    let pattern = r"^x".to_string();
    let re = regex::RegexBuilder::new(&pattern)
        .multi_line(true)
        .build()
        .unwrap();

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
        None,
    );

    assert!(
        !result.matched,
        "`^x` must not match an x that's mid-line; line-anchoring must remain strict"
    );
}

#[test]
fn test_eval_raw_regex_unanchored_still_finds_substring() {
    // Sanity: a non-anchored pattern continues to match anywhere in the file.
    // Guards against a regression where someone confuses multi-line with anchored-only.
    let report = create_test_report();
    let content = "alpha\nbeta needle gamma\ndelta\n";
    let ctx = create_test_context(&report, content.as_bytes());

    let pattern = r"needle".to_string();
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
        None,
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
        None,
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
        None,
    );

    assert!(!result.matched);
}

// ==================== eval_encoded Tests ====================

fn create_test_report_with_multiple_encodings() -> AnalysisReport {
    let mut report = create_test_report();

    // Base64-encoded strings
    report.strings.push(StringInfo {
        value: ("password123".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: Some(".data".to_string()),
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });

    report.strings.push(StringInfo {
        value: ("https://evil.com/payload".to_string()).into(),
        offset: Some(0x1100),
        encoding: "utf8".to_string(),
        string_type: Some(StringType::Url),
        section: Some(".data".to_string()),
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });

    // Hex-encoded strings
    report.strings.push(StringInfo {
        value: ("secret_key".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: Some(".text".to_string()),
        encoding_chain: vec!["hex".to_string()],
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });

    report.strings.push(StringInfo {
        value: ("admin".to_string()).into(),
        offset: Some(0x2100),
        encoding: "utf8".to_string(),
        string_type: None,
        section: Some(".text".to_string()),
        encoding_chain: vec!["hex".to_string()],
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });

    // XOR-encoded strings
    report.strings.push(StringInfo {
        value: ("malware".to_string()).into(),
        offset: Some(0x3000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: Some(".data".to_string()),
        encoding_chain: vec!["xor".to_string()],
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });

    // URL-encoded strings
    report.strings.push(StringInfo {
        value: ("command.exe arg1 arg2".to_string()).into(),
        offset: Some(0x4000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: Some(".data".to_string()),
        encoding_chain: vec!["url".to_string()],
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });

    // Plain string (no encoding)
    report.strings.push(StringInfo {
        value: ("plain_text".to_string()).into(),
        offset: Some(0x5000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: Some(".data".to_string()),
        encoding_chain: vec![],
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
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
            value: (format!("token_match_{}", i)).into(),
            offset: Some(0x1000 + i * 0x100),
            encoding: "utf8".to_string(),
            string_type: None,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
            matched: std::sync::atomic::AtomicBool::new(false),
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
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    };

    let result = eval_text(&params, None, &ctx, None);
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
        value: ("http://evil.com/payload".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: Some(crate::types::StringType::Url),
        section: None,
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });
    report.strings.push(StringInfo {
        value: ("http://apple.com/safe".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: Some(crate::types::StringType::Url),
        section: None,
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
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
        value: ("connect 8.8.8.8:443".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });
    // String with RFC1918 internal IP
    report.strings.push(StringInfo {
        value: ("connect 192.168.1.1:80".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
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
        None,
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
        None,
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
        value: ("connect to 192.168.1.1:8080".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });
    // Add string containing an external IP — should be kept
    report.strings.push(StringInfo {
        value: ("connect to 8.8.8.8:53".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
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
        is_check: Some(crate::composite_rules::condition::StringValidator::ExternalIp),
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    };

    let result = eval_text(&params, None, &ctx, None);

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
        None,
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
        None,
    );

    assert!(
        result.matched,
        "Match near external IP should be kept when external_ip=true"
    );
}

// =============================================================================
// A6: Location constraints skip imports/exports
// (legacy eval_string fused imports with string search; eval_text searches
// only extracted strings, so this test no longer applies)
// =============================================================================

// =============================================================================
// Gap #4: word: boundary matching in eval_string
// =============================================================================

#[test]
fn test_eval_string_word_boundary() {
    let mut report = create_test_report();
    // "cat" as standalone word
    report.strings.push(StringInfo {
        value: ("the cat sat".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });
    // "cat" inside another word — should NOT match word boundary
    report.strings.push(StringInfo {
        value: ("category list".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let word = "cat".to_string();
    let params = StringParams {
        exact: None,
        substr: None,
        regex: None,
        word: Some(&word),
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    };

    let result = eval_text(&params, None, &ctx, None);
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
        None,
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
        None,
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
        None,
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
        None,
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
        None,
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
        value: ("MAGIC".to_string()).into(),
        offset: Some(0x1100),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });
    // String at absolute offset 0x2050 (= .data + 0x50)
    report.strings.push(StringInfo {
        value: ("OTHER".to_string()).into(),
        offset: Some(0x2050),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });

    let data = vec![0u8; 0x3000];
    let section_map = SectionMap::from_sections_and_size(
        vec![(".text", 0x1000, 0x2000), (".data", 0x2000, 0x3000)],
        0x3000,
    );

    let mut ctx = create_test_context(&report, &data);
    ctx.section_map = Some(&section_map);

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
        is_check: None,
        section: Some(&sec_text),
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: Some((0, Some(0x200))),
        arch_clamp: None,
    };
    let result = eval_text(&params, None, &ctx, None);
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
        is_check: None,
        section: Some(&sec_data),
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: Some((0, Some(0x100))),
        arch_clamp: None,
    };
    let result2 = eval_text(&params2, None, &ctx, None);
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
        is_check: None,
        section: Some(&sec_text),
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: Some((0, Some(0x1000))),
        arch_clamp: None,
    };
    let result3 = eval_text(&params3, None, &ctx, None);
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
    ctx.section_map = Some(&section_map);

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
        None,
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
        None,
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
        None,
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
        value: ("target_string".to_string()).into(),
        offset: Some(100),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
    });
    // Same string at offset 5000
    report.strings.push(StringInfo {
        value: ("target_string".to_string()).into(),
        offset: Some(5000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
        matched: std::sync::atomic::AtomicBool::new(false),
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
        is_check: None,
        section: None,
        offset: None,
        offset_range: Some((0, Some(200))),
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    };
    let result = eval_text(&params, None, &ctx, None);
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
        is_check: None,
        section: None,
        offset: None,
        offset_range: Some((4000, Some(6000))),
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    };
    let result2 = eval_text(&params2, None, &ctx, None);
    assert!(result2.matched);
    assert_eq!(
        result2.match_count, 1,
        "Only string at offset 5000 should match"
    );
}

// =============================================================================
// eval_symbol `kind:` filter tests
// =============================================================================

fn report_with_import_export_function() -> AnalysisReport {
    let mut report = create_test_report();
    report
        .imports
        .push(Import::new("LoadLibraryA", None, "goblin"));
    report.exports.push(Export::new(
        "MyExport",
        Some("0x1234".to_string()),
        "goblin",
    ));
    report.functions.push(Function {
        name: "internal_func".to_string(),
        offset: None,
        size: None,
        complexity: None,
        calls: vec![],
        source: "goblin".to_string(),
        control_flow: None,
        register_usage: None,
        constants: vec![],
        signature: None,
        nesting: None,
        call_patterns: None,
    });
    report
}

#[test]
fn kind_import_only_matches_imports() {
    let report = report_with_import_export_function();
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Without a kind filter the pattern hits across all three categories.
    let all = eval_symbol_with_kind(
        None,
        Some(&"Library".to_string()),
        None,
        None,
        None,
        None,
        None,
        &ctx,
    );
    assert!(all.matched);
    assert_eq!(all.match_count, 1);

    // kind: import narrows to imports only.
    let imports = eval_symbol_with_kind(
        None,
        Some(&"Library".to_string()),
        None,
        None,
        Some(SymbolKind::Import),
        None,
        None,
        &ctx,
    );
    assert!(imports.matched);
    assert_eq!(imports.match_count, 1);
    assert_eq!(imports.evidence[0].value, "LoadLibraryA");

    // kind: export skips imports entirely — no match.
    let exports = eval_symbol_with_kind(
        None,
        Some(&"Library".to_string()),
        None,
        None,
        Some(SymbolKind::Export),
        None,
        None,
        &ctx,
    );
    assert!(!exports.matched);
}

#[test]
fn kind_function_only_matches_functions() {
    let report = report_with_import_export_function();
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_symbol_with_kind(
        None,
        Some(&"internal".to_string()),
        None,
        None,
        Some(SymbolKind::Function),
        None,
        None,
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence[0].value, "internal_func");

    // A function name with kind: import should not match.
    let as_import = eval_symbol_with_kind(
        None,
        Some(&"internal".to_string()),
        None,
        None,
        Some(SymbolKind::Import),
        None,
        None,
        &ctx,
    );
    assert!(!as_import.matched);
}

#[test]
fn kind_forward_matches_forwarded_exports_by_name_or_target() {
    let mut report = create_test_report();
    // Forwarded export: name=GetFileAttributesA → target=KERNEL32.GetFileAttributesA
    report.exports.push(Export::forwarded(
        "GetFileAttributesA",
        "KERNEL32.GetFileAttributesA",
        "goblin",
    ));
    // Non-forwarded export with a similar-looking name must NOT be counted.
    report.exports.push(Export::new(
        "GetLangID",
        Some("0x1010".to_string()),
        "goblin",
    ));
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Matching by export name.
    let by_name = eval_symbol_with_kind(
        None,
        Some(&"GetFileAttributes".to_string()),
        None,
        None,
        Some(SymbolKind::Forward),
        None,
        None,
        &ctx,
    );
    assert!(by_name.matched);
    assert_eq!(by_name.match_count, 1);

    // Matching by forward target (DLL prefix).
    let by_target = eval_symbol_with_kind(
        None,
        Some(&"KERNEL32".to_string()),
        None,
        None,
        Some(SymbolKind::Forward),
        None,
        None,
        &ctx,
    );
    assert!(by_target.matched);
    assert_eq!(by_target.match_count, 1);
    // Evidence carries the export name; the forward target lives in the
    // location column so rule output stays readable.
    assert_eq!(by_target.evidence[0].value, "GetFileAttributesA");
    assert_eq!(
        by_target.evidence[0].location.as_deref(),
        Some("forward → KERNEL32.GetFileAttributesA")
    );

    // kind: forward must ignore the non-forwarded export even if the pattern matches.
    let miss = eval_symbol_with_kind(
        None,
        Some(&"GetLangID".to_string()),
        None,
        None,
        Some(SymbolKind::Forward),
        None,
        None,
        &ctx,
    );
    assert!(!miss.matched);
}

#[test]
fn kind_none_preserves_legacy_semantics() {
    // No `kind:` means the pattern hits the first category that has it;
    // backwards-compat guard so every rule authored before `kind:` landed keeps
    // firing unchanged.
    let report = report_with_import_export_function();
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_symbol_with_kind(
        None,
        Some(&"MyExport".to_string()),
        None,
        None,
        None,
        None,
        None,
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence[0].value, "MyExport");
}

// =============================================================================
// Regex builder multi-line guard.
//
// Both `build_regex` (Unicode/cache path) and `compile_bytes_regex` (ASCII byte
// path) MUST enable multi-line so `^` / `$` anchor at `\n` boundaries in raw-text
// mode. The eval_raw flow uses these directly, and trait authors writing
// `regex: '^namespace '` against source code expect line anchoring — without
// multi-line they get whole-file anchoring instead, which never matches a PHP
// file (PHP starts with `<?php`). These tests guard the builders themselves
// against a future refactor that drops the flag.
// =============================================================================

#[test]
fn build_regex_enables_multi_line_anchors() {
    // Unicode path: cached `build_regex` must compile with multi_line so `^`
    // matches start-of-line, not only start-of-haystack.
    let re = crate::composite_rules::evaluators::build_regex(r"^namespace ", false)
        .expect("build_regex must succeed for a simple pattern");
    assert!(
        re.is_match("<?php\n\nnamespace Foo;\n"),
        "build_regex should produce a multi-line regex so `^` matches per-line in raw text"
    );
    assert!(
        !re.is_match("<?php\nuse Foo;\n"),
        "anchored pattern must still reject input where no line begins with the prefix"
    );
}

#[test]
fn compile_bytes_regex_enables_multi_line_anchors() {
    // ASCII byte path: hot loop in eval_raw. Same guarantee required.
    let re = crate::composite_rules::evaluators::compile_bytes_regex(r"^namespace ", false)
        .expect("compile_bytes_regex must succeed for a simple ASCII pattern");
    assert!(
        re.is_match(b"<?php\n\nnamespace Foo;\n"),
        "compile_bytes_regex should produce a multi-line bytes regex"
    );
    assert!(
        !re.is_match(b"<?php\nuse Foo;\n"),
        "byte-regex line anchor must remain strict for non-matching input"
    );
}

#[test]
fn build_regex_dollar_anchors_per_line() {
    // `$` should match before each `\n` as well as at end of haystack.
    let re = crate::composite_rules::evaluators::build_regex(r";$", false).unwrap();
    let haystack = "use Foo\\Bar;\nuse Baz;\n";
    let count = re.find_iter(haystack).count();
    assert!(
        count >= 2,
        "multi-line `$` should match end of every line, got {count} matches"
    );
}
