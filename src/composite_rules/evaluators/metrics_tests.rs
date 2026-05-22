//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for metrics-based condition evaluators.

use super::*;
use crate::composite_rules::context::EvaluationContext;
use crate::composite_rules::types::FileType;
use crate::types::core::MetricsExt;
use crate::types::{AnalysisReport, TargetInfo};

fn create_test_report() -> AnalysisReport {
    let target = TargetInfo {
        path: "/test/file".to_string(),
        file_type: "source".to_string(),
        size_bytes: 1024,
        sha256: "abc123".to_string(),
        architectures: None,
    };
    AnalysisReport::new(target)
}

fn create_test_context<'a>(report: &'a AnalysisReport, data: &'a [u8]) -> EvaluationContext<'a> {
    EvaluationContext::test_only_new(report, data, FileType::All)
}

/// Set a single flat metric on the report. Mirrors how expose populates
/// `report.expose_metrics` in production — production sets dotted keys
/// directly; tests do the same.
fn set_metric(report: &mut AnalysisReport, key: &str, value: f64) {
    report
        .expose_metrics
        .get_or_insert_with(Default::default)
        .set_f(key.to_string(), value);
}

// =============================================================================
// eval_metrics tests - Text metrics
// =============================================================================

#[test]
fn test_eval_metrics_text_char_entropy() {
    let mut report = create_test_report();
    set_metric(&mut report, "text.char_entropy", 5.5);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_metrics("text.char_entropy", Some(5.0), Some(6.0), None, None, &ctx);
    assert!(result.matched);
    assert!(result.evidence[0].value.contains("5.5"));
}

#[test]
fn test_eval_metrics_text_avg_line_length() {
    let mut report = create_test_report();
    set_metric(&mut report, "text.avg_line_length", 85.0);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_metrics("text.avg_line_length", Some(80.0), None, None, None, &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_metrics_text_whitespace_ratio() {
    let mut report = create_test_report();
    set_metric(&mut report, "text.whitespace_ratio", 0.15);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Low whitespace ratio
    let result = eval_metrics("text.whitespace_ratio", None, Some(0.20), None, None, &ctx);
    assert!(result.matched);
}

// =============================================================================
// eval_metrics tests - Identifier metrics
// =============================================================================

#[test]
fn test_eval_metrics_identifiers_avg_entropy() {
    let mut report = create_test_report();
    set_metric(&mut report, "identifiers.avg_entropy", 3.8);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // High entropy identifiers (obfuscation signal)
    let result = eval_metrics("identifiers.avg_entropy", Some(3.5), None, None, None, &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_metrics_identifiers_single_char_ratio() {
    let mut report = create_test_report();
    set_metric(&mut report, "identifiers.single_char_ratio", 0.45);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // High single-char ratio (obfuscation signal)
    let result = eval_metrics(
        "identifiers.single_char_ratio",
        Some(0.30),
        None,
        None,
        None,
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_eval_metrics_identifiers_reuse_ratio() {
    let mut report = create_test_report();
    set_metric(&mut report, "identifiers.reuse_ratio", 0.25);
    set_metric(&mut report, "identifiers.total", 100.0);
    set_metric(&mut report, "identifiers.unique_count", 25.0);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Low reuse ratio (repetitive code)
    let result = eval_metrics(
        "identifiers.reuse_ratio",
        None,
        Some(0.30),
        None,
        None,
        &ctx,
    );
    assert!(result.matched);
}

// =============================================================================
// eval_metrics tests - Function metrics
// =============================================================================

#[test]
fn test_eval_metrics_functions_max_nesting_depth() {
    let mut report = create_test_report();
    set_metric(&mut report, "functions.max_nesting_depth", 8.0);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Deep nesting
    let result = eval_metrics(
        "functions.max_nesting_depth",
        Some(5.0),
        None,
        None,
        None,
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_eval_metrics_functions_over_100_lines() {
    let mut report = create_test_report();
    set_metric(&mut report, "functions.over_100_lines", 3.0);
    set_metric(&mut report, "functions.total", 10.0);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_metrics(
        "functions.over_100_lines",
        Some(2.0),
        None,
        None,
        None,
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_eval_metrics_functions_density() {
    let mut report = create_test_report();
    set_metric(&mut report, "functions.density_per_100_lines", 15.0);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_metrics(
        "functions.density_per_100_lines",
        Some(10.0),
        Some(20.0),
        None,
        None,
        &ctx,
    );
    assert!(result.matched);
}

// =============================================================================
// eval_metrics tests - File size constraints
// =============================================================================

#[test]
fn test_eval_metrics_min_size() {
    let mut report = create_test_report();
    report.target.size_bytes = 5000;
    set_metric(&mut report, "text.char_entropy", 5.0);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // File too small
    let result = eval_metrics(
        "text.char_entropy",
        None,
        None,
        Some(10000), // min_size > actual size
        None,
        &ctx,
    );
    assert!(!result.matched);

    // File large enough
    let result = eval_metrics("text.char_entropy", None, None, Some(1000), None, &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_metrics_max_size() {
    let mut report = create_test_report();
    report.target.size_bytes = 5000;
    set_metric(&mut report, "text.char_entropy", 5.0);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // File too large
    let result = eval_metrics(
        "text.char_entropy",
        None,
        None,
        None,
        Some(1000), // max_size < actual size
        &ctx,
    );
    assert!(!result.matched);

    // File small enough
    let result = eval_metrics("text.char_entropy", None, None, None, Some(10000), &ctx);
    assert!(result.matched);
}

// =============================================================================
// eval_metrics tests - Edge cases
// =============================================================================

#[test]
fn test_eval_metrics_no_metrics() {
    let report = create_test_report(); // No metrics set
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_metrics("text.char_entropy", Some(1.0), None, None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_metrics_missing_field() {
    let mut report = create_test_report();
    // Empty flat map — `text.char_entropy` lookups return None.
    report.expose_metrics.get_or_insert_with(Default::default);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Field absent → !matched.
    let result = eval_metrics("text.char_entropy", Some(1.0), None, None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_metrics_unknown_field() {
    let mut report = create_test_report();
    report.expose_metrics.get_or_insert_with(Default::default);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_metrics("nonexistent.field", Some(1.0), None, None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_metrics_missing_submetrics() {
    let mut report = create_test_report();
    // Populate identifiers but not text.
    set_metric(&mut report, "identifiers.avg_entropy", 0.0);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // text.* keys absent → !matched.
    let result = eval_metrics("text.char_entropy", Some(1.0), None, None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_metrics_evidence_format() {
    let mut report = create_test_report();
    set_metric(&mut report, "text.char_entropy", 5.5);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    let result = eval_metrics("text.char_entropy", Some(5.0), None, None, None, &ctx);
    assert!(result.matched);
    assert_eq!(result.evidence.len(), 1);
    assert_eq!(result.evidence[0].method, "metrics");
    assert_eq!(result.evidence[0].source, "analyzer");
    assert!(result.evidence[0].value.contains("text.char_entropy"));
    assert!(result.evidence[0].value.contains("5.5"));
}

#[test]
fn test_eval_metrics_min_and_max() {
    let mut report = create_test_report();
    set_metric(&mut report, "text.char_entropy", 5.0);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Within range
    let result = eval_metrics("text.char_entropy", Some(4.0), Some(6.0), None, None, &ctx);
    assert!(result.matched);

    // Below min
    let result = eval_metrics("text.char_entropy", Some(6.0), Some(7.0), None, None, &ctx);
    assert!(!result.matched);

    // Above max
    let result = eval_metrics("text.char_entropy", Some(3.0), Some(4.0), None, None, &ctx);
    assert!(!result.matched);
}

#[test]
fn test_eval_metrics_digit_ratio() {
    let mut report = create_test_report();
    set_metric(&mut report, "text.digit_ratio", 0.35);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // High digit ratio (possible hex/encoded data)
    let result = eval_metrics("text.digit_ratio", Some(0.30), None, None, None, &ctx);
    assert!(result.matched);
}

#[test]
fn test_eval_metrics_empty_line_ratio() {
    let mut report = create_test_report();
    set_metric(&mut report, "text.empty_line_ratio", 0.05);
    let data = vec![];
    let ctx = create_test_context(&report, &data);

    // Low empty line ratio (minified code?)
    let result = eval_metrics("text.empty_line_ratio", None, Some(0.10), None, None, &ctx);
    assert!(result.matched);
}
