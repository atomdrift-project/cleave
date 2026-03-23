//! Metrics-based condition evaluators.
//!
//! This module handles evaluation of computed metrics against thresholds:
//! - Text metrics (entropy, line lengths, whitespace)
//! - Identifier metrics (reuse, entropy, naming patterns)
//! - String metrics (entropy, length distributions)
//! - Comment metrics (ratio, density)
//! - Function metrics (complexity, nesting, parameters)
//! - Binary metrics (entropy, sections, imports, functions)
//! - Language-specific metrics (Go)

use crate::composite_rules::context::{ConditionResult, EvaluationContext};
use crate::types::scores::get_metric_value;
use crate::types::Evidence;

/// Evaluate metrics condition - check computed metrics against thresholds
/// Field path examples: "identifiers.avg_entropy", "functions.density_per_100_lines"
#[must_use]
pub(crate) fn eval_metrics<'a>(
    field: &str,
    min: Option<f64>,
    max: Option<f64>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    // Check file size constraints first
    let file_size = ctx.report.target.size_bytes;
    if let Some(min_sz) = min_size {
        if file_size < min_sz {
            return ConditionResult::no_match();
        }
    }
    if let Some(max_sz) = max_size {
        if file_size > max_sz {
            return ConditionResult::no_match();
        }
    }

    let Some(metrics) = &ctx.report.metrics else {
        return ConditionResult::no_match();
    };

    // Dynamic field lookup via serde — no hardcoded match needed
    let value = get_metric_value(metrics, field);

    let Some(value) = value else {
        return ConditionResult::no_match();
    };

    let min_ok = min.is_none_or(|m| value >= m);
    let max_ok = max.is_none_or(|m| value <= m);
    let matched = min_ok && max_ok;

    // Calculate precision: base 1.0 + 0.5 each for min/max/min_size/max_size
    let mut precision = 1.0f32;
    if min.is_some() {
        precision += 0.5;
    }
    if max.is_some() {
        precision += 0.5;
    }
    if min_size.is_some() {
        precision += 0.5;
    }
    if max_size.is_some() {
        precision += 0.5;
    }

    let evidence = if matched {
        vec![Evidence {
            method: "metrics".to_string(),
            source: "analyzer".to_string(),
            value: format!("{} = {:.2}", field, value),
            location: None,
            ..Default::default()
        }]
    } else {
        Vec::new()
    };
    let match_count = evidence.len();
    ConditionResult {
        matched,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision,
        matched_trait_ids: Vec::new(),
    }
}
