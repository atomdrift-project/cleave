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
use crate::types::Evidence;
use crate::types::scores::get_metric_value;

/// Evaluate metrics condition - check computed metrics against thresholds
/// Field path examples: "identifiers.avg_entropy", "functions.density"
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
    if let Some(min_sz) = min_size
        && file_size < min_sz
    {
        return ConditionResult::no_match();
    }
    if let Some(max_sz) = max_size
        && file_size > max_sz
    {
        return ConditionResult::no_match();
    }

    // Dynamic field lookup — `get_metric_value` consults the typed
    // `Metrics` struct first (cleave-native fields) then falls back
    // to `report.filefacts_metrics` (filefacts's verbatim flat map).
    let value = get_metric_value(ctx.report, field);

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
        // A *located* metric carries the byte spans it was measured from (e.g.
        // `binary.peak_region_entropy` → the high-entropy runs). When present,
        // anchor the evidence at those spans so the finding points at the bytes
        // (prism). Otherwise a metric describes the whole file, so anchor at the
        // header (offset 0) for scope/proximity bucketing.
        let spans = ctx
            .report
            .filefacts_metric_spans
            .as_ref()
            .and_then(|m| m.get(field));
        let (location, offsets, match_len) = match spans.and_then(|s| s.split_first()) {
            Some((first, _)) => (
                // Single parseable start offset, matching content-matcher
                // convention; the span length rides `match_len`. (A range string
                // would defeat `parse_offset_from_location`.)
                Some(format!("0x{:x}", first.offset)),
                spans
                    .map(|s| s.iter().map(|sp| sp.offset).collect())
                    .unwrap_or_default(),
                // The finding location surface collapses to one span today; the
                // largest run is first, so its length is the representative span.
                Some(first.len),
            ),
            None => (Some("0x0".to_string()), Vec::new(), None),
        };
        vec![Evidence {
            method: "metrics".to_string(),
            source: "analyzer".to_string(),
            value: format!("{} = {:.2}", field, value),
            location,
            offsets,
            match_len,
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
