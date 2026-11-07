//! Validation's soundness check on anchored tree-sitter evaluation.

use super::run_ast_query;
use crate::composite_rules::context::{AnalysisWarning, ConditionResult, EvaluationContext};
use crate::types::MAX_EVIDENCE_PER_TRAIT;

/// Largest source `cleave validate` re-walks whole to check an anchored
/// result: fixtures that size exercise every anchoring path, and a bundle's
/// whole walk is the cost anchoring exists to avoid.
pub(super) const ANCHOR_CHECK_MAX_BYTES: usize = 256 * 1024;

/// Validation's guard on anchored evaluation (see `ast_gate::Anchors`): the
/// anchored runs and the whole-tree walk must find the same matches. Both
/// count every match, so neither stops at a first match the other reaches in
/// a different order; runs a limit cut short prove nothing and are skipped.
pub(super) fn check_anchoring(
    query_str: &str,
    ctx: &EvaluationContext<'_>,
    cpu_budget: std::time::Duration,
) {
    let _count = super::super::symbol_string::MatchCountGuard::set(true);
    let anchored = run_ast_query(query_str, ctx, cpu_budget, true, &mut false);
    let whole = run_ast_query(query_str, ctx, cpu_budget, false, &mut false);
    let bounded = |result: &ConditionResult| {
        result.warnings.iter().any(|warning| {
            matches!(
                warning,
                AnalysisWarning::AstTooDeep { max_depth: 0 }
                    | AnalysisWarning::AstQueryLimited { .. }
            )
        })
    };
    if bounded(&anchored) || bounded(&whole) || ctx.is_cancelled() {
        return;
    }
    // Evidence is capped; past the cap, which matches are kept depends on
    // order, so only the counts can be compared.
    let evidence = |result: &ConditionResult| {
        let mut kept: Vec<_> = result
            .evidence
            .iter()
            .map(|e| (e.offsets.clone(), e.value.clone()))
            .collect();
        kept.sort();
        kept
    };
    let comparable = anchored.evidence.len() < MAX_EVIDENCE_PER_TRAIT
        && whole.evidence.len() < MAX_EVIDENCE_PER_TRAIT;
    if anchored.match_count != whole.match_count
        || (comparable && evidence(&anchored) != evidence(&whole))
    {
        crate::validation_performance::anchoring_diverged(
            query_str,
            &ctx.report.target.path,
            &format!(
                "{} anchored matches, {} whole-tree matches",
                anchored.match_count, whole.match_count
            ),
        );
    }
}
