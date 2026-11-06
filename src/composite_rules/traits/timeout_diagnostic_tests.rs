use super::*;
use crate::types::{AnalysisGap, AnalysisReport, TargetInfo};

#[test]
fn rule_timeout_records_a_transient_gap_without_a_threat_finding() {
    let report = AnalysisReport::new(TargetInfo::default());
    assert!(!record_rule_timeout(&report, MAX_RULE_EVAL_DURATION));
    assert!(report.analysis_gaps.is_empty());
    assert!(record_rule_timeout(
        &report,
        MAX_RULE_EVAL_DURATION + Duration::from_millis(1)
    ));
    assert!(
        report
            .analysis_gaps
            .contains(AnalysisGap::EvaluationDeadline)
    );
    assert!(report.findings.is_empty());
    let other = AnalysisReport::new(TargetInfo::default());
    assert!(other.analysis_gaps.is_empty());
}
