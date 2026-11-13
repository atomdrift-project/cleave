use super::merge_own_finding;
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind, TargetInfo};
use rustc_hash::FxHashSet;

fn finding(id: &str, crit: Criticality, location: &str) -> Finding {
    let mut finding = Finding::new(id.to_string(), FindingKind::Capability, id.to_string(), 1.0);
    finding.crit = crit;
    finding.evidence.push(Evidence {
        method: "value".to_string(),
        source: "test".to_string(),
        value: "x".to_string(),
        location: Some(location.to_string()),
        ..Default::default()
    });
    finding
}

fn report_with(findings: Vec<Finding>) -> (AnalysisReport, FxHashSet<crate::types::Istr>) {
    let mut report = AnalysisReport::new(TargetInfo {
        path: "/samples/setup.exe".to_string(),
        file_type: "pe".to_string(),
        ..TargetInfo::default()
    });
    report.findings = findings;
    let seen = report.findings.iter().map(|f| f.id.clone()).collect();
    (report, seen)
}

/// An installer stub that is unsigned itself keeps that finding as its own
/// even when an extracted payload rolled up the same trait first.
#[test]
fn own_finding_replaces_a_member_only_copy() {
    let id = "metadata/signature/absent::unsigned-pe-executable";
    let (mut report, mut seen) = report_with(vec![finding(
        id,
        Criticality::Notable,
        "archive:payload.dll:value:pe.signatures",
    )]);
    let new = merge_own_finding(
        &mut report,
        &mut seen,
        finding(id, Criticality::Notable, "value:pe.signatures"),
    );
    assert!(!new, "the id was already listed");
    assert_eq!(report.findings.len(), 1);
    assert_eq!(
        report.findings[0].evidence[0].location.as_deref(),
        Some("value:pe.signatures"),
        "the file's own evidence wins"
    );
}

#[test]
fn a_more_severe_member_copy_and_own_findings_are_kept() {
    let (mut report, mut seen) = report_with(vec![
        finding(
            "t::hostile",
            Criticality::Hostile,
            "archive:payload.dll:0x10",
        ),
        finding("t::own", Criticality::Notable, "offset:4"),
    ]);
    merge_own_finding(
        &mut report,
        &mut seen,
        finding("t::hostile", Criticality::Notable, "offset:8"),
    );
    merge_own_finding(
        &mut report,
        &mut seen,
        finding("t::own", Criticality::Hostile, "offset:9"),
    );
    assert_eq!(report.findings[0].crit, Criticality::Hostile);
    assert_eq!(
        report.findings[0].evidence[0].location.as_deref(),
        Some("archive:payload.dll:0x10")
    );
    assert_eq!(
        report.findings[1].evidence[0].location.as_deref(),
        Some("offset:4"),
        "a finding the file already owns is not replaced"
    );
    assert!(merge_own_finding(
        &mut report,
        &mut seen,
        finding("t::new", Criticality::Notable, "offset:1"),
    ));
    assert_eq!(report.findings.len(), 3);
}
