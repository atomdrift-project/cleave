use super::*;
use crate::types::traits_findings::FindingKind;

fn finding(id: &str, crit: Criticality, conf: f32) -> Finding {
    let mut f = Finding::new(id.to_string(), FindingKind::Capability, String::new(), conf);
    f.crit = crit;
    f
}

fn member_with(findings: Vec<Finding>) -> FileAnalysis {
    let mut fa = FileAnalysis::new(
        1,
        "pkg.zip!!m.js".to_string(),
        "javascript".to_string(),
        "a".repeat(64),
        100,
    );
    fa.findings = findings;
    fa
}

#[test]
fn dynamic_imports_survive_archive_compaction() {
    let mut member = member_with(
        (0..8)
            .map(|i| {
                finding(
                    &format!("metadata/import/python/pkg{i}::alias{i}"),
                    if i % 2 == 0 {
                        Criticality::Baseline
                    } else {
                        Criticality::Notable
                    },
                    0.95,
                )
            })
            .collect(),
    );
    early_strip_impl(&mut member, |_| false);
    assert_eq!(
        member.findings.len(),
        8,
        "all imports must survive, not just top-three rescue"
    );
    let mut report = AnalysisReport::new(TargetInfo {
        path: "pkg.zip".into(),
        file_type: "zip".into(),
        size_bytes: 100,
        sha256: "test".into(),
        architectures: None,
    });
    report.files.push(member);
    report.strip_unmatched_traits();
    assert_eq!(report.files[0].findings.len(), 8);
}

/// The early strip's whole claim: the risk score recomputes identically
/// from the kept subset, because each 3-level group's max baseline
/// contribution survives.
#[test]
fn score_recomputes_identically_after_strip() {
    let mut full = member_with(vec![
        finding("a/b/c::one", Criticality::Baseline, 0.9),
        finding("a/b/c::two", Criticality::Baseline, 0.5),
        finding("a/b/c::three", Criticality::Baseline, 0.7),
        finding("d/e/f::one", Criticality::Baseline, 0.6),
        finding("d/e/f/deep::x", Criticality::Baseline, 0.8),
        finding("g/h/i::keep", Criticality::Notable, 0.9),
    ]);
    let mut stripped = full.clone();
    early_strip_impl(&mut stripped, |_| false);

    full.compute_summary();
    stripped.compute_summary();
    assert_eq!(
        full.score, stripped.score,
        "group-max reps must preserve the per-group score maxima"
    );
    assert_eq!(full.counts, stripped.counts, "counts only track notable+");
    assert!(
        stripped.findings.len() < 6,
        "something must actually have been stripped"
    );
}

/// `rescue_low_tier` rescues the top-3 sub-notables of a file with no
/// notable findings; the strip must keep at least that top-3.
#[test]
fn rescue_top3_survive_strip() {
    let mut fa = member_with(vec![
        finding("a/b/c::r1", Criticality::Baseline, 0.9),
        finding("a/b/c::r2", Criticality::Baseline, 0.8),
        finding("a/b/c::r3", Criticality::Baseline, 0.7),
        finding("a/b/c::gone", Criticality::Baseline, 0.1),
    ]);
    early_strip_impl(&mut fa, |_| false);
    let ids: Vec<&str> = fa.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"a/b/c::r1"));
    assert!(ids.contains(&"a/b/c::r2"));
    assert!(ids.contains(&"a/b/c::r3"));
    assert!(!ids.contains(&"a/b/c::gone"), "non-top, non-max rep drops");
}

/// Rule-referenceable findings are untouchable regardless of rank, and
/// non-strippable criticalities are never considered.
#[test]
fn referenced_and_higher_crits_are_kept() {
    let mut fa = member_with(vec![
        finding("x/y/z::referenced", Criticality::Baseline, 0.05),
        finding("x/y/z::a", Criticality::Baseline, 0.9),
        finding("x/y/z::b", Criticality::Baseline, 0.8),
        finding("x/y/z::c", Criticality::Baseline, 0.7),
        finding("comp/one::c", Criticality::Component, 0.1),
        finding("exc/one::e", Criticality::Exception, 0.1),
    ]);
    early_strip_impl(&mut fa, |id| id == "x/y/z::referenced");
    let ids: Vec<&str> = fa.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"x/y/z::referenced"), "oracle-kept survives");
    assert!(ids.contains(&"comp/one::c"), "components untouched in v1");
    assert!(ids.contains(&"exc/one::e"), "exceptions untouched in v1");
}
