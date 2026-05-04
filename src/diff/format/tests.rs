//! Integration tests over the assembled `format_terminal` output.
//! Submodule-local rendering tests live next to the helper they
//! cover (e.g. `numeric_direction` in `panes::tests`).
#![allow(clippy::unwrap_used)]

use super::format_terminal;
use crate::types::{
    AnalysisReport, Criticality, DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, ScopeDiff,
    ScopeDiffs, ScopeRocs, StringChange, TargetInfo, TraitChange,
};

fn report_with_diff(diff: DiffReportV1) -> AnalysisReport {
    let mut r = AnalysisReport::new(TargetInfo::default());
    r.diff = Some(diff);
    r
}

#[test]
fn empty_diff_renders_header() {
    let r = report_with_diff(DiffReportV1 {
        old_root: "old".into(),
        new_root: "new".into(),
        summary: DiffSummary::default(),
        scopes: ScopeDiffs::default(),
        files: vec![],
    });
    let out = format_terminal(&r);
    assert!(out.contains("diff"));
    assert!(out.contains("ROC"));
}

#[test]
fn renders_ledger_row_for_added_file() {
    let r = report_with_diff(DiffReportV1 {
        old_root: "a".into(),
        new_root: "b".into(),
        summary: DiffSummary {
            files_added: 1,
            overall_roc: 0.9,
            scope_roc: ScopeRocs {
                traits: 0.9,
                ..Default::default()
            },
            ..Default::default()
        },
        scopes: ScopeDiffs::default(),
        files: vec![FileDiffEntry {
            path: "lib/foo.so".into(),
            status: FileStatus::Added,
            scopes: ScopeDiffs {
                traits: Some(ScopeDiff {
                    added: vec![TraitChange {
                        id: "well-known/malware/supply-chain/family::evil".into(),
                        trait_section: "well-known".into(),
                        crit: Criticality::Suspicious,
                        desc: "evil thing".into(),
                        count: 1,
                    }],
                    old_count: 0,
                    new_count: 1,
                    old_weight: 0.0,
                    new_weight: 36.0,
                    change_weight: 36.0,
                    roc: 1.0,
                    truncated: false,
                    ..Default::default()
                }),
                ..Default::default()
            },
        }],
    });
    let out = format_terminal(&r);
    assert!(out.contains("a"));
    assert!(out.contains("b"));
    assert!(out.contains("ROC"));
    assert!(out.contains("lib/foo.so"));
    assert!(out.contains("TRAITS"));
    assert!(out.contains("family::evil"));
}

#[test]
fn renders_changed_file_in_ledger_no_zero_filler() {
    let r = report_with_diff(DiffReportV1 {
        old_root: "a".into(),
        new_root: "b".into(),
        summary: DiffSummary {
            files_changed: 1,
            overall_roc: 0.16,
            scope_roc: ScopeRocs {
                strings: 0.16,
                ..Default::default()
            },
            ..Default::default()
        },
        scopes: ScopeDiffs::default(),
        files: vec![FileDiffEntry {
            path: "x.py".into(),
            status: FileStatus::Changed,
            scopes: ScopeDiffs {
                strings: Some(ScopeDiff {
                    added: vec![StringChange {
                        value: "needle".into(),
                    }],
                    old_count: 5,
                    new_count: 6,
                    old_weight: 5.0,
                    new_weight: 6.0,
                    change_weight: 1.0,
                    roc: 0.166_666_67,
                    truncated: false,
                    ..Default::default()
                }),
                ..Default::default()
            },
        }],
    });
    let out = format_terminal(&r);
    assert!(out.contains("1 file changed"));
    assert!(out.contains("x.py"));
    assert!(out.contains("STRINGS"));
    assert!(!out.contains("+0"));
    assert!(!out.contains("~0"));
    assert!(!out.contains("-0"));
    assert!(out.contains("needle"));
}

#[test]
fn compact_pair_strips_common_prefix() {
    let (a, b) = super::header::compact_pair("/x/y/v1", "/x/y/v2");
    assert_eq!(a, "v1");
    assert_eq!(b, "v2");

    let (a, b) = super::header::compact_pair("v1", "v2");
    assert_eq!(a, "v1");
    assert_eq!(b, "v2");

    // Differing parents → no collapse.
    let (a, b) = super::header::compact_pair("/a/v1", "/b/v1");
    assert_eq!(a, "/a/v1");
    assert_eq!(b, "/b/v1");
}

#[test]
fn sort_files_by_max_crit_then_roc() {
    let mk = |path: &str, crit: Criticality, roc: f32| FileDiffEntry {
        path: path.into(),
        status: FileStatus::Changed,
        scopes: ScopeDiffs {
            traits: Some(ScopeDiff {
                added: vec![TraitChange {
                    id: "x".into(),
                    trait_section: "x".into(),
                    crit,
                    desc: "".into(),
                    count: 1,
                }],
                old_count: 1,
                new_count: 1,
                roc,
                ..Default::default()
            }),
            ..Default::default()
        },
    };
    let files = [
        mk("low.py", Criticality::Notable, 0.9),
        mk("med.py", Criticality::Suspicious, 0.1),
        mk("high.py", Criticality::Hostile, 0.05),
        mk("susp_high_roc.py", Criticality::Suspicious, 0.5),
    ];
    let mut refs: Vec<&FileDiffEntry> = files.iter().collect();
    super::ledger::sort_in_place(&mut refs);
    let order: Vec<&str> = refs.iter().map(|f| f.path.as_str()).collect();
    // hostile first regardless of ROC; then both suspicious (higher ROC
    // first), then the notable file.
    assert_eq!(
        order,
        vec!["high.py", "susp_high_roc.py", "med.py", "low.py"]
    );
}
