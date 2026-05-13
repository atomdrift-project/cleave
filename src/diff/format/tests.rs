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
    assert!(out.contains("changed"));
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
            old_formula: None,
            new_formula: None,
        }],
    });
    let out = format_terminal(&r);
    assert!(out.contains("a"));
    assert!(out.contains("b"));
    assert!(out.contains("changed"));
    assert!(out.contains("lib/foo.so"));
    // Per-scope change-% rides on the scope heading now.
    assert!(out.contains("traits"));
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
            old_formula: None,
            new_formula: None,
        }],
    });
    let out = format_terminal(&r);
    assert!(out.contains("1 file changed"));
    assert!(out.contains("x.py"));
    // Per-scope change-% rides on the scope heading now.
    assert!(out.contains("strings"));
    assert!(!out.contains("+0"));
    assert!(!out.contains("~0"));
    assert!(!out.contains("-0"));
    assert!(out.contains("needle"));
}

#[test]
fn header_aligns_formula_arrow_under_label_arrow_single_file() {
    // Single-file mode: the formula line lives in the header and its `→`
    // must land directly under the header's `→` regardless of whether
    // the filename or the formula is wider.
    colored::control::set_override(false);
    let r = report_with_diff(DiffReportV1 {
        old_root: "liblzma.so.5.4.5".into(),
        new_root: "liblzma.so.5.6.0".into(),
        summary: DiffSummary {
            files_changed: 1,
            overall_roc: 0.35,
            ..Default::default()
        },
        scopes: ScopeDiffs::default(),
        files: vec![FileDiffEntry {
            path: "<root>".into(),
            status: FileStatus::Changed,
            scopes: ScopeDiffs::default(),
            // Mirror the real liblzma case the user reported: new formula
            // is wider than `new_label`, which used to cause `35.2% changed
            // 1 file changed` to overlap the formula on the line below.
            old_formula: Some("H(Db)Md(Bk)".into()),
            new_formula: Some("O\u{2082}(ErS)H(Db)Md\u{2082}(BiBk)Th\u{2082}".into()),
        }],
    });
    let out = format_terminal(&r);
    colored::control::unset_override();

    let lines: Vec<&str> = out.lines().collect();
    let header = lines.iter().find(|l| l.starts_with("diff ")).copied();
    assert!(header.is_some(), "header line missing");
    let header = header.unwrap_or_default();

    let formula = lines.iter().find(|l| l.contains("H(Db)Md(Bk)")).copied();
    assert!(formula.is_some(), "formula line missing");
    let formula = formula.unwrap_or_default();
    // Compare *codepoint* offsets, not byte offsets — `→` is multibyte.
    let codepoint_col = |s: &str, c: char| s.chars().position(|x| x == c);
    assert_eq!(
        codepoint_col(header, '→'),
        codepoint_col(formula, '→'),
        "arrows must align in:\n{header}\n{formula}",
    );

    // `35.2% changed` MUST start past the formula's last codepoint so the
    // header text doesn't visually overlap the formula line below.
    let pct_col = codepoint_col(header, '%');
    assert!(pct_col.is_some(), "header missing '%'");
    let pct_col = pct_col.unwrap_or_default();
    let formula_end = formula.chars().count();
    assert!(
        pct_col >= formula_end,
        "header `% changed` (col {pct_col}) must not overlap formula \
         (ends at col {formula_end})\nheader:  {header}\nformula: {formula}",
    );
}

#[test]
fn pane_renders_old_and_new_formula_under_path() {
    // Changed file with both formulas populated should hang both
    // fingerprints under the file path, joined by an arrow.
    let r = report_with_diff(DiffReportV1 {
        old_root: "a".into(),
        new_root: "b".into(),
        summary: DiffSummary {
            files_changed: 1,
            overall_roc: 0.5,
            scope_roc: ScopeRocs {
                strings: 0.5,
                ..Default::default()
            },
            ..Default::default()
        },
        scopes: ScopeDiffs::default(),
        files: vec![FileDiffEntry {
            path: "lib/foo.so".into(),
            status: FileStatus::Changed,
            scopes: ScopeDiffs {
                strings: Some(ScopeDiff {
                    added: vec![StringChange {
                        value: "needle".into(),
                    }],
                    old_count: 1,
                    new_count: 2,
                    roc: 0.5,
                    ..Default::default()
                }),
                ..Default::default()
            },
            old_formula: Some("Md(Pt)".into()),
            new_formula: Some("KO(C)Md(Pt)".into()),
        }],
    });
    let out = format_terminal(&r);
    assert!(out.contains("Md(Pt)"), "expected old formula in:\n{out}");
    assert!(
        out.contains("KO(C)Md(Pt)"),
        "expected new formula in:\n{out}"
    );
    assert!(
        out.contains("→"),
        "expected formula arrow joiner in:\n{out}"
    );
}

#[test]
fn pane_renders_added_file_formula_only() {
    // Added file: only the new-side formula should show, prefixed with
    // an "(added)" marker so the missing left side reads correctly.
    let r = report_with_diff(DiffReportV1 {
        old_root: "a".into(),
        new_root: "b".into(),
        summary: DiffSummary {
            files_changed: 1,
            overall_roc: 1.0,
            ..Default::default()
        },
        scopes: ScopeDiffs::default(),
        files: vec![FileDiffEntry {
            path: "new_only.py".into(),
            status: FileStatus::Added,
            scopes: ScopeDiffs {
                traits: Some(ScopeDiff {
                    added: vec![TraitChange {
                        id: "objectives/c2/http/beacon".into(),
                        trait_section: "objectives".into(),
                        crit: Criticality::Suspicious,
                        desc: "x".into(),
                        count: 1,
                    }],
                    old_count: 0,
                    new_count: 1,
                    roc: 1.0,
                    ..Default::default()
                }),
                ..Default::default()
            },
            old_formula: None,
            new_formula: Some("O(C)".into()),
        }],
    });
    let out = format_terminal(&r);
    assert!(
        out.contains("(added)"),
        "expected (added) marker in:\n{out}"
    );
    assert!(out.contains("O(C)"), "expected new formula in:\n{out}");
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
        old_formula: None,
        new_formula: None,
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
