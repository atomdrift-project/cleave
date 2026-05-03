//! End-to-end tests for `cleave diff`. Exercises the full pipeline
//! (analyze cache → scope diffs → envelope) against on-disk fixtures.
#![allow(clippy::expect_used)]

use std::path::Path;

use cleave::diff::{diff_paths, ScopeMask, DEFAULT_LIMIT_CHANGES};
use cleave::types::FileStatus;
use cleave::AnalysisOptions;

const ELF: &str = "tests/fixtures/test.elf";
const MACHO: &str = "tests/fixtures/test.macho";

fn options() -> AnalysisOptions {
    AnalysisOptions {
        // Speed up the test: skip YARA and r2 — the diff cares about traits,
        // metrics, kv, symbols, strings, sections, none of which require YARA.
        disable_yara: true,
        disable_radare2: true,
        ..AnalysisOptions::default()
    }
}

#[test]
fn diff_same_file_has_zero_roc() {
    let report = diff_paths(
        Path::new(ELF),
        Path::new(ELF),
        &options(),
        ScopeMask::all(),
        DEFAULT_LIMIT_CHANGES,
    )
    .expect("diff should succeed");

    let diff = report.diff.expect("diff should be present");
    assert_eq!(diff.summary.files_added, 0);
    assert_eq!(diff.summary.files_removed, 0);
    assert_eq!(diff.summary.files_changed, 0);
    assert!(diff.summary.files_unchanged >= 1);
    assert_eq!(diff.summary.overall_roc, 0.0);
    // Self-diff should produce no per-file detail (all are unchanged and
    // therefore filtered out of the visible files list).
    assert!(diff.files.is_empty());
}

#[test]
fn diff_different_binaries_has_changes() {
    let report = diff_paths(
        Path::new(ELF),
        Path::new(MACHO),
        &options(),
        ScopeMask::all(),
        DEFAULT_LIMIT_CHANGES,
    )
    .expect("diff should succeed");

    let diff = report.diff.expect("diff should be present");
    // Two single-file inputs canonicalize their root path so they pair —
    // even when the filenames differ. ELF vs Mach-O thus shows up as a
    // single CHANGED entry with substantial scope churn, not add+remove.
    assert_eq!(diff.summary.files_changed, 1);
    assert_eq!(diff.summary.files_added, 0);
    assert_eq!(diff.summary.files_removed, 0);
    assert!(diff.summary.overall_roc > 0.0);

    assert_eq!(diff.files.len(), 1);
    assert_eq!(diff.files[0].status, FileStatus::Changed);
}

#[test]
fn scope_filter_excludes_other_scopes() {
    let mask = ScopeMask::parse("strings").expect("parse");
    let report = diff_paths(
        Path::new(ELF),
        Path::new(MACHO),
        &options(),
        mask,
        DEFAULT_LIMIT_CHANGES,
    )
    .expect("diff should succeed");

    let diff = report.diff.expect("diff should be present");
    // Strings scope should be present in at least the program-level rollup.
    let strings_present = diff.scopes.strings.is_some();
    assert!(strings_present, "strings scope should be included");
    assert!(diff.scopes.traits.is_none(), "traits should be excluded");
    assert!(diff.scopes.metrics.is_none(), "metrics should be excluded");
    assert!(diff.scopes.kv.is_none(), "kv should be excluded");
    assert!(diff.scopes.symbols.is_none(), "symbols should be excluded");
    assert!(
        diff.scopes.sections.is_none(),
        "sections should be excluded"
    );

    for entry in &diff.files {
        assert!(
            entry.scopes.traits.is_none() && entry.scopes.metrics.is_none(),
            "per-file scopes outside the mask should be absent"
        );
    }
}

#[test]
fn limit_changes_caps_visible_lists() {
    let mask = ScopeMask::parse("strings").expect("parse");
    let limit = 3;
    let report = diff_paths(Path::new(ELF), Path::new(MACHO), &options(), mask, limit)
        .expect("diff should succeed");

    let diff = report.diff.expect("diff should be present");
    if let Some(strings) = diff.scopes.strings {
        assert!(strings.added.len() <= limit);
        assert!(strings.removed.len() <= limit);
        // Counts reflect pre-truncation totals.
        if strings.truncated {
            assert!(strings.old_count > 0 || strings.new_count > 0);
        }
    }
}
