//! End-to-end tests for `cleave diff`. Exercises the full pipeline
//! (analyze cache → scope diffs → envelope) against on-disk fixtures.
//!
//! All assertions are bundled into two `#[test]` functions so the heavy
//! analysis work — analyzing ELF and Mach-O fixtures — runs once per
//! test binary instead of being repeated across separate test processes.
#![allow(clippy::expect_used)]

use std::path::Path;

use cleave::AnalysisOptions;
use cleave::diff::{DEFAULT_LIMIT_CHANGES, ScopeMask, diff_paths};
use cleave::types::FileStatus;

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
    if !Path::new(ELF).exists() {
        crate::support::skip_missing(&format!("diff_same_file_has_zero_roc: {ELF}"));
        return;
    }
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

/// Combined assertions for ELF-vs-Mach-O diff behavior.
///
/// Bundled into one test so the underlying file analyses (which dominate
/// runtime) happen once per test process instead of three times.
#[test]
fn diff_elf_vs_macho_behavior() {
    if !Path::new(ELF).exists() || !Path::new(MACHO).exists() {
        crate::support::skip_missing(&format!("diff_elf_vs_macho_behavior: {ELF} / {MACHO}"));
        return;
    }
    // ── changes are detected at top level ──
    let full = diff_paths(
        Path::new(ELF),
        Path::new(MACHO),
        &options(),
        ScopeMask::all(),
        DEFAULT_LIMIT_CHANGES,
    )
    .expect("full-scope diff should succeed");
    let full_diff = full.diff.expect("diff should be present");
    // Two single-file inputs canonicalize their root path so they pair —
    // even when the filenames differ. ELF vs Mach-O thus shows up as a
    // single CHANGED entry with substantial scope churn, not add+remove.
    assert_eq!(full_diff.summary.files_changed, 1);
    assert_eq!(full_diff.summary.files_added, 0);
    assert_eq!(full_diff.summary.files_removed, 0);
    assert!(full_diff.summary.overall_roc > 0.0);
    assert_eq!(full_diff.files.len(), 1);
    assert_eq!(full_diff.files[0].status, FileStatus::Changed);

    // ── scope filter excludes other scopes ──
    let strings_mask = ScopeMask::parse("strings").expect("parse");
    let scoped = diff_paths(
        Path::new(ELF),
        Path::new(MACHO),
        &options(),
        strings_mask,
        DEFAULT_LIMIT_CHANGES,
    )
    .expect("strings-scope diff should succeed");
    let scoped_diff = scoped.diff.expect("diff should be present");
    assert!(
        scoped_diff.scopes.strings.is_some(),
        "strings scope should be included"
    );
    assert!(
        scoped_diff.scopes.traits.is_none(),
        "traits should be excluded"
    );
    assert!(
        scoped_diff.scopes.metrics.is_none(),
        "metrics should be excluded"
    );
    assert!(scoped_diff.scopes.kv.is_none(), "value should be excluded");
    assert!(
        scoped_diff.scopes.symbols.is_none(),
        "symbols should be excluded"
    );
    assert!(
        scoped_diff.scopes.sections.is_none(),
        "sections should be excluded"
    );
    for entry in &scoped_diff.files {
        assert!(
            entry.scopes.traits.is_none() && entry.scopes.metrics.is_none(),
            "per-file scopes outside the mask should be absent"
        );
    }

    // ── limit caps visible change lists ──
    let limit = 3;
    let limited = diff_paths(
        Path::new(ELF),
        Path::new(MACHO),
        &options(),
        ScopeMask::parse("strings").expect("parse"),
        limit,
    )
    .expect("limited diff should succeed");
    let limited_diff = limited.diff.expect("diff should be present");
    if let Some(strings) = limited_diff.scopes.strings {
        assert!(strings.added.len() <= limit);
        assert!(strings.removed.len() <= limit);
        if strings.truncated {
            assert!(strings.old_count > 0 || strings.new_count > 0);
        }
    }
}
