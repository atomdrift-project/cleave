//! Cross-pane helpers retained from the ex-ledger module.
//!
//! `write_jitter` emits a single dimmed footer noting how many files
//! were collapsed for being below the noise floor; `sort_in_place`
//! orders panes by max trait criticality then change-%.
//!
//! The old per-file ledger table (column headers + one row per file)
//! was removed — per-scope change-% now rides on each scope heading
//! inside the per-file pane (`traits  98% changed  +10 -1`), which
//! is denser and renders cleanly under 80 columns.

use std::fmt::Write as _;

use colored::Colorize;

use crate::types::{DiffReportV1, FileDiffEntry, FileStatus};

use super::{crit_rank, file_max_roc, is_significant_file};

/// Emit a one-line footer when files were filtered out for being
/// below the noise floor (sub-1% ROC on every scope, no above-baseline
/// trait changes). Skipped silently when no jitter or no diff at all.
pub(super) fn write_jitter(out: &mut String, diff: &DiffReportV1) {
    let jitter = diff
        .files
        .iter()
        .filter(|f| f.status != FileStatus::Unchanged && !is_significant_file(f))
        .count();
    if jitter == 0 {
        return;
    }
    let _ = writeln!(
        out,
        "  {}",
        format!("· {jitter} files with low-magnitude changes only").dimmed()
    );
}

pub(super) fn sort_in_place(files: &mut [&FileDiffEntry]) {
    files.sort_by(|a, b| {
        max_added_crit_rank(b)
            .cmp(&max_added_crit_rank(a))
            .then_with(|| {
                let ra = file_max_roc(&a.scopes);
                let rb = file_max_roc(&b.scopes);
                rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.path.cmp(&b.path))
    });
}

fn max_added_crit_rank(file: &FileDiffEntry) -> i32 {
    file.scopes
        .traits
        .as_ref()
        .map(|t| t.added.iter().map(|x| crit_rank(x.crit)).max().unwrap_or(0))
        .unwrap_or(0)
}
