//! Header line: `diff <old> → <new>   <pct> changed   <count phrase>`.
//!
//! The header collapses a common path prefix between old and new so
//! version-stamped roots (`/foo/v1` vs `/foo/v2`) read as `v1 → v2`.
//! Per-scope change percentages sit on each scope heading in the
//! per-file pane, where they have context.

use std::fmt::Write as _;

use colored::Colorize;

use crate::types::{DiffReportV1, FileStatus};

use super::{is_significant_file, paint_roc};

pub(super) fn write(out: &mut String, diff: &DiffReportV1) {
    let (old_label, new_label) = compact_pair(&diff.old_root, &diff.new_root);
    let s = &diff.summary;
    let total_files = s.files_added + s.files_changed + s.files_removed + s.files_unchanged;
    let significant = diff
        .files
        .iter()
        .filter(|f| f.status != FileStatus::Unchanged && is_significant_file(f))
        .count() as u32;

    let count_phrase = match (total_files, significant) {
        (0, _) => String::new(),
        (1, 0) => "1 file unchanged".to_string(),
        (_, 0) => format!("{total_files} files unchanged"),
        (t, n) if n == t && n == 1 => "1 file changed".to_string(),
        (t, n) if n == t => format!("{n} files changed"),
        (_, 1) => format!("1 of {total_files} files changed"),
        (t, n) => format!("{n} of {t} files changed"),
    };

    let _ = writeln!(
        out,
        "{}  {} {} {}    {} {}    {}",
        "diff".bold().bright_cyan(),
        old_label.bold(),
        "→".dimmed(),
        new_label.bold(),
        paint_roc(s.overall_roc).bold(),
        "changed".dimmed(),
        count_phrase.dimmed(),
    );
}

/// Drop a common path prefix that ends at the last shared `/`. Returns
/// `(old_suffix, new_suffix)`. Skips degenerate root-only prefixes
/// (`"/a"` vs `"/b"` shouldn't lose its leading slash for no benefit).
/// Absolute roots remain available in `diff.old_root`/`diff.new_root`.
pub(super) fn compact_pair(old: &str, new: &str) -> (String, String) {
    let common_bytes = old
        .bytes()
        .zip(new.bytes())
        .take_while(|(a, b)| a == b)
        .count();
    let common = &old[..common_bytes];
    let split = common.rfind('/').map_or(0, |i| i + 1);
    if split <= 1 {
        (old.to_string(), new.to_string())
    } else {
        (old[split..].to_string(), new[split..].to_string())
    }
}
