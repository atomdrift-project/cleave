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

/// Indent that matches the column of `old_label` in the header line —
/// exactly the visible width of `"diff  "`.
const DIFF_PREFIX_WIDTH: usize = 6;

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

    // Single-file formula info, if any. Captured up-front so we can pad
    // both labels to leave room for the formula line's `old → new`:
    //   * `old_label` is right-padded to the wider of label / old formula
    //     so the formula's `→` lands directly under the header's `→`.
    //   * `new_label` is right-padded to the wider of label / new formula
    //     so `35.2% changed   1 file changed` always starts past the
    //     formula end — no visual overlap with the line below.
    let formula_pair = single_file_formula(diff);
    let label_width = old_label.chars().count();
    let new_label_width = new_label.chars().count();
    let (old_formula_width, new_formula_width) = formula_pair
        .as_ref()
        .map(|(o, n)| {
            (
                o.as_deref().map(|s| s.chars().count()).unwrap_or(0),
                n.as_deref().map(|s| s.chars().count()).unwrap_or(0),
            )
        })
        .unwrap_or((0, 0));
    let arrow_col = label_width.max(old_formula_width);
    let new_col = new_label_width.max(new_formula_width);
    let label_pad = " ".repeat(arrow_col - label_width);
    let new_label_pad = " ".repeat(new_col - new_label_width);

    let _ = writeln!(
        out,
        "{}  {}{} {} {}{}    {} {}    {}",
        "diff".bold().bright_cyan(),
        old_label.bold(),
        label_pad,
        "→".dimmed(),
        new_label.bold(),
        new_label_pad,
        paint_roc(s.overall_roc).bold(),
        "changed".dimmed(),
        count_phrase.dimmed(),
    );

    if let Some((old, new)) = formula_pair {
        write_formula_line(out, arrow_col, old.as_deref(), new.as_deref());
    }
}

/// Pull the root file's formulas if this is single-file mode.
fn single_file_formula(diff: &DiffReportV1) -> Option<(Option<String>, Option<String>)> {
    if diff.files.len() != 1 || diff.files[0].path != "<root>" {
        return None;
    }
    let f = &diff.files[0];
    if f.old_formula.is_none() && f.new_formula.is_none() {
        return None;
    }
    Some((f.old_formula.clone(), f.new_formula.clone()))
}

/// Render the `{old_formula} → {new_formula}` line under the header.
/// `old_label_width` is the visible-column width the old formula must
/// occupy (right-padded with spaces) so the formula's `→` lands at the
/// same column as the header's `→`. Skipped silently when both sides
/// are empty.
fn write_formula_line(
    out: &mut String,
    old_label_width: usize,
    old: Option<&str>,
    new: Option<&str>,
) {
    if old.is_none() && new.is_none() {
        return;
    }
    let pad = " ".repeat(DIFF_PREFIX_WIDTH);
    let arrow = "→".dimmed();
    let blank = String::new();
    let old_text = old.unwrap_or(&blank);
    let new_text = new.unwrap_or(&blank);
    // Right-pad the old formula to the exact visible width of the old
    // label so the formula's arrow aligns under the header's arrow. The
    // padding spaces are emitted *outside* the colored-string so the
    // dimmed coloring doesn't trail invisible escapes past the arrow.
    let old_visible = old_text.chars().count();
    let extra = old_label_width.saturating_sub(old_visible);
    let _ = writeln!(
        out,
        "{pad}{} {}{} {}",
        old_text.dimmed(),
        " ".repeat(extra),
        arrow,
        new_text.dimmed(),
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
