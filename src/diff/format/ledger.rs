//! Ledger table — one row per significant file, ranked by max trait
//! criticality then ROC. Per-scope ROCs ride in the column headers.
//! Columns whose every cell is empty are omitted entirely.

use std::fmt::Write as _;

use colored::Colorize;

use crate::types::{DiffReportV1, FileDiffEntry, FileStatus, Scope, ScopeRocs};

use super::{
    count_badges, crit_dots, crit_rank, file_max_roc, is_significant_file, max_added_crit,
    paint_roc, scope_col_width, visible_chars, WIDTH,
};

pub(super) fn write(out: &mut String, diff: &DiffReportV1) {
    // Show only the scope columns with at least one non-empty file cell.
    let cols: Vec<Scope> = Scope::ALL
        .iter()
        .copied()
        .filter(|&scope| diff.files.iter().any(|f| f.scopes.view(scope).has_changes))
        .collect();

    // Files: skip Unchanged + jitter; sort by max-crit then ROC desc.
    let mut files: Vec<&FileDiffEntry> = diff
        .files
        .iter()
        .filter(|f| f.status != FileStatus::Unchanged && is_significant_file(f))
        .collect();
    if files.is_empty() {
        let jitter = diff
            .files
            .iter()
            .filter(|f| f.status != FileStatus::Unchanged && !is_significant_file(f))
            .count();
        if jitter > 0 {
            let _ = writeln!(
                out,
                "  {}",
                format!("{jitter} files with low-magnitude changes only (collapsed)").dimmed()
            );
            out.push('\n');
        }
        return;
    }
    sort_in_place(&mut files);

    // Header row.
    let mut header = format!("  {:<3}  {:<6}  {:<32}", "", "ROC", "FILE");
    for &scope in &cols {
        let cell = header_cell(scope, &diff.summary.scope_roc);
        header.push_str("  ");
        header.push_str(&cell);
    }
    let _ = writeln!(out, "{}", header.dimmed());

    let rule_n = std::cmp::min(WIDTH, header.len()).saturating_sub(2);
    let _ = writeln!(out, "  {}", "─".repeat(rule_n).dimmed());

    for file in &files {
        write_row(out, file, &cols);
    }

    // Tail-collapse line if any jitter files were filtered out.
    let jitter = diff
        .files
        .iter()
        .filter(|f| f.status != FileStatus::Unchanged && !is_significant_file(f))
        .count();
    if jitter > 0 {
        let _ = writeln!(
            out,
            "  {}",
            format!("· {jitter} files with low-magnitude changes only").dimmed()
        );
    }

    out.push('\n');
}

/// `TRAITS 86%` when ROC is non-zero, just `TRAITS` otherwise.
fn header_cell(scope: Scope, rocs: &ScopeRocs) -> String {
    let label = scope.label();
    let width = scope_col_width(scope);
    let roc = rocs.get(scope);
    if roc <= 0.0 {
        format!("{label:<width$}")
    } else {
        let cell = format!("{label} {}", paint_roc(roc));
        // Pad based on visible (escape-stripped) width — colored ROCs
        // bring ANSI codes that don't take up screen real estate.
        let visible = label.len() + 1 + format!("{:.1}%", roc * 100.0).len();
        format!("{cell}{}", " ".repeat(width.saturating_sub(visible)))
    }
}

fn write_row(out: &mut String, file: &FileDiffEntry, cols: &[Scope]) {
    let max_crit = max_added_crit(file);
    let max_roc = file_max_roc(&file.scopes);

    let mut row = format!("  {}  ", crit_dots(max_crit));
    let roc_text = paint_roc(max_roc).bold().to_string();
    let pad = 6_usize.saturating_sub(visible_chars(&roc_text));
    row.push_str(&roc_text);
    row.push_str(&" ".repeat(pad));

    let path_truncated = if file.path.chars().count() > 32 {
        let tail: String = file.path.chars().rev().take(31).collect();
        let tail: String = tail.chars().rev().collect();
        format!("…{tail}")
    } else {
        file.path.clone()
    };
    row.push_str("  ");
    let bolded = path_truncated.bold().to_string();
    let path_pad = 32_usize.saturating_sub(visible_chars(&bolded));
    row.push_str(&bolded);
    row.push_str(&" ".repeat(path_pad));

    for &scope in cols {
        let cell = scope_cell(&file.scopes, scope);
        row.push_str("  ");
        row.push_str(&cell);
    }
    let _ = writeln!(out, "{row}");
}

/// One scope's cell: `+12 -1`, `~10`, `+5 ~3`, etc. Empty renders as `—`.
fn scope_cell(scopes: &crate::types::ScopeDiffs, scope: Scope) -> String {
    let width = scope_col_width(scope);
    let parts = count_badges(scopes.view(scope));
    if parts.is_empty() {
        let dash = "—";
        let pad = width.saturating_sub(dash.chars().count());
        return format!("{}{}", dash.dimmed(), " ".repeat(pad));
    }
    let visible: usize =
        parts.iter().map(|s| visible_chars(s)).sum::<usize>() + parts.len().saturating_sub(1); // joining spaces
    format!(
        "{}{}",
        parts.join(" "),
        " ".repeat(width.saturating_sub(visible))
    )
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
