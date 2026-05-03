//! Terminal renderer for diff reports — "ledger" layout.
//!
//! Layout:
//!   1. Single-line header. Common path prefix between old and new is dropped
//!      so `cleave diff /a/b/v1 /a/b/v2` reads `v1 → v2`. ROC and file count
//!      sit on the same line. Zero-count buckets are not printed.
//!   2. Ledger table — one row per file ranked by `(max trait criticality,
//!      ROC)` descending. Per-scope ROCs ride in the column headers so the
//!      `traits` / `metrics` / `kv` / `symbols` / `strings` columns each
//!      carry their program-level context. Columns whose every cell is empty
//!      are omitted entirely (so a Python-source diff doesn't carry a dead
//!      `SECTIONS` column).
//!   3. Per-file detail panes (one per significant file). Each pane lists
//!      only the scopes that actually changed.
//!
//! Conventions:
//!   * `+` (green) = added, `-` (red) = removed, `~` (yellow) = changed.
//!   * Metric numeric changes use `↑` / `↓` (yellow) for direction.
//!   * Trait dots: ●●● hostile, ●● suspicious, ● notable, · baseline/component.
//!   * Per-file ROC tints by intensity: red ≥50%, yellow ≥20%, blue ≥5%,
//!     dim below.
use std::fmt::Write as _;

use colored::Colorize;
use serde_json::Value;

use crate::types::{AnalysisReport, Criticality};
use crate::types::{
    Changed, DiffReportV1, FileDiffEntry, FileStatus, KvChange, MetricChange, ScopeDiff,
    SectionChange, StringChange, SymbolChange, SymbolKind, TraitChange,
};

/// Render an `AnalysisReport` carrying a [`DiffReportV1`] as a colored
/// terminal-friendly string.
#[must_use]
pub fn format_terminal(report: &AnalysisReport) -> String {
    let Some(diff) = report.diff.as_ref() else {
        return "no diff present in report\n".to_string();
    };
    let mut out = String::new();
    write_header(&mut out, diff);
    write_ledger(&mut out, diff);
    write_file_panes(&mut out, diff);
    out
}

// =============================================================================
// 1. Header
// =============================================================================

/// Single-line summary: drops a common path prefix between old and new
/// (so `/foo/v1` vs `/foo/v2` reads `v1 → v2`), pins ROC + file count to
/// the right. The file count uses the post-filter "significant" set — the
/// number of files the user will actually see rendered below — so it lines
/// up with the ledger row count instead of inflating it with jitter.
/// Per-scope ROCs are *not* on this line — they sit in the ledger column
/// headers below where they have context.
fn write_header(out: &mut String, diff: &DiffReportV1) {
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
        (_, n) if n == 1 => format!("1 of {total_files} files changed"),
        (t, n) => format!("{n} of {t} files changed"),
    };

    let _ = writeln!(
        out,
        "{}  {} {} {}    {} {}    {}",
        "diff".bold().bright_cyan(),
        old_label.bold(),
        "→".dimmed(),
        new_label.bold(),
        "ROC".dimmed(),
        paint_roc(s.overall_roc).bold(),
        count_phrase.dimmed(),
    );
    out.push('\n');
}

/// Drop a common path prefix that ends at the last shared `/` separator.
/// Returns `(old_suffix, new_suffix)`. Only collapses when the common
/// prefix contains a real path component (more than just the root `/`),
/// so `/a/v1` vs `/b/v2` is left alone.
///
/// The caller can still see the absolute roots in the JSON output's
/// `diff.old_root` / `diff.new_root`.
fn compact_pair(old: &str, new: &str) -> (String, String) {
    let common_bytes = old
        .bytes()
        .zip(new.bytes())
        .take_while(|(a, b)| a == b)
        .count();
    let common = &old[..common_bytes];
    let split = common.rfind('/').map_or(0, |i| i + 1);
    // Skip degenerate root-only prefixes — `"/a"` vs `"/b"` shouldn't be
    // shown as `a` vs `b` (loses the absolute marker for no benefit).
    if split <= 1 {
        (old.to_string(), new.to_string())
    } else {
        (old[split..].to_string(), new[split..].to_string())
    }
}

/// Color a ROC percentage by intensity.
fn paint_roc(roc: f32) -> String {
    let pct = format!("{:.1}%", roc * 100.0);
    match roc {
        r if r >= 0.50 => pct.bright_red().to_string(),
        r if r >= 0.20 => pct.bright_yellow().to_string(),
        r if r >= 0.05 => pct.bright_blue().to_string(),
        r if r > 0.0 => pct.normal().to_string(),
        _ => pct.dimmed().to_string(),
    }
}

// =============================================================================
// 2. Ledger table — one row per file, ranked by max trait crit then ROC.
// =============================================================================

/// One scope's column in the ledger. We compute the visible scope set up
/// front so we don't print a column whose every cell is empty.
#[derive(Clone, Copy)]
struct ScopeCol {
    label: &'static str,
    width: usize,
    kind: ScopeKind,
}

#[derive(Clone, Copy)]
enum ScopeKind {
    Traits,
    Metrics,
    Kv,
    Symbols,
    Strings,
    Sections,
}

impl ScopeKind {
    fn roc(self, summary: &crate::types::ScopeRocs) -> f32 {
        match self {
            ScopeKind::Traits => summary.traits,
            ScopeKind::Metrics => summary.metrics,
            ScopeKind::Kv => summary.kv,
            ScopeKind::Symbols => summary.symbols,
            ScopeKind::Strings => summary.strings,
            ScopeKind::Sections => summary.sections,
        }
    }
}

const ALL_SCOPES: [ScopeCol; 6] = [
    ScopeCol {
        label: "TRAITS",
        width: 12,
        kind: ScopeKind::Traits,
    },
    ScopeCol {
        label: "METRICS",
        width: 12,
        kind: ScopeKind::Metrics,
    },
    ScopeCol {
        label: "KV",
        width: 9,
        kind: ScopeKind::Kv,
    },
    ScopeCol {
        label: "SYMBOLS",
        width: 9,
        kind: ScopeKind::Symbols,
    },
    ScopeCol {
        label: "STRINGS",
        width: 11,
        kind: ScopeKind::Strings,
    },
    ScopeCol {
        label: "SECTIONS",
        width: 11,
        kind: ScopeKind::Sections,
    },
];

fn write_ledger(out: &mut String, diff: &DiffReportV1) {
    // Determine which scope columns have at least one non-empty file cell.
    let cols: Vec<&ScopeCol> = ALL_SCOPES
        .iter()
        .filter(|c| {
            diff.files
                .iter()
                .any(|f| has_scope_changes(&f.scopes, c.kind))
        })
        .collect();

    // Files: skip Unchanged + jitter; sort by max-crit then ROC desc.
    let mut files: Vec<&FileDiffEntry> = diff
        .files
        .iter()
        .filter(|f| f.status != FileStatus::Unchanged && is_significant_file(f))
        .collect();
    if files.is_empty() {
        // Show a tail-collapse line if there are jitter-only files lurking.
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
    for col in &cols {
        let cell = ledger_header_cell(col, &diff.summary.scope_roc);
        header.push_str("  ");
        header.push_str(&cell);
    }
    let _ = writeln!(out, "{}", header.dimmed());

    let rule_n = std::cmp::min(WIDTH, header.len()).saturating_sub(2);
    let _ = writeln!(out, "  {}", "─".repeat(rule_n).dimmed());

    // Per-file rows.
    for file in &files {
        write_ledger_row(out, file, &cols);
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

fn has_scope_changes(scopes: &crate::types::ScopeDiffs, kind: ScopeKind) -> bool {
    fn changed<T>(d: &Option<ScopeDiff<T>>) -> bool {
        d.as_ref().is_some_and(ScopeDiff::has_changes)
    }
    match kind {
        ScopeKind::Traits => changed(&scopes.traits),
        ScopeKind::Metrics => changed(&scopes.metrics),
        ScopeKind::Kv => changed(&scopes.kv),
        ScopeKind::Symbols => changed(&scopes.symbols),
        ScopeKind::Strings => changed(&scopes.strings),
        ScopeKind::Sections => changed(&scopes.sections),
    }
}

/// Header cell text: `TRAITS 86%` when ROC is non-zero, just `TRAITS` otherwise.
fn ledger_header_cell(col: &ScopeCol, rocs: &crate::types::ScopeRocs) -> String {
    let roc = col.kind.roc(rocs);
    if roc <= 0.0 {
        format!("{:<width$}", col.label, width = col.width)
    } else {
        let cell = format!("{} {}", col.label, paint_roc_plain(roc));
        // Pad to column width based on visible-character count, since the
        // colored ROC may add escape codes.
        let visible = col.label.len() + 1 + format!("{:.1}%", roc * 100.0).len();
        let pad = col.width.saturating_sub(visible);
        format!("{cell}{}", " ".repeat(pad))
    }
}

fn write_ledger_row(out: &mut String, file: &FileDiffEntry, cols: &[&ScopeCol]) {
    let max_crit = max_added_crit(file);
    let max_roc = file_max_roc(&file.scopes);

    let mut row = format!("  {}  ", crit_dots(max_crit));
    let roc_text = paint_roc(max_roc).bold().to_string();
    // ROC column is fixed-width 6 (e.g. "100.0%"). Pad to that visible width
    // so subsequent columns line up regardless of whether the value is
    // 100.0% or 5.4%.
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
    // Pad after coloring so the ANSI escapes don't eat into the visible width.
    row.push_str("  ");
    let bolded = path_truncated.bold().to_string();
    let path_pad = 32_usize.saturating_sub(visible_chars(&bolded));
    row.push_str(&bolded);
    row.push_str(&" ".repeat(path_pad));

    for col in cols {
        let cell = scope_cell(&file.scopes, col.kind, col.width);
        row.push_str("  ");
        row.push_str(&cell);
    }
    let _ = writeln!(out, "{row}");
}

/// One scope's cell: `+12 -1`, `~10`, `+5 ~3`, etc. Empty scope renders as `—`.
fn scope_cell(scopes: &crate::types::ScopeDiffs, kind: ScopeKind, width: usize) -> String {
    let parts = match kind {
        ScopeKind::Traits => scope_counts(&scopes.traits),
        ScopeKind::Metrics => scope_counts(&scopes.metrics),
        ScopeKind::Kv => scope_counts(&scopes.kv),
        ScopeKind::Symbols => scope_counts(&scopes.symbols),
        ScopeKind::Strings => scope_counts(&scopes.strings),
        ScopeKind::Sections => scope_counts(&scopes.sections),
    };
    if parts.is_empty() {
        let dash = "—";
        let pad = width.saturating_sub(dash.chars().count());
        return format!("{}{}", dash.dimmed(), " ".repeat(pad));
    }
    let visible: usize = parts
        .iter()
        .map(|s| visible_chars(s.as_str()))
        .sum::<usize>()
        + parts.len().saturating_sub(1); // joining spaces
    let pad = width.saturating_sub(visible);
    format!("{}{}", parts.join(" "), " ".repeat(pad))
}

fn scope_counts<T>(scope: &Option<ScopeDiff<T>>) -> Vec<String> {
    let Some(s) = scope else { return Vec::new() };
    let mut parts = Vec::new();
    if !s.added.is_empty() {
        parts.push(format!("+{}", s.added.len()).bright_green().to_string());
    }
    if !s.removed.is_empty() {
        parts.push(format!("-{}", s.removed.len()).bright_red().to_string());
    }
    if !s.changed.is_empty() {
        parts.push(format!("~{}", s.changed.len()).bright_yellow().to_string());
    }
    parts
}

fn max_added_crit(file: &FileDiffEntry) -> Criticality {
    file.scopes
        .traits
        .as_ref()
        .map(|t| {
            t.added
                .iter()
                .map(|x| x.crit)
                .chain(t.changed.iter().map(|c| c.new.crit))
                .max()
                .unwrap_or(Criticality::Baseline)
        })
        .unwrap_or(Criticality::Baseline)
}

/// A file is "significant" (worth listing in the ledger and giving a pane
/// to) if any scope ROC clears the noise floor, OR if any trait change is
/// above baseline. This keeps the metric-rounding tail out of the renderer
/// without hiding real findings.
fn is_significant_file(file: &FileDiffEntry) -> bool {
    const ROC_FLOOR: f32 = 0.01;
    if file_max_roc(&file.scopes) >= ROC_FLOOR {
        return true;
    }
    let Some(traits) = file.scopes.traits.as_ref() else {
        return false;
    };
    traits
        .added
        .iter()
        .chain(traits.removed.iter())
        .any(|t| matters(t.crit))
        || traits.changed.iter().any(|c| matters(c.new.crit))
}

/// ROC formatted without color (for visible-width arithmetic).
fn paint_roc_plain(roc: f32) -> String {
    paint_roc(roc).to_string()
}

/// Number of visible characters in a string ignoring ANSI escape sequences.
fn visible_chars(s: &str) -> usize {
    let mut n = 0;
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c2 in chars.by_ref() {
                if c2 == 'm' {
                    break;
                }
            }
        } else {
            n += 1;
        }
    }
    n
}

// =============================================================================
// 3. Per-file detail panes
// =============================================================================

fn write_file_panes(out: &mut String, diff: &DiffReportV1) {
    let mut files: Vec<&FileDiffEntry> = diff
        .files
        .iter()
        .filter(|f| f.status != FileStatus::Unchanged && is_significant_file(f))
        .collect();
    sort_in_place(&mut files);
    for file in files {
        write_pane(out, file);
        out.push('\n');
    }
}

/// Per-file detail pane. Flat layout that visually continues the ledger:
/// heading line (criticality dot, ROC, path), thin rule, then each scope as
/// a sub-block with a `name  +A -R ~C` heading and its entries indented.
/// No left rail, no closing rule — the next file's heading separates them.
fn write_pane(out: &mut String, file: &FileDiffEntry) {
    let max_roc = file_max_roc(&file.scopes);
    let max_crit = max_added_crit(file);

    // Heading: ●●  100.0%  models/yolo/model.py
    let _ = writeln!(
        out,
        "{}  {}  {}",
        crit_dots(max_crit),
        paint_roc(max_roc).bold(),
        file.path.bold(),
    );
    let _ = writeln!(out, "{}", "─".repeat(WIDTH).dimmed());

    if let Some(t) = &file.scopes.traits {
        if t.has_changes() {
            write_traits_section(out, t);
        }
    }
    if let Some(m) = &file.scopes.metrics {
        if m.has_changes() {
            write_metrics_section(out, m);
        }
    }
    if let Some(k) = &file.scopes.kv {
        if k.has_changes() {
            write_kv_section(out, k);
        }
    }
    if let Some(y) = &file.scopes.symbols {
        if y.has_changes() {
            write_symbols_section(out, y);
        }
    }
    if let Some(s) = &file.scopes.strings {
        if s.has_changes() {
            write_strings_section(out, s);
        }
    }
    if let Some(e) = &file.scopes.sections {
        if e.has_changes() {
            write_sections_section(out, e);
        }
    }
}

/// Render `traits  +10 -1` as a section heading: scope name in bold, then
/// dimmed counts. Skips zero counts. Omits the counts entirely if all are
/// zero (caller already gated on `has_changes`).
fn scope_heading<T>(scope_name: &str, scope: &ScopeDiff<T>) -> String {
    let mut bits: Vec<String> = Vec::new();
    if !scope.added.is_empty() {
        bits.push(format!("+{}", scope.added.len()).bright_green().to_string());
    }
    if !scope.removed.is_empty() {
        bits.push(format!("-{}", scope.removed.len()).bright_red().to_string());
    }
    if !scope.changed.is_empty() {
        bits.push(
            format!("~{}", scope.changed.len())
                .bright_yellow()
                .to_string(),
        );
    }
    if bits.is_empty() {
        format!("\n  {}", scope_name.bold())
    } else {
        format!("\n  {}  {}", scope_name.bold(), bits.join(" "))
    }
}

// ---- traits -----------------------------------------------------------------

fn write_traits_section(out: &mut String, scope: &ScopeDiff<TraitChange>) {
    let _ = writeln!(out, "{}", scope_heading("traits", scope));

    // Order: above-baseline first by crit desc, then alphabetical by id.
    let mut visible: Vec<(&'static str, &TraitChange)> = Vec::new();
    let mut hidden = 0u32;

    for t in &scope.added {
        if matters(t.crit) {
            visible.push(("+", t));
        } else {
            hidden += 1;
        }
    }
    for t in &scope.removed {
        if matters(t.crit) {
            visible.push(("-", t));
        } else {
            hidden += 1;
        }
    }
    for c in &scope.changed {
        if matters(c.new.crit) {
            visible.push(("~", &c.new));
        } else {
            hidden += 1;
        }
    }
    visible.sort_by(|a, b| {
        crit_rank(b.1.crit)
            .cmp(&crit_rank(a.1.crit))
            .then_with(|| a.1.id.cmp(&b.1.id))
    });

    for (sign, t) in &visible {
        let _ = writeln!(
            out,
            "    {} {} {}",
            crit_dots(t.crit),
            paint_sign(sign),
            paint_crit(short_id(&t.id), t.crit),
        );
    }
    if hidden > 0 {
        let _ = writeln!(
            out,
            "    {}",
            format!("· {} baseline/component traits hidden", hidden).dimmed(),
        );
    }
}

// ---- metrics ----------------------------------------------------------------

fn write_metrics_section(out: &mut String, scope: &ScopeDiff<MetricChange>) {
    let _ = writeln!(out, "{}", scope_heading("metrics", scope));

    for c in &scope.added {
        let _ = writeln!(
            out,
            "    {} {:<40} = {}",
            paint_sign("+"),
            c.path,
            format_value(&c.value),
        );
    }
    for c in &scope.removed {
        let _ = writeln!(
            out,
            "    {} {:<40} = {}",
            paint_sign("-"),
            c.path,
            format_value(&c.value),
        );
    }
    for Changed { old, new } in &scope.changed {
        let arrow = numeric_direction(&old.value, &new.value);
        let _ = writeln!(
            out,
            "    {} {:<40} : {} {} {}",
            arrow,
            new.path,
            format_value(&old.value).dimmed(),
            "→".dimmed(),
            format_value(&new.value),
        );
    }
}

/// `↑` for numeric increase, `↓` for numeric decrease, `~` for everything
/// else (boolean flips, string changes). Always yellow — same as the global
/// "changed" verb so the eye doesn't have to learn three colors.
fn numeric_direction(old: &Value, new: &Value) -> colored::ColoredString {
    if let (Some(a), Some(b)) = (old.as_f64(), new.as_f64()) {
        if b > a {
            return "↑".bright_yellow();
        }
        if b < a {
            return "↓".bright_yellow();
        }
    }
    "~".bright_yellow()
}

// ---- kv ---------------------------------------------------------------------

fn write_kv_section(out: &mut String, scope: &ScopeDiff<KvChange>) {
    let _ = writeln!(out, "{}", scope_heading("kv", scope));

    for c in &scope.added {
        write_kv_row(out, "+", &c.path, None, &c.value);
    }
    for c in &scope.removed {
        write_kv_row(out, "-", &c.path, None, &c.value);
    }
    for Changed { old, new } in &scope.changed {
        write_kv_row(out, "~", &new.path, Some(&old.value), &new.value);
    }
}

/// One kv row. Membership-encoded paths (`prefix[]=value`, produced by the
/// flattener for arrays of leaves) display as `prefix[]   value` since the
/// path already contains the value — printing `path = value` would show the
/// same string twice. Regular path/value pairs use the `path = value` form.
fn write_kv_row(
    out: &mut String,
    sign: &str,
    path: &str,
    old_value: Option<&Value>,
    value: &Value,
) {
    let (display_path, is_membership) = match path.find("[]=") {
        Some(idx) => (format!("{}[]", &path[..idx]), true),
        None => (path.to_string(), false),
    };

    if is_membership {
        // For membership entries, the value IS the path's tail. Show only the
        // value (already contained in the path); a "changed" form is unusual
        // here because paths are value-keyed, but render conservatively.
        let _ = writeln!(
            out,
            "    {} {:<40}   {}",
            paint_sign(sign),
            truncate(&display_path, 40),
            format_value(value),
        );
    } else if let Some(old) = old_value {
        let _ = writeln!(
            out,
            "    {} {:<40} : {} {} {}",
            paint_sign(sign),
            truncate(&display_path, 40),
            format_value(old).dimmed(),
            "→".dimmed(),
            format_value(value),
        );
    } else {
        let _ = writeln!(
            out,
            "    {} {:<40} = {}",
            paint_sign(sign),
            truncate(&display_path, 40),
            format_value(value),
        );
    }
}

// ---- symbols ----------------------------------------------------------------

fn write_symbols_section(out: &mut String, scope: &ScopeDiff<SymbolChange>) {
    let _ = writeln!(out, "{}", scope_heading("symbols", scope));

    for c in &scope.added {
        let _ = writeln!(out, "    {} {}", paint_sign("+"), symbol_label(c));
    }
    for c in &scope.removed {
        let _ = writeln!(out, "    {} {}", paint_sign("-"), symbol_label(c));
    }
}

fn symbol_label(c: &SymbolChange) -> String {
    let kind = match c.kind {
        SymbolKind::Import => "import",
        SymbolKind::Export => "export",
    };
    match &c.library {
        Some(lib) => format!("[{kind}] {} @ {lib}", c.symbol),
        None => format!("[{kind}] {}", c.symbol),
    }
}

// ---- strings ----------------------------------------------------------------

const STRING_TAIL: usize = 25;

fn write_strings_section(out: &mut String, scope: &ScopeDiff<StringChange>) {
    let _ = writeln!(
        out,
        "{}    {}",
        scope_heading("strings", scope),
        format!("(last {STRING_TAIL} in file)").dimmed(),
    );

    let added_tail = tail(&scope.added, STRING_TAIL);
    let removed_tail = tail(&scope.removed, STRING_TAIL);
    let changed_tail = tail(&scope.changed, STRING_TAIL);

    if let Some(hidden) = added_tail.hidden {
        let _ = writeln!(
            out,
            "    {}",
            format!("· {hidden} earlier added strings hidden").dimmed()
        );
    }
    for s in added_tail.items {
        let _ = writeln!(out, "    {} {}", paint_sign("+"), truncate(&s.value, 200));
    }
    if let Some(hidden) = removed_tail.hidden {
        let _ = writeln!(
            out,
            "    {}",
            format!("· {hidden} earlier removed strings hidden").dimmed()
        );
    }
    for s in removed_tail.items {
        let _ = writeln!(out, "    {} {}", paint_sign("-"), truncate(&s.value, 200));
    }
    for c in changed_tail.items {
        let _ = writeln!(
            out,
            "    {} {} {} {}",
            paint_sign("~"),
            truncate(&c.old.value, 80).dimmed(),
            "→".dimmed(),
            truncate(&c.new.value, 80),
        );
    }
}

struct Tail<'a, T> {
    items: Vec<&'a T>,
    hidden: Option<usize>,
}

fn tail<T>(items: &[T], n: usize) -> Tail<'_, T> {
    if items.len() <= n {
        Tail {
            items: items.iter().collect(),
            hidden: None,
        }
    } else {
        let start = items.len() - n;
        Tail {
            items: items[start..].iter().collect(),
            hidden: Some(start),
        }
    }
}

// ---- sections (binary) ------------------------------------------------------

fn write_sections_section(out: &mut String, scope: &ScopeDiff<SectionChange>) {
    let _ = writeln!(out, "{}", scope_heading("sections", scope));

    for s in &scope.added {
        let _ = writeln!(out, "    {} {}", paint_sign("+"), section_label(s));
    }
    for s in &scope.removed {
        let _ = writeln!(out, "    {} {}", paint_sign("-"), section_label(s));
    }
    for Changed { old, new } in &scope.changed {
        let _ = writeln!(
            out,
            "    {} {} : size {} {} {}, entropy {:.2} {} {:.2}",
            paint_sign("~"),
            new.name,
            old.size,
            "→".dimmed(),
            new.size,
            old.entropy,
            "→".dimmed(),
            new.entropy
        );
    }
}

fn section_label(s: &SectionChange) -> String {
    let perms = s.permissions.as_deref().unwrap_or("???");
    format!(
        "{} (size {}, entropy {:.2}, perms {})",
        s.name, s.size, s.entropy, perms
    )
}

// =============================================================================
// Sorting + ranking helpers
// =============================================================================

fn sort_in_place(files: &mut [&FileDiffEntry]) {
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

/// Highest criticality among newly-added traits in this file. `0` when none.
fn max_added_crit_rank(file: &FileDiffEntry) -> i32 {
    file.scopes
        .traits
        .as_ref()
        .map(|t| t.added.iter().map(|x| crit_rank(x.crit)).max().unwrap_or(0))
        .unwrap_or(0)
}

/// Worst ROC across this file's scopes. Used for the per-file `[NN%]` header
/// and for tie-breaking the sort.
fn file_max_roc(scopes: &crate::types::ScopeDiffs) -> f32 {
    let candidates = [
        scopes.traits.as_ref().map(|s| s.roc),
        scopes.metrics.as_ref().map(|s| s.roc),
        scopes.kv.as_ref().map(|s| s.roc),
        scopes.symbols.as_ref().map(|s| s.roc),
        scopes.strings.as_ref().map(|s| s.roc),
        scopes.sections.as_ref().map(|s| s.roc),
    ];
    candidates.iter().filter_map(|x| *x).fold(0.0_f32, f32::max)
}

// =============================================================================
// Trait helpers
// =============================================================================

fn matters(c: Criticality) -> bool {
    matches!(
        c,
        Criticality::Notable | Criticality::Suspicious | Criticality::Hostile
    )
}

fn crit_rank(c: Criticality) -> i32 {
    match c {
        Criticality::Hostile => 5,
        Criticality::Suspicious => 4,
        Criticality::Notable => 3,
        Criticality::Baseline => 2,
        Criticality::Component => 1,
        Criticality::Filtered => 0,
    }
}

fn crit_dots(c: Criticality) -> colored::ColoredString {
    match c {
        Criticality::Hostile => "●●●".bright_red().bold(),
        Criticality::Suspicious => "●● ".bright_yellow().bold(),
        Criticality::Notable => "●  ".bright_blue(),
        Criticality::Baseline => "·  ".bright_green(),
        Criticality::Component | Criticality::Filtered => "·  ".dimmed(),
    }
}

fn paint_crit<S: AsRef<str>>(text: S, c: Criticality) -> colored::ColoredString {
    let s = text.as_ref();
    match c {
        Criticality::Hostile => s.bright_red().bold(),
        Criticality::Suspicious => s.bright_yellow().bold(),
        Criticality::Notable => s.bright_blue(),
        Criticality::Baseline => s.bright_green(),
        Criticality::Component | Criticality::Filtered => s.dimmed(),
    }
}

fn paint_sign(sign: &str) -> colored::ColoredString {
    match sign {
        "+" => "+".bright_green().bold(),
        "-" => "-".bright_red().bold(),
        "~" => "~".bright_yellow().bold(),
        _ => sign.normal(),
    }
}

// =============================================================================
// Misc
// =============================================================================

const WIDTH: usize = 80;

fn short_id(id: &str) -> String {
    id.strip_prefix("well-known/malware/supply-chain/")
        .or_else(|| id.strip_prefix("well-known/"))
        .or_else(|| id.strip_prefix("objectives/"))
        .or_else(|| id.strip_prefix("micro-behaviors/"))
        .or_else(|| id.strip_prefix("metadata/"))
        .unwrap_or(id)
        .to_string()
}

fn format_value(v: &Value) -> String {
    match v {
        Value::String(s) => format!("\"{}\"", truncate(s, 80)),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        _ => truncate(&v.to_string(), 80),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::{
        DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, ScopeDiff, ScopeDiffs, ScopeRocs,
        StringChange, TargetInfo, TraitChange,
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
        // Header line with both old/new and ROC.
        assert!(out.contains("a"));
        assert!(out.contains("b"));
        assert!(out.contains("ROC"));
        // The ledger should include the file path and the per-scope tally.
        assert!(out.contains("lib/foo.so"));
        assert!(out.contains("TRAITS"));
        // The pane below should surface the actual finding id.
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
        // 1 file in, 1 file changed → singular "1 file changed".
        assert!(out.contains("1 file changed"));
        // Ledger row must list the path and the +1 added strings cell.
        assert!(out.contains("x.py"));
        assert!(out.contains("STRINGS"));
        // No zero-count noise: the renderer should not emit "+0" / "-0" / "~0".
        assert!(!out.contains("+0"));
        assert!(!out.contains("~0"));
        assert!(!out.contains("-0"));
        // The pane below should surface the actual string.
        assert!(out.contains("needle"));
    }

    #[test]
    fn compact_pair_strips_common_prefix() {
        let (a, b) = compact_pair("/x/y/v1", "/x/y/v2");
        assert_eq!(a, "v1");
        assert_eq!(b, "v2");

        let (a, b) = compact_pair("v1", "v2");
        assert_eq!(a, "v1");
        assert_eq!(b, "v2");

        // Differing parents → no collapse.
        let (a, b) = compact_pair("/a/v1", "/b/v1");
        assert_eq!(a, "/a/v1");
        assert_eq!(b, "/b/v1");
    }

    #[test]
    fn metric_direction_arrows() {
        let scope: ScopeDiff<MetricChange> = ScopeDiff {
            changed: vec![
                Changed {
                    old: MetricChange {
                        path: "x".into(),
                        value: Value::from(10),
                    },
                    new: MetricChange {
                        path: "x".into(),
                        value: Value::from(20),
                    },
                },
                Changed {
                    old: MetricChange {
                        path: "y".into(),
                        value: Value::from(20),
                    },
                    new: MetricChange {
                        path: "y".into(),
                        value: Value::from(10),
                    },
                },
            ],
            old_count: 2,
            new_count: 2,
            old_weight: 2.0,
            new_weight: 2.0,
            change_weight: 0.5,
            roc: 0.25,
            truncated: false,
            ..Default::default()
        };
        let mut out = String::new();
        write_metrics_section(&mut out, &scope);
        // ↑ for the increase, ↓ for the decrease.
        assert!(out.contains('↑'));
        assert!(out.contains('↓'));
        assert!(!out.contains(" ~ "));
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
        let files = [mk("low.py", Criticality::Notable, 0.9),
            mk("med.py", Criticality::Suspicious, 0.1),
            mk("high.py", Criticality::Hostile, 0.05),
            mk("susp_high_roc.py", Criticality::Suspicious, 0.5)];
        let mut refs: Vec<&FileDiffEntry> = files.iter().collect();
        sort_in_place(&mut refs);
        let order: Vec<&str> = refs.iter().map(|f| f.path.as_str()).collect();
        // hostile first regardless of ROC; then both suspicious (higher ROC
        // first), then the notable file.
        assert_eq!(
            order,
            vec!["high.py", "susp_high_roc.py", "med.py", "low.py"]
        );
    }
}
