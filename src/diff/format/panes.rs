//! Per-file detail panes — one per significant file. Each pane lists
//! only the scopes that actually changed, in the same order as the
//! ledger columns.

use std::fmt::Write as _;

use colored::Colorize;
use serde_json::Value;

use crate::types::{
    Changed, DiffReportV1, FileDiffEntry, FileStatus, KvChange, MetricChange, ScopeDiff,
    SectionChange, StringChange, SymbolChange, SymbolKind, TraitChange,
};

use super::ledger::sort_in_place;
use super::{
    count_badges, crit_dots, crit_rank, file_max_roc, format_value, is_significant_file, matters,
    max_added_crit, paint_crit, paint_roc, paint_sign, short_id, truncate, WIDTH,
};

pub(super) fn write(out: &mut String, diff: &DiffReportV1) {
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

/// Per-file detail pane. Flat layout that visually continues the
/// ledger: heading line (criticality dot, ROC, path), thin rule, then
/// each scope as a sub-block with a `name  +A -R ~C` heading and its
/// entries indented. No left rail; the next file's heading separates them.
fn write_pane(out: &mut String, file: &FileDiffEntry) {
    let max_roc = file_max_roc(&file.scopes);
    let max_crit = max_added_crit(file);

    let _ = writeln!(
        out,
        "{}  {}  {}",
        crit_dots(max_crit),
        paint_roc(max_roc).bold(),
        file.path.bold(),
    );
    let _ = writeln!(out, "{}", "─".repeat(WIDTH).dimmed());

    if let Some(t) = file.scopes.traits.as_ref().filter(|s| s.has_changes()) {
        write_traits(out, t);
    }
    if let Some(m) = file.scopes.metrics.as_ref().filter(|s| s.has_changes()) {
        write_metrics(out, m);
    }
    if let Some(k) = file.scopes.kv.as_ref().filter(|s| s.has_changes()) {
        write_kv(out, k);
    }
    if let Some(y) = file.scopes.symbols.as_ref().filter(|s| s.has_changes()) {
        write_symbols(out, y);
    }
    if let Some(s) = file.scopes.strings.as_ref().filter(|s| s.has_changes()) {
        write_strings(out, s);
    }
    if let Some(e) = file.scopes.sections.as_ref().filter(|s| s.has_changes()) {
        write_sections(out, e);
    }
}

/// `traits  +10 -1` heading: scope name in bold + dimmed counts.
/// Caller has already gated on `has_changes`, so at least one count
/// will be present.
fn scope_heading<T>(scope_name: &str, scope: &ScopeDiff<T>) -> String {
    let view: crate::types::ScopeView<'_> = Some(scope).into();
    let bits = count_badges(view);
    if bits.is_empty() {
        format!("\n  {}", scope_name.bold())
    } else {
        format!("\n  {}  {}", scope_name.bold(), bits.join(" "))
    }
}

// ---- traits -----------------------------------------------------------------

fn write_traits(out: &mut String, scope: &ScopeDiff<TraitChange>) {
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

fn write_metrics(out: &mut String, scope: &ScopeDiff<MetricChange>) {
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
        let _ = writeln!(
            out,
            "    {} {:<40} : {} {} {}",
            numeric_direction(&old.value, &new.value),
            new.path,
            format_value(&old.value).dimmed(),
            "→".dimmed(),
            format_value(&new.value),
        );
    }
}

/// `↑` / `↓` for numeric increase / decrease, `~` otherwise. Always
/// yellow — same color as the global "changed" verb so the reader
/// doesn't have to learn three palettes.
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

fn write_kv(out: &mut String, scope: &ScopeDiff<KvChange>) {
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

/// One kv row. Membership-encoded paths (`prefix[]=value`, produced by
/// the flattener for arrays of leaves) display as `prefix[]   value`
/// since the path already contains the value — printing
/// `path = value` would show the same string twice. Regular
/// path/value pairs use the `path = value` form.
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

fn write_symbols(out: &mut String, scope: &ScopeDiff<SymbolChange>) {
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

fn write_strings(out: &mut String, scope: &ScopeDiff<StringChange>) {
    let _ = writeln!(
        out,
        "{}    {}",
        scope_heading("strings", scope),
        format!("(last {STRING_TAIL} in file)").dimmed(),
    );

    let (added, added_hidden) = tail(&scope.added, STRING_TAIL);
    let (removed, removed_hidden) = tail(&scope.removed, STRING_TAIL);
    let (changed, _) = tail(&scope.changed, STRING_TAIL);

    if added_hidden > 0 {
        let _ = writeln!(
            out,
            "    {}",
            format!("· {added_hidden} earlier added strings hidden").dimmed()
        );
    }
    for s in added {
        let _ = writeln!(out, "    {} {}", paint_sign("+"), truncate(&s.value, 200));
    }
    if removed_hidden > 0 {
        let _ = writeln!(
            out,
            "    {}",
            format!("· {removed_hidden} earlier removed strings hidden").dimmed()
        );
    }
    for s in removed {
        let _ = writeln!(out, "    {} {}", paint_sign("-"), truncate(&s.value, 200));
    }
    for c in changed {
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

/// Last `n` items plus the count hidden ahead of them. `(slice, 0)`
/// when the input fits within the window. The strings renderer uses
/// this to surface the most recent matches and a "·N earlier hidden"
/// breadcrumb so a 5000-string diff doesn't wallpaper the pane.
fn tail<T>(items: &[T], n: usize) -> (&[T], usize) {
    if items.len() <= n {
        (items, 0)
    } else {
        let start = items.len() - n;
        (&items[start..], start)
    }
}

// ---- sections (binary) ------------------------------------------------------

fn write_sections(out: &mut String, scope: &ScopeDiff<SectionChange>) {
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
// Tests for pane-level rendering. Header + ledger have their own
// tests in submodule `tests`.
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::{Criticality, MetricChange, ScopeDiff};

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
        let _ = Criticality::Baseline; // silence unused import (tests/imports stay tidy)
        let mut out = String::new();
        write_metrics(&mut out, &scope);
        assert!(out.contains('↑'));
        assert!(out.contains('↓'));
        assert!(!out.contains(" ~ "));
    }
}
