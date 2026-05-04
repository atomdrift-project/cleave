//! Terminal renderer for diff reports — "ledger" layout.
//!
//! Three sections, each in its own submodule:
//!
//!   1. [`header`] — single-line header. Common path prefix between old
//!      and new is dropped so `cleave diff /a/b/v1 /a/b/v2` reads
//!      `v1 → v2`. Overall ROC and a "N of M files changed" phrase ride
//!      on the same line.
//!   2. [`ledger`] — one row per significant file ranked by
//!      `(max trait criticality, ROC)` descending. Per-scope ROCs sit
//!      in column headers; columns whose every cell is empty are
//!      omitted.
//!   3. [`panes`] — per-file detail panes, one per significant file.
//!      Each pane lists only the scopes that actually changed.
//!
//! Conventions:
//!   * `+` (green) = added, `-` (red) = removed, `~` (yellow) = changed.
//!   * Metric numeric changes use `↑` / `↓` for direction.
//!   * Trait dots: `●●●` hostile, `●●` suspicious, `●` notable, `·` baseline.
//!   * Per-file ROC tints by intensity: red ≥50%, yellow ≥20%, blue ≥5%.

use colored::Colorize;
use serde_json::Value;

use crate::types::{AnalysisReport, Criticality, Scope, ScopeView};

mod header;
mod ledger;
mod panes;

#[cfg(test)]
mod tests;

/// Render an `AnalysisReport` carrying a [`crate::types::DiffReportV1`]
/// as a colored terminal-friendly string.
#[must_use]
pub fn format_terminal(report: &AnalysisReport) -> String {
    let Some(diff) = report.diff.as_ref() else {
        return "no diff present in report\n".to_string();
    };
    let mut out = String::new();
    header::write(&mut out, diff);
    panes::write(&mut out, diff);
    ledger::write_jitter(&mut out, diff);
    out
}

// =============================================================================
// Shared helpers — everything below is used by 2+ submodules.
// =============================================================================

/// Fixed terminal width target for hairline rules.
pub(super) const WIDTH: usize = 80;

/// Color a ROC percentage by intensity. Returns the printable form
/// (with ANSI escapes) so callers can drop it straight into a writeln.
/// Routed through `crate::theme::paint_intensity` so the analyze and
/// diff surfaces share a single severity palette.
pub(super) fn paint_roc(roc: f32) -> String {
    let pct = format!("{:.1}%", roc * 100.0);
    crate::theme::paint_intensity(roc, &pct).to_string()
}

/// Colored `+N -N ~N` badges for a scope. Each bucket is omitted when
/// empty, so a "+1" cell renders without trailing zeros. Shared
/// between the ledger row and the per-file pane heading.
pub(super) fn count_badges(view: ScopeView<'_>) -> Vec<String> {
    let mut parts = Vec::with_capacity(3);
    if view.added_len > 0 {
        parts.push(crate::theme::paint_baseline(format!("+{}", view.added_len)).to_string());
    }
    if view.removed_len > 0 {
        parts.push(crate::theme::paint_hostile(format!("-{}", view.removed_len)).to_string());
    }
    if view.changed_len > 0 {
        parts.push(crate::theme::paint_suspicious(format!("~{}", view.changed_len)).to_string());
    }
    parts
}

/// True for criticalities that aren't baseline / component / filtered.
pub(super) fn matters(c: Criticality) -> bool {
    matches!(
        c,
        Criticality::Notable | Criticality::Suspicious | Criticality::Hostile
    )
}

/// Total ordering on criticalities — high → 5, low → 0.
pub(super) fn crit_rank(c: Criticality) -> i32 {
    match c {
        Criticality::Hostile => 5,
        Criticality::Suspicious => 4,
        Criticality::Notable => 3,
        Criticality::Baseline => 2,
        Criticality::Component => 1,
        Criticality::Filtered => 0,
    }
}

/// One-glance criticality dot column: ●●● hostile, ●● suspicious,
/// ● notable, · baseline / component.  Severity colors come from
/// `crate::theme` so the diff and analyze surfaces share a palette.
pub(super) fn crit_dots(c: Criticality) -> colored::ColoredString {
    match c {
        Criticality::Hostile => crate::theme::paint_hostile("●●●"),
        Criticality::Suspicious => crate::theme::paint_suspicious("●● "),
        Criticality::Notable => crate::theme::paint_notable("●  "),
        Criticality::Baseline => crate::theme::paint_baseline("·  "),
        Criticality::Component | Criticality::Filtered => "·  ".dimmed(),
    }
}

/// Tint a string by criticality (used for trait IDs in the panes).
pub(super) fn paint_crit<S: AsRef<str>>(text: S, c: Criticality) -> colored::ColoredString {
    let s = text.as_ref();
    match c {
        Criticality::Hostile => crate::theme::paint_hostile(s),
        Criticality::Suspicious => crate::theme::paint_suspicious(s),
        Criticality::Notable => crate::theme::paint_notable(s),
        Criticality::Baseline => crate::theme::paint_baseline(s),
        Criticality::Component | Criticality::Filtered => s.dimmed(),
    }
}

/// Colored `+ / - / ~` change-indicator glyph.
pub(super) fn paint_sign(sign: &str) -> colored::ColoredString {
    crate::theme::paint_sign(sign)
}

/// Drop the verbose taxonomy prefix from trait IDs for display.
pub(super) fn short_id(id: &str) -> String {
    id.strip_prefix("well-known/malware/supply-chain/")
        .or_else(|| id.strip_prefix("well-known/"))
        .or_else(|| id.strip_prefix("objectives/"))
        .or_else(|| id.strip_prefix("micro-behaviors/"))
        .or_else(|| id.strip_prefix("metadata/"))
        .unwrap_or(id)
        .to_string()
}

/// Render a JSON leaf for human consumption: strings get quotes,
/// numbers / bools / null use their canonical form, structures fall
/// back to JSON. Long values truncate at 80 chars.
pub(super) fn format_value(v: &Value) -> String {
    match v {
        Value::String(s) => format!("\"{}\"", truncate(s, 80)),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        _ => truncate(&v.to_string(), 80),
    }
}

/// Char-aware truncation with a trailing ellipsis. Strings shorter
/// than `max` round-trip unchanged.
pub(super) fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let kept: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

/// Worst ROC across this file's scopes. Used both for per-file `[NN%]`
/// headers and for tie-breaking the ledger sort.
pub(super) fn file_max_roc(scopes: &crate::types::ScopeDiffs) -> f32 {
    Scope::ALL
        .iter()
        .map(|&s| scopes.view(s))
        .filter(|v| v.present)
        .map(|v| v.roc)
        .fold(0.0_f32, f32::max)
}

/// Highest criticality among newly-added or promoted traits in this
/// file. `Baseline` when none.
pub(super) fn max_added_crit(file: &crate::types::FileDiffEntry) -> Criticality {
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

/// A file is "significant" — listed in the ledger and given a pane —
/// when any scope ROC clears the noise floor *or* any trait change is
/// above baseline. Keeps metric-rounding jitter out of the renderer
/// without hiding real findings.
pub(super) fn is_significant_file(file: &crate::types::FileDiffEntry) -> bool {
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
