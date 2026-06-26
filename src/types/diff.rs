//! Differential analysis types (diff schema v1).
//!
//! A `DiffReportV1` is embedded in [`AnalysisReport::diff`] when produced by
//! [`crate::diff::diff_paths`]. The schema is intentionally narrow: a uniform
//! [`ScopeDiff`] holds added/removed/changed lists for each of six scopes
//! (traits, metrics, kv, symbols, strings, sections). Rate of change is derived
//! from the four counts; consumers that do not pre-compute it can divide
//! `change_count() / max(old_count, new_count)` themselves.
//!
//! The report carries program-level scope rollups in [`DiffReportV1::scopes`]
//! plus per-file detail in [`DiffReportV1::files`]. Pooled counts mean overall
//! ROCs are honest across mixed-size files.
//!
//! Litmus consumes the structured added/removed/changed lists; prism reads
//! `summary` for headlines and `files` for the per-file UI.
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::core::Criticality;

/// One of the six diff scopes. Iterating [`Scope::ALL`] is the canonical
/// way to fan out across all scopes — every "for each scope do X" site
/// in the diff/format code is one of these iterations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// Per-finding (trait) diff.
    Traits,
    /// Flattened-metric-path diff.
    Metrics,
    /// Flattened kv-tree-path diff.
    Kv,
    /// Imported / exported symbol diff.
    Symbols,
    /// Extracted-string-literal diff.
    Strings,
    /// Binary-section diff (ELF / Mach-O / PE).
    Sections,
}

impl Scope {
    /// All six scopes in canonical (display) order.
    pub const ALL: [Scope; 6] = [
        Scope::Traits,
        Scope::Metrics,
        Scope::Kv,
        Scope::Symbols,
        Scope::Strings,
        Scope::Sections,
    ];

    /// Lower-case scope name used in CLI flags (`--scope traits`),
    /// section headings, and trait references.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Scope::Traits => "traits",
            Scope::Metrics => "metrics",
            Scope::Kv => "value",
            Scope::Symbols => "symbols",
            Scope::Strings => "strings",
            Scope::Sections => "sections",
        }
    }

    /// All-caps label for the ledger column header.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Scope::Traits => "TRAITS",
            Scope::Metrics => "METRICS",
            Scope::Kv => "KV",
            Scope::Symbols => "SYMBOLS",
            Scope::Strings => "STRINGS",
            Scope::Sections => "SECTIONS",
        }
    }
}

impl std::str::FromStr for Scope {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Scope::ALL
            .iter()
            .copied()
            .find(|sc| sc.as_str() == s)
            .ok_or(())
    }
}

/// Top-level diff report (schema v1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReportV1 {
    /// Source root for the "old" / baseline side.
    pub old_root: String,
    /// Source root for the "new" / target side.
    pub new_root: String,
    /// Pre-computed summary (counts and rates of change).
    pub summary: DiffSummary,
    /// Program-level rollup of per-scope diffs.
    pub scopes: ScopeDiffs,
    /// Per-file diffs. Files with `status == Unchanged` are omitted unless
    /// `include_unchanged` was requested.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub files: Vec<FileDiffEntry>,
}

/// Headline metrics: file-level changes plus per-scope and overall ROCs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DiffSummary {
    /// Mean of the per-scope rates of change (scopes with no data on either
    /// side excluded). v1 is unweighted; criticality weighting is a future
    /// enhancement.
    pub overall_roc: f32,
    /// Per-scope rate of change at the program level (pooled across files).
    pub scope_roc: ScopeRocs,
    /// Files present only in the new side.
    #[serde(default, skip_serializing_if = "super::is_zero_u32")]
    pub files_added: u32,
    /// Files present only in the old side.
    #[serde(default, skip_serializing_if = "super::is_zero_u32")]
    pub files_removed: u32,
    /// Files that exist on both sides and have at least one scope change.
    #[serde(default, skip_serializing_if = "super::is_zero_u32")]
    pub files_changed: u32,
    /// Files that exist on both sides with identical analysis output across
    /// all selected scopes.
    #[serde(default, skip_serializing_if = "super::is_zero_u32")]
    pub files_unchanged: u32,
}

/// Pre-computed rate of change per scope (program-level pooled).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScopeRocs {
    /// ROC for the traits scope.
    #[serde(default, skip_serializing_if = "super::is_zero_f32")]
    pub traits: f32,
    /// ROC for the metrics scope.
    #[serde(default, skip_serializing_if = "super::is_zero_f32")]
    pub metrics: f32,
    /// ROC for the KV scope.
    #[serde(default, skip_serializing_if = "super::is_zero_f32")]
    pub kv: f32,
    /// ROC for the symbols scope.
    #[serde(default, skip_serializing_if = "super::is_zero_f32")]
    pub symbols: f32,
    /// ROC for the strings scope.
    #[serde(default, skip_serializing_if = "super::is_zero_f32")]
    pub strings: f32,
    /// ROC for the sections scope.
    #[serde(default, skip_serializing_if = "super::is_zero_f32")]
    pub sections: f32,
}

impl ScopeRocs {
    /// Look up the ROC for one scope. Pairs with [`Scope::ALL`] for
    /// "for each scope, do X" loops.
    #[must_use]
    pub fn get(&self, scope: Scope) -> f32 {
        match scope {
            Scope::Traits => self.traits,
            Scope::Metrics => self.metrics,
            Scope::Kv => self.kv,
            Scope::Symbols => self.symbols,
            Scope::Strings => self.strings,
            Scope::Sections => self.sections,
        }
    }

    /// Set the ROC for one scope.
    pub fn set(&mut self, scope: Scope, value: f32) {
        match scope {
            Scope::Traits => self.traits = value,
            Scope::Metrics => self.metrics = value,
            Scope::Kv => self.kv = value,
            Scope::Symbols => self.symbols = value,
            Scope::Strings => self.strings = value,
            Scope::Sections => self.sections = value,
        }
    }
}

/// Per-scope rollup. A scope is `None` when it was excluded from the run by
/// `--scope` or when neither side had any data for it.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScopeDiffs {
    /// Diff over per-file findings, identified by Finding.id (the trait ID).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub traits: Option<ScopeDiff<TraitChange>>,
    /// Diff over flattened metric paths.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metrics: Option<ScopeDiff<MetricChange>>,
    /// Diff over flattened KV-tree paths.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kv: Option<ScopeDiff<KvChange>>,
    /// Diff over imported and exported symbols.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub symbols: Option<ScopeDiff<SymbolChange>>,
    /// Diff over extracted string literals.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub strings: Option<ScopeDiff<StringChange>>,
    /// Diff over binary sections (ELF/Mach-O/PE).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sections: Option<ScopeDiff<SectionChange>>,
}

impl ScopeDiffs {
    /// Erased per-scope view: `Some` when this scope ran, regardless of
    /// the underlying change type. Use for queries that don't care about
    /// the change-row shape (e.g. "did anything change?").
    #[must_use]
    pub fn view(&self, scope: Scope) -> ScopeView<'_> {
        match scope {
            Scope::Traits => self.traits.as_ref().into(),
            Scope::Metrics => self.metrics.as_ref().into(),
            Scope::Kv => self.kv.as_ref().into(),
            Scope::Symbols => self.symbols.as_ref().into(),
            Scope::Strings => self.strings.as_ref().into(),
            Scope::Sections => self.sections.as_ref().into(),
        }
    }
}

/// Type-erased peek at one scope's [`ScopeDiff`]. Carries just the
/// shape questions callers need (`present`, `has_changes`, counts,
/// `roc`) — typed iteration over `added`/`removed`/`changed` still
/// goes through the concrete `ScopeDiffs` field.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScopeView<'a> {
    /// `true` when the scope ran (`Some(_)`), regardless of whether it
    /// found any items.
    pub present: bool,
    /// `true` when at least one item is in `added`/`removed`/`changed`.
    pub has_changes: bool,
    /// `true` when neither side had any data for this scope. Distinct
    /// from `!has_changes`: a scope can be non-empty (counts on both
    /// sides) yet have no diff.
    pub is_empty: bool,
    /// Number of items in `ScopeDiff::added`.
    pub added_len: usize,
    /// Number of items in `ScopeDiff::removed`.
    pub removed_len: usize,
    /// Number of items in `ScopeDiff::changed`.
    pub changed_len: usize,
    /// Pre-computed rate of change for this scope.
    pub roc: f32,
    _life: std::marker::PhantomData<&'a ()>,
}

impl<'a, T> From<Option<&'a ScopeDiff<T>>> for ScopeView<'a> {
    fn from(opt: Option<&'a ScopeDiff<T>>) -> Self {
        opt.map(|s| ScopeView {
            present: true,
            has_changes: s.has_changes(),
            is_empty: s.is_empty(),
            added_len: s.added.len(),
            removed_len: s.removed.len(),
            changed_len: s.changed.len(),
            roc: s.roc,
            _life: std::marker::PhantomData,
        })
        .unwrap_or_default()
    }
}

/// Identity headline for a diffed file: who/what each side claims to be.
///
/// Unlike the six scopes (which only carry *changes*), identity is shown
/// for every file — a stable headline, like the analyze view — so a
/// reader always sees the claimed identity and instantly spots drift
/// (Apple-signed → unsigned, a new publisher, a different build user).
/// It is rendered first, ahead of the trait diff, because a changed
/// identity is the highest-signal change a file can have.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityDiff {
    /// Identity on the old/baseline side. Absent for added files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<filefacts::Identity>,
    /// Identity on the new side. Absent for removed files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<filefacts::Identity>,
    /// True when the two sides differ — the high-signal case.
    pub changed: bool,
}

/// A single file's contribution to the diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDiffEntry {
    /// Path relative to the input root (or the archive prefix for nested members).
    pub path: String,
    /// Whether the file was added, removed, changed, or unchanged.
    pub status: FileStatus,
    /// Identity headline (claimed/verified identity of each side).
    /// Present whenever either side carried an identity; rendered first,
    /// ahead of the scope diffs. `None` when neither side had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<IdentityDiff>,
    /// Per-scope diffs for this file. Scopes with no changes are `None`.
    pub scopes: ScopeDiffs,
    /// Behavioral fingerprint of the old side (notable-or-higher findings).
    /// `None` when the file is purely added or its old findings produced no formula.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_formula: Option<String>,
    /// Behavioral fingerprint of the new side. `None` when the file is purely
    /// removed or its new findings produced no formula.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_formula: Option<String>,
}

/// Status of a file in the diff.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FileStatus {
    /// File present only in the new side.
    Added,
    /// File present only in the old side.
    Removed,
    /// File present on both sides with at least one scope change.
    Changed,
    /// File present on both sides with no scope changes.
    Unchanged,
}

/// Generic per-scope diff. Every scope produces this shape over its own item
/// type `T`. The `roc` is computed scope-specifically: traits weight by
/// `criticality.score_weight() * conf`, metrics and kv weight by relative
/// magnitude of value change, and symbols/strings/sections use raw counts.
/// See `crate::diff::scopes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeDiff<T> {
    /// Items present only in the new side.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub added: Vec<T>,
    /// Items present only in the old side.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub removed: Vec<T>,
    /// Items present on both sides with at least one differing field.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub changed: Vec<Changed<T>>,
    /// Raw item count on the old side (total, before truncation).
    #[serde(default, skip_serializing_if = "super::is_zero_u32")]
    pub old_count: u32,
    /// Raw item count on the new side (total, before truncation).
    #[serde(default, skip_serializing_if = "super::is_zero_u32")]
    pub new_count: u32,
    /// Scope-specific weight on the old side. Equal to `old_count` for
    /// scopes whose change is binary (symbols/strings/sections); equal to
    /// the score-weighted total for traits; equal to `old_count` for
    /// metrics/kv (where weight is per-change magnitude, not per-item).
    #[serde(default, skip_serializing_if = "super::is_zero_f32")]
    pub old_weight: f32,
    /// Scope-specific weight on the new side; see `old_weight`.
    #[serde(default, skip_serializing_if = "super::is_zero_f32")]
    pub new_weight: f32,
    /// Scope-specific weight summed across all changes. For traits,
    /// `crit.score_weight() * conf` per added/removed plus the absolute
    /// score delta for `changed`. For metrics/kv, `|Δ|/max(|old|,|new|)`
    /// per numeric change, `1.0` for boolean/string flips and add/removes.
    /// For symbols/strings/sections, `added + removed + changed`.
    #[serde(default, skip_serializing_if = "super::is_zero_f32")]
    pub change_weight: f32,
    /// Rate of change in `[0.0, 1.0]`. `change_weight / max(old_weight, new_weight)`,
    /// clamped. `0.0` when both weights are zero.
    #[serde(default, skip_serializing_if = "super::is_zero_f32")]
    pub roc: f32,
    /// True when one or more of `added`/`removed`/`changed` was capped by
    /// `--limit-changes`. Counts and weights remain accurate.
    #[serde(default, skip_serializing_if = "super::is_false")]
    pub truncated: bool,
}

impl<T> Default for ScopeDiff<T> {
    fn default() -> Self {
        Self {
            added: Vec::new(),
            removed: Vec::new(),
            changed: Vec::new(),
            old_count: 0,
            new_count: 0,
            old_weight: 0.0,
            new_weight: 0.0,
            change_weight: 0.0,
            roc: 0.0,
            truncated: false,
        }
    }
}

impl<T> ScopeDiff<T> {
    /// Number of items in `added + removed + changed`. Independent of weight.
    /// Reflects post-truncation list lengths; consult `old_count`, `new_count`,
    /// and the `truncated` flag for pre-truncation totals.
    #[must_use]
    pub fn change_count(&self) -> u32 {
        (self.added.len() + self.removed.len() + self.changed.len()) as u32
    }

    /// True when the scope has no observed activity on either side.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.old_count == 0 && self.new_count == 0
    }

    /// True when a meaningful change was recorded (added, removed, or changed).
    #[must_use]
    pub fn has_changes(&self) -> bool {
        self.change_count() > 0
    }

    /// Recompute `roc` from the three weight fields, clamped to `[0.0, 1.0]`.
    /// Called by the engine after pooling per-file diffs.
    pub fn recompute_roc(&mut self) {
        let denom = self.old_weight.max(self.new_weight);
        self.roc = if denom <= 0.0 {
            0.0
        } else {
            (self.change_weight / denom).clamp(0.0, 1.0)
        };
    }
}

/// One side of a `changed` pair. Both sides carry the same identity, only
/// fields that distinguish them differ.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Changed<T> {
    /// Old-side value.
    pub old: T,
    /// New-side value.
    pub new: T,
}

/// A trait-level change. Identity is `id` (Finding ID, e.g.
/// `credential-access/aws-keys`); `trait_section` is the top-level taxonomy
/// directory used to group entries in the CLI render.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TraitChange {
    /// Finding ID — the canonical trait identifier.
    pub id: String,
    /// Top-level taxonomy directory (`well-known`, `objectives`, `metadata`,
    /// `micro-behaviors`, etc.). Derived from `id.split('/').next()`.
    pub trait_section: String,
    /// Criticality at the side this change came from.
    pub crit: Criticality,
    /// Short human-readable description (for display).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub desc: String,
    /// Match count on this side.
    #[serde(default, skip_serializing_if = "super::is_zero_u32")]
    pub count: u32,
}

/// A change to a flattened metric path (e.g. `binary.entropy`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricChange {
    /// Dotted metric path (`parent.child.leaf`).
    pub path: String,
    /// Leaf value at this side.
    pub value: Value,
}

/// A change to a flattened KV-tree path. KV paths use `parent.child` for
/// objects and `parent[i]` for arrays — the same syntax accepted by
/// `type: value` matchers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KvChange {
    /// KV-path-syntax path.
    pub path: String,
    /// Top-level namespace of the path (`metadata`, `code`, `overlay`,
    /// `signature`, …) — empty for flat trees.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub namespace: String,
    /// Leaf value at this side.
    pub value: Value,
}

/// A change to a symbol (import or export).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SymbolChange {
    /// Normalized symbol name.
    pub symbol: String,
    /// Whether this symbol is imported or exported.
    pub kind: SymbolKind,
    /// Library name for imports (e.g. `libc.so.6`); always `None` for exports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
}

/// Symbol direction.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum SymbolKind {
    /// Symbol imported from an external module.
    #[default]
    Import,
    /// Symbol exported by this file.
    Export,
}

/// A change to a string literal.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StringChange {
    /// String value.
    pub value: String,
}

/// A change to a binary section. Identity is `name`; `changed` entries carry
/// both old and new versions so callers can render `entropy: 4.1 → 7.8`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SectionChange {
    /// Section name (`.text`, `__TEXT`, `.rdata`, …).
    pub name: String,
    /// Section size in bytes.
    pub size: u64,
    /// Shannon entropy of section bytes.
    pub entropy: f64,
    /// Permission flags when known (`r-x`, `rw-`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn scope_diff_default_is_zero() {
        let d: ScopeDiff<StringChange> = ScopeDiff::default();
        assert_eq!(d.roc, 0.0);
        assert!(d.is_empty());
    }

    #[test]
    fn recompute_roc_clamps_and_handles_empty() {
        let mut d: ScopeDiff<StringChange> = ScopeDiff {
            old_weight: 0.0,
            new_weight: 0.0,
            change_weight: 5.0,
            ..Default::default()
        };
        d.recompute_roc();
        // Both weights zero ⇒ ROC stays 0 even when change_weight is positive.
        assert_eq!(d.roc, 0.0);

        d.old_weight = 100.0;
        d.new_weight = 110.0;
        d.change_weight = 5.0;
        d.recompute_roc();
        assert!((d.roc - 5.0 / 110.0).abs() < f32::EPSILON);

        // Clamp: if change_weight exceeds the larger side (transient pool
        // arithmetic) the ROC pins at 1.0 rather than going negative or wild.
        d.change_weight = 500.0;
        d.recompute_roc();
        assert_eq!(d.roc, 1.0);
    }

    #[test]
    fn schema_roundtrips() {
        let report = DiffReportV1 {
            old_root: "/old".to_string(),
            new_root: "/new".to_string(),
            summary: DiffSummary {
                overall_roc: 0.25,
                scope_roc: ScopeRocs {
                    strings: 0.5,
                    ..Default::default()
                },
                files_changed: 1,
                ..Default::default()
            },
            scopes: ScopeDiffs::default(),
            files: vec![FileDiffEntry {
                path: "lib/foo.so".to_string(),
                status: FileStatus::Changed,
                identity: None,
                scopes: ScopeDiffs {
                    strings: Some(ScopeDiff {
                        added: vec![StringChange {
                            value: "/etc/passwd".to_string(),
                        }],
                        old_count: 10,
                        new_count: 11,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                old_formula: None,
                new_formula: None,
            }],
        };
        let s = serde_json::to_string(&report).unwrap();
        let back: DiffReportV1 = serde_json::from_str(&s).unwrap();
        assert_eq!(back.files.len(), 1);
        assert_eq!(back.files[0].status, FileStatus::Changed);
        let strings = back.files[0].scopes.strings.as_ref().unwrap();
        assert_eq!(strings.added.len(), 1);
        assert_eq!(strings.added[0].value, "/etc/passwd");
    }
}
