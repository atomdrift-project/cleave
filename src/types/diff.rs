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

/// A single file's contribution to the diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDiffEntry {
    /// Path relative to the input root (or the archive prefix for nested members).
    pub path: String,
    /// Whether the file was added, removed, changed, or unchanged.
    pub status: FileStatus,
    /// Per-scope diffs for this file. Scopes with no changes are `None`.
    pub scopes: ScopeDiffs,
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
/// type `T`. ROC is derived from the four counts at format time.
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
    /// Item count on the old side (total, before truncation).
    #[serde(default, skip_serializing_if = "super::is_zero_u32")]
    pub old_count: u32,
    /// Item count on the new side (total, before truncation).
    #[serde(default, skip_serializing_if = "super::is_zero_u32")]
    pub new_count: u32,
    /// True when one or more of `added`/`removed`/`changed` was capped by
    /// `--limit-changes`. The counts above remain accurate.
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
            truncated: false,
        }
    }
}

impl<T> ScopeDiff<T> {
    /// Total number of changes (`added + removed + changed`), un-capped.
    /// Counts are taken from the in-memory vectors after any truncation, so
    /// callers that need pre-truncation totals should consult `old_count`,
    /// `new_count`, and the `truncated` flag.
    #[must_use]
    pub fn change_count(&self) -> u32 {
        (self.added.len() + self.removed.len() + self.changed.len()) as u32
    }

    /// Rate of change in `[0.0, 1.0]`. Returns `0.0` when both sides are empty.
    #[must_use]
    pub fn roc(&self) -> f32 {
        let denom = self.old_count.max(self.new_count) as f32;
        if denom == 0.0 {
            0.0
        } else {
            self.change_count() as f32 / denom
        }
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
/// `type: kv` matchers.
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
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
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
    fn scope_diff_roc_empty() {
        let d: ScopeDiff<StringChange> = ScopeDiff::default();
        assert_eq!(d.roc(), 0.0);
        assert!(d.is_empty());
    }

    #[test]
    fn scope_diff_roc_full_replacement() {
        let mut d: ScopeDiff<StringChange> = ScopeDiff::default();
        d.added.push(StringChange {
            value: "a".to_string(),
        });
        d.removed.push(StringChange {
            value: "b".to_string(),
        });
        d.old_count = 1;
        d.new_count = 1;
        // Two changes against max(1, 1) = 1 → roc = 2.0 / 1.0 = 2.0.
        // ROC > 1.0 happens when an item is both added and removed against the
        // same single-element side; this is honest and we don't clamp it.
        assert_eq!(d.roc(), 2.0);
    }

    #[test]
    fn scope_diff_roc_partial() {
        let mut d: ScopeDiff<StringChange> = ScopeDiff::default();
        d.added.extend((0..10).map(|i| StringChange {
            value: format!("a{i}"),
        }));
        d.old_count = 100;
        d.new_count = 110;
        assert!((d.roc() - 10.0 / 110.0).abs() < f32::EPSILON);
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
