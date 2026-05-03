//! Per-scope diff functions. Each `diff_*` takes the two paired
//! [`DiffUnit`]s and returns a [`ScopeDiff`] over the scope's item type.
//!
//! Identity is keyed differently by scope but the shape is always the same:
//! `added` (new only), `removed` (old only), `changed` (both, distinct).
//! The `truncate` helper caps each list at `limit_changes` and sets the
//! `truncated` flag — counts and ROC denominators are unaffected.
use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::Value;

use crate::types::binary::{Export, Import, Section, StringInfo};
use crate::types::traits_findings::Finding;
use crate::types::{
    Changed, KvChange, MetricChange, ScopeDiff, SectionChange, StringChange, SymbolChange,
    SymbolKind, TraitChange,
};

use super::DiffUnit;

// =============================================================================
// Traits — keyed on Finding.id (the trait ID). Findings present on both sides
// with a different `crit` are treated as changed. This is the most useful
// signal for supply-chain attacks: a benign baseline trait promoted to
// suspicious when the new build introduces a sketchy combination.
// =============================================================================

pub(super) fn diff_traits(old: &DiffUnit, new: &DiffUnit, limit: usize) -> ScopeDiff<TraitChange> {
    let old_idx: FxHashMap<&str, &Finding> =
        old.findings.iter().map(|f| (f.id.as_str(), f)).collect();
    let new_idx: FxHashMap<&str, &Finding> =
        new.findings.iter().map(|f| (f.id.as_str(), f)).collect();

    let mut diff = ScopeDiff::<TraitChange> {
        old_count: old.findings.len() as u32,
        new_count: new.findings.len() as u32,
        ..Default::default()
    };

    for f in &new.findings {
        match old_idx.get(f.id.as_str()) {
            None => diff.added.push(trait_change(f)),
            Some(prev) if prev.crit != f.crit => diff.changed.push(Changed {
                old: trait_change(prev),
                new: trait_change(f),
            }),
            Some(_) => {}
        }
    }
    for f in &old.findings {
        if !new_idx.contains_key(f.id.as_str()) {
            diff.removed.push(trait_change(f));
        }
    }
    truncate(&mut diff, limit);
    diff
}

fn trait_change(f: &Finding) -> TraitChange {
    let trait_section = f.id.split('/').next().unwrap_or_default().to_string();
    TraitChange {
        id: f.id.clone(),
        trait_section,
        crit: f.crit,
        desc: f.desc.clone(),
        count: f.match_count as u32,
    }
}

// =============================================================================
// Metrics — flatten the Metrics struct to (path, value) pairs and diff by
// path. Numeric leaves only; strings/booleans are also captured but most of
// the metric tree is numeric.
// =============================================================================

pub(super) fn diff_metrics(
    old: &DiffUnit,
    new: &DiffUnit,
    limit: usize,
) -> ScopeDiff<MetricChange> {
    let old_flat = flatten_metrics(old.metrics.as_ref());
    let new_flat = flatten_metrics(new.metrics.as_ref());
    diff_flat_paths(
        &old_flat,
        &new_flat,
        |path, value| MetricChange {
            path: path.to_string(),
            value: value.clone(),
        },
        limit,
    )
}

fn flatten_metrics(m: Option<&crate::types::scores::Metrics>) -> Vec<(String, Value)> {
    let Some(m) = m else { return Vec::new() };
    let Ok(value) = serde_json::to_value(m) else {
        return Vec::new();
    };
    flatten_dotted(&value)
}

/// Flatten a JSON value into `parent.child` paths for metrics. Arrays are
/// joined with `[i]` so paths stay matcher-syntax compatible.
fn flatten_dotted(value: &Value) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    walk(value, "", &mut out);
    out
}

fn walk(value: &Value, prefix: &str, out: &mut Vec<(String, Value)>) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (k, v) in map {
                let next = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                walk(v, &next, out);
            }
        }
        Value::Array(arr) if !arr.is_empty() => {
            for (i, v) in arr.iter().enumerate() {
                let next = format!("{prefix}[{i}]");
                walk(v, &next, out);
            }
        }
        Value::Null => {}
        _ if prefix.is_empty() => {}
        _ => out.push((prefix.to_string(), value.clone())),
    }
}

// =============================================================================
// KV — flatten kv_tree to the same path syntax accepted by `type: kv` rules
// and `cleave kv`, then diff by path. Identity is path; values may be of any
// JSON type. Top-level path segment is captured as `namespace` for grouping.
// =============================================================================

pub(super) fn diff_kv(old: &DiffUnit, new: &DiffUnit, limit: usize) -> ScopeDiff<KvChange> {
    let old_flat = old.kv_tree.as_ref().map(flatten_dotted).unwrap_or_default();
    let new_flat = new.kv_tree.as_ref().map(flatten_dotted).unwrap_or_default();
    diff_flat_paths(
        &old_flat,
        &new_flat,
        |path, value| KvChange {
            path: path.to_string(),
            namespace: path
                .split(['.', '['])
                .next()
                .unwrap_or_default()
                .to_string(),
            value: value.clone(),
        },
        limit,
    )
}

/// Shared engine for path-keyed diffs (metrics, KV).
fn diff_flat_paths<T, F>(
    old: &[(String, Value)],
    new: &[(String, Value)],
    mut make: F,
    limit: usize,
) -> ScopeDiff<T>
where
    F: FnMut(&str, &Value) -> T,
{
    let old_idx: FxHashMap<&str, &Value> = old.iter().map(|(k, v)| (k.as_str(), v)).collect();
    let new_idx: FxHashMap<&str, &Value> = new.iter().map(|(k, v)| (k.as_str(), v)).collect();

    let mut diff = ScopeDiff::<T> {
        old_count: old.len() as u32,
        new_count: new.len() as u32,
        ..Default::default()
    };

    for (path, value) in new {
        match old_idx.get(path.as_str()) {
            None => diff.added.push(make(path, value)),
            Some(prev) if json_neq(prev, value) => diff.changed.push(Changed {
                old: make(path, prev),
                new: make(path, value),
            }),
            Some(_) => {}
        }
    }
    for (path, value) in old {
        if !new_idx.contains_key(path.as_str()) {
            diff.removed.push(make(path, value));
        }
    }
    truncate(&mut diff, limit);
    diff
}

/// JSON inequality with epsilon tolerance for floating-point numbers so
/// trivial rounding does not generate spurious change entries.
fn json_neq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(an), Value::Number(bn)) => match (an.as_f64(), bn.as_f64()) {
            (Some(x), Some(y)) => (x - y).abs() > 1e-9,
            _ => an != bn,
        },
        _ => a != b,
    }
}

// =============================================================================
// Symbols — imports and exports together, keyed on (kind, library, symbol).
// Two imports with the same name from different libraries are distinct.
// Symbol entries do not have field-level "changed" semantics in v1.
// =============================================================================

pub(super) fn diff_symbols(
    old: &DiffUnit,
    new: &DiffUnit,
    limit: usize,
) -> ScopeDiff<SymbolChange> {
    let to_changes = |imports: &[Import], exports: &[Export]| -> Vec<SymbolChange> {
        let mut v: Vec<SymbolChange> = imports
            .iter()
            .map(|i| SymbolChange {
                symbol: i.symbol.clone(),
                kind: SymbolKind::Import,
                library: i.library.clone(),
            })
            .collect();
        v.extend(exports.iter().map(|e| SymbolChange {
            symbol: e.symbol.clone(),
            kind: SymbolKind::Export,
            library: None,
        }));
        v
    };

    let old_v = to_changes(&old.imports, &old.exports);
    let new_v = to_changes(&new.imports, &new.exports);

    let key = |c: &SymbolChange| -> String {
        format!(
            "{:?}:{}:{}",
            c.kind,
            c.library.as_deref().unwrap_or(""),
            c.symbol
        )
    };
    set_diff(&old_v, &new_v, key, limit)
}

// =============================================================================
// Strings — keyed on the literal value. Repeated values collapse to one entry.
// =============================================================================

pub(super) fn diff_strings(
    old: &DiffUnit,
    new: &DiffUnit,
    limit: usize,
) -> ScopeDiff<StringChange> {
    let old_v: Vec<StringChange> = unique_strings(&old.strings);
    let new_v: Vec<StringChange> = unique_strings(&new.strings);
    set_diff(&old_v, &new_v, |c| c.value.clone(), limit)
}

fn unique_strings(strings: &[StringInfo]) -> Vec<StringChange> {
    let mut seen: FxHashSet<&str> = FxHashSet::default();
    let mut out = Vec::with_capacity(strings.len());
    for s in strings {
        if seen.insert(s.value.as_str()) {
            out.push(StringChange {
                value: s.value.clone(),
            });
        }
    }
    out
}

// =============================================================================
// Sections — keyed on name; (size, entropy, permissions) tuple distinguishes
// changed sections. Entropy is compared with a small epsilon to suppress
// rounding noise.
// =============================================================================

pub(super) fn diff_sections(
    old: &DiffUnit,
    new: &DiffUnit,
    limit: usize,
) -> ScopeDiff<SectionChange> {
    let old_idx: FxHashMap<&str, &Section> =
        old.sections.iter().map(|s| (s.name.as_str(), s)).collect();
    let new_idx: FxHashMap<&str, &Section> =
        new.sections.iter().map(|s| (s.name.as_str(), s)).collect();

    let mut diff = ScopeDiff::<SectionChange> {
        old_count: old.sections.len() as u32,
        new_count: new.sections.len() as u32,
        ..Default::default()
    };

    for s in &new.sections {
        match old_idx.get(s.name.as_str()) {
            None => diff.added.push(section_change(s)),
            Some(prev) if section_neq(prev, s) => diff.changed.push(Changed {
                old: section_change(prev),
                new: section_change(s),
            }),
            Some(_) => {}
        }
    }
    for s in &old.sections {
        if !new_idx.contains_key(s.name.as_str()) {
            diff.removed.push(section_change(s));
        }
    }
    truncate(&mut diff, limit);
    diff
}

fn section_change(s: &Section) -> SectionChange {
    SectionChange {
        name: s.name.clone(),
        size: s.size,
        entropy: s.entropy,
        permissions: s.permissions.clone(),
    }
}

fn section_neq(a: &Section, b: &Section) -> bool {
    a.size != b.size || (a.entropy - b.entropy).abs() > 0.005 || a.permissions != b.permissions
}

// =============================================================================
// Generic helpers
// =============================================================================

/// Set-difference helper for scopes whose items have no field-level "changed"
/// semantics — every item is either present or absent. Caller supplies a key
/// function used for identity.
fn set_diff<T, K, F>(old: &[T], new: &[T], key: F, limit: usize) -> ScopeDiff<T>
where
    T: Clone,
    K: std::hash::Hash + Eq,
    F: Fn(&T) -> K,
{
    let old_keys: FxHashSet<K> = old.iter().map(&key).collect();
    let new_keys: FxHashSet<K> = new.iter().map(&key).collect();

    let mut diff = ScopeDiff::<T> {
        old_count: old.len() as u32,
        new_count: new.len() as u32,
        ..Default::default()
    };

    for item in new {
        if !old_keys.contains(&key(item)) {
            diff.added.push(item.clone());
        }
    }
    for item in old {
        if !new_keys.contains(&key(item)) {
            diff.removed.push(item.clone());
        }
    }
    truncate(&mut diff, limit);
    diff
}

/// Cap each of `added` / `removed` / `changed` to `limit` and set the
/// `truncated` flag if any list was clipped. `limit == 0` disables the cap.
pub(super) fn truncate<T>(diff: &mut ScopeDiff<T>, limit: usize) {
    if limit == 0 {
        return;
    }
    let trunc = |v: &mut Vec<T>, t: &mut bool| {
        if v.len() > limit {
            v.truncate(limit);
            *t = true;
        }
    };
    trunc(&mut diff.added, &mut diff.truncated);
    trunc(&mut diff.removed, &mut diff.truncated);
    if diff.changed.len() > limit {
        diff.changed.truncate(limit);
        diff.truncated = true;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::binary::{Export, Import, Section, StringInfo};
    use crate::types::traits_findings::{Finding, FindingKind};
    use crate::types::Criticality;

    fn unit() -> DiffUnit {
        DiffUnit::empty("test".to_string())
    }

    fn finding(id: &str, crit: Criticality) -> Finding {
        Finding {
            id: id.to_string(),
            kind: FindingKind::Capability,
            desc: format!("desc {id}"),
            conf: 0.9,
            crit,
            mbc: None,
            attack: None,
            trait_refs: Vec::new(),
            evidence: Vec::new(),
            match_count: 1,
            source_file: None,
        }
    }

    #[test]
    fn traits_added_removed_changed() {
        let mut old = unit();
        let mut new = unit();
        old.findings = vec![
            finding("metadata/identity/binary", Criticality::Baseline),
            finding("credential-access/aws-keys", Criticality::Notable),
        ];
        new.findings = vec![
            finding("metadata/identity/binary", Criticality::Baseline),
            finding("credential-access/aws-keys", Criticality::Suspicious), // crit bumped
            finding("anti-analysis/timing-check", Criticality::Suspicious), // new
        ];
        let d = diff_traits(&old, &new, 0);
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].id, "anti-analysis/timing-check");
        assert_eq!(d.added[0].trait_section, "anti-analysis");
        assert_eq!(d.removed.len(), 0);
        assert_eq!(d.changed.len(), 1);
        assert_eq!(d.changed[0].new.crit, Criticality::Suspicious);
        assert_eq!(d.old_count, 2);
        assert_eq!(d.new_count, 3);
    }

    #[test]
    fn metrics_path_change() {
        use crate::types::scores::Metrics;
        use crate::types::text_metrics::TextMetrics;

        let mut old = unit();
        let mut new = unit();
        let m_old = Metrics {
            text: Some(TextMetrics {
                total_lines: 100,
                ..Default::default()
            }),
            ..Default::default()
        };
        let m_new = Metrics {
            text: Some(TextMetrics {
                total_lines: 150,
                ..Default::default()
            }),
            ..Default::default()
        };
        old.metrics = Some(m_old);
        new.metrics = Some(m_new);

        let d = diff_metrics(&old, &new, 0);
        assert!(d.old_count > 0);
        assert!(d.new_count > 0);
        assert!(d.changed.iter().any(|c| c.new.path == "text.total_lines"));
    }

    #[test]
    fn kv_added_namespace_extracted() {
        let mut old = unit();
        let mut new = unit();
        old.kv_tree = Some(serde_json::json!({"metadata": {"sig": "old"}}));
        new.kv_tree = Some(serde_json::json!({
            "metadata": {"sig": "new"},
            "signature": {"team_id": "ABC123"},
        }));
        let d = diff_kv(&old, &new, 0);
        assert!(d
            .added
            .iter()
            .any(|c| c.path == "signature.team_id" && c.namespace == "signature"));
        assert!(d
            .changed
            .iter()
            .any(|c| c.new.path == "metadata.sig" && c.new.namespace == "metadata"));
    }

    #[test]
    fn symbols_distinguish_kind_and_library() {
        let mut old = unit();
        let mut new = unit();
        old.imports = vec![Import::new("malloc", Some("libc.so.6".into()), "goblin")];
        new.imports = vec![
            Import::new("malloc", Some("libc.so.6".into()), "goblin"),
            Import::new("malloc", Some("musl.so".into()), "goblin"),
        ];
        new.exports = vec![Export::new("init", None, "goblin")];

        let d = diff_symbols(&old, &new, 0);
        assert_eq!(d.added.len(), 2); // malloc@musl + init export
        assert_eq!(d.removed.len(), 0);
    }

    #[test]
    fn strings_dedup_within_side() {
        let mut old = unit();
        let mut new = unit();
        old.strings = vec![s("hello"), s("hello"), s("world")];
        new.strings = vec![s("hello"), s("evil")];
        let d = diff_strings(&old, &new, 0);
        assert_eq!(d.old_count, 2);
        assert_eq!(d.new_count, 2);
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].value, "evil");
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].value, "world");
    }

    fn s(v: &str) -> StringInfo {
        StringInfo {
            value: v.to_string(),
            offset: None,
            encoding: "utf8".to_string(),
            string_type: None,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        }
    }

    #[test]
    fn sections_entropy_change_detected() {
        let mut old = unit();
        let mut new = unit();
        old.sections = vec![sec(".text", 1024, 5.0, Some("r-x"))];
        new.sections = vec![sec(".text", 1024, 7.5, Some("r-x"))];
        let d = diff_sections(&old, &new, 0);
        assert_eq!(d.changed.len(), 1);
        assert!((d.changed[0].new.entropy - 7.5).abs() < 1e-9);
    }

    fn sec(name: &str, size: u64, entropy: f64, perms: Option<&str>) -> Section {
        Section {
            name: name.to_string(),
            address: None,
            offset: None,
            size,
            entropy,
            permissions: perms.map(str::to_string),
        }
    }

    #[test]
    fn truncate_caps_and_marks() {
        let mut diff: ScopeDiff<StringChange> = ScopeDiff {
            added: (0..200)
                .map(|i| StringChange {
                    value: i.to_string(),
                })
                .collect(),
            old_count: 0,
            new_count: 200,
            ..Default::default()
        };
        truncate(&mut diff, 100);
        assert_eq!(diff.added.len(), 100);
        assert!(diff.truncated);
        assert_eq!(diff.new_count, 200); // count untouched
    }

    #[test]
    fn truncate_zero_disables_cap() {
        let mut diff: ScopeDiff<StringChange> = ScopeDiff {
            added: (0..50)
                .map(|i| StringChange {
                    value: i.to_string(),
                })
                .collect(),
            ..Default::default()
        };
        truncate(&mut diff, 0);
        assert_eq!(diff.added.len(), 50);
        assert!(!diff.truncated);
    }

    #[test]
    fn diff_unchanged_yields_zero_changes() {
        let mut old = unit();
        let mut new = unit();
        old.findings = vec![finding("a/b/c", Criticality::Notable)];
        new.findings = vec![finding("a/b/c", Criticality::Notable)];
        let d = diff_traits(&old, &new, 0);
        assert!(!d.has_changes());
        assert!(!d.is_empty());
    }
}
