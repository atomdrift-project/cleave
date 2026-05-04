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
        old_weight: old.findings.iter().map(finding_score).sum(),
        new_weight: new.findings.iter().map(finding_score).sum(),
        ..Default::default()
    };

    let mut change_weight = 0.0_f32;

    for f in &new.findings {
        match old_idx.get(f.id.as_str()) {
            None => {
                change_weight += finding_score(f);
                diff.added.push(trait_change(f));
            }
            Some(prev) if prev.crit != f.crit => {
                // Promotion or demotion: weight by the absolute score delta so
                // that baseline → suspicious counts more than baseline → notable.
                change_weight += (finding_score(f) - finding_score(prev)).abs();
                diff.changed.push(Changed {
                    old: trait_change(prev),
                    new: trait_change(f),
                });
            }
            Some(_) => {}
        }
    }
    for f in &old.findings {
        if !new_idx.contains_key(f.id.as_str()) {
            change_weight += finding_score(f);
            diff.removed.push(trait_change(f));
        }
    }

    diff.change_weight = change_weight;
    diff.recompute_roc();
    truncate(&mut diff, limit);
    diff
}

/// Per-finding score weight, mirroring `Criticality::score_weight()` from
/// the analysis pipeline (hostile=120, suspicious=40, notable=1, others=0)
/// scaled by confidence. Component traits contribute 0.3·conf only when
/// referenced, but at diff time we don't have the full reference graph;
/// 0 is the safe under-counting choice.
fn finding_score(f: &Finding) -> f32 {
    f.crit.score_weight() as f32 * f.conf
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
    // The analyze pipeline populates `metrics.file.size` for every file
    // regardless of analyzer, so size shows up here naturally without any
    // diff-time synthesis.
    let old_flat = flatten_metrics(old.metrics.as_ref());
    let new_flat = flatten_metrics(new.metrics.as_ref());
    let mut diff = diff_flat_paths(
        &old_flat,
        &new_flat,
        |path, value| MetricChange {
            path: path.to_string(),
            value: value.clone(),
        },
        limit,
    );

    // Drop numeric deltas under 9% — matches the section-pane noise
    // floor. A 27% binary-size growth manifests as proportional moves
    // in 30+ derivative metrics (func_count, dynsym_count,
    // import_count, code_size, …); only the top-level deltas and the
    // anomalies (densities that move *opposite* to file size) carry
    // real signal. Bool flips and string changes are kept verbatim.
    let mut dropped = 0.0_f32;
    diff.changed.retain(|c| {
        if is_trivial_metric_change(&c.old.value, &c.new.value) {
            dropped += value_change_weight(&c.old.value, &c.new.value);
            false
        } else {
            true
        }
    });
    if dropped > 0.0 {
        diff.change_weight = (diff.change_weight - dropped).max(0.0);
        diff.recompute_roc();
    }
    diff
}

/// `true` if both sides are numeric and the change is noise: relative
/// change below the 9% floor (same threshold as the section pane), or
/// both sides round identically to 2dp (catches sub-1e-2 ratios like
/// `0.00004 → 0.00003` that change measurably but render as the same
/// "0.00 → 0.00" digits).
fn is_trivial_metric_change(old: &Value, new: &Value) -> bool {
    let (Value::Number(an), Value::Number(bn)) = (old, new) else {
        return false;
    };
    let (Some(a), Some(b)) = (an.as_f64(), bn.as_f64()) else {
        return false;
    };
    if !a.is_finite() || !b.is_finite() {
        return false;
    }
    let denom = a.abs().max(b.abs());
    if denom == 0.0 {
        return true;
    }
    let rel = (a - b).abs() / denom;
    rel < 0.09 || format!("{a:.2}") == format!("{b:.2}")
}

fn flatten_metrics(m: Option<&crate::types::scores::Metrics>) -> Vec<(String, Value)> {
    let Some(m) = m else { return Vec::new() };
    let Ok(value) = serde_json::to_value(m) else {
        return Vec::new();
    };
    flatten_dotted(&value)
}

/// Flatten a JSON value into `parent.child` paths for metrics. For arrays,
/// the representation depends on the contents:
///
/// * **All leaves** (numbers / strings / bools): emitted as `parent[]=<value>`
///   entries — value-keyed so identity is *membership*. Inserting an item at
///   the start of `imports` no longer fabricates a "change" at every shifted
///   index; only the genuine add/remove shows up.
/// * **Heterogeneous or nested**: fall back to indexed paths `parent[i]`.
///   Object arrays don't have a natural member key in v1; their indices
///   remain stable across most analyzer outputs (e.g. `needed_versions[i]`).
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
            // Rank-keyed arrays (`binary.top_*`) carry their signal in
            // the head; ranks beyond the cap are tail noise that
            // bloats kv diffs without adding diff value.
            let cap = rank_keyed_cap(prefix).unwrap_or(arr.len());
            let arr = &arr[..arr.len().min(cap)];

            if arr.iter().all(is_leaf) {
                for v in arr {
                    let key = leaf_key(v).unwrap_or_default();
                    out.push((format!("{prefix}[]={key}"), v.clone()));
                }
            } else if let Some(id_field) = identity_field_for(arr) {
                // Array of objects with a stable identity field (e.g.
                // `lib`, `name`, `path`). Index by the identity value so
                // reordering doesn't fabricate diffs at every shifted slot.
                // Skip the identity field as a leaf inside the object —
                // its value would tautologically equal the bracket key
                // (`[name=foo].name = "foo"`).
                for v in arr {
                    let id = v
                        .as_object()
                        .and_then(|o| o.get(id_field))
                        .and_then(leaf_key)
                        .unwrap_or_default();
                    let key = format!("{prefix}[{id_field}={id}]");
                    walk_skipping(v, &key, id_field, out);
                }
            } else {
                for (i, v) in arr.iter().enumerate() {
                    let next = format!("{prefix}[{i}]");
                    walk(v, &next, out);
                }
            }
        }
        Value::Null => {}
        _ if prefix.is_empty() => {}
        _ => out.push((prefix.to_string(), value.clone())),
    }
}

/// Like [`walk`] but skips one named field in the immediate object —
/// used by the identity-keyed array branch to drop the tautological
/// `[name=foo].name = "foo"` leaf (the value is just the bracket key
/// echoed back).  For non-object values, falls through to `walk`.
fn walk_skipping(value: &Value, prefix: &str, skip: &str, out: &mut Vec<(String, Value)>) {
    if let Value::Object(map) = value {
        for (k, v) in map {
            if k == skip {
                continue;
            }
            let next = format!("{prefix}.{k}");
            walk(v, &next, out);
        }
    } else {
        walk(value, prefix, out);
    }
}

/// Cap on rank-keyed array entries surfaced into kv-flat paths.  The
/// `binary.top_*` arrays are sorted lists where the head carries the
/// signal (top-N most complex / largest / hottest) — entries past the
/// head are tail noise that bloats kv diffs without adding value.
/// Returns `None` for arrays not in this category, leaving them
/// uncapped.
fn rank_keyed_cap(prefix: &str) -> Option<usize> {
    if prefix.starts_with("binary.top_") {
        return Some(3);
    }
    None
}

/// `Some(stable string form)` for JSON leaves; `None` for objects /
/// arrays / null. The `Some(_)` branches define both "what's a leaf?"
/// and the membership-encoding key in one place — earlier code split
/// these into `is_leaf` plus `leaf_key`, which had to stay in sync by
/// inspection.
fn leaf_key(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn is_leaf(v: &Value) -> bool {
    leaf_key(v).is_some()
}

/// If every element of `arr` is an object that carries the *same* well-known
/// identity field with a leaf value, return that field name. This lets the
/// flattener key array entries by member identity rather than by index, so
/// reordering doesn't fabricate change entries at every shifted slot.
///
/// The ranked candidate list covers what cleave's analyzers actually emit:
///
/// * `name` — ELF/Mach-O dynamic entries, PE imports, sections, JAR
///   `inner_classes`, RPM file entries
/// * `id` — generic structured-data; CRX/Apk identifiers
/// * `lib` — older Go/PE import shape
/// * `path` — Go `dependencies[]`, JAR pom modules, archive members
/// * `key` — Office relationships, plist keyed lists
/// * `symbol` — pickle / class-file symbol references
///
/// First field carried by *every* element wins. Returns `None` for arrays
/// without an obvious key — the caller then falls back to indexed paths.
/// New analyzer outputs that should benefit from identity-keyed diffs
/// belong on this list.
fn identity_field_for(arr: &[Value]) -> Option<&'static str> {
    const CANDIDATES: &[&str] = &["name", "id", "lib", "path", "key", "symbol"];
    CANDIDATES.iter().copied().find(|cand| {
        arr.iter().all(|v| {
            v.as_object()
                .and_then(|o| o.get(*cand))
                .is_some_and(is_leaf)
        })
    })
}

// =============================================================================
// KV — diffs a kv_tree pre-flattened by `flatten_kv_for_diff` into path /
// value pairs. Identity is path; values may be of any JSON type. The top-
// level path segment becomes `namespace` for downstream grouping.
// =============================================================================

/// Flatten a kv_tree into the diff-engine's path/value pairs. Public to
/// the `diff` module so unit construction can pre-flatten once per side.
/// Mirrors the encoding accepted by `type: kv` rules and `cleave kv`,
/// with smart array handling that doesn't fabricate diffs on reorder.
///
/// `source.imports[]` and `source.exports[]` are dropped — they're
/// kv-tree projections of `report.imports` / `report.exports`
/// (load-bearing for trait authoring via `type: kv`) but the diff
/// already shows the same data through the dedicated `symbols` scope.
/// Keeping them in the kv flatten would double-list every changed
/// import. The kv tree on each report is unmodified — traits keep
/// working.
pub(crate) fn flatten_kv_for_diff(value: &Value) -> Vec<(String, Value)> {
    let mut flat = flatten_dotted(value);
    flat.retain(|(path, _)| !is_redundant_kv_path(path));
    flat
}

/// `true` for kv paths whose content is fully shown by another diff
/// scope. Currently `source.imports[]` and `source.exports[]` (the
/// `symbols` scope is the canonical view).
fn is_redundant_kv_path(path: &str) -> bool {
    path.starts_with("source.imports[") || path.starts_with("source.exports[")
}

pub(super) fn diff_kv(old: &DiffUnit, new: &DiffUnit, limit: usize) -> ScopeDiff<KvChange> {
    let mut diff = diff_flat_paths(
        &old.kv_flat,
        &new.kv_flat,
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
    );

    // `.addr` leaf paths whose values are hex addresses change on
    // every build (function / init-array / fini-array slots get
    // relocated by the linker); the *moved* signal is captured by
    // sibling fields like `.size`, `.cc`, `.bbs` — the address itself
    // carries no diff value.  Drop those `~` entries.
    let mut dropped = 0.0_f32;
    diff.changed.retain(|c| {
        if is_trivial_address_change(&c.new.path, &c.old.value, &c.new.value) {
            dropped += value_change_weight(&c.old.value, &c.new.value);
            false
        } else {
            true
        }
    });
    if dropped > 0.0 {
        diff.change_weight = (diff.change_weight - dropped).max(0.0);
        diff.recompute_roc();
    }
    diff
}

/// `true` for `~` changes where the path ends in `.addr` and both
/// sides are hex-encoded addresses.  Distinct hex value content (build
/// IDs, hashes) lives at non-`.addr` paths so it isn't caught here.
fn is_trivial_address_change(path: &str, old: &Value, new: &Value) -> bool {
    if !path.ends_with(".addr") {
        return false;
    }
    let (Value::String(a), Value::String(b)) = (old, new) else {
        return false;
    };
    a.starts_with("0x") && b.starts_with("0x")
}

/// Shared engine for path-keyed diffs (metrics, KV). Per-change weight is
/// `value_change_weight`: numeric values weight by relative magnitude so that
/// 8 bytes off a multi-megabyte field counts as ~0, while a boolean flip or
/// add/remove counts as 1.0.
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
        // For path-keyed scopes the denominator is the total number of paths
        // on the larger side — every path is one "slot" of potential change.
        old_weight: old.len() as f32,
        new_weight: new.len() as f32,
        ..Default::default()
    };

    let mut change_weight = 0.0_f32;

    for (path, value) in new {
        match old_idx.get(path.as_str()) {
            None => {
                change_weight += 1.0; // new path: full slot of change
                diff.added.push(make(path, value));
            }
            Some(prev) if !json_eq(prev, value) => {
                change_weight += value_change_weight(prev, value);
                diff.changed.push(Changed {
                    old: make(path, prev),
                    new: make(path, value),
                });
            }
            Some(_) => {}
        }
    }
    for (path, value) in old {
        if !new_idx.contains_key(path.as_str()) {
            change_weight += 1.0; // path removed: full slot of change
            diff.removed.push(make(path, value));
        }
    }

    diff.change_weight = change_weight;
    diff.recompute_roc();
    truncate(&mut diff, limit);
    diff
}

/// Per-value change weight in `[0.0, 1.0]`.
///
/// - **Numbers**: relative magnitude `|new - old| / max(|old|, |new|)`.
///   8 bytes off a 1 MB field ⇒ 1e-5; doubling a counter ⇒ ~0.5.
/// - **Bools**: `1.0` if flipped, else `0.0`.
/// - **Strings / arrays / objects**: `1.0` if not equal, else `0.0`. We do
///   not edit-distance these in v1 — false zeros would be misleading.
/// - **Null**: handled as missing by the engine; this function is only
///   called when both sides have a value.
fn value_change_weight(old: &Value, new: &Value) -> f32 {
    match (old, new) {
        (Value::Number(a), Value::Number(b)) => {
            let av = a.as_f64().unwrap_or(0.0);
            let bv = b.as_f64().unwrap_or(0.0);
            let denom = av.abs().max(bv.abs());
            if denom <= 0.0 {
                0.0
            } else {
                (((av - bv).abs()) / denom).clamp(0.0, 1.0) as f32
            }
        }
        (Value::Bool(a), Value::Bool(b)) => {
            if a == b {
                0.0
            } else {
                1.0
            }
        }
        _ => {
            if old == new {
                0.0
            } else {
                1.0
            }
        }
    }
}

/// JSON equality with epsilon tolerance for floating-point numbers so
/// trivial rounding does not generate spurious change entries.
fn json_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(an), Value::Number(bn)) => match (an.as_f64(), bn.as_f64()) {
            (Some(x), Some(y)) => (x - y).abs() <= 1e-9,
            _ => an == bn,
        },
        _ => a == b,
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
    // Some upstream extractors emit the same symbol multiple times (e.g.
    // each call site of an import). Dedupe by `(kind, library, symbol)`
    // before diffing so the output doesn't repeat the same entry.
    // Tuple-keyed dedup. Replaces an earlier `format!("{:?}:{}:{}",...)`
    // hot path that allocated a `String` per symbol (~10K-50K
    // allocations on shared-library imports on a typical binary).
    fn key(c: &SymbolChange) -> (SymbolKind, String, String) {
        (
            c.kind,
            c.library.clone().unwrap_or_default(),
            c.symbol.clone(),
        )
    }
    let to_changes = |imports: &[Import], exports: &[Export]| -> Vec<SymbolChange> {
        let mut seen: FxHashSet<(SymbolKind, String, String)> = FxHashSet::default();
        let mut v: Vec<SymbolChange> = Vec::with_capacity(imports.len() + exports.len());
        let mut push = |v: &mut Vec<SymbolChange>, c: SymbolChange| {
            if seen.insert(key(&c)) {
                v.push(c);
            }
        };
        for i in imports {
            push(
                &mut v,
                SymbolChange {
                    symbol: i.symbol.clone(),
                    kind: SymbolKind::Import,
                    library: i.library.clone(),
                },
            );
        }
        for e in exports {
            push(
                &mut v,
                SymbolChange {
                    symbol: e.symbol.clone(),
                    kind: SymbolKind::Export,
                    library: None,
                },
            );
        }
        v
    };

    let old_v = to_changes(&old.imports, &old.exports);
    let new_v = to_changes(&new.imports, &new.exports);

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
        old_weight: old.sections.len() as f32,
        new_weight: new.sections.len() as f32,
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

    diff.change_weight = (diff.added.len() + diff.removed.len() + diff.changed.len()) as f32;
    diff.recompute_roc();
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
        old_weight: old.len() as f32,
        new_weight: new.len() as f32,
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

    diff.change_weight = (diff.added.len() + diff.removed.len()) as f32;
    diff.recompute_roc();
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
        old.kv_flat = flatten_kv_for_diff(&serde_json::json!({"metadata": {"sig": "old"}}));
        new.kv_flat = flatten_kv_for_diff(&serde_json::json!({
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
