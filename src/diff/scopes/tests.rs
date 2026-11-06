use super::*;
use crate::types::Criticality;
use crate::types::binary::{Export, Import, Section, StringInfo};
use crate::types::traits_findings::{Finding, FindingKind};

fn unit() -> DiffUnit {
    DiffUnit::empty("test".to_string())
}

fn finding(id: &str, crit: Criticality) -> Finding {
    Finding {
        precomputed_spans: None,
        src: None,
        id: id.to_string().into(),
        kind: FindingKind::Capability,
        desc: format!("desc {id}").into(),
        conf: 0.9,
        crit,
        mbc: None,
        attack: None,
        trait_refs: Vec::new(),
        evidence: Vec::new(),
        match_count: 1,
        source_file: None,
        downgraded: false,
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
    use std::collections::BTreeMap;

    let mut old = unit();
    let mut new = unit();
    old.filefacts_metrics = Some(BTreeMap::from([("text.lines".to_string(), 100.0)]));
    new.filefacts_metrics = Some(BTreeMap::from([("text.lines".to_string(), 150.0)]));

    let d = diff_metrics(&old, &new, 0);
    assert!(d.old_count > 0);
    assert!(d.new_count > 0);
    assert!(d.changed.iter().any(|c| c.new.path == "text.lines"));
}

/// Contract: the metrics scope carries digits only — counters,
/// totals, ratios, bools. Strings, arrays of strings, and nested
/// objects are kv content; the `flatten_metrics` filter must drop
/// them so they don't double-list under metrics (kv carries the
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
    assert!(
        d.added
            .iter()
            .any(|c| c.path == "signature.team_id" && c.namespace == "signature")
    );
    assert!(
        d.changed
            .iter()
            .any(|c| c.new.path == "metadata.sig" && c.new.namespace == "metadata")
    );
}

/// `file.basename`/`file.stem` are derived from the CLI-supplied path —
/// the rename is already in the diff header. Two byte-identical files
/// under different names must diff as unchanged.
#[test]
fn kv_ignores_path_derived_file_identity() {
    let mut old = unit();
    let mut new = unit();
    old.kv_flat = flatten_kv_for_diff(&serde_json::json!({
        "file": {"basename": "file1.sh", "stem": "file1"},
    }));
    new.kv_flat = flatten_kv_for_diff(&serde_json::json!({
        "file": {"basename": "file2.sh", "stem": "file2"},
    }));
    let d = diff_kv(&old, &new, 0);
    assert!(d.added.is_empty());
    assert!(d.removed.is_empty());
    assert!(d.changed.is_empty());
}

#[test]
fn symbols_distinguish_kind_and_library() {
    let mut old = unit();
    let mut new = unit();
    old.imports = vec![Import::new("malloc", Some("libc.so.6".into()))];
    new.imports = vec![
        Import::new("malloc", Some("libc.so.6".into())),
        Import::new("malloc", Some("musl.so".into())),
    ];
    new.exports = vec![Export::new("init", None)];

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
        value: (v.to_string()).into(),
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
        flags: Vec::new(),
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
fn trait_truncation_keeps_late_hostile_findings() {
    let mut diff: ScopeDiff<TraitChange> = ScopeDiff {
        added: (0..100)
            .map(|i| TraitChange {
                id: format!("metadata/noise/{i:03}"),
                trait_section: "metadata".to_string(),
                crit: Criticality::Baseline,
                conf: 0.9,
                desc: "low-signal finding".to_string(),
                count: 1,
            })
            .chain(std::iter::once(TraitChange {
                id: "objectives/command-and-control/remote-shell".to_string(),
                trait_section: "objectives".to_string(),
                crit: Criticality::Hostile,
                conf: 0.99,
                desc: "hostile composite".to_string(),
                count: 1,
            }))
            .collect(),
        new_count: 101,
        ..Default::default()
    };

    truncate_traits(&mut diff, 100);

    assert_eq!(diff.added.len(), 100);
    assert!(diff.truncated);
    assert_eq!(diff.added[0].crit, Criticality::Hostile);
    assert!(
        diff.added
            .iter()
            .any(|finding| finding.id.ends_with("remote-shell"))
    );
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
