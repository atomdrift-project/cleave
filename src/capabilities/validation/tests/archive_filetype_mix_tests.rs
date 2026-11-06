use crate::capabilities::validation::find_mixed_archive_filetype_traits;
use crate::composite_rules::{Arch, Condition, FileType, Platform, TextQuery, TraitDefinition};
use std::path::PathBuf;

fn trait_for(id: &str, types: Vec<FileType>, from_groups: bool) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        r#if: Condition::Text(TextQuery {
            substr: Some("MARKER".to_string()),
            ..Default::default()
        }),
        r#for: types,
        for_from_groups: from_groups,
        platforms: vec![Platform::Unix],
        arch: vec![Arch::All],
        defined_in: PathBuf::from("test.yml"),
        ..Default::default()
    }
}

#[test]
fn flags_an_atomic_that_straddles_the_archive_boundary() {
    // `for: [tar, shell]` reads as "either", but an atomic runs on one node.
    // cleave expands the tar and scans `src/a.txt` as its own `text` node --
    // the container's bytes are never content-scanned, even though the
    // marker is present in them verbatim. Only the `shell` half can fire.
    let traits = vec![trait_for(
        "test/mix::tar-and-shell",
        vec![FileType::Tar, FileType::Shell],
        false,
    )];

    let found = find_mixed_archive_filetype_traits(&traits);
    assert_eq!(found.len(), 1, "expected the mixed trait to be flagged");
    assert_eq!(found[0].0, "test/mix::tar-and-shell");
    assert_eq!(found[0].1, vec![FileType::Tar]);
    assert_eq!(found[0].2, vec![FileType::Shell]);
}

#[test]
fn allows_archive_only_and_plain_only_atomics() {
    let traits = vec![
        trait_for(
            "test/mix::archive-only",
            vec![FileType::Tar, FileType::Zip],
            false,
        ),
        trait_for(
            "test/mix::plain-only",
            vec![FileType::Shell, FileType::Python],
            false,
        ),
    ];
    assert!(find_mixed_archive_filetype_traits(&traits).is_empty());
}

#[test]
fn allows_for_all_and_group_derived_lists() {
    // `for: [all]` is the sanctioned "any node". A named group may itself
    // expand to a mix -- `data` covers `ipa` beside `json`/`text` -- and the
    // author wrote one group name, so group-derived lists are exempt.
    let traits = vec![
        trait_for("test/mix::all", vec![FileType::All, FileType::Shell], false),
        trait_for(
            "test/mix::from-group",
            vec![FileType::Ipa, FileType::Json],
            true,
        ),
    ];
    assert!(find_mixed_archive_filetype_traits(&traits).is_empty());
}

fn path_trait(id: &str, types: Vec<FileType>) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        r#if: Condition::Path(crate::composite_rules::condition::PathQuery {
            basename: true,
            regex: Some("^installer\\.exe$".to_string()),
            ..Default::default()
        }),
        r#for: types,
        platforms: vec![Platform::Unix],
        arch: vec![Arch::All],
        defined_in: PathBuf::from("test.yml"),
        ..Default::default()
    }
}

/// `type: path`/`basename` reads the node's own path, which every node
/// has -- archive or not -- so mixing archive and plain types is not the
/// one-node-one-matcher conflation this validator exists to catch.
/// `izpack-package-path` (`for: [jar, pe, shell, javascript, java]`) is
/// the real shape: one basename check, whichever node it lands on.
#[test]
fn path_matchers_are_exempt_from_the_archive_boundary_check() {
    let traits = vec![path_trait(
        "test/mix::path-mix",
        vec![FileType::Jar, FileType::Pe, FileType::Shell],
    )];
    assert!(find_mixed_archive_filetype_traits(&traits).is_empty());
}

fn metrics_trait(id: &str, types: Vec<FileType>) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        r#if: Condition::Metrics(crate::composite_rules::condition::MetricsQuery {
            field: "file.entropy".to_string(),
            min: Some(7.9),
            ..Default::default()
        }),
        r#for: types,
        platforms: vec![Platform::Unix],
        arch: vec![Arch::All],
        defined_in: PathBuf::from("test.yml"),
        ..Default::default()
    }
}

/// `type: metrics` is measurement, not a content scan: `file.entropy` is
/// computed for whichever node is analysed, container and member alike,
/// so an archive type beside a leaf type is not the "only one half can
/// fire" conflation. `near-maximum-entropy-file` is the live shape.
#[test]
fn metrics_matchers_are_exempt_from_the_archive_boundary_check() {
    let traits = vec![metrics_trait(
        "test/mix::entropy-mix",
        vec![FileType::Zip, FileType::Tar, FileType::Data],
    )];
    assert!(find_mixed_archive_filetype_traits(&traits).is_empty());
}

/// But `type: value` stays reported: a container-scoped fact such as
/// `archive.members[*].path` exists only on a node the archive analyser
/// cracked, so a leaf type listed beside an archive type really is dead.
#[test]
fn value_matchers_are_still_flagged() {
    let mut t = trait_for(
        "test/mix::member-path-mix",
        vec![FileType::Zip, FileType::JavaScript],
        false,
    );
    t.r#if = Condition::Kv(crate::composite_rules::condition::KvQuery {
        path: "archive.members[*].path".to_string(),
        substr: Some("node_modules/".to_string()),
        ..Default::default()
    });
    assert_eq!(find_mixed_archive_filetype_traits(&[t]).len(), 1);
}

#[test]
fn static_lib_is_not_an_archive_so_it_may_pair_with_source() {
    // `ar` is the one container cleave does not expand: a `type: text`
    // trait declared `for: [static-lib]` does match the archive's own
    // bytes, so pairing it with a source type is legitimate.
    let traits = vec![trait_for(
        "test/mix::ar-and-c",
        vec![FileType::StaticLib, FileType::C],
        false,
    )];
    assert!(find_mixed_archive_filetype_traits(&traits).is_empty());
}
