use crate::capabilities::validation::constraints::find_orphaned_components;
use crate::composite_rules::traits::{CompositeTrait, DowngradeConditions};
use crate::composite_rules::{Arch, Condition, FileType, Platform, RawQuery, TraitDefinition};
use std::collections::HashMap;
use std::path::PathBuf;

fn make_component_trait(id: &str) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "component".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Component,
        mbc: None,
        attack: None,
        r#if: Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("test".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        }),
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        r#for: vec![FileType::All],
        for_from_groups: false,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        not: None,
        unless: None,
        downgrade: None,
        defined_in: PathBuf::from("test.yml"),
        precision: None,
        ..Default::default()
    }
}

fn make_composite(
    id: &str,
    all_conditions: Vec<Condition>,
    downgrade: Option<DowngradeConditions>,
) -> CompositeTrait {
    CompositeTrait {
        required_trait_indices: Vec::new(),
        id: id.to_string(),
        desc: "composite".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(all_conditions),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade,
        defined_in: PathBuf::from("test.yml"),
        precision: None,
        ..Default::default()
    }
}

#[test]
fn test_find_orphaned_includes_downgrade_any() {
    // Component referenced ONLY in downgrade.any: should NOT be orphaned
    let trait_defs = vec![make_component_trait("test::comp-any-ref")];
    let composites = vec![make_composite(
        "test::my-composite",
        vec![Condition::Trait {
            id: "some-other".to_string(),
        }],
        Some(DowngradeConditions {
            all: None,
            any: Some(vec![Condition::Trait {
                id: "test::comp-any-ref".to_string(),
            }]),
            needs: None,
            scope: None,
        }),
    )];

    let source_files: HashMap<String, String> = HashMap::new();
    let orphans = find_orphaned_components(&trait_defs, &composites, &source_files);
    let orphan_ids: Vec<&str> = orphans.iter().map(|(id, _)| id.as_str()).collect();

    assert!(
        !orphan_ids.contains(&"test::comp-any-ref"),
        "Component referenced in downgrade.any should NOT be orphaned, but got orphans: {:?}",
        orphan_ids
    );
}

/// A directory reference covers the components under that directory and
/// its subdirectories, and nothing in a sibling that merely shares its
/// name as a prefix.
#[test]
fn a_directory_reference_covers_only_its_own_components() {
    let trait_defs: Vec<TraitDefinition> = ["a/a::w", "a/b::x", "a/b/c::y", "a/bc::z"]
        .into_iter()
        .map(make_component_trait)
        .collect();
    let composites = vec![make_composite(
        "test::uses-dir",
        vec![Condition::Trait {
            id: "a/b/".to_string(),
        }],
        None,
    )];

    let orphans = find_orphaned_components(&trait_defs, &composites, &HashMap::new());
    let orphan_ids: Vec<&str> = orphans.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(orphan_ids, ["a/a::w", "a/bc::z"]);
}
