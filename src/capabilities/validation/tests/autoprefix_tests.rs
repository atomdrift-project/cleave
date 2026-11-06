use super::super::composite::{collect_trait_refs_from_rule, collect_trait_refs_from_trait_def};
use crate::capabilities::parsing::autoprefix_trait_refs;
use crate::composite_rules::condition::{Condition, RawQuery};
use crate::composite_rules::traits::{CompositeTrait, DowngradeConditions, TraitDefinition};
use crate::composite_rules::types::{Arch, FileType, Platform};
use crate::types::Criticality;

fn make_rule(
    unless: Option<Vec<Condition>>,
    downgrade: Option<DowngradeConditions>,
) -> CompositeTrait {
    CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/rule".to_string(),
        desc: "Test".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless,
        not: None,
        downgrade,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

#[test]
fn test_autoprefix_unless_refs() {
    let mut rule = make_rule(
        Some(vec![Condition::Trait {
            id: "local-trait".to_string(),
        }]),
        None,
    );

    autoprefix_trait_refs(&mut rule, "my-prefix");

    match &rule.unless.unwrap()[0] {
        Condition::Trait { id } => {
            assert_eq!(id, "my-prefix::local-trait");
        }
        _ => panic!("Expected Trait condition"),
    }
}

#[test]
fn test_autoprefix_downgrade_refs() {
    let mut rule = make_rule(
        None,
        Some(DowngradeConditions {
            all: Some(vec![Condition::Trait {
                id: "all-local".to_string(),
            }]),
            any: Some(vec![Condition::Trait {
                id: "any-local".to_string(),
            }]),
            needs: None,
            scope: None,
        }),
    );

    autoprefix_trait_refs(&mut rule, "pfx");

    let dg = rule.downgrade.unwrap();
    match &dg.all.unwrap()[0] {
        Condition::Trait { id } => assert_eq!(id, "pfx::all-local"),
        _ => panic!("Expected Trait"),
    }
    match &dg.any.unwrap()[0] {
        Condition::Trait { id } => assert_eq!(id, "pfx::any-local"),
        _ => panic!("Expected Trait"),
    }
}

#[test]
fn test_collect_refs_includes_unless_and_downgrade() {
    let rule = make_rule(
        Some(vec![Condition::Trait {
            id: "unless-ref".to_string(),
        }]),
        Some(DowngradeConditions {
            all: None,
            any: Some(vec![Condition::Trait {
                id: "dg-any-ref".to_string(),
            }]),
            needs: None,
            scope: None,
        }),
    );

    let refs = collect_trait_refs_from_rule(&rule);
    let ids: Vec<&str> = refs.iter().map(|(id, _)| id.as_str()).collect();
    assert!(ids.contains(&"unless-ref"));
    assert!(ids.contains(&"dg-any-ref"));
}

fn make_trait_def(
    r#if: Condition,
    unless: Option<Vec<Condition>>,
    downgrade: Option<DowngradeConditions>,
) -> TraitDefinition {
    TraitDefinition {
        id: "atomic-trait".to_string(),
        desc: "atomic".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        r#if,
        r#for: vec![FileType::All],
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        unless,
        not: None,
        downgrade,
        defined_in: std::path::PathBuf::from("test.yaml"),
        ..Default::default()
    }
}

// Atomic traits reference other traits in `if:`, `unless:`, and `downgrade:`;
// those refs went unvalidated before `collect_trait_refs_from_trait_def`, so a
// dangling exemption (e.g. a YAML-filename-in-ID `unless`) silently became a
// no-op rather than a load error.
#[test]
fn test_collect_refs_from_atomic_trait_covers_if_unless_downgrade() {
    let trait_def = make_trait_def(
        Condition::Trait {
            id: "if-ref".to_string(),
        },
        Some(vec![Condition::Trait {
            id: "unless-ref".to_string(),
        }]),
        Some(DowngradeConditions {
            all: Some(vec![Condition::Trait {
                id: "dg-all-ref".to_string(),
            }]),
            any: None,
            needs: None,
            scope: None,
        }),
    );

    let refs = collect_trait_refs_from_trait_def(&trait_def);
    let ids: Vec<&str> = refs.iter().map(|(id, _)| id.as_str()).collect();
    assert!(ids.contains(&"if-ref"), "if: ref must be collected");
    assert!(ids.contains(&"unless-ref"), "unless: ref must be collected");
    assert!(
        ids.contains(&"dg-all-ref"),
        "downgrade: ref must be collected"
    );
    // Every collected ref is owned by the atomic trait.
    assert!(refs.iter().all(|(_, owner)| owner == "atomic-trait"));
}

// A non-trait `if:` (raw/pattern condition) yields no refs, and an atomic trait
// with no exemptions is ref-free — the common case must not spuriously report refs.
#[test]
fn test_collect_refs_from_atomic_trait_ignores_non_trait_conditions() {
    let trait_def = make_trait_def(
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("marker".to_string()),
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
        None,
        None,
    );

    assert!(collect_trait_refs_from_trait_def(&trait_def).is_empty());
}
