//! `rule_shapes`: what the slow-rule and duplicate-trait audits learn about
//! each rule — its declared criticality, and whether it matches content
//! itself (atomic) or composes other traits.
#![allow(clippy::unwrap_used)]

use super::*;
use crate::types::Criticality;

fn shapes() -> std::collections::BTreeMap<String, rule_shape::RuleShape> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("shapes.yaml");
    std::fs::write(
        &path,
        r#"
traits:
  - id: test/shape::content
    desc: Matches content
    crit: suspicious
    if: {type: text, substr: "needle"}
  - id: test/shape::raw
    desc: Matches raw bytes
    crit: component
    if: {type: raw, regex: 'ne+dle'}
  - id: test/shape::alias
    desc: Restates another trait
    crit: notable
    if: {type: trait, id: test/shape::content}
composite_rules:
  - id: test/shape::combined
    desc: Combines traits
    crit: hostile
    all:
      - id: test/shape::content
      - id: test/shape::raw
"#,
    )
    .unwrap();
    CapabilityMapper::from_yaml(&path).unwrap().rule_shapes()
}

#[test]
fn content_matching_traits_are_atomic() {
    let shapes = shapes();
    assert!(shapes["test/shape::content"].atomic);
    assert!(shapes["test/shape::raw"].atomic);
}

#[test]
fn trait_references_and_composites_are_not_atomic() {
    let shapes = shapes();
    assert!(!shapes["test/shape::alias"].atomic);
    assert!(!shapes["test/shape::combined"].atomic);
}

#[test]
fn shapes_carry_the_declared_criticality() {
    let shapes = shapes();
    assert_eq!(shapes["test/shape::content"].crit, Criticality::Suspicious);
    assert_eq!(shapes["test/shape::raw"].crit, Criticality::Component);
    assert_eq!(shapes["test/shape::alias"].crit, Criticality::Notable);
    assert_eq!(shapes["test/shape::combined"].crit, Criticality::Hostile);
}

#[test]
fn shapes_record_where_each_rule_is_defined() {
    let shapes = shapes();
    assert!(
        shapes
            .values()
            .all(|s| s.defined_in.ends_with("shapes.yaml"))
    );
}
