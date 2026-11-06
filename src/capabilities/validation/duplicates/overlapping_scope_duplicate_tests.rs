use super::*;
use crate::composite_rules::{Condition, Scope};

fn leg(id: &str) -> Condition {
    Condition::Trait { id: id.to_string() }
}

fn base(id: &str, crit: Criticality) -> CompositeTrait {
    CompositeTrait {
        id: id.to_string(),
        desc: "r".to_string(),
        crit,
        all: Some(vec![leg("a"), leg("b")]),
        r#for: vec![RuleFileType::Shell],
        ..Default::default()
    }
}

#[test]
fn same_legs_same_crit_is_flagged() {
    let rules = vec![
        base("r1", Criticality::Notable),
        base("r2", Criticality::Notable),
    ];
    let found = find_overlapping_scope_duplicates(&rules);
    assert_eq!(found.len(), 1);
    assert!(found[0].4, "same crit should report same_crit = true");
}

/// `scope` changes what counts as the same evidence: two rules with identical
/// legs but different pooling scopes draw on different evidence and are not
/// duplicates (`pkgsrc-maintainer-archive-context`, `scope: outer`, looked
/// like a duplicate of a file-scoped sibling before this fix).
#[test]
fn differing_scope_is_not_a_duplicate() {
    let mut a = base("r1", Criticality::Notable);
    let mut b = base("r2", Criticality::Notable);
    a.scope = Some(Scope::Outer);
    b.scope = None;
    assert!(find_overlapping_scope_duplicates(&[a, b]).is_empty());
}

/// A `downgrade:` changes the verdict the shared evidence produces, so two
/// rules differing only there are not reporting the same finding twice
/// (`excessive-line-length-large-pe` vs `...-protobuf-text`).
#[test]
fn differing_downgrade_is_not_a_duplicate() {
    let mut a = base("r1", Criticality::Notable);
    let b = base("r2", Criticality::Notable);
    a.downgrade = Some(DowngradeConditions {
        any: Some(vec![leg("x")]),
        all: None,
        needs: None,
        scope: None,
    });
    assert!(find_overlapping_scope_duplicates(&[a, b]).is_empty());
}

/// An exception is a suppressor, not a finding: it never surfaces on its
/// own, so "two findings report the same evidence" is false whenever
/// either side is one (`pkgsrc-maintainer-archive-context` alongside a
/// baseline sibling with the same legs looked like a duplicate pair).
#[test]
fn either_side_being_an_exception_is_not_a_duplicate() {
    let a = base("r1", Criticality::Exception);
    let b = base("r2", Criticality::Notable);
    assert!(find_overlapping_scope_duplicates(&[a, b]).is_empty());
}
