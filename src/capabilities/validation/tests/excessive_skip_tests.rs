use crate::capabilities::validation::constraints::find_excessive_skip_conditions;
use crate::composite_rules::condition::{Condition, RawQuery};
use crate::composite_rules::traits::{CompositeTrait, DowngradeConditions, TraitDefinition};
use crate::types::Criticality;

/// `n` distinct, inert raw conditions — stand-ins for suppression entries.
fn raw_conds(n: usize) -> Vec<Condition> {
    (0..n)
        .map(|i| {
            Condition::Raw(RawQuery {
                exact: Some(format!("c{i}")),
                ..Default::default()
            })
        })
        .collect()
}

fn trait_def(id: &str, r#if: Condition, unless: usize, downgrade_all: usize) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "t".to_string(),
        crit: Criticality::Suspicious,
        r#if,
        unless: (unless > 0).then(|| raw_conds(unless)),
        downgrade: (downgrade_all > 0).then(|| DowngradeConditions {
            any: None,
            all: Some(raw_conds(downgrade_all)),
            needs: None,
            scope: None,
        }),
        ..Default::default()
    }
}

fn raw_if() -> Condition {
    Condition::Raw(RawQuery {
        exact: Some("marker".to_string()),
        ..Default::default()
    })
}

/// `Condition::Trait` reference for each ID.
fn refs(ids: &[&str]) -> Vec<Condition> {
    ids.iter()
        .map(|r| Condition::Trait {
            id: (*r).to_string(),
        })
        .collect()
}

/// An aggregator composite — its `any:` legs are the exception list a rule pulls
/// in by referencing it from `unless:`.
fn aggregator(id: &str, any_legs: &[&str]) -> CompositeTrait {
    CompositeTrait {
        id: id.to_string(),
        desc: "agg".to_string(),
        crit: Criticality::Component,
        any: Some(refs(any_legs)),
        ..Default::default()
    }
}

/// A composite rule whose only suppression is the given `unless:` conditions.
fn rule_unless(id: &str, unless: Vec<Condition>) -> CompositeTrait {
    CompositeTrait {
        id: id.to_string(),
        desc: "r".to_string(),
        crit: Criticality::Suspicious,
        unless: Some(unless),
        ..Default::default()
    }
}

/// Leaf IDs `p0..pn` (e.g. `a0`, `b0`) — referenced but never defined as composites,
/// so each resolves to a single leaf exception.
fn leaf_ids(prefix: &str, n: usize) -> Vec<String> {
    (0..n).map(|i| format!("{prefix}{i}")).collect()
}

// The own limit (10) counts the `unless:`/`downgrade:` entries written literally on a
// single rule, regardless of what it references. This is the original behavior.
#[test]
fn own_limit_flags_single_rule() {
    let traits = vec![trait_def("t", raw_if(), 6, 4)];
    let v = find_excessive_skip_conditions(&traits, &[]);
    let t = v
        .iter()
        .find(|e| e.id == "t")
        .expect("flagged on own count");
    assert_eq!((t.own, t.is_composite), (10, false));
}

// A few literal exceptions, no aggregator references => clean on both limits.
#[test]
fn under_both_limits_is_clean() {
    let traits = vec![trait_def("a", raw_if(), 9, 0)];
    assert!(find_excessive_skip_conditions(&traits, &[]).is_empty());
}

// The expanded limit (48) catches an exception list hidden behind one reference:
// `unless: [agg]` where `agg` enumerates 80 benign indicators. Own count is 1.
#[test]
fn expanded_aggregator_reference_flags_rule() {
    let leaves = leaf_ids("a", 80);
    let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
    let composites = vec![
        aggregator("agg", &leaf_refs),
        rule_unless("comp", refs(&["agg"])),
    ];

    let v = find_excessive_skip_conditions(&[], &composites);
    let comp = v
        .iter()
        .find(|e| e.id == "comp")
        .expect("flagged on expanded count");
    assert_eq!((comp.own, comp.expanded), (1, 80));
    // The aggregator itself carries no suppressions, so it is not flagged.
    assert!(!v.iter().any(|e| e.id == "agg"));
}

// A bare reference names an aggregator the way the engine resolves it: the referrer's
// own directory first, then a unique short name. Looking it up by exact string
// counted it as one leaf, so a rule hiding a 80-leg exception list behind a bare
// reference was never flagged.
#[test]
fn bare_aggregator_reference_expands_like_a_qualified_one() {
    let leaves = leaf_ids("a", 80);
    let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();

    // Same directory: the reference resolves to `dir/x::agg`.
    let same_dir = vec![
        aggregator("dir/x::agg", &leaf_refs),
        rule_unless("dir/x::comp", refs(&["agg"])),
    ];
    let v = find_excessive_skip_conditions(&[], &same_dir);
    let comp = v
        .iter()
        .find(|e| e.id == "dir/x::comp")
        .expect("a bare same-directory reference must expand");
    assert_eq!((comp.own, comp.expanded), (1, 80));

    // Another directory: the short name is unique, so it still resolves.
    let other_dir = vec![
        aggregator("dir/x::agg", &leaf_refs),
        rule_unless("elsewhere::comp", refs(&["agg"])),
    ];
    let v = find_excessive_skip_conditions(&[], &other_dir);
    assert!(
        v.iter()
            .any(|e| e.id == "elsewhere::comp" && e.expanded == 80),
        "a unique short name must resolve to its aggregator"
    );
}

// A metadata property or well-known identity is one stated fact; an exception list
// in the same tier is still a list of carve-outs and still expands.
#[test]
fn stated_property_counts_one_but_exception_list_expands() {
    let leaves = leaf_ids("a", 80);
    let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
    let mut property = aggregator("metadata/package/testing::is-test", &leaf_refs);
    property.crit = Criticality::Baseline;
    let mut identity = aggregator("well-known/lib/net/x::identity", &leaf_refs);
    identity.crit = Criticality::Notable;
    let mut carve_outs = aggregator("metadata/package/empty::benign-context", &leaf_refs);
    carve_outs.crit = Criticality::Exception;
    // A notable capability group outside metadata/well-known keeps expanding.
    let mut capability = aggregator("micro-behaviors/x::group", &leaf_refs);
    capability.crit = Criticality::Notable;
    let composites = vec![
        property,
        identity,
        carve_outs,
        capability,
        rule_unless("p::r1", refs(&["metadata/package/testing::is-test"])),
        rule_unless("p::r2", refs(&["well-known/lib/net/x::identity"])),
        rule_unless("p::r3", refs(&["metadata/package/empty::benign-context"])),
        rule_unless("p::r4", refs(&["micro-behaviors/x::group"])),
    ];
    let v = find_excessive_skip_conditions(&[], &composites);
    assert!(!v.iter().any(|e| e.id == "p::r1"), "a property is one fact");
    assert!(
        !v.iter().any(|e| e.id == "p::r2"),
        "an identity is one fact"
    );
    assert!(
        v.iter().any(|e| e.id == "p::r3" && e.expanded == 80),
        "an exception list expands"
    );
    assert!(
        v.iter().any(|e| e.id == "p::r4" && e.expanded == 80),
        "a capability group expands"
    );
}

// The expanded limit is inclusive: exactly the limit flags, one fewer does not.
#[test]
fn expanded_limit_boundary() {
    use crate::capabilities::validation::MAX_AGGREGATE_SUPPRESSIONS as LIMIT;
    for (n, flagged) in [(LIMIT - 1, false), (LIMIT, true)] {
        let leaves = leaf_ids("a", n);
        let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
        let composites = vec![
            aggregator("agg", &leaf_refs),
            rule_unless("comp", refs(&["agg"])),
        ];
        let v = find_excessive_skip_conditions(&[], &composites);
        assert_eq!(v.iter().any(|e| e.id == "comp"), flagged, "{n} expanded");
    }
    assert_eq!(LIMIT, 48);
}

// An ambiguous short name resolves to nothing: guessing between two aggregators
// would charge a rule with a list it may not mean. It stays a single leaf.
#[test]
fn ambiguous_bare_reference_is_not_guessed() {
    let leaves = leaf_ids("a", 80);
    let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
    let composites = vec![
        aggregator("one::agg", &leaf_refs),
        aggregator("two::agg", &leaf_refs),
        rule_unless("elsewhere::comp", refs(&["agg"])),
    ];
    let v = find_excessive_skip_conditions(&[], &composites);
    assert!(
        !v.iter().any(|e| e.id == "elsewhere::comp"),
        "an ambiguous short name must not be expanded"
    );
}

// The referrer's own directory wins over a same-named aggregator elsewhere.
#[test]
fn bare_reference_prefers_the_referrers_directory() {
    let big = leaf_ids("a", 80);
    let big_refs: Vec<&str> = big.iter().map(String::as_str).collect();
    let composites = vec![
        aggregator("near::agg", &["only-one"]),
        aggregator("far::agg", &big_refs),
        rule_unless("near::comp", refs(&["agg"])),
    ];
    let v = find_excessive_skip_conditions(&[], &composites);
    assert!(
        !v.iter().any(|e| e.id == "near::comp"),
        "must resolve to near::agg (1 leg), not far::agg (80 legs)"
    );
}

// The KEY property: `all:`/`any:` MATCHING references are never counted as
// suppressions. A rule that merely requires a heavily-suppressed composite to match
// inherits none of its exceptions.
#[test]
fn matching_references_are_not_counted() {
    let heavy = rule_unless("heavy", raw_conds(50)); // 50 literal exceptions
    let comp = CompositeTrait {
        id: "comp".to_string(),
        desc: "c".to_string(),
        crit: Criticality::Hostile,
        all: Some(refs(&["heavy"])), // requires heavy as a match, no unless of its own
        ..Default::default()
    };
    let v = find_excessive_skip_conditions(&[], &[heavy, comp]);
    assert!(
        !v.iter().any(|e| e.id == "comp"),
        "a matching (all:) reference must not contribute to the suppression count"
    );
    assert!(
        v.iter().any(|e| e.id == "heavy"),
        "heavy itself is over the limit"
    );
}

// A suspicious/hostile detection named in `unless:` stands the rule down when a
// stronger verdict fired: one condition, not its 80 legs. A component aggregator
// with the same legs is still an exception list and still expands.
#[test]
fn detection_verdict_in_unless_counts_one() {
    let leaves = leaf_ids("a", 80);
    let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
    let mut verdict = aggregator("stealer", &leaf_refs);
    verdict.crit = Criticality::Hostile;
    let composites = vec![
        verdict,
        aggregator("benign-group", &leaf_refs),
        rule_unless("defers-to-verdict", refs(&["stealer"])),
        rule_unless("uses-exception-list", refs(&["benign-group"])),
    ];

    let v = find_excessive_skip_conditions(&[], &composites);
    assert!(
        !v.iter().any(|e| e.id == "defers-to-verdict"),
        "a verdict reference must count once"
    );
    let listed = v
        .iter()
        .find(|e| e.id == "uses-exception-list")
        .expect("a 80-leg exception list is still over the cap");
    assert_eq!((listed.own, listed.expanded), (1, 80));
}

// Leaf and `dir/` references inside `unless:` each count as one — only aggregator
// composites expand. Here 71 expanded + 1 dir + 1 leaf = 73 trips the limit.
#[test]
fn leaf_and_directory_references_count_one() {
    let leaves = leaf_ids("a", 71);
    let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
    let composites = vec![
        aggregator("agg", &leaf_refs),
        rule_unless("comp", refs(&["agg", "some/dir/", "x::leaf"])),
    ];

    let v = find_excessive_skip_conditions(&[], &composites);
    let comp = v.iter().find(|e| e.id == "comp").expect("flagged");
    assert_eq!((comp.own, comp.expanded), (3, 73));
}

// An aggregator is expanded for every referrer, shared or not: the recursive cap
// measures each rule's exception burden, and sharing a 80-leg cluster does not make
// the 80 conditions weigh less on the rule that pulls them in. Both users are flagged.
#[test]
fn shared_aggregator_is_expanded_for_every_referrer() {
    let leaves = leaf_ids("a", 80);
    let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
    let composites = vec![
        aggregator("agg", &leaf_refs),
        rule_unless("r1", refs(&["agg"])),
        rule_unless("r2", refs(&["agg"])), // sharing is no discount
    ];

    let v = find_excessive_skip_conditions(&[], &composites);
    for id in ["r1", "r2"] {
        let e = v.iter().find(|e| e.id == id).expect("flagged");
        assert_eq!((e.own, e.expanded), (1, 80));
    }
}

// Aggregator cycles still terminate: a node revisited within one rule's walk is
// counted zero the second time, so two aggregators that reference each other resolve
// to a finite total rather than recursing forever.
#[test]
fn aggregator_cycle_terminates() {
    let composites = vec![
        CompositeTrait {
            id: "a".to_string(),
            desc: "agg".to_string(),
            crit: Criticality::Component,
            any: Some(refs(&["b"])),
            ..Default::default()
        },
        CompositeTrait {
            id: "b".to_string(),
            desc: "agg".to_string(),
            crit: Criticality::Component,
            any: Some(refs(&["a"])),
            ..Default::default()
        },
        rule_unless("comp", refs(&["a"])),
    ];

    let v = find_excessive_skip_conditions(&[], &composites);
    // a -> b -> a(already counted, 0): the cycle contributes nothing past first visit,
    // so `comp` stays well under the cap and is not flagged.
    assert!(!v.iter().any(|e| e.id == "comp"));
}

// A `*-known-benign-context` composite is a named exception group: an author
// wrote it specifically to be referenced widely, and growing its own list is
// the fix this validator's message recommends when a rule's suppressions run
// long. Expanding through it counted the group's membership as the referrer's
// burden, so `js-global-object-alias-assignment` (real shape: 1 written,
// 112 expanded via `js-assign-common-root-known-benign-context`) tripped the
// cap for taking that advice. It must be treated as opaque, like a directory
// reference, regardless of how many benign shapes it enumerates internally.
#[test]
fn named_exception_group_counts_as_one_not_expanded() {
    let leaves = leaf_ids("a", 112);
    let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
    let composites = vec![
        aggregator(
            "some/dir::js-assign-common-root-known-benign-context",
            &leaf_refs,
        ),
        rule_unless(
            "js-global-object-alias-assignment",
            refs(&["some/dir::js-assign-common-root-known-benign-context"]),
        ),
    ];

    let v = find_excessive_skip_conditions(&[], &composites);
    assert!(
        !v.iter()
            .any(|e| e.id == "js-global-object-alias-assignment"),
        "a single reference to a named exception group must not trip the expanded cap"
    );
}
