use crate::capabilities::validation::find_convictions_without_content;
use crate::composite_rules::condition::{PathQuery, TextQuery};
use crate::composite_rules::{
    Arch, CompositeTrait, Condition, FileType, Platform, TraitDefinition,
};
use crate::types::Criticality;
use std::path::PathBuf;

fn atom(id: &str, cond: Condition) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "atom".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        r#if: cond,
        r#for: vec![FileType::All],
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        defined_in: PathBuf::from("t.yml"),
        ..Default::default()
    }
}

fn name(id: &str, exact: &str) -> TraitDefinition {
    atom(
        id,
        Condition::Path(PathQuery {
            exact: Some(exact.to_string()),
            basename: true,
            ..Default::default()
        }),
    )
}

fn text(id: &str, exact: &str) -> TraitDefinition {
    atom(
        id,
        Condition::Text(TextQuery {
            exact: Some(exact.to_string()),
            ..Default::default()
        }),
    )
}

fn rule(id: &str, crit: Criticality, legs: &[&str]) -> CompositeTrait {
    CompositeTrait {
        id: id.to_string(),
        desc: "rule".to_string(),
        conf: 0.9,
        crit,
        r#for: vec![FileType::All],
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        all: Some(
            legs.iter()
                .map(|leg| Condition::Trait {
                    id: (*leg).to_string(),
                })
                .collect(),
        ),
        defined_in: PathBuf::from("t.yml"),
        ..Default::default()
    }
}

/// Each leg is walked once and shared across rules, so every rule that
/// uses a leg must still see what it reaches, through nested composites,
/// and one content-reading leg must clear a rule wherever it sits.
#[test]
fn shared_legs_are_judged_per_rule() {
    let traits = vec![
        name("t::a", "a.exe"),
        name("t::b", "b.exe"),
        text("t::c", "payload"),
    ];
    let rules = vec![
        rule("t::names", Criticality::Hostile, &["t::a", "t::b"]),
        rule("t::names-again", Criticality::Suspicious, &["t::b", "t::a"]),
        rule("t::content-last", Criticality::Hostile, &["t::a", "t::c"]),
        rule("t::content-first", Criticality::Hostile, &["t::c", "t::a"]),
        rule("t::inner", Criticality::Notable, &["t::a"]),
        rule("t::outer", Criticality::Hostile, &["t::inner", "t::b"]),
    ];
    let found = find_convictions_without_content(&traits, &rules);
    let names = vec!["t::a".to_string(), "t::b".to_string()];
    assert_eq!(
        found,
        vec![
            ("t::names".to_string(), names.clone()),
            ("t::names-again".to_string(), names.clone()),
            ("t::outer".to_string(), names),
        ]
    );
}

/// A leg is settled by its first content-reading trait or inline condition
/// however deep it sits, cycles between composites terminate, and a
/// reported rule still lists every terminal it rests on -- including
/// through a directory reference.
#[test]
fn legs_settle_at_content_and_reported_rules_list_every_terminal() {
    let traits = vec![
        name("t::a", "a.exe"),
        name("t::b", "b.exe"),
        text("t::c", "payload"),
        name("d/x::n1", "n1.exe"),
        name("d/x::n2", "n2.exe"),
    ];
    let mut inline = rule("t::inline-inner", Criticality::Notable, &["t::a"]);
    if let Some(all) = inline.all.as_mut() {
        all.push(Condition::Text(TextQuery {
            exact: Some("x".to_string()),
            ..Default::default()
        }));
    }
    let rules = vec![
        rule("t::mixed", Criticality::Notable, &["t::a", "t::c"]),
        rule("t::cyc1", Criticality::Notable, &["t::cyc2", "t::a"]),
        rule("t::cyc2", Criticality::Notable, &["t::cyc1", "t::b"]),
        inline,
        rule("t::via-mixed", Criticality::Hostile, &["t::b", "t::mixed"]),
        rule("t::cycle", Criticality::Hostile, &["t::cyc1"]),
        rule("t::dir", Criticality::Hostile, &["d/x"]),
        rule("t::via-inline", Criticality::Hostile, &["t::inline-inner"]),
        rule("t::empty", Criticality::Hostile, &["t::nowhere"]),
    ];
    let found = find_convictions_without_content(&traits, &rules);
    assert_eq!(
        found,
        vec![
            (
                "t::cycle".to_string(),
                vec!["t::a".to_string(), "t::b".to_string()]
            ),
            (
                "t::dir".to_string(),
                vec!["d/x::n1".to_string(), "d/x::n2".to_string()]
            ),
        ]
    );
}
