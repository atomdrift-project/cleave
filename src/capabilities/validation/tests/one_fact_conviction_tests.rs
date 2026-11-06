use crate::capabilities::validation::find_one_fact_convictions;
use crate::composite_rules::condition::{KvQuery, PathQuery};
use crate::composite_rules::{
    Arch, CompositeTrait, Condition, FileType, Platform, TraitDefinition,
};
use std::path::PathBuf;

const MEMBER_PATH: &str = "archive.members[*].path";

fn leg(id: &str, cond: Condition) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "leg".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        r#if: cond,
        r#for: vec![FileType::Zip],
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        defined_in: PathBuf::from("t.yml"),
        ..Default::default()
    }
}

fn member_regex(id: &str, regex: &str) -> TraitDefinition {
    leg(
        id,
        Condition::Kv(KvQuery {
            path: MEMBER_PATH.to_string(),
            regex: Some(regex.to_string()),
            ..Default::default()
        }),
    )
}

fn member_exact(id: &str, value: &str) -> TraitDefinition {
    leg(
        id,
        Condition::Kv(KvQuery {
            path: MEMBER_PATH.to_string(),
            exact: Some(value.to_string()),
            ..Default::default()
        }),
    )
}

fn hostile(legs: &[&str]) -> CompositeTrait {
    CompositeTrait {
        id: "t::stage".to_string(),
        desc: "stage".to_string(),
        conf: 0.93,
        crit: crate::types::Criticality::Hostile,
        r#for: vec![FileType::Zip],
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        all: Some(
            legs.iter()
                .map(|id| Condition::Trait {
                    id: (*id).to_string(),
                })
                .collect(),
        ),
        defined_in: PathBuf::from("t.yml"),
        ..Default::default()
    }
}

/// A hostile composite may not be built from two `archive.members[*].path`
/// regexes that one member can satisfy. Containment is not the bar and is
/// not tested for: these two extension sets each carry a spelling the
/// other lacks, so neither implies the other -- but one `.xlsx` member
/// answers both legs, and a conviction resting on that member has one
/// piece of evidence, not two.
#[test]
fn two_overlapping_member_path_regexes_cannot_convict() {
    let traits = vec![
        member_regex("t::xlsx-or-xls", r"(?i)\.(xlsx|xls)$"),
        member_regex("t::xlsm-or-xlsx", r"(?i)\.(xlsm|xlsx)$"),
    ];
    let found =
        find_one_fact_convictions(&traits, &[hostile(&["t::xlsx-or-xls", "t::xlsm-or-xlsx"])]);
    assert_eq!(found.len(), 1, "expected one finding, got {found:?}");
    assert_eq!(found[0].0, "t::stage");
    assert_eq!(found[0].1, "t::xlsx-or-xls");
    assert_eq!(found[0].2, "t::xlsm-or-xlsx");
    assert_eq!(found[0].3, MEMBER_PATH, "the shared fact is named");
}

/// The same rule with the spellings swapped: an `exact:` member path and a
/// regex that accepts it. The `exact` leg names one file, the regex leg
/// names a family containing it, and the archive member that satisfies the
/// first always satisfies the second -- one observation, two legs.
#[test]
fn an_exact_member_path_and_an_overlapping_regex_cannot_convict() {
    let traits = vec![
        member_exact("t::named", "docs/Invoice-90233.xlsx"),
        member_regex("t::any-spreadsheet", r"(?i)\.(xlsx|xlsm|xlsb|xls)$"),
    ];
    let found = find_one_fact_convictions(&traits, &[hostile(&["t::named", "t::any-spreadsheet"])]);
    assert_eq!(found.len(), 1, "expected one finding, got {found:?}");
    assert_eq!(found[0].1, "t::named");
    assert_eq!(found[0].2, "t::any-spreadsheet");
}

/// The shape the pasted rule had: one leg inside the other's alternation.
#[test]
fn a_leg_inside_another_legs_alternation_cannot_convict() {
    let traits = vec![
        member_regex("t::xlsx", r"(?i)\.xlsx$"),
        member_regex("t::spreadsheet", r"(?i)\.(xlsx|xlsm|xlsb|xls)$"),
    ];
    assert_eq!(
        find_one_fact_convictions(&traits, &[hostile(&["t::xlsx", "t::spreadsheet"])]).len(),
        1
    );
}

/// Requiring two *different* members is a real layout fingerprint, and no
/// single path is both a root `setup.exe` and a binary under `Updates/`.
/// A check that keyed on the shared fact alone would delete this.
#[test]
fn legs_no_single_member_can_satisfy_are_silent() {
    let traits = vec![
        member_regex("t::setup", r"(?i)^setup\.exe$"),
        member_regex("t::staged", r"(?i)(^|/)updates?/[^/]+\.(exe|dll)$"),
    ];
    assert!(find_one_fact_convictions(&traits, &[hostile(&["t::setup", "t::staged"])]).is_empty());
}

/// Two staging directories are still two members, however alike the
/// patterns look.
#[test]
fn disjoint_directory_legs_are_silent() {
    let traits = vec![
        member_regex("t::updates", r"(?i)(^|/)updates/[^/]+\.(exe|dll)$"),
        member_regex("t::library", r"(?i)(^|/)library/[^/]+\.(exe|dll)$"),
    ];
    assert!(
        find_one_fact_convictions(&traits, &[hostile(&["t::updates", "t::library"])]).is_empty()
    );
}

/// Disjoint extension sets: no value ends in both `.xls` and `.docm`.
#[test]
fn disjoint_extension_sets_are_silent() {
    let traits = vec![
        member_regex("t::spreadsheet", r"(?i)\.(xlsx|xls)$"),
        member_regex("t::macro-doc", r"(?i)\.(docm|dotm)$"),
    ];
    assert!(
        find_one_fact_convictions(&traits, &[hostile(&["t::spreadsheet", "t::macro-doc"])])
            .is_empty()
    );
}

/// Different facts are different evidence even when the patterns match:
/// a basename is not an archive member path.
#[test]
fn different_facts_are_never_compared() {
    let traits = vec![
        leg(
            "t::basename",
            Condition::Path(PathQuery {
                regex: Some(r"(?i)\.xlsx$".to_string()),
                ..Default::default()
            }),
        ),
        member_regex("t::member", r"(?i)\.xlsx$"),
    ];
    assert!(
        find_one_fact_convictions(&traits, &[hostile(&["t::basename", "t::member"])]).is_empty()
    );
}

/// A count floor on one leg is a claim the other is not making -- "three
/// spreadsheet members" is not "an xlsx member" -- so the two are not the
/// same evidence however their matchers overlap.
#[test]
fn a_leg_with_its_own_count_floor_is_silent() {
    let mut many = member_regex("t::spreadsheet", r"(?i)\.(xlsx|xlsm|xlsb|xls)$");
    many.count_min = Some(3);
    let traits = vec![member_regex("t::xlsx", r"(?i)\.xlsx$"), many];
    assert!(
        find_one_fact_convictions(&traits, &[hostile(&["t::xlsx", "t::spreadsheet"])]).is_empty()
    );
}

/// Below `suspicious` two spellings of one fact are untidy rather than
/// manufactured evidence, and the check stays out of it.
#[test]
fn a_notable_rule_is_out_of_scope() {
    let traits = vec![
        member_regex("t::xlsx", r"(?i)\.xlsx$"),
        member_regex("t::spreadsheet", r"(?i)\.(xlsx|xlsm|xlsb|xls)$"),
    ];
    let mut rule = hostile(&["t::xlsx", "t::spreadsheet"]);
    rule.crit = crate::types::Criticality::Notable;
    assert!(find_one_fact_convictions(&traits, &[rule]).is_empty());
}

/// `any:` legs are alternatives, so sharing a fact is how they are meant
/// to be written. Only `all:` claims independent evidence.
#[test]
fn an_any_clause_is_out_of_scope() {
    let traits = vec![
        member_regex("t::xlsx", r"(?i)\.xlsx$"),
        member_regex("t::spreadsheet", r"(?i)\.(xlsx|xlsm|xlsb|xls)$"),
    ];
    let mut rule = hostile(&[]);
    rule.all = None;
    rule.any = Some(
        ["t::xlsx", "t::spreadsheet"]
            .iter()
            .map(|id| Condition::Trait {
                id: (*id).to_string(),
            })
            .collect(),
    );
    assert!(find_one_fact_convictions(&traits, &[rule]).is_empty());
}

/// Case folding widens the value set, so a case-insensitive leg and a
/// case-sensitive one still meet on the spelling they share.
#[test]
fn case_folding_does_not_hide_the_shared_value() {
    let traits = vec![
        member_exact("t::named", "payload.xlsx"),
        member_regex("t::any-xlsx", r"\.xlsx$"),
    ];
    assert_eq!(
        find_one_fact_convictions(&traits, &[hostile(&["t::named", "t::any-xlsx"])]).len(),
        1
    );
}
