use crate::capabilities::validation::find_one_fact_convictions;
use crate::composite_rules::condition::KvQuery;
use crate::composite_rules::{
    Arch, CompositeTrait, Condition, FileType, Platform, TraitDefinition,
};
use std::path::PathBuf;

fn scalar_leg(id: &str, fact: &str, regex: &str) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "leg".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        r#if: Condition::Kv(KvQuery {
            path: fact.to_string(),
            regex: Some(regex.to_string()),
            ..Default::default()
        }),
        r#for: vec![FileType::PackageJson],
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        defined_in: PathBuf::from("t.yml"),
        ..Default::default()
    }
}

fn hostile(legs: &[&str]) -> CompositeTrait {
    CompositeTrait {
        id: "t::rule".to_string(),
        desc: "rule".to_string(),
        conf: 0.93,
        crit: crate::types::Criticality::Hostile,
        r#for: vec![FileType::PackageJson],
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

/// Two legs over one install script that match *different text* are two
/// observations, however reliably they co-occur. A rule pairing a URL with
/// a hex-encode call is doing what it says; only a check asking "does one
/// value satisfy both" would delete it.
#[test]
fn two_matchers_on_one_string_finding_different_text_are_silent() {
    let traits = vec![
        scalar_leg("t::url", "scripts.preinstall", r"https?://"),
        scalar_leg("t::xxd", "scripts.preinstall", r"\bxxd\b"),
    ];
    assert!(find_one_fact_convictions(&traits, &[hostile(&["t::url", "t::xxd"])]).is_empty());
}

/// The same fact, two spellings of one match: both legs can match the
/// literal text `curl `, so the second is restating the first.
#[test]
fn two_spellings_of_one_match_on_one_string_are_reported() {
    let traits = vec![
        scalar_leg("t::curl", "scripts.preinstall", r"curl\s"),
        scalar_leg("t::fetcher", "scripts.preinstall", r"(curl|wget)\s"),
    ];
    assert_eq!(
        find_one_fact_convictions(&traits, &[hostile(&["t::curl", "t::fetcher"])]).len(),
        1
    );
}

/// Two path properties that a single member can carry but that match
/// different parts of it -- a directory and an extension -- are still two
/// facts about that member, not one spelled twice.
#[test]
fn a_directory_leg_and_an_extension_leg_are_silent() {
    let traits = vec![
        scalar_leg("t::libdir", "archive.members[*].path", r"(^|/)lib/"),
        scalar_leg("t::dll", "archive.members[*].path", r"(?i)\.dll$"),
    ];
    assert!(find_one_fact_convictions(&traits, &[hostile(&["t::libdir", "t::dll"])]).is_empty());
}
