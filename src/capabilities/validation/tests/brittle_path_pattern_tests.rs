use crate::capabilities::validation::patterns::find_brittle_path_patterns;
use crate::composite_rules::{Arch, Condition, FileType, PathQuery, Platform, TraitDefinition};
use std::path::PathBuf;

fn make_trait(condition: Condition) -> TraitDefinition {
    TraitDefinition {
        id: "test/path-brittle".to_string(),
        desc: "test".to_string(),
        conf: 0.8,
        crit: crate::types::Criticality::Notable,
        mbc: None,
        attack: None,
        r#if: condition,
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

fn path_substr(value: &str) -> Condition {
    Condition::Path(PathQuery {
        exact: None,
        substr: Some(value.to_string()),
        regex: None,
        case_insensitive: false,
        is_check: None,
        basename: false,
        dirname: false,
    })
}

fn path_regex(value: &str) -> Condition {
    Condition::Path(PathQuery {
        exact: None,
        substr: None,
        regex: Some(value.to_string()),
        case_insensitive: false,
        is_check: None,
        basename: false,
        dirname: false,
    })
}

fn warnings_for(condition: Condition) -> Vec<String> {
    let mut warnings = Vec::new();
    find_brittle_path_patterns(&[make_trait(condition)], &mut warnings);
    warnings
}

#[test]
fn flags_bang_in_substr() {
    let w = warnings_for(path_substr("foo!bar"));
    assert_eq!(w.len(), 1);
    assert!(w[0].contains("contains '!'"), "{}", w[0]);
}

#[test]
fn flags_too_many_slashes() {
    let w = warnings_for(path_substr("usr/local/bin/thing"));
    assert_eq!(w.len(), 1);
    assert!(w[0].contains("'/' separators"), "{}", w[0]);
}

#[test]
fn allows_two_slashes() {
    assert!(warnings_for(path_substr("usr/bin/env")).is_empty());
}

#[test]
fn flags_overlong_pattern() {
    let long = "a".repeat(65);
    let w = warnings_for(path_regex(&long));
    assert_eq!(w.len(), 1);
    assert!(w[0].contains("chars long"), "{}", w[0]);
}

#[test]
fn allows_exactly_64_chars() {
    let exact_len = "a".repeat(64);
    assert!(warnings_for(path_substr(&exact_len)).is_empty());
}

#[test]
fn checks_regex_field_too() {
    let w = warnings_for(path_regex(r"a/b/c/d"));
    assert_eq!(w.len(), 1);
    assert!(w[0].contains("regex"), "{}", w[0]);
}

#[test]
fn ignores_exact_full_paths() {
    // `exact` is a precise full-path match — slashes are legitimate there.
    let cond = Condition::Path(PathQuery {
        exact: Some("/usr/local/bin/evil".to_string()),
        substr: None,
        regex: None,
        case_insensitive: false,
        is_check: None,
        basename: false,
        dirname: false,
    });
    assert!(warnings_for(cond).is_empty());
}

#[test]
fn allows_shallow_short_substr() {
    assert!(warnings_for(path_substr(".bashrc")).is_empty());
}
