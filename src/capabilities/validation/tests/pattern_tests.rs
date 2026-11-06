use super::super::patterns::{find_incompatible_regex_features, find_non_capturing_groups};
use crate::composite_rules::{Arch, Condition, FileType, Platform, RawQuery, TraitDefinition};
use std::path::PathBuf;

fn create_raw_regex_trait(id: &str, pattern: &str) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "test trait".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        mbc: None,
        attack: None,
        r#if: Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some(pattern.to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
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
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

#[test]
fn test_non_capturing_group_detected() {
    let traits = vec![create_raw_regex_trait("test-noncap", r"(?:foo|bar)baz")];
    let mut warnings = Vec::new();
    find_non_capturing_groups(&traits, &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("non-capturing group"));
    assert!(warnings[0].contains("test-noncap"));
}

#[test]
fn test_regular_group_no_warning() {
    let traits = vec![create_raw_regex_trait("test-cap", r"(foo|bar)baz")];
    let mut warnings = Vec::new();
    find_non_capturing_groups(&traits, &mut warnings);

    assert!(warnings.is_empty());
}

#[test]
fn test_no_group_no_warning() {
    let traits = vec![create_raw_regex_trait("test-nogroup", r"foobarbaz")];
    let mut warnings = Vec::new();
    find_non_capturing_groups(&traits, &mut warnings);

    assert!(warnings.is_empty());
}

#[test]
fn test_incompatible_lookaround_and_backref_detected() {
    // Every construct the linear-time engine can't compile must be flagged.
    for pat in [
        r"(?<!\w)base64", // negative lookbehind (the real base64-d-cmd bug)
        r"(?<=\s)rm -rf", // positive lookbehind
        r"(?=foo)bar",    // positive lookahead
        r"(?!x)y",        // negative lookahead
        r"(\w+)\s+\1",    // backreference
    ] {
        let traits = vec![create_raw_regex_trait("test-incompat", pat)];
        let mut errors = Vec::new();
        find_incompatible_regex_features(&traits, &mut errors);
        assert_eq!(
            errors.len(),
            1,
            "expected {pat:?} to be flagged, got {errors:?}"
        );
        assert!(errors[0].contains("test-incompat"));
    }
}

#[test]
fn test_compatible_patterns_not_flagged() {
    // Supported features — including named captures (which share the `(?<`
    // prefix with lookbehind) and byte escapes — must never be flagged.
    for pat in [
        r"\bbase64\s+-(d|D)", // the fixed base64-d-cmd
        r"(?:^|[^\w])base64", // lookbehind-free alternation
        r"(?<name>\w+)=\w+",  // named capture, NOT lookbehind
        r"(?P<n>\d+)",        // named capture, alt syntax
        r"[\x00-\xff]+",      // byte range (byte-mode only)
        r"(foo|bar)baz",      // plain group
    ] {
        let traits = vec![create_raw_regex_trait("test-ok", pat)];
        let mut errors = Vec::new();
        find_incompatible_regex_features(&traits, &mut errors);
        assert!(
            errors.is_empty(),
            "{pat:?} must not be flagged, got {errors:?}"
        );
    }
}
