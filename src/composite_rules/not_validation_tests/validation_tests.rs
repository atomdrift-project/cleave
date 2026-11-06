use crate::composite_rules::{
    Arch, Condition, RawQuery, SymbolQuery, TextQuery, TraitDefinition,
    condition::{NotException, NotExceptionStructured},
};
use crate::types::Criticality;

fn create_test_trait(condition: Condition, not: Option<Vec<NotException>>) -> TraitDefinition {
    TraitDefinition {
        id: "test".to_string(),
        desc: "Test trait".to_string(),
        conf: 0.8,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![],
        arch: vec![Arch::All],
        r#for: vec![],
        for_from_groups: false,
        r#if: condition,
        not,
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::new(),
        precision: None,
        ..Default::default()
    }
}

#[test]
fn test_exact_match_should_use_unless() {
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
        platforms: None,
    });

    let not = vec![NotException::Shorthand("test".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_some());
    assert!(
        warning
            .unwrap()
            .contains("consider using 'unless:' instead")
    );
}

#[test]
fn test_substr_with_valid_not_exception() {
    // substr: "test" should match strings like "testing", "test123", etc.
    // not: ["testing"] should work because "testing" contains "test"
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: Some("test".to_string()),
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
        platforms: None,
    });

    let not = vec![NotException::Shorthand("testing".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(
        warning.is_none(),
        "Should not warn for valid substr/not combination"
    );
}

#[test]
fn test_substr_with_invalid_not_exception() {
    // substr: "test" won't match "hurl", so not: ["hurl"] will never apply
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: Some("test".to_string()),
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
        platforms: None,
    });

    let not = vec![NotException::Shorthand("hurl".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_some());
    assert!(
        warning
            .as_ref()
            .unwrap()
            .contains("does not contain the search substr")
    );
    assert!(warning.as_ref().unwrap().contains("hurl"));
    assert!(warning.as_ref().unwrap().contains("test"));
}

#[test]
fn test_substr_with_exact_not_exception_valid() {
    // substr: "test" should match "testing"
    // not: {exact: "testing"} should work
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: Some("test".to_string()),
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
        platforms: None,
    });

    let not = vec![NotException::Structured(NotExceptionStructured {
        exact: Some("testing".to_string()),
        substr: None,
        regex: None,
        lowered_substr: None,
    })];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_none());
}

#[test]
fn test_substr_with_exact_not_exception_invalid() {
    // substr: "test" won't match strings containing "hurl"
    // not: {exact: "hurl"} will never apply
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: Some("test".to_string()),
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
        platforms: None,
    });

    let not = vec![NotException::Structured(NotExceptionStructured {
        exact: Some("hurl".to_string()),
        substr: None,
        regex: None,
        lowered_substr: None,
    })];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("exact"));
    assert!(warning.as_ref().unwrap().contains("hurl"));
}

#[test]
fn test_substr_with_overlapping_substr_not_exception() {
    // substr: "test" and not: {substr: "testing"}
    // "testing" contains "test", so this should be valid
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: Some("test".to_string()),
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
        platforms: None,
    });

    let not = vec![NotException::Structured(NotExceptionStructured {
        exact: None,
        substr: Some("testing".to_string()),
        regex: None,
        lowered_substr: None,
    })];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_none());
}

#[test]
fn test_substr_with_non_overlapping_substr_not_exception() {
    // substr: "test" and not: {substr: "hurl"}
    // No overlap, so the not will never apply
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: Some("test".to_string()),
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
        platforms: None,
    });

    let not = vec![NotException::Structured(NotExceptionStructured {
        exact: None,
        substr: Some("hurl".to_string()),
        regex: None,
        lowered_substr: None,
    })];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("no overlap"));
}

#[test]
fn test_substr_case_insensitive() {
    // substr: "test" (case insensitive) should match "TESTING"
    // not: ["TESTING"] should work
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: Some("test".to_string()),
        regex: None,
        word: None,
        case_insensitive: true,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
        platforms: None,
    });

    let not = vec![NotException::Shorthand("TESTING".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_none());
}

#[test]
fn test_regex_with_matching_not_exception() {
    // regex: "c.?rl" matches "crl" and "curl"
    // not: ["curl"] should work
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: None,
        regex: Some("c.?rl".to_string()),
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
        platforms: None,
    });

    let not = vec![NotException::Shorthand("curl".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_none());
}

#[test]
fn test_regex_with_non_matching_not_exception_curl() {
    // regex: "c.?rl" matches "crl" and "curl" but not "hurl"
    // not: ["hurl"] will never apply
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: None,
        regex: Some("c.?rl".to_string()),
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
        platforms: None,
    });

    let not = vec![NotException::Shorthand("hurl".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("does not match"));
    assert!(warning.as_ref().unwrap().contains("hurl"));
    assert!(warning.as_ref().unwrap().contains("c.?rl"));
}

#[test]
fn test_regex_with_non_matching_not_exception() {
    // regex: "^test$" only matches exactly "test"
    // not: ["testing"] will never apply because "testing" doesn't match "^test$"
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: None,
        regex: Some("^test$".to_string()),
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
        platforms: None,
    });

    let not = vec![NotException::Shorthand("testing".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("does not match"));
    assert!(warning.as_ref().unwrap().contains("testing"));
    assert!(warning.as_ref().unwrap().contains("^test$"));
}

#[test]
fn test_content_substr_with_not_should_error() {
    // content + substr + not should be an error - behavior is unclear
    let cond = Condition::Raw(RawQuery {
        length_min: None,
        length_max: None,
        exact: None,
        substr: Some("test".to_string()),
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
    });

    let not = vec![NotException::Shorthand("testing".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("content/substr"));
    assert!(warning.as_ref().unwrap().contains("behavior is unclear"));
}

#[test]
fn test_content_exact_with_not_should_error() {
    // content + exact + not should be an error - doesn't make sense
    let cond = Condition::Raw(RawQuery {
        length_min: None,
        length_max: None,
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
    });

    let not = vec![NotException::Shorthand("test".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("content/exact"));
    assert!(warning.as_ref().unwrap().contains("doesn't make sense"));
}

#[test]
fn test_content_regex_with_not_is_ok() {
    // content + regex + not should work (no warning)
    let cond = Condition::Raw(RawQuery {
        length_min: None,
        length_max: None,
        exact: None,
        substr: None,
        regex: Some("test.*".to_string()),
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        not: None,
    });

    let not = vec![NotException::Shorthand("testing".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_none());
}

#[test]
fn test_symbol_exact_with_not_should_warn() {
    // Symbol exact match with not: should suggest using unless:
    let cond = Condition::Symbol(SymbolQuery {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        kind: None,
        arg: None,
        args: None,
        alias: None,
        not: None,
        module_level: false,
        receiver: None,
    });

    let not = vec![NotException::Shorthand("test".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("symbol exact"));
    assert!(warning.as_ref().unwrap().contains("unless"));
}

#[test]
fn test_symbol_substr_with_valid_not() {
    // Symbol substr with not: should work if exception contains substr
    let cond = Condition::Symbol(SymbolQuery {
        exact: None,
        substr: Some("test".to_string()),
        regex: None,
        platforms: None,
        is_check: None,
        kind: None,
        arg: None,
        args: None,
        alias: None,
        not: None,
        module_level: false,
        receiver: None,
    });

    let not = vec![NotException::Shorthand("testing".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_none());
}

#[test]
fn test_symbol_substr_with_invalid_not() {
    // Symbol substr with not: should error if exception doesn't contain substr
    let cond = Condition::Symbol(SymbolQuery {
        exact: None,
        substr: Some("test".to_string()),
        regex: None,
        platforms: None,
        is_check: None,
        kind: None,
        arg: None,
        args: None,
        alias: None,
        not: None,
        module_level: false,
        receiver: None,
    });

    let not = vec![NotException::Shorthand("hurl".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("does not contain"));
    assert!(warning.as_ref().unwrap().contains("hurl"));
    assert!(warning.as_ref().unwrap().contains("test"));
}

#[test]
fn test_symbol_regex_with_valid_not() {
    // Symbol regex with not: should work if exception matches regex
    let cond = Condition::Symbol(SymbolQuery {
        exact: None,
        substr: None,
        regex: Some("c.?rl".to_string()),
        platforms: None,
        is_check: None,
        kind: None,
        arg: None,
        args: None,
        alias: None,
        not: None,
        module_level: false,
        receiver: None,
    });

    let not = vec![NotException::Shorthand("curl".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_none());
}

#[test]
fn test_symbol_regex_with_invalid_not() {
    // Symbol regex with not: should error if exception doesn't match regex
    let cond = Condition::Symbol(SymbolQuery {
        exact: None,
        substr: None,
        regex: Some("c.?rl".to_string()),
        platforms: None,
        is_check: None,
        kind: None,
        arg: None,
        args: None,
        alias: None,
        not: None,
        module_level: false,
        receiver: None,
    });

    let not = vec![NotException::Shorthand("hurl".to_string())];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("does not match"));
    assert!(warning.as_ref().unwrap().contains("hurl"));
    assert!(warning.as_ref().unwrap().contains("c.?rl"));
}
