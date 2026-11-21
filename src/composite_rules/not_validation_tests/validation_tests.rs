use crate::composite_rules::{
    Arch, Condition, RawQuery, SymbolQuery, TextQuery, TraitDefinition, condition::NotException,
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
        exclude_comments: false,
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

/// A content condition from its YAML-shaped JSON.
fn condition(json: serde_json::Value) -> Condition {
    serde_json::from_value(json).unwrap()
}

fn exception(json: serde_json::Value) -> NotException {
    serde_json::from_value(json).unwrap()
}

/// `check_not_field_usage` for `if: condition` with trait-level `not:`.
fn substr_warning(condition: serde_json::Value, not: serde_json::Value) -> Option<String> {
    create_test_trait(self::condition(condition), Some(vec![exception(not)]))
        .check_not_field_usage()
}

const NEVER_APPLIES: &str = "can never apply to substr";
const NEVER_FIRES: &str = "excludes every match of substr";

// A `substr:` match is the needle itself, so its `not:` judges only the
// needle: an exception describing the text around it never applies, and one
// that holds for the needle excludes every hit.

#[test]
fn test_substr_not_naming_surrounding_text_never_applies() {
    let text = serde_json::json!({"type": "text", "substr": "test"});
    for not in [
        serde_json::json!("testing"),
        serde_json::json!({"substr": "testing"}),
        serde_json::json!({"exact": "testing"}),
        serde_json::json!({"regex": "test\\s+suite"}),
        serde_json::json!("hurl"),
        serde_json::json!({"substr": "hurl"}),
    ] {
        let warning = substr_warning(text.clone(), not.clone()).unwrap_or_default();
        assert!(warning.contains(NEVER_APPLIES), "{not}: {warning}");
        assert!(warning.contains("'test'"), "{warning}");
    }
}

#[test]
fn test_substr_not_holding_for_the_needle_excludes_every_hit() {
    let text = serde_json::json!({"type": "text", "substr": "test"});
    for not in [
        serde_json::json!("test"),
        serde_json::json!("es"),
        serde_json::json!({"substr": "TEST"}),
        serde_json::json!({"exact": "test"}),
        serde_json::json!({"regex": "^test$"}),
    ] {
        let warning = substr_warning(text.clone(), not.clone()).unwrap_or_default();
        assert!(warning.contains(NEVER_FIRES), "{not}: {warning}");
    }
}

#[test]
fn test_case_insensitive_substr_not_that_tells_casings_apart_is_kept() {
    let text = serde_json::json!({"type": "text", "substr": "test", "case_insensitive": true});
    // Case-sensitive exceptions can exclude one casing of a hit and not another.
    assert_eq!(
        substr_warning(text.clone(), serde_json::json!({"exact": "TEST"})),
        None
    );
    assert_eq!(
        substr_warning(text.clone(), serde_json::json!({"regex": "^[a-z]+$"})),
        None
    );
    // Shorthand and `substr` exceptions ignore case, so they hold for every casing.
    let warning = substr_warning(text.clone(), serde_json::json!("TESTING")).unwrap();
    assert!(warning.contains(NEVER_APPLIES), "{warning}");
    let warning = substr_warning(text, serde_json::json!({"substr": "Test"})).unwrap();
    assert!(warning.contains(NEVER_FIRES), "{warning}");
}

#[test]
fn test_substr_not_is_checked_for_every_content_type() {
    for kind in ["text", "literal", "string_literal", "raw", "encoded"] {
        let warning = substr_warning(
            serde_json::json!({"type": kind, "substr": "test"}),
            serde_json::json!("testing"),
        )
        .unwrap_or_default();
        assert!(warning.contains(NEVER_APPLIES), "{kind}: {warning}");
    }
}

#[test]
fn test_condition_level_substr_not_is_checked() {
    let trait_def = create_test_trait(
        condition(serde_json::json!({
            "type": "text",
            "substr": "android.permission.BIND_DEVICE_ADMIN",
            "not": [{"regex": "[\\w-]+:node\\s*=\\s*[\"']remove(All)?[\"']"}],
        })),
        None,
    );
    let warning = trait_def.check_not_field_usage().unwrap_or_default();
    assert!(warning.contains(NEVER_APPLIES), "{warning}");
    assert!(warning.contains("(regex)"), "{warning}");
}

#[test]
fn test_substr_without_not_is_fine() {
    let trait_def = create_test_trait(
        condition(serde_json::json!({"type": "text", "substr": "test"})),
        None,
    );
    assert_eq!(trait_def.check_not_field_usage(), None);
}

#[test]
fn test_word_and_regex_not_keep_their_own_checks() {
    // `word:` matches are the word too, but this rule covers `substr:` only.
    assert_eq!(
        substr_warning(
            serde_json::json!({"type": "text", "word": "test"}),
            serde_json::json!("testing"),
        ),
        None
    );
    // A regex condition's `not:` is still checked against the regex.
    let warning = substr_warning(
        serde_json::json!({"type": "text", "regex": "^test$"}),
        serde_json::json!("hurl"),
    )
    .unwrap_or_default();
    assert!(
        warning.contains("does not match the search regex"),
        "{warning}"
    );
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
        exclude_comments: false,
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
        exclude_comments: false,
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
        exclude_comments: false,
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
    // A not: equal to the needle is live: it excludes every match
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

    let not = vec![NotException::Structured(
        crate::composite_rules::condition::NotExceptionStructured {
            exact: None,
            substr: None,
            regex: Some("^test$".to_string()),
            lowered_substr: None,
        },
    )];
    let trait_def = create_test_trait(cond, Some(not));

    let warning = trait_def.check_not_field_usage();
    assert!(warning.is_some_and(|w| w.contains("can never fire")));
}

#[test]
fn test_symbol_substr_with_invalid_not() {
    // A symbol substr's not: judges only the needle; `hurl` never applies
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
    let warning = warning.unwrap();
    assert!(warning.contains("can never apply"), "{warning}");
    assert!(
        warning.contains("hurl") && warning.contains("test"),
        "{warning}"
    );
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
