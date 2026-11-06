use crate::composite_rules::condition::{NotException, NotExceptionStructured};
use crate::composite_rules::{Arch, Condition, SymbolQuery, TextQuery, TraitDefinition};
use crate::types::Criticality;

#[test]
fn test_empty_string_pattern() {
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: Some("".to_string()),
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

    let warning = cond.check_empty_patterns();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("empty pattern"));
}

#[test]
fn test_whitespace_only_pattern() {
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: Some("   ".to_string()),
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

    let warning = cond.check_empty_patterns();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("whitespace-only"));
}

#[test]
fn test_short_substr_pattern() {
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: Some("a".to_string()),
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

    let warning = cond.check_short_patterns();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("very short"));
}

#[test]
fn test_short_word_pattern() {
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: None,
        regex: None,
        word: Some("x".to_string()),
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

    let warning = cond.check_short_patterns();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("very short"));
}

#[test]
fn test_literal_regex() {
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: None,
        regex: Some("literalstring".to_string()),
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

    let warning = cond.check_literal_regex();
    assert!(warning.is_some());
    assert!(
        warning
            .as_ref()
            .unwrap()
            .contains("no regex metacharacters")
    );
}

#[test]
fn test_regex_with_metacharacters_is_valid() {
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: None,
        regex: Some("test.*pattern".to_string()),
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

    let warning = cond.check_literal_regex();
    assert!(warning.is_none());
}

#[test]
fn test_case_insensitive_on_numeric_pattern() {
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: Some("12345".to_string()),
        substr: None,
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

    let warning = cond.check_case_insensitive_on_non_alpha();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("contains no letters"));
}

#[test]
fn test_case_insensitive_on_alpha_pattern() {
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: Some("test".to_string()),
        substr: None,
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

    let warning = cond.check_case_insensitive_on_non_alpha();
    assert!(warning.is_none());
}

#[test]
fn test_count_min_zero() {
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

    let trait_def = TraitDefinition {
        id: "test-trait".to_string(),
        desc: "Test trait".to_string(),
        conf: 0.8,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![],
        arch: vec![Arch::All],
        r#for: vec![],
        for_from_groups: false,
        r#if: cond,
        size_min: None,
        size_max: None,
        count_min: Some(0), // Invalid: count_min should not be 0
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::new(),
        precision: None,
        ..Default::default()
    };

    let warning = trait_def.check_count_min_value();
    assert!(warning.is_some());
    assert!(
        warning.as_ref().unwrap().contains("count_min: 0")
            || warning.as_ref().unwrap().contains("count_min of 0")
    );
}

#[test]
fn test_count_min_nonzero() {
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

    let warning = cond.check_count_min_value();
    assert!(warning.is_none());
}

#[test]
fn test_empty_description() {
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

    let trait_def = TraitDefinition {
        id: "test".to_string(),
        desc: "".to_string(),
        conf: 0.8,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![],
        arch: vec![Arch::All],
        r#for: vec![],
        for_from_groups: false,
        r#if: cond,
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::new(),
        precision: None,
        ..Default::default()
    };

    let warning = trait_def.check_description_quality();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("empty"));
}

#[test]
fn test_placeholder_words_allowed_in_descriptions() {
    // Placeholder words are now allowed since traits may legitimately
    // detect placeholder text in manifests
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

    let trait_def = TraitDefinition {
        id: "test".to_string(),
        desc: "Manifest contains placeholder author name".to_string(),
        conf: 0.8,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![],
        arch: vec![Arch::All],
        r#for: vec![],
        for_from_groups: false,
        r#if: cond,
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::new(),
        precision: None,
        ..Default::default()
    };

    let warning = trait_def.check_description_quality();
    assert!(
        warning.is_none(),
        "Descriptions mentioning placeholders should be valid"
    );
}

#[test]
fn test_short_description() {
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

    let trait_def = TraitDefinition {
        id: "test".to_string(),
        desc: "ok".to_string(),
        conf: 0.8,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![],
        arch: vec![Arch::All],
        r#for: vec![],
        for_from_groups: false,
        r#if: cond,
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::new(),
        precision: None,
        ..Default::default()
    };

    let warning = trait_def.check_description_quality();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("too short"));
}

#[test]
fn test_valid_description() {
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

    let trait_def = TraitDefinition {
        id: "test".to_string(),
        desc: "This is a valid description".to_string(),
        conf: 0.8,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![],
        arch: vec![Arch::All],
        r#for: vec![],
        for_from_groups: false,
        r#if: cond,
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::new(),
        precision: None,
        ..Default::default()
    };

    let warning = trait_def.check_description_quality();
    assert!(warning.is_none());
}

#[test]
fn test_empty_not_array() {
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
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
        platforms: None,
    });

    let trait_def = TraitDefinition {
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
        r#if: cond,
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        not: Some(vec![]),
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::new(),
        precision: None,
        ..Default::default()
    };

    let warning = trait_def.check_empty_not_array();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("not: array is empty"));
}

#[test]
fn test_empty_unless_array() {
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

    let trait_def = TraitDefinition {
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
        r#if: cond,
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        not: None,
        unless: Some(vec![]),
        downgrade: None,
        defined_in: std::path::PathBuf::new(),
        precision: None,
        ..Default::default()
    };

    let warning = trait_def.check_empty_unless_array();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("unless: array is empty"));
}

#[test]
fn test_symbol_regex_word_boundary_simple() {
    let cond = Condition::Symbol(SymbolQuery {
        exact: None,
        substr: None,
        regex: Some(r"\bsetsid\b".to_string()),
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

    let warning = cond.check_symbol_regex_whitespace();
    assert!(warning.is_some());
    let msg = warning.unwrap();
    assert!(msg.contains("exact"));
    assert!(msg.contains("setsid"));
}

#[test]
fn test_symbol_regex_word_boundary_complex() {
    // \b with alternation - not a simple word, but still a bad pattern for symbols
    let cond = Condition::Symbol(SymbolQuery {
        exact: None,
        substr: None,
        regex: Some(r"\b(fork|exec)\b".to_string()),
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

    let warning = cond.check_symbol_regex_whitespace();
    assert!(warning.is_some());
    let msg = warning.unwrap();
    assert!(msg.contains(r"\b"));
}

#[test]
fn test_symbol_regex_whitespace_space() {
    let cond = Condition::Symbol(SymbolQuery {
        exact: None,
        substr: None,
        regex: Some("some function".to_string()),
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

    let warning = cond.check_symbol_regex_whitespace();
    assert!(warning.is_some());
    assert!(warning.unwrap().contains("whitespace"));
}

#[test]
fn test_symbol_regex_whitespace_class() {
    let cond = Condition::Symbol(SymbolQuery {
        exact: None,
        substr: None,
        regex: Some(r"foo\sbar".to_string()),
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

    let warning = cond.check_symbol_regex_whitespace();
    assert!(warning.is_some());
    assert!(warning.unwrap().contains("whitespace"));
}

#[test]
fn test_symbol_regex_valid_no_warning() {
    let cond = Condition::Symbol(SymbolQuery {
        exact: None,
        substr: None,
        regex: Some(r"dlopen|dlsym".to_string()),
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

    let warning = cond.check_symbol_regex_whitespace();
    assert!(warning.is_none());
}

#[test]
fn test_symbol_regex_valid_substr_no_warning() {
    // Non-symbol condition should not trigger
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: None,
        regex: Some(r"\bsetsid\b".to_string()),
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

    let warning = cond.check_symbol_regex_whitespace();
    assert!(warning.is_none());
}

// `not: exact:` negates against the regex's matched span and must be
// case-SENSITIVE ("exact string equality"). The powershell-case-randomized
// trait matches any casing of `powershell`, then excludes the canonical
// spellings via `not: exact:`. A case-insensitive `exact` would also exclude
// the respelled `pOwErShElL`, silently killing the whole technique.
#[test]
fn test_exact_not_exception_is_case_sensitive() {
    let canonical = NotException::Structured(NotExceptionStructured {
        exact: Some("PowerShell".to_string()),
        substr: None,
        regex: None,
        lowered_substr: None,
    });
    // The canonical casing it names is suppressed.
    assert!(
        canonical.matches("PowerShell"),
        "exact: PowerShell must match the identical span"
    );
    // A different casing (the evasion) is NOT suppressed.
    assert!(
        !canonical.matches("pOwErShElL"),
        "exact: PowerShell must NOT match a case-randomized span"
    );
    assert!(
        !canonical.matches("POWERSHELL"),
        "exact: PowerShell must NOT match an all-caps span"
    );
}
