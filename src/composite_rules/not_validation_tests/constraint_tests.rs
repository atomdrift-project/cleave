use crate::composite_rules::{Arch, Condition, TextQuery, TraitDefinition};
use crate::types::Criticality;

#[test]
fn test_confidence_out_of_range_low() {
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

    let trait_def = TraitDefinition {
        id: "test".to_string(),
        desc: "Test trait".to_string(),
        conf: -0.5,
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

    let warning = trait_def.check_confidence();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("outside valid range"));
}

#[test]
fn test_confidence_out_of_range_high() {
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

    let trait_def = TraitDefinition {
        id: "test".to_string(),
        desc: "Test trait".to_string(),
        conf: 1.5,
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

    let warning = trait_def.check_confidence();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("outside valid range"));
}

#[test]
fn test_size_max_less_than_min() {
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
        size_min: Some(1000),
        size_max: Some(500), // max < min
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

    let warning = trait_def.check_size_constraints();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("size_max"));
    assert!(warning.as_ref().unwrap().contains("size_min"));
}

#[test]
fn test_count_max_less_than_min() {
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
        count_min: Some(10),
        count_max: Some(5), // max < min
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

    let warning = trait_def.check_count_constraints();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("count_max"));
    assert!(warning.as_ref().unwrap().contains("count_min"));
}

#[test]
fn test_per_kb_max_less_than_min() {
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
        per_kb_min: Some(10.0),
        per_kb_max: Some(5.0), // max < min
        entropy_min: None,
        entropy_max: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::new(),
        precision: None,
        ..Default::default()
    };

    let warning = trait_def.check_density_constraints();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("per_kb_max"));
    assert!(warning.as_ref().unwrap().contains("per_kb_min"));
}

#[test]
fn test_mutually_exclusive_match_types() {
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: Some("test".to_string()),
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

    let warning = cond.check_match_exclusivity();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("mutually exclusive"));
    assert!(warning.as_ref().unwrap().contains("exact"));
    assert!(warning.as_ref().unwrap().contains("substr"));
}

#[test]
fn test_valid_constraints() {
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

    assert!(cond.check_count_constraints().is_none());
    assert!(cond.check_density_constraints().is_none());
    assert!(cond.check_match_exclusivity().is_none());

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
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::new(),
        precision: None,
        ..Default::default()
    };

    assert!(trait_def.check_confidence().is_none());
    assert!(trait_def.check_size_constraints().is_none());
}
