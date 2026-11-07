use crate::composite_rules::{Arch, Condition, TextQuery, TraitDefinition};
use crate::types::Criticality;

#[test]
fn test_filtered_criticality_should_error() {
    // Criticality::Filtered is internal-only
    let cond = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exclude_comments: false,
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
        crit: Criticality::Filtered,
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

    let warning = trait_def.check_criticality();
    assert!(warning.is_some());
    assert!(warning.as_ref().unwrap().contains("filtered"));
    assert!(warning.as_ref().unwrap().contains("internal-only"));
    assert!(warning.as_ref().unwrap().contains("baseline"));
    assert!(warning.as_ref().unwrap().contains("notable"));
    assert!(warning.as_ref().unwrap().contains("suspicious"));
    assert!(warning.as_ref().unwrap().contains("hostile"));
}

#[test]
fn test_valid_criticality_levels() {
    // All valid criticality levels should pass
    for crit in &[
        Criticality::Baseline,
        Criticality::Notable,
        Criticality::Suspicious,
        Criticality::Hostile,
    ] {
        let cond = Condition::Text(TextQuery {
            encoding: None,
            length_min: None,
            length_max: None,
            exclude_html_comments: false,
            exclude_comments: false,
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
            crit: *crit,
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

        let warning = trait_def.check_criticality();
        assert!(warning.is_none(), "Criticality {:?} should be valid", crit);
    }
}
