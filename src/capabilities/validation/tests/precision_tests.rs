use crate::capabilities::precision::calculate_trait_precision;
use crate::composite_rules::{Arch, Condition, FileType, Platform, RawQuery, TraitDefinition};
use std::path::PathBuf;

fn create_minimal_trait(condition: Condition) -> TraitDefinition {
    TraitDefinition {
        id: "test/precision".to_string(),
        desc: "test".to_string(),
        conf: 1.0,
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

#[test]
fn test_precision_count_min_scored() {
    let mut trait_def = create_minimal_trait(Condition::Raw(RawQuery {
        length_min: None,
        length_max: None,
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        not: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    }));
    let base = calculate_trait_precision(&trait_def);

    trait_def.count_min = Some(3);
    let with_count_min = calculate_trait_precision(&trait_def);

    assert!(
        with_count_min > base,
        "count_min should add precision: base={}, with_count_min={}",
        base,
        with_count_min
    );
    let unit = crate::capabilities::precision::PARAM_UNIT;
    assert!((with_count_min - base - unit).abs() < 0.01);
}

#[test]
fn test_precision_density_scored() {
    let mut trait_def = create_minimal_trait(Condition::Raw(RawQuery {
        length_min: None,
        length_max: None,
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        not: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    }));
    let base = calculate_trait_precision(&trait_def);

    trait_def.per_kb_min = Some(1.0);
    trait_def.per_kb_max = Some(10.0);
    let with_density = calculate_trait_precision(&trait_def);

    assert!(
        with_density > base,
        "density constraints should add precision: base={}, with_density={}",
        base,
        with_density
    );
    let unit = crate::capabilities::precision::PARAM_UNIT;
    assert!((with_density - base - 2.0 * unit).abs() < 0.01);
}
