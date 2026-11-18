use crate::capabilities::validation::taxonomy::{
    find_meta_missing_section_filter, find_wellknown_missing_section_filter,
    find_wellknown_missing_size_filter,
};
use crate::composite_rules::{Arch, Condition, FileType, Platform, TextQuery, TraitDefinition};
use crate::types::Criticality;
use std::collections::HashMap;
use std::path::PathBuf;

fn text_trait(id: &str, for_types: Vec<FileType>) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "test".to_string(),
        conf: 0.8,
        crit: crate::types::Criticality::Notable,
        mbc: None,
        attack: None,
        r#if: Condition::Text(TextQuery {
            encoding: None,
            length_min: None,
            length_max: None,
            exclude_html_comments: false,
            exclude_comments: false,
            exact: None,
            substr: Some("ProjectDiscovery".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        }),
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        r#for: for_types,
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
fn wellknown_section_filter_skips_mixed_binary_and_script_targets() {
    let mut traits = vec![text_trait(
        "well-known/tool/test::mixed",
        vec![FileType::Pe, FileType::Shell],
    )];
    traits[0].crit = Criticality::Suspicious;
    let mut sources = HashMap::new();
    sources.insert(
        "well-known/tool/test::mixed".to_string(),
        "./well-known/tool/test/traits.yaml".to_string(),
    );
    let result = find_wellknown_missing_section_filter(&traits, &sources);
    assert!(result.is_empty());
}

#[test]
fn wellknown_section_filter_flags_binary_only_targets() {
    let mut traits = vec![text_trait(
        "well-known/tool/test::binary",
        vec![FileType::Pe],
    )];
    traits[0].crit = Criticality::Suspicious;
    let mut sources = HashMap::new();
    sources.insert(
        "well-known/tool/test::binary".to_string(),
        "./well-known/tool/test/traits.yaml".to_string(),
    );
    let result = find_wellknown_missing_section_filter(&traits, &sources);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, "well-known/tool/test::binary");
}

#[test]
fn binary_bounds_follow_evidence_strength_and_matcher_type() -> anyhow::Result<()> {
    let mut rule = text_trait("well-known/tool/example::marker", vec![FileType::Pe]);
    let sources = HashMap::new();
    let issues = |rule: &TraitDefinition| {
        (
            find_wellknown_missing_size_filter(std::slice::from_ref(rule), &sources).len(),
            find_wellknown_missing_section_filter(std::slice::from_ref(rule), &sources).len(),
        )
    };
    assert_eq!(
        issues(&rule),
        (0, 0),
        "a supporting whole-file text observation"
    );
    rule.crit = Criticality::Suspicious;
    assert_eq!(issues(&rule), (1, 1), "a high-criticality fingerprint");
    rule.size_max = Some(100_000);
    assert_eq!(
        issues(&rule),
        (0, 1),
        "a size range cannot constrain location"
    );

    rule.crit = Criticality::Notable;
    rule.size_max = None;
    rule.r#if = crate::yaml::from_str("type: raw\nregex: 'header.{1,30}marker'")?;
    assert_eq!(
        issues(&rule),
        (1, 1),
        "a low-tier raw signature still needs bounds"
    );
    rule.r#if = crate::yaml::from_str("type: raw\nsubstr: LiteralMarker\noffset: 0")?;
    assert_eq!(
        issues(&rule),
        (0, 0),
        "a fixed byte marker at an explicit location"
    );
    Ok(())
}

#[test]
fn metadata_section_filter_requires_a_location_claim() {
    let traits = vec![
        text_trait(
            "metadata/file/string/command::vocabulary",
            vec![FileType::Pe],
        ),
        text_trait("metadata/binary/debug::pdb-name", vec![FileType::Pe]),
        text_trait(
            "metadata/binary/section/data::section-name",
            vec![FileType::Pe],
        ),
    ];
    let result = find_meta_missing_section_filter(&traits, &HashMap::new());
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, "metadata/binary/section/data::section-name");
}

#[test]
fn metadata_section_filter_skips_mixed_binary_and_script_targets() {
    let traits = vec![text_trait(
        "metadata/binary/test::mixed",
        vec![FileType::Pe, FileType::Shell],
    )];
    let mut sources = HashMap::new();
    sources.insert(
        "metadata/binary/test::mixed".to_string(),
        "./metadata/binary/test/traits.yaml".to_string(),
    );
    let result = find_meta_missing_section_filter(&traits, &sources);
    assert!(result.is_empty());
}
