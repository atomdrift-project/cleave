use crate::capabilities::validation::patterns::find_string_literal_should_use_text;
use crate::composite_rules::{Arch, Condition, FileType, LiteralQuery, Platform, TraitDefinition};
use std::path::PathBuf;

fn source_trait(id: &str, condition: Condition, file_type: FileType) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
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
        r#for: vec![file_type],
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
fn flags_code_structure_pattern() {
    let t = source_trait(
        "t::literal-eval",
        Condition::Literal(LiteralQuery {
            kind: None,
            exact: None,
            substr: Some("eval(".to_string()),
            regex: None,
            word: None,
            value: None,
            radix: None,
            case_insensitive: false,
            exclude_docstrings: false,
            is_check: None,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        }),
        FileType::Python,
    );
    let mut warnings = Vec::new();
    find_string_literal_should_use_text(&[t], &mut warnings);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("type: text"));
}
