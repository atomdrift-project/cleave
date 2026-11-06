use super::*;
use crate::composite_rules::FileType;

#[test]
fn syscall_is_binary_only() {
    let cond = Condition::Syscall {
        name: Some(vec!["connect".to_string()]),
        number: None,
        arch: None,
        args: Vec::new(),
    };
    assert!(cond.can_match_file_type(&FileType::Pe));
    assert!(cond.can_match_file_type(&FileType::Elf));
    assert!(cond.can_match_file_type(&FileType::Macho));
    assert!(!cond.can_match_file_type(&FileType::JavaScript));
    assert!(!cond.can_match_file_type(&FileType::Go));
    assert!(!cond.can_match_file_type(&FileType::Python));
}

#[test]
fn section_is_binary_only() {
    let cond = Condition::Section(SectionQuery {
        exact: Some(".text".to_string()),
        ..SectionQuery::default()
    });
    assert!(cond.can_match_file_type(&FileType::Pe));
    assert!(!cond.can_match_file_type(&FileType::JavaScript));
    assert!(!cond.can_match_file_type(&FileType::Go));
}

#[test]
fn symbol_and_text_still_apply_to_source() {
    let symbol = Condition::Symbol(SymbolQuery {
        exact: Some("eval".to_string()),
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
    let text = Condition::Text(TextQuery {
        substr: Some("eval".to_string()),
        ..TextQuery::default()
    });
    assert!(symbol.can_match_file_type(&FileType::JavaScript));
    assert!(symbol.can_match_file_type(&FileType::Go));
    assert!(text.can_match_file_type(&FileType::JavaScript));
    assert!(text.can_match_file_type(&FileType::Pe));
}

#[test]
fn section_pinned_text_raw_hex_skip_source_but_keep_offset_only() {
    let text_section = Condition::Text(TextQuery {
        exact: Some("Microsoft".to_string()),
        section: Some(".rdata".to_string()),
        ..TextQuery::default()
    });
    let text_offset = Condition::Text(TextQuery {
        substr: Some("hello".to_string()),
        offset: Some(0),
        ..TextQuery::default()
    });
    let raw_section = Condition::Raw(RawQuery {
        substr: Some("MZ".to_string()),
        section: Some(".text".to_string()),
        ..RawQuery::default()
    });
    let hex_section = Condition::Hex(HexQuery {
        pattern: "4d5a".to_string(),
        section: Some(".text".to_string()),
        ..HexQuery::default()
    });
    assert!(!text_section.can_match_file_type(&FileType::JavaScript));
    assert!(!text_section.can_match_file_type(&FileType::Go));
    assert!(text_section.can_match_file_type(&FileType::Pe));
    assert!(text_offset.can_match_file_type(&FileType::JavaScript));
    assert!(text_offset.can_match_file_type(&FileType::Pe));
    assert!(!raw_section.can_match_file_type(&FileType::JavaScript));
    assert!(raw_section.can_match_file_type(&FileType::Pe));
    assert!(!hex_section.can_match_file_type(&FileType::Python));
    assert!(hex_section.can_match_file_type(&FileType::Elf));
}
