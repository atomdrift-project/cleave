use crate::capabilities::validation::patterns::find_ast_function_call_should_use_symbol;
use crate::composite_rules::{Arch, Condition, FileType, Platform, TextQuery, TraitDefinition};
use std::path::PathBuf;

fn make_trait(id: &str, condition: Condition, for_types: Vec<FileType>) -> TraitDefinition {
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

fn text_substr(value: &str) -> Condition {
    Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exclude_comments: false,
        exact: None,
        substr: Some(value.to_string()),
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
    })
}

fn text_regex(value: &str) -> Condition {
    Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exclude_comments: false,
        exact: None,
        substr: None,
        regex: Some(value.to_string()),
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
    })
}

#[test]
fn flags_substr_eval_paren_on_javascript() {
    let t = make_trait("t::eval", text_substr("eval("), vec![FileType::JavaScript]);
    let mut warnings = Vec::new();
    find_ast_function_call_should_use_symbol(&[t], &mut warnings);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("type: symbol"));
    assert!(warnings[0].contains("exact: eval"));
}

#[test]
fn flags_regex_with_leading_boundary_on_python() {
    let t = make_trait(
        "t::eval-py",
        text_regex(r"(^|[^\w$])eval\s*\("),
        vec![FileType::Python],
    );
    let mut warnings = Vec::new();
    find_ast_function_call_should_use_symbol(&[t], &mut warnings);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("exact: eval"));
}

#[test]
fn flags_when_all_for_types_are_ast_sources() {
    let t = make_trait(
        "t::eval-multi",
        text_substr("eval("),
        vec![FileType::JavaScript, FileType::TypeScript, FileType::Python],
    );
    let mut warnings = Vec::new();
    find_ast_function_call_should_use_symbol(&[t], &mut warnings);
    assert_eq!(warnings.len(), 1);
}

#[test]
fn skips_when_any_for_type_is_non_ast() {
    // Mixing an AST language with a binary type means symbol semantics
    // diverge — leave it alone.
    let t = make_trait(
        "t::eval-mixed",
        text_substr("eval("),
        vec![FileType::JavaScript, FileType::Pe],
    );
    let mut warnings = Vec::new();
    find_ast_function_call_should_use_symbol(&[t], &mut warnings);
    assert_eq!(warnings.len(), 0);
}

#[test]
fn skips_when_for_is_empty() {
    // Empty `for:` means "all" — includes binary types.
    let t = make_trait("t::eval-all", text_substr("eval("), vec![]);
    let mut warnings = Vec::new();
    find_ast_function_call_should_use_symbol(&[t], &mut warnings);
    assert_eq!(warnings.len(), 0);
}

#[test]
fn skips_method_calls_with_dot() {
    // `obj.method(` is not a top-level symbol — leave as text.
    let t = make_trait(
        "t::method",
        text_substr("console.log("),
        vec![FileType::JavaScript],
    );
    let mut warnings = Vec::new();
    find_ast_function_call_should_use_symbol(&[t], &mut warnings);
    assert_eq!(warnings.len(), 0);
}

#[test]
fn skips_patterns_with_arguments() {
    // `eval(arg)` includes argument-shape matching that symbol can't replace.
    let t = make_trait(
        "t::eval-arg",
        text_regex(r"eval\(\w+\)"),
        vec![FileType::JavaScript],
    );
    let mut warnings = Vec::new();
    find_ast_function_call_should_use_symbol(&[t], &mut warnings);
    assert_eq!(warnings.len(), 0);
}

#[test]
fn skips_when_no_paren() {
    // Plain identifier — already a candidate for word/symbol but not the
    // shape this check targets.
    let t = make_trait("t::just-name", text_substr("eval"), vec![FileType::Python]);
    let mut warnings = Vec::new();
    find_ast_function_call_should_use_symbol(&[t], &mut warnings);
    assert_eq!(warnings.len(), 0);
}
