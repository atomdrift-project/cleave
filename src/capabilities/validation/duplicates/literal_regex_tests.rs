use super::*;

#[test]
fn regex_overlap_keeps_structured_argument_filters_out_of_regex_syntax() {
    let rule = |id: &str, callee: &str, setting: &str| -> TraitDefinition {
        crate::yaml::from_str(&format!(
            "id: {id}\ndesc: test\nfor: [shell]\nif:\n  type: symbol\n  kind: call\n  regex: '{callee}'\n  args:\n    - index: 2\n      kind: string\n      regex: '^echo 0 > /proc/sys/kernel/{setting}([ \\t;]|$)'\n"
        )).unwrap()
    };
    let first = rule("first", "(^|/)sudo$", "kptr_restrict");
    let different_arg = rule("different", "(^|/)sudo$", "perf_event_paranoid");
    let mut warnings = Vec::new();
    check_overlapping_regex_patterns(
        &ExtractedPatterns::of(&[first.clone(), different_arg]),
        &mut warnings,
    );
    assert!(warnings.is_empty(), "{warnings:?}");
    let equivalent = rule("equivalent", "(^|/)(?:sudo)$", "kptr_restrict");
    check_overlapping_regex_patterns(&ExtractedPatterns::of(&[first, equivalent]), &mut warnings);
    assert!(
        !warnings.is_empty(),
        "equivalent callee and argument predicates must still be detected"
    );
}

#[test]
fn structural_regex_duplicates_preserve_symbol_argument_provenance() {
    let rule = |id: &str, callee: &str, source: &str| -> TraitDefinition {
        crate::yaml::from_str(&format!(
            "id: {id}\ndesc: test\ncrit: notable\nfor: [javascript]\nif:\n  type: symbol\n  kind: call\n  regex: '{callee}'\n  arg:\n    index: 0\n    from:\n      call: {source}\n"
        )).unwrap()
    };
    let first = rule("remote", "^(exec|execSync)$", "fetchRemoteText");
    let different = rule("local", "(^|\\.)(exec|execSync)$", "readFileSync");
    let mut warnings = Vec::new();
    find_structural_regex_duplicates(&[first.clone(), different], &mut warnings);
    assert!(warnings.is_empty(), "{warnings:?}");
    let equivalent = rule("remote-alias", "(^|\\.)(exec|execSync)$", "fetchRemoteText");
    find_structural_regex_duplicates(&[first, equivalent], &mut warnings);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
}

#[test]
fn symbol_arguments_keep_positions_shapes_and_provenance_distinct() {
    use crate::composite_rules::condition::ArgFilter;
    let parse = |yaml: &str| crate::yaml::from_str::<ArgFilter>(yaml).unwrap();
    let variants = [
        "{exact: token}",
        "{substr: token}",
        "{exact: token, index: 0}",
        "{exact: token, index: 1}",
        "{kind: number, value: 511, radix: 8}",
        "{kind: number, value: 511, radix: 10}",
        "{from: {call: read, literal: TOKEN, field: body}}",
        "{from: {call: read, literal: TOKEN, field: headers}}",
        "{from: {call: read, literal: PASSWORD, field: body}}",
    ];
    let keys: HashSet<_> = variants
        .iter()
        .map(|yaml| symbol_argument_discriminator(Some(&parse(yaml)), None))
        .collect();
    assert_eq!(keys.len(), variants.len());
    let a = parse("{exact: a}");
    let b = parse("{exact: b}");
    let pair = symbol_argument_discriminator(None, Some(&[a.clone(), b.clone()]));
    assert_eq!(
        pair,
        symbol_argument_discriminator(None, Some(&[b, a.clone()]))
    );
    assert_ne!(
        pair,
        symbol_argument_discriminator(None, Some(&[a.clone()]))
    );
    assert_ne!(
        symbol_argument_discriminator(None, Some(&[a.clone(), a.clone()])),
        symbol_argument_discriminator(None, Some(&[a]))
    );
}

#[test]
fn pure_literal_with_escaped_dot_decodes() {
    // The canonical false-positive: regex `\.aws/credentials` matches the
    // exact same bytes as substr `.aws/credentials` and must compare equal
    // for duplicate detection.
    assert_eq!(
        extract_pure_literal_from_regex("\\.aws/credentials"),
        Some(".aws/credentials".to_string())
    );
}

#[test]
fn pure_literal_unescaped_punctuation_passes_through() {
    // `/`, `-`, `_` are not regex metacharacters and stay as-is.
    assert_eq!(
        extract_pure_literal_from_regex("/etc/passwd"),
        Some("/etc/passwd".to_string())
    );
    assert_eq!(
        extract_pure_literal_from_regex("AKIA_TEST-KEY"),
        Some("AKIA_TEST-KEY".to_string())
    );
}

#[test]
fn escaped_metacharacters_decode_to_their_literal_form() {
    assert_eq!(
        extract_pure_literal_from_regex("\\(literal\\)"),
        Some("(literal)".to_string())
    );
    assert_eq!(
        extract_pure_literal_from_regex("a\\|b"),
        Some("a|b".to_string())
    );
}

#[test]
fn unescaped_metacharacters_block_literal_extraction() {
    assert!(extract_pure_literal_from_regex(".aws/credentials").is_none());
    assert!(extract_pure_literal_from_regex("foo|bar").is_none());
    assert!(extract_pure_literal_from_regex("[abc]").is_none());
    assert!(extract_pure_literal_from_regex("a*").is_none());
    assert!(extract_pure_literal_from_regex("a+").is_none());
    assert!(extract_pure_literal_from_regex("a?").is_none());
    assert!(extract_pure_literal_from_regex("(group)").is_none());
    assert!(extract_pure_literal_from_regex("a{1,3}").is_none());
    assert!(extract_pure_literal_from_regex("^foo").is_none());
    assert!(extract_pure_literal_from_regex("foo$").is_none());
}

#[test]
fn regex_shorthand_classes_block_literal_extraction() {
    // \w \d \s \b — these are character classes / boundaries, not literals.
    assert!(extract_pure_literal_from_regex("\\bfoo\\b").is_none());
    assert!(extract_pure_literal_from_regex("\\d{3}").is_none());
    assert!(extract_pure_literal_from_regex("\\w+").is_none());
    assert!(extract_pure_literal_from_regex("\\s").is_none());
}

#[test]
fn trailing_backslash_blocks_literal_extraction() {
    assert!(extract_pure_literal_from_regex("foo\\").is_none());
}

#[test]
fn normalize_pattern_strips_anchors_then_extracts_literal() {
    // `^\.aws/credentials$` should be treated as substr `.aws/credentials`
    // after anchor-stripping + literal-decoding.
    assert_eq!(
        normalize_pattern_for_comparison("^\\.aws/credentials$", true),
        ".aws/credentials"
    );
}

#[test]
fn normalize_pattern_keeps_meta_regex_unchanged_apart_from_anchors() {
    // Real metacharacter → no decode, only anchor stripping.
    assert_eq!(
        normalize_pattern_for_comparison("^foo|bar$", true),
        "foo|bar"
    );
    assert_eq!(
        normalize_pattern_for_comparison("\\d{3}-\\d{4}", true),
        "\\d{3}-\\d{4}"
    );
}

#[test]
fn substr_normalization_unaffected_by_regex_decode() {
    assert_eq!(
        normalize_pattern_for_comparison(".aws/credentials", false),
        ".aws/credentials"
    );
    assert_eq!(
        normalize_pattern_for_comparison("\\.aws/credentials", false),
        "\\.aws/credentials"
    );
}
