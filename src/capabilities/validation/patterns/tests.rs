use super::find_uncompilable_ast_queries;
use super::{
    REGEX_NFA_BUDGET_BYTES, RegexFacts, RegexMemoryIssue, find_memory_hungry_regex_patterns,
    regex_memory_issue, regex_performance_issues,
};
use super::{find_short_pattern_warnings, is_positioned_value_literal};
use crate::composite_rules::KvQuery;
use crate::composite_rules::condition::{NotException, NotExceptionStructured};
use crate::composite_rules::{
    CompositeTrait, Condition, FileType, RawQuery, TextQuery, TraitDefinition, TreeSitterQuery,
};
use std::collections::HashMap;

#[test]
fn positioned_value_literals_are_bounded_but_raw_and_recursive_queries_are_not() {
    let value = |path: &str, pattern: &str| {
        Condition::Kv(KvQuery {
            path: path.into(),
            regex: Some(pattern.into()),
            ..Default::default()
        })
    };
    for pattern in ["^/", r"^\\", "x$", "^xy$"] {
        let condition = value("archive.members[*].path", pattern);
        assert!(is_positioned_value_literal(&condition), "{pattern}");
        let t = TraitDefinition {
            id: "positioned-value".into(),
            r#for: vec![FileType::Zip, FileType::Tar, FileType::Jar, FileType::Npm],
            r#if: condition,
            ..Default::default()
        };
        assert!(find_short_pattern_warnings(&[t], &HashMap::new()).is_empty());
    }
    for pattern in ["/", "^a.*", "^a|b", "(?m)^/", "^$"] {
        assert!(!is_positioned_value_literal(&value(
            "archive.members[*].path",
            pattern
        )));
    }
    assert!(!is_positioned_value_literal(&value("$..strings[*]", "^/")));
    let raw = TraitDefinition {
        id: "raw-prefix".into(),
        r#for: vec![FileType::Zip, FileType::Tar, FileType::Jar, FileType::Npm],
        r#if: Condition::Raw(RawQuery {
            regex: Some("^/".into()),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(
        find_short_pattern_warnings(&[raw], &HashMap::new()).len(),
        1
    );
}

fn ast_query(query: &str, language: Option<&str>) -> Condition {
    Condition::TreeSitter(TreeSitterQuery {
        query: Some(query.to_string()),
        language: language.map(str::to_string),
        ..Default::default()
    })
}

#[test]
fn parallel_ast_lint_preserves_serial_diagnostics_and_order() {
    let cases = [
        (
            vec![FileType::JavaScript, FileType::TypeScript],
            "(call_expression) @c",
            None,
        ),
        (
            vec![FileType::JavaScript, FileType::Python],
            "(call_expression) @c",
            None,
        ),
        (vec![FileType::All], "(call_expression", None),
        (vec![FileType::All], "(_) @node", None),
        (
            vec![FileType::Python],
            "(call) @c",
            Some("unknown-language"),
        ),
        (
            vec![FileType::JavaScript],
            "(identifier) @id (#eq? @id \"eval\")",
            None,
        ),
        (
            vec![FileType::Python],
            "(call_expression) @c",
            Some("javascript"),
        ),
    ];
    let mut traits: Vec<_> = cases
        .into_iter()
        .enumerate()
        .map(|(i, (types, query, language))| TraitDefinition {
            id: format!("test-{i}"),
            r#for: types,
            r#if: ast_query(query, language),
            ..Default::default()
        })
        .collect();
    traits[0].unless = Some(vec![ast_query("(missing_unless_node) @c", None)]);
    let downgrade = super::DowngradeConditions {
        any: Some(vec![ast_query("(missing_downgrade_node) @c", None)]),
        all: None,
        needs: None,
        scope: None,
    };
    traits[0].downgrade = Some(downgrade.clone());
    let composites = [CompositeTrait {
        id: "composite".into(),
        r#for: vec![FileType::Python],
        all: Some(vec![ast_query("(missing_all_node) @c", None)]),
        any: Some(vec![ast_query("(call_expression) @c", Some("javascript"))]),
        unless: Some(vec![ast_query("(missing_unless_node) @c", None)]),
        downgrade: Some(downgrade),
        ..Default::default()
    }];
    let mut serial = Vec::new();
    super::find_uncompilable_ast_queries_with_parallel(&traits, &composites, &mut serial, false);
    assert!(!serial.is_empty());
    for _ in 0..8 {
        let mut parallel = Vec::new();
        super::find_uncompilable_ast_queries_with_parallel(
            &traits,
            &composites,
            &mut parallel,
            true,
        );
        assert_eq!(serial, parallel);
    }
}

#[test]
fn ast_query_compile_accepts_a_query_valid_for_every_for_type() {
    // The one pairing the ≤2 cap exists for: `call_expression` is a node in
    // both the JavaScript and TypeScript grammars.
    let trait_def = TraitDefinition {
        id: "t".to_string(),
        r#for: vec![FileType::JavaScript, FileType::TypeScript],
        r#if: ast_query("(call_expression) @c", None),
        ..Default::default()
    };
    let mut warnings = Vec::new();
    find_uncompilable_ast_queries(&[trait_def], &[], &mut warnings);
    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn ast_query_compile_flags_query_dead_on_one_of_its_for_types() {
    // Compiling for JavaScript is not enough: the trait claims Python too,
    // and every Python file it covers silently never matches.
    let trait_def = TraitDefinition {
        id: "t".to_string(),
        r#for: vec![FileType::JavaScript, FileType::Python],
        r#if: ast_query("(call_expression) @c", None),
        ..Default::default()
    };
    let mut warnings = Vec::new();
    find_uncompilable_ast_queries(&[trait_def], &[], &mut warnings);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("every grammar it targets"));
    assert!(warnings[0].contains("python:"));
}

#[test]
fn ast_query_compile_flags_query_valid_for_no_for_type() {
    // `call_expression` exists in no grammar this trait can run on, so the
    // query compiles nowhere and the rule is dead.
    let trait_def = TraitDefinition {
        id: "t".to_string(),
        r#for: vec![FileType::Python],
        r#if: ast_query("(call_expression) @c", None),
        ..Default::default()
    };
    let mut warnings = Vec::new();
    find_uncompilable_ast_queries(&[trait_def], &[], &mut warnings);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("trait 't'"));
    assert!(warnings[0].contains("python:"));
}

#[test]
fn ast_query_compile_flags_malformed_s_expression_without_for_types() {
    // No AST-capable `for:` type — fall back to every grammar. An
    // unbalanced S-expression compiles against none of them.
    let trait_def = TraitDefinition {
        id: "t".to_string(),
        r#for: vec![FileType::All],
        r#if: ast_query("(call_expression", None),
        ..Default::default()
    };
    let mut warnings = Vec::new();
    find_uncompilable_ast_queries(&[trait_def], &[], &mut warnings);
    assert_eq!(warnings.len(), 1);
}

#[test]
fn ast_query_compile_honors_explicit_language_over_for_types() {
    // `language:` pins the grammar even when `for:` is wider, so a query
    // that only compiles elsewhere is still reported.
    let trait_def = TraitDefinition {
        id: "t".to_string(),
        r#for: vec![FileType::JavaScript, FileType::Python],
        r#if: ast_query("(call_expression) @c", Some("python")),
        ..Default::default()
    };
    let mut warnings = Vec::new();
    find_uncompilable_ast_queries(&[trait_def], &[], &mut warnings);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("python:"));
}

#[test]
fn ast_query_compile_reaches_unless_and_composite_legs() {
    // A broken query hidden in a suppression leg silently stops suppressing,
    // which is a false positive — the walker must reach every query.
    let trait_def = TraitDefinition {
        id: "t".to_string(),
        r#for: vec![FileType::Python],
        r#if: ast_query("(call) @c", None),
        unless: Some(vec![ast_query("(bogus_node) @c", None)]),
        ..Default::default()
    };
    let composite = CompositeTrait {
        id: "c".to_string(),
        r#for: vec![FileType::Python],
        all: Some(vec![ast_query("(also_bogus) @c", None)]),
        ..Default::default()
    };
    let mut warnings = Vec::new();
    find_uncompilable_ast_queries(&[trait_def], &[composite], &mut warnings);
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    assert!(warnings[0].contains("trait 't'"));
    assert!(warnings[1].contains("composite 'c'"));
}

#[test]
fn tree_sitter_language_names_are_all_known_to_filefacts() {
    // The name map is the bridge to filefacts' grammar registry; a typo
    // here would silently turn the validator into a no-op for that type.
    for file_type in FileType::all_variants() {
        let Some(name) = file_type.tree_sitter_language_name() else {
            continue;
        };
        assert!(
            filefacts::validate_source_query(name, "(ERROR) @e").is_ok(),
            "{file_type:?} maps to unknown grammar name {name:?}"
        );
    }
}

#[test]
fn regex_memory_skips_cheap_and_unparseable_patterns() {
    // Brace-free patterns can't approach the budget (measured 15x margin).
    assert!(regex_memory_issue(r"https?://evil\.example/payload").is_none());
    // Small counted bounds are cheap in the resident byte-mode engine.
    assert!(regex_memory_issue(r"\w{1,40}").is_none());
    // Backreferences don't parse under engine syntax — other validators own those.
    assert!(regex_memory_issue(r"(.)\1{3}").is_none());
}

#[test]
fn regex_memory_flags_broad_gap_spans() {
    // The motivating shape: a wide [\s\S]{0,N} gap between two anchors,
    // which a near_lines/near_bytes composite expresses for a few KB.
    assert!(matches!(
        regex_memory_issue(r"curl[\s\S]{0,4000}\bbackdoor\b"),
        Some(RegexMemoryIssue::OverBudget(bytes)) if bytes > REGEX_NFA_BUDGET_BYTES
    ));
}

#[test]
fn regex_memory_flags_engine_compile_failures() {
    // Byte-mode NFA exceeds the 10 MB runtime ceiling too: never matches.
    assert!(matches!(
        regex_memory_issue(r"[\s\S]{0,250000}x"),
        Some(RegexMemoryIssue::NeverCompiles)
    ));
    // Resident byte-mode engine is small (~71 KB) but the Unicode engine
    // is ~15 MB: silently degrades to no-match on non-ASCII haystacks.
    assert!(matches!(
        regex_memory_issue(r"\w{1,900}"),
        Some(RegexMemoryIssue::UnicodeDegrades)
    ));
}

#[test]
fn regex_memory_reaches_unless_and_not_legs() {
    // The corpus' worst offender hid in an inline exclusion leg, not the
    // primary `if:` — the walker must reach every regex a rule compiles.
    let trait_def = TraitDefinition {
        id: "t".to_string(),
        r#if: Condition::Text(TextQuery {
            regex: Some("harmless".to_string()),
            ..Default::default()
        }),
        unless: Some(vec![Condition::Raw(RawQuery {
            regex: Some(r"curl[\s\S]{0,4000}\bbackdoor\b".to_string()),
            ..Default::default()
        })]),
        ..Default::default()
    };
    let composite = CompositeTrait {
        id: "c".to_string(),
        not: Some(vec![NotException::Structured(NotExceptionStructured {
            exact: None,
            substr: None,
            regex: Some(r"n[\s\S]{0,200000}\bbackdoor\b".to_string()),
            lowered_substr: None,
        })]),
        ..Default::default()
    };
    let mut warnings = Vec::new();
    find_memory_hungry_regex_patterns(&[trait_def], &[composite], &mut warnings);
    assert_eq!(warnings.len(), 2);
    assert!(warnings[0].contains("trait 't'"));
    assert!(warnings[0].contains("near_lines/near_bytes"));
    assert!(warnings[1].contains("composite 'c'"));
}

#[test]
fn regex_memory_measures_case_insensitive_compile() {
    // `(?i)` is applied before measuring, exactly as lazy_regex compiles it.
    let trait_def = TraitDefinition {
        id: "t".to_string(),
        r#if: Condition::Text(TextQuery {
            regex: Some(r"curl[\s\S]{0,4000}\bbackdoor\b".to_string()),
            case_insensitive: true,
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut warnings = Vec::new();
    find_memory_hungry_regex_patterns(&[trait_def], &[], &mut warnings);
    assert_eq!(warnings.len(), 1);
    // The message shows the pattern as authored, without the (?i) prefix.
    assert!(warnings[0].contains(r"curl[\s\S]{0,4000}"));
}

fn issues(pattern: &str, type_label: &'static str) -> Vec<String> {
    regex_performance_issues(&RegexFacts::analyze(pattern, type_label))
}

#[test]
fn regex_perf_allows_moderate_bounded_spans() {
    assert!(issues(r"\S{1,80}", "text").is_empty());
    assert!(issues(r"https?://\S{1,200}\.ps1\b", "text").is_empty());
}

#[test]
fn regex_perf_flags_large_broad_text_spans() {
    let warnings = issues(r"^.{0,2000}Invoke-Expression", "text");
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("broad counted repeat"));
}

#[test]
fn regex_perf_is_lenient_for_bounded_fields() {
    assert!(issues(r".{0,2000}Invoke-Expression", "value").is_empty());

    let warnings = issues(r".{0,5000}Invoke-Expression", "value");
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("broad counted repeat"));
}

#[test]
fn regex_perf_flags_unanchored_broad_scans_only_when_too_loose() {
    let warnings = issues(r".*\w+.*", "raw");
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("leading broad span"));

    assert!(issues(r".*BackdoorConfig", "raw").is_empty());
}
