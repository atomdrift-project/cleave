#![allow(clippy::unwrap_used)]

use super::*;

fn shorthand(text: &str) -> NotException {
    NotException::Shorthand(text.to_owned())
}

fn regex(pattern: &str) -> NotException {
    NotException::Structured(NotExceptionStructured {
        exact: None,
        substr: None,
        regex: Some(pattern.to_owned()),
        lowered_substr: None,
    })
}

fn exact(text: &str) -> NotException {
    NotException::Structured(NotExceptionStructured {
        exact: Some(text.to_owned()),
        substr: None,
        regex: None,
        lowered_substr: None,
    })
}

fn problems(pattern: &str, exceptions: &[NotException]) -> Vec<String> {
    exception_problems(pattern, &exceptions.iter().collect::<Vec<_>>())
}

#[test]
fn context_beyond_an_anchored_prefix_is_dead() {
    let found = problems(
        "^http://",
        &[regex(r"^http://(localhost|127\.0\.0\.1)(:[0-9]+)?/")],
    );
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("can never apply"), "{found:?}");
}

#[test]
fn context_inside_the_match_is_live() {
    assert!(problems(r"^http://[^/\s]+/", &[regex(r"^http://localhost/")]).is_empty());
    assert!(problems(r"(localhost/)?http", &[shorthand("localhost")]).is_empty());
    // A case-insensitive shorthand sees the match in any casing.
    assert!(problems("(?i)token", &[shorthand("TOKEN_X"), shorthand("ToKeN")]).len() == 1);
}

#[test]
fn word_boundaries_do_not_hide_a_live_exception() {
    // In context `\bfoo` can match after `x-`; the span `foo` is what is judged.
    assert!(problems(r"\bfoo\w*", &[exact("foobar")]).is_empty());
    assert!(problems(r"\bfoo\b", &[shorthand("bar")]).len() == 1);
}

#[test]
fn exceptions_covering_every_match_are_reported() {
    let found = problems("^(cd|pushd) ", &[regex("^cd "), regex("^pushd ")]);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("can never fire"), "{found:?}");
    assert!(problems("^(cd|pushd) ", &[regex("^cd ")]).is_empty());
}

#[test]
fn exact_exceptions_must_equal_a_whole_match() {
    assert!(problems("lodash-[a-z]+", &[exact("lodash-es")]).is_empty());
    assert!(problems("^lodash-", &[exact("lodash-es")]).len() == 1);
}

#[test]
fn every_condition_location_is_checked() {
    let condition = |json| serde_json::from_value::<Condition>(json).unwrap();
    let url = TraitDefinition {
        id: "url".to_owned(),
        r#if: condition(serde_json::json!({
            "type": "value", "path": "dependencies.*", "regex": "^http://"
        })),
        not: Some(vec![regex("^http://localhost/")]),
        unless: Some(vec![condition(serde_json::json!({
            "type": "symbol", "regex": "^babel-", "not": [{"exact": "babel-core"}]
        }))]),
        ..Default::default()
    };
    let combo = CompositeTrait {
        id: "combo".to_owned(),
        all: Some(vec![condition(serde_json::json!({
            "type": "comment", "word": "TODO", "not": ["TODO: later"]
        }))]),
        ..Default::default()
    };
    let mut found: Vec<_> = find_dead_regex_exceptions(&[url], &[combo])
        .into_iter()
        .map(|d| d.rule)
        .collect();
    found.sort();
    assert_eq!(found, ["combo", "url", "url"]);
}
