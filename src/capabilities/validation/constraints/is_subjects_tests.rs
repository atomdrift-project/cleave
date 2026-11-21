#![allow(clippy::unwrap_used)]

use super::*;

fn problem(json: serde_json::Value) -> Option<String> {
    is_subject_problem(&serde_json::from_value(json).unwrap())
}

#[test]
fn several_groups_are_ambiguous() {
    let found = problem(serde_json::json!({
        "type": "text", "regex": r"(curl|wget) (\S+)", "is": "external_ip"
    }));
    assert!(found.unwrap().contains("has 2"));
    for regex in [
        r"(?:curl|wget) (\S+)",
        r"(?:curl|wget) \S+",
        r"curl (?P<host>\S+)",
    ] {
        let json = serde_json::json!({"type": "text", "regex": regex, "is": "external_ip"});
        assert_eq!(problem(json), None, "{regex}");
    }
}

#[test]
fn fixed_text_subjects_are_reported() {
    for (key, kind) in [
        ("substr", "text"),
        ("exact", "value"),
        ("word", "raw"),
        ("substr", "symbol"),
    ] {
        let mut json = serde_json::json!({"type": kind, "is": "random_like"});
        json[key] = serde_json::json!("connect to");
        if kind == "value" {
            json["path"] = serde_json::json!("name");
        }
        assert!(
            problem(json).unwrap().contains("fixed text"),
            "{key}/{kind}"
        );
    }
}

#[test]
fn conditions_without_is_are_ignored() {
    let json = serde_json::json!({"type": "text", "regex": r"(a)(b)"});
    assert_eq!(problem(json), None);
}
