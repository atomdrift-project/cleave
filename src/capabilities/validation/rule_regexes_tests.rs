//! The regex inventory, and the per-pattern checks over it: each must reach a
//! pattern wherever a rule lists it.
#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;
use crate::capabilities::validation::{
    find_backtracking_regex_patterns, find_incompatible_regex_features,
    find_memory_hungry_regex_patterns, find_pathological_regex_patterns, find_slow_regex_patterns,
};
use serde_json::{Value, json};

fn condition(json: Value) -> Condition {
    serde_json::from_value(json).unwrap()
}

fn nots(patterns: &[&str]) -> Vec<NotException> {
    patterns
        .iter()
        .map(|p| serde_json::from_value(json!({ "regex": p })).unwrap())
        .collect()
}

fn downgrade(json: Value) -> DowngradeConditions {
    serde_json::from_value(json).unwrap()
}

/// A trait listing `pattern` in the given place.
fn trait_with(place: &str, pattern: &str) -> TraitDefinition {
    let plain = condition(json!({"type": "text", "substr": "plain"}));
    let mut t = TraitDefinition {
        id: "test/re::t".to_string(),
        r#if: plain.clone(),
        ..Default::default()
    };
    let text = condition(json!({"type": "text", "regex": pattern}));
    let text_not = condition(json!({"type": "text", "substr": "x", "not": [{"regex": pattern}]}));
    match place {
        "if:" => t.r#if = text,
        "if: not:" => t.r#if = text_not,
        "not:" => t.not = Some(nots(&[pattern])),
        "unless:" => t.unless = Some(vec![text]),
        "unless: not:" => t.unless = Some(vec![text_not]),
        "downgrade:" => {
            t.downgrade = Some(downgrade(
                json!({"any": [{"type": "text", "regex": pattern}]}),
            ))
        }
        _ => panic!("no such place: {place}"),
    }
    t
}

/// A composite listing `pattern` in the given place.
fn composite_with(place: &str, pattern: &str) -> CompositeTrait {
    let mut c = CompositeTrait {
        id: "test/re::c".to_string(),
        ..Default::default()
    };
    let raw = || Some(vec![condition(json!({"type": "raw", "regex": pattern}))]);
    match place {
        "all:" => c.all = raw(),
        "any:" => c.any = raw(),
        "unless:" => c.unless = raw(),
        "not:" => c.not = Some(nots(&[pattern])),
        "downgrade:" => {
            c.downgrade = Some(downgrade(
                json!({"all": [{"type": "raw", "regex": pattern}]}),
            ))
        }
        _ => panic!("no such place: {place}"),
    }
    c
}

const TRAIT_PLACES: [&str; 6] = [
    "if:",
    "if: not:",
    "not:",
    "unless:",
    "unless: not:",
    "downgrade:",
];
const COMPOSITE_PLACES: [&str; 5] = ["all:", "any:", "unless:", "not:", "downgrade:"];

#[test]
fn inventory_finds_a_pattern_in_every_trait_and_composite_place() {
    for place in TRAIT_PLACES {
        let t = [trait_with(place, "NEEDLE")];
        let found: Vec<_> = rule_regexes(&t, &[])
            .into_iter()
            .filter(|r| r.pattern == "NEEDLE")
            .collect();
        assert_eq!(found.len(), 1, "{place}");
        assert_eq!(
            (found[0].kind, found[0].place, found[0].reads),
            ("trait", place, "text")
        );
    }
    for place in COMPOSITE_PLACES {
        let c = [composite_with(place, "NEEDLE")];
        let found: Vec<_> = rule_regexes(&[], &c)
            .into_iter()
            .filter(|r| r.pattern == "NEEDLE")
            .collect();
        assert_eq!(found.len(), 1, "{place}");
        assert_eq!((found[0].kind, found[0].place), ("composite", place));
    }
}

#[test]
fn inventory_finds_symbol_filter_and_provenance_regexes() {
    let t = [TraitDefinition {
        id: "test/re::sym".to_string(),
        r#if: condition(json!({
            "type": "symbol",
            "regex": "SYM",
            "kind": "call",
            "arg": {
                "regex": "ARG",
                "name_regex": "NAME",
                "from": {
                    "call": "CALL",
                    "literal": "LITERAL",
                    "through": [{"call": "THROUGH", "arguments": [0]}],
                },
            },
            "args": [{"regex": "ARGS", "from": {"whole_value": "WHOLE"}}],
            "alias": {"regex": "ALIAS"},
            "receiver": {"from": {"member": "MEMBER"}},
        })),
        ..Default::default()
    }];
    let mut found: Vec<_> = rule_regexes(&t, &[])
        .iter()
        .map(|r| (r.pattern, r.reads))
        .collect();
    found.sort_unstable();
    let mut expected: Vec<_> = [
        "SYM", "ARG", "NAME", "CALL", "LITERAL", "THROUGH", "ARGS", "WHOLE", "ALIAS", "MEMBER",
    ]
    .map(|p| (p, "symbol"))
    .to_vec();
    expected.sort_unstable();
    assert_eq!(found, expected);
}

#[test]
fn exceptions_read_the_surface_of_what_they_filter() {
    let t = [TraitDefinition {
        id: "test/re::surface".to_string(),
        r#if: condition(json!({"type": "symbol", "regex": "S", "not": [{"regex": "SN"}]})),
        not: Some(nots(&["TN"])),
        unless: Some(vec![condition(
            json!({"type": "raw", "substr": "u", "not": [{"regex": "UN"}]}),
        )]),
        ..Default::default()
    }];
    let reads: Vec<_> = rule_regexes(&t, &[])
        .iter()
        .map(|r| (r.pattern, r.place, r.reads))
        .collect();
    assert!(reads.contains(&("SN", "if: not:", "symbol")));
    assert!(reads.contains(&("TN", "not:", "symbol")));
    assert!(reads.contains(&("UN", "unless: not:", "raw")));
}

#[test]
fn uncompilable_regexes_are_flagged_wherever_listed() {
    for pattern in [r"(?=x)y", r"(.)\1", r"(unclosed"] {
        for place in TRAIT_PLACES {
            let mut errors = Vec::new();
            find_incompatible_regex_features(&[trait_with(place, pattern)], &[], &mut errors);
            assert_eq!(errors.len(), 1, "{pattern} in trait {place}: {errors:?}");
            assert!(
                errors[0].contains(&format!("in its {place} ")),
                "{}",
                errors[0]
            );
        }
        for place in COMPOSITE_PLACES {
            let mut errors = Vec::new();
            find_incompatible_regex_features(&[], &[composite_with(place, pattern)], &mut errors);
            assert_eq!(
                errors.len(),
                1,
                "{pattern} in composite {place}: {errors:?}"
            );
            assert!(
                errors[0].contains("composite 'test/re::c'"),
                "{}",
                errors[0]
            );
        }
    }
}

#[test]
fn uncompilable_symbol_filter_regex_is_flagged() {
    let t = TraitDefinition {
        id: "test/re::sym".to_string(),
        r#if: condition(
            json!({"type": "symbol", "exact": "f", "kind": "call", "arg": {"regex": "(?<=a)b"}}),
        ),
        ..Default::default()
    };
    let mut errors = Vec::new();
    find_incompatible_regex_features(&[t], &[], &mut errors);
    assert_eq!(errors.len(), 1, "{errors:?}");
}

#[test]
fn backtracking_shapes_are_flagged_wherever_listed_on_broad_input() {
    for place in TRAIT_PLACES {
        let mut warnings = Vec::new();
        find_backtracking_regex_patterns(&[trait_with(place, "a.*b")], &[], &mut warnings);
        assert_eq!(warnings.len(), 1, "trait {place}: {warnings:?}");
        assert!(
            warnings[0].contains(&format!("in its {place}:")),
            "{}",
            warnings[0]
        );
    }
    for place in COMPOSITE_PLACES {
        let mut warnings = Vec::new();
        find_backtracking_regex_patterns(&[], &[composite_with(place, "[^x]+y")], &mut warnings);
        assert_eq!(warnings.len(), 1, "composite {place}: {warnings:?}");
    }
}

#[test]
fn backtracking_shapes_on_bounded_values_are_not_slow() {
    let t = TraitDefinition {
        id: "test/re::sym".to_string(),
        r#if: condition(json!({"type": "symbol", "regex": "^lib.+$", "not": [{"regex": ".*x"}]})),
        ..Default::default()
    };
    let mut warnings = Vec::new();
    find_backtracking_regex_patterns(&[t], &[], &mut warnings);
    assert!(warnings.is_empty(), "{warnings:?}");
}

#[test]
fn slow_regexes_are_flagged_wherever_listed() {
    let slow = r"a[\s\S]{0,5000}b";
    for place in TRAIT_PLACES {
        let mut warnings = Vec::new();
        find_slow_regex_patterns(&[trait_with(place, slow)], &[], &mut warnings);
        assert_eq!(warnings.len(), 1, "trait {place}: {warnings:?}");
        assert!(
            warnings[0].contains(&format!("in its {place} ")),
            "{}",
            warnings[0]
        );
    }
    for place in COMPOSITE_PLACES {
        let mut warnings = Vec::new();
        find_slow_regex_patterns(&[], &[composite_with(place, slow)], &mut warnings);
        assert_eq!(warnings.len(), 1, "composite {place}: {warnings:?}");
    }
}

#[test]
fn memory_hungry_regexes_are_flagged_wherever_listed() {
    let hungry = r"n[\s\S]{0,200000}\bbackdoor\b";
    for place in TRAIT_PLACES {
        let mut warnings = Vec::new();
        find_memory_hungry_regex_patterns(&[trait_with(place, hungry)], &[], &mut warnings);
        assert_eq!(warnings.len(), 1, "trait {place}: {warnings:?}");
        assert!(
            warnings[0].contains(&format!("in its {place} ")),
            "{}",
            warnings[0]
        );
    }
}

#[test]
fn exploding_regexes_are_flagged_wherever_listed() {
    let exploding = r#"(^|[\\/])[^\r\n]{1,120}\.vmx($|[\s"'`])"#;
    for place in ["if: not:", "unless:", "downgrade:"] {
        let mut warnings = Vec::new();
        find_pathological_regex_patterns(&[trait_with(place, exploding)], &[], &mut warnings);
        assert_eq!(warnings.len(), 1, "trait {place}: {warnings:?}");
        assert!(
            warnings[0].contains(&format!("in its {place} ")),
            "{}",
            warnings[0]
        );
    }
    let mut warnings = Vec::new();
    find_pathological_regex_patterns(&[], &[composite_with("any:", exploding)], &mut warnings);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
}
