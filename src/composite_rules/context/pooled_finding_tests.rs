use super::FindingScope;
use crate::types::{Evidence, Finding};

#[test]
fn pooled_scope_borrows_evidence_and_preserves_seed_then_iteration_order() {
    let left = Finding {
        id: "fixture/left".into(),
        evidence: vec![Evidence::new("text", "fixture", "original evidence")],
        ..Default::default()
    };
    let right = Finding {
        id: "fixture/right".into(),
        ..Default::default()
    };
    let extra = [Finding {
        id: "fixture/derived".into(),
        ..Default::default()
    }];
    let pooled = [&left, &right, &left];
    let scope = FindingScope::from_pooled(&pooled, &extra);
    let observed: Vec<_> = scope.iter().collect();
    let expected = [&left, &right, &left, &extra[0]];
    assert_eq!(observed.len(), expected.len());
    for (actual, original) in observed.into_iter().zip(expected) {
        assert!(
            std::ptr::eq(actual, original),
            "finding storage must be borrowed"
        );
    }
    for id in ["fixture/left", "fixture/right", "fixture/derived"] {
        assert!(scope.contains_id(id));
    }
    assert!(!scope.contains_id("fixture/missing"));
}

#[test]
fn container_scope_preserves_own_then_pooled_then_derived_order() {
    let own = [Finding {
        id: "fixture/own".into(),
        ..Default::default()
    }];
    let member = Finding {
        id: "fixture/member".into(),
        ..Default::default()
    };
    let derived = [Finding {
        id: "fixture/derived".into(),
        ..Default::default()
    }];
    let pooled = [&member, &own[0], &member];
    let scope = FindingScope::with_pooled(&own, &pooled, &derived);
    let expected = [&own[0], &member, &own[0], &member, &derived[0]];
    let actual: Vec<_> = scope.iter().collect();
    assert_eq!(actual.len(), expected.len());
    for (borrowed, original) in actual.into_iter().zip(expected) {
        assert!(std::ptr::eq(borrowed, original));
        assert!(scope.contains_id(original.id.as_str()));
    }
    assert!(!scope.contains_id("fixture/missing"));
}
