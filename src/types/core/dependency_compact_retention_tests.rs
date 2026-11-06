use crate::types::filefacts_view::retained_dependency_values;
use serde_json::json;
#[test]
fn compact_members_keep_dependency_identity_and_hooks_without_unrelated_values() {
    let expected = json!({"npm":{"name":"tool","version":"1.2.3","scripts":{"postinstall":"npm install companion@2.0.0"}}});
    let mut input = expected.clone();
    input["npm"]["description"] = json!("large unrelated prose");
    input["source"] = json!({"large":"unrelated AST metadata"});
    assert_eq!(retained_dependency_values(&input), expected);
    assert!(retained_dependency_values(&json!({"source":{}})).is_null());
    assert!(retained_dependency_values(&serde_json::Value::Null).is_null());
    assert_eq!(
        retained_dependency_values(
            &json!({"pe":{"debug":{"pdb":{"path":"C:\\build\\agent.pdb"}}}})
        ),
        json!({"pe":{"debug":{"pdb":{"path":"C:\\build\\agent.pdb"}}}})
    );
}
