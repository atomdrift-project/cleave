use super::retain_cargo_context_values;
use serde_json::json;
use std::collections::BTreeMap;
#[test]
fn retains_graph_inputs_without_unrelated_member_values() {
    let tree = json!({"source":{"rust":{"modules":[{"name":"helper","path":"helper.rs"}]},
        "payload_flow":{"events":[{"kind":"file-http-body"}]}},"large_unused_tree":"discard"});
    let mut kept = BTreeMap::new();
    retain_cargo_context_values("a.crate!!pkg/src/lib.rs", &tree, &mut kept);
    assert_eq!(
        kept.get("source.rust.modules[0].name"),
        Some(&json!("helper"))
    );
    assert_eq!(
        kept.get("source.payload_flow.events[0].kind"),
        Some(&json!("file-http-body"))
    );
    assert!(!kept.contains_key("large_unused_tree"));
}
#[test]
fn retains_explicit_disabled_and_custom_build_context() {
    for mode in ["disabled", "custom"] {
        let mut kept = BTreeMap::new();
        retain_cargo_context_values(
            "a.crate!!pkg/Cargo.toml",
            &json!({"cargo":{"build_mode":mode},"package":{"build":"bootstrap.rs"},"lib":{"proc-macro":true}}),
            &mut kept,
        );
        assert_eq!(kept.get("cargo.build_mode"), Some(&json!(mode)));
        assert_eq!(kept.get("lib.proc-macro"), Some(&json!(true)));
    }
}
