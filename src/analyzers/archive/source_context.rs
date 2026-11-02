//! Report adapters only. Language/package semantics belong to filefacts.
use crate::types::AnalysisReport;
use filefacts::package_context::{ContextLimits, Coverage, SourceFile, SourceMember};

pub(super) fn attach(report: &mut AnalysisReport) {
    let values: Vec<filefacts::Values> = report
        .files
        .iter()
        .map(|file| {
            let basename = file
                .path
                .rsplit(['/', '\\', '!'])
                .next()
                .unwrap_or(&file.path);
            if file.file_type.eq_ignore_ascii_case("rust")
                || basename.eq_ignore_ascii_case("Cargo.toml")
            {
                cargo_values(&file.kv, file.file_type.eq_ignore_ascii_case("rust"))
            } else {
                filefacts::Values::new()
            }
        })
        .collect();
    let members: Vec<_> = report
        .files
        .iter()
        .zip(&values)
        .map(|(file, values)| SourceMember {
            path: &file.path,
            values,
        })
        .collect();
    let context =
        filefacts::package_context::cargo_source_context(&members, &ContextLimits::default());
    if (context.truncated || !context.targets.is_empty())
        && let Ok(facts) = serde_json::to_value(&context)
    {
        report.merge_kv_subtree("cargo_context", facts);
    }
}

pub(super) fn attach_go(
    report: &mut AnalysisReport,
    sources: &[(String, String)],
    incomplete: bool,
) {
    let files: Vec<_> = sources
        .iter()
        .map(|(path, source)| SourceFile { path, source })
        .collect();
    let coverage = if incomplete {
        Coverage::Incomplete
    } else {
        Coverage::Complete
    };
    let context = filefacts::go_source_context(&files, coverage, &ContextLimits::default(), None);
    if (context.truncated || !context.packages.is_empty())
        && let Ok(facts) = serde_json::to_value(&context)
    {
        report.merge_kv_subtree("go_context", facts);
    }
}

/// Compact members use dotted/indexed keys, while filefacts consumes a tree.
/// Reconstruct only the schema-bound Cargo graph inputs, never document-owned
/// lookalike fields from unrelated member formats.
fn cargo_values(
    kv: &std::collections::BTreeMap<String, serde_json::Value>,
    is_rust: bool,
) -> filefacts::Values {
    use serde_json::Value;
    fn insert(node: &mut Value, path: &str, value: Value) {
        if path.is_empty() {
            *node = value;
            return;
        }
        if let Some(indexed) = path.strip_prefix('[') {
            let Some((index, rest)) = indexed.split_once(']') else {
                return;
            };
            let Ok(index) = index.parse::<usize>() else {
                return;
            };
            if !node.is_array() {
                *node = Value::Array(Vec::new());
            }
            let array = node.as_array_mut().expect("array initialized");
            array.resize_with(array.len().max(index + 1), || Value::Null);
            insert(&mut array[index], rest.trim_start_matches('.'), value);
        } else {
            let end = path.find(['.', '[']).unwrap_or(path.len());
            let (key, rest) = path.split_at(end);
            if !node.is_object() {
                *node = serde_json::json!({});
            }
            let child = node
                .as_object_mut()
                .expect("object initialized")
                .entry(key)
                .or_insert(Value::Null);
            insert(child, rest.trim_start_matches('.'), value);
        }
    }
    let mut tree = serde_json::json!({});
    for (key, value) in kv {
        if matches!(
            key.as_str(),
            "package.build" | "cargo.build_mode" | "lib.proc-macro" | "lib.path"
        ) || (is_rust
            && (key.starts_with("source.rust.modules[")
                || key.starts_with("source.payload_flow.events[")))
        {
            insert(&mut tree, key, value.clone());
        }
    }
    serde_json::from_value(tree).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::core::flatten_kv_for_output;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn compact_cargo_graph_retains_custom_entry_and_helper_upload() {
        let facts = |tree| {
            let mut flat = BTreeMap::new();
            flatten_kv_for_output(&tree, &mut flat);
            cargo_values(&flat, tree.get("source").is_some())
        };
        let manifest = facts(json!({"package":{"build":"bootstrap.rs"}}));
        let root = facts(
            json!({"source":{"rust":{"modules":[{"name":"helper","path":"support/upload.rs"}]}}}),
        );
        let helper =
            facts(json!({"source":{"payload_flow":{"events":[{"kind":"environment-http-body"}]}}}));
        let unrelated = facts(
            json!({"source":{"payload_flow":{"events":[{"kind":"credential-file-http-body"}]}}}),
        );
        let members = [
            SourceMember {
                path: "pkg/Cargo.toml",
                values: &manifest,
            },
            SourceMember {
                path: "pkg/bootstrap.rs",
                values: &root,
            },
            SourceMember {
                path: "pkg/support/upload.rs",
                values: &helper,
            },
            SourceMember {
                path: "pkg/unrelated.rs",
                values: &unrelated,
            },
        ];
        let context =
            filefacts::package_context::cargo_source_context(&members, &ContextLimits::default());
        let [target] = context.targets.as_slice() else {
            panic!("one build target: {context:?}")
        };
        assert_eq!(target.phase, filefacts::package_context::Phase::Build);
        assert_eq!(target.entry, "pkg/bootstrap.rs");
        assert_eq!(
            target.events,
            std::collections::BTreeSet::from(["environment-http-body".to_owned()])
        );
        assert!(target.members.contains("pkg/support/upload.rs"));
        assert!(!target.members.contains("pkg/unrelated.rs"));
    }

    #[test]
    fn compact_cargo_graph_keeps_disabled_build() {
        let mut flat = BTreeMap::new();
        flatten_kv_for_output(&json!({"cargo":{"build_mode":"disabled"}}), &mut flat);
        let values = cargo_values(&flat, false);
        let members = [SourceMember {
            path: "Cargo.toml",
            values: &values,
        }];
        let context =
            filefacts::package_context::cargo_source_context(&members, &ContextLimits::default());
        assert!(context.targets.is_empty());
    }
    #[test]
    fn cargo_manifest_cannot_supply_parser_owned_source_events() {
        let mut flat = BTreeMap::new();
        flatten_kv_for_output(
            &json!({"source":{"payload_flow":{"events":[{"kind":"environment-http-body"}]}}}),
            &mut flat,
        );
        assert!(cargo_values(&flat, false).get("source").is_none());
    }
}
