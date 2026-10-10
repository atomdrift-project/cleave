//! Facts command — dump everything filefacts extracts from one or more files.
//!
//! Output shape:
//! - **One target, no view** → pretty JSON object with every view
//!   filefacts extracts (`fileid`, `values`, `text`, `literals`,
//!   `comments`, `metrics`, `sections`, `symbols`, `flow`, `identity`,
//!   `references`, `archive_members`, `errors`). `flow` is `null` when
//!   the file has no flow producer, which is not an empty graph.
//! - **One target, view filter** → pretty JSON of that one view.
//! - **Multiple targets** → JSONL, one line per file with a `"path"`
//!   field plus either the full bundle or the single filtered tree.
//!   Failures emit `{"path": ..., "error": ...}` so the stream stays
//!   consumable by `jq`.
//!
//! Every read comes from `filefacts::open_with_path` so the output is
//! exactly what the trait engine sees — `cleave facts` doubles as
//! the discovery tool for authoring `type: value` / `type: metrics`
//! rules against filefacts's schema.

use crate::cli;
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

/// Dispatch entry. Single target → pretty JSON; many → JSONL.
pub fn run(
    targets: &[String],
    tree: Option<&cli::InspectTree>,
    _format: &cli::OutputFormat,
    disabled: &cli::DisabledComponents,
) -> Result<String> {
    if targets.is_empty() {
        anyhow::bail!("cleave facts: at least one target file required");
    }
    let options = crate::commands::shared::dev_engine(
        crate::capabilities::CapabilityMapper::empty(),
        disabled,
    )
    .filefacts_options();

    if targets.len() == 1 {
        let value = inspect_one(&targets[0], tree, &options)?;
        return Ok(serde_json::to_string_pretty(&value)?);
    }

    let mut out = String::new();
    for target in targets {
        let line = match inspect_one(target, tree, &options) {
            Ok(mut value) => {
                if let Value::Object(map) = &mut value {
                    map.insert("path".into(), json!(target));
                } else {
                    // A view may be a non-object (e.g., `imports` is
                    // a JSON array). Wrap it so each JSONL line is an
                    // object with `path` + the named tree.
                    value = json!({
                        "path": target,
                        tree.map_or("facts", cli::InspectTree::name): value,
                    });
                }
                value
            }
            Err(e) => json!({ "path": target, "error": e.to_string() }),
        };
        out.push_str(&serde_json::to_string(&line)?);
        out.push('\n');
    }
    Ok(out)
}

fn inspect_one(
    target: &str,
    tree: Option<&cli::InspectTree>,
    options: &filefacts::OpenOptions<'_>,
) -> Result<Value> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }
    let bytes = fs::read(path).with_context(|| format!("reading {}", target))?;
    let parsed = options.clone().path(path).open(&bytes);

    use filefacts::SymbolKind;
    let kind_to_value = |k: SymbolKind| -> Result<Value> {
        Ok(serde_json::to_value(
            parsed.symbols().iter_kind(k).collect::<Vec<_>>(),
        )?)
    };
    Ok(match tree {
        None => json!({
            "fileid": parsed.fileid(),
            "values": parsed.values(),
            "text": parsed.text(),
            "literals": parsed.literals(),
            "comments": parsed.comments(),
            "metrics": parsed.metrics(),
            "sections": parsed.sections(),
            "symbols": parsed.symbols(),
            "flow": parsed.flow(),
            "identity": parsed.identity(),
            "references": parsed.references(),
            "archive_members": parsed.archive_members(),
            "errors": parsed.errors(),
        }),
        Some(cli::InspectTree::Fileid { .. }) => serde_json::to_value(parsed.fileid())?,
        Some(cli::InspectTree::Values { .. }) => serde_json::to_value(parsed.values())?,
        Some(cli::InspectTree::Text { .. }) => serde_json::to_value(parsed.text())?,
        Some(cli::InspectTree::Literals { .. }) => serde_json::to_value(parsed.literals())?,
        Some(cli::InspectTree::Metrics { .. }) => serde_json::to_value(parsed.metrics())?,
        Some(cli::InspectTree::Sections { .. }) => serde_json::to_value(parsed.sections())?,
        Some(cli::InspectTree::Symbols { .. }) => serde_json::to_value(parsed.symbols())?,
        Some(cli::InspectTree::Imports { .. }) => kind_to_value(SymbolKind::Import)?,
        Some(cli::InspectTree::Exports { .. }) => kind_to_value(SymbolKind::Export)?,
        Some(cli::InspectTree::Functions { .. }) => kind_to_value(SymbolKind::Function)?,
        Some(cli::InspectTree::Calls { .. }) => kind_to_value(SymbolKind::Call)?,
        Some(cli::InspectTree::Members { .. }) => kind_to_value(SymbolKind::Member)?,
        Some(cli::InspectTree::Binds { .. }) => kind_to_value(SymbolKind::Bind)?,
        Some(cli::InspectTree::Identifiers { .. }) => kind_to_value(SymbolKind::Identifier)?,
        Some(cli::InspectTree::References { .. }) => serde_json::to_value(parsed.references())?,
        Some(cli::InspectTree::Errors { .. }) => serde_json::to_value(parsed.errors())?,
        Some(cli::InspectTree::Comments { .. }) => serde_json::to_value(parsed.comments())?,
        Some(cli::InspectTree::Flow { .. }) => serde_json::to_value(parsed.flow())?,
        Some(cli::InspectTree::Identity { .. }) => serde_json::to_value(parsed.identity())?,
        Some(cli::InspectTree::ArchiveMembers { .. }) => {
            serde_json::to_value(parsed.archive_members())?
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn facts_of(source: &str, tree: Option<&cli::InspectTree>) -> Value {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("loader.js");
        fs::write(&path, source).unwrap();
        inspect_one(path.to_str().unwrap(), tree, &filefacts::OpenOptions::new()).unwrap()
    }

    /// The dump is the authoring reference for every filefacts-backed
    /// condition, so a view the engine reads must not be missing from it
    /// (`flow`, which `arg.from` provenance runs on, once was).
    #[test]
    fn full_dump_carries_every_filefacts_view() {
        let facts = facts_of("const cp = require('child_process');\n", None);
        let keys: Vec<&str> = facts
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        for view in [
            "fileid",
            "values",
            "text",
            "literals",
            "comments",
            "metrics",
            "sections",
            "symbols",
            "flow",
            "identity",
            "references",
            "archive_members",
            "errors",
        ] {
            assert!(keys.contains(&view), "missing `{view}` in {keys:?}");
        }
    }

    /// The flow view shows what provenance can follow: a method call's
    /// receiver traced to the `require` that produced it.
    #[test]
    fn flow_view_links_a_call_receiver_to_its_origin() {
        let flow = facts_of(
            "const cp = require('child_process');\ncp.execSync('id');\n",
            Some(&cli::InspectTree::Flow {
                targets: Vec::new(),
            }),
        );
        let values = flow["values"].as_array().unwrap();
        let require = values
            .iter()
            .position(|v| v["target"] == "require")
            .expect("require call in flow");
        let exec = values
            .iter()
            .find(|v| v["target"] == "cp.execSync")
            .expect("method call in flow");
        assert_eq!(exec["receiver"], json!(require));
    }
}
