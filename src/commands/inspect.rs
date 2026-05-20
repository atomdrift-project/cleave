//! Inspect command — dump everything expose extracts from one or more files.
//!
//! Output shape:
//! - **One target, no subtree** → pretty JSON object with every
//!   top-level tree (`fileid`, `values`, `strings`, `metrics`, `ast`,
//!   `sections`, `imports`, `exports`, `functions`, `errors`).
//! - **One target, subtree filter** → pretty JSON of that one tree.
//! - **Multiple targets** → JSONL, one line per file with a `"path"`
//!   field plus either the full bundle or the single filtered tree.
//!   Failures emit `{"path": ..., "error": ...}` so the stream stays
//!   consumable by `jq`.
//!
//! Every read comes from `expose::open_with_path` so the output is
//! exactly what the trait engine sees — `cleave inspect` doubles as
//! the discovery tool for authoring `type: kv` / `type: metrics`
//! rules against expose's schema.

use crate::cli;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

/// Dispatch entry. Single target → pretty JSON; many → JSONL.
pub fn run(
    targets: &[String],
    tree: Option<&cli::InspectTree>,
    _format: &cli::OutputFormat,
) -> Result<String> {
    if targets.is_empty() {
        anyhow::bail!("cleave inspect: at least one target file required");
    }

    if targets.len() == 1 {
        let value = inspect_one(&targets[0], tree)?;
        return Ok(serde_json::to_string_pretty(&value)?);
    }

    let mut out = String::new();
    for target in targets {
        let line = match inspect_one(target, tree) {
            Ok(mut value) => {
                if let Value::Object(map) = &mut value {
                    map.insert("path".into(), json!(target));
                } else {
                    // Subtree may be a non-object (e.g., `imports` is
                    // a JSON array). Wrap it so each JSONL line is an
                    // object with `path` + the named tree.
                    value = json!({
                        "path": target,
                        tree.map_or("inspect", cli::InspectTree::name): value,
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

fn inspect_one(target: &str, tree: Option<&cli::InspectTree>) -> Result<Value> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }
    let bytes = fs::read(path).with_context(|| format!("reading {}", target))?;
    let parsed = expose::open_with_path(path, &bytes)
        .map_err(|e| anyhow::anyhow!("expose failed to parse {}: {}", target, e))?;

    Ok(match tree {
        None => json!({
            "fileid": parsed.fileid(),
            "values": parsed.values(),
            "strings": parsed.strings(),
            "metrics": parsed.metrics(),
            "ast": parsed.ast(),
            "sections": parsed.sections(),
            "imports": parsed.imports(),
            "exports": parsed.exports(),
            "functions": parsed.functions(),
            "errors": parsed.errors(),
        }),
        Some(cli::InspectTree::Fileid { .. }) => serde_json::to_value(parsed.fileid())?,
        Some(cli::InspectTree::Values { .. }) => serde_json::to_value(parsed.values())?,
        Some(cli::InspectTree::Strings { .. }) => serde_json::to_value(parsed.strings())?,
        Some(cli::InspectTree::Metrics { .. }) => serde_json::to_value(parsed.metrics())?,
        Some(cli::InspectTree::Ast { .. }) => serde_json::to_value(parsed.ast())?,
        Some(cli::InspectTree::Sections { .. }) => serde_json::to_value(parsed.sections())?,
        Some(cli::InspectTree::Imports { .. }) => serde_json::to_value(parsed.imports())?,
        Some(cli::InspectTree::Exports { .. }) => serde_json::to_value(parsed.exports())?,
        Some(cli::InspectTree::Functions { .. }) => serde_json::to_value(parsed.functions())?,
    })
}
