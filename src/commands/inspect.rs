//! Facts command — dump everything filefacts extracts from one or more files.
//!
//! Output shape:
//! - **One target, no view** → pretty JSON object with every
//!   top-level view (`fileid`, `values`, `strings`, `metrics`, `ast`,
//!   `sections`, `imports`, `exports`, `functions`, `errors`).
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
        anyhow::bail!("cleave facts: at least one target file required");
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

fn inspect_one(target: &str, tree: Option<&cli::InspectTree>) -> Result<Value> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }
    let bytes = fs::read(path).with_context(|| format!("reading {}", target))?;
    let parsed = filefacts::open_with_path(path, &bytes)
        .map_err(|e| anyhow::anyhow!("filefacts failed to parse {}: {}", target, e))?;

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
            "metrics": parsed.metrics(),
            "sections": parsed.sections(),
            "symbols": parsed.symbols(),
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
        Some(cli::InspectTree::Errors { .. }) => serde_json::to_value(parsed.errors())?,
    })
}
