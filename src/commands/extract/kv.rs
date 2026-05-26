//! Structural value extraction command.
//!
//! Dumps the parsed structure of manifest-style files as a flat list of
//! `path: value` pairs. Supported formats: JSON (package.json, manifest.json,
//! composer.json), YAML (GitHub Actions workflows, action.yml), TOML
//! (Cargo.toml, pyproject.toml), Apple plists, Python PKG-INFO/METADATA,
//! Windows Shell Link (.lnk), systemd .service unit files, and Microsoft
//! Office documents (legacy OLE2 `.doc`/`.xls`/`.ppt` and modern OOXML
//! `.docx`/`.xlsx`/`.pptx`).
//!
//! For office documents the dump is the synthesized values tree the office
//! analyzer attaches to `report.values_tree` during analysis — `summary.*`,
//! `core.*`, `ole.compobj.*`, `relationships[]`, `embedded[]`. The same
//! paths are accepted by `type: value` traits, so this command is the
//! canonical discovery tool for authoring office-document value rules.
//!
//! The emitted paths use the same syntax accepted by `test-match --type value
//! --path`, so the output doubles as a discovery tool for authoring value rules.

use crate::analyzers;
use crate::analyzers::FileType;
use crate::cli;
use crate::composite_rules::evaluators::kv::{navigate, parse_path, parse_structured_content};
use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
struct KvEntry {
    path: String,
    value: Value,
}

/// Dump the parsed structural values of a manifest-style file.
///
/// Dispatch order:
/// 1. `filefacts::open_with_path` — single source of truth for format-native
///    values (`lnk.*`, `pe.*`, `pdf.*`, `chm.*`, …). One call covers every
///    format filefacts has an extractor for.
/// 2. Office (OLE2 / OOXML) — cleave-owned until filefacts Phase 2 lands.
/// 3. Binary cross-format kv — cleave's `binary_extractors` layer
///    augments filefacts's `pe|elf|macho.*` trees with cleave-derived
///    fields (Rich header, imphash, ELF .comment, DWARF, …).
/// 4. Source code analyzer — `source.*` / `metrics.*` are cleave-side.
/// 5. Generic structured fallback — JSON / YAML / TOML / plist /
///    PKG-INFO / systemd / desktop / XML manifests.
pub fn run(target: &str, path_filter: Option<&str>, format: &cli::OutputFormat) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    let content = fs::read(path)?;

    let parsed = if let Some(value) = filefacts_values(path, &content) {
        value
    } else if let Some(binary_value) = extract_binary_kv_via_analyzer(path, &content) {
        binary_value
    } else if let Some(source_value) = extract_source_kv_via_analyzer(path, &content) {
        source_value
    } else if let Some((_, structured_value)) = parse_structured_content(path, &content) {
        structured_value
    } else {
        anyhow::bail!(
            "File is not a recognized structured format (expected JSON/YAML/TOML/plist/PKG-INFO/systemd/desktop manifest, OLE2/OOXML office document, or a format with a filefacts extractor — LNK, PE/ELF/Mach-O, PDF, RTF, JPEG/PNG, JAR, CHM, ...): {}",
            target
        );
    };

    let roots: Vec<(&Value, String)> = if let Some(filter) = path_filter {
        let segments = parse_path(filter).map_err(|e| anyhow::anyhow!("invalid path: {}", e))?;
        let values = navigate(&parsed, &segments);
        if values.is_empty() {
            anyhow::bail!("path '{}' not found in {}", filter, target);
        }
        values
            .into_iter()
            .map(|v| (v, filter.to_string()))
            .collect()
    } else {
        vec![(&parsed, String::new())]
    };

    let mut entries: Vec<KvEntry> = Vec::new();
    for (root, prefix) in roots {
        flatten(root, &prefix, &mut entries);
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));

    format_output(&entries, target, format)
}

/// Flatten a JSON value into `path: leaf` entries using value-path syntax.
///
/// Objects become `parent.child`, arrays become `parent[0]`, `parent[1]`, etc.
/// Empty collections are emitted as-is so callers can still see they exist.
fn flatten(value: &Value, prefix: &str, entries: &mut Vec<KvEntry>) {
    match value {
        Value::Object(map) if !map.is_empty() => {
            for (key, v) in map {
                let child = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", prefix, key)
                };
                flatten(v, &child, entries);
            }
        }
        Value::Array(arr) if !arr.is_empty() => {
            for (i, v) in arr.iter().enumerate() {
                let child = format!("{}[{}]", prefix, i);
                flatten(v, &child, entries);
            }
        }
        _ => {
            entries.push(KvEntry {
                path: prefix.to_string(),
                value: value.clone(),
            });
        }
    }
}

fn format_output(entries: &[KvEntry], target: &str, format: &cli::OutputFormat) -> Result<String> {
    match format {
        cli::OutputFormat::Json | cli::OutputFormat::Jsonl => {
            Ok(serde_json::to_string_pretty(entries)?)
        }
        cli::OutputFormat::Terminal | cli::OutputFormat::Tiny => {
            let mut out = String::new();
            out.push_str(&format!(
                "Extracted {} values from {}\n\n",
                entries.len(),
                target,
            ));
            out.push_str("# Paths use value-path syntax (type: value, path: <path>)\n\n");
            let width = entries.iter().map(|e| e.path.len()).max().unwrap_or(0);
            for entry in entries {
                out.push_str(&format!(
                    "{:<width$}  {}\n",
                    entry.path,
                    render_value(&entry.value),
                    width = width
                ));
            }
            Ok(out)
        }
    }
}

/// Pull the structured values tree from the shared [`AnalysisContext`].
///
/// This is the only place the `cleave value` command touches filefacts —
/// every format filefacts owns (PE, ELF, Mach-O, LNK, PDF, RTF, JPEG,
/// PNG, JAR, CHM, RPM, pyc, pickle, class, VSIX, source code, …)
/// flows through this single helper.
fn filefacts_values(path: &Path, content: &[u8]) -> Option<Value> {
    let ctx = crate::analysis_context::AnalysisContext::open(path, content).ok()?;
    ctx.values_tree_if_nonempty()
}

fn extract_binary_kv_via_analyzer(path: &Path, content: &[u8]) -> Option<Value> {
    let detected = analyzers::detect_file_type_from_data(path, content);
    if !matches!(detected, FileType::Pe | FileType::Elf | FileType::MachO) {
        return None;
    }
    let analyzer = analyzers::analyzer_for_file_type(&detected, None)?;
    let mut report = analyzer.analyze(path).ok()?;
    // `pe.*` / `elf.*` / `macho.*` come exclusively from filefacts
    // (single source of truth). `binary_extractors` augments with
    // `.comment` / sanitizer detections.
    if let Ok(ctx) = crate::analysis_context::AnalysisContext::open(path, content)
        && let Value::Object(map) = ctx.values_tree()
    {
        for (namespace, subtree) in map {
            report.merge_kv_subtree(&namespace, subtree);
        }
    }
    analyzers::binary_extractors::augment_report(&mut report, content);
    report.values_tree.as_deref().cloned()
}

/// Run the unified source-code analyzer (any tree-sitter–supported
/// language) and return the synthesized values tree from `report.values_tree`,
/// which the analyzer populates via `source_kv::attach_to_report`.
/// Returns `None` for non-source input or when the analyzer fails.
fn extract_source_kv_via_analyzer(path: &Path, content: &[u8]) -> Option<Value> {
    let detected = analyzers::detect_file_type_from_data(path, content);
    // Skip file types already handled upstream — binaries, archives,
    // structured documents, and the unknown bucket.  Anything else
    // routes through `UnifiedSourceAnalyzer` (or a generic fallback)
    // which attaches `source.*` and `metrics.*` to `report.values_tree`.
    if matches!(
        detected,
        FileType::Pe
            | FileType::Elf
            | FileType::MachO
            | FileType::Unknown
            | FileType::Pdf
            | FileType::Rtf
            | FileType::OleDoc
            | FileType::Ooxml
    ) {
        return None;
    }
    let analyzer = analyzers::analyzer_for_file_type(&detected, None)?;
    let report = analyzer.analyze(path).ok()?;
    report.values_tree.as_deref().cloned()
}

fn render_value(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Array(arr) if arr.is_empty() => "[]".to_string(),
        Value::Object(obj) if obj.is_empty() => "{}".to_string(),
        _ => value.to_string(),
    }
}
