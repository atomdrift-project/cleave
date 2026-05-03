//! Key/value extraction command.
//!
//! Dumps the parsed structure of manifest-style files as a flat list of
//! `path: value` pairs. Supported formats: JSON (package.json, manifest.json,
//! composer.json), YAML (GitHub Actions workflows, action.yml), TOML
//! (Cargo.toml, pyproject.toml), Apple plists, Python PKG-INFO/METADATA,
//! Windows Shell Link (.lnk), systemd .service unit files, and Microsoft
//! Office documents (legacy OLE2 `.doc`/`.xls`/`.ppt` and modern OOXML
//! `.docx`/`.xlsx`/`.pptx`).
//!
//! For office documents the dump is the synthesized kv tree the office
//! analyzer attaches to `report.kv_tree` during analysis — `summary.*`,
//! `core.*`, `ole.compobj.*`, `relationships[]`, `embedded[]`. The same
//! paths are accepted by `type: kv` traits, so this command is the
//! canonical discovery tool for authoring office-document kv rules.
//!
//! The emitted paths use the same syntax accepted by `test-match --type kv
//! --kv-path`, so the output doubles as a discovery tool for authoring kv rules.

use crate::analyzers;
use crate::analyzers::binary_kv;
use crate::analyzers::office::office_kv;
use crate::analyzers::pdf::pdf_kv;
use crate::analyzers::FileType;
use crate::cli;
use crate::composite_rules::evaluators::kv::{
    detect_format, navigate, parse_path, parse_structured_content, StructuredFormat,
};
use crate::rtf::rtf_kv;
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

/// Dump the parsed key/value structure of a manifest-style file.
pub fn run(target: &str, path_filter: Option<&str>, format: &cli::OutputFormat) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    let content = fs::read(path)?;

    // Documents that aren't natively manifest formats (office, RTF,
    // and eventually PDF) get a synthetic kv tree built by their
    // dedicated analyzer module. We try each in order before
    // falling through to the generic structured-content parser. The
    // returned trees use snake_case schemas — see
    // `analyzers::office::office_kv` and `rtf::rtf_kv`.
    let (detected, parsed) = if let Some(office_value) =
        office_kv::extract_office_kv(path, &content)
    {
        (StructuredFormat::Json, office_value)
    } else if let Some(rtf_value) = rtf_kv::extract_rtf_kv(&content) {
        (StructuredFormat::Json, rtf_value)
    } else if let Some(pdf_value) = pdf_kv::extract_pdf_kv(&content) {
        (StructuredFormat::Json, pdf_value)
    } else if let Some(binary_value) = extract_binary_kv_via_analyzer(path, &content) {
        (StructuredFormat::Json, binary_value)
    } else {
        let Some((detected, parsed)) = parse_structured_content(path, &content) else {
            let format = detect_format(path, &content);
            if format == StructuredFormat::Unknown {
                anyhow::bail!(
                    "File is not a recognized structured format (expected JSON/YAML/TOML/plist/PKG-INFO/LNK/systemd manifest, OLE2/OOXML office document, RTF, PDF, or PE/ELF/Mach-O binary): {}",
                    target
                );
            }
            anyhow::bail!("Detected {:?} but failed to parse: {}", format, target);
        };
        (detected, parsed)
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

    format_output(&entries, target, &detected, format)
}

/// Flatten a JSON value into `path: leaf` entries using kv-path syntax.
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

fn format_output(
    entries: &[KvEntry],
    target: &str,
    detected: &StructuredFormat,
    format: &cli::OutputFormat,
) -> Result<String> {
    match format {
        cli::OutputFormat::Json | cli::OutputFormat::Jsonl => {
            Ok(serde_json::to_string_pretty(entries)?)
        }
        cli::OutputFormat::Terminal | cli::OutputFormat::Tiny => {
            let mut out = String::new();
            out.push_str(&format!(
                "Extracted {} key/value pairs from {} ({:?})\n\n",
                entries.len(),
                target,
                detected
            ));
            out.push_str("# Paths use kv-path syntax (type: kv, path: <path>)\n\n");
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

/// Run the appropriate binary analyzer (PE / ELF / Mach-O) end-to-
/// end and return the synthesized kv tree from `report.kv_tree`.
/// Returns `None` for non-binary input or when the analyzer fails.
///
/// This is heavier than the document kv extractors because the
/// binary metrics need a structural analysis pass to populate the
/// fields the kv builder reads — the analyzer crate doesn't yet
/// expose a metrics-only fast path.  Acceptable for `cleave kv`
/// (interactive trait-authoring tool); real analysis flows
/// already go through the same path and pay the cost once.
fn extract_binary_kv_via_analyzer(path: &Path, content: &[u8]) -> Option<Value> {
    let detected = analyzers::detect_file_type_from_data(path, content);
    if !matches!(detected, FileType::Pe | FileType::Elf | FileType::MachO) {
        return None;
    }
    let analyzer = analyzers::analyzer_for_file_type(&detected, None)?;
    let mut report = analyzer.analyze(path).ok()?;
    // The analyzer's `analyze()` trait method is shorter than the
    // full lib.rs pipeline — it doesn't run the binary_kv +
    // binary_extractors hooks.  Invoke them here so `cleave kv`
    // returns the same kv tree that `cleave analyze` would emit
    // (including the augmenting `.comment` / sanitizer detections
    // layered onto the metrics-derived base).
    binary_kv::attach_to_report(&mut report);
    analyzers::binary_extractors::augment_report(&mut report, content);
    report.kv_tree.as_deref().cloned()
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
