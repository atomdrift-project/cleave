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
use crate::analyzers::class_kv;
use crate::analyzers::jar_kv;
use crate::analyzers::jpeg_kv;
use crate::analyzers::office::office_kv;
use crate::analyzers::pdf::pdf_kv;
use crate::analyzers::pickle_kv;
use crate::analyzers::png_kv;
use crate::analyzers::pyc_kv;
use crate::analyzers::rpm_kv;
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

    // Try the dispatch table first — each probe checks magic /
    // extension cheaply and parses on hit, wrapping the result in
    // its top-level kv namespace (`png`, `jpeg`, `class`, …).
    // Office / RTF / PDF return pre-namespaced trees so they're
    // tried first as standalone parsers.
    let (detected, parsed) = if let Some(office_value) =
        office_kv::extract_office_kv(path, &content)
    {
        (StructuredFormat::Json, office_value)
    } else if let Some(rtf_value) = rtf_kv::extract_rtf_kv(&content) {
        (StructuredFormat::Json, rtf_value)
    } else if let Some(pdf_value) = pdf_kv::extract_pdf_kv(&content) {
        (StructuredFormat::Json, pdf_value)
    } else if let Some(probe_value) = run_kv_probes(path, &content) {
        (StructuredFormat::Json, probe_value)
    } else if let Some(binary_value) = extract_binary_kv_via_analyzer(path, &content) {
        (StructuredFormat::Json, binary_value)
    } else if let Some(source_value) = extract_source_kv_via_analyzer(path, &content) {
        (StructuredFormat::Json, source_value)
    } else {
        let Some((detected, parsed)) = parse_structured_content(path, &content) else {
            let format = detect_format(path, &content);
            if format == StructuredFormat::Unknown {
                anyhow::bail!(
                    "File is not a recognized structured format (expected JSON/YAML/TOML/plist/PKG-INFO/LNK/systemd manifest, OLE2/OOXML office document, RTF, PDF, PE/ELF/Mach-O binary, or tree-sitter–supported source code): {}",
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
/// One probe in the kv-format dispatch table. `matches` runs first
/// (cheap magic / extension check); on hit, `parse` is invoked and
/// the resulting tree is wrapped as `{ namespace: tree }` so kv-paths
/// always read `<namespace>.<...>`.
struct KvProbe {
    namespace: &'static str,
    matches: fn(&Path, &[u8]) -> bool,
    parse: fn(&[u8]) -> Option<Value>,
}

/// Probes are tried in order; first match wins. Cheap magic checks
/// come before parsers that need extension help (pickle), so the hot
/// non-matching path stays a few byte comparisons.
const KV_PROBES: &[KvProbe] = &[
    KvProbe {
        namespace: "png",
        matches: starts_with_png,
        parse: parse_png,
    },
    KvProbe {
        namespace: "jpeg",
        matches: starts_with_jpeg,
        parse: parse_jpeg,
    },
    KvProbe {
        namespace: "class",
        matches: starts_with_class,
        parse: class_kv::extract,
    },
    KvProbe {
        namespace: "pyc",
        matches: looks_like_pyc,
        parse: pyc_kv::extract,
    },
    KvProbe {
        namespace: "rpm",
        matches: starts_with_rpm,
        parse: rpm_kv::extract,
    },
    KvProbe {
        namespace: "jar",
        matches: looks_like_jar,
        parse: jar_kv::extract_jar_kv,
    },
    KvProbe {
        namespace: "pickle",
        matches: looks_like_pickle,
        parse: pickle_kv::extract,
    },
];

fn run_kv_probes(path: &Path, content: &[u8]) -> Option<Value> {
    let probe = KV_PROBES.iter().find(|p| (p.matches)(path, content))?;
    let inner = (probe.parse)(content)?;
    let mut root = serde_json::Map::new();
    root.insert(probe.namespace.into(), inner);
    Some(Value::Object(root))
}

fn starts_with_png(_: &Path, content: &[u8]) -> bool {
    content.starts_with(b"\x89PNG\r\n\x1a\n")
}
fn starts_with_jpeg(_: &Path, content: &[u8]) -> bool {
    content.starts_with(&[0xFF, 0xD8])
}
fn starts_with_class(_: &Path, content: &[u8]) -> bool {
    content.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])
}
fn starts_with_rpm(_: &Path, content: &[u8]) -> bool {
    content.starts_with(&[0xED, 0xAB, 0xEE, 0xDB])
}
/// `.pyc` files start with a 2-byte magic word followed by `\r\n`;
/// the magic word varies per Python version (3-byte detection covers
/// every release we map in `pyc_kv`).
fn looks_like_pyc(path: &Path, content: &[u8]) -> bool {
    let ext_match = path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("pyc"));
    let magic_match = content.len() >= 4 && content[2] == 0x0D && content[3] == 0x0A;
    ext_match && magic_match
}
/// JAR / WAR / EAR are all ZIPs — accept either the magic + filename
/// hint or the analyzer's positive type detection.
fn looks_like_jar(path: &Path, content: &[u8]) -> bool {
    if !content.starts_with(b"PK\x03\x04") {
        return false;
    }
    let ext_match = path
        .extension()
        .and_then(|s| s.to_str())
        .is_some_and(|s| matches!(s.to_ascii_lowercase().as_str(), "jar" | "war" | "ear"));
    ext_match
        || matches!(
            analyzers::detect_file_type_from_data(path, content),
            FileType::Jar
        )
}
/// Pickle has no robust magic (protocol 0 is plain ASCII), so we gate
/// on extension only. Misclassified inputs are still handled cleanly
/// by `pickle_kv::extract` returning `None`.
fn looks_like_pickle(path: &Path, _: &[u8]) -> bool {
    path.extension().and_then(|s| s.to_str()).is_some_and(|e| {
        matches!(
            e.to_ascii_lowercase().as_str(),
            "pkl" | "pickle" | "joblib" | "pt"
        )
    })
}

/// Adapter: png_kv returns `(Value, StructuralCounts)`; the kv
/// command only wants the value.
fn parse_png(content: &[u8]) -> Option<Value> {
    png_kv::extract(content).map(|(v, _)| v)
}
fn parse_jpeg(content: &[u8]) -> Option<Value> {
    jpeg_kv::extract(content).map(|(v, _)| v)
}

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

/// Run the unified source-code analyzer (any tree-sitter–supported
/// language) and return the synthesized kv tree from `report.kv_tree`,
/// which the analyzer populates via `source_kv::attach_to_report`.
/// Returns `None` for non-source input or when the analyzer fails.
fn extract_source_kv_via_analyzer(path: &Path, content: &[u8]) -> Option<Value> {
    let detected = analyzers::detect_file_type_from_data(path, content);
    // Skip file types already handled upstream — binaries, archives,
    // structured documents, and the unknown bucket.  Anything else
    // routes through `UnifiedSourceAnalyzer` (or a generic fallback)
    // which attaches `source.*` and `metrics.*` to `report.kv_tree`.
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
