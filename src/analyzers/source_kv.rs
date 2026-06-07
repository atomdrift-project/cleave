//! `source.*` kv subtree — pivots the unified analyzer's already-
//! extracted imports / exports / functions / strings into a kv
//! shape so trait authors can ask aggregate questions ("does this
//! file import both X and Y?") without walking each `Import` /
//! `Export` entry. Cheap: no new tree-sitter queries.
//!
//! Schema is the [`SourceKv`] struct.

use crate::types::AnalysisReport;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;

/// Maximum string-constant entries to surface. Caps the per-file kv
/// payload so a script with thousands of literals doesn't bloat the
/// trait-evaluation cost.
const MAX_STRING_CONSTANTS: usize = 256;

/// Minimum string length to surface — filters out single-char and
/// noise strings that aren't useful for trait matching.
const MIN_STRING_LEN: usize = 6;

/// Build a `source.*` subtree from the imports/exports/functions
/// already populated on `report`, plus optional string-constant
/// extraction from `report.strings` and shebang detection from the
#[derive(Default, Serialize)]
struct SourceKv {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    imports: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    import_libraries: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    has_imports: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    exports: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    has_exports: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    functions: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    strings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shebang: Option<String>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

/// Build the `source.*` subtree from `report.imports` / `exports` /
/// `functions` / `strings` plus the leading shebang in `content`
/// (when supplied). Returns `None` when no source data is present.
#[must_use]
pub(crate) fn build_source_kv(report: &AnalysisReport, content: Option<&[u8]>) -> Option<Value> {
    let mut kv = SourceKv::default();

    if !report.imports.is_empty() {
        let mut symbols: BTreeSet<&str> = BTreeSet::new();
        let mut libraries: BTreeSet<&str> = BTreeSet::new();
        for imp in &report.imports {
            symbols.insert(imp.symbol.as_str());
            if let Some(lib) = imp.library.as_deref()
                && !lib.is_empty()
            {
                libraries.insert(lib);
            }
        }
        if !symbols.is_empty() {
            kv.imports = symbols.iter().map(|s| (*s).to_string()).collect();
            kv.has_imports = true;
        }
        kv.import_libraries = libraries.iter().map(|s| (*s).to_string()).collect();
    }

    if !report.exports.is_empty() {
        let symbols: BTreeSet<&str> = report.exports.iter().map(|e| e.symbol.as_str()).collect();
        if !symbols.is_empty() {
            kv.exports = symbols.iter().map(|s| (*s).to_string()).collect();
            kv.has_exports = true;
        }
    }

    if !report.functions.is_empty() {
        let names: BTreeSet<&str> = report
            .functions
            .iter()
            .map(|f| f.name.as_str())
            .filter(|s| !s.is_empty())
            .collect();
        kv.functions = names.iter().map(|s| (*s).to_string()).collect();
    }

    if !report.strings.is_empty() {
        let mut strings: BTreeSet<&str> = BTreeSet::new();
        for s in &report.strings {
            if s.value.len() >= MIN_STRING_LEN && strings.len() < MAX_STRING_CONSTANTS {
                strings.insert(s.value.as_str());
            }
        }
        kv.strings = strings.iter().map(|s| (*s).to_string()).collect();
    }

    if let Some(bytes) = content {
        kv.shebang = parse_shebang(bytes);
    }

    let value = serde_json::to_value(kv).ok()?;
    if value.as_object().is_some_and(serde_json::Map::is_empty) {
        None
    } else {
        Some(value)
    }
}

/// Parse a `#!/path/to/interpreter [args]` shebang line, returning
/// the full directive (without the leading `#!` and trailing newline).
/// Returns `None` when the file doesn't start with `#!` or the line
/// is unparseably long.
fn parse_shebang(content: &[u8]) -> Option<String> {
    if content.len() < 4 || &content[..2] != b"#!" {
        return None;
    }
    let end = content[2..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| 2 + p)
        .unwrap_or(content.len())
        .min(2 + 256);
    let line = &content[2..end];
    let s = std::str::from_utf8(line).ok()?.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}

/// Stash the synthesized source kv tree on `report.values_tree`.
/// Idempotent: when no source data is present (binary-only file),
/// `report.values_tree` is left untouched.
pub(crate) fn attach_to_report(report: &mut AnalysisReport, content: Option<&[u8]>) {
    if let Some(source) = build_source_kv(report, content) {
        report.merge_kv_subtree("source", source);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::types::{AnalysisReport, Function, Import, TargetInfo};
    use serde_json::json;

    fn empty_report() -> AnalysisReport {
        AnalysisReport::new(TargetInfo {
            path: "test.py".into(),
            file_type: "python".into(),
            size_bytes: 0,
            sha256: "0".repeat(64),
            architectures: None,
        })
    }

    #[test]
    fn empty_report_yields_none() {
        let r = empty_report();
        assert!(build_source_kv(&r, None).is_none());
    }

    #[test]
    fn imports_surface_sorted_and_distinct() {
        let mut r = empty_report();
        r.imports.push(Import::new("requests", Some("test".into())));
        r.imports.push(Import::new("os", Some("test".into())));
        r.imports.push(Import::new("os", Some("test".into())));
        let v = build_source_kv(&r, None).expect("non-empty");
        let imports = v["imports"].as_array().unwrap();
        let names: Vec<&str> = imports.iter().filter_map(|x| x.as_str()).collect();
        assert_eq!(names, vec!["os", "requests"]);
        assert_eq!(v["has_imports"], json!(true));
        let libs = v["import_libraries"].as_array().unwrap();
        assert_eq!(libs.len(), 1);
    }

    fn make_function(name: &str) -> Function {
        // Use serde to construct without naming all 14 fields by hand.
        let json = serde_json::json!({"name": name});
        serde_json::from_value(json).expect("function default")
    }

    #[test]
    fn functions_surface() {
        let mut r = empty_report();
        r.functions.push(make_function("main"));
        r.functions.push(make_function("helper"));
        let v = build_source_kv(&r, None).expect("non-empty");
        let names: Vec<&str> = v["functions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x.as_str())
            .collect();
        assert_eq!(names, vec!["helper", "main"]);
    }

    #[test]
    fn attach_preserves_existing_kv() {
        let mut r = empty_report();
        r.imports.push(Import::new("requests", None));
        r.values_tree = Some(Box::new(json!({"existing": "value"})));
        attach_to_report(&mut r, None);
        let kv = r.values_tree.as_ref().unwrap();
        assert_eq!(kv["existing"], "value");
        assert!(kv["source"].is_object());
        assert!(kv["source"]["imports"].is_array());
    }

    #[test]
    fn shebang_extracted() {
        let r = empty_report();
        let v = build_source_kv(&r, Some(b"#!/usr/bin/env python3\nprint('hi')\n"))
            .expect("shebang only");
        assert_eq!(v["shebang"], "/usr/bin/env python3");
    }

    #[test]
    fn shebang_absent_returns_none() {
        let r = empty_report();
        assert!(build_source_kv(&r, Some(b"print('hi')\n")).is_none());
    }
}
