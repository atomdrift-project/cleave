//! Source-code kv-tree synthesis. Surfaces structured AST data
//! (imports, exports, function names, decorators) as `source.*`
//! kv paths so YAML traits can target them precisely.
//!
//! Designed to be cheap: every value here is already extracted by
//! the unified analyzer's tree-sitter walk; this module just
//! pivots the existing `report.imports` / `report.exports` /
//! `report.functions` vectors into a kv tree shape.
//!
//! No new tree-sitter queries are run.  If a value isn't already on
//! the report, it doesn't appear here — keeping the per-file kv
//! synthesis cost flat.
//!
//! ## Schema
//!
//! ```text
//! source:
//!   imports[]               sorted distinct import symbols
//!   exports[]               sorted distinct exported names
//!   functions[]             sorted distinct function names
//!   import_libraries[]      sorted distinct library names
//!                           (for languages where Import.library is
//!                            populated, e.g. Python `from X import Y`)
//!   has_imports             bool — at least one import present
//!   has_exports             bool — at least one named export
//! ```
//!
//! Trait authors can target precise call sites via the existing
//! `type: import`/`type: symbol` matchers; `source.*` is for
//! aggregate-shape questions ("does this binary import both X and
//! Y", "are there any exports at all", etc.) where kv-tree
//! traversal is cleaner than walking each Import/Export entry.

use crate::types::AnalysisReport;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// Build a `source.*` subtree from the imports/exports/functions
/// already populated on `report`. Returns `None` when none of those
/// vectors carry data (binary-only reports get `None` here, which is
/// correct — they have their own format-specific kv subtrees).
#[must_use]
pub(crate) fn build_source_kv(report: &AnalysisReport) -> Option<Value> {
    let mut out = Map::new();

    // Imports — sorted distinct symbols.
    if !report.imports.is_empty() {
        let mut symbols: BTreeSet<&str> = BTreeSet::new();
        let mut libraries: BTreeSet<&str> = BTreeSet::new();
        for imp in &report.imports {
            symbols.insert(imp.symbol.as_str());
            if let Some(lib) = imp.library.as_deref() {
                if !lib.is_empty() {
                    libraries.insert(lib);
                }
            }
        }
        if !symbols.is_empty() {
            let v: Vec<&&str> = symbols.iter().collect();
            out.insert("imports".into(), json!(v));
            out.insert("has_imports".into(), json!(true));
        }
        if !libraries.is_empty() {
            let v: Vec<&&str> = libraries.iter().collect();
            out.insert("import_libraries".into(), json!(v));
        }
    }

    // Exports — sorted distinct names.
    if !report.exports.is_empty() {
        let symbols: BTreeSet<&str> =
            report.exports.iter().map(|e| e.symbol.as_str()).collect();
        if !symbols.is_empty() {
            let v: Vec<&&str> = symbols.iter().collect();
            out.insert("exports".into(), json!(v));
            out.insert("has_exports".into(), json!(true));
        }
    }

    // Function names — sorted distinct.  `report.functions` is the
    // unified analyzer's per-file function list (tree-sitter
    // function_definition nodes).
    if !report.functions.is_empty() {
        let names: BTreeSet<&str> = report
            .functions
            .iter()
            .map(|f| f.name.as_str())
            .filter(|s| !s.is_empty())
            .collect();
        if !names.is_empty() {
            let v: Vec<&&str> = names.iter().collect();
            out.insert("functions".into(), json!(v));
        }
    }

    if out.is_empty() {
        None
    } else {
        Some(Value::Object(out))
    }
}

/// Stash the synthesized source kv tree on `report.kv_tree`.
/// Idempotent: when no source data is present (binary-only file),
/// `report.kv_tree` is left untouched.
pub(crate) fn attach_to_report(report: &mut AnalysisReport) {
    let Some(source) = build_source_kv(report) else {
        return;
    };
    let mut root = match report.kv_tree.take().map(|b| *b) {
        Some(Value::Object(m)) => m,
        Some(v) => {
            // Existing kv tree was a non-object value (shouldn't
            // happen, but defensive); stash it under `_legacy` so we
            // don't lose data.
            let mut m = Map::new();
            m.insert("_legacy".into(), v);
            m
        }
        None => Map::new(),
    };
    root.insert("source".into(), source);
    report.kv_tree = Some(Box::new(Value::Object(root)));
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::types::{AnalysisReport, Function, Import, TargetInfo};

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
        assert!(build_source_kv(&r).is_none());
    }

    #[test]
    fn imports_surface_sorted_and_distinct() {
        let mut r = empty_report();
        r.imports.push(Import::new("requests", Some("test".into()), "test"));
        r.imports.push(Import::new("os", Some("test".into()), "test"));
        r.imports.push(Import::new("os", Some("test".into()), "test"));
        let v = build_source_kv(&r).expect("non-empty");
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
        let v = build_source_kv(&r).expect("non-empty");
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
        r.imports.push(Import::new("requests", None, "test"));
        r.kv_tree = Some(Box::new(json!({"existing": "value"})));
        attach_to_report(&mut r);
        let kv = r.kv_tree.as_ref().unwrap();
        assert_eq!(kv["existing"], "value");
        assert!(kv["source"].is_object());
        assert!(kv["source"]["imports"].is_array());
    }
}
