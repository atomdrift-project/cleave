//! Cleave's report-side mirror of filefacts's typed views.
//!
//! Schema v3.0 ships filefacts's output verbatim under `filefacts: ...` so
//! downstream consumers can navigate `filefacts.values.pe.signatures[0]`
//! and friends without going through cleave's projection structs. The
//! `sections` / `imports` / `exports` / `functions` / `errors` lists
//! are held as `serde_json::Value` (rather than the strongly-typed
//! filefacts structs) because cleave's `AnalysisReport` derives
//! `Deserialize` for its on-disk cache and filefacts's types use
//! `&'static str` for the `source` field — incompatible with
//! deserialization. The JSON shape is byte-identical to filefacts's
//! native serialization.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Report-side projection of `filefacts::ParsedFile`'s typed views.
///
/// Built from an [`AnalysisContext`](crate::analysis_context::AnalysisContext)
/// via [`FilefactsView::from_ctx`]. Every field is `skip_serializing_if`-elided
/// when empty so binary-only fields don't appear in source-file
/// reports and vice versa.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FilefactsView {
    /// Structural key-value tree (`pe.*`, `elf.*`, `macho.*`,
    /// `lnk.*`, `pdf.*`, …). Mirrors `ctx.parsed.values()`.
    #[serde(skip_serializing_if = "is_null_or_empty_object", default)]
    pub values: serde_json::Value,
    /// Flat metric map (`pe.import_count`, `binary.section_count`,
    /// `text.char_entropy`, …). Mirrors `ctx.parsed.metrics()`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub metrics: BTreeMap<String, f64>,
    /// AST projection - see filefacts::Ast.
    #[serde(skip_serializing_if = "is_null_or_empty_object", default)]
    pub ast: serde_json::Value,
    /// Section / segment table — see `filefacts::Section`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sections: Vec<serde_json::Value>,
    /// Imported symbols — see `filefacts::Import`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub imports: Vec<serde_json::Value>,
    /// Locally-defined exported symbols — see `filefacts::Export`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub exports: Vec<serde_json::Value>,
    /// Functions defined in the file — see `filefacts::Function`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub functions: Vec<serde_json::Value>,
    /// Recoverable parse errors filefacts collected — see `filefacts::ParseError`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<serde_json::Value>,
}

impl FilefactsView {
    /// Project an [`AnalysisContext`](crate::analysis_context::AnalysisContext)
    /// into the report-side shape by serializing each typed view to
    /// its canonical JSON form.
    ///
    /// The serializations below cannot fail in practice — every
    /// filefacts view is built from owned data with no non-stringifiable
    /// `Map<_, _>` keys — but if `serde_json::to_value` ever returns
    /// an error the affected list is left empty rather than
    /// propagating the failure into the report.
    #[must_use]
    pub fn from_ctx(ctx: &crate::analysis_context::AnalysisContext<'_>) -> Self {
        let parsed = &ctx.parsed;
        Self {
            values: parsed.values().as_json().clone(),
            metrics: parsed.metrics().as_map().clone(),
            ast: if parsed.ast().is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::to_value(parsed.ast()).unwrap_or(serde_json::Value::Null)
            },
            sections: serialize_to_array(parsed.sections()),
            imports: serialize_to_array(parsed.imports()),
            exports: serialize_to_array(parsed.exports()),
            functions: serialize_to_array(parsed.functions()),
            errors: serialize_to_array(parsed.errors()),
        }
    }

    /// True when every list and the values tree are empty. Used by
    /// callers that want to skip attaching an `FilefactsView` to a
    /// report when filefacts produced nothing of substance.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        is_null_or_empty_object(&self.values)
            && self.metrics.is_empty()
            && is_null_or_empty_object(&self.ast)
            && self.sections.is_empty()
            && self.imports.is_empty()
            && self.exports.is_empty()
            && self.functions.is_empty()
            && self.errors.is_empty()
    }
}

/// Serialize a `#[serde(transparent)] Vec<T>` wrapper (e.g.
/// `filefacts::Sections`) to a `Vec<serde_json::Value>` matching the
/// native JSON shape. Returns an empty Vec if serialization fails
/// or the value isn't an array — neither is expected in practice.
fn serialize_to_array<T: Serialize>(view: &T) -> Vec<serde_json::Value> {
    match serde_json::to_value(view) {
        Ok(serde_json::Value::Array(arr)) => arr,
        _ => Vec::new(),
    }
}

fn is_null_or_empty_object(v: &serde_json::Value) -> bool {
    v.is_null() || v.as_object().is_some_and(serde_json::Map::is_empty)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    #[test]
    fn filefacts_view_round_trips_through_serde_json() {
        let mut metrics = BTreeMap::new();
        metrics.insert("pe.import_count".to_string(), 42.0);
        metrics.insert("binary.section_count".to_string(), 5.0);
        let view = FilefactsView {
            values: json!({ "pe": { "machine": "x86_64" } }),
            metrics,
            ast: serde_json::Value::Null,
            sections: vec![json!({
                "name": ".text",
                "vaddr": 4096,
                "file_offset": 1024,
                "file_size": 8192,
                "flags": ["readable", "executable"]
            })],
            imports: Vec::new(),
            exports: Vec::new(),
            functions: Vec::new(),
            errors: Vec::new(),
        };

        let json_str = serde_json::to_string(&view).expect("serialize");
        let round_tripped: FilefactsView = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(round_tripped.values, view.values);
        assert_eq!(round_tripped.metrics, view.metrics);
        assert_eq!(round_tripped.sections, view.sections);
        assert!(round_tripped.imports.is_empty());
    }

    #[test]
    fn filefacts_view_is_empty_for_default() {
        assert!(FilefactsView::default().is_empty());
    }

    #[test]
    fn filefacts_view_serializes_with_skip_empty() {
        let empty = FilefactsView::default();
        let json_str = serde_json::to_string(&empty).expect("serialize");
        assert_eq!(
            json_str, "{}",
            "default FilefactsView should serialize to an empty object"
        );
    }

    #[test]
    fn filefacts_view_from_ctx_populates_ast_for_source() {
        let path = std::path::Path::new("sample.js");
        let bytes = b"function main() { fetch(\"https://example.com\"); }";
        let ctx = crate::analysis_context::AnalysisContext::open(path, bytes)
            .expect("filefacts opens JS fixture");

        let view = FilefactsView::from_ctx(&ctx);
        assert_eq!(
            view.ast
                .get("targets")
                .and_then(serde_json::Value::as_array)
                .and_then(|items| items.first())
                .and_then(serde_json::Value::as_str),
            Some("fetch")
        );
    }

    #[test]
    fn filefacts_view_from_ctx_populates_values_for_test_pe() {
        let path = std::path::Path::new("tests/fixtures/test.exe");
        let bytes = std::fs::read(path).expect("PE fixture present");
        let ctx = crate::analysis_context::AnalysisContext::open(path, &bytes)
            .expect("filefacts opens PE fixture");

        let view = FilefactsView::from_ctx(&ctx);

        let machine = view
            .values
            .get("pe")
            .and_then(|pe| pe.get("coff"))
            .and_then(|c| c.get("machine"))
            .or_else(|| view.values.get("pe").and_then(|pe| pe.get("machine")))
            .and_then(serde_json::Value::as_str);
        assert!(
            machine.is_some(),
            "pe.machine should be populated, got values={}",
            view.values
        );

        let import_count = view.metrics.get("imports.count").copied().unwrap_or(0.0);
        assert!(
            import_count > 0.0,
            "imports.count metric should be > 0 for test PE fixture"
        );
    }
}
