//! Cleave's report-side mirror of expose's typed views.
//!
//! Schema v3.0 ships expose's output verbatim under `expose: ...` so
//! downstream consumers can navigate `expose.values.pe.signatures[0]`
//! and friends without going through cleave's projection structs. The
//! `sections` / `imports` / `exports` / `functions` / `errors` lists
//! are held as `serde_json::Value` (rather than the strongly-typed
//! expose structs) because cleave's `AnalysisReport` derives
//! `Deserialize` for its on-disk cache and expose's types use
//! `&'static str` for the `source` field — incompatible with
//! deserialization. The JSON shape is byte-identical to expose's
//! native serialization.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Report-side projection of `expose::ParsedFile`'s typed views.
///
/// Built from an [`AnalysisContext`](crate::analysis_context::AnalysisContext)
/// via [`ExposeView::from_ctx`]. Every field is `skip_serializing_if`-elided
/// when empty so binary-only fields don't appear in source-file
/// reports and vice versa.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExposeView {
    /// Structural key-value tree (`pe.*`, `elf.*`, `macho.*`,
    /// `lnk.*`, `pdf.*`, …). Mirrors `ctx.parsed.values()`.
    #[serde(skip_serializing_if = "is_null_or_empty_object", default)]
    pub values: serde_json::Value,
    /// Flat metric map (`pe.import_count`, `binary.section_count`,
    /// `text.char_entropy`, …). Mirrors `ctx.parsed.metrics()`.
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub metrics: BTreeMap<String, f64>,
    /// Section / segment table — see `expose::Section`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sections: Vec<serde_json::Value>,
    /// Imported symbols — see `expose::Import`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub imports: Vec<serde_json::Value>,
    /// Locally-defined exported symbols — see `expose::Export`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub exports: Vec<serde_json::Value>,
    /// Functions defined in the file — see `expose::Function`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub functions: Vec<serde_json::Value>,
    /// Recoverable parse errors expose collected — see `expose::ParseError`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<serde_json::Value>,
}

impl ExposeView {
    /// Project an [`AnalysisContext`](crate::analysis_context::AnalysisContext)
    /// into the report-side shape by serializing each typed view to
    /// its canonical JSON form.
    ///
    /// The serializations below cannot fail in practice — every
    /// expose view is built from owned data with no non-stringifiable
    /// `Map<_, _>` keys — but if `serde_json::to_value` ever returns
    /// an error the affected list is left empty rather than
    /// propagating the failure into the report.
    #[must_use]
    pub fn from_ctx(ctx: &crate::analysis_context::AnalysisContext<'_>) -> Self {
        let parsed = &ctx.parsed;
        Self {
            values: parsed.values().as_json().clone(),
            metrics: parsed.metrics().as_map().clone(),
            sections: serialize_to_array(parsed.sections()),
            imports: serialize_to_array(parsed.imports()),
            exports: serialize_to_array(parsed.exports()),
            functions: serialize_to_array(parsed.functions()),
            errors: serialize_to_array(parsed.errors()),
        }
    }

    /// True when every list and the values tree are empty. Used by
    /// callers that want to skip attaching an `ExposeView` to a
    /// report when expose produced nothing of substance.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        is_null_or_empty_object(&self.values)
            && self.metrics.is_empty()
            && self.sections.is_empty()
            && self.imports.is_empty()
            && self.exports.is_empty()
            && self.functions.is_empty()
            && self.errors.is_empty()
    }
}

/// Serialize a `#[serde(transparent)] Vec<T>` wrapper (e.g.
/// `expose::Sections`) to a `Vec<serde_json::Value>` matching the
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
    use super::*;
    use serde_json::json;

    #[test]
    fn expose_view_round_trips_through_serde_json() {
        let mut metrics = BTreeMap::new();
        metrics.insert("pe.import_count".to_string(), 42.0);
        metrics.insert("binary.section_count".to_string(), 5.0);
        let view = ExposeView {
            values: json!({ "pe": { "machine": "x86_64" } }),
            metrics,
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
        let round_tripped: ExposeView = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(round_tripped.values, view.values);
        assert_eq!(round_tripped.metrics, view.metrics);
        assert_eq!(round_tripped.sections, view.sections);
        assert!(round_tripped.imports.is_empty());
    }

    #[test]
    fn expose_view_is_empty_for_default() {
        assert!(ExposeView::default().is_empty());
    }

    #[test]
    fn expose_view_serializes_with_skip_empty() {
        let empty = ExposeView::default();
        let json_str = serde_json::to_string(&empty).expect("serialize");
        assert_eq!(
            json_str, "{}",
            "default ExposeView should serialize to an empty object"
        );
    }

    #[test]
    fn expose_view_from_ctx_populates_values_for_test_pe() {
        let path = std::path::Path::new("tests/fixtures/test.exe");
        let bytes = std::fs::read(path).expect("PE fixture present");
        let ctx = crate::analysis_context::AnalysisContext::open(path, &bytes)
            .expect("expose opens PE fixture");

        let view = ExposeView::from_ctx(&ctx);

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

        let import_count = view.metrics.get("pe.import_count").copied().unwrap_or(0.0);
        assert!(
            import_count > 0.0,
            "pe.import_count metric should be > 0 for test PE fixture"
        );
    }
}
