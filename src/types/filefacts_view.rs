//! Cleave's report-side mirror of filefacts's typed views.
//!
//! Schema v4 (cleave) ships filefacts v6's output verbatim under
//! `filefacts: ...` so downstream consumers can navigate
//! `filefacts.values.pe.signatures[0]` and friends without going through
//! cleave's projection structs.
//!
//! The fields are held as `serde_json::Value` (rather than the strongly
//! typed filefacts structs) because cleave's `AnalysisReport` derives
//! `Deserialize` for its on-disk cache. Even though filefacts v6 now
//! uses `String` (not `&'static str`) for `source` fields and would
//! deserialize cleanly, JSON Values keep cleave's report independent of
//! filefacts version drift — a forward-compatible field that filefacts
//! adds shows up automatically without a cleave rebuild.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Report-side projection of `filefacts::ParsedFile`'s typed views.
///
/// Built from an [`AnalysisContext`](crate::analysis_context::AnalysisContext)
/// via [`FilefactsView::from_ctx`]. Every field is `skip_serializing_if`-elided
/// when empty so binary-only fields don't appear in source-file
/// reports and vice versa.
///
/// The eight-key flat shape mirrors filefacts v6's public output:
/// `values`, `metrics`, `sections`, `symbols`, `text`, `literals`,
/// `errors`. There is no `ast` field — calls / members / binds live
/// inside `symbols` tagged by kind.
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
    /// Section / segment table — see `filefacts::Section`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sections: Vec<serde_json::Value>,
    /// Unified named-entity facts (imports, exports, functions, calls,
    /// members, binds, identifiers) tagged by kind. See
    /// `filefacts::Symbol`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub symbols: Vec<serde_json::Value>,
    /// Byte-scan extracted text runs — ascii + utf16le partitions.
    /// See `filefacts::Text`.
    #[serde(skip_serializing_if = "is_null_or_empty_object", default)]
    pub text: serde_json::Value,
    /// Parser-extracted string literals from tree-sitter / structured
    /// parses. See `filefacts::Literals`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub literals: Vec<serde_json::Value>,
    /// Recoverable parse errors filefacts collected — see
    /// `filefacts::ParseError`.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<serde_json::Value>,
}

impl FilefactsView {
    /// Project an [`AnalysisContext`](crate::analysis_context::AnalysisContext)
    /// into the report-side shape by serializing each typed view to
    /// its canonical JSON form.
    ///
    /// The serializations cannot fail in practice — every filefacts
    /// view is built from owned data with no non-stringifiable
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
            symbols: serialize_to_array(parsed.symbols()),
            text: serde_json::to_value(parsed.text()).unwrap_or(serde_json::Value::Null),
            literals: serialize_to_array(parsed.literals()),
            errors: serialize_to_array(parsed.errors()),
        }
    }

    /// True when every field is empty. Used by callers that want to
    /// skip attaching a `FilefactsView` to a report when filefacts
    /// produced nothing of substance.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        is_null_or_empty_object(&self.values)
            && self.metrics.is_empty()
            && self.sections.is_empty()
            && self.symbols.is_empty()
            && is_null_or_empty_object(&self.text)
            && self.literals.is_empty()
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
            sections: vec![json!({
                "name": ".text",
                "vaddr": 4096,
                "file_offset": 1024,
                "file_size": 8192,
                "flags": ["readable", "executable"]
            })],
            symbols: Vec::new(),
            text: serde_json::Value::Null,
            literals: Vec::new(),
            errors: Vec::new(),
        };

        let json_str = serde_json::to_string(&view).expect("serialize");
        let round_tripped: FilefactsView = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(round_tripped.values, view.values);
        assert_eq!(round_tripped.metrics, view.metrics);
        assert_eq!(round_tripped.sections, view.sections);
        assert!(round_tripped.symbols.is_empty());
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
    fn filefacts_view_from_ctx_populates_symbols_for_source() {
        let path = std::path::Path::new("sample.js");
        let bytes = b"function main() { fetch(\"https://example.com\"); }";
        let ctx = crate::analysis_context::AnalysisContext::open(path, bytes)
            .expect("filefacts opens JS fixture");

        let view = FilefactsView::from_ctx(&ctx);
        let call_target = view
            .symbols
            .iter()
            .filter(|s| s.get("kind").and_then(|k| k.as_str()) == Some("call"))
            .find_map(|s| s.get("target").and_then(|t| t.as_str()).map(str::to_string));
        assert_eq!(call_target.as_deref(), Some("fetch"));
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
