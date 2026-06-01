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
    /// Structural key-value tree (`pe.*`, `elf.*`, `macho.*`, …). Mirrors
    /// `ctx.parsed.values()`. Retained because host-PE detectors read
    /// `pe.signatures[*].subject` and `pe.debug.pdb.path` from it. Small for
    /// source members (no binary tree).
    #[serde(skip_serializing_if = "is_null_or_empty_object", default)]
    pub values: serde_json::Value,
    /// Call and member-access symbols, held as typed `filefacts::Symbol`
    /// (not `serde_json::Value`) so the per-symbol heap cost is the typed
    /// payload rather than a JSON map with duplicated string keys — the
    /// dominant per-member retention on source-heavy archives. Only `Call`
    /// (read by `eval_call`, emitted as `ff.ct`) and `Member` (`ff.mc`) are
    /// retained; other kinds are read from the typed `FileAnalysis` fields or
    /// unused. Serializes to the same `{"kind": ...}` JSON shape as before.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub symbols: Vec<filefacts::Symbol>,
    /// Recoverable parse errors filefacts collected — see
    /// `filefacts::ParseError`. Emitted in compact output.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<serde_json::Value>,
}

impl FilefactsView {
    /// Project an [`AnalysisContext`](crate::analysis_context::AnalysisContext)
    /// into the report-side shape.
    ///
    /// Only the fields downstream actually consumes are retained: call/member
    /// symbols (eval + `ff.ct`/`ff.mc`) and parse errors. The former
    /// `values`/`metrics`/`sections`/`literals`/`text` mirrors were dead
    /// weight — `kv`/strings/metrics/sections reach output and the trait
    /// engine through the typed `FileAnalysis` fields, not this view.
    #[must_use]
    pub fn from_ctx(ctx: &crate::analysis_context::AnalysisContext<'_>) -> Self {
        let parsed = &ctx.parsed;
        Self {
            values: parsed.values().as_json().clone(),
            symbols: retained_symbols(parsed),
            errors: serialize_to_array(parsed.errors()),
        }
    }

    /// True when every field is empty. Used by callers that want to
    /// skip attaching a `FilefactsView` to a report when filefacts
    /// produced nothing of substance.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        is_null_or_empty_object(&self.values) && self.symbols.is_empty() && self.errors.is_empty()
    }
}

fn is_null_or_empty_object(v: &serde_json::Value) -> bool {
    v.is_null() || v.as_object().is_some_and(serde_json::Map::is_empty)
}

/// Mirror every symbol kind filefacts extracted. Source-AST projections —
/// `call`, `member`, `bind`, `identifier` — are all matchable by the
/// `type: symbol, kind: …` trait evaluators (the targets `query:` rules
/// migrate onto), so retaining them is what makes those migrations fire.
/// Imports/exports/functions are also read from the typed `FileAnalysis`
/// fields, but keeping them here too costs little and keeps the view a
/// faithful mirror of `parsed.symbols()`.
fn retained_symbols(parsed: &filefacts::ParsedFile<'_>) -> Vec<filefacts::Symbol> {
    parsed.symbols().iter().cloned().collect()
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn filefacts_view_round_trips_through_serde_json() {
        let view = FilefactsView {
            symbols: vec![filefacts::Symbol::Member {
                path: "window.localStorage".to_string(),
            }],
            ..Default::default()
        };

        let json_str = serde_json::to_string(&view).expect("serialize");
        let round_tripped: FilefactsView = serde_json::from_str(&json_str).expect("deserialize");
        assert_eq!(round_tripped.symbols.len(), 1);
        assert!(round_tripped.errors.is_empty());
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
        let call_target = view.symbols.iter().find_map(|s| match s {
            filefacts::Symbol::Call {
                target: Some(t), ..
            } => Some(t.clone()),
            _ => None,
        });
        assert_eq!(call_target.as_deref(), Some("fetch"));
    }
}
