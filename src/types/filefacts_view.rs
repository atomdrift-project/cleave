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
    /// Source-AST symbols only — `Call`, `Member`, `Bind`, `Identifier` —
    /// held as typed `filefacts::Symbol`. These are the four kinds the
    /// `type: symbol, kind: …` evaluators read back from this view (`eval_call`
    /// for `Call`, `eval_symbol_fact` for the rest). `Import`/`Export`/`Function`
    /// are deliberately NOT mirrored here: they already live in the typed
    /// `report.{imports,exports,functions}` fields, and the symbol-match index +
    /// offset map read them from there — so mirroring them was a pure duplicate
    /// of the (often huge) binary symbol table on every analyzed member.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub symbols: Vec<filefacts::Symbol>,
    /// Recoverable parse errors filefacts collected — see
    /// `filefacts::ParseError`. Emitted in compact output.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<serde_json::Value>,
    /// External references this file's content *declares* — package
    /// dependencies, lockfile pins, `.SRCINFO` `source=` URLs — as parsed by
    /// filefacts. An intrinsic content fact, carried per file (including archive
    /// members) so a downstream composer (scan + fletch) can fetch and scan
    /// them without re-extracting member bytes. Imperative/undeclared discovery
    /// (install-hook `curl|sh`, npm `scripts`) is fletch's job and is not
    /// surfaced here — only what filefacts declares.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub references: Vec<filefacts::Reference>,
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
            references: parsed.references().to_vec(),
        }
    }

    /// True when every field is empty. Used by callers that want to
    /// skip attaching a `FilefactsView` to a report when filefacts
    /// produced nothing of substance.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        is_null_or_empty_object(&self.values)
            && self.symbols.is_empty()
            && self.errors.is_empty()
            && self.references.is_empty()
    }
}

fn is_null_or_empty_object(v: &serde_json::Value) -> bool {
    v.is_null() || v.as_object().is_some_and(serde_json::Map::is_empty)
}

/// Retain only the source-AST symbol kinds — `Call`, `Member`, `Bind`,
/// `Identifier` — that the `type: symbol, kind: …` evaluators read back from
/// this view. `Import`/`Export`/`Function` are dropped: they're already carried
/// by `report.{imports,exports,functions}`, so mirroring them here duplicated
/// the entire binary symbol table (thousands of entries) on every member.
fn retained_symbols(parsed: &filefacts::ParsedFile<'_>) -> Vec<filefacts::Symbol> {
    parsed
        .symbols()
        .iter()
        .filter(|s| {
            matches!(
                s,
                filefacts::Symbol::Call { .. }
                    | filefacts::Symbol::Member { .. }
                    | filefacts::Symbol::Bind { .. }
                    | filefacts::Symbol::Identifier { .. }
            )
        })
        .cloned()
        .collect()
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
                offset: Some(0),
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
