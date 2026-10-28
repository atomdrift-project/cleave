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
    /// Typed, policy-free value links, independent of the producing format.
    /// None means unavailable, not an empty graph or a clean verdict.
    /// Dropped after member evaluation in compact mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<filefacts::Flow>,
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
        Self::from_ctx_with_values(ctx, ctx.parsed.values().as_json().clone())
    }

    /// Project a context for a report that will be folded into compact output.
    ///
    /// Compact files serialize structural values through their flattened `kv`
    /// facts, so retaining the complete native tree here duplicates that data.
    /// Dependency identity/scripts, runtime imports, and Maven coverage gaps
    /// have post-evaluation readers; the remaining fields are still required by the
    /// symbol/flow evaluators and compact reference projection.
    #[must_use]
    pub(crate) fn from_ctx_compact(ctx: &crate::analysis_context::AnalysisContext<'_>) -> Self {
        Self::from_ctx_with_values(
            ctx,
            retained_dependency_values(ctx.parsed.values().as_json()),
        )
    }

    fn from_ctx_with_values(
        ctx: &crate::analysis_context::AnalysisContext<'_>,
        values: serde_json::Value,
    ) -> Self {
        let parsed = &ctx.parsed;
        Self {
            flow: parsed.flow().cloned(),
            values,
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
            && self.flow.is_none()
            && self.symbols.is_empty()
            && self.errors.is_empty()
            && self.references.is_empty()
    }

    /// Release native values with no compact-output reader after evaluation.
    pub(crate) fn retain_compact_values(&mut self) {
        self.values = retained_dependency_values(&self.values);
    }
}

pub(super) fn retained_dependency_values(tree: &serde_json::Value) -> serde_json::Value {
    let mut npm = serde_json::Map::new();
    for key in ["name", "version", "scripts"] {
        if let Some(value) = tree.get("npm").and_then(|npm| npm.get(key)) {
            npm.insert(key.to_owned(), value.clone());
        }
    }
    let mut retained = serde_json::Map::new();
    // Typed references carry resolved declarations; unsupported POM model
    // operations must also survive compact archive reports as coverage gaps.
    if let Some(gaps) = tree.pointer("/jar/pom/dependency_gaps") {
        retained.insert(
            "jar".into(),
            serde_json::json!({"pom":{"dependency_gaps":gaps}}),
        );
    }
    if !npm.is_empty() {
        retained.insert("npm".into(), serde_json::Value::Object(npm));
    }
    if let Some(imports) = tree.pointer("/source/js/runtime_imports") {
        retained.insert(
            "source".into(),
            serde_json::json!({"js": {"runtime_imports": imports}}),
        );
    }
    // Fixed Batch program recipes need their complete source after archive or
    // decoded-layer folding. Never retain unrelated source/Batch properties.
    for key in ["command_sites", "command_sites_truncated"] {
        if let Some(value) = tree.pointer(&format!("/source/batch/{key}")) {
            let source = retained
                .entry("source")
                .or_insert_with(|| serde_json::json!({}));
            if let Some(source) = source.as_object_mut() {
                let batch = source
                    .entry("batch")
                    .or_insert_with(|| serde_json::json!({}));
                if let Some(batch) = batch.as_object_mut() {
                    batch.insert(key.to_owned(), value.clone());
                }
            }
        }
    }
    // PE augmentation reads this path after the view is attached so it can
    // derive a high-confidence builder username. Keep it through evaluation;
    // compact folding drops it with the other non-dependency values later.
    if let Some(path) = tree
        .get("pe")
        .and_then(|pe| pe.get("debug"))
        .and_then(|debug| debug.get("pdb"))
        .and_then(|pdb| pdb.get("path"))
    {
        retained.insert(
            "pe".into(),
            serde_json::json!({"debug": {"pdb": {"path": path}}}),
        );
    }
    if retained.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::Value::Object(retained)
    }
}

fn is_null_or_empty_object(v: &serde_json::Value) -> bool {
    v.is_null() || v.as_object().is_some_and(serde_json::Map::is_empty)
}

/// Retain only the source-AST symbol kinds — `Call`, `Member`, `Bind`,
/// `Identifier` — that the `type: symbol, kind: …` evaluators read back from
/// this view. Python imports and Ruby process-method definitions also have
/// post-fold dependency readers: compact members drop the ordinary import and
/// function vectors. Other Import/Export/Function records are already carried
/// by the report; do not duplicate native symbol tables here.
fn retained_symbols(parsed: &filefacts::ParsedFile<'_>) -> Vec<filefacts::Symbol> {
    let file_type = parsed.fileid().file_type();
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
            ) || (file_type == filefacts::FileType::Python && matches!(s, filefacts::Symbol::Import { .. }))
                || (file_type == filefacts::FileType::Ruby && matches!(s, filefacts::Symbol::Function { name, .. } if matches!(name.as_str(), "system" | "exec")))
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
    fn compact_values_keep_runtime_imports_without_unrelated_source_values() {
        let tree = serde_json::json!({"source":{"js":{"runtime_imports":[{"specifier":"axios","offset":4}]},"other":"discard"}});
        let retained = retained_dependency_values(&tree);
        assert_eq!(
            retained
                .pointer("/source/js/runtime_imports/0/specifier")
                .and_then(|v| v.as_str()),
            Some("axios")
        );
        assert!(retained.pointer("/source/other").is_none());
    }

    #[test]
    fn compact_values_keep_batch_program_source_and_coverage_after_roundtrip() {
        let tree = serde_json::json!({"source":{"batch":{
            "command_sites":[{"name":"mshta", "text":"mshta https://program.test/a.hta", "offset":0,"name_offset":0,"name_end":5}],
            "command_sites_truncated":true, "unrelated":"discard"}, "other":"discard"}});
        let retained = retained_dependency_values(&tree);
        let view = FilefactsView {
            values: retained,
            ..Default::default()
        };
        let view: FilefactsView =
            serde_json::from_slice(&serde_json::to_vec(&view).unwrap()).unwrap();
        assert_eq!(
            view.values.pointer("/source/batch/command_sites/0/name"),
            Some(&"mshta".into())
        );
        assert_eq!(
            view.values.pointer("/source/batch/command_sites_truncated"),
            Some(&true.into())
        );
        assert!(view.values.pointer("/source/batch/unrelated").is_none());
        assert!(view.values.pointer("/source/other").is_none());
    }

    #[test]
    fn compact_values_preserve_maven_coverage_gaps_without_duplicate_declarations() {
        let mut view = FilefactsView {
            values: serde_json::json!({"jar":{"pom":{
                "group_id":"g", "dependencies":[{"purl":"pkg:maven/g/a@1"}],
                "dependency_gaps":[{"member":"META-INF/maven/g/a/pom.xml","reason":"version unresolved"}]
            }}}),
            ..Default::default()
        };
        view.retain_compact_values();
        assert_eq!(
            view.values
                .pointer("/jar/pom/dependency_gaps/0/reason")
                .and_then(|v| v.as_str()),
            Some("version unresolved")
        );
        assert!(view.values.pointer("/jar/pom/dependencies").is_none());
        assert!(view.values.pointer("/jar/pom/group_id").is_none());
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
        let ctx = crate::analysis_context::AnalysisContext::open(path, bytes);

        let view = FilefactsView::from_ctx(&ctx);
        let call_target = view.symbols.iter().find_map(|s| match s {
            filefacts::Symbol::Call {
                target: Some(t), ..
            } => Some(t.clone()),
            _ => None,
        });
        assert_eq!(call_target.as_deref(), Some("fetch"));
        let flow = view.flow.as_ref().expect("source flow available");
        assert_eq!(flow.producer, "tree-sitter");
        let json = serde_json::to_value(&view).expect("serialize flow");
        assert!(json.get("flow").is_some());
        let decoded: FilefactsView = serde_json::from_value(json).expect("deserialize flow");
        assert_eq!(decoded.flow.unwrap().values.len(), flow.values.len());
    }
}
