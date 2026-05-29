//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! End-to-end tests that `near_bytes` and `near_lines` proximity
//! constraints work for `type: symbol` conditions whose hits land in
//! `report.imports` — the tree-sitter call-site extraction path used
//! by Python, JavaScript, Ruby, etc.
//!
//! Before the fix, `extract_symbols_from_tree` deduped call sites into
//! a `HashSet<String>` and pushed `Import { offset: None }` entries, so
//! symbol evidence carried `location: "import"` with no resolvable byte
//! offset. Proximity checks silently dropped every candidate. The fix
//! emits one `Import` per call site with a byte offset, and
//! `eval_symbol` threads that offset onto `Evidence.offsets` so
//! `check_proximity_constraints` can colocate clustered calls.

#[cfg(test)]
mod proximity_scripting_symbols_tests {
    use crate::analyzers::FileType;
    use crate::analyzers::unified::UnifiedSourceAnalyzer;
    use crate::composite_rules::condition::SymbolKind;
    use crate::composite_rules::context::EvaluationContext;
    use crate::composite_rules::types::{FileType as CFileType, Platform};
    use crate::composite_rules::{Arch, CompositeTrait, Condition};
    use crate::types::{AnalysisReport, Criticality, Import, TargetInfo};
    use std::path::PathBuf;

    /// Parse `source` as Python and return the fully populated report
    /// (imports carry per-call-site offsets from tree-sitter).
    fn parse_python(source: &str) -> AnalysisReport {
        let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Python)
            .expect("python analyzer available");
        analyzer.analyze_source(&PathBuf::from("test.py"), source)
    }

    /// Build a composite rule whose `all:` conditions are `symbol`
    /// matchers restricted to `kind: import`. Proximity parameters are
    /// passed through verbatim so individual tests can tune them.
    fn symbol_cluster_rule(
        substrs: &[&str],
        near_bytes: Option<usize>,
        near_lines: Option<usize>,
    ) -> CompositeTrait {
        let conds: Vec<Condition> = substrs
            .iter()
            .map(|s| Condition::Symbol {
                exact: Some((*s).to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: Some(SymbolKind::Import),
                arg: None,
                not: None,
            })
            .collect();

        CompositeTrait {
            required_trait_indices: Vec::new(),
            id: "test/decoder-stub".to_string(),
            desc: "Clustered exec + decompress + decode (decoder stub)".to_string(),
            conf: 0.9,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![CFileType::All],
            for_from_groups: false,
            size_min: None,
            size_max: None,
            all: Some(conds),
            any: None,
            unless: None,
            not: None,
            downgrade: None,
            needs: None,
            near_lines,
            near_bytes,
            scope: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }
    }

    /// Clustered decoder stub: exec/zlib.decompress/b64decode sit within
    /// a single function body (tens of bytes apart).
    const CLUSTERED_PY: &str = r#"
import base64
import zlib

def decoder(payload):
    stage1 = base64.b64decode(payload)
    stage2 = zlib.decompress(stage1)
    exec(compile(stage2, '<mem>', 'exec'))
"#;

    /// Spread-out variant: same three calls, but separated by ~300
    /// lines of filler so no window under ~2KB can contain all three.
    fn spread_out_py() -> String {
        let filler = "x = 1\n".repeat(300);
        format!(
            "import base64\nimport zlib\n\n\
             stage1 = base64.b64decode(b'abc')\n\
             {filler}\
             stage2 = zlib.decompress(stage1)\n\
             {filler}\
             exec(compile(stage2, '<mem>', 'exec'))\n"
        )
    }

    // ---------------------------------------------------------------
    // 1. Structural: call-site imports carry byte offsets
    // ---------------------------------------------------------------

    #[test]
    fn call_sites_emit_per_site_imports_with_offsets() {
        let report = parse_python(CLUSTERED_PY);
        let ast_imports: Vec<&Import> = report
            .imports
            .iter()
            .filter(|i| i.source == "ast")
            .collect();

        // One entry per call site — no HashSet dedup. The sample has
        // exactly three AST-extracted calls (b64decode, decompress,
        // exec); `compile` nests inside `exec` and counts too.
        assert!(
            ast_imports.len() >= 3,
            "expected at least 3 call-site imports, got {}: {:?}",
            ast_imports.len(),
            ast_imports.iter().map(|i| &i.symbol).collect::<Vec<_>>()
        );

        // Every AST-extracted import carries a parseable hex offset.
        for imp in &ast_imports {
            let off = imp
                .offset
                .as_deref()
                .unwrap_or_else(|| panic!("missing offset on {}", imp.symbol));
            assert!(
                off.starts_with("0x"),
                "expected hex-prefixed offset, got {off:?} on {}",
                imp.symbol
            );
            assert!(
                u64::from_str_radix(off.trim_start_matches("0x"), 16).is_ok(),
                "offset {off:?} on {} should parse as hex",
                imp.symbol
            );
        }
    }

    // ---------------------------------------------------------------
    // 2. near_bytes
    // ---------------------------------------------------------------

    #[test]
    fn near_bytes_matches_clustered_decoder_stub() {
        let report = parse_python(CLUSTERED_PY);
        let data = CLUSTERED_PY.as_bytes().to_vec();
        let ctx = EvaluationContext::new(
            &report,
            &data,
            CFileType::Python,
            &[Platform::All],
            None,
            None,
        );

        // The three calls fit in ~120 bytes. A 300-byte window should
        // match; a 10-byte window should not.
        let pass = symbol_cluster_rule(
            &["exec", "base64.b64decode", "zlib.decompress"],
            Some(300),
            None,
        );
        assert!(
            pass.evaluate(&ctx).is_some(),
            "near_bytes: 300 should cluster exec/b64decode/decompress in the decoder stub"
        );

        let fail = symbol_cluster_rule(
            &["exec", "base64.b64decode", "zlib.decompress"],
            Some(10),
            None,
        );
        assert!(
            fail.evaluate(&ctx).is_none(),
            "near_bytes: 10 is narrower than the stub — must reject"
        );
    }

    #[test]
    fn near_bytes_rejects_spread_calls() {
        let source = spread_out_py();
        let report = parse_python(&source);
        let data = source.as_bytes().to_vec();
        let ctx = EvaluationContext::new(
            &report,
            &data,
            CFileType::Python,
            &[Platform::All],
            None,
            None,
        );

        let rule = symbol_cluster_rule(
            &["exec", "base64.b64decode", "zlib.decompress"],
            Some(500),
            None,
        );
        assert!(
            rule.evaluate(&ctx).is_none(),
            "near_bytes: 500 must reject when calls sit ~1800 bytes apart"
        );

        // But without proximity, the same three symbols still match
        // (sanity check — the rejection above is proximity-driven, not
        // a missing-symbol artifact).
        let no_proximity =
            symbol_cluster_rule(&["exec", "base64.b64decode", "zlib.decompress"], None, None);
        assert!(
            no_proximity.evaluate(&ctx).is_some(),
            "baseline: without near_bytes the rule should match on symbol presence alone"
        );
    }

    // ---------------------------------------------------------------
    // 3. near_lines
    // ---------------------------------------------------------------

    #[test]
    fn near_lines_matches_clustered_decoder_stub() {
        let report = parse_python(CLUSTERED_PY);
        let data = CLUSTERED_PY.as_bytes().to_vec();
        let ctx = EvaluationContext::new(
            &report,
            &data,
            CFileType::Python,
            &[Platform::All],
            None,
            None,
        );

        // The three calls span three consecutive lines inside decoder.
        let pass = symbol_cluster_rule(
            &["exec", "base64.b64decode", "zlib.decompress"],
            None,
            Some(5),
        );
        assert!(
            pass.evaluate(&ctx).is_some(),
            "near_lines: 5 should cluster calls that sit within 3 lines of each other"
        );

        let fail = symbol_cluster_rule(
            &["exec", "base64.b64decode", "zlib.decompress"],
            None,
            Some(1),
        );
        assert!(
            fail.evaluate(&ctx).is_none(),
            "near_lines: 1 is narrower than the 3-line stub — must reject"
        );
    }

    #[test]
    fn near_lines_rejects_spread_calls() {
        let source = spread_out_py();
        let report = parse_python(&source);
        let data = source.as_bytes().to_vec();
        let ctx = EvaluationContext::new(
            &report,
            &data,
            CFileType::Python,
            &[Platform::All],
            None,
            None,
        );

        let rule = symbol_cluster_rule(
            &["exec", "base64.b64decode", "zlib.decompress"],
            None,
            Some(20),
        );
        assert!(
            rule.evaluate(&ctx).is_none(),
            "near_lines: 20 must reject when calls sit ~300 lines apart"
        );
    }

    // ---------------------------------------------------------------
    // 4. Unit: serde roundtrip of Import.offset
    // ---------------------------------------------------------------

    #[test]
    fn import_offset_roundtrips_through_serde() {
        let import = Import::with_offset("exec", None, "ast", 0x2a);
        assert_eq!(import.symbol, "exec");
        assert_eq!(import.offset.as_deref(), Some("0x2a"));

        let json = serde_json::to_string(&import).expect("serialize");
        assert!(
            json.contains("\"offset\":\"0x2a\""),
            "offset in JSON: {json}"
        );

        let decoded: Import = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.offset.as_deref(), Some("0x2a"));

        // Old-format payload without offset still deserializes (field is
        // `#[serde(default)]`), preserving backwards compatibility for
        // compiled-binary imports.
        let legacy = r#"{"symbol":"socket","source":"goblin"}"#;
        let legacy_imp: Import = serde_json::from_str(legacy).expect("legacy deserialize");
        assert!(legacy_imp.offset.is_none());
    }

    // ---------------------------------------------------------------
    // 5. Unit: eval_symbol populates Evidence.offsets from Import.offset
    // ---------------------------------------------------------------

    #[test]
    fn eval_symbol_evidence_carries_byte_offset_from_import() {
        use crate::composite_rules::evaluators::eval_symbol;

        let mut report = AnalysisReport::new(TargetInfo {
            path: "/test.py".to_string(),
            file_type: "python".to_string(),
            size_bytes: 100,
            sha256: "t".to_string(),
            architectures: None,
        });
        report
            .imports
            .push(Import::with_offset("exec", None, "ast", 0x42));

        let data: Vec<u8> = vec![0; 0x100];
        let ctx = EvaluationContext::new(
            &report,
            &data,
            CFileType::Python,
            &[Platform::All],
            None,
            None,
        );

        let result = eval_symbol(
            Some(&"exec".to_string()),
            None,
            None,
            None,
            None,
            Some(SymbolKind::Import),
            None,
            &ctx,
        );
        assert!(result.matched);
        assert_eq!(result.evidence.len(), 1);
        let ev = &result.evidence[0];
        assert_eq!(ev.offsets, vec![0x42]);
        assert_eq!(ev.location.as_deref(), Some("0x42"));
    }
}
