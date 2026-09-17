//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! A `type: metrics` leg is a whole-file property (`text.lines`,
//! `binary.entropy`) and carries no location, so it never lands in
//! `tagged_locations` and can never fall inside a proximity window.
//!
//! Before the fix, `check_proximity_constraints` derived its
//! `min_distinct` threshold from the *declared* leg count, so any
//! composite mixing a metrics leg with `near_bytes`/`near_lines`
//! demanded N distinct located indices when only N-1 could ever exist
//! — the rule became unsatisfiable, silently, with no validation error.
//! `required_all` already exempted such legs via `located_all_indices`;
//! these tests pin the same exemption on the count.

#[cfg(test)]
mod proximity_metrics_tests {
    use crate::analyzers::FileType;
    use crate::analyzers::unified::UnifiedSourceAnalyzer;
    use crate::composite_rules::condition::PathQuery;
    use crate::composite_rules::condition::{MetricsQuery, SymbolKind};
    use crate::composite_rules::context::EvaluationContext;
    use crate::composite_rules::types::{FileType as CFileType, Platform};
    use crate::composite_rules::{Arch, CompositeTrait, Condition, SymbolQuery};
    use crate::types::{AnalysisReport, Criticality};
    use std::path::PathBuf;

    /// Two calls ~40 bytes apart, so any window over ~100 bytes holds both.
    const CLUSTERED_PY: &str = r#"
import base64
import zlib

def decoder(payload):
    stage1 = base64.b64decode(payload)
    stage2 = zlib.decompress(stage1)
"#;

    /// Parse as Python and attach a filefacts metric the rule can read.
    fn report_with_metric(source: &str, field: &str, value: f64) -> AnalysisReport {
        let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::Python)
            .expect("python analyzer available");
        let mut report = analyzer.analyze_source(&PathBuf::from("test.py"), source);
        report
            .filefacts_metrics
            .get_or_insert_with(Default::default)
            .insert(field.to_string(), value);
        report
    }

    fn symbol_leg(name: &str) -> Condition {
        Condition::Symbol(SymbolQuery {
            exact: Some(name.to_string()),
            kind: Some(SymbolKind::Import),
            ..Default::default()
        })
    }

    fn metrics_leg(field: &str, min: f64) -> Condition {
        Condition::Metrics(MetricsQuery {
            field: field.to_string(),
            min: Some(min),
            ..Default::default()
        })
    }

    /// A `type: path` leg — matches the target's filename, which is
    /// metadata about the path and never a byte range in the content.
    fn path_leg(substr: &str) -> Condition {
        Condition::Path(PathQuery {
            substr: Some(substr.to_string()),
            basename: true,
            ..Default::default()
        })
    }

    fn rule(conds: Vec<Condition>, near_bytes: Option<usize>) -> CompositeTrait {
        CompositeTrait {
            id: "test/metrics-proximity".to_string(),
            desc: "Clustered calls in a large file".to_string(),
            conf: 0.9,
            crit: Criticality::Notable,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![CFileType::All],
            all: Some(conds),
            near_bytes,
            defined_in: PathBuf::from("test.yaml"),
            ..Default::default()
        }
    }

    /// The regression: two clustered symbol legs plus one location-less
    /// metrics leg. The symbols sit ~40 bytes apart, so a 300-byte window
    /// holds every leg that *can* be placed. Requiring a third located
    /// index made this unsatisfiable at any `near_bytes`.
    #[test]
    fn metrics_leg_does_not_block_near_bytes() {
        let report = report_with_metric(CLUSTERED_PY, "text.lines", 42.0);
        let data = CLUSTERED_PY.as_bytes().to_vec();
        let ctx = EvaluationContext::new(
            &report,
            &data,
            CFileType::Python,
            &[Platform::All],
            None,
            None,
        );

        let conds = vec![
            symbol_leg("base64.b64decode"),
            symbol_leg("zlib.decompress"),
            metrics_leg("text.lines", 10.0),
        ];

        // Sanity: without proximity the rule matches, so a later failure
        // is attributable to the proximity check and nothing else.
        assert!(
            rule(conds.clone(), None).evaluate(&ctx).is_some(),
            "all three legs should be satisfied with no proximity constraint"
        );

        assert!(
            rule(conds, Some(300)).evaluate(&ctx).is_some(),
            "the metrics leg has no location and must not be counted toward \
             the proximity threshold — the two symbol legs are ~40 bytes apart"
        );
    }

    /// The exemption must not become a bypass: the two *locatable* legs
    /// still have to satisfy the window.
    #[test]
    fn metrics_leg_exemption_still_enforces_located_legs() {
        let filler = "x = 1\n".repeat(300);
        let src = format!(
            "import base64\nimport zlib\n\n\
             stage1 = base64.b64decode(b'abc')\n\
             {filler}\
             stage2 = zlib.decompress(stage1)\n"
        );
        let report = report_with_metric(&src, "text.lines", 400.0);
        let data = src.as_bytes().to_vec();
        let ctx = EvaluationContext::new(
            &report,
            &data,
            CFileType::Python,
            &[Platform::All],
            None,
            None,
        );

        let conds = vec![
            symbol_leg("base64.b64decode"),
            symbol_leg("zlib.decompress"),
            metrics_leg("text.lines", 10.0),
        ];

        assert!(
            rule(conds, Some(300)).evaluate(&ctx).is_none(),
            "the two symbol legs are ~1800 bytes apart — the metrics \
             exemption must not let a spread-out match through"
        );
    }

    /// With only one locatable leg, proximity cannot discriminate at all.
    /// It passes through rather than rejecting, matching what
    /// `apply_scope_filter` does when every scope key is empty.
    #[test]
    fn single_located_leg_passes_proximity_through() {
        let report = report_with_metric(CLUSTERED_PY, "text.lines", 42.0);
        let data = CLUSTERED_PY.as_bytes().to_vec();
        let ctx = EvaluationContext::new(
            &report,
            &data,
            CFileType::Python,
            &[Platform::All],
            None,
            None,
        );

        let conds = vec![
            symbol_leg("base64.b64decode"),
            metrics_leg("text.lines", 10.0),
        ];

        assert!(
            rule(conds, Some(300)).evaluate(&ctx).is_some(),
            "one located leg plus one metrics leg: nothing to co-locate"
        );
    }

    /// A filename leg is location-less for the same reason a metrics leg
    /// is — `eval_path` emits `location: None` because a path match is
    /// metadata about the target, not bytes in it. The analyzer is handed
    /// `test.py`, so `basename: "test.py"` holds.
    #[test]
    fn path_leg_does_not_block_near_bytes() {
        let report = report_with_metric(CLUSTERED_PY, "text.lines", 42.0);
        let data = CLUSTERED_PY.as_bytes().to_vec();
        let ctx = EvaluationContext::new(
            &report,
            &data,
            CFileType::Python,
            &[Platform::All],
            None,
            None,
        );

        let conds = vec![
            symbol_leg("base64.b64decode"),
            symbol_leg("zlib.decompress"),
            path_leg("test.py"),
        ];

        assert!(
            rule(conds.clone(), None).evaluate(&ctx).is_some(),
            "all three legs should be satisfied with no proximity constraint"
        );

        assert!(
            rule(conds, Some(300)).evaluate(&ctx).is_some(),
            "the path leg has no location and must not be counted toward \
             the proximity threshold"
        );
    }

    /// Same guard as for metrics: exempting the path leg must not excuse
    /// the legs that can be placed.
    #[test]
    fn path_leg_exemption_still_enforces_located_legs() {
        let filler = "x = 1\n".repeat(300);
        let src = format!(
            "import base64\nimport zlib\n\n\
             stage1 = base64.b64decode(b'abc')\n\
             {filler}\
             stage2 = zlib.decompress(stage1)\n"
        );
        let report = report_with_metric(&src, "text.lines", 400.0);
        let data = src.as_bytes().to_vec();
        let ctx = EvaluationContext::new(
            &report,
            &data,
            CFileType::Python,
            &[Platform::All],
            None,
            None,
        );

        let conds = vec![
            symbol_leg("base64.b64decode"),
            symbol_leg("zlib.decompress"),
            path_leg("test.py"),
        ];

        assert!(
            rule(conds, Some(300)).evaluate(&ctx).is_none(),
            "the two symbol legs are ~1800 bytes apart — the path \
             exemption must not let a spread-out match through"
        );
    }

    /// Both location-less kinds in one rule, leaving a single placeable
    /// leg: there is nothing left to co-locate.
    #[test]
    fn path_and_metrics_legs_together_pass_proximity_through() {
        let report = report_with_metric(CLUSTERED_PY, "text.lines", 42.0);
        let data = CLUSTERED_PY.as_bytes().to_vec();
        let ctx = EvaluationContext::new(
            &report,
            &data,
            CFileType::Python,
            &[Platform::All],
            None,
            None,
        );

        let conds = vec![
            symbol_leg("base64.b64decode"),
            path_leg("test.py"),
            metrics_leg("text.lines", 10.0),
        ];

        assert!(
            rule(conds, Some(300)).evaluate(&ctx).is_some(),
            "one located leg plus a path and a metrics leg: nothing to co-locate"
        );
    }
}
