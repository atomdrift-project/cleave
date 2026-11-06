use super::super::binary::{Import, Section};
use super::super::file_analysis::FileAnalysis;
use super::super::filefacts_view::FilefactsView;
use super::super::traits_findings::Finding;
use super::super::{Criticality, Evidence, FindingKind};
use super::{Facts, compact_from_files};
use serde_json::json;

#[test]
fn retaining_model_facts_after_conversion_equals_converting_to_the_model_profile() {
    let mut fa = FileAnalysis::new(0, "/t.exe".into(), "pe".into(), "sha".into(), 64);
    fa.imports = vec![
        super::super::binary::Import {
            symbol: "VirtualAlloc".into(),
            library: Some("kernel32.dll".into()),
            ..Default::default()
        },
        super::super::binary::Import {
            symbol: "GetTickCount".into(),
            library: Some("kernel32.dll".into()),
            ..Default::default()
        },
    ];
    let model = compact_from_files(std::slice::from_ref(&fa), Facts::Model);
    let mut full = compact_from_files(&[fa], Facts::Full);
    full.retain_model_facts();
    assert_eq!(
        serde_json::to_value(&full).ok(),
        serde_json::to_value(&model).ok()
    );
    assert_eq!(model.fp.as_deref(), Some(crate::model_facts::profile_id()));
}

#[test]
fn reducing_an_old_profile_does_not_claim_richer_facts() {
    let mut report = super::CompactReport {
        fp: Some("azoth-1fbfcdb8a8ed5902".into()),
        ..Default::default()
    };
    report.retain_model_facts();
    assert_eq!(report.fp.as_deref(), Some("azoth-1fbfcdb8a8ed5902"));
}

fn finding(id: &str, crit: Criticality, conf: f32) -> Finding {
    Finding {
        precomputed_spans: None,
        src: None,
        id: id.to_string().into(),
        kind: FindingKind::Capability,
        desc: "test".to_string().into(),
        conf,
        crit,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![Evidence {
            method: "test".to_string(),
            source: "test".to_string(),
            value: "v".to_string(),
            location: None,
            ..Default::default()
        }],
        match_count: 1,
        source_file: None,
        downgraded: false,
    }
}

fn file_with(findings: Vec<Finding>) -> FileAnalysis {
    let mut fa = FileAnalysis::new(0, "t.py".into(), "python".into(), "sha".into(), 1);
    fa.findings = findings;
    fa
}

/// Provenance fields serialize sparsely: an ordinary content member emits
/// none of them, keeping the common case free of the new keys. `rel` and
/// `role` are orthogonal — a fetched dependency is `Content` (no `role`),
/// while a registry record is `Sidecar` with no `via`.
#[test]
fn rel_role_via_serialize_sparsely() {
    use super::super::file_analysis::{Rel, Role};
    use super::convert_file;

    let obj = |fa: &FileAnalysis| -> serde_json::Value {
        let v = serde_json::to_value(convert_file(fa, fa.id, Facts::Full));
        assert!(v.is_ok(), "serialize compact file: {v:?}");
        v.unwrap_or(serde_json::Value::Null)
    };

    // Ordinary content member emits none of the provenance keys.
    let o = obj(&file_with(vec![]));
    for k in ["rel", "via", "role", "pid"] {
        assert!(o.get(k).is_none(), "content member should omit {k}");
    }

    // Fetched dependency: content by role, so `role` stays absent while
    // `rel`/`via`/`pid` are present.
    let mut fetched = FileAnalysis::new(1, "4.13.0".into(), "gz".into(), "s".into(), 9);
    fetched.parent_id = Some(0);
    fetched.rel = Rel::Fetched;
    fetched.via = Some("https://example.test/4.13.0.tar.gz".into());
    let o = obj(&fetched);
    assert_eq!(o["pid"], json!(0));
    assert_eq!(o["rel"], json!("fetched"));
    assert_eq!(o["via"], json!("https://example.test/4.13.0.tar.gz"));
    assert!(o.get("role").is_none(), "fetched content should omit role");

    // Registry sidecar: `rel`/`role`/`pid` present, no `via`.
    let mut sidecar = FileAnalysis::new(2, "registry".into(), "registry".into(), "s".into(), 4);
    sidecar.parent_id = Some(0);
    sidecar.rel = Rel::Registry;
    sidecar.role = Role::Sidecar;
    let o = obj(&sidecar);
    assert_eq!(o["rel"], json!("registry"));
    assert_eq!(o["role"], json!("sidecar"));
    assert!(
        o.get("via").is_none(),
        "sidecar without fetch should omit via"
    );
}

/// The emit guard must neutralize any cross-file reference that does not
/// resolve to an emitted file id: a dangling inherited `src` is cleared and
/// a dangling composite source is dropped, while valid references survive.
/// This is what makes a dangling-ref report (the symptom of an upstream
/// drop/renumber) impossible to emit.
#[test]
fn sanitize_strips_only_dangling_references() {
    use super::{CompactSource, convert_file, sanitize_references};

    let mut files = vec![
        convert_file(
            &file_with(vec![finding("a/b/c", Criticality::Notable, 0.9)]),
            0,
            Facts::Full,
        ),
        convert_file(
            &file_with(vec![finding("d/e/f", Criticality::Notable, 0.9)]),
            1,
            Facts::Full,
        ),
    ];
    let src = |f: u32| CompactSource {
        file: f,
        line: None,
        offset: None,
    };
    files[0].findings[0].from = vec![src(1), src(9)]; // one valid, one dangling

    let dangling = sanitize_references(&mut files);

    assert_eq!(dangling, 1, "one dangling from entry");
    let kept = &files[0].findings[0].from;
    assert_eq!(kept.len(), 1, "dangling source dropped");
    assert_eq!(kept[0].file, 1, "valid source kept");
    // A clean report passes through untouched.
    assert_eq!(sanitize_references(&mut files), 0);
}

/// JSON `f` formula must mirror the CLI: only notable-or-higher findings
/// with confidence ≥ 0.65. Component- and baseline-criticality findings
/// must not contribute, even when they would survive the lib-side
/// component-reference filter.
#[test]
fn json_formula_excludes_component_and_baseline() {
    let files = vec![file_with(vec![
        finding("objectives/c2/http/beacon", Criticality::Notable, 0.9),
        finding("micro-behaviors/fs/file/read", Criticality::Component, 0.95),
        finding("metadata/lang/source", Criticality::Baseline, 0.95),
    ])];

    let compact = compact_from_files(&files, Facts::Full);
    let formula = compact.files[0].formula.as_deref().unwrap_or("");
    assert!(
        formula.contains('O'),
        "expected O (objectives/Notable) in `{formula}`",
    );
    assert!(
        !formula.contains('H'),
        "did not expect H (micro-behaviors/Component) in `{formula}`",
    );
    assert!(
        !formula.contains("Md"),
        "did not expect Md (metadata/Baseline) in `{formula}`",
    );
}

/// Findings below the 0.65 confidence floor must not contribute, even
/// when their criticality is otherwise eligible.
#[test]
fn json_formula_drops_low_confidence() {
    let files = vec![file_with(vec![finding(
        "objectives/c2/http/beacon",
        Criticality::Notable,
        0.6,
    )])];
    let compact = compact_from_files(&files, Facts::Full);
    assert!(
        compact.files[0].formula.is_none(),
        "expected no formula when sole finding is below 0.65 conf, got {:?}",
        compact.files[0].formula,
    );
}

/// JSON output must reuse a pre-populated `file.formula` rather than
/// recomputing from raw findings. This is the path that fires after
/// `AnalysisReport::finalize()` calls `refresh_formula`.
#[test]
fn json_formula_prefers_prepopulated_value() {
    let mut fa = file_with(vec![finding(
        "objectives/c2/http/beacon",
        Criticality::Notable,
        0.9,
    )]);
    fa.formula = Some("PRECOMPUTED".to_string());
    let compact = compact_from_files(&[fa], Facts::Full);
    assert_eq!(compact.files[0].formula.as_deref(), Some("PRECOMPUTED"));
}

#[test]
fn compact_v7_packs_filefacts_under_fact() {
    let mut fa = FileAnalysis::new(0, "t.exe".into(), "pe".into(), "sha".into(), 7);
    fa.imports
        .push(Import::new("CreateFileW", Some("kernel32.dll".into())));
    fa.sections.push(Section {
        name: ".text".into(),
        address: Some(0x1000),
        offset: Some(0x400),
        size: 0x1000,
        entropy: 6.424,
        permissions: Some("r-x".into()),
        flags: Vec::new(),
    });
    fa.filefacts_metrics = Some([("file.entropy".to_string(), 7.125)].into_iter().collect());
    fa.filefacts = Some(FilefactsView {
        symbols: vec![
            filefacts::Symbol::Call {
                target: Some("fetch".to_string()),
                args: vec![filefacts::Arg::String {
                    value: "https://example.com".to_string(),
                }],
                offset: None,
            },
            filefacts::Symbol::Member {
                path: "window.localStorage".to_string(),
                offset: Some(0),
            },
        ],
        ..FilefactsView::default()
    });

    let value = serde_json::to_value(compact_from_files(&[fa], Facts::Full));
    assert!(value.is_ok(), "serialize compact: {value:?}");
    let Ok(value) = value else {
        return;
    };
    assert_eq!(
        value.get("v").and_then(serde_json::Value::as_str),
        Some("9")
    );
    let ff = &value["files"][0]["facts"];
    assert_eq!(ff["metrics"]["file"]["entropy"], 7.13);
    assert_eq!(ff["imp"][0], json!(["kernel32.dll", "CreateFileW"]));
    assert_eq!(ff["sec"][0], json!([".text", 1024, 4096, 6.42, "r-x"]));
    assert_eq!(ff["tgt"], json!(["fetch"]));
    assert_eq!(ff["mbr"], json!(["window.localStorage"]));
    // call_args was derived from the dropped Ast.call_strings index.
    // The unified Symbol::Call no longer carries inline strings —
    // literal values live in top-level `literals` and correlate by
    // offset window. compact_ast returns empty here; rule engines
    // do the offset correlation themselves.
    assert!(value["files"][0].get("ms").is_none());
    assert!(value["files"][0].get("k").is_none());
}
