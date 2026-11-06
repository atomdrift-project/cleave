use super::*;
use yara_engine::YaraScan;

fn report() -> types::AnalysisReport {
    types::AnalysisReport::new(types::TargetInfo {
        path: "sample.exe".to_string(),
        file_type: "pe".to_string(),
        size_bytes: 0,
        sha256: String::new(),
        architectures: Some(vec!["aarch64".to_string()]),
    })
}

fn matched(rule: &str, namespace: &str) -> types::YaraMatch {
    serde_json::from_value(serde_json::json!({
        "rule": rule, "namespace": namespace,
        "crit": "suspicious", "desc": "Marker"
    }))
    .unwrap()
}

#[test]
fn yara_result_reports_matches_and_returns_inline_evidence() {
    let mut report = report();
    let evidence = types::Evidence {
        value: "marker".to_string(),
        offsets: vec![7],
        ..Default::default()
    };
    let scan = YaraScan {
        matches: vec![matched("one", "test.marker"), matched("two", "test.marker")],
        inline_traits: HashMap::from([("inline.test::marker".to_string(), vec![evidence.clone()])]),
    };
    let mut conversions = 0;
    let inline = process_yara_result_with(&mut report, Some(Ok(scan)), |_| {
        conversions += 1;
        vec![evidence.clone()]
    });
    assert_eq!(report.yara_matches.len(), 2);
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].id, "test/marker");
    assert_eq!(report.findings[0].crit, types::Criticality::Suspicious);
    assert_eq!(report.findings[0].evidence[0].offsets, [7]);
    assert_eq!(conversions, 1, "duplicate findings are not converted twice");
    assert_eq!(inline["inline.test::marker"][0].offsets, [7]);
    process_yara_result_with(&mut report, Some(Ok(YaraScan::default())), |_| vec![]);
    assert_eq!(
        report
            .metadata
            .tools_used
            .iter()
            .filter(|t| *t == "yara-x")
            .count(),
        1
    );
}

#[test]
fn yara_result_arch_filter_keeps_raw_matches_but_not_incompatible_findings() {
    let mut report = report();
    let mut explicit_x86 = matched("marker", "test.x86");
    explicit_x86.arch_context = Some("x86".to_string());
    let inferred_x86 = matched("Marker_X64", "test.inferred");
    // Explicit architecture metadata overrides the name heuristic.
    let mut explicit_arm = matched("Marker_X64", "test.arm");
    explicit_arm.arch_context = Some("arm64".to_string());
    let scan = YaraScan {
        matches: vec![explicit_x86, inferred_x86, explicit_arm],
        inline_traits: HashMap::from([("inline.test::marker".to_string(), vec![])]),
    };
    let inline = process_yara_result_with(&mut report, Some(Ok(scan)), |_| vec![]);
    assert_eq!(report.yara_matches.len(), 3);
    let ids: Vec<_> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert_eq!(ids, ["test/arm"]);
    assert!(inline.contains_key("inline.test::marker"));
}

#[test]
fn yara_result_distinguishes_missing_failed_and_empty_scans() {
    let mut report = report();
    assert!(process_yara_result_with(&mut report, None, |_| vec![]).is_empty());
    assert!(report.metadata.errors.is_empty());
    assert!(report.metadata.tools_used.is_empty());
    let error = anyhow::anyhow!("scanner failed");
    assert!(process_yara_result_with(&mut report, Some(Err(error)), |_| vec![]).is_empty());
    assert_eq!(report.metadata.errors, ["yara: scanner failed"]);
    assert!(report.metadata.tools_used.is_empty());
    assert!(
        process_yara_result_with(&mut report, Some(Ok(YaraScan::default())), |_| vec![]).is_empty()
    );
    assert_eq!(report.metadata.tools_used, ["yara-x"]);
    assert!(report.findings.is_empty());
}
