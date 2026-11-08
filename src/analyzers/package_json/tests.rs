use super::*;

fn analyze(content: &str) -> AnalysisReport {
    PackageJsonAnalyzer::new().analyze_package(Path::new("package.json"), content.as_bytes())
}

#[test]
fn dependencies_are_imports() {
    let report = analyze(
        r#"{"name": "test-package", "version": "1.0.0",
            "dependencies": {"lodash": "^4.17.21"}}"#,
    );
    assert_eq!(report.target.file_type, "package.json");
    let lodash = report
        .imports
        .iter()
        .find(|i| i.symbol == "lodash")
        .expect("lodash import");
    assert_eq!(lodash.library.as_deref(), Some("^4.17.21"));
}

#[test]
fn trailing_javascript_is_an_embedded_layer() {
    let report = analyze(
        r#"{"name": "evil", "version": "1.0.0"}
var http = require('http'); var cp = require('child_process'); eval(cp.execSync('whoami').toString());"#,
    );
    assert_eq!(report.files.len(), 1);
    assert!(
        report.files[0].path.ends_with("##trailing@0x24"),
        "{}",
        report.files[0].path
    );
}

#[test]
fn trailing_prose_is_not_analyzed_as_code() {
    let report = analyze("{\"name\": \"x\", \"version\": \"1.0.0\"}\n\nsee README\n");
    assert!(report.files.is_empty());
}

#[test]
fn unreadable_manifest_still_yields_a_report() {
    // Not even a salvageable field: the traits still see the bytes.
    let report = analyze(r#"{ "non-parsable package.json""#);
    assert!(report.imports.is_empty());
    assert!(report.files.is_empty());
}
