//! Content-classified YARA rule files must not be scanned as malware samples.
//!
//! The corpus includes YARA rules with suffixes such as `.unknown`; scanning
//! those bytes with the configured third-party YARA signatures matches the
//! indicators embedded in the rule source itself.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::Path;

use cleave::{AnalysisOptions, analyze_file};

#[test]
fn content_classified_yara_rule_source_skips_sample_scanning() -> anyhow::Result<()> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/yara/hiddenvnc-rule.unknown");

    let report = analyze_file(&path, &AnalysisOptions::default())?;

    assert_eq!(report.target.file_type, "yara");
    assert!(
        !report
            .metadata
            .tools_used
            .iter()
            .any(|tool| tool == "yara-x"),
        "a YARA rule source is a signature definition, not a malware sample to scan",
    );
    Ok(())
}
