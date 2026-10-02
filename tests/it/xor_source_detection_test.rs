//! Regression guard for XOR detection in source.
//!
//! stng's XOR scanners are built for binaries and run only on binary input:
//! they recovered nothing from real-world source, and only noise from benign
//! source. XOR in source is detected by source-shaped signals instead — the
//! AST-level XOR traits — which these fixtures (`testdata/xor/`) exercise in
//! JavaScript and Python. Each pairs a single-byte-XOR payload with a genuine
//! `^`-based decoder, and must keep producing an XOR finding.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use cleave::{AnalysisOptions, AnalysisReport, analyze_file};

fn opts() -> AnalysisOptions {
    AnalysisOptions {
        disable_yara: true,
        disable_radare2: true,
        disable_upx: true,
        ..Default::default()
    }
}

fn xor_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/xor")
}

/// Every finding id in the report — top-level plus any nested member.
fn all_finding_ids(r: &AnalysisReport) -> Vec<String> {
    let mut ids: Vec<String> = r.findings.iter().map(|f| f.id.to_string()).collect();
    for m in &r.files {
        ids.extend(m.findings.iter().map(|f| f.id.to_string()));
    }
    ids
}

fn analyze(name: &str) -> Vec<String> {
    let path = xor_dir().join(name);
    let report = analyze_file(&path, &opts())
        .unwrap_or_else(|e| panic!("analyze_file failed for {}: {e}", path.display()));
    all_finding_ids(&report)
}

/// Each fixture must surface at least one XOR-related finding.
#[test]
fn xor_source_fixtures_still_detect() {
    for name in ["xor_loader.js", "xor_base64_stealer.py"] {
        let ids = analyze(name);
        assert!(
            ids.iter().any(|id| id.to_lowercase().contains("xor")),
            "{name}: expected XOR detection but found none. all findings: {ids:?}"
        );
    }
}
