//! Regression guard for the source/script XOR-scan gate.
//!
//! filefacts skips stng's (expensive, FP-prone) XOR auto-detect scan on source
//! files that show no XOR intent — no `^` operator and no `xor` keyword — and on
//! archive containers (whose real payloads live in members, scanned separately).
//! That gate cut a batch of speculative-decode false positives on benign source
//! (plain comments / coordinate strings mis-decoded as "XOR payloads") while
//! preserving real detection: a self-contained script wielding an XOR-encoded
//! payload necessarily carries its decoder (`^` / `xor`) in the same file, so the
//! gate lets the scan run there.
//!
//! These fixtures (`testdata/xor/`) each pair a real single-byte-XOR payload with
//! a genuine `^`-based decoder, in C, JavaScript, Python (raw and XOR+base64),
//! and bash. They must keep producing XOR detection — if the gate ever wrongly
//! skips intent-bearing source, the scan-based findings (notably
//! `metadata/encoded-payload/xor` for C/bash/python, which have no AST-level XOR
//! trait to fall back on) disappear and these fail loudly.
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
    let mut ids: Vec<String> = r.findings.iter().map(|f| f.id.clone()).collect();
    for m in &r.files {
        ids.extend(m.findings.iter().map(|f| f.id.clone()));
    }
    ids
}

fn analyze(name: &str) -> Vec<String> {
    let path = xor_dir().join(name);
    let report = analyze_file(&path, &opts())
        .unwrap_or_else(|e| panic!("analyze_file failed for {}: {e}", path.display()));
    all_finding_ids(&report)
}

/// Each fixture must surface at least one XOR-related finding. C, bash and the
/// raw-byte Python fixture have no AST-level XOR trait, so their only signal is
/// the scan-based `metadata/encoded-payload/xor` — asserting it proves the gate
/// actually ran stng's XOR scan on intent-bearing source.
#[test]
fn xor_source_fixtures_still_detect() {
    let cases: &[(&str, &str)] = &[
        // (fixture, a finding-id substring that MUST be present)
        ("xor_dropper.c", "encoded-payload/xor"),
        ("xor_drop.sh", "encoded-payload/xor"),
        ("xor_raw_beacon.py", "encoded-payload/xor"),
        ("xor_loader.js", "xor"),
        ("xor_base64_stealer.py", "xor"),
    ];

    for (name, needle) in cases {
        let ids = analyze(name);
        let xor_hits: Vec<&String> = ids
            .iter()
            .filter(|id| id.to_lowercase().contains("xor"))
            .collect();
        assert!(
            !xor_hits.is_empty(),
            "{name}: expected XOR detection but found none. all findings: {ids:?}"
        );
        assert!(
            ids.iter().any(|id| id.contains(needle)),
            "{name}: expected a finding containing {needle:?} (the gate must run \
             stng's XOR scan on this intent-bearing source). xor findings: {xor_hits:?}"
        );
    }
}
