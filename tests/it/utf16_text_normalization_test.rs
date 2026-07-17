//! Regression: UTF-16 (LE/BE BOM) source/script files must produce the same
//! text-derived findings as their UTF-8 equivalent.
//!
//! Bug: `type: text` on `uses_raw_text_search()` file types is evaluated by
//! `eval_raw()` against the file content. A UTF-16 script is null-interleaved
//! at the byte level (`E\0x\0e\0c\0...`), so every text/regex pattern missed and
//! a malicious UTF-16 VBS produced zero findings — while its UTF-8 twin matched
//! normally. The pipeline now normalizes UTF-16 -> UTF-8 for source/text types
//! before string extraction, metrics, and trait matching, so matching is
//! encoding-agnostic without rerouting `type: text` away from cross-line search.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cleave::{AnalysisOptions, AnalysisReport, analyze_bytes};
use std::collections::BTreeSet;

fn utf16le_with_bom(s: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

fn utf16be_with_bom(s: &str) -> Vec<u8> {
    let mut out = vec![0xFE, 0xFF];
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out
}

fn finding_ids(report: &AnalysisReport) -> BTreeSet<String> {
    report.findings.iter().map(|f| f.id.clone()).collect()
}

// A small VBScript exercising single-line `type: text` patterns (ExecuteGlobal
// loader, ChrW char-code construction) plus an opaque variable name.
const SCRIPT: &str = "On Error Resume Next\r\n\
Dim compiledCode\r\n\
compiledCode = ChrW(72) & ChrW(73) & ChrW(33)\r\n\
ExecuteGlobal compiledCode\r\n";

fn assert_utf16_matches_utf8(utf16_bytes: &[u8], label: &str) {
    // Keep the test deterministic across engine rebuilds: the analysis cache is
    // keyed on file SHA + traits revision (not the engine build), so a stale
    // pre-fix entry could otherwise mask a regression. Serialize and restore the
    // env var so a shared-process run (`cargo test --test it`) can't leak
    // cache-skipping into a concurrent test.
    let _guard = crate::support::global_lock();
    let _skip_cache = crate::support::EnvVarGuard::set("CLEAVE_SKIP_CACHE", "1");

    let opts = AnalysisOptions::default();
    let utf8 = analyze_bytes(SCRIPT.as_bytes(), "sample.vbs", &opts).unwrap();
    let utf16 = analyze_bytes(utf16_bytes, "sample.vbs", &opts).unwrap();

    let u8_ids = finding_ids(&utf8);
    let u16_ids = finding_ids(&utf16);

    assert!(
        !u8_ids.is_empty(),
        "UTF-8 baseline should produce text-derived findings (none did — test is not exercising any text trait)"
    );
    assert_eq!(
        u8_ids,
        u16_ids,
        "{label} script must yield identical findings to its UTF-8 equivalent.\n\
         only in UTF-8: {:?}\n  only in {label}: {:?}",
        u8_ids.difference(&u16_ids).collect::<Vec<_>>(),
        u16_ids.difference(&u8_ids).collect::<Vec<_>>(),
    );
}

#[test]
fn utf16le_script_matches_utf8_findings() {
    assert_utf16_matches_utf8(&utf16le_with_bom(SCRIPT), "UTF-16LE");
}

#[test]
fn utf16be_script_matches_utf8_findings() {
    assert_utf16_matches_utf8(&utf16be_with_bom(SCRIPT), "UTF-16BE");
}
