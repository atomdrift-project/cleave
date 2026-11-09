//! Archive member emission through the cleave binary. What filefacts emits
//! per format (metrics, typed facts) is tested in filefacts.
//!
//! The test runs cleave via subprocess on a real fixture and parses the
//! compact JSON output. A missing fixture skips.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::path::Path;

/// Run `cleave --json analyze <path>` and return the compact
/// report with the complete metric map.
/// Skips YARA + cache for speed and determinism. Returns `None` when the
/// fixture is not present on the test host (binary fixtures are gitignored;
/// we test what the host can extract, not require every one).
fn analyze_report(path: &Path) -> Option<Value> {
    if !path.exists() {
        crate::support::skip_missing(&path.display().to_string());
        return None;
    }
    let mut cmd = assert_cmd::cargo_bin_cmd!("cleave");
    let output = cmd
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(["--json", "analyze", path.to_str().unwrap()])
        .output()
        .expect("cleave run");
    assert!(
        output.status.success(),
        "cleave failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with('{'))
        .expect("no JSON line in cleave output");
    let report: Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("bad JSON: {e}"));
    assert_eq!(
        report["fp"].as_str(),
        Some(cleave::model_facts::profile_id())
    );
    Some(report)
}

// ────────────────────────────────────────────────────────────────────
//  Cross-format canonical paths
// ────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────
//  PE format-specific
// ────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────
//  ELF format-specific
// ────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────
//  Mach-O format-specific
// ────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────
//  LNK format-specific
// ────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────
//  ZIP archive
// ────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────
//  Tar (gzipped)
// ────────────────────────────────────────────────────────────────────

/// Tar.gz is handled by cleave's archive analyzer (which decompresses and
/// recurses). In v8 the wrapper is typed `tar.gz` and each member is surfaced
/// as its own `files[]` entry (path `<archive>!!<member>`, `depth > 0`) rather
/// than the retired `archive.members[N].*` kv keys — those member files are
/// what traits targeting tar.gz contents now analyze.
#[test]
fn targz_emits_members_as_child_files() {
    let Some(report) = analyze_report(Path::new("tests/fixtures/archives/test.tar.gz")) else {
        return;
    };
    let files = report["files"]
        .as_array()
        .expect("report should contain file entries");
    assert_eq!(
        files[0]["type"].as_str(),
        Some("tar.gz"),
        "wrapper file should be typed tar.gz"
    );
    let member = files.iter().find(|f| {
        f["path"].as_str().is_some_and(|p| p.contains("!!")) && f["depth"].as_u64().unwrap_or(0) > 0
    });
    assert!(
        member.is_some(),
        "tar.gz member should be surfaced as a child file: {files:?}"
    );
}

// ────────────────────────────────────────────────────────────────────
//  parse.error_count is the universal "malformed" signal
// ────────────────────────────────────────────────────────────────────
