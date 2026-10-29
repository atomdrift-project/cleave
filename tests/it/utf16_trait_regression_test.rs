//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use assert_cmd::Command;
use predicates::prelude::*;
use std::time::{Duration, Instant};

/// End-to-end regression for the UTF-16 sample's trait evaluation path.
///
/// This intentionally exercises the real `analyze` CLI pipeline on the UTF-16 WSH
/// sample, but keeps the run bounded:
/// - YARA is disabled to avoid unrelated startup cost
/// - analysis cache is disabled so we do not mask the hot path
/// - the subprocess itself is capped at 90 seconds
#[test]
#[ignore = "targeted end-to-end regression; run directly when validating the UTF-16 trait path"]
fn test_utf16_sample_full_analysis_completes_within_90_seconds() {
    let (_dir, sample) =
        crate::support::sample_file("tests/fixtures/malware/utf16le_wsh_dropper.js");
    let sample = sample.as_path();

    let mut cmd = Command::cargo_bin("cleave").expect("Failed to locate cleave binary");
    let start = Instant::now();

    let assert = cmd
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(["--json", "analyze", sample.to_str().unwrap()])
        .timeout(Duration::from_secs(90))
        .assert();

    let elapsed = start.elapsed();

    assert
        .success()
        .stdout(predicate::str::contains("\"type\":\"javascript\""));

    assert!(
        elapsed < Duration::from_secs(90),
        "UTF-16 full analysis exceeded 90 seconds: {:?}",
        elapsed
    );
}
