//! Environment check: the traits tree these tests actually run against must be
//! parseable end to end.
//!
//! Most of this suite asserts real detections from the *installed* traits
//! checkout — developer-mutable data that usually lives in a separate repo. At
//! analysis time a trait file cleave cannot parse is only a warning (forward
//! compatibility: a newer rule pack must not brick an older build), so a single
//! mid-edit YAML there silently removes every rule in that file. The visible
//! result is a few dozen scattered "expected finding X, got none" failures
//! across unrelated modules, with nothing pointing at the cause.
//!
//! This test names the cause in one place. If it fails, fix the trait file it
//! reports before reading anything else in the run: the other failures are
//! symptoms, not regressions.
#![allow(clippy::expect_used, clippy::panic)]

/// Marker text from the loader's forward-compatibility warning
/// (`capabilities::mapper::loader_directory`).
const SKIPPED_MARKER: &str = "could not parse";

#[test]
fn installed_traits_all_parse() {
    // Deliberately no CLEAVE_TRAITS_DIR: the point is to exercise the default
    // resolution every other module in this suite inherits.
    let file = tempfile::Builder::new()
        .suffix(".json")
        .tempfile()
        .expect("create probe file");
    std::fs::write(file.path(), br#"{"name":"probe","version":"1.0.0"}"#)
        .expect("write probe file");

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("RUST_LOG", "error")
        .env("CLEAVE_SKIP_YARA", "1")
        .args([
            "--json",
            "analyze",
            file.path().to_str().expect("probe path is UTF-8"),
        ])
        .output()
        .expect("run cleave analyze");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains(SKIPPED_MARKER),
        "the installed traits checkout has unparseable file(s), so the rules in \
         them will not run and detection assertions elsewhere in this suite will \
         fail for reasons unrelated to the code under test. Fix the file(s) below \
         (or run `cleave validate`) and re-run:\n{stderr}"
    );
}
