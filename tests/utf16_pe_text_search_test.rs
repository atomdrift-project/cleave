//! Regression: `type: text` must search short UTF-16 strings extracted from a
//! managed PE's .NET `#US` heap. These command constants are structurally
//! bounded strings, not raw byte patterns.
#![allow(clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

fn assert_text_match(pattern: &str) {
    let sample = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/dotnet_utf16_clipboard.dll");
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args([
            "test-match",
            "--type",
            "text",
            "--method",
            "exact",
            "--pattern",
            pattern,
            sample.to_str().expect("fixture path is UTF-8"),
        ])
        .output()
        .expect("run cleave test-match");

    assert!(
        output.status.success(),
        "test-match failed for {pattern}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("MATCHED"),
        "UTF-16 PE text search did not match {pattern}:\n{stdout}"
    );
}

#[test]
fn dotnet_utf16_user_strings_match_as_text() {
    for pattern in ["pbcopy", "xclip", "clip"] {
        assert_text_match(pattern);
    }
}
