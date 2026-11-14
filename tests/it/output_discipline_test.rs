//! Output discipline for benign input: stderr stays empty, terminal output
//! stays short, and `--json` output parses.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::Path;
use std::process::Output;
use tempfile::TempDir;

/// Benign sample: a small native Rust Mach-O (see `cli_integration_test`).
const BENIGN: &str = "tests/fixtures/lang_strings/rust_native";

/// Max stdout lines for a single benign file in terminal mode (includes the
/// 2-line version banner).
const MAX_SCAN_LINES: usize = 6;
/// Max stdout lines for a small directory of benign files in terminal mode.
const MAX_DIR_LINES: usize = 14;

/// A complete (YAML + YARA) fixture traits dir, so the result does not depend
/// on the developer-mutable installed rule tree.
fn quiet_traits() -> TempDir {
    let dir = TempDir::new().unwrap();
    let ns = dir.path().join("metadata/package/manifest");
    fs::create_dir_all(&ns).unwrap();
    fs::write(
        ns.join("probe.yaml"),
        "defaults:\n  platforms: [unix, windows]\n  crit: notable\n  conf: 0.9\n\
         traits:\n  - id: fx-probe\n    desc: probe\n    for: [package.json]\n\
         \x20   if:\n      type: value\n      path: name\n      exists: true\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("probe.yar"),
        "rule fx_probe_yara { strings: $a = \"cleave-silence-probe-never-matches\" condition: $a }\n",
    )
    .unwrap();
    dir
}

fn run(traits: &Path, args: &[&str]) -> Output {
    let out = assert_cmd::cargo_bin_cmd!("cleave")
        .env("RUST_LOG", "error")
        .env("CLEAVE_TRAITS_DIR", traits)
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(args)
        .output()
        .unwrap();
    assert!(out.status.success(), "cleave {args:?} failed: {out:?}");
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "",
        "cleave {args:?} wrote to stderr"
    );
    out
}

fn assert_json_parses(out: &Output) {
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.trim().is_empty(), "--json produced no output");
    for line in stdout.lines().filter(|l| !l.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|e| panic!("unparseable JSON line ({e}): {line}"));
    }
}

fn assert_max_lines(out: &Output, max: usize) {
    let n = String::from_utf8_lossy(&out.stdout).lines().count();
    assert!(n <= max, "benign output is {n} lines, cap is {max}");
}

#[test]
fn scan_benign_file_is_silent_and_short() {
    let traits = quiet_traits();
    assert_max_lines(&run(traits.path(), &[BENIGN]), MAX_SCAN_LINES);
}

#[test]
fn scan_benign_file_json_parses_and_is_silent() {
    let traits = quiet_traits();
    assert_json_parses(&run(traits.path(), &["--json", BENIGN]));
}

#[test]
fn analyze_benign_directory_is_silent_short_and_json_parses() {
    let traits = quiet_traits();
    let dir = TempDir::new().unwrap();
    for f in [BENIGN, "tests/fixtures/java/HelloWorld.class"] {
        fs::copy(f, dir.path().join(Path::new(f).file_name().unwrap())).unwrap();
    }
    let d = dir.path().to_str().unwrap();
    assert_max_lines(&run(traits.path(), &["analyze", d]), MAX_DIR_LINES);
    assert_json_parses(&run(traits.path(), &["--json", "analyze", d]));
}
