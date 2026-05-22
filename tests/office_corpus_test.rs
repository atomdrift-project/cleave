//! Office corpus regression test.
//!
//! Walks `tests/testdata/office/manifest.yaml`, runs `cleave --json analyze`
//! on each listed sample, and asserts the manifest's expectations
//! (criticality floor, must-fire/must-not-fire trait IDs, optional
//! `office.*` metric assertions). The full finding list per sample is
//! captured via `insta` snapshots so behavior diffs are visible in PRs.
//!
//! This is the primary regression gate for office-document accuracy work.
//! See `tests/testdata/office/README.md` for corpus management notes.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(default)]
    samples: Vec<Sample>,
}

#[derive(Debug, Deserialize)]
struct Sample {
    path: String,
    #[allow(dead_code)]
    bucket: String,
    description: String,
    #[serde(default)]
    xor_encoded: bool,
    min_max_crit: String,
    #[serde(default)]
    must_fire: Vec<String>,
    #[serde(default)]
    must_not_fire: Vec<String>,
    #[serde(default)]
    expected_metrics: serde_yaml::Mapping,
}

/// Criticality ordinal matching `Criticality` ordering in cleave proper.
fn crit_rank(c: &str) -> u8 {
    match c {
        "component" => 0,
        "baseline" => 1,
        "notable" => 2,
        "suspicious" => 3,
        "hostile" => 4,
        _ => panic!("unknown criticality: {c}"),
    }
}

/// XOR-decode a buffer with the corpus encoding key (0x42).
fn xor_decode(data: &[u8]) -> Vec<u8> {
    data.iter().map(|b| b ^ 0x42).collect()
}

fn corpus_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("testdata")
        .join("office")
}

fn load_manifest() -> Manifest {
    let path = corpus_root().join("manifest.yaml");
    let body = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_yaml::from_str(&body).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

/// Materialize a sample to a path the analyzer can read. XOR-encoded
/// samples are decoded into a temp file inside `staging`, returning the
/// staged path. Plain samples return their original path unchanged.
fn stage_sample(sample: &Sample, staging: &Path) -> PathBuf {
    let raw = corpus_root().join(&sample.path);
    if !sample.xor_encoded {
        return raw;
    }
    let bytes = fs::read(&raw).unwrap_or_else(|e| panic!("read {}: {e}", raw.display()));
    let decoded = xor_decode(&bytes);
    // Strip the _xor_0x42_encoded suffix when staging
    let stem = raw
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("sample")
        .replace("_xor_0x42_encoded", "");
    let staged = staging.join(stem);
    fs::write(&staged, decoded).expect("stage decoded sample");
    staged
}

/// Run cleave's CLI in JSON mode and return the parsed report.
fn analyze(path: &Path) -> serde_json::Value {
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .args(["--json", "analyze", path.to_str().unwrap()])
        .output()
        .expect("invoke cleave");
    if !output.status.success() {
        panic!(
            "cleave exited {} on {}: stderr={}",
            output.status,
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("parse cleave output for {}: {e}", path.display()))
}

/// Pull the union of compact v5 finding IDs from `fs[].ts`.
fn collect_finding_ids(report: &serde_json::Value) -> Vec<String> {
    let mut ids = Vec::new();
    if let Some(files) = report.get("fs").and_then(|v| v.as_array()) {
        for file in files {
            if let Some(findings) = file.get("ts").and_then(|v| v.as_array()) {
                ids.extend(
                    findings
                        .iter()
                        .filter_map(|f| f.get("i").and_then(|v| v.as_str()).map(str::to_owned)),
                );
            }
        }
    }
    ids.sort();
    ids.dedup();
    ids
}

/// Pull the maximum criticality observed across all compact v5 findings.
fn max_criticality(report: &serde_json::Value) -> String {
    let mut best_rank = 1u8;
    if let Some(files) = report.get("fs").and_then(|v| v.as_array()) {
        for file in files {
            if let Some(findings) = file.get("ts").and_then(|v| v.as_array()) {
                for finding in findings {
                    if let Some(level) = finding.get("l").and_then(serde_json::Value::as_u64) {
                        best_rank = best_rank.max(level as u8);
                    }
                }
            }
        }
    }
    match best_rank {
        0 | 1 => "component",
        2 => "baseline",
        3 => "notable",
        4 => "suspicious",
        _ => "hostile",
    }
    .to_string()
}

/// Look up an `office.*` compact v5 metric path under `fs[0].ff.m`.
fn metric_at(report: &serde_json::Value, path: &str) -> serde_json::Value {
    let Some((group, field)) = path.split_once(".") else {
        return serde_json::Value::Null;
    };
    report
        .get("fs")
        .and_then(|v| v.as_array())
        .and_then(|files| files.first())
        .and_then(|file| file.pointer(&format!("/ff/m/{group}/{field}")))
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

/// Validate a manifest entry against the analyzer report. Panics with a
/// descriptive message on violation; the caller aggregates failures so
/// one bad sample doesn't mask others.
fn validate_sample(sample: &Sample, report: &serde_json::Value) -> Result<(), String> {
    let ids = collect_finding_ids(report);
    let max_crit = max_criticality(report);

    if crit_rank(&max_crit) < crit_rank(&sample.min_max_crit) {
        return Err(format!(
            "max crit {max_crit} < required {} (sample: {})",
            sample.min_max_crit, sample.description
        ));
    }
    for id in &sample.must_fire {
        if !ids.iter().any(|got| got == id) {
            return Err(format!(
                "must_fire trait `{id}` did not fire (sample: {})",
                sample.description
            ));
        }
    }
    for id in &sample.must_not_fire {
        if ids.iter().any(|got| got == id) {
            return Err(format!(
                "must_not_fire trait `{id}` fired (sample: {})",
                sample.description
            ));
        }
    }
    for (k, v) in &sample.expected_metrics {
        let key = k.as_str().ok_or("expected_metrics key must be a string")?;
        let actual = metric_at(report, key);
        let want: serde_json::Value = serde_json::to_value(v)
            .map_err(|e| format!("convert expected_metrics value for {key}: {e}"))?;
        if actual != want {
            return Err(format!(
                "metric {key} expected {want} got {actual} (sample: {})",
                sample.description
            ));
        }
    }
    Ok(())
}

#[test]
fn office_corpus() {
    let manifest = load_manifest();
    if manifest.samples.is_empty() {
        eprintln!(
            "office corpus is empty — see tests/testdata/office/README.md for adding samples"
        );
        return;
    }

    let staging = TempDir::new().expect("staging tempdir");
    let mut failures = Vec::new();

    for sample in &manifest.samples {
        let staged = stage_sample(sample, staging.path());
        if !staged.exists() {
            failures.push(format!(
                "missing sample file: {} ({})",
                staged.display(),
                sample.description
            ));
            continue;
        }
        let report = analyze(&staged);

        if let Err(msg) = validate_sample(sample, &report) {
            failures.push(msg);
        }

        // Snapshot the sorted finding-ID list per sample. The snapshot name
        // uses the sample path so each sample gets its own .snap file.
        let ids = collect_finding_ids(&report);
        let snapshot_name = sample
            .path
            .replace('/', "__")
            .replace(".xor_0x42_encoded", "")
            .replace('.', "_");
        insta::with_settings!({
            snapshot_path => corpus_root().join("snapshots"),
            prepend_module_to_snapshot => false,
        }, {
            insta::assert_yaml_snapshot!(snapshot_name.as_str(), &ids);
        });
    }

    if !failures.is_empty() {
        panic!("office corpus failures:\n  - {}", failures.join("\n  - "));
    }
}
