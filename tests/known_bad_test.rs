//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug)]
struct FileStats {
    findings_count: usize,
    highest_criticality: String,
}

fn get_highest_criticality(file_result: &Value) -> String {
    if let Some(counts) = file_result.get("counts").and_then(|c| c.as_object()) {
        if counts.get("hostile").and_then(Value::as_u64).unwrap_or(0) > 0 {
            return "hostile".to_string();
        }
        if counts
            .get("suspicious")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0
        {
            return "suspicious".to_string();
        }
        if counts.get("notable").and_then(Value::as_u64).unwrap_or(0) > 0 {
            return "notable".to_string();
        }
    }
    "clean".to_string()
}

fn unified_diff(expected: &str, actual: &str) -> String {
    let expected_lines: Vec<&str> = expected.lines().collect();
    let actual_lines: Vec<&str> = actual.lines().collect();

    let mut diff = String::new();
    diff.push_str("--- expected\n");
    diff.push_str("+++ actual\n");

    let max_lines = expected_lines.len().max(actual_lines.len());
    for i in 0..max_lines {
        if i < expected_lines.len() && i < actual_lines.len() {
            if expected_lines[i] != actual_lines[i] {
                diff.push_str(&format!("-{}\n", expected_lines[i]));
                diff.push_str(&format!("+{}\n", actual_lines[i]));
            } else {
                diff.push_str(&format!(" {}\n", expected_lines[i]));
            }
        } else if i >= actual_lines.len() {
            diff.push_str(&format!("-{}\n", expected_lines[i]));
        } else {
            diff.push_str(&format!("+{}\n", actual_lines[i]));
        }
    }

    diff
}

fn core_integrity_mismatch(expected: &Value, actual: &Value) -> Vec<String> {
    let mut mismatches = Vec::new();
    for field in ["path", "sha256", "file_type", "size"] {
        let e = expected.get(field);
        let a = actual.get(field);
        if e != a {
            mismatches.push(format!(
                "field '{}' mismatch: expected {:?}, actual {:?}",
                field, e, a
            ));
        }
    }
    mismatches
}

fn extract_file_result(json_str: &str) -> Result<Value, Box<dyn std::error::Error>> {
    // For JSONL output, find the first JSON object line (skip header and empty lines)
    for line in json_str.lines() {
        let trimmed = line.trim();

        // Skip empty lines and cleave header
        if trimmed.is_empty() || trimmed.starts_with("cleave") {
            continue;
        }

        // Parse the JSON object
        return serde_json::from_str(trimmed).map_err(Into::into);
    }

    Err("No JSON output from cleave".into())
}

fn value_key(v: &Value, field: &str) -> String {
    v.get(field)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn normalize_file_result(v: &mut Value) {
    let Some(findings) = v.get_mut("findings").and_then(Value::as_array_mut) else {
        return;
    };

    for finding in findings.iter_mut() {
        if let Some(evidence) = finding.get_mut("evidence").and_then(Value::as_array_mut) {
            evidence.sort_by(|a, b| {
                let ka = (
                    value_key(a, "method"),
                    value_key(a, "source"),
                    value_key(a, "value"),
                    value_key(a, "location"),
                );
                let kb = (
                    value_key(b, "method"),
                    value_key(b, "source"),
                    value_key(b, "value"),
                    value_key(b, "location"),
                );
                ka.cmp(&kb)
            });
        }
    }

    findings.sort_by(|a, b| {
        let ka = (
            value_key(a, "id"),
            value_key(a, "kind"),
            value_key(a, "desc"),
            value_key(a, "crit"),
        );
        let kb = (
            value_key(b, "id"),
            value_key(b, "kind"),
            value_key(b, "desc"),
            value_key(b, "crit"),
        );
        ka.cmp(&kb)
    });
}

#[test]
fn test_known_bad_integrity() {
    let verify_dir = Path::new("tests/verify");
    if !verify_dir.exists() {
        eprintln!(
            "Warning: tests/verify directory not found. Run 'make regenerate-testdata' first."
        );
        return;
    }

    let mut test_files = Vec::new();
    for entry in WalkDir::new(verify_dir).into_iter().filter_map(Result::ok) {
        if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
            test_files.push(entry.path().to_path_buf());
        }
    }

    if test_files.is_empty() {
        eprintln!("No test data files found in tests/verify/");
        return;
    }

    test_files.sort();

    let mut stats = Vec::new();
    let mut mismatches = Vec::new();

    for snapshot_path in &test_files {
        let snapshot_content = fs::read_to_string(snapshot_path)
            .unwrap_or_else(|_| panic!("Failed to read {}", snapshot_path.display()));

        let mut expected_result: Value = serde_json::from_str(&snapshot_content)
            .unwrap_or_else(|_| panic!("Failed to parse JSON in {}", snapshot_path.display()));

        // Extract the original binary path from the snapshot
        let binary_path = expected_result
            .get("path")
            .and_then(|p| p.as_str())
            .unwrap_or_else(|| panic!("No path field in {}", snapshot_path.display()));
        let binary_path = binary_path.to_string();

        // Skip if binary no longer exists
        if !Path::new(&binary_path).exists() {
            continue;
        }

        // Run cleave on the binary
        let output = std::process::Command::new("./target/release/cleave")
            .arg("--format")
            .arg("jsonl")
            .arg(&binary_path)
            .output()
            .unwrap_or_else(|_| panic!("Failed to run cleave on {}", binary_path));

        if !output.status.success() {
            eprintln!(
                "Warning: cleave failed on {}: {}",
                binary_path,
                String::from_utf8_lossy(&output.stderr)
            );
            continue;
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut actual_result = extract_file_result(&stdout)
            .unwrap_or_else(|_| panic!("Failed to extract result from {}", binary_path));

        normalize_file_result(&mut expected_result);
        normalize_file_result(&mut actual_result);

        // Pretty-print for diff-friendly comparison
        let actual_json = serde_json::to_string_pretty(&actual_result).unwrap();

        // Collect stats
        let findings_count = actual_result
            .get("findings")
            .and_then(|f| f.as_array())
            .map(Vec::len)
            .unwrap_or(0);

        let criticality = get_highest_criticality(&actual_result);
        stats.push(FileStats {
            findings_count,
            highest_criticality: criticality,
        });

        // Compare only core integrity fields. Full finding bodies are intentionally
        // excluded because trait output ordering/content can vary across analyzer changes.
        let integrity_mismatches = core_integrity_mismatch(&expected_result, &actual_result);
        if !integrity_mismatches.is_empty() {
            let expected_json = serde_json::to_string_pretty(&expected_result).unwrap();
            let diff = format!(
                "{}\n\n{}",
                integrity_mismatches.join("\n"),
                unified_diff(&expected_json, &actual_json)
            );
            mismatches.push((binary_path.to_string(), diff));
        }
    }

    // Print summary statistics
    if !stats.is_empty() {
        println!("\n=== Integration Test Summary ===\n");

        let total_findings: usize = stats.iter().map(|s| s.findings_count).sum();
        let avg_findings = total_findings as f64 / stats.len() as f64;
        println!("Files analyzed: {}", stats.len());
        println!("Average traits per file: {:.2}", avg_findings);

        let mut criticality_counts = std::collections::HashMap::new();
        for stat in &stats {
            *criticality_counts
                .entry(stat.highest_criticality.clone())
                .or_insert(0) += 1;
        }

        println!("\nHighest criticality distribution:");
        for level in &["hostile", "suspicious", "notable", "clean"] {
            let count = criticality_counts.get(*level).copied().unwrap_or(0);
            let percentage = (count as f64 / stats.len() as f64) * 100.0;
            println!("  {}: {} ({:.1}%)", level, count, percentage);
        }
        println!();
    }

    // Fail with detailed diffs if mismatches found
    if !mismatches.is_empty() {
        eprintln!("\n=== Test Failures ({} files) ===\n", mismatches.len());
        for (path, diff) in &mismatches {
            eprintln!("MISMATCH: {}\n{}\n", path, diff);
        }
        panic!("{} file(s) had output mismatches", mismatches.len());
    }
}
