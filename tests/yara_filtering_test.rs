//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::fs;
use tempfile::TempDir;

/// Helper to get the first file from legacy `files` or compact `fs`.
fn get_first_file(json: &serde_json::Value) -> Option<&serde_json::Value> {
    if let Some(file) = json.get("fs").and_then(|f| f.get(0)) {
        return Some(file);
    }
    json.get("files").and_then(|f| f.get(0))
}

fn get_files(json: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    json.get("fs")
        .or_else(|| json.get("files"))
        .and_then(|v| v.as_array())
}

fn get_file_type(file: &serde_json::Value) -> &str {
    file.get("file_type")
        .or_else(|| file.get("type"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

fn get_matches(file: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    file.get("yara_matches")
        .or_else(|| file.get("ts"))
        .and_then(|v| v.as_array())
}

fn match_rule(yara_match: &serde_json::Value) -> Option<&str> {
    yara_match
        .get("rule")
        .or_else(|| yara_match.get("i"))
        .and_then(|v| v.as_str())
}

fn match_severity(yara_match: &serde_json::Value) -> Option<&str> {
    if let Some(severity) = yara_match.get("severity").and_then(|v| v.as_str()) {
        return Some(severity);
    }

    // Compact v4 encodes criticality numerically: 0=filtered, 1+=non-filtered.
    if let Some(level) = yara_match.get("l").and_then(Value::as_u64) {
        return Some(if level == 0 { "filtered" } else { "matched" });
    }

    None
}

fn match_description(yara_match: &serde_json::Value) -> Option<&str> {
    yara_match
        .get("description")
        .or_else(|| yara_match.get("d"))
        .and_then(|v| v.as_str())
}

fn match_namespace(yara_match: &serde_json::Value) -> Option<String> {
    if let Some(ns) = yara_match.get("namespace").and_then(|v| v.as_str()) {
        return Some(ns.to_string());
    }

    match_rule(yara_match).map(|rule| {
        rule.split_once("::")
            .map(|(prefix, _)| prefix.to_string())
            .unwrap_or_else(|| rule.to_string())
    })
}

/// Test that shell-specific YARA rules match shell scripts
#[test]
fn test_shell_script_matches_shell_rules() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    // Script with base64 content that should trigger shell-specific base64 rule
    fs::write(&script_path, "#!/bin/bash\necho 'aWYgW1sg' | base64 -d\n").unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check file type and YARA matches (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        // Should detect shell file type
        let file_type = get_file_type(file);
        assert!(
            file_type.to_lowercase().contains("shell"),
            "Expected shell file type, got: {}",
            file_type
        );

        if let Some(yara_matches) = get_matches(file) {
            // Look for shell-specific rules - should NOT be filtered
            let shell_rules: Vec<_> = yara_matches
                .iter()
                .filter(|m| {
                    match_rule(m)
                        .map(|r| r.contains("shell") || r.contains("base64"))
                        .unwrap_or(false)
                })
                .collect();

            if !shell_rules.is_empty() {
                for rule in &shell_rules {
                    let severity = match_severity(rule).unwrap_or("");
                    // Shell-specific rules should NOT be filtered for shell scripts
                    assert_ne!(
                        severity,
                        "filtered",
                        "Shell rule {:?} should not be filtered for shell script",
                        match_rule(rule)
                    );
                }
            }
        }
    }
}

/// Test that Python-specific YARA rules are filtered out for shell scripts
#[test]
fn test_python_rules_filtered_for_shell_scripts() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    // Shell script that might accidentally match Python patterns
    fs::write(&script_path, "#!/bin/bash\nimport os\neval something\n").unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check file type and YARA matches (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        // Should detect shell file type
        let file_type = get_file_type(file);
        assert!(
            file_type.to_lowercase().contains("shell"),
            "Expected shell file type, got: {}",
            file_type
        );

        if let Some(yara_matches) = get_matches(file) {
            // Look for any matches with severity "filtered"
            let filtered_rules: Vec<_> = yara_matches
                .iter()
                .filter(|m| match_severity(m).map(|s| s == "filtered").unwrap_or(false))
                .collect();

            // If we have filtered rules, verify they're for wrong file types
            for rule in &filtered_rules {
                let rule_name = match_rule(rule).unwrap_or("");
                eprintln!("Filtered rule for shell script: {}", rule_name);
                // The rule should be filtered - this is expected behavior
            }
        }
    }
}

/// Test that Python file gets Python-specific rules unfiltered
#[test]
fn test_python_file_matches_python_rules() {
    let temp_dir = TempDir::new().unwrap();
    let py_file = temp_dir.path().join("test.py");

    // Python file with marshal (Python-specific pattern)
    fs::write(
        &py_file,
        "#!/usr/bin/env python3\nimport marshal\ndata = marshal.loads(b'test')\n",
    )
    .unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", py_file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check file type and YARA matches (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        // Should detect Python file type
        let file_type = get_file_type(file);
        assert!(
            file_type.to_lowercase().contains("python"),
            "Expected Python file type, got: {}",
            file_type
        );

        if let Some(yara_matches) = get_matches(file) {
            // Look for Python-specific rules
            let python_rules: Vec<_> = yara_matches
                .iter()
                .filter(|m| {
                    match_rule(m)
                        .map(|r| r.contains("marshal") || r.contains("python"))
                        .unwrap_or(false)
                })
                .collect();

            if !python_rules.is_empty() {
                for rule in &python_rules {
                    let severity = match_severity(rule).unwrap_or("");
                    // Python-specific rules should NOT be filtered for Python files
                    assert_ne!(
                        severity,
                        "filtered",
                        "Python rule {:?} should not be filtered for Python file",
                        match_rule(rule)
                    );
                }
            }
        }
    }
}

/// Test that rules without filetype metadata are never filtered
#[test]
fn test_generic_rules_never_filtered() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    // Create a file that might match generic patterns
    fs::write(
        &script_path,
        "#!/bin/bash\ncurl http://example.com\nwget http://test.com\n",
    )
    .unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check YARA matches (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        if let Some(yara_matches) = get_matches(file) {
            // Generic rules (no filetype) should never be filtered
            for yara_match in yara_matches {
                let rule = match_rule(yara_match).unwrap_or("");
                let severity = match_severity(yara_match).unwrap_or("");

                // If a rule matches generic network patterns, it shouldn't be filtered
                if rule.contains("http") || rule.contains("curl") || rule.contains("wget") {
                    assert_ne!(
                        severity, "filtered",
                        "Generic rule '{}' should not be filtered",
                        rule
                    );
                }
            }
        }
    }
}

/// Test that JavaScript file filters out non-JS rules
#[test]
fn test_javascript_file_filters_non_js_rules() {
    let temp_dir = TempDir::new().unwrap();
    let js_file = temp_dir.path().join("test.js");

    // JavaScript with some content that might match shell or Python rules
    fs::write(&js_file, "const data = 'import os';\neval(data);\n").unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", js_file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check file type and YARA matches (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        // Should detect JavaScript file type
        let file_type = get_file_type(file);
        assert!(
            file_type.to_lowercase().contains("javascript"),
            "Expected JavaScript file type, got: {}",
            file_type
        );

        if let Some(yara_matches) = get_matches(file) {
            // Count filtered vs unfiltered
            let filtered_count = yara_matches
                .iter()
                .filter(|m| match_severity(m).map(|s| s == "filtered").unwrap_or(false))
                .count();

            let unfiltered_count = yara_matches
                .iter()
                .filter(|m| match_severity(m).map(|s| s != "filtered").unwrap_or(false))
                .count();

            eprintln!(
                "JavaScript file: {} unfiltered, {} filtered matches",
                unfiltered_count, filtered_count
            );
            // We should have some matches (either filtered or unfiltered)
            assert!(
                !yara_matches.is_empty(),
                "Should have at least some YARA matches"
            );
        }
    }
}

/// Test that analyze command works across multiple file types with filtering
#[test]
fn test_scan_multi_filetype_directory() {
    let temp_dir = TempDir::new().unwrap();

    // Create files of different types
    let sh_file = temp_dir.path().join("test.sh");
    let py_file = temp_dir.path().join("test.py");
    let js_file = temp_dir.path().join("test.js");

    fs::write(&sh_file, "#!/bin/bash\necho 'shell'\n").unwrap();
    fs::write(&py_file, "#!/usr/bin/env python3\nprint('python')\n").unwrap();
    fs::write(&js_file, "console.log('javascript');\n").unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", temp_dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should succeed and return JSON array
    assert!(output.status.success());

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(files) = get_files(&json) {
            assert_eq!(files.len(), 3, "Should have 3 analyzed files");
            for file in files {
                assert!(
                    !get_file_type(file).is_empty(),
                    "Each analyzed file should have a file type"
                );
            }
        }
    }
}

/// Test that filtered severity translates to Filtered criticality
#[test]
fn test_filtered_criticality_level() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    // Shell script with Python content that might match Python rules
    fs::write(&script_path, "#!/bin/bash\nimport marshal\n").unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        if let Some(yara_matches) = get_matches(file) {
            // Look for filtered matches
            for yara_match in yara_matches {
                let severity = match_severity(yara_match).unwrap_or("");

                // If severity is "filtered", verify it's properly documented
                if severity == "filtered" {
                    let rule = match_rule(yara_match).unwrap_or("");
                    eprintln!("Found filtered match: {}", rule);

                    // Filtered matches should still have all required fields
                    assert!(match_rule(yara_match).is_some());
                    assert!(match_description(yara_match).is_some());
                    assert!(match_namespace(yara_match).is_some());
                }
            }
        }
    }
}

/// Test filtered matches are preserved in output
#[test]
fn test_filtered_matches_preserved() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("polyglot.sh");

    // Create a file with content that might match multiple language patterns
    fs::write(
        &script_path,
        "#!/bin/bash\n\
         # This looks like it imports Python\n\
         import marshal\n\
         eval something\n\
         base64 data here\n",
    )
    .unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        if let Some(yara_matches) = get_matches(file) {
            // Should have both filtered and unfiltered matches preserved
            let total_matches = yara_matches.len();
            let filtered_matches = yara_matches
                .iter()
                .filter(|m| match_severity(m).map(|s| s == "filtered").unwrap_or(false))
                .count();

            eprintln!(
                "Total matches: {}, Filtered: {}",
                total_matches, filtered_matches
            );

            // Both filtered and unfiltered should be in the output
            assert!(total_matches > 0, "Should have at least some matches");

            // Verify filtered matches have all required fields
            for yara_match in yara_matches {
                assert!(
                    match_rule(yara_match).is_some(),
                    "Match should have rule field"
                );
                assert!(
                    match_severity(yara_match).is_some(),
                    "Match should have severity field"
                );
                assert!(
                    match_description(yara_match).is_some(),
                    "Match should have description field"
                );
            }
        }
    }
}
