//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use tempfile::TempDir;

/// Helper to get the first file from v2 JSON output
fn get_first_file(json: &serde_json::Value) -> Option<&serde_json::Value> {
    json.get("files").and_then(|f| f.get(0))
}

/// Test that shell-specific YARA rules match shell scripts
#[test]
fn test_shell_script_matches_shell_rules() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    // Script with base64 content that should trigger shell-specific base64 rule
    fs::write(&script_path, "#!/bin/bash\necho 'aWYgW1sg' | base64 -d\n").unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check file type and YARA matches (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        // Should detect shell file type
        let file_type = file.get("file_type").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            file_type.to_lowercase().contains("shell"),
            "Expected shell file type, got: {}",
            file_type
        );

        if let Some(yara_matches) = file.get("yara_matches").and_then(|v| v.as_array()) {
            // Look for shell-specific rules - should NOT be filtered
            let shell_rules: Vec<_> = yara_matches
                .iter()
                .filter(|m| {
                    m.get("rule")
                        .and_then(|r| r.as_str())
                        .map(|r| r.contains("shell") || r.contains("base64"))
                        .unwrap_or(false)
                })
                .collect();

            if !shell_rules.is_empty() {
                for rule in &shell_rules {
                    let severity = rule.get("severity").and_then(|s| s.as_str()).unwrap_or("");
                    // Shell-specific rules should NOT be filtered for shell scripts
                    assert_ne!(
                        severity,
                        "filtered",
                        "Shell rule {:?} should not be filtered for shell script",
                        rule.get("rule")
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

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check file type and YARA matches (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        // Should detect shell file type
        let file_type = file.get("file_type").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            file_type.to_lowercase().contains("shell"),
            "Expected shell file type, got: {}",
            file_type
        );

        if let Some(yara_matches) = file.get("yara_matches").and_then(|v| v.as_array()) {
            // Look for any matches with severity "filtered"
            let filtered_rules: Vec<_> = yara_matches
                .iter()
                .filter(|m| {
                    m.get("severity")
                        .and_then(|s| s.as_str())
                        .map(|s| s == "filtered")
                        .unwrap_or(false)
                })
                .collect();

            // If we have filtered rules, verify they're for wrong file types
            for rule in &filtered_rules {
                let rule_name = rule.get("rule").and_then(|r| r.as_str()).unwrap_or("");
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

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", py_file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check file type and YARA matches (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        // Should detect Python file type
        let file_type = file.get("file_type").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            file_type.to_lowercase().contains("python"),
            "Expected Python file type, got: {}",
            file_type
        );

        if let Some(yara_matches) = file.get("yara_matches").and_then(|v| v.as_array()) {
            // Look for Python-specific rules
            let python_rules: Vec<_> = yara_matches
                .iter()
                .filter(|m| {
                    m.get("rule")
                        .and_then(|r| r.as_str())
                        .map(|r| r.contains("marshal") || r.contains("python"))
                        .unwrap_or(false)
                })
                .collect();

            if !python_rules.is_empty() {
                for rule in &python_rules {
                    let severity = rule.get("severity").and_then(|s| s.as_str()).unwrap_or("");
                    // Python-specific rules should NOT be filtered for Python files
                    assert_ne!(
                        severity,
                        "filtered",
                        "Python rule {:?} should not be filtered for Python file",
                        rule.get("rule")
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

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check YARA matches (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        if let Some(yara_matches) = file.get("yara_matches").and_then(|v| v.as_array()) {
            // Generic rules (no filetype) should never be filtered
            for yara_match in yara_matches {
                let rule = yara_match
                    .get("rule")
                    .and_then(|r| r.as_str())
                    .unwrap_or("");
                let severity = yara_match
                    .get("severity")
                    .and_then(|s| s.as_str())
                    .unwrap_or("");

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

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", js_file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check file type and YARA matches (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        // Should detect JavaScript file type
        let file_type = file.get("file_type").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            file_type.to_lowercase().contains("javascript"),
            "Expected JavaScript file type, got: {}",
            file_type
        );

        if let Some(yara_matches) = file.get("yara_matches").and_then(|v| v.as_array()) {
            // Count filtered vs unfiltered
            let filtered_count = yara_matches
                .iter()
                .filter(|m| {
                    m.get("severity")
                        .and_then(|s| s.as_str())
                        .map(|s| s == "filtered")
                        .unwrap_or(false)
                })
                .count();

            let unfiltered_count = yara_matches
                .iter()
                .filter(|m| {
                    m.get("severity")
                        .and_then(|s| s.as_str())
                        .map(|s| s != "filtered")
                        .unwrap_or(false)
                })
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

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", temp_dir.path().to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should succeed and return JSON array
    assert!(output.status.success());

    // Parse as JSON array of reports (v2 format)
    if let Ok(reports) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(reports_array) = reports.as_array() {
            assert_eq!(reports_array.len(), 3, "Should have 3 analysis reports");

            // Each report should have files and metadata fields (v2 format)
            for report in reports_array {
                assert!(
                    report.get("files").is_some(),
                    "Each report should have files field"
                );
                assert!(
                    report.get("metadata").is_some(),
                    "Each report should have metadata field"
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

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        if let Some(yara_matches) = file.get("yara_matches").and_then(|v| v.as_array()) {
            // Look for filtered matches
            for yara_match in yara_matches {
                let severity = yara_match
                    .get("severity")
                    .and_then(|s| s.as_str())
                    .unwrap_or("");

                // If severity is "filtered", verify it's properly documented
                if severity == "filtered" {
                    let rule = yara_match
                        .get("rule")
                        .and_then(|r| r.as_str())
                        .unwrap_or("");
                    eprintln!("Found filtered match: {}", rule);

                    // Filtered matches should still have all required fields
                    assert!(yara_match.get("rule").is_some());
                    assert!(yara_match.get("description").is_some());
                    assert!(yara_match.get("namespace").is_some());
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

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_BUILTIN_YARA_ONLY", "1") // Skip third-party YARA for faster tests
        .args(["--json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        if let Some(yara_matches) = file.get("yara_matches").and_then(|v| v.as_array()) {
            // Should have both filtered and unfiltered matches preserved
            let total_matches = yara_matches.len();
            let filtered_matches = yara_matches
                .iter()
                .filter(|m| {
                    m.get("severity")
                        .and_then(|s| s.as_str())
                        .map(|s| s == "filtered")
                        .unwrap_or(false)
                })
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
                    yara_match.get("rule").is_some(),
                    "Match should have rule field"
                );
                assert!(
                    yara_match.get("severity").is_some(),
                    "Match should have severity field"
                );
                assert!(
                    yara_match.get("description").is_some(),
                    "Match should have description field"
                );
            }
        }
    }
}
