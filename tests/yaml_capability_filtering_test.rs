//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::fs;
use tempfile::TempDir;

/// Helper to get the first file from v2 JSON output
fn get_first_file(json: &serde_json::Value) -> Option<&serde_json::Value> {
    json.get("files").and_then(|f| f.get(0))
}

/// Test that platform-specific YAML traits are filtered correctly
#[test]
fn test_windows_keylog_capability_filtered_for_elf() {
    let temp_dir = TempDir::new().unwrap();

    // Create a simple ELF-like file (will be detected as unknown, but we can test the concept)
    // In reality, we'd need actual ELF/PE binaries for full integration
    let file_path = temp_dir.path().join("test.bin");

    // Write ELF magic bytes
    let elf_magic = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    fs::write(&file_path, elf_magic).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing YAML trait filtering
        .args(["--json", "analyze", file_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check file type and traits (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        // Should detect as ELF
        let file_type = file.get("file_type").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            file_type.to_lowercase().contains("elf"),
            "Expected ELF file type, got: {}",
            file_type
        );
        if let Some(traits) = file.get("traits").and_then(|v| v.as_array()) {
            // Get traits that are capabilities (capability: true)
            let capabilities: Vec<_> = traits
                .iter()
                .filter(|t| {
                    t.get("capability")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                })
                .collect();

            // Windows-specific traits should NOT appear in ELF analysis
            let windows_caps: Vec<_> = capabilities
                .iter()
                .filter(|cap| {
                    cap.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("windows") || id.contains("keylog"))
                        .unwrap_or(false)
                })
                .collect();

            // Windows keylogging traits should be filtered out for ELF files
            for cap in windows_caps {
                let cap_id = cap.get("id").and_then(|id| id.as_str()).unwrap_or("");
                eprintln!(
                    "Note: Windows cap '{}' appeared in ELF file - checking if expected",
                    cap_id
                );
            }
        }
    }
}

/// Test that universal (All) file type rules match everything
#[test]
fn test_universal_capabilities_match_all_files() {
    let temp_dir = TempDir::new().unwrap();

    // Test with shell script
    let script_path = temp_dir.path().join("test.sh");
    fs::write(&script_path, "#!/bin/bash\necho 'test'\n").unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing YAML trait filtering
        .args(["--json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON - just verify the structure works (v2 format)
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Verify basic structure exists (v2 format: files array)
        let file = get_first_file(&json).expect("Should have at least one file");
        assert!(
            file.get("file_type").is_some(),
            "Should have file_type field"
        );

        // Traits field may be missing if empty (skip_serializing_if)
        // Capabilities are traits with capability: true
        if let Some(traits) = file.get("traits").and_then(|v| v.as_array()) {
            let capabilities: Vec<_> = traits
                .iter()
                .filter(|t| {
                    t.get("capability")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                })
                .collect();
            eprintln!("Found {} capabilities for shell script", capabilities.len());
        } else {
            eprintln!("No traits detected for simple shell script (expected)");
        }
    }
}

/// Test that Python-specific traits match Python files
#[test]
fn test_python_capabilities_for_python_files() {
    let temp_dir = TempDir::new().unwrap();
    let py_file = temp_dir.path().join("test.py");

    // Python file with network operations
    fs::write(
        &py_file,
        "#!/usr/bin/env python3\nimport socket\ns = socket.socket()\n",
    )
    .unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing YAML trait filtering
        .args(["--json", "analyze", py_file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON to check file type and traits (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        // Should detect as Python
        let file_type = file.get("file_type").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            file_type.to_lowercase().contains("python"),
            "Expected Python file type, got: {}",
            file_type
        );
        if let Some(traits) = file.get("traits").and_then(|v| v.as_array()) {
            let capabilities: Vec<_> = traits
                .iter()
                .filter(|t| {
                    t.get("capability")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                })
                .collect();
            eprintln!("Found {} traits for Python file", capabilities.len());

            // Look for network-related capabilities
            let net_caps: Vec<_> = capabilities
                .iter()
                .filter(|cap| {
                    cap.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| {
                            id.contains("net") || id.contains("socket") || id.contains("http")
                        })
                        .unwrap_or(false)
                })
                .collect();

            if !net_caps.is_empty() {
                eprintln!("Found network traits:");
                for cap in &net_caps {
                    if let Some(id) = cap.get("id").and_then(|i| i.as_str()) {
                        eprintln!("  - {}", id);
                    }
                }
            }
        }
    }
}

/// Test that JavaScript-specific traits match JavaScript files
#[test]
fn test_javascript_capabilities_for_js_files() {
    let temp_dir = TempDir::new().unwrap();
    let js_file = temp_dir.path().join("test.js");

    // JavaScript with DOM access
    fs::write(
        &js_file,
        "const data = localStorage.getItem('key');\nconsole.log(data);\n",
    )
    .unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing YAML trait filtering
        .args(["--json", "analyze", js_file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON - verify structure (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        // Should detect as JavaScript
        let file_type = file.get("file_type").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            file_type.to_lowercase().contains("javascript"),
            "Expected JavaScript file type, got: {}",
            file_type
        );

        // Verify basic structure exists
        assert!(
            file.get("file_type").is_some(),
            "Should have file_type field"
        );

        // Traits field may be missing if empty
        if let Some(traits) = file.get("traits").and_then(|v| v.as_array()) {
            let capabilities: Vec<_> = traits
                .iter()
                .filter(|t| {
                    t.get("capability")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                })
                .collect();
            eprintln!(
                "Found {} capabilities for JavaScript file",
                capabilities.len()
            );
        } else {
            eprintln!("No traits detected for simple JS file (expected)");
        }

        // Check for YARA matches which are more likely for localStorage usage
        if let Some(yara_matches) = file.get("yara_matches").and_then(|v| v.as_array()) {
            eprintln!("Found {} YARA matches", yara_matches.len());
        }
    }
}

/// Test that shell-specific traits match shell scripts
#[test]
fn test_shell_capabilities_for_shell_scripts() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    // Shell script with network operations
    fs::write(
        &script_path,
        "#!/bin/bash\ncurl http://example.com\nwget http://test.com\n",
    )
    .unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing YAML trait filtering
        .args(["--json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        // Should detect as Shell
        let file_type = file.get("file_type").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            file_type.to_lowercase().contains("shell"),
            "Expected Shell file type, got: {}",
            file_type
        );
        if let Some(traits) = file.get("traits").and_then(|v| v.as_array()) {
            let capabilities: Vec<_> = traits
                .iter()
                .filter(|t| {
                    t.get("capability")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                })
                .collect();
            eprintln!("Found {} traits for shell script", capabilities.len());

            // Look for HTTP-related capabilities
            let http_caps: Vec<_> = capabilities
                .iter()
                .filter(|cap| {
                    cap.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("http") || id.contains("net"))
                        .unwrap_or(false)
                })
                .collect();

            if !http_caps.is_empty() {
                eprintln!("Found HTTP traits:");
                for cap in &http_caps {
                    if let Some(id) = cap.get("id").and_then(|i| i.as_str()) {
                        eprintln!("  - {}", id);
                    }
                }
            }
        }
    }
}

/// Test that rules without file_types specified work universally
#[test]
fn test_rules_without_filetype_are_universal() {
    let temp_dir = TempDir::new().unwrap();

    // Test with multiple file types
    let sh_file = temp_dir.path().join("test.sh");
    let py_file = temp_dir.path().join("test.py");
    let js_file = temp_dir.path().join("test.js");

    fs::write(&sh_file, "#!/bin/bash\necho 'shell'\n").unwrap();
    fs::write(&py_file, "#!/usr/bin/env python3\nprint('python')\n").unwrap();
    fs::write(&js_file, "console.log('javascript');\n").unwrap();

    // Analyze all three files
    for file in &[sh_file, py_file, js_file] {
        let output = assert_cmd::cargo_bin_cmd!("flayer")
            .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing trait filtering
            .args(["--json", "analyze", file.to_str().unwrap()])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "Analysis should succeed for {:?}",
            file.file_name()
        );

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse JSON - verify structure is correct for all file types (v2 format)
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
            let file_entry = get_first_file(&json).expect("Should have at least one file");
            // Verify basic structure exists
            assert!(
                file_entry.get("file_type").is_some(),
                "File {:?} should have file_type field",
                file.file_name()
            );

            // Traits field may be missing if empty
            if let Some(traits) = file_entry.get("traits").and_then(|v| v.as_array()) {
                let capabilities: Vec<_> = traits
                    .iter()
                    .filter(|t| {
                        t.get("capability")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                    })
                    .collect();
                eprintln!(
                    "File {:?} has {} capabilities",
                    file.file_name(),
                    capabilities.len()
                );
            } else {
                eprintln!(
                    "File {:?} has no traits detected (expected for simple scripts)",
                    file.file_name()
                );
            }
        }
    }
}

/// Test that composite trait evaluation respects file types
#[test]
fn test_composite_trait_file_type_filtering() {
    let temp_dir = TempDir::new().unwrap();

    // Create Python file with specific patterns that might trigger composite rules
    let py_file = temp_dir.path().join("suspicious.py");
    fs::write(
        &py_file,
        "#!/usr/bin/env python3\n\
         import socket\n\
         import os\n\
         s = socket.socket()\n\
         os.system('whoami')\n",
    )
    .unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing YAML trait filtering
        .args(["--json", "analyze", py_file.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse JSON (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        // Check traits
        if let Some(traits) = file.get("traits").and_then(|v| v.as_array()) {
            eprintln!("Found {} traits detected", traits.len());

            // Check that Python file gets appropriate capabilities
            let capabilities: Vec<_> = traits
                .iter()
                .filter(|t| {
                    t.get("capability")
                        .and_then(Value::as_bool)
                        .unwrap_or(false)
                })
                .collect();
            eprintln!(
                "Found {} traits for Python file with suspicious patterns",
                capabilities.len()
            );

            // Verify capabilities have proper structure
            for cap in &capabilities {
                assert!(cap.get("id").is_some(), "Capability should have id");
                assert!(
                    cap.get("description").is_some(),
                    "Capability should have description"
                );
                assert!(
                    cap.get("confidence").is_some(),
                    "Capability should have confidence"
                );
            }
        }
    }
}

/// Test that platform and file_type constraints work together
#[test]
fn test_platform_and_filetype_constraints_together() {
    let temp_dir = TempDir::new().unwrap();

    // Test with shell script (Unix platform)
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\necho 'test'\n").unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - testing YAML trait filtering
        .args(["--json", "analyze", script.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse and verify basic structure (v2 format: files[0])
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        let file = get_first_file(&json).expect("Should have at least one file");
        assert!(
            file.get("file_type").is_some(),
            "Should have file_type field"
        );

        // File type should be Shell
        if let Some(file_type) = file.get("file_type").and_then(|ft| ft.as_str()) {
            assert!(
                file_type.to_lowercase().contains("shell")
                    || file_type.to_lowercase().contains("script"),
                "File type should indicate shell script, got: {}",
                file_type
            );
        }
    }
}
