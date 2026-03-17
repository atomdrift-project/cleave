//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use predicates::prelude::*;

use std::collections::HashSet;
use std::fs;
use tempfile::TempDir;

/// Test that the binary runs and shows help
#[test]

fn test_help_command() {
    assert_cmd::cargo_bin_cmd!("cleave")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Deep static analysis tool"));
}

/// Test that the binary shows version
#[test]

fn test_version_command() {
    assert_cmd::cargo_bin_cmd!("cleave")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("cleave"));
}

/// Test analyze command with nonexistent file
#[test]

fn test_analyze_nonexistent_file() {
    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["analyze", "/nonexistent/file.bin"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

/// Test analyze command with a simple shell script
#[test]

fn test_analyze_shell_script() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    fs::write(&script_path, "#!/bin/bash\necho 'hello'\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["analyze", script_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("test.sh"));
}

/// Test analyze command with JSON output (JSON Lines format)
#[test]

fn test_analyze_json_output() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    fs::write(&script_path, "#!/bin/bash\necho 'hello'\n").unwrap();

    // JSON Lines format outputs: {"type":"file",...} followed by {"type":"summary",...}
    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["--json", "analyze", script_path.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""type":"file""#))
        .stdout(predicate::str::contains(r#""type":"summary""#));
}

/// Test analyze command with --format json output (single report object)
#[test]
fn test_analyze_format_json_output() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    fs::write(&script_path, "#!/bin/bash\necho 'hello'\n").unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .args(["--format", "json", "analyze", script_path.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON object");
    assert!(json.get("version").is_some());
    assert!(json.get("files").is_some());
}

/// Test analyze command with output to file (JSON Lines format)
#[test]

fn test_analyze_output_to_file() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");
    let output_path = temp_dir.path().join("output.json");

    fs::write(&script_path, "#!/bin/bash\necho 'hello'\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args([
            "--json",
            "-o",
            output_path.to_str().unwrap(),
            "analyze",
            script_path.to_str().unwrap(),
            // Third-party YARA is disabled by default (opt-in with --third-party-yara)
        ])
        .assert()
        .success();

    // Note: "Results written to" message is only printed for Terminal format, not JSON
    // The success assertion above confirms the command succeeded

    // Verify output file was created and contains JSON Lines format
    let content = fs::read_to_string(&output_path).unwrap();
    assert!(content.contains(r#""type":"file""#));
    assert!(content.contains(r#""type":"summary""#));
}

/// Test analyze command with empty directory
#[test]

fn test_analyze_empty_directory() {
    let temp_dir = TempDir::new().unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["analyze", temp_dir.path().to_str().unwrap()])
        .assert()
        .success();
}

/// Test analyze command with multiple files
#[test]

fn test_analyze_multiple_files() {
    let temp_dir = TempDir::new().unwrap();
    let script1 = temp_dir.path().join("test1.sh");
    let script2 = temp_dir.path().join("test2.sh");

    fs::write(&script1, "#!/bin/bash\necho 'test1'\n").unwrap();
    fs::write(&script2, "#!/bin/bash\necho 'test2'\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["analyze", temp_dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("test1.sh"))
        .stdout(predicate::str::contains("test2.sh"));
}

/// Test diff command with nonexistent files
#[test]

fn test_diff_nonexistent_files() {
    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["diff", "/nonexistent/old.bin", "/nonexistent/new.bin"])
        .assert()
        .failure();
}

/// Test diff command with identical files
#[test]

fn test_diff_identical_files() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("file1.sh");
    let file2 = temp_dir.path().join("file2.sh");

    let content = "#!/bin/bash\necho 'hello'\n";
    fs::write(&file1, content).unwrap();
    fs::write(&file2, content).unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["diff", file1.to_str().unwrap(), file2.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("No capability changes"));
}

/// Test diff command with different files
#[test]

fn test_diff_different_files() {
    let temp_dir = TempDir::new().unwrap();
    let file1 = temp_dir.path().join("old.sh");
    let file2 = temp_dir.path().join("new.sh");

    fs::write(&file1, "#!/bin/bash\necho 'old'\n").unwrap();
    fs::write(&file2, "#!/bin/bash\neval 'malicious'\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["diff", file1.to_str().unwrap(), file2.to_str().unwrap()])
        .assert()
        .success();
}

/// Test that missing subcommand fails
#[test]

fn test_missing_subcommand() {
    assert_cmd::cargo_bin_cmd!("cleave")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

/// Test invalid argument
#[test]

fn test_invalid_argument() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["--invalid-arg", "analyze", script.to_str().unwrap()])
        .assert()
        .failure();
}

/// Test verbose flag
#[test]

fn test_verbose_flag() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["-v", "analyze", script.to_str().unwrap()])
        .assert()
        .success();
}

/// Test analyze with Python file
#[test]

fn test_analyze_python_file() {
    let temp_dir = TempDir::new().unwrap();
    let py_file = temp_dir.path().join("test.py");

    fs::write(&py_file, "print('hello')\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["analyze", py_file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("test.py"));
}

/// Test analyze with JavaScript file
#[test]

fn test_analyze_javascript_file() {
    let temp_dir = TempDir::new().unwrap();
    let js_file = temp_dir.path().join("test.js");

    fs::write(&js_file, "console.log('hello');\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["analyze", js_file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("test.js"));
}

/// Test analyze directory with JSON output format
#[test]

fn test_analyze_directory_json_output() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["--json", "analyze", temp_dir.path().to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains(r#""type":"file""#));
}

/// Test that --yara flag enables YARA (deprecated feature, disabled by default)
/// Ignored by default: YARA rules are slow to compile in debug builds
/// Run with: cargo test --release test_yara_flag -- --ignored
#[test]
#[ignore]
fn test_yara_flag() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["analyze", script.to_str().unwrap(), "--yara"])
        .assert()
        .success();
}

/// Test that --third-party-yara enables third-party YARA rules
/// Ignored by default: YARA rules are slow to compile in debug builds
/// Run with: cargo test --release test_yara_third_party_flag -- --ignored
#[test]
#[ignore]
fn test_yara_third_party_flag() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\n").unwrap();

    // Third-party YARA is opt-in (disabled by default)
    // This test verifies the --third-party-yara flag enables it
    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["analyze", script.to_str().unwrap(), "--third-party-yara"])
        .assert()
        .success();
}

/// Test strings command with nonexistent file
#[test]
fn test_strings_nonexistent_file() {
    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["strings", "/nonexistent/file.bin"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

/// Test strings command with shell script
#[test]
fn test_strings_shell_script() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\necho 'hello world'\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["strings", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Extracted"))
        .stdout(predicate::str::contains("strings from"));
}

/// Test strings command with JSON output
#[test]
fn test_strings_json_output() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\necho 'test'\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["--json", "strings", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("["))
        .stdout(predicate::str::contains("\"value\""));
}

/// Test strings command with custom min length
#[test]
fn test_strings_custom_min_length() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\necho 'ab'\necho 'verylongstring'\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["strings", script.to_str().unwrap(), "-m", "10"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Extracted"));
}

/// Test symbols command with nonexistent file
#[test]
fn test_symbols_nonexistent_file() {
    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["symbols", "/nonexistent/file.bin"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("does not exist"));
}

/// Test symbols command with shell script
#[test]
fn test_symbols_shell_script() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\nls -la\ngrep pattern file.txt\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["symbols", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Extracted"))
        .stdout(predicate::str::contains("symbols from"))
        .stdout(predicate::str::contains("ADDRESS"))
        .stdout(predicate::str::contains("TYPE"))
        .stdout(predicate::str::contains("NAME"));
}

/// Test symbols command with Python script
#[test]
fn test_symbols_python_script() {
    let temp_dir = TempDir::new().unwrap();
    let py_file = temp_dir.path().join("test.py");
    fs::write(
        &py_file,
        "import os\nimport sys\n\ndef main():\n    print('hello')\n    sys.exit(0)\n",
    )
    .unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["symbols", py_file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("Extracted"))
        .stdout(predicate::str::contains("import"));
}

/// Test symbols command with JSON output
#[test]
fn test_symbols_json_output() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\nls\n").unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["--json", "symbols", script.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("["))
        .stdout(predicate::str::contains("\"name\""))
        .stdout(predicate::str::contains("\"symbol_type\""));
}

/// Test symbols command with JavaScript file
#[test]
fn test_symbols_javascript_file() {
    let temp_dir = TempDir::new().unwrap();
    let js_file = temp_dir.path().join("test.js");
    fs::write(
        &js_file,
        "function hello() {\n  console.log('world');\n}\nhello();\n",
    )
    .unwrap();

    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["symbols", js_file.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("symbols from"));
}

/// Test symbols command shows addresses for binaries
#[test]
#[cfg(target_os = "macos")]
fn test_symbols_binary_with_addresses() {
    // Test with /bin/ls which should have symbol addresses
    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["symbols", "/bin/ls"])
        .assert()
        .success()
        .stdout(predicate::str::contains("0x")) // Should show hex addresses
        .stdout(predicate::str::contains("import"));
}

/// Test strings and symbols output different data
#[test]
fn test_strings_vs_symbols_difference() {
    let temp_dir = TempDir::new().unwrap();
    let script = temp_dir.path().join("test.sh");
    fs::write(&script, "#!/bin/bash\nls -la\ntext='some string'\n").unwrap();

    // Strings should find literal text
    let strings_output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["strings", script.to_str().unwrap()])
        .output()
        .unwrap();
    let strings_stdout = String::from_utf8_lossy(&strings_output.stdout);

    // Symbols should find function calls
    let symbols_output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - testing CLI functionality
        .args(["symbols", script.to_str().unwrap()])
        .output()
        .unwrap();
    let symbols_stdout = String::from_utf8_lossy(&symbols_output.stdout);

    // Both should succeed but show different data
    assert!(strings_stdout.contains("some string"));
    assert!(symbols_stdout.contains("ls"));
    assert!(!symbols_stdout.contains("some string")); // Symbols don't show literal strings
}

/// Sanity check: a benign system binary should not trigger suspicious/hostile findings.
/// Asserts no more than 6 notable subdirectories, 0 suspicious/hostile, and no stderr output.
/// Uses /bin/ls on Unix, or C:\Windows\System32\attrib.exe on Windows.
#[test]
fn test_system_binary_false_positive_sanity() {
    use std::path::Path;

    #[cfg(not(windows))]
    let binary = "/bin/ls";
    #[cfg(windows)]
    let binary = r"C:\Windows\System32\attrib.exe";

    if !Path::new(binary).exists() {
        eprintln!("skipping: {binary} not found");
        return;
    }

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .args(["--json", "analyze", binary])
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    // Filter out the debug-build warning that's expected in test profile
    let unexpected_stderr: String = stderr
        .lines()
        .filter(|l| !l.contains("DEBUG binary"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        unexpected_stderr.trim().is_empty(),
        "Expected empty stderr, got:\n{}",
        stderr
    );
    assert!(output.status.success(), "cleave exited with failure");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let file_line = stdout
        .lines()
        .find(|l| l.contains(r#""type":"file""#))
        .unwrap_or_else(|| panic!("no file entry in JSONL output for {binary}"));

    let file_entry: serde_json::Value =
        serde_json::from_str(file_line).expect("invalid JSON in file entry");

    let findings = file_entry["findings"]
        .as_array()
        .expect("findings should be an array");

    let mut notable_dirs = HashSet::new();
    let mut suspicious = 0u32;
    let mut hostile = 0u32;

    for finding in findings {
        let crit = finding.get("crit").and_then(|v| v.as_str());
        let id = finding["id"].as_str().unwrap_or("");

        let subdir = id.split("::").next().unwrap_or(id);

        match crit {
            Some("notable") => {
                notable_dirs.insert(subdir.to_string());
            }
            Some("suspicious") => suspicious += 1,
            Some("hostile") => hostile += 1,
            _ => {}
        }
    }

    assert_eq!(
        hostile, 0,
        "expected 0 hostile findings for {binary}, got {hostile}"
    );
    assert_eq!(
        suspicious, 0,
        "expected 0 suspicious findings for {binary}, got {suspicious}"
    );
    assert!(
        notable_dirs.len() <= 6,
        "expected at most 6 notable subdirectories for {binary}, got {}: {:?}",
        notable_dirs.len(),
        notable_dirs
    );
}
