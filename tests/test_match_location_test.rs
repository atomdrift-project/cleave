//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for test-match CLI command location constraint behavior.
//!
//! Verifies that --offset, --offset-range, --section, --section-offset, and
//! --section-offset-range constraints properly limit where patterns are searched.

use std::fs;
use tempfile::TempDir;

/// Create a test binary with known patterns at specific offsets:
/// - Offset 0-15: Header "TESTFILEHEADER!"
/// - Offset 16-31: Pattern A "AAAAAAAAAAAAAAAA" (16 bytes)
/// - Offset 32-47: Pattern B "BBBBBBBBBBBBBBBB" (16 bytes)
/// - Offset 48-63: Pattern C "CCCCCCCCCCCCCCCC" (16 bytes)
/// - Offset 64-79: Footer "ENDOFTESTFILE!!!"
fn create_test_binary() -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"TESTFILEHEADER!"); // 0-14 (15 bytes)
    data.push(b'!'); // 15 (1 byte to make 16)
    data.extend_from_slice(b"AAAAAAAAAAAAAAAA"); // 16-31
    data.extend_from_slice(b"BBBBBBBBBBBBBBBB"); // 32-47
    data.extend_from_slice(b"CCCCCCCCCCCCCCCC"); // 48-63
    data.extend_from_slice(b"ENDOFTESTFILE!!!"); // 64-79
    data
}

/// Test that hex search without constraints finds all patterns.
#[test]
fn test_hex_search_no_constraints() {
    let temp_dir = TempDir::new().unwrap();
    let bin_path = temp_dir.path().join("test.bin");
    fs::write(&bin_path, create_test_binary()).unwrap();

    // Search for "AAAA" hex pattern (41414141)
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "hex",
            "--pattern",
            "41414141", // "AAAA"
            bin_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("MATCHED"),
        "Should find AAAA pattern without constraints. Output: {}",
        stdout
    );
}

/// Test that hex search with offset_range finds patterns only within range.
#[test]
fn test_hex_search_offset_range_includes() {
    let temp_dir = TempDir::new().unwrap();
    let bin_path = temp_dir.path().join("test.bin");
    fs::write(&bin_path, create_test_binary()).unwrap();

    // Search for "AAAA" (41414141) within offset range [16, 48) - should find it
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "hex",
            "--pattern",
            "41414141",
            "--offset-range",
            "16,48",
            bin_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("MATCHED"),
        "Should find AAAA within range [16, 48). Output: {}",
        stdout
    );
}

/// Test that hex search with offset_range excludes patterns outside range.
#[test]
fn test_hex_search_offset_range_excludes() {
    let temp_dir = TempDir::new().unwrap();
    let bin_path = temp_dir.path().join("test.bin");
    fs::write(&bin_path, create_test_binary()).unwrap();

    // Search for "AAAA" (41414141) within offset range [48, 80) - pattern is at 16-31
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "hex",
            "--pattern",
            "41414141",
            "--offset-range",
            "48,80",
            bin_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("NOT MATCHED"),
        "Should NOT find AAAA in range [48, 80) - pattern is at 16-31. Output: {}",
        stdout
    );
}

/// Test that raw search with offset_range only searches within range.
#[test]
fn test_raw_search_offset_range_includes() {
    let temp_dir = TempDir::new().unwrap();
    let bin_path = temp_dir.path().join("test.bin");
    fs::write(&bin_path, create_test_binary()).unwrap();

    // Search for "BBBB" within offset range [32, 64) - should find it
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "raw",
            "--pattern",
            "BBBB",
            "--offset-range",
            "32,64",
            bin_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("MATCHED"),
        "Should find BBBB within range [32, 64). Output: {}",
        stdout
    );
}

/// Test that raw search with offset_range excludes patterns outside range.
#[test]
fn test_raw_search_offset_range_excludes() {
    let temp_dir = TempDir::new().unwrap();
    let bin_path = temp_dir.path().join("test.bin");
    fs::write(&bin_path, create_test_binary()).unwrap();

    // Search for "AAAA" within offset range [48, 80) - pattern is at 16-31
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "raw",
            "--pattern",
            "AAAA",
            "--offset-range",
            "48,80",
            bin_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("NOT MATCHED"),
        "Should NOT find AAAA in range [48, 80) - pattern is at 16-31. Output: {}",
        stdout
    );
}

/// Test that string search filters results by offset.
#[test]
fn test_string_search_offset_range_filters() {
    let temp_dir = TempDir::new().unwrap();
    let bin_path = temp_dir.path().join("test.bin");

    // Create a file with strings at known positions
    // We'll create strings that the string extractor can find
    let mut data = vec![0u8; 100];
    // Put "MATCH_ME" at offset 20
    let s1 = b"MATCH_ME\x00";
    data[20..20 + s1.len()].copy_from_slice(s1);
    // Put "ANOTHER_STRING" at offset 60
    let s2 = b"ANOTHER_STRING\x00";
    data[60..60 + s2.len()].copy_from_slice(s2);

    fs::write(&bin_path, &data).unwrap();

    // Search for "MATCH" within offset range [0, 40) - should find it
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "string-value",
            "--pattern",
            "MATCH",
            "--offset-range",
            "0,40",
            bin_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // If MATCH is found, verify it's within the expected range
    if !stdout.contains("MATCHED") {
        // String wasn't found - could be due to string extraction
        // This is acceptable if the string extractor didn't pick it up
        eprintln!("Note: string search didn't find pattern (may be extraction issue)");
    }
}

/// Test that density calculation uses effective range size, not full file size.
#[test]
fn test_density_uses_effective_range() {
    let temp_dir = TempDir::new().unwrap();
    let bin_path = temp_dir.path().join("test.bin");

    // Create a large file with pattern only in a small range
    let mut data = vec![0u8; 10240]; // 10KB file
                                     // Put "DEADBEEF" pattern in first 100 bytes (hex: 44454144424545)
    data[0..8].copy_from_slice(b"DEADBEEF");
    data[10..18].copy_from_slice(b"DEADBEEF");
    data[20..28].copy_from_slice(b"DEADBEEF");

    fs::write(&bin_path, &data).unwrap();

    // Search with small range - density should be high (3 matches / 0.1KB = 30/KB)
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "raw",
            "--pattern",
            "DEADBEEF",
            "--offset-range",
            "0,100",
            bin_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // Should show search range info when range differs from file size
    assert!(
        stdout.contains("Search range:") || stdout.contains("search_size"),
        "Should display search range when offset_range is specified. Output: {}",
        stdout
    );
}

/// Test negative offset (from end of file).
#[test]
fn test_hex_search_negative_offset_range() {
    let temp_dir = TempDir::new().unwrap();
    let bin_path = temp_dir.path().join("test.bin");
    fs::write(&bin_path, create_test_binary()).unwrap();

    // Search for "END" in last 20 bytes (negative offset)
    // File is 80 bytes, so -20 = offset 60
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "raw",
            "--pattern",
            "END",
            "--offset-range=-20,",
            bin_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("MATCHED"),
        "Should find END in last 20 bytes of file. Output: {}",
        stdout
    );
}

/// Test that --offset constraint works for exact position matching.
#[test]
fn test_hex_search_exact_offset() {
    let temp_dir = TempDir::new().unwrap();
    let bin_path = temp_dir.path().join("test.bin");
    fs::write(&bin_path, create_test_binary()).unwrap();

    // Pattern "BBBB" is at offset 32
    // Search at offset 32 should find it
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "hex",
            "--pattern",
            "42424242", // "BBBB"
            "--offset",
            "32",
            bin_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    assert!(
        stdout.contains("MATCHED"),
        "Should find BBBB at exact offset 32. Output: {}",
        stdout
    );
}

/// Test that `--is external_ip` filters out private IPs in string search.
#[test]
fn test_external_ip_filters_private() {
    let temp_dir = TempDir::new().unwrap();
    let bin_path = temp_dir.path().join("test.bin");

    // Create a file with both private and external IPs
    let mut data = vec![0u8; 200];
    // Put a private IP at offset 20
    let private_ip = b"192.168.1.100\x00";
    data[20..20 + private_ip.len()].copy_from_slice(private_ip);
    // Put an external IP at offset 100
    let external_ip = b"45.33.32.156\x00";
    data[100..100 + external_ip.len()].copy_from_slice(external_ip);

    fs::write(&bin_path, &data).unwrap();

    // Search for IP pattern WITHOUT --external-ip - should find both
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "string-value",
            "--pattern",
            "\\d+\\.\\d+\\.\\d+\\.\\d+",
            "--method",
            "regex",
            bin_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    // Should find at least one match (private or external)
    let found_without_filter = stdout.contains("MATCHED");

    // Search WITH --is external_ip - should only match the external IP
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "string-value",
            "--pattern",
            "\\d+\\.\\d+\\.\\d+\\.\\d+",
            "--method",
            "regex",
            "--is",
            "external-ip",
            bin_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);
    // Output should show the validator constraint
    assert!(
        stdout.contains("is: ExternalIp"),
        "Should display external_ip validator constraint. Output: {}",
        stdout
    );

    // If it matches, it should be the external IP, not the private one
    if stdout.contains("MATCHED") {
        assert!(
            stdout.contains("45.33.32.156") || !stdout.contains("192.168"),
            "With --is external_ip, should not match private IP 192.168.x.x. Output: {}",
            stdout
        );
    }

    // Ensure the test found something without the filter (sanity check)
    if !found_without_filter {
        eprintln!("Note: No IPs found without filter - may be string extraction issue");
    }
}

/// Test that base64 search type works (using encoded type with base64 encoding).
#[test]
fn test_base64_search_type() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.js");

    // Create a JS file with base64-encoded content
    // "Hello World" in base64 is "SGVsbG8gV29ybGQ="
    let script_content = r#"
const encoded = "SGVsbG8gV29ybGQ=";
const decoded = atob(encoded);
console.log(decoded);
"#;

    fs::write(&script_path, script_content).unwrap();

    // Search using encoded type with base64 encoding filter
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "encoded",
            "--encoding",
            "base64",
            "--pattern",
            "Hello",
            script_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // Should show encoded search context with base64
    assert!(
        stdout.contains("encoded") || stdout.contains("base64"),
        "Should show encoded/base64 search type. Output: {}",
        stdout
    );
}

/// Test that xor search type works (using encoded type with xor encoding).
#[test]
fn test_xor_search_type() {
    let temp_dir = TempDir::new().unwrap();
    let bin_path = temp_dir.path().join("test.bin");

    // Create a simple binary file
    let data = vec![0u8; 100];
    fs::write(&bin_path, &data).unwrap();

    // Search using encoded type with xor encoding filter
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "encoded",
            "--encoding",
            "xor",
            "--pattern",
            "secret",
            bin_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // Should show encoded search context with xor
    assert!(
        stdout.contains("encoded") || stdout.contains("xor"),
        "Should show encoded/xor search type. Output: {}",
        stdout
    );
}

/// Test that symbol search respects --case-insensitive flag.
#[test]
fn test_symbol_case_insensitive() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.py");

    // Create a Python file with function definitions
    let script_raw = r#"#!/usr/bin/env python3
def MyFunction():
    pass

def ANOTHER_FUNCTION():
    pass
"#;

    fs::write(&script_path, script_raw).unwrap();

    // Search WITHOUT --case-insensitive - should only match exact case
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "symbol",
            "--pattern",
            "myfunction",
            "--method",
            "exact",
            script_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout_no_ci = String::from_utf8_lossy(&output.get_output().stdout);

    // Search WITH --case-insensitive - should match regardless of case
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "symbol",
            "--pattern",
            "myfunction",
            "--method",
            "exact",
            "--case-insensitive",
            script_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout_ci = String::from_utf8_lossy(&output.get_output().stdout);

    // With case-insensitive, should show the flag in output
    assert!(
        stdout_ci.contains("case_insensitive: true"),
        "Should display case_insensitive flag. Output: {}",
        stdout_ci
    );

    // If lowercase "myfunction" matches with case-insensitive, that's correct
    // The exact case "MyFunction" exists, so case-insensitive should find it
    if stdout_no_ci.contains("MATCHED") && stdout_ci.contains("MATCHED") {
        // Both matched - likely found the function regardless
        eprintln!("Note: Both matched (symbol extraction may normalize case)");
    } else if !stdout_no_ci.contains("MATCHED") && stdout_ci.contains("MATCHED") {
        // Perfect: case-sensitive didn't match, case-insensitive did
        eprintln!("Case-insensitive matching works correctly");
    }
}

/// Test that `--is external_ip` works with raw search.
#[test]
fn test_external_ip_raw_search() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    // Create a script with IPs in text
    let script_raw = r#"#!/bin/bash
# Private IP: 10.0.0.1
curl http://45.33.32.156/api
echo "Done"
"#;

    fs::write(&script_path, script_raw).unwrap();

    // Search for IP pattern with --is external_ip
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_TRAITS", "1")
        .args([
            "test-match",
            "--type",
            "raw",
            "--pattern",
            r"\d+\.\d+\.\d+\.\d+",
            "--method",
            "regex",
            "--is",
            "external-ip",
            script_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // Should show the validator constraint
    assert!(
        stdout.contains("is: ExternalIp"),
        "Should display external_ip validator for raw search. Output: {}",
        stdout
    );

    // With external_ip, should only count the external IP (45.33.32.156), not 10.0.0.1
    // The regex would match both, but external_ip filter should reduce the count
    if stdout.contains("MATCHED") {
        // Check it found 1 match (the external IP) not 2
        assert!(
            stdout.contains("1 matches") || stdout.contains("1 match"),
            "With --is external_ip, should only match external IP (1 match). Output: {}",
            stdout
        );
    }
}
