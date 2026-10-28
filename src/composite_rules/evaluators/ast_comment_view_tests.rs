//! Comment-insensitive views must never change code, literals, or evidence.
#![allow(clippy::unwrap_used, reason = "invalid fixtures should fail the test")]
use super::ast::{batch_ast_queries, eval_ast_query, eval_ast_query_with_budget};
use crate::composite_rules::context::{AnalysisWarning, EvaluationContext};
use crate::composite_rules::types::FileType;
use crate::types::{AnalysisReport, TargetInfo};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

fn make_report(path: &str, source: &str) -> AnalysisReport {
    AnalysisReport::new(TargetInfo {
        path: path.into(),
        file_type: "source".into(),
        size_bytes: source.len() as u64,
        sha256: "fixture".into(),
        architectures: None,
    })
}
fn opt_in(query: &str) -> String {
    let (prefix, _) = query.rsplit_once(')').unwrap();
    format!("{prefix} (#set! cleave.ignore-comments \"true\"))")
}

#[test]
fn comment_view_preserves_literal_bytes_and_unicode_offsets_across_languages() {
    let cases = [
        (
            "view.c",
            FileType::C,
            "void f(void) { read(); /* λ\r\n comment */ send(\"/*literal*/\"); }",
            r#"((compound_statement . (expression_statement (call_expression function: (identifier) @a))
           . (expression_statement (call_expression function: (identifier) @b)) @evidence .)
           (#eq? @a "read") (#eq? @b "send"))"#,
        ),
        (
            "view.go",
            FileType::Go,
            "package fixture\nfunc f() { read()\n// λ comment\nsend(\"/*literal*/\")\n}",
            r#"((statement_list . (expression_statement (call_expression function: (identifier) @a))
           . (expression_statement (call_expression function: (identifier) @b)) @evidence .)
           (#eq? @a "read") (#eq? @b "send"))"#,
        ),
        (
            "view.ex",
            FileType::Elixir,
            "defmodule Fixture do\n def f do\n read()\n # λ comment\n send(\"#literal\")\n end\nend\n",
            r#"((do_block . (call target: (identifier) @a)
           . (call target: (identifier) @b) @evidence .)
           (#eq? @a "read") (#eq? @b "send"))"#,
        ),
    ];
    for (path, kind, source, query) in cases {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new(path))
            .open(source.as_bytes());
        let _ = parsed.values();
        let report = make_report(path, source);
        let mut ctx = EvaluationContext::test_only_new(&report, source.as_bytes(), kind);
        ctx.cached_ast = parsed.source_ast().map(|ast| ast.tree);
        assert!(
            !eval_ast_query(query, &ctx).matched,
            "ordinary tree: {path}"
        );
        let result = eval_ast_query(&opt_in(query), &ctx);
        assert!(result.matched, "comment-free tree: {path}");
        assert!(result.warnings.is_empty(), "{path}: {:?}", result.warnings);
        assert_eq!(
            result.evidence[0].offsets,
            [source.find("send(").unwrap() as u64]
        );
        assert!(result.evidence[0].value.contains("literal"));
        assert!(
            ctx.cached_commentless_ast
                .get()
                .is_some_and(Option::is_some)
        );
    }
}

#[test]
fn comment_view_does_not_activate_code_inside_comments_or_leak_into_raw_batches() {
    let source = "a(); /* b(); */\nb(\"/*literal*/\");";
    let parsed = filefacts::OpenOptions::new()
        .path(std::path::Path::new("view.js"))
        .open(source.as_bytes());
    let _ = parsed.values();
    let tree = parsed.source_ast().unwrap().tree;
    let raw = r#"((program . (expression_statement (call_expression function: (identifier) @a))
        . (expression_statement (call_expression function: (identifier) @b)) @evidence .)
        (#eq? @a "a") (#eq? @b "b"))"#;
    let normalized = opt_in(raw);
    let comment = "(comment) @evidence";
    let other = r#"((identifier) @evidence (#eq? @evidence "a"))"#;
    let batch = batch_ast_queries(
        tree,
        source,
        FileType::JavaScript,
        &[normalized.as_str(), comment, other],
        None,
        None,
    )
    .unwrap();
    assert!(
        !batch.contains_key(&normalized),
        "alternate trees are not answered by raw banks"
    );
    assert!(batch[comment].matched && batch[other].matched);
    let report = make_report("view.js", source);
    let mut ctx =
        EvaluationContext::test_only_new(&report, source.as_bytes(), FileType::JavaScript);
    ctx.cached_ast = Some(tree);
    ctx.ast_query_cache = Some(&batch);
    assert!(eval_ast_query(&normalized, &ctx).matched);
    assert!(!eval_ast_query(raw, &ctx).matched);
    assert!(eval_ast_query(comment, &ctx).matched);
    let only_comment = "a(); /* b(); */";
    let parsed = filefacts::OpenOptions::new()
        .path(std::path::Path::new("only.js"))
        .open(only_comment.as_bytes());
    let _ = parsed.values();
    let report = make_report("only.js", only_comment);
    let mut ctx =
        EvaluationContext::test_only_new(&report, only_comment.as_bytes(), FileType::JavaScript);
    ctx.cached_ast = parsed.source_ast().map(|ast| ast.tree);
    assert!(!eval_ast_query(&normalized, &ctx).matched);
}

#[test]
fn comment_view_keeps_cpu_limits_and_does_not_cache_interruptions() {
    let source = "a(); /* comment */ b();";
    let parsed = filefacts::OpenOptions::new()
        .path(std::path::Path::new("limit.js"))
        .open(source.as_bytes());
    let _ = parsed.values();
    let report = make_report("limit.js", source);
    let mut ctx =
        EvaluationContext::test_only_new(&report, source.as_bytes(), FileType::JavaScript);
    ctx.cached_ast = parsed.source_ast().map(|ast| ast.tree);
    let query =
        opt_in(r#"((program . (expression_statement) . (expression_statement) @evidence .))"#);
    let limited = eval_ast_query_with_budget(&query, &ctx, Duration::ZERO);
    assert!(!limited.matched);
    assert!(
        limited
            .warnings
            .iter()
            .any(|w| matches!(w, AnalysisWarning::AstTooDeep { max_depth: 0 }))
    );
    assert!(ctx.cached_commentless_ast.get().is_none());
    let cancelled = AtomicBool::new(true);
    ctx.cancellation = Some(&cancelled);
    assert!(!eval_ast_query(&query, &ctx).matched);
    assert!(ctx.cached_commentless_ast.get().is_none());
    cancelled.store(false, Ordering::Relaxed);
    assert!(eval_ast_query(&query, &ctx).matched);
}

#[test]
fn missing_required_literal_skips_comment_view_and_its_budget() {
    let source = "a(); /* comment */ b();";
    let parsed = filefacts::OpenOptions::new()
        .path(std::path::Path::new("prefilter.js"))
        .open(source.as_bytes());
    let _ = parsed.values();
    let report = make_report("prefilter.js", source);
    let mut ctx =
        EvaluationContext::test_only_new(&report, source.as_bytes(), FileType::JavaScript);
    ctx.cached_ast = parsed.source_ast().map(|ast| ast.tree);
    let query = opt_in(r#"((identifier) @name (#eq? @name "absent_required_name"))"#);
    let result = eval_ast_query_with_budget(&query, &ctx, Duration::ZERO);
    assert!(!result.matched);
    assert!(result.warnings.is_empty());
    assert!(ctx.cached_commentless_ast.get().is_none());
    let present = opt_in(r#"((identifier) @name (#eq? @name "b"))"#);
    let result = eval_ast_query(&present, &ctx);
    assert!(result.matched);
    assert_eq!(
        result.evidence[0].offsets,
        [source.find("b();").unwrap() as u64]
    );
    assert!(
        ctx.cached_commentless_ast
            .get()
            .is_some_and(Option::is_some)
    );
}
