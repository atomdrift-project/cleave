//! AST-based condition evaluators for source code analysis.
//!
//! This module handles evaluation of Abstract Syntax Tree conditions:
//! - Pattern matching within specific AST node types
//! - Tree-sitter query execution
//! - Safe AST traversal with depth limits

use super::{build_regex, truncate_evidence};
use crate::composite_rules::ast_kinds::map_kind_to_node_types;
use crate::composite_rules::context::{AnalysisWarning, ConditionResult, EvaluationContext};
use crate::composite_rules::types::FileType;
use crate::types::{Evidence, MAX_EVIDENCE_PER_TRAIT};
use std::cell::RefCell;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::sync::Arc;
use streaming_iterator::StreamingIterator;

/// Maximum number of compiled tree-sitter queries to cache per thread.
/// Queries are keyed by (FileType, query_string). The set of distinct queries
/// is bounded by the number of trait definitions, so 256 is generous while
/// keeping memory modest (~10-50 KB per compiled query).
const QUERY_CACHE_MAX_SIZE: usize = 256;
const QUERY_CACHE_SIZE: NonZeroUsize = {
    #[allow(clippy::expect_used)]
    NonZeroUsize::new(QUERY_CACHE_MAX_SIZE).expect("QUERY_CACHE_MAX_SIZE is non-zero")
};

thread_local! {
    static QUERY_CACHE: RefCell<lru::LruCache<(FileType, String), Arc<tree_sitter::Query>>> = {
        RefCell::new(lru::LruCache::new(QUERY_CACHE_SIZE))
    };
}

/// Clear the thread-local AST query cache for this thread.
#[allow(dead_code)] // Called via clear_thread_local_caches
pub(crate) fn clear_ast_query_cache() {
    QUERY_CACHE.with(|cache| {
        cache.borrow_mut().clear();
    });
}

/// Match mode for AST pattern matching
#[derive(Clone, Copy)]
enum MatchMode {
    /// Exact equality match
    Exact,
    /// Substring/contains match
    Substr,
    /// Regex pattern match
    Regex,
}

/// Check if file type supports AST parsing.
/// Positive list: only types with a tree-sitter parser are supported.
fn supports_ast(file_type: FileType) -> bool {
    matches!(
        file_type,
        FileType::C
            | FileType::Python
            | FileType::JavaScript
            | FileType::TypeScript
            | FileType::Rust
            | FileType::Go
            | FileType::Java
            | FileType::Ruby
            | FileType::Shell
            | FileType::Php
            | FileType::CSharp
            | FileType::Lua
            | FileType::Perl
            | FileType::PowerShell
            | FileType::Swift
            | FileType::ObjectiveC
            | FileType::Groovy
            | FileType::Scala
            | FileType::Zig
            | FileType::Elixir
    )
}

/// Evaluate unified AST condition
/// Handles both simple mode (kind/node + exact/substr/regex) and advanced mode (query)
pub(crate) fn eval_ast<'a>(
    kind: Option<&str>,
    node: Option<&str>,
    exact: Option<&str>,
    substr: Option<&str>,
    regex: Option<&str>,
    query: Option<&str>,
    case_insensitive: bool,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    // Skip AST evaluation for file types that don't support tree-sitter parsing
    if !supports_ast(ctx.file_type) {
        return ConditionResult::no_match();
    }

    // Advanced mode: use tree-sitter query
    if let Some(query_str) = query {
        return eval_ast_query(query_str, ctx);
    }

    // Simple mode: kind/node + exact/substr/regex
    // Determine match mode: exact (equality), substr (contains), or regex
    let (pattern, match_mode) = if let Some(e) = exact {
        (e, MatchMode::Exact)
    } else if let Some(s) = substr {
        (s, MatchMode::Substr)
    } else if let Some(r) = regex {
        (r, MatchMode::Regex)
    } else {
        ("", MatchMode::Substr) // default to substr for empty pattern
    };

    // Get node types to search for
    let node_types: Vec<&str> = if let Some(k) = kind {
        map_kind_to_node_types(k, ctx.file_type)
    } else if let Some(n) = node {
        vec![n]
    } else {
        return ConditionResult::no_match();
    };

    if node_types.is_empty() {
        return ConditionResult::no_match();
    }

    // Idea 9: Use batch AST cache if available
    if let Some(cache) = ctx.ast_kind_cache {
        let mut evidence = Vec::new();
        let mut match_count = 0;

        for &nt in &node_types {
            if let Some(nodes) = cache.get(nt) {
                for node_ev in nodes {
                    // Re-verify the pattern on the cached node text
                    let matched = match match_mode {
                        MatchMode::Exact => {
                            if case_insensitive {
                                node_ev.value.eq_ignore_ascii_case(pattern)
                            } else {
                                node_ev.value == pattern
                            }
                        }
                        MatchMode::Substr => {
                            if case_insensitive {
                                node_ev.value.to_lowercase().contains(&pattern.to_lowercase())
                            } else {
                                node_ev.value.contains(pattern)
                            }
                        }
                        MatchMode::Regex => match build_regex(pattern, case_insensitive) {
                            Ok(re) => re.is_match(&node_ev.value),
                            Err(_) => false,
                        },
                    };

                    if matched {
                        match_count += 1;
                        if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                            evidence.push(node_ev.clone());
                        }
                    }
                }
            }
        }

        if match_count > 0 {
            return ConditionResult {
                matched: true,
                evidence,
                match_count,
                warnings: Vec::new(),
                precision: 2.0, // Same as simple mode
                matched_trait_ids: Vec::new(),
            };
        } else {
            return ConditionResult::no_match();
        }
    }

    // Use cached AST or parse
    let Ok(source) = std::str::from_utf8(ctx.binary_data) else {
        return ConditionResult::no_match();
    };

    if let Some(cached_tree) = ctx.cached_ast {
        return eval_ast_pattern_multi(
            cached_tree,
            source,
            &node_types,
            pattern,
            match_mode,
            case_insensitive,
            ctx.deadline,
        );
    }

    // No cached AST: the primary parse either timed out or was never attempted.
    // For large files the primary parse already failed — re-parsing per-rule would
    // only duplicate the failure while burning memory across every rayon thread.
    // Bail out immediately for anything over the threshold; smaller files get a
    // bounded fallback parse below (safety net for file types generic.rs handles).
    const MAX_FALLBACK_PARSE_BYTES: usize = 2_000_000; // 2 MB
    if ctx.binary_data.len() > MAX_FALLBACK_PARSE_BYTES {
        return ConditionResult::no_match();
    }

    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::info!(file_type = ?ctx.file_type, "AST cache miss — re-parsing AST for each trait");
    }

    // Get parser language for file type
    let parser_lang = match ctx.file_type {
        FileType::C => Some(tree_sitter_c::LANGUAGE),
        FileType::Python => Some(tree_sitter_python::LANGUAGE),
        FileType::JavaScript => Some(tree_sitter_javascript::LANGUAGE),
        FileType::TypeScript => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT),
        FileType::Rust => Some(tree_sitter_rust::LANGUAGE),
        FileType::Go => Some(tree_sitter_go::LANGUAGE),
        FileType::Java => Some(tree_sitter_java::LANGUAGE),
        FileType::Ruby => Some(tree_sitter_ruby::LANGUAGE),
        FileType::Shell => Some(tree_sitter_bash::LANGUAGE),
        FileType::Php => Some(tree_sitter_php::LANGUAGE_PHP),
        FileType::CSharp => Some(tree_sitter_c_sharp::LANGUAGE),
        FileType::Lua => Some(tree_sitter_lua::LANGUAGE),
        FileType::Perl => Some(tree_sitter_perl::LANGUAGE),
        FileType::PowerShell => Some(tree_sitter_powershell::LANGUAGE),
        FileType::Swift => Some(tree_sitter_swift::LANGUAGE),
        FileType::ObjectiveC => Some(tree_sitter_objc::LANGUAGE),
        FileType::Groovy => Some(tree_sitter_groovy::LANGUAGE),
        FileType::Scala => Some(tree_sitter_scala::LANGUAGE),
        FileType::Zig => Some(tree_sitter_zig::LANGUAGE),
        FileType::Elixir => Some(tree_sitter_elixir::LANGUAGE),
        _ => None,
    };

    let lang: tree_sitter::Language = match parser_lang {
        Some(l) => l.into(),
        None => return ConditionResult::no_match(),
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang).is_err() {
        return ConditionResult::no_match();
    }

    // Use a 4-second timeout for fallback parses to avoid unbounded memory growth
    // when the primary parse already timed out (e.g. huge minified JS files).
    let fallback_deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
    let mut parse_opts = tree_sitter::ParseOptions::new();
    let mut timeout_cb = |_: &tree_sitter::ParseState| -> std::ops::ControlFlow<()> {
        if std::time::Instant::now() > fallback_deadline {
            std::ops::ControlFlow::Break(())
        } else {
            std::ops::ControlFlow::Continue(())
        }
    };
    parse_opts.progress_callback = Some(&mut timeout_cb);
    let src_bytes = source.as_bytes();
    let Some(tree) = parser.parse_with_options(
        &mut |i, _| {
            if i < src_bytes.len() {
                &src_bytes[i..]
            } else {
                &[]
            }
        },
        None,
        Some(parse_opts),
    ) else {
        return ConditionResult::no_match();
    };

    eval_ast_pattern_multi(
        &tree,
        source,
        &node_types,
        pattern,
        match_mode,
        case_insensitive,
        ctx.deadline,
    )
}

/// Evaluate AST pattern matching against multiple node types
fn eval_ast_pattern_multi(
    tree: &tree_sitter::Tree,
    source: &str,
    node_types: &[&str],
    pattern: &str,
    match_mode: MatchMode,
    case_insensitive: bool,
    deadline: Option<std::time::Instant>,
) -> ConditionResult {
    // Track parse errors but continue — tree-sitter recovers from minor errors
    let has_parse_errors = tree.root_node().has_error();

    // Build the pattern matcher based on match mode
    let matcher: Box<dyn Fn(&str) -> bool> = match match_mode {
        MatchMode::Regex => match build_regex(pattern, case_insensitive) {
            Ok(re) => Box::new(move |s: &str| re.is_match(s)),
            Err(_) => return ConditionResult::no_match(),
        },
        MatchMode::Exact => {
            let pattern_owned = pattern.to_string();
            if case_insensitive {
                Box::new(move |s: &str| s.eq_ignore_ascii_case(&pattern_owned))
            } else {
                Box::new(move |s: &str| s == pattern_owned)
            }
        }
        MatchMode::Substr => {
            let pattern_owned = pattern.to_string();
            if case_insensitive {
                let pattern_lower = pattern.to_lowercase();
                Box::new(move |s: &str| s.to_lowercase().contains(&pattern_lower))
            } else {
                Box::new(move |s: &str| s.contains(&pattern_owned))
            }
        }
    };

    // Walk the AST and find matching nodes
    let mut evidence = Vec::new();
    let mut match_count: usize = 0;
    let mut cursor = tree.walk();
    let stats = walk_ast_for_pattern_multi(
        &mut cursor,
        source.as_bytes(),
        node_types,
        &matcher,
        &mut evidence,
        &mut match_count,
        deadline,
    );

    let mut warnings = Vec::new();
    if has_parse_errors {
        warnings.push(AnalysisWarning::AstParseError);
    }
    if stats.depth_limit_hit {
        warnings.push(AnalysisWarning::AstTooDeep {
            max_depth: stats.max_depth_reached,
        });
    }

    // Calculate precision: base 2.0 + 1.0 for node type + 1.0 for pattern + case_insensitive penalty
    let mut precision = 2.0f32; // Base for AST
    precision += 1.0; // node_types are always present here (from kind or node)

    // Pattern type specificity
    match match_mode {
        MatchMode::Exact | MatchMode::Regex => precision += 1.0, // Most specific / pattern matching
        MatchMode::Substr => precision += 0.5,                   // Least specific
    }

    if case_insensitive {
        precision *= 0.5;
    }

    ConditionResult {
        matched: match_count > 0,
        evidence,
        match_count,
        warnings,
        precision,
        matched_trait_ids: Vec::new(),
    }
}

/// Iteratively walk AST looking for nodes matching any of the target types
fn walk_ast_for_pattern_multi<'a>(
    cursor: &mut tree_sitter::TreeCursor<'a>,
    source: &[u8],
    target_node_types: &[&str],
    matcher: &dyn Fn(&str) -> bool,
    evidence: &mut Vec<Evidence>,
    match_count: &mut usize,
    deadline: Option<std::time::Instant>,
) -> crate::analyzers::ast_walker::WalkStats {
    crate::analyzers::ast_walker::walk_tree_with_stats(cursor, deadline, |node, _depth| {
        // Check if this node matches any of the target types
        let node_kind = node.kind();
        if target_node_types.contains(&node_kind) {
            if let Ok(text) = node.utf8_text(source) {
                if matcher(text) {
                    *match_count += 1;
                    if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                        evidence.push(Evidence {
                            method: "ast".to_string(),
                            source: "tree-sitter".to_string(),
                            value: truncate_evidence(text, 100),
                            location: Some(format!(
                                "{}:{}",
                                node.start_position().row + 1,
                                node.start_position().column + 1
                            )),
                            offsets: vec![node.start_byte() as u64],
                            ..Default::default()
                        });
                    }
                }
            }
        }
        true // continue traversal into children
    })
}

/// Evaluate full tree-sitter query condition
#[must_use]
pub(crate) fn eval_ast_query<'a>(query_str: &str, ctx: &EvaluationContext<'a>) -> ConditionResult {
    // Only works for source code files
    let Ok(source) = std::str::from_utf8(ctx.binary_data) else {
        return ConditionResult::no_match();
    };

    // Get the appropriate language for this file type
    let lang: tree_sitter::Language = match ctx.file_type {
        FileType::C => tree_sitter_c::LANGUAGE.into(),
        FileType::Python => tree_sitter_python::LANGUAGE.into(),
        FileType::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        FileType::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        FileType::Rust => tree_sitter_rust::LANGUAGE.into(),
        FileType::Go => tree_sitter_go::LANGUAGE.into(),
        FileType::Java => tree_sitter_java::LANGUAGE.into(),
        FileType::Ruby => tree_sitter_ruby::LANGUAGE.into(),
        FileType::Shell => tree_sitter_bash::LANGUAGE.into(),
        FileType::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        FileType::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        FileType::Lua => tree_sitter_lua::LANGUAGE.into(),
        FileType::Perl => tree_sitter_perl::LANGUAGE.into(),
        FileType::PowerShell => tree_sitter_powershell::LANGUAGE.into(),
        FileType::Swift => tree_sitter_swift::LANGUAGE.into(),
        FileType::ObjectiveC => tree_sitter_objc::LANGUAGE.into(),
        FileType::Groovy => tree_sitter_groovy::LANGUAGE.into(),
        FileType::Scala => tree_sitter_scala::LANGUAGE.into(),
        FileType::Zig => tree_sitter_zig::LANGUAGE.into(),
        FileType::Elixir => tree_sitter_elixir::LANGUAGE.into(),
        _ => return ConditionResult::no_match(),
    };

    // Use cached AST if available, otherwise attempt a bounded fallback parse.
    // Large files skip the fallback immediately: if the primary parse timed out,
    // a per-rule re-parse across N rayon threads would replicate the failure while
    // spiking RSS proportionally to thread count.
    let parsed_tree;
    let tree = if let Some(cached) = ctx.cached_ast {
        cached
    } else {
        const MAX_FALLBACK_PARSE_BYTES: usize = 2_000_000; // 2 MB
        if source.len() > MAX_FALLBACK_PARSE_BYTES {
            return ConditionResult::no_match();
        }
        let mut parser = tree_sitter::Parser::new();
        if parser.set_language(&lang).is_err() {
            return ConditionResult::no_match();
        }
        // Bounded fallback parse: 4-second timeout as a safety net.
        let fallback_deadline = std::time::Instant::now() + std::time::Duration::from_secs(4);
        let mut parse_opts = tree_sitter::ParseOptions::new();
        let mut timeout_cb = |_: &tree_sitter::ParseState| -> std::ops::ControlFlow<()> {
            if std::time::Instant::now() > fallback_deadline {
                std::ops::ControlFlow::Break(())
            } else {
                std::ops::ControlFlow::Continue(())
            }
        };
        parse_opts.progress_callback = Some(&mut timeout_cb);
        let src_bytes = source.as_bytes();
        parsed_tree = match parser.parse_with_options(
            &mut |i, _| {
                if i < src_bytes.len() {
                    &src_bytes[i..]
                } else {
                    &[]
                }
            },
            None,
            Some(parse_opts),
        ) {
            Some(t) => t,
            None => return ConditionResult::no_match(),
        };
        &parsed_tree
    };

    // Track parse errors but continue — tree-sitter recovers from minor errors
    let has_parse_errors = tree.root_node().has_error();

    // Compile the query (cached per thread to avoid recompilation across files).
    // Uses Arc so the Query stays alive even if evicted from the LRU cache mid-use.
    let query_arc = QUERY_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let key = (ctx.file_type, query_str.to_string());
        if let Some(q) = cache.get(&key) {
            return Some(Arc::clone(q));
        }
        match tree_sitter::Query::new(&lang, query_str) {
            Ok(q) => {
                let arc = Arc::new(q);
                cache.put(key, Arc::clone(&arc));
                Some(arc)
            }
            Err(_) => None,
        }
    });
    let Some(query) = query_arc else {
        return ConditionResult::no_match();
    };

    // Execute the query with safety limits
    let mut query_cursor = tree_sitter::QueryCursor::new();

    // Set limits to prevent runaway queries on pathological inputs
    // This prevents tree-sitter assertion failures on malformed files
    query_cursor.set_match_limit(100_000); // Limit pattern matches
    query_cursor.set_byte_range(0..source.len().min(10_000_000)); // Limit to first 10MB

    let mut evidence = Vec::new();

    // Text provider implementation for predicate checking
    struct SourceTextProvider<'a>(&'a [u8]);
    impl<'a> tree_sitter::TextProvider<&'a [u8]> for SourceTextProvider<'a> {
        type I = std::iter::Once<&'a [u8]>;
        fn text<'b>(&mut self, node: tree_sitter::Node<'b>) -> Self::I {
            let start = node.byte_range().start;
            let end = node.byte_range().end.min(self.0.len());
            std::iter::once(&self.0[start..end])
        }
    }

    // Use matches_with_options to enforce deadline via progress callback.
    // Without this, pathological inputs can cause queries to run for minutes.
    let mut match_count: usize = 0;
    let deadline = ctx.deadline;
    let mut timed_out = false;
    let mut progress_cb = |_state: &tree_sitter::QueryCursorState| -> ControlFlow<()> {
        if let Some(dl) = deadline {
            if std::time::Instant::now() > dl {
                return ControlFlow::Break(());
            }
        }
        ControlFlow::Continue(())
    };
    let options = tree_sitter::QueryCursorOptions::default().progress_callback(&mut progress_cb);
    let mut matches =
        query_cursor.matches_with_options(&query, tree.root_node(), source.as_bytes(), options);
    let mut buffer1: Vec<u8> = Vec::new();
    let mut buffer2: Vec<u8> = Vec::new();
    while let Some(m) = matches.next() {
        // Check deadline between matches too
        if let Some(dl) = deadline {
            if std::time::Instant::now() > dl {
                timed_out = true;
                break;
            }
        }
        // Check text predicates (e.g., #eq?, #match?) using tree-sitter's built-in method
        // This is REQUIRED - tree-sitter does NOT automatically filter by text predicates
        let mut text_provider = SourceTextProvider(source.as_bytes());
        if !m.satisfies_text_predicates(&query, &mut buffer1, &mut buffer2, &mut text_provider) {
            continue; // Skip matches that don't satisfy predicates
        }

        for capture in m.captures {
            if let Ok(text) = capture.node.utf8_text(source.as_bytes()) {
                match_count += 1;
                if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "ast_query".to_string(),
                        source: "tree-sitter".to_string(),
                        value: truncate_evidence(text, 100),
                        location: Some(format!(
                            "{}:{}",
                            capture.node.start_position().row + 1,
                            capture.node.start_position().column + 1
                        )),
                        offsets: vec![capture.node.start_byte() as u64],
                        ..Default::default()
                    });
                }
            }
        }
    }
    let mut warnings = Vec::new();
    if has_parse_errors {
        warnings.push(AnalysisWarning::AstParseError);
    }
    if timed_out {
        warnings.push(AnalysisWarning::AstTooDeep { max_depth: 0 });
    }
    ConditionResult {
        matched: match_count > 0,
        evidence,
        match_count,
        warnings,
        precision: 2.0, // Tree-sitter queries are complex and specific
        matched_trait_ids: Vec::new(),
    }
}
