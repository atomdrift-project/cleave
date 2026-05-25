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
use parking_lot::RwLock;
use std::num::NonZeroUsize;
use std::ops::ControlFlow;
use std::sync::{Arc, LazyLock};
use streaming_iterator::StreamingIterator;

/// Maximum number of compiled tree-sitter queries to cache.
/// Queries are keyed by (FileType, query_string). The set of distinct queries
/// is bounded by the number of trait definitions, so 256 is generous while
/// keeping memory modest (~10-50 KB per compiled query).
const QUERY_CACHE_MAX_SIZE: usize = 256;
const QUERY_CACHE_SIZE: NonZeroUsize = {
    #[allow(clippy::expect_used)]
    NonZeroUsize::new(QUERY_CACHE_MAX_SIZE).expect("QUERY_CACHE_MAX_SIZE is non-zero")
};

/// Process-wide compiled-query cache.
///
/// Was previously per-thread — but `tree_sitter::Query` is `Send + Sync` via
/// `Arc`, and CPU profiles showed `ts_query_new` consuming thousands of
/// samples because each rayon worker recompiled the same queries
/// independently. Sharing across threads eliminates that redundancy. Writes
/// are rare (cache miss on cold start), reads are frequent; `RwLock` keeps
/// reads parallel.
static QUERY_CACHE: LazyLock<RwLock<lru::LruCache<(FileType, String), Arc<tree_sitter::Query>>>> =
    LazyLock::new(|| RwLock::new(lru::LruCache::new(QUERY_CACHE_SIZE)));

/// Clear the shared AST query cache.
#[allow(dead_code)] // Called via clear_thread_local_caches
pub(crate) fn clear_ast_query_cache() {
    QUERY_CACHE.write().clear();
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
pub(crate) fn supports_ast(file_type: FileType) -> bool {
    file_type.supports_ast_queries()
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

        // Build the matcher once so it's shared between value/alt_value tries.
        let test_match = |candidate: &str| -> bool {
            match match_mode {
                MatchMode::Exact => {
                    if case_insensitive {
                        candidate.eq_ignore_ascii_case(pattern)
                    } else {
                        candidate == pattern
                    }
                }
                MatchMode::Substr => {
                    if case_insensitive {
                        candidate.to_lowercase().contains(&pattern.to_lowercase())
                    } else {
                        candidate.contains(pattern)
                    }
                }
                MatchMode::Regex => match build_regex(pattern, case_insensitive) {
                    Ok(re) => re.is_match(candidate),
                    Err(_) => false,
                },
            }
        };
        for &nt in &node_types {
            if let Some(nodes) = cache.get(nt) {
                for node_ev in nodes {
                    // Try the primary value first (full node text), then
                    // the alternate value if one is set. For call-kind
                    // nodes `alt_value` holds the extracted function
                    // name, so `exact: foo` matches `foo(args)` via the
                    // alt path while `substr:`/`regex:` still resolve
                    // against the full call-expression text via `value`.
                    // Each node counts at most once.
                    let matched = test_match(&node_ev.value)
                        || node_ev.alt_value.as_deref().is_some_and(&test_match);

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

    // Use cached AST or parse. Prefer the per-file cached UTF-8 view populated in
    // `EvaluationContext::new` — it avoids re-running from_utf8 on the full file
    // once per rule, which dominated CPU on large source archives.
    let source = match ctx.cached_source_utf8 {
        Some(s) => s,
        None => match std::str::from_utf8(ctx.binary_data) {
            Ok(s) => s,
            Err(_) => return ConditionResult::no_match(),
        },
    };

    let Some(cached_tree) = ctx.cached_ast else {
        return ConditionResult::no_match();
    };
    eval_ast_pattern_multi(
        cached_tree,
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
                // For call-kind nodes, also try the extracted function
                // name as a fallback so `exact: foo` matches `foo(args)`.
                // Mirrors the cache path; see `Evidence.alt_value` docs.
                let alt = crate::analyzers::symbol_extraction::extract_function_name(&node, source);
                let matched = matcher(text) || alt.as_deref().is_some_and(&matcher);
                if matched {
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
                            alt_value: alt,
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
    // Only works for source code files — prefer the cached UTF-8 view when available.
    let source = match ctx.cached_source_utf8 {
        Some(s) => s,
        None => match std::str::from_utf8(ctx.binary_data) {
            Ok(s) => s,
            Err(_) => return ConditionResult::no_match(),
        },
    };

    // Trust filefacts's cached parse — cleave no longer carries its own
    // tree-sitter grammars or fallback parser. If filefacts has no tree
    // for this file (unsupported language, oversized source), the AST
    // query has nothing to match against.
    let Some(tree) = ctx.cached_ast else {
        return ConditionResult::no_match();
    };
    let lang = &*tree.language();

    // Track parse errors but continue — tree-sitter recovers from minor errors
    let has_parse_errors = tree.root_node().has_error();

    // Compile the query (cached process-wide to avoid recompilation across
    // files and threads). Uses Arc so the Query stays alive even if evicted
    // from the LRU cache mid-use. Reads use `peek` to skip LRU promotion —
    // with a 256-entry cache and a bounded trait set the LRU eviction order
    // doesn't meaningfully help correctness, and avoiding the `get`-induced
    // promotion keeps reads on the read-lock fast path.
    let key = (ctx.file_type, query_str.to_string());
    let cached = QUERY_CACHE.read().peek(&key).map(Arc::clone);
    let query = if let Some(q) = cached {
        q
    } else {
        match tree_sitter::Query::new(lang, query_str) {
            Ok(q) => {
                let arc = Arc::new(q);
                QUERY_CACHE.write().put(key, Arc::clone(&arc));
                arc
            }
            Err(_) => return ConditionResult::no_match(),
        }
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
