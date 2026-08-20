//! AST-based condition evaluators for source code analysis.
//!
//! This module handles evaluation of Abstract Syntax Tree conditions:
//! - Pattern matching within specific AST node types
//! - Tree-sitter query execution
//! - Safe AST traversal with depth limits

use super::{build_regex, truncate_evidence};
use crate::analyzers::ast_walker::{AST_QUERY_CPU_BUDGET, thread_cpu_time};
use crate::composite_rules::ast_kinds::map_kind_to_node_types;
use crate::composite_rules::context::{AnalysisWarning, ConditionResult, EvaluationContext};
use crate::composite_rules::types::FileType;
use crate::types::{Evidence, MAX_EVIDENCE_PER_TRAIT};
use parking_lot::RwLock;
use rustc_hash::FxHashMap;
use std::ops::ControlFlow;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, LazyLock};
use std::time::Instant;
use streaming_iterator::StreamingIterator;

/// Maximum number of compiled tree-sitter queries to cache.
/// Process-wide compiled-query cache, keyed by (FileType, query_string).
///
/// Was previously per-thread — but `tree_sitter::Query` is `Send + Sync` via
/// `Arc`, and CPU profiles showed `ts_query_new` consuming thousands of
/// samples because each rayon worker recompiled the same queries
/// independently. Sharing across threads eliminates that redundancy. Reads are
/// frequent and run in parallel on the `RwLock` read path; compilation (a
/// cache miss) is one-time per key.
///
/// CORRECTNESS-CRITICAL — guards against nondeterministic finding loss during
/// parallel archive analysis (`tests/archive_determinism_test.rs`).
///
/// **Must stay unbounded.** The keyspace is bounded by the trait set (~thousands
/// of entries, ~10-50 KB each), so the cache never needs to evict. A bounded LRU
/// here (formerly 256) thrashed under multi-language archives, and the resulting
/// eviction-driven concurrent recompilation churn intermittently produced a
/// query that matched nothing — the nondeterminism bug. With no eviction each
/// query compiles ~once and is never recompiled, which is what fixes it.
///
/// Design: **unbounded** (eviction was the original drift trigger — a bounded LRU
/// thrashed under multi-language archives and recompiled queries concurrently) +
/// **serialized compile** (`eval_ast_query` compiles under the write lock,
/// double-checked, so no two `Query::new` overlap). Per-key concurrent
/// compilation was tried and measured *wall-neutral* (the one-time compile
/// warmup is small and amortized), so it's not worth the extra concurrency on
/// this correctness-sensitive path.
static QUERY_CACHE: LazyLock<RwLock<FxHashMap<(String, String), Arc<tree_sitter::Query>>>> =
    LazyLock::new(|| RwLock::new(FxHashMap::default()));

/// Combined `query:` set for one (language, sorted query list). `pattern_to_query[i]`
/// is the index into that list for combined-query pattern `i`.
struct CombinedAstQuery {
    query: Arc<tree_sitter::Query>,
    pattern_to_query: Vec<usize>,
}

static COMBINED_QUERY_CACHE: LazyLock<RwLock<FxHashMap<(String, String), Arc<CombinedAstQuery>>>> =
    LazyLock::new(|| RwLock::new(FxHashMap::default()));

/// Must stay within tree-sitter's accepted `set_match_limit` range
/// (`1..=65_536`). Keep the cap below the binding maximum so pathological
/// queries truncate predictably instead of relying on binding/runtime behavior.
const AST_QUERY_MATCH_LIMIT: u32 = 50_000;
const AST_QUERY_BYTE_LIMIT: usize = 10 * 1024 * 1024;
pub(crate) const AST_QUERY_CAPTURE_LIMIT: usize = 100_000;

/// Clear the shared AST query cache.
#[allow(dead_code)] // Called via clear_thread_local_caches
pub(crate) fn clear_ast_query_cache() {
    QUERY_CACHE.write().clear();
    COMBINED_QUERY_CACHE.write().clear();
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
        // The regex LRU probe (lock + key alloc + clone) and the pattern
        // lowercasing are hoisted out of the per-node calls.
        let compiled = matches!(match_mode, MatchMode::Regex)
            .then(|| build_regex(pattern, case_insensitive).ok())
            .flatten();
        let pattern_lower = (matches!(match_mode, MatchMode::Substr) && case_insensitive)
            .then(|| pattern.to_lowercase());
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
                    if let Some(pl) = &pattern_lower {
                        candidate.to_lowercase().contains(pl)
                    } else {
                        candidate.contains(pattern)
                    }
                }
                MatchMode::Regex => compiled.as_ref().is_some_and(|re| re.is_match(candidate)),
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
        if target_node_types.contains(&node_kind)
            && let Ok(text) = node.utf8_text(source)
        {
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
        true // continue traversal into children
    })
}

/// Evaluate full tree-sitter query condition
#[must_use]
pub(crate) fn eval_ast_query<'a>(query_str: &str, ctx: &EvaluationContext<'a>) -> ConditionResult {
    if let Some(cache) = ctx.ast_query_cache
        && let Some(cached) = cache.get(query_str)
    {
        return cached.clone();
    }

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

    let Some(query) = cached_ast_query(lang, ctx.file_type, query_str) else {
        return ConditionResult::no_match();
    };

    // Execute the query with safety limits
    let mut query_cursor = tree_sitter::QueryCursor::new();

    // Set limits to prevent runaway queries on pathological inputs.
    query_cursor.set_match_limit(AST_QUERY_MATCH_LIMIT);
    query_cursor.set_byte_range(0..source.len().min(AST_QUERY_BYTE_LIMIT));

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

    // Bound the query by CPU time (not wall-clock) via the progress callback.
    // Without a bound, pathological inputs can burn minutes of CPU; with a
    // wall-clock bound, a thread descheduled under oversubscription gets cut off
    // spuriously and silently drops detections. CPU time avoids both.
    let mut match_count: usize = 0;
    let cpu_budget = ctx.deadline.map(|_| AST_QUERY_CPU_BUDGET);
    let cpu_start = thread_cpu_time();
    let deadline = ctx.deadline;
    let mut timed_out = false;
    let mut capture_limited = false;
    // Break out of a runaway query on any of three signals: the per-rule CPU
    // budget, the wall-clock deadline, or cooperative cancellation (SIGTERM).
    // The progress callback fires mid-query, so a single pathological pattern
    // can no longer pin a rayon thread for minutes — which is what let one stuck
    // member hang an entire worker and block graceful shutdown.
    let mut progress_cb = |_state: &tree_sitter::QueryCursorState| -> ControlFlow<()> {
        if ctx.is_cancelled() {
            return ControlFlow::Break(());
        }
        if let Some(dl) = deadline
            && Instant::now() > dl
        {
            return ControlFlow::Break(());
        }
        if let Some(budget) = cpu_budget
            && thread_cpu_time().saturating_sub(cpu_start) > budget
        {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    };
    let options = tree_sitter::QueryCursorOptions::default().progress_callback(&mut progress_cb);
    let mut matches =
        query_cursor.matches_with_options(&query, tree.root_node(), source.as_bytes(), options);
    let mut buffer1: Vec<u8> = Vec::new();
    let mut buffer2: Vec<u8> = Vec::new();
    'matches: while let Some(m) = matches.next() {
        // Mirror the progress-callback guards between matches: cancellation and
        // the wall-clock deadline stop work promptly; the CPU budget marks a
        // genuine analysis-bomb timeout.
        if ctx.is_cancelled() || deadline.is_some_and(|dl| Instant::now() > dl) {
            break;
        }
        if let Some(budget) = cpu_budget
            && thread_cpu_time().saturating_sub(cpu_start) > budget
        {
            timed_out = true;
            break;
        }
        // Check text predicates (e.g., #eq?, #match?) using tree-sitter's built-in method
        // This is REQUIRED - tree-sitter does NOT automatically filter by text predicates
        let mut text_provider = SourceTextProvider(source.as_bytes());
        if !m.satisfies_text_predicates(&query, &mut buffer1, &mut buffer2, &mut text_provider) {
            continue; // Skip matches that don't satisfy predicates
        }

        for capture in m.captures {
            if match_count >= AST_QUERY_CAPTURE_LIMIT {
                capture_limited = true;
                break 'matches;
            }
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
    if query_cursor.did_exceed_match_limit() || capture_limited {
        warnings.push(AnalysisWarning::AstQueryLimited {
            limit: if capture_limited {
                AST_QUERY_CAPTURE_LIMIT
            } else {
                AST_QUERY_MATCH_LIMIT as usize
            },
        });
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

fn cached_ast_query(
    lang: &tree_sitter::Language,
    file_type: FileType,
    query_str: &str,
) -> Option<Arc<tree_sitter::Query>> {
    // Compile the query, cached process-wide to avoid recompilation across files
    // and threads. The frequent case is a hit on the read-lock fast path. On a
    // miss we take the write lock and compile *while holding it*, double-checking
    // first: each (language, query) compiles exactly once with no overlapping
    // `Query::new`. CORRECTNESS-CRITICAL (see the QUERY_CACHE doc): compiling
    // outside the lock reintroduces finding drift; do not "optimize" it away.
    let key = (
        ast_query_language_key(lang, file_type),
        query_str.to_string(),
    );
    let cached = QUERY_CACHE.read().get(&key).map(Arc::clone);
    if let Some(q) = cached {
        return Some(q);
    }
    let mut cache = QUERY_CACHE.write();
    if let Some(q) = cache.get(&key).map(Arc::clone) {
        drop(cache);
        return Some(q);
    }
    let compiled = match tree_sitter::Query::new(lang, query_str) {
        Ok(q) => {
            let arc = Arc::new(q);
            cache.insert(key, Arc::clone(&arc));
            Some(arc)
        }
        Err(_) => None,
    };
    drop(cache);
    compiled
}

/// Tree-sitter's `set_match_limit` accepts at most this many matches per cursor.
/// Combined `query:` batches share one cursor, so a bomb can starve later
/// patterns — on exceed we drop the batch and fall back to per-query eval.
const COMBINED_AST_QUERY_MATCH_LIMIT: u32 = 65_536;

/// Run every applicable `query:` in one `QueryCursor` walk. `None` means
/// "do not use a batch" — caller keeps the per-trait `eval_ast_query` path
/// (fewer than two compiling queries, combined compile failed, match-limit
/// overflow, timeout, or cancel). Results are keyed by the original query
/// string so `unless:` / duplicate `if:` share one bucket.
pub(crate) fn batch_ast_queries(
    tree: &tree_sitter::Tree,
    source: &str,
    file_type: FileType,
    query_strs: &[&str],
    deadline: Option<Instant>,
    cancellation: Option<&AtomicBool>,
) -> Option<FxHashMap<String, ConditionResult>> {
    if query_strs.len() < 2 || source.len() > AST_QUERY_BYTE_LIMIT {
        return None;
    }
    let lang = &*tree.language();
    let mut compiling: Vec<(&str, Arc<tree_sitter::Query>)> = Vec::new();
    for &q in query_strs {
        if let Some(compiled) = cached_ast_query(lang, file_type, q) {
            compiling.push((q, compiled));
        }
    }
    if compiling.len() < 2 {
        return None;
    }

    let combined_source: String = compiling
        .iter()
        .map(|(q, _)| *q)
        .collect::<Vec<_>>()
        .join("\n");
    let lang_key = ast_query_language_key(lang, file_type);
    let cache_key = (lang_key, combined_source.clone());
    let cached = COMBINED_QUERY_CACHE.read().get(&cache_key).map(Arc::clone);
    let combined = if let Some(c) = cached {
        c
    } else {
        let mut cache = COMBINED_QUERY_CACHE.write();
        if let Some(c) = cache.get(&cache_key).map(Arc::clone) {
            c
        } else {
            let Ok(query) = tree_sitter::Query::new(lang, &combined_source) else {
                return None;
            };
            let mut pattern_to_query = Vec::new();
            let mut expected = 0usize;
            for (i, (_, q)) in compiling.iter().enumerate() {
                let n = q.pattern_count();
                expected = expected.saturating_add(n);
                pattern_to_query.extend(std::iter::repeat_n(i, n));
            }
            if query.pattern_count() != expected {
                return None;
            }
            let arc = Arc::new(CombinedAstQuery {
                query: Arc::new(query),
                pattern_to_query,
            });
            cache.insert(cache_key, Arc::clone(&arc));
            arc
        }
    };

    struct SourceTextProvider<'a>(&'a [u8]);
    impl<'a> tree_sitter::TextProvider<&'a [u8]> for SourceTextProvider<'a> {
        type I = std::iter::Once<&'a [u8]>;
        fn text<'b>(&mut self, node: tree_sitter::Node<'b>) -> Self::I {
            let start = node.byte_range().start;
            let end = node.byte_range().end.min(self.0.len());
            std::iter::once(&self.0[start..end])
        }
    }

    struct Bucket {
        evidence: Vec<Evidence>,
        match_count: usize,
        query_matches: usize,
        capture_limited: bool,
        match_limited: bool,
    }
    let n = compiling.len();
    let mut buckets: Vec<Bucket> = (0..n)
        .map(|_| Bucket {
            evidence: Vec::new(),
            match_count: 0,
            query_matches: 0,
            capture_limited: false,
            match_limited: false,
        })
        .collect();

    let mut query_cursor = tree_sitter::QueryCursor::new();
    query_cursor.set_match_limit(COMBINED_AST_QUERY_MATCH_LIMIT);
    query_cursor.set_byte_range(0..source.len().min(AST_QUERY_BYTE_LIMIT));

    let cancelled = || cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed));
    let cpu_budget = deadline.map(|_| AST_QUERY_CPU_BUDGET);
    let cpu_start = thread_cpu_time();
    let mut timed_out = false;
    let mut progress_cb = |_state: &tree_sitter::QueryCursorState| -> ControlFlow<()> {
        if cancelled() {
            return ControlFlow::Break(());
        }
        if let Some(dl) = deadline
            && Instant::now() > dl
        {
            return ControlFlow::Break(());
        }
        if let Some(budget) = cpu_budget
            && thread_cpu_time().saturating_sub(cpu_start) > budget
        {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    };
    let options = tree_sitter::QueryCursorOptions::default().progress_callback(&mut progress_cb);
    let mut matches = query_cursor.matches_with_options(
        &combined.query,
        tree.root_node(),
        source.as_bytes(),
        options,
    );
    let mut buffer1: Vec<u8> = Vec::new();
    let mut buffer2: Vec<u8> = Vec::new();
    while let Some(m) = matches.next() {
        if cancelled() || deadline.is_some_and(|dl| Instant::now() > dl) {
            return None;
        }
        if let Some(budget) = cpu_budget
            && thread_cpu_time().saturating_sub(cpu_start) > budget
        {
            timed_out = true;
            break;
        }
        let Some(&qi) = combined.pattern_to_query.get(m.pattern_index) else {
            continue;
        };
        let bucket = &mut buckets[qi];
        if bucket.capture_limited || bucket.match_limited {
            continue;
        }
        if bucket.query_matches >= AST_QUERY_MATCH_LIMIT as usize {
            bucket.match_limited = true;
            continue;
        }
        let mut text_provider = SourceTextProvider(source.as_bytes());
        if !m.satisfies_text_predicates(
            &combined.query,
            &mut buffer1,
            &mut buffer2,
            &mut text_provider,
        ) {
            continue;
        }
        bucket.query_matches += 1;
        for capture in m.captures {
            if bucket.match_count >= AST_QUERY_CAPTURE_LIMIT {
                bucket.capture_limited = true;
                break;
            }
            if let Ok(text) = capture.node.utf8_text(source.as_bytes()) {
                bucket.match_count += 1;
                if bucket.evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    bucket.evidence.push(Evidence {
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
    if timed_out || cancelled() || query_cursor.did_exceed_match_limit() {
        return None;
    }

    let has_parse_errors = tree.root_node().has_error();
    let mut out = FxHashMap::default();
    for (i, (qstr, _)) in compiling.iter().enumerate() {
        let bucket = &mut buckets[i];
        let mut warnings = Vec::new();
        if has_parse_errors {
            warnings.push(AnalysisWarning::AstParseError);
        }
        if bucket.capture_limited || bucket.match_limited {
            warnings.push(AnalysisWarning::AstQueryLimited {
                limit: if bucket.capture_limited {
                    AST_QUERY_CAPTURE_LIMIT
                } else {
                    AST_QUERY_MATCH_LIMIT as usize
                },
            });
        }
        out.insert(
            (*qstr).to_string(),
            ConditionResult {
                matched: bucket.match_count > 0,
                evidence: std::mem::take(&mut bucket.evidence),
                match_count: bucket.match_count,
                warnings,
                precision: 2.0,
                matched_trait_ids: Vec::new(),
            },
        );
    }
    Some(out)
}

fn ast_query_language_key(lang: &tree_sitter::Language, file_type: FileType) -> String {
    format!(
        "{}:{}:{}:{}:{file_type:?}",
        lang.name().unwrap_or("<unnamed>"),
        lang.abi_version(),
        lang.node_kind_count(),
        lang.field_count()
    )
}
