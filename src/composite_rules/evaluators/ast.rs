//! AST-based condition evaluators for source code analysis.
//!
//! This module handles evaluation of Abstract Syntax Tree conditions:
//! - Pattern matching within specific AST node types
//! - Tree-sitter query execution
//! - Safe AST traversal with depth limits

use super::ast_gate::{
    DeferredPredicates, NodeTextIndex, RequiredLiterals, RequiredNodes, RequiredSubqueries,
};
use super::{build_regex, truncate_evidence};
use crate::analyzers::ast_walker::{AST_QUERY_CPU_BUDGET, thread_cpu_time};
use crate::composite_rules::ast_kinds::map_kind_to_node_types;
use crate::composite_rules::context::{AnalysisWarning, ConditionResult, EvaluationContext};
use crate::composite_rules::types::FileType;
use crate::types::{Evidence, MAX_EVIDENCE_PER_TRAIT};
use parking_lot::{Mutex, RwLock};
use rustc_hash::FxHashMap;
use std::cell::Cell;
use std::ops::ControlFlow;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Instant;
use streaming_iterator::StreamingIterator;

/// Whole-command predicates belong after structural matching. Running a
/// pipeline/command regex as soon as its root is visited pays regex costs on
/// candidates whose command names/arguments later reject the pattern. Scalar
/// captures retain early pruning; QueryMatches checks every text predicate on
/// each completed match in both the independent and combined cursor paths.
fn capture_satisfies_early_predicates(
    query: &tree_sitter::Query,
    deferred: &DeferredPredicates,
    pattern: usize,
    capture: u32,
    node: tree_sitter::Node<'_>,
    previous: &[tree_sitter::QueryCapture<'_>],
    source: &[u8],
) -> bool {
    deferred.contains(pattern, capture)
        || query.capture_satisfies_match_predicates(pattern, capture, node, previous, source)
}

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
/// **once-per-key compile** (a sharded compiler mutex and double-checked
/// cache ensure no two `Query::new` calls for the same key overlap). Cache
/// hits remain readable while another query compiles. Compiles of different
/// keys proceed in parallel: under one global compiler lock, `cleave
/// validate`'s sixteen lanes met the cold cache together and fifteen waited
/// while one compiled, a tenth of the run's samples.
/// `None` records a query that failed to compile for this language: traits are
/// written against several grammars, so a JS file sees a handful of foreign
/// `query:` strings whose compile always errors. Without the negative entry
/// those recompiled (serially, under the write lock) on every archive member —
/// ~150 s CPU and a lock convoy on a 54k-member zip. Compilation is
/// deterministic, so a cached failure is exactly as correct as retrying it.
static QUERY_CACHE: LazyLock<RwLock<FxHashMap<(String, String), Option<Arc<CompiledAstQuery>>>>> =
    LazyLock::new(|| RwLock::new(FxHashMap::default()));

// Separate compiler ownership from cache publication so hits never wait for
// an unrelated compilation. Individual queries compile under a shard chosen
// by key, so one key compiles once while unrelated keys compile alongside;
// the combined bank keeps its single compiler domain.
const QUERY_COMPILER_SHARDS: usize = 64;
static QUERY_COMPILERS: [Mutex<()>; QUERY_COMPILER_SHARDS] =
    [const { Mutex::new(()) }; QUERY_COMPILER_SHARDS];

/// The compiler lock for `key`.
fn query_compiler(key: &(String, String)) -> &'static Mutex<()> {
    use std::hash::{Hash, Hasher};
    let mut hasher = rustc_hash::FxHasher::default();
    key.hash(&mut hasher);
    &QUERY_COMPILERS[(hasher.finish() as usize) % QUERY_COMPILER_SHARDS]
}
static COMBINED_QUERY_COMPILER: Mutex<()> = Mutex::new(());

/// A compiled `query:` and the literals its matches require of the source.
struct CompiledAstQuery {
    query: tree_sitter::Query,
    literals: RequiredLiterals,
    nodes: RequiredNodes,
    subqueries: RequiredSubqueries,
    deferred: DeferredPredicates,
    ignore_comments: bool,
    /// Node kinds the patterns are rooted at, when every pattern is one
    /// node (see [`super::ast_gate::pattern_root_kinds`]): the query can then
    /// run per node of those kinds. Sorted for binary search.
    root_kinds: Option<Box<[u16]>>,
}

impl CompiledAstQuery {
    fn prune_subqueries(
        &self,
        tree: &tree_sitter::Tree,
        source: &str,
        index: Option<&NodeTextIndex>,
        enabled: &mut [bool],
        deadline: Option<Instant>,
        cancellation: Option<&AtomicBool>,
    ) {
        if source.len() >= 64 * 1024
            && let Some(index) = index
        {
            self.subqueries
                .prune_indexed(tree, source, index, enabled, deadline, cancellation);
        }
    }

    /// Whether `source` holds every literal some pattern requires. `false`
    /// proves the query cannot match, so the walk can be skipped.
    fn may_match(&self, source: &[u8]) -> bool {
        self.literals
            .may_match(|literal, ci| super::ast_gate::source_contains(source, literal, ci))
    }
}

/// Combined `query:` set for one (language, sorted query list). `pattern_to_query[i]`
/// is the index into that list for combined-query pattern `i`.
struct CombinedAstQuery {
    query: Arc<tree_sitter::Query>,
    deferred: DeferredPredicates,
    pattern_to_query: Vec<usize>,
}

/// `None` records a combined source that failed to compile (or whose pattern
/// count didn't line up): same negative-caching rationale as [`QUERY_CACHE`].
static COMBINED_QUERY_CACHE: LazyLock<
    RwLock<FxHashMap<(String, String), Option<Arc<CombinedAstQuery>>>>,
> = LazyLock::new(|| RwLock::new(FxHashMap::default()));

/// Must stay within tree-sitter's accepted `set_match_limit` range
/// (`1..=65_536`). Keep the cap below the binding maximum so pathological
/// queries truncate predictably instead of relying on binding/runtime behavior.
const AST_QUERY_MATCH_LIMIT: u32 = 50_000;
/// Cap on in-progress states one pattern may hold at one start depth (tree-sitter
/// abandons the rest and flags the result as limited). A pattern with several
/// unanchored wildcard siblings (`argument: (_) @a argument: (_) @b`) explores
/// every alignment against a node with thousands of children, and tree-sitter's
/// per-step state dedup is quadratic in that count: a Tcl file parsed as bash
/// held 50k states for one pattern and burned 30+ CPU-seconds per query with no
/// interruptible step. 16384 gives wide but ordinary objects more headroom
/// while keeping pathological wildcard expansion tightly bounded. A 8192-state
/// cap still truncated ordinary samples with several independent sibling
/// wildcards, so this doubles that headroom while preserving a firm ceiling.
pub(super) const AST_QUERY_GROUP_STATE_LIMIT: u32 = 16384;
const AST_QUERY_BYTE_LIMIT: usize = 10 * 1024 * 1024;
pub(crate) const AST_QUERY_CAPTURE_LIMIT: usize = 100_000;
const AST_QUERY_MULTI_WILDCARD_CPU_BUDGET: std::time::Duration =
    std::time::Duration::from_millis(100);

/// Every AST query has a CPU ceiling, including direct scans without an outer
/// scan deadline. The deadline remains a separate wall-clock/cancellation
/// mechanism; its absence must not disable the per-query safety bound.
pub(super) fn ast_query_cpu_budget(query: &str, _deadline: Option<Instant>) -> std::time::Duration {
    // Two unbounded wildcard siblings can enumerate combinatorial alignments
    // inside a wide object. Keep the normal budget for ordinary queries, but
    // cap this expensive shape before it stalls archive workers for 30s.
    if count_unbounded_any_wildcards(query) >= 2 {
        AST_QUERY_MULTI_WILDCARD_CPU_BUDGET
    } else {
        AST_QUERY_CPU_BUDGET
    }
}

/// `true` when a shared batch leaves `query` to the per-trait path for a
/// reason other than cost: a comment-stripped view needs its own tree, and
/// a multi-wildcard shape runs alone under its 100 ms budget. Both are
/// ordinary standalone work, not the abandoned-query tail that
/// `evaluate_traits` spreads across workers.
pub(crate) fn batch_leaves_out_by_design(query: &str) -> bool {
    count_unbounded_any_wildcards(query) >= 2 || query.contains("cleave.ignore-comments")
}

fn count_unbounded_any_wildcards(query: &str) -> usize {
    let bytes = query.as_bytes();
    let mut count = 0;
    for i in 0..bytes.len() {
        if bytes[i] != b'(' {
            continue;
        }
        let mut j = i + 1;
        while bytes.get(j).is_some_and(u8::is_ascii_whitespace) {
            j += 1;
        }
        if bytes.get(j) != Some(&b'_') {
            continue;
        }
        j += 1;
        while bytes.get(j).is_some_and(u8::is_ascii_whitespace) {
            j += 1;
        }
        if bytes.get(j) != Some(&b')') {
            continue;
        }
        j += 1;
        while bytes.get(j).is_some_and(u8::is_ascii_whitespace) {
            j += 1;
        }
        if bytes.get(j) == Some(&b'*') {
            count += 1;
        }
    }
    count
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

    // A literal the pattern requires that the file lacks: no node can match.
    if let Some(source) = ctx.ast_source()
        && !simple_pattern_may_match(source.as_bytes(), pattern, match_mode, case_insensitive)
    {
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
                        || node_ev.alt_value.as_deref().is_some_and(test_match);

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
    let Some(source) = ctx.ast_source() else {
        return ConditionResult::no_match();
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

/// Whether a simple-mode pattern could match some node of `source`.
///
/// Every string a node is tested against comes from the source: its text,
/// possibly truncated with a `...` suffix, or, for a call, a callee name
/// assembled from source identifiers joined by `.`. So each `.`-free piece of
/// a literal the pattern requires occurs in the source verbatim. Pieces under
/// 3 bytes are not looked for. `false` proves no match; anything this cannot
/// reason about answers `true`.
fn simple_pattern_may_match(
    source: &[u8],
    pattern: &str,
    match_mode: MatchMode,
    case_insensitive: bool,
) -> bool {
    let requirement: Option<Vec<(Box<[u8]>, bool)>> = match match_mode {
        // The condition's flag compiles the regex case-insensitively; the
        // atoms of the `(?i)` form follow the regex crate's own case folding.
        MatchMode::Regex => super::ast_gate::regex_requirement(&if case_insensitive {
            format!("(?i){pattern}")
        } else {
            pattern.to_owned()
        }),
        // Exact matching folds ASCII case only.
        MatchMode::Exact => Some(vec![(pattern.as_bytes().into(), case_insensitive)]),
        // Case-insensitive substrings compare Unicode lowercase forms, under
        // which non-ASCII text can lowercase to ASCII (`K` Kelvin to `k`).
        MatchMode::Substr if case_insensitive => None,
        MatchMode::Substr => Some(vec![(pattern.as_bytes().into(), false)]),
    };
    let Some(any_of) = requirement else {
        return true;
    };
    any_of.iter().any(|(literal, ci)| {
        literal
            .split(|&b| b == b'.')
            .filter(|piece| piece.len() >= 3)
            .all(|piece| super::ast_gate::source_contains(source, piece, *ci))
    })
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
            let matched = matcher(text) || alt.as_deref().is_some_and(matcher);
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
    eval_ast_query_with_budget(
        query_str,
        ctx,
        ast_query_cpu_budget(query_str, ctx.deadline),
    )
}

pub(super) fn eval_ast_query_with_budget<'a>(
    query_str: &str,
    ctx: &EvaluationContext<'a>,
    cpu_budget: std::time::Duration,
) -> ConditionResult {
    eval_ast_query_once(query_str, ctx, cpu_budget, per_root_enabled())
}

/// `eval_ast_query` with the per-root walk forced on or off, for tests that
/// compare the two walks.
#[cfg(test)]
pub(super) fn eval_ast_query_with_mode<'a>(
    query_str: &str,
    ctx: &EvaluationContext<'a>,
    per_root: bool,
) -> ConditionResult {
    eval_ast_query_once(
        query_str,
        ctx,
        ast_query_cpu_budget(query_str, ctx.deadline),
        per_root,
    )
}

/// Whether a rooted query walks per root node (`CLEAVE_AST_PER_ROOT`, on by
/// default) rather than once over the whole tree.
fn per_root_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| crate::env::bool_var("CLEAVE_AST_PER_ROOT").unwrap_or(true))
}

/// Run `query_str` on `ctx` again for its cost alone: validation confirms a
/// fixture's cost outliers this way once the fixture is evaluated (see
/// [`crate::validation_performance::confirm_outliers`]). `None` when the
/// run was cut short, so a bounded run never certifies a cost.
pub(crate) fn remeasure_ast_query(
    query_str: &str,
    ctx: &EvaluationContext<'_>,
) -> Option<std::time::Duration> {
    let probe = crate::validation_performance::AstProbe::begin();
    let result = eval_ast_query_once(
        query_str,
        ctx,
        ast_query_cpu_budget(query_str, ctx.deadline),
        per_root_enabled(),
    );
    let cost = probe.cost();
    drop(probe);
    let bounded = result.warnings.iter().any(|warning| {
        matches!(
            warning,
            AnalysisWarning::AstTooDeep { max_depth: 0 } | AnalysisWarning::AstQueryLimited { .. }
        )
    });
    if bounded || ctx.is_cancelled() {
        return None;
    }
    cost
}

fn eval_ast_query_once<'a>(
    query_str: &str,
    ctx: &EvaluationContext<'a>,
    cpu_budget: std::time::Duration,
    per_root: bool,
) -> ConditionResult {
    if let Some(cache) = ctx.ast_query_cache
        && let Some(cached) = cache.get(query_str)
    {
        return cached.clone();
    }

    // Only works for source code files — prefer the cached UTF-8 view when available.
    let Some(source) = ctx.ast_source() else {
        return ConditionResult::no_match();
    };

    // Trust filefacts's cached parse — cleave no longer carries its own
    // tree-sitter grammars or fallback parser. If filefacts has no tree
    // for this file (unsupported language, oversized source), the AST
    // query has nothing to match against.
    let Some(tree) = ctx.cached_ast else {
        return ConditionResult::no_match();
    };
    let lang = &*tree.language();

    let Some(compiled) = cached_ast_query(lang, ctx.file_type, query_str) else {
        return ConditionResult::no_match();
    };
    // Required literal predicates read the original source in both views.
    // Reject impossible queries before walking or reparsing for comment removal.
    if !compiled.may_match(source.as_bytes()) {
        return ConditionResult::no_match();
    }
    let normalization_start = thread_cpu_time();
    if compiled.ignore_comments && ctx.cached_commentless_ast.get().is_none() {
        let _timer = crate::validation_performance::ast_execution_started();
        let view = super::ast_comment_view::build(
            tree,
            source,
            AST_QUERY_BYTE_LIMIT,
            cpu_budget,
            ctx.deadline,
            ctx.cancellation,
        );
        match view {
            Ok(view) => {
                let _ = ctx.cached_commentless_ast.set(view);
            }
            Err(reason) => {
                let warnings = match reason {
                    super::ast_comment_view::ViewError::Limited => {
                        vec![AnalysisWarning::AstTooDeep { max_depth: 0 }]
                    }
                    super::ast_comment_view::ViewError::ParseChanged => {
                        vec![AnalysisWarning::AstParseError]
                    }
                    super::ast_comment_view::ViewError::Cancelled => vec![],
                };
                return ConditionResult {
                    matched: false,
                    evidence: vec![],
                    warnings,
                    match_count: 0,
                    ..ConditionResult::no_match()
                };
            }
        }
    }
    let cpu_budget = if compiled.ignore_comments {
        cpu_budget.saturating_sub(thread_cpu_time().saturating_sub(normalization_start))
    } else {
        cpu_budget
    };
    let alternate = compiled
        .ignore_comments
        .then(|| ctx.cached_commentless_ast.get())
        .flatten()
        .and_then(Option::as_ref);
    let tree = alternate.unwrap_or(tree);
    // Original-tree structure indexes cannot certify an alternate-tree negative.
    let node_text = if alternate.is_some() {
        None
    } else {
        ctx.ast_node_text
    };
    let has_parse_errors = tree.root_node().has_error();
    if node_text.is_some_and(|index| !compiled.nodes.may_match(index)) {
        return ConditionResult::no_match();
    }
    // Include necessary-child pruning in measured execution cost. Validation
    // uses the same semantics-preserving gate as ordinary scans, while still
    // executing queries independently rather than reusing a shared batch.
    // Normal batches usually narrow a private query copy. Independent measured
    // validation must also isolate regex cache pools: shared Regex instances
    // contend on tiny inputs and charge that contention as AST execution.
    // deep_clone reuses compiled regex code while giving caches private pools;
    // copying stays outside cursor timing and inside the whole-rule deadline.
    let measured_query =
        crate::validation_performance::active().then(|| compiled.query.deep_clone());
    let _execution_timer = crate::validation_performance::ast_execution_started();
    if RequiredSubqueries::enabled() {
        let mut enabled = vec![true; compiled.query.pattern_count()];
        compiled.prune_subqueries(
            tree,
            source,
            node_text,
            &mut enabled,
            ctx.deadline,
            ctx.cancellation,
        );
        if !enabled.iter().any(|&active| active) {
            return ConditionResult::no_match();
        }
    }
    let query = measured_query.as_ref().unwrap_or(&compiled.query);
    // Predicate captures establish relationships; an explicit @evidence
    // capture chooses the source occurrence a proximity consumer may join.
    // Queries without it retain their existing all-captures behavior.
    let evidence_capture = query
        .capture_names()
        .iter()
        .position(|name| *name == "evidence")
        .and_then(|index| u32::try_from(index).ok());

    // Execute the query with safety limits
    let mut query_cursor = tree_sitter::QueryCursor::new();

    // Set limits to prevent runaway queries on pathological inputs.
    query_cursor.set_match_limit(AST_QUERY_MATCH_LIMIT);
    query_cursor.set_max_states_per_group(AST_QUERY_GROUP_STATE_LIMIT);
    let byte_limit = source.len().min(AST_QUERY_BYTE_LIMIT);
    query_cursor.set_byte_range(0..byte_limit);

    // Bound the query by CPU time (not wall-clock) via the progress callback.
    // Without a bound, pathological inputs can burn minutes of CPU; with a
    // wall-clock bound, a thread descheduled under oversubscription gets cut off
    // spuriously and silently drops detections. CPU time avoids both.
    let cpu_start = thread_cpu_time();
    let deadline = ctx.deadline;
    let timed_out = Cell::new(false);
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
        if thread_cpu_time().saturating_sub(cpu_start) >= cpu_budget {
            timed_out.set(true);
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    };
    let mut capture_predicate =
        |pattern,
         capture,
         node: tree_sitter::Node<'_>,
         previous: &[tree_sitter::QueryCapture<'_>]| {
            capture_satisfies_early_predicates(
                query,
                &compiled.deferred,
                pattern,
                capture,
                node,
                previous,
                source.as_bytes(),
            )
        };
    let mut sink = MatchSink {
        evidence_capture,
        source: source.as_bytes(),
        evidence: Vec::new(),
        match_count: 0,
        capture_count: 0,
        capture_limited: false,
    };
    // Mirror the progress-callback guards between matches: cancellation and
    // the wall-clock deadline stop work promptly; the CPU budget marks a
    // genuine analysis-bomb timeout.
    let stop = || -> bool {
        if ctx.is_cancelled() || deadline.is_some_and(|dl| Instant::now() > dl) {
            return true;
        }
        if thread_cpu_time().saturating_sub(cpu_start) >= cpu_budget {
            timed_out.set(true);
            return true;
        }
        false
    };
    let mut exceeded_match_limit = false;
    match compiled.root_kinds.as_deref().filter(|_| per_root) {
        // One cursor run per node the patterns can be rooted at, each
        // confined to starting there (`max_start_depth` 0), so the cursor
        // only descends as far as that node's own match needs. A whole-tree
        // walk keeps one in-progress state per open candidate root, and on
        // a deeply nested tree -- a 5 MB JSFuck expression nests calls and
        // subscripts thousands of levels -- a self-nesting pattern such as
        // `(call_expression function: (subscript_expression))` holds
        // thousands of states at once: the shared batch drops it at its
        // state cap, and the walk alone then spends its whole CPU budget on
        // a partial result (87 s to finish). Per root, each run holds one
        // state and the file costs the walk. The matches are the same set:
        // a rooted pattern matches at exactly the nodes of its root kind.
        // Only their order differs (an enclosing root now comes before the
        // roots inside it), which matters to nothing but which of more
        // than MAX_EVIDENCE_PER_TRAIT matches are kept as evidence.
        Some(root_kinds) => {
            query_cursor.set_max_start_depth(Some(0));
            let mut walk = tree.walk();
            let mut visited: usize = 0;
            'roots: loop {
                let node = walk.node();
                // Nodes starting past the byte limit cannot intersect it.
                if node.start_byte() < byte_limit {
                    if root_kinds.binary_search(&node.kind_id()).is_ok() {
                        let options = tree_sitter::QueryCursorOptions::default()
                            .progress_callback(&mut progress_cb)
                            .capture_match_predicate(&mut capture_predicate);
                        let mut matches = query_cursor.matches_with_options(
                            query,
                            node,
                            source.as_bytes(),
                            options,
                        );
                        while let Some(m) = matches.next() {
                            if stop() || sink.accept(m).is_break() {
                                break 'roots;
                            }
                        }
                        drop(matches);
                        exceeded_match_limit |= query_cursor.did_exceed_match_limit();
                        if timed_out.get() || ctx.is_cancelled() {
                            break 'roots;
                        }
                    }
                    visited += 1;
                    if visited.is_multiple_of(4096) && stop() {
                        break 'roots;
                    }
                    if walk.goto_first_child() {
                        continue;
                    }
                }
                loop {
                    if walk.goto_next_sibling() {
                        continue 'roots;
                    }
                    if !walk.goto_parent() {
                        break 'roots;
                    }
                }
            }
        }
        None => {
            let options = tree_sitter::QueryCursorOptions::default()
                .progress_callback(&mut progress_cb)
                .capture_match_predicate(&mut capture_predicate);
            let mut matches = query_cursor.matches_with_options(
                query,
                tree.root_node(),
                source.as_bytes(),
                options,
            );
            while let Some(m) = matches.next() {
                if stop() || sink.accept(m).is_break() {
                    break;
                }
            }
            drop(matches);
            exceeded_match_limit = query_cursor.did_exceed_match_limit();
        }
    }
    let MatchSink {
        evidence,
        match_count,
        capture_limited,
        ..
    } = sink;
    let mut warnings = Vec::new();
    if has_parse_errors {
        warnings.push(AnalysisWarning::AstParseError);
    }
    if timed_out.get() {
        warnings.push(AnalysisWarning::AstTooDeep { max_depth: 0 });
    }
    if exceeded_match_limit || capture_limited {
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

/// Collects one standalone query's matches into evidence and counts, the
/// same way whether the cursor ran once over the tree or once per root.
struct MatchSink<'s> {
    evidence_capture: Option<u32>,
    source: &'s [u8],
    evidence: Vec<Evidence>,
    match_count: usize,
    capture_count: usize,
    capture_limited: bool,
}

impl MatchSink<'_> {
    /// `Break` once no further match can change the result.
    fn accept(&mut self, m: &tree_sitter::QueryMatch<'_, '_>) -> ControlFlow<()> {
        // Standalone predicate patterns can yield empty-capture matches.
        // They are not an observed source occurrence and must not satisfy a trait.
        if m.captures().is_empty()
            || self.evidence_capture.is_some_and(|selected| {
                !m.captures().iter().any(|capture| capture.index == selected)
            })
        {
            return ControlFlow::Continue(());
        }
        // QueryMatches already checks the built-in text predicates.

        // Count complete query matches once; captures provide evidence and
        // have their own work bound. A four-capture query is one occurrence.
        if self.capture_count >= AST_QUERY_CAPTURE_LIMIT {
            self.capture_limited = true;
            return ControlFlow::Break(());
        }
        self.match_count += 1;
        for capture in m.captures() {
            if self.capture_count >= AST_QUERY_CAPTURE_LIMIT {
                self.capture_limited = true;
                return ControlFlow::Break(());
            }
            self.capture_count += 1;
            if self
                .evidence_capture
                .is_some_and(|selected| capture.index != selected)
            {
                continue;
            }
            if let Ok(text) = capture.node.utf8_text(self.source)
                && self.evidence.len() < MAX_EVIDENCE_PER_TRAIT
            {
                self.evidence.push(Evidence {
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
        // Queries without count or proximity consumers only need to prove one
        // match. Some sibling-wildcard patterns have combinatorial result sets;
        // continuing to enumerate every valid alignment can burn the whole
        // per-query CPU budget after the trait has already matched.
        if !super::symbol_string::match_count_needed() {
            return ControlFlow::Break(());
        }
        // Floor-only count filters already satisfied and the evidence list
        // full: later matches change neither verdict nor output.
        if self.match_count >= super::symbol_string::match_count_bound()
            && self.evidence.len() >= MAX_EVIDENCE_PER_TRAIT
        {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}

/// The node kinds `query` can be rooted at, as sorted grammar ids, when every
/// pattern is one named node (see `pattern_root_kinds`). Supertypes and
/// unknown kinds disqualify: no node carries a supertype's id.
fn per_root_kinds(
    lang: &tree_sitter::Language,
    query: &tree_sitter::Query,
    source: &str,
) -> Option<Box<[u16]>> {
    if (0..query.pattern_count()).any(|pattern| !query.is_pattern_rooted(pattern)) {
        return None;
    }
    let mut ids = super::ast_gate::pattern_root_kinds(source)?
        .into_iter()
        .map(|kind| {
            let id = lang.id_for_node_kind(kind, true);
            (id != 0 && !lang.node_kind_is_supertype(id)).then_some(id)
        })
        .collect::<Option<Vec<u16>>>()?;
    ids.sort_unstable();
    ids.dedup();
    Some(ids.into_boxed_slice())
}

fn cached_ast_query(
    lang: &tree_sitter::Language,
    file_type: FileType,
    query_str: &str,
) -> Option<Arc<CompiledAstQuery>> {
    // Serialize misses without blocking cache readers. Hold compiler ownership
    // through publication and recheck after acquiring it, so each key still
    // compiles exactly once. Cache clearing takes the same compiler locks.
    let key = (
        ast_query_language_key(lang, file_type),
        query_str.to_string(),
    );
    // Bind the lookup before the `if let` so the read guard is released here
    // rather than at the end of the `if let` — the write lock below is taken on
    // exactly the path that falls through it.
    let hit = QUERY_CACHE.read().get(&key).cloned();
    if let Some(entry) = hit {
        return entry;
    }
    let diagnostic = tracing::enabled!(tracing::Level::DEBUG);
    let wait_started = diagnostic.then(Instant::now);
    let _compiler = query_compiler(&key).lock();
    if let Some(started) = wait_started
        && started.elapsed().as_millis() >= 10
    {
        tracing::debug!(wait_ms = started.elapsed().as_millis(), file_type = ?file_type, grammar = %key.0,
            "waited for AST query compiler");
    }
    let hit = QUERY_CACHE.read().get(&key).cloned();
    if let Some(entry) = hit {
        return entry;
    }
    let compile_started = diagnostic.then(Instant::now);
    let compiled = tree_sitter::Query::new(lang, query_str).ok().map(|query| {
        let literals = RequiredLiterals::of(&query, query_str);
        let nodes = RequiredNodes::of(lang, &query, query_str);
        let subqueries = if RequiredSubqueries::enabled() {
            RequiredSubqueries::of(lang, &query, query_str)
        } else {
            RequiredSubqueries::default()
        };
        let deferred = DeferredPredicates::of(&query, query_str);
        let ignore_comments = super::ast_comment_view::requested(&query);
        let root_kinds = per_root_kinds(lang, &query, query_str);
        Arc::new(CompiledAstQuery {
            query,
            deferred,
            literals,
            nodes,
            subqueries,
            ignore_comments,
            root_kinds,
        })
    });
    if let Some(started) = compile_started {
        tracing::debug!(compile_us = started.elapsed().as_micros(), file_type = ?file_type, grammar = %key.0,
            success = compiled.is_some(), query = ?query_str, "compiled individual AST query");
    }
    QUERY_CACHE.write().insert(key, compiled.clone());
    compiled
}

/// Tree-sitter's `set_match_limit` accepts at most this many matches per cursor.
/// Combined `query:` batches share one cursor, so a bomb can starve later
/// patterns — on exceed we drop the batch and fall back to per-query eval.
const COMBINED_AST_QUERY_MATCH_LIMIT: u32 = 65_536;
// A shared cursor must not let one combinatorial pattern spend the whole
// batch's CPU budget. Its per-pattern overflow bit sends only that query to
// the ordinary evaluator, which retains the full standalone state limit.
const COMBINED_AST_QUERY_GROUP_STATE_LIMIT: u32 = 64;
/// The shared batch walk's CPU budget is the per-query budget times the
/// active queries it stands in for, up to this many (12 x 5 s = 60 s).
const BATCH_CPU_BUDGET_MAX_QUERIES: usize = 12;
/// Trees nested at least this deep run the shared batch per root node
/// (`CLEAVE_AST_BATCH_PER_ROOT_DEPTH`). One whole-tree cursor keeps up to
/// `COMBINED_AST_QUERY_GROUP_STATE_LIMIT` live states per pattern for every
/// level of nesting of its root kind, and visits each node against all of
/// them: a 5 MB JSFuck expression nested past 1,000 levels burned the whole
/// 60 s budget without settling any of its 27 active queries. Per root, each
/// run holds one state per pattern and only descends as far as that root's
/// own match needs.
const BATCH_PER_ROOT_DEPTH: u32 = 512;

fn batch_per_root_depth() -> u32 {
    #[cfg(test)]
    if let Some(depth) = BATCH_PER_ROOT_DEPTH_OVERRIDE.with(Cell::get) {
        return depth;
    }
    static DEPTH: OnceLock<u32> = OnceLock::new();
    *DEPTH.get_or_init(|| {
        crate::env::parse::<u32>("CLEAVE_AST_BATCH_PER_ROOT_DEPTH").unwrap_or(BATCH_PER_ROOT_DEPTH)
    })
}

#[cfg(test)]
thread_local! {
    /// Test override for [`batch_per_root_depth`] on this thread.
    pub(super) static BATCH_PER_ROOT_DEPTH_OVERRIDE: Cell<Option<u32>> = const { Cell::new(None) };
}

/// Run every applicable `query:` in one `QueryCursor` walk. `None` means
/// "do not use a batch" — caller keeps the per-trait `eval_ast_query` path
/// (fewer than two compiling queries, combined compile failed, match-limit
/// overflow, timeout, or cancel). Results are keyed by the original query
/// string so `unless:` / duplicate `if:` share one bucket.
#[cfg(test)]
pub(crate) fn batch_ast_queries(
    tree: &tree_sitter::Tree,
    source: &str,
    file_type: FileType,
    query_strs: &[&str],
    deadline: Option<Instant>,
    cancellation: Option<&AtomicBool>,
) -> Option<FxHashMap<String, ConditionResult>> {
    batch_ast_queries_with_budget(
        tree,
        source,
        file_type,
        query_strs,
        deadline,
        cancellation,
        None,
    )
}

#[cfg(test)]
pub(super) fn batch_ast_queries_with_budget(
    tree: &tree_sitter::Tree,
    source: &str,
    file_type: FileType,
    query_strs: &[&str],
    deadline: Option<Instant>,
    cancellation: Option<&AtomicBool>,
    cpu_budget_override: Option<std::time::Duration>,
) -> Option<FxHashMap<String, ConditionResult>> {
    batch_ast_queries_with_index(
        tree,
        source,
        file_type,
        query_strs,
        deadline,
        cancellation,
        cpu_budget_override,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn batch_ast_queries_with_index(
    tree: &tree_sitter::Tree,
    source: &str,
    file_type: FileType,
    query_strs: &[&str],
    deadline: Option<Instant>,
    cancellation: Option<&AtomicBool>,
    cpu_budget_override: Option<std::time::Duration>,
    node_text: Option<&NodeTextIndex>,
    boolean_queries: Option<&rustc_hash::FxHashSet<String>>,
) -> Option<FxHashMap<String, ConditionResult>> {
    let mut out = batch_ast_bank(
        tree,
        source,
        file_type,
        query_strs,
        deadline,
        cancellation,
        cpu_budget_override,
        node_text,
        boolean_queries,
        false,
    );
    // Comment-ignoring queries read a comment-masked reparse, so they share a
    // second walk over that tree instead of walking it one query at a time
    // (each also outside the structural gate). The view is built only when
    // two of them can match the file's literals; when it cannot be built
    // they stay on the per-query path, which reports why.
    if comment_bank_enabled() && source.len() <= AST_QUERY_BYTE_LIMIT {
        let lang = &*tree.language();
        let candidates = query_strs
            .iter()
            .filter(|q| batch_leaves_out_by_design(q) && count_unbounded_any_wildcards(q) < 2)
            .filter_map(|q| cached_ast_query(lang, file_type, q))
            .filter(|compiled| compiled.ignore_comments && compiled.may_match(source.as_bytes()))
            .take(2)
            .count();
        if candidates >= 2
            && let Ok(view) = super::ast_comment_view::build(
                tree,
                source,
                AST_QUERY_BYTE_LIMIT,
                AST_QUERY_CPU_BUDGET,
                deadline,
                cancellation,
            )
        {
            let (view_tree, view_index) = match &view {
                Some(view) => (view, None),
                None => (tree, node_text),
            };
            if let Some(comment_out) = batch_ast_bank(
                view_tree,
                source,
                file_type,
                query_strs,
                deadline,
                cancellation,
                cpu_budget_override,
                view_index,
                boolean_queries,
                true,
            ) {
                out.get_or_insert_with(FxHashMap::default).extend(comment_out);
            }
        }
    }
    out
}

/// Whether comment-ignoring queries share a walk (`CLEAVE_AST_COMMENT_BATCH`,
/// on by default).
fn comment_bank_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| crate::env::bool_var("CLEAVE_AST_COMMENT_BATCH").unwrap_or(true))
}

/// One shared walk for the queries of one tree view: ordinary queries over the
/// parsed tree (`comment_view == false`) or comment-ignoring queries over the
/// comment-masked reparse (`comment_view == true`).
#[allow(clippy::too_many_arguments)]
fn batch_ast_bank(
    tree: &tree_sitter::Tree,
    source: &str,
    file_type: FileType,
    query_strs: &[&str],
    deadline: Option<Instant>,
    cancellation: Option<&AtomicBool>,
    cpu_budget_override: Option<std::time::Duration>,
    node_text: Option<&NodeTextIndex>,
    boolean_queries: Option<&rustc_hash::FxHashSet<String>>,
    comment_view: bool,
) -> Option<FxHashMap<String, ConditionResult>> {
    if query_strs.len() < 2 || source.len() > AST_QUERY_BYTE_LIMIT {
        return None;
    }
    let lang = &*tree.language();
    let mut compiling: Vec<(&str, Arc<CompiledAstQuery>)> = Vec::new();
    let mut active = Vec::new();
    let mut pattern_active = Vec::new();
    let owned_node_text;
    let node_text = match node_text {
        Some(index) => index,
        None => {
            owned_node_text = NodeTextIndex::new(tree, source);
            &owned_node_text
        }
    };
    // Queries whose required literals the file lacks: answered "no match"
    // without joining the walk. Queries share literals (`require`, `exec`),
    // so each is searched for once.
    let mut out: FxHashMap<String, ConditionResult> = FxHashMap::default();
    let mut presence: FxHashMap<(Vec<u8>, bool), bool> = FxHashMap::default();
    let mut contains = |literal: &[u8], ci: bool| {
        let key = (literal.to_vec(), ci);
        if let Some(&found) = presence.get(&key) {
            return found;
        }
        let found = super::ast_gate::source_contains(source.as_bytes(), literal, ci);
        presence.insert(key, found);
        found
    };
    // Keep this set independent of source text: filtering before building the
    // bank would recompile one native query for each file-specific subset.
    for &q in query_strs {
        // A batch runs under the tightest budget among its queries, and a
        // multi-wildcard query's is 100ms. Batched, it capped every ordinary
        // query beside it at that, so on a loaded machine the walk stopped
        // early and their matches later in the file came and went with load.
        // Left out of the map, it runs alone under its own budget.
        if let Some(compiled) = cached_ast_query(lang, file_type, q) {
            // A comment-ignoring query reads the comment-masked tree; each
            // bank holds only the queries of the tree it walks.
            if compiled.ignore_comments != comment_view {
                continue;
            }
            let mut enabled: Vec<bool> = (0..compiled.query.pattern_count())
                .map(|pattern| {
                    compiled.nodes.pattern_may_match(pattern, node_text)
                        && compiled.literals.pattern_may_match(pattern, &mut contains)
                })
                .collect();
            compiled.prune_subqueries(
                tree,
                source,
                Some(node_text),
                &mut enabled,
                deadline,
                cancellation,
            );
            let possible = enabled.iter().any(|&enabled| enabled);
            if !possible {
                out.insert(q.to_string(), ConditionResult::no_match());
            }
            if count_unbounded_any_wildcards(q) >= 2 {
                continue;
            }
            active.push(possible);
            pattern_active.extend(enabled);
            compiling.push((q, compiled));
        }
    }
    if active.iter().filter(|&&enabled| enabled).count() < 2 {
        // Too few left to share a walk; the gate's answers still stand, and a
        // lone query left out of the map walks on the per-trait path.
        return (!out.is_empty()).then_some(out);
    }

    let combined_source: String = compiling
        .iter()
        .map(|(q, _)| *q)
        .collect::<Vec<_>>()
        .join("\n");
    let lang_key = ast_query_language_key(lang, file_type);
    let cache_key = (lang_key, combined_source.clone());
    let cached = COMBINED_QUERY_CACHE.read().get(&cache_key).cloned();
    let combined = if let Some(entry) = cached {
        entry?
    } else {
        let wait_started = tracing::enabled!(tracing::Level::DEBUG).then(Instant::now);
        let _compiler = COMBINED_QUERY_COMPILER.lock();
        if let Some(started) = wait_started
            && started.elapsed().as_millis() >= 10
        {
            tracing::debug!(wait_ms = started.elapsed().as_millis(),
                file_type = ?file_type, grammar = %cache_key.0,
                "waited for AST query bank compiler");
        }
        let cached = COMBINED_QUERY_CACHE.read().get(&cache_key).cloned();
        if let Some(entry) = cached {
            entry?
        } else {
            // Compile (or fail) once and record the outcome either way; a
            // failure or pattern-count mismatch is deterministic for this
            // combined source, so retrying it per member only burns CPU.
            let entry = (|| {
                let compile_started = Instant::now();
                let query = tree_sitter::Query::new(lang, &combined_source).ok()?;
                tracing::debug!(
                    queries = compiling.len(),
                    patterns = query.pattern_count(),
                    file_type = ?file_type,
                    grammar = %cache_key.0,
                    compile_ms = compile_started.elapsed().as_millis(),
                    "compiled AST query bank"
                );
                let mut pattern_to_query = Vec::new();
                let mut expected = 0usize;
                for (i, (_, q)) in compiling.iter().enumerate() {
                    let n = q.query.pattern_count();
                    expected = expected.saturating_add(n);
                    pattern_to_query.extend(std::iter::repeat_n(i, n));
                }
                if query.pattern_count() != expected {
                    return None;
                }
                let deferred = DeferredPredicates::of(&query, &combined_source);
                Some(Arc::new(CombinedAstQuery {
                    deferred,
                    query: Arc::new(query),
                    pattern_to_query,
                }))
            })();
            COMBINED_QUERY_CACHE
                .write()
                .insert(cache_key, entry.clone());
            entry?
        }
    };

    // Compile the same query set once across archive members. File-specific
    // literal gates only disable patterns on a private copy; they must not
    // create another expensive ts_query_new for each surviving subset, or
    // mutate the shared query observed by concurrent archive workers.
    let mut narrowed = pattern_active.iter().any(|&enabled| !enabled).then(|| {
        let mut query = combined.query.deep_clone();
        for (pattern, &enabled) in pattern_active.iter().enumerate() {
            if !enabled {
                query.disable_pattern(pattern);
            }
        }
        query
    });
    // On a deep tree the shared walk runs once per node of the kinds the
    // queries are rooted at. A query not rooted at one kind (sibling
    // patterns, alternation or wildcard roots) cannot be served that way
    // and walks alone like a query the gates left out.
    let per_root_kinds = (node_text.max_depth() >= batch_per_root_depth()).then(|| {
        let mut query = narrowed
            .take()
            .unwrap_or_else(|| combined.query.deep_clone());
        let mut kinds = Vec::new();
        for (qi, (_, compiled)) in compiling.iter().enumerate() {
            if !active[qi] {
                continue;
            }
            match compiled.root_kinds.as_deref() {
                Some(root_kinds) => kinds.extend_from_slice(root_kinds),
                None => {
                    active[qi] = false;
                    for (pattern, &owner) in combined.pattern_to_query.iter().enumerate() {
                        if owner == qi {
                            query.disable_pattern(pattern);
                        }
                    }
                }
            }
        }
        kinds.sort_unstable();
        kinds.dedup();
        narrowed = Some(query);
        kinds
    });
    let query = narrowed.as_ref().unwrap_or(&combined.query);
    let shared_evidence_capture = query
        .capture_names()
        .iter()
        .position(|name| *name == "evidence")
        .and_then(|index| u32::try_from(index).ok());
    // Capture names are shared by a query bank. Opt-in belongs to each
    // original query, so one query cannot hide a sibling's evidence.
    let evidence_captures: Vec<Option<u32>> = compiling
        .iter()
        .map(|(_, compiled)| {
            if compiled.query.capture_names().contains(&"evidence") {
                shared_evidence_capture
            } else {
                None
            }
        })
        .collect();

    struct Bucket {
        evidence: Vec<Evidence>,
        match_count: usize,
        query_matches: usize,
        capture_count: usize,
        capture_limited: bool,
        match_limited: bool,
        complete: bool,
    }
    let n = compiling.len();
    let mut buckets: Vec<Bucket> = (0..n)
        .map(|_| Bucket {
            evidence: Vec::new(),
            match_count: 0,
            query_matches: 0,
            capture_count: 0,
            capture_limited: false,
            match_limited: false,
            complete: false,
        })
        .collect();

    let mut query_cursor = tree_sitter::QueryCursor::new();
    query_cursor.set_match_limit(COMBINED_AST_QUERY_MATCH_LIMIT);
    query_cursor.set_max_states_per_group(COMBINED_AST_QUERY_GROUP_STATE_LIMIT);
    // A limited pattern will be retried independently. Stop spending shared
    // traversal time on it so unrelated patterns can finish within the budget.
    query_cursor.set_stop_on_pattern_limit(true);
    query_cursor.set_byte_range(0..source.len().min(AST_QUERY_BYTE_LIMIT));

    let cancelled = || cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed));
    // The shared walk replaces one standalone walk per active query, so it
    // gets their budgets, not one query's: a 10 MB JavaScript bundle (449
    // traits, 10.15 MB) under the single-query ceiling hit it after 5 s and
    // then paid ~1 s for every standalone walk that followed (142 CPU-s);
    // with the walks' combined budget the batch settles every query (70
    // CPU-s, identical findings). The sum is capped so a pathological tree
    // cannot hold a worker for minutes before the fallback; above the cap
    // the standalone walks were going to cost more than the cap anyway.
    let per_query_budget = compiling
        .iter()
        .map(|(query, _)| ast_query_cpu_budget(query, deadline))
        .min()
        .unwrap_or(AST_QUERY_CPU_BUDGET);
    let active_queries = active.iter().filter(|&&enabled| enabled).count();
    let default_cpu_budget = per_query_budget.saturating_mul(
        u32::try_from(active_queries.clamp(1, BATCH_CPU_BUDGET_MAX_QUERIES)).unwrap_or(1),
    );
    // Diagnostic override for measuring the cost of repeated standalone
    // walks after the shared batch reaches its CPU budget. An unfinished
    // query still falls back to its ordinary per-query budget below.
    let cpu_budget = cpu_budget_override
        .or_else(|| {
            crate::env::parse::<u64>("CLEAVE_AST_BATCH_CPU_MS")
                .filter(|&ms| ms > 0)
                .map(std::time::Duration::from_millis)
        })
        .unwrap_or(default_cpu_budget);
    let cpu_start = thread_cpu_time();
    let timed_out = Cell::new(false);
    let mut progress_cb = |_state: &tree_sitter::QueryCursorState| -> ControlFlow<()> {
        if cancelled() {
            return ControlFlow::Break(());
        }
        if let Some(dl) = deadline
            && Instant::now() > dl
        {
            return ControlFlow::Break(());
        }
        if thread_cpu_time().saturating_sub(cpu_start) >= cpu_budget {
            timed_out.set(true);
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    };
    let mut capture_predicate =
        |pattern,
         capture,
         node: tree_sitter::Node<'_>,
         previous: &[tree_sitter::QueryCapture<'_>]| {
            capture_satisfies_early_predicates(
                query,
                &combined.deferred,
                pattern,
                capture,
                node,
                previous,
                source.as_bytes(),
            )
        };
    // One match's bookkeeping, shared by both walks. Patterns to switch off
    // on the cursor come back in `disable`: the match borrows the cursor's
    // iterator, so they are applied after it is released.
    let mut accept = |m: &tree_sitter::QueryMatch<'_, '_>, disable: &mut Vec<usize>| {
        if m.captures().is_empty() {
            return;
        }
        let Some(&qi) = combined.pattern_to_query.get(m.pattern_index) else {
            return;
        };
        let evidence_capture = evidence_captures[qi];
        if evidence_capture
            .is_some_and(|selected| !m.captures().iter().any(|capture| capture.index == selected))
        {
            return;
        }
        let bucket = &mut buckets[qi];
        if bucket.complete || bucket.capture_limited || bucket.match_limited {
            disable.push(m.pattern_index);
            return;
        }
        if bucket.query_matches >= AST_QUERY_MATCH_LIMIT as usize {
            bucket.match_limited = true;
            disable.push(m.pattern_index);
            return;
        }
        if bucket.capture_count >= AST_QUERY_CAPTURE_LIMIT {
            bucket.capture_limited = true;
            disable.push(m.pattern_index);
            return;
        }
        bucket.query_matches += 1;
        bucket.match_count += 1;
        for capture in m.captures() {
            if bucket.capture_count >= AST_QUERY_CAPTURE_LIMIT {
                bucket.capture_limited = true;
                break;
            }
            bucket.capture_count += 1;
            if evidence_capture.is_some_and(|selected| capture.index != selected) {
                continue;
            }
            if let Ok(text) = capture.node.utf8_text(source.as_bytes())
                && bucket.evidence.len() < MAX_EVIDENCE_PER_TRAIT
            {
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
        if boolean_queries.is_some_and(|queries| queries.contains(compiling[qi].0)) {
            bucket.complete = true;
            // A query can contain several patterns. Stop all of them without
            // mutating the shared compiled Query or the other queries' states.
            for (pattern, &owner) in combined.pattern_to_query.iter().enumerate() {
                if owner == qi {
                    disable.push(pattern);
                }
            }
        }
    };
    let over_budget = || thread_cpu_time().saturating_sub(cpu_start) >= cpu_budget;
    let mut disable = Vec::new();
    // Patterns whose states were abandoned (the per-group state cap or the
    // shared capture-list pool): their queries have partial results.
    let mut exceeded = vec![false; n];
    let note_exceeded = |query_cursor: &tree_sitter::QueryCursor, exceeded: &mut [bool]| {
        if query_cursor.did_exceed_match_limit() {
            for (pattern, &qi) in combined.pattern_to_query.iter().enumerate() {
                if query_cursor.pattern_exceeded(pattern) {
                    exceeded[qi] = true;
                }
            }
        }
    };
    match per_root_kinds.as_deref() {
        None => {
            let options = tree_sitter::QueryCursorOptions::default()
                .progress_callback(&mut progress_cb)
                .capture_match_predicate(&mut capture_predicate);
            let mut matches = query_cursor.matches_with_options(
                query,
                tree.root_node(),
                source.as_bytes(),
                options,
            );
            while let Some(m) = matches.next() {
                if cancelled() || deadline.is_some_and(|dl| Instant::now() > dl) {
                    return None;
                }
                if over_budget() {
                    timed_out.set(true);
                    break;
                }
                accept(m, &mut disable);
                for pattern in disable.drain(..) {
                    matches.disable_pattern(pattern);
                }
            }
            drop(matches);
            note_exceeded(&query_cursor, &mut exceeded);
        }
        Some(root_kinds) => {
            // As in `eval_ast_query_once`: each run may only start a match at
            // the node it is given, and the walk is iterative so the depth
            // that made the tree pathological costs no stack.
            query_cursor.set_max_start_depth(Some(0));
            let byte_limit = source.len().min(AST_QUERY_BYTE_LIMIT);
            let mut walk = tree.walk();
            let mut visited: usize = 0;
            'roots: loop {
                let node = walk.node();
                if node.start_byte() < byte_limit {
                    if root_kinds.binary_search(&node.kind_id()).is_ok() {
                        let options = tree_sitter::QueryCursorOptions::default()
                            .progress_callback(&mut progress_cb)
                            .capture_match_predicate(&mut capture_predicate);
                        let mut matches = query_cursor.matches_with_options(
                            query,
                            node,
                            source.as_bytes(),
                            options,
                        );
                        while let Some(m) = matches.next() {
                            if cancelled() || deadline.is_some_and(|dl| Instant::now() > dl) {
                                return None;
                            }
                            if over_budget() {
                                timed_out.set(true);
                                break 'roots;
                            }
                            accept(m, &mut disable);
                            for pattern in disable.drain(..) {
                                matches.disable_pattern(pattern);
                            }
                        }
                        drop(matches);
                        note_exceeded(&query_cursor, &mut exceeded);
                        if timed_out.get() {
                            break 'roots;
                        }
                    }
                    visited += 1;
                    if visited.is_multiple_of(4096) {
                        if cancelled() || deadline.is_some_and(|dl| Instant::now() > dl) {
                            return None;
                        }
                        if over_budget() {
                            timed_out.set(true);
                            break 'roots;
                        }
                    }
                    if walk.goto_first_child() {
                        continue;
                    }
                }
                loop {
                    if walk.goto_next_sibling() {
                        continue 'roots;
                    }
                    if !walk.goto_parent() {
                        break 'roots;
                    }
                }
            }
        }
    }
    if timed_out.get() {
        tracing::debug!(
            queries = n,
            source_bytes = source.len(),
            budget_ms = cpu_budget.as_millis(),
            "tree-sitter query batch hit its CPU budget; unresolved queries walk alone"
        );
    }
    // An interrupted shared walk has not established absence for queries it
    // never reached. Do not cache those partial negatives: evaluating each
    // query independently gives later source nodes their own bounded walk.
    if cancelled() || deadline.is_some_and(|dl| Instant::now() > dl) {
        // The gates proved these negatives before the interrupted cursor ran.
        // Keep them so fallback does not re-run queries known to be impossible.
        return (!out.is_empty()).then_some(out);
    }
    // A query with partial results (see `exceeded`) is left out of the map
    // so `eval_ast_query` walks it alone with its own limits, and every other
    // query keeps its complete result rather than re-walking the tree once
    // per query for all of them.

    tracing::debug!(
        queries = n,
        active_queries = active.iter().filter(|&&enabled| enabled).count(),
        per_root = per_root_kinds.is_some(),
        tree_depth = node_text.max_depth(),
        limited_queries = exceeded.iter().filter(|&&limited| limited).count(),
        settled_queries = buckets.iter().filter(|b| b.complete).count(),
        source_bytes = source.len(),
        cpu_ms = thread_cpu_time().saturating_sub(cpu_start).as_millis(),
        timed_out = timed_out.get(),
        "AST query batch summary"
    );
    let has_parse_errors = tree.root_node().has_error();
    for (i, (qstr, _)) in compiling.iter().enumerate() {
        if !active[i] {
            continue;
        }
        if (exceeded[i] || timed_out.get()) && !buckets[i].complete {
            continue;
        }
        let bucket = &mut buckets[i];
        let mut warnings = Vec::new();
        if has_parse_errors {
            warnings.push(AnalysisWarning::AstParseError);
        }
        if timed_out.get() {
            warnings.push(AnalysisWarning::AstTooDeep { max_depth: 0 });
        }
        if exceeded[i] {
            warnings.push(AnalysisWarning::AstQueryLimited {
                limit: AST_QUERY_GROUP_STATE_LIMIT as usize,
            });
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
    (!out.is_empty()).then_some(out)
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

#[cfg(test)]
pub(super) fn combined_bank_cached_for_test(
    lang: &tree_sitter::Language,
    file_type: FileType,
    queries: &[&str],
) -> bool {
    COMBINED_QUERY_CACHE
        .read()
        .get(&(ast_query_language_key(lang, file_type), queries.join("\n")))
        .is_some_and(Option::is_some)
}

#[cfg(test)]
mod batch_design_exclusion_tests {
    use super::batch_leaves_out_by_design;

    #[test]
    fn multi_wildcard_and_comment_view_queries_stay_off_the_heavy_tail() {
        assert!(batch_leaves_out_by_design(
            "(call_expression arguments: (arguments (_)* @a (_)* @b))"
        ));
        assert!(batch_leaves_out_by_design(
            "((call_expression) @c (#set! cleave.ignore-comments \"true\"))"
        ));
        assert!(!batch_leaves_out_by_design(
            "(binary_expression left: (_) @l operator: \"-\")"
        ));
    }
}

#[cfg(test)]
mod cache_lock_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn ast_cache_hit_does_not_wait_for_compiler() {
        let source = b"const value = 1;";
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("cache-lock.js"))
            .cache(false)
            .open(source);
        let _ = parsed.values();
        let tree = parsed.source_ast().unwrap().tree.clone();
        let language = tree.language();
        let pattern = "(identifier) @cache_lock_hit";
        let key = (
            ast_query_language_key(&language, FileType::JavaScript),
            pattern.to_string(),
        );
        let compiler = query_compiler(&key).lock();
        let query = tree_sitter::Query::new(&language, pattern).unwrap();
        let compiled = Arc::new(CompiledAstQuery {
            literals: RequiredLiterals::of(&query, pattern),
            nodes: RequiredNodes::of(&language, &query, pattern),
            subqueries: RequiredSubqueries::default(),
            ignore_comments: false,
            deferred: DeferredPredicates::of(&query, pattern),
            root_kinds: per_root_kinds(&language, &query, pattern),
            query,
        });
        QUERY_CACHE.write().insert(key, Some(compiled.clone()));
        let (send, receive) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            let hit = cached_ast_query(&tree.language(), FileType::JavaScript, pattern);
            send.send(hit).unwrap();
        });
        // Release before asserting/joining so a regression cannot deadlock the test.
        let hit = receive.recv_timeout(std::time::Duration::from_secs(5));
        drop(compiler);
        thread.join().unwrap();
        assert!(Arc::ptr_eq(
            &compiled,
            &hit.expect("cached hits must not wait for compilation")
                .unwrap()
        ));
    }

    #[test]
    fn ast_cache_concurrent_misses_share_one_query() {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("cache-misses.js"))
            .cache(false)
            .open(b"const value = 1;");
        let _ = parsed.values();
        let tree = parsed.source_ast().unwrap().tree;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(16));
        let queries: Vec<_> = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..16)
                .map(|_| {
                    let tree = tree.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        cached_ast_query(
                            &tree.language(),
                            FileType::JavaScript,
                            "(identifier) @cache_concurrent_misses",
                        )
                        .unwrap()
                    })
                })
                .collect();
            threads.into_iter().map(|t| t.join().unwrap()).collect()
        });
        assert!(queries.iter().all(|q| Arc::ptr_eq(&queries[0], q)));
    }
}
