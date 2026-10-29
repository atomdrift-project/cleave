//! Necessary loop queries for expensive wildcard sibling joins.
//! Execute only at indexed for-statement roots, avoiding another full AST walk.
//! Removing a required parent/sibling restriction broadens a query. A complete
//! negative for that broader query therefore proves the original cannot match.
use super::{NodeTextIndex, Op, positive_text_predicates, query_token_spans};
use crate::analyzers::ast_walker::{AST_QUERY_CPU_BUDGET, thread_cpu_time};
use std::ops::ControlFlow;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Query, QueryCursor, QueryCursorOptions, Tree};

#[derive(Default)]
pub(crate) struct RequiredSubqueries {
    queries: Vec<Query>,
    patterns: Vec<Option<usize>>,
}

impl RequiredSubqueries {
    pub(crate) fn enabled() -> bool {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| crate::env::bool_var("CLEAVE_AST_LOOP_GATE").unwrap_or(true))
    }

    pub(crate) fn of(language: &Language, query: &Query, source: &str) -> Self {
        let mut result = Self::default();
        let mut compiled = rustc_hash::FxHashMap::default();
        for pattern in 0..query.pattern_count() {
            let gate = source
                .get(query.start_byte_for_pattern(pattern)..query.end_byte_for_pattern(pattern))
                .and_then(required_child_query);
            let index = gate.and_then(|gate| {
                if let Some(&index) = compiled.get(&gate) {
                    return Some(index);
                }
                // A detached child referencing a capture outside itself is
                // not independently executable; compilation fails open.
                let query = Query::new(language, &gate).ok()?;
                let index = result.queries.len();
                result.queries.push(query);
                compiled.insert(gate, index);
                Some(index)
            });
            result.patterns.push(index);
        }
        result
    }

    pub(crate) fn prune_indexed(
        &self,
        tree: &Tree,
        source: &str,
        node_index: &NodeTextIndex,
        enabled: &mut [bool],
        deadline: Option<Instant>,
        cancellation: Option<&AtomicBool>,
    ) {
        if self.queries.is_empty() || stopped(deadline, cancellation) {
            return;
        }
        let started = thread_cpu_time();
        let wall = std::time::Instant::now();
        let budget = AST_QUERY_CPU_BUDGET / 10;
        let mut answers = vec![None; self.queries.len()];
        for (pattern, gate) in self.patterns.iter().enumerate() {
            let Some(active) = enabled.get_mut(pattern) else {
                continue;
            };
            if !*active {
                continue;
            }
            let Some(index) = *gate else { continue };
            let possible = match answers[index] {
                Some(answer) => answer,
                None => {
                    let elapsed = if started.is_zero() {
                        wall.elapsed()
                    } else {
                        thread_cpu_time().saturating_sub(started)
                    };
                    let remaining = budget.saturating_sub(elapsed);
                    if remaining.is_zero() {
                        break;
                    }
                    let answer = may_match_indexed(
                        &self.queries[index],
                        tree,
                        source,
                        node_index,
                        remaining,
                        deadline,
                        cancellation,
                    );
                    answers[index] = Some(answer);
                    answer
                }
            };
            if !possible {
                *active = false;
                tracing::debug!(target: "cleave::ast_loop_gate", pattern, bytes = source.len(), "required child query absent");
            }
        }
    }
    #[cfg(test)]
    fn prune(
        &self,
        tree: &Tree,
        source: &str,
        enabled: &mut [bool],
        deadline: Option<Instant>,
        cancellation: Option<&AtomicBool>,
    ) {
        self.prune_indexed(
            tree,
            source,
            &NodeTextIndex::new(tree, source),
            enabled,
            deadline,
            cancellation,
        );
    }
}

fn stopped(deadline: Option<Instant>, cancellation: Option<&AtomicBool>) -> bool {
    deadline.is_some_and(|end| Instant::now() >= end)
        || cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed))
}

fn may_match_indexed(
    query: &Query,
    tree: &Tree,
    source: &str,
    index: &NodeTextIndex,
    budget: std::time::Duration,
    deadline: Option<Instant>,
    cancellation: Option<&AtomicBool>,
) -> bool {
    let Some(ranges) = index.for_statement_ranges() else {
        return true;
    };
    let started = thread_cpu_time();
    let wall = Instant::now();
    for range in ranges {
        let elapsed = if started.is_zero() {
            wall.elapsed()
        } else {
            thread_cpu_time().saturating_sub(started)
        };
        let remaining = budget.saturating_sub(elapsed);
        if remaining.is_zero() || stopped(deadline, cancellation) {
            return true;
        }
        let Some(node) = tree
            .root_node()
            .named_descendant_for_byte_range(range.start, range.end)
        else {
            return true;
        };
        // An index from different bytes/tree cannot establish a negative.
        if node.kind() != "for_statement" || node.byte_range() != *range {
            return true;
        }
        if may_match(query, node, source, remaining, deadline, cancellation) {
            return true;
        }
    }
    tracing::debug!(target: "cleave::ast_loop_gate", loops = ranges.len(), bytes = source.len(), "required loop query absent");
    false
}

fn may_match(
    query: &Query,
    root: tree_sitter::Node<'_>,
    source: &str,
    budget: std::time::Duration,
    deadline: Option<Instant>,
    cancellation: Option<&AtomicBool>,
) -> bool {
    if budget.is_zero() || stopped(deadline, cancellation) {
        return true;
    }
    let started = thread_cpu_time();
    let wall = std::time::Instant::now();
    let mut interrupted = false;
    let mut progress = |_: &tree_sitter::QueryCursorState| {
        let elapsed = if started.is_zero() {
            wall.elapsed()
        } else {
            thread_cpu_time().saturating_sub(started)
        };
        if elapsed >= budget || stopped(deadline, cancellation) {
            interrupted = true;
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    };
    let mut cursor = QueryCursor::new();
    cursor.set_max_start_depth(Some(0));
    cursor.set_match_limit(1024);
    cursor.set_max_states_per_group(128);
    cursor.set_stop_on_pattern_limit(true);
    let mut capture = |pattern: usize,
                       id: u32,
                       node: tree_sitter::Node<'_>,
                       previous: &[tree_sitter::QueryCapture<'_>]| {
        query.capture_satisfies_match_predicates(pattern, id, node, previous, source.as_bytes())
    };
    let mut matches = cursor.matches_with_options(
        query,
        root,
        source.as_bytes(),
        QueryCursorOptions::new()
            .progress_callback(&mut progress)
            .capture_match_predicate(&mut capture),
    );
    let matched = matches.next().is_some();
    drop(matches);
    let limited = cursor.did_exceed_match_limit()
        || (0..query.pattern_count()).any(|pattern| cursor.pattern_exceeded(pattern));
    tracing::trace!(target: "cleave::ast_loop_gate", bytes = source.len(), matched, interrupted, limited,
        captures = ?query.capture_names(), "required child query checked");
    matched || interrupted || limited
}

/// Only a statement container with multiple mandatory children qualifies.
/// Optional direct children deliberately receive no gate. Mandatory alternatives
/// count as a sibling, but are not themselves extracted as a required child.
fn required_child_query(source: &str) -> Option<String> {
    let tokens = query_token_spans(source);
    let mut closes = vec![None; tokens.len()];
    let mut stack = Vec::new();
    for (index, &(token, _, _)) in tokens.iter().enumerate() {
        match token {
            "(" | "[" => stack.push(index),
            ")" | "]" => {
                let open = stack.pop()?;
                if (tokens[open].0 == "(") != (token == ")") {
                    return None;
                }
                closes[open] = Some(index);
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return None;
    }
    let root = (0..tokens.len()).find(|&i| {
        tokens[i].0 == "("
            && tokens
                .get(i + 1)
                .is_some_and(|t| !matches!(t.0, "(" | "[") && !t.0.starts_with('#'))
    })?;
    if !matches!(tokens.get(root + 1)?.0, "_" | "program" | "statement_block") {
        return None;
    }
    let end = closes[root]?;
    for open in 0..=root {
        if closes[open].is_some_and(|close| close >= end) {
            if tokens[open].0 == "[" {
                return None;
            }
            let mut after = closes[open]? + 1;
            while tokens.get(after).is_some_and(|t| t.0.starts_with('@')) {
                after += 1;
            }
            if tokens.get(after).is_some_and(|t| matches!(t.0, "?" | "*")) {
                return None;
            }
        }
    }
    let mut i = root + 2;
    let mut children = Vec::new();
    let mut required_children = 0;
    while i < end {
        match tokens[i].0 {
            "[" => {
                let close = closes[i]?;
                let mut after = close + 1;
                while tokens.get(after).is_some_and(|t| t.0.starts_with('@')) {
                    after += 1;
                }
                if tokens.get(after).is_some_and(|t| matches!(t.0, "?" | "*")) {
                    return None;
                }
                required_children += 1;
                i = close + 1;
            }
            "(" => {
                let close = closes[i]?;
                let kind = tokens.get(i + 1)?.0;
                let mut after = close + 1;
                while tokens.get(after).is_some_and(|t| t.0.starts_with('@')) {
                    after += 1;
                }
                if tokens.get(after).is_some_and(|t| matches!(t.0, "?" | "*")) {
                    return None;
                }
                if !kind.starts_with('#') && !matches!(kind, "(" | "[" | "\"") {
                    required_children += 1;
                    if kind != "_" {
                        children.push(tokens[i].1..tokens[close].2);
                    }
                }
                i = close + 1;
            }
            _ => i += 1,
        }
    }
    if required_children < 2 {
        return None;
    }
    let child = children.into_iter().max_by_key(ExactSizeIterator::len)?;
    // Small joins are cheaper to execute directly.
    if child.len() < 256 {
        return None;
    }
    let child = &source[child];
    if query_token_spans(child).get(1)?.0 != "for_statement" {
        return None;
    }
    let captures: rustc_hash::FxHashSet<_> = query_token_spans(child)
        .into_iter()
        .filter_map(|(token, _, _)| token.strip_prefix('@'))
        .collect();
    let mut gate = format!("({child}");
    for (op, capture, argument) in positive_text_predicates(source) {
        if !captures.contains(capture) {
            continue;
        }
        let op = match op {
            Op::Eq => "eq?",
            Op::Match => "match?",
        };
        gate.push_str(&format!(" (#{op} @{capture} {} )", quote(&argument)));
    }
    gate.push(')');
    Some(gate)
}

fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    const QUERY: &str = r#"((_ (variable_declaration
        (variable_declarator name: (identifier) @buf value: (string)))
      (for_statement
        initializer: (variable_declaration (variable_declarator name: (identifier) @i value: (number) @start))
        condition: (binary_expression left: (identifier) @counter operator: "<" right: (number) @bound)
        increment: (update_expression argument: (identifier) @inc operator: "++")
        body: (statement_block (expression_statement (augmented_assignment_expression
            left: (identifier) @lhs operator: "+=" right: (identifier) @rhs)))))
      (#eq? @start "0") (#eq? @i @counter) (#eq? @i @inc)
      (#eq? @buf @lhs) (#eq? @buf @rhs) (#match? @bound "^(32|64)$"))"#;

    fn with_tree(source: &str, f: impl FnOnce(&Tree)) {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new("subquery.js"))
            .cache(false)
            .open(source.as_bytes());
        let _ = parsed.values();
        f(parsed.source_ast().unwrap().tree);
    }

    #[test]
    fn required_loop_prunes_negatives_and_preserves_full_query_matches() {
        for (source, expected_match, expected_possible) in [
            ("var s=''; for(var i=0;i<32;i++){s+=s;}", true, true),
            (
                "function f(){ var α=''; for(var j=0;j<64;j++){α+=α;} }",
                true,
                true,
            ),
            ("var s=''; for(var i=0;i<2;i++){s+=s;}", false, false),
            ("var s=''; for(var i=0;i<32;i++){var x=1;}", false, false),
            // Cross-sibling captures stay in the real query; the gate is
            // deliberately broader and must not enforce an invented binding.
            ("var s=''; for(var i=0;i<32;i++){t+=s;}", false, true),
            ("for(var i=0;i<32;i++){s+=s;} var s='';", false, true),
        ] {
            with_tree(source, |tree| {
                let query = Query::new(&tree.language(), QUERY).unwrap();
                let gates = RequiredSubqueries::of(&tree.language(), &query, QUERY);
                assert_eq!(gates.queries.len(), 1);
                let mut enabled = vec![true; query.pattern_count()];
                gates.prune(tree, source, &mut enabled, None, None);
                let possible = enabled.iter().any(|&x| x);
                let mut cursor = QueryCursor::new();
                let matched = cursor
                    .matches(&query, tree.root_node(), source.as_bytes())
                    .next()
                    .is_some();
                assert_eq!(matched, expected_match, "{source}");
                assert_eq!(possible, expected_possible, "{source}");
                assert!(!matched || possible, "a real match cannot be pruned");
            });
        }
    }

    #[test]
    fn optional_and_alternative_roots_or_children_do_not_gate() {
        let child = format!("(for_statement ;{}\n)", "padding".repeat(50));
        let root = format!("(_ (identifier) {child})");
        assert!(required_child_query(&root).is_some());
        for query in [
            format!("{root}?"),
            format!("({root})*"),
            format!("[{root} (identifier)]"),
            format!("(_ (identifier) {child}?)"),
            format!("(_ (identifier) [{child} (identifier)])"),
        ] {
            assert!(required_child_query(&query).is_none(), "{query}");
        }
    }

    #[test]
    fn interrupted_precheck_falls_back_to_full_query() {
        let source = "var s='';".repeat(2000);
        with_tree(&source, |tree| {
            let query = Query::new(&tree.language(), "(for_statement) @loop").unwrap();
            assert!(may_match(
                &query,
                tree.root_node(),
                &source,
                std::time::Duration::ZERO,
                None,
                None
            ));
            assert!(!may_match(
                &query,
                tree.root_node(),
                &source,
                std::time::Duration::from_secs(1),
                None,
                None
            ));
        });
    }

    #[test]
    fn state_limited_precheck_falls_back_to_full_query() {
        let source = format!("for(var i=0;i<32;i++){{{}}}", "s+=s;".repeat(2000));
        with_tree(&source, |tree| {
            let query = Query::new(&tree.language(), "(for_statement body: (statement_block (expression_statement) @a (expression_statement) @b (return_statement) @never))").unwrap();
            let root = tree.root_node().named_child(0).unwrap();
            let mut cursor = QueryCursor::new();
            cursor.set_max_start_depth(Some(0));
            cursor.set_match_limit(1024);
            cursor.set_max_states_per_group(128);
            cursor.set_stop_on_pattern_limit(true);
            assert!(
                cursor
                    .matches(&query, root, source.as_bytes())
                    .next()
                    .is_none()
            );
            assert!(cursor.did_exceed_match_limit());
            assert!(may_match(
                &query,
                root,
                &source,
                std::time::Duration::from_secs(10),
                None,
                None
            ));
        });
    }

    #[test]
    fn shared_prechecks_only_disable_their_own_patterns() {
        let source = "var s='';";
        with_tree(source, |tree| {
            let query_source = format!("{QUERY}\n{QUERY}\n(identifier) @other");
            let query = Query::new(&tree.language(), &query_source).unwrap();
            let gates = RequiredSubqueries::of(&tree.language(), &query, &query_source);
            assert_eq!(gates.queries.len(), 1);
            let mut enabled = vec![true; query.pattern_count()];
            gates.prune(tree, source, &mut enabled, None, None);
            assert_eq!(enabled, [false, false, true]);
        });
    }

    #[test]
    fn cancellation_and_outer_deadlines_leave_patterns_enabled() {
        let source = "var s='';";
        with_tree(source, |tree| {
            let query = Query::new(&tree.language(), QUERY).unwrap();
            let gates = RequiredSubqueries::of(&tree.language(), &query, QUERY);
            let cancelled = AtomicBool::new(true);
            let mut enabled = vec![true; query.pattern_count()];
            gates.prune(tree, source, &mut enabled, None, Some(&cancelled));
            assert!(enabled.iter().all(|&active| active));
            gates.prune(tree, source, &mut enabled, Some(Instant::now()), None);
            assert!(enabled.iter().all(|&active| active));
            gates.prune(tree, source, &mut enabled, None, None);
            assert!(enabled.iter().all(|&active| !active));
        });
    }

    #[test]
    fn query_string_quoting_matches_tree_sitter_escapes() {
        for value in ["nul\0value", "a\nb\rc\td", "quote\"\\slash", "αβ"] {
            assert_eq!(
                super::super::string_literal(&quote(value)).unwrap().0,
                value
            );
        }
    }

    #[test]
    fn incomplete_index_cannot_prove_absence() {
        let source = "var s=''; for(var i=0;i<32;i++){s+=s;}";
        with_tree(source, |tree| {
            let query = Query::new(&tree.language(), QUERY).unwrap();
            let gates = RequiredSubqueries::of(&tree.language(), &query, QUERY);
            let mut enabled = vec![true];
            gates.prune_indexed(
                tree,
                source,
                &NodeTextIndex::default(),
                &mut enabled,
                None,
                None,
            );
            assert_eq!(enabled, [true]);
        });
    }

    #[test]
    fn wildcard_declaration_sibling_still_requires_its_loop() {
        let pattern = QUERY.replacen("(variable_declaration", "(_", 1);
        for (source, possible) in [
            ("var s=''; for(var i=0;i<32;i++){s+=s;}", true),
            ("var s=''; for(var i=0;i<2;i++){s+=s;}", false),
        ] {
            with_tree(source, |tree| {
                let query = Query::new(&tree.language(), &pattern).unwrap();
                let gates = RequiredSubqueries::of(&tree.language(), &query, &pattern);
                assert_eq!(gates.queries.len(), 1);
                let mut enabled = vec![true];
                gates.prune(tree, source, &mut enabled, None, None);
                assert_eq!(enabled, [possible]);
                let mut cursor = QueryCursor::new();
                let matched = cursor
                    .matches(&query, tree.root_node(), source.as_bytes())
                    .next()
                    .is_some();
                assert!(!matched || possible);
            });
        }
    }

    #[test]
    fn named_containers_with_alternative_declarations_keep_intervening_statements() {
        for kind in ["program", "statement_block"] {
            let pattern = QUERY.replacen("((_ (variable_declaration", &format!("(({kind} [(variable_declaration"), 1)
                .replacen("value: (string)))", "value: (string))) (lexical_declaration (variable_declarator name: (identifier) @buf value: (string)))]", 1);
            for (code, possible) in [
                ("var s=''; observe(); for(var i=0;i<32;i++){s+=s;}", true),
                ("let s=''; observe(); for(var i=0;i<32;i++){s+=s;}", true),
                ("var s=''; for(var i=0;i<2;i++){s+=s;}", false),
            ] {
                let source = if kind == "statement_block" {
                    format!("function f(){{{code}}}")
                } else {
                    code.to_string()
                };
                with_tree(&source, |tree| {
                    let query = Query::new(&tree.language(), &pattern).unwrap();
                    let gates = RequiredSubqueries::of(&tree.language(), &query, &pattern);
                    assert_eq!(gates.queries.len(), 1);
                    let mut enabled = vec![true];
                    gates.prune(tree, &source, &mut enabled, None, None);
                    assert_eq!(enabled, [possible]);
                    let mut cursor = QueryCursor::new();
                    let matched = cursor
                        .matches(&query, tree.root_node(), source.as_bytes())
                        .next()
                        .is_some();
                    assert_eq!(matched, possible);
                });
            }
        }
    }

    #[test]
    fn indexed_nested_loop_is_not_hidden_by_outer_loop() {
        let source = "for(var k=0;k<2;k++){var s=''; for(var i=0;i<32;i++){s+=s;}}";
        with_tree(source, |tree| {
            let index = NodeTextIndex::new(tree, source);
            assert_eq!(index.for_statement_ranges().unwrap().len(), 2);
            let query = Query::new(&tree.language(), QUERY).unwrap();
            let gates = RequiredSubqueries::of(&tree.language(), &query, QUERY);
            let mut enabled = vec![true];
            gates.prune_indexed(tree, source, &index, &mut enabled, None, None);
            assert_eq!(enabled, [true]);
            let mut cursor = QueryCursor::new();
            assert!(
                cursor
                    .matches(&query, tree.root_node(), source.as_bytes())
                    .next()
                    .is_some()
            );
        });
    }
}
