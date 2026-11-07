#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;
use crate::composite_rules::context::{ConditionResult, EvaluationContext};
use crate::composite_rules::evaluators::ast::{batch_ast_queries, eval_ast_query_with_mode};
use crate::composite_rules::evaluators::symbol_string::MatchCountGuard;
use crate::composite_rules::types::FileType;
use crate::types::{AnalysisReport, TargetInfo};

/// `micro-behaviors/communications/dns/resolver::dns-destructured-resolve-call`:
/// a wildcard root and first child, a quantified alternation between
/// anchors, and literals at two depths.
const DESTRUCTURED_RESOLVE: &str = r#"((_
  (_ (variable_declarator
    name: (object_pattern [
      (shorthand_property_identifier_pattern) @api @bound
      (pair_pattern key: (property_identifier) @api
        value: (identifier) @bound)])
    value: (call_expression function: (identifier) @require
      arguments: (arguments (string (string_fragment) @library)))))
  .
  [(lexical_declaration) (variable_declaration)]*
  .
  (expression_statement (call_expression function: (identifier) @called)))
  (#eq? @require "require")
  (#match? @library "^(node:)?dns$")
  (#eq? @api "resolve")
  (#eq? @bound @called))"#;

/// The shapes anchoring must agree with the whole-tree walk on, each with
/// the match count the fixture below holds.
const EQUIVALENCE_QUERIES: &[(&str, usize)] = &[
    (DESTRUCTURED_RESOLVE, 4),
    // Leaf capture, exact literal.
    (
        "((call_expression function: (member_expression object: (identifier) @o property: (property_identifier) @p)) (#eq? @o \"JSON\") (#eq? @p \"stringify\"))",
        3,
    ),
    // Non-leaf capture: the literal spans a member expression.
    (
        "((call_expression function: (member_expression) @m) (#eq? @m \"JSON.stringify\"))",
        3,
    ),
    // Case-folded regex literal.
    (
        "((string (string_fragment) @s) (#match? @s \"(?i)secret\"))",
        2,
    ),
    // One capture at two depths across a root alternation.
    (
        "([(call_expression function: (identifier) @f) (expression_statement (call_expression function: (identifier) @f))] (#eq? @f \"run\"))",
        4,
    ),
    // Two patterns, each anchored on its own literal.
    (
        "((call_expression function: (identifier) @f) (#eq? @f \"run\")) ((new_expression constructor: (identifier) @c) (#eq? @c \"Worker\"))",
        3,
    ),
    // Roots of one kind nested inside each other.
    (
        "((call_expression function: (identifier) @f arguments: (arguments (call_expression))) (#eq? @f \"wrap\"))",
        2,
    ),
    // A quantified capture every match binds at least once.
    (
        "((array (string (string_fragment) @item)+) (#eq? @item \"k\"))",
        2,
    ),
    // Literals that also occur in comments, on the comment-masked tree.
    (
        "((call_expression function: (identifier) @f) (#eq? @f \"run\") (#set! cleave.ignore-comments \"true\"))",
        2,
    ),
    (
        "((new_expression constructor: (identifier) @c) (#eq? @c \"Worker\") (#set! cleave.ignore-comments \"true\"))",
        1,
    ),
    // A wildcard parent with a concrete first child: tree-sitter starts it at
    // the child, so its runs start one level down under a root check.
    (
        "((_ (lexical_declaration (variable_declarator name: (identifier) @n)) . (expression_statement (call_expression function: (identifier) @f))) (#eq? @f \"fire\"))",
        5,
    ),
    // The same with an alternation as the first child.
    (
        "((_ [(lexical_declaration (variable_declarator name: (identifier) @n)) (variable_declaration (variable_declarator name: (identifier) @n))] . (expression_statement (call_expression function: (identifier) @f))) (#eq? @f \"fire\"))",
        6,
    ),
    // A rooted pattern beside a child-started one: runs start one level down,
    // so the rooted pattern is reached at a nested block (`m`'s inner block,
    // a root itself, is a direct child of its body, another root) from its
    // parent's run too, and the root check keeps it from counting there.
    (
        "((statement_block (expression_statement (call_expression function: (identifier) @g))) (#eq? @g \"fire\")) ((_ (lexical_declaration (variable_declarator name: (identifier) @n)) . (expression_statement (call_expression function: (identifier) @f))) (#eq? @f \"fire\"))",
        12,
    ),
    // A child-started pattern sharing its first child's kind with a rooted
    // pattern (micro-behaviors/os/module/require/node.yaml). tree-sitter
    // judged every pattern under a symbol by the first one's start depth,
    // so at a root the rooted pattern was dropped whenever the child-started
    // one could not begin there (fork patch-09).
    (
        r#"((_ (call_expression function: (import) arguments: (arguments (string) @module)) @call) @parent (#not-match? @parent "\\)\\s*\\.") (#match? @module "^[\"']node:vm[\"']$")) ((call_expression function: (member_expression object: (call_expression function: (import) arguments: (arguments (string) @module)))) (#match? @module "^[\"']node:vm[\"']$"))"#,
        2,
    ),
];

const FIXTURE: &str = r#"
const { resolve } = require("dns");
resolve("a.example");
function f() {
  const { resolve: r } = require("node:dns");
  let x = 1;
  r("b.example");
  if (y) { const { resolve } = require("dns"); other(); resolve("c"); }
}
switch (k) { case 1: var { resolve } = require("dns"); resolve("d"); }
class C { static { const { resolve } = require("dns"); resolve("e"); } }
fetch(u, { body: JSON.stringify({ a: JSON.stringify(b) }) });
log(JSON.stringify(z));
const SECRET = "Secret-Token"; log("secret");
run(1); run(run); // run(2) in a comment
new Worker("w.js"); /* new Worker("x.js") */
wrap(wrap(g()));
const keys = ["k", "k", "v"];
const top = 2;
fire(top);
function g() { const w = 1; fire(w); }
function h() { const a = 1; fire(a); if (z) { const b = 2; fire(b); var c = 3; fire(c); } }
function k() { { const q = 1; fire(q); } }
function m() { fire(1); { fire(2); } }
async function n() { await import("node:vm"); }
import("node:vm").then(use);
"#;

fn parsed(source: &str) -> filefacts::ParsedFile<'_> {
    let parsed = filefacts::OpenOptions::new()
        .path(std::path::Path::new("script.js"))
        .open(source.as_bytes());
    let _ = parsed.values();
    parsed
}

fn language() -> Language {
    parsed("x;")
        .source_ast()
        .unwrap()
        .tree
        .language()
        .to_owned()
}

fn evaluate(source: &str, query: &str, per_root: bool) -> ConditionResult {
    let parsed = parsed(source);
    let report = AnalysisReport::new(TargetInfo {
        path: "script.js".into(),
        file_type: "source".into(),
        size_bytes: source.len() as u64,
        sha256: String::new(),
        architectures: None,
    });
    let mut ctx =
        EvaluationContext::test_only_new(&report, source.as_bytes(), FileType::JavaScript);
    ctx.cached_ast = parsed.source_ast().map(|ast| ast.tree);
    eval_ast_query_with_mode(query, &ctx, per_root)
}

/// What a result says, independent of match order.
fn summary(result: &ConditionResult) -> (usize, Vec<(Vec<u64>, String)>, String) {
    let mut evidence: Vec<_> = result
        .evidence
        .iter()
        .map(|e| (e.offsets.clone(), e.value.clone()))
        .collect();
    evidence.sort();
    (
        result.match_count,
        evidence,
        format!("{:?}", result.warnings),
    )
}

#[test]
fn capture_depths_count_named_nodes_only() {
    let shape = capture_depths(DESTRUCTURED_RESOLVE).unwrap();
    assert_eq!(shape.root, Some("_"));
    let depths = shape.depths;
    // Root `_` 0, declaration 1, declarator 2, call 3, callee 4, arguments 4,
    // string 5, fragment 6: fields, groups and alternations add no level.
    assert_eq!(depths["require"].as_deref(), Some(&[4][..]));
    assert_eq!(depths["library"].as_deref(), Some(&[6][..]));
    assert_eq!(depths["called"].as_deref(), Some(&[3][..]));
    // One depth per alternation branch.
    assert_eq!(depths["api"].as_deref(), Some(&[4, 5][..]));
    // A capture on an alternation names no single node.
    let alternation = capture_depths("([(identifier) (number)] @value)").unwrap();
    assert_eq!(alternation.depths["value"], None);
    // Two top-level nodes, or a quantified one, are not one root.
    assert_eq!(alternation.root, None);
    assert_eq!(
        capture_depths("((identifier) @a . (identifier) @b)")
            .unwrap()
            .root,
        None
    );
    assert_eq!(capture_depths("((identifier)+ @a)").unwrap().root, None);
    assert_eq!(
        capture_depths("((call_expression) @c (#eq? @c \"x\"))")
            .unwrap()
            .root,
        Some("call_expression")
    );
    // Unbalanced syntax is not followed.
    assert!(capture_depths("((identifier) @x").is_none());
}

#[test]
fn anchors_need_a_bound_literal_capture_in_every_pattern() {
    let lang = language();
    let anchored = |source: &str| {
        let query = Query::new(&lang, source).unwrap();
        Anchors::of(&lang, &query, source).is_some()
    };
    for (query, _) in EQUIVALENCE_QUERIES {
        assert!(anchored(query), "{query}");
    }
    // No literal predicate, a negated one, a capture-to-capture one.
    assert!(!anchored("(call_expression) @call"));
    assert!(!anchored(
        "((call_expression function: (identifier) @f) (#not-eq? @f \"eval\"))"
    ));
    assert!(!anchored(
        "((call_expression function: (identifier) @f arguments: (arguments (identifier) @a)) (#eq? @f @a))"
    ));
    // A capture a match may leave unbound.
    assert!(!anchored(
        "((call_expression function: (identifier) @f arguments: (arguments (string)? @s)) (#eq? @s \"x\"))"
    ));
    // Different kinds across branches: no single kind to look for.
    assert!(!anchored(
        "([(call_expression function: (identifier) @f) (call_expression function: (member_expression property: (property_identifier) @f))] (#eq? @f \"run\"))"
    ));
    // One pattern without an anchor disqualifies the query.
    assert!(!anchored(
        "((call_expression function: (identifier) @f) (#eq? @f \"eval\")) (new_expression) @n"
    ));
    // Unrooted: a sibling sequence has no single node to start at.
    assert!(!anchored(
        "((identifier) @a . (identifier) @b (#eq? @a \"x\"))"
    ));
    // A wildcard parent whose first child is concrete starts at the child,
    // and is anchored with a root check by its witness capture.
    assert!(anchored(
        "((_ (string (string_fragment) @s)) (#eq? @s \"x\"))"
    ));
    // A repeated wildcard root is not one node.
    assert!(!anchored(
        "((_ (string (string_fragment) @s))+ (#eq? @s \"x\"))"
    ));
}

#[test]
fn occurrences_overlap_and_stop_past_the_limit() {
    let literal: AnyOf = vec![(Box::from(&b"aa"[..]), false)];
    assert_eq!(
        occurrences(&literal, b"aaa", MAX_OCCURRENCES).unwrap(),
        vec![(0, 2), (1, 3)]
    );
    assert!(occurrences(&literal, b"aaa", 1).is_none());
    let folded: AnyOf = vec![(Box::from(&b"dns"[..]), true)];
    assert_eq!(
        occurrences(&folded, b"x DNS dns", MAX_OCCURRENCES)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn rarest_anchor_wins() {
    let lang = language();
    let source = "((call_expression function: (identifier) @f arguments: (arguments (string (string_fragment) @s))) (#eq? @f \"log\") (#eq? @s \"rare\"))";
    let query = Query::new(&lang, source).unwrap();
    let anchors = Anchors::of(&lang, &query, source).unwrap();
    let text = b"log('a'); log('b'); log('rare'); log('c');";
    let (anchor, spans) = rarest(&anchors.patterns[0].anchors, text).unwrap();
    assert_eq!(spans, vec![(25, 29)]);
    assert_eq!(&*anchor.literals[0].0, b"rare");
}

/// The cursor descent yields, for every occurrence in ascending order, the
/// same ancestor chain as `Node::parent` from the smallest spanning node:
/// across siblings, back up out of nested blocks, and through gaps.
#[test]
fn descent_matches_parent_chains() {
    let source = FIXTURE.repeat(3);
    let parsed = parsed(&source);
    let tree = parsed.source_ast().unwrap().tree;
    let top = tree.root_node();
    let mut spans = Vec::new();
    let mut walk = top.walk();
    'nodes: loop {
        let node = walk.node();
        if node.child_count() == 0 && node.end_byte() > node.start_byte() {
            spans.push((node.start_byte(), node.end_byte()));
        }
        if walk.goto_first_child() {
            continue;
        }
        loop {
            if walk.goto_next_sibling() {
                continue 'nodes;
            }
            if !walk.goto_parent() {
                break 'nodes;
            }
        }
    }
    // Spans inside one token, and ones crossing two, as well as whole leaves.
    let extra: Vec<_> = spans
        .iter()
        .flat_map(|&(s, e)| [(s, s + 1), (s, (e + 3).min(source.len()))])
        .collect();
    spans.extend(extra);
    spans.sort_unstable();
    let mut descent = Descent::new(top);
    for (start, end) in spans {
        let mut expected = Vec::new();
        let mut node = top.descendant_for_byte_range(start, end);
        while let Some(current) = node {
            expected.push(current.id());
            node = current.parent();
        }
        expected.reverse();
        let got: Vec<_> = descent
            .to(start, end)
            .unwrap()
            .iter()
            .map(Node::id)
            .collect();
        assert_eq!(got, expected, "span {start}..{end}");
    }
}

/// Anchored runs find exactly the whole-tree walk's matches: same count,
/// same evidence, same warnings.
#[test]
fn anchored_queries_match_the_whole_tree_walk() {
    let _count = MatchCountGuard::set(true);
    let parsed = parsed(FIXTURE);
    let tree = parsed.source_ast().unwrap().tree;
    let lang = tree.language().to_owned();
    for &(query, expected) in EQUIVALENCE_QUERIES {
        let compiled = Query::new(&lang, query).unwrap();
        let anchors = Anchors::of(&lang, &compiled, query).unwrap();
        assert!(anchors.roots(tree, FIXTURE.as_bytes()).is_some(), "{query}");

        let whole = evaluate(FIXTURE, query, false);
        assert_eq!(whole.match_count, expected, "{query}");
        assert_eq!(
            summary(&whole),
            summary(&evaluate(FIXTURE, query, true)),
            "{query}"
        );
    }
}

/// The shared batch, whose anchored queries sit out the walk and run after
/// it at their roots, answers every query as its own whole-tree walk does.
#[test]
fn batch_with_anchored_queries_matches_whole_tree_walks() {
    let _count = MatchCountGuard::set(true);
    // Small enough that no query's evidence reaches its cap, so the evidence
    // itself is comparable regardless of match order.
    let source = FIXTURE;
    let parsed = parsed(source);
    let tree = parsed.source_ast().unwrap().tree;
    let mut queries: Vec<&str> = EQUIVALENCE_QUERIES.iter().map(|(q, _)| *q).collect();
    // Walked beside the anchored ones.
    queries.push("(call_expression function: (identifier) @any)");
    queries.push("((identifier) @i (#match? @i \"^re\"))");
    let batch = batch_ast_queries(tree, source, FileType::JavaScript, &queries, None, None)
        .expect("batched");
    for query in queries {
        let whole = evaluate(source, query, false);
        let batched = batch.get(query).expect(query);
        assert!(whole.matched, "fixture exercises {query}");
        assert_eq!(summary(&whole).0, summary(batched).0, "{query}");
        assert_eq!(summary(&whole).1, summary(batched).1, "{query}");
    }
}

/// A deeply nested tree still gets the whole-tree walk's answer, anchored or
/// (past the descent budget) not.
#[test]
fn deep_tree_matches_the_whole_tree_walk() {
    let _count = MatchCountGuard::set(true);
    let depth = 2000;
    let mut source = String::new();
    for _ in 0..depth {
        source.push_str("run(");
    }
    source.push('0');
    for _ in 0..depth {
        source.push(')');
    }
    source.push_str(";\n");
    let query = "((call_expression function: (identifier) @f) (#eq? @f \"run\"))";
    let whole = evaluate(&source, query, false);
    assert_eq!(whole.match_count, depth);
    assert_eq!(summary(&whole), summary(&evaluate(&source, query, true)));
}
