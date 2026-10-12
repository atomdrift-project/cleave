//! Literal gate for tree-sitter queries.
//!
//! A query cursor enumerates sibling alignments before it checks a single text
//! predicate, so on a minified bundle a query whose
//! `(#match? @v "Invalid seed phrase")` can never hold still walks until the CPU
//! budget stops it — 30 s, several times over, on one 7.7 MB VS Code extension
//! bundle. A positive `#eq?` or `#match?` on a capture that every match binds
//! names bytes the file must contain; when the file lacks them no match is
//! possible, and the walk is skipped.
//!
//! The gate is sound by reading less, never more: any predicate this scanner
//! does not fully understand contributes no literal, which costs only a skip
//! that did not happen.

use crate::capabilities::indexes::StringMatchIndex;
use tree_sitter::{CaptureQuantifier, Query};

/// Per pattern, the literals every match of that pattern contains.
#[derive(Debug, Default)]
pub(crate) struct RequiredLiterals(Vec<Vec<Box<[u8]>>>);

impl RequiredLiterals {
    /// The literals `query`, compiled from `source`, requires of its input.
    pub(crate) fn of(query: &Query, source: &str) -> Self {
        let patterns = (0..query.pattern_count())
            .map(|i| {
                let text = source
                    .get(query.start_byte_for_pattern(i)..query.end_byte_for_pattern(i))
                    .unwrap_or_default();
                let quantifiers = query.capture_quantifiers(i);
                let mut literals: Vec<Box<[u8]>> = Vec::new();
                for (op, capture, arg) in positive_text_predicates(text) {
                    // A capture a match may leave unbound passes its predicate
                    // vacuously, so only always-bound captures carry a literal.
                    let bound = query.capture_index_for_name(capture).is_some_and(|c| {
                        matches!(
                            quantifiers.get(c as usize),
                            Some(CaptureQuantifier::One | CaptureQuantifier::OneOrMore)
                        )
                    });
                    if !bound {
                        continue;
                    }
                    let literal = match op {
                        Op::Eq => Some(arg),
                        // A guaranteed prefix of every regex match (>= 3 bytes).
                        Op::Match => StringMatchIndex::extract_regex_literal(&arg),
                    };
                    if let Some(literal) = literal
                        && !literal.is_empty()
                        && !literals.iter().any(|l| **l == *literal.as_bytes())
                    {
                        literals.push(literal.into_bytes().into_boxed_slice());
                    }
                }
                literals
            })
            .collect();
        Self(patterns)
    }

    /// Whether some pattern could match input in which `present` reports which
    /// literals occur.
    pub(crate) fn may_match(&self, mut present: impl FnMut(&[u8]) -> bool) -> bool {
        self.0.is_empty()
            || self
                .0
                .iter()
                .any(|literals| literals.iter().all(|l| present(l)))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Eq,
    Match,
}

/// Every `(#eq? @capture "literal")` and `(#match? @capture "regex")` in one
/// pattern's source, with the string argument unescaped as tree-sitter does.
/// Negated and `any-` forms, capture or bare-symbol arguments, and anything
/// malformed are not requirements and are skipped.
fn positive_text_predicates(mut rest: &str) -> Vec<(Op, &str, String)> {
    let mut out = Vec::new();
    while let Some(c) = rest.chars().next() {
        match c {
            ';' => rest = rest.find('\n').map_or("", |i| &rest[i..]),
            // Strings outside predicates (anonymous nodes such as `"("`) are
            // skipped whole so their contents are never read as syntax.
            '"' => match string_literal(rest) {
                Some((_, after)) => rest = after,
                None => break,
            },
            '(' => {
                rest = &rest[1..];
                if let Some((predicate, after)) = predicate(rest) {
                    out.push(predicate);
                    rest = after;
                }
            }
            _ => rest = &rest[c.len_utf8()..],
        }
    }
    out
}

/// One predicate body following its `(`.
fn predicate(s: &str) -> Option<((Op, &str, String), &str)> {
    let s = skip_whitespace(s).strip_prefix('#')?;
    let (op, s) = if let Some(s) = s.strip_prefix("eq?") {
        (Op::Eq, s)
    } else {
        (Op::Match, s.strip_prefix("match?")?)
    };
    let s = skip_whitespace(s).strip_prefix('@')?;
    let end = s.find(|c: char| !is_identifier_char(c)).unwrap_or(s.len());
    let (capture, s) = s.split_at(end);
    if capture.is_empty() {
        return None;
    }
    let (arg, s) = string_literal(skip_whitespace(s))?;
    let s = skip_whitespace(s).strip_prefix(')')?;
    Some(((op, capture, arg), s))
}

/// tree-sitter's `stream_scan_identifier` alphabet.
fn is_identifier_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '.')
}

/// Whitespace and `;` line comments, as tree-sitter's `stream_skip_whitespace`.
fn skip_whitespace(mut s: &str) -> &str {
    loop {
        s = s.trim_start();
        match s.strip_prefix(';') {
            Some(comment) => s = comment.find('\n').map_or("", |i| &comment[i..]),
            None => return s,
        }
    }
}

/// A `"…"` literal at the start of `s`, unescaped as tree-sitter's
/// `ts_query__parse_string_literal` does, and the text after it. `None` for an
/// unterminated literal, which tree-sitter rejects, as it does a raw newline.
fn string_literal(s: &str) -> Option<(String, &str)> {
    let body = s.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = body.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((out, &body[i + 1..])),
            '\n' => return None,
            '\\' => out.push(match chars.next()?.1 {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                '0' => '\0',
                other => other,
            }),
            _ => out.push(c),
        }
    }
    None
}

/// Necessary capture predicates, checked against node text before enumerating
/// sibling alignments. Raw text alone admits `http` inside a comment or string
/// for a query that requires an identifier named `http`.
#[derive(Default)]
pub(super) struct RequiredNodes(Vec<Vec<NodePredicate>>);

struct NodePredicate {
    kind: String,
    predicate: NodePredicateValue,
}

enum NodePredicateValue {
    Exact(String),
    Regex(regex::bytes::Regex),
}

/// Complete raw capture text, collected during the existing AST facts walk.
/// Display evidence is truncated and decoded literals lose source spelling;
/// neither can prove that a Tree-sitter capture is absent.
#[derive(Debug, Default)]
pub(crate) struct NodeTextIndex(rustc_hash::FxHashMap<String, rustc_hash::FxHashSet<Box<str>>>);

fn indexed_kind(kind: &str) -> bool {
    matches!(
        kind,
        "pair:key" // synthetic domain: complete text of object keys
            | "identifier"
            | "property_identifier"
            | "field_identifier"
            | "type_identifier"
            | "string_fragment"
            | "string"
            | "string_literal"
            | "number"
            | "integer"
            | "simple_name"
            | "bare_word"
            | "command_name"
    )
}

impl NodeTextIndex {
    pub(crate) fn record_node(&mut self, node: &tree_sitter::Node<'_>, source: &[u8]) {
        // A wildcard object-key capture can be any node kind, including a
        // quoted or computed key. Index the entire field, never a decoded or
        // truncated spelling, so absence is a sound negative even for `_`.
        if node.kind() == "pair"
            && let Some(key) = node.child_by_field_name("key")
            && let Ok(text) = key.utf8_text(source)
        {
            self.record("pair:key", text);
        }
        if indexed_kind(node.kind())
            && let Ok(text) = node.utf8_text(source)
        {
            self.record(node.kind(), text);
        }
    }

    pub(crate) fn record(&mut self, kind: &str, text: &str) {
        if !indexed_kind(kind) {
            return;
        }
        if let Some(values) = self.0.get_mut(kind) {
            if !values.contains(text) {
                values.insert(text.into());
            }
        } else {
            self.0
                .entry(kind.to_owned())
                .or_default()
                .insert(text.into());
        }
    }

    pub(super) fn new(tree: &tree_sitter::Tree, source: &str) -> Self {
        let mut values = Self::default();
        let mut cursor = tree.walk();
        loop {
            let node = cursor.node();
            values.record_node(&node, source.as_bytes());
            if cursor.goto_first_child() {
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    return values;
                }
            }
        }
    }
}

impl RequiredNodes {
    pub(super) fn of(query: &Query, source: &str) -> Self {
        Self(
            (0..query.pattern_count())
                .map(|i| {
                    let text = source
                        .get(query.start_byte_for_pattern(i)..query.end_byte_for_pattern(i))
                        .unwrap_or_default();
                    let kinds = capture_node_kinds(text);
                    let quantifiers = query.capture_quantifiers(i);
                    positive_text_predicates(text)
                        .into_iter()
                        .filter_map(|(op, capture, arg)| {
                            let bound = query.capture_index_for_name(capture).is_some_and(|c| {
                                matches!(
                                    quantifiers.get(c as usize),
                                    Some(CaptureQuantifier::One | CaptureQuantifier::OneOrMore)
                                )
                            });
                            if !bound {
                                return None;
                            }
                            let kind = kinds.get(capture).copied().flatten()?;
                            let predicate = match op {
                                Op::Eq => NodePredicateValue::Exact(arg),
                                // The tree-sitter Rust binding uses this same regex engine
                                // and flags for #match?. Failed compilation cannot gate.
                                Op::Match => {
                                    NodePredicateValue::Regex(regex::bytes::Regex::new(&arg).ok()?)
                                }
                            };
                            Some(NodePredicate {
                                kind: kind.to_owned(),
                                predicate,
                            })
                        })
                        .collect()
                })
                .collect(),
        )
    }

    pub(super) fn may_match(&self, index: &NodeTextIndex) -> bool {
        self.0.is_empty()
            || self.0.iter().any(|pattern| {
                pattern.iter().all(|p| {
                    let Some(values) = index.0.get(p.kind.as_str()) else {
                        return false;
                    };
                    match &p.predicate {
                        NodePredicateValue::Exact(value) => values.contains(value.as_str()),
                        NodePredicateValue::Regex(regex) => {
                            values.iter().any(|v| regex.is_match(v.as_bytes()))
                        }
                    }
                })
            })
    }
}

/// Recognize only `(small_node_kind) @capture`. If the same capture occurs in
/// an alternative shape, abandon its restriction. Predicates, comments and
/// quoted node names are not capture declarations. Unknown syntax means less
/// pruning, never a stronger claim about what the query can match.
fn capture_node_kinds(source: &str) -> rustc_hash::FxHashMap<&str, Option<&str>> {
    let mut tokens = Vec::new();
    let mut rest = source;
    while !rest.is_empty() {
        rest = skip_whitespace(rest);
        if rest.is_empty() {
            break;
        }
        if rest.starts_with('"') {
            let Some((_, after)) = string_literal(rest) else {
                return Default::default();
            };
            tokens.push("\"");
            rest = after;
        } else if matches!(
            rest.as_bytes()[0],
            b'(' | b')' | b'[' | b']' | b'?' | b'*' | b'+'
        ) {
            tokens.push(&rest[..1]);
            rest = &rest[1..];
        } else {
            let end = rest
                .find(|c: char| c.is_whitespace() || "()[]?*+\";".contains(c))
                .unwrap_or(rest.len());
            if end == 0 {
                return Default::default();
            }
            tokens.push(&rest[..end]);
            rest = &rest[end..];
        }
    }
    let mut kinds = rustc_hash::FxHashMap::default();
    let mut predicates = Vec::new();
    let mut opens = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        if *token == "(" {
            opens.push(i);
            predicates.push(
                predicates.last().copied().unwrap_or(false)
                    || tokens.get(i + 1).is_some_and(|t| t.starts_with('#')),
            );
        } else if *token == ")" {
            opens.pop();
            predicates.pop();
        } else if !predicates.last().copied().unwrap_or(false)
            && let Some(capture) = token.strip_prefix('@')
        {
            let mut j = i;
            while j > 0
                && (matches!(tokens[j - 1], "?" | "*" | "+") || tokens[j - 1].starts_with('@'))
            {
                j -= 1;
            }
            let simple_node = j >= 3 && tokens[j - 1] == ")" && tokens[j - 3] == "(";
            let pair_key = simple_node
                && j >= 4
                && tokens[j - 4] == "key:"
                && opens
                    .last()
                    .is_some_and(|&open| tokens.get(open + 1) == Some(&"pair"));
            let kind = if pair_key {
                Some("pair:key")
            } else if simple_node && indexed_kind(tokens[j - 2]) {
                Some(tokens[j - 2])
            } else {
                None
            };
            kinds
                .entry(capture)
                .and_modify(|previous| {
                    if *previous != kind {
                        *previous = None;
                    }
                })
                .or_insert(kind);
        }
    }
    kinds
}
