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

#[path = "ast_loop_gate.rs"]
mod loop_gate;
pub(super) use loop_gate::RequiredSubqueries;

#[path = "ast_anchor.rs"]
mod anchor;
pub(super) use anchor::{Anchors, enabled as anchors_enabled};

/// Compound text checks may run after structural matching only when a
/// mandatory scalar capture inside that same node provides early pruning.
/// Unguarded joins (for example mkfifo-command regexes) must keep their early
/// checks, or unrelated sibling commands create combinatorial search states.
#[derive(Default)]
pub(super) struct DeferredPredicates(Vec<rustc_hash::FxHashSet<u32>>);

impl DeferredPredicates {
    pub(super) fn of(query: &Query, source: &str) -> Self {
        Self(
            (0..query.pattern_count())
                .map(|pattern| {
                    let text = source
                        .get(
                            query.start_byte_for_pattern(pattern)
                                ..query.end_byte_for_pattern(pattern),
                        )
                        .unwrap_or_default();
                    let tokens = query_token_spans(text);
                    let mut stack = Vec::new();
                    let mut captures = Vec::new();
                    for (i, &(token, _, _)) in tokens.iter().enumerate() {
                        match token {
                            "(" | "[" => stack.push(i),
                            ")" | "]" => {
                                let Some(open) = stack.pop() else {
                                    return Default::default();
                                };
                                if token != ")" {
                                    continue;
                                }
                                let kind = tokens.get(open + 1).map_or("", |t| t.0);
                                let mut after = i + 1;
                                while let Some(name) =
                                    tokens.get(after).and_then(|t| t.0.strip_prefix('@'))
                                {
                                    captures.push((name, kind, open, i));
                                    after += 1;
                                }
                            }
                            _ => {}
                        }
                    }
                    let positive: rustc_hash::FxHashSet<_> = positive_text_predicates(text)
                        .into_iter()
                        .map(|(_, capture, _)| capture)
                        .collect();
                    let scalar: Vec<_> = captures
                        .iter()
                        .filter(|(name, kind, _, _)| {
                            indexed_kind(kind)
                                && positive.contains(name)
                                && query.capture_index_for_name(name).is_some_and(|id| {
                                    query.capture_quantifiers(pattern).get(id as usize)
                                        == Some(&CaptureQuantifier::One)
                                })
                        })
                        .collect();
                    captures
                        .iter()
                        .filter(|(_, kind, open, close)| {
                            matches!(
                                *kind,
                                "pipeline"
                                    | "command"
                                    | "redirected_statement"
                                    | "compound_statement"
                            ) && scalar.iter().any(|(_, _, child_open, child_close)| {
                                child_open > open && child_close < close
                            })
                        })
                        .filter_map(|(name, _, _, _)| query.capture_index_for_name(name))
                        .collect()
                })
                .collect(),
        )
    }

    pub(super) fn contains(&self, pattern: usize, capture: u32) -> bool {
        self.0
            .get(pattern)
            .is_some_and(|captures| captures.contains(&capture))
    }
}

/// One requirement of a pattern: at least one of these literals occurs in
/// every match, each flagged when it is to be found ASCII-case-insensitively.
type AnyOf = Vec<(Box<[u8]>, bool)>;

/// Per pattern, the literal requirements every match of that pattern meets.
#[derive(Debug, Default)]
pub(crate) struct RequiredLiterals(Vec<Vec<AnyOf>>);

/// Whether `source` holds `literal`, ASCII-case-insensitively when `ci`.
pub(crate) fn source_contains(source: &[u8], literal: &[u8], ci: bool) -> bool {
    if !ci {
        return memchr::memmem::find(source, literal).is_some();
    }
    aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build([literal])
        // An automaton that cannot be built cannot prove absence.
        .map_or(true, |ac| ac.is_match(source))
}

/// The literals every match of `regex` contains, any one of which suffices:
/// its mandatory atoms (anywhere in a match, through alternations and
/// `(?i)`), or else its guaranteed prefix (>= 3 bytes).
///
/// The atoms are derived for `type: text`'s engine, which folds the case of
/// an ASCII pattern within ASCII. Tree-sitter's `#match?` and simple mode
/// compile with Unicode folding, where `k` also matches the Kelvin sign and
/// `s` the long s, so a case-insensitive atom is cut down to its longest run
/// free of either letter.
pub(crate) fn regex_requirement(regex: &str) -> Option<AnyOf> {
    // A pure function of the pattern text, re-asked by the simple-mode gate
    // on every file a `regex:` AST trait applies to: without the memo,
    // `extract_regex_literal` re-parsed (and Unicode case-folded) the same
    // few hundred patterns once per member, 8 s of a 3,300-member wheel's
    // 310 CPU-s. Distinct patterns are bounded by the rule set.
    static MEMO: std::sync::OnceLock<
        parking_lot::RwLock<rustc_hash::FxHashMap<Box<str>, Option<AnyOf>>>,
    > = std::sync::OnceLock::new();
    let memo = MEMO.get_or_init(Default::default);
    if let Some(hit) = memo.read().get(regex) {
        return hit.clone();
    }
    let computed = compute_regex_requirement(regex);
    memo.write()
        .entry(regex.into())
        .or_insert_with(|| computed.clone());
    computed
}

fn compute_regex_requirement(regex: &str) -> Option<AnyOf> {
    let unicode_folded = |atom: String, ci: bool| -> Option<(Box<[u8]>, bool)> {
        if !ci {
            return Some((atom.into_bytes().into_boxed_slice(), false));
        }
        atom.as_bytes()
            .split(|b| matches!(b, b'k' | b'K' | b's' | b'S'))
            .filter(|piece| piece.len() >= 3)
            .max_by_key(|piece| piece.len())
            .map(|piece| (Box::from(piece), true))
    };
    if let Some(atoms) = crate::capabilities::derivation_memo::mandatory_atom_set(regex)
        && let Some(any_of) = atoms
            .into_iter()
            .map(|(atom, ci)| unicode_folded(atom, ci))
            .collect::<Option<AnyOf>>()
    {
        return Some(any_of);
    }
    StringMatchIndex::extract_regex_literal(regex)
        .filter(|literal| !literal.is_empty())
        .map(|literal| vec![(literal.into_bytes().into_boxed_slice(), false)])
}

impl RequiredLiterals {
    /// The stored form, for [`crate::capabilities::derivation_memo`].
    pub(crate) fn to_stored(&self) -> crate::capabilities::derivation_memo::AstLiterals {
        self.0
            .iter()
            .map(|pattern| {
                pattern
                    .iter()
                    .map(|any| any.iter().map(|(l, ci)| (l.to_vec(), *ci)).collect())
                    .collect()
            })
            .collect()
    }

    /// The literals `query`, compiled from `source`, requires of its input.
    ///
    /// Recorded across processes by `derivation_memo`: a change to what this
    /// derives must bump that memo's file version, or a stale record would rule
    /// out a query the new derivation admits.
    pub(crate) fn of(query: &Query, source: &str) -> Self {
        let patterns = (0..query.pattern_count())
            .map(|i| {
                let text = source
                    .get(query.start_byte_for_pattern(i)..query.end_byte_for_pattern(i))
                    .unwrap_or_default();
                let quantifiers = query.capture_quantifiers(i);
                let mut requirements: Vec<AnyOf> = Vec::new();
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
                    let requirement = match op {
                        Op::Eq => (!arg.is_empty())
                            .then(|| vec![(arg.into_bytes().into_boxed_slice(), false)]),
                        Op::Match => regex_requirement(&arg),
                    };
                    if let Some(requirement) = requirement
                        && !requirements.contains(&requirement)
                    {
                        requirements.push(requirement);
                    }
                }
                requirements
            })
            .collect();
        Self(patterns)
    }

    /// Whether some pattern could match input in which `present` reports which
    /// literals occur (the flag asks for an ASCII-case-insensitive search).
    pub(super) fn pattern_may_match(
        &self,
        pattern: usize,
        mut present: impl FnMut(&[u8], bool) -> bool,
    ) -> bool {
        self.0.get(pattern).is_none_or(|requirements| {
            requirements
                .iter()
                .all(|any| any.iter().any(|(l, ci)| present(l, *ci)))
        })
    }

    pub(crate) fn may_match(&self, mut present: impl FnMut(&[u8], bool) -> bool) -> bool {
        self.0.is_empty()
            || self.0.iter().any(|requirements| {
                requirements
                    .iter()
                    .all(|any| any.iter().any(|(l, ci)| present(l, *ci)))
            })
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
    let end = s
        .find(|c: char| !(c.is_alphanumeric() || matches!(c, '_' | '-' | '.')))
        .unwrap_or(s.len());
    let (capture, s) = s.split_at(end);
    if capture.is_empty() {
        return None;
    }
    let (arg, s) = string_literal(skip_whitespace(s))?;
    let s = skip_whitespace(s).strip_prefix(')')?;
    Some(((op, capture, arg), s))
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
    Present,
    Exact(String),
    Regex(regex::bytes::Regex),
}

/// Complete raw capture text, collected during the existing AST facts walk.
/// Display evidence is truncated and decoded literals lose source spelling;
/// neither can prove that a Tree-sitter capture is absent.
#[derive(Debug, Default)]
pub(crate) struct NodeTextIndex(
    rustc_hash::FxHashMap<String, rustc_hash::FxHashSet<Box<str>>>,
    rustc_hash::FxHashSet<Box<str>>,
    Vec<std::ops::Range<usize>>,
    bool,
    /// Deepest nesting the walk that filled this index saw (root = 0).
    u32,
);

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
    pub(crate) fn finish(&mut self) {
        self.3 = true;
    }
    /// Note a node at `depth` below the root; the deepest is kept.
    pub(crate) fn note_depth(&mut self, depth: u32) {
        self.4 = self.4.max(depth);
    }
    /// Deepest nesting of the tree this index was built from (root = 0).
    pub(crate) fn max_depth(&self) -> u32 {
        self.4
    }
    pub(super) fn for_statement_ranges(&self) -> Option<&[std::ops::Range<usize>]> {
        self.3.then_some(&self.2)
    }

    pub(crate) fn record_node(&mut self, node: &tree_sitter::Node<'_>, source: &[u8]) {
        if node.kind() == "for_statement" {
            self.2.push(node.byte_range());
        }
        if !self.1.contains(node.kind()) {
            self.1.insert(node.kind().into());
        }
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
        let mut depth: u32 = 0;
        loop {
            let node = cursor.node();
            values.record_node(&node, source.as_bytes());
            if cursor.goto_first_child() {
                depth += 1;
                values.note_depth(depth);
                continue;
            }
            loop {
                if cursor.goto_next_sibling() {
                    break;
                }
                if !cursor.goto_parent() {
                    values.finish();
                    return values;
                }
                depth -= 1;
            }
        }
    }
}

impl RequiredNodes {
    pub(super) fn of(language: &tree_sitter::Language, query: &Query, source: &str) -> Self {
        Self(
            (0..query.pattern_count())
                .map(|i| {
                    let text = source
                        .get(query.start_byte_for_pattern(i)..query.end_byte_for_pattern(i))
                        .unwrap_or_default();
                    let kinds = capture_node_kinds(text);
                    let quantifiers = query.capture_quantifiers(i);
                    let mut predicates: Vec<_> = positive_text_predicates(text)
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
                            if !indexed_kind(kind) {
                                return None;
                            }
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
                        .collect();
                    for (&capture, &kind) in &kinds {
                        let Some(kind) = kind else { continue };
                        if kind == "pair:key" || kind == "_" {
                            continue;
                        }
                        let id = language.id_for_node_kind(kind, true);
                        if language.node_kind_for_id(id) != Some(kind)
                            || language.node_kind_is_supertype(id)
                        {
                            continue;
                        }
                        let required = query.capture_index_for_name(capture).is_some_and(|c| {
                            matches!(
                                quantifiers.get(c as usize),
                                Some(CaptureQuantifier::One | CaptureQuantifier::OneOrMore)
                            )
                        });
                        if required {
                            predicates.push(NodePredicate {
                                kind: kind.to_owned(),
                                predicate: NodePredicateValue::Present,
                            });
                        }
                    }
                    for kind in required_node_kinds(text) {
                        let id = language.id_for_node_kind(kind, true);
                        if language.node_kind_for_id(id) == Some(kind)
                            && !language.node_kind_is_supertype(id)
                        {
                            predicates.push(NodePredicate {
                                kind: kind.to_owned(),
                                predicate: NodePredicateValue::Present,
                            });
                        }
                    }
                    // Cheap structural absence should avoid searching every
                    // indexed value for a regex the file cannot satisfy.
                    predicates.sort_by_key(|p| match p.predicate {
                        NodePredicateValue::Present => 0,
                        NodePredicateValue::Exact(_) => 1,
                        NodePredicateValue::Regex(_) => 2,
                    });
                    predicates
                })
                .collect(),
        )
    }

    pub(super) fn may_match(&self, index: &NodeTextIndex) -> bool {
        self.0.is_empty() || (0..self.0.len()).any(|pattern| self.pattern_may_match(pattern, index))
    }

    pub(super) fn pattern_may_match(&self, pattern: usize, index: &NodeTextIndex) -> bool {
        self.0.get(pattern).is_none_or(|pattern| {
            pattern.iter().all(|p| {
                if matches!(p.predicate, NodePredicateValue::Present) {
                    return index.1.contains(p.kind.as_str());
                }
                let Some(values) = index.0.get(p.kind.as_str()) else {
                    return false;
                };
                match &p.predicate {
                    NodePredicateValue::Present => true,
                    NodePredicateValue::Exact(value) => values.contains(value.as_str()),
                    NodePredicateValue::Regex(regex) => {
                        values.iter().any(|v| regex.is_match(v.as_bytes()))
                    }
                }
            })
        })
    }
}

/// Recognize named-node captures, including nodes with children. Text gates
/// use only the small kinds we index; other kinds can prove structural absence.
/// If the same capture occurs in an alternative shape, abandon its restriction. Predicates, comments and
/// quoted node names are not capture declarations. Unknown syntax means less
/// pruning, never a stronger claim about what the query can match.
pub(super) fn query_tokens(source: &str) -> Vec<&str> {
    query_token_spans(source)
        .into_iter()
        .map(|(token, _, _)| token)
        .collect()
}

fn query_token_spans(source: &str) -> Vec<(&str, usize, usize)> {
    let mut tokens = Vec::new();
    let mut rest = source;
    while !rest.is_empty() {
        rest = skip_whitespace(rest);
        if rest.is_empty() {
            break;
        }
        let start = source.len() - rest.len();
        if rest.starts_with('"') {
            let Some((_, after)) = string_literal(rest) else {
                return Default::default();
            };
            tokens.push(("\"", start, source.len() - after.len()));
            rest = after;
        } else if matches!(
            rest.as_bytes()[0],
            b'(' | b')' | b'[' | b']' | b'?' | b'*' | b'+'
        ) {
            tokens.push((&rest[..1], start, start + 1));
            rest = &rest[1..];
        } else {
            let end = rest
                .find(|c: char| c.is_whitespace() || "()[]?*+\";".contains(c))
                .unwrap_or(rest.len());
            if end == 0 {
                return Default::default();
            }
            tokens.push((&rest[..end], start, start + end));
            rest = &rest[end..];
        }
    }
    tokens
}

/// The named node kind each pattern of `source` is rooted at, when every
/// pattern is one node pattern, optionally captured and optionally grouped
/// with predicates, as in `(call_expression ...) @call` or
/// `((identifier) @id (#match? @id "x"))`. Such a query can run once per node
/// of those kinds instead of once over the whole tree (see
/// `eval_ast_query_once`). `None` for anything else -- sibling patterns,
/// alternation or wildcard roots, anonymous roots, quantified roots -- and
/// for syntax this reader does not understand: unknown shapes get the whole
/// tree walk, never a root set that could miss a match.
pub(super) fn pattern_root_kinds(source: &str) -> Option<Vec<&str>> {
    let tokens = query_tokens(source);
    if tokens.is_empty() {
        return None;
    }
    let mut closes = vec![usize::MAX; tokens.len()];
    let mut stack = Vec::new();
    for (i, &token) in tokens.iter().enumerate() {
        match token {
            "(" | "[" => stack.push(i),
            ")" | "]" => closes[stack.pop()?] = i,
            _ => {}
        }
    }
    if !stack.is_empty() {
        return None;
    }
    // A pattern's optional captures, then a quantifier that would make it
    // a sibling sequence rather than one node.
    let after_captures = |mut i: usize| {
        while tokens.get(i).is_some_and(|t| t.starts_with('@')) {
            i += 1;
        }
        i
    };
    let quantified = |i: usize| matches!(tokens.get(i), Some(&"?" | &"*" | &"+"));
    fn root_of_list<'a>(
        tokens: &[&'a str],
        closes: &[usize],
        open: usize,
        after_captures: &dyn Fn(usize) -> usize,
        quantified: &dyn Fn(usize) -> bool,
    ) -> Option<&'a str> {
        let head = *tokens.get(open + 1)?;
        if head != "(" {
            return (head != "_"
                && !head.is_empty()
                && head.chars().all(|c| c.is_alphanumeric() || c == '_'))
            .then_some(head);
        }
        // A group: exactly one node pattern beside its predicates.
        let close = closes[open];
        let mut root = None;
        let mut i = open + 1;
        while i < close {
            let token = tokens[i];
            if token == "(" {
                let inner_close = closes[i];
                if tokens.get(i + 1).is_some_and(|t| t.starts_with('#')) {
                    i = inner_close + 1;
                    continue;
                }
                if root.is_some() {
                    return None;
                }
                root = Some(root_of_list(tokens, closes, i, after_captures, quantified)?);
                i = after_captures(inner_close + 1);
                if quantified(i) {
                    return None;
                }
                continue;
            }
            return None;
        }
        root
    }
    let mut kinds = Vec::new();
    let mut i = 0;
    while i < tokens.len() {
        if tokens[i] != "(" {
            return None;
        }
        kinds.push(root_of_list(
            &tokens,
            &closes,
            i,
            &after_captures,
            &quantified,
        )?);
        i = after_captures(closes[i] + 1);
        if quantified(i) {
            return None;
        }
    }
    Some(kinds)
}

/// Necessary named node kinds, even when the query does not capture them.
/// Alternatives and optional/repeated subtrees contribute no requirements;
/// unknown node names and supertypes are rejected against the grammar above.
fn required_node_kinds(source: &str) -> rustc_hash::FxHashSet<&str> {
    let tokens = query_tokens(source);
    let mut closes = vec![None; tokens.len()];
    let mut stack = Vec::new();
    for (i, &token) in tokens.iter().enumerate() {
        match token {
            "(" | "[" => stack.push(i),
            ")" | "]" => {
                let Some(open) = stack.pop() else {
                    return Default::default();
                };
                closes[open] = Some(i);
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Default::default();
    }
    let optional = |open: usize| {
        let Some(close) = closes[open] else {
            return true;
        };
        let mut after = close + 1;
        while tokens
            .get(after)
            .is_some_and(|t| t.starts_with('@') || *t == "+")
        {
            after += 1;
        }
        matches!(tokens.get(after), Some(&"?" | &"*"))
    };
    let mut kinds = rustc_hash::FxHashSet::default();
    // Each stack entry says whether this subtree can prove a requirement.
    let mut required = Vec::new();
    for (i, &token) in tokens.iter().enumerate() {
        match token {
            "(" | "[" => {
                let kind = tokens.get(i + 1).copied().unwrap_or_default();
                let active = required.last().copied().unwrap_or(true)
                    && token == "("
                    && !kind.starts_with('#')
                    && !optional(i);
                required.push(active);
                if active
                    && kind != "_"
                    && !kind.is_empty()
                    && kind.chars().all(|c| c.is_alphanumeric() || c == '_')
                {
                    kinds.insert(kind);
                }
            }
            ")" | "]" => {
                required.pop();
            }
            _ => {}
        }
    }
    kinds
}

fn capture_node_kinds(source: &str) -> rustc_hash::FxHashMap<&str, Option<&str>> {
    let tokens = query_tokens(source);
    let mut kinds = rustc_hash::FxHashMap::default();
    let mut predicates = Vec::new();
    let mut opens = Vec::new();
    let mut matching_open = rustc_hash::FxHashMap::default();
    for (i, token) in tokens.iter().enumerate() {
        if *token == "(" {
            opens.push(i);
            predicates.push(
                predicates.last().copied().unwrap_or(false)
                    || tokens.get(i + 1).is_some_and(|t| t.starts_with('#')),
            );
        } else if *token == ")" {
            if let Some(open) = opens.pop() {
                matching_open.insert(i, open);
            }
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
            } else if j > 0 && tokens[j - 1] == ")" {
                matching_open.get(&(j - 1)).and_then(|&open| {
                    tokens.get(open + 1).copied().filter(|kind| {
                        !kind.is_empty() && kind.chars().all(|c| c.is_alphanumeric() || c == '_')
                    })
                })
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
