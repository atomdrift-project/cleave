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
