//! Anchored roots for tree-sitter queries.
//!
//! The literal gate proves a file *can* hold a match, and then the cursor
//! still tries every pattern at every node. On a 2.9 MB bundle that walk costs
//! about a second per query even when the literal a match needs occurs nine
//! times.
//!
//! Query patterns nest only by direct parent and child, so a capture written
//! `d` levels below its pattern's root lies exactly `d` parents below the
//! node that root matches. When every match of a pattern binds a capture of a
//! concrete node kind whose positive `#eq?` or `#match?` requires a literal,
//! the pattern can only match at the `d`-th ancestor of a node of that kind
//! spanning an occurrence of the literal. A capture written at several depths
//! (one per branch of an alternation) places a root at each of them. Running
//! the query at those nodes alone, confined to start there
//! (`max_start_depth` 0), yields exactly the whole-tree walk's matches.
//!
//! Sound by falling back: a pattern without such a capture, a literal that
//! occurs too often, or a descent too long for the budget give `None`, and
//! the caller walks the tree as before. `cleave validate` checks the claim on
//! every fixture (see `eval_ast_query_once`).

use super::{
    AnyOf, Op, capture_node_kinds, positive_text_predicates, query_tokens, regex_requirement,
};
use rustc_hash::FxHashMap;
use std::sync::OnceLock;
use tree_sitter::{CaptureQuantifier, Language, Node, Query, QueryCapture, Tree, TreeCursor};

/// Occurrences of one pattern's anchor literal worth descending to; past
/// this many, the whole-tree walk is as cheap.
const MAX_OCCURRENCES: usize = 4096;
/// Cursor moves one evaluation's descents may take together. A deeply nested
/// tree (thousands of levels in a JSFuck expression) costs a descent of that
/// depth per occurrence, and past this the walk is cheaper.
const MAX_CURSOR_STEPS: usize = 1 << 20;

/// Whether anchored evaluation is on (`CLEAVE_AST_ANCHORS`, default on).
/// Off, every query walks as it did before anchoring: a switch for isolating
/// a suspected anchoring fault, not a tuning knob.
pub(crate) fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| crate::env::bool_var("CLEAVE_AST_ANCHORS").unwrap_or(true))
}

/// A capture that roots its pattern: every match binds a `kind` node holding
/// one of `literals`, at one of `depths` below the pattern's root.
#[derive(Debug)]
struct Anchor {
    kind: u16,
    depths: Box<[u32]>,
    literals: AnyOf,
}

/// One pattern's anchors, and how to confirm a match belongs to a root.
#[derive(Debug)]
struct PatternAnchors {
    /// Every capture that can anchor the pattern.
    anchors: Vec<Anchor>,
    /// A capture every match binds at exactly this many levels below the
    /// pattern's root: walking that far down from a candidate root must reach
    /// it when the match is rooted there.
    witness: Option<(Box<str>, u32)>,
}

/// Per pattern, every capture that can anchor it.
///
/// A rooted pattern starts at its root node, so a run confined to start at a
/// candidate root finds exactly the matches rooted there. A wildcard root
/// whose first child is concrete is started by tree-sitter at that child; its
/// runs start one level down (`start_depth` 1), and since a pattern started
/// one level down may then be rooted at a child rather than at the run's
/// node, every match is confirmed by its pattern's witness capture
/// (`rooted_at`).
#[derive(Debug)]
pub(crate) struct Anchors {
    patterns: Vec<PatternAnchors>,
    child_starts: bool,
}

impl Anchors {
    /// Anchors for `query`, compiled from `source` for `language`; `None`
    /// unless every pattern has one (and, when some pattern starts at a
    /// child, a witness).
    pub(crate) fn of(language: &Language, query: &Query, source: &str) -> Option<Self> {
        let mut child_starts = false;
        let patterns = (0..query.pattern_count())
            .map(|pattern| {
                let text = source.get(
                    query.start_byte_for_pattern(pattern)..query.end_byte_for_pattern(pattern),
                )?;
                let shape = capture_depths(text)?;
                // A sibling sequence has no single node to start at; a wildcard
                // root is started at its first child.
                if !query.is_pattern_rooted(pattern) {
                    if shape.root != Some("_") {
                        return None;
                    }
                    child_starts = true;
                }
                let kinds = capture_node_kinds(text);
                let quantifiers = query.capture_quantifiers(pattern);
                let bound = |capture: &str| {
                    query.capture_index_for_name(capture).is_some_and(|index| {
                        matches!(
                            quantifiers.get(index as usize),
                            Some(CaptureQuantifier::One | CaptureQuantifier::OneOrMore)
                        )
                    })
                };
                let anchors: Vec<Anchor> = positive_text_predicates(text)
                    .into_iter()
                    .filter_map(|(op, capture, arg)| {
                        // An unbound capture passes its predicate vacuously
                        // and places nothing.
                        if !bound(capture) {
                            return None;
                        }
                        let kind = kinds.get(capture).copied().flatten()?;
                        let id = language.id_for_node_kind(kind, true);
                        if language.node_kind_for_id(id) != Some(kind)
                            || language.node_kind_is_supertype(id)
                        {
                            return None;
                        }
                        let literals = match op {
                            Op::Eq => (!arg.is_empty())
                                .then(|| vec![(arg.into_bytes().into_boxed_slice(), false)])?,
                            Op::Match => regex_requirement(&arg)?,
                        };
                        Some(Anchor {
                            kind: id,
                            depths: shape.depths.get(capture)?.clone()?,
                            literals,
                        })
                    })
                    .collect();
                let witness = shape
                    .depths
                    .iter()
                    .filter(|(capture, _)| bound(capture))
                    .filter_map(|(capture, depths)| match depths.as_deref() {
                        Some(&[depth]) => Some((Box::from(*capture), depth)),
                        _ => None,
                    })
                    .min();
                (!anchors.is_empty()).then_some(PatternAnchors { anchors, witness })
            })
            .collect::<Option<Vec<_>>>()?;
        if child_starts && patterns.iter().any(|p| p.witness.is_none()) {
            return None;
        }
        Some(Self {
            patterns,
            child_starts,
        })
    }

    /// The deepest a match may start below each root: `0`, or `1` when some
    /// pattern is started at its root's first child.
    pub(crate) fn start_depth(&self) -> u32 {
        u32::from(self.child_starts)
    }

    /// Whether a match of `pattern` with `captures` is rooted at `root`.
    /// Always so for runs confined to their root; with child starts, the
    /// pattern's witness capture must lie exactly its depth below `root`.
    /// `capture_index` maps a capture name to its index in the query run.
    pub(crate) fn rooted_at(
        &self,
        pattern: usize,
        root: Node<'_>,
        captures: &[QueryCapture<'_>],
        capture_index: impl Fn(&str) -> Option<u32>,
    ) -> bool {
        if !self.child_starts {
            return true;
        }
        let Some((name, depth)) = self.patterns.get(pattern).and_then(|p| p.witness.as_ref())
        else {
            return false;
        };
        let Some(index) = capture_index(name) else {
            return false;
        };
        captures
            .iter()
            .filter(|capture| capture.index == index)
            .any(|capture| {
                let mut node = root;
                for _ in 0..*depth {
                    match node.child_with_descendant(capture.node) {
                        Some(child) => node = child,
                        None => return false,
                    }
                }
                node.id() == capture.node.id()
            })
    }

    /// The nodes every match of the query is rooted at, in document order
    /// with an enclosing root before those inside it; `None` when finding
    /// them would cost about as much as walking the tree.
    pub(crate) fn roots<'t>(&self, tree: &'t Tree, source: &[u8]) -> Option<Vec<Node<'t>>> {
        let mut roots: FxHashMap<usize, Node<'t>> = FxHashMap::default();
        let mut descent = Descent::new(tree.root_node());
        for pattern in &self.patterns {
            let (anchor, mut spans) = rarest(&pattern.anchors, source)?;
            spans.sort_unstable();
            for (start, end) in spans {
                let path = descent.to(start, end)?;
                for (at, node) in path.iter().enumerate() {
                    if node.kind_id() != anchor.kind {
                        continue;
                    }
                    for &depth in &anchor.depths {
                        if let Some(root) = usize::try_from(depth)
                            .ok()
                            .and_then(|depth| at.checked_sub(depth))
                            .and_then(|r| path.get(r))
                        {
                            roots.entry(root.id()).or_insert(*root);
                        }
                    }
                }
            }
        }
        let mut roots: Vec<Node<'t>> = roots.into_values().collect();
        roots.sort_by_key(|node| (node.start_byte(), std::cmp::Reverse(node.end_byte())));
        Some(roots)
    }
}

/// The anchor of one pattern whose literals occur least, with their spans.
/// Counting stops as soon as a candidate passes the best so far, so a common
/// literal costs no more than the rare one that beats it.
fn rarest<'a>(anchors: &'a [Anchor], source: &[u8]) -> Option<(&'a Anchor, Vec<(usize, usize)>)> {
    let mut best: Option<(&Anchor, Vec<(usize, usize)>)> = None;
    for anchor in anchors {
        let limit = best
            .as_ref()
            .map_or(MAX_OCCURRENCES, |(_, kept)| kept.len().saturating_sub(1));
        if let Some(spans) = occurrences(&anchor.literals, source, limit) {
            best = Some((anchor, spans));
        }
        if best.as_ref().is_some_and(|(_, kept)| kept.is_empty()) {
            break;
        }
    }
    best
}

/// Byte spans of every occurrence, overlapping ones included, of any of
/// `literals` in `source`; `None` once there are more than `limit`.
fn occurrences(literals: &AnyOf, source: &[u8], limit: usize) -> Option<Vec<(usize, usize)>> {
    let mut spans = Vec::new();
    for (literal, ci) in literals {
        if *ci {
            let automaton = aho_corasick::AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build([literal.as_ref()])
                .ok()?;
            for found in automaton.find_overlapping_iter(source) {
                spans.push((found.start(), found.end()));
                if spans.len() > limit {
                    return None;
                }
            }
        } else {
            let finder = memchr::memmem::Finder::new(literal.as_ref());
            let mut from = 0;
            while let Some(at) = source.get(from..).and_then(|rest| finder.find(rest)) {
                let start = from + at;
                spans.push((start, start + literal.len()));
                if spans.len() > limit {
                    return None;
                }
                from = start + 1;
            }
        }
    }
    Some(spans)
}

/// The chain of nodes spanning an occurrence, root first, for occurrences
/// visited in ascending order. One cursor serves them all: it backs up only
/// as far as the deepest node still spanning the next occurrence and moves
/// forward through siblings, so a long statement list is crossed once rather
/// than rescanned per occurrence. (`Node::parent` would walk down from the
/// root on every call: tree-sitter keeps no parent pointers.)
struct Descent<'t> {
    top: Node<'t>,
    cursor: TreeCursor<'t>,
    /// The cursor's node and its ancestors, root first.
    path: Vec<Node<'t>>,
    steps: usize,
}

impl<'t> Descent<'t> {
    fn new(top: Node<'t>) -> Self {
        Self {
            top,
            cursor: top.walk(),
            path: vec![top],
            steps: 0,
        }
    }

    /// Every node spanning `start..end`, root first (empty when even the root
    /// does not); `None` once the budget is spent.
    fn to(&mut self, start: usize, end: usize) -> Option<&[Node<'t>]> {
        let spans = |node: &Node<'_>| node.start_byte() <= start && end <= node.end_byte();
        if !spans(&self.top) {
            return Some(&[]);
        }
        // Back up, trying later siblings first: occurrences ascend.
        while let Some(&last) = self.path.last() {
            if spans(&last) {
                break;
            }
            if self.path.len() > 1 && last.end_byte() <= start {
                while self.cursor.goto_next_sibling() {
                    self.steps += 1;
                    if self.cursor.node().end_byte() > start {
                        break;
                    }
                }
                let reached = self.cursor.node();
                if let Some(slot) = self.path.last_mut() {
                    *slot = reached;
                }
                if spans(&reached) {
                    break;
                }
            }
            // The root spans (checked above), so the path never empties.
            self.cursor.goto_parent();
            self.path.pop();
        }
        // Then down to the deepest spanning node.
        while self.cursor.goto_first_child_for_byte(start).is_some() {
            self.steps += 1;
            let child = self.cursor.node();
            if !spans(&child) {
                self.cursor.goto_parent();
                break;
            }
            self.path.push(child);
        }
        (self.steps <= MAX_CURSOR_STEPS).then_some(self.path.as_slice())
    }
}

/// What one pattern's source says about where its captures sit.
struct Shape<'s> {
    /// The named-node depths below the pattern's root at which each capture
    /// is written, sorted; `None` for a capture on a group or an alternation.
    depths: FxHashMap<&'s str, Option<Box<[u32]>>>,
    /// The node kind (`_` for a wildcard) of the pattern's root, when the
    /// pattern is one unquantified node; `None` for a sibling sequence or a
    /// root alternation.
    root: Option<&'s str>,
}

/// Read one pattern's source into its [`Shape`]; `None` for syntax this
/// reader does not follow.
fn capture_depths(source: &str) -> Option<Shape<'_>> {
    let tokens = query_tokens(source);
    if tokens.is_empty() {
        return None;
    }
    /// One open `(` or `[`: whether it is a named-node pattern, and whether it
    /// sits inside a predicate.
    struct Open {
        at: usize,
        node: bool,
        predicate: bool,
    }
    let mut stack: Vec<Open> = Vec::new();
    // The depth of each node pattern, by the index of its `(`.
    let mut node_depth: FxHashMap<usize, u32> = FxHashMap::default();
    // The `(` or `[` each `)` or `]` closes.
    let mut opened_by: FxHashMap<usize, usize> = FxHashMap::default();
    let mut depths: FxHashMap<&str, Option<Vec<u32>>> = FxHashMap::default();
    // Named-node patterns at the top level: where each opens, and its kind.
    let mut top: Vec<(usize, &str)> = Vec::new();
    for (i, &token) in tokens.iter().enumerate() {
        let in_predicate = stack.last().is_some_and(|open| open.predicate);
        match token {
            "(" => {
                let head = *tokens.get(i + 1)?;
                if head == "\"" {
                    // A parenthesized anonymous node: not followed here.
                    return None;
                }
                let predicate = in_predicate || head.starts_with('#');
                let node = !predicate
                    && head != "("
                    && head != "["
                    && head.chars().all(|c| c.is_alphanumeric() || c == '_');
                if node {
                    let depth = stack.iter().filter(|open| open.node).count();
                    node_depth.insert(i, u32::try_from(depth).ok()?);
                    if depth == 0 {
                        top.push((i, head));
                    }
                }
                stack.push(Open {
                    at: i,
                    node,
                    predicate,
                });
            }
            "[" => stack.push(Open {
                at: i,
                node: false,
                predicate: in_predicate,
            }),
            ")" | "]" => {
                opened_by.insert(i, stack.pop()?.at);
            }
            _ if !in_predicate && token.starts_with('@') => {
                let capture = &token[1..];
                // Captures and quantifiers trail the pattern they name.
                let mut j = i;
                while j > 0
                    && (matches!(tokens[j - 1], "?" | "*" | "+") || tokens[j - 1].starts_with('@'))
                {
                    j -= 1;
                }
                let depth = (j > 0 && tokens[j - 1] == ")")
                    .then(|| opened_by.get(&(j - 1)))
                    .flatten()
                    .and_then(|open| node_depth.get(open).copied());
                let entry = depths.entry(capture).or_insert_with(|| Some(Vec::new()));
                match (entry.as_mut(), depth) {
                    (Some(all), Some(depth)) => all.push(depth),
                    _ => *entry = None,
                }
            }
            _ => {}
        }
    }
    if !stack.is_empty() {
        return None;
    }
    // One top-level node, not repeated: no quantifier after its captures.
    let root = match top.as_slice() {
        &[(open, head)] => {
            let close = opened_by
                .iter()
                .find_map(|(&close, &o)| (o == open).then_some(close))?;
            let mut after = close + 1;
            while tokens.get(after).is_some_and(|t| t.starts_with('@')) {
                after += 1;
            }
            (!matches!(tokens.get(after), Some(&"?" | &"*" | &"+"))).then_some(head)
        }
        _ => None,
    };
    let depths = depths
        .into_iter()
        .map(|(capture, depths)| {
            let depths = depths.map(|mut all| {
                all.sort_unstable();
                all.dedup();
                all.into_boxed_slice()
            });
            (capture, depths)
        })
        .collect();
    Some(Shape { depths, root })
}

#[cfg(test)]
#[path = "ast_anchor/tests.rs"]
mod tests;
