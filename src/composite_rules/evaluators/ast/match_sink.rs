//! The match collector for one standalone query: evidence and counts.

use super::{AST_QUERY_CAPTURE_LIMIT, truncate_evidence};
use crate::types::{Evidence, MAX_EVIDENCE_PER_TRAIT};
use std::ops::ControlFlow;

/// Collects one standalone query's matches into evidence and counts, the
/// same way whether the cursor ran once over the tree or once per root.
pub(super) struct MatchSink<'s> {
    pub(super) evidence_capture: Option<u32>,
    pub(super) source: &'s [u8],
    pub(super) evidence: Vec<Evidence>,
    pub(super) match_count: usize,
    pub(super) capture_count: usize,
    pub(super) capture_limited: bool,
}

impl MatchSink<'_> {
    /// `Break` once no further match can change the result.
    pub(super) fn accept(&mut self, m: &tree_sitter::QueryMatch<'_, '_>) -> ControlFlow<()> {
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
        if !crate::composite_rules::evaluators::symbol_string::match_count_needed() {
            return ControlFlow::Break(());
        }
        // Floor-only count filters already satisfied and the evidence list
        // full: later matches change neither verdict nor output.
        if self.match_count
            >= crate::composite_rules::evaluators::symbol_string::match_count_bound()
            && self.evidence.len() >= MAX_EVIDENCE_PER_TRAIT
        {
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    }
}
