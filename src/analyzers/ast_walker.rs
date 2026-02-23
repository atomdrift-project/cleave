//! Iterative AST traversal utilities
//!
//! Provides stack-safe alternatives to recursive AST walking.
//! This prevents stack overflow on deeply nested code (minified JS, malicious files).

use tree_sitter::{Node, TreeCursor};

/// Maximum depth to prevent runaway traversal on malformed ASTs
pub(crate) const MAX_AST_DEPTH: usize = 10_000;

/// Result of AST traversal with limit detection
#[derive(Debug, Clone, Default)]
pub(crate) struct WalkStats {
    /// Whether the depth limit was reached (potential anti-analysis)
    pub depth_limit_hit: bool,
    /// Maximum depth actually reached
    pub max_depth_reached: usize,
}

/// Like walk_tree but returns stats including whether depth limits were hit.
/// Use this when you need to detect potential anti-analysis techniques.
pub(crate) fn walk_tree_with_stats<'a, F>(cursor: &mut TreeCursor<'a>, mut visitor: F) -> WalkStats
where
    F: FnMut(Node<'a>, usize) -> bool,
{
    let mut stats = WalkStats::default();
    let mut depth = 0usize;

    loop {
        if depth > stats.max_depth_reached {
            stats.max_depth_reached = depth;
        }

        if depth > MAX_AST_DEPTH {
            stats.depth_limit_hit = true;
            return stats; // Safety limit reached
        }

        let node = cursor.node();
        let should_descend = visitor(node, depth);

        // Try to descend if visitor allows
        if should_descend && cursor.goto_first_child() {
            depth += 1;
            continue;
        }

        // Try to go to sibling
        if cursor.goto_next_sibling() {
            continue;
        }

        // Go back up until we can go sideways or reach root
        loop {
            if !cursor.goto_parent() {
                return stats; // Reached root, done
            }
            depth = depth.saturating_sub(1);
            if cursor.goto_next_sibling() {
                break; // Found a sibling, continue outer loop
            }
        }
    }
}
