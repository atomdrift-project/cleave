//! Opt-in structural comment removal. Literal bytes and offsets stay original.
use crate::analyzers::ast_walker::thread_cpu_time;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(super) fn requested(query: &tree_sitter::Query) -> bool {
    (0..query.pattern_count()).any(|pattern| {
        query.property_settings(pattern).iter().any(|property| {
            property.capture_id.is_none()
                && property.key.as_ref() == "cleave.ignore-comments"
                && property.value.as_deref() == Some("true")
        })
    })
}

pub(super) enum ViewError {
    Limited,
    Cancelled,
    ParseChanged,
}

/// Mask only real, extra comment nodes found by the cached grammar. Delimiters
/// in strings are never searched or rewritten. CR/LF and all byte positions
/// survive; queries continue to read evidence and predicates from original text.
pub(super) fn build(
    original: &tree_sitter::Tree,
    source: &str,
    byte_limit: usize,
    cpu_budget: Duration,
    deadline: Option<Instant>,
    cancellation: Option<&AtomicBool>,
) -> Result<Option<tree_sitter::Tree>, ViewError> {
    if source.len() > byte_limit {
        return Err(ViewError::Limited);
    }
    let start = thread_cpu_time();
    let stopped = || {
        if cancellation.is_some_and(|flag| flag.load(Ordering::Relaxed))
            || deadline.is_some_and(|at| Instant::now() >= at)
        {
            Err(ViewError::Cancelled)
        } else if thread_cpu_time().saturating_sub(start) >= cpu_budget {
            Err(ViewError::Limited)
        } else {
            Ok(())
        }
    };
    stopped()?;
    let mut cursor = original.walk();
    let mut masked: Option<Vec<u8>> = None;
    let mut visited = 0usize;
    loop {
        visited += 1;
        if visited.is_multiple_of(128) {
            stopped()?;
        }
        let node = cursor.node();
        let comment =
            node.is_extra() && matches!(node.kind(), "comment" | "line_comment" | "block_comment");
        if comment {
            let bytes = masked.get_or_insert_with(|| source.as_bytes().to_vec());
            let Some(span) = bytes.get_mut(node.byte_range()) else {
                return Err(ViewError::ParseChanged);
            };
            for byte in span {
                if !matches!(*byte, b'\r' | b'\n') {
                    *byte = b' ';
                }
            }
        } else if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                stopped()?;
                let Some(masked) = masked else {
                    return Ok(None);
                };
                let mut parser = tree_sitter::Parser::new();
                parser
                    .set_language(&original.language())
                    .map_err(|_language_error| ViewError::ParseChanged)?;
                let mut interrupted = None;
                let mut progress = |_state: &tree_sitter::ParseState| {
                    if let Err(reason) = stopped() {
                        interrupted = Some(reason);
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    }
                };
                let options = tree_sitter::ParseOptions::default().progress_callback(&mut progress);
                let mut read = |offset: usize, _point| masked.get(offset..).unwrap_or(&[]);
                let parsed = parser.parse_with_options(&mut read, None, Some(options));
                if let Some(reason) = interrupted {
                    return Err(reason);
                }
                stopped()?;
                let parsed = parsed.ok_or(ViewError::ParseChanged)?;
                if parsed.root_node().has_error() && !original.root_node().has_error() {
                    return Err(ViewError::ParseChanged);
                }
                return Ok(Some(parsed));
            }
        }
    }
}
