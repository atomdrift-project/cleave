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
#[allow(clippy::too_many_arguments)]
pub(super) fn build(
    original: &tree_sitter::Tree,
    source: &str,
    file_type: crate::composite_rules::FileType,
    indexed_comments: Option<&[tree_sitter::Range]>,
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
    let collected;
    let ranges = match indexed_comments {
        Some(ranges) => ranges,
        None => {
            collected = find_comments(original, stopped)?;
            &collected
        }
    };
    if ranges.is_empty() {
        return Ok(None);
    }
    use crate::composite_rules::FileType;
    let incremental = matches!(file_type, FileType::JavaScript | FileType::TypeScript);
    let mut masked = source.as_bytes().to_vec();
    let mut edits: Vec<tree_sitter::InputEdit> = Vec::new();
    for range in ranges {
        stopped()?;
        let span = masked
            .get_mut(range.start_byte..range.end_byte)
            .ok_or(ViewError::ParseChanged)?;
        for byte in span {
            if !matches!(*byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
        if incremental {
            // Nearby comments can share one same-width edit. Distant runs of
            // unchanged syntax remain available to the incremental parser.
            if let Some(last) = edits.last_mut()
                && range.start_byte.saturating_sub(last.old_end_byte) < 4096
            {
                last.old_end_byte = range.end_byte;
                last.new_end_byte = range.end_byte;
                last.old_end_position = range.end_point;
                last.new_end_position = range.end_point;
            } else {
                edits.push(tree_sitter::InputEdit {
                    start_byte: range.start_byte,
                    start_position: range.start_point,
                    old_end_byte: range.end_byte,
                    new_end_byte: range.end_byte,
                    old_end_position: range.end_point,
                    new_end_position: range.end_point,
                });
            }
        }
    }
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
    let mut previous = incremental.then(|| original.clone());
    if let Some(tree) = &mut previous {
        for edit in edits {
            stopped()?;
            tree.edit(&edit);
        }
    }
    let parsed = parser.parse_with_options(&mut read, previous.as_ref(), Some(options));
    if let Some(reason) = interrupted {
        return Err(reason);
    }
    stopped()?;
    let parsed = parsed.ok_or(ViewError::ParseChanged)?;
    if parsed.root_node().has_error() && !original.root_node().has_error() {
        return Err(ViewError::ParseChanged);
    }
    Ok(Some(parsed))
}

pub(super) fn is_comment(node: &tree_sitter::Node<'_>) -> bool {
    matches!(node.kind(), "comment" | "line_comment" | "block_comment") && node.is_extra()
}

fn find_comments(
    original: &tree_sitter::Tree,
    stopped: impl Fn() -> Result<(), ViewError>,
) -> Result<Vec<tree_sitter::Range>, ViewError> {
    let mut ranges = Vec::new();
    let mut cursor = original.walk();
    let mut visited = 0usize;
    loop {
        visited += 1;
        if visited.is_multiple_of(128) {
            stopped()?;
        }
        let node = cursor.node();
        if is_comment(&node) {
            ranges.push(node.range());
        } else if cursor.goto_first_child() {
            continue;
        }
        loop {
            if cursor.goto_next_sibling() {
                break;
            }
            if !cursor.goto_parent() {
                stopped()?;
                return Ok(ranges);
            }
        }
    }
}
