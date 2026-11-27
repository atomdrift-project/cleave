//! Adversarial inputs for the helpers that walk a whole file's bytes in one
//! call: markup-comment masking, comment-span masking, lossy UTF-8 decoding
//! and raw-content search.
//!
//! Each is run over a few MB shaped to defeat a naive scanner — openers with
//! no closer, unbalanced quotes, one giant line, long runs of one byte — under
//! a wall-clock budget that a linear walk meets with room to spare even
//! unoptimized, and a quadratic one misses by minutes. A 70 MB Markdown file
//! of `<--` annotations with no `>` once held an analysis for hours inside
//! the markup masker; these keep every sibling helper honest the same way.
//!
//! The cancellation tests pin the other half: a raised flag stops a long walk
//! and leaves a result that cannot be mistaken for a complete one.
#![allow(clippy::unwrap_used)]

use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use super::{Cancelled, EvaluationContext, lossy_utf8, mask_markup_comments, mask_spans};
use crate::composite_rules::evaluators::{ContentLocationParams, TextPattern, eval_raw};
use crate::composite_rules::types::FileType;
use crate::types::{AnalysisGap, AnalysisReport, TargetInfo};

/// Size of each corpus entry: enough that O(n²) work takes minutes, small
/// enough that the linear walk is milliseconds.
const SIZE: usize = 4 << 20;

/// Generous on purpose: these must never flake on a loaded CI box.
const BUDGET: Duration = Duration::from_secs(2);

/// `unit` repeated to about [`SIZE`] bytes.
fn fill(unit: &[u8]) -> Vec<u8> {
    unit.repeat(SIZE / unit.len())
}

/// Inputs shaped against naive scanners: each names what it defeats.
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut one_line = fill(b"x = 'a' < \"b\" ");
    one_line.extend(b"<!-- tail -->");
    vec![
        // Every `<` hunts for a `>` that never comes.
        ("angles without a close", fill(b"   -1.43E+003  <-- E\n")),
        ("millions of angles", vec![b'<'; SIZE]),
        // Each quote flips a tag scanner into "inside a string" to EOF.
        ("unclosed quotes", fill(b"<a it's <b \"x ")),
        // No line breaks: line-oriented helpers see one 4 MB line.
        ("one multi-MB line", one_line),
        ("open html comments", fill(b"<!--")),
        ("open server comments", fill(b"<%--")),
        ("unclosed raw-text tags", fill(b"<script '")),
        ("raw-text tag never closed", {
            let mut s = b"<script>".to_vec();
            s.extend(fill(b"if (a </scrip b) { c('<!--') }\n"));
            s
        }),
        // One invalid sequence per two bytes: lossy decoding's worst case.
        ("dense invalid utf-8", fill(b"a\xff")),
        // Long runs a backtracking regex or a naive prefilter rescans.
        ("one-byte run", vec![b'a'; SIZE]),
    ]
}

/// Run `f`, failing if it misses the budget.
fn timed<T>(what: &str, f: impl FnOnce() -> T) -> T {
    let started = Instant::now();
    let out = f();
    let elapsed = started.elapsed();
    assert!(elapsed < BUDGET, "{what} took {elapsed:?}");
    out
}

fn new_report() -> AnalysisReport {
    AnalysisReport::new(TargetInfo {
        path: "adversarial".to_string(),
        file_type: "html".to_string(),
        size_bytes: SIZE as u64,
        sha256: "0".repeat(64),
        architectures: None,
    })
}

#[test]
fn markup_masking_is_linear_on_every_shape() {
    for (name, input) in corpus() {
        let masked = timed(name, || mask_markup_comments(&input, None)).unwrap();
        if let Some(masked) = masked {
            assert_eq!(masked.len(), input.len(), "{name}: offsets must not shift");
        }
    }
}

#[test]
fn span_masking_is_linear_when_spans_overlap() {
    // Every span runs to EOF from a later start: the old walk re-blanked the
    // tail once per span, O(spans × len).
    for (name, input) in corpus() {
        let spans: Vec<(usize, usize)> = (0..input.len())
            .step_by(512)
            .map(|start| (start, input.len() - start))
            .rev()
            .collect();
        let masked = timed(name, || mask_spans(&input, &spans, None))
            .unwrap()
            .unwrap();
        assert_eq!(masked.len(), input.len());
        assert!(
            masked.iter().all(|b| matches!(*b, b' ' | b'\n' | b'\r')),
            "{name}: every byte is inside some span"
        );
    }
}

#[test]
fn span_masking_matches_the_spans_it_was_given() {
    let source = b"a /* x */ b // y\nc";
    let spans = [(14, 2), (2, 7), (4, 2)];
    let masked = mask_spans(source, &spans, None).unwrap().unwrap();
    assert_eq!(&masked, b"a         b //  \nc");
}

#[test]
fn lossy_decoding_is_linear_and_matches_std() {
    for (name, input) in corpus() {
        let text = timed(name, || lossy_utf8(&input, None)).unwrap();
        assert_eq!(text, String::from_utf8_lossy(&input), "{name}");
    }
}

#[test]
fn raw_search_is_linear_on_every_shape() {
    let report = new_report();
    let regexes = [
        r"<script[^>]*>",
        r"<!--[\s\S]{0,64}-->",
        r"(?:a|aa)+b",
        r"['\x22][^'\x22]{4,}['\x22]",
    ];
    let substrs = ["-->", "</script"];
    let words = ["script", "eval"];
    for (name, input) in corpus() {
        let ctx = EvaluationContext::test_only_new(&report, &input, FileType::All);
        let search = |pattern: TextPattern<'_>| {
            eval_raw(
                pattern,
                (None, None),
                None,
                None,
                &ContentLocationParams::default(),
                &ctx,
                None,
            )
        };
        for regex in regexes.map(str::to_owned) {
            timed(&format!("{name}: regex {regex}"), || {
                search(TextPattern {
                    regex: Some(&regex),
                    ..TextPattern::default()
                })
            });
        }
        for substr in substrs.map(str::to_owned) {
            timed(&format!("{name}: substr {substr}"), || {
                search(TextPattern {
                    substr: Some(&substr),
                    case_insensitive: true,
                    ..TextPattern::default()
                })
            });
        }
        for word in words.map(str::to_owned) {
            timed(&format!("{name}: word {word}"), || {
                search(TextPattern {
                    word: Some(&word),
                    ..TextPattern::default()
                })
            });
        }
    }
}

#[test]
fn whole_file_scans_stop_when_cancelled() {
    let raised = AtomicBool::new(true);
    let input = vec![b'<'; 3 * SIZE];
    assert_eq!(mask_markup_comments(&input, Some(&raised)), Err(Cancelled));
    assert_eq!(
        mask_spans(&input, &[(0, input.len())], Some(&raised)),
        Err(Cancelled)
    );
    assert_eq!(lossy_utf8(&input, Some(&raised)), Err(Cancelled));
    // Small inputs finish before the first poll: a scan that short costs
    // less than stopping it.
    assert!(mask_markup_comments(b"<!-- x -->", Some(&raised)).is_ok());
}

#[test]
fn a_cancelled_view_matches_nothing_and_marks_the_report_incomplete() {
    let report = new_report();
    let raised = AtomicBool::new(true);
    // Past the first poll in both the markup walk and the decoder.
    let mut input = b"<!-- hidden -->".to_vec();
    input.extend(b"live <-- no close\n".repeat(2 * SIZE / 18));
    input.extend(fill(b"\xff"));
    let ctx =
        EvaluationContext::test_only_new(&report, &input, FileType::All).with_cancellation(&raised);

    // Never the unmasked bytes (which would match what the mask hides), and
    // never a partial mask.
    assert!(ctx.html_comment_free_source() == Some(&[][..]));
    assert!(ctx.full_utf8().is_empty());
    assert!(
        report
            .analysis_gaps
            .contains(AnalysisGap::EvaluationDeadline)
    );

    // The same bytes, uncancelled, give the full answers.
    let fresh = new_report();
    let ctx = EvaluationContext::test_only_new(&fresh, &input, FileType::All);
    let masked = ctx.html_comment_free_source().unwrap();
    assert_eq!(masked.len(), input.len());
    assert!(!masked.windows(6).any(|w| w == b"hidden"));
    assert_eq!(ctx.full_utf8(), String::from_utf8_lossy(&input));
    assert!(fresh.analysis_gaps.is_empty());
}
