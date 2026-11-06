#![allow(clippy::expect_used)]
use super::*;

/// Reference: line bounds found by scanning from the haystack ends, the
/// way the builder worked before the incremental walk.
fn naive_line_windows(hay: &[u8], hits: &[u32]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    for &hit in hits {
        let hit = hit as usize;
        let lo = memchr::memrchr(b'\n', &hay[..hit]).map_or(0, |n| n + 1);
        let hi = memchr::memchr(b'\n', &hay[hit..]).map_or(hay.len(), |n| hit + n + 1);
        spans.push((lo, hi));
    }
    merge_spans(spans)
}

#[test]
fn line_local_windows_match_the_naive_scan_on_long_lines() {
    // Three long minified-style lines with many atom hits each, plus a
    // short one: every shape the incremental walk has to get right.
    let mut hay = Vec::new();
    let mut hits = Vec::new();
    for (line_no, reps) in [(0usize, 40usize), (1, 1), (2, 25), (3, 3)] {
        for i in 0..reps {
            if line_no == 1 {
                hay.extend_from_slice(b"short foo(x) bar;");
            } else {
                hay.extend_from_slice(b"var a=b.c(d);if(e){f=g}");
                if i % 2 == 0 {
                    hits.push(hay.len() as u32);
                    hay.extend_from_slice(b"foo(");
                }
                hay.extend_from_slice(b"h.i(j,k);");
            }
        }
        hay.push(b'\n');
    }
    // Windowing is only chosen when the windows cover under half of the
    // haystack: pad with a long hit-free line.
    hay.extend(std::iter::repeat_n(b'x', 8 * hay.len()));
    hay.push(b'\n');
    assert!(hay.len() > MIN_HAYSTACK_TO_WINDOW);
    let pattern = r"foo\([^\n]*bar";
    assert!(
        matches!(window_shape(pattern), Some((true, _, 0))),
        "test pattern must be line-local"
    );
    let got = windows_from_atom_hits(&hay, &hits, pattern, 0, hay.len()).expect("windowable");
    assert_eq!(got, naive_line_windows(&hay, &hits));
}
