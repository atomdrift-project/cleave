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
        matches!(
            window_shape(pattern),
            Some(WindowShape {
                line: true,
                radius: 0,
                ..
            })
        ),
        "test pattern must be line-local"
    );
    let got = windows_from_atom_hits(&hay, &hits, pattern, 0, hay.len()).expect("windowable");
    assert_eq!(got, naive_line_windows(&hay, &hits));
}

/// Every match a whole-file search finds lies inside one window, for patterns
/// whose unbounded repetitions are bound to a line while their whitespace can
/// cross lines. Windowing them is what keeps a `class\s+\w+\s*\(` from walking
/// every file that says "class".
#[test]
fn line_bound_repetitions_window_without_losing_a_match() {
    let long_word = "w".repeat(3 * MAX_WINDOW_RADIUS);
    let blank = "\n".repeat(40);
    for (pattern, atom, lines) in [
        (
            r"class\s+\w+\s*\(",
            "class",
            vec![
                "class Plain(object):".to_string(),
                format!("class {long_word}("),
                format!("class\n{long_word}\n("),
                format!("class{blank}Spaced{blank}("),
                "a class of its own, then nothing".to_string(),
                format!("subclass \t {long_word}\t\t("),
            ],
        ),
        (
            r"(?m)^[ \t]*@[A-Za-z_][\w.]*\.(get|post|put)\s*\(",
            ".get",
            vec![
                format!("@{long_word}.get("),
                format!("    @app.{long_word}.get\n\n("),
                "value = table.get(key)".to_string(),
            ],
        ),
        (
            r"for\s+\w+\s+in\s+\[[^\]\n]{0,140}'\.(cc|io)'",
            "for",
            vec![
                format!("for {long_word} in ['.com', '.cc']"),
                format!("for\n{long_word}\nin\n['.io']"),
                "before and for ever after".to_string(),
            ],
        ),
    ] {
        let shape = window_shape(pattern).expect("windowable");
        assert!(shape.line_runs > 0, "{pattern} has a line-bound repetition");
        let filler = format!("{}\n", "x = 1  # nothing to see ".repeat(8));
        let mut hay = String::new();
        for line in &lines {
            // Enough hit-free text that the windows stay under half the file.
            for _ in 0..(8 * line.len() / filler.len() + 4) {
                hay.push_str(&filler);
            }
            hay.push_str(line);
            hay.push('\n');
        }
        let hay = hay.as_bytes();
        let hits: Vec<u32> = memchr::memmem::find_iter(hay, atom.as_bytes())
            .map(|at| at as u32)
            .collect();
        let windows = windows_from_atom_hits(hay, &hits, pattern, 0, hay.len()).expect("windowed");
        assert!(
            windows.windows(2).all(|pair| pair[0].1 < pair[1].0),
            "{pattern}: windows are sorted and disjoint: {windows:?}"
        );
        let regex = regex::bytes::Regex::new(pattern).expect("test pattern compiles");
        let found: Vec<_> = regex.find_iter(hay).map(|m| (m.start(), m.end())).collect();
        assert!(
            found.len() >= 2,
            "{pattern}: the fixture has matches: {found:?}"
        );
        for (start, end) in found {
            assert!(
                windows.iter().any(|&(lo, hi)| lo <= start && end <= hi),
                "{pattern}: match {start}..{end} is outside every window {windows:?}"
            );
        }
    }
}

/// A repetition that can cross lines through more than whitespace is never
/// windowed, however the rest of the pattern is bounded.
#[test]
fn a_repetition_that_crosses_lines_is_not_windowed() {
    for pattern in [
        r"readdirSync[\s\S]*\w+\.push",
        r#"key\s*=\s*"[^"]*""#,
        r"(?s)begin.*end",
        r"(\w+\s)+tail",
    ] {
        assert_eq!(window_shape(pattern), None, "{pattern}");
    }
    assert_eq!(
        window_shape(r"class\s+\w+\s*\("),
        Some(WindowShape {
            line: false,
            any_look: false,
            radius: 5 + UNBOUNDED_WS_CAP + UNBOUNDED_WS_CAP + 1,
            line_runs: 1,
        })
    );
}
