//! Universal text metrics analyzer
//!
//! Computes text-level metrics that apply to all source files before
//! language-specific parsing. These metrics are useful for ML-based
//! anomaly detection and obfuscation identification.

use crate::types::TextMetrics;

#[derive(Default)]
struct ByteMetrics {
    char_entropy: f32,
    unique_chars: u32,
    most_common_char: Option<char>,
    most_common_ratio: f32,
    non_ascii_ratio: f32,
    non_printable_ratio: f32,
    null_byte_count: u32,
    high_byte_ratio: f32,
}

#[derive(Default)]
struct LineMetrics {
    total_lines: u32,
    avg_line_length: f32,
    max_line_length: u32,
    line_length_stddev: f32,
    lines_over_200: u32,
    lines_over_500: u32,
    lines_over_1000: u32,
    last_line_length: u32,
    empty_line_ratio: f32,
    mixed_indent: bool,
    trailing_whitespace_lines: u32,
    max_inline_whitespace_run: u32,
    ascii_art_lines: u32,
}

#[derive(Default)]
struct CharMetrics {
    whitespace_ratio: f32,
    tab_count: u32,
    space_count: u32,
    unusual_whitespace: u32,
    invisible_chars: u32,
    long_token_count: u32,
    repeated_char_sequences: u32,
    digit_ratio: f32,
}

/// Analyze raw text content and produce TextMetrics
#[must_use]
pub(crate) fn analyze_text(content: &str) -> TextMetrics {
    let mut metrics = TextMetrics::default();

    if content.is_empty() {
        return metrics;
    }

    let byte_metrics = analyze_byte_metrics(content.as_bytes());
    metrics.char_entropy = byte_metrics.char_entropy;
    metrics.unique_chars = byte_metrics.unique_chars;
    metrics.most_common_char = byte_metrics.most_common_char;
    metrics.most_common_ratio = byte_metrics.most_common_ratio;
    metrics.non_ascii_ratio = byte_metrics.non_ascii_ratio;
    metrics.non_printable_ratio = byte_metrics.non_printable_ratio;
    metrics.null_byte_count = byte_metrics.null_byte_count;
    metrics.high_byte_ratio = byte_metrics.high_byte_ratio;

    let line_metrics = analyze_line_metrics(content);
    metrics.total_lines = line_metrics.total_lines;
    metrics.avg_line_length = line_metrics.avg_line_length;
    metrics.max_line_length = line_metrics.max_line_length;
    metrics.line_length_stddev = line_metrics.line_length_stddev;
    metrics.lines_over_200 = line_metrics.lines_over_200;
    metrics.lines_over_500 = line_metrics.lines_over_500;
    metrics.lines_over_1000 = line_metrics.lines_over_1000;
    metrics.last_line_length = line_metrics.last_line_length;
    metrics.empty_line_ratio = line_metrics.empty_line_ratio;
    metrics.mixed_indent = line_metrics.mixed_indent;
    metrics.trailing_whitespace_lines = line_metrics.trailing_whitespace_lines;
    metrics.max_inline_whitespace_run = line_metrics.max_inline_whitespace_run;
    metrics.ascii_art_lines = line_metrics.ascii_art_lines;

    let char_metrics = analyze_char_metrics(content);
    metrics.whitespace_ratio = char_metrics.whitespace_ratio;
    metrics.tab_count = char_metrics.tab_count;
    metrics.space_count = char_metrics.space_count;
    metrics.unusual_whitespace = char_metrics.unusual_whitespace;
    metrics.invisible_chars = char_metrics.invisible_chars;
    metrics.long_token_count = char_metrics.long_token_count;
    metrics.repeated_char_sequences = char_metrics.repeated_char_sequences;
    metrics.digit_ratio = char_metrics.digit_ratio;

    // === Escape Sequences ===
    let (hex_esc, unicode_esc, octal_esc) = count_escapes(content.as_bytes());
    metrics.hex_escape_count = hex_esc;
    metrics.unicode_escape_count = unicode_esc;
    metrics.octal_escape_count = octal_esc;
    let total_escapes = hex_esc + unicode_esc + octal_esc;
    metrics.escape_density = (total_escapes as f32 / content.len() as f32) * 100.0;

    metrics
}

/// Calculate Shannon entropy, byte distribution, and byte-level metrics.
fn analyze_byte_metrics(bytes: &[u8]) -> ByteMetrics {
    let mut freq = [0u32; 256];
    let total = bytes.len();

    if total == 0 {
        return ByteMetrics::default();
    }

    let mut non_ascii = 0usize;
    let mut non_printable = 0usize;
    let mut null_count = 0u32;
    let mut high_byte = 0usize;

    for &b in bytes {
        freq[b as usize] += 1;
        if b == 0 {
            null_count += 1;
        }
        if b > 127 {
            non_ascii += 1;
            high_byte += 1;
        }
        if (b < 32 && b != 9 && b != 10 && b != 13) || b == 127 {
            non_printable += 1;
        }
    }

    let unique_chars = freq.iter().filter(|&&c| c > 0).count() as u32;

    // Shannon entropy
    let entropy: f32 = freq
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f32 / total as f32;
            -p * p.log2()
        })
        .sum();

    // Most common non-whitespace byte
    let most_common = freq
        .iter()
        .enumerate()
        .filter(|&(b, &count)| count > 0 && !matches!(b as u8, b' ' | b'\t' | b'\n' | b'\r'))
        .max_by_key(|&(_, &count)| count)
        .map(|(b, _)| b as u8 as char);

    let most_common_ratio = most_common
        .map(|c| freq[c as u8 as usize] as f32 / total as f32)
        .unwrap_or(0.0);

    ByteMetrics {
        char_entropy: entropy,
        unique_chars,
        most_common_char: most_common,
        most_common_ratio,
        non_ascii_ratio: non_ascii as f32 / total as f32,
        non_printable_ratio: non_printable as f32 / total as f32,
        null_byte_count: null_count,
        high_byte_ratio: high_byte as f32 / total as f32,
    }
}

/// Analyze line-oriented metrics without allocating temporary vectors.
fn analyze_line_metrics(content: &str) -> LineMetrics {
    let mut total_lines = 0u32;
    let mut mean = 0.0f32;
    let mut m2 = 0.0f32;
    let mut max_line_length = 0u32;
    let mut lines_over_200 = 0u32;
    let mut lines_over_500 = 0u32;
    let mut lines_over_1000 = 0u32;
    let mut last_line_length = 0u32;
    let mut empty_lines = 0u32;
    let mut lines_with_tab_indent = 0u32;
    let mut lines_with_space_indent = 0u32;
    let mut trailing_whitespace_lines = 0u32;
    let mut max_inline_whitespace_run = 0u32;
    let mut ascii_art_lines = 0u32;

    for line in content.lines() {
        total_lines += 1;

        let len = line.len() as u32;
        max_line_length = max_line_length.max(len);

        let len_f = len as f32;
        let count_f = total_lines as f32;
        let delta = len_f - mean;
        mean += delta / count_f;
        let delta2 = len_f - mean;
        m2 += delta * delta2;

        if len > 200 {
            lines_over_200 += 1;
        }
        if len > 500 {
            lines_over_500 += 1;
        }
        if len > 1000 {
            lines_over_1000 += 1;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            empty_lines += 1;
        } else {
            last_line_length = len;
        }

        if !line.is_empty() && line.ends_with(|c: char| c.is_whitespace()) {
            trailing_whitespace_lines += 1;
        }

        let (has_tab_indent, has_space_indent, inline_ws_run) = scan_line_whitespace(line);
        if has_tab_indent {
            lines_with_tab_indent += 1;
        }
        if has_space_indent {
            lines_with_space_indent += 1;
        }
        max_inline_whitespace_run = max_inline_whitespace_run.max(inline_ws_run);

        if is_ascii_art_line(line) {
            ascii_art_lines += 1;
        }
    }

    if total_lines == 0 {
        return LineMetrics::default();
    }

    LineMetrics {
        total_lines,
        avg_line_length: mean,
        max_line_length,
        line_length_stddev: (m2 / total_lines as f32).sqrt(),
        lines_over_200,
        lines_over_500,
        lines_over_1000,
        last_line_length,
        empty_line_ratio: empty_lines as f32 / total_lines as f32,
        mixed_indent: lines_with_tab_indent > 0 && lines_with_space_indent > 0,
        trailing_whitespace_lines,
        max_inline_whitespace_run,
        ascii_art_lines,
    }
}

/// Analyze character-oriented metrics in a single pass.
fn analyze_char_metrics(content: &str) -> CharMetrics {
    let mut whitespace_count = 0usize;
    let mut tabs = 0u32;
    let mut spaces = 0u32;
    let mut unusual_whitespace = 0u32;
    let mut invisible_chars = 0u32;
    let mut current_token_bytes = 0usize;
    let mut long_token_count = 0u32;
    let mut prev_char = None;
    let mut run_length = 0u32;
    let mut repeated_char_sequences = 0u32;
    let mut digits = 0usize;
    let mut alphanumeric = 0usize;
    let mut is_first_char = true;

    for c in content.chars() {
        if c.is_whitespace() {
            whitespace_count += 1;
            match c {
                '\t' => tabs += 1,
                ' ' => spaces += 1,
                _ => {}
            }
            if is_unusual_whitespace(c) {
                unusual_whitespace += 1;
            }
            if current_token_bytes > 100 {
                long_token_count += 1;
            }
            current_token_bytes = 0;
        } else {
            current_token_bytes += c.len_utf8();
        }

        if is_invisible_char(c, is_first_char) {
            invisible_chars = invisible_chars.saturating_add(1);
        }

        if c.is_ascii_digit() {
            digits += 1;
            alphanumeric += 1;
        } else if c.is_ascii_alphabetic() {
            alphanumeric += 1;
        }

        if Some(c) == prev_char {
            run_length += 1;
        } else {
            if run_length >= 10 {
                repeated_char_sequences += 1;
            }
            prev_char = Some(c);
            run_length = 1;
        }

        is_first_char = false;
    }

    if current_token_bytes > 100 {
        long_token_count += 1;
    }
    if run_length >= 10 {
        repeated_char_sequences += 1;
    }

    CharMetrics {
        whitespace_ratio: whitespace_count as f32 / content.len() as f32,
        tab_count: tabs,
        space_count: spaces,
        unusual_whitespace,
        invisible_chars,
        long_token_count,
        repeated_char_sequences,
        digit_ratio: if alphanumeric == 0 {
            0.0
        } else {
            digits as f32 / alphanumeric as f32
        },
    }
}

fn scan_line_whitespace(line: &str) -> (bool, bool, u32) {
    let mut has_tab_indent = false;
    let mut has_space_indent = false;

    for c in line.chars() {
        if c == '\t' {
            has_tab_indent = true;
        } else if c == ' ' {
            has_space_indent = true;
        } else {
            break;
        }
    }

    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return (has_tab_indent, has_space_indent, 0);
    }

    let mut current_run = 0u32;
    let mut max_run = 0u32;
    for ch in trimmed.chars() {
        if ch == ' ' || ch == '\t' {
            current_run += 1;
        } else {
            max_run = max_run.max(current_run);
            current_run = 0;
        }
    }

    (has_tab_indent, has_space_indent, max_run)
}

/// Count escape sequences in content
fn count_escapes(bytes: &[u8]) -> (u32, u32, u32) {
    let mut hex_count = 0u32;
    let mut unicode_count = 0u32;
    let mut octal_count = 0u32;

    // Simple pattern matching - not perfect but catches most cases
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            match bytes[i + 1] {
                // \xNN - hex escape
                b'x' if i + 3 < len
                    && bytes[i + 2].is_ascii_hexdigit()
                    && bytes[i + 3].is_ascii_hexdigit() =>
                {
                    hex_count += 1;
                    i += 4;
                    continue;
                }
                // \uNNNN or \u{...}
                b'u' if i + 5 < len => {
                    unicode_count += 1;
                    i += 2;
                    continue;
                }
                // \UNNNNNNNN
                b'U' if i + 9 < len => {
                    unicode_count += 1;
                    i += 2;
                    continue;
                }
                b'0'..=b'7' => {
                    // Octal escape \NNN
                    octal_count += 1;
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        i += 1;
    }

    (hex_count, unicode_count, octal_count)
}

fn is_unusual_whitespace(c: char) -> bool {
    matches!(
        c,
        '\u{00A0}' | '\u{2000}'..='\u{200B}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}'
    )
}

fn is_invisible_char(c: char, is_first_char: bool) -> bool {
    let cp = c as u32;
    if is_first_char && cp == 0xFEFF {
        return false;
    }

    (0xFE00..=0xFE0F).contains(&cp)
        || (0xE0100..=0xE01EF).contains(&cp)
        || (0xE0001..=0xE007F).contains(&cp)
        || matches!(cp, 0x200B | 0x200C | 0x200D | 0x2060 | 0xFEFF)
}

fn is_ascii_art_line(line: &str) -> bool {
    let art_chars = ['=', '-', '*', '#', '+', '|', '/', '\\', '_', '.'];
    let trimmed = line.trim();
    if trimmed.len() < 20 {
        return false;
    }

    let art_count = trimmed
        .bytes()
        .filter(|b| art_chars.contains(&(*b as char)))
        .count();
    art_count as f32 / trimmed.len() as f32 > 0.7
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_content() {
        let metrics = analyze_text("");
        assert_eq!(metrics.total_lines, 0);
        assert_eq!(metrics.char_entropy, 0.0);
    }

    #[test]
    fn test_simple_content() {
        let metrics = analyze_text("hello world\n");
        assert_eq!(metrics.total_lines, 1);
        assert!(metrics.char_entropy > 0.0);
    }

    #[test]
    fn test_long_lines() {
        let long_line = "x".repeat(250);
        let content = format!("{}\n{}\nshort", long_line, long_line);
        let metrics = analyze_text(&content);
        assert_eq!(metrics.lines_over_200, 2);
        assert_eq!(metrics.lines_over_500, 0);
    }

    #[test]
    fn test_hex_escapes() {
        let content = r#"buf = "\x90\x90\x90\x41\x42""#;
        let metrics = analyze_text(content);
        assert!(metrics.hex_escape_count >= 5);
    }

    #[test]
    fn test_repeated_sequences() {
        let content = "aaaaaaaaaaaaa normal bbbbbbbbbbbbb";
        let metrics = analyze_text(content);
        assert_eq!(metrics.repeated_char_sequences, 2);
    }

    #[test]
    fn test_whitespace_analysis() {
        let content = "  spaces\n\ttabs\n";
        let metrics = analyze_text(content);
        assert!(metrics.tab_count > 0);
        assert!(metrics.space_count > 0);
        assert!(metrics.mixed_indent);
    }

    #[test]
    fn test_max_inline_whitespace_run() {
        // Normal code — small inline gaps from alignment
        let normal = "const x = 1;\nconst y  = 2;\n";
        let m = analyze_text(normal);
        assert!(m.max_inline_whitespace_run <= 2);

        // Whitespace-padded payload hiding (supply-chain attack pattern)
        let padded = format!("export default config;{}global['!']=1;", " ".repeat(500));
        let m = analyze_text(&padded);
        assert_eq!(m.max_inline_whitespace_run, 500);

        // Leading indent should NOT count — only the single space in "foo() {}" counts
        let indented = format!("{}function foo() {{}}", " ".repeat(200));
        let m = analyze_text(&indented);
        assert_eq!(m.max_inline_whitespace_run, 1);

        // Trailing whitespace should NOT count — only the single space in "code here" counts
        let trailing = format!("code here{}", " ".repeat(300));
        let m = analyze_text(&trailing);
        assert_eq!(m.max_inline_whitespace_run, 1);

        // Tab padding counts too
        let tabbed = format!("code;{}malicious();", "\t".repeat(150));
        let m = analyze_text(&tabbed);
        assert_eq!(m.max_inline_whitespace_run, 150);
    }
}
