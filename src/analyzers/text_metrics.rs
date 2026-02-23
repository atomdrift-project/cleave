//! Universal text metrics analyzer
//!
//! Computes text-level metrics that apply to all source files before
//! language-specific parsing. These metrics are useful for ML-based
//! anomaly detection and obfuscation identification.

use crate::types::TextMetrics;
use std::collections::HashMap;

/// Analyze raw text content and produce TextMetrics
#[must_use]
pub(crate) fn analyze_text(content: &str) -> TextMetrics {
    let bytes = content.as_bytes();
    let mut metrics = TextMetrics::default();

    if content.is_empty() {
        return metrics;
    }

    // === Character Distribution ===
    let (char_entropy, unique_chars, most_common, most_common_ratio) =
        analyze_char_distribution(content);
    metrics.char_entropy = char_entropy;
    metrics.unique_chars = unique_chars;
    metrics.most_common_char = most_common;
    metrics.most_common_ratio = most_common_ratio;

    // === Byte-Level Analysis ===
    let (non_ascii, non_printable, null_count, high_byte) = analyze_bytes(bytes);
    metrics.non_ascii_ratio = non_ascii;
    metrics.non_printable_ratio = non_printable;
    metrics.null_byte_count = null_count;
    metrics.high_byte_ratio = high_byte;

    // === Line Statistics ===
    let lines: Vec<&str> = content.lines().collect();
    metrics.total_lines = lines.len() as u32;

    if !lines.is_empty() {
        let line_lengths: Vec<usize> = lines.iter().map(|l| l.len()).collect();
        let total_len: usize = line_lengths.iter().sum();
        metrics.avg_line_length = total_len as f32 / lines.len() as f32;
        metrics.max_line_length = *line_lengths.iter().max().unwrap_or(&0) as u32;

        // Standard deviation
        let mean = metrics.avg_line_length;
        let variance: f32 = line_lengths
            .iter()
            .map(|&len| {
                let diff = len as f32 - mean;
                diff * diff
            })
            .sum::<f32>()
            / lines.len() as f32;
        metrics.line_length_stddev = variance.sqrt();

        // Long line counts
        metrics.lines_over_200 = line_lengths.iter().filter(|&&l| l > 200).count() as u32;
        metrics.lines_over_500 = line_lengths.iter().filter(|&&l| l > 500).count() as u32;
        metrics.lines_over_1000 = line_lengths.iter().filter(|&&l| l > 1000).count() as u32;

        // Empty line ratio
        let empty_count = lines.iter().filter(|l| l.trim().is_empty()).count();
        metrics.empty_line_ratio = empty_count as f32 / lines.len() as f32;

        // Trailing whitespace
        metrics.trailing_whitespace_lines = lines
            .iter()
            .filter(|l| !l.is_empty() && l.ends_with(|c: char| c.is_whitespace()))
            .count() as u32;
    }

    // === Whitespace Forensics ===
    let (ws_ratio, tabs, spaces, mixed, unusual) = analyze_whitespace(content);
    metrics.whitespace_ratio = ws_ratio;
    metrics.tab_count = tabs;
    metrics.space_count = spaces;
    metrics.mixed_indent = mixed;
    metrics.unusual_whitespace = unusual;

    // === Escape Sequences ===
    let (hex_esc, unicode_esc, octal_esc) = count_escapes(content);
    metrics.hex_escape_count = hex_esc;
    metrics.unicode_escape_count = unicode_esc;
    metrics.octal_escape_count = octal_esc;
    let total_escapes = hex_esc + unicode_esc + octal_esc;
    metrics.escape_density = if !content.is_empty() {
        (total_escapes as f32 / content.len() as f32) * 100.0
    } else {
        0.0
    };

    // === Suspicious Text Patterns ===
    metrics.long_token_count = count_long_tokens(content);
    metrics.repeated_char_sequences = count_repeated_sequences(content);
    metrics.digit_ratio = calculate_digit_ratio(content);
    metrics.ascii_art_lines = detect_ascii_art(&lines);

    metrics
}

/// Calculate Shannon entropy and character distribution
fn analyze_char_distribution(content: &str) -> (f32, u32, Option<char>, f32) {
    let mut freq: HashMap<char, usize> = HashMap::new();
    let mut total = 0usize;

    for c in content.chars() {
        *freq.entry(c).or_insert(0) += 1;
        total += 1;
    }

    if total == 0 {
        return (0.0, 0, None, 0.0);
    }

    let unique_chars = freq.len() as u32;

    // Shannon entropy
    let entropy: f32 = freq
        .values()
        .map(|&count| {
            let p = count as f32 / total as f32;
            if p > 0.0 {
                -p * p.log2()
            } else {
                0.0
            }
        })
        .sum();

    // Most common non-whitespace character
    let most_common = freq
        .iter()
        .filter(|(&c, _)| !c.is_whitespace())
        .max_by_key(|(_, &count)| count)
        .map(|(&c, _)| c);

    let most_common_ratio = most_common
        .and_then(|c| freq.get(&c))
        .map(|&count| count as f32 / total as f32)
        .unwrap_or(0.0);

    (entropy, unique_chars, most_common, most_common_ratio)
}

/// Analyze bytes for non-ASCII, non-printable, null, and high bytes
fn analyze_bytes(bytes: &[u8]) -> (f32, f32, u32, f32) {
    if bytes.is_empty() {
        return (0.0, 0.0, 0, 0.0);
    }

    let total = bytes.len();
    let mut non_ascii = 0usize;
    let mut non_printable = 0usize;
    let mut null_count = 0u32;
    let mut high_byte = 0usize;

    for &b in bytes {
        if b == 0 {
            null_count += 1;
        }
        if b > 127 {
            non_ascii += 1;
            high_byte += 1;
        }
        // Non-printable: control chars (0-31 except tab/newline/CR) and DEL (127)
        if (b < 32 && b != 9 && b != 10 && b != 13) || b == 127 {
            non_printable += 1;
        }
    }

    (
        non_ascii as f32 / total as f32,
        non_printable as f32 / total as f32,
        null_count,
        high_byte as f32 / total as f32,
    )
}

/// Analyze whitespace patterns
fn analyze_whitespace(content: &str) -> (f32, u32, u32, bool, u32) {
    let total_chars = content.chars().count();
    if total_chars == 0 {
        return (0.0, 0, 0, false, 0);
    }

    let mut tabs = 0u32;
    let mut spaces = 0u32;
    let mut whitespace_count = 0usize;
    let mut unusual = 0u32;

    // Track indentation patterns per line
    let mut lines_with_tab_indent = 0;
    let mut lines_with_space_indent = 0;

    for line in content.lines() {
        let mut saw_tab = false;
        let mut saw_space = false;

        for c in line.chars() {
            if c == '\t' {
                saw_tab = true;
            } else if c == ' ' {
                saw_space = true;
            } else {
                break; // Stop at first non-whitespace
            }
        }

        if saw_tab {
            lines_with_tab_indent += 1;
        }
        if saw_space {
            lines_with_space_indent += 1;
        }
    }

    for c in content.chars() {
        if c.is_whitespace() {
            whitespace_count += 1;
            match c {
                '\t' => tabs += 1,
                ' ' => spaces += 1,
                // Unusual whitespace characters
                '\u{00A0}' | // Non-breaking space
                '\u{2000}'..='\u{200B}' | // Various Unicode spaces + zero-width
                '\u{202F}' | // Narrow no-break space
                '\u{205F}' | // Medium mathematical space
                '\u{3000}' | // Ideographic space
                '\u{FEFF}'   // Zero-width no-break space (BOM)
                    => unusual += 1,
                _ => {}
            }
        }
    }

    let mixed_indent = lines_with_tab_indent > 0 && lines_with_space_indent > 0;
    let ws_ratio = whitespace_count as f32 / total_chars as f32;

    (ws_ratio, tabs, spaces, mixed_indent, unusual)
}

/// Count escape sequences in content
fn count_escapes(content: &str) -> (u32, u32, u32) {
    let mut hex_count = 0u32;
    let mut unicode_count = 0u32;
    let mut octal_count = 0u32;

    // Simple pattern matching - not perfect but catches most cases
    let bytes = content.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i] == b'\\' && i + 1 < len {
            match bytes[i + 1] {
                b'x' => {
                    // \xNN - hex escape
                    if i + 3 < len
                        && bytes[i + 2].is_ascii_hexdigit()
                        && bytes[i + 3].is_ascii_hexdigit()
                    {
                        hex_count += 1;
                        i += 4;
                        continue;
                    }
                }
                b'u' => {
                    // \uNNNN or \u{...}
                    if i + 5 < len {
                        unicode_count += 1;
                        i += 2;
                        continue;
                    }
                }
                b'U' => {
                    // \UNNNNNNNN
                    if i + 9 < len {
                        unicode_count += 1;
                        i += 2;
                        continue;
                    }
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

/// Count tokens longer than 100 characters without spaces
fn count_long_tokens(content: &str) -> u32 {
    content
        .split_whitespace()
        .filter(|token| token.len() > 100)
        .count() as u32
}

/// Count sequences of 10+ repeated characters
fn count_repeated_sequences(content: &str) -> u32 {
    let mut count = 0u32;
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        let mut run_length = 1;

        while i + run_length < chars.len() && chars[i + run_length] == c {
            run_length += 1;
        }

        if run_length >= 10 {
            count += 1;
        }

        i += run_length;
    }

    count
}

/// Calculate ratio of digits to alphanumeric characters
fn calculate_digit_ratio(content: &str) -> f32 {
    let mut digits = 0usize;
    let mut alphanumeric = 0usize;

    for c in content.chars() {
        if c.is_ascii_digit() {
            digits += 1;
            alphanumeric += 1;
        } else if c.is_ascii_alphabetic() {
            alphanumeric += 1;
        }
    }

    if alphanumeric == 0 {
        0.0
    } else {
        digits as f32 / alphanumeric as f32
    }
}

/// Detect lines that look like ASCII art or banners
fn detect_ascii_art(lines: &[&str]) -> u32 {
    let art_chars = ['=', '-', '*', '#', '+', '|', '/', '\\', '_', '.'];
    let mut count = 0u32;

    for line in lines {
        let trimmed = line.trim();
        if trimmed.len() >= 20 {
            // Count art characters
            let art_count = trimmed.chars().filter(|c| art_chars.contains(c)).count();

            // If >70% are art characters, likely ASCII art
            if art_count as f32 / trimmed.len() as f32 > 0.7 {
                count += 1;
            }
        }
    }

    count
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
}
