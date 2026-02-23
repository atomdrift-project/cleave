//! Comment and documentation metrics analyzer
//!
//! Analyzes comments for obfuscation detection and suspicious patterns.

use crate::types::CommentMetrics;
use std::collections::HashMap;

/// Comment style for different languages
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum CommentStyle {
    /// C-style: // and /* */
    CStyle,
    /// Shell/Python: #
    Hash,
    /// Lua: -- and --[[ ]]
    Lua,
}

/// Extract and analyze comments from source code
#[must_use]
pub(crate) fn analyze_comments(content: &str, style: CommentStyle) -> CommentMetrics {
    let comments = extract_comments(content, style);
    analyze_comment_list(&comments, content)
}

/// Analyze a list of already-extracted comments
#[must_use]
pub(crate) fn analyze_comment_list(comments: &[String], full_content: &str) -> CommentMetrics {
    let mut metrics = CommentMetrics::default();

    if comments.is_empty() {
        return metrics;
    }

    metrics.total = comments.len() as u32;

    let mut total_chars: u64 = 0;
    let mut comment_lines: u32 = 0;
    let mut todo_count: u32 = 0;
    let mut fixme_count: u32 = 0;
    let mut hack_count: u32 = 0;
    let mut xxx_count: u32 = 0;
    let mut empty_comments: u32 = 0;
    let mut high_entropy_comments: u32 = 0;
    let mut code_in_comments: u32 = 0;
    let mut url_in_comments: u32 = 0;
    let mut base64_in_comments: u32 = 0;

    for comment in comments {
        let trimmed = comment.trim();
        total_chars += comment.len() as u64;
        comment_lines += comment.lines().count() as u32;

        if trimmed.is_empty() {
            empty_comments += 1;
            continue;
        }

        let upper = trimmed.to_uppercase();

        // Annotation patterns
        if upper.contains("TODO") {
            todo_count += 1;
        }
        if upper.contains("FIXME") {
            fixme_count += 1;
        }
        if upper.contains("HACK") {
            hack_count += 1;
        }
        if upper.contains("XXX") {
            xxx_count += 1;
        }

        // Entropy check
        let entropy = calculate_entropy(trimmed);
        if entropy > 4.5 && trimmed.len() > 20 {
            high_entropy_comments += 1;
        }

        // Code in comments
        if has_code_patterns(trimmed) {
            code_in_comments += 1;
        }

        // URLs
        if trimmed.contains("http://") || trimmed.contains("https://") || trimmed.contains("ftp://")
        {
            url_in_comments += 1;
        }

        // Base64 in comments
        if has_base64_pattern(trimmed) {
            base64_in_comments += 1;
        }
    }

    metrics.lines = comment_lines;
    metrics.chars = total_chars;

    // Calculate comment-to-code ratio
    let total_lines = full_content.lines().count() as f32;
    let code_lines = total_lines - comment_lines as f32;
    metrics.to_code_ratio = if code_lines > 0.0 {
        comment_lines as f32 / code_lines
    } else {
        0.0
    };

    metrics.todo_count = todo_count;
    metrics.fixme_count = fixme_count;
    metrics.hack_count = hack_count;
    metrics.xxx_count = xxx_count;
    metrics.empty_comments = empty_comments;
    metrics.high_entropy_comments = high_entropy_comments;
    metrics.code_in_comments = code_in_comments;
    metrics.url_in_comments = url_in_comments;
    metrics.base64_in_comments = base64_in_comments;

    metrics
}

/// Extract comments from source code based on language style
#[must_use]
pub(crate) fn extract_comments(content: &str, style: CommentStyle) -> Vec<String> {
    match style {
        CommentStyle::CStyle => extract_c_style_comments(content),
        CommentStyle::Hash => extract_hash_comments(content),
        CommentStyle::Lua => extract_lua_comments(content),
    }
}

/// Extract C-style comments (// and /* */)
fn extract_c_style_comments(content: &str) -> Vec<String> {
    let mut comments = Vec::new();
    let chars: Vec<char> = content.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Skip string literals
        if chars[i] == '"' || chars[i] == '\'' {
            let quote = chars[i];
            i += 1;
            while i < len && chars[i] != quote {
                if chars[i] == '\\' && i + 1 < len {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }

        // Single-line comment
        if i + 1 < len && chars[i] == '/' && chars[i + 1] == '/' {
            let start = i + 2;
            i += 2;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            let comment: String = chars[start..i].iter().collect();
            comments.push(comment);
            continue;
        }

        // Multi-line comment
        if i + 1 < len && chars[i] == '/' && chars[i + 1] == '*' {
            let start = i + 2;
            i += 2;
            while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            let comment: String = chars[start..i].iter().collect();
            comments.push(comment);
            i += 2;
            continue;
        }

        i += 1;
    }

    comments
}

/// Extract hash-style comments (#)
fn extract_hash_comments(content: &str) -> Vec<String> {
    let mut comments = Vec::new();
    let chars: Vec<char> = content.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Skip string literals
        if chars[i] == '"' || chars[i] == '\'' {
            let quote = chars[i];

            // Check for triple quotes
            if i + 2 < len && chars[i + 1] == quote && chars[i + 2] == quote {
                i += 3;
                while i + 2 < len
                    && !(chars[i] == quote && chars[i + 1] == quote && chars[i + 2] == quote)
                {
                    i += 1;
                }
                i += 3;
                continue;
            }

            i += 1;
            while i < len && chars[i] != quote {
                if chars[i] == '\\' && i + 1 < len {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }

        // Hash comment
        if chars[i] == '#' {
            let start = i + 1;
            i += 1;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            let comment: String = chars[start..i].iter().collect();
            comments.push(comment);
            continue;
        }

        i += 1;
    }

    comments
}

/// Extract XML/HTML comments (<!-- -->)
/// Extract Lua comments (-- and --[[ ]])
fn extract_lua_comments(content: &str) -> Vec<String> {
    let mut comments = Vec::new();
    let chars: Vec<char> = content.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        // Skip string literals
        if chars[i] == '"' || chars[i] == '\'' {
            let quote = chars[i];
            i += 1;
            while i < len && chars[i] != quote {
                if chars[i] == '\\' && i + 1 < len {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            continue;
        }

        // Multi-line comment --[[ ]]
        if i + 3 < len
            && chars[i] == '-'
            && chars[i + 1] == '-'
            && chars[i + 2] == '['
            && chars[i + 3] == '['
        {
            let start = i + 4;
            i += 4;
            while i + 1 < len && !(chars[i] == ']' && chars[i + 1] == ']') {
                i += 1;
            }
            let comment: String = chars[start..i].iter().collect();
            comments.push(comment);
            i += 2;
            continue;
        }

        // Single-line comment --
        if i + 1 < len && chars[i] == '-' && chars[i + 1] == '-' {
            let start = i + 2;
            i += 2;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            let comment: String = chars[start..i].iter().collect();
            comments.push(comment);
            continue;
        }

        i += 1;
    }

    comments
}

/// Calculate Shannon entropy of text
fn calculate_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    let total = s.chars().count();

    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }

    freq.values()
        .map(|&count| {
            let p = count as f32 / total as f32;
            if p > 0.0 {
                -p * p.log2()
            } else {
                0.0
            }
        })
        .sum()
}

/// Check if comment contains code-like patterns
fn has_code_patterns(s: &str) -> bool {
    let patterns = [
        "function(",
        "def ",
        "class ",
        "if (",
        "for (",
        "while (",
        "return ",
        "import ",
        "require(",
        "var ",
        "let ",
        "const ",
        "eval(",
        "exec(",
        "= function",
        "=> {",
    ];

    let lower = s.to_lowercase();
    let count = patterns
        .iter()
        .filter(|p| lower.contains(&p.to_lowercase()))
        .count();

    // Multiple code patterns suggest actual code
    count >= 2
}

/// Check if comment contains base64-like data
fn has_base64_pattern(s: &str) -> bool {
    // Look for long sequences of base64 characters
    let words: Vec<&str> = s.split_whitespace().collect();

    for word in words {
        if word.len() >= 20 {
            // Check if it's predominantly base64 charset
            let base64_chars = word
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
                .count();

            if base64_chars as f32 / word.len() as f32 > 0.9 {
                // Check for mixed case (indicative of base64)
                let has_upper = word.chars().any(|c| c.is_ascii_uppercase());
                let has_lower = word.chars().any(|c| c.is_ascii_lowercase());
                if has_upper && has_lower {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_c_style_comments() {
        let code = r#"
            // single line
            /* multi
               line */
            int x = 5; // inline
        "#;
        let comments = extract_c_style_comments(code);
        assert_eq!(comments.len(), 3);
    }

    #[test]
    fn test_hash_comments() {
        let code = "
            # comment 1
            x = 5  # inline
            \"this is a string\"
        ";
        let comments = extract_hash_comments(code);
        assert_eq!(comments.len(), 2);
    }

    #[test]
    fn test_todo_detection() {
        let comments = vec![
            "TODO: fix this".to_string(),
            "normal comment".to_string(),
            "FIXME: broken".to_string(),
        ];
        let metrics = analyze_comment_list(&comments, "");
        assert_eq!(metrics.todo_count, 1);
        assert_eq!(metrics.fixme_count, 1);
    }

    #[test]
    fn test_code_in_comments() {
        let comments = vec![
            "function foo() { var x = 1; return x; }".to_string(),
            "just a normal comment".to_string(),
        ];
        let metrics = analyze_comment_list(&comments, "");
        assert_eq!(metrics.code_in_comments, 1);
    }

    #[test]
    fn test_url_in_comments() {
        let comments = vec![
            "See https://example.com for details".to_string(),
            "normal comment".to_string(),
        ];
        let metrics = analyze_comment_list(&comments, "");
        assert_eq!(metrics.url_in_comments, 1);
    }

    #[test]
    fn test_lua_comments() {
        let code = r#"
            -- single line
            --[[
            multi line
            ]]
            x = 5
        "#;
        let comments = extract_lua_comments(code);
        assert_eq!(comments.len(), 2);
    }
}
