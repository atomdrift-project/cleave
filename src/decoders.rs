//! Decoders for extracting hidden content (base64, xor, etc.)
//! Note: This module is deprecated. Use StringInfo with encoding_chain instead.

use crate::types::DecodedString;

/// Extract and decode base64 strings from binary data
/// Returns decoded strings that are valid UTF-8 and > 10 characters
#[must_use]
pub fn extract_base64_strings(data: &[u8]) -> Vec<DecodedString> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let mut results = Vec::new();

    // Find base64-like sequences (alphanumeric + +/= characters, min 12 chars to catch short IPs)
    let text = String::from_utf8_lossy(data);
    let Ok(base64_pattern) = regex::Regex::new(r"[A-Za-z0-9+/]{12,}={0,2}") else {
        return results;
    };

    for mat in base64_pattern.find_iter(&text) {
        let encoded = mat.as_str();

        // Try to decode
        if let Ok(decoded_bytes) = STANDARD.decode(encoded) {
            // Check if decoded content is valid UTF-8 and meaningful
            if let Ok(decoded_str) = String::from_utf8(decoded_bytes) {
                // Skip if decoded string is too short or not interesting
                if decoded_str.len() < 10 {
                    continue;
                }

                // Check if decoded string contains printable ASCII (heuristic for real content)
                let printable_ratio = decoded_str
                    .chars()
                    .filter(|c| c.is_ascii() && !c.is_control())
                    .count() as f32
                    / decoded_str.len() as f32;

                if printable_ratio > 0.7 {
                    let encoded_preview = if encoded.len() > 100 {
                        format!("{}...", &encoded[..100])
                    } else {
                        encoded.to_string()
                    };

                    results.push(DecodedString {
                        value: decoded_str,
                        encoded: encoded_preview,
                        method: "base64".to_string(),
                        key: None,
                        offset: Some(format!("0x{:x}", mat.start())),
                    });
                }
            }
        }
    }

    results
}

/// Extract XOR-decoded strings using common single-byte XOR keys
/// Returns decoded strings for keys 0x01-0xFF that produce valid UTF-8
#[must_use]
pub fn extract_xor_strings(data: &[u8]) -> Vec<DecodedString> {
    let mut results = Vec::new();

    // Only try XOR decoding on files < 1MB to avoid performance issues
    if data.len() > 1_000_000 {
        return results;
    }

    // Try common XOR keys (skip 0x20 - that's just case toggling, not obfuscation)
    let common_keys = [0x01, 0x02, 0x42, 0x55, 0xAA, 0xFF];

    for key in common_keys {
        let decoded: Vec<u8> = data.iter().map(|b| b ^ key).collect();

        // Check if decoded bytes contain interesting strings
        if let Ok(decoded_str) = String::from_utf8(decoded.clone()) {
            // Look for interesting patterns in decoded content
            if decoded_str.contains("http://")
                || decoded_str.contains("https://")
                || decoded_str.contains("eval(")
                || decoded_str.contains("exec(")
            {
                // Extract the interesting substring
                let interesting_part = if let Some(pos) = decoded_str.find("http") {
                    let start = pos;
                    let end = (pos + 100).min(decoded_str.len());
                    decoded_str[start..end].to_string()
                } else if let Some(pos) = decoded_str.find("eval(") {
                    let start = pos.saturating_sub(10);
                    let end = (pos + 50).min(decoded_str.len());
                    decoded_str[start..end].to_string()
                } else {
                    decoded_str[..100.min(decoded_str.len())].to_string()
                };

                results.push(DecodedString {
                    value: interesting_part,
                    encoded: format!("XOR-encoded data ({} bytes)", data.len()),
                    method: "xor".to_string(),
                    key: Some(format!("0x{:02x}", key)),
                    offset: None,
                });
                break; // One match per key is enough
            }
        }
    }

    results
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_base64_strings_basic() {
        let data = b"const x = 'aGVsbG8gd29ybGQ='; // hello world";
        let decoded = extract_base64_strings(data);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].value, "hello world");
        assert_eq!(decoded[0].method, "base64");
    }

    #[test]
    fn test_extract_base64_url() {
        let data = b"var url = 'aHR0cHM6Ly9ldmlsLmNvbS9wYXlsb2FkLnNo';";
        let decoded = extract_base64_strings(data);

        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].value.contains("https://"));
        assert!(decoded[0].value.contains("evil.com"));
    }

    #[test]
    fn test_extract_base64_min_length() {
        // Too short (< 10 chars decoded)
        let data = b"const x = 'aGk='; // 'hi'";
        let decoded = extract_base64_strings(data);

        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn test_extract_base64_min_encoded_length() {
        // Less than 20 chars encoded should be ignored
        let data = b"const x = 'SGVsbG8=';"; // "Hello" - only 12 chars
        let decoded = extract_base64_strings(data);

        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn test_extract_base64_non_printable() {
        // Binary data that decodes but isn't printable
        let data = b"const x = 'AQIDBAUGAAAAAAAAAAAAAAAAAAA=';";
        let decoded = extract_base64_strings(data);

        // Should be filtered out due to low printable ratio
        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn test_extract_xor_strings_http() {
        let plaintext = b"https://evil.com/payload";
        let key = 0x42;
        let encoded: Vec<u8> = plaintext.iter().map(|b| b ^ key).collect();

        let decoded = extract_xor_strings(&encoded);

        assert!(!decoded.is_empty());
        assert!(decoded[0].value.contains("https://"));
        assert_eq!(decoded[0].method, "xor");
        assert_eq!(decoded[0].key, Some("0x42".to_string()));
    }

    #[test]
    fn test_extract_xor_strings_eval() {
        let plaintext = b"eval(atob('malicious'))";
        let key = 0x55;
        let encoded: Vec<u8> = plaintext.iter().map(|b| b ^ key).collect();

        let decoded = extract_xor_strings(&encoded);

        assert!(!decoded.is_empty());
        assert!(decoded[0].value.contains("eval("));
    }

    #[test]
    fn test_extract_xor_skips_0x20() {
        // XOR with 0x20 just toggles case - should not be detected
        let plaintext = b"Hello World https://test.com";
        let encoded: Vec<u8> = plaintext.iter().map(|b| b ^ 0x20).collect();

        let decoded = extract_xor_strings(&encoded);

        // Should be empty since we skip 0x20
        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn test_extract_xor_large_file_skipped() {
        // Files > 1MB should be skipped for performance
        let large_data = vec![0x42; 1_500_000];
        let decoded = extract_xor_strings(&large_data);

        assert_eq!(decoded.len(), 0);
    }

    #[test]
    fn test_base64_performance() {
        // Test on a realistic minified file size
        let data = vec![b'A'; 100_000];

        let start = std::time::Instant::now();
        let _decoded = extract_base64_strings(&data);
        let elapsed = start.elapsed();

        // Should complete in < 100ms
        assert!(
            elapsed.as_millis() < 100,
            "Base64 extraction took {}ms",
            elapsed.as_millis()
        );
    }

    #[test]
    fn test_xor_performance() {
        // Test XOR performance on reasonable file size
        let data = vec![0x42; 500_000];

        let start = std::time::Instant::now();
        let _decoded = extract_xor_strings(&data);
        let elapsed = start.elapsed();

        // Should complete in < 500ms (7 keys to try)
        assert!(
            elapsed.as_millis() < 500,
            "XOR extraction took {}ms",
            elapsed.as_millis()
        );
    }
}
