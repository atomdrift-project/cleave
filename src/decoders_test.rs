//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Test utilities for decoder modules.

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

        assert!(decoded.len() > 0);
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

        assert!(decoded.len() > 0);
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

    #[test]
    fn test_extract_base64_shell_command() {
        // Test detection of shell commands in decoded base64
        // "type nul > prueba33.txt" - Windows command to create empty file
        let data = b"os.system(b64d(\"dHlwZSBudWwgPiBwcnVlYmEzMy50eHQ=\"))";
        let decoded = extract_base64_strings(data);

        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].value, "type nul > prueba33.txt");
        assert_eq!(decoded[0].method, "base64");

        // Verify it contains malicious indicators
        assert!(decoded[0].value.contains(">")); // File redirection
        assert!(decoded[0].value.contains(".txt")); // File creation
    }

    #[test]
    fn test_extract_base64_python_payload() {
        // Test detection of Python code in decoded base64
        // Pre-encoded: "import os; os.system('rm -rf /')"
        let encoded = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3JtIC1yZiAvJyk=";
        let data = format!("exec(base64.b64decode('{}'))", encoded);
        let decoded = extract_base64_strings(data.as_bytes());

        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].value.contains("import os"));
        assert!(decoded[0].value.contains("os.system"));
    }

    #[test]
    fn test_extract_base64_python_payload() {
        // Test detection of Python code in decoded base64
        let python_code = "import os; os.system('rm -rf /')";
        let encoded = base64::encode(python_code);
        let data = format!("exec(base64.b64decode('{}'))", encoded);
        let decoded = extract_base64_strings(data.as_bytes());

        assert_eq!(decoded.len(), 1);
        assert!(decoded[0].value.contains("import os"));
        assert!(decoded[0].value.contains("os.system"));
    }
}
