//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for AES encrypted payload extraction
//!
//! Comprehensive tests for AES key extraction, decryption, and payload analysis.

#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use super::super::*;
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    // Helper to encrypt test data with AES-256-CBC
    fn encrypt_aes_256_cbc(
        plaintext: &[u8],
        key: &[u8],
        iv: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        let key_array: [u8; 32] = key.try_into().map_err(|_| "Key must be exactly 32 bytes")?;
        let iv_array: [u8; 16] = iv.try_into().map_err(|_| "IV must be exactly 16 bytes")?;

        let cipher = Aes256CbcEnc::new(&key_array.into(), &iv_array.into());

        Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
    }

    #[test]
    fn test_extract_aes_params_basic() {
        let content = r#"
const crypto = require("crypto");
let d = crypto.createDecipheriv(
    "aes-256-cbc",
    "wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz",
    Buffer.from("dfc1fefb224b2a757b7d3d97a93a1db9", "hex")
);
"#;

        let params = extract_aes_params(content);
        assert_eq!(params.len(), 1, "Should extract one set of AES params");

        let p = &params[0];
        assert_eq!(p.algorithm, "aes-256-cbc");
        assert_eq!(p.key.len(), 32);
        assert_eq!(p.iv.len(), 16);
        assert_eq!(&p.key, b"wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz");
    }

    #[test]
    fn test_extract_aes_params_multiple() {
        let content = r#"
let d1 = createDecipheriv("aes-256-cbc", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Buffer.from("00000000000000000000000000000000", "hex"));
let d2 = createDecipheriv("aes-256-cbc", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Buffer.from("11111111111111111111111111111111", "hex"));
"#;

        let params = extract_aes_params(content);
        assert_eq!(params.len(), 2, "Should extract two sets of AES params");
    }

    #[test]
    fn test_extract_aes_params_invalid_key_length() {
        let content = r#"
let d = createDecipheriv("aes-256-cbc", "short", Buffer.from("00000000000000000000000000000000", "hex"));
"#;

        let params = extract_aes_params(content);
        assert!(params.is_empty(), "Should reject short key");
    }

    #[test]
    fn test_extract_aes_params_invalid_iv() {
        let content = r#"
let d = createDecipheriv("aes-256-cbc", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Buffer.from("short", "hex"));
"#;

        let params = extract_aes_params(content);
        assert!(params.is_empty(), "Should reject invalid IV");
    }

    #[test]
    fn test_extract_ciphertext_with_update() {
        let content = r#"
let b = d.update("1485f244afcf43866a06b845745710a89ee437f9beb945ccdbca8839b38e3a41", "hex", "utf8");
"#;

        let blobs = extract_ciphertext_blobs(content);
        assert_eq!(blobs.len(), 1, "Should extract one ciphertext");
        assert_eq!(
            blobs[0].data.len(),
            32,
            "Should have 32 bytes (64 hex chars)"
        );
    }

    #[test]
    fn test_extract_ciphertext_long_hex() {
        // 128 hex chars = 64 bytes
        let hex_str = "a".repeat(128);
        let content = format!(r#"const encrypted = "{}";"#, hex_str);

        let blobs = extract_ciphertext_blobs(&content);
        assert_eq!(blobs.len(), 1, "Should extract long hex string");
    }

    #[test]
    fn test_extract_ciphertext_too_short() {
        // Only 32 hex chars - too short
        let content = r#"
let b = d.update("00112233445566778899aabbccddeeff", "hex", "utf8");
"#;

        let blobs = extract_ciphertext_blobs(content);
        assert!(blobs.is_empty(), "Should reject short ciphertext");
    }

    #[test]
    fn test_decrypt_aes_256_cbc() {
        let key = b"wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz";
        let iv = hex::decode("dfc1fefb224b2a757b7d3d97a93a1db9").unwrap();
        let plaintext = b"console.log('hello world');";

        // Encrypt
        let ciphertext = encrypt_aes_256_cbc(plaintext, key, &iv)
            .expect("Test uses valid hardcoded 32-byte key and 16-byte IV");

        // Decrypt
        let decrypted = decrypt_aes_256_cbc(&ciphertext, key, &iv);
        assert!(decrypted.is_some(), "Should decrypt successfully");
        assert_eq!(
            decrypted.unwrap(),
            plaintext.to_vec(),
            "Decrypted should match original"
        );
    }

    #[test]
    fn test_decrypt_aes_256_cbc_wrong_key() {
        let key = b"wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz";
        let wrong_key = b"wrongkeywrongkeywrongkeywrongkey";
        let iv = hex::decode("dfc1fefb224b2a757b7d3d97a93a1db9").unwrap();
        let plaintext = b"console.log('hello world');";

        let ciphertext = encrypt_aes_256_cbc(plaintext, key, &iv)
            .expect("Test uses valid hardcoded 32-byte key and 16-byte IV");
        let decrypted = decrypt_aes_256_cbc(&ciphertext, wrong_key, &iv);

        // Wrong key should either fail or produce garbage that fails validation
        if let Some(dec) = decrypted {
            assert!(
                !validate_decrypted_content(&dec),
                "Wrong key should produce invalid content"
            );
        }
    }

    #[test]
    fn test_validate_decrypted_content_javascript() {
        let js_code = b"const x = require('fs'); function foo() { return 42; }";
        assert!(
            validate_decrypted_content(js_code),
            "Should validate JavaScript"
        );
    }

    #[test]
    fn test_validate_decrypted_content_python() {
        let py_code = b"import os\ndef main():\n    print('hello')";
        assert!(
            validate_decrypted_content(py_code),
            "Should validate Python"
        );
    }

    #[test]
    fn test_validate_decrypted_content_garbage() {
        let garbage = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09";
        assert!(
            !validate_decrypted_content(garbage),
            "Should reject binary garbage"
        );
    }

    #[test]
    fn test_validate_decrypted_content_random_text() {
        let random = b"xyz abc 123 !@# $%^";
        assert!(
            !validate_decrypted_content(random),
            "Should reject random text without code patterns"
        );
    }

    #[test]
    fn test_detect_payload_type_javascript() {
        let js = b"const fs = require('fs'); module.exports = {}";
        assert_eq!(
            detect_payload_type(js),
            FileType::JavaScript,
            "Should detect JavaScript"
        );
    }

    #[test]
    fn test_detect_payload_type_python() {
        let py = b"import os\nclass Foo:\n    def bar(self): pass";
        assert_eq!(
            detect_payload_type(py),
            FileType::Python,
            "Should detect Python"
        );
    }

    #[test]
    fn test_detect_payload_type_shell() {
        let sh = b"#!/bin/bash\necho 'hello'";
        assert_eq!(
            detect_payload_type(sh),
            FileType::Shell,
            "Should detect Shell"
        );
    }

    #[test]
    fn test_generate_preview_printable() {
        let code = b"const x = 1; function test() { return x; }";
        let preview = generate_preview(code);
        assert!(preview.len() <= 40);
        assert!(preview.contains("const"));
    }

    #[test]
    fn test_generate_preview_binary() {
        let binary = b"\x7fELF\x01\x00\x00";
        let preview = generate_preview(binary);
        assert_eq!(preview, "<binary data>");
    }

    #[test]
    fn test_full_extraction_pipeline() {
        // Create a realistic malware-like JavaScript content
        let key = b"wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz";
        let iv = hex::decode("dfc1fefb224b2a757b7d3d97a93a1db9").unwrap();
        let payload = b"const os = require('os'); function steal() { return os.homedir(); }";

        let ciphertext = encrypt_aes_256_cbc(payload, key, &iv)
            .expect("Test uses valid hardcoded 32-byte key and 16-byte IV");
        let ciphertext_hex = hex::encode(&ciphertext);

        let malicious_code = format!(
            r#"
const crypto = require("crypto");
let d = crypto.createDecipheriv("aes-256-cbc", "wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz", Buffer.from("dfc1fefb224b2a757b7d3d97a93a1db9", "hex"));
let b = d.update("{}", "hex", "utf8");
b += d.final("utf8");
eval(b);
"#,
            ciphertext_hex
        );

        let payloads = extract_aes_payloads(malicious_code.as_bytes());

        assert_eq!(payloads.len(), 1, "Should extract one payload");

        let p = &payloads[0];
        assert_eq!(p.algorithm, "aes-256-cbc");
        assert_eq!(p.detected_type, FileType::JavaScript);
        assert!(p.preview.contains("const"));

        // Verify temp file contents
        let decrypted = std::fs::read(&p.temp_path).expect("Should read temp file");
        assert_eq!(decrypted, payload.to_vec());

        // Cleanup
        let _ = std::fs::remove_file(&p.temp_path);
    }

    #[test]
    fn test_extraction_with_no_aes_content() {
        let normal_code = r#"
const fs = require('fs');
function readFile(path) {
    return fs.readFileSync(path);
}
"#;

        let payloads = extract_aes_payloads(normal_code.as_bytes());
        assert!(payloads.is_empty(), "Should not extract from normal code");
    }

    #[test]
    fn test_extraction_incomplete_params() {
        // Has createDecipheriv but no ciphertext
        let content = r#"
const crypto = require("crypto");
let d = crypto.createDecipheriv("aes-256-cbc", "wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz", Buffer.from("dfc1fefb224b2a757b7d3d97a93a1db9", "hex"));
// No .update() call
"#;

        let payloads = extract_aes_payloads(content.as_bytes());
        assert!(payloads.is_empty(), "Should not extract without ciphertext");
    }

    #[test]
    fn test_extraction_real_world_pattern() {
        // Pattern from actual ssh-tools malware
        let key = b"wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz";
        let iv = hex::decode("4c4b9a3773e9dced6015a670855fd32b").unwrap();
        let stage1 = b"const child_process = require('child_process'); function exec(cmd) { return child_process.execSync(cmd); }";

        let ciphertext = encrypt_aes_256_cbc(stage1, key, &iv)
            .expect("Test uses valid hardcoded 32-byte key and 16-byte IV");
        let ciphertext_hex = hex::encode(&ciphertext);

        let content = format!(
            r#"
function activate(context) {{
    return __awaiter(this, void 0, void 0, function* () {{
        const d = __webpack_require__(6982).createDecipheriv(
            "aes-256-cbc",
            "wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz",
            Buffer.from("4c4b9a3773e9dced6015a670855fd32b", "hex"),
        );
        let b = d.update(
            "{}",
            "hex",
            "utf8",
        );
        b += d.final("utf8");
        yield eval(b);
    }});
}}
"#,
            ciphertext_hex
        );

        let payloads = extract_aes_payloads(content.as_bytes());
        assert_eq!(payloads.len(), 1, "Should extract from webpack bundle");

        // Cleanup
        for p in payloads {
            let _ = std::fs::remove_file(&p.temp_path);
        }
    }

    #[test]
    fn test_nested_decryption() {
        // Create nested AES encryption: outer encrypts inner encrypted payload
        let inner_key = b"innerkey12345678innerkey12345678";
        let inner_iv = hex::decode("00000000000000000000000000000001").unwrap();
        let final_payload = b"function malicious() { require('child_process').exec('whoami'); }";

        // Encrypt inner payload
        let inner_ciphertext = encrypt_aes_256_cbc(final_payload, inner_key, &inner_iv)
            .expect("Test uses valid hardcoded 32-byte key and 16-byte IV");
        let inner_hex = hex::encode(&inner_ciphertext);

        // Create stage 1 code that decrypts inner
        let stage1 = format!(
            r#"const d = require("crypto").createDecipheriv("aes-256-cbc", "innerkey12345678innerkey12345678", Buffer.from("00000000000000000000000000000001", "hex")); let b = d.update("{}", "hex", "utf8"); b += d.final("utf8"); eval(b);"#,
            inner_hex
        );

        // Encrypt stage 1
        let outer_key = b"outerkey12345678outerkey12345678";
        let outer_iv = hex::decode("ffffffffffffffffffffffffffffffff").unwrap();
        let outer_ciphertext = encrypt_aes_256_cbc(stage1.as_bytes(), outer_key, &outer_iv)
            .expect("Test uses valid hardcoded 32-byte key and 16-byte IV");
        let outer_hex = hex::encode(&outer_ciphertext);

        let content = format!(
            r#"const d = require("crypto").createDecipheriv("aes-256-cbc", "outerkey12345678outerkey12345678", Buffer.from("ffffffffffffffffffffffffffffffff", "hex")); let b = d.update("{}", "hex", "utf8"); b += d.final("utf8"); eval(b);"#,
            outer_hex
        );

        let payloads = extract_aes_payloads(content.as_bytes());
        assert_eq!(payloads.len(), 1, "Should extract nested payload");

        let p = &payloads[0];
        assert!(
            p.encoding_chain.len() >= 2,
            "Should have multiple encoding layers"
        );

        // Verify we got to the final payload
        let decrypted = std::fs::read(&p.temp_path).expect("Should read temp file");
        assert!(
            String::from_utf8_lossy(&decrypted).contains("malicious"),
            "Should decrypt to final payload"
        );

        // Cleanup
        let _ = std::fs::remove_file(&p.temp_path);
    }

    #[test]
    fn test_performance_large_file() {
        // Create a large file with AES encrypted payload at the end
        let key = b"wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz";
        let iv = hex::decode("dfc1fefb224b2a757b7d3d97a93a1db9").unwrap();
        let payload = b"const test = require('test'); function run() { return 42; }";

        let ciphertext = encrypt_aes_256_cbc(payload, key, &iv)
            .expect("Test uses valid hardcoded 32-byte key and 16-byte IV");
        let ciphertext_hex = hex::encode(&ciphertext);

        // Generate ~500KB of padding (realistic webpack bundle)
        let padding = "// ".to_string() + &"x".repeat(500_000) + "\n";

        let content = format!(
            r#"{}
const crypto = require("crypto");
let d = crypto.createDecipheriv("aes-256-cbc", "wDO6YyTm6DL0T0zJ0SXhUql5Mo0pdlSz", Buffer.from("dfc1fefb224b2a757b7d3d97a93a1db9", "hex"));
let b = d.update("{}", "hex", "utf8");
b += d.final("utf8");
eval(b);
"#,
            padding, ciphertext_hex
        );

        let start = std::time::Instant::now();
        let payloads = extract_aes_payloads(content.as_bytes());
        let elapsed = start.elapsed();

        assert_eq!(payloads.len(), 1, "Should extract from large file");
        assert!(
            elapsed.as_millis() < 2000,
            "Should complete in <2 seconds, took {:?}",
            elapsed
        );

        // Cleanup
        for p in payloads {
            let _ = std::fs::remove_file(&p.temp_path);
        }
    }

    #[test]
    fn test_binary_garbage_rejection() {
        // If someone passes binary data that happens to have the pattern
        let mut content = Vec::new();
        content.extend_from_slice(b"createDecipheriv(\"aes-256-cbc\", \"");
        content.extend_from_slice(&[0u8; 32]); // null key
        content.extend_from_slice(b"\", Buffer.from(\"");
        content.extend_from_slice(b"00000000000000000000000000000000"); // hex IV
        content.extend_from_slice(b"\", \"hex\"))");

        let payloads = extract_aes_payloads(&content);
        assert!(payloads.is_empty(), "Should reject binary content");
    }
}
