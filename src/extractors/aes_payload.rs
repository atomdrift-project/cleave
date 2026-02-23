//! AES Encrypted Payload Extractor
//!
//! Extracts AES-encrypted payloads from JavaScript/TypeScript files,
//! decrypts them using keys found in the same code, and writes the
//! decrypted content to temp files for analysis.
//!
//! Common malware pattern:
//! ```javascript
//! const crypto = require("crypto");
//! let d = crypto.createDecipheriv("aes-256-cbc", "32-byte-key-here", Buffer.from("hex-iv", "hex"));
//! let b = d.update("hex-ciphertext", "hex", "utf8");
//! b += d.final("utf8");
//! eval(b);
//! ```

use crate::analyzers::FileType;
use regex::Regex;
use std::io::Write;
use std::path::PathBuf;
use std::sync::LazyLock;

/// Represents an extracted AES-encrypted payload
#[derive(Debug)]
pub(crate) struct AesExtractedPayload {
    /// Path to temp file containing decrypted content
    pub temp_path: PathBuf,
    /// Encoding chain (e.g., ["aes-256-cbc"])
    pub encoding_chain: Vec<String>,
    /// Preview of decrypted content (first 40 chars, printable only)
    pub preview: String,
    /// Detected type of decrypted payload
    pub detected_type: FileType,
    /// Byte offset in original file where pattern was found
    pub original_offset: usize,
    /// The algorithm used (e.g., "aes-256-cbc")
    pub algorithm: String,
}

/// Extracted AES parameters from code
#[derive(Debug, Clone)]
struct AesParams {
    /// Algorithm (e.g., "aes-256-cbc")
    algorithm: String,
    /// Raw key bytes
    key: Vec<u8>,
    /// Raw IV bytes
    iv: Vec<u8>,
}

/// Extracted ciphertext from code
#[derive(Debug, Clone)]
struct CiphertextBlob {
    /// Raw ciphertext bytes (decoded from hex)
    data: Vec<u8>,
    /// Offset in source
    offset: usize,
}

/// Maximum recursion depth for nested decryption
const MAX_RECURSION_DEPTH: usize = 3;

/// Minimum ciphertext length (in hex chars) to consider - filters noise
const MIN_CIPHERTEXT_HEX_LEN: usize = 64;

/// Maximum ciphertext length to prevent memory issues (10MB decoded)
const MAX_CIPHERTEXT_BYTES: usize = 10 * 1024 * 1024;

// Pre-compiled regexes for pattern matching
#[allow(clippy::unwrap_used)] // Static regex pattern is hardcoded and valid
static RE_CREATE_DECIPHERIV: LazyLock<Regex> = LazyLock::new(|| {
    // Match: createDecipheriv("aes-256-cbc", "key", Buffer.from("iv", "hex"))
    // Or: createDecipheriv("aes-256-cbc", key_var, iv_var)
    Regex::new(
        r#"createDecipheriv\s*\(\s*["']([^"']+)["']\s*,\s*["']([^"']+)["']\s*,\s*Buffer\.from\s*\(\s*["']([a-fA-F0-9]+)["']\s*,\s*["']hex["']\s*\)"#
    ).unwrap()
});

#[allow(clippy::unwrap_used)] // Static regex pattern is hardcoded and valid
static RE_DECIPHER_UPDATE: LazyLock<Regex> = LazyLock::new(|| {
    // Match: .update("hex_ciphertext", "hex", "utf8")
    // The hex string can be very long (megabytes)
    Regex::new(
        r#"\.update\s*\(\s*["']([a-fA-F0-9]+)["']\s*,\s*["']hex["']\s*,\s*["']utf8["']\s*\)"#,
    )
    .unwrap()
});

#[allow(clippy::unwrap_used)] // Static regex pattern is hardcoded and valid
static RE_HEX_STRING: LazyLock<Regex> = LazyLock::new(|| {
    // Match long hex strings in quotes (potential ciphertext)
    Regex::new(r#"["']([a-fA-F0-9]{64,})["']"#).unwrap()
});

/// Extract AES parameters from JavaScript/TypeScript content
fn extract_aes_params(content: &str) -> Vec<AesParams> {
    let mut params = Vec::new();

    // Find createDecipheriv calls with inline key and IV
    for caps in RE_CREATE_DECIPHERIV.captures_iter(content) {
        let algorithm = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let key_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        let iv_hex = caps.get(3).map(|m| m.as_str()).unwrap_or("");

        // Validate algorithm
        if !is_supported_algorithm(algorithm) {
            continue;
        }

        // Parse key (plain ASCII for aes-256-cbc, must be 32 bytes)
        let key = key_str.as_bytes().to_vec();
        if !is_valid_key_length(algorithm, key.len()) {
            continue;
        }

        // Parse IV (hex encoded, must be 16 bytes for CBC)
        let iv = match hex::decode(iv_hex) {
            Ok(iv) if iv.len() == 16 => iv,
            _ => continue,
        };

        params.push(AesParams {
            algorithm: algorithm.to_string(),
            key,
            iv,
        });
    }

    params
}

/// Extract ciphertext blobs from content
fn extract_ciphertext_blobs(content: &str) -> Vec<CiphertextBlob> {
    let mut blobs = Vec::new();

    // First try to find .update("hex", "hex", "utf8") pattern
    for caps in RE_DECIPHER_UPDATE.captures_iter(content) {
        let hex_str = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        if hex_str.len() < MIN_CIPHERTEXT_HEX_LEN {
            continue;
        }

        if let Ok(data) = hex::decode(hex_str) {
            if data.len() <= MAX_CIPHERTEXT_BYTES {
                blobs.push(CiphertextBlob {
                    data,
                    offset: caps.get(0).map(|m| m.start()).unwrap_or(0),
                });
            }
        }
    }

    // If no .update() pattern found, look for standalone long hex strings
    if blobs.is_empty() {
        for caps in RE_HEX_STRING.captures_iter(content) {
            let hex_str = caps.get(1).map(|m| m.as_str()).unwrap_or("");
            if hex_str.len() < MIN_CIPHERTEXT_HEX_LEN {
                continue;
            }

            // Skip if this looks like an IV (32 hex chars = 16 bytes)
            if hex_str.len() == 32 {
                continue;
            }

            if let Ok(data) = hex::decode(hex_str) {
                if data.len() <= MAX_CIPHERTEXT_BYTES && data.len() % 16 == 0 {
                    // AES block size check
                    blobs.push(CiphertextBlob {
                        data,
                        offset: caps.get(0).map(|m| m.start()).unwrap_or(0),
                    });
                }
            }
        }
    }

    blobs
}

/// Check if algorithm is supported
fn is_supported_algorithm(algo: &str) -> bool {
    matches!(
        algo.to_lowercase().as_str(),
        "aes-256-cbc" | "aes-128-cbc" | "aes256" | "aes128"
    )
}

/// Check if key length is valid for algorithm
fn is_valid_key_length(algo: &str, len: usize) -> bool {
    match algo.to_lowercase().as_str() {
        "aes-256-cbc" | "aes256" => len == 32,
        "aes-128-cbc" | "aes128" => len == 16,
        _ => false,
    }
}

/// Decrypt AES-256-CBC ciphertext
pub(crate) fn decrypt_aes_256_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

    if key.len() != 32 || iv.len() != 16 {
        return None;
    }

    let key_array: [u8; 32] = key.try_into().ok()?;
    let iv_array: [u8; 16] = iv.try_into().ok()?;

    let cipher = Aes256CbcDec::new(&key_array.into(), &iv_array.into());
    let mut buf = ciphertext.to_vec();

    cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .ok()
        .map(<[u8]>::to_vec)
}

/// Decrypt AES-128-CBC ciphertext
pub(crate) fn decrypt_aes_128_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

    if key.len() != 16 || iv.len() != 16 {
        return None;
    }

    let key_array: [u8; 16] = key.try_into().ok()?;
    let iv_array: [u8; 16] = iv.try_into().ok()?;

    let cipher = Aes128CbcDec::new(&key_array.into(), &iv_array.into());
    let mut buf = ciphertext.to_vec();

    cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .ok()
        .map(<[u8]>::to_vec)
}

/// Try to decrypt ciphertext with given params
fn try_decrypt(ciphertext: &[u8], params: &AesParams) -> Option<Vec<u8>> {
    match params.algorithm.to_lowercase().as_str() {
        "aes-256-cbc" | "aes256" => decrypt_aes_256_cbc(ciphertext, &params.key, &params.iv),
        "aes-128-cbc" | "aes128" => decrypt_aes_128_cbc(ciphertext, &params.key, &params.iv),
        _ => None,
    }
}

/// Validate that decrypted content looks reasonable
fn validate_decrypted_content(plaintext: &[u8]) -> bool {
    if plaintext.is_empty() {
        return false;
    }

    // Check if it's valid UTF-8 (most JavaScript payloads are)
    let Ok(text) = std::str::from_utf8(plaintext) else {
        // Could be binary, check for known binary signatures
        if plaintext.len() > 4 {
            // ELF, Mach-O, PE signatures
            if (plaintext[0] == 0x7F && plaintext[1] == b'E')
                || (plaintext[0] == 0xFE && plaintext[1] == 0xED)
                || (plaintext[0] == 0xCA && plaintext[1] == 0xFE)
                || (plaintext[0] == b'M' && plaintext[1] == b'Z')
            {
                return true;
            }
        }
        return false;
    };

    // For text content, check it's not just random garbage

    // Must have some alphanumeric content
    let alpha_count = text.chars().filter(|c| c.is_alphanumeric()).count();
    if alpha_count < plaintext.len() / 4 {
        return false;
    }

    // Check for common code patterns

    text.contains("function")
        || text.contains("const ")
        || text.contains("let ")
        || text.contains("var ")
        || text.contains("import ")
        || text.contains("require(")
        || text.contains("module.")
        || text.contains("exports")
        || text.contains("class ")
        || text.contains("def ")
        || text.contains("if ")
        || text.contains("for ")
        || text.contains("while ")
}

/// Detect the type of decrypted payload
fn detect_payload_type(data: &[u8]) -> FileType {
    // Check if valid UTF-8
    let Ok(text) = std::str::from_utf8(data) else {
        return FileType::Unknown;
    };

    // JavaScript indicators
    if text.contains("function")
        || text.contains("const ")
        || text.contains("let ")
        || text.contains("require(")
        || text.contains("module.exports")
        || text.contains("=>")
        || text.contains("async ")
    {
        return FileType::JavaScript;
    }

    // Python indicators
    if text.contains("def ") || text.contains("import ") || text.contains("class ") {
        return FileType::Python;
    }

    // Shell indicators
    if text.starts_with("#!/") || text.contains("echo ") {
        return FileType::Shell;
    }

    FileType::Unknown
}

/// Generate a preview string (first 40 chars, printable only)
fn generate_preview(data: &[u8]) -> String {
    let is_printable = data.iter().take(40).all(|&b| {
        b.is_ascii_alphanumeric()
            || b.is_ascii_punctuation()
            || b == b' '
            || b == b'\n'
            || b == b'\r'
            || b == b'\t'
    });

    if !is_printable {
        return "<binary data>".to_string();
    }

    let preview_len = data.len().min(40);
    let preview = String::from_utf8_lossy(&data[..preview_len]);
    preview.replace('\n', " ").replace('\r', "")
}

/// Extract all AES-encrypted payloads from JavaScript/TypeScript content
#[must_use]
pub(crate) fn extract_aes_payloads(content: &[u8]) -> Vec<AesExtractedPayload> {
    let mut payloads = Vec::new();

    // Convert to string (AES patterns are in text)
    let Ok(content_str) = std::str::from_utf8(content) else {
        return payloads;
    };

    // Extract AES parameters and ciphertext
    let params_list = extract_aes_params(content_str);
    let ciphertext_list = extract_ciphertext_blobs(content_str);

    if params_list.is_empty() || ciphertext_list.is_empty() {
        return payloads;
    }

    // Try all combinations of params and ciphertext
    for params in &params_list {
        for blob in &ciphertext_list {
            if let Some(decrypted) = try_decrypt(&blob.data, params) {
                // Validate the decrypted content
                if !validate_decrypted_content(&decrypted) {
                    continue;
                }

                // Detect type
                let detected_type = detect_payload_type(&decrypted);

                // Try nested decryption (up to MAX_RECURSION_DEPTH)
                let (final_decrypted, encoding_chain) =
                    decrypt_nested(&decrypted, vec![params.algorithm.clone()], 1);

                // Write to temp file
                if let Ok(temp_file) = tempfile::NamedTempFile::new() {
                    let temp_path = temp_file.path().to_path_buf();

                    if let Ok(mut file) = std::fs::File::create(&temp_path) {
                        if file.write_all(&final_decrypted).is_ok() {
                            let _ = temp_file.keep();

                            payloads.push(AesExtractedPayload {
                                temp_path,
                                encoding_chain,
                                preview: generate_preview(&final_decrypted),
                                detected_type,
                                original_offset: blob.offset,
                                algorithm: params.algorithm.clone(),
                            });

                            // Found a valid decryption, don't try other combinations
                            // for this ciphertext
                            break;
                        }
                    }
                }
            }
        }
    }

    payloads
}

/// Recursively try to decrypt nested AES payloads
fn decrypt_nested(data: &[u8], chain: Vec<String>, depth: usize) -> (Vec<u8>, Vec<String>) {
    if depth >= MAX_RECURSION_DEPTH {
        return (data.to_vec(), chain);
    }

    // Try to find AES patterns in decrypted content
    let Ok(content_str) = std::str::from_utf8(data) else {
        return (data.to_vec(), chain);
    };

    let params_list = extract_aes_params(content_str);
    let ciphertext_list = extract_ciphertext_blobs(content_str);

    if params_list.is_empty() || ciphertext_list.is_empty() {
        return (data.to_vec(), chain);
    }

    // Try first valid decryption
    for params in &params_list {
        for blob in &ciphertext_list {
            if let Some(decrypted) = try_decrypt(&blob.data, params) {
                if validate_decrypted_content(&decrypted) {
                    let mut new_chain = chain.clone();
                    new_chain.push(params.algorithm.clone());
                    return decrypt_nested(&decrypted, new_chain, depth + 1);
                }
            }
        }
    }

    (data.to_vec(), chain)
}

#[cfg(test)]
#[path = "aes_payload_test.rs"]
mod tests;
