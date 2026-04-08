//! Encoded Payload Extractor
//!
//! Extracts encoded payloads from files using stng for detection, handles
//! compression/decompression, and writes decoded payloads to temp files for analysis.
//!
//! **Division of Responsibilities:**
//! - **stng**: Detects and decodes all encoding types (base64, hex, URL, XOR, etc.)
//! - **cleave**: Handles compression (zlib/gzip), nested encoding, and payload classification

use crate::analyzers::FileType;
use crate::types::ExtractedPayload;

/// Maximum recursion depth for nested encoding
const MAX_RECURSION_DEPTH: usize = 3;
/// Minimum decoded payload length to consider (24 bytes)
const MIN_PAYLOAD_LENGTH: usize = 24;

/// Encoding methods from stng that represent decoded content
const DECODED_METHODS: &[stng::StringMethod] = &[
    stng::StringMethod::Base64Decode,
    stng::StringMethod::Base64ObfuscatedDecode,
    stng::StringMethod::HexDecode,
    stng::StringMethod::UrlDecode,
    stng::StringMethod::UnicodeEscapeDecode,
    stng::StringMethod::Base32Decode,
    stng::StringMethod::Base85Decode,
    stng::StringMethod::XorDecode,
];

/// Map stng StringMethod to encoding name for meta tags and encoding chains
fn method_to_encoding_name(method: stng::StringMethod) -> &'static str {
    match method {
        stng::StringMethod::Base64Decode | stng::StringMethod::Base64ObfuscatedDecode => "base64",
        stng::StringMethod::HexDecode => "hex",
        stng::StringMethod::UrlDecode => "url",
        stng::StringMethod::UnicodeEscapeDecode => "unicode-escape",
        stng::StringMethod::Base32Decode => "base32",
        stng::StringMethod::Base85Decode => "base85",
        stng::StringMethod::XorDecode => "xor",
        stng::StringMethod::Utf16LeDecode => "utf16le",
        stng::StringMethod::Utf16BeDecode => "utf16be",
        _ => "unknown",
    }
}

/// Check if a string is a valid base64 candidate (for nested detection)
/// Uses MIN_PAYLOAD_LENGTH (24 bytes) for nested detection
#[must_use]
pub(crate) fn is_base64_candidate(s: &str) -> bool {
    // Check minimum length (lower threshold for nested detection)
    if s.len() < MIN_PAYLOAD_LENGTH {
        return false;
    }

    // Length should be multiple of 4 (with padding) — check early to skip char validation
    if !s.len().is_multiple_of(4) {
        return false;
    }

    // Check valid base64 characters using direct byte checks (no HashSet allocation)
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return false;
    }

    // Check padding (max 2 '=' at end)
    let padding_count = s.bytes().rev().take_while(|&b| b == b'=').count();
    if padding_count > 2 {
        return false;
    }

    true
}

/// Check if a string is hex-encoded (for nested detection)
fn is_hex_string(s: &str) -> bool {
    // Must be at least 48 chars (24 bytes when decoded) and all hex digits
    s.len() >= 48 && s.len().is_multiple_of(2) && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Decode hex string (for nested detection)
fn decode_hex_string(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }

    let mut decoded = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte_str = &s[i..i + 2];
        if let Ok(byte) = u8::from_str_radix(byte_str, 16) {
            decoded.push(byte);
        } else {
            return None;
        }
    }

    Some(decoded)
}

/// Maximum size for decompressed payloads to prevent decompression bombs
const MAX_DECOMPRESSED_SIZE: usize = 50 * 1024 * 1024; // 50 MB

/// Check if data is zlib-compressed (magic bytes: 0x78 0x9C/0x01/0xDA)
fn is_zlib_compressed(data: &[u8]) -> bool {
    data.len() > 2 && data[0] == 0x78 && (data[1] == 0x9C || data[1] == 0x01 || data[1] == 0xDA)
}

/// Check if data is gzip-compressed (magic bytes: 0x1F 0x8B)
fn is_gzip_compressed(data: &[u8]) -> bool {
    data.len() > 2 && data[0] == 0x1F && data[1] == 0x8B
}

/// Decompress data if it's compressed, returns (decompressed_bytes, compression_type)
fn decompress_if_compressed(data: &[u8]) -> Option<(Vec<u8>, String)> {
    use flate2::read::{GzDecoder, ZlibDecoder};
    use std::io::Read;

    if is_zlib_compressed(data) {
        let decoder = ZlibDecoder::new(data);
        let mut decompressed = Vec::with_capacity(data.len() * 4);

        match decoder
            .take(MAX_DECOMPRESSED_SIZE as u64)
            .read_to_end(&mut decompressed)
        {
            Ok(_) if decompressed.len() < MAX_DECOMPRESSED_SIZE => {
                Some((decompressed, "zlib".to_string()))
            }
            _ => None,
        }
    } else if is_gzip_compressed(data) {
        let decoder = GzDecoder::new(data);
        let mut decompressed = Vec::with_capacity(data.len() * 4);

        match decoder
            .take(MAX_DECOMPRESSED_SIZE as u64)
            .read_to_end(&mut decompressed)
        {
            Ok(_) if decompressed.len() < MAX_DECOMPRESSED_SIZE => {
                Some((decompressed, "gzip".to_string()))
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Decode base64 string, checking for and decompressing zlib or gzip if present
/// Returns the decoded data and the compression algorithm used (if any)
/// NOTE: This is kept for nested decoding only. Initial base64 detection uses stng.
#[must_use]
pub(crate) fn decode_base64(encoded: &str) -> Option<(Vec<u8>, Option<String>)> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    // Strip whitespace before decoding
    let cleaned: String = encoded
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();

    // Try base64 decode
    let decoded = STANDARD.decode(&cleaned).ok()?;

    // Check for compression using helper function
    if let Some((decompressed, comp_type)) = decompress_if_compressed(&decoded) {
        return Some((decompressed, Some(comp_type)));
    }

    Some((decoded, None))
}

/// Generate a preview string (first 40 chars, printable only)
#[must_use]
pub(crate) fn generate_preview(data: &[u8]) -> String {
    // Check if data is printable ASCII
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

    // Take first 40 bytes and convert to string
    let preview_len = data.len().min(40);
    let preview = String::from_utf8_lossy(&data[..preview_len]);

    // Replace newlines with spaces for display
    preview.replace('\n', " ").replace('\r', "")
}

/// Recursively decompress and check for nested encodings
/// This handles compression + nested base64/hex that stng doesn't process
pub(crate) fn decompress_and_nest(
    data: &[u8],
    mut chain: Vec<String>,
    depth: usize,
) -> (Vec<u8>, Vec<String>) {
    if depth >= MAX_RECURSION_DEPTH {
        return (data.to_vec(), chain);
    }

    // Check for compression (cleave-specific: stng doesn't decompress)
    if let Some((decompressed, comp_type)) = decompress_if_compressed(data) {
        chain.push(comp_type);
        // Recursively check decompressed data
        return decompress_and_nest(&decompressed, chain, depth + 1);
    }

    // Check if data contains additional encoding
    if let Ok(text) = std::str::from_utf8(data) {
        let text = text.trim();

        // Check for additional base64 (nested)
        if text.len() >= MIN_PAYLOAD_LENGTH && is_base64_candidate(text) {
            if let Some((decoded, compression)) = decode_base64(text) {
                chain.push("base64".to_string());
                if let Some(comp_type) = compression {
                    chain.push(comp_type);
                }
                return decompress_and_nest(&decoded, chain, depth + 1);
            }
        }

        // Check for additional hex (nested)
        if text.len() >= 48 && is_hex_string(text) {
            if let Some(decoded) = decode_hex_string(text) {
                chain.push("hex".to_string());
                return decompress_and_nest(&decoded, chain, depth + 1);
            }
        }
    }

    (data.to_vec(), chain)
}

/// Extract all encoded payloads from stng-extracted strings
/// stng_strings should be the result of calling stng::extract_strings_with_options() once
pub fn extract_encoded_payloads(stng_strings: &[stng::ExtractedString]) -> Vec<ExtractedPayload> {
    let mut payloads = Vec::new();

    // Filter for decoded strings from ANY encoding method
    let decoded_strings: Vec<_> = stng_strings
        .iter()
        .filter(|s| DECODED_METHODS.contains(&s.method))
        .filter(|s| s.value.len() >= MIN_PAYLOAD_LENGTH) // Minimum 24 bytes
        .collect();

    tracing::trace!(
        "Processing {} total strings from stng, {} decoded strings, {} meet size threshold",
        stng_strings.len(),
        stng_strings
            .iter()
            .filter(|s| DECODED_METHODS.contains(&s.method))
            .count(),
        decoded_strings.len()
    );

    // Process each decoded string through compression/nesting pipeline
    for decoded_str in decoded_strings {
        process_decoded_string(decoded_str, &mut payloads);
    }

    // NOTE: We used to manually scan RawScan strings for base64 patterns here,
    // but stng now handles all base64 detection and decoding automatically,
    // including base64 embedded in code like: exec(base64.b64decode('...'))
    // This redundant scanning was causing major performance issues on large files.

    payloads
}

/// Process a decoded string from stng and add to payloads
fn process_decoded_string(
    decoded_str: &stng::ExtractedString,
    payloads: &mut Vec<ExtractedPayload>,
) {
    let decoded_bytes = decoded_str.value.as_bytes();

    // Start encoding chain with stng's detection
    let encoding_chain = vec![method_to_encoding_name(decoded_str.method).to_string()];

    // cleave: Check for compression and nested encoding
    let (final_bytes, final_chain) = decompress_and_nest(decoded_bytes, encoding_chain, 0);

    // Store decoded content in memory for recursive analysis
    payloads.push(ExtractedPayload {
        data: final_bytes.clone(),
        encoding_chain: final_chain,
        preview: generate_preview(&final_bytes),
        detected_type: FileType::Unknown, // Will be determined during recursive analysis
        original_offset: decoded_str.data_offset as usize,
    });
}

#[cfg(test)]
#[path = "encoded_payload_test.rs"]
mod tests;
