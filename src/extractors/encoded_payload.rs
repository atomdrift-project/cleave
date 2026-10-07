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

/// Decompress data if it's compressed, returns (decompressed_bytes, compression_type)
fn decompress_if_compressed(data: &[u8]) -> Option<(Vec<u8>, String)> {
    use flate2::read::{GzDecoder, ZlibDecoder};
    use std::io::Read;

    if matches!(data, [0x78, 0x9c | 0x01 | 0xda, _, ..]) {
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
    } else if matches!(data, [0x1f, 0x8b, _, ..]) {
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
    use base64::{Engine as _, engine::general_purpose::STANDARD};

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

/// Alphabet compatibility alone does not establish another encoding layer:
/// hashes and identifiers also decode as base64/hex, usually into opaque bytes.
/// Keep the already decoded text unless the candidate has readable content or
/// a recognized binary header. Header detection is bounded and uses no filename
/// or heuristic classification. Successful decompression is checked separately.
fn supports_nested_encoding(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    if std::str::from_utf8(data).is_ok_and(|text| {
        text.chars()
            .all(|c| !c.is_control() || matches!(c, '\n' | '\r' | '\t'))
    }) {
        return true;
    }
    filefacts::fileid::detect_content(&data[..data.len().min(4096)]).is_some()
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

        // Check for additional base64 (nested). `is_base64_candidate` already
        // enforces the MIN_PAYLOAD_LENGTH floor.
        if is_base64_candidate(text)
            && let Some((decoded, compression)) = decode_base64(text)
            && (compression.is_some() || supports_nested_encoding(&decoded))
        {
            chain.push("base64".to_string());
            if let Some(comp_type) = compression {
                chain.push(comp_type);
            }
            return decompress_and_nest(&decoded, chain, depth + 1);
        }

        // Check for additional hex (nested). `is_hex_string` already enforces
        // the 48-char floor.
        if is_hex_string(text)
            && let Some(decoded) = decode_hex_string(text)
            && supports_nested_encoding(&decoded)
        {
            chain.push("hex".to_string());
            return decompress_and_nest(&decoded, chain, depth + 1);
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

/// Decode MIME attachment bodies using only their declared transfer encoding.
/// Keep the supported binary formats bounded; no attachment is executed.
pub(crate) fn extract_mime_attachments(data: &[u8]) -> Vec<ExtractedPayload> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    if data.len() > 10 * 1024 * 1024 {
        return Vec::new();
    }
    let Ok(source) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let lower = source.to_ascii_lowercase();
    if !lower.contains("mime-version:") || !lower.contains("multipart/") {
        return Vec::new();
    }
    let Ok(parts) = regex::Regex::new(
        r"(?im)content-transfer-encoding:[ \t]*base64[^\r\n]*\r?\n(?:[^\r\n]+\r?\n)*\r?\n([A-Za-z0-9+/=\r\n]+)",
    ) else {
        return Vec::new();
    };
    parts
        .captures_iter(source)
        .take(16)
        .filter_map(|caps| {
            let body = caps.get(1)?;
            let compact: String = body
                .as_str()
                .chars()
                .filter(|c| !c.is_ascii_whitespace())
                .collect();
            let decoded = STANDARD.decode(compact).ok()?;
            let detected_type = if decoded.starts_with(b"PK\x03\x04") {
                FileType::Zip
            } else if decoded.starts_with(b"MZ") {
                FileType::Pe
            } else if decoded.starts_with(b"\x7fELF") {
                FileType::Elf
            } else {
                return None;
            };
            Some(ExtractedPayload {
                preview: generate_preview(&decoded),
                data: decoded,
                encoding_chain: vec!["mime-base64".to_string()],
                detected_type,
                original_offset: body.start(),
            })
        })
        .collect()
}

/// Reconstruct literal low/high nibble tables consumed by a script interpreter.
/// This evaluates only decimal literals, never the surrounding program. Bounds
/// and an explicit reconstruction/dispatch shape keep ordinary CSV data out.
pub(crate) fn extract_nibble_table_payloads(data: &[u8]) -> Vec<ExtractedPayload> {
    if data.len() > 1024 * 1024 {
        return Vec::new();
    }
    let Ok(source) = std::str::from_utf8(data) else {
        return Vec::new();
    };
    let lower = source.to_ascii_lowercase();
    let is_powershell = lower.contains("addscript") && lower.contains("[int]");
    let is_vbs = lower.contains("chr(clng(") && lower.contains("\nexecute ");
    if !is_powershell && !is_vbs {
        return Vec::new();
    }
    let mut decoded = Vec::new();
    let offset;
    if is_powershell {
        let Ok(formula) = regex::Regex::new(r"(?i)\[int\].{0,40}\*\s*16\s*\+\s*\[int\]") else {
            return Vec::new();
        };
        if !formula.is_match(source) {
            return Vec::new();
        }
        let Ok(row) = regex::Regex::new(r"(?m)^\d{1,8},(\d{1,2}),(\d{1,2})\r?$") else {
            return Vec::new();
        };
        offset = row.find(source).map_or(0, |m| m.start());
        for caps in row.captures_iter(source) {
            let (Ok(lo), Ok(hi)) = (caps[1].parse::<u8>(), caps[2].parse::<u8>()) else {
                return Vec::new();
            };
            if lo > 15 || hi > 15 {
                return Vec::new();
            }
            decoded.push(hi * 16 + lo);
        }
    } else {
        let Ok(formula) = regex::Regex::new(r"(?i)Chr\(CLng\([^\r\n]{1,60}\)\*16\+CLng") else {
            return Vec::new();
        };
        if !formula.is_match(source) {
            return Vec::new();
        }
        let Ok(chunks) = regex::Regex::new(r#""([0-9.,]+)""#) else {
            return Vec::new();
        };
        offset = chunks.find(source).map_or(0, |m| m.start());
        let joined: String = chunks
            .captures_iter(source)
            .filter_map(|c| {
                let chunk = &c[1];
                (chunk == ","
                    || chunk.split(',').filter(|s| !s.is_empty()).all(|pair| {
                        pair.split_once('.').is_some_and(|(lo, hi)| {
                            !lo.is_empty()
                                && !hi.is_empty()
                                && lo.bytes().all(|b| b.is_ascii_digit())
                                && hi.bytes().all(|b| b.is_ascii_digit())
                        })
                    }))
                .then(|| chunk.to_string())
            })
            .collect();
        for pair in joined.split(',').filter(|s| !s.is_empty()) {
            let Some((lo, hi)) = pair.split_once('.') else {
                return Vec::new();
            };
            let (Ok(lo), Ok(hi)) = (lo.parse::<u8>(), hi.parse::<u8>()) else {
                return Vec::new();
            };
            if lo > 15 || hi > 15 {
                return Vec::new();
            }
            decoded.push(hi * 16 + lo);
        }
    }
    if decoded.len() < MIN_PAYLOAD_LENGTH || !supports_nested_encoding(&decoded) {
        return Vec::new();
    }
    vec![ExtractedPayload {
        preview: generate_preview(&decoded),
        data: decoded,
        encoding_chain: vec!["nibble-table".to_string()],
        detected_type: if is_powershell {
            FileType::PowerShell
        } else {
            FileType::Vbs
        },
        original_offset: offset,
    }]
}

/// A whole file that is a PE under a repeating XOR key: a dropper's payload
/// shipped as opaque bytes. filefacts recovered the key while identifying the
/// file, so this only decodes, and the image joins the other decoded payloads.
/// The image is binary, so the text nesting in [`decompress_and_nest`] has
/// nothing to add.
#[must_use]
pub(crate) fn xor_encoded_pe(fileid: &filefacts::FileId, data: &[u8]) -> Option<ExtractedPayload> {
    let key = fileid.xor_pe_key()?;
    let image_offset = key.pe_offset();
    let image = key.decode(data).get(image_offset..)?.to_vec();
    Some(ExtractedPayload {
        preview: generate_preview(&image),
        data: image,
        encoding_chain: vec!["xor".to_string()],
        detected_type: FileType::Pe,
        original_offset: image_offset,
    })
}

/// Reuse stng's located single-byte keys to recover whole universal Mach-O
/// images. No second section scan or key search; exact extents and slice
/// validation stay in stng. Bound both candidate work and retained bytes.
pub(crate) fn xor_encoded_machos(
    data: &[u8],
    strings: &[stng::ExtractedString],
) -> Vec<ExtractedPayload> {
    let mut out = Vec::new();
    let mut total = 0usize;
    for candidate in strings
        .iter()
        .filter(|s| {
            s.kind == Some(stng::StringKind::XorKey)
                && s.method == stng::StringMethod::XorDecode
                && s.value.len() == 4
                && s.value.starts_with("0x")
        })
        .take(8)
    {
        let Ok(offset) = usize::try_from(candidate.data_offset) else {
            continue;
        };
        if out
            .iter()
            .any(|p: &ExtractedPayload| p.original_offset == offset)
        {
            continue;
        }
        let Ok(key) = u8::from_str_radix(&candidate.value[2..], 16) else {
            continue;
        };
        let Some(tail) = data.get(offset..) else {
            continue;
        };
        let Some(image) = stng::decode_xor_fat_macho(tail, key) else {
            continue;
        };
        total += image.len();
        if total > 32 * 1024 * 1024 {
            break;
        }
        out.push(ExtractedPayload {
            preview: "Universal Mach-O image".to_string(),
            data: image,
            encoding_chain: vec!["xor".to_string()],
            detected_type: FileType::MachO,
            original_offset: offset,
        });
    }
    out
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
    let preview = generate_preview(&final_bytes);

    payloads.push(ExtractedPayload {
        data: final_bytes,
        encoding_chain: final_chain,
        preview,
        detected_type: FileType::Unknown, // Will be determined during recursive analysis
        original_offset: decoded_str.data_offset as usize,
    });
}

#[cfg(test)]
#[path = "encoded_payload_test.rs"]
mod tests;
