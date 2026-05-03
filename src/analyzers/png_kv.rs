//! PNG structural extraction — chunk-table walk for kv synthesis and
//! steganography-relevant metrics.
//!
//! Distinct from `analyzers::png`'s pixel-statistic pass: this module
//! only decodes the chunk header table (no zlib decompression of IDAT
//! or text), so it stays cheap on huge PNGs and complements the
//! pixel-entropy/edge-density analysis with structural signals.
//!
//! # Why these fields
//!
//! Image-as-payload supply-chain attacks (npm/PyPI packages that pull
//! a "logo" PNG and extract a hidden payload) almost always leave one
//! of two structural fingerprints:
//!
//!   * Trailing bytes after the IEND chunk — the loader appends raw
//!     bytes the PNG decoder ignores; trivial for an attacker, very
//!     visible to a chunk walker.
//!   * Oversized or unusual `tEXt`/`zTXt`/`iTXt` chunks holding
//!     base64-encoded payloads.
//!
//! Plus the standard attribution fields (Software, Author, Creation
//! Time, ICC profile name) that supply-chain swap detection diffs
//! across versions.
//!
//! # Schema
//!
//! kv (raw extracted values):
//! ```text
//! png:
//!   text.<key>           tEXt/iTXt/zTXt key → value
//!   time                 tIME chunk as `YYYY-MM-DDTHH:MM:SSZ`
//!   icc_profile_name     iCCP profile name (string before NUL)
//!   color_type           raw IHDR byte (0/2/3/4/6)
//!   interlace_method     raw IHDR byte (0/1)
//!   unknown_chunks       list of 4-letter chunk codes not in the
//!                        standard set
//! ```
//!
//! metrics (counts / interpretations) land on `PngMetrics` via the
//! returned `StructuralCounts` — see `png.rs`.

use serde_json::{json, Map, Value};

/// Counts and interpretations the caller folds into `PngMetrics`.
/// Kept separate from the kv tree so the kv/metrics split stays
/// clean: kv carries raw extracted values, metrics carry derivations.
#[derive(Debug, Default, Clone)]
pub(crate) struct StructuralCounts {
    pub chunks_total: u32,
    pub chunks_idat: u32,
    pub chunks_after_iend: u32,
    pub trailing_bytes: u32,
    pub text_chunks_total_bytes: u32,
    pub unknown_chunks_count: u32,
}

/// Extract structural kv + metrics from PNG bytes. Returns `None` for
/// non-PNG inputs or truncated/malformed headers. Cost is one linear
/// pass over the chunk table — IDAT contents are skipped without
/// decompression.
#[must_use]
pub(crate) fn extract(data: &[u8]) -> Option<(Value, StructuralCounts)> {
    const SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if data.len() < 8 || &data[..8] != SIGNATURE {
        return None;
    }

    let mut counts = StructuralCounts::default();
    let mut text: Map<String, Value> = Map::new();
    let mut time: Option<String> = None;
    let mut icc_profile_name: Option<String> = None;
    let mut color_type: Option<u8> = None;
    let mut interlace_method: Option<u8> = None;
    let mut unknown: Vec<String> = Vec::new();
    let mut iend_seen = false;
    let mut last_chunk_end: usize = 8;

    let mut i = 8usize;
    while i + 8 <= data.len() {
        let length = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let ctype_bytes = &data[i + 4..i + 8];
        let chunk_data_start = i + 8;
        let chunk_end = chunk_data_start.checked_add(length)?.checked_add(4)?; // +4 CRC
        if chunk_end > data.len() {
            // Truncated chunk — stop walking but keep counts so far.
            break;
        }
        last_chunk_end = chunk_end;

        let ctype = std::str::from_utf8(ctype_bytes).unwrap_or("");
        counts.chunks_total = counts.chunks_total.saturating_add(1);
        if iend_seen {
            counts.chunks_after_iend = counts.chunks_after_iend.saturating_add(1);
        }

        let body = &data[chunk_data_start..chunk_data_start + length];
        match ctype {
            "IHDR" if body.len() >= 13 => {
                color_type = Some(body[9]);
                interlace_method = Some(body[12]);
            }
            "IDAT" => counts.chunks_idat = counts.chunks_idat.saturating_add(1),
            "IEND" => iend_seen = true,
            "tEXt" => {
                counts.text_chunks_total_bytes =
                    counts.text_chunks_total_bytes.saturating_add(length as u32);
                if let Some((key, value)) = parse_text_chunk(body) {
                    text.insert(snake_case(&key), json!(value));
                }
            }
            "zTXt" => {
                counts.text_chunks_total_bytes =
                    counts.text_chunks_total_bytes.saturating_add(length as u32);
                if let Some((key, value)) = parse_ztxt_chunk(body) {
                    text.insert(snake_case(&key), json!(value));
                }
            }
            "iTXt" => {
                counts.text_chunks_total_bytes =
                    counts.text_chunks_total_bytes.saturating_add(length as u32);
                if let Some((key, value)) = parse_itxt_chunk(body) {
                    text.insert(snake_case(&key), json!(value));
                }
            }
            "tIME" if body.len() >= 7 => {
                let year = u16::from_be_bytes([body[0], body[1]]);
                time = Some(format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                    year, body[2], body[3], body[4], body[5], body[6]
                ));
            }
            "iCCP" => {
                if let Some(end) = body.iter().position(|&b| b == 0) {
                    if let Ok(s) = std::str::from_utf8(&body[..end]) {
                        if !s.is_empty() {
                            icc_profile_name = Some(s.to_string());
                        }
                    }
                }
            }
            _ if !is_standard_chunk(ctype) => {
                if !ctype.is_empty() && unknown.iter().all(|u| u != ctype) {
                    unknown.push(ctype.to_string());
                }
                counts.unknown_chunks_count = counts.unknown_chunks_count.saturating_add(1);
            }
            _ => {}
        }

        i = chunk_end;
    }

    counts.trailing_bytes = (data.len().saturating_sub(last_chunk_end)) as u32;

    let mut out = Map::new();
    if !text.is_empty() {
        out.insert("text".into(), Value::Object(text));
    }
    if let Some(t) = time {
        out.insert("time".into(), json!(t));
    }
    if let Some(name) = icc_profile_name {
        out.insert("icc_profile_name".into(), json!(name));
    }
    if let Some(ct) = color_type {
        out.insert("color_type".into(), json!(ct));
    }
    if let Some(im) = interlace_method {
        out.insert("interlace_method".into(), json!(im));
    }
    if !unknown.is_empty() {
        out.insert("unknown_chunks".into(), json!(unknown));
    }

    Some((Value::Object(out), counts))
}

/// Standard PNG chunk types (PNG 1.2 spec + APNG + the few that
/// trait authors have specifically asked about). Anything outside
/// this set surfaces in `unknown_chunks` for stego inspection.
fn is_standard_chunk(t: &str) -> bool {
    matches!(
        t,
        "IHDR" | "IDAT" | "IEND" | "PLTE"
            | "tRNS" | "cHRM" | "gAMA" | "iCCP" | "sBIT" | "sRGB"
            | "tEXt" | "zTXt" | "iTXt"
            | "bKGD" | "hIST" | "pHYs" | "sPLT" | "tIME"
            | "eXIf"
            | "acTL" | "fcTL" | "fdAT" // APNG
    )
}

fn parse_text_chunk(body: &[u8]) -> Option<(String, String)> {
    let nul = body.iter().position(|&b| b == 0)?;
    let key = std::str::from_utf8(&body[..nul]).ok()?;
    let val = std::str::from_utf8(body.get(nul + 1..)?).ok()?;
    Some((key.to_string(), val.to_string()))
}

fn parse_ztxt_chunk(body: &[u8]) -> Option<(String, String)> {
    let nul = body.iter().position(|&b| b == 0)?;
    let key = std::str::from_utf8(&body[..nul]).ok()?;
    // body[nul+1] is compression method; body[nul+2..] is zlib payload.
    // We surface the keyword + a placeholder marker; decompression is
    // intentionally skipped to keep the kv pass cheap. Trait authors
    // who need decoded text can target the raw zTXt presence.
    if body.get(nul + 1).copied() != Some(0) {
        return Some((key.to_string(), String::new()));
    }
    Some((key.to_string(), String::new()))
}

fn parse_itxt_chunk(body: &[u8]) -> Option<(String, String)> {
    // iTXt layout: keyword\0 cflag(1) cmethod(1) language\0 translated_kw\0 text
    let kw_end = body.iter().position(|&b| b == 0)?;
    let key = std::str::from_utf8(&body[..kw_end]).ok()?;
    let cflag = *body.get(kw_end + 1)?;
    let cursor = kw_end + 3;
    let lang_end = cursor + body[cursor..].iter().position(|&b| b == 0)?;
    let trans_start = lang_end + 1;
    let trans_end = trans_start + body[trans_start..].iter().position(|&b| b == 0)?;
    let text_bytes = &body[trans_end + 1..];
    if cflag == 0 {
        let text = std::str::from_utf8(text_bytes).ok()?;
        Some((key.to_string(), text.to_string()))
    } else {
        // Compressed iTXt — surface key only; decoded text would
        // require zlib decompression which we skip on the kv path.
        Some((key.to_string(), String::new()))
    }
}

/// Convert a PNG text keyword (free-form, may contain spaces or
/// punctuation) into a snake_case kv-path component. Standard
/// keywords ("Software", "Author", "Creation Time") map to "software",
/// "author", "creation_time".
fn snake_case(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    let mut prev_upper = false;
    for ch in key.chars() {
        if ch.is_ascii_uppercase() {
            // Only insert a boundary underscore at a lower→upper edge,
            // and never doubled (the previous char might already be a
            // separator-derived '_').
            if !prev_upper && !out.is_empty() && !out.ends_with('_') {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
            prev_upper = true;
        } else if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_upper = false;
        } else {
            if !out.is_empty() && !out.ends_with('_') {
                out.push('_');
            }
            prev_upper = false;
        }
    }
    out.trim_matches('_').to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn build_png(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"\x89PNG\r\n\x1a\n");
        for (ctype, body) in chunks {
            out.extend_from_slice(&(body.len() as u32).to_be_bytes());
            out.extend_from_slice(*ctype);
            out.extend_from_slice(body);
            out.extend_from_slice(&[0u8; 4]); // dummy CRC
        }
        out
    }

    fn ihdr_body() -> [u8; 13] {
        let mut b = [0u8; 13];
        b[0..4].copy_from_slice(&100u32.to_be_bytes()); // width
        b[4..8].copy_from_slice(&100u32.to_be_bytes()); // height
        b[8] = 8; // depth
        b[9] = 6; // color type RGBA
        b[10] = 0; // compression
        b[11] = 0; // filter
        b[12] = 0; // interlace
        b
    }

    #[test]
    fn rejects_non_png() {
        assert!(extract(b"not a png").is_none());
    }

    #[test]
    fn surfaces_ihdr_and_text() {
        let png = build_png(&[
            (b"IHDR", &ihdr_body()),
            (b"tEXt", b"Software\0Adobe Photoshop CC"),
            (b"tEXt", b"Author\0Alice"),
            (b"IEND", b""),
        ]);
        let (kv, counts) = extract(&png).unwrap();
        assert_eq!(kv["color_type"], 6);
        assert_eq!(kv["interlace_method"], 0);
        assert_eq!(kv["text"]["software"], "Adobe Photoshop CC");
        assert_eq!(kv["text"]["author"], "Alice");
        assert_eq!(counts.chunks_total, 4);
        assert_eq!(counts.trailing_bytes, 0);
    }

    #[test]
    fn detects_trailing_bytes() {
        let mut png = build_png(&[(b"IHDR", &ihdr_body()), (b"IEND", b"")]);
        png.extend_from_slice(b"PAYLOAD-AFTER-IEND");
        let (_, counts) = extract(&png).unwrap();
        assert_eq!(counts.trailing_bytes, 18);
    }

    #[test]
    fn detects_chunks_after_iend() {
        let png = build_png(&[
            (b"IHDR", &ihdr_body()),
            (b"IEND", b""),
            (b"stEG", b"hidden-payload-bytes"),
        ]);
        let (kv, counts) = extract(&png).unwrap();
        assert_eq!(counts.chunks_after_iend, 1);
        assert_eq!(counts.unknown_chunks_count, 1);
        assert_eq!(kv["unknown_chunks"][0], "stEG");
    }

    #[test]
    fn time_chunk_renders_iso() {
        let mut body = Vec::new();
        body.extend_from_slice(&2024u16.to_be_bytes());
        body.extend_from_slice(&[3, 14, 9, 26, 53]);
        let png = build_png(&[
            (b"IHDR", &ihdr_body()),
            (b"tIME", &body),
            (b"IEND", b""),
        ]);
        let (kv, _) = extract(&png).unwrap();
        assert_eq!(kv["time"], "2024-03-14T09:26:53Z");
    }

    #[test]
    fn icc_profile_name_extracted() {
        let mut body = Vec::new();
        body.extend_from_slice(b"sRGB IEC61966-2.1\0");
        body.push(0); // compression method
        body.extend_from_slice(b"\x78\x9c"); // dummy zlib stream
        let png = build_png(&[
            (b"IHDR", &ihdr_body()),
            (b"iCCP", &body),
            (b"IEND", b""),
        ]);
        let (kv, _) = extract(&png).unwrap();
        assert_eq!(kv["icc_profile_name"], "sRGB IEC61966-2.1");
    }

    #[test]
    fn snake_case_handles_free_form_keys() {
        assert_eq!(snake_case("Software"), "software");
        assert_eq!(snake_case("Creation Time"), "creation_time");
        assert_eq!(snake_case("XML:com.adobe.xmp"), "xml_com_adobe_xmp");
        assert_eq!(snake_case("Author"), "author");
    }
}
