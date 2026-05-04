//! `png.*` kv subtree — PNG chunk-table walk for structural
//! attribution (Software, Author, ICC profile, tIME) plus
//! steganography signals (trailing bytes, post-IEND chunks,
//! unknown chunk types).
//!
//! No zlib pass; complements the pixel-statistic analysis in
//! `analyzers::png`. Schema is the [`PngKv`] struct; counts ride
//! on [`StructuralCounts`].

use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// Strongly-typed `png.*` kv tree.
#[derive(Default, Serialize)]
struct PngKv {
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    text: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icc_profile_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    color_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interlace_method: Option<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    unknown_chunks: Vec<String>,
}

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
    let mut kv = PngKv::default();
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
                kv.color_type = Some(body[9]);
                kv.interlace_method = Some(body[12]);
            }
            "IDAT" => counts.chunks_idat = counts.chunks_idat.saturating_add(1),
            "IEND" => iend_seen = true,
            "tEXt" | "zTXt" | "iTXt" => {
                counts.text_chunks_total_bytes =
                    counts.text_chunks_total_bytes.saturating_add(length as u32);
                if let Some((key, value)) = parse_text_chunk_variant(ctype, body) {
                    kv.text.insert(snake_case(&key), value);
                }
            }
            "tIME" if body.len() >= 7 => {
                let year = u16::from_be_bytes([body[0], body[1]]);
                kv.time = Some(format!(
                    "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                    year, body[2], body[3], body[4], body[5], body[6]
                ));
            }
            "iCCP" => {
                if let Some(end) = body.iter().position(|&b| b == 0) {
                    if let Ok(s) = std::str::from_utf8(&body[..end]) {
                        if !s.is_empty() {
                            kv.icc_profile_name = Some(s.to_string());
                        }
                    }
                }
            }
            _ if !is_standard_chunk(ctype) => {
                if !ctype.is_empty() && kv.unknown_chunks.iter().all(|u| u != ctype) {
                    kv.unknown_chunks.push(ctype.to_string());
                }
                counts.unknown_chunks_count = counts.unknown_chunks_count.saturating_add(1);
            }
            _ => {}
        }

        i = chunk_end;
    }

    counts.trailing_bytes = (data.len().saturating_sub(last_chunk_end)) as u32;

    Some((serde_json::to_value(kv).ok()?, counts))
}

/// Standard PNG chunk types (PNG 1.2 spec + APNG + the few that
/// trait authors have specifically asked about). Anything outside
/// this set surfaces in `unknown_chunks` for stego inspection.
fn is_standard_chunk(t: &str) -> bool {
    matches!(
        t,
        "IHDR"
            | "IDAT"
            | "IEND"
            | "PLTE"
            | "tRNS"
            | "cHRM"
            | "gAMA"
            | "iCCP"
            | "sBIT"
            | "sRGB"
            | "tEXt"
            | "zTXt"
            | "iTXt"
            | "bKGD"
            | "hIST"
            | "pHYs"
            | "sPLT"
            | "tIME"
            | "eXIf"
            | "acTL"
            | "fcTL"
            | "fdAT" // APNG
    )
}

/// Parse the keyword + value out of any PNG text chunk variant.
/// All three (`tEXt`, `zTXt`, `iTXt`) start with a NUL-terminated
/// keyword; what differs is what follows. We surface the keyword
/// always, the text value only when it's plain (uncompressed) UTF-8,
/// and an empty value otherwise — decoded text from compressed
/// chunks would need a zlib pass that the kv layer intentionally
/// skips.
fn parse_text_chunk_variant(ctype: &str, body: &[u8]) -> Option<(String, String)> {
    let kw_end = body.iter().position(|&b| b == 0)?;
    let key = std::str::from_utf8(&body[..kw_end]).ok()?.to_string();
    let value = match ctype {
        "tEXt" => std::str::from_utf8(body.get(kw_end + 1..)?)
            .ok()?
            .to_string(),
        "zTXt" => String::new(), // compression method byte + zlib payload
        "iTXt" => {
            // iTXt: keyword\0 cflag(1) cmethod(1) language\0 translated_kw\0 text
            let cflag = *body.get(kw_end + 1)?;
            let after_meta = kw_end + 3;
            let lang_end = after_meta + body.get(after_meta..)?.iter().position(|&b| b == 0)?;
            let trans_start = lang_end + 1;
            let trans_end = trans_start + body.get(trans_start..)?.iter().position(|&b| b == 0)?;
            if cflag == 0 {
                std::str::from_utf8(body.get(trans_end + 1..)?)
                    .ok()?
                    .to_string()
            } else {
                String::new()
            }
        }
        _ => return None,
    };
    Some((key, value))
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
        let png = build_png(&[(b"IHDR", &ihdr_body()), (b"tIME", &body), (b"IEND", b"")]);
        let (kv, _) = extract(&png).unwrap();
        assert_eq!(kv["time"], "2024-03-14T09:26:53Z");
    }

    #[test]
    fn icc_profile_name_extracted() {
        let mut body = Vec::new();
        body.extend_from_slice(b"sRGB IEC61966-2.1\0");
        body.push(0); // compression method
        body.extend_from_slice(b"\x78\x9c"); // dummy zlib stream
        let png = build_png(&[(b"IHDR", &ihdr_body()), (b"iCCP", &body), (b"IEND", b"")]);
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
