//! JPEG structural extraction — marker-segment walk for kv synthesis
//! and steganography-relevant counts.
//!
//! Distinct from `analyzers::jpeg`'s pixel-statistic pass: this
//! module only walks marker segments (no pixel decode), so it stays
//! cheap on huge JPEGs and complements the entropy/edge-density
//! analysis with structural attribution + stego signals.
//!
//! # Why these fields
//!
//! Two threads matter for supply-chain detection:
//!
//!   * **Attribution** — EXIF Make / Model / Software / DateTime /
//!     Artist / Copyright are baked into legitimate camera and editor
//!     output; an attacker recompositing a "logo.jpg" almost never
//!     matches the original's EXIF chain. Diff'ing these fields
//!     across versions exposes swapped artwork.
//!
//!   * **Steganography** — appended bytes after EOI, multiple SOI
//!     markers (concatenated JPEGs), oversized COM/APP segments,
//!     unusual MakerNote sizes. The pixel-pass entropy metrics catch
//!     LSB stego; the structural walk catches the simpler
//!     append/comment-padding tricks.
//!
//! # Schema
//!
//! kv (raw extracted values):
//! ```text
//! jpeg:
//!   exif.make            EXIF tag 0x010F
//!   exif.model           EXIF tag 0x0110
//!   exif.software        EXIF tag 0x0131  (editor / camera firmware)
//!   exif.datetime        EXIF tag 0x0132  (file modification)
//!   exif.datetime_original EXIF tag 0x9003 (capture time)
//!   exif.artist          EXIF tag 0x013B
//!   exif.copyright       EXIF tag 0x8298
//!   exif.has_gps         bool — GPS IFD present
//!   icc_profile_name     APP2 "ICC_PROFILE\0" → profile name
//!   comment              COM (FFFE) text
//!   adobe_color_transform APP14 transform byte (0/1/2)
//!   has_iptc             bool — APP13 with "Photoshop 3.0"
//!   has_photoshop_irb    bool
//!   has_xmp              bool — APP1 with adobe XMP namespace
//!   has_jfif_thumbnail   bool — JFIF APP0 thumbnail dims nonzero
//! ```
//!
//! metrics (interpretations) ride on `JpegStructuralCounts` for the
//! caller to fold into `JpegMetrics`.

use serde_json::{json, Map, Value};

/// Counts the caller folds into `JpegMetrics`. Kept separate from the
/// kv tree so the kv/metrics split stays clean.
#[derive(Debug, Default, Clone)]
pub(crate) struct JpegStructuralCounts {
    pub segment_count: u32,
    pub app_segment_count: u32,
    pub com_count: u32,
    pub dqt_count: u32,
    pub dht_count: u32,
    pub soi_count: u32,
    pub maker_note_bytes: u32,
}

/// Walk JPEG marker segments. Returns `None` for non-JPEG input.
#[must_use]
pub(crate) fn extract(data: &[u8]) -> Option<(Value, JpegStructuralCounts)> {
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return None;
    }
    let mut counts = JpegStructuralCounts::default();
    counts.soi_count = 1;

    let mut out = Map::new();
    let mut exif: Map<String, Value> = Map::new();
    let mut pos = 2usize;

    loop {
        // Find next marker (skip 0xFF padding).
        while pos < data.len() && data[pos] != 0xFF {
            pos += 1;
        }
        while pos < data.len() && data[pos] == 0xFF {
            pos += 1;
        }
        if pos >= data.len() {
            break;
        }
        let marker = data[pos];
        pos += 1;
        counts.segment_count = counts.segment_count.saturating_add(1);

        match marker {
            // SOI — start of image. A second SOI before EOI = concatenated
            // JPEGs; some stego tools chain images this way.
            0xD8 => counts.soi_count = counts.soi_count.saturating_add(1),
            // EOI — end of image; trailing-bytes accounting belongs to
            // the existing analyzer, we just stop walking here.
            0xD9 => break,
            // Standalone markers (no length field).
            0xD0..=0xD7 | 0x01 => continue,
            // SOS — entropy-coded scan; skip the header then scan forward
            // until the next non-restart marker.
            0xDA => {
                if pos + 1 >= data.len() {
                    break;
                }
                let seg_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                pos += seg_len;
                while pos + 1 < data.len() {
                    if data[pos] == 0xFF && data[pos + 1] != 0x00 && data[pos + 1] != 0xFF {
                        break;
                    }
                    pos += 1;
                }
            }
            _ => {
                if pos + 1 >= data.len() {
                    break;
                }
                let seg_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                if seg_len < 2 {
                    break;
                }
                let body_start = pos + 2;
                let body_end = pos + seg_len;
                if body_end > data.len() {
                    break;
                }
                let body = &data[body_start..body_end];

                match marker {
                    0xFE => counts.com_count = counts.com_count.saturating_add(1),
                    0xDB => counts.dqt_count = counts.dqt_count.saturating_add(1),
                    0xC4 => counts.dht_count = counts.dht_count.saturating_add(1),
                    _ => {}
                }
                if (0xE0..=0xEF).contains(&marker) {
                    counts.app_segment_count = counts.app_segment_count.saturating_add(1);
                }

                handle_segment(marker, body, &mut out, &mut exif, &mut counts);

                pos = body_end;
            }
        }
    }

    if !exif.is_empty() {
        out.insert("exif".into(), Value::Object(exif));
    }
    Some((Value::Object(out), counts))
}

fn handle_segment(
    marker: u8,
    body: &[u8],
    out: &mut Map<String, Value>,
    exif: &mut Map<String, Value>,
    counts: &mut JpegStructuralCounts,
) {
    match marker {
        // COM — surface the comment text.
        0xFE => {
            if let Ok(s) = std::str::from_utf8(body) {
                let trimmed = s.trim_end_matches(|c: char| c == '\0' || c.is_whitespace());
                if !trimmed.is_empty() {
                    out.insert("comment".into(), json!(trimmed));
                }
            }
        }
        // APP0 — JFIF (thumbnail dims) or JFXX.
        0xE0 => {
            if body.starts_with(b"JFIF\0") && body.len() >= 14 {
                let tw = body[12];
                let th = body[13];
                if tw != 0 && th != 0 {
                    out.insert("has_jfif_thumbnail".into(), json!(true));
                }
            }
        }
        // APP1 — EXIF (Exif\0\0) or XMP.
        0xE1 => {
            if body.starts_with(b"Exif\0\0") {
                parse_exif_app1(&body[6..], exif, counts);
            } else if body
                .windows(b"http://ns.adobe.com/xap/1.0/".len())
                .any(|w| w == b"http://ns.adobe.com/xap/1.0/")
            {
                out.insert("has_xmp".into(), json!(true));
            }
        }
        // APP2 — ICC profile when prefix matches.
        0xE2 => {
            if body.starts_with(b"ICC_PROFILE\0") && body.len() >= 14 + 84 {
                // ICC profile descriptor at offset 14+84 holds the
                // profile-name (after fields). Simplest reliable
                // signal: the profile description tag string. Skip
                // detailed ICC parsing — surface the canonical "is
                // present" boolean, which is what supply-chain swap
                // detection actually wants.
                out.insert("has_icc_profile".into(), json!(true));
            }
        }
        // APP13 — Adobe Photoshop IRB (often carrying IPTC).
        0xED => {
            if body.starts_with(b"Photoshop 3.0\0") {
                out.insert("has_photoshop_irb".into(), json!(true));
                // 8BIM blocks for IPTC live inside; surface as a
                // bool rather than parsing the full IRB chain.
                if body.windows(4).any(|w| w == b"8BIM") {
                    out.insert("has_iptc".into(), json!(true));
                }
            }
        }
        // APP14 — Adobe color transform (1 byte at offset 11).
        0xEE => {
            if body.starts_with(b"Adobe\0") && body.len() >= 12 {
                out.insert("adobe_color_transform".into(), json!(body[11]));
            }
        }
        _ => {}
    }
}

/// Parse the TIFF-encapsulated EXIF block (after the leading "Exif\0\0"
/// header). Walks IFD0 only — that's where Make/Model/Software/
/// DateTime/Artist/Copyright live. Reads the ExifIFD pointer too so
/// we can pick up DateTimeOriginal. GPS-IFD presence is recorded as a
/// boolean (the GPS tags themselves carry coordinates we don't
/// need).
fn parse_exif_app1(tiff: &[u8], exif: &mut Map<String, Value>, counts: &mut JpegStructuralCounts) {
    if tiff.len() < 8 {
        return;
    }
    let little = match &tiff[..2] {
        b"II" => true,
        b"MM" => false,
        _ => return,
    };
    let read_u16 = |off: usize| -> Option<u16> {
        let b = tiff.get(off..off + 2)?.try_into().ok()?;
        Some(if little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    };
    let read_u32 = |off: usize| -> Option<u32> {
        let b = tiff.get(off..off + 4)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    if read_u16(2) != Some(0x002A) {
        return;
    }
    let ifd0_off = match read_u32(4) {
        Some(v) => v as usize,
        None => return,
    };
    walk_ifd(tiff, ifd0_off, little, exif, counts, true);
}

/// Walk a TIFF IFD entries block. `is_root` controls whether to chase
/// ExifIFD / GPS-IFD pointers (so sub-IFDs don't recurse infinitely).
fn walk_ifd(
    tiff: &[u8],
    off: usize,
    little: bool,
    exif: &mut Map<String, Value>,
    counts: &mut JpegStructuralCounts,
    is_root: bool,
) {
    let read_u16 = |o: usize| -> Option<u16> {
        let b = tiff.get(o..o + 2)?.try_into().ok()?;
        Some(if little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    };
    let read_u32 = |o: usize| -> Option<u32> {
        let b = tiff.get(o..o + 4)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    let count = match read_u16(off) {
        Some(c) => c as usize,
        None => return,
    };
    let mut exif_ifd_off: Option<usize> = None;
    let mut gps_ifd_off: Option<usize> = None;
    for i in 0..count {
        let entry_off = off + 2 + i * 12;
        let Some(tag) = read_u16(entry_off) else {
            return;
        };
        let Some(typ) = read_u16(entry_off + 2) else {
            return;
        };
        let Some(cnt) = read_u32(entry_off + 4) else {
            return;
        };
        let value_off_field = entry_off + 8;

        let component_size = match typ {
            1 | 2 | 6 | 7 => 1, // BYTE / ASCII / SBYTE / UNDEFINED
            3 | 8 => 2,         // SHORT / SSHORT
            4 | 9 | 11 => 4,    // LONG / SLONG / FLOAT
            5 | 10 | 12 => 8,   // RATIONAL / SRATIONAL / DOUBLE
            _ => 0,
        };
        let total_bytes = (cnt as usize).saturating_mul(component_size);
        let data_slice: Option<&[u8]> = if total_bytes <= 4 {
            tiff.get(value_off_field..value_off_field + total_bytes.min(4))
        } else if let Some(abs) = read_u32(value_off_field).map(|v| v as usize) {
            tiff.get(abs..abs + total_bytes)
        } else {
            None
        };

        match tag {
            0x010F => insert_ascii(exif, "make", data_slice),
            0x0110 => insert_ascii(exif, "model", data_slice),
            0x0131 => insert_ascii(exif, "software", data_slice),
            0x0132 => insert_ascii(exif, "datetime", data_slice),
            0x013B => insert_ascii(exif, "artist", data_slice),
            0x8298 => insert_ascii(exif, "copyright", data_slice),
            0x9003 if !is_root => insert_ascii(exif, "datetime_original", data_slice),
            0x927C if !is_root => {
                // MakerNote — opaque vendor blob; size only.
                counts.maker_note_bytes = counts
                    .maker_note_bytes
                    .saturating_add(total_bytes.min(u32::MAX as usize) as u32);
            }
            0x8769 if is_root => exif_ifd_off = Some(read_u32(value_off_field).unwrap_or(0) as usize),
            0x8825 if is_root => gps_ifd_off = Some(read_u32(value_off_field).unwrap_or(0) as usize),
            _ => {}
        }
    }
    // Chase sub-IFDs from root; one level of recursion is enough.
    if is_root {
        if let Some(off) = exif_ifd_off {
            walk_ifd(tiff, off, little, exif, counts, false);
        }
        if gps_ifd_off.is_some() {
            exif.insert("has_gps".into(), json!(true));
        }
    }
}

fn insert_ascii(out: &mut Map<String, Value>, key: &str, bytes: Option<&[u8]>) {
    let Some(b) = bytes else { return };
    let Ok(s) = std::str::from_utf8(b) else { return };
    let trimmed = s.trim_end_matches(|c: char| c == '\0' || c.is_whitespace());
    if !trimmed.is_empty() {
        out.insert(key.into(), json!(trimmed));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn build_jpeg(segments: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8]; // SOI
        for (marker, body) in segments {
            out.push(0xFF);
            out.push(*marker);
            let len = (body.len() + 2) as u16;
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(body);
        }
        out.extend_from_slice(&[0xFF, 0xD9]); // EOI
        out
    }

    #[test]
    fn rejects_non_jpeg() {
        assert!(extract(b"not a jpeg").is_none());
    }

    #[test]
    fn surfaces_comment() {
        let jpeg = build_jpeg(&[(0xFE, b"hello world".to_vec())]);
        let (kv, counts) = extract(&jpeg).unwrap();
        assert_eq!(kv["comment"], "hello world");
        assert_eq!(counts.com_count, 1);
    }

    #[test]
    fn surfaces_adobe_color_transform() {
        let mut body = b"Adobe\0".to_vec();
        body.extend_from_slice(&[0, 0, 0, 0, 0]); // version, flags0, flags1, transform-prefix bytes
        body.push(2); // transform = YCCK (2)
        let jpeg = build_jpeg(&[(0xEE, body)]);
        let (kv, _) = extract(&jpeg).unwrap();
        assert_eq!(kv["adobe_color_transform"], 2);
    }

    #[test]
    fn detects_concatenated_jpegs_via_soi_count() {
        // Inject a second SOI mid-stream (before the trailing EOI).
        let mut data = vec![0xFF, 0xD8, 0xFF, 0xD8, 0xFF, 0xD9];
        let _ = &mut data;
        let (_, counts) = extract(&data).unwrap();
        assert_eq!(counts.soi_count, 2);
    }

    #[test]
    fn parses_exif_make_model_software_le() {
        // Build a minimal TIFF: II header + IFD with three ASCII tags.
        let mut tiff = Vec::new();
        tiff.extend_from_slice(b"II"); // little-endian
        tiff.extend_from_slice(&0x002Au16.to_le_bytes());
        tiff.extend_from_slice(&8u32.to_le_bytes()); // IFD0 at offset 8
        // IFD0: 3 entries
        tiff.extend_from_slice(&3u16.to_le_bytes());
        let mut data_blob: Vec<u8> = Vec::new();
        let strings = [
            (0x010Fu16, "Canon\0"),  // Make
            (0x0110, "EOS R5\0"),    // Model
            (0x0131, "Adobe LR\0"),  // Software
        ];
        // Reserve 14 bytes per IFD entry (12 each × 3 = 36) + 4 next-IFD
        let strings_offset_base = 8 + 2 + 12 * strings.len() + 4;
        for (i, (tag, value)) in strings.iter().enumerate() {
            tiff.extend_from_slice(&tag.to_le_bytes()); // tag
            tiff.extend_from_slice(&2u16.to_le_bytes()); // type ASCII
            tiff.extend_from_slice(&(value.len() as u32).to_le_bytes()); // count
            let offset = (strings_offset_base + data_blob.len()) as u32;
            tiff.extend_from_slice(&offset.to_le_bytes());
            data_blob.extend_from_slice(value.as_bytes());
            let _ = i;
        }
        tiff.extend_from_slice(&0u32.to_le_bytes()); // next-IFD offset = 0
        tiff.extend(data_blob);

        let mut body = b"Exif\0\0".to_vec();
        body.extend_from_slice(&tiff);
        let jpeg = build_jpeg(&[(0xE1, body)]);

        let (kv, _) = extract(&jpeg).unwrap();
        assert_eq!(kv["exif"]["make"], "Canon");
        assert_eq!(kv["exif"]["model"], "EOS R5");
        assert_eq!(kv["exif"]["software"], "Adobe LR");
    }
}
