//! Lenient PDF byte-scan extractor.
//!
//! PDF malware analysis tools (peepdf, pdfid, dpd) take this
//! approach because strict PDF parsers (lopdf etc.) reject
//! deliberately-malformed PDFs by design — exactly the documents
//! we want to analyze. We never attempt:
//!
//! - Cross-reference table reconstruction (xref / xref-stream).
//! - Decryption, even for known-empty passwords.
//! - Complete PDF stream filter coverage (we decode common JS/ObjStm cases).
//! - Object-graph traversal (refs are recorded as text, not chased).
//!
//! What we DO recover, robustly, against adversarial input:
//!
//! - Every `%PDF-1.x` header occurrence.
//! - Every `<id> <gen> obj … endobj` body, with top-level dict keys.
//! - The most recent `trailer << … >>` dict.
//! - `%%EOF`, `trailer`, and `startxref` counts.
//! - Stream filter chains and malformed stream-length/delimiter facts.
//! - Action dicts (`/S /JavaScript`, `/S /Launch`, …) and their
//!   targets / snippets.
//! - Embedded-file records via `/Type /Filespec` and `/Names
//!   /EmbeddedFiles`.
//! - `/Info` dict string values when reachable from the trailer.

use super::types::{
    PdfAction, PdfActionKind, PdfDocument, PdfEmbeddedFile, PdfFormField, PdfHeader, PdfObject,
    PdfStreamAnomalies, PdfStreamRecord, PdfStructural, PdfTrailer,
};
use std::collections::{BTreeMap, BTreeSet};

/// Maximum object body byte length captured per object. Keeps memory
/// bounded for adversarial inputs that pile huge streams into a
/// single object body.
const MAX_OBJECT_BODY: usize = 1 << 20;

/// Maximum total objects extracted. Caps work on PDFs with >50K
/// objects (legitimate large PDFs run ~50K; anything more is
/// usually an artifact).
const MAX_OBJECTS: usize = 100_000;

/// Maximum length of a captured action snippet (JavaScript / URI /
/// command line). Trait authors can pattern-match on snippets up
/// to this size.
const MAX_SNIPPET: usize = 512;

/// Maximum stream bytes captured per object before truncation.
/// Trait detection on JS streams works comfortably within this; the
/// bound caps memory on adversarial inputs that pile huge streams.
const MAX_STREAM_BYTES: usize = 256 * 1024;

/// Maximum decoded payload size we'll keep after filter decoding.
/// JS streams are usually < 32KB; this gives headroom without
/// unbounded zip-bomb risk.
const MAX_DECODED_BYTES: usize = 1 << 20;

/// Maximum decoded form-field value exposed to kv. This catches staged
/// JavaScript in hidden fields without letting unbounded form values bloat
/// reports.
const MAX_FORM_FIELD_DECODED_VALUE: usize = 128 * 1024;

/// Maximum decoded stream text exposed to kv. This is enough for exploit API
/// strings and small scripts while keeping reports bounded.
const MAX_DECODED_STREAM_TEXT: usize = 4096;

/// Run the lenient extractor over PDF bytes. Always returns a
/// document — empty when the file isn't a PDF or recovery fails
/// completely. Callers should check `headers.is_empty()` to detect
/// "not a PDF" cleanly.
#[must_use]
pub(crate) fn parse(data: &[u8]) -> PdfDocument {
    let headers = scan_headers(data);
    if headers.is_empty() {
        return PdfDocument {
            headers,
            ..Default::default()
        };
    }
    let mut objects = scan_objects(data);
    let visible_object_count = objects.len();
    let object_stream_objects = scan_object_stream_objects(&objects);
    let object_stream_inner_object_count = object_stream_objects.len();
    objects.extend(object_stream_objects);
    let trailer = scan_trailer(data);
    let structural = compute_structural(
        data,
        &objects,
        &trailer,
        visible_object_count,
        object_stream_inner_object_count,
    );
    let actions = collect_actions(&objects, &trailer);
    let embedded_files = collect_embedded_files(&objects);
    let streams = collect_stream_records(&objects);
    let form_fields = collect_form_fields(&objects);
    let info = collect_info_dict(&objects, &trailer);
    let eof_count = scan_eof_count(data);
    PdfDocument {
        headers,
        eof_count,
        objects,
        structural,
        actions,
        embedded_files,
        streams,
        form_fields,
        info,
    }
}

// ---------------------------------------------------------------------------
// %PDF- header scan
// ---------------------------------------------------------------------------

fn scan_headers(data: &[u8]) -> Vec<PdfHeader> {
    let mut out = Vec::new();
    let needle = b"%PDF-";
    let mut start = 0;
    // Cap the search at first 4KB to avoid quadratic behavior on
    // adversarial inputs that pad headers throughout.
    let bound = data.len().min(64 * 1024);
    while start + needle.len() <= bound {
        let Some(pos) = find_subslice(&data[start..bound], needle) else {
            break;
        };
        let abs = start + pos;
        // Capture up to whitespace.
        let mut end = abs + needle.len();
        while end < data.len() && !is_ws(data[end]) {
            end += 1;
            if end - abs > 16 {
                break;
            }
        }
        let version = String::from_utf8_lossy(&data[abs + needle.len()..end]).to_string();
        out.push(PdfHeader { version });
        start = abs + needle.len();
    }
    out
}

fn scan_eof_count(data: &[u8]) -> u32 {
    let mut count: u32 = 0;
    let needle = b"%%EOF";
    let mut start = 0;
    while start + needle.len() <= data.len() {
        let Some(pos) = find_subslice(&data[start..], needle) else {
            break;
        };
        count = count.saturating_add(1);
        start = start + pos + needle.len();
    }
    count
}

// ---------------------------------------------------------------------------
// Object scan: find every "ID GEN obj ... endobj" pair
// ---------------------------------------------------------------------------

fn scan_objects(data: &[u8]) -> Vec<PdfObject> {
    let mut out = Vec::new();
    let mut start = 0;
    while out.len() < MAX_OBJECTS && start < data.len() {
        // Find the next "obj" keyword.
        let Some(obj_rel) = find_subslice(&data[start..], b"obj") else {
            break;
        };
        let obj_pos = start + obj_rel;
        // Parse `<id> <gen> obj` backwards from obj_pos. The id and
        // gen are the two whitespace-separated decimals immediately
        // preceding `obj`. We back up past whitespace and digits.
        let Some(id) = parse_object_header(&data[..obj_pos]) else {
            start = obj_pos + 3;
            continue;
        };
        // Body runs from after `obj` to next `endobj`.
        let body_start = obj_pos + 3;
        let endobj_rel = find_subslice(&data[body_start..], b"endobj");
        let body_end = match endobj_rel {
            Some(rel) => body_start + rel,
            None => data.len().min(body_start + MAX_OBJECT_BODY),
        };
        let body_len = (body_end - body_start).min(MAX_OBJECT_BODY);
        let body = &data[body_start..body_start + body_len];

        let (dict, dict_raw) = parse_top_level_dict_with_raw(body);
        let stream_meta = parse_stream_meta(body, &dict);
        let stream_bytes = if stream_meta.has_stream && !stream_meta.anomalies.missing_endstream {
            extract_stream_bytes(body)
        } else {
            Vec::new()
        };
        let raw_value = parse_direct_object_value(body, stream_meta.has_stream, !dict.is_empty());

        out.push(PdfObject {
            id,
            dict,
            dict_raw,
            raw_value,
            stream_filters: stream_meta.filters,
            stream_bytes,
            stream_anomalies: stream_meta.anomalies,
        });
        start = if endobj_rel.is_some() {
            body_end + b"endobj".len()
        } else {
            body_end
        };
    }
    out
}

/// Walk back from a slice end to recover `<id> <gen>`. Returns
/// Parse the `<id> <gen> obj` header backwards from just before the
/// `obj` keyword. Returns the object id; gen and header offset are
/// not consumed by any caller and are dropped.
fn parse_object_header(prefix: &[u8]) -> Option<u32> {
    // Skip trailing whitespace before `obj`, then the gen digits, then
    // the inter-token whitespace, then the id digits.
    let mut end = prefix.len();
    while end > 0 && is_ws(prefix[end - 1]) {
        end -= 1;
    }
    while end > 0 && prefix[end - 1].is_ascii_digit() {
        end -= 1;
    }
    while end > 0 && is_ws(prefix[end - 1]) {
        end -= 1;
    }
    let id_end = end;
    while end > 0 && prefix[end - 1].is_ascii_digit() {
        end -= 1;
    }
    let id_start = end;
    if id_start == id_end {
        return None;
    }
    std::str::from_utf8(&prefix[id_start..id_end])
        .ok()?
        .parse()
        .ok()
}

fn parse_direct_object_value(body: &[u8], has_stream: bool, has_dict: bool) -> String {
    if has_stream || has_dict {
        return String::new();
    }
    let trimmed = trim_bytes(body);
    if trimmed.is_empty() {
        String::new()
    } else {
        truncate(&String::from_utf8_lossy(trimmed), MAX_SNIPPET)
    }
}

fn scan_object_stream_objects(objects: &[PdfObject]) -> Vec<PdfObject> {
    let mut out = Vec::new();
    let mut existing_ids: BTreeSet<u32> = objects.iter().map(|o| o.id).collect();

    for obj in objects {
        if obj.dict.get("Type").map(|v| v.trim()) != Some("/ObjStm") {
            continue;
        }
        let Some(decoded) = decoded_stream_bytes(obj) else {
            continue;
        };
        let n = obj
            .dict
            .get("N")
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        let first = obj
            .dict
            .get("First")
            .and_then(|v| v.trim().parse::<usize>().ok())
            .unwrap_or(0);
        if n == 0 || first >= decoded.len() {
            continue;
        }
        let index = parse_object_stream_index(&decoded[..first], n);
        let object_area = &decoded[first..];
        for (idx, (id, offset)) in index.iter().copied().enumerate() {
            if out.len() + objects.len() >= MAX_OBJECTS || existing_ids.contains(&id) {
                continue;
            }
            if offset >= object_area.len() {
                continue;
            }
            let end = index
                .get(idx + 1)
                .map(|(_, next)| (*next).min(object_area.len()))
                .unwrap_or(object_area.len());
            if end <= offset {
                continue;
            }
            let body = &object_area[offset..end];
            let (dict, dict_raw) = parse_top_level_dict_with_raw(body);
            let raw_value = parse_direct_object_value(body, false, !dict.is_empty());
            out.push(PdfObject {
                id,
                dict,
                dict_raw,
                raw_value,
                stream_filters: Vec::new(),
                stream_bytes: Vec::new(),
                stream_anomalies: PdfStreamAnomalies::default(),
            });
            existing_ids.insert(id);
        }
    }

    out
}

fn parse_object_stream_index(header: &[u8], max_objects: usize) -> Vec<(u32, usize)> {
    let mut nums = header
        .split(|b| is_ws(*b))
        .filter(|s| !s.is_empty())
        .filter_map(|s| std::str::from_utf8(s).ok()?.parse::<usize>().ok());
    let mut out = Vec::new();
    while out.len() < max_objects {
        let Some(id) = nums.next() else {
            break;
        };
        let Some(offset) = nums.next() else {
            break;
        };
        if let Ok(id) = u32::try_from(id) {
            out.push((id, offset));
        }
    }
    out.sort_by_key(|(_, offset)| *offset);
    out
}

fn decoded_stream_bytes(obj: &PdfObject) -> Option<Vec<u8>> {
    if obj.stream_bytes.is_empty() {
        return None;
    }
    if obj.stream_filters.is_empty() {
        Some(obj.stream_bytes.clone())
    } else {
        decode_filters(&obj.stream_bytes, &obj.stream_filters)
    }
}

// ---------------------------------------------------------------------------
// Top-level dict parsing: capture `/Name <value>` pairs at depth 1
// ---------------------------------------------------------------------------

fn parse_top_level_dict_with_raw(
    body: &[u8],
) -> (BTreeMap<String, String>, BTreeMap<String, Vec<u8>>) {
    let mut out = BTreeMap::new();
    let mut raw_out = BTreeMap::new();
    // Find the outermost `<<` … `>>` pair in the body.
    let Some(open) = find_subslice(body, b"<<") else {
        return (out, raw_out);
    };
    let Some(close) = find_matching_dict_close(&body[open..]) else {
        return (out, raw_out);
    };
    let dict_bytes = &body[open + 2..open + close];
    walk_top_level_pairs(dict_bytes, &mut out, &mut raw_out);
    (out, raw_out)
}

/// Find the matching `>>` for an opening `<<` at byte 0 of slice.
/// Returns the byte offset (relative to slice start) of the close,
/// accounting for nested dicts and strings.
fn find_matching_dict_close(slice: &[u8]) -> Option<usize> {
    if slice.len() < 4 || &slice[..2] != b"<<" {
        return None;
    }
    let mut depth: i32 = 1;
    let mut i = 2;
    while i + 1 < slice.len() {
        match (slice[i], slice[i + 1]) {
            (b'<', b'<') => {
                depth += 1;
                i += 2;
            }
            (b'>', b'>') => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
                i += 2;
            }
            (b'(', _) => {
                // Skip balanced literal-string `(...)` with PDF
                // backslash escapes. Don't peek depth changes inside.
                i = skip_paren_string(slice, i);
            }
            _ => i += 1,
        }
    }
    None
}

fn skip_paren_string(slice: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    let mut depth: i32 = 1;
    while i < slice.len() && depth > 0 {
        match slice[i] {
            b'\\' => i += 2, // skip escaped char
            b'(' => {
                depth += 1;
                i += 1;
            }
            b')' => {
                depth -= 1;
                i += 1;
            }
            _ => i += 1,
        }
    }
    i
}

/// Walk a dict body capturing top-level `/Name <value>` pairs. Values
/// span until the next `/Name` at the same depth, or end of slice.
fn walk_top_level_pairs(
    body: &[u8],
    out: &mut BTreeMap<String, String>,
    raw_out: &mut BTreeMap<String, Vec<u8>>,
) {
    let mut i = 0;
    while i < body.len() {
        if body[i] != b'/' {
            i += 1;
            continue;
        }
        // Read the name token.
        let name_start = i + 1;
        let mut name_end = name_start;
        while name_end < body.len() && is_name_char(body[name_end]) {
            name_end += 1;
        }
        if name_end == name_start {
            i += 1;
            continue;
        }
        let name = String::from_utf8_lossy(&body[name_start..name_end]).to_string();
        // Skip whitespace before value.
        let mut value_start = name_end;
        while value_start < body.len() && is_ws(body[value_start]) {
            value_start += 1;
        }
        // Value runs until the next top-level `/Name` boundary or end.
        // We need to track nesting: `<< >>`, `[ ]`, `( )`.
        let value_end = scan_value_end(body, value_start);
        let raw = trim_bytes(&body[value_start..value_end]).to_vec();
        let value_text = String::from_utf8_lossy(&raw).trim().to_string();
        raw_out.insert(name.clone(), raw);
        out.insert(name, value_text);
        i = value_end;
    }
}

fn scan_value_end(body: &[u8], start: usize) -> usize {
    let mut i = start;
    let mut emitted_leading_name = false;
    while i < body.len() {
        match body[i] {
            b'/' => {
                // Values can themselves be `/Name` (e.g. `/Type
                // /Catalog`). Allow exactly one leading-name token at
                // the start of the value; subsequent `/`s are
                // boundaries.
                if !emitted_leading_name && i == start {
                    emitted_leading_name = true;
                    i += 1;
                    while i < body.len() && is_name_char(body[i]) {
                        i += 1;
                    }
                } else {
                    return i;
                }
            }
            b'<' if body.get(i + 1) == Some(&b'<') => {
                let nested_close = find_matching_dict_close(&body[i..]);
                match nested_close {
                    Some(off) => i += off + 2,
                    None => return body.len(),
                }
            }
            b'[' => {
                i = skip_array(body, i);
            }
            b'(' => {
                i = skip_paren_string(body, i);
            }
            _ => i += 1,
        }
    }
    i
}

fn skip_array(body: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    let mut depth: i32 = 1;
    while i < body.len() && depth > 0 {
        match body[i] {
            b'[' => {
                depth += 1;
                i += 1;
            }
            b']' => {
                depth -= 1;
                i += 1;
            }
            b'(' => i = skip_paren_string(body, i),
            b'<' if body.get(i + 1) == Some(&b'<') => {
                let off = find_matching_dict_close(&body[i..]).unwrap_or(0);
                i += off + 2;
            }
            _ => i += 1,
        }
    }
    i
}

// ---------------------------------------------------------------------------
// Stream metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct StreamMeta {
    has_stream: bool,
    filters: Vec<String>,
    anomalies: PdfStreamAnomalies,
}

fn parse_stream_meta(body: &[u8], dict: &BTreeMap<String, String>) -> StreamMeta {
    let stream_pos = find_subslice(body, b"stream");
    let has_stream = stream_pos.is_some();
    let mut anomalies = PdfStreamAnomalies {
        has_stream,
        ..Default::default()
    };

    let mut filters = Vec::new();
    if let Some(filter_value) = dict.get("Filter") {
        filters = parse_filter_list(filter_value);
    }

    if let Some(s_pos) = stream_pos {
        let stream_data_start = stream_data_start(body, s_pos);
        anomalies.bad_delimiter = stream_keyword_has_bad_delimiter(body, s_pos);
        match find_subslice(&body[stream_data_start..], b"endstream") {
            Some(e_rel) => {
                let observed =
                    stream_observed_len(body, stream_data_start, stream_data_start + e_rel);
                anomalies.observed_length = Some(observed as u64);
            }
            None => anomalies.missing_endstream = true,
        }

        match dict.get("Length").map(|v| v.trim()) {
            None => anomalies.missing_length = true,
            Some(value) => {
                if is_indirect_ref_text(value) {
                    // Indirect /Length is legal; this lenient scanner does
                    // not resolve it for stream-boundary telemetry.
                } else if let Some(length) = parse_direct_length(value) {
                    anomalies.declared_length = Some(length);
                    if let Some(observed) = anomalies.observed_length {
                        anomalies.length_mismatch = length != observed;
                    }
                } else {
                    anomalies.invalid_length = true;
                }
            }
        }
    }

    StreamMeta {
        has_stream,
        filters,
        anomalies,
    }
}

/// Pull the raw byte slice between `stream\n` (or `stream\r\n`) and
/// `endstream`. Capped at `MAX_STREAM_BYTES`. Returns empty when the
/// markers can't be paired.
fn extract_stream_bytes(body: &[u8]) -> Vec<u8> {
    let Some(s_pos) = find_subslice(body, b"stream") else {
        return Vec::new();
    };
    let start = stream_data_start(body, s_pos);
    let Some(e_rel) = find_subslice(&body[start..], b"endstream") else {
        return Vec::new();
    };
    let end = trim_stream_data_end(body, start, start + e_rel);
    let len = (end.saturating_sub(start)).min(MAX_STREAM_BYTES);
    body[start..start + len].to_vec()
}

fn stream_data_start(body: &[u8], stream_pos: usize) -> usize {
    let mut start = stream_pos + b"stream".len();
    while start < body.len() && matches!(body[start], b' ' | b'\t') {
        start += 1;
    }
    if start < body.len() && body[start] == b'\r' {
        start += 1;
    }
    if start < body.len() && body[start] == b'\n' {
        start += 1;
    }
    start
}

fn stream_keyword_has_bad_delimiter(body: &[u8], stream_pos: usize) -> bool {
    let after = stream_pos + b"stream".len();
    match body.get(after).copied() {
        Some(b'\r' | b'\n') => false,
        Some(b' ' | b'\t') => {
            let mut i = after;
            while i < body.len() && matches!(body[i], b' ' | b'\t') {
                i += 1;
            }
            !matches!(body.get(i).copied(), Some(b'\r' | b'\n'))
        }
        Some(_) | None => true,
    }
}

fn stream_observed_len(body: &[u8], start: usize, raw_end: usize) -> usize {
    trim_stream_data_end(body, start, raw_end).saturating_sub(start)
}

fn trim_stream_data_end(body: &[u8], start: usize, mut end: usize) -> usize {
    if end > start && body[end - 1] == b'\n' {
        end -= 1;
    }
    if end > start && body[end - 1] == b'\r' {
        end -= 1;
    }
    end
}

fn parse_direct_length(value: &str) -> Option<u64> {
    let token = value.split_whitespace().next()?;
    token.parse::<u64>().ok()
}

fn is_indirect_ref_text(value: &str) -> bool {
    let mut parts = value.split_whitespace();
    let Some(obj) = parts.next() else {
        return false;
    };
    let Some(gen) = parts.next() else {
        return false;
    };
    let Some(marker) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && obj.parse::<u32>().is_ok()
        && gen.parse::<u32>().is_ok()
        && marker == "R"
}

fn parse_filter_list(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    if trimmed.starts_with('[') {
        // Array form: `[/FlateDecode /ASCIIHexDecode]`.
        let inner = trimmed.trim_start_matches('[').trim_end_matches(']');
        inner
            .split_whitespace()
            .filter_map(|s| s.strip_prefix('/'))
            .map(std::string::ToString::to_string)
            .collect()
    } else if let Some(name) = trimmed.strip_prefix('/') {
        vec![name.to_string()]
    } else {
        Vec::new()
    }
}

/// Decode the most common PDF stream filters in chain order.
/// Unknown filters short-circuit to `None` — we'd rather skip
/// payload extraction than emit garbage.  The output is bounded
/// by `MAX_DECODED_BYTES` to defend against zip-bomb streams.
pub(crate) fn decode_filters(input: &[u8], filters: &[String]) -> Option<Vec<u8>> {
    let mut current = input.to_vec();
    for f in filters {
        current = match f.as_str() {
            "FlateDecode" | "Fl" => decode_flate(&current)?,
            "ASCIIHexDecode" | "AHx" => decode_asciihex(&current)?,
            "ASCII85Decode" | "A85" => decode_ascii85(&current)?,
            // LZW etc. are rare in malicious JS streams; punt.
            _ => return None,
        };
        if current.len() > MAX_DECODED_BYTES {
            current.truncate(MAX_DECODED_BYTES);
            break;
        }
    }
    Some(current)
}

fn decode_flate(input: &[u8]) -> Option<Vec<u8>> {
    use flate2::read::ZlibDecoder;
    use std::io::Read;
    let mut out = Vec::with_capacity(input.len() * 2);
    // Per PDF spec the FlateDecode payload is zlib-wrapped DEFLATE.
    // Some malicious / hand-built PDFs strip the zlib header — try
    // both, returning the longer successful decode.
    let mut decoder = ZlibDecoder::new(input);
    if decoder.read_to_end(&mut out).is_ok() && !out.is_empty() {
        return Some(out);
    }
    out.clear();
    let mut raw = flate2::read::DeflateDecoder::new(input);
    if raw.read_to_end(&mut out).is_ok() && !out.is_empty() {
        return Some(out);
    }
    None
}

fn decode_asciihex(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut nibble: Option<u8> = None;
    for &b in input {
        if b == b'>' {
            break;
        }
        if b.is_ascii_whitespace() {
            continue;
        }
        let n = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => 10 + (b - b'a'),
            b'A'..=b'F' => 10 + (b - b'A'),
            _ => return None,
        };
        match nibble.take() {
            None => nibble = Some(n),
            Some(hi) => out.push((hi << 4) | n),
        }
    }
    if let Some(hi) = nibble {
        out.push(hi << 4);
    }
    Some(out)
}

/// PDF ASCII85 decoder (with `~>` terminator support and `z` zero
/// shorthand).  Faithful enough for the kind of trivial obfuscation
/// malicious PDFs use; not a full Adobe-spec implementation.
fn decode_ascii85(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut tuple: u32 = 0;
    let mut count: u32 = 0;
    for &b in input {
        if b == b'~' {
            break;
        }
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'z' && count == 0 {
            out.extend_from_slice(&[0; 4]);
            continue;
        }
        if !(b'!'..=b'u').contains(&b) {
            return None;
        }
        tuple = tuple.checked_mul(85)?.checked_add((b - b'!') as u32)?;
        count += 1;
        if count == 5 {
            out.extend_from_slice(&tuple.to_be_bytes());
            tuple = 0;
            count = 0;
        }
    }
    if count > 0 {
        for _ in count..5 {
            tuple = tuple.checked_mul(85)?.checked_add(84)?;
        }
        let bytes = tuple.to_be_bytes();
        out.extend_from_slice(&bytes[..(count - 1) as usize]);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Trailer scan
// ---------------------------------------------------------------------------

fn scan_trailer(data: &[u8]) -> Option<PdfTrailer> {
    // Find the LAST `trailer` keyword followed by `<<`.
    let needle = b"trailer";
    let mut last: Option<usize> = None;
    let mut start = 0;
    while start + needle.len() <= data.len() {
        let Some(rel) = find_subslice(&data[start..], needle) else {
            break;
        };
        last = Some(start + rel);
        start = start + rel + needle.len();
    }
    let pos = last?;
    let after = &data[pos + needle.len()..];
    // Skip whitespace before `<<`.
    let mut j = 0;
    while j < after.len() && is_ws(after[j]) {
        j += 1;
    }
    if after[j..].starts_with(b"<<") {
        let close = find_matching_dict_close(&after[j..])?;
        let mut dict = BTreeMap::new();
        let mut raw = BTreeMap::new();
        walk_top_level_pairs(&after[j + 2..j + close], &mut dict, &mut raw);
        Some(PdfTrailer { dict })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Structural flag computation
// ---------------------------------------------------------------------------

fn compute_structural(
    data: &[u8],
    objects: &[PdfObject],
    trailer: &Option<PdfTrailer>,
    visible_object_count: usize,
    object_stream_inner_object_count: usize,
) -> PdfStructural {
    let mut s = PdfStructural {
        visible_object_count: visible_object_count as u32,
        object_stream_inner_object_count: object_stream_inner_object_count as u32,
        trailing_bytes_after_eof: trailing_bytes_after_last_eof(data) as u64,
        leading_bytes_before_header: leading_bytes_before_first_header(data) as u64,
        trailer_count: count_subslice(data, b"trailer"),
        startxref_count: count_subslice(data, b"startxref"),
        byte_range_count: count_subslice(data, b"/ByteRange"),
        ..Default::default()
    };
    if let Some(t) = trailer {
        s.encrypted = t.dict.contains_key("Encrypt");
    }
    // Linearization marker: object 0 typically carries `/Linearized 1`
    // when the PDF is linearized; check for the substring early.
    s.linearized = data
        .iter()
        .take(2048)
        .collect::<Vec<_>>()
        .windows(b"/Linearized".len())
        .any(|w| w.iter().map(|b| **b).eq(b"/Linearized".iter().copied()));
    // Catalog scan.
    if let Some(cat) = find_catalog(objects) {
        s.has_acroform = cat.dict.contains_key("AcroForm");
        s.has_openaction = cat.dict.contains_key("OpenAction");
        s.has_additional_actions = cat.dict.contains_key("AA");
        s.has_names_javascript = cat
            .dict
            .get("Names")
            .map(|names| names.contains("/JavaScript"))
            .unwrap_or(false);
        // XFA detection: AcroForm value contains `/XFA`.
        if let Some(af) = cat.dict.get("AcroForm") {
            s.has_xfa = af.contains("/XFA");
        }
    }
    // Filter / annotation scan.
    for obj in objects {
        if obj.stream_anomalies.has_stream {
            s.stream_count = s.stream_count.saturating_add(1);
        }
        if obj.stream_anomalies.missing_length {
            s.stream_missing_length_count = s.stream_missing_length_count.saturating_add(1);
        }
        if obj.stream_anomalies.invalid_length {
            s.stream_invalid_length_count = s.stream_invalid_length_count.saturating_add(1);
        }
        if obj.stream_anomalies.length_mismatch {
            s.stream_length_mismatch_count = s.stream_length_mismatch_count.saturating_add(1);
        }
        if obj.stream_anomalies.bad_delimiter {
            s.stream_bad_delimiter_count = s.stream_bad_delimiter_count.saturating_add(1);
        }
        if obj.stream_anomalies.missing_endstream {
            s.stream_missing_endstream_count = s.stream_missing_endstream_count.saturating_add(1);
        }
        match obj.dict.get("Type").map(|v| v.trim()) {
            Some("/Page") => s.page_count = s.page_count.saturating_add(1),
            Some("/Annot") => s.annotation_count = s.annotation_count.saturating_add(1),
            Some("/XObject") => s.xobject_count = s.xobject_count.saturating_add(1),
            Some("/Font") => s.font_count = s.font_count.saturating_add(1),
            Some("/Metadata") => s.metadata_count = s.metadata_count.saturating_add(1),
            Some("/ObjStm") => s.objstm_count = s.objstm_count.saturating_add(1),
            Some("/XRef") => s.xref_stream_count = s.xref_stream_count.saturating_add(1),
            Some("/Sig") => s.signature_object_count = s.signature_object_count.saturating_add(1),
            Some("/3D") => {
                s.has_3d = true;
                s.three_d_object_count = s.three_d_object_count.saturating_add(1);
            }
            _ => {}
        }
        if obj.dict.get("FT").map(|v| v.trim()) == Some("/Sig") {
            s.signature_object_count = s.signature_object_count.saturating_add(1);
        }
        if obj.stream_filters.iter().any(|f| f == "JBIG2Decode") {
            s.jbig2_filter_count = s.jbig2_filter_count.saturating_add(1);
        }
        if obj.stream_filters.iter().any(|f| is_unusual_filter(f)) {
            s.streams_with_unusual_filter_count =
                s.streams_with_unusual_filter_count.saturating_add(1);
        }
        if obj.dict.get("Subtype").map(|v| v.contains("/3D")) == Some(true) {
            s.has_3d = true;
            s.three_d_object_count = s.three_d_object_count.saturating_add(1);
        }
        if obj.dict.values().any(|value| value.contains("/RichMedia")) {
            s.has_richmedia = true;
        }
    }
    s.unreferenced_object_count = count_unreferenced_objects(objects, trailer);
    s
}

fn is_unusual_filter(filter: &str) -> bool {
    matches!(
        filter,
        "JBIG2Decode" | "JBIG2" | "LZWDecode" | "LZW" | "Crypt"
    )
}

fn trailing_bytes_after_last_eof(data: &[u8]) -> usize {
    let needle = b"%%EOF";
    let mut last = None;
    let mut start = 0;
    while start + needle.len() <= data.len() {
        let Some(rel) = find_subslice(&data[start..], needle) else {
            break;
        };
        let abs = start + rel;
        last = Some(abs + needle.len());
        start = abs + needle.len();
    }
    last.map(|end| data.len().saturating_sub(end)).unwrap_or(0)
}

fn leading_bytes_before_first_header(data: &[u8]) -> usize {
    find_subslice(data, b"%PDF-").unwrap_or(0)
}

fn count_subslice(data: &[u8], needle: &[u8]) -> u32 {
    if needle.is_empty() {
        return 0;
    }
    let mut count: u32 = 0;
    let mut start = 0;
    while start + needle.len() <= data.len() {
        let Some(pos) = find_subslice(&data[start..], needle) else {
            break;
        };
        count = count.saturating_add(1);
        start = start + pos + needle.len();
    }
    count
}

fn count_unreferenced_objects(objects: &[PdfObject], trailer: &Option<PdfTrailer>) -> u32 {
    let object_ids: BTreeSet<u32> = objects.iter().map(|o| o.id).collect();
    if object_ids.is_empty() {
        return 0;
    }

    let mut refs = BTreeSet::new();
    for obj in objects {
        for value in obj.dict.values() {
            collect_indirect_refs(value, &mut refs);
        }
    }
    if let Some(t) = trailer {
        for value in t.dict.values() {
            collect_indirect_refs(value, &mut refs);
        }
    }

    object_ids.difference(&refs).count() as u32
}

fn collect_indirect_refs(value: &str, refs: &mut BTreeSet<u32>) {
    let tokens: Vec<&str> = value.split_whitespace().collect();
    for window in tokens.windows(3) {
        if window[2] == "R" {
            if let Ok(id) = window[0].parse::<u32>() {
                refs.insert(id);
            }
        }
    }
}

fn find_catalog(objects: &[PdfObject]) -> Option<&PdfObject> {
    objects
        .iter()
        .find(|o| o.dict.get("Type").map(|v| v.trim()) == Some("/Catalog"))
}

// ---------------------------------------------------------------------------
// Action collection
// ---------------------------------------------------------------------------

fn collect_actions(objects: &[PdfObject], trailer: &Option<PdfTrailer>) -> Vec<PdfAction> {
    let mut out = Vec::new();

    // Catalog OpenAction value: can be inline action dict or array
    // `[ref /Fit]` etc. We surface JS / Launch / URI / Named when
    // recognizable.
    if let Some(cat) = find_catalog(objects) {
        if let Some(oa) = cat.dict.get("OpenAction") {
            push_action_from_value(oa, "openaction", &mut out, objects);
        }
        if let Some(aa) = cat.dict.get("AA") {
            // /AA value is typically a dict of named events → actions.
            // We surface each top-level event as one action record.
            push_actions_from_aa(aa, "additional_actions", &mut out, objects);
        }
        if let Some(names) = cat.dict.get("Names") {
            // `/Names /JavaScript ...` named-action JavaScript.
            if names.contains("/JavaScript") {
                out.push(PdfAction {
                    kind: PdfActionKind::JavaScript,
                    source: "named:JavaScript".to_string(),
                    snippet: String::new(),
                });
            }
        }
    }

    // Walk every object for action dicts. Heuristic: any dict with
    // `/S /<verb>` is an action. Annotations (`/Subtype /<...>`)
    // carry actions via `/A`.
    for obj in objects {
        if let (Some(s), Some(_)) = (obj.dict.get("S"), Some(())) {
            if let Some(kind) = action_kind_from_subtype(s) {
                let snippet = extract_action_snippet(&obj.dict, kind, objects);
                out.push(PdfAction {
                    kind,
                    source: format!("object:{}", obj.id),
                    snippet,
                });
            }
        }
        // /JS key implies JavaScript even without explicit /S.
        if obj.dict.contains_key("JS") || obj.dict.contains_key("JavaScript") {
            let snippet = obj
                .dict
                .get("JS")
                .or_else(|| obj.dict.get("JavaScript"))
                .map(|raw| resolve_js_value(raw, objects))
                .unwrap_or_default();
            // Avoid duplicate when /S /JavaScript already pushed.
            let already = obj
                .dict
                .get("S")
                .map(|v| v.trim() == "/JavaScript" || v.trim() == "/JS")
                .unwrap_or(false);
            if !already {
                out.push(PdfAction {
                    kind: PdfActionKind::JavaScript,
                    source: format!("object:{}", obj.id),
                    snippet,
                });
            }
        }
    }

    let _ = trailer; // unused for now; reserved for /Encrypt-aware action filtering
    out
}

fn push_action_from_value(
    value: &str,
    source: &str,
    out: &mut Vec<PdfAction>,
    objects: &[PdfObject],
) {
    // Inline action dict?
    if let Some(s) = extract_subkey(value, "S") {
        if let Some(kind) = action_kind_from_subtype(&s) {
            let snippet = extract_inline_snippet(value, kind, objects);
            out.push(PdfAction {
                kind,
                source: source.to_string(),
                snippet,
            });
            return;
        }
    }
    // Reference to another object?
    if let Some((id, _gen)) = parse_indirect_ref(value) {
        if let Some(target) = objects.iter().find(|o| o.id == id) {
            if let Some(s) = target.dict.get("S") {
                if let Some(kind) = action_kind_from_subtype(s) {
                    let snippet = extract_action_snippet(&target.dict, kind, objects);
                    out.push(PdfAction {
                        kind,
                        source: source.to_string(),
                        snippet,
                    });
                }
            }
        }
    }
}

fn push_actions_from_aa(aa: &str, source: &str, out: &mut Vec<PdfAction>, objects: &[PdfObject]) {
    // /AA dict like `<< /WC 12 0 R /WS 13 0 R >>` — capture each ref.
    let mut chars = aa.chars();
    while let Some(c) = chars.next() {
        if c == '/' {
            // Read event name then ref.
            let _evt = take_name(&mut chars);
            let ref_text = take_until_slash(&mut chars);
            push_action_from_value(ref_text.trim(), source, out, objects);
        }
    }
}

fn take_name<I: Iterator<Item = char>>(chars: &mut I) -> String {
    let mut s = String::new();
    for c in chars.by_ref() {
        if c.is_ascii_alphanumeric() {
            s.push(c);
        } else {
            break;
        }
    }
    s
}

fn take_until_slash<I: Iterator<Item = char>>(chars: &mut I) -> String {
    let mut s = String::new();
    let mut depth: i32 = 0;
    for c in chars.by_ref() {
        match c {
            '<' | '[' | '(' => depth += 1,
            '>' | ']' | ')' => depth -= 1,
            '/' if depth <= 0 => break,
            _ => {}
        }
        s.push(c);
    }
    s
}

fn action_kind_from_subtype(value: &str) -> Option<PdfActionKind> {
    let v = value.trim().trim_start_matches('/');
    Some(match v {
        "JavaScript" | "JS" => PdfActionKind::JavaScript,
        "Launch" => PdfActionKind::Launch,
        "URI" => PdfActionKind::Uri,
        "SubmitForm" => PdfActionKind::SubmitForm,
        "Named" => PdfActionKind::Named,
        "GoToR" => PdfActionKind::GoToR,
        "GoToE" => PdfActionKind::GoToE,
        "Movie" => PdfActionKind::Movie,
        "Sound" => PdfActionKind::Sound,
        "Rendition" => PdfActionKind::Rendition,
        "ImportData" => PdfActionKind::ImportData,
        _ => return None,
    })
}

fn extract_action_snippet(
    dict: &BTreeMap<String, String>,
    kind: PdfActionKind,
    objects: &[PdfObject],
) -> String {
    let key = match kind {
        PdfActionKind::JavaScript => "JS",
        PdfActionKind::Launch => "F",
        PdfActionKind::Uri => "URI",
        PdfActionKind::Named => "N",
        _ => return String::new(),
    };
    let Some(raw) = dict.get(key) else {
        return String::new();
    };
    if matches!(kind, PdfActionKind::JavaScript) {
        resolve_js_value(raw, objects)
    } else {
        truncate(raw, MAX_SNIPPET)
    }
}

fn extract_inline_snippet(dict_value: &str, kind: PdfActionKind, objects: &[PdfObject]) -> String {
    let key = match kind {
        PdfActionKind::JavaScript => "JS",
        PdfActionKind::Launch => "F",
        PdfActionKind::Uri => "URI",
        PdfActionKind::Named => "N",
        _ => return String::new(),
    };
    let Some(raw) = extract_subkey(dict_value, key) else {
        return String::new();
    };
    if matches!(kind, PdfActionKind::JavaScript) {
        resolve_js_value(&raw, objects)
    } else {
        truncate(&raw, MAX_SNIPPET)
    }
}

/// Resolve a raw `/JS` value into a captured JavaScript snippet.
/// Handles three forms:
///
/// - Literal string `(...)` — return contents verbatim.
/// - Hex string `<...>` — best-effort hex decode.
/// - Indirect ref `<id> <gen> R` — resolve to the target object's
///   stream, run the filter chain, and return the decoded text.
///
/// All forms are bounded by `MAX_SNIPPET`.  Decoding failures fall
/// back to the raw value text — a partial signal beats none.
pub(crate) fn resolve_js_value(raw: &str, objects: &[PdfObject]) -> String {
    let trimmed = raw.trim();

    // Indirect reference?
    if let Some((id, _gen)) = parse_indirect_ref(trimmed) {
        if let Some(target) = objects.iter().find(|o| o.id == id) {
            if !target.stream_bytes.is_empty() {
                let decoded = if target.stream_filters.is_empty() {
                    target.stream_bytes.clone()
                } else {
                    decode_filters(&target.stream_bytes, &target.stream_filters)
                        .unwrap_or_else(|| target.stream_bytes.clone())
                };
                let s = String::from_utf8_lossy(&decoded);
                return truncate(&s, MAX_SNIPPET);
            }
            if !target.raw_value.is_empty() {
                return decode_pdf_value_text(target.raw_value.as_bytes());
            }
            if let Some(names) = target.dict.get("Names") {
                if let Some(js) = extract_subkey(names, "JS") {
                    return resolve_js_value(&js, objects);
                }
            }
        }
        return truncate(trimmed, MAX_SNIPPET);
    }

    // Literal `(...)` string — preserve contents (caller will see
    // the same text whether escaped or not).
    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        return truncate(&trimmed[1..trimmed.len() - 1], MAX_SNIPPET);
    }

    // Hex `<...>` string — best-effort decode.
    if trimmed.starts_with('<') && !trimmed.starts_with("<<") && trimmed.ends_with('>') {
        let inner = &trimmed[1..trimmed.len() - 1];
        if let Some(bytes) = decode_asciihex(inner.as_bytes()) {
            return truncate(&String::from_utf8_lossy(&bytes), MAX_SNIPPET);
        }
    }

    truncate(trimmed, MAX_SNIPPET)
}

fn extract_subkey(dict_value: &str, key: &str) -> Option<String> {
    let needle = format!("/{} ", key);
    let pos = dict_value.find(&needle)?;
    let rest = &dict_value[pos + needle.len()..];

    // The value itself often starts with `/<Name>` (e.g. `/JavaScript`)
    // or with a literal `(...)`/`<...>`. We want to capture the whole
    // value up to the next *separator key*. Walk the bytes skipping
    // balanced parens/dicts/arrays, and stop at the next `/Name`
    // boundary that isn't part of a value-name like `/JavaScript`.
    //
    // Rule: capture leading `/Name` if the value starts with `/`,
    // then continue until the next `/` that follows whitespace.
    let bytes = rest.as_bytes();
    let mut i = 0;
    let mut emitted_leading_name = false;
    while i < bytes.len() {
        match bytes[i] {
            b'(' => i = skip_paren_string(bytes, i),
            b'[' => i = skip_array(bytes, i),
            b'<' if bytes.get(i + 1) == Some(&b'<') => {
                let off = find_matching_dict_close(&bytes[i..]).unwrap_or(0);
                i += off + 2;
            }
            b'>' if bytes.get(i + 1) == Some(&b'>') => break,
            b'/' if i > 0 && is_ws(bytes[i - 1]) && emitted_leading_name => break,
            b'/' if i == 0 => {
                // Leading-name token like `/JavaScript`.
                emitted_leading_name = true;
                i += 1;
            }
            _ => i += 1,
        }
    }
    Some(rest[..i].trim().to_string())
}

fn parse_indirect_ref(value: &str) -> Option<(u32, u16)> {
    // `12 0 R`
    let parts: Vec<&str> = value.split_whitespace().collect();
    if parts.len() >= 3 && parts[2] == "R" {
        Some((parts[0].parse().ok()?, parts[1].parse().ok()?))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Embedded files
// ---------------------------------------------------------------------------

fn collect_embedded_files(objects: &[PdfObject]) -> Vec<PdfEmbeddedFile> {
    let mut out = Vec::new();
    for obj in objects {
        // /Type /Filespec
        if obj.dict.get("Type").map(|v| v.trim()) != Some("/Filespec") {
            continue;
        }
        let filename = obj
            .dict
            .get("UF")
            .or_else(|| obj.dict.get("F"))
            .map(|v| v.trim().trim_matches(['(', ')']).to_string())
            .unwrap_or_default();
        let size = obj
            .dict
            .get("EF")
            .and_then(|ef| extract_subkey(ef, "Length"))
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        if !filename.is_empty() {
            out.push(PdfEmbeddedFile { filename, size });
        }
    }
    out
}

fn collect_stream_records(objects: &[PdfObject]) -> Vec<PdfStreamRecord> {
    let mut out = Vec::new();
    for obj in objects {
        let Some(decoded) = decoded_stream_bytes(obj) else {
            continue;
        };
        if decoded.is_empty() {
            continue;
        }
        let magic_hex = decoded
            .iter()
            .take(8)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("");
        let decoded_text = decoded_stream_text(&decoded);
        if decoded_text.is_empty() && !is_interesting_stream_magic(&magic_hex) {
            continue;
        }
        out.push(PdfStreamRecord {
            object_id: obj.id,
            filters: obj.stream_filters.clone(),
            magic_hex,
            decoded_text,
        });
    }
    out
}

fn decoded_stream_text(decoded: &[u8]) -> String {
    if !has_stream_text_signal(decoded) {
        return String::new();
    }
    truncate(&String::from_utf8_lossy(decoded), MAX_DECODED_STREAM_TEXT)
}

fn has_stream_text_signal(data: &[u8]) -> bool {
    const SIGNALS: &[&[u8]] = &[
        b"/JavaScript",
        b"eval",
        b"unescape",
        b"fromCharCode",
        b"byteToChar",
        b".replace",
        b".substring",
        b"Collab",
        b"util.",
        b"app.",
        b"media.",
        b"spell.",
        b"SOAP",
        b"Object.defineProperty",
        b"event.richValue",
        b"this.resetForm",
        b"FWS",
        b"CWS",
    ];
    SIGNALS
        .iter()
        .any(|signal| find_subslice_case_insensitive(data, signal).is_some())
}

fn is_interesting_stream_magic(magic_hex: &str) -> bool {
    magic_hex.starts_with("465753")
        || magic_hex.starts_with("435753")
        || magic_hex.starts_with("5a5753")
        || magic_hex.starts_with("d0cf11e0")
        || magic_hex.starts_with("4d5a")
        || magic_hex.starts_with("25504446")
        || magic_hex.starts_with("504b0304")
        || magic_hex.starts_with("7b5c727466")
        || magic_hex.starts_with("0000000c6a502020")
}

fn collect_form_fields(objects: &[PdfObject]) -> Vec<PdfFormField> {
    let mut out = Vec::new();
    for obj in objects {
        if !obj.dict.contains_key("FT")
            && !obj.dict.contains_key("T")
            && !obj.dict.contains_key("V")
        {
            continue;
        }
        let name = obj
            .dict_raw
            .get("T")
            .map(|v| decode_pdf_value_text(v))
            .unwrap_or_default();
        let field_type = obj
            .dict
            .get("FT")
            .map(|v| v.trim().trim_start_matches('/').to_string())
            .unwrap_or_default();
        let rect = obj
            .dict
            .get("Rect")
            .map(|v| v.trim().to_string())
            .unwrap_or_default();
        let raw_value = obj.dict_raw.get("V").map(Vec::as_slice).unwrap_or_default();
        let value_length = raw_value.len().min(u32::MAX as usize) as u32;
        let decoded = decode_base64_form_field_value(raw_value);
        let decoded_value_length = decoded.len().min(u32::MAX as usize) as u32;
        let decoded_value_snippet = truncate(&String::from_utf8_lossy(&decoded), MAX_SNIPPET);
        let decoded_value = if decoded.len() <= MAX_FORM_FIELD_DECODED_VALUE {
            String::from_utf8_lossy(&decoded).to_string()
        } else {
            String::new()
        };

        if !name.is_empty()
            || !field_type.is_empty()
            || !rect.is_empty()
            || value_length > 0
            || decoded_value_length > 0
        {
            out.push(PdfFormField {
                name,
                field_type,
                rect,
                value_length,
                decoded_value_length,
                decoded_value,
                decoded_value_snippet,
            });
        }
    }
    out
}

fn decode_base64_form_field_value(raw: &[u8]) -> Vec<u8> {
    let trimmed = trim_bytes(raw);
    let encoded = if trimmed.starts_with(b"/") {
        decode_pdf_name_bytes(&trimmed[1..])
    } else if trimmed.starts_with(b"(") && trimmed.ends_with(b")") && trimmed.len() >= 2 {
        unescape_pdf_literal_bytes(&trimmed[1..trimmed.len() - 1])
    } else {
        Vec::new()
    };
    if encoded.is_empty() {
        return Vec::new();
    }
    decode_base64_bytes(&encoded).unwrap_or_default()
}

fn decode_pdf_name_bytes(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'#' && i + 2 < raw.len() {
            if let (Some(h), Some(l)) = (
                nibble(raw[i + 1].to_ascii_uppercase()),
                nibble(raw[i + 2].to_ascii_uppercase()),
            ) {
                out.push((h << 4) | l);
                i += 3;
                continue;
            }
        }
        out.push(raw[i]);
        i += 1;
    }
    out
}

fn decode_base64_bytes(input: &[u8]) -> Option<Vec<u8>> {
    use base64::Engine;

    let compact: Vec<u8> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(compact)
        .ok()
}

// ---------------------------------------------------------------------------
// Info dict extraction
// ---------------------------------------------------------------------------

fn collect_info_dict(
    objects: &[PdfObject],
    trailer: &Option<PdfTrailer>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let info_ref = trailer.as_ref().and_then(|t| t.dict.get("Info"));
    let Some(info_ref) = info_ref else {
        return out;
    };
    let Some((id, _gen)) = parse_indirect_ref(info_ref) else {
        return out;
    };
    let Some(info_obj) = objects.iter().find(|o| o.id == id) else {
        return out;
    };
    for (k, v) in &info_obj.dict {
        let cleaned = info_obj
            .dict_raw
            .get(k)
            .map(|raw| decode_pdf_value_text(raw))
            .unwrap_or_else(|| decode_pdf_value_text(v.as_bytes()));
        if !cleaned.is_empty() {
            out.insert(k.clone(), cleaned);
        }
    }
    out
}

fn decode_pdf_value_text(raw: &[u8]) -> String {
    let trimmed = trim_bytes(raw);
    let bytes = if trimmed.starts_with(b"(") && trimmed.ends_with(b")") && trimmed.len() >= 2 {
        unescape_pdf_literal_bytes(&trimmed[1..trimmed.len() - 1])
    } else if trimmed.starts_with(b"<")
        && !trimmed.starts_with(b"<<")
        && trimmed.ends_with(b">")
        && trimmed.len() >= 2
    {
        decode_hex_bytes(&trimmed[1..trimmed.len() - 1]).unwrap_or_else(|| trimmed.to_vec())
    } else {
        trimmed.to_vec()
    };
    decode_pdf_text_bytes(&bytes)
}

fn unescape_pdf_literal_bytes(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] != b'\\' {
            out.push(s[i]);
            i += 1;
            continue;
        }
        i += 1;
        if i >= s.len() {
            break;
        }
        match s[i] {
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0c),
            b'(' => out.push(b'('),
            b')' => out.push(b')'),
            b'\\' => out.push(b'\\'),
            b'\r' => {
                if s.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
            }
            b'\n' => {}
            b'0'..=b'7' => {
                let mut value = s[i] - b'0';
                let mut consumed = 1;
                while consumed < 3 {
                    let Some(next @ b'0'..=b'7') = s.get(i + consumed).copied() else {
                        break;
                    };
                    value = value.saturating_mul(8).saturating_add(next - b'0');
                    consumed += 1;
                }
                out.push(value);
                i += consumed - 1;
            }
            other => out.push(other),
        }
        i += 1;
    }
    out
}

fn decode_hex_bytes(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut high: Option<u8> = None;
    for &b in s {
        if b.is_ascii_whitespace() {
            continue;
        }
        let n = nibble(b.to_ascii_uppercase())?;
        if let Some(h) = high.take() {
            out.push((h << 4) | n);
        } else {
            high = Some(n);
        }
    }
    if let Some(h) = high {
        out.push(h << 4);
    }
    Some(out)
}

fn decode_pdf_text_bytes(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xfe, 0xff]) {
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]));
        String::from_utf16_lossy(&units.collect::<Vec<_>>())
    } else if bytes.starts_with(&[0xff, 0xfe]) {
        let units = bytes[2..]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]));
        String::from_utf16_lossy(&units.collect::<Vec<_>>())
    } else {
        String::from_utf8_lossy(bytes).to_string()
    }
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn find_subslice_case_insensitive(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0c)
}

fn is_name_char(b: u8) -> bool {
    !matches!(
        b,
        b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')' | 0x0c
    )
}

fn trim_bytes(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && is_ws(bytes[start]) {
        start += 1;
    }
    while end > start && is_ws(bytes[end - 1]) {
        end -= 1;
    }
    &bytes[start..end]
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let cut = s
            .char_indices()
            .take_while(|(i, _)| *i < max)
            .last()
            .map(|(i, c)| i + c.len_utf8())
            .unwrap_or(0);
        s[..cut].to_string()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Empty / non-PDF input produces an empty document.
    #[test]
    fn parse_non_pdf_returns_empty() {
        let doc = parse(b"hello world");
        assert!(doc.headers.is_empty());
        assert!(doc.objects.is_empty());
    }

    /// Minimal PDF with one object dict, info dict, and trailer.
    #[test]
    fn parse_minimal_pdf_with_info() {
        let pdf = b"%PDF-1.4\n\
1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert\\(123\\)) >> >>\nendobj\n\
2 0 obj\n<< /Type /Pages /Count 0 >>\nendobj\n\
3 0 obj\n<< /Author (John Doe) /Title (Test) /Producer (Acme PDF) >>\nendobj\n\
trailer\n<< /Size 4 /Root 1 0 R /Info 3 0 R >>\nstartxref\n0\n%%EOF\n";
        let doc = parse(pdf);
        assert_eq!(doc.headers.len(), 1);
        assert_eq!(doc.headers[0].version, "1.4");
        assert_eq!(doc.eof_count, 1);
        assert_eq!(doc.objects.len(), 3);
        assert_eq!(
            doc.info.get("Author").map(std::string::String::as_str),
            Some("John Doe")
        );
        assert_eq!(
            doc.info.get("Title").map(std::string::String::as_str),
            Some("Test")
        );
        // OpenAction with /S /JavaScript should fire as a JS action.
        assert!(doc
            .actions
            .iter()
            .any(|a| a.kind == PdfActionKind::JavaScript && a.source == "openaction"));
        // Catalog flags.
        assert!(doc.structural.has_openaction);
    }

    /// Stacked PDF (two `%PDF-` headers).
    #[test]
    fn parse_detects_stacked_headers() {
        let pdf = b"%PDF-1.4\n%dummy\n%PDF-2.0\n";
        let doc = parse(pdf);
        assert_eq!(doc.headers.len(), 2);
        assert_eq!(doc.headers[0].version, "1.4");
        assert_eq!(doc.headers[1].version, "2.0");
    }

    /// Multiple `%%EOF` markers indicate incremental updates.
    #[test]
    fn parse_counts_eof_markers() {
        let pdf = b"%PDF-1.4\nstuff\n%%EOF\nmore stuff\n%%EOF\nyet more\n%%EOF\n";
        let doc = parse(pdf);
        assert_eq!(doc.eof_count, 3);
    }

    /// /Launch action surfaces with the target file.
    #[test]
    fn parse_launch_action() {
        let pdf = b"%PDF-1.7\n\
1 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) >>\nendobj\n\
trailer\n<<>>\n%%EOF\n";
        let doc = parse(pdf);
        let launch = doc
            .actions
            .iter()
            .find(|a| a.kind == PdfActionKind::Launch)
            .expect("launch action present");
        assert!(
            launch.snippet.contains("cmd.exe"),
            "snippet: {}",
            launch.snippet
        );
    }

    /// JBIG2 filter on a stream is captured.
    #[test]
    fn parse_jbig2_filter() {
        let pdf = b"%PDF-1.4\n\
1 0 obj\n<< /Filter /JBIG2Decode /Length 0 >>\nstream\nendstream\nendobj\n\
trailer\n<<>>\n%%EOF\n";
        let doc = parse(pdf);
        assert_eq!(doc.structural.jbig2_filter_count, 1);
    }

    /// Embedded file via /Type /Filespec.
    #[test]
    fn parse_embedded_filespec() {
        let pdf = b"%PDF-1.4\n\
1 0 obj\n<< /Type /Filespec /UF (invoice.exe) /F (invoice.exe) /EF << /F 2 0 R /Length 524288 >> >>\nendobj\n\
trailer\n<<>>\n%%EOF\n";
        let doc = parse(pdf);
        assert_eq!(doc.embedded_files.len(), 1);
        assert_eq!(doc.embedded_files[0].filename, "invoice.exe");
    }

    /// Filter chain (array form).
    #[test]
    fn parse_filter_chain() {
        let pdf = b"%PDF-1.4\n\
1 0 obj\n<< /Filter [/FlateDecode /ASCIIHexDecode] /Length 0 >>\nstream\nendstream\nendobj\n\
trailer\n<<>>\n%%EOF\n";
        let doc = parse(pdf);
        assert_eq!(doc.objects[0].stream_filters.len(), 2);
        assert_eq!(doc.objects[0].stream_filters[0], "FlateDecode");
        assert_eq!(doc.objects[0].stream_filters[1], "ASCIIHexDecode");
        assert_eq!(doc.structural.stream_count, 1);
    }

    #[test]
    fn parse_stream_length_mismatch() {
        let pdf = b"%PDF-1.4\n\
1 0 obj\n<< /Length 3 >>\nstream\nabcdef\nendstream\nendobj\n\
trailer\n<<>>\nstartxref\n0\n%%EOF\n";
        let doc = parse(pdf);
        assert_eq!(doc.structural.stream_count, 1);
        assert_eq!(doc.structural.stream_length_mismatch_count, 1);
        assert_eq!(doc.structural.trailer_count, 1);
        assert_eq!(doc.structural.startxref_count, 1);
    }

    #[test]
    fn parse_stream_missing_length_and_bad_delimiter() {
        let pdf = b"%PDF-1.4\n\
1 0 obj\n<< /Filter /FlateDecode >>\nstream abc\nendstream\nendobj\n\
trailer\n<<>>\n%%EOF\n";
        let doc = parse(pdf);
        assert_eq!(doc.structural.stream_count, 1);
        assert_eq!(doc.structural.stream_missing_length_count, 1);
        assert_eq!(doc.structural.stream_bad_delimiter_count, 1);
    }

    #[test]
    fn parse_stream_missing_endstream() {
        let pdf = b"%PDF-1.4\n\
1 0 obj\n<< /Length 4 >>\nstream\ndata\nendobj\n\
trailer\n<<>>\n%%EOF\n";
        let doc = parse(pdf);
        assert_eq!(doc.structural.stream_count, 1);
        assert_eq!(doc.structural.stream_missing_endstream_count, 1);
    }

    /// AcroForm with XFA payload is detected.
    #[test]
    fn parse_acroform_xfa() {
        let pdf = b"%PDF-1.7\n\
1 0 obj\n<< /Type /Catalog /AcroForm << /XFA 2 0 R >> >>\nendobj\n\
trailer\n<<>>\n%%EOF\n";
        let doc = parse(pdf);
        assert!(doc.structural.has_acroform);
        assert!(doc.structural.has_xfa);
    }

    #[test]
    fn parse_expands_flate_object_stream() {
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let obj2 = b"<< /Type /Action /S /JavaScript /JS 3 0 R >>";
        let obj3 = b"(app.alert(\"from objstm\"))";
        let obj5 = b"<< /Type /Filespec /F (payload.exe) >>";
        let off2 = 0;
        let off3 = obj2.len() + 1;
        let off5 = off3 + obj3.len() + 1;
        let header = format!("2 {off2} 3 {off3} 5 {off5}\n");
        let first = header.len();
        let mut decoded = header.into_bytes();
        decoded.extend_from_slice(obj2);
        decoded.push(b'\n');
        decoded.extend_from_slice(obj3);
        decoded.push(b'\n');
        decoded.extend_from_slice(obj5);

        let mut enc = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&decoded).unwrap();
        let compressed = enc.finish().unwrap();

        let mut pdf = b"%PDF-1.7\n\
1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n\
4 0 obj\n"
            .to_vec();
        pdf.extend_from_slice(
            format!(
                "<< /Type /ObjStm /N 3 /First {first} /Filter /FlateDecode /Length {} >>\nstream\n",
                compressed.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n");

        let doc = parse(&pdf);
        assert_eq!(doc.structural.objstm_count, 1);
        assert_eq!(doc.structural.object_stream_inner_object_count, 3);
        assert!(doc
            .embedded_files
            .iter()
            .any(|f| f.filename == "payload.exe"));
        let js = doc
            .actions
            .iter()
            .find(|a| a.kind == PdfActionKind::JavaScript)
            .expect("js action present");
        assert!(
            js.snippet.contains("from objstm"),
            "snippet was: {}",
            js.snippet
        );
    }

    #[test]
    fn info_literal_decodes_utf16be_bom() {
        let mut pdf = b"%PDF-1.4\n\
1 0 obj\n<< /Type /Catalog >>\nendobj\n\
3 0 obj\n<< /Author ("
            .to_vec();
        pdf.extend_from_slice(&[0xfe, 0xff, 0x04, 0x14, 0x04, 0x38, 0x04, 0x3c, 0x04, 0x30]);
        pdf.extend_from_slice(b") >>\nendobj\ntrailer\n<< /Root 1 0 R /Info 3 0 R >>\n%%EOF\n");

        let doc = parse(&pdf);
        assert_eq!(
            doc.info.get("Author").map(std::string::String::as_str),
            Some("Дима")
        );
    }

    /// `/JS <id> <gen> R` resolves to the target object's stream
    /// content.  Uncompressed (no filter) variant.
    #[test]
    fn resolve_js_indirect_ref_uncompressed() {
        let pdf = b"%PDF-1.7\n\
1 0 obj\n<< /Type /Action /S /JavaScript /JS 2 0 R >>\nendobj\n\
2 0 obj\n<< /Length 28 >>\nstream\napp.alert(\"loaded from stream\")\nendstream\nendobj\n\
trailer\n<<>>\n%%EOF\n";
        let doc = parse(pdf);
        let js = doc
            .actions
            .iter()
            .find(|a| a.kind == PdfActionKind::JavaScript)
            .expect("js action present");
        assert!(
            js.snippet.contains("loaded from stream"),
            "snippet was: {}",
            js.snippet
        );
    }

    /// FlateDecode round-trip — decode_filters([flate]) must match
    /// the input we compressed.
    #[test]
    fn flate_decode_round_trip() {
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let original = b"app.alert(\"hidden via flate\");";
        let mut enc = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(original).unwrap();
        let compressed = enc.finish().unwrap();
        let decoded =
            decode_filters(&compressed, &["FlateDecode".to_string()]).expect("decode succeeds");
        assert_eq!(decoded, original);
    }

    /// ASCIIHexDecode reverses a hex-encoded JS payload.
    #[test]
    fn ascii_hex_decode_basic() {
        // "Hi" = 4869
        let decoded = decode_filters(b"4869>", &["ASCIIHexDecode".to_string()]).unwrap();
        assert_eq!(decoded, b"Hi");
    }

    /// Two-stage filter chain: ASCIIHex first then Flate.
    #[test]
    fn flate_plus_asciihex_chain() {
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let original = b"this.print({});";
        let mut enc = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(original).unwrap();
        let compressed = enc.finish().unwrap();
        // Re-encode the compressed bytes as ASCII hex.
        let hex: String = compressed
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join("");
        let chained = format!("{hex}>");
        // Filter order is from-the-data outward: hex first, then flate.
        let decoded = decode_filters(
            chained.as_bytes(),
            &["ASCIIHexDecode".to_string(), "FlateDecode".to_string()],
        )
        .expect("chain decodes");
        assert_eq!(decoded, original);
    }

    /// Unknown filter aborts cleanly (returns None) — better than
    /// emitting garbage that traits might match.
    #[test]
    fn unknown_filter_returns_none() {
        let res = decode_filters(b"xxxx", &["UnknownFilter".to_string()]);
        assert!(res.is_none());
    }

    /// Garbage prefix before the header doesn't break the parse.
    #[test]
    fn parse_with_garbage_prefix() {
        let mut pdf = b"randombytes\x00\xff".to_vec();
        pdf.extend_from_slice(b"%PDF-1.4\n%%EOF\n");
        let doc = parse(&pdf);
        assert_eq!(doc.headers.len(), 1);
    }
}
