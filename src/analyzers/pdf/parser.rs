//! Lenient PDF byte-scan extractor.
//!
//! PDF malware analysis tools (peepdf, pdfid, dpd) take this
//! approach because strict PDF parsers (lopdf etc.) reject
//! deliberately-malformed PDFs by design — exactly the documents
//! we want to analyze. We never attempt:
//!
//! - Cross-reference table reconstruction (xref / xref-stream).
//! - Decryption, even for known-empty passwords.
//! - Full stream filter resolution (we only record the filter list).
//! - Object-graph traversal (refs are recorded as text, not chased).
//!
//! What we DO recover, robustly, against adversarial input:
//!
//! - Every `%PDF-1.x` header occurrence.
//! - Every `<id> <gen> obj … endobj` body, with top-level dict keys.
//! - The most recent `trailer << … >>` dict.
//! - `%%EOF` count.
//! - Action dicts (`/S /JavaScript`, `/S /Launch`, …) and their
//!   targets / snippets.
//! - Embedded-file records via `/Type /Filespec` and `/Names
//!   /EmbeddedFiles`.
//! - `/Info` dict string values when reachable from the trailer.

use super::types::{
    PdfAction, PdfActionKind, PdfDocument, PdfEmbeddedFile, PdfHeader, PdfObject, PdfStructural,
    PdfTrailer,
};
use std::collections::BTreeMap;

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

/// Run the lenient extractor over PDF bytes. Always returns a
/// document — empty when the file isn't a PDF or recovery fails
/// completely. Callers should check `headers.is_empty()` to detect
/// "not a PDF" cleanly.
#[must_use]
pub(crate) fn parse(data: &[u8]) -> PdfDocument {
    let mut doc = PdfDocument::default();
    doc.headers = scan_headers(data);
    if doc.headers.is_empty() {
        return doc;
    }

    doc.eof_count = scan_eof_count(data);
    doc.objects = scan_objects(data);
    doc.trailer = scan_trailer(data);
    doc.structural = compute_structural(data, &doc.objects, &doc.trailer);
    doc.actions = collect_actions(&doc.objects, &doc.trailer);
    doc.embedded_files = collect_embedded_files(&doc.objects);
    doc.info = collect_info_dict(&doc.objects, &doc.trailer);
    doc
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
        out.push(PdfHeader {
            version,
            offset: abs,
        });
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
        let (id, gen, header_start) = match parse_object_header(&data[..obj_pos]) {
            Some(t) => t,
            None => {
                start = obj_pos + 3;
                continue;
            }
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

        let dict = parse_top_level_dict(body);
        let (has_stream, stream_filters) = parse_stream_meta(body);
        let stream_bytes = if has_stream {
            extract_stream_bytes(body)
        } else {
            Vec::new()
        };

        out.push(PdfObject {
            id,
            gen,
            offset: header_start,
            dict,
            has_stream,
            stream_filters,
            stream_bytes,
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
/// `(id, gen, header_offset)` where `header_offset` points to the
/// start of the id digits.
fn parse_object_header(prefix: &[u8]) -> Option<(u32, u16, usize)> {
    // Skip trailing whitespace before `obj`.
    let mut end = prefix.len();
    while end > 0 && is_ws(prefix[end - 1]) {
        end -= 1;
    }
    // Read gen digits.
    let gen_end = end;
    while end > 0 && prefix[end - 1].is_ascii_digit() {
        end -= 1;
    }
    let gen_start = end;
    if gen_start == gen_end {
        return None;
    }
    let gen: u16 = std::str::from_utf8(&prefix[gen_start..gen_end])
        .ok()?
        .parse()
        .ok()?;
    // Skip ws between id and gen.
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
    let id: u32 = std::str::from_utf8(&prefix[id_start..id_end])
        .ok()?
        .parse()
        .ok()?;
    Some((id, gen, id_start))
}

// ---------------------------------------------------------------------------
// Top-level dict parsing: capture `/Name <value>` pairs at depth 1
// ---------------------------------------------------------------------------

fn parse_top_level_dict(body: &[u8]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    // Find the outermost `<<` … `>>` pair in the body.
    let Some(open) = find_subslice(body, b"<<") else {
        return out;
    };
    let Some(close) = find_matching_dict_close(&body[open..]) else {
        return out;
    };
    let dict_bytes = &body[open + 2..open + close];
    walk_top_level_pairs(dict_bytes, &mut out);
    out
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
fn walk_top_level_pairs(body: &[u8], out: &mut BTreeMap<String, String>) {
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
        let raw = body[value_start..value_end].to_vec();
        let value_text = String::from_utf8_lossy(&raw).trim().to_string();
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

fn parse_stream_meta(body: &[u8]) -> (bool, Vec<String>) {
    let has_stream = find_subslice(body, b"stream").is_some()
        && find_subslice(body, b"endstream").is_some();
    let dict = parse_top_level_dict(body);
    let mut filters = Vec::new();
    if let Some(filter_value) = dict.get("Filter") {
        filters = parse_filter_list(filter_value);
    }
    (has_stream, filters)
}

/// Pull the raw byte slice between `stream\n` (or `stream\r\n`) and
/// `endstream`. Capped at `MAX_STREAM_BYTES`. Returns empty when the
/// markers can't be paired.
fn extract_stream_bytes(body: &[u8]) -> Vec<u8> {
    let Some(s_pos) = find_subslice(body, b"stream") else {
        return Vec::new();
    };
    // The byte immediately after "stream" is a newline per spec
    // (`\r\n` or `\n`).  Skip it.
    let mut start = s_pos + b"stream".len();
    if start < body.len() && body[start] == b'\r' {
        start += 1;
    }
    if start < body.len() && body[start] == b'\n' {
        start += 1;
    }
    let Some(e_rel) = find_subslice(&body[start..], b"endstream") else {
        return Vec::new();
    };
    let mut end = start + e_rel;
    // Trim a trailing newline before `endstream` per spec.
    if end > start && body[end - 1] == b'\n' {
        end -= 1;
    }
    if end > start && body[end - 1] == b'\r' {
        end -= 1;
    }
    let len = (end.saturating_sub(start)).min(MAX_STREAM_BYTES);
    body[start..start + len].to_vec()
}

fn parse_filter_list(value: &str) -> Vec<String> {
    let trimmed = value.trim();
    if trimmed.starts_with('[') {
        // Array form: `[/FlateDecode /ASCIIHexDecode]`.
        let inner = trimmed.trim_start_matches('[').trim_end_matches(']');
        inner
            .split_whitespace()
            .filter_map(|s| s.strip_prefix('/'))
            .map(|s| s.to_string())
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
        walk_top_level_pairs(&after[j + 2..j + close], &mut dict);
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
) -> PdfStructural {
    let mut s = PdfStructural::default();
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
        // XFA detection: AcroForm value contains `/XFA`.
        if let Some(af) = cat.dict.get("AcroForm") {
            s.has_xfa = af.contains("/XFA");
        }
    }
    // Filter / annotation scan.
    for obj in objects {
        if obj
            .stream_filters
            .iter()
            .any(|f| f == "JBIG2Decode")
        {
            s.jbig2_filter_count = s.jbig2_filter_count.saturating_add(1);
        }
        if obj.dict.get("Subtype").map(|v| v.contains("/3D")) == Some(true) {
            s.three_d_object_count = s.three_d_object_count.saturating_add(1);
        }
    }
    s
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

fn push_actions_from_aa(
    aa: &str,
    source: &str,
    out: &mut Vec<PdfAction>,
    objects: &[PdfObject],
) {
    // /AA dict like `<< /WC 12 0 R /WS 13 0 R >>` — capture each ref.
    let mut chars = aa.chars();
    let mut buf = String::new();
    while let Some(c) = chars.next() {
        if c == '/' {
            // Read event name then ref.
            let _evt = take_name(&mut chars);
            let ref_text = take_until_slash(&mut chars);
            buf = ref_text.trim().to_string();
            push_action_from_value(&buf, source, out, objects);
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

fn extract_inline_snippet(
    dict_value: &str,
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
        // Strip surrounding `(...)` literal-string parens.
        let trimmed = v.trim();
        let cleaned = if trimmed.starts_with('(') && trimmed.ends_with(')') {
            unescape_pdf_string(&trimmed[1..trimmed.len() - 1])
        } else if trimmed.starts_with('<') && trimmed.ends_with('>') {
            // Hex-string literal `<...>` — best-effort decode.
            decode_hex_string(&trimmed[1..trimmed.len() - 1])
        } else {
            trimmed.to_string()
        };
        if !cleaned.is_empty() {
            out.insert(k.clone(), cleaned);
        }
    }
    out
}

fn unescape_pdf_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('(') => out.push('('),
                Some(')') => out.push(')'),
                Some('\\') => out.push('\\'),
                Some(other) => out.push(other),
                None => break,
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn decode_hex_string(s: &str) -> String {
    let bytes: Vec<u8> = s
        .as_bytes()
        .chunks(2)
        .filter_map(|w| {
            let hi = (w.first()?).to_ascii_uppercase();
            let lo = w.get(1).copied().unwrap_or(b'0').to_ascii_uppercase();
            let h = nibble(hi)?;
            let l = nibble(lo)?;
            Some((h << 4) | l)
        })
        .collect();
    String::from_utf8_lossy(&bytes).to_string()
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

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0c)
}

fn is_name_char(b: u8) -> bool {
    !matches!(
        b,
        b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'<' | b'>' | b'[' | b']' | b'(' | b')' | 0x0c
    )
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
        assert!(doc.trailer.is_some());
        assert_eq!(doc.info.get("Author").map(|s| s.as_str()), Some("John Doe"));
        assert_eq!(doc.info.get("Title").map(|s| s.as_str()), Some("Test"));
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
        assert!(launch.snippet.contains("cmd.exe"), "snippet: {}", launch.snippet);
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
