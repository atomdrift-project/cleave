//! Synthesize the kv tree for a parsed PDF document.
//!
//! Mirrors `analyzers/office/office_kv.rs` and `rtf::rtf_kv`. The
//! schema is the stable trait-base API for `type: kv` rules
//! targeting PDF.
//!
//! # Schema
//!
//! ```text
//! info:                     (DocumentInfo dict; string-typed)
//!   title, author, creator, producer, subject, keywords,
//!   creation_date, mod_date, trapped
//! catalog:
//!   has_openaction, has_additional_actions,
//!   has_acroform, has_xfa,
//!   embedded_file_count
//! actions[]:
//!   - kind:   "javascript"|"launch"|"uri"|"submitform"|...
//!     source: "openaction"|"additional_actions"|"object:N"|...
//!     snippet: "first 200 chars of value"
//! embedded_files[]:
//!   - filename, size
//! streams[]:
//!   - object_id, filters, magic_hex, decoded_text
//! form_fields[]:
//!   - name, field_type, rect, value_length,
//!     decoded_value_length, decoded_value_snippet, decoded_value
//! filter_chains[]:
//!   - "FlateDecode"
//!   - "ASCIIHexDecode,FlateDecode"
//! header:
//!   version (first), header_count
//! shape:
//!   object_count, eof_count, encrypted, linearized,
//!   trailer_count, startxref_count,
//!   jbig2_filter_count, three_d_object_count
//! ```

use super::types::{PdfAction, PdfActionKind, PdfDocument};
use crate::types::PdfMetrics;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Build the kv tree for a parsed PDF document.
#[must_use]
pub(crate) fn build_pdf_kv(doc: &PdfDocument) -> Value {
    let mut root = Map::new();

    // info.* — DocumentInfo dict, lowercased PDF-spec field names.
    if !doc.info.is_empty() {
        let mut info = Map::new();
        for (k, v) in &doc.info {
            let snake = info_key_to_snake(k);
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                info.insert(snake, Value::String(trimmed.to_string()));
            }
        }
        if !info.is_empty() {
            root.insert("info".into(), Value::Object(info));
        }
    }

    // catalog.* — boolean flags from the structural pass.
    let mut catalog = Map::new();
    if doc.structural.has_openaction {
        catalog.insert("has_openaction".into(), json!(true));
    }
    if doc.structural.has_additional_actions {
        catalog.insert("has_additional_actions".into(), json!(true));
    }
    if doc.structural.has_acroform {
        catalog.insert("has_acroform".into(), json!(true));
    }
    if doc.structural.has_xfa {
        catalog.insert("has_xfa".into(), json!(true));
    }
    if doc.structural.has_names_javascript {
        catalog.insert("has_names_javascript".into(), json!(true));
    }
    if doc.structural.has_richmedia {
        catalog.insert("has_richmedia".into(), json!(true));
    }
    if doc.structural.has_3d {
        catalog.insert("has_3d".into(), json!(true));
    }
    if !doc.embedded_files.is_empty() {
        catalog.insert(
            "embedded_file_count".into(),
            json!(doc.embedded_files.len()),
        );
    }
    if !catalog.is_empty() {
        root.insert("catalog".into(), Value::Object(catalog));
    }

    // actions[]
    if !doc.actions.is_empty() {
        let arr: Vec<Value> = doc
            .actions
            .iter()
            .map(|a| {
                let mut entry = Map::new();
                entry.insert("kind".into(), json!(a.kind.as_str()));
                entry.insert("source".into(), json!(a.source));
                if !a.snippet.is_empty() {
                    entry.insert("snippet".into(), json!(a.snippet));
                }
                Value::Object(entry)
            })
            .collect();
        root.insert("actions".into(), Value::Array(arr));
    }

    // embedded_files[]
    if !doc.embedded_files.is_empty() {
        let arr: Vec<Value> = doc
            .embedded_files
            .iter()
            .map(|f| {
                json!({
                    "filename": f.filename,
                    "size": f.size,
                })
            })
            .collect();
        root.insert("embedded_files".into(), Value::Array(arr));
    }

    // streams[] — decoded stream summaries for compressed JavaScript and
    // embedded payload signatures. `decoded_text` is capped by the parser.
    if !doc.streams.is_empty() {
        let arr: Vec<Value> = doc
            .streams
            .iter()
            .map(|s| {
                let mut entry = Map::new();
                entry.insert("object_id".into(), json!(s.object_id));
                if !s.filters.is_empty() {
                    entry.insert("filters".into(), json!(s.filters));
                }
                if !s.magic_hex.is_empty() {
                    entry.insert("magic_hex".into(), json!(s.magic_hex));
                }
                if !s.decoded_text.is_empty() {
                    entry.insert("decoded_text".into(), json!(s.decoded_text));
                }
                Value::Object(entry)
            })
            .collect();
        root.insert("streams".into(), Value::Array(arr));
    }

    // form_fields[]
    if !doc.form_fields.is_empty() {
        let arr: Vec<Value> = doc
            .form_fields
            .iter()
            .map(|f| {
                let mut entry = Map::new();
                if !f.name.is_empty() {
                    entry.insert("name".into(), json!(f.name));
                }
                if !f.field_type.is_empty() {
                    entry.insert("field_type".into(), json!(f.field_type));
                }
                if !f.rect.is_empty() {
                    entry.insert("rect".into(), json!(f.rect));
                }
                if f.value_length > 0 {
                    entry.insert("value_length".into(), json!(f.value_length));
                }
                if f.decoded_value_length > 0 {
                    entry.insert("decoded_value_length".into(), json!(f.decoded_value_length));
                }
                if !f.decoded_value_snippet.is_empty() {
                    entry.insert(
                        "decoded_value_snippet".into(),
                        json!(f.decoded_value_snippet),
                    );
                }
                if !f.decoded_value.is_empty() {
                    entry.insert("decoded_value".into(), json!(f.decoded_value));
                }
                Value::Object(entry)
            })
            .collect();
        root.insert("form_fields".into(), Value::Array(arr));
    }

    // filter_chains[] — comma-joined per object so trait authors can
    // pattern-match on chain shapes (`FlateDecode,ASCIIHexDecode`).
    let chains: Vec<String> = doc
        .objects
        .iter()
        .filter(|o| !o.stream_filters.is_empty())
        .map(|o| o.stream_filters.join(","))
        .collect();
    if !chains.is_empty() {
        root.insert(
            "filter_chains".into(),
            Value::Array(chains.into_iter().map(Value::String).collect()),
        );
    }

    // header.* — first version + total header count (multiple = stacked).
    let mut header = Map::new();
    if let Some(h) = doc.headers.first() {
        header.insert("version".into(), json!(h.version));
    }
    header.insert("header_count".into(), json!(doc.headers.len()));
    root.insert("header".into(), Value::Object(header));

    // shape.* — structural counts.
    let mut shape = Map::new();
    shape.insert("object_count".into(), json!(doc.objects.len()));
    shape.insert("eof_count".into(), json!(doc.eof_count));
    if doc.structural.trailer_count > 0 {
        shape.insert("trailer_count".into(), json!(doc.structural.trailer_count));
    }
    if doc.structural.startxref_count > 0 {
        shape.insert(
            "startxref_count".into(),
            json!(doc.structural.startxref_count),
        );
    }
    if doc.structural.encrypted {
        shape.insert("encrypted".into(), json!(true));
    }
    if doc.structural.linearized {
        shape.insert("linearized".into(), json!(true));
    }
    if doc.structural.jbig2_filter_count > 0 {
        shape.insert(
            "jbig2_filter_count".into(),
            json!(doc.structural.jbig2_filter_count),
        );
    }
    if doc.structural.three_d_object_count > 0 {
        shape.insert(
            "three_d_object_count".into(),
            json!(doc.structural.three_d_object_count),
        );
    }
    root.insert("shape".into(), Value::Object(shape));

    Value::Object(root)
}

#[must_use]
pub(crate) fn build_pdf_metrics(doc: &PdfDocument) -> PdfMetrics {
    let page_count = doc.structural.page_count;
    let uri_action_count = doc
        .actions
        .iter()
        .filter(|a| a.kind == PdfActionKind::Uri)
        .count() as u32;
    let javascript_action_count = action_count_by_kind(&doc.actions, PdfActionKind::JavaScript);
    let embedded_file_count = doc.embedded_files.len() as u32;

    PdfMetrics {
        visible_object_count: doc.structural.visible_object_count,
        object_count: doc.objects.len() as u32,
        object_stream_inner_object_count: doc.structural.object_stream_inner_object_count,
        page_count,
        annotation_count: doc.structural.annotation_count,
        xobject_count: doc.structural.xobject_count,
        font_count: doc.structural.font_count,
        metadata_count: doc.structural.metadata_count,
        objstm_count: doc.structural.objstm_count,
        xref_stream_count: doc.structural.xref_stream_count,
        unreferenced_object_count: doc.structural.unreferenced_object_count,
        trailing_bytes_after_eof: doc.structural.trailing_bytes_after_eof,
        leading_bytes_before_header: doc.structural.leading_bytes_before_header,
        trailer_count: doc.structural.trailer_count,
        startxref_count: doc.structural.startxref_count,
        stream_count: doc.structural.stream_count,
        stream_missing_length_count: doc.structural.stream_missing_length_count,
        stream_invalid_length_count: doc.structural.stream_invalid_length_count,
        stream_length_mismatch_count: doc.structural.stream_length_mismatch_count,
        stream_bad_delimiter_count: doc.structural.stream_bad_delimiter_count,
        stream_missing_endstream_count: doc.structural.stream_missing_endstream_count,
        streams_with_unusual_filter_count: doc.structural.streams_with_unusual_filter_count,
        signature_object_count: doc.structural.signature_object_count,
        byte_range_count: doc.structural.byte_range_count,
        signed_incremental_update_count: if doc.structural.byte_range_count > 0 && doc.eof_count > 1
        {
            doc.eof_count.saturating_sub(1)
        } else {
            0
        },
        jbig2_filter_count: doc.structural.jbig2_filter_count,
        three_d_object_count: doc.structural.three_d_object_count,
        embedded_file_count,
        form_field_count: doc.form_fields.len() as u32,
        hidden_zero_rect_field_count: doc
            .form_fields
            .iter()
            .filter(|f| is_zero_rect(&f.rect))
            .count() as u32,
        duplicate_form_name_count: duplicate_form_name_count(doc),
        duplicate_form_rect_count: duplicate_form_rect_count(doc),
        duplicate_form_name_rect_count: duplicate_form_name_rect_count(doc),
        overlapping_form_field_pair_count: overlapping_form_field_pair_count(doc),
        decoded_form_value_max_len: doc
            .form_fields
            .iter()
            .map(|f| f.decoded_value_length)
            .max()
            .unwrap_or(0),
        action_count: doc.actions.len() as u32,
        uri_action_count,
        javascript_action_count,
        risky_feature_score: pdf_risky_feature_score(
            doc,
            embedded_file_count,
            unique_action_count_by_kind(&doc.actions, PdfActionKind::JavaScript),
            unique_action_count_by_kind(&doc.actions, PdfActionKind::Launch),
        ),
        annotations_per_page: ratio(doc.structural.annotation_count, page_count),
        uri_actions_per_page: ratio(uri_action_count, page_count),
    }
}

fn pdf_risky_feature_score(
    doc: &PdfDocument,
    embedded_file_count: u32,
    javascript_action_count: u32,
    launch_action_count: u32,
) -> u32 {
    let mut score = 0u32;
    score += weighted_indicator(launch_action_count, 30);
    score += weighted_indicator(embedded_file_count, 25);
    score += weighted_indicator(
        javascript_action_count + u32::from(doc.structural.has_names_javascript),
        25,
    );
    score += weighted_indicator(u32::from(doc.structural.has_openaction), 25);
    score += weighted_indicator(u32::from(doc.structural.has_additional_actions), 20);
    score += weighted_indicator(u32::from(doc.structural.has_xfa), 15);
    score += weighted_indicator(u32::from(doc.structural.has_acroform), 10);
    score += weighted_indicator(u32::from(doc.structural.has_richmedia), 20);
    score += weighted_indicator(doc.structural.objstm_count, 8);
    score.min(100)
}

fn action_count_by_kind(actions: &[PdfAction], kind: PdfActionKind) -> u32 {
    actions.iter().filter(|a| a.kind == kind).count() as u32
}

fn unique_action_count_by_kind(actions: &[PdfAction], kind: PdfActionKind) -> u32 {
    let mut seen = BTreeSet::new();
    for action in actions.iter().filter(|a| a.kind == kind) {
        seen.insert(action.snippet.trim());
    }
    seen.len() as u32
}

fn weighted_indicator(count: u32, weight: u32) -> u32 {
    if count == 0 {
        0
    } else {
        weight * (1 + (count / 2).min(3))
    }
}

fn non_signature_forms(doc: &PdfDocument) -> impl Iterator<Item = &super::types::PdfFormField> {
    doc.form_fields
        .iter()
        .filter(|f| !f.field_type.eq_ignore_ascii_case("Sig"))
}

fn duplicate_form_name_count(doc: &PdfDocument) -> u32 {
    let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
    for field in non_signature_forms(doc).filter(|f| !f.name.trim().is_empty()) {
        *counts.entry(field.name.trim()).or_default() += 1;
    }
    duplicate_excess_count(counts.values().copied())
}

fn duplicate_form_rect_count(doc: &PdfDocument) -> u32 {
    let mut counts: BTreeMap<String, u32> = BTreeMap::new();
    for field in non_signature_forms(doc).filter(|f| !f.rect.trim().is_empty()) {
        *counts.entry(normalize_rect_text(&field.rect)).or_default() += 1;
    }
    duplicate_excess_count(counts.values().copied())
}

fn duplicate_form_name_rect_count(doc: &PdfDocument) -> u32 {
    let mut counts: BTreeMap<(String, String), u32> = BTreeMap::new();
    for field in
        non_signature_forms(doc).filter(|f| !f.name.trim().is_empty() && !f.rect.trim().is_empty())
    {
        let key = (
            field.name.trim().to_string(),
            normalize_rect_text(&field.rect),
        );
        *counts.entry(key).or_default() += 1;
    }
    duplicate_excess_count(counts.values().copied())
}

fn duplicate_excess_count(counts: impl Iterator<Item = u32>) -> u32 {
    counts
        .filter(|count| *count > 1)
        .map(|count| count.saturating_sub(1))
        .sum()
}

fn overlapping_form_field_pair_count(doc: &PdfDocument) -> u32 {
    let rects: Vec<_> = non_signature_forms(doc)
        .filter_map(|f| parse_rect(&f.rect))
        .collect();
    let mut count: u32 = 0;
    for i in 0..rects.len() {
        for j in i + 1..rects.len() {
            if rects_overlap(rects[i], rects[j]) {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

fn normalize_rect_text(rect: &str) -> String {
    if let Some(parsed) = parse_rect(rect) {
        parsed
            .iter()
            .map(|n| {
                if n.fract() == 0.0 {
                    format!("{n:.0}")
                } else {
                    format!("{n:.3}")
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        rect.split_whitespace().collect::<Vec<_>>().join(" ")
    }
}

fn parse_rect(rect: &str) -> Option<[f64; 4]> {
    let nums: Vec<f64> = rect
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split_whitespace()
        .filter_map(|part| part.trim_matches(',').parse::<f64>().ok())
        .collect();
    if nums.len() < 4 {
        return None;
    }
    let left = nums[0].min(nums[2]);
    let right = nums[0].max(nums[2]);
    let bottom = nums[1].min(nums[3]);
    let top = nums[1].max(nums[3]);
    Some([left, bottom, right, top])
}

fn rects_overlap(a: [f64; 4], b: [f64; 4]) -> bool {
    let width = a[2].min(b[2]) - a[0].max(b[0]);
    let height = a[3].min(b[3]) - a[1].max(b[1]);
    width > 0.0 && height > 0.0
}

fn is_zero_rect(rect: &str) -> bool {
    rect.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split_whitespace()
        .all(|part| part == "0" || part == "0.0")
        && rect.split_whitespace().count() >= 4
}

fn ratio(numerator: u32, denominator: u32) -> f32 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f32 / denominator as f32
    }
}

/// `cleave kv` dispatcher entry — parse PDF bytes lenient-ly and
/// return the synthesized kv tree, or `None` for non-PDF input.
pub(crate) fn extract_pdf_kv(data: &[u8]) -> Option<Value> {
    let doc = super::parser::parse(data);
    if doc.headers.is_empty() {
        return None;
    }
    Some(build_pdf_kv(&doc))
}

/// Snake-case the PDF-spec PascalCase info-dict keys
/// (`Author` → `author`, `CreationDate` → `creation_date`,
/// `ModDate` → `mod_date`).
fn info_key_to_snake(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 2);
    for (i, c) in key.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::analyzers::pdf::parser;

    #[test]
    fn pdf_kv_minimal_document() {
        let pdf = b"%PDF-1.4\n\
1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.alert\\(123\\)) >> >>\nendobj\n\
3 0 obj\n<< /Author (John Doe) /Producer (Acme PDF) >>\nendobj\n\
trailer\n<< /Root 1 0 R /Info 3 0 R >>\nstartxref\n0\n%%EOF\n";
        let doc = parser::parse(pdf);
        let kv = build_pdf_kv(&doc);
        assert_eq!(kv["info"]["author"], "John Doe");
        assert_eq!(kv["info"]["producer"], "Acme PDF");
        assert_eq!(kv["catalog"]["has_openaction"], true);
        let actions = kv["actions"].as_array().unwrap();
        assert!(actions.iter().any(|a| a["kind"] == "javascript"));
        assert_eq!(kv["header"]["version"], "1.4");
        assert_eq!(kv["header"]["header_count"], 1);
    }

    #[test]
    fn pdf_kv_filter_chains_serialized() {
        let pdf = b"%PDF-1.7\n\
1 0 obj\n<< /Filter [/FlateDecode /ASCIIHexDecode] /Length 0 >>\nstream\nendstream\nendobj\n\
trailer\n<<>>\n%%EOF\n";
        let doc = parser::parse(pdf);
        let kv = build_pdf_kv(&doc);
        let chains = kv["filter_chains"].as_array().unwrap();
        assert_eq!(chains[0], "FlateDecode,ASCIIHexDecode");
    }

    #[test]
    fn pdf_kv_exposes_decoded_stream_text() {
        use flate2::write::ZlibEncoder;
        use std::io::Write;

        let original = b"eval(unescape(payload)); Collab.getIcon();";
        let mut enc = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(original).unwrap();
        let compressed = enc.finish().unwrap();
        let mut pdf = b"%PDF-1.7\n1 0 obj\n".to_vec();
        pdf.extend_from_slice(
            format!(
                "<< /Filter /FlateDecode /Length {} >>\nstream\n",
                compressed.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&compressed);
        pdf.extend_from_slice(b"\nendstream\nendobj\ntrailer\n<<>>\n%%EOF\n");

        let doc = parser::parse(&pdf);
        let kv = build_pdf_kv(&doc);
        assert!(kv["streams"][0]["decoded_text"]
            .as_str()
            .unwrap()
            .contains("Collab.getIcon"));
    }

    #[test]
    fn pdf_kv_extract_returns_none_for_non_pdf() {
        assert!(extract_pdf_kv(b"hello world").is_none());
    }

    #[test]
    fn info_key_to_snake_handles_pdf_spec_names() {
        assert_eq!(info_key_to_snake("Author"), "author");
        assert_eq!(info_key_to_snake("CreationDate"), "creation_date");
        assert_eq!(info_key_to_snake("ModDate"), "mod_date");
    }

    #[test]
    fn pdf_metrics_surface_signature_and_form_overlay_shape() {
        let pdf = b"%PDF-1.4\n\
1 0 obj\n<< /Type /Catalog >>\nendobj\n\
2 0 obj\n<< /FT /Tx /T (recipient) /Rect [ 10 10 100 30 ] /V (Alice) >>\nendobj\n\
3 0 obj\n<< /FT /Tx /T (recipient) /Rect [10 10 100 30] /V (Mallory) >>\nendobj\n\
4 0 obj\n<< /Type /Sig /ByteRange [0 10 20 30] /Contents <00> >>\nendobj\n\
trailer\n<< /Root 1 0 R >>\nstartxref\n0\n%%EOF\n\
xref\n0 1\n0000000000 65535 f\ntrailer\n<< /Root 1 0 R /Prev 0 >>\nstartxref\n1\n%%EOF\n";
        let doc = parser::parse(pdf);
        let metrics = build_pdf_metrics(&doc);
        assert_eq!(metrics.signature_object_count, 1);
        assert_eq!(metrics.byte_range_count, 1);
        assert_eq!(metrics.signed_incremental_update_count, 1);
        assert_eq!(metrics.duplicate_form_name_count, 1);
        assert_eq!(metrics.duplicate_form_rect_count, 1);
        assert_eq!(metrics.duplicate_form_name_rect_count, 1);
        assert_eq!(metrics.overlapping_form_field_pair_count, 1);
    }

    #[test]
    fn pdf_metrics_surface_weighted_risky_feature_score() {
        let pdf = b"%PDF-1.7\n\
1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /AcroForm << /XFA 4 0 R >> >>\nendobj\n\
2 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert\\(1\\)) >>\nendobj\n\
3 0 obj\n<< /Type /ObjStm /N 0 /First 0 /Length 0 >>\nstream\nendstream\nendobj\n\
trailer\n<< /Root 1 0 R >>\n%%EOF\n";
        let doc = parser::parse(pdf);
        let metrics = build_pdf_metrics(&doc);
        assert_eq!(metrics.javascript_action_count, 2);
        assert_eq!(metrics.objstm_count, 1);
        assert_eq!(metrics.risky_feature_score, 83);
    }
}
