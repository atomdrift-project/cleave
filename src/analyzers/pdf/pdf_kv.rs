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
//! filter_chains[]:
//!   - "FlateDecode"
//!   - "ASCIIHexDecode,FlateDecode"
//! header:
//!   version (first), header_count
//! shape:
//!   object_count, eof_count, encrypted, linearized,
//!   jbig2_filter_count, three_d_object_count
//! ```

use super::types::PdfDocument;
use serde_json::{json, Map, Value};

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
    fn pdf_kv_extract_returns_none_for_non_pdf() {
        assert!(extract_pdf_kv(b"hello world").is_none());
    }

    #[test]
    fn info_key_to_snake_handles_pdf_spec_names() {
        assert_eq!(info_key_to_snake("Author"), "author");
        assert_eq!(info_key_to_snake("CreationDate"), "creation_date");
        assert_eq!(info_key_to_snake("ModDate"), "mod_date");
    }
}
