//! Synthesize a `serde_json::Value` kv tree from a parsed RTF document.
//!
//! Mirrors `analyzers/office/office_kv.rs`. The schema below is the
//! stable trait-base API for `type: kv` rules targeting RTF files —
//! once traits depend on these paths, renames are breaking changes.
//!
//! # Schema
//!
//! ```text
//! info:                         (\info group string fields)
//!   title, author, manager, company, operator,
//!   subject, category, keywords, comment, doccomm,
//!   hlinkbase, creatim, revtim, printim, version
//! info_numeric:                 (\info group integer fields)
//!   nofpages, nofwords, nofchars, nofcharsws,
//!   edmins, version, vern
//! objects:                      (cross-format embedded OLE list)
//!   - class, name, data_size, auto_update,
//!     suspicious_flags: ["objupdate", "webdav", ...]
//! fields:                       (\field instruction list)
//!   - kind:    "DDEAUTO"|"INCLUDETEXT"|"IMPORT"|"LINK"|...
//!     target:  "<inline string>"
//! header:
//!   version, charset
//! shape:
//!   font_count, max_nesting_depth
//! ```
//!
//! The `objects[]`/`fields[]` arrays parallel the office kv tree
//! shape — trait authors can write `path: objects[*].class` regex
//! across formats with the same idiom.

use crate::rtf::types::{RtfDocument, SuspiciousFlag};
use serde_json::{json, Map, Value};

/// Build the kv tree for a parsed RTF document. Empty fields are
/// dropped so the JSON output stays clean for sparse documents.
#[must_use]
pub(crate) fn build_rtf_kv(doc: &RtfDocument) -> Value {
    let mut root = Map::new();

    // info.* — string fields
    if !doc.metadata.info.is_empty() {
        let mut info = Map::new();
        for (k, v) in &doc.metadata.info {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                info.insert(k.clone(), Value::String(trimmed.to_string()));
            }
        }
        if !info.is_empty() {
            root.insert("info".into(), Value::Object(info));
        }
    }

    // info_numeric.* — integer fields (page/word/char counts, edit
    // time, version) — surfaced separately so trait authors don't
    // have to disambiguate strings from numbers in `path: info.*`.
    if !doc.metadata.info_numeric.is_empty() {
        let mut nm = Map::new();
        for (k, v) in &doc.metadata.info_numeric {
            nm.insert(k.clone(), json!(v));
        }
        root.insert("info_numeric".into(), Value::Object(nm));
    }

    // objects[]
    if !doc.embedded_objects.is_empty() {
        let arr: Vec<Value> = doc
            .embedded_objects
            .iter()
            .map(|o| {
                let flags: Vec<&str> = o
                    .suspicious_flags
                    .iter()
                    .map(|f| match f {
                        SuspiciousFlag::ObjUpdateDirective => "objupdate",
                        SuspiciousFlag::ObfuscatedOleHeader => "obfuscated_ole_header",
                        SuspiciousFlag::UncPath(_) => "unc_path",
                        SuspiciousFlag::WebdavPath => "webdav",
                        SuspiciousFlag::MalformedHeader => "malformed_header",
                        SuspiciousFlag::ExcessiveNesting => "excessive_nesting",
                    })
                    .collect();
                let unc_target = o.suspicious_flags.iter().find_map(|f| match f {
                    SuspiciousFlag::UncPath(p) => Some(p.clone()),
                    _ => None,
                });
                let mut entry = Map::new();
                entry.insert("class".into(), json!(o.class_name));
                entry.insert("data_size".into(), json!(o.objdata.len()));
                entry.insert(
                    "auto_update".into(),
                    json!(o
                        .suspicious_flags
                        .iter()
                        .any(|f| matches!(f, SuspiciousFlag::ObjUpdateDirective))),
                );
                if !flags.is_empty() {
                    entry.insert("suspicious_flags".into(), json!(flags));
                }
                if let Some(p) = unc_target {
                    entry.insert("unc_target".into(), json!(p));
                }
                Value::Object(entry)
            })
            .collect();
        root.insert("objects".into(), Value::Array(arr));
    }

    // fields[]
    if !doc.fields.is_empty() {
        let arr: Vec<Value> = doc
            .fields
            .iter()
            .map(|f| {
                json!({
                    "kind": f.kind,
                    "target": f.target,
                })
            })
            .collect();
        root.insert("fields".into(), Value::Array(arr));
    }

    // header.*
    let mut header = Map::new();
    header.insert("version".into(), json!(doc.header.version));
    if let Some(charset) = &doc.header.charset {
        header.insert("charset".into(), json!(charset));
    }
    root.insert("header".into(), Value::Object(header));

    // shape.*
    let mut shape = Map::new();
    if doc.metadata.font_count > 0 {
        shape.insert("font_count".into(), json!(doc.metadata.font_count));
    }
    if doc.metadata.max_nesting_depth > 0 {
        shape.insert(
            "max_nesting_depth".into(),
            json!(doc.metadata.max_nesting_depth),
        );
    }
    if !shape.is_empty() {
        root.insert("shape".into(), Value::Object(shape));
    }

    Value::Object(root)
}

/// `cleave kv` dispatcher entry — parse RTF bytes and return the
/// synthesized kv tree, or `None` for non-RTF input or parse failure.
pub(crate) fn extract_rtf_kv(data: &[u8]) -> Option<Value> {
    let parser = crate::rtf::parser::RtfParser::new();
    parser.parse(data).ok().map(|doc| build_rtf_kv(&doc))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::rtf::parser::RtfParser;

    #[test]
    fn rtf_kv_captures_info_group_and_fields() {
        let body = "{\\rtf1\\ansi\n\
{\\info\n\
{\\title Q4 Audit}\n\
{\\author Иван Иванов}\n\
{\\nofpages3}\n\
{\\nofwords1234}\n\
}\n\
{\\field{\\*\\fldinst{ DDEAUTO \"C:\\\\Windows\\\\System32\\\\cmd.exe\" \"/c calc\" }}}\n\
}";
        let doc = RtfParser::new().parse(body.as_bytes()).unwrap();
        let kv = build_rtf_kv(&doc);
        assert_eq!(kv["info"]["title"], "Q4 Audit");
        assert_eq!(kv["info"]["author"], "Иван Иванов");
        assert_eq!(kv["info_numeric"]["nofpages"], 3);
        assert_eq!(kv["info_numeric"]["nofwords"], 1234);
        let fields = kv["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0]["kind"], "DDEAUTO");
    }

    #[test]
    fn rtf_kv_empty_doc_drops_optional_sections() {
        let body = b"{\\rtf1\\ansi}";
        let doc = RtfParser::new().parse(body).unwrap();
        let kv = build_rtf_kv(&doc);
        assert!(kv.get("info").is_none());
        assert!(kv.get("info_numeric").is_none());
        assert!(kv.get("objects").is_none());
        assert!(kv.get("fields").is_none());
        // `header` is always present.
        assert!(kv.get("header").is_some());
    }

    #[test]
    fn extract_rtf_kv_returns_none_for_non_rtf() {
        let png = [0x89, b'P', b'N', b'G'];
        assert!(extract_rtf_kv(&png).is_none());
    }
}
