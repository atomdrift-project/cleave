//! Synthesize a `serde_json::Value` "kv tree" from parsed office docs.
//!
//! `type: value` traits walk a JSON-shaped tree by path (`a.b.c`,
//! `arr[*].field`, etc.). Office documents are not natively kv files —
//! their metadata is buried in OLE2 streams and OOXML XML parts — so
//! the office analyzer parses everything, then this module flattens
//! the relevant string and discrete-identifier fields into a tree the
//! value evaluator can consume.
//!
//! # Schema (stable trait-base API)
//!
//! ```text
//! ole:                 (OLE2-only; absent for OOXML)
//!   compobj:
//!     user_type, clipboard_format, app_version
//!
//! summary:             (OLE2 SummaryInformation strings + revision)
//!   title, author, last_author, application, create_time,
//!   last_save_time, revision
//!
//! core:                (OOXML docProps/core.xml + app.xml)
//!   creator, last_modified_by, created, modified, application,
//!   company, title, subject, description, keywords, category
//!
//! relationships:       (cross-format external relationships)
//!   - type, target
//!
//! embedded:            (cross-format embedded objects)
//!   - filename, size
//! ```
//!
//! Numeric counts (page count, word count, edit time, embedded-exec
//! count, all the per-API/per-DLL frequency vectors) live on
//! `OfficeMetrics` and are reached via `type: metrics`. Discrete
//! identifiers that are technically integers but aren't intended for
//! threshold comparison (revision number — "12" isn't bigger than "1"
//! in any security sense) live in the kv tree as ints.
//!
//! Names are normalized to snake_case throughout, mirroring the LNK
//! kv shape rather than the source format's mixed PascalCase /
//! camelCase. This keeps trait paths uniform across legacy and modern
//! office documents.

use super::{ole2, ooxml};
use crate::analyzers::FileType;
use serde_json::{json, Map, Value};
use std::path::Path;

/// Best-effort dispatcher used by `cleave value <doc>` to surface the
/// office values tree without running full analysis. Returns `None` when
/// the file isn't an office document or fails to parse.
///
/// Pure read path — no findings, no metric population, no
/// capability-mapper invocation. The returned `Value` matches the
/// schema documented in this module.
pub(crate) fn extract_office_kv(path: &Path, data: &[u8]) -> Option<Value> {
    let file_type = crate::analyzers::detect_file_type_from_data(path, data);
    match file_type {
        FileType::OleDoc => {
            let doc = ole2::parse_ole2(data).ok()?;
            Some(build_ole_kv(&doc))
        }
        FileType::Ooxml => {
            let doc = ooxml::parse_ooxml(data).ok()?;
            Some(build_ooxml_kv(&doc))
        }
        _ => None,
    }
}

/// Build the kv tree for a parsed OLE2 compound document.
#[must_use]
pub(crate) fn build_ole_kv(doc: &ole2::Ole2Document) -> Value {
    let mut root = Map::new();

    // ole.compobj.*
    if let Some(c) = &doc.compobj {
        let mut compobj = Map::new();
        if !c.user_type.is_empty() {
            compobj.insert("user_type".into(), json!(c.user_type));
        }
        if !c.clipboard_format.is_empty() {
            compobj.insert("clipboard_format".into(), json!(c.clipboard_format));
        }
        if !c.app_version.is_empty() {
            compobj.insert("app_version".into(), json!(c.app_version));
        }
        if !compobj.is_empty() {
            let mut ole = Map::new();
            ole.insert("compobj".into(), Value::Object(compobj));
            root.insert("ole".into(), Value::Object(ole));
        }
    }

    // summary.*
    let mut summary = Map::new();
    insert_str(&mut summary, "title", doc.metadata.title.as_deref());
    insert_str(&mut summary, "author", doc.metadata.author.as_deref());
    insert_str(
        &mut summary,
        "last_author",
        doc.metadata.last_author.as_deref(),
    );
    insert_str(
        &mut summary,
        "application",
        doc.metadata.application.as_deref(),
    );
    insert_str(
        &mut summary,
        "create_time",
        doc.metadata.create_time.as_deref(),
    );
    insert_str(
        &mut summary,
        "last_save_time",
        doc.metadata.last_save_time.as_deref(),
    );
    if let Some(r) = doc.metadata.revision_number {
        summary.insert("revision".into(), json!(r));
    }
    if !summary.is_empty() {
        root.insert("summary".into(), Value::Object(summary));
    }

    // embedded[]
    let embedded = build_ole_embedded(doc);
    if !embedded.is_empty() {
        root.insert("embedded".into(), Value::Array(embedded));
    }

    Value::Object(root)
}

/// Build the kv tree for a parsed OOXML document.
#[must_use]
pub(crate) fn build_ooxml_kv(doc: &ooxml::OoxmlDocument) -> Value {
    let mut root = Map::new();

    // core.* — Dublin Core + OOXML extras
    let mut core = Map::new();
    insert_str(&mut core, "creator", doc.metadata.creator.as_deref());
    insert_str(
        &mut core,
        "last_modified_by",
        doc.metadata.last_modified_by.as_deref(),
    );
    insert_str(&mut core, "created", doc.metadata.created.as_deref());
    insert_str(&mut core, "modified", doc.metadata.modified.as_deref());
    insert_str(
        &mut core,
        "application",
        doc.metadata.application.as_deref(),
    );
    insert_str(&mut core, "company", doc.metadata.company.as_deref());
    insert_str(&mut core, "title", doc.metadata.title.as_deref());
    insert_str(&mut core, "subject", doc.metadata.subject.as_deref());
    insert_str(
        &mut core,
        "description",
        doc.metadata.description.as_deref(),
    );
    insert_str(&mut core, "keywords", doc.metadata.keywords.as_deref());
    insert_str(&mut core, "category", doc.metadata.category.as_deref());
    if !core.is_empty() {
        root.insert("core".into(), Value::Object(core));
    }

    // relationships[] — flatten external_refs to (type, target) tuples.
    if !doc.external_refs.is_empty() {
        let rels: Vec<Value> = doc
            .external_refs
            .iter()
            .map(|r| {
                json!({
                    // Strip the schema URI prefix; trait authors care about
                    // the relationship suffix (`attachedTemplate`,
                    // `oleObject`, `image`, etc.), not the namespace.
                    "type": r
                        .rel_type
                        .rsplit('/')
                        .next()
                        .unwrap_or(r.rel_type.as_str()),
                    "target": r.target,
                })
            })
            .collect();
        root.insert("relationships".into(), Value::Array(rels));
    }

    // embedded[] — OOXML embedded executable list (filename only — we
    // don't sniff size at this layer; the count lives on metrics).
    if !doc.embedded_executables.is_empty() {
        let embedded: Vec<Value> = doc
            .embedded_executables
            .iter()
            .map(|name| {
                json!({
                    "filename": name,
                })
            })
            .collect();
        root.insert("embedded".into(), Value::Array(embedded));
    }

    Value::Object(root)
}

/// Build the kv `embedded[]` array for an OLE2 document. Combines
/// OLE10Native objects (which have explicit filenames) and embedded
/// PE/ELF streams (which don't, so we use the stream path as the
/// filename surrogate).
fn build_ole_embedded(doc: &ole2::Ole2Document) -> Vec<Value> {
    let mut out = Vec::new();
    for obj in &doc.ole10_native_objects {
        let mut entry = Map::new();
        if let Some(name) = &obj.embedded_filename {
            entry.insert("filename".into(), json!(name));
        }
        entry.insert("size".into(), json!(obj.embedded_size));
        entry.insert("source".into(), json!("ole10native"));
        out.push(Value::Object(entry));
    }
    for exec in &doc.embedded_executables {
        out.push(json!({
            "filename": exec.stream_path,
            "size": exec.data.len(),
            "source": "ole_stream",
            "kind": format!("{:?}", exec.kind).to_lowercase(),
        }));
    }
    out
}

fn insert_str(map: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(v) = value {
        let trimmed = v.trim();
        if !trimmed.is_empty() {
            map.insert(key.into(), Value::String(trimmed.to_string()));
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::analyzers::office::ole2::{
        ClsidMatch, CompObjData, DocumentMetadata, Ole10NativeInfo, Ole2Document, Ole2Subtype,
    };
    use crate::analyzers::office::ooxml::{
        ExternalRef, OoxmlDocument, OoxmlMetadata, OoxmlSubtype,
    };

    fn empty_ole_doc() -> Ole2Document {
        Ole2Document {
            doc_subtype: Ole2Subtype::Word,
            has_vba: false,
            vba_modules: Vec::new(),
            has_encryption: false,
            stream_names: Vec::new(),
            embedded_executables: Vec::new(),
            ole10_native_objects: Vec::new(),
            dangerous_clsids: Vec::<ClsidMatch>::new(),
            metadata: DocumentMetadata::default(),
            compobj: None,
        }
    }

    fn empty_ooxml_doc() -> OoxmlDocument {
        OoxmlDocument {
            doc_subtype: OoxmlSubtype::Word,
            has_vba: false,
            vba_modules: Vec::new(),
            external_refs: Vec::new(),
            dde_links: Vec::new(),
            embedded_executables: Vec::new(),
            metadata: OoxmlMetadata::default(),
            has_encryption: false,
            entry_names: Vec::new(),
            word_document_xml: None,
            content_types_xml: None,
            workbook_xml: None,
            workbook_rels_xml: None,
            excel_styles_xml: None,
            excel_macrosheet_xml: None,
            vba_project_strings: Vec::new(),
            max_entry_size: 0,
        }
    }

    #[test]
    fn ole_kv_empty_document_produces_empty_object() {
        let doc = empty_ole_doc();
        let kv = build_ole_kv(&doc);
        assert_eq!(kv, json!({}));
    }

    #[test]
    fn ole_kv_compobj_and_summary_populated() {
        let mut doc = empty_ole_doc();
        doc.compobj = Some(CompObjData {
            user_type: "Microsoft Office Excel Worksheet".into(),
            clipboard_format: "Biff8".into(),
            app_version: "Excel.Sheet.8".into(),
        });
        doc.metadata = DocumentMetadata {
            title: Some("Q4 Report".into()),
            author: Some("John Doe".into()),
            last_author: Some("Иван Иванов".into()),
            application: Some("Microsoft Office Word".into()),
            create_time: Some("2025-03-12T10:30:00Z".into()),
            last_save_time: Some("2026-12-01T11:45:00Z".into()),
            revision_number: Some(7),
            ..Default::default()
        };
        let kv = build_ole_kv(&doc);
        assert_eq!(
            value["ole"]["compobj"]["user_type"],
            "Microsoft Office Excel Worksheet"
        );
        assert_eq!(value["ole"]["compobj"]["clipboard_format"], "Biff8");
        assert_eq!(value["ole"]["compobj"]["app_version"], "Excel.Sheet.8");
        assert_eq!(value["summary"]["title"], "Q4 Report");
        assert_eq!(value["summary"]["author"], "John Doe");
        assert_eq!(value["summary"]["last_author"], "Иван Иванов");
        assert_eq!(value["summary"]["create_time"], "2025-03-12T10:30:00Z");
        assert_eq!(value["summary"]["revision"], 7);
        // Empty optional sections must not appear
        assert!(kv.get("core").is_none());
        assert!(kv.get("relationships").is_none());
    }

    #[test]
    fn ole_kv_ole10_native_filename_surfaces() {
        let mut doc = empty_ole_doc();
        doc.ole10_native_objects.push(Ole10NativeInfo {
            stream_path: "/ObjectPool/_1234/\\x01Ole10Native".into(),
            embedded_filename: Some("invoice.exe".into()),
            embedded_size: 524288,
        });
        let kv = build_ole_kv(&doc);
        let embedded = value["embedded"].as_array().unwrap();
        assert_eq!(embedded.len(), 1);
        assert_eq!(embedded[0]["filename"], "invoice.exe");
        assert_eq!(embedded[0]["size"], 524288);
        assert_eq!(embedded[0]["source"], "ole10native");
    }

    #[test]
    fn ooxml_kv_core_props_and_relationships() {
        let mut doc = empty_ooxml_doc();
        doc.metadata = OoxmlMetadata {
            creator: Some("John Doe".into()),
            last_modified_by: Some("Jane".into()),
            created: Some("2025-03-12T10:30:00Z".into()),
            modified: Some("2026-12-01T11:45:00Z".into()),
            application: Some("Microsoft Office Word".into()),
            company: Some("Contoso".into()),
            title: Some("Quarterly".into()),
            subject: None,
            description: None,
            keywords: Some("invoice".into()),
            category: None,
        };
        doc.external_refs.push(ExternalRef {
            source: "word/_rels/document.xml.rels".into(),
            target: "https://attacker.example/template.dotm".into(),
            rel_type:
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
                    .into(),
        });
        doc.external_refs.push(ExternalRef {
            source: "word/_rels/document.xml.rels".into(),
            target: "https://example.com/pixel.gif".into(),
            rel_type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image"
                .into(),
        });
        let kv = build_ooxml_kv(&doc);
        assert_eq!(value["core"]["creator"], "John Doe");
        assert_eq!(value["core"]["last_modified_by"], "Jane");
        assert_eq!(value["core"]["application"], "Microsoft Office Word");
        assert_eq!(value["core"]["keywords"], "invoice");
        let rels = value["relationships"].as_array().unwrap();
        assert_eq!(rels.len(), 2);
        // The schema-URI prefix is stripped — trait authors match on
        // `attachedTemplate` / `image`, not the full URI.
        assert_eq!(rels[0]["type"], "attachedTemplate");
        assert_eq!(rels[0]["target"], "https://attacker.example/template.dotm");
        assert_eq!(rels[1]["type"], "image");
    }

    /// `extract_office_kv` returns None for non-office formats so the
    /// `cleave value` command falls through to its existing manifest path.
    #[test]
    fn extract_office_kv_returns_none_for_non_office() {
        // PNG magic — not OLE2 or ZIP.
        let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        assert!(extract_office_kv(std::path::Path::new("img.png"), &png).is_none());

        // Plain text.
        let txt = b"hello world\n";
        assert!(extract_office_kv(std::path::Path::new("notes.txt"), txt).is_none());
    }

    #[test]
    fn whitespace_only_strings_are_dropped() {
        let mut doc = empty_ole_doc();
        doc.metadata.author = Some("   ".into());
        doc.metadata.title = Some("Real Title".into());
        let kv = build_ole_kv(&doc);
        assert!(value["summary"].get("author").is_none());
        assert_eq!(value["summary"]["title"], "Real Title");
    }
}
