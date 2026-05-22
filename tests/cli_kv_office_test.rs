//! End-to-end test for `cleave value` over an office document.
//!
//! Builds a minimal OOXML archive containing `[Content_Types].xml`,
//! a relationships part, and `docProps/core.xml` populated with
//! Cyrillic / suspicious-date metadata. Invokes the binary's `value`
//! subcommand, parses the JSON output, and asserts that:
//!
//! 1. The synthesized office values tree drives the dump (paths under
//!    `core.*` etc., matching the `analyzers::office::office_kv`
//!    schema, not whatever the generic structured-content parser
//!    might guess from a ZIP).
//! 2. Path filtering (`--path core.creator`) works against the
//!    office tree.
//! 3. The output's `path` strings are the exact strings trait
//!    authors will use in `type: value path:`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;

fn build_minimal_docx(creator: &str, created: &str, modified: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = zip::ZipWriter::new(cursor);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);

        zip.start_file("[Content_Types].xml", opts).unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#,
        )
        .unwrap();

        zip.start_file("_rels/.rels", opts).unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"#,
        )
        .unwrap();

        zip.start_file("word/document.xml", opts).unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body><w:p><w:r><w:t>Test</w:t></w:r></w:p></w:body>
</w:document>"#,
        )
        .unwrap();

        zip.start_file("docProps/core.xml", opts).unwrap();
        let core = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                  xmlns:dc="http://purl.org/dc/elements/1.1/"
                  xmlns:dcterms="http://purl.org/dc/terms/"
                  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <dc:creator>{creator}</dc:creator>
  <cp:lastModifiedBy>{creator}</cp:lastModifiedBy>
  <dcterms:created xsi:type="dcterms:W3CDTF">{created}</dcterms:created>
  <dcterms:modified xsi:type="dcterms:W3CDTF">{modified}</dcterms:modified>
  <dc:title>Test</dc:title>
  <dc:subject>Audit</dc:subject>
  <dc:description>Q4 metrics</dc:description>
  <dc:language>en-US</dc:language>
</cp:coreProperties>"#
        );
        zip.write_all(core.as_bytes()).unwrap();

        zip.start_file("docProps/app.xml", opts).unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office Word</Application>
  <Company>Contoso</Company>
</Properties>"#,
        )
        .unwrap();

        zip.finish().unwrap();
    }
    buf
}

fn run_kv(path: &std::path::Path, filter: Option<&str>) -> serde_json::Value {
    let mut cmd = assert_cmd::cargo_bin_cmd!("cleave");
    cmd.env("CLEAVE_SKIP_YARA", "1")
        .args(["--json", "value", path.to_str().unwrap()]);
    if let Some(f) = filter {
        cmd.args(["--path", f]);
    }
    let output = cmd.output().expect("run cleave value");
    if !output.status.success() {
        panic!(
            "cleave value exited {}: stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).expect("parse value json")
}

fn paths_in(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .expect("entries array")
        .iter()
        .map(|e| e["path"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn cleave_kv_emits_office_schema_for_ooxml() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("evil.docx");
    let content = build_minimal_docx(
        "Иван Иванов",
        "2030-01-01T00:00:00Z",
        "2030-01-02T00:00:00Z",
    );
    std::fs::write(&path, &content).unwrap();

    let entries = run_kv(&path, None);
    let paths = paths_in(&entries);

    // Schema keys we promise trait authors. Filefacts namespaces OOXML
    // metadata under `office.*` — `office.core.*` for Dublin Core,
    // `office.application` / `office.company` for app-info.
    assert!(
        paths.iter().any(|p| p == "office.core.creator"),
        "paths: {:?}",
        paths
    );
    assert!(paths.iter().any(|p| p == "office.core.last_modified_by"));
    assert!(paths.iter().any(|p| p == "office.core.created"));
    assert!(paths.iter().any(|p| p == "office.core.modified"));
    assert!(paths.iter().any(|p| p == "office.core.title"));
    assert!(paths.iter().any(|p| p == "office.application"));
    assert!(paths.iter().any(|p| p == "office.company"));

    // Cyrillic creator round-trips intact through the xml-to-value path.
    let creator_entry = entries
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["path"] == "office.core.creator")
        .expect("creator entry present");
    assert_eq!(creator_entry["value"], "Иван Иванов");
}

#[test]
fn cleave_kv_filter_resolves_office_paths() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("doc.docx");
    let content = build_minimal_docx("Alice", "2024-06-01T00:00:00Z", "2024-06-02T00:00:00Z");
    std::fs::write(&path, &content).unwrap();

    let entries = run_kv(&path, Some("office.core.creator"));
    let arr = entries.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["path"], "office.core.creator");
    assert_eq!(arr[0]["value"], "Alice");
}
