//! OOXML document parser for modern Office formats.
//!
//! Handles .docx, .xlsx, .pptx and macro-enabled variants (.docm, .xlsm, .pptm).
//! These are ZIP archives containing XML files and optional VBA project binaries.

use crate::analyzers::utils::parse_xml_safe;
use crate::types::ArchiveEntry;
use anyhow::Result;
use std::io::{Cursor, Read};

const OOXML_ENTRY_READ_LIMIT: u64 = 50 * 1024 * 1024;

/// Parsed OOXML document.
#[derive(Debug)]
#[allow(dead_code)] // Fields used for Debug output and future analysis expansion
pub(crate) struct OoxmlDocument {
    /// Document subtype (Word, Excel, PowerPoint)
    pub doc_subtype: OoxmlSubtype,
    /// Whether VBA macros were found (vbaProject.bin present)
    pub has_vba: bool,
    /// External template references (template injection vector)
    pub external_refs: Vec<ExternalRef>,
    /// DDE field codes found
    pub dde_links: Vec<String>,
    /// Embedded objects that contain PE/ELF executables
    pub embedded_executables: Vec<String>,
    /// Document metadata
    pub metadata: OoxmlMetadata,
    /// Whether the document is encrypted
    pub has_encryption: bool,
    /// ZIP entry names
    pub entry_names: Vec<String>,
    /// Decompressed Word document XML text when available
    pub word_document_xml: Option<String>,
    /// Decompressed [Content_Types].xml when available
    pub content_types_xml: Option<String>,
    /// Decompressed Excel workbook XML when available
    pub workbook_xml: Option<String>,
    /// Decompressed Excel workbook relationship XML when available
    pub workbook_rels_xml: Option<String>,
    /// Decompressed Excel styles XML when available
    pub excel_styles_xml: Option<String>,
    /// Decompressed Excel macrosheet XML when available
    pub excel_macrosheet_xml: Option<String>,
    /// Printable strings recovered from vbaProject.bin when present
    pub vba_project_strings: Vec<String>,
    /// Largest ZIP member uncompressed size.
    pub max_entry_size: u64,
}

/// OOXML document subtype.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OoxmlSubtype {
    Word,
    Excel,
    PowerPoint,
    Unknown,
}

impl OoxmlSubtype {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Word => "docx",
            Self::Excel => "xlsx",
            Self::PowerPoint => "pptx",
            Self::Unknown => "ooxml",
        }
    }
}

/// An external reference found in relationship files.
#[derive(Debug, Clone)]
pub(crate) struct ExternalRef {
    pub source: String,
    pub target: String,
    pub rel_type: String,
}

/// Document metadata from docProps/core.xml (Dublin Core) and
/// docProps/app.xml (Office-specific application metadata).
///
/// Field names mirror the OPC element tags so the office values tree
/// snake_case mapping is mechanical.
#[derive(Debug, Default)]
pub(crate) struct OoxmlMetadata {
    pub creator: Option<String>,
    pub last_modified_by: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub application: Option<String>,
    pub company: Option<String>,
    pub title: Option<String>,
    pub subject: Option<String>,
    pub description: Option<String>,
    pub keywords: Option<String>,
    pub category: Option<String>,
}

/// Read OOXML entries from either a filefacts ZIP index or a local ZIP parser.
trait OoxmlEntryReader {
    fn entry_names(&self) -> &[String];
    fn max_entry_size(&self) -> u64;
    fn read_entry(&mut self, name: &str) -> Option<Vec<u8>>;
}

struct ZipArchiveReader<'a> {
    archive: zip::ZipArchive<Cursor<&'a [u8]>>,
    entry_names: Vec<String>,
    max_entry_size: u64,
}

impl<'a> ZipArchiveReader<'a> {
    fn new(data: &'a [u8]) -> Result<Self> {
        let cursor = Cursor::new(data);
        let mut archive = zip::ZipArchive::new(cursor)?;
        if archive.len() > crate::analyzers::archive::MAX_ZIP_ENTRIES {
            anyhow::bail!(
                "OOXML ZIP claims {} entries (max {})",
                archive.len(),
                crate::analyzers::archive::MAX_ZIP_ENTRIES
            );
        }

        let mut entry_names = Vec::with_capacity(archive.len());
        let mut max_entry_size = 0u64;
        for i in 0..archive.len() {
            let entry = archive.by_index(i)?;
            max_entry_size = max_entry_size.max(entry.size());
            entry_names.push(entry.name().to_string());
        }

        Ok(Self {
            archive,
            entry_names,
            max_entry_size,
        })
    }
}

impl OoxmlEntryReader for ZipArchiveReader<'_> {
    fn entry_names(&self) -> &[String] {
        &self.entry_names
    }

    fn max_entry_size(&self) -> u64 {
        self.max_entry_size
    }

    fn read_entry(&mut self, name: &str) -> Option<Vec<u8>> {
        let mut entry = self.archive.by_name(name).ok()?;
        if entry.size() > OOXML_ENTRY_READ_LIMIT {
            return None;
        }
        let mut data = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut data).ok()?;
        Some(data)
    }
}

struct IndexedZipReader<'a> {
    data: &'a [u8],
    entries: &'a [ArchiveEntry],
    entry_names: Vec<String>,
    max_entry_size: u64,
}

impl<'a> IndexedZipReader<'a> {
    fn new(data: &'a [u8], entries: &'a [ArchiveEntry]) -> Option<Self> {
        if entries.is_empty() || entries.len() > crate::analyzers::archive::MAX_ZIP_ENTRIES {
            return None;
        }
        let mut entry_names = Vec::with_capacity(entries.len());
        let mut max_entry_size = 0u64;
        for entry in entries {
            entry_names.push(entry.path.clone());
            max_entry_size = max_entry_size.max(entry.size_bytes);
        }
        Some(Self {
            data,
            entries,
            entry_names,
            max_entry_size,
        })
    }

    fn find(&self, name: &str) -> Option<&ArchiveEntry> {
        self.entries.iter().find(|entry| entry.path == name)
    }
}

impl OoxmlEntryReader for IndexedZipReader<'_> {
    fn entry_names(&self) -> &[String] {
        &self.entry_names
    }

    fn max_entry_size(&self) -> u64 {
        self.max_entry_size
    }

    fn read_entry(&mut self, name: &str) -> Option<Vec<u8>> {
        let entry = self.find(name)?;
        if entry.entry_type.as_deref() == Some("directory") || entry.encrypted {
            return None;
        }
        if entry.size_bytes > OOXML_ENTRY_READ_LIMIT {
            return None;
        }
        crate::analyzers::archive::zip::read_indexed_zip_member(
            self.data,
            entry,
            OOXML_ENTRY_READ_LIMIT,
        )
        .ok()
    }
}

/// Parse an OOXML document.
pub(crate) fn parse_ooxml(data: &[u8]) -> Result<OoxmlDocument> {
    let mut reader = ZipArchiveReader::new(data)?;
    Ok(parse_ooxml_from_reader(&mut reader))
}

/// Parse an OOXML document, borrowing filefacts's ZIP member index when available.
pub(crate) fn parse_ooxml_with_archive_entries(
    data: &[u8],
    entries: &[ArchiveEntry],
) -> Result<OoxmlDocument> {
    if let Some(mut reader) = IndexedZipReader::new(data, entries) {
        return Ok(parse_ooxml_from_reader(&mut reader));
    }
    parse_ooxml(data)
}

fn parse_ooxml_from_reader<R: OoxmlEntryReader>(reader: &mut R) -> OoxmlDocument {
    let entry_names: Vec<String> = reader.entry_names().to_vec();
    let max_entry_size = reader.max_entry_size();

    let doc_subtype = detect_subtype(reader);

    let has_vba = entry_names
        .iter()
        .any(|n| n.to_lowercase().contains("vbaproject.bin"));

    // VBA module source is decompressed by filefacts (from vbaProject.bin)
    // and read back via `vba::modules_from_ctx`; the parser only records
    // macro presence and the raw vbaProject string surface.
    let vba_project_strings = extract_vba_project_strings(reader, &entry_names);
    let external_refs = find_external_refs(reader, &entry_names);
    let dde_links = find_dde_links(reader, &entry_names);
    let embedded_executables = find_embedded_executables(reader, &entry_names);
    let metadata = extract_metadata(reader);
    let content_types_xml = read_zip_entry(reader, "[Content_Types].xml")
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    let word_document_xml = match doc_subtype {
        OoxmlSubtype::Word => read_zip_entry(reader, "word/document.xml")
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        _ => None,
    };
    let workbook_xml = match doc_subtype {
        OoxmlSubtype::Excel => read_zip_entry(reader, "xl/workbook.xml")
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        _ => None,
    };
    let workbook_rels_xml = match doc_subtype {
        OoxmlSubtype::Excel => read_zip_entry(reader, "xl/_rels/workbook.xml.rels")
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        _ => None,
    };
    let excel_styles_xml = match doc_subtype {
        OoxmlSubtype::Excel => read_zip_entry(reader, "xl/styles.xml")
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        _ => None,
    };
    let excel_macrosheet_xml = match doc_subtype {
        OoxmlSubtype::Excel => entry_names
            .iter()
            .find(|n| n.starts_with("xl/macrosheets/") && n.ends_with(".xml"))
            .and_then(|name| read_zip_entry(reader, name))
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        _ => None,
    };

    let has_encryption = entry_names
        .iter()
        .any(|n| n.contains("EncryptedPackage") || n.contains("EncryptionInfo"));

    OoxmlDocument {
        doc_subtype,
        has_vba,
        external_refs,
        dde_links,
        embedded_executables,
        metadata,
        has_encryption,
        entry_names,
        word_document_xml,
        content_types_xml,
        workbook_xml,
        workbook_rels_xml,
        excel_styles_xml,
        excel_macrosheet_xml,
        vba_project_strings,
        max_entry_size,
    }
}

/// Detect document subtype from [Content_Types].xml.
fn detect_subtype<R: OoxmlEntryReader>(reader: &mut R) -> OoxmlSubtype {
    let Some(xml) = read_zip_entry(reader, "[Content_Types].xml") else {
        return OoxmlSubtype::Unknown;
    };

    let text = String::from_utf8_lossy(&xml);
    if text.contains("wordprocessingml") || text.contains("word/") {
        OoxmlSubtype::Word
    } else if text.contains("spreadsheetml") || text.contains("xl/") {
        OoxmlSubtype::Excel
    } else if text.contains("presentationml") || text.contains("ppt/") {
        OoxmlSubtype::PowerPoint
    } else {
        OoxmlSubtype::Unknown
    }
}

fn extract_vba_project_strings<R: OoxmlEntryReader>(
    reader: &mut R,
    entry_names: &[String],
) -> Vec<String> {
    let vba_entry = entry_names
        .iter()
        .find(|n| n.to_lowercase().ends_with("vbaproject.bin"))
        .or_else(|| {
            entry_names
                .iter()
                .find(|n| n.to_lowercase().contains("vbaproject.bin"))
        });
    let Some(vba_path) = vba_entry else {
        return Vec::new();
    };
    let Some(vba_data) = read_zip_entry(reader, vba_path) else {
        return Vec::new();
    };
    extract_ascii_strings(&vba_data, 4)
}

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Vec::new();
    for &b in data {
        if (0x20..=0x7e).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= min_len {
                out.push(String::from_utf8_lossy(&current).into_owned());
            }
            current.clear();
        }
    }
    if current.len() >= min_len {
        out.push(String::from_utf8_lossy(&current).into_owned());
    }
    out
}

/// Find external references in relationship (.rels) files.
///
/// Template injection attacks use `TargetMode="External"` in .rels files
/// to fetch remote templates containing malicious macros.
fn find_external_refs<R: OoxmlEntryReader>(
    reader: &mut R,
    entry_names: &[String],
) -> Vec<ExternalRef> {
    let mut refs = Vec::new();

    let rels_entries: Vec<String> = entry_names
        .iter()
        .filter(|n| n.ends_with(".rels"))
        .cloned()
        .collect();

    for rels_path in &rels_entries {
        let Some(data) = read_zip_entry(reader, rels_path) else {
            continue;
        };

        let text = String::from_utf8_lossy(&data);

        // Parse XML to find External TargetMode
        if let Some(doc) = parse_xml_safe(&text) {
            for node in doc.descendants() {
                if node.tag_name().name() == "Relationship" {
                    let target_mode = node.attribute("TargetMode").unwrap_or("");
                    if target_mode.eq_ignore_ascii_case("External") {
                        let target = node.attribute("Target").unwrap_or("").to_string();
                        let rel_type = node.attribute("Type").unwrap_or("").to_string();
                        if !target.is_empty() {
                            refs.push(ExternalRef {
                                source: rels_path.clone(),
                                target,
                                rel_type,
                            });
                        }
                    }
                }
            }
        }
    }

    refs
}

/// Detect DDE (Dynamic Data Exchange) field codes in document XML.
///
/// DDE is used in attacks to execute commands without macros.
fn find_dde_links<R: OoxmlEntryReader>(reader: &mut R, entry_names: &[String]) -> Vec<String> {
    let mut dde_links = Vec::new();

    // Check Word documents
    let doc_entries: Vec<String> = entry_names
        .iter()
        .filter(|n| {
            n.starts_with("word/") && n.ends_with(".xml") || n.starts_with("xl/externalLinks/")
        })
        .cloned()
        .collect();

    for entry_path in &doc_entries {
        let Some(data) = read_zip_entry(reader, entry_path) else {
            continue;
        };

        let text = String::from_utf8_lossy(&data);
        let text_upper = text.to_uppercase();

        // Look for DDE/DDEAUTO in field codes
        if text_upper.contains("DDEAUTO") || text_upper.contains("DDE ") {
            // Extract the DDE command context
            for line in text.lines() {
                let line_upper = line.to_uppercase();
                if line_upper.contains("DDEAUTO") || line_upper.contains("DDE ") {
                    let trimmed = line.trim();
                    if trimmed.len() > 200 {
                        dde_links.push(format!(
                            "{}...",
                            &trimmed[..trimmed.floor_char_boundary(200)]
                        ));
                    } else {
                        dde_links.push(trimmed.to_string());
                    }
                }
            }
        }
    }

    dde_links
}

/// Find embedded objects containing PE/ELF executables.
fn find_embedded_executables<R: OoxmlEntryReader>(
    reader: &mut R,
    entry_names: &[String],
) -> Vec<String> {
    let mut found = Vec::new();

    let embed_entries: Vec<String> = entry_names
        .iter()
        .filter(|n| n.contains("embeddings/") || n.contains("oleObject") || n.contains("activeX/"))
        .cloned()
        .collect();

    for entry_path in &embed_entries {
        let Some(data) = read_zip_entry(reader, entry_path) else {
            continue;
        };

        if data.len() >= 2 {
            // Check for MZ (PE)
            if data[0] == b'M' && data[1] == b'Z' {
                found.push(entry_path.clone());
                continue;
            }
            // Check for embedded executables (ELF, PE) or OLE2 containers with PE
            let file_type = filefacts::FileId::from_bytes(&data).file_type();
            match file_type {
                filefacts::FileType::Elf | filefacts::FileType::Pe | filefacts::FileType::MachO => {
                    found.push(entry_path.clone());
                    continue;
                }
                filefacts::FileType::OleDoc => {
                    // OLE2 container — scan for embedded PE
                    let scan_len = data.len().min(64 * 1024);
                    if memchr::memmem::find(&data[..scan_len], b"MZ").is_some() {
                        found.push(entry_path.clone());
                    }
                }
                _ => {}
            }
        }
    }

    found
}

/// Extract metadata from docProps/core.xml and docProps/app.xml.
fn extract_metadata<R: OoxmlEntryReader>(reader: &mut R) -> OoxmlMetadata {
    let mut meta = OoxmlMetadata::default();

    // Parse core.xml (Dublin Core metadata)
    if let Some(data) = read_zip_entry(reader, "docProps/core.xml") {
        let text = String::from_utf8_lossy(&data);
        if let Some(doc) = parse_xml_safe(&text) {
            for node in doc.descendants() {
                match node.tag_name().name() {
                    "creator" => meta.creator = node.text().map(String::from),
                    "lastModifiedBy" => meta.last_modified_by = node.text().map(String::from),
                    "created" => meta.created = node.text().map(String::from),
                    "modified" => meta.modified = node.text().map(String::from),
                    "title" => meta.title = node.text().map(String::from),
                    "subject" => meta.subject = node.text().map(String::from),
                    "description" => meta.description = node.text().map(String::from),
                    "keywords" => meta.keywords = node.text().map(String::from),
                    "category" => meta.category = node.text().map(String::from),
                    _ => {}
                }
            }
        }
    }

    // Parse app.xml (application metadata)
    if let Some(data) = read_zip_entry(reader, "docProps/app.xml") {
        let text = String::from_utf8_lossy(&data);
        if let Some(doc) = parse_xml_safe(&text) {
            for node in doc.descendants() {
                match node.tag_name().name() {
                    "Application" => meta.application = node.text().map(String::from),
                    "Company" => meta.company = node.text().map(String::from),
                    _ => {}
                }
            }
        }
    }

    meta
}

/// Read a ZIP entry by name, returning None on any error.
fn read_zip_entry<R: OoxmlEntryReader>(reader: &mut R, name: &str) -> Option<Vec<u8>> {
    reader.read_entry(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ooxml_subtype_str() {
        assert_eq!(OoxmlSubtype::Word.as_str(), "docx");
        assert_eq!(OoxmlSubtype::Excel.as_str(), "xlsx");
        assert_eq!(OoxmlSubtype::PowerPoint.as_str(), "pptx");
        assert_eq!(OoxmlSubtype::Unknown.as_str(), "ooxml");
    }

    fn tiny_docx() -> anyhow::Result<Vec<u8>> {
        use std::io::Write;

        let mut out = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut out);
            let options = zip::write::FileOptions::<()>::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zip.start_file("[Content_Types].xml", options)?;
            zip.write_all(br#"<Types><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#)?;
            zip.start_file("word/document.xml", options)?;
            zip.write_all(br#"<w:document><w:body><w:p>Hello</w:p></w:body></w:document>"#)?;
            zip.start_file("word/_rels/document.xml.rels", options)?;
            zip.write_all(br#"<Relationships><Relationship TargetMode="External" Target="https://example.invalid/template.dotm" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"/></Relationships>"#)?;
            zip.start_file("docProps/app.xml", options)?;
            zip.write_all(br#"<Properties><Application>Word</Application><Company>ACME</Company></Properties>"#)?;
            zip.finish()?;
        }
        Ok(out.into_inner())
    }

    #[test]
    fn parses_ooxml_from_filefacts_zip_index() -> anyhow::Result<()> {
        let data = tiny_docx()?;
        let path = std::path::Path::new("sample.docx");
        let ctx = crate::analysis_context::AnalysisContext::open(path, &data)?;
        let entries = ctx.archive_entries();
        assert!(
            !entries.is_empty(),
            "filefacts should expose OOXML ZIP entries"
        );
        assert!(entries.iter().any(|entry| entry.data_offset.is_some()));

        let doc = parse_ooxml_with_archive_entries(&data, &entries)?;
        assert_eq!(doc.doc_subtype, OoxmlSubtype::Word);
        assert!(doc.max_entry_size > 0);
        assert_eq!(doc.metadata.application.as_deref(), Some("Word"));
        assert_eq!(doc.external_refs.len(), 1);
        assert_eq!(
            doc.external_refs[0].target,
            "https://example.invalid/template.dotm"
        );
        Ok(())
    }

    /// Wrap raw bytes as a single uncompressed MS-OVBA chunk (≤ 4096).
    fn ovba_store(raw: &[u8]) -> Vec<u8> {
        let mut out = vec![0x01u8];
        out.extend_from_slice(&0u16.to_le_bytes()); // header, high bit clear → uncompressed
        out.extend_from_slice(raw);
        out
    }

    /// A `tiny_docx` with an added `word/vbaProject.bin` macro container
    /// holding a single module "Module1" whose source calls Shell.
    fn tiny_docm() -> anyhow::Result<Vec<u8>> {
        use std::io::{Cursor, Write};

        // dir stream: one standard module "Module1" at stream offset 0.
        let mut dir = Vec::new();
        let push = |d: &mut Vec<u8>, id: u16, body: &[u8]| {
            d.extend_from_slice(&id.to_le_bytes());
            d.extend_from_slice(&(body.len() as u32).to_le_bytes());
            d.extend_from_slice(body);
        };
        push(&mut dir, 0x0019, b"Module1"); // MODULENAME
        push(&mut dir, 0x001A, b"Module1"); // MODULESTREAMNAME
        push(&mut dir, 0x0031, &0u32.to_le_bytes()); // MODULEOFFSET
        push(&mut dir, 0x0021, &[]); // procedural
        push(&mut dir, 0x002B, &[]); // terminator
        let source = b"Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n  Shell \"calc.exe\"\r\nEnd Sub\r\n";

        let mut buf = Cursor::new(Vec::<u8>::new());
        {
            let mut comp = cfb::CompoundFile::create(&mut buf)?;
            comp.create_storage("/VBA")?;
            comp.create_stream("/VBA/dir")?
                .write_all(&ovba_store(&dir))?;
            comp.create_stream("/VBA/Module1")?
                .write_all(&ovba_store(source))?;
        }
        let vba_bin = buf.into_inner();

        let mut out = Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut out);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            zip.start_file("[Content_Types].xml", options)?;
            zip.write_all(br#"<Types><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/><Override PartName="/word/vbaProject.bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>"#)?;
            zip.start_file("word/document.xml", options)?;
            zip.write_all(br#"<w:document><w:body><w:p>Hello</w:p></w:body></w:document>"#)?;
            zip.start_file("docProps/app.xml", options)?;
            zip.write_all(br#"<Properties><Application>Word</Application></Properties>"#)?;
            zip.start_file("word/vbaProject.bin", options)?;
            zip.write_all(&vba_bin)?;
            zip.finish()?;
        }
        Ok(out.into_inner())
    }

    /// End-to-end keystone: filefacts decompresses the OOXML
    /// `vbaProject.bin` and cleave reads the module source back via
    /// `vba::modules_from_ctx` — no cleave-side decompressor involved.
    #[test]
    fn vba_modules_decompressed_via_filefacts() -> anyhow::Result<()> {
        let data = tiny_docm()?;
        let path = std::path::Path::new("evil.docm");
        let ctx = crate::analysis_context::AnalysisContext::open(path, &data)?;
        let modules = crate::analyzers::office::vba::modules_from_ctx(Some(&ctx));
        assert_eq!(modules.len(), 1, "one VBA module decompressed");
        assert_eq!(modules[0].name, "Module1");
        assert!(
            modules[0].source_code.contains("AutoOpen") && modules[0].source_code.contains("Shell"),
            "decompressed source: {}",
            modules[0].source_code
        );
        Ok(())
    }
}
