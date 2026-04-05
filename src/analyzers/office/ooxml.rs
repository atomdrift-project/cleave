//! OOXML document parser for modern Office formats.
//!
//! Handles .docx, .xlsx, .pptx and macro-enabled variants (.docm, .xlsm, .pptm).
//! These are ZIP archives containing XML files and optional VBA project binaries.

use super::{ole2, vba};
use anyhow::Result;
use std::io::{Cursor, Read};

/// Parsed OOXML document.
#[derive(Debug)]
#[allow(dead_code)] // Fields used for Debug output and future analysis expansion
pub(crate) struct OoxmlDocument {
    /// Document subtype (Word, Excel, PowerPoint)
    pub doc_subtype: OoxmlSubtype,
    /// Whether VBA macros were found (vbaProject.bin present)
    pub has_vba: bool,
    /// Extracted VBA modules (if any)
    pub vba_modules: Vec<vba::VbaModule>,
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

/// Document metadata from docProps.
#[derive(Debug, Default)]
pub(crate) struct OoxmlMetadata {
    pub creator: Option<String>,
    pub last_modified_by: Option<String>,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub application: Option<String>,
    pub company: Option<String>,
}

/// Check if data is an OOXML document (ZIP with [Content_Types].xml).
pub(crate) fn is_ooxml(data: &[u8]) -> bool {
    if data.len() < 4 || &data[..2] != b"PK" {
        return false;
    }
    let cursor = Cursor::new(data);
    if let Ok(archive) = zip::ZipArchive::new(cursor) {
        archive.file_names().any(|n| n == "[Content_Types].xml")
    } else {
        false
    }
}

/// Parse an OOXML document.
pub(crate) fn parse_ooxml(data: &[u8]) -> Result<OoxmlDocument> {
    let cursor = Cursor::new(data);
    let mut archive = zip::ZipArchive::new(cursor)?;

    // Collect entry names
    let entry_names: Vec<String> = archive.file_names().map(String::from).collect();

    // Detect document type from [Content_Types].xml
    let doc_subtype = detect_subtype(&mut archive);

    // Check for VBA project
    let has_vba = entry_names
        .iter()
        .any(|n| n.to_lowercase().contains("vbaproject.bin"));

    // Extract VBA modules
    let vba_modules = if has_vba {
        extract_vba_from_ooxml(&mut archive, &entry_names)
    } else {
        Vec::new()
    };
    let vba_project_strings = extract_vba_project_strings(&mut archive, &entry_names);

    // Find external references (template injection)
    let external_refs = find_external_refs(&mut archive, &entry_names);

    // Detect DDE links
    let dde_links = find_dde_links(&mut archive, &entry_names);

    // Find embedded executables
    let embedded_executables = find_embedded_executables(&mut archive, &entry_names);

    // Extract metadata
    let metadata = extract_metadata(&mut archive);
    let content_types_xml = read_zip_entry(&mut archive, "[Content_Types].xml")
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    let word_document_xml = match doc_subtype {
        OoxmlSubtype::Word => read_zip_entry(&mut archive, "word/document.xml")
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        _ => None,
    };
    let workbook_xml = match doc_subtype {
        OoxmlSubtype::Excel => read_zip_entry(&mut archive, "xl/workbook.xml")
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        _ => None,
    };
    let workbook_rels_xml = match doc_subtype {
        OoxmlSubtype::Excel => read_zip_entry(&mut archive, "xl/_rels/workbook.xml.rels")
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        _ => None,
    };
    let excel_styles_xml = match doc_subtype {
        OoxmlSubtype::Excel => read_zip_entry(&mut archive, "xl/styles.xml")
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        _ => None,
    };
    let excel_macrosheet_xml = match doc_subtype {
        OoxmlSubtype::Excel => entry_names
            .iter()
            .find(|n| n.starts_with("xl/macrosheets/") && n.ends_with(".xml"))
            .and_then(|name| read_zip_entry(&mut archive, name))
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned()),
        _ => None,
    };

    // Check for encryption marker
    let has_encryption = entry_names
        .iter()
        .any(|n| n.contains("EncryptedPackage") || n.contains("EncryptionInfo"));

    Ok(OoxmlDocument {
        doc_subtype,
        has_vba,
        vba_modules,
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
    })
}

/// Detect document subtype from [Content_Types].xml.
fn detect_subtype(archive: &mut zip::ZipArchive<Cursor<&[u8]>>) -> OoxmlSubtype {
    let Some(xml) = read_zip_entry(archive, "[Content_Types].xml") else {
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

/// Extract VBA modules from vbaProject.bin within the OOXML archive.
fn extract_vba_from_ooxml(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
    entry_names: &[String],
) -> Vec<vba::VbaModule> {
    // Find the vbaProject.bin entry
    let vba_entry = entry_names
        .iter()
        .find(|n| n.to_lowercase().ends_with("vbaproject.bin"))
        .or_else(|| {
            entry_names
                .iter()
                .find(|n| n.to_lowercase().contains("vbaproject.bin"))
        });

    let vba_path = match vba_entry {
        Some(path) => path.clone(),
        None => return Vec::new(),
    };

    let Some(vba_data) = read_zip_entry(archive, &vba_path) else {
        return Vec::new();
    };

    // vbaProject.bin is itself an OLE2 compound file
    match vba::extract_vba_modules(&vba_data) {
        Ok(modules) => modules,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to extract VBA from OOXML vbaProject.bin");
            Vec::new()
        }
    }
}

fn extract_vba_project_strings(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
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
    let Some(vba_data) = read_zip_entry(archive, vba_path) else {
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
fn find_external_refs(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
    entry_names: &[String],
) -> Vec<ExternalRef> {
    let mut refs = Vec::new();

    let rels_entries: Vec<String> = entry_names
        .iter()
        .filter(|n| n.ends_with(".rels"))
        .cloned()
        .collect();

    for rels_path in &rels_entries {
        let Some(data) = read_zip_entry(archive, rels_path) else {
            continue;
        };

        let text = String::from_utf8_lossy(&data);

        // Parse XML to find External TargetMode
        if let Ok(doc) = roxmltree::Document::parse(&text) {
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
fn find_dde_links(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
    entry_names: &[String],
) -> Vec<String> {
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
        let Some(data) = read_zip_entry(archive, entry_path) else {
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
                        dde_links.push(format!("{}...", &trimmed[..200]));
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
fn find_embedded_executables(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
    entry_names: &[String],
) -> Vec<String> {
    let mut found = Vec::new();

    let embed_entries: Vec<String> = entry_names
        .iter()
        .filter(|n| n.contains("embeddings/") || n.contains("oleObject") || n.contains("activeX/"))
        .cloned()
        .collect();

    for entry_path in &embed_entries {
        let Some(data) = read_zip_entry(archive, entry_path) else {
            continue;
        };

        if data.len() >= 2 {
            // Check for MZ (PE)
            if data[0] == b'M' && data[1] == b'Z' {
                found.push(entry_path.clone());
                continue;
            }
            // Check for ELF
            if data.len() >= 4 && data[..4] == [0x7f, b'E', b'L', b'F'] {
                found.push(entry_path.clone());
                continue;
            }
            // Check for OLE2 containing PE (embedded OLE objects)
            if data.len() >= 8 && ole2::is_ole2(&data) {
                // Scan the first few KB for MZ within the OLE2 container
                let scan_len = data.len().min(64 * 1024);
                if memchr::memmem::find(&data[..scan_len], b"MZ").is_some() {
                    found.push(entry_path.clone());
                }
            }
        }
    }

    found
}

/// Extract metadata from docProps/core.xml and docProps/app.xml.
fn extract_metadata(archive: &mut zip::ZipArchive<Cursor<&[u8]>>) -> OoxmlMetadata {
    let mut meta = OoxmlMetadata::default();

    // Parse core.xml (Dublin Core metadata)
    if let Some(data) = read_zip_entry(archive, "docProps/core.xml") {
        let text = String::from_utf8_lossy(&data);
        if let Ok(doc) = roxmltree::Document::parse(&text) {
            for node in doc.descendants() {
                match node.tag_name().name() {
                    "creator" => meta.creator = node.text().map(String::from),
                    "lastModifiedBy" => meta.last_modified_by = node.text().map(String::from),
                    "created" => meta.created = node.text().map(String::from),
                    "modified" => meta.modified = node.text().map(String::from),
                    _ => {}
                }
            }
        }
    }

    // Parse app.xml (application metadata)
    if let Some(data) = read_zip_entry(archive, "docProps/app.xml") {
        let text = String::from_utf8_lossy(&data);
        if let Ok(doc) = roxmltree::Document::parse(&text) {
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
fn read_zip_entry(archive: &mut zip::ZipArchive<Cursor<&[u8]>>, name: &str) -> Option<Vec<u8>> {
    let mut entry = archive.by_name(name).ok()?;
    // Limit to 50MB to prevent zip bombs
    if entry.size() > 50 * 1024 * 1024 {
        return None;
    }
    let mut data = Vec::with_capacity(entry.size() as usize);
    entry.read_to_end(&mut data).ok()?;
    Some(data)
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

    #[test]
    fn test_is_ooxml_non_zip() {
        assert!(!is_ooxml(b"not a zip file"));
        assert!(!is_ooxml(&[0xD0, 0xCF, 0x11, 0xE0])); // OLE2 magic
    }

    #[test]
    fn test_is_ooxml_plain_zip() {
        // Create a minimal ZIP without [Content_Types].xml
        let buf = Vec::new();
        let cursor = Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        #[allow(clippy::expect_used)]
        writer.start_file("test.txt", options).expect("start_file");
        #[allow(clippy::expect_used)]
        let cursor = writer.finish().expect("finish");
        let data = cursor.into_inner();
        assert!(!is_ooxml(&data)); // ZIP but not OOXML
    }

    #[test]
    fn test_is_ooxml_valid() {
        // Create a minimal ZIP with [Content_Types].xml
        let buf = Vec::new();
        let cursor = Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        #[allow(clippy::expect_used)]
        writer
            .start_file("[Content_Types].xml", options)
            .expect("start_file");
        #[allow(clippy::expect_used)]
        let cursor = writer.finish().expect("finish");
        let data = cursor.into_inner();
        assert!(is_ooxml(&data));
    }
}
