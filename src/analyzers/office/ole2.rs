//! OLE2/CFBF compound document parser for legacy Office formats.
//!
//! Handles .doc, .xls, .ppt, .msg and other legacy Microsoft Office documents
//! that use the Compound File Binary Format (CFBF/OLE2).

use super::vba;
use anyhow::Result;
use std::io::{Cursor, Read};

/// Parsed OLE2 compound document.
#[derive(Debug)]
#[allow(dead_code)] // Fields used for Debug output and future analysis expansion
pub(crate) struct Ole2Document {
    /// Document subtype detected from streams
    pub doc_subtype: Ole2Subtype,
    /// Whether VBA macros were found
    pub has_vba: bool,
    /// Extracted VBA modules (if any)
    pub vba_modules: Vec<vba::VbaModule>,
    /// Whether the document is encrypted
    pub has_encryption: bool,
    /// Stream names found in the document
    pub stream_names: Vec<String>,
    /// Streams containing embedded PE/ELF executables
    pub embedded_executables: Vec<String>,
    /// OLE10Native embedded objects (filename, size)
    pub ole10_native_objects: Vec<Ole10NativeInfo>,
    /// Known dangerous CLSIDs found on storages
    pub dangerous_clsids: Vec<ClsidMatch>,
    /// Document metadata (author, title, etc.)
    pub metadata: DocumentMetadata,
}

/// Info about an OLE10Native embedded object.
#[derive(Debug, Clone)]
pub(crate) struct Ole10NativeInfo {
    pub stream_path: String,
    pub embedded_filename: Option<String>,
    pub embedded_size: u32,
}

/// A dangerous CLSID found on a storage entry.
#[derive(Debug, Clone)]
pub(crate) struct ClsidMatch {
    pub storage_path: String,
    pub clsid: String,
    pub description: &'static str,
}

/// Office document subtype detected from OLE2 stream names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ole2Subtype {
    Word,
    Excel,
    PowerPoint,
    Msg,
    Unknown,
}

impl Ole2Subtype {
    /// Return the file type string for report metadata.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Word => "doc",
            Self::Excel => "xls",
            Self::PowerPoint => "ppt",
            Self::Msg => "msg",
            Self::Unknown => "ole",
        }
    }
}

/// Document metadata extracted from SummaryInformation property set.
#[derive(Debug, Default)]
#[allow(dead_code)] // Fields populated for metadata reporting
pub(crate) struct DocumentMetadata {
    pub title: Option<String>,
    pub author: Option<String>,
    pub last_author: Option<String>,
    pub application: Option<String>,
    pub create_time: Option<String>,
    pub last_save_time: Option<String>,
}

/// OLE2 magic bytes: D0 CF 11 E0 A1 B1 1A E1
pub(crate) const OLE2_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Check if data starts with OLE2 magic bytes.
pub(crate) fn is_ole2(data: &[u8]) -> bool {
    data.len() >= 8 && data[..8] == OLE2_MAGIC
}

/// Parse an OLE2 compound document.
pub(crate) fn parse_ole2(data: &[u8]) -> Result<Ole2Document> {
    let cursor = Cursor::new(data);
    let mut comp = cfb::CompoundFile::open(cursor)?;

    // Enumerate all entries, collecting CLSIDs from storages
    let mut entries: Vec<(String, u64)> = Vec::new();
    let mut dangerous_clsids: Vec<ClsidMatch> = Vec::new();

    for entry in comp.walk() {
        let path = entry.path().to_string_lossy().to_string();
        let len = entry.len();

        // Check CLSIDs on storage entries
        if entry.is_storage() {
            let clsid = entry.clsid().to_string();
            if let Some(desc) = lookup_dangerous_clsid(&clsid) {
                dangerous_clsids.push(ClsidMatch {
                    storage_path: path.clone(),
                    clsid,
                    description: desc,
                });
            }
        }

        entries.push((path, len));
    }

    let stream_names: Vec<String> = entries.iter().map(|(name, _)| name.clone()).collect();

    // Detect document subtype
    let doc_subtype = detect_subtype(&stream_names);

    // Check for VBA
    let has_vba = stream_names
        .iter()
        .any(|s| s.to_lowercase().contains("/vba/") || s.to_lowercase().ends_with("/vba"));

    // Extract VBA modules
    let vba_modules = if has_vba {
        match vba::extract_vba_modules(data) {
            Ok(modules) => modules,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to extract VBA modules from OLE2");
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Check for encryption
    let has_encryption = stream_names
        .iter()
        .any(|s| s.contains("EncryptionInfo") || s.contains("EncryptedPackage"));

    // Check for embedded executables
    let embedded_executables = find_embedded_executables(&mut comp, &entries);

    // Check for OLE10Native embedded objects
    let ole10_native_objects = find_ole10_native(&mut comp, &entries);

    // Extract metadata
    let metadata = extract_metadata(&mut comp);

    Ok(Ole2Document {
        doc_subtype,
        has_vba,
        vba_modules,
        has_encryption,
        stream_names,
        embedded_executables,
        ole10_native_objects,
        dangerous_clsids,
        metadata,
    })
}

/// Detect document subtype from stream names.
fn detect_subtype(stream_names: &[String]) -> Ole2Subtype {
    for name in stream_names {
        let lower = name.to_lowercase();
        if lower.contains("worddocument") {
            return Ole2Subtype::Word;
        }
        if lower.contains("workbook") || lower.contains("/book") {
            return Ole2Subtype::Excel;
        }
        if lower.contains("powerpoint document") || lower.contains("powerpoint") {
            return Ole2Subtype::PowerPoint;
        }
        if lower.contains("__properties_version") || lower.contains("__substg1") {
            return Ole2Subtype::Msg;
        }
    }
    Ole2Subtype::Unknown
}

/// Scan streams for embedded PE/ELF executables.
fn find_embedded_executables(
    comp: &mut cfb::CompoundFile<Cursor<&[u8]>>,
    entries: &[(String, u64)],
) -> Vec<String> {
    let mut found = Vec::new();

    for (path, size) in entries {
        // Skip very large streams to avoid excessive memory use
        if *size > 50 * 1024 * 1024 || *size < 2 {
            continue;
        }

        // Only check streams that might contain embedded objects
        let lower = path.to_lowercase();
        if lower.contains("ole")
            || lower.contains("embed")
            || lower.contains("object")
            || lower.contains("package")
        {
            if let Ok(mut stream) = comp.open_stream(path) {
                let mut header = [0u8; 8];
                if stream.read_exact(&mut header).is_ok() {
                    // Check for MZ (PE) header
                    if header[0] == b'M' && header[1] == b'Z' {
                        found.push(path.clone());
                    }
                    // Check for ELF header
                    if header[..4] == [0x7f, b'E', b'L', b'F'] {
                        found.push(path.clone());
                    }
                }
            }
        }
    }

    found
}

/// Find OLE10Native embedded objects and extract their metadata.
///
/// OLE10Native streams contain embedded files (often executables) packaged
/// using the legacy OLE1 embedding format. The stream starts with a size
/// field followed by embedded file metadata (filename, path).
fn find_ole10_native(
    comp: &mut cfb::CompoundFile<Cursor<&[u8]>>,
    entries: &[(String, u64)],
) -> Vec<Ole10NativeInfo> {
    let mut found = Vec::new();

    for (path, size) in entries {
        if *size < 6 || *size > 50 * 1024 * 1024 {
            continue;
        }

        // OLE10Native streams have \x01Ole10Native in the name
        let lower = path.to_lowercase();
        if !lower.contains("ole10native") {
            continue;
        }

        if let Ok(mut stream) = comp.open_stream(path) {
            let mut header = vec![0u8; (*size).min(512) as usize];
            if stream.read_exact(&mut header).is_ok() {
                // OLE10Native format: u32 total_size, u16 version (==2)
                if header.len() >= 6 {
                    let total_size = u32::from_le_bytes([
                        header[0], header[1], header[2], header[3],
                    ]);
                    let version = u16::from_le_bytes([header[4], header[5]]);

                    let embedded_filename = if version == 2 && header.len() > 6 {
                        // After version, there are null-terminated strings: label, filename, ...
                        read_null_terminated(&header[6..])
                    } else {
                        None
                    };

                    found.push(Ole10NativeInfo {
                        stream_path: path.clone(),
                        embedded_filename,
                        embedded_size: total_size,
                    });
                }
            }
        }
    }

    found
}

/// Read a null-terminated ASCII string from bytes.
fn read_null_terminated(data: &[u8]) -> Option<String> {
    let end = data.iter().position(|&b| b == 0)?;
    if end == 0 {
        return None;
    }
    let s = String::from_utf8_lossy(&data[..end]).to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Known dangerous CLSIDs that indicate specific exploit vectors or suspicious objects.
///
/// These CLSIDs on storage entries signal known attack techniques:
/// - Equation Editor: CVE-2017-11882, CVE-2018-0802
/// - Packager Shell Object: Embeds arbitrary files
/// - scriptlet.typelib: Script execution
fn lookup_dangerous_clsid(clsid: &str) -> Option<&'static str> {
    // Normalize: cfb returns lowercase with hyphens
    match clsid {
        // Equation Editor (CVE-2017-11882, CVE-2018-0802)
        "0002ce02-0000-0000-c000-000000000046" => Some("Equation Editor 3.0 (CVE-2017-11882)"),
        // Packager Shell Object — embeds arbitrary files
        "f20da720-c02f-11ce-927b-0800095ae340" => Some("OLE Package Shell Object"),
        // scriptlet.typelib — script execution
        "06290bd2-48aa-11d2-8432-006008c3fbfc" => Some("scriptlet.typelib (script execution)"),
        // htmlfile — HTML Application
        "25336920-03f9-11cf-8fd0-00aa00686f13" => Some("htmlfile (HTML document)"),
        // MSCOMCTL.ListViewCtrl — CVE-2012-0158
        "996bf5e0-8044-4650-adeb-0b013914e99c" => Some("MSCOMCTL.ListViewCtrl (CVE-2012-0158)"),
        "bdd1f04b-858b-11d1-b16a-00c0f0283628" => Some("MSCOMCTL.ListViewCtrl.2 (CVE-2012-0158)"),
        // Shell.Explorer — embedded browser
        "8856f961-340a-11d0-a96b-00c04fd705a2" => Some("Shell.Explorer (embedded browser)"),
        // OLE2Link — external link object
        "00000300-0000-0000-c000-000000000046" => Some("StdOleLink (external link)"),
        _ => None,
    }
}

/// Extract metadata from SummaryInformation property set.
///
/// The OLE property set format (MS-OLEPS) uses fixed-offset records.
/// We parse just enough to extract the key metadata fields.
fn extract_metadata(comp: &mut cfb::CompoundFile<Cursor<&[u8]>>) -> DocumentMetadata {
    let mut meta = DocumentMetadata::default();

    // Try \x05SummaryInformation
    if let Ok(mut stream) = comp.open_stream("\x05SummaryInformation") {
        let mut data = Vec::new();
        if stream.read_to_end(&mut data).is_ok() {
            parse_summary_info(&data, &mut meta);
        }
    }

    meta
}

/// Parse OLE2 SummaryInformation property set (MS-OLEPS).
///
/// Structure:
/// - 28 byte header (byte_order, version, os_version, clsid, num_sections)
/// - Section header: fmtid (16 bytes) + offset (4 bytes) per section
/// - Section: size (4 bytes) + num_properties (4 bytes) + property entries
/// - Property entry: property_id (4 bytes) + offset (4 bytes)
fn parse_summary_info(data: &[u8], meta: &mut DocumentMetadata) {
    if data.len() < 48 {
        return;
    }

    // Check byte order mark
    let bom = u16::from_le_bytes([data[0], data[1]]);
    if bom != 0xFFFE {
        return;
    }

    // Get section offset (first section)
    let num_sections = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as usize;
    if num_sections == 0 {
        return;
    }

    // Section offset is at byte 44 (after header + fmtid)
    if data.len() < 48 {
        return;
    }
    let section_offset = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;

    if section_offset + 8 > data.len() {
        return;
    }

    let section = &data[section_offset..];
    if section.len() < 8 {
        return;
    }

    let num_props = u32::from_le_bytes([section[4], section[5], section[6], section[7]]) as usize;

    // Read property id/offset pairs
    for i in 0..num_props {
        let entry_offset = 8 + i * 8;
        if entry_offset + 8 > section.len() {
            break;
        }

        let prop_id = u32::from_le_bytes([
            section[entry_offset],
            section[entry_offset + 1],
            section[entry_offset + 2],
            section[entry_offset + 3],
        ]);
        let prop_offset = u32::from_le_bytes([
            section[entry_offset + 4],
            section[entry_offset + 5],
            section[entry_offset + 6],
            section[entry_offset + 7],
        ]) as usize;

        if prop_offset + 8 > section.len() {
            continue;
        }

        // Property IDs for SummaryInformation:
        // 2 = Title, 4 = Author, 6 = ApplicationName, 8 = LastAuthor
        // 12 = CreateTime, 13 = LastSaveTime
        match prop_id {
            2 => meta.title = read_property_string(section, prop_offset),
            4 => meta.author = read_property_string(section, prop_offset),
            6 => meta.application = read_property_string(section, prop_offset),
            8 => meta.last_author = read_property_string(section, prop_offset),
            _ => {}
        }
    }
}

/// Read a VT_LPSTR property value from the section.
fn read_property_string(section: &[u8], offset: usize) -> Option<String> {
    if offset + 8 > section.len() {
        return None;
    }

    let vt_type = u32::from_le_bytes([
        section[offset],
        section[offset + 1],
        section[offset + 2],
        section[offset + 3],
    ]);

    // VT_LPSTR = 0x001E
    if vt_type != 0x001E {
        return None;
    }

    let str_len = u32::from_le_bytes([
        section[offset + 4],
        section[offset + 5],
        section[offset + 6],
        section[offset + 7],
    ]) as usize;

    if str_len == 0 || offset + 8 + str_len > section.len() {
        return None;
    }

    let bytes = &section[offset + 8..offset + 8 + str_len];
    let s = String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .to_string();

    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ole2() {
        assert!(is_ole2(&OLE2_MAGIC));
        assert!(is_ole2(&[
            0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00
        ]));
        assert!(!is_ole2(&[0x00; 8]));
        assert!(!is_ole2(&[0xD0, 0xCF])); // too short
    }

    #[test]
    fn test_detect_subtype() {
        let word_streams = vec!["/WordDocument".to_string(), "/1Table".to_string()];
        assert_eq!(detect_subtype(&word_streams), Ole2Subtype::Word);

        let excel_streams = vec!["/Workbook".to_string()];
        assert_eq!(detect_subtype(&excel_streams), Ole2Subtype::Excel);

        let ppt_streams = vec!["/PowerPoint Document".to_string()];
        assert_eq!(detect_subtype(&ppt_streams), Ole2Subtype::PowerPoint);

        let unknown_streams = vec!["/SomeStream".to_string()];
        assert_eq!(detect_subtype(&unknown_streams), Ole2Subtype::Unknown);
    }

    #[test]
    fn test_ole2_subtype_str() {
        assert_eq!(Ole2Subtype::Word.as_str(), "doc");
        assert_eq!(Ole2Subtype::Excel.as_str(), "xls");
        assert_eq!(Ole2Subtype::PowerPoint.as_str(), "ppt");
        assert_eq!(Ole2Subtype::Msg.as_str(), "msg");
        assert_eq!(Ole2Subtype::Unknown.as_str(), "ole");
    }
}
