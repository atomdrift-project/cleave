//! OLE2/CFBF compound document parser for legacy Office formats.
//!
//! Handles .doc, .xls, .ppt, .msg and other legacy Microsoft Office documents
//! that use the Compound File Binary Format (CFBF/OLE2).

use super::vba;
use anyhow::Result;
use std::io::{Cursor, Read};

/// Maximum embedded executables extracted per OLE2 document.
/// Bounds work for adversarial inputs that pile many MZ-prefixed streams.
const MAX_EMBEDDED_EXECUTABLES: usize = 10;

/// Maximum embedded executable size to extract (50 MB).
/// Streams above this are reported as present but skipped for sub-analysis.
const MAX_EMBEDDED_EXECUTABLE_SIZE: u64 = 50 * 1024 * 1024;

/// Minimum credible PE/ELF size — anything smaller is a stub or a false MZ.
const MIN_EMBEDDED_EXECUTABLE_SIZE: u64 = 1024;

/// Kind of embedded executable detected by header sniffing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmbeddedExecKind {
    Pe,
    Elf,
}

/// Embedded executable extracted from an OLE2 stream.
#[derive(Debug, Clone)]
pub(crate) struct EmbeddedExecutable {
    pub stream_path: String,
    pub kind: EmbeddedExecKind,
    pub data: Vec<u8>,
}

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
    /// Streams containing embedded PE/ELF executables (with extracted bytes for sub-analysis)
    pub embedded_executables: Vec<EmbeddedExecutable>,
    /// OLE10Native embedded objects (filename, size)
    pub ole10_native_objects: Vec<Ole10NativeInfo>,
    /// Known dangerous CLSIDs found on storages
    pub dangerous_clsids: Vec<ClsidMatch>,
    /// Document metadata (author, title, etc.)
    pub metadata: DocumentMetadata,
    /// CompObj stream contents (None when stream missing or malformed).
    pub compobj: Option<CompObjData>,
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
    Msi,
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
            Self::Msi => "msi",
            Self::Unknown => "ole",
        }
    }
}

/// Document metadata extracted from SummaryInformation /
/// DocumentSummaryInformation property sets.
///
/// String fields come from `\x05SummaryInformation` per MS-OLEPS;
/// numeric fields cover both streams.  Keep all fields optional —
/// many real-world documents omit several properties.
#[derive(Debug, Default)]
#[allow(dead_code)] // Fields populated for metadata reporting
pub(crate) struct DocumentMetadata {
    pub title: Option<String>,
    pub author: Option<String>,
    pub last_author: Option<String>,
    pub application: Option<String>,
    pub create_time: Option<String>,
    pub last_save_time: Option<String>,
    /// PIDSI_PAGECOUNT (0x0E) — VT_I4.  Zero on freshly-built lures.
    pub page_count: Option<u32>,
    /// PIDSI_WORDCOUNT (0x0F) — VT_I4.  Low values on lures.
    pub word_count: Option<u32>,
    /// PIDSI_CHARCOUNT (0x10) — VT_I4.
    pub char_count: Option<u32>,
    /// PIDSI_REVNUMBER (0x09) — VT_LPSTR holding a decimal integer
    /// (Word writes "1" / "12" etc.); we parse the leading number.
    pub revision_number: Option<u32>,
    /// PIDSI_EDITTIME (0x0A) — VT_FILETIME stored as a duration in
    /// 100-ns units.  Surfaced as minutes for trait friendliness.
    pub total_edit_time_minutes: Option<u64>,
    /// PIDDSI_SECURITY (0x13) from DocumentSummaryInformation —
    /// bit 0 password-protected, bit 1 read-only-recommended,
    /// bit 2 read-only-enforced, bit 3 locked.
    pub security_flag: Option<u32>,
}

/// CompObj stream contents per MS-OLEDS §2.3.6.1.  Surfaces the three
/// ProgID/clipboard fields most useful for fake-extension detection
/// — a `.doc` whose CompObj says `Excel.Sheet.8` is a known
/// masquerade pattern (CVE-2017-0199 droppers, malicious DOCX renames).
#[derive(Debug, Default, Clone)]
#[allow(dead_code)] // Read by office analyzer to populate OleMetrics
pub(crate) struct CompObjData {
    /// AnsiUserType — human-readable type label
    /// (e.g., "Microsoft Office Excel Worksheet").
    pub user_type: String,
    /// AnsiClipboardFormat string variant (e.g., "Biff8"). Empty when
    /// the format is a registered clipboard ID rather than a string.
    pub clipboard_format: String,
    /// "Reserved3" string — the canonical ProgID Office writes here
    /// (e.g., "Excel.Sheet.8", "Word.Document.8", "PowerPoint.Show.8").
    pub app_version: String,
}

/// Parse an OLE2 compound document.
pub(crate) fn parse_ole2(data: &[u8]) -> Result<Ole2Document> {
    let cursor = Cursor::new(data);
    let mut comp = cfb::CompoundFile::open(cursor)?;

    // Enumerate all entries, collecting CLSIDs from storages.
    // `is_stream` is captured so embedded-executable scanning can skip storages
    // without round-tripping through `open_stream` errors.
    let mut entries: Vec<(String, u64, bool)> = Vec::new();
    let mut dangerous_clsids: Vec<ClsidMatch> = Vec::new();

    for entry in comp.walk() {
        let path = entry.path().to_string_lossy().to_string();
        let len = entry.len();
        let is_stream = entry.is_stream();

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

        entries.push((path, len, is_stream));
    }

    let stream_names: Vec<String> = entries.iter().map(|(name, _, _)| name.clone()).collect();

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

    // CompObj stream parsing — best-effort; missing or malformed
    // streams produce None and the doc is otherwise unaffected.
    let compobj = extract_compobj(&mut comp);

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
        compobj,
    })
}

/// Read and parse the `\x01CompObj` stream if present.
fn extract_compobj(comp: &mut cfb::CompoundFile<Cursor<&[u8]>>) -> Option<CompObjData> {
    let mut data = Vec::new();
    {
        let mut stream = comp.open_stream("\x01CompObj").ok()?;
        if stream.read_to_end(&mut data).is_err() {
            return None;
        }
    }
    parse_compobj(&data)
}

/// Parse the CompObj stream layout (MS-OLEDS §2.3.6.1).
///
/// The stream begins with a 28-byte fixed header (Reserved1 4 + Version
/// 4 + Reserved2 20) followed by:
///   - AnsiUserType: LengthPrefixedAnsiString
///   - AnsiClipboardFormat: ClipboardFormatOrAnsiString
///   - Reserved3:  optional LengthPrefixedAnsiString (the ProgID)
///
/// LengthPrefixedAnsiString = u32 LE length (incl. trailing NUL) +
/// `length` bytes. A length of 0 means absent. ClipboardFormat encodes
/// either a 32-bit clipboard ID (1..=0x1FF, no string) or a marker
/// `0xFFFFFFFE`/`0xFFFFFFFF` followed by a length-prefixed string. We
/// surface only the *string* variant — the registered-ID case isn't
/// useful for masquerade detection.
fn parse_compobj(data: &[u8]) -> Option<CompObjData> {
    const HEADER_SIZE: usize = 28;
    if data.len() < HEADER_SIZE + 4 {
        return None;
    }
    let mut pos = HEADER_SIZE;
    let mut out = CompObjData::default();

    // 1) AnsiUserType
    if let Some((s, advance)) = read_length_prefixed_ansi(&data[pos..]) {
        out.user_type = s;
        pos += advance;
    } else {
        return Some(out);
    }

    // 2) AnsiClipboardFormat — MS-OLEDS encodes this as either a 4-byte
    //    registered clipboard ID or a length-prefixed ANSI string. The
    //    naive "small value = ID, large value = length" heuristic fails
    //    for short formats like `"Biff8\0"` (length 6, looks like an
    //    ID).  We prefer the string interpretation: if the declared
    //    length fits in the remaining buffer AND the bytes look like
    //    printable ASCII, accept as a string. Otherwise fall back to
    //    "registered ID, advance 4".
    if data.len() < pos + 4 {
        return Some(out);
    }
    let marker = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
    if marker == 0 {
        pos += 4;
    } else {
        let len = marker as usize;
        let str_start = pos + 4;
        let fits = data.len() >= str_start + len && len > 0 && len <= 256;
        let printable = fits
            && data[str_start..str_start + len]
                .iter()
                .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == 0);
        if fits && printable {
            out.clipboard_format = sanitize_ansi(&data[str_start..str_start + len]);
            pos = str_start + len;
        } else {
            // Registered clipboard ID — no string follows.
            pos += 4;
        }
    }

    // 3) Reserved3 — optional LengthPrefixedAnsiString carrying ProgID.
    if let Some((s, _advance)) = read_length_prefixed_ansi(&data[pos..]) {
        out.app_version = s;
    }

    Some(out)
}

/// Read a `LengthPrefixedAnsiString` from the start of `buf`. Returns
/// the decoded string (with trailing NUL stripped) and the number of
/// bytes consumed. Returns `None` when the buffer is too short or the
/// length field exceeds remaining bytes.
fn read_length_prefixed_ansi(buf: &[u8]) -> Option<(String, usize)> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len == 0 {
        return Some((String::new(), 4));
    }
    if buf.len() < 4 + len {
        return None;
    }
    Some((sanitize_ansi(&buf[4..4 + len]), 4 + len))
}

fn sanitize_ansi(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .to_string()
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
        // MSI installers: _Tables stream or Binary. streams with MSI structure
        if lower.contains("_tables") || lower.contains("/binary.") {
            return Ole2Subtype::Msi;
        }
        // MSI installers also encode their table/stream names into the Unicode
        // PUA-ish range U+3800..U+4900. A stream whose payload-name (everything
        // after the leading "/" and excluding the SummaryInformation control
        // stream) is composed entirely of codepoints in that range is an MSI
        // table/storage entry — see the MSI streamname encoding in [MS-MSI].
        let payload = name.trim_start_matches('/').trim_start_matches('\u{0005}');
        if !payload.is_empty()
            && payload
                .chars()
                .all(|c| ('\u{3800}'..'\u{4900}').contains(&c))
        {
            return Ole2Subtype::Msi;
        }
    }
    Ole2Subtype::Unknown
}

/// Scan streams for embedded PE/ELF executables.
///
/// Sniffs the first 8 bytes of every stream (no name filter) so MSI binary
/// streams (`Binary.<name>`), ad-hoc storage attachments, and obfuscated
/// container streams are all caught. The full stream payload is read into
/// memory for matching streams so the caller can route the bytes through the
/// PE/ELF analyzer pipeline.
///
/// Bounds: skips streams below [`MIN_EMBEDDED_EXECUTABLE_SIZE`] (no real
/// payload fits) or above [`MAX_EMBEDDED_EXECUTABLE_SIZE`] (avoid OOM on
/// adversarial inputs); caps the result count at
/// [`MAX_EMBEDDED_EXECUTABLES`].
fn find_embedded_executables(
    comp: &mut cfb::CompoundFile<Cursor<&[u8]>>,
    entries: &[(String, u64, bool)],
) -> Vec<EmbeddedExecutable> {
    let mut found = Vec::new();

    for (path, size, is_stream) in entries {
        if found.len() >= MAX_EMBEDDED_EXECUTABLES {
            break;
        }
        if !*is_stream
            || *size < MIN_EMBEDDED_EXECUTABLE_SIZE
            || *size > MAX_EMBEDDED_EXECUTABLE_SIZE
        {
            continue;
        }

        let Ok(mut stream) = comp.open_stream(path) else {
            continue;
        };
        let mut header = [0u8; 8];
        if stream.read_exact(&mut header).is_err() {
            continue;
        }
        let kind = if header[0] == b'M' && header[1] == b'Z' {
            EmbeddedExecKind::Pe
        } else if header[..4] == [0x7f, b'E', b'L', b'F'] {
            EmbeddedExecKind::Elf
        } else {
            continue;
        };

        // Slurp the full stream. cfb's stream reader is in-memory backed by
        // the host slice, so this is a single contiguous copy.
        let mut data = Vec::with_capacity(*size as usize);
        data.extend_from_slice(&header);
        if stream.read_to_end(&mut data).is_err() {
            continue;
        }

        found.push(EmbeddedExecutable {
            stream_path: path.clone(),
            kind,
            data,
        });
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
    entries: &[(String, u64, bool)],
) -> Vec<Ole10NativeInfo> {
    let mut found = Vec::new();

    for (path, size, _is_stream) in entries {
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
                    let total_size =
                        u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
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

/// Extract metadata from SummaryInformation and
/// DocumentSummaryInformation property sets.
///
/// The OLE property set format (MS-OLEPS) uses fixed-offset records.
/// Both streams share the same outer structure; only the property IDs
/// they filefacts differ.
fn extract_metadata(comp: &mut cfb::CompoundFile<Cursor<&[u8]>>) -> DocumentMetadata {
    let mut meta = DocumentMetadata::default();

    // \x05SummaryInformation — title/author/page count/edit time/etc.
    if let Ok(mut stream) = comp.open_stream("\x05SummaryInformation") {
        let mut data = Vec::new();
        if stream.read_to_end(&mut data).is_ok() {
            parse_summary_info(&data, &mut meta);
        }
    }
    // \x05DocumentSummaryInformation — security flag and custom props.
    if let Ok(mut stream) = comp.open_stream("\x05DocumentSummaryInformation") {
        let mut data = Vec::new();
        if stream.read_to_end(&mut data).is_ok() {
            parse_doc_summary_info(&data, &mut meta);
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

        // Property IDs for SummaryInformation (PIDSI_*):
        // 0x02 Title, 0x04 Author, 0x06 ApplicationName, 0x08 LastAuthor,
        // 0x09 RevNumber, 0x0A EditTime, 0x0E PageCount, 0x0F WordCount,
        // 0x10 CharCount, 0x0C CreateTime, 0x0D LastSaveTime
        match prop_id {
            0x02 => meta.title = read_property_string(section, prop_offset),
            0x04 => meta.author = read_property_string(section, prop_offset),
            0x06 => meta.application = read_property_string(section, prop_offset),
            0x08 => meta.last_author = read_property_string(section, prop_offset),
            0x09 => {
                if let Some(s) = read_property_string(section, prop_offset) {
                    meta.revision_number = parse_leading_u32(&s);
                }
            }
            0x0A => meta.total_edit_time_minutes = read_filetime_minutes(section, prop_offset),
            0x0E => meta.page_count = read_property_u32(section, prop_offset),
            0x0F => meta.word_count = read_property_u32(section, prop_offset),
            0x10 => meta.char_count = read_property_u32(section, prop_offset),
            _ => {}
        }
    }
}

/// Parse DocumentSummaryInformation. Currently captures `PIDDSI_SECURITY`
/// (property 0x13) only; future expansion can pick up custom properties
/// here without touching SummaryInformation parsing.
fn parse_doc_summary_info(data: &[u8], meta: &mut DocumentMetadata) {
    let Some(section) = locate_first_section(data) else {
        return;
    };
    if section.len() < 8 {
        return;
    }
    let num_props = u32::from_le_bytes([section[4], section[5], section[6], section[7]]) as usize;

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

        if prop_id == 0x13 {
            meta.security_flag = read_property_u32(section, prop_offset);
        }
    }
}

/// Walk the MS-OLEPS outer structure and return a slice into the first
/// property-set section (the `size + num_properties + entries` block).
fn locate_first_section(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 48 {
        return None;
    }
    let bom = u16::from_le_bytes([data[0], data[1]]);
    if bom != 0xFFFE {
        return None;
    }
    let num_sections = u32::from_le_bytes([data[24], data[25], data[26], data[27]]) as usize;
    if num_sections == 0 {
        return None;
    }
    let section_offset = u32::from_le_bytes([data[44], data[45], data[46], data[47]]) as usize;
    if section_offset + 8 > data.len() {
        return None;
    }
    Some(&data[section_offset..])
}

/// Read a VT_I4 (0x0003) property value as u32.  Negative values are
/// clamped to zero — the four numeric SummaryInformation properties
/// we care about are intrinsically non-negative.
fn read_property_u32(section: &[u8], offset: usize) -> Option<u32> {
    if offset + 8 > section.len() {
        return None;
    }
    let vt_type = u32::from_le_bytes([
        section[offset],
        section[offset + 1],
        section[offset + 2],
        section[offset + 3],
    ]);
    if vt_type != 0x0003 {
        return None;
    }
    let value = i32::from_le_bytes([
        section[offset + 4],
        section[offset + 5],
        section[offset + 6],
        section[offset + 7],
    ]);
    Some(value.max(0) as u32)
}

/// Read a VT_FILETIME (0x0040) property value and return the duration
/// in *minutes*.  PIDSI_EDITTIME stores the total time the document
/// has been edited, packaged as a FILETIME-style duration in 100-ns
/// units.  Real edit times are tiny relative to absolute FILETIMEs,
/// so a literal-FILETIME-as-timestamp interpretation overflows; we
/// always treat the value as a duration here.
fn read_filetime_minutes(section: &[u8], offset: usize) -> Option<u64> {
    if offset + 12 > section.len() {
        return None;
    }
    let vt_type = u32::from_le_bytes([
        section[offset],
        section[offset + 1],
        section[offset + 2],
        section[offset + 3],
    ]);
    if vt_type != 0x0040 {
        return None;
    }
    let raw = u64::from_le_bytes([
        section[offset + 4],
        section[offset + 5],
        section[offset + 6],
        section[offset + 7],
        section[offset + 8],
        section[offset + 9],
        section[offset + 10],
        section[offset + 11],
    ]);
    // 100-ns units → minutes: divide by 600_000_000.
    Some(raw / 600_000_000)
}

/// Parse the leading run of decimal digits as a u32 (ignoring trailing
/// junk like "12.0" → 12). Used for `PIDSI_REVNUMBER` which Word stores
/// as a string.
fn parse_leading_u32(s: &str) -> Option<u32> {
    let digits: String = s.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
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

    if s.is_empty() { None } else { Some(s) }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Helper: build a CompObj stream payload with the given strings.
    /// `clipboard_marker` controls whether the clipboard slot is a
    /// registered ID, absent, or a length-prefixed string.
    #[derive(Clone, Copy)]
    enum ClipboardSlot {
        RegisteredId(u32),
        AnsiString(&'static str),
    }

    fn build_compobj(
        user_type: &str,
        clipboard: ClipboardSlot,
        app_version: Option<&str>,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0u8; 28]); // header (Reserved1 + Version + Reserved2)

        // AnsiUserType
        let ut_len = (user_type.len() + 1) as u32;
        buf.extend_from_slice(&ut_len.to_le_bytes());
        buf.extend_from_slice(user_type.as_bytes());
        buf.push(0);

        // AnsiClipboardFormat
        match clipboard {
            ClipboardSlot::RegisteredId(id) => {
                buf.extend_from_slice(&id.to_le_bytes());
            }
            ClipboardSlot::AnsiString(s) => {
                let len = (s.len() + 1) as u32;
                buf.extend_from_slice(&len.to_le_bytes());
                buf.extend_from_slice(s.as_bytes());
                buf.push(0);
            }
        }

        // Reserved3 (ProgID)
        if let Some(av) = app_version {
            let len = (av.len() + 1) as u32;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(av.as_bytes());
            buf.push(0);
        }

        buf
    }

    /// Excel CompObj layout — string clipboard slot + ProgID.
    #[test]
    fn parse_compobj_excel_typical() {
        let payload = build_compobj(
            "Microsoft Office Excel Worksheet",
            ClipboardSlot::AnsiString("Biff8"),
            Some("Excel.Sheet.8"),
        );
        let parsed = parse_compobj(&payload).expect("parses");
        assert_eq!(parsed.user_type, "Microsoft Office Excel Worksheet");
        assert_eq!(parsed.clipboard_format, "Biff8");
        assert_eq!(parsed.app_version, "Excel.Sheet.8");
    }

    /// Word with a registered clipboard ID — clipboard_format stays empty
    /// (no string variant), but user_type and ProgID still parse.
    #[test]
    fn parse_compobj_registered_clipboard_id() {
        let payload = build_compobj(
            "Microsoft Word Document",
            ClipboardSlot::RegisteredId(0x31),
            Some("Word.Document.8"),
        );
        let parsed = parse_compobj(&payload).expect("parses");
        assert_eq!(parsed.user_type, "Microsoft Word Document");
        assert_eq!(parsed.clipboard_format, "");
        assert_eq!(parsed.app_version, "Word.Document.8");
    }

    /// Adversarial CompObj that lies about user_type length — parser
    /// must refuse the user_type read (returns Some with empty fields)
    /// rather than panic on the slice.
    #[test]
    fn parse_compobj_oversized_user_type_does_not_panic() {
        let mut payload = vec![0u8; 28];
        payload.extend_from_slice(&100u32.to_le_bytes());
        payload.extend_from_slice(b"\x00\x00\x00\x00");
        let parsed = parse_compobj(&payload).expect("returns parsed default");
        assert_eq!(parsed.user_type, "");
    }

    /// Empty user_type slot still parses (length 0 means absent).
    #[test]
    fn parse_compobj_empty_user_type() {
        let mut payload = vec![0u8; 28];
        payload.extend_from_slice(&0u32.to_le_bytes()); // user_type len = 0
        payload.extend_from_slice(&0u32.to_le_bytes()); // clipboard marker = 0
        let parsed = parse_compobj(&payload).expect("parses");
        assert_eq!(parsed.user_type, "");
        assert_eq!(parsed.clipboard_format, "");
        assert_eq!(parsed.app_version, "");
    }

    /// Build a minimal MS-OLEPS property-set stream containing one
    /// section with the given (property_id, payload) entries. Every
    /// payload byte slice must be a fully formed VT_* value (type
    /// dword + value bytes). Returns the assembled stream.
    fn build_property_set_stream(entries: &[(u32, &[u8])]) -> Vec<u8> {
        // Outer header (28 bytes): BOM + version + osversion + clsid + num_sections=1
        let mut out = Vec::new();
        out.extend_from_slice(&0xFFFEu16.to_le_bytes()); // BOM
        out.extend_from_slice(&0u16.to_le_bytes()); // version
        out.extend_from_slice(&0u32.to_le_bytes()); // osversion
        out.extend_from_slice(&[0u8; 16]); // clsid
        out.extend_from_slice(&1u32.to_le_bytes()); // num_sections

        // SectionHeader: fmtid (16 bytes) + offset (4 bytes)
        out.extend_from_slice(&[0u8; 16]); // fmtid
        let section_offset_pos = out.len();
        out.extend_from_slice(&0u32.to_le_bytes()); // placeholder offset

        // Pad to ensure section_offset >= 48 (matches the parser's bound).
        while out.len() < 48 {
            out.push(0);
        }
        let section_start = out.len();
        // Patch section_offset.
        let off = (section_start as u32).to_le_bytes();
        out[section_offset_pos..section_offset_pos + 4].copy_from_slice(&off);

        // Section: size (4) + num_props (4), then num_props (id + offset)
        // entries, then payloads.
        let num_props = entries.len() as u32;
        // Section size patched after we know the final size.
        let section_size_pos = out.len();
        out.extend_from_slice(&0u32.to_le_bytes()); // placeholder
        out.extend_from_slice(&num_props.to_le_bytes());

        // Compute payload offsets relative to the section start.
        let table_size = entries.len() * 8; // 4 id + 4 offset per entry
        let mut payload_offset = 8 + table_size; // section header (8) + table

        // Emit id+offset entries first.
        let mut payload_offsets = Vec::with_capacity(entries.len());
        for (id, payload) in entries {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&(payload_offset as u32).to_le_bytes());
            payload_offsets.push(payload_offset);
            payload_offset += payload.len();
        }
        // Emit payloads in order.
        for (_, payload) in entries {
            out.extend_from_slice(payload);
        }
        // Patch section_size.
        let section_size = (out.len() - section_start) as u32;
        out[section_size_pos..section_size_pos + 4].copy_from_slice(&section_size.to_le_bytes());
        let _ = payload_offsets; // for debugging
        out
    }

    fn vt_i4(v: i32) -> [u8; 8] {
        let mut b = [0u8; 8];
        b[..4].copy_from_slice(&0x0003u32.to_le_bytes());
        b[4..].copy_from_slice(&v.to_le_bytes());
        b
    }

    fn vt_filetime(units_100ns: u64) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[..4].copy_from_slice(&0x0040u32.to_le_bytes());
        b[4..].copy_from_slice(&units_100ns.to_le_bytes());
        b
    }

    fn vt_lpstr(s: &str) -> Vec<u8> {
        let mut b = Vec::with_capacity(8 + s.len() + 1);
        b.extend_from_slice(&0x001Eu32.to_le_bytes());
        let len = (s.len() + 1) as u32;
        b.extend_from_slice(&len.to_le_bytes());
        b.extend_from_slice(s.as_bytes());
        b.push(0);
        b
    }

    #[test]
    fn parse_summary_info_captures_numeric_properties() {
        let page = vt_i4(7);
        let word = vt_i4(123);
        let char_ = vt_i4(800);
        let rev = vt_lpstr("12");
        // 30 minutes = 30 * 60 * 10_000_000 = 18_000_000_000
        let edit = vt_filetime(18_000_000_000);
        let stream = build_property_set_stream(&[
            (0x0E, &page),
            (0x0F, &word),
            (0x10, &char_),
            (0x09, &rev),
            (0x0A, &edit),
        ]);
        let mut meta = DocumentMetadata::default();
        parse_summary_info(&stream, &mut meta);
        assert_eq!(meta.page_count, Some(7));
        assert_eq!(meta.word_count, Some(123));
        assert_eq!(meta.char_count, Some(800));
        assert_eq!(meta.revision_number, Some(12));
        assert_eq!(meta.total_edit_time_minutes, Some(30));
    }

    #[test]
    fn parse_doc_summary_info_captures_security_flag() {
        // Security flag = 2 (recommend read-only).
        let security = vt_i4(2);
        let stream = build_property_set_stream(&[(0x13, &security)]);
        let mut meta = DocumentMetadata::default();
        parse_doc_summary_info(&stream, &mut meta);
        assert_eq!(meta.security_flag, Some(2));
    }

    #[test]
    fn read_property_u32_rejects_wrong_vt_type() {
        // Build VT_LPSTR where VT_I4 is expected.
        let mut buf = vec![0u8; 0];
        buf.extend_from_slice(&0x001Eu32.to_le_bytes()); // wrong type
        buf.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(read_property_u32(&buf, 0), None);
    }

    #[test]
    fn read_filetime_minutes_zero_for_zero_units() {
        let mut buf = vec![0u8; 0];
        buf.extend_from_slice(&0x0040u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(read_filetime_minutes(&buf, 0), Some(0));
    }

    #[test]
    fn parse_leading_u32_handles_mixed_input() {
        assert_eq!(parse_leading_u32("12"), Some(12));
        assert_eq!(parse_leading_u32("12.0"), Some(12));
        assert_eq!(parse_leading_u32("abc"), None);
        assert_eq!(parse_leading_u32(""), None);
    }

    /// LengthPrefixedAnsiString with NUL preserved correctly: trailing
    /// NUL stripped, embedded NULs kept.
    #[test]
    fn read_length_prefixed_ansi_strips_trailing_nul_only() {
        // "ABC\0" = 4 bytes
        let raw = b"\x04\x00\x00\x00ABC\0";
        let (s, advance) = read_length_prefixed_ansi(raw).expect("reads");
        assert_eq!(s, "ABC");
        assert_eq!(advance, 8);
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

        let msi_streams = vec!["/Binary.123".to_string(), "/_Tables".to_string()];
        assert_eq!(detect_subtype(&msi_streams), Ole2Subtype::Msi);
    }

    #[test]
    fn test_ole2_subtype_str() {
        assert_eq!(Ole2Subtype::Word.as_str(), "doc");
        assert_eq!(Ole2Subtype::Excel.as_str(), "xls");
        assert_eq!(Ole2Subtype::PowerPoint.as_str(), "ppt");
        assert_eq!(Ole2Subtype::Msg.as_str(), "msg");
        assert_eq!(Ole2Subtype::Msi.as_str(), "msi");
        assert_eq!(Ole2Subtype::Unknown.as_str(), "ole");
    }
}
