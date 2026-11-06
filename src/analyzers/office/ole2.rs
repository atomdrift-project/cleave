//! OLE2/CFBF compound document parser for legacy Office formats.
//!
//! Handles .doc, .xls, .ppt, .msg and other legacy Microsoft Office documents
//! that use the Compound File Binary Format (CFBF/OLE2).

// Parses attacker-controlled bytes: index and offset arithmetic must be
// checked, so a forged header is a parse error rather than a panic.
#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use anyhow::Result;
use std::io::{Cursor, Read};

/// Maximum executable or cabinet streams extracted per OLE2 document.
const MAX_EMBEDDED_EXECUTABLES: usize = 32;

/// Maximum embedded executable size to extract (50 MB).
/// Streams above this are reported as present but skipped for sub-analysis.
const MAX_EMBEDDED_EXECUTABLE_SIZE: u64 = 50 * 1024 * 1024;

/// Minimum credible PE/ELF size — anything smaller is a stub or a false MZ.
const MIN_EMBEDDED_EXECUTABLE_SIZE: u64 = 1024;

/// Maximum attachments extracted per Outlook message.
const MAX_MSG_ATTACHMENTS: usize = 32;

/// Maximum attachment payload extracted for sub-analysis — the same ceiling
/// as embedded executables. Larger attachments stay listed in the filefacts
/// `office.msg.attachments` values but are not analyzed.
const MAX_MSG_ATTACHMENT_SIZE: u64 = MAX_EMBEDDED_EXECUTABLE_SIZE;

/// Maximum entries copied when rebuilding an attached message / OLE object
/// storage into a standalone compound file.
const MAX_REBUILT_STORAGE_ENTRIES: usize = 4096;

/// Longest attachment filename kept for a member path, in characters.
const MAX_ATTACHMENT_NAME_CHARS: usize = 255;

/// Storage-name prefix of an Outlook attachment object (MS-OXMSG §2.2.2).
const MSG_ATTACH_STORAGE_PREFIX: &str = "__attach_version1.0_#";

/// Kind of embedded executable detected by header sniffing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmbeddedExecKind {
    Pe,
    Elf,
    Cab,
    PowerShell,
    Vbs,
    Python,
    JavaScript,
}

/// Embedded executable extracted from an OLE2 stream.
#[derive(Debug, Clone)]
pub(crate) struct EmbeddedExecutable {
    pub stream_path: String,
    pub kind: EmbeddedExecKind,
    pub data: Vec<u8>,
}

/// How an Outlook attachment's payload is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MsgAttachmentKind {
    /// `PidTagAttachDataBinary` stream: the attached file's bytes as-is.
    File,
    /// `PidTagAttachDataObject` storage — an attached message or OLE
    /// object — rebuilt into a standalone compound file.
    Storage,
}

/// An Outlook `.msg` attachment extracted for sub-analysis.
#[derive(Debug, Clone)]
pub(crate) struct MsgAttachment {
    /// Attachment storage path (`/__attach_version1.0_#00000000`).
    pub storage_path: String,
    /// Path of the stream or storage the payload was read from.
    pub payload_path: String,
    /// Filename safe to use as a member path component (see
    /// [`sanitize_attachment_filename`]).
    pub filename: String,
    pub kind: MsgAttachmentKind,
    pub data: Vec<u8>,
}

/// Parsed OLE2 compound document.
#[derive(Debug)]
pub(crate) struct Ole2Document {
    /// Document subtype detected from streams
    pub doc_subtype: Ole2Subtype,
    /// Whether VBA macros were found
    pub has_vba: bool,
    /// Whether the document is encrypted
    pub has_encryption: bool,
    /// Stream names found in the document
    pub stream_names: Vec<String>,
    /// Streams containing embedded PE/ELF executables (with extracted bytes for sub-analysis)
    pub embedded_executables: Vec<EmbeddedExecutable>,
    /// OLE10Native embedded objects (filename, size)
    pub ole10_native_objects: Vec<Ole10NativeInfo>,
    /// Outlook message attachments (empty unless `doc_subtype` is `Msg`).
    /// An attachment whose data stream is already in `embedded_executables`
    /// is left out so it is analyzed once.
    pub msg_attachments: Vec<MsgAttachment>,
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
pub(crate) struct DocumentMetadata {
    pub title: Option<String>,
    pub author: Option<String>,
    pub last_author: Option<String>,
    pub application: Option<String>,
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

    // VBA module source is decompressed by filefacts and read back via
    // `vba::modules_from_ctx`; the parser only records macro presence.

    // Check for encryption
    let has_encryption = stream_names
        .iter()
        .any(|s| s.contains("EncryptionInfo") || s.contains("EncryptedPackage"));

    // Check for embedded executables
    let embedded_executables = find_embedded_executables(&mut comp, &entries);

    // Check for OLE10Native embedded objects
    let ole10_native_objects = find_ole10_native(&mut comp, &entries);

    let msg_attachments = if doc_subtype == Ole2Subtype::Msg {
        let already_extracted: Vec<&str> = embedded_executables
            .iter()
            .map(|e| e.stream_path.as_str())
            .collect();
        find_msg_attachments(&mut comp, &entries, &already_extracted)
    } else {
        Vec::new()
    };

    // Extract metadata
    let metadata = extract_metadata(&mut comp);

    // CompObj stream parsing — best-effort; missing or malformed
    // streams produce None and the doc is otherwise unaffected.
    let compobj = extract_compobj(&mut comp);

    Ok(Ole2Document {
        doc_subtype,
        has_vba,
        has_encryption,
        stream_names,
        embedded_executables,
        ole10_native_objects,
        msg_attachments,
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
    if let Some((s, advance)) = data.get(pos..).and_then(read_length_prefixed_ansi) {
        out.user_type = s;
        pos = pos.checked_add(advance)?;
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
    let Some(marker) = le_u32(data, pos) else {
        return Some(out);
    };
    let str_start = pos.saturating_add(4);
    if marker == 0 {
        pos = str_start;
    } else {
        let len = marker as usize;
        let format = data
            .get(str_start..str_start.saturating_add(len))
            .filter(|field| {
                (1..=256).contains(&len)
                    && field
                        .iter()
                        .all(|b| b.is_ascii_graphic() || *b == b' ' || *b == 0)
            });
        if let Some(format) = format {
            out.clipboard_format = sanitize_ansi(format);
            pos = str_start.saturating_add(len);
        } else {
            // Registered clipboard ID — no string follows.
            pos = str_start;
        }
    }

    // 3) Reserved3 — optional LengthPrefixedAnsiString carrying ProgID.
    if let Some((s, _advance)) = data.get(pos..).and_then(read_length_prefixed_ansi) {
        out.app_version = s;
    }

    Some(out)
}

/// Read a `LengthPrefixedAnsiString` from the start of `buf`. Returns
/// the decoded string (with trailing NUL stripped) and the number of
/// bytes consumed. Returns `None` when the buffer is too short or the
/// length field exceeds remaining bytes.
fn read_length_prefixed_ansi(buf: &[u8]) -> Option<(String, usize)> {
    let len = le_u32(buf, 0)? as usize;
    if len == 0 {
        return Some((String::new(), 4));
    }
    let end = len.checked_add(4)?;
    Some((sanitize_ansi(buf.get(4..end)?), end))
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

/// Scan streams for executable binaries, cabinets, and MSI Binary scripts.
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
        let binary_kind = if header[0] == b'M' && header[1] == b'Z' {
            Some(EmbeddedExecKind::Pe)
        } else if header[..4] == [0x7f, b'E', b'L', b'F'] {
            Some(EmbeddedExecKind::Elf)
        } else if header[..4] == *b"MSCF" {
            Some(EmbeddedExecKind::Cab)
        } else {
            None
        };

        // MSI stores Binary-table stream names in a compact Unicode alphabet.
        // Only those streams are eligible for source detection: database tables
        // and ordinary Office text streams are not executable script members.
        let stream_path = decode_msi_stream_name(path);
        if binary_kind.is_none() && !stream_path.trim_start_matches('/').starts_with("Binary.") {
            continue;
        }

        // Slurp the full stream. cfb's stream reader is in-memory backed by
        // the host slice, so this is a single contiguous copy.
        let mut data = Vec::with_capacity(*size as usize);
        data.extend_from_slice(&header);
        if stream.read_to_end(&mut data).is_err() {
            continue;
        }

        let Some(kind) = binary_kind.or_else(|| embedded_script_kind(&stream_path, &data)) else {
            continue;
        };

        found.push(EmbeddedExecutable {
            stream_path,
            kind,
            data,
        });
    }

    found
}

fn decode_msi_stream_name(path: &str) -> String {
    const ALPHABET: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";
    let mut decoded = String::new();
    for c in path.chars() {
        let n = u32::from(c);
        if let Some(pair) = n.checked_sub(0x3800).filter(|&pair| pair < 0x1000) {
            if let (Some(&first), Some(&second)) = (
                ALPHABET.get((pair & 63) as usize),
                ALPHABET.get((pair >> 6) as usize),
            ) {
                decoded.push(char::from(first));
                decoded.push(char::from(second));
            }
        } else if let Some(index) = n.checked_sub(0x4800).filter(|&index| index < 64) {
            if let Some(&byte) = ALPHABET.get(index as usize) {
                decoded.push(char::from(byte));
            }
        } else {
            decoded.push(c);
        }
    }
    decoded
}

fn embedded_script_kind(path: &str, data: &[u8]) -> Option<EmbeddedExecKind> {
    use filefacts::FileType;
    let text = std::str::from_utf8(data).ok()?;
    // Long encoded data tables can precede the actual script. Use the complete
    // stream for language identification, as archive members do.
    let lower = text.to_ascii_lowercase();
    if lower.contains("[powershell]::create") && lower.contains(".addscript(") {
        return Some(EmbeddedExecKind::PowerShell);
    }
    if lower.contains("end function")
        && (lower.contains("createobject(")
            || (lower.contains("split(") && lower.contains("\nexecute ")))
    {
        return Some(EmbeddedExecKind::Vbs);
    }
    match filefacts::FileId::from_path_and_bytes(std::path::Path::new(path), data).file_type() {
        FileType::PowerShell => Some(EmbeddedExecKind::PowerShell),
        FileType::Vbs => Some(EmbeddedExecKind::Vbs),
        FileType::Python => Some(EmbeddedExecKind::Python),
        FileType::JavaScript => Some(EmbeddedExecKind::JavaScript),
        _ => None,
    }
}

/// Extract the attachments of an Outlook `.msg` (MS-OXMSG).
///
/// Each top-level `__attach_version1.0_#XXXXXXXX` storage holds one
/// attachment. A file attachment's bytes are the `PidTagAttachDataBinary`
/// stream (`__substg1.0_37010102`); an attached message or OLE object is a
/// `PidTagAttachDataObject` storage (`__substg1.0_3701000D`), which is
/// rebuilt into a standalone compound file so the office analyzer can
/// recurse into it (recursion depth is bounded by the caller). Attachments
/// of an attached message live under that storage and are reached through
/// that recursion, not here.
///
/// `already_extracted` lists payload streams the PE/ELF pass took, so an
/// executable attachment is analyzed once. Bounds: at most
/// [`MAX_MSG_ATTACHMENTS`] attachments of at most
/// [`MAX_MSG_ATTACHMENT_SIZE`] bytes each.
fn find_msg_attachments(
    comp: &mut cfb::CompoundFile<Cursor<&[u8]>>,
    entries: &[(String, u64, bool)],
    already_extracted: &[&str],
) -> Vec<MsgAttachment> {
    let storages: Vec<&str> = entries
        .iter()
        .filter(|(path, _, is_stream)| {
            !*is_stream
                && path.strip_prefix('/').is_some_and(|name| {
                    name.starts_with(MSG_ATTACH_STORAGE_PREFIX) && !name.contains('/')
                })
        })
        .map(|(path, _, _)| path.as_str())
        .collect();

    let mut found: Vec<MsgAttachment> = Vec::new();
    for storage in storages {
        if found.len() >= MAX_MSG_ATTACHMENTS {
            break;
        }
        let binary_path = format!("{storage}/__substg1.0_37010102");
        let object_path = format!("{storage}/__substg1.0_3701000D");
        let (kind, payload_path, data) = if comp.is_stream(&binary_path) {
            if already_extracted.contains(&binary_path.as_str()) {
                continue;
            }
            let Some(data) = read_bounded_stream(comp, &binary_path, MAX_MSG_ATTACHMENT_SIZE)
            else {
                continue;
            };
            (MsgAttachmentKind::File, binary_path, data)
        } else if comp.is_storage(&object_path) {
            let Some(data) = rebuild_storage(comp, &object_path, MAX_MSG_ATTACHMENT_SIZE) else {
                continue;
            };
            (MsgAttachmentKind::Storage, object_path, data)
        } else {
            // By-reference attachments carry a path, not bytes.
            continue;
        };
        if data.is_empty() {
            continue;
        }

        let index = storage
            .rsplit('#')
            .next()
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            .unwrap_or(found.len() as u32);
        let raw_name = ["3707", "3704", "3001"]
            .iter()
            .find_map(|id| read_msg_string(comp, storage, id));
        let mut filename = sanitize_attachment_filename(raw_name.as_deref(), index);
        if kind == MsgAttachmentKind::Storage
            && std::path::Path::new(&filename).extension().is_none()
        {
            // An attached message is usually named by its subject only.
            filename.push_str(if data_is_msg(&data) { ".msg" } else { ".ole" });
        }
        if found.iter().any(|a| a.filename == filename) {
            filename = format!("attachment-{index}-{filename}");
        }

        found.push(MsgAttachment {
            storage_path: storage.to_string(),
            payload_path,
            filename,
            kind,
            data,
        });
    }
    found
}

/// Read a whole stream, refusing one longer than `max` bytes.
fn read_bounded_stream(
    comp: &mut cfb::CompoundFile<Cursor<&[u8]>>,
    path: &str,
    max: u64,
) -> Option<Vec<u8>> {
    let stream = comp.open_stream(path).ok()?;
    if stream.len() > max {
        return None;
    }
    let mut data = Vec::with_capacity(stream.len() as usize);
    stream.take(max).read_to_end(&mut data).ok()?;
    Some(data)
}

/// True when a rebuilt attachment storage is itself a message rather than
/// an OLE object: it carries `__substg1.0_` property streams.
fn data_is_msg(data: &[u8]) -> bool {
    cfb::CompoundFile::open(Cursor::new(data))
        .is_ok_and(|comp| comp.walk().any(|e| e.name().starts_with("__substg1.0_")))
}

/// Copy the storage at `storage` and everything beneath it into a new
/// in-memory compound file whose root is that storage. Returns `None` when
/// the subtree holds more than [`MAX_REBUILT_STORAGE_ENTRIES`] entries or
/// more than `max_bytes` of stream data, or when any copy fails.
fn rebuild_storage(
    comp: &mut cfb::CompoundFile<Cursor<&[u8]>>,
    storage: &str,
    max_bytes: u64,
) -> Option<Vec<u8>> {
    use std::io::Write;

    let subtree: Vec<(String, bool)> = comp
        .walk_storage(storage)
        .ok()?
        .take(MAX_REBUILT_STORAGE_ENTRIES + 1)
        .map(|e| (e.path().to_string_lossy().into_owned(), e.is_stream()))
        .collect();
    if subtree.len() > MAX_REBUILT_STORAGE_ENTRIES {
        return None;
    }
    let total: u64 = comp
        .walk_storage(storage)
        .ok()?
        .filter(cfb::Entry::is_stream)
        .map(|e| e.len())
        .sum();
    if total > max_bytes {
        return None;
    }

    let mut out = cfb::CompoundFile::create(Cursor::new(Vec::new())).ok()?;
    for (path, is_stream) in subtree {
        let Some(rel) = path
            .strip_prefix(storage)
            .filter(|r| !r.is_empty() && *r != "/")
        else {
            continue;
        };
        if is_stream {
            let mut data = Vec::new();
            comp.open_stream(&path).ok()?.read_to_end(&mut data).ok()?;
            out.create_stream(rel).ok()?.write_all(&data).ok()?;
        } else {
            out.create_storage(rel).ok()?;
        }
    }
    out.flush().ok()?;
    Some(out.into_inner().into_inner())
}

/// Read an MSG string property `__substg1.0_<id>001F` (UTF-16LE), falling
/// back to the 8-bit `001E` spelling. NULs are stripped and surrounding
/// whitespace trimmed; an empty value reads as absent.
fn read_msg_string(
    comp: &mut cfb::CompoundFile<Cursor<&[u8]>>,
    storage: &str,
    prop_id: &str,
) -> Option<String> {
    const MAX_BYTES: u64 = 4096;
    for (prop_type, wide) in [("001F", true), ("001E", false)] {
        let Ok(stream) = comp.open_stream(format!("{storage}/__substg1.0_{prop_id}{prop_type}"))
        else {
            continue;
        };
        let mut data = Vec::new();
        if stream.take(MAX_BYTES).read_to_end(&mut data).is_err() {
            continue;
        }
        let text = if wide {
            let units: Vec<u16> = data
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(&data).into_owned()
        };
        let text: String = text.chars().filter(|c| *c != '\0').collect();
        let text = text.trim();
        if !text.is_empty() {
            return Some(text.to_string());
        }
    }
    None
}

/// Turn an attacker-chosen attachment filename into a single safe member
/// path component: keep only the final `/`- or `\`-separated segment,
/// drop control characters, break up the `!!` nesting delimiter, and cap
/// the length. Names that reduce to nothing, `.` or `..` become
/// `attachment-<index>`.
pub(crate) fn sanitize_attachment_filename(raw: Option<&str>, index: u32) -> String {
    let base = raw
        .unwrap_or_default()
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or_default();
    let mut name: String = base
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_ATTACHMENT_NAME_CHARS)
        .collect();
    while name.contains("!!") {
        name = name.replace("!!", "!_");
    }
    let name = name.trim();
    if name.is_empty() || name == "." || name == ".." {
        format!("attachment-{index}")
    } else {
        name.to_string()
    }
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
                if let (Some(total_size), Some(version)) = (le_u32(&header, 0), le_u16(&header, 4))
                {
                    let embedded_filename = if version == 2 {
                        // After version, there are null-terminated strings: label, filename, ...
                        let bytes = header.get(6..).unwrap_or_default();
                        bytes
                            .iter()
                            .position(|&byte| byte == 0)
                            .filter(|&end| end > 0)
                            .and_then(|end| bytes.get(..end))
                            .map(|label| String::from_utf8_lossy(label).into_owned())
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
/// they expose differ.
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
    let Some(section) = locate_first_section(data) else {
        return;
    };
    for (prop_id, prop_offset) in property_entries(section) {
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
    for (prop_id, prop_offset) in property_entries(section) {
        if prop_id == 0x13 {
            meta.security_flag = read_property_u32(section, prop_offset);
        }
    }
}

/// Walk the MS-OLEPS outer structure and return a slice into the first
/// property-set section (the `size + num_properties + entries` block).
/// - 28 byte header (byte_order, version, os_version, clsid, num_sections)
/// - Section header: fmtid (16 bytes) + offset (4 bytes) per section
fn locate_first_section(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 48 || le_u16(data, 0)? != 0xFFFE || le_u32(data, 24)? == 0 {
        return None;
    }
    let section_offset = le_u32(data, 44)? as usize;
    if section_offset.checked_add(8)? > data.len() {
        return None;
    }
    data.get(section_offset..)
}

/// The `(property_id, offset)` entries of a property-set section (each an
/// 8-byte `id + offset` pair after the `size + num_properties` header), as
/// far as both the declared count and the section's bytes go. Entries whose
/// value would start past the section are skipped.
fn property_entries(section: &[u8]) -> impl Iterator<Item = (u32, usize)> + '_ {
    let count = le_u32(section, 4).map_or(0, |n| n as usize);
    section
        .get(8..)
        .unwrap_or_default()
        .as_chunks::<8>()
        .0
        .iter()
        .take(count)
        .filter_map(|entry| {
            let id = le_u32(entry, 0)?;
            let offset = le_u32(entry, 4)? as usize;
            (offset.checked_add(8)? <= section.len()).then_some((id, offset))
        })
}

/// Read a VT_I4 (0x0003) property value as u32.  Negative values are
/// clamped to zero — the four numeric SummaryInformation properties
/// we care about are intrinsically non-negative.
fn read_property_u32(section: &[u8], offset: usize) -> Option<u32> {
    if le_u32(section, offset)? != 0x0003 {
        return None;
    }
    let value = le_u32(section, offset.checked_add(4)?)? as i32;
    Some(value.max(0) as u32)
}

/// Read a VT_FILETIME (0x0040) property value and return the duration
/// in *minutes*.  PIDSI_EDITTIME stores the total time the document
/// has been edited, packaged as a FILETIME-style duration in 100-ns
/// units.  Real edit times are tiny relative to absolute FILETIMEs,
/// so a literal-FILETIME-as-timestamp interpretation overflows; we
/// always treat the value as a duration here.
fn read_filetime_minutes(section: &[u8], offset: usize) -> Option<u64> {
    if le_u32(section, offset)? != 0x0040 {
        return None;
    }
    let raw = le_u64(section, offset.checked_add(4)?)?;
    // 100-ns units → minutes.
    raw.checked_div(600_000_000)
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
    // VT_LPSTR = 0x001E
    if le_u32(section, offset)? != 0x001E {
        return None;
    }
    let str_len = le_u32(section, offset.checked_add(4)?)? as usize;
    if str_len == 0 {
        return None;
    }
    let start = offset.checked_add(8)?;
    let bytes = section.get(start..start.checked_add(str_len)?)?;
    let s = String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .to_string();

    if s.is_empty() { None } else { Some(s) }
}

fn le_u16(buf: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        buf.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn le_u32(buf: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        buf.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn le_u64(buf: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        buf.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
pub(crate) mod tests;
