//! Payload extraction from OLE2 compound files (.doc, .xls, .ppt, .msg, .msi).
//!
//! filefacts parses the document (`office.*`); this module only copies out
//! the bytes cleave analyzes as sub-files: streams that are executables,
//! cabinets or MSI Binary-table scripts, OLE1 Packager payloads at the
//! offsets filefacts located, and Outlook attachments.

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

/// A payload filefacts located inside a stream (an OLE1 Packager object's
/// file), from an `office.embedded[]` entry with a `data_offset`.
#[derive(Debug, Clone)]
pub(crate) struct LocatedPayload {
    pub stream: String,
    pub filename: String,
    pub offset: u64,
    pub size: u64,
    pub kind: EmbeddedExecKind,
}

/// The payloads of one compound file, for sub-analysis.
#[derive(Debug, Default)]
pub(crate) struct Ole2Payloads {
    pub executables: Vec<EmbeddedExecutable>,
    pub msg_attachments: Vec<MsgAttachment>,
}

/// Copy out the payloads of the compound file `data`: executable and script
/// streams, the `located` payloads inside streams, and, for an Outlook
/// message, its attachments.
pub(crate) fn extract_payloads(
    data: &[u8],
    is_msg: bool,
    located: &[LocatedPayload],
) -> Result<Ole2Payloads> {
    let mut comp = cfb::CompoundFile::open(Cursor::new(data))?;
    let entries: Vec<(String, u64, bool)> = comp
        .walk()
        .map(|e| {
            (
                e.path().to_string_lossy().into_owned(),
                e.len(),
                e.is_stream(),
            )
        })
        .collect();
    let mut executables = find_embedded_executables(&mut comp, &entries);
    for payload in located {
        if executables.len() >= MAX_EMBEDDED_EXECUTABLES {
            break;
        }
        if let Some(executable) = carve(&mut comp, payload) {
            executables.push(executable);
        }
    }
    let msg_attachments = if is_msg {
        let already_extracted: Vec<&str> =
            executables.iter().map(|e| e.stream_path.as_str()).collect();
        find_msg_attachments(&mut comp, &entries, &already_extracted)
    } else {
        Vec::new()
    };
    Ok(Ole2Payloads {
        executables,
        msg_attachments,
    })
}

/// The `payload` bytes of its stream, named for the packaged file beside it
/// (`/ObjectPool/_1/payload.exe`) so the member path reads as what it is.
fn carve(
    comp: &mut cfb::CompoundFile<Cursor<&[u8]>>,
    payload: &LocatedPayload,
) -> Option<EmbeddedExecutable> {
    if payload.size < MIN_EMBEDDED_EXECUTABLE_SIZE || payload.size > MAX_EMBEDDED_EXECUTABLE_SIZE {
        return None;
    }
    let mut stream = comp.open_stream(&payload.stream).ok()?;
    let end = payload.offset.checked_add(payload.size)?;
    if end > stream.len() {
        return None;
    }
    std::io::copy(
        &mut (&mut stream).take(payload.offset),
        &mut std::io::sink(),
    )
    .ok()?;
    let mut data = Vec::with_capacity(usize::try_from(payload.size).ok()?);
    stream.take(payload.size).read_to_end(&mut data).ok()?;
    let parent = payload
        .stream
        .rsplit_once('/')
        .map_or("", |(parent, _)| parent);
    let name = sanitize_attachment_filename(Some(&payload.filename), 0);
    Some(EmbeddedExecutable {
        stream_path: format!("{parent}/{name}"),
        kind: payload.kind,
        data,
    })
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

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
pub(crate) mod tests;
