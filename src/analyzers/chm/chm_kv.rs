//! `chm.*` kv subtree — CHM container metadata.
//!
//! Surfaces information that lives inside CHM control files
//! (`#SYSTEM`, `::DataSpace/NameList`, the directory roster) but not
//! inside the LZX-compressed user content. Cheap to extract because
//! all the source records are in the Uncompressed section.

use serde::Serialize;
use serde_json::Value;

use super::Chm;

/// `chm.*` kv tree. All fields are optional; only fields with data
/// get serialized.
#[derive(Default, Serialize)]
struct ChmKv {
    /// Number of internal directory entries (excluding control files).
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_count: Option<u32>,
    /// Names of every user-visible internal file (skipping `#`/`::`/`$`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    entries: Vec<String>,
    /// Names of the named content sections (typically `Uncompressed`,
    /// `MSCompressed`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    content_sections: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<ChmSystem>,
    /// True if any user-visible HTML topic was found in the directory.
    has_html: bool,
    /// True if a TOC file (`.hhc`) is present in the directory.
    has_toc: bool,
    /// True if an index file (`.hhk`) is present in the directory.
    has_index: bool,
    /// LZX window size (bytes), if MSCompressed/ControlData was found.
    #[serde(skip_serializing_if = "Option::is_none")]
    lzx_window_bytes: Option<u64>,
    /// LZX reset interval in bytes (uncompressed), if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    lzx_reset_interval_bytes: Option<u64>,
}

/// `chm.system.*` — fields parsed from the `#SYSTEM` control file.
#[derive(Default, Serialize)]
struct ChmSystem {
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_topic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_window: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_font: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compiler_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locale_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<u32>,
    /// True if the CHM declares an HTML Help Workshop compiler version
    /// (suggests authentic build) — useful as a baseline for malware
    /// triage.
    has_compiler_version: bool,
}

/// Extract the `chm.*` kv subtree from raw CHM bytes. Returns `None`
/// for non-CHM input.
#[must_use]
pub(crate) fn extract(data: &[u8]) -> Option<Value> {
    let chm = Chm::parse(data).ok()?;
    let mut kv = ChmKv::default();

    // Content section names live in `::DataSpace/NameList` (in the
    // Uncompressed section). The format is:
    //   u16 length_in_words
    //   u16 num_entries
    //   then for each entry: u16 name_length_words, UTF-16LE name (no NUL)
    if let Some(entry) = chm.entries.iter().find(|e| e.name == "::DataSpace/NameList") {
        if let Some(bytes) = read_uncompressed_entry(&chm, entry) {
            kv.content_sections = parse_namelist(bytes);
        }
    }

    // Per-entry roster — surface only user-visible names.
    let mut entries = Vec::new();
    let mut html_count = 0u32;
    for e in &chm.entries {
        if e.length == 0 {
            continue;
        }
        // CHM directory names usually carry a leading '/' for user-visible
        // files. Strip it before classifying so '/#SYSTEM' and '/$OBJINST'
        // are correctly recognized as control files.
        let stripped = e.name.strip_prefix('/').unwrap_or(&e.name);
        if stripped.starts_with('#')
            || stripped.starts_with("::")
            || stripped.starts_with('$')
        {
            continue;
        }
        if e.name == "/" || e.name.ends_with('/') {
            continue;
        }
        let lower = e.name.to_ascii_lowercase();
        if lower.ends_with(".html") || lower.ends_with(".htm") {
            html_count += 1;
        }
        if lower.ends_with(".hhc") {
            kv.has_toc = true;
        }
        if lower.ends_with(".hhk") {
            kv.has_index = true;
        }
        entries.push(e.name.clone());
    }
    kv.has_html = html_count > 0;
    kv.entry_count = Some(entries.len() as u32);
    if entries.len() <= 256 {
        kv.entries = entries;
    }

    // #SYSTEM record block (some CHMs prefix with '/', some don't).
    if let Some(entry) = chm
        .entries
        .iter()
        .find(|e| e.name == "/#SYSTEM" || e.name == "#SYSTEM")
    {
        if let Some(bytes) = read_uncompressed_entry(&chm, entry) {
            kv.system = Some(parse_system(bytes));
        }
    }

    // LZX parameters from ControlData.
    if let Some(entry) = chm
        .entries
        .iter()
        .find(|e| e.name == "::DataSpace/Storage/MSCompressed/ControlData")
    {
        if let Some(bytes) = read_uncompressed_entry(&chm, entry) {
            if let Some((window, reset)) = parse_control_data_kv(bytes) {
                kv.lzx_window_bytes = Some(window);
                kv.lzx_reset_interval_bytes = Some(reset);
            }
        }
    }

    serde_json::to_value(kv).ok()
}

fn read_uncompressed_entry<'a>(chm: &'a Chm<'_>, entry: &super::ChmEntry) -> Option<&'a [u8]> {
    if entry.section != 0 {
        return None;
    }
    chm.read_uncompressed_for(entry)
}

fn parse_namelist(bytes: &[u8]) -> Vec<String> {
    if bytes.len() < 4 {
        return Vec::new();
    }
    let count = u16_le(bytes, 2) as usize;
    let mut out = Vec::with_capacity(count);
    let mut pos = 4usize;
    for _ in 0..count {
        if pos + 2 > bytes.len() {
            break;
        }
        let name_words = u16_le(bytes, pos) as usize;
        pos += 2;
        let nbytes = name_words * 2;
        if pos + nbytes + 2 > bytes.len() {
            break;
        }
        let name = utf16le_to_string(&bytes[pos..pos + nbytes]);
        out.push(name);
        // Skip name + trailing NUL u16
        pos += nbytes + 2;
    }
    out
}

/// `#SYSTEM` is a sequence of (u16 code, u16 length, u8[length] data) records.
/// We pull the codes that carry attribution-grade strings.
fn parse_system(bytes: &[u8]) -> ChmSystem {
    let mut sys = ChmSystem::default();
    if bytes.len() < 4 {
        return sys;
    }
    // First 4 bytes: u32 version (typically 3).
    let mut pos = 4usize;
    while pos + 4 <= bytes.len() {
        let code = u16_le(bytes, pos);
        let len = u16_le(bytes, pos + 2) as usize;
        pos += 4;
        if pos + len > bytes.len() {
            break;
        }
        let payload = &bytes[pos..pos + len];
        pos += len;
        match code {
            0 => sys.default_topic = decode_cstr(payload),
            1 => sys.default_window = decode_cstr(payload),
            2 => sys.title = decode_cstr(payload),
            3 => {
                if payload.len() >= 4 {
                    sys.locale_id = Some(u32::from_le_bytes([
                        payload[0], payload[1], payload[2], payload[3],
                    ]));
                }
            }
            4 => {
                // u32 lcid + u32 timestamp + u32 unknown
                if payload.len() >= 8 {
                    sys.timestamp = Some(u32::from_le_bytes([
                        payload[4], payload[5], payload[6], payload[7],
                    ]));
                }
            }
            6 => {
                // CHM file basename — not retained (PII path noise).
            }
            9 => {
                // Compiler version string (e.g. "HHA Version 4.74.8702").
                sys.compiler_version = decode_cstr(payload);
                sys.has_compiler_version = sys.compiler_version.is_some();
            }
            16 => sys.default_font = decode_cstr(payload),
            _ => {}
        }
    }
    sys
}

fn parse_control_data_kv(bytes: &[u8]) -> Option<(u64, u64)> {
    if bytes.len() < 0x1c || &bytes[4..8] != b"LZXC" {
        return None;
    }
    let reset_interval_chunks = u32::from_le_bytes([bytes[0x0c], bytes[0x0d], bytes[0x0e], bytes[0x0f]]);
    let window_chunks = u32::from_le_bytes([bytes[0x10], bytes[0x11], bytes[0x12], bytes[0x13]]);
    let window_bytes = u64::from(window_chunks) * 0x8000;
    let reset_bytes = u64::from(reset_interval_chunks) * 0x8000;
    Some((window_bytes, reset_bytes))
}

fn decode_cstr(b: &[u8]) -> Option<String> {
    let nul = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    let s = std::str::from_utf8(&b[..nul]).ok()?.trim();
    (!s.is_empty()).then(|| s.to_string())
}

fn utf16le_to_string(b: &[u8]) -> String {
    let mut units = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i + 1 < b.len() {
        units.push(u16::from_le_bytes([b[i], b[i + 1]]));
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

fn u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_namelist_safe() {
        assert!(parse_namelist(&[]).is_empty());
    }

    #[test]
    fn truncated_system_safe() {
        assert!(parse_system(&[]).title.is_none());
        assert!(parse_system(&[0, 0, 0]).title.is_none());
    }

    #[test]
    fn system_extracts_title() {
        // version=3, then code=2 (title) len=5 "Hello"
        let mut data = vec![3, 0, 0, 0]; // version
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(b"Hello");
        let sys = parse_system(&data);
        assert_eq!(sys.title.as_deref(), Some("Hello"));
    }

    #[test]
    fn parse_control_data_window() {
        let mut data = vec![0u8; 0x1c];
        data[4..8].copy_from_slice(b"LZXC");
        // reset_interval = 2
        data[0x0c..0x10].copy_from_slice(&2u32.to_le_bytes());
        // window = 0x10 → 0x10 * 0x8000 = 0x80000 (512 KB)
        data[0x10..0x14].copy_from_slice(&0x10u32.to_le_bytes());
        let (window, reset) = parse_control_data_kv(&data).unwrap();
        assert_eq!(window, 0x80000);
        assert_eq!(reset, 0x10000);
    }
}
