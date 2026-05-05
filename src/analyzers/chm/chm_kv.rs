//! `chm.*` kv subtree + `chm` metrics for CHM containers.
//!
//! kv (`chm.*`) carries direct, attribution-grade fields lifted out of
//! ITSF/ITSP/`#SYSTEM` — who built it, where (locale), when (rebuild
//! counter), what's inside (entry roster, content sections, presence
//! flags), and the LZX framing parameters. Ratios, sums, and mismatch
//! flags that need to be computed from those raw fields live on
//! `ChmMetrics` instead, per the project's "extrapolation belongs in
//! metrics" rule.

use serde::Serialize;
use serde_json::Value;

use super::{Chm, ChmEntry};
use crate::types::container_metrics::ChmMetrics;

/// `chm.*` kv tree. All fields are optional; only fields with data
/// get serialized.
#[derive(Default, Serialize)]
struct ChmKv {
    /// ITSF header signals (version, locale, rebuild counter).
    #[serde(skip_serializing_if = "Option::is_none")]
    itsf: Option<ChmItsf>,
    /// `#SYSTEM` records — who/where/when from the compile pass.
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<ChmSystem>,
    /// LZX framing for `MSCompressed/Content`.
    #[serde(skip_serializing_if = "Option::is_none")]
    lzx: Option<ChmLzx>,

    /// Names of every user-visible internal file (skipping `#`/`::`/`$`).
    /// Use `size_max:`/`size_min:` against this path to gate on entry
    /// count from a trait condition; the absolute number is mirrored
    /// to `metrics.chm.user_entry_count` for `field: ... max: N`-style
    /// rules.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    entries: Vec<String>,
    /// Names of the named content sections (typically `Uncompressed`,
    /// `MSCompressed`).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    content_sections: Vec<String>,

    /// True if any user-visible HTML topic was found in the directory.
    has_html: bool,
    /// True if a TOC file (`.hhc`) is present in the directory.
    has_toc: bool,
    /// True if an index file (`.hhk`) is present in the directory.
    has_index: bool,
    /// True if `$OBJINST` (active-content object instances) is present.
    /// HTML Help's ShortCut control and other ActiveX-instantiated
    /// objects record their instance data here.
    has_objinst: bool,
    /// True if `$WWKeywordLinks/Property` is present (the
    /// keyword-search subsystem). HHA Workshop emits it for any
    /// non-trivial help build.
    has_keyword_links: bool,
    /// True if `$WWAssociativeLinks/Property` is present.
    has_associative_links: bool,
    /// True if `$FIftiMain` (full-text index) is present. Authentic
    /// HHA-built CHMs almost always have one; hand-rolled droppers
    /// often skip it.
    has_fifti: bool,
}

/// `chm.itsf.*` — ITSF v3 header fields.
#[derive(Default, Serialize)]
struct ChmItsf {
    #[serde(skip_serializing_if = "is_zero_u32")]
    version: u32,
    /// Last-modified counter (the file rebuild generation; not a
    /// timestamp). Same source rebuilt produces the same value.
    #[serde(skip_serializing_if = "is_zero_u32")]
    timestamp_counter: u32,
    /// Windows LCID at the ITSF level — the locale of the compiling
    /// box. (`#SYSTEM.locale_id` is the locale the *content* targets.)
    #[serde(skip_serializing_if = "is_zero_u32")]
    lcid: u32,
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
    /// HHA Workshop / Sandcastle / custom compiler version string.
    /// Strong "who built it" signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    compiler_version: Option<String>,
    /// Original CHM source filename (HHA `#SYSTEM` code 6). Often
    /// reveals the local path on the build machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    chm_filename: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locale_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<u32>,
    /// True if the CHM declares an HTML Help Workshop compiler version
    /// (suggests authentic build) — useful as a baseline for malware
    /// triage.
    has_compiler_version: bool,
    /// Internal-only: count of `InfoType` records in `#SYSTEM`.
    /// Surfaced on `metrics.chm.infotype_count` rather than as kv
    /// (counts go in metrics).
    #[serde(skip)]
    infotype_count: u32,
}

/// `chm.lzx.*` — MSCompressed/Content framing parameters.
///
/// Direct values from `MSCompressed/ControlData` and the `ResetTable`
/// header — no aggregation. Counts (`reset_count`) live on
/// `metrics.chm.lzx_reset_count` instead.
#[derive(Default, Serialize)]
struct ChmLzx {
    #[serde(skip_serializing_if = "is_zero_u64")]
    window_bytes: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    reset_interval_bytes: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    block_len: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    uncompressed_size: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    compressed_size: u64,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// Extract the `chm.*` kv subtree from raw CHM bytes. Returns `None`
/// for non-CHM input.
#[must_use]
pub(crate) fn extract(data: &[u8]) -> Option<Value> {
    let chm = Chm::parse(data).ok()?;
    let kv = build_kv(&chm);
    serde_json::to_value(kv).ok()
}

/// Compute the `ChmMetrics` (derived ratios + per-entry aggregates)
/// for a CHM file. Returns `None` for non-CHM input or when the file
/// has no signals worth surfacing.
#[must_use]
pub(crate) fn metrics(data: &[u8]) -> Option<ChmMetrics> {
    let chm = Chm::parse(data).ok()?;
    Some(build_metrics(&chm, data.len() as u64))
}

fn build_kv(chm: &Chm<'_>) -> ChmKv {
    let mut kv = ChmKv::default();

    kv.itsf = Some(ChmItsf {
        version: chm.itsf.version,
        timestamp_counter: chm.itsf.timestamp_counter,
        lcid: chm.itsf.lcid,
    });

    // Content section names live in `::DataSpace/NameList`.
    if let Some(entry) = chm
        .entries
        .iter()
        .find(|e| e.name == "::DataSpace/NameList")
    {
        if let Some(bytes) = read_uncompressed_entry(chm, entry) {
            kv.content_sections = parse_namelist(bytes);
        }
    }

    // Per-entry roster + presence flags.
    let mut entries = Vec::new();
    let mut html_count = 0u32;
    for e in &chm.entries {
        if e.length == 0 {
            continue;
        }
        let stripped = strip_leading_slash(&e.name);
        if is_control_name(stripped) {
            // Detect specific control entries we want to flag.
            if stripped == "$OBJINST" {
                kv.has_objinst = true;
            } else if stripped == "$WWKeywordLinks/Property" {
                kv.has_keyword_links = true;
            } else if stripped == "$WWAssociativeLinks/Property" {
                kv.has_associative_links = true;
            } else if stripped == "$FIftiMain" {
                kv.has_fifti = true;
            }
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
    if entries.len() <= 256 {
        kv.entries = entries;
    }

    // #SYSTEM record block (some CHMs prefix with '/', some don't).
    if let Some(entry) = chm
        .entries
        .iter()
        .find(|e| e.name == "/#SYSTEM" || e.name == "#SYSTEM")
    {
        if let Some(bytes) = read_uncompressed_entry(chm, entry) {
            kv.system = Some(parse_system(bytes));
        }
    }

    // LZX framing — pull from the parser's accessor so we don't
    // re-walk ControlData / ResetTable.
    if let Some(p) = chm.lzx_params() {
        kv.lzx = Some(ChmLzx {
            window_bytes: p.window_bytes,
            reset_interval_bytes: p.reset_interval_bytes,
            block_len: p.block_len,
            uncompressed_size: p.uncompressed_size,
            compressed_size: p.compressed_size,
        });
    }

    kv
}

fn build_metrics(chm: &Chm<'_>, file_size: u64) -> ChmMetrics {
    let mut m = ChmMetrics::default();

    let mut control_count = 0u32;
    let mut user_count = 0u32;
    let mut user_total = 0u64;
    let mut user_max = 0u64;
    let mut html = 0u32;
    let mut script = 0u32;
    let mut image = 0u32;
    let mut user_names: Vec<String> = Vec::new();
    for e in &chm.entries {
        let stripped = strip_leading_slash(&e.name);
        if is_control_name(stripped) {
            control_count += 1;
            continue;
        }
        if e.name == "/" || e.name.ends_with('/') {
            continue;
        }
        if e.length == 0 {
            continue;
        }
        user_count += 1;
        user_total = user_total.saturating_add(e.length);
        if e.length > user_max {
            user_max = e.length;
        }
        let lower = e.name.to_ascii_lowercase();
        if lower.ends_with(".html") || lower.ends_with(".htm") {
            html += 1;
        }
        if lower.ends_with(".js") || lower.ends_with(".vbs") || lower.ends_with(".wsf") {
            script += 1;
        }
        if lower.ends_with(".png")
            || lower.ends_with(".jpg")
            || lower.ends_with(".jpeg")
            || lower.ends_with(".gif")
            || lower.ends_with(".bmp")
        {
            image += 1;
        }
        user_names.push(stripped.to_string());
    }
    m.user_entry_count = user_count;
    m.control_entry_count = control_count;
    m.html_entry_count = html;
    m.script_entry_count = script;
    m.image_entry_count = image;
    m.max_user_entry_size = user_max;
    m.total_user_entry_size = user_total;
    if file_size > 0 {
        m.user_byte_ratio = (user_total as f64 / file_size as f64) as f32;
    }

    if let Some(p) = chm.lzx_params() {
        m.lzx_reset_count = p.reset_count;
        if p.compressed_size > 0 {
            m.lzx_compression_ratio =
                (p.uncompressed_size as f64 / p.compressed_size as f64) as f32;
        }
    }

    // Mismatch / consistency flags — derived from #SYSTEM + roster.
    if let Some(entry) = chm
        .entries
        .iter()
        .find(|e| e.name == "/#SYSTEM" || e.name == "#SYSTEM")
    {
        if let Some(bytes) = read_uncompressed_entry(chm, entry) {
            let sys = parse_system(bytes);
            m.no_compiler_version = !sys.has_compiler_version;
            m.infotype_count = sys.infotype_count;
            if let Some(topic) = sys.default_topic.as_deref() {
                let lower = topic.to_ascii_lowercase();
                m.default_topic_missing = !user_names
                    .iter()
                    .any(|n| n.eq_ignore_ascii_case(topic) || n.to_ascii_lowercase() == lower);
            }
            if let (Some(title), Some(topic)) = (sys.title.as_deref(), sys.default_topic.as_deref())
            {
                m.title_topic_mismatch = title != topic
                    && !title.is_empty()
                    && !topic.is_empty()
                    && !title.eq_ignore_ascii_case(topic);
            }
        }
    } else {
        // No #SYSTEM at all: count as missing compiler version.
        m.no_compiler_version = true;
    }

    m
}

fn strip_leading_slash(name: &str) -> &str {
    name.strip_prefix('/').unwrap_or(name)
}

fn is_control_name(stripped: &str) -> bool {
    stripped.starts_with('#') || stripped.starts_with("::") || stripped.starts_with('$')
}

fn read_uncompressed_entry<'a>(chm: &'a Chm<'_>, entry: &ChmEntry) -> Option<&'a [u8]> {
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
            5 => {
                // InfoType record — count occurrences only; payload format
                // is opaque to us here.
                sys.infotype_count = sys.infotype_count.saturating_add(1);
            }
            6 => {
                // CHM source filename — useful for build-machine
                // attribution. Decode but bail on garbage.
                sys.chm_filename = decode_cstr(payload);
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
    fn system_counts_infotypes() {
        // version=3, three InfoType (code=5) records
        let mut data = vec![3, 0, 0, 0];
        for _ in 0..3 {
            data.extend_from_slice(&5u16.to_le_bytes());
            data.extend_from_slice(&2u16.to_le_bytes());
            data.extend_from_slice(&[0xaa, 0xbb]);
        }
        let sys = parse_system(&data);
        assert_eq!(sys.infotype_count, 3);
    }

    #[test]
    fn control_name_classification() {
        assert!(is_control_name("#SYSTEM"));
        assert!(is_control_name("$OBJINST"));
        assert!(is_control_name("::DataSpace/NameList"));
        assert!(!is_control_name("help.html"));
        assert!(!is_control_name("page_1.html"));
    }
}
