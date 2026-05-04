//! `rpm.*` kv subtree — RPM lead + signature + main-header
//! attribution (BUILDHOST, PACKAGER, VENDOR, BUILDTIME, …).
//!
//! Header-only parse, no payload decompression — stays cheap on
//! multi-GB packages. The schema is defined by the [`RpmKv`] struct.

use serde::Serialize;
use serde_json::Value;

const RPM_LEAD_MAGIC: [u8; 4] = [0xed, 0xab, 0xee, 0xdb];
const RPM_HEADER_MAGIC: [u8; 3] = [0x8e, 0xad, 0xe8];
const LEAD_BYTES: usize = 96;

/// Cap the per-header structure to keep the kv pass cheap on
/// pathological / hostile inputs (real headers are typically <1 MB).
const MAX_HEADER_BYTES: usize = 16 * 1024 * 1024;

/// Main-header tag numbers (RPM tag space). Disambiguated from the
/// signature-header tags by living in their own module — the two
/// namespaces overlap numerically (e.g. main `VERSION = 1001`,
/// sig `PGP = 1002`) and the original flat `TAG_*` / `SIG_TAG_*`
/// naming was easy to mix up.
mod main_tag {
    pub(super) const NAME: u32 = 1000;
    pub(super) const VERSION: u32 = 1001;
    pub(super) const RELEASE: u32 = 1002;
    pub(super) const EPOCH: u32 = 1003;
    pub(super) const SUMMARY: u32 = 1004;
    pub(super) const BUILDTIME: u32 = 1006;
    pub(super) const BUILDHOST: u32 = 1007;
    pub(super) const DISTRIBUTION: u32 = 1010;
    pub(super) const VENDOR: u32 = 1011;
    pub(super) const LICENSE: u32 = 1014;
    pub(super) const PACKAGER: u32 = 1015;
    pub(super) const GROUP: u32 = 1016;
    pub(super) const URL: u32 = 1020;
    pub(super) const OS: u32 = 1021;
    pub(super) const ARCH: u32 = 1022;
    pub(super) const SOURCERPM: u32 = 1044;
    pub(super) const RPMVERSION: u32 = 1064;
    pub(super) const COOKIE: u32 = 1094;
    pub(super) const PAYLOADFORMAT: u32 = 1124;
    pub(super) const PAYLOADCOMPRESSOR: u32 = 1125;
    pub(super) const PAYLOADFLAGS: u32 = 1126;
    pub(super) const PLATFORM: u32 = 1132;
}

/// Signature-header tag numbers. Numerically overlap with main-header
/// tags but live in a separate header.
mod sig_tag {
    pub(super) const DSA: u32 = 267;
    pub(super) const RSA: u32 = 268;
    pub(super) const PGP: u32 = 1002;
    pub(super) const GPG: u32 = 1005;
}

/// `rpm.*` kv tree. Every named field is optional except `signed`,
/// which is a derived bool always emitted.
#[derive(Default, Serialize)]
struct RpmKv {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    release: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epoch: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    buildtime: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    buildhost: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    distribution: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    license: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    packager: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rpmversion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cookie: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sourcerpm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_format: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_compressor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_flags: Option<String>,
    signed: bool,
}

/// Extract the `rpm.*` kv subtree from raw RPM bytes. Returns `None`
/// for non-RPM input or truncated headers.
#[must_use]
pub(crate) fn extract(data: &[u8]) -> Option<Value> {
    if data.len() < LEAD_BYTES + 16 || data[..4] != RPM_LEAD_MAGIC {
        return None;
    }

    let mut pos = LEAD_BYTES;

    // Signature header — short-circuit on the first signing tag we
    // see in the index without materializing the data store.
    let (sig_entries, _sig_data, sig_total) = read_header(&data[pos..])?;
    let signed = sig_entries.iter().any(|e| {
        matches!(
            e.tag,
            sig_tag::RSA | sig_tag::DSA | sig_tag::PGP | sig_tag::GPG
        ) && e.count > 0
    });
    pos += sig_total;
    pos += (8 - (pos % 8)) % 8;

    // Main header.
    let (main_entries, main_data, _) = read_header(&data[pos..])?;

    let mut kv = RpmKv {
        signed,
        ..Default::default()
    };
    for entry in &main_entries {
        apply_main_tag(&mut kv, entry, main_data);
    }
    serde_json::to_value(kv).ok()
}

/// Decode one main-header entry into the matching `RpmKv` field.
/// Tags outside the curated allow-list are dropped silently.
fn apply_main_tag(kv: &mut RpmKv, entry: &IndexEntry, data: &[u8]) {
    match entry.tag {
        main_tag::NAME => kv.name = decode_string(entry, data),
        main_tag::VERSION => kv.version = decode_string(entry, data),
        main_tag::RELEASE => kv.release = decode_string(entry, data),
        main_tag::EPOCH => kv.epoch = decode_u32(entry, data),
        main_tag::SUMMARY => kv.summary = decode_string(entry, data),
        main_tag::BUILDTIME => kv.buildtime = decode_u32(entry, data),
        main_tag::BUILDHOST => kv.buildhost = decode_string(entry, data),
        main_tag::DISTRIBUTION => kv.distribution = decode_string(entry, data),
        main_tag::VENDOR => kv.vendor = decode_string(entry, data),
        main_tag::LICENSE => kv.license = decode_string(entry, data),
        main_tag::PACKAGER => kv.packager = decode_string(entry, data),
        main_tag::GROUP => kv.group = decode_string(entry, data),
        main_tag::URL => kv.url = decode_string(entry, data),
        main_tag::OS => kv.os = decode_string(entry, data),
        main_tag::ARCH => kv.arch = decode_string(entry, data),
        main_tag::RPMVERSION => kv.rpmversion = decode_string(entry, data),
        main_tag::COOKIE => kv.cookie = decode_string(entry, data),
        main_tag::SOURCERPM => kv.sourcerpm = decode_string(entry, data),
        main_tag::PLATFORM => kv.platform = decode_string(entry, data),
        main_tag::PAYLOADFORMAT => kv.payload_format = decode_string(entry, data),
        main_tag::PAYLOADCOMPRESSOR => kv.payload_compressor = decode_string(entry, data),
        main_tag::PAYLOADFLAGS => kv.payload_flags = decode_string(entry, data),
        _ => {}
    }
}

/// STRING (type 6) and I18NSTRING (type 9) decode the same way:
/// NUL-terminated UTF-8 starting at `entry.offset`. Returns `None`
/// on missing / empty / non-UTF-8 values.
fn decode_string(entry: &IndexEntry, data: &[u8]) -> Option<String> {
    if !matches!(entry.typ, 6 | 9) {
        return None;
    }
    let off = entry.offset as usize;
    let rest = data.get(off..)?;
    let nul = rest.iter().position(|&b| b == 0)?;
    let s = std::str::from_utf8(&rest[..nul]).ok()?;
    (!s.is_empty()).then(|| s.to_string())
}

/// INT32 scalar (type 4, count 1).
fn decode_u32(entry: &IndexEntry, data: &[u8]) -> Option<u32> {
    if entry.typ != 4 || entry.count != 1 {
        return None;
    }
    let off = entry.offset as usize;
    let bytes = data.get(off..off + 4)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

/// One index entry from an RPM header — `(tag, type, offset, count)`.
#[derive(Debug, Clone, Copy)]
struct IndexEntry {
    tag: u32,
    typ: u32,
    offset: u32,
    count: u32,
}

/// Parse one RPM header (magic + entries + data store). Returns the
/// parsed entries, a view of the data store, and the total header
/// byte size (header bytes + entry bytes + data bytes).
fn read_header(slice: &[u8]) -> Option<(Vec<IndexEntry>, &[u8], usize)> {
    if slice.len() < 16 || slice[..3] != RPM_HEADER_MAGIC {
        return None;
    }
    let nindex = u32::from_be_bytes(slice[8..12].try_into().ok()?) as usize;
    let hsize = u32::from_be_bytes(slice[12..16].try_into().ok()?) as usize;
    let index_size = nindex.checked_mul(16)?;
    if index_size > MAX_HEADER_BYTES || hsize > MAX_HEADER_BYTES {
        return None;
    }
    let entries_end = 16usize.checked_add(index_size)?;
    let data_end = entries_end.checked_add(hsize)?;
    if data_end > slice.len() {
        return None;
    }

    let mut entries = Vec::with_capacity(nindex);
    for i in 0..nindex {
        let off = 16 + i * 16;
        let tag = u32::from_be_bytes(slice[off..off + 4].try_into().ok()?);
        let typ = u32::from_be_bytes(slice[off + 4..off + 8].try_into().ok()?);
        let offset = u32::from_be_bytes(slice[off + 8..off + 12].try_into().ok()?);
        let count = u32::from_be_bytes(slice[off + 12..off + 16].try_into().ok()?);
        entries.push(IndexEntry {
            tag,
            typ,
            offset,
            count,
        });
    }
    let data_store = &slice[entries_end..data_end];
    Some((entries, data_store, data_end))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Minimal fake RPM: 96-byte lead + signature header (empty) +
    /// pad + main header with NAME / VERSION / BUILDHOST / BUILDTIME.
    fn build_minimal_rpm() -> Vec<u8> {
        let mut out = Vec::new();
        // Lead
        out.extend_from_slice(&RPM_LEAD_MAGIC);
        out.extend_from_slice(&[0u8; 92]);

        // Signature header — empty (0 entries, 0 data bytes).
        out.extend_from_slice(&RPM_HEADER_MAGIC);
        out.push(1); // version
        out.extend_from_slice(&[0u8; 4]); // reserved
        out.extend_from_slice(&0u32.to_be_bytes()); // nindex
        out.extend_from_slice(&0u32.to_be_bytes()); // hsize

        // 8-byte alignment after sig (sig was exactly 16 bytes; we're at
        // 96 + 16 = 112 which is already aligned).

        // Main header — 4 entries: NAME, VERSION, BUILDHOST, BUILDTIME
        out.extend_from_slice(&RPM_HEADER_MAGIC);
        out.push(1); // version
        out.extend_from_slice(&[0u8; 4]); // reserved
        out.extend_from_slice(&4u32.to_be_bytes()); // nindex

        // Data store layout (offsets within data store):
        //   0   "openssh\0"          → 8 bytes
        //   8   "9.9p1\0"             → 6 bytes
        //   14  "build-1.example.org\0"  → 20 bytes
        //   34  4-byte BE int (1700000000)
        //
        // Total data size = 38 bytes.
        out.extend_from_slice(&38u32.to_be_bytes()); // hsize

        // Index entries: tag(4) typ(4) offset(4) count(4)
        // NAME (1000), STRING (6), offset 0, count 1
        out.extend_from_slice(&main_tag::NAME.to_be_bytes());
        out.extend_from_slice(&6u32.to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        // VERSION (1001), STRING (6), offset 8
        out.extend_from_slice(&main_tag::VERSION.to_be_bytes());
        out.extend_from_slice(&6u32.to_be_bytes());
        out.extend_from_slice(&8u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        // BUILDHOST (1007), STRING (6), offset 14
        out.extend_from_slice(&main_tag::BUILDHOST.to_be_bytes());
        out.extend_from_slice(&6u32.to_be_bytes());
        out.extend_from_slice(&14u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        // BUILDTIME (1006), INT32 (4), offset 34, count 1
        out.extend_from_slice(&main_tag::BUILDTIME.to_be_bytes());
        out.extend_from_slice(&4u32.to_be_bytes());
        out.extend_from_slice(&34u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());

        // Data store (38 bytes)
        out.extend_from_slice(b"openssh\0");
        out.extend_from_slice(b"9.9p1\0");
        out.extend_from_slice(b"build-1.example.org\0");
        out.extend_from_slice(&1_700_000_000u32.to_be_bytes());

        out
    }

    #[test]
    fn rejects_non_rpm() {
        assert!(extract(b"not an rpm").is_none());
    }

    #[test]
    fn surfaces_name_buildhost_buildtime() {
        let rpm = build_minimal_rpm();
        let kv = extract(&rpm).expect("parses");
        assert_eq!(kv["name"], "openssh");
        assert_eq!(kv["version"], "9.9p1");
        assert_eq!(kv["buildhost"], "build-1.example.org");
        assert_eq!(kv["buildtime"], 1_700_000_000_u32);
        assert_eq!(kv["signed"], false);
    }
}
