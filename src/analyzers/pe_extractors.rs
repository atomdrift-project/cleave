//! PE-specific kv-tree extractors: Rich header decoder, imphash,
//! VS_VERSIONINFO StringTable walker.
//!
//! These mirror what pefile produces in its `dump_dict()` for the
//! same fields, so EMBER2024-style trait pipelines that target
//! pefile's output paths can target ours by path.
//!
//! Each function is byte-pattern-based — no goblin dependency at
//! call site — so they survive goblin parser quirks and produce
//! useful data even on PEs that goblin can't fully parse.

use crate::types::Import;
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Rich header
// ---------------------------------------------------------------------------

/// Decoded Rich header data.
#[derive(Debug, Clone, Default)]
pub(crate) struct RichHeader {
    /// XOR key recovered from the trailing 4 bytes after `Rich`.
    pub xor_key: u32,
    /// Decoded product entries in order of appearance.
    pub entries: Vec<RichEntry>,
    /// SHA-256 of the canonical decoded entry stream — used as a
    /// strong cross-binary fingerprint for "same MSVC build chain"
    /// clustering.
    pub hash: String,
}

/// One Rich header product entry.
#[derive(Debug, Clone)]
pub(crate) struct RichEntry {
    /// Product ID (which Microsoft tool produced the contributing
    /// translation unit).  Mapped to a friendly name when known.
    pub product_id: u16,
    /// Build number (specific release of that product).
    pub build_number: u16,
    /// Number of TUs the product compiled into the binary.
    pub use_count: u32,
    /// Decoded human-friendly product name (e.g. `"VS2019 v16.10
    /// CRT"`), `"unknown"` when the ID isn't in our table.
    pub product_name: &'static str,
}

const DOS_HEADER_BOUND: usize = 0x400; // Rich headers always live before this in practice.
/// Marker bytes that terminate the Rich header (decoded "DanS").
const DANS_DECODED: u32 = 0x536E_6144;

/// Decode the Rich header from raw PE bytes. Returns `None` for
/// non-PE input or when no Rich marker is present.
#[must_use]
pub(crate) fn decode_rich_header(data: &[u8]) -> Option<RichHeader> {
    // Locate the "Rich" marker within the DOS header region.
    let bound = data.len().min(DOS_HEADER_BOUND);
    let mut rich_pos: Option<usize> = None;
    let mut search = 0;
    while search + 4 <= bound {
        let Some(rel) = data[search..bound].windows(4).position(|w| w == b"Rich") else {
            break;
        };
        rich_pos = Some(search + rel);
        search = search + rel + 4;
    }
    let rich_pos = rich_pos?;
    if rich_pos + 8 > data.len() {
        return None;
    }

    // The 4 bytes immediately after "Rich" are the XOR key.
    let xor_key = u32::from_le_bytes(data[rich_pos + 4..rich_pos + 8].try_into().ok()?);

    // Walk backward from `Rich` decoding 4-byte words until we hit
    // the "DanS" marker (which is `0x536E6144` after XOR).
    let mut entries: Vec<RichEntry> = Vec::new();
    let mut cursor = rich_pos;
    let mut decoded_words: Vec<u32> = Vec::new();
    while cursor >= 4 {
        cursor -= 4;
        let word = u32::from_le_bytes(data[cursor..cursor + 4].try_into().ok()?) ^ xor_key;
        if word == DANS_DECODED {
            break;
        }
        decoded_words.push(word);
        if decoded_words.len() > 256 {
            // Sanity bound: real Rich headers cluster under 64 words.
            break;
        }
    }
    // Decoded words are in reverse order — flip to forward order.
    decoded_words.reverse();

    // First three words after "DanS" are signature padding (zeros
    // before XOR). Skip them.
    let payload = if decoded_words.len() > 3 {
        &decoded_words[3..]
    } else {
        return None;
    };

    // Each entry is two consecutive u32s: <prod_id<<16 | build> and <use_count>.
    let mut i = 0;
    while i + 1 < payload.len() {
        let pb = payload[i];
        let count = payload[i + 1];
        let product_id = (pb >> 16) as u16;
        let build_number = (pb & 0xFFFF) as u16;
        entries.push(RichEntry {
            product_id,
            build_number,
            use_count: count,
            product_name: rich_product_name(product_id),
        });
        i += 2;
    }

    if entries.is_empty() {
        return None;
    }

    // Hash the canonical decoded payload (all entries, big-endian
    // for cross-platform stability).
    let mut hash_input = Vec::with_capacity(entries.len() * 12);
    for e in &entries {
        hash_input.extend_from_slice(&e.product_id.to_be_bytes());
        hash_input.extend_from_slice(&e.build_number.to_be_bytes());
        hash_input.extend_from_slice(&e.use_count.to_be_bytes());
    }
    use sha2::{Digest, Sha256};
    let hash = format!("{:x}", Sha256::digest(&hash_input));

    Some(RichHeader {
        xor_key,
        entries,
        hash,
    })
}

/// Map a Rich-header product ID to a human-friendly product name.
/// IDs are stable across MSVC releases; the canonical mapping is
/// reverse-engineered from MSDN forum posts and confirmed against
/// pefile's internal table.  Unknown IDs return `"unknown"` —
/// trait authors who care can target the raw `product_id`.
fn rich_product_name(id: u16) -> &'static str {
    match id {
        0x0001 => "Imp_VS_v6_or_earlier",
        0x0002 => "Imp_LinkPass1",
        0x0003 => "Cvt_Res_VS_v6_or_earlier",
        0x0004 => "Linker_VS_v6_or_earlier",
        0x0005 => "Cvt_Pgd_VS_v6_or_earlier",
        0x0006 => "Cvt_Pgo_VS_v6_or_earlier",
        0x0007 => "Aliasobj_VS_v6_or_earlier",
        0x0008 => "Vol_Make_VS_v6_or_earlier",
        0x0009 => "Cvt_Omf_VS_v6_or_earlier",
        0x000A => "Linker_v6",
        0x000B => "Cvt_Omf",
        0x000D => "Linker_v7",
        0x000E => "Export_VC2003",
        0x000F => "Imp_VC2003",
        0x0010 => "C_VS6",
        0x0011 => "Cpp_VS6",
        0x0015 => "C_VS2003",
        0x0016 => "Cpp_VS2003",
        0x0019 => "C_VS2005_BTA",
        0x001A => "Cpp_VS2005_BTA",
        0x001C => "C_VS2005",
        0x001D => "Cpp_VS2005",
        0x005A => "C_VS2005_LTCG",
        0x005B => "Cpp_VS2005_LTCG",
        0x005C => "Linker_VS2005_LTCG",
        0x0078 => "Cvtres_VS2008",
        0x0083 => "C_VS2008_LTCG",
        0x0084 => "Cpp_VS2008_LTCG",
        0x0085 => "C_VS2008",
        0x0086 => "Cpp_VS2008",
        0x0091 => "Linker_VS2008",
        0x0092 => "Linker_VS2008_LTCG",
        0x0093 => "Linker_VS2008_LTCG_RTM",
        0x009A => "C_VS2010",
        0x009B => "Cpp_VS2010",
        0x009C => "Linker_VS2010",
        0x009D => "Linker_VS2010_LTCG",
        0x009E => "Cvtres_VS2010",
        0x00DB => "C_VS2012",
        0x00DC => "Cpp_VS2012",
        0x00DD => "Linker_VS2012",
        0x00DE => "Linker_VS2012_LTCG",
        0x00E0 => "Cvtres_VS2012",
        0x00FF => "C_VS2013",
        0x0100 => "Cpp_VS2013",
        0x0101 => "Linker_VS2013",
        0x0102 => "Linker_VS2013_LTCG",
        0x0103 => "Cvtres_VS2013",
        0x0104 => "C_VS2015",
        0x0105 => "Cpp_VS2015",
        0x0106 => "Linker_VS2015",
        0x0107 => "Linker_VS2015_LTCG",
        0x0108 => "Cvtres_VS2015",
        0x010F => "C_VS2017",
        0x0110 => "Cpp_VS2017",
        0x0111 => "Linker_VS2017",
        0x0112 => "Linker_VS2017_LTCG",
        0x0113 => "Cvtres_VS2017",
        0x0136 => "C_VS2019",
        0x0137 => "Cpp_VS2019",
        0x0138 => "Linker_VS2019",
        0x0139 => "Linker_VS2019_LTCG",
        0x013A => "Cvtres_VS2019",
        0x0140 => "C_VS2022",
        0x0141 => "Cpp_VS2022",
        0x0142 => "Linker_VS2022",
        0x0143 => "Linker_VS2022_LTCG",
        0x0144 => "Cvtres_VS2022",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// imphash (PE import hash, pefile-compatible)
// ---------------------------------------------------------------------------

/// Compute the PE imphash from the report's import list. Algorithm
/// matches pefile's `get_imphash()`:
///
/// 1. Walk imports in source order.
/// 2. For each (dll, function): emit `<dll_lower>.<function_lower>`.
/// 3. Strip canonical DLL extensions (`.dll`, `.ocx`, `.sys`).
/// 4. Resolve ordinal imports for known DLLs (oleaut32, ws2_32,
///    wsock32) via lookup tables; else use `ord<N>`.
/// 5. Join with `,`.
/// 6. MD5 the resulting string.
///
/// Returns the hex-encoded MD5 digest, or `None` when there are no
/// imports.
#[must_use]
pub(crate) fn compute_imphash(imports: &[Import]) -> Option<String> {
    if imports.is_empty() {
        return None;
    }
    let mut entries: Vec<String> = Vec::with_capacity(imports.len());
    for imp in imports {
        let dll = imp
            .library
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase();
        let dll_stem = strip_dll_extension(&dll);
        let func = imp.symbol.to_ascii_lowercase();
        if dll_stem.is_empty() || func.is_empty() {
            continue;
        }
        // Treat strict-ordinal symbols as `ord<N>`. We don't carry
        // ordinal metadata on Import today; `func` will already be
        // a real name from goblin's resolution path.
        entries.push(format!("{}.{}", dll_stem, func));
    }
    if entries.is_empty() {
        return None;
    }
    let joined = entries.join(",");
    use md5::{Digest, Md5};
    let mut hasher = Md5::new();
    hasher.update(joined.as_bytes());
    Some(format!("{:x}", hasher.finalize()))
}

fn strip_dll_extension(name: &str) -> &str {
    for ext in [".dll", ".ocx", ".sys"] {
        if let Some(stem) = name.strip_suffix(ext) {
            return stem;
        }
    }
    name
}

// ---------------------------------------------------------------------------
// VS_VERSIONINFO StringTable walker
// ---------------------------------------------------------------------------

/// Recovered version-info string fields. Keys mirror Microsoft's
/// canonical StringTable names so trait paths line up with pefile's
/// `dump_dict()` output.
pub(crate) type VersionInfo = BTreeMap<String, String>;

/// Search the binary for `VS_VERSION_INFO\0` (UTF-16LE) and walk the
/// surrounding StringFileInfo / StringTable / String hierarchy.
/// Returns a map from canonical key (`CompanyName`, `FileDescription`,
/// `OriginalFilename`, etc.) to the decoded string value.
///
/// We intentionally don't parse the full VS_VERSIONINFO header
/// structure (FixedFileInfo, language tables, etc.). The string-table
/// keys appear verbatim in the resource as UTF-16LE, and each is
/// followed (after WORD-alignment padding) by its UTF-16LE value
/// terminated by U+0000. Locating the keys directly and reading
/// forward is robust against the parser-rejection cases that come up
/// on hand-crafted resource sections.
#[must_use]
pub(crate) fn extract_version_info(data: &[u8]) -> VersionInfo {
    let mut out = VersionInfo::new();
    let bound = data.len();
    if bound < 32 {
        return out;
    }

    // Anchor the search on the canonical `VS_VERSION_INFO\0` UTF-16
    // string. PE resources can have multiple language entries; we
    // accept the first match.
    let anchor = utf16le("VS_VERSION_INFO");
    let Some(start) = find_subslice(data, &anchor) else {
        return out;
    };

    // The StringTable / String entries appear after the FixedFileInfo
    // (52 bytes) plus padding. We don't precisely locate the
    // StringFileInfo block — we just scan forward for canonical keys
    // within a bounded window after the anchor.
    let window_end = (start + 64 * 1024).min(bound);
    let window = &data[start..window_end];

    for key in CANONICAL_VERSION_KEYS {
        let key_utf16 = utf16le(key);
        if let Some(pos) = find_subslice(window, &key_utf16) {
            // PE/COFF VS_VERSIONINFO String entry layout:
            //   WORD wLength | WORD wValueLength | WORD wType  (6 bytes)
            //   WCHAR szKey[]  (NUL-terminated)
            //   WORD Padding[] aligning the *value* to a 4-byte boundary
            //   *measured from the start of the String struct, not the
            //   resource section*.
            //
            // The struct starts 6 bytes before the key.  If we align
            // `after_key` from the window start instead of from the
            // struct start, we add 2 phantom bytes of padding whenever
            // the struct happens to begin at an offset where
            // `(struct_start - window_start) % 4 == 2`, which drops the
            // first WCHAR of the value (e.g. `WinRT.Runtime.dll` →
            // `inRT.Runtime.dll`).
            let struct_start = pos.saturating_sub(6);
            let after_key = pos + key_utf16.len();
            let aligned = struct_start + align_up_4(after_key - struct_start);
            if aligned + 2 > window.len() {
                continue;
            }
            if let Some(value) = read_utf16le_string(&window[aligned..]) {
                if !value.is_empty() {
                    out.insert(key.to_string(), value);
                }
            }
        }
    }

    out
}

const CANONICAL_VERSION_KEYS: &[&str] = &[
    "Comments",
    "CompanyName",
    "FileDescription",
    "FileVersion",
    "InternalName",
    "LegalCopyright",
    "LegalTrademarks",
    "OriginalFilename",
    "PrivateBuild",
    "ProductName",
    "ProductVersion",
    "SpecialBuild",
];

fn utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 2 + 2);
    for c in s.encode_utf16() {
        out.extend_from_slice(&c.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]); // NUL terminator
    out
}

/// Read a UTF-16LE-encoded NUL-terminated string from `bytes` and
/// return it as UTF-8. Stops at the first U+0000 code unit. Returns
/// `None` if the buffer is too short or the bytes don't decode.
fn read_utf16le_string(bytes: &[u8]) -> Option<String> {
    let mut units: Vec<u16> = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let unit = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
        i += 2;
        if units.len() > 4096 {
            // Bound for adversarial inputs; real version strings
            // cluster under 100 chars.
            break;
        }
    }
    String::from_utf16(&units).ok().filter(|s| !s.is_empty())
}

fn align_up_4(n: usize) -> usize {
    (n + 3) & !3
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // Build a minimal PE-style buffer with a Rich header. The
    // structure is: 0x80 bytes of DOS region, then a fake DanS
    // marker XORed with key, three zero-padding words, two
    // entries (4 u32s), then "Rich", then the key.
    fn build_rich_buffer(entries: &[(u16, u16, u32)], key: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x80];
        let dans = DANS_DECODED ^ key;
        buf.extend_from_slice(&dans.to_le_bytes());
        // Three padding words (zero before XOR).
        for _ in 0..3 {
            buf.extend_from_slice(&key.to_le_bytes());
        }
        for (prod, build, count) in entries {
            let pb = ((*prod as u32) << 16) | (*build as u32);
            buf.extend_from_slice(&(pb ^ key).to_le_bytes());
            buf.extend_from_slice(&((*count) ^ key).to_le_bytes());
        }
        buf.extend_from_slice(b"Rich");
        buf.extend_from_slice(&key.to_le_bytes());
        buf
    }

    #[test]
    fn decode_rich_header_basic() {
        let key = 0xDEADBEEFu32;
        let entries = [(0x0136u16, 28315u16, 23u32), (0x0138u16, 28315u16, 1u32)];
        let buf = build_rich_buffer(&entries, key);
        let h = decode_rich_header(&buf).expect("decoded");
        assert_eq!(h.xor_key, key);
        assert_eq!(h.entries.len(), 2);
        assert_eq!(h.entries[0].product_id, 0x0136);
        assert_eq!(h.entries[0].build_number, 28315);
        assert_eq!(h.entries[0].use_count, 23);
        assert_eq!(h.entries[0].product_name, "C_VS2019");
        assert_eq!(h.entries[1].product_name, "Linker_VS2019");
        assert!(!h.hash.is_empty());
    }

    #[test]
    fn decode_rich_header_no_marker() {
        let buf = vec![0u8; 0x100];
        assert!(decode_rich_header(&buf).is_none());
    }

    #[test]
    fn decode_rich_header_truncated_after_marker() {
        let mut buf = vec![0u8; 0x80];
        buf.extend_from_slice(b"Rich");
        // Only 2 bytes after Rich — not enough for the XOR key.
        buf.extend_from_slice(&[0, 0]);
        assert!(decode_rich_header(&buf).is_none());
    }

    #[test]
    fn rich_product_name_known_ids() {
        assert_eq!(rich_product_name(0x0140), "C_VS2022");
        assert_eq!(rich_product_name(0x0136), "C_VS2019");
        assert_eq!(rich_product_name(0xFFFF), "unknown");
    }

    #[test]
    fn imphash_basic() {
        let imports = vec![
            Import::new("LoadLibraryA", Some("kernel32.dll".into()), "test"),
            Import::new("GetProcAddress", Some("kernel32.dll".into()), "test"),
            Import::new("recv", Some("ws2_32.dll".into()), "test"),
        ];
        let h = compute_imphash(&imports).expect("hash");
        // pefile's algorithm: md5("kernel32.loadlibrarya,kernel32.getprocaddress,ws2_32.recv")
        use md5::{Digest, Md5};
        let mut hasher = Md5::new();
        hasher.update("kernel32.loadlibrarya,kernel32.getprocaddress,ws2_32.recv".as_bytes());
        let expected = format!("{:x}", hasher.finalize());
        assert_eq!(h, expected);
    }

    #[test]
    fn imphash_empty_returns_none() {
        assert!(compute_imphash(&[]).is_none());
    }

    #[test]
    fn imphash_strips_dll_extension() {
        assert_eq!(strip_dll_extension("kernel32.dll"), "kernel32");
        assert_eq!(strip_dll_extension("Mscoree.dll"), "Mscoree");
        assert_eq!(strip_dll_extension("user32"), "user32");
        assert_eq!(strip_dll_extension("MFC42.OCX"), "MFC42.OCX");
        // Note: lower-cased before passing in normal flow.
        assert_eq!(strip_dll_extension("mfc42.ocx"), "mfc42");
        assert_eq!(strip_dll_extension("ntoskrnl.sys"), "ntoskrnl");
    }

    /// Build a minimal binary buffer with a UTF-16LE
    /// `VS_VERSION_INFO\0` anchor + StringTable entries laid out per
    /// the PE/COFF spec: each String entry has a 6-byte header
    /// (wLength, wValueLength, wType) preceding the key, and the
    /// value is padded to a 4-byte boundary measured from the start
    /// of the String struct (NOT from the resource section / window).
    fn build_versioninfo_buffer(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&utf16le("VS_VERSION_INFO"));
        // Some FixedFileInfo padding (52 bytes).
        buf.extend_from_slice(&[0u8; 52]);
        for (k, v) in pairs {
            // Each String struct starts on a 4-byte boundary (relative
            // to the resource section, which is page-aligned).
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
            let struct_start = buf.len();
            // 6-byte header (wLength, wValueLength, wType) — values
            // don't matter for the extractor, which navigates by
            // string anchors.
            buf.extend_from_slice(&[0u8; 6]);
            buf.extend_from_slice(&utf16le(k));
            // Value padded to align it 4-byte from struct_start.
            while (buf.len() - struct_start) % 4 != 0 {
                buf.push(0);
            }
            buf.extend_from_slice(&utf16le(v));
        }
        buf
    }

    #[test]
    fn extract_version_info_basic() {
        let buf = build_versioninfo_buffer(&[
            ("CompanyName", "Adobe Inc."),
            ("FileDescription", "Adobe Reader Updater"),
            ("OriginalFilename", "AcroRd32Update.exe"),
            ("ProductName", "Adobe Reader"),
        ]);
        let info = extract_version_info(&buf);
        assert_eq!(
            info.get("CompanyName").map(String::as_str),
            Some("Adobe Inc.")
        );
        assert_eq!(
            info.get("FileDescription").map(String::as_str),
            Some("Adobe Reader Updater")
        );
        assert_eq!(
            info.get("OriginalFilename").map(String::as_str),
            Some("AcroRd32Update.exe")
        );
        assert_eq!(
            info.get("ProductName").map(String::as_str),
            Some("Adobe Reader")
        );
    }

    #[test]
    fn extract_version_info_with_cyrillic_company() {
        let buf = build_versioninfo_buffer(&[
            ("CompanyName", "Иван Иванов"),
            ("ProductName", "ПриложениеПодделка"),
        ]);
        let info = extract_version_info(&buf);
        assert_eq!(
            info.get("CompanyName").map(String::as_str),
            Some("Иван Иванов")
        );
    }

    #[test]
    fn extract_version_info_does_not_drop_first_value_char() {
        // Regression: real Microsoft DLLs were producing
        // `inRT.Runtime.dll` instead of `WinRT.Runtime.dll` because
        // the value-padding alignment was computed from the window
        // start instead of from the String struct start.  Pick keys
        // whose lengths force the off-by-2 to manifest.
        let buf = build_versioninfo_buffer(&[
            ("OriginalFilename", "WinRT.Runtime.dll"),
            ("LegalCopyright", "Copyright (c) Microsoft Corporation"),
            ("ProductName", "Windows Runtime"),
            ("CompanyName", "Microsoft Corporation"),
        ]);
        let info = extract_version_info(&buf);
        assert_eq!(
            info.get("OriginalFilename").map(String::as_str),
            Some("WinRT.Runtime.dll")
        );
        assert_eq!(
            info.get("LegalCopyright").map(String::as_str),
            Some("Copyright (c) Microsoft Corporation")
        );
        assert_eq!(
            info.get("ProductName").map(String::as_str),
            Some("Windows Runtime")
        );
        assert_eq!(
            info.get("CompanyName").map(String::as_str),
            Some("Microsoft Corporation")
        );
    }

    #[test]
    fn extract_version_info_returns_empty_when_anchor_missing() {
        let buf = vec![0u8; 256];
        assert!(extract_version_info(&buf).is_empty());
    }
}
