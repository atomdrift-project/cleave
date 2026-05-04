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
// PE TLS callbacks — Windows analog of ELF init_array
// ---------------------------------------------------------------------------

/// One TLS callback entry. TLS callbacks run before the binary's
/// `main()` and provide an attacker a hook into load-time execution
/// under a benign-looking PE. Modern compilers rarely emit callbacks
/// for ordinary applications; their *appearance* between releases of
/// an otherwise-stable binary is a tampering tell.
#[derive(Debug, Clone)]
pub(crate) struct TlsCallback {
    /// Virtual address of the callback function (as it appears in
    /// `dumpbin /TLS` / IDA — image-base-relative VA).
    pub addr: u64,
}

/// Parse the TLS Directory (data directory entry 9) and walk the
/// callback array. Returns `None` for non-PE input, missing TLS
/// directory, or empty callback list.
#[must_use]
pub(crate) fn extract_tls_callbacks(data: &[u8]) -> Option<Vec<TlsCallback>> {
    let pe = PeHeaders::parse(data)?;
    let tls_rva = pe.data_directory(9)?.0 as usize;
    if tls_rva == 0 {
        return None;
    }
    let tls_off = pe.rva_to_offset(tls_rva)?;
    // TLS Directory layout:
    //   PE32:  4*u32 (StartVA EndVA IndexVA CallbacksVA), 2*u32 trailers
    //   PE32+: 4*u64                                   , 2*u32 trailers
    let ptr_size = if pe.is_64 { 8 } else { 4 };
    let callbacks_va_off = tls_off.checked_add(ptr_size * 3)?;
    if callbacks_va_off + ptr_size > data.len() {
        return None;
    }
    let callbacks_va = if pe.is_64 {
        u64::from_le_bytes(
            data[callbacks_va_off..callbacks_va_off + 8]
                .try_into()
                .ok()?,
        )
    } else {
        u32::from_le_bytes(
            data[callbacks_va_off..callbacks_va_off + 4]
                .try_into()
                .ok()?,
        ) as u64
    };
    if callbacks_va == 0 {
        return None;
    }
    // CallbacksVA is image-base-relative. Subtract ImageBase to get RVA.
    let callbacks_rva = callbacks_va.checked_sub(pe.image_base)? as usize;
    let mut walk = pe.rva_to_offset(callbacks_rva)?;
    let mut out = Vec::new();
    for _ in 0..256 {
        if walk + ptr_size > data.len() {
            break;
        }
        let entry = if pe.is_64 {
            u64::from_le_bytes(data[walk..walk + 8].try_into().ok()?)
        } else {
            u32::from_le_bytes(data[walk..walk + 4].try_into().ok()?) as u64
        };
        if entry == 0 {
            break;
        }
        out.push(TlsCallback { addr: entry });
        walk += ptr_size;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Minimal PE header view used by TLS-callback / image-base / RVA
/// translation lookups. `pe_extractors` is byte-pattern-based by
/// design; this parser keeps that property.
pub(crate) struct PeHeaders<'a> {
    data: &'a [u8],
    pub is_64: bool,
    pub image_base: u64,
    data_dirs_off: usize,
    data_dirs_count: usize,
    sections_off: usize,
    sections_count: usize,
    section_entry_size: usize,
}

impl<'a> PeHeaders<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 0x40 || &data[..2] != b"MZ" {
            return None;
        }
        let e_lfanew = u32::from_le_bytes(data[0x3c..0x40].try_into().ok()?) as usize;
        if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
            return None;
        }
        let coff_off = e_lfanew + 4;
        let num_sections =
            u16::from_le_bytes(data[coff_off + 2..coff_off + 4].try_into().ok()?) as usize;
        let opt_size =
            u16::from_le_bytes(data[coff_off + 16..coff_off + 18].try_into().ok()?) as usize;
        let opt_off = coff_off + 20;
        if opt_off + 2 > data.len() {
            return None;
        }
        let magic = u16::from_le_bytes(data[opt_off..opt_off + 2].try_into().ok()?);
        let (is_64, image_base, data_dirs_off, num_dirs_off) = match magic {
            0x10b => {
                if opt_off + 96 > data.len() {
                    return None;
                }
                let ib =
                    u32::from_le_bytes(data[opt_off + 28..opt_off + 32].try_into().ok()?) as u64;
                (false, ib, opt_off + 96, opt_off + 92)
            }
            0x20b => {
                if opt_off + 112 > data.len() {
                    return None;
                }
                let ib = u64::from_le_bytes(data[opt_off + 24..opt_off + 32].try_into().ok()?);
                (true, ib, opt_off + 112, opt_off + 108)
            }
            _ => return None,
        };
        let data_dirs_count =
            u32::from_le_bytes(data[num_dirs_off..num_dirs_off + 4].try_into().ok()?) as usize;
        let sections_off = opt_off + opt_size;
        Some(Self {
            data,
            is_64,
            image_base,
            data_dirs_off,
            data_dirs_count,
            sections_off,
            sections_count: num_sections,
            section_entry_size: 40,
        })
    }

    /// Return `(rva, size)` for data directory `idx`.
    pub(crate) fn data_directory(&self, idx: usize) -> Option<(u32, u32)> {
        if idx >= self.data_dirs_count {
            return None;
        }
        let off = self.data_dirs_off + idx * 8;
        if off + 8 > self.data.len() {
            return None;
        }
        let rva = u32::from_le_bytes(self.data[off..off + 4].try_into().ok()?);
        let size = u32::from_le_bytes(self.data[off + 4..off + 8].try_into().ok()?);
        Some((rva, size))
    }

    /// Translate a virtual RVA to a file offset by walking the section
    /// table. Returns `None` if no section covers the RVA.
    pub(crate) fn rva_to_offset(&self, rva: usize) -> Option<usize> {
        for i in 0..self.sections_count {
            let off = self.sections_off + i * self.section_entry_size;
            if off + 40 > self.data.len() {
                return None;
            }
            let vsize = u32::from_le_bytes(self.data[off + 8..off + 12].try_into().ok()?) as usize;
            let vaddr = u32::from_le_bytes(self.data[off + 12..off + 16].try_into().ok()?) as usize;
            let rsize = u32::from_le_bytes(self.data[off + 16..off + 20].try_into().ok()?) as usize;
            let rdata = u32::from_le_bytes(self.data[off + 20..off + 24].try_into().ok()?) as usize;
            let coverage = vsize.max(rsize);
            if rva >= vaddr && rva < vaddr + coverage {
                return Some(rdata + (rva - vaddr));
            }
        }
        None
    }

    /// Walk all sections returning `(name, virtual_size, raw_size)` for
    /// each. Used by callers needing per-section size analysis.
    pub(crate) fn sections(&self) -> Vec<(String, u32, u32)> {
        let mut out = Vec::with_capacity(self.sections_count);
        for i in 0..self.sections_count {
            let off = self.sections_off + i * self.section_entry_size;
            if off + 40 > self.data.len() {
                break;
            }
            let name_bytes = &self.data[off..off + 8];
            let nul = name_bytes.iter().position(|&b| b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..nul]).into_owned();
            let Ok(vs) = self.data[off + 8..off + 12].try_into() else {
                continue;
            };
            let Ok(rs) = self.data[off + 16..off + 20].try_into() else {
                continue;
            };
            let vsize = u32::from_le_bytes(vs);
            let rsize = u32::from_le_bytes(rs);
            out.push((name, vsize, rsize));
        }
        out
    }
}

// ---------------------------------------------------------------------------
// PE per-section virtual_size vs raw_size — packing / inflation signal
// ---------------------------------------------------------------------------

/// Sections whose `virtual_size` substantially exceeds their on-disk
/// `raw_size`. Returns the section name + ratio for any section with
/// `vsize > rsize * 4` and `rsize > 0` (excluding BSS-style sections
/// where rsize is legitimately zero). Large inflation indicates a
/// runtime-decompressed payload — the classic packer fingerprint.
#[must_use]
pub(crate) fn extract_inflated_sections(data: &[u8]) -> Option<Vec<(String, f64)>> {
    let pe = PeHeaders::parse(data)?;
    let mut out = Vec::new();
    for (name, vsize, rsize) in pe.sections() {
        if rsize == 0 || vsize <= rsize.saturating_mul(4) {
            continue;
        }
        let ratio = (vsize as f64) / (rsize as f64);
        out.push((name, ratio));
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// PE Resource Directory TimeDateStamp
// ---------------------------------------------------------------------------

/// Timestamp embedded in the top-level IMAGE_RESOURCE_DIRECTORY,
/// independent of the PE COFF header's TimeDateStamp. Set by the
/// resource compiler at link time; often left untouched across
/// rebuilds, so a *change* between releases of an otherwise-stable
/// binary is a tampering tell. Returns 0 / None when unset or the
/// resource directory is absent.
#[must_use]
pub(crate) fn extract_resource_timestamp(data: &[u8]) -> Option<u32> {
    let pe = PeHeaders::parse(data)?;
    let rsrc_rva = pe.data_directory(2)?.0 as usize;
    if rsrc_rva == 0 {
        return None;
    }
    let off = pe.rva_to_offset(rsrc_rva)?;
    if off + 8 > data.len() {
        return None;
    }
    let ts = u32::from_le_bytes(data[off + 4..off + 8].try_into().ok()?);
    if ts == 0 {
        None
    } else {
        Some(ts)
    }
}

// ---------------------------------------------------------------------------
// PE Debug Directory entries
// ---------------------------------------------------------------------------

/// One IMAGE_DEBUG_DIRECTORY entry. Each carries its own timestamp
/// distinct from the PE COFF TimeDateStamp; PDB info is the most
/// common type but CodeView (1), POGO (13), MPX, REPRO etc. each
/// surface separately. Drift signals build-pipeline change.
#[derive(Debug, Clone)]
pub(crate) struct DebugDirEntry {
    pub timestamp: u32,
    pub type_id: u32,
    pub size: u32,
    /// Canonical short name for `type_id`, e.g. "codeview", "pogo",
    /// "vc_feature", "ex_dllchars", "repro". `None` for unrecognized
    /// types (the caller still surfaces `type_id` for new variants).
    pub type_name: Option<&'static str>,
}

/// Parse all IMAGE_DEBUG_DIRECTORY entries (DataDirectory[6]). Each
/// entry is 28 bytes. Returns `None` for non-PE input or an empty
/// directory.
#[must_use]
pub(crate) fn extract_debug_directory(data: &[u8]) -> Option<Vec<DebugDirEntry>> {
    let pe = PeHeaders::parse(data)?;
    let (rva, size) = pe.data_directory(6)?;
    if rva == 0 || size < 28 {
        return None;
    }
    let off = pe.rva_to_offset(rva as usize)?;
    let n = (size as usize) / 28;
    let mut out = Vec::with_capacity(n);
    for i in 0..n.min(64) {
        let entry_off = off + i * 28;
        if entry_off + 28 > data.len() {
            break;
        }
        let timestamp = u32::from_le_bytes(data[entry_off + 4..entry_off + 8].try_into().ok()?);
        let type_id = u32::from_le_bytes(data[entry_off + 12..entry_off + 16].try_into().ok()?);
        let size = u32::from_le_bytes(data[entry_off + 16..entry_off + 20].try_into().ok()?);
        out.push(DebugDirEntry {
            timestamp,
            type_id,
            size,
            type_name: debug_type_name(type_id),
        });
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// IMAGE_DEBUG_TYPE_* canonical short names. Returns `None` for
/// unrecognized types so callers can fall back to `type_id`.
fn debug_type_name(id: u32) -> Option<&'static str> {
    Some(match id {
        1 => "coff",
        2 => "codeview",
        3 => "fpo",
        4 => "misc",
        5 => "exception",
        6 => "fixup",
        7 => "omap_to_src",
        8 => "omap_from_src",
        9 => "borland",
        10 => "reserved10",
        11 => "clsid",
        12 => "vc_feature",
        13 => "pogo",
        14 => "iltcg",
        15 => "mpx",
        16 => "repro",
        17 => "ex_dllcharacteristics",
        20 => "perfmap",
        _ => return None,
    })
}

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
        let dll = imp.library.as_deref().unwrap_or("").to_ascii_lowercase();
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
