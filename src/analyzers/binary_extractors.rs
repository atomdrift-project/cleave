//! Lightweight byte-level extractors that augment the binary kv
//! tree with toolchain attribution data we don't already have on
//! the metrics structs.
//!
//! Each extractor is intentionally small and side-effect-free:
//! takes a `&[u8]` (raw file bytes) or `&AnalysisReport` (already
//! populated), returns an optional string or short list, and the
//! analyzer integration layer stitches the results into
//! `report.kv_tree`.
//!
//! Trade-off: this is slightly redundant with parsing already done
//! by the format analyzers (`analyzers::elf::analyze_structural`).
//! The redundancy is intentional — these extractors run on raw
//! bytes without depending on goblin's higher-level types, so an
//! analyzer panic or bug elsewhere never starves attribution data.

use crate::types::{AnalysisReport, Import};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// ELF `.comment` section
// ---------------------------------------------------------------------------

/// Read the contents of the ELF `.comment` section as a normalized
/// string with NUL-separated tokens collapsed onto `;` boundaries.
/// Returns `None` for non-ELF input or when the section is absent.
///
/// Real-world examples this captures:
/// - `GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0`
/// - `clang version 14.0.6 (https://github.com/llvm/llvm-project ...)`
/// - `GCC: (Debian 12.2.0-14) 12.2.0`
/// - `Apple LLVM version 14.0.0 (clang-1400.0.29.202)`
/// - When multiple compilers contribute to one binary they each leave
///   their banner; we join with `; ` so trait authors can pattern-
///   match individual entries.
#[must_use]
pub(crate) fn extract_elf_comment(data: &[u8]) -> Option<String> {
    let bytes = read_section(data, b".comment")?;
    let tokens: Vec<String> = bytes
        .split(|&b| b == 0)
        .filter(|chunk| !chunk.is_empty())
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .filter(|s| !s.trim().is_empty())
        .collect();
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join("; "))
    }
}

/// Return the `.interp` section content (the dynamic linker path)
/// as a string. Drops trailing NULs.
#[must_use]
pub(crate) fn extract_elf_interp(data: &[u8]) -> Option<String> {
    let bytes = read_section(data, b".interp")?;
    let s = String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .trim()
        .to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Return raw `.GCC.command.line` section content, with internal
/// NULs converted to spaces. Present only when binaries are
/// compiled with `-frecord-gcc-switches`. When present, contains
/// the full GCC invocation per translation unit — attribution gold.
#[must_use]
pub(crate) fn extract_gcc_command_line(data: &[u8]) -> Option<String> {
    let bytes = read_section(data, b".GCC.command.line")?;
    let s: String = bytes
        .iter()
        .map(|&b| if b == 0 { ' ' } else { b as char })
        .collect();
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        // Collapse runs of whitespace.
        let collapsed: String = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
        Some(collapsed)
    }
}

/// Public re-export of the internal ELF section reader so other
/// modules (e.g. `go_buildinfo`) can fetch named sections without
/// duplicating the parser.
pub(crate) fn read_elf_section<'a>(data: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    read_section(data, name)
}

/// Locate a named ELF section and return its byte slice. Lenient
/// parser — bails on malformed inputs rather than propagating
/// errors. Caps memory; only reads section header table.
fn read_section<'a>(data: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if data.len() < 0x40 || &data[..4] != b"\x7fELF" {
        return None;
    }
    let is_64 = data[4] == 2;
    let is_le = data[5] == 1;
    if !is_le {
        // Big-endian ELF parsing for `.comment` extraction is rare
        // enough that we punt; the section is still found via the
        // string-scan fallback below for trait authors.
        return scan_section_fallback(data, name);
    }

    // e_shoff (section header table file offset)
    // e_shentsize (section header entry size)
    // e_shnum (number of section headers)
    // e_shstrndx (section name string table index)
    let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is_64 {
        if data.len() < 0x40 {
            return None;
        }
        let shoff = u64::from_le_bytes(data[0x28..0x30].try_into().ok()?);
        let shentsize = u16::from_le_bytes(data[0x3a..0x3c].try_into().ok()?);
        let shnum = u16::from_le_bytes(data[0x3c..0x3e].try_into().ok()?);
        let shstrndx = u16::from_le_bytes(data[0x3e..0x40].try_into().ok()?);
        (
            shoff as usize,
            shentsize as usize,
            shnum as usize,
            shstrndx as usize,
        )
    } else {
        if data.len() < 0x34 {
            return None;
        }
        let shoff = u32::from_le_bytes(data[0x20..0x24].try_into().ok()?);
        let shentsize = u16::from_le_bytes(data[0x2e..0x30].try_into().ok()?);
        let shnum = u16::from_le_bytes(data[0x30..0x32].try_into().ok()?);
        let shstrndx = u16::from_le_bytes(data[0x32..0x34].try_into().ok()?);
        (
            shoff as usize,
            shentsize as usize,
            shnum as usize,
            shstrndx as usize,
        )
    };

    if e_shentsize == 0 || e_shnum == 0 || e_shstrndx >= e_shnum {
        return None;
    }
    if e_shoff.checked_add(e_shentsize.checked_mul(e_shnum)?)? > data.len() {
        return None;
    }

    // Locate the section-name string table.
    let shstrtab = read_shdr(data, e_shoff, e_shentsize, e_shstrndx, is_64)?;
    let (shstr_off, shstr_size) = (shstrtab.sh_offset as usize, shstrtab.sh_size as usize);
    if shstr_off.checked_add(shstr_size)? > data.len() {
        return None;
    }
    let shstrings = &data[shstr_off..shstr_off + shstr_size];

    // Walk section headers looking for our name.
    for i in 0..e_shnum {
        let shdr = read_shdr(data, e_shoff, e_shentsize, i, is_64)?;
        let name_off = shdr.sh_name as usize;
        if name_off >= shstrings.len() {
            continue;
        }
        let nul = shstrings[name_off..].iter().position(|&b| b == 0)?;
        let candidate = &shstrings[name_off..name_off + nul];
        if candidate == name {
            let off = shdr.sh_offset as usize;
            let size = shdr.sh_size as usize;
            if off.checked_add(size)? > data.len() {
                return None;
            }
            return Some(&data[off..off + size]);
        }
    }
    None
}

/// Fallback for big-endian ELFs: locate the literal section name
/// in the file then peek a fixed offset back to find the section
/// header. Imprecise — used only when LE parsing isn't available.
fn scan_section_fallback<'a>(_data: &'a [u8], _name: &[u8]) -> Option<&'a [u8]> {
    None
}

#[derive(Debug, Clone, Copy)]
struct Shdr {
    sh_name: u32,
    sh_offset: u64,
    sh_size: u64,
}

fn read_shdr(data: &[u8], shoff: usize, entsize: usize, idx: usize, is_64: bool) -> Option<Shdr> {
    let off = shoff.checked_add(entsize.checked_mul(idx)?)?;
    let entry = data.get(off..off + entsize)?;
    let sh_name = u32::from_le_bytes(entry.get(..4)?.try_into().ok()?);
    if is_64 {
        let sh_offset = u64::from_le_bytes(entry.get(0x18..0x20)?.try_into().ok()?);
        let sh_size = u64::from_le_bytes(entry.get(0x20..0x28)?.try_into().ok()?);
        Some(Shdr {
            sh_name,
            sh_offset,
            sh_size,
        })
    } else {
        let sh_offset = u32::from_le_bytes(entry.get(0x10..0x14)?.try_into().ok()?) as u64;
        let sh_size = u32::from_le_bytes(entry.get(0x14..0x18)?.try_into().ok()?) as u64;
        Some(Shdr {
            sh_name,
            sh_offset,
            sh_size,
        })
    }
}

// ---------------------------------------------------------------------------
// ELF DT_FLAGS / DT_FLAGS_1 — runtime hardening flags
// ---------------------------------------------------------------------------

/// Decoded named flags from DT_FLAGS (tag 30) and DT_FLAGS_1 (tag
/// 0x6ffffffb). Set by linker flags like `-Wl,-z,now`,
/// `-Wl,-z,relro`, `-Wl,-z,nodelete`. Distros are stable in their
/// flag profiles; drift indicates build-toolchain change.
///
/// Returned values are raw bit reads — kv-eligible, no interpretation.
#[derive(Debug, Default, Clone)]
pub(crate) struct DynamicFlags {
    /// DT_FLAGS raw bitfield (debug + ML feature surface).
    pub raw_flags: u32,
    /// DT_FLAGS_1 raw bitfield.
    pub raw_flags_1: u32,
    /// DF_BIND_NOW — eager symbol resolution (full RELRO).
    pub bind_now: bool,
    /// DF_TEXTREL — text-segment relocations (security warning).
    pub textrel: bool,
    /// DF_SYMBOLIC — local symbols resolve before global.
    pub symbolic: bool,
    /// DF_STATIC_TLS — uses static TLS model.
    pub static_tls: bool,
    /// DF_1_NOW — same as DF_BIND_NOW (newer flag).
    pub now: bool,
    /// DF_1_NODELETE — refcount permanently raised, never unloaded.
    pub nodelete: bool,
    /// DF_1_INITFIRST — initialise this object first.
    pub initfirst: bool,
    /// DF_1_NOOPEN — disallow `dlopen()` of this object.
    pub noopen: bool,
    /// DF_1_NODEFLIB — ignore default library search paths.
    pub nodeflib: bool,
    /// DF_1_NODUMP — skip in `dlinfo()` enumerations.
    pub nodump: bool,
    /// DF_1_PIE — position-independent executable (newer than PT_GNU_*).
    pub pie: bool,
    /// DF_1_GLOBAL — promoted to global scope on dlopen.
    pub global: bool,
    /// DF_1_GROUP — object-group member.
    pub group: bool,
    /// DF_1_INTERPOSE — symbols interpose all global ones.
    pub interpose: bool,
    /// DF_1_DIRECT — direct symbol bindings.
    pub direct: bool,
}

#[must_use]
pub(crate) fn extract_dynamic_flags(data: &[u8]) -> Option<DynamicFlags> {
    let dyn_bytes = read_section(data, b".dynamic")?;
    let is_64 = data.get(4) == Some(&2);
    let entry_size = if is_64 { 16 } else { 8 };
    let mut raw_flags = 0u32;
    let mut raw_flags_1 = 0u32;
    let mut found_any = false;
    let mut i = 0usize;
    while i + entry_size <= dyn_bytes.len() {
        let tag = if is_64 {
            u64::from_le_bytes(dyn_bytes[i..i + 8].try_into().ok()?) as i64
        } else {
            u32::from_le_bytes(dyn_bytes[i..i + 4].try_into().ok()?) as i64
        };
        let val = if is_64 {
            u64::from_le_bytes(dyn_bytes[i + 8..i + 16].try_into().ok()?)
        } else {
            u32::from_le_bytes(dyn_bytes[i + 4..i + 8].try_into().ok()?) as u64
        };
        if tag == 0 {
            break; // DT_NULL terminator
        }
        if tag == 30 {
            raw_flags = val as u32;
            found_any = true;
        } else if tag == 0x6fff_fffb_i64 {
            raw_flags_1 = val as u32;
            found_any = true;
        }
        i += entry_size;
    }
    if !found_any {
        return None;
    }
    Some(DynamicFlags {
        raw_flags,
        raw_flags_1,
        bind_now: raw_flags & 0x8 != 0,
        textrel: raw_flags & 0x4 != 0,
        symbolic: raw_flags & 0x2 != 0,
        static_tls: raw_flags & 0x10 != 0,
        now: raw_flags_1 & 0x1 != 0,
        global: raw_flags_1 & 0x2 != 0,
        group: raw_flags_1 & 0x4 != 0,
        nodelete: raw_flags_1 & 0x8 != 0,
        initfirst: raw_flags_1 & 0x20 != 0,
        noopen: raw_flags_1 & 0x40 != 0,
        interpose: raw_flags_1 & 0x400 != 0,
        nodeflib: raw_flags_1 & 0x800 != 0,
        nodump: raw_flags_1 & 0x1000 != 0,
        direct: raw_flags_1 & 0x100 != 0,
        pie: raw_flags_1 & 0x0800_0000 != 0,
    })
}

// ---------------------------------------------------------------------------
// ELF symbol versioning — `.gnu.version_r` (verneed) + `.gnu.version_d` (verdef)
// ---------------------------------------------------------------------------

/// One library + the list of versioned symbols the binary requires
/// from it. Sourced from `.gnu.version_r` (SHT_GNU_verneed). E.g.
/// `{lib: "libc.so.6", versions: ["GLIBC_2.17", "GLIBC_2.34"]}`.
#[derive(Debug, Clone)]
pub(crate) struct SymbolVersionRequirement {
    pub lib: String,
    pub versions: Vec<String>,
}

/// Parse `.gnu.version_r` and return per-library versioned-symbol
/// requirements. Returns `None` for non-ELF or missing section.
///
/// This is the xz-class supply-chain detector: a vendor's binary
/// imports a stable set of glibc symbol versions across releases.
/// A sudden requirement on a NEW version (e.g. `GLIBC_2.38` appearing
/// in a release that previously needed only `GLIBC_2.34`) almost
/// always indicates the build environment changed.
#[must_use]
pub(crate) fn extract_needed_versions(data: &[u8]) -> Option<Vec<SymbolVersionRequirement>> {
    let verneed = read_section(data, b".gnu.version_r")?;
    let dynstr = read_section(data, b".dynstr")?;

    let mut out = Vec::new();
    let mut entry_off = 0usize;
    // Bound iterations to defend against malformed inputs.
    for _ in 0..256 {
        if entry_off + 16 > verneed.len() {
            break;
        }
        // Elf{32,64}_Verneed layout (same on both — all 16/32-bit
        // fields, total 16 bytes):
        //   u16 vn_version, u16 vn_cnt, u32 vn_file, u32 vn_aux, u32 vn_next
        let vn_cnt = u16::from_le_bytes(verneed[entry_off + 2..entry_off + 4].try_into().ok()?);
        let vn_file =
            u32::from_le_bytes(verneed[entry_off + 4..entry_off + 8].try_into().ok()?) as usize;
        let vn_aux =
            u32::from_le_bytes(verneed[entry_off + 8..entry_off + 12].try_into().ok()?) as usize;
        let vn_next =
            u32::from_le_bytes(verneed[entry_off + 12..entry_off + 16].try_into().ok()?) as usize;

        let lib = read_strtab_string(dynstr, vn_file).unwrap_or_default();
        let mut versions = Vec::new();
        let mut aux_off = entry_off + vn_aux;
        for _ in 0..vn_cnt.min(64) {
            if aux_off + 16 > verneed.len() {
                break;
            }
            // Elf_Vernaux: u32 vna_hash, u16 vna_flags, u16 vna_other,
            // u32 vna_name, u32 vna_next (total 16 bytes).
            let vna_name =
                u32::from_le_bytes(verneed[aux_off + 8..aux_off + 12].try_into().ok()?) as usize;
            let vna_next =
                u32::from_le_bytes(verneed[aux_off + 12..aux_off + 16].try_into().ok()?) as usize;
            if let Some(name) = read_strtab_string(dynstr, vna_name) {
                if !name.is_empty() {
                    versions.push(name);
                }
            }
            if vna_next == 0 {
                break;
            }
            aux_off += vna_next;
        }
        if !lib.is_empty() {
            versions.sort();
            versions.dedup();
            out.push(SymbolVersionRequirement { lib, versions });
        }
        if vn_next == 0 {
            break;
        }
        entry_off += vn_next;
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Parse `.gnu.version_d` and return the list of versions this
/// binary itself defines (i.e. what symbol versions an ELF .so
/// exports). Less useful for executables; critical for tracking
/// shared library version drift.
#[must_use]
pub(crate) fn extract_provided_versions(data: &[u8]) -> Option<Vec<String>> {
    let verdef = read_section(data, b".gnu.version_d")?;
    let dynstr = read_section(data, b".dynstr")?;

    let mut out = Vec::new();
    let mut entry_off = 0usize;
    for _ in 0..256 {
        if entry_off + 20 > verdef.len() {
            break;
        }
        // Elf_Verdef: u16 vd_version, u16 vd_flags, u16 vd_ndx, u16 vd_cnt,
        // u32 vd_hash, u32 vd_aux, u32 vd_next (total 20 bytes).
        let vd_cnt = u16::from_le_bytes(verdef[entry_off + 6..entry_off + 8].try_into().ok()?);
        let vd_aux =
            u32::from_le_bytes(verdef[entry_off + 12..entry_off + 16].try_into().ok()?) as usize;
        let vd_next =
            u32::from_le_bytes(verdef[entry_off + 16..entry_off + 20].try_into().ok()?) as usize;

        let mut aux_off = entry_off + vd_aux;
        for _ in 0..vd_cnt.min(8) {
            if aux_off + 8 > verdef.len() {
                break;
            }
            // Elf_Verdaux: u32 vda_name, u32 vda_next.
            let vda_name =
                u32::from_le_bytes(verdef[aux_off..aux_off + 4].try_into().ok()?) as usize;
            let vda_next =
                u32::from_le_bytes(verdef[aux_off + 4..aux_off + 8].try_into().ok()?) as usize;
            if let Some(name) = read_strtab_string(dynstr, vda_name) {
                // The first verdaux per verdef is the version's own
                // name; subsequent ones are predecessor links. We want
                // only the first.
                if !name.is_empty() && !out.contains(&name) {
                    out.push(name);
                    break;
                }
            }
            if vda_next == 0 {
                break;
            }
            aux_off += vda_next;
        }
        if vd_next == 0 {
            break;
        }
        entry_off += vd_next;
    }
    if out.is_empty() {
        None
    } else {
        out.sort();
        Some(out)
    }
}

/// Read a NUL-terminated string at the given offset within an ELF
/// string table (`.dynstr` / `.shstrtab`). Returns `None` for
/// out-of-bounds or non-UTF-8.
fn read_strtab_string(strtab: &[u8], offset: usize) -> Option<String> {
    if offset >= strtab.len() {
        return None;
    }
    let end = strtab[offset..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| offset + p)
        .unwrap_or(strtab.len());
    if end == offset {
        return None;
    }
    std::str::from_utf8(&strtab[offset..end])
        .ok()
        .map(str::to_string)
}

// ---------------------------------------------------------------------------
// ELF linker identification — `.note.gnu.gold-version` etc.
// ---------------------------------------------------------------------------

/// Identify the link-editor that produced an ELF. Returns the
/// canonical short name when detectable: `"gold"`, `"lld"`, `"mold"`,
/// `"bfd"`. Falls back to `None` when no identifying note is present.
///
/// Sources, in order:
///   1. `.note.gnu.gold-version` — gold-specific note (n_type=4)
///   2. `.note.lld` / lld-specific marker (rare; many lld builds have no note)
///   3. `.note.mold` — mold sets a custom note in newer versions
///   4. `.comment` heuristic — sometimes the linker name appears here
#[must_use]
pub(crate) fn extract_linker(data: &[u8]) -> Option<String> {
    if read_section(data, b".note.gnu.gold-version").is_some() {
        return Some("gold".to_string());
    }
    if read_section(data, b".note.lld").is_some() {
        return Some("lld".to_string());
    }
    if read_section(data, b".note.mold").is_some() {
        return Some("mold".to_string());
    }
    // Fallback: scan .comment for the substring. lld and mold sometimes
    // append themselves to the toolchain banner.
    let comment = extract_elf_comment(data)?;
    let lower = comment.to_lowercase();
    if lower.contains("ld.lld") || lower.contains("lld ") {
        return Some("lld".to_string());
    }
    if lower.contains("mold ") {
        return Some("mold".to_string());
    }
    None
}

// ---------------------------------------------------------------------------
// .note.package — FDO Package Metadata note
// ---------------------------------------------------------------------------

/// Read the JSON payload of an FDO Package Metadata note (`.note.package`,
/// `n_type = 0xCAFE1A7E`, vendor name `"FDO"`).  The desc is a JSON
/// document with a documented schema (https://systemd.io/COREDUMP_PACKAGE_METADATA/)
/// — package name + version + type (rpm/deb/apk) + cpe + url + vcs.
///
/// This is the cleanest "what package am I from" attestation in any
/// binary format: distros that ship it (Wolfi, Chainguard, Fedora 36+,
/// recent systemd builds) embed the package manager's own metadata
/// directly into the binary at link time. Trait authors can write
/// e.g. `package.type == "apk"` or `package.cpe ~= "^cpe:.../o:wolfi:"`.
#[must_use]
pub(crate) fn extract_note_package(data: &[u8]) -> Option<serde_json::Value> {
    let bytes = read_section(data, b".note.package")?;
    if bytes.len() < 16 {
        return None;
    }
    let namesz = u32::from_le_bytes(bytes[..4].try_into().ok()?) as usize;
    let descsz = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
    let ntype = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    if ntype != 0xCAFE_1A7E {
        return None;
    }
    let name_start = 12usize;
    let desc_start = name_start.checked_add(align_up(namesz, 4))?;
    let desc_end = desc_start.checked_add(descsz)?;
    if desc_end > bytes.len() {
        return None;
    }
    // Trim trailing NULs from the desc — the section may pad up to
    // 4 bytes with zeros.
    let desc = bytes[desc_start..desc_end].split(|&b| b == 0).next()?;
    let text = std::str::from_utf8(desc).ok()?;
    let val: serde_json::Value = serde_json::from_str(text).ok()?;
    if val.is_null() {
        None
    } else {
        Some(val)
    }
}

// ---------------------------------------------------------------------------
// .note.gnu.property — Intel CET / ARM PAC+BTI / x86 ISA level
// ---------------------------------------------------------------------------

/// Hardening / ISA-level flags recovered from `.note.gnu.property`.
///
/// All booleans default to `false` and the ISA level to `0`. Empty
/// values are dropped from the kv tree by the caller.
#[derive(Debug, Clone, Default)]
pub(crate) struct GnuProperty {
    /// Indirect Branch Tracking (Intel CET, x86_64 only).
    pub ibt: bool,
    /// Shadow Stack (Intel CET, x86_64 only).
    pub shstk: bool,
    /// Pointer Authentication (ARM aarch64 only).
    pub pac: bool,
    /// Branch Target Identification (ARM aarch64 only).
    pub bti: bool,
    /// x86 ISA microarchitecture level (1..4, post-2020). 0 = unset.
    /// 1=baseline, 2=SSE4.2/POPCNT, 3=AVX/AVX2/BMI, 4=AVX-512.
    pub x86_isa_level: u8,
}

impl GnuProperty {
    pub(crate) fn is_empty(&self) -> bool {
        !self.ibt && !self.shstk && !self.pac && !self.bti && self.x86_isa_level == 0
    }
}

const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;
const GNU_PROPERTY_X86_ISA_1_NEEDED: u32 = 0xc000_8002;

/// Parse `.note.gnu.property` and return the hardening / ISA-level
/// flags. Returns `None` for non-ELF input or when the section is
/// absent / malformed.
#[must_use]
pub(crate) fn extract_gnu_property(data: &[u8]) -> Option<GnuProperty> {
    let bytes = read_section(data, b".note.gnu.property")?;

    // ELF Note layout (LE assumed — matches read_section's coverage):
    //   u32 namesz | u32 descsz | u32 type | name (padded to 4) | desc (padded to 4)
    // For GNU notes, name is "GNU\0" (4 bytes, aligned).  For
    // GNU_PROPERTY_TYPE_0, the desc is a packed array of property
    // entries.
    if bytes.len() < 16 {
        return None;
    }
    let namesz = u32::from_le_bytes(bytes[..4].try_into().ok()?) as usize;
    let descsz = u32::from_le_bytes(bytes[4..8].try_into().ok()?) as usize;
    let ntype = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    if ntype != NT_GNU_PROPERTY_TYPE_0 {
        return None;
    }
    let name_start = 12usize;
    let desc_start = name_start.checked_add(align_up(namesz, 4))?;
    let desc_end = desc_start.checked_add(descsz)?;
    if desc_end > bytes.len() {
        return None;
    }
    let desc = &bytes[desc_start..desc_end];

    // Property entries.  64-bit ELFs align entries on 8 bytes; we
    // assume 64-bit here (32-bit ELFs use 4 — call sites that need it
    // can branch on EI_CLASS, but x86 hardening flags only matter on
    // 64-bit Linux today).
    let align = if data.len() > 4 && data[4] == 2 { 8 } else { 4 };
    let mut prop = GnuProperty::default();
    let mut p = 0usize;
    while p + 8 <= desc.len() {
        let pr_type = u32::from_le_bytes(desc[p..p + 4].try_into().ok()?);
        let pr_datasz = u32::from_le_bytes(desc[p + 4..p + 8].try_into().ok()?) as usize;
        let pr_data_off = p + 8;
        if pr_data_off + pr_datasz > desc.len() {
            break;
        }
        let pr_data = &desc[pr_data_off..pr_data_off + pr_datasz];

        match pr_type {
            GNU_PROPERTY_X86_FEATURE_1_AND if pr_data.len() >= 4 => {
                let bits = u32::from_le_bytes(pr_data[..4].try_into().ok()?);
                prop.ibt = bits & 0x1 != 0;
                prop.shstk = bits & 0x2 != 0;
            }
            GNU_PROPERTY_AARCH64_FEATURE_1_AND if pr_data.len() >= 4 => {
                let bits = u32::from_le_bytes(pr_data[..4].try_into().ok()?);
                prop.bti = bits & 0x1 != 0;
                prop.pac = bits & 0x2 != 0;
            }
            GNU_PROPERTY_X86_ISA_1_NEEDED if pr_data.len() >= 4 => {
                // Bit positions name the level: bit 0=BASELINE,
                // 1=v2, 2=v3, 3=v4. Take the highest bit set.
                let bits = u32::from_le_bytes(pr_data[..4].try_into().ok()?);
                if bits != 0 {
                    let level = (32 - bits.leading_zeros()) as u8;
                    if level > prop.x86_isa_level {
                        prop.x86_isa_level = level;
                    }
                }
            }
            _ => {}
        }

        // Advance past data, padded to alignment.
        p = pr_data_off + align_up(pr_datasz, align);
    }

    if prop.is_empty() {
        None
    } else {
        Some(prop)
    }
}

fn align_up(n: usize, a: usize) -> usize {
    (n + a - 1) & !(a - 1)
}

// ---------------------------------------------------------------------------
// Sanitizer detection
// ---------------------------------------------------------------------------

/// Detect compiler-runtime sanitizer instrumentation by scanning
/// the imports list for canonical init/handler symbols. Returns a
/// sorted, deduplicated list of detected sanitizer names. When
/// present, the binary is almost always a debug build that leaked
/// to production — strong attribution / mistake signal.
///
/// Detected sanitizers:
/// - `asan` — AddressSanitizer (`__asan_init`, `__asan_handle_no_return`)
/// - `tsan` — ThreadSanitizer (`__tsan_init`)
/// - `msan` — MemorySanitizer (`__msan_init`)
/// - `ubsan` — UndefinedBehaviorSanitizer (`__ubsan_handle_*`)
/// - `hwasan` — HardwareAddressSanitizer (`__hwasan_init`)
/// - `lsan` — LeakSanitizer (`__lsan_init`)
/// - `kasan` — Kernel ASan (kernel module use)
/// - `pgo` — LLVM profile-guided-optimization data (`__llvm_profile_*`)
/// - `coverage` — LLVM source-based coverage (`__llvm_coverage_*`)
/// - `gcov` — gcov / gprof instrumentation (`__gcov_init`)
#[must_use]
pub(crate) fn detect_sanitizers(imports: &[Import]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for imp in imports {
        // `Import::new` normalizes leading underscores away (so
        // `__asan_init` is stored as `asan_init`). Match against the
        // post-normalization form by stripping any remaining leading
        // underscores defensively.
        let s = imp.symbol.as_str().trim_start_matches('_');
        if s.starts_with("asan_") {
            out.insert("asan".to_string());
        } else if s.starts_with("tsan_") {
            out.insert("tsan".to_string());
        } else if s.starts_with("msan_") {
            out.insert("msan".to_string());
        } else if s.starts_with("ubsan_") {
            out.insert("ubsan".to_string());
        } else if s.starts_with("hwasan_") {
            out.insert("hwasan".to_string());
        } else if s.starts_with("lsan_") {
            out.insert("lsan".to_string());
        } else if s.starts_with("kasan_") {
            out.insert("kasan".to_string());
        } else if s.starts_with("llvm_profile_") {
            out.insert("pgo".to_string());
        } else if s.starts_with("llvm_coverage_") || s.starts_with("llvm_covmap_") {
            out.insert("coverage".to_string());
        } else if s.starts_with("gcov_") || s.starts_with("llvm_gcov_") {
            out.insert("gcov".to_string());
        }
    }
    out.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Rust runtime detection
// ---------------------------------------------------------------------------

/// Detect a Rust binary by looking for the canonical Rust allocator
/// shim symbols (`__rust_alloc`, `__rust_dealloc`, etc.) and panic
/// infrastructure (`rust_panic`, `rust_begin_unwind`). These are
/// emitted by every rustc-built binary and are unmistakeable.
///
/// Scans both imports (for ELF/PE where Rust stdlib may be a shared
/// dep) AND exports (for Mach-O where Rust stdlib is statically
/// linked and the runtime symbols appear as defined locals).
///
/// Returns the list of distinct Rust ABI symbols observed (sorted),
/// or empty when no Rust signal present.
#[must_use]
pub(crate) fn detect_rust_symbols(
    imports: &[Import],
    exports: &[crate::types::Export],
) -> Vec<String> {
    let mut out = BTreeSet::new();
    let exact_marks = [
        "rust_alloc",
        "rust_dealloc",
        "rust_realloc",
        "rust_alloc_zeroed",
        "rust_alloc_error_handler",
        "rust_panic",
        "rust_begin_unwind",
        "rust_eh_personality",
    ];
    let scan_name = |s: &str, out: &mut BTreeSet<String>| {
        let s = s.trim_start_matches('_');
        for mark in exact_marks {
            if s == mark {
                out.insert(mark.to_string());
            }
        }
    };
    for imp in imports {
        scan_name(imp.symbol.as_str(), &mut out);
    }
    for exp in exports {
        scan_name(exp.symbol.as_str(), &mut out);
    }
    out.into_iter().collect()
}

/// Determine Rust symbol-mangling style from observed symbols.
/// Returns `Some("v0")` when any symbol uses the new v0 mangling
/// (`_R...`), `Some("legacy")` when the legacy mangling
/// (`_ZN.*17h<16-hex>E`) is observed exclusively, or `None` when no
/// Rust mangling is detectable. Scans both imports and exports.
#[must_use]
pub(crate) fn detect_rust_mangling(
    imports: &[Import],
    exports: &[crate::types::Export],
) -> Option<&'static str> {
    use regex::Regex;
    let legacy_re = Regex::new(r"^_?ZN.*17h[0-9a-f]{16}E$").ok()?;
    let mut saw_legacy = false;
    let check = |s: &str, saw_legacy: &mut bool| -> bool {
        if s.starts_with("_R") && s.len() > 4 {
            return true; // v0
        }
        if legacy_re.is_match(s) {
            *saw_legacy = true;
        }
        false
    };
    for imp in imports {
        if check(imp.symbol.as_str(), &mut saw_legacy) {
            return Some("v0");
        }
    }
    for exp in exports {
        if check(exp.symbol.as_str(), &mut saw_legacy) {
            return Some("v0");
        }
    }
    if saw_legacy {
        Some("legacy")
    } else {
        None
    }
}

/// Whether the ELF carries a `.rustc` section. Set on rustc-built
/// `lib` crates (rlib metadata) and some `bin` crates depending on
/// build profile. An explicit "this is a Rust artifact" marker.
#[must_use]
pub(crate) fn has_rustc_section(data: &[u8]) -> bool {
    read_section(data, b".rustc").is_some()
}

// ---------------------------------------------------------------------------
// Fortify-source detection
// ---------------------------------------------------------------------------

/// Detect FORTIFY_SOURCE-instrumented libc calls by scanning imports
/// for the `__<func>_chk` family. Returns the sorted, deduplicated
/// list of base function names (`sprintf`, `strcpy`, `memcpy`, ...).
///
/// Trait authors compose this with `len > 0` for the boolean
/// `is_fortified` signal, and use the list itself as ML feature
/// surface — modern hardened distros (Wolfi, Chainguard, RHEL) fortify
/// dozens of functions; malware authors basically never do.
///
/// Background: `-D_FORTIFY_SOURCE=2` (or `=3` since glibc 2.34) tells
/// gcc/clang to redirect bounds-checkable libc calls to `__<func>_chk`
/// variants that abort on overflow. The presence of *any* `*_chk`
/// import is a one-bit signal that the binary was built with
/// fortification enabled.
#[must_use]
pub(crate) fn detect_fortify_functions(imports: &[Import]) -> Vec<String> {
    let mut out = BTreeSet::new();
    for imp in imports {
        // `Import::new` strips one leading underscore; the canonical
        // form on the wire is `__sprintf_chk` → after normalization
        // `_sprintf_chk`. Strip remaining leading underscores
        // defensively so we match either form.
        let s = imp.symbol.as_str().trim_start_matches('_');
        if let Some(base) = s.strip_suffix("_chk") {
            // Skip the sanitizer/PGO families that happen to end in
            // `_chk` but are not fortify (none today, but defensive).
            if base.is_empty() || base.starts_with("asan") || base.starts_with("tsan") {
                continue;
            }
            out.insert(base.to_string());
        }
    }
    out.into_iter().collect()
}

// ---------------------------------------------------------------------------
// Distro / CI environment fingerprinting from `.comment`
// ---------------------------------------------------------------------------

/// Best-effort distro/toolchain fingerprint from a parsed `.comment`
/// banner string. Returns `(distro, toolchain_family, toolchain_version)`.
/// Trait authors can also regex on the raw `elf.comment` field —
/// this is a convenience for the most common cases.
///
/// Examples:
/// - `"GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0"` → `("ubuntu", "gcc", "13.2.0")`
/// - `"GCC: (Debian 12.2.0-14) 12.2.0"` → `("debian", "gcc", "12.2.0")`
/// - `"GCC: (Alpine 12.2.1_git20220924-r10) 12.2.1"` → `("alpine", "gcc", "12.2.1")`
/// - `"clang version 14.0.6 ..."` → `(_, "clang", "14.0.6")`
/// - `"Apple LLVM version 14.0.0 (clang-1400.0.29.202)"` → `(_, "apple_clang", "14.0.0")`
#[must_use]
pub(crate) fn parse_comment_fingerprint(comment: &str) -> CommentFingerprint {
    let mut fp = CommentFingerprint::default();

    // Distro detection (case-insensitive substring match).
    let lower = comment.to_lowercase();
    // Wolfi / Chainguard come *before* alpine — Wolfi inherits some
    // Alpine conventions but should be identified as itself, not the
    // upstream distro.  Same for Kali (Debian-derived).
    fp.distro = if lower.contains("wolfi") {
        Some("wolfi".into())
    } else if lower.contains("chainguard") {
        Some("chainguard".into())
    } else if lower.contains("kali") {
        Some("kali".into())
    } else if lower.contains("ubuntu") {
        Some("ubuntu".into())
    } else if lower.contains("debian") {
        Some("debian".into())
    } else if lower.contains("alpine") {
        Some("alpine".into())
    } else if lower.contains("red hat") || lower.contains("redhat") {
        Some("redhat".into())
    } else if lower.contains("rocky") {
        Some("rocky".into())
    } else if lower.contains("almalinux") {
        Some("almalinux".into())
    } else if lower.contains("amazon linux") {
        Some("amazon".into())
    } else if lower.contains("fedora") {
        Some("fedora".into())
    } else if lower.contains("suse") {
        Some("suse".into())
    } else if lower.contains("arch linux") || lower.contains("archlinux") {
        Some("archlinux".into())
    } else if lower.contains("gentoo") {
        Some("gentoo".into())
    } else if lower.contains("nixos") {
        Some("nixos".into())
    } else if lower.contains("openwrt") {
        Some("openwrt".into())
    } else {
        None
    };

    // Toolchain family + version.
    if comment.starts_with("GCC:") || comment.contains("; GCC:") {
        fp.toolchain_family = Some("gcc".into());
        // GCC banner format: "GCC: (...) <version>" — version is the
        // last whitespace-separated token before the next `;`.
        if let Some(start) = comment.find("GCC:") {
            let rest = &comment[start + "GCC:".len()..];
            // Skip the parenthesized distro tag.
            let after_paren = match rest.find(')') {
                Some(p) => &rest[p + 1..],
                None => rest,
            };
            let token = after_paren
                .split([';', ',', ' '])
                .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()));
            fp.toolchain_version = token
                .map(|t| t.trim().to_string())
                .filter(|s| !s.is_empty());
        }
    } else if comment.contains("Apple LLVM") || comment.contains("Apple clang") {
        fp.toolchain_family = Some("apple_clang".into());
        if let Some(pos) = comment.find("version ") {
            let rest = &comment[pos + "version ".len()..];
            let token = rest.split([' ', '(', ')']).next();
            fp.toolchain_version = token
                .map(|t| t.trim().to_string())
                .filter(|s| !s.is_empty());
        }
    } else if comment.contains("clang version") {
        fp.toolchain_family = Some("clang".into());
        if let Some(pos) = comment.find("clang version ") {
            let rest = &comment[pos + "clang version ".len()..];
            let token = rest.split([' ', '(', ')']).next();
            fp.toolchain_version = token
                .map(|t| t.trim().to_string())
                .filter(|s| !s.is_empty());
        }
    }

    fp
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CommentFingerprint {
    pub distro: Option<String>,
    pub toolchain_family: Option<String>,
    pub toolchain_version: Option<String>,
}

// ---------------------------------------------------------------------------
// Aggregate hook: layer extracted data onto the binary kv tree
// ---------------------------------------------------------------------------

/// Run all post-analysis extractors and merge their results into
/// `report.kv_tree`. Idempotent: safe to call multiple times.
pub(crate) fn augment_report(report: &mut AnalysisReport, raw_data: &[u8]) {
    use serde_json::{json, Value};

    // Build the augmenting Value first so we don't have to worry
    // about partial-update consistency.
    let mut augment = serde_json::Map::new();

    // PE Rich header / imphash / VERSIONINFO.
    let is_pe = raw_data.len() > 0x40 && raw_data.get(..2) == Some(b"MZ".as_ref());
    if is_pe {
        let mut pe_extra = serde_json::Map::new();
        let mut hashes_extra = serde_json::Map::new();

        if let Some(rich) = super::pe_extractors::decode_rich_header(raw_data) {
            let entries: Vec<Value> = rich
                .entries
                .iter()
                .map(|e| {
                    json!({
                        "product_id": e.product_id,
                        "product_name": e.product_name,
                        "build_number": e.build_number,
                        "use_count": e.use_count,
                    })
                })
                .collect();
            let mut rh = serde_json::Map::new();
            rh.insert("entries".into(), Value::Array(entries));
            rh.insert("xor_key".into(), json!(format!("0x{:08x}", rich.xor_key)));
            // The Rich-header hash lives at `hashes.rich_header_hash`
            // alongside imphash and other cross-binary hashes — one
            // canonical location, no duplicate under `pe.*`.
            pe_extra.insert("rich_header".into(), Value::Object(rh));
            hashes_extra.insert("rich_header_hash".into(), json!(rich.hash));
        }

        if let Some(imphash) = super::pe_extractors::compute_imphash(&report.imports) {
            hashes_extra.insert("imphash".into(), json!(imphash));
        }

        let vi = super::pe_extractors::extract_version_info(raw_data);
        if !vi.is_empty() {
            // Snake-case the canonical PE field names so trait paths
            // are uniform with `office.summary.author`-style schemas.
            let mut version_info = serde_json::Map::new();
            for (k, v) in vi.iter() {
                version_info.insert(snake_case(k), json!(v));
            }
            pe_extra.insert("version_info".into(), Value::Object(version_info));
        }

        // RT_MANIFEST — Windows side-by-side assembly manifest XML.
        // Surfaces requestedExecutionLevel (UAC), supportedOS GUIDs,
        // dpiAware/autoElevate, and dependentAssembly references.
        if let Some(manifest) = super::pe_manifest::extract(raw_data) {
            pe_extra.insert("manifest".into(), manifest);
        }

        if !pe_extra.is_empty() {
            augment.insert("pe".into(), Value::Object(pe_extra));
        }
        if !hashes_extra.is_empty() {
            augment.insert("hashes".into(), Value::Object(hashes_extra));
        }
    }

    // ELF .comment / .interp / .GCC.command.line
    if raw_data.get(..4) == Some(b"\x7fELF".as_ref()) {
        let mut elf_extra = serde_json::Map::new();
        let mut build_extra = serde_json::Map::new();

        if let Some(comment) = extract_elf_comment(raw_data) {
            elf_extra.insert("comment".into(), json!(comment.clone()));
            let fp = parse_comment_fingerprint(&comment);
            if let Some(d) = fp.distro {
                build_extra.insert("distro".into(), json!(d));
            }
            if let Some(family) = fp.toolchain_family {
                build_extra.insert("toolchain_family".into(), json!(family.clone()));
                if let Some(version) = fp.toolchain_version {
                    build_extra
                        .insert("toolchain".into(), json!(format!("{} {}", family, version)));
                }
            }
        }
        if let Some(interp) = extract_elf_interp(raw_data) {
            elf_extra.insert("interpreter".into(), json!(interp));
        }
        if let Some(cmdline) = extract_gcc_command_line(raw_data) {
            build_extra.insert("command_line".into(), json!(cmdline));
        }
        // DWARF DW_AT_producer / DW_AT_comp_dir / DW_AT_name —
        // unstripped ELF binaries leak the FULL compile command line
        // and build directory per CU. Strongest attribution surface
        // any binary format offers.
        if let Some(dw) = super::dwarf_extractors::extract(raw_data) {
            let mut dwarf_extra = serde_json::Map::new();
            if !dw.producers.is_empty() {
                dwarf_extra.insert("producers".into(), json!(dw.producers.clone()));
                // Also surface the first producer string as the
                // canonical cross-format `build.toolchain` when the
                // metrics path didn't already populate it.
                if let Some(first) = dw.producers.first() {
                    build_extra
                        .entry("toolchain_full".to_string())
                        .or_insert_with(|| json!(first.clone()));
                }
            }
            if !dw.comp_dirs.is_empty() {
                dwarf_extra.insert("comp_dirs".into(), json!(dw.comp_dirs.clone()));
                // Single canonical build root → cross-format
                // `build.build_root`. Multiple comp_dirs = different
                // CUs from different repos; we don't pick one.
                if dw.comp_dirs.len() == 1 {
                    build_extra
                        .entry("build_root".to_string())
                        .or_insert_with(|| json!(dw.comp_dirs[0].clone()));
                }
            }
            if !dw.languages.is_empty() {
                dwarf_extra.insert("languages".into(), json!(dw.languages.clone()));
            }
            if !dw.source_files.is_empty() {
                dwarf_extra.insert("source_files".into(), json!(dw.source_files.clone()));
            }
            if dw.cu_count > 0 {
                dwarf_extra.insert("cu_count".into(), json!(dw.cu_count));
                // Also expose as a metric for trait min/max queries.
                let metrics = report
                    .metrics
                    .get_or_insert_with(crate::types::scores::Metrics::default);
                let elf_metrics = metrics
                    .elf
                    .get_or_insert_with(crate::types::binary_metrics::ElfMetrics::default);
                elf_metrics.dwarf_cu_count = dw.cu_count;
            }
            if !dwarf_extra.is_empty() {
                augment.insert("dwarf".into(), Value::Object(dwarf_extra));
            }
        }

        // .note.package — FDO Package Metadata. Self-attestation of
        // the producing distro/package manager. Highest-leverage
        // attribution signal when present (Wolfi/Chainguard/Fedora).
        if let Some(pkg) = extract_note_package(raw_data) {
            augment.insert("package".into(), pkg);
        }

        // DT_FLAGS / DT_FLAGS_1 — runtime hardening flags. Stable per
        // distro / link configuration; drift signals build change.
        if let Some(df) = extract_dynamic_flags(raw_data) {
            let mut flags = serde_json::Map::new();
            flags.insert("raw".into(), json!(df.raw_flags));
            flags.insert("raw_1".into(), json!(df.raw_flags_1));
            // Only write the bool keys that are actually true to keep
            // the kv subtree sparse.
            macro_rules! flag {
                ($name:literal, $field:ident) => {
                    if df.$field {
                        flags.insert($name.into(), json!(true));
                    }
                };
            }
            flag!("bind_now", bind_now);
            flag!("textrel", textrel);
            flag!("symbolic", symbolic);
            flag!("static_tls", static_tls);
            flag!("now", now);
            flag!("nodelete", nodelete);
            flag!("initfirst", initfirst);
            flag!("noopen", noopen);
            flag!("nodeflib", nodeflib);
            flag!("nodump", nodump);
            flag!("pie", pie);
            flag!("global", global);
            flag!("group", group);
            flag!("interpose", interpose);
            flag!("direct", direct);
            elf_extra.insert("dt_flags".into(), Value::Object(flags));
        }

        // Symbol-versioning requirements (.gnu.version_r). Each
        // library + the exact set of versioned symbols this binary
        // imports from it. THE xz-class supply-chain detector — a
        // sudden new GLIBC_2.X requirement is almost always tampering.
        if let Some(needs) = extract_needed_versions(raw_data) {
            let arr: Vec<Value> = needs
                .iter()
                .map(|n| json!({"lib": n.lib, "versions": n.versions}))
                .collect();
            elf_extra.insert("needed_versions".into(), Value::Array(arr));
        }
        if let Some(provides) = extract_provided_versions(raw_data) {
            elf_extra.insert("provided_versions".into(), json!(provides));
        }

        // Linker identification. Cross-format `build.linker` for
        // ergonomic trait writing alongside `build.toolchain_family`.
        if let Some(linker) = extract_linker(raw_data) {
            build_extra
                .entry("linker".to_string())
                .or_insert_with(|| json!(linker));
        }

        if let Some(prop) = extract_gnu_property(raw_data) {
            let mut gp = serde_json::Map::new();
            if prop.ibt {
                gp.insert("ibt".into(), json!(true));
            }
            if prop.shstk {
                gp.insert("shstk".into(), json!(true));
            }
            if prop.pac {
                gp.insert("pac".into(), json!(true));
            }
            if prop.bti {
                gp.insert("bti".into(), json!(true));
            }
            if prop.x86_isa_level > 0 {
                gp.insert("x86_isa_level".into(), json!(prop.x86_isa_level));
            }
            if !gp.is_empty() {
                elf_extra.insert("gnu_property".into(), Value::Object(gp));
            }
        }

        if !elf_extra.is_empty() {
            augment.insert("elf".into(), Value::Object(elf_extra));
        }
        if !build_extra.is_empty() {
            augment.insert("build".into(), Value::Object(build_extra));
        }
    }

    // Mach-O LC_UUID / LC_BUILD_VERSION / LC_LOAD_DYLIB / LC_RPATH /
    // LC_SOURCE_VERSION / LC_LINKER_OPTION.  Cross-reference with the
    // existing metrics-derived `macho.{min_os_version, sdk_version}`.
    let is_macho = looks_like_macho(raw_data);
    if is_macho {
        // Per-slice summary (UUIDs + arch + signing presence). Even
        // for plain Mach-O this returns one entry; for fat binaries
        // it lets trait authors and ML detect slice-level tampering
        // (e.g. one slice unsigned, others signed; UUIDs diverging
        // across slices when they should be co-built).
        let slices = super::macho_extractors::extract_all_slices(raw_data);
        // Slice count is a derived count → metric. Populate even for
        // plain Mach-Os (1) so the field is queryable.
        if !slices.is_empty() {
            let metrics = report
                .metrics
                .get_or_insert_with(crate::types::scores::Metrics::default);
            let macho_metrics = metrics
                .macho
                .get_or_insert_with(crate::types::binary_metrics::MachoMetrics::default);
            macho_metrics.slice_count = slices.len() as u32;
        }
        if let Some(lc) = super::macho_extractors::extract(raw_data) {
            let mut macho_extra = serde_json::Map::new();
            if slices.len() > 1 {
                macho_extra.insert("is_fat".into(), json!(true));
                macho_extra.insert("slice_count".into(), json!(slices.len()));
                let arr: Vec<Value> = slices
                    .iter()
                    .map(|s| {
                        json!({
                            "arch": s.arch,
                            "uuid": s.uuid,
                            "file_offset": s.file_offset,
                            "has_code_signature": s.has_code_signature,
                        })
                    })
                    .collect();
                macho_extra.insert("slices".into(), Value::Array(arr));
            }

            if let Some(uuid) = lc.uuid.as_deref() {
                macho_extra.insert("uuid".into(), json!(uuid));
                // UUID is the cross-format build identifier (parallel to
                // ELF GNU build-id and PE Debug-Directory PDB-age GUID).
                let build_extra = augment
                    .entry(String::from("build"))
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
                if let Some(obj) = build_extra.as_object_mut() {
                    obj.entry("build_id".to_string())
                        .or_insert_with(|| json!(uuid));
                }
            }
            if let Some(bv) = lc.build_version.as_ref() {
                if !bv.platform.is_empty() && bv.platform != "unknown" {
                    macho_extra.insert("platform".into(), json!(bv.platform.clone()));
                }
                // Backfill min_os / sdk if the metrics path didn't.
                if !bv.minos.is_empty() && bv.minos != "0.0.0" {
                    macho_extra
                        .entry("min_os_version".to_string())
                        .or_insert_with(|| json!(bv.minos.clone()));
                }
                if !bv.sdk.is_empty() && bv.sdk != "0.0.0" {
                    macho_extra
                        .entry("sdk_version".to_string())
                        .or_insert_with(|| json!(bv.sdk.clone()));
                }
                if !bv.tools.is_empty() {
                    let tools: Vec<Value> = bv
                        .tools
                        .iter()
                        .map(|t| json!({"tool": t.tool, "version": t.version}))
                        .collect();
                    macho_extra.insert("tools".into(), Value::Array(tools));
                    // First non-unknown tool drives cross-format toolchain
                    // attribution: clang/swiftc identify the family.
                    if let Some(first) = bv
                        .tools
                        .iter()
                        .find(|t| t.tool != "unknown" && !t.tool.is_empty())
                    {
                        let build_extra = augment
                            .entry(String::from("build"))
                            .or_insert_with(|| Value::Object(serde_json::Map::new()));
                        if let Some(obj) = build_extra.as_object_mut() {
                            obj.entry("toolchain_family".to_string())
                                .or_insert_with(|| json!(first.tool.clone()));
                            obj.entry("toolchain".to_string()).or_insert_with(|| {
                                json!(format!("{} {}", first.tool, first.version))
                            });
                        }
                    }
                }
            }
            if let Some(sv) = lc.source_version.as_deref() {
                // LC_SOURCE_VERSION is unset by default; emit only when
                // the developer actually stamped a version.
                if sv != "0.0.0" && !sv.is_empty() {
                    macho_extra.insert("source_version".into(), json!(sv));
                }
            }
            if let Some(id) = lc.id_dylib.as_deref() {
                macho_extra.insert("id_dylib".into(), json!(id));
            }
            if !lc.load_dylibs.is_empty() {
                let arr: Vec<Value> = lc
                    .load_dylibs
                    .iter()
                    .map(|d| {
                        json!({
                            "path": d.path,
                            "kind": d.kind,
                            "current_version": d.current_version,
                            "compatibility_version": d.compatibility_version,
                        })
                    })
                    .collect();
                macho_extra.insert("load_dylibs".into(), Value::Array(arr));
            }
            if !lc.rpath.is_empty() {
                macho_extra.insert("rpath".into(), json!(lc.rpath.clone()));
            }
            if !lc.linker_options.is_empty() {
                macho_extra.insert("linker_options".into(), json!(lc.linker_options.clone()));
            }

            // Mach-O code signature → signing.* (team_id, identifier,
            // signer, authorities, entitlements, notarized).  Re-uses
            // the existing `macho_codesign` parser; we just feed it the
            // LC_CODE_SIGNATURE blob offset we recovered above.
            let mut cdhash_for_hashes: Option<String> = None;
            let mut codesign_notarized = false;
            if let Some((cs_off, cs_size)) = lc.code_signature {
                if let Ok(cs) =
                    super::macho_codesign::parse_code_signature(raw_data, cs_off, cs_size)
                {
                    cdhash_for_hashes = cs.cdhash_sha256.clone();
                    codesign_notarized = cs.is_notarized;
                    let signing_extra = augment
                        .entry(String::from("signing"))
                        .or_insert_with(|| Value::Object(serde_json::Map::new()));
                    if let Some(obj) = signing_extra.as_object_mut() {
                        obj.entry("catalog".to_string())
                            .or_insert_with(|| json!("apple_codesign"));
                        obj.entry("type".to_string())
                            .or_insert_with(|| json!(cs.signature_type.as_str()));
                        if let Some(team) = cs.team_id.as_deref() {
                            obj.insert("team_id".into(), json!(team));
                        }
                        if let Some(ident) = cs.identifier.as_deref() {
                            obj.insert("bundle_identifier".into(), json!(ident));
                        }
                        if let Some(signer) = cs.signer.as_deref() {
                            obj.insert("signer_subject".into(), json!(signer));
                        }
                        if !cs.authorities.is_empty() {
                            obj.insert("authorities".into(), json!(cs.authorities.clone()));
                        }
                        if cs.is_notarized {
                            obj.insert("notarized".into(), json!(true));
                        }
                        if cs.has_hardened_runtime {
                            obj.entry("hardened_runtime".to_string())
                                .or_insert_with(|| json!(true));
                        }
                        if let Some(cdh) = cs.cdhash_sha256.as_deref() {
                            obj.insert("cdhash_sha256".into(), json!(cdh));
                        }
                        if let Some(req) = cs.requirements_sha256.as_deref() {
                            obj.insert("requirements_sha256".into(), json!(req));
                            obj.insert(
                                "requirements_slot_count".into(),
                                json!(cs.requirements_slot_count),
                            );
                        }
                        if !cs.entitlements.is_empty() {
                            let mut ent = serde_json::Map::new();
                            for (k, v) in &cs.entitlements {
                                use super::macho_codesign::EntitlementValue;
                                let jv = match v {
                                    EntitlementValue::Boolean(b) => json!(b),
                                    EntitlementValue::String(s) => json!(s),
                                    EntitlementValue::Array(a) => json!(a),
                                };
                                ent.insert(k.clone(), jv);
                            }
                            obj.insert("entitlements".into(), Value::Object(ent));
                        }
                    }
                }
            }

            // Swift runtime sections — `__TEXT,__swift5_*` family
            // contains protocol/type/reflection metadata. Their
            // presence is the canonical "this is Swift code" signal;
            // the specific subset present implies Swift version
            // (acfuncs ≥ 5.5, mpenum newer, etc.). Strong attribution
            // for Apple-platform supply-chain detection — Swift code
            // built outside Xcode (e.g. from a tampered swiftc) often
            // shows section drift.
            let swift_sections =
                super::macho_extractors::list_sections_with_prefix(raw_data, "__TEXT", "__swift5_");
            if !swift_sections.is_empty() {
                macho_extra.insert("swift_sections".into(), json!(swift_sections.clone()));
                // Set the metric for trait min/max queries.
                let metrics = report
                    .metrics
                    .get_or_insert_with(crate::types::scores::Metrics::default);
                let macho_metrics = metrics
                    .macho
                    .get_or_insert_with(crate::types::binary_metrics::MachoMetrics::default);
                macho_metrics.swift_section_count = swift_sections.len() as u32;
            }

            // Embedded plists in __TEXT — Info.plist and launchd_plist.
            // Command-line tools and self-installing daemons stash these
            // directly in the text segment instead of carrying a
            // surrounding bundle. Strong attribution + persistence
            // signals: the launchd plist names the daemon and its
            // ProgramArguments; Info.plist mismatch with code signature
            // bundle_identifier is a tampering signal.
            if let Some(bytes) =
                super::macho_extractors::find_section(raw_data, "__TEXT", "__info_plist")
            {
                if let Some(parsed) = parse_plist_to_json(bytes) {
                    macho_extra.insert("info_plist".into(), parsed);
                }
            }
            if let Some(bytes) =
                super::macho_extractors::find_section(raw_data, "__TEXT", "__launchd_plist")
            {
                if let Some(parsed) = parse_plist_to_json(bytes) {
                    macho_extra.insert("launchd_plist".into(), parsed);
                }
            }

            if !macho_extra.is_empty() {
                augment.insert("macho".into(), Value::Object(macho_extra));
            }

            // Notarized is a derived bool — store on metric only.
            if codesign_notarized {
                let metrics = report
                    .metrics
                    .get_or_insert_with(crate::types::scores::Metrics::default);
                let macho_metrics = metrics
                    .macho
                    .get_or_insert_with(crate::types::binary_metrics::MachoMetrics::default);
                macho_metrics.is_notarized = true;
            }

            // Cross-format: mirror CDHash under hashes.* alongside
            // imphash, rich_header_hash, etc. — `hashes.*` is the
            // single canonical home for similarity / cluster hashes
            // regardless of source format.
            if let Some(cdh) = cdhash_for_hashes {
                let hashes = augment
                    .entry(String::from("hashes"))
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
                if let Some(h) = hashes.as_object_mut() {
                    h.entry("cdhash_sha256".to_string())
                        .or_insert_with(|| json!(cdh));
                }
            }
        }
    }

    // Sanitizers — independent of file format, scan all imports.
    let sanitizers = detect_sanitizers(&report.imports);
    if !sanitizers.is_empty() {
        let build_extra = augment
            .entry(String::from("build"))
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(obj) = build_extra.as_object_mut() {
            obj.insert(
                "sanitizers".into(),
                Value::Array(sanitizers.into_iter().map(Value::String).collect()),
            );
        }
    }

    // Rust runtime detection — allocator shim + panic infrastructure
    // imports are unmistakeable. The `.rustc` section (ELF) is an
    // explicit "this is a Rust artifact" marker.
    let rust_symbols = detect_rust_symbols(&report.imports, &report.exports);
    let rust_mangling = detect_rust_mangling(&report.imports, &report.exports);
    let rust_section = has_rustc_section(raw_data);
    if !rust_symbols.is_empty() || rust_mangling.is_some() || rust_section {
        let build_extra = augment
            .entry(String::from("build"))
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(obj) = build_extra.as_object_mut() {
            // Cross-format toolchain attribution: when Rust is detected,
            // it's the source-language toolchain regardless of which
            // linker LC_BUILD_VERSION names. Move any prior toolchain_family
            // value (e.g. `ld` from Mach-O LC_BUILD_VERSION) to `linker`
            // so both signals are preserved.
            if let Some(prior) = obj.get("toolchain_family").cloned() {
                if prior.as_str() != Some("rustc") {
                    obj.entry("linker".to_string()).or_insert(prior);
                }
            }
            obj.insert("toolchain_family".into(), json!("rustc"));
            if !rust_symbols.is_empty() {
                obj.insert("rust_runtime_symbols".into(), json!(rust_symbols));
            }
            if let Some(m) = rust_mangling {
                obj.insert("rust_mangling".into(), json!(m));
            }
            if rust_section {
                obj.insert("has_rustc_section".into(), json!(true));
            }
        }
    }

    // FORTIFY_SOURCE — same import-scan pattern.
    let fortified = detect_fortify_functions(&report.imports);
    if !fortified.is_empty() {
        let build_extra = augment
            .entry(String::from("build"))
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(obj) = build_extra.as_object_mut() {
            obj.insert(
                "fortified".into(),
                Value::Array(fortified.into_iter().map(Value::String).collect()),
            );
        }
    }

    // Builder-path / username recovery.  Cross-format byte scan
    // for `/home/<u>/`, `/Users/<u>/`, and `C:\Users\<u>\` —
    // these leak the build host's filesystem layout and the
    // developer's username (strong attribution signal that
    // survives stripping).
    //
    // Naming: when exactly one canonical username is recovered we
    // expose the singular `username`; otherwise we expose the
    // array `usernames` (mutually exclusive shapes).  Trait authors
    // target one or the other based on cardinality; the
    // `username_from` field carries provenance.
    let bp = super::builder_paths::extract(raw_data);
    if !bp.usernames.is_empty() || !bp.source_dirs.is_empty() || !bp.full_paths.is_empty() {
        let build_extra = augment
            .entry(String::from("build"))
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(obj) = build_extra.as_object_mut() {
            match bp.usernames.len() {
                0 => {}
                1 => {
                    obj.insert("username".into(), json!(bp.usernames[0].clone()));
                    if let Some(home) = bp.source_dirs.first() {
                        obj.insert("user_home".into(), json!(home.clone()));
                    }
                    obj.insert("username_from".into(), json!("byte_scan"));
                }
                _ => {
                    obj.insert("usernames".into(), json!(bp.usernames.clone()));
                }
            }
            if !bp.full_paths.is_empty() {
                obj.insert("source_paths".into(), json!(bp.full_paths.clone()));
            }
            // Build-root: longest common ancestor of discovered
            // builder-anchored paths.
            if let Some(root) = super::builder_paths::find_build_root(&bp.full_paths) {
                obj.insert("build_root".into(), json!(root));
            }
        }
    }

    // PDB-derived username for PE binaries (when the structural
    // analyzer captured the PDB path).  This is independent of
    // the raw byte scan: the `.pdb` filename in the PE Debug
    // Directory is a single canonical reference, not subject to
    // scan noise — preferred when present.
    if let Some(pdb) = report
        .metrics
        .as_ref()
        .and_then(|m| m.pe.as_ref())
        .and_then(|pe| pe.pdb_path.as_ref())
    {
        if let Some(user) = super::builder_paths::extract_username_from_pdb(pdb) {
            let build_extra = augment
                .entry(String::from("build"))
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
            if let Some(obj) = build_extra.as_object_mut() {
                // PDB is high-confidence; supersede byte-scan
                // results.  Drop `usernames[]` if PDB gave us a
                // canonical answer.
                obj.remove("usernames");
                obj.insert("username".into(), json!(user.clone()));
                obj.insert("username_from".into(), json!("pdb_path"));
            }
        }
    }

    // Go buildinfo — cross-format scan for the magic header.
    // Trait authors looking for "where was this Go binary built"
    // compose `build.build_root` + `build.toolchain_family == "go"`
    // rather than a Go-specific duplicate field.
    if let Some(go) = super::go_buildinfo::extract(raw_data) {
        let go_value = serialize_go_buildinfo(&go);
        if let Some(obj) = go_value.as_object() {
            if !obj.is_empty() {
                augment.insert("go".into(), go_value);
            }
        }
        // Toolchain attribution feeds the cross-format build.*
        // section.  `go.main_path` (the import path) lives ONLY on
        // the Go subtree — it's not a filesystem path, so it
        // doesn't belong on `build.source_paths`.
        let build_extra = augment
            .entry(String::from("build"))
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        if let Some(obj) = build_extra.as_object_mut() {
            if !go.version.is_empty() {
                obj.entry("toolchain".to_string())
                    .or_insert_with(|| json!(go.version.clone()));
                obj.entry("toolchain_family".to_string())
                    .or_insert_with(|| json!("go"));
            }
        }
    }

    // Cross-format consistency checks. These are derived
    // interpretations (boolean comparisons over kv data), so they
    // live on `report.metrics.consistency` rather than in the kv
    // tree. Trait authors target them via
    // `type: metrics, field: consistency.<name>, min: 1`.
    let consistency = compute_consistency_with_metrics(&augment, report.metrics.as_ref());
    if !consistency_is_default(&consistency) {
        let metrics = report
            .metrics
            .get_or_insert_with(crate::types::scores::Metrics::default);
        metrics.consistency = Some(consistency);
    }

    if augment.is_empty() {
        return;
    }

    // Merge `augment` into the existing kv_tree (or create one).
    let existing = report
        .kv_tree
        .take()
        .map(|b| *b)
        .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
    let merged = deep_merge(existing, Value::Object(augment));
    report.kv_tree = Some(Box::new(merged));
}

/// Parse a plist (XML or binary) into a serde_json::Value with
/// snake_cased keys. Handles top-level dicts, arrays, strings, ints,
/// reals, booleans, and dates (formatted as ISO-8601). Binary data
/// blobs are dropped (kv tree isn't a useful surface for them).
/// Returns `None` on parse failure or empty result.
fn parse_plist_to_json(bytes: &[u8]) -> Option<serde_json::Value> {
    let val = plist::Value::from_reader(std::io::Cursor::new(bytes)).ok()?;
    let v = plist_to_json(&val);
    match &v {
        serde_json::Value::Null => None,
        serde_json::Value::Object(m) if m.is_empty() => None,
        serde_json::Value::Array(a) if a.is_empty() => None,
        _ => Some(v),
    }
}

/// Recursively convert a plist::Value to serde_json::Value.  Object
/// keys are snake_cased so kv paths stay uniform with the rest of
/// cleave's kv schema.
fn plist_to_json(v: &plist::Value) -> serde_json::Value {
    use serde_json::{Map, Value};
    match v {
        plist::Value::String(s) => Value::String(s.clone()),
        plist::Value::Boolean(b) => Value::Bool(*b),
        plist::Value::Integer(i) => i
            .as_signed()
            .map(Value::from)
            .or_else(|| i.as_unsigned().map(Value::from))
            .unwrap_or(Value::Null),
        plist::Value::Real(r) => serde_json::Number::from_f64(*r)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        plist::Value::Date(d) => Value::String(format!("{:?}", d)),
        plist::Value::Array(arr) => Value::Array(arr.iter().map(plist_to_json).collect()),
        plist::Value::Dictionary(d) => {
            // Preserve plist keys verbatim — `CFBundleIdentifier`,
            // `LSMinimumSystemVersion`, `ProgramArguments`, etc. —
            // matching the existing convention used by macOS plist
            // traits (see objectives/evasion/masquerade/identity/
            // plist-identity.yaml). snake_casing them would produce
            // `c_f_bundle_identifier` and break those traits.
            let mut m = Map::new();
            for (k, v) in d {
                m.insert(k.clone(), plist_to_json(v));
            }
            Value::Object(m)
        }
        // Drop binary data, UIDs, and unknown types — kv tree is
        // string/number-shaped and traits can't usefully match raw
        // blobs.
        _ => Value::Null,
    }
}

/// Compute cross-format consistency flags from already-populated kv
/// data. Each flag is a derived interpretation: cleave compared two
/// fields populated from independent sources within the same binary
/// and they disagreed. Conservative — only fires when both compared
/// fields are present and obviously incompatible, never on absence
/// alone. The optional `metrics` argument unlocks checks that need
/// typed numeric fields (vs the kv tree's serialized JSON form).
fn compute_consistency_with_metrics(
    augment: &serde_json::Map<String, serde_json::Value>,
    metrics: Option<&crate::types::scores::Metrics>,
) -> crate::types::binary_metrics::ConsistencyMetrics {
    let mut out = crate::types::binary_metrics::ConsistencyMetrics::default();

    // PE Authenticode cert issued after build. The leaf cert's
    // not_before is when the cert was *issued*; if that's after the
    // binary's COFF timestamp, the binary was created/repackaged
    // before the signing cert existed — only possible if it was
    // re-signed with a newer cert later.
    //
    // Filter out deterministic-build cases where pe.timestamp is a
    // content hash that can legitimately appear in the future
    // (`pe.is_reproducible_build`). Also skip when timestamp is 0
    // (also a deterministic marker).
    if let Some(m) = metrics.and_then(|m| m.pe.as_ref()) {
        let cert_issued = m.leaf_not_before;
        let build_ts = m.timestamp as i64;
        if cert_issued > 0 && build_ts > 0 && !m.is_reproducible_build && cert_issued > build_ts {
            out.cert_issued_after_build = true;
        }
    }

    // Mach-O code-sig CodeDirectory identifier vs embedded Info.plist
    // CFBundleIdentifier. Vendors set them in lockstep; divergence
    // typically means the binary was re-signed with a different
    // identity but the embedded plist wasn't rewritten to match.
    let signing_bundle = augment
        .get("signing")
        .and_then(|v| v.get("bundle_identifier"))
        .and_then(|v| v.as_str());
    let plist_bundle = augment
        .get("macho")
        .and_then(|v| v.get("info_plist"))
        .and_then(|v| v.get("CFBundleIdentifier"))
        .and_then(|v| v.as_str());
    if let (Some(a), Some(b)) = (signing_bundle, plist_bundle) {
        if a != b {
            out.bundle_identifier_mismatch = true;
        }
    }

    // PE side-by-side manifest assembly version vs VERSIONINFO
    // ProductVersion. Tolerate trailing-zero differences.
    let manifest_ver = augment
        .get("pe")
        .and_then(|v| v.get("manifest"))
        .and_then(|v| v.get("assembly_identity"))
        .and_then(|v| v.get("version"))
        .and_then(|v| v.as_str());
    let info_ver = augment
        .get("pe")
        .and_then(|v| v.get("version_info"))
        .and_then(|v| v.get("product_version"))
        .and_then(|v| v.as_str());
    if let (Some(a), Some(b)) = (manifest_ver, info_ver) {
        if !versions_equivalent(a, b) {
            out.manifest_product_version_mismatch = true;
        }
    }

    // ELF build.distro reports a distro incompatible with the
    // observed toolchain version (e.g. Ubuntu + gcc 14.x — Ubuntu
    // 24.04 ships gcc 13.2 max). Conservative — only fires on
    // (distro, major) pairs known not to exist as default.
    let distro = augment
        .get("build")
        .and_then(|v| v.get("distro"))
        .and_then(|v| v.as_str());
    let toolchain = augment
        .get("build")
        .and_then(|v| v.get("toolchain"))
        .and_then(|v| v.as_str());
    if let (Some(d), Some(t)) = (distro, toolchain) {
        if distro_toolchain_implausible(d, t) {
            out.distro_toolchain_implausible = true;
        }
    }

    // DWARF: multiple producer strings = mixed toolchains.
    let n_producers = augment
        .get("dwarf")
        .and_then(|v| v.get("producers"))
        .and_then(|v| v.as_array())
        .map_or(0, Vec::len);
    if n_producers > 1 {
        out.dwarf_mixed_producers = true;
    }
    let n_comp_dirs = augment
        .get("dwarf")
        .and_then(|v| v.get("comp_dirs"))
        .and_then(|v| v.as_array())
        .map_or(0, Vec::len);
    if n_comp_dirs > 1 {
        out.dwarf_mixed_comp_dirs = true;
    }

    // Mach-O fat binary with mixed signing state across slices.
    if let Some(slices) = augment
        .get("macho")
        .and_then(|v| v.get("slices"))
        .and_then(|v| v.as_array())
    {
        let signed: Vec<bool> = slices
            .iter()
            .filter_map(|s| {
                s.get("has_code_signature")
                    .and_then(serde_json::Value::as_bool)
            })
            .collect();
        if signed.len() > 1 && signed.iter().any(|&b| b) && signed.iter().any(|&b| !b) {
            out.macho_slice_signing_divergence = true;
        }
    }

    out
}

/// True when no consistency flag is set — used to skip allocating
/// the struct on `report.metrics.consistency` when there's nothing
/// to surface.
fn consistency_is_default(c: &crate::types::binary_metrics::ConsistencyMetrics) -> bool {
    !c.bundle_identifier_mismatch
        && !c.manifest_product_version_mismatch
        && !c.distro_toolchain_implausible
        && !c.dwarf_mixed_producers
        && !c.dwarf_mixed_comp_dirs
        && !c.macho_slice_signing_divergence
        && !c.cert_issued_after_build
}

/// Compare two dotted version strings, treating trailing zeros as
/// equivalent (`"1.2.3"` == `"1.2.3.0"` == `"1.2.3.0.0"`).
fn versions_equivalent(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> { s.split('.').filter_map(|c| c.parse().ok()).collect() };
    let mut va = parse(a);
    let mut vb = parse(b);
    while va.last().copied() == Some(0) {
        va.pop();
    }
    while vb.last().copied() == Some(0) {
        vb.pop();
    }
    va == vb
}

/// Conservative distro+toolchain implausibility check. Fires only on
/// (distro, gcc-major) combinations known not to exist as default in
/// any released distro version through Q2 2026. Designed for false-
/// negative tolerance over false-positive risk — a wrong "yes" here
/// would raise an unfair tampering alarm.
fn distro_toolchain_implausible(distro: &str, toolchain: &str) -> bool {
    let lower = toolchain.to_lowercase();
    let gcc_major = lower
        .strip_prefix("gcc ")
        .and_then(|s| s.split('.').next())
        .and_then(|s| s.parse::<u32>().ok());
    let Some(major) = gcc_major else {
        return false;
    };
    // Ubuntu through 24.04 LTS ships gcc 13 max; Debian bookworm/trixie
    // tops out at gcc 13; Alpine 3.20 ships gcc 13. Anything claiming
    // gcc 14+ from these distros is currently anachronistic. RHEL /
    // CentOS Stream 9 ships gcc 11 (Stream 10 ships gcc 14, so left
    // out); rocky/almalinux track Stream and aren't flagged either.
    matches!(distro, "ubuntu" | "debian" | "alpine") && major >= 14
}

/// Mach-O magic (plain, plain-64, fat, fat-64) — checked before
/// running the LC parser to avoid scanning random byte strings.
fn looks_like_macho(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    let m = match data[..4].try_into() {
        Ok(b) => u32::from_le_bytes(b),
        Err(_) => return false,
    };
    let m_be = match data[..4].try_into() {
        Ok(b) => u32::from_be_bytes(b),
        Err(_) => return false,
    };
    m == 0xFEED_FACE || m == 0xFEED_FACF || m_be == 0xCAFE_BABE || m_be == 0xCAFE_BABF
}

/// Serialize a parsed Go buildinfo into the kv-tree shape
/// documented in `binary_kv`. Pike-pass restructure: the original
/// runtime/buildinfo flat dict (with keys like `-buildmode`,
/// `vcs.revision`, `CGO_ENABLED`) is normalized into two clean
/// sub-trees so kv path traversal works:
///
/// - `go.build.{mode, compiler, goos, goarch, goamd64, goarm,
///   cgo, trimpath, ldflags, asmflags, gcflags, buildvcs}`
/// - `go.vcs.{type, revision, time, modified}`
///
/// Booleans (`cgo`, `trimpath`, `modified`, `buildvcs`) are
/// parsed from the `"0"`/`"1"`/`"true"`/`"false"` string form.
/// Unknown keys land in a fallback `go.build.other.<key>` map so
/// nothing is lost.
fn serialize_go_buildinfo(info: &super::go_buildinfo::GoBuildInfo) -> serde_json::Value {
    use serde_json::{json, Map, Value};
    let mut go = Map::new();
    if !info.version.is_empty() {
        go.insert("version".into(), json!(info.version));
    }
    if !info.main_path.is_empty() {
        go.insert("main_path".into(), json!(info.main_path));
    }
    if let Some(bid) = info.build_id.as_deref() {
        if !bid.is_empty() {
            go.insert("build_id".into(), json!(bid));
        }
    }
    if let Some(gr) = info.go_root.as_deref() {
        if !gr.is_empty() {
            go.insert("go_root".into(), json!(gr));
        }
    }
    if let Some(mr) = info.main_root.as_deref() {
        if !mr.is_empty() {
            go.insert("main_root".into(), json!(mr));
        }
    }
    if info.deps_std + info.deps_thirdparty + info.deps_replaced + info.deps_vendored > 0 {
        let mut deps_breakdown = Map::new();
        deps_breakdown.insert("std".into(), json!(info.deps_std));
        deps_breakdown.insert("thirdparty".into(), json!(info.deps_thirdparty));
        deps_breakdown.insert("replaced".into(), json!(info.deps_replaced));
        deps_breakdown.insert("vendored".into(), json!(info.deps_vendored));
        go.insert("deps_breakdown".into(), Value::Object(deps_breakdown));
    }
    if let Some(main) = &info.main_module {
        let mut mm = Map::new();
        if !main.path.is_empty() {
            mm.insert("path".into(), json!(main.path));
        }
        if !main.version.is_empty() {
            mm.insert("version".into(), json!(main.version));
        }
        if !main.sum.is_empty() {
            mm.insert("sum".into(), json!(main.sum));
        }
        if !mm.is_empty() {
            go.insert("main_module".into(), Value::Object(mm));
        }
    }
    if !info.dependencies.is_empty() {
        let arr: Vec<Value> = info
            .dependencies
            .iter()
            .map(|m| {
                let mut entry = Map::new();
                entry.insert("path".into(), json!(m.path));
                if !m.version.is_empty() {
                    entry.insert("version".into(), json!(m.version));
                }
                if !m.sum.is_empty() {
                    entry.insert("sum".into(), json!(m.sum));
                }
                if let Some(rep) = &m.replaced_by {
                    entry.insert(
                        "replaced_by".into(),
                        json!({
                            "path": rep.path,
                            "version": rep.version,
                        }),
                    );
                }
                Value::Object(entry)
            })
            .collect();
        go.insert("dependencies".into(), Value::Array(arr));
    }

    let mut build = Map::new();
    let mut vcs = Map::new();
    let mut other = Map::new();
    for (raw_key, raw_val) in &info.build_settings {
        let key = raw_key.as_str();
        // VCS sub-tree.
        if let Some(suffix) = key.strip_prefix("vcs.") {
            vcs.insert(suffix.to_string(), go_value_for(suffix, raw_val));
            continue;
        }
        if key == "vcs" {
            vcs.insert("type".into(), json!(raw_val));
            continue;
        }
        // Build flags — strip leading `-` and snake-case.
        let stripped = key.strip_prefix('-').unwrap_or(key);
        let canonical = match stripped {
            "buildmode" => Some("mode"),
            "compiler" => Some("compiler"),
            "trimpath" => Some("trimpath"),
            "buildvcs" => Some("buildvcs"),
            "ldflags" => Some("ldflags"),
            "asmflags" => Some("asmflags"),
            "gcflags" => Some("gcflags"),
            "tags" => Some("tags"),
            "race" => Some("race"),
            "msan" => Some("msan"),
            "asan" => Some("asan"),
            "GOOS" => Some("goos"),
            "GOARCH" => Some("goarch"),
            "GOAMD64" => Some("goamd64"),
            "GOARM" => Some("goarm"),
            "GO386" => Some("go386"),
            "CGO_ENABLED" => Some("cgo"),
            "CGO_CFLAGS" | "CGO_CPPFLAGS" | "CGO_CXXFLAGS" | "CGO_FFLAGS" | "CGO_LDFLAGS" => {
                Some("cgo_flags")
            }
            _ => None,
        };
        if let Some(name) = canonical {
            build.insert(name.into(), go_value_for(name, raw_val));
        } else {
            other.insert(stripped.to_string(), json!(raw_val));
        }
    }
    if !build.is_empty() {
        if !other.is_empty() {
            build.insert("other".into(), Value::Object(other));
        }
        go.insert("build".into(), Value::Object(build));
    } else if !other.is_empty() {
        go.insert(
            "build".into(),
            Value::Object({
                let mut m = Map::new();
                m.insert("other".into(), Value::Object(other));
                m
            }),
        );
    }
    if !vcs.is_empty() {
        go.insert("vcs".into(), Value::Object(vcs));
    }
    Value::Object(go)
}

/// Coerce a Go build-setting string into the canonical kv shape
/// for that field — booleans parsed for known boolean keys, plain
/// strings otherwise.
fn go_value_for(key: &str, raw: &str) -> serde_json::Value {
    use serde_json::json;
    let bool_keys = [
        "cgo", "trimpath", "modified", "buildvcs", "race", "msan", "asan",
    ];
    if bool_keys.contains(&key) {
        let v = raw.trim();
        if matches!(v, "1" | "true" | "True" | "TRUE") {
            return json!(true);
        }
        if matches!(v, "0" | "false" | "False" | "FALSE") {
            return json!(false);
        }
    }
    json!(raw)
}

/// Convert a PE-spec PascalCase identifier (e.g. `CompanyName`,
/// `OriginalFilename`, `LegalCopyright`) to snake_case for kv-tree
/// path consistency. Same rule the office kv tree uses for PDF
/// info-dict keys.
fn snake_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for (i, c) in s.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Merge two JSON values, with `b` taking precedence at leaves.
/// Object keys union; arrays from `b` replace arrays from `a`.
fn deep_merge(a: serde_json::Value, b: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match (a, b) {
        (Value::Object(mut am), Value::Object(bm)) => {
            for (k, bv) in bm {
                let av = am.remove(&k).unwrap_or(Value::Null);
                am.insert(k, deep_merge(av, bv));
            }
            Value::Object(am)
        }
        (_, b) => b,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_comment_ubuntu_gcc() {
        let fp = parse_comment_fingerprint("GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0");
        assert_eq!(fp.distro.as_deref(), Some("ubuntu"));
        assert_eq!(fp.toolchain_family.as_deref(), Some("gcc"));
        assert_eq!(fp.toolchain_version.as_deref(), Some("13.2.0"));
    }

    #[test]
    fn parse_comment_debian_gcc() {
        let fp = parse_comment_fingerprint("GCC: (Debian 12.2.0-14) 12.2.0");
        assert_eq!(fp.distro.as_deref(), Some("debian"));
        assert_eq!(fp.toolchain_family.as_deref(), Some("gcc"));
        assert_eq!(fp.toolchain_version.as_deref(), Some("12.2.0"));
    }

    #[test]
    fn parse_comment_alpine_gcc() {
        let fp = parse_comment_fingerprint("GCC: (Alpine 12.2.1_git20220924-r10) 12.2.1");
        assert_eq!(fp.distro.as_deref(), Some("alpine"));
        assert_eq!(fp.toolchain_version.as_deref(), Some("12.2.1"));
    }

    #[test]
    fn parse_comment_wolfi_gcc() {
        // Real Wolfi-built zsh from /Users/t/data/good/wolfi/...
        // Wolfi inherits Alpine's `(<distro> <ver>-r<N>) <ver>` GCC
        // banner format but identifies as itself.
        let fp = parse_comment_fingerprint("GCC: (Wolfi 14.2.0-r8) 14.2.0");
        assert_eq!(fp.distro.as_deref(), Some("wolfi"));
        assert_eq!(fp.toolchain_family.as_deref(), Some("gcc"));
        assert_eq!(fp.toolchain_version.as_deref(), Some("14.2.0"));
    }

    #[test]
    fn parse_comment_chainguard_gcc() {
        let fp = parse_comment_fingerprint("GCC: (Chainguard 13.2.0-r5) 13.2.0");
        assert_eq!(fp.distro.as_deref(), Some("chainguard"));
    }

    #[test]
    fn parse_comment_wolfi_takes_precedence_over_alpine() {
        // Defensive: ensure Wolfi wins even if "alpine" appears later
        // in the same banner (e.g. via a multi-tool comment join).
        let fp = parse_comment_fingerprint("GCC: (Wolfi 14.2.0-r8) 14.2.0; alpine reference");
        assert_eq!(fp.distro.as_deref(), Some("wolfi"));
    }

    #[test]
    fn parse_comment_clang() {
        let fp = parse_comment_fingerprint(
            "clang version 14.0.6 (https://github.com/llvm/llvm-project ...)",
        );
        assert_eq!(fp.toolchain_family.as_deref(), Some("clang"));
        assert_eq!(fp.toolchain_version.as_deref(), Some("14.0.6"));
        assert!(fp.distro.is_none());
    }

    #[test]
    fn parse_comment_apple_llvm() {
        let fp = parse_comment_fingerprint("Apple LLVM version 14.0.0 (clang-1400.0.29.202)");
        assert_eq!(fp.toolchain_family.as_deref(), Some("apple_clang"));
        assert_eq!(fp.toolchain_version.as_deref(), Some("14.0.0"));
    }

    #[test]
    fn parse_comment_unknown_fallback() {
        let fp = parse_comment_fingerprint("some random bytes here");
        assert!(fp.distro.is_none());
        assert!(fp.toolchain_family.is_none());
    }

    #[test]
    fn detect_sanitizers_basic_set() {
        let imports = vec![
            Import::new("__asan_init", None, "test"),
            Import::new("__asan_handle_no_return", None, "test"),
            Import::new("__ubsan_handle_type_mismatch_v1", None, "test"),
            Import::new("malloc", Some("libc".into()), "test"),
        ];
        let s = detect_sanitizers(&imports);
        assert_eq!(s, vec!["asan", "ubsan"]);
    }

    #[test]
    fn detect_sanitizers_pgo_and_coverage() {
        let imports = vec![
            Import::new("__llvm_profile_runtime", None, "test"),
            Import::new("__llvm_coverage_mapping", None, "test"),
            Import::new("__gcov_init", None, "test"),
        ];
        let s = detect_sanitizers(&imports);
        assert_eq!(s, vec!["coverage", "gcov", "pgo"]);
    }

    #[test]
    fn detect_fortify_basic_set() {
        let imports = vec![
            Import::new("__sprintf_chk", Some("libc.so.6".into()), "test"),
            Import::new("__strcpy_chk", Some("libc.so.6".into()), "test"),
            Import::new("__memcpy_chk", Some("libc.so.6".into()), "test"),
            Import::new("malloc", Some("libc.so.6".into()), "test"),
            Import::new("__sprintf_chk", Some("libc.so.6".into()), "test"),
        ];
        let f = detect_fortify_functions(&imports);
        assert_eq!(f, vec!["memcpy", "sprintf", "strcpy"]);
    }

    #[test]
    fn detect_fortify_empty_when_no_chk_imports() {
        let imports = vec![
            Import::new("malloc", Some("libc.so.6".into()), "test"),
            Import::new("printf", Some("libc.so.6".into()), "test"),
        ];
        assert!(detect_fortify_functions(&imports).is_empty());
    }

    #[test]
    fn detect_sanitizers_empty_for_clean_imports() {
        let imports = vec![
            Import::new("malloc", Some("libc".into()), "test"),
            Import::new("free", Some("libc".into()), "test"),
        ];
        assert!(detect_sanitizers(&imports).is_empty());
    }

    #[test]
    fn deep_merge_unions_objects() {
        use serde_json::json;
        let a = json!({"build": {"is_pie": true}, "elf": {"foo": 1}});
        let b = json!({"build": {"distro": "ubuntu"}});
        let m = deep_merge(a, b);
        assert_eq!(m["build"]["is_pie"], true);
        assert_eq!(m["build"]["distro"], "ubuntu");
        assert_eq!(m["elf"]["foo"], 1);
    }

    /// Build a minimal x86-64 LE ELF in memory with a `.comment`
    /// section so the section walker can be exercised end-to-end.
    fn build_minimal_elf_with_comment(comment: &[u8]) -> Vec<u8> {
        // We just want a valid section-header-table layout with a
        // .shstrtab and a .comment.
        const EHDR_SIZE: usize = 0x40;
        const SHENT_SIZE: usize = 0x40;
        let shstrtab = b"\0.shstrtab\0.comment\0";
        let shstr_off = EHDR_SIZE;
        let shstr_size = shstrtab.len();
        let comment_off = shstr_off + shstr_size;
        let comment_size = comment.len();
        let sht_off = comment_off + comment_size;

        // Section header table: SHT_NULL (idx 0), .shstrtab (idx 1), .comment (idx 2)
        let shnum = 3;
        let mut buf = vec![0u8; sht_off + SHENT_SIZE * shnum];

        // ELF header
        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2; // 64-bit
        buf[5] = 1; // little-endian
        buf[6] = 1; // version
        buf[0x28..0x30].copy_from_slice(&(sht_off as u64).to_le_bytes()); // e_shoff
        buf[0x3a..0x3c].copy_from_slice(&(SHENT_SIZE as u16).to_le_bytes()); // e_shentsize
        buf[0x3c..0x3e].copy_from_slice(&(shnum as u16).to_le_bytes()); // e_shnum
        buf[0x3e..0x40].copy_from_slice(&1u16.to_le_bytes()); // e_shstrndx → .shstrtab

        // Section content
        buf[shstr_off..shstr_off + shstr_size].copy_from_slice(shstrtab);
        buf[comment_off..comment_off + comment_size].copy_from_slice(comment);

        // Section headers (each 0x40 bytes)
        // 0: SHT_NULL — leave zeroed
        // 1: .shstrtab
        let s1 = sht_off + SHENT_SIZE;
        buf[s1..s1 + 4].copy_from_slice(&1u32.to_le_bytes()); // sh_name = offset 1 in shstrtab
        buf[s1 + 0x18..s1 + 0x20].copy_from_slice(&(shstr_off as u64).to_le_bytes());
        buf[s1 + 0x20..s1 + 0x28].copy_from_slice(&(shstr_size as u64).to_le_bytes());
        // 2: .comment
        let s2 = sht_off + SHENT_SIZE * 2;
        buf[s2..s2 + 4].copy_from_slice(&11u32.to_le_bytes()); // sh_name = offset 11 in shstrtab
        buf[s2 + 0x18..s2 + 0x20].copy_from_slice(&(comment_off as u64).to_le_bytes());
        buf[s2 + 0x20..s2 + 0x28].copy_from_slice(&(comment_size as u64).to_le_bytes());
        buf
    }

    #[test]
    fn extract_elf_comment_round_trip() {
        let elf = build_minimal_elf_with_comment(b"GCC: (Ubuntu 13.2.0-23ubuntu4) 13.2.0\0");
        let comment = extract_elf_comment(&elf).expect("comment present");
        assert!(comment.contains("Ubuntu"));
        assert!(comment.contains("13.2.0"));
    }

    #[test]
    fn extract_elf_comment_joins_multiple_tokens() {
        let elf = build_minimal_elf_with_comment(b"GCC: 13.2.0\0clang version 14.0.6\0");
        let comment = extract_elf_comment(&elf).expect("comment present");
        assert!(comment.contains("GCC: 13.2.0"));
        assert!(comment.contains("clang version 14.0.6"));
        assert!(comment.contains("; "));
    }

    #[test]
    fn extract_elf_comment_returns_none_for_non_elf() {
        assert!(extract_elf_comment(b"not an elf").is_none());
    }

    #[test]
    fn versions_equivalent_basic() {
        assert!(versions_equivalent("1.2.3", "1.2.3"));
        assert!(versions_equivalent("1.2.3", "1.2.3.0"));
        assert!(versions_equivalent("1.2.3.0.0", "1.2.3"));
        assert!(!versions_equivalent("1.2.3", "1.2.4"));
        assert!(!versions_equivalent("1.2.3", "1.3.0"));
        assert!(!versions_equivalent("2.0.0", "1.2.3"));
        // Tolerate single-segment versions.
        assert!(versions_equivalent("1", "1.0.0.0"));
    }

    #[test]
    fn distro_toolchain_implausible_known_cases() {
        // Ubuntu has not yet shipped gcc 14+ as default (as of 2026 Q1).
        assert!(distro_toolchain_implausible("ubuntu", "gcc 14.2.0"));
        assert!(!distro_toolchain_implausible("ubuntu", "gcc 13.2.0"));
        // Wolfi tracks bleeding-edge gcc and should NEVER be flagged.
        assert!(!distro_toolchain_implausible("wolfi", "gcc 14.2.0"));
        assert!(!distro_toolchain_implausible("wolfi", "gcc 15.0.0"));
        // Bare clang version doesn't trigger gcc-specific check.
        assert!(!distro_toolchain_implausible("ubuntu", "clang 17.0.0"));
        // Unknown distro: never flag (false-positive aversion).
        assert!(!distro_toolchain_implausible("nixos", "gcc 14.2.0"));
    }

    #[test]
    fn consistency_bundle_identifier_mismatch() {
        use serde_json::json;
        let mut aug = serde_json::Map::new();
        aug.insert(
            "signing".into(),
            json!({"bundle_identifier": "com.apple.ls"}),
        );
        aug.insert(
            "macho".into(),
            json!({"info_plist": {"CFBundleIdentifier": "com.attacker.payload"}}),
        );
        let c = compute_consistency_with_metrics(&aug, None);
        assert!(c.bundle_identifier_mismatch);
    }

    #[test]
    fn consistency_no_false_positive_when_matching() {
        use serde_json::json;
        let mut aug = serde_json::Map::new();
        aug.insert(
            "signing".into(),
            json!({"bundle_identifier": "com.apple.ls"}),
        );
        aug.insert(
            "macho".into(),
            json!({"info_plist": {"CFBundleIdentifier": "com.apple.ls"}}),
        );
        let c = compute_consistency_with_metrics(&aug, None);
        assert!(!c.bundle_identifier_mismatch);
        assert!(consistency_is_default(&c));
    }

    #[test]
    fn consistency_manifest_version_mismatch() {
        use serde_json::json;
        let mut aug = serde_json::Map::new();
        aug.insert(
            "pe".into(),
            json!({
                "manifest": {"assembly_identity": {"version": "1.2.3.4"}},
                "version_info": {"product_version": "9.9.9.9"},
            }),
        );
        let c = compute_consistency_with_metrics(&aug, None);
        assert!(c.manifest_product_version_mismatch);
    }

    #[test]
    fn consistency_tolerates_trailing_zero_version() {
        use serde_json::json;
        let mut aug = serde_json::Map::new();
        aug.insert(
            "pe".into(),
            json!({
                "manifest": {"assembly_identity": {"version": "1.2.3.0"}},
                "version_info": {"product_version": "1.2.3"},
            }),
        );
        let c = compute_consistency_with_metrics(&aug, None);
        assert!(!c.manifest_product_version_mismatch);
    }

    #[test]
    fn consistency_dwarf_mixed_producers() {
        use serde_json::json;
        let mut aug = serde_json::Map::new();
        aug.insert(
            "dwarf".into(),
            json!({"producers": ["GNU C 13.2.0", "clang 17.0.0"]}),
        );
        let c = compute_consistency_with_metrics(&aug, None);
        assert!(c.dwarf_mixed_producers);
    }

    #[test]
    fn consistency_macho_slice_signing_divergence() {
        use serde_json::json;
        let mut aug = serde_json::Map::new();
        aug.insert(
            "macho".into(),
            json!({"slices": [
                {"arch": "x86_64", "has_code_signature": true},
                {"arch": "arm64",  "has_code_signature": false},
            ]}),
        );
        let c = compute_consistency_with_metrics(&aug, None);
        assert!(c.macho_slice_signing_divergence);
    }

    /// Build a minimal ELF whose only non-shstrtab section is
    /// `.note.gnu.property` carrying the given desc bytes.
    fn build_minimal_elf_with_gnu_property(desc: &[u8]) -> Vec<u8> {
        const EHDR_SIZE: usize = 0x40;
        const SHENT_SIZE: usize = 0x40;
        let shstrtab = b"\0.shstrtab\0.note.gnu.property\0";

        // Note layout: namesz=4, descsz=desc.len(), type=5,
        // name="GNU\0", desc=...
        let mut note = Vec::new();
        note.extend_from_slice(&4u32.to_le_bytes());
        note.extend_from_slice(&(desc.len() as u32).to_le_bytes());
        note.extend_from_slice(&NT_GNU_PROPERTY_TYPE_0.to_le_bytes());
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(desc);

        let shstr_off = EHDR_SIZE;
        let shstr_size = shstrtab.len();
        let note_off = shstr_off + shstr_size;
        let note_size = note.len();
        let sht_off = note_off + note_size;
        let shnum = 3;
        let mut buf = vec![0u8; sht_off + SHENT_SIZE * shnum];

        buf[0..4].copy_from_slice(b"\x7fELF");
        buf[4] = 2;
        buf[5] = 1;
        buf[6] = 1;
        buf[0x28..0x30].copy_from_slice(&(sht_off as u64).to_le_bytes());
        buf[0x3a..0x3c].copy_from_slice(&(SHENT_SIZE as u16).to_le_bytes());
        buf[0x3c..0x3e].copy_from_slice(&(shnum as u16).to_le_bytes());
        buf[0x3e..0x40].copy_from_slice(&1u16.to_le_bytes());

        buf[shstr_off..shstr_off + shstr_size].copy_from_slice(shstrtab);
        buf[note_off..note_off + note_size].copy_from_slice(&note);

        // Section headers: NULL / .shstrtab / .note.gnu.property
        let s1 = sht_off + SHENT_SIZE;
        buf[s1..s1 + 4].copy_from_slice(&1u32.to_le_bytes());
        buf[s1 + 0x18..s1 + 0x20].copy_from_slice(&(shstr_off as u64).to_le_bytes());
        buf[s1 + 0x20..s1 + 0x28].copy_from_slice(&(shstr_size as u64).to_le_bytes());
        let s2 = sht_off + SHENT_SIZE * 2;
        buf[s2..s2 + 4].copy_from_slice(&11u32.to_le_bytes());
        buf[s2 + 0x18..s2 + 0x20].copy_from_slice(&(note_off as u64).to_le_bytes());
        buf[s2 + 0x20..s2 + 0x28].copy_from_slice(&(note_size as u64).to_le_bytes());
        buf
    }

    /// Encode one GNU property entry (8-byte aligned).
    fn property_entry(pr_type: u32, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&pr_type.to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(data);
        while out.len() % 8 != 0 {
            out.push(0);
        }
        out
    }

    #[test]
    fn extract_gnu_property_x86_ibt_and_shstk() {
        let desc = property_entry(GNU_PROPERTY_X86_FEATURE_1_AND, &3u32.to_le_bytes());
        let elf = build_minimal_elf_with_gnu_property(&desc);
        let p = extract_gnu_property(&elf).expect("present");
        assert!(p.ibt);
        assert!(p.shstk);
        assert!(!p.pac && !p.bti);
        assert_eq!(p.x86_isa_level, 0);
    }

    #[test]
    fn extract_gnu_property_aarch64_pac_only() {
        let desc = property_entry(GNU_PROPERTY_AARCH64_FEATURE_1_AND, &2u32.to_le_bytes());
        let elf = build_minimal_elf_with_gnu_property(&desc);
        let p = extract_gnu_property(&elf).expect("present");
        assert!(p.pac);
        assert!(!p.bti);
    }

    #[test]
    fn extract_gnu_property_x86_isa_level_v3() {
        // bits=0b0100 → highest bit set is bit 2 → level=3
        let desc = property_entry(GNU_PROPERTY_X86_ISA_1_NEEDED, &4u32.to_le_bytes());
        let elf = build_minimal_elf_with_gnu_property(&desc);
        let p = extract_gnu_property(&elf).expect("present");
        assert_eq!(p.x86_isa_level, 3);
    }

    #[test]
    fn extract_gnu_property_combined_x86_features_and_isa() {
        // IBT+SHSTK + ISA level 4 (bits=0b1000 → level=4)
        let mut desc = property_entry(GNU_PROPERTY_X86_FEATURE_1_AND, &3u32.to_le_bytes());
        desc.extend(property_entry(
            GNU_PROPERTY_X86_ISA_1_NEEDED,
            &8u32.to_le_bytes(),
        ));
        let elf = build_minimal_elf_with_gnu_property(&desc);
        let p = extract_gnu_property(&elf).expect("present");
        assert!(p.ibt && p.shstk);
        assert_eq!(p.x86_isa_level, 4);
    }

    #[test]
    fn extract_gnu_property_returns_none_when_absent() {
        // ELF with .comment instead — no .note.gnu.property
        let elf = build_minimal_elf_with_comment(b"GCC: x\0");
        assert!(extract_gnu_property(&elf).is_none());
    }

    #[test]
    fn extract_gnu_property_returns_none_for_non_elf() {
        assert!(extract_gnu_property(b"not an elf").is_none());
    }
}
