//! DWARF compilation-unit metadata extraction for unstripped ELF
//! binaries.  Surfaces the per-CU attributes that carry the richest
//! build-environment attribution available in any binary format:
//!
//! - **DW_AT_producer** — full compile command line, e.g.
//!   `"GNU C17 13.2.0 -mtune=generic -march=x86-64 -O2 -fstack-protector-strong"`.
//!   Distinguishes Ubuntu/Debian/Wolfi/Chainguard GCC builds, MSVC,
//!   clang versions, Rust, Go's `gccgo`, etc.
//! - **DW_AT_comp_dir** — build directory at compile time, e.g.
//!   `"/builddir/build/BUILD/glibc-2.34/build-x86_64-linux"`.
//!   Leaks the build host's filesystem layout — distros use
//!   distinctive build-root patterns (Debian: `/build/<pkg>-*`,
//!   Fedora: `/builddir/build/BUILD/`, Wolfi: `/home/build/`,
//!   Yocto: `/work/<arch>/`).
//! - **DW_AT_name** — main source filename per CU, capped per file.
//! - **DW_AT_language** — source language (C, C++, Rust, Go, etc).
//!
//! Stripped binaries have no `.debug_*` sections and the extractor
//! returns `None`. Most malware is stripped, so this is primarily an
//! attribution surface for legitimate vendor binaries — exactly what
//! we need for supply-chain swap detection.

use gimli::{
    DebugAbbrev, DebugInfo, DebugLine, DebugLineStr, DebugStr, DwLang, EndianSlice, LittleEndian,
    Reader, RunTimeEndian,
};
use std::collections::BTreeSet;

/// Structured DWARF attribution data.  All collections are sorted +
/// deduplicated so they're stable across reanalysis.
#[derive(Debug, Default, Clone)]
pub(crate) struct DwarfMetadata {
    /// Distinct DW_AT_producer strings observed across CUs.
    pub producers: Vec<String>,
    /// Distinct DW_AT_comp_dir directories observed across CUs.
    pub comp_dirs: Vec<String>,
    /// Distinct DW_AT_language values mapped to canonical names.
    pub languages: Vec<String>,
    /// First N main-source filenames (capped to keep the kv tree small).
    pub source_files: Vec<String>,
    /// Total compilation-unit count.
    pub cu_count: u32,
}

impl DwarfMetadata {
    fn is_empty(&self) -> bool {
        self.producers.is_empty()
            && self.comp_dirs.is_empty()
            && self.languages.is_empty()
            && self.source_files.is_empty()
            && self.cu_count == 0
    }
}

/// Maximum source-file names to retain. Real binaries can have
/// thousands of CUs (one per .o); we just need enough for attribution.
const MAX_SOURCE_FILES: usize = 32;

/// Extract DWARF metadata from raw ELF bytes. Returns `None` for
/// non-ELF input, stripped binaries, or when DWARF parsing fails at
/// any structural level. Lenient by design — partial recovery is
/// preferred over hard failure.
#[must_use]
pub(crate) fn extract(data: &[u8]) -> Option<DwarfMetadata> {
    if data.len() < 0x40 || &data[..4] != b"\x7fELF" {
        return None;
    }

    let debug_info_data = read_section(data, b".debug_info")?;
    let debug_abbrev_data = read_section(data, b".debug_abbrev").unwrap_or(&[]);
    let debug_str_data = read_section(data, b".debug_str").unwrap_or(&[]);
    let debug_line_str_data = read_section(data, b".debug_line_str").unwrap_or(&[]);
    let debug_line_data = read_section(data, b".debug_line").unwrap_or(&[]);

    let endian = if data[5] == 1 {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };

    // gimli's RunTimeEndian variant requires a generic; we can use
    // EndianSlice<LittleEndian> for the LE case which is the dominant
    // form. BE ELFs are rare; bail on them rather than templating.
    if !matches!(endian, RunTimeEndian::Little) {
        return None;
    }

    let endian = LittleEndian;
    let debug_info = DebugInfo::new(debug_info_data, endian);
    let debug_abbrev = DebugAbbrev::new(debug_abbrev_data, endian);
    let debug_str = DebugStr::new(debug_str_data, endian);
    let debug_line_str = DebugLineStr::from(EndianSlice::new(debug_line_str_data, endian));
    let debug_line = DebugLine::new(debug_line_data, endian);

    let mut out = DwarfMetadata::default();
    let mut producers = BTreeSet::new();
    let mut comp_dirs = BTreeSet::new();
    let mut languages = BTreeSet::new();
    let mut source_files: Vec<String> = Vec::new();

    let mut units = debug_info.units();
    while let Ok(Some(header)) = units.next() {
        out.cu_count = out.cu_count.saturating_add(1);
        let abbrevs = match header.abbreviations(&debug_abbrev) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let mut entries = header.entries(&abbrevs);
        // The first DIE in each unit is the DW_TAG_compile_unit.
        let Ok(Some((_, root))) = entries.next_dfs() else {
            continue;
        };
        let mut cu_name: Option<String> = None;
        let mut cu_comp_dir: Option<String> = None;

        let mut attrs = root.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_producer => {
                    if let Some(s) = attr_string(&attr, &header, &debug_str, &debug_line_str) {
                        producers.insert(s);
                    }
                }
                gimli::DW_AT_comp_dir => {
                    if let Some(s) = attr_string(&attr, &header, &debug_str, &debug_line_str) {
                        cu_comp_dir = Some(s.clone());
                        comp_dirs.insert(s);
                    }
                }
                gimli::DW_AT_name => {
                    if let Some(s) = attr_string(&attr, &header, &debug_str, &debug_line_str) {
                        cu_name = Some(s);
                    }
                }
                gimli::DW_AT_language => {
                    if let gimli::AttributeValue::Language(lang) = attr.value() {
                        languages.insert(language_name(lang).to_string());
                    }
                }
                _ => {}
            }
        }

        if let Some(name) = cu_name {
            if source_files.len() < MAX_SOURCE_FILES {
                let full = match cu_comp_dir.as_deref() {
                    Some(dir) if !name.starts_with('/') => format!("{}/{}", dir, name),
                    _ => name,
                };
                if !source_files.contains(&full) {
                    source_files.push(full);
                }
            }
        }

        // Suppress unused-variable for the line-program reader: a
        // future extractor pass may want per-CU file table info.
        let _ = &debug_line;
    }

    out.producers = producers.into_iter().collect();
    out.comp_dirs = comp_dirs.into_iter().collect();
    out.languages = languages.into_iter().collect();
    out.source_files = source_files;

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Resolve an attribute value to a UTF-8 string.  Handles direct
/// strings, indirect `.debug_str` references, and `.debug_line_str`
/// references (DWARF 5).
fn attr_string<R: Reader>(
    attr: &gimli::Attribute<R>,
    header: &gimli::UnitHeader<R>,
    debug_str: &DebugStr<R>,
    debug_line_str: &DebugLineStr<R>,
) -> Option<String> {
    match attr.value() {
        gimli::AttributeValue::String(s) => s.to_string_lossy().ok().map(std::borrow::Cow::into_owned),
        gimli::AttributeValue::DebugStrRef(off) => debug_str
            .get_str(off)
            .ok()
            .and_then(|r| r.to_string_lossy().ok().map(std::borrow::Cow::into_owned)),
        gimli::AttributeValue::DebugLineStrRef(off) => debug_line_str
            .get_str(off)
            .ok()
            .and_then(|r| r.to_string_lossy().ok().map(std::borrow::Cow::into_owned)),
        gimli::AttributeValue::DebugStrRefSup(_) => None,
        _ => {
            let _ = header;
            None
        }
    }
}

/// Map a DW_LANG_* constant to a human-readable canonical name.
/// Unknown values fall through to the raw `DW_LANG_<n>` form.
fn language_name(lang: DwLang) -> &'static str {
    match lang {
        gimli::DW_LANG_C89 | gimli::DW_LANG_C99 | gimli::DW_LANG_C11 | gimli::DW_LANG_C17 => "c",
        gimli::DW_LANG_C => "c",
        gimli::DW_LANG_C_plus_plus
        | gimli::DW_LANG_C_plus_plus_03
        | gimli::DW_LANG_C_plus_plus_11
        | gimli::DW_LANG_C_plus_plus_14 => "cpp",
        gimli::DW_LANG_Rust => "rust",
        gimli::DW_LANG_Go => "go",
        gimli::DW_LANG_Swift => "swift",
        gimli::DW_LANG_ObjC => "objc",
        gimli::DW_LANG_ObjC_plus_plus => "objcpp",
        gimli::DW_LANG_Fortran77
        | gimli::DW_LANG_Fortran90
        | gimli::DW_LANG_Fortran95
        | gimli::DW_LANG_Fortran03
        | gimli::DW_LANG_Fortran08 => "fortran",
        gimli::DW_LANG_Ada83 | gimli::DW_LANG_Ada95 => "ada",
        gimli::DW_LANG_Haskell => "haskell",
        gimli::DW_LANG_OCaml => "ocaml",
        gimli::DW_LANG_Mips_Assembler => "asm",
        _ => "unknown",
    }
}

/// Locate a named ELF section and return its byte slice. Lifted from
/// `binary_extractors::read_section`'s LE-only fast path. Lenient —
/// returns `None` for malformed inputs rather than propagating errors.
fn read_section<'a>(data: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    if data.len() < 0x40 || &data[..4] != b"\x7fELF" {
        return None;
    }
    let is_64 = data[4] == 2;

    let (e_shoff, e_shentsize, e_shnum, e_shstrndx) = if is_64 {
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

    let shstr_hdr = read_shdr(data, e_shoff, e_shentsize, e_shstrndx, is_64)?;
    let (shstr_off, shstr_size) = (shstr_hdr.sh_offset as usize, shstr_hdr.sh_size as usize);
    if shstr_off.checked_add(shstr_size)? > data.len() {
        return None;
    }
    let shstrings = &data[shstr_off..shstr_off + shstr_size];

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn extract_returns_none_for_non_elf() {
        assert!(extract(b"random bytes here").is_none());
    }

    #[test]
    fn extract_returns_none_for_truncated_elf() {
        let buf = b"\x7fELF\x02\x01\x01\x00".to_vec();
        assert!(extract(&buf).is_none());
    }

    #[test]
    fn language_name_known_constants() {
        assert_eq!(language_name(gimli::DW_LANG_C99), "c");
        assert_eq!(language_name(gimli::DW_LANG_Rust), "rust");
        assert_eq!(language_name(gimli::DW_LANG_Go), "go");
        assert_eq!(language_name(gimli::DW_LANG_C_plus_plus_14), "cpp");
    }

    #[test]
    fn language_name_unknown_falls_through() {
        // DW_LANG values >= 0x8000 are vendor-specific.
        assert_eq!(language_name(DwLang(0xC000)), "unknown");
    }
}
