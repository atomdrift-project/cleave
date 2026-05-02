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
        (shoff as usize, shentsize as usize, shnum as usize, shstrndx as usize)
    } else {
        if data.len() < 0x34 {
            return None;
        }
        let shoff = u32::from_le_bytes(data[0x20..0x24].try_into().ok()?);
        let shentsize = u16::from_le_bytes(data[0x2e..0x30].try_into().ok()?);
        let shnum = u16::from_le_bytes(data[0x30..0x32].try_into().ok()?);
        let shstrndx = u16::from_le_bytes(data[0x32..0x34].try_into().ok()?);
        (shoff as usize, shentsize as usize, shnum as usize, shstrndx as usize)
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
        let s = imp
            .symbol
            .as_str()
            .trim_start_matches('_');
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
            fp.toolchain_version = token.map(|t| t.trim().to_string()).filter(|s| !s.is_empty());
        }
    } else if comment.contains("Apple LLVM") || comment.contains("Apple clang") {
        fp.toolchain_family = Some("apple_clang".into());
        if let Some(pos) = comment.find("version ") {
            let rest = &comment[pos + "version ".len()..];
            let token = rest.split([' ', '(', ')']).next();
            fp.toolchain_version = token.map(|t| t.trim().to_string()).filter(|s| !s.is_empty());
        }
    } else if comment.contains("clang version") {
        fp.toolchain_family = Some("clang".into());
        if let Some(pos) = comment.find("clang version ") {
            let rest = &comment[pos + "clang version ".len()..];
            let token = rest.split([' ', '(', ')']).next();
            fp.toolchain_version = token.map(|t| t.trim().to_string()).filter(|s| !s.is_empty());
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
    let is_pe = raw_data.len() > 0x40
        && raw_data.get(..2) == Some(b"MZ".as_ref());
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

        if !pe_extra.is_empty() {
            augment.insert("pe".into(), Value::Object(pe_extra));
        }
        if !hashes_extra.is_empty() {
            augment.insert("hashes".into(), Value::Object(hashes_extra));
        }
    }

    // ELF .comment / .interp / .GCC.command.line
    if &raw_data.get(..4) == &Some(b"\x7fELF".as_ref()) {
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
                    build_extra.insert(
                        "toolchain".into(),
                        json!(format!("{} {}", family, version)),
                    );
                }
            }
        }
        if let Some(interp) = extract_elf_interp(raw_data) {
            elf_extra.insert("interpreter".into(), json!(interp));
        }
        if let Some(cmdline) = extract_gcc_command_line(raw_data) {
            build_extra.insert("command_line".into(), json!(cmdline));
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
        if let Some(lc) = super::macho_extractors::extract(raw_data) {
            let mut macho_extra = serde_json::Map::new();

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
            if let Some((cs_off, cs_size)) = lc.code_signature {
                if let Ok(cs) = super::macho_codesign::parse_code_signature(
                    raw_data, cs_off, cs_size,
                ) {
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
                            obj.insert(
                                "authorities".into(),
                                json!(cs.authorities.clone()),
                            );
                        }
                        if cs.is_notarized {
                            obj.insert("notarized".into(), json!(true));
                        }
                        if cs.has_hardened_runtime {
                            obj.entry("hardened_runtime".to_string())
                                .or_insert_with(|| json!(true));
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

            if !macho_extra.is_empty() {
                augment.insert("macho".into(), Value::Object(macho_extra));
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
    if !bp.usernames.is_empty()
        || !bp.source_dirs.is_empty()
        || !bp.full_paths.is_empty()
    {
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
    m == 0xFEED_FACE
        || m == 0xFEED_FACF
        || m_be == 0xCAFE_BABE
        || m_be == 0xCAFE_BABF
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
            vcs.insert(
                suffix.to_string(),
                go_value_for(suffix, raw_val),
            );
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
            "CGO_CFLAGS"
            | "CGO_CPPFLAGS"
            | "CGO_CXXFLAGS"
            | "CGO_FFLAGS"
            | "CGO_LDFLAGS" => Some("cgo_flags"),
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
        let fp =
            parse_comment_fingerprint("GCC: (Chainguard 13.2.0-r5) 13.2.0");
        assert_eq!(fp.distro.as_deref(), Some("chainguard"));
    }

    #[test]
    fn parse_comment_wolfi_takes_precedence_over_alpine() {
        // Defensive: ensure Wolfi wins even if "alpine" appears later
        // in the same banner (e.g. via a multi-tool comment join).
        let fp = parse_comment_fingerprint(
            "GCC: (Wolfi 14.2.0-r8) 14.2.0; alpine reference",
        );
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
        let fp =
            parse_comment_fingerprint("Apple LLVM version 14.0.0 (clang-1400.0.29.202)");
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
        let desc = property_entry(
            GNU_PROPERTY_AARCH64_FEATURE_1_AND,
            &2u32.to_le_bytes(),
        );
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
