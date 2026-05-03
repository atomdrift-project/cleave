//! Mach-O load-command extractor — byte-pattern walker for the
//! string-typed metadata that goblin doesn't surface as plain
//! strings (LC_UUID, LC_BUILD_VERSION tool array, LC_LOAD_DYLIB
//! paths, LC_RPATH, LC_ID_DYLIB, LC_SOURCE_VERSION, LC_LINKER_OPTION).
//!
//! These are the fields Apple's `otool -l` / `codesign -dv` print
//! and that malware authors regularly leak through:
//!
//! - **LC_UUID** — 16-byte build identifier; unique per build.
//!   Apple uses it as the primary clustering key for crash reports.
//! - **LC_BUILD_VERSION** — platform (macOS/iOS/...), minimum OS
//!   version, SDK version, and a per-tool version array (clang,
//!   swiftc, ld) — the cleanest compiler-attribution surface in
//!   any binary format.
//! - **LC_LOAD_DYLIB** family — every linked framework or dylib
//!   with its exact compatibility/current versions.  Reveals
//!   target macOS version, framework dependencies, and
//!   `@executable_path/...` injection paths.
//! - **LC_RPATH** — runtime library search paths.
//! - **LC_ID_DYLIB** — install-name for `.dylib` files.
//! - **LC_SOURCE_VERSION** — user-set source-version stamp.
//! - **LC_LINKER_OPTION** — linker flags carried from `.o` files.
//!
//! All parsing is endianness-agnostic for LE Mach-Os (the
//! overwhelming majority); BE Mach-Os fall back to None.  Fat /
//! universal binaries are dispatched by reading the first slice.

use serde::{Deserialize, Serialize};

// --- Mach-O magic constants ---
const MH_MAGIC: u32 = 0xFEED_FACE;
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_MAGIC_64: u32 = 0xCAFE_BABF;

// --- LC_* command IDs (low bits; high bit 0x80000000 is REQ_DYLD,
//     we mask it off before comparing) ---
const LC_UUID: u32 = 0x1B;
const LC_LOAD_DYLIB: u32 = 0x0C;
const LC_ID_DYLIB: u32 = 0x0D;
const LC_LOAD_WEAK_DYLIB: u32 = 0x18;
const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
const LC_REEXPORT_DYLIB: u32 = 0x1F;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x23;
const LC_RPATH: u32 = 0x1C;
const LC_SOURCE_VERSION: u32 = 0x2A;
const LC_LINKER_OPTION: u32 = 0x2D;
const LC_BUILD_VERSION: u32 = 0x32;
const LC_CODE_SIGNATURE: u32 = 0x1D;
const LC_SEGMENT: u32 = 0x01;
const LC_SEGMENT_64: u32 = 0x19;

const LC_REQ_DYLD: u32 = 0x8000_0000;

const MAX_LOAD_COMMANDS: usize = 4096;
const MAX_LC_PAYLOAD: usize = 1 << 20;

/// One row per slice in a Mach-O fat (universal) binary.  Plain
/// (non-fat) Mach-Os return a single entry. Used by binary_extractors
/// to surface `macho.slices[]` for cross-slice consistency checks
/// (UUID drift across slices is a tamper signal — vendors typically
/// rebuild all slices simultaneously and they share UUIDs).
#[derive(Debug, Clone)]
pub(crate) struct SliceSummary {
    /// Slice CPU architecture name: `"x86_64"`, `"arm64"`, `"arm64e"`,
    /// `"i386"`, `"ppc"`, `"ppc64"`, or `"unknown"`.
    pub arch: String,
    /// LC_UUID hex (canonical hyphenated form), or `None` if absent.
    pub uuid: Option<String>,
    /// File offset where this slice begins (0 for non-fat Mach-O).
    pub file_offset: u64,
    /// Whether this slice carries an LC_CODE_SIGNATURE blob.
    pub has_code_signature: bool,
}

/// Walk all slices in a Mach-O fat binary, returning one summary
/// per slice. Plain Mach-O returns a single-element vec. Used to
/// detect tampering where one slice has a different UUID or signing
/// state than the rest.
#[must_use]
pub(crate) fn extract_all_slices(data: &[u8]) -> Vec<SliceSummary> {
    let mut out = Vec::new();
    for (offset, is_64) in iterate_slice_starts(data) {
        let arch = read_arch_name(data, offset, is_64);
        let mut uuid = None;
        let mut has_cs = false;
        if let Some(after) = parse_header(data, offset, is_64) {
            if let Some(lc) = parse_load_commands(data, after.cmds_offset, after.ncmds) {
                uuid = lc.uuid;
                has_cs = lc.code_signature.is_some();
            }
        }
        out.push(SliceSummary {
            arch,
            uuid,
            file_offset: offset as u64,
            has_code_signature: has_cs,
        });
    }
    out
}

/// Yield (offset, is_64) for every Mach-O slice in `data`. Plain
/// Mach-O returns one entry; FAT_MAGIC fans out to N.
fn iterate_slice_starts(data: &[u8]) -> Vec<(usize, bool)> {
    let mut out = Vec::new();
    if data.len() < 8 {
        return out;
    }
    let magic_le = match data[..4].try_into() {
        Ok(b) => u32::from_le_bytes(b),
        Err(_) => return out,
    };
    let magic_be = match data[..4].try_into() {
        Ok(b) => u32::from_be_bytes(b),
        Err(_) => return out,
    };
    if magic_le == MH_MAGIC_64 {
        out.push((0, true));
        return out;
    }
    if magic_le == MH_MAGIC {
        out.push((0, false));
        return out;
    }
    if magic_be == FAT_MAGIC || magic_be == FAT_MAGIC_64 {
        let nfat = match data[4..8].try_into() {
            Ok(b) => u32::from_be_bytes(b) as usize,
            Err(_) => return out,
        };
        let entry_size = if magic_be == FAT_MAGIC_64 { 32 } else { 20 };
        for i in 0..nfat.min(32) {
            let entry_off = 8 + i * entry_size;
            if entry_off + entry_size > data.len() {
                break;
            }
            let slice_off: usize = if magic_be == FAT_MAGIC_64 {
                match data[entry_off + 8..entry_off + 16].try_into() {
                    Ok(b) => u64::from_be_bytes(b) as usize,
                    Err(_) => continue,
                }
            } else {
                match data[entry_off + 8..entry_off + 12].try_into() {
                    Ok(b) => u32::from_be_bytes(b) as usize,
                    Err(_) => continue,
                }
            };
            if slice_off + 4 > data.len() {
                continue;
            }
            let inner = match data[slice_off..slice_off + 4].try_into() {
                Ok(b) => u32::from_le_bytes(b),
                Err(_) => continue,
            };
            if inner == MH_MAGIC_64 {
                out.push((slice_off, true));
            } else if inner == MH_MAGIC {
                out.push((slice_off, false));
            }
        }
    }
    out
}

/// Decode a slice's CPU type / subtype into a canonical arch name.
/// Falls back to `"unknown"` for unsupported types.
fn read_arch_name(data: &[u8], header_off: usize, is_64: bool) -> String {
    if header_off + 12 > data.len() {
        return "unknown".to_string();
    }
    let cputype = match data[header_off + 4..header_off + 8].try_into() {
        Ok(b) => u32::from_le_bytes(b),
        Err(_) => return "unknown".to_string(),
    };
    let cpusubtype = match data[header_off + 8..header_off + 12].try_into() {
        Ok(b) => u32::from_le_bytes(b),
        Err(_) => return "unknown".to_string(),
    };
    cputype_name(cputype, cpusubtype, is_64).to_string()
}

/// Mach-O CPU type constants → canonical arch name. The list mirrors
/// what `lipo -archs` prints. cpu_subtype is used to disambiguate
/// arm64 vs arm64e (Apple Silicon PAC-enabled).
fn cputype_name(cputype: u32, cpusubtype: u32, is_64: bool) -> &'static str {
    const CPU_TYPE_X86: u32 = 0x7;
    const CPU_TYPE_X86_64: u32 = 0x01000007;
    const CPU_TYPE_ARM: u32 = 0xC;
    const CPU_TYPE_ARM64: u32 = 0x0100000C;
    const CPU_TYPE_ARM64_32: u32 = 0x0200000C;
    const CPU_TYPE_PPC: u32 = 0x12;
    const CPU_TYPE_PPC64: u32 = 0x01000012;
    // arm64e (Apple Silicon with PAC) carries a specific cpusubtype.
    const CPU_SUBTYPE_ARM64E: u32 = 2;
    let cpusubtype_masked = cpusubtype & 0x00FF_FFFF;
    match cputype {
        CPU_TYPE_X86_64 => "x86_64",
        CPU_TYPE_X86 => "i386",
        CPU_TYPE_ARM64 => {
            if cpusubtype_masked == CPU_SUBTYPE_ARM64E {
                "arm64e"
            } else {
                "arm64"
            }
        }
        CPU_TYPE_ARM64_32 => "arm64_32",
        CPU_TYPE_ARM => "arm",
        CPU_TYPE_PPC64 => "ppc64",
        CPU_TYPE_PPC => "ppc",
        _ => {
            let _ = is_64;
            "unknown"
        }
    }
}

/// Recovered Mach-O load-command data.  Empty fields drop from the
/// kv tree.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct MachoLoadCommands {
    pub uuid: Option<String>,
    pub build_version: Option<MachoBuildVersion>,
    pub source_version: Option<String>,
    pub id_dylib: Option<String>,
    pub load_dylibs: Vec<MachoDylib>,
    pub rpath: Vec<String>,
    pub linker_options: Vec<String>,
    /// File offset + size of the LC_CODE_SIGNATURE blob, when present.
    /// Callers feed this to `macho_codesign::parse_code_signature` to
    /// recover team_id / entitlements / authorities.
    pub code_signature: Option<(u32, u32)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MachoBuildVersion {
    /// Platform: `"macOS"`, `"iOS"`, `"tvOS"`, `"watchOS"`,
    /// `"macCatalyst"`, `"iOSSimulator"`, `"driverkit"`, etc.
    pub platform: String,
    /// Minimum supported OS version (e.g. `"10.13.0"`).
    pub minos: String,
    /// SDK version this binary was built against (e.g. `"11.0.0"`).
    pub sdk: String,
    /// Build tools used: clang, swiftc, ld, lld each with a version.
    pub tools: Vec<MachoTool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MachoTool {
    pub tool: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MachoDylib {
    pub path: String,
    /// One of `"load"`, `"weak"`, `"lazy"`, `"reexport"`, `"upward"`.
    pub kind: String,
    /// Compatibility version (encoded X.Y.Z).
    pub compatibility_version: String,
    /// Current version (encoded X.Y.Z).
    pub current_version: String,
}

/// Extract load-command data from raw Mach-O bytes.  Returns
/// `None` for non-Mach-O input (unrecognized magic) or when the
/// command list looks structurally broken.
#[must_use]
pub(crate) fn extract(data: &[u8]) -> Option<MachoLoadCommands> {
    let (header_off, is_64) = locate_first_macho_slice(data)?;
    let after_header = parse_header(data, header_off, is_64)?;
    let mut out =
        parse_load_commands(data, after_header.cmds_offset, after_header.ncmds)?;
    // LC_CODE_SIGNATURE.dataoff is slice-relative.  Promote to a
    // file-absolute offset so callers (binary_extractors) can pass
    // the raw file bytes without having to track which slice we
    // dispatched to.
    if header_off > 0 {
        if let Some((off, sz)) = out.code_signature {
            out.code_signature = Some((off.saturating_add(header_off as u32), sz));
        }
    }
    Some(out)
}

struct HeaderInfo {
    cmds_offset: usize,
    ncmds: usize,
}

/// Find the start of the (first) Mach-O slice. For fat binaries we
/// dispatch to the first arch slice; for plain Mach-Os, this is the
/// file start.  Returns `(offset, is_64bit)`.
fn locate_first_macho_slice(data: &[u8]) -> Option<(usize, bool)> {
    if data.len() < 8 {
        return None;
    }
    let magic_le = u32::from_le_bytes(data[..4].try_into().ok()?);
    let magic_be = u32::from_be_bytes(data[..4].try_into().ok()?);

    // Plain Mach-O.
    if magic_le == MH_MAGIC_64 {
        return Some((0, true));
    }
    if magic_le == MH_MAGIC {
        return Some((0, false));
    }

    // Fat / universal binaries — pick the first slice.
    if magic_be == FAT_MAGIC || magic_be == FAT_MAGIC_64 {
        let nfat = u32::from_be_bytes(data[4..8].try_into().ok()?) as usize;
        if nfat == 0 {
            return None;
        }
        let entry_size = if magic_be == FAT_MAGIC_64 { 32 } else { 20 };
        let entry_off = 8;
        if entry_off + entry_size > data.len() {
            return None;
        }
        // Slice offset lives at bytes 8..16 in entry (big-endian
        // u64 for FAT_MAGIC_64; big-endian u32 at 8..12 for legacy
        // FAT_MAGIC).
        let slice_off: usize = if magic_be == FAT_MAGIC_64 {
            u64::from_be_bytes(data[entry_off + 8..entry_off + 16].try_into().ok()?) as usize
        } else {
            u32::from_be_bytes(data[entry_off + 8..entry_off + 12].try_into().ok()?) as usize
        };
        if slice_off + 8 > data.len() {
            return None;
        }
        let inner = u32::from_le_bytes(data[slice_off..slice_off + 4].try_into().ok()?);
        let is_64 = inner == MH_MAGIC_64;
        if inner != MH_MAGIC && inner != MH_MAGIC_64 {
            return None;
        }
        return Some((slice_off, is_64));
    }

    None
}

fn parse_header(data: &[u8], off: usize, is_64: bool) -> Option<HeaderInfo> {
    let header_size = if is_64 { 32 } else { 28 };
    if off + header_size > data.len() {
        return None;
    }
    // ncmds at offset 16 of the header (after magic, cputype, cpusubtype, filetype).
    let ncmds = u32::from_le_bytes(data[off + 16..off + 20].try_into().ok()?) as usize;
    if ncmds > MAX_LOAD_COMMANDS {
        return None;
    }
    Some(HeaderInfo {
        cmds_offset: off + header_size,
        ncmds,
    })
}

fn parse_load_commands(
    data: &[u8],
    start: usize,
    ncmds: usize,
) -> Option<MachoLoadCommands> {
    let mut out = MachoLoadCommands::default();
    let mut cursor = start;
    for _ in 0..ncmds {
        if cursor + 8 > data.len() {
            break;
        }
        let cmd_raw = u32::from_le_bytes(data[cursor..cursor + 4].try_into().ok()?);
        let cmdsize = u32::from_le_bytes(data[cursor + 4..cursor + 8].try_into().ok()?) as usize;
        if cmdsize < 8 || cmdsize > MAX_LC_PAYLOAD || cursor + cmdsize > data.len() {
            break;
        }
        let cmd = cmd_raw & !LC_REQ_DYLD;
        let body = &data[cursor..cursor + cmdsize];

        match cmd {
            LC_UUID => {
                if body.len() >= 24 {
                    let uuid_bytes = &body[8..24];
                    out.uuid = Some(format_uuid(uuid_bytes));
                }
            }
            LC_BUILD_VERSION => {
                if let Some(bv) = parse_build_version(body) {
                    out.build_version = Some(bv);
                }
            }
            LC_SOURCE_VERSION => {
                if body.len() >= 16 {
                    let raw = u64::from_le_bytes(body[8..16].try_into().ok()?);
                    out.source_version = Some(decode_source_version(raw));
                }
            }
            LC_RPATH => {
                if body.len() >= 12 {
                    let off = u32::from_le_bytes(body[8..12].try_into().ok()?) as usize;
                    if let Some(s) = read_lc_string(body, off) {
                        out.rpath.push(s);
                    }
                }
            }
            LC_LOAD_DYLIB
            | LC_ID_DYLIB
            | LC_LOAD_WEAK_DYLIB
            | LC_LAZY_LOAD_DYLIB
            | LC_REEXPORT_DYLIB
            | LC_LOAD_UPWARD_DYLIB => {
                if let Some(d) = parse_dylib(body, cmd) {
                    if cmd == LC_ID_DYLIB {
                        out.id_dylib = Some(d.path);
                    } else {
                        out.load_dylibs.push(d);
                    }
                }
            }
            LC_CODE_SIGNATURE => {
                if body.len() >= 16 {
                    let off = u32::from_le_bytes(body[8..12].try_into().ok()?);
                    let sz = u32::from_le_bytes(body[12..16].try_into().ok()?);
                    if sz > 0 {
                        out.code_signature = Some((off, sz));
                    }
                }
            }
            LC_LINKER_OPTION => {
                if body.len() >= 12 {
                    let count = u32::from_le_bytes(body[8..12].try_into().ok()?) as usize;
                    let mut p = 12;
                    for _ in 0..count.min(64) {
                        if p >= body.len() {
                            break;
                        }
                        let nul = body[p..]
                            .iter()
                            .position(|&b| b == 0)
                            .map(|n| p + n)
                            .unwrap_or(body.len());
                        if nul > p {
                            let s = String::from_utf8_lossy(&body[p..nul]).into_owned();
                            if !s.is_empty() {
                                out.linker_options.push(s);
                            }
                        }
                        p = nul + 1;
                    }
                }
            }
            _ => {}
        }
        cursor += cmdsize;
    }

    if out.uuid.is_none()
        && out.build_version.is_none()
        && out.source_version.is_none()
        && out.id_dylib.is_none()
        && out.load_dylibs.is_empty()
        && out.rpath.is_empty()
        && out.linker_options.is_empty()
        && out.code_signature.is_none()
    {
        return None;
    }
    Some(out)
}

/// Format the LC_UUID 16-byte field as a canonical hyphenated UUID.
fn format_uuid(bytes: &[u8]) -> String {
    if bytes.len() < 16 {
        return String::new();
    }
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

fn parse_build_version(body: &[u8]) -> Option<MachoBuildVersion> {
    if body.len() < 24 {
        return None;
    }
    let platform = u32::from_le_bytes(body[8..12].try_into().ok()?);
    let minos = u32::from_le_bytes(body[12..16].try_into().ok()?);
    let sdk = u32::from_le_bytes(body[16..20].try_into().ok()?);
    let ntools = u32::from_le_bytes(body[20..24].try_into().ok()?) as usize;
    let mut tools = Vec::with_capacity(ntools.min(8));
    for i in 0..ntools.min(16) {
        let off = 24 + i * 8;
        if off + 8 > body.len() {
            break;
        }
        let tool_id = u32::from_le_bytes(body[off..off + 4].try_into().ok()?);
        let version = u32::from_le_bytes(body[off + 4..off + 8].try_into().ok()?);
        tools.push(MachoTool {
            tool: build_tool_name(tool_id).to_string(),
            version: decode_xyz_version(version),
        });
    }
    Some(MachoBuildVersion {
        platform: platform_name(platform).to_string(),
        minos: decode_xyz_version(minos),
        sdk: decode_xyz_version(sdk),
        tools,
    })
}

fn parse_dylib(body: &[u8], cmd: u32) -> Option<MachoDylib> {
    if body.len() < 24 {
        return None;
    }
    let name_offset = u32::from_le_bytes(body[8..12].try_into().ok()?) as usize;
    let _timestamp = u32::from_le_bytes(body[12..16].try_into().ok()?);
    let current = u32::from_le_bytes(body[16..20].try_into().ok()?);
    let compat = u32::from_le_bytes(body[20..24].try_into().ok()?);
    let path = read_lc_string(body, name_offset)?;
    Some(MachoDylib {
        path,
        kind: dylib_kind(cmd).to_string(),
        compatibility_version: decode_xyz_version(compat),
        current_version: decode_xyz_version(current),
    })
}

fn dylib_kind(cmd: u32) -> &'static str {
    match cmd {
        LC_LOAD_DYLIB => "load",
        LC_LOAD_WEAK_DYLIB => "weak",
        LC_LAZY_LOAD_DYLIB => "lazy",
        LC_REEXPORT_DYLIB => "reexport",
        LC_LOAD_UPWARD_DYLIB => "upward",
        LC_ID_DYLIB => "id",
        _ => "load",
    }
}

fn read_lc_string(body: &[u8], offset: usize) -> Option<String> {
    if offset >= body.len() {
        return None;
    }
    let bytes = &body[offset..];
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let s = String::from_utf8_lossy(&bytes[..end]).into_owned();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Decode an OS / SDK / compat version u32: bits 31-16 = X (major),
/// bits 15-8 = Y (minor), bits 7-0 = Z (patch).
fn decode_xyz_version(v: u32) -> String {
    let major = v >> 16;
    let minor = (v >> 8) & 0xFF;
    let patch = v & 0xFF;
    format!("{}.{}.{}", major, minor, patch)
}

/// Decode LC_SOURCE_VERSION's 64-bit packed encoding: A.B.C.D.E with
/// 24 + 10 + 10 + 10 + 10 bits respectively.
fn decode_source_version(v: u64) -> String {
    let a = v >> 40;
    let b = (v >> 30) & 0x3FF;
    let c = (v >> 20) & 0x3FF;
    let d = (v >> 10) & 0x3FF;
    let e = v & 0x3FF;
    if d == 0 && e == 0 {
        format!("{}.{}.{}", a, b, c)
    } else {
        format!("{}.{}.{}.{}.{}", a, b, c, d, e)
    }
}

fn platform_name(p: u32) -> &'static str {
    match p {
        1 => "macOS",
        2 => "iOS",
        3 => "tvOS",
        4 => "watchOS",
        5 => "bridgeOS",
        6 => "macCatalyst",
        7 => "iOSSimulator",
        8 => "tvOSSimulator",
        9 => "watchOSSimulator",
        10 => "driverkit",
        _ => "unknown",
    }
}

/// Walk the load commands of the first Mach-O slice looking for a
/// section named `(segname, sectname)`. Returns the section's byte
/// slice when found, or `None` for non-Mach-O input or absent
/// sections. Lenient — bails on malformed inputs rather than
/// propagating errors.
///
/// Used to extract embedded text-segment payloads:
/// `("__TEXT", "__info_plist")` for command-line tools' Info.plist,
/// `("__TEXT", "__launchd_plist")` for self-installing daemons,
/// `("__TEXT", "__entitlements")` for inline entitlements,
/// `("__DATA_CONST", "__objc_classlist")` for ObjC reflection.
#[must_use]
pub(crate) fn find_section<'a>(
    data: &'a [u8],
    segname: &str,
    sectname: &str,
) -> Option<&'a [u8]> {
    let (header_off, is_64) = locate_first_macho_slice(data)?;
    let after_header = parse_header(data, header_off, is_64)?;
    walk_segments_for_section(data, header_off, after_header, is_64, segname, sectname)
}

fn walk_segments_for_section<'a>(
    data: &'a [u8],
    header_off: usize,
    after_header: HeaderInfo,
    is_64: bool,
    target_seg: &str,
    target_sect: &str,
) -> Option<&'a [u8]> {
    let mut cursor = after_header.cmds_offset;
    for _ in 0..after_header.ncmds {
        if cursor + 8 > data.len() {
            break;
        }
        let cmd = u32::from_le_bytes(data[cursor..cursor + 4].try_into().ok()?) & !LC_REQ_DYLD;
        let cmdsize =
            u32::from_le_bytes(data[cursor + 4..cursor + 8].try_into().ok()?) as usize;
        if cmdsize < 8 || cmdsize > MAX_LC_PAYLOAD || cursor + cmdsize > data.len() {
            break;
        }
        let body = &data[cursor..cursor + cmdsize];

        let want_64 = is_64 && cmd == LC_SEGMENT_64;
        let want_32 = !is_64 && cmd == LC_SEGMENT;
        if want_64 || want_32 {
            // Layout (LE):
            //   u32 cmd | u32 cmdsize | char segname[16]
            //   { u64 vmaddr,vmsize,fileoff,filesize ; i32 maxprot,initprot ; u32 nsects,flags } (64)
            //   or 32-bit equivalents
            //   followed by section_64[nsects] (each 80 bytes) or section[nsects] (each 68 bytes)
            let segname_off = 8usize;
            if body.len() < segname_off + 16 {
                cursor += cmdsize;
                continue;
            }
            let segname = parse_fixed_name(&body[segname_off..segname_off + 16]);
            let (header_size, section_size, nsects_off) = if is_64 {
                (72, 80, 64) // segment header is 72 bytes; nsects at offset 64
            } else {
                (56, 68, 48) // segment header is 56 bytes; nsects at offset 48
            };
            if body.len() < nsects_off + 4 {
                cursor += cmdsize;
                continue;
            }
            let nsects =
                u32::from_le_bytes(body[nsects_off..nsects_off + 4].try_into().ok()?) as usize;

            // Only walk sections if this segment matches the target —
            // typically only __TEXT carries the inline payloads we care
            // about, and __LINKEDIT alone has many sections we'd skip.
            if segname == target_seg {
                for i in 0..nsects.min(256) {
                    let s_off = header_size + i * section_size;
                    if s_off + section_size > body.len() {
                        break;
                    }
                    let sect_bytes = &body[s_off..s_off + section_size];
                    let sectname = parse_fixed_name(&sect_bytes[..16]);
                    if sectname == target_sect {
                        let (offset, size) = if is_64 {
                            (
                                u32::from_le_bytes(sect_bytes[48..52].try_into().ok()?)
                                    as usize,
                                u64::from_le_bytes(sect_bytes[40..48].try_into().ok()?)
                                    as usize,
                            )
                        } else {
                            (
                                u32::from_le_bytes(sect_bytes[40..44].try_into().ok()?)
                                    as usize,
                                u32::from_le_bytes(sect_bytes[36..40].try_into().ok()?)
                                    as usize,
                            )
                        };
                        // Section file offset is relative to the
                        // file's slice start, which is `header_off`
                        // for fat binaries and 0 for plain Mach-O.
                        let abs_off = header_off.checked_add(offset)?;
                        if abs_off.checked_add(size)? > data.len() || size == 0 {
                            return None;
                        }
                        return Some(&data[abs_off..abs_off + size]);
                    }
                }
            }
        }

        cursor += cmdsize;
    }
    None
}

/// Decode a 16-byte fixed-length NUL-padded segment/section name
/// into a Rust string. Stops at the first NUL.
fn parse_fixed_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Enumerate every section under the given segment whose name starts
/// with `prefix`. Returns the matching section names (with their
/// `__` prefix, sorted, deduped). Used to surface the
/// `__TEXT,__swift5_*` family for Swift detection.
#[must_use]
pub(crate) fn list_sections_with_prefix(
    data: &[u8],
    segname: &str,
    prefix: &str,
) -> Vec<String> {
    let Some((header_off, is_64)) = locate_first_macho_slice(data) else {
        return Vec::new();
    };
    let Some(after_header) = parse_header(data, header_off, is_64) else {
        return Vec::new();
    };

    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut cursor = after_header.cmds_offset;
    for _ in 0..after_header.ncmds {
        if cursor + 8 > data.len() {
            break;
        }
        let Ok(cmd_bytes) = data[cursor..cursor + 4].try_into() else {
            break;
        };
        let Ok(size_bytes) = data[cursor + 4..cursor + 8].try_into() else {
            break;
        };
        let cmd = u32::from_le_bytes(cmd_bytes) & !LC_REQ_DYLD;
        let cmdsize = u32::from_le_bytes(size_bytes) as usize;
        if cmdsize < 8 || cmdsize > MAX_LC_PAYLOAD || cursor + cmdsize > data.len() {
            break;
        }
        let body = &data[cursor..cursor + cmdsize];

        let want_64 = is_64 && cmd == LC_SEGMENT_64;
        let want_32 = !is_64 && cmd == LC_SEGMENT;
        if want_64 || want_32 {
            let segname_off = 8usize;
            if body.len() < segname_off + 16 {
                cursor += cmdsize;
                continue;
            }
            let this_segname = parse_fixed_name(&body[segname_off..segname_off + 16]);
            let (header_size, section_size, nsects_off) = if is_64 {
                (72, 80, 64)
            } else {
                (56, 68, 48)
            };
            if body.len() < nsects_off + 4 {
                cursor += cmdsize;
                continue;
            }
            let Ok(nsects_bytes) = body[nsects_off..nsects_off + 4].try_into() else {
                cursor += cmdsize;
                continue;
            };
            let nsects = u32::from_le_bytes(nsects_bytes) as usize;
            if this_segname == segname {
                for i in 0..nsects.min(256) {
                    let s_off = header_size + i * section_size;
                    if s_off + section_size > body.len() {
                        break;
                    }
                    let sectname = parse_fixed_name(&body[s_off..s_off + 16]);
                    if sectname.starts_with(prefix) {
                        out.insert(sectname);
                    }
                }
            }
        }
        cursor += cmdsize;
    }
    out.into_iter().collect()
}

fn build_tool_name(t: u32) -> &'static str {
    match t {
        1 => "clang",
        2 => "swiftc",
        3 => "ld",
        4 => "lld",
        _ => "unknown",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Build a minimal LE 64-bit Mach-O header with `ncmds`
    /// load-commands following.  Caller appends the command bodies.
    fn build_macho_header_64(ncmds: u32, sizeofcmds: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(&MH_MAGIC_64.to_le_bytes()); // magic
        out.extend_from_slice(&0u32.to_le_bytes()); // cputype
        out.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
        out.extend_from_slice(&2u32.to_le_bytes()); // filetype = executable
        out.extend_from_slice(&ncmds.to_le_bytes()); // ncmds
        out.extend_from_slice(&sizeofcmds.to_le_bytes()); // sizeofcmds
        out.extend_from_slice(&0u32.to_le_bytes()); // flags
        out.extend_from_slice(&0u32.to_le_bytes()); // reserved
        out
    }

    fn lc_uuid(uuid: [u8; 16]) -> Vec<u8> {
        let mut out = Vec::with_capacity(24);
        out.extend_from_slice(&LC_UUID.to_le_bytes());
        out.extend_from_slice(&24u32.to_le_bytes());
        out.extend_from_slice(&uuid);
        out
    }

    fn lc_build_version(
        platform: u32,
        minos: u32,
        sdk: u32,
        tools: &[(u32, u32)],
    ) -> Vec<u8> {
        let cmdsize = 24 + tools.len() * 8;
        let mut out = Vec::with_capacity(cmdsize);
        out.extend_from_slice(&LC_BUILD_VERSION.to_le_bytes());
        out.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        out.extend_from_slice(&platform.to_le_bytes());
        out.extend_from_slice(&minos.to_le_bytes());
        out.extend_from_slice(&sdk.to_le_bytes());
        out.extend_from_slice(&(tools.len() as u32).to_le_bytes());
        for (tool, ver) in tools {
            out.extend_from_slice(&tool.to_le_bytes());
            out.extend_from_slice(&ver.to_le_bytes());
        }
        out
    }

    fn lc_dylib(cmd: u32, path: &str, current: u32, compat: u32) -> Vec<u8> {
        let path_bytes = path.as_bytes();
        // Dylib command header is 24 bytes; path follows immediately.
        let cmdsize = (24 + path_bytes.len() + 1).next_multiple_of(8);
        let mut out = Vec::with_capacity(cmdsize);
        out.extend_from_slice(&cmd.to_le_bytes());
        out.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        out.extend_from_slice(&24u32.to_le_bytes()); // name offset
        out.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        out.extend_from_slice(&current.to_le_bytes());
        out.extend_from_slice(&compat.to_le_bytes());
        out.extend_from_slice(path_bytes);
        while out.len() < cmdsize {
            out.push(0);
        }
        out
    }

    fn lc_rpath(path: &str) -> Vec<u8> {
        let path_bytes = path.as_bytes();
        let cmdsize = (12 + path_bytes.len() + 1).next_multiple_of(8);
        let mut out = Vec::with_capacity(cmdsize);
        out.extend_from_slice(&LC_RPATH.to_le_bytes());
        out.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        out.extend_from_slice(&12u32.to_le_bytes()); // path offset
        out.extend_from_slice(path_bytes);
        while out.len() < cmdsize {
            out.push(0);
        }
        out
    }

    fn lc_source_version(major: u32, minor: u32, patch: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&LC_SOURCE_VERSION.to_le_bytes());
        out.extend_from_slice(&16u32.to_le_bytes());
        let v: u64 = ((major as u64) << 40) | ((minor as u64) << 30) | ((patch as u64) << 20);
        out.extend_from_slice(&v.to_le_bytes());
        out
    }

    #[test]
    fn decode_xyz_basic() {
        // 11.0.0 = 0x000B0000
        assert_eq!(decode_xyz_version(0x000B_0000), "11.0.0");
        // 10.13.5 = 0x000A0D05
        assert_eq!(decode_xyz_version(0x000A_0D05), "10.13.5");
    }

    #[test]
    fn extract_uuid() {
        let uuid = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let cmd = lc_uuid(uuid);
        let mut buf = build_macho_header_64(1, cmd.len() as u32);
        buf.extend_from_slice(&cmd);
        let lc = extract(&buf).expect("uuid present");
        assert_eq!(
            lc.uuid.as_deref(),
            Some("12345678-9ABC-DEF0-1122-334455667788")
        );
    }

    #[test]
    fn extract_build_version() {
        // platform=1 (macOS), minos=0x000B0000 (11.0.0), sdk=0x000B0100 (11.1.0)
        let cmd = lc_build_version(
            1,
            0x000B_0000,
            0x000B_0100,
            &[(1, 0x0E00_0000), (3, 0x03F0_0000)],
        );
        let mut buf = build_macho_header_64(1, cmd.len() as u32);
        buf.extend_from_slice(&cmd);
        let lc = extract(&buf).expect("present");
        let bv = lc.build_version.expect("build_version");
        assert_eq!(bv.platform, "macOS");
        assert_eq!(bv.minos, "11.0.0");
        assert_eq!(bv.sdk, "11.1.0");
        assert_eq!(bv.tools.len(), 2);
        assert_eq!(bv.tools[0].tool, "clang");
        assert_eq!(bv.tools[1].tool, "ld");
    }

    #[test]
    fn extract_load_dylib_kinds() {
        let mut all = Vec::new();
        all.extend_from_slice(&lc_dylib(LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib", 0x0510_0000, 0x0001_0000));
        all.extend_from_slice(&lc_dylib(LC_LOAD_WEAK_DYLIB, "@rpath/libThing.dylib", 0x0001_0000, 0x0001_0000));
        all.extend_from_slice(&lc_dylib(LC_REEXPORT_DYLIB | LC_REQ_DYLD, "@rpath/Reex.dylib", 0x0001_0000, 0x0001_0000));
        let mut buf = build_macho_header_64(3, all.len() as u32);
        buf.extend_from_slice(&all);
        let lc = extract(&buf).expect("present");
        assert_eq!(lc.load_dylibs.len(), 3);
        assert_eq!(lc.load_dylibs[0].path, "/usr/lib/libSystem.B.dylib");
        assert_eq!(lc.load_dylibs[0].kind, "load");
        assert_eq!(lc.load_dylibs[1].kind, "weak");
        assert_eq!(lc.load_dylibs[2].kind, "reexport");
    }

    #[test]
    fn extract_rpath() {
        let cmd = lc_rpath("@executable_path/../Frameworks");
        let mut buf = build_macho_header_64(1, cmd.len() as u32);
        buf.extend_from_slice(&cmd);
        let lc = extract(&buf).expect("present");
        assert_eq!(lc.rpath.len(), 1);
        assert_eq!(lc.rpath[0], "@executable_path/../Frameworks");
    }

    #[test]
    fn extract_source_version() {
        let cmd = lc_source_version(2, 5, 1);
        let mut buf = build_macho_header_64(1, cmd.len() as u32);
        buf.extend_from_slice(&cmd);
        let lc = extract(&buf).expect("present");
        assert_eq!(lc.source_version.as_deref(), Some("2.5.1"));
    }

    #[test]
    fn extract_returns_none_for_non_macho() {
        assert!(extract(b"random bytes").is_none());
    }

    #[test]
    fn extract_returns_none_for_truncated_header() {
        let buf = vec![0x12, 0x34];
        assert!(extract(&buf).is_none());
    }

    #[test]
    fn extract_id_dylib_for_dylibs() {
        let cmd = lc_dylib(LC_ID_DYLIB, "@rpath/MyFramework", 0x0001_0000, 0x0001_0000);
        let mut buf = build_macho_header_64(1, cmd.len() as u32);
        buf.extend_from_slice(&cmd);
        let lc = extract(&buf).expect("present");
        assert_eq!(lc.id_dylib.as_deref(), Some("@rpath/MyFramework"));
        assert!(lc.load_dylibs.is_empty());
    }
}
