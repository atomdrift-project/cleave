//! Mach-O section locator for cleave's Go buildinfo decoder.
//!
//! Filefacts owns every Mach-O `macho.*` fact emitted in the report
//! (slices, build_version, code signature, info_plist, launchd_plist,
//! rpaths, dylibs, source_version, …). The only function that still
//! lives here is `find_section`, which `go_buildinfo` calls on raw
//! bytes to locate `__TEXT,__rodata` / `__TEXT,__gopclntab` /
//! `__DATA,__go_buildinfo` — sections it then walks itself with the
//! Go-specific decoders.

const MH_MAGIC: u32 = 0xFEED_FACE;
const MH_MAGIC_64: u32 = 0xFEED_FACF;
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_MAGIC_64: u32 = 0xCAFE_BABF;

const LC_SEGMENT: u32 = 0x01;
const LC_SEGMENT_64: u32 = 0x19;
const LC_REQ_DYLD: u32 = 0x8000_0000;

const MAX_LOAD_COMMANDS: usize = 4096;
const MAX_LC_PAYLOAD: usize = 1 << 20;

/// Locate the named section's bytes within a Mach-O file. Picks the
/// first slice of a fat binary; returns `None` for non-Mach-O input
/// or when the section is absent.
#[must_use]
pub(crate) fn find_section<'a>(data: &'a [u8], segname: &str, sectname: &str) -> Option<&'a [u8]> {
    let (header_off, is_64) = locate_first_macho_slice(data)?;
    let after_header = parse_header(data, header_off, is_64)?;
    walk_segments_for_section(data, header_off, after_header, is_64, segname, sectname)
}

#[derive(Debug, Clone, Copy)]
struct HeaderInfo {
    cmds_offset: usize,
    ncmds: usize,
}

fn locate_first_macho_slice(data: &[u8]) -> Option<(usize, bool)> {
    if data.len() < 8 {
        return None;
    }
    let magic_le = u32::from_le_bytes(data[..4].try_into().ok()?);
    let magic_be = u32::from_be_bytes(data[..4].try_into().ok()?);

    if magic_le == MH_MAGIC_64 {
        return Some((0, true));
    }
    if magic_le == MH_MAGIC {
        return Some((0, false));
    }

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
    let ncmds = u32::from_le_bytes(data[off + 16..off + 20].try_into().ok()?) as usize;
    if ncmds > MAX_LOAD_COMMANDS {
        return None;
    }
    Some(HeaderInfo {
        cmds_offset: off + header_size,
        ncmds,
    })
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
        let cmdsize = u32::from_le_bytes(data[cursor + 4..cursor + 8].try_into().ok()?) as usize;
        if !(8..=MAX_LC_PAYLOAD).contains(&cmdsize) || cursor + cmdsize > data.len() {
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
                (72, 80, 64)
            } else {
                (56, 68, 48)
            };
            if body.len() < nsects_off + 4 {
                cursor += cmdsize;
                continue;
            }
            let nsects =
                u32::from_le_bytes(body[nsects_off..nsects_off + 4].try_into().ok()?) as usize;

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
                                u32::from_le_bytes(sect_bytes[48..52].try_into().ok()?) as usize,
                                u64::from_le_bytes(sect_bytes[40..48].try_into().ok()?) as usize,
                            )
                        } else {
                            (
                                u32::from_le_bytes(sect_bytes[40..44].try_into().ok()?) as usize,
                                u32::from_le_bytes(sect_bytes[36..40].try_into().ok()?) as usize,
                            )
                        };
                        // Section file offset is relative to the
                        // file's slice start (`header_off` for fat,
                        // 0 for plain Mach-O).
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

fn parse_fixed_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
