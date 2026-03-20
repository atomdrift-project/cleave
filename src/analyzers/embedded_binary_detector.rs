//! Embedded binary detector for PE and ELF files hidden within other binaries.
//!
//! Scans raw binary data for embedded PE and ELF files using strict header
//! validation to minimize false positives. Common in dropper malware, reflective
//! loaders, and multi-stage payloads.

use crate::types::*;
use memchr::memmem;

/// Maximum embedded binaries to report per file (prevents noise on heavily packed files).
const MAX_EMBEDDED: usize = 20;

/// Minimum credible embedded binary size in bytes.
const MIN_BINARY_SIZE: usize = 512;

/// Maximum credible PE SizeOfImage (500 MB).
const MAX_PE_IMAGE_SIZE: usize = 500 * 1024 * 1024;

/// Kind of embedded binary detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmbeddedKind {
    Pe32,
    Pe64,
    Elf32Le,
    Elf32Be,
    Elf64Le,
    Elf64Be,
}

impl EmbeddedKind {
    /// Short name for use in finding IDs and evidence.
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            EmbeddedKind::Pe32 | EmbeddedKind::Pe64 => "pe",
            EmbeddedKind::Elf32Le
            | EmbeddedKind::Elf32Be
            | EmbeddedKind::Elf64Le
            | EmbeddedKind::Elf64Be => "elf",
        }
    }
}

/// A validated embedded binary found within a larger file.
#[derive(Debug)]
pub(crate) struct EmbeddedBinary {
    /// Byte offset within the host file.
    pub offset: usize,
    /// Detected binary kind.
    pub kind: EmbeddedKind,
    /// Estimated size in bytes (from SizeOfImage or remainder of file).
    pub estimated_size: usize,
}

/// Scan binary data for embedded PE and ELF files.
///
/// Uses strict header validation to minimize false positives. Skips the first
/// few bytes (the host binary's own header). Returns at most [`MAX_EMBEDDED`]
/// results sorted by offset.
#[must_use]
pub(crate) fn scan_for_embedded_binaries(data: &[u8]) -> Vec<EmbeddedBinary> {
    let mut results = Vec::new();
    scan_pe(data, &mut results);
    scan_elf(data, &mut results);
    results.sort_by_key(|e| e.offset);
    results.truncate(MAX_EMBEDDED);
    results
}

/// Build a finding for a detected embedded binary.
#[must_use]
pub(crate) fn finding_for(binary: &EmbeddedBinary, parent_path: &str) -> Finding {
    let type_upper = binary.kind.as_str().to_uppercase();
    Finding {
        kind: FindingKind::Capability,
        id: format!("binary/embedded/{}", binary.kind.as_str()),
        desc: format!(
            "Embedded {} binary at file offset {:#x} (~{} bytes)",
            type_upper, binary.offset, binary.estimated_size,
        ),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: Some("T1027.009".to_string()), // Embedded Payloads
        evidence: vec![Evidence {
            method: "header_validation".to_string(),
            source: "embedded_binary_detector".to_string(),
            value: format!(
                "kind={:?} estimated_size={}",
                binary.kind, binary.estimated_size
            ),
            location: Some(format!("offset:{:#x}", binary.offset)),
            ..Default::default()
        }],
        match_count: 1,
        trait_refs: vec![],
        source_file: Some(parent_path.to_string()),
    }
}

// ── PE scanning ──────────────────────────────────────────────────────────────

fn scan_pe(data: &[u8], results: &mut Vec<EmbeddedBinary>) {
    // Start past byte 0 so we skip the host PE's own MZ header.
    let search_start = 2.min(data.len());
    let finder = memmem::Finder::new(b"MZ");
    for pos in finder.find_iter(&data[search_start..]) {
        if results.len() >= MAX_EMBEDDED {
            break;
        }
        if let Some(emb) = validate_pe(data, pos + search_start) {
            results.push(emb);
        }
    }
}

/// Validate a potential PE header at `offset` within `data`.
///
/// Checks MZ → e_lfanew → PE\0\0 → Machine → NumberOfSections → optional
/// header magic. Rejects anything that fails any criterion.
fn validate_pe(data: &[u8], offset: usize) -> Option<EmbeddedBinary> {
    // e_lfanew is at DOS header offset 0x3C (4 bytes LE)
    let e_lfanew = read_u32_le(data, offset + 0x3C)? as usize;

    // Must be non-zero, 4-byte aligned, and within a reasonable range
    if !(4..=1024).contains(&e_lfanew) || !e_lfanew.is_multiple_of(4) {
        return None;
    }

    let pe_base = offset + e_lfanew;

    // PE\0\0 signature
    if data.get(pe_base..pe_base + 4)? != [0x50, 0x45, 0x00, 0x00] {
        return None;
    }

    // COFF Machine (u16 LE) at pe_base + 4
    let machine = read_u16_le(data, pe_base + 4)?;
    const VALID_MACHINES: &[u16] = &[
        0x014C, // i386
        0x8664, // x86-64
        0x01C0, // ARM LE
        0x01C2, // ARM Thumb
        0x01C4, // ARM Thumb-2 / ARMv7
        0xAA64, // ARM64
        0x0200, // IA-64
        0x5032, // RISC-V 32
        0x5064, // RISC-V 64
        0x0166, // MIPS I
        0x0366, // MIPS FPU
        0x0466, // MIPS FPU16
    ];
    if !VALID_MACHINES.contains(&machine) {
        return None;
    }

    // NumberOfSections (u16 LE) at pe_base + 6
    let n_sections = read_u16_le(data, pe_base + 6)?;
    if n_sections == 0 || n_sections > 96 {
        return None;
    }

    // SizeOfOptionalHeader (u16 LE) at pe_base + 20
    let size_of_optional_header = read_u16_le(data, pe_base + 20)? as usize;
    let section_table_offset = pe_base + 24 + size_of_optional_header;

    // Optional header magic (u16 LE) at pe_base + 24 (right after COFF header)
    let opt_magic = read_u16_le(data, pe_base + 24)?;
    let kind = match opt_magic {
        0x010B => EmbeddedKind::Pe32,
        0x020B => EmbeddedKind::Pe64,
        _ => return None, // Neither PE32 nor PE32+ — reject
    };

    // SizeOfImage is at optional header offset 56 for both PE32 and PE32+
    let size_of_image_offset = pe_base + 24 + 56; // optional header base + 56
    let estimated_size = read_u32_le(data, size_of_image_offset)
        .map(|soi| soi as usize)
        .filter(|&soi| (MIN_BINARY_SIZE..=MAX_PE_IMAGE_SIZE).contains(&soi))
        .unwrap_or_else(|| data.len().saturating_sub(offset));

    if estimated_size < MIN_BINARY_SIZE {
        return None;
    }

    let available_size = data.len().saturating_sub(offset);
    let bounded_size = estimated_size.min(available_size);
    if section_table_offset < offset
        || section_table_offset.saturating_sub(offset) >= bounded_size
        || section_table_offset
            .checked_add(n_sections as usize * 40)
            .is_none_or(|end| end > data.len())
    {
        return None;
    }

    // Reject PE-like blobs whose section table points outside the embedded slice.
    for i in 0..n_sections as usize {
        let sh = section_table_offset + i * 40;
        let size_of_raw_data = read_u32_le(data, sh + 16)? as usize;
        let pointer_to_raw_data = read_u32_le(data, sh + 20)? as usize;

        if size_of_raw_data == 0 {
            continue;
        }

        let section_end = pointer_to_raw_data.checked_add(size_of_raw_data)?;
        if pointer_to_raw_data == 0 || section_end > bounded_size {
            return None;
        }
    }

    Some(EmbeddedBinary {
        offset,
        kind,
        estimated_size,
    })
}

// ── ELF scanning ─────────────────────────────────────────────────────────────

fn scan_elf(data: &[u8], results: &mut Vec<EmbeddedBinary>) {
    // Start past byte 0 so we skip the host ELF's own magic.
    let search_start = 4.min(data.len());
    let finder = memmem::Finder::new(b"\x7fELF");
    for pos in finder.find_iter(&data[search_start..]) {
        if results.len() >= MAX_EMBEDDED {
            break;
        }
        if let Some(emb) = validate_elf(data, pos + search_start) {
            results.push(emb);
        }
    }
}

/// ELF e_machine values we consider valid.
const VALID_ELF_MACHINES: &[u16] = &[
    0x0002, // SPARC
    0x0003, // x86
    0x0008, // MIPS
    0x0014, // PowerPC
    0x0015, // PowerPC 64
    0x0028, // ARM
    0x002A, // SuperH
    0x0032, // IA-64
    0x003E, // x86-64
    0x00B7, // AArch64
    0x00F3, // RISC-V
    0x00F7, // BPF
    0x016F, // s390x
];

/// Validate a potential ELF header at `offset` within `data`.
fn validate_elf(data: &[u8], offset: usize) -> Option<EmbeddedBinary> {
    // ELF identity is 16 bytes; full header needs at least 20 for e_machine
    if offset + 20 > data.len() {
        return None;
    }

    // e_ident[4]: EI_CLASS — 1 = 32-bit, 2 = 64-bit
    let class = data[offset + 4];
    if class != 1 && class != 2 {
        return None;
    }

    // e_ident[5]: EI_DATA — 1 = LE, 2 = BE
    let encoding = data[offset + 5];
    if encoding != 1 && encoding != 2 {
        return None;
    }

    // e_ident[6]: EI_VERSION must be 1
    if data[offset + 6] != 1 {
        return None;
    }

    let le = encoding == 1;

    // e_type (u16) at offset 16: 1=REL, 2=EXEC, 3=DYN, 4=CORE
    let e_type = read_u16_endian(data, offset + 16, le)?;
    if e_type == 0 || e_type > 4 {
        return None;
    }

    // e_machine (u16) at offset 18
    let e_machine = read_u16_endian(data, offset + 18, le)?;
    if !VALID_ELF_MACHINES.contains(&e_machine) {
        return None;
    }

    let kind = match (class, le) {
        (1, true) => EmbeddedKind::Elf32Le,
        (1, false) => EmbeddedKind::Elf32Be,
        (2, true) => EmbeddedKind::Elf64Le,
        (_, _) => EmbeddedKind::Elf64Be,
    };

    Some(EmbeddedBinary {
        offset,
        kind,
        estimated_size: data.len().saturating_sub(offset),
    })
}

// ── Byte reading helpers ──────────────────────────────────────────────────────

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u16_endian(data: &[u8], offset: usize, le: bool) -> Option<u16> {
    let bytes: [u8; 2] = data.get(offset..offset + 2)?.try_into().ok()?;
    Some(if le {
        u16::from_le_bytes(bytes)
    } else {
        u16::from_be_bytes(bytes)
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal but structurally valid PE32 blob at the given offset within a buffer.
    fn make_synthetic_pe(buf: &mut Vec<u8>, offset: usize) {
        while buf.len() < offset + 4096 {
            buf.push(0u8);
        }
        // MZ header
        buf[offset] = 0x4D; // M
        buf[offset + 1] = 0x5A; // Z
                                // e_lfanew at offset + 0x3C = 0x40 (64)
        let e_lfanew: u32 = 0x40;
        buf[offset + 0x3C..offset + 0x40].copy_from_slice(&e_lfanew.to_le_bytes());

        let pe_base = offset + 0x40;
        // PE\0\0
        buf[pe_base] = 0x50;
        buf[pe_base + 1] = 0x45;
        buf[pe_base + 2] = 0x00;
        buf[pe_base + 3] = 0x00;
        // Machine: x86 (0x014C)
        buf[pe_base + 4..pe_base + 6].copy_from_slice(&0x014Cu16.to_le_bytes());
        // NumberOfSections: 3
        buf[pe_base + 6..pe_base + 8].copy_from_slice(&3u16.to_le_bytes());
        // Optional header magic: PE32 (0x010B)
        buf[pe_base + 24..pe_base + 26].copy_from_slice(&0x010Bu16.to_le_bytes());
        // SizeOfImage at optional header + 56 = pe_base + 24 + 56 = pe_base + 80
        buf[pe_base + 80..pe_base + 84].copy_from_slice(&(8192u32).to_le_bytes());
    }

    /// Build a minimal ELF64 LE blob at the given offset within a buffer.
    fn make_synthetic_elf(buf: &mut Vec<u8>, offset: usize) {
        while buf.len() < offset + 64 {
            buf.push(0u8);
        }
        buf[offset] = 0x7F;
        buf[offset + 1] = 0x45; // E
        buf[offset + 2] = 0x4C; // L
        buf[offset + 3] = 0x46; // F
        buf[offset + 4] = 2; // 64-bit
        buf[offset + 5] = 1; // LE
        buf[offset + 6] = 1; // version
                             // e_type = EXEC (2)
        buf[offset + 16..offset + 18].copy_from_slice(&2u16.to_le_bytes());
        // e_machine = x86-64 (0x3E)
        buf[offset + 18..offset + 20].copy_from_slice(&0x3Eu16.to_le_bytes());
    }

    #[test]
    fn test_scan_empty() {
        assert!(scan_for_embedded_binaries(&[]).is_empty());
    }

    #[test]
    fn test_scan_finds_embedded_pe() {
        let mut buf = vec![0u8; 8192];
        // Host PE header at offset 0 (just needs MZ so our scan starts at 2)
        buf[0] = 0x4D;
        buf[1] = 0x5A;
        // Embedded PE at offset 512
        make_synthetic_pe(&mut buf, 512);

        let found = scan_for_embedded_binaries(&buf);
        assert!(!found.is_empty(), "should detect embedded PE");
        assert_eq!(found[0].offset, 512);
        assert!(matches!(found[0].kind, EmbeddedKind::Pe32));
    }

    #[test]
    fn test_scan_finds_embedded_elf() {
        let mut buf = vec![0u8; 2048];
        // Host ELF at offset 0
        buf[0] = 0x7F;
        buf[1] = 0x45;
        buf[2] = 0x4C;
        buf[3] = 0x46;
        // Embedded ELF at offset 512
        make_synthetic_elf(&mut buf, 512);

        let found = scan_for_embedded_binaries(&buf);
        assert!(!found.is_empty(), "should detect embedded ELF");
        assert_eq!(found[0].offset, 512);
        assert!(matches!(found[0].kind, EmbeddedKind::Elf64Le));
    }

    #[test]
    fn test_rejects_bad_e_lfanew_zero() {
        let mut data = vec![0u8; 256];
        data[0] = 0x4D;
        data[1] = 0x5A;
        // e_lfanew = 0 (invalid)
        data[0x3C..0x40].copy_from_slice(&0u32.to_le_bytes());
        assert!(validate_pe(&data, 0).is_none());
    }

    #[test]
    fn test_rejects_bad_e_lfanew_too_large() {
        let mut data = vec![0u8; 256];
        data[0] = 0x4D;
        data[1] = 0x5A;
        // e_lfanew = 2048 (> 1024, invalid)
        data[0x3C..0x40].copy_from_slice(&2048u32.to_le_bytes());
        assert!(validate_pe(&data, 0).is_none());
    }

    #[test]
    fn test_rejects_bad_e_lfanew_misaligned() {
        let mut data = vec![0u8; 256];
        data[0] = 0x4D;
        data[1] = 0x5A;
        // e_lfanew = 65 (not 4-byte aligned)
        data[0x3C..0x40].copy_from_slice(&65u32.to_le_bytes());
        assert!(validate_pe(&data, 0).is_none());
    }

    #[test]
    fn test_rejects_bad_machine_type() {
        let mut buf = vec![0u8; 4096];
        make_synthetic_pe(&mut buf, 0);
        // Overwrite machine with unknown value 0xFFFF
        buf[0x40 + 4..0x40 + 6].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert!(validate_pe(&buf, 0).is_none());
    }

    #[test]
    fn test_rejects_zero_sections() {
        let mut buf = vec![0u8; 4096];
        make_synthetic_pe(&mut buf, 0);
        // NumberOfSections = 0
        buf[0x40 + 6..0x40 + 8].copy_from_slice(&0u16.to_le_bytes());
        assert!(validate_pe(&buf, 0).is_none());
    }

    #[test]
    fn test_rejects_too_many_sections() {
        let mut buf = vec![0u8; 4096];
        make_synthetic_pe(&mut buf, 0);
        // NumberOfSections = 200 (> 96)
        buf[0x40 + 6..0x40 + 8].copy_from_slice(&200u16.to_le_bytes());
        assert!(validate_pe(&buf, 0).is_none());
    }

    #[test]
    fn test_rejects_unknown_opt_magic() {
        let mut buf = vec![0u8; 4096];
        make_synthetic_pe(&mut buf, 0);
        // Optional header magic = 0xDEAD (neither PE32 nor PE32+)
        buf[0x40 + 24..0x40 + 26].copy_from_slice(&0xDEADu16.to_le_bytes());
        assert!(validate_pe(&buf, 0).is_none());
    }

    #[test]
    fn test_rejects_sections_outside_embedded_slice() {
        let mut buf = vec![0u8; 4096];
        make_synthetic_pe(&mut buf, 0);
        // SizeOfOptionalHeader = 0xE0 so the section table starts at 0x138.
        buf[0x40 + 20..0x40 + 22].copy_from_slice(&0x00E0u16.to_le_bytes());
        // First section header points far beyond SizeOfImage.
        let section_table = 0x40 + 24 + 0xE0;
        buf[section_table + 16..section_table + 20].copy_from_slice(&0x200u32.to_le_bytes());
        buf[section_table + 20..section_table + 24].copy_from_slice(&0x9000u32.to_le_bytes());
        assert!(validate_pe(&buf, 0).is_none());
    }

    #[test]
    fn test_elf_rejects_bad_class() {
        let mut data = vec![0u8; 64];
        make_synthetic_elf(&mut data, 0);
        data[4] = 3; // invalid class
        assert!(validate_elf(&data, 0).is_none());
    }

    #[test]
    fn test_elf_rejects_bad_encoding() {
        let mut data = vec![0u8; 64];
        make_synthetic_elf(&mut data, 0);
        data[5] = 3; // invalid encoding
        assert!(validate_elf(&data, 0).is_none());
    }

    #[test]
    fn test_elf_rejects_bad_machine() {
        let mut data = vec![0u8; 64];
        make_synthetic_elf(&mut data, 0);
        // e_machine = 0xDEAD (unknown)
        data[18..20].copy_from_slice(&0xDEADu16.to_le_bytes());
        assert!(validate_elf(&data, 0).is_none());
    }

    #[test]
    fn test_max_candidates_enforced() {
        // Build a buffer with many valid ELF headers
        let elf_size = 64;
        let n = MAX_EMBEDDED + 5;
        let mut buf = vec![0u8; 4 + n * (elf_size + 4)];
        for i in 0..n {
            make_synthetic_elf(&mut buf, 4 + i * (elf_size + 4));
        }
        let found = scan_for_embedded_binaries(&buf);
        assert!(found.len() <= MAX_EMBEDDED);
    }

    #[test]
    fn test_no_false_positive_on_null_bytes() {
        let data = vec![0u8; 4096];
        assert!(scan_for_embedded_binaries(&data).is_empty());
    }

    #[test]
    fn test_no_false_positive_on_text() {
        let data = b"This is just plain ASCII text with no binary content whatsoever. \
                     It repeats a few times to be sure. \
                     This is just plain ASCII text with no binary content whatsoever."
            .to_vec();
        assert!(scan_for_embedded_binaries(&data).is_empty());
    }

    #[test]
    fn test_finding_fields() {
        let binary = EmbeddedBinary {
            offset: 0x400,
            kind: EmbeddedKind::Pe32,
            estimated_size: 8192,
        };
        let finding = finding_for(&binary, "/tmp/test.exe");
        assert_eq!(finding.id, "binary/embedded/pe");
        assert_eq!(finding.crit, Criticality::Suspicious);
        assert!(finding.attack.is_some());
        assert!(!finding.evidence.is_empty());
    }
}
