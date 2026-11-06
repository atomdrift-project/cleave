//! Embedded binary detector for PE and ELF files hidden within other binaries.
//!
//! Scans raw binary data for embedded PE and ELF files using strict header
//! validation to minimize false positives. Common in dropper malware, reflective
//! loaders, and multi-stage payloads.

use crate::types::{Criticality, Evidence, Finding, FindingKind};
use memchr::memmem;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

/// Maximum embedded binaries to report per file (prevents noise on heavily packed files).
const MAX_EMBEDDED: usize = 20;

/// Candidate validation is spread across the file so a dense prefix cannot
/// starve a later stage. Per-region quotas cap header checks at 8,192 and valid
/// candidates at 1,024 per encoding/kind scan while the magic-byte walk stays
/// linear and allocation-free.
const CANDIDATE_BUCKETS: usize = 256;
const CANDIDATES_PER_BUCKET: u8 = 4;
const HEADER_CHECKS_PER_BUCKET: u8 = 32;

/// Minimum credible embedded binary size in bytes.
const MIN_BINARY_SIZE: usize = 512;
/// Tiny packer stubs often mimic ELF headers without carrying a real payload.
const MIN_EMBEDDED_ELF_SIZE: usize = 8 * 1024;

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
#[derive(Debug, Clone)]
pub(crate) struct EmbeddedBinary {
    /// Byte offset within the host file. For base64-encoded payloads
    /// this is the start of the *encoded* run — the dropper's
    /// physical location in the parent.
    pub offset: usize,
    /// Detected binary kind.
    pub kind: EmbeddedKind,
    /// Estimated size in bytes. For raw embeds this is the binary
    /// size; for base64 it's the decoded payload size.
    pub estimated_size: usize,
    /// Encoding wrapper between the host bytes and the payload —
    /// `None` for raw/plain, `Some("base64")` for base64-encoded.
    /// Recursive analyzers must decode before treating
    /// `host_data[offset..]` as the payload.
    pub encoding: Option<&'static str>,
    /// Optional container/packer format inferred from bytes surrounding
    /// the embedded program, used for child names and overlay-aware carving.
    pub format_hint: Option<&'static str>,
}

impl EmbeddedBinary {
    /// Name fragment used when reporting/analyzing this embedded child.
    #[must_use]
    pub(crate) fn display_kind(&self) -> String {
        match self.format_hint {
            Some(hint) => format!("{}.{}", self.kind.as_str(), hint),
            None => self.kind.as_str().to_string(),
        }
    }
}

/// Scan binary data for embedded PE and ELF files.
///
/// Uses strict header validation to minimize false positives. Skips the first
/// few bytes (the host binary's own header). Candidate discovery is intentionally
/// wider than the reporting budget: content-distinct images are selected first,
/// then remaining slots are filled with offset-stratified duplicates. Returns at
/// most [`MAX_EMBEDDED`] results sorted by offset. Includes both raw-magic finds and
/// base64-encoded payloads — droppers that hide a stage-2 binary
/// inside `.rodata` (Kong-ingress-controller 2024) appear as a
/// single `EmbeddedBinary` entry per detection.
#[must_use]
pub(crate) fn scan_for_embedded_binaries(
    data: &[u8],
    cancelled: Option<&AtomicBool>,
) -> Vec<EmbeddedBinary> {
    let mut results = Vec::new();
    scan_pe(data, &mut results, cancelled);
    scan_elf(data, &mut results, cancelled);
    scan_base64_packed(data, &mut results, cancelled);
    results.sort_by_key(|e| e.offset);
    select_embedded_candidates(data, results)
}

/// Select candidates for recursive analysis without letting repeated content
/// consume every slot. When there are more unique payloads than the budget,
/// sample them across the entire file rather than taking only the earliest.
fn select_embedded_candidates(data: &[u8], candidates: Vec<EmbeddedBinary>) -> Vec<EmbeddedBinary> {
    if candidates.len() <= MAX_EMBEDDED {
        return candidates;
    }

    let mut seen = HashSet::new();
    let mut unique = Vec::new();
    let mut duplicates = Vec::new();
    for candidate in candidates {
        let fingerprint = embedded_fingerprint(data, &candidate);
        if seen.insert(fingerprint) {
            unique.push(candidate);
        } else {
            duplicates.push(candidate);
        }
    }

    let mut selected = take_stratified(unique, MAX_EMBEDDED);
    if selected.len() < MAX_EMBEDDED {
        let remaining = MAX_EMBEDDED - selected.len();
        selected.extend(take_stratified(duplicates, remaining));
    }
    selected.sort_by_key(|e| e.offset);
    selected
}

/// SHA-256 over a bounded, position-independent representation of a candidate.
/// Small payloads are hashed in full. Large ones use head/middle/tail windows so
/// nested or overlapping multi-hundred-megabyte images cannot amplify scan cost.
fn embedded_fingerprint(data: &[u8], candidate: &EmbeddedBinary) -> [u8; 32] {
    const WINDOW: usize = 8 * 1024;
    let mut hasher = Sha256::new();
    hasher.update(candidate.kind.as_str().as_bytes());
    hasher.update(candidate.encoding.unwrap_or("raw").as_bytes());
    hasher.update(candidate.estimated_size.to_le_bytes());

    let available = data.get(candidate.offset..).unwrap_or_default();
    let encoded_size = if candidate.encoding == Some("base64") {
        candidate.estimated_size.saturating_mul(4).div_ceil(3)
    } else {
        candidate.estimated_size
    };
    let bytes = &available[..available.len().min(encoded_size)];
    if bytes.len() <= WINDOW * 3 {
        hasher.update(bytes);
    } else {
        hasher.update(&bytes[..WINDOW]);
        let middle = bytes.len() / 2;
        hasher.update(&bytes[middle - WINDOW / 2..middle + WINDOW / 2]);
        hasher.update(&bytes[bytes.len() - WINDOW..]);
    }
    hasher.finalize().into()
}

fn candidate_bucket(offset: usize, file_size: usize) -> usize {
    let bucket_width = file_size.div_ceil(CANDIDATE_BUCKETS).max(1);
    (offset / bucket_width).min(CANDIDATE_BUCKETS - 1)
}

/// Deterministically retain the first and last items and spread the remaining
/// picks across the full ordered input.
fn take_stratified(items: Vec<EmbeddedBinary>, limit: usize) -> Vec<EmbeddedBinary> {
    if items.len() <= limit {
        return items;
    }
    if limit == 0 {
        return Vec::new();
    }
    if limit == 1 {
        return items.into_iter().take(1).collect();
    }

    let last = items.len() - 1;
    (0..limit)
        .map(|slot| slot * last / (limit - 1))
        .map(|index| items[index].clone())
        .collect()
}

// ── Base64-encoded payload scanning ──────────────────────────────────────────

/// Minimum base64-run length to consider a packed-binary candidate.
/// Smaller blobs (<4 KB decoded → ~5.5 KB encoded) hit
/// `MIN_EMBEDDED_ELF_SIZE` after decoding and get filtered there;
/// this gate just avoids decoding every small base64 string in a
/// binary's data section.
const MIN_BASE64_RUN: usize = 8 * 1024;

/// Distinct base64 marker for an aligned `\x7fELF` prefix:
/// `\x7fEL` (3 bytes) → `f0VM`. Adding the next byte (`F` = 0x46)
/// pulls in two more chars, but the first 4 are the unambiguous
/// alignment-0 marker. We use 6 chars so the search rejects more
/// than 99% of false matches before we ever decode.
const ELF_BASE64_PREFIX: &[u8] = b"f0VMRg";

/// PE DOS header `MZ\x90\x00` (universal) → base64 `TVqQAA`.
const PE_BASE64_PREFIX: &[u8] = b"TVqQAA";

fn scan_base64_packed(
    data: &[u8],
    results: &mut Vec<EmbeddedBinary>,
    cancelled: Option<&AtomicBool>,
) {
    for (prefix, expected_kind) in [(ELF_BASE64_PREFIX, "elf"), (PE_BASE64_PREFIX, "pe")] {
        let mut retained_per_bucket = [0u8; CANDIDATE_BUCKETS];
        let mut checked_per_bucket = [0u8; CANDIDATE_BUCKETS];
        for marker_off in memmem::find_iter(data, prefix) {
            if cancelled.is_some_and(|f| f.load(Ordering::Acquire)) {
                return;
            }
            let bucket = candidate_bucket(marker_off, data.len());
            if retained_per_bucket[bucket] >= CANDIDATES_PER_BUCKET
                || checked_per_bucket[bucket] >= HEADER_CHECKS_PER_BUCKET
            {
                continue;
            }
            checked_per_bucket[bucket] += 1;
            // Walk forward from the marker while we stay inside the
            // base64 alphabet. This bounds the run cheaply.
            let run_end = marker_off
                + data[marker_off..]
                    .iter()
                    .take_while(|&&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
                    .count();
            let run_len = run_end - marker_off;
            if run_len < MIN_BASE64_RUN {
                continue;
            }
            let trimmed = &data[marker_off..run_end - run_len % 4];
            // Decode just enough to confirm magic — 256 chars → 192
            // bytes, plenty for header validation.
            let head_chars = trimmed.len().min(256);
            let Ok(head) = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &trimmed[..head_chars - head_chars % 4],
            ) else {
                continue;
            };
            let Some(kind) = classify_decoded_head(&head) else {
                continue;
            };
            // Sanity: the kind we discovered must match what the
            // marker prefix claimed. Otherwise we caught a coincidence.
            if kind.as_str() != expected_kind {
                continue;
            }
            // Estimated decoded size = 3/4 of the run length.
            let estimated_size = (run_len / 4) * 3;
            if estimated_size < MIN_EMBEDDED_ELF_SIZE {
                continue;
            }
            results.push(EmbeddedBinary {
                offset: marker_off,
                kind,
                estimated_size,
                encoding: Some("base64"),
                format_hint: None,
            });
            retained_per_bucket[bucket] += 1;
        }
    }
}

fn classify_decoded_head(data: &[u8]) -> Option<EmbeddedKind> {
    if data.len() < 8 {
        return None;
    }
    if &data[..4] == b"\x7fELF" {
        let class = data[4];
        let endian = data[5];
        return Some(match (class, endian) {
            (1, 1) => EmbeddedKind::Elf32Le,
            (1, 2) => EmbeddedKind::Elf32Be,
            (2, 1) => EmbeddedKind::Elf64Le,
            (2, 2) => EmbeddedKind::Elf64Be,
            _ => return None,
        });
    }
    if &data[..2] == b"MZ" {
        // Probe for the PE signature offset stamped at 0x3c. The
        // base64 head doesn't get us all the way to the PE header
        // (~256 bytes vs ~0x80 minimum), so we accept on DOS magic
        // alone and let downstream consumers re-validate if needed.
        return Some(EmbeddedKind::Pe64);
    }
    None
}

/// Build a finding for a detected embedded binary.
#[must_use]
pub(crate) fn finding_for(binary: &EmbeddedBinary, parent_path: &str) -> Finding {
    let type_upper = binary.kind.as_str().to_uppercase();
    Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        id: format!("binary/embedded/{}", binary.kind.as_str()).into(),
        desc: format!(
            "Embedded {} binary at file offset {:#x} (~{} bytes)",
            type_upper, binary.offset, binary.estimated_size,
        )
        .into(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: Some("T1027.009".into()), // Embedded Payloads
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
        downgraded: false,
    }
}

// ── PE scanning ──────────────────────────────────────────────────────────────

fn scan_pe(data: &[u8], results: &mut Vec<EmbeddedBinary>, cancelled: Option<&AtomicBool>) {
    // Start past byte 0 so we skip the host PE's own MZ header.
    let search_start = 2.min(data.len());
    let finder = memmem::Finder::new(b"MZ");
    let mut pe_results = Vec::new();
    let mut retained_per_bucket = [0u8; CANDIDATE_BUCKETS];
    let mut checked_per_bucket = [0u8; CANDIDATE_BUCKETS];
    for pos in finder.find_iter(&data[search_start..]) {
        if cancelled.is_some_and(|f| f.load(Ordering::Acquire)) {
            break;
        }
        let offset = pos + search_start;
        let bucket = candidate_bucket(offset, data.len());
        if retained_per_bucket[bucket] >= CANDIDATES_PER_BUCKET
            || checked_per_bucket[bucket] >= HEADER_CHECKS_PER_BUCKET
        {
            continue;
        }
        checked_per_bucket[bucket] += 1;
        if let Some(emb) = validate_pe(data, offset) {
            pe_results.push(emb);
            retained_per_bucket[bucket] += 1;
        }
    }
    results.extend(pe_results);
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

    let available_size = data.len().saturating_sub(offset);
    let mut physical_size = section_table_offset.checked_add(n_sections as usize * 40)?;
    physical_size = physical_size.checked_sub(offset)?;
    if section_table_offset < offset
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
        if pointer_to_raw_data == 0 || section_end > available_size {
            return None;
        }
        physical_size = physical_size.max(section_end);
    }

    // Authenticode's security directory stores a file offset, not an RVA.
    // Include it in the physical child span so signed embedded PEs are not
    // carved into malformed unsigned fragments.
    // PE32 standard fields are 96 bytes; PE32+ are 112. `kind` here is
    // only ever Pe32 or Pe64 — the optional-header magic check above
    // rejects everything else — so the non-Pe64 branch is the Pe32 layout.
    let std_fields_len = if matches!(kind, EmbeddedKind::Pe64) {
        112
    } else {
        96
    };
    let data_directory_base = pe_base + 24 + std_fields_len;
    if let (Some(cert_offset), Some(cert_size)) = (
        read_u32_le(data, data_directory_base + 4 * 8).map(|v| v as usize),
        read_u32_le(data, data_directory_base + 4 * 8 + 4).map(|v| v as usize),
    ) && cert_offset > 0
        && cert_size > 0
    {
        let cert_end = cert_offset.checked_add(cert_size)?;
        if cert_end <= available_size {
            physical_size = physical_size.max(cert_end);
        }
    }

    let embedded_data = &data[offset..];
    let format_hint = detect_embedded_pe_format(embedded_data);
    let sfx_size = match format_hint {
        Some("nsis") => nsis_physical_size(embedded_data),
        Some("inno") => Some(available_size),
        _ => None,
    };
    // SizeOfImage describes the loaded virtual address space. Applying it
    // to an on-disk child consumes neighboring resources and can mix their
    // code, metadata, or signatures into this child's analysis.
    let estimated_size = physical_size.max(sfx_size.unwrap_or(0)).min(available_size);

    if estimated_size < MIN_BINARY_SIZE {
        return None;
    }

    Some(EmbeddedBinary {
        offset,
        kind,
        estimated_size,
        encoding: None,
        format_hint,
    })
}

fn detect_embedded_pe_format(data: &[u8]) -> Option<&'static str> {
    if memmem::find(data, &[0xEF, 0xBE, 0xAD, 0xDE]).is_some()
        && [
            b"Nullsoft Install System".as_slice(),
            b"NSIS Error".as_slice(),
            b"nsis.sf.net/NSIS_Error".as_slice(),
            b"/NCRC".as_slice(),
        ]
        .iter()
        .any(|marker| memmem::find(data, marker).is_some())
    {
        return Some("nsis");
    }
    // The marker has to sit NEAR this candidate's header for the candidate to
    // be an Inno stub. `data` runs from the candidate to end-of-file, so an
    // unbounded search also matches the *host's* setup data lying far beyond an
    // unrelated interior PE -- and the "inno" hint then sets the carve size to
    // everything remaining (see `sfx_size` below), which has no upper bound the
    // way `nsis_physical_size` does.
    //
    // AOMEI Backupper Standard is the worked case: a 190MB Inno installer whose
    // helper `callbackctrl.dll` sits at 0x69e04, with an "Inno Setup Setup Data"
    // occurrence 198MB further on at 0xbd17cd5. The DLL was carved as
    // header-to-EOF (198,554,228 bytes), so a small helper DLL was analyzed as a
    // 189MB binary: a vast appended blob with no resources and a handful of
    // imports, which scored `huge-file-tiny-imports` and
    // `pe-missing-rsrc-with-resource-imports` hostile. A genuine stub carries
    // its setup data immediately after it -- this installer's own is at 0x15e5c,
    // roughly 90KB in -- so a 1MiB window is generous for the real shape and
    // excludes the far-away match.
    const INNO_MARKER_WINDOW: usize = 1 << 20;
    let inno_window = &data[..data.len().min(INNO_MARKER_WINDOW)];
    if memmem::find(inno_window, b"Inno Setup Setup Data").is_some() {
        return Some("inno");
    }
    None
}

fn nsis_physical_size(data: &[u8]) -> Option<usize> {
    let header = memmem::find_iter(data, &[0xEF, 0xBE, 0xAD, 0xDE])
        .find(|&pos| data.get(pos + 4..pos + 16) == Some(b"NullsoftInst".as_slice()))?;

    let archive_size = read_u32_le(data, header + 20)? as usize;
    // NSIS stores a three-byte tail after the archive body; 7-Zip reports
    // this separately as "Tail Size = 3".
    let end = header.checked_add(archive_size)?.checked_add(3)?;
    (end <= data.len()).then_some(end)
}

// ── ELF scanning ─────────────────────────────────────────────────────────────

fn scan_elf(data: &[u8], results: &mut Vec<EmbeddedBinary>, cancelled: Option<&AtomicBool>) {
    // Start past byte 0 so we skip the host ELF's own magic.
    let search_start = 4.min(data.len());
    let finder = memmem::Finder::new(b"\x7fELF");
    let mut retained_per_bucket = [0u8; CANDIDATE_BUCKETS];
    let mut checked_per_bucket = [0u8; CANDIDATE_BUCKETS];
    for pos in finder.find_iter(&data[search_start..]) {
        if cancelled.is_some_and(|f| f.load(Ordering::Acquire)) {
            break;
        }
        let offset = pos + search_start;
        let bucket = candidate_bucket(offset, data.len());
        if retained_per_bucket[bucket] >= CANDIDATES_PER_BUCKET
            || checked_per_bucket[bucket] >= HEADER_CHECKS_PER_BUCKET
        {
            continue;
        }
        checked_per_bucket[bucket] += 1;
        if let Some(emb) = validate_elf(data, offset) {
            results.push(emb);
            retained_per_bucket[bucket] += 1;
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

    // e_version (u32) at offset 20 must be EV_CURRENT
    let e_version = read_u32_endian(data, offset + 20, le)?;
    if e_version != 1 {
        return None;
    }

    // e_machine (u16) at offset 18
    let e_machine = read_u16_endian(data, offset + 18, le)?;
    if !VALID_ELF_MACHINES.contains(&e_machine) {
        return None;
    }

    let (kind, ehsize_expected, phentsize_expected, shentsize_expected) = match (class, le) {
        (1, true) => (EmbeddedKind::Elf32Le, 52usize, 32usize, 40usize),
        (1, false) => (EmbeddedKind::Elf32Be, 52usize, 32usize, 40usize),
        (2, true) => (EmbeddedKind::Elf64Le, 64usize, 56usize, 64usize),
        (_, _) => (EmbeddedKind::Elf64Be, 64usize, 56usize, 64usize),
    };

    let phoff_offset = if class == 1 { 28 } else { 32 };
    let shoff_offset = if class == 1 { 32 } else { 40 };
    let ehsize_offset = if class == 1 { 40 } else { 52 };
    let phentsize_offset = ehsize_offset + 2;
    let phnum_offset = phentsize_offset + 2;
    let shentsize_offset = phnum_offset + 2;
    let shnum_offset = shentsize_offset + 2;
    let shstrndx_offset = shnum_offset + 2;

    let ehsize = read_u16_endian(data, offset + ehsize_offset, le)? as usize;
    if ehsize != ehsize_expected {
        return None;
    }

    let phoff = read_u64_class(data, offset + phoff_offset, class, le)? as usize;
    let shoff = read_u64_class(data, offset + shoff_offset, class, le)? as usize;
    let phentsize = read_u16_endian(data, offset + phentsize_offset, le)? as usize;
    let phnum = read_u16_endian(data, offset + phnum_offset, le)? as usize;
    let shentsize = read_u16_endian(data, offset + shentsize_offset, le)? as usize;
    let shnum = read_u16_endian(data, offset + shnum_offset, le)? as usize;
    let shstrndx = read_u16_endian(data, offset + shstrndx_offset, le)? as usize;

    if phnum == 0 && shnum == 0 {
        return None;
    }
    if phnum > 256 || shnum > 512 {
        return None;
    }
    if phnum > 0 && phentsize != phentsize_expected {
        return None;
    }
    if shnum > 0 && shentsize != shentsize_expected {
        return None;
    }
    if phnum == 0 && phoff != 0 {
        return None;
    }
    if shnum == 0 && (shoff != 0 || shstrndx != 0) {
        return None;
    }
    if shnum > 0 && shstrndx >= shnum && shstrndx != 0xFFFF {
        return None;
    }

    let available = data.len().saturating_sub(offset);
    let mut estimated_size = ehsize;
    if phnum > 0 {
        if phoff < ehsize || phoff >= available {
            return None;
        }
        let ph_table_end = phoff.checked_add(phnum.checked_mul(phentsize)?)?;
        if ph_table_end > available {
            return None;
        }
        estimated_size = estimated_size.max(ph_table_end);
    }
    if shnum > 0 {
        if shoff < ehsize || shoff >= available {
            return None;
        }
        let sh_table_end = shoff.checked_add(shnum.checked_mul(shentsize)?)?;
        if sh_table_end > available {
            return None;
        }
        estimated_size = estimated_size.max(sh_table_end);
    }

    let mut loadable_end = 0usize;
    let mut loadable_segments = 0usize;
    if phnum > 0 {
        for i in 0..phnum {
            let ph = offset + phoff + i * phentsize;
            let p_type = read_u32_endian(data, ph, le)?;
            let (p_offset, p_filesz) = if class == 1 {
                (
                    read_u32_endian(data, ph + 4, le)? as usize,
                    read_u32_endian(data, ph + 16, le)? as usize,
                )
            } else {
                (
                    read_u64_endian(data, ph + 8, le)? as usize,
                    read_u64_endian(data, ph + 32, le)? as usize,
                )
            };
            if p_type == 1 {
                loadable_segments += 1;
                let segment_end = p_offset.checked_add(p_filesz)?;
                if p_filesz == 0 || segment_end > available {
                    return None;
                }
                loadable_end = loadable_end.max(segment_end);
            }
        }
    }
    if phnum > 0 && loadable_segments == 0 {
        return None;
    }
    estimated_size = estimated_size.max(loadable_end);
    if estimated_size < MIN_EMBEDDED_ELF_SIZE || estimated_size > available {
        return None;
    }

    Some(EmbeddedBinary {
        offset,
        kind,
        estimated_size,
        encoding: None,
        format_hint: None,
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

fn read_u32_endian(data: &[u8], offset: usize, le: bool) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(bytes)
    } else {
        u32::from_be_bytes(bytes)
    })
}

fn read_u64_endian(data: &[u8], offset: usize, le: bool) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset + 8)?.try_into().ok()?;
    Some(if le {
        u64::from_le_bytes(bytes)
    } else {
        u64::from_be_bytes(bytes)
    })
}

fn read_u64_class(data: &[u8], offset: usize, class: u8, le: bool) -> Option<u64> {
    if class == 1 {
        read_u32_endian(data, offset, le).map(u64::from)
    } else {
        read_u64_endian(data, offset, le)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests;
