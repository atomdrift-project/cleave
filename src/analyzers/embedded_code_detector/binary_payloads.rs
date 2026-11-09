//! Base64-embedded executables and archives.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Minimum base64 string length to attempt binary decoding.
pub(super) const MIN_BASE64_LEN: usize = 100;

/// Return true if `s` looks like a base64-encoded blob: long enough and nearly all base64 chars.
pub(super) fn looks_like_base64(s: &str) -> bool {
    if s.len() < MIN_BASE64_LEN {
        return false;
    }
    let bytes = s.as_bytes();
    let base64_count = bytes
        .iter()
        .filter(|&&byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_' | b'\n' | b'\r')
        })
        .count();
    base64_count * 100 / bytes.len() >= 95
}

pub(super) fn strip_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Cheap O(1) gatekeeper for huge strings: decode the first ~256
/// base64 characters and check for ELF / PE / archive magic. Lets
/// `detect_base64_binary` proceed on multi-MB strings *only* when
/// they look like packed binaries — avoiding a full 8MB+ decode on
/// every JSON fixture or source-code blob that happens to be base64-
/// shaped.
///
/// Two paths mirroring `detect_base64_binary`: pre-decoded bytes (via
/// `encoding_chain`) get magic-checked directly; raw text gets a
/// trial decode of just the head.
pub(super) fn head_decodes_to_known_magic(string_info: &StringInfo) -> bool {
    if string_info
        .encoding_chain
        .iter()
        .any(|e| e == "base64" || e == "base64-obf")
    {
        return filefacts::payload_magic(string_info.value.as_bytes()).is_some();
    }
    head_decodes_to_known_magic_text(&string_info.value)
}

pub(super) fn head_decodes_to_known_magic_text(value: &str) -> bool {
    if !looks_like_base64(value) {
        return false;
    }
    // 256 base64 chars decode to 192 bytes — plenty for any magic check.
    let head_chars: String = value
        .chars()
        .filter(|c| !c.is_whitespace())
        .take(256)
        .collect();
    // Must be a multiple of 4 for standard base64; truncate.
    let trimmed = &head_chars[..head_chars.len() - (head_chars.len() % 4)];
    base64::Engine::decode(&base64::engine::general_purpose::STANDARD, trimmed)
        .or_else(|_| {
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, trimmed)
        })
        .ok()
        .and_then(|bytes| filefacts::payload_magic(&bytes))
        .is_some()
}

/// Try to decode `string_info` as base64 containing a binary payload (PE, ELF, or archive).
/// Only runs at depth 0 to prevent compounding recursion.
///
/// Two paths:
/// - `encoding_chain = ["base64"]`: stng already decoded this; treat the value bytes directly.
/// - No encoding chain: try to base64-decode the value text and check magic.
pub(super) fn detect_base64_binary(
    parent_path: &str,
    string_info: &StringInfo,
    depth: u32,
    engine: &crate::Engine,
) -> Vec<FileAnalysis> {
    if depth > 0 {
        return Vec::new();
    }

    // Path 1: stng already decoded the base64 for us — value bytes ARE the payload.
    let decoded: Vec<u8> = if string_info
        .encoding_chain
        .iter()
        .any(|e| e == "base64" || e == "base64-obf")
    {
        string_info.value.as_bytes().to_vec()
    } else {
        // Path 2: raw base64 text — decode it ourselves.
        if !looks_like_base64(&string_info.value) {
            return Vec::new();
        }
        let clean = strip_whitespace(&string_info.value);
        match base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &clean).or_else(
            |_| base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &clean),
        ) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        }
    };

    let Some(inner_type) = filefacts::payload_magic(&decoded) else {
        return Vec::new();
    };
    if matches!(inner_type, "elf" | "pe") && decoded.len() < MIN_BASE64_EXECUTABLE_SIZE {
        return Vec::new();
    }
    if matches!(inner_type, "gz" | "zip" | "xz" | "lzma" | "bz2")
        && decoded.len() < MIN_BASE64_COMPRESSED_SIZE
    {
        return Vec::new();
    }
    let offset = string_info.offset.unwrap_or(0);
    let virtual_path = format!("{}##base64@{:#x}", parent_path, offset);
    let sha256 = crate::analyzers::utils::calculate_sha256(&decoded);

    // ZIP is also the container for documents and ordinary application assets.
    // Encoding plus archive magic establishes a format property, not evasion.
    // The dispatcher below still analyzes every decoded member for behavior.
    let is_archive = matches!(inner_type, "zip" | "gz" | "xz" | "lzma" | "bz2");
    let finding = Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        id: if is_archive {
            format!("metadata/file/encoding::base64-decoded-{inner_type}").into()
        } else {
            format!("binary/embedded/base64-{}", inner_type).into()
        },
        desc: if is_archive {
            format!(
                "Base64-encoded {} archive ({} decoded bytes)",
                inner_type.to_uppercase(),
                decoded.len()
            )
        } else {
            format!(
                "Base64-encoded {} payload ({} bytes decoded) at offset {:#x}",
                inner_type.to_uppercase(),
                decoded.len(),
                offset,
            )
        }
        .into(),
        conf: 0.85,
        crit: if is_archive {
            Criticality::Notable
        } else {
            Criticality::Suspicious
        },
        mbc: None,
        attack: if is_archive {
            None
        } else {
            Some("T1027.009".into())
        },
        evidence: vec![Evidence {
            method: "base64_magic_detection".to_string(),
            source: "embedded_code_detector".to_string(),
            value: format!("decoded_size={} inner_type={}", decoded.len(), inner_type),
            location: Some(format!("offset:{:#x}", offset)),
            ..Default::default()
        }],
        match_count: 1,
        trait_refs: vec![],
        source_file: Some(parent_path.to_string()),
        downgraded: false,
    };

    let mut entry = FileAnalysis::new(
        0,
        virtual_path.clone(),
        inner_type.to_string(),
        sha256,
        decoded.len() as u64,
    );
    entry.depth = depth + 1;
    entry.encoding = Some(vec!["base64".to_string()]);
    entry.findings = vec![finding];
    entry.compute_summary();

    // For container payloads (gz / zip / tar / xz / bz2 / elf / pe),
    // hand the decoded bytes to the unified sub-file dispatcher so
    // the archive is walked and its members get the full analyzer
    // treatment — this is how shell→base64→tar.gz→python reaches
    // the innermost python file. Source-language payloads (Python /
    // Shell / JS in raw base64) are handled by the embedded-code
    // path immediately above and don't go through this dispatcher.
    let mut out = vec![entry];
    if let Some(inner_file_type) = inner_type_to_file_type(inner_type, &decoded, &virtual_path) {
        let sub_entries = crate::analyzers::subfile::analyze_subfile_bytes(
            &decoded,
            &virtual_path,
            inner_file_type,
            &format!("embedded@{:#x}", offset),
            depth + 1,
            engine,
        );
        out.extend(sub_entries);
    }
    out
}

/// Map the `filefacts::payload_magic` string ("gz", "zip", …) back to a
/// [`FileType`] using filefacts's magic detector. `filefacts::payload_magic`
/// returned a stable string label ("gz", "tar.gz", "elf", "pe", …);
/// re-running detect_file_type_from_data is the right way to get a
/// strongly-typed [`FileType`] that the analyzer dispatcher
/// understands — single source of truth for the byte-pattern →
/// FileType mapping.
pub(super) fn inner_type_to_file_type(
    inner_type: &str,
    decoded: &[u8],
    virtual_path: &str,
) -> Option<crate::analyzers::FileType> {
    // Re-detect from the full byte buffer (`payload_magic` only inspects
    // the leading magic; the full detector also distinguishes
    // bare-gz from tar.gz, plain-tar from .gem, etc.).
    let detected =
        crate::analyzers::detect_file_type_from_data(std::path::Path::new(virtual_path), decoded);
    if detected != crate::analyzers::FileType::Unknown {
        return Some(detected);
    }
    // Fall back to the `payload_magic` label so callers get *some*
    // dispatch decision — better an over-broad attempt than no
    // recursion at all for unusual file headers.
    match inner_type {
        "gz" => Some(crate::analyzers::FileType::Gz),
        "zip" => Some(crate::analyzers::FileType::Zip),
        "xz" => Some(crate::analyzers::FileType::Xz),
        "lzma" => Some(crate::analyzers::FileType::Lzma),
        "bz2" => Some(crate::analyzers::FileType::Bz2),
        "tar.gz" => Some(crate::analyzers::FileType::TarGz),
        "tar" => Some(crate::analyzers::FileType::Tar),
        "elf" => Some(crate::analyzers::FileType::Elf),
        "pe" => Some(crate::analyzers::FileType::Pe),
        _ => None,
    }
}
