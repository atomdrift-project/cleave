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
        return magic_type(string_info.value.as_bytes()).is_some();
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
        .and_then(|bytes| magic_type(&bytes))
        .is_some()
}

/// Detect archive/binary type from raw magic bytes.
pub(super) fn magic_type(data: &[u8]) -> Option<&'static str> {
    filefacts::archive_magic(data).or_else(|| {
        if data.starts_with(b"MZ") {
            Some("pe")
        } else if data.len() >= 4 && data[..4] == [0x7F, 0x45, 0x4C, 0x46] {
            Some("elf")
        } else {
            None
        }
    })
}

/// Recognize the small Firefox profile bootstrap archive used by browser
/// integration tests. The content check is intentionally structural: an XZ
/// stream must contain only Firefox `profiles.ini`/`installs.ini` metadata and
/// a profile `times.json`. A similarly named test file carrying another
/// compressed payload still gets reported.
pub(super) fn is_firefox_profile_bootstrap_fixture(data: &[u8]) -> bool {
    const MAX_EXPANDED_SIZE: u64 = 32 * 1024;
    const MAX_MEMBERS: usize = 8;

    let decoder = xz2::read::XzDecoder::new(std::io::Cursor::new(data)).take(MAX_EXPANDED_SIZE + 1);
    let mut archive = tar::Archive::new(decoder);
    let Ok(entries) = archive.entries() else {
        return false;
    };

    let mut profiles_ini = None;
    let mut installs_ini = None;
    let mut times_json = None;
    let mut member_count = 0;
    let mut total_size = 0u64;
    for entry in entries {
        let Ok(entry) = entry else {
            return false;
        };
        member_count += 1;
        if member_count > MAX_MEMBERS {
            return false;
        }
        total_size = total_size.saturating_add(entry.header().size().unwrap_or(0));
        if total_size > MAX_EXPANDED_SIZE {
            return false;
        }
        if entry.header().entry_type().is_dir() {
            continue;
        }

        let Ok(path) = entry.path() else {
            return false;
        };
        let path = path.to_string_lossy();
        let slot = if path == "profiles.ini" {
            &mut profiles_ini
        } else if path == "installs.ini" {
            &mut installs_ini
        } else if path.ends_with("/times.json") {
            &mut times_json
        } else {
            return false;
        };
        if slot.is_some() {
            return false;
        }
        let mut content = String::new();
        if entry.take(4097).read_to_string(&mut content).is_err() || content.len() > 4096 {
            return false;
        }
        *slot = Some(content);
    }

    let (Some(profiles_ini), Some(installs_ini), Some(times_json)) =
        (profiles_ini, installs_ini, times_json)
    else {
        return false;
    };

    let mut in_default_release_profile = false;
    let mut default_release_path = None;
    for line in profiles_ini.lines() {
        if line.starts_with('[') {
            in_default_release_profile = false;
        } else if line == "Name=default-release" {
            in_default_release_profile = true;
        } else if in_default_release_profile && let Some(path) = line.strip_prefix("Path=") {
            default_release_path = Some(path);
            break;
        }
    }
    let Some(default_release_path) = default_release_path else {
        return false;
    };

    default_release_path.ends_with(".default-release")
        && profiles_ini.contains("[Profile")
        && profiles_ini.contains("IsRelative=1")
        && installs_ini.contains(&format!("Default={default_release_path}"))
        && times_json.contains("\"created\"")
        && times_json.contains("\"firstUse\"")
}

pub(super) fn is_test_source_path(path: &str) -> bool {
    path.split(['/', '\\', '!']).any(|component| {
        matches!(component, "test" | "tests" | "testing")
            || component.starts_with("test_")
            || component.ends_with("_test.py")
    })
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

    let Some(inner_type) = magic_type(&decoded) else {
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
    // Browser-cookie3's integration test embeds a tiny, non-secret Firefox
    // profile bootstrap tar.xz. Confirm both its test-source context and its
    // profile metadata before suppressing this generic compressed-payload
    // signal; path names alone must not hide embedded archives.
    if inner_type == "xz"
        && is_test_source_path(parent_path)
        && is_firefox_profile_bootstrap_fixture(&decoded)
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

/// Map the `magic_type` string ("gz", "zip", …) back to a
/// [`FileType`] using filefacts's magic detector. `magic_type`
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
    // Re-detect from the full byte buffer (magic_type only inspects
    // the leading magic; the full detector also distinguishes
    // bare-gz from tar.gz, plain-tar from .gem, etc.).
    let detected =
        crate::analyzers::detect_file_type_from_data(std::path::Path::new(virtual_path), decoded);
    if detected != crate::analyzers::FileType::Unknown {
        return Some(detected);
    }
    // Fall back to the magic_type label so callers get *some*
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
