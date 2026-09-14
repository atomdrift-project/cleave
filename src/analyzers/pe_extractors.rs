//! PE VS_VERSIONINFO StringTable walker.
//!
//! filefacts owns the full PE structural surface (rich header, imphash,
//! manifest, TLS callbacks, debug directory, inflated sections, resource
//! timestamps). The only function that still lives here is
//! `extract_version_info`, which the embedded-PE name fallback in
//! `analyzers::utils` calls on raw child bytes that haven't been opened
//! through filefacts.

use std::collections::BTreeMap;

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

    let anchor = utf16le("VS_VERSION_INFO");
    let Some(start) = find_subslice(data, &anchor) else {
        return out;
    };

    let window_end = (start + 64 * 1024).min(bound);
    let window = &data[start..window_end];

    // Enumerate structurally valid String entries first, including custom
    // vendor/compiler keys. Malware and legacy toolchains frequently use
    // non-canonical names (for example `CompiledScript`) that the old fixed
    // key list could never surface even though the resource was well formed.
    for struct_start in (0..window.len().saturating_sub(8)).step_by(2) {
        if let Some((key, value)) = parse_string_entry(window, struct_start) {
            out.entry(key).or_insert(value);
        }
    }

    // Keep the direct canonical-key recovery as a fallback for hand-crafted
    // resources with damaged/zeroed String-entry headers.
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
            let aligned = struct_start + ((after_key - struct_start + 3) & !3);
            if aligned + 2 > window.len() {
                continue;
            }
            if let Some(value) = read_utf16le_string(&window[aligned..])
                && !value.is_empty()
            {
                out.entry(key.to_string()).or_insert(value);
            }
        }
    }

    out
}

/// Merge recovered version strings under `pe.version_info`, preserving values
/// already supplied by filefacts and filling only missing canonical/custom keys.
pub(crate) fn augment_version_info_tree(root: &mut serde_json::Value, data: &[u8]) {
    let recovered = extract_version_info(data);
    if recovered.is_empty() {
        return;
    }

    if !root.is_object() {
        *root = serde_json::Value::Object(serde_json::Map::new());
    }
    let Some(root_obj) = root.as_object_mut() else {
        return;
    };
    let pe = root_obj
        .entry("pe".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !pe.is_object() {
        *pe = serde_json::Value::Object(serde_json::Map::new());
    }
    let Some(pe_obj) = pe.as_object_mut() else {
        return;
    };
    let version_info = pe_obj
        .entry("version_info".to_string())
        .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
    if !version_info.is_object() {
        *version_info = serde_json::Value::Object(serde_json::Map::new());
    }
    let Some(version_obj) = version_info.as_object_mut() else {
        return;
    };

    for (key, value) in recovered {
        version_obj
            .entry(version_key_to_snake_case(&key))
            .or_insert_with(|| serde_json::Value::String(value));
    }
}

fn parse_string_entry(data: &[u8], struct_start: usize) -> Option<(String, String)> {
    let length = read_u16_le(data, struct_start)? as usize;
    let value_length = read_u16_le(data, struct_start + 2)? as usize;
    let value_type = read_u16_le(data, struct_start + 4)?;
    if value_type != 1 || value_length == 0 || length < 10 {
        return None;
    }
    let struct_end = struct_start.checked_add(length)?;
    if struct_end > data.len() {
        return None;
    }

    let (key, key_bytes) = read_utf16le_key(data.get(struct_start + 6..struct_end)?)?;
    if !is_plausible_version_key(&key) {
        return None;
    }
    let after_key = struct_start + 6 + key_bytes;
    let value_start = struct_start + ((after_key - struct_start + 3) & !3);
    let declared_end = value_start.checked_add(value_length.saturating_mul(2))?;
    let value_end = declared_end.min(struct_end);
    if value_start >= value_end {
        return None;
    }
    let value = read_utf16le_string(&data[value_start..value_end])?;
    Some((key, value))
}

fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_utf16le_key(bytes: &[u8]) -> Option<(String, usize)> {
    let mut units = Vec::new();
    let (pairs, _) = bytes.as_chunks::<2>();
    for (index, pair) in pairs.iter().take(128).enumerate() {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            let key = String::from_utf16(&units).ok()?;
            return (!key.is_empty()).then_some((key, (index + 1) * 2));
        }
        units.push(unit);
    }
    None
}

fn is_plausible_version_key(key: &str) -> bool {
    key.len() <= 128
        && key.chars().any(|ch| ch.is_ascii_alphabetic())
        && key
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ' '))
}

fn version_key_to_snake_case(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 4);
    let mut previous_was_lower_or_digit = false;
    for ch in key.chars() {
        if ch.is_ascii_uppercase() && previous_was_lower_or_digit && !out.ends_with('_') {
            out.push('_');
        }
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            previous_was_lower_or_digit = ch.is_ascii_lowercase() || ch.is_ascii_digit();
        } else {
            if !out.is_empty() && !out.ends_with('_') {
                out.push('_');
            }
            previous_was_lower_or_digit = false;
        }
    }
    out.trim_matches('_').to_string()
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
    out.extend_from_slice(&[0, 0]);
    out
}

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

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(haystack, needle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Build a minimal binary buffer with a UTF-16LE
    /// `VS_VERSION_INFO\0` anchor + StringTable entries laid out per
    /// the PE/COFF spec: each String entry has a 6-byte header
    /// (wLength, wValueLength, wType) preceding the key, and the
    /// value is padded to a 4-byte boundary measured from the start
    /// of the String struct (NOT from the resource section / window).
    fn build_versioninfo_buffer(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&utf16le("VS_VERSION_INFO"));
        buf.extend_from_slice(&[0u8; 52]);
        for (k, v) in pairs {
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
            let struct_start = buf.len();
            buf.extend_from_slice(&[0u8; 6]);
            buf.extend_from_slice(&utf16le(k));
            while (buf.len() - struct_start) % 4 != 0 {
                buf.push(0);
            }
            buf.extend_from_slice(&utf16le(v));
            let struct_len = (buf.len() - struct_start) as u16;
            let value_len = (v.encode_utf16().count() + 1) as u16;
            buf[struct_start..struct_start + 2].copy_from_slice(&struct_len.to_le_bytes());
            buf[struct_start + 2..struct_start + 4].copy_from_slice(&value_len.to_le_bytes());
            buf[struct_start + 4..struct_start + 6].copy_from_slice(&1u16.to_le_bytes());
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
    fn extract_version_info_preserves_custom_stringtable_keys() {
        let buf = build_versioninfo_buffer(&[(
            "CompiledScript",
            "*E_P_E_N KA* Sorong_papua By LunaMaya",
        )]);
        let info = extract_version_info(&buf);
        assert_eq!(
            info.get("CompiledScript").map(String::as_str),
            Some("*E_P_E_N KA* Sorong_papua By LunaMaya")
        );

        let mut tree = serde_json::json!({"pe": {"machine": "i386"}});
        augment_version_info_tree(&mut tree, &buf);
        assert_eq!(
            tree["pe"]["version_info"]["compiled_script"],
            "*E_P_E_N KA* Sorong_papua By LunaMaya"
        );
    }

    #[test]
    fn extract_version_info_recovers_canonical_key_with_damaged_header() {
        let mut buf = build_versioninfo_buffer(&[("FileDescription", "Damaged resource")]);
        let key_pos = find_subslice(&buf, &utf16le("FileDescription")).unwrap();
        buf[key_pos - 6..key_pos].fill(0);

        let info = extract_version_info(&buf);
        assert_eq!(
            info.get("FileDescription").map(String::as_str),
            Some("Damaged resource")
        );
    }

    #[test]
    fn extract_version_info_does_not_drop_first_value_char() {
        // Regression: real Microsoft DLLs were producing
        // `inRT.Runtime.dll` instead of `WinRT.Runtime.dll` because
        // the value-padding alignment was computed from the window
        // start instead of from the String struct start.
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
