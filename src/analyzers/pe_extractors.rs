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
                out.insert(key.to_string(), value);
            }
        }
    }

    out
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
    haystack.windows(needle.len()).position(|w| w == needle)
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
