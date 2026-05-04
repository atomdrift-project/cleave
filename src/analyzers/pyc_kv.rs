//! `pyc.*` kv subtree — `.pyc` header (magic + flags +
//! timestamp/hash) and any `.py` source filenames recovered from
//! the marshalled code object's `co_filename`. Source-path leaks
//! catch trojanized rebuilds where the path differs from the
//! maintainer's expected build tree.
//!
//! Marshal-format-agnostic: scans for ASCII `.py` strings rather
//! than decoding the version-specific marshal stream. Schema is the
//! [`PycKv`] struct.

use serde::Serialize;
use serde_json::Value;

/// Maximum bytes of the `.pyc` body to scan for source-filename
/// strings. Real `co_filename` paths sit very early in the marshal
/// stream; capping the scan keeps the kv pass cheap on huge bytecode
/// modules (think numpy aggregates).
const MAX_BODY_SCAN: usize = 256 * 1024;

/// Maximum number of distinct source filenames to surface.
const MAX_SOURCE_FILES: usize = 32;

#[derive(Default, Serialize)]
struct PycKv {
    magic: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    python_version: Option<&'static str>,
    #[serde(skip_serializing_if = "is_false")]
    is_hash_based: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    timestamp: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_size: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    source_files: Vec<String>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_false(b: &bool) -> bool {
    !*b
}

/// Extract `pyc.*` kv tree from Python bytecode. Returns `None` for
/// inputs that don't look like a `.pyc` (header too short / unknown
/// magic).
#[must_use]
pub(crate) fn extract(data: &[u8]) -> Option<Value> {
    if data.len() < 16 {
        return None;
    }
    // PEP 3147+ magic ends in 0x0d 0x0a (`\r\n`). Bail early on inputs
    // that obviously aren't bytecode rather than trying to walk a
    // malformed stream.
    if data[2] != 0x0D || data[3] != 0x0A {
        return None;
    }
    let magic_word = u16::from_le_bytes([data[0], data[1]]);
    let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let is_hash_based = (flags & 1) != 0;
    let body_offset = 16; // header is fixed at 16 bytes since 3.7

    // Marshal's TYPE_ASCII / TYPE_SHORT_ASCII formats prefix strings
    // with a length byte (or 4-byte LE int), so the actual filename
    // bytes appear contiguously in the body — substring search picks
    // them up without needing a marshal decoder.
    let body = &data[body_offset..body_offset + (data.len() - body_offset).min(MAX_BODY_SCAN)];

    let kv = PycKv {
        magic: format!(
            "{:08x}",
            u32::from_le_bytes([data[0], data[1], data[2], data[3]])
        ),
        python_version: python_version_for_magic(magic_word),
        is_hash_based,
        timestamp: (!is_hash_based)
            .then(|| u32::from_le_bytes([data[8], data[9], data[10], data[11]]))
            .filter(|&v| v != 0),
        source_size: (!is_hash_based)
            .then(|| u32::from_le_bytes([data[12], data[13], data[14], data[15]]))
            .filter(|&v| v != 0),
        source_files: scan_source_files(body),
    };
    serde_json::to_value(kv).ok()
}

/// Map a Python bytecode magic number to a human-readable Python
/// release. Values from CPython's `importlib._bootstrap_external`
/// (the canonical table). Unknown magics return `None` so the kv
/// path stays absent rather than carrying a stale label.
fn python_version_for_magic(magic: u16) -> Option<&'static str> {
    // CPython adds new magics every minor release (and sometimes
    // mid-cycle for bytecode changes). Cover 3.6 onward — older
    // versions are EOL and unlikely in active supply-chain analysis.
    match magic {
        3379 => Some("3.6"),
        3390..=3394 => Some("3.7"),
        3400..=3413 => Some("3.8"),
        3420..=3425 => Some("3.9"),
        3430..=3439 => Some("3.10"),
        3450..=3495 => Some("3.11"),
        3500..=3531 => Some("3.12"),
        3550..=3571 => Some("3.13"),
        _ => None,
    }
}

/// Walk the body looking for ASCII byte runs that end in `.py` (or
/// `.pyx`/`.pyw`). Bounded by `MAX_SOURCE_FILES` and
/// `MAX_BODY_SCAN`. De-duplicates while preserving first-seen order.
fn scan_source_files(body: &[u8]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut i = 0;
    while i < body.len() {
        if body[i] != b'.' {
            i += 1;
            continue;
        }
        // Look for ".py" / ".pyx" / ".pyw" / ".pyi" then a non-path
        // boundary byte (NUL, control char, or another length byte).
        let suffix_len = match body
            .get(i..i + 3)
            .and_then(|s| if s == b".py" { Some(3) } else { None })
        {
            Some(n) => {
                let extra = match body.get(i + 3) {
                    Some(b) if matches!(*b, b'x' | b'w' | b'i') => 1,
                    _ => 0,
                };
                n + extra
            }
            None => {
                i += 1;
                continue;
            }
        };
        let after = i + suffix_len;
        // Walk backwards from the dot to the start of the path run.
        // Require at least one path byte before the dot — a bare
        // ".py" with no name is marshal noise. The `MAX_SOURCE_FILES`
        // cap upstream bounds false positives; trying to filter
        // longer-extension cases like `.python3` by looking at the
        // byte after `.py` proved unreliable (marshal opcode bytes
        // can be ASCII letters too).
        let mut start = i;
        while start > 0 && is_path_byte(body[start - 1]) {
            start -= 1;
        }
        if start == i {
            i += 1;
            continue;
        }
        if let Ok(s) = std::str::from_utf8(&body[start..after]) {
            if !s.is_empty() && !found.iter().any(|x| x == s) {
                found.push(s.to_string());
                if found.len() >= MAX_SOURCE_FILES {
                    return found;
                }
            }
        }
        i = after;
    }
    found
}

fn is_path_byte(b: u8) -> bool {
    matches!(b, b'/' | b'\\' | b'.' | b'-' | b'_' | b':' | b'+') || b.is_ascii_alphanumeric()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn build_pyc(magic_word: u16, flags: u32, ts: u32, sz: u32, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + body.len());
        out.extend_from_slice(&magic_word.to_le_bytes());
        out.extend_from_slice(&[0x0D, 0x0A]);
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&ts.to_le_bytes());
        out.extend_from_slice(&sz.to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn rejects_too_short() {
        assert!(extract(b"short").is_none());
    }

    #[test]
    fn rejects_bad_signature() {
        let data = vec![0u8; 32];
        assert!(extract(&data).is_none());
    }

    #[test]
    fn surfaces_header_and_filenames() {
        // 3413 → Python 3.8
        let mut body = Vec::new();
        body.push(0x10); // length byte (TYPE_SHORT_ASCII format)
        body.extend_from_slice(b"/build/foo/bar.py");
        body.push(0); // boundary
        let pyc = build_pyc(3413, 0, 1_700_000_000, 1234, &body);
        let kv = extract(&pyc).unwrap();
        assert_eq!(kv["python_version"], "3.8");
        assert_eq!(kv["timestamp"], 1_700_000_000_u32);
        assert_eq!(kv["source_size"], 1234);
        assert_eq!(kv["source_files"][0], "/build/foo/bar.py");
    }

    #[test]
    fn hash_based_skips_timestamp() {
        let body = b"\x10/build/foo.py\x00".to_vec();
        let pyc = build_pyc(3439, 0x01, 0, 0, &body);
        let kv = extract(&pyc).unwrap();
        assert_eq!(kv["is_hash_based"], true);
        assert!(kv.get("timestamp").is_none());
        assert_eq!(kv["source_files"][0], "/build/foo.py");
    }

    #[test]
    fn unknown_magic_omits_version() {
        let pyc = build_pyc(9999, 0, 0, 0, b"");
        let kv = extract(&pyc).unwrap();
        assert!(kv.get("python_version").is_none());
        assert!(kv.get("magic").is_some());
    }

    #[test]
    fn dedups_and_caps_source_files() {
        let mut body = Vec::new();
        for _ in 0..MAX_SOURCE_FILES + 5 {
            body.push(0x10);
            body.extend_from_slice(b"/tmp/file.py");
            body.push(0);
        }
        let pyc = build_pyc(3413, 0, 1, 1, &body);
        let kv = extract(&pyc).unwrap();
        let files = kv["source_files"].as_array().unwrap();
        assert_eq!(files.len(), 1); // de-duplicated to a single entry
    }
}
