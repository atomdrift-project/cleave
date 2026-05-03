//! Python bytecode (`.pyc`) structural extraction — surfaces the
//! header (magic + flags + timestamp/hash) and any embedded `.py`
//! source filenames as a `pyc.*` kv subtree.
//!
//! # Why these fields
//!
//! Python supply-chain attacks frequently ship rebuilt `.pyc` files
//! that *appear* to match the legitimate `.py` (because Python prefers
//! cached bytecode when timestamps line up) but actually carry
//! attacker-controlled instructions. The marshalled code object
//! embeds `co_filename` — the path to the source file as seen from
//! the build host. A trojanized rebuild leaks a different filename
//! (e.g. `/Users/attacker/work/...` instead of the maintainer's
//! `/build/myproject/src/...`).
//!
//! We don't decode the full marshal stream (it's deeply
//! version-dependent); instead we walk forward looking for ASCII
//! strings ending in `.py` — that's where `co_filename` lands in
//! every Python version since 3.0.
//!
//! # Schema
//!
//! ```text
//! pyc:
//!   magic              hex string of the 4 magic bytes
//!   python_version     mapped from magic, e.g. "3.11"
//!   is_hash_based      bool — PEP 552 hash-based pyc
//!   timestamp          u32 — source mtime (only when not hash-based)
//!   source_size        u32 — source size (only when not hash-based)
//!   source_files[]     ASCII strings ending in `.py` discovered in
//!                      the marshalled body (`co_filename` lives here)
//! ```

use serde_json::{json, Map, Value};

/// Maximum bytes of the `.pyc` body to scan for source-filename
/// strings. Real `co_filename` paths sit very early in the marshal
/// stream; capping the scan keeps the kv pass cheap on huge bytecode
/// modules (think numpy aggregates).
const MAX_BODY_SCAN: usize = 256 * 1024;

/// Maximum number of distinct source filenames to surface.
const MAX_SOURCE_FILES: usize = 32;

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

    let mut out = Map::new();
    out.insert(
        "magic".into(),
        json!(format!("{:08x}", u32::from_le_bytes([data[0], data[1], data[2], data[3]]))),
    );
    if let Some(version) = python_version_for_magic(magic_word) {
        out.insert("python_version".into(), json!(version));
    }
    if is_hash_based {
        out.insert("is_hash_based".into(), json!(true));
    } else {
        let ts = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let sz = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        if ts != 0 {
            out.insert("timestamp".into(), json!(ts));
        }
        if sz != 0 {
            out.insert("source_size".into(), json!(sz));
        }
    }

    // Scan body for ASCII strings ending in `.py`. Marshal's TYPE_ASCII
    // / TYPE_SHORT_ASCII formats prefix strings with a length byte (or
    // 4-byte LE int), so the actual filename bytes appear contiguously
    // in the stream — substring search picks them up reliably without
    // needing a marshal decoder.
    let body = &data[body_offset..body_offset + (data.len() - body_offset).min(MAX_BODY_SCAN)];
    let files = scan_source_files(body);
    if !files.is_empty() {
        out.insert("source_files".into(), json!(files));
    }

    Some(Value::Object(out))
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
        let suffix_len = match body.get(i..i + 3).and_then(|s| {
            if s == b".py" {
                Some(3)
            } else {
                None
            }
        }) {
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
        let mut start = i;
        while start > 0 {
            let b = body[start - 1];
            if !is_path_byte(b) {
                break;
            }
            start -= 1;
        }
        // Require at least one byte before the dot — a bare ".py"
        // alone is marshal noise. Anything longer is a real filename
        // (the byte AFTER the suffix is unreliable: marshal opcodes
        // can be ASCII letters that look like extension chars).
        if start == i {
            i += 1;
            continue;
        }
        // Reject extension-extension cases (`.pythonpath`, `.python3`)
        // by checking the byte right after the suffix is a path-ish
        // continuation. Marshal opcode bytes that follow a real
        // filename are typically *length prefixes* or *type tags* —
        // both are non-alpha — so this only filters true extensions.
        if after < body.len() {
            let term = body[after];
            if term == b'_' || term == b'.' || (term.is_ascii_alphabetic() && (i - start) < 3) {
                i += 1;
                continue;
            }
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
    matches!(b, b'/' | b'\\' | b'.' | b'-' | b'_' | b':' | b'+')
        || b.is_ascii_alphanumeric()
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
