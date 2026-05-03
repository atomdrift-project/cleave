//! Python pickle (`.pkl` / `.pickle` / `.joblib`) structural
//! extraction — surfaces protocol version, referenced modules, and
//! the set of opcodes used as a `pickle.*` kv subtree.
//!
//! Distinct from `analyzers::pickle`'s import / string extraction:
//! that pass collects `module.attr` references for trait matching;
//! this pass surfaces the structural shape (protocol, opcode set,
//! module-only names) so trait authors can target raw structural
//! signals without per-opcode bool fields.
//!
//! # Why these fields
//!
//! Pickle is the canonical Python supply-chain RCE vector — every
//! malicious model file (PyTorch `.pt`, joblib, scikit-learn) carries
//! a pickle stream that loads `os.system` / `subprocess` /
//! `builtins.eval` via the GLOBAL or STACK_GLOBAL opcode. The
//! structural shape (which opcodes are present, what protocol) is
//! itself a strong signal:
//!
//!   * Protocol 0/1: legacy text/short binary forms — rare in modern
//!     ML model files; unexpected presence in a "modern" `.pt` hints
//!     at a hand-crafted payload.
//!   * REDUCE / OBJ / BUILD / INST: classic RCE constructions.
//!   * EXT1/EXT2/EXT4: extension registry abuse — often unused by
//!     legitimate libraries and a strong outlier.
//!
//! # Schema
//!
//! ```text
//! pickle:
//!   protocol      int — from PROTO opcode (0..5); -1 if absent
//!   modules[]     str — distinct module names referenced via
//!                       GLOBAL / STACK_GLOBAL (e.g. `subprocess`,
//!                       `os`, `builtins`)
//!   opcodes[]     str — distinct opcode names seen, sorted
//!                       (e.g. `["GLOBAL", "REDUCE", "STACK_GLOBAL"]`)
//! ```

use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// Cap on opcodes scanned to keep the kv pass cheap on huge model
/// files (multi-GB joblib/pytorch). Real malicious payloads are tiny;
/// this protects against pathological inputs.
const MAX_BYTES_SCANNED: usize = 8 * 1024 * 1024;

/// Build the `pickle.*` kv tree from raw bytes. Returns `None` for
/// empty inputs or streams that don't look like pickle (no recognised
/// opcodes encountered).
#[must_use]
pub(crate) fn extract(data: &[u8]) -> Option<Value> {
    if data.is_empty() {
        return None;
    }
    let scan = &data[..data.len().min(MAX_BYTES_SCANNED)];
    let mut protocol: i32 = -1;
    let mut modules: BTreeSet<String> = BTreeSet::new();
    let mut opcodes: BTreeSet<&'static str> = BTreeSet::new();
    // Track recent SHORT_BINUNICODE strings so STACK_GLOBAL pairs can
    // be resolved to module/attr.
    let mut recent_strings: Vec<&str> = Vec::with_capacity(16);

    let mut i = 0usize;
    while i < scan.len() {
        let op = scan[i];
        if let Some(name) = opcode_name(op) {
            opcodes.insert(name);
        }
        match op {
            0x80 => {
                // PROTO <byte>
                if let Some(p) = scan.get(i + 1) {
                    protocol = i32::from(*p);
                }
                i += 2;
            }
            b'c' => {
                // GLOBAL <module>\n<attr>\n
                let after = i + 1;
                let nl1 = scan
                    .get(after..)
                    .and_then(|s| s.iter().position(|&b| b == b'\n'))?;
                let module_end = after + nl1;
                let module = std::str::from_utf8(&scan[after..module_end]).ok()?;
                if !module.is_empty() {
                    modules.insert(module.to_string());
                }
                let attr_start = module_end + 1;
                let nl2 = scan
                    .get(attr_start..)
                    .and_then(|s| s.iter().position(|&b| b == b'\n'))?;
                i = attr_start + nl2 + 1;
            }
            0x8C => {
                // SHORT_BINUNICODE <len><bytes>
                let len = *scan.get(i + 1)? as usize;
                let start = i + 2;
                let end = start + len;
                if end > scan.len() {
                    break;
                }
                if let Ok(s) = std::str::from_utf8(&scan[start..end]) {
                    recent_strings.push(s);
                    if recent_strings.len() > 16 {
                        recent_strings.remove(0);
                    }
                }
                i = end;
            }
            0x8D => {
                // BINUNICODE8 <8-byte len><bytes>
                let bytes = scan.get(i + 1..i + 9)?.try_into().ok()?;
                let len = u64::from_le_bytes(bytes) as usize;
                i += 9 + len;
            }
            0x8A => {
                // LONG1 <len><bytes>
                let len = *scan.get(i + 1)? as usize;
                i += 2 + len;
            }
            0x8B => {
                // LONG4 <len:u32><bytes>
                let bytes = scan.get(i + 1..i + 5)?.try_into().ok()?;
                let len = u32::from_le_bytes(bytes) as usize;
                i += 5 + len;
            }
            b'X' => {
                // BINUNICODE <len:u32><bytes>
                let bytes = scan.get(i + 1..i + 5)?.try_into().ok()?;
                let len = u32::from_le_bytes(bytes) as usize;
                let start = i + 5;
                let end = start + len;
                if end > scan.len() {
                    break;
                }
                if let Ok(s) = std::str::from_utf8(&scan[start..end]) {
                    recent_strings.push(s);
                    if recent_strings.len() > 16 {
                        recent_strings.remove(0);
                    }
                }
                i = end;
            }
            b'T' => {
                // BINSTRING <len:u32><bytes>
                let bytes = scan.get(i + 1..i + 5)?.try_into().ok()?;
                let len = u32::from_le_bytes(bytes) as usize;
                i += 5 + len;
            }
            b'U' => {
                // SHORT_BINSTRING <len:u8><bytes>
                let len = *scan.get(i + 1)? as usize;
                i += 2 + len;
            }
            0x95 => {
                // FRAME <8-byte len> — frame just precedes payload;
                // we walk through it anyway, no special handling.
                i += 9;
            }
            0x93 => {
                // STACK_GLOBAL — pops attr then module from the
                // stack; the most recent two strings on `recent_strings`
                // are typically (module, attr) for protocol 4+.
                if recent_strings.len() >= 2 {
                    let module = recent_strings[recent_strings.len() - 2];
                    if !module.is_empty() {
                        modules.insert(module.to_string());
                    }
                }
                i += 1;
            }
            // Single-byte opcodes — skip without payload.
            0x29 | 0x28 | 0x2E | 0x30 | 0x31 | 0x32 | 0x33 | 0x52 | 0x5D | 0x61 | 0x62 | 0x65
            | 0x68 | 0x69 | 0x6F | 0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x75 | 0x76 | 0x77 | 0x78
            | 0x79 | 0x7D | 0x81 | 0x82 | 0x83 | 0x84 | 0x85 | 0x86 | 0x87 | 0x88 | 0x89 | 0x8E
            | 0x8F | 0x90 | 0x91 | 0x92 | 0x94 => {
                i += 1;
            }
            // Length-prefixed payloads with known sizes.
            b'I' | b'L' | b'F' | b'V' | b'S' => {
                // Text-form integer/long/float/unicode/string — skip
                // to next newline.
                let nl = scan.get(i + 1..).and_then(|s| s.iter().position(|&b| b == b'\n'))?;
                i += 2 + nl;
            }
            b'g' | b'p' => {
                // GET <int>\n / PUT <int>\n
                let nl = scan.get(i + 1..).and_then(|s| s.iter().position(|&b| b == b'\n'))?;
                i += 2 + nl;
            }
            b'h' | b'q' | b'r' => {
                // BINGET/BINPUT/LONG_BINPUT — 1-byte index + opcode
                i += if op == b'r' { 5 } else { 2 };
            }
            b'J' | b'K' | b'M' | b'G' => {
                // BININT (4) / BININT1 (1) / BININT2 (2) / BINFLOAT (8)
                i += match op {
                    b'J' => 5,
                    b'K' => 2,
                    b'M' => 3,
                    b'G' => 9,
                    _ => 1,
                };
            }
            _ => {
                // Unknown / unhandled opcode — advance one byte and
                // keep walking. Safer than bailing because legitimate
                // pickle streams use the full opcode space.
                i += 1;
            }
        }
    }

    if opcodes.is_empty() && modules.is_empty() && protocol < 0 {
        return None;
    }

    let mut out = Map::new();
    if protocol >= 0 {
        out.insert("protocol".into(), json!(protocol));
    }
    if !modules.is_empty() {
        let v: Vec<&String> = modules.iter().collect();
        out.insert("modules".into(), json!(v));
    }
    if !opcodes.is_empty() {
        let v: Vec<&&str> = opcodes.iter().collect();
        out.insert("opcodes".into(), json!(v));
    }
    Some(Value::Object(out))
}

/// Map a pickle opcode byte to its standard name. Only the opcodes
/// whose presence is interesting to trait authors are named — the
/// others (memo / stack manipulation) just bump the count without
/// becoming visible kv entries.
fn opcode_name(op: u8) -> Option<&'static str> {
    Some(match op {
        b'(' => "MARK",
        b'.' => "STOP",
        b'0' => "POP",
        b'1' => "POP_MARK",
        b'2' => "DUP",
        b'F' => "FLOAT",
        b'I' => "INT",
        b'J' => "BININT",
        b'K' => "BININT1",
        b'L' => "LONG",
        b'M' => "BININT2",
        b'N' => "NONE",
        b'P' => "PERSID",
        b'Q' => "BINPERSID",
        b'R' => "REDUCE",
        b'S' => "STRING",
        b'T' => "BINSTRING",
        b'U' => "SHORT_BINSTRING",
        b'V' => "UNICODE",
        b'X' => "BINUNICODE",
        b'a' => "APPEND",
        b'b' => "BUILD",
        b'c' => "GLOBAL",
        b'd' => "DICT",
        b'}' => "EMPTY_DICT",
        b'e' => "APPENDS",
        b'f' => "GET",
        b'g' => "GET",
        b'h' => "BINGET",
        b'i' => "INST",
        b'j' => "LONG_BINGET",
        b'l' => "LIST",
        b']' => "EMPTY_LIST",
        b'o' => "OBJ",
        b'p' => "PUT",
        b'q' => "BINPUT",
        b'r' => "LONG_BINPUT",
        b's' => "SETITEM",
        b't' => "TUPLE",
        b')' => "EMPTY_TUPLE",
        b'u' => "SETITEMS",
        b'G' => "BINFLOAT",
        0x80 => "PROTO",
        0x81 => "NEWOBJ",
        0x82 => "EXT1",
        0x83 => "EXT2",
        0x84 => "EXT4",
        0x85 => "TUPLE1",
        0x86 => "TUPLE2",
        0x87 => "TUPLE3",
        0x88 => "NEWTRUE",
        0x89 => "NEWFALSE",
        0x8A => "LONG1",
        0x8B => "LONG4",
        0x8C => "SHORT_BINUNICODE",
        0x8D => "BINUNICODE8",
        0x8E => "BINBYTES8",
        0x8F => "EMPTY_SET",
        0x90 => "ADDITEMS",
        0x91 => "FROZENSET",
        0x92 => "NEWOBJ_EX",
        0x93 => "STACK_GLOBAL",
        0x94 => "MEMOIZE",
        0x95 => "FRAME",
        0x96 => "BYTEARRAY8",
        0x97 => "NEXT_BUFFER",
        0x98 => "READONLY_BUFFER",
        _ => return None,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert!(extract(&[]).is_none());
    }

    #[test]
    fn surfaces_protocol_and_global() {
        // PROTO 4, GLOBAL os system, REDUCE, STOP
        let mut data = vec![0x80, 4];
        data.push(b'c');
        data.extend_from_slice(b"os\nsystem\n");
        data.push(b'R');
        data.push(b'.');
        let kv = extract(&data).unwrap();
        assert_eq!(kv["protocol"], 4);
        assert_eq!(kv["modules"][0], "os");
        let opcodes = kv["opcodes"].as_array().unwrap();
        let names: Vec<&str> = opcodes.iter().filter_map(|v| v.as_str()).collect();
        assert!(names.contains(&"PROTO"));
        assert!(names.contains(&"GLOBAL"));
        assert!(names.contains(&"REDUCE"));
        assert!(names.contains(&"STOP"));
    }

    #[test]
    fn surfaces_stack_global_modern() {
        // PROTO 5, FRAME, SHORT_BINUNICODE "subprocess", MEMOIZE,
        // SHORT_BINUNICODE "Popen", MEMOIZE, STACK_GLOBAL, STOP.
        let mut data = vec![0x80, 5, 0x95, 0, 0, 0, 0, 0, 0, 0, 0];
        data.push(0x8C);
        data.push(10);
        data.extend_from_slice(b"subprocess");
        data.push(0x94);
        data.push(0x8C);
        data.push(5);
        data.extend_from_slice(b"Popen");
        data.push(0x94);
        data.push(0x93); // STACK_GLOBAL
        data.push(b'.');
        let kv = extract(&data).unwrap();
        assert_eq!(kv["protocol"], 5);
        let modules = kv["modules"].as_array().unwrap();
        assert!(modules.iter().any(|v| v == "subprocess"));
    }
}
