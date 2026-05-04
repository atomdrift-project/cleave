//! `pickle.*` kv subtree — protocol version, distinct modules
//! referenced via GLOBAL / STACK_GLOBAL, and the sorted set of
//! opcode names seen. Pickle is the canonical Python supply-chain
//! RCE vector; the opcode set itself (REDUCE / BUILD / INST /
//! EXT*) is the signal.
//!
//! Schema is the [`PickleKv`] struct.

use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeSet, VecDeque};

#[derive(Default, Serialize)]
struct PickleKv {
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    modules: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    opcodes: Vec<&'static str>,
}

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
    // be resolved to module/attr. VecDeque so eviction past the cap is
    // O(1) — Vec::remove(0) was O(n) per push beyond 16, painful on
    // PyTorch model files with thousands of strings.
    const RECENT_STRING_CAP: usize = 16;
    let mut recent_strings: VecDeque<&str> = VecDeque::with_capacity(RECENT_STRING_CAP);

    let mut i = 0usize;
    while i < scan.len() {
        let op = scan[i];
        if let Some(name) = OPCODE_NAMES[op as usize] {
            opcodes.insert(name);
        }
        // Pull out side-effecting kv updates before advancing —
        // GLOBAL / SHORT_BINUNICODE / BINUNICODE / STACK_GLOBAL / PROTO
        // all mutate `protocol`, `modules`, or `recent_strings`.
        apply_side_effects(
            op,
            i,
            scan,
            &mut protocol,
            &mut modules,
            &mut recent_strings,
            RECENT_STRING_CAP,
        );
        // Advance past the opcode + its payload. `payload_size`
        // returns the total opcode-frame length; `None` means
        // truncated / out-of-bounds and we stop walking.
        let Some(frame) = payload_size(op, i, scan) else {
            break;
        };
        i += frame;
    }

    if opcodes.is_empty() && modules.is_empty() && protocol < 0 {
        return None;
    }
    let kv = PickleKv {
        protocol: (protocol >= 0).then_some(protocol),
        modules: modules.into_iter().collect(),
        opcodes: opcodes.into_iter().collect(),
    };
    serde_json::to_value(kv).ok()
}

/// Total bytes occupied by `op` plus its payload. Returns `None`
/// when the payload would run past `scan.len()` or the length
/// prefix can't be read — the caller treats that as end-of-stream.
fn payload_size(op: u8, i: usize, scan: &[u8]) -> Option<usize> {
    // Newline-terminated text payload (opcode + one `\n`-terminated
    // value): I, L, F, V, S, g, p.
    let read_until_newline = || -> Option<usize> {
        let nl = scan.get(i + 1..)?.iter().position(|&b| b == b'\n')?;
        Some(2 + nl)
    };
    // Length-prefixed payload: opcode + length bytes + N data bytes.
    let read_len_prefixed = |len_bytes: usize, len_value: usize| -> Option<usize> {
        let frame = 1 + len_bytes + len_value;
        if i + frame > scan.len() {
            None
        } else {
            Some(frame)
        }
    };
    match op {
        // Fixed-size payloads, grouped by total frame length:
        //   2 bytes: PROTO / BININT1 / EXT1 / BINGET / BINPUT
        //   3 bytes: EXT2 / BININT2
        //   5 bytes: EXT4 / BININT / LONG_BINPUT
        //   9 bytes: BINFLOAT / FRAME (8-byte length prefix)
        0x80 | b'K' | 0x82 | b'h' | b'q' => Some(2),
        0x83 | b'M' => Some(3),
        0x84 | b'J' | b'r' => Some(5),
        b'G' | 0x95 => Some(9),
        // Newline-terminated.
        b'I' | b'L' | b'F' | b'V' | b'S' | b'g' | b'p' => read_until_newline(),
        // GLOBAL: <module>\n<attr>\n
        b'c' => {
            let m_nl = scan.get(i + 1..)?.iter().position(|&b| b == b'\n')?;
            let attr_start = i + 2 + m_nl;
            let a_nl = scan.get(attr_start..)?.iter().position(|&b| b == b'\n')?;
            Some((attr_start + a_nl + 1) - i)
        }
        // INST: same shape as GLOBAL.
        b'i' => {
            let m_nl = scan.get(i + 1..)?.iter().position(|&b| b == b'\n')?;
            let attr_start = i + 2 + m_nl;
            let a_nl = scan.get(attr_start..)?.iter().position(|&b| b == b'\n')?;
            Some((attr_start + a_nl + 1) - i)
        }
        // Length-prefixed (1-byte length).
        0x8A | 0x8C | b'U' => {
            let len = *scan.get(i + 1)? as usize;
            read_len_prefixed(1, len)
        }
        // Length-prefixed (4-byte LE length).
        0x8B | b'X' | b'T' => {
            let bytes = scan.get(i + 1..i + 5)?.try_into().ok()?;
            let len = u32::from_le_bytes(bytes) as usize;
            read_len_prefixed(4, len)
        }
        // Length-prefixed (8-byte LE length).
        0x8D | 0x96 => {
            let bytes = scan.get(i + 1..i + 9)?.try_into().ok()?;
            let len = u64::from_le_bytes(bytes) as usize;
            read_len_prefixed(8, len)
        }
        // Standalone single-byte opcodes (MARK, STOP, REDUCE,
        // EMPTY_*, NEWOBJ, NEWTRUE / NEWFALSE, MEMOIZE, …) and any
        // unknown opcode both advance one byte. Pickle uses the
        // full opcode space; unfamiliar bytes shouldn't bail.
        _ => Some(1),
    }
}

/// Apply opcode-specific kv side effects (PROTO captures protocol,
/// GLOBAL/STACK_GLOBAL append to modules, SHORT_BINUNICODE/BINUNICODE
/// push to the recent-strings ring buffer).
fn apply_side_effects<'a>(
    op: u8,
    i: usize,
    scan: &'a [u8],
    protocol: &mut i32,
    modules: &mut BTreeSet<String>,
    recent_strings: &mut VecDeque<&'a str>,
    cap: usize,
) {
    let push_recent = |rs: &mut VecDeque<&'a str>, s: &'a str| {
        if rs.len() == cap {
            rs.pop_front();
        }
        rs.push_back(s);
    };
    match op {
        0x80 => {
            if let Some(&p) = scan.get(i + 1) {
                *protocol = i32::from(p);
            }
        }
        b'c' => {
            if let Some(nl) = scan
                .get(i + 1..)
                .and_then(|s| s.iter().position(|&b| b == b'\n'))
            {
                if let Ok(module) = std::str::from_utf8(&scan[i + 1..i + 1 + nl]) {
                    if !module.is_empty() {
                        modules.insert(module.to_string());
                    }
                }
            }
        }
        0x8C => {
            // SHORT_BINUNICODE: 1-byte length then bytes.
            if let Some(&len) = scan.get(i + 1) {
                let start = i + 2;
                let end = start + len as usize;
                if let Some(slice) = scan.get(start..end) {
                    if let Ok(s) = std::str::from_utf8(slice) {
                        push_recent(recent_strings, s);
                    }
                }
            }
        }
        b'X' => {
            // BINUNICODE: 4-byte LE length then bytes.
            if let Some(bytes) = scan.get(i + 1..i + 5) {
                if let Ok(arr) = bytes.try_into() {
                    let len = u32::from_le_bytes(arr) as usize;
                    let start = i + 5;
                    let end = start + len;
                    if let Some(slice) = scan.get(start..end) {
                        if let Ok(s) = std::str::from_utf8(slice) {
                            push_recent(recent_strings, s);
                        }
                    }
                }
            }
        }
        0x93 => {
            // STACK_GLOBAL: pops attr then module from the stack;
            // the most recent two recorded strings are typically
            // (module, attr) for protocol 4+.
            let n = recent_strings.len();
            if let Some(&module) = n.checked_sub(2).and_then(|j| recent_strings.get(j)) {
                if !module.is_empty() {
                    modules.insert(module.to_string());
                }
            }
        }
        _ => {}
    }
}

/// Compile-time-built lookup table mapping every opcode byte to its
/// canonical name. Lookup is `O(1)` via direct indexing — replaces
/// the 75-arm `match` that was previously the largest readability
/// hit in this module.
const OPCODE_NAMES: [Option<&'static str>; 256] = {
    let mut t: [Option<&'static str>; 256] = [None; 256];
    t[b'(' as usize] = Some("MARK");
    t[b'.' as usize] = Some("STOP");
    t[b'0' as usize] = Some("POP");
    t[b'1' as usize] = Some("POP_MARK");
    t[b'2' as usize] = Some("DUP");
    t[b'F' as usize] = Some("FLOAT");
    t[b'I' as usize] = Some("INT");
    t[b'J' as usize] = Some("BININT");
    t[b'K' as usize] = Some("BININT1");
    t[b'L' as usize] = Some("LONG");
    t[b'M' as usize] = Some("BININT2");
    t[b'N' as usize] = Some("NONE");
    t[b'P' as usize] = Some("PERSID");
    t[b'Q' as usize] = Some("BINPERSID");
    t[b'R' as usize] = Some("REDUCE");
    t[b'S' as usize] = Some("STRING");
    t[b'T' as usize] = Some("BINSTRING");
    t[b'U' as usize] = Some("SHORT_BINSTRING");
    t[b'V' as usize] = Some("UNICODE");
    t[b'X' as usize] = Some("BINUNICODE");
    t[b'a' as usize] = Some("APPEND");
    t[b'b' as usize] = Some("BUILD");
    t[b'c' as usize] = Some("GLOBAL");
    t[b'd' as usize] = Some("DICT");
    t[b'}' as usize] = Some("EMPTY_DICT");
    t[b'e' as usize] = Some("APPENDS");
    t[b'g' as usize] = Some("GET");
    t[b'h' as usize] = Some("BINGET");
    t[b'i' as usize] = Some("INST");
    t[b'j' as usize] = Some("LONG_BINGET");
    t[b'l' as usize] = Some("LIST");
    t[b']' as usize] = Some("EMPTY_LIST");
    t[b'o' as usize] = Some("OBJ");
    t[b'p' as usize] = Some("PUT");
    t[b'q' as usize] = Some("BINPUT");
    t[b'r' as usize] = Some("LONG_BINPUT");
    t[b's' as usize] = Some("SETITEM");
    t[b't' as usize] = Some("TUPLE");
    t[b')' as usize] = Some("EMPTY_TUPLE");
    t[b'u' as usize] = Some("SETITEMS");
    t[b'G' as usize] = Some("BINFLOAT");
    t[0x80] = Some("PROTO");
    t[0x81] = Some("NEWOBJ");
    t[0x82] = Some("EXT1");
    t[0x83] = Some("EXT2");
    t[0x84] = Some("EXT4");
    t[0x85] = Some("TUPLE1");
    t[0x86] = Some("TUPLE2");
    t[0x87] = Some("TUPLE3");
    t[0x88] = Some("NEWTRUE");
    t[0x89] = Some("NEWFALSE");
    t[0x8A] = Some("LONG1");
    t[0x8B] = Some("LONG4");
    t[0x8C] = Some("SHORT_BINUNICODE");
    t[0x8D] = Some("BINUNICODE8");
    t[0x8E] = Some("BINBYTES8");
    t[0x8F] = Some("EMPTY_SET");
    t[0x90] = Some("ADDITEMS");
    t[0x91] = Some("FROZENSET");
    t[0x92] = Some("NEWOBJ_EX");
    t[0x93] = Some("STACK_GLOBAL");
    t[0x94] = Some("MEMOIZE");
    t[0x95] = Some("FRAME");
    t[0x96] = Some("BYTEARRAY8");
    t[0x97] = Some("NEXT_BUFFER");
    t[0x98] = Some("READONLY_BUFFER");
    t
};

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
