//! Recover data encoded by x86-64 indexed subtract/XOR integer tables.
//! Only recognized instruction forms and file-backed operands are read. No
//! specimen instructions are executed. A recovered alphabet is derived from
//! the file, and decoded text is analyzed separately without inferring intent.
use super::primitives::{u32_le, unhex};
use filefacts::{ParsedFile, Section};

pub(crate) struct RecoveredText {
    pub(crate) data: Vec<u8>,
    pub(crate) offset: usize,
}
const MAX_TEXT: usize = 1024 * 1024;
const MAX_TABLES: usize = 32;
fn bytes(b: &[u8], p: usize, n: usize) -> Option<&[u8]> {
    b.get(p..p.checked_add(n)?)
}
fn rip(code: &[u8], va: u64, pos: usize) -> Option<u64> {
    let disp = i32::from_le_bytes(bytes(code, pos.checked_add(3)?, 4)?.try_into().ok()?);
    va.checked_add(u64::try_from(pos.checked_add(7)?).ok()?)?
        .checked_add_signed(i64::from(disp))
}
fn mapped(sections: &[Section], va: u64, len: usize) -> Option<usize> {
    sections.iter().find_map(|s| {
        let delta = va.checked_sub(s.vaddr)?;
        if delta.checked_add(u64::try_from(len).ok()?)? > s.file_size {
            return None;
        }
        usize::try_from(s.file_offset.checked_add(delta)?).ok()
    })
}
fn table(
    data: &[u8],
    sections: &[Section],
    arr: u64,
    sub: u64,
    xor: u64,
    count: usize,
) -> Option<RecoveredText> {
    if !(16..=MAX_TEXT).contains(&count) {
        return None;
    }
    let len = count.checked_mul(4)?;
    let [a, s, x] = [arr, sub, xor].map(|v| mapped(sections, v, len));
    let (a, s, x) = (a?, s?, x?);
    let mut text = Vec::with_capacity(count);
    for i in 0..count {
        let j = i.checked_mul(4)?;
        let value = u32_le(data, a.checked_add(j)?)?.wrapping_sub(u32_le(data, s.checked_add(j)?)?)
            ^ u32_le(data, x.checked_add(j)?)?;
        text.push(value as u8);
    }
    Some(RecoveredText {
        data: unhex(&text)?,
        offset: a,
    })
}
fn base64_custom(data: &[u8], alphabet: &[u8]) -> Option<Vec<u8>> {
    if alphabet.len() != 64 {
        return None;
    }
    let mut lookup = [u8::MAX; 256];
    for (i, &ch) in alphabet.iter().enumerate() {
        if !(33..=126).contains(&ch) || lookup[usize::from(ch)] != u8::MAX {
            return None;
        }
        lookup[usize::from(ch)] = i as u8;
    }
    let mut bits = 0u32;
    let mut count = 0u8;
    let mut out = Vec::new();
    for &ch in data {
        let n = lookup[usize::from(ch)];
        // Discarding unknown bytes could manufacture apparent code. Reject
        // unsupported padding rather than guessing an alphabet position.
        if n == u8::MAX {
            return None;
        }
        bits = (bits << 6) | u32::from(n);
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
        }
    }
    if out.is_empty() || out.len() > MAX_TEXT || std::str::from_utf8(&out).is_err() {
        return None;
    }
    if out
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        .count()
        * 100
        < out.len() * 95
    {
        return None;
    }
    Some(out)
}
/// At most 32 tables, 1 MiB per table, from the first code-bearing Mach-O
/// slice. Unsupported instruction layouts return no recovered text.
pub(crate) fn recover(data: &[u8], parsed: &ParsedFile<'_>) -> Vec<RecoveredText> {
    if data.len() > 32 * 1024 * 1024 {
        return Vec::new();
    }
    let sections = parsed.sections();
    recover_sections(data, sections.as_slice())
}

fn recover_sections(data: &[u8], sections: &[Section]) -> Vec<RecoveredText> {
    let Some(text) = sections.iter().find(|s| s.name.ends_with("__text")) else {
        return Vec::new();
    };
    let (Ok(off), Ok(size)) = (
        usize::try_from(text.file_offset),
        usize::try_from(text.file_size),
    ) else {
        return Vec::new();
    };
    if size > 2 * 1024 * 1024 {
        return Vec::new();
    }
    let Some(code) = bytes(data, off, size) else {
        return Vec::new();
    };
    let mut tables = Vec::new();
    for pos in 0..code.len() {
        if tables.len() == MAX_TABLES {
            break;
        }
        // Flattened sequential loop: sub and xor table addresses are loaded
        // into r15/r13; the data table into rax. The same r12 index is used
        // in all three operations, and the result goes to push_back.
        if bytes(code, pos, 3) == Some(&[0x4c, 0x8d, 0x3d]) {
            let Some(sub) = rip(code, text.vaddr, pos) else {
                continue;
            };
            if bytes(code, pos + 7, 3) != Some(&[0x4c, 0x8d, 0x2d]) {
                continue;
            }
            let Some(xor) = rip(code, text.vaddr, pos + 7) else {
                continue;
            };
            for q in pos.saturating_add(14)..pos.saturating_add(100).min(code.len()) {
                if bytes(code, q, 3) != Some(&[0x48, 0x8d, 0x05]) {
                    continue;
                }
                if bytes(code, q + 7, 17)
                    != Some(&[
                        0x42, 0x8b, 0x04, 0xa0, 0x43, 0x2b, 0x04, 0xa7, 0x43, 0x33, 0x44, 0xa5,
                        0x00, 0x0f, 0xbe, 0xf0, 0x48,
                    ])
                {
                    continue;
                }
                let mut count = None;
                for k in pos + 14..q {
                    if bytes(code, k, 3) == Some(&[0x41, 0x83, 0xfc]) {
                        count = bytes(code, k + 3, 1).map(|b| usize::from(b[0]) + 1);
                    }
                    if bytes(code, k, 3) == Some(&[0x41, 0x81, 0xfc]) {
                        count = u32_le(code, k + 3)
                            .and_then(|n| usize::try_from(n).ok())
                            .and_then(|n| n.checked_add(1));
                    }
                }
                if let (Some(count), Some(arr)) = (count, rip(code, text.vaddr, q))
                    && let Some(t) = table(data, sections, arr, sub, xor, count)
                {
                    tables.push(t);
                }
                break;
            }
        }
        // Permuted loop: rcx is an index permutation. rdx/rsi/rdi hold the
        // three operand tables; each decoded byte is stored at that index.
        if bytes(code, pos, 3) == Some(&[0x48, 0x8d, 0x0d])
            && bytes(code, pos + 7, 3) == Some(&[0x48, 0x8d, 0x15])
            && bytes(code, pos + 14, 3) == Some(&[0x48, 0x8d, 0x35])
            && bytes(code, pos + 21, 3) == Some(&[0x48, 0x8d, 0x3d])
        {
            let [Some(order), Some(arr), Some(sub), Some(xor)] =
                [pos, pos + 7, pos + 14, pos + 21].map(|p| rip(code, text.vaddr, p))
            else {
                continue;
            };
            let Some(n) = xor
                .checked_sub(arr)
                .and_then(|n| usize::try_from(n / 4).ok())
            else {
                continue;
            };
            if !(16..=MAX_TEXT).contains(&n) || sub.checked_sub(xor) != u64::try_from(n * 4).ok() {
                continue;
            }
            let Some(order_offset) = mapped(sections, order, n * 4) else {
                continue;
            };
            let mut seen = vec![false; n];
            let mut valid = true;
            for i in 0..n {
                let Some(idx) =
                    u32_le(data, order_offset + i * 4).and_then(|n| usize::try_from(n).ok())
                else {
                    valid = false;
                    break;
                };
                if idx >= n || seen[idx] {
                    valid = false;
                    break;
                }
                seen[idx] = true;
            }
            if !valid {
                continue;
            }
            let win = bytes(code, pos, 160.min(code.len() - pos)).unwrap_or_default();
            if !win.windows(12).any(|w| {
                w == [
                    0x46, 0x8b, 0x0c, 0x82, 0x46, 0x2b, 0x0c, 0x86, 0x46, 0x33, 0x0c, 0x87,
                ]
            }) {
                continue;
            }
            if let Some(t) = table(data, sections, arr, sub, xor, n) {
                tables.push(t);
            }
        }
    }
    let mut result = Vec::new();
    for alphabet in &tables {
        if alphabet.data.len() != 64 {
            continue;
        }
        for t in &tables {
            if t.data.len() == 64 {
                continue;
            }
            if let Some(data) = base64_custom(&t.data, &alphabet.data)
                && !result.iter().any(|r: &RecoveredText| r.data == data)
            {
                result.push(RecoveredText {
                    data,
                    offset: t.offset,
                });
            }
        }
    }
    result
}

/// Accept a complete single quoted inline invocation, optionally backgrounded.
/// Shell tails and incomplete wrappers are never interpreted as script source.
pub(crate) fn inline_applescript(command: &str) -> Option<&str> {
    let body = command.strip_prefix("osascript -e '")?;
    body.strip_suffix("'&")
        .or_else(|| body.strip_suffix("' &"))
        .or_else(|| body.strip_suffix('\''))
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::panic,
        reason = "invalid fixtures should fail the test"
    )]
    use super::*;

    fn fixture(command: &[u8], permuted: bool) -> (Vec<u8>, Vec<Section>) {
        use base64::Engine as _;
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(command);
        let inputs = [alphabet.as_slice(), encoded.as_bytes()];
        let mut data = vec![0x90; 512];
        for (i, input) in inputs.iter().enumerate() {
            let hex: String = input.iter().map(|v| format!("{v:02x}")).collect();
            let n = hex.len();
            let a = data.len();
            for b in hex.bytes() {
                data.extend_from_slice(&((u32::from(b) ^ 0x39) + 11).to_le_bytes());
            }
            let first = data.len();
            for _ in 0..n {
                data.extend_from_slice(&(if permuted { 0x39u32 } else { 11u32 }).to_le_bytes());
            }
            let second = data.len();
            for _ in 0..n {
                data.extend_from_slice(&(if permuted { 11u32 } else { 0x39u32 }).to_le_bytes());
            }
            let (sub, xor) = if permuted {
                (second, first)
            } else {
                (first, second)
            };
            let order = data.len();
            if permuted {
                for idx in (0..n).rev() {
                    data.extend_from_slice(&(idx as u32).to_le_bytes());
                }
            }
            let p = i * 100;
            let loads = if permuted {
                vec![
                    (p, [0x48, 0x8d, 0x0d], order),
                    (p + 7, [0x48, 0x8d, 0x15], a),
                    (p + 14, [0x48, 0x8d, 0x35], sub),
                    (p + 21, [0x48, 0x8d, 0x3d], xor),
                ]
            } else {
                vec![
                    (p, [0x4c, 0x8d, 0x3d], sub),
                    (p + 7, [0x4c, 0x8d, 0x2d], xor),
                    (p + 32, [0x48, 0x8d, 0x05], a),
                ]
            };
            for (at, op, target) in loads {
                data[at..at + 3].copy_from_slice(&op);
                data[at + 3..at + 7]
                    .copy_from_slice(&((target as i32) - (at as i32) - 7).to_le_bytes());
            }
            if permuted {
                data[p + 32..p + 44].copy_from_slice(&[
                    0x46, 0x8b, 0x0c, 0x82, 0x46, 0x2b, 0x0c, 0x86, 0x46, 0x33, 0x0c, 0x87,
                ]);
                continue;
            }
            data[p + 16..p + 19].copy_from_slice(&[0x41, 0x81, 0xfc]);
            data[p + 19..p + 23].copy_from_slice(&((n - 1) as u32).to_le_bytes());
            data[p + 39..p + 56].copy_from_slice(&[
                0x42, 0x8b, 0x04, 0xa0, 0x43, 0x2b, 0x04, 0xa7, 0x43, 0x33, 0x44, 0xa5, 0x00, 0x0f,
                0xbe, 0xf0, 0x48,
            ]);
        }
        let section = |name: &str, off: usize, len: usize| {
            serde_json::from_value(serde_json::json!({
                "name":name,"vaddr":4096+off,"vsize":len,"file_offset":off,"file_size":len,
                "flags":[],"flags_raw":null,"entropy":null
            }))
            .unwrap_or_else(|e| panic!("synthetic section: {e}"))
        };
        let sections = vec![
            section("__TEXT,__text", 0, 512),
            section("__TEXT,__const", 512, data.len() - 512),
        ];
        (data, sections)
    }
    #[test]
    fn table_recovery_and_malformed_operands() {
        let command = b"osascript -e 'display dialog \"inert fixture\"'&";
        let (data, sections) = fixture(command, false);
        let recovered = recover_sections(&data, &sections);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].data, command);
        assert_eq!(
            inline_applescript(std::str::from_utf8(command).unwrap()),
            Some("display dialog \"inert fixture\"")
        );
        assert_eq!(
            inline_applescript("osascript -e 'x'; touch /tmp/wrong"),
            None
        );
        let mut corrupted = data.clone();
        corrupted[100 + 39 + 5] = 0x03; // ADD is not the recognized SUB instruction.
        assert!(recover_sections(&corrupted, &sections).is_empty());
        for end in [0, 16, 200, 512, data.len() - 4] {
            assert!(recover_sections(&data[..end], &sections).is_empty());
        }
    }
    #[test]
    fn permuted_table_recovery_and_bad_index() {
        let command = b"osascript -e 'display dialog \"permuted fixture\"'&";
        let (data, sections) = fixture(command, true);
        let recovered = recover_sections(&data, &sections);
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].data, command);
        let mut corrupted = data.clone();
        // The first loop's permutation address is a RIP-relative operand.
        let target = 7 + i32::from_le_bytes(data[3..7].try_into().unwrap()) as usize;
        corrupted[target..target + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(recover_sections(&corrupted, &sections).is_empty());
        corrupted = data.clone();
        corrupted[100 + 32 + 5] = 0x03;
        assert!(recover_sections(&corrupted, &sections).is_empty());
    }
    #[test]
    fn custom_alphabet_and_invalid_inputs() {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        assert_eq!(
            base64_custom(b"ZWNobyBvaw", alphabet).as_deref(),
            Some(b"echo ok".as_slice())
        );
        assert!(base64_custom(b"ZWNobyBvaw!", alphabet).is_none());
        assert!(base64_custom(b"ZWNobyBvaw", &[b'A'; 64]).is_none());
        assert!(base64_custom(b"////", alphabet).is_none());
        assert_eq!(unhex(b"6563686f"), Some(b"echo".to_vec()));
        assert!(unhex(b"65zz").is_none());
        assert!(unhex(b"656").is_none());
    }
}
