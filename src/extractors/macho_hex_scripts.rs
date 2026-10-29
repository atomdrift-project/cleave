//! Bounded recovery of encoded and XOR-obfuscated inline scripts in Mach-O.
//! This is a static transform: it never executes the input.
use super::macho_integer_tables::{RecoveredText, inline_applescript};
use super::primitives::{rc4, unhex};
use filefacts::ParsedFile;

fn recover_strings(data: &[u8], base: usize) -> Vec<RecoveredText> {
    let mut keys = Vec::new();
    let mut payloads = Vec::new();
    let mut pos = 0;
    for part in data.split(|c| *c == 0) {
        let offset = pos;
        pos += part.len() + 1;
        if !part.iter().all(u8::is_ascii_hexdigit) || !part.len().is_multiple_of(2) {
            continue;
        }
        if (16..=128).contains(&part.len()) && keys.len() < 32 {
            keys.extend(unhex(part));
        } else if (1024..=2 * 1024 * 1024).contains(&part.len())
            && payloads.len() < 8
            && let Some(cipher) = unhex(part)
        {
            payloads.push((offset, cipher));
        }
    }
    let mut result = Vec::new();
    for (offset, cipher) in payloads {
        for key in &keys {
            let plain = rc4(&cipher, key);
            if std::str::from_utf8(&plain).is_ok_and(|text| inline_applescript(text).is_some()) {
                result.push(RecoveredText {
                    data: plain,
                    offset: base + offset,
                });
                break;
            }
        }
    }
    result
}
pub(crate) fn recover(data: &[u8], parsed: &ParsedFile<'_>) -> Vec<RecoveredText> {
    if data.len() > 32 * 1024 * 1024 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for section in parsed.sections() {
        if !section.name.ends_with("__cstring") {
            continue;
        }
        let Ok(start) = usize::try_from(section.file_offset) else {
            continue;
        };
        let Ok(size) = usize::try_from(section.file_size) else {
            continue;
        };
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        if size > 4 * 1024 * 1024 {
            continue;
        }
        if let Some(bytes) = data.get(start..end) {
            out.extend(recover_strings(bytes, start));
        }
    }
    out
}

fn custom_base64(data: &[u8], alphabet: &[u8]) -> Option<Vec<u8>> {
    if alphabet.len() != 64 {
        return None;
    }
    let mut map = [u8::MAX; 256];
    for (i, &b) in alphabet.iter().enumerate() {
        if !(33..=126).contains(&b) || map[b as usize] != u8::MAX {
            return None;
        }
        map[b as usize] = i as u8;
    }
    let (mut acc, mut bits) = (0u32, 0u8);
    let mut out = Vec::new();
    for &b in data {
        let v = map[b as usize];
        if v == u8::MAX {
            return None;
        }
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}
fn recover_custom_strings(data: &[u8], base: usize) -> Vec<RecoveredText> {
    let mut alphabets = Vec::new();
    let mut payloads = Vec::new();
    let mut pos = 0;
    for part in data.split(|c| *c == 0) {
        let offset = pos;
        pos += part.len() + 1;
        if part.len() == 64 && alphabets.len() < 16 && custom_base64(b"", part).is_some() {
            alphabets.push(part);
        } else if (1024..=2 * 1024 * 1024).contains(&part.len())
            && payloads.len() < 8
            && part.iter().all(u8::is_ascii_hexdigit)
            && let Some(bytes) = unhex(part)
        {
            payloads.push((offset, bytes));
        }
    }
    let mut out = Vec::new();
    for (offset, encoded) in payloads {
        for alphabet in &alphabets {
            let Some(decoded) = custom_base64(&encoded, alphabet) else {
                continue;
            };
            if std::str::from_utf8(&decoded)
                .ok()
                .and_then(inline_applescript)
                .is_some()
            {
                out.push(RecoveredText {
                    data: decoded,
                    offset: base + offset,
                });
                break;
            }
        }
    }
    // Some launchers store consecutive slices of the encoded text as
    // separate C strings. Reassemble a bounded run in file order; accept a
    // result only when the complete interpreter wrapper is recovered.
    let mut joined = Vec::new();
    let mut run_start = 0usize;
    let mut count = 0usize;
    let mut cursor = 0usize;
    for part in data.split(|c| *c == 0) {
        let offset = cursor;
        cursor += part.len() + 1;
        if part.len() > 512
            || part.len() < 2
            || (part.len() < 128 && count == 0)
            || !part.iter().all(u8::is_ascii_hexdigit)
        {
            joined.clear();
            count = 0;
            continue;
        }
        if count == 0 {
            run_start = offset;
        }
        count += 1;
        if count > 512 || joined.len() + part.len() > 2 * 1024 * 1024 {
            break;
        }
        joined.extend_from_slice(part);
        if count < 4 || joined.len() % 2 != 0 {
            continue;
        }
        let Some(encoded) = unhex(&joined) else {
            continue;
        };
        for alphabet in &alphabets {
            let Some(prefix) = custom_base64(&encoded[..encoded.len().min(32)], alphabet) else {
                continue;
            };
            if !prefix.starts_with(b"osascript -e '") {
                continue;
            }
            let Some(decoded) = custom_base64(&encoded, alphabet) else {
                continue;
            };
            if std::str::from_utf8(&decoded)
                .ok()
                .and_then(inline_applescript)
                .is_some()
            {
                out.push(RecoveredText {
                    data: decoded,
                    offset: base + run_start,
                });
                return out;
            }
        }
    }
    out
}
pub(crate) fn recover_custom(data: &[u8], parsed: &ParsedFile<'_>) -> Vec<RecoveredText> {
    if data.len() > 32 * 1024 * 1024 {
        return Vec::new();
    }
    let mut out = Vec::new();
    for section in parsed.sections() {
        if !section.name.ends_with("__cstring") {
            continue;
        }
        let Ok(start) = usize::try_from(section.file_offset) else {
            continue;
        };
        let Ok(size) = usize::try_from(section.file_size) else {
            continue;
        };
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        if size > 4 * 1024 * 1024 {
            continue;
        }
        if let Some(bytes) = data.get(start..end) {
            out.extend(recover_custom_strings(bytes, start));
        }
    }
    out
}

fn decode_lcg(cipher: &[u8], seed: u32, multiplier: u32, modulus: u32) -> Option<Vec<u8>> {
    if modulus == 0 || cipher.len() > 1024 * 1024 {
        return None;
    }
    let mut state = seed;
    let mut out = Vec::with_capacity(cipher.len());
    for &b in cipher {
        let byte = b ^ state as u8;
        if byte == 0 {
            break;
        }
        out.push(byte);
        state = state.wrapping_mul(multiplier) % modulus;
    }
    std::str::from_utf8(&out)
        .ok()
        .and_then(inline_applescript)?;
    Some(out)
}
pub(crate) fn recover_lcg(data: &[u8], parsed: &ParsedFile<'_>) -> Vec<RecoveredText> {
    if data.len() > 32 * 1024 * 1024 {
        return Vec::new();
    }
    let sections = parsed.sections();
    let mut multipliers = Vec::new();
    let mut moduli = Vec::new();
    for section in sections.as_slice() {
        let Ok(start) = usize::try_from(section.file_offset) else {
            continue;
        };
        let Ok(size) = usize::try_from(section.file_size) else {
            continue;
        };
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        if size > 4 * 1024 * 1024 {
            continue;
        }
        let Some(bytes) = data.get(start..end) else {
            continue;
        };
        if section.name.ends_with("__text") {
            // x86 multiply-immediate followed by storage and division.
            for w in bytes.windows(29) {
                if w[0..2] == [0x69, 0x45]
                    && w[7..9] == [0x89, 0x45]
                    && w[10] == 0xe8
                    && w[15..17] == [0x89, 0xc1]
                    && w[20..24] == [0x31, 0xd2, 0xf7, 0xf1]
                {
                    let n = u32::from_le_bytes([w[3], w[4], w[5], w[6]]);
                    if n > 1 && !multipliers.contains(&n) {
                        multipliers.push(n);
                    }
                    if multipliers.len() == 4 {
                        break;
                    }
                }
            }
        } else if section.name.ends_with("__cstring") {
            for w in bytes.windows(9) {
                if w[2] != b':'
                    || w[5] != b':'
                    || w[8] != 0
                    || ![w[0], w[1], w[3], w[4], w[6], w[7]]
                        .iter()
                        .all(u8::is_ascii_digit)
                {
                    continue;
                }
                let hour = u32::from(w[0] - b'0') * 10 + u32::from(w[1] - b'0');
                let minute = u32::from(w[3] - b'0') * 10 + u32::from(w[4] - b'0');
                let second = u32::from(w[6] - b'0') * 10 + u32::from(w[7] - b'0');
                if hour < 24 && minute < 60 && second < 60 {
                    let n = hour * 3600 + minute * 60 + second;
                    if n > 0 && !moduli.contains(&n) {
                        moduli.push(n);
                    }
                    if moduli.len() == 4 {
                        break;
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    for section in sections.as_slice() {
        if !section.name.ends_with("__const") {
            continue;
        }
        let Ok(start) = usize::try_from(section.file_offset) else {
            continue;
        };
        let Ok(size) = usize::try_from(section.file_size) else {
            continue;
        };
        if !(1024..=1024 * 1024).contains(&size) {
            continue;
        }
        let Some(end) = start.checked_add(size) else {
            continue;
        };
        let Some(bytes) = data.get(start..end) else {
            continue;
        };
        let seed = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        for &m in &multipliers {
            for &n in &moduli {
                if let Some(plain) = decode_lcg(&bytes[4..], seed, m, n) {
                    out.push(RecoveredText {
                        data: plain,
                        offset: start + 4,
                    });
                    return out;
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn custom_alphabet_recovery_and_controls() {
        use base64::Engine as _;
        let standard = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let alphabet: Vec<u8> = standard.iter().copied().rev().collect();
        let plain = format!("osascript -e '{}{}'", "x".repeat(600), "hello");
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(plain.as_bytes());
        let custom: Vec<u8> = encoded
            .bytes()
            .map(|x| alphabet[standard.iter().position(|c| *c == x).unwrap()])
            .collect();
        let hex: String = custom.iter().map(|x| format!("{x:02x}")).collect();
        let input = [alphabet.as_slice(), b"\0", hex.as_bytes(), b"\0"].concat();
        let found = recover_custom_strings(&input, 0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].data, plain.as_bytes());
        assert!(custom_base64(&custom, &[b'A'; 64]).is_none());
        assert!(custom_base64(b"invalid?", standard).is_none());
        let mut split = Vec::new();
        for chunk in hex.as_bytes().chunks(137) {
            split.extend_from_slice(chunk);
            split.push(0);
        }
        split.extend_from_slice(&alphabet);
        split.push(0);
        let split_found = recover_custom_strings(&split, 0);
        assert_eq!(split_found.len(), 1);
        assert_eq!(split_found[0].data, plain.as_bytes());
        split[10] = b'Z';
        assert!(recover_custom_strings(&split, 0).is_empty());
    }
    #[test]
    fn lcg_stream_recovery_and_wrong_key() {
        let seed = 123456u32;
        let multiplier = 14213u32;
        let modulus = 70129u32;
        let plain = format!("osascript -e '{}{}'", "x".repeat(600), "hello");
        let mut state = seed;
        let mut cipher = Vec::new();
        for byte in plain.bytes().chain(std::iter::once(0)) {
            cipher.push(byte ^ state as u8);
            state = state.wrapping_mul(multiplier) % modulus;
        }
        assert_eq!(
            decode_lcg(&cipher, seed, multiplier, modulus).unwrap(),
            plain.as_bytes()
        );
        assert!(decode_lcg(&cipher, seed + 1, multiplier, modulus).is_none());
    }
    #[test]
    fn recover_and_reject_near_misses() {
        let key = b"different-key-01";
        let plain = b"osascript -e 'display dialog \"hello\"'";
        let cipher = rc4(plain, key);
        let hex = |v: &[u8]| v.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let long_plain = format!("osascript -e '{}{}'", "x".repeat(512), "hello");
        let long_cipher = rc4(long_plain.as_bytes(), key);
        let input = format!("{}\0{}\0", hex(key), hex(&long_cipher));
        let found = recover_strings(input.as_bytes(), 0);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].data, long_plain.as_bytes());
        assert!(
            recover_strings(
                format!("{}\0{}\0", hex(b"wrong-key-123456"), hex(&long_cipher)).as_bytes(),
                0
            )
            .is_empty()
        );
        assert!(
            recover_strings(format!("{}\0{}\0", hex(key), hex(&cipher)).as_bytes(), 0).is_empty()
        );
    }
}
