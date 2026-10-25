//! Recover PE data from a bounded batch self-read / certutil hex envelope.
//! Recovery records content provenance; it does not prove the batch executes.

pub(crate) struct Recovered {
    pub(crate) offset: usize,
    pub(crate) data: Vec<u8>,
}

fn word(b: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(p..p.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn dword(b: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(p..p.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn valid_pe(b: &[u8]) -> bool {
    (|| -> Option<()> {
        if b.len() < 512 || b.get(..2)? != b"MZ" {
            return None;
        }
        let pe = dword(b, 60)? as usize;
        if b.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
            return None;
        }
        let sections = usize::from(word(b, pe.checked_add(6)?)?);
        if !(1..=96).contains(&sections) {
            return None;
        }
        let opt = pe.checked_add(24)?;
        if !matches!(word(b, opt)?, 0x10b | 0x20b) {
            return None;
        }
        let first = opt.checked_add(usize::from(word(b, pe.checked_add(20)?)?))?;
        for i in 0..sections {
            let at = first.checked_add(i.checked_mul(40)?)?;
            b.get(at..at.checked_add(40)?)?;
            let size = dword(b, at.checked_add(16)?)? as usize;
            let off = dword(b, at.checked_add(20)?)? as usize;
            if size != 0 {
                b.get(off..off.checked_add(size)?)?;
            }
        }
        Some(())
    })()
    .is_some()
}
fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn recover(source: &[u8]) -> Option<Recovered> {
    const MAX_INPUT: usize = 64 * 1024 * 1024;
    const MAX_PE: usize = 32 * 1024 * 1024;
    if source.len() > MAX_INPUT {
        return None;
    }
    let header_end = source.len().min(64 * 1024);
    let header = std::str::from_utf8(source.get(..header_end)?)
        .ok()?
        .to_ascii_lowercase();
    let mut skip = None;
    let mut decoder = false;
    for line in header.lines().take(256) {
        let line = line.trim();
        if line.starts_with("rem ") || line.starts_with("::") {
            continue;
        }
        if line.contains("certutil") && line.contains("-decodehex") {
            decoder = true;
        }
        if let Some((_, tail)) = line.split_once("more +") {
            if !tail.contains("%~f0") {
                continue;
            }
            let n: usize = tail.split_whitespace().next()?.parse().ok()?;
            if n > 256 {
                return None;
            }
            skip = Some(n);
        }
    }
    if !decoder {
        return None;
    }
    let skip = skip?;
    let mut offset = 0usize;
    let mut begin = None;
    let mut data = Vec::new();
    let mut half = None;
    for (i, line) in source.split_inclusive(|&b| b == b'\n').enumerate() {
        if i < skip {
            offset = offset.checked_add(line.len())?;
            continue;
        }
        let hex = line.iter().copied().filter(|b| !b.is_ascii_whitespace());
        let count = hex.clone().count();
        if begin.is_none() {
            // A source footer can precede the encoded block. This is content
            // recovery, not an assertion about certutil's tolerance for it.
            if count < 32 || !hex.clone().all(|b| nibble(b).is_some()) {
                if i >= skip.checked_add(8)? {
                    return None;
                }
                offset = offset.checked_add(line.len())?;
                continue;
            }
            begin = Some(offset);
        }
        for b in hex {
            let n = nibble(b)?;
            if let Some(hi) = half.take() {
                if data.len() >= MAX_PE {
                    return None;
                }
                data.push((hi << 4) | n);
            } else {
                half = Some(n);
            }
        }
        offset = offset.checked_add(line.len())?;
    }
    if half.is_some() || !valid_pe(&data) {
        return None;
    }
    Some(Recovered {
        offset: begin?,
        data,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "invalid fixtures and failed recovery should fail the test"
)]
mod tests {
    use super::*;
    fn pe() -> Vec<u8> {
        let mut b = vec![0u8; 1024];
        b[..2].copy_from_slice(b"MZ");
        b[60..64].copy_from_slice(&128u32.to_le_bytes());
        b[128..132].copy_from_slice(b"PE\0\0");
        b[132..134].copy_from_slice(&0x14cu16.to_le_bytes());
        b[134..136].copy_from_slice(&1u16.to_le_bytes());
        b[148..150].copy_from_slice(&224u16.to_le_bytes());
        b[152..154].copy_from_slice(&0x10bu16.to_le_bytes());
        b[392..396].copy_from_slice(&512u32.to_le_bytes());
        b[396..400].copy_from_slice(&512u32.to_le_bytes());
        b
    }
    fn envelope(data: &[u8]) -> Vec<u8> {
        let mut s = String::from(
            "@echo off\r\nmore +4 \"%~f0\" > \"%TEMP%\\any.data\"\r\nCERTUTIL.EXE -f -decodehex a b 4\r\nexit /b\r\n",
        );
        for part in data.chunks(64) {
            for b in part {
                use std::fmt::Write;
                write!(s, "{b:02X}").unwrap();
            }
            s.push_str("\r\n");
        }
        s.into_bytes()
    }
    #[test]
    fn valid_renamed_envelope() {
        let b = pe();
        assert_eq!(recover(&envelope(&b)).unwrap().data, b);
    }
    #[test]
    fn rejects_missing_decoder() {
        let s = String::from_utf8(envelope(&pe()))
            .unwrap()
            .replace("-decodehex", "-hashfile");
        assert!(recover(s.as_bytes()).is_none());
    }
    #[test]
    fn rejects_missing_self_read() {
        let s = String::from_utf8(envelope(&pe()))
            .unwrap()
            .replace("%~f0", "ordinary-file");
        assert!(recover(s.as_bytes()).is_none());
    }
    #[test]
    fn rejects_bad_hex_and_truncation() {
        let mut s = envelope(&pe());
        s.push(b'!');
        assert!(recover(&s).is_none());
        let b = pe();
        assert!(recover(&envelope(&b[..600])).is_none());
    }
    #[test]
    fn rejects_non_pe() {
        assert!(recover(&envelope(&vec![65; 1024])).is_none());
    }
    #[test]
    fn actual_fixture() {
        let Ok(path) = std::env::var("CLEAVE_BATCH_HEX_FIXTURE") else {
            return;
        };
        let data = std::fs::read(path).unwrap();
        let r = recover(&data).expect("embedded PE");
        let expected = std::fs::read(std::env::var("CLEAVE_BATCH_HEX_PE").unwrap()).unwrap();
        assert_eq!(r.data, expected);
        assert_eq!(&data[r.offset..r.offset + 4], b"4d5a");
    }
}
