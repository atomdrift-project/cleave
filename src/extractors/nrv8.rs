//! Bounded recovery of length-prefixed NRV2B streams containing PE images.
//! This is static decompression, with independent container/child validation.
const MAX_INPUT: usize = 8 * 1024 * 1024;
const MAX_OUTPUT: usize = 8 * 1024 * 1024;

pub(super) struct Image {
    pub offset: usize,
    pub data: Vec<u8>,
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

// Require a complete disk image, not merely a decompressed MZ prefix.
fn valid_pe(data: &[u8]) -> bool {
    let check = || -> Option<()> {
        if data.get(..2)? != b"MZ" {
            return None;
        }
        let pe = u32_at(data, 0x3c)? as usize;
        if pe < 0x40 || data.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
            return None;
        }
        let machine = u16_at(data, pe + 4)?;
        if !matches!(machine, 0x14c | 0x8664 | 0x1c0 | 0x1c4 | 0xaa64) {
            return None;
        }
        let count = u16_at(data, pe + 6)? as usize;
        let opt_size = u16_at(data, pe + 20)? as usize;
        if !(1..=96).contains(&count) || opt_size < 96 {
            return None;
        }
        if !matches!(u16_at(data, pe + 24)?, 0x10b | 0x20b) {
            return None;
        }
        let table = pe.checked_add(24)?.checked_add(opt_size)?;
        data.get(table..table.checked_add(count * 40)?)?;
        for i in 0..count {
            let row = table + i * 40;
            let size = u32_at(data, row + 16)? as usize;
            let start = u32_at(data, row + 20)? as usize;
            if size > 0 {
                data.get(start..start.checked_add(size)?)?;
            }
        }
        Some(())
    };
    check().is_some()
}

struct Reader<'a> {
    data: &'a [u8],
    at: usize,
    bits: u8,
}
impl Reader<'_> {
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.at)?;
        self.at += 1;
        Some(byte)
    }
    fn bit(&mut self) -> Option<u32> {
        let carry = self.bits >> 7;
        self.bits = self.bits.wrapping_shl(1);
        if self.bits != 0 {
            return Some(u32::from(carry));
        }
        let byte = self.byte()?;
        self.bits = byte.wrapping_shl(1) | 1;
        Some(u32::from(byte >> 7))
    }
}

fn decode(data: &[u8]) -> Option<Vec<u8>> {
    let mut reader = Reader {
        data,
        at: 0,
        bits: 0,
    };
    let mut out = Vec::new();
    let mut last = 1usize;
    // Every iteration consumes input or produces output; cap both independently.
    for _ in 0..MAX_OUTPUT {
        while reader.bit()? != 0 {
            if out.len() >= MAX_OUTPUT {
                return None;
            }
            out.push(reader.byte()?);
        }
        let mut offset = 1u32;
        loop {
            offset = offset.checked_mul(2)?.checked_add(reader.bit()?)?;
            if offset > 0x1000002 {
                return None;
            }
            if reader.bit()? != 0 {
                break;
            }
        }
        let distance = if offset == 2 {
            last
        } else {
            let value = offset
                .checked_sub(3)?
                .checked_mul(256)?
                .checked_add(u32::from(reader.byte()?))?;
            if value == u32::MAX {
                return (reader.at == data.len()).then_some(out);
            }
            last = (value as usize).checked_add(1)?;
            last
        };
        let mut length = reader.bit()? as usize * 2 + reader.bit()? as usize;
        if length == 0 {
            length = 1;
            loop {
                length = length.checked_mul(2)?.checked_add(reader.bit()? as usize)?;
                if length > MAX_OUTPUT {
                    return None;
                }
                if reader.bit()? != 0 {
                    break;
                }
            }
            length += 2;
        }
        length += usize::from(distance > 0xd00) + 1;
        if distance == 0 || distance > out.len() || out.len().checked_add(length)? > MAX_OUTPUT {
            return None;
        }
        for _ in 0..length {
            out.push(out[out.len() - distance]);
        }
    }
    None
}

pub(super) fn recover(data: &[u8]) -> Vec<Image> {
    if data.len() > 64 * 1024 * 1024 || !valid_pe(data) {
        return Vec::new();
    }
    let mut images = Vec::new();
    let mut candidates = 0;
    let mut total = 0;
    for offset in 4..data.len().min(16 * 1024 * 1024).saturating_sub(3) {
        // First two literal bits followed by MZ; later evidence must validate PE.
        if data[offset] & 0xc0 != 0xc0 || data.get(offset + 1..offset + 3) != Some(b"MZ") {
            continue;
        }
        let Some(size) = u32_at(data, offset - 4).map(|n| n as usize) else {
            continue;
        };
        if !(128..=MAX_INPUT).contains(&size) {
            continue;
        }
        let Some(input) = offset
            .checked_add(size)
            .and_then(|end| data.get(offset..end))
        else {
            continue;
        };
        candidates += 1;
        if candidates > 8 {
            break;
        }
        let Some(child) = decode(input) else {
            continue;
        };
        if !valid_pe(&child) || child == data {
            continue;
        }
        total += child.len();
        if total > 32 * 1024 * 1024 {
            break;
        }
        images.push(Image {
            offset,
            data: child,
        });
        if images.len() == 4 {
            break;
        }
    }
    images
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Writer {
        bytes: Vec<u8>,
        flag: usize,
        count: u8,
    }
    impl Writer {
        fn bit(&mut self, bit: u32) {
            if self.count == 0 {
                self.flag = self.bytes.len();
                self.bytes.push(0);
            }
            self.bytes[self.flag] |= (bit as u8) << (7 - self.count);
            self.count = (self.count + 1) % 8;
        }
    }
    fn literal_stream(data: &[u8]) -> Vec<u8> {
        let mut w = Writer {
            bytes: Vec::new(),
            flag: 0,
            count: 0,
        };
        for &byte in data {
            w.bit(1);
            w.bytes.push(byte);
        }
        w.bit(0);
        for i in (0..24).rev() {
            w.bit((0x1000002 >> i) & 1);
            w.bit(u32::from(i == 0));
        }
        w.bytes.push(0xff);
        w.bytes
    }
    fn fixture_pe() -> Vec<u8> {
        let mut b = vec![0; 1024];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
        b[128..132].copy_from_slice(b"PE\0\0");
        b[132..134].copy_from_slice(&0x14cu16.to_le_bytes());
        b[134..136].copy_from_slice(&1u16.to_le_bytes());
        b[148..150].copy_from_slice(&224u16.to_le_bytes());
        b[152..154].copy_from_slice(&0x10bu16.to_le_bytes());
        b[392..396].copy_from_slice(&512u32.to_le_bytes());
        b[396..400].copy_from_slice(&512u32.to_le_bytes());
        b
    }
    #[test]
    fn recovers_length_prefixed_pe_and_preserves_offset() {
        let child = fixture_pe();
        let stream = literal_stream(&child);
        assert_eq!(decode(&stream), Some(child.clone()));
        let mut carrier = fixture_pe();
        carrier.extend_from_slice(&(stream.len() as u32).to_le_bytes());
        let offset = carrier.len();
        carrier.extend_from_slice(&stream);
        let found = recover(&carrier);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].offset, offset);
        assert_eq!(found[0].data, child);
    }
    #[test]
    fn rejects_plain_truncated_and_invalid_images() {
        assert!(recover(&fixture_pe()).is_empty());
        let mut stream = literal_stream(&fixture_pe());
        stream.pop();
        assert!(decode(&stream).is_none());
        let stream = literal_stream(b"MZ this is not an executable");
        let mut carrier = fixture_pe();
        carrier.extend_from_slice(&(stream.len() as u32).to_le_bytes());
        carrier.extend_from_slice(&stream);
        assert!(recover(&carrier).is_empty());
        assert!(decode(&[0; 128]).is_none());
    }
    #[test]
    fn validates_raw_section_bounds() {
        let mut pe = fixture_pe();
        pe[392..396].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!valid_pe(&pe));
    }
}
