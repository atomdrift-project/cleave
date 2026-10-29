//! Recover a bounded x86 feedback-stream/RC4 graft without running specimen code.
//! The decoder's code-relative parameter block supplies its seed, multiplier
//! and size. The decoded section trailer supplies the RC4 key and DLL extent.
//! Names, keys, addresses and payload contents are not fixed signatures.
use super::primitives::{rc4, u16_le, u32_le};
const LIMIT: usize = 32 * 1024 * 1024;
const DECODER: &[u8] = &[
    0xe8, 0, 0, 0, 0, 0x5d, 0x8d, 0x7d, 0x3c, 0x8b, 0x0f, 0x8b, 0x47, 0xf8, 0x8b, 0x57, 0xfc, 0x8d,
    0x77, 0x04, 0x89, 0xf5, 0x09, 0xc9, 0x74, 0x1d, 0x0f, 0xaf, 0xc2, 0x8d, 0x40, 0x13, 0x89, 0xc3,
    0xc1, 0xe3, 0x03, 0xc1, 0xe8, 0x1d, 0x09, 0xd8, 0x88, 0xc3, 0x30, 0x1e, 0x0f, 0xb6, 0x1e, 0x01,
    0xd8, 0x46, 0x49, 0xeb, 0xdf, 0xff, 0xe5,
];
fn bytes(b: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    b.get(at..at.checked_add(len)?)
}
struct Section {
    rva: u32,
    raw: usize,
    size: usize,
    executable: bool,
}
fn sections(b: &[u8]) -> Option<Vec<Section>> {
    if bytes(b, 0, 2)? != b"MZ" {
        return None;
    }
    let pe = usize::try_from(u32_le(b, 0x3c)?).ok()?;
    if bytes(b, pe, 4)? != b"PE\0\0" || u16_le(b, pe + 4)? != 0x14c {
        return None;
    }
    let count = usize::from(u16_le(b, pe + 6)?);
    if !(1..=96).contains(&count) {
        return None;
    }
    let optional = pe.checked_add(24)?;
    if u16_le(b, optional)? != 0x10b {
        return None;
    }
    let table = optional.checked_add(usize::from(u16_le(b, pe + 20)?))?;
    bytes(b, table, count.checked_mul(40)?)?;
    (0..count)
        .map(|i| {
            let at = table.checked_add(i.checked_mul(40)?)?;
            let raw = usize::try_from(u32_le(b, at + 20)?).ok()?;
            let size = usize::try_from(u32_le(b, at + 16)?).ok()?;
            bytes(b, raw, size)?;
            Some(Section {
                rva: u32_le(b, at + 12)?,
                raw,
                size,
                executable: u32_le(b, at + 36)? & 0x2000_0000 != 0,
            })
        })
        .collect()
}
fn stream(b: &[u8], mut seed: u32, multiplier: u32) -> Vec<u8> {
    b.iter()
        .map(|v| {
            seed = seed
                .wrapping_mul(multiplier)
                .wrapping_add(19)
                .rotate_left(3);
            let plain = v ^ seed as u8;
            seed = seed.wrapping_add(u32::from(plain));
            plain
        })
        .collect()
}
pub(crate) struct Recovered {
    pub(crate) data: Vec<u8>,
    pub(crate) offset: usize,
}
pub(crate) fn recover(b: &[u8]) -> Option<Recovered> {
    let sections = sections(b)?;
    let last = sections.last()?;
    if !last.executable || last.size > LIMIT {
        return None;
    }
    let section = bytes(b, last.raw, last.size)?;
    // One recognized decoder per input. Reject malformed candidates rather
    // than repeatedly decrypting attacker-selected overlapping ranges.
    let pos = section.windows(DECODER.len()).position(|w| w == DECODER)?;
    let block = pos.checked_add(5 + 0x3c)?;
    let size = usize::try_from(u32_le(section, block)?).ok()?;
    if !(512..=LIMIT).contains(&size) {
        return None;
    }
    let start = block.checked_add(4)?;
    if start.checked_add(size)? != section.len() {
        return None;
    }
    let plain = stream(
        bytes(section, start, size)?,
        u32_le(section, block.checked_sub(8)?)?,
        u32_le(section, block.checked_sub(4)?)?,
    );
    // A manual mapper, not merely an arbitrary decrypted byte string.
    let mapper = [0x64, 0xa1, 0x30, 0, 0, 0, 0x8b, 0x40, 0x08];
    let ksa = [0x83, 0xe0, 0x07, 0x02, 0x14, 0x03];
    if !plain.windows(mapper.len()).any(|w| w == mapper)
        || !plain.windows(ksa.len()).any(|w| w == ksa)
    {
        return None;
    }
    let tail = size.checked_sub(48)?;
    let key = bytes(&plain, tail + 8, 8)?;
    let dll_size = usize::try_from(u32_le(&plain, tail + 36)?).ok()?;
    if !(256..=LIMIT).contains(&dll_size) {
        return None;
    }
    let dll_rva = u32_le(&plain, tail + 40)?;
    let stream_rva = u64::from(last.rva).checked_add(start as u64)?;
    let relative = usize::try_from(u64::from(dll_rva).checked_sub(stream_rva)?).ok()?;
    if relative.checked_add(dll_size)? > tail {
        return None;
    }
    let data = rc4(bytes(&plain, relative, dll_size)?, key);
    let child_sections = sections_for_dll(&data)?;
    if child_sections == 0 {
        return None;
    }
    Some(Recovered {
        data,
        offset: last.raw.checked_add(start)?.checked_add(relative)?,
    })
}
fn sections_for_dll(b: &[u8]) -> Option<usize> {
    let sections = sections(b)?;
    let pe = usize::try_from(u32_le(b, 0x3c)?).ok()?;
    (u16_le(b, pe + 22)? & 0x2000 != 0).then_some(sections.len())
}
#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    #[test]
    fn malformed_is_rejected() {
        for n in 0..300 {
            assert!(recover(&vec![0; n]).is_none());
        }
    }
    #[test]
    fn stream_feedback_is_plaintext() {
        let plain = b"decoder feedback control";
        let mut seed = 17u32;
        let cipher: Vec<_> = plain
            .iter()
            .map(|v| {
                seed = seed.wrapping_mul(77).wrapping_add(19).rotate_left(3);
                let c = v ^ seed as u8;
                seed = seed.wrapping_add(u32::from(*v));
                c
            })
            .collect();
        assert_eq!(stream(&cipher, 17, 77), plain);
        assert_ne!(stream(&cipher, 18, 77), plain);
    }
    #[test]
    fn original_and_near_misses() -> anyhow::Result<()> {
        let Ok(path) = std::env::var("CLEAVE_GRAFT_FIXTURE") else {
            return Ok(());
        };
        let original = std::fs::read(path)?;
        let recovered = recover(&original).context("real graft must decode")?;
        let expected = std::fs::read(std::env::var("CLEAVE_GRAFT_DLL")?)?;
        assert_eq!(recovered.data, expected);
        assert!(recovered.offset < original.len());
        let mut no_code = original.clone();
        let pe = u32_le(&no_code, 0x3c).context("missing PE offset")? as usize;
        let table =
            pe + 24 + u16_le(&no_code, pe + 20).context("missing optional header size")? as usize;
        let last =
            table + 40 * (u16_le(&no_code, pe + 6).context("missing section count")? as usize - 1);
        let flags = u32_le(&no_code, last + 36).context("missing section flags")? & !0x2000_0000;
        no_code[last + 36..last + 40].copy_from_slice(&flags.to_le_bytes());
        assert!(recover(&no_code).is_none());
        let mut corrupt = original.clone();
        let pos = corrupt
            .windows(DECODER.len())
            .position(|w| w == DECODER)
            .context("missing decoder")?;
        corrupt[pos + 30] ^= 1;
        assert!(recover(&corrupt).is_none());
        let mut wrong_key = original.clone();
        let last_section = sections(&wrong_key)
            .context("invalid PE sections")?
            .pop()
            .context("missing last section")?;
        let block = pos + 5 + 0x3c;
        wrong_key[block - 8] ^= 1;
        assert!(recover(&wrong_key).is_none());
        let mut huge = original.clone();
        huge[block..block + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(recover(&huge).is_none());
        let mut wrong_child = original.clone();
        wrong_child[recovered.offset] ^= 1;
        assert!(recover(&wrong_child).is_none());
        assert!(recover(&original[..last_section.raw + last_section.size - 1]).is_none());
        Ok(())
    }
}
