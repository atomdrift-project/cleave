//! Authenticated AES-CBC / LZNT1 managed-resource envelopes, read as data only.
use sha2::{Digest, Sha256};
fn u32at(b: &[u8], p: usize) -> Option<usize> {
    Some(u32::from_le_bytes(b.get(p..p.checked_add(4)?)?.try_into().ok()?) as usize)
}
fn resources(data: &[u8]) -> Option<Vec<&[u8]>> {
    let image = super::fragment_gcm_pe::layout(data)?;
    let pe = u32at(data, 60)?;
    let opt = pe.checked_add(24)?;
    let dd = match data.get(opt..opt + 2)? {
        [0x0b, 0x01] => opt + 96,
        [0x0b, 0x02] => opt + 112,
        _ => return None,
    };
    let cli = image.offset(u32at(data, dd + 14 * 8)? as u64, 32)?;
    let rva = u32at(data, cli + 24)?;
    let size = u32at(data, cli + 28)?;
    if size > 64 * 1024 * 1024 {
        return None;
    }
    let off = image.offset(rva as u64, size)?;
    let blob = data.get(off..off.checked_add(size)?)?;
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos < blob.len() && out.len() < 128 {
        if blob.len() - pos < 4 {
            break;
        }
        let n = u32at(blob, pos)?;
        let start = pos.checked_add(4)?;
        let end = start.checked_add(n)?;
        out.push(blob.get(start..end)?);
        pos = end.checked_add(7)? & !7;
    }
    Some(out)
}
fn lznt1(data: &[u8], expected: usize) -> Option<Vec<u8>> {
    if expected == 0 || expected > 32 * 1024 * 1024 {
        return None;
    }
    let mut out = Vec::with_capacity(expected);
    let mut pos = 0usize;
    while pos < data.len() {
        let h = u16::from_le_bytes(data.get(pos..pos.checked_add(2)?)?.try_into().ok()?);
        pos += 2;
        if h & 0x7000 != 0x3000 {
            return None;
        }
        let n = usize::from(h & 0xfff) + 1;
        let chunk = data.get(pos..pos.checked_add(n)?)?;
        pos += n;
        let base = out.len();
        if h & 0x8000 == 0 {
            if out.len().checked_add(n)? > expected {
                return None;
            }
            out.extend_from_slice(chunk);
            continue;
        }
        let mut at = 0;
        while at < chunk.len() {
            let flags = chunk[at];
            at += 1;
            for bit in 0..8 {
                if at == chunk.len() {
                    break;
                }
                if flags & (1 << bit) == 0 {
                    if out.len() >= expected || out.len() - base >= 4096 {
                        return None;
                    }
                    out.push(chunk[at]);
                    at += 1;
                } else {
                    let token =
                        u16::from_le_bytes(chunk.get(at..at.checked_add(2)?)?.try_into().ok()?);
                    at += 2;
                    let mut p = (out.len() - base).checked_sub(1)?;
                    let mut mask = 0xfff;
                    let mut shift = 12;
                    while p >= 16 {
                        mask >>= 1;
                        shift -= 1;
                        p >>= 1;
                    }
                    let len = usize::from(token & mask) + 3;
                    let distance = usize::from(token >> shift) + 1;
                    if distance > out.len() - base
                        || out.len().checked_add(len)? > expected
                        || out.len() - base + len > 4096
                    {
                        return None;
                    }
                    for _ in 0..len {
                        out.push(out[out.len() - distance]);
                    }
                }
            }
        }
    }
    (out.len() == expected).then_some(out)
}
fn authenticated(blob: &[u8], mac_key: &[u8]) -> bool {
    if blob.len() < 64 || blob.len() > 32 * 1024 * 1024 || mac_key.len() != 32 {
        return false;
    }
    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for (i, key) in mac_key.iter().enumerate() {
        inner[i] ^= key;
        outer[i] ^= key;
    }
    let mut h = Sha256::new();
    h.update(inner);
    h.update(&blob[..16]);
    h.update(&blob[48..]);
    let digest = h.finalize();
    let mut h = Sha256::new();
    h.update(outer);
    h.update(digest);
    let mac = h.finalize();
    mac.iter()
        .zip(&blob[16..48])
        .fold(0u8, |a, (x, y)| a | (x ^ y))
        == 0
}
pub(crate) fn recover(data: &[u8]) -> Option<Vec<u8>> {
    let members = resources(data)?;
    for cfg in members
        .iter()
        .filter(|v| v.len() >= 84 && v.len() <= 16384 && v.starts_with(b"SKC3"))
    {
        for blob in &members {
            if !authenticated(blob, &cfg[52..84]) {
                continue;
            }
            let mut plain =
                super::aes_payload::decrypt_aes_256_cbc(&blob[48..], &cfg[20..52], &blob[..16])?;
            if cfg[17] != 0 {
                plain = lznt1(plain.get(4..)?, u32at(&plain, 0)?)?;
            }
            super::fragment_gcm_pe::layout(&plain)?;
            return Some(plain);
        }
    }
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lznt1_literals_overlap_and_bounds() {
        assert_eq!(
            lznt1(&[2, 0x30, b'a', b'b', b'c'], 3),
            Some(b"abc".to_vec())
        );
        assert_eq!(
            lznt1(&[3, 0xb0, 2, b'a', 2, 0], 6),
            Some(b"aaaaaa".to_vec())
        );
        assert!(lznt1(&[1, 0xb0, 1, 0], 8).is_none());
        assert!(lznt1(&[2, 0x30, b'a', b'b'], 3).is_none());
        assert!(lznt1(&[2, 0x30, b'a', b'b', b'c'], 2).is_none());
    }
    #[test]
    fn actual_managed_resources_and_integrity() -> anyhow::Result<()> {
        let Ok(path) = std::env::var("CLEAVE_SKC3_FIXTURE") else {
            return Ok(());
        };
        let bytes = std::fs::read(path)?;
        let plain =
            recover(&bytes).ok_or_else(|| anyhow::anyhow!("authenticated managed payload"))?;
        assert_eq!(plain.len(), 36864);
        assert!(plain.windows(11).any(|v| v == b"XWormClient"));
        let resources = resources(&bytes).ok_or_else(|| anyhow::anyhow!("managed resources"))?;
        for cfg in resources.iter().filter(|v| v.starts_with(b"SKC3")) {
            for blob in &resources {
                if authenticated(blob, &cfg[52..84]) {
                    let mut wrong = blob.to_vec();
                    wrong[16] ^= 1;
                    assert!(!authenticated(&wrong, &cfg[52..84]));
                    let mut wrong = blob.to_vec();
                    wrong[48] ^= 1;
                    assert!(!authenticated(&wrong, &cfg[52..84]));
                }
            }
        }
        assert!(recover(&bytes[..bytes.len() / 2]).is_none());
        Ok(())
    }
}
