//! Static hex/RC4/forward-feedback envelope recovery. Never executes specimens.
pub(crate) struct Member {
    pub(crate) offset: usize,
    pub(crate) data: Vec<u8>,
}
fn dword(b: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(p..p.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn rc4(b: &[u8], key: &[u8; 4]) -> Vec<u8> {
    let mut s = [0u8; 256];
    for (i, v) in s.iter_mut().enumerate() {
        *v = i as u8;
    }
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + usize::from(s[i]) + usize::from(key[i % 4])) & 255;
        s.swap(i, j);
    }
    let (mut i, mut j) = (0usize, 0usize);
    b.iter()
        .map(|v| {
            i = (i + 1) & 255;
            j = (j + usize::from(s[i])) & 255;
            s.swap(i, j);
            v ^ s[(usize::from(s[i]) + usize::from(s[j])) & 255]
        })
        .collect()
}
fn unhex(b: &[u8]) -> Option<Vec<u8>> {
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            Some(((char::from(p[0]).to_digit(16)? << 4) | char::from(p[1]).to_digit(16)?) as u8)
        })
        .collect()
}
pub(crate) fn recover(b: &[u8]) -> Option<Member> {
    if b.len() > 64 * 1024 * 1024 {
        return None;
    }
    super::fragment_gcm_pe::layout(b)?;
    let mut keys = Vec::new();
    // MOV stack immediate; ADD same stack slot. Operands vary between builds.
    for p in b.windows(16) {
        if p[..3] == [0xc7, 0x44, 0x24] && p[8..11] == [0x81, 0x44, 0x24] && p[3] == p[11] {
            let k = dword(p, 4)?.wrapping_add(dword(p, 12)?).to_le_bytes();
            if !keys.contains(&k) {
                keys.push(k);
            }
            if keys.len() == 32 {
                break;
            }
        }
    }
    if keys.is_empty() {
        return None;
    }
    let mut candidates = 0;
    for at in 0..b.len().saturating_sub(16) {
        if dword(b, at + 4) != Some(0) || dword(b, at + 8) != Some(0) {
            continue;
        }
        let n = dword(b, at + 12)? as usize;
        if !(2048..=8 * 1024 * 1024).contains(&n) || !n.is_multiple_of(2) {
            continue;
        }
        let Some(hex) = b.get(at + 16..at.checked_add(16)?.checked_add(n)?) else {
            continue;
        };
        if !hex.iter().all(u8::is_ascii_hexdigit) {
            continue;
        }
        candidates += 1;
        if candidates > 4 {
            return None;
        }
        let cipher = unhex(hex)?;
        for key in &keys {
            let mut plain = rc4(&cipher, key);
            for i in 0..plain.len() {
                plain[i] = (plain[i] ^ key[i % 4]).wrapping_sub(plain[(i + 1) % plain.len()]);
            }
            for pos in 0..plain.len().saturating_sub(64).min(65536) {
                if plain.get(pos..pos + 2) == Some(b"MZ")
                    && super::fragment_gcm_pe::layout(&plain[pos..]).is_some()
                {
                    return Some(Member {
                        offset: at,
                        data: plain[pos..].to_vec(),
                    });
                }
            }
        }
    }
    None
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn variable_key_envelope_and_negative_controls() {
        let pe = include_bytes!("testdata/hex-rc4-benign-pe.bin");
        let mut plain = vec![0x90; 64];
        plain.extend_from_slice(pe);
        plain.push(0);
        let key = 0x79a41234u32.to_le_bytes();
        let mut chain = vec![0u8; plain.len()];
        chain[0] = 0x57;
        for i in 0..chain.len() - 1 {
            chain[i + 1] = (chain[i] ^ key[i % 4]).wrapping_sub(plain[i]);
        }
        let last = chain.len() - 1;
        plain[last] = (chain[last] ^ key[last % 4]).wrapping_sub(plain[0]);
        let hex: Vec<u8> = rc4(&chain, &key)
            .iter()
            .flat_map(|v| format!("{v:02x}").into_bytes())
            .collect();
        let mut outer = pe.to_vec();
        outer.extend_from_slice(&[0xc7, 0x44, 0x24, 0x34]);
        outer.extend_from_slice(&0x79a41200u32.to_le_bytes());
        outer.extend_from_slice(&[0x81, 0x44, 0x24, 0x34]);
        outer.extend_from_slice(&0x34u32.to_le_bytes());
        outer.extend_from_slice(&[0x19, 0x28, 0x37, 0x46]);
        outer.extend_from_slice(&[0; 8]);
        outer.extend_from_slice(&(hex.len() as u32).to_le_bytes());
        outer.extend_from_slice(&hex);
        assert_eq!(recover(&outer).unwrap().data, &plain[64..]);
        let mut wrong_key = outer.clone();
        wrong_key[pe.len() + 4] ^= 1;
        assert!(recover(&wrong_key).is_none());
        let last = outer.len() - 1;
        outer[last] = b'z';
        assert!(recover(&outer).is_none());
        assert!(recover(&outer[..100]).is_none());
    }
}
