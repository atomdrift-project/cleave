//! Static PyArmor 8 container recovery using a bundled Windows runtime.
//! No Python objects, native runtime or specimen code is executed. GCM's
//! counter stream is decoded and checked structurally; this is not tag authentication.
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use md5::{Digest, Md5};

fn u16at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}
fn span(b: &[u8], at: usize, n: usize) -> Option<&[u8]> {
    b.get(at..at.checked_add(n)?)
}
fn ctr(data: &[u8], key: &[u8], nonce: &[u8; 12]) -> Option<Vec<u8>> {
    let cipher = aes::Aes128::new_from_slice(key).ok()?;
    let mut out = Vec::with_capacity(data.len());
    for (i, chunk) in data.chunks(16).enumerate() {
        let counter = u32::try_from(i).ok()?.checked_add(2)?;
        let mut raw = [0; 16];
        raw[..12].copy_from_slice(nonce);
        raw[12..].copy_from_slice(&counter.to_be_bytes());
        let mut block = raw.into();
        cipher.encrypt_block(&mut block);
        out.extend(chunk.iter().zip(block.iter()).map(|(a, b)| a ^ b));
    }
    Some(out)
}
fn header_valid(plain: &[u8], n: usize, flags: u32) -> bool {
    u32at(plain, 0) == Some(32)
        && u32at(plain, 4) == Some(0)
        && u32at(plain, 8) == u32::try_from(n.saturating_sub(32)).ok()
        && u32at(plain, 12) == Some(flags)
        && u32at(plain, 16) == Some(8)
}
/// Only the reviewed v8 container and PE runtime layout are admitted. Search
/// for the runtime's XOR-masked 270-byte salt in bounded writable PE sections,
/// validating keys against five independent decrypted header fields. The salt
/// location and value may change; neither specimen hashes nor C2 strings gate recovery.
pub(crate) fn recover(runtime: &[u8], pyc: &[u8]) -> Option<Vec<u8>> {
    if runtime.len() > 8 * 1024 * 1024 || pyc.len() > 16 * 1024 * 1024 {
        return None;
    }
    let at = pyc.windows(8).position(|v| v == b"PY000000")?;
    let blob = pyc.get(at..)?;
    let offset = u32at(blob, 0x1c)? as usize;
    let n = u32at(blob, 0x20)? as usize;
    let flags = u32at(blob, 0x24)?;
    if !(32..=16 * 1024 * 1024).contains(&n) || offset != 64 || flags >> 8 & 7 == 0 {
        return None;
    }
    let cipher = span(blob, offset, n)?;
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(&flags.to_le_bytes());
    nonce[4..].copy_from_slice(span(blob, 0x2c, 8)?);
    let id = runtime.windows(12).position(|v| v == b"pyarmor-vax-")?;
    let ident = span(runtime, id, 20)?;
    if !ident[12..18].iter().all(u8::is_ascii_digit) {
        return None;
    }
    let start = id.checked_add(0x34)?;
    let public_at = start.checked_add(u32at(runtime, id + 0x24)? as usize)?;
    let public_len = u32at(runtime, id + 0x28)? as usize;
    let license = start.checked_add(u32at(runtime, id + 0x2c)? as usize)?;
    let extra_len = u32at(runtime, license + 4)? as usize;
    if public_len > 8192 || extra_len > 8192 {
        return None;
    }
    let mut prefix = Md5::new();
    prefix.update(ident);
    prefix.update(span(runtime, public_at, public_len)?);
    prefix.update(span(runtime, license.checked_add(32)?, extra_len)?);
    if runtime.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32at(runtime, 60)? as usize;
    if span(runtime, pe, 4)? != b"PE\0\0" {
        return None;
    }
    let count = usize::from(u16at(runtime, pe + 6)?);
    if count > 96 {
        return None;
    }
    let sections = pe
        .checked_add(24)?
        .checked_add(usize::from(u16at(runtime, pe + 20)?))?;
    let mut attempts = 0;
    for i in 0..count {
        let sh = sections.checked_add(i.checked_mul(40)?)?;
        if u32at(runtime, sh + 36)? & 0x80000000 == 0 {
            continue;
        }
        let off = u32at(runtime, sh + 20)? as usize;
        let size = u32at(runtime, sh + 16)? as usize;
        let data = span(runtime, off, size)?;
        for salt in data.windows(270) {
            attempts += 1;
            if attempts > 65536 {
                return None;
            }
            let mut hash = prefix.clone();
            let salt: Vec<u8> = salt.iter().map(|v| v ^ 0xf1).collect();
            hash.update(&salt);
            let key = hash.finalize();
            let probe = ctr(&cipher[..32], &key, &nonce)?;
            if header_valid(&probe, n, flags) {
                return ctr(cipher, &key, &nonce);
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn independent_openssl_fixture_and_negative_controls() {
        let runtime = include_bytes!("testdata/pyarmor-runtime-data.bin");
        let container = include_bytes!("testdata/pyarmor-container.bin");
        let expected = include_bytes!("testdata/pyarmor-plain.bin");
        assert_eq!(
            recover(runtime, container).as_deref(),
            Some(expected.as_slice())
        );
        let mut wrong_salt = *runtime;
        wrong_salt[0x300] ^= 1;
        assert!(recover(&wrong_salt, container).is_none());
        let mut wrong_nonce = *container;
        wrong_nonce[0x2c] ^= 1;
        assert!(recover(runtime, &wrong_nonce).is_none());
        assert!(recover(runtime, &container[..100]).is_none());
    }
    #[test]
    fn ctr_roundtrip_and_structural_near_misses() {
        let mut header = vec![0u8; 80];
        for (at, v) in [(0, 32u32), (8, 48), (12, 0x40912), (16, 8)] {
            header[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        let decrypted = ctr(&header, &[0x7a; 16], &[0x19; 12])
            .and_then(|enc| ctr(&enc, &[0x7a; 16], &[0x19; 12]));
        assert_eq!(decrypted, Some(header.clone()));
        assert!(header_valid(&header, 80, 0x40912));
        assert!(!header_valid(&header, 81, 0x40912));
        header[16] = 9;
        assert!(!header_valid(&header, 80, 0x40912));
        assert!(recover(b"MZ", b"PY000000").is_none());
    }
}
