//! Authenticate and recover a code-integrity-bound Mach-O script envelope.
//!
//! Recognition uses the x86-64 nonce construction and three indexed pointer
//! tables, not file hashes, addresses, keys, domains, or plaintext signatures.
//! All variable inputs come from the file. Nothing from the file is executed.
//! Unsupported layouts and failed authentication produce no recovered payload.

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use filefacts::{ParsedFile, Section};
use sha2::{Digest, Sha256};

/// One fully authenticated compiled script and its encrypted origin.
pub(crate) struct RecoveredScript {
    pub(crate) data: Vec<u8>,
    pub(crate) offset: usize,
    pub(crate) segments: usize,
    pub(crate) iterations: u32,
}

fn range(data: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    data.get(offset..offset.checked_add(size)?)
}

fn address_offset(sections: &[Section], address: u64) -> Option<usize> {
    sections.iter().find_map(|section| {
        let delta = address.checked_sub(section.vaddr)?;
        (delta < section.file_size)
            .then(|| section.file_offset.checked_add(delta))
            .flatten()
            .and_then(|offset| usize::try_from(offset).ok())
    })
}

fn pointer(data: &[u8], sections: &[Section], offset: usize) -> Option<usize> {
    let address = u64::from_le_bytes(range(data, offset, 8)?.try_into().ok()?);
    address_offset(sections, address)
}

fn rip_target(code: &[u8], code_va: u64, pos: usize) -> Option<u64> {
    let displacement = i32::from_le_bytes(range(code, pos.checked_add(3)?, 4)?.try_into().ok()?);
    code_va
        .checked_add(u64::try_from(pos.checked_add(7)?).ok()?)?
        .checked_add_signed(i64::from(displacement))
}

// One-block HKDF-SHA256 and PBKDF2-SHA256. HMAC uses the existing sha2
// implementation; bounded callers never request more than a digest's length.
fn hmac(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 64];
    if key.len() > 64 {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let inner_pad = padded.map(|b| b ^ 0x36);
    let outer_pad = padded.map(|b| b ^ 0x5c);
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    outer.finalize().into()
}

fn derive_key(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut input = salt.to_vec();
    input.extend_from_slice(&1u32.to_be_bytes());
    let mut current = hmac(password, &input);
    let mut result = current;
    for _ in 1..iterations {
        current = hmac(password, &current);
        for (out, next) in result.iter_mut().zip(current) {
            *out ^= next;
        }
    }
    result
}

fn nonce(key: &[u8], info: &[u8]) -> [u8; 12] {
    let prk = hmac(&[0u8; 32], key);
    let mut input = info.to_vec();
    input.push(1);
    let expanded = hmac(&prk, &input);
    let mut result = [0; 12];
    result.copy_from_slice(&expanded[..12]);
    result
}

/// Recover only envelopes whose every AEAD tag validates, within fixed bounds.
pub(crate) fn recover(data: &[u8], parsed: &ParsedFile<'_>) -> Vec<RecoveredScript> {
    let mut recovered = Vec::new();
    if data.len() > 32 * 1024 * 1024 {
        return recovered;
    }
    let sections = parsed.sections();
    let sections = sections.as_slice();
    let Some(text) = sections.iter().find(|s| s.name.ends_with("__text")) else {
        return recovered;
    };
    let (Ok(text_offset), Ok(text_size)) = (
        usize::try_from(text.file_offset),
        usize::try_from(text.file_size),
    ) else {
        return recovered;
    };
    let Some(code) = range(data, text_offset, text_size) else {
        return recovered;
    };
    if code.len() > 2 * 1024 * 1024 {
        return recovered;
    }
    let digest = Sha256::digest(code);
    // The envelope stores the live text digest after its eight-byte root seed
    // and alignment padding. Require code references to both root and salt.
    let Some(digest_offset) = data.windows(32).position(|w| w == digest.as_slice()) else {
        return recovered;
    };
    let Some(root_offset) = digest_offset.checked_sub(32) else {
        return recovered;
    };
    let Some(salt_offset) = digest_offset.checked_add(64) else {
        return recovered;
    };
    let Some(root_bytes) = range(data, root_offset, 4) else {
        return recovered;
    };
    let Some(salt) = range(data, salt_offset, 32) else {
        return recovered;
    };
    let root = u32::from_le_bytes(match root_bytes.try_into() {
        Ok(v) => v,
        Err(_) => return recovered,
    });
    let mut has_root = false;
    let mut has_salt = false;
    let mut iteration_candidates = Vec::new();
    for pos in 0..code.len().saturating_sub(8) {
        if code.get(pos..pos + 3) == Some(&[0x48, 0x8b, 0x15]) {
            has_root |= rip_target(code, text.vaddr, pos)
                .and_then(|va| address_offset(sections, va))
                == Some(root_offset);
        }
        if code.get(pos..pos + 3) == Some(&[0x0f, 0x28, 0x05]) {
            has_salt |= rip_target(code, text.vaddr, pos)
                .and_then(|va| address_offset(sections, va))
                == Some(salt_offset);
        }
        if code.get(pos..pos + 4) == Some(&[0xff, 0xc5, 0x81, 0xfd])
            && let Some(bytes) = range(code, pos + 4, 4)
            && let Ok(bytes) = bytes.try_into()
        {
            let iterations = u32::from_le_bytes(bytes);
            if (1..=250_000).contains(&iterations) && !iteration_candidates.contains(&iterations) {
                iteration_candidates.push(iterations);
            }
        }
    }
    if !has_root || !has_salt || iteration_candidates.is_empty() || iteration_candidates.len() > 4 {
        return recovered;
    }
    let mut password = vec![0u8; 36];
    password[..4].copy_from_slice(&root.to_be_bytes());
    let keys: Vec<_> = iteration_candidates
        .iter()
        .map(|&i| (i, derive_key(&password, salt, i)))
        .collect();
    // Literal nonce stores, followed by three RIP-relative indexed tables.
    // Layout offsets describe instruction operands, never sample file offsets.
    for pos in 0..code.len().saturating_sub(180) {
        let Some(window) = range(code, pos, 180) else {
            continue;
        };
        if window.get(..2) != Some(&[0x48, 0xb8])
            || window.get(10..14) != Some(&[0x4c, 0x8d, 0x84, 0x24])
            || window.get(18..24) != Some(&[0x49, 0x89, 0x40, 0x05, 0x48, 0xb8])
            || window.get(32..35) != Some(&[0x49, 0x89, 0x00])
            || window.get(35..51)
                != Some(&[
                    0x66, 0x41, 0xc7, 0x40, 0x0d, 0, 0, 0x41, 0xc6, 0x40, 0x0f, 0, 0x41, 0x88,
                    0x68, 0x10,
                ])
            || window.get(107..110) != Some(&[0x48, 0x8d, 0x05])
            || window.get(119..122) != Some(&[0x48, 0x8d, 0x05])
            || window.get(131..134) != Some(&[0x48, 0x8d, 0x05])
            || window.get(171..174) != Some(&[0x48, 0x83, 0xfd])
        {
            continue;
        }
        let count = usize::from(window[174]);
        if !(1..=32).contains(&count) {
            continue;
        }
        let tables = [107, 119, 131].map(|offset| {
            rip_target(code, text.vaddr, pos + offset).and_then(|va| address_offset(sections, va))
        });
        let [Some(cipher_table), Some(length_table), Some(tag_table)] = tables else {
            continue;
        };
        let mut info = [0u8; 17];
        info[5..13].copy_from_slice(&window[2..10]);
        info[..8].copy_from_slice(&window[24..32]);
        for &(iterations, key) in &keys {
            let Some(payload) = decrypt_segments(
                data,
                sections,
                &key,
                &mut info,
                count,
                cipher_table,
                length_table,
                tag_table,
            ) else {
                continue;
            };
            if payload.starts_with(b"Fasd")
                && let Some(offset) = pointer(data, sections, cipher_table)
            {
                recovered.push(RecoveredScript {
                    data: payload,
                    offset,
                    segments: count,
                    iterations,
                });
            }
        }
        if recovered.len() >= 4 {
            break;
        }
    }
    recovered
}

fn decrypt_segments(
    data: &[u8],
    sections: &[Section],
    key: &[u8; 32],
    info: &mut [u8; 17],
    count: usize,
    cipher_table: usize,
    length_table: usize,
    tag_table: usize,
) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    let mut result = Vec::new();
    for index in 0..count {
        let delta = index.checked_mul(8)?;
        let cp = pointer(data, sections, cipher_table.checked_add(delta)?)?;
        let tp = pointer(data, sections, tag_table.checked_add(delta)?)?;
        let size = u64::from_le_bytes(
            range(data, length_table.checked_add(delta)?, 8)?
                .try_into()
                .ok()?,
        );
        let size = usize::try_from(size).ok()?;
        if size == 0 || result.len().checked_add(size)? > 8 * 1024 * 1024 {
            return None;
        }
        let mut chunk = range(data, cp, size)?.to_vec();
        chunk.extend_from_slice(range(data, tp, 16)?);
        info[16] = u8::try_from(index).ok()?;
        let n = nonce(key, info);
        result.extend_from_slice(
            &cipher
                .decrypt(Nonce::from_slice(&n), chunk.as_slice())
                .ok()?,
        );
    }
    Some(result)
}
