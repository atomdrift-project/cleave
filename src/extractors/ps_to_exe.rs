//! Recover PowerShell-to-EXE converter resources without executing the stub.
//! Recognize the converter's negated runtime vocabulary, derive candidate
//! RC4 keys from code-referenced eight-byte seeds, and inspect RCDATA only.
//! Addresses, resource names, keys, and script contents are never pinned.
use super::primitives::rc4;

use filefacts::{ParsedFile, Section};
use md5::{Digest, Md5};

pub(crate) struct RecoveredScript {
    pub(crate) data: Vec<u8>,
    pub(crate) offset: usize,
}

fn range(data: &[u8], offset: usize, size: usize) -> Option<&[u8]> {
    data.get(offset..offset.checked_add(size)?)
}

fn u16_at(data: &[u8], offset: usize) -> Option<usize> {
    Some(u16::from_le_bytes(range(data, offset, 2)?.try_into().ok()?) as usize)
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(range(data, offset, 4)?.try_into().ok()?))
}

fn rva_offset(sections: &[Section], rva: u64) -> Option<usize> {
    sections.iter().find_map(|s| {
        let delta = rva.checked_sub(s.vaddr)?;
        (delta < s.file_size)
            .then(|| s.file_offset.checked_add(delta))
            .flatten()
            .and_then(|n| usize::try_from(n).ok())
    })
}

fn marker(data: &[u8], plain: &[u8]) -> bool {
    data.windows(plain.len())
        .any(|w| w.iter().zip(plain).all(|(&a, &b)| a == b.wrapping_neg()))
}

// Resource directories use offsets relative to the resource root; payload
// RVAs map through filefacts sections. Restrict the walk to RT_RCDATA and the
// fixed type/name/language hierarchy, with a shared entry and byte budget.
fn resources(data: &[u8], sections: &[Section], root: usize, size: usize) -> Vec<(usize, usize)> {
    fn walk(
        table: &[u8],
        off: usize,
        depth: usize,
        budget: &mut usize,
        out: &mut Vec<(u32, usize)>,
    ) -> Option<()> {
        let count = u16_at(table, off.checked_add(12)?)?
            .checked_add(u16_at(table, off.checked_add(14)?)?)?;
        if count > *budget {
            return None;
        }
        *budget -= count;
        let entries = off.checked_add(16)?;
        range(table, entries, count.checked_mul(8)?)?;
        for i in 0..count {
            let entry = entries.checked_add(i.checked_mul(8)?)?;
            let name = u32_at(table, entry)?;
            let target = u32_at(table, entry.checked_add(4)?)?;
            if depth == 0 && name != 10 {
                continue;
            }
            let rel = (target & 0x7fff_ffff) as usize;
            if depth < 2 && target & 0x8000_0000 != 0 {
                walk(table, rel, depth + 1, budget, out)?;
            } else if depth == 2 && target & 0x8000_0000 == 0 {
                let rva = u32_at(table, rel)?;
                let len = u32_at(table, rel.checked_add(4)?)? as usize;
                if (64..=4 * 1024 * 1024).contains(&len) {
                    out.push((rva, len));
                }
            }
        }
        Some(())
    }
    let Some(table) = range(data, root, size) else {
        return vec![];
    };
    let mut entries = Vec::new();
    if walk(table, 0, 0, &mut 256, &mut entries).is_none() {
        return vec![];
    }
    let mut remaining: usize = 4 * 1024 * 1024;
    entries
        .into_iter()
        .filter_map(|(rva, len)| {
            let offset = rva_offset(sections, u64::from(rva))?;
            range(data, offset, len)?;
            remaining = remaining.checked_sub(len)?;
            Some((offset, len))
        })
        .collect()
}

fn script_prefix(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
        && data
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace())
        && data.contains(&b'$')
        && data.iter().any(|b| b"=({|".contains(b))
}

pub(crate) fn recover(data: &[u8], parsed: &ParsedFile<'_>) -> Vec<RecoveredScript> {
    if data.len() > 32 * 1024 * 1024
        || !marker(data, b"p2eincfilepath")
        || !marker(data, b"powershell")
    {
        return vec![];
    }
    let values = parsed.values();
    if values
        .get("pe.machine_id")
        .and_then(serde_json::Value::as_u64)
        != Some(0x8664)
    {
        return vec![];
    }
    let Some(base) = values
        .get("pe.image_base")
        .and_then(serde_json::Value::as_u64)
    else {
        return vec![];
    };
    let Some(dirs) = values.get("pe.data_directories").and_then(|v| v.as_array()) else {
        return vec![];
    };
    let Some(dir) = dirs
        .iter()
        .find(|d| d.get("name").and_then(|v| v.as_str()) == Some("resource"))
    else {
        return vec![];
    };
    let Some(rva) = dir.get("rva").and_then(serde_json::Value::as_u64) else {
        return vec![];
    };
    let Some(size) = dir
        .get("size")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
    else {
        return vec![];
    };
    let sections = parsed.sections();
    let sections = sections.as_slice();
    let Some(root) = rva_offset(sections, rva) else {
        return vec![];
    };
    let entries = resources(data, sections, root, size);
    if entries.is_empty() {
        return vec![];
    }
    let mut keys = Vec::new();
    for section in sections
        .iter()
        .filter(|s| s.flags.contains(&filefacts::SectionFlag::Executable))
    {
        let (Ok(offset), Ok(len)) = (
            usize::try_from(section.file_offset),
            usize::try_from(section.file_size),
        ) else {
            continue;
        };
        if len > 2 * 1024 * 1024 {
            continue;
        }
        let Some(code) = range(data, offset, len) else {
            continue;
        };
        for w in code.windows(17) {
            if w[..2] != [0x48, 0xb8] || w[10..13] != [0x48, 0x89, 0x05] {
                continue;
            }
            let va = u64::from_le_bytes([w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9]]);
            let Some(seed_offset) = va.checked_sub(base).and_then(|r| rva_offset(sections, r))
            else {
                continue;
            };
            let Some(seed) = range(data, seed_offset, 8) else {
                continue;
            };
            let key = hex::encode_upper(Md5::digest(seed)).into_bytes();
            if !keys.contains(&key) {
                keys.push(key);
            }
            if keys.len() >= 32 {
                break;
            }
        }
        if keys.len() >= 32 {
            break;
        }
    }
    let mut recovered = Vec::new();
    for (offset, len) in entries {
        let Some(ciphertext) = range(data, offset, len) else {
            continue;
        };
        for key in &keys {
            if !script_prefix(&rc4(&ciphertext[..ciphertext.len().min(256)], key)) {
                continue;
            }
            let mut plain = rc4(ciphertext, key);
            while plain.last() == Some(&0) {
                plain.pop();
            }
            if std::str::from_utf8(&plain).is_err() {
                continue;
            }
            if !recovered.iter().any(|p: &RecoveredScript| p.data == plain) {
                recovered.push(RecoveredScript {
                    data: plain,
                    offset,
                });
            }
            break;
        }
    }
    recovered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_truncated_and_cyclic_resource_tables() {
        for size in 0..64 {
            let data = vec![0u8; size];
            assert!(resources(&data, &[], 0, size).is_empty());
        }
        let mut data = vec![0; 64];
        data[14] = 1;
        data[16] = 10;
        data[23] = 0x80;
        assert!(resources(&data, &[], 0, 64).is_empty());
    }

    #[test]
    fn randomized_plaintext_and_wrong_keys() {
        let script = b"$message = 'ordinary application'; Write-Output $message\r\n";
        let key = hex::encode_upper(Md5::digest(b"new seed")).into_bytes();
        let ciphertext = rc4(script, &key);
        assert_eq!(rc4(&ciphertext, &key), script);
        assert!(!script_prefix(&rc4(&ciphertext, b"wrong key")));
        assert!(script_prefix(script));
    }
    fn fixture(seed: &[u8; 8], image_base: u64) -> Vec<u8> {
        fn put16(d: &mut [u8], o: usize, n: u16) {
            d[o..o + 2].copy_from_slice(&n.to_le_bytes());
        }
        fn put32(d: &mut [u8], o: usize, n: u32) {
            d[o..o + 4].copy_from_slice(&n.to_le_bytes());
        }
        let mut d = vec![0; 0xa00];
        d[..2].copy_from_slice(b"MZ");
        put32(&mut d, 0x3c, 0x80);
        d[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut d, 0x84, 0x8664);
        put16(&mut d, 0x86, 3);
        put16(&mut d, 0x94, 0xf0);
        put16(&mut d, 0x96, 0x22);
        put16(&mut d, 0x98, 0x20b);
        put32(&mut d, 0xa8, 0x1000);
        d[0xb0..0xb8].copy_from_slice(&image_base.to_le_bytes());
        put32(&mut d, 0xb8, 0x1000);
        put32(&mut d, 0xbc, 0x200);
        put32(&mut d, 0xd0, 0x4000);
        put32(&mut d, 0xd4, 0x200);
        put16(&mut d, 0xdc, 2);
        put32(&mut d, 0x104, 16);
        put32(&mut d, 0x118, 0x3000);
        put32(&mut d, 0x11c, 0x400);
        for (i, (name, rva, offset, len, flags)) in [
            (b".renamed" as &[u8], 0x1000, 0x200, 0x200, 0x60000020),
            (b".values" as &[u8], 0x2000, 0x400, 0x200, 0xc0000040),
            (b".assets" as &[u8], 0x3000, 0x600, 0x400, 0x40000040),
        ]
        .iter()
        .enumerate()
        {
            let o = 0x188 + i * 40;
            d[o..o + name.len()].copy_from_slice(name);
            put32(&mut d, o + 8, *len);
            put32(&mut d, o + 12, *rva);
            put32(&mut d, o + 16, *len);
            put32(&mut d, o + 20, *offset);
            put32(&mut d, o + 36, *flags);
        }
        d[0x200..0x202].copy_from_slice(&[0x48, 0xb8]);
        d[0x202..0x20a].copy_from_slice(&(image_base + 0x20a0).to_le_bytes());
        d[0x20a..0x211].copy_from_slice(&[0x48, 0x89, 0x05, 0, 0, 0, 0]);
        d[0x4a0..0x4a8].copy_from_slice(seed);
        let vocabulary = b"p2eincfilepath powershell";
        for (i, c) in vocabulary.iter().enumerate() {
            d[0x400 + i] = c.wrapping_neg();
        }
        put16(&mut d, 0x60e, 1);
        put32(&mut d, 0x610, 10);
        put32(&mut d, 0x614, 0x80000020);
        put16(&mut d, 0x62e, 1);
        put32(&mut d, 0x630, 735);
        put32(&mut d, 0x634, 0x80000040);
        put16(&mut d, 0x64e, 1);
        put32(&mut d, 0x650, 0);
        put32(&mut d, 0x654, 0x60);
        let script = b"$message = 'ordinary application with no destructive behavior'; Write-Output $message\r\n";
        let encrypted = rc4(script, hex::encode_upper(Md5::digest(seed)).as_bytes());
        put32(&mut d, 0x660, 0x3080);
        put32(&mut d, 0x664, encrypted.len() as u32);
        d[0x680..0x680 + encrypted.len()].copy_from_slice(&encrypted);
        d
    }

    #[test]
    fn recovers_benign_scripts_with_changed_seed_base_sections_and_resource_name() {
        for (seed, base) in [(b"new seed", 0x180000000), (b"seed two", 0x240000000)] {
            let data = fixture(seed, base);
            let parsed = filefacts::OpenOptions::new().rizin(false).open(&data);
            let recovered = recover(&data, &parsed);
            assert_eq!(recovered.len(), 1);
            assert_eq!(recovered[0].offset, 0x680);
            assert!(
                recovered[0]
                    .data
                    .starts_with(b"$message = 'ordinary application")
            );
        }
    }

    #[test]
    fn rejects_wrong_seed_missing_marker_and_truncated_ciphertext() {
        for variant in 0..3 {
            let mut data = fixture(b"new seed", 0x180000000);
            match variant {
                0 => data[0x4a0] ^= 0x55,
                1 => data[0x400..0x420].fill(0),
                _ => data.truncate(0x690),
            }
            let parsed = filefacts::OpenOptions::new().rizin(false).open(&data);
            assert!(recover(&data, &parsed).is_empty());
        }
    }
}
