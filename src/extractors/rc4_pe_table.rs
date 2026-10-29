//! Recover PE members from a code-relative RC4 table envelope as inert data.
//! No specimen code or Windows APIs are executed.
use super::primitives::{rc4, u16_le, u32_le, u64_le};

pub(crate) struct Member {
    pub(crate) offset: usize,
    pub(crate) data: Vec<u8>,
}
#[derive(Clone)]
struct Section {
    va: u32,
    off: usize,
    size: usize,
    exec: bool,
}
struct Layout {
    base: u64,
    sections: Vec<Section>,
}
fn layout(b: &[u8]) -> Option<Layout> {
    if b.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32_le(b, 60)? as usize;
    if b.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let n = usize::from(u16_le(b, pe.checked_add(6)?)?);
    if !(1..=96).contains(&n) {
        return None;
    }
    let opt = pe.checked_add(24)?;
    let base = match u16_le(b, opt)? {
        0x20b => u64_le(b, opt.checked_add(24)?)?,
        0x10b => u64::from(u32_le(b, opt.checked_add(28)?)?),
        _ => return None,
    };
    let first = opt.checked_add(usize::from(u16_le(b, pe.checked_add(20)?)?))?;
    let mut sections = Vec::new();
    for i in 0..n {
        let p = first.checked_add(i.checked_mul(40)?)?;
        let va = u32_le(b, p.checked_add(12)?)?;
        let size = u32_le(b, p.checked_add(16)?)? as usize;
        let off = u32_le(b, p.checked_add(20)?)? as usize;
        b.get(off..off.checked_add(size)?)?;
        sections.push(Section {
            va,
            off,
            size,
            exec: u32_le(b, p.checked_add(36)?)? & 0x20000000 != 0,
        });
    }
    Some(Layout { base, sections })
}
impl Layout {
    fn offset(&self, rva: u64, n: usize) -> Option<usize> {
        for s in &self.sections {
            let delta = rva.checked_sub(u64::from(s.va));
            if let Some(delta) = delta.and_then(|d| usize::try_from(d).ok())
                && delta.checked_add(n)? <= s.size
            {
                return s.off.checked_add(delta);
            }
        }
        None
    }
    fn rva(&self, off: usize) -> Option<u64> {
        self.sections.iter().find_map(|s| {
            off.checked_sub(s.off)
                .filter(|d| *d < s.size)
                .map(|d| u64::from(s.va) + d as u64)
        })
    }
}
fn rel_target(b: &[u8], p: usize, image: &Layout) -> Option<u64> {
    let disp = i64::from(u32_le(b, p.checked_add(3)?)? as i32);
    image.rva(p)?.checked_add(7)?.checked_add_signed(disp)
}
pub(crate) fn recover(b: &[u8]) -> Vec<Member> {
    let Some(image) = layout(b) else {
        return Vec::new();
    };
    if b.len() > 512 * 1024 * 1024 {
        return Vec::new();
    }
    for section in image
        .sections
        .iter()
        .filter(|s| s.exec && s.size <= 4 * 1024 * 1024)
    {
        let Some(code) = b.get(section.off..section.off + section.size) else {
            continue;
        };
        for (at, window) in code.windows(16).enumerate() {
            // RC4 KSA: a 16-byte key is indexed relative to the loaded image.
            if window.get(..8) != Some(&[0x83, 0xe0, 0x0f, 0x42, 0x0f, 0xb6, 0x8c, 0x18])
                || window.get(12..16) != Some(&[0x41, 0x03, 0xca, 0x03])
            {
                continue;
            }
            let Some(key_rva) = u32_le(window, 8) else {
                continue;
            };
            let Some(key_at) = image.offset(u64::from(key_rva), 16) else {
                continue;
            };
            let key = &b[key_at..key_at + 16];
            let absolute = section.off + at;
            let image_base_loaded = (absolute.saturating_sub(128)..absolute).any(|p| {
                b.get(p..p + 3) == Some(&[0x4c, 0x8d, 0x1d]) && rel_target(b, p, &image) == Some(0)
            });
            if !image_base_loaded {
                continue;
            }
            for p in (absolute.saturating_sub(1024)..absolute).rev() {
                if b.get(p..p + 3) != Some(&[0x4c, 0x8d, 0x3d]) {
                    continue;
                }
                let Some(table) = rel_target(b, p, &image)
                    .and_then(|r| r.checked_sub(8))
                    .and_then(|r| image.offset(r, 16))
                else {
                    continue;
                };
                let count = (p + 7..(p + 96).min(absolute)).find_map(|q| {
                    if b.get(q..q + 3) == Some(&[0x49, 0x83, 0xfe]) {
                        b.get(q + 3).map(|n| usize::from(*n))
                    } else {
                        None
                    }
                });
                let Some(count) = count.filter(|n| (1..=32).contains(n)) else {
                    continue;
                };
                let mut members = Vec::new();
                let mut total = 0usize;
                for i in 0..count {
                    let entry = table + i * 16;
                    let Some(address) = u64_le(b, entry) else {
                        break;
                    };
                    let Some(size) = u32_le(b, entry + 8).map(|n| n as usize) else {
                        break;
                    };
                    if !(512..=32 * 1024 * 1024).contains(&size)
                        || total.saturating_add(size) > 256 * 1024 * 1024
                    {
                        continue;
                    }
                    let Some(offset) = address
                        .checked_sub(image.base)
                        .and_then(|r| image.offset(r, size))
                    else {
                        continue;
                    };
                    total += size;
                    let data = rc4(&b[offset..offset + size], key);
                    if layout(&data).is_some() {
                        members.push(Member { offset, data });
                    }
                }
                if !members.is_empty() {
                    return members;
                }
            }
        }
    }
    Vec::new()
}
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "invalid fixtures and failed recovery should fail the test"
)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_images() {
        for b in [&[][..], &[0; 200][..], b"MZ not a PE"] {
            assert!(recover(b).is_empty());
        }
    }
    #[test]
    fn actual_envelope_and_key_variant() {
        let Ok(path) = std::env::var("CLEAVE_RC4_TABLE_FIXTURE") else {
            return;
        };
        let original = std::fs::read(path).unwrap();
        let members = recover(&original);
        assert_eq!(members.len(), 10);
        let directory = std::env::var("CLEAVE_RC4_TABLE_MEMBERS").unwrap();
        for (i, m) in members.iter().enumerate() {
            assert_eq!(
                m.data,
                std::fs::read(format!("{directory}/{i}.exe")).unwrap()
            );
        }
        let image = layout(&original).unwrap();
        let key_at = image.offset(0xe320, 16).unwrap();
        let mut changed = original.clone();
        let key = [0x69u8; 16];
        changed[key_at..key_at + 16].copy_from_slice(&key);
        for m in &members {
            changed[m.offset..m.offset + m.data.len()].copy_from_slice(&rc4(&m.data, &key));
        }
        let recovered = recover(&changed);
        assert_eq!(recovered.len(), 10);
        for (a, b) in recovered.iter().zip(members) {
            assert_eq!(a.data, b.data);
        }
        changed[key_at] ^= 1;
        assert!(recover(&changed).is_empty());
    }
}
