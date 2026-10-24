//! Bounded Node.js single-executable resource recovery. Only data is read;
//! JavaScript, bytecode, snapshots and native entry points are never executed.
const LIMIT: usize = 64 * 1024 * 1024;
pub(crate) struct Member {
    pub(crate) name: String,
    pub(crate) data: Vec<u8>,
    pub(crate) javascript: bool,
}
fn u16_at(b: &[u8], p: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(p..p.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32_at(b: &[u8], p: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(p..p.checked_add(4)?)?.try_into().ok()?,
    ))
}
struct Reader<'a> {
    b: &'a [u8],
    at: usize,
    width: usize,
}
impl<'a> Reader<'a> {
    fn number(&mut self) -> Option<usize> {
        let end = self.at.checked_add(self.width)?;
        let raw = self.b.get(self.at..end)?;
        let value = if self.width == 8 {
            u64::from_le_bytes(raw.try_into().ok()?)
        } else {
            u32::from_le_bytes(raw.try_into().ok()?) as u64
        };
        self.at = end;
        usize::try_from(value).ok()
    }
    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.number()?;
        if len > LIMIT {
            return None;
        }
        let end = self.at.checked_add(len)?;
        let value = self.b.get(self.at..end)?;
        self.at = end;
        Some(value)
    }
}
fn blob(b: &[u8], width: usize) -> Option<Vec<Member>> {
    // Node v26's 10-byte header: magic, flags, argv mode, module format.
    // Unknown formats are not guessed. Snapshot data is never called source.
    if b.len() > LIMIT || u32_at(b, 0)? != 0x0143_da20 || !matches!(width, 4 | 8) {
        return None;
    }
    let flags = u32_at(b, 4)?;
    if flags & !31 != 0 || *b.get(8)? > 2 || *b.get(9)? > 1 {
        return None;
    }
    let mut r = Reader { b, at: 10, width };
    let path = r.string()?;
    if path.len() > 16384 || std::str::from_utf8(path).is_err() {
        return None;
    }
    let code = r.string()?;
    if flags & 4 != 0 {
        r.string()?;
    } // optional V8 code cache
    let mut members = Vec::new();
    if flags & 2 == 0 && std::str::from_utf8(code).is_ok() {
        members.push(Member {
            name: "main.cjs".into(),
            data: code.to_vec(),
            javascript: true,
        });
    }
    if flags & 8 != 0 {
        let count = r.number()?;
        if count > 128 {
            return None;
        }
        for i in 0..count {
            let name = r.string()?;
            if name.len() > 16384 {
                return None;
            }
            let bytes = r.string()?;
            // Logical coordinates never use attacker-controlled asset paths.
            let suffix = if bytes.starts_with(b"MZ") {
                "dll"
            } else {
                "bin"
            };
            members.push(Member {
                name: format!("asset-{i}.{suffix}"),
                data: bytes.to_vec(),
                javascript: false,
            });
        }
    }
    if flags & 16 != 0 {
        let count = r.number()?;
        if count > 128 {
            return None;
        }
        for _ in 0..count {
            r.string()?;
        }
    }
    if r.at != b.len() {
        return None;
    }
    Some(members)
}
struct Pe<'a> {
    b: &'a [u8],
    section: usize,
    count: usize,
}
impl Pe<'_> {
    fn offset(&self, rva: u32, len: usize) -> Option<usize> {
        for i in 0..self.count {
            let s = self.section + i * 40;
            let start = u32_at(self.b, s + 12)?;
            let Some(delta) = rva.checked_sub(start).map(|n| n as usize) else {
                continue;
            };
            if delta.checked_add(len)? <= u32_at(self.b, s + 16)? as usize {
                let at = (u32_at(self.b, s + 20)? as usize).checked_add(delta)?;
                self.b.get(at..at.checked_add(len)?)?;
                return Some(at);
            }
        }
        None
    }
}
fn entries(b: &[u8], at: usize) -> Option<Vec<(u32, u32)>> {
    let n = usize::from(u16_at(b, at.checked_add(12)?)?)
        .checked_add(usize::from(u16_at(b, at.checked_add(14)?)?))?;
    if n > 512 {
        return None;
    }
    let start = at.checked_add(16)?;
    b.get(start..start.checked_add(n.checked_mul(8)?)?)?;
    (0..n)
        .map(|i| {
            let p = start + i * 8;
            Some((u32_at(b, p)?, u32_at(b, p + 4)?))
        })
        .collect()
}
pub(crate) fn recover(data: &[u8]) -> Option<Vec<Member>> {
    if data.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32_at(data, 0x3c)? as usize;
    if data.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let optional = pe.checked_add(24)?;
    let size = usize::from(u16_at(data, pe.checked_add(20)?)?);
    let (directories, width) = match u16_at(data, optional)? {
        0x20b => (112, 8),
        0x10b => (96, 4),
        _ => return None,
    };
    if size < directories + 24 {
        return None;
    }
    let count = usize::from(u16_at(data, pe.checked_add(6)?)?);
    if count == 0 || count > 96 {
        return None;
    }
    let section = optional.checked_add(size)?;
    data.get(section..section.checked_add(count.checked_mul(40)?)?)?;
    let image = Pe {
        b: data,
        section,
        count,
    };
    let dir = optional.checked_add(directories + 16)?;
    let rva = u32_at(data, dir)?;
    let len = u32_at(data, dir + 4)? as usize;
    if rva == 0 || len > LIMIT {
        return None;
    }
    let at = image.offset(rva, len)?;
    let tree = data.get(at..at.checked_add(len)?)?;
    for (ty, sub) in entries(tree, 0)? {
        if ty != 10 || sub & 0x8000_0000 == 0 {
            continue;
        }
        for (name, langs) in entries(tree, (sub & 0x7fff_ffff) as usize)? {
            if name & 0x8000_0000 == 0 || langs & 0x8000_0000 == 0 {
                continue;
            }
            let np = (name & 0x7fff_ffff) as usize;
            if u16_at(tree, np)? != 13 {
                continue;
            }
            let expected: Vec<u8> = "NODE_SEA_BLOB"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            // The resource name has 13 UTF-16 code units (including neither NUL nor prefix).
            let name_start = np.checked_add(2)?;
            if tree.get(name_start..name_start.checked_add(expected.len())?)? != expected {
                continue;
            }
            for (_, leaf) in entries(tree, (langs & 0x7fff_ffff) as usize)? {
                if leaf & 0x8000_0000 != 0 {
                    continue;
                }
                let lp = leaf as usize;
                let size = u32_at(tree, lp.checked_add(4)?)? as usize;
                if size > LIMIT {
                    continue;
                }
                let off = image.offset(u32_at(tree, lp)?, size)?;
                if let Some(result) = blob(data.get(off..off.checked_add(size)?)?, width) {
                    return Some(result);
                }
            }
        }
    }
    None
}
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail immediately on invalid setup"
)]
mod tests {
    use super::*;
    fn push(b: &mut Vec<u8>, s: &[u8]) {
        b.extend_from_slice(&(s.len() as u64).to_le_bytes());
        b.extend_from_slice(s);
    }
    fn sample(flags: u32) -> Vec<u8> {
        let mut b = 0x0143_da20u32.to_le_bytes().to_vec();
        b.extend_from_slice(&flags.to_le_bytes());
        b.extend_from_slice(&[1, 0]);
        push(&mut b, b"main.cjs");
        push(&mut b, b"console.log('marker');");
        b
    }
    #[test]
    fn plain_source_is_data() {
        let b = sample(1);
        let m = blob(&b, 8).unwrap();
        assert_eq!(m[0].data, b"console.log('marker');");
        assert!(m[0].javascript);
    }
    #[test]
    fn snapshots_are_not_source() {
        assert!(blob(&sample(3), 8).unwrap().is_empty());
    }
    #[test]
    fn asset_paths_are_never_used() {
        let mut b = sample(9);
        b.extend_from_slice(&1u64.to_le_bytes());
        push(&mut b, b"../../evil.dll");
        push(&mut b, b"MZexample");
        let m = blob(&b, 8).unwrap();
        assert_eq!(m[1].name, "asset-0.dll");
    }
    #[test]
    fn bounds_and_unknown_layouts_fail_closed() {
        let b = sample(1);
        for n in 0..b.len() {
            assert!(blob(&b[..n], 8).is_none());
        }
        let mut huge = b.clone();
        huge[10..18].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(blob(&huge, 8).is_none());
        assert!(blob(&sample(32), 8).is_none());
        assert!(recover(b"MZshort").is_none());
    }
    #[test]
    fn huge_asset_count_is_rejected() {
        let mut b = sample(9);
        b.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(blob(&b, 8).is_none());
    }
    #[test]
    fn independent_resource_reference_if_supplied() {
        if let Ok(p) = std::env::var("SEA_EXTERNAL_SAMPLE") {
            let b = std::fs::read(p).unwrap();
            let m = recover(&b).expect("resource recovery");
            assert_eq!(
                m[0].data,
                std::fs::read(std::env::var("SEA_EXTERNAL_REFERENCE").unwrap()).unwrap()
            );
            assert_eq!(m.len(), 4);
        }
    }
}
