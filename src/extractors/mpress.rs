//! Recover resources carried in MPRESS 2.x x86 LZMA images as data.
//! No native instructions or imports are executed. The recognized entry stub
//! supplies the header address; all sizes, RVAs, properties and tree walks are
//! bounded. Branch conversion follows that stub, not the unrelated XZ BCJ filter.
use std::io::{Cursor, Read};

const LIMIT: usize = 64 * 1024 * 1024;
pub(crate) struct Resource {
    pub(crate) rva: u32,
    pub(crate) data: Vec<u8>,
    pub(crate) executable: bool,
}
fn bytes(data: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    data.get(off..off.checked_add(len)?)
}
fn word(data: &[u8], off: usize) -> Option<usize> {
    Some(u16::from_le_bytes(bytes(data, off, 2)?.try_into().ok()?) as usize)
}
fn dword(data: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes(data, off, 4)?.try_into().ok()?))
}
struct Pe<'a> {
    data: &'a [u8],
    sections: usize,
    count: usize,
    optional: usize,
}
impl<'a> Pe<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        if data.get(..2)? != b"MZ" {
            return None;
        }
        let pe = dword(data, 0x3c)? as usize;
        if bytes(data, pe, 4)? != b"PE\0\0" || word(data, pe + 4)? != 0x14c {
            return None;
        }
        let optional = pe.checked_add(24)?;
        let size = word(data, pe + 20)?;
        if size < 120 || word(data, optional)? != 0x10b {
            return None;
        }
        let count = word(data, pe + 6)?;
        if !(1..=96).contains(&count) {
            return None;
        }
        let sections = optional.checked_add(size)?;
        bytes(data, sections, count * 40)?;
        Some(Self {
            data,
            sections,
            count,
            optional,
        })
    }
    fn offset(&self, rva: u32, len: usize) -> Option<usize> {
        for i in 0..self.count {
            let s = self.sections + 40 * i;
            let start = dword(self.data, s + 12)?;
            let size = dword(self.data, s + 16)? as usize;
            let Some(delta) = rva.checked_sub(start).map(|n| n as usize) else {
                continue;
            };
            if delta.checked_add(len)? <= size {
                let off = (dword(self.data, s + 20)? as usize).checked_add(delta)?;
                bytes(self.data, off, len)?;
                return Some(off);
            }
        }
        None
    }
}
fn decode(stream: &[u8], size: usize) -> Result<Vec<u8>, &'static str> {
    if !(4096..=LIMIT).contains(&size) || stream.len() < 7 || stream.len() > LIMIT {
        return Err("MPRESS size limit or truncated stream");
    }
    let (lc, lp, pb) = (stream[1], stream[0] & 15, stream[0] >> 4);
    if lc > 4 || lp > 4 || lc + lp > 4 || pb > 4 {
        return Err("Unsupported MPRESS LZMA properties");
    }
    // Convert the two-byte MPRESS properties to a known-size LZMA-alone header.
    let mut header = vec![(pb * 5 + lp) * 9 + lc];
    header.extend_from_slice(&(size as u32).to_le_bytes());
    header.extend_from_slice(&(size as u64).to_le_bytes());
    let input = Cursor::new(header).chain(Cursor::new(&stream[2..]));
    let lzma = xz2::stream::Stream::new_lzma_decoder((LIMIT + 16 * 1024 * 1024) as u64)
        .map_err(|_error| "MPRESS LZMA decoder unavailable")?;
    let mut reader = xz2::read::XzDecoder::new_stream(input, lzma).take(size as u64 + 1);
    let mut output = Vec::new();
    reader
        .read_to_end(&mut output)
        .map_err(|_error| "Invalid MPRESS LZMA stream")?;
    if output.len() != size {
        return Err("MPRESS output length mismatch");
    }
    Ok(output)
}
fn repair_branches(data: &mut [u8]) {
    let end = data.len().saturating_sub(4096);
    let mut i = 0;
    while i < end {
        let opcode = data[i];
        i += 1;
        if opcode & 0xfe != 0xe8 {
            continue;
        }
        let Some(&b) = data.get(i..).and_then(<[u8]>::first_chunk::<4>) else {
            break;
        };
        let mut value = i32::from_le_bytes(b);
        let pos = i as i32;
        i += 4;
        if value >= 0 {
            if value as usize >= end {
                continue;
            }
        } else {
            value = value.wrapping_add(pos);
            if value < 0 {
                continue;
            }
            value = value.wrapping_add(end as i32);
        }
        data[i - 4..i].copy_from_slice(&value.wrapping_sub(pos).to_le_bytes());
    }
}
fn leaves(
    table: &[u8],
    off: usize,
    depth: usize,
    budget: &mut usize,
    out: &mut Vec<(u32, usize)>,
) -> Option<()> {
    let count =
        word(table, off.checked_add(12)?)?.checked_add(word(table, off.checked_add(14)?)?)?;
    *budget = budget.checked_sub(count)?;
    let entries = off.checked_add(16)?;
    bytes(table, entries, count.checked_mul(8)?)?;
    for i in 0..count {
        let target = dword(table, entries + i * 8 + 4)?;
        let next = (target & 0x7fff_ffff) as usize;
        if depth < 2 && target & 0x8000_0000 != 0 {
            leaves(table, next, depth + 1, budget, out)?;
        } else if depth == 2 && target & 0x8000_0000 == 0 {
            out.push((dword(table, next)?, dword(table, next + 4)? as usize));
        } else {
            return None;
        }
    }
    Some(())
}
pub(crate) fn recover(data: &[u8]) -> Result<Vec<Resource>, &'static str> {
    if data.len() > LIMIT {
        return Ok(vec![]);
    }
    let Some(pe) = Pe::parse(data) else {
        return Ok(vec![]);
    };
    let Some(entry) = dword(data, pe.optional + 16) else {
        return Ok(vec![]);
    };
    let Some(ep) = pe.offset(entry, 48) else {
        return Ok(vec![]);
    };
    // Only this recognized LZMA/branch-repair stub layout is supported. Section
    // names, image base, payload location and compressed bytes are not pinned.
    if bytes(data, ep, 8) != Some(&[0x60, 0xe8, 0, 0, 0, 0, 0x58, 0x05])
        || bytes(data, ep + 12, 20)
            != Some(&[
                0x8b, 0x30, 0x03, 0xf0, 0x2b, 0xc0, 0x8b, 0xfe, 0x66, 0xad, 0xc1, 0xe0, 0x0c, 0x8b,
                0xc8, 0x50, 0xad, 0x2b, 0xc8, 0x03,
            ])
    {
        return Ok(vec![]);
    }
    let meta = entry
        .checked_add(6)
        .and_then(|n| n.checked_add(dword(data, ep + 8)?))
        .ok_or("MPRESS metadata overflow")?;
    let mo = pe.offset(meta, 4).ok_or("MPRESS metadata outside file")?;
    let start =
        i64::from(meta) + i64::from(dword(data, mo).ok_or("MPRESS metadata outside file")? as i32);
    let start = u32::try_from(start).map_err(|_error| "MPRESS payload RVA overflow")?;
    let off = pe.offset(start, 6).ok_or("MPRESS header outside file")?;
    let size = word(data, off).ok_or("MPRESS header outside file")? << 12;
    let packed_size = dword(data, off + 2).ok_or("MPRESS header outside file")? as usize;
    if packed_size > LIMIT {
        return Err("MPRESS compressed size limit");
    }
    let packed_rva = start.checked_add(6).ok_or("MPRESS payload overflow")?;
    let packed_off = pe
        .offset(packed_rva, packed_size)
        .ok_or("MPRESS payload outside file")?;
    let mut unpacked = decode(
        bytes(data, packed_off, packed_size).ok_or("MPRESS payload outside file")?,
        size,
    )?;
    repair_branches(&mut unpacked);
    let get = |rva: u32, len: usize| -> Option<&[u8]> {
        if let Some(delta) = rva.checked_sub(start).map(|n| n as usize)
            && delta < unpacked.len()
        {
            return bytes(&unpacked, delta, len);
        }
        bytes(data, pe.offset(rva, len)?, len)
    };
    let root = dword(data, pe.optional + 112).ok_or("MPRESS resource directory absent")?;
    let len = dword(data, pe.optional + 116).ok_or("MPRESS resource directory absent")? as usize;
    if len == 0 {
        return Ok(vec![]);
    }
    if len > 1024 * 1024 {
        return Err("MPRESS resource directory limit");
    }
    let table = get(root, len).ok_or("MPRESS resource directory outside image")?;
    let mut entries = vec![];
    leaves(table, 0, 0, &mut 256, &mut entries).ok_or("Invalid MPRESS resource tree")?;
    let mut resources = vec![];
    let mut remaining = LIMIT;
    let mut seen = std::collections::HashSet::new();
    for (rva, len) in entries {
        if len == 0 || !seen.insert((rva, len)) {
            continue;
        }
        let payload = get(rva, len).ok_or("MPRESS resource outside image")?;
        let executable = payload.starts_with(b"MZ");
        // Text configs are useful evidence too; arbitrary image/icon resources
        // are not recursively interpreted as programs.
        let config =
            len <= 64 * 1024 && payload.starts_with(b"[") && std::str::from_utf8(payload).is_ok();
        if !executable && !config {
            continue;
        }
        remaining = remaining
            .checked_sub(len)
            .ok_or("MPRESS resource byte budget")?;
        if resources.len() >= 16 {
            return Err("MPRESS resource count limit");
        }
        resources.push(Resource {
            rva,
            data: payload.to_vec(),
            executable,
        });
    }
    Ok(resources)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test fixtures fail immediately on invalid setup"
)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_pe_and_truncations() {
        for n in 0..256 {
            assert!(recover(&vec![0; n]).unwrap().is_empty());
        }
    }
    #[test]
    fn bounded_properties_and_sizes() {
        assert!(decode(&[0; 8], LIMIT + 1).is_err());
        assert!(decode(&[0xff; 8], 4096).is_err());
        assert!(decode(&[0; 2], 4096).is_err());
        assert!(decode(&[0; 8], 4096).is_err());
    }
    #[test]
    fn branch_conversion_and_unfiltered_tail() {
        let mut data = vec![0; 4112];
        data[0..5].copy_from_slice(&[0xe8, 12, 0, 0, 0]);
        data[5..10].copy_from_slice(&[0xe9, 0xfe, 0xff, 0xff, 0xff]);
        data[16..21].copy_from_slice(&[0xe8, 12, 0, 0, 0]);
        repair_branches(&mut data);
        assert_eq!(dword(&data, 1), Some(11));
        assert_eq!(dword(&data, 6), Some(14));
        assert_eq!(dword(&data, 17), Some(12));
    }
    #[test]
    fn resource_cycles_and_huge_counts_stop() {
        let mut t = vec![0; 32];
        t[14] = 1;
        t[20..24].copy_from_slice(&0x80000000u32.to_le_bytes());
        assert!(leaves(&t, 0, 0, &mut 256, &mut vec![]).is_none());
        t[14..16].copy_from_slice(&65535u16.to_le_bytes());
        assert!(leaves(&t, 0, 0, &mut 256, &mut vec![]).is_none());
    }
    #[test]
    #[ignore = "external independently recovered specimen"]
    fn supplied_mpress_resources_match_independent_recovery() {
        use sha2::{Digest, Sha256};
        let input = std::fs::read(std::env::var("MPRESS_SAMPLE").unwrap()).unwrap();
        let recovered = recover(&input).unwrap();
        let hashes: Vec<_> = recovered
            .iter()
            .map(|r| hex::encode(Sha256::digest(&r.data)))
            .collect();
        assert!(hashes.contains(
            &"7ed2a077a1ce34fcb182e5135ae75ad7bd96207c3204c9f343095f967bfa109f".to_string()
        ));
        assert!(hashes.contains(
            &"bf41e6af51ccba343098f403093b195fb5f238559f723d4088196a2648fb9272".to_string()
        ));
        assert_eq!(recovered.len(), 4);
        // Relocation-independent metadata arithmetic; changed image base and
        // section names must not change the recovered bytes.
        let mut renamed = input.clone();
        let pe = Pe::parse(&input).unwrap();
        renamed[pe.optional + 28..pe.optional + 32].copy_from_slice(&0x600000u32.to_le_bytes());
        for i in 0..pe.count {
            renamed[pe.sections + i * 40..pe.sections + i * 40 + 8].fill(b'X');
        }
        let again = recover(&renamed).unwrap();
        assert_eq!(
            again.iter().map(|r| &r.data).collect::<Vec<_>>(),
            recovered.iter().map(|r| &r.data).collect::<Vec<_>>()
        );
    }
}
