//! Bounded recovery of the recognized x86 NRV2B load/decode stub as data.
//! The result is a memory-layout analysis image, not an executable rebuilt
//! with live imports. No specimen instruction or OS API is executed.
const LIMIT: usize = 64 * 1024 * 1024;
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
struct Bits<'a> {
    bytes: &'a [u8],
    at: usize,
    bits: u32,
}
impl Bits<'_> {
    fn byte(&mut self) -> Result<u8, &'static str> {
        let b = *self.bytes.get(self.at).ok_or("truncated NRV input")?;
        self.at += 1;
        Ok(b)
    }
    fn bit(&mut self) -> Result<u32, &'static str> {
        let carry = self.bits >> 31;
        self.bits <<= 1;
        if self.bits != 0 {
            return Ok(carry);
        }
        let w = u32_at(self.bytes, self.at).ok_or("truncated NRV bitstream")?;
        self.at += 4;
        self.bits = (w << 1) | 1;
        Ok(w >> 31)
    }
}
pub(crate) fn decode(input: &[u8], limit: usize) -> Result<Vec<u8>, &'static str> {
    if limit > LIMIT || limit == 0 {
        return Err("invalid NRV output limit");
    }
    let mut reader = Bits {
        bytes: input,
        at: 0,
        bits: 0,
    };
    let mut out = Vec::new();
    let mut last = 1usize;
    // Each iteration emits output or finishes. Offset/length growth and all
    // copies are bounded separately; malformed bitstreams cannot spin forever.
    for _ in 0..limit {
        while reader.bit()? != 0 {
            if out.len() == limit {
                return Err("NRV output limit");
            }
            out.push(reader.byte()?);
        }
        let mut offset = 1u32;
        loop {
            offset = offset
                .checked_mul(2)
                .and_then(|v| v.checked_add(reader.bit().ok()?))
                .ok_or("NRV offset overflow")?;
            if offset > 0x1000002 {
                return Err("invalid NRV offset");
            }
            if reader.bit()? != 0 {
                break;
            }
        }
        let distance = if offset == 2 {
            last
        } else {
            let encoded = (offset - 3)
                .checked_mul(256)
                .and_then(|v| v.checked_add(reader.byte().ok()? as u32))
                .ok_or("NRV offset overflow")?;
            if encoded == u32::MAX {
                return Ok(out);
            }
            let n = encoded as usize + 1;
            last = n;
            n
        };
        let mut len = (reader.bit()? * 2 + reader.bit()?) as usize;
        if len == 0 {
            len = 1;
            loop {
                len = len
                    .checked_mul(2)
                    .and_then(|v| v.checked_add(reader.bit().ok()? as usize))
                    .ok_or("NRV length overflow")?;
                if len > limit {
                    return Err("NRV length limit");
                }
                if reader.bit()? != 0 {
                    break;
                }
            }
            len = len.checked_add(2).ok_or("NRV length overflow")?;
        }
        len += usize::from(distance > 0xd00) + 1;
        if distance == 0 || distance > out.len() {
            return Err("invalid NRV back-reference");
        }
        if len > limit.saturating_sub(out.len()) {
            return Err("NRV output limit");
        }
        for _ in 0..len {
            let b = out[out.len() - distance];
            out.push(b);
        }
    }
    Err("NRV work limit")
}
fn branches(data: &mut [u8], count: usize) -> Result<(), &'static str> {
    if count > data.len() / 5 {
        return Err("NRV branch count limit");
    }
    let mut at = 0usize;
    let mut pending = None;
    for _ in 0..count {
        loop {
            let opcode = if let Some(v) = pending.take() {
                v
            } else {
                let v = *data.get(at).ok_or("truncated NRV branch filter")?;
                at += 1;
                v
            };
            if (opcode == 0xe8 || opcode == 0xe9) && data.get(at) == Some(&5) {
                let b = data
                    .get(at..at.checked_add(5).ok_or("NRV branch overflow")?)
                    .ok_or("truncated NRV branch filter")?;
                let value = ((u32::from(b[1]) << 16) | (u32::from(b[2]) << 8) | u32::from(b[3]))
                    .wrapping_sub(at as u32);
                pending = Some(b[4]);
                data[at..at + 4].copy_from_slice(&value.to_le_bytes());
                at += 5;
                break;
            }
        }
    }
    Ok(())
}
/// Return None for other formats/stubs, including ordinary UPX variants.
/// Recognition is structural; names, URLs and family identifiers are unused.
pub(crate) fn recover(data: &[u8]) -> Result<Option<Vec<u8>>, &'static str> {
    if data.len() > LIMIT || data.get(..2) != Some(b"MZ") {
        return Ok(None);
    }
    let Some(pe) = u32_at(data, 0x3c).map(|x| x as usize) else {
        return Ok(None);
    };
    if data.get(pe..pe.saturating_add(4)) != Some(b"PE\0\0") || u16_at(data, pe + 4) != Some(0x14c)
    {
        return Ok(None);
    }
    let optional = pe.checked_add(24).ok_or("NRV PE overflow")?;
    if u16_at(data, optional) != Some(0x10b) {
        return Ok(None);
    }
    let count = u16_at(data, pe + 6).ok_or("truncated NRV PE")? as usize;
    let opt_size = u16_at(data, pe + 20).ok_or("truncated NRV PE")? as usize;
    if opt_size < 96 || !(1..=96).contains(&count) {
        return Ok(None);
    }
    let sections = optional.checked_add(opt_size).ok_or("NRV PE overflow")?;
    if data
        .get(sections..sections.saturating_add(count * 40))
        .is_none()
    {
        return Ok(None);
    }
    let base = u32_at(data, optional + 28).ok_or("truncated NRV PE")?;
    let size = (u32_at(data, optional + 56).ok_or("truncated NRV PE")? as usize)
        .checked_add(4095)
        .ok_or("NRV image overflow")?
        & !4095;
    let declared_headers = u32_at(data, optional + 60).ok_or("truncated NRV PE")? as usize;
    let first_raw = (0..count)
        .filter_map(|i| u32_at(data, sections + i * 40 + 20))
        .filter(|n| *n != 0)
        .min()
        .unwrap_or(declared_headers as u32) as usize;
    let headers = declared_headers.min(first_raw);
    if headers < sections + count * 40 {
        return Ok(None);
    }
    if size == 0 || size > LIMIT || headers > data.len() || headers > size {
        return Ok(None);
    }
    for index in 0..count {
        let section = sections + index * 40;
        let raw = u32_at(data, section + 20).ok_or("truncated NRV section")? as usize;
        let raw_size = u32_at(data, section + 16).ok_or("truncated NRV section")? as usize;
        let rva = u32_at(data, section + 12).ok_or("truncated NRV section")? as usize;
        let Some(body) = data.get(raw..raw.saturating_add(raw_size)) else {
            continue;
        };
        // The stub follows its own compressed stream. Restrict the search to the
        // final 64 KiB of each backed section and require the NRV loop as well as
        // the source/destination address setup and branch-restoration implementation.
        for pos in body.len().saturating_sub(65536)..body.len().saturating_sub(272) {
            if body.get(pos..pos + 2) != Some(&[0x60, 0xbe])
                || body.get(pos + 6..pos + 8) != Some(&[0x8d, 0xbe])
                || body.get(pos + 12..pos + 17) != Some(&[0x57, 0x83, 0xcd, 0xff, 0xeb])
            {
                continue;
            }
            if body.get(pos + 21..pos + 27) != Some(&[0x8a, 0x06, 0x46, 0x88, 0x07, 0x47])
                || !matches!(
                    body.get(pos + 207..pos + 211),
                    Some([0x5e, 0x8b, 0xfe, 0xb9]) | Some([0x5e, 0x89, 0xf7, 0xb9])
                )
            {
                continue;
            }
            if body.get(pos + 215..pos + 221) != Some(&[0x8a, 0x07, 0x47, 0x2c, 0xe8, 0x3c]) {
                continue;
            }
            let source = u32_at(body, pos + 2).ok_or("NRV source missing")?;
            let displacement = u32_at(body, pos + 8).ok_or("NRV destination missing")? as i32;
            let source_rva = source.checked_sub(base).ok_or("NRV source below image")? as usize;
            let destination = (i64::from(source) + i64::from(displacement))
                .checked_sub(i64::from(base))
                .filter(|v| *v >= 0)
                .ok_or("NRV destination outside image")? as usize;
            let Some(stream_start) = source_rva.checked_sub(rva) else {
                return Err("NRV source outside stub section");
            };
            if stream_start >= pos || destination >= size {
                return Err("NRV source/destination extent");
            }
            let mut plain = decode(&body[stream_start..pos], size - destination)?;
            let branches_count =
                u32_at(body, pos + 211).ok_or("NRV branch count missing")? as usize;
            branches(&mut plain, branches_count)?;
            let mut image = vec![0u8; size];
            image[..headers].copy_from_slice(&data[..headers]);
            for i in 0..count {
                let s = sections + i * 40;
                let start = u32_at(data, s + 12).ok_or("truncated NRV section")? as usize;
                let len = u32_at(data, s + 16).ok_or("truncated NRV section")? as usize;
                let source = u32_at(data, s + 20).ok_or("truncated NRV section")? as usize;
                let virtual_size = u32_at(data, s + 8).ok_or("truncated NRV section")? as usize;
                let src = data
                    .get(source..source.checked_add(len).ok_or("NRV section overflow")?)
                    .ok_or("truncated NRV section data")?;
                let dest = image
                    .get_mut(start..start.checked_add(len).ok_or("NRV image overflow")?)
                    .ok_or("NRV section outside image")?;
                dest.copy_from_slice(src);
                let extent = virtual_size
                    .checked_add(511)
                    .ok_or("NRV section overflow")?
                    & !511;
                if start.checked_add(extent).is_none_or(|end| end > size) {
                    return Err("NRV virtual section outside image");
                }
                image[s + 16..s + 20].copy_from_slice(&(extent as u32).to_le_bytes());
                image[s + 20..s + 24].copy_from_slice(&(start as u32).to_le_bytes());
            }
            image[destination..destination + plain.len()].copy_from_slice(&plain);
            return Ok(Some(image));
        }
    }
    Ok(None)
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
    fn unrelated_and_truncated_inputs_do_not_recover() {
        for data in [&b""[..], &b"MZ"[..], &[0u8; 256][..]] {
            assert_eq!(recover(data).unwrap(), None);
        }
    }
    #[test]
    fn literal_stream_and_output_cap() {
        struct Writer {
            data: Vec<u8>,
            word: usize,
            used: u32,
        }
        impl Writer {
            fn bit(&mut self, v: u8) {
                if self.used == 32 {
                    self.word = self.data.len();
                    self.data.extend_from_slice(&[0; 4]);
                    self.used = 0;
                }
                let shift = 31 - self.used;
                let word = u32_at(&self.data, self.word).unwrap() | ((v as u32) << shift);
                self.data[self.word..self.word + 4].copy_from_slice(&word.to_le_bytes());
                self.used += 1;
            }
            fn byte(&mut self, v: u8) {
                self.data.push(v);
            }
        }
        let mut w = Writer {
            data: vec![],
            word: 0,
            used: 32,
        };
        for b in b"Hi" {
            w.bit(1);
            w.byte(*b);
        }
        w.bit(0);
        let marker = 0x1000002u32;
        for shift in (0..24).rev() {
            w.bit(((marker >> shift) & 1) as u8);
            w.bit(u8::from(shift == 0));
        }
        w.byte(255);
        assert_eq!(decode(&w.data, 3).unwrap(), b"Hi");
        assert!(decode(&w.data, 1).is_err());
    }
    #[test]
    fn truncated_bitstreams_and_invalid_limits_fail() {
        assert!(decode(&[], 4096).is_err());
        assert!(decode(&[0, 0, 0], 4096).is_err());
        assert!(decode(&[0xff; 16], 2).is_err());
        assert!(decode(&[], LIMIT + 1).is_err());
    }
    #[test]
    fn back_reference_cannot_read_before_output() {
        assert!(decode(&[0, 0, 0, 0], 4096).is_err());
    }
    #[test]
    fn branch_filter_rewrites_only_tagged_operands() {
        let mut b = vec![0xe8, 5, 0, 0, 8, 0x90];
        branches(&mut b, 1).unwrap();
        assert_eq!(&b[1..5], &7u32.to_le_bytes());
        assert!(branches(&mut [0xe8, 5], 1).is_err());
    }
    #[test]
    fn external_sample_matches_isolated_reference_if_supplied() {
        let Ok(path) = std::env::var("NRV_EXTERNAL_SAMPLE") else {
            return;
        };
        let Ok(reference) = std::env::var("NRV_EXTERNAL_REFERENCE") else {
            return;
        };
        let result = recover(&std::fs::read(path).unwrap()).unwrap().unwrap();
        let expected = std::fs::read(reference).unwrap();
        let first = result.iter().zip(&expected).position(|(a, b)| a != b);
        eprintln!(
            "length {} vs {}, first difference {:?}",
            result.len(),
            expected.len(),
            first
        );
        if let Some(at) = first {
            eprintln!(
                "bytes at diff: {:?} vs {:?}",
                &result[at..(at + 16).min(result.len())],
                &expected[at..(at + 16).min(expected.len())]
            );
        }
        assert!(
            result == expected,
            "recovered memory differs from independent reference"
        );
    }
}
