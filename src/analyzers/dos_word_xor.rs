//! Literal reconstruction of a bounded DOS COM word-XOR entry stub.
//!
//! These are recognizers for fixed instruction recipes, not an x86 emulator.
//! Its patch and XOR parameters are read as data; no sample code is run.
const MAX_COM: usize = 65536;

pub(crate) fn decode(data: &[u8]) -> Option<(usize, Vec<u8>)> {
    if data.len() > MAX_COM {
        return None;
    }
    if data.first() == Some(&0xe8) {
        return decode_call_rotate_xor(data);
    }
    if data.first() != Some(&0xe9) {
        return None;
    }
    let jump = i16::from_le_bytes([*data.get(1)?, *data.get(2)?]) as isize;
    let entry = usize::try_from(3isize.checked_add(jump)?).ok()?;
    decode_patched_entry(data, entry)
        .or_else(|| decode_fallthrough(data, entry))
        .or_else(|| decode_byte_fallthrough(data, entry))
        .or_else(|| decode_byte_subtract(data, entry))
}

/// Decode a literal byte-XOR loop that falls through into its payload.
fn decode_byte_fallthrough(data: &[u8], entry: usize) -> Option<(usize, Vec<u8>)> {
    let stub = data.get(entry..entry.checked_add(14)?)?;
    if stub[0] != 0xb2
        || stub[1] == 0
        || stub[2] != 0xbe
        || stub[5] != 0xb9
        || stub.get(8..14)? != [0x2e, 0x30, 0x14, 0x46, 0xe2, 0xfa]
    {
        return None;
    }
    let start = usize::from(u16::from_le_bytes([stub[3], stub[4]])).checked_sub(0x100)?;
    let length = usize::from(u16::from_le_bytes([stub[6], stub[7]]));
    let body_end = start.checked_add(length)?;
    let after_stub = entry.checked_add(14)?;
    if length == 0
        || start < after_stub
        || start > after_stub.checked_add(4)?
        || body_end > data.len()
        || body_end > 0xff00
        || !data
            .get(after_stub..start)?
            .iter()
            .all(|byte| *byte == 0x90)
    {
        return None;
    }
    let mut decoded = data.to_vec();
    for byte in decoded.get_mut(start..body_end)? {
        *byte ^= stub[1];
    }
    Some((entry, decoded))
}

/// Recognize a forward subtract-byte recipe reached by a near CALL. This
/// reconstructs under the conventional DOS clear-direction-flag entry state.
fn decode_byte_subtract(data: &[u8], entry: usize) -> Option<(usize, Vec<u8>)> {
    let limit = entry.checked_add(64)?.min(data.len());
    for stub in entry..limit {
        let Some(end_stub) = stub.checked_add(26) else {
            continue;
        };
        let Some(body) = data.get(stub..end_stub) else {
            continue;
        };
        if body.get(..4) != Some(&[0xfa, 0x5f, 0x00, 0xfb])
            || body[4] != 0xb9
            || body[7..9] != [0xfa, 0xbe]
            || body[11..14] != [0x23, 0xff, 0xb2]
            || body[14] == 0
            || body[15..21] != [0x23, 0xff, 0x90, 0x2e, 0x28, 0x94]
            || body[23..26] != [0xa6, 0xe2, 0xf7]
        {
            continue;
        }
        let linked = (entry..stub.saturating_sub(2)).any(|at| {
            if data.get(at) != Some(&0xe8) {
                return false;
            }
            let Some(bytes) = data.get(at + 1..at + 3) else {
                return false;
            };
            let rel = i16::from_le_bytes([bytes[0], bytes[1]]) as isize;
            (at as isize)
                .checked_add(3)
                .and_then(|x| x.checked_add(rel))
                == Some(stub as isize)
        });
        if !linked {
            continue;
        }
        let si = u16::from_le_bytes([body[9], body[10]]);
        let disp = u16::from_le_bytes([body[21], body[22]]);
        let Some(start) = usize::from(si.wrapping_add(disp)).checked_sub(0x100) else {
            continue;
        };
        let count = usize::from(u16::from_le_bytes([body[5], body[6]]));
        let Some(end) = start.checked_add(count) else {
            continue;
        };
        if count == 0 || start != end_stub || end > data.len() || end > 0xff00 {
            continue;
        }
        let mut decoded = data.to_vec();
        for byte in decoded.get_mut(start..end)? {
            *byte = byte.wrapping_sub(body[14]);
        }
        return Some((stub, decoded));
    }
    None
}

/// Recognize a COM entry that calls a bounded subtract/XOR/rotate decoder,
/// then jumps to the decoded block. This interprets a fixed recipe only.
fn decode_call_rotate_xor(data: &[u8]) -> Option<(usize, Vec<u8>)> {
    if data.len() < 5 || data[3] != 0xeb {
        return None;
    }
    let relative = i16::from_le_bytes([data[1], data[2]]) as isize;
    let decoder = usize::try_from(3isize.checked_add(relative)?).ok()?;
    let jump = data[4] as i8 as isize;
    let target = usize::try_from(5isize.checked_add(jump)?).ok()?;
    let body = data.get(decoder..decoder.checked_add(25)?)?;
    if body[0] != 0xe8
        || body.get(3..5)? != [0x83, 0x3e]
        || body.get(7..12)? != [0x00, 0x74, 0x0e, 0xad, 0x2b]
        || body.get(12..19)? != [0xc1, 0x33, 0xc1, 0xd3, 0xc0, 0xab, 0xff]
        || body[19] != 0x0e
        || body.get(22..25)? != [0xeb, 0xeb, 0xc3]
        || body[5..7] != body[20..22]
    {
        return None;
    }
    let setup_rel = i16::from_le_bytes([body[1], body[2]]) as isize;
    let setup = usize::try_from((decoder as isize).checked_add(3)?.checked_add(setup_rel)?).ok()?;
    let setup_bytes = data.get(setup..setup.checked_add(16)?)?;
    if setup_bytes.get(..2)? != [0xc7, 0x06]
        || setup_bytes[2..4] != body[5..7]
        || setup_bytes[6] != 0xbe
        || setup_bytes.get(9..11)? != [0x8b, 0x0e]
        || setup_bytes.get(13..16)? != [0x8b, 0xfe, 0xc3]
    {
        return None;
    }
    let start =
        usize::from(u16::from_le_bytes([setup_bytes[7], setup_bytes[8]])).checked_sub(0x100)?;
    let count = usize::from(u16::from_le_bytes([setup_bytes[4], setup_bytes[5]]));
    let end = start.checked_add(count.checked_mul(2)?)?;
    let key_at =
        usize::from(u16::from_le_bytes([setup_bytes[11], setup_bytes[12]])).checked_sub(0x100)?;
    let counter_at =
        usize::from(u16::from_le_bytes([setup_bytes[2], setup_bytes[3]])).checked_sub(0x100)?;
    let overlaps =
        |offset: usize, length: usize| offset < end && offset.saturating_add(length) > start;
    if start != target
        || count == 0
        || end > data.len()
        || end > 0xff00
        || overlaps(decoder, 25)
        || overlaps(setup, 16)
        || overlaps(key_at, 2)
        || overlaps(counter_at, 2)
    {
        return None;
    }
    let key = u16::from_le_bytes([*data.get(key_at)?, *data.get(key_at.checked_add(1)?)?]);
    let mut decoded = data.to_vec();
    for chunk in decoded.get_mut(start..end)?.as_chunks_mut::<2>().0 {
        let word = u16::from_le_bytes([chunk[0], chunk[1]]).wrapping_sub(key) ^ key;
        chunk.copy_from_slice(&word.rotate_left(u32::from(key & 0xff)).to_le_bytes());
    }
    Some((decoder, decoded))
}

fn decode_patched_entry(data: &[u8], entry: usize) -> Option<(usize, Vec<u8>)> {
    let stub = data.get(entry..entry.checked_add(28)?)?;
    if stub.get(..4)? != [0xbe, 0x00, 0x01, 0x56]
        || stub[4] != 0xb9
        || stub.get(7..9)? != [0xc7, 0x04]
        || stub.get(11..14)? != [0xc6, 0x44, 0x02]
        || stub.get(15..17)? != [0x81, 0x34]
        || stub.get(19..28)? != [0x46, 0x46, 0xe2, 0xf8, 0x31, 0xf6, 0x31, 0xc9, 0xc3]
    {
        return None;
    }
    let words = usize::from(u16::from_le_bytes([stub[5], stub[6]]));
    let length = words.checked_mul(2)?;
    // The decoder may not change its own instructions, and the patched bytes
    // must be within the decoded span. This also bounds the work to 64 KiB.
    if length < 4 || length > entry || length > data.len() {
        return None;
    }
    let mut decoded = data.to_vec();
    decoded[..2].copy_from_slice(&stub[9..11]);
    decoded[2] = stub[14];
    let key = [stub[17], stub[18]];
    for chunk in decoded[..length].as_chunks_mut::<2>().0 {
        chunk[0] ^= key[0];
        chunk[1] ^= key[1];
    }
    // A near jump back into the decoded span is an additional structural
    // guard; do not interpret arbitrary XOR-ed data as a program.
    if decoded[0] != 0xe9 {
        return None;
    }
    let next = i16::from_le_bytes([decoded[1], decoded[2]]) as isize;
    let target = usize::try_from(3isize.checked_add(next)?).ok()?;
    if target >= length {
        return None;
    }
    Some((entry, decoded))
}

/// A forward word-XOR loop decodes the bytes immediately after itself and
/// then falls through into them. The address is a DOS COM memory address.
fn decode_fallthrough(data: &[u8], entry: usize) -> Option<(usize, Vec<u8>)> {
    let stub = data.get(entry..entry.checked_add(19)?)?;
    if stub[0] != 0xbf
        || stub[3] != 0xfc
        || stub[4] != 0xb9
        || stub.get(7..9)? != [0x81, 0x35]
        || stub.get(11..19)? != [0x83, 0xc7, 0x03, 0x83, 0xef, 0x01, 0xe2, 0xf4]
    {
        return None;
    }
    let address = usize::from(u16::from_le_bytes([stub[1], stub[2]]));
    let start = address.checked_sub(0x100)?;
    let length = usize::from(u16::from_le_bytes([stub[5], stub[6]])).checked_mul(2)?;
    let end = start.checked_add(length)?;
    if start != entry.checked_add(19)?
        || length == 0
        || end > data.len()
        || end.checked_add(0x100)? > 0x10000
        || stub[9..11] == [0, 0]
    {
        return None;
    }
    let key = [stub[9], stub[10]];
    let mut decoded = data.to_vec();
    for chunk in decoded.get_mut(start..end)?.as_chunks_mut::<2>().0 {
        chunk[0] ^= key[0];
        chunk[1] ^= key[1];
    }
    Some((entry, decoded))
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "invalid fixtures should fail the test")]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let key = [0x16, 0x44];
        let mut decoded = [0x90; 64];
        decoded[..3].copy_from_slice(&[0xe9, 0x0d, 0x00]);
        let patch = [
            decoded[0] ^ key[0],
            decoded[1] ^ key[1],
            decoded[2] ^ key[0],
        ];
        let mut encoded = decoded
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i & 1])
            .collect::<Vec<_>>();
        encoded[..3].copy_from_slice(&[0xe9, 61, 0]);
        encoded.extend_from_slice(&[
            0xbe, 0, 1, 0x56, 0xb9, 32, 0, 0xc7, 4, patch[0], patch[1], 0xc6, 0x44, 2, patch[2],
            0x81, 0x34, key[0], key[1], 0x46, 0x46, 0xe2, 0xf8, 0x31, 0xf6, 0x31, 0xc9, 0xc3,
        ]);
        encoded
    }
    #[test]
    fn restores_patched_entry_and_decodes_words() {
        let input = fixture();
        let (offset, result) = decode(&input).expect("recognized recipe");
        assert_eq!(offset, 64);
        assert_eq!(&result[..3], &[0xe9, 0x0d, 0]);
        assert!(result[3..64].iter().all(|b| *b == 0x90));
    }
    #[test]
    fn decodes_forward_fallthrough_and_rejects_unsafe_variants() {
        let entry = 16usize;
        let mut input = vec![0x90; entry];
        input[..3].copy_from_slice(&[0xe9, 13, 0]);
        let address = (0x100u16 + entry as u16 + 19).to_le_bytes();
        input.extend_from_slice(&[
            0xbf, address[0], address[1], 0xfc, 0xb9, 8, 0, 0x81, 0x35, 0x85, 0xdb, 0x83, 0xc7, 3,
            0x83, 0xef, 1, 0xe2, 0xf4,
        ]);
        let plain = [
            0xe8, 0, 0, 0x5d, 0x81, 0xed, 1, 0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xcd, 0x20,
        ];
        input.extend(
            plain
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ [0x85, 0xdb][i & 1]),
        );
        let (_, decoded) = decode(&input).expect("forward recipe");
        assert_eq!(&decoded[entry + 19..], &plain);
        for (offset, value) in [
            (entry + 1, address[0].wrapping_add(1)),
            (entry + 5, 9),
            (entry + 11, 0x82),
            (entry + 18, 0xf3),
        ] {
            let mut altered = input.clone();
            altered[offset] = value;
            assert!(decode(&altered).is_none(), "offset {offset}");
        }
        assert!(decode(&input[..input.len() - 1]).is_none());
    }
    #[test]
    fn decodes_call_linked_byte_subtract_and_rejects_bad_links() {
        let stub = 16usize;
        let start = stub + 26;
        let mut input = vec![0x90u8; 80];
        input[..3].copy_from_slice(&[0xe9, 0, 0]);
        input[5..8].copy_from_slice(&[0xe8, 8, 0]);
        let si = 0x2000u16;
        let displacement = (0x100u16 + start as u16).wrapping_sub(si).to_le_bytes();
        input[stub..stub + 26].copy_from_slice(&[
            0xfa,
            0x5f,
            0x00,
            0xfb,
            0xb9,
            12,
            0,
            0xfa,
            0xbe,
            0x00,
            0x20,
            0x23,
            0xff,
            0xb2,
            0x31,
            0x23,
            0xff,
            0x90,
            0x2e,
            0x28,
            0x94,
            displacement[0],
            displacement[1],
            0xa6,
            0xe2,
            0xf7,
        ]);
        let plain = [
            0x90u8, 0x90, 0xb4, 0x4e, 0xcd, 0x21, 0xb4, 0x40, 0xcd, 0x21, 0xcd, 0x20,
        ];
        for (dst, src) in input[start..start + plain.len()].iter_mut().zip(plain) {
            *dst = src.wrapping_add(0x31);
        }
        let (offset, decoded) = decode(&input).expect("byte subtract recipe");
        assert_eq!(offset, stub);
        assert_eq!(&decoded[start..start + plain.len()], &plain);
        for (offset, value) in [
            (5, 0x90),
            (stub + 5, 60),
            (stub + 14, 0),
            (stub + 21, displacement[0].wrapping_add(1)),
            (stub + 25, 0xf6),
        ] {
            let mut changed = input.clone();
            changed[offset] = value;
            assert!(decode(&changed).is_none(), "offset {offset}");
        }
        assert!(decode(&input[..stub + 25]).is_none());
    }

    #[test]
    fn decodes_byte_xor_fallthrough_and_rejects_bad_bounds() {
        let entry = 16usize;
        let start = entry + 15;
        let mut input = vec![0x90; 64];
        input[..3].copy_from_slice(&[0xe9, 13, 0]);
        let address = (0x100u16 + start as u16).to_le_bytes();
        input[entry..entry + 14].copy_from_slice(&[
            0xb2, 0x0e, 0xbe, address[0], address[1], 0xb9, 16, 0, 0x2e, 0x30, 0x14, 0x46, 0xe2,
            0xfa,
        ]);
        let plain = [
            0x90u8, 0x90, 0xb4, 0x4e, 0xcd, 0x21, 0xb4, 0x40, 0xcd, 0x21, 0x90, 0x90, 0x90, 0x90,
            0xcd, 0x20,
        ];
        for (dst, src) in input[start..start + plain.len()].iter_mut().zip(plain) {
            *dst = src ^ 0x0e;
        }
        let (offset, decoded) = decode(&input).expect("byte XOR recipe");
        assert_eq!(offset, entry);
        assert_eq!(&decoded[start..start + plain.len()], &plain);
        for (offset, value) in [
            (entry + 1, 0),
            (entry + 3, 0),
            (entry + 6, 80),
            (entry + 13, 0xf9),
            (entry + 14, 0xcc),
        ] {
            let mut changed = input.clone();
            changed[offset] = value;
            assert!(decode(&changed).is_none(), "offset {offset}");
        }
        assert!(decode(&input[..entry + 13]).is_none());
    }

    #[test]
    fn call_rotate_xor_recovers_bounded_words_and_rejects_invalid_stubs() {
        let mut input = vec![0x90; 128];
        let start = 16usize;
        let setup = 64usize;
        let decoder = 80usize;
        let key = 0x304eu16;
        input[0] = 0xe8;
        input[1..3].copy_from_slice(&((decoder as i16) - 3).to_le_bytes());
        input[3..5].copy_from_slice(&[0xeb, (start - 5) as u8]);
        input[40..42].copy_from_slice(&key.to_le_bytes());
        input[setup..setup + 16].copy_from_slice(&[
            0xc7, 0x06, 0x2a, 0x01, 0x08, 0x00, 0xbe, 0x10, 0x01, 0x8b, 0x0e, 0x28, 0x01, 0x8b,
            0xfe, 0xc3,
        ]);
        let displacement = ((setup as i16) - (decoder as i16) - 3).to_le_bytes();
        input[decoder..decoder + 25].copy_from_slice(&[
            0xe8,
            displacement[0],
            displacement[1],
            0x83,
            0x3e,
            0x2a,
            0x01,
            0x00,
            0x74,
            0x0e,
            0xad,
            0x2b,
            0xc1,
            0x33,
            0xc1,
            0xd3,
            0xc0,
            0xab,
            0xff,
            0x0e,
            0x2a,
            0x01,
            0xeb,
            0xeb,
            0xc3,
        ]);
        let plain = [
            0x90u8, 0x90, 0xb4, 0x4e, 0xcd, 0x21, 0xb4, 0x40, 0xcd, 0x21, 0x90, 0x90, 0x90, 0x90,
            0xcd, 0x20,
        ];
        for (i, bytes) in plain.as_chunks::<2>().0.iter().enumerate() {
            let word = u16::from_le_bytes([bytes[0], bytes[1]]);
            let encoded = (word.rotate_right(u32::from(key & 0xff)) ^ key).wrapping_add(key);
            input[start + i * 2..start + i * 2 + 2].copy_from_slice(&encoded.to_le_bytes());
        }
        let (offset, decoded) = decode(&input).expect("recognized rotate recipe");
        assert_eq!(offset, decoder);
        assert_eq!(&decoded[start..start + plain.len()], &plain);
        for (offset, value) in [
            (3, 0x90),
            (setup + 4, 40),
            (setup + 11, 0x1f),
            (decoder + 14, 0x90),
            (decoder + 20, 0x20),
        ] {
            let mut changed = input.clone();
            changed[offset] = value;
            assert!(decode(&changed).is_none(), "offset {offset}");
        }
        assert!(decode(&input[..100]).is_none());
    }

    #[test]
    fn generic_analyzer_emits_a_single_bounded_child() {
        use crate::analyzers::{AnalysisInput, Analyzer, FileType, generic::GenericAnalyzer};
        let input = fixture();
        let path = std::path::Path::new("fixture.com");
        let analyzer = GenericAnalyzer::new(FileType::DosCom);
        let report = analyzer
            .analyze_input(&AnalysisInput::new(path, &input, FileType::DosCom))
            .expect("analysis");
        assert_eq!(report.files.len(), 1);
        assert_eq!(
            report.files[0].encoding.as_deref(),
            Some(["dos-word-xor".to_owned()].as_slice())
        );
        assert!(report.files[0].path.contains("##dos-word-xor@64"));
    }
    #[test]
    fn rejects_changed_code_bounds_and_invalid_entry() {
        let input = fixture();
        for (offset, value) in [(64, 0xbf), (68, 0xba), (85, 0xe1), (69, 33), (73, 0)] {
            let mut changed = input.clone();
            changed[offset] = value;
            assert!(decode(&changed).is_none(), "offset {offset}");
        }
        assert!(decode(&input[..70]).is_none());
    }
}
