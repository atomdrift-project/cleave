//! Bounds-checked byte primitives shared by the extractors. Every read takes
//! attacker-controlled input and returns `None` past the end of the buffer.

pub(crate) fn u16_le(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

pub(crate) fn u32_le(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

pub(crate) fn u64_le(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

/// Decode ASCII hex pairs; `None` on odd length or a non-hex digit.
pub(crate) fn unhex(b: &[u8]) -> Option<Vec<u8>> {
    let (pairs, rest) = b.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    pairs
        .iter()
        .map(|&[hi, lo]| {
            let hi = char::from(hi).to_digit(16)?;
            let lo = char::from(lo).to_digit(16)?;
            u8::try_from((hi << 4) | lo).ok()
        })
        .collect()
}

/// RC4 keystream applied to `data`. An empty key is not RC4 and yields no
/// output rather than a division by zero.
pub(crate) fn rc4(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return Vec::new();
    }
    let mut s: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut j = 0u8;
    for (i, &k) in (0..256).zip(key.iter().cycle()) {
        j = j.wrapping_add(s[i]).wrapping_add(k);
        s.swap(i, usize::from(j));
    }
    let (mut i, mut j) = (0u8, 0u8);
    data.iter()
        .map(|b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[usize::from(i)]);
            s.swap(usize::from(i), usize::from(j));
            b ^ s[usize::from(s[usize::from(i)].wrapping_add(s[usize::from(j)]))]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_matches_published_vectors() {
        assert_eq!(hex::encode(rc4(b"Plaintext", b"Key")), "bbf316e8d940af0ad3");
        assert_eq!(hex::encode(rc4(b"pedia", b"Wiki")), "1021bf0420");
        assert_eq!(
            hex::encode(rc4(b"Attack at dawn", b"Secret")),
            "45a01f645fc35b383552544b9bf5"
        );
        assert!(rc4(b"data", b"").is_empty());
    }

    #[test]
    fn unhex_rejects_odd_and_non_hex_input() {
        assert_eq!(unhex(b"00ff7A"), Some(vec![0x00, 0xff, 0x7a]));
        assert_eq!(unhex(b"abc"), None);
        assert_eq!(unhex(b"zz"), None);
    }

    #[test]
    fn reads_stop_at_the_buffer_end() {
        let b = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(u16_le(&b, 6), Some(0x0807));
        assert_eq!(u32_le(&b, 0), Some(0x0403_0201));
        assert_eq!(u64_le(&b, 0), Some(0x0807_0605_0403_0201));
        assert_eq!(u16_le(&b, 7), None);
        assert_eq!(u32_le(&b, usize::MAX), None);
    }
}
