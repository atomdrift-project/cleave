//! Z85 binary-to-text encoding (ZeroMQ RFC 32 alphabet) with arbitrary-length
//! support.
//!
//! Z85 packs four bytes into five printable ASCII characters (1.25× expansion —
//! the densest JSON-safe option, since the alphabet contains neither `"` nor
//! `\`). The base spec only encodes inputs whose length is a multiple of four;
//! we handle a trailing partial group the way Ascii85 does — encode the padded
//! group and emit `k + 1` characters for `k` remaining bytes — so the length is
//! self-describing and no separate length field is needed.
//!
//! Used to carry [`crate::types::ContextLine`] match bytes in the JSON report:
//! analysis emits raw bytes, and the hex/text view is a render-time concern.

/// The 85 Z85 digits, in value order (`0..=84`).
const ALPHABET: &[u8; 85] =
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";

/// Reverse map: ASCII byte → Z85 digit value, or `0xFF` for non-digits.
static DECODE: [u8; 256] = build_decode();

const fn build_decode() -> [u8; 256] {
    let mut table = [0xFFu8; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
}

/// Encode bytes as a Z85 string. A trailing group of 1–3 bytes yields 2–4
/// characters (`k + 1`), so the original length is recoverable.
#[must_use]
pub(crate) fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(4) * 5);
    for chunk in data.chunks(4) {
        let mut value = 0u32;
        for &b in chunk {
            value = (value << 8) | u32::from(b);
        }
        // Left-justify a partial group into the high bytes (zero-padded low).
        value <<= 8 * (4 - chunk.len());

        let mut digits = [0u8; 5];
        let mut v = value;
        for slot in digits.iter_mut().rev() {
            *slot = ALPHABET[(v % 85) as usize];
            v /= 85;
        }
        // Full group → 5 chars; a k-byte tail → k + 1 chars.
        let emit = if chunk.len() == 4 { 5 } else { chunk.len() + 1 };
        out.push_str(std::str::from_utf8(&digits[..emit]).unwrap_or(""));
    }
    out
}

/// An invalid Z85 string: a non-digit character, or a `% 5 == 1` length (no
/// partial group encodes to a single character).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodeError;

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid Z85 input")
    }
}

impl std::error::Error for DecodeError {}

/// Decode a Z85 string back to bytes. A trailing group of 2–4 characters yields
/// 1–3 bytes (`m - 1`), inverting [`encode`].
///
/// # Errors
/// Returns [`DecodeError`] on a non-Z85 character or a length that is `1` more
/// than a multiple of five (unreachable from [`encode`]).
pub(crate) fn decode(text: &str) -> Result<Vec<u8>, DecodeError> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 5 * 4);
    for chunk in bytes.chunks(5) {
        if chunk.len() == 1 {
            return Err(DecodeError); // no partial group is one character
        }
        // Pad a partial group with the max digit (84) so the kept high bytes
        // decode unchanged, mirroring Ascii85.
        let mut value = 0u64;
        for i in 0..5 {
            let digit = if i < chunk.len() {
                let d = DECODE[chunk[i] as usize];
                if d == 0xFF {
                    return Err(DecodeError);
                }
                u64::from(d)
            } else {
                84
            };
            value = value * 85 + digit;
        }
        if value > u64::from(u32::MAX) {
            return Err(DecodeError); // overflows a 4-byte group
        }
        let group = (value as u32).to_be_bytes();
        let keep = if chunk.len() == 5 { 4 } else { chunk.len() - 1 };
        out.extend_from_slice(&group[..keep]);
    }
    Ok(out)
}

/// Serde glue for a `Vec<u8>` field carried as a Z85 string in JSON.
pub(crate) mod serde_z85 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(d)?;
        super::decode(&text).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    // Tests assert on known-good round trips; unwrap is the clearest failure.
    #![allow(clippy::unwrap_used)]
    use super::{DecodeError, decode, encode};

    #[test]
    fn rfc_test_vector() {
        // RFC 32: the 8-byte HelloWorld frame.
        let data = [0x86, 0x4F, 0xD2, 0x6F, 0xB5, 0x59, 0xF7, 0x5B];
        assert_eq!(encode(&data), "HelloWorld");
        assert_eq!(decode("HelloWorld").unwrap(), data);
    }

    #[test]
    fn round_trips_every_length() {
        // A deterministic byte ramp at every length exercises full and all
        // partial-group tails (len % 4 ∈ {0,1,2,3}).
        for len in 0..=260usize {
            let data: Vec<u8> = (0..len)
                .map(|i| (i.wrapping_mul(37) ^ 0xA5) as u8)
                .collect();
            let encoded = encode(&data);
            assert_eq!(decode(&encoded).unwrap(), data, "len {len}");
            // k bytes → ceil(k/4)*... with k%4 tail emitting (k%4)+1 chars.
            let expected = len / 4 * 5 + if len % 4 == 0 { 0 } else { len % 4 + 1 };
            assert_eq!(encoded.len(), expected, "encoded len for {len}");
        }
    }

    #[test]
    fn empty_is_empty() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn rejects_invalid() {
        assert_eq!(decode("ab\"cd"), Err(DecodeError)); // quote isn't a Z85 digit
        assert_eq!(decode("abcde f"), Err(DecodeError)); // trailing single char
    }

    #[test]
    fn json_safe_alphabet() {
        // The whole alphabet must survive a JSON string round-trip unescaped.
        let all: String = super::ALPHABET.iter().map(|&b| b as char).collect();
        let json = serde_json::to_string(&all).unwrap();
        assert!(!json.contains('\\'), "alphabet needs escaping: {json}");
    }
}
