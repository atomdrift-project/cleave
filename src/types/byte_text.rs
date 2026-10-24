//! Bytes as readable JSON text: byte `b` is the code point `U+00bb`, except NUL,
//! which is `U+0100` because PostgreSQL's JSONB rejects `\u0000`.
//!
//! ASCII stays legible and searchable, every other byte costs at most two UTF-8
//! bytes, and the mapping is total and exact. Readers accept nothing else:
//! U+0000 and any code point above U+0100 are errors.

/// The code point standing in for NUL.
const NUL: char = '\u{100}';

/// Encode `data` as text, one code point per byte.
#[must_use]
pub(crate) fn encode(data: &[u8]) -> String {
    data.iter()
        .map(|&b| if b == 0 { NUL } else { char::from(b) })
        .collect()
}

/// Decode text written by [`encode`].
///
/// # Errors
/// Returns the first code point [`encode`] never writes.
pub(crate) fn decode(text: &str) -> Result<Vec<u8>, DecodeError> {
    text.chars()
        .map(|c| match c {
            NUL => Ok(0),
            _ => u8::try_from(c)
                .ok()
                .filter(|&b| b != 0)
                .ok_or(DecodeError(c)),
        })
        .collect()
}

/// A code point outside the byte-text alphabet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DecodeError(char);

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid byte-text code point U+{:04X}",
            u32::from(self.0)
        )
    }
}

impl std::error::Error for DecodeError {}

/// Serde glue: write a `Vec<u8>` field as byte text.
pub(crate) fn serialize<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&encode(bytes))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn every_byte_round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        let text = encode(&all);
        assert_eq!(text.chars().count(), 256);
        assert_eq!(decode(&text).unwrap(), all);
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn ascii_is_verbatim_and_nul_is_never_written() {
        assert_eq!(
            encode(b"curl -s http://x | sh\n"),
            "curl -s http://x | sh\n"
        );
        assert!(!encode(&[0, 0, 1]).contains('\0'));
        let json = serde_json::to_string(&encode(&[0, b'a'])).unwrap();
        assert!(!json.contains("\\u0000"), "{json}");
    }

    #[test]
    fn rejects_code_points_it_never_writes() {
        for bad in ["\0", "a\0b", "\u{101}", "€", "😀", "\u{fffd}"] {
            assert!(decode(bad).is_err(), "{bad:?}");
        }
    }
}
