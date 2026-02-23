#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use crate::rtf::error::{Result, RtfError};

/// Decode a hex string into bytes. Tolerates whitespace.
/// RTF uses ASCII hex encoding where binary data is represented as two-character hex strings.
pub(crate) fn decode_hex_tolerant(input: &str) -> Result<Vec<u8>> {
    // First pass: collect all hex digits, skipping whitespace
    let mut hex_digits = Vec::new();
    for &b in input.as_bytes() {
        if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
            continue;
        }
        hex_digits.push(b);
    }

    // Check for odd length
    if hex_digits.len() % 2 != 0 {
        return Err(RtfError::HexDecodeError {
            position: hex_digits.len(),
            reason: "hex string has odd length (after removing whitespace)".to_string(),
        });
    }

    // Second pass: decode pairs
    let mut result = Vec::with_capacity(hex_digits.len() / 2);
    for chunk in hex_digits.chunks(2) {
        let hi = parse_hex_digit(chunk[0])?;
        let lo = parse_hex_digit(chunk[1])?;
        result.push((hi << 4) | lo);
    }

    Ok(result)
}

/// Parse a single hex digit
fn parse_hex_digit(b: u8) -> Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(RtfError::HexDecodeError {
            position: 0,
            reason: format!("invalid hex digit: {}", b as char),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_hex_tolerant_with_spaces() {
        assert_eq!(
            decode_hex_tolerant("D 0 C F 1 1 E 0").unwrap(),
            vec![0xD0, 0xCF, 0x11, 0xE0]
        );
    }

    #[test]
    fn test_decode_hex_tolerant_mixed() {
        assert_eq!(
            decode_hex_tolerant("D0CF11E0\nA1B1\r\n1AE1").unwrap(),
            vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]
        );
    }
}
