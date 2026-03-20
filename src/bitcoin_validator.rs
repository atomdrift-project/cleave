//! Bitcoin address validation with checksum verification.
//! Supports Legacy (P2PKH), P2SH, and SegWit (Bech32/Bech32m).

use std::sync::OnceLock;

/// Base58 alphabet used by Bitcoin
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Bech32 alphabet used by SegWit
const BECH32_ALPHABET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Regex pattern to find potential Bitcoin addresses in text.
fn btc_addr_pattern() -> Option<&'static regex::Regex> {
    static PATTERN: OnceLock<Option<regex::Regex>> = OnceLock::new();
    PATTERN
        .get_or_init(|| {
            // Legacy/P2SH: [13][a-km-zA-HJ-NP-Z1-9]{25,34}
            // Bech32/Bech32m: bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,87}
            regex::Regex::new(
            r"\b([13][1-9A-HJ-NP-Za-km-z]{25,34}|bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,87})\b",
        )
        .ok()
        })
        .as_ref()
}

/// Validate if a string is a valid Bitcoin address (with checksum).
#[must_use]
pub(crate) fn validate_bitcoin_address(s: &str) -> bool {
    if s.starts_with("bc1") {
        validate_bech32(s)
    } else if s.starts_with('1') || s.starts_with('3') {
        validate_base58check(s)
    } else {
        false
    }
}

/// Check if a text string contains at least one valid Bitcoin address.
#[must_use]
pub fn contains_bitcoin_address(text: &str) -> bool {
    let Some(pattern) = btc_addr_pattern() else {
        return false;
    };
    for m in pattern.find_iter(text) {
        if validate_bitcoin_address(m.as_str()) {
            return true;
        }
    }
    false
}

/// Validate Base58Check address (Legacy/P2SH)
fn validate_base58check(s: &str) -> bool {
    if s.len() < 26 || s.len() > 35 {
        return false;
    }

    // Decode Base58
    let mut bytes = Vec::with_capacity(25);
    if !decode_base58(s, &mut bytes) {
        return false;
    }

    if bytes.len() != 25 {
        return false;
    }

    // Checksum is last 4 bytes
    let (data, checksum) = bytes.split_at(21);

    // Bitcoin uses double SHA-256 for Base58Check
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash1 = hasher.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(hash1);
    let hash2 = hasher2.finalize();

    &hash2[0..4] == checksum
}

/// Simple Base58 decoder (Bitcoin alphabet)
fn decode_base58(s: &str, out: &mut Vec<u8>) -> bool {
    let mut decoded = vec![0u8; s.len()];

    for c in s.bytes() {
        let mut carry = match BASE58_ALPHABET.iter().position(|&x| x == c) {
            Some(v) => v as u32,
            None => return false,
        };

        for byte in decoded.iter_mut().rev() {
            carry += 58 * (*byte as u32);
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }

        if carry != 0 {
            return false;
        }
    }

    let leading_zeros = s.bytes().take_while(|&c| c == b'1').count();
    out.clear();
    out.resize(leading_zeros, 0);

    let first_nonzero = decoded
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(decoded.len());
    out.extend_from_slice(&decoded[first_nonzero..]);

    true
}

/// Validate Bech32/Bech32m address (SegWit)
fn validate_bech32(s: &str) -> bool {
    if s.len() < 8 || s.len() > 90 {
        return false;
    }

    if s.bytes().any(|b| b.is_ascii_uppercase()) && s.bytes().any(|b| b.is_ascii_lowercase()) {
        return false;
    }

    let normalized = s.to_ascii_lowercase();
    let separator = match normalized.rfind('1') {
        Some(pos) => pos,
        None => return false,
    };
    if separator == 0 || separator + 7 > normalized.len() {
        return false;
    }

    let hrp = &normalized[..separator];
    if hrp != "bc" {
        return false;
    }

    let data_part = &normalized[separator + 1..];
    let mut values = Vec::with_capacity(data_part.len());
    for c in data_part.bytes() {
        match BECH32_ALPHABET.iter().position(|&x| x == c) {
            Some(v) => values.push(v as u8),
            None => return false,
        }
    }

    let encoding = match verify_bech32_checksum(hrp, &values) {
        Some(encoding) => encoding,
        None => return false,
    };

    let (witness_version, program_values) = match values.split_first() {
        Some(parts) => parts,
        None => return false,
    };
    if *witness_version > 16 {
        return false;
    }

    let program_data = &program_values[..program_values.len() - 6];
    let program = match convert_bits(program_data, 5, 8, false) {
        Some(program) => program,
        None => return false,
    };

    if program.len() < 2 || program.len() > 40 {
        return false;
    }

    if *witness_version == 0 {
        if encoding != Bech32Encoding::Bech32 {
            return false;
        }
        program.len() == 20 || program.len() == 32
    } else {
        encoding == Bech32Encoding::Bech32m
    }
}

fn hrp_expand(hrp: &str) -> Vec<u32> {
    let mut expanded = Vec::with_capacity(hrp.len() * 2 + 1);
    for b in hrp.bytes() {
        expanded.push((b >> 5) as u32);
    }
    expanded.push(0);
    for b in hrp.bytes() {
        expanded.push((b & 0x1f) as u32);
    }
    expanded
}

fn polymod(hrp: &[u32], data: &[u32]) -> u32 {
    let mut chk = 1u32;
    for &v in hrp {
        chk = polymod_step(chk, v);
    }
    for &v in data {
        chk = polymod_step(chk, v);
    }
    chk
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Bech32Encoding {
    Bech32,
    Bech32m,
}

fn verify_bech32_checksum(hrp: &str, values: &[u8]) -> Option<Bech32Encoding> {
    let data: Vec<u32> = values.iter().map(|&v| v as u32).collect();
    match polymod(&hrp_expand(hrp), &data) {
        1 => Some(Bech32Encoding::Bech32),
        0x2bc8_30a3 => Some(Bech32Encoding::Bech32m),
        _ => None,
    }
}

fn convert_bits(data: &[u8], from_bits: u32, to_bits: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let maxv = (1u32 << to_bits) - 1;
    let max_acc = (1u32 << (from_bits + to_bits - 1)) - 1;
    let mut result = Vec::new();

    for &value in data {
        if u32::from(value) >> from_bits != 0 {
            return None;
        }

        acc = ((acc << from_bits) | u32::from(value)) & max_acc;
        bits += from_bits;
        while bits >= to_bits {
            bits -= to_bits;
            result.push(((acc >> bits) & maxv) as u8);
        }
    }

    if pad {
        if bits > 0 {
            result.push(((acc << (to_bits - bits)) & maxv) as u8);
        }
    } else if bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0 {
        return None;
    }

    Some(result)
}

fn polymod_step(chk: u32, v: u32) -> u32 {
    let b = chk >> 25;
    let mut next_chk = ((chk & 0x1ffffff) << 5) ^ v;
    if (b >> 0) & 1 != 0 {
        next_chk ^= 0x3b6a57b2;
    }
    if (b >> 1) & 1 != 0 {
        next_chk ^= 0x26508e6d;
    }
    if (b >> 2) & 1 != 0 {
        next_chk ^= 0x1ea119fa;
    }
    if (b >> 3) & 1 != 0 {
        next_chk ^= 0x3d4233dd;
    }
    if (b >> 4) & 1 != 0 {
        next_chk ^= 0x2a1462b3;
    }
    next_chk
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_segwit_address_for_test(
        hrp: &str,
        witness_version: u8,
        program: &[u8],
        encoding: Bech32Encoding,
    ) -> String {
        let mut data = vec![witness_version];
        data.extend(convert_bits(program, 8, 5, true).expect("program should convert to base32"));

        let mut checksum_input: Vec<u32> = data.iter().map(|&v| u32::from(v)).collect();
        checksum_input.extend([0; 6]);
        let target = match encoding {
            Bech32Encoding::Bech32 => 1,
            Bech32Encoding::Bech32m => 0x2bc8_30a3,
        };
        let polymod = polymod(&hrp_expand(hrp), &checksum_input) ^ target;

        let mut encoded = String::from(hrp);
        encoded.push('1');
        for &value in &data {
            encoded.push(BECH32_ALPHABET[value as usize] as char);
        }
        for shift in (0..6).rev() {
            let value = ((polymod >> (5 * shift)) & 0x1f) as usize;
            encoded.push(BECH32_ALPHABET[value] as char);
        }

        encoded
    }

    #[test]
    fn test_valid_legacy() {
        assert!(validate_bitcoin_address(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        )); // Genesis
        assert!(validate_bitcoin_address("1111111111111111111114oLvT2"));
    }

    #[test]
    fn test_valid_p2sh() {
        // Real P2SH
        assert!(validate_bitcoin_address(
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        ));
    }

    #[test]
    fn test_valid_bech32() {
        assert!(validate_bitcoin_address(
            "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
        ));

        let taproot_program = [0u8; 32];
        let taproot_address =
            encode_segwit_address_for_test("bc", 1, &taproot_program, Bech32Encoding::Bech32m);
        assert!(validate_bitcoin_address(&taproot_address));
    }

    #[test]
    fn test_invalid_checksum() {
        // Change one char
        assert!(!validate_bitcoin_address(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"
        ));
    }

    #[test]
    fn test_garbage_rejected() {
        assert!(!validate_bitcoin_address("characteristics"));
        assert!(!validate_bitcoin_address("sharedSecret"));
    }
}
