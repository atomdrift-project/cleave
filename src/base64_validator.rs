//! Syntax validation for Base64-compatible matched text.
//!
//! This is not an encoding detector: ordinary words can be valid Base64.
//! Rules still need their own length/content/context constraints. No decoded
//! buffer is allocated, and no claim is made about the decoded language.

/// Accept nonempty canonical standard or URL-safe Base64, padded or unpadded.
/// ASCII space, tab, CR and LF are ignored for wrapped MIME-style content.
/// Mixed alphabets, misplaced padding and nonzero unused tail bits fail.
#[must_use]
pub(crate) fn is_base64(text: &str) -> bool {
    let mut remainder = 0u8;
    let mut last = 0u8;
    let mut padding = 0u8;
    let mut any = false;
    let mut standard = false;
    let mut url_safe = false;
    for byte in text.bytes() {
        let value = match byte {
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            b'=' => {
                padding += 1;
                if padding > 2 {
                    return false;
                }
                continue;
            }
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'/' => {
                standard = true;
                if byte == b'+' { 62 } else { 63 }
            }
            b'-' | b'_' => {
                url_safe = true;
                if byte == b'-' { 62 } else { 63 }
            }
            _ => return false,
        };
        if padding != 0 || (standard && url_safe) {
            return false;
        }
        any = true;
        last = value;
        remainder = (remainder + 1) % 4;
    }
    any && match (remainder, padding) {
        (0, 0) => true,
        (2, 0 | 2) => last & 0x0f == 0,
        (3, 0 | 1) => last & 0x03 == 0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::is_base64;

    #[test]
    fn accepts_canonical_padded_unpadded_and_wrapped_text() {
        for text in [
            "Zg==",
            "Zg",
            "Zm8=",
            "Zm8",
            "Zm9v",
            "Zm9vYg==",
            "+/8=",
            "-_8=",
            "+/8",
            "-_8",
            " Zm9v\r\nYmFy\t",
        ] {
            assert!(is_base64(text), "{text:?}");
        }
    }

    #[test]
    fn rejects_bad_alphabet_length_padding_and_tail_bits() {
        for text in [
            "",
            " \t\r\n",
            "=",
            "====",
            "A",
            "AAAAA",
            "Zg=",
            "Zg===",
            "=Zg",
            "Z=g=",
            "Zg==AAAA",
            "Zm9v=",
            "Zh==",
            "Zh",
            "Zm9=",
            "Zm9",
            "+_8=",
            "-/8=",
            "Zg!!",
            "Zg==\0",
            "Zg==é",
            "Zg==\u{a0}",
            "data:text/plain;base64,Zg==",
        ] {
            assert!(!is_base64(text), "{text:?}");
        }
    }

    #[test]
    fn matches_reference_encoders_across_tail_lengths_and_alphabets() {
        use base64::{Engine, engine::general_purpose};
        for length in 1..=256 {
            let data: Vec<u8> = (0u8..=255).cycle().take(length).collect();
            for engine in [
                general_purpose::STANDARD,
                general_purpose::STANDARD_NO_PAD,
                general_purpose::URL_SAFE,
                general_purpose::URL_SAFE_NO_PAD,
            ] {
                assert!(is_base64(&engine.encode(&data)), "length={length}");
            }
        }
    }

    #[test]
    fn compatibility_does_not_imply_encoded_or_executable_content() {
        assert!(is_base64("test")); // A word is compatible too.
        assert!(is_base64("AAAA")); // Binary NULs need not be UTF-8 code.
        assert!(!is_base64(&"=".repeat(100_000)));
        assert!(is_base64(&"AAAA".repeat(25_000)));
    }
}
