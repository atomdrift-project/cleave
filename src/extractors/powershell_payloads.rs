//! Bounded reconstruction of literal PowerShell payload containers.
//! No script functions are executed. AES candidates require explicit CBC and
//! PKCS7 usage, valid padding and a recognized source/binary result. Candidate
//! relationships are hypotheses, not claims that the program executed them.
use crate::{
    analyzers::{FileType, detect_file_type_from_data},
    types::ExtractedPayload,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use regex::Regex;
use std::{path::Path, sync::LazyLock};

const MAX_SOURCE: usize = 24 * 1024 * 1024;
const MAX_BYTES: usize = 10 * 1024 * 1024;
const MAX_RESULTS: usize = 8;

static LITERALS: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(
    r#"(?m)^\s*\$[A-Za-z_][\w:]*\s*=\s*(?:'([^'\r\n]*)'|"([^"\r\n]*)"|@'\r?\n([\s\S]*?)\r?\n'@|@"\r?\n([\s\S]*?)\r?\n"@)"#
).ok()
});
static BYTE_ARRAY: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r"(?i)\[\s*byte\s*\[\s*\]\s*\]\s*\$[A-Za-z_]\w*\s*=\s*@?\(\s*([0-9,\s]{512,})\s*\)")
        .ok()
});

fn base64_bytes(value: &str) -> Option<Vec<u8>> {
    if value.len() > MAX_SOURCE {
        return None;
    }
    let clean: Vec<u8> = value.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if clean.len() > MAX_BYTES * 4 / 3 + 4 {
        return None;
    }
    STANDARD
        .decode(&clean)
        .or_else(|_| URL_SAFE_NO_PAD.decode(&clean))
        .ok()
}

fn valid_pe(bytes: &[u8]) -> bool {
    bytes.len() >= 256
        && bytes.starts_with(b"MZ")
        && detect_file_type_from_data(Path::new("decoded.bin"), bytes) == FileType::Pe
}

fn push(
    out: &mut Vec<ExtractedPayload>,
    data: Vec<u8>,
    chain: &[&str],
    offset: usize,
    pe_only: bool,
) {
    if data.len() > MAX_BYTES || out.len() >= MAX_RESULTS || out.iter().any(|p| p.data == data) {
        return;
    }
    let file_type = if valid_pe(&data) {
        FileType::Pe
    } else {
        if pe_only || std::str::from_utf8(&data).is_err() {
            return;
        }
        let ft = detect_file_type_from_data(Path::new("decoded"), &data);
        if !ft.is_source_code() {
            return;
        }
        ft
    };
    out.push(ExtractedPayload {
        data,
        encoding_chain: chain.iter().map(|s| (*s).to_string()).collect(),
        preview: String::new(),
        detected_type: file_type,
        original_offset: offset,
    });
}

pub(crate) fn extract(content: &[u8]) -> Vec<ExtractedPayload> {
    let mut out = Vec::new();
    if content.len() > MAX_SOURCE {
        return out;
    }
    let Ok(source) = std::str::from_utf8(content) else {
        return out;
    };
    let lower = source.to_ascii_lowercase();
    // A typed decimal byte array can contain a complete native or managed PE.
    if lower.contains("byte")
        && let Some(re) = BYTE_ARRAY.as_ref()
    {
        for c in re.captures_iter(source).take(MAX_RESULTS) {
            let Some(m) = c.get(1) else {
                continue;
            };
            let data = m
                .as_str()
                .split(',')
                .map(|s| s.trim().parse::<u8>().ok())
                .collect::<Option<Vec<_>>>();
            if let Some(data) = data {
                push(&mut out, data, &["decimal-byte-array"], m.start(), true);
            }
        }
    }
    let aes = lower.contains("security.cryptography.aes")
        && lower.contains("ciphermode]::cbc")
        && lower.contains("paddingmode]::pkcs7")
        && lower.contains("createdecryptor");
    let xor = lower.contains("-bxor") && lower.contains("frombase64string") && lower.contains('%');
    if !aes && !xor {
        return out;
    }
    let Some(re) = LITERALS.as_ref() else {
        return out;
    };
    let literals: Vec<_> = re
        .captures_iter(source)
        .take(64)
        .filter_map(|c| {
            let m = (1..=4).find_map(|i| c.get(i))?;
            // Interpolated double-quoted values are not constants.
            if (c.get(2).is_some() || c.get(4).is_some())
                && (m.as_str().contains('$') || m.as_str().contains('`'))
            {
                return None;
            }
            Some((m.as_str(), m.start()))
        })
        .collect();
    let decoded: Vec<_> = literals
        .iter()
        .filter_map(|(s, o)| base64_bytes(s).map(|b| (b, *o)))
        .collect();
    let mut work = 128 * 1024 * 1024usize;
    if aes {
        let keys: Vec<_> = decoded
            .iter()
            .filter(|(b, _)| matches!(b.len(), 16 | 32))
            .take(8)
            .collect();
        let ivs: Vec<_> = decoded
            .iter()
            .filter(|(b, _)| b.len() == 16)
            .take(8)
            .collect();
        for (cipher, offset) in decoded
            .iter()
            .filter(|(b, _)| b.len() >= 64 && b.len().is_multiple_of(16))
            .take(8)
        {
            for (key, _) in &keys {
                for (iv, _) in &ivs {
                    let Some(remaining) = work.checked_sub(cipher.len()) else {
                        return out;
                    };
                    work = remaining;
                    let plain = if key.len() == 32 {
                        super::aes_payload::decrypt_aes_256_cbc(cipher, key, iv)
                    } else {
                        super::aes_payload::decrypt_aes_128_cbc(cipher, key, iv)
                    };
                    if let Some(plain) = plain {
                        push(&mut out, plain, &["base64", "aes-cbc"], *offset, false);
                    }
                }
            }
        }
    }
    if xor {
        let keys: Vec<_> = literals
            .iter()
            .filter(|(s, _)| !s.is_empty() && s.len() <= 64 && s.is_ascii())
            .take(16)
            .collect();
        for (cipher, offset) in decoded.iter().filter(|(b, _)| b.len() >= 256).take(8) {
            for (key, _) in &keys {
                let Some(remaining) = work.checked_sub(cipher.len()) else {
                    return out;
                };
                work = remaining;
                let plain: Vec<u8> = cipher
                    .iter()
                    .enumerate()
                    .map(|(i, b)| b ^ key.as_bytes()[i % key.len()])
                    .collect();
                if valid_pe(&plain) {
                    push(&mut out, plain, &["base64", "xor"], *offset, true);
                } else if let Ok(text) = std::str::from_utf8(&plain)
                    && let Some(pe) = base64_bytes(text)
                {
                    push(&mut out, pe, &["base64", "xor", "base64"], *offset, true);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};

    fn pe() -> Vec<u8> {
        let mut b = vec![0u8; 1024];
        b[..2].copy_from_slice(b"MZ");
        b[60..64].copy_from_slice(&128u32.to_le_bytes());
        b[128..132].copy_from_slice(b"PE\0\0");
        b[132..134].copy_from_slice(&0x14cu16.to_le_bytes());
        b[148..150].copy_from_slice(&224u16.to_le_bytes());
        b[152..154].copy_from_slice(&0x10bu16.to_le_bytes());
        b
    }

    #[test]
    fn decimal_pe_requires_byte_range_and_complete_header() {
        let bytes = pe();
        assert!(valid_pe(&bytes));
        let numbers = bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let code = format!("[Byte[]]$renamed = ({numbers})");
        assert_eq!(extract(code.as_bytes())[0].data, bytes);
        assert!(extract(code.replace("77,90", "999,90").as_bytes()).is_empty());
        assert!(extract(code.replace("77,90", "77,91").as_bytes()).is_empty());
    }

    #[test]
    fn xor_rekeys_and_renames_without_executing_functions() {
        for key in ["different-key", "second_key!"] {
            let text = STANDARD.encode(pe());
            let bytes: Vec<_> = text
                .bytes()
                .enumerate()
                .map(|(i, b)| b ^ key.as_bytes()[i % key.len()])
                .collect();
            let code = format!(
                "$seed = '{key}'\n$blob = '{}'\n[Convert]::FromBase64String($blob); $output[$i] = $raw[$i] -bxor $key[$i % $key.Length]",
                STANDARD.encode(bytes)
            );
            let out = extract(code.as_bytes());
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].data, pe());
            assert!(extract(code.replace("-bxor", "-bor").as_bytes()).is_empty());
        }
    }

    #[test]
    fn aes_accepts_multiline_and_rejects_wrong_key_mode_and_interpolation() {
        let plain=b"$ErrorActionPreference = 'Stop'\nWrite-Host 'decoded constant script'\nNew-Object IO.MemoryStream\n";
        let key = [37u8; 32];
        let iv = [59u8; 16];
        let encrypted = cbc::Encryptor::<aes::Aes256>::new(&key.into(), &iv.into())
            .encrypt_padded_vec::<Pkcs7>(plain);
        let code = format!(
            "$one = @'\r\n{}\r\n'@\r\n$two = '{}'\n$three = '{}'\n$a=[System.Security.Cryptography.Aes]::Create(); $a.Mode=[Security.Cryptography.CipherMode]::CBC; $a.Padding=[Security.Cryptography.PaddingMode]::PKCS7; $a.CreateDecryptor()",
            STANDARD.encode(encrypted),
            STANDARD.encode(key),
            STANDARD.encode(iv)
        );
        let out = extract(code.as_bytes());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].data, plain);
        assert_eq!(out[0].detected_type, FileType::PowerShell);
        assert!(extract(code.replace("::CBC", "::ECB").as_bytes()).is_empty());
        assert!(
            extract(
                code.replace(&STANDARD.encode(key), &STANDARD.encode([4u8; 32]))
                    .as_bytes()
            )
            .is_empty()
        );
        assert!(
            extract(
                code.replace(
                    &format!("'{}'", STANDARD.encode(key)),
                    &format!("\"${}\"", STANDARD.encode(key))
                )
                .as_bytes()
            )
            .is_empty()
        );
    }
}
