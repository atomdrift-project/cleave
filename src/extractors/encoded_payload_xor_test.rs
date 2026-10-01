//! Bounded binary recovery and conservative nested-decoding regressions.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::super::*;
use sha2::{Digest, Sha256};
use stng::{ExtractedString, StringKind, StringMethod};
const FILE: &[u8] = include_bytes!("../../testdata/xor/xor_fat_dropper.macho");
const OFFSET: usize = 0x6210;
const LEN: usize = 153824;
fn key(offset: u64) -> ExtractedString {
    ExtractedString {
        value: "0x9c".into(),
        data_offset: offset,
        method: StringMethod::XorDecode,
        kind: Some(StringKind::XorKey),
        ..Default::default()
    }
}
#[test]
fn specimen_pipeline_recovers_complete_binary_and_provenance() {
    assert_eq!(
        hex::encode(Sha256::digest(FILE)),
        "30c99015f9c432604d8a8206ce8dcb4fba7866b062e5bd1a8f0adb88fba8807c"
    );
    let opts = stng::ExtractOptions {
        use_cache: false,
        caller_provides_symbols: true,
        filter_garbage: true,
        ..Default::default()
    };
    let strings = stng::extract_strings_with_options(FILE, &opts);
    let out = xor_encoded_machos(FILE, &strings);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].original_offset, OFFSET);
    assert_eq!(out[0].encoding_chain, ["xor"]);
    assert_eq!(out[0].detected_type, FileType::MachO);
    assert_eq!(out[0].data.len(), LEN);
    assert_eq!(
        hex::encode(Sha256::digest(&out[0].data)),
        "5f522222dd8c3237058f7b7b00e717d1365f14aea6f45e41c9f982dd866cb8c0"
    );
}
#[test]
fn only_located_valid_xor_key_observations_trigger_recovery() {
    assert!(xor_encoded_machos(FILE, &[]).is_empty());
    for value in ["0x00", "0x9d", "0xzz", "9c", "0x09c", "xxxx"] {
        let mut k = key(OFFSET as u64);
        k.value = value.into();
        assert!(xor_encoded_machos(FILE, &[k]).is_empty(), "{value}");
    }
    for offset in [0, OFFSET as u64 - 1, FILE.len() as u64, u64::MAX] {
        assert!(xor_encoded_machos(FILE, &[key(offset)]).is_empty());
    }
    let mut k = key(OFFSET as u64);
    k.kind = None;
    assert!(xor_encoded_machos(FILE, &[k]).is_empty());
    let mut k = key(OFFSET as u64);
    k.method = StringMethod::RawScan;
    assert!(xor_encoded_machos(FILE, &[k]).is_empty());
    assert!(xor_encoded_machos(&FILE[..OFFSET + LEN - 1], &[key(OFFSET as u64)]).is_empty());
}
#[test]
fn duplicate_offsets_are_emitted_once_and_attempts_are_bounded() {
    let good = key(OFFSET as u64);
    assert_eq!(xor_encoded_machos(FILE, &vec![good.clone(); 8]).len(), 1);
    let mut bad = key(u64::MAX);
    let mut keys = vec![bad.clone(); 7];
    keys.push(good.clone());
    assert_eq!(xor_encoded_machos(FILE, &keys).len(), 1);
    keys.insert(0, bad.clone());
    assert!(xor_encoded_machos(FILE, &keys).is_empty());
    // Ordinary strings do not consume the binary-candidate budget.
    bad.kind = None;
    let mut keys = vec![bad; 100];
    keys.push(good);
    assert_eq!(xor_encoded_machos(FILE, &keys).len(), 1);
}
#[test]
fn retained_output_never_exceeds_32_mib() {
    let mut p: Vec<u8> = FILE[OFFSET..OFFSET + LEN]
        .iter()
        .map(|b| b ^ 0x9c)
        .collect();
    // Enlarge the last slice's trailing extent without changing its load commands.
    let size = 5 * 1024 * 1024;
    p.resize(size, 0);
    p[40..44].copy_from_slice(&((size - 81920) as u32).to_be_bytes());
    let encoded: Vec<u8> = p.iter().map(|b| b ^ 0x9c).collect();
    assert!(stng::decode_xor_fat_macho(&encoded, 0x9c).is_some());
    let mut bytes = Vec::new();
    let mut keys = Vec::new();
    for _ in 0..8 {
        keys.push(key(bytes.len() as u64));
        bytes.extend_from_slice(&encoded);
    }
    let out = xor_encoded_machos(&bytes, &keys);
    assert_eq!(out.len(), 6);
    assert_eq!(
        out.iter().map(|p| p.data.len()).sum::<usize>(),
        30 * 1024 * 1024
    );
}
#[test]
fn opaque_identifier_text_is_not_guessed_as_another_encoding_layer() {
    for text in [
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "9fcdee1a5c39dd46bfcbfbe0658f092752c2de57e15301ff5f1d8bdbe125e981",
    ] {
        let chain = vec!["xor".into()];
        assert_eq!(
            decompress_and_nest(text.as_bytes(), chain.clone(), 0),
            (text.as_bytes().to_vec(), chain)
        );
    }
}
#[test]
fn readable_and_recognized_binary_layers_are_still_decoded() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let text = "Readable Unicode café text\nwith tabs\tand line endings\r\n";
    let encoded = STANDARD.encode(text);
    let (bytes, chain) = decompress_and_nest(encoded.as_bytes(), vec!["xor".into()], 0);
    assert_eq!(bytes, text.as_bytes());
    assert_eq!(chain, ["xor", "base64"]);
    let image: Vec<u8> = FILE[OFFSET..OFFSET + LEN]
        .iter()
        .map(|b| b ^ 0x9c)
        .collect();
    let encoded = STANDARD.encode(&image);
    let (bytes, chain) = decompress_and_nest(encoded.as_bytes(), vec!["xor".into()], 0);
    assert_eq!(bytes, image);
    assert_eq!(chain, ["xor", "base64"]);
    let hex: String = text.bytes().map(|b| format!("{b:02x}")).collect();
    let (bytes, chain) = decompress_and_nest(hex.as_bytes(), vec!["xor".into()], 0);
    assert_eq!(bytes, text.as_bytes());
    assert_eq!(chain, ["xor", "hex"]);
}
#[test]
fn nested_depth_limit_and_invalid_control_text_are_preserved() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    assert!(!supports_nested_encoding(&[]));
    assert!(!supports_nested_encoding(
        b"unrecognized\x01opaque\x00bytes"
    ));
    let original = b"ordinary decoded script text with a few words";
    let encoded = STANDARD.encode(original);
    let chain = vec!["xor".into()];
    assert_eq!(
        decompress_and_nest(encoded.as_bytes(), chain.clone(), 3),
        (encoded.into_bytes(), chain)
    );
}
