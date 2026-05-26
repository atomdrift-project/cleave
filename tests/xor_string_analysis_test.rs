//! Regression test: XOR-decoded strings must appear in report.strings.
//!
//! The main analysis pipeline pre-extracts strings with stng via
//! `analyzers::stng_analysis_opts()`. XOR scanning must be enabled in that
//! function, otherwise XOR-decoded strings won't be available for trait
//! matching (string_value conditions).
//!
//! Bug: lib.rs was constructing stng options without `.with_xor(None)`, so
//! binary analyzers received pre-extracted strings that lacked XOR decodes.
//! The `cleave strings` command worked because its fallback path had XOR
//! enabled, making the discrepancy hard to notice.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

/// Verify that the shared stng options enable XOR scanning.
///
/// All analysis code paths use `stng_analysis_opts()` to construct extraction
/// options. If XOR scanning is ever removed from that function, this test
/// catches it immediately.
#[test]
fn test_stng_analysis_opts_enables_xor() {
    let opts = cleave::analyzers::stng_analysis_opts(4);
    assert!(
        opts.xor_scan,
        "stng_analysis_opts must enable xor_scan — without it, XOR-decoded \
         strings won't appear in report.strings and string_value trait \
         conditions will miss encoded content"
    );
}

/// Verify that XOR-decoded strings from stng end up in analyze_file() output.
///
/// Creates a binary with single-byte XOR-encoded strings and confirms the
/// analysis report contains them with an "xor" encoding_chain entry.
#[test]
fn test_analyze_file_includes_xor_decoded_strings() {
    use cleave::{AnalysisOptions, analyze_file};
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let bin_path = temp_dir.path().join("xor_test.elf");

    // Build a minimal ELF with single-byte XOR-encoded strings.
    // Key 0x5A ('Z'); stng detects it from the repeated key bytes.
    let xor_key: u8 = 0x5A;
    let mut data = vec![
        0x7f, b'E', b'L', b'F', // ELF magic
        0x02, 0x01, 0x01, 0x00, // 64-bit, LE, v1, SysV
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    data.resize(128, 0x00);

    // Repeated key byte (stng uses this for auto-detection)
    data.extend_from_slice(&[xor_key; 32]);

    // XOR-encode several realistic strings
    let strings_to_encode = [
        "Library/Application Support/discord",
        "/usr/local/bin/curl --silent",
        "Library/Cookies/Cookies.binarycookies",
        "wallet.dat",
        "screenshot.png",
    ];
    for s in &strings_to_encode {
        let enc: Vec<u8> = s.bytes().map(|b| b ^ xor_key).collect();
        data.extend_from_slice(&enc);
        data.push(xor_key); // XOR'd null terminator (0x00 ^ key == key)
    }
    data.resize(data.len().max(4096), 0x00);

    fs::write(&bin_path, &data).unwrap();

    let options = AnalysisOptions {
        disable_yara: true,
        disable_radare2: true,
        disable_upx: true,
        ..Default::default()
    };

    let report = analyze_file(&bin_path, &options).expect("analyze_file should succeed");

    let xor_decoded: Vec<_> = report
        .strings
        .iter()
        .filter(|s| {
            s.encoding_chain
                .iter()
                .any(|enc| enc.contains("xor") || enc.contains("Xor"))
        })
        .collect();

    assert!(
        !xor_decoded.is_empty(),
        "analyze_file must include XOR-decoded strings in report.strings. \
         Found {} total strings, none with XOR encoding_chain. \
         This means the analysis pipeline is not passing XOR-decoded strings through.",
        report.strings.len()
    );
}
