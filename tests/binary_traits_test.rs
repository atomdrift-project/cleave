//! Smoke tests for binary trait detection across synthetic ELF fixtures.
//!
//! These tests previously ran the `cleave` binary 12 times in separate
//! subprocesses with no real assertions — only `eprintln!` reporting of
//! whatever traits happened to fire. That cost ~25-50s per test for
//! near-zero validation value.
//!
//! The combined test below runs the same fixtures in-process so they share
//! a single CapabilityMapper init, dropping the per-test cost by ~10x.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use tempfile::TempDir;

fn options() -> cleave::AnalysisOptions {
    cleave::AnalysisOptions {
        disable_yara: true,
        ..Default::default()
    }
}

/// Build a path under `dir` containing `bytes`, then analyze it in-process.
/// Returns the analysis report — assertions are the caller's responsibility.
fn analyze(dir: &std::path::Path, name: &str, bytes: &[u8]) -> cleave::AnalysisReport {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    cleave::analyze_file(&path, &options()).expect("analyze should not fail")
}

/// Smoke test: every synthetic fixture below must be analyzable without
/// panic. Specific trait-firing expectations are intentionally lax — the
/// installed rule set evolves and these inputs are too minimal to demand
/// stable findings. The MIPS-detection assertion lives in its own
/// `#[ignore]`-d test to preserve intent; everything else is "did cleave
/// crash or hang."
#[test]
fn binary_trait_detection_smoke() {
    let tmp = TempDir::new().unwrap();

    // ELF64 LE with /dev/null marker
    let mut daemon = vec![
        0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    daemon.extend_from_slice(b"/dev/null\x00");
    daemon.resize(256, 0);
    let _ = analyze(tmp.path(), "daemon.elf", &daemon);

    // ELF64 LE with HTTP protocol strings
    let mut http = vec![
        0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    http.extend_from_slice(b"GET /path HTTP/1.1\r\n\x00");
    http.extend_from_slice(b"User-Agent: Mozilla\x00");
    http.resize(512, 0);
    let _ = analyze(tmp.path(), "http.elf", &http);

    // ELF64 LE with hex-charset strings (cipher heuristic)
    let mut hex = vec![
        0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    hex.extend_from_slice(b"0123456789abcdef0123456789abcdef\x00");
    hex.resize(512, 0);
    let _ = analyze(tmp.path(), "hex.elf", &hex);

    // ELF32 BE with PowerPC e_machine
    let ppc = vec![
        0x7f, b'E', b'L', b'F', 0x01, 0x02, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x02, 0x00,
        0x14, 0x00, 0x00, 0x00, 0x01,
    ];
    let _ = analyze(tmp.path(), "ppc.elf", &ppc);

    // ELF32 LE with ARM e_machine
    let arm32 = vec![
        0x7f, b'E', b'L', b'F', 0x01, 0x01, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x00, 0x28,
        0x00, 0x01, 0x00, 0x00, 0x00,
    ];
    let _ = analyze(tmp.path(), "arm32.elf", &arm32);

    // ELF32 BE with MIPS e_machine
    let mips = vec![
        0x7f, b'E', b'L', b'F', 0x01, 0x02, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x02, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x01,
    ];
    let _ = analyze(tmp.path(), "mips.elf", &mips);

    // ELF32 BE — generic big-endian
    let be = vec![
        0x7f, b'E', b'L', b'F', 0x01, 0x02, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let _ = analyze(tmp.path(), "big_endian.elf", &be);

    // Combined daemon composite — multiple persistence markers
    let mut full_daemon = vec![
        0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    full_daemon.extend_from_slice(b"/dev/null\x00");
    full_daemon.extend_from_slice(b"fork\x00");
    full_daemon.extend_from_slice(b"setsid\x00");
    full_daemon.extend_from_slice(b"/proc/self\x00");
    full_daemon.resize(512, 0);
    let _ = analyze(tmp.path(), "full_daemon.elf", &full_daemon);

    // HTTP composite — protocol + headers
    let mut http_client = vec![
        0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    http_client.extend_from_slice(b"GET /path HTTP/1.1\r\n\x00");
    http_client.extend_from_slice(b"User-Agent: Mozilla\x00");
    http_client.extend_from_slice(b"Content-Type: text/html\x00");
    http_client.resize(512, 0);
    let _ = analyze(tmp.path(), "http_client.elf", &http_client);

    // IoT-target composite — MIPS BE static
    let iot = vec![
        0x7f, b'E', b'L', b'F', 0x01, 0x02, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x02, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x01,
    ];
    let _ = analyze(tmp.path(), "iot_target.elf", &iot);

    // Generic static-binary marker
    let static_bin = vec![
        0x7f, b'E', b'L', b'F', 0x02, 0x01, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let _ = analyze(tmp.path(), "static.elf", &static_bin);
}

/// Real assertion: MIPS ELF should fire an exotic-arch trait. Currently
/// gated on the experimental binary-condition trait definitions.
#[test]
#[ignore = "Depends on binary.yaml.disabled which has experimental binary condition types"]
fn test_exotic_arch_mips_trait() {
    let tmp = TempDir::new().unwrap();
    let mips = vec![
        0x7f, b'E', b'L', b'F', 0x01, 0x02, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x02, 0x00,
        0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34, 0x00, 0x20, 0x00, 0x01, 0x00, 0x28, 0x00,
        0x00, 0x00, 0x00,
    ];
    let report = analyze(tmp.path(), "mips.elf", &mips);

    let arch_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.id.contains("exotic-arch") || f.id.contains("mips"))
        .collect();
    assert!(
        !arch_findings.is_empty(),
        "Should detect exotic-arch-mips trait for MIPS binary"
    );
}
