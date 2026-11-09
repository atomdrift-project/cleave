use super::*;
use std::path::PathBuf;

fn test_elf_path() -> PathBuf {
    PathBuf::from("tests/fixtures/test.elf")
}

/// End-to-end through filefacts: a direct `mprotect` site must arrive with
/// its *number* populated, not just its name. `number` was silently 0 for
/// every syscall until the producer emitted it, which made any rule
/// filtering on `number:` match nothing at all.
#[test]
fn direct_syscall_projection_carries_number_and_args() {
    use std::io::Write;

    // mov edx, 7 (PROT_READ|WRITE|EXEC); mov eax, 10 (mprotect); syscall
    let code = [
        0xBA, 0x07, 0x00, 0x00, 0x00, 0xB8, 0x0A, 0x00, 0x00, 0x00, 0x0F, 0x05,
    ];
    // Minimal ELF64 LE with one executable PROGBITS section holding `code`.
    const EH: usize = 64;
    const SH: usize = 64;
    let shtab = EH + code.len();
    let mut buf = vec![0u8; shtab + 2 * SH];
    buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT
    buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    // Entry point at the code's address seeds recovery; with no symbols,
    // no PLT and no unwind info it is the only thing that marks the section
    // start as a function to walk.
    buf[24..32].copy_from_slice(&(EH as u64).to_le_bytes()); // e_entry == code vaddr
    buf[40..48].copy_from_slice(&(shtab as u64).to_le_bytes()); // e_shoff
    buf[52..54].copy_from_slice(&(EH as u16).to_le_bytes()); // e_ehsize
    buf[58..60].copy_from_slice(&(SH as u16).to_le_bytes()); // e_shentsize
    buf[60..62].copy_from_slice(&2u16.to_le_bytes()); // e_shnum
    buf[EH..EH + code.len()].copy_from_slice(&code);
    let sh = shtab + SH; // [0] is the mandatory null header
    buf[sh + 4..sh + 8].copy_from_slice(&1u32.to_le_bytes()); // SHT_PROGBITS
    // SHF_ALLOC | SHF_EXECINSTR: ALLOC makes it a loadable segment recovery
    // reads, EXECINSTR marks it as code.
    buf[sh + 8..sh + 16].copy_from_slice(&0x6u64.to_le_bytes());
    // sh_addr == sh_offset, so a site's virtual address equals its file
    // offset and the `address == 74` assertion still pins the file offset.
    buf[sh + 16..sh + 24].copy_from_slice(&(EH as u64).to_le_bytes()); // sh_addr
    buf[sh + 24..sh + 32].copy_from_slice(&(EH as u64).to_le_bytes()); // sh_offset
    buf[sh + 32..sh + 40].copy_from_slice(&(code.len() as u64).to_le_bytes()); // sh_size

    let mut f = tempfile::Builder::new()
        .suffix(".elf")
        .tempfile()
        .expect("temp file");
    f.write_all(&buf).expect("write synthetic ELF");
    f.flush().expect("flush");

    let report = ElfAnalyzer::new().analyze(f.path()).expect("analyze");
    let sc = report
        .syscalls
        .iter()
        .find(|s| s.name == "mprotect")
        .expect("the direct mprotect site must be projected");
    assert_eq!(sc.number, 10, "number must survive into SyscallInfo");
    assert_eq!(sc.arch, "x86_64");
    assert_eq!(sc.args.get(2), Some(&Some(7)), "prot arg carries PROT_RWX");
    // Section starts at file offset 64, `0F 05` is 10 bytes in. Must be the
    // absolute file offset — a section-relative 10 would anchor findings to
    // the wrong bytes.
    assert_eq!(sc.address, 74, "address must be a file offset");
}

#[test]
fn test_analyze_elf_file() {
    let analyzer = ElfAnalyzer::new();
    let test_file = test_elf_path();

    let result = analyzer.analyze(&test_file);
    assert!(result.is_ok());

    let report = result.unwrap();
    assert_eq!(report.target.file_type, "elf");
    assert!(report.target.size_bytes > 0);
    assert!(!report.target.sha256.is_empty());
}

/// The analyzer records how many strings it was offered and kept, so a
/// rule or reviewer can tell when text matchers searched only part of a
/// binary. Checks the wiring, not the cap (the fixture is small).
#[test]
fn test_elf_records_string_count_metrics() {
    let test_file = test_elf_path();
    let report = ElfAnalyzer::new().analyze(&test_file).unwrap();
    let m = report
        .filefacts_metrics
        .as_ref()
        .expect("ELF report carries metrics");
    let extracted = m
        .get("strings.extracted_count")
        .copied()
        .expect("extracted_count");
    let retained = m
        .get("strings.retained_count")
        .copied()
        .expect("retained_count");
    assert!(extracted > 0.0, "fixture has strings");
    assert!(
        retained >= extracted,
        "no cap on a small fixture (sidecars may add)"
    );
    assert_eq!(m.get("strings.truncated").copied(), Some(0.0));
}

#[test]
fn test_elf_architecture_detected() {
    let analyzer = ElfAnalyzer::new();
    let test_file = test_elf_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(report.target.architectures.is_some());
    let archs = report.target.architectures.unwrap();
    assert!(!archs.is_empty());
}

#[test]
fn test_elf_sections_analyzed() {
    let analyzer = ElfAnalyzer::new();
    let test_file = test_elf_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(!report.sections.is_empty());
}

#[test]
fn test_elf_has_imports() {
    let analyzer = ElfAnalyzer::new();
    let test_file = test_elf_path();

    let report = analyzer.analyze(&test_file).unwrap();
    // Most ELF binaries have dynamic imports
    assert!(!report.imports.is_empty());
}

#[test]
fn test_elf_capabilities_detected() {
    let analyzer = ElfAnalyzer::new();
    let test_file = test_elf_path();

    let report = analyzer.analyze(&test_file).unwrap();
    // Capabilities may or may not be detected depending on the binary
    // Just verify the analysis completes successfully
    let _ = &report.traits;
}

#[test]
fn test_elf_strings_extracted() {
    let analyzer = ElfAnalyzer::new();
    let test_file = test_elf_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(!report.strings.is_empty());
}

#[test]
fn test_elf_tools_used() {
    let analyzer = ElfAnalyzer::new();
    let test_file = test_elf_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(
        report
            .metadata
            .tools_used
            .contains(&"filefacts".to_string())
    );
}

#[test]
fn test_elf_analysis_duration() {
    let analyzer = ElfAnalyzer::new();
    let test_file = test_elf_path();

    let report = analyzer.analyze(&test_file).unwrap();
    // Duration can vary substantially on loaded CI hosts.
    // Keep this as a sanity bound, not a performance benchmark.
    assert!(report.metadata.analysis_duration_ms < 60000);
}

// =========================================================================
// UPX Integration Tests
// =========================================================================

#[test]
fn test_upx_detection_in_data() {
    // Data with UPX magic
    let upx_data = b"\x7fELF\x00\x00\x00\x00UPX!\x00\x00";
    assert!(unpack::upx::is_packed(upx_data));

    // Data without UPX magic
    let normal_data = b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    assert!(!unpack::upx::is_packed(normal_data));
}

#[test]
fn test_upx_packed_creates_finding() {
    let analyzer = ElfAnalyzer::new();

    // Create minimal UPX-packed ELF-like data (won't actually decompress)
    let mut upx_data = vec![0u8; 256];
    // ELF magic
    upx_data[0..4].copy_from_slice(b"\x7fELF");
    // UPX magic
    upx_data[100..104].copy_from_slice(b"UPX!");

    assert!(unpack::upx::is_packed(&upx_data));

    // Use a temp file for the analysis
    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), &upx_data).unwrap();

    let report = analyzer.analyze_structural(temp_file.path(), &upx_data, None);

    // Should have UPX packer finding
    assert!(
        crate::upx::recorded(&report, "packed"),
        "Should have UPX packer finding"
    );
}

#[test]
fn test_upx_tool_missing_creates_finding() {
    // An engine with UPX off reports the unpacked image as not analyzed,
    // exactly as when the tool is missing.
    let analyzer = ElfAnalyzer::new().with_engine(crate::Engine::empty().with_settings(
        crate::engine::Settings {
            upx: false,
            ..Default::default()
        },
    ));

    // Create minimal UPX-packed ELF-like data
    let mut upx_data = vec![0u8; 256];
    upx_data[0..4].copy_from_slice(b"\x7fELF");
    upx_data[100..104].copy_from_slice(b"UPX!");

    assert!(unpack::upx::is_packed(&upx_data));

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), &upx_data).unwrap();

    let report = analyzer.analyze_structural(temp_file.path(), &upx_data, None);

    // Should have both UPX finding and tool-missing finding
    assert!(
        crate::upx::recorded(&report, "packed"),
        "Should have UPX packer finding"
    );
    assert!(
        crate::upx::recorded(&report, "tool_missing"),
        "Should have tool-missing finding when UPX is disabled"
    );

    // Should NOT have unpacked file analysis (since tool is missing)
    assert!(
        report.files.is_empty(),
        "Should not have unpacked FileAnalysis when tool is missing"
    );
}

#[test]
fn test_non_upx_data_no_upx_finding() {
    let analyzer = ElfAnalyzer::new();

    // Create minimal ELF-like data without UPX magic
    let mut elf_data = vec![0u8; 256];
    elf_data[0..4].copy_from_slice(b"\x7fELF");
    elf_data[4] = 2; // 64-bit
    elf_data[5] = 1; // little-endian

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), &elf_data).unwrap();

    let report = analyzer.analyze_structural(temp_file.path(), &elf_data, None);

    // Should NOT have UPX packer finding
    assert!(
        !crate::upx::recorded(&report, "packed"),
        "Should not have UPX finding for non-UPX binary"
    );

    // Should NOT have unpacked file analysis
    assert!(
        report.files.is_empty(),
        "Should not have unpacked FileAnalysis for non-UPX binary"
    );
}

#[test]
fn test_upx_path_encoding_format() {
    use crate::types::file_analysis::encode_upx_path;

    // Test basic path encoding
    assert_eq!(
        encode_upx_path("/path/to/file.elf"),
        "/path/to/file.elf!!upx@0"
    );

    // Test path with special characters
    assert_eq!(
        encode_upx_path("/tmp/test-file_v1.2.elf"),
        "/tmp/test-file_v1.2.elf!!upx@0"
    );

    // Test path that already has archive delimiter
    assert_eq!(
        encode_upx_path("archive.zip!!inner.elf"),
        "archive.zip!!inner.elf!!upx@0"
    );
}

#[test]
fn test_upx_file_analysis_fields() {
    use crate::types::file_analysis::{FileAnalysis, encode_upx_path};

    // Create a FileAnalysis as if from UPX unpacking
    let parent_path = "/test/sample.elf";
    let virtual_path = encode_upx_path(parent_path);

    let mut file = FileAnalysis::new(
        1, // id (unpacked is typically id=1)
        virtual_path.clone(),
        "elf".to_string(),
        "abc123def456".to_string(),
        1000,
    );
    file.parent_id = Some(0);
    file.depth = 1;
    file.encoding = Some(vec!["upx".to_string()]);
    file.compute_summary();

    // Verify all UPX-specific fields
    assert_eq!(file.id, 1);
    assert_eq!(file.path, "/test/sample.elf!!upx@0");
    assert_eq!(file.parent_id, Some(0));
    assert_eq!(file.depth, 1);
    assert_eq!(file.encoding, Some(vec!["upx".to_string()]));
    assert_eq!(file.file_type, "elf");
}

#[test]
fn test_upx_tampered_magic_detection() {
    // Test tampered UPX magic variants (APX!, BPX!, etc.)
    let mut data_apx = vec![0u8; 256];
    data_apx[100..104].copy_from_slice(b"APX!");
    assert!(
        unpack::upx::is_packed(&data_apx),
        "Should detect APX! (tampered UPX)"
    );

    let mut data_bpx = vec![0u8; 256];
    data_bpx[100..104].copy_from_slice(b"BPX!");
    assert!(
        unpack::upx::is_packed(&data_bpx),
        "Should detect BPX! (tampered UPX)"
    );

    let mut data_zpx = vec![0u8; 256];
    data_zpx[100..104].copy_from_slice(b"ZPX!");
    assert!(
        unpack::upx::is_packed(&data_zpx),
        "Should detect ZPX! (tampered UPX)"
    );

    // lowercase should NOT match
    let mut data_lowercase = vec![0u8; 256];
    data_lowercase[100..104].copy_from_slice(b"upx!");
    assert!(
        !unpack::upx::is_packed(&data_lowercase),
        "Should not detect lowercase upx!"
    );
}
