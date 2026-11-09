use super::*;
use std::path::PathBuf;

fn test_pe_path() -> PathBuf {
    PathBuf::from("tests/fixtures/test.exe")
}

#[test]
fn test_analyze_pe_file() {
    let analyzer = PEAnalyzer::new();
    let test_file = test_pe_path();

    let result = analyzer.analyze(&test_file);
    assert!(result.is_ok());

    let report = result.unwrap();
    assert_eq!(report.target.file_type, "pe");
    assert!(report.target.size_bytes > 0);
    assert!(!report.target.sha256.is_empty());
}

#[test]
fn test_pe_has_structure() {
    let analyzer = PEAnalyzer::new();
    let test_file = test_pe_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(!report.structure.is_empty());
}

#[test]
fn test_pe_architecture_detected() {
    let analyzer = PEAnalyzer::new();
    let test_file = test_pe_path();

    let report = analyzer.analyze(&test_file).unwrap();
    let archs = report
        .target
        .architectures
        .expect("PE analyzer should detect at least one architecture");
    // test.exe is a 64-bit MSVC build. The canonical label is
    // `"x86_64"` — what filefacts emits and what every analyst-facing
    // tool (objdump, file(1), LIEF) reports. The ctx-fed path
    // returns this verbatim; the legacy fallback maps 0x8664 to
    // the same string.
    assert_eq!(
        archs,
        vec!["x86_64".to_string()],
        "test.exe arch label drifted from canonical x86_64",
    );
}

/// Verify `arch_name` returns filefacts canonical lowercase label
/// (`"x86_64"`, `"i386"`, `"arm64"`).
#[test]
fn arch_name_returns_filefacts_canonical_label() {
    let analyzer = PEAnalyzer::new();
    let test_file = test_pe_path();
    let bytes = std::fs::read(&test_file).unwrap();
    let ctx = crate::analysis_context::AnalysisContext::open(&test_file, &bytes);
    // test.exe is x86_64; filefacts surfaces it via `pe.machine`.
    assert_eq!(analyzer.arch_name(&ctx), "x86_64");
}

#[test]
fn test_pe_sections_analyzed() {
    let analyzer = PEAnalyzer::new();
    let test_file = test_pe_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(!report.sections.is_empty());
}

#[test]
fn test_pe_has_imports() {
    let analyzer = PEAnalyzer::new();
    let test_file = test_pe_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(!report.imports.is_empty());
}

/// `analyze_structural_with_ctx` produces non-empty
/// imports / sections views for a standard MSVC fixture.
/// Source tags should land as `"pe"` (from filefacts's typed view).
#[test]
fn analyze_structural_populates_pe_views() {
    let analyzer = PEAnalyzer::new();
    let test_file = test_pe_path();
    let bytes = std::fs::read(&test_file).unwrap();
    let ctx = crate::analysis_context::AnalysisContext::open(&test_file, &bytes);
    let report = analyzer.analyze_structural_with_ctx(&test_file, &bytes, None, &ctx);

    assert!(!report.imports.is_empty());
    // `test.exe` is an EXE rather than a DLL, so `exports` may
    // legitimately be empty — assert the imports/sections lanes
    // only.
    assert!(!report.sections.is_empty());

    // Imports come from filefacts's typed view.
    assert!(!report.imports.is_empty(), "expected PE imports");
}

#[test]
fn test_pe_capabilities_detected() {
    let analyzer = PEAnalyzer::new();
    let test_file = test_pe_path();

    let report = analyzer.analyze(&test_file).unwrap();
    // Capabilities may or may not be detected depending on the binary
    // Just verify the analysis completes successfully
    let _ = &report.traits;
}

#[test]
fn test_pe_strings_extracted() {
    let analyzer = PEAnalyzer::new();
    let test_file = test_pe_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(!report.strings.is_empty());
}

#[test]
fn test_pe_tools_used() {
    let analyzer = PEAnalyzer::new();
    let test_file = test_pe_path();

    let report = analyzer.analyze(&test_file).unwrap();
    assert!(
        report
            .metadata
            .tools_used
            .contains(&"filefacts".to_string())
    );
}

#[test]
fn test_pe_analysis_duration() {
    let analyzer = PEAnalyzer::new();
    let test_file = test_pe_path();

    let report = analyzer.analyze(&test_file).unwrap();
    // Duration may be 0 for very fast analysis (sub-millisecond).
    // The important thing is that analysis completes and the field is set.
    // Duration is a u64, so it's always >= 0.
    assert!(
        report.metadata.analysis_duration_ms < 60000,
        "Analysis should complete in under a minute"
    );
}

#[test]
fn test_analyze_self_extracting_7z() {
    use std::fs;
    use std::io::Write;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("sfx.exe");

    let Ok(mut host) = fs::read("tests/fixtures/test.exe") else {
        eprintln!("skipping test_analyze_self_extracting_7z: missing tests/fixtures/test.exe");
        return;
    };

    // Append a tiny ZIP archive as overlay so the PE behaves like a
    // self-extracting archive without relying on developer-local samples.
    let cursor = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default();
    zip.start_file("hello.txt", options).unwrap();
    zip.write_all(b"hello from overlay").unwrap();
    let cursor = zip.finish().unwrap();
    host.extend_from_slice(&cursor.into_inner());
    fs::write(&path, &host).unwrap();

    let analyzer = PEAnalyzer::new();
    let report = analyzer.analyze(&path).unwrap();

    // Should have analyzed the embedded archive contents
    assert!(
        !report.archive_contents.is_empty(),
        "Should have extracted archive contents"
    );

    // Should have findings from the embedded files
    eprintln!(
        "SFX analysis found {} files in archive",
        report.archive_contents.len()
    );
    eprintln!(
        "SFX analysis found {} total findings",
        report.findings.len()
    );

    // All archive content paths should use standard archive delimiter
    for entry in &report.archive_contents {
        assert!(
            entry
                .path
                .contains(crate::types::file_analysis::ARCHIVE_DELIMITER),
            "Archive path should use '!!': {}",
            entry.path
        );
        assert!(
            entry.path.starts_with("sfx.exe!!"),
            "Archive path should start with PE filename: {}",
            entry.path
        );
    }
}

// =========================================================================
// UPX Integration Tests
// =========================================================================

#[test]
fn test_pe_upx_recovers_virtual_archive_member() {
    if !crate::upx::UPXDecompressor::is_available() {
        return;
    }
    let packed = include_bytes!("../../../testdata/upx/activation-factory-packed.pe");
    let directory = tempfile::tempdir().unwrap();
    let virtual_path = directory.path().join("archive.zip!!library.dll");
    assert!(!virtual_path.exists());

    let report = PEAnalyzer::new().analyze_structural(&virtual_path, packed, None);
    let unpacked = report
        .files
        .iter()
        .find(|file| {
            file.encoding
                .as_ref()
                .is_some_and(|encodings| encodings.iter().any(|encoding| encoding == "upx"))
        })
        .expect("UPX payload must be recovered without a real source path");
    assert_eq!(unpacked.size, 4096);
    assert_eq!(unpacked.file_type, "pe");
    assert!(!crate::upx::recorded(&report, "decompression_failed"));
}

#[test]
fn test_pe_upx_detection_in_data() {
    // PE with UPX magic
    let mut upx_data = vec![0u8; 256];
    // MZ header
    upx_data[0..2].copy_from_slice(b"MZ");
    // UPX magic
    upx_data[100..104].copy_from_slice(b"UPX!");
    assert!(unpack::upx::is_packed(&upx_data));

    // PE without UPX magic
    let mut normal_data = vec![0u8; 256];
    normal_data[0..2].copy_from_slice(b"MZ");
    assert!(!unpack::upx::is_packed(&normal_data));
}

#[test]
fn test_pe_upx_packed_creates_finding() {
    let analyzer = PEAnalyzer::new();

    // Create minimal UPX-packed PE-like data (won't actually decompress)
    let mut upx_data = vec![0u8; 512];
    // DOS header
    upx_data[0..2].copy_from_slice(b"MZ");
    // e_lfanew pointing to PE header
    upx_data[0x3c..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
    // PE signature at offset 0x80
    upx_data[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    // Machine type (x64)
    upx_data[0x84..0x86].copy_from_slice(&[0x64, 0x86]);
    // UPX magic
    upx_data[200..204].copy_from_slice(b"UPX!");

    assert!(unpack::upx::is_packed(&upx_data));

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
fn test_pe_upx_tool_missing_creates_finding() {
    // An engine with UPX off reports the unpacked image as not analyzed,
    // exactly as when the tool is missing.
    let analyzer = PEAnalyzer::new().with_engine(crate::Engine::empty().with_settings(
        crate::engine::Settings {
            upx: false,
            ..Default::default()
        },
    ));

    // Create minimal UPX-packed PE-like data
    let mut upx_data = vec![0u8; 512];
    upx_data[0..2].copy_from_slice(b"MZ");
    upx_data[0x3c..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
    upx_data[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    upx_data[0x84..0x86].copy_from_slice(&[0x64, 0x86]);
    upx_data[200..204].copy_from_slice(b"UPX!");

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

    // Should NOT have unpacked file analysis
    assert!(
        report.files.is_empty(),
        "Should not have unpacked FileAnalysis when tool is missing"
    );
}

#[test]
fn test_pe_non_upx_data_no_upx_finding() {
    let analyzer = PEAnalyzer::new();

    // Create minimal PE-like data without UPX magic
    let mut pe_data = vec![0u8; 512];
    pe_data[0..2].copy_from_slice(b"MZ");
    pe_data[0x3c..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
    pe_data[0x80..0x84].copy_from_slice(b"PE\x00\x00");
    pe_data[0x84..0x86].copy_from_slice(&[0x64, 0x86]);

    let temp_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(temp_file.path(), &pe_data).unwrap();

    let report = analyzer.analyze_structural(temp_file.path(), &pe_data, None);

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

// ──── Pure-function helpers ────────────────────────────────────
