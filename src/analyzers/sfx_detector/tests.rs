use super::*;

fn posix_nuitka_bundle(entries: &[(&str, &[u8], u8)]) -> std::io::Result<Vec<u8>> {
    let mut records = Vec::new();
    for (name, content, flag) in entries {
        records.extend_from_slice(name.as_bytes());
        records.push(0);
        records.push(*flag);
        records.extend_from_slice(&(content.len() as u64).to_le_bytes());
        records.extend_from_slice(&crc32fast::hash(content).max(1).to_le_bytes());
        records.extend_from_slice(content);
    }
    records.push(0);
    let mut host = b"\xcf\xfa\xed\xfeNUITKA_ONEFILE_PARENT\0KAY".to_vec();
    host.extend(zstd::stream::encode_all(records.as_slice(), 1)?);
    host.extend_from_slice(b"host trailer");
    Ok(host)
}

fn extract_posix_test(data: &[u8], out: &Path) -> std::io::Result<()> {
    let offset = memmem::find(data, NUITKA_COMPRESSED)
        .ok_or_else(|| std::io::Error::other("missing marker"))?;
    extract_nuitka_posix_cached_at(data, offset, out)
}

#[test]
fn nuitka_posix_cached_extracts_regular_members() -> std::io::Result<()> {
    let data = posix_nuitka_bundle(&[("main", b"code", 1), ("lib/caf\u{e9}.txt", b"text", 0)])?;
    assert_eq!(detect_sfx(&data, &[]), Some(SfxKind::Nuitka));
    let out = tempfile::tempdir()?;
    extract_posix_test(&data, out.path())?;
    assert_eq!(std::fs::read(out.path().join("main"))?, b"code");
    assert_eq!(
        std::fs::read(out.path().join("lib/caf\u{e9}.txt"))?,
        b"text"
    );
    Ok(())
}

#[test]
fn nuitka_posix_cached_rejects_unsafe_or_corrupt_records() -> std::io::Result<()> {
    for name in [
        "../escape",
        "/absolute",
        "a/../escape",
        "C:\\escape",
        "a//b",
    ] {
        let out = tempfile::tempdir()?;
        assert!(extract_posix_test(&posix_nuitka_bundle(&[(name, b"x", 0)])?, out.path()).is_err());
    }
    let out = tempfile::tempdir()?;
    assert!(
        extract_posix_test(
            &posix_nuitka_bundle(&[("a", b"x", 0), ("A", b"y", 0)])?,
            out.path()
        )
        .is_err()
    );
    let out = tempfile::tempdir()?;
    assert!(
        extract_posix_test(&posix_nuitka_bundle(&[("link", b"target", 2)])?, out.path()).is_err()
    );
    let mut records = b"file\0\0".to_vec();
    records.extend_from_slice(&1u64.to_le_bytes());
    records.extend_from_slice(&123u32.to_le_bytes());
    records.extend_from_slice(b"x\0");
    let mut bad_crc = b"KAY".to_vec();
    bad_crc.extend(zstd::stream::encode_all(records.as_slice(), 1)?);
    let out = tempfile::tempdir()?;
    assert!(extract_posix_test(&bad_crc, out.path()).is_err());
    let mut oversized = b"file\0\0".to_vec();
    oversized.extend_from_slice(&(NUITKA_MAX_MEMBER + 1).to_le_bytes());
    oversized.extend_from_slice(&1u32.to_le_bytes());
    let mut oversized_frame = b"KAY".to_vec();
    oversized_frame.extend(zstd::stream::encode_all(oversized.as_slice(), 1)?);
    let out = tempfile::tempdir()?;
    assert!(extract_posix_test(&oversized_frame, out.path()).is_err());
    let mut truncated = posix_nuitka_bundle(&[("main", b"content", 0)])?;
    truncated.truncate(truncated.len() - 16);
    let out = tempfile::tempdir()?;
    assert!(extract_posix_test(&truncated, out.path()).is_err());
    Ok(())
}

#[test]
fn nuitka_depth_limit_reports_incomplete_extraction() -> std::io::Result<()> {
    let data = posix_nuitka_bundle(&[("main", b"code", 1)])?;
    let config = ArchiveAnalyzerConfig::default().with_depth(3);
    let result = analyze_sfx(
        Path::new("nested"),
        SfxKind::Nuitka,
        &data,
        &crate::Engine::empty(),
        None,
        Some(&config),
        &[],
    );
    assert!(result.archive_report.is_none());
    assert!(
        result
            .extraction_findings
            .iter()
            .any(|f| f.id == "metadata/file/format/nuitka::extraction-incomplete")
    );
    Ok(())
}

fn nuitka_bundle(entries: &[(&str, &[u8])]) -> std::io::Result<Vec<u8>> {
    let mut records = Vec::new();
    for (name, content) in entries {
        for unit in name.encode_utf16().chain(std::iter::once(0)) {
            records.extend_from_slice(&unit.to_le_bytes());
        }
        records.extend_from_slice(&(content.len() as u64).to_le_bytes());
        records.extend_from_slice(content);
    }
    records.extend_from_slice(&[0, 0]);
    let mut host = pe_stub();
    host.extend_from_slice(b"NUITKA_ONEFILE_PARENT\0KAY");
    host.extend(zstd::stream::encode_all(records.as_slice(), 1)?);
    host.extend_from_slice(b"host section trailer");
    Ok(host)
}

#[test]
fn nuitka_extracts_unicode_and_nested_members_without_consuming_host_trailer() -> std::io::Result<()>
{
    let data = nuitka_bundle(&[("main.dll", b"MZdemo"), ("lib\\caf\u{e9}.txt", b"text")])?;
    assert_eq!(detect_sfx(&data, &[]), Some(SfxKind::Nuitka));
    let out = tempfile::tempdir()?;
    extract_nuitka(&data, out.path())?;
    assert_eq!(std::fs::read(out.path().join("main.dll"))?, b"MZdemo");
    assert_eq!(
        std::fs::read(out.path().join("lib/caf\u{e9}.txt"))?,
        b"text"
    );
    Ok(())
}

#[test]
fn nuitka_rejects_unsafe_duplicate_and_truncated_members() -> std::io::Result<()> {
    for name in [
        "../escape",
        "a\\..\\escape",
        "/absolute",
        "C:\\absolute",
        "a//b",
    ] {
        let out = tempfile::tempdir()?;
        assert!(extract_nuitka(&nuitka_bundle(&[(name, b"x")])?, out.path()).is_err());
    }
    let out = tempfile::tempdir()?;
    assert!(extract_nuitka(&nuitka_bundle(&[("a", b"x"), ("A", b"y")])?, out.path()).is_err());
    let mut data = nuitka_bundle(&[("main.dll", b"MZdemo")])?;
    data.truncate(data.len() - 25);
    assert!(extract_nuitka(&data, out.path()).is_err());
    Ok(())
}

#[test]
fn nuitka_requires_both_runtime_and_frame_outside_embedded_images() -> std::io::Result<()> {
    let data = nuitka_bundle(&[("main.dll", b"MZdemo")])?;
    let frame = memmem::find(&data, NUITKA_COMPRESSED)
        .ok_or_else(|| std::io::Error::other("test bundle missing Nuitka frame"))?;
    let embedded = [crate::analyzers::embedded_binary_detector::EmbeddedBinary {
        offset: frame,
        kind: crate::analyzers::embedded_binary_detector::EmbeddedKind::Pe64,
        estimated_size: data.len() - frame,
        encoding: None,
        format_hint: None,
    }];
    assert_eq!(detect_sfx(&data, &embedded), None);
    assert_eq!(detect_sfx(b"MZNUITKA_ONEFILE_PARENT", &[]), None);
    Ok(())
}

fn pe_stub() -> Vec<u8> {
    // Minimal 256-byte buffer with MZ header (enough for marker scanning)
    let mut buf = vec![0u8; 256];
    buf[0] = 0x4D; // M
    buf[1] = 0x5A; // Z
    buf
}

fn make_synthetic_pe(buf: &mut Vec<u8>, offset: usize) {
    while buf.len() < offset + 4096 {
        buf.push(0);
    }
    buf[offset..offset + 2].copy_from_slice(b"MZ");
    buf[offset + 0x3C..offset + 0x40].copy_from_slice(&0x80u32.to_le_bytes());
    let pe = offset + 0x80;
    buf[pe..pe + 4].copy_from_slice(b"PE\0\0");
    buf[pe + 4..pe + 6].copy_from_slice(&0x014Cu16.to_le_bytes());
    buf[pe + 6..pe + 8].copy_from_slice(&1u16.to_le_bytes());
    buf[pe + 20..pe + 22].copy_from_slice(&0x00E0u16.to_le_bytes());
    buf[pe + 24..pe + 26].copy_from_slice(&0x010Bu16.to_le_bytes());
    buf[pe + 80..pe + 84].copy_from_slice(&4096u32.to_le_bytes());
    let section = pe + 24 + 0xE0;
    buf[section + 16..section + 20].copy_from_slice(&512u32.to_le_bytes());
    buf[section + 20..section + 24].copy_from_slice(&512u32.to_le_bytes());
}

#[test]
fn test_detect_nsis_deadbeef() {
    let mut data = pe_stub();
    data.extend_from_slice(NSIS_DEADBEEF);
    assert_eq!(detect_sfx(&data, &[]), None);
}

#[test]
fn test_detect_nsis_with_secondary_marker() {
    let mut data = pe_stub();
    data.extend_from_slice(NSIS_DEADBEEF);
    data.extend_from_slice(NSIS_ERROR_TITLE);
    assert_eq!(detect_sfx(&data, &[]), Some(SfxKind::Nsis));
}

#[test]
fn test_detect_inno_marker() {
    let mut data = pe_stub();
    data.extend_from_slice(INNO_MARKER);
    assert_eq!(detect_sfx(&data, &[]), Some(SfxKind::InnoSetup));
}

#[test]
fn ignores_inno_marker_inside_validated_embedded_pe() {
    use crate::analyzers::embedded_binary_detector::{EmbeddedBinary, EmbeddedKind};

    let mut data = vec![0u8; 1024];
    data[..2].copy_from_slice(b"MZ");
    let offset = 512;
    data[offset..offset + 2].copy_from_slice(b"MZ");
    data[offset + 64..offset + 64 + INNO_MARKER.len()].copy_from_slice(INNO_MARKER);
    let embedded = [EmbeddedBinary {
        offset,
        kind: EmbeddedKind::Pe32,
        estimated_size: 512,
        encoding: None,
        format_hint: Some("inno"),
    }];

    assert_eq!(detect_sfx(&data, &embedded), None);
}

#[test]
fn embedded_scanner_span_prevents_nested_inno_host_classification() {
    let mut data = vec![0u8; 8192];
    data[..2].copy_from_slice(b"MZ");
    let offset = 512;
    make_synthetic_pe(&mut data, offset);
    data[offset + 1024..offset + 1024 + INNO_MARKER.len()].copy_from_slice(INNO_MARKER);

    let embedded =
        crate::analyzers::embedded_binary_detector::scan_for_embedded_binaries(&data, None);
    assert!(
        embedded
            .iter()
            .any(|binary| { binary.offset == offset && binary.format_hint == Some("inno") })
    );
    assert_eq!(detect_sfx(&data, &embedded), None);
}

#[test]
fn root_inno_marker_still_detected_alongside_nested_inno() {
    use crate::analyzers::embedded_binary_detector::{EmbeddedBinary, EmbeddedKind};

    let mut data = vec![0u8; 1024];
    data[..2].copy_from_slice(b"MZ");
    data[256..256 + INNO_MARKER.len()].copy_from_slice(INNO_MARKER);
    let offset = 512;
    data[offset..offset + 2].copy_from_slice(b"MZ");
    data[offset + 64..offset + 64 + INNO_MARKER.len()].copy_from_slice(INNO_MARKER);
    let embedded = [EmbeddedBinary {
        offset,
        kind: EmbeddedKind::Pe32,
        estimated_size: 512,
        encoding: None,
        format_hint: Some("inno"),
    }];

    assert_eq!(detect_sfx(&data, &embedded), Some(SfxKind::InnoSetup));
    assert_eq!(
        marker_outside_embedded_binary(&data, INNO_MARKER, &embedded),
        Some(256)
    );
}

#[test]
fn ignores_nsis_markers_inside_validated_embedded_pe() {
    use crate::analyzers::embedded_binary_detector::{EmbeddedBinary, EmbeddedKind};

    let mut data = vec![0u8; 1024];
    data[..2].copy_from_slice(b"MZ");
    let offset = 512;
    data[offset..offset + 2].copy_from_slice(b"MZ");
    data[offset + 64..offset + 64 + NSIS_DEADBEEF.len()].copy_from_slice(NSIS_DEADBEEF);
    data[offset + 96..offset + 96 + NSIS_ERROR_TITLE.len()].copy_from_slice(NSIS_ERROR_TITLE);
    let embedded = [EmbeddedBinary {
        offset,
        kind: EmbeddedKind::Pe32,
        estimated_size: 512,
        encoding: None,
        format_hint: Some("nsis"),
    }];

    assert_eq!(detect_sfx(&data, &embedded), None);
}

#[test]
fn test_inno_takes_precedence_over_weak_nsis_marker() {
    let mut data = pe_stub();
    data.extend_from_slice(INNO_MARKER);
    data.extend_from_slice(NSIS_DEADBEEF);
    assert_eq!(detect_sfx(&data, &[]), Some(SfxKind::InnoSetup));
}

#[test]
fn test_detect_none_on_benign_data() {
    let data = b"This is a normal binary without any installer markers.".to_vec();
    assert_eq!(detect_sfx(&data, &[]), None);
}

#[test]
fn test_detect_none_on_empty() {
    assert_eq!(detect_sfx(&[], &[]), None);
}

#[test]
fn materializes_exact_analyzed_bytes_for_external_extractor() -> std::io::Result<()> {
    let data = b"installer bytes that only exist in memory";
    let materialized = materialize_extraction_input(data)?;

    assert_eq!(std::fs::read(materialized.path())?, data);
    assert_eq!(
        materialized.path().extension().and_then(|ext| ext.to_str()),
        Some("exe")
    );
    Ok(())
}

#[test]
fn test_finding_nsis_no_extract() {
    let finding = build_finding(SfxKind::Nsis, false, Some(0x3136C));
    assert_eq!(finding.id, "file/sfx/nsis");
    assert_eq!(finding.crit, Criticality::Notable);
    assert!((finding.conf - 0.9).abs() < f32::EPSILON);
    assert_eq!(
        finding.evidence[0].location.as_deref(),
        Some("offset:0x3136c")
    );
}

#[test]
fn test_finding_inno_with_extract() {
    let finding = build_finding(SfxKind::InnoSetup, true, None);
    assert_eq!(finding.id, "file/sfx/inno-setup");
    assert!((finding.conf - 1.0).abs() < f32::EPSILON);
    assert!(finding.evidence[0].location.is_none());
}

#[test]
fn test_classify_innoextract_known_failures() {
    let diagnostics = classify_innoextract_diagnostics(
        "Warning: unexpected setup loader revision: 2\n\
             Warning: setup loader checksum mismatch\n\
             Error: could not determine setup data version\n",
    );

    let kinds: Vec<_> = diagnostics
        .iter()
        .map(|diagnostic| diagnostic.kind)
        .collect();
    assert_eq!(
        kinds,
        vec![
            InnoExtractDiagnosticKind::UnexpectedLoaderRevision,
            InnoExtractDiagnosticKind::LoaderChecksumMismatch,
            InnoExtractDiagnosticKind::SetupDataVersionUndetermined,
        ]
    );
}

#[test]
fn test_classify_innoextract_generic_failure() {
    let diagnostics = classify_innoextract_diagnostics("Error: unsupported Inno stream\n");

    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].kind,
        InnoExtractDiagnosticKind::GenericFailure
    );
    assert_eq!(diagnostics[0].message, "Error: unsupported Inno stream");
}

#[test]
fn test_build_innoextract_finding_criticality() {
    let finding = build_innoextract_finding(&InnoExtractDiagnostic {
        kind: InnoExtractDiagnosticKind::LoaderChecksumMismatch,
        message: "setup loader checksum mismatch".to_string(),
    });

    assert_eq!(
        finding.id,
        "file/sfx/inno-setup/extraction/loader-checksum-mismatch"
    );
    assert_eq!(finding.crit, Criticality::Suspicious);
    assert_eq!(finding.evidence[0].value, "setup loader checksum mismatch");
}

#[test]
fn test_build_inno_long_member_path_finding_is_not_malware_attribution() {
    let long = "a".repeat(300);
    let stderr = format!("Error: could not open output file \"app/{long}.dll\"");
    let diagnostics = classify_innoextract_diagnostics(&stderr);
    assert_eq!(diagnostics.len(), 1);
    let finding = build_innoextract_finding(&diagnostics[0]);

    assert_eq!(
        finding.id,
        "file/sfx/inno-setup/extraction/long-member-path"
    );
    assert_eq!(finding.crit, Criticality::Notable);
    assert_eq!(finding.attack, None);
}
#[test]
fn iexpress_requires_resources_and_bounded_cabinet() {
    let mut data = b"MZ".to_vec();
    for name in ["CABINET", "RUNPROGRAM"] {
        data.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
    }
    let start = data.len();
    let mut cab = [0_u8; 64];
    cab[..4].copy_from_slice(b"MSCF");
    cab[8..12].copy_from_slice(&64_u32.to_le_bytes());
    cab[16..20].copy_from_slice(&44_u32.to_le_bytes());
    cab[24..30].copy_from_slice(&[3, 1, 1, 0, 1, 0]);
    data.extend(cab);
    assert_eq!(detect_sfx(&data, &[]), Some(SfxKind::IExpress));
    assert_eq!(detect_sfx(&data[..start + 48], &[]), None);
    let mut version_only = b"MZ Microsoft wextract.pdb".to_vec();
    version_only.extend(cab);
    assert_eq!(detect_sfx(&version_only, &[]), None);
    data[start + 28] = 0;
    assert_eq!(detect_sfx(&data, &[]), None);
}
