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

/// The zstd frame a Nuitka one-file payload starts at, behind `KAY`.
const NUITKA_FRAME: &[u8] = b"KAY\x28\xb5\x2f\xfd";

fn nuitka_frame(data: &[u8]) -> std::io::Result<usize> {
    memchr::memmem::find(data, NUITKA_FRAME).ok_or_else(|| std::io::Error::other("missing marker"))
}

fn extract_posix_test(data: &[u8], out: &Path) -> std::io::Result<()> {
    extract_nuitka_to(data, nuitka_frame(data)?, out)
}

fn extract_nuitka(data: &[u8], out: &Path) -> std::io::Result<()> {
    extract_nuitka_to(data, nuitka_frame(data)?, out)
}

#[test]
fn nuitka_posix_cached_extracts_regular_members() -> std::io::Result<()> {
    let data = posix_nuitka_bundle(&[("main", b"code", 1), ("lib/caf\u{e9}.txt", b"text", 0)])?;
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
    oversized.extend_from_slice(&(unpack::nuitka::MAX_MEMBER + 1).to_le_bytes());
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
        Some(nuitka_frame(&data)?),
        &data,
        &crate::Engine::empty(),
        None,
        Some(&config),
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

fn pe_stub() -> Vec<u8> {
    // Minimal 256-byte buffer with MZ header (enough for marker scanning)
    let mut buf = vec![0u8; 256];
    buf[0] = 0x4D; // M
    buf[1] = 0x5A; // Z
    buf
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
