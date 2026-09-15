//! Harmless RPM/CPIO traversal checks. No package is installed or script run.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::io::Write;

fn payload(malformed_tail: bool) -> Vec<u8> {
    let mut data = Vec::new();
    for (name, body) in [
        ("padding.txt", b"x".as_slice()),
        ("later.sh", b"echo 'ready'\n".as_slice()),
    ] {
        let mut entry = cpio::newc::Builder::new(name)
            .mode(0o100644)
            .write(&mut data, body.len() as u32);
        entry.write_all(body).unwrap();
        entry.finish().unwrap();
    }
    if malformed_tail {
        data.extend_from_slice(&[b'x'; 110]);
    } else {
        cpio::newc::trailer(&mut data).unwrap();
    }
    data
}

fn rpm(payload: &[u8], gzip: bool) -> Vec<u8> {
    let mut bytes = vec![0u8; 96];
    bytes[..6].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 3, 0]);
    // Empty signature header and a main header carrying RPMTAG_NAME.
    bytes.extend_from_slice(&[0x8e, 0xad, 0xe8, 1]);
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(&[0x8e, 0xad, 0xe8, 1]);
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&1u32.to_be_bytes());
    bytes.extend_from_slice(&8u32.to_be_bytes());
    for field in [1000u32, 6, 0, 1] {
        bytes.extend_from_slice(&field.to_be_bytes());
    }
    bytes.extend_from_slice(b"fixture\0");
    if gzip {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(payload).unwrap();
        bytes.extend(encoder.finish().unwrap());
    } else {
        bytes.extend_from_slice(payload);
    }
    bytes
}

#[test]
fn rpm_preserves_later_source_and_reports_partial_cpio() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("micro-behaviors/ui/terminal");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("echo.yaml"),
        r#"
traits:
  - id: ready-output
    desc: Echo prints the ready literal
    for: [shell]
    crit: notable
    if: {type: symbol, kind: call, exact: echo, arg: {kind: string, exact: ready}}
"#,
    )
    .unwrap();
    cleave::traits_repo::set_override_dir(Some(dir.path().to_path_buf()));
    let options = cleave::AnalysisOptions {
        disable_yara: true,
        disable_radare2: true,
        disable_upx: true,
        ..Default::default()
    };
    for gzip in [false, true] {
        for malformed in [false, true] {
            let bytes = rpm(&payload(malformed), gzip);
            let report = cleave::analyze_bytes(&bytes, "fixture.rpm", &options).unwrap();
            let script = report.files.iter().find(|file| file.path == "later.sh");
            assert!(
                script.is_some(),
                "gzip={gzip}, malformed={malformed}, target={:?}, files={:?}, errors={:?}",
                report.target,
                report
                    .files
                    .iter()
                    .map(|file| &file.path)
                    .collect::<Vec<_>>(),
                report.metadata.errors
            );
            let script = script.unwrap();
            assert_eq!(script.file_type, "shell");
            assert!(
                script
                    .findings
                    .iter()
                    .any(|finding| finding.id.as_str()
                        == "micro-behaviors/ui/terminal::ready-output")
            );
            let incomplete = report
                .findings
                .iter()
                .any(|finding| finding.id.as_str() == "anti-analysis/malformed/archive-incomplete");
            assert_eq!(incomplete, malformed, "gzip={gzip}, malformed={malformed}");
        }
    }
    for payload in [b"07070X00000000".as_slice(), &[b'x'; 110]] {
        let report =
            cleave::analyze_bytes(&rpm(payload, true), "unsupported.rpm", &options).unwrap();
        assert!(report.files.is_empty());
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.id.as_str() == "anti-analysis/malformed/archive-incomplete")
        );
        let facts = report
            .filefacts
            .as_ref()
            .expect("retain parsed RPM header facts");
        assert_eq!(facts.values["rpm"]["name"], "fixture");
    }
}
