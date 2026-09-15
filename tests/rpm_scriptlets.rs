//! Static, harmless package fixtures. No RPM command or script is executed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

fn rpm(mut tags: Vec<(u32, u32, u32, Vec<u8>)>, unsupported_payload: bool) -> Vec<u8> {
    tags.push((1000, 6, 1, b"fixture\0".to_vec()));
    let mut bytes = vec![0; 96];
    bytes[..6].copy_from_slice(&[0xed, 0xab, 0xee, 0xdb, 3, 0]);
    bytes.extend_from_slice(&[0x8e, 0xad, 0xe8, 1]);
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(&[0x8e, 0xad, 0xe8, 1]);
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&(tags.len() as u32).to_be_bytes());
    let size: usize = tags.iter().map(|t| t.3.len()).sum();
    bytes.extend_from_slice(&(size as u32).to_be_bytes());
    let mut offset = 0;
    for (tag, typ, count, value) in &tags {
        for field in [*tag, *typ, offset, *count] {
            bytes.extend_from_slice(&field.to_be_bytes());
        }
        offset += value.len() as u32;
    }
    for (_, _, _, value) in tags {
        bytes.extend(value);
    }
    if unsupported_payload {
        bytes.extend_from_slice(b"07070X00000000");
    } else {
        cpio::newc::trailer(&mut bytes).unwrap();
    }
    bytes
}

#[test]
fn scripts_survive_payload_errors_and_keep_independent_scopes() {
    let dir = tempfile::tempdir().unwrap();
    let rules = dir.path().join("micro-behaviors/ui/terminal");
    std::fs::create_dir_all(&rules).unwrap();
    std::fs::write(
        rules.join("echo.yaml"),
        r#"
traits:
  - id: alpha
    desc: Prints alpha
    for: [shell]
    crit: notable
    if: {type: symbol, kind: call, exact: echo, arg: {kind: string, exact: alpha}}
  - id: beta
    desc: Prints beta
    for: [shell]
    crit: notable
    if: {type: symbol, kind: call, exact: echo, arg: {kind: string, exact: beta}}
composite_rules:
  - id: both-in-one-source
    desc: One shell source prints both literals
    for: [shell]
    crit: notable
    all: [{id: alpha}, {id: beta}]
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
    for unsupported_payload in [false, true] {
        let bytes = rpm(
            vec![
                (1023, 6, 1, b"echo 'alpha'\n\0".to_vec()),
                (1085, 6, 1, b"/bin/sh\0".to_vec()),
                (1024, 6, 1, b"echo 'beta'\n\0".to_vec()),
                (1086, 8, 1, b"/bin/sh\0".to_vec()),
                (1004, 9, 1, b"echo 'alpha'; echo 'beta'\0".to_vec()),
            ],
            unsupported_payload,
        );
        let report = cleave::analyze_bytes(&bytes, "fixture.rpm", &options).unwrap();
        assert_eq!(report.files.len(), 2);
        for (phase, marker) in [("prein", "alpha"), ("postin", "beta")] {
            let path = format!("fixture.rpm!!/rpm/scriptlets/{phase}/body");
            let file = report.files.iter().find(|f| f.path == path).unwrap();
            assert_eq!(file.file_type, "shell");
            assert!(file.encoding.is_none());
            assert!(
                file.findings
                    .iter()
                    .any(|f| f.id.as_str() == format!("micro-behaviors/ui/terminal::{marker}"))
            );
            assert!(
                !file
                    .findings
                    .iter()
                    .any(|f| f.id.as_str().ends_with("::both-in-one-source"))
            );
        }
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.id.as_str().ends_with("::both-in-one-source"))
        );
        assert_eq!(
            report
                .findings
                .iter()
                .any(|f| f.id.as_str() == "anti-analysis/malformed/archive-incomplete"),
            unsupported_payload
        );
    }

    // Unknown or runtime-expanded interpreters retain metadata and a gap,
    // A literal GitHub expression spelling in RPM is not a runner template.
    let bytes = rpm(
        vec![(1024, 6, 1, b"echo '${{literal}}'\n\0".to_vec())],
        false,
    );
    let report = cleave::analyze_bytes(&bytes, "literal.rpm", &options).unwrap();
    assert_eq!(report.files.len(), 1);
    assert!(report.analysis_gaps.is_empty());

    // Unknown or runtime-expanded interpreters retain metadata and a gap,
    // not shell detections produced by guessing from the body.
    for extra in [
        (1086, 8, 1, b"/custom/interpreter\0".to_vec()),
        (5021, 4, 1, 1u32.to_be_bytes().to_vec()),
    ] {
        let bytes = rpm(vec![(1024, 6, 1, b"echo 'alpha'\0".to_vec()), extra], false);
        let report = cleave::analyze_bytes(&bytes, "unknown.rpm", &options).unwrap();
        assert!(report.files.is_empty());
        assert!(
            report
                .analysis_gaps
                .iter()
                .any(|g| g == cleave::types::AnalysisGap::EmbeddedSourceIncomplete)
        );
    }

    let bytes = rpm(
        vec![
            (1023, 8, 1, b"invalid body type\0".to_vec()),
            (1024, 6, 1, b"echo 'beta'\0".to_vec()),
        ],
        false,
    );
    let report = cleave::analyze_bytes(&bytes, "partial.rpm", &options).unwrap();
    assert_eq!(report.files.len(), 1);
    assert!(report.files[0].path.ends_with("/postin/body"));
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id.as_str() == "anti-analysis/malformed/archive-incomplete")
    );
}
