//! Static traversal of harmless gzip-wrapped installer-style CPIO scripts.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::io::Write;

fn entry(out: &mut Vec<u8>, name: &str, body: &[u8]) {
    out.extend_from_slice(
        format!(
            "070707{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:06o}{:011o}{:06o}{:011o}",
            0,
            1,
            0o100755,
            0,
            0,
            1,
            0,
            0,
            name.len() + 1,
            body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(name.as_bytes());
    out.push(0);
    out.extend_from_slice(body);
}

#[test]
fn compressed_cpio_exposes_named_script_and_partial_diagnostics() {
    let rules = tempfile::tempdir().unwrap();
    let path = rules.path().join("micro-behaviors/ui/terminal");
    std::fs::create_dir_all(&path).unwrap();
    std::fs::write(
        path.join("echo.yaml"),
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
    cleave::traits_repo::set_override_dir(Some(rules.path().to_path_buf()));
    let options = cleave::AnalysisOptions {
        disable_yara: true,
        disable_radare2: true,
        disable_upx: true,
        ..Default::default()
    };
    for compressed in [false, true] {
        for partial in [false, true] {
            let mut bytes = Vec::new();
            entry(&mut bytes, "padding", b"x");
            entry(&mut bytes, "./postinstall", b"#!/bin/sh\necho 'ready'\n");
            if partial {
                bytes.extend_from_slice(b"broken");
            } else {
                entry(&mut bytes, "TRAILER!!!", b"");
            }
            if compressed {
                let mut gz =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                gz.write_all(&bytes).unwrap();
                bytes = gz.finish().unwrap();
            }
            let report = cleave::analyze_bytes(&bytes, "Scripts", &options).unwrap();
            let script = report
                .files
                .iter()
                .find(|file| file.path.ends_with("postinstall"));
            assert!(
                script.is_some(),
                "compressed={compressed}, partial={partial}, paths={:?}",
                report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
            );
            let script = script.unwrap();
            assert_eq!(script.file_type, "shell");
            assert!(
                script
                    .findings
                    .iter()
                    .any(|f| f.id.as_str() == "micro-behaviors/ui/terminal::ready-output")
            );
            let incomplete = report
                .findings
                .iter()
                .chain(report.files.iter().flat_map(|f| &f.findings))
                .any(|f| f.id.as_str() == "anti-analysis/malformed/archive-incomplete");
            assert_eq!(incomplete, partial, "compressed={compressed}");
        }
    }
    let mut empty = Vec::new();
    entry(&mut empty, "TRAILER!!!", b"");
    let report = cleave::analyze_bytes(&empty, "empty.cpio", &options).unwrap();
    assert!(report.files.is_empty());
    assert!(
        report
            .findings
            .iter()
            .all(|f| f.id.as_str() != "anti-analysis/malformed/archive-incomplete")
    );
}
