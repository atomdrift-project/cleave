//! Partial extraction is an archive parsing property, including through the CLI.
#![allow(clippy::unwrap_used)]
use std::{io::Write, process::Command};

#[test]
fn partial_archive_reports_parsing_property_and_retains_readable_members() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    std::fs::create_dir_all(root.join("metadata/filename/identity")).unwrap();
    std::fs::write(root.join("metadata/filename/identity/control.yaml"),
        "defaults:\n  platforms: [unix, windows]\n  for: [text]\ntraits:\n- id: control\n  desc: Control filename\n  crit: notable\n  if: {type: basename, exact: control}\n").unwrap();
    let mut whole = Vec::new();
    {
        let enc = flate2::write::GzEncoder::new(&mut whole, flate2::Compression::none());
        let mut builder = tar::Builder::new(enc);
        for name in ["alpha.txt", "beta.txt", "gamma.txt"] {
            let content = vec![b'A'; 40_000];
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, name, &content[..])
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
    }
    for partial in [false, true] {
        let path = root.join(if partial { "partial" } else { "intact" });
        let bytes = if partial {
            &whole[..whole.len() / 2]
        } else {
            &whole[..]
        };
        std::fs::File::create(&path)
            .unwrap()
            .write_all(bytes)
            .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_cleave"))
            .args([
                "--traits-dir",
                root.to_str().unwrap(),
                "--disable",
                "yara,radare2,upx",
                "--format",
                "json",
                "analyze",
                path.to_str().unwrap(),
            ])
            .env("CLEAVE_SKIP_CACHE", "1")
            .env("CLEAVE_NO_UPDATE_CHECK", "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let source = String::from_utf8(output.stdout).unwrap();
        assert!(!source.contains("metadata/file/archive::partial-extraction"));
        assert_eq!(
            source.contains("metadata/archive/parsing::partial-extraction"),
            partial,
            "{report}"
        );
        assert!(
            source.contains("alpha.txt"),
            "readable prefix lost: {report}"
        );
    }
}
