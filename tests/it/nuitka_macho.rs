//! Verify one-file payload provenance through both public analysis paths.
use cleave::AnalysisOptions;

fn fixture() -> Vec<u8> {
    let content = b"const marker = 'NUITKA_CHILD_SENTINEL_7419';\n";
    let mut records = b"child.js\0\0".to_vec();
    records.extend_from_slice(&(content.len() as u64).to_le_bytes());
    records.extend_from_slice(&crc32fast::hash(content).max(1).to_le_bytes());
    records.extend_from_slice(content);
    records.push(0);
    let mut data = include_bytes!("../fixtures/test.macho").to_vec();
    data.extend_from_slice(b"NUITKA_ONEFILE_PARENT\0KAY");
    data.extend(zstd::stream::encode_all(records.as_slice(), 1).unwrap());
    data
}

#[test]
fn cached_posix_payload_is_visible_standalone_and_in_archive() {
    let dir = tempfile::tempdir().unwrap();
    let traits = dir.path().join("traits");
    let ns = traits.join("micro-behaviors/data/test-nuitka");
    std::fs::create_dir_all(&ns).unwrap();
    std::fs::write(
        ns.join("probe.yaml"),
        r#"
defaults:
  platforms: [unix, windows]
  for: [javascript]
  crit: suspicious
traits:
  - id: child-sentinel
    desc: Child sentinel text
    if:
      type: text
      substr: NUITKA_CHILD_SENTINEL_7419
"#,
    )
    .unwrap();
    cleave::traits_repo::set_override_dir(Some(traits));
    let opts = AnalysisOptions {
        disable_yara: true,
        disable_radare2: true,
        disable_upx: true,
        ..Default::default()
    };
    let data = fixture();
    let standalone = cleave::analyze_bytes(&data, "wrapper.macho", &opts).unwrap();
    let standalone_path = dir.path().join("wrapper.macho");
    std::fs::write(&standalone_path, &data).unwrap();
    let standalone_file = cleave::analyze_file(&standalone_path, &opts).unwrap();
    let archive_path = dir.path().join("outer.tar");
    let mut archive = tar::Builder::new(std::fs::File::create(&archive_path).unwrap());
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, "wrapper.macho", data.as_slice())
        .unwrap();
    archive.finish().unwrap();
    let nested = cleave::analyze_file(&archive_path, &opts).unwrap();
    for (label, report) in [
        ("standalone", standalone),
        ("file", standalone_file),
        ("archive", nested),
    ] {
        let found = report
            .findings
            .iter()
            .chain(report.files.iter().flat_map(|f| f.findings.iter()));
        assert!(
            found
                .into_iter()
                .any(|f| f.id == "micro-behaviors/data/test-nuitka::child-sentinel"),
            "{label}: missing embedded child finding"
        );
        assert!(
            report
                .files
                .iter()
                .all(|f| !f.path.contains("wrapper.macho!!wrapper.macho!!")),
            "{label}: duplicated wrapper path"
        );
        assert!(
            report
                .files
                .iter()
                .any(|f| f.path.contains("wrapper.macho!!child.js")),
            "{label}: missing wrapper-to-child provenance: {:?}",
            report.files.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
    }
    cleave::traits_repo::set_override_dir(None);
}
