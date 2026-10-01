//! Hermetic standalone/archive recursion regression using the original wrapper.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use cleave::{AnalysisOptions, AnalysisReport};
use std::collections::BTreeSet;
fn ids(report: &AnalysisReport) -> BTreeSet<String> {
    report
        .findings
        .iter()
        .chain(report.files.iter().flat_map(|f| f.findings.iter()))
        .map(|f| f.id.to_string())
        .collect()
}
#[test]
fn recovered_macho_imports_are_analyzed_standalone_and_inside_an_archive() {
    let dir = tempfile::tempdir().unwrap();
    let traits = dir.path().join("traits");
    let ns = traits.join("micro-behaviors/communications/socket");
    std::fs::create_dir_all(&ns).unwrap();
    std::fs::write(
        ns.join("probe.yaml"),
        r#"
defaults:
  platforms: [macos]
  for: [macho]
  crit: notable
  conf: 1.0
traits:
  - id: decoded-socket-import
    desc: Socket import in recovered executable
    if:
      type: symbol
      exact: socket
"#,
    )
    .unwrap();
    cleave::traits_repo::set_override_dir(Some(traits));
    filefacts::cache::set_caching_enabled(false);
    let opts = AnalysisOptions {
        disable_yara: true,
        disable_radare2: true,
        disable_upx: true,
        ..Default::default()
    };
    let file = include_bytes!("../testdata/xor/xor_fat_dropper.macho");
    let payload: Vec<u8> = file[0x6210..0x6210 + 153824]
        .iter()
        .map(|b| b ^ 0x9c)
        .collect();
    let probe = "micro-behaviors/communications/socket::decoded-socket-import";
    let plain = ids(&cleave::analyze_bytes(&payload, "plain.macho", &opts).unwrap());
    assert!(plain.contains(probe), "decoded image sanity: {plain:?}");
    // Same wrapper with its encrypted image erased retains native wrapper imports,
    // but has neither the payload's socket import nor a recoverable child.
    let mut erased = file.to_vec();
    erased[0x6210..0x6210 + 153824].fill(0);
    let negative = ids(&cleave::analyze_bytes(&erased, "erased.macho", &opts).unwrap());
    assert!(
        !negative.contains(probe),
        "wrapper itself cannot satisfy child probe"
    );
    let standalone = ids(&cleave::analyze_bytes(file, "wrapper.macho", &opts).unwrap());
    let path = dir.path().join("sample.tar.gz");
    let out = std::fs::File::create(&path).unwrap();
    let gzip = flate2::write::GzEncoder::new(out, flate2::Compression::default());
    let mut tar = tar::Builder::new(gzip);
    let mut header = tar::Header::new_gnu();
    header.set_size(file.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "app/wrapper.macho", &file[..])
        .unwrap();
    tar.into_inner().unwrap().finish().unwrap();
    let archive = ids(&cleave::analyze_file(&path, &opts).unwrap());
    for (label, found) in [("standalone", standalone), ("archive", archive)] {
        assert!(
            found.contains(probe),
            "{label}: child import missing: {found:?}"
        );
        assert!(
            found.contains("metadata/encoded-payload/xor"),
            "{label}: XOR provenance missing: {found:?}"
        );
    }
    cleave::traits_repo::set_override_dir(None);
}
