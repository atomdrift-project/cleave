use super::*;

fn write(root: &Path, name: &str) {
    let path = root.join(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, "fixture").unwrap();
}

#[test]
fn discovery_uses_only_first_directory_and_includes_hidden_inputs() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "hostile/generated/baseline/.payload.js");
    write(root.path(), "baseline/.github/action.yml");
    write(root.path(), "notable/scripts/build.py");
    let targets = discover_targets(root.path()).unwrap();
    assert_eq!(targets.len(), 3);
    assert_eq!(targets[0].expected, Criticality::Baseline);
    assert_eq!(targets[1].expected, Criticality::Hostile);
    assert_eq!(targets[2].expected, Criticality::Notable);
    // Gitignore, extensions and script directory names never exclude data.
    write(root.path(), "notable/.gitignore");
    assert_eq!(discover_targets(root.path()).unwrap().len(), 4);
}

#[test]
fn fresh_unknown_files_and_legacy_manifests_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "hostile/sample.js");
    assert!(discover_targets(root.path()).is_ok());
    write(root.path(), "triage/receipt.json");
    let error = discover_targets(root.path()).err().unwrap().to_string();
    assert!(error.contains("triage/receipt.json"), "{error}");
    std::fs::remove_file(root.path().join("triage/receipt.json")).unwrap();
    write(root.path(), "expectations.toml");
    assert!(
        discover_targets(root.path())
            .err()
            .unwrap()
            .to_string()
            .contains("expectations.toml")
    );
}

#[cfg(unix)]
#[test]
fn symlinks_are_errors_and_never_followed() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    write(root.path(), "baseline/real.txt");
    std::os::unix::fs::symlink(outside.path(), root.path().join("baseline/link")).unwrap();
    assert!(
        discover_targets(root.path())
            .err()
            .unwrap()
            .to_string()
            .contains("baseline/link")
    );
}

#[test]
fn empty_fixture_tree_is_not_a_passing_test_suite() {
    let root = tempfile::tempdir().unwrap();
    assert!(discover_targets(root.path()).is_err());
}

#[test]
fn size_limits_have_exact_boundaries_and_only_noop_subtrees_are_exempt() {
    let root = tempfile::tempdir().unwrap();
    write(root.path(), "baseline/input.bin");
    let input = root.path().join("baseline/input.bin");
    std::fs::write(&input, vec![0; 20 * 1024]).unwrap();
    assert!(discover_targets(root.path()).is_ok());
    std::fs::write(&input, vec![0; 20 * 1024 + 1]).unwrap();
    assert!(
        discover_targets(root.path())
            .err()
            .unwrap()
            .to_string()
            .contains("20 KiB")
    );
    let compressed = root.path().join("baseline/input.bin.xz");
    std::fs::rename(&input, &compressed).unwrap();
    std::fs::write(&compressed, vec![0; 500 * 1024]).unwrap();
    assert!(discover_targets(root.path()).is_ok());
    std::fs::write(&compressed, vec![0; 500 * 1024 + 1]).unwrap();
    assert!(
        discover_targets(root.path())
            .err()
            .unwrap()
            .to_string()
            .contains("500 KiB")
    );
    let exempt = root.path().join("baseline/does-nothing/input.bin");
    std::fs::create_dir_all(exempt.parent().unwrap()).unwrap();
    std::fs::rename(&compressed, exempt).unwrap();
    assert!(discover_targets(root.path()).is_ok());
}

#[test]
fn storage_compression_preserves_bytes_and_original_basename() {
    use std::io::Write;
    let root = tempfile::tempdir().unwrap();
    let stage = NeutralStage::new(root.path()).unwrap();
    let path = root.path().join("package.json.xz");
    let input = b"{\"name\":\"fixture\"}";
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(input).unwrap();
    std::fs::write(&path, encoder.finish().unwrap()).unwrap();
    let staged = stage.stage(&path).unwrap();
    assert_eq!(staged.file_name().unwrap(), "package.json");
    assert_eq!(std::fs::read(staged).unwrap(), input);
    std::fs::write(&path, b"invalid xz").unwrap();
    assert!(stage.stage(&path).is_err());
}

#[test]
fn severity_uses_members_and_ignores_scores_and_filtered_findings() {
    let mut report = AnalysisReport::new(cleave::TargetInfo {
        path: "bundle.zip".into(),
        file_type: "zip".into(),
        size_bytes: 1,
        sha256: "abc".into(),
        architectures: None,
    });
    report.finalize();
    assert_eq!(report_severity(&report).unwrap(), Criticality::Baseline);
    let mut member = report.files[0].clone();
    member.path = "bundle.zip!!member.js##base64@1".into();
    let mut finding = cleave::types::Finding::new("test", Default::default(), "test", 1.0);
    finding.crit = Criticality::Hostile;
    member.findings.push(finding);
    report.files.push(member);
    assert_eq!(report_severity(&report).unwrap(), Criticality::Hostile);
    let target = Target {
        path: "sample".into(),
        expected: Criticality::Suspicious,
        metadata: None,
    };
    assert!(evaluate(vec![(target, Ok(report))]).is_err());
}
