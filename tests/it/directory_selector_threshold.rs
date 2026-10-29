//! A directory can satisfy a threshold through two of its child findings.
use cleave::types::CompactReport;
use std::{path::Path, process::Command};

fn write(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

#[test]
fn directory_members_do_not_make_an_optional_peer_mandatory() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let members = "micro-behaviors/data/string/concat";
    let peer = "micro-behaviors/data/string/compare";
    let result = "micro-behaviors/data/control-flow/branch";
    write(
        root,
        &format!("{members}/atoms.yaml"),
        r#"
defaults: {platforms: [unix, windows], for: [text], crit: component}
traits:
- id: alpha
  desc: First selector input
  if: {type: text, word: alpha}
- id: beta
  desc: Second selector input
  if: {type: text, word: beta}
"#,
    );
    write(
        root,
        &format!("{peer}/atoms.yaml"),
        r#"
defaults: {platforms: [unix, windows], for: [text], crit: component}
traits:
- id: spare
  desc: Independent optional input
  if: {type: text, word: spare}
"#,
    );
    write(
        root,
        &format!("{result}/rule.yaml"),
        &format!(
            r#"
defaults: {{platforms: [unix, windows], for: [text]}}
composite_rules:
- id: threshold
  desc: Two selector inputs
  crit: notable
  conf: 0.95
  any:
  - id: {members}
  - id: {peer}::spare
  needs: 2
"#
        ),
    );
    for (name, source, expected) in [
        ("two-members", "alpha beta", true),
        ("member-and-peer", "alpha spare", true),
        ("single-member", "alpha", false),
    ] {
        let rel = format!("testdata/notable/{name}.txt");
        write(root, &rel, source);
        let output = Command::new(env!("CARGO_BIN_EXE_cleave"))
            .args([
                "--traits-dir",
                root.to_str().unwrap(),
                "--disable",
                "yara,radare2,upx",
                "--format",
                "json",
                "analyze",
                root.join(&rel).to_str().unwrap(),
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
        let report: CompactReport = serde_json::from_slice(&output.stdout).unwrap();
        let actual = report.files[0]
            .findings
            .iter()
            .any(|f| f.id == format!("{result}::threshold"));
        assert_eq!(actual, expected, "{source}");
    }
}

#[test]
fn removed_migration_selector_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    write(
        root,
        "micro-behaviors/data/string/concat/rule.yaml",
        r#"
defaults: {platforms: [unix, windows], for: [text]}
composite_rules:
- id: invalid-selector
  desc: Unsupported migration selector
  crit: notable
  any:
  - type: trait-set
    ids: ['micro-behaviors/data/string/concat::missing']
"#,
    );
    write(root, "testdata/baseline/plain.txt", "ordinary input");
    let output = Command::new(env!("CARGO_BIN_EXE_cleave"))
        .args(["--traits-dir", root.to_str().unwrap(), "validate"])
        .env("CLEAVE_SKIP_CACHE", "1")
        .env("CLEAVE_NO_UPDATE_CHECK", "1")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("trait-set"));
}
