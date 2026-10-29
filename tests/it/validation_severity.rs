//! Directory labels are the complete fixture contract, including cache hits.

use std::path::Path;
use std::process::{Command, Output};

fn validate(root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cleave"))
        .args([
            "--traits-dir",
            root.to_str().unwrap(),
            "validate",
            "--exclude",
            "validation",
        ])
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env_remove("CLEAVE_SKIP_CACHE")
        .env_remove("CLEAVE_VALIDATE_SOFT")
        .output()
        .unwrap()
}

#[test]
fn directory_contract_is_checked_before_a_cached_pass_and_rule_loading() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let rules = root.join("metadata/lang/source/shape");
    std::fs::create_dir_all(&rules).unwrap();
    let rule = rules.join("marker.yaml");
    std::fs::write(
        &rule,
        r#"
defaults:
  for: [python]
  platforms: [unix, windows]
  crit: notable
traits:
  - id: fixture-operation
    desc: Fixture operation marker
    conf: 1.0
    if: {type: text, substr: fixture_operation_marker}
"#,
    )
    .unwrap();
    let input = root.join("testdata/baseline/.github/input.py");
    std::fs::create_dir_all(input.parent().unwrap()).unwrap();
    std::fs::write(&input, "pass\n").unwrap();
    for _ in 0..2 {
        let output = validate(root);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("baseline 1/1"));
    }

    // Neither an old successful result nor a malformed rule can hide unused
    // data. Discovery must reject it before fingerprinting or loading rules.
    let junk = root.join("testdata/receipt.json");
    std::fs::write(&junk, "{}").unwrap();
    let original = std::fs::read(&rule).unwrap();
    std::fs::write(&rule, "malformed: [").unwrap();
    let output = validate(root);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("receipt.json"));
    std::fs::remove_file(junk).unwrap();
    std::fs::write(rule, original).unwrap();

    // An automatically discovered hidden input must enforce its label. A
    // notable finding cannot pass a baseline fixture just because it is benign.
    std::fs::write(&input, "fixture_operation_marker\n").unwrap();
    let output = validate(root);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected B, found N"));
    let destination = root.join("testdata/notable/control/input.py");
    std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
    std::fs::rename(input, destination).unwrap();
    let output = validate(root);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("notable 1/1"));
}
