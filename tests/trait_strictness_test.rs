//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_hostile_trait_downgrade_warning() {
    let temp_dir = TempDir::new().unwrap();

    // 1. Atomic trait marked HOSTILE
    let traits_dir = temp_dir.path().join("traits");
    fs::create_dir(&traits_dir).unwrap();

    let atomic_yaml = r##"
traits:
  - id: hostile/atomic
    desc: "Short"
    crit: hostile
    if:
      type: symbol
      pattern: "evil_func"
"##;
    fs::write(traits_dir.join("atomic.yaml"), atomic_yaml).unwrap();

    // 2. Composite trait marked HOSTILE but with only 1 condition
    let composite_yaml = r##"
composite_rules:
  - id: hostile/weak-composite
    desc: "Composite trait marked HOSTILE but too weak"
    crit: hostile
    all:
      - type: symbol
        pattern: "func1"
"##;
    fs::write(traits_dir.join("composite.yaml"), composite_yaml).unwrap();

    // 3. Composite trait marked HOSTILE with 3 conditions but NO file_type filter (FileType::All is default)
    let composite_no_filter_yaml = r##"
composite_rules:
  - id: hostile/no-filter
    desc: "Composite trait marked HOSTILE but no file_type filter"
    crit: hostile
    all:
      - type: symbol
        pattern: "func1"
      - type: symbol
        pattern: "func2"
      - type: symbol
        pattern: "func3"
"##;
    fs::write(traits_dir.join("no_filter.yaml"), composite_no_filter_yaml).unwrap();

    let target_file = temp_dir.path().join("target.sh");
    fs::write(&target_file, "#!/bin/bash\nevil_func\n").unwrap();

    // Run flayer pointing to the temp traits directory
    // We need to set the working directory so it finds "traits"
    // Allow inline primitives since these tests are testing criticality downgrading, not inline validation
    // Warnings are now fatal, so this should fail with exit code 1
    assert_cmd::cargo_bin_cmd!("flayer")
        .current_dir(temp_dir.path())
        .env("flayer_ALLOW_INLINE_PRIMITIVES", "1")
        .args(["analyze", target_file.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("FATAL"))
        .stderr(predicate::str::contains("trait configuration warning"))
        .stderr(predicate::str::contains("hostile/atomic"))
        .stderr(predicate::str::contains("hostile/weak-composite"))
        .stderr(predicate::str::contains("hostile/no-filter"));
}

#[test]
fn test_hostile_trait_valid() {
    let temp_dir = TempDir::new().unwrap();
    let traits_dir = temp_dir.path().join("traits");
    fs::create_dir(&traits_dir).unwrap();

    let valid_yaml = r##"
composite_rules:
  - id: hostile/valid
    desc: "Valid HOSTILE trait with enough context"
    crit: hostile
    mbc: B0001
    for: [shell]
    all:
      - type: symbol
        pattern: "func1"
      - type: symbol
        pattern: "func2"
      - type: symbol
        pattern: "func3"
"##;
    fs::write(traits_dir.join("valid.yaml"), valid_yaml).unwrap();

    let target_file = temp_dir.path().join("target.sh");
    fs::write(&target_file, "#!/bin/bash\n# dummy\n").unwrap();

    // Should NOT show downgrade warning for the valid rule
    // Allow inline primitives since these tests are testing criticality downgrading, not inline validation
    assert_cmd::cargo_bin_cmd!("flayer")
        .current_dir(temp_dir.path())
        .env("flayer_ALLOW_INLINE_PRIMITIVES", "1")
        .args(["analyze", target_file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("Downgrading to SUSPICIOUS").count(0))
        .stderr(predicate::str::contains("lacks an MBC or MITRE ATT&CK mapping").count(0));
}

#[test]
fn test_suspicious_trait_no_mapping_no_warning() {
    let temp_dir = TempDir::new().unwrap();
    let traits_dir = temp_dir.path().join("traits");
    fs::create_dir(&traits_dir).unwrap();

    let suspicious_yaml = r##"
traits:
  - id: suspicious/no-mapping
    desc: "Suspicious trait with no mapping"
    crit: suspicious
    if:
      type: symbol
      pattern: "some_func"
"##;
    fs::write(traits_dir.join("suspicious.yaml"), suspicious_yaml).unwrap();

    let target_file = temp_dir.path().join("target.sh");
    fs::write(&target_file, "#!/bin/bash\n# dummy\n").unwrap();

    // Should NOT show warning for SUSPICIOUS traits anymore
    assert_cmd::cargo_bin_cmd!("flayer")
        .current_dir(temp_dir.path())
        .args(["analyze", target_file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("lacks an MBC or MITRE ATT&CK mapping").count(0))
        .stderr(predicate::str::contains("targets all platforms and file types").count(0));
}
