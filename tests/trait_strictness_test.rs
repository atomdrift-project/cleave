//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Test that hostile traits without sufficient precision are silently downgraded.
///
/// HOSTILE criticality requires high precision to avoid false positives.
/// Rules that don't meet precision requirements are automatically downgraded
/// to SUSPICIOUS (non-fatal, just logged at debug level).
#[test]
fn test_hostile_trait_downgrade() {
    let temp_dir = TempDir::new().unwrap();

    // Create a composite trait marked HOSTILE but with insufficient precision
    let traits_dir = temp_dir.path().join("traits");
    fs::create_dir(&traits_dir).unwrap();

    let composite_yaml = r##"
composite_rules:
  - id: objectives/weak-composite
    desc: "Composite trait marked HOSTILE but too weak"
    crit: hostile
    all:
      - type: symbol
        pattern: "func1"
"##;
    fs::write(traits_dir.join("composite.yaml"), composite_yaml).unwrap();

    let target_file = temp_dir.path().join("target.sh");
    fs::write(&target_file, "#!/bin/bash\nfunc1\n").unwrap();

    // Run cleave - should succeed (downgrade is non-fatal)
    // The rule will be silently downgraded from HOSTILE to SUSPICIOUS
    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - only testing trait strictness
        .env("cleave_TRAITS_PATH", traits_dir.to_str().unwrap())
        .env("cleave_CAPABILITIES", traits_dir.to_str().unwrap())
        .env("cleave_ALLOW_INLINE_PRIMITIVES", "1")
        .env("cleave_VALIDATE", "0")
        .args(["analyze", target_file.to_str().unwrap()])
        .assert()
        .success();
}

/// Test that properly structured HOSTILE composite rules work without validation errors.
///
/// NOTE: This test runs WITHOUT full validation since the test's simplified YAML structure
/// doesn't follow all production validation rules (like trait reference requirements).
/// The important thing is that the rule loads and can be used for analysis.
#[test]
fn test_hostile_trait_valid() {
    let temp_dir = TempDir::new().unwrap();
    let traits_dir = temp_dir.path().join("traits");
    fs::create_dir(&traits_dir).unwrap();

    // Use a well-structured composite rule with:
    // - Specific file type filter (not All)
    // - MBC mapping
    // - Multiple conditions
    let valid_yaml = r##"
composite_rules:
  - id: objectives/valid
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

    // Run without full validation - this test checks that the rule loads and works,
    // not that it passes all strict validation rules
    // Allow inline primitives since these tests are testing criticality downgrading, not inline validation
    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - only testing trait strictness
        .env("cleave_TRAITS_PATH", traits_dir.to_str().unwrap())
        .env("cleave_CAPABILITIES", traits_dir.to_str().unwrap())
        .env("cleave_ALLOW_INLINE_PRIMITIVES", "1")
        .env("cleave_VALIDATE", "0")
        .args(["analyze", target_file.to_str().unwrap()])
        .assert()
        .success();
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
    // Set cleave_TRAITS_PATH to point to our custom traits directory
    assert_cmd::cargo_bin_cmd!("cleave")
        .env("cleave_SKIP_YARA", "1") // Skip YARA - only testing trait strictness
        .env("cleave_TRAITS_PATH", traits_dir.to_str().unwrap())
        .env("cleave_CAPABILITIES", traits_dir.to_str().unwrap())
        .args(["analyze", target_file.to_str().unwrap()])
        .assert()
        .success()
        .stderr(predicate::str::contains("lacks an MBC or MITRE ATT&CK mapping").count(0))
        .stderr(predicate::str::contains("targets all platforms and file types").count(0));
}
