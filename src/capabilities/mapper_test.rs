//! Test module.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::len_zero
)]

//! Tests for CapabilityMapper
//!
//! Comprehensive test coverage for the core capability mapping functionality.

use super::mapper::CapabilityMapper;
use crate::composite_rules::{Platform, SectionMap};
use crate::types::{AnalysisReport, Criticality};
use tempfile::TempDir;

/// Helper: Create a minimal test YAML file
fn create_test_yaml(content: &str) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("test.yaml");
    std::fs::write(&file_path, content).unwrap();
    (dir, file_path)
}

/// Helper: Create a test analysis report
fn create_test_report() -> AnalysisReport {
    create_test_report_with_size(1024)
}

/// Helper: Create a test analysis report with specific size
fn create_test_report_with_size(size: u64) -> AnalysisReport {
    use crate::types::TargetInfo;

    AnalysisReport::new(TargetInfo {
        path: "test.bin".to_string(),
        file_type: "executable".to_string(),
        size_bytes: size,
        sha256: "abc123".to_string(),
        architectures: None,
    })
}

/// Helper: Create a test analysis report for source files.
fn create_test_source_report(path: &str, file_type: &str, size: u64) -> AnalysisReport {
    use crate::types::TargetInfo;

    AnalysisReport::new(TargetInfo {
        path: path.to_string(),
        file_type: file_type.to_string(),
        size_bytes: size,
        sha256: "abc123".to_string(),
        architectures: None,
    })
}

#[test]
fn test_empty_mapper() {
    let mapper = CapabilityMapper::empty();
    assert_eq!(mapper.trait_definitions_count(), 0);
    assert_eq!(mapper.composite_rules_count(), 0);
}

#[test]
fn test_new_mapper() {
    let mapper = CapabilityMapper::new_without_validation();
    // Test constructor should be hermetic unless a test opts into a traits directory.
    assert_eq!(mapper.trait_definitions_count(), 0);
}

#[test]
fn test_with_platforms() {
    let mapper = CapabilityMapper::empty().with_platforms(vec![Platform::MacOS, Platform::Linux]);

    // Should accept the platforms (can't directly test private field, but verify construction)
    assert_eq!(mapper.trait_definitions_count(), 0);
}

#[test]
fn test_with_platforms_empty_defaults_to_all() {
    let mapper = CapabilityMapper::empty().with_platforms(vec![]);
    // Should default to Platform::All when empty vec is provided
    assert_eq!(mapper.trait_definitions_count(), 0);
}

#[test]
fn test_with_platforms_filters_index_but_keeps_definitions() {
    // One Linux-only and one Windows-only standalone trait, each with a distinct
    // raw substring pattern.
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/linux::marker"
    desc: "Linux marker"
    crit: baseline
    platforms: [linux]
    if:
      type: text
      substr: "linux_only_pattern"
  - id: "test/windows::marker"
    desc: "Windows marker"
    crit: baseline
    platforms: [windows]
    if:
      type: text
      substr: "windows_only_pattern"
"#;
    let (_dir, path) = create_test_yaml(yaml);

    let full = CapabilityMapper::from_yaml(&path).unwrap();
    let full_patterns = full.match_indexes().string_match_index.total_patterns;
    assert_eq!(full.trait_definitions_count(), 2);

    let linux = CapabilityMapper::from_yaml(&path)
        .unwrap()
        .with_platforms(vec![Platform::Linux]);

    // Definitions stay whole, so composites referencing either trait still resolve.
    assert_eq!(linux.trait_definitions_count(), 2);
    assert!(linux.find_trait("test/windows::marker").is_some());

    // ...but the Windows-only pattern is excluded from the match index, so a Linux
    // scan never pays to match it.
    assert!(
        linux.match_indexes().string_match_index.total_patterns < full_patterns,
        "expected platform filter to drop off-platform patterns: {} !< {}",
        linux.match_indexes().string_match_index.total_patterns,
        full_patterns
    );
}

#[test]
fn test_from_yaml_with_trait() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/simple::basic"
    desc: "Basic test trait"
    crit: baseline
    if:
      type: text
      substr: "test_pattern"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    assert_eq!(mapper.trait_definitions_count(), 1);
    let trait_def = mapper.find_trait("test/simple::basic");
    assert!(trait_def.is_some());
    assert_eq!(trait_def.unwrap().desc, "Basic test trait");
}

#[test]
fn test_from_yaml_with_composite_rule() {
    let yaml = r#"
composite_rules:
  - id: "test/composite::multi"
    desc: "Composite test rule"
    crit: notable
    any:
      - id: "test/trait1::check"
      - id: "test/trait2::check"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    assert_eq!(mapper.composite_rules_count(), 1);
}

#[test]
fn test_from_yaml_invalid_yaml() {
    let yaml = "invalid: [unclosed array";
    let (_dir, path) = create_test_yaml(yaml);
    let result = CapabilityMapper::from_yaml(&path);

    assert!(result.is_err());
}

#[test]
fn test_from_yaml_empty_file() {
    let yaml = "";
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    // Empty YAML should create empty mapper
    assert_eq!(mapper.trait_definitions_count(), 0);
}

#[test]
fn test_evaluate_traits_empty_report() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/simple::basic"
    desc: "Basic test trait"
    crit: baseline
    if:
      type: text
      substr: "test_pattern"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let report = create_test_report();

    let findings = mapper.evaluate_traits(&report, b"");
    // No matches expected for empty content
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_evaluate_traits_string_match() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/simple::string_check"
    desc: "String pattern match"
    crit: notable
    conf: 0.9
    if:
      type: text
      substr: "malicious_pattern"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    // Verify the trait was loaded
    assert_eq!(mapper.trait_definitions_count(), 1);

    let binary_data = b"This contains malicious_pattern in the binary";
    let mut report = create_test_report_with_size(binary_data.len() as u64);

    // Add the string to the report so it can be matched
    report.strings.push(crate::types::StringInfo {
        value: ("This contains malicious_pattern in the binary".to_string()).into(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let findings = mapper.evaluate_traits(&report, binary_data);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "test/simple::string_check");
    assert_eq!(findings[0].crit, Criticality::Notable);
}

#[test]
fn test_evaluate_traits_regex_match() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/regex::pattern"
    desc: "Regex pattern match"
    crit: suspicious
    if:
      type: text
      regex: "eval\\s*\\("
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let mut report = create_test_report();

    let binary_data = b"code uses eval(malicious_code)";
    report.strings.push(crate::types::StringInfo {
        value: ("code uses eval(malicious_code)".to_string()).into(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let findings = mapper.evaluate_traits(&report, binary_data);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "test/regex::pattern");
}

#[test]
fn test_evaluate_traits_file_type_filter() {
    let yaml = r#"
traits:
  - id: "test/python::import"
    desc: "Python import"
    crit: baseline
    for:
      - python
    if:
      type: text
      substr: "import os"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    let mut report = create_test_report();
    report.target.file_type = "python".to_string();

    let binary_data = b"import os\nprint('test')";
    report.strings.push(crate::types::StringInfo {
        value: ("import os\nprint('test')".to_string()).into(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let findings = mapper.evaluate_traits(&report, binary_data);

    // Should match since file_type is python
    assert_eq!(findings.len(), 1);
}

#[test]
fn test_evaluate_traits_file_type_mismatch() {
    let yaml = r#"
traits:
  - id: "test/python::import"
    desc: "Python import"
    crit: baseline
    for:
      - python
    if:
      type: text
      substr: "import os"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    let mut report = create_test_report();
    report.target.file_type = "javascript".to_string();

    let binary_data = b"import os\nprint('test')";
    let findings = mapper.evaluate_traits(&report, binary_data);

    // Should NOT match since file_type is javascript, not python
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_symbol_lookup_respects_file_type() {
    // A `for: [dll]` symbol trait must not fire on an ELF file â€” file-type
    // filtering applies to symbol traits like every other kind.
    let yaml = r#"
defaults:
  for: [dll]
  platforms: [windows]
traits:
  - id: "test/dll-only::textdomain"
    desc: "DLL-only symbol"
    crit: notable
    conf: 0.9
    for: [dll]
    if:
      type: symbol
      exact: "textdomain"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    // Verify via full evaluation on an ELF report
    let mut report = create_test_report();
    report.target.file_type = "elf".to_string();
    report
        .imports
        .push(crate::types::Import::new("textdomain", None));

    let findings = mapper.evaluate_traits(&report, b"");
    assert!(
        !findings.iter().any(|f| f.id.contains("textdomain")),
        "DLL-only symbol trait should not fire on ELF file"
    );
}

#[test]
fn test_evaluate_composite_rules_empty() {
    let mapper = CapabilityMapper::empty();
    let report = create_test_report();

    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default(), None);
    assert_eq!(findings.len(), 0);
}

#[test]
fn test_evaluate_and_merge_findings() {
    // A symbol trait (matched against an import) and a text trait both fire
    // through the single evaluation pass â€” symbol matching flows through the
    // trait engine, not a separate lookup path.
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/mem::malloc"
    desc: "Allocate memory"
    crit: notable
    if:
      type: symbol
      exact: "malloc"
  - id: "test/string::check"
    desc: "String check"
    crit: notable
    if:
      type: text
      substr: "test_marker"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    let mut report = create_test_report();
    // Add malloc as an import
    use crate::types::Import;
    report.imports.push(Import {
        symbol: "malloc".to_string(),
        library: Some("libc".to_string()),
        offset: None,
        alias: None,
    });

    let binary_data = b"some binary with test_marker inside";
    report.strings.push(crate::types::StringInfo {
        value: ("some binary with test_marker inside".to_string()).into(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    mapper.evaluate_and_merge_findings(&mut report, binary_data, None, None);

    // The symbol trait (matched on the malloc import) fires...
    assert!(report.findings.iter().any(|f| f.id == "test/mem::malloc"));
    // ...and so does the text trait.
    assert!(report.findings.iter().any(|f| f.id == "test/string::check"));
}

#[test]
fn test_find_trait() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/finder::target"
    desc: "Target trait"
    crit: baseline
    if:
      type: text
      substr: "test"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    let trait_def = mapper.find_trait("test/finder::target");
    assert!(trait_def.is_some());
    assert_eq!(trait_def.unwrap().desc, "Target trait");

    let nonexistent = mapper.find_trait("nonexistent::trait");
    assert!(nonexistent.is_none());
}

#[test]
fn test_trait_definitions() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/one::first"
    desc: "First trait"
    crit: baseline
    if:
      type: text
      substr: "first"

  - id: "test/two::second"
    desc: "Second trait"
    crit: notable
    if:
      type: text
      substr: "second"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    let definitions = mapper.trait_definitions();
    assert_eq!(definitions.len(), 2);

    let ids: Vec<&str> = definitions.iter().map(|t| t.id.as_str()).collect();
    assert!(ids.contains(&"test/one::first"));
    assert!(ids.contains(&"test/two::second"));
}

#[test]
fn test_from_directory_nonexistent() {
    let result = CapabilityMapper::from_directory("/nonexistent/path/to/traits");
    assert!(result.is_err());
}

#[test]
fn test_composite_rules_count() {
    let yaml = r#"
composite_rules:
  - id: "test/comp1::rule"
    desc: "Rule 1"
    crit: notable
    any:
      - id: "test::trait1"

  - id: "test/comp2::rule"
    desc: "Rule 2"
    crit: suspicious
    all:
      - id: "test::trait2"
      - id: "test::trait3"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    assert_eq!(mapper.composite_rules_count(), 2);
}

#[test]
fn test_evaluate_traits_with_count_constraint() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/count::multiple"
    desc: "Multiple occurrences"
    crit: suspicious
    count_min: 3
    if:
      type: text
      substr: "keyword"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let mut report = create_test_report();

    // Test with 2 separate strings containing keyword (should NOT match)
    let binary_data = b"keyword appears keyword here";
    report.strings.push(crate::types::StringInfo {
        value: ("keyword".to_string()).into(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(crate::types::StringInfo {
        value: ("keyword".to_string()).into(),
        offset: Some(16),
        encoding: "ascii".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let findings = mapper.evaluate_traits(&report, binary_data);
    assert_eq!(findings.len(), 0, "Should not match with only 2 strings");

    // Test with 3 separate strings containing keyword (should match)
    let binary_data = b"keyword appears keyword here and keyword again";
    report.strings.clear();
    report.strings.push(crate::types::StringInfo {
        value: ("keyword".to_string()).into(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(crate::types::StringInfo {
        value: ("keyword".to_string()).into(),
        offset: Some(16),
        encoding: "ascii".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(crate::types::StringInfo {
        value: ("keyword".to_string()).into(),
        offset: Some(33),
        encoding: "ascii".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let findings = mapper.evaluate_traits(&report, binary_data);
    assert_eq!(findings.len(), 1, "Should match with 3 strings");
}

#[test]
fn test_evaluate_traits_case_insensitive() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/case::insensitive"
    desc: "Case insensitive match"
    crit: baseline
    if:
      type: text
      substr: "password"
      case_insensitive: true
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let mut report = create_test_report();

    let binary_data = b"Enter your PASSWORD here";
    report.strings.push(crate::types::StringInfo {
        value: ("Enter your PASSWORD here".to_string()).into(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let findings = mapper.evaluate_traits(&report, binary_data);

    assert_eq!(findings.len(), 1);
}

#[test]
fn test_precision_thresholds() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/mem::malloc"
    desc: "malloc"
    crit: notable
    if:
      type: symbol
      exact: "malloc"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper =
        CapabilityMapper::from_yaml_with_precision_thresholds(&path, 5.0, 3.0, false).unwrap();

    assert_eq!(mapper.trait_definitions_count(), 1);
}

#[test]
fn test_from_yaml_with_defaults() {
    let yaml = r#"
defaults:
  for: [all]
  crit: suspicious
  attack: "T1059.001"

traits:
  - id: "test/defaults::check"
    desc: "Test trait using default configuration values"
    if:
      type: text
      substr: "test"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    let trait_def = mapper.find_trait("test/defaults::check").unwrap();
    // Defaults should be applied
    assert_eq!(trait_def.crit, Criticality::Suspicious);
}

#[test]
fn test_evaluate_traits_with_section_filter() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/section::text"
    desc: "Pattern in .text section"
    crit: notable
    if:
      type: text
      substr: "code_pattern"
      section: ".text"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    let mut report = create_test_report();
    // Add a .text section with the pattern
    use crate::types::Section;
    report.sections.push(Section {
        name: ".text".to_string(),
        address: Some(0x1000),
        offset: None,
        size: 100,
        entropy: 5.5,
        permissions: Some("rx".to_string()),
        flags: Vec::new(),
    });

    let binary_data = b"some code_pattern in text section";
    report.strings.push(crate::types::StringInfo {
        value: ("some code_pattern in text section".to_string()).into(),
        offset: Some(0x1000), // Offset in .text section
        encoding: "ascii".to_string(),
        string_type: None,
        section: Some(".text".to_string()),
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let findings = mapper.evaluate_traits(&report, binary_data);

    // Should match if section exists
    assert!(findings.len() > 0);
}

/// Test that atomic traits can depend on other atomic traits via `trait:` conditions.
/// This is a regression test for the evaluation order bug where traits evaluated in
/// parallel couldn't see each other's results.
#[test]
fn test_evaluate_traits_with_trait_dependency() {
    // Create two traits: A depends on B via `trait:` condition
    // Both are atomic traits that should be evaluated together
    let yaml = r#"
defaults:
  for: [all]

traits:
  # Base trait - detects a string pattern
  - id: "test/base::string-marker"
    desc: "Base trait that matches a string"
    crit: baseline
    conf: 0.9
    if:
      type: text
      exact: "MARKER_STRING"

  # Dependent trait - depends on the base trait
  - id: "test/derived::depends-on-marker"
    desc: "Trait that depends on base trait"
    crit: notable
    conf: 0.9
    if:
      type: trait
      id: "test/base::string-marker"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    // Verify both traits were loaded
    assert_eq!(mapper.trait_definitions_count(), 2);

    let binary_data = b"MARKER_STRING";
    let mut report = create_test_report_with_size(binary_data.len() as u64);

    // Add the string to the report
    report.strings.push(crate::types::StringInfo {
        value: ("MARKER_STRING".to_string()).into(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    // Use evaluate_and_merge_findings which is the production code path
    mapper.evaluate_and_merge_findings(&mut report, binary_data, None, None);

    // Both traits should match:
    // 1. Base trait matches the string
    // 2. Derived trait should see the base trait's finding and also match
    let base_found = report
        .findings
        .iter()
        .any(|f| f.id == "test/base::string-marker");
    let derived_found = report
        .findings
        .iter()
        .any(|f| f.id == "test/derived::depends-on-marker");

    assert!(
        base_found,
        "Base trait should match the MARKER_STRING pattern"
    );
    assert!(
        derived_found,
        "Derived trait should match because base trait matched (trait dependency bug)"
    );
}

/// Test multi-level trait dependencies (A -> B -> C)
#[test]
fn test_evaluate_traits_with_chained_dependency() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  # Level 1: Base trait
  - id: "test/chain::level1"
    desc: "Level 1 base trait"
    crit: baseline
    conf: 0.9
    if:
      type: text
      exact: "CHAIN_START"

  # Level 2: Depends on level 1
  - id: "test/chain::level2"
    desc: "Level 2 depends on level 1"
    crit: baseline
    conf: 0.9
    if:
      type: trait
      id: "test/chain::level1"

  # Level 3: Depends on level 2
  - id: "test/chain::level3"
    desc: "Level 3 depends on level 2"
    crit: notable
    conf: 0.9
    if:
      type: trait
      id: "test/chain::level2"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    assert_eq!(mapper.trait_definitions_count(), 3);

    let binary_data = b"CHAIN_START";
    let mut report = create_test_report_with_size(binary_data.len() as u64);

    report.strings.push(crate::types::StringInfo {
        value: ("CHAIN_START".to_string()).into(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    mapper.evaluate_and_merge_findings(&mut report, binary_data, None, None);

    // All three levels should match
    let level1_found = report.findings.iter().any(|f| f.id == "test/chain::level1");
    let level2_found = report.findings.iter().any(|f| f.id == "test/chain::level2");
    let level3_found = report.findings.iter().any(|f| f.id == "test/chain::level3");

    assert!(level1_found, "Level 1 should match the string pattern");
    assert!(level2_found, "Level 2 should match because level 1 matched");
    assert!(
        level3_found,
        "Level 3 should match because level 2 matched (chained dependency)"
    );
}

/// Retroactive unless-suppression: atomic trait with `unless: [composite-id]`.
///
/// When an atomic trait's `unless:` condition references a composite rule, the
/// composite is not in `report.findings` at atomic evaluation time (Steps 1-2).
/// The engine's Step 6 retroactive pass must re-check and suppress the finding
/// after all composites have fired.
#[test]
fn test_retroactive_unless_suppression_atomic_with_composite_ref() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/packer::signal-a"
    desc: "Packer signal A"
    crit: baseline
    conf: 0.9
    if:
      type: text
      substr: "SIGNAL_A"

  - id: "test/packer::signal-b"
    desc: "Packer signal B"
    crit: baseline
    conf: 0.9
    if:
      type: text
      substr: "SIGNAL_B"

  # This atomic fires on a common string, but should be SUPPRESSED when the
  # packer composite fires â€” i.e., when it's a legitimate packed binary.
  - id: "test/victim::generic-api"
    desc: "Generic API (suppressed when packer detected)"
    crit: suspicious
    conf: 0.9
    if:
      type: text
      substr: "GENERIC_API"
    unless:
      - id: test/packer::combined

composite_rules:
  - id: "test/packer::combined"
    desc: "Both packer signals present"
    crit: notable
    conf: 0.9
    all:
      - id: test/packer::signal-a
      - id: test/packer::signal-b
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    // All three strings present: both packer signals + the generic API string.
    // combined composite should fire; generic-api should be retroactively suppressed.
    let binary_data = b"SIGNAL_A SIGNAL_B GENERIC_API";
    let mut report = create_test_report_with_size(binary_data.len() as u64);
    for s in ["SIGNAL_A", "SIGNAL_B", "GENERIC_API"] {
        report.strings.push(crate::types::StringInfo {
            value: (s.to_string()).into(),
            offset: Some(0),
            encoding: "ascii".to_string(),
            string_type: None,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        });
    }

    mapper.evaluate_and_merge_findings(&mut report, binary_data, None, None);

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "test/packer::signal-a"),
        "signal-a should fire"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "test/packer::signal-b"),
        "signal-b should fire"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "test/packer::combined"),
        "combined composite should fire"
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "test/victim::generic-api"),
        "generic-api should be retroactively suppressed by unless: test/packer::combined"
    );
}

/// Retroactive unless-suppression: atomic fires normally when suppressor composite is absent.
#[test]
fn test_retroactive_unless_suppression_fires_when_suppressor_absent() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/packer::signal-a"
    desc: "Packer signal A"
    crit: baseline
    conf: 0.9
    if:
      type: text
      substr: "SIGNAL_A"

  - id: "test/packer::signal-b"
    desc: "Packer signal B"
    crit: baseline
    conf: 0.9
    if:
      type: text
      substr: "SIGNAL_B"

  - id: "test/victim::generic-api"
    desc: "Generic API (suppressed when packer detected)"
    crit: suspicious
    conf: 0.9
    if:
      type: text
      substr: "GENERIC_API"
    unless:
      - id: test/packer::combined

composite_rules:
  - id: "test/packer::combined"
    desc: "Both packer signals present"
    crit: notable
    conf: 0.9
    all:
      - id: test/packer::signal-a
      - id: test/packer::signal-b
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    // Only GENERIC_API present: combined composite does NOT fire; generic-api should fire.
    let binary_data = b"GENERIC_API";
    let mut report = create_test_report_with_size(binary_data.len() as u64);
    report.strings.push(crate::types::StringInfo {
        value: ("GENERIC_API".to_string()).into(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    mapper.evaluate_and_merge_findings(&mut report, binary_data, None, None);

    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "test/packer::combined"),
        "combined composite should not fire (only one signal)"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "test/victim::generic-api"),
        "generic-api should fire when suppressor composite is absent"
    );
}

/// Retroactive unless-suppression: composite with `unless: [other-composite]`.
///
/// Two composites evaluated in parallel in Pass 1 of Step 4 both fire. One
/// has `unless: [other-composite]`. Because they're evaluated in parallel, the
/// `unless:` check is skipped (the other composite isn't in `all_findings` yet).
/// Step 6 must retroactively suppress it.
#[test]
fn test_retroactive_unless_suppression_composite_with_composite_ref() {
    let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "test/base::signal-a"
    desc: "Signal A"
    crit: baseline
    conf: 0.9
    if:
      type: text
      substr: "SIGNAL_A"

  - id: "test/base::signal-b"
    desc: "Signal B"
    crit: baseline
    conf: 0.9
    if:
      type: text
      substr: "SIGNAL_B"

  - id: "test/base::signal-c"
    desc: "Signal C (used by victim composite)"
    crit: baseline
    conf: 0.9
    if:
      type: text
      substr: "SIGNAL_C"

composite_rules:
  # Suppressor: fires when both A and B are present.
  - id: "test/suppressor::combined"
    desc: "Combined suppressor"
    crit: notable
    conf: 0.9
    all:
      - id: test/base::signal-a
      - id: test/base::signal-b

  # Victim: fires when C is present, but suppressed when suppressor fires.
  - id: "test/victim::composite"
    desc: "Victim composite (suppressed by combined)"
    crit: suspicious
    conf: 0.9
    unless:
      - id: test/suppressor::combined
    any:
      - id: test/base::signal-c
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    // All three signals: suppressor fires, victim should be retroactively suppressed.
    let binary_data = b"SIGNAL_A SIGNAL_B SIGNAL_C";
    let mut report = create_test_report_with_size(binary_data.len() as u64);
    for s in ["SIGNAL_A", "SIGNAL_B", "SIGNAL_C"] {
        report.strings.push(crate::types::StringInfo {
            value: (s.to_string()).into(),
            offset: Some(0),
            encoding: "ascii".to_string(),
            string_type: None,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        });
    }

    mapper.evaluate_and_merge_findings(&mut report, binary_data, None, None);

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "test/suppressor::combined"),
        "combined suppressor should fire"
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "test/victim::composite"),
        "victim composite should be retroactively suppressed by unless: test/suppressor::combined"
    );
}

#[test]
fn test_source_text_traits_do_not_use_extracted_string_prefilter() {
    let yaml = r#"
defaults:
  platforms: [unix, windows]
  for: [javascript]

traits:
  - id: "test/source::native-addon-require"
    desc: "Requires prebuilt native addon"
    crit: suspicious
    conf: 0.9
    if:
      type: text
      regex: "require\\(['\"]\\./prebuilt/[^'\"\\n]{1,120}\\.node['\"]\\)"

  - id: "test/source::version-facade"
    desc: "Exports version facade only"
    crit: suspicious
    conf: 0.9
    if:
      type: text
      substr: "module.exports = { version: require('./package.json').version }"

composite_rules:
  - id: "test/source::native-addon-loader"
    desc: "Version facade native addon loader"
    crit: hostile
    conf: 0.95
    all:
      - id: test/source::native-addon-require
      - id: test/source::version-facade
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    let source = concat!(
        "try { require('./prebuilt/addon.node') } catch(e) {}\n",
        "module.exports = { version: require('./package.json').version }\n"
    );
    let mut report = create_test_source_report("index.js", "javascript", source.len() as u64);

    // Mimic source analyzer output: string literals are extracted, but the raw-text
    // source patterns should still be evaluated against the full source content.
    for value in ["./prebuilt/addon.node", "./package.json"] {
        report.strings.push(crate::types::StringInfo {
            value: (value.to_string()).into(),
            offset: Some(0),
            encoding: "utf-8".to_string(),
            string_type: None,
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        });
    }

    mapper.evaluate_and_merge_findings(&mut report, source.as_bytes(), None, None);

    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "test/source::native-addon-require"),
        "source text regex trait should be emitted from raw source text"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "test/source::version-facade"),
        "source text substr trait should be emitted from raw source text"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "test/source::native-addon-loader"),
        "composite depending on raw source text traits should also fire"
    );
}

/// Regression guard: building the match indexes must not happen while the
/// `indexes` `OnceLock` is held.
///
/// `MatchIndexes::build` fans out across the global rayon pool. While the cell
/// was filled with `get_or_init(|| MatchIndexes::build(..))`, every rayon worker
/// that reached trait matching parked on the cell waiting for the winner, and the
/// winner sat waiting for a free worker to finish its parallel build â€” a cycle
/// with no way out. In production a traits reload republished an unwarmed mapper
/// mid-scan, the first build landed with the pool already saturated, and workers
/// wedged for days while still heartbeating.
///
/// This saturates the pool with callers of the cell plus one off-pool caller (the
/// shape a reload creates) and requires the whole set to finish. The timeout turns
/// a reintroduced deadlock into a failure instead of a hung CI job.
#[test]
fn match_indexes_survives_saturated_rayon_pool() {
    let mapper = std::sync::Arc::new(CapabilityMapper::new_without_validation());
    let callers = rayon::current_num_threads().max(2);

    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::sync::Arc::clone(&mapper);
    std::thread::spawn(move || {
        // `scope` blocks this off-pool thread on a rayon latch, so the pool must
        // make progress for it to return â€” exactly the production dependency.
        rayon::scope(|s| {
            for _ in 0..callers {
                let m = std::sync::Arc::clone(&spawned);
                s.spawn(move |_| {
                    let _ = m.match_indexes();
                });
            }
        });
        let _ = spawned.match_indexes();
        let _ = tx.send(());
    });

    assert!(
        rx.recv_timeout(std::time::Duration::from_secs(120)).is_ok(),
        "match_indexes deadlocked with every rayon worker contending on the cell"
    );

    // All callers must agree on one published set of indexes.
    let ptr = std::ptr::from_ref(mapper.match_indexes());
    assert!(
        std::ptr::eq(ptr, std::ptr::from_ref(mapper.match_indexes())),
        "match_indexes must publish a single shared build"
    );
}

fn pad_source(mut src: String) -> String {
    while src.len() < 100 {
        src.push_str("// pad\n");
    }
    src
}

#[test]
fn source_text_regex_atom_only_does_not_fire() {
    let yaml = r#"
defaults:
  for: [javascript]
traits:
  - id: "test/source-text::eval-call"
    desc: "eval call"
    crit: notable
    if:
      type: text
      regex: '\beval\s*\('
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let source = pad_source(String::from("let x = eval; // mention only\n"));
    let mut report = create_test_source_report("probe.js", "javascript", source.len() as u64);
    mapper.evaluate_and_merge_findings(&mut report, source.as_bytes(), None, None);
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "test/source-text::eval-call"),
        "atom-only eval mention must not fire: {:?}",
        report
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn source_text_regex_unless_does_not_reuse_if_verify() {
    let yaml = r#"
defaults:
  for: [javascript]
traits:
  - id: "test/source-text::unless-reuse"
    desc: "if atom must not satisfy unless"
    crit: notable
    if:
      type: text
      regex: "GATEVERIFY_IF_ATOM_xyz123"
    unless:
      - type: text
        regex: "GATEVERIFY_UNLESS_ATOM_abc456"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let source = pad_source(String::from("GATEVERIFY_IF_ATOM_xyz123\n"));
    let mut report = create_test_source_report("probe.js", "javascript", source.len() as u64);
    mapper.evaluate_and_merge_findings(&mut report, source.as_bytes(), None, None);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "test/source-text::unless-reuse"),
        "unless pattern is absent; if: must still fire: {:?}",
        report
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect::<Vec<_>>()
    );

    let both = pad_source(String::from(
        "GATEVERIFY_IF_ATOM_xyz123\nGATEVERIFY_UNLESS_ATOM_abc456\n",
    ));
    let mut report_both = create_test_source_report("probe.js", "javascript", both.len() as u64);
    mapper.evaluate_and_merge_findings(&mut report_both, both.as_bytes(), None, None);
    assert!(
        !report_both
            .findings
            .iter()
            .any(|f| f.id == "test/source-text::unless-reuse"),
        "unless pattern present must suppress: {:?}",
        report_both
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect::<Vec<_>>()
    );
}

#[test]
fn source_text_regex_decoded_only_still_fires() {
    let yaml = r#"
defaults:
  for: [javascript]
traits:
  - id: "test/source-text::decoded-regex"
    desc: "needle only after decode"
    crit: notable
    if:
      type: text
      regex: "ZXQ_DECODED_REGEX_NEEDLE_9c4a"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let source = pad_source(String::from("const x = 1;\n"));
    assert!(!source.contains("ZXQ_DECODED_REGEX_NEEDLE_9c4a"));
    let mut report = create_test_source_report("index.js", "javascript", source.len() as u64);
    report.strings.push(crate::types::StringInfo {
        value: "ZXQ_DECODED_REGEX_NEEDLE_9c4a".to_string().into(),
        offset: Some(0),
        encoding: "utf-8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: vec!["base64".to_string()],
        fragments: None,
    });
    mapper.evaluate_and_merge_findings(&mut report, source.as_bytes(), None, None);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "test/source-text::decoded-regex"),
        "decoded-only regex must survive raw-gate miss"
    );
}

#[test]
fn source_text_regex_length_min_still_filters() {
    let yaml = r#"
defaults:
  for: [javascript]
traits:
  - id: "test/source-text::len-min"
    desc: "span too short"
    crit: notable
    if:
      type: text
      regex: "GATEVERIFY_LEN_[A-Z]+"
      length_min: 40
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let source = pad_source(String::from("GATEVERIFY_LEN_SHORT\n"));
    let mut report = create_test_source_report("probe.js", "javascript", source.len() as u64);
    mapper.evaluate_and_merge_findings(&mut report, source.as_bytes(), None, None);
    assert!(
        !report
            .findings
            .iter()
            .any(|f| f.id == "test/source-text::len-min"),
        "gate is_match must not bypass length_min: {:?}",
        report
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect::<Vec<_>>()
    );

    let long = pad_source(String::from("GATEVERIFY_LEN_ABCDEFGHIJKLMNOPQRSTUVWXYZ\n"));
    let mut report_ok = create_test_source_report("probe.js", "javascript", long.len() as u64);
    mapper.evaluate_and_merge_findings(&mut report_ok, long.as_bytes(), None, None);
    assert!(
        report_ok
            .findings
            .iter()
            .any(|f| f.id == "test/source-text::len-min"),
        "span meeting length_min must fire"
    );
}

/// Specimen from dscodegpt `extension/toggle-main.js` (571 B). Official scan
/// JSON omits `path-join-dirname` / `useragent-variable-branch-call` even
/// though the bytes match those YAML regexes. This locks whether `evaluate`
/// itself matches before `strip_unmatched_traits`.
const TOGGLE_MAIN_JS: &str = r#"#!/usr/bin/env node

const fs = require('fs')
const path = require('path')

const target = process.argv[2]

if (!target || !['src', 'dist'].includes(target)) {
  console.error('Usage: node toggle-main.js <src|dist>')
  process.exit(1)
}

const packageJsonPath = path.join(__dirname, 'package.json')
const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'))

packageJson.main = `./${target}/extension.js`

fs.writeFileSync(packageJsonPath, JSON.stringify(packageJson, null, 2) + '\n')

console.log(`Updated package.json main to: ./${target}/extension.js`)
"#;

fn finding_ids(report: &AnalysisReport) -> Vec<String> {
    let mut ids: Vec<String> = report
        .findings
        .iter()
        .map(|f| format!("{}#{}", f.id, f.crit.rank()))
        .collect();
    ids.sort();
    ids
}

#[test]
fn toggle_main_isolated_text_regexes_match_bytes() {
    let yaml = r#"
defaults:
  platforms: [windows, unix]
  for: [javascript, typescript]
traits:
  - id: path-join-dirname
    desc: path.join with __dirname
    crit: baseline
    conf: 0.5
    if:
      type: text
      regex: 'path\.join\s*\(\s*__dirname'
  - id: useragent-variable-branch-call
    desc: Calls a matcher in a conditional expression
    crit: component
    conf: 0.88
    if:
      type: text
      regex: '(?i)\b(if|while)\s*\([^;\r\n]{0,120}\b(test|includes|match|indexOf)\s*\('
composite_rules:
  - id: javascript-local-path
    desc: JavaScript constructs a local script path
    crit: baseline
    conf: 0.7
    any:
      - id: path-join-dirname
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let mut report = create_test_source_report(
        "toggle-main.js",
        "javascript",
        TOGGLE_MAIN_JS.len() as u64,
    );
    mapper.evaluate_and_merge_findings(&mut report, TOGGLE_MAIN_JS.as_bytes(), None, None);
    let before = finding_ids(&report);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id.ends_with("path-join-dirname")),
        "eval must match path.join(__dirname): {before:?}"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id.ends_with("useragent-variable-branch-call")),
        "eval must match if (...includes(: {before:?}"
    );
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id.ends_with("javascript-local-path")),
        "composite any: path-join-dirname must fire: {before:?}"
    );

    report.strip_unmatched_traits();
    let after = finding_ids(&report);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id.ends_with("path-join-dirname")),
        "referenced baseline must survive strip when no notable+ signal: {after:?}"
    );
}

#[test]
#[ignore = "loads the production traits tree; diagnostic for strip vs evaluate"]
fn toggle_main_production_traits_before_and_after_strip() {
    let traits_dir = dirs::data_dir()
        .unwrap()
        .join("atomdrift")
        .join("cleave")
        .join("traits");
    if !traits_dir.join("micro-behaviors").is_dir() {
        eprintln!("skip: production traits missing at {}", traits_dir.display());
        return;
    }
    let mapper = CapabilityMapper::from_directory_with_options(
        &traits_dir,
        CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
        CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
        false,
        false,
    )
    .expect("load production traits");
    let mut report = create_test_source_report(
        "toggle-main.js",
        "javascript",
        TOGGLE_MAIN_JS.len() as u64,
    );
    mapper.evaluate_and_merge_findings(&mut report, TOGGLE_MAIN_JS.as_bytes(), None, None);
    let before: Vec<String> = report.findings.iter().map(|f| f.id.to_string()).collect();
    let had_path = before.iter().any(|id| id.ends_with("path-join-dirname"));
    let had_ua = before
        .iter()
        .any(|id| id.ends_with("useragent-variable-branch-call"));
    let had_local = before.iter().any(|id| id.ends_with("javascript-local-path"));
    eprintln!(
        "toggle-main production before strip ({}): path-join={} ua={} local={}\n{:#?}",
        before.len(),
        had_path,
        had_ua,
        had_local,
        before
    );
    report.strip_unmatched_traits();
    let after: Vec<String> = report.findings.iter().map(|f| f.id.to_string()).collect();
    eprintln!(
        "toggle-main production after strip ({}): {:#?}",
        after.len(),
        after
    );
    assert!(
        had_path,
        "production evaluate() should match path-join-dirname on these bytes: {before:?}"
    );
}

#[test]
#[ignore = "loads the production traits tree; diagnostic for AST+strip"]
fn toggle_main_source_analyzer_production_before_strip() {
    let traits_dir = dirs::data_dir()
        .unwrap()
        .join("atomdrift")
        .join("cleave")
        .join("traits");
    if !traits_dir.join("micro-behaviors").is_dir() {
        eprintln!("skip: production traits missing at {}", traits_dir.display());
        return;
    }
    let mapper = CapabilityMapper::from_directory_with_options(
        &traits_dir,
        CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
        CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
        false,
        false,
    )
    .expect("load production traits");
    let analyzer = crate::analyzers::unified::UnifiedSourceAnalyzer::for_file_type(
        &crate::analyzers::FileType::JavaScript,
    )
    .unwrap()
    .with_capability_mapper(mapper);
    let mut report = analyzer.analyze_source(std::path::Path::new("toggle-main.js"), TOGGLE_MAIN_JS);
    let before: Vec<String> = report.findings.iter().map(|f| f.id.to_string()).collect();
    eprintln!(
        "source-analyzer before strip ({}): path-join={} ua={} local={}\n{:#?}",
        before.len(),
        before.iter().any(|id| id.ends_with("path-join-dirname")),
        before
            .iter()
            .any(|id| id.ends_with("useragent-variable-branch-call")),
        before.iter().any(|id| id.ends_with("javascript-local-path")),
        before
    );
    report.strip_unmatched_traits();
    let after: Vec<String> = report.findings.iter().map(|f| f.id.to_string()).collect();
    eprintln!("source-analyzer after strip ({}): {:#?}", after.len(), after);
}

const DOOMED_SKIP_YAML: &str = r#"
defaults:
  platforms: [unix, windows]
  for: [javascript]
traits:
  - id: "test/doomed::assigned"
    desc: assigned partner
    crit: component
    if:
      type: text
      regex: 'DOOMED_ASSIGNED_ATOM_xyz123'
  - id: "test/doomed::branch"
    desc: weak branch
    crit: component
    if:
      type: text
      regex: '(?i)\b(if|while)\s*\([^;\r\n]{0,120}\b(test|includes|match|indexOf)\s*\('
  - id: "test/doomed::notable"
    desc: notable pad
    crit: notable
    if:
      type: text
      regex: 'DOOMED_NOTABLE_ATOM_abc456'
composite_rules:
  - id: "test/doomed::both"
    desc: requires assigned and branch
    crit: notable
    all:
      - id: "test/doomed::assigned"
      - id: "test/doomed::branch"
"#;

fn doomed_ids(report: &AnalysisReport) -> Vec<String> {
    let mut ids: Vec<String> = report.findings.iter().map(|f| f.id.to_string()).collect();
    ids.sort();
    ids
}

#[test]
fn doomed_skip_drops_branch_when_partner_atom_misses_and_notable_present() {
    let (_dir, path) = create_test_yaml(DOOMED_SKIP_YAML);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let source = pad_source(String::from(
        "if (x.includes(y)) {}\nDOOMED_NOTABLE_ATOM_abc456\n",
    ));
    let mut report = create_test_source_report("probe.js", "javascript", source.len() as u64);
    mapper.evaluate_and_merge_findings(&mut report, source.as_bytes(), None, None);
    let ids = doomed_ids(&report);
    assert!(
        ids.iter().any(|id| id.ends_with("::notable")),
        "notable must fire: {ids:?}"
    );
    assert!(
        !ids.iter().any(|id| id.ends_with("::branch")),
        "branch eval_raw must be skipped when assigned atom misses: {ids:?}"
    );
    assert!(
        !ids.iter().any(|id| id.ends_with("::both")),
        "all: composite cannot fire without assigned: {ids:?}"
    );
}

#[test]
fn doomed_skip_still_evaluates_when_both_partners_hit() {
    let (_dir, path) = create_test_yaml(DOOMED_SKIP_YAML);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let source = pad_source(String::from(
        "DOOMED_ASSIGNED_ATOM_xyz123\nif (x.includes(y)) {}\nDOOMED_NOTABLE_ATOM_abc456\n",
    ));
    let mut report = create_test_source_report("probe.js", "javascript", source.len() as u64);
    mapper.evaluate_and_merge_findings(&mut report, source.as_bytes(), None, None);
    let ids = doomed_ids(&report);
    assert!(
        ids.iter().any(|id| id.ends_with("::branch")),
        "branch must evaluate when assigned can match: {ids:?}"
    );
    assert!(
        ids.iter().any(|id| id.ends_with("::both")),
        "all: composite must fire: {ids:?}"
    );
}

#[test]
fn doomed_skip_rescues_branch_when_file_has_no_notable() {
    let (_dir, path) = create_test_yaml(DOOMED_SKIP_YAML);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let source = pad_source(String::from("if (x.includes(y)) {}\n"));
    let mut report = create_test_source_report("probe.js", "javascript", source.len() as u64);
    mapper.evaluate_and_merge_findings(&mut report, source.as_bytes(), None, None);
    let ids = doomed_ids(&report);
    assert!(
        ids.iter().any(|id| id.ends_with("::branch")),
        "rescue path must still evaluate doomed branch: {ids:?}"
    );
    let (file, _, _) = report.into_file_analysis(0);
    let mut wrapped = create_test_source_report("probe.js", "javascript", source.len() as u64);
    wrapped.files = vec![file];
    wrapped.strip_unmatched_traits();
    let after: Vec<String> = wrapped.files[0]
        .findings
        .iter()
        .map(|f| f.id.to_string())
        .collect();
    assert!(
        after.iter().any(|id| id.ends_with("::branch")),
        "rescued branch must survive strip when no notable+: {after:?}"
    );
}

#[test]
fn doomed_skip_does_not_skip_any_satisfier() {
    let yaml = r#"
defaults:
  platforms: [unix, windows]
  for: [javascript]
traits:
  - id: "test/doomed-any::assigned"
    desc: assigned partner
    crit: component
    if:
      type: text
      regex: 'DOOMED_ANY_ASSIGNED_ATOM_xyz123'
  - id: "test/doomed-any::branch"
    desc: weak branch
    crit: component
    if:
      type: text
      regex: '(?i)\b(if|while)\s*\([^;\r\n]{0,120}\b(test|includes|match|indexOf)\s*\('
  - id: "test/doomed-any::notable"
    desc: notable pad
    crit: notable
    if:
      type: text
      regex: 'DOOMED_ANY_NOTABLE_ATOM_abc456'
composite_rules:
  - id: "test/doomed-any::either"
    desc: any of assigned or branch
    crit: notable
    any:
      - id: "test/doomed-any::assigned"
      - id: "test/doomed-any::branch"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let source = pad_source(String::from(
        "if (x.includes(y)) {}\nDOOMED_ANY_NOTABLE_ATOM_abc456\n",
    ));
    let mut report = create_test_source_report("probe.js", "javascript", source.len() as u64);
    mapper.evaluate_and_merge_findings(&mut report, source.as_bytes(), None, None);
    let ids = doomed_ids(&report);
    assert!(
        ids.iter().any(|id| id.ends_with("::branch")),
        "any: satisfier must still evaluate when the other leg misses: {ids:?}"
    );
    assert!(
        ids.iter().any(|id| id.ends_with("::either")),
        "any: composite must fire from branch alone: {ids:?}"
    );
}

#[test]
fn doomed_skip_never_skips_unless_target() {
    let yaml = r#"
defaults:
  platforms: [unix, windows]
  for: [javascript]
traits:
  - id: "test/doomed-unless::partner"
    desc: partner that will miss
    crit: component
    if:
      type: text
      regex: 'DOOMED_UNLESS_PARTNER_ATOM_xyz'
  - id: "test/doomed-unless::target"
    desc: unless suppressor
    crit: component
    if:
      type: text
      regex: '(?i)\b(if|while)\s*\([^;\r\n]{0,120}\b(test|includes|match|indexOf)\s*\('
  - id: "test/doomed-unless::notable"
    desc: notable gated by unless
    crit: notable
    if:
      type: text
      regex: 'DOOMED_UNLESS_NOTABLE_ATOM_abc'
    unless:
      - id: "test/doomed-unless::target"
composite_rules:
  - id: "test/doomed-unless::comp"
    desc: would doom target if unless did not protect it
    crit: notable
    all:
      - id: "test/doomed-unless::partner"
      - id: "test/doomed-unless::target"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let source = pad_source(String::from(
        "if (x.includes(y)) {}\nDOOMED_UNLESS_NOTABLE_ATOM_abc\n",
    ));
    let mut report = create_test_source_report("probe.js", "javascript", source.len() as u64);
    mapper.evaluate_and_merge_findings(&mut report, source.as_bytes(), None, None);
    let ids = doomed_ids(&report);
    assert!(
        ids.iter().any(|id| id.ends_with("::target")),
        "unless target must still evaluate: {ids:?}"
    );
    assert!(
        !ids.iter().any(|id| id.ends_with("::notable")),
        "skipping the unless target would FP the notable: {ids:?}"
    );
}

/// A sibling member firing the composite must not force us to evaluate the
/// weak leg on a file whose partner atom missed. Official report-wide strip
/// would have kept that extra copy; the skip treats it as not local evidence.
#[test]
fn doomed_skip_does_not_create_sibling_rescued_copy() {
    let (_dir, path) = create_test_yaml(DOOMED_SKIP_YAML);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    let both = pad_source(String::from(
        "DOOMED_ASSIGNED_ATOM_xyz123\nif (x.includes(y)) {}\nDOOMED_NOTABLE_ATOM_abc456\n",
    ));
    let mut report_a = create_test_source_report("a.js", "javascript", both.len() as u64);
    mapper.evaluate_and_merge_findings(&mut report_a, both.as_bytes(), None, None);
    assert!(
        doomed_ids(&report_a)
            .iter()
            .any(|id| id.ends_with("::both")),
        "file A must fire the composite: {:?}",
        doomed_ids(&report_a)
    );

    let weak = pad_source(String::from(
        "if (x.includes(y)) {}\nDOOMED_NOTABLE_ATOM_abc456\n",
    ));
    let mut report_b = create_test_source_report("b.js", "javascript", weak.len() as u64);
    mapper.evaluate_and_merge_findings(&mut report_b, weak.as_bytes(), None, None);
    assert!(
        !doomed_ids(&report_b)
            .iter()
            .any(|id| id.ends_with("::branch")),
        "file B must not create the doomed branch: {:?}",
        doomed_ids(&report_b)
    );

    let (file_a, _, _) = report_a.into_file_analysis(0);
    let (mut file_b, _, _) = report_b.into_file_analysis(1);
    file_b.parent_id = Some(0);
    let mut wrapped = create_test_source_report("bundle.js", "javascript", 0);
    wrapped.files = vec![file_a, file_b];
    wrapped.strip_unmatched_traits();
    let b_ids: Vec<String> = wrapped.files[1]
        .findings
        .iter()
        .map(|f| f.id.to_string())
        .collect();
    assert!(
        !b_ids.iter().any(|id| id.ends_with("::branch")),
        "sibling composite must not resurrect a skipped branch: {b_ids:?}"
    );
    let a_ids: Vec<String> = wrapped.files[0]
        .findings
        .iter()
        .map(|f| f.id.to_string())
        .collect();
    assert!(
        a_ids.iter().any(|id| id.ends_with("::both")),
        "file A composite must survive: {a_ids:?}"
    );
}

