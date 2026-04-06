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

#[test]
fn test_empty_mapper() {
    let mapper = CapabilityMapper::empty();
    assert_eq!(mapper.mapping_count(), 0);
    assert_eq!(mapper.trait_definitions_count(), 0);
    assert_eq!(mapper.composite_rules_count(), 0);
}

#[test]
fn test_new_mapper() {
    let mapper = CapabilityMapper::new_without_validation();
    // Test constructor should be hermetic unless a test opts into a traits directory.
    assert_eq!(mapper.mapping_count(), 0);
    assert_eq!(mapper.trait_definitions_count(), 0);
}

#[test]
fn test_with_platforms() {
    let mapper = CapabilityMapper::empty().with_platforms(vec![Platform::MacOS, Platform::Linux]);

    // Should accept the platforms (can't directly test private field, but verify construction)
    assert_eq!(mapper.mapping_count(), 0);
}

#[test]
fn test_with_platforms_empty_defaults_to_all() {
    let mapper = CapabilityMapper::empty().with_platforms(vec![]);
    // Should default to Platform::All when empty vec is provided
    assert_eq!(mapper.mapping_count(), 0);
}

#[test]
fn test_from_yaml_minimal_symbol_map() {
    let yaml = r#"
symbols:
  - symbol: "malloc"
    capability: "micro-behaviors/mem/allocate::malloc"
    desc: "Allocate memory"
    conf: 0.9
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    assert_eq!(mapper.mapping_count(), 1);
    assert!(mapper.lookup("malloc", "libc").is_some());
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
      type: string_value
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
    assert_eq!(mapper.mapping_count(), 0);
    assert_eq!(mapper.trait_definitions_count(), 0);
}

#[test]
fn test_lookup_with_symbol() {
    let yaml = r#"
symbols:
  - symbol: "malloc"
    capability: "micro-behaviors/mem/allocate::malloc"
    desc: "Allocate memory"
    conf: 0.9
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    let finding = mapper.lookup("malloc", "libc").unwrap();
    assert_eq!(finding.id, "micro-behaviors/mem/allocate::malloc");
    assert_eq!(finding.desc, "Allocate memory");
    assert_eq!(finding.crit, Criticality::Baseline);
}

#[test]
fn test_lookup_nonexistent_symbol() {
    let mapper = CapabilityMapper::empty();
    let finding = mapper.lookup("nonexistent_func", "libfoo");
    assert!(finding.is_none());
}

#[test]
fn test_lookup_with_prefix_stripping() {
    let yaml = r#"
symbols:
  - symbol: "malloc"
    capability: "micro-behaviors/mem/allocate::malloc"
    desc: "Allocate memory"
    conf: 0.9
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    // Should strip common prefixes like '_', '__', etc.
    let finding = mapper.lookup("_malloc", "libc");
    assert!(finding.is_some());
    assert_eq!(finding.unwrap().id, "micro-behaviors/mem/allocate::malloc");
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
      type: string_value
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
      type: string_value
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
        value: "This contains malicious_pattern in the binary".to_string(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
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
      type: string_value
      regex: "eval\\s*\\("
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let mut report = create_test_report();

    let binary_data = b"code uses eval(malicious_code)";
    report.strings.push(crate::types::StringInfo {
        value: "code uses eval(malicious_code)".to_string(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
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
      type: string_value
      substr: "import os"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    let mut report = create_test_report();
    report.target.file_type = "python".to_string();

    let binary_data = b"import os\nprint('test')";
    report.strings.push(crate::types::StringInfo {
        value: "import os\nprint('test')".to_string(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
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
      type: string_value
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
    // Traits with restrictive for: constraints should not be in the symbol_map
    // fast-path, which bypasses file type filtering. Regression test for a bug
    // where `for: [dll]` symbol traits matched on ELF files via lookup().
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

    // The symbol_map should NOT contain this trait since it has for: [dll]
    assert!(
        mapper.lookup("textdomain", "test").is_none(),
        "symbol_map should not include traits with restrictive for: constraints"
    );

    // Also verify via full evaluation on an ELF report
    let mut report = create_test_report();
    report.target.file_type = "elf".to_string();
    report.imports.push(crate::types::Import::new("textdomain", None, "test"));

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
    let yaml = r#"
defaults:
  for: [all]

symbols:
  - symbol: "malloc"
    capability: "micro-behaviors/mem/allocate::malloc"
    desc: "Allocate memory"
    conf: 0.9

traits:
  - id: "test/string::check"
    desc: "String check"
    crit: notable
    if:
      type: string_value
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
        source: "static".to_string(),
    });

    // Manually lookup and add symbol findings
    for import in &report.imports {
        if let Some(finding) = mapper.lookup(&import.symbol, &import.source) {
            report.findings.push(finding);
        }
    }

    let binary_data = b"some binary with test_marker inside";
    report.strings.push(crate::types::StringInfo {
        value: "some binary with test_marker inside".to_string(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    mapper.evaluate_and_merge_findings(&mut report, binary_data, None, None);

    // Should have findings from both symbol lookup and trait evaluation
    assert!(report.findings.len() >= 2);

    // Verify we have the malloc capability
    assert!(report
        .findings
        .iter()
        .any(|f| f.id == "micro-behaviors/mem/allocate::malloc"));

    // Verify we have the string check trait
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
      type: string_value
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
      type: string_value
      substr: "first"

  - id: "test/two::second"
    desc: "Second trait"
    crit: notable
    if:
      type: string_value
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
fn test_mapping_count() {
    let yaml = r#"
symbols:
  - symbol: "malloc"
    capability: "micro-behaviors/mem::malloc"
    desc: "malloc"
    conf: 0.9
  - symbol: "free"
    capability: "micro-behaviors/mem::free"
    desc: "free"
    conf: 0.9
  - symbol: "calloc"
    capability: "micro-behaviors/mem::calloc"
    desc: "calloc"
    conf: 0.9
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();

    assert_eq!(mapper.mapping_count(), 3);
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
      type: string_value
      substr: "keyword"
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let mut report = create_test_report();

    // Test with 2 separate strings containing keyword (should NOT match)
    let binary_data = b"keyword appears keyword here";
    report.strings.push(crate::types::StringInfo {
        value: "keyword".to_string(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(crate::types::StringInfo {
        value: "keyword".to_string(),
        offset: Some(16),
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
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
        value: "keyword".to_string(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(crate::types::StringInfo {
        value: "keyword".to_string(),
        offset: Some(16),
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(crate::types::StringInfo {
        value: "keyword".to_string(),
        offset: Some(33),
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
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
      type: string_value
      substr: "password"
      case_insensitive: true
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper = CapabilityMapper::from_yaml(&path).unwrap();
    let mut report = create_test_report();

    let binary_data = b"Enter your PASSWORD here";
    report.strings.push(crate::types::StringInfo {
        value: "Enter your PASSWORD here".to_string(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
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
symbols:
  - symbol: "malloc"
    capability: "micro-behaviors/mem::malloc"
    desc: "malloc"
    conf: 0.9
"#;
    let (_dir, path) = create_test_yaml(yaml);
    let mapper =
        CapabilityMapper::from_yaml_with_precision_thresholds(&path, 5.0, 3.0, false).unwrap();

    assert_eq!(mapper.mapping_count(), 1);
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
      type: string_value
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
      type: string_value
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
    });

    let binary_data = b"some code_pattern in text section";
    report.strings.push(crate::types::StringInfo {
        value: "some code_pattern in text section".to_string(),
        offset: Some(0x1000), // Offset in .text section
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
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
      type: string_value
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
        value: "MARKER_STRING".to_string(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
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
      type: string_value
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
        value: "CHAIN_START".to_string(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
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
      type: string_value
      substr: "SIGNAL_A"

  - id: "test/packer::signal-b"
    desc: "Packer signal B"
    crit: baseline
    conf: 0.9
    if:
      type: string_value
      substr: "SIGNAL_B"

  # This atomic fires on a common string, but should be SUPPRESSED when the
  # packer composite fires — i.e., when it's a legitimate packed binary.
  - id: "test/victim::generic-api"
    desc: "Generic API (suppressed when packer detected)"
    crit: suspicious
    conf: 0.9
    if:
      type: string_value
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
            value: s.to_string(),
            offset: Some(0),
            encoding: "ascii".to_string(),
            string_type: crate::types::StringType::Const,
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
      type: string_value
      substr: "SIGNAL_A"

  - id: "test/packer::signal-b"
    desc: "Packer signal B"
    crit: baseline
    conf: 0.9
    if:
      type: string_value
      substr: "SIGNAL_B"

  - id: "test/victim::generic-api"
    desc: "Generic API (suppressed when packer detected)"
    crit: suspicious
    conf: 0.9
    if:
      type: string_value
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
        value: "GENERIC_API".to_string(),
        offset: Some(0),
        encoding: "ascii".to_string(),
        string_type: crate::types::StringType::Const,
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
      type: string_value
      substr: "SIGNAL_A"

  - id: "test/base::signal-b"
    desc: "Signal B"
    crit: baseline
    conf: 0.9
    if:
      type: string_value
      substr: "SIGNAL_B"

  - id: "test/base::signal-c"
    desc: "Signal C (used by victim composite)"
    crit: baseline
    conf: 0.9
    if:
      type: string_value
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
            value: s.to_string(),
            offset: Some(0),
            encoding: "ascii".to_string(),
            string_type: crate::types::StringType::Const,
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
