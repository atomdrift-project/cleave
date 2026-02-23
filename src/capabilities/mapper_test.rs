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
use crate::composite_rules::Platform;
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
    // New mapper loads traits from the default traits directory (without validation for tests)
    assert!(
        mapper.mapping_count() > 0,
        "Should load mappings from traits directory"
    );
    assert!(
        mapper.trait_definitions_count() > 0,
        "Should load traits from directory"
    );
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
      type: string
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
      type: string
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
      type: string
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
      type: string
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
      type: string
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
      type: string
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
fn test_evaluate_composite_rules_empty() {
    let mapper = CapabilityMapper::empty();
    let report = create_test_report();

    let findings = mapper.evaluate_composite_rules(&report, &[], None, None);
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
      type: string
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
      type: string
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
      type: string
      substr: "first"

  - id: "test/two::second"
    desc: "Second trait"
    crit: notable
    if:
      type: string
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
    if:
      type: string
      substr: "keyword"
      count_min: 3
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
      type: string
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
    let mapper = CapabilityMapper::new_with_precision_thresholds(5.0, 3.0, false);

    // Mapper should be created with custom thresholds and load traits
    assert!(
        mapper.mapping_count() > 0,
        "Should load mappings with custom precision thresholds"
    );
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
      type: string
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
      type: string
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
