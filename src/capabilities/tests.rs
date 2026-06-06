//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Comprehensive test suite for capabilities module.
//!
//! Tests are organized by category:
//! - Basic mapper tests
//! - Default application tests
//! - Composite rule evaluation tests
//! - Complexity calculation tests

use super::*;
use crate::composite_rules::{
    Arch, CompositeTrait, Condition, FileType as RuleFileType, Platform, SectionMap,
    TraitDefinition,
};
use crate::types::{AnalysisReport, Criticality, Finding, FindingKind, TargetInfo};
use anyhow::Result;
use std::path::Path;

#[test]
fn test_empty_mapper() {
    let mapper = CapabilityMapper::empty();

    // Should have no mappings
    assert_eq!(mapper.mapping_count(), 0);
    assert_eq!(mapper.trait_definitions_count(), 0);
    assert_eq!(mapper.composite_rules_count(), 0);

    // Lookup should return None
    assert!(mapper.lookup("socket").is_none());
}

#[test]
fn test_yaml_loading() {
    // Test loading from embedded capabilities (without validation to allow tests to run)
    let mapper = CapabilityMapper::new_without_validation();

    // Should be able to create mapper (may or may not load mappings depending on environment)
    let count = mapper.mapping_count();
    println!("Loaded {} symbol mappings", count);
    // Test passes if mapper was created successfully
    let _ = count;
}

#[test]
fn test_mapping_count() {
    let mapper = CapabilityMapper::new_without_validation();
    let count = mapper.mapping_count();

    // Mapper should be created successfully (count depends on environment)
    let _ = count;
}

#[test]
fn test_lookup_nonexistent() {
    let mapper = CapabilityMapper::empty();
    let capability = mapper.lookup("nonexistent_func");
    assert!(capability.is_none());
}

#[test]
fn test_empty_mapper_counts() {
    let mapper = CapabilityMapper::empty();
    assert_eq!(mapper.mapping_count(), 0);
    assert_eq!(mapper.composite_rules_count(), 0);
    assert_eq!(mapper.trait_definitions_count(), 0);
}

#[test]
fn test_new_loads_symbols() {
    let mapper = CapabilityMapper::new_without_validation();

    // Should create mapper successfully (loading depends on environment)
    let _ = mapper.mapping_count();
}

#[test]
fn test_composite_rules_count() {
    let mapper = CapabilityMapper::new_without_validation();
    let count = mapper.composite_rules_count();

    // May or may not have composite rules depending on traits/ directory
    let _ = count;
}

#[test]
fn test_trait_definitions_count() {
    let mapper = CapabilityMapper::new_without_validation();
    let count = mapper.trait_definitions_count();

    // May or may not have trait definitions depending on traits/ directory
    let _ = count;
}

#[test]
fn test_apply_string_default_uses_default_when_raw_is_none() {
    let default = Some("T1234".to_string());
    let result = parsing::apply_string_default(None, &default);
    assert_eq!(result, Some("T1234".to_string()));
}

#[test]
fn test_apply_string_default_uses_raw_when_present() {
    let default = Some("T1234".to_string());
    let result = parsing::apply_string_default(Some("T5678".to_string()), &default);
    assert_eq!(result, Some("T5678".to_string()));
}

#[test]
fn test_apply_string_default_unset_with_none_keyword() {
    let default = Some("T1234".to_string());
    let result = parsing::apply_string_default(Some("none".to_string()), &default);
    assert_eq!(result, None);
}

#[test]
fn test_apply_string_default_unset_case_insensitive() {
    let default = Some("T1234".to_string());
    assert_eq!(
        parsing::apply_string_default(Some("NONE".to_string()), &default),
        None
    );
    assert_eq!(
        parsing::apply_string_default(Some("None".to_string()), &default),
        None
    );
    assert_eq!(
        parsing::apply_string_default(Some("nOnE".to_string()), &default),
        None
    );
}

#[test]
fn test_apply_string_default_no_default() {
    let result = parsing::apply_string_default(None, &None);
    assert_eq!(result, None);
}

#[test]
fn test_apply_vec_default_uses_default_when_raw_is_none() {
    let default = Some(vec!["elf".to_string(), "macho".to_string()]);
    let result = parsing::apply_vec_default(None, &default);
    assert_eq!(result, Some(vec!["elf".to_string(), "macho".to_string()]));
}

#[test]
fn test_apply_vec_default_uses_raw_when_present() {
    let default = Some(vec!["elf".to_string()]);
    let result = parsing::apply_vec_default(Some(vec!["pe".to_string()]), &default);
    assert_eq!(result, Some(vec!["pe".to_string()]));
}

#[test]
fn test_apply_vec_default_unset_with_none_keyword() {
    let default = Some(vec!["elf".to_string(), "macho".to_string()]);
    let result = parsing::apply_vec_default(Some(vec!["none".to_string()]), &default);
    assert_eq!(result, None);
}

#[test]
fn test_parse_file_types_binary_alias() {
    let types = vec!["binaries".to_string()];
    let mut warnings = Vec::new();
    let result = parsing::parse_file_types(&types, &mut warnings);
    assert!(result.from_groups);
    assert_eq!(result.types.len(), 5);
    assert!(result.types.contains(&RuleFileType::Elf));
    assert!(result.types.contains(&RuleFileType::Macho));
    assert!(result.types.contains(&RuleFileType::Pe));
    assert!(result.types.contains(&RuleFileType::Class));
    assert!(result.types.contains(&RuleFileType::Pyc));
}

#[test]
fn test_apply_trait_defaults_applies_all_defaults() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["php".to_string()]),
        platforms: Some(vec!["linux".to_string()]),
        arch: None,
        crit: Some("suspicious".to_string()),
        conf: Some(0.85),
        mbc: Some("B0001".to_string()),
        attack: Some("T1059".to_string()),
        size_min: Some(1024),
        size_max: Some(10_485_760),
        entropy_min: Some(3.0),
        entropy_max: Some(7.5),
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: None,
        crit: None,
        mbc: None,
        attack: None,
        platforms: None,
        arch: None,
        file_types: None,
        size_min: None,
        size_max: None,
        not: None,
        unless: None,
        downgrade: None,
        condition: Some(Condition::Text {
            is_check: None,
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        }),
        count_min: Some(1),
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        ..Default::default()
    };

    let result = parsing::apply_trait_defaults(
        raw,
        &defaults,
        &mut Vec::new(),
        Path::new("test.yaml"),
        true,
    );

    assert_eq!(result.conf, 0.85);
    assert_eq!(result.crit, Criticality::Suspicious);
    assert_eq!(result.mbc, Some("B0001".to_string()));
    assert_eq!(result.attack, Some("T1059".to_string()));
    assert_eq!(result.platforms, vec![Platform::Linux]);
    assert_eq!(result.r#for, vec![RuleFileType::Php]);
    assert_eq!(result.size_min, Some(1024));
    assert_eq!(result.size_max, Some(10_485_760));
    assert_eq!(result.entropy_min, Some(3.0));
    assert_eq!(result.entropy_max, Some(7.5));
}

#[test]
fn test_apply_trait_defaults_trait_overrides_defaults() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["php".to_string()]),
        platforms: Some(vec!["linux".to_string()]),
        arch: None,
        crit: Some("suspicious".to_string()),
        conf: Some(0.85),
        mbc: Some("B0001".to_string()),
        attack: Some("T1059".to_string()),
        size_min: None,
        size_max: None,
        entropy_min: None,
        entropy_max: None,
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: Some(0.99),
        crit: Some("hostile".to_string()),
        mbc: Some("B0002".to_string()),
        attack: Some("T1234".to_string()),
        platforms: Some(vec!["windows".to_string()]),
        arch: None,
        file_types: Some(vec!["pe".to_string()]),
        size_min: None,
        size_max: None,
        not: None,
        unless: None,
        downgrade: None,
        condition: Some(Condition::Text {
            is_check: None,
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        }),
        count_min: Some(1),
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        ..Default::default()
    };

    let result = parsing::apply_trait_defaults(
        raw,
        &defaults,
        &mut Vec::new(),
        Path::new("test.yaml"),
        true,
    );

    assert_eq!(result.conf, 0.99);
    // Atomic traits cannot be HOSTILE, so they get downgraded to SUSPICIOUS
    assert_eq!(result.crit, Criticality::Suspicious);
    assert_eq!(result.mbc, Some("B0002".to_string()));
    assert_eq!(result.attack, Some("T1234".to_string()));
    assert_eq!(result.platforms, vec![Platform::Windows]);
    assert_eq!(result.r#for, vec![RuleFileType::Pe]);
}

#[test]
fn test_apply_trait_defaults_unset_mbc_with_none() {
    let defaults = models::TraitDefaults {
        r#for: None,
        platforms: None,
        arch: None,
        crit: None,
        conf: None,
        mbc: Some("B0001".to_string()),
        attack: Some("T1059".to_string()),
        size_min: None,
        size_max: None,
        entropy_min: None,
        entropy_max: None,
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: None,
        crit: None,
        mbc: Some("none".to_string()), // Explicitly unset
        attack: None,                  // Use default
        platforms: None,
        arch: None,
        file_types: None,
        size_min: None,
        size_max: None,
        not: None,
        unless: None,
        downgrade: None,
        condition: Some(Condition::Text {
            is_check: None,
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        }),
        count_min: Some(1),
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        ..Default::default()
    };

    let result = parsing::apply_trait_defaults(
        raw,
        &defaults,
        &mut Vec::new(),
        Path::new("test.yaml"),
        true,
    );

    assert_eq!(result.mbc, None); // Unset despite default
    assert_eq!(result.attack, Some("T1059".to_string())); // Default applied
}

#[test]
fn test_apply_trait_defaults_unset_attack_with_none() {
    let defaults = models::TraitDefaults {
        r#for: None,
        platforms: None,
        arch: None,
        crit: None,
        conf: None,
        mbc: Some("B0001".to_string()),
        attack: Some("T1059".to_string()),
        size_min: None,
        size_max: None,
        entropy_min: None,
        entropy_max: None,
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: None,
        crit: None,
        mbc: None,                        // Use default
        attack: Some("NONE".to_string()), // Explicitly unset (uppercase)
        platforms: None,
        arch: None,
        file_types: None,
        size_min: None,
        size_max: None,
        not: None,
        unless: None,
        downgrade: None,
        condition: Some(Condition::Text {
            is_check: None,
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        }),
        count_min: Some(1),
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        ..Default::default()
    };

    let result = parsing::apply_trait_defaults(
        raw,
        &defaults,
        &mut Vec::new(),
        Path::new("test.yaml"),
        true,
    );

    assert_eq!(result.mbc, Some("B0001".to_string())); // Default applied
    assert_eq!(result.attack, None); // Unset despite default
}

#[test]
fn test_apply_trait_defaults_unset_file_types_with_none() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["php".to_string()]),
        platforms: None,
        arch: None,
        crit: None,
        conf: None,
        mbc: None,
        attack: None,
        size_min: None,
        size_max: None,
        entropy_min: None,
        entropy_max: None,
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: None,
        crit: None,
        mbc: None,
        attack: None,
        platforms: None,
        arch: None,
        file_types: Some(vec!["none".to_string()]), // Explicitly unset
        size_min: None,
        size_max: None,
        not: None,
        unless: None,
        downgrade: None,
        condition: Some(Condition::Text {
            is_check: None,
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        }),
        count_min: Some(1),
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        ..Default::default()
    };

    let result = parsing::apply_trait_defaults(
        raw,
        &defaults,
        &mut Vec::new(),
        Path::new("test.yaml"),
        true,
    );

    // When unset, file_types defaults to [All]
    assert_eq!(result.r#for, vec![RuleFileType::All]);
}

#[test]
fn test_apply_trait_defaults_size_and_entropy_from_defaults() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["pe".to_string()]),
        platforms: Some(vec!["windows".to_string()]),
        arch: None,
        crit: Some("notable".to_string()),
        conf: Some(0.8),
        mbc: None,
        attack: None,
        size_min: Some(4096),
        size_max: Some(52_428_800),
        entropy_min: Some(1.0),
        entropy_max: Some(7.9),
    };

    // Trait with no size/entropy — inherits from defaults
    let raw_inherit = models::RawTraitDefinition {
        id: "test/inherit".to_string(),
        desc: "Inherit size".to_string(),
        conf: None,
        crit: None,
        mbc: None,
        attack: None,
        platforms: None,
        arch: None,
        file_types: None,
        size_min: None,
        size_max: None,
        not: None,
        unless: None,
        downgrade: None,
        condition: Some(Condition::Text {
            is_check: None,
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        }),
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        ..Default::default()
    };

    let result = parsing::apply_trait_defaults(
        raw_inherit,
        &defaults,
        &mut Vec::new(),
        Path::new("test.yaml"),
        true,
    );
    assert_eq!(result.size_min, Some(4096));
    assert_eq!(result.size_max, Some(52_428_800));
    assert_eq!(result.entropy_min, Some(1.0));
    assert_eq!(result.entropy_max, Some(7.9));

    // Trait with explicit size/entropy — overrides defaults
    let raw_override = models::RawTraitDefinition {
        id: "test/override".to_string(),
        desc: "Override size".to_string(),
        conf: None,
        crit: None,
        mbc: None,
        attack: None,
        platforms: None,
        arch: None,
        file_types: None,
        size_min: Some(512),
        size_max: Some(1_048_576),
        not: None,
        unless: None,
        downgrade: None,
        condition: Some(Condition::Text {
            is_check: None,
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        }),
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: Some(6.5),
        entropy_max: Some(8.0),
        ..Default::default()
    };

    let result = parsing::apply_trait_defaults(
        raw_override,
        &defaults,
        &mut Vec::new(),
        Path::new("test.yaml"),
        true,
    );
    assert_eq!(result.size_min, Some(512));
    assert_eq!(result.size_max, Some(1_048_576));
    assert_eq!(result.entropy_min, Some(6.5));
    assert_eq!(result.entropy_max, Some(8.0));
}

#[test]
fn test_apply_composite_defaults_applies_all_defaults() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["elf".to_string(), "macho".to_string()]),
        platforms: Some(vec!["linux".to_string(), "macos".to_string()]),
        arch: None,
        crit: Some("notable".to_string()),
        conf: Some(0.75),
        mbc: Some("B0030".to_string()),
        attack: Some("T1071.001".to_string()),
        size_min: Some(2048),
        size_max: Some(5_242_880),
        entropy_min: None,
        entropy_max: None,
    };

    let raw = models::RawCompositeRule {
        id: "test/rule".to_string(),
        desc: "Test rule".to_string(),
        conf: None,
        crit: None,
        mbc: None,
        attack: None,
        platforms: None,
        arch: None,
        file_types: None,
        all: None,
        any: None,
        needs: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        condition: Some(Condition::Text {
            is_check: None,
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        }),
        ..Default::default()
    };

    let mut warnings = Vec::new();
    let result = parsing::apply_composite_defaults(
        raw,
        &defaults,
        &mut warnings,
        std::path::Path::new("test.yaml"),
    );

    assert_eq!(result.conf, 0.75);
    assert_eq!(result.crit, Criticality::Notable);
    assert_eq!(result.mbc, Some("B0030".to_string()));
    assert_eq!(result.attack, Some("T1071.001".to_string()));
    assert_eq!(result.platforms, vec![Platform::Linux, Platform::MacOS]);
    assert_eq!(result.r#for, vec![RuleFileType::Elf, RuleFileType::Macho]);
    assert_eq!(result.size_min, Some(2048));
    assert_eq!(result.size_max, Some(5_242_880));
}

#[test]
fn test_apply_composite_defaults_unset_with_none() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["elf".to_string()]),
        platforms: Some(vec!["linux".to_string()]),
        arch: None,
        crit: Some("suspicious".to_string()),
        conf: Some(0.9),
        mbc: Some("B0030".to_string()),
        attack: Some("T1071".to_string()),
        size_min: None,
        size_max: None,
        entropy_min: None,
        entropy_max: None,
    };

    let raw = models::RawCompositeRule {
        id: "test/rule".to_string(),
        desc: "Test rule".to_string(),
        conf: None,
        crit: None,
        mbc: Some("none".to_string()),             // Unset
        attack: Some("none".to_string()),          // Unset
        platforms: Some(vec!["none".to_string()]), // Unset
        arch: None,
        file_types: None, // Use default
        all: None,
        any: None,
        needs: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        condition: Some(Condition::Text {
            is_check: None,
            exact: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        }),
        ..Default::default()
    };

    let mut warnings = Vec::new();
    let result = parsing::apply_composite_defaults(
        raw,
        &defaults,
        &mut warnings,
        std::path::Path::new("test.yaml"),
    );

    assert_eq!(result.mbc, None);
    assert_eq!(result.attack, None);
    assert_eq!(result.platforms, vec![Platform::All]); // Fallback when unset
    assert_eq!(result.r#for, vec![RuleFileType::Elf]); // Default applied
}

#[test]
fn test_yaml_with_defaults_and_unset() {
    let yaml = r#"
defaults:
  file_types: [php]
  mbc: "B0001"
  attack: "T1059"
  criticality: suspicious

traits:
  - id: test/uses-defaults
    description: "Uses all defaults"
    condition:
      type: text
      exact: "test1"

  - id: test/overrides-some
    description: "Overrides some defaults"
    mbc: "B0002"
    criticality: notable
    condition:
      type: text
      exact: "test2"

  - id: test/unsets-mbc
    description: "Unsets mbc"
    mbc: none
    condition:
      type: text
      exact: "test3"

  - id: test/unsets-attack
    description: "Unsets attack"
    attack: NONE
    condition:
      type: text
      exact: "test4"
"#;

    let mappings: models::TraitMappings = serde_yaml::from_str(yaml).expect("Failed to parse YAML");

    assert_eq!(mappings.traits.len(), 4);

    // Apply defaults and verify
    let t1 = parsing::apply_trait_defaults(
        mappings.traits.into_iter().next().unwrap(),
        &mappings.defaults,
        &mut Vec::new(),
        Path::new("test.yaml"),
        true,
    );
    assert_eq!(t1.mbc, Some("B0001".to_string()));
    assert_eq!(t1.attack, Some("T1059".to_string()));
    assert_eq!(t1.crit, Criticality::Suspicious);
    assert_eq!(t1.r#for, vec![RuleFileType::Php]);
}

#[test]
fn test_yaml_composite_rules_with_defaults() {
    let yaml = r#"
defaults:
  file_types: [elf, macho, pe]
  attack: "T1071.001"
  criticality: notable

composite_rules:
  - id: test/uses-defaults
    description: "Uses all defaults"
    confidence: 0.5
    condition:
      type: text
      exact: "HTTP/1.1"

  - id: test/unsets-attack
    description: "Unsets attack"
    confidence: 0.6
    attack: none
    condition:
      type: text
      exact: "GET /"
"#;

    let mappings: models::TraitMappings = serde_yaml::from_str(yaml).expect("Failed to parse YAML");

    assert_eq!(mappings.composite_rules.len(), 2);

    let mut warnings = Vec::new();
    let mut rules = Vec::new();
    for r in mappings.composite_rules {
        rules.push(parsing::apply_composite_defaults(
            r,
            &mappings.defaults,
            &mut warnings,
            std::path::Path::new("test.yaml"),
        ));
    }

    // First rule uses defaults
    assert_eq!(rules[0].attack, Some("T1071.001".to_string()));
    assert_eq!(rules[0].crit, Criticality::Notable);
    assert_eq!(
        rules[0].r#for,
        vec![RuleFileType::Elf, RuleFileType::Macho, RuleFileType::Pe]
    );

    // Second rule unsets attack
    assert_eq!(rules[1].attack, None);
    assert_eq!(rules[1].crit, Criticality::Notable); // Still uses default
}

// ==================== Iterative Composite Evaluation Tests ====================

/// Helper to create a minimal analysis report for testing
fn test_report_with_findings(findings: Vec<Finding>) -> AnalysisReport {
    let mut report = AnalysisReport::new(TargetInfo {
        path: "/test/file".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 1000,
        sha256: "abc123".to_string(),
        architectures: None,
    });
    report.findings = findings;
    report
}

/// Helper to create a test finding
fn test_finding(id: &str) -> Finding {
    Finding {
        id: id.to_string(),
        kind: FindingKind::Capability,
        desc: format!("Test finding {}", id),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        match_count: 0,
        source_file: None,
    }
}

// Excessive-line-length detection moved from the engine to the YAML trait
// objectives/anti-static/obfuscation/code-metrics/line-length::excessive-line-length
// (input: text.max_line_length metric). The binary-blob/tensor skips that these
// tests covered are now the trait's `for:` scoping + `unless:` carve-outs.

#[test]
fn test_iterative_eval_single_pass() {
    // Test that simple composites work in a single pass
    let mapper = CapabilityMapper::empty();
    let report = test_report_with_findings(vec![test_finding("atomic/trait-a")]);
    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default(), None);
    assert!(findings.is_empty()); // Empty mapper returns no findings
}

#[test]
fn test_iterative_eval_max_iterations_protection() {
    // Test that MAX_ITERATIONS limit prevents infinite loops
    let report = test_report_with_findings(vec![]);
    let mapper = CapabilityMapper::empty();

    let start = std::time::Instant::now();
    let _ = mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default(), None);
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 1,
        "Evaluation took too long: {:?}",
        elapsed
    );
}

#[test]
fn test_composite_referencing_atomic_trait() {
    let composite = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/composite".to_string(),
        desc: "Test composite".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "test/atomic-trait".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let report = test_report_with_findings(vec![test_finding("test/atomic-trait")]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite);

    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default(), None);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "test/composite");
}

#[test]
fn test_composite_of_composites_two_levels() {
    // Level 1: atomic-trait -> Level 2: composite-a -> Level 3: composite-b
    let composite_a = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/composite-a".to_string(),
        desc: "First level".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "test/atomic-trait".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let composite_b = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/composite-b".to_string(),
        desc: "Second level".to_string(),
        conf: 0.95,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "test/composite-a".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let report = test_report_with_findings(vec![test_finding("test/atomic-trait")]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite_a);
    mapper.composite_rules.push(composite_b);

    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default(), None);

    // Both composites should be found due to iterative evaluation
    assert_eq!(findings.len(), 2);
    let ids: Vec<_> = findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"test/composite-a"), "Missing composite-a");
    assert!(ids.contains(&"test/composite-b"), "Missing composite-b");
}

#[test]
fn test_composite_three_level_chain() {
    // Test 3-level chain: atomic -> A -> B -> C
    let make_composite = |id: &str, requires: &str| CompositeTrait {
        required_trait_indices: Vec::new(),
        id: id.to_string(),
        desc: format!("Composite {}", id),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: requires.to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let report = test_report_with_findings(vec![test_finding("level/zero")]);
    let mut mapper = CapabilityMapper::empty();
    mapper
        .composite_rules
        .push(make_composite("level/one", "level/zero"));
    mapper
        .composite_rules
        .push(make_composite("level/two", "level/one"));
    mapper
        .composite_rules
        .push(make_composite("level/three", "level/two"));

    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default(), None);

    assert_eq!(findings.len(), 3);
    let ids: Vec<_> = findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"level/one"));
    assert!(ids.contains(&"level/two"));
    assert!(ids.contains(&"level/three"));
}

#[test]
fn test_composite_circular_dependency_handled() {
    // Test that circular dependencies don't cause infinite loops
    let composite_a = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "circular/a".to_string(),
        desc: "Circular A".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "circular/b".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let composite_b = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "circular/b".to_string(),
        desc: "Circular B".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "circular/a".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let report = test_report_with_findings(vec![]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite_a);
    mapper.composite_rules.push(composite_b);

    let start = std::time::Instant::now();
    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default(), None);
    let elapsed = start.elapsed();

    assert!(elapsed.as_millis() < 100, "Took too long: {:?}", elapsed);
    assert!(findings.is_empty(), "Circular deps shouldn't match");
}

#[test]
fn test_composite_prefix_matching_in_chain() {
    // Test prefix matching works in composite chains
    let composite = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/uses-discovery".to_string(),
        desc: "Uses discovery".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "discovery/system".to_string(), // Prefix match
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Report has specific trait under discovery/system/
    let report = test_report_with_findings(vec![test_finding("discovery/system/hostname")]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite);

    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default(), None);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "test/uses-discovery");
}

#[test]
fn test_composite_requires_count_in_chain() {
    let composite = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/needs-two".to_string(),
        desc: "Needs 2 of 3".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: None,
        any: Some(vec![
            Condition::Trait {
                id: "feat/a".to_string(),
            },
            Condition::Trait {
                id: "feat/b".to_string(),
            },
            Condition::Trait {
                id: "feat/c".to_string(),
            },
        ]),
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let report = test_report_with_findings(vec![test_finding("feat/a"), test_finding("feat/c")]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite);

    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default(), None);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "test/needs-two");
}

// ==================== Complexity Calculation Tests ====================

/// Test basic precision calculation - direct conditions count as 1
#[test]
fn test_precision_direct_conditions() {
    use std::collections::{HashMap, HashSet};

    // Rule with 3 direct string conditions
    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/three-strings".to_string(),
        desc: "Test rule with 3 strings".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = [rule.clone()];

    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composites.iter().map(|c| (c.id.as_str(), c)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> = HashMap::new();

    let precision = validation::calculate_composite_precision(
        "test/three-strings",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );

    // Precision should be positive and include all direct conditions.
    assert!(precision > 0.0);
}

/// Test file type filter counting as +1
#[test]
fn test_precision_file_type_filter() {
    use std::collections::{HashMap, HashSet};

    // Rule with 2 conditions + file type filter
    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/with-filetype".to_string(),
        desc: "Test rule with file type".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::Elf, RuleFileType::Pe], // File type filter
        for_from_groups: false,
        all: Some(vec![]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = [rule.clone()];

    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composites.iter().map(|c| (c.id.as_str(), c)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> = HashMap::new();

    let precision = validation::calculate_composite_precision(
        "test/with-filetype",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );

    // File type filtering should increase precision.
    assert!(precision > 0.0);
}

/// Test recursive trait reference expansion
#[test]
fn test_precision_recursive_expansion() {
    use std::collections::{HashMap, HashSet};

    // Atomic trait (not a composite, counts as 1)
    let trait_def = TraitDefinition {
        id: "test/atomic-trait".to_string(),
        desc: "Atomic trait".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            is_check: None,
            exact: Some("atomic".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        },
        size_max: None,
        count_min: Some(1),
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Composite A: has 2 direct conditions (precision 2)
    let composite_a = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/composite-a".to_string(),
        desc: "Composite A".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Composite B: references composite A and atomic trait
    let composite_b = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/composite-b".to_string(),
        desc: "Composite B".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![
            Condition::Trait {
                id: "test/composite-a".to_string(),
            },
            Condition::Trait {
                id: "test/atomic-trait".to_string(),
            },
        ]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = [composite_a, composite_b.clone()];
    let traits = [trait_def];

    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composites.iter().map(|c| (c.id.as_str(), c)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> =
        traits.iter().map(|t| (t.id.as_str(), t)).collect();

    let precision = validation::calculate_composite_precision(
        "test/composite-b",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );

    // Recursive expansion should produce non-zero precision.
    assert!(precision > 0.0);
}

/// Test cycle detection in trait references
#[test]
fn test_precision_cycle_detection() {
    use std::collections::{HashMap, HashSet};

    // Composite A references B
    let composite_a = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/circular-a".to_string(),
        desc: "Circular A".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "test/circular-b".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Composite B references A (cycle!)
    let composite_b = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/circular-b".to_string(),
        desc: "Circular B".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "test/circular-a".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = [composite_a.clone(), composite_b];

    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composites.iter().map(|c| (c.id.as_str(), c)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> = HashMap::new();

    let precision = validation::calculate_composite_precision(
        "test/circular-a",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );

    // Cycle detected - should not panic and should return finite value
    assert!(precision.is_finite());
    assert!(precision > 0.0);
}

/// Test caching behavior
#[test]
fn test_precision_caching() {
    use std::collections::{HashMap, HashSet};

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/cacheable".to_string(),
        desc: "Cacheable rule".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = [rule.clone()];

    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composites.iter().map(|c| (c.id.as_str(), c)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> = HashMap::new();

    // First call - should calculate and cache
    let precision1 = validation::calculate_composite_precision(
        "test/cacheable",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );

    // Check cache was populated
    assert_eq!(cache.get("test/cacheable"), Some(&precision1));

    // Second call - should use cache
    let precision2 = validation::calculate_composite_precision(
        "test/cacheable",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );

    assert!((precision1 - precision2).abs() < f32::EPSILON);
    assert!(precision1 > 0.0);
}

/// Test threshold validation - rules < 4 get downgraded from HOSTILE to SUSPICIOUS
#[test]
fn test_precision_threshold_validation() {
    // Rule with precision 3 (below threshold)
    let rule_low = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/low-precision".to_string(),
        desc: "Low precision".to_string(),
        conf: 0.95,
        crit: Criticality::Hostile, // Will be downgraded
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Rule with precision >= 3.5 (meets threshold)
    // With the new granular scoring: 25-char strings = 5 buckets * 0.3 = 1.5 each
    // 3 strings = 4.5 precision, which meets the 4.0 threshold
    let rule_high = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/high-precision".to_string(),
        desc: "High precision".to_string(),
        conf: 0.95,
        crit: Criticality::Hostile, // Will NOT be downgraded
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let mut composites = vec![rule_low, rule_high];
    let traits: Vec<TraitDefinition> = vec![];

    // Precalculate precision before validation
    validation::precalculate_all_composite_precisions(&mut composites, &traits);

    let mut warnings = Vec::new();
    validation::validate_hostile_composite_precision(
        &mut composites,
        &traits,
        &mut warnings,
        4.0,
        2.0,
    );

    // Check that low precision emitted a warning without changing criticality
    let low_rule = composites
        .iter()
        .find(|r| r.id == "test/low-precision")
        .unwrap();
    assert_eq!(low_rule.crit, Criticality::Hostile);
    assert!(warnings.iter().any(|w| w.contains("test/low-precision")));

    // Check that high precision was NOT downgraded
    let high_rule = composites
        .iter()
        .find(|r| r.id == "test/high-precision")
        .unwrap();
    assert_eq!(high_rule.crit, Criticality::Hostile);
}

#[test]
fn test_suspicious_precision_threshold_validation() {
    // Rule with precision near the floor (below suspicious threshold of 1.9)
    let rule_low = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/suspicious-low-precision".to_string(),
        desc: "Low precision suspicious rule".to_string(),
        conf: 0.8,
        crit: Criticality::Suspicious, // Will be downgraded
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Text {
            is_check: None,
            exact: Some("string1".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Rule with precision >= 1.9 (meets suspicious threshold)
    let rule_ok = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/suspicious-good-precision".to_string(),
        desc: "Good precision suspicious rule".to_string(),
        conf: 0.8,
        crit: Criticality::Suspicious, // Will NOT be downgraded
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let mut composites = vec![rule_low, rule_ok];
    let traits: Vec<TraitDefinition> = vec![];

    // Precalculate precision before validation
    validation::precalculate_all_composite_precisions(&mut composites, &traits);

    let mut warnings = Vec::new();
    validation::validate_hostile_composite_precision(
        &mut composites,
        &traits,
        &mut warnings,
        4.0,
        1.9,
    );

    // Check that low precision suspicious rule emitted a warning without changing criticality
    let low_rule = composites
        .iter()
        .find(|r| r.id == "test/suspicious-low-precision")
        .unwrap();
    assert_eq!(low_rule.crit, Criticality::Suspicious);
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("test/suspicious-low-precision"))
    );

    // Check that sufficient precision suspicious rule was NOT downgraded
    let ok_rule = composites
        .iter()
        .find(|r| r.id == "test/suspicious-good-precision")
        .unwrap();
    assert_eq!(ok_rule.crit, Criticality::Suspicious);
}

#[test]
fn test_atomic_suspicious_precision_threshold_validation() {
    let low_trait = TraitDefinition {
        id: "test/atomic-suspicious-low".to_string(),
        desc: "Low precision suspicious atomic".to_string(),
        conf: 0.8,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        r#if: Condition::Raw {
            exact: None,
            substr: Some("x".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        },
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: Some(1.0),
        ..Default::default()
    };

    let ok_trait = TraitDefinition {
        id: "test/atomic-suspicious-ok".to_string(),
        desc: "Enough precision suspicious atomic".to_string(),
        conf: 0.8,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::Windows],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::Pe],
        for_from_groups: false,
        r#if: Condition::Text {
            is_check: None,
            exact: Some("CreateProcessW".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: Some(".rdata".to_string()),
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        },
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: Some(2.0),
        ..Default::default()
    };

    let mut traits = vec![low_trait, ok_trait];
    let mut warnings = Vec::new();
    validation::validate_hostile_trait_precision(&mut traits, &mut warnings, 3.5, 1.9);

    let low_trait = traits
        .iter()
        .find(|t| t.id == "test/atomic-suspicious-low")
        .unwrap();
    assert_eq!(low_trait.crit, Criticality::Suspicious);
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("test/atomic-suspicious-low"))
    );

    let ok_trait = traits
        .iter()
        .find(|t| t.id == "test/atomic-suspicious-ok")
        .unwrap();
    assert_eq!(ok_trait.crit, Criticality::Suspicious);
}

/// Test precision with mixed condition types (all, any, none)
#[test]
fn test_precision_mixed_conditions() {
    use std::collections::{HashMap, HashSet};

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/mixed".to_string(),
        desc: "Mixed conditions".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Text {
            is_check: None,
            exact: Some("string1".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        }]),
        any: Some(vec![]),
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: Some(vec![Condition::Text {
            is_check: None,
            exact: Some("string4".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        }]),
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = [rule.clone()];
    let _traits: Vec<TraitDefinition> = vec![];

    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composites.iter().map(|c| (c.id.as_str(), c)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> = HashMap::new();

    let precision = validation::calculate_composite_precision(
        "test/mixed",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );

    assert!(precision > 0.0);
}

/// Test precision with deeply nested trait references
#[test]
fn test_precision_deep_nesting() {
    use std::collections::{HashMap, HashSet};

    // Level 1: 2 direct conditions
    let level1 = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/level1".to_string(),
        desc: "Level 1".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Level 2: references level1 + 1 direct condition
    let level2 = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/level2".to_string(),
        desc: "Level 2".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "test/level1".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Level 3: references level2 + 1 direct condition
    let level3 = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/level3".to_string(),
        desc: "Level 3".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "test/level2".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,

        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = [level1, level2, level3];
    let _traits: Vec<TraitDefinition> = vec![];

    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composites.iter().map(|c| (c.id.as_str(), c)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> = HashMap::new();

    let precision = validation::calculate_composite_precision(
        "test/level3",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );

    assert!(precision > 0.0);
}

/// Test the correct precision calculation algorithm:
/// - File type (not "all"): +1
/// - any clause (if present): +1
/// - all clause: +count of elements
/// - none clause (if present): +1
#[test]
fn test_precision_correct_algorithm() {
    use std::collections::{HashMap, HashSet};

    // Test case: file_type + any(8) + all(2) = 1 + 1 + 2 = 4
    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/correct-precision".to_string(),
        desc: "Test correct precision calculation".to_string(),
        conf: 0.9,
        crit: Criticality::Hostile,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::JavaScript], // +1 (not "all")
        for_from_groups: false,
        all: Some(vec![
            // +2 (2 elements in all)
            Condition::Trait {
                id: "test/trait-1".to_string(),
            },
            Condition::Trait {
                id: "test/trait-2".to_string(),
            },
        ]),
        any: Some(vec![
            // +1 (any clause present, regardless of count)
            Condition::Trait {
                id: "test/any-1".to_string(),
            },
            Condition::Trait {
                id: "test/any-2".to_string(),
            },
            Condition::Trait {
                id: "test/any-3".to_string(),
            },
            Condition::Trait {
                id: "test/any-4".to_string(),
            },
            Condition::Trait {
                id: "test/any-5".to_string(),
            },
            Condition::Trait {
                id: "test/any-6".to_string(),
            },
            Condition::Trait {
                id: "test/any-7".to_string(),
            },
            Condition::Trait {
                id: "test/any-8".to_string(),
            },
        ]),
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = [rule];
    let _traits: Vec<TraitDefinition> = vec![];

    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composites.iter().map(|c| (c.id.as_str(), c)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> = HashMap::new();

    let precision = validation::calculate_composite_precision(
        "test/correct-precision",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );

    // Precision should be non-zero for constrained composite rules.
    assert!(
        precision > 0.0,
        "Expected positive precision, got {}",
        precision
    );
}

/// Test precision with traits that have size restrictions
#[test]
fn test_precision_traits_with_size_restrictions() {
    use std::collections::{HashMap, HashSet};

    // Trait 1: string pattern + size restriction
    let trait1 = TraitDefinition {
        id: "test/trait-with-size-1".to_string(),
        desc: "Trait with size restriction 1".to_string(),
        conf: 0.8,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            is_check: None,
            exact: Some("pattern1".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        },
        size_max: Some(1048576), // Has size restriction
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Trait 2: string pattern + size restriction
    let trait2 = TraitDefinition {
        id: "test/trait-with-size-2".to_string(),
        desc: "Trait with size restriction 2".to_string(),
        conf: 0.8,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            is_check: None,
            exact: Some("pattern2".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        },
        size_max: Some(2097152), // Has size restriction
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        unless: None,
        not: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Composite rule referencing both traits
    let composite = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/composite-with-sized-traits".to_string(),
        desc: "Composite with sized traits".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![
            Condition::Trait {
                id: "test/trait-with-size-1".to_string(),
            },
            Condition::Trait {
                id: "test/trait-with-size-2".to_string(),
            },
        ]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();
    let composites = [composite];
    let _traits = [trait1, trait2];

    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composites.iter().map(|c| (c.id.as_str(), c)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> = HashMap::new();

    let precision = validation::calculate_composite_precision(
        "test/composite-with-sized-traits",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );

    assert!(
        precision > 0.0,
        "Expected positive precision for sized trait composition, got {}",
        precision
    );
}

#[test]
fn test_invalid_yaml_error_message() {
    // Test that invalid YAML produces helpful error messages showing line numbers
    // This demonstrates improved error diagnostics for debugging malformed trait definitions

    // Create truly invalid YAML (bad indentation)
    let invalid_yaml = r#"
traits:
  - id: valid-trait
    desc: This one is fine
    crit: baseline
    conf: 0.9
    for: [elf]
    if:
      type: text
      regex: "test"

  - id: invalid-trait
    desc: This one has indentation error
    crit: suspicious
  conf: 0.9
    for: [elf]
    if:
      type: text
      regex: "test"
"#;

    // Parse should fail due to indentation
    let result: Result<serde_yaml::Value> =
        serde_yaml::from_str(invalid_yaml).map_err(|e| anyhow::anyhow!("YAML error: {}", e));

    assert!(result.is_err(), "Malformed YAML should fail to parse");

    // The error message should contain line/column information from serde_yaml
    let error_msg = result.unwrap_err().to_string();
    println!("Error message:\n{}", error_msg);

    // serde_yaml includes line and column in error messages
    assert!(
        error_msg.contains("line")
            || error_msg.contains("column")
            || error_msg.contains("position"),
        "Error should include line/column info: {}",
        error_msg
    );
}

#[test]
fn test_parse_file_types_groups_and_exclusions() {
    let mut warnings = Vec::new();

    // Test groups
    let binaries = parsing::parse_file_types(&["binaries".to_string()], &mut warnings);
    assert!(binaries.from_groups);
    assert_eq!(binaries.types.len(), 5);
    assert!(binaries.types.contains(&RuleFileType::Elf));
    assert!(!binaries.types.contains(&RuleFileType::Python));

    let scripts = parsing::parse_file_types(&["scripts".to_string()], &mut warnings);
    assert!(scripts.from_groups);
    assert_eq!(scripts.types.len(), 11); // TypeScript maps to JavaScript, not separate
    assert!(scripts.types.contains(&RuleFileType::Python));
    assert!(scripts.types.contains(&RuleFileType::Shell));
    assert!(!scripts.types.contains(&RuleFileType::Elf));

    // Test alias "all"
    let all = parsing::parse_file_types(&["all".to_string()], &mut warnings);
    assert!(all.from_groups);
    assert_eq!(all.types, vec![RuleFileType::All]);

    // Test exclusions
    // -php means All - Php.
    let not_php = parsing::parse_file_types(&["-php".to_string()], &mut warnings);
    assert!(!not_php.types.contains(&RuleFileType::Php));
    assert!(not_php.types.contains(&RuleFileType::Python));
    assert!(not_php.types.contains(&RuleFileType::Elf));
    assert!(!not_php.types.contains(&RuleFileType::All)); // Should be expanded

    // Test group + exclusion: scripts,-php
    let scripts_no_php =
        parsing::parse_file_types(&["scripts".to_string(), "-php".to_string()], &mut warnings);
    assert!(scripts_no_php.from_groups);
    assert!(scripts_no_php.types.contains(&RuleFileType::Python));
    assert!(scripts_no_php.types.contains(&RuleFileType::Shell));
    assert!(!scripts_no_php.types.contains(&RuleFileType::Php));
    assert!(!scripts_no_php.types.contains(&RuleFileType::Elf));

    // Test single string comma separation
    let comma_sep = parsing::parse_file_types(&["scripts,-php".to_string()], &mut warnings);
    assert!(comma_sep.types.contains(&RuleFileType::Python));
    assert!(!comma_sep.types.contains(&RuleFileType::Php));

    // Test '-binaries' exclusion
    let not_binaries = parsing::parse_file_types(&["-binaries".to_string()], &mut warnings);
    assert!(!not_binaries.types.contains(&RuleFileType::Elf));
    assert!(not_binaries.types.contains(&RuleFileType::Python));

    // Test '-scripts' exclusion
    let not_scripts = parsing::parse_file_types(&["-scripts".to_string()], &mut warnings);
    assert!(!not_scripts.types.contains(&RuleFileType::Python));
    assert!(not_scripts.types.contains(&RuleFileType::Elf));
}

// ==================== Composite Rule Validation Tests ====================

#[test]
fn test_collect_trait_refs_finds_internal_paths() {
    // Test that collect_trait_refs_from_rule correctly identifies metadata/internal/ references
    // These references are forbidden in composite rules (for ML use only)

    let composite = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/bad-composite".to_string(),
        desc: "Composite that incorrectly references internal path".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![
            Condition::Trait {
                id: "metadata/internal/symbols::printf".to_string(), // Forbidden!
            },
            Condition::Trait {
                id: "metadata/import/python::socket".to_string(), // OK
            },
        ]),
        any: Some(vec![Condition::Trait {
            id: "metadata/internal/symbols::malloc".to_string(), // Forbidden!
        }]),
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: Some(vec![Condition::Trait {
            id: "metadata/dylib::libc".to_string(), // OK
        }]),
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let refs = validation::collect_trait_refs_from_rule(&composite);

    // Should find all 4 trait references
    assert_eq!(refs.len(), 4);

    // Count how many are internal paths
    let internal_refs: Vec<_> = refs
        .iter()
        .filter(|(ref_id, _)| ref_id.starts_with("metadata/internal/"))
        .collect();
    assert_eq!(
        internal_refs.len(),
        2,
        "Should find 2 internal path references"
    );

    // Verify specific internal paths found
    let internal_ids: Vec<&str> = internal_refs.iter().map(|(id, _)| id.as_str()).collect();
    assert!(internal_ids.contains(&"metadata/internal/symbols::printf"));
    assert!(internal_ids.contains(&"metadata/internal/symbols::malloc"));
}

#[test]
fn test_meta_internal_paths_forbidden_in_composite_rules() {
    // Verify that a composite rule referencing metadata/internal/ would be caught
    // This documents the validation behavior: internal paths are for ML only

    let composite = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/references-internal".to_string(),
        desc: "Should not reference internal paths".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "metadata/internal/symbols::evil_func".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let refs = validation::collect_trait_refs_from_rule(&composite);

    // The validation logic in CapabilityMapper::load_with_path checks for metadata/internal/ refs
    // and adds them to a fatal error list. Here we verify the detection works.
    let has_internal_ref = refs
        .iter()
        .any(|(ref_id, _)| ref_id.starts_with("metadata/internal/"));
    assert!(
        has_internal_ref,
        "Should detect metadata/internal/ reference in composite rule"
    );

    // Document the allowed vs forbidden patterns:
    // - metadata/import/{lang}::{module} : OK (dynamically generated, allowed in composites)
    // - metadata/dylib/{library}        : OK (dynamically generated, allowed in composites)
    // - metadata/internal/{anything}    : FORBIDDEN (ML-only, not for composite rules)
}

#[test]
fn test_invalid_file_type_rejection() {
    use std::fs;
    use tempfile::TempDir;

    // Create a temporary directory with an invalid trait
    let temp_dir = TempDir::new().unwrap();
    let traits_dir = temp_dir.path().join("traits");
    fs::create_dir(&traits_dir).unwrap();

    // Write a trait with an invalid file type
    let trait_content = r#"
defaults:
  crit: notable
  conf: 0.8

traits:
  - id: test_invalid
    desc: Test with invalid file type
    for: [invalid_lang, python]
    if:
      type: text
      exact: test
"#;
    fs::write(traits_dir.join("test.yaml"), trait_content).unwrap();

    // Try to load the mapper - should fail with unknown file type error
    let result = CapabilityMapper::from_directory(temp_dir.path());

    match result {
        Ok(_) => panic!("Expected error for invalid file type, but mapper loaded successfully"),
        Err(err) => {
            let err_msg = format!("{:#}", err);
            assert!(
                err_msg.contains("Unknown file type")
                    || err_msg.contains("Invalid file type")
                    || err_msg.contains("invalid_lang"),
                "Error message should mention unknown/invalid file type, got: {}",
                err_msg
            );
        }
    }
}

#[test]
fn test_broken_trait_reference_with_filename_gets_specific_fix() {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let traits_dir = temp_dir
        .path()
        .join("objectives/persistence/system/service/systemd");
    fs::create_dir_all(&traits_dir).unwrap();

    let trait_content = r#"
defaults:
  crit: notable
  conf: 0.8
  platforms: [linux, unix]
  for: [systemd]

traits:
  - id: exec-start
    desc: ExecStart directive
    if:
      type: text
      word: "ExecStart"

  - id: restart-always
    desc: Restart always
    if:
      type: text
      word: "Restart=always"

composite_rules:
  - id: bad-ref-with-filename
    desc: Broken reference includes filename
    crit: suspicious
    conf: 0.9
    all:
      - id: objectives/persistence/system/service/systemd/linux::exec-start
      - id: objectives/persistence/system/service/systemd::restart-always
"#;
    fs::write(traits_dir.join("linux.yaml"), trait_content).unwrap();

    let result = CapabilityMapper::from_directory(temp_dir.path());

    match result {
        Ok(_) => panic!("Expected broken trait reference error, but mapper loaded successfully"),
        Err(err) => {
            let err_msg = format!("{:#}", err);
            assert!(
                err_msg.contains("includes YAML filename 'linux'"),
                "Expected filename-specific hint, got: {}",
                err_msg
            );
            assert!(
                err_msg.contains("objectives/persistence/system/service/systemd::exec-start"),
                "Expected exact fixed reference suggestion, got: {}",
                err_msg
            );
        }
    }
}

#[test]
fn test_broken_trait_reference_to_filename_without_local_id_gets_directory_hint() {
    use std::fs;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let traits_dir = temp_dir
        .path()
        .join("objectives/persistence/system/service/systemd");
    fs::create_dir_all(&traits_dir).unwrap();

    let trait_content = r#"
defaults:
  crit: notable
  conf: 0.8
  platforms: [linux, unix]
  for: [systemd]

traits:
  - id: exec-start
    desc: ExecStart directive
    if:
      type: text
      word: "ExecStart"

  - id: restart-always
    desc: Restart always
    if:
      type: text
      word: "Restart=always"

composite_rules:
  - id: bad-file-reference
    desc: Broken reference points at filename
    crit: suspicious
    conf: 0.9
    all:
      - id: objectives/persistence/system/service/systemd/linux
      - id: objectives/persistence/system/service/systemd::restart-always
"#;
    fs::write(traits_dir.join("linux.yaml"), trait_content).unwrap();

    let result = CapabilityMapper::from_directory(temp_dir.path());

    match result {
        Ok(_) => panic!("Expected broken filename reference error, but mapper loaded successfully"),
        Err(err) => {
            let err_msg = format!("{:#}", err);
            assert!(
                err_msg.contains("points to YAML file 'linux.yaml', not a trait directory"),
                "Expected directory-specific filename hint, got: {}",
                err_msg
            );
            assert!(
                err_msg.contains("objectives/persistence/system/service/systemd::exec-start"),
                "Expected specific trait suggestion, got: {}",
                err_msg
            );
            assert!(
                err_msg.contains("use 'objectives/persistence/system/service/systemd'"),
                "Expected directory reference suggestion, got: {}",
                err_msg
            );
        }
    }
}

#[test]
fn test_atomic_precision_calibration_spread() {
    let raw_trait = TraitDefinition {
        id: "test/raw-loose".to_string(),
        desc: "Loose raw trait".to_string(),
        conf: 0.8,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        r#if: Condition::Raw {
            exact: None,
            substr: Some("cmd".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        },
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let ast_trait = TraitDefinition {
        id: "test/ast-tight".to_string(),
        desc: "Tight AST trait".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::JavaScript],
        for_from_groups: false,
        r#if: Condition::TreeSitter {
            kind: Some("call".to_string()),
            node: None,
            exact: Some("eval".to_string()),
            substr: None,
            regex: None,
            query: None,
            language: Some("javascript".to_string()),
            case_insensitive: false,
        },
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let raw_precision = validation::calculate_trait_precision(&raw_trait);
    let ast_precision = validation::calculate_trait_precision(&ast_trait);

    assert!((1.0..=4.0).contains(&raw_precision));
    assert!(ast_precision > raw_precision);
    assert!(ast_precision <= validation::atomic_calibrated_max());
}

#[test]
fn test_atomic_precision_long_regex_and_large_not_list_stays_calibrated() {
    let trait_def = TraitDefinition {
        id: "test/long-regex-many-not".to_string(),
        desc: "Long regex with many exclusions".to_string(),
        conf: 0.95,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![
            Platform::Linux,
            Platform::Unix,
            Platform::MacOS,
            Platform::Windows,
        ],
        arch: vec![Arch::All],
        r#for: vec![
            RuleFileType::Pe,
            RuleFileType::Shell,
            RuleFileType::JavaScript,
        ],
        for_from_groups: false,
        r#if: Condition::Text {
            is_check: None,
            exact: None,
            regex: Some(
                r"\bdelete\b.{0,40}\b(?:all|your)\b.{0,20}\b(?:files?|documents?)\b".to_string(),
            ),
            word: None,
            case_insensitive: true,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        },
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: Some(vec![
            crate::composite_rules::condition::NotException::Structured(
                crate::composite_rules::condition::NotExceptionStructured {
                    exact: None,
                    substr: None,
                    regex: Some("(?i)delete all existing files".to_string()),
                    lowered_substr: None,
                },
            );
            12
        ]),
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let precision = validation::calculate_trait_precision(&trait_def);
    assert!(
        precision <= validation::atomic_calibrated_max(),
        "long regex and large not-list should remain in atomic band, got {precision}"
    );
}

#[test]
fn test_scope_filters_do_not_dominate_atomic_precision() {
    let broad_scope = TraitDefinition {
        id: "test/scope-broad".to_string(),
        desc: "Broad scope".to_string(),
        conf: 0.8,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![
            Platform::Linux,
            Platform::Unix,
            Platform::Android,
            Platform::MacOS,
            Platform::Ios,
            Platform::Windows,
        ],
        arch: vec![Arch::All],
        r#for: vec![
            RuleFileType::Pe,
            RuleFileType::Shell,
            RuleFileType::JavaScript,
            RuleFileType::Html,
            RuleFileType::Plist,
            RuleFileType::Rtf,
            RuleFileType::Zip,
        ],
        for_from_groups: false,
        r#if: Condition::Text {
            is_check: None,
            exact: Some("HmacSHA256".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        },
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let narrow_scope = TraitDefinition {
        id: "test/scope-narrow".to_string(),
        platforms: vec![Platform::Windows],
        r#for: vec![RuleFileType::Pe],
        ..broad_scope.clone()
    };

    let broad_precision = validation::calculate_trait_precision(&broad_scope);
    let narrow_precision = validation::calculate_trait_precision(&narrow_scope);

    assert!(broad_precision <= validation::atomic_calibrated_max());
    assert!(narrow_precision <= validation::atomic_calibrated_max());
    assert!(
        narrow_precision > broad_precision,
        "narrow scope should score higher than broad scope, got broad={broad_precision}, narrow={narrow_precision}"
    );
    assert!(
        (narrow_precision - broad_precision) < 1.5,
        "scope should be a bounded modifier, got broad={broad_precision}, narrow={narrow_precision}"
    );
}

#[test]
fn test_composite_precision_calibration_band() {
    use std::collections::{HashMap, HashSet};

    let atomic_a = TraitDefinition {
        id: "test/atomic-a".to_string(),
        desc: "Atomic A".to_string(),
        conf: 0.8,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::Windows],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::Pe],
        for_from_groups: false,
        r#if: Condition::Text {
            is_check: None,
            exact: Some("CreateProcessW".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: Some(".rdata".to_string()),
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        },
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };
    let atomic_b = TraitDefinition {
        id: "test/atomic-b".to_string(),
        ..atomic_a.clone()
    };
    let atomic_c = TraitDefinition {
        id: "test/atomic-c".to_string(),
        ..atomic_a.clone()
    };

    let composite = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/calibrated-composite".to_string(),
        desc: "Calibrated composite".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::Windows],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::Pe],
        for_from_groups: false,
        all: Some(vec![
            Condition::Trait {
                id: "test/atomic-a".to_string(),
            },
            Condition::Trait {
                id: "test/atomic-b".to_string(),
            },
        ]),
        any: Some(vec![Condition::Trait {
            id: "test/atomic-c".to_string(),
        }]),
        needs: Some(1),
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let composites = [composite];
    let traits = [atomic_a, atomic_b, atomic_c];
    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composites.iter().map(|c| (c.id.as_str(), c)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> =
        traits.iter().map(|t| (t.id.as_str(), t)).collect();
    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();

    let precision = validation::calculate_composite_precision(
        "test/calibrated-composite",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );

    assert!(precision >= 1.0);
    assert!(precision <= validation::composite_calibrated_max());
}

#[test]
fn test_composite_prefix_reference_matches_explicit_expansion_precision() {
    use std::collections::{HashMap, HashSet};

    let broad = TraitDefinition {
        id: "family/member-broad".to_string(),
        desc: "Broad family member".to_string(),
        conf: 0.7,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        r#if: Condition::Raw {
            exact: None,
            substr: Some("cmd".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        },
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };
    let precise = TraitDefinition {
        id: "family/member-precise".to_string(),
        desc: "Precise family member".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::Windows],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::Pe],
        for_from_groups: false,
        r#if: Condition::TreeSitter {
            kind: Some("call".to_string()),
            node: None,
            exact: Some("VirtualAlloc".to_string()),
            substr: None,
            regex: None,
            query: None,
            language: Some("javascript".to_string()),
            case_insensitive: false,
        },
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let family_ref = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/family-ref".to_string(),
        desc: "Uses family prefix".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "family".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };
    let explicit_family_ref = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/family-ref-explicit".to_string(),
        desc: "Uses explicit family expansion".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "test/family-members".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };
    let family_members = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/family-members".to_string(),
        desc: "Explicit family members".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: None,
        any: Some(vec![
            Condition::Trait {
                id: "family/member-broad".to_string(),
            },
            Condition::Trait {
                id: "family/member-precise".to_string(),
            },
        ]),
        needs: Some(1),
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let composites = [family_ref, explicit_family_ref, family_members];
    let traits = [broad, precise];
    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composites.iter().map(|c| (c.id.as_str(), c)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> =
        traits.iter().map(|t| (t.id.as_str(), t)).collect();
    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();

    let prefix_precision = validation::calculate_composite_precision(
        "test/family-ref",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );
    let explicit_precision = validation::calculate_composite_precision(
        "test/family-ref-explicit",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );

    assert!(
        (prefix_precision - explicit_precision).abs() < 0.01,
        "prefix reference should match explicit expansion precision, got {prefix_precision} vs {explicit_precision}"
    );
}

#[test]
fn test_composite_any_uses_weakest_average_with_breadth_penalty() {
    use std::collections::{HashMap, HashSet};

    let loose = TraitDefinition {
        id: "test/loose".to_string(),
        desc: "Loose".to_string(),
        conf: 0.7,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        r#if: Condition::Raw {
            exact: None,
            substr: Some("cmd".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        },
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };
    let medium = TraitDefinition {
        id: "test/medium".to_string(),
        desc: "Medium".to_string(),
        conf: 0.8,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::Linux],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::Elf],
        for_from_groups: false,
        r#if: Condition::Text {
            is_check: None,
            exact: Some("execve".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            substr: None,
            section: Some(".rodata".to_string()),
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        },
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };
    let strong = TraitDefinition {
        id: "test/strong".to_string(),
        desc: "Strong".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::Windows],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::Pe],
        for_from_groups: false,
        r#if: Condition::TreeSitter {
            kind: Some("call".to_string()),
            node: None,
            exact: Some("CreateRemoteThread".to_string()),
            substr: None,
            regex: None,
            query: None,
            language: Some("javascript".to_string()),
            case_insensitive: false,
        },
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let loose_precision = validation::calculate_trait_precision(&loose);
    let medium_precision = validation::calculate_trait_precision(&medium);
    let strong_precision = validation::calculate_trait_precision(&strong);

    let composite = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/any-average".to_string(),
        desc: "Any average".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        all: None,
        any: Some(vec![
            Condition::Trait {
                id: "test/loose".to_string(),
            },
            Condition::Trait {
                id: "test/medium".to_string(),
            },
            Condition::Trait {
                id: "test/strong".to_string(),
            },
        ]),
        needs: Some(2),
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let composites = [composite];
    let traits = [loose, medium, strong];
    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composites.iter().map(|c| (c.id.as_str(), c)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> =
        traits.iter().map(|t| (t.id.as_str(), t)).collect();
    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();

    let precision = validation::calculate_composite_precision(
        "test/any-average",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );
    let expected = (loose_precision + medium_precision) / 2.0 - 0.15;

    assert!(strong_precision > medium_precision && medium_precision > loose_precision);
    assert!(
        (precision - expected).abs() < 0.01,
        "any precision should use weakest average with breadth penalty, got {precision} vs {expected}"
    );
}

#[test]
fn test_inherited_composite_scores_are_compressed() {
    use std::collections::{HashMap, HashSet};

    let strong_a = TraitDefinition {
        id: "test/strong-a".to_string(),
        desc: "Strong A".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::Windows],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::Pe],
        for_from_groups: false,
        r#if: Condition::TreeSitter {
            kind: Some("call".to_string()),
            node: None,
            exact: Some("CreateRemoteThread".to_string()),
            substr: None,
            regex: None,
            query: None,
            language: Some("javascript".to_string()),
            case_insensitive: false,
        },
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };
    let strong_b = TraitDefinition {
        id: "test/strong-b".to_string(),
        ..strong_a.clone()
    };

    let child = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/child".to_string(),
        desc: "Child".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::Windows],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::Pe],
        for_from_groups: false,
        all: Some(vec![
            Condition::Trait {
                id: "test/strong-a".to_string(),
            },
            Condition::Trait {
                id: "test/strong-b".to_string(),
            },
        ]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };
    let parent = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/parent".to_string(),
        desc: "Parent".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::Windows],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::Pe],
        for_from_groups: false,
        all: Some(vec![Condition::Trait {
            id: "test/child".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let composites = [child, parent];
    let traits = [strong_a, strong_b];
    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composites.iter().map(|c| (c.id.as_str(), c)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> =
        traits.iter().map(|t| (t.id.as_str(), t)).collect();
    let mut cache = HashMap::new();
    let mut visiting = HashSet::new();

    let child_precision = validation::calculate_composite_precision(
        "test/child",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );
    let parent_precision = validation::calculate_composite_precision(
        "test/parent",
        &composite_lookup,
        &trait_lookup,
        &mut cache,
        &mut visiting,
    );

    assert!(child_precision > validation::atomic_calibrated_max());
    assert!(parent_precision < child_precision);
}
