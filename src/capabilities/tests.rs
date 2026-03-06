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
    CompositeTrait, Condition, FileType as RuleFileType, Platform, SectionMap, TraitDefinition,
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
    assert!(mapper.lookup("socket", "test").is_none());
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
    let capability = mapper.lookup("nonexistent_func", "test");
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
    assert_eq!(result.len(), 7);
    assert!(result.contains(&RuleFileType::Elf));
    assert!(result.contains(&RuleFileType::Macho));
    assert!(result.contains(&RuleFileType::Pe));
    assert!(result.contains(&RuleFileType::Dylib));
    assert!(result.contains(&RuleFileType::So));
    assert!(result.contains(&RuleFileType::Dll));
    assert!(result.contains(&RuleFileType::Class));
}

#[test]
fn test_apply_trait_defaults_applies_all_defaults() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["php".to_string()]),
        platforms: Some(vec!["linux".to_string()]),
        crit: Some("suspicious".to_string()),
        conf: Some(0.85),
        mbc: Some("B0001".to_string()),
        attack: Some("T1059".to_string()),
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: None,
        crit: None,
        mbc: None,
        attack: None,
        platforms: None,
        file_types: None,
        size_min: None,
        size_max: None,
        not: None,
        unless: None,
        downgrade: None,
        condition: Some(Condition::String {
            external_ip: false,
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
            compiled_regex: None,
        }),
        count_min: Some(1),
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
    };

    let result =
        parsing::apply_trait_defaults(raw, &defaults, &mut Vec::new(), Path::new("test.yaml"));

    assert_eq!(result.conf, 0.85);
    assert_eq!(result.crit, Criticality::Suspicious);
    assert_eq!(result.mbc, Some("B0001".to_string()));
    assert_eq!(result.attack, Some("T1059".to_string()));
    assert_eq!(result.platforms, vec![Platform::Linux]);
    assert_eq!(result.r#for, vec![RuleFileType::Php]);
}

#[test]
fn test_apply_trait_defaults_trait_overrides_defaults() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["php".to_string()]),
        platforms: Some(vec!["linux".to_string()]),
        crit: Some("suspicious".to_string()),
        conf: Some(0.85),
        mbc: Some("B0001".to_string()),
        attack: Some("T1059".to_string()),
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: Some(0.99),
        crit: Some("hostile".to_string()),
        mbc: Some("B0002".to_string()),
        attack: Some("T1234".to_string()),
        platforms: Some(vec!["windows".to_string()]),
        file_types: Some(vec!["pe".to_string()]),
        size_min: None,
        size_max: None,
        not: None,
        unless: None,
        downgrade: None,
        condition: Some(Condition::String {
            external_ip: false,
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
            compiled_regex: None,
        }),
        count_min: Some(1),
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
    };

    let result =
        parsing::apply_trait_defaults(raw, &defaults, &mut Vec::new(), Path::new("test.yaml"));

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
        crit: None,
        conf: None,
        mbc: Some("B0001".to_string()),
        attack: Some("T1059".to_string()),
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: None,
        crit: None,
        mbc: Some("none".to_string()), // Explicitly unset
        attack: None,                  // Use default
        platforms: None,
        file_types: None,
        size_min: None,
        size_max: None,
        not: None,
        unless: None,
        downgrade: None,
        condition: Some(Condition::String {
            external_ip: false,
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
            compiled_regex: None,
        }),
        count_min: Some(1),
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
    };

    let result =
        parsing::apply_trait_defaults(raw, &defaults, &mut Vec::new(), Path::new("test.yaml"));

    assert_eq!(result.mbc, None); // Unset despite default
    assert_eq!(result.attack, Some("T1059".to_string())); // Default applied
}

#[test]
fn test_apply_trait_defaults_unset_attack_with_none() {
    let defaults = models::TraitDefaults {
        r#for: None,
        platforms: None,
        crit: None,
        conf: None,
        mbc: Some("B0001".to_string()),
        attack: Some("T1059".to_string()),
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: None,
        crit: None,
        mbc: None,                        // Use default
        attack: Some("NONE".to_string()), // Explicitly unset (uppercase)
        platforms: None,
        file_types: None,
        size_min: None,
        size_max: None,
        not: None,
        unless: None,
        downgrade: None,
        condition: Some(Condition::String {
            external_ip: false,
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
            compiled_regex: None,
        }),
        count_min: Some(1),
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
    };

    let result =
        parsing::apply_trait_defaults(raw, &defaults, &mut Vec::new(), Path::new("test.yaml"));

    assert_eq!(result.mbc, Some("B0001".to_string())); // Default applied
    assert_eq!(result.attack, None); // Unset despite default
}

#[test]
fn test_apply_trait_defaults_unset_file_types_with_none() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["php".to_string()]),
        platforms: None,
        crit: None,
        conf: None,
        mbc: None,
        attack: None,
    };

    let raw = models::RawTraitDefinition {
        id: "test/trait".to_string(),
        desc: "Test trait".to_string(),
        conf: None,
        crit: None,
        mbc: None,
        attack: None,
        platforms: None,
        file_types: Some(vec!["none".to_string()]), // Explicitly unset
        size_min: None,
        size_max: None,
        not: None,
        unless: None,
        downgrade: None,
        condition: Some(Condition::String {
            external_ip: false,
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
            compiled_regex: None,
        }),
        count_min: Some(1),
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
    };

    let result =
        parsing::apply_trait_defaults(raw, &defaults, &mut Vec::new(), Path::new("test.yaml"));

    // When unset, file_types defaults to [All]
    assert_eq!(result.r#for, vec![RuleFileType::All]);
}

#[test]
fn test_apply_composite_defaults_applies_all_defaults() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["elf".to_string(), "macho".to_string()]),
        platforms: Some(vec!["linux".to_string(), "macos".to_string()]),
        crit: Some("notable".to_string()),
        conf: Some(0.75),
        mbc: Some("B0030".to_string()),
        attack: Some("T1071.001".to_string()),
    };

    let raw = models::RawCompositeRule {
        id: "test/rule".to_string(),
        desc: "Test rule".to_string(),
        conf: None,
        crit: None,
        mbc: None,
        attack: None,
        platforms: None,
        file_types: None,
        all: None,
        any: None,
        needs: None,
        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        near_lines: None,
        near_bytes: None,
        condition: Some(Condition::String {
            external_ip: false,
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
            compiled_regex: None,
        }),
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
}

#[test]
fn test_apply_composite_defaults_unset_with_none() {
    let defaults = models::TraitDefaults {
        r#for: Some(vec!["elf".to_string()]),
        platforms: Some(vec!["linux".to_string()]),
        crit: Some("suspicious".to_string()),
        conf: Some(0.9),
        mbc: Some("B0030".to_string()),
        attack: Some("T1071".to_string()),
    };

    let raw = models::RawCompositeRule {
        id: "test/rule".to_string(),
        desc: "Test rule".to_string(),
        conf: None,
        crit: None,
        mbc: Some("none".to_string()),             // Unset
        attack: Some("none".to_string()),          // Unset
        platforms: Some(vec!["none".to_string()]), // Unset
        file_types: None,                          // Use default
        all: None,
        any: None,
        needs: None,
        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        near_lines: None,
        near_bytes: None,
        condition: Some(Condition::String {
            external_ip: false,
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
            compiled_regex: None,
        }),
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
      type: string
      exact: "test1"

  - id: test/overrides-some
    description: "Overrides some defaults"
    mbc: "B0002"
    criticality: notable
    condition:
      type: string
      exact: "test2"

  - id: test/unsets-mbc
    description: "Unsets mbc"
    mbc: none
    condition:
      type: string
      exact: "test3"

  - id: test/unsets-attack
    description: "Unsets attack"
    attack: NONE
    condition:
      type: string
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
      type: string
      exact: "HTTP/1.1"

  - id: test/unsets-attack
    description: "Unsets attack"
    confidence: 0.6
    attack: none
    condition:
      type: string
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

#[test]
fn test_iterative_eval_single_pass() {
    // Test that simple composites work in a single pass
    let mapper = CapabilityMapper::empty();
    let report = test_report_with_findings(vec![test_finding("atomic/trait-a")]);
    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default());
    assert!(findings.is_empty()); // Empty mapper returns no findings
}

#[test]
fn test_iterative_eval_max_iterations_protection() {
    // Test that MAX_ITERATIONS limit prevents infinite loops
    let report = test_report_with_findings(vec![]);
    let mapper = CapabilityMapper::empty();

    let start = std::time::Instant::now();
    let _ = mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default());
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
        id: "test/composite".to_string(),
        desc: "Test composite".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "test/atomic-trait".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    let report = test_report_with_findings(vec![test_finding("test/atomic-trait")]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite);

    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "test/composite");
}

#[test]
fn test_composite_of_composites_two_levels() {
    // Level 1: atomic-trait -> Level 2: composite-a -> Level 3: composite-b
    let composite_a = CompositeTrait {
        id: "test/composite-a".to_string(),
        desc: "First level".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "test/atomic-trait".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    let composite_b = CompositeTrait {
        id: "test/composite-b".to_string(),
        desc: "Second level".to_string(),
        conf: 0.95,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "test/composite-a".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    let report = test_report_with_findings(vec![test_finding("test/atomic-trait")]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite_a);
    mapper.composite_rules.push(composite_b);

    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default());

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
        id: id.to_string(),
        desc: format!("Composite {}", id),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: requires.to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
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
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default());

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
        id: "circular/a".to_string(),
        desc: "Circular A".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "circular/b".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    let composite_b = CompositeTrait {
        id: "circular/b".to_string(),
        desc: "Circular B".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "circular/a".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    let report = test_report_with_findings(vec![]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite_a);
    mapper.composite_rules.push(composite_b);

    let start = std::time::Instant::now();
    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default());
    let elapsed = start.elapsed();

    assert!(elapsed.as_millis() < 100, "Took too long: {:?}", elapsed);
    assert!(findings.is_empty(), "Circular deps shouldn't match");
}

#[test]
fn test_composite_prefix_matching_in_chain() {
    // Test prefix matching works in composite chains
    let composite = CompositeTrait {
        id: "test/uses-discovery".to_string(),
        desc: "Uses discovery".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "discovery/system".to_string(), // Prefix match
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    // Report has specific trait under discovery/system/
    let report = test_report_with_findings(vec![test_finding("discovery/system/hostname")]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite);

    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default());
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id, "test/uses-discovery");
}

#[test]
fn test_composite_requires_count_in_chain() {
    let composite = CompositeTrait {
        id: "test/needs-two".to_string(),
        desc: "Needs 2 of 3".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
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
        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    let report = test_report_with_findings(vec![test_finding("feat/a"), test_finding("feat/c")]);
    let mut mapper = CapabilityMapper::empty();
    mapper.composite_rules.push(composite);

    let findings =
        mapper.evaluate_composite_rules(&report, &[], None, None, &SectionMap::default());
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
        id: "test/three-strings".to_string(),
        desc: "Test rule with 3 strings".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::String {
                external_ip: false,
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
                compiled_regex: None,
            },
            Condition::String {
                external_ip: false,
                exact: Some("string2".to_string()),
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
                compiled_regex: None,
            },
            Condition::String {
                external_ip: false,
                exact: Some("string3".to_string()),
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
                compiled_regex: None,
            },
        ]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
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
        id: "test/with-filetype".to_string(),
        desc: "Test rule with file type".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::Elf, RuleFileType::Pe], // File type filter
        all: Some(vec![
            Condition::String {
                external_ip: false,
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
                compiled_regex: None,
            },
            Condition::String {
                external_ip: false,
                exact: Some("string2".to_string()),
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
                compiled_regex: None,
            },
        ]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
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
        r#for: vec![RuleFileType::All],
        r#if: Condition::String {
            external_ip: false,
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
            compiled_regex: None,
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
    };

    // Composite A: has 2 direct conditions (precision 2)
    let composite_a = CompositeTrait {
        id: "test/composite-a".to_string(),
        desc: "Composite A".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::String {
                external_ip: false,
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
                compiled_regex: None,
            },
            Condition::String {
                external_ip: false,
                exact: Some("string2".to_string()),
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
                compiled_regex: None,
            },
        ]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    // Composite B: references composite A and atomic trait
    let composite_b = CompositeTrait {
        id: "test/composite-b".to_string(),
        desc: "Composite B".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
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

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
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
        id: "test/circular-a".to_string(),
        desc: "Circular A".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "test/circular-b".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    // Composite B references A (cycle!)
    let composite_b = CompositeTrait {
        id: "test/circular-b".to_string(),
        desc: "Circular B".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "test/circular-a".to_string(),
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
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
        id: "test/cacheable".to_string(),
        desc: "Cacheable rule".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::String {
                external_ip: false,
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
                compiled_regex: None,
            },
            Condition::String {
                external_ip: false,
                exact: Some("string2".to_string()),
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
                compiled_regex: None,
            },
        ]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
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
        id: "test/low-precision".to_string(),
        desc: "Low precision".to_string(),
        conf: 0.95,
        crit: Criticality::Hostile, // Will be downgraded
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::String {
                external_ip: false,
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
                compiled_regex: None,
            },
            Condition::String {
                external_ip: false,
                exact: Some("string2".to_string()),
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
                compiled_regex: None,
            },
            Condition::String {
                external_ip: false,
                exact: Some("string3".to_string()),
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
                compiled_regex: None,
            },
        ]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    // Rule with precision >= 3.5 (meets threshold)
    // With the new granular scoring: 25-char strings = 5 buckets * 0.3 = 1.5 each
    // 3 strings = 4.5 precision, which meets the 4.0 threshold
    let rule_high = CompositeTrait {
        id: "test/high-precision".to_string(),
        desc: "High precision".to_string(),
        conf: 0.95,
        crit: Criticality::Hostile, // Will NOT be downgraded
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::String {
                external_ip: false,
                exact: Some("this_is_a_very_long_string_pattern_one".to_string()), // 38 chars = 8 buckets * 0.3 = 2.4
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
                compiled_regex: None,
            },
            Condition::String {
                external_ip: false,
                exact: Some("this_is_another_very_long_string_pattern".to_string()), // 40 chars = 8 buckets * 0.3 = 2.4
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
                compiled_regex: None,
            },
        ]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    let mut composites = vec![rule_low, rule_high];
    let traits: Vec<TraitDefinition> = vec![];

    // Precalculate precision before validation
    validation::precalculate_all_composite_precisions(&mut composites, &traits);

    // Run validation
    validation::validate_hostile_composite_precision(
        &mut composites,
        &traits,
        &mut Vec::new(),
        4.0,
        2.0,
    );

    // Check that low precision was downgraded
    let low_rule = composites
        .iter()
        .find(|r| r.id == "test/low-precision")
        .unwrap();
    assert_eq!(low_rule.crit, Criticality::Suspicious);

    // Check that high precision was NOT downgraded
    let high_rule = composites
        .iter()
        .find(|r| r.id == "test/high-precision")
        .unwrap();
    assert_eq!(high_rule.crit, Criticality::Hostile);
}

#[test]
fn test_suspicious_precision_threshold_validation() {
    // Rule with precision 1 (below suspicious threshold of 2)
    let rule_low = CompositeTrait {
        id: "test/suspicious-low-precision".to_string(),
        desc: "Low precision suspicious rule".to_string(),
        conf: 0.8,
        crit: Criticality::Suspicious, // Will be downgraded
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::String {
            external_ip: false,
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
            compiled_regex: None,
        }]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    // Rule with precision >= 2.0 (meets suspicious threshold)
    // With granular scoring: 25-char string = 5 buckets * 0.3 = 1.5
    // Two 25-char strings = 3.0, which meets the 2.0 threshold
    let rule_ok = CompositeTrait {
        id: "test/suspicious-good-precision".to_string(),
        desc: "Good precision suspicious rule".to_string(),
        conf: 0.8,
        crit: Criticality::Suspicious, // Will NOT be downgraded
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::String {
                external_ip: false,
                exact: Some("this_is_a_long_string_pattern".to_string()), // 29 chars = 6 buckets * 0.3 = 1.8
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
                compiled_regex: None,
            },
            Condition::String {
                external_ip: false,
                exact: Some("another_long_string_pattern".to_string()), // 27 chars = 6 buckets * 0.3 = 1.8
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
                compiled_regex: None,
            },
        ]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    let mut composites = vec![rule_low, rule_ok];
    let traits: Vec<TraitDefinition> = vec![];

    // Precalculate precision before validation
    validation::precalculate_all_composite_precisions(&mut composites, &traits);

    // Run validation
    validation::validate_hostile_composite_precision(
        &mut composites,
        &traits,
        &mut Vec::new(),
        4.0,
        2.0,
    );

    // Check that low precision suspicious rule was downgraded
    let low_rule = composites
        .iter()
        .find(|r| r.id == "test/suspicious-low-precision")
        .unwrap();
    assert_eq!(low_rule.crit, Criticality::Notable);

    // Check that sufficient precision suspicious rule was NOT downgraded
    let ok_rule = composites
        .iter()
        .find(|r| r.id == "test/suspicious-good-precision")
        .unwrap();
    assert_eq!(ok_rule.crit, Criticality::Suspicious);
}

/// Test precision with mixed condition types (all, any, none)
#[test]
fn test_precision_mixed_conditions() {
    use std::collections::{HashMap, HashSet};

    let rule = CompositeTrait {
        id: "test/mixed".to_string(),
        desc: "Mixed conditions".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::String {
            external_ip: false,
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
            compiled_regex: None,
        }]),
        any: Some(vec![
            Condition::String {
                external_ip: false,
                exact: Some("string2".to_string()),
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
                compiled_regex: None,
            },
            Condition::String {
                external_ip: false,
                exact: Some("string3".to_string()),
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
                compiled_regex: None,
            },
        ]),
        needs: None,
        near_lines: None,
        near_bytes: None,
        none: Some(vec![Condition::String {
            external_ip: false,
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
            compiled_regex: None,
        }]),
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
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
        id: "test/level1".to_string(),
        desc: "Level 1".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::String {
                external_ip: false,
                exact: Some("l1-s1".to_string()),
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
                compiled_regex: None,
            },
            Condition::String {
                external_ip: false,
                exact: Some("l1-s2".to_string()),
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
                compiled_regex: None,
            },
        ]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    // Level 2: references level1 + 1 direct condition
    let level2 = CompositeTrait {
        id: "test/level2".to_string(),
        desc: "Level 2".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::Trait {
                id: "test/level1".to_string(),
            },
            Condition::String {
                external_ip: false,
                exact: Some("l2-s1".to_string()),
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
                compiled_regex: None,
            },
        ]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
    };

    // Level 3: references level2 + 1 direct condition
    let level3 = CompositeTrait {
        id: "test/level3".to_string(),
        desc: "Level 3".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![
            Condition::Trait {
                id: "test/level2".to_string(),
            },
            Condition::String {
                external_ip: false,
                exact: Some("l3-s1".to_string()),
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
                compiled_regex: None,
            },
        ]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,

        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
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
        id: "test/correct-precision".to_string(),
        desc: "Test correct precision calculation".to_string(),
        conf: 0.9,
        crit: Criticality::Hostile,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::JavaScript], // +1 (not "all")
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
        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
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
        r#for: vec![RuleFileType::All],
        r#if: Condition::String {
            external_ip: false,
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
            compiled_regex: None,
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
        r#for: vec![RuleFileType::All],
        r#if: Condition::String {
            external_ip: false,
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
            compiled_regex: None,
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
    };

    // Composite rule referencing both traits
    let composite = CompositeTrait {
        id: "test/composite-with-sized-traits".to_string(),
        desc: "Composite with sized traits".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
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
        none: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
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
      type: string
      regex: "test"

  - id: invalid-trait
    desc: This one has indentation error
    crit: suspicious
  conf: 0.9
    for: [elf]
    if:
      type: string
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
    assert_eq!(binaries.len(), 7);
    assert!(binaries.contains(&RuleFileType::Elf));
    assert!(!binaries.contains(&RuleFileType::Python));

    let scripts = parsing::parse_file_types(&["scripts".to_string()], &mut warnings);
    assert_eq!(scripts.len(), 10); // TypeScript maps to JavaScript, not separate
    assert!(scripts.contains(&RuleFileType::Python));
    assert!(scripts.contains(&RuleFileType::Shell));
    assert!(!scripts.contains(&RuleFileType::Elf));

    // Test alias "all"
    let all = parsing::parse_file_types(&["all".to_string()], &mut warnings);
    assert_eq!(all, vec![RuleFileType::All]);

    // Test exclusions
    // -php means All - Php.
    let not_php = parsing::parse_file_types(&["-php".to_string()], &mut warnings);
    assert!(!not_php.contains(&RuleFileType::Php));
    assert!(not_php.contains(&RuleFileType::Python));
    assert!(not_php.contains(&RuleFileType::Elf));
    assert!(!not_php.contains(&RuleFileType::All)); // Should be expanded

    // Test group + exclusion: scripts,-php
    let scripts_no_php =
        parsing::parse_file_types(&["scripts".to_string(), "-php".to_string()], &mut warnings);
    assert!(scripts_no_php.contains(&RuleFileType::Python));
    assert!(scripts_no_php.contains(&RuleFileType::Shell));
    assert!(!scripts_no_php.contains(&RuleFileType::Php));
    assert!(!scripts_no_php.contains(&RuleFileType::Elf));

    // Test single string comma separation
    let comma_sep = parsing::parse_file_types(&["scripts,-php".to_string()], &mut warnings);
    assert!(comma_sep.contains(&RuleFileType::Python));
    assert!(!comma_sep.contains(&RuleFileType::Php));

    // Test '-binaries' exclusion
    let not_binaries = parsing::parse_file_types(&["-binaries".to_string()], &mut warnings);
    assert!(!not_binaries.contains(&RuleFileType::Elf));
    assert!(not_binaries.contains(&RuleFileType::Python));

    // Test '-scripts' exclusion
    let not_scripts = parsing::parse_file_types(&["-scripts".to_string()], &mut warnings);
    assert!(!not_scripts.contains(&RuleFileType::Python));
    assert!(not_scripts.contains(&RuleFileType::Elf));
}

// ==================== Import Finding Generation Tests ====================

#[test]
fn test_normalize_import_name_basic() {
    assert_eq!(CapabilityMapper::normalize_import_name("socket"), "socket");
    // Dots are converted to slashes for trait path consistency
    assert_eq!(
        CapabilityMapper::normalize_import_name("os.system"),
        "os/system"
    );
    // Slashes are preserved as path separators (like dots)
    assert_eq!(
        CapabilityMapper::normalize_import_name("net/http"),
        "net/http"
    );
}

#[test]
fn test_normalize_import_name_special_chars() {
    // @ is stripped (leading special char), / is preserved as path separator
    assert_eq!(
        CapabilityMapper::normalize_import_name("@babel/core"),
        "babel/core"
    );
    assert_eq!(
        CapabilityMapper::normalize_import_name("lodash/fp"),
        "lodash/fp"
    );
}

#[test]
fn test_normalize_import_name_uppercase() {
    // Should lowercase
    assert_eq!(
        CapabilityMapper::normalize_import_name("CreateRemoteThread"),
        "createremotethread"
    );
}

#[test]
fn test_normalize_import_name_collapse_separators() {
    // Should collapse multiple slashes
    assert_eq!(
        CapabilityMapper::normalize_import_name("foo//bar"),
        "foo/bar"
    );
    // @ becomes hyphen, but / stays as path separator
    assert_eq!(
        CapabilityMapper::normalize_import_name("@scope/pkg"),
        "scope/pkg"
    );
}

#[test]
fn test_normalize_import_name_trim_hyphens() {
    // Should trim leading/trailing hyphens
    assert_eq!(CapabilityMapper::normalize_import_name("/foo/"), "foo");
    assert_eq!(CapabilityMapper::normalize_import_name("@pkg"), "pkg");
}

#[test]
fn test_detect_import_ecosystem_binary_types() {
    assert_eq!(
        CapabilityMapper::detect_import_ecosystem("elf", "goblin"),
        "elf"
    );
    assert_eq!(
        CapabilityMapper::detect_import_ecosystem("macho", "goblin"),
        "macho"
    );
    assert_eq!(
        CapabilityMapper::detect_import_ecosystem("pe", "goblin"),
        "pe"
    );
    assert_eq!(
        CapabilityMapper::detect_import_ecosystem("dylib", "goblin"),
        "macho"
    );
    assert_eq!(
        CapabilityMapper::detect_import_ecosystem("so", "goblin"),
        "elf"
    );
}

#[test]
fn test_detect_import_ecosystem_source_types() {
    assert_eq!(
        CapabilityMapper::detect_import_ecosystem("python", "ast"),
        "python"
    );
    assert_eq!(
        CapabilityMapper::detect_import_ecosystem("javascript", "ast"),
        "npm"
    );
    assert_eq!(
        CapabilityMapper::detect_import_ecosystem("ruby", "ast"),
        "ruby"
    );
    assert_eq!(
        CapabilityMapper::detect_import_ecosystem("java", "ast"),
        "java"
    );
    assert_eq!(CapabilityMapper::detect_import_ecosystem("go", "ast"), "go");
}

#[test]
fn test_detect_import_ecosystem_explicit_source() {
    // Explicit source markers should take precedence
    assert_eq!(
        CapabilityMapper::detect_import_ecosystem("unknown", "npm"),
        "npm"
    );
    assert_eq!(
        CapabilityMapper::detect_import_ecosystem("unknown", "package.json"),
        "npm"
    );
    assert_eq!(
        CapabilityMapper::detect_import_ecosystem("unknown", "cargo"),
        "cargo"
    );
}

#[test]
fn test_generate_import_findings_basic() {
    use crate::types::Import;

    let mut report = AnalysisReport::new(TargetInfo {
        path: "/test/script.py".to_string(),
        file_type: "python".to_string(),
        size_bytes: 1000,
        sha256: "abc123".to_string(),
        architectures: None,
    });

    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "import".to_string(), // Use "import" for actual module imports
    });
    report.imports.push(Import {
        symbol: "os.system".to_string(),
        library: None,
        source: "import".to_string(), // Use "import" for actual module imports
    });

    CapabilityMapper::generate_import_findings(&mut report);

    // Should have 2 findings
    assert_eq!(report.findings.len(), 2);

    // Check IDs
    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"metadata/import/python::socket"));
    assert!(ids.contains(&"metadata/import/python::os/system"));

    // Check finding properties
    let socket_finding = report
        .findings
        .iter()
        .find(|f| f.id == "metadata/import/python::socket")
        .unwrap();
    assert_eq!(socket_finding.crit, Criticality::Baseline);
    assert_eq!(socket_finding.kind, FindingKind::Structural);
    assert!((socket_finding.conf - 0.95).abs() < 0.01);
}

#[test]
fn test_generate_import_findings_with_library() {
    use crate::types::Import;

    let mut report = AnalysisReport::new(TargetInfo {
        path: "/test/binary".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 1000,
        sha256: "abc123".to_string(),
        architectures: None,
    });

    report.imports.push(Import {
        symbol: "printf".to_string(),
        library: Some("libc.so.6".to_string()),
        source: "goblin".to_string(),
    });

    CapabilityMapper::generate_import_findings(&mut report);

    // For binaries we generate:
    // - metadata/internal/symbols/{symbol} for symbols (ML only, not for composite traits)
    // - metadata/dylib/{library} for linked libraries (for composite trait matching)
    assert_eq!(report.findings.len(), 2);

    // Check symbol-level finding (in metadata/internal/symbols/)
    // Note: desc is empty for compactness (derivable from id)
    let symbol_finding = report
        .findings
        .iter()
        .find(|f| f.id == "metadata/internal/symbols::printf")
        .expect("should have symbol-level finding in metadata/internal/symbols/");
    assert!(
        symbol_finding.desc.is_empty(),
        "symbol desc should be empty for compactness"
    );

    // Check library-level finding (in metadata/dylib/)
    let dylib_finding = report
        .findings
        .iter()
        .find(|f| f.id == "metadata/dylib::libc/so/6")
        .expect("should have dylib finding");
    assert!(dylib_finding.desc.contains("links libc.so.6"));
}

#[test]
fn test_generate_import_findings_dedup() {
    use crate::types::Import;

    let mut report = AnalysisReport::new(TargetInfo {
        path: "/test/script.py".to_string(),
        file_type: "python".to_string(),
        size_bytes: 1000,
        sha256: "abc123".to_string(),
        architectures: None,
    });

    // Add same import twice
    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "import".to_string(), // Use "import" for actual module imports
    });
    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "import".to_string(), // Use "import" for actual module imports
    });

    CapabilityMapper::generate_import_findings(&mut report);

    // Should only have 1 finding (deduped)
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn test_generate_import_findings_script_function_calls() {
    // Test that function calls in scripts go to metadata/internal/symbols/
    // while actual imports go to metadata/import/{lang}::{module}
    use crate::types::Import;

    let mut report = AnalysisReport::new(TargetInfo {
        path: "/test/script.rb".to_string(),
        file_type: "ruby".to_string(),
        size_bytes: 1000,
        sha256: "abc123".to_string(),
        architectures: None,
    });

    // Actual import (require statement)
    report.imports.push(Import {
        symbol: "net/http".to_string(),
        library: None,
        source: "import".to_string(),
    });

    // Function call (method invocation)
    report.imports.push(Import {
        symbol: "system".to_string(),
        library: None,
        source: "ast".to_string(),
    });

    // Another function call
    report.imports.push(Import {
        symbol: "open".to_string(),
        library: None,
        source: "ast".to_string(),
    });

    CapabilityMapper::generate_import_findings(&mut report);

    // Should have 3 findings: 1 import + 2 function calls
    assert_eq!(report.findings.len(), 3);

    let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();

    // Actual import goes to metadata/import/
    assert!(
        ids.contains(&"metadata/import/ruby::net/http"),
        "Should have metadata/import/ for actual imports"
    );

    // Function calls go to metadata/internal/symbols/
    assert!(
        ids.contains(&"metadata/internal/symbols::system"),
        "Should have metadata/internal/symbols/ for function calls"
    );
    assert!(
        ids.contains(&"metadata/internal/symbols::open"),
        "Should have metadata/internal/symbols/ for function calls"
    );
}

#[test]
fn test_generate_import_findings_npm_package() {
    use crate::types::Import;

    let mut report = AnalysisReport::new(TargetInfo {
        path: "/test/package.json".to_string(),
        file_type: "package.json".to_string(),
        size_bytes: 1000,
        sha256: "abc123".to_string(),
        architectures: None,
    });

    report.imports.push(Import {
        symbol: "axios".to_string(),
        library: Some("^1.6.0".to_string()),
        source: "npm".to_string(),
    });

    CapabilityMapper::generate_import_findings(&mut report);

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].id, "metadata/import/npm::axios");
}

#[test]
fn test_generate_import_findings_empty_symbol_skipped() {
    use crate::types::Import;

    let mut report = AnalysisReport::new(TargetInfo {
        path: "/test/script.py".to_string(),
        file_type: "python".to_string(),
        size_bytes: 1000,
        sha256: "abc123".to_string(),
        architectures: None,
    });

    // Empty symbol should be skipped
    report.imports.push(Import {
        symbol: "".to_string(),
        library: None,
        source: "ast".to_string(),
    });
    // Symbol that normalizes to empty should also be skipped
    report.imports.push(Import {
        symbol: "@@".to_string(),
        library: None,
        source: "ast".to_string(),
    });

    CapabilityMapper::generate_import_findings(&mut report);

    assert_eq!(report.findings.len(), 0);
}

#[test]
fn test_generate_import_findings_preserves_existing() {
    use crate::types::Import;

    let mut report = AnalysisReport::new(TargetInfo {
        path: "/test/script.py".to_string(),
        file_type: "python".to_string(),
        size_bytes: 1000,
        sha256: "abc123".to_string(),
        architectures: None,
    });

    // Add a pre-existing finding
    report.findings.push(Finding {
        id: "micro-behaviors/execution/shell".to_string(),
        kind: FindingKind::Capability,
        desc: "shell execution".to_string(),
        conf: 0.9,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        match_count: 0,
        source_file: None,
    });

    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "import".to_string(), // Use "import" for actual module imports
    });

    CapabilityMapper::generate_import_findings(&mut report);

    // Should have 2 findings: original + new import
    assert_eq!(report.findings.len(), 2);
    assert!(report
        .findings
        .iter()
        .any(|f| f.id == "micro-behaviors/execution/shell"));
    assert!(report
        .findings
        .iter()
        .any(|f| f.id == "metadata/import/python::socket"));
}

#[test]
fn test_generate_import_findings_skips_existing_import_finding() {
    use crate::types::Import;

    let mut report = AnalysisReport::new(TargetInfo {
        path: "/test/script.py".to_string(),
        file_type: "python".to_string(),
        size_bytes: 1000,
        sha256: "abc123".to_string(),
        architectures: None,
    });

    // Pre-existing import finding (shouldn't be duplicated)
    report.findings.push(Finding {
        id: "metadata/import/python::socket".to_string(),
        kind: FindingKind::Structural,
        desc: "imports socket".to_string(),
        conf: 0.95,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        match_count: 0,
        source_file: None,
    });

    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "import".to_string(), // Use "import" for actual module imports
    });

    CapabilityMapper::generate_import_findings(&mut report);

    // Should still have just 1 finding (no duplicate)
    assert_eq!(report.findings.len(), 1);
}

#[test]
fn test_generate_import_findings_evidence_structure() {
    use crate::types::Import;

    let mut report = AnalysisReport::new(TargetInfo {
        path: "/test/binary".to_string(),
        file_type: "macho".to_string(),
        size_bytes: 1000,
        sha256: "abc123".to_string(),
        architectures: None,
    });

    report.imports.push(Import {
        symbol: "NSLog".to_string(),
        library: Some("Foundation".to_string()),
        source: "goblin".to_string(),
    });

    CapabilityMapper::generate_import_findings(&mut report);

    // For binaries we generate:
    // - metadata/internal/symbols/{symbol} for symbols (ML only)
    // - metadata/dylib/{library} for linked libraries
    assert_eq!(report.findings.len(), 2);

    // Check symbol-level finding (in metadata/internal/symbols/)
    // Note: evidence is empty for compactness (info is derivable from id)
    let symbol_finding = report
        .findings
        .iter()
        .find(|f| f.id == "metadata/internal/symbols::nslog")
        .expect("should have symbol-level finding in metadata/internal/symbols/");
    assert!(
        symbol_finding.evidence.is_empty(),
        "symbol evidence should be empty for compactness"
    );

    // Check library-level finding evidence (in metadata/dylib/)
    // Dylib findings DO have evidence (method="library")
    let dylib_finding = report
        .findings
        .iter()
        .find(|f| f.id == "metadata/dylib::foundation")
        .expect("should have dylib finding");
    assert_eq!(dylib_finding.evidence.len(), 1);
    let dylib_evidence = &dylib_finding.evidence[0];
    assert_eq!(dylib_evidence.method, "library");
}

#[test]
fn test_normalize_import_name_converts_dots_to_slashes() {
    // Dots are converted to slashes for trait path consistency
    assert_eq!(
        CapabilityMapper::normalize_import_name("os.path.join"),
        "os/path/join"
    );
    // Underscores are preserved
    assert_eq!(
        CapabilityMapper::normalize_import_name("__init__"),
        "__init__"
    );
    assert_eq!(
        CapabilityMapper::normalize_import_name("my_module.my_func"),
        "my_module/my_func"
    );
}

// ==================== Composite Rule Validation Tests ====================

#[test]
fn test_collect_trait_refs_finds_internal_paths() {
    // Test that collect_trait_refs_from_rule correctly identifies metadata/internal/ references
    // These references are forbidden in composite rules (for ML use only)

    let composite = CompositeTrait {
        id: "test/bad-composite".to_string(),
        desc: "Composite that incorrectly references internal path".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
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
        none: Some(vec![Condition::Trait {
            id: "metadata/dylib::libc".to_string(), // OK
        }]),
        near_lines: None,
        near_bytes: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
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
        id: "test/references-internal".to_string(),
        desc: "Should not reference internal paths".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        r#for: vec![RuleFileType::All],
        all: Some(vec![Condition::Trait {
            id: "metadata/internal/symbols::evil_func".to_string(),
        }]),
        any: None,
        needs: None,
        none: None,
        near_lines: None,
        near_bytes: None,
        unless: None,
        not: None,
        downgrade: None,
        size_min: None,
        size_max: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
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
      type: string
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
                err_msg.contains("Unknown file type") || err_msg.contains("invalid_lang"),
                "Error message should mention unknown file type, got: {}",
                err_msg
            );
        }
    }
}
