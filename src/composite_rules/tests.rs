//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for composite rules module.

use super::*;
use crate::composite_rules::condition::{NotException, NotExceptionStructured};
use crate::composite_rules::traits::DowngradeConditions;
use crate::types::{
    AnalysisReport, Criticality, Finding, FindingKind, Import, StringInfo, TargetInfo,
};

fn create_test_context() -> (AnalysisReport, Vec<u8>) {
    let target = TargetInfo {
        path: "/test".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 1024,
        sha256: "test".to_string(),
        architectures: Some(vec!["x86_64".to_string()]),
    };

    let mut report = AnalysisReport::new(target);

    // Add some test imports
    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "test".to_string(),
        offset: None,
        alias: None,
    });

    report.imports.push(Import {
        symbol: "connect".to_string(),
        library: None,
        source: "test".to_string(),
        offset: None,
        alias: None,
    });

    // Add some test strings
    report.strings.push(StringInfo {
        value: ("/bin/sh".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: Some(crate::types::StringType::Path),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    (report, vec![])
}

#[test]
fn test_symbol_condition() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/capability".to_string(),
        desc: "Test".to_string(),
        conf: 0.9,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        }]),
        any: None,

        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());

    let cap = result.unwrap();
    assert_eq!(cap.id, "test/capability");
    assert!(!cap.evidence.is_empty());
}

#[test]
fn test_all() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "net/reverse-shell".to_string(),
        desc: "Reverse shell".to_string(),
        conf: 0.9,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        }]),
        any: None,

        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
}

#[test]
fn test_count() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/multi".to_string(),
        desc: "Multiple conditions".to_string(),
        conf: 0.85,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![
            Condition::Symbol {
                exact: None,
                substr: None,
                regex: Some("socket".to_string()),
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: None,
                substr: None,
                regex: Some("connect".to_string()),
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: None,
                substr: None,
                regex: Some("nonexistent".to_string()),
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
        ]),
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
}

#[test]
fn test_string_exact_condition() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/string-exact".to_string(),
        desc: "Exact string match".to_string(),
        conf: 0.9,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Text {
            exact: Some("/bin/sh".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
        }]),
        any: None,

        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
}

#[test]
fn test_any() {
    let (report, data) = create_test_context();
    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/requires-any".to_string(),
        desc: "Requires any condition".to_string(),
        conf: 0.9,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![
            Condition::Symbol {
                exact: None,
                substr: None,
                regex: Some("nonexistent".to_string()),
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: None,
                substr: None,
                regex: Some("socket".to_string()),
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
        ]),

        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
}

// ============================================================================
// Tests for new directives: not:, unless:, downgrade:
// ============================================================================

#[test]
fn test_not_directive_shorthand() {
    let (mut report, data) = create_test_context();

    // Add multiple domain strings
    report.strings.push(StringInfo {
        value: ("apple.com".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: Some(crate::types::StringType::Url),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: ("evil.com".to_string()).into(),
        offset: Some(0x3000),
        encoding: "utf8".to_string(),
        string_type: Some(crate::types::StringType::Url),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let trait_def = TraitDefinition {
        id: "test/domains".to_string(),
        desc: "Domain detection".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: None,
            substr: None,
            regex: Some(r"[a-z]+\.com".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
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
        not: Some(vec![NotException::Shorthand("apple.com".to_string())]),
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should only have evil.com, not apple.com
    assert_eq!(finding.evidence.len(), 1);
    assert!(finding.evidence[0].value.contains("evil.com"));
}

#[test]
fn test_not_directive_exact() {
    let (mut report, data) = create_test_context();

    report.strings.push(StringInfo {
        value: ("github.com".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: Some(crate::types::StringType::Url),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: ("bad.com".to_string()).into(),
        offset: Some(0x3000),
        encoding: "utf8".to_string(),
        string_type: Some(crate::types::StringType::Url),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let trait_def = TraitDefinition {
        id: "test/domains".to_string(),
        desc: "Domain detection".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: None,
            substr: None,
            regex: Some(r"[a-z]+\.com".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
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
        not: Some(vec![NotException::Structured(NotExceptionStructured {
            exact: Some("github.com".to_string()),
            substr: None,
            regex: None,
            lowered_substr: None,
        })]),
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    assert_eq!(finding.evidence.len(), 1);
    assert!(finding.evidence[0].value.contains("bad.com"));
}

#[test]
fn test_not_directive_regex() {
    let (mut report, data) = create_test_context();

    // Add IP addresses
    report.strings.push(StringInfo {
        value: ("192.168.1.1".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: Some(crate::types::StringType::IP),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: ("8.8.8.8".to_string()).into(),
        offset: Some(0x3000),
        encoding: "utf8".to_string(),
        string_type: Some(crate::types::StringType::IP),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let trait_def = TraitDefinition {
        id: "test/ips".to_string(),
        desc: "IP detection".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: None,
            substr: None,
            regex: Some(r"\d+\.\d+\.\d+\.\d+".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
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
        not: Some(vec![NotException::Structured(NotExceptionStructured {
            exact: None,
            substr: None,
            regex: Some(r"^192\.168\.".to_string()),
            lowered_substr: None,
        })]),
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should only have 8.8.8.8, not 192.168.1.1
    assert_eq!(finding.evidence.len(), 1);
    assert!(finding.evidence[0].value.contains("8.8.8.8"));
}

#[test]
fn test_unless_directive_skips_trait() {
    let (report, data) = create_test_context();

    // Add a finding that would trigger unless condition
    let findings = vec![Finding {
        id: "file/signed/apple".to_string(),
        kind: FindingKind::Capability,
        desc: "Apple signed binary".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        match_count: 0,
        source_file: None,
    }];

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None)
        .with_additional_findings(&findings);

    let trait_def = TraitDefinition {
        id: "test/network".to_string(),
        desc: "Network activity".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
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
        unless: Some(vec![Condition::Trait {
            id: "file/signed/apple".to_string(),
        }]),
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Should return None because unless condition matches
    let result = trait_def.evaluate(&ctx);
    assert!(result.is_none());
}

#[test]
fn test_unless_directive_allows_trait() {
    let (report, data) = create_test_context();

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let trait_def = TraitDefinition {
        id: "test/network".to_string(),
        desc: "Network activity".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
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
        unless: Some(vec![Condition::Trait {
            id: "file/signed/apple".to_string(),
        }]),
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Should return Some because unless condition doesn't match
    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
}

#[test]
fn test_downgrade_to_notable() {
    let (report, data) = create_test_context();

    // Add finding for downgrade condition
    let findings = vec![Finding {
        id: "file/type/shell-script".to_string(),
        kind: FindingKind::Capability,
        desc: "Shell script".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        match_count: 0,
        source_file: None,
    }];

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None)
        .with_additional_findings(&findings);

    let trait_def = TraitDefinition {
        id: "test/curl-pipe".to_string(),
        desc: "Curl pipe to bash".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: Some("/bin/sh".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
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
        downgrade: Some(DowngradeConditions {
            any: Some(vec![Condition::Trait {
                id: "file/type/shell-script".to_string(),
            }]),
            all: None,
            none: None,
            needs: None,
        }),
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should be downgraded one level: Suspicious → Notable
    assert_eq!(finding.crit, Criticality::Notable);
}

#[test]
fn test_downgrade_one_level() {
    let (report, data) = create_test_context();

    let findings = vec![Finding {
        id: "file/path/test-fixtures".to_string(),
        kind: FindingKind::Capability,
        desc: "Test fixture".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        match_count: 0,
        source_file: None,
    }];

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None)
        .with_additional_findings(&findings);

    let trait_def = TraitDefinition {
        id: "test/network".to_string(),
        desc: "Network call".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
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
        downgrade: Some(DowngradeConditions {
            any: Some(vec![Condition::Trait {
                id: "file/path/test-fixtures".to_string(),
            }]),
            all: None,
            none: None,
            needs: None,
        }),
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should be downgraded one level: Notable → baseline
    assert_eq!(finding.crit, Criticality::Baseline);
}

#[test]
fn test_downgrade_no_match_keeps_original() {
    let (report, data) = create_test_context();

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let trait_def = TraitDefinition {
        id: "test/network".to_string(),
        desc: "Network call".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
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
        downgrade: Some(DowngradeConditions {
            any: Some(vec![Condition::Trait {
                id: "file/signed/apple".to_string(),
            }]),
            all: None,
            none: None,
            needs: None,
        }),
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should keep original Suspicious (downgrade condition didn't match)
    assert_eq!(finding.crit, Criticality::Suspicious);
}

#[test]
fn test_downgrade_from_hostile() {
    let (report, data) = create_test_context();

    // Add finding that will trigger downgrade
    let findings = vec![Finding {
        id: "file/type/shell-script".to_string(),
        kind: FindingKind::Capability,
        desc: "Shell script".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        match_count: 0,
        source_file: None,
    }];

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None)
        .with_additional_findings(&findings);

    let trait_def = TraitDefinition {
        id: "test/network".to_string(),
        desc: "Network call".to_string(),
        conf: 1.0,
        crit: Criticality::Hostile,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
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
        downgrade: Some(DowngradeConditions {
            any: Some(vec![Condition::Trait {
                id: "file/type/shell-script".to_string(),
            }]),
            all: None,
            none: None,
            needs: None,
        }),
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should be downgraded one level: Hostile → Suspicious
    assert_eq!(finding.crit, Criticality::Suspicious);
}

#[test]
fn test_all_three_directives_combined() {
    let (mut report, data) = create_test_context();

    // Add strings
    report.strings.push(StringInfo {
        value: ("apple.com".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: Some(crate::types::StringType::Url),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: ("evil.com".to_string()).into(),
        offset: Some(0x3000),
        encoding: "utf8".to_string(),
        string_type: Some(crate::types::StringType::Url),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    // Add finding for downgrade
    let findings = vec![Finding {
        id: "file/type/test".to_string(),
        kind: FindingKind::Capability,
        desc: "Test file".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        match_count: 0,
        source_file: None,
    }];

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None)
        .with_additional_findings(&findings);

    let trait_def = TraitDefinition {
        id: "test/domains".to_string(),
        desc: "Domain detection".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: None,
            substr: None,
            regex: Some(r"[a-z]+\.com".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
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
        not: Some(vec![NotException::Shorthand("apple.com".to_string())]),
        unless: None,
        downgrade: Some(DowngradeConditions {
            any: Some(vec![Condition::Trait {
                id: "file/type/test".to_string(),
            }]),
            all: None,
            none: None,
            needs: None,
        }),
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());

    let finding = result.unwrap();
    // Should filter apple.com (not:)
    assert_eq!(finding.evidence.len(), 1);
    assert!(finding.evidence[0].value.contains("evil.com"));
    // Should be downgraded one level: Suspicious → Notable
    assert_eq!(finding.crit, Criticality::Notable);
}

// ===== Tests for exact vs substr vs regex match modes =====

#[test]
fn test_string_exact_match_requires_full_equality() {
    let (mut report, data) = create_test_context();

    // Add test strings
    report.strings.push(StringInfo {
        value: ("hello".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: ("hello world".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    // exact: "hello" should match only "hello", not "hello world"
    let trait_def = TraitDefinition {
        id: "test/exact".to_string(),
        desc: "Exact match test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: Some("hello".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
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

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // Should only match "hello", not "hello world"
    assert_eq!(finding.evidence.len(), 1);
    assert_eq!(finding.evidence[0].value, "hello");
}

#[test]
fn test_string_substr_matches_substrings() {
    let (mut report, data) = create_test_context();

    // Add test strings
    report.strings.push(StringInfo {
        value: ("hello".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: ("hello world".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    // substr: "hello" should match both "hello" and "hello world"
    let trait_def = TraitDefinition {
        id: "test/substr".to_string(),
        desc: "Substr match test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: None,
            substr: Some("hello".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
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

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // Should match both strings
    assert_eq!(finding.evidence.len(), 2);
}

#[test]
fn test_symbol_exact_vs_substr() {
    let (mut report, data) = create_test_context();

    // Add test symbols
    report.imports.push(Import {
        symbol: "read".to_string(),
        library: None,
        source: "test".to_string(),
        offset: None,
        alias: None,
    });
    report.imports.push(Import {
        symbol: "readlink".to_string(),
        library: None,
        source: "test".to_string(),
        offset: None,
        alias: None,
    });

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    // exact: "read" should match only "read", not "readlink"
    let trait_exact = TraitDefinition {
        id: "test/symbol-exact".to_string(),
        desc: "Symbol exact test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Symbol {
            exact: Some("read".to_string()),
            substr: None,
            regex: None,
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
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

    let result = trait_exact.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    assert_eq!(finding.evidence.len(), 1);
    assert_eq!(finding.evidence[0].value, "read");

    // substr: "read" should match both "read" and "readlink"
    let trait_substr = TraitDefinition {
        id: "test/symbol-substr".to_string(),
        desc: "Symbol substr test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Symbol {
            exact: None,
            substr: Some("read".to_string()),
            regex: None,
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
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

    let result = trait_substr.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    assert_eq!(finding.evidence.len(), 2);
}

#[test]
fn test_string_case_insensitive_exact() {
    let (mut report, data) = create_test_context();

    report.strings.push(StringInfo {
        value: ("HELLO".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    // Case-insensitive exact match
    let trait_def = TraitDefinition {
        id: "test/case-insensitive".to_string(),
        desc: "Case insensitive test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: Some("hello".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: true,
            is_check: None,
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

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
}

#[test]
fn test_string_word_boundary_match() {
    let (mut report, data) = create_test_context();

    report.strings.push(StringInfo {
        value: ("the cat sat".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: ("category".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    // word: "cat" should match "the cat sat" but not "category"
    let trait_def = TraitDefinition {
        id: "test/word".to_string(),
        desc: "Word boundary test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: None,
            substr: None,
            regex: None,
            word: Some("cat".to_string()),
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            not: None,
            platforms: None,
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

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // Should only match "the cat sat", not "category"
    assert_eq!(finding.evidence.len(), 1);
    assert!(finding.evidence[0].value.contains("cat"));
}

#[test]
fn test_string_regex_match() {
    let (mut report, data) = create_test_context();

    report.strings.push(StringInfo {
        value: ("192.168.1.1".to_string()).into(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: Some(crate::types::StringType::IP),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: ("10.0.0.1".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: Some(crate::types::StringType::IP),
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });
    report.strings.push(StringInfo {
        value: ("not an ip".to_string()).into(),
        offset: Some(0x3000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    // regex for IP addresses
    let trait_def = TraitDefinition {
        id: "test/regex".to_string(),
        desc: "Regex test".to_string(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: None,
            substr: None,
            regex: Some(r"\d+\.\d+\.\d+\.\d+".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            not: None,
            platforms: None,
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

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // Should match both IP addresses
    assert_eq!(finding.evidence.len(), 2);
}

#[test]
fn test_content_exact_vs_substr() {
    let data = b"hello world this is a test".to_vec();
    let (mut report, _) = create_test_context();
    report.strings.clear(); // Clear existing strings so we fall through to content check

    let ctx = EvaluationContext::new(
        &report,
        &data,
        FileType::Shell,
        &[Platform::All],
        None,
        None,
    );

    // exact: should match only if entire content equals the pattern (won't match)
    let location = super::evaluators::ContentLocationParams::default();
    let result = super::evaluators::eval_raw(
        Some(&"hello".to_string()),
        None,
        None,
        None,
        false,
        None,
        None,
        &location,
        &ctx,
        None,
    );
    // Exact match against whole content should fail (content is "hello world..." not "hello")
    assert!(!result.matched);

    // substr: should match because "hello" appears in the content
    let result = super::evaluators::eval_raw(
        None,
        Some(&"hello".to_string()),
        None,
        None,
        false,
        None,
        None,
        &location,
        &ctx,
        None,
    );
    assert!(result.matched);
}

// ============================================================================
// Tests for basename condition
// ============================================================================

fn create_test_context_with_path(path: &str) -> (AnalysisReport, Vec<u8>) {
    let target = TargetInfo {
        path: path.to_string(),
        file_type: "python".to_string(),
        size_bytes: 1024,
        sha256: "test".to_string(),
        architectures: None,
    };

    let report = AnalysisReport::new(target);
    (report, vec![])
}

#[test]
fn test_basename_exact_match() {
    let (report, data) = create_test_context_with_path("/home/user/project/__init__.py");

    let ctx = EvaluationContext::new(
        &report,
        &data,
        FileType::Python,
        &[Platform::All],
        None,
        None,
    );

    // exact: "__init__.py" should match
    let result = super::evaluators::eval_basename(
        Some(&"__init__.py".to_string()),
        None,
        None,
        false,
        None,
        &ctx,
    );
    assert!(result.matched);
    assert_eq!(result.evidence[0].value, "__init__.py");
}

#[test]
fn test_basename_exact_no_match() {
    let (report, data) = create_test_context_with_path("/home/user/project/main.py");

    let ctx = EvaluationContext::new(
        &report,
        &data,
        FileType::Python,
        &[Platform::All],
        None,
        None,
    );

    // exact: "__init__.py" should not match "main.py"
    let result = super::evaluators::eval_basename(
        Some(&"__init__.py".to_string()),
        None,
        None,
        false,
        None,
        &ctx,
    );
    assert!(!result.matched);
}

#[test]
fn test_basename_substr_match() {
    let (report, data) = create_test_context_with_path("/home/user/project/setup_tools.py");

    let ctx = EvaluationContext::new(
        &report,
        &data,
        FileType::Python,
        &[Platform::All],
        None,
        None,
    );

    // substr: "setup" should match "setup_tools.py"
    let result =
        super::evaluators::eval_basename(None, Some(&"setup".to_string()), None, false, None, &ctx);
    assert!(result.matched);
}

#[test]
fn test_basename_regex_match() {
    let (report, data) = create_test_context_with_path("/home/user/project/test_utils.py");

    let ctx = EvaluationContext::new(
        &report,
        &data,
        FileType::Python,
        &[Platform::All],
        None,
        None,
    );

    // regex: "^test_" should match files starting with "test_"
    let result = super::evaluators::eval_basename(
        None,
        None,
        Some(&"^test_".to_string()),
        false,
        None,
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_basename_case_insensitive() {
    let (report, data) = create_test_context_with_path("/home/user/project/README.md");

    let ctx = EvaluationContext::new(&report, &data, FileType::All, &[Platform::All], None, None);

    // exact: "readme.md" should match "README.md" with case_insensitive
    let result = super::evaluators::eval_basename(
        Some(&"readme.md".to_string()),
        None,
        None,
        true, // case_insensitive
        None,
        &ctx,
    );
    assert!(result.matched);
}

#[test]
fn test_basename_in_trait_definition() {
    let (report, data) = create_test_context_with_path("/home/user/project/__init__.py");

    let ctx = EvaluationContext::new(
        &report,
        &data,
        FileType::Python,
        &[Platform::All],
        None,
        None,
    );

    let trait_def = TraitDefinition {
        id: "test/init-file".to_string(),
        desc: "Python init file".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::Python],
        for_from_groups: false,
        r#if: Condition::Path {
            exact: Some("__init__.py".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            is_check: None,
            basename: true,
            dirname: false,
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

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    assert_eq!(finding.id, "test/init-file");
}

#[test]
fn test_basename_in_composite_rule() {
    let (report, data) = create_test_context_with_path("/home/user/project/setup.py");

    let ctx = EvaluationContext::new(
        &report,
        &data,
        FileType::Python,
        &[Platform::All],
        None,
        None,
    );

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/setup-file".to_string(),
        desc: "Python setup file".to_string(),
        conf: 0.9,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::Python],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Path {
            exact: None,
            substr: None,
            regex: Some("^setup\\.py$".to_string()),
            case_insensitive: false,
            is_check: None,
            basename: true,
            dirname: false,
        }]),
        any: None,
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
}

// ============================================================================
// Tests for unless directive on CompositeTrait
// ============================================================================

#[test]
fn test_composite_unless_skips_rule() {
    let (report, data) = create_test_context();

    // Add a finding that would trigger the unless condition
    let findings = vec![Finding {
        id: "file/signed/apple".to_string(),
        kind: FindingKind::Capability,
        desc: "Apple signed binary".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        match_count: 0,
        source_file: None,
    }];

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None)
        .with_additional_findings(&findings);

    // Composite rule with unless condition
    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/network-composite".to_string(),
        desc: "Network activity composite".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        }]),
        any: None,
        unless: Some(vec![Condition::Trait {
            id: "file/signed/apple".to_string(),
        }]),
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Should return None because unless condition matches
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_none(),
        "Composite rule should be skipped when unless condition matches"
    );
}

#[test]
fn test_composite_unless_allows_rule() {
    let (report, data) = create_test_context();

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/network-composite".to_string(),
        desc: "Network activity composite".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        }]),
        any: None,
        unless: Some(vec![Condition::Trait {
            id: "file/signed/apple".to_string(),
        }]),
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Should return Some because unless condition doesn't match
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_some(),
        "Composite rule should match when unless condition doesn't match"
    );
}

#[test]
fn test_composite_unless_with_basename() {
    // Test the libX11.so case that was the original bug report
    let (report, data) = create_test_context_with_path("/usr/lib/libX11.so.6");

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/x11-keylog".to_string(),
        desc: "X11 keylogger pattern".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::Elf],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        any: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("XQueryKeymap".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        }]),
        all: None,
        // Skip if this looks like libX11 itself
        unless: Some(vec![Condition::Path {
            exact: None,
            substr: None,
            regex: Some(r"^libX11(\\.so|\\.dylib).*".to_string()),
            case_insensitive: false,
            is_check: None,
            basename: true,
            dirname: false,
        }]),
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Should return None because the basename matches libX11.so
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_none(),
        "Composite rule should be skipped for libX11.so (unless basename condition should match)"
    );
}

#[test]
fn test_composite_unless_multiple_conditions_any_matches() {
    let (mut report, data) = create_test_context();

    // Add a string that will match one of the unless conditions
    report.strings.push(StringInfo {
        value: ("X.Org Foundation".to_string()).into(),
        offset: Some(0x4000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/multi-unless".to_string(),
        desc: "Rule with multiple unless conditions".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        }]),
        any: None,
        // Multiple unless conditions - any match should skip the rule
        unless: Some(vec![
            Condition::Path {
                exact: Some("system-library.so".to_string()),
                substr: None,
                regex: None,
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            },
            Condition::Text {
                exact: None,
                substr: Some("X.Org Foundation".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                not: None,
                platforms: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
            },
        ]),
        not: None,
        downgrade: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Should return None because the second unless condition (string regex) matches
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_none(),
        "Composite rule should be skipped when ANY unless condition matches"
    );
}

// ============================================================================
// Tests for `needs` constraint with both `all` and `any` conditions
// ============================================================================

#[test]
fn test_needs_with_any_only_respects_threshold() {
    let (report, data) = create_test_context();

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    // Rule with needs: 3, but only 2 conditions can match (socket, connect)
    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/needs-any-only".to_string(),
        desc: "Needs constraint with any only".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![
            Condition::Symbol {
                exact: Some("socket".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("connect".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("nonexistent1".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("nonexistent2".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
        ]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(3), // Require 3 matches, but only 2 exist
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Should NOT match because only 2 of 3 required conditions match
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_none(),
        "Rule with needs:3 should NOT match when only 2 conditions are satisfied"
    );
}

#[test]
fn test_needs_with_any_only_matches_when_threshold_met() {
    let (report, data) = create_test_context();

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    // Rule with needs: 2, and 2 conditions can match (socket, connect)
    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/needs-any-met".to_string(),
        desc: "Needs constraint met".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![
            Condition::Symbol {
                exact: Some("socket".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("connect".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("nonexistent".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
        ]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(2), // Require 2 matches, and 2 exist
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Should match because exactly 2 conditions are satisfied
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_some(),
        "Rule with needs:2 should match when 2 conditions are satisfied"
    );
}

#[test]
fn test_needs_with_directory_ref_counts_child_matches() {
    let (report, data) = create_test_context();
    let findings = vec![
        finding_at_offset("micro-behaviors/data/text/config/xcode::scheme-file", 10),
        finding_at_offset("micro-behaviors/data/text/config/xcode::scheme-renamer", 20),
    ];
    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None)
        .with_additional_findings(&findings);

    let mut rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/needs-directory-ref".to_string(),
        desc: "Needs counts directory children".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![Condition::Trait {
            id: "micro-behaviors/data/text/config/xcode".to_string(),
        }]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(2),
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    assert!(
        rule.evaluate(&ctx).is_some(),
        "Directory refs should contribute distinct child trait matches to needs"
    );

    rule.needs = Some(3);
    assert!(
        rule.evaluate(&ctx).is_none(),
        "Directory refs should not satisfy needs above the child match count"
    );
}

#[test]
fn test_required_trait_prefilter_for_any_needs_is_not_overconstrained() {
    let mut rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/prefilter-any-needs".to_string(),
        desc: "Prefilter should not require every any item".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![
            Condition::Trait {
                id: "test::a".to_string(),
            },
            Condition::Trait {
                id: "test::b".to_string(),
            },
            Condition::Trait {
                id: "test::c".to_string(),
            },
            Condition::Trait {
                id: "test::d".to_string(),
            },
        ]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(3),
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let trait_id_map = std::collections::HashMap::from([
        ("test::a".to_string(), 0usize),
        ("test::b".to_string(), 1usize),
        ("test::c".to_string(), 2usize),
        ("test::d".to_string(), 3usize),
    ]);

    rule.populate_required_traits(&trait_id_map);

    assert!(
        rule.required_trait_indices.is_empty(),
        "any+needs prefilter should not require all optional refs"
    );
}

#[test]
fn test_required_trait_prefilter_keeps_all_and_fully_required_any_refs() {
    let mut rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/prefilter-all-and-any".to_string(),
        desc: "Prefilter should keep mandatory refs".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![
            Condition::Trait {
                id: "test::a".to_string(),
            },
            Condition::Trait {
                id: "test::b".to_string(),
            },
        ]),
        any: Some(vec![
            Condition::Trait {
                id: "test::c".to_string(),
            },
            Condition::Trait {
                id: "test::d".to_string(),
            },
        ]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(2),
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let trait_id_map = std::collections::HashMap::from([
        ("test::a".to_string(), 0usize),
        ("test::b".to_string(), 1usize),
        ("test::c".to_string(), 2usize),
        ("test::d".to_string(), 3usize),
    ]);

    rule.populate_required_traits(&trait_id_map);

    assert_eq!(rule.required_trait_indices, vec![0, 1, 2, 3]);
}

#[test]
fn test_needs_with_all_and_any_respects_threshold() {
    // This is the bug that was fixed: when both all and any are present,
    // the needs constraint on any was being ignored
    let (report, data) = create_test_context();

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    // Rule with:
    // - all: socket (matches)
    // - any: connect, nonexistent1, nonexistent2, nonexistent3 (only 1 matches)
    // - needs: 3 (requires 3 from any)
    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/needs-all-any-fail".to_string(),
        desc: "Needs with all and any - should NOT match".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: Some("socket".to_string()),
            substr: None,
            regex: None,
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        }]),
        any: Some(vec![
            Condition::Symbol {
                exact: Some("connect".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("nonexistent1".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("nonexistent2".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("nonexistent3".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
        ]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(3), // Require 3 from any, but only 1 matches
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // BUG FIX: This should NOT match because:
    // - all conditions pass (socket matches)
    // - BUT any conditions fail: only 1 of 3 required matches
    // Before the fix, this would incorrectly match because needs was ignored
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_none(),
        "Rule with all + any + needs:3 should NOT match when only 1 any-condition is satisfied"
    );
}

#[test]
fn test_needs_with_all_and_any_matches_when_threshold_met() {
    let (mut report, data) = create_test_context();

    // Add more imports so we can match the threshold
    report.imports.push(Import {
        symbol: "send".to_string(),
        library: None,
        source: "test".to_string(),
        offset: None,
        alias: None,
    });
    report.imports.push(Import {
        symbol: "recv".to_string(),
        library: None,
        source: "test".to_string(),
        offset: None,
        alias: None,
    });

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    // Rule with:
    // - all: socket (matches)
    // - any: connect, send, recv, nonexistent (3 match)
    // - needs: 3 (requires 3 from any)
    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/needs-all-any-pass".to_string(),
        desc: "Needs with all and any - should match".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: Some("socket".to_string()),
            substr: None,
            regex: None,
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        }]),
        any: Some(vec![
            Condition::Symbol {
                exact: Some("connect".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("send".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("recv".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("nonexistent".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
        ]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(3), // Require 3 from any, and 3 match
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Should match because:
    // - all conditions pass (socket matches)
    // - any conditions pass: 3 of 3 required match (connect, send, recv)
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_some(),
        "Rule with all + any + needs:3 should match when 3 any-conditions are satisfied"
    );
}

#[test]
fn test_needs_with_all_and_any_all_fails() {
    let (report, data) = create_test_context();

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    // Rule where all fails but any would pass
    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/needs-all-fails".to_string(),
        desc: "All fails, any passes".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: Some("nonexistent_required".to_string()),
            substr: None,
            regex: None,
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        }]),
        any: Some(vec![
            Condition::Symbol {
                exact: Some("socket".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("connect".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
        ]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(1),
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Should NOT match because all fails (even though any would pass)
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_none(),
        "Rule should NOT match when all condition fails, even if any would pass"
    );
}

#[test]
fn test_all_and_any_without_needs_requires_one_any() {
    // When needs is NOT specified, any should require just 1 match (default behavior)
    let (report, data) = create_test_context();

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/all-any-no-needs".to_string(),
        desc: "All and any without needs".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: Some("socket".to_string()),
            substr: None,
            regex: None,
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        }]),
        any: Some(vec![
            Condition::Symbol {
                exact: Some("connect".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("nonexistent1".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
            Condition::Symbol {
                exact: Some("nonexistent2".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
            },
        ]),
        unless: None,
        not: None,
        downgrade: None,
        needs: None, // No needs constraint - default is any 1
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    // Should match because:
    // - all passes (socket)
    // - any passes (connect matches, which is sufficient without needs)
    let result = rule.evaluate(&ctx);
    assert!(
        result.is_some(),
        "Rule with all + any (no needs) should match when 1 any-condition is satisfied"
    );
}

// ============================================================================
// Proximity constraint tests (near_lines, near_bytes)
// ============================================================================

/// Helper: build a Finding with evidence at a specific line:column location (AST-style).
/// Each finding gets a unique value (the id) to prevent deduplication during evidence merging.
fn finding_at_line(id: &str, line: usize, col: usize) -> Finding {
    Finding {
        id: id.to_string(),
        kind: FindingKind::Capability,
        desc: format!("Test finding at line {}", line),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![crate::types::Evidence {
            method: "ast".to_string(),
            source: "tree-sitter".to_string(),
            value: id.to_string(), // unique per finding to avoid dedup
            location: Some(format!("{}:{}", line, col)),
            ..Default::default()
        }],
        match_count: 0,
        source_file: None,
    }
}

/// Helper: build a Finding with evidence at a specific byte offset.
/// Each finding gets a unique value (the id) to prevent deduplication during evidence merging.
fn finding_at_offset(id: &str, offset: u64) -> Finding {
    Finding {
        id: id.to_string(),
        kind: FindingKind::Capability,
        desc: format!("Test finding at offset {}", offset),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![crate::types::Evidence {
            method: "string".to_string(),
            source: "test".to_string(),
            value: id.to_string(), // unique per finding to avoid dedup
            location: None,
            offsets: vec![offset],
            ..Default::default()
        }],
        match_count: 0,
        source_file: None,
    }
}

/// Helper: build a CompositeTrait for proximity tests with `all` conditions referencing trait IDs.
fn proximity_rule(
    trait_ids: &[&str],
    near_lines: Option<usize>,
    near_bytes: Option<usize>,
) -> CompositeTrait {
    let all_conds: Vec<Condition> = trait_ids
        .iter()
        .map(|id| Condition::Trait { id: id.to_string() })
        .collect();
    CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/proximity".to_string(),
        desc: "Proximity test".to_string(),
        conf: 0.9,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(all_conds),
        any: None,
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines,
        near_bytes,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

/// Helper: create an EvaluationContext with given findings and binary data.
fn proximity_ctx<'a>(
    report: &'a AnalysisReport,
    data: &'a [u8],
    findings: &'a [Finding],
) -> EvaluationContext<'a> {
    EvaluationContext::test_only_new(report, data, FileType::Python)
        .with_additional_findings(findings)
}

fn empty_report() -> AnalysisReport {
    AnalysisReport::new(TargetInfo {
        path: "/test.py".to_string(),
        file_type: "python".to_string(),
        size_bytes: 100,
        sha256: "test".to_string(),
        architectures: None,
    })
}

#[test]
fn test_near_lines_same_line_passes() {
    let report = empty_report();
    let data = b"line1\nline2\nline3\n";
    let findings = vec![
        finding_at_line("trait-a", 2, 1),
        finding_at_line("trait-b", 2, 10),
    ];
    let ctx = proximity_ctx(&report, data, &findings);
    let rule = proximity_rule(&["trait-a", "trait-b"], Some(0), None);
    assert!(
        rule.evaluate(&ctx).is_some(),
        "near_lines: 0 should pass when evidence is on the same line"
    );
}

#[test]
fn test_near_lines_same_line_fails() {
    let report = empty_report();
    let data = b"line1\nline2\nline3\n";
    let findings = vec![
        finding_at_line("trait-a", 1, 1),
        finding_at_line("trait-b", 2, 1),
    ];
    let ctx = proximity_ctx(&report, data, &findings);
    let rule = proximity_rule(&["trait-a", "trait-b"], Some(0), None);
    assert!(
        rule.evaluate(&ctx).is_none(),
        "near_lines: 0 should fail when evidence is on different lines"
    );
}

#[test]
fn test_near_lines_within_window() {
    let report = empty_report();
    let data = b"line1\nline2\nline3\nline4\nline5\n";
    let findings = vec![
        finding_at_line("trait-a", 2, 1),
        finding_at_line("trait-b", 4, 1),
    ];
    let ctx = proximity_ctx(&report, data, &findings);
    let rule = proximity_rule(&["trait-a", "trait-b"], Some(5), None);
    assert!(
        rule.evaluate(&ctx).is_some(),
        "near_lines: 5 should pass when evidence is 2 lines apart"
    );
}

#[test]
fn test_near_lines_outside_window() {
    let report = empty_report();
    let data = b"line1\nline2\nline3\nline4\nline5\n";
    let findings = vec![
        finding_at_line("trait-a", 1, 1),
        finding_at_line("trait-b", 5, 1),
    ];
    let ctx = proximity_ctx(&report, data, &findings);
    let rule = proximity_rule(&["trait-a", "trait-b"], Some(2), None);
    assert!(
        rule.evaluate(&ctx).is_none(),
        "near_lines: 2 should fail when evidence is 4 lines apart"
    );
}

#[test]
fn test_near_lines_boundary_exact() {
    let report = empty_report();
    let data = b"line1\nline2\nline3\nline4\nline5\n";
    // Lines 2 and 5 are exactly 3 apart
    let findings = vec![
        finding_at_line("trait-a", 2, 1),
        finding_at_line("trait-b", 5, 1),
    ];
    let ctx = proximity_ctx(&report, data, &findings);

    let pass_rule = proximity_rule(&["trait-a", "trait-b"], Some(3), None);
    assert!(
        pass_rule.evaluate(&ctx).is_some(),
        "near_lines: 3 should pass when evidence is exactly 3 lines apart"
    );

    let fail_rule = proximity_rule(&["trait-a", "trait-b"], Some(2), None);
    assert!(
        fail_rule.evaluate(&ctx).is_none(),
        "near_lines: 2 should fail when evidence is exactly 3 lines apart"
    );
}

#[test]
fn test_near_lines_with_byte_offsets() {
    // Simulate a text file where evidence has byte offsets (no line:column location).
    // File: "aaa\nbbb\nccc\nddd\neee\n" — 5 lines, each 4 bytes (3 chars + newline)
    let report = empty_report();
    let data = b"aaa\nbbb\nccc\nddd\neee\n";
    // Byte offset 0 = line 1, offset 4 = line 2, offset 8 = line 3, offset 12 = line 4
    let findings = vec![
        finding_at_offset("trait-a", 4),  // line 2
        finding_at_offset("trait-b", 12), // line 4
    ];
    let ctx = proximity_ctx(&report, data, &findings);

    let pass = proximity_rule(&["trait-a", "trait-b"], Some(5), None);
    assert!(
        pass.evaluate(&ctx).is_some(),
        "near_lines: 5 should pass — byte offsets map to lines 2 and 4 (2 apart)"
    );

    let fail = proximity_rule(&["trait-a", "trait-b"], Some(1), None);
    assert!(
        fail.evaluate(&ctx).is_none(),
        "near_lines: 1 should fail — byte offsets map to lines 2 and 4 (2 apart)"
    );
}

#[test]
fn test_near_lines_mixed_evidence_formats() {
    // Mix of AST evidence (line:column) and string evidence (byte offset)
    let report = empty_report();
    let data = b"aaa\nbbb\nccc\nddd\neee\n";
    let findings = vec![
        finding_at_line("trait-a", 3, 1), // AST evidence at line 3
        finding_at_offset("trait-b", 12), // Byte offset 12 → line 4
    ];
    let ctx = proximity_ctx(&report, data, &findings);

    let pass = proximity_rule(&["trait-a", "trait-b"], Some(5), None);
    assert!(
        pass.evaluate(&ctx).is_some(),
        "Should pass with mixed evidence formats (line 3 + line 4, 1 apart)"
    );

    let fail = proximity_rule(&["trait-a", "trait-b"], Some(0), None);
    assert!(
        fail.evaluate(&ctx).is_none(),
        "Same-line constraint should fail for lines 3 and 4"
    );
}

#[test]
fn test_near_lines_all_requires_multiple() {
    // With 3 `all` conditions, min_required = 3. Need 3 items in the window.
    let report = empty_report();
    let data = b"line1\nline2\nline3\nline4\nline5\n";
    let findings = vec![
        finding_at_line("trait-a", 1, 1),
        finding_at_line("trait-b", 2, 1),
        finding_at_line("trait-c", 3, 1),
    ];
    let ctx = proximity_ctx(&report, data, &findings);

    let rule = proximity_rule(&["trait-a", "trait-b", "trait-c"], Some(5), None);
    assert!(
        rule.evaluate(&ctx).is_some(),
        "3 all conditions within 5 lines should pass"
    );
}

#[test]
fn test_near_lines_all_three_too_spread() {
    // 3 conditions, one is too far from the others
    let report = empty_report();
    let data: Vec<u8> = "x\n".repeat(200).into_bytes();
    let findings = vec![
        finding_at_line("trait-a", 1, 1),
        finding_at_line("trait-b", 3, 1),
        finding_at_line("trait-c", 100, 1),
    ];
    let ctx = proximity_ctx(&report, &data, &findings);

    let rule = proximity_rule(&["trait-a", "trait-b", "trait-c"], Some(5), None);
    assert!(
        rule.evaluate(&ctx).is_none(),
        "3 conditions with one 100 lines away should fail with near_lines: 5"
    );
}

#[test]
fn test_near_lines_any_with_needs() {
    // `any` with needs: 3 and near_lines: 10. Need 3 items in the window.
    let report = empty_report();
    let data = b"line1\nline2\nline3\nline4\nline5\n";
    let findings = vec![
        finding_at_line("trait-a", 1, 1),
        finding_at_line("trait-b", 3, 1),
        finding_at_line("trait-c", 5, 1),
        finding_at_line("trait-d", 2, 1),
    ];
    let ctx = proximity_ctx(&report, data, &findings);

    let mut rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/any-needs".to_string(),
        desc: "Any with needs".to_string(),
        conf: 0.9,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![
            Condition::Trait {
                id: "trait-a".to_string(),
            },
            Condition::Trait {
                id: "trait-b".to_string(),
            },
            Condition::Trait {
                id: "trait-c".to_string(),
            },
            Condition::Trait {
                id: "trait-d".to_string(),
            },
        ]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(3),
        near_lines: Some(10),
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    assert!(
        rule.evaluate(&ctx).is_some(),
        "any with needs: 3, near_lines: 10 should pass (4 items within 5 lines)"
    );

    // Tighten the window — all 4 are within 4 lines so needs:3 can still fit
    rule.near_lines = Some(2);
    assert!(
        rule.evaluate(&ctx).is_some(),
        "near_lines: 2 should pass — lines 1,2,3 are within 2 lines of each other"
    );
}

#[test]
fn test_near_lines_any_with_needs_too_spread() {
    let report = empty_report();
    let data: Vec<u8> = "x\n".repeat(200).into_bytes();
    let findings = vec![
        finding_at_line("trait-a", 1, 1),
        finding_at_line("trait-b", 50, 1),
        finding_at_line("trait-c", 100, 1),
        finding_at_line("trait-d", 150, 1),
    ];
    let ctx = proximity_ctx(&report, &data, &findings);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/spread".to_string(),
        desc: "Spread test".to_string(),
        conf: 0.9,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![
            Condition::Trait {
                id: "trait-a".to_string(),
            },
            Condition::Trait {
                id: "trait-b".to_string(),
            },
            Condition::Trait {
                id: "trait-c".to_string(),
            },
            Condition::Trait {
                id: "trait-d".to_string(),
            },
        ]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(3),
        near_lines: Some(10),
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    assert!(
        rule.evaluate(&ctx).is_none(),
        "4 traits each 50 lines apart should fail near_lines: 10 with needs: 3"
    );
}

#[test]
fn test_near_lines_all_plus_any() {
    // all(2) + any(needs:2) = min_required 4
    let report = empty_report();
    let data = b"line1\nline2\nline3\nline4\nline5\nline6\n";
    let findings = vec![
        finding_at_line("all-a", 2, 1),
        finding_at_line("all-b", 3, 1),
        finding_at_line("any-a", 4, 1),
        finding_at_line("any-b", 5, 1),
        finding_at_line("any-c", 6, 1),
    ];
    let ctx = proximity_ctx(&report, data, &findings);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/all-any".to_string(),
        desc: "All + any".to_string(),
        conf: 0.9,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![
            Condition::Trait {
                id: "all-a".to_string(),
            },
            Condition::Trait {
                id: "all-b".to_string(),
            },
        ]),
        any: Some(vec![
            Condition::Trait {
                id: "any-a".to_string(),
            },
            Condition::Trait {
                id: "any-b".to_string(),
            },
            Condition::Trait {
                id: "any-c".to_string(),
            },
        ]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(2),
        near_lines: Some(10),
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    assert!(
        rule.evaluate(&ctx).is_some(),
        "all(2) + any(needs:2) with near_lines:10 should pass (lines 2-6)"
    );
}

#[test]
fn test_near_bytes_with_offsets() {
    let report = empty_report();
    let data = b"some file content here";
    let findings = vec![
        finding_at_offset("trait-a", 100),
        finding_at_offset("trait-b", 150),
    ];
    let ctx = proximity_ctx(&report, data, &findings);

    let pass = proximity_rule(&["trait-a", "trait-b"], None, Some(100));
    assert!(
        pass.evaluate(&ctx).is_some(),
        "near_bytes: 100 should pass (offsets 100 and 150 are 50 apart)"
    );

    let fail = proximity_rule(&["trait-a", "trait-b"], None, Some(30));
    assert!(
        fail.evaluate(&ctx).is_none(),
        "near_bytes: 30 should fail (offsets 100 and 150 are 50 apart)"
    );
}

#[test]
fn test_near_bytes_boundary_exact() {
    let report = empty_report();
    let data = b"x";
    let findings = vec![
        finding_at_offset("trait-a", 100),
        finding_at_offset("trait-b", 200),
    ];
    let ctx = proximity_ctx(&report, data, &findings);

    let pass = proximity_rule(&["trait-a", "trait-b"], None, Some(100));
    assert!(
        pass.evaluate(&ctx).is_some(),
        "near_bytes: 100 should pass (exactly 100 apart)"
    );

    let fail = proximity_rule(&["trait-a", "trait-b"], None, Some(99));
    assert!(
        fail.evaluate(&ctx).is_none(),
        "near_bytes: 99 should fail (100 apart)"
    );
}

#[test]
fn test_near_lines_no_location_evidence_fails() {
    // Evidence with no location or offsets cannot participate in proximity
    let report = empty_report();
    let data = b"some content\n";
    let findings = vec![
        Finding {
            id: "trait-a".to_string(),
            kind: FindingKind::Capability,
            desc: "No location".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![crate::types::Evidence {
                method: "symbol".to_string(),
                source: "test".to_string(),
                value: "trait-a".to_string(),
                location: Some("import".to_string()),
                ..Default::default()
            }],
            match_count: 0,
            source_file: None,
        },
        Finding {
            id: "trait-b".to_string(),
            kind: FindingKind::Capability,
            desc: "No location".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![crate::types::Evidence {
                method: "symbol".to_string(),
                source: "test".to_string(),
                value: "trait-b".to_string(),
                location: Some("import".to_string()),
                ..Default::default()
            }],
            match_count: 0,
            source_file: None,
        },
    ];
    let ctx = proximity_ctx(&report, data, &findings);

    let rule = proximity_rule(&["trait-a", "trait-b"], Some(5), None);
    assert!(
        rule.evaluate(&ctx).is_none(),
        "Evidence with non-numeric locations should not satisfy proximity constraints"
    );
}

#[test]
fn test_near_lines_hex_offset_location() {
    // Evidence with hex offset location (e.g., "0x10") should be converted via line index
    let report = empty_report();
    // 5 lines: "aaaa\nbbbb\ncccc\ndddd\neeee\n" — each line 5 bytes
    let data = b"aaaa\nbbbb\ncccc\ndddd\neeee\n";
    let findings = vec![
        // Hex offset 0x05 = byte 5 = start of line 2
        Finding {
            id: "trait-a".to_string(),
            kind: FindingKind::Capability,
            desc: "Hex loc".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![crate::types::Evidence {
                method: "string".to_string(),
                source: "test".to_string(),
                value: "bbbb".to_string(),
                location: Some("0x05".to_string()),
                ..Default::default()
            }],
            match_count: 0,
            source_file: None,
        },
        // Hex offset 0x0f = byte 15 = start of line 4
        Finding {
            id: "trait-b".to_string(),
            kind: FindingKind::Capability,
            desc: "Hex loc".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![crate::types::Evidence {
                method: "string".to_string(),
                source: "test".to_string(),
                value: "dddd".to_string(),
                location: Some("0x0f".to_string()),
                ..Default::default()
            }],
            match_count: 0,
            source_file: None,
        },
    ];
    let ctx = proximity_ctx(&report, data, &findings);

    let pass = proximity_rule(&["trait-a", "trait-b"], Some(5), None);
    assert!(
        pass.evaluate(&ctx).is_some(),
        "Hex offset locations should map to lines — 0x05 (line 2) and 0x0f (line 4) are 2 apart"
    );

    let fail = proximity_rule(&["trait-a", "trait-b"], Some(1), None);
    assert!(
        fail.evaluate(&ctx).is_none(),
        "near_lines: 1 should fail when hex offsets map to lines 2 and 4"
    );
}

// ============================================================================
// Unit tests for proximity helper functions
// ============================================================================

#[test]
fn test_build_line_index() {
    let data = b"hello\nworld\nfoo\n";
    let idx = super::traits::build_line_index(data);
    assert_eq!(idx, vec![0, 6, 12, 16]);
}

#[test]
fn test_build_line_index_empty() {
    let idx = super::traits::build_line_index(b"");
    assert_eq!(idx, vec![0]);
}

#[test]
fn test_build_line_index_no_newlines() {
    let idx = super::traits::build_line_index(b"no newlines");
    assert_eq!(idx, vec![0]);
}

#[test]
fn test_byte_offset_to_line() {
    let data = b"aaa\nbbb\nccc\n";
    let idx = super::traits::build_line_index(data);
    // Line starts: [0, 4, 8, 12]
    assert_eq!(super::traits::byte_offset_to_line(&idx, 0), 1); // start of line 1
    assert_eq!(super::traits::byte_offset_to_line(&idx, 2), 1); // within line 1
    assert_eq!(super::traits::byte_offset_to_line(&idx, 4), 2); // start of line 2
    assert_eq!(super::traits::byte_offset_to_line(&idx, 6), 2); // within line 2
    assert_eq!(super::traits::byte_offset_to_line(&idx, 8), 3); // start of line 3
    assert_eq!(super::traits::byte_offset_to_line(&idx, 11), 3); // end of line 3
}

#[test]
fn test_evidence_to_line_line_column() {
    let line_starts = vec![0]; // doesn't matter for line:column
    let e = crate::types::Evidence {
        method: "ast".to_string(),
        source: "tree-sitter".to_string(),
        value: "test".to_string(),
        location: Some("42:5".to_string()),
        ..Default::default()
    };
    assert_eq!(super::traits::evidence_to_line(&e, &line_starts), Some(42));
}

#[test]
fn test_evidence_to_line_byte_offset() {
    // "aaa\nbbb\n" — line starts at [0, 4]
    let line_starts = vec![0, 4];
    let e = crate::types::Evidence {
        method: "string".to_string(),
        source: "test".to_string(),
        value: "test".to_string(),
        location: None,
        offsets: vec![5], // within line 2
        ..Default::default()
    };
    assert_eq!(super::traits::evidence_to_line(&e, &line_starts), Some(2));
}

#[test]
fn test_evidence_to_line_hex_location() {
    // "aaa\nbbb\n" — line starts at [0, 4]
    let line_starts = vec![0, 4];
    let e = crate::types::Evidence {
        method: "string".to_string(),
        source: "test".to_string(),
        value: "test".to_string(),
        location: Some("0x05".to_string()),
        ..Default::default()
    };
    assert_eq!(super::traits::evidence_to_line(&e, &line_starts), Some(2));
}

#[test]
fn test_evidence_to_line_unparseable() {
    let line_starts = vec![0];
    let e = crate::types::Evidence {
        method: "symbol".to_string(),
        source: "test".to_string(),
        value: "test".to_string(),
        location: Some("import".to_string()),
        ..Default::default()
    };
    assert_eq!(super::traits::evidence_to_line(&e, &line_starts), None);
}

#[test]
fn test_evidence_to_byte_offset_from_offsets() {
    let e = crate::types::Evidence {
        method: "string".to_string(),
        source: "test".to_string(),
        value: "test".to_string(),
        location: None,
        offsets: vec![42, 100],
        ..Default::default()
    };
    assert_eq!(super::traits::evidence_to_byte_offset(&e), Some(42));
}

#[test]
fn test_evidence_to_byte_offset_from_hex_location() {
    let e = crate::types::Evidence {
        method: "string".to_string(),
        source: "test".to_string(),
        value: "test".to_string(),
        location: Some("0x1000".to_string()),
        ..Default::default()
    };
    assert_eq!(super::traits::evidence_to_byte_offset(&e), Some(0x1000));
}

#[test]
fn test_evidence_to_byte_offset_none() {
    let e = crate::types::Evidence {
        method: "symbol".to_string(),
        source: "test".to_string(),
        value: "test".to_string(),
        location: Some("import".to_string()),
        ..Default::default()
    };
    assert_eq!(super::traits::evidence_to_byte_offset(&e), None);
}

// =============================================================================
// B2+B3: Downgrade combinatorial all/any/none + needs threshold
// =============================================================================

#[test]
fn test_downgrade_combined_all_and_none_blocked_by_none() {
    let (mut report, data) = create_test_context();

    // Add strings for all: condition
    report.strings.push(StringInfo {
        value: ("suspicious_call".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    // Add finding for none: condition — this should BLOCK the downgrade
    let findings = vec![Finding {
        id: "file/type/binary".to_string(),
        kind: FindingKind::Capability,
        desc: "Binary file".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        match_count: 0,
        source_file: None,
    }];

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None)
        .with_additional_findings(&findings);

    let trait_def = TraitDefinition {
        id: "test/combined-downgrade".to_string(),
        desc: "Test combined all+none downgrade".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: Some("suspicious_call".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
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
        downgrade: Some(DowngradeConditions {
            // all: passes (string matches)
            all: Some(vec![Condition::Text {
                exact: Some("/bin/sh".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
            }]),
            any: None,
            // none: should block downgrade because "file/type/binary" IS present
            none: Some(vec![Condition::Trait {
                id: "file/type/binary".to_string(),
            }]),
            needs: None,
        }),
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // none: blocked the downgrade, so crit stays at Suspicious
    assert_eq!(finding.crit, Criticality::Suspicious);
}

#[test]
fn test_downgrade_combined_all_and_none_pass() {
    let (mut report, data) = create_test_context();

    report.strings.push(StringInfo {
        value: ("suspicious_call".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    });

    // No findings that would match the none: condition
    let findings = vec![];

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None)
        .with_additional_findings(&findings);

    let trait_def = TraitDefinition {
        id: "test/combined-downgrade-pass".to_string(),
        desc: "Test combined all+none downgrade passes".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: Some("suspicious_call".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
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
        downgrade: Some(DowngradeConditions {
            all: Some(vec![Condition::Text {
                exact: Some("/bin/sh".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
            }]),
            any: None,
            // none: passes because "nonexistent/trait" is NOT present
            none: Some(vec![Condition::Trait {
                id: "nonexistent/trait".to_string(),
            }]),
            needs: None,
        }),
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // Both all: and none: pass → downgrade fires: Suspicious → Notable
    assert_eq!(finding.crit, Criticality::Notable);
}

#[test]
fn test_downgrade_needs_threshold_not_met() {
    let (report, data) = create_test_context();

    // Only one finding present (socket)
    let findings = vec![Finding {
        id: "test/socket".to_string(),
        kind: FindingKind::Capability,
        desc: "Socket".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        match_count: 0,
        source_file: None,
    }];

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None)
        .with_additional_findings(&findings);

    let trait_def = TraitDefinition {
        id: "test/needs-threshold".to_string(),
        desc: "Test needs threshold".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: Some("/bin/sh".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
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
        downgrade: Some(DowngradeConditions {
            all: None,
            any: Some(vec![
                Condition::Trait {
                    id: "test/socket".to_string(),
                },
                Condition::Trait {
                    id: "test/nonexistent".to_string(),
                },
                Condition::Trait {
                    id: "test/also-nonexistent".to_string(),
                },
            ]),
            none: None,
            needs: Some(2), // Requires 2 matches, only 1 present
        }),
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // needs: 2 but only 1 matched → no downgrade
    assert_eq!(finding.crit, Criticality::Suspicious);
}

#[test]
fn test_downgrade_needs_threshold_met() {
    let (report, data) = create_test_context();

    // Two findings present
    let findings = vec![
        Finding {
            id: "test/socket".to_string(),
            kind: FindingKind::Capability,
            desc: "Socket".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![],
            match_count: 0,
            source_file: None,
        },
        Finding {
            id: "test/connect".to_string(),
            kind: FindingKind::Capability,
            desc: "Connect".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![],
            match_count: 0,
            source_file: None,
        },
    ];

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None)
        .with_additional_findings(&findings);

    let trait_def = TraitDefinition {
        id: "test/needs-threshold-met".to_string(),
        desc: "Test needs threshold met".to_string(),
        conf: 1.0,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        r#if: Condition::Text {
            exact: Some("/bin/sh".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
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
        downgrade: Some(DowngradeConditions {
            all: None,
            any: Some(vec![
                Condition::Trait {
                    id: "test/socket".to_string(),
                },
                Condition::Trait {
                    id: "test/connect".to_string(),
                },
                Condition::Trait {
                    id: "test/nonexistent".to_string(),
                },
            ]),
            none: None,
            needs: Some(2), // Requires 2 matches, 2 present
        }),
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // needs: 2 and 2 matched → downgrade fires: Suspicious → Notable
    assert_eq!(finding.crit, Criticality::Notable);
}

// =============================================================================
// T7: CompositeTrait downgrade tests
// =============================================================================

#[test]
fn test_composite_downgrade_all_match() {
    let (mut report, data) = create_test_context();
    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "libc".to_string(),
        offset: None,
        alias: None,
    });

    // Provide findings that satisfy both the rule's `all` and the downgrade's `all`
    let findings = vec![
        Finding {
            id: "file/type/shell-script".to_string(),
            kind: FindingKind::Capability,
            desc: "Shell script".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![],
            match_count: 0,
            source_file: None,
        },
        Finding {
            id: "file/path/test-fixtures".to_string(),
            kind: FindingKind::Capability,
            desc: "Test fixture".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![],
            match_count: 0,
            source_file: None,
        },
    ];

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None)
        .with_additional_findings(&findings);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/composite-downgrade-all".to_string(),
        desc: "Test downgrade with all".to_string(),
        conf: 0.9,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        }]),
        any: None,
        unless: None,
        not: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        downgrade: Some(DowngradeConditions {
            all: Some(vec![
                Condition::Trait {
                    id: "file/type/shell-script".to_string(),
                },
                Condition::Trait {
                    id: "file/path/test-fixtures".to_string(),
                },
            ]),
            any: None,
            none: None,
            needs: None,
        }),
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // Both downgrade.all conditions match → downgrade fires: Suspicious → Notable
    assert_eq!(finding.crit, Criticality::Notable);
}

#[test]
fn test_composite_downgrade_none_blocks() {
    let (mut report, data) = create_test_context();
    report.imports.push(Import {
        symbol: "socket".to_string(),
        library: None,
        source: "libc".to_string(),
        offset: None,
        alias: None,
    });

    // Provide a finding that matches the downgrade.none condition — should block downgrade
    let findings = vec![Finding {
        id: "file/signed/apple".to_string(),
        kind: FindingKind::Capability,
        desc: "Apple-signed binary".to_string(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![],
        match_count: 0,
        source_file: None,
    }];

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None)
        .with_additional_findings(&findings);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/composite-downgrade-none".to_string(),
        desc: "Test downgrade blocked by none".to_string(),
        conf: 0.9,
        crit: Criticality::Hostile,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("socket".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        }]),
        any: None,
        unless: None,
        not: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        downgrade: Some(DowngradeConditions {
            all: None,
            any: Some(vec![Condition::Trait {
                id: "file/type/shell-script".to_string(), // NOT in findings
            }]),
            none: Some(vec![Condition::Trait {
                id: "file/signed/apple".to_string(), // IS in findings → blocks downgrade
            }]),
            needs: None,
        }),
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = rule.evaluate(&ctx);
    assert!(result.is_some());
    let finding = result.unwrap();
    // downgrade.none includes "file/signed/apple" which IS present → downgrade blocked
    // Original criticality should be preserved
    assert_eq!(finding.crit, Criticality::Hostile);
}

// ============================================================================
// Cross-condition proximity tests (A4)
//
// Verify that proximity constraints require evidence from DISTINCT conditions
// to co-occur within the window, not just N items from any single condition.
// ============================================================================

/// Helper: build a Finding with multiple evidence items at different line locations.
fn finding_at_lines(id: &str, lines: &[(usize, usize)]) -> Finding {
    Finding {
        id: id.to_string(),
        kind: FindingKind::Capability,
        desc: format!("Multi-evidence finding {}", id),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: lines
            .iter()
            .enumerate()
            .map(|(i, (line, col))| crate::types::Evidence {
                method: "ast".to_string(),
                source: "tree-sitter".to_string(),
                value: format!("{}-ev{}", id, i), // unique to avoid dedup
                location: Some(format!("{}:{}", line, col)),
                ..Default::default()
            })
            .collect(),
        match_count: 0,
        source_file: None,
    }
}

#[test]
fn test_proximity_same_condition_not_sufficient() {
    // One trait has 3 evidence items at lines 1, 2, 3 (all close together).
    // Second trait is at line 100 (far away).
    // With near_lines: 5, this should FAIL because no window of 5 lines
    // contains evidence from both conditions.
    let report = empty_report();
    let data: Vec<u8> = "x\n".repeat(110).into_bytes();
    let findings = vec![
        finding_at_lines("trait-a", &[(1, 1), (2, 1), (3, 1)]),
        finding_at_line("trait-b", 100, 1),
    ];
    let ctx = proximity_ctx(&report, &data, &findings);
    let rule = proximity_rule(&["trait-a", "trait-b"], Some(5), None);
    assert!(
        rule.evaluate(&ctx).is_none(),
        "Multiple evidence items from trait-a near each other should not satisfy proximity \
         when trait-b is 100 lines away"
    );
}

#[test]
fn test_proximity_cross_condition_passes() {
    // trait-a at line 5, trait-b at line 7 → 2 lines apart, well within near_lines: 5
    let report = empty_report();
    let data = b"1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n";
    let findings = vec![
        finding_at_line("trait-a", 5, 1),
        finding_at_line("trait-b", 7, 1),
    ];
    let ctx = proximity_ctx(&report, data, &findings);
    let rule = proximity_rule(&["trait-a", "trait-b"], Some(5), None);
    assert!(
        rule.evaluate(&ctx).is_some(),
        "Evidence from two conditions 2 lines apart should pass near_lines: 5"
    );
}

#[test]
fn test_proximity_cross_condition_fails() {
    // trait-a at line 5, trait-b at line 50 → 45 lines apart, fails near_lines: 5
    let report = empty_report();
    let data: Vec<u8> = "x\n".repeat(60).into_bytes();
    let findings = vec![
        finding_at_line("trait-a", 5, 1),
        finding_at_line("trait-b", 50, 1),
    ];
    let ctx = proximity_ctx(&report, &data, &findings);
    let rule = proximity_rule(&["trait-a", "trait-b"], Some(5), None);
    assert!(
        rule.evaluate(&ctx).is_none(),
        "Evidence from two conditions 45 lines apart should fail near_lines: 5"
    );
}

#[test]
fn test_proximity_three_conditions_all_close() {
    // 3 conditions all within a 5-line window: lines 5, 7, 9
    let report = empty_report();
    let data = b"1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n";
    let findings = vec![
        finding_at_line("trait-a", 5, 1),
        finding_at_line("trait-b", 7, 1),
        finding_at_line("trait-c", 9, 1),
    ];
    let ctx = proximity_ctx(&report, data, &findings);
    let rule = proximity_rule(&["trait-a", "trait-b", "trait-c"], Some(5), None);
    assert!(
        rule.evaluate(&ctx).is_some(),
        "3 conditions within a 5-line span should pass near_lines: 5"
    );
}

#[test]
fn test_proximity_any_needs_cross_condition() {
    // any: 4 traits at lines 5, 7, 50, 100. needs: 2, near_lines: 5.
    // Traits at lines 5 and 7 are distinct conditions within the window → pass.
    let report = empty_report();
    let data: Vec<u8> = "x\n".repeat(110).into_bytes();
    let findings = vec![
        finding_at_line("trait-a", 5, 1),
        finding_at_line("trait-b", 7, 1),
        finding_at_line("trait-c", 50, 1),
        finding_at_line("trait-d", 100, 1),
    ];
    let ctx = proximity_ctx(&report, &data, &findings);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/any-cross".to_string(),
        desc: "Any cross-condition proximity".to_string(),
        conf: 0.9,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![
            Condition::Trait {
                id: "trait-a".to_string(),
            },
            Condition::Trait {
                id: "trait-b".to_string(),
            },
            Condition::Trait {
                id: "trait-c".to_string(),
            },
            Condition::Trait {
                id: "trait-d".to_string(),
            },
        ]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(2),
        near_lines: Some(5),
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };
    assert!(
        rule.evaluate(&ctx).is_some(),
        "any(needs:2) with near_lines:5 should pass — traits at lines 5 and 7 are close"
    );
}

#[test]
fn test_proximity_bytes_cross_condition() {
    // trait-a at offset 100, trait-b at offset 110 → 10 bytes apart, within near_bytes: 20
    let report = empty_report();
    let data = vec![0u8; 200];
    let findings = vec![
        finding_at_offset("trait-a", 100),
        finding_at_offset("trait-b", 110),
    ];
    let ctx = proximity_ctx(&report, &data, &findings);

    let rule = proximity_rule(&["trait-a", "trait-b"], None, Some(20));
    assert!(
        rule.evaluate(&ctx).is_some(),
        "near_bytes: 20 should pass when offsets are 10 apart"
    );

    let tight = proximity_rule(&["trait-a", "trait-b"], None, Some(5));
    assert!(
        tight.evaluate(&ctx).is_none(),
        "near_bytes: 5 should fail when offsets are 10 apart"
    );
}

#[test]
fn test_proximity_multi_evidence_one_near() {
    // trait-a has evidence at lines 5 AND 50.
    // trait-b has evidence at line 52.
    // near_lines: 5 should pass — trait-a@50 is near trait-b@52.
    let report = empty_report();
    let data: Vec<u8> = "x\n".repeat(60).into_bytes();
    let findings = vec![
        finding_at_lines("trait-a", &[(5, 1), (50, 1)]),
        finding_at_line("trait-b", 52, 1),
    ];
    let ctx = proximity_ctx(&report, &data, &findings);
    let rule = proximity_rule(&["trait-a", "trait-b"], Some(5), None);
    assert!(
        rule.evaluate(&ctx).is_some(),
        "trait-a has evidence at 5 and 50; trait-b at 52. \
         Lines 50 and 52 are within 5 → should pass"
    );
}

#[test]
fn test_proximity_does_not_boost_confidence() {
    // A proximity rule with conf: 0.6 should keep conf: 0.6 in the finding,
    // not boost it toward 1.0. Proximity increases precision, not confidence.
    let report = empty_report();
    let data = b"1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n";
    let findings = vec![
        finding_at_line("trait-a", 5, 1),
        finding_at_line("trait-b", 7, 1),
    ];
    let ctx = proximity_ctx(&report, data, &findings);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "test/conf-check".to_string(),
        desc: "Confidence check".to_string(),
        conf: 0.6,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![
            Condition::Trait {
                id: "trait-a".to_string(),
            },
            Condition::Trait {
                id: "trait-b".to_string(),
            },
        ]),
        any: None,
        unless: None,
        not: None,
        downgrade: None,
        needs: None,
        near_lines: Some(5),
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let finding = rule.evaluate(&ctx).expect("proximity rule should match");
    assert!(
        (finding.conf - 0.6).abs() < f32::EPSILON,
        "Proximity should not boost confidence. Expected 0.6, got {}",
        finding.conf
    );
}

#[test]
fn test_proximity_filters_evidence_to_window() {
    // trait-a has evidence at lines 5 AND 50.
    // trait-b has evidence at line 7.
    // near_lines: 5 → window is lines 5-7.
    // Finding should only contain evidence within the window (lines 5 and 7),
    // NOT the trait-a evidence at line 50.
    let report = empty_report();
    let data: Vec<u8> = "x\n".repeat(60).into_bytes();
    let findings = vec![
        finding_at_lines("trait-a", &[(5, 1), (50, 1)]),
        finding_at_line("trait-b", 7, 1),
    ];
    let ctx = proximity_ctx(&report, &data, &findings);
    let rule = proximity_rule(&["trait-a", "trait-b"], Some(5), None);

    let finding = rule.evaluate(&ctx).expect("proximity rule should match");

    // All evidence should be within the proximity window (lines 5-7)
    for ev in &finding.evidence {
        if let Some(ref loc) = ev.location
            && let Some(colon) = loc.find(':')
        {
            let line: usize = loc[..colon].parse().unwrap_or(0);
            assert!(
                (5..=7).contains(&line),
                "Evidence at line {} is outside proximity window 5-7: {:?}",
                line,
                ev
            );
        }
    }

    // Should have exactly 2 evidence items (line 5 from trait-a, line 7 from trait-b)
    assert_eq!(
        finding.evidence.len(),
        2,
        "Expected 2 evidence items in window, got {}: {:?}",
        finding.evidence.len(),
        finding
            .evidence
            .iter()
            .map(|e| e.location.as_deref().unwrap_or("none"))
            .collect::<Vec<_>>()
    );
}

/// Helper: build a Finding with the given id (component-style member trait).
#[cfg(test)]
fn member_finding(id: &str) -> Finding {
    Finding {
        id: id.to_string(),
        kind: FindingKind::Capability,
        desc: format!("member {id}"),
        conf: 0.9,
        crit: Criticality::Component,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        // Evidence carries a `location` so the (default) `file` scope filter
        // actually engages — empty evidence makes the scope filter a no-op and
        // would hide this bug.
        evidence: vec![crate::types::Evidence {
            method: "symbol".to_string(),
            source: "test".to_string(),
            value: id.to_string(),
            location: Some("libavformat.so".to_string()),
            ..Default::default()
        }],
        match_count: 1,
        source_file: None,
    }
}

/// Regression: a composite whose `any:` is a single directory-prefix reference
/// with `needs: 2` MUST fire when the directory matched >= 2 distinct member
/// traits. The directory ref's matched-member count must be weighted toward
/// `needs` (not collapsed to one condition). See bug: "needs over single
/// dir-ref never fires".
#[test]
fn test_needs_counts_directory_ref_member_matches() {
    let (mut report, data) = create_test_context();
    report
        .findings
        .push(member_finding("well-known/lib/ffmpeg::av-malloc"));
    report
        .findings
        .push(member_finding("well-known/lib/ffmpeg::av-free"));
    report
        .findings
        .push(member_finding("well-known/lib/ffmpeg::av-log"));

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "well-known/lib/ffmpeg::ffmpeg-lib-marker".to_string(),
        desc: "FFmpeg marker".to_string(),
        conf: 0.95,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![Condition::Trait {
            id: "well-known/lib/ffmpeg".to_string(),
        }]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(2),
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let result = rule.evaluate(&ctx);
    assert!(
        result.is_some(),
        "dir-ref matched 3 members; needs:2 must be satisfied"
    );
}

/// Control: needs:2 over a single dir-ref that matched only ONE member must NOT fire.
#[test]
fn test_needs_two_not_met_by_single_dir_ref_member() {
    let (mut report, data) = create_test_context();
    report
        .findings
        .push(member_finding("well-known/lib/ffmpeg::av-malloc"));

    let ctx = EvaluationContext::new(&report, &data, FileType::Elf, &[Platform::All], None, None);

    let rule = CompositeTrait {
        required_trait_indices: Vec::new(),
        id: "well-known/lib/ffmpeg::ffmpeg-lib-marker".to_string(),
        desc: "FFmpeg marker".to_string(),
        conf: 0.95,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![FileType::All],
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: None,
        any: Some(vec![Condition::Trait {
            id: "well-known/lib/ffmpeg".to_string(),
        }]),
        unless: None,
        not: None,
        downgrade: None,
        needs: Some(2),
        near_lines: None,
        near_bytes: None,
        scope: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    assert!(
        rule.evaluate(&ctx).is_none(),
        "only one member matched; needs:2 must not be satisfied"
    );
}
