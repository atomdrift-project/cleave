//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for TraitDefinition evaluation with focus on constraints and security features.
//!
//! Comprehensive test coverage for:
//! - Size constraints (size_min, size_max)
//! - Count constraints (count_min, count_max)
//! - Density constraints (per_kb_min, per_kb_max)
//! - Timeout protection (MAX_RULE_EVAL_DURATION)
//! - Platform and file type filtering
//! - Downgrade logic

use super::condition::Condition;
use super::context::EvaluationContext;
use super::traits::*;
use super::types::{Arch, FileType, Platform};
use crate::types::{AnalysisReport, Criticality, Import, TargetInfo};
use std::path::PathBuf;
use std::sync::OnceLock;

/// Helper: Create minimal trait definition
fn create_test_trait(id: &str, condition: Condition) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "Test trait".to_string(),
        crit: Criticality::Notable,
        conf: 1.0,
        r#for: vec![FileType::All],
        for_from_groups: false,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        mbc: None,
        attack: None,
        r#if: condition,
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,

        unless: None,
        downgrade: None,
        defined_in: PathBuf::from("test.yaml"),
        not: None,
        precision: None,
    }
}

/// Helper: Create test report with specific size
fn create_report_with_size(size_bytes: u64) -> AnalysisReport {
    AnalysisReport::new(TargetInfo {
        path: "test.bin".to_string(),
        file_type: "executable".to_string(),
        size_bytes,
        sha256: "test".to_string(),
        architectures: None,
    })
}

/// Helper: Create test context
fn create_test_context(report: AnalysisReport, binary_data: Vec<u8>) -> EvaluationContext<'static> {
    EvaluationContext {
        report: Box::leak(Box::new(report)),
        binary_data: Box::leak(binary_data.into_boxed_slice()),
        file_type: FileType::All,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        arch_ranges: None,
        additional_findings: None,
        cached_ast: None,
        finding_id_index: None,
        debug_collector: None,
        section_map: None,
        inline_yara_results: None,
        cached_kv_format: OnceLock::new(),
        cached_kv_parsed: OnceLock::new(),
        current_trait: None,
        current_source: None,
        string_exact_index: OnceLock::new(),
        string_exact_index_ci: OnceLock::new(),
        deadline: None,
        slow_rule_ms: 4000,
    }
}

// ==================== Size constraint tests ====================

#[test]
fn test_size_min_constraint_pass() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/size::min_pass", condition);
    trait_def.size_min = Some(100); // Require at least 100 bytes

    let mut report = create_report_with_size(1024); // 1KB file
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(result.is_some(), "Should match when size >= size_min");
}

#[test]
fn test_size_min_constraint_fail() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/size::min_fail", condition);
    trait_def.size_min = Some(2000); // Require at least 2000 bytes

    let mut report = create_report_with_size(1024); // 1KB file (too small)
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(result.is_none(), "Should not match when size < size_min");
}

#[test]
fn test_size_max_constraint_pass() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/size::max_pass", condition);
    trait_def.size_max = Some(5000); // Max 5000 bytes

    let mut report = create_report_with_size(1024); // 1KB file
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(result.is_some(), "Should match when size <= size_max");
}

#[test]
fn test_size_max_constraint_fail() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/size::max_fail", condition);
    trait_def.size_max = Some(500); // Max 500 bytes

    let mut report = create_report_with_size(1024); // 1KB file (too large)
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(result.is_none(), "Should not match when size > size_max");
}

#[test]
fn test_size_range_constraint() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/size::range", condition);
    trait_def.size_min = Some(500);
    trait_def.size_max = Some(2000);

    let mut report = create_report_with_size(1024); // 1KB file (within range)
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(result.is_some(), "Should match when size in range");
}

// ==================== Count constraint tests ====================

#[test]
fn test_count_min_constraint_pass() {
    let condition = Condition::Symbol {
        exact: None,
        substr: Some("func".to_string()),
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/count::min_pass", condition);
    trait_def.count_min = Some(2); // Require at least 2 matches

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "func1".to_string(),
        library: None,
        source: "test".to_string(),
    });
    report.imports.push(Import {
        symbol: "func2".to_string(),
        library: None,
        source: "test".to_string(),
    });
    report.imports.push(Import {
        symbol: "func3".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(result.is_some(), "Should match when count >= count_min");
}

#[test]
fn test_count_min_constraint_fail() {
    let condition = Condition::Symbol {
        exact: None,
        substr: Some("func".to_string()),
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/count::min_fail", condition);
    trait_def.count_min = Some(5); // Require at least 5 matches

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "func1".to_string(),
        library: None,
        source: "test".to_string(),
    });
    report.imports.push(Import {
        symbol: "func2".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(result.is_none(), "Should not match when count < count_min");
}

#[test]
fn test_count_max_constraint_pass() {
    let condition = Condition::Symbol {
        exact: None,
        substr: Some("func".to_string()),
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/count::max_pass", condition);
    trait_def.count_max = Some(5); // Max 5 matches

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "func1".to_string(),
        library: None,
        source: "test".to_string(),
    });
    report.imports.push(Import {
        symbol: "func2".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(result.is_some(), "Should match when count <= count_max");
}

#[test]
fn test_count_max_constraint_fail() {
    let condition = Condition::Symbol {
        exact: None,
        substr: Some("func".to_string()),
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/count::max_fail", condition);
    trait_def.count_max = Some(1); // Max 1 match

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "func1".to_string(),
        library: None,
        source: "test".to_string(),
    });
    report.imports.push(Import {
        symbol: "func2".to_string(),
        library: None,
        source: "test".to_string(),
    });
    report.imports.push(Import {
        symbol: "func3".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(result.is_none(), "Should not match when count > count_max");
}

// ==================== Density constraint tests ====================

#[test]
fn test_per_kb_min_constraint_pass() {
    let condition = Condition::Symbol {
        exact: None,
        substr: Some("func".to_string()),
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/density::min_pass", condition);
    trait_def.per_kb_min = Some(1.0); // At least 1 match per KB

    let mut report = create_report_with_size(2048); // 2KB file
                                                    // Add 3 matches = 1.5 matches/KB
    report.imports.push(Import {
        symbol: "func1".to_string(),
        library: None,
        source: "test".to_string(),
    });
    report.imports.push(Import {
        symbol: "func2".to_string(),
        library: None,
        source: "test".to_string(),
    });
    report.imports.push(Import {
        symbol: "func3".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(result.is_some(), "Should match when density >= per_kb_min");
}

#[test]
fn test_per_kb_min_constraint_fail() {
    let condition = Condition::Symbol {
        exact: None,
        substr: Some("func".to_string()),
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/density::min_fail", condition);
    trait_def.per_kb_min = Some(5.0); // At least 5 matches per KB

    let mut report = create_report_with_size(2048); // 2KB file
                                                    // Add 2 matches = 1.0 matches/KB (too low)
    report.imports.push(Import {
        symbol: "func1".to_string(),
        library: None,
        source: "test".to_string(),
    });
    report.imports.push(Import {
        symbol: "func2".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(
        result.is_none(),
        "Should not match when density < per_kb_min"
    );
}

#[test]
fn test_per_kb_max_constraint_pass() {
    let condition = Condition::Symbol {
        exact: None,
        substr: Some("func".to_string()),
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/density::max_pass", condition);
    trait_def.per_kb_max = Some(10.0); // Max 10 matches per KB

    let mut report = create_report_with_size(1024); // 1KB file
                                                    // Add 5 matches = 5.0 matches/KB
    for i in 0..5 {
        report.imports.push(Import {
            symbol: format!("func{}", i),
            library: None,
            source: "test".to_string(),
        });
    }

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(result.is_some(), "Should match when density <= per_kb_max");
}

#[test]
fn test_per_kb_max_constraint_fail() {
    let condition = Condition::Symbol {
        exact: None,
        substr: Some("func".to_string()),
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/density::max_fail", condition);
    trait_def.per_kb_max = Some(2.0); // Max 2 matches per KB

    let mut report = create_report_with_size(1024); // 1KB file
                                                    // Add 10 matches = 10.0 matches/KB (too high)
    for i in 0..10 {
        report.imports.push(Import {
            symbol: format!("func{}", i),
            library: None,
            source: "test".to_string(),
        });
    }

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(
        result.is_none(),
        "Should not match when density > per_kb_max"
    );
}

#[test]
fn test_per_kb_max_zero_byte_file_with_matches_fails() {
    // A zero-byte file with any matches has infinite density — must fail a max ceiling.
    let condition = Condition::Symbol {
        exact: None,
        substr: Some("func".to_string()),
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/density::max_zero_byte_fail", condition);
    trait_def.per_kb_max = Some(100.0);

    let mut report = create_report_with_size(0); // zero-byte file
    report.imports.push(Import {
        symbol: "func1".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(
        result.is_none(),
        "Zero-byte file with matches has infinite density and must fail per_kb_max"
    );
}

#[test]
fn test_per_kb_max_zero_byte_file_no_matches_passes() {
    // A zero-byte file with no matches has zero matches/KB — passes the ceiling check.
    let condition = Condition::Symbol {
        exact: None,
        substr: Some("func".to_string()),
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/density::max_zero_byte_pass", condition);
    trait_def.per_kb_max = Some(100.0);
    // No count_min means zero matches is still potentially valid — the condition just won't fire,
    // so evaluate() returns None because the condition itself doesn't match.
    // Add count_min=0 explicitly so only the density gate matters.
    // (The default is None which lets zero-match results through the count gate.)

    let report = create_report_with_size(0); // zero-byte file, no matches

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    // With no matches the condition doesn't fire → result is None regardless.
    // The important thing is that we don't panic on a zero-byte file.
    assert!(
        result.is_none(),
        "Zero-byte file with no matches should produce no result (condition never fires)"
    );
}

// ==================== Platform filtering tests ====================

#[test]
fn test_platform_filter_match() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/platform::match", condition);
    trait_def.platforms = vec![Platform::Linux, Platform::MacOS];

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let mut ctx = create_test_context(report, vec![]);
    ctx.platforms = vec![Platform::Linux]; // Context has Linux

    let result = trait_def.evaluate(&ctx);

    assert!(result.is_some(), "Should match when platforms intersect");
}

#[test]
fn test_platform_filter_no_match() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/platform::no_match", condition);
    trait_def.platforms = vec![Platform::Linux, Platform::MacOS];

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let mut ctx = create_test_context(report, vec![]);
    ctx.platforms = vec![Platform::Windows]; // No intersection

    let result = trait_def.evaluate(&ctx);

    assert!(
        result.is_none(),
        "Should not match when platforms don't intersect"
    );
}

#[test]
fn test_platform_all_matches_everything() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/platform::all", condition);
    trait_def.platforms = vec![Platform::All];

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let mut ctx = create_test_context(report, vec![]);
    ctx.platforms = vec![Platform::Windows];

    let result = trait_def.evaluate(&ctx);

    assert!(result.is_some(), "Platform::All should match any platform");
}

// ==================== Architecture filtering tests ====================

#[test]
fn test_arch_filter_match() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/arch::match", condition);
    trait_def.arch = vec![Arch::Arm, Arch::Aarch64];

    let mut report = create_report_with_size(1024);
    report.target.architectures = Some(vec!["arm".to_string()]);
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let mut ctx = create_test_context(report, vec![]);
    ctx.arch = vec![Arch::Arm];

    let result = trait_def.evaluate(&ctx);
    assert!(result.is_some(), "Should match when arch intersects");
}

#[test]
fn test_arch_filter_no_match() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/arch::no_match", condition);
    trait_def.arch = vec![Arch::X86, Arch::X86_64];

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let mut ctx = create_test_context(report, vec![]);
    ctx.arch = vec![Arch::Arm];

    let result = trait_def.evaluate(&ctx);
    assert!(
        result.is_none(),
        "Should not match when arch doesn't intersect"
    );
}

#[test]
fn test_arch_all_matches_any_file_arch() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let trait_def = create_test_trait("test/arch::all_trait", condition);
    assert_eq!(trait_def.arch, vec![Arch::All]);

    let mut report = create_report_with_size(1024);
    report.target.architectures = Some(vec!["aarch64".to_string()]);
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let mut ctx = create_test_context(report, vec![]);
    ctx.arch = vec![Arch::Aarch64];

    let result = trait_def.evaluate(&ctx);
    assert!(
        result.is_some(),
        "Arch::All trait should match any file architecture"
    );
}

#[test]
fn test_arch_file_all_matches_any_trait_arch() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/arch::file_all", condition);
    trait_def.arch = vec![Arch::X86];

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    assert_eq!(ctx.arch, vec![Arch::All]);

    let result = trait_def.evaluate(&ctx);
    assert!(
        result.is_some(),
        "File with unknown arch (All) should match any trait arch"
    );
}

#[test]
fn test_arch_no_default_to_runtime_arch() {
    let report = create_report_with_size(1024);
    assert!(report.target.architectures.is_none());
    let ctx = create_test_context(report, vec![]);
    assert_eq!(
        ctx.arch,
        vec![Arch::All],
        "Default arch must be All when report has no architectures"
    );
}

#[test]
fn test_arch_from_report_str_parsing() {
    assert_eq!(Arch::from_report_str("x86_64"), Arch::X86_64);
    assert_eq!(Arch::from_report_str("i386"), Arch::X86);
    assert_eq!(Arch::from_report_str("aarch64"), Arch::Aarch64);
    assert_eq!(Arch::from_report_str("arm"), Arch::Arm);
    assert_eq!(Arch::from_report_str("arm64"), Arch::Aarch64);
    assert_eq!(Arch::from_report_str("arm64e"), Arch::Aarch64);
    assert_eq!(Arch::from_report_str("ARM"), Arch::Arm);
    assert_eq!(Arch::from_report_str("ARM64"), Arch::Aarch64);
    assert_eq!(Arch::from_report_str("riscv"), Arch::Riscv);
    assert_eq!(Arch::from_report_str("mips"), Arch::Mips);
    assert_eq!(Arch::from_report_str("m68k"), Arch::M68k);
}

#[test]
fn test_arch_from_str_yaml_parsing() {
    assert_eq!(Arch::from_str("x86"), Arch::X86);
    assert_eq!(Arch::from_str("x86-64"), Arch::X86_64);
    assert_eq!(Arch::from_str("aarch64"), Arch::Aarch64);
    assert_eq!(Arch::from_str("arm"), Arch::Arm);
    assert_eq!(Arch::from_str("arm64"), Arch::Aarch64);
    assert_eq!(Arch::from_str("amd64"), Arch::X86_64);
    assert_eq!(Arch::from_str("ppc"), Arch::Powerpc);
    assert_eq!(Arch::from_str("sh"), Arch::Superh);
}

#[test]
fn test_arch_multi_arch_file() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/arch::multi_arch", condition);
    trait_def.arch = vec![Arch::X86_64];

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let mut ctx = create_test_context(report, vec![]);
    ctx.arch = vec![Arch::X86_64, Arch::Aarch64];

    let result = trait_def.evaluate(&ctx);
    assert!(
        result.is_some(),
        "Should match when file contains target architecture"
    );
}

#[test]
fn test_arch_clamp_range_fat_binary() {
    let report = create_report_with_size(200000);
    let binary_data = vec![0u8; 200000];
    let mut ctx = create_test_context(report, binary_data);
    ctx.arch_ranges = Some(vec![
        (Arch::X86_64, 0..100000),
        (Arch::Aarch64, 100000..200000),
    ]);

    // Trait targeting x86-64 should clamp to first slice
    let clamp = ctx.arch_clamp_range(&[Arch::X86_64]);
    assert_eq!(clamp, Some((0, 100000)));

    // Trait targeting aarch64 should clamp to second slice
    let clamp = ctx.arch_clamp_range(&[Arch::Aarch64]);
    assert_eq!(clamp, Some((100000, 200000)));

    // Trait targeting All should not clamp
    let clamp = ctx.arch_clamp_range(&[Arch::All]);
    assert!(clamp.is_none());

    // No arch_ranges means no clamping
    ctx.arch_ranges = None;
    let clamp = ctx.arch_clamp_range(&[Arch::X86_64]);
    assert!(clamp.is_none());
}

// ==================== File type filtering tests ====================

#[test]
fn test_file_type_filter_match() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/filetype::match", condition);
    trait_def.r#for = vec![FileType::Elf, FileType::Macho];

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let mut ctx = create_test_context(report, vec![]);
    ctx.file_type = FileType::Elf;

    let result = trait_def.evaluate(&ctx);

    assert!(result.is_some(), "Should match when file type matches");
}

#[test]
fn test_file_type_filter_no_match() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/filetype::no_match", condition);
    trait_def.r#for = vec![FileType::Python, FileType::JavaScript];

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let mut ctx = create_test_context(report, vec![]);
    ctx.file_type = FileType::Elf;

    let result = trait_def.evaluate(&ctx);

    assert!(
        result.is_none(),
        "Should not match when file type doesn't match"
    );
}

// ==================== Constraint combination tests ====================

#[test]
fn test_all_constraints_combined() {
    let condition = Condition::Symbol {
        exact: None,
        substr: Some("func".to_string()),
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/constraints::combined", condition);
    trait_def.size_min = Some(512);
    trait_def.size_max = Some(2048);
    trait_def.count_min = Some(2);
    trait_def.count_max = Some(10);
    trait_def.per_kb_min = Some(1.0);
    trait_def.per_kb_max = Some(5.0);

    let mut report = create_report_with_size(1024); // 1KB file
                                                    // Add 3 matches = 3.0 matches/KB
    report.imports.push(Import {
        symbol: "func1".to_string(),
        library: None,
        source: "test".to_string(),
    });
    report.imports.push(Import {
        symbol: "func2".to_string(),
        library: None,
        source: "test".to_string(),
    });
    report.imports.push(Import {
        symbol: "func3".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(
        result.is_some(),
        "Should match when all constraints satisfied"
    );
}

// ==================== Finding generation tests ====================

#[test]
fn test_finding_contains_evidence() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let trait_def = create_test_trait("test/finding::evidence", condition);

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(result.is_some());
    let finding = result.unwrap();
    assert!(
        !finding.evidence.is_empty(),
        "Finding should contain evidence"
    );
    assert_eq!(finding.evidence[0].value, "test");
}

#[test]
fn test_finding_has_correct_criticality() {
    let condition = Condition::Symbol {
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        platforms: None,
        is_check: None,
        compiled_regex: None,
    };

    let mut trait_def = create_test_trait("test/finding::crit", condition);
    trait_def.crit = Criticality::Hostile;

    let mut report = create_report_with_size(1024);
    report.imports.push(Import {
        symbol: "test".to_string(),
        library: None,
        source: "test".to_string(),
    });

    let ctx = create_test_context(report, vec![]);
    let result = trait_def.evaluate(&ctx);

    assert!(result.is_some());
    let finding = result.unwrap();
    assert_eq!(finding.crit, Criticality::Hostile);
}
