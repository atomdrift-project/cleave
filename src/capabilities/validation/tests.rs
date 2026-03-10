//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for validation module.
//!
//! Tests are organized by submodule to match the module structure.

#[cfg(test)]
mod precision_tests {
    use crate::capabilities::validation::precision::calculate_trait_precision;
    use crate::composite_rules::{Arch, Condition, FileType, Platform, TraitDefinition};
    use std::path::PathBuf;

    fn create_minimal_trait(condition: Condition) -> TraitDefinition {
        TraitDefinition {
            id: "test/precision".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
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
            r#for: vec![FileType::All],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yml"),
            precision: None,
        }
    }

    #[test]
    fn test_precision_count_min_scored() {
        let mut trait_def = create_minimal_trait(Condition::String {
            exact: Some("test".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            external_ip: false,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
        });
        let base = calculate_trait_precision(&trait_def);

        trait_def.count_min = Some(3);
        let with_count_min = calculate_trait_precision(&trait_def);

        assert!(
            with_count_min > base,
            "count_min should add precision: base={}, with_count_min={}",
            base,
            with_count_min
        );
        // Should add exactly PARAM_UNIT (0.3)
        assert!((with_count_min - base - 0.3).abs() < 0.01);
    }

    #[test]
    fn test_precision_density_scored() {
        let mut trait_def = create_minimal_trait(Condition::String {
            exact: Some("test".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            external_ip: false,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
        });
        let base = calculate_trait_precision(&trait_def);

        trait_def.per_kb_min = Some(1.0);
        trait_def.per_kb_max = Some(10.0);
        let with_density = calculate_trait_precision(&trait_def);

        assert!(
            with_density > base,
            "density constraints should add precision: base={}, with_density={}",
            base,
            with_density
        );
        // Should add 2 * PARAM_UNIT (0.6)
        assert!((with_density - base - 0.6).abs() < 0.01);
    }
}

#[cfg(test)]
mod duplicate_tests {
    use super::super::duplicates::*;
    use super::super::helpers::extract_tier;
    use crate::composite_rules::{Arch, Condition, FileType, Platform, TraitDefinition};
    use std::path::PathBuf;

    // ========================================================================
    // Test Helpers
    // ========================================================================

    /// Create a minimal trait definition for testing
    fn create_test_trait(
        id: &str,
        condition: Condition,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait_with_conf_crit(
            id,
            condition,
            for_types,
            file_path,
            1.0,
            crate::types::Criticality::Notable,
        )
    }

    /// Create a trait definition with specific confidence and criticality
    fn create_test_trait_with_conf_crit(
        id: &str,
        condition: Condition,
        for_types: Vec<FileType>,
        file_path: &str,
        conf: f32,
        crit: crate::types::Criticality,
    ) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test trait".to_string(),
            conf,
            crit,
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
            r#for: for_types,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from(file_path),
            precision: None,
        }
    }

    /// Create a string exact trait
    fn create_string_exact(
        id: &str,
        pattern: &str,
        case_insensitive: bool,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::String {
                exact: Some(pattern.to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            for_types,
            file_path,
        )
    }

    /// Create a string substr trait
    fn create_string_substr(
        id: &str,
        pattern: &str,
        case_insensitive: bool,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::String {
                exact: None,
                substr: Some(pattern.to_string()),
                regex: None,
                word: None,
                case_insensitive,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            for_types,
            file_path,
        )
    }

    /// Create a string regex trait
    fn create_string_regex(
        id: &str,
        pattern: &str,
        case_insensitive: bool,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::String {
                exact: None,
                substr: None,
                regex: Some(pattern.to_string()),
                word: None,
                case_insensitive,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            for_types,
            file_path,
        )
    }

    /// Create a symbol exact trait
    fn create_symbol_exact(
        id: &str,
        pattern: &str,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Symbol {
                exact: Some(pattern.to_string()),
                substr: None,
                regex: None,
                platforms: None,
                compiled_regex: None,
            },
            for_types,
            file_path,
        )
    }

    /// Create a raw regex trait
    fn create_raw_regex(
        id: &str,
        pattern: &str,
        case_insensitive: bool,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Raw {
                exact: None,
                substr: None,
                regex: Some(pattern.to_string()),
                word: None,
                case_insensitive,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                compiled_regex: None,
            },
            for_types,
            file_path,
        )
    }

    // ========================================================================
    // Phase 1: Hex Escape Normalization Tests
    // ========================================================================

    #[test]
    fn test_hex_escape_single_byte() {
        assert_eq!(decode_hex_escapes("\\x27"), "'");
        assert_eq!(decode_hex_escapes("\\x00"), "\0");
        assert_eq!(decode_hex_escapes("\\x41"), "A");
        assert_eq!(decode_hex_escapes("\\x7f"), "\x7f");
    }

    #[test]
    fn test_hex_escape_in_string() {
        assert_eq!(decode_hex_escapes("test\\x27string"), "test'string");
        assert_eq!(decode_hex_escapes("\\x48ello"), "Hello");
        assert_eq!(decode_hex_escapes("foo\\x20bar"), "foo bar");
    }

    #[test]
    fn test_hex_escape_multiple() {
        assert_eq!(decode_hex_escapes("\\x41\\x42\\x43"), "ABC");
        assert_eq!(decode_hex_escapes("\\x27\\x22"), "'\"");
    }

    #[test]
    fn test_hex_escape_invalid_kept_as_is() {
        // Invalid hex (only 1 digit)
        assert_eq!(decode_hex_escapes("\\x2"), "\\x2");
        // Invalid hex (non-hex chars)
        assert_eq!(decode_hex_escapes("\\xZZ"), "\\xZZ");
        // Other escape sequences preserved
        assert_eq!(decode_hex_escapes("\\n"), "\\n");
        assert_eq!(decode_hex_escapes("\\t"), "\\t");
    }

    #[test]
    fn test_hex_escape_duplicate_detection() {
        let trait1 =
            create_string_exact("test::a", "\\x27", false, vec![FileType::All], "file1.yaml");
        let trait2 = create_string_exact("test::b", "'", false, vec![FileType::All], "file2.yaml");

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Duplicate"));
        assert!(warnings[0].contains("test::a"));
        assert!(warnings[0].contains("test::b"));
    }

    #[test]
    fn test_hex_escape_real_example() {
        // Hex escape vs literal - exact patterns that normalize the same
        let trait1 = create_string_exact(
            "test::a",
            "\\x27", // \x27 is hex for single quote '
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let trait2 = create_string_exact(
            "test::b",
            "'", // Literal single quote
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        // Should detect as duplicate - \x27 normalizes to '
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Duplicate"));
    }

    // ========================================================================
    // Phase 2: Containment Detection Tests
    // ========================================================================

    #[test]
    fn test_exact_contained_by_substr() {
        let exact = create_string_exact(
            "test::exact",
            "/dev/kmem",
            false,
            vec![FileType::Elf],
            "file1.yaml",
        );
        let substr = create_string_substr(
            "test::substr",
            "/dev/kmem",
            false,
            vec![FileType::Elf],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_exact_contained_by_substr(&[exact, substr], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("REDUNDANT"));
        assert!(warnings[0].contains("exact pattern"));
        assert!(warnings[0].contains("/dev/kmem"));
    }

    #[test]
    fn test_exact_not_contained_different_strings() {
        let exact = create_string_exact(
            "test::exact",
            "os.rename",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let substr = create_string_substr(
            "test::substr",
            "os.rename ", // trailing space
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_exact_contained_by_substr(&[exact, substr], &mut warnings);

        // No redundancy because strings differ (trailing space)
        assert_eq!(warnings.len(), 0);
    }

    // ========================================================================
    // Phase 3: Case-Insensitive Overlap Tests
    // ========================================================================

    #[test]
    fn test_case_insensitive_subsumes_case_sensitive() {
        let case_sensitive = create_string_exact(
            "test::sensitive",
            "PASSWORD",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let case_insensitive = create_string_exact(
            "test::insensitive",
            "password",
            true,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_case_insensitive_overlaps(&[case_sensitive, case_insensitive], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("CASE SUBSUMPTION"));
    }

    #[test]
    fn test_both_case_insensitive_differ_in_case() {
        let trait1 = create_string_exact(
            "test::a",
            "GetProcAddress",
            true,
            vec![FileType::All],
            "file1.yaml",
        );
        let trait2 = create_string_exact(
            "test::b",
            "getprocaddress",
            true,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_case_insensitive_overlaps(&[trait1, trait2], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("DUPLICATE (case only)"));
    }

    #[test]
    fn test_both_case_sensitive_different_case_ok() {
        let trait1 = create_string_exact(
            "test::a",
            "GetProcAddress",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let trait2 = create_string_exact(
            "test::b",
            "GETPROCADDRESS",
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_case_insensitive_overlaps(&[trait1, trait2], &mut warnings);

        // No warning - both case-sensitive, different case = different patterns
        assert_eq!(warnings.len(), 0);
    }

    // ========================================================================
    // Phase 4: Regex Containment Tests
    // ========================================================================

    #[test]
    fn test_regex_exact_match_cross_type() {
        let symbol_exact = create_symbol_exact(
            "test::symbol",
            "GetProcAddress",
            vec![FileType::Pe],
            "file1.yaml",
        );
        let raw_regex = create_raw_regex(
            "test::raw",
            "GetProcAddress",
            false,
            vec![FileType::Pe],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_regex_contains_literal(&[symbol_exact, raw_regex], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("REGEX vs LITERAL DUPLICATE"));
        assert!(warnings[0].contains("cross-type"));
    }

    #[test]
    fn test_regex_contains_literal() {
        let exact = create_string_exact(
            "test::exact",
            "foo",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let regex = create_string_regex(
            "test::regex",
            "foo.*",
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_regex_contains_literal(&[exact, regex], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("REGEX CONTAINS LITERAL"));
    }

    #[test]
    fn test_regex_doesnt_match_no_warning() {
        let exact = create_string_exact(
            "test::exact",
            "bar",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let regex = create_string_regex(
            "test::regex",
            "foo.*",
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_regex_contains_literal(&[exact, regex], &mut warnings);

        // No warning - regex doesn't match literal
        assert_eq!(warnings.len(), 0);
    }

    // ========================================================================
    // Phase 5: Regex Alternative Subset Tests
    // ========================================================================

    #[test]
    fn test_regex_alternative_subset() {
        let regex1 = create_string_regex(
            "test::subset",
            "(read|write)",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let regex2 = create_string_regex(
            "test::superset",
            "(read|write|execute)",
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_regex_alternative_subsets(&[regex1, regex2], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("REGEX ALTERNATIVE SUBSET"));
    }

    #[test]
    fn test_regex_case_insensitive_subsumption() {
        let case_sensitive = create_string_regex(
            "test::sensitive",
            "(password|secret)",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let case_insensitive = create_string_regex(
            "test::insensitive",
            "(PASSWORD|SECRET)",
            true,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_regex_alternative_subsets(&[case_sensitive, case_insensitive], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("REGEX CASE SUBSUMPTION"));
    }

    // ========================================================================
    // Phase 6: Tier Violation Tests
    // ========================================================================

    #[test]
    fn test_tier_violation_detection() {
        let micro = create_symbol_exact(
            "micro-behaviors/fs/file/delete::unlink",
            "unlink",
            vec![FileType::Elf],
            "traits/micro-behaviors/fs/file/delete.yaml",
        );
        let objective = create_symbol_exact(
            "objectives/anti-forensics/cleanup::artifact",
            "unlink",
            vec![FileType::Elf],
            "traits/objectives/anti-forensics/cleanup.yaml",
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[micro, objective], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("TIER VIOLATION"));
        assert!(warnings[0].contains("objectives/ should REFERENCE micro-behaviors/"));
    }

    #[test]
    fn test_no_tier_violation_same_tier() {
        let trait1 = create_symbol_exact(
            "micro-behaviors/fs/file/delete::unlink",
            "unlink",
            vec![FileType::Elf],
            "traits/micro-behaviors/fs/file/delete.yaml",
        );
        let trait2 = create_symbol_exact(
            "micro-behaviors/fs/file/remove::rm",
            "unlink",
            vec![FileType::Elf],
            "traits/micro-behaviors/fs/file/remove.yaml",
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        assert_eq!(warnings.len(), 1);
        // Should NOT contain TIER VIOLATION (both in micro-behaviors)
        assert!(!warnings[0].contains("TIER VIOLATION"));
    }

    // ========================================================================
    // File Type Overlap Tests
    // ========================================================================

    #[test]
    fn test_filetype_overlap_all_vs_specific() {
        let trait1 =
            create_string_exact("test::a", "test", false, vec![FileType::All], "file1.yaml");
        let trait2 =
            create_string_exact("test::b", "test", false, vec![FileType::Elf], "file2.yaml");

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        // Should detect overlap (All overlaps with everything)
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn test_filetype_no_overlap_disjoint() {
        let trait1 =
            create_string_exact("test::a", "test", false, vec![FileType::Elf], "file1.yaml");
        let trait2 =
            create_string_exact("test::b", "test", false, vec![FileType::Pe], "file2.yaml");

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        // No overlap - disjoint file types
        assert_eq!(warnings.len(), 0);
    }

    // ========================================================================
    // Carveout Exception Tests (>2 char diff + conf/crit differs)
    // ========================================================================

    #[test]
    fn test_decode_hex_for_carveout() {
        // Verify hex decoding works as expected
        assert_eq!(decode_hex_escapes("AB"), "AB");
        assert_eq!(decode_hex_escapes("\\x41B"), "AB");
        assert_eq!(decode_hex_escapes("test"), "test");
        assert_eq!(decode_hex_escapes("\\x74est"), "test");
    }

    #[test]
    fn test_simple_duplicate_without_carveout() {
        // Same exact pattern without any carveout -> should warn
        let trait1 = create_test_trait_with_conf_crit(
            "test::a",
            Condition::String {
                exact: Some("duplicate".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::String {
                exact: Some("duplicate".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file2.yaml",
            0.9,
            crate::types::Criticality::Notable,
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        // Should warn - exact duplicate, carveout doesn't apply (len diff = 0)
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Duplicate"));
    }

    #[test]
    fn test_hex_duplicate_without_carveout() {
        // Hex-encoded duplicate with same conf/crit -> should warn
        let trait1 = create_test_trait_with_conf_crit(
            "test::a",
            Condition::String {
                exact: Some("AB".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::String {
                exact: Some("\\x41B".to_string()), // Normalizes to "AB"
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file2.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        // Should warn - normalizes to same pattern, carveout doesn't apply (same conf/crit)
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Duplicate"));
    }

    #[test]
    fn test_carveout_large_pattern_diff_with_conf_diff() {
        // Same normalized pattern "test", but original values differ by >2 chars AND confidence differs by >=0.2 -> NO warning
        let trait1 = create_test_trait_with_conf_crit(
            "test::a",
            Condition::String {
                exact: Some("test".to_string()), // 4 chars
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file1.yaml",
            0.5, // conf = 0.5
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::String {
                exact: Some("\\x74\\x65\\x73\\x74".to_string()), // 16 chars hex-encoded "test" (diff = 12 > 2)
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file2.yaml",
            0.9, // conf = 0.9 (diff = 0.4 >= 0.2)
            crate::types::Criticality::Notable,
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        // Should NOT warn - carveout applies (same normalized "test", but original differs by >2 and conf differs)
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_carveout_large_pattern_diff_with_crit_diff() {
        // Same normalized "data", but original differs by >2 chars AND criticality differs -> NO warning
        let trait1 = create_test_trait_with_conf_crit(
            "test::a",
            Condition::String {
                exact: Some("data".to_string()), // 4 chars
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::String {
                exact: Some("\\x64ata".to_string()), // 7 chars hex-encoded first char (diff = 3 > 2)
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file2.yaml",
            0.8,
            crate::types::Criticality::Hostile, // Different criticality
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        // Should NOT warn - carveout applies
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_carveout_fails_small_pattern_diff() {
        // Identical patterns (0-char diff) with different conf/crit -> should warn
        // Carveout requires BOTH >2 char diff AND conf/crit difference
        let trait1 = create_test_trait_with_conf_crit(
            "test::a",
            Condition::String {
                exact: Some("pattern".to_string()), // 7 chars
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file1.yaml",
            0.5,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::String {
                exact: Some("pattern".to_string()), // 7 chars (diff = 0, not >2)
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file2.yaml",
            0.9, // conf diff = 0.4 >= 0.2 (but pattern diff = 0, so carveout doesn't apply)
            crate::types::Criticality::Notable,
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        // Should WARN - carveout does NOT apply (pattern diff = 0, not >2)
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Duplicate"));
    }

    #[test]
    fn test_carveout_fails_small_conf_diff() {
        // Same normalized "value", original differs by >2 chars BUT confidence diff <0.2 and crit same -> should warn
        let trait1 = create_test_trait_with_conf_crit(
            "test::a",
            Condition::String {
                exact: Some("value".to_string()), // 5 chars
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::String {
                exact: Some("\\x76\\x61lue".to_string()), // 11 chars, first 2 chars hex-encoded (diff = 6 > 2)
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file2.yaml",
            0.9,                                // conf diff = 0.1 < 0.2
            crate::types::Criticality::Notable, // Same criticality
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        // Should WARN - carveout does NOT apply (conf diff <0.2 AND crit same)
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Duplicate"));
    }

    #[test]
    fn test_carveout_multiple_pairs_all_pass() {
        // Three traits, all normalize to "name", all pairs meet carveout criteria -> NO warnings
        let trait1 = create_test_trait_with_conf_crit(
            "test::a",
            Condition::String {
                exact: Some("name".to_string()), // 4 chars
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file1.yaml",
            0.5,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::String {
                exact: Some("\\x6e\\x61me".to_string()), // 11 chars (diff from trait1 = 7 > 2)
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file2.yaml",
            0.9, // conf diff from trait1 = 0.4 >= 0.2
            crate::types::Criticality::Notable,
        );

        let trait3 = create_test_trait_with_conf_crit(
            "test::c",
            Condition::String {
                exact: Some("\\x6e\\x61\\x6d\\x65".to_string()), // 16 chars, all hex-encoded (diff from trait1 = 12, from trait2 = 5 > 2)
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file3.yaml",
            0.5,
            crate::types::Criticality::Hostile, // Different from traits 1 and 2
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2, trait3], &mut warnings);

        // Should NOT warn - all pairs meet carveout criteria
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_carveout_multiple_pairs_one_fails() {
        // Three traits, all normalize to "code", one pair doesn't meet carveout -> should warn
        let trait1 = create_test_trait_with_conf_crit(
            "test::a",
            Condition::String {
                exact: Some("code".to_string()), // 4 chars
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::String {
                exact: Some("\\x63\\x6fde".to_string()), // 11 chars (diff = 7 > 2)
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file2.yaml",
            0.9,                                // conf diff from trait1 = 0.1 < 0.2
            crate::types::Criticality::Notable, // Same as trait1 - FAILS carveout
        );

        let trait3 = create_test_trait_with_conf_crit(
            "test::c",
            Condition::String {
                exact: Some("\\x63\\x6f\\x64\\x65".to_string()), // 16 chars (diff from trait1 = 12 > 2)
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file3.yaml",
            0.5,
            crate::types::Criticality::Hostile, // Different from trait1 - PASSES carveout with trait1
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2, trait3], &mut warnings);

        // Should WARN - trait1 and trait2 don't meet carveout criteria (conf diff <0.2 and same crit)
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Duplicate"));
    }

    // ========================================================================
    // Helper Function Tests
    // ========================================================================

    #[test]
    fn test_extract_tier() {
        assert_eq!(
            extract_tier("micro-behaviors/fs/file/delete::unlink"),
            Some("micro-behaviors")
        );
        assert_eq!(
            extract_tier("objectives/collection/metadata::home-env"),
            Some("objectives")
        );
        assert_eq!(
            extract_tier("well-known/malware/rat::geacon"),
            Some("well-known")
        );
        assert_eq!(
            extract_tier("metadata/format/extension::exe"),
            Some("metadata")
        );

        // Invalid formats
        assert_eq!(extract_tier("invalid-id"), None);
        assert_eq!(extract_tier(""), None);
    }

    // ========================================================================
    // Basename Pattern Duplicate Tests
    // ========================================================================

    #[test]
    fn test_basename_exact_duplicate() {
        let traits = vec![
            create_test_trait(
                "test1",
                Condition::Basename {
                    exact: Some("setup.py".to_string()),
                    substr: None,
                    regex: None,
                    case_insensitive: false,
                    compiled_regex: None,
                },
                vec![FileType::Python],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Basename {
                    exact: Some("setup.py".to_string()),
                    substr: None,
                    regex: None,
                    case_insensitive: false,
                    compiled_regex: None,
                },
                vec![FileType::Python],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        check_basename_pattern_duplicates(&traits, &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Duplicate basename exact pattern 'setup.py'"));
        assert!(warnings[0].contains("test1"));
        assert!(warnings[0].contains("test2"));
    }

    #[test]
    fn test_basename_substr_duplicate() {
        let traits = vec![
            create_test_trait(
                "test1",
                Condition::Basename {
                    exact: None,
                    substr: Some("chrome".to_string()),
                    regex: None,
                    case_insensitive: false,
                    compiled_regex: None,
                },
                vec![FileType::All],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Basename {
                    exact: None,
                    substr: Some("chrome".to_string()),
                    regex: None,
                    case_insensitive: false,
                    compiled_regex: None,
                },
                vec![FileType::All],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        check_basename_pattern_duplicates(&traits, &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Duplicate basename substr pattern 'chrome'"));
    }

    #[test]
    fn test_basename_regex_duplicate() {
        let traits = vec![
            create_test_trait(
                "test1",
                Condition::Basename {
                    exact: None,
                    substr: None,
                    regex: Some("\\.pyc$".to_string()),
                    case_insensitive: false,
                    compiled_regex: None,
                },
                vec![FileType::Python],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Basename {
                    exact: None,
                    substr: None,
                    regex: Some("\\.pyc$".to_string()),
                    case_insensitive: false,
                    compiled_regex: None,
                },
                vec![FileType::Python],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        check_basename_pattern_duplicates(&traits, &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Duplicate basename regex pattern '\\.pyc$'"));
    }

    #[test]
    fn test_basename_regex_should_be_exact() {
        let traits = vec![
            create_test_trait(
                "test1",
                Condition::Basename {
                    exact: None,
                    substr: None,
                    regex: Some("^Makefile$".to_string()),
                    case_insensitive: false,
                    compiled_regex: None,
                },
                vec![FileType::All],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Basename {
                    exact: None,
                    substr: None,
                    regex: Some("^setup\\.py$".to_string()),
                    case_insensitive: false,
                    compiled_regex: None,
                },
                vec![FileType::Python],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        check_basename_pattern_duplicates(&traits, &mut warnings);

        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("is just ^literal$ and should use exact: 'Makefile'"));
        assert!(warnings[1].contains("is just ^literal$ and should use exact: 'setup.py'"));
    }

    #[test]
    fn test_basename_regex_should_be_exact_case_insensitive() {
        let traits = vec![create_test_trait(
            "test1",
            Condition::Basename {
                exact: None,
                substr: None,
                regex: Some("(?i)^setup\\.py$".to_string()),
                case_insensitive: false,
                compiled_regex: None,
            },
            vec![FileType::Python],
            "file1.yaml",
        )];

        let mut warnings = Vec::new();
        check_basename_pattern_duplicates(&traits, &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("should use exact: 'setup.py', case_insensitive: true"));
    }

    #[test]
    fn test_basename_regex_with_metacharacters_not_flagged() {
        let traits = vec![
            create_test_trait(
                "test1",
                Condition::Basename {
                    exact: None,
                    substr: None,
                    regex: Some("^(setup|install)\\.py$".to_string()),
                    case_insensitive: false,
                    compiled_regex: None,
                },
                vec![FileType::Python],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Basename {
                    exact: None,
                    substr: None,
                    regex: Some(".*\\.exe$".to_string()),
                    case_insensitive: false,
                    compiled_regex: None,
                },
                vec![FileType::Pe],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        check_basename_pattern_duplicates(&traits, &mut warnings);

        // Should not flag these as "should be exact" because they have regex metacharacters
        for warning in &warnings {
            assert!(!warning.contains("should use exact"));
        }
    }

    #[test]
    fn test_basename_empty_pattern_skipped() {
        let traits = vec![create_test_trait(
            "test1",
            Condition::Basename {
                exact: None,
                substr: None,
                regex: None,
                case_insensitive: false,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file1.yaml",
        )];

        let mut warnings = Vec::new();
        check_basename_pattern_duplicates(&traits, &mut warnings);

        // Empty basename pattern should be skipped
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_basename_bogus_dot_pattern_skipped() {
        let traits = vec![create_test_trait(
            "test1",
            Condition::Basename {
                exact: None,
                substr: None,
                regex: Some(".".to_string()),
                case_insensitive: false,
                compiled_regex: None,
            },
            vec![FileType::All],
            "file1.yaml",
        )];

        let mut warnings = Vec::new();
        check_basename_pattern_duplicates(&traits, &mut warnings);

        // Bogus "." pattern should be skipped
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_basename_non_basename_conditions_ignored() {
        let traits = vec![
            create_test_trait(
                "test1",
                Condition::String {
                    exact: Some("setup.py".to_string()),
                    substr: None,
                    word: None,
                    regex: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::Python],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Symbol {
                    exact: Some("setup".to_string()),
                    substr: None,
                    regex: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::Python],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        check_basename_pattern_duplicates(&traits, &mut warnings);

        // Non-basename conditions should be ignored
        assert_eq!(warnings.len(), 0);
    }

    // ========================================================================
    // Regex Overlap Tests
    // ========================================================================

    #[test]
    fn test_regex_literal_overlap_same_length_blocked() {
        use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

        let traits = vec![
            create_string_exact(
                "exact_trait",
                "chrome.exe",
                false,
                vec![FileType::Pe],
                "file1.yaml",
            ),
            create_string_regex(
                "regex_trait",
                "chrome\\.exe",
                false,
                vec![FileType::Pe],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        // Same length patterns should trigger warning
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Ambiguous regex overlap"));
    }

    #[test]
    fn test_regex_literal_overlap_33_percent_diff_allowed() {
        use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

        let traits = vec![
            // ".exe" = 4 chars, "7z.exe" = 6 chars
            // Diff: 2/6 = 33.33% -> should be allowed
            create_string_substr(
                "substr_trait",
                ".exe",
                false,
                vec![FileType::Pe],
                "file1.yaml",
            ),
            create_string_regex(
                "regex_trait",
                "7z\\.exe",
                false,
                vec![FileType::Pe],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        // 33% or more difference should be allowed
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_regex_literal_overlap_with_alternation_blocked() {
        use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

        let traits = vec![
            // Even with length difference, alternation should block the exemption
            create_string_exact(
                "exact_trait",
                "chrome.exe",
                false,
                vec![FileType::Pe],
                "file1.yaml",
            ),
            create_string_regex(
                "regex_trait",
                "(chrome\\.exe|firefox\\.exe)",
                false,
                vec![FileType::Pe],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        // Alternation present means no exemption
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Ambiguous regex overlap"));
    }

    #[test]
    fn test_regex_literal_overlap_prefix_blocked() {
        use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

        let traits = vec![
            // "foo" (3 chars) vs "foo.*" (5 chars) = 40% difference
            // BUT "foo" is a prefix of "foo.*", so should still be blocked
            create_string_exact(
                "exact_trait",
                "foo",
                false,
                vec![FileType::All],
                "file1.yaml",
            ),
            create_string_regex(
                "regex_trait",
                "foo.*",
                false,
                vec![FileType::All],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        // Prefix match should be blocked even with >33% length difference
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Ambiguous regex overlap"));
    }

    #[test]
    fn test_regex_literal_overlap_suffix_blocked() {
        use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

        let traits = vec![
            // ".exe" is a suffix of ".*\.exe", should be blocked
            create_string_substr(
                "substr_trait",
                ".exe",
                false,
                vec![FileType::Pe],
                "file1.yaml",
            ),
            create_string_regex(
                "regex_trait",
                ".*\\.exe",
                false,
                vec![FileType::Pe],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        // Suffix match should be blocked
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Ambiguous regex overlap"));
    }

    #[test]
    fn test_regex_literal_overlap_different_criticality_allowed() {
        use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

        let traits = vec![
            create_test_trait_with_conf_crit(
                "exact_notable",
                Condition::String {
                    exact: Some("malware.exe".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::Pe],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "regex_hostile",
                Condition::String {
                    exact: None,
                    substr: None,
                    regex: Some("malware\\.exe".to_string()),
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::Pe],
                "file2.yaml",
                1.0,
                crate::types::Criticality::Hostile,
            ),
        ];

        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        // Different criticality should be allowed
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_regex_regex_overlap_with_length_diff_allowed() {
        use crate::capabilities::validation::duplicates::check_overlapping_regex_patterns;

        let traits = vec![
            // Both regexes, >33% length difference, one has no alternation
            create_string_regex(
                "regex_short",
                "\\.exe$",
                false,
                vec![FileType::Pe],
                "file1.yaml",
            ),
            create_string_regex(
                "regex_long",
                "7z\\.exe$",
                false,
                vec![FileType::Pe],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        check_overlapping_regex_patterns(&traits, &mut warnings);

        // Should be allowed due to length difference and no alternation
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_regex_regex_overlap_both_alternation_checked() {
        use crate::capabilities::validation::duplicates::check_overlapping_regex_patterns;

        let traits = vec![
            // Both have alternation and share alternatives
            create_string_regex(
                "regex_a",
                "(chrome\\.exe|firefox\\.exe)",
                false,
                vec![FileType::Pe],
                "file1.yaml",
            ),
            create_string_regex(
                "regex_b",
                "(firefox\\.exe|safari\\.exe)",
                false,
                vec![FileType::Pe],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        check_overlapping_regex_patterns(&traits, &mut warnings);

        // Should warn about shared alternative "firefox.exe"
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Overlapping regex patterns"));
    }

    #[test]
    fn test_regex_regex_one_alternation_length_diff_allowed() {
        use crate::capabilities::validation::duplicates::check_overlapping_regex_patterns;

        let traits = vec![
            // One has alternation, but >33% length difference
            create_string_regex(
                "regex_simple",
                "\\.exe",
                false,
                vec![FileType::Pe],
                "file1.yaml",
            ),
            create_string_regex(
                "regex_alternation",
                "(chrome\\.exe|firefox\\.exe|safari\\.exe)",
                false,
                vec![FileType::Pe],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        check_overlapping_regex_patterns(&traits, &mut warnings);

        // Should be allowed: >33% diff and one has no alternation
        assert_eq!(warnings.len(), 0);
    }

    // ========================================================================
    // Criticality Equivalence Tests
    // ========================================================================

    #[test]
    fn test_criticalities_equivalent_inert_levels() {
        use crate::capabilities::validation::duplicates::criticalities_equivalent;
        use crate::types::Criticality;

        // Component, Baseline, and Filtered should all be equivalent
        assert!(criticalities_equivalent(
            Criticality::Component,
            Criticality::Baseline
        ));
        assert!(criticalities_equivalent(
            Criticality::Baseline,
            Criticality::Component
        ));
        assert!(criticalities_equivalent(
            Criticality::Filtered,
            Criticality::Baseline
        ));
        assert!(criticalities_equivalent(
            Criticality::Filtered,
            Criticality::Component
        ));
        assert!(criticalities_equivalent(
            Criticality::Component,
            Criticality::Filtered
        ));

        // Same level is always equivalent
        assert!(criticalities_equivalent(
            Criticality::Component,
            Criticality::Component
        ));
        assert!(criticalities_equivalent(
            Criticality::Baseline,
            Criticality::Baseline
        ));
        assert!(criticalities_equivalent(
            Criticality::Filtered,
            Criticality::Filtered
        ));
    }

    #[test]
    fn test_criticalities_equivalent_distinct_levels() {
        use crate::capabilities::validation::duplicates::criticalities_equivalent;
        use crate::types::Criticality;

        // Notable, Suspicious, Hostile should be distinct from each other and from inert levels
        assert!(!criticalities_equivalent(
            Criticality::Notable,
            Criticality::Baseline
        ));
        assert!(!criticalities_equivalent(
            Criticality::Notable,
            Criticality::Component
        ));
        assert!(!criticalities_equivalent(
            Criticality::Suspicious,
            Criticality::Baseline
        ));
        assert!(!criticalities_equivalent(
            Criticality::Hostile,
            Criticality::Baseline
        ));

        assert!(!criticalities_equivalent(
            Criticality::Notable,
            Criticality::Suspicious
        ));
        assert!(!criticalities_equivalent(
            Criticality::Notable,
            Criticality::Hostile
        ));
        assert!(!criticalities_equivalent(
            Criticality::Suspicious,
            Criticality::Hostile
        ));

        // Same level is equivalent
        assert!(criticalities_equivalent(
            Criticality::Notable,
            Criticality::Notable
        ));
        assert!(criticalities_equivalent(
            Criticality::Suspicious,
            Criticality::Suspicious
        ));
        assert!(criticalities_equivalent(
            Criticality::Hostile,
            Criticality::Hostile
        ));
    }

    // ========================================================================
    // Atomic Logic Duplicates Tests
    // ========================================================================

    #[test]
    fn test_atomic_logic_duplicates_same_logic_different_crit() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

        let traits = vec![
            create_test_trait_with_conf_crit(
                "trait_notable",
                Condition::String {
                    exact: Some("malicious_pattern".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::Elf],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_hostile",
                Condition::String {
                    exact: Some("malicious_pattern".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::Elf],
                "file2.yaml",
                1.0,
                crate::types::Criticality::Hostile,
            ),
        ];

        let duplicates = find_atomic_logic_duplicates(&traits);
        assert_eq!(duplicates.len(), 1);
        assert!(duplicates[0].2.contains("crit:"));
    }

    #[test]
    fn test_atomic_logic_duplicates_same_logic_different_conf() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

        let traits = vec![
            create_test_trait_with_conf_crit(
                "trait_low_conf",
                Condition::String {
                    exact: Some("test_pattern".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::Shell],
                "file1.yaml",
                0.5,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_high_conf",
                Condition::String {
                    exact: Some("test_pattern".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::Shell],
                "file2.yaml",
                0.9,
                crate::types::Criticality::Notable,
            ),
        ];

        let duplicates = find_atomic_logic_duplicates(&traits);
        assert_eq!(duplicates.len(), 1);
        assert!(duplicates[0].2.contains("conf:"));
    }

    #[test]
    fn test_atomic_logic_duplicates_overlapping_for_types() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

        // Same pattern, overlapping file types (both include Elf), different crit
        let traits = vec![
            create_test_trait_with_conf_crit(
                "trait_elf_macho",
                Condition::String {
                    exact: Some("shared_pattern".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::Elf, FileType::Macho],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_elf_pe",
                Condition::String {
                    exact: Some("shared_pattern".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::Elf, FileType::Pe],
                "file2.yaml",
                1.0,
                crate::types::Criticality::Hostile,
            ),
        ];

        let duplicates = find_atomic_logic_duplicates(&traits);
        // Should flag: same logic, overlapping types (Elf), different crit
        assert_eq!(duplicates.len(), 1);
    }

    #[test]
    fn test_atomic_logic_duplicates_no_overlap_no_warning() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

        // Same pattern but disjoint file types - no warning
        let traits = vec![
            create_test_trait_with_conf_crit(
                "trait_macho",
                Condition::String {
                    exact: Some("platform_pattern".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::Macho],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_pe",
                Condition::String {
                    exact: Some("platform_pattern".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::Pe],
                "file2.yaml",
                1.0,
                crate::types::Criticality::Hostile,
            ),
        ];

        let duplicates = find_atomic_logic_duplicates(&traits);
        // No overlap in file types, so no warning even with different crit
        assert_eq!(duplicates.len(), 0);
    }

    #[test]
    fn test_atomic_logic_duplicates_inert_crit_equivalent() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

        // Component vs Baseline should NOT trigger a warning (they're equivalent)
        let traits = vec![
            create_test_trait_with_conf_crit(
                "trait_component",
                Condition::String {
                    exact: Some("building_block".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::All],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Component,
            ),
            create_test_trait_with_conf_crit(
                "trait_baseline",
                Condition::String {
                    exact: Some("building_block".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::All],
                "file2.yaml",
                1.0,
                crate::types::Criticality::Baseline,
            ),
        ];

        let duplicates = find_atomic_logic_duplicates(&traits);
        // Component and Baseline are equivalent, same conf, so no warning
        assert_eq!(duplicates.len(), 0);
    }

    #[test]
    fn test_atomic_logic_duplicates_different_logic_no_warning() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

        // Different patterns - no warning even with same metadata
        let traits = vec![
            create_test_trait_with_conf_crit(
                "trait_a",
                Condition::String {
                    exact: Some("pattern_a".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::All],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_b",
                Condition::String {
                    exact: Some("pattern_b".to_string()),
                    substr: None,
                    regex: None,
                    word: None,
                    case_insensitive: false,
                    external_ip: false,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
                    platforms: None,
                    compiled_regex: None,
                },
                vec![FileType::All],
                "file2.yaml",
                1.0,
                crate::types::Criticality::Hostile,
            ),
        ];

        let duplicates = find_atomic_logic_duplicates(&traits);
        // Different logic, so no warning
        assert_eq!(duplicates.len(), 0);
    }
}

#[cfg(test)]
mod composite_tests {
    // Composite validation tests would go here
    // Tests from original validation.rs lines ~4800-5200
}

#[cfg(test)]
mod pattern_tests {
    use super::super::patterns::find_non_capturing_groups;
    use crate::composite_rules::{Arch, Condition, FileType, Platform, TraitDefinition};
    use std::path::PathBuf;

    fn create_raw_regex_trait(id: &str, pattern: &str) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test trait".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            mbc: None,
            attack: None,
            r#if: Condition::Raw {
                exact: None,
                substr: None,
                regex: Some(pattern.to_string()),
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                compiled_regex: None,
            },
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            r#for: vec![FileType::All],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            size_min: None,
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }
    }

    #[test]
    fn test_non_capturing_group_detected() {
        let traits = vec![create_raw_regex_trait("test-noncap", r"(?:foo|bar)baz")];
        let mut warnings = Vec::new();
        find_non_capturing_groups(&traits, &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("non-capturing group"));
        assert!(warnings[0].contains("test-noncap"));
    }

    #[test]
    fn test_regular_group_no_warning() {
        let traits = vec![create_raw_regex_trait("test-cap", r"(foo|bar)baz")];
        let mut warnings = Vec::new();
        find_non_capturing_groups(&traits, &mut warnings);

        assert!(warnings.is_empty());
    }

    #[test]
    fn test_no_group_no_warning() {
        let traits = vec![create_raw_regex_trait("test-nogroup", r"foobarbaz")];
        let mut warnings = Vec::new();
        find_non_capturing_groups(&traits, &mut warnings);

        assert!(warnings.is_empty());
    }
}

#[cfg(test)]
mod taxonomy_tests {
    use crate::capabilities::validation::taxonomy::{
        find_cap_obj_violations, find_cap_wellknown_violations, find_metadata_cross_tier_refs,
    };
    use crate::composite_rules::traits::CompositeTrait;
    use crate::composite_rules::{Arch, Condition, FileType, Platform, TraitDefinition};
    use crate::types::Criticality;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn make_trait(id: &str, ref_id: &str) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            r#if: Condition::Trait {
                id: ref_id.to_string(),
            },
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }
    }

    fn make_composite(id: &str, all_refs: &[&str]) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            size_min: None,
            size_max: None,
            all: Some(
                all_refs
                    .iter()
                    .map(|r| Condition::Trait { id: r.to_string() })
                    .collect(),
            ),
            any: None,
            none: None,
            unless: None,
            not: None,
            downgrade: None,
            needs: None,
            near_lines: None,
            near_bytes: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }
    }

    // ---- metadata cross-tier refs ----

    #[test]
    fn test_metadata_referencing_cap_is_violation() {
        let traits = vec![make_trait(
            "metadata/format/suspicious",
            "micro-behaviors/crypto/aes",
        )];
        let composites = vec![];
        let sources = HashMap::new();
        let v = find_metadata_cross_tier_refs(&traits, &composites, &sources);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, "micro-behaviors/crypto/aes");
    }

    #[test]
    fn test_metadata_referencing_objectives_is_violation() {
        let composites = vec![make_composite(
            "metadata/format/bad",
            &["objectives/impact/encrypt"],
        )];
        let sources = HashMap::new();
        let v = find_metadata_cross_tier_refs(&[], &composites, &sources);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, "objectives/impact/encrypt");
    }

    #[test]
    fn test_metadata_referencing_wellknown_is_violation() {
        let composites = vec![make_composite(
            "metadata/format/bad",
            &["well-known/malware/emotet/loader"],
        )];
        let sources = HashMap::new();
        let v = find_metadata_cross_tier_refs(&[], &composites, &sources);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn test_metadata_referencing_metadata_is_ok() {
        let traits = vec![make_trait(
            "metadata/format/composite",
            "metadata/format/elf",
        )];
        let composites = vec![make_composite(
            "metadata/quality/check",
            &["metadata/format/elf", "metadata/language/go"],
        )];
        let sources = HashMap::new();
        let v = find_metadata_cross_tier_refs(&traits, &composites, &sources);
        assert!(v.is_empty(), "metadata → metadata should be allowed");
    }

    // ---- micro-behaviors → well-known ----

    #[test]
    fn test_cap_referencing_wellknown_is_violation() {
        let traits = vec![make_trait(
            "micro-behaviors/crypto/known-malware",
            "well-known/malware/emotet/loader",
        )];
        let sources = HashMap::new();
        let v = find_cap_wellknown_violations(&traits, &[], &sources);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, "well-known/malware/emotet/loader");
    }

    #[test]
    fn test_cap_composite_referencing_wellknown_is_violation() {
        let composites = vec![make_composite(
            "micro-behaviors/net/suspicious",
            &[
                "micro-behaviors/net/http-post",
                "well-known/tools/cobalt-strike/beacon",
            ],
        )];
        let sources = HashMap::new();
        let v = find_cap_wellknown_violations(&[], &composites, &sources);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn test_cap_referencing_cap_and_metadata_is_ok() {
        let traits = vec![make_trait(
            "micro-behaviors/crypto/aes",
            "micro-behaviors/crypto/symmetric",
        )];
        let composites = vec![make_composite(
            "micro-behaviors/net/http",
            &["micro-behaviors/net/socket", "metadata/format/elf"],
        )];
        let sources = HashMap::new();
        let v = find_cap_wellknown_violations(&traits, &composites, &sources);
        assert!(
            v.is_empty(),
            "cap → cap and cap → metadata should be allowed"
        );
    }

    // ---- existing: micro-behaviors → objectives ----

    #[test]
    fn test_cap_referencing_objectives_is_violation() {
        let traits = vec![make_trait(
            "micro-behaviors/process/shell",
            "objectives/execution/reverse-shell",
        )];
        let sources = HashMap::new();
        let v = find_cap_obj_violations(&traits, &[], &sources);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn test_objectives_referencing_cap_is_ok() {
        let composites = vec![make_composite(
            "objectives/c2/reverse-shell",
            &["micro-behaviors/net/socket", "micro-behaviors/process/exec"],
        )];
        let sources = HashMap::new();
        let v = find_cap_obj_violations(&[], &composites, &sources);
        assert!(
            v.is_empty(),
            "objectives → cap is the normal direction and should be allowed"
        );
    }
}

#[cfg(test)]
mod constraint_tests {
    use crate::capabilities::validation::constraints::{
        find_empty_condition_clauses, find_needs_zero, find_none_only_with_proximity,
        find_pure_alias_traits,
    };
    use crate::composite_rules::{
        Arch, CompositeTrait, Condition, FileType, Platform, TraitDefinition,
    };
    use crate::types::Criticality;
    use std::path::PathBuf;

    /// Helper to create a trait with a trait reference condition
    fn create_trait_ref(
        id: &str,
        ref_id: &str,
        crit: Criticality,
        count_min: Option<usize>,
        has_downgrade: bool,
    ) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test trait".to_string(),
            conf: 1.0,
            crit,
            mbc: None,
            attack: None,
            r#if: Condition::Trait {
                id: ref_id.to_string(),
            },
            size_min: None,
            size_max: None,
            count_min,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            r#for: vec![FileType::All],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: if has_downgrade {
                Some(crate::composite_rules::DowngradeConditions {
                    any: Some(vec![Condition::Trait {
                        id: "some-other-trait".to_string(),
                    }]),
                    all: None,
                    none: None,
                    needs: None,
                })
            } else {
                None
            },
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }
    }

    /// Helper to create a base trait (not a reference)
    fn create_base_trait(id: &str, crit: Criticality) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "base trait".to_string(),
            conf: 1.0,
            crit,
            mbc: None,
            attack: None,
            r#if: Condition::String {
                exact: Some("test".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
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
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            r#for: vec![FileType::All],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            size_min: None,
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }
    }

    #[test]
    fn test_pure_alias_detected() {
        // Trait A references Trait B with same criticality and no constraints
        let base = create_base_trait("micro-behaviors/test::base", Criticality::Notable);
        let alias = create_trait_ref(
            "objectives/test::alias",
            "micro-behaviors/test::base",
            Criticality::Notable, // Same as base
            None,                 // No count_min
            false,                // No downgrade
        );

        let traits = vec![base, alias];
        let violations = find_pure_alias_traits(&traits);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "objectives/test::alias");
        assert_eq!(violations[0].1, "micro-behaviors/test::base");
    }

    #[test]
    fn test_criticality_change_not_flagged() {
        // Trait A references Trait B but changes criticality - this adds value
        let base = create_base_trait("micro-behaviors/test::base", Criticality::Baseline);
        let alias = create_trait_ref(
            "objectives/test::upgraded",
            "micro-behaviors/test::base",
            Criticality::Suspicious, // Different from base
            None,
            false,
        );

        let traits = vec![base, alias];
        let violations = find_pure_alias_traits(&traits);

        assert!(violations.is_empty(), "Should not flag criticality changes");
    }

    #[test]
    fn test_count_constraint_not_flagged() {
        // Trait A references Trait B with count_min - this adds value
        let base = create_base_trait("micro-behaviors/test::base", Criticality::Notable);
        let alias = create_trait_ref(
            "objectives/test::with-count",
            "micro-behaviors/test::base",
            Criticality::Notable,
            Some(5), // Has count_min constraint
            false,
        );

        let traits = vec![base, alias];
        let violations = find_pure_alias_traits(&traits);

        assert!(
            violations.is_empty(),
            "Should not flag traits with count constraints"
        );
    }

    #[test]
    fn test_downgrade_not_flagged() {
        // Trait A references Trait B with downgrade - this adds value
        let base = create_base_trait("micro-behaviors/test::base", Criticality::Notable);
        let alias = create_trait_ref(
            "objectives/test::with-downgrade",
            "micro-behaviors/test::base",
            Criticality::Notable,
            None,
            true, // Has downgrade
        );

        let traits = vec![base, alias];
        let violations = find_pure_alias_traits(&traits);

        assert!(
            violations.is_empty(),
            "Should not flag traits with downgrade"
        );
    }

    #[test]
    fn test_self_reference_not_flagged() {
        // Trait references itself - this is a different bug, not a pure alias
        let self_ref = create_trait_ref(
            "micro-behaviors/test::self-ref",
            "micro-behaviors/test::self-ref", // Same ID
            Criticality::Notable,
            None,
            false,
        );

        let traits = vec![self_ref];
        let violations = find_pure_alias_traits(&traits);

        assert!(violations.is_empty(), "Should not flag self-references");
    }

    #[test]
    fn test_short_ref_not_flagged() {
        // Short reference without :: or / should not be flagged
        let base = create_base_trait("micro-behaviors/test::base", Criticality::Notable);
        let short_ref = create_trait_ref(
            "objectives/test::short-ref",
            "base", // Short reference (no :: or /)
            Criticality::Notable,
            None,
            false,
        );

        let traits = vec![base, short_ref];
        let violations = find_pure_alias_traits(&traits);

        assert!(violations.is_empty(), "Should not flag short references");
    }

    #[test]
    fn test_external_ref_not_flagged() {
        // Reference to trait not in our list - can't compare, don't flag
        let alias = create_trait_ref(
            "objectives/test::external-ref",
            "some-external/trait::not-in-list",
            Criticality::Notable,
            None,
            false,
        );

        let traits = vec![alias];
        let violations = find_pure_alias_traits(&traits);

        assert!(
            violations.is_empty(),
            "Should not flag references to unknown traits"
        );
    }

    #[test]
    fn test_multiple_violations() {
        // Multiple pure aliases should all be detected
        let base1 = create_base_trait("micro-behaviors/a::base1", Criticality::Notable);
        let base2 = create_base_trait("micro-behaviors/b::base2", Criticality::Suspicious);

        let alias1 = create_trait_ref(
            "objectives/a::alias1",
            "micro-behaviors/a::base1",
            Criticality::Notable,
            None,
            false,
        );
        let alias2 = create_trait_ref(
            "objectives/b::alias2",
            "micro-behaviors/b::base2",
            Criticality::Suspicious,
            None,
            false,
        );

        let traits = vec![base1, base2, alias1, alias2];
        let violations = find_pure_alias_traits(&traits);

        assert_eq!(violations.len(), 2);
    }

    #[test]
    fn test_kv_exists_with_exact_is_flagged() {
        use crate::capabilities::validation::constraints::find_kv_exists_with_matcher;

        let traits = vec![TraitDefinition {
            id: "test/kv-redundant".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            r#if: Condition::Kv {
                path: "scripts.postinstall".to_string(),
                exact: Some("curl".to_string()),
                substr: None,
                regex: None,
                case_insensitive: false,
                exists: Some(false),
                size_min: None,
                size_max: None,
                compiled_regex: None,
            },
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            r#for: vec![FileType::All],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }];

        let v = find_kv_exists_with_matcher(&traits, &[]);
        assert_eq!(v.len(), 1, "exists: false + exact should be flagged");
    }

    #[test]
    fn test_kv_exists_without_matcher_is_ok() {
        use crate::capabilities::validation::constraints::find_kv_exists_with_matcher;

        let traits = vec![TraitDefinition {
            id: "test/kv-ok".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            r#if: Condition::Kv {
                path: "scripts.postinstall".to_string(),
                exact: None,
                substr: None,
                regex: None,
                case_insensitive: false,
                exists: Some(false),
                size_min: None,
                size_max: None,
                compiled_regex: None,
            },
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            r#for: vec![FileType::All],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }];

        let v = find_kv_exists_with_matcher(&traits, &[]);
        assert!(v.is_empty(), "exists: false without matcher is valid");
    }

    #[test]
    fn test_none_only_with_proximity_is_flagged() {
        let rules = vec![CompositeTrait {
            id: "test/none-prox".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            none: Some(vec![Condition::Trait {
                id: "some-trait".to_string(),
            }]),
            unless: None,
            not: None,
            downgrade: None,
            needs: None,
            near_lines: Some(10),
            near_bytes: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }];
        let result = find_none_only_with_proximity(&rules);
        assert_eq!(result, vec!["test/none-prox"]);
    }

    #[test]
    fn test_none_with_all_and_proximity_is_ok() {
        let rules = vec![CompositeTrait {
            id: "test/none-plus-all".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            size_min: None,
            size_max: None,
            all: Some(vec![Condition::Trait {
                id: "some-trait".to_string(),
            }]),
            any: None,
            none: Some(vec![Condition::Trait {
                id: "other-trait".to_string(),
            }]),
            unless: None,
            not: None,
            downgrade: None,
            needs: None,
            near_lines: Some(10),
            near_bytes: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }];
        let result = find_none_only_with_proximity(&rules);
        assert!(result.is_empty());
    }

    #[test]
    fn test_empty_all_with_none_is_flagged() {
        // all: [] + none: [something] should still be flagged — empty all vacuously matches
        let rules = vec![CompositeTrait {
            id: "test/empty-all-none".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            size_min: None,
            size_max: None,
            all: Some(vec![]),
            any: None,
            none: Some(vec![Condition::Trait {
                id: "some-trait".to_string(),
            }]),
            unless: None,
            not: None,
            downgrade: None,
            needs: None,
            near_lines: None,
            near_bytes: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }];
        let result = find_empty_condition_clauses(&rules);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ("test/empty-all-none".to_string(), "all"));
    }

    #[test]
    fn test_needs_zero_is_flagged() {
        let rules = vec![CompositeTrait {
            id: "test/needs-zero".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: Some(vec![Condition::Trait {
                id: "some-trait".to_string(),
            }]),
            none: None,
            unless: None,
            not: None,
            downgrade: None,
            needs: Some(0),
            near_lines: None,
            near_bytes: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }];
        let result = find_needs_zero(&rules);
        assert_eq!(result, vec!["test/needs-zero"]);
    }

    #[test]
    fn test_needs_one_is_not_flagged_by_needs_zero() {
        let rules = vec![CompositeTrait {
            id: "test/needs-one".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: Some(vec![Condition::Trait {
                id: "some-trait".to_string(),
            }]),
            none: None,
            unless: None,
            not: None,
            downgrade: None,
            needs: Some(1),
            near_lines: None,
            near_bytes: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }];
        let result = find_needs_zero(&rules);
        assert!(result.is_empty());
    }
}

#[cfg(test)]
mod autoprefix_tests {
    use super::super::composite::{autoprefix_trait_refs, collect_trait_refs_from_rule};
    use crate::composite_rules::condition::Condition;
    use crate::composite_rules::traits::{CompositeTrait, DowngradeConditions};
    use crate::composite_rules::types::{Arch, FileType, Platform};
    use crate::types::Criticality;

    fn make_rule(
        unless: Option<Vec<Condition>>,
        downgrade: Option<DowngradeConditions>,
    ) -> CompositeTrait {
        CompositeTrait {
            id: "test/rule".to_string(),
            desc: "Test".to_string(),
            conf: 1.0,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless,
            not: None,
            downgrade,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
        }
    }

    #[test]
    fn test_autoprefix_unless_refs() {
        let mut rule = make_rule(
            Some(vec![Condition::Trait {
                id: "local-trait".to_string(),
            }]),
            None,
        );

        autoprefix_trait_refs(&mut rule, "my-prefix");

        match &rule.unless.unwrap()[0] {
            Condition::Trait { id } => {
                assert_eq!(id, "my-prefix::local-trait");
            }
            _ => panic!("Expected Trait condition"),
        }
    }

    #[test]
    fn test_autoprefix_downgrade_refs() {
        let mut rule = make_rule(
            None,
            Some(DowngradeConditions {
                all: Some(vec![Condition::Trait {
                    id: "all-local".to_string(),
                }]),
                any: Some(vec![Condition::Trait {
                    id: "any-local".to_string(),
                }]),
                none: Some(vec![Condition::Trait {
                    id: "none-local".to_string(),
                }]),
                needs: None,
            }),
        );

        autoprefix_trait_refs(&mut rule, "pfx");

        let dg = rule.downgrade.unwrap();
        match &dg.all.unwrap()[0] {
            Condition::Trait { id } => assert_eq!(id, "pfx::all-local"),
            _ => panic!("Expected Trait"),
        }
        match &dg.any.unwrap()[0] {
            Condition::Trait { id } => assert_eq!(id, "pfx::any-local"),
            _ => panic!("Expected Trait"),
        }
        match &dg.none.unwrap()[0] {
            Condition::Trait { id } => assert_eq!(id, "pfx::none-local"),
            _ => panic!("Expected Trait"),
        }
    }

    #[test]
    fn test_collect_refs_includes_unless_and_downgrade() {
        let rule = make_rule(
            Some(vec![Condition::Trait {
                id: "unless-ref".to_string(),
            }]),
            Some(DowngradeConditions {
                all: None,
                any: Some(vec![Condition::Trait {
                    id: "dg-any-ref".to_string(),
                }]),
                none: Some(vec![Condition::Trait {
                    id: "dg-none-ref".to_string(),
                }]),
                needs: None,
            }),
        );

        let refs = collect_trait_refs_from_rule(&rule);
        let ids: Vec<&str> = refs.iter().map(|(id, _)| id.as_str()).collect();
        assert!(ids.contains(&"unless-ref"));
        assert!(ids.contains(&"dg-any-ref"));
        assert!(ids.contains(&"dg-none-ref"));
    }
}

#[cfg(test)]
mod orphan_tests {
    use crate::capabilities::validation::constraints::find_orphaned_components;
    use crate::composite_rules::traits::{CompositeTrait, DowngradeConditions};
    use crate::composite_rules::{Arch, Condition, FileType, Platform, TraitDefinition};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn make_component_trait(id: &str) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "component".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Component,
            mbc: None,
            attack: None,
            r#if: Condition::String {
                exact: Some("test".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                not: None,
                platforms: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                compiled_regex: None,
            },
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            r#for: vec![FileType::All],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yml"),
            precision: None,
        }
    }

    fn make_composite(
        id: &str,
        all_conditions: Vec<Condition>,
        downgrade: Option<DowngradeConditions>,
    ) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "composite".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Suspicious,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            size_min: None,
            size_max: None,
            all: Some(all_conditions),
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade,
            defined_in: PathBuf::from("test.yml"),
            precision: None,
        }
    }

    #[test]
    fn test_find_orphaned_includes_downgrade_none() {
        // Component referenced ONLY in downgrade.none: should NOT be orphaned
        let trait_defs = vec![make_component_trait("test::comp-none-ref")];
        let composites = vec![make_composite(
            "test::my-composite",
            vec![Condition::Trait {
                id: "some-other".to_string(),
            }],
            Some(DowngradeConditions {
                all: None,
                any: None,
                none: Some(vec![Condition::Trait {
                    id: "test::comp-none-ref".to_string(),
                }]),
                needs: None,
            }),
        )];

        let source_files: HashMap<String, String> = HashMap::new();
        let orphans = find_orphaned_components(&trait_defs, &composites, &source_files);
        let orphan_ids: Vec<&str> = orphans.iter().map(|(id, _)| id.as_str()).collect();

        assert!(
            !orphan_ids.contains(&"test::comp-none-ref"),
            "Component referenced in downgrade.none should NOT be orphaned, but got orphans: {:?}",
            orphan_ids
        );
    }
}

#[cfg(test)]
mod excessive_file_types_tests {
    use crate::capabilities::validation::constraints::find_excessive_file_types;
    use crate::composite_rules::{
        Arch, CompositeTrait, Condition, FileType, Platform, TraitDefinition,
    };
    use crate::types::Criticality;
    use std::path::PathBuf;

    fn trait_with_for(id: &str, types: Vec<FileType>) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            r#if: Condition::String {
                exact: Some("test".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                external_ip: false,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
                platforms: None,
                compiled_regex: None,
            },
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            r#for: types,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        }
    }

    #[test]
    fn test_under_threshold_not_flagged() {
        let traits = vec![trait_with_for(
            "test::few-types",
            vec![FileType::Elf, FileType::Macho, FileType::Pe],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_exactly_threshold_flagged() {
        // 7 types that don't form a canonical group — must be flagged
        let traits = vec![trait_with_for(
            "test::seven-types",
            vec![
                FileType::Elf,
                FileType::Macho,
                FileType::Pe,
                FileType::Dylib,
                FileType::So,
                FileType::Dll,
                FileType::Python, // not the canonical `binaries` set
            ],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "test::seven-types");
        assert_eq!(result[0].1, 7);
    }

    #[test]
    fn test_all_exempt() {
        let traits = vec![trait_with_for("test::all-types", vec![FileType::All])];
        let result = find_excessive_file_types(&traits, &[]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_exact_binaries_group_exempt() {
        // Exact `binaries` expansion must not be flagged — the author used `for: [binaries]`
        // and the parser expanded it; we should not warn them to do what they already did.
        let traits = vec![trait_with_for(
            "test::all-binaries",
            vec![
                FileType::Elf,
                FileType::Macho,
                FileType::Pe,
                FileType::Dylib,
                FileType::So,
                FileType::Dll,
                FileType::Class,
                FileType::Pyc,
            ],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert!(
            result.is_empty(),
            "exact `binaries` expansion should not warn"
        );
    }

    #[test]
    fn test_exact_scripts_group_exempt() {
        // Exact `scripts` expansion must not be flagged.
        let traits = vec![trait_with_for(
            "test::all-scripts",
            vec![
                FileType::Shell,
                FileType::Batch,
                FileType::Python,
                FileType::JavaScript,
                FileType::Ruby,
                FileType::Php,
                FileType::Perl,
                FileType::Lua,
                FileType::PowerShell,
                FileType::AppleScript,
            ],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert!(
            result.is_empty(),
            "exact `scripts` expansion should not warn"
        );
    }

    #[test]
    fn test_exact_source_group_exempt() {
        let traits = vec![trait_with_for(
            "test::all-source",
            vec![
                FileType::TypeScript,
                FileType::Rust,
                FileType::Java,
                FileType::C,
                FileType::Cpp,
                FileType::Go,
                FileType::CSharp,
                FileType::Swift,
                FileType::ObjectiveC,
                FileType::Groovy,
                FileType::Kotlin,
                FileType::Scala,
                FileType::Zig,
                FileType::Elixir,
                FileType::Vbs,
            ],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert!(
            result.is_empty(),
            "exact `source` expansion should not warn"
        );
    }

    #[test]
    fn test_subset_of_source_suggests_source() {
        // All types are within `source` but not the exact canonical set → suggest `source`
        let traits = vec![trait_with_for(
            "test::some-source",
            vec![
                FileType::TypeScript,
                FileType::Rust,
                FileType::Java,
                FileType::C,
                FileType::Cpp,
                FileType::Go,
                FileType::CSharp,
            ],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert_eq!(result.len(), 1);
        assert!(result[0].2.contains("source"));
    }

    #[test]
    fn test_mixed_types_suggest_all() {
        // Mix spanning multiple groups → suggest `all`
        let traits = vec![trait_with_for(
            "test::mixed",
            vec![
                FileType::Elf,
                FileType::Macho,
                FileType::Pe,
                FileType::Python,
                FileType::Shell,
                FileType::Ruby,
                FileType::Rust,
            ],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert_eq!(result.len(), 1);
        assert!(result[0].2.contains("all"));
    }

    #[test]
    fn test_multi_group_union_exempt() {
        // `for: [scripts, binaries, source]` in YAML expands to 33 concrete types.
        // The validator must not re-warn the author to use groups they already used.
        let scripts = vec![
            FileType::Shell,
            FileType::Batch,
            FileType::Python,
            FileType::JavaScript,
            FileType::Ruby,
            FileType::Php,
            FileType::Perl,
            FileType::Lua,
            FileType::PowerShell,
            FileType::AppleScript,
        ];
        let binaries = vec![
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
            FileType::Dylib,
            FileType::So,
            FileType::Dll,
            FileType::Class,
            FileType::Pyc,
        ];
        let source = vec![
            FileType::TypeScript,
            FileType::Rust,
            FileType::Java,
            FileType::C,
            FileType::Cpp,
            FileType::Go,
            FileType::CSharp,
            FileType::Swift,
            FileType::ObjectiveC,
            FileType::Groovy,
            FileType::Kotlin,
            FileType::Scala,
            FileType::Zig,
            FileType::Elixir,
            FileType::Vbs,
        ];
        let combined: Vec<FileType> = scripts.into_iter().chain(binaries).chain(source).collect();
        assert_eq!(combined.len(), 33);
        let traits = vec![trait_with_for("test::multi-group", combined)];
        let result = find_excessive_file_types(&traits, &[]);
        assert!(
            result.is_empty(),
            "union of complete named groups should not be flagged"
        );
    }

    #[test]
    fn test_partial_group_still_flagged() {
        // Cherry-picking types from multiple groups (not complete groups) must still warn.
        // [elf, macho, pe] is a partial binaries group; [python, shell] is partial scripts.
        let traits = vec![trait_with_for(
            "test::partial-groups",
            vec![
                FileType::Elf,
                FileType::Macho,
                FileType::Pe,
                FileType::Python,
                FileType::Shell,
                FileType::Ruby,
                FileType::Rust,
            ],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert_eq!(result.len(), 1, "partial group selection should still warn");
    }

    #[test]
    fn test_composite_rule_flagged() {
        let rule = CompositeTrait {
            id: "test::composite-many".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![
                FileType::Elf,
                FileType::Macho,
                FileType::Pe,
                FileType::Dylib,
                FileType::So,
                FileType::Dll,
                FileType::Python, // not the canonical `binaries` set
            ],
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            needs: None,
            none: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
        };
        let result = find_excessive_file_types(&[], &[rule]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "test::composite-many");
        assert!(result[0].3); // is_composite
    }
}

mod defaults_tests {
    use crate::capabilities::models::{RawCompositeRule, RawTraitDefinition, TraitDefaults};
    use crate::capabilities::validation::constraints::{
        find_redundant_explicit_defaults, find_should_use_defaults,
    };

    fn raw_trait(
        id: &str,
        platforms: Option<Vec<&str>>,
        file_types: Option<Vec<&str>>,
        mbc: Option<&str>,
        attack: Option<&str>,
    ) -> RawTraitDefinition {
        RawTraitDefinition {
            id: id.to_string(),
            desc: "test trait".to_string(),
            conf: None,
            crit: None,
            mbc: mbc.map(str::to_string),
            attack: attack.map(str::to_string),
            platforms: platforms.map(|v| v.into_iter().map(str::to_string).collect()),
            arch: None,
            file_types: file_types.map(|v| v.into_iter().map(str::to_string).collect()),
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            condition: None,
            not: None,
            unless: None,
            downgrade: None,
        }
    }

    fn raw_composite(
        id: &str,
        platforms: Option<Vec<&str>>,
        file_types: Option<Vec<&str>>,
        mbc: Option<&str>,
        attack: Option<&str>,
    ) -> RawCompositeRule {
        RawCompositeRule {
            id: id.to_string(),
            desc: "test composite".to_string(),
            conf: None,
            crit: None,
            mbc: mbc.map(str::to_string),
            attack: attack.map(str::to_string),
            platforms: platforms.map(|v| v.into_iter().map(str::to_string).collect()),
            arch: None,
            file_types: file_types.map(|v| v.into_iter().map(str::to_string).collect()),
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            needs: None,
            none: None,
            condition: None,
            near_lines: None,
            near_bytes: None,
            unless: None,
            not: None,
            downgrade: None,
        }
    }

    fn defaults(
        platforms: Option<Vec<&str>>,
        file_types: Option<Vec<&str>>,
        mbc: Option<&str>,
        attack: Option<&str>,
    ) -> TraitDefaults {
        TraitDefaults {
            r#for: file_types.map(|v| v.into_iter().map(str::to_string).collect()),
            platforms: platforms.map(|v| v.into_iter().map(str::to_string).collect()),
            arch: None,
            crit: None,
            conf: None,
            mbc: mbc.map(str::to_string),
            attack: attack.map(str::to_string),
            size_min: None,
            size_max: None,
            entropy_min: None,
            entropy_max: None,
        }
    }

    // --- find_should_use_defaults ---

    #[test]
    fn test_suggest_platforms_when_all_agree() {
        let traits = vec![
            raw_trait("t/a", Some(vec!["windows"]), None, None, None),
            raw_trait("t/b", Some(vec!["windows"]), None, None, None),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        assert_eq!(result, vec![("platforms", "[windows]".to_string())]);
    }

    #[test]
    fn test_suggest_for_when_all_agree() {
        let traits = vec![
            raw_trait("t/a", None, Some(vec!["elf", "pe"]), None, None),
            raw_trait("t/b", None, Some(vec!["pe", "elf"]), None, None),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        // Order-independent: both have [elf, pe] even though written in different order
        let fields: Vec<&str> = result.iter().map(|(f, _)| *f).collect();
        assert!(fields.contains(&"for"), "should suggest 'for' field");
    }

    #[test]
    fn test_suggest_mbc_when_all_agree() {
        let traits = vec![
            raw_trait("t/a", None, None, Some("OB0001"), None),
            raw_trait("t/b", None, None, Some("OB0001"), None),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        assert_eq!(result, vec![("mbc", "OB0001".to_string())]);
    }

    #[test]
    fn test_suggest_attack_when_all_agree() {
        let traits = vec![
            raw_trait("t/a", None, None, None, Some("T1003")),
            raw_trait("t/b", None, None, None, Some("T1003")),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        assert_eq!(result, vec![("attack", "T1003".to_string())]);
    }

    #[test]
    fn test_no_suggestion_when_values_differ() {
        let traits = vec![
            raw_trait("t/a", Some(vec!["windows"]), None, None, None),
            raw_trait("t/b", Some(vec!["linux"]), None, None, None),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        assert!(result.is_empty());
    }

    #[test]
    fn test_no_suggestion_when_one_trait_missing_field() {
        // t/b has no platforms → not all items agree
        let traits = vec![
            raw_trait("t/a", Some(vec!["windows"]), None, None, None),
            raw_trait("t/b", None, None, None, None),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        assert!(result.is_empty());
    }

    #[test]
    fn test_no_suggestion_when_default_already_set() {
        let traits = vec![
            raw_trait("t/a", Some(vec!["windows"]), None, None, None),
            raw_trait("t/b", Some(vec!["windows"]), None, None, None),
        ];
        // Default already covers platforms — no suggestion needed
        let result = find_should_use_defaults(
            &traits,
            &[],
            &defaults(Some(vec!["windows"]), None, None, None),
        );
        assert!(result.is_empty());
    }

    #[test]
    fn test_no_suggestion_for_single_item() {
        let traits = vec![raw_trait("t/a", Some(vec!["windows"]), None, None, None)];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        assert!(result.is_empty());
    }

    #[test]
    fn test_suggest_includes_composites() {
        let traits = vec![raw_trait("t/a", Some(vec!["windows"]), None, None, None)];
        let composites = vec![raw_composite(
            "c/a",
            Some(vec!["windows"]),
            None,
            None,
            None,
        )];
        let result =
            find_should_use_defaults(&traits, &composites, &defaults(None, None, None, None));
        assert_eq!(result, vec![("platforms", "[windows]".to_string())]);
    }

    #[test]
    fn test_suggest_platforms_case_insensitive() {
        // "Windows" and "windows" should be treated as the same value
        let traits = vec![
            raw_trait("t/a", Some(vec!["Windows"]), None, None, None),
            raw_trait("t/b", Some(vec!["windows"]), None, None, None),
        ];
        let result = find_should_use_defaults(&traits, &[], &defaults(None, None, None, None));
        let fields: Vec<&str> = result.iter().map(|(f, _)| *f).collect();
        assert!(
            fields.contains(&"platforms"),
            "case-insensitive match should still suggest"
        );
    }

    // --- find_redundant_explicit_defaults ---

    #[test]
    fn test_redundant_platforms_flagged() {
        let traits = vec![raw_trait("t/a", Some(vec!["windows"]), None, None, None)];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(Some(vec!["windows"]), None, None, None),
        );
        assert_eq!(result, vec![("t/a".to_string(), "platforms")]);
    }

    #[test]
    fn test_redundant_for_flagged() {
        let traits = vec![raw_trait("t/a", None, Some(vec!["elf", "pe"]), None, None)];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(None, Some(vec!["pe", "elf"]), None, None),
        );
        assert_eq!(result, vec![("t/a".to_string(), "for")]);
    }

    #[test]
    fn test_redundant_mbc_flagged() {
        let traits = vec![raw_trait("t/a", None, None, Some("OB0001"), None)];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(None, None, Some("OB0001"), None),
        );
        assert_eq!(result, vec![("t/a".to_string(), "mbc")]);
    }

    #[test]
    fn test_redundant_attack_flagged() {
        let traits = vec![raw_trait("t/a", None, None, None, Some("T1003"))];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(None, None, None, Some("T1003")),
        );
        assert_eq!(result, vec![("t/a".to_string(), "attack")]);
    }

    #[test]
    fn test_not_redundant_when_value_differs() {
        let traits = vec![raw_trait("t/a", Some(vec!["linux"]), None, None, None)];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(Some(vec!["windows"]), None, None, None),
        );
        assert!(result.is_empty());
    }

    #[test]
    fn test_not_redundant_when_no_default() {
        let traits = vec![raw_trait("t/a", Some(vec!["windows"]), None, None, None)];
        let result =
            find_redundant_explicit_defaults(&traits, &[], &defaults(None, None, None, None));
        assert!(result.is_empty());
    }

    #[test]
    fn test_redundant_composite_flagged() {
        let composites = vec![raw_composite(
            "c/a",
            Some(vec!["windows"]),
            None,
            None,
            None,
        )];
        let result = find_redundant_explicit_defaults(
            &[],
            &composites,
            &defaults(Some(vec!["windows"]), None, None, None),
        );
        assert_eq!(result, vec![("c/a".to_string(), "platforms")]);
    }

    #[test]
    fn test_redundant_platforms_order_independent() {
        // Trait sets [linux, windows], default is [windows, linux] — same, so redundant
        let traits = vec![raw_trait(
            "t/a",
            Some(vec!["linux", "windows"]),
            None,
            None,
            None,
        )];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(Some(vec!["windows", "linux"]), None, None, None),
        );
        assert_eq!(result, vec![("t/a".to_string(), "platforms")]);
    }

    #[test]
    fn test_only_redundant_traits_flagged_not_compliant_ones() {
        let traits = vec![
            raw_trait("t/redundant", Some(vec!["windows"]), None, None, None),
            raw_trait("t/different", Some(vec!["linux"]), None, None, None),
        ];
        let result = find_redundant_explicit_defaults(
            &traits,
            &[],
            &defaults(Some(vec!["windows"]), None, None, None),
        );
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "t/redundant");
    }
}
