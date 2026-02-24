//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for validation module.
//!
//! Tests are organized by submodule to match the module structure.

#[cfg(test)]
mod precision_tests {
    // Precision calculation tests would go here
    // Tests from original validation.rs lines ~3312-4200
}

#[cfg(test)]
mod duplicate_tests {
    use super::super::duplicates::*;
    use super::super::helpers::extract_tier;
    use crate::composite_rules::{
        Condition, ConditionWithFilters, FileType, Platform, TraitDefinition,
    };
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
            r#if: ConditionWithFilters {
                condition,
                size_min: None,
                size_max: None,
                count_min: None,
                count_max: None,
                per_kb_min: None,
                per_kb_max: None,
                entropy_min: None,
                entropy_max: None,
            },
            r#for: for_types,
            platforms: vec![Platform::All],
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
    use crate::composite_rules::{
        Condition, ConditionWithFilters, FileType, Platform, TraitDefinition,
    };
    use std::path::PathBuf;

    fn create_raw_regex_trait(id: &str, pattern: &str) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test trait".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            mbc: None,
            attack: None,
            r#if: ConditionWithFilters {
                condition: Condition::Raw {
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
            },
            r#for: vec![FileType::All],
            platforms: vec![Platform::All],
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
    // Taxonomy validation tests would go here
    // Tests from original validation.rs lines ~5600-5900
}

#[cfg(test)]
mod constraint_tests {
    use crate::capabilities::validation::constraints::find_pure_alias_traits;
    use crate::composite_rules::{
        Condition, ConditionWithFilters, FileType, Platform, TraitDefinition,
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
            r#if: ConditionWithFilters {
                condition: Condition::Trait {
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
            },
            r#for: vec![FileType::All],
            platforms: vec![Platform::All],
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
            r#if: ConditionWithFilters {
                condition: Condition::String {
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
            },
            r#for: vec![FileType::All],
            platforms: vec![Platform::All],
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
}
