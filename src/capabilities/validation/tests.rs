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
            for_from_groups: false,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yml"),
            precision: None,
            ..Default::default()
        }
    }

    #[test]
    #[ignore]
    fn test_precision_count_min_scored() {
        let mut trait_def = create_minimal_trait(Condition::Raw {
            exact: Some("test".to_string()),
            substr: None,
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
    #[ignore]
    fn test_precision_density_scored() {
        let mut trait_def = create_minimal_trait(Condition::Raw {
            exact: Some("test".to_string()),
            substr: None,
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
    use crate::composite_rules::condition::EncodingSpec;
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
            for_from_groups: false,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from(file_path),
            precision: None,
            ..Default::default()
        }
    }

    /// Create a string exact trait (backed by `Condition::Raw` so the duplicate
    /// detectors scoped to Raw/Symbol see the fixture).
    fn create_string_exact(
        id: &str,
        pattern: &str,
        case_insensitive: bool,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Raw {
                exact: Some(pattern.to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive,
                is_check: None,
                not: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
            },
            for_types,
            file_path,
        )
    }

    /// Create a text exact trait.
    fn create_text_exact(
        id: &str,
        pattern: &str,
        case_insensitive: bool,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Text {
                exact: Some(pattern.to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive,
                is_check: None,
                not: None,
                platforms: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
            },
            for_types,
            file_path,
        )
    }

    /// Create a string-literal exact trait.
    fn create_string_literal_exact(
        id: &str,
        pattern: &str,
        case_insensitive: bool,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Literal {
                kind: None,
                exact: Some(pattern.to_string()),
                substr: None,
                regex: None,
                word: None,
                value: None,
                radix: None,
                case_insensitive,
                is_check: None,
                not: None,
                platforms: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
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
            Condition::Raw {
                exact: None,
                substr: Some(pattern.to_string()),
                regex: None,
                word: None,
                case_insensitive,
                is_check: None,
                not: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
            },
            for_types,
            file_path,
        )
    }

    /// Create an encoded substr trait.
    fn create_encoded_substr(
        id: &str,
        pattern: &str,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Encoded {
                exact: None,
                substr: Some(pattern.to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                encoding: Some(EncodingSpec::Single("base64".to_string())),
                is_check: None,
                not: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
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
            Condition::Raw {
                exact: None,
                substr: None,
                regex: Some(pattern.to_string()),
                word: None,
                case_insensitive,
                is_check: None,
                not: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
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
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
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
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            },
            for_types,
            file_path,
        )
    }

    fn create_raw_regex_in_section(
        id: &str,
        pattern: &str,
        section: Option<&str>,
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
                case_insensitive: false,
                is_check: None,
                section: section.map(str::to_string),
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            },
            for_types,
            file_path,
        )
    }

    fn create_basename_regex(
        id: &str,
        pattern: &str,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Path {
                exact: None,
                substr: None,
                regex: Some(pattern.to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
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
        assert!(warnings[0].contains("Exact pattern"));
        assert!(warnings[0].contains("substr pattern"));
        assert!(warnings[0].contains("/dev/kmem"));
    }

    #[test]
    fn test_redundant_skips_low_value_same_tier_token_across_dirs() {
        let exact = create_string_exact(
            "objectives/a::client",
            "client",
            false,
            vec![FileType::Python],
            "objectives/a/traits.yaml",
        );
        let substr = create_string_substr(
            "objectives/b::client",
            "client",
            false,
            vec![FileType::Python],
            "objectives/b/traits.yaml",
        );

        let mut warnings = Vec::new();
        check_exact_contained_by_substr(&[exact, substr], &mut warnings);

        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_redundant_skips_same_tier_across_dirs() {
        let exact = create_string_exact(
            "objectives/anti-static/obfuscation/string/runtime-decrypt::ntdll-wide-string",
            "ntdll.dll",
            false,
            vec![FileType::Pe],
            "objectives/anti-static/obfuscation/string/runtime-decrypt/pe.yaml",
        );
        let substr = create_string_substr(
            "objectives/evasion/anti-av/platform/defender::ntdll-dll-str",
            "ntdll.dll",
            false,
            vec![FileType::Pe],
            "objectives/evasion/anti-av/platform/defender/windows.yaml",
        );

        let mut warnings = Vec::new();
        check_exact_contained_by_substr(&[exact, substr], &mut warnings);

        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_redundant_keeps_same_dir_duplicate() {
        let exact = create_string_exact(
            "objectives/evasion/anti-av/platform/defender::amsi-bypass-init-flag",
            "amsiInitFailed",
            false,
            vec![FileType::PowerShell],
            "objectives/evasion/anti-av/platform/defender/windows.yaml",
        );
        let substr = create_string_substr(
            "objectives/evasion/anti-av/platform/defender::amsi-init-failed-substr",
            "amsiInitFailed",
            false,
            vec![FileType::PowerShell],
            "objectives/evasion/anti-av/platform/defender/windows.yaml",
        );

        let mut warnings = Vec::new();
        check_exact_contained_by_substr(&[exact, substr], &mut warnings);

        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn test_redundant_keeps_reusable_cross_tier_token() {
        let exact = create_string_exact(
            "micro-behaviors/data/decode/base64::atob",
            "atob",
            false,
            vec![FileType::JavaScript],
            "micro-behaviors/data/decode/base64/javascript.yaml",
        );
        let substr = create_string_substr(
            "objectives/anti-static/obfuscation/string::atob",
            "atob",
            false,
            vec![FileType::JavaScript],
            "objectives/anti-static/obfuscation/string/traits.yaml",
        );

        let mut warnings = Vec::new();
        check_exact_contained_by_substr(&[exact, substr], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("atob"));
    }

    #[test]
    fn test_redundant_skips_low_signal_lexicon_token() {
        let exact = create_string_exact(
            "objectives/command-and-control/backdoor/tasking/filesystem::task-command-field",
            "command",
            false,
            vec![FileType::Go],
            "objectives/command-and-control/backdoor/tasking/filesystem/macos-go.yaml",
        );
        let substr = create_string_substr(
            "micro-behaviors/data/text/keywords/lexicon::command-dup",
            "command",
            false,
            vec![FileType::Go],
            "micro-behaviors/data/text/keywords/lexicon/traits.yaml",
        );

        let mut warnings = Vec::new();
        check_exact_contained_by_substr(&[exact, substr], &mut warnings);

        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_redundant_skips_text_vs_encoded_context() {
        let exact = create_string_exact(
            "micro-behaviors/process/create/shell/invoke::bin-sh",
            "/bin/sh",
            false,
            vec![FileType::Elf],
            "micro-behaviors/process/create/shell/invoke/generic.yaml",
        );
        let encoded = create_encoded_substr(
            "objectives/anti-static/obfuscation/encoding/content::encoded-bin-sh",
            "/bin/sh",
            vec![FileType::Elf],
            "objectives/anti-static/obfuscation/encoding/content/malware.yaml",
        );

        let mut warnings = Vec::new();
        check_exact_contained_by_substr(&[exact, encoded], &mut warnings);

        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_cross_type_keeps_same_file_text_string_literal_duplicate() {
        let text = create_text_exact(
            "well-known/malware/ransomware/jigsaw::game-message",
            "I want to play a game with you.",
            false,
            vec![FileType::CSharp],
            "well-known/malware/ransomware/jigsaw/traits.yaml",
        );
        let literal = create_string_literal_exact(
            "well-known/malware/ransomware/jigsaw::game-message-source",
            "I want to play a game with you.",
            false,
            vec![FileType::CSharp],
            "well-known/malware/ransomware/jigsaw/traits.yaml",
        );

        let mut warnings = Vec::new();
        check_same_string_different_types(&[text, literal], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("I want to play a game"));
    }

    #[test]
    fn test_cross_type_flags_symbol_raw_api_duplicate() {
        // The same literal searched as both `symbol` and `raw` with
        // overlapping file types is a duplicate to collapse, even in the
        // same file.
        let symbol = create_symbol_exact(
            "micro-behaviors/fs/memory/mmap::create-file-mapping-w",
            "CreateFileMappingW",
            vec![FileType::Pe],
            "micro-behaviors/fs/memory/mmap/windows.yaml",
        );
        let raw = create_string_exact(
            "micro-behaviors/fs/memory/mmap::create-file-mapping-w-import",
            "CreateFileMappingW",
            false,
            vec![FileType::Pe],
            "micro-behaviors/fs/memory/mmap/windows.yaml",
        );

        let mut warnings = Vec::new();
        check_same_string_different_types(&[symbol, raw], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("CreateFileMappingW"));
    }

    #[test]
    fn test_cross_type_flags_cross_dir_api_duplicate() {
        // Cross-type duplicates are flagged regardless of which directory
        // each trait lives in.
        let symbol = create_symbol_exact(
            "micro-behaviors/fs/memory/mmap::create-file-mapping-w",
            "CreateFileMappingW",
            vec![FileType::Pe],
            "micro-behaviors/fs/memory/mmap/windows.yaml",
        );
        let raw = create_string_exact(
            "well-known/malware/example::create-file-mapping-w",
            "CreateFileMappingW",
            false,
            vec![FileType::Pe],
            "well-known/malware/example/traits.yaml",
        );

        let mut warnings = Vec::new();
        check_same_string_different_types(&[symbol, raw], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("CreateFileMappingW"));
    }

    #[test]
    fn test_cross_type_flags_same_dir_different_file_duplicate() {
        // Cross-type duplicates are flagged regardless of which file each
        // trait lives in.
        let symbol = create_symbol_exact(
            "micro-behaviors/communications/http/get::internet-open",
            "InternetOpen",
            vec![FileType::Pe],
            "micro-behaviors/communications/http/get/wininet.yaml",
        );
        let raw = create_string_exact(
            "micro-behaviors/communications/http/get::internet-open-str",
            "InternetOpen",
            false,
            vec![FileType::Pe],
            "micro-behaviors/communications/http/get/wininet-dynamic.yaml",
        );

        let mut warnings = Vec::new();
        check_same_string_different_types(&[symbol, raw], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("InternetOpen"));
    }

    #[test]
    fn test_cross_type_skips_encoded_context() {
        let raw = create_string_exact(
            "objectives/evasion/indicator-removal/logs::utmp-cleanup-status",
            "utmp logs cleaned up.",
            false,
            vec![FileType::Elf],
            "objectives/evasion/indicator-removal/logs/unix-accounting.yaml",
        );
        let encoded = create_encoded_substr(
            "objectives/evasion/indicator-removal/logs::utmp-cleanup-status-xor",
            "utmp logs cleaned up.",
            vec![FileType::Elf],
            "objectives/evasion/indicator-removal/logs/unix-accounting.yaml",
        );

        let mut warnings = Vec::new();
        check_same_string_different_types(&[raw, encoded], &mut warnings);

        assert_eq!(warnings.len(), 0);
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
        assert!(warnings[0].contains("Same pattern, different match types"));
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
        assert!(warnings[0].contains("Regex pattern matches literal"));
    }

    #[test]
    fn test_broad_regex_matching_literal_no_warning() {
        let exact = create_string_exact(
            "test::exact",
            "COMPUTERNAME",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let regex = create_string_regex(
            "test::regex",
            "^[A-Z]{8,12}$",
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_regex_contains_literal(&[exact, regex], &mut warnings);

        assert_eq!(warnings.len(), 0);
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
        assert!(warnings[0].contains("Duplicate reusable atom"));
        assert!(warnings[0].contains("Reference reusable atom"));
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

    #[test]
    fn test_dup_pattern_ignores_match_all_basename_carrier() {
        let trait1 = create_basename_regex(
            "metadata/binary/metrics/size::large-file",
            ".",
            vec![FileType::Pe],
            "metadata/binary/metrics/size.yaml",
        );
        let trait2 = create_basename_regex(
            "well-known/malware/test::tiny-file",
            ".",
            vec![FileType::Pe],
            "well-known/malware/test/traits.yaml",
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[trait1, trait2], &mut warnings);

        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_dup_pattern_requires_same_section_scope() {
        let unscoped = create_raw_regex_in_section(
            "metadata/binary/anomaly/content::sha256",
            "^[a-f0-9]{64}$",
            None,
            vec![FileType::Pe],
            "metadata/binary/anomaly/content/hash.yaml",
        );
        let scoped = create_raw_regex_in_section(
            "metadata/binary/anomaly/format::sha256-rdata",
            "^[a-f0-9]{64}$",
            Some(".rdata"),
            vec![FileType::Pe],
            "metadata/binary/anomaly/format/pe.yaml",
        );

        let mut warnings = Vec::new();
        find_string_pattern_duplicates(&[unscoped, scoped], &mut warnings);

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
            Condition::Raw {
                exact: Some("duplicate".to_string()),
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
            },
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw {
                exact: Some("duplicate".to_string()),
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
            Condition::Raw {
                exact: Some("AB".to_string()),
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
            },
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw {
                exact: Some("\\x41B".to_string()), // Normalizes to "AB"
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
            Condition::Raw {
                exact: Some("test".to_string()), // 4 chars
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
            },
            vec![FileType::All],
            "file1.yaml",
            0.5, // conf = 0.5
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw {
                exact: Some("\\x74\\x65\\x73\\x74".to_string()), // 16 chars hex-encoded "test" (diff = 12 > 2)
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
            Condition::Raw {
                exact: Some("data".to_string()), // 4 chars
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
            },
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw {
                exact: Some("\\x64ata".to_string()), // 7 chars hex-encoded first char (diff = 3 > 2)
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
            Condition::Raw {
                exact: Some("pattern".to_string()), // 7 chars
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
            },
            vec![FileType::All],
            "file1.yaml",
            0.5,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw {
                exact: Some("pattern".to_string()), // 7 chars (diff = 0, not >2)
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
            Condition::Raw {
                exact: Some("value".to_string()), // 5 chars
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
            },
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw {
                exact: Some("\\x76\\x61lue".to_string()), // 11 chars, first 2 chars hex-encoded (diff = 6 > 2)
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
            Condition::Raw {
                exact: Some("name".to_string()), // 4 chars
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
            },
            vec![FileType::All],
            "file1.yaml",
            0.5,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw {
                exact: Some("\\x6e\\x61me".to_string()), // 11 chars (diff from trait1 = 7 > 2)
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
            },
            vec![FileType::All],
            "file2.yaml",
            0.9, // conf diff from trait1 = 0.4 >= 0.2
            crate::types::Criticality::Notable,
        );

        let trait3 = create_test_trait_with_conf_crit(
            "test::c",
            Condition::Raw {
                exact: Some("\\x6e\\x61\\x6d\\x65".to_string()), // 16 chars, all hex-encoded (diff from trait1 = 12, from trait2 = 5 > 2)
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
            Condition::Raw {
                exact: Some("code".to_string()), // 4 chars
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
            },
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw {
                exact: Some("\\x63\\x6fde".to_string()), // 11 chars (diff = 7 > 2)
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
            },
            vec![FileType::All],
            "file2.yaml",
            0.9,                                // conf diff from trait1 = 0.1 < 0.2
            crate::types::Criticality::Notable, // Same as trait1 - FAILS carveout
        );

        let trait3 = create_test_trait_with_conf_crit(
            "test::c",
            Condition::Raw {
                exact: Some("\\x63\\x6f\\x64\\x65".to_string()), // 16 chars (diff from trait1 = 12 > 2)
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
                Condition::Path {
                    exact: Some("setup.py".to_string()),
                    substr: None,
                    regex: None,
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                },
                vec![FileType::Python],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Path {
                    exact: Some("setup.py".to_string()),
                    substr: None,
                    regex: None,
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
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
                Condition::Path {
                    exact: None,
                    substr: Some("chrome".to_string()),
                    regex: None,
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                },
                vec![FileType::All],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Path {
                    exact: None,
                    substr: Some("chrome".to_string()),
                    regex: None,
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
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
                Condition::Path {
                    exact: None,
                    substr: None,
                    regex: Some("\\.pyc$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                },
                vec![FileType::Python],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Path {
                    exact: None,
                    substr: None,
                    regex: Some("\\.pyc$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
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
                Condition::Path {
                    exact: None,
                    substr: None,
                    regex: Some("^Makefile$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                },
                vec![FileType::All],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Path {
                    exact: None,
                    substr: None,
                    regex: Some("^setup\\.py$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
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
            Condition::Path {
                exact: None,
                substr: None,
                regex: Some("(?i)^setup\\.py$".to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
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
                Condition::Path {
                    exact: None,
                    substr: None,
                    regex: Some("^(setup|install)\\.py$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                },
                vec![FileType::Python],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Path {
                    exact: None,
                    substr: None,
                    regex: Some(".*\\.exe$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
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
            Condition::Path {
                exact: None,
                substr: None,
                regex: None,
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
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
            Condition::Path {
                exact: None,
                substr: None,
                regex: Some(".".to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
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
                Condition::Raw {
                    exact: Some("setup.py".to_string()),
                    substr: None,
                    word: None,
                    regex: None,
                    case_insensitive: false,
                    is_check: None,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
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
                    is_check: None,
                    kind: None,
                    arg: None,
                    args: None,
                    alias: None,
                    not: None,
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
    fn test_basename_regex_literal_overlap_blocked() {
        use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

        let traits = vec![
            create_test_trait(
                "basename_exact",
                Condition::Path {
                    exact: Some("sshd".to_string()),
                    substr: None,
                    regex: None,
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                },
                vec![FileType::Shell],
                "file1.yaml",
            ),
            create_test_trait(
                "basename_regex",
                Condition::Path {
                    exact: None,
                    substr: None,
                    regex: Some("^(ssh|sshd|ssh_config)$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                },
                vec![FileType::Shell],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        validate_regex_overlap_with_literal(&traits, &mut warnings);

        assert!(!warnings.is_empty());
        assert!(warnings.iter().any(|w| w.contains("sshd")));
    }

    #[test]
    fn test_regex_literal_overlap_different_criticality_allowed() {
        use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

        let traits = vec![
            create_test_trait_with_conf_crit(
                "exact_notable",
                Condition::Raw {
                    exact: Some("malware.exe".to_string()),
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
                },
                vec![FileType::Pe],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "regex_hostile",
                Condition::Raw {
                    exact: None,
                    substr: None,
                    regex: Some("malware\\.exe".to_string()),
                    word: None,
                    case_insensitive: false,
                    is_check: None,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    not: None,
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
    fn test_basename_regex_alternative_subset_detected() {
        use crate::capabilities::validation::duplicates::check_regex_alternative_subsets;

        let traits = vec![
            create_test_trait(
                "subset",
                Condition::Path {
                    exact: None,
                    substr: None,
                    regex: Some("\\.(test|spec)\\.[cm]?[jt]sx?$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                },
                vec![FileType::JavaScript, FileType::TypeScript],
                "file1.yaml",
            ),
            create_test_trait(
                "superset",
                Condition::Path {
                    exact: None,
                    substr: None,
                    regex: Some("\\.(test|spec|bench)\\.[cm]?[jt]sx?$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                },
                vec![FileType::JavaScript, FileType::TypeScript],
                "file2.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        check_regex_alternative_subsets(&traits, &mut warnings);

        assert!(!warnings.is_empty());
        assert!(warnings[0].contains("REGEX ALTERNATIVE SUBSET"));
        assert!(warnings[0].contains("\\.(test|spec)\\.[cm]?[jt]sx?$"));
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
                Condition::Raw {
                    exact: Some("malicious_pattern".to_string()),
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
                },
                vec![FileType::Elf],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_hostile",
                Condition::Raw {
                    exact: Some("malicious_pattern".to_string()),
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
                Condition::Raw {
                    exact: Some("test_pattern".to_string()),
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
                },
                vec![FileType::Shell],
                "file1.yaml",
                0.5,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_high_conf",
                Condition::Raw {
                    exact: Some("test_pattern".to_string()),
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
                Condition::Raw {
                    exact: Some("shared_pattern".to_string()),
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
                },
                vec![FileType::Elf, FileType::Macho],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_elf_pe",
                Condition::Raw {
                    exact: Some("shared_pattern".to_string()),
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
                Condition::Raw {
                    exact: Some("platform_pattern".to_string()),
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
                },
                vec![FileType::Macho],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_pe",
                Condition::Raw {
                    exact: Some("platform_pattern".to_string()),
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
                Condition::Raw {
                    exact: Some("building_block".to_string()),
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
                },
                vec![FileType::All],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Component,
            ),
            create_test_trait_with_conf_crit(
                "trait_baseline",
                Condition::Raw {
                    exact: Some("building_block".to_string()),
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
                Condition::Raw {
                    exact: Some("pattern_a".to_string()),
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
                },
                vec![FileType::All],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_b",
                Condition::Raw {
                    exact: Some("pattern_b".to_string()),
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

    // ========================================================================
    // Structural Regex Duplicate Tests
    // ========================================================================

    #[test]
    fn test_structural_regex_duplicate_char_class_diff() {
        // Two regexes that differ only inside a character class collapse to
        // the same shape and should be flagged.
        let a = create_string_regex(
            "test::a",
            r"(^|[^\w$])eval\s*\(",
            false,
            vec![FileType::JavaScript],
            "file_a.yaml",
        );
        let b = create_string_regex(
            "test::b",
            r"(^|[^\w$.])eval\s*\(",
            false,
            vec![FileType::JavaScript],
            "file_b.yaml",
        );

        let mut warnings = Vec::new();
        find_structural_regex_duplicates(&[a, b], &mut warnings);

        assert_eq!(warnings.len(), 1, "expected one duplicate warning");
        assert!(warnings[0].contains("Structurally duplicate"));
    }

    #[test]
    fn test_structural_regex_duplicate_skipped_when_baseline() {
        // Component/Baseline tier traits are intentional building blocks.
        let a = create_test_trait_with_conf_crit(
            "test::comp_a",
            Condition::Raw {
                exact: None,
                substr: None,
                regex: Some(r"eval\s*\([a-z]+\)".to_string()),
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            },
            vec![FileType::JavaScript],
            "file_a.yaml",
            1.0,
            crate::types::Criticality::Component,
        );
        let b = create_test_trait_with_conf_crit(
            "test::comp_b",
            Condition::Raw {
                exact: None,
                substr: None,
                regex: Some(r"eval\s*\([A-Z]+\)".to_string()),
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            },
            vec![FileType::JavaScript],
            "file_b.yaml",
            1.0,
            crate::types::Criticality::Component,
        );

        let mut warnings = Vec::new();
        find_structural_regex_duplicates(&[a, b], &mut warnings);
        assert_eq!(warnings.len(), 0, "component-tier should be ignored");
    }

    #[test]
    fn test_structural_regex_duplicate_no_overlap_when_filetypes_disjoint() {
        let a = create_string_regex(
            "test::a",
            r"\bnft\s+flush\s+ruleset\b",
            false,
            vec![FileType::Elf],
            "file_a.yaml",
        );
        let b = create_string_regex(
            "test::b",
            r"nft\s+flush\s+ruleset",
            false,
            vec![FileType::Pe],
            "file_b.yaml",
        );

        let mut warnings = Vec::new();
        find_structural_regex_duplicates(&[a, b], &mut warnings);
        assert_eq!(warnings.len(), 0, "disjoint file types should not collide");
    }

    #[test]
    fn test_structural_regex_duplicate_no_overlap_across_tiers() {
        // notable vs suspicious — different active tiers shouldn't collide,
        // since a graduated severity ladder is intentional.
        let a = create_test_trait_with_conf_crit(
            "test::a",
            Condition::Raw {
                exact: None,
                substr: None,
                regex: Some(r"eval\s*\(\s*[a-z]+\s*\)".to_string()),
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            },
            vec![FileType::JavaScript],
            "file_a.yaml",
            1.0,
            crate::types::Criticality::Notable,
        );
        let b = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw {
                exact: None,
                substr: None,
                regex: Some(r"eval\s*\(\s*[A-Z]+\s*\)".to_string()),
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            },
            vec![FileType::JavaScript],
            "file_b.yaml",
            1.0,
            crate::types::Criticality::Suspicious,
        );

        let mut warnings = Vec::new();
        find_structural_regex_duplicates(&[a, b], &mut warnings);
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn test_structural_regex_duplicate_short_shape_ignored() {
        // Only 3 literal bytes; too generic to bucket.
        let a = create_string_regex(
            "test::a",
            r"a[CC]b",
            false,
            vec![FileType::All],
            "file_a.yaml",
        );
        let b = create_string_regex(
            "test::b",
            r"a[A-Z]b",
            false,
            vec![FileType::All],
            "file_b.yaml",
        );

        let mut warnings = Vec::new();
        find_structural_regex_duplicates(&[a, b], &mut warnings);
        assert_eq!(warnings.len(), 0);
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
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            },
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            r#for: vec![FileType::All],
            for_from_groups: false,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            size_min: None,
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
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
        ObjectivesWellknownViolation, find_cap_obj_violations, find_cap_wellknown_violations,
        find_metadata_cross_tier_refs, find_objectives_wellknown_violations,
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
            for_from_groups: false,
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
            ..Default::default()
        }
    }

    fn make_composite(id: &str, all_refs: &[&str]) -> CompositeTrait {
        CompositeTrait {
            required_trait_indices: Vec::new(),
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            for_from_groups: false,
            size_min: None,
            size_max: None,
            all: Some(
                all_refs
                    .iter()
                    .map(|r| Condition::Trait { id: r.to_string() })
                    .collect(),
            ),
            any: None,
            unless: None,
            not: None,
            downgrade: None,
            needs: None,
            near_lines: None,
            near_bytes: None,
            scope: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
        }
    }

    fn make_composite_suspicious(id: &str, all_refs: &[&str]) -> CompositeTrait {
        CompositeTrait {
            required_trait_indices: Vec::new(),
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Suspicious,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            for_from_groups: false,
            size_min: None,
            size_max: None,
            all: Some(
                all_refs
                    .iter()
                    .map(|r| Condition::Trait { id: r.to_string() })
                    .collect(),
            ),
            any: None,
            unless: None,
            not: None,
            downgrade: None,
            needs: None,
            near_lines: None,
            near_bytes: None,
            scope: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
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
    fn test_metadata_referencing_wellknown_non_malware_is_also_violation() {
        let composites = vec![make_composite(
            "metadata/format/composite",
            &[
                "well-known/tool/cobalt-strike/beacon",
                "well-known/lib/openssl/v3",
                "well-known/app/chrome/extension",
            ],
        )];
        let sources = HashMap::new();
        let v = find_metadata_cross_tier_refs(&[], &composites, &sources);
        assert_eq!(
            v.len(),
            3,
            "metadata/ must not reference any well-known/ subtree"
        );
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
    fn test_cap_referencing_wellknown_malware_is_violation() {
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
    fn test_cap_composite_referencing_wellknown_non_malware_is_also_violation() {
        let composites = vec![make_composite_suspicious(
            "micro-behaviors/net/suspicious",
            &[
                "micro-behaviors/net/http-post",
                "well-known/tool/cobalt-strike/beacon",
            ],
        )];
        let sources = HashMap::new();
        let v = find_cap_wellknown_violations(&[], &composites, &sources);
        assert_eq!(
            v.len(),
            1,
            "micro-behaviors/ may not reference any well-known/ subtree"
        );
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

    // ---- objectives/ → well-known/ ----

    fn make_composite_with_unless(
        id: &str,
        all_refs: &[&str],
        unless_refs: &[&str],
    ) -> CompositeTrait {
        let mut c = make_composite(id, all_refs);
        c.unless = Some(
            unless_refs
                .iter()
                .map(|r| Condition::Trait { id: r.to_string() })
                .collect(),
        );
        c
    }

    #[test]
    fn test_objectives_positive_wellknown_tool_is_ok() {
        // Objectives may freely reference well-known/{tool,app,lib,game}/
        // as positive evidence at any criticality — these are
        // legitimate-software identifiers, not malware-family attribution.
        let composites = vec![make_composite_suspicious(
            "objectives/credential-access/dump",
            &[
                "micro-behaviors/process/lsass",
                "well-known/tool/mimikatz/sekurlsa",
            ],
        )];
        let sources = HashMap::new();
        let v = find_objectives_wellknown_violations(&[], &composites, &sources);
        assert!(
            v.is_empty(),
            "objectives/ may reference well-known/{{tool,app,lib,game}}/ as positive evidence"
        );
    }

    #[test]
    fn test_objectives_unless_wellknown_tool_is_ok() {
        let composites = vec![make_composite_with_unless(
            "objectives/credential-access/dump",
            &["micro-behaviors/process/lsass"],
            &["well-known/tool/sysinternals/procdump"],
        )];
        let sources = HashMap::new();
        let v = find_objectives_wellknown_violations(&[], &composites, &sources);
        assert!(
            v.is_empty(),
            "well-known/tool/ in `unless:` is benign-context suppression and is allowed"
        );
    }

    #[test]
    fn test_objectives_unless_wellknown_malware_is_violation() {
        let composites = vec![make_composite_with_unless(
            "objectives/credential-access/dump",
            &["micro-behaviors/process/lsass"],
            &["well-known/malware/stealer/redline"],
        )];
        let sources = HashMap::new();
        let v = find_objectives_wellknown_violations(&[], &composites, &sources);
        assert_eq!(
            v.len(),
            1,
            "well-known/malware refs are forbidden even in unless/downgrade clauses"
        );
        assert_eq!(v[0].3, ObjectivesWellknownViolation::MalwareRef);
    }

    #[test]
    fn test_objectives_positive_wellknown_malware_is_violation() {
        let composites = vec![make_composite(
            "objectives/credential-access/dump",
            &[
                "micro-behaviors/process/lsass",
                "well-known/malware/stealer/redline",
            ],
        )];
        let sources = HashMap::new();
        let v = find_objectives_wellknown_violations(&[], &composites, &sources);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].3, ObjectivesWellknownViolation::MalwareRef);
    }

    #[test]
    fn test_non_objectives_skipped() {
        // The objectives/ check must not double-fire on micro-behaviors/ or metadata/ rules
        // (those are flagged by find_cap_wellknown_violations / find_metadata_cross_tier_refs).
        let composites = vec![
            make_composite(
                "micro-behaviors/foo",
                &["well-known/tool/mimikatz/sekurlsa"],
            ),
            make_composite("metadata/format/foo", &["well-known/lib/openssl/v3"]),
        ];
        let sources = HashMap::new();
        let v = find_objectives_wellknown_violations(&[], &composites, &sources);
        assert!(v.is_empty());
    }
}

#[cfg(test)]
mod constraint_tests {
    use crate::capabilities::validation::constraints::{
        find_empty_condition_clauses, find_needs_zero, find_none_only_with_proximity,
        find_pure_alias_traits, find_too_short_patterns,
    };
    use crate::capabilities::validation::find_pure_directory_alias_composites;
    use crate::composite_rules::{
        Arch, CompositeTrait, Condition, FileType, Platform, TraitDefinition,
    };
    use crate::types::Criticality;
    use std::collections::{HashMap, HashSet};
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
            for_from_groups: false,
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
            ..Default::default()
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
            r#if: Condition::Raw {
                exact: Some("test".to_string()),
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
            },
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            r#for: vec![FileType::All],
            for_from_groups: false,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            size_min: None,
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
        }
    }

    fn short_raw_trait(id: &str, condition: Condition) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "short raw trait".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
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
            for_from_groups: false,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
        }
    }

    fn raw_exact_with_offsets(
        offset: Option<i64>,
        offset_range: Option<(i64, Option<i64>)>,
        section: Option<&str>,
        section_offset: Option<i64>,
        section_offset_range: Option<(i64, Option<i64>)>,
    ) -> Condition {
        Condition::Raw {
            exact: Some("MZ".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: section.map(String::from),
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            not: None,
        }
    }

    #[test]
    fn short_patterns_allow_exact_or_limited_byte_offsets() {
        let traits = vec![
            short_raw_trait(
                "test/absolute-offset",
                raw_exact_with_offsets(Some(0), None, None, None, None),
            ),
            short_raw_trait(
                "test/absolute-range",
                raw_exact_with_offsets(None, Some((0, Some(64))), None, None, None),
            ),
            short_raw_trait(
                "test/section-offset",
                raw_exact_with_offsets(None, None, Some(".text"), Some(16), None),
            ),
            short_raw_trait(
                "test/section-range",
                raw_exact_with_offsets(None, None, Some(".rdata"), None, Some((8, Some(128)))),
            ),
        ];

        assert!(find_too_short_patterns(&traits).is_empty());
    }

    #[test]
    fn short_patterns_reject_open_or_large_byte_ranges() {
        let traits = vec![
            short_raw_trait(
                "test/open-absolute-range",
                raw_exact_with_offsets(None, Some((0, None)), None, None, None),
            ),
            short_raw_trait(
                "test/large-absolute-range",
                raw_exact_with_offsets(None, Some((0, Some(16_384))), None, None, None),
            ),
            short_raw_trait(
                "test/open-section-range",
                raw_exact_with_offsets(None, None, Some(".text"), None, Some((0, None))),
            ),
            short_raw_trait(
                "test/large-section-range",
                raw_exact_with_offsets(None, None, Some(".rdata"), None, Some((0, Some(16_384)))),
            ),
        ];

        let violations = find_too_short_patterns(&traits);
        assert_eq!(violations.len(), 4);
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

    fn create_composite_any(id: &str, refs: &[&str]) -> CompositeTrait {
        CompositeTrait {
            required_trait_indices: Vec::new(),
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            for_from_groups: false,
            size_min: None,
            size_max: None,
            all: None,
            any: Some(
                refs.iter()
                    .map(|id| Condition::Trait {
                        id: (*id).to_string(),
                    })
                    .collect(),
            ),
            unless: None,
            not: None,
            downgrade: None,
            needs: None,
            near_lines: None,
            near_bytes: None,
            scope: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
        }
    }

    fn dir_traits(dir: &str, ids: &[&str]) -> HashMap<String, HashSet<String>> {
        let mut map = HashMap::new();
        map.insert(
            dir.to_string(),
            ids.iter().map(|id| (*id).to_string()).collect(),
        );
        map
    }

    #[test]
    fn test_pure_directory_alias_composite_detected() {
        let traits = dir_traits("foo/bar", &["foo/bar::a", "foo/bar::b"]);
        let rules = vec![create_composite_any(
            "foo/bar::alias",
            &["foo/bar::a", "foo/bar::b"],
        )];

        let violations = find_pure_directory_alias_composites(&rules, &traits);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "foo/bar::alias");
        assert_eq!(violations[0].1, "foo/bar");
    }

    #[test]
    fn test_directory_alias_with_constraints_not_flagged() {
        let traits = dir_traits("foo/bar", &["foo/bar::a", "foo/bar::b"]);
        let mut rule = create_composite_any("foo/bar::alias", &["foo/bar::a", "foo/bar::b"]);
        rule.needs = Some(2);

        let violations = find_pure_directory_alias_composites(&[rule], &traits);

        assert!(violations.is_empty());
    }

    #[test]
    fn test_single_directory_ref_with_needs_not_flagged_as_alias() {
        // A single `any:` entry that is a *directory* reference with `needs: 2`
        // is a real k-of-N marker (>= 2 distinct member traits), not a pure
        // alias, and must not be flagged by the single-item validator. (The
        // engine weights the dir-ref by its matched-member count.)
        use crate::capabilities::validation::find_single_item_clauses;
        let mut rule =
            create_composite_any("well-known/lib/ffmpeg::marker", &["well-known/lib/ffmpeg"]);
        rule.needs = Some(2);

        assert!(
            find_single_item_clauses(&rule).is_empty(),
            "single directory-ref + needs must not be flagged as a single-item alias"
        );

        // Control: a single *specific* trait ref (with `::`) IS a pure alias.
        let alias = create_composite_any("foo/bar::alias", &["foo/bar::a"]);
        assert_eq!(
            find_single_item_clauses(&alias).len(),
            1,
            "single specific trait ref is a pure alias and must be flagged"
        );
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
                eq: None,
                ne: None,
                case_insensitive: false,
                exists: Some(false),
                size_min: None,
                size_max: None,
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
            for_from_groups: false,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
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
                eq: None,
                ne: None,
                case_insensitive: false,
                exists: Some(false),
                size_min: None,
                size_max: None,
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
            for_from_groups: false,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
        }];

        let v = find_kv_exists_with_matcher(&traits, &[]);
        assert!(v.is_empty(), "exists: false without matcher is valid");
    }

    #[test]
    fn test_none_only_with_proximity_is_flagged() {
        let rules = vec![CompositeTrait {
            required_trait_indices: Vec::new(),
            id: "test/none-prox".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
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
            any: None,
            unless: Some(vec![Condition::Trait {
                id: "some-trait".to_string(),
            }]),
            not: None,
            downgrade: None,
            needs: None,
            near_lines: Some(10),
            near_bytes: None,
            scope: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
        }];
        let result = find_none_only_with_proximity(&rules);
        assert_eq!(result, vec!["test/none-prox"]);
    }

    #[test]
    fn test_none_with_all_and_proximity_is_ok() {
        let rules = vec![CompositeTrait {
            required_trait_indices: Vec::new(),
            id: "test/none-plus-all".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            for_from_groups: false,
            size_min: None,
            size_max: None,
            all: Some(vec![Condition::Trait {
                id: "some-trait".to_string(),
            }]),
            any: None,
            unless: Some(vec![Condition::Trait {
                id: "other-trait".to_string(),
            }]),
            not: None,
            downgrade: None,
            needs: None,
            near_lines: Some(10),
            near_bytes: None,
            scope: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
        }];
        let result = find_none_only_with_proximity(&rules);
        assert!(result.is_empty());
    }

    #[test]
    fn test_empty_all_with_none_is_flagged() {
        // all: [] + none: [something] should still be flagged — empty all vacuously matches
        let rules = vec![CompositeTrait {
            required_trait_indices: Vec::new(),
            id: "test/empty-all-none".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            for_from_groups: false,
            size_min: None,
            size_max: None,
            all: Some(vec![]),
            any: None,
            unless: Some(vec![Condition::Trait {
                id: "some-trait".to_string(),
            }]),
            not: None,
            downgrade: None,
            needs: None,
            near_lines: None,
            near_bytes: None,
            scope: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
        }];
        let result = find_empty_condition_clauses(&rules);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ("test/empty-all-none".to_string(), "all"));
    }

    #[test]
    fn test_needs_zero_is_flagged() {
        let rules = vec![CompositeTrait {
            required_trait_indices: Vec::new(),
            id: "test/needs-zero".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
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
                id: "some-trait".to_string(),
            }]),
            unless: None,
            not: None,
            downgrade: None,
            needs: Some(0),
            near_lines: None,
            near_bytes: None,
            scope: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
        }];
        let result = find_needs_zero(&rules);
        assert_eq!(result, vec!["test/needs-zero"]);
    }

    #[test]
    fn test_needs_one_is_not_flagged_by_needs_zero() {
        let rules = vec![CompositeTrait {
            required_trait_indices: Vec::new(),
            id: "test/needs-one".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
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
                id: "some-trait".to_string(),
            }]),
            unless: None,
            not: None,
            downgrade: None,
            needs: Some(1),
            near_lines: None,
            near_bytes: None,
            scope: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
        }];
        let result = find_needs_zero(&rules);
        assert!(result.is_empty());
    }
}

#[cfg(test)]
mod autoprefix_tests {
    use super::super::composite::{
        autoprefix_trait_refs, collect_trait_refs_from_rule, collect_trait_refs_from_trait_def,
    };
    use crate::composite_rules::condition::Condition;
    use crate::composite_rules::traits::{CompositeTrait, DowngradeConditions, TraitDefinition};
    use crate::composite_rules::types::{Arch, FileType, Platform};
    use crate::types::Criticality;

    fn make_rule(
        unless: Option<Vec<Condition>>,
        downgrade: Option<DowngradeConditions>,
    ) -> CompositeTrait {
        CompositeTrait {
            required_trait_indices: Vec::new(),
            id: "test/rule".to_string(),
            desc: "Test".to_string(),
            conf: 1.0,
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
            any: None,
            needs: None,
            near_lines: None,
            near_bytes: None,
            scope: None,
            unless,
            not: None,
            downgrade,
            defined_in: std::path::PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
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

    fn make_trait_def(
        r#if: Condition,
        unless: Option<Vec<Condition>>,
        downgrade: Option<DowngradeConditions>,
    ) -> TraitDefinition {
        TraitDefinition {
            id: "atomic-trait".to_string(),
            desc: "atomic".to_string(),
            conf: 1.0,
            crit: Criticality::Suspicious,
            r#if,
            r#for: vec![FileType::All],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            unless,
            not: None,
            downgrade,
            defined_in: std::path::PathBuf::from("test.yaml"),
            ..Default::default()
        }
    }

    // Atomic traits reference other traits in `if:`, `unless:`, and `downgrade:`;
    // those refs went unvalidated before `collect_trait_refs_from_trait_def`, so a
    // dangling exemption (e.g. a YAML-filename-in-ID `unless`) silently became a
    // no-op rather than a load error.
    #[test]
    fn test_collect_refs_from_atomic_trait_covers_if_unless_downgrade() {
        let trait_def = make_trait_def(
            Condition::Trait {
                id: "if-ref".to_string(),
            },
            Some(vec![Condition::Trait {
                id: "unless-ref".to_string(),
            }]),
            Some(DowngradeConditions {
                all: Some(vec![Condition::Trait {
                    id: "dg-all-ref".to_string(),
                }]),
                any: None,
                none: None,
                needs: None,
            }),
        );

        let refs = collect_trait_refs_from_trait_def(&trait_def);
        let ids: Vec<&str> = refs.iter().map(|(id, _)| id.as_str()).collect();
        assert!(ids.contains(&"if-ref"), "if: ref must be collected");
        assert!(ids.contains(&"unless-ref"), "unless: ref must be collected");
        assert!(ids.contains(&"dg-all-ref"), "downgrade: ref must be collected");
        // Every collected ref is owned by the atomic trait.
        assert!(refs.iter().all(|(_, owner)| owner == "atomic-trait"));
    }

    // A non-trait `if:` (raw/pattern condition) yields no refs, and an atomic trait
    // with no exemptions is ref-free — the common case must not spuriously report refs.
    #[test]
    fn test_collect_refs_from_atomic_trait_ignores_non_trait_conditions() {
        let trait_def = make_trait_def(
            Condition::Raw {
                exact: Some("marker".to_string()),
                substr: None,
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
            None,
            None,
        );

        assert!(collect_trait_refs_from_trait_def(&trait_def).is_empty());
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
            r#if: Condition::Raw {
                exact: Some("test".to_string()),
                substr: None,
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
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            r#for: vec![FileType::All],
            for_from_groups: false,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yml"),
            precision: None,
            ..Default::default()
        }
    }

    fn make_composite(
        id: &str,
        all_conditions: Vec<Condition>,
        downgrade: Option<DowngradeConditions>,
    ) -> CompositeTrait {
        CompositeTrait {
            required_trait_indices: Vec::new(),
            id: id.to_string(),
            desc: "composite".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Suspicious,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            for_from_groups: false,
            size_min: None,
            size_max: None,
            all: Some(all_conditions),
            any: None,
            needs: None,
            near_lines: None,
            near_bytes: None,
            scope: None,
            unless: None,
            not: None,
            downgrade,
            defined_in: PathBuf::from("test.yml"),
            precision: None,
            ..Default::default()
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
            r#if: Condition::Raw {
                exact: Some("test".to_string()),
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
            for_from_groups: false,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
        }
    }

    fn trait_with_for_from_groups(id: &str, types: Vec<FileType>) -> TraitDefinition {
        let mut t = trait_with_for(id, types);
        t.for_from_groups = true;
        t
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
    fn test_eight_types_accepted() {
        // 8 hand-picked types that don't form a canonical group — accepted
        // (a spread across groups that no single named group expresses).
        let traits = vec![trait_with_for(
            "test::eight-types",
            vec![
                FileType::Elf,
                FileType::Macho,
                FileType::Pe,
                FileType::Class,
                FileType::Pyc,
                FileType::Python,
                FileType::Shell,
                FileType::Php,
            ],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert!(result.is_empty(), "8 explicit types should be accepted");
    }

    #[test]
    fn test_exactly_threshold_flagged() {
        // 9 types that don't form a canonical group — must be flagged
        let traits = vec![trait_with_for(
            "test::nine-types",
            vec![
                FileType::Elf,
                FileType::Macho,
                FileType::Pe,
                FileType::Class,
                FileType::Pyc,
                FileType::Python,
                FileType::Shell, // not the canonical `binaries` set
                FileType::Php,
                FileType::JavaScript,
            ],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "test::nine-types");
        assert_eq!(result[0].1, 9);
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
                FileType::Jcl,
                FileType::Python,
                FileType::JavaScript,
                FileType::Ruby,
                FileType::Php,
                FileType::Perl,
                FileType::Lua,
                FileType::PowerShell,
                FileType::AppleScript,
                FileType::Vbs,
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
                FileType::Swift,
                FileType::Kotlin,
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
                FileType::Php,
                FileType::Java,
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
            FileType::Jcl,
            FileType::Python,
            FileType::JavaScript,
            FileType::Ruby,
            FileType::Php,
            FileType::Perl,
            FileType::Lua,
            FileType::PowerShell,
            FileType::AppleScript,
            FileType::Vbs,
        ];
        let binaries = vec![
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
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
        ];
        let combined: Vec<FileType> = scripts.into_iter().chain(binaries).chain(source).collect();
        assert_eq!(combined.len(), 31);
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
                FileType::Php,
                FileType::Lua,
            ],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert_eq!(result.len(), 1, "partial group selection should still warn");
    }

    #[test]
    fn test_composite_rule_flagged() {
        let rule = CompositeTrait {
            required_trait_indices: Vec::new(),
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
                FileType::Class,
                FileType::Pyc,
                FileType::Python,
                FileType::Shell, // not the canonical `binaries` set
                FileType::Php,
                FileType::JavaScript,
            ],
            for_from_groups: false,
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            needs: None,
            near_lines: None,
            near_bytes: None,
            scope: None,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yaml"),
            precision: None,
            ..Default::default()
        };
        let result = find_excessive_file_types(&[], &[rule]);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "test::composite-many");
        assert!(result[0].3); // is_composite
    }

    #[test]
    fn test_from_groups_skips_check_with_many_types() {
        // `for: [binaries, c]` expands to 9 types with for_from_groups=true.
        // After platform filtering the set may be a partial group, but the
        // author already used named groups — don't flag it.
        let traits = vec![trait_with_for_from_groups(
            "test::groups-plus-extra",
            vec![
                FileType::Elf,
                FileType::Macho,
                FileType::Pe,
                FileType::Class,
                FileType::Pyc,
                FileType::C,
            ],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert!(
            result.is_empty(),
            "for_from_groups=true should suppress the warning"
        );
    }

    #[test]
    fn test_from_groups_platform_filtered_not_flagged() {
        // `for: [scripts, binaries]` after platform filtering for unix-only:
        // PE/DLL/Batch/VBS removed → partial groups. Still exempt because
        // for_from_groups=true.
        let traits = vec![trait_with_for_from_groups(
            "test::filtered-groups",
            vec![
                FileType::Elf,
                FileType::Macho,
                FileType::Class,
                FileType::Pyc,
                FileType::Shell,
                FileType::Python,
                FileType::JavaScript,
                FileType::Ruby,
                FileType::Php,
                FileType::Perl,
                FileType::Lua,
                FileType::AppleScript,
            ],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert!(
            result.is_empty(),
            "platform-filtered groups should not be flagged"
        );
    }

    #[test]
    fn test_not_from_groups_still_flagged() {
        // Same 14 types but for_from_groups=false — author manually listed them.
        let traits = vec![trait_with_for(
            "test::manual-many",
            vec![
                FileType::Elf,
                FileType::Macho,
                FileType::Class,
                FileType::Pyc,
                FileType::Shell,
                FileType::Python,
                FileType::JavaScript,
                FileType::Ruby,
                FileType::Php,
                FileType::Perl,
                FileType::Lua,
                FileType::AppleScript,
            ],
        )];
        let result = find_excessive_file_types(&traits, &[]);
        assert_eq!(result.len(), 1, "manual listing should still be flagged");
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
            ..Default::default()
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
            condition: None,
            near_lines: None,
            near_bytes: None,
            scope: None,
            unless: None,
            not: None,
            downgrade: None,
            ..Default::default()
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

#[cfg(test)]
mod raw_should_use_string_value_tests {
    use crate::capabilities::validation::patterns::find_raw_should_use_string_value;
    use crate::composite_rules::{Arch, Condition, FileType, Platform, TraitDefinition};
    use std::path::PathBuf;

    fn binary_trait(id: &str, condition: Condition) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.8,
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
            r#for: vec![FileType::Elf, FileType::Pe, FileType::Macho],
            for_from_groups: false,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yml"),
            precision: None,
            ..Default::default()
        }
    }

    fn raw_substr(pattern: &str) -> Condition {
        Condition::Raw {
            exact: None,
            substr: Some(pattern.to_string()),
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
        }
    }

    fn raw_regex(pattern: &str) -> Condition {
        Condition::Raw {
            exact: None,
            substr: None,
            regex: Some(pattern.to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        }
    }

    #[test]
    fn flags_long_substr_on_binary() {
        let traits = vec![binary_trait(
            "t/long-substr",
            raw_substr("MobileDeviceUpdater"),
        )];
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&traits, &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("MobileDeviceUpdater"));
        assert!(warnings[0].contains("type: text"));
    }

    #[test]
    fn skips_short_substr_on_binary() {
        let traits = vec![binary_trait("t/short", raw_substr("abc"))];
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&traits, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn flags_literal_regex_on_binary() {
        let traits = vec![binary_trait("t/literal-regex", raw_regex("scrobj\\.dll"))];
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&traits, &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("scrobj\\.dll"));
    }

    #[test]
    fn skips_regex_with_metacharacters() {
        let traits = vec![binary_trait("t/real-regex", raw_regex("^GIF8[79]a"))];
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&traits, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn skips_regex_with_alternation() {
        let traits = vec![binary_trait("t/alternation", raw_regex("pytest|def test_"))];
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&traits, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn flags_source_types() {
        let mut t = binary_trait("t/script", raw_substr("long_pattern_here"));
        t.r#for = vec![FileType::Shell];
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&[t], &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("type: text"));
    }

    #[test]
    fn flags_plain_text_on_all_file_types() {
        // Plain extractable text is reachable by `type: text` for EVERY file
        // type (flat strings extraction), so `for: [all]` no longer skips.
        let mut t = binary_trait("t/all", raw_substr("long_pattern_here"));
        t.r#for = vec![FileType::All];
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&[t], &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("type: text"));
    }

    #[test]
    fn skips_with_offset_constraint() {
        let t = binary_trait(
            "t/offset",
            Condition::Raw {
                exact: None,
                substr: Some("long_pattern_here".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                not: None,
                section: None,
                offset: Some(0),
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
            },
        );
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&[t], &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn skips_with_section_constraint() {
        let t = binary_trait(
            "t/section",
            Condition::Raw {
                exact: None,
                substr: Some("long_pattern_here".to_string()),
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                not: None,
                section: Some(".text".to_string()),
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
            },
        );
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&[t], &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn skips_with_density_constraints() {
        let mut t = binary_trait("t/density", raw_substr("long_pattern_here"));
        t.count_min = Some(5);
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&[t], &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn flags_macho_type() {
        let mut t = binary_trait("t/macho", raw_substr("long_pattern_here"));
        t.r#for = vec![FileType::Macho];
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&[t], &mut warnings);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn flags_plain_text_on_mixed_binary_and_script_types() {
        // Plain extractable text is flagged regardless of the `for:` mix —
        // string extraction surfaces it for every file type.
        let mut t = binary_trait("t/mixed", raw_substr("long_pattern_here"));
        t.r#for = vec![FileType::Elf, FileType::Shell];
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&[t], &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("type: text"));
    }

    #[test]
    fn skips_short_literal_regex() {
        let traits = vec![binary_trait("t/short-re", raw_regex("abc"))];
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&traits, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn flags_raw_on_source_type() {
        let mut t = binary_trait("t/source-raw", raw_substr("document.cookie"));
        t.r#for = vec![FileType::JavaScript];
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&[t], &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("type: text"));
    }
}

#[cfg(test)]
mod section_filter_validation_tests {
    use crate::capabilities::validation::taxonomy::{
        find_meta_missing_section_filter, find_wellknown_missing_section_filter,
    };
    use crate::composite_rules::{Arch, Condition, FileType, Platform, TraitDefinition};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn text_trait(id: &str, for_types: Vec<FileType>) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.8,
            crit: crate::types::Criticality::Notable,
            mbc: None,
            attack: None,
            r#if: Condition::Text {
                exact: None,
                substr: Some("ProjectDiscovery".to_string()),
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
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            r#for: for_types,
            for_from_groups: false,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yml"),
            precision: None,
            ..Default::default()
        }
    }

    #[test]
    fn wellknown_section_filter_skips_mixed_binary_and_script_targets() {
        let traits = vec![text_trait(
            "well-known/tool/test::mixed",
            vec![FileType::Pe, FileType::Shell],
        )];
        let mut sources = HashMap::new();
        sources.insert(
            "well-known/tool/test::mixed".to_string(),
            "./well-known/tool/test/traits.yaml".to_string(),
        );
        let result = find_wellknown_missing_section_filter(&traits, &sources);
        assert!(result.is_empty());
    }

    #[test]
    fn wellknown_section_filter_flags_binary_only_targets() {
        let traits = vec![text_trait(
            "well-known/tool/test::binary",
            vec![FileType::Pe],
        )];
        let mut sources = HashMap::new();
        sources.insert(
            "well-known/tool/test::binary".to_string(),
            "./well-known/tool/test/traits.yaml".to_string(),
        );
        let result = find_wellknown_missing_section_filter(&traits, &sources);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "well-known/tool/test::binary");
    }

    #[test]
    fn metadata_section_filter_skips_mixed_binary_and_script_targets() {
        let traits = vec![text_trait(
            "metadata/binary/test::mixed",
            vec![FileType::Pe, FileType::Shell],
        )];
        let mut sources = HashMap::new();
        sources.insert(
            "metadata/binary/test::mixed".to_string(),
            "./metadata/binary/test/traits.yaml".to_string(),
        );
        let result = find_meta_missing_section_filter(&traits, &sources);
        assert!(result.is_empty());
    }
}

#[cfg(test)]
mod string_literal_should_use_text_tests {
    use crate::capabilities::validation::patterns::find_string_literal_should_use_text;
    use crate::composite_rules::{Arch, Condition, FileType, Platform, TraitDefinition};
    use std::path::PathBuf;

    fn source_trait(id: &str, condition: Condition, file_type: FileType) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.8,
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
            r#for: vec![file_type],
            for_from_groups: false,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yml"),
            precision: None,
            ..Default::default()
        }
    }

    #[test]
    fn flags_code_structure_pattern() {
        let t = source_trait(
            "t::literal-eval",
            Condition::Literal {
                kind: None,
                exact: None,
                substr: Some("eval(".to_string()),
                regex: None,
                word: None,
                value: None,
                radix: None,
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
            FileType::Python,
        );
        let mut warnings = Vec::new();
        find_string_literal_should_use_text(&[t], &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("type: text"));
    }
}

#[cfg(test)]
mod ast_function_call_should_use_symbol_tests {
    use crate::capabilities::validation::patterns::find_ast_function_call_should_use_symbol;
    use crate::composite_rules::{Arch, Condition, FileType, Platform, TraitDefinition};
    use std::path::PathBuf;

    fn make_trait(id: &str, condition: Condition, for_types: Vec<FileType>) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.8,
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
            r#for: for_types,
            for_from_groups: false,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            not: None,
            unless: None,
            downgrade: None,
            defined_in: PathBuf::from("test.yml"),
            precision: None,
            ..Default::default()
        }
    }

    fn text_substr(value: &str) -> Condition {
        Condition::Text {
            exact: None,
            substr: Some(value.to_string()),
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
        }
    }

    fn text_regex(value: &str) -> Condition {
        Condition::Text {
            exact: None,
            substr: None,
            regex: Some(value.to_string()),
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
        }
    }

    #[test]
    fn flags_substr_eval_paren_on_javascript() {
        let t = make_trait("t::eval", text_substr("eval("), vec![FileType::JavaScript]);
        let mut warnings = Vec::new();
        find_ast_function_call_should_use_symbol(&[t], &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("type: symbol"));
        assert!(warnings[0].contains("exact: eval"));
    }

    #[test]
    fn flags_regex_with_leading_boundary_on_python() {
        let t = make_trait(
            "t::eval-py",
            text_regex(r"(^|[^\w$])eval\s*\("),
            vec![FileType::Python],
        );
        let mut warnings = Vec::new();
        find_ast_function_call_should_use_symbol(&[t], &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("exact: eval"));
    }

    #[test]
    fn flags_when_all_for_types_are_ast_sources() {
        let t = make_trait(
            "t::eval-multi",
            text_substr("eval("),
            vec![FileType::JavaScript, FileType::TypeScript, FileType::Python],
        );
        let mut warnings = Vec::new();
        find_ast_function_call_should_use_symbol(&[t], &mut warnings);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn skips_when_any_for_type_is_non_ast() {
        // Mixing an AST language with a binary type means symbol semantics
        // diverge — leave it alone.
        let t = make_trait(
            "t::eval-mixed",
            text_substr("eval("),
            vec![FileType::JavaScript, FileType::Pe],
        );
        let mut warnings = Vec::new();
        find_ast_function_call_should_use_symbol(&[t], &mut warnings);
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn skips_when_for_is_empty() {
        // Empty `for:` means "all" — includes binary types.
        let t = make_trait("t::eval-all", text_substr("eval("), vec![]);
        let mut warnings = Vec::new();
        find_ast_function_call_should_use_symbol(&[t], &mut warnings);
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn skips_method_calls_with_dot() {
        // `obj.method(` is not a top-level symbol — leave as text.
        let t = make_trait(
            "t::method",
            text_substr("console.log("),
            vec![FileType::JavaScript],
        );
        let mut warnings = Vec::new();
        find_ast_function_call_should_use_symbol(&[t], &mut warnings);
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn skips_patterns_with_arguments() {
        // `eval(arg)` includes argument-shape matching that symbol can't replace.
        let t = make_trait(
            "t::eval-arg",
            text_regex(r"eval\(\w+\)"),
            vec![FileType::JavaScript],
        );
        let mut warnings = Vec::new();
        find_ast_function_call_should_use_symbol(&[t], &mut warnings);
        assert_eq!(warnings.len(), 0);
    }

    #[test]
    fn skips_when_no_paren() {
        // Plain identifier — already a candidate for word/symbol but not the
        // shape this check targets.
        let t = make_trait("t::just-name", text_substr("eval"), vec![FileType::Python]);
        let mut warnings = Vec::new();
        find_ast_function_call_should_use_symbol(&[t], &mut warnings);
        assert_eq!(warnings.len(), 0);
    }
}
