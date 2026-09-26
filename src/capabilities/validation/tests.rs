//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for validation module.
//!
//! Tests are organized by submodule to match the module structure.

#[cfg(test)]
mod precision_tests {
    use crate::capabilities::validation::precision::calculate_trait_precision;
    use crate::composite_rules::{Arch, Condition, FileType, Platform, RawQuery, TraitDefinition};
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
        let mut trait_def = create_minimal_trait(Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
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
        }));
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
        let mut trait_def = create_minimal_trait(Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
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
        }));
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
    use crate::composite_rules::condition::{ArgFilter, EncodingSpec, SymbolKind};
    use crate::composite_rules::{
        Arch, Condition, EncodedQuery, FileType, LiteralQuery, PathQuery, Platform, RawQuery,
        SymbolQuery, TextQuery, TraitDefinition,
    };
    use std::path::PathBuf;

    // ========================================================================
    // Test Helpers
    // ========================================================================

    /// Create a minimal trait definition for testing
    /// A `type: text` `substr:` condition, optionally pinned to a section.
    fn text_substr_cond(value: &str, section: Option<&str>) -> Condition {
        Condition::Text(TextQuery {
            encoding: None,
            length_min: None,
            length_max: None,
            exact: None,
            substr: Some(value.to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            platforms: None,
            section: section.map(str::to_string),
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        })
    }

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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Text(TextQuery {
                encoding: None,
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Literal(LiteralQuery {
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
            }),
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Encoded(EncodedQuery {
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
            }),
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Symbol(SymbolQuery {
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
            }),
            for_types,
            file_path,
        )
    }

    fn create_symbol_exact_with_kind(
        id: &str,
        pattern: &str,
        kind: SymbolKind,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Symbol(SymbolQuery {
                exact: Some(pattern.to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: Some(kind),
                arg: None,
                args: None,
                alias: None,
                not: None,
            }),
            for_types,
            file_path,
        )
    }

    fn create_symbol_exact_with_arg(
        id: &str,
        pattern: &str,
        arg: &str,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Symbol(SymbolQuery {
                exact: Some(pattern.to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: Some(SymbolKind::Call),
                arg: Some(ArgFilter {
                    exact: Some(arg.to_string()),
                    ..Default::default()
                }),
                args: None,
                alias: None,
                not: None,
            }),
            for_types,
            file_path,
        )
    }

    fn create_text_regex_trait(
        id: &str,
        pattern: &str,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Text(TextQuery {
                regex: Some(pattern.to_string()),
                ..Default::default()
            }),
            for_types,
            file_path,
        )
    }

    fn create_string_literal_regex(
        id: &str,
        pattern: &str,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Literal(LiteralQuery {
                regex: Some(pattern.to_string()),
                ..Default::default()
            }),
            for_types,
            file_path,
        )
    }

    fn create_text_word(
        id: &str,
        pattern: &str,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Text(TextQuery {
                word: Some(pattern.to_string()),
                ..Default::default()
            }),
            for_types,
            file_path,
        )
    }

    fn create_text_substr(
        id: &str,
        pattern: &str,
        for_types: Vec<FileType>,
        file_path: &str,
    ) -> TraitDefinition {
        create_test_trait(
            id,
            Condition::Text(TextQuery {
                substr: Some(pattern.to_string()),
                ..Default::default()
            }),
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Path(PathQuery {
                exact: None,
                substr: None,
                regex: Some(pattern.to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            for_types,
            file_path,
        )
    }

    // ========================================================================
    // Phase 1: Hex Escape Normalization Tests
    // ========================================================================

    /// A whole-file content matcher inlined in `unless:` while the identical
    /// matcher already exists as a named trait must be reported — it is invisible
    /// to every other duplicate check, so the two copies silently drift apart.
    #[test]
    fn test_inline_content_matcher_duplicating_named_trait_is_flagged() {
        let owner = create_test_trait(
            "pack/detect::enigma-protector",
            text_substr_cond("Enigma Protector", None),
            vec![FileType::Pe],
            "pack.yaml",
        );
        let mut borrower = create_test_trait(
            "hardening/memory::wx-section",
            text_substr_cond("writable executable", None),
            vec![FileType::Pe],
            "wx.yaml",
        );
        borrower.unless = Some(vec![text_substr_cond("Enigma Protector", None)]);

        let found = find_inline_content_duplicates(&[owner, borrower], &[]);
        assert_eq!(found.len(), 1, "expected one finding, got {found:?}");
        assert_eq!(found[0].0, "hardening/memory::wx-section");
        assert_eq!(found[0].1, "unless");
        assert!(
            found[0].3.contains("pack/detect::enigma-protector"),
            "advice should name the trait to reference: {}",
            found[0].3
        );
    }

    /// A matcher pinned to a section is not the same assertion as the same
    /// pattern searched file-wide, so it must not be reported as a duplicate.
    #[test]
    fn test_section_pinned_inline_is_not_a_content_duplicate() {
        let owner = create_test_trait(
            "a::file-wide",
            text_substr_cond("Enigma Protector", None),
            vec![FileType::Pe],
            "a.yaml",
        );
        let mut borrower = create_test_trait(
            "b::section-pinned",
            text_substr_cond("something else", None),
            vec![FileType::Pe],
            "b.yaml",
        );
        borrower.unless = Some(vec![text_substr_cond("Enigma Protector", Some(".rsrc"))]);
        assert!(
            find_inline_content_duplicates(&[owner, borrower], &[]).is_empty(),
            "a section-pinned inline is a different assertion"
        );
    }

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

    /// A kinded symbol and a text matcher for the same API name are the same
    /// evidence read off two surfaces. Keying the symbol as
    /// `<literal>#kind:Call` used to file it in a bucket no text matcher could
    /// reach, so this pair -- by far the most common duplicate shape in the
    /// tree -- went unreported.
    #[test]
    fn test_cross_type_flags_kinded_symbol_against_text_word() {
        let symbol = create_symbol_exact_with_kind(
            "micro-behaviors/fs/write/file/direct::php-file-put-contents",
            "file_put_contents",
            SymbolKind::Call,
            vec![FileType::Php],
            "micro-behaviors/fs/write/file/direct/write-php.yaml",
        );
        let text = create_text_word(
            "micro-behaviors/fs/write/file/direct::file-put-contents",
            "file_put_contents",
            vec![FileType::Php],
            "micro-behaviors/fs/write/file/direct/php.yaml",
        );

        let mut warnings = Vec::new();
        check_same_string_different_types(&[symbol, text], &mut warnings);

        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("file_put_contents"));
        // The advice must preserve both surfaces: a stripped binary keeps the
        // string and loses the symbol, and a source file does the reverse.
        assert!(warnings[0].contains("`any:` composite"));
    }

    /// `word` and `exact` both demand the whole token, so they are the same
    /// question asked on two surfaces even though they are spelled differently.
    #[test]
    fn test_cross_type_flags_word_against_exact() {
        let symbol = create_symbol_exact(
            "micro-behaviors/communications/http/client/winhttp::winhttp-connect",
            "WinHttpConnect",
            vec![FileType::Pe],
            "micro-behaviors/communications/http/client/winhttp/traits.yaml",
        );
        let text = create_text_word(
            "micro-behaviors/communications/http/client/winhttp::winhttp-connect-api-name",
            "WinHttpConnect",
            vec![FileType::Pe],
            "micro-behaviors/communications/http/client/winhttp/traits.yaml",
        );

        let mut warnings = Vec::new();
        check_same_string_different_types(&[symbol, text], &mut warnings);

        assert_eq!(warnings.len(), 1);
    }

    /// Exporting an API is the opposite of calling it: the file implements the
    /// Windows surface rather than abusing it, which is exactly what
    /// metadata/binary/vendor distinguishes. Pairing an export with a text
    /// reference would call a discriminator a duplicate of what it discriminates.
    #[test]
    fn test_cross_type_keeps_export_against_text_reference() {
        let export = create_symbol_exact_with_kind(
            "metadata/binary/vendor::exports-mem-map-inject-api--virtualallocex",
            "VirtualAllocEx",
            SymbolKind::Export,
            vec![FileType::Pe],
            "metadata/binary/vendor/wine.yaml",
        );
        let text = create_text_word(
            "micro-behaviors/mem/alloc/remote::virtual-alloc-ex-text",
            "VirtualAllocEx",
            vec![FileType::Pe],
            "micro-behaviors/mem/alloc/remote/traits.yaml",
        );

        let mut warnings = Vec::new();
        check_same_string_different_types(&[export, text], &mut warnings);

        assert_eq!(warnings.len(), 0);
    }

    /// Four same-context, same-tier regexes matching one literal phrase is the
    /// shape this reports: the phrase is covered several times over.
    #[test]
    fn test_literal_covered_by_four_regexes() {
        let mut defs = vec![create_text_word(
            "micro-behaviors/os/module/load::get-proc-address-reference",
            "GetProcAddress",
            vec![FileType::Pe],
            "micro-behaviors/os/module/load/windows-loader.yaml",
        )];
        for (i, pat) in [
            r"(?m)^GetProcAddress$",
            r"(?i)getprocaddress",
            r"\bGetProcAddress\b",
            r"Get(Proc|Module)Address",
        ]
        .iter()
        .enumerate()
        {
            defs.push(create_text_regex_trait(
                &format!("objectives/evasion/dynamic::resolver-{i}"),
                pat,
                vec![FileType::Pe],
                "objectives/evasion/dynamic/traits.yaml",
            ));
        }

        let mut warnings = Vec::new();
        find_literals_covered_by_regexes(&defs, &mut warnings);

        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("GetProcAddress"));
        assert!(warnings[0].contains("consolidate"));
    }

    /// Literal coverage served from stored facts reports exactly what a run
    /// without them does, and a one-byte edit to either side -- a regex, its
    /// flag, or the literal -- is recomputed rather than served stale.
    #[test]
    fn test_literal_coverage_with_stored_facts_matches_a_cold_run() {
        use crate::capabilities::validation::facts_cache;
        let _slot = facts_cache::TEST_SLOT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path().join("facts.bin");
        let tree = |literal: &str, patterns: &[&str]| {
            let mut defs = vec![create_text_word(
                "micro-behaviors/os/module/load::get-proc-address-reference",
                literal,
                vec![FileType::Pe],
                "micro-behaviors/os/module/load/windows-loader.yaml",
            )];
            for (i, pat) in patterns.iter().enumerate() {
                defs.push(create_text_regex_trait(
                    &format!("objectives/evasion/dynamic::resolver-{i}"),
                    pat,
                    vec![FileType::Pe],
                    "objectives/evasion/dynamic/traits.yaml",
                ));
            }
            defs
        };
        let run = |defs: &[TraitDefinition], with_facts: bool| {
            let _session = with_facts.then(|| facts_cache::begin_at(&store));
            let mut warnings = Vec::new();
            find_literals_covered_by_regexes(defs, &mut warnings);
            warnings
        };
        let patterns = [
            r"(?m)^GetProcAddress$",
            r"(?i)getprocaddress",
            r"\bGetProcAddress\b",
            r"Get(Proc|Module)Address",
        ];

        let base = tree("GetProcAddress", &patterns);
        let cold = run(&base, false);
        assert_eq!(cold.len(), 1, "{cold:?}");
        assert_eq!(run(&base, true), cold);
        assert!(facts_cache::stored_entries(&store) > 0);
        assert_eq!(run(&base, true), cold);

        for edited in [
            // One byte of one regex: it stops covering the literal.
            tree(
                "GetProcAddress",
                &[patterns[0], patterns[1], r"\bGetProcAddresz\b", patterns[3]],
            ),
            // A flag: without (?i) the lowercase regex no longer matches.
            tree(
                "GetProcAddress",
                &[patterns[0], "getprocaddress", patterns[2], patterns[3]],
            ),
            // The literal side: no regex covers the new phrase.
            tree("GetProcAddresz", &patterns),
        ] {
            let expected = run(&edited, false);
            assert!(expected.is_empty(), "{expected:?}");
            assert_eq!(run(&edited, true), expected);
        }
        // The original tree is still served correctly after the edits.
        assert_eq!(run(&base, true), cold);
    }

    /// Three is under the threshold: a couple of rules sharing a token is
    /// ordinary, and reporting it would bury the real cases.
    #[test]
    fn test_literal_covered_by_three_regexes_is_quiet() {
        let mut defs = vec![create_text_word(
            "micro-behaviors/os/module/load::get-proc-address-reference",
            "GetProcAddress",
            vec![FileType::Pe],
            "micro-behaviors/os/module/load/windows-loader.yaml",
        )];
        for (i, pat) in [
            r"GetProcAddress\s*\(",
            r"(?i)getprocaddress",
            r"\bGetProcAddress\b",
        ]
        .iter()
        .enumerate()
        {
            defs.push(create_text_regex_trait(
                &format!("objectives/evasion/dynamic::resolver-{i}"),
                pat,
                vec![FileType::Pe],
                "objectives/evasion/dynamic/traits.yaml",
            ));
        }

        let mut warnings = Vec::new();
        find_literals_covered_by_regexes(&defs, &mut warnings);

        assert!(warnings.is_empty(), "{warnings:?}");
    }

    /// A regex that needs context the phrase does not carry is not counted, even
    /// though both rules fire on a real file. Counting it would mean guessing at
    /// what surrounds the phrase.
    #[test]
    fn test_literal_coverage_ignores_regexes_needing_context() {
        let mut defs = vec![create_text_word(
            "micro-behaviors/os/module/load::get-proc-address-reference",
            "GetProcAddress",
            vec![FileType::Pe],
            "micro-behaviors/os/module/load/windows-loader.yaml",
        )];
        for (i, pat) in [
            r"GetProcAddress\s*\(",
            r"GetProcAddress[^\n]{0,80}LoadLibrary",
            r"LoadLibrary[^\n]{0,80}GetProcAddress",
            r"\bGetProcAddress\b\s*=\s*\w+",
        ]
        .iter()
        .enumerate()
        {
            defs.push(create_text_regex_trait(
                &format!("objectives/evasion/dynamic::resolver-{i}"),
                pat,
                vec![FileType::Pe],
                "objectives/evasion/dynamic/traits.yaml",
            ));
        }

        let mut warnings = Vec::new();
        find_literals_covered_by_regexes(&defs, &mut warnings);

        assert!(warnings.is_empty(), "{warnings:?}");
    }

    /// A literal `#` inside a pattern is not a symbol discriminator. Splitting
    /// on the first one truncated these regexes to a shared `[?&]\w{1,24}=[^&`
    /// prefix and filed four unrelated injection patterns in one bucket.
    #[test]
    fn test_cross_type_keeps_regexes_sharing_only_a_prefix() {
        let text = create_text_regex_trait(
            "objectives/execution/exploit/http-command-injection::url-pipe-interpreter-raw",
            r#"(?i)[?&]\w{1,24}=[^&#\r\n"]{0,48}\| *(sh|bash)\b"#,
            vec![FileType::Python],
            "objectives/execution/exploit/http-command-injection/remote-query.yaml",
        );
        let literal = create_string_literal_regex(
            "objectives/execution/exploit/http-command-injection::url-pipe-command-encoded",
            r#"(?i)[?&]\w{1,24}=[^&#]{0,48}%7c(%20|\+)*(id|whoami)\b"#,
            vec![FileType::Python],
            "objectives/execution/exploit/http-command-injection/remote-query.yaml",
        );

        let mut warnings = Vec::new();
        check_same_string_different_types(&[text, literal], &mut warnings);

        assert_eq!(warnings.len(), 0);
    }

    /// A text matcher that stands down wherever the symbol matcher fires is the
    /// runtime-resolution case: the API name is present as a string but the
    /// binary does not import it. That is distinct evidence, not a second
    /// reading of the same fact.
    #[test]
    fn test_cross_type_keeps_pair_where_one_suppresses_the_other() {
        let symbol = create_symbol_exact(
            "micro-behaviors/communications/http/client/winhttp::winhttp-connect",
            "WinHttpConnect",
            vec![FileType::Pe],
            "micro-behaviors/communications/http/client/winhttp/traits.yaml",
        );
        let mut text = create_text_word(
            "micro-behaviors/communications/http/client/winhttp::winhttp-connect-api-name",
            "WinHttpConnect",
            vec![FileType::Pe],
            "micro-behaviors/communications/http/client/winhttp/traits.yaml",
        );
        text.unless = Some(vec![Condition::Trait {
            id: "winhttp-connect".to_string(),
        }]);

        let mut warnings = Vec::new();
        check_same_string_different_types(&[symbol, text], &mut warnings);

        assert_eq!(warnings.len(), 0);
    }

    /// `substr` reaches inside longer tokens (`WriteFile` inside
    /// `WriteFileEx`), so pairing it with a whole-token matcher would call two
    /// different reaches a duplicate and invite the author to drop the broader
    /// one -- a loss of detection, which is the opposite of the point.
    #[test]
    fn test_cross_type_keeps_substr_against_whole_token_match() {
        let symbol = create_symbol_exact(
            "micro-behaviors/fs/write/file/direct::write-file",
            "WriteFile",
            vec![FileType::Pe],
            "micro-behaviors/fs/write/file/direct/file-write.yaml",
        );
        let text = create_text_substr(
            "micro-behaviors/fs/write/file/direct::native-binary-write-file-text",
            "WriteFile",
            vec![FileType::Pe],
            "micro-behaviors/fs/write/file/direct/go-binary.yaml",
        );

        let mut warnings = Vec::new();
        check_same_string_different_types(&[symbol, text], &mut warnings);

        assert_eq!(warnings.len(), 0);
    }

    /// An `arg:` filter changes which fact the token names: `require('fs')` is
    /// not `require('dns')`, and a text matcher for the bare token is neither
    /// of them. Only `kind:` -- which narrows where the token was found, not
    /// what it means -- may be dropped when comparing across surfaces.
    #[test]
    fn test_cross_type_keeps_arg_discriminated_symbol_against_text() {
        let symbol = create_symbol_exact_with_arg(
            "micro-behaviors/process/create/spawn::require-child-process",
            "require",
            "child_process",
            vec![FileType::JavaScript],
            "micro-behaviors/process/create/spawn/javascript.yaml",
        );
        let text = create_text_word(
            "metadata/lang/scripted::js-require-keyword",
            "require",
            vec![FileType::JavaScript],
            "metadata/lang/scripted/javascript.yaml",
        );

        let mut warnings = Vec::new();
        check_same_string_different_types(&[symbol, text], &mut warnings);

        assert_eq!(warnings.len(), 0);
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

    #[test]
    fn test_regex_contains_literal_after_leading_metacharacters() {
        let exact = create_string_exact(
            "test::exact",
            ".exe",
            false,
            vec![FileType::All],
            "file1.yaml",
        );
        let regex = create_string_regex(
            "test::regex",
            r".*\.exe",
            false,
            vec![FileType::All],
            "file2.yaml",
        );

        let mut warnings = Vec::new();
        check_regex_contains_literal(&[exact, regex], &mut warnings);

        assert_eq!(warnings.len(), 1);
    }

    /// Every pair the regex-vs-literal check can report must be among the
    /// candidates its index proposes, or the report silently loses it.
    #[test]
    fn test_regex_literal_candidates_cover_every_reportable_pair() {
        use std::collections::HashMap;

        let regexes = [
            "foo.*", ".*foo", "^foo$", r".*\.exe", r"7z\.exe", "foo", "a.b", r"\.\*", ".*", "",
            "x+foo?", "foo.*bar", r"\\", "^.*", "fo.o", "foo.*foo", "..foo..",
        ];
        let literals = [
            "foo", ".exe", "exe", "7z.exe", "", "a.b", ".*", r"\", "bar", "FOO", "fo.o",
            "foo.*bar", "..", "o",
        ];
        let normalized: Vec<String> = literals
            .iter()
            .map(|literal| normalize_pattern_for_comparison(literal, false))
            .collect();
        let mut by_normalized: HashMap<&str, Vec<usize>> = HashMap::new();
        let mut by_escaped: HashMap<String, Vec<usize>> = HashMap::new();
        for (idx, literal) in literals.iter().enumerate() {
            by_normalized
                .entry(normalized[idx].as_str())
                .or_default()
                .push(idx);
            by_escaped
                .entry(regex::escape(literal))
                .or_default()
                .push(idx);
        }

        for pattern in regexes {
            let pattern_normalized = normalize_pattern_for_comparison(pattern, true);
            let candidates =
                regex_literal_candidates(pattern, &pattern_normalized, &by_normalized, &by_escaped);
            for (idx, literal) in literals.iter().enumerate() {
                let reportable = pattern_normalized == normalized[idx]
                    || trivially_extends(pattern, &regex::escape(literal));
                assert!(
                    !reportable || candidates.contains(&idx),
                    "{pattern:?} vs {literal:?} is reportable but not a candidate"
                );
            }
        }
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
            vec![FileType::All],
            "file1.yaml",
            0.5, // conf = 0.5
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
            vec![FileType::All],
            "file1.yaml",
            0.5,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
            vec![FileType::All],
            "file1.yaml",
            0.5,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
            vec![FileType::All],
            "file2.yaml",
            0.9, // conf diff from trait1 = 0.4 >= 0.2
            crate::types::Criticality::Notable,
        );

        let trait3 = create_test_trait_with_conf_crit(
            "test::c",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
            vec![FileType::All],
            "file1.yaml",
            0.8,
            crate::types::Criticality::Notable,
        );

        let trait2 = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
            vec![FileType::All],
            "file2.yaml",
            0.9,                                // conf diff from trait1 = 0.1 < 0.2
            crate::types::Criticality::Notable, // Same as trait1 - FAILS carveout
        );

        let trait3 = create_test_trait_with_conf_crit(
            "test::c",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
                Condition::Path(PathQuery {
                    exact: Some("setup.py".to_string()),
                    substr: None,
                    regex: None,
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
                vec![FileType::Python],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Path(PathQuery {
                    exact: Some("setup.py".to_string()),
                    substr: None,
                    regex: None,
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
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
                Condition::Path(PathQuery {
                    exact: None,
                    substr: Some("chrome".to_string()),
                    regex: None,
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
                vec![FileType::All],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Path(PathQuery {
                    exact: None,
                    substr: Some("chrome".to_string()),
                    regex: None,
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
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
                Condition::Path(PathQuery {
                    exact: None,
                    substr: None,
                    regex: Some("\\.pyc$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
                vec![FileType::Python],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Path(PathQuery {
                    exact: None,
                    substr: None,
                    regex: Some("\\.pyc$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
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
                Condition::Path(PathQuery {
                    exact: None,
                    substr: None,
                    regex: Some("^Makefile$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
                vec![FileType::All],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Path(PathQuery {
                    exact: None,
                    substr: None,
                    regex: Some("^setup\\.py$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
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
            Condition::Path(PathQuery {
                exact: None,
                substr: None,
                regex: Some("(?i)^setup\\.py$".to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
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
                Condition::Path(PathQuery {
                    exact: None,
                    substr: None,
                    regex: Some("^(setup|install)\\.py$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
                vec![FileType::Python],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Path(PathQuery {
                    exact: None,
                    substr: None,
                    regex: Some(".*\\.exe$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
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
            Condition::Path(PathQuery {
                exact: None,
                substr: None,
                regex: None,
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
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
            Condition::Path(PathQuery {
                exact: None,
                substr: None,
                regex: Some(".".to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
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
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
                vec![FileType::Python],
                "file1.yaml",
            ),
            create_test_trait(
                "test2",
                Condition::Symbol(SymbolQuery {
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
                }),
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
                Condition::Path(PathQuery {
                    exact: Some("sshd".to_string()),
                    substr: None,
                    regex: None,
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
                vec![FileType::Shell],
                "file1.yaml",
            ),
            create_test_trait(
                "basename_regex",
                Condition::Path(PathQuery {
                    exact: None,
                    substr: None,
                    regex: Some("^(ssh|sshd|ssh_config)$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
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
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
                vec![FileType::Pe],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "regex_hostile",
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
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
                Condition::Path(PathQuery {
                    exact: None,
                    substr: None,
                    regex: Some("\\.(test|spec)\\.[cm]?[jt]sx?$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
                vec![FileType::JavaScript, FileType::TypeScript],
                "file1.yaml",
            ),
            create_test_trait(
                "superset",
                Condition::Path(PathQuery {
                    exact: None,
                    substr: None,
                    regex: Some("\\.(test|spec|bench)\\.[cm]?[jt]sx?$".to_string()),
                    case_insensitive: false,
                    is_check: None,
                    basename: true,
                    dirname: false,
                }),
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

    #[test]
    fn test_regex_regex_structurally_identical_shorthand_vs_class() {
        use crate::capabilities::validation::duplicates::check_overlapping_regex_patterns;

        // `\d{3}` and `[0-9]{3}` are the same language written two ways. The HIR
        // canonicalization must flag them even though they differ in length by
        // >33% with no alternation (the heuristic that allowed `\.exe$` vs
        // `7z\.exe$` must not suppress a genuine duplicate).
        let traits = vec![
            create_string_regex(
                "digits_shorthand",
                r"\d{3}",
                false,
                vec![FileType::Pe],
                "a.yaml",
            ),
            create_string_regex(
                "digits_class",
                r"[0-9]{3}",
                false,
                vec![FileType::Pe],
                "b.yaml",
            ),
        ];

        let mut warnings = Vec::new();
        check_overlapping_regex_patterns(&traits, &mut warnings);

        assert_eq!(warnings.len(), 1, "expected one duplicate: {warnings:?}");
        assert!(warnings[0].contains("Structurally identical regex patterns"));
        assert!(warnings[0].contains("canonical form"));
    }

    #[test]
    fn test_regex_regex_structurally_identical_class_order() {
        use crate::capabilities::validation::duplicates::check_overlapping_regex_patterns;

        // Character-class member order is not semantic: `gr[ae]y` ≡ `gr[ea]y`.
        let traits = vec![
            create_string_regex("grey_ae", r"gr[ae]y", false, vec![FileType::Pe], "a.yaml"),
            create_string_regex("grey_ea", r"gr[ea]y", false, vec![FileType::Pe], "b.yaml"),
        ];

        let mut warnings = Vec::new();
        check_overlapping_regex_patterns(&traits, &mut warnings);

        assert_eq!(warnings.len(), 1, "expected one duplicate: {warnings:?}");
        assert!(warnings[0].contains("Structurally identical regex patterns"));
    }

    #[test]
    fn test_regex_regex_word_boundary_not_identical_to_substring() {
        use crate::capabilities::validation::duplicates::check_overlapping_regex_patterns;

        // `\bfoobar\b` (whole word) and `foobar` (substring) describe different
        // languages — the look-around boundaries change the match, so this must
        // NOT be reported as structurally identical.
        let traits = vec![
            create_string_regex("word", r"\bfoobar\b", false, vec![FileType::Pe], "a.yaml"),
            create_string_regex("substr", r"foobar", false, vec![FileType::Pe], "b.yaml"),
        ];

        let mut warnings = Vec::new();
        check_overlapping_regex_patterns(&traits, &mut warnings);

        assert!(
            !warnings
                .iter()
                .any(|w| w.contains("Structurally identical")),
            "word-boundary vs substring must not be called identical: {warnings:?}"
        );
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
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
                vec![FileType::Elf],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_hostile",
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
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

    /// `not:` is a carve-out, not the assertion — two traits that match the same
    /// thing at the same criticality are one detection however their exclusions
    /// are spelled, so the pair must still be reported.
    #[test]
    fn test_atomic_logic_duplicates_not_differs_at_same_crit_is_reported() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;
        use crate::composite_rules::condition::NotException;

        let matcher = || {
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            })
        };
        let mut a = create_test_trait_with_conf_crit(
            "a",
            matcher(),
            vec![FileType::Elf],
            "a.yaml",
            1.0,
            crate::types::Criticality::Notable,
        );
        let mut b = create_test_trait_with_conf_crit(
            "b",
            matcher(),
            vec![FileType::Elf],
            "b.yaml",
            1.0,
            crate::types::Criticality::Notable,
        );
        a.not = Some(vec![NotException::Shorthand("carve_out_one".to_string())]);
        b.not = Some(vec![NotException::Shorthand("carve_out_two".to_string())]);

        let duplicates = find_atomic_logic_duplicates(&[a, b]);
        assert_eq!(
            duplicates.len(),
            1,
            "same matcher + same crit is one detection"
        );
        assert!(
            duplicates[0].2.contains("not: differs"),
            "the report must say what differs: {}",
            duplicates[0].2
        );
    }

    /// The opposite case: a generic matcher beside one narrowed by `not:` that
    /// says something stronger is a deliberate specialization, and the differing
    /// `crit:` is what marks it as intentional. Reporting it would be noise.
    #[test]
    fn test_atomic_logic_duplicates_not_differs_at_different_crit_is_quiet() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;
        use crate::composite_rules::condition::NotException;

        let matcher = || {
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("ip_pattern".to_string()),
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
            })
        };
        let generic = create_test_trait_with_conf_crit(
            "any-ip",
            matcher(),
            vec![FileType::Elf],
            "generic.yaml",
            1.0,
            crate::types::Criticality::Baseline,
        );
        let mut external_only = create_test_trait_with_conf_crit(
            "external-ip",
            matcher(),
            vec![FileType::Elf],
            "external.yaml",
            1.0,
            crate::types::Criticality::Notable,
        );
        external_only.not = Some(vec![NotException::Shorthand("10.".to_string())]);

        let duplicates = find_atomic_logic_duplicates(&[generic, external_only]);
        assert!(
            duplicates.is_empty(),
            "a narrowed matcher at a higher crit is a specialization, not a duplicate: {duplicates:?}"
        );
    }

    #[test]
    fn test_atomic_logic_duplicates_same_logic_different_conf() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

        let traits = vec![
            create_test_trait_with_conf_crit(
                "trait_low_conf",
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
                vec![FileType::Shell],
                "file1.yaml",
                0.5,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_high_conf",
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
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
    fn test_atomic_logic_duplicates_differ_only_in_unless() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

        // Same matcher, same crit/conf/platforms — they differ only in `unless:`.
        // The matcher signature ignores `unless`, so the pair is flagged and the
        // recommendation is to collapse it into one trait with a downgrade.
        let matcher = || {
            Condition::Raw(RawQuery {
                exact: Some("shared_matcher".to_string()),
                ..Default::default()
            })
        };
        let mut guarded = create_test_trait_with_conf_crit(
            "trait_guarded",
            matcher(),
            vec![FileType::Shell],
            "a.yaml",
            0.9,
            crate::types::Criticality::Suspicious,
        );
        guarded.unless = Some(vec![Condition::Trait {
            id: "some/benign::context".to_string(),
        }]);
        let unguarded = create_test_trait_with_conf_crit(
            "trait_unguarded",
            matcher(),
            vec![FileType::Shell],
            "b.yaml",
            0.9,
            crate::types::Criticality::Suspicious,
        );

        let duplicates = find_atomic_logic_duplicates(&[guarded, unguarded]);
        assert_eq!(
            duplicates.len(),
            1,
            "same matcher differing only in unless must be flagged"
        );
        assert!(duplicates[0].2.contains("unless: differs"));
        assert!(
            duplicates[0].2.contains("downgrade:"),
            "should recommend merging via a downgrade"
        );
    }

    /// Build two `metadata/` traits sharing a matcher, with the given ids and `unless:`.
    fn metadata_unless_pair(
        id_a: &str,
        id_b: &str,
        unless_a: &str,
        unless_b: &str,
    ) -> Vec<TraitDefinition> {
        let matcher = || {
            Condition::Raw(RawQuery {
                exact: Some("gate_matcher".to_string()),
                ..Default::default()
            })
        };
        let mut a = create_test_trait_with_conf_crit(
            id_a,
            matcher(),
            vec![FileType::Shell],
            "a.yaml",
            0.7,
            crate::types::Criticality::Component,
        );
        a.unless = Some(vec![Condition::Trait {
            id: unless_a.to_string(),
        }]);
        let mut b = create_test_trait_with_conf_crit(
            id_b,
            matcher(),
            vec![FileType::Shell],
            "b.yaml",
            0.7,
            crate::types::Criticality::Component,
        );
        b.unless = Some(vec![Condition::Trait {
            id: unless_b.to_string(),
        }]);
        vec![a, b]
    }

    // The metadata field-presence idiom: two metadata traits sharing a gate matcher,
    // distinct ids, differing only in `unless:` — distinct detections, NOT flagged.
    #[test]
    fn test_atomic_logic_duplicates_metadata_unless_idiom_skipped() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;
        let traits = metadata_unless_pair(
            "metadata/package/manifest::pkginfo-no-author",
            "metadata/package/manifest::pkginfo-no-author-email",
            "field-author-present",
            "field-author-email-present",
        );
        assert!(
            find_atomic_logic_duplicates(&traits).is_empty(),
            "metadata gate+unless idiom must not be flagged"
        );
    }

    // The same local id duplicated across two metadata directories is a copy-paste —
    // flagged even though it differs only in unless and lives under metadata/.
    #[test]
    fn test_atomic_logic_duplicates_metadata_same_local_id_flagged() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;
        let traits = metadata_unless_pair(
            "metadata/binary/metrics/structural::text-dominates-cstring",
            "metadata/binary/anomaly/format::text-dominates-cstring",
            "guard-apple",
            "guard-funcs",
        );
        assert_eq!(
            find_atomic_logic_duplicates(&traits).len(),
            1,
            "same local id across metadata dirs is a copy-paste dupe"
        );
    }

    // A crit mismatch is a real inconsistency — flagged even within metadata/.
    #[test]
    fn test_atomic_logic_duplicates_metadata_crit_diff_flagged() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;
        let mut traits = metadata_unless_pair(
            "metadata/hardening/mitigation::textrel",
            "metadata/hardening/mitigation::text-relocations",
            "guard-a",
            "guard-b",
        );
        traits[1].crit = crate::types::Criticality::Suspicious; // a is Component
        assert_eq!(
            find_atomic_logic_duplicates(&traits).len(),
            1,
            "crit mismatch must flag even under metadata/"
        );
    }

    // When the shared matcher is a bare existence gate, crit may legitimately vary per
    // field (missing description = notable, missing author = component). Not flagged.
    #[test]
    fn test_atomic_logic_duplicates_metadata_gate_crit_diff_skipped() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;
        let gate = || {
            Condition::Kv(crate::composite_rules::KvQuery {
                path: "metadata-version".to_string(),
                ..Default::default()
            })
        };
        let mut a = create_test_trait_with_conf_crit(
            "metadata/package/manifest::pkginfo-missing-description",
            gate(),
            vec![FileType::Shell],
            "a.yaml",
            0.7,
            crate::types::Criticality::Notable,
        );
        a.unless = Some(vec![Condition::Trait {
            id: "field-description-present".to_string(),
        }]);
        let mut b = create_test_trait_with_conf_crit(
            "metadata/package/manifest::pkginfo-no-author",
            gate(),
            vec![FileType::Shell],
            "b.yaml",
            0.7,
            crate::types::Criticality::Component,
        );
        b.unless = Some(vec![Condition::Trait {
            id: "field-author-present".to_string(),
        }]);
        assert!(
            find_atomic_logic_duplicates(&[a, b]).is_empty(),
            "gate matcher: per-field crit variation is legitimate, not a dupe"
        );
    }

    #[test]
    fn test_atomic_logic_duplicates_overlapping_for_types() {
        use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

        // Same pattern, overlapping file types (both include Elf), different crit
        let traits = vec![
            create_test_trait_with_conf_crit(
                "trait_elf_macho",
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
                vec![FileType::Elf, FileType::Macho],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_elf_pe",
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
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
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
                vec![FileType::Macho],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_pe",
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
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
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
                vec![FileType::All],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Component,
            ),
            create_test_trait_with_conf_crit(
                "trait_baseline",
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
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
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
                vec![FileType::All],
                "file1.yaml",
                1.0,
                crate::types::Criticality::Notable,
            ),
            create_test_trait_with_conf_crit(
                "trait_b",
                Condition::Raw(RawQuery {
                    length_min: None,
                    length_max: None,
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
                }),
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
            vec![FileType::JavaScript],
            "file_a.yaml",
            1.0,
            crate::types::Criticality::Component,
        );
        let b = create_test_trait_with_conf_crit(
            "test::comp_b",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
            vec![FileType::JavaScript],
            "file_a.yaml",
            1.0,
            crate::types::Criticality::Notable,
        );
        let b = create_test_trait_with_conf_crit(
            "test::b",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
    use super::super::patterns::{find_incompatible_regex_features, find_non_capturing_groups};
    use crate::composite_rules::{Arch, Condition, FileType, Platform, RawQuery, TraitDefinition};
    use std::path::PathBuf;

    fn create_raw_regex_trait(id: &str, pattern: &str) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test trait".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            mbc: None,
            attack: None,
            r#if: Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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

    #[test]
    fn test_incompatible_lookaround_and_backref_detected() {
        // Every construct the linear-time engine can't compile must be flagged.
        for pat in [
            r"(?<!\w)base64", // negative lookbehind (the real base64-d-cmd bug)
            r"(?<=\s)rm -rf", // positive lookbehind
            r"(?=foo)bar",    // positive lookahead
            r"(?!x)y",        // negative lookahead
            r"(\w+)\s+\1",    // backreference
        ] {
            let traits = vec![create_raw_regex_trait("test-incompat", pat)];
            let mut errors = Vec::new();
            find_incompatible_regex_features(&traits, &mut errors);
            assert_eq!(
                errors.len(),
                1,
                "expected {pat:?} to be flagged, got {errors:?}"
            );
            assert!(errors[0].contains("test-incompat"));
        }
    }

    #[test]
    fn test_compatible_patterns_not_flagged() {
        // Supported features — including named captures (which share the `(?<`
        // prefix with lookbehind) and byte escapes — must never be flagged.
        for pat in [
            r"\bbase64\s+-(d|D)", // the fixed base64-d-cmd
            r"(?:^|[^\w])base64", // lookbehind-free alternation
            r"(?<name>\w+)=\w+",  // named capture, NOT lookbehind
            r"(?P<n>\d+)",        // named capture, alt syntax
            r"[\x00-\xff]+",      // byte range (byte-mode only)
            r"(foo|bar)baz",      // plain group
        ] {
            let traits = vec![create_raw_regex_trait("test-ok", pat)];
            let mut errors = Vec::new();
            find_incompatible_regex_features(&traits, &mut errors);
            assert!(
                errors.is_empty(),
                "{pat:?} must not be flagged, got {errors:?}"
            );
        }
    }
}

#[cfg(test)]
mod taxonomy_tests {
    use crate::capabilities::validation::taxonomy::{
        ObjectivesWellknownViolation, find_cap_obj_violations, find_cap_wellknown_violations,
        find_metadata_cross_tier_refs, find_objectives_wellknown_violations,
        find_suppression_only_building_blocks,
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

    // ---- hostile composites must reference two notable+ legs ----

    #[test]
    fn test_hostile_with_too_few_notable_legs() {
        use crate::capabilities::validation::find_hostile_composites_with_too_few_notable_legs;

        fn leaf(id: &str, crit: Criticality) -> TraitDefinition {
            TraitDefinition {
                crit,
                ..make_trait(id, "ignored")
            }
        }
        let traits = vec![
            leaf("objectives/x::a", Criticality::Component),
            leaf("objectives/x::b", Criticality::Component),
            leaf("objectives/x::notable-leg", Criticality::Notable),
            leaf("objectives/x::notable-leg-2", Criticality::Notable),
            // notable traits reachable only via a directory-subtree reference
            leaf("micro-behaviors/comms/http::client", Criticality::Notable),
            leaf("micro-behaviors/comms/http::request", Criticality::Notable),
        ];

        let mut all_component =
            make_composite("objectives/x::bad", &["objectives/x::a", "objectives/x::b"]);
        all_component.crit = Criticality::Hostile;

        let mut direct_notable = make_composite(
            "objectives/x::good-direct",
            &[
                "objectives/x::a",
                "objectives/x::notable-leg",
                "objectives/x::notable-leg-2",
            ],
        );
        direct_notable.crit = Criticality::Hostile;

        // directory reference into a subtree containing a notable trait
        let mut dir_ref = make_composite("objectives/x::good-dir", &["micro-behaviors/comms/http"]);
        dir_ref.crit = Criticality::Hostile;

        // transitive: hostile -> component sub-composite -> two notable legs
        let sub = make_composite(
            "objectives/x::sub",
            &["objectives/x::notable-leg", "objectives/x::notable-leg-2"],
        ); // Baseline
        let mut transitive =
            make_composite("objectives/x::good-transitive", &["objectives/x::sub"]);
        transitive.crit = Criticality::Hostile;

        // non-hostile composites are ignored even with only component legs
        let non_hostile = make_composite("objectives/x::ignored", &["objectives/x::a"]);

        let composites = vec![
            all_component,
            direct_notable,
            dir_ref,
            sub,
            transitive,
            non_hostile,
        ];
        let v = find_hostile_composites_with_too_few_notable_legs(&traits, &composites);
        assert_eq!(v, vec!["objectives/x::bad".to_string()]);
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

    // ---- suppression-only building blocks ----

    /// A baseline/component atomic leaf (raw matcher, no references).
    fn leaf(id: &str, crit: Criticality) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "leaf".to_string(),
            conf: 1.0,
            crit,
            mbc: None,
            attack: None,
            r#if: Condition::Raw(crate::composite_rules::RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("needle".to_string()),
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
            }),
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

    /// A composite with explicit crit, optional `any:`, and optional `unless:` references.
    fn comp(id: &str, crit: Criticality, any: &[&str], unless: &[&str]) -> CompositeTrait {
        let to_conds = |refs: &[&str]| {
            refs.iter()
                .map(|r| Condition::Trait { id: r.to_string() })
                .collect::<Vec<_>>()
        };
        CompositeTrait {
            required_trait_indices: Vec::new(),
            id: id.to_string(),
            desc: "comp".to_string(),
            conf: 1.0,
            crit,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::All],
            for_from_groups: false,
            size_min: None,
            size_max: None,
            all: None,
            any: (!any.is_empty()).then(|| to_conds(any)),
            unless: (!unless.is_empty()).then(|| to_conds(unless)),
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

    fn ids(v: &[(String, String)]) -> Vec<&str> {
        v.iter().map(|(id, _)| id.as_str()).collect()
    }

    #[test]
    fn flags_baseline_leaf_referenced_only_in_unless() {
        let traits = vec![leaf(
            "objectives/evasion/x::benign-ctx",
            Criticality::Baseline,
        )];
        // A notable composite that only *suppresses* on the leaf.
        let composites = vec![comp(
            "objectives/evasion/x::detect",
            Criticality::Notable,
            &["micro-behaviors/foo::bar"],
            &["objectives/evasion/x::benign-ctx"],
        )];
        let v = find_suppression_only_building_blocks(&traits, &composites, &HashMap::new());
        assert_eq!(ids(&v), vec!["objectives/evasion/x::benign-ctx"]);
    }

    #[test]
    fn exempt_when_positive_evidence_in_notable_composite() {
        let traits = vec![leaf("objectives/evasion/x::probe", Criticality::Baseline)];
        let composites = vec![comp(
            "objectives/evasion/x::detect",
            Criticality::Notable,
            &["objectives/evasion/x::probe"],
            &[],
        )];
        let v = find_suppression_only_building_blocks(&traits, &composites, &HashMap::new());
        assert!(
            v.is_empty(),
            "positive ref by a notable composite satisfies"
        );
    }

    #[test]
    fn exempt_transitively_through_baseline_aggregator() {
        // component fragment -> baseline aggregator -> notable composite.
        let traits = vec![leaf("objectives/evasion/x::frag", Criticality::Component)];
        let composites = vec![
            comp(
                "objectives/evasion/x::agg",
                Criticality::Baseline,
                &["objectives/evasion/x::frag"],
                &[],
            ),
            comp(
                "objectives/evasion/x::detect",
                Criticality::Notable,
                &["objectives/evasion/x::agg"],
                &[],
            ),
        ];
        let v = find_suppression_only_building_blocks(&traits, &composites, &HashMap::new());
        assert!(
            v.is_empty(),
            "a fragment feeding a notable detection transitively is fine, got {:?}",
            ids(&v)
        );
    }

    #[test]
    fn flags_chain_that_never_reaches_notable() {
        // fragment -> baseline aggregator, but nothing notable consumes the aggregator.
        let traits = vec![leaf("objectives/evasion/x::frag", Criticality::Component)];
        let composites = vec![comp(
            "objectives/evasion/x::agg",
            Criticality::Baseline,
            &["objectives/evasion/x::frag"],
            &[],
        )];
        let v = find_suppression_only_building_blocks(&traits, &composites, &HashMap::new());
        // Both the fragment and the baseline aggregator are unreached building blocks.
        assert_eq!(
            ids(&v),
            vec!["objectives/evasion/x::agg", "objectives/evasion/x::frag"]
        );
    }

    #[test]
    fn directory_reference_from_notable_satisfies_members() {
        let traits = vec![leaf(
            "well-known/malware/foo::marker",
            Criticality::Baseline,
        )];
        // Notable composite references the directory, not the specific id.
        let composites = vec![comp(
            "well-known/malware/foo::detect",
            Criticality::Notable,
            &["well-known/malware/foo"],
            &[],
        )];
        let v = find_suppression_only_building_blocks(&traits, &composites, &HashMap::new());
        assert!(v.is_empty(), "a directory ref covers members beneath it");
    }

    #[test]
    fn ignores_other_tiers() {
        // micro-behaviors/ and metadata/ are out of scope even when only suppressed.
        let traits = vec![leaf("micro-behaviors/foo::ctx", Criticality::Baseline)];
        let composites = vec![comp(
            "objectives/evasion/x::detect",
            Criticality::Notable,
            &["other::thing"],
            &["micro-behaviors/foo::ctx"],
        )];
        let v = find_suppression_only_building_blocks(&traits, &composites, &HashMap::new());
        assert!(
            v.is_empty(),
            "only objectives/ and well-known/ are candidates"
        );
    }

    #[test]
    fn notable_rule_itself_is_not_a_candidate() {
        // A notable leaf in objectives/ surfaces on its own — not a building block.
        let traits = vec![leaf(
            "objectives/evasion/x::standalone",
            Criticality::Notable,
        )];
        let v = find_suppression_only_building_blocks(&traits, &[], &HashMap::new());
        assert!(v.is_empty());
    }
}

#[cfg(test)]
mod constraint_tests {
    use crate::capabilities::validation::constraints::{
        MISSING_CONDITIONS, find_empty_condition_clauses, find_invalid_hex_patterns,
        find_needs_zero, find_none_only_with_proximity, find_pure_alias_traits,
        find_too_short_patterns,
    };
    use crate::capabilities::validation::{
        find_many_directory_refs, find_pure_directory_alias_composites, find_redundant_any_refs,
        find_self_referencing_composites,
    };
    use crate::composite_rules::{
        Arch, CompositeTrait, Condition, FileType, KvQuery, Platform, RawQuery, TraitDefinition,
    };
    use crate::types::Criticality;
    use crate::validation_controls::{Severity, validator_severity};
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
                    scope: None,
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
            r#if: Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
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
        })
    }

    fn short_hex_trait(pattern: &str, offset: Option<i64>) -> Condition {
        Condition::Hex(crate::composite_rules::condition::HexQuery {
            pattern: pattern.to_string(),
            not: None,
            offset,
            offset_range: None,
            section: None,
            section_offset: None,
            section_offset_range: None,
        })
    }

    #[test]
    fn short_hex_patterns_rejected_unpinned_and_allowed_pinned() {
        // Unpinned two-byte pattern is impossibly short; offset-pinned is fine.
        let traits = vec![
            short_raw_trait("test/hex-unpinned", short_hex_trait("5C ?? 44", None)),
            short_raw_trait("test/hex-pinned", short_hex_trait("5C ?? 44", Some(0))),
        ];
        let violations = find_too_short_patterns(&traits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "test/hex-unpinned");
    }

    #[test]
    fn hex_alternation_counts_as_one_concrete_byte() {
        // (5C|5D) constrains a full byte, exactly like a nibble wildcard does.
        let traits = vec![short_raw_trait(
            "test/hex-alternation",
            short_hex_trait("A3 (5C|5D) 19", None),
        )];
        assert!(
            find_too_short_patterns(&traits).is_empty(),
            "literal + alternation + literal = 3 concrete bytes"
        );
    }

    #[test]
    fn invalid_hex_patterns_are_reported_as_hard_validation_inputs() {
        let traits = vec![
            short_raw_trait(
                "test/valid-yara-nibble-alternation",
                short_hex_trait("1F 8B 08 (0?|1?)", None),
            ),
            short_raw_trait(
                "test/invalid-hex",
                short_hex_trait("1F 8B 08 (0?|ZZ)", None),
            ),
        ];
        let violations = find_invalid_hex_patterns(&traits);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "test/invalid-hex");
        assert!(violations[0].2.contains("invalid"));
        assert_eq!(
            validator_severity("invalid-hex-pattern"),
            Severity::Hard,
            "unparseable hex must fail even in --soft validation"
        );
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
    fn test_criticality_change_is_still_a_pure_alias() {
        // A different `crit:` used to exempt an alias on the theory that it
        // "adds value". It does not: the alias matches exactly what the base
        // matches, so the file gets the same evidence twice under two names at
        // two severities, and a reader has to work out which id to believe.
        // Promoting is the worse direction — it relabels one matcher's hit as a
        // stronger verdict with no new evidence behind it.
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

        assert_eq!(violations.len(), 1, "a retiered rename is still a rename");
        assert_eq!(violations[0].0, "objectives/test::upgraded");
    }

    #[test]
    fn test_directory_reference_is_not_a_pure_alias() {
        // `if: id: <dir>/` is an OR across every trait beneath the directory —
        // real logic, not a rename of one trait — so it must stay exempt. The
        // old code skipped it only as a side effect of failing the criticality
        // lookup; with that gone the guard has to be explicit.
        let base = create_base_trait("micro-behaviors/test::base", Criticality::Notable);
        let alias = create_trait_ref(
            "objectives/test::fans-out",
            "micro-behaviors/test/", // directory, not a single trait
            Criticality::Notable,
            None,
            false,
        );

        let traits = vec![base, alias];
        assert!(
            find_pure_alias_traits(&traits).is_empty(),
            "a directory reference matches many traits, so it is not an alias"
        );
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
        let traits = dir_traits(
            "foo/bar",
            &["foo/bar::a", "foo/bar::b", "foo/bar::c", "foo/bar::d"],
        );
        let rules = vec![create_composite_any(
            "other/dir::alias",
            &["foo/bar::a", "foo/bar::b", "foo/bar::c", "foo/bar::d"],
        )];

        let violations = find_pure_directory_alias_composites(&rules, &traits);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0, "other/dir::alias");
        assert_eq!(violations[0].1, "foo/bar");
    }

    #[test]
    fn test_small_directory_alias_composite_not_flagged() {
        // Three members is small enough that naming them beats the indirection.
        let traits = dir_traits("foo/bar", &["foo/bar::a", "foo/bar::b", "foo/bar::c"]);
        let rules = vec![create_composite_any(
            "other/dir::alias",
            &["foo/bar::a", "foo/bar::b", "foo/bar::c"],
        )];

        assert!(find_pure_directory_alias_composites(&rules, &traits).is_empty());
    }

    /// A directory whose entire membership is what the rule enumerates.
    fn fully_covered(dir: &str, n: usize) -> std::collections::HashMap<String, usize> {
        std::collections::HashMap::from([(dir.to_string(), n)])
    }

    #[test]
    fn test_redundant_any_refs_needs_eight_from_one_directory() {
        let sizes = fully_covered("foo/bar", 8);
        let seven: Vec<String> = (0..7).map(|i| format!("foo/bar::t{i}")).collect();
        let seven_refs: Vec<&str> = seven.iter().map(String::as_str).collect();
        let rule = create_composite_any("other/dir::rule", &seven_refs);
        assert!(
            find_redundant_any_refs(&rule, &sizes).is_empty(),
            "seven refs are still hand-listable"
        );

        let eight: Vec<String> = (0..8).map(|i| format!("foo/bar::t{i}")).collect();
        let eight_refs: Vec<&str> = eight.iter().map(String::as_str).collect();
        let rule = create_composite_any("other/dir::rule", &eight_refs);
        let violations = find_redundant_any_refs(&rule, &sizes);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].1, "foo/bar");
        assert_eq!(violations[0].2, 8);
    }

    #[test]
    fn test_redundant_any_refs_flags_metadata_directory() {
        let refs: Vec<String> = (0..8).map(|i| format!("metadata/foo::t{i}")).collect();
        let refs: Vec<&str> = refs.iter().map(String::as_str).collect();
        let rule = create_composite_any("other/dir::rule", &refs);

        let violations = find_redundant_any_refs(&rule, &fully_covered("metadata/foo", 8));

        assert_eq!(violations.len(), 1, "metadata/ is no longer exempt");
        assert_eq!(violations[0].1, "metadata/foo");
    }

    /// Eight references into a large directory is not redundancy — it is the
    /// rule being specific. Collapsing to `id: <dir>` there would match the
    /// other 295 members too. `generic-bundle-id-pattern` enumerates 8 of
    /// ~303 ids under `metadata/signed/id`; naming the directory would have
    /// matched every signed application, `com.apple.*` included.
    #[test]
    fn enumerating_a_small_slice_of_a_large_directory_is_not_redundant() {
        let refs: Vec<String> = (0..8)
            .map(|i| format!("metadata/signed/id::t{i}"))
            .collect();
        let refs: Vec<&str> = refs.iter().map(String::as_str).collect();
        let rule = create_composite_any("other/dir::rule", &refs);

        let violations = find_redundant_any_refs(&rule, &fully_covered("metadata/signed/id", 303));

        assert!(
            violations.is_empty(),
            "8 of 303 is precision, not redundancy"
        );
    }

    /// A directory cleave knows nothing about is never flagged: without its
    /// size there is no way to tell a collapse from a widening.
    #[test]
    fn an_unknown_directory_is_not_flagged() {
        let refs: Vec<String> = (0..8).map(|i| format!("foo/bar::t{i}")).collect();
        let refs: Vec<&str> = refs.iter().map(String::as_str).collect();
        let rule = create_composite_any("other/dir::rule", &refs);

        assert!(find_redundant_any_refs(&rule, &std::collections::HashMap::new()).is_empty());
    }

    #[test]
    fn test_same_directory_alias_composite_not_recommended() {
        let traits = dir_traits(
            "foo/bar",
            &["foo/bar::a", "foo/bar::b", "foo/bar::c", "foo/bar::d"],
        );
        let rule = create_composite_any(
            "foo/bar::alias",
            &["foo/bar::a", "foo/bar::b", "foo/bar::c", "foo/bar::d"],
        );

        assert!(
            find_many_directory_refs(&rule, &traits).is_empty(),
            "same-directory replacement would recursively include the composite"
        );
        assert!(
            find_pure_directory_alias_composites(&[rule], &traits).is_empty(),
            "same-directory aliases must not be rewritten as recursive directory refs"
        );
    }

    #[test]
    fn exhaustive_directory_suppressor_is_detected() {
        use crate::capabilities::validation::constraints::find_exhaustive_suppressors;
        fn unless(v: &[&str]) -> Vec<Condition> {
            v.iter()
                .map(|r| Condition::Trait {
                    id: (*r).to_string(),
                })
                .collect()
        }

        use crate::composite_rules::condition::MetricsQuery;

        let metric = |id: &str, min: Option<f64>, max: Option<f64>, fts: Vec<FileType>| {
            let mut t = create_trait_ref(id, "x::x", Criticality::Baseline, None, false);
            t.r#if = Condition::Metrics(MetricsQuery {
                field: "exports.count".to_string(),
                min,
                max,
                min_size: None,
                max_size: None,
            });
            t.r#for = fts;
            t
        };

        // Complementary halves of one integer metric, same file types: their
        // union is every file that emits it.
        let none = metric("g/dir::no-exports", None, Some(0.0), vec![FileType::Elf]);
        let some = metric("g/dir::has-exports", Some(1.0), None, vec![FileType::Elf]);

        // The rule that stands down on the whole directory.
        let mut victim = create_trait_ref("v::packer", "x::x", Criticality::Notable, None, false);
        victim.unless = Some(unless(&["g/dir/"]));

        let found = find_exhaustive_suppressors(&[none, some, victim], &[]);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].id, "v::packer");
        assert_eq!(found[0].field, "exports.count");
    }

    #[test]
    fn suppressor_with_a_real_gap_is_not_flagged() {
        use crate::capabilities::validation::constraints::find_exhaustive_suppressors;
        fn unless(v: &[&str]) -> Vec<Condition> {
            v.iter()
                .map(|r| Condition::Trait {
                    id: (*r).to_string(),
                })
                .collect()
        }

        use crate::composite_rules::condition::MetricsQuery;

        let ratio = |id: &str, min: Option<f64>, max: Option<f64>| {
            let mut t = create_trait_ref(id, "x::x", Criticality::Baseline, None, false);
            t.r#if = Condition::Metrics(MetricsQuery {
                field: "binary.largest_section_ratio".to_string(),
                min,
                max,
                min_size: None,
                max_size: None,
            });
            t.r#for = vec![FileType::Pe];
            t
        };
        // A continuous metric has no "next value", so 0.1 and 0.95 leave a
        // genuine band uncovered -- this is an ordinary pair of filters.
        let low = ratio("g/dir::small-section", None, Some(0.1));
        let high = ratio("g/dir::dominant-section", Some(0.95), None);
        let mut victim = create_trait_ref("v::rule", "x::x", Criticality::Notable, None, false);
        victim.unless = Some(unless(&["g/dir/"]));

        let found = find_exhaustive_suppressors(&[low, high, victim], &[]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn disjoint_file_types_are_not_exhaustive() {
        use crate::capabilities::validation::constraints::find_exhaustive_suppressors;
        fn unless(v: &[&str]) -> Vec<Condition> {
            v.iter()
                .map(|r| Condition::Trait {
                    id: (*r).to_string(),
                })
                .collect()
        }

        use crate::composite_rules::condition::MetricsQuery;

        let metric = |id: &str, min: Option<f64>, max: Option<f64>, ft: FileType| {
            let mut t = create_trait_ref(id, "x::x", Criticality::Baseline, None, false);
            t.r#if = Condition::Metrics(MetricsQuery {
                field: "exports.count".to_string(),
                min,
                max,
                min_size: None,
                max_size: None,
            });
            t.r#for = vec![ft];
            t
        };
        // No single file is both a PE and an ELF, so neither half ever covers
        // what the other misses. This is the real shape of
        // metadata/binary/symbols/exports/, and it is not this defect.
        let none = metric("g/dir::no-exports", None, Some(0.0), FileType::Pe);
        let some = metric("g/dir::has-exports", Some(1.0), None, FileType::Elf);
        let mut victim = create_trait_ref("v::rule", "x::x", Criticality::Notable, None, false);
        victim.unless = Some(unless(&["g/dir/"]));

        let found = find_exhaustive_suppressors(&[none, some, victim], &[]);
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn test_dead_downgrade_detected() {
        use crate::capabilities::validation::constraints::find_dead_downgrades;
        use crate::composite_rules::traits::DowngradeConditions;

        fn dg(
            any: Option<&[&str]>,
            all: Option<&[&str]>,
            none: Option<&[&str]>,
        ) -> DowngradeConditions {
            let conv = |v: &[&str]| {
                v.iter()
                    .map(|r| Condition::Trait {
                        id: (*r).to_string(),
                    })
                    .collect::<Vec<_>>()
            };
            DowngradeConditions {
                any: any.map(conv),
                all: all.map(conv),
                none: none.map(conv),
                needs: None,
                scope: None,
            }
        }
        fn unless(v: &[&str]) -> Vec<Condition> {
            v.iter()
                .map(|r| Condition::Trait {
                    id: (*r).to_string(),
                })
                .collect()
        }

        // Whole `any:` clause dead — every leg is also suppressed.
        let mut whole = create_trait_ref("d::whole", "x::x", Criticality::Suspicious, None, false);
        whole.unless = Some(unless(&["g::a"]));
        whole.downgrade = Some(dg(Some(&["g::a"]), None, None));

        // Partially dead `any:` — one leg survives, so the clause still works.
        let mut partial =
            create_trait_ref("d::partial", "x::x", Criticality::Suspicious, None, false);
        partial.unless = Some(unless(&["g::a"]));
        partial.downgrade = Some(dg(Some(&["g::a", "g::b"]), None, None));

        // `all:` needs every leg, so one suppressed leg kills the whole clause.
        let mut all_dead = create_trait_ref("d::all", "x::x", Criticality::Suspicious, None, false);
        all_dead.unless = Some(unless(&["g::a"]));
        all_dead.downgrade = Some(dg(None, Some(&["g::a", "g::b"]), None));

        // `none:` is inverted — an entry there is not dead.
        let mut inverted =
            create_trait_ref("d::none", "x::x", Criticality::Suspicious, None, false);
        inverted.unless = Some(unless(&["g::a"]));
        inverted.downgrade = Some(dg(None, None, Some(&["g::a"])));

        // Disjoint unless/downgrade — the ordinary, healthy shape.
        let mut clean = create_trait_ref("d::clean", "x::x", Criticality::Suspicious, None, false);
        clean.unless = Some(unless(&["g::a"]));
        clean.downgrade = Some(dg(Some(&["g::b"]), None, None));

        let traits = [whole, partial, all_dead, inverted, clean];
        let found = find_dead_downgrades(&traits, &[]);

        let ids: Vec<&str> = found.iter().map(|d| d.id.as_str()).collect();
        assert_eq!(ids, ["d::whole", "d::partial", "d::all"]);
        assert!(
            found[0].whole_clause,
            "single dead any: leg is the whole clause"
        );
        assert!(
            !found[1].whole_clause,
            "a surviving any: leg keeps the clause alive"
        );
        assert!(found[2].whole_clause, "all: dies on one suppressed leg");
        assert_eq!(found[2].clause, "all");
        assert!(found.iter().all(|d| !d.is_composite));
    }

    #[test]
    fn test_trait_self_suppression_detected() {
        use crate::capabilities::validation::composite::find_self_suppressing_traits;

        // Direct self-reference in `unless:`.
        let mut direct = create_trait_ref(
            "foo/bar::alias",
            "unrelated/dir::x",
            Criticality::Notable,
            None,
            false,
        );
        direct.unless = Some(vec![Condition::Trait {
            id: "foo/bar::alias".to_string(),
        }]);

        // Own-directory reference in `unless:` — the shape that killed
        // objectives/lateral-movement/ssh/backdoor-deploy::ssh-permit-root.
        let mut via_dir = create_trait_ref(
            "foo/bar::other",
            "unrelated/dir::x",
            Criticality::Notable,
            None,
            false,
        );
        via_dir.unless = Some(vec![Condition::Trait {
            id: "foo/bar".to_string(),
        }]);

        // Self-reference in `downgrade:` — pins the trait a level below its
        // declared criticality forever.
        let mut downgraded = create_trait_ref(
            "foo/bar::pinned",
            "unrelated/dir::x",
            Criticality::Notable,
            None,
            false,
        );
        downgraded.downgrade = Some(crate::composite_rules::traits::DowngradeConditions {
            any: Some(vec![Condition::Trait {
                id: "foo/bar::pinned".to_string(),
            }]),
            all: None,
            none: None,
            needs: None,
            scope: None,
        });

        // A reference to a different directory is legitimate.
        let mut clean = create_trait_ref(
            "foo/bar::fine",
            "unrelated/dir::x",
            Criticality::Notable,
            None,
            false,
        );
        clean.unless = Some(vec![Condition::Trait {
            id: "other/dir".to_string(),
        }]);

        let traits = [direct, via_dir, downgraded, clean];
        let violations = find_self_suppressing_traits(&traits);

        assert_eq!(violations.len(), 3, "{violations:?}");
        assert_eq!(violations[0].0.id, "foo/bar::alias");
        assert_eq!(violations[0].2, "unless");
        assert_eq!(violations[1].0.id, "foo/bar::other");
        assert_eq!(violations[1].1, "foo/bar");
        assert_eq!(violations[2].0.id, "foo/bar::pinned");
        assert_eq!(violations[2].2, "downgrade");
    }

    #[test]
    fn test_composite_suppressed_by_own_leg_detected() {
        use crate::capabilities::validation::composite::find_leg_suppressing_composites;
        use crate::composite_rules::traits::{DowngradeConditions, Scope};

        fn refs(ids: &[&str]) -> Vec<Condition> {
            ids.iter()
                .map(|id| Condition::Trait {
                    id: (*id).to_string(),
                })
                .collect()
        }
        fn rule(id: &str, all: &[&str], any: &[&str], unless: &[&str]) -> CompositeTrait {
            let mut r = create_composite_any(id, any);
            r.all = (!all.is_empty()).then(|| refs(all));
            r.any = (!any.is_empty()).then(|| refs(any));
            r.unless = (!unless.is_empty()).then(|| refs(unless));
            r
        }

        // The shape that killed pkginfo-minimal-shell-package: the unless
        // directory contains a required all: leg.
        let dir_covers_all = rule(
            "x/y::shell",
            &["meta/versioning/scheme::lowest", "meta/eco::core"],
            &[],
            &["meta/versioning/"],
        );
        // Every any: leg covered (by different suppressors).
        let covers_every_any = rule(
            "x/y::every-any",
            &["a/b::base"],
            &["c/d::one", "e/f::two"],
            &["c/d/", "e/f::two"],
        );
        // One any: leg survives, so the rule can still fire.
        let one_any_survives = rule(
            "x/y::survives",
            &["a/b::base"],
            &["c/d::one", "e/f::two"],
            &["c/d/"],
        );
        // A directory leg inside the unless directory.
        let dir_leg_in_dir = rule("x/y::dir-leg", &["m/n/o/"], &[], &["m/n"]);
        // Archive scope: the leg can come from another member, not provable.
        let mut archive = rule("x/y::archive", &["m/n::leg"], &[], &["m/n/"]);
        archive.scope = Some(Scope::Archive);
        // builtin-* hook carriers are meant never to fire.
        let builtin = rule(
            "p/q::builtin-some-finding",
            &["p/q::ctx"],
            &[],
            &["p/q::ctx"],
        );
        // A downgrade whose only entry is a required leg pins the tier.
        let mut pinned = rule("x/y::pinned", &["s/t::leg", "u/v::other"], &[], &[]);
        pinned.downgrade = Some(DowngradeConditions {
            any: Some(refs(&["s/t/"])),
            all: None,
            none: None,
            needs: None,
            scope: None,
        });
        // A downgrade that also needs something outside the legs is fine.
        let mut conditional = rule("x/y::conditional", &["s/t::leg"], &[], &[]);
        conditional.downgrade = Some(DowngradeConditions {
            any: None,
            all: Some(refs(&["s/t::leg", "w/z::context"])),
            none: None,
            needs: None,
            scope: None,
        });
        // Prefix of a sibling directory name is not containment.
        let sibling_prefix = rule(
            "x/y::sibling",
            &["meta/versioning-extra::leg"],
            &[],
            &["meta/versioning"],
        );

        let rules = [
            dir_covers_all,
            covers_every_any,
            one_any_survives,
            dir_leg_in_dir,
            archive,
            builtin,
            pinned,
            conditional,
            sibling_prefix,
        ];
        let found = find_leg_suppressing_composites(&rules);
        let got: Vec<(&str, &str, &str, &str)> = found
            .iter()
            .map(|(r, s, l, c)| (r.id.as_str(), s.as_str(), l.as_str(), *c))
            .collect();
        assert_eq!(
            got,
            vec![
                (
                    "x/y::shell",
                    "meta/versioning/",
                    "meta/versioning/scheme::lowest",
                    "unless"
                ),
                ("x/y::every-any", "c/d/", "c/d::one", "unless"),
                ("x/y::dir-leg", "m/n", "m/n/o/", "unless"),
                ("x/y::pinned", "s/t/", "s/t::leg", "downgrade"),
            ]
        );
    }

    /// The branches the first leg-suppression test does not reach: which
    /// scopes count as file-local, which downgrade shapes can miss a match,
    /// and which `any:` clauses can still fire without a covered trait.
    #[test]
    fn test_leg_suppression_scope_and_clause_boundaries() {
        use crate::capabilities::validation::composite::find_leg_suppressing_composites;
        use crate::composite_rules::traits::{DowngradeConditions, Scope};

        fn refs(ids: &[&str]) -> Option<Vec<Condition>> {
            (!ids.is_empty()).then(|| {
                ids.iter()
                    .map(|id| Condition::Trait {
                        id: (*id).to_string(),
                    })
                    .collect()
            })
        }
        fn rule(id: &str, all: &[&str], unless: &[&str], scope: Option<Scope>) -> CompositeTrait {
            let mut r = create_composite_any(id, &[]);
            r.all = refs(all);
            r.any = None;
            r.unless = refs(unless);
            r.scope = scope;
            r
        }
        fn dg(
            any: &[&str],
            all: &[&str],
            none: &[&str],
            needs: Option<usize>,
            scope: Option<Scope>,
        ) -> DowngradeConditions {
            DowngradeConditions {
                any: refs(any),
                all: refs(all),
                none: refs(none),
                needs,
                scope,
            }
        }

        let leaf_scope = rule("r::leaf-scope", &["a/b::leg"], &["a/b"], Some(Scope::Leaf));
        let package_scope = rule(
            "r::package-scope",
            &["a/b::leg"],
            &["a/b/"],
            Some(Scope::Package),
        );
        let outer_scope = rule(
            "r::outer-scope",
            &["a/b::leg"],
            &["a/b/"],
            Some(Scope::Outer),
        );
        // Leg is a directory; suppressor names the same directory, with and
        // without the slash.
        let same_dir = rule("r::same-dir", &["a/b/"], &["a/b"], None);

        // `any:` with an inline condition can match without any trait, so
        // covering every trait entry does not make the rule dead.
        let mut inline_any = rule("r::inline-any", &[], &["c/d/"], None);
        inline_any.any = Some(vec![
            Condition::Trait {
                id: "c/d::one".to_string(),
            },
            Condition::Syscall {
                name: Some(vec!["socket".to_string()]),
                number: None,
                arch: None,
                args: Vec::new(),
            },
        ]);

        let mut dg_none = rule("r::dg-none", &["s/t::leg"], &[], None);
        dg_none.downgrade = Some(dg(&["s/t/"], &[], &["x/y::ctx"], None, None));
        let mut dg_scoped = rule("r::dg-scoped", &["s/t::leg"], &[], None);
        dg_scoped.downgrade = Some(dg(&["s/t/"], &[], &[], None, Some(Scope::Archive)));
        let mut dg_needs_short = rule("r::dg-needs-short", &["s/t::leg"], &[], None);
        dg_needs_short.downgrade = Some(dg(&["s/t/", "x/y::ctx"], &[], &[], Some(2), None));
        let mut dg_needs_met = rule("r::dg-needs-met", &["s/t::leg", "u/v::leg"], &[], None);
        dg_needs_met.downgrade = Some(dg(&["s/t/", "u/v::leg"], &[], &[], Some(2), None));

        let rules = [
            leaf_scope,
            package_scope,
            outer_scope,
            same_dir,
            inline_any,
            dg_none,
            dg_scoped,
            dg_needs_short,
            dg_needs_met,
        ];
        let flagged: Vec<(&str, &str)> = find_leg_suppressing_composites(&rules)
            .iter()
            .map(|(r, _, _, clause)| (r.id.as_str(), *clause))
            .collect();
        assert_eq!(
            flagged,
            [
                ("r::leaf-scope", "unless"),
                ("r::same-dir", "unless"),
                ("r::dg-needs-met", "downgrade"),
            ]
        );
    }

    #[test]
    fn test_composite_directory_self_reference_detected() {
        let rule = create_composite_any("foo/bar::alias", &["foo/bar"]);
        let rules = [rule];
        let violations = find_self_referencing_composites(&rules);

        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].0.id, "foo/bar::alias");
        assert_eq!(violations[0].1, "foo/bar");
    }

    #[test]
    fn test_directory_alias_with_constraints_not_flagged() {
        let traits = dir_traits(
            "foo/bar",
            &["foo/bar::a", "foo/bar::b", "foo/bar::c", "foo/bar::d"],
        );
        let mut rule = create_composite_any(
            "foo/bar::alias",
            &["foo/bar::a", "foo/bar::b", "foo/bar::c", "foo/bar::d"],
        );
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
            r#if: Condition::Kv(KvQuery {
                match_mode: Default::default(),
                path: "scripts.postinstall".to_string(),
                exact: Some("curl".to_string()),
                substr: None,
                regex: None,
                eq: None,
                ne: None,
                case_insensitive: false,
                exists: Some(false),
                length_min: None,
                length_max: None,
                is_check: None,
                not: None,
            }),
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
            r#if: Condition::Kv(KvQuery {
                match_mode: Default::default(),
                path: "scripts.postinstall".to_string(),
                exact: None,
                substr: None,
                regex: None,
                eq: None,
                ne: None,
                case_insensitive: false,
                exists: Some(false),
                length_min: None,
                length_max: None,
                is_check: None,
                not: None,
            }),
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

    /// A composite with neither `all:` nor `any:` fires on nothing —
    /// `evaluate_with_gates` matches `(None, None)` and bails — so it must be
    /// flagged. This is the shape authors actually write, since YAML omits a
    /// key rather than spelling out `all: []`.
    #[test]
    fn test_absent_all_and_any_is_flagged() {
        let rules = vec![CompositeTrait {
            required_trait_indices: Vec::new(),
            id: "test/no-conditions".to_string(),
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
            all: None,
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
        }];
        let result = find_empty_condition_clauses(&rules);
        assert_eq!(result.len(), 1);
        assert_eq!(
            result[0],
            ("test/no-conditions".to_string(), MISSING_CONDITIONS)
        );
    }

    /// Filter fields and `unless:` constrain or withhold evidence; they never
    /// supply it. A composite carrying only those still fires on nothing.
    #[test]
    fn test_filters_and_unless_do_not_count_as_conditions() {
        let rules = vec![CompositeTrait {
            required_trait_indices: Vec::new(),
            id: "test/filters-only".to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            r#for: vec![FileType::Pe],
            for_from_groups: false,
            size_min: Some(512),
            size_max: Some(102_400),
            all: None,
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
        assert_eq!(
            result[0],
            ("test/filters-only".to_string(), MISSING_CONDITIONS)
        );
    }

    /// A composite that carries real conditions is untouched, and the check
    /// only ever inspects composites — a size-only *atomic* trait is legal
    /// (`parsing.rs` synthesizes an always-true condition for it) and cannot
    /// reach this validator at all.
    #[test]
    fn test_populated_conditions_are_not_flagged() {
        let rules = vec![CompositeTrait {
            required_trait_indices: Vec::new(),
            id: "test/has-conditions".to_string(),
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
            all: Some(vec![Condition::Trait {
                id: "some-trait".to_string(),
            }]),
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
        }];
        assert!(find_empty_condition_clauses(&rules).is_empty());
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
    use crate::composite_rules::condition::{Condition, RawQuery};
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
                scope: None,
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
                scope: None,
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
                scope: None,
            }),
        );

        let refs = collect_trait_refs_from_trait_def(&trait_def);
        let ids: Vec<&str> = refs.iter().map(|(id, _)| id.as_str()).collect();
        assert!(ids.contains(&"if-ref"), "if: ref must be collected");
        assert!(ids.contains(&"unless-ref"), "unless: ref must be collected");
        assert!(
            ids.contains(&"dg-all-ref"),
            "downgrade: ref must be collected"
        );
        // Every collected ref is owned by the atomic trait.
        assert!(refs.iter().all(|(_, owner)| owner == "atomic-trait"));
    }

    // A non-trait `if:` (raw/pattern condition) yields no refs, and an atomic trait
    // with no exemptions is ref-free — the common case must not spuriously report refs.
    #[test]
    fn test_collect_refs_from_atomic_trait_ignores_non_trait_conditions() {
        let trait_def = make_trait_def(
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
            None,
            None,
        );

        assert!(collect_trait_refs_from_trait_def(&trait_def).is_empty());
    }
}

#[cfg(test)]
mod excessive_skip_tests {
    use crate::capabilities::validation::constraints::find_excessive_skip_conditions;
    use crate::composite_rules::condition::{Condition, RawQuery};
    use crate::composite_rules::traits::{CompositeTrait, DowngradeConditions, TraitDefinition};
    use crate::types::Criticality;

    /// `n` distinct, inert raw conditions — stand-ins for suppression entries.
    fn raw_conds(n: usize) -> Vec<Condition> {
        (0..n)
            .map(|i| {
                Condition::Raw(RawQuery {
                    exact: Some(format!("c{i}")),
                    ..Default::default()
                })
            })
            .collect()
    }

    fn trait_def(
        id: &str,
        r#if: Condition,
        unless: usize,
        downgrade_all: usize,
    ) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "t".to_string(),
            crit: Criticality::Suspicious,
            r#if,
            unless: (unless > 0).then(|| raw_conds(unless)),
            downgrade: (downgrade_all > 0).then(|| DowngradeConditions {
                any: None,
                all: Some(raw_conds(downgrade_all)),
                none: None,
                needs: None,
                scope: None,
            }),
            ..Default::default()
        }
    }

    fn raw_if() -> Condition {
        Condition::Raw(RawQuery {
            exact: Some("marker".to_string()),
            ..Default::default()
        })
    }

    /// `Condition::Trait` reference for each ID.
    fn refs(ids: &[&str]) -> Vec<Condition> {
        ids.iter()
            .map(|r| Condition::Trait {
                id: (*r).to_string(),
            })
            .collect()
    }

    /// An aggregator composite — its `any:` legs are the exception list a rule pulls
    /// in by referencing it from `unless:`.
    fn aggregator(id: &str, any_legs: &[&str]) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "agg".to_string(),
            crit: Criticality::Component,
            any: Some(refs(any_legs)),
            ..Default::default()
        }
    }

    /// A composite rule whose only suppression is the given `unless:` conditions.
    fn rule_unless(id: &str, unless: Vec<Condition>) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "r".to_string(),
            crit: Criticality::Suspicious,
            unless: Some(unless),
            ..Default::default()
        }
    }

    /// Leaf IDs `p0..pn` (e.g. `a0`, `b0`) — referenced but never defined as composites,
    /// so each resolves to a single leaf exception.
    fn leaf_ids(prefix: &str, n: usize) -> Vec<String> {
        (0..n).map(|i| format!("{prefix}{i}")).collect()
    }

    // The own limit (10) counts the `unless:`/`downgrade:` entries written literally on a
    // single rule, regardless of what it references. This is the original behavior.
    #[test]
    fn own_limit_flags_single_rule() {
        let traits = vec![trait_def("t", raw_if(), 6, 4)];
        let v = find_excessive_skip_conditions(&traits, &[]);
        let t = v
            .iter()
            .find(|e| e.id == "t")
            .expect("flagged on own count");
        assert_eq!((t.own, t.is_composite), (10, false));
    }

    // A few literal exceptions, no aggregator references => clean on both limits.
    #[test]
    fn under_both_limits_is_clean() {
        let traits = vec![trait_def("a", raw_if(), 9, 0)];
        assert!(find_excessive_skip_conditions(&traits, &[]).is_empty());
    }

    // The expanded limit (32) catches an exception list hidden behind one reference:
    // `unless: [agg]` where `agg` enumerates 45 benign indicators. Own count is 1.
    #[test]
    fn expanded_aggregator_reference_flags_rule() {
        let leaves = leaf_ids("a", 45);
        let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
        let composites = vec![
            aggregator("agg", &leaf_refs),
            rule_unless("comp", refs(&["agg"])),
        ];

        let v = find_excessive_skip_conditions(&[], &composites);
        let comp = v
            .iter()
            .find(|e| e.id == "comp")
            .expect("flagged on expanded count");
        assert_eq!((comp.own, comp.expanded), (1, 45));
        // The aggregator itself carries no suppressions, so it is not flagged.
        assert!(!v.iter().any(|e| e.id == "agg"));
    }

    // The KEY property: `all:`/`any:` MATCHING references are never counted as
    // suppressions. A rule that merely requires a heavily-suppressed composite to match
    // inherits none of its exceptions.
    #[test]
    fn matching_references_are_not_counted() {
        let heavy = rule_unless("heavy", raw_conds(50)); // 50 literal exceptions
        let comp = CompositeTrait {
            id: "comp".to_string(),
            desc: "c".to_string(),
            crit: Criticality::Hostile,
            all: Some(refs(&["heavy"])), // requires heavy as a match, no unless of its own
            ..Default::default()
        };
        let v = find_excessive_skip_conditions(&[], &[heavy, comp]);
        assert!(
            !v.iter().any(|e| e.id == "comp"),
            "a matching (all:) reference must not contribute to the suppression count"
        );
        assert!(
            v.iter().any(|e| e.id == "heavy"),
            "heavy itself is over the limit"
        );
    }

    // Leaf and `dir/` references inside `unless:` each count as one — only aggregator
    // composites expand. Here 39 expanded + 1 dir + 1 leaf = 41 trips the limit.
    #[test]
    fn leaf_and_directory_references_count_one() {
        let leaves = leaf_ids("a", 39);
        let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
        let composites = vec![
            aggregator("agg", &leaf_refs),
            rule_unless("comp", refs(&["agg", "some/dir/", "x::leaf"])),
        ];

        let v = find_excessive_skip_conditions(&[], &composites);
        let comp = v.iter().find(|e| e.id == "comp").expect("flagged");
        assert_eq!((comp.own, comp.expanded), (3, 41));
    }

    // An aggregator is expanded for every referrer, shared or not: the recursive cap
    // measures each rule's exception burden, and sharing a 45-leg cluster does not make
    // the 45 conditions weigh less on the rule that pulls them in. Both users are flagged.
    #[test]
    fn shared_aggregator_is_expanded_for_every_referrer() {
        let leaves = leaf_ids("a", 45);
        let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
        let composites = vec![
            aggregator("agg", &leaf_refs),
            rule_unless("r1", refs(&["agg"])),
            rule_unless("r2", refs(&["agg"])), // sharing is no discount
        ];

        let v = find_excessive_skip_conditions(&[], &composites);
        for id in ["r1", "r2"] {
            let e = v.iter().find(|e| e.id == id).expect("flagged");
            assert_eq!((e.own, e.expanded), (1, 45));
        }
    }

    // Aggregator cycles still terminate: a node revisited within one rule's walk is
    // counted zero the second time, so two aggregators that reference each other resolve
    // to a finite total rather than recursing forever.
    #[test]
    fn aggregator_cycle_terminates() {
        let composites = vec![
            CompositeTrait {
                id: "a".to_string(),
                desc: "agg".to_string(),
                crit: Criticality::Component,
                any: Some(refs(&["b"])),
                ..Default::default()
            },
            CompositeTrait {
                id: "b".to_string(),
                desc: "agg".to_string(),
                crit: Criticality::Component,
                any: Some(refs(&["a"])),
                ..Default::default()
            },
            rule_unless("comp", refs(&["a"])),
        ];

        let v = find_excessive_skip_conditions(&[], &composites);
        // a -> b -> a(already counted, 0): the cycle contributes nothing past first visit,
        // so `comp` stays well under the cap and is not flagged.
        assert!(!v.iter().any(|e| e.id == "comp"));
    }

    // A `*-known-benign-context` composite is a named exception group: an author
    // wrote it specifically to be referenced widely, and growing its own list is
    // the fix this validator's message recommends when a rule's suppressions run
    // long. Expanding through it counted the group's membership as the referrer's
    // burden, so `js-global-object-alias-assignment` (real shape: 1 written,
    // 112 expanded via `js-assign-common-root-known-benign-context`) tripped the
    // cap for taking that advice. It must be treated as opaque, like a directory
    // reference, regardless of how many benign shapes it enumerates internally.
    #[test]
    fn named_exception_group_counts_as_one_not_expanded() {
        let leaves = leaf_ids("a", 112);
        let leaf_refs: Vec<&str> = leaves.iter().map(String::as_str).collect();
        let composites = vec![
            aggregator(
                "some/dir::js-assign-common-root-known-benign-context",
                &leaf_refs,
            ),
            rule_unless(
                "js-global-object-alias-assignment",
                refs(&["some/dir::js-assign-common-root-known-benign-context"]),
            ),
        ];

        let v = find_excessive_skip_conditions(&[], &composites);
        assert!(
            !v.iter()
                .any(|e| e.id == "js-global-object-alias-assignment"),
            "a single reference to a named exception group must not trip the expanded cap"
        );
    }
}

#[cfg(test)]
mod orphan_tests {
    use crate::capabilities::validation::constraints::find_orphaned_components;
    use crate::composite_rules::traits::{CompositeTrait, DowngradeConditions};
    use crate::composite_rules::{Arch, Condition, FileType, Platform, RawQuery, TraitDefinition};
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
            r#if: Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
                scope: None,
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

    /// A directory reference covers the components under that directory and
    /// its subdirectories, and nothing in a sibling that merely shares its
    /// name as a prefix.
    #[test]
    fn a_directory_reference_covers_only_its_own_components() {
        let trait_defs: Vec<TraitDefinition> = ["a/a::w", "a/b::x", "a/b/c::y", "a/bc::z"]
            .into_iter()
            .map(make_component_trait)
            .collect();
        let composites = vec![make_composite(
            "test::uses-dir",
            vec![Condition::Trait {
                id: "a/b/".to_string(),
            }],
            None,
        )];

        let orphans = find_orphaned_components(&trait_defs, &composites, &HashMap::new());
        let orphan_ids: Vec<&str> = orphans.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(orphan_ids, ["a/a::w", "a/bc::z"]);
    }
}

#[cfg(test)]
mod excessive_file_types_tests {
    use crate::capabilities::validation::constraints::find_excessive_file_types;
    use crate::composite_rules::{
        Arch, CompositeTrait, Condition, FileType, Platform, RawQuery, TraitDefinition,
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
            r#if: Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
                FileType::Beam,
                FileType::Wasm,
                FileType::Dex,
                FileType::StaticLib,
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
                FileType::Mirc,
                FileType::IrcII,
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
                FileType::Clojure,
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
    fn test_mixed_types_suggest_named_groups() {
        // Mix spanning multiple groups → suggest combining named groups, not `all`
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
        assert!(result[0].2.contains("named groups"));
        assert!(!result[0].2.contains("[all]"));
    }

    #[test]
    fn test_multi_group_union_exempt() {
        // `for: [scripts, binaries, source]` in YAML expands to the concrete
        // union of those named groups. The validator must not re-warn the
        // author to use groups they already used.
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
            FileType::Mirc,
            FileType::IrcII,
        ];
        let binaries = vec![
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
            FileType::Class,
            FileType::Pyc,
            FileType::Beam,
            FileType::Wasm,
            FileType::Dex,
            FileType::StaticLib,
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
            FileType::Clojure,
        ];
        let combined: Vec<FileType> = scripts.into_iter().chain(binaries).chain(source).collect();
        assert_eq!(combined.len(), 38);
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
    /// The check must still catch a genuine hand-enumeration: a set no
    /// complete group covers.
    #[test]
    fn partial_enumeration_is_still_reported() {
        let hand_picked = vec![
            FileType::Png,
            FileType::Jpeg,
            FileType::Wav,
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
            FileType::Python,
            FileType::Shell,
            FileType::Ruby,
        ];
        let violations =
            find_excessive_file_types(&[trait_with_for("t/handpicked", hand_picked)], &[]);
        assert_eq!(violations.len(), 1, "{violations:?}");
    }

    /// Every file type belongs to exactly one named group.
    ///
    /// Group membership is how `for:` breadth is judged, so a type in two
    /// groups makes that judgement ambiguous: naming one complete group then
    /// partially "touches" the other through the shared type and reads as a
    /// hand-written enumeration. Dockerfile was in both `manifests` and
    /// `build`, and folding SVG into `media` while `Xml` stayed in `manifests`
    /// would have reintroduced it. This test is the enforcement.
    #[test]
    fn named_groups_are_disjoint() {
        use crate::capabilities::validation::constraints::ALL_GROUPS;
        let mut owner: std::collections::HashMap<FileType, &str> = std::collections::HashMap::new();
        let mut clashes = Vec::new();
        for (types, name) in ALL_GROUPS {
            for ft in *types {
                if let Some(prev) = owner.insert(*ft, name) {
                    clashes.push(format!("{ft:?} is in both `{prev}` and `{name}`"));
                }
            }
        }
        assert!(
            clashes.is_empty(),
            "file-type groups must be disjoint:\n  {}",
            clashes.join("\n  ")
        );
    }

    /// A complete named group is expressible however many types it holds.
    #[test]
    fn each_named_group_is_expressible_on_its_own() {
        use crate::capabilities::validation::constraints::ALL_GROUPS;
        for (types, name) in ALL_GROUPS {
            let violations =
                find_excessive_file_types(&[trait_with_for("t/g", types.to_vec())], &[]);
            assert!(
                violations.is_empty(),
                "group `{name}` should be expressible: {violations:?}"
            );
        }
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
    use crate::composite_rules::{Arch, Condition, FileType, Platform, RawQuery, TraitDefinition};
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
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
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
        })
    }

    fn raw_regex(pattern: &str) -> Condition {
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
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
        })
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
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
        );
        let mut warnings = Vec::new();
        find_raw_should_use_string_value(&[t], &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn skips_with_section_constraint() {
        let t = binary_trait(
            "t/section",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
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
            }),
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
    use crate::composite_rules::{Arch, Condition, FileType, Platform, TextQuery, TraitDefinition};
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
            r#if: Condition::Text(TextQuery {
                encoding: None,
                length_min: None,
                length_max: None,
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
            }),
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
    use crate::composite_rules::{
        Arch, Condition, FileType, LiteralQuery, Platform, TraitDefinition,
    };
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
            Condition::Literal(LiteralQuery {
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
            }),
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
    use crate::composite_rules::{Arch, Condition, FileType, Platform, TextQuery, TraitDefinition};
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
        Condition::Text(TextQuery {
            encoding: None,
            length_min: None,
            length_max: None,
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
        })
    }

    fn text_regex(value: &str) -> Condition {
        Condition::Text(TextQuery {
            encoding: None,
            length_min: None,
            length_max: None,
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
        })
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

#[cfg(test)]
mod brittle_path_pattern_tests {
    use crate::capabilities::validation::patterns::find_brittle_path_patterns;
    use crate::composite_rules::{Arch, Condition, FileType, PathQuery, Platform, TraitDefinition};
    use std::path::PathBuf;

    fn make_trait(condition: Condition) -> TraitDefinition {
        TraitDefinition {
            id: "test/path-brittle".to_string(),
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

    fn path_substr(value: &str) -> Condition {
        Condition::Path(PathQuery {
            exact: None,
            substr: Some(value.to_string()),
            regex: None,
            case_insensitive: false,
            is_check: None,
            basename: false,
            dirname: false,
        })
    }

    fn path_regex(value: &str) -> Condition {
        Condition::Path(PathQuery {
            exact: None,
            substr: None,
            regex: Some(value.to_string()),
            case_insensitive: false,
            is_check: None,
            basename: false,
            dirname: false,
        })
    }

    fn warnings_for(condition: Condition) -> Vec<String> {
        let mut warnings = Vec::new();
        find_brittle_path_patterns(&[make_trait(condition)], &mut warnings);
        warnings
    }

    #[test]
    fn flags_bang_in_substr() {
        let w = warnings_for(path_substr("foo!bar"));
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("contains '!'"), "{}", w[0]);
    }

    #[test]
    fn flags_too_many_slashes() {
        let w = warnings_for(path_substr("usr/local/bin/thing"));
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("'/' separators"), "{}", w[0]);
    }

    #[test]
    fn allows_two_slashes() {
        assert!(warnings_for(path_substr("usr/bin/env")).is_empty());
    }

    #[test]
    fn flags_overlong_pattern() {
        let long = "a".repeat(65);
        let w = warnings_for(path_regex(&long));
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("chars long"), "{}", w[0]);
    }

    #[test]
    fn allows_exactly_64_chars() {
        let exact_len = "a".repeat(64);
        assert!(warnings_for(path_substr(&exact_len)).is_empty());
    }

    #[test]
    fn checks_regex_field_too() {
        let w = warnings_for(path_regex(r"a/b/c/d"));
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("regex"), "{}", w[0]);
    }

    #[test]
    fn ignores_exact_full_paths() {
        // `exact` is a precise full-path match — slashes are legitimate there.
        let cond = Condition::Path(PathQuery {
            exact: Some("/usr/local/bin/evil".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            is_check: None,
            basename: false,
            dirname: false,
        });
        assert!(warnings_for(cond).is_empty());
    }

    #[test]
    fn allows_shallow_short_substr() {
        assert!(warnings_for(path_substr(".bashrc")).is_empty());
    }
}

#[cfg(test)]
mod exception_validation_tests {
    use crate::capabilities::validation::taxonomy::{
        find_benign_misplaced, find_exception_atomic_traits, find_exception_inline_conditions,
        find_exception_non_notable_members, find_exception_positive_refs,
        find_unreferenced_exceptions,
    };
    use crate::composite_rules::traits::{CompositeTrait, DowngradeConditions};
    use crate::composite_rules::{Condition, TraitDefinition};
    use crate::types::Criticality;
    use std::collections::HashMap;

    fn tcond(id: &str) -> Condition {
        Condition::Trait { id: id.to_string() }
    }

    fn inline_cond() -> Condition {
        Condition::Syscall {
            name: Some(vec!["socket".to_string()]),
            number: None,
            arch: None,
            args: Vec::new(),
        }
    }

    fn atom(id: &str, crit: Criticality) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "d".to_string(),
            crit,
            ..Default::default()
        }
    }

    fn comp(id: &str, crit: Criticality) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "d".to_string(),
            crit,
            ..Default::default()
        }
    }

    fn with_all(mut c: CompositeTrait, refs: &[&str]) -> CompositeTrait {
        c.all = Some(refs.iter().map(|r| tcond(r)).collect());
        c
    }

    fn with_any(mut c: CompositeTrait, refs: &[&str]) -> CompositeTrait {
        c.any = Some(refs.iter().map(|r| tcond(r)).collect());
        c
    }

    fn with_unless(mut c: CompositeTrait, refs: &[&str]) -> CompositeTrait {
        c.unless = Some(refs.iter().map(|r| tcond(r)).collect());
        c
    }

    fn sources(ids: &[&str]) -> HashMap<String, String> {
        ids.iter()
            .map(|i| ((*i).to_string(), "test.yaml".to_string()))
            .collect()
    }

    // ---- V1: only composites may be crit: exception ----

    #[test]
    fn v1_flags_atomic_exception_only() {
        let traits = vec![
            atom("micro-behaviors/x::a", Criticality::Exception),
            atom("micro-behaviors/x::b", Criticality::Notable),
        ];
        let src = sources(&["micro-behaviors/x::a", "micro-behaviors/x::b"]);
        let v = find_exception_atomic_traits(&traits, &src);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, "micro-behaviors/x::a");
    }

    // ---- V2: exception referenced as positive evidence ----

    #[test]
    fn v2_flags_exact_positive_ref_from_non_exception() {
        let composites = vec![
            comp(
                "well-known/tool/foo::benign-pattern",
                Criticality::Exception,
            ),
            with_all(
                comp("objectives/c2::beacon", Criticality::Suspicious),
                &["well-known/tool/foo::benign-pattern"],
            ),
        ];
        let src = sources(&[
            "well-known/tool/foo::benign-pattern",
            "objectives/c2::beacon",
        ]);
        let v = find_exception_positive_refs(&[], &composites, &src);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].0, "objectives/c2::beacon");
    }

    #[test]
    fn v2_flags_exact_positive_ref_in_any_clause() {
        let composites = vec![
            comp(
                "well-known/tool/foo::benign-pattern",
                Criticality::Exception,
            ),
            with_any(
                comp("objectives/c2::beacon", Criticality::Suspicious),
                &["well-known/tool/foo::benign-pattern"],
            ),
        ];
        let src = sources(&[
            "well-known/tool/foo::benign-pattern",
            "objectives/c2::beacon",
        ]);
        let v = find_exception_positive_refs(&[], &composites, &src);
        assert_eq!(v.len(), 1, "{v:?}");
    }

    #[test]
    fn v2_ignores_directory_ref_containing_exception() {
        // A bare-directory positive ref that *contains* an exception is NOT a violation —
        // the runtime excludes the exception from directory expansion.
        let composites = vec![
            comp(
                "objectives/tools/foo::benign-pattern",
                Criticality::Exception,
            ),
            with_all(
                comp("objectives/c2::beacon", Criticality::Suspicious),
                &["objectives/tools"],
            ),
        ];
        let src = sources(&[
            "objectives/tools/foo::benign-pattern",
            "objectives/c2::beacon",
        ]);
        let v = find_exception_positive_refs(&[], &composites, &src);
        assert!(v.is_empty(), "directory ref should not be flagged: {v:?}");
    }

    #[test]
    fn v2_exempts_exception_parent() {
        let composites = vec![
            comp("well-known/tool/a::exc-a", Criticality::Exception),
            with_all(
                comp("well-known/tool/b::exc-b", Criticality::Exception),
                &["well-known/tool/a::exc-a"],
            ),
        ];
        let src = sources(&["well-known/tool/a::exc-a", "well-known/tool/b::exc-b"]);
        let v = find_exception_positive_refs(&[], &composites, &src);
        assert!(
            v.is_empty(),
            "exception parent may compose exceptions: {v:?}"
        );
    }

    #[test]
    fn v2_allows_unless_ref_to_exception() {
        let composites = vec![
            comp(
                "well-known/tool/foo::benign-pattern",
                Criticality::Exception,
            ),
            with_unless(
                comp("objectives/c2::beacon", Criticality::Suspicious),
                &["well-known/tool/foo::benign-pattern"],
            ),
        ];
        let src = sources(&[
            "well-known/tool/foo::benign-pattern",
            "objectives/c2::beacon",
        ]);
        let v = find_exception_positive_refs(&[], &composites, &src);
        assert!(v.is_empty(), "unless ref is fine: {v:?}");
    }

    // ---- V3: unreferenced exceptions ----

    #[test]
    fn v3_flags_unreferenced_exception() {
        let composites = vec![comp("well-known/tool/foo::lonely", Criticality::Exception)];
        let src = sources(&["well-known/tool/foo::lonely"]);
        let v = find_unreferenced_exceptions(&[], &composites, &src);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, "well-known/tool/foo::lonely");
    }

    #[test]
    fn v3_exact_unless_ref_satisfies() {
        let composites = vec![
            comp("well-known/tool/foo::exc", Criticality::Exception),
            with_unless(
                comp("objectives/c2::beacon", Criticality::Suspicious),
                &["well-known/tool/foo::exc"],
            ),
        ];
        let src = sources(&["well-known/tool/foo::exc", "objectives/c2::beacon"]);
        let v = find_unreferenced_exceptions(&[], &composites, &src);
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn v3_exception_parent_directory_ref_satisfies() {
        // An exception parent IS allowed to assemble a directory of exceptions, so a
        // directory ref from one reaches (references) the exceptions beneath it.
        let composites = vec![
            comp("objectives/tools/foo::exc", Criticality::Exception),
            with_all(
                comp("objectives/tools::bundle", Criticality::Exception),
                &["objectives/tools"],
            ),
            with_unless(
                comp("objectives/c2::beacon", Criticality::Suspicious),
                &["objectives/tools::bundle"],
            ),
        ];
        let src = sources(&[
            "objectives/tools/foo::exc",
            "objectives/tools::bundle",
            "objectives/c2::beacon",
        ]);
        let v = find_unreferenced_exceptions(&[], &composites, &src);
        // foo::exc is reached by the bundle's directory ref; the bundle by the
        // beacon's unless. Neither is unreferenced.
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn v3_directory_ref_does_not_satisfy() {
        // Only an exact ref reaches an exception; a directory ref leaves it dead.
        let composites = vec![
            comp("objectives/tools/foo::exc", Criticality::Exception),
            with_unless(
                comp("objectives/c2::beacon", Criticality::Suspicious),
                &["objectives/tools"],
            ),
        ];
        let src = sources(&["objectives/tools/foo::exc", "objectives/c2::beacon"]);
        let v = find_unreferenced_exceptions(&[], &composites, &src);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].0, "objectives/tools/foo::exc");
    }

    // ---- V4: members must be exactly notable (or another exception) ----

    #[test]
    fn v4_allows_notable_and_exception_members() {
        let traits = vec![atom("objectives/x::n", Criticality::Notable)];
        let composites = vec![
            comp("well-known/tool/sub::exc-sub", Criticality::Exception),
            with_all(
                comp("well-known/tool/foo::exc", Criticality::Exception),
                &["objectives/x::n", "well-known/tool/sub::exc-sub"],
            ),
        ];
        let src = sources(&[
            "objectives/x::n",
            "well-known/tool/sub::exc-sub",
            "well-known/tool/foo::exc",
        ]);
        let v = find_exception_non_notable_members(&traits, &composites, &src);
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn v4_flags_baseline_and_suspicious_members() {
        let traits = vec![
            atom("objectives/x::base", Criticality::Baseline),
            atom("objectives/x::susp", Criticality::Suspicious),
        ];
        let composites = vec![with_all(
            comp("well-known/tool/foo::exc", Criticality::Exception),
            &["objectives/x::base", "objectives/x::susp"],
        )];
        let src = sources(&[
            "objectives/x::base",
            "objectives/x::susp",
            "well-known/tool/foo::exc",
        ]);
        let v = find_exception_non_notable_members(&traits, &composites, &src);
        assert_eq!(v.len(), 2, "{v:?}");
    }

    #[test]
    fn v4_directory_member_requires_notable_non_exceptions() {
        let traits = vec![
            atom("objectives/dir::n", Criticality::Notable),
            atom("objectives/dir::base", Criticality::Baseline),
        ];
        let composites = vec![
            comp("objectives/dir::exc-inside", Criticality::Exception),
            with_all(
                comp("well-known/tool/foo::exc", Criticality::Exception),
                &["objectives/dir"],
            ),
        ];
        let src = sources(&[
            "objectives/dir::n",
            "objectives/dir::base",
            "objectives/dir::exc-inside",
            "well-known/tool/foo::exc",
        ]);
        let v = find_exception_non_notable_members(&traits, &composites, &src);
        // Only the baseline under the dir is flagged; the notable and the nested
        // exception are fine.
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].1, "objectives/dir::base");
    }

    // ---- V5: named traits only (no inline conditions) ----

    #[test]
    fn v5_flags_inline_condition_in_any_clause() {
        let mut c = comp("well-known/tool/foo::exc", Criticality::Exception);
        c.all = Some(vec![tcond("objectives/x::n")]);
        c.any = Some(vec![inline_cond()]);
        let composites = vec![c];
        let src = sources(&["well-known/tool/foo::exc"]);
        let v = find_exception_inline_conditions(&composites, &src);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].1, "any");
        assert_eq!(v[0].2, "syscall");
    }

    #[test]
    fn v5_flags_inline_condition_in_downgrade() {
        let mut c = comp("well-known/tool/foo::exc", Criticality::Exception);
        c.all = Some(vec![tcond("objectives/x::n")]);
        c.downgrade = Some(DowngradeConditions {
            any: Some(vec![inline_cond()]),
            all: None,
            none: None,
            needs: None,
            scope: None,
        });
        let composites = vec![c];
        let src = sources(&["well-known/tool/foo::exc"]);
        let v = find_exception_inline_conditions(&composites, &src);
        assert_eq!(v.len(), 1, "{v:?}");
        assert_eq!(v[0].1, "downgrade.any");
    }

    #[test]
    fn v5_allows_all_trait_refs() {
        let composites = vec![with_all(
            comp("well-known/tool/foo::exc", Criticality::Exception),
            &["objectives/x::n"],
        )];
        let src = sources(&["well-known/tool/foo::exc"]);
        let v = find_exception_inline_conditions(&composites, &src);
        assert!(v.is_empty(), "{v:?}");
    }

    // ---- benign-misplaced ----

    #[test]
    fn benign_flags_objectives_and_wellknown_malware() {
        let traits = vec![atom("objectives/c2::benign-beacon", Criticality::Notable)];
        let mut malware = comp("well-known/malware/trojan::x", Criticality::Notable);
        malware.desc = "safety-context suppressor".to_string();
        let composites = vec![malware];
        let src = sources(&[
            "objectives/c2::benign-beacon",
            "well-known/malware/trojan::x",
        ]);
        let v = find_benign_misplaced(&traits, &composites, &src);
        assert_eq!(v.len(), 2, "{v:?}");
    }

    #[test]
    fn benign_flags_context_and_fp_context_conventions() {
        let traits = vec![
            // `*-context` suppression-context convention (the dominant one in-corpus).
            atom(
                "objectives/supply-chain/trojanized::ghost-theme-preview-context",
                Criticality::Notable,
            ),
            // `fp-context` explicitly, in a description.
            atom(
                "well-known/malware/trojan/x::network-helper",
                Criticality::Component,
            ),
        ];
        let mut traits = traits;
        traits[1].desc = "fp-context for known network library".to_string();
        let src = sources(&[
            "objectives/supply-chain/trojanized::ghost-theme-preview-context",
            "well-known/malware/trojan/x::network-helper",
        ]);
        let v = find_benign_misplaced(&traits, &[], &src);
        assert_eq!(v.len(), 2, "{v:?}");
    }

    #[test]
    fn benign_flags_fp_and_exceptions_suffixes() {
        let traits = vec![
            atom(
                "objectives/anti-static/shape::control-flow-soft-fp",
                Criticality::Component,
            ),
            atom(
                "objectives/anti-static/shape::many-strings-known-fps",
                Criticality::Component,
            ),
            atom(
                "objectives/c2/dropper::curl-pipe-shell-exceptions",
                Criticality::Notable,
            ),
        ];
        let src = sources(&[
            "objectives/anti-static/shape::control-flow-soft-fp",
            "objectives/anti-static/shape::many-strings-known-fps",
            "objectives/c2/dropper::curl-pipe-shell-exceptions",
        ]);
        let v = find_benign_misplaced(&traits, &[], &src);
        assert_eq!(v.len(), 3, "{v:?}");
    }

    #[test]
    fn benign_does_not_flag_plain_detection_rules() {
        // A normal detection rule with no suppression marker is left alone.
        let traits = vec![
            atom("objectives/c2/http::beacon-interval", Criticality::Notable),
            atom(
                "well-known/malware/trojan/x::c2-domain",
                Criticality::Notable,
            ),
        ];
        let src = sources(&[
            "objectives/c2/http::beacon-interval",
            "well-known/malware/trojan/x::c2-domain",
        ]);
        let v = find_benign_misplaced(&traits, &[], &src);
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn benign_exempts_exception_and_other_tiers() {
        let traits = vec![
            // wrong tier: micro-behaviors is fine
            atom("micro-behaviors/x::benign-thing", Criticality::Baseline),
            // well-known/tool is not malware: fine
            atom("well-known/tool/foo::benign-id", Criticality::Notable),
        ];
        // crit: exception in objectives with "benign" in id — the sanctioned home.
        let composites = vec![comp(
            "objectives/c2::benign-pattern",
            Criticality::Exception,
        )];
        let src = sources(&[
            "micro-behaviors/x::benign-thing",
            "well-known/tool/foo::benign-id",
            "objectives/c2::benign-pattern",
        ]);
        let v = find_benign_misplaced(&traits, &composites, &src);
        assert!(v.is_empty(), "{v:?}");
    }
}

#[cfg(test)]
mod wide_directory_tests {
    use crate::capabilities::validation::{
        MAX_SUBDIRECTORIES_PER_DIRECTORY, find_wide_trait_directories,
    };

    /// Leaf directories under `parent`, one per child: `parent/child-<n>`.
    fn leaves(parent: &str, count: usize) -> Vec<String> {
        (0..count).map(|n| format!("{parent}/child-{n}")).collect()
    }

    #[test]
    fn narrow_directory_is_clean() {
        let dirs = leaves("well-known/app", MAX_SUBDIRECTORIES_PER_DIRECTORY);
        assert!(find_wide_trait_directories(&dirs).is_empty());
    }

    #[test]
    fn wide_directory_is_flagged() {
        let dirs = leaves("well-known/app", MAX_SUBDIRECTORIES_PER_DIRECTORY + 1);
        assert_eq!(
            find_wide_trait_directories(&dirs),
            vec![(
                "well-known/app".to_string(),
                MAX_SUBDIRECTORIES_PER_DIRECTORY + 1
            )]
        );
    }

    #[test]
    fn counts_immediate_children_not_descendants() {
        // One child holding many grandchildren keeps the parent narrow.
        let dirs = leaves(
            "well-known/app/chrome",
            MAX_SUBDIRECTORIES_PER_DIRECTORY + 1,
        );
        let violations = find_wide_trait_directories(&dirs);
        assert_eq!(
            violations,
            vec![(
                "well-known/app/chrome".to_string(),
                MAX_SUBDIRECTORIES_PER_DIRECTORY + 1
            )],
            "only the level that fans out should be reported"
        );
    }

    #[test]
    fn child_seen_through_many_leaves_counts_once() {
        // Deeper leaves under the same child must not inflate the parent's width.
        let mut dirs = leaves("well-known/app", MAX_SUBDIRECTORIES_PER_DIRECTORY);
        dirs.extend((0..50).map(|n| format!("well-known/app/child-0/deep-{n}")));
        assert!(find_wide_trait_directories(&dirs).is_empty());
    }

    #[test]
    fn violations_are_widest_first_then_lexicographic() {
        let mut dirs = leaves("well-known/app", MAX_SUBDIRECTORIES_PER_DIRECTORY + 9);
        dirs.extend(leaves(
            "well-known/lib",
            MAX_SUBDIRECTORIES_PER_DIRECTORY + 1,
        ));
        dirs.extend(leaves(
            "well-known/game",
            MAX_SUBDIRECTORIES_PER_DIRECTORY + 1,
        ));
        let violations = find_wide_trait_directories(&dirs);
        let order: Vec<&str> = violations.iter().map(|(dir, _)| dir.as_str()).collect();
        assert_eq!(
            order,
            ["well-known/app", "well-known/game", "well-known/lib"]
        );
    }
}

/// Tests for [`find_bare_or_crit_escalations`]: a bare `any:` composite that
/// adds no filtering must agree with its legs about how serious a match is.
mod bare_or_crit_escalation_tests {
    use crate::capabilities::validation::find_bare_or_crit_escalations;
    use crate::composite_rules::traits::DowngradeConditions;
    use crate::composite_rules::{CompositeTrait, Condition, FileType, Platform, TraitDefinition};
    use crate::types::Criticality;

    /// A leaf trait at `crit`, scoped to `for_types` (empty = every type).
    fn leg(id: &str, crit: Criticality, for_types: Vec<FileType>) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "leg".to_string(),
            crit,
            r#for: for_types,
            platforms: vec![Platform::All],
            ..Default::default()
        }
    }

    /// A composite whose whole logic is `any:` over `legs`.
    fn bare_or(id: &str, crit: Criticality, legs: &[&str]) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "or".to_string(),
            crit,
            r#for: vec![],
            platforms: vec![Platform::All],
            any: Some(
                legs.iter()
                    .map(|l| Condition::Trait {
                        id: (*l).to_string(),
                    })
                    .collect(),
            ),
            ..Default::default()
        }
    }

    fn flagged_legs(
        traits: &[TraitDefinition],
        rules: &[CompositeTrait],
    ) -> Vec<(String, Criticality)> {
        let violations = find_bare_or_crit_escalations(traits, rules);
        assert!(violations.len() <= 1, "one rule under test: {violations:?}");
        violations
            .into_iter()
            .next()
            .map(|(_, _, l)| l)
            .unwrap_or_default()
    }

    #[test]
    fn under_ranked_legs_of_a_pure_relabelling_or_are_reported() {
        // The `offensive-tool-pdb` shape: one leg already carries the tier, the
        // other is promoted to it purely by being listed.
        let traits = vec![
            leg("d::metasploit", Criticality::Suspicious, vec![]),
            leg("d::cobalt", Criticality::Notable, vec![]),
        ];
        let rules = vec![bare_or(
            "d::offensive-pdb",
            Criticality::Suspicious,
            &["d::metasploit", "d::cobalt"],
        )];
        assert_eq!(
            flagged_legs(&traits, &rules),
            vec![("d::cobalt".to_string(), Criticality::Notable)],
            "only the leg below the composite is reported"
        );
    }

    #[test]
    fn legs_that_agree_with_the_composite_are_clean() {
        let traits = vec![
            leg("d::a", Criticality::Suspicious, vec![]),
            leg("d::b", Criticality::Suspicious, vec![]),
        ];
        let rules = vec![bare_or("d::or", Criticality::Suspicious, &["d::a", "d::b"])];
        assert!(flagged_legs(&traits, &rules).is_empty());
    }

    #[test]
    fn a_leg_above_the_composite_is_not_an_escalation() {
        // Demotion is a deliberate, separate choice; this validator is only
        // about a wrapper claiming more than its legs.
        let traits = vec![leg("d::a", Criticality::Hostile, vec![])];
        let rules = vec![bare_or("d::or", Criticality::Notable, &["d::a"])];
        assert!(flagged_legs(&traits, &rules).is_empty());
    }

    #[test]
    fn filtering_clauses_exempt_the_composite() {
        // `unless:`, `all:`, `needs:`, size and scope bounds all mean the
        // composite decides something its legs do not.
        let traits = vec![
            leg("d::a", Criticality::Component, vec![]),
            leg("d::b", Criticality::Component, vec![]),
        ];
        let base = bare_or("d::or", Criticality::Suspicious, &["d::a", "d::b"]);
        assert!(
            !flagged_legs(&traits, std::slice::from_ref(&base)).is_empty(),
            "the unfiltered form must flag, or the exemptions below prove nothing"
        );

        let with_unless = CompositeTrait {
            unless: Some(vec![Condition::Trait {
                id: "d::benign".to_string(),
            }]),
            ..base.clone()
        };
        assert!(
            flagged_legs(&traits, &[with_unless]).is_empty(),
            "unless: exempts"
        );

        let with_needs = CompositeTrait {
            needs: Some(2),
            ..base.clone()
        };
        assert!(
            flagged_legs(&traits, &[with_needs]).is_empty(),
            "needs: exempts"
        );

        let with_size = CompositeTrait {
            size_max: Some(4096),
            ..base.clone()
        };
        assert!(
            flagged_legs(&traits, &[with_size]).is_empty(),
            "size_max: exempts"
        );

        let with_downgrade = CompositeTrait {
            downgrade: Some(DowngradeConditions {
                any: Some(vec![Condition::Trait {
                    id: "d::benign".to_string(),
                }]),
                all: None,
                none: None,
                needs: None,
                scope: None,
            }),
            ..base.clone()
        };
        assert!(
            flagged_legs(&traits, &[with_downgrade]).is_empty(),
            "downgrade: exempts"
        );

        let with_all = CompositeTrait {
            all: Some(vec![Condition::Trait {
                id: "d::a".to_string(),
            }]),
            ..base
        };
        assert!(
            flagged_legs(&traits, &[with_all]).is_empty(),
            "all: exempts"
        );
    }

    #[test]
    fn a_different_for_scope_exempts_the_composite() {
        // Deciding *where* a leg counts is real work, and can earn a tier the
        // leg does not have everywhere. Exact agreement is required, so a
        // composite scoped differently from its leg — wider or narrower — is
        // left alone.
        let traits = vec![leg("d::a", Criticality::Notable, vec![])];
        let narrowed = CompositeTrait {
            r#for: vec![FileType::Elf],
            ..bare_or("d::or", Criticality::Suspicious, &["d::a"])
        };
        assert!(flagged_legs(&traits, &[narrowed]).is_empty());
    }

    #[test]
    fn a_rules_own_regex_split_legs_are_judged_like_any_other() {
        // Splitting an alternation into `--rx-N` legs is meant to give each
        // alternative a meaning of its own. A leg matching therefore says what
        // the reassembled composite says, so demoting the fragments below it is
        // the same laundering, arrived at mechanically.
        let traits = vec![
            leg("d::term--rx-1", Criticality::Component, vec![]),
            leg("d::term--rx-2", Criticality::Component, vec![]),
        ];
        let rules = vec![bare_or(
            "d::term",
            Criticality::Notable,
            &["d::term--rx-1", "d::term--rx-2"],
        )];
        assert_eq!(
            flagged_legs(&traits, &rules),
            vec![
                ("d::term--rx-1".to_string(), Criticality::Component),
                ("d::term--rx-2".to_string(), Criticality::Component),
            ]
        );
    }

    #[test]
    fn a_directory_leg_skips_the_whole_rule() {
        // "Raise every trait under this directory" is not a fix worth
        // prescribing, so the rule is not judged at all.
        let traits = vec![leg("d::a", Criticality::Component, vec![])];
        let rules = vec![bare_or(
            "d::or",
            Criticality::Suspicious,
            &["d::a", "d/sub"],
        )];
        assert!(flagged_legs(&traits, &rules).is_empty());
    }
}

/// `find_uncallable_symbol_matchers` — a `type: symbol` literal that no
/// extracted symbol can equal.
mod uncallable_symbol_matchers {
    use crate::capabilities::validation::find_uncallable_symbol_matchers;
    use crate::composite_rules::condition::{Condition, SymbolQuery};
    use crate::composite_rules::traits::TraitDefinition;
    use std::path::PathBuf;

    fn symbol_trait(id: &str, exact: &str) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 0.8,
            crit: crate::types::Criticality::Notable,
            r#if: Condition::Symbol(SymbolQuery {
                exact: Some(exact.to_string()),
                ..Default::default()
            }),
            defined_in: PathBuf::from("test.yml"),
            ..Default::default()
        }
    }

    fn flagged(exact: &str) -> bool {
        !find_uncallable_symbol_matchers(&[symbol_trait("t", exact)], &[]).is_empty()
    }

    /// A symbol is a dotted path of identifiers, so any spelling of the call
    /// itself is dead on arrival — including the trailing `()` that reads as
    /// the natural way to write a call.
    #[test]
    fn call_syntax_is_flagged() {
        assert!(flagged(".system()"), "trailing call marker");
        assert!(flagged("open().read"), "inner call marker");
        assert!(flagged("open(\"/tmp/x\").read"), "argument text");
        assert!(flagged(".eval("), "half-open call");
    }

    /// `exact:`/`substr:` compare literally, so a regex there matches nothing.
    #[test]
    fn regex_in_a_literal_field_is_flagged() {
        assert!(flagged("os\\.environ"), "escaped dot");
        assert!(flagged("os\\.environ\\[.{0,50}\\]"), "character class");
        assert!(flagged("clone|rename"), "alternation");
        assert!(flagged("^setup"), "anchor");
    }

    /// Names that really do occur must not be flagged. Go binaries export the
    /// receiver form; PE ordinal imports are named `ORDINAL <n>`; C++ has
    /// `operator delete`; and `$` is a legal JavaScript identifier character.
    #[test]
    fn real_symbol_names_are_left_alone() {
        for name in [
            "net.(*Dialer).Dial",
            "exec.(*Cmd).Run",
            "ORDINAL 187",
            "operator delete",
            "platform.system",
            "Date.getTimezoneOffset",
            "$",
            "jQuery$",
            "__import__.decompress",
            "s.replace.replace",
        ] {
            assert!(
                !flagged(name),
                "{name:?} is a real symbol and must not flag"
            );
        }
    }
}

/// `find_stale_filetype_allowlist_entries` — an allowlist entry whose
/// directory prefix matches no trait.
mod stale_filetype_allowlist {
    use crate::capabilities::validation::find_stale_filetype_allowlist_entries;
    use crate::capabilities::validation::taxonomy::BROAD_FILETYPE_ALLOWLIST;
    use std::collections::HashMap;

    /// Every shipped entry must match a real directory. When one does not, the
    /// exemption it encodes is silently gone -- the usual cause is a directory
    /// renamed without updating the entry, and the symptom is a pile of
    /// file-type cap violations nowhere near the rename.
    #[test]
    fn shipped_entries_all_match_a_real_directory() {
        // Stand in for the loaded taxonomy: one source path per entry prefix.
        let sources: HashMap<String, String> = BROAD_FILETYPE_ALLOWLIST
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                e.split_once(':')
                    .map(|(_, p)| (format!("t{i}"), format!("./{p}traits.yaml")))
            })
            .collect();
        assert!(
            find_stale_filetype_allowlist_entries(&sources).is_empty(),
            "every entry should match when each prefix has a source file"
        );
    }

    /// With no traits at all, every entry is stale — the check is actually
    /// looking at the sources rather than always passing.
    #[test]
    fn every_entry_is_stale_when_nothing_matches() {
        let empty: HashMap<String, String> = HashMap::new();
        assert_eq!(
            find_stale_filetype_allowlist_entries(&empty).len(),
            BROAD_FILETYPE_ALLOWLIST.len()
        );
    }

    /// A prefix that no longer exists is reported while its neighbours are not.
    #[test]
    fn only_the_unmatched_prefix_is_reported() {
        let mut sources: HashMap<String, String> = HashMap::new();
        let mut skipped = None;
        for (i, e) in BROAD_FILETYPE_ALLOWLIST.iter().enumerate() {
            let Some((_, prefix)) = e.split_once(':') else {
                continue;
            };
            if skipped.is_none() {
                skipped = Some(*e);
                continue;
            }
            sources.insert(format!("t{i}"), format!("./{prefix}traits.yaml"));
        }
        let stale = find_stale_filetype_allowlist_entries(&sources);
        let skipped = skipped.expect("at least one entry");
        assert!(
            stale.contains(&skipped),
            "the dropped prefix must be flagged"
        );
    }
}

#[cfg(test)]
mod archive_filetype_mix_tests {
    use crate::capabilities::validation::find_mixed_archive_filetype_traits;
    use crate::composite_rules::{Arch, Condition, FileType, Platform, TextQuery, TraitDefinition};
    use std::path::PathBuf;

    fn trait_for(id: &str, types: Vec<FileType>, from_groups: bool) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#if: Condition::Text(TextQuery {
                substr: Some("MARKER".to_string()),
                ..Default::default()
            }),
            r#for: types,
            for_from_groups: from_groups,
            platforms: vec![Platform::Unix],
            arch: vec![Arch::All],
            defined_in: PathBuf::from("test.yml"),
            ..Default::default()
        }
    }

    #[test]
    fn flags_an_atomic_that_straddles_the_archive_boundary() {
        // `for: [tar, shell]` reads as "either", but an atomic runs on one node.
        // cleave expands the tar and scans `src/a.txt` as its own `text` node --
        // the container's bytes are never content-scanned, even though the
        // marker is present in them verbatim. Only the `shell` half can fire.
        let traits = vec![trait_for(
            "test/mix::tar-and-shell",
            vec![FileType::Tar, FileType::Shell],
            false,
        )];

        let found = find_mixed_archive_filetype_traits(&traits);
        assert_eq!(found.len(), 1, "expected the mixed trait to be flagged");
        assert_eq!(found[0].0, "test/mix::tar-and-shell");
        assert_eq!(found[0].1, vec![FileType::Tar]);
        assert_eq!(found[0].2, vec![FileType::Shell]);
    }

    #[test]
    fn allows_archive_only_and_plain_only_atomics() {
        let traits = vec![
            trait_for(
                "test/mix::archive-only",
                vec![FileType::Tar, FileType::Zip],
                false,
            ),
            trait_for(
                "test/mix::plain-only",
                vec![FileType::Shell, FileType::Python],
                false,
            ),
        ];
        assert!(find_mixed_archive_filetype_traits(&traits).is_empty());
    }

    #[test]
    fn allows_for_all_and_group_derived_lists() {
        // `for: [all]` is the sanctioned "any node". A named group may itself
        // expand to a mix -- `data` covers `ipa` beside `json`/`text` -- and the
        // author wrote one group name, so group-derived lists are exempt.
        let traits = vec![
            trait_for("test/mix::all", vec![FileType::All, FileType::Shell], false),
            trait_for(
                "test/mix::from-group",
                vec![FileType::Ipa, FileType::Json],
                true,
            ),
        ];
        assert!(find_mixed_archive_filetype_traits(&traits).is_empty());
    }

    fn path_trait(id: &str, types: Vec<FileType>) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#if: Condition::Path(crate::composite_rules::condition::PathQuery {
                basename: true,
                regex: Some("^installer\\.exe$".to_string()),
                ..Default::default()
            }),
            r#for: types,
            platforms: vec![Platform::Unix],
            arch: vec![Arch::All],
            defined_in: PathBuf::from("test.yml"),
            ..Default::default()
        }
    }

    /// `type: path`/`basename` reads the node's own path, which every node
    /// has -- archive or not -- so mixing archive and plain types is not the
    /// one-node-one-matcher conflation this validator exists to catch.
    /// `izpack-package-path` (`for: [jar, pe, shell, javascript, java]`) is
    /// the real shape: one basename check, whichever node it lands on.
    #[test]
    fn path_matchers_are_exempt_from_the_archive_boundary_check() {
        let traits = vec![path_trait(
            "test/mix::path-mix",
            vec![FileType::Jar, FileType::Pe, FileType::Shell],
        )];
        assert!(find_mixed_archive_filetype_traits(&traits).is_empty());
    }

    fn metrics_trait(id: &str, types: Vec<FileType>) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "test".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#if: Condition::Metrics(crate::composite_rules::condition::MetricsQuery {
                field: "file.entropy".to_string(),
                min: Some(7.9),
                ..Default::default()
            }),
            r#for: types,
            platforms: vec![Platform::Unix],
            arch: vec![Arch::All],
            defined_in: PathBuf::from("test.yml"),
            ..Default::default()
        }
    }

    /// `type: metrics` is measurement, not a content scan: `file.entropy` is
    /// computed for whichever node is analysed, container and member alike,
    /// so an archive type beside a leaf type is not the "only one half can
    /// fire" conflation. `near-maximum-entropy-file` is the live shape.
    #[test]
    fn metrics_matchers_are_exempt_from_the_archive_boundary_check() {
        let traits = vec![metrics_trait(
            "test/mix::entropy-mix",
            vec![FileType::Zip, FileType::Tar, FileType::Data],
        )];
        assert!(find_mixed_archive_filetype_traits(&traits).is_empty());
    }

    /// But `type: value` stays reported: a container-scoped fact such as
    /// `archive.members[*].path` exists only on a node the archive analyser
    /// cracked, so a leaf type listed beside an archive type really is dead.
    #[test]
    fn value_matchers_are_still_flagged() {
        let mut t = trait_for(
            "test/mix::member-path-mix",
            vec![FileType::Zip, FileType::JavaScript],
            false,
        );
        t.r#if = Condition::Kv(crate::composite_rules::condition::KvQuery {
            path: "archive.members[*].path".to_string(),
            substr: Some("node_modules/".to_string()),
            ..Default::default()
        });
        assert_eq!(find_mixed_archive_filetype_traits(&[t]).len(), 1);
    }

    #[test]
    fn static_lib_is_not_an_archive_so_it_may_pair_with_source() {
        // `ar` is the one container cleave does not expand: a `type: text`
        // trait declared `for: [static-lib]` does match the archive's own
        // bytes, so pairing it with a source type is legitimate.
        let traits = vec![trait_for(
            "test/mix::ar-and-c",
            vec![FileType::StaticLib, FileType::C],
            false,
        )];
        assert!(find_mixed_archive_filetype_traits(&traits).is_empty());
    }
}

#[cfg(test)]
mod dead_composite_tests {
    use crate::capabilities::validation::find_dead_composites;
    use crate::composite_rules::{
        Arch, CompositeTrait, Condition, FileType, Platform, Scope, TextQuery, TraitDefinition,
    };
    use std::path::PathBuf;

    fn leg(id: &str, types: Vec<FileType>) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "leg".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#if: Condition::Text(TextQuery {
                substr: Some("X".to_string()),
                ..Default::default()
            }),
            r#for: types,
            platforms: vec![Platform::Unix],
            arch: vec![Arch::All],
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    fn comp(id: &str, types: Vec<FileType>, legs: Vec<&str>) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "comp".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#for: types,
            platforms: vec![Platform::Unix],
            arch: vec![Arch::All],
            all: Some(
                legs.into_iter()
                    .map(|l| Condition::Trait { id: l.to_string() })
                    .collect(),
            ),
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    #[test]
    fn a_composite_whose_every_declared_type_is_unreachable_is_dead() {
        // The `lua-http-post-request` shape: two Lua legs, but the composite
        // inherited a file default that never mentions Lua, so it could not
        // fire anywhere.
        let traits = vec![
            leg("t::lua-a", vec![FileType::Lua]),
            leg("t::lua-b", vec![FileType::Lua]),
        ];
        let comps = vec![comp(
            "t::lua-rule",
            vec![FileType::Python, FileType::Shell],
            vec!["t::lua-a", "t::lua-b"],
        )];
        assert_eq!(find_dead_composites(&traits, &comps), vec!["t::lua-rule"]);
    }

    #[test]
    fn a_composite_with_one_reachable_type_is_not_dead() {
        let traits = vec![leg("t::lua-a", vec![FileType::Lua])];
        let comps = vec![comp(
            "t::mixed",
            vec![FileType::Python, FileType::Lua],
            vec!["t::lua-a"],
        )];
        assert!(find_dead_composites(&traits, &comps).is_empty());
    }

    #[test]
    fn a_container_type_keeps_a_pooling_composite_alive() {
        // On an archive the legs arrive as inherited member findings, so a
        // declared container type is always reachable and the rule is not dead.
        let traits = vec![leg("t::js", vec![FileType::JavaScript])];
        let comps = vec![comp("t::pkg", vec![FileType::Npm], vec!["t::js"])];
        assert!(find_dead_composites(&traits, &comps).is_empty());
    }

    #[test]
    fn a_pooling_scope_keeps_a_non_archive_container_alive() {
        // A self-extracting PE (PyInstaller onefile) pools its extracted
        // members' findings under `scope: outer`/`archive`/`package` the same
        // way an archive-tagged container does, even though `Pe` itself
        // carries no `#[archive]` marker. `pyinstaller-pyarmor-xor-sidecar-
        // stage` (for: [pe], scope: outer) requiring a Python-only leg is the
        // real-world shape this covers.
        let traits = vec![leg("t::py", vec![FileType::Python])];
        let mut rule = comp("t::pyinstaller", vec![FileType::Pe], vec!["t::py"]);
        rule.scope = Some(Scope::Outer);
        assert!(find_dead_composites(&traits, &[rule]).is_empty());
    }
}

#[cfg(test)]
mod unbindable_package_scope_tests {
    use crate::capabilities::validation::find_scope_without_valid_container;
    use crate::composite_rules::condition::TextQuery;
    use crate::composite_rules::{
        Arch, CompositeTrait, Condition, FileType, Platform, Scope, TraitDefinition,
    };
    use std::path::PathBuf;

    fn leg(id: &str, types: Vec<FileType>) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "leg".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#if: Condition::Text(TextQuery {
                substr: Some("X".to_string()),
                ..Default::default()
            }),
            r#for: types,
            platforms: vec![Platform::Unix],
            arch: vec![Arch::All],
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    fn comp(id: &str, types: Vec<FileType>, legs: Vec<&str>) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "comp".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#for: types,
            scope: Some(Scope::Package),
            platforms: vec![Platform::Unix],
            arch: vec![Arch::All],
            all: Some(
                legs.into_iter()
                    .map(|l| Condition::Trait { id: l.to_string() })
                    .collect(),
            ),
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    /// Shape 1: `for: [registry]` names the one node type no package archive
    /// can contain. This is the live `fresh-package-outbound-exfil-channel`
    /// family in the trait tree -- ten rules under
    /// `objectives/supply-chain/...` that all want `scope: outer`.
    #[test]
    fn registry_only_for_is_flagged() {
        let traits = vec![leg("t::reg", vec![FileType::Registry])];
        let rule = comp("t::bad", vec![FileType::Registry], vec!["t::reg"]);
        let bad = find_scope_without_valid_container(&traits, &[rule]);
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].id, "t::bad");
        assert!(
            bad[0].reason.contains("registry nodes"),
            "unexpected reason: {}",
            bad[0].reason
        );
    }

    /// Shape 2: `for:` is fine, but the required legs straddle the boundary --
    /// a registry-only leg can never share a package key with a leg that only
    /// ever fires on a real file. This is `removed-inflated-node-hook`
    /// (`for:` defaulted to `all`, so shape 1 misses it).
    #[test]
    fn registry_leg_mixed_with_a_file_leg_is_flagged() {
        let traits = vec![
            leg("t::reg", vec![FileType::Registry]),
            leg("t::manifest", vec![FileType::PackageJson]),
        ];
        let rule = comp("t::bad", vec![FileType::All], vec!["t::reg", "t::manifest"]);
        let bad = find_scope_without_valid_container(&traits, &[rule]);
        assert_eq!(bad.len(), 1);
        assert!(
            bad[0].reason.contains("t::reg") && bad[0].reason.contains("t::manifest"),
            "reason should name both legs, got: {}",
            bad[0].reason
        );
    }

    /// A registry-only leg resolved through a *composite* counts the same --
    /// `removed-inflated-node-hook`'s registry leg is itself a composite.
    #[test]
    fn a_registry_only_composite_leg_counts() {
        let traits = vec![leg("t::manifest", vec![FileType::PackageJson])];
        let mut registry_comp = comp("t::reg-comp", vec![FileType::Registry], vec!["t::none"]);
        registry_comp.scope = None;
        let rule = comp(
            "t::bad",
            vec![FileType::All],
            vec!["t::reg-comp", "t::manifest"],
        );
        let bad = find_scope_without_valid_container(&traits, &[registry_comp, rule]);
        assert_eq!(bad.len(), 1);
        assert_eq!(bad[0].id, "t::bad");
    }

    /// A bare same-directory leg name resolves against the rule's own
    /// directory, the way the loader resolves it -- otherwise shape 2 is blind
    /// to the most common way legs are written.
    #[test]
    fn bare_same_directory_leg_names_resolve() {
        let traits = vec![
            leg("t::reg", vec![FileType::Registry]),
            leg("t::manifest", vec![FileType::PackageJson]),
        ];
        let rule = comp("t::bad", vec![FileType::All], vec!["reg", "manifest"]);
        assert_eq!(
            find_scope_without_valid_container(&traits, &[rule]).len(),
            1
        );
    }

    /// All legs on the registry side pool fine: every key is the empty string,
    /// so the rule still fires. Pointless, but not broken -- and a validator
    /// that cannot distinguish the two is the one that gets disabled.
    #[test]
    fn an_all_registry_composite_is_not_flagged() {
        let traits = vec![
            leg("t::reg-a", vec![FileType::Registry]),
            leg("t::reg-b", vec![FileType::Registry]),
        ];
        let rule = comp("t::ok", vec![FileType::All], vec!["t::reg-a", "t::reg-b"]);
        assert!(find_scope_without_valid_container(&traits, &[rule]).is_empty());
    }

    /// The canonical, correct use: a leaf file inside an npm tarball pooling
    /// with its manifest. Flagging this was the false positive that got the
    /// previous, broader version of this validator pulled.
    #[test]
    fn a_leaf_type_inside_a_package_is_never_flagged() {
        let traits = vec![
            leg("t::js", vec![FileType::JavaScript]),
            leg("t::manifest", vec![FileType::PackageJson]),
        ];
        let rule = comp(
            "t::ok",
            vec![FileType::JavaScript, FileType::TypeScript],
            vec!["t::js", "t::manifest"],
        );
        assert!(find_scope_without_valid_container(&traits, &[rule]).is_empty());
    }

    /// A plain container type degrades to `scope: file` when nothing packages
    /// it, which is harmless -- and a `.zip` nested in an npm tarball binds
    /// for real. Not our business either way.
    #[test]
    fn a_non_package_archive_type_is_not_flagged() {
        let traits = vec![leg("t::js", vec![FileType::JavaScript])];
        let rule = comp("t::ok", vec![FileType::Zip], vec!["t::js"]);
        assert!(find_scope_without_valid_container(&traits, &[rule]).is_empty());
    }

    /// An unresolvable leg, a directory reference, and a leg that runs on both
    /// registry and file nodes all prove nothing. This check fires on
    /// certainty only.
    #[test]
    fn unprovable_legs_are_left_alone() {
        let traits = vec![
            leg("t::reg", vec![FileType::Registry]),
            leg("t::both", vec![FileType::Registry, FileType::PackageJson]),
        ];

        let dangling = comp("t::a", vec![FileType::All], vec!["t::reg", "t::nowhere"]);
        assert!(find_scope_without_valid_container(&traits, &[dangling]).is_empty());

        let dir_ref = comp(
            "t::b",
            vec![FileType::All],
            vec!["t::reg", "metadata/package/"],
        );
        assert!(find_scope_without_valid_container(&traits, &[dir_ref]).is_empty());

        let ambiguous = comp("t::c", vec![FileType::All], vec!["t::reg", "t::both"]);
        assert!(find_scope_without_valid_container(&traits, &[ambiguous]).is_empty());
    }

    /// Only an explicit `scope: package` is checked. The `for:`-derived
    /// default is the engine's own choice (`CompositeTrait::default_scope`)
    /// and cannot be wrong in this way, and every other scope is out of
    /// bounds -- `outer` is the fix this validator recommends.
    #[test]
    fn other_scopes_and_the_default_are_exempt() {
        let traits = vec![
            leg("t::reg", vec![FileType::Registry]),
            leg("t::manifest", vec![FileType::PackageJson]),
        ];
        for scope in [
            None,
            Some(Scope::Outer),
            Some(Scope::Archive),
            Some(Scope::File),
        ] {
            let mut rule = comp(
                "t::ok",
                vec![FileType::Registry],
                vec!["t::reg", "t::manifest"],
            );
            rule.scope = scope;
            assert!(
                find_scope_without_valid_container(&traits, &[rule]).is_empty(),
                "scope {scope:?} must not be flagged"
            );
        }
    }

    /// A composite with no `all:` legs cannot be proven broken by shape 2, and
    /// a non-registry `for:` keeps shape 1 quiet.
    #[test]
    fn a_composite_without_required_legs_is_exempt() {
        let traits = vec![leg("t::reg", vec![FileType::Registry])];
        let mut rule = comp("t::ok", vec![FileType::Npm], vec![]);
        rule.all = None;
        rule.any = Some(vec![Condition::Trait {
            id: "t::reg".to_string(),
        }]);
        assert!(find_scope_without_valid_container(&traits, &[rule]).is_empty());
    }

    /// The validator is registered, so `--disable-validator` can name it and
    /// its findings carry a real label instead of the `unknown` fallback.
    #[test]
    fn the_validator_id_is_registered() {
        assert!(
            crate::validation_controls::validator_spec("unbindable-package-scope").is_some(),
            "unbindable-package-scope must be in VALIDATOR_SPECS"
        );
        assert!(
            crate::validation_controls::validator_spec("exhaustive-suppressor").is_some(),
            "exhaustive-suppressor must be in VALIDATOR_SPECS"
        );
        assert!(
            crate::validation_controls::validator_spec("leg-suppression").is_some(),
            "leg-suppression must be in VALIDATOR_SPECS"
        );
    }
}

#[cfg(test)]
mod pooling_scope_container_tests {
    use crate::capabilities::validation::find_pooling_scope_without_container;
    use crate::composite_rules::{Arch, CompositeTrait, Condition, FileType, Platform, Scope};
    use std::path::PathBuf;

    fn comp(id: &str, types: Vec<FileType>, scope: Option<Scope>) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "comp".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#for: types,
            scope,
            platforms: vec![Platform::Unix],
            arch: vec![Arch::All],
            all: Some(vec![Condition::Trait {
                id: "t::leg".to_string(),
            }]),
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    /// MSI, OLE compound documents and OOXML hold more than one stream and
    /// cleave pools their members' findings (the office analyser calls
    /// `evaluate_container_composites` exactly as the archive analyser does).
    /// They carry no `#[archive]` marker only because the *archive* analyser
    /// is not what opens them. Without this, `find_impossible_composite_filetypes`
    /// and this check deadlock: the first tells an MSI rule to declare its
    /// container and take a pooling scope, and this one then rejects it.
    #[test]
    fn office_and_installer_containers_satisfy_the_pooling_requirement() {
        for ft in [FileType::Msi, FileType::OleDoc, FileType::Ooxml] {
            for scope in [Scope::Archive, Scope::Package, Scope::Outer] {
                let rule = comp("t::office", vec![ft], Some(scope));
                assert!(
                    find_pooling_scope_without_container(&[rule]).is_empty(),
                    "{ft:?} at {scope:?} is a container and must be accepted"
                );
            }
        }
    }

    /// The dead shape: pooling scopes are evaluated on the container node, so a
    /// leaf-only `for:` means the rule is never handed a node it declared.
    #[test]
    fn a_leaf_only_for_with_a_pooling_scope_is_flagged() {
        for scope in [Scope::Archive, Scope::Package, Scope::Outer] {
            let rule = comp("t::bad", vec![FileType::JavaScript], Some(scope));
            let bad = find_pooling_scope_without_container(&[rule]);
            assert_eq!(bad.len(), 1, "scope {scope:?} should be flagged");
            assert_eq!(bad[0].0, "t::bad");
        }
    }

    /// Naming the container is the fix -- and the member types may stay in the
    /// list, since `for:` also says what evidence may be mixed in.
    #[test]
    fn naming_a_container_clears_it() {
        let rule = comp(
            "t::ok",
            vec![FileType::Npm, FileType::JavaScript],
            Some(Scope::Package),
        );
        assert!(find_pooling_scope_without_container(&[rule]).is_empty());
    }

    /// `registry` is the container for `scope: outer` -- the synthetic
    /// artifact↔registry node is typed `registry` -- but it is not an archive,
    /// so it does not license `archive`/`package`.
    #[test]
    fn registry_is_a_container_only_for_outer() {
        let ok = comp(
            "t::ok",
            vec![FileType::Registry, FileType::JavaScript],
            Some(Scope::Outer),
        );
        assert!(find_pooling_scope_without_container(&[ok]).is_empty());

        for scope in [Scope::Archive, Scope::Package] {
            let bad = comp("t::bad", vec![FileType::Registry], Some(scope));
            assert_eq!(
                find_pooling_scope_without_container(&[bad]).len(),
                1,
                "registry is not an archive ancestor, so scope {scope:?} cannot bind"
            );
        }
    }

    /// The default scope counts: `for: [npm]` with no `scope:` resolves to
    /// `package`, and `for: [javascript]` to `file`. Neither is a violation,
    /// but the check must read `effective_scope`, not the raw field.
    #[test]
    fn the_default_scope_is_evaluated_not_the_raw_field() {
        assert!(
            find_pooling_scope_without_container(&[comp("t::ok-npm", vec![FileType::Npm], None)])
                .is_empty()
        );
        assert!(
            find_pooling_scope_without_container(&[comp(
                "t::ok-js",
                vec![FileType::JavaScript],
                None
            )])
            .is_empty()
        );
        // ...and a registry default (outer) is satisfied by registry itself.
        assert!(
            find_pooling_scope_without_container(&[comp(
                "t::ok-reg",
                vec![FileType::Registry],
                None
            )])
            .is_empty()
        );
    }

    /// File-scoped composites run per node and are none of this check's
    /// business, whatever they declare.
    #[test]
    fn file_and_leaf_scopes_are_exempt() {
        for scope in [Scope::File, Scope::Leaf] {
            let rule = comp("t::ok", vec![FileType::JavaScript], Some(scope));
            assert!(find_pooling_scope_without_container(&[rule]).is_empty());
        }
    }

    /// `for: [all]` runs everywhere by definition, and a group-derived list is
    /// not what the author wrote -- neither is evidence of a mistake.
    #[test]
    fn all_and_group_derived_lists_are_exempt() {
        let rule = comp("t::ok", vec![FileType::All], Some(Scope::Archive));
        assert!(find_pooling_scope_without_container(&[rule]).is_empty());

        let mut grouped = comp("t::ok2", vec![FileType::JavaScript], Some(Scope::Archive));
        grouped.for_from_groups = true;
        assert!(find_pooling_scope_without_container(&[grouped]).is_empty());
    }

    #[test]
    fn the_validator_id_is_registered() {
        assert!(
            crate::validation_controls::validator_spec("pooling-scope-no-container").is_some(),
            "pooling-scope-no-container must be in VALIDATOR_SPECS"
        );
    }

    /// `Pe` is the established non-archive exception -- same precedent as
    /// `find_dead_composites`'s `a_pooling_scope_keeps_a_non_archive_container_alive`.
    /// A self-extracting PE (PyInstaller onefile) pools its children the same
    /// way an archive does without carrying the `#[archive]` marker; the live
    /// shape is `known-nondeployed-filename-context` (`for: [pe]`,
    /// `scope: outer`), joining a PE's own version-resource fact with an
    /// identity marker that may live in an embedded MSI/CAB member.
    #[test]
    fn pe_is_an_accepted_non_archive_pooling_container() {
        for scope in [Scope::Outer, Scope::Archive, Scope::Package] {
            let rule = comp("t::pe-pool", vec![FileType::Pe], Some(scope));
            assert!(
                find_pooling_scope_without_container(&[rule]).is_empty(),
                "scope {scope:?} with for: [pe] must not be flagged"
            );
        }
    }
}

#[cfg(test)]
mod legs_outside_for_tests {
    use crate::capabilities::validation::find_legs_outside_for;
    use crate::composite_rules::condition::TextQuery;
    use crate::composite_rules::{
        Arch, CompositeTrait, Condition, FileType, Platform, Scope, TraitDefinition,
    };
    use std::path::PathBuf;

    fn leg(id: &str, types: Vec<FileType>) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "leg".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#if: Condition::Text(TextQuery {
                substr: Some("X".to_string()),
                ..Default::default()
            }),
            r#for: types,
            platforms: vec![Platform::Unix],
            arch: vec![Arch::All],
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    fn comp(
        id: &str,
        types: Vec<FileType>,
        scope: Option<Scope>,
        legs: Vec<&str>,
    ) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "comp".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#for: types,
            scope,
            platforms: vec![Platform::Unix],
            arch: vec![Arch::All],
            all: Some(
                legs.into_iter()
                    .map(|l| Condition::Trait { id: l.to_string() })
                    .collect(),
            ),
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    fn path_leg(id: &str, types: Vec<FileType>) -> TraitDefinition {
        TraitDefinition {
            r#if: Condition::Path(crate::composite_rules::condition::PathQuery {
                basename: true,
                exact: Some("package.json".to_string()),
                ..Default::default()
            }),
            ..leg(id, types)
        }
    }

    /// A `type: path` leg is not subject to the origin filter at all:
    /// `evaluate_basename_traits_for_entries` runs every path trait against
    /// the archive's entry list with no `for:` gate, and the finding is
    /// stamped with the *container's* type. So a rule naming only its
    /// container really can satisfy it, and flagging it is a false positive.
    /// `runtime-shipped-without-publish-manifest` is the live shape: its
    /// `unless: npm-publish-root-manifest` (`for: [package.json]`,
    /// `type: path`) does fire on the npm node.
    #[test]
    fn a_path_leg_is_not_subject_to_the_origin_filter() {
        let legs = vec![path_leg("t::manifest", vec![FileType::PackageJson])];
        let rule = comp(
            "t::npm-rule",
            vec![FileType::Npm],
            Some(Scope::Archive),
            vec!["t::manifest"],
        );
        assert!(find_legs_outside_for(&legs, &[rule]).is_empty());
    }

    /// ...but a content leg in the same position stays reported, because that
    /// one really is filtered by origin.
    #[test]
    fn a_content_leg_in_the_same_position_is_still_reported() {
        let legs = vec![leg("t::script", vec![FileType::JavaScript])];
        let rule = comp(
            "t::npm-rule",
            vec![FileType::Npm],
            Some(Scope::Archive),
            vec!["t::script"],
        );
        assert_eq!(find_legs_outside_for(&legs, &[rule]).len(), 1);
    }

    /// The `vscode-activated-curl-shell` shape: a rule naming only its
    /// container, whose legs live in members. Before the origin filter this
    /// rule was satisfied by any member at all; now it is dead, and the fix is
    /// to say which members it is about.
    #[test]
    fn a_container_only_for_with_member_legs_is_flagged() {
        let traits = vec![
            leg("t::manifest", vec![FileType::Json]),
            leg("t::script", vec![FileType::JavaScript]),
        ];
        let rule = comp(
            "t::vsix-rule",
            vec![FileType::VsixArchive],
            Some(Scope::Archive),
            vec!["t::manifest", "t::script"],
        );
        let bad = find_legs_outside_for(&traits, &[rule]);
        assert_eq!(bad.len(), 2, "both member legs are outside for:");
        // The message has to name the types to add, or the author is left
        // guessing which of 127 file types the leg wanted.
        assert_eq!(bad[0].leg_types, vec![FileType::Json]);
        assert_eq!(bad[1].leg_types, vec![FileType::JavaScript]);
    }

    /// Declaring the member types is the fix.
    #[test]
    fn declaring_the_member_types_clears_it() {
        let traits = vec![
            leg("t::manifest", vec![FileType::Json]),
            leg("t::script", vec![FileType::JavaScript]),
        ];
        let rule = comp(
            "t::vsix-rule",
            vec![FileType::VsixArchive, FileType::Json, FileType::JavaScript],
            Some(Scope::Archive),
            vec!["t::manifest", "t::script"],
        );
        assert!(find_legs_outside_for(&traits, &[rule]).is_empty());
    }

    /// A leg only needs *one* of its types declared: a trait that fires on
    /// javascript or typescript is satisfiable by a rule that names only
    /// javascript, and `for:` is allowed to be stricter than its children.
    #[test]
    fn one_overlapping_type_is_enough() {
        let traits = vec![leg(
            "t::script",
            vec![FileType::JavaScript, FileType::TypeScript],
        )];
        let rule = comp(
            "t::rule",
            vec![FileType::Npm, FileType::JavaScript],
            Some(Scope::Package),
            vec!["t::script"],
        );
        assert!(find_legs_outside_for(&traits, &[rule]).is_empty());
    }

    /// File-scoped composites match within one node; they are
    /// `find_impossible_composite_filetypes`'s business, not this check's.
    #[test]
    fn file_scoped_composites_are_not_this_checks_business() {
        let traits = vec![leg("t::script", vec![FileType::JavaScript])];
        let rule = comp(
            "t::rule",
            vec![FileType::PackageJson],
            Some(Scope::File),
            vec!["t::script"],
        );
        assert!(find_legs_outside_for(&traits, &[rule]).is_empty());
    }

    /// `for: [all]` opts out of the origin filter, so it cannot exclude
    /// anything; a leg declared `for: [all]` fires anywhere, so it is never
    /// excluded. Neither is a mistake.
    #[test]
    fn all_on_either_side_is_exempt() {
        let traits = vec![leg("t::anywhere", vec![FileType::All])];
        let rule = comp(
            "t::rule",
            vec![FileType::Npm],
            Some(Scope::Package),
            vec!["t::anywhere"],
        );
        assert!(find_legs_outside_for(&traits, &[rule]).is_empty());

        let traits2 = vec![leg("t::script", vec![FileType::JavaScript])];
        let rule2 = comp(
            "t::rule2",
            vec![FileType::All],
            Some(Scope::Package),
            vec!["t::script"],
        );
        assert!(find_legs_outside_for(&traits2, &[rule2]).is_empty());
    }

    /// A directory reference resolves to every definition under it, so the
    /// union of their types is what must overlap -- one member is enough.
    #[test]
    fn a_directory_reference_unions_its_members_types() {
        let traits = vec![
            leg("objectives/exfil/http::a", vec![FileType::Python]),
            leg("objectives/exfil/http::b", vec![FileType::JavaScript]),
        ];
        let ok = comp(
            "t::ok",
            vec![FileType::Npm, FileType::JavaScript],
            Some(Scope::Package),
            vec!["objectives/exfil/http/"],
        );
        assert!(find_legs_outside_for(&traits, &[ok]).is_empty());

        let bad = comp(
            "t::bad",
            vec![FileType::Npm, FileType::Elf],
            Some(Scope::Package),
            vec!["objectives/exfil/http/"],
        );
        assert_eq!(find_legs_outside_for(&traits, &[bad]).len(), 1);
    }

    /// An unresolvable leg proves nothing -- dangling references are a
    /// different validator's error, and reporting them here would send the
    /// author to the wrong fix.
    #[test]
    fn an_unresolvable_leg_is_ignored() {
        let traits = vec![leg("t::script", vec![FileType::JavaScript])];
        let rule = comp(
            "t::rule",
            vec![FileType::Npm, FileType::JavaScript],
            Some(Scope::Package),
            vec!["t::script", "t::nowhere"],
        );
        assert!(find_legs_outside_for(&traits, &[rule]).is_empty());
    }

    /// The default scope counts: `for: [npm]` with no `scope:` is
    /// package-scoped, so its legs are filtered and this check applies.
    #[test]
    fn the_default_scope_brings_a_rule_into_scope() {
        let traits = vec![leg("t::script", vec![FileType::JavaScript])];
        let rule = comp("t::rule", vec![FileType::Npm], None, vec!["t::script"]);
        assert_eq!(
            find_legs_outside_for(&traits, &[rule]).len(),
            1,
            "for: [npm] defaults to package scope, so the filter applies"
        );
    }

    #[test]
    fn the_validator_id_is_registered() {
        assert!(
            crate::validation_controls::validator_spec("leg-outside-for").is_some(),
            "leg-outside-for must be in VALIDATOR_SPECS"
        );
    }
}

#[cfg(test)]
mod leg_role_tests {
    use crate::capabilities::validation::{
        LegRole, find_dead_any_alternatives, find_legs_outside_for,
    };
    use crate::composite_rules::condition::TextQuery;
    use crate::composite_rules::{
        Arch, CompositeTrait, Condition, FileType, Platform, Scope, TraitDefinition,
    };
    use std::path::PathBuf;

    fn leg(id: &str, types: Vec<FileType>) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "leg".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#if: Condition::Text(TextQuery {
                substr: Some("X".to_string()),
                ..Default::default()
            }),
            r#for: types,
            platforms: vec![Platform::Unix],
            arch: vec![Arch::All],
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    fn refs(ids: &[&str]) -> Vec<Condition> {
        ids.iter()
            .map(|i| Condition::Trait { id: i.to_string() })
            .collect()
    }

    fn comp(types: Vec<FileType>) -> CompositeTrait {
        CompositeTrait {
            id: "t::rule".to_string(),
            desc: "comp".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#for: types,
            scope: Some(Scope::Package),
            platforms: vec![Platform::Unix],
            arch: vec![Arch::All],
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    /// An `unless:` leg outside `for:` does NOT kill the rule -- it kills the
    /// carve-out, so the rule keeps firing where the author excluded it. That
    /// costs false positives rather than detections, which is the opposite
    /// urgency from a dead `all:` leg, so it is reported with its own role.
    ///
    /// Found by review of the live tree: `readme-clone-foreign-npm-links`
    /// suppresses on `archive-cargo-toml-entry` (`for: [tar, crate]`) while the
    /// rule itself was narrowed to `[npm]`.
    #[test]
    fn a_suppressor_leg_outside_for_is_reported_as_a_false_positive_risk() {
        let traits = vec![
            leg("t::manifest", vec![FileType::PackageJson]),
            leg("t::cargo", vec![FileType::Tar, FileType::Crate]),
        ];
        let mut rule = comp(vec![FileType::Npm, FileType::PackageJson]);
        rule.all = Some(refs(&["t::manifest"]));
        rule.unless = Some(refs(&["t::cargo"]));

        let found = find_legs_outside_for(&traits, &[rule]);
        assert_eq!(found.len(), 1, "the suppressor leg must be reported");
        assert_eq!(found[0].role, LegRole::Suppressor);
        assert_eq!(found[0].leg, "t::cargo");
    }

    /// A directory leg stands for the union of the definitions under it --
    /// subdirectories included, a sibling that shares its name as a prefix
    /// not -- so it is outside `for:` only when all of those are. The union
    /// is reported in id order, so the message is the same on every run.
    #[test]
    fn a_directory_leg_is_the_union_of_its_own_definitions() {
        let traits = vec![
            leg("t/dir::a", vec![FileType::Tar]),
            leg("t/dir/sub::b", vec![FileType::Crate]),
            leg("t/dirx::c", vec![FileType::PackageJson]),
        ];
        let mut rule = comp(vec![FileType::PackageJson]);
        rule.all = Some(refs(&["t/dir"]));

        let found = find_legs_outside_for(&traits, &[rule]);
        assert_eq!(found.len(), 1, "the directory leg must be reported");
        assert_eq!(found[0].role, LegRole::Required);
        // `t/dir/sub::b` sorts before `t/dir::a`.
        assert_eq!(found[0].leg_types, [FileType::Crate, FileType::Tar]);
    }

    /// One reachable `any:` branch is enough, so a partially-excluded `any:`
    /// clause is working as written and must stay silent -- otherwise the
    /// validator buries its real findings in noise.
    #[test]
    fn a_partially_reachable_any_clause_is_silent() {
        let traits = vec![
            leg("t::js", vec![FileType::JavaScript]),
            leg("t::elf", vec![FileType::Elf]),
        ];
        let mut rule = comp(vec![FileType::Npm, FileType::JavaScript]);
        rule.any = Some(refs(&["t::js", "t::elf"]));
        assert!(find_legs_outside_for(&traits, &[rule]).is_empty());
    }

    /// The same clause is still worth a warning: its ELF branch is dead code.
    /// A release-zip correlator with `for: [zip, tar, go]` fired on source
    /// tarballs through its Go branch and never on the ELF it was written for.
    #[test]
    fn a_dead_any_alternative_is_warned_per_leg() {
        let traits = vec![
            leg("t::js", vec![FileType::JavaScript]),
            leg("t::elf", vec![FileType::Elf]),
        ];
        let mut rule = comp(vec![FileType::Npm, FileType::JavaScript]);
        rule.any = Some(refs(&["t::js", "t::elf"]));

        let found = find_dead_any_alternatives(&traits, std::slice::from_ref(&rule));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].role, LegRole::DeadAlternative);
        assert_eq!(found[0].leg, "t::elf");

        rule.r#for.push(FileType::Elf);
        assert!(find_dead_any_alternatives(&traits, &[rule]).is_empty());
    }

    /// When every alternative is excluded the clause can never be satisfied,
    /// so the rule is dead and is reported once for the clause, not per leg.
    #[test]
    fn an_entirely_excluded_any_clause_is_reported_once() {
        let traits = vec![
            leg("t::elf", vec![FileType::Elf]),
            leg("t::macho", vec![FileType::Macho]),
        ];
        let mut rule = comp(vec![FileType::Npm, FileType::JavaScript]);
        rule.any = Some(refs(&["t::elf", "t::macho"]));

        let found = find_legs_outside_for(&traits, &[rule]);
        assert_eq!(found.len(), 1, "one finding per dead clause, not per leg");
        assert_eq!(found[0].role, LegRole::EveryAlternative);
    }

    /// An `all:` leg keeps its own role, so the message can say "can never
    /// fire" rather than the suppressor wording.
    #[test]
    fn a_required_leg_keeps_the_required_role() {
        let traits = vec![leg("t::js", vec![FileType::JavaScript])];
        let mut rule = comp(vec![FileType::Npm]);
        rule.all = Some(refs(&["t::js"]));

        let found = find_legs_outside_for(&traits, &[rule]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].role, LegRole::Required);
    }
}

#[cfg(test)]
mod one_fact_conviction_tests {
    use crate::capabilities::validation::find_one_fact_convictions;
    use crate::composite_rules::condition::{KvQuery, PathQuery};
    use crate::composite_rules::{
        Arch, CompositeTrait, Condition, FileType, Platform, TraitDefinition,
    };
    use std::path::PathBuf;

    const MEMBER_PATH: &str = "archive.members[*].path";

    fn leg(id: &str, cond: Condition) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "leg".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#if: cond,
            r#for: vec![FileType::Zip],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    fn member_regex(id: &str, regex: &str) -> TraitDefinition {
        leg(
            id,
            Condition::Kv(KvQuery {
                path: MEMBER_PATH.to_string(),
                regex: Some(regex.to_string()),
                ..Default::default()
            }),
        )
    }

    fn member_exact(id: &str, value: &str) -> TraitDefinition {
        leg(
            id,
            Condition::Kv(KvQuery {
                path: MEMBER_PATH.to_string(),
                exact: Some(value.to_string()),
                ..Default::default()
            }),
        )
    }

    fn hostile(legs: &[&str]) -> CompositeTrait {
        CompositeTrait {
            id: "t::stage".to_string(),
            desc: "stage".to_string(),
            conf: 0.93,
            crit: crate::types::Criticality::Hostile,
            r#for: vec![FileType::Zip],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            all: Some(
                legs.iter()
                    .map(|id| Condition::Trait {
                        id: (*id).to_string(),
                    })
                    .collect(),
            ),
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    /// A hostile composite may not be built from two `archive.members[*].path`
    /// regexes that one member can satisfy. Containment is not the bar and is
    /// not tested for: these two extension sets each carry a spelling the
    /// other lacks, so neither implies the other -- but one `.xlsx` member
    /// answers both legs, and a conviction resting on that member has one
    /// piece of evidence, not two.
    #[test]
    fn two_overlapping_member_path_regexes_cannot_convict() {
        let traits = vec![
            member_regex("t::xlsx-or-xls", r"(?i)\.(xlsx|xls)$"),
            member_regex("t::xlsm-or-xlsx", r"(?i)\.(xlsm|xlsx)$"),
        ];
        let found =
            find_one_fact_convictions(&traits, &[hostile(&["t::xlsx-or-xls", "t::xlsm-or-xlsx"])]);
        assert_eq!(found.len(), 1, "expected one finding, got {found:?}");
        assert_eq!(found[0].0, "t::stage");
        assert_eq!(found[0].1, "t::xlsx-or-xls");
        assert_eq!(found[0].2, "t::xlsm-or-xlsx");
        assert_eq!(found[0].3, MEMBER_PATH, "the shared fact is named");
    }

    /// The same rule with the spellings swapped: an `exact:` member path and a
    /// regex that accepts it. The `exact` leg names one file, the regex leg
    /// names a family containing it, and the archive member that satisfies the
    /// first always satisfies the second -- one observation, two legs.
    #[test]
    fn an_exact_member_path_and_an_overlapping_regex_cannot_convict() {
        let traits = vec![
            member_exact("t::named", "docs/Invoice-90233.xlsx"),
            member_regex("t::any-spreadsheet", r"(?i)\.(xlsx|xlsm|xlsb|xls)$"),
        ];
        let found =
            find_one_fact_convictions(&traits, &[hostile(&["t::named", "t::any-spreadsheet"])]);
        assert_eq!(found.len(), 1, "expected one finding, got {found:?}");
        assert_eq!(found[0].1, "t::named");
        assert_eq!(found[0].2, "t::any-spreadsheet");
    }

    /// The shape the pasted rule had: one leg inside the other's alternation.
    #[test]
    fn a_leg_inside_another_legs_alternation_cannot_convict() {
        let traits = vec![
            member_regex("t::xlsx", r"(?i)\.xlsx$"),
            member_regex("t::spreadsheet", r"(?i)\.(xlsx|xlsm|xlsb|xls)$"),
        ];
        assert_eq!(
            find_one_fact_convictions(&traits, &[hostile(&["t::xlsx", "t::spreadsheet"])]).len(),
            1
        );
    }

    /// Requiring two *different* members is a real layout fingerprint, and no
    /// single path is both a root `setup.exe` and a binary under `Updates/`.
    /// A check that keyed on the shared fact alone would delete this.
    #[test]
    fn legs_no_single_member_can_satisfy_are_silent() {
        let traits = vec![
            member_regex("t::setup", r"(?i)^setup\.exe$"),
            member_regex("t::staged", r"(?i)(^|/)updates?/[^/]+\.(exe|dll)$"),
        ];
        assert!(
            find_one_fact_convictions(&traits, &[hostile(&["t::setup", "t::staged"])]).is_empty()
        );
    }

    /// Two staging directories are still two members, however alike the
    /// patterns look.
    #[test]
    fn disjoint_directory_legs_are_silent() {
        let traits = vec![
            member_regex("t::updates", r"(?i)(^|/)updates/[^/]+\.(exe|dll)$"),
            member_regex("t::library", r"(?i)(^|/)library/[^/]+\.(exe|dll)$"),
        ];
        assert!(
            find_one_fact_convictions(&traits, &[hostile(&["t::updates", "t::library"])])
                .is_empty()
        );
    }

    /// Disjoint extension sets: no value ends in both `.xls` and `.docm`.
    #[test]
    fn disjoint_extension_sets_are_silent() {
        let traits = vec![
            member_regex("t::spreadsheet", r"(?i)\.(xlsx|xls)$"),
            member_regex("t::macro-doc", r"(?i)\.(docm|dotm)$"),
        ];
        assert!(
            find_one_fact_convictions(&traits, &[hostile(&["t::spreadsheet", "t::macro-doc"])])
                .is_empty()
        );
    }

    /// Different facts are different evidence even when the patterns match:
    /// a basename is not an archive member path.
    #[test]
    fn different_facts_are_never_compared() {
        let traits = vec![
            leg(
                "t::basename",
                Condition::Path(PathQuery {
                    regex: Some(r"(?i)\.xlsx$".to_string()),
                    ..Default::default()
                }),
            ),
            member_regex("t::member", r"(?i)\.xlsx$"),
        ];
        assert!(
            find_one_fact_convictions(&traits, &[hostile(&["t::basename", "t::member"])])
                .is_empty()
        );
    }

    /// A count floor on one leg is a claim the other is not making -- "three
    /// spreadsheet members" is not "an xlsx member" -- so the two are not the
    /// same evidence however their matchers overlap.
    #[test]
    fn a_leg_with_its_own_count_floor_is_silent() {
        let mut many = member_regex("t::spreadsheet", r"(?i)\.(xlsx|xlsm|xlsb|xls)$");
        many.count_min = Some(3);
        let traits = vec![member_regex("t::xlsx", r"(?i)\.xlsx$"), many];
        assert!(
            find_one_fact_convictions(&traits, &[hostile(&["t::xlsx", "t::spreadsheet"])])
                .is_empty()
        );
    }

    /// Below `suspicious` two spellings of one fact are untidy rather than
    /// manufactured evidence, and the check stays out of it.
    #[test]
    fn a_notable_rule_is_out_of_scope() {
        let traits = vec![
            member_regex("t::xlsx", r"(?i)\.xlsx$"),
            member_regex("t::spreadsheet", r"(?i)\.(xlsx|xlsm|xlsb|xls)$"),
        ];
        let mut rule = hostile(&["t::xlsx", "t::spreadsheet"]);
        rule.crit = crate::types::Criticality::Notable;
        assert!(find_one_fact_convictions(&traits, &[rule]).is_empty());
    }

    /// `any:` legs are alternatives, so sharing a fact is how they are meant
    /// to be written. Only `all:` claims independent evidence.
    #[test]
    fn an_any_clause_is_out_of_scope() {
        let traits = vec![
            member_regex("t::xlsx", r"(?i)\.xlsx$"),
            member_regex("t::spreadsheet", r"(?i)\.(xlsx|xlsm|xlsb|xls)$"),
        ];
        let mut rule = hostile(&[]);
        rule.all = None;
        rule.any = Some(
            ["t::xlsx", "t::spreadsheet"]
                .iter()
                .map(|id| Condition::Trait {
                    id: (*id).to_string(),
                })
                .collect(),
        );
        assert!(find_one_fact_convictions(&traits, &[rule]).is_empty());
    }

    /// Case folding widens the value set, so a case-insensitive leg and a
    /// case-sensitive one still meet on the spelling they share.
    #[test]
    fn case_folding_does_not_hide_the_shared_value() {
        let traits = vec![
            member_exact("t::named", "payload.xlsx"),
            member_regex("t::any-xlsx", r"\.xlsx$"),
        ];
        assert_eq!(
            find_one_fact_convictions(&traits, &[hostile(&["t::named", "t::any-xlsx"])]).len(),
            1
        );
    }
}

#[cfg(test)]
mod one_fact_evidence_boundary_tests {
    use crate::capabilities::validation::find_one_fact_convictions;
    use crate::composite_rules::condition::KvQuery;
    use crate::composite_rules::{
        Arch, CompositeTrait, Condition, FileType, Platform, TraitDefinition,
    };
    use std::path::PathBuf;

    fn scalar_leg(id: &str, fact: &str, regex: &str) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "leg".to_string(),
            conf: 1.0,
            crit: crate::types::Criticality::Notable,
            r#if: Condition::Kv(KvQuery {
                path: fact.to_string(),
                regex: Some(regex.to_string()),
                ..Default::default()
            }),
            r#for: vec![FileType::PackageJson],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    fn hostile(legs: &[&str]) -> CompositeTrait {
        CompositeTrait {
            id: "t::rule".to_string(),
            desc: "rule".to_string(),
            conf: 0.93,
            crit: crate::types::Criticality::Hostile,
            r#for: vec![FileType::PackageJson],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            all: Some(
                legs.iter()
                    .map(|id| Condition::Trait {
                        id: (*id).to_string(),
                    })
                    .collect(),
            ),
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    /// Two legs over one install script that match *different text* are two
    /// observations, however reliably they co-occur. A rule pairing a URL with
    /// a hex-encode call is doing what it says; only a check asking "does one
    /// value satisfy both" would delete it.
    #[test]
    fn two_matchers_on_one_string_finding_different_text_are_silent() {
        let traits = vec![
            scalar_leg("t::url", "scripts.preinstall", r"https?://"),
            scalar_leg("t::xxd", "scripts.preinstall", r"\bxxd\b"),
        ];
        assert!(find_one_fact_convictions(&traits, &[hostile(&["t::url", "t::xxd"])]).is_empty());
    }

    /// The same fact, two spellings of one match: both legs can match the
    /// literal text `curl `, so the second is restating the first.
    #[test]
    fn two_spellings_of_one_match_on_one_string_are_reported() {
        let traits = vec![
            scalar_leg("t::curl", "scripts.preinstall", r"curl\s"),
            scalar_leg("t::fetcher", "scripts.preinstall", r"(curl|wget)\s"),
        ];
        assert_eq!(
            find_one_fact_convictions(&traits, &[hostile(&["t::curl", "t::fetcher"])]).len(),
            1
        );
    }

    /// Two path properties that a single member can carry but that match
    /// different parts of it -- a directory and an extension -- are still two
    /// facts about that member, not one spelled twice.
    #[test]
    fn a_directory_leg_and_an_extension_leg_are_silent() {
        let traits = vec![
            scalar_leg("t::libdir", "archive.members[*].path", r"(^|/)lib/"),
            scalar_leg("t::dll", "archive.members[*].path", r"(?i)\.dll$"),
        ];
        assert!(
            find_one_fact_convictions(&traits, &[hostile(&["t::libdir", "t::dll"])]).is_empty()
        );
    }
}

#[cfg(test)]
mod reference_index_tests {
    use crate::capabilities::validation::constraints::ReferenceIndex;

    /// The linear scan the index replaced, kept as the definition of the
    /// matching rules it must reproduce exactly.
    fn scan<'a>(reference: &str, ids: &[&'a str]) -> Vec<&'a str> {
        let id = reference.trim_end_matches('/');
        ids.iter()
            .copied()
            .filter(|f| {
                if id.contains("::") {
                    *f == id
                } else if !id.contains('/') {
                    f.ends_with(&format!("::{id}")) || f.ends_with(&format!("/{id}"))
                } else {
                    *f == id
                        || f.starts_with(&format!("{id}::"))
                        || f.starts_with(&format!("{id}/"))
                }
            })
            .collect()
    }

    #[test]
    fn resolve_matches_a_scan_of_every_id() {
        let ids = vec![
            "objectives/c2/irc::mirc-ping",
            "objectives/c2/irc::mirc-join",
            "objectives/c2/irc/client::mirc-ping",
            "objectives/c2/ircd::daemon",
            "micro-behaviors/net/socket::open",
            "micro-behaviors/net/socket/raw::open",
            "legacy/path/open",
            "objectives/c2/irc::mirc-join",
            "well-known/tool::a:b",
            "objectives/c2",
        ];
        let index = ReferenceIndex::new(ids.clone());
        for reference in [
            "objectives/c2/irc::mirc-ping",
            "objectives/c2/irc::mirc-join",
            "objectives/c2/irc::missing",
            "mirc-ping",
            "open",
            "a:b",
            "b",
            "objectives/c2/irc",
            "objectives/c2/irc/",
            "objectives/c2",
            "objectives",
            "micro-behaviors/net/socket",
            "legacy/path",
            "legacy/path/open",
            "",
            "/",
            "missing",
        ] {
            assert_eq!(
                index.resolve(reference),
                scan(reference, &ids),
                "reference {reference:?}"
            );
        }
    }
}

#[cfg(test)]
mod convictions_without_content_tests {
    use crate::capabilities::validation::find_convictions_without_content;
    use crate::composite_rules::condition::{PathQuery, TextQuery};
    use crate::composite_rules::{
        Arch, CompositeTrait, Condition, FileType, Platform, TraitDefinition,
    };
    use crate::types::Criticality;
    use std::path::PathBuf;

    fn atom(id: &str, cond: Condition) -> TraitDefinition {
        TraitDefinition {
            id: id.to_string(),
            desc: "atom".to_string(),
            conf: 1.0,
            crit: Criticality::Notable,
            r#if: cond,
            r#for: vec![FileType::All],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    fn name(id: &str, exact: &str) -> TraitDefinition {
        atom(
            id,
            Condition::Path(PathQuery {
                exact: Some(exact.to_string()),
                basename: true,
                ..Default::default()
            }),
        )
    }

    fn text(id: &str, exact: &str) -> TraitDefinition {
        atom(
            id,
            Condition::Text(TextQuery {
                exact: Some(exact.to_string()),
                ..Default::default()
            }),
        )
    }

    fn rule(id: &str, crit: Criticality, legs: &[&str]) -> CompositeTrait {
        CompositeTrait {
            id: id.to_string(),
            desc: "rule".to_string(),
            conf: 0.9,
            crit,
            r#for: vec![FileType::All],
            platforms: vec![Platform::All],
            arch: vec![Arch::All],
            all: Some(
                legs.iter()
                    .map(|leg| Condition::Trait {
                        id: (*leg).to_string(),
                    })
                    .collect(),
            ),
            defined_in: PathBuf::from("t.yml"),
            ..Default::default()
        }
    }

    /// Each leg is walked once and shared across rules, so every rule that
    /// uses a leg must still see what it reaches, through nested composites,
    /// and one content-reading leg must clear a rule wherever it sits.
    #[test]
    fn shared_legs_are_judged_per_rule() {
        let traits = vec![
            name("t::a", "a.exe"),
            name("t::b", "b.exe"),
            text("t::c", "payload"),
        ];
        let rules = vec![
            rule("t::names", Criticality::Hostile, &["t::a", "t::b"]),
            rule("t::names-again", Criticality::Suspicious, &["t::b", "t::a"]),
            rule("t::content-last", Criticality::Hostile, &["t::a", "t::c"]),
            rule("t::content-first", Criticality::Hostile, &["t::c", "t::a"]),
            rule("t::inner", Criticality::Notable, &["t::a"]),
            rule("t::outer", Criticality::Hostile, &["t::inner", "t::b"]),
        ];
        let found = find_convictions_without_content(&traits, &rules);
        let names = vec!["t::a".to_string(), "t::b".to_string()];
        assert_eq!(
            found,
            vec![
                ("t::names".to_string(), names.clone()),
                ("t::names-again".to_string(), names.clone()),
                ("t::outer".to_string(), names),
            ]
        );
    }

    /// A leg is settled by its first content-reading trait or inline condition
    /// however deep it sits, cycles between composites terminate, and a
    /// reported rule still lists every terminal it rests on -- including
    /// through a directory reference.
    #[test]
    fn legs_settle_at_content_and_reported_rules_list_every_terminal() {
        let traits = vec![
            name("t::a", "a.exe"),
            name("t::b", "b.exe"),
            text("t::c", "payload"),
            name("d/x::n1", "n1.exe"),
            name("d/x::n2", "n2.exe"),
        ];
        let mut inline = rule("t::inline-inner", Criticality::Notable, &["t::a"]);
        if let Some(all) = inline.all.as_mut() {
            all.push(Condition::Text(TextQuery {
                exact: Some("x".to_string()),
                ..Default::default()
            }));
        }
        let rules = vec![
            rule("t::mixed", Criticality::Notable, &["t::a", "t::c"]),
            rule("t::cyc1", Criticality::Notable, &["t::cyc2", "t::a"]),
            rule("t::cyc2", Criticality::Notable, &["t::cyc1", "t::b"]),
            inline,
            rule("t::via-mixed", Criticality::Hostile, &["t::b", "t::mixed"]),
            rule("t::cycle", Criticality::Hostile, &["t::cyc1"]),
            rule("t::dir", Criticality::Hostile, &["d/x"]),
            rule("t::via-inline", Criticality::Hostile, &["t::inline-inner"]),
            rule("t::empty", Criticality::Hostile, &["t::nowhere"]),
        ];
        let found = find_convictions_without_content(&traits, &rules);
        assert_eq!(
            found,
            vec![
                (
                    "t::cycle".to_string(),
                    vec!["t::a".to_string(), "t::b".to_string()]
                ),
                (
                    "t::dir".to_string(),
                    vec!["d/x::n1".to_string(), "d/x::n2".to_string()]
                ),
            ]
        );
    }
}
