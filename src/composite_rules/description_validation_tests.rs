//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for description validation in trait definitions

#[cfg(test)]
#[allow(clippy::module_inception)]
mod description_validation_tests {
    use crate::composite_rules::{Condition, ConditionWithFilters, TraitDefinition};
    use crate::types::Criticality;

    fn create_test_trait_with_desc(desc: &str) -> TraitDefinition {
        TraitDefinition {
            id: "test".to_string(),
            desc: desc.to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
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
            },
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
        }
    }

    #[test]
    fn test_concise_descriptions_are_valid() {
        // Concise but clear descriptions should pass
        let valid_descriptions = vec![
            "PyCryptodome AES import",
            "AES.new call",
            "encrypt function",
            "pyaes library import",
        ];

        for desc in valid_descriptions {
            let trait_def = create_test_trait_with_desc(desc);
            let warning = trait_def.check_description_quality();
            assert!(
                warning.is_none(),
                "Concise but clear description '{}' should be valid, got: {:?}",
                desc,
                warning
            );
        }
    }

    #[test]
    fn test_placeholder_words_are_allowed() {
        // Descriptions that mention placeholders, examples, etc. are valid
        // This is needed for traits that detect placeholder text in manifests
        let valid_descriptions = vec![
            "Package author field contains generic placeholder (test, example, admin)",
            "Placeholder bundle ID in plist",
            "TODO comment in source code",
            "Example configuration file",
            "Sample data in test fixtures",
        ];

        for desc in valid_descriptions {
            let trait_def = create_test_trait_with_desc(desc);
            let warning = trait_def.check_description_quality();
            assert!(
                warning.is_none(),
                "Should not warn for legitimate use of placeholder words in desc: '{}', got: {:?}",
                desc,
                warning
            );
        }
    }

    #[test]
    fn test_empty_description() {
        let trait_def = create_test_trait_with_desc("");
        let warning = trait_def.check_description_quality();
        assert!(warning.is_some());
        assert!(warning.unwrap().contains("empty"));
    }

    #[test]
    fn test_very_short_description() {
        let trait_def = create_test_trait_with_desc("test");
        let warning = trait_def.check_description_quality();
        assert!(warning.is_some());
        assert!(warning.unwrap().contains("too short"));
    }

    #[test]
    fn test_both_concise_and_detailed_descriptions_valid() {
        // Both concise and detailed descriptions should be valid
        let valid_descriptions = vec![
            // Concise
            "PyCryptodome AES import",
            "Redis CLI tool usage",
            "XOR decryption loop",
            // Detailed
            "Detects usage of AES encryption from PyCryptodome library",
            "Identifies AES cipher imports which may indicate encryption capabilities",
            "Checks for cryptography library usage in the codebase",
            "Scans for potential data encryption implementation",
        ];

        for desc in valid_descriptions {
            let trait_def = create_test_trait_with_desc(desc);
            let warning = trait_def.check_description_quality();
            assert!(
                warning.is_none(),
                "Did not expect warning for valid desc: '{}', but got: {:?}",
                desc,
                warning
            );
        }
    }

    #[test]
    fn test_descriptive_explanations_are_valid() {
        // Longer descriptions with context should always pass
        let valid_descriptions = vec![
            "Detects malicious code attempting to bypass security via shell import",
            "Identifies encryption library usage that may indicate ransomware",
            "Scans for network communication patterns typical of command and control",
        ];

        for desc in valid_descriptions {
            let trait_def = create_test_trait_with_desc(desc);
            let warning = trait_def.check_description_quality();
            assert!(
                warning.is_none(),
                "Descriptive explanation '{}' should be valid, got: {:?}",
                desc,
                warning
            );
        }
    }
}
