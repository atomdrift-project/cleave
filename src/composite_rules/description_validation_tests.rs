//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for description validation in trait definitions

#[cfg(test)]
#[allow(clippy::module_inception)]
mod description_validation_tests {
    use crate::composite_rules::traits::CompositeTrait;
    use crate::composite_rules::{Arch, Condition, TextQuery, TraitDefinition};
    use crate::types::Criticality;

    #[test]
    fn composite_description_length() {
        // Composites get a roomier cap (80) than atomic traits (48): they summarize
        // a combination, so a one-line description that names a few entities is fine.
        let comp = |desc: &str| CompositeTrait {
            id: "test".to_string(),
            desc: desc.to_string(),
            ..Default::default()
        };
        // ~57 chars — a concise triage line naming entities: allowed.
        assert!(
            comp("Benign mass-delete-with-callback (CI, monitoring, guards)")
                .check_description_quality()
                .is_none()
        );
        // Over 80 — a sentence-length blurb: rejected.
        let long = "Recognized-benign packages that trip the hidden-listener heuristic — Glide, gettext, and KeePassXC";
        assert!(long.chars().count() > 80);
        assert!(comp(long).check_description_quality().is_some());
        // Empty: rejected.
        assert!(comp("").check_description_quality().is_some());
    }

    fn create_test_trait_with_desc(desc: &str) -> TraitDefinition {
        TraitDefinition {
            id: "test".to_string(),
            desc: desc.to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            arch: vec![Arch::All],
            r#for: vec![],
            for_from_groups: false,
            r#if: Condition::Text(TextQuery {
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
                platforms: None,
            }),
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
            defined_in: std::path::PathBuf::new(),
            precision: None,
            ..Default::default()
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
            "Package author placeholder text",
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
    fn test_concise_and_bounded_descriptions_valid() {
        let valid_descriptions = vec![
            "PyCryptodome AES import",
            "Redis CLI tool usage",
            "XOR decryption loop",
            "PyCryptodome AES encryption usage",
            "Cryptography library usage in code",
            "Potential data encryption logic",
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
    fn test_long_description() {
        let trait_def = create_test_trait_with_desc(
            "Detects malicious code attempting to bypass security via shell import",
        );
        let warning = trait_def.check_description_quality();
        assert!(warning.is_some());
        assert!(warning.unwrap().contains("too long"));
    }
}
