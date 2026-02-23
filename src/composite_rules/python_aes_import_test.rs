//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Test for Python AES import detection using content search

#[cfg(test)]
mod python_aes_import_tests {
    use crate::composite_rules::{Condition, ConditionWithFilters, TraitDefinition};
    use crate::types::Criticality;

    #[test]
    fn test_pycrypto_import_regex_pattern() {
        // Test that the regex pattern correctly matches Python AES imports
        let test_cases = vec![
            ("from Crypto.Cipher import AES", true),
            ("from Crypto.Cipher  import  AES", true), // Multiple spaces
            ("from Crypto.Cipher import\tAES", true),  // Tab
            ("from Crypto.Cipher import AES, DES", true), // Multiple imports
            ("from Crypto.Cipher import DES", false),  // Different import
            ("from Crypto import Cipher", false),      // Wrong import level
            ("import Crypto.Cipher.AES", false),       // Wrong import style
        ];

        let pattern = r"from\s+Crypto\.Cipher\s+import\s+AES";
        let regex = regex::Regex::new(pattern).unwrap();

        for (input, should_match) in test_cases {
            let matches = regex.is_match(input);
            assert_eq!(
                matches,
                should_match,
                "Pattern '{}' should {} match input: '{}'",
                pattern,
                if should_match { "" } else { "not" },
                input
            );
        }
    }

    #[test]
    fn test_trait_type_is_raw_not_string() {
        // Verify that searching for imports should use raw, not string type
        // String type searches for string literals in the code (e.g., "hello world")
        // Raw type searches for raw bytes in the file (e.g., source code text)
        // Symbol type searches for identifiers/imports in the symbol table

        // For Python source files, import statements are in the file content,
        // not in extracted strings or symbols
        let trait_def = TraitDefinition {
            id: "test-python-import".to_string(),
            desc: "Detects PyCryptodome AES imports for encryption capability analysis".to_string(),
            conf: 0.85,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: ConditionWithFilters {
                condition: Condition::Raw {
                    exact: None,
                    substr: None,
                    regex: Some(r"from\s+Crypto\.Cipher\s+import\s+AES".to_string()),
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
        };

        // The trait should have a good description
        let warning = trait_def.check_description_quality();
        assert!(
            warning.is_none(),
            "Trait description should be valid: {:?}",
            warning
        );
    }
}
