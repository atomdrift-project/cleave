//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for `not:` field validation in trait definitions

#[cfg(test)]
mod validation_tests {
    use crate::composite_rules::{
        condition::{NotException, NotExceptionStructured},
        Condition, TraitDefinition,
    };
    use crate::types::Criticality;

    fn create_test_trait(condition: Condition, not: Option<Vec<NotException>>) -> TraitDefinition {
        TraitDefinition {
            id: "test".to_string(),
            desc: "Test trait".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: condition,
            not,
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
            defined_in: std::path::PathBuf::new(),
            precision: None,
        }
    }

    #[test]
    fn test_exact_match_should_use_unless() {
        let cond = Condition::String {
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
        };

        let not = vec![NotException::Shorthand("test".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_some());
        assert!(warning
            .unwrap()
            .contains("consider using 'unless:' instead"));
    }

    #[test]
    fn test_substr_with_valid_not_exception() {
        // substr: "test" should match strings like "testing", "test123", etc.
        // not: ["testing"] should work because "testing" contains "test"
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
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
        };

        let not = vec![NotException::Shorthand("testing".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(
            warning.is_none(),
            "Should not warn for valid substr/not combination"
        );
    }

    #[test]
    fn test_substr_with_invalid_not_exception() {
        // substr: "test" won't match "hurl", so not: ["hurl"] will never apply
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
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
        };

        let not = vec![NotException::Shorthand("hurl".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_some());
        assert!(warning
            .as_ref()
            .unwrap()
            .contains("does not contain the search substr"));
        assert!(warning.as_ref().unwrap().contains("hurl"));
        assert!(warning.as_ref().unwrap().contains("test"));
    }

    #[test]
    fn test_substr_with_exact_not_exception_valid() {
        // substr: "test" should match "testing"
        // not: {exact: "testing"} should work
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
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
        };

        let not = vec![NotException::Structured(NotExceptionStructured {
            exact: Some("testing".to_string()),
            substr: None,
            regex: None,
        })];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_none());
    }

    #[test]
    fn test_substr_with_exact_not_exception_invalid() {
        // substr: "test" won't match strings containing "hurl"
        // not: {exact: "hurl"} will never apply
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
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
        };

        let not = vec![NotException::Structured(NotExceptionStructured {
            exact: Some("hurl".to_string()),
            substr: None,
            regex: None,
        })];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("exact"));
        assert!(warning.as_ref().unwrap().contains("hurl"));
    }

    #[test]
    fn test_substr_with_overlapping_substr_not_exception() {
        // substr: "test" and not: {substr: "testing"}
        // "testing" contains "test", so this should be valid
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
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
        };

        let not = vec![NotException::Structured(NotExceptionStructured {
            exact: None,
            substr: Some("testing".to_string()),
            regex: None,
        })];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_none());
    }

    #[test]
    fn test_substr_with_non_overlapping_substr_not_exception() {
        // substr: "test" and not: {substr: "hurl"}
        // No overlap, so the not will never apply
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
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
        };

        let not = vec![NotException::Structured(NotExceptionStructured {
            exact: None,
            substr: Some("hurl".to_string()),
            regex: None,
        })];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("no overlap"));
    }

    #[test]
    fn test_substr_case_insensitive() {
        // substr: "test" (case insensitive) should match "TESTING"
        // not: ["TESTING"] should work
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
            regex: None,
            word: None,
            case_insensitive: true,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
            compiled_regex: None,
        };

        let not = vec![NotException::Shorthand("TESTING".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_none());
    }

    #[test]
    fn test_regex_with_matching_not_exception() {
        // regex: "c.?rl" matches "crl" and "curl"
        // not: ["curl"] should work
        let cond = Condition::String {
            exact: None,
            substr: None,
            regex: Some("c.?rl".to_string()),
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
        };

        let not = vec![NotException::Shorthand("curl".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_none());
    }

    #[test]
    fn test_regex_with_non_matching_not_exception_curl() {
        // regex: "c.?rl" matches "crl" and "curl" but not "hurl"
        // not: ["hurl"] will never apply
        let cond = Condition::String {
            exact: None,
            substr: None,
            regex: Some("c.?rl".to_string()),
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
        };

        let not = vec![NotException::Shorthand("hurl".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("does not match"));
        assert!(warning.as_ref().unwrap().contains("hurl"));
        assert!(warning.as_ref().unwrap().contains("c.?rl"));
    }

    #[test]
    fn test_regex_with_non_matching_not_exception() {
        // regex: "^test$" only matches exactly "test"
        // not: ["testing"] will never apply because "testing" doesn't match "^test$"
        let cond = Condition::String {
            exact: None,
            substr: None,
            regex: Some("^test$".to_string()),
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
        };

        let not = vec![NotException::Shorthand("testing".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("does not match"));
        assert!(warning.as_ref().unwrap().contains("testing"));
        assert!(warning.as_ref().unwrap().contains("^test$"));
    }

    #[test]
    fn test_content_substr_with_not_should_error() {
        // content + substr + not should be an error - behavior is unclear
        let cond = Condition::Raw {
            exact: None,
            substr: Some("test".to_string()),
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
            compiled_regex: None,
        };

        let not = vec![NotException::Shorthand("testing".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("content/substr"));
        assert!(warning.as_ref().unwrap().contains("behavior is unclear"));
    }

    #[test]
    fn test_content_exact_with_not_should_error() {
        // content + exact + not should be an error - doesn't make sense
        let cond = Condition::Raw {
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
            compiled_regex: None,
        };

        let not = vec![NotException::Shorthand("test".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("content/exact"));
        assert!(warning.as_ref().unwrap().contains("doesn't make sense"));
    }

    #[test]
    fn test_content_regex_with_not_is_ok() {
        // content + regex + not should work (no warning)
        let cond = Condition::Raw {
            exact: None,
            substr: None,
            regex: Some("test.*".to_string()),
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
        };

        let not = vec![NotException::Shorthand("testing".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_none());
    }

    #[test]
    fn test_symbol_exact_with_not_should_warn() {
        // Symbol exact match with not: should suggest using unless:
        let cond = Condition::Symbol {
            exact: Some("test".to_string()),
            substr: None,
            regex: None,
            platforms: None,
            compiled_regex: None,
        };

        let not = vec![NotException::Shorthand("test".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("symbol exact"));
        assert!(warning.as_ref().unwrap().contains("unless"));
    }

    #[test]
    fn test_symbol_substr_with_valid_not() {
        // Symbol substr with not: should work if exception contains substr
        let cond = Condition::Symbol {
            exact: None,
            substr: Some("test".to_string()),
            regex: None,
            platforms: None,
            compiled_regex: None,
        };

        let not = vec![NotException::Shorthand("testing".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_none());
    }

    #[test]
    fn test_symbol_substr_with_invalid_not() {
        // Symbol substr with not: should error if exception doesn't contain substr
        let cond = Condition::Symbol {
            exact: None,
            substr: Some("test".to_string()),
            regex: None,
            platforms: None,
            compiled_regex: None,
        };

        let not = vec![NotException::Shorthand("hurl".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("does not contain"));
        assert!(warning.as_ref().unwrap().contains("hurl"));
        assert!(warning.as_ref().unwrap().contains("test"));
    }

    #[test]
    fn test_symbol_regex_with_valid_not() {
        // Symbol regex with not: should work if exception matches regex
        let cond = Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("c.?rl".to_string()),
            platforms: None,
            compiled_regex: None,
        };

        let not = vec![NotException::Shorthand("curl".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_none());
    }

    #[test]
    fn test_symbol_regex_with_invalid_not() {
        // Symbol regex with not: should error if exception doesn't match regex
        let cond = Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some("c.?rl".to_string()),
            platforms: None,
            compiled_regex: None,
        };

        let not = vec![NotException::Shorthand("hurl".to_string())];
        let trait_def = create_test_trait(cond, Some(not));

        let warning = trait_def.check_not_field_usage();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("does not match"));
        assert!(warning.as_ref().unwrap().contains("hurl"));
        assert!(warning.as_ref().unwrap().contains("c.?rl"));
    }
}

#[cfg(test)]
mod criticality_tests {
    use crate::composite_rules::{Condition, TraitDefinition};
    use crate::types::Criticality;

    #[test]
    fn test_filtered_criticality_should_error() {
        // Criticality::Filtered is internal-only
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
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
        };

        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "Test trait".to_string(),
            conf: 0.8,
            crit: Criticality::Filtered,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
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
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        let warning = trait_def.check_criticality();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("filtered"));
        assert!(warning.as_ref().unwrap().contains("internal-only"));
        assert!(warning.as_ref().unwrap().contains("baseline"));
        assert!(warning.as_ref().unwrap().contains("notable"));
        assert!(warning.as_ref().unwrap().contains("suspicious"));
        assert!(warning.as_ref().unwrap().contains("hostile"));
    }

    #[test]
    fn test_valid_criticality_levels() {
        // All valid criticality levels should pass
        for crit in &[
            Criticality::Baseline,
            Criticality::Notable,
            Criticality::Suspicious,
            Criticality::Hostile,
        ] {
            let cond = Condition::String {
                exact: None,
                substr: Some("test".to_string()),
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
            };

            let trait_def = TraitDefinition {
                id: "test".to_string(),
                desc: "Test trait".to_string(),
                conf: 0.8,
                crit: *crit,
                mbc: None,
                attack: None,
                platforms: vec![],
                r#for: vec![],
                r#if: cond,
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
                defined_in: std::path::PathBuf::new(),
                precision: None,
            };

            let warning = trait_def.check_criticality();
            assert!(warning.is_none(), "Criticality {:?} should be valid", crit);
        }
    }
}

#[cfg(test)]
mod constraint_tests {
    use crate::composite_rules::{Condition, TraitDefinition};
    use crate::types::Criticality;

    #[test]
    fn test_confidence_out_of_range_low() {
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
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
        };

        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "Test trait".to_string(),
            conf: -0.5,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
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
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        let warning = trait_def.check_confidence();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("outside valid range"));
    }

    #[test]
    fn test_confidence_out_of_range_high() {
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
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
        };

        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "Test trait".to_string(),
            conf: 1.5,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
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
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        let warning = trait_def.check_confidence();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("outside valid range"));
    }

    #[test]
    fn test_size_max_less_than_min() {
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
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
        };

        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "Test trait".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
            size_min: Some(1000),
            size_max: Some(500), // max < min
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        let warning = trait_def.check_size_constraints();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("size_max"));
        assert!(warning.as_ref().unwrap().contains("size_min"));
    }

    #[test]
    fn test_count_max_less_than_min() {
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
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
        };

        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "Test trait".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
            size_min: None,
            size_max: None,
            count_min: Some(10),
            count_max: Some(5), // max < min
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        let warning = trait_def.check_count_constraints();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("count_max"));
        assert!(warning.as_ref().unwrap().contains("count_min"));
    }

    #[test]
    fn test_per_kb_max_less_than_min() {
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
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
        };

        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "Test trait".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: Some(10.0),
            per_kb_max: Some(5.0), // max < min
            entropy_min: None,
            entropy_max: None,
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        let warning = trait_def.check_density_constraints();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("per_kb_max"));
        assert!(warning.as_ref().unwrap().contains("per_kb_min"));
    }

    #[test]
    fn test_mutually_exclusive_match_types() {
        let cond = Condition::String {
            exact: Some("test".to_string()),
            substr: Some("test".to_string()),
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
        };

        let warning = cond.check_match_exclusivity();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("mutually exclusive"));
        assert!(warning.as_ref().unwrap().contains("exact"));
        assert!(warning.as_ref().unwrap().contains("substr"));
    }

    #[test]
    fn test_valid_constraints() {
        let cond = Condition::String {
            exact: None,
            substr: Some("test".to_string()),
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
        };

        assert!(cond.check_count_constraints().is_none());
        assert!(cond.check_density_constraints().is_none());
        assert!(cond.check_match_exclusivity().is_none());

        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "Test trait".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
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
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        assert!(trait_def.check_confidence().is_none());
        assert!(trait_def.check_size_constraints().is_none());
    }
}

#[cfg(test)]
mod llm_validation_tests {
    use crate::composite_rules::{Condition, TraitDefinition};
    use crate::types::Criticality;

    #[test]
    fn test_empty_string_pattern() {
        let cond = Condition::String {
            exact: Some("".to_string()),
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
        };

        let warning = cond.check_empty_patterns();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("empty pattern"));
    }

    #[test]
    fn test_whitespace_only_pattern() {
        let cond = Condition::String {
            exact: Some("   ".to_string()),
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
        };

        let warning = cond.check_empty_patterns();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("whitespace-only"));
    }

    #[test]
    fn test_short_substr_pattern() {
        let cond = Condition::String {
            exact: None,
            substr: Some("a".to_string()),
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
        };

        let warning = cond.check_short_patterns();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("very short"));
    }

    #[test]
    fn test_short_word_pattern() {
        let cond = Condition::String {
            exact: None,
            substr: None,
            regex: None,
            word: Some("x".to_string()),
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
        };

        let warning = cond.check_short_patterns();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("very short"));
    }

    #[test]
    fn test_literal_regex() {
        let cond = Condition::String {
            exact: None,
            substr: None,
            regex: Some("literalstring".to_string()),
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
        };

        let warning = cond.check_literal_regex();
        assert!(warning.is_some());
        assert!(warning
            .as_ref()
            .unwrap()
            .contains("no regex metacharacters"));
    }

    #[test]
    fn test_regex_with_metacharacters_is_valid() {
        let cond = Condition::String {
            exact: None,
            substr: None,
            regex: Some("test.*pattern".to_string()),
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
        };

        let warning = cond.check_literal_regex();
        assert!(warning.is_none());
    }

    #[test]
    fn test_case_insensitive_on_numeric_pattern() {
        let cond = Condition::String {
            exact: Some("12345".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: true,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
            compiled_regex: None,
        };

        let warning = cond.check_case_insensitive_on_non_alpha();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("contains no letters"));
    }

    #[test]
    fn test_case_insensitive_on_alpha_pattern() {
        let cond = Condition::String {
            exact: Some("test".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: true,
            external_ip: false,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
            platforms: None,
            compiled_regex: None,
        };

        let warning = cond.check_case_insensitive_on_non_alpha();
        assert!(warning.is_none());
    }

    #[test]
    fn test_count_min_zero() {
        let cond = Condition::String {
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
        };

        let trait_def = TraitDefinition {
            id: "test-trait".to_string(),
            desc: "Test trait".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
            size_min: None,
            size_max: None,
            count_min: Some(0), // Invalid: count_min should not be 0
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            not: None,
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        let warning = trait_def.check_count_min_value();
        assert!(warning.is_some());
        assert!(
            warning.as_ref().unwrap().contains("count_min: 0")
                || warning.as_ref().unwrap().contains("count_min of 0")
        );
    }

    #[test]
    fn test_count_min_nonzero() {
        let cond = Condition::String {
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
        };

        let warning = cond.check_count_min_value();
        assert!(warning.is_none());
    }

    #[test]
    fn test_empty_description() {
        let cond = Condition::String {
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
        };

        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
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
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        let warning = trait_def.check_description_quality();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("empty"));
    }

    #[test]
    fn test_placeholder_words_allowed_in_descriptions() {
        // Placeholder words are now allowed since traits may legitimately
        // detect placeholder text in manifests
        let cond = Condition::String {
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
        };

        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "Package manifest contains placeholder author name".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
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
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        let warning = trait_def.check_description_quality();
        assert!(
            warning.is_none(),
            "Descriptions mentioning placeholders should be valid"
        );
    }

    #[test]
    fn test_short_description() {
        let cond = Condition::String {
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
        };

        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "ok".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
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
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        let warning = trait_def.check_description_quality();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("too short"));
    }

    #[test]
    fn test_valid_description() {
        let cond = Condition::String {
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
        };

        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "This is a valid description".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
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
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        let warning = trait_def.check_description_quality();
        assert!(warning.is_none());
    }

    #[test]
    fn test_empty_not_array() {
        let cond = Condition::String {
            exact: None,
            substr: None,
            regex: Some("test.*".to_string()),
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
        };

        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "Test trait".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            not: Some(vec![]),
            unless: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        let warning = trait_def.check_empty_not_array();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("not: array is empty"));
    }

    #[test]
    fn test_empty_unless_array() {
        let cond = Condition::String {
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
        };

        let trait_def = TraitDefinition {
            id: "test".to_string(),
            desc: "Test trait".to_string(),
            conf: 0.8,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: vec![],
            r#for: vec![],
            r#if: cond,
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            not: None,
            unless: Some(vec![]),
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
        };

        let warning = trait_def.check_empty_unless_array();
        assert!(warning.is_some());
        assert!(warning.as_ref().unwrap().contains("unless: array is empty"));
    }
}
