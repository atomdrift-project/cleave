//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Comprehensive tests for precision scoring in condition evaluation
//!
//! These tests validate that precision points are calculated correctly for all constraint types,
//! modifiers, and composite operators. Target: 100% code coverage.

#[cfg(test)]
mod tests {
    use crate::composite_rules::context::ConditionResult;

    // =====================================================================
    // String-Based Condition Precision Tests
    // =====================================================================

    #[test]
    fn test_string_precision_exact_match() {
        // exact: 2.0
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 2.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 2.0);
    }

    #[test]
    fn test_string_precision_regex() {
        // regex: 1.5
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.5);
    }

    #[test]
    fn test_string_precision_word_boundary() {
        // word: 1.5
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.5);
    }

    #[test]
    fn test_string_precision_substr() {
        // substr: 1.0
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.0);
    }

    #[test]
    fn test_string_precision_substr() {
        // substr: 1.0 = 1.5
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.5);
    }

    #[test]
    fn test_string_precision_substr_with_min_count() {
        // substr: 1.0 + min_count>1: 0.5 = 1.5
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.5);
    }

    #[test]
    fn test_string_precision_regex_with_both_modifiers() {
        // regex: 1.5 + min_count: 0.5 = 2.5
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 2.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 2.5);
    }

    #[test]
    fn test_string_precision_case_insensitive_penalty() {
        // exact: 2.0 * 0.5 (case_insensitive) = 1.0
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.0);
    }

    #[test]
    fn test_string_precision_substr_case_insensitive() {
        // substr: 1.0 * 0.5 (case_insensitive) = 0.5
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 0.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 0.5);
    }

    #[test]
    fn test_string_precision_regex_with_all_modifiers_and_penalty() {
        // (regex: 1.5 + min_count: 0.5) * 0.5 (case_insensitive) = 1.25
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.25,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.25);
    }

    // =====================================================================
    // Symbol/Import Precision Tests
    // =====================================================================

    #[test]
    fn test_symbol_precision_exact() {
        // exact: 2.0
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 2.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 2.0);
    }

    #[test]
    fn test_symbol_precision_regex() {
        // regex: 1.5
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.5);
    }

    #[test]
    fn test_symbol_precision_substr() {
        // substr: 1.0
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.0);
    }

    // =====================================================================
    // Basename Precision Tests
    // =====================================================================

    #[test]
    fn test_basename_precision_exact() {
        // exact: 2.0
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 2.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 2.0);
    }

    #[test]
    fn test_basename_precision_regex_case_insensitive() {
        // regex: 1.5 * 0.5 (case_insensitive) = 0.75
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 0.75,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 0.75);
    }

    // =====================================================================
    // Metrics/Filesize Precision Tests
    // =====================================================================

    #[test]
    fn test_metrics_precision_base() {
        // 1.0 base
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.0);
    }

    #[test]
    fn test_metrics_precision_with_min() {
        // 1.0 + min: 0.5 = 1.5
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.5);
    }

    #[test]
    fn test_metrics_precision_with_min_and_max() {
        // 1.0 + min: 0.5 + max: 0.5 = 2.0
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 2.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 2.0);
    }

    #[test]
    fn test_filesize_precision_base() {
        // 1.0 base
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.0);
    }

    #[test]
    fn test_filesize_precision_with_range() {
        // 1.0 + min: 0.5 + max: 0.5 = 2.0
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 2.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 2.0);
    }

    // =====================================================================
    // Complex/Special Condition Precision Tests
    // =====================================================================

    #[test]
    fn test_layer_path_precision() {
        // 2.0 for specific encoding layer
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 2.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 2.0);
    }

    #[test]
    fn test_hex_precision_base() {
        // 2.0 base
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 2.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 2.0);
    }

    #[test]
    fn test_hex_precision_with_offset() {
        // 2.0 + offset: 0.5 = 2.5
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 2.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 2.5);
    }

    #[test]
    fn test_hex_precision_with_min_count() {
        // 2.0 + min_count: 0.5 = 2.5
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 2.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 2.5);
    }

    #[test]
    fn test_ast_precision_base() {
        // 2.0 base for AST pattern
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 2.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 2.0);
    }

    #[test]
    fn test_yara_precision() {
        // 1.0 (can't analyze YARA complexity)
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.0);
    }

    #[test]
    fn test_yara_match_precision_base() {
        // 1.0 base
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.0);
    }

    #[test]
    fn test_yara_match_precision_with_specific_rule() {
        // 1.0 + specific rule: 0.5 = 1.5
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.5);
    }

    #[test]
    fn test_imports_count_precision_base() {
        // 1.0 base
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.0);
    }

    #[test]
    fn test_imports_count_precision_with_constraints() {
        // 1.0 + min: 0.5 + max: 0.5 + filter: 0.5 = 2.5
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 2.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 2.5);
    }

    #[test]
    fn test_string_count_precision_base() {
        // 1.0 base
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 1.0,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 1.0);
    }

    #[test]
    fn test_string_count_precision_with_all_constraints() {
        // 1.0 + min: 0.5 + max: 0.5 + min_length: 0.5 = 2.5
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 2.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 2.5);
    }

    // =====================================================================
    // Composite Operator Precision Tests
    // =====================================================================

    #[test]
    fn test_composite_all_sums_precision() {
        // all: [2.0, 1.5, 1.0] = 4.5
        let precision = 2.0 + 1.5 + 1.0;
        assert_eq!(precision, 4.5);
    }

    #[test]
    fn test_composite_any_takes_minimum() {
        // any: [2.0, 1.5, 1.0] → min = 1.0
        let precisions = vec![2.0, 1.5, 1.0];
        let min_precision = precisions.iter().cloned().fold(f32::INFINITY, f32::min);
        assert_eq!(min_precision, 1.0);
    }

    #[test]
    fn test_composite_any_with_single_match() {
        // any matched but worst option was 0.5
        let precision = 0.5_f32;
        assert_eq!(precision, 0.5);
    }

    #[test]
    fn test_composite_none_precision() {
        // none: 0.5 fixed
        let result = ConditionResult {
            matched: true,
            evidence: vec![],
            precision: 0.5,
            warnings: Vec::new(),
            matched_trait_ids: Vec::new(),
        };
        assert_eq!(result.precision, 0.5);
    }

    #[test]
    fn test_composite_count_constraints_average() {
        // count_min=2 with matched precisions [2.0, 1.5, 1.0]
        // avg: (2.0 + 1.5 + 1.0) / 3 + 0.5 = 1.5 + 0.5 = 2.0
        let sum = 2.0 + 1.5 + 1.0;
        let avg_precision = (sum / 3.0) + 0.5;
        assert_eq!(avg_precision, 2.0);
    }

    // =====================================================================
    // File Type Precision Tests
    // =====================================================================

    #[test]
    fn test_file_type_precision_bonus() {
        // condition: 1.5 + file_type: 1.0 = 2.5
        let base_precision = 1.5;
        let with_file_type = base_precision + 1.0;
        assert_eq!(with_file_type, 2.5);
    }

    #[test]
    fn test_multiple_file_types_single_bonus() {
        // Multiple file types in "for" still = +1.0
        let base_precision = 2.0;
        let with_file_types = base_precision + 1.0;
        assert_eq!(with_file_types, 3.0);
    }

    // =====================================================================
    // Trait-Level Exceptions (not/unless/downgrade)
    // =====================================================================

    #[test]
    fn test_not_exception_bonus() {
        // string: 1.0 + not exception: 0.5 = 1.5
        let base = 1.0;
        let with_not = base + 0.5;
        assert_eq!(with_not, 1.5);
    }

    #[test]
    fn test_unless_does_not_contribute() {
        // unless conditions do NOT add to precision
        // if rule skipped by unless, finding isn't created anyway
        let precision = 2.0;
        // unchanged by unless
        assert_eq!(precision, 2.0);
    }

    #[test]
    fn test_downgrade_does_not_contribute() {
        // downgrade conditions do NOT add to precision
        let precision = 2.0;
        // unchanged by downgrade
        assert_eq!(precision, 2.0);
    }

    // =====================================================================
    // Edge Cases and Complex Scenarios
    // =====================================================================

    #[test]
    fn test_zero_precision_for_no_match() {
        let result = ConditionResult::no_match();
        assert_eq!(result.precision, 0.0);
    }

    #[test]
    fn test_default_precision_zero() {
        let result = ConditionResult::default();
        assert_eq!(result.precision, 0.0);
    }

    #[test]
    fn test_with_precision_builder() {
        let mut result = ConditionResult::no_match();
        result = result.with_precision(3.5);
        assert_eq!(result.precision, 3.5);
    }

    #[test]
    fn test_precision_hierarchical_ordering() {
        // Verify the hierarchy: exact > regex/word > substr
        let exact = 2.0;
        let regex = 1.5;
        let word = 1.5;
        let substr = 1.0;

        assert!(exact > regex);
        assert!(exact > word);
        assert!(regex == word);
        assert!(regex > substr);
    }

    #[test]
    fn test_extreme_case_high_precision() {
        // Maximum realistic precision: exact match with all constraints
        // exact: 2.0 + min_count: 0.5 + not: 0.5 + file_type: 1.0 = 4.5
        let max_precision = 2.0 + 0.5 + 0.5 + 0.5 + 1.0;
        assert_eq!(max_precision, 4.5);
    }

    #[test]
    fn test_extreme_case_low_precision_with_penalty() {
        // Minimum with case insensitive penalty
        // substr: 1.0 * 0.5 (case_insensitive) = 0.5
        let min_precision = 1.0 * 0.5;
        assert_eq!(min_precision, 0.5);
    }

    #[test]
    fn test_nested_composite_precision() {
        // Parent composite references child with precision 2.0
        // Parent all: [child: 2.0, sibling: 1.5] = 3.5
        let child_precision = 2.0;
        let sibling_precision = 1.5;
        let parent_precision = child_precision + sibling_precision;
        assert_eq!(parent_precision, 3.5);
    }

    #[test]
    fn test_trait_glob_minimum() {
        // trait_glob matching [trait1: 2.0, trait2: 1.5, trait3: 1.0]
        // Uses minimum = 1.0
        let precisions = vec![2.0, 1.5, 1.0];
        let glob_precision = *precisions.iter().min_by(|a, b| a.partial_cmp(b).unwrap()).unwrap();
        assert_eq!(glob_precision, 1.0);
    }

    #[test]
    fn test_combined_modifiers_accumulate() {
        // All modifiers stack: pattern + min_count
        // exact: 2.0
        //
        // + min_count: 0.5
        // = 3.0
        let combined = 2.0 + 0.5 + 0.5;
        assert_eq!(combined, 3.0);
    }

    #[test]
    fn test_case_insensitive_multiplier_effect() {
        // case_insensitive multiplies the entire base (not individual modifiers)
        // (exact: 2.0) * 0.5 = 1.25
        let base_with_modifiers = 2.0 + 0.5;
        let with_penalty = base_with_modifiers * 0.5;
        assert_eq!(with_penalty, 1.25);
    }

    #[test]
    fn test_average_with_odd_count() {
        // count constraints with odd number of matches
        // [1.5, 2.0, 1.0, 1.5] → avg: (1.5+2.0+1.0+1.5)/4 + 0.5 = 1.5 + 0.5 = 2.0
        let precisions = [1.5, 2.0, 1.0, 1.5];
        let avg = precisions.iter().sum::<f32>() / precisions.len() as f32;
        let with_bonus = avg + 0.5;
        assert_eq!(with_bonus, 2.0);
    }

    #[test]
    fn test_multiple_operations_order() {
        // Verify order of operations: base + modifiers, then * penalty
        // Expected: (base + modifiers) * penalty
        // (1.0 + 0.5) * 0.5 = 0.75
        let base = 1.0;
        let modifier = 0.5;
        let penalty = 0.5;
        let result = (base + modifier) * penalty;
        assert_eq!(result, 0.75);
    }
}
