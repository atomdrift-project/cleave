//! Rule validation and precision analysis for trait definitions.
//!
//! This module validates trait and composite rule definitions, calculates
//! precision scores, and detects various quality issues including:
//!
//! - Precision calculation for atomic traits and composite rules
//! - Duplicate trait and pattern detection
//! - Pattern quality analysis (short patterns, slow regex)
//! - Composite rule validation (trait-only, redundancy)
//! - Taxonomy validation (directory structure, naming)
//! - Logic constraint validation (impossible conditions)
//!
//! ## Module Structure
//!
//! - [`precision`]: Precision scoring and calculation
//! - [`duplicates`]: Duplicate trait and pattern detection
//! - [`composite`]: Composite rule specific validation
//! - [`patterns`]: Pattern quality and performance checks
//! - [`taxonomy`]: Directory structure and naming validation
//! - [`constraints`]: Logic constraint validation
//! - [`helpers`]: Utility functions (regex, line numbers, conversions)
//!
//! ## Example
//!
//! ```ignore
//! use crate::capabilities::validation::{calculate_trait_precision, validate_composite_trait_only};
//!
//! let precision = calculate_trait_precision(&trait_def);
//! validate_composite_trait_only(&composite_rule, &mut warnings);
//! ```

mod composite;
mod constraints;
mod directory_whitelist;
mod duplicates;
mod helpers;
mod patterns;
mod precision;
mod taxonomy;

// Shared types used across validation modules
pub(super) mod shared {
    use std::collections::HashSet;

    /// Information about where a pattern was found
    #[derive(Debug, Clone)]
    pub(super) struct PatternLocation {
        pub(super) trait_id: String,
        pub(super) file_path: String,
        pub(super) condition_type: String, // "string", "symbol", "raw"
        pub(super) match_type: String,     // "exact", "substr", "word", "regex"
        pub(super) original_value: String, // Original pattern before normalization
        pub(super) for_types: HashSet<String>,
        pub(super) section: Option<String>,
        pub(super) count_min: Option<usize>,
        pub(super) count_max: Option<usize>,
        pub(super) per_kb_min: Option<f64>,
        pub(super) per_kb_max: Option<f64>,
        pub(super) confidence: f32,
        pub(super) criticality: crate::types::Criticality,
    }

    /// Signature for string/raw matching conditions (for collision detection)
    /// Note: count/density fields excluded - they're at trait level now and don't affect matching logic
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub(super) struct MatchSignature {
        pub(super) exact: Option<String>,
        pub(super) substr: Option<String>,
        pub(super) regex: Option<String>,
        pub(super) word: Option<String>,
        pub(super) case_insensitive: bool,
        pub(super) external_ip: bool,
        pub(super) section: Option<String>,
        pub(super) offset: Option<i64>,
        pub(super) offset_range: Option<(i64, Option<i64>)>,
        pub(super) section_offset: Option<i64>,
        pub(super) section_offset_range: Option<(i64, Option<i64>)>,
    }
}

// Re-export public API (pub(crate) - accessible to capabilities module)

// Precision calculation
#[allow(unused_imports)] // calculate_composite_precision is used by test_rules in binary
pub(crate) use precision::{
    calculate_composite_precision, calculate_trait_precision,
    precalculate_all_composite_precisions, validate_hostile_composite_precision,
};

// Duplicate detection
pub(crate) use duplicates::{
    check_basename_pattern_duplicates, check_case_insensitive_overlaps,
    check_exact_contained_by_substr, check_overlapping_regex_patterns,
    check_regex_alternative_subsets, check_regex_contains_literal,
    check_regex_or_overlapping_exact, check_regex_should_be_exact,
    check_same_string_different_types, find_alternation_merge_candidates,
    find_atomic_logic_duplicates, find_duplicate_traits_and_composites, find_for_only_duplicates,
    find_string_content_collisions, find_string_pattern_duplicates,
};

// Composite rule validation
pub(crate) use composite::{
    autoprefix_trait_refs, collect_trait_refs_from_rule, find_overlapping_conditions,
    find_redundant_any_refs, find_single_item_clauses, validate_composite_trait_only,
};

// Pattern quality checks
pub(crate) use patterns::{
    find_non_capturing_groups, find_short_pattern_warnings, find_slow_regex_patterns,
};

// Taxonomy validation
pub(crate) use directory_whitelist::validate_directory_structure;
pub(crate) use taxonomy::{
    find_banned_directory_segments, find_cap_obj_violations, find_cap_wellknown_violations,
    find_composite_only_wellknown_files, find_depth_violations,
    find_duplicate_second_level_directories, find_generic_wellknown_leaf_dirs,
    find_hostile_cap_rules, find_hostile_meta_rules, find_invalid_trait_ids,
    find_malware_subcategory_violations, find_meta_missing_section_filter,
    find_metadata_cross_tier_refs, find_oversized_trait_directories,
    find_parent_duplicate_segments, find_platform_named_directories,
    find_unanchored_wellknown_composites, find_wellknown_category_violations,
    find_wellknown_missing_section_filter, find_wellknown_missing_size_filter,
    find_wellknown_unscoped_filetypes, find_wellknown_unscoped_platforms, MAX_TRAITS_PER_DIRECTORY,
};

// Logic constraint validation
#[allow(unused_imports)] // find_needs_zero used by binary target
pub(crate) use constraints::{
    find_empty_condition_clauses, find_excessive_file_types, find_excessive_skip_conditions,
    find_hex_binary_missing_section, find_impossible_count_constraints, find_impossible_needs,
    find_impossible_size_constraints, find_invalid_not_usage, find_kv_exists_with_matcher,
    find_missing_search_patterns, find_needs_without_any, find_needs_zero,
    find_none_only_with_proximity, find_orphaned_components, find_pure_alias_traits,
    find_redundant_explicit_defaults, find_redundant_needs_one, find_should_use_defaults,
    find_too_short_patterns,
};

// Utility functions
pub(crate) use helpers::{find_line_number, simple_rule_to_composite_rule};

#[cfg(test)]
mod tests;
