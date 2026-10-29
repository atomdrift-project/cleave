//! The trait-rule linter: every check full validation runs over a merged
//! trait set, in the order it reports.
//!
//! A validator is two halves. Its check reads the finished trait set -- which
//! does not change again after precision scoring -- and returns its report.
//! The checks run together, so validation costs about as much as the longest
//! of them; the reports then run one at a time in table order, so stderr and
//! the issue list read the same on every run.

mod clauses;
mod composites;
mod patterns;
mod references;
mod scope;
mod taxonomy;
mod tiers;

use super::loader_directory::MergedRules;
use crate::capabilities::validation::ExtractedPatterns;
use crate::composite_rules::{CompositeTrait, TraitDefinition};
use crate::validation_controls::ValidationIssues;
use rayon::prelude::*;
use rustc_hash::FxHashSet;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// What every validator reads: the merged trait set, and what is derived from
/// it once for all of them.
struct ValidationInput<'a> {
    dir_path: &'a Path,
    yaml_files: &'a [PathBuf],
    trait_definitions: &'a [TraitDefinition],
    composite_rules: &'a [CompositeTrait],
    /// Rule id to the file that defines it, for traits and composites alike.
    rule_source_files: &'a HashMap<String, String>,
    /// Trait id to the file that defines it.
    trait_source_files: &'a HashMap<String, String>,
    /// Every directory that holds a trait or composite, with all its parents.
    prefix_hierarchy: HashSet<&'a str>,
    /// Every directory that holds a trait or composite.
    dir_list: Vec<String>,
    patterns: ExtractedPatterns,
    /// Every trait and composite id: what the broken-reference check reads.
    valid_trait_ids: FxHashSet<String>,
    all_trait_ids: Vec<String>,
}

impl<'a> ValidationInput<'a> {
    fn new(dir_path: &'a Path, yaml_files: &'a [PathBuf], rules: &'a MergedRules) -> Self {
        let (known_prefixes, prefix_hierarchy) =
            known_prefixes(&rules.trait_definitions, &rules.composite_rules);
        let dir_list = known_prefixes.iter().map(|&p| p.to_owned()).collect();
        let mut valid_trait_ids: FxHashSet<String> = rules
            .trait_definitions
            .iter()
            .map(|t| t.id.clone())
            .collect();
        valid_trait_ids.extend(rules.composite_rules.iter().map(|r| r.id.clone()));
        let all_trait_ids = valid_trait_ids.iter().cloned().collect();
        Self {
            dir_path,
            yaml_files,
            trait_definitions: &rules.trait_definitions,
            composite_rules: &rules.composite_rules,
            rule_source_files: &rules.rule_source_files,
            trait_source_files: &rules.trait_source_files,
            prefix_hierarchy,
            dir_list,
            patterns: ExtractedPatterns::of(&rules.trait_definitions),
            valid_trait_ids,
            all_trait_ids,
        }
    }
}

/// A validator's second half: what it prints and records.
type Report<'a> = Box<dyn FnOnce(&mut ValidationIssues) + Send + 'a>;

/// A validator's first half: what it computes from the trait set.
type Check = for<'a> fn(&'a ValidationInput<'a>) -> Report<'a>;

fn report<'a>(f: impl FnOnce(&mut ValidationIssues) + Send + 'a) -> Report<'a> {
    Box::new(f)
}

fn enabled(validator_id: &str) -> bool {
    !crate::validation_controls::is_validator_disabled(validator_id)
}

/// Run a `warnings.collect_as` check ahead of the step that reports it:
/// `None` when the validator is disabled, which that step would skip.
fn collect_early(validator_id: &str, check: impl FnOnce(&mut Vec<String>)) -> Option<Vec<String>> {
    if crate::validation_controls::is_validator_disabled(validator_id) {
        return None;
    }
    let mut messages = Vec::new();
    let started = std::time::Instant::now();
    check(&mut messages);
    tracing::debug!(
        validator = validator_id,
        elapsed_ms = started.elapsed().as_millis(),
        "validator timing"
    );
    Some(messages)
}

/// Lint a merged trait set, adding what it finds to `warnings`.
///
/// Without full validation only the check that composite references name a
/// known directory runs; it has always run on every load.
pub(super) fn run(
    dir_path: &Path,
    yaml_files: &[PathBuf],
    rules: &MergedRules,
    enable_full_validation: bool,
    warnings: &mut ValidationIssues,
) {
    if !enable_full_validation {
        tracing::trace!(
            "Step 1/15: Skipping precision validation (run 'cleave validate' to enable)"
        );
        let (_, prefix_hierarchy) =
            known_prefixes(&rules.trait_definitions, &rules.composite_rules);
        references::report_unresolved_trait_prefixes(&rules.composite_rules, &prefix_hierarchy);
        return;
    }

    let input = ValidationInput::new(dir_path, yaml_files, rules);
    let reports: Vec<Report<'_>> = VALIDATORS
        .par_iter()
        .map(|&(id, check)| {
            let _span = tracing::trace_span!("validator_check", id).entered();
            check(&input)
        })
        .collect();
    for (&(id, _), report) in VALIDATORS.iter().zip(reports) {
        let _span = tracing::trace_span!("validator_report", id).entered();
        report(warnings);
    }
}

/// The directory prefix of every trait and composite id, and those prefixes
/// with all their parents added: what a cross-directory reference may name.
fn known_prefixes<'a>(
    trait_definitions: &'a [TraitDefinition],
    composite_rules: &'a [CompositeTrait],
) -> (HashSet<&'a str>, HashSet<&'a str>) {
    tracing::trace!("Step 2/15: Building known prefixes");
    // Composite rule prefixes count too (composite rules can reference
    // other composite rules). The prefixes are borrowed from the ids.
    let known_prefixes: HashSet<&str> = trait_definitions
        .iter()
        .map(|t| t.id.as_str())
        .chain(composite_rules.iter().map(|r| r.id.as_str()))
        .filter_map(|id| {
            // Extract the directory prefix from trait IDs
            // New format: everything before '::' (e.g., "micro-behaviors/communications/http::curl" -> "micro-behaviors/communications/http")
            // Legacy format: everything before last '/' (e.g., "micro-behaviors/communications/http/curl" -> "micro-behaviors/communications/http")
            match id.find("::") {
                Some(idx) => Some(&id[..idx]),
                None => id.rfind('/').map(|idx| &id[..idx]),
            }
        })
        .collect();

    // Pre-compute all parent paths for O(1) prefix matching
    // This avoids O(n) iteration for every trait reference check
    let mut prefix_hierarchy = known_prefixes.clone();
    for prefix in &known_prefixes {
        // Add all parent paths: "micro-behaviors/fs/write" -> ["cap", "micro-behaviors/fs", "micro-behaviors/fs/write"]
        prefix_hierarchy.extend(prefix.match_indices('/').map(|(i, _)| &prefix[..i]));
    }
    tracing::trace!(
        "Built prefix hierarchy with {} entries from {} base prefixes",
        prefix_hierarchy.len(),
        known_prefixes.len()
    );
    (known_prefixes, prefix_hierarchy)
}

/// Every validator, in the order it reports.
#[rustfmt::skip]
const VALIDATORS: &[(&str, Check)] = &[
    // Search patterns.
    ("duplicate-rules", patterns::duplicate_rules),
    ("duplicate-patterns", patterns::duplicate_patterns),
    ("regex-or-literal-overlap", patterns::regex_or_literal_overlap),
    ("overlapping-regex-patterns", patterns::overlapping_regex_patterns),
    ("structural-regex-duplicates", patterns::structural_regex_duplicates),
    ("regex-should-be-exact", patterns::regex_should_be_exact),
    ("cross-type-patterns", patterns::cross_type_patterns),
    ("slow-regexes", patterns::slow_regexes),
    ("memory-hungry-regexes", patterns::memory_hungry_regexes),
    ("pathological-regexes", patterns::pathological_regexes),
    ("uncompilable-ast-queries", patterns::uncompilable_ast_queries),
    ("non-capturing-groups", patterns::non_capturing_groups),
    ("incompatible-regexes", patterns::incompatible_regexes),
    ("brittle-path-patterns", patterns::brittle_path_patterns),
    ("raw-should-use-text", patterns::raw_should_use_text),
    ("string-literal-should-use-text", patterns::string_literal_should_use_text),
    ("ast-calls-should-use-symbol", patterns::ast_calls_should_use_symbol),
    ("exact-contained-by-substr", patterns::exact_contained_by_substr),
    ("case-insensitive-overlaps", patterns::case_insensitive_overlaps),
    ("regex-literal-overlaps", patterns::regex_literal_overlaps),
    ("regex-alternative-subsets", patterns::regex_alternative_subsets),
    ("basename-duplicates", patterns::basename_duplicates),

    // Directory layout.
    ("unknown-subdirectories", taxonomy::unknown_subdirectories),
    ("non-leaf-yaml-files", taxonomy::non_leaf_yaml_files),
    ("platform-named-directories", taxonomy::platform_named_directories),
    ("duplicate-second-level-directories", taxonomy::duplicate_second_level_directories),
    ("wide-directories", taxonomy::wide_directories),
    ("banned-directory-segments", taxonomy::banned_directory_segments),
    ("permuted-directory-paths", taxonomy::permuted_directory_paths),
    ("sibling-name-restatement", taxonomy::sibling_name_restatement),
    ("metadata-content-dirs", taxonomy::metadata_content_dirs),
    ("new-metadata-file-ids", taxonomy::new_metadata_file_ids),
    ("parent-duplicate-segments", taxonomy::parent_duplicate_segments),
    ("deep-taxonomy-directories", taxonomy::deep_taxonomy_directories),
    ("fragmented-sibling-cohorts", taxonomy::fragmented_sibling_cohorts),

    // References and self-references.
    ("invalid-trait-ids", references::invalid_trait_ids),
    ("self-referencing-traits", references::self_referencing_traits),
    ("dead-downgrades", references::dead_downgrades),
    ("exhaustive-suppressors", references::exhaustive_suppressors),
    ("directory-shadowed-refs", references::directory_shadowed_refs),
    ("uncallable-symbol-matchers", references::uncallable_symbol_matchers),
    ("broad-notable-downgrades", references::broad_notable_downgrades),
    ("self-suppressing-traits", references::self_suppressing_traits),
    ("self-referencing-composites", references::self_referencing_composites),
    ("leg-suppressing-composites", references::leg_suppressing_composites),
    ("unresolved-trait-prefixes", references::unresolved_trait_prefixes),
    ("retired-internal-refs", references::retired_internal_refs),

    // Tier boundaries and the `crit: exception` contract.
    ("cap-obj-violations", tiers::cap_obj_violations),
    ("hostile-cap-rules", tiers::hostile_cap_rules),
    ("hostile-meta-rules", tiers::hostile_meta_rules),
    ("metadata-cross-tier-refs", tiers::metadata_cross_tier_refs),
    ("cap-wellknown-violations", tiers::cap_wellknown_violations),
    ("objectives-wellknown-violations", tiers::objectives_wellknown_violations),
    ("wellknown-baseline-rules", tiers::wellknown_baseline_rules),
    ("wellknown-high-criticality-basenames", tiers::wellknown_high_criticality_basenames),
    ("suppression-only-building-blocks", tiers::suppression_only_building_blocks),
    ("exception-atomic-traits", tiers::exception_atomic_traits),
    ("exception-inline-conditions", tiers::exception_inline_conditions),
    ("exception-non-notable-members", tiers::exception_non_notable_members),
    ("exception-positive-refs", tiers::exception_positive_refs),
    ("unreferenced-exceptions", tiers::unreferenced_exceptions),
    ("benign-misplaced", tiers::benign_misplaced),
    ("long-composite-descriptions", tiers::long_composite_descriptions),
    ("malware-subcategory-violations", tiers::malware_subcategory_violations),

    // Placement, platforms and file types.
    ("wellknown-category-violations", scope::wellknown_category_violations),
    ("generic-wellknown-leaf-dirs", scope::generic_wellknown_leaf_dirs),
    ("unanchored-wellknown-composites", scope::unanchored_wellknown_composites),
    ("composite-only-wellknown-files", scope::composite_only_wellknown_files),
    ("all-platform-rules-outside-allowlist", scope::all_platform_rules_outside_allowlist),
    ("broad-platform-traits", scope::broad_platform_traits),
    ("redundant-unix-platforms", scope::redundant_unix_platforms),
    ("stale-filetype-allowlist", scope::stale_filetype_allowlist),
    ("impossible-composite-filetypes", scope::impossible_composite_filetypes),
    ("mixed-archive-filetypes", scope::mixed_archive_filetypes),
    ("legs-outside-for", scope::legs_outside_for),
    ("dead-any-alternatives", scope::dead_any_alternatives),
    ("pooling-scope-without-container", scope::pooling_scope_without_container),
    ("unbindable-package-scope", scope::unbindable_package_scope),
    ("broad-filetype-traits", scope::broad_filetype_traits),
    ("wellknown-missing-size-filter", scope::wellknown_missing_size_filter),
    ("wellknown-version-paths", scope::wellknown_version_paths),
    ("wellknown-missing-section-filter", scope::wellknown_missing_section_filter),
    ("metadata-missing-section-filter", scope::metadata_missing_section_filter),
    ("hex-binary-missing-section", scope::hex_binary_missing_section),

    // Composite clauses and conditions.
    ("directory-reference-clauses", clauses::directory_reference_clauses),
    ("single-item-clauses", clauses::single_item_clauses),
    ("overlapping-conditions", clauses::overlapping_conditions),
    ("string-content-collisions", clauses::string_content_collisions),
    ("overlapping-scope-duplicates", clauses::overlapping_scope_duplicates),
    ("for-only-duplicates", clauses::for_only_duplicates),
    ("inline-content-duplicates", clauses::inline_content_duplicates),
    ("atomic-logic-duplicates", clauses::atomic_logic_duplicates),
    ("alternation-merge-candidates", clauses::alternation_merge_candidates),
    ("impossible-needs", clauses::impossible_needs),
    ("impossible-size-constraints", clauses::impossible_size_constraints),
    ("impossible-count-constraints", clauses::impossible_count_constraints),
    ("empty-condition-clauses", clauses::empty_condition_clauses),
    ("needs-without-any", clauses::needs_without_any),
    ("needs-zero", clauses::needs_zero),
    ("invalid-hex-patterns", clauses::invalid_hex_patterns),
    ("missing-search-patterns", clauses::missing_search_patterns),
    ("too-short-patterns", clauses::too_short_patterns),
    ("invalid-not-usage", clauses::invalid_not_usage),
    ("length-bounds-without-regex", clauses::length_bounds_without_regex),
    ("impossible-length-bounds", clauses::impossible_length_bounds),
    ("kv-exists-with-matcher", clauses::kv_exists_with_matcher),
    ("none-only-with-proximity", clauses::none_only_with_proximity),
    ("redundant-needs-one", clauses::redundant_needs_one),

    // How composites assemble evidence.
    ("bare-or-crit-escalations", composites::bare_or_crit_escalations),
    ("excessive-suppressions", composites::excessive_suppressions),
    ("excessive-file-types", composites::excessive_file_types),
    ("pure-alias-traits", composites::pure_alias_traits),
    ("orphaned-components", composites::orphaned_components),
    ("hostile-too-few-notable-legs", composites::hostile_too_few_notable_legs),
    ("container-name-convictions", composites::container_name_convictions),
    ("subsumed-required-legs", composites::subsumed_required_legs),
    ("one-fact-convictions", composites::one_fact_convictions),
    ("convictions-without-content", composites::convictions_without_content),
    ("dangling-directory-refs", composites::dangling_directory_refs),
    ("short-patterns", composites::short_patterns),
    ("oversized-directories", composites::oversized_directories),
    ("broken-references", references::broken_references),
    ("unknown-metric-fields", references::unknown_metric_fields),
    ("composite-inline-primitives", composites::composite_inline_primitives),
    ("single-trait-composites", composites::single_trait_composites),
];

/// True when `ref_id` targets a namespace that analyzers synthesize at runtime
/// (from imports, code signatures, entitlements, or embedded-language detection)
/// rather than one defined by a static YAML trait. Such references never appear
/// in `valid_trait_ids`, so the broken-reference check must exempt them.
///
/// Keep this in sync with the analyzers that synthesize these IDs:
/// `imports.rs` (`metadata/import/…`, `metadata/dylib…`), `macho.rs`/`pe.rs`
/// (`metadata/signed/…`, `metadata/entitlement/…`, `metadata/binary/linking::macho-*`),
/// `embedded_code_detector.rs` (`metadata/lang/embedded::…`, `metadata/lang/encoded/…`),
/// and the debug-info analyzer (`metadata/build/debug::elf-debuglink`). The trailing ids below are
/// specific, not prefixes, because their directories also hold static YAML traits
/// (e.g. `metadata/binary/linking::ifunc`) that must still be validated.
fn is_dynamic_metadata_ref(ref_id: &str) -> bool {
    crate::capabilities::validation::is_runtime_synthesized_namespace(ref_id)
}
