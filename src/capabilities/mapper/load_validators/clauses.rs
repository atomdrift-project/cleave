//! Checks on composite clauses and conditions: redundant or overlapping
//! references, duplicates, and constraints that can never be met.

use super::{Report, ValidationInput, enabled, report};
use crate::capabilities::validation::{
    MISSING_CONDITIONS, find_alternation_merge_candidates, find_atomic_logic_duplicates,
    find_empty_condition_clauses, find_for_only_duplicates, find_impossible_count_constraints,
    find_impossible_length_bounds, find_impossible_needs, find_impossible_size_constraints,
    find_inline_content_duplicates, find_invalid_hex_patterns, find_invalid_not_usage,
    find_kv_exists_with_matcher, find_length_bounds_without_regex, find_line_number,
    find_many_directory_refs, find_missing_search_patterns, find_needs_without_any,
    find_needs_zero, find_none_only_with_proximity, find_overlapping_conditions,
    find_overlapping_scope_duplicates, find_pure_directory_alias_composites,
    find_redundant_any_refs, find_redundant_needs_one, find_single_item_clauses,
    find_string_content_collisions, find_too_short_patterns,
};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Validate that `any:` clauses don't have 8+ traits from the same external directory
/// Recommend using directory references instead for better maintainability
pub(super) fn directory_reference_clauses<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        tracing::trace!("Step 14/15: Checking for redundant any refs");
        // How many definitions live under each directory prefix. Collapsing
        // an enumerated `any:` to `id: <dir>` preserves the rule's meaning
        // only when the enumeration already covers all of them;
        // short of that the advice widens the rule, so the check needs the
        // directory's size as well as the reference count.
        let dir_members = directory_trait_members(
            input
                .trait_definitions
                .iter()
                .map(|t| &t.id)
                .chain(input.composite_rules.iter().map(|c| &c.id)),
        );
        let dir_sizes = dir_members
            .iter()
            .map(|(dir, members)| (dir.clone(), members.len()))
            .collect();
        // Each rule is checked on its own, so the rules are checked in
        // parallel here and in the three checks below; `collect` keeps
        // their order.
        let redundant_any_refs: Vec<_> = input
            .composite_rules
            .par_iter()
            .flat_map_iter(|rule| find_redundant_any_refs(rule, &dir_sizes))
            .map(|(rule_id, dir, count, trait_ids)| {
                let source_file = input
                    .rule_source_files
                    .get(&rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                (rule_id, dir, count, trait_ids, source_file.to_string())
            })
            .collect();

        if !redundant_any_refs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have redundant any: clauses",
                redundant_any_refs.len()
            );
            eprintln!(
                "   Rules with 8+ distinct references covering a whole directory should use directory notation:\n"
            );
            for (rule_id, dir, count, trait_ids, source_file) in &redundant_any_refs {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' references {} traits from '{}'",
                        source_file, line, rule_id, count, dir
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' references {} traits from '{}'",
                        source_file, rule_id, count, dir
                    );
                }
                eprintln!("      Traits: {}", trait_ids.join(", "));
                eprintln!(
                    "      Recommendation: Use 'id: {}', or create a new subdirectory within it to hold common traits instead.\n",
                    dir
                );
            }
            warnings.push(format!(
                "{} composite rules have redundant any: clauses (use directory notation)",
                redundant_any_refs.len()
            ));
        }

        // Validate exhaustive any: lists. all: conjunctions are not directory aliases.
        tracing::trace!("Checking for many directory references in composite clauses");
        let mut dir_traits: HashMap<String, HashSet<String>> = HashMap::new();
        let disable_many_directory_references =
            crate::validation_controls::is_validator_disabled("many-directory-references");
        let disable_dir_alias_composite =
            crate::validation_controls::is_validator_disabled("directory-alias-composite");
        if !disable_many_directory_references || !disable_dir_alias_composite {
            // A positive directory reference includes composites too. An
            // atomic-only or direct-child inventory widens the rule.
            dir_traits = dir_members;
        }
        let mut many_dir_ref_clauses = Vec::new();
        if !disable_many_directory_references {
            many_dir_ref_clauses = input
                .composite_rules
                .par_iter()
                .flat_map_iter(|rule| find_many_directory_refs(rule, &dir_traits))
                .map(|(rule_id, clause, dir, count, trait_ids)| {
                    let source_file = input
                        .rule_source_files
                        .get(&rule_id)
                        .map(std::string::String::as_str)
                        .unwrap_or("unknown");
                    (
                        rule_id,
                        clause,
                        dir,
                        count,
                        trait_ids,
                        source_file.to_string(),
                    )
                })
                .collect();
        }

        if !many_dir_ref_clauses.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules hand-maintain many refs to one directory",
                many_dir_ref_clauses.len()
            );
            eprintln!(
                "   An exhaustive any: list can use its directory without adding alternatives:\n"
            );
            for (rule_id, clause, dir, count, trait_ids, source_file) in &many_dir_ref_clauses {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' {}: clause covers all {} traits in '{}'",
                        source_file, line, rule_id, clause, count, dir
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' {}: clause covers all {} traits in '{}'",
                        source_file, rule_id, clause, count, dir
                    );
                }
                eprintln!("      Traits: {}", trait_ids.join(", "));
                if *clause == "any" {
                    eprintln!(
                        "      Recommendation: Replace the explicit list with 'id: {}'.\n",
                        dir
                    );
                } else {
                    eprintln!(
                        "      Recommendation: Keep small intentional bundles together; split only when there are clear sub-techniques.\n"
                    );
                }
            }
            warnings.push_count(
                "many-directory-references",
                many_dir_ref_clauses.len(),
                format!(
                    "{} composite rules hand-maintain many refs to one directory",
                    many_dir_ref_clauses.len()
                ),
            );
        }

        let dir_alias_composites = if disable_dir_alias_composite {
            Vec::new()
        } else {
            find_pure_directory_alias_composites(input.composite_rules, &dir_traits)
        };
        if !dir_alias_composites.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composites are pure directory aliases",
                dir_alias_composites.len()
            );
            eprintln!("   These composites add no logic beyond matching any trait in a directory.");
            eprintln!("   Delete the composite and reference the directory directly:\n");
            for (rule_id, dir, count, trait_ids) in &dir_alias_composites {
                let source_file = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' is equivalent to '{}'",
                        source_file, line, rule_id, dir
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' is equivalent to '{}'",
                        source_file, rule_id, dir
                    );
                }
                eprintln!("      Traits ({}): {}", count, trait_ids.join(", "));
                eprintln!(
                    "      Recommendation: Remove the composite and use 'id: {}'.\n",
                    dir
                );
            }
            warnings.push_count(
                "directory-alias-composite",
                dir_alias_composites.len(),
                format!(
                    "{} composites are pure directory aliases",
                    dir_alias_composites.len()
                ),
            );
        }
    })
}

/// Validate that `any:` and `all:` clauses don't have exactly 1 item
/// Single-item clauses are pointless wrappers that add complexity
pub(super) fn single_item_clauses<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        tracing::trace!("Step 15/15: Checking for single-item clauses");
        let single_item_clauses: Vec<_> = input
            .composite_rules
            .par_iter()
            .flat_map_iter(find_single_item_clauses)
            .map(|(rule_id, clause_type, trait_id)| {
                let source_file = input
                    .rule_source_files
                    .get(&rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                (rule_id, clause_type, trait_id, source_file.to_string())
            })
            .collect();

        if !single_item_clauses.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have single-item any:/all: clauses",
                single_item_clauses.len()
            );
            eprintln!(
                "   Single-item clauses add no value - reference the trait directly instead:\n"
            );
            for (rule_id, clause_type, trait_id, source_file) in &single_item_clauses {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' has single-item {}: clause referencing '{}'",
                        source_file, line, rule_id, clause_type, trait_id
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' has single-item {}: clause referencing '{}'",
                        source_file, rule_id, clause_type, trait_id
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} composite rules have single-item any:/all: clauses",
                single_item_clauses.len()
            ));
        }
    })
}

/// Validate that all:/any: clauses don't contain overlapping IDs.
/// A directory reference subsumes any specific trait from that directory.
pub(super) fn overlapping_conditions<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        let overlapping: Vec<_> = input
            .composite_rules
            .par_iter()
            .flat_map_iter(find_overlapping_conditions)
            .map(|(rule_id, clause, dir_ref, specific_ref)| {
                let source_file = input
                    .rule_source_files
                    .get(&rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                (
                    rule_id,
                    clause,
                    dir_ref,
                    specific_ref,
                    source_file.to_string(),
                )
            })
            .collect();
        if !crate::validation_controls::is_validator_disabled("overlapping-conditions")
            && !overlapping.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} composite rules have overlapping all:/any: conditions",
                overlapping.len()
            );
            eprintln!(
                "   A directory reference already includes all traits within it;\n   remove the specific trait reference:\n"
            );
            for (rule_id, clause, dir_ref, specific_ref, source_file) in &overlapping {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' {}: clause - '{}' is subsumed by '{}'",
                        source_file, line, rule_id, clause, specific_ref, dir_ref
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' {}: clause - '{}' is subsumed by '{}'",
                        source_file, rule_id, clause, specific_ref, dir_ref
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} composite rules have overlapping all:/any: conditions",
                overlapping.len()
            ));
        }
    })
}

/// Validate: string vs raw type collisions (same pattern at same criticality)
/// These should be merged to just `raw` (which is broader)
pub(super) fn string_content_collisions<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let collisions = find_string_content_collisions(input.trait_definitions);
    report(move |warnings| {
        if !collisions.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} trait pairs have deprecated string_value/raw type collisions",
                collisions.len()
            );
            eprintln!(
                "   When both deprecated `type: text` and `type: raw` exist for the same pattern,"
            );
            eprintln!(
                "   remove the legacy `string_value` rule. Keep `raw` only for byte-precise matching; otherwise prefer a single `text` rule:\n"
            );
            for (string_id, raw_id, pattern) in &collisions {
                let string_source = input
                    .rule_source_files
                    .get(string_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(string_source, string_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: string trait '{}' duplicates raw trait '{}'",
                        string_source, line, string_id, raw_id
                    );
                } else {
                    eprintln!(
                        "   {}: string trait '{}' duplicates raw trait '{}'",
                        string_source, string_id, raw_id
                    );
                }
                eprintln!("      Pattern: {}", pattern);
                eprintln!("      Action: Delete the string trait, keep the raw trait\n");
            }
            warnings.push(format!(
                "{} string/raw type collisions (merge to raw only)",
                collisions.len()
            ));
        }
    })
}

/// Validate: traits identical but for their scope -- `for:`, `platforms:`
/// or both -- should be one trait covering the union.
/// The composite counterpart: identical evidence, overlapping scope.
pub(super) fn overlapping_scope_duplicates<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let scope_dups = if enabled("overlapping-scope-duplicate") {
        find_overlapping_scope_duplicates(input.composite_rules)
    } else {
        Vec::new()
    };
    report(move |warnings| {
        if !crate::validation_controls::is_validator_disabled("overlapping-scope-duplicate")
            && !scope_dups.is_empty()
        {
            let contradictions = scope_dups.iter().filter(|d| !d.4).count();
            eprintln!(
                "\n❌ ERROR: {} composite pairs carry identical evidence with overlapping scope",
                scope_dups.len()
            );
            eprintln!("   Both fire on any file the two scopes share, so one set of facts");
            eprintln!("   produces two findings. Merge them into one rule covering the union.");
            if contradictions > 0 {
                eprintln!(
                    "   {contradictions} of them disagree on crit:, which is worse than a duplicate --"
                );
                eprintln!("   the same legs cannot be hostile in one file and suspicious in");
                eprintln!("   another. Settle the verdict, then merge.\n");
            } else {
                eprintln!();
            }
            for (a, b, ca, cb, same) in &scope_dups {
                let note = if *same { "same crit" } else { "CRIT DISAGREES" };
                eprintln!("   {note}: '{a}' ({ca}) vs '{b}' ({cb})");
            }
            eprintln!();
            warnings.push(format!(
                "{} composite pairs duplicate evidence across overlapping scopes",
                scope_dups.len()
            ));
        }
    })
}

/// Traits whose logic is identical and that differ only in `for:` or
/// `platforms:` should be one trait.
pub(super) fn for_only_duplicates<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let for_duplicates = find_for_only_duplicates(input.trait_definitions);
    report(move |warnings| {
        if !for_duplicates.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} trait groups differ only in scope (`for:`/`platforms:`)",
                for_duplicates.len()
            );
            eprintln!(
                "   These traits have identical logic -- same matcher, criticality, confidence,"
            );
            eprintln!("   bounds and exclusions -- and differ only in which files or platforms");
            eprintln!("   they are scoped to. Both fire on anything the scopes share.\n");
            eprintln!("   Merge them into one trait covering the union of the scopes:\n");
            for (trait_ids, _pattern) in &for_duplicates {
                // Find source file for the first trait
                let first_id = &trait_ids[0];
                let source = input
                    .rule_source_files
                    .get(first_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, first_id);
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: {}", source, line, trait_ids.join(", "));
                } else {
                    eprintln!("   {}: {}", source, trait_ids.join(", "));
                }
                eprintln!(
                    "      Action: merge into one trait with the combined `for:`/`platforms:`\n"
                );
            }
            warnings.push(format!(
                "{} trait groups differ only in scope (should be merged)",
                for_duplicates.len()
            ));
        }
    })
}

/// Validate: inline whole-file content matchers duplicating a named
/// trait, or repeated inline across files. Invisible to every other
/// duplicate check, so a literal can be named once and inlined again
/// with nothing noticing the two must move together.
pub(super) fn inline_content_duplicates<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let inline_dups =
        find_inline_content_duplicates(input.trait_definitions, input.composite_rules);
    report(move |warnings| {
        if !inline_dups.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} inline content matchers duplicate an existing matcher",
                inline_dups.len()
            );
            eprintln!(
                "   An inline matcher in `unless:`/`downgrade:` is invisible to the other\n                        duplicate checks, so it drifts from the copy it was taken from:\n"
            );
            for (rule_id, clause, what, advice) in &inline_dups {
                let source = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                if let Some(line) = find_line_number(source, rule_id) {
                    eprintln!("   {source}:{line}: '{rule_id}' {clause}: {what}");
                } else {
                    eprintln!("   {source}: '{rule_id}' {clause}: {what}");
                }
                eprintln!("      {advice}");
            }
            eprintln!();
            warnings.push_id(
                "inline-content-duplicate",
                format!(
                    "{} inline content matchers duplicate an existing matcher",
                    inline_dups.len()
                ),
            );
        }
    })
}

/// Shared matcher bodies require review of the effective predicates.
pub(super) fn atomic_logic_duplicates<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let logic_duplicates = find_atomic_logic_duplicates(input.trait_definitions);
    report(move |warnings| {
        if !logic_duplicates.is_empty() {
            eprintln!(
                "\n⚠️  WARNING: {} shared-matcher pairs need scope/verdict review",
                logic_duplicates.len()
            );
            eprintln!(
                "   Compare effective scopes, exclusions and verdicts before merging; scope unions can broaden detection:\n"
            );
            for (id_a, id_b, desc) in &logic_duplicates {
                let source_a = input
                    .rule_source_files
                    .get(id_a)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let source_b = input
                    .rule_source_files
                    .get(id_b)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_a = find_line_number(source_a, id_a);
                let line_b = find_line_number(source_b, id_b);

                let loc_a = if let Some(line) = line_a {
                    format!("{}:{}", source_a, line)
                } else {
                    source_a.to_string()
                };
                let loc_b = if let Some(line) = line_b {
                    format!("{}:{}", source_b, line)
                } else {
                    source_b.to_string()
                };

                eprintln!("   {} vs {}", id_a, id_b);
                eprintln!("      {}", loc_a);
                eprintln!("      {}", loc_b);
                eprintln!("      {}\n", desc);
            }
            warnings.push(format!(
                "{} shared-matcher pairs need scope/verdict review",
                logic_duplicates.len()
            ));
        }
    })
}

/// Validate: regex patterns that could be merged with alternation (case-only differences)
/// e.g., `nc\s+-e` and `NC\s+-e` -> `(nc|NC)\s+-e`
pub(super) fn alternation_merge_candidates<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let alternation_candidates =
        find_alternation_merge_candidates(input.trait_definitions, input.trait_source_files);
    report(move |warnings| {
        if !alternation_candidates.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} trait groups have regex patterns that should use alternation",
                alternation_candidates.len()
            );
            eprintln!(
                "   These traits have identical criticality and regex patterns where the first token differs only in case."
            );
            eprintln!("   Merge them into a single trait using alternation syntax:\n");
            for (trait_ids, _suffix, suggested) in &alternation_candidates {
                let first_id = &trait_ids[0];
                let source = input
                    .rule_source_files
                    .get(first_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, first_id);
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: {}", source, line, trait_ids.join(", "));
                } else {
                    eprintln!("   {}: {}", source, trait_ids.join(", "));
                }
                eprintln!("      Suggested regex: {}\n", suggested);
            }
            warnings.push(format!(
                "{} trait groups should use regex alternation",
                alternation_candidates.len()
            ));
        }
    })
}

/// Validate: `needs` value exceeds number of potential matches in `any:` (impossible to satisfy)
/// Directory references can match multiple traits, so we count potential matches
pub(super) fn impossible_needs<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let impossible_needs = find_impossible_needs(input.composite_rules, &input.all_trait_ids);
    report(move |warnings| {
        if !impossible_needs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have impossible `needs` values",
                impossible_needs.len()
            );
            eprintln!("   The `needs` value exceeds the number of potential matches in `any:`:\n");
            for (rule_id, needs, potential) in &impossible_needs {
                let source = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: '{}' has needs: {} but only {} potential matches",
                        source, line, rule_id, needs, potential
                    );
                } else {
                    eprintln!(
                        "   {}: '{}' has needs: {} but only {} potential matches",
                        source, rule_id, needs, potential
                    );
                }
            }
            eprintln!();
            warnings.push_id(
                "impossible-constraint",
                format!(
                    "{} composite rules have impossible `needs` values",
                    impossible_needs.len()
                ),
            );
        }
    })
}

/// Validate: size_min > size_max (impossible constraint)
pub(super) fn impossible_size_constraints<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let impossible_sizes =
        find_impossible_size_constraints(input.trait_definitions, input.composite_rules);
    report(move |warnings| {
        if !impossible_sizes.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} rules have impossible size constraints (size_min > size_max)",
                impossible_sizes.len()
            );
            for (id, min, max, is_composite) in &impossible_sizes {
                let kind = if *is_composite { "composite" } else { "trait" };
                let source = input
                    .rule_source_files
                    .get(id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: {} '{}' has size_min: {} > size_max: {}",
                        source, line, kind, id, min, max
                    );
                } else {
                    eprintln!(
                        "   {}: {} '{}' has size_min: {} > size_max: {}",
                        source, kind, id, min, max
                    );
                }
            }
            eprintln!();
            warnings.push_id(
                "impossible-constraint",
                format!(
                    "{} rules have impossible size constraints",
                    impossible_sizes.len()
                ),
            );
        }
    })
}

/// Validate: count_min > count_max (impossible constraint)
pub(super) fn impossible_count_constraints<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let impossible_counts = find_impossible_count_constraints(input.trait_definitions);
    report(move |warnings| {
        if !impossible_counts.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} traits have impossible count constraints (count_min > count_max)",
                impossible_counts.len()
            );
            for (id, min, max) in &impossible_counts {
                let source = input
                    .rule_source_files
                    .get(id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: '{}' has count_min: {} > count_max: {}",
                        source, line, id, min, max
                    );
                } else {
                    eprintln!(
                        "   {}: '{}' has count_min: {} > count_max: {}",
                        source, id, min, max
                    );
                }
            }
            eprintln!();
            warnings.push_id(
                "impossible-constraint",
                format!(
                    "{} traits have impossible count constraints",
                    impossible_counts.len()
                ),
            );
        }
    })
}

/// Validate: `all:`/`any:` empty, or absent altogether
pub(super) fn empty_condition_clauses<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let empty_clauses = find_empty_condition_clauses(input.composite_rules);
    report(move |warnings| {
        if !empty_clauses.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have empty or missing condition clauses",
                empty_clauses.len()
            );
            eprintln!(
                "   A composite draws its evidence from `all:`/`any:`. An empty \
     clause fires on everything; an absent one fires on nothing.\n"
            );
            for (rule_id, clause_type) in &empty_clauses {
                let source = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let detail = if *clause_type == MISSING_CONDITIONS {
                    "has no `all:` or `any:` conditions, so it can never fire \
         (filter fields and `unless:` do not supply evidence; a rule whose \
         whole predicate is a size/type filter belongs in `traits:`)"
                        .to_string()
                } else {
                    format!("has empty `{clause_type}:` clause")
                };
                if let Some(line) = find_line_number(source, rule_id) {
                    eprintln!("   {source}:{line}: '{rule_id}' {detail}");
                } else {
                    eprintln!("   {source}: '{rule_id}' {detail}");
                }
            }
            eprintln!();
            warnings.push_id(
                "malformed-condition",
                format!(
                    "{} composite rules have empty or missing condition clauses",
                    empty_clauses.len()
                ),
            );
        }
    })
}

/// Validate: `needs` without `any:` (silently ignored, likely authoring mistake)
pub(super) fn needs_without_any<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let needs_without_any = find_needs_without_any(input.composite_rules);
    report(move |warnings| {
        if !needs_without_any.is_empty() {
            eprintln!(
                "\n⚠️  WARNING: {} composite rules have `needs` without `any:`",
                needs_without_any.len()
            );
            eprintln!(
                "   `needs` only applies to `any:` conditions and is ignored on `all:`-only rules:\n"
            );
            for rule_id in &needs_without_any {
                let source = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, rule_id);
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: '{}'", source, line, rule_id);
                } else {
                    eprintln!("   {}: '{}'", source, rule_id);
                }
            }
            eprintln!();
            warnings.push_id(
                "malformed-condition",
                format!(
                    "{} composite rules have `needs` without `any:`",
                    needs_without_any.len()
                ),
            );
        }
    })
}

/// Validate: needs: 0 vacuously matches (any: clause is meaningless)
pub(super) fn needs_zero<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let needs_zero = find_needs_zero(input.composite_rules);
    report(move |warnings| {
        if !needs_zero.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have `needs: 0`",
                needs_zero.len()
            );
            eprintln!("   `needs: 0` vacuously matches regardless of `any:` conditions:\n");
            for rule_id in &needs_zero {
                let source = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, "needs:");
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: '{}'", source, line, rule_id);
                } else {
                    eprintln!("   {}: '{}'", source, rule_id);
                }
            }
            eprintln!();
            warnings.push_id(
                "malformed-condition",
                format!(
                    "{} composite rules have `needs: 0` (vacuous match)",
                    needs_zero.len()
                ),
            );
        }
    })
}

/// Validate: hex patterns must be parseable by the matcher. A
/// malformed pattern would otherwise load and degrade to a
/// runtime no-match, silently disabling the trait.
pub(super) fn invalid_hex_patterns<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let invalid_hex = find_invalid_hex_patterns(input.trait_definitions);
    report(move |warnings| {
        if !invalid_hex.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} hex pattern(s) cannot be parsed by cleave\n",
                invalid_hex.len()
            );
            for (id, pattern, error) in &invalid_hex {
                let source = input
                    .rule_source_files
                    .get(id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: '{}' (hex: \"{}\"): {}",
                        source, line, id, pattern, error
                    );
                } else {
                    eprintln!("   {}: '{}' (hex: \"{}\"): {}", source, id, pattern, error);
                }
            }
            eprintln!();
            warnings.push_id(
                "invalid-hex-pattern",
                format!(
                    "{} hex pattern(s) cannot be parsed by cleave",
                    invalid_hex.len()
                ),
            );
        }
    })
}

/// Validate: string/content conditions with no search pattern
pub(super) fn missing_search_patterns<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let missing_patterns = find_missing_search_patterns(input.trait_definitions);
    report(move |warnings| {
        if !missing_patterns.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} traits have no search pattern",
                missing_patterns.len()
            );
            eprintln!(
                "   String/content conditions need at least one of: exact, substr, regex, word:\n"
            );
            for id in &missing_patterns {
                let source = input
                    .rule_source_files
                    .get(id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, id);
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: '{}'", source, line, id);
                } else {
                    eprintln!("   {}: '{}'", source, id);
                }
            }
            eprintln!();
            warnings.push_id(
                "no-search-pattern",
                format!("{} traits have no search pattern", missing_patterns.len()),
            );
        }
    })
}

/// Validate: patterns too short to be useful (1-2 concrete chars/bytes)
pub(super) fn too_short_patterns<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let too_short = find_too_short_patterns(input.trait_definitions);
    report(move |warnings| {
        if !too_short.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} traits have patterns too short to be useful (<3 concrete chars/bytes)",
                too_short.len()
            );
            eprintln!("   Short patterns must bound their search space (~8KB ideal). Add one of:");
            eprintln!("   - offset or small closed offset_range (absolute file position)");
            eprintln!("   - section + section_offset or small closed section_offset_range");
            eprintln!("   - section + size_max (bound total file size)\n");
            for (id, pattern, kind) in &too_short {
                let source = input
                    .rule_source_files
                    .get(id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: '{}' ({}: \"{}\")",
                        source, line, id, kind, pattern
                    );
                } else {
                    eprintln!("   {}: '{}' ({}: \"{}\")", source, id, kind, pattern);
                }
            }
            eprintln!();
            warnings.push_id(
                "no-search-pattern",
                format!(
                    "{} traits have patterns too short (<3 concrete chars/bytes)",
                    too_short.len()
                ),
            );
        }
    })
}

/// Validate: `not:` only used with `regex:` patterns
pub(super) fn invalid_not_usage<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let invalid_not = find_invalid_not_usage(input.trait_definitions);
    report(move |warnings| {
        if !invalid_not.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} traits use `not:` without `regex:`",
                invalid_not.len()
            );
            eprintln!(
                "   `not:` filters individual matches and only makes sense with `regex:` patterns:\n"
            );
            for msg in &invalid_not {
                eprintln!("   {}", msg);
            }
            eprintln!();
            warnings.push_id(
                "malformed-condition",
                format!("{} traits use `not:` without `regex:`", invalid_not.len()),
            );
        }
    })
}

/// Validate: text/raw length bounds require `regex:`
pub(super) fn length_bounds_without_regex<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let invalid_length = find_length_bounds_without_regex(input.trait_definitions);
    report(move |warnings| {
        if !invalid_length.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} traits use `length_min`/`length_max` without `regex:`",
                invalid_length.len()
            );
            eprintln!(
                "   length bounds constrain the regex match span; with exact/substr/word the match length is fixed by the pattern:\n"
            );
            for msg in &invalid_length {
                eprintln!("   {}", msg);
            }
            eprintln!();
            warnings.push_id(
                "malformed-condition",
                format!(
                    "{} traits use `length_min`/`length_max` without `regex:`",
                    invalid_length.len()
                ),
            );
        }
    })
}

/// Validate: length_min > length_max (impossible constraint)
pub(super) fn impossible_length_bounds<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let impossible_lengths = find_impossible_length_bounds(input.trait_definitions);
    report(move |warnings| {
        if !impossible_lengths.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} traits have impossible length bounds (length_min > length_max)",
                impossible_lengths.len()
            );
            for (id, min, max) in &impossible_lengths {
                let source = input
                    .rule_source_files
                    .get(id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: '{}' has length_min: {} > length_max: {}",
                        source, line, id, min, max
                    );
                } else {
                    eprintln!(
                        "   {}: '{}' has length_min: {} > length_max: {}",
                        source, id, min, max
                    );
                }
            }
            eprintln!();
            warnings.push_id(
                "impossible-constraint",
                format!(
                    "{} traits have impossible length bounds",
                    impossible_lengths.len()
                ),
            );
        }
    })
}

/// Validate: KV `exists` alongside value matcher is redundant
pub(super) fn kv_exists_with_matcher<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let kv_exists = find_kv_exists_with_matcher(input.trait_definitions, input.composite_rules);
    report(move |warnings| {
        if !kv_exists.is_empty() {
            eprintln!(
                "\n⚠ WARNING: {} rules have KV `exists` alongside a value matcher",
                kv_exists.len()
            );
            eprintln!("   `exists` is redundant when `exact`, `substr`, or `regex` is set:");
            eprintln!(
                "   - `exists: true` is implied (a value matcher requires the field to exist)"
            );
            eprintln!(
                "   - `exists: false` is contradictory (a non-existent field can't have a value)\n"
            );
            for rule_id in &kv_exists {
                let source = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, "exists:");
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: '{}'", source, line, rule_id);
                } else {
                    eprintln!("   {}: '{}'", source, rule_id);
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} rules have KV `exists` alongside a value matcher (redundant)",
                kv_exists.len()
            ));
        }
    })
}

/// Validate: none-only rules with proximity constraints (always fail silently)
pub(super) fn none_only_with_proximity<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let none_prox = find_none_only_with_proximity(input.composite_rules);
    report(move |warnings| {
        if !none_prox.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have proximity on none-only rules",
                none_prox.len()
            );
            eprintln!("   `near_lines`/`near_bytes` requires positive conditions (`all:`/`any:`).");
            eprintln!(
                "   A rule without positive conditions and with proximity can never match:\n"
            );
            for rule_id in &none_prox {
                let source = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                eprintln!("   {}: '{}'", source, rule_id);
            }
            eprintln!();
            warnings.push_id(
                "malformed-condition",
                format!(
                    "{} composite rules have proximity on none-only rules (can never match)",
                    none_prox.len()
                ),
            );
        }
    })
}

/// Validate: redundant `needs: 1` when only `any:` exists
pub(super) fn redundant_needs_one<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let redundant_needs = find_redundant_needs_one(input.composite_rules);
    report(move |warnings| {
        if !redundant_needs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules have redundant `needs: 1`",
                redundant_needs.len()
            );
            eprintln!("   `needs: 1` is the default when only `any:` exists - remove it:\n");
            for rule_id in &redundant_needs {
                let source = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, rule_id);
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: '{}'", source, line, rule_id);
                } else {
                    eprintln!("   {}: '{}'", source, rule_id);
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} composite rules have redundant `needs: 1`",
                redundant_needs.len()
            ));
        }
    })
}

fn directory_trait_members<'a>(
    ids: impl Iterator<Item = &'a String>,
) -> HashMap<String, HashSet<String>> {
    let mut members: HashMap<String, HashSet<String>> = HashMap::new();
    for id in ids {
        if let Some((directory, _)) = id.split_once("::") {
            for ancestor in Path::new(directory).ancestors() {
                if !ancestor.as_os_str().is_empty() {
                    members
                        .entry(ancestor.to_string_lossy().into_owned())
                        .or_default()
                        .insert(id.clone());
                }
            }
        }
    }
    members
}

#[cfg(test)]
mod tests {

    #[test]
    fn directory_inventory_includes_descendants_without_prefix_siblings() {
        let ids: Vec<String> = ["item::broad", "item/key::specific", "item-else::sibling"]
            .into_iter()
            .map(String::from)
            .collect();
        let members = super::directory_trait_members(ids.iter());
        assert_eq!(members["item"].len(), 2);
        assert!(members["item"].contains("item::broad"));
        assert!(members["item"].contains("item/key::specific"));
        assert_eq!(members["item/key"].len(), 1);
        assert_eq!(members["item-else"].len(), 1);
    }
}
