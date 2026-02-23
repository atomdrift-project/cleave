//! Composite rule specific validation.
//!
//! This module provides validation for composite rules, including checking
//! that composite rules only contain trait references (not inline primitives),
//! auto-prefixing trait references, and detecting redundant patterns.

use crate::composite_rules::{CompositeTrait, Condition};
use std::collections::HashMap;

/// Validate that a composite rule only contains trait references, not inline conditions.
///
/// Composite rules in objectives/ should only reference traits from micro-behaviors/,
/// not define their own inline patterns. This ensures clean separation between
/// atomic traits (micro-behaviors/) and high-level objectives (objectives/).
///
/// Returns a vector of error messages for violations found.
#[must_use]
pub(crate) fn validate_composite_trait_only(
    rule: &CompositeTrait,
    source_file: &str,
) -> Vec<String> {
    let mut errors = Vec::new();

    fn check_conditions(
        conditions: &[Condition],
        rule_id: &str,
        field_name: &str,
        source_file: &str,
        errors: &mut Vec<String>,
    ) {
        for cond in conditions {
            if !cond.is_trait_reference() {
                errors.push(format!(
                    "{}: Composite rule '{}' has inline '{}' in {}. Convert to a trait.",
                    source_file,
                    rule_id,
                    cond.type_name(),
                    field_name
                ));
            }
        }
    }

    if let Some(ref c) = rule.all {
        check_conditions(c, &rule.id, "all", source_file, &mut errors);
    }
    if let Some(ref c) = rule.any {
        check_conditions(c, &rule.id, "any", source_file, &mut errors);
    }
    if let Some(ref c) = rule.none {
        check_conditions(c, &rule.id, "none", source_file, &mut errors);
    }

    errors
}

/// Auto-prefix trait references in composite rule conditions.
///
/// If a trait reference doesn't contain '::' or '/', prepend the given prefix with ::.
/// This allows local trait references within a file to be automatically namespaced.
pub(crate) fn autoprefix_trait_refs(rule: &mut CompositeTrait, prefix: &str) {
    fn prefix_conditions(conditions: &mut [Condition], prefix: &str) {
        for cond in conditions {
            if let Condition::Trait { id } = cond {
                // Only prefix if ID doesn't already contain '::' or '/' (i.e., it's local to this file)
                if !id.contains("::") && !id.contains('/') {
                    *id = format!("{}::{}", prefix, id);
                }
            }
        }
    }

    if let Some(ref mut conditions) = rule.all {
        prefix_conditions(conditions, prefix);
    }
    if let Some(ref mut conditions) = rule.any {
        prefix_conditions(conditions, prefix);
    }
    if let Some(ref mut conditions) = rule.none {
        prefix_conditions(conditions, prefix);
    }
}

/// Collect all trait reference IDs from a composite rule's conditions.
///
/// Returns a vector of `(trait_id, rule_id)` tuples for all trait references
/// found in the rule's `all`, `any`, and `none` clauses.
#[must_use]
pub(crate) fn collect_trait_refs_from_rule(rule: &CompositeTrait) -> Vec<(String, String)> {
    let mut refs = Vec::new();

    fn collect_from_conditions(
        conditions: &[Condition],
        rule_id: &str,
        refs: &mut Vec<(String, String)>,
    ) {
        for cond in conditions {
            if let Condition::Trait { id } = cond {
                refs.push((id.clone(), rule_id.to_string()));
            }
        }
    }

    if let Some(ref conditions) = rule.all {
        collect_from_conditions(conditions, &rule.id, &mut refs);
    }
    if let Some(ref conditions) = rule.any {
        collect_from_conditions(conditions, &rule.id, &mut refs);
    }
    if let Some(ref conditions) = rule.none {
        collect_from_conditions(conditions, &rule.id, &mut refs);
    }

    refs
}

/// Find `any:` clauses that reference 4+ traits from the same external directory.
///
/// This suggests the rule should either:
/// - Use directory notation (e.g., `micro-behaviors/foo`) instead of listing individual traits
/// - Move to a different directory where the traits are local
///
/// Returns a list of `(rule_id, directory, trait_count, trait_ids)` for violations.
#[must_use]
pub(crate) fn find_redundant_any_refs(
    rule: &CompositeTrait,
) -> Vec<(String, String, usize, Vec<String>)> {
    let mut violations = Vec::new();

    let Some(ref any_conditions) = rule.any else {
        return violations;
    };

    // Extract the rule's own directory prefix
    let rule_dir = if let Some(idx) = rule.id.find("::") {
        &rule.id[..idx]
    } else if let Some(idx) = rule.id.rfind('/') {
        &rule.id[..idx]
    } else {
        ""
    };

    // Collect trait refs from `any:` and group by directory
    // ONLY count specific trait IDs (with ::), not directory references
    let mut dir_refs: HashMap<String, Vec<String>> = HashMap::new();

    for cond in any_conditions {
        if let Condition::Trait { id } = cond {
            // Only process specific trait references (with ::)
            // Skip directory references like "objectives/credential-access/browser/chromium"
            if let Some(idx) = id.find("::") {
                let trait_dir = &id[..idx];

                // Only flag external directories (different from rule's directory)
                // Skip metadata/ paths since those are auto-generated and can't use directory notation
                if trait_dir != rule_dir && !trait_dir.starts_with("metadata/") {
                    dir_refs
                        .entry(trait_dir.to_string())
                        .or_default()
                        .push(id.clone());
                }
            }
            // If no ::, it's a directory reference - these are always fine
        }
    }

    // Find directories with 4+ references
    for (dir, trait_ids) in dir_refs {
        if trait_ids.len() >= 4 {
            violations.push((rule.id.clone(), dir, trait_ids.len(), trait_ids));
        }
    }

    violations
}

/// Find composite rules that have only a single condition total across `any:` and `all:`.
///
/// A single-item `any:` or `all:` is redundant - the rule should just be that single trait.
/// Only flagged if there's no other meaningful clause (`none:`, `unless:`, `downgrade:`).
/// Also skips directory references since they can match multiple traits.
///
/// Returns `(rule_id, clause_type: "any" or "all", trait_id)`.
#[must_use]
pub(crate) fn find_single_item_clauses(
    rule: &CompositeTrait,
) -> Vec<(String, &'static str, String)> {
    let mut violations = Vec::new();

    // Skip rules with none:, unless:, or downgrade: clauses - they add meaningful conditions
    let has_none = rule.none.as_ref().is_some_and(|v| !v.is_empty());
    let has_unless = rule.unless.as_ref().is_some_and(|v| !v.is_empty());
    let has_downgrade = rule.downgrade.is_some();
    if has_none || has_unless || has_downgrade {
        return violations;
    }

    let any_count = rule.any.as_ref().map_or(0, std::vec::Vec::len);
    let all_count = rule.all.as_ref().map_or(0, std::vec::Vec::len);
    let total_count = any_count + all_count;

    // Only flag if there's exactly 1 condition total
    if total_count != 1 {
        return violations;
    }

    // Check which clause has the single item
    // Skip directory references (no :: separator) - they match multiple traits
    if any_count == 1 {
        if let Some(Condition::Trait { id }) = rule.any.as_ref().and_then(|v| v.first()) {
            // Only flag specific trait references (with ::), not directory references
            if id.contains("::") {
                violations.push((rule.id.clone(), "any", id.clone()));
            }
        }
    }

    if all_count == 1 {
        if let Some(Condition::Trait { id }) = rule.all.as_ref().and_then(|v| v.first()) {
            // Only flag specific trait references (with ::), not directory references
            if id.contains("::") {
                violations.push((rule.id.clone(), "all", id.clone()));
            }
        }
    }

    violations
}

/// Find composite rules where an `all:` or `any:` clause contains overlapping IDs.
///
/// Overlap occurs when one entry is a directory reference that is a prefix of another
/// specific trait reference in the same clause (e.g. `micro-behaviors/foo` subsumes `micro-behaviors/foo::bar`).
///
/// Returns a list of `(rule_id, clause_type, dir_ref, specific_ref)` for each overlap.
#[must_use]
pub(crate) fn find_overlapping_conditions(
    rule: &CompositeTrait,
) -> Vec<(String, &'static str, String, String)> {
    let mut violations = Vec::new();

    for (conditions, clause) in [(rule.all.as_deref(), "all"), (rule.any.as_deref(), "any")] {
        let Some(conditions) = conditions else {
            continue;
        };

        let dir_refs: Vec<&str> = conditions
            .iter()
            .filter_map(|c| {
                if let Condition::Trait { id } = c {
                    if !id.contains("::") {
                        Some(id.as_str())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        for cond in conditions {
            if let Condition::Trait { id } = cond {
                if let Some(idx) = id.find("::") {
                    let trait_dir = &id[..idx];
                    if let Some(&dir) = dir_refs.iter().find(|&&d| d == trait_dir) {
                        violations.push((rule.id.clone(), clause, dir.to_string(), id.clone()));
                    }
                }
            }
        }
    }

    violations
}
