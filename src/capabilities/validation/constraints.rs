//! Logic constraint validation.
//!
//! This module validates logical constraints in rules, detecting impossible
//! or contradictory configurations that would make rules unsatisfiable.

use crate::composite_rules::{CompositeTrait, Condition, TraitDefinition};

/// Find composite rules where `needs` exceeds the number of items in `any:`.
///
/// This makes the rule impossible to satisfy.
///
/// Returns: `Vec<(rule_id, needs_value, any_length)>`
#[must_use]
pub(crate) fn find_impossible_needs(
    composite_rules: &[CompositeTrait],
) -> Vec<(String, usize, usize)> {
    let mut violations = Vec::new();

    for rule in composite_rules {
        if let (Some(needs), Some(any_items)) = (rule.needs, rule.any.as_ref()) {
            if needs > any_items.len() {
                violations.push((rule.id.clone(), needs, any_items.len()));
            }
        }
    }

    violations
}

/// Find traits/rules with impossible size constraints (size_min > size_max).
///
/// Returns: `Vec<(id, size_min, size_max, is_composite)>`
#[must_use]
pub(crate) fn find_impossible_size_constraints(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, usize, usize, bool)> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        if let (Some(min), Some(max)) = (t.r#if.size_min, t.r#if.size_max) {
            if min > max {
                violations.push((t.id.clone(), min, max, false));
            }
        }
    }

    for r in composite_rules {
        if let (Some(min), Some(max)) = (r.size_min, r.size_max) {
            if min > max {
                violations.push((r.id.clone(), min, max, true));
            }
        }
    }

    violations
}

/// Find conditions with impossible count constraints (count_min > count_max).
///
/// Returns: `Vec<(trait_id, count_min, count_max)>`
#[must_use]
pub(crate) fn find_impossible_count_constraints(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, usize, usize)> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        // count_min and count_max are now at trait level in ConditionWithFilters
        if let (Some(min), Some(max)) = (t.r#if.count_min, t.r#if.count_max) {
            if min > max {
                violations.push((t.id.clone(), min, max));
            }
        }
    }

    violations
}

/// Find composite rules with empty `any:` or `all:` clauses that are the only condition.
///
/// An empty clause makes the rule either always match (empty all) or never match (empty any with needs > 0).
///
/// Returns: `Vec<(rule_id, clause_type)>`
#[must_use]
pub(crate) fn find_empty_condition_clauses(
    composite_rules: &[CompositeTrait],
) -> Vec<(String, &'static str)> {
    let mut violations = Vec::new();

    for rule in composite_rules {
        let all_empty = rule.all.as_ref().is_none_or(std::vec::Vec::is_empty);
        let any_empty = rule.any.as_ref().is_none_or(std::vec::Vec::is_empty);
        let none_empty = rule.none.as_ref().is_none_or(std::vec::Vec::is_empty);

        // Only flag if we have an explicit empty clause (Some([]))
        if let Some(all) = &rule.all {
            if all.is_empty() && any_empty && none_empty {
                violations.push((rule.id.clone(), "all"));
            }
        }

        if let Some(any) = &rule.any {
            if any.is_empty() && all_empty && none_empty {
                violations.push((rule.id.clone(), "any"));
            }
        }
    }

    violations
}

/// Find string/content conditions with no actual search pattern.
///
/// A condition needs at least one of: exact, substr, regex, word.
///
/// Returns: `Vec<trait_id>`
#[must_use]
pub(crate) fn find_missing_search_patterns(trait_definitions: &[TraitDefinition]) -> Vec<String> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        let has_pattern = match &t.r#if.condition {
            Condition::String {
                exact,
                substr,
                regex,
                word,
                ..
            }
            | Condition::Raw {
                exact,
                substr,
                regex,
                word,
                ..
            }
            | Condition::Encoded {
                exact,
                substr,
                regex,
                word,
                ..
            } => exact.is_some() || substr.is_some() || regex.is_some() || word.is_some(),
            Condition::Hex { pattern, .. } => !pattern.is_empty(),
            Condition::Symbol {
                exact,
                substr,
                regex,
                ..
            } => exact.is_some() || substr.is_some() || regex.is_some(),
            // Other condition types have required fields
            _ => true,
        };

        if !has_pattern {
            violations.push(t.id.clone());
        }
    }

    violations
}

/// Find traits that are pure aliases: `if: id: other-trait` with no added value.
///
/// A pure alias trait references another trait but adds no constraints:
/// - No filtering (count_min, count_max, section, offset, per_kb_*, size_*)
/// - No criticality change (same crit as referenced trait)
/// - No unless/not/downgrade modifiers
///
/// These should either add constraints or be removed in favor of direct references.
///
/// Returns: `Vec<(trait_id, referenced_trait_id)>`
#[must_use]
pub(crate) fn find_pure_alias_traits(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, String)> {
    use std::collections::HashMap;

    // Build a map of trait ID -> criticality for lookup
    let crit_map: HashMap<&str, &crate::types::Criticality> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), &t.crit))
        .collect();

    let mut violations = Vec::new();

    for t in trait_definitions {
        // Check if the condition is a trait reference
        let Condition::Trait { id: ref_id } = &t.r#if.condition else {
            continue;
        };

        // Must be a cross-trait reference (contains :: or /)
        if !ref_id.contains("::") && !ref_id.contains('/') {
            continue;
        }

        // Skip self-references (these are a different bug - circular reference)
        if ref_id == &t.id {
            continue;
        }

        // Check for any filtering constraints that add value
        let has_filters = t.r#if.count_min.is_some()
            || t.r#if.count_max.is_some()
            || t.r#if.size_min.is_some()
            || t.r#if.size_max.is_some()
            || t.r#if.per_kb_min.is_some()
            || t.r#if.per_kb_max.is_some();

        if has_filters {
            continue;
        }

        // Check for modifiers that add value
        let has_modifiers = t.unless.as_ref().is_some_and(|v| !v.is_empty())
            || t.not.as_ref().is_some_and(|v| !v.is_empty())
            || t.downgrade.is_some();

        if has_modifiers {
            continue;
        }

        // Check if criticality differs from referenced trait
        // If referenced trait isn't found, assume it differs (don't flag)
        if let Some(ref_crit) = crit_map.get(ref_id.as_str()) {
            if &t.crit != *ref_crit {
                continue; // Criticality change adds value
            }
        } else {
            continue; // Referenced trait not found locally, can't compare
        }

        violations.push((t.id.clone(), ref_id.clone()));
    }

    violations
}

/// Find composite rules with redundant `needs: 1` when only `any:` clause exists.
///
/// `needs: 1` is the default, so specifying it explicitly adds noise.
///
/// Returns: `Vec<rule_id>`
#[must_use]
pub(crate) fn find_redundant_needs_one(composite_rules: &[CompositeTrait]) -> Vec<String> {
    let mut violations = Vec::new();

    for rule in composite_rules {
        // Check if needs is explicitly set to 1
        if rule.needs != Some(1) {
            continue;
        }

        // Check if only `any:` clause exists (no all:, no none:)
        let has_all = rule.all.as_ref().is_some_and(|v| !v.is_empty());
        let has_none = rule.none.as_ref().is_some_and(|v| !v.is_empty());
        let has_any = rule.any.as_ref().is_some_and(|v| !v.is_empty());

        if has_any && !has_all && !has_none {
            violations.push(rule.id.clone());
        }
    }

    violations
}
