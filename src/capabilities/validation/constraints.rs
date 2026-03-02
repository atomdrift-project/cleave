//! Logic constraint validation.
//!
//! This module validates logical constraints in rules, detecting impossible
//! or contradictory configurations that would make rules unsatisfiable.

use crate::composite_rules::{CompositeTrait, Condition, TraitDefinition};

/// Find composite rules where `needs` exceeds the number of possible matching items in `any:`.
///
/// This accounts for directory references that can match multiple traits.
/// For example, `{ id: well-known/malware/stealer/amos }` matches ALL traits in that directory,
/// so a single entry can represent many potential matches.
///
/// Returns: `Vec<(rule_id, needs_value, potential_matches)>`
#[must_use]
pub(crate) fn find_impossible_needs(
    composite_rules: &[CompositeTrait],
    all_trait_ids: &[String],
) -> Vec<(String, usize, usize)> {
    let mut violations = Vec::new();

    for rule in composite_rules {
        if let (Some(needs), Some(any_items)) = (rule.needs, rule.any.as_ref()) {
            // Calculate potential matches, accounting for directory references
            let potential_matches = count_potential_matches(any_items, all_trait_ids);

            if needs > potential_matches {
                violations.push((rule.id.clone(), needs, potential_matches));
            }
        }
    }

    violations
}

/// Count the potential number of trait matches for a list of conditions.
///
/// - Specific trait references (with `::`) count as 1
/// - Directory references (with `/` but no `::`) count as the number of traits in that directory
/// - Non-trait conditions count as 1
fn count_potential_matches(conditions: &[Condition], all_trait_ids: &[String]) -> usize {
    let mut total = 0;

    for condition in conditions {
        if let Condition::Trait { id } = condition {
            if id.contains("::") {
                // Specific trait reference: counts as 1
                total += 1;
            } else if id.contains('/') {
                // Directory reference: count traits matching this prefix
                let prefix_new = format!("{}::", id);
                let prefix_legacy = format!("{}/", id);
                let matching_count = all_trait_ids
                    .iter()
                    .filter(|t| t.starts_with(&prefix_new) || t.starts_with(&prefix_legacy))
                    .count();
                // If no traits found, still count as 1 (might be a forward reference or typo)
                total += matching_count.max(1);
            } else {
                // Short name reference: counts as 1
                total += 1;
            }
        } else {
            // Non-trait conditions (inline conditions) count as 1
            total += 1;
        }
    }

    total
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
        if let (Some(min), Some(max)) = (t.size_min, t.size_max) {
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
        // count_min and count_max are now at trait level on TraitDefinition
        if let (Some(min), Some(max)) = (t.count_min, t.count_max) {
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
        let has_pattern = match &t.r#if {
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
        let Condition::Trait { id: ref_id } = &t.r#if else {
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
        let has_filters = t.count_min.is_some()
            || t.count_max.is_some()
            || t.size_min.is_some()
            || t.size_max.is_some()
            || t.per_kb_min.is_some()
            || t.per_kb_max.is_some();

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

/// Find traits/rules with excessive unless: and downgrade: clauses combined.
///
/// A rule with 8 or more combined skip/downgrade conditions likely has poor precision
/// and should be improved rather than patched with exceptions.
///
/// Returns: `Vec<(id, unless_count, downgrade_count, is_composite)>`
#[must_use]
pub(crate) fn find_excessive_skip_conditions(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, usize, usize, bool)> {
    const MAX_COMBINED: usize = 8;
    let mut violations = Vec::new();

    for t in trait_definitions {
        let unless_count = t.unless.as_ref().map_or(0, Vec::len);
        let downgrade_count = t.downgrade.as_ref().map_or(0, |d| {
            d.any.as_ref().map_or(0, Vec::len)
                + d.all.as_ref().map_or(0, Vec::len)
                + d.none.as_ref().map_or(0, Vec::len)
        });

        if unless_count + downgrade_count >= MAX_COMBINED {
            violations.push((t.id.clone(), unless_count, downgrade_count, false));
        }
    }

    for r in composite_rules {
        let unless_count = r.unless.as_ref().map_or(0, Vec::len);
        let downgrade_count = r.downgrade.as_ref().map_or(0, |d| {
            d.any.as_ref().map_or(0, Vec::len)
                + d.all.as_ref().map_or(0, Vec::len)
                + d.none.as_ref().map_or(0, Vec::len)
        });

        if unless_count + downgrade_count >= MAX_COMBINED {
            violations.push((r.id.clone(), unless_count, downgrade_count, true));
        }
    }

    violations
}

/// Find component traits that are never referenced by any composite rule or atomic trait.
///
/// Component traits (`crit: component`) are building blocks that should only exist to be
/// referenced by composite rules or by other traits via `if: id:` form. If a component
/// isn't referenced anywhere, it's "orphaned" and serves no purpose.
///
/// Returns: `Vec<(trait_id, source_file)>`
#[must_use]
pub(crate) fn find_orphaned_components(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    trait_source_files: &std::collections::HashMap<String, String>,
) -> Vec<(String, String)> {
    use crate::types::Criticality;
    use std::collections::HashSet;

    // Collect all component trait IDs
    let component_ids: HashSet<&str> = trait_definitions
        .iter()
        .filter(|t| t.crit == Criticality::Component)
        .map(|t| t.id.as_str())
        .collect();

    if component_ids.is_empty() {
        return Vec::new();
    }

    // Collect all trait references from composite rules
    let mut referenced_ids: HashSet<String> = HashSet::new();

    for rule in composite_rules {
        // Check all:, any:, none: clauses
        for conditions in [rule.all.as_ref(), rule.any.as_ref(), rule.none.as_ref()]
            .into_iter()
            .flatten()
        {
            for condition in conditions {
                if let Condition::Trait { id } = condition {
                    // Handle both specific references (with ::) and directory references
                    if id.contains("::") {
                        referenced_ids.insert(id.clone());
                    } else {
                        // Directory reference - mark all traits in that directory as referenced
                        let prefix = format!("{}::", id);
                        for component_id in &component_ids {
                            if component_id.starts_with(&prefix) {
                                referenced_ids.insert((*component_id).to_string());
                            }
                        }
                    }
                }
            }
        }

        // Also check unless: and downgrade: conditions
        if let Some(unless_conditions) = &rule.unless {
            for condition in unless_conditions {
                if let Condition::Trait { id } = condition {
                    if id.contains("::") {
                        referenced_ids.insert(id.clone());
                    } else {
                        let prefix = format!("{}::", id);
                        for component_id in &component_ids {
                            if component_id.starts_with(&prefix) {
                                referenced_ids.insert((*component_id).to_string());
                            }
                        }
                    }
                }
            }
        }

        if let Some(downgrade) = &rule.downgrade {
            for conditions in [downgrade.any.as_ref(), downgrade.all.as_ref()]
                .into_iter()
                .flatten()
            {
                for condition in conditions {
                    if let Condition::Trait { id } = condition {
                        if id.contains("::") {
                            referenced_ids.insert(id.clone());
                        } else {
                            let prefix = format!("{}::", id);
                            for component_id in &component_ids {
                                if component_id.starts_with(&prefix) {
                                    referenced_ids.insert((*component_id).to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Collect trait references from atomic traits (if: id: form)
    for trait_def in trait_definitions {
        if let Condition::Trait { id } = &trait_def.r#if {
            if id.contains("::") {
                referenced_ids.insert(id.clone());
            } else if id.contains('/') {
                // Directory reference
                let prefix = format!("{}::", id);
                for component_id in &component_ids {
                    if component_id.starts_with(&prefix) {
                        referenced_ids.insert((*component_id).to_string());
                    }
                }
            }
        }

        // Also check unless: and downgrade: conditions on atomic traits
        if let Some(unless_conditions) = &trait_def.unless {
            for condition in unless_conditions {
                if let Condition::Trait { id } = condition {
                    if id.contains("::") {
                        referenced_ids.insert(id.clone());
                    } else {
                        let prefix = format!("{}::", id);
                        for component_id in &component_ids {
                            if component_id.starts_with(&prefix) {
                                referenced_ids.insert((*component_id).to_string());
                            }
                        }
                    }
                }
            }
        }

        if let Some(downgrade) = &trait_def.downgrade {
            for conditions in [downgrade.any.as_ref(), downgrade.all.as_ref()]
                .into_iter()
                .flatten()
            {
                for condition in conditions {
                    if let Condition::Trait { id } = condition {
                        if id.contains("::") {
                            referenced_ids.insert(id.clone());
                        } else {
                            let prefix = format!("{}::", id);
                            for component_id in &component_ids {
                                if component_id.starts_with(&prefix) {
                                    referenced_ids.insert((*component_id).to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Find orphaned components (not in referenced set)
    let mut orphans: Vec<(String, String)> = component_ids
        .into_iter()
        .filter(|id| !referenced_ids.contains(*id))
        .map(|id| {
            let source = trait_source_files
                .get(id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            (id.to_string(), source)
        })
        .collect();

    // Sort for deterministic output
    orphans.sort_by(|a, b| a.0.cmp(&b.0));

    orphans
}
