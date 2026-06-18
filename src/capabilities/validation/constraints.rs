//! Logic constraint validation.
//!
//! This module validates logical constraints in rules, detecting impossible
//! or contradictory configurations that would make rules unsatisfiable.

use std::collections::{HashMap, HashSet};

use crate::capabilities::models::{RawCompositeRule, RawTraitDefinition, TraitDefaults};
use crate::capabilities::validation::shared::is_limited_byte_range;
use crate::composite_rules::{
    CompositeTrait, Condition, DowngradeConditions, FileType, KvQuery, TraitDefinition,
};
use crate::composite_rules::{
    EncodedQuery, HexQuery, LiteralQuery, PathQuery, RawQuery, SectionQuery, SymbolQuery, TextQuery,
};

/// Compare two slices of strings in a case-insensitive, order-independent way.
fn vec_values_equal(a: &[String], b: &[String]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut sa: Vec<String> = a.iter().map(|s| s.to_ascii_lowercase()).collect();
    let mut sb: Vec<String> = b.iter().map(|s| s.to_ascii_lowercase()).collect();
    sa.sort_unstable();
    sb.sort_unstable();
    sa == sb
}

/// If all values are `Some` and equal, return the common value; otherwise `None`.
fn all_same_str<'a>(values: &[Option<&'a str>]) -> Option<&'a str> {
    let first = values.first().and_then(|v| *v)?;
    values
        .iter()
        .skip(1)
        .all(|v| *v == Some(first))
        .then_some(first)
}

/// If all values are `Some` and element-wise equal (order-independent), return the common slice.
fn all_same_vec<'a>(values: &[Option<&'a [String]>]) -> Option<&'a [String]> {
    let first = values.first().and_then(|v| *v)?;
    values
        .iter()
        .skip(1)
        .all(|v| v.is_some_and(|other| vec_values_equal(first, other)))
        .then_some(first)
}

/// Per-file: flag traits/composites that explicitly repeat a value already set in file defaults.
///
/// When `platforms: [windows]` appears on a trait and the file already has
/// `defaults: platforms: [windows]`, the per-trait setting is redundant noise.
///
/// Returns: `Vec<(item_id, field_name)>`
#[must_use]
pub(crate) fn find_redundant_explicit_defaults(
    raw_traits: &[RawTraitDefinition],
    raw_composites: &[RawCompositeRule],
    defaults: &TraitDefaults,
) -> Vec<(String, &'static str)> {
    let mut violations = Vec::new();

    for t in raw_traits {
        if let (Some(def), Some(val)) = (&defaults.platforms, &t.platforms)
            && vec_values_equal(def, val)
        {
            violations.push((t.id.clone(), "platforms"));
        }
        if let (Some(def), Some(val)) = (&defaults.r#for, &t.file_types)
            && vec_values_equal(def, val)
        {
            violations.push((t.id.clone(), "for"));
        }
        if let (Some(def), Some(val)) = (&defaults.mbc, &t.mbc)
            && def == val
        {
            violations.push((t.id.clone(), "mbc"));
        }
        if let (Some(def), Some(val)) = (&defaults.attack, &t.attack)
            && def == val
        {
            violations.push((t.id.clone(), "attack"));
        }
    }

    for r in raw_composites {
        if let (Some(def), Some(val)) = (&defaults.platforms, &r.platforms)
            && vec_values_equal(def, val)
        {
            violations.push((r.id.clone(), "platforms"));
        }
        if let (Some(def), Some(val)) = (&defaults.r#for, &r.file_types)
            && vec_values_equal(def, val)
        {
            violations.push((r.id.clone(), "for"));
        }
        if let (Some(def), Some(val)) = (&defaults.mbc, &r.mbc)
            && def == val
        {
            violations.push((r.id.clone(), "mbc"));
        }
        if let (Some(def), Some(val)) = (&defaults.attack, &r.attack)
            && def == val
        {
            violations.push((r.id.clone(), "attack"));
        }
    }

    violations
}

/// Per-file: recommend `defaults:` when all items in a file share the same explicit value.
///
/// When every trait and composite in a YAML file explicitly sets the same value for
/// `platforms`, `for`, `mbc`, or `attack`, it should be set once in `defaults:` instead.
/// Only fires for 2+ items and only for fields not already covered by file defaults.
///
/// Returns: `Vec<(field_name, common_value)>`
#[must_use]
pub(crate) fn find_should_use_defaults(
    raw_traits: &[RawTraitDefinition],
    raw_composites: &[RawCompositeRule],
    defaults: &TraitDefaults,
) -> Vec<(&'static str, String)> {
    if raw_traits.len() + raw_composites.len() < 2 {
        return Vec::new();
    }

    let mut suggestions = Vec::new();

    if defaults.platforms.is_none() {
        let vals: Vec<Option<&[String]>> = raw_traits
            .iter()
            .map(|t| t.platforms.as_deref())
            .chain(raw_composites.iter().map(|r| r.platforms.as_deref()))
            .collect();
        if let Some(common) = all_same_vec(&vals) {
            suggestions.push(("platforms", format!("[{}]", common.join(", "))));
        }
    }

    if defaults.r#for.is_none() {
        let vals: Vec<Option<&[String]>> = raw_traits
            .iter()
            .map(|t| t.file_types.as_deref())
            .chain(raw_composites.iter().map(|r| r.file_types.as_deref()))
            .collect();
        if let Some(common) = all_same_vec(&vals) {
            suggestions.push(("for", format!("[{}]", common.join(", "))));
        }
    }

    if defaults.mbc.is_none() {
        let vals: Vec<Option<&str>> = raw_traits
            .iter()
            .map(|t| t.mbc.as_deref())
            .chain(raw_composites.iter().map(|r| r.mbc.as_deref()))
            .collect();
        if let Some(common) = all_same_str(&vals) {
            suggestions.push(("mbc", common.to_string()));
        }
    }

    if defaults.attack.is_none() {
        let vals: Vec<Option<&str>> = raw_traits
            .iter()
            .map(|t| t.attack.as_deref())
            .chain(raw_composites.iter().map(|r| r.attack.as_deref()))
            .collect();
        if let Some(common) = all_same_str(&vals) {
            suggestions.push(("attack", common.to_string()));
        }
    }

    suggestions
}

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
        if let (Some(min), Some(max)) = (t.size_min, t.size_max)
            && min > max
        {
            violations.push((t.id.clone(), min, max, false));
        }
    }

    for r in composite_rules {
        if let (Some(min), Some(max)) = (r.size_min, r.size_max)
            && min > max
        {
            violations.push((r.id.clone(), min, max, true));
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
        if let (Some(min), Some(max)) = (t.count_min, t.count_max)
            && min > max
        {
            violations.push((t.id.clone(), min, max));
        }
    }

    violations
}

/// Find composite rules with empty `any:` or `all:` clauses.
///
/// An empty `all:` vacuously matches everything (zero conditions all satisfied).
/// An empty `any:` with `needs > 0` can never match; with `needs: 0` or default it vacuously matches.
/// Both are authoring mistakes.
///
/// Returns: `Vec<(rule_id, clause_type)>`
#[must_use]
pub(crate) fn find_empty_condition_clauses(
    composite_rules: &[CompositeTrait],
) -> Vec<(String, &'static str)> {
    let mut violations = Vec::new();

    for rule in composite_rules {
        if let Some(all) = &rule.all
            && all.is_empty()
        {
            violations.push((rule.id.clone(), "all"));
        }

        if let Some(any) = &rule.any
            && any.is_empty()
        {
            violations.push((rule.id.clone(), "any"));
        }
    }

    violations
}

/// Find composite rules where `needs` is set but `any:` is absent.
///
/// The `needs` field only applies to `any:` conditions. When used with `all:`-only rules,
/// it is silently ignored, which likely indicates an authoring mistake.
///
/// Returns: `Vec<rule_id>`
#[must_use]
pub(crate) fn find_needs_without_any(composite_rules: &[CompositeTrait]) -> Vec<String> {
    let mut violations = Vec::new();

    for rule in composite_rules {
        if rule.needs.is_some() && rule.any.is_none() {
            violations.push(rule.id.clone());
        }
    }

    violations
}

/// Find composite rules with `needs: 0`, which vacuously matches regardless of `any:` conditions.
///
/// `needs: 0` means "require zero conditions to match", which is always satisfied and makes
/// the `any:` clause meaningless. This is an authoring mistake.
///
/// Returns: `Vec<rule_id>`
#[allow(dead_code)] // Used by binary target
#[must_use]
pub(crate) fn find_needs_zero(composite_rules: &[CompositeTrait]) -> Vec<String> {
    composite_rules
        .iter()
        .filter(|rule| rule.needs == Some(0))
        .map(|rule| rule.id.clone())
        .collect()
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
            Condition::Raw(RawQuery {
                exact,
                substr,
                regex,
                word,
                ..
            })
            | Condition::Text(TextQuery {
                exact,
                substr,
                regex,
                word,
                ..
            })
            | Condition::Literal(LiteralQuery {
                exact,
                substr,
                regex,
                word,
                ..
            })
            | Condition::Encoded(EncodedQuery {
                exact,
                substr,
                regex,
                word,
                ..
            }) => exact.is_some() || substr.is_some() || regex.is_some() || word.is_some(),
            Condition::Hex(HexQuery { pattern, .. }) => !pattern.is_empty(),
            Condition::Symbol(SymbolQuery {
                exact,
                substr,
                regex,
                ..
            })
            | Condition::Path(PathQuery {
                exact,
                substr,
                regex,
                ..
            }) => exact.is_some() || substr.is_some() || regex.is_some(),
            Condition::Section(SectionQuery {
                exact,
                substr,
                regex,
                word,
                length_min,
                length_max,
                entropy_min,
                entropy_max,
                readable,
                writable,
                executable,
                size_ratio_min,
                size_ratio_max,
                entropy_ratio_min,
                entropy_ratio_max,
                ..
            }) => {
                exact.is_some()
                    || substr.is_some()
                    || regex.is_some()
                    || word.is_some()
                    || length_min.is_some()
                    || length_max.is_some()
                    || entropy_min.is_some()
                    || entropy_max.is_some()
                    || readable.is_some()
                    || writable.is_some()
                    || executable.is_some()
                    || size_ratio_min.is_some()
                    || size_ratio_max.is_some()
                    || entropy_ratio_min.is_some()
                    || entropy_ratio_max.is_some()
            }
            // Other condition types (Trait, Yara, Syscall, Metrics, Kv, Ast)
            // have required fields enforced by the type system or deserializer.
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

        // Check if only `any:` clause exists (no all:)
        let has_all = rule.all.as_ref().is_some_and(|v| !v.is_empty());
        let has_any = rule.any.as_ref().is_some_and(|v| !v.is_empty());

        if has_any && !has_all {
            violations.push(rule.id.clone());
        }
    }

    violations
}

/// Count the `unless:` and `downgrade:` conditions declared directly on a single rule.
///
/// Returns `(unless_count, downgrade_count)`.
fn direct_suppression_counts(
    unless: Option<&Vec<Condition>>,
    downgrade: Option<&DowngradeConditions>,
) -> (usize, usize) {
    let unless_count = unless.map_or(0, Vec::len);
    let downgrade_count = downgrade.map_or(0, |d| {
        d.any.as_ref().map_or(0, Vec::len)
            + d.all.as_ref().map_or(0, Vec::len)
            + d.none.as_ref().map_or(0, Vec::len)
    });
    (unless_count, downgrade_count)
}

/// One node in a rule's suppression-expansion tree.
///
/// `count` is the number of *newly* counted distinct exceptions in this node's subtree
/// (first occurrence wins; a leaf or aggregator reached again contributes 0 and is
/// marked in `label`). A rule's expanded total is the sum of its top-level branches'
/// `count`s.
pub(crate) struct SuppressionBranch {
    /// The reference ID (or a marker like `(inline condition)` / `… (already counted)`).
    pub label: String,
    /// Distinct exceptions newly contributed by this subtree.
    pub count: usize,
    /// Expansion of an aggregator composite's matching legs; empty for a leaf.
    pub children: Vec<SuppressionBranch>,
}

impl SuppressionBranch {
    /// Append an indented rendering of this branch to `out`, one line per node as
    /// `<label> (<count>)`. Nested aggregators are recursed into; the leaf references
    /// directly under a node are collapsed into a single summary line so a branch with
    /// dozens of leaves stays readable.
    pub(crate) fn render(&self, depth: usize, out: &mut String) {
        use std::fmt::Write as _;
        let indent = "  ".repeat(depth);
        let _ = writeln!(out, "        {indent}{} ({})", self.label, self.count);

        let mut leaf_refs = 0usize;
        let mut leaf_counted = 0usize;
        for child in &self.children {
            if child.children.is_empty() {
                leaf_refs += 1;
                leaf_counted += child.count;
            } else {
                child.render(depth + 1, out);
            }
        }
        if leaf_refs > 0 {
            let _ = writeln!(
                out,
                "        {indent}  ({leaf_refs} leaf refs, {leaf_counted} counted)"
            );
        }
    }
}

/// Builds suppression-expansion trees while deduplicating across the whole rule:
/// each aggregator and each leaf is counted at its first occurrence only, which keeps
/// the per-node counts additive (a node's `count` equals the sum of its children's)
/// and bounds the walk to one visit per reference.
///
/// Only a *bespoke* aggregator — one used by a single rule — is expanded into its
/// underlying conditions. An aggregator reused by several rules is shared exception
/// infrastructure (e.g. `has-tests`, a benign-context cluster), so referencing it is
/// reuse, not hidden bloat; it counts as one, like a leaf.
struct SuppressionExpander<'a> {
    composite_map: &'a HashMap<&'a str, &'a CompositeTrait>,
    shared: &'a HashSet<&'a str>,
    seen_aggregators: HashSet<&'a str>,
    seen_leaves: HashSet<&'a str>,
}

impl<'a> SuppressionExpander<'a> {
    fn branch(&mut self, cond: &'a Condition) -> SuppressionBranch {
        let Condition::Trait { id } = cond else {
            // An inline (non-reference) condition is one bespoke exception.
            return SuppressionBranch {
                label: "(inline condition)".to_string(),
                count: 1,
                children: Vec::new(),
            };
        };
        let key = id.as_str();

        // Expand only bespoke aggregators; shared infrastructure and plain leaf/
        // directory references each count as one.
        let is_bespoke_aggregator =
            self.composite_map.contains_key(key) && !self.shared.contains(key);
        if is_bespoke_aggregator {
            if !self.seen_aggregators.insert(key) {
                return SuppressionBranch {
                    label: format!("{key} (already counted)"),
                    count: 0,
                    children: Vec::new(),
                };
            }
            let c = self.composite_map[key];
            let children: Vec<SuppressionBranch> = c
                .all
                .iter()
                .chain(c.any.iter())
                .flatten()
                .map(|leg| self.branch(leg))
                .collect();
            let count = children.iter().map(|b| b.count).sum();
            SuppressionBranch {
                label: key.to_string(),
                count,
                children,
            }
        } else if self.seen_leaves.insert(key) {
            SuppressionBranch {
                label: key.to_string(),
                count: 1,
                children: Vec::new(),
            }
        } else {
            SuppressionBranch {
                label: format!("{key} (dup)"),
                count: 0,
                children: Vec::new(),
            }
        }
    }
}

/// Expand a rule's `unless:`/`downgrade:` into a counted tree, returning the effective
/// exception total and the per-branch breakdown.
///
/// Authors can hide a large exception list behind a single reference:
/// `unless: [some-benign-context]`, where `some-benign-context` is a composite whose
/// `any:`/`all:` legs enumerate dozens of benign indicators. Counting the reference as
/// one would understate the real burden, so an entry that points at a composite is
/// expanded (recursively). A leaf or directory reference (no exact composite) counts as
/// one. Everything is deduplicated across the rule, so cycles terminate and a shared
/// aggregator is counted once.
fn expand_suppressions<'a>(
    unless: Option<&'a Vec<Condition>>,
    downgrade: Option<&'a DowngradeConditions>,
    composite_map: &'a HashMap<&'a str, &'a CompositeTrait>,
    shared: &'a HashSet<&'a str>,
) -> (usize, Vec<SuppressionBranch>) {
    let mut expander = SuppressionExpander {
        composite_map,
        shared,
        seen_aggregators: HashSet::new(),
        seen_leaves: HashSet::new(),
    };

    let downgrade_lists = downgrade
        .into_iter()
        .flat_map(|d| [d.any.as_ref(), d.all.as_ref(), d.none.as_ref()]);
    let conditions = unless
        .into_iter()
        .chain(downgrade_lists.flatten())
        .flatten();

    let branches: Vec<SuppressionBranch> = conditions.map(|cond| expander.branch(cond)).collect();
    let total = branches.iter().map(|b| b.count).sum();
    (total, branches)
}

/// A rule flagged for carrying too many `unless:`/`downgrade:` suppressions.
pub(crate) struct ExcessiveSkip {
    /// The offending rule's ID.
    pub id: String,
    /// True for a composite rule, false for an atomic trait.
    pub is_composite: bool,
    /// Number of `unless:`/`downgrade:` entries written literally on the rule.
    pub own: usize,
    /// Effective exception count once aggregator references in `unless:`/`downgrade:`
    /// are expanded to their underlying conditions.
    pub expanded: usize,
    /// Per-branch expansion of the rule's suppressions, for debugging where the weight
    /// comes from.
    pub branches: Vec<SuppressionBranch>,
}

/// Exceptions a single rule may write directly on itself.
const MAX_OWN_SUPPRESSIONS: usize = 8;

/// Effective exceptions a rule may carry once *bespoke* aggregator references in its
/// `unless:`/`downgrade:` are expanded. Higher than the direct cap because one
/// reference can legitimately stand in for a handful of related benign indicators;
/// this only catches rules whose true exception burden is runaway.
const MAX_AGGREGATE_SUPPRESSIONS: usize = 40;

/// A composite referenced as a building block by at least this many rules is treated as
/// shared infrastructure (counted as one), not an inlined exception subtree.
const SHARED_REFERENCE_THRESHOLD: usize = 2;

/// Tally each `Condition::Trait` reference in a clause into `counts`.
fn tally_clause<'a>(conds: Option<&'a Vec<Condition>>, counts: &mut HashMap<&'a str, usize>) {
    for cond in conds.into_iter().flatten() {
        if let Condition::Trait { id } = cond {
            *counts.entry(id.as_str()).or_default() += 1;
        }
    }
}

/// Find traits/rules with excessive `unless:`/`downgrade:` suppressions.
///
/// Both limits look only at a rule's own `unless:`/`downgrade:` — never at its `all:`/
/// `any:` matching conditions. Flagged on either:
///
/// - **Own** (`MAX_OWN_SUPPRESSIONS`, 8): `unless:`/`downgrade:` entries written
///   literally on the rule. A rule this heavily patched usually has poor precision and
///   should be improved rather than suppressed.
/// - **Expanded** (`MAX_AGGREGATE_SUPPRESSIONS`, 40): the effective exception count once
///   any `unless:`/`downgrade:` entry that references a *bespoke* (single-use) aggregator
///   composite is expanded to its underlying conditions. This catches a large exception
///   list hidden behind one reference. Leaf/directory references — and aggregators reused
///   by several rules (shared infrastructure like a benign-context cluster) — each count
///   as one, so reuse is not mistaken for bloat.
#[must_use]
pub(crate) fn find_excessive_skip_conditions<'a>(
    trait_definitions: &'a [TraitDefinition],
    composite_rules: &'a [CompositeTrait],
) -> Vec<ExcessiveSkip> {
    let composite_map: HashMap<&'a str, &'a CompositeTrait> =
        composite_rules.iter().map(|r| (r.id.as_str(), r)).collect();

    // Count how often each composite is referenced across all rules (any clause). A
    // composite reused by several rules is shared infrastructure, so the expander stops
    // at it instead of inlining its whole subtree.
    let mut ref_counts: HashMap<&'a str, usize> = HashMap::new();
    for t in trait_definitions {
        if let Condition::Trait { id } = &t.r#if {
            *ref_counts.entry(id.as_str()).or_default() += 1;
        }
        tally_clause(t.unless.as_ref(), &mut ref_counts);
        for dg in t.downgrade.iter() {
            tally_clause(dg.any.as_ref(), &mut ref_counts);
            tally_clause(dg.all.as_ref(), &mut ref_counts);
            tally_clause(dg.none.as_ref(), &mut ref_counts);
        }
    }
    for r in composite_rules {
        tally_clause(r.all.as_ref(), &mut ref_counts);
        tally_clause(r.any.as_ref(), &mut ref_counts);
        tally_clause(r.unless.as_ref(), &mut ref_counts);
        for dg in r.downgrade.iter() {
            tally_clause(dg.any.as_ref(), &mut ref_counts);
            tally_clause(dg.all.as_ref(), &mut ref_counts);
            tally_clause(dg.none.as_ref(), &mut ref_counts);
        }
    }
    let shared: HashSet<&'a str> = ref_counts
        .iter()
        .filter(|&(_, &n)| n >= SHARED_REFERENCE_THRESHOLD)
        .map(|(&k, _)| k)
        .collect();

    let mut violations = Vec::new();

    let mut flag = |id: &'a str,
                    unless: Option<&'a Vec<Condition>>,
                    downgrade: Option<&'a DowngradeConditions>,
                    is_composite: bool| {
        let (u, d) = direct_suppression_counts(unless, downgrade);
        let own = u + d;
        let (expanded, branches) = expand_suppressions(unless, downgrade, &composite_map, &shared);
        if own >= MAX_OWN_SUPPRESSIONS || expanded >= MAX_AGGREGATE_SUPPRESSIONS {
            violations.push(ExcessiveSkip {
                id: id.to_string(),
                is_composite,
                own,
                expanded,
                branches,
            });
        }
    };

    for t in trait_definitions {
        flag(
            t.id.as_str(),
            t.unless.as_ref(),
            t.downgrade.as_ref(),
            false,
        );
    }

    for r in composite_rules {
        flag(r.id.as_str(), r.unless.as_ref(), r.downgrade.as_ref(), true);
    }

    violations
}

/// Minimum effective pattern length. Patterns with fewer concrete characters/bytes
/// are too noisy and slow to be useful without additional specificity constraints.
const MIN_PATTERN_LENGTH: usize = 3;

/// Check whether a short pattern has sufficient constraints to bound the search space.
///
/// Short patterns (1-2 concrete chars/bytes) are only acceptable if the search is
/// reasonably bounded (~8KB ideal). Acceptable constraint combinations:
///
/// - `offset` or a small closed `offset_range` (absolute location)
/// - `section` + `section_offset` or a small closed `section_offset_range`
/// - `section` + `size_max`
///   (section narrows the region, plus a pinpoint or file-size bound)
///
/// Section alone is NOT enough — a `.text` section can be megabytes.
/// `size_max` alone is NOT enough — the whole file is still searched.
/// Density constraints (`count_min`, `per_kb_min`) don't bound the search space.
fn has_short_pattern_constraints(t: &TraitDefinition, cond: &Condition) -> bool {
    let (Condition::Raw(RawQuery {
        section,
        offset,
        offset_range,
        section_offset,
        section_offset_range,
        ..
    })
    | Condition::Text(TextQuery {
        section,
        offset,
        offset_range,
        section_offset,
        section_offset_range,
        ..
    })
    | Condition::Literal(LiteralQuery {
        section,
        offset,
        offset_range,
        section_offset,
        section_offset_range,
        ..
    })
    | Condition::Encoded(EncodedQuery {
        section,
        offset,
        offset_range,
        section_offset,
        section_offset_range,
        ..
    })
    | Condition::Hex(HexQuery {
        section,
        offset,
        offset_range,
        section_offset,
        section_offset_range,
        ..
    })) = cond
    else {
        return true;
    };

    // Exact absolute offsets and small closed absolute ranges bound the search.
    if offset.is_some() || is_limited_byte_range(*offset_range) {
        return true;
    }

    // Section + exact relative offset, small closed relative range, or file-size
    // cap bounds the search region.
    if section.is_some()
        && (section_offset.is_some()
            || is_limited_byte_range(*section_offset_range)
            || t.size_max.is_some())
    {
        return true;
    }

    false
}

/// Find raw/hex traits with patterns too short to be useful without sufficient constraints.
///
/// Short patterns (1-2 chars for raw substr/exact, 1-2 concrete bytes for hex) are
/// rejected unless the search space is reasonably bounded (~8KB ideal):
///
/// - `offset` or a small closed `offset_range` (absolute location)
/// - `section` + (`section_offset*` or `size_max`) — narrows to a bounded region
///
/// For hex patterns, `??` full wildcards and `[N]` gaps don't count toward length,
/// but nibble wildcards like `4?` or `?F` do (they still constrain one nibble).
///
/// Applies uniformly to all string-pattern condition types (text, raw,
/// string_literal, encoded). Binary string extraction has a low minimum
/// (typically 4 bytes) — a 1–2 char text substr still matches anywhere inside
/// every extracted string, so the same noise floor applies.
///
/// Returns: `Vec<(trait_id, pattern_value, pattern_type)>`
#[must_use]
pub(crate) fn find_too_short_patterns(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, String, &'static str)> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        if has_short_pattern_constraints(t, &t.r#if) {
            continue;
        }

        let (exact, substr) = match &t.r#if {
            Condition::Raw(RawQuery { exact, substr, .. })
            | Condition::Text(TextQuery { exact, substr, .. })
            | Condition::Literal(LiteralQuery { exact, substr, .. })
            | Condition::Encoded(EncodedQuery { exact, substr, .. }) => {
                (exact.as_deref(), substr.as_deref())
            }
            Condition::Hex(HexQuery { pattern, .. }) => {
                let concrete_bytes = count_concrete_hex_bytes(pattern);
                if concrete_bytes < MIN_PATTERN_LENGTH {
                    violations.push((t.id.clone(), pattern.clone(), "hex"));
                }
                continue;
            }
            _ => continue,
        };

        if let Some(s) = exact
            && s.len() < MIN_PATTERN_LENGTH
        {
            violations.push((t.id.clone(), s.to_string(), "exact"));
        }
        if let Some(s) = substr
            && s.len() < MIN_PATTERN_LENGTH
        {
            violations.push((t.id.clone(), s.to_string(), "substr"));
        }
    }

    violations
}

/// Count effective bytes in a hex pattern string.
///
/// Excludes full `??` wildcards and `[N]` gap specifiers, but counts nibble
/// wildcards like `4?` or `?F` since they still constrain one nibble.
fn count_concrete_hex_bytes(pattern: &str) -> usize {
    pattern
        .split_whitespace()
        .filter(|token| {
            // Exclude gap specifiers like [4], [2-8]
            if token.starts_with('[') {
                return false;
            }
            // Exclude full wildcard bytes — no signal
            if *token == "??" {
                return false;
            }
            // Accept nibble wildcards (4?, ?F) — they constrain one nibble
            // Accept full hex bytes (4D, 5A)
            token.len() == 2 && token.chars().all(|c| c.is_ascii_hexdigit() || c == '?')
        })
        .count()
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
        // Check all:, any:, unless: clauses
        for conditions in [rule.all.as_ref(), rule.any.as_ref(), rule.unless.as_ref()]
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
            for conditions in [
                downgrade.any.as_ref(),
                downgrade.all.as_ref(),
                downgrade.none.as_ref(),
            ]
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
            for conditions in [
                downgrade.any.as_ref(),
                downgrade.all.as_ref(),
                downgrade.none.as_ref(),
            ]
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

/// Find traits where `not:` is used inside a condition without `regex:`.
///
/// The `not:` field excludes individual evidence matches and only makes sense
/// with ambiguous patterns: `regex:` on string/raw/encoded conditions, or any
/// `hex:` condition (which inherently has wildcards). With `exact:`, `substr:`,
/// or `word:`, the match is already precise — change the pattern instead.
#[must_use]
pub(crate) fn find_invalid_not_usage(trait_definitions: &[TraitDefinition]) -> Vec<String> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        let invalid = match &t.r#if {
            // Variants that carry both `regex` and `not`: `not` only makes sense
            // alongside an ambiguous matcher (regex). With exact/substr/word the
            // match is already precise — change the pattern instead.
            Condition::Raw(RawQuery { regex, not, .. })
            | Condition::Encoded(EncodedQuery { regex, not, .. })
            | Condition::Symbol(SymbolQuery { regex, not, .. })
            | Condition::Text(TextQuery { regex, not, .. })
            | Condition::Literal(LiteralQuery { regex, not, .. }) => {
                not.is_some() && regex.is_none()
            }
            // Hex: not is always valid (patterns are inherently ambiguous).
            // Other condition types do not have a `not:` field.
            _ => false,
        };

        if invalid {
            violations.push(format!(
                "{}: `not:` is only valid with `regex:` or `hex:` patterns",
                t.id,
            ));
        }
    }

    violations
}

/// Check if a KV condition has a redundant `exists` field alongside a value matcher.
fn is_kv_exists_redundant(cond: &Condition) -> bool {
    matches!(
        cond,
        Condition::Kv(KvQuery {
            exists: Some(_),
            exact,
            substr,
            regex,
            ..
        }) if exact.is_some() || substr.is_some() || regex.is_some()
    )
}

/// Find KV conditions where `exists` is set alongside a value matcher.
///
/// When `exact`, `substr`, or `regex` is present, `exists` is redundant:
/// - `exists: true` is implied (a value matcher requires the field to exist)
/// - `exists: false` is contradictory (a non-existent field can't have a value)
///
/// Returns: `Vec<rule_id>`
#[must_use]
pub(crate) fn find_kv_exists_with_matcher(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<String> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        if is_kv_exists_redundant(&t.r#if) {
            violations.push(t.id.clone());
        }
    }

    for rule in composite_rules {
        let has_redundant = [&rule.all, &rule.any, &rule.unless]
            .iter()
            .filter_map(|list| list.as_ref())
            .any(|conds| conds.iter().any(is_kv_exists_redundant));
        if has_redundant {
            violations.push(rule.id.clone());
        }
    }

    violations
}

/// Find composite rules with proximity constraints but no positive conditions.
///
/// A rule without `all:`/`any:` and with `near_lines` or `near_bytes` can never match
/// because proximity requires co-occurring evidence from positive conditions.
///
/// Returns: `Vec<rule_id>`
#[must_use]
pub(crate) fn find_none_only_with_proximity(composite_rules: &[CompositeTrait]) -> Vec<String> {
    composite_rules
        .iter()
        .filter(|rule| {
            rule.all.is_none()
                && rule.any.is_none()
                && (rule.near_lines.is_some() || rule.near_bytes.is_some())
        })
        .map(|rule| rule.id.clone())
        .collect()
}

/// Find traits and composite rules with 9 or more explicit file types in their `for:` field.
///
/// Listing many individual file types defeats the purpose of specific targeting and is
/// equivalent to broad groupings like `binaries`, `scripts`, or `all`. Authors should
/// use these aggregates instead of enumerating every covered type.
///
/// Up to 8 explicit types is accepted: real traits routinely need a hand-picked spread
/// across two or three groups (e.g. a few scripts + a binary format + a manifest) that
/// no single named group expresses, and forcing a group there over-broadens coverage.
/// Nine or more almost always maps to an existing group and should use it.
///
/// Traits with `for: [all]` are exempt — they already use the broadest specifier.
///
/// Returns: `Vec<(id, count, suggestion, is_composite)>`
#[must_use]
pub(crate) fn find_excessive_file_types(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, usize, &'static str, bool)> {
    const MIN_FOR_WARNING: usize = 9;

    let binaries: &[FileType] = &[
        FileType::Elf,
        FileType::Macho,
        FileType::Pe,
        FileType::Class,
        FileType::Pyc,
    ];
    let scripts: &[FileType] = &[
        FileType::Shell,
        FileType::Batch,
        FileType::Jcl,
        FileType::Python,
        FileType::JavaScript,
        FileType::Ruby,
        FileType::Php,
        FileType::Perl,
        FileType::Lua,
        FileType::PowerShell,
        FileType::AppleScript,
        FileType::Vbs,
    ];
    let source: &[FileType] = &[
        FileType::TypeScript,
        FileType::Rust,
        FileType::Java,
        FileType::C,
        FileType::Cpp,
        FileType::Go,
        FileType::CSharp,
        FileType::Swift,
        FileType::ObjectiveC,
        FileType::Groovy,
        FileType::Kotlin,
        FileType::Scala,
        FileType::Zig,
        FileType::Elixir,
    ];
    let manifests: &[FileType] = &[
        FileType::PackageJson,
        FileType::PackageLockJson,
        FileType::GoMod,
        FileType::Json,
        FileType::ChromeManifest,
        FileType::CargoToml,
        FileType::PyProjectToml,
        FileType::GithubActions,
        FileType::SystemdService,
        FileType::DesktopEntry,
        FileType::Xml,
        FileType::ComposerJson,
        FileType::PkgInfo,
        FileType::Plist,
        FileType::Lnk,
        FileType::Dockerfile,
    ];
    let documents: &[FileType] = &[
        FileType::Pdf,
        FileType::Rtf,
        FileType::Html,
        FileType::Text,
        FileType::OleDoc,
        FileType::Ooxml,
    ];
    let images: &[FileType] = &[FileType::Jpeg, FileType::Png];
    let data: &[FileType] = &[FileType::Ipa, FileType::Text, FileType::Data];
    let archives: &[FileType] = &[
        FileType::Archive,
        FileType::Zip,
        FileType::Apk,
        FileType::Jar,
        FileType::Tar,
        FileType::Npm,
        FileType::Nupkg,
        FileType::Gem,
        FileType::Whl,
        FileType::Deb,
        FileType::Rpm,
        FileType::Crx,
        FileType::VsixArchive,
        FileType::Xpi,
    ];
    let all_groups: &[(&[FileType], &str)] = &[
        (binaries, "binaries"),
        (scripts, "scripts"),
        (source, "source"),
        (manifests, "manifests"),
        (documents, "documents"),
        (images, "images"),
        (data, "data"),
        (archives, "archives"),
    ];

    // Returns true if `types` is an exact union of complete named groups.
    // Each group must be either fully included or fully excluded — partial
    // groups are not expressible and should be flagged.
    let is_group_expressible = |types: &[FileType]| -> bool {
        let type_set: std::collections::HashSet<_> = types.iter().collect();
        // Every type must belong to some group
        if !type_set
            .iter()
            .all(|ft| all_groups.iter().any(|(group, _)| group.contains(ft)))
        {
            return false;
        }
        // Each touched group must be completely included (no partial groups)
        for (group, _) in all_groups {
            let overlap = group.iter().filter(|ft| type_set.contains(ft)).count();
            if overlap > 0 && overlap != group.len() {
                return false;
            }
        }
        true
    };

    // Only called when is_group_expressible returned false, so types contain at least one
    // member that doesn't belong to any named group — always suggest [all] or named groups.
    let suggest = |_types: &[FileType]| -> &'static str {
        "use `for: [all]` or combine named groups (binaries, scripts, source, manifests, documents, media, data, archives)"
    };

    let mut violations = Vec::new();

    for t in trait_definitions {
        // Skip if the author already used named groups — platform filtering may
        // have removed some members, making the expanded set look like a partial
        // group, but the YAML source is correct.
        if t.for_from_groups || t.r#for.contains(&FileType::All) || is_group_expressible(&t.r#for) {
            continue;
        }
        if t.r#for.len() >= MIN_FOR_WARNING {
            violations.push((t.id.clone(), t.r#for.len(), suggest(&t.r#for), false));
        }
    }

    for r in composite_rules {
        if r.for_from_groups || r.r#for.contains(&FileType::All) || is_group_expressible(&r.r#for) {
            continue;
        }
        if r.r#for.len() >= MIN_FOR_WARNING {
            violations.push((r.id.clone(), r.r#for.len(), suggest(&r.r#for), true));
        }
    }

    violations
}

/// Find hex conditions targeting binary file types that lack a required section filter.
///
/// Hex pattern matching against binaries without a section constraint scans the entire
/// file content, which is both expensive and increases false-positive risk. Every hex
/// condition whose `for:` includes `all`, `pe`, `macho`, `elf`, `dylib`, `so`, or `dll`
/// must specify a `section:` field to scope the search to a named section.
///
/// Traits with an absolute `offset` or `offset_range` are exempt — a pinned location
/// already bounds the search space without needing a section.
///
/// Returns: `Vec<trait_id>`
#[must_use]
pub(crate) fn find_hex_binary_missing_section(
    trait_definitions: &[TraitDefinition],
) -> Vec<String> {
    trait_definitions
        .iter()
        .filter(|t| {
            let Condition::Hex(HexQuery {
                section,
                offset,
                offset_range,
                ..
            }) = &t.r#if
            else {
                return false;
            };
            // Absolute offset or offset_range already pins the search — exempt.
            if offset.is_some() || offset_range.is_some() {
                return false;
            }
            // Require section when targeting binary file types.
            section.is_none()
                && (t.r#for.contains(&FileType::All)
                    || t.r#for
                        .iter()
                        .any(|ft| super::helpers::is_binary_file_type(*ft)))
        })
        .map(|t| t.id.clone())
        .collect()
}

// Per-condition-type file-type caps moved to
// `validation::taxonomy::find_broad_filetype_traits`, which now enforces a
// single per-matcher-type threshold table (text/value/symbol/ast) plus a
// type-qualified allowlist. The former `find_condition_scope_violations`
// (tree-sitter ≤2, symbol/hex/yara ≤4) is subsumed by those caps.
