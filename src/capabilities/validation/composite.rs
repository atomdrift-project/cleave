//! Composite rule specific validation.
//!
//! This module provides validation for composite rules, including checking
//! that composite rules only contain trait references (not inline primitives),
//! auto-prefixing trait references, and detecting redundant patterns.

use crate::capabilities::mapper::doomed_skip::{composite_applies, trait_applies_to_file};
use crate::composite_rules::{
    CompositeTrait, Condition, FileType, Platform, Scope, TraitDefinition,
};
use std::collections::{HashMap, HashSet};

/// Find atomic traits whose `if:` clause references themselves
/// (`type: trait, id: <self>`). Such traits never fire — the runtime
/// resolves the trait reference by querying the findings table, but
/// the trait being evaluated hasn't been added yet, so the lookup
/// always returns false. Earlier, this also caused the test-rules
/// debugger to recurse forever and overflow the stack.
///
/// Returns `(trait_id, source_file_hint)` for each violation. Caller
/// can join with the loader's `rule_source_files` map to print a
/// useful line-number diagnostic.
#[must_use]
pub(crate) fn find_self_referencing_traits(traits: &[TraitDefinition]) -> Vec<&TraitDefinition> {
    traits
        .iter()
        .filter(|t| matches!(&t.r#if, Condition::Trait { id } if id == &t.id))
        .collect()
}

fn directory_ref_includes_rule(ref_id: &str, rule_id: &str) -> bool {
    if ref_id.contains("::") {
        return false;
    }
    // Directory references are conventionally written with a trailing slash
    // (`objectives/exfiltration/messaging/webhook/`), while a rule id joins its
    // directory to its name with `::`. Comparing the two without trimming that
    // slash silently matched only rules in *sub*directories -- the one case the
    // check least needed -- and never a rule in the directory named. That let
    // self-suppressing traits through: the shape this function exists to catch.
    let dir = ref_id.strip_suffix('/').unwrap_or(ref_id);
    rule_id
        .strip_prefix(dir)
        .is_some_and(|rest| rest.starts_with("::") || rest.starts_with('/'))
}

/// Find atomic traits that suppress or downgrade themselves.
///
/// An atomic trait whose `unless:` names its own id — or a directory that
/// expands to include it — can never surface: its own match satisfies its own
/// suppression clause. The same shape in `downgrade:` silently pins the trait
/// one level below its declared criticality, forever.
///
/// This is the atomic counterpart of [`find_self_referencing_composites`], and
/// it is easy to introduce the same way: collapsing a same-directory
/// `unless:` list into a bare directory reference. It is also near-invisible,
/// because `test-rules` evaluates a rule in isolation and happily reports
/// MATCHED — only a full scan, where the trait's own finding is in the table,
/// shows it being skipped.
///
/// Returns `(trait, offending_ref_id, clause_name)` per violation.
#[must_use]
pub(crate) fn find_self_suppressing_traits(
    traits: &[TraitDefinition],
) -> Vec<(&TraitDefinition, String, &'static str)> {
    fn ref_includes_rule(ref_id: &str, rule_id: &str) -> bool {
        ref_id == rule_id || directory_ref_includes_rule(ref_id, rule_id)
    }

    fn scan(trait_def: &TraitDefinition, conditions: Option<&[Condition]>) -> Option<String> {
        conditions?.iter().find_map(|cond| {
            let Condition::Trait { id } = cond else {
                return None;
            };
            ref_includes_rule(id, &trait_def.id).then(|| id.clone())
        })
    }

    let mut violations = Vec::new();
    for trait_def in traits {
        if let Some(ref_id) = scan(trait_def, trait_def.unless.as_deref()) {
            violations.push((trait_def, ref_id, "unless"));
            continue;
        }
        if let Some(downgrade) = trait_def.downgrade.as_ref() {
            let hit = scan(trait_def, downgrade.all.as_deref())
                .or_else(|| scan(trait_def, downgrade.any.as_deref()))
                .or_else(|| scan(trait_def, downgrade.none.as_deref()));
            if let Some(ref_id) = hit {
                violations.push((trait_def, ref_id, "downgrade"));
            }
        }
    }

    violations
}

/// Find composite rules whose conditions reference the composite itself.
///
/// This catches both direct references (`id: <rule-id>`) and directory
/// references that would expand to include the composite (`id: <rule-dir>`).
/// The latter is easy to introduce when replacing a long same-directory `any:`
/// list with a bare directory reference.
#[must_use]
pub(crate) fn find_self_referencing_composites(
    rules: &[CompositeTrait],
) -> Vec<(&CompositeTrait, String)> {
    fn ref_includes_rule(ref_id: &str, rule_id: &str) -> bool {
        if ref_id == rule_id {
            return true;
        }
        directory_ref_includes_rule(ref_id, rule_id)
    }

    fn scan_conditions(rule: &CompositeTrait, conditions: Option<&[Condition]>) -> Option<String> {
        conditions?.iter().find_map(|cond| {
            let Condition::Trait { id } = cond else {
                return None;
            };
            ref_includes_rule(id, &rule.id).then(|| id.clone())
        })
    }

    let mut violations = Vec::new();
    for rule in rules {
        let direct_ref = scan_conditions(rule, rule.all.as_deref())
            .or_else(|| scan_conditions(rule, rule.any.as_deref()))
            .or_else(|| scan_conditions(rule, rule.unless.as_deref()))
            .or_else(|| {
                let downgrade = rule.downgrade.as_ref()?;
                scan_conditions(rule, downgrade.all.as_deref())
                    .or_else(|| scan_conditions(rule, downgrade.any.as_deref()))
                    .or_else(|| scan_conditions(rule, downgrade.none.as_deref()))
            });
        if let Some(ref_id) = direct_ref {
            violations.push((rule, ref_id));
        }
    }

    violations
}

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
    if let Some(ref c) = rule.unless {
        check_conditions(c, &rule.id, "unless", source_file, &mut errors);
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
    if let Some(ref mut conditions) = rule.unless {
        prefix_conditions(conditions, prefix);
    }
    if let Some(ref mut downgrade) = rule.downgrade {
        if let Some(ref mut conditions) = downgrade.all {
            prefix_conditions(conditions, prefix);
        }
        if let Some(ref mut conditions) = downgrade.any {
            prefix_conditions(conditions, prefix);
        }
        if let Some(ref mut conditions) = downgrade.none {
            prefix_conditions(conditions, prefix);
        }
    }
}

/// Collect all trait reference IDs from a composite rule's conditions.
///
/// Returns a vector of `(trait_id, rule_id)` tuples for all trait references
/// found in the rule's `all`, `any`, and `unless` clauses.
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
    if let Some(ref conditions) = rule.unless {
        collect_from_conditions(conditions, &rule.id, &mut refs);
    }
    if let Some(ref downgrade) = rule.downgrade {
        if let Some(ref conditions) = downgrade.all {
            collect_from_conditions(conditions, &rule.id, &mut refs);
        }
        if let Some(ref conditions) = downgrade.any {
            collect_from_conditions(conditions, &rule.id, &mut refs);
        }
        if let Some(ref conditions) = downgrade.none {
            collect_from_conditions(conditions, &rule.id, &mut refs);
        }
    }

    refs
}

/// Collect all trait reference IDs from an atomic trait definition.
///
/// Returns a vector of `(trait_id, owner_id)` tuples for every `type: trait`
/// reference reachable from the trait's `if:`, `unless:`, and `downgrade:`
/// clauses. The `not:` field carries only string exclusions (`NotException`),
/// never trait references, so it is not inspected.
///
/// Counterpart to [`collect_trait_refs_from_rule`] for composites — atomic
/// traits can reference other traits too (an `if: { id: … }` chains to another
/// detection; an `unless: [{ id: … }]` suppresses on one), and those refs went
/// unvalidated until this was added.
#[must_use]
pub(crate) fn collect_trait_refs_from_trait_def(t: &TraitDefinition) -> Vec<(String, String)> {
    let mut refs = Vec::new();

    fn collect_from_conditions(
        conditions: &[Condition],
        owner_id: &str,
        refs: &mut Vec<(String, String)>,
    ) {
        for cond in conditions {
            if let Condition::Trait { id } = cond {
                refs.push((id.clone(), owner_id.to_string()));
            }
        }
    }

    if let Condition::Trait { id } = &t.r#if {
        refs.push((id.clone(), t.id.clone()));
    }
    if let Some(ref conditions) = t.unless {
        collect_from_conditions(conditions, &t.id, &mut refs);
    }
    if let Some(ref downgrade) = t.downgrade {
        if let Some(ref conditions) = downgrade.all {
            collect_from_conditions(conditions, &t.id, &mut refs);
        }
        if let Some(ref conditions) = downgrade.any {
            collect_from_conditions(conditions, &t.id, &mut refs);
        }
        if let Some(ref conditions) = downgrade.none {
            collect_from_conditions(conditions, &t.id, &mut refs);
        }
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

/// Find `any:` or `all:` clauses that explicitly list every atomic trait in a directory.
///
/// For `any:`, directory references already mean "any rule in this directory", so a composite like:
///
/// ```yaml
/// any:
///   - id: foo/bar::a
///   - id: foo/bar::b
/// ```
///
/// is needlessly hand-maintained when `foo/bar` contains only `a` and `b`.
///
/// For `all:`, directory syntax is not equivalent because directory references are any-of
/// prefix matches at runtime. Still, listing every trait in a directory is usually a taxonomy
/// smell: the directory has become the rule definition instead of a reusable technique bucket.
///
/// This catches both local and external directories, and complements `find_redundant_any_refs`,
/// which catches large same-directory groups even when they do not cover the whole directory.
///
/// Returns `(rule_id, clause, directory, trait_count, trait_ids)` for violations.
#[must_use]
pub(crate) fn find_many_directory_refs(
    rule: &CompositeTrait,
    dir_traits: &HashMap<String, HashSet<String>>,
) -> Vec<(String, &'static str, String, usize, Vec<String>)> {
    const MIN_DIRECTORY_REFS: usize = 5;
    let mut violations = Vec::new();

    fn collect_clause_refs(conditions: &[Condition]) -> HashMap<String, HashSet<String>> {
        let mut dir_refs: HashMap<String, HashSet<String>> = HashMap::new();
        for cond in conditions {
            if let Condition::Trait { id } = cond
                && let Some(idx) = id.find("::")
            {
                dir_refs
                    .entry(id[..idx].to_string())
                    .or_default()
                    .insert(id.clone());
            }
        }
        dir_refs
    }

    for (clause, conditions) in [("any", rule.any.as_deref()), ("all", rule.all.as_deref())] {
        let Some(conditions) = conditions else {
            continue;
        };
        for (dir, refs) in collect_clause_refs(conditions) {
            let Some(traits) = dir_traits.get(&dir) else {
                continue;
            };
            if directory_ref_includes_rule(&dir, &rule.id) {
                continue;
            }
            if traits.len() < MIN_DIRECTORY_REFS || refs.len() != traits.len() {
                continue;
            }
            if refs.is_superset(traits) {
                let mut trait_ids: Vec<String> = refs.into_iter().collect();
                trait_ids.sort();
                violations.push((rule.id.clone(), clause, dir, trait_ids.len(), trait_ids));
            }
        }
    }

    violations
}

/// Find composites that add no value beyond a directory reference.
///
/// A composite is a pure directory alias when its only logic is:
///
/// ```yaml
/// any:
///   - id: foo/bar::a
///   - id: foo/bar::b
/// ```
///
/// and `foo/bar` contains exactly `a` and `b`. Callers should reference
/// `foo/bar` directly instead of maintaining the extra composite rule.
#[must_use]
pub(crate) fn find_pure_directory_alias_composites(
    rules: &[CompositeTrait],
    dir_traits: &HashMap<String, HashSet<String>>,
) -> Vec<(String, String, usize, Vec<String>)> {
    let mut violations = Vec::new();

    for rule in rules {
        if rule.all.as_ref().is_some_and(|v| !v.is_empty())
            || rule.unless.as_ref().is_some_and(|v| !v.is_empty())
            || rule.not.as_ref().is_some_and(|v| !v.is_empty())
            || rule.downgrade.is_some()
            || rule.needs.is_some()
            || rule.near_lines.is_some()
            || rule.near_bytes.is_some()
            || rule.size_min.is_some()
            || rule.size_max.is_some()
            || rule.scope.is_some()
        {
            continue;
        }

        let Some(any) = rule.any.as_ref() else {
            continue;
        };
        if any.is_empty() {
            continue;
        }

        let mut dirs: HashMap<String, HashSet<String>> = HashMap::new();
        let mut all_trait_refs = true;
        for cond in any {
            let Condition::Trait { id } = cond else {
                all_trait_refs = false;
                break;
            };
            let Some(idx) = id.find("::") else {
                all_trait_refs = false;
                break;
            };
            dirs.entry(id[..idx].to_string())
                .or_default()
                .insert(id.clone());
        }
        if !all_trait_refs || dirs.len() != 1 {
            continue;
        }

        let Some((dir, refs)) = dirs.into_iter().next() else {
            continue;
        };
        let Some(traits) = dir_traits.get(&dir) else {
            continue;
        };
        if directory_ref_includes_rule(&dir, &rule.id) {
            continue;
        }
        if traits.len() < 2 || refs.len() != traits.len() || !refs.is_superset(traits) {
            continue;
        }

        let mut trait_ids: Vec<String> = refs.into_iter().collect();
        trait_ids.sort();
        violations.push((rule.id.clone(), dir, trait_ids.len(), trait_ids));
    }

    violations
}

/// Find composite rules that have only a single condition total across `any:` and `all:`.
///
/// A single-item `any:` or `all:` is redundant - the rule should just be that single trait.
/// Only flagged if there's no other meaningful clause (`unless:`, `downgrade:`).
/// Also skips directory references since they can match multiple traits.
///
/// Returns `(rule_id, clause_type: "any" or "all", trait_id)`.
#[must_use]
pub(crate) fn find_single_item_clauses(
    rule: &CompositeTrait,
) -> Vec<(String, &'static str, String)> {
    let mut violations = Vec::new();

    // Skip rules with unless: or downgrade: clauses - they add meaningful conditions
    let has_unless = rule.unless.as_ref().is_some_and(|v| !v.is_empty());
    let has_downgrade = rule.downgrade.is_some();
    if has_unless || has_downgrade {
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
    if any_count == 1
        && let Some(Condition::Trait { id }) = rule.any.as_ref().and_then(|v| v.first())
    {
        // Only flag specific trait references (with ::), not directory references
        if id.contains("::") {
            violations.push((rule.id.clone(), "any", id.clone()));
        }
    }

    if all_count == 1
        && let Some(Condition::Trait { id }) = rule.all.as_ref().and_then(|v| v.first())
    {
        // Only flag specific trait references (with ::), not directory references
        if id.contains("::") {
            violations.push((rule.id.clone(), "all", id.clone()));
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
            if let Condition::Trait { id } = cond
                && let Some(idx) = id.find("::")
            {
                let trait_dir = &id[..idx];
                if let Some(&dir) = dir_refs.iter().find(|&&d| d == trait_dir) {
                    violations.push((rule.id.clone(), clause, dir.to_string(), id.clone()));
                }
            }
        }
    }

    violations
}

/// Find composites that can never match, because no file type exists that the
/// rule and every trait it requires all apply to.
///
/// At `scope: file` one file has to satisfy every leg of an `all:`, so the rule
/// is only reachable if some file type passes the engine's own applicability
/// test for the composite *and* for each of its legs. Asking the engine rather
/// than re-deriving the answer keeps this honest: `for:` is not a plain set
/// test — a rule naming an archive type also reaches container nodes, and a
/// trait's `if:` can rule out types its `for:` admits.
///
/// This is easy to get wrong by accident, because `for:` is usually inherited.
/// A file whose `defaults:` say `for: [package.json]` hands that to every rule
/// in it, including composites assembled entirely out of JavaScript traits —
/// the rule then reads perfectly and matches nothing.
///
/// Reported as a warning rather than an error: a leg backed by `type: encoded`
/// can match inside a decoded layer whose type differs from the file that
/// carried it, so an empty result is strong evidence of a dead rule rather
/// than proof of one.
///
/// Returns `(rule_id, rule_for, legs, types_the_legs_share)`.
#[must_use]
pub(crate) fn find_unsatisfiable_file_types<'a>(
    rules: &'a [CompositeTrait],
    traits_by_id: &HashMap<String, &TraitDefinition>,
    composites_by_id: &HashMap<String, &CompositeTrait>,
) -> Vec<(&'a str, Vec<FileType>, Vec<String>, Vec<FileType>)> {
    let platforms = [Platform::All];
    let types = FileType::all_variants();
    let mut violations = Vec::new();

    for rule in rules {
        // Only `scope: file` forces one file to satisfy every leg. Wider scopes
        // pool evidence across members, where differing types are the normal
        // case rather than a contradiction.
        if !matches!(rule.scope, None | Some(Scope::File)) {
            continue;
        }
        // A rule naming an archive type is evaluated on the container node,
        // which carries the findings of the members folded into it. Its legs
        // matched real files of their own types, so the intersection this
        // check looks for is not the question being asked.
        if rule
            .r#for
            .iter()
            .any(|t| t.is_archive() || *t == FileType::All)
        {
            continue;
        }
        let Some(conditions) = rule.all.as_deref() else {
            continue;
        };
        let legs: Vec<&String> = conditions
            .iter()
            .filter_map(|c| match c {
                Condition::Trait { id } => Some(id),
                _ => None,
            })
            // A directory reference stands for a set of traits, any one of
            // which may satisfy the leg; there is no single rule to ask.
            .filter(|id| !id.ends_with('/'))
            .collect();
        if legs.len() < 2 {
            continue;
        }
        // Every leg has to be resolvable; an unknown reference could be
        // satisfiable by a type this check would otherwise rule out.
        if legs.iter().any(|id| {
            !traits_by_id.contains_key(id.as_str()) && !composites_by_id.contains_key(id.as_str())
        }) {
            continue;
        }

        let reachable = types.iter().any(|&ft| {
            composite_applies(rule, &platforms, ft)
                && legs.iter().all(|id| {
                    traits_by_id
                        .get(id.as_str())
                        .is_some_and(|t| trait_applies_to_file(t, &platforms, ft))
                        || composites_by_id
                            .get(id.as_str())
                            .is_some_and(|c| composite_applies(c, &platforms, ft))
                })
        });
        if !reachable {
            // What the rule should say instead: the types on which every leg
            // does apply. Empty means the legs disagree with each other, and
            // no `for:` can rescue the rule.
            let suggested: Vec<FileType> = types
                .iter()
                .copied()
                .filter(|&ft| {
                    ft != FileType::All
                        && legs.iter().all(|id| {
                            traits_by_id
                                .get(id.as_str())
                                .is_some_and(|t| trait_applies_to_file(t, &platforms, ft))
                                || composites_by_id
                                    .get(id.as_str())
                                    .is_some_and(|c| composite_applies(c, &platforms, ft))
                        })
                })
                .collect();
            let mut ids: Vec<String> = legs.iter().map(|id| (*id).clone()).collect();
            ids.sort();
            violations.push((rule.id.as_str(), rule.r#for.clone(), ids, suggested));
        }
    }
    violations
}
