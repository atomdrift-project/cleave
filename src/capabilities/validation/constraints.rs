//! Logic constraint validation.
//!
//! This module validates logical constraints in rules, detecting impossible
//! or contradictory configurations that would make rules unsatisfiable.

use rayon::prelude::*;
use std::collections::{HashMap, HashSet};

use crate::capabilities::models::{RawCompositeRule, RawTraitDefinition, TraitDefaults};
use crate::capabilities::validation::shared::is_limited_byte_range;
use crate::composite_rules::{
    CompositeTrait, Condition, DowngradeConditions, FileType, KvQuery, Scope, TraitDefinition,
};
use crate::composite_rules::{
    EncodedQuery, HexQuery, LiteralQuery, PathQuery, RawQuery, SectionQuery, SymbolQuery, TextQuery,
};

mod file_scope;
#[allow(clippy::wildcard_imports)]
pub(crate) use file_scope::*;

mod convictions;
#[allow(clippy::wildcard_imports)]
pub(crate) use convictions::*;

mod reach;
#[allow(clippy::wildcard_imports)]
pub(crate) use reach::*;

mod references;
#[allow(clippy::wildcard_imports)]
pub(crate) use references::*;

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

/// Find composite rules whose positive conditions are empty or absent.
///
/// A composite draws all of its evidence from `all:`/`any:`, and the two ways of
/// getting that wrong fail in *opposite* directions:
///
/// - **Present but empty** (`all: []`, `any: []`). An empty `all:` vacuously
///   matches everything, because `eval_requires_all` returns `matched: true`
///   over an empty slice — the rule fires on every file that clears its
///   platform/type/size gates, carrying no evidence. An empty `any:` with
///   `needs > 0` can never match; with `needs: 0` or the default it vacuously
///   matches.
/// - **Absent entirely** (neither key present). The rule fires on nothing:
///   `CompositeTrait::evaluate_with_gates` matches `(None, None)` and returns
///   `None`, calling it an invalid rule. Nothing else reports it, so the rule
///   loads, counts toward the taxonomy, and silently never fires.
///
/// The absent case is the one authors actually hit, since YAML omits a key
/// rather than spelling out an empty list. Filter fields (`for:`, `size_min`,
/// `size_max`, `platforms:`) do not rescue it — they constrain evidence rather
/// than supplying it — and neither does `unless:`, which can only withhold a
/// match. A rule whose whole predicate *is* a size/type filter belongs in
/// `traits:`, where `parsing.rs` synthesizes an always-true condition for
/// size-only atomic traits; as a composite it is simply dead.
///
/// Atomic traits are deliberately out of scope: this only ever inspects
/// composites, so a legitimate size-only trait cannot be caught by it.
///
/// Returns: `Vec<(rule_id, clause_type)>`, where `clause_type` is `"all"` or
/// `"any"` for an empty clause and [`MISSING_CONDITIONS`] when both are absent.
#[must_use]
pub(crate) fn find_empty_condition_clauses(
    composite_rules: &[CompositeTrait],
) -> Vec<(String, &'static str)> {
    let mut violations = Vec::new();

    for rule in composite_rules {
        if rule.all.is_none() && rule.any.is_none() {
            violations.push((rule.id.clone(), MISSING_CONDITIONS));
            continue;
        }

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

/// `clause_type` marker for a composite carrying neither `all:` nor `any:`.
/// Distinguishes "the clause is there but empty" from "there is no clause",
/// which need different messages because they fail in opposite directions.
pub(crate) const MISSING_CONDITIONS: &str = "__missing__";

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
/// - No unless/not/downgrade modifiers
///
/// A different `crit:` does not rescue it. The alias matches exactly what its
/// target matches, so a tier change reports the same evidence a second time
/// under a second name, and a reader has to work out which id to believe. If
/// the tier is wrong, fix it on the trait that owns the matcher; if two
/// contexts genuinely need different severities, that belongs in the composites
/// that consume the trait, not in a renamed copy of it.
///
/// A reference that does not resolve to a single trait is left alone: a
/// directory prefix (`micro-behaviors/fs/file/rename/`) is an OR across
/// everything beneath it, which is real logic rather than a rename.
///
/// These should either add constraints or be removed in favor of direct references.
///
/// Returns: `Vec<(trait_id, referenced_trait_id)>`
#[must_use]
pub(crate) fn find_pure_alias_traits(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, String)> {
    // Every defined trait id, to tell a rename of one trait from a directory
    // reference that fans out across many.
    let known_ids: HashSet<&str> = trait_definitions.iter().map(|t| t.id.as_str()).collect();

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

        // Only a reference naming one trait is a rename of it; a directory
        // prefix fans out across every trait beneath it and is real logic.
        if !known_ids.contains(ref_id.as_str()) {
            continue;
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

/// A `downgrade:` entry that `unless:` already suppresses, so it can never fire.
pub(crate) struct DeadDowngrade {
    /// The offending rule's ID.
    pub id: String,
    /// True for a composite rule, false for an atomic trait.
    pub is_composite: bool,
    /// Which `downgrade:` clause the dead references sit in (`any`/`all`).
    pub clause: &'static str,
    /// The references present in both `unless:` and `downgrade:`.
    pub refs: Vec<String>,
    /// True when the whole clause is dead, not just some of its entries.
    pub whole_clause: bool,
}

/// Reference id of a condition, if it is a plain trait reference.
fn trait_ref(cond: &Condition) -> Option<&str> {
    match cond {
        Condition::Trait { id } => Some(id.as_str()),
        _ => None,
    }
}

/// Find `downgrade:` conditions that can never lower a rule's criticality because
/// `unless:` on the same rule already skips the match outright.
///
/// `unless:` wins: if the same reference appears in both, whenever it matches the rule
/// is suppressed entirely and the downgrade is unreachable. Two shapes are dead:
///
/// - a `downgrade.any` entry that is also in `unless:` (that leg is dead; if every leg
///   is, the whole clause is)
/// - any `downgrade.all` entry that is also in `unless:` (the clause needs all of them,
///   so one suppressed leg kills it)
///
/// Returns one entry per dead clause.
#[must_use]
/// A suppressor that can never let its rule through.
#[derive(Debug, Clone)]
pub(crate) struct ExhaustiveSuppressor {
    /// The offending rule's ID.
    pub id: String,
    /// True for a composite rule, false for an atomic trait.
    pub is_composite: bool,
    /// The directory reference in the rule's `unless:`.
    pub dir_ref: String,
    /// The metric field whose buckets cover everything.
    pub field: String,
    /// The member trait covering the low end, and its `max:`.
    pub low: (String, f64),
    /// The member trait covering the high end, and its `min:`.
    pub high: (String, f64),
}

/// Directory `unless:` references whose members bucket one metric field into
/// complementary halves.
///
/// `- id: some/dir/` in an `unless:` expands to every trait under that
/// directory. When two of them constrain the same `type: metrics` field, one
/// with only `max: B` and the other with only `min: A` where `A <= B + 1`,
/// their union is the whole domain: every file for which the metric is emitted
/// matches one of them, so the rule is suppressed unconditionally and can
/// never fire.
///
/// Found in the wild: `many-wx-sections` ("Multiple W+X sections (packer
/// pattern)") suppressed on `metadata/binary/symbols/exports/`, which holds
/// `no-exports` (`max: 0`) beside `has-exports` (`min: 1`). Every ELF that
/// exports a symbol -- which is every shared object -- skipped the rule.
///
/// Only pairs whose `for:` lists intersect are reported, since two members
/// that apply to disjoint file types never both cover a single file.
pub(crate) fn find_exhaustive_suppressors(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<ExhaustiveSuppressor> {
    use crate::composite_rules::condition::MetricsQuery;

    // Bucket every trait by the directory that contains it.
    let mut by_dir: HashMap<&str, Vec<&TraitDefinition>> = HashMap::new();
    for t in trait_definitions {
        if let Some((dir, _)) = t.id.rsplit_once("::") {
            by_dir.entry(dir).or_default().push(t);
        }
    }

    // A trait's metric bucket, if it has exactly one open end.
    fn bucket(t: &TraitDefinition) -> Option<(&str, Option<f64>, Option<f64>)> {
        match &t.r#if {
            Condition::Metrics(MetricsQuery {
                field, min, max, ..
            }) => Some((field.as_str(), *min, *max)),
            _ => None,
        }
    }

    let types_intersect = |a: &TraitDefinition, b: &TraitDefinition| -> bool {
        a.r#for.is_empty() || b.r#for.is_empty() || a.r#for.iter().any(|f| b.r#for.contains(f))
    };

    let mut out = Vec::new();
    let mut check = |id: &str, unless: Option<&Vec<Condition>>, is_composite: bool| {
        let Some(unless) = unless else { return };
        for cond in unless {
            let Some(r) = trait_ref(cond) else { continue };
            if !r.ends_with('/') {
                continue;
            }
            let dir = r.trim_end_matches('/');
            let Some(members) = by_dir.get(dir) else {
                continue;
            };
            // Group the members' one-sided metric buckets by field.
            let mut lows: HashMap<&str, Vec<(&str, f64)>> = HashMap::new();
            let mut highs: HashMap<&str, Vec<(&str, f64)>> = HashMap::new();
            for m in members.iter() {
                match bucket(m) {
                    Some((f, None, Some(mx))) => {
                        lows.entry(f).or_default().push((m.id.as_str(), mx))
                    }
                    Some((f, Some(mn), None)) => {
                        highs.entry(f).or_default().push((m.id.as_str(), mn))
                    }
                    _ => {}
                }
            }
            for (field, ls) in &lows {
                let Some(hs) = highs.get(field) else { continue };
                for (lid, lmax) in ls {
                    for (hid, hmin) in hs {
                        // Exhaustive when the ranges touch or overlap. The
                        // `+1` step only applies to integer-valued metrics
                        // (counts): `max: 0` beside `min: 1` leaves nothing
                        // between them. On a continuous metric such as a 0..1
                        // ratio there is no next value, so `<= 0.1` beside
                        // `>= 0.95` is a real gap, not total coverage.
                        let touches = *hmin <= *lmax;
                        let integral = lmax.fract() == 0.0 && hmin.fract() == 0.0;
                        let adjacent = integral && (*hmin - *lmax - 1.0).abs() < f64::EPSILON;
                        if !touches && !adjacent {
                            continue;
                        }
                        let (Some(lt), Some(ht)) = (
                            members.iter().find(|m| m.id == *lid),
                            members.iter().find(|m| m.id == *hid),
                        ) else {
                            continue;
                        };
                        if !types_intersect(lt, ht) {
                            continue;
                        }
                        out.push(ExhaustiveSuppressor {
                            id: id.to_string(),
                            is_composite,
                            dir_ref: r.to_string(),
                            field: (*field).to_string(),
                            low: ((*lid).to_string(), *lmax),
                            high: ((*hid).to_string(), *hmin),
                        });
                    }
                }
            }
        }
    };

    for t in trait_definitions {
        check(&t.id, t.unless.as_ref(), false);
    }
    for c in composite_rules {
        check(&c.id, c.unless.as_ref(), true);
    }
    out
}

pub(crate) fn find_dead_downgrades(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<DeadDowngrade> {
    let mut violations = Vec::new();

    let mut check = |id: &str,
                     unless: Option<&Vec<Condition>>,
                     downgrade: Option<&DowngradeConditions>,
                     is_composite: bool| {
        let (Some(unless), Some(downgrade)) = (unless, downgrade) else {
            return;
        };
        // `unless:` resolves against the file the rule matched in. A downgrade
        // that asks for a different scope is evaluating a different subject --
        // the enclosing archive, say -- so a shared id is not dead there: the
        // suppressor can miss at leaf scope while the downgrade still fires at
        // outer scope. Only same-scope clauses can kill each other.
        if downgrade.scope.is_some_and(|sc| sc != Scope::File) {
            return;
        }
        let suppressed: HashSet<&str> = unless.iter().filter_map(trait_ref).collect();
        if suppressed.is_empty() {
            return;
        }

        for (clause, list) in [
            ("any", downgrade.any.as_ref()),
            ("all", downgrade.all.as_ref()),
        ] {
            let Some(list) = list else { continue };
            if list.is_empty() {
                continue;
            }
            let dead: Vec<String> = list
                .iter()
                .filter_map(trait_ref)
                .filter(|r| suppressed.contains(r))
                .map(String::from)
                .collect();
            if dead.is_empty() {
                continue;
            }
            // `all:` needs every leg, so a single suppressed leg kills the clause.
            let whole_clause = clause == "all" || dead.len() == list.len();
            violations.push(DeadDowngrade {
                id: id.to_string(),
                is_composite,
                clause,
                refs: dead,
                whole_clause,
            });
        }
    };

    for t in trait_definitions {
        check(
            t.id.as_str(),
            t.unless.as_ref(),
            t.downgrade.as_ref(),
            false,
        );
    }
    for r in composite_rules {
        check(r.id.as_str(), r.unless.as_ref(), r.downgrade.as_ref(), true);
    }

    violations
}

/// A suppression (`unless:` or `downgrade:`) that cites a signature finding
/// outside `metadata/signature/verified/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnverifiedSignatureSuppressor {
    pub(crate) id: String,
    pub(crate) clause: &'static str,
    pub(crate) reference: String,
}

/// The id of the validator below, which `exempt:` names.
pub(crate) const UNVERIFIED_SIGNATURE_SUPPRESSOR: &str = "unverified-signature-suppressor";

/// Find suppressions that trust a signature nothing verified. Only
/// `metadata/signature/verified/` proves a signer; every other state is a
/// claim its maker chose, so a rule excused by it is excused by the attacker.
/// The bare parent `metadata/signature/` counts too: it matches every state.
/// Detection legs (`all:`, `any:`) may cite any state. A rule that must cite
/// another state in a suppression names this validator in `exempt:`.
pub(crate) fn find_unverified_signature_suppressors(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<UnverifiedSignatureSuppressor> {
    fn trusts_unverified(reference: &str) -> bool {
        (reference == "metadata/signature" || reference.starts_with("metadata/signature/"))
            && !reference.starts_with("metadata/signature/verified/")
    }
    let mut found = Vec::new();
    let mut check =
        |id: &str, unless: Option<&Vec<Condition>>, downgrade: Option<&DowngradeConditions>| {
            let downgrade = downgrade
                .into_iter()
                .flat_map(|d| d.any.iter().flatten().chain(d.all.iter().flatten()));
            let clauses = unless
                .into_iter()
                .flatten()
                .map(|c| ("unless", c))
                .chain(downgrade.map(|c| ("downgrade", c)));
            for (clause, condition) in clauses {
                if let Some(reference) = trait_ref(condition)
                    && trusts_unverified(reference)
                {
                    found.push(UnverifiedSignatureSuppressor {
                        id: id.to_string(),
                        clause,
                        reference: reference.to_string(),
                    });
                }
            }
        };
    for t in trait_definitions {
        if !t.is_exempt(UNVERIFIED_SIGNATURE_SUPPRESSOR) {
            check(t.id.as_str(), t.unless.as_ref(), t.downgrade.as_ref());
        }
    }
    for r in composite_rules {
        if !r.is_exempt(UNVERIFIED_SIGNATURE_SUPPRESSOR) {
            check(r.id.as_str(), r.unless.as_ref(), r.downgrade.as_ref());
        }
    }
    found
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
        d.any.as_ref().map_or(0, Vec::len) + d.all.as_ref().map_or(0, Vec::len)
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
/// and bounds the walk to one visit per reference (so cycles terminate).
///
/// Every aggregator composite is expanded into its underlying conditions, regardless of
/// how widely it is reused: the recursive cap measures one rule's *exception burden*, and
/// a rule that suppresses on a 45-leg cluster carries that weight whether or not the
/// cluster is shared. Sharing is a DRY property of the composite, not a discount on the
/// burden it imposes on each referrer.
/// Composite lookup for suppression expansion.
///
/// Rule ids are directory-qualified when loaded, but the ids written inside
/// `unless:`/`downgrade:` stay as the author wrote them, and the engine resolves a bare
/// one to a rule at runtime: the referrer's own directory first, then a unique short
/// name. Looking a bare reference up by exact string misses every aggregator it names,
/// so it was counted as a single leaf and the aggregator's real burden went unchecked.
struct SuppressionIndex<'a> {
    composites: HashMap<&'a str, &'a CompositeTrait>,
    by_leaf: HashMap<&'a str, Vec<&'a str>>,
}

impl<'a> SuppressionIndex<'a> {
    fn new(rules: &'a [CompositeTrait]) -> Self {
        let mut by_leaf: HashMap<&'a str, Vec<&'a str>> = HashMap::new();
        for r in rules {
            let id = r.id.as_str();
            let leaf = id.rsplit_once("::").map_or(id, |(_, leaf)| leaf);
            by_leaf.entry(leaf).or_default().push(id);
        }
        Self {
            composites: rules.iter().map(|r| (r.id.as_str(), r)).collect(),
            by_leaf,
        }
    }

    /// The composite id a reference names, or the reference itself when it names no
    /// composite. An exact id always wins, so a qualified reference is unaffected.
    fn resolve(&self, raw: &'a str, referrer: &str) -> &'a str {
        if self.composites.contains_key(raw) || raw.contains("::") || raw.contains('/') {
            return raw;
        }
        if let Some((directory, _)) = referrer.rsplit_once("::")
            && let Some((key, _)) = self
                .composites
                .get_key_value(format!("{directory}::{raw}").as_str())
        {
            return key;
        }
        match self.by_leaf.get(raw).map(Vec::as_slice) {
            Some([only]) => only,
            _ => raw,
        }
    }
}

struct SuppressionExpander<'a> {
    index: &'a SuppressionIndex<'a>,
    referrer: String,
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
        let key = self.index.resolve(id.as_str(), &self.referrer);

        // A `*-known-benign-context` composite is a named exception group, not an
        // ad-hoc reference: authors write one to hold "the benign shapes this
        // idiom legitimately has" and point every affected rule at it, which is
        // exactly the fix this validator's own message recommends when a rule's
        // own suppressions run long. Expanding through it counted the group's
        // *membership* as the referrer's burden, so growing the shared list (or
        // widening reuse) tripped the cap on every referrer -- the two rules that
        // did this, `js-global-object-alias-assignment` and
        // `js-global-object-self-assignment`, were penalized for taking the
        // advice. Treat it as opaque, like a directory reference: one unit,
        // regardless of how many benign shapes it enumerates internally.
        if key.ends_with("known-benign-context") {
            return SuppressionBranch {
                label: format!("{key} (named exception group)"),
                count: 1,
                children: Vec::new(),
            };
        }

        // A `metadata/` property or a `well-known/` identity named in `unless:` is a
        // stated fact about the artifact ("this file is a test", "this package is
        // octokit"), one condition however many ways the fact is recognized. Expanding it
        // charged the referrer with the property's evidence -- 84 legs for the shared
        // test-file classifier -- as if each were a carve-out. Exception lists
        // (`exception`, `component`) in those tiers still expand: they are carve-outs.
        if let Some(c) = self.index.composites.get(key)
            && (key.starts_with("metadata/") || key.starts_with("well-known/"))
            && c.crit >= crate::types::Criticality::Baseline
        {
            return if self.seen_leaves.insert(key) {
                SuppressionBranch {
                    label: format!("{key} (stated property or identity)"),
                    count: 1,
                    children: Vec::new(),
                }
            } else {
                SuppressionBranch {
                    label: format!("{key} (dup)"),
                    count: 0,
                    children: Vec::new(),
                }
            };
        }

        // A suspicious or hostile composite named in `unless:` is a verdict, not an
        // exception list: the rule stands down because a stronger detection already
        // fired on the file, which is one condition however many legs that
        // detection has. Expanding it charged the referrer with every leg of the
        // detection -- 73 for one wallet-stealer rule -- as if each were a benign
        // carve-out. (Unmarked composites default to notable and are often benign
        // groups, so only the stronger tiers are taken as verdicts.)
        if let Some(c) = self.index.composites.get(key)
            && c.crit >= crate::types::Criticality::Suspicious
        {
            return if self.seen_leaves.insert(key) {
                SuppressionBranch {
                    label: format!("{key} (detection verdict)"),
                    count: 1,
                    children: Vec::new(),
                }
            } else {
                SuppressionBranch {
                    label: format!("{key} (dup)"),
                    count: 0,
                    children: Vec::new(),
                }
            };
        }

        // An aggregator composite expands into its legs; a leaf or directory reference
        // (no exact composite) counts as one.
        if self.index.composites.contains_key(key) {
            if !self.seen_aggregators.insert(key) {
                return SuppressionBranch {
                    label: format!("{key} (already counted)"),
                    count: 0,
                    children: Vec::new(),
                };
            }
            let c = self.index.composites[key];
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
/// one, as does a detection verdict (suspicious+), a named exception group, and a
/// `metadata/` property or `well-known/` identity that is not itself an exception list. Everything is deduplicated across the rule, so cycles terminate and a shared
/// aggregator is counted once.
fn expand_suppressions<'a>(
    unless: Option<&'a Vec<Condition>>,
    downgrade: Option<&'a DowngradeConditions>,
    index: &'a SuppressionIndex<'a>,
    referrer: &str,
) -> (usize, Vec<SuppressionBranch>) {
    let mut expander = SuppressionExpander {
        index,
        referrer: referrer.to_string(),
        seen_aggregators: HashSet::new(),
        seen_leaves: HashSet::new(),
    };

    let downgrade_lists = downgrade
        .into_iter()
        .flat_map(|d| [d.any.as_ref(), d.all.as_ref()]);
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
pub(crate) const MAX_OWN_SUPPRESSIONS: usize = 10;

/// Effective exceptions a rule may carry once aggregator references in its
/// `unless:`/`downgrade:` are recursively expanded. Higher than the direct cap because
/// one reference can legitimately stand in for a handful of related benign indicators;
/// this only catches rules whose true exception burden is runaway.
pub(crate) const MAX_AGGREGATE_SUPPRESSIONS: usize = 48;

/// Find traits/rules with excessive `unless:`/`downgrade:` suppressions.
///
/// Both limits look only at a rule's own `unless:`/`downgrade:` — never at its `all:`/
/// `any:` matching conditions. Flagged on either:
///
/// - **Own** (`MAX_OWN_SUPPRESSIONS`, 10): `unless:`/`downgrade:` entries written
///   literally on the rule. A rule this heavily patched usually has poor precision and
///   should be improved rather than suppressed.
/// - **Expanded** (`MAX_AGGREGATE_SUPPRESSIONS`, 48): the effective exception count once
///   any `unless:`/`downgrade:` entry that references an aggregator composite is
///   recursively expanded to its underlying conditions. This catches a large exception
///   list hidden behind one reference, even when the aggregator is shared by several
///   rules — sharing is a DRY property of the composite, not a discount on the burden it
///   imposes on each referrer. Leaf and directory references each count as one.
#[must_use]
pub(crate) fn find_excessive_skip_conditions<'a>(
    trait_definitions: &'a [TraitDefinition],
    composite_rules: &'a [CompositeTrait],
) -> Vec<ExcessiveSkip> {
    let index = SuppressionIndex::new(composite_rules);

    let mut violations = Vec::new();

    let mut flag = |id: &'a str,
                    unless: Option<&'a Vec<Condition>>,
                    downgrade: Option<&'a DowngradeConditions>,
                    is_composite: bool| {
        let (u, d) = direct_suppression_counts(unless, downgrade);
        let own = u + d;
        let (expanded, branches) = expand_suppressions(unless, downgrade, &index, id);
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

/// Find hex conditions that the matcher cannot parse.
///
/// A malformed hex pattern is a detection-integrity failure: evaluation would
/// otherwise degrade to a runtime no-match. Keep this validator hard so invalid
/// rules cannot load into a silently dead trait set.
#[must_use]
pub(crate) fn find_invalid_hex_patterns(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, String, String)> {
    trait_definitions
        .iter()
        .filter_map(|trait_def| {
            let Condition::Hex(HexQuery { pattern, .. }) = &trait_def.r#if else {
                return None;
            };
            crate::composite_rules::evaluators::validate_hex_pattern(pattern)
                .err()
                .map(|error| (trait_def.id.clone(), pattern.clone(), error))
        })
        .collect()
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
    fn is_hex_alternation(token: &str) -> bool {
        let Some(inner) = token.strip_prefix('(').and_then(|t| t.strip_suffix(')')) else {
            return false;
        };
        !inner.is_empty()
            && inner
                .split('|')
                .all(|b| b.len() == 2 && b.chars().all(|c| c.is_ascii_hexdigit() || c == '?'))
    }

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
            // Accept alternations ((5C|5D)) — one constrained byte regardless
            // of branch count; mirrors the matcher's floor in evaluators/yara.rs
            (token.len() == 2 && token.chars().all(|c| c.is_ascii_hexdigit() || c == '?'))
                || is_hex_alternation(token)
        })
        .count()
}
