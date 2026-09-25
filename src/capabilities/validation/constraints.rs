//! Logic constraint validation.
//!
//! This module validates logical constraints in rules, detecting impossible
//! or contradictory configurations that would make rules unsatisfiable.

use std::collections::{HashMap, HashSet};

use crate::capabilities::models::{RawCompositeRule, RawTraitDefinition, TraitDefaults};
use crate::capabilities::validation::shared::is_limited_byte_range;
use crate::composite_rules::{
    CompositeTrait, Condition, DowngradeConditions, FileType, KvQuery, Scope, TraitDefinition,
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
/// `downgrade.none` is inverted — an entry there is not dead — and is skipped.
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
/// and bounds the walk to one visit per reference (so cycles terminate).
///
/// Every aggregator composite is expanded into its underlying conditions, regardless of
/// how widely it is reused: the recursive cap measures one rule's *exception burden*, and
/// a rule that suppresses on a 45-leg cluster carries that weight whether or not the
/// cluster is shared. Sharing is a DRY property of the composite, not a discount on the
/// burden it imposes on each referrer.
struct SuppressionExpander<'a> {
    composite_map: &'a HashMap<&'a str, &'a CompositeTrait>,
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

        // An aggregator composite expands into its legs; a leaf or directory reference
        // (no exact composite) counts as one.
        if self.composite_map.contains_key(key) {
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
) -> (usize, Vec<SuppressionBranch>) {
    let mut expander = SuppressionExpander {
        composite_map,
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
const MAX_OWN_SUPPRESSIONS: usize = 10;

/// Effective exceptions a rule may carry once aggregator references in its
/// `unless:`/`downgrade:` are recursively expanded. Higher than the direct cap because
/// one reference can legitimately stand in for a handful of related benign indicators;
/// this only catches rules whose true exception burden is runaway.
const MAX_AGGREGATE_SUPPRESSIONS: usize = 32;

/// Find traits/rules with excessive `unless:`/`downgrade:` suppressions.
///
/// Both limits look only at a rule's own `unless:`/`downgrade:` — never at its `all:`/
/// `any:` matching conditions. Flagged on either:
///
/// - **Own** (`MAX_OWN_SUPPRESSIONS`, 10): `unless:`/`downgrade:` entries written
///   literally on the rule. A rule this heavily patched usually has poor precision and
///   should be improved rather than suppressed.
/// - **Expanded** (`MAX_AGGREGATE_SUPPRESSIONS`, 32): the effective exception count once
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
    let composite_map: HashMap<&'a str, &'a CompositeTrait> =
        composite_rules.iter().map(|r| (r.id.as_str(), r)).collect();

    let mut violations = Vec::new();

    let mut flag = |id: &'a str,
                    unless: Option<&'a Vec<Condition>>,
                    downgrade: Option<&'a DowngradeConditions>,
                    is_composite: bool| {
        let (u, d) = direct_suppression_counts(unless, downgrade);
        let own = u + d;
        let (expanded, branches) = expand_suppressions(unless, downgrade, &composite_map);
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

/// Find component traits that are never referenced by any composite rule or atomic trait.
///
/// Component traits (`crit: component`) are building blocks that should only exist to be
/// referenced by composite rules or by other traits via `if: id:` form. If a component
/// isn't referenced anywhere, it's "orphaned" and serves no purpose.
///
/// Returns: `Vec<(trait_id, source_file)>`
#[must_use]
/// Collect a composite's positive (`all:`/`any:`) trait references.
///
/// `unless:`, `none:`, and `downgrade:` are exclusions and deliberately ignored —
/// they suppress a match, they never supply the purpose-defining evidence.
fn positive_trait_refs(rule: &CompositeTrait) -> Vec<String> {
    let mut refs = Vec::new();
    for conditions in [rule.all.as_ref(), rule.any.as_ref()].into_iter().flatten() {
        for cond in conditions {
            if let Condition::Trait { id } = cond {
                refs.push(id.clone());
            }
        }
    }
    refs
}

/// Every id a reference can name, indexed so that resolving one is a lookup.
///
/// Resolution used to scan every id in the tree for each distinct reference.
/// With ~40,000 ids and the tens of thousands of references the conviction
/// checks follow, that scan was over a minute of `cleave validate`, all of it
/// on the main thread.
pub(super) struct ReferenceIndex<'a> {
    ids: Vec<&'a str>,
    /// Positions into `ids`, ordered by id: exact and directory references
    /// are prefix ranges of it.
    sorted: Vec<usize>,
    /// Positions into `ids`, keyed by the text after each id's last `:` or
    /// `/`, which is where a short-name reference must match.
    by_tail: HashMap<&'a str, Vec<usize>>,
}

/// The text after the last `:` or `/`, or all of `id` when it has neither.
fn tail(id: &str) -> &str {
    id.rsplit([':', '/']).next().unwrap_or(id)
}

impl<'a> ReferenceIndex<'a> {
    pub(super) fn new(ids: Vec<&'a str>) -> Self {
        let mut sorted: Vec<usize> = (0..ids.len()).collect();
        sorted.sort_unstable_by_key(|&i| ids[i]);
        let mut by_tail: HashMap<&'a str, Vec<usize>> = HashMap::new();
        for (i, id) in ids.iter().enumerate() {
            by_tail.entry(tail(id)).or_default().push(i);
        }
        Self {
            ids,
            sorted,
            by_tail,
        }
    }

    /// Resolve a reference to the concrete ids it matches, mirroring the
    /// runtime resolver in `evaluate_merged`: an exact `::` reference matches
    /// one id; a bare short name (no `/`) suffix-matches `::name`/`/name`; a
    /// directory reference (has `/`, no `::`) prefix-matches the id itself,
    /// `dir::*`, and the whole `dir/*` subtree. A trailing slash is trimmed
    /// first. Matches come back in the order the ids were given.
    pub(super) fn resolve(&self, reference: &str) -> Vec<&'a str> {
        let id = reference.trim_end_matches('/');
        let mut hits: Vec<usize> = if id.contains("::") {
            self.starting_with(id)
                .filter(|&i| self.ids[i] == id)
                .collect()
        } else if !id.contains('/') {
            let (suffix_new, suffix_legacy) = (format!("::{id}"), format!("/{id}"));
            self.by_tail
                .get(tail(id))
                .into_iter()
                .flatten()
                .copied()
                .filter(|&i| {
                    let f = self.ids[i];
                    f.ends_with(&suffix_new) || f.ends_with(&suffix_legacy)
                })
                .collect()
        } else {
            let (prefix_new, prefix_legacy) = (format!("{id}::"), format!("{id}/"));
            self.starting_with(id)
                .filter(|&i| {
                    let f = self.ids[i];
                    f == id || f.starts_with(&prefix_new) || f.starts_with(&prefix_legacy)
                })
                .collect()
        };
        hits.sort_unstable();
        hits.into_iter().map(|i| self.ids[i]).collect()
    }

    /// Positions of the ids that begin with `prefix`.
    fn starting_with<'s>(&'s self, prefix: &'s str) -> impl Iterator<Item = usize> + 's {
        let start = self.sorted.partition_point(|&i| self.ids[i] < prefix);
        self.sorted[start..]
            .iter()
            .copied()
            .take_while(move |&i| self.ids[i].starts_with(prefix))
    }
}

/// Find `crit: hostile` composites that reference fewer than two distinct
/// notable-or-higher evidence legs anywhere in their positive (`all:`/`any:`)
/// reference tree.
///
/// Every genuine hostile pattern should rest on at least two legs an analyst would
/// want surfaced on their own — communications, code-execution, crypto, encoding,
/// privilege-escalation, sensitive-file, registry, or persistence capabilities
/// (the behaviours that earn at least `notable` per TAXONOMY.md). A hostile
/// composite assembled from fewer than two such legs signals that purpose-defining
/// capability has been buried at the wrong tier, or that the rule is low quality.
///
/// Resolution mirrors the loader: trait ids are fully qualified (`dir::id`),
/// directory references (`dir/path`, no `::`) expand to every id under that prefix,
/// and a leg that is itself a composite is followed transitively.
///
/// Returns the ids of the offending hostile composites.
#[must_use]
pub(crate) fn find_hostile_composites_with_too_few_notable_legs(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<String> {
    use crate::types::Criticality;

    // Effective criticality (defaults already applied at load) for every trait and
    // composite, keyed by full id.
    let mut crit_by_id: HashMap<&str, Criticality> = HashMap::new();
    for t in trait_definitions {
        crit_by_id.insert(t.id.as_str(), t.crit);
    }
    for c in composite_rules {
        crit_by_id.insert(c.id.as_str(), c.crit);
    }
    let index = ReferenceIndex::new(crit_by_id.keys().copied().collect());
    let composite_by_id: HashMap<&str, &CompositeTrait> =
        composite_rules.iter().map(|c| (c.id.as_str(), c)).collect();

    fn add_limited(out: &mut Vec<String>, values: impl IntoIterator<Item = String>) {
        for value in values {
            if !out.contains(&value) {
                out.push(value);
                if out.len() == 2 {
                    break;
                }
            }
        }
    }

    fn collect_notable_for_id(
        id: &str,
        crit_by_id: &HashMap<&str, Criticality>,
        index: &ReferenceIndex<'_>,
        composite_by_id: &HashMap<&str, &CompositeTrait>,
        reference_cache: &mut HashMap<String, Vec<String>>,
        terminal_cache: &mut HashMap<String, Vec<String>>,
        visiting: &mut HashSet<String>,
    ) -> Vec<String> {
        if let Some(cached) = terminal_cache.get(id) {
            return cached.clone();
        }
        if !visiting.insert(id.to_string()) {
            return Vec::new();
        }

        let mut terminals = Vec::new();
        if let Some(sub) = composite_by_id.get(id) {
            for child in positive_trait_refs(sub) {
                let child_terms = collect_notable_for_reference(
                    &child,
                    crit_by_id,
                    index,
                    composite_by_id,
                    reference_cache,
                    terminal_cache,
                    visiting,
                );
                add_limited(&mut terminals, child_terms);
                if terminals.len() == 2 {
                    break;
                }
            }
            // A named notable composite with no notable terminal children is
            // itself the strongest honest evidence available.
            if terminals.is_empty()
                && crit_by_id
                    .get(id)
                    .is_some_and(|crit| *crit >= Criticality::Notable)
            {
                terminals.push(id.to_string());
            }
        } else if crit_by_id
            .get(id)
            .is_some_and(|crit| *crit >= Criticality::Notable)
        {
            terminals.push(id.to_string());
        }

        visiting.remove(id);
        terminal_cache.insert(id.to_string(), terminals.clone());
        terminals
    }

    fn collect_notable_for_reference(
        reference: &str,
        crit_by_id: &HashMap<&str, Criticality>,
        index: &ReferenceIndex<'_>,
        composite_by_id: &HashMap<&str, &CompositeTrait>,
        reference_cache: &mut HashMap<String, Vec<String>>,
        terminal_cache: &mut HashMap<String, Vec<String>>,
        visiting: &mut HashSet<String>,
    ) -> Vec<String> {
        let key = reference.trim_end_matches('/').to_string();
        let resolved = if let Some(cached) = reference_cache.get(&key) {
            cached.clone()
        } else {
            let ids = if key.contains("::") {
                crit_by_id
                    .contains_key(key.as_str())
                    .then_some(vec![key.clone()])
                    .unwrap_or_default()
            } else {
                index.resolve(&key).into_iter().map(str::to_owned).collect()
            };
            reference_cache.insert(key, ids.clone());
            ids
        };

        let mut terminals = Vec::new();
        for id in resolved {
            add_limited(
                &mut terminals,
                collect_notable_for_id(
                    &id,
                    crit_by_id,
                    index,
                    composite_by_id,
                    reference_cache,
                    terminal_cache,
                    visiting,
                ),
            );
            if terminals.len() == 2 {
                break;
            }
        }
        terminals
    }

    let mut violations = Vec::new();
    let mut reference_cache = HashMap::new();
    let mut terminal_cache = HashMap::new();
    for rule in composite_rules {
        if rule.crit != Criticality::Hostile {
            continue;
        }

        let mut terminals = Vec::new();
        let mut visiting = HashSet::new();
        for reference in positive_trait_refs(rule) {
            add_limited(
                &mut terminals,
                collect_notable_for_reference(
                    &reference,
                    &crit_by_id,
                    &index,
                    &composite_by_id,
                    &mut reference_cache,
                    &mut terminal_cache,
                    &mut visiting,
                ),
            );
            if terminals.len() == 2 {
                break;
            }
        }

        if terminals.len() < 2 {
            violations.push(rule.id.clone());
        }
    }
    violations
}

/// Does directory reference `dir` cover trait id `trait_id`?
///
/// Two details the naive `format!("{dir}::")` prefix missed, both of which made
/// a referenced component look orphaned:
/// * the reference is usually written with a trailing slash
///   (`metadata/file/catalog/identity/`), which turned the prefix into
///   `.../identity/::` and matched nothing;
/// * a directory also covers traits in its *sub*directories, which a `::`-only
///   prefix never matched.
fn directory_covers(dir: &str, trait_id: &str) -> bool {
    let dir = dir.trim_end_matches('/');
    trait_id
        .strip_prefix(dir)
        .is_some_and(|rest| rest.starts_with("::") || rest.starts_with('/'))
}

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
                        for component_id in &component_ids {
                            if directory_covers(id, component_id) {
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
                        for component_id in &component_ids {
                            if directory_covers(id, component_id) {
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
                        for component_id in &component_ids {
                            if directory_covers(id, component_id) {
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

/// Find text/raw conditions with `length_min`/`length_max` but no `regex:`.
///
/// The bounds constrain the regex match span (the cheap replacement for
/// counted repetitions like `{4000,}`); with `exact:`/`substr:`/`word:` the
/// match length is fixed by the pattern, so bounds are a no-op at best.
#[must_use]
pub(crate) fn find_length_bounds_without_regex(
    trait_definitions: &[TraitDefinition],
) -> Vec<String> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        let invalid = match &t.r#if {
            Condition::Text(TextQuery {
                regex,
                length_min,
                length_max,
                ..
            })
            | Condition::Raw(RawQuery {
                regex,
                length_min,
                length_max,
                ..
            }) => (length_min.is_some() || length_max.is_some()) && regex.is_none(),
            _ => false,
        };

        if invalid {
            violations.push(format!(
                "{}: `length_min`/`length_max` on text/raw is only valid with `regex:`",
                t.id,
            ));
        }
    }

    violations
}

/// Find conditions with `length_min > length_max` — a bound pair no value or
/// match span can ever satisfy, so the rule never fires.
///
/// Returns `(rule_id, min, max)`.
#[must_use]
pub(crate) fn find_impossible_length_bounds(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, usize, usize)> {
    let mut violations = Vec::new();

    for t in trait_definitions {
        let bounds = match &t.r#if {
            Condition::Text(TextQuery {
                length_min,
                length_max,
                ..
            })
            | Condition::Raw(RawQuery {
                length_min,
                length_max,
                ..
            })
            | Condition::Kv(KvQuery {
                length_min,
                length_max,
                ..
            }) => (*length_min, *length_max),
            Condition::Section(SectionQuery {
                length_min,
                length_max,
                ..
            }) => (
                length_min.map(|min| usize::try_from(min).unwrap_or(usize::MAX)),
                length_max.map(|max| usize::try_from(max).unwrap_or(usize::MAX)),
            ),
            _ => (None, None),
        };

        if let (Some(min), Some(max)) = bounds
            && min > max
        {
            violations.push((t.id.clone(), min, max));
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
/// The named file-type groups rules may target, and the only place they are
/// defined for validation purposes.
///
/// **Every file type appears in exactly one group.** Group membership is how
/// `for:` breadth is judged, and a type in two groups makes the judgement
/// ambiguous: while Dockerfile sat in both `manifests` and `build`, naming
/// either complete group read as a hand-written enumeration because the set
/// "touched" the other group through that one shared type. The invariant is
/// enforced by `named_groups_are_disjoint`.
const BINARIES: &[FileType] = &[
    FileType::Elf,
    FileType::Macho,
    FileType::Pe,
    FileType::Class,
    FileType::Pyc,
    FileType::Beam,
    FileType::Wasm,
    FileType::Dex,
    FileType::StaticLib,
];
const SCRIPTS: &[FileType] = &[
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
    FileType::Mirc,
    FileType::IrcII,
];
const SOURCE: &[FileType] = &[
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
    FileType::Clojure,
];
const MANIFESTS: &[FileType] = &[
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
    FileType::Nib,
    FileType::Lnk,
];
// Executable build logic, as opposed to the declarative metadata in
// `manifests`. Overlaps it on Dockerfile, which is both.
const BUILD: &[FileType] = &[
    FileType::Makefile,
    FileType::Cmake,
    FileType::Pbxproj,
    FileType::Dockerfile,
];
const DOCUMENTS: &[FileType] = &[
    FileType::Pdf,
    FileType::Rtf,
    FileType::Html,
    FileType::Text,
    FileType::OleDoc,
    FileType::Ooxml,
];
// `Text` lives in `documents` alongside the other readable formats; it was in
// both groups, which the one-group-per-type invariant forbids. These tables
// only decide whether a `for:` list reads as named groups — expansion happens
// in capabilities/parsing.rs — so moving it changes no rule's matching.
// `Ipa` is NOT here: it carries the `#[archive]` marker (an .ipa is a ZIP
// container) and now that ARCHIVES is derived from that same marker set
// instead of hand-duplicated, keeping Ipa in both groups would violate the
// one-group-per-type invariant below.
const DATA: &[FileType] = &[FileType::Data];
// Derived from the same `#[archive]` enum markers that drive `is_archive()`
// and the `archives` group expansion in capabilities/parsing.rs, instead of
// hand-duplicating the member list here. The two lists had drifted before
// (this one carried `Apk` while the macro-generated family did not, because
// the old `Apk` variant lacked the `#[archive]` marker) -- deriving it
// removes that class of bug permanently.
const ARCHIVES: &[FileType] = FileType::archive_family_types();
// Every passive container that can carry a payload — fonts, raster and
// vector images, audio, video. They share one `media.*` fact namespace
// precisely so a carrier rule is written once rather than a dozen times.
const MEDIA: &[FileType] = &[
    FileType::Font,
    FileType::Png,
    FileType::Jpeg,
    FileType::Svg,
    FileType::Wav,
    FileType::Aiff,
    FileType::Mp3,
    FileType::Mp4,
    FileType::Ico,
    FileType::Gif,
    FileType::Bmp,
    FileType::Webp,
];
pub(crate) const ALL_GROUPS: &[(&[FileType], &str)] = &[
    (MEDIA, "media"),
    (BINARIES, "binaries"),
    (SCRIPTS, "scripts"),
    (SOURCE, "source"),
    (MANIFESTS, "manifests"),
    (BUILD, "build"),
    (DOCUMENTS, "documents"),
    (DATA, "data"),
    (ARCHIVES, "archives"),
];

/// Source file path fragments where an explicit `for:` list spanning most or
/// all of the archive-type family is permitted despite `archives` not being a
/// usable `for:` group (see [`ALL_GROUPS`] and the `archives` ban in
/// `capabilities::parsing`). Each of these checks a structural, per-container
/// fact -- member count, entropy, a path pattern inside `archive.members`,
/// extension-vs-content consistency -- that the archive analyzer computes
/// identically no matter which specific archive format produced the
/// container, so enumerating the whole family is the correct targeting, not
/// an author who forgot a group. Entries are file paths, not directories: a
/// sibling file in the same directory that targets a specific format is not
/// covered just because it shares a path prefix.
pub(crate) const BROAD_ARCHIVE_FILETYPE_ALLOWLIST: &[&str] = &[
    // Container-shape facts (member count, compression ratio, executable/script
    // member counts, misplaced-executable heuristic, parse errors): all read
    // metrics the archive analyzer emits the same way for every format.
    "metadata/file/archive/archive.yaml",
    "metadata/file/archive/many-members.yaml",
    // Extension-vs-detected-format consistency is a property of "this file
    // claims to be format X but the bytes say Y", which is meaningful for any
    // archive format on either side of the mismatch.
    "metadata/file/extension/identity/archive-mismatch.yaml",
    // `archive.path_traversal_count` is a central-directory fact with the same
    // meaning (a member path that escapes the extraction root) regardless of
    // container format.
    "metadata/package/files/archive-member/shape.yaml",
    // `file.entropy` is computed over raw bytes; it has no dependency on the
    // container format wrapping them.
    "metadata/file/data-blob/near-maximum-entropy.yaml",
    // These search `archive.members[*].path` for a literal filename/pattern
    // (go.mod, Package.swift, a Vim swap file, a vendored node_modules tree):
    // the member listing has the same shape for every archive format cleave
    // extracts, so the check behaves identically across the family.
    "metadata/package/files/included/package.yaml",
    // `nested-source-package-context` requires two shell-scoped legs
    // (`packaging/PKGBUILD`, `packaging/mktarball.sh` path matches) that fire
    // on member paths, not on the container's own format.
    "metadata/build/archive/source.yaml",
];

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
/// Traits that already use the broadest expressible named-group union are exempt —
/// listing every member type again would only restate the groups.
///
/// Returns: `Vec<(id, count, suggestion, is_composite)>`
#[must_use]
pub(crate) fn find_excessive_file_types(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, usize, &'static str, bool)> {
    const MIN_FOR_WARNING: usize = 9;

    let all_groups = ALL_GROUPS;

    // Returns true if `types` is a union of complete named groups.
    //
    // A type set is expressible when every type in it is covered by at least
    // one group that lies *entirely* inside the set. The earlier form asked
    // the opposite question — that every group the set *touches* be complete —
    // which is wrong as soon as one file type belongs to two groups. Dockerfile
    // is in both `manifests` and `build`, so `for: [manifests]` "touched"
    // `build` through that single shared type and was reported as an
    // unexpressible enumeration despite being exactly one named group; the same
    // happened to `for: [carriers]`, which shares Xml with `manifests`.
    // Asking what covers the set makes overlapping groups work: a shared type
    // is satisfied by whichever group is fully present.
    let is_group_expressible = |types: &[FileType]| -> bool {
        let type_set: std::collections::HashSet<&FileType> = types.iter().collect();
        let covered: std::collections::HashSet<&FileType> = all_groups
            .iter()
            .filter(|(group, _)| group.iter().all(|ft| type_set.contains(ft)))
            .flat_map(|(group, _)| group.iter())
            .collect();
        type_set.iter().all(|ft| covered.contains(*ft))
    };

    // Only called when is_group_expressible returned false — suggest combining
    // named groups rather than listing every type (or the rejected `for: [all]`).
    let suggest = |_types: &[FileType]| -> &'static str {
        "combine named groups (binaries, scripts, source, manifests, build, documents, media, data)"
    };

    let is_allowlisted = |defined_in: &std::path::Path| -> bool {
        let source = defined_in.to_string_lossy();
        BROAD_ARCHIVE_FILETYPE_ALLOWLIST
            .iter()
            .any(|suffix| source.contains(suffix))
    };

    let mut violations = Vec::new();

    for t in trait_definitions {
        // Skip if the author already used named groups — platform filtering may
        // have removed some members, making the expanded set look like a partial
        // group, but the YAML source is correct.
        if t.for_from_groups
            || t.r#for.contains(&FileType::All)
            || is_group_expressible(&t.r#for)
            || is_allowlisted(&t.defined_in)
        {
            continue;
        }
        if t.r#for.len() >= MIN_FOR_WARNING {
            violations.push((t.id.clone(), t.r#for.len(), suggest(&t.r#for), false));
        }
    }

    for r in composite_rules {
        if r.for_from_groups
            || r.r#for.contains(&FileType::All)
            || is_group_expressible(&r.r#for)
            || is_allowlisted(&r.defined_in)
        {
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

/// Direct `downgrade:` entries allowed on a rule declared `notable`.
///
/// A `downgrade:` on a notable rule lands it on `Baseline`, and `Baseline`
/// means something specific: functionality nearly every program has. A clear
/// behavior does not become universal because of where it sits — `pkill <name>`
/// terminates a process by name in shipped code and in a test file alike. So
/// crossing that line is a claim about the matcher, not the context, and it
/// should be rare and argued rather than reached for as routine FP control.
pub(crate) const MAX_NOTABLE_DOWNGRADE_DIRECT: usize = 4;

/// Same limit once aggregator references are expanded.
///
/// A single directory reference can stand for hundreds of traits — one
/// `metadata/package/testing/presence/harness/` leg expands to 126, any one of
/// which fires the downgrade. Counting only the literal entries would let a
/// rule hide an unbounded trigger set behind one line.
pub(crate) const MAX_NOTABLE_DOWNGRADE_EXPANDED: usize = 8;

/// A rule declared `notable` whose `downgrade:` reaches too broadly.
pub(crate) struct BroadNotableDowngrade {
    /// The offending rule's ID.
    pub id: String,
    /// True for a composite rule, false for an atomic trait.
    pub is_composite: bool,
    /// `downgrade:` entries written literally on the rule.
    pub direct: usize,
    /// Distinct exceptions once aggregator references are expanded.
    pub expanded: usize,
}

/// Find `notable` rules whose `downgrade:` crosses into `Baseline` on too broad
/// a trigger set.
///
/// Sibling of [`find_excessive_skip_conditions`], and deliberately the same
/// shape — a direct cap plus an expanded cap — but scoped to the one transition
/// that reclassifies a behavior rather than merely de-emphasizing it. Rules at
/// `suspicious`/`hostile` are untouched: those downgrades land on `notable` or
/// `suspicious`, which say nothing false about the matcher.
#[must_use]
pub(crate) fn find_broad_notable_downgrades<'a>(
    trait_definitions: &'a [TraitDefinition],
    composite_rules: &'a [CompositeTrait],
) -> Vec<BroadNotableDowngrade> {
    let composite_map: HashMap<&'a str, &'a CompositeTrait> =
        composite_rules.iter().map(|r| (r.id.as_str(), r)).collect();

    let mut violations = Vec::new();

    let mut flag = |id: &'a str,
                    crit: crate::types::Criticality,
                    downgrade: Option<&'a DowngradeConditions>,
                    is_composite: bool| {
        if crit != crate::types::Criticality::Notable {
            return;
        }
        let Some(downgrade) = downgrade else { return };
        // Breadth is how many *independent* things can fire the downgrade, so
        // `any:`/`none:` legs count one each while a whole `all:` block counts
        // once: its legs must all match, which narrows the trigger rather than
        // widening it. Summing them punished well-targeted conjunctions like
        // "many imports AND a graphics import AND one of three runtime markers".
        let all_len = downgrade.all.as_ref().map_or(0, Vec::len);
        let widening = DowngradeConditions {
            all: None,
            any: downgrade.any.clone(),
            none: downgrade.none.clone(),
            needs: downgrade.needs,
            scope: downgrade.scope,
        };
        let conjunction = usize::from(all_len > 0);
        let (_, direct) = direct_suppression_counts(None, Some(&widening));
        let direct = direct + conjunction;
        let (expanded, _) = expand_suppressions(None, Some(&widening), &composite_map);
        let expanded = expanded + conjunction;
        if direct > MAX_NOTABLE_DOWNGRADE_DIRECT || expanded > MAX_NOTABLE_DOWNGRADE_EXPANDED {
            violations.push(BroadNotableDowngrade {
                id: id.to_string(),
                is_composite,
                direct,
                expanded,
            });
        }
    };

    for t in trait_definitions {
        flag(t.id.as_str(), t.crit, t.downgrade.as_ref(), false);
    }
    for r in composite_rules {
        flag(r.id.as_str(), r.crit, r.downgrade.as_ref(), true);
    }

    violations
}

/// A clause that lists two references where one already covers the other.
pub(crate) struct ShadowedRef {
    /// The offending rule's ID.
    pub id: String,
    /// True for a composite rule, false for an atomic trait.
    pub is_composite: bool,
    /// Which clause the pair sits in (`unless`, `any`, `all`, `none`, …).
    pub clause: &'static str,
    /// The reference that is already covered by `covered_by`.
    pub specific: String,
    /// The reference that covers it — a duplicate, a parent directory, or a
    /// directory containing the trait.
    pub directory: String,
    /// How the pair overlaps, for the message.
    pub kind: &'static str,
}

/// Find clauses that list two references where one already covers the other.
///
/// Three shapes, all the same defect — a leg that cannot change the clause's
/// outcome because a sibling leg already subsumes it:
///
/// * **duplicate** — the same reference written twice.
/// * **directory over trait** — `a/b/` beside `a/b::c`.
/// * **directory over directory** — `well-known/lib/` beside
///   `well-known/lib/utext/`.
///
/// A covered leg is dead weight: `any:` was already satisfied by the covering
/// leg, `unless:` already suppressed on it. It makes a rule read as broader
/// than it is and inflates both suppression budgets
/// ([`find_excessive_skip_conditions`] and [`find_broad_notable_downgrades`])
/// with entries that carry no reach.
///
/// Keep the covering reference and drop the covered one — or, if only the
/// narrower one was meant, drop the broad reference, which is the case where
/// this check has found a real behavior bug rather than redundancy.
#[must_use]
pub(crate) fn find_directory_shadowed_refs(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<ShadowedRef> {
    let mut out = Vec::new();

    // A directory reference has no `::` and at least one path separator.
    fn as_directory(r: &str) -> Option<&str> {
        let r = r.trim_end_matches('/');
        (!r.contains("::") && r.contains('/')).then_some(r)
    }

    /// Does `a` cover `b`? True when `a` is a directory and `b` names a trait
    /// or directory beneath it.
    fn covers(a: &str, b: &str) -> bool {
        let Some(dir) = as_directory(a) else {
            return false;
        };
        let b = b.trim_end_matches('/');
        b.strip_prefix(dir)
            .is_some_and(|rest| rest.starts_with("::") || rest.starts_with('/'))
    }

    // Directory references deliberately exclude `crit: exception` members, so a
    // directory does NOT cover an exception that lives under it and the pair is
    // not redundant. Skip those, or this check would advise deleting a
    // reference that is doing real work.
    let exceptions: HashSet<&str> = trait_definitions
        .iter()
        .filter(|t| t.crit == crate::types::Criticality::Exception)
        .map(|t| t.id.as_str())
        .chain(
            composite_rules
                .iter()
                .filter(|r| r.crit == crate::types::Criticality::Exception)
                .map(|r| r.id.as_str()),
        )
        .collect();

    let mut scan = |id: &str, is_composite: bool, clause: &'static str, list: &[Condition]| {
        let refs: Vec<&str> = list.iter().filter_map(trait_ref).collect();
        for (i, b) in refs.iter().enumerate() {
            if exceptions.contains(*b) {
                continue;
            }
            for (j, a) in refs.iter().enumerate() {
                if i == j {
                    continue;
                }
                let same = a.trim_end_matches('/') == b.trim_end_matches('/');
                // For an exact duplicate only the later copy is reported, so a
                // pair yields one finding rather than two.
                let kind = if same && j < i {
                    "duplicate"
                } else if !same && covers(a, b) {
                    if b.contains("::") {
                        "directory over trait"
                    } else {
                        "directory over directory"
                    }
                } else {
                    continue;
                };
                out.push(ShadowedRef {
                    id: id.to_string(),
                    is_composite,
                    clause,
                    specific: (*b).to_string(),
                    directory: (*a).to_string(),
                    kind,
                });
                break;
            }
        }
    };

    let mut visit = |id: &str,
                     is_composite: bool,
                     all: Option<&Vec<Condition>>,
                     any: Option<&Vec<Condition>>,
                     none: Option<&Vec<Condition>>,
                     unless: Option<&Vec<Condition>>,
                     downgrade: Option<&DowngradeConditions>| {
        for (clause, list) in [
            ("all", all),
            ("any", any),
            ("none", none),
            ("unless", unless),
        ] {
            if let Some(list) = list {
                scan(id, is_composite, clause, list);
            }
        }
        if let Some(d) = downgrade {
            for (clause, list) in [
                ("downgrade.all", d.all.as_ref()),
                ("downgrade.any", d.any.as_ref()),
                ("downgrade.none", d.none.as_ref()),
            ] {
                if let Some(list) = list {
                    scan(id, is_composite, clause, list);
                }
            }
        }
    };

    for t in trait_definitions {
        visit(
            t.id.as_str(),
            false,
            None,
            None,
            None,
            t.unless.as_ref(),
            t.downgrade.as_ref(),
        );
    }
    for r in composite_rules {
        visit(
            r.id.as_str(),
            true,
            r.all.as_ref(),
            r.any.as_ref(),
            None,
            r.unless.as_ref(),
            r.downgrade.as_ref(),
        );
    }

    out
}

/// A `type: symbol` matcher whose literal no extracted symbol can ever equal.
pub(crate) struct UncallableSymbolMatcher {
    /// The offending rule's ID.
    pub id: String,
    /// True for a composite rule, false for an atomic trait.
    pub is_composite: bool,
    /// Which clause the matcher sits in (`if`, `unless`, …).
    pub clause: &'static str,
    /// Which field carried the literal (`exact` or `substr`).
    pub field: &'static str,
    /// The literal as written.
    pub literal: String,
    /// The same literal with argument text removed — what it should say.
    pub suggestion: String,
}

/// Is the `(` at `open` the Go receiver form, as in `net.(*Dialer).Dial`?
///
/// Compiled Go binaries really do export symbols spelled that way, so those
/// parentheses are part of a legitimate name and carry a type, not arguments.
fn is_go_receiver_paren(literal: &str, open: usize) -> bool {
    literal[..open].ends_with('.') && literal[open + 1..].starts_with('*')
}

/// Rewrite a matcher literal into the symbol format: drop every call.
fn strip_call_syntax(literal: &str) -> String {
    let mut out = String::with_capacity(literal.len());
    let mut depth = 0usize;
    for (i, ch) in literal.char_indices() {
        match ch {
            '(' if depth == 0 && !is_go_receiver_paren(literal, i) => depth += 1,
            '(' if depth > 0 => depth += 1,
            ')' if depth > 0 => depth -= 1,
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    // `.system()` collapses to `.system`; a trailing dot from `foo().` would
    // be a dangling separator.
    out.trim_end_matches('.').to_string()
}

/// Find `type: symbol` matchers that are not symbols.
///
/// Two shapes, both silent: a matcher that spells out a call, and a regex
/// sitting in `exact:`/`substr:`, which compare literally.
///
/// A symbol is a dotted path of identifiers — `platform.system`,
/// `open.read`, `Date.getTimezoneOffset` — with no parentheses and no
/// argument text, whatever the language and whether the file was source or a
/// stripped binary. A matcher that writes the call (`.system()`,
/// `open().read`, `open("/tmp/x").read`, or a half-open `.eval(`) matches
/// nothing at all.
///
/// These fail silently: the trait loads, validates, and never fires. Run
/// `cleave facts <file>` on a sample to see the exact strings to match.
///
/// `regex:` is exempt — a pattern legitimately escapes `\(` — and so is the Go
/// receiver form `net.(*Dialer).Dial`, which is a real symbol in a compiled
/// binary rather than a call.
#[must_use]
pub(crate) fn find_uncallable_symbol_matchers(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<UncallableSymbolMatcher> {
    /// Characters that never appear in a symbol we emit, so their presence
    /// means the author put a regex in `exact:`/`substr:`.
    ///
    /// Deliberately narrow. `*` is excluded because Go binaries really export
    /// `net.(*Dialer).Dial`; whitespace is excluded because PE ordinal imports
    /// are named `ORDINAL 187` and C++ has `operator delete`; and a trailing
    /// `$` is excluded because it is a legal JavaScript identifier character
    /// (`$`, `jQuery$`). What is left cannot occur in any name: a subscript is
    /// normalised to a dot, so brackets never survive either.
    fn looks_like_regex(literal: &str) -> bool {
        literal.contains('\\')
            || literal.contains('|')
            || literal.contains('^')
            || literal.contains('[')
            || literal.contains(']')
            || literal.contains(".{")
    }

    /// Does this literal name something no symbol can be?
    fn carries_call_syntax(literal: &str) -> bool {
        literal
            .char_indices()
            .any(|(i, c)| c == '(' && !is_go_receiver_paren(literal, i))
    }

    let mut out = Vec::new();

    let mut check = |id: &str, is_composite: bool, clause: &'static str, cond: &Condition| {
        let Condition::Symbol(q) = cond else { return };
        for (field, literal) in [("exact", q.exact.as_ref()), ("substr", q.substr.as_ref())] {
            let Some(literal) = literal else { continue };
            if !carries_call_syntax(literal) && !looks_like_regex(literal) {
                continue;
            }
            // A literal carrying regex metacharacters is a pattern in the
            // wrong field, not a symbol with arguments. Emptying its parens
            // would produce nonsense (`\.clone\(` -> `\.clone\()`), so say
            // what is actually wrong.
            let suggestion = if looks_like_regex(literal) {
                format!("move it to `regex:` -- {literal:?} is a pattern, not a symbol")
            } else {
                format!("write it as {:?}", strip_call_syntax(literal))
            };
            out.push(UncallableSymbolMatcher {
                id: id.to_string(),
                is_composite,
                clause,
                field,
                literal: literal.clone(),
                suggestion,
            });
        }
    };

    for t in trait_definitions {
        check(&t.id, false, "if", &t.r#if);
        for c in t.unless.iter().flatten() {
            check(&t.id, false, "unless", c);
        }
    }
    for r in composite_rules {
        for c in r.unless.iter().flatten() {
            check(&r.id, true, "unless", c);
        }
    }

    out
}

/// Container filenames a collector assigns, not the attack.
///
/// A `suspicious`/`hostile` composite that *requires* an exact match on the
/// scanned artifact's own filename detects one stored copy of a specimen. The
/// name of the outer container is chosen when the sample is fetched or filed --
/// `Win32.Volk.7z`, `2026-03-27-telnyx-v4.87.2.zip` -- so it changes on
/// re-collection and carries no attack information. The same rule with the leg
/// removed usually still fires on the archive's contents.
///
/// The real distinction is container versus member: a file *inside* an archive
/// is named by the attacker or mandated by the format (`SKILL.md`,
/// `package.json`, `AUTOEXEC.BAT`), and requiring one of those is legitimate.
/// Validation is static and cannot know where a basename will land, so an
/// archive extension stands in for "this can only ever match the container".
const COLLECTOR_NAMED_CONTAINER_EXTS: &[&str] = &[
    ".zip", ".7z", ".rar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar", ".apk", ".vsix",
    ".nupkg", ".whl", ".jar", ".gem", ".crate", ".nupkg", ".xpi", ".crx",
];

/// A path/basename literal carrying a specimen-collection date (`2026-03-27-…`)
/// is never an artifact name a registry or a victim would see.
fn looks_like_collection_date(literal: &str) -> bool {
    let b = literal.as_bytes();
    b.windows(10).any(|w| {
        w[0..4].iter().all(u8::is_ascii_digit)
            && w[4] == b'-'
            && w[5..7].iter().all(u8::is_ascii_digit)
            && w[7] == b'-'
            && w[8..10].iter().all(u8::is_ascii_digit)
    })
}

/// The filename a trait pins a whole basename to, whether written as an exact
/// literal or as a regex.
///
/// `type: basename` normalises into a Path query with `basename: true`, so one
/// arm covers both spellings. The regex arm matters: a rule can pin a specimen
/// just as tightly with `^2026-03-21-yelp-react-component-badge-v99\.` as with
/// an `exact:`, and checking only `exact:` let that form through.
fn required_basename_literal(trait_def: &TraitDefinition) -> Option<(&str, bool)> {
    match &trait_def.r#if {
        Condition::Path(PathQuery {
            exact: Some(x),
            basename: true,
            ..
        }) => Some((x.as_str(), false)),
        Condition::Path(PathQuery {
            regex: Some(x),
            basename: true,
            ..
        }) => Some((x.as_str(), true)),
        _ => None,
    }
}

/// Composites at `suspicious`+ whose `all:` requires a collector-assigned
/// container filename. Returns `(composite id, trait id, literal, reason)`.
pub(crate) fn find_container_name_convictions(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, String, String, &'static str)> {
    use crate::types::Criticality;

    let by_id: HashMap<&str, &TraitDefinition> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), t))
        .collect();
    let index = ReferenceIndex::new(by_id.keys().copied().collect());

    let mut found = Vec::new();
    for rule in composite_rules {
        if rule.crit < Criticality::Suspicious {
            continue;
        }
        let Some(required) = rule.all.as_ref() else {
            continue;
        };
        for cond in required {
            let Condition::Trait { id } = cond else {
                continue;
            };
            for resolved in index.resolve(id) {
                let Some(def) = by_id.get(resolved) else {
                    continue;
                };
                let Some((literal, is_regex)) = required_basename_literal(def) else {
                    continue;
                };
                let lower = literal.to_ascii_lowercase();
                // A regex basename is only damning when it pins one specimen. An
                // extension alone (`(?i)\.vsix$`) is a file-type test, and a
                // family's own naming convention (`^(T1|DCM-T[123])\.zip$`) is
                // real evidence -- neither is a collector's choice. A collection
                // date is, whichever way it is written.
                let reason = if looks_like_collection_date(literal) {
                    "carries a specimen-collection date, so it only ever matches our stored copy"
                } else if !is_regex
                    && COLLECTOR_NAMED_CONTAINER_EXTS
                        .iter()
                        .any(|ext| lower.ends_with(ext))
                {
                    "names the scanned container, which is assigned when the sample is fetched"
                } else {
                    continue;
                };
                found.push((rule.id.clone(), def.id.clone(), literal.to_string(), reason));
            }
        }
    }
    found
}

/// Terminal trait ids a reference *requires*, following nested composites
/// through their `all:` only.
///
/// `None` means indeterminate, and the callers treat that as "prove nothing".
/// A directory reference (`objectives/foo/`) or a bare short name can resolve to
/// many ids, and those are alternatives -- any one of them satisfies the leg --
/// so they are not a required set. Reading them as a conjunction made every
/// single-trait leg look like a subset of every directory leg.
fn required_terminals<'a>(
    reference: &str,
    index: &ReferenceIndex<'a>,
    composite_by_id: &HashMap<&str, &CompositeTrait>,
    depth: usize,
    cache: &mut HashMap<String, Vec<&'a str>>,
) -> Option<HashSet<String>> {
    if depth > 8 {
        return None;
    }
    let resolved = resolve_cached(reference, index, cache);
    let [id] = resolved[..] else {
        return None;
    };
    match composite_by_id.get(id) {
        Some(sub) => {
            // An `any:` clause makes the composite's requirements conditional,
            // so its required set is not determinate either.
            if sub.any.is_some() {
                return None;
            }
            let mut out = HashSet::new();
            for cond in sub.all.iter().flatten() {
                let Condition::Trait { id: child } = cond else {
                    return None;
                };
                out.extend(required_terminals(
                    child,
                    index,
                    composite_by_id,
                    depth + 1,
                    cache,
                )?);
            }
            Some(out)
        }
        None => Some(HashSet::from([id.to_string()])),
    }
}

/// Legs of one `all:` clause that another leg already requires.
///
/// Two families convicted on inflated evidence this way. `abot`'s
/// `winlogon-userinit-persistence` required an exact filename *and* a regex
/// matching the same filename; `antisocial`'s `family` required
/// `source-archive` (readme + apee) alongside `polymorphic-macro-source`
/// (readme + apee + aaa), which already contains it. Both read as several
/// independent legs and are worth one.
///
/// Returns `(composite id, redundant leg, leg that subsumes it)`.
pub(crate) fn find_subsumed_required_legs(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, String, String)> {
    let composite_by_id: HashMap<&str, &CompositeTrait> =
        composite_rules.iter().map(|c| (c.id.as_str(), c)).collect();
    let mut all_ids: Vec<&str> = trait_definitions.iter().map(|t| t.id.as_str()).collect();
    all_ids.extend(composite_by_id.keys().copied());
    let index = ReferenceIndex::new(all_ids);

    let mut cache: HashMap<String, Vec<&str>> = HashMap::new();
    let mut found = Vec::new();
    for rule in composite_rules {
        // Scoped to convictions. A repeated leg in a notable or exception
        // composite is untidy; in a suspicious/hostile one it manufactures
        // evidence, which is how `abot` and `antisocial` came to look
        // substantiated.
        if rule.crit < crate::types::Criticality::Suspicious {
            continue;
        }
        let Some(required) = rule.all.as_ref() else {
            continue;
        };
        let legs: Vec<&str> = required
            .iter()
            .filter_map(|c| match c {
                Condition::Trait { id } => Some(id.as_str()),
                _ => None,
            })
            .collect();
        if legs.len() < 2 {
            continue;
        }
        let expanded: Vec<Option<HashSet<String>>> = legs
            .iter()
            .map(|l| required_terminals(l, &index, &composite_by_id, 0, &mut cache))
            .collect();
        for (i, a) in expanded.iter().enumerate() {
            let Some(a) = a else { continue };
            if a.is_empty() {
                continue;
            }
            for (j, b) in expanded.iter().enumerate() {
                let Some(b) = b else { continue };
                // `a` adds nothing `b` does not already require. On an exact tie
                // only report once, so the pair yields one finding.
                if i == j || !a.is_subset(b) || (a == b && i > j) {
                    continue;
                }
                found.push((rule.id.clone(), legs[i].to_string(), legs[j].to_string()));
                break;
            }
        }
    }
    found
}

/// The fact a leg reads, as a comparable key.
///
/// Two legs sharing a key are asking about one thing, so a single value can
/// answer both and the question of the moment is whether one ever does. Only
/// the *name* facts are keyed: a path never reads the bytes, so two name legs
/// satisfied by one member are one observation. Content surfaces are a
/// different question -- two `text:` legs over one file can be independent
/// evidence even when their patterns overlap.
fn leg_fact_key(cond: &Condition) -> Option<(&'static str, &str)> {
    match cond {
        Condition::Kv(q) => {
            // A cross-fact comparison, an existence assertion, a length bound
            // or a validator is not a value matcher, so there is no value set
            // to intersect.
            if q.eq.is_some()
                || q.ne.is_some()
                || q.exists.is_some()
                || q.length_min.is_some()
                || q.length_max.is_some()
                || q.is_check.is_some()
                || q.not.is_some()
            {
                return None;
            }
            Some(("value", q.path.as_str()))
        }
        Condition::Path(q) => {
            if q.is_check.is_some() {
                return None;
            }
            Some(("basename", ""))
        }
        _ => None,
    }
}

/// The set of values a leg accepts, written as one regex.
///
/// `exact` is pinned to the whole value, `substr` floats, and `regex` is taken
/// as authored; a case-insensitive leg gets the flag its engine would apply.
/// Reducing all three spellings to one language is the point -- an `exact:`
/// and a `regex:` naming the same file are the same evidence, however they are
/// written.
fn leg_value_pattern(cond: &Condition) -> Option<String> {
    let (exact, substr, regex, case_insensitive) = match cond {
        Condition::Kv(q) => (
            q.exact.as_deref(),
            q.substr.as_deref(),
            q.regex.as_deref(),
            q.case_insensitive,
        ),
        Condition::Path(q) => (
            q.exact.as_deref(),
            q.substr.as_deref(),
            q.regex.as_deref(),
            q.case_insensitive,
        ),
        _ => return None,
    };
    let body = match (exact, substr, regex) {
        (Some(v), None, None) => format!(r"\A{}\z", regex::escape(v)),
        (None, Some(v), None) => regex::escape(v),
        (None, None, Some(v)) => format!("(?:{v})"),
        _ => return None,
    };
    Some(if case_insensitive {
        format!("(?i){body}")
    } else {
        body
    })
}

/// A value-set automaton: the byte strings a leg accepts, searched the way the
/// engine searches them (a pattern with no anchor matches anywhere).
type ValueSetDfa = regex_automata::dfa::dense::DFA<Vec<u32>>;

/// Build the [`ValueSetDfa`] for `pattern`, or `None` when it exceeds the
/// determinization budget.
fn value_set_dfa(pattern: &str) -> Option<ValueSetDfa> {
    use regex_automata::dfa::dense;

    // `MatchKind::All` keeps the automaton reporting every match rather than
    // stopping at the leftmost one, which is what "does any value satisfy
    // this" needs. The size limits keep a pathological pattern from turning a
    // validation run into a determinization.
    dense::Builder::new()
        .configure(
            dense::Config::new()
                .match_kind(regex_automata::MatchKind::All)
                .dfa_size_limit(Some(1 << 22))
                .determinize_size_limit(Some(1 << 22)),
        )
        .build(pattern)
        .ok()
}

/// A witness search over the two automata run in lockstep.
///
/// Every node is a pair of states; the walk is finite because the state pair
/// space is, and `None` means it hit its budget without deciding. Callers
/// supply what counts as a witness at the end of the value.
fn product_walk(
    dfa_a: &ValueSetDfa,
    dfa_b: &ValueSetDfa,
    anchored: bool,
    witness: impl Fn(bool, bool) -> bool,
    prune_on_b_match: bool,
) -> Option<bool> {
    use regex_automata::Anchored;
    use regex_automata::dfa::Automaton;
    use regex_automata::util::start;

    let config = start::Config::new().anchored(if anchored {
        Anchored::Yes
    } else {
        Anchored::No
    });
    let (start_a, start_b) = (
        dfa_a.start_state(&config).ok()?,
        dfa_b.start_state(&config).ok()?,
    );

    // Byte classes collapse the 256 transitions into the handful each pattern
    // actually distinguishes. Two bytes are interchangeable here only when
    // *both* automata treat them alike, so the alphabet is one representative
    // per distinct pair of classes -- typically a dozen bytes, not 256.
    let (classes_a, classes_b) = (dfa_a.byte_classes(), dfa_b.byte_classes());
    let mut seen_classes = HashSet::new();
    let alphabet: Vec<u8> = (0..=255u8)
        .filter(|&byte| seen_classes.insert((classes_a.get(byte), classes_b.get(byte))))
        .collect();

    // A side that has already matched is frozen: its obligation is discharged,
    // and stepping it on could only walk it into a dead state and prune a
    // search that is still live for the other side. Under `anchored` there is
    // nothing to freeze -- the match has to end exactly at the value's end.
    let mut seen = HashSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back((start_a, start_b, false, false));
    seen.insert((start_a, start_b, false, false));

    let mut budget = 250_000usize;
    while let Some((sa, sb, ma, mb)) = queue.pop_front() {
        budget = budget.checked_sub(1)?;

        let done_a = ma || dfa_a.is_match_state(dfa_a.next_eoi_state(sa));
        let done_b = mb || dfa_b.is_match_state(dfa_b.next_eoi_state(sb));
        if witness(done_a, done_b) {
            return Some(true);
        }

        for &byte in &alphabet {
            let (mut na, mut nb) = (sa, sb);
            let (mut nma, mut nmb) = (ma, mb);
            if !ma {
                na = dfa_a.next_state(sa, byte);
                if dfa_a.is_dead_state(na) || dfa_a.is_quit_state(na) {
                    continue;
                }
                nma = !anchored && dfa_a.is_match_state(na);
            }
            if !mb {
                nb = dfa_b.next_state(sb, byte);
                if dfa_b.is_quit_state(nb) {
                    continue;
                }
                // A dead `b` is fatal when the witness needs `b` to match and
                // is exactly what the witness wants when it needs `b` not to.
                if dfa_b.is_dead_state(nb) && prune_on_b_match {
                    continue;
                }
                nmb = !anchored && dfa_b.is_match_state(nb);
                if nmb && prune_on_b_match {
                    continue;
                }
            }
            if seen.insert((na, nb, nma, nmb)) {
                queue.push_back((na, nb, nma, nmb));
            }
        }
    }
    Some(false)
}

/// Whether both matchers can match the *same text*.
///
/// This is "the same evidence, spelled differently" stated precisely: run both
/// patterns anchored at both ends and ask whether one span satisfies both.
/// `\.(xlsx|xls)$` and `\.(xlsm|xlsx)$` meet on `.xlsx`, so an archive member
/// named that way answers both legs with one filename.
///
/// It is deliberately not "one value satisfies both". A preinstall script
/// holding `http://…` and an `xxd` call satisfies a URL leg and a hex-encode
/// leg at once, but those legs match different text and are two observations.
fn same_span_satisfies_both(a: &ValueSetDfa, b: &ValueSetDfa) -> Option<bool> {
    product_walk(a, b, true, |done_a, done_b| done_a && done_b, true)
}

/// Whether every value `a` accepts, `b` accepts too.
///
/// The search is for a counter-example -- a value that `a` matches and `b`
/// does not -- so finding none proves containment. An `exact:` leg naming
/// `docs/Invoice-90233.xlsx` alongside a regex leg for `\.(xlsx|xls)$` matches
/// different *text*, but every member the first accepts the second accepts,
/// so the second is not telling the rule anything new.
fn value_set_contains(a: &ValueSetDfa, b: &ValueSetDfa) -> Option<bool> {
    let witness = product_walk(a, b, false, |done_a, done_b| done_a && !done_b, false)?;
    Some(!witness)
}

/// Whether two legs carry the same surrounding constraints.
///
/// A leg with its own count floor, density, size window or suppression is
/// asserting something the other one is not -- "three spreadsheet members" is
/// a different claim from "an xlsx member" even though one member answers
/// both matchers. Only legs that differ solely in how their matcher is
/// spelled are the same evidence.
fn same_leg_constraints(a: &TraitDefinition, b: &TraitDefinition) -> bool {
    a.count_min == b.count_min
        && a.count_max == b.count_max
        && a.per_kb_min == b.per_kb_min
        && a.per_kb_max == b.per_kb_max
        && a.size_min == b.size_min
        && a.size_max == b.size_max
        && a.entropy_min == b.entropy_min
        && a.entropy_max == b.entropy_max
        && a.not.is_none()
        && b.not.is_none()
        && a.unless.is_none()
        && b.unless.is_none()
}

/// Required legs that one value can satisfy at once.
///
/// A conviction is supposed to rest on two pieces of evidence. When two `all:`
/// legs read the same fact and some single value answers both, there is one
/// piece of evidence spelled two ways: `zip-xlsx-spreadsheet-stage` required
/// an archive member matching `\\.xlsx$` and one matching
/// `\\.(xlsx|xlsm|xlsb|xls)$`, which one `.xlsx` member satisfies. The rule
/// convicts at `hostile`/0.93 on a filename it counted twice.
///
/// Overlap is enough -- containment is not required. `\\.(xlsx|xls)$` and
/// `\\.(xlsm|xlsx)$` cover different extension sets, and neither implies the
/// other, but one `.xlsx` member still answers both.
///
/// Legs that no single value can satisfy stay silent, because requiring two
/// *different* members is a real layout fingerprint: `archive-sideload-bundle`
/// wants a `setup.exe` at the root and a binary under `Updates/`, and no one
/// path is both.
///
/// Returns `(composite id, first leg, second leg, the fact they share)`.
pub(crate) fn find_one_fact_convictions(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, String, String, String)> {
    let composite_by_id: HashMap<&str, &CompositeTrait> =
        composite_rules.iter().map(|c| (c.id.as_str(), c)).collect();
    let by_id: HashMap<&str, &TraitDefinition> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), t))
        .collect();
    let mut all_ids: Vec<&str> = by_id.keys().copied().collect();
    all_ids.extend(composite_by_id.keys().copied());
    let index = ReferenceIndex::new(all_ids);

    let mut cache: HashMap<String, Vec<&str>> = HashMap::new();
    // Every pair of legs is compared three ways, and the same patterns recur
    // across pairs and rules, so each is determinized once per run rather than
    // up to six times per pair.
    let mut dfas: HashMap<String, Option<ValueSetDfa>> = HashMap::new();
    let mut found = Vec::new();
    for rule in composite_rules {
        // Scoped to convictions. Two spellings of one fact in a notable rule
        // are untidy; in a suspicious or hostile one they are the difference
        // between evidence and the appearance of it.
        if rule.crit < crate::types::Criticality::Suspicious {
            continue;
        }
        let Some(required) = rule.all.as_ref() else {
            continue;
        };
        let legs: Vec<&str> = required
            .iter()
            .filter_map(|c| match c {
                Condition::Trait { id } => Some(id.as_str()),
                _ => None,
            })
            .collect();
        if legs.len() < 2 {
            continue;
        }

        // A leg that resolves to a composite, a directory or an ambiguous
        // short name stands for several conditions, and no one value set
        // describes it.
        let resolved: Vec<Option<&TraitDefinition>> = legs
            .iter()
            .map(|leg| {
                let ids = resolve_cached(leg, &index, &mut cache);
                let [id] = ids[..] else { return None };
                by_id.get(id).copied()
            })
            .collect();

        for (i, a) in resolved.iter().enumerate() {
            let Some(a) = a else { continue };
            for (j, b) in resolved.iter().enumerate().skip(i + 1) {
                let Some(b) = b else { continue };
                if a.id == b.id {
                    continue;
                }
                let (Some(key_a), Some(key_b)) = (leg_fact_key(&a.r#if), leg_fact_key(&b.r#if))
                else {
                    continue;
                };
                if key_a != key_b {
                    continue;
                }
                if !same_leg_constraints(a, b) {
                    continue;
                }
                let (Some(pattern_a), Some(pattern_b)) =
                    (leg_value_pattern(&a.r#if), leg_value_pattern(&b.r#if))
                else {
                    continue;
                };
                // The same evidence, either because the two matchers can
                // match one span or because one leg's values are all already
                // accepted by the other.
                for pattern in [&pattern_a, &pattern_b] {
                    if !dfas.contains_key(pattern) {
                        dfas.insert(pattern.clone(), value_set_dfa(pattern));
                    }
                }
                let (Some(Some(dfa_a)), Some(Some(dfa_b))) =
                    (dfas.get(&pattern_a), dfas.get(&pattern_b))
                else {
                    continue;
                };
                let same_evidence = same_span_satisfies_both(dfa_a, dfa_b) == Some(true)
                    || value_set_contains(dfa_a, dfa_b) == Some(true)
                    || value_set_contains(dfa_b, dfa_a) == Some(true);
                if !same_evidence {
                    continue;
                }
                let fact = if key_a.1.is_empty() {
                    "the file name".to_string()
                } else {
                    key_a.1.to_string()
                };
                found.push((
                    rule.id.clone(),
                    legs[i].to_string(),
                    legs[j].to_string(),
                    fact,
                ));
            }
        }
    }
    found
}

/// Cache for [`ReferenceIndex::resolve`]. These checks resolve the same
/// handful of references across thousands of composites.
fn resolve_cached<'a>(
    reference: &str,
    index: &ReferenceIndex<'a>,
    cache: &mut HashMap<String, Vec<&'a str>>,
) -> Vec<&'a str> {
    if let Some(hit) = cache.get(reference) {
        return hit.clone();
    }
    let resolved = index.resolve(reference);
    cache.insert(reference.to_string(), resolved.clone());
    resolved
}

/// Whether a condition describes what a file *is called* or pins it to an exact
/// measurement, rather than saying anything about its contents.
///
/// A path never reads the bytes. A metric usually does -- an overlay's entropy,
/// a section ratio, a zeroed PE checksum are all measurements of the file
/// itself, and rules built from them are doing real structural analysis. The
/// exception is a metric pinned to a single value (`min == max`), which
/// identifies one artifact the way a hash does: `digininja-postinstall` required
/// `strings.count` of exactly 13.
fn is_name_or_shape_only(condition: &Condition) -> bool {
    match condition {
        Condition::Path(_) => true,
        Condition::Metrics(m) => matches!((m.min, m.max), (Some(lo), Some(hi)) if lo == hi),
        _ => false,
    }
}

/// Objective directories whose whole subject is the filename an attacker chose.
const NAME_IS_THE_TECHNIQUE: &[&str] = &[
    "objectives/evasion/masquerade/",
    "objectives/supply-chain/impersonation/",
    "objectives/execution/lure/",
    "metadata/file/extension/",
];

/// Convictions assembled entirely from name, size and metric facts.
///
/// `digininja-postinstall` was the clearest: an exact `.tgz` basename, a file
/// size pinned to 1917 bytes, and `strings.count` of exactly 13 -- a file hash
/// wearing behavioural clothing, which matches one artifact and not the next
/// build of the same malware. Names and shapes corroborate; they do not convict.
///
/// Returns `(composite id, the terminal ids it rests on)`.
pub(crate) fn find_convictions_without_content(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, Vec<String>)> {
    use crate::types::Criticality;

    let by_id: HashMap<&str, &TraitDefinition> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), t))
        .collect();
    let composite_by_id: HashMap<&str, &CompositeTrait> =
        composite_rules.iter().map(|c| (c.id.as_str(), c)).collect();
    let mut all_ids: Vec<&str> = by_id.keys().copied().collect();
    all_ids.extend(composite_by_id.keys().copied());
    let index = ReferenceIndex::new(all_ids);

    let mut cache: HashMap<String, Vec<&str>> = HashMap::new();
    let mut found = Vec::new();
    for rule in composite_rules {
        if rule.crit < Criticality::Suspicious {
            continue;
        }
        // Objectives where the name IS the finding. Masquerading, lures,
        // typosquats and architecture-suffixed bot drops are detected precisely
        // by what the attacker called the file -- `payment-receipt.pdf.exe` is
        // the attack, not a label on it -- so a name-only conviction is correct
        // there and nowhere else.
        if NAME_IS_THE_TECHNIQUE
            .iter()
            .any(|prefix| rule.id.starts_with(prefix))
        {
            continue;
        }
        // Every positive leg counts here, `any:` included: one content-derived
        // alternative is enough to say the rule rests on more than a filename.
        let mut terminals: HashSet<String> = HashSet::new();
        let mut saw_inline_content = false;
        for cond in rule.all.iter().flatten().chain(rule.any.iter().flatten()) {
            match cond {
                Condition::Trait { id } => {
                    // A reference into a runtime-synthesized namespace resolves
                    // to nothing statically, but it is not absent evidence: an
                    // import, a code signature or an entitlement is a fact about
                    // the file's contents, recovered per-scan. Counting those as
                    // "no content" reported rules like `setup-py-ctypes-imports`
                    // as resting on their filename alone.
                    if is_runtime_synthesized_namespace(id) {
                        saw_inline_content = true;
                        continue;
                    }
                    // Every id this leg can reach, required or alternative: one
                    // content-derived possibility is enough to clear the rule.
                    let mut stack = resolve_cached(id, &index, &mut cache);
                    let mut seen = HashSet::new();
                    while let Some(next) = stack.pop() {
                        if !seen.insert(next.to_string()) {
                            continue;
                        }
                        match composite_by_id.get(next) {
                            Some(sub) => {
                                for c in sub.all.iter().flatten().chain(sub.any.iter().flatten()) {
                                    match c {
                                        Condition::Trait { id: child } => {
                                            stack.extend(resolve_cached(child, &index, &mut cache));
                                        }
                                        other => {
                                            if !is_name_or_shape_only(other) {
                                                saw_inline_content = true;
                                            }
                                        }
                                    }
                                }
                            }
                            None => {
                                terminals.insert(next.to_string());
                            }
                        }
                    }
                }
                other => {
                    if !is_name_or_shape_only(other) {
                        saw_inline_content = true;
                    }
                }
            }
        }
        if saw_inline_content || terminals.is_empty() {
            continue;
        }
        let resting_on: Vec<String> = terminals.iter().cloned().collect();
        let all_name_or_shape = terminals.iter().all(|t| {
            by_id
                .get(t.as_str())
                .is_some_and(|d| is_name_or_shape_only(&d.r#if))
        });
        if all_name_or_shape {
            let mut ids = resting_on;
            ids.sort();
            found.push((rule.id.clone(), ids));
        }
    }
    found
}

/// Directory references that match no trait at all.
///
/// `broken-reference` validates exact `dir::id` references; a reference without
/// `::` is treated as a directory or short-name lookup and silently contributes
/// nothing when it resolves to zero traits.
///
/// Namespaces the analyzers synthesize at runtime are NOT dangling and must be
/// skipped: `metadata/import/<ecosystem>/<target>::<local-name>`, `metadata/signed/…`,
/// `metadata/entitlement/…`
/// and the rest are built from the file's own imports, code signature and
/// entitlements, so they never appear as static YAML and resolve only during a
/// scan. `is_dynamic_metadata_ref` in the loader is the authority; this must
/// stay in sync with it.
///
/// Returns `(rule id, clause, dangling reference)`.
/// IDs synthesized per-file rather than loaded from YAML. Import findings use
/// the target/local-name format emitted by `mapper/imports.rs`. Directory
/// references under a source ecosystem match all bindings in that namespace.
pub(crate) fn is_runtime_synthesized_namespace(ref_id: &str) -> bool {
    if ref_id.starts_with("metadata/import/") {
        return crate::capabilities::mapper::imports::is_dynamic_import_ref(ref_id);
    }

    const DYNAMIC_PREFIXES: &[&str] = &[
        "metadata/dylib::",
        "metadata/dylib/",
        "metadata/signed/",
        "metadata/entitlement/",
        "metadata/lang/embedded::",
        "metadata/lang/encoded/",
        "metadata/binary/linking::macho-install-name",
        "metadata/binary/linking::macho-dylib",
        "metadata/binary/linking::macho-rpath",
        "metadata/build/debug::elf-debuglink",
    ];
    DYNAMIC_PREFIXES
        .iter()
        .any(|prefix| ref_id.starts_with(prefix))
}

pub(crate) fn find_dangling_directory_refs(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, &'static str, String)> {
    let mut all_ids: Vec<&str> = trait_definitions.iter().map(|t| t.id.as_str()).collect();
    all_ids.extend(composite_rules.iter().map(|c| c.id.as_str()));
    let index = ReferenceIndex::new(all_ids);

    let mut cache: HashMap<String, Vec<&str>> = HashMap::new();
    let mut found = Vec::new();
    for rule in composite_rules {
        for (clause, conds) in [
            ("all", rule.all.as_ref()),
            ("any", rule.any.as_ref()),
            ("unless", rule.unless.as_ref()),
        ] {
            for cond in conds.into_iter().flatten() {
                let Condition::Trait { id } = cond else {
                    continue;
                };
                // Exact references are already covered by `broken-reference`.
                if id.contains("::") {
                    continue;
                }
                if is_runtime_synthesized_namespace(id) {
                    continue;
                }
                if resolve_cached(id, &index, &mut cache).is_empty() {
                    found.push((rule.id.clone(), clause, id.clone()));
                }
            }
        }
    }
    found
}

/// Find atomic traits whose `for:` mixes archive types with non-archive types.
///
/// An atomic has one matcher and runs on one node, and an archive node and the
/// files inside it are different nodes. cleave expands every archive into member
/// nodes and never runs a content scan over the container's own bytes -- a
/// `type: text` trait declared `for: [tar, shell]` can only ever fire through
/// the `shell` half, even though the marker is present verbatim in the tar's
/// bytes. (Compression is not what decides this: a *stored*, uncompressed zip
/// behaves the same.) So the two halves never both apply, and declaring both
/// hides which one the author meant.
///
/// Composites are deliberately exempt: one may bridge the two levels on
/// purpose, firing at the container for an archive and at the member for a
/// standalone file, and its `for:` says which nodes it is evaluated on.
///
/// `for: [all]` is exempt -- that is the sanctioned way to say "any node".
/// Group-derived lists are exempt too, because a named group can legitimately
/// expand to a mix (`data` covers `ipa` alongside `json`/`text`), and the YAML
/// the author wrote is a single group name.
///
/// Returns `(trait_id, archive_types, non_archive_types)`.
pub(crate) fn find_mixed_archive_filetype_traits(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, Vec<FileType>, Vec<FileType>)> {
    let mut violations = Vec::new();
    for t in trait_definitions {
        if t.for_from_groups || t.r#for.contains(&FileType::All) {
            continue;
        }
        // `type: path`/`basename` reads the analyzed node's OWN path, which
        // every node has regardless of whether it is an archive container or
        // a plain file -- unlike every other matcher kind, it never touches
        // file *content*, so the "cleave never content-scans a container's
        // own bytes" rationale this validator is built on does not apply to
        // it. `izpack-package-path` (`for: [jar, pe, shell, javascript,
        // java]`, `type: path`) is a legitimate single check on whichever
        // node's path matches, not five conflated facts -- 394 of the
        // tree's traits share this shape and none of them are the bug this
        // validator exists to catch.
        if matches!(t.r#if, Condition::Path(_)) {
            continue;
        }
        // `type: metrics` is measurement, not a content scan: `file.entropy`,
        // `consistency.*` and the `packing`/`obfuscation` scores are computed
        // for whatever node is being analysed, container and member alike. So
        // an archive type sitting beside a leaf type says nothing about
        // whether "only one half can fire" -- both halves can. The same is
        // NOT true of `type: value`: a container-scoped fact like
        // `archive.members[*].path` exists only on a node the archive
        // analyser cracked, so a leaf type listed beside it really is dead,
        // and that is this validator catching a real defect rather than
        // misfiring. Leave `value` alone.
        if matches!(t.r#if, Condition::Metrics(_)) {
            continue;
        }
        let (archive, plain): (Vec<_>, Vec<_>) =
            t.r#for.iter().partition(|ft| FileType::is_archive(ft));
        if !archive.is_empty() && !plain.is_empty() {
            violations.push((t.id.clone(), archive, plain));
        }
    }
    violations
}

/// Find composites whose `for:` lists a file type no required leg can match on.
///
/// A composite fires on one node. On a *leaf* node its `all:` legs must each be
/// able to match that node's type, so a declared type that some required leg
/// cannot match is dead: the rule can never fire on it.
///
/// `prepare-decoded-command-loader` declared `for: [javascript, typescript]`
/// while requiring `has-prepare`, which is a `package.json` field. On a
/// JavaScript node that leg can never match, so both leaf types were
/// unreachable -- the rule only ever fired on the npm package node, where the
/// container inherits the member findings. The correct `for:` was `[npm]`.
///
/// Archive types in the `for:` are skipped, because on a container the legs are
/// satisfied by inherited member findings rather than by matching the container
/// itself -- that is the whole point of a cross-archive scope. Directory
/// references and non-trait conditions are skipped too, since they resolve to
/// many definitions with differing `for:` lists.
///
/// Returns `(composite_id, impossible_type, blocking_leg_id)`.
pub(crate) fn find_impossible_composite_filetypes(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, FileType, String)> {
    let mut sink = Vec::new();
    find_impossible_composite_filetypes_inner(trait_definitions, composite_rules, &mut sink)
}

fn find_impossible_composite_filetypes_inner(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    dead_rules: &mut Vec<String>,
) -> Vec<(String, FileType, String)> {
    let trait_for: HashMap<&str, &Vec<FileType>> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), &t.r#for))
        .collect();
    let composite_for: HashMap<&str, &Vec<FileType>> = composite_rules
        .iter()
        .map(|c| (c.id.as_str(), &c.r#for))
        .collect();

    // A retired metric leaves behind a `__cleave_missing_*__` placeholder trait
    // so its references do not dangle. That leg never matches anything, on any
    // type, so every consumer looks unreachable here -- which is true but is a
    // dead-leg problem, not a file-type one, and reporting it as the latter
    // sends the reader to the wrong fix.
    // The sentinel appears under whichever matcher the retired metric used --
    // `section` for the section-ratio ones, `string_literal` for the macOS
    // library fingerprints, and so on -- so match on the value wherever it
    // sits rather than enumerating condition kinds. Tenorshare's
    // `ts-lib-fingerprint-methods` is `string_literal: __cleave_missing_macos__`
    // and on its own made all sixteen composites in that file look dead.
    let is_retired_placeholder = |id: &str| -> bool {
        trait_definitions
            .iter()
            .find(|t| t.id == id)
            .is_some_and(|t| format!("{:?}", t.r#if).contains("__cleave_missing"))
    };

    let mut found = Vec::new();
    for rule in composite_rules {
        if rule.r#for.contains(&FileType::All) || rule.for_from_groups {
            continue;
        }
        // A pooling composite (`archive`/`package`/`outer`) runs on the
        // container and legitimately declares the *member* types whose
        // findings may satisfy its legs -- that is what `for:` means since the
        // origin filter landed (see SCOPE_PLAN.md). Those member types are not
        // leaf-match candidates, so asking "can every required leg match this
        // declared type on one node" is the wrong question for them: it made
        // this validator report a fresh violation for every member type the
        // `for:`-migration correctly added. `find_legs_outside_for` covers the
        // pooling case, from the other direction.
        if matches!(
            rule.effective_scope(),
            Scope::Archive | Scope::Package | Scope::Outer
        ) {
            continue;
        }
        let Some(required) = rule.all.as_ref() else {
            continue;
        };
        let before = found.len();
        let mut checkable = 0usize;
        for declared in &rule.r#for {
            // On a container the legs arrive as inherited member findings.
            if FileType::is_archive(declared) {
                continue;
            }
            checkable += 1;
            for cond in required {
                let Condition::Trait { id } = cond else {
                    continue;
                };
                // A *directory* reference resolves to many definitions with
                // differing `for:` lists, so it proves nothing here. A bare
                // same-directory name (`has-prepare`) is an ordinary trait
                // reference and must still be resolved -- skipping those was
                // what let `prepare-decoded-command-loader` past this check.
                if id.contains('/') && !id.contains("::") {
                    continue;
                }
                let own_dir = rule.id.split("::").next().unwrap_or("");
                let qualified = format!("{own_dir}::{id}");
                let Some(leg_for) = trait_for
                    .get(id.as_str())
                    .or_else(|| composite_for.get(id.as_str()))
                    .or_else(|| trait_for.get(qualified.as_str()))
                    .or_else(|| composite_for.get(qualified.as_str()))
                else {
                    continue;
                };
                if leg_for.contains(&FileType::All) || leg_for.contains(declared) {
                    continue;
                }
                if is_retired_placeholder(id) || is_retired_placeholder(&qualified) {
                    continue;
                }
                found.push((rule.id.clone(), *declared, id.clone()));
                break;
            }
        }
        // Every non-archive type it declares is unreachable AND it names no
        // container type: the rule cannot fire anywhere. That is a different
        // and worse problem than one dead entry in a list, so mark it. A
        // declared archive type is not itself re-checked here (its legs
        // arrive as inherited member findings, which this static check
        // cannot simulate), but its mere presence means the rule has a live
        // path to fire and must not be reported dead.
        //
        // A pooling scope (`outer`/`archive`/`package`) is the same escape
        // hatch even when `for:` names a non-archive container -- a
        // self-extracting PE (PyInstaller onefile) or an ISO with embedded
        // members pools its children's findings the same way an archive
        // does, without the container's FileType itself carrying the
        // `#[archive]` marker. `Scope::Archive` also degrades to `Outer`
        // (pools the whole input) when the container isn't nested inside an
        // archive at all, so it is never narrower than the type check below.
        let has_pooling_scope = matches!(
            rule.scope,
            Some(Scope::Outer | Scope::Archive | Scope::Package)
        );
        let names_container = rule.r#for.iter().any(FileType::is_archive) || has_pooling_scope;
        if checkable > 0 && found.len() - before == checkable && !names_container {
            dead_rules.push(rule.id.clone());
        }
    }
    found
}

/// Composites that cannot fire on *any* declared type -- see
/// [`find_impossible_composite_filetypes`], which records them as it goes.
pub(crate) fn find_dead_composites(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<String> {
    let mut dead = Vec::new();
    let impossible =
        find_impossible_composite_filetypes_inner(trait_definitions, composite_rules, &mut dead);
    let _ = impossible;
    dead
}

/// A `scope: package` declaration that can never bind to a package boundary.
#[derive(Debug, Clone)]
pub(crate) struct UnbindablePackageScope {
    /// The offending composite's ID.
    pub id: String,
    /// Why it can never bind, phrased for the validator's output.
    pub reason: String,
}

/// True for a node type no package archive can ever contain.
///
/// [`FileType::Registry`] is the only one: normalized registry metadata is
/// synthesized from an API response *beside* the fetched artifact, not
/// extracted from inside it, so its findings carry no `archive:` location for
/// a package key to be derived from.
fn is_synthetic_non_member_type(ft: &FileType) -> bool {
    matches!(ft, FileType::Registry)
}

/// Resolve a leg reference to the `for:` list of the trait or composite it
/// names. Bare same-directory names are qualified with the referring rule's
/// own directory, the way the loader resolves them. Directory references
/// resolve to many definitions with differing `for:` lists, so they return
/// `None` -- they prove nothing here.
fn leg_file_types<'a>(
    id: &str,
    own_dir: &str,
    trait_for: &HashMap<&str, &'a Vec<FileType>>,
    composite_for: &HashMap<&str, &'a Vec<FileType>>,
) -> Option<&'a Vec<FileType>> {
    if id.ends_with('/') || (id.contains('/') && !id.contains("::")) {
        return None;
    }
    let qualified = format!("{own_dir}::{id}");
    trait_for
        .get(id)
        .or_else(|| composite_for.get(id))
        .or_else(|| trait_for.get(qualified.as_str()))
        .or_else(|| composite_for.get(qualified.as_str()))
        .copied()
}

/// Find `scope: package` composites that can never bind to a package boundary.
///
/// `scope: package` keys evidence by its nearest enclosing registry-fetch
/// package archive (npm/gem/whl/nupkg/crate/conda/egg/python_sdist) and, when
/// the evidence has no such ancestor, degrades to `scope: file` -- it never
/// widens into a global pool. That makes a merely *unlikely* package ancestor
/// harmless, which is why this check reports only declarations that can never
/// bind at all. Two shapes qualify, both grounded in `Scope::key`:
///
/// 1. Every declared `for:` type is a synthetic node no package can contain
///    (today: `registry`). Registry findings have no `archive:` location, so
///    `parent_package` has nothing to walk.
/// 2. The `all:` legs mix a registry-only leg with a leg that never runs on a
///    registry node. Registry evidence keys to the empty string while
///    artifact evidence keys to its archive or file path, so the two can never
///    land in the same scope bucket and the rule is unsatisfiable.
///
/// Both shapes want [`Scope::Outer`] instead -- the one scope that
/// deliberately pools by presence, which is exactly how the fetched artifact
/// and its separately-fetched registry metadata are meant to be joined (see
/// `evaluate_package_composites`).
///
/// Only rules that spell `scope: package` out are checked. The `for:`-derived
/// default in `CompositeTrait::default_scope` is the engine's own choice and
/// cannot be wrong in this way.
pub(crate) fn find_scope_without_valid_container(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<UnbindablePackageScope> {
    let trait_for: HashMap<&str, &Vec<FileType>> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), &t.r#for))
        .collect();
    let composite_for: HashMap<&str, &Vec<FileType>> = composite_rules
        .iter()
        .map(|c| (c.id.as_str(), &c.r#for))
        .collect();

    let mut found = Vec::new();
    for rule in composite_rules {
        if rule.scope != Some(Scope::Package) {
            continue;
        }

        // Shape 1: the node itself can never sit under a package.
        if !rule.r#for.is_empty() && rule.r#for.iter().all(is_synthetic_non_member_type) {
            found.push(UnbindablePackageScope {
                id: rule.id.clone(),
                reason: "for: names only registry nodes, which carry no archive location for a package key".to_string(),
            });
            continue;
        }

        // Shape 2: required legs straddle the registry/artifact boundary.
        let Some(all) = rule.all.as_ref() else {
            continue;
        };
        let own_dir = rule.id.split("::").next().unwrap_or("");
        let mut registry_leg: Option<&str> = None;
        let mut artifact_leg: Option<&str> = None;
        for cond in all {
            let Condition::Trait { id } = cond else {
                continue;
            };
            // Only resolvable legs count: this check fires on certainty.
            let Some(types) = leg_file_types(id, own_dir, &trait_for, &composite_for) else {
                continue;
            };
            if types.is_empty() {
                continue;
            }
            if types.iter().all(is_synthetic_non_member_type) {
                registry_leg.get_or_insert(id.as_str());
            } else if !types.contains(&FileType::All)
                && !types.iter().any(is_synthetic_non_member_type)
            {
                // Runs only on real files -- never on a registry node.
                artifact_leg.get_or_insert(id.as_str());
            }
        }
        if let (Some(reg), Some(art)) = (registry_leg, artifact_leg) {
            found.push(UnbindablePackageScope {
                id: rule.id.clone(),
                reason: format!(
                    "registry-only leg '{reg}' can never share a package key with file-based leg '{art}'"
                ),
            });
        }
    }
    found
}

/// Find composites whose pooling scope has no container to run on.
///
/// `archive`, `package` and `outer` are evaluated in the *container* pass —
/// the per-node pass takes only `file`/`leaf` (see the scope filters in
/// `evaluate_composites`). So a pooling-scoped composite runs only on a node
/// whose own type is a container, and one that declares no container type in
/// `for:` never runs at all: `for: [javascript]` + `scope: archive` reports on
/// a JavaScript node that the container pass will never hand it.
///
/// A container is an `#[archive]` type, or `registry` for `scope: outer` (the
/// synthetic artifact↔registry node is typed `registry`). `for: [all]` and
/// group-derived lists are exempt — `all` runs everywhere by definition, and a
/// named group's expansion is not what the author wrote.
///
/// Returns `(composite_id, scope, declared_types)`.
pub(crate) fn find_pooling_scope_without_container(
    composite_rules: &[CompositeTrait],
) -> Vec<(String, Scope, Vec<FileType>)> {
    let mut found = Vec::new();
    for rule in composite_rules {
        let scope = rule.effective_scope();
        if !matches!(scope, Scope::Archive | Scope::Package | Scope::Outer) {
            continue;
        }
        if rule.for_from_groups || rule.r#for.is_empty() || rule.r#for.contains(&FileType::All) {
            continue;
        }
        // `Pe` is the established non-archive exception: a self-extracting PE
        // (PyInstaller onefile) or one with embedded cabinet/resource members
        // pools its children's findings the same way an archive does, without
        // carrying the `#[archive]` marker. `find_impossible_composite_filetypes`
        // already grants this exact carve-out (see its `has_pooling_scope`
        // comment and `a_pooling_scope_keeps_a_non_archive_container_alive`);
        // this check follows the same precedent rather than contradicting it.
        // `known-nondeployed-filename-context` (`for: [pe]`, `scope: outer`) is
        // the live shape: a PE's own version-resource fact joined with an
        // identity marker that may live in an embedded MSI/CAB member's path.
        // MSI, OLE compound documents and OOXML are containers too: each
        // holds more than one stream/part, and cleave cracks them and pools
        // their members' findings -- `analyzers/office/mod.rs` calls
        // `evaluate_container_composites` exactly as the archive analyser
        // does. They carry no `#[archive]` marker only because the *archive*
        // analyser is not what opens them (filefacts's `is_archive()` excludes
        // them; the office analyser owns them and emits `office.*` rather than
        // `archive.*`). Without this arm the two validators deadlock:
        // `find_impossible_composite_filetypes` tells an MSI or Office rule to
        // declare its container and take a pooling scope, and then this one
        // rejects the result -- 23 composites, most of
        // `dropper/execution/msi/msi.yaml`, had no legal state to be in.
        let has_container = rule.r#for.iter().any(|ft| {
            FileType::is_archive(ft)
                || matches!(
                    ft,
                    FileType::Pe | FileType::Msi | FileType::OleDoc | FileType::Ooxml
                )
                || (scope == Scope::Outer && *ft == FileType::Registry)
        });
        if !has_container {
            found.push((rule.id.clone(), scope, rule.r#for.clone()));
        }
    }
    found
}

/// Which clause a leg outside `for:` sits in — the consequence differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegRole {
    /// An `all:` leg: the rule can never fire.
    Required,
    /// Every `any:` alternative is outside `for:`: the rule can never fire.
    EveryAlternative,
    /// An `unless:` leg: the *carve-out* can never fire, so the rule keeps
    /// firing where the author said it should not. Reported separately because
    /// this one costs false positives rather than detections.
    Suppressor,
    /// One `any:` alternative is outside `for:` while another is reachable:
    /// the rule still fires, but never through this branch. Reported only by
    /// [`find_dead_any_alternatives`], as a warning.
    DeadAlternative,
}

/// A leg whose evidence the rule's `for:` excludes.
#[derive(Debug, Clone)]
pub(crate) struct LegOutsideFor {
    /// The composite.
    pub id: String,
    /// Its effective scope, for the message.
    pub scope: Scope,
    /// The leg that can never be satisfied.
    pub leg: String,
    /// The types that leg fires on — what `for:` is missing.
    pub leg_types: Vec<FileType>,
    /// Where the leg sits, which decides what breaks.
    pub role: LegRole,
}

/// Find pooling composites whose `for:` excludes a required leg's file types.
///
/// `for:` lists the file types a composite is about: the container it reports
/// on *and* the members whose findings may satisfy its legs (see
/// `EvaluationContext::origin_allows`). A required leg that only ever fires on
/// a type the rule does not name can therefore never be satisfied, and the
/// rule is dead.
///
/// This is the check that makes a rule *targeted*. `for: [vsix]` with a
/// JavaScript leg used to mean "any evidence in any member counts", which is
/// how `vscode-activated-curl-shell` scored hostile on a Rust crate. Naming the
/// member types is what narrows a rule to the files it is actually about, so
/// this error asks for the one edit that removes a false-positive class:
/// declare what you mix.
///
/// Only pooling scopes (`archive`/`package`/`outer`) are checked — they are the
/// ones the origin filter applies to. File-scoped composites match within one
/// node and are covered by `find_impossible_composite_filetypes`.
///
/// Skipped, because none of them proves a mistake: `for: [all]` (opts out of
/// the filter), group-derived lists, a leg declared `for: [all]`, a leg that
/// cannot be resolved, and a directory reference whose members' types are
/// unioned (any overlap clears it).
pub(crate) fn find_legs_outside_for(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<LegOutsideFor> {
    legs_outside_for(trait_definitions, composite_rules, false)
}

/// `any:` alternatives the rule's `for:` makes unreachable while a sibling
/// alternative keeps the clause alive.
///
/// The rule works, so this is a warning rather than an error, but the branch
/// is dead code with a detection's name on it. Example: a release-zip
/// correlator with `for: [zip, tar, go]` and `any: [source-hash-names,
/// binary-hash-names]` fired on source tarballs and never on the release zip
/// it was written for, because the binary alternative only fires on ELF.
pub(crate) fn find_dead_any_alternatives(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<LegOutsideFor> {
    legs_outside_for(trait_definitions, composite_rules, true)
        .into_iter()
        .filter(|l| l.role == LegRole::DeadAlternative)
        .collect()
}

fn legs_outside_for(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    partial_any: bool,
) -> Vec<LegOutsideFor> {
    let trait_for: HashMap<&str, &Vec<FileType>> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), &t.r#for))
        .collect();
    let composite_for: HashMap<&str, &Vec<FileType>> = composite_rules
        .iter()
        .map(|c| (c.id.as_str(), &c.r#for))
        .collect();

    // A leg whose definition is a `type: path`/`basename`/`dirname` matcher is
    // not subject to the origin filter at all:
    // `evaluate_basename_traits_for_entries` runs every path trait against the
    // archive's entry list with no `for:` gate, and `analyzers/archive`
    // stamps those findings with the *container's* own type. So such a leg is
    // satisfiable by a rule that names only the container, and reporting it
    // here is a false positive -- 57 of them, 8 rules' worth entirely.
    // (The container itself still has to be declared; that is
    // `find_pooling_scope_without_container`'s job, not this one's.)
    let path_legs: std::collections::HashSet<&str> = trait_definitions
        .iter()
        .filter(|t| matches!(t.r#if, Condition::Path(_)))
        .map(|t| t.id.as_str())
        .collect();

    // Union of every definition under a directory reference.
    let dir_types = |dir: &str| -> Vec<FileType> {
        let prefix = dir.trim_end_matches('/');
        let mut out: Vec<FileType> = Vec::new();
        for (id, types) in trait_for.iter().chain(composite_for.iter()) {
            if id.starts_with(prefix) && id[prefix.len()..].starts_with([':', '/']) {
                for ft in types.iter() {
                    if !out.contains(ft) {
                        out.push(*ft);
                    }
                }
            }
        }
        out
    };

    let mut found = Vec::new();
    for rule in composite_rules {
        if !matches!(
            rule.effective_scope(),
            Scope::Archive | Scope::Package | Scope::Outer
        ) {
            continue;
        }
        if rule.for_from_groups || rule.r#for.is_empty() || rule.r#for.contains(&FileType::All) {
            continue;
        }
        let own_dir = rule.id.split("::").next().unwrap_or("");
        let is_path_leg = |id: &String| -> bool {
            let qualified = format!("{own_dir}::{id}");
            path_legs.contains(id.as_str()) || path_legs.contains(qualified.as_str())
        };
        let resolve = |id: &String| -> Option<Vec<FileType>> {
            if is_path_leg(id) {
                return None;
            }
            let types: Vec<FileType> =
                if id.ends_with('/') || (id.contains('/') && !id.contains("::")) {
                    dir_types(id)
                } else {
                    let qualified = format!("{own_dir}::{id}");
                    (*trait_for
                        .get(id.as_str())
                        .or_else(|| composite_for.get(id.as_str()))
                        .or_else(|| trait_for.get(qualified.as_str()))
                        .or_else(|| composite_for.get(qualified.as_str()))?)
                    .clone()
                };
            if types.is_empty() || types.contains(&FileType::All) {
                return None;
            }
            Some(types)
        };
        let excluded = |types: &[FileType]| !types.iter().any(|ft| rule.r#for.contains(ft));

        // `any:`: only dead when EVERY alternative is excluded. One reachable
        // branch is enough for the clause, so reporting per-leg here would be
        // noise on rules that are working exactly as written.
        if let Some(any) = rule.any.as_ref() {
            let resolved: Vec<(String, Vec<FileType>)> = any
                .iter()
                .filter_map(|cond| match cond {
                    Condition::Trait { id } => resolve(id).map(|t| (id.clone(), t)),
                    _ => None,
                })
                .collect();
            if !resolved.is_empty() && resolved.iter().all(|(_, t)| excluded(t)) {
                let (leg, leg_types) = resolved[0].clone();
                found.push(LegOutsideFor {
                    id: rule.id.clone(),
                    scope: rule.effective_scope(),
                    leg,
                    leg_types,
                    role: LegRole::EveryAlternative,
                });
            } else if partial_any {
                for (leg, leg_types) in resolved.iter().filter(|(_, t)| excluded(t)) {
                    found.push(LegOutsideFor {
                        id: rule.id.clone(),
                        scope: rule.effective_scope(),
                        leg: leg.clone(),
                        leg_types: leg_types.clone(),
                        role: LegRole::DeadAlternative,
                    });
                }
            }
        }

        // `unless:`: an excluded suppressor leg silently stops suppressing.
        if let Some(unless) = rule.unless.as_ref() {
            for cond in unless {
                let Condition::Trait { id } = cond else {
                    continue;
                };
                let Some(leg_types) = resolve(id) else {
                    continue;
                };
                if excluded(&leg_types) {
                    found.push(LegOutsideFor {
                        id: rule.id.clone(),
                        scope: rule.effective_scope(),
                        leg: id.clone(),
                        leg_types,
                        role: LegRole::Suppressor,
                    });
                }
            }
        }

        let Some(all) = rule.all.as_ref() else {
            continue;
        };
        for cond in all {
            let Condition::Trait { id } = cond else {
                continue;
            };
            let Some(leg_types) = resolve(id) else {
                continue;
            };
            if !excluded(&leg_types) {
                continue;
            }
            found.push(LegOutsideFor {
                id: rule.id.clone(),
                scope: rule.effective_scope(),
                leg: id.clone(),
                leg_types,
                role: LegRole::Required,
            });
        }
    }
    found
}
