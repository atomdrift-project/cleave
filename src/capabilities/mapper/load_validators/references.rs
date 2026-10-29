//! Checks that trait and composite references resolve, and that no rule
//! references, suppresses or downgrades itself.

use super::{Report, ValidationInput, is_dynamic_metadata_ref, report};
use crate::capabilities::validation::{
    MAX_NOTABLE_DOWNGRADE_DIRECT, MAX_NOTABLE_DOWNGRADE_EXPANDED, collect_trait_refs_from_rule,
    collect_trait_refs_from_trait_def, find_broad_notable_downgrades, find_dead_downgrades,
    find_directory_shadowed_refs, find_exhaustive_suppressors, find_invalid_trait_ids,
    find_leg_suppressing_composites, find_line_number, find_self_referencing_composites,
    find_self_referencing_traits, find_self_suppressing_traits, find_uncallable_symbol_matchers,
};
use crate::composite_rules::{CompositeTrait, MetricsQuery, TraitDefinition};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::collections::HashSet;
use std::path::Path;

/// Check for invalid characters in trait/rule IDs
pub(super) fn invalid_trait_ids<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let invalid_ids = find_invalid_trait_ids(
        input.trait_definitions,
        input.composite_rules,
        input.rule_source_files,
    );
    report(move |warnings| {
        tracing::trace!("Step 7/15: Checking for invalid trait IDs");
        if !invalid_ids.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} trait/rule IDs contain invalid characters",
                invalid_ids.len()
            );
            warnings.push_id(
                "invalid-id-chars",
                format!(
                    "{} trait/rule IDs contain invalid characters",
                    invalid_ids.len()
                ),
            );
        }
    })
}

/// Self-referencing traits — `if: type: trait, id: <self>`
/// never fires because the runtime resolves the reference
/// by checking the findings table, but the trait itself
/// hasn't been added yet. Silent failure → every composite
/// depending on it is silently dead.
pub(super) fn self_referencing_traits<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let self_refs = find_self_referencing_traits(input.trait_definitions);
    report(move |warnings| {
        tracing::trace!("Step 7b/15: Checking for self-referencing traits");
        if !self_refs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} traits self-reference (will never fire)",
                self_refs.len()
            );
            eprintln!(
                "   `if: type: trait, id: <self>` queries the findings table for the\n   \
     trait being evaluated, which hasn't been added yet — the lookup is\n   \
     always false. Composites that depend on this trait silently fail.\n"
            );
            for trait_def in &self_refs {
                let source_file = input
                    .rule_source_files
                    .get(&trait_def.id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source_file, &trait_def.id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Trait '{}' references itself",
                        source_file, line, trait_def.id
                    );
                } else {
                    eprintln!(
                        "   {}: Trait '{}' references itself",
                        source_file, trait_def.id
                    );
                }
            }
            eprintln!();
            warnings.push_id(
                "self-reference",
                format!(
                    "{} self-referencing traits (will never fire)",
                    self_refs.len()
                ),
            );
        }
    })
}

/// Dead `downgrade:` clauses -- a reference that also sits in
/// `unless:`. Suppression wins, so the rule never survives long
/// enough for the downgrade to apply and the clause is unreachable.
/// Sibling of the self-suppression check below: both are cases where
/// a rule's own guards quietly cancel part of it out, and neither is
/// visible from reading the rule top to bottom.
pub(super) fn dead_downgrades<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let dead_downgrades = find_dead_downgrades(input.trait_definitions, input.composite_rules);
    report(move |warnings| {
        let disable_dead_downgrade =
            crate::validation_controls::is_validator_disabled("dead-downgrade");
        if !disable_dead_downgrade && !dead_downgrades.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} rules have a dead downgrade clause",
                dead_downgrades.len()
            );
            eprintln!(
                "   `unless:` wins over `downgrade:`. A reference in both means the rule is\n   \
     suppressed whenever it matches, so the downgrade is unreachable.\n"
            );
            for d in &dead_downgrades {
                let kind = if d.is_composite { "Rule" } else { "Trait" };
                let scope = if d.whole_clause { "clause" } else { "entries" };
                eprintln!(
                    "   {} '{}': dead downgrade.{} {} ({})",
                    kind,
                    d.id,
                    d.clause,
                    scope,
                    d.refs.join(", ")
                );
            }
            eprintln!();
            warnings.push_id(
                "dead-downgrade",
                format!(
                    "{} rules have a dead downgrade clause",
                    dead_downgrades.len()
                ),
            );
        }
    })
}

/// A directory `unless:` whose members bucket one metric field into
/// complementary halves suppresses the rule for every file that
/// emits the metric, so it can never fire.
pub(super) fn exhaustive_suppressors<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let exhaustive = find_exhaustive_suppressors(input.trait_definitions, input.composite_rules);
    report(move |warnings| {
        let disable_exhaustive =
            crate::validation_controls::is_validator_disabled("exhaustive-suppressor");
        if !disable_exhaustive && !exhaustive.is_empty() {
            eprintln!(
                "\n\u{274c} ERROR: {} rules are suppressed by a directory that covers every file",
                exhaustive.len()
            );
            eprintln!(
                "   A `- id: dir/` in `unless:` expands to every trait under it. When two of\n   \
     those bucket the same metric field into complementary halves, their union is\n   \
     the whole domain: the rule is skipped whenever the metric exists.\n   \
     Reference the one member you meant instead of the directory.\n"
            );
            for e in &exhaustive {
                let kind = if e.is_composite { "Rule" } else { "Trait" };
                eprintln!(
                    "   {} '{}' unless '{}' on {}:\n      '{}' covers <= {} and '{}' covers >= {}",
                    kind, e.id, e.dir_ref, e.field, e.low.0, e.low.1, e.high.0, e.high.1
                );
            }
            eprintln!();
            warnings.push_id(
                "exhaustive-suppressor",
                format!(
                    "{} rules are suppressed by a directory covering every file",
                    exhaustive.len()
                ),
            );
        }
    })
}

/// A `downgrade:` on a `notable` rule lands it on `Baseline`, which
/// asserts the matcher is functionality nearly every program has.
/// That is a claim about the matcher, not the context, so it must be
/// rare and narrow: capped at 4 literal entries and 8 once
/// aggregator references expand. Sibling of the excessive-suppression
/// rule above, scoped to the one transition that reclassifies a
/// behavior instead of merely de-emphasizing it.
/// A clause that names a directory and a trait inside it: the
/// directory already matches that trait, so the specific entry can
/// never change the outcome. Dead weight that reads as extra reach
/// and inflates the suppression budgets.
pub(super) fn directory_shadowed_refs<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let shadowed = find_directory_shadowed_refs(input.trait_definitions, input.composite_rules);
    report(move |warnings| {
        let disable_shadowed =
            crate::validation_controls::is_validator_disabled("directory-shadowed-ref");
        if !disable_shadowed && !shadowed.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} clauses list a directory and a trait inside it",
                shadowed.len()
            );
            eprintln!(
                "   A sibling leg already subsumes these - a duplicate, a parent directory,\n   \
     or a directory containing the trait - so they cannot change the clause.\n   \
     Drop the covered leg, or the broad one if only the narrow leg was meant\n   \
     (that case is a behavior bug, not redundancy).\n"
            );
            for s in shadowed.iter().take(40) {
                let kind = if s.is_composite { "Rule" } else { "Trait" };
                eprintln!(
                    "   {} '{}': {} leg '{}' covered by '{}' ({})",
                    kind, s.id, s.clause, s.specific, s.directory, s.kind
                );
            }
            if shadowed.len() > 40 {
                eprintln!("   ... and {} more", shadowed.len() - 40);
            }
            eprintln!();
            warnings.push_id(
                "directory-shadowed-ref",
                format!(
                    "{} clauses list a directory and a trait inside it",
                    shadowed.len()
                ),
            );
        }
    })
}

/// `type: symbol` matchers written as source text. A symbol never
/// contains a call, so these match nothing -- silently, forever.
pub(super) fn uncallable_symbol_matchers<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let uncallable =
        find_uncallable_symbol_matchers(input.trait_definitions, input.composite_rules);
    report(move |warnings| {
        let disable_uncallable =
            crate::validation_controls::is_validator_disabled("uncallable-symbol-matcher");
        if !disable_uncallable && !uncallable.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} symbol matchers are not symbols",
                uncallable.len()
            );
            eprintln!(
                "   A symbol is a dotted path of identifiers -- `platform.system`,\n   \
     `open.read`, `Date.getTimezoneOffset` -- with no parentheses and no\n   \
     argument text, in every language and for source and binaries alike.\n   \
     Spelling out the call matches nothing, and `exact:`/`substr:` compare\n   \
     literally, so a regex in those fields matches nothing either. Both\n   \
     load cleanly and then never fire. Run `cleave facts <file>` to see\n   \
     the exact strings.\n"
            );
            for u in uncallable.iter().take(40) {
                let kind = if u.is_composite { "Rule" } else { "Trait" };
                eprintln!(
                    "   {} '{}' {}: {}: {:?}\n      {}",
                    kind, u.id, u.clause, u.field, u.literal, u.suggestion
                );
            }
            if uncallable.len() > 40 {
                eprintln!("   ... and {} more", uncallable.len() - 40);
            }
            eprintln!();
            warnings.push_id(
                "uncallable-symbol-matcher",
                format!("{} symbol matchers are not symbols", uncallable.len()),
            );
        }
    })
}

/// `notable` rules that a `downgrade:` sends to baseline on too broad a
/// trigger.
pub(super) fn broad_notable_downgrades<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let broad_downgrades =
        find_broad_notable_downgrades(input.trait_definitions, input.composite_rules);
    report(move |warnings| {
        let disable_broad_downgrade =
            crate::validation_controls::is_validator_disabled("broad-notable-downgrade");
        if !disable_broad_downgrade && !broad_downgrades.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} notable rules downgrade to baseline on too broad a trigger",
                broad_downgrades.len()
            );
            eprintln!(
                "   `baseline` means functionality nearly every program has. A behavior does\n   \
     not become universal because of where it sits, so a notable rule may cross\n   \
     that line only on a narrow, argued trigger: at most {} direct `downgrade:`\n   \
     entries and {} after expanding aggregator/directory references.\n",
                MAX_NOTABLE_DOWNGRADE_DIRECT, MAX_NOTABLE_DOWNGRADE_EXPANDED
            );
            for d in &broad_downgrades {
                let kind = if d.is_composite { "Rule" } else { "Trait" };
                eprintln!(
                    "   {} '{}': {} direct, {} expanded",
                    kind, d.id, d.direct, d.expanded
                );
            }
            eprintln!();
            warnings.push_id(
                "broad-notable-downgrade",
                format!(
                    "{} notable rules downgrade to baseline on too broad a trigger",
                    broad_downgrades.len()
                ),
            );
        }
    })
}

/// Self-suppressing / self-downgrading atomic traits. Same class of
/// bug as the composite check below, but on `unless:`/`downgrade:`
/// instead of `all:`/`any:` — and quieter, because the trait matches
/// fine in isolation and only dies during a real scan.
pub(super) fn self_suppressing_traits<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let self_suppress = find_self_suppressing_traits(input.trait_definitions);
    report(move |warnings| {
        tracing::trace!("Step 7b2/15: Checking for self-suppressing traits");
        if !self_suppress.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} traits suppress or downgrade themselves",
                self_suppress.len()
            );
            eprintln!(
                "   A trait listed in its own `unless:` — directly, or through a\n   \
     directory reference that expands to include it — is satisfied by its\n   \
     own match, so it can never surface. In `downgrade:` the same shape\n   \
     pins it one criticality level below what it declares. Reference the\n   \
     specific sibling traits it should defer to instead of the directory.\n"
            );
            for (trait_def, ref_id, clause) in &self_suppress {
                let source_file = input
                    .rule_source_files
                    .get(&trait_def.id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source_file, &trait_def.id);
                let location = line_hint
                    .map(|line| format!("{source_file}:{line}"))
                    .unwrap_or_else(|| source_file.to_string());
                eprintln!(
                    "   {}: Trait '{}' names itself in `{}:` through '{}'",
                    location, trait_def.id, clause, ref_id
                );
            }
            eprintln!();
            warnings.push_id(
                "self-suppression",
                format!(
                    "{} traits suppress or downgrade themselves",
                    self_suppress.len()
                ),
            );
        }
    })
}

/// Composites that reference themselves, directly or through a directory
/// reference: they never fire.
pub(super) fn self_referencing_composites<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let composite_self_refs = find_self_referencing_composites(input.composite_rules);
    report(move |warnings| {
        tracing::trace!("Step 7c/15: Checking for self-referencing composites");
        if !composite_self_refs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composites self-reference (will never fire)",
                composite_self_refs.len()
            );
            eprintln!(
                "   A composite cannot reference itself directly, or through a directory\n   \
     reference that expands to include its own rule ID. Directory refs in\n   \
     the same directory as the composite are recursive.\n"
            );
            for (rule, ref_id) in &composite_self_refs {
                let source_file = input
                    .rule_source_files
                    .get(&rule.id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source_file, &rule.id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' references itself through '{}'",
                        source_file, line, rule.id, ref_id
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' references itself through '{}'",
                        source_file, rule.id, ref_id
                    );
                }
            }
            eprintln!();
            warnings.push_id(
                "self-reference",
                format!(
                    "{} self-referencing composites (will never fire)",
                    composite_self_refs.len()
                ),
            );
        }
    })
}

/// Composites whose `unless:` or `downgrade:` covers one of their own
/// required legs.
pub(super) fn leg_suppressing_composites<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let leg_suppress = find_leg_suppressing_composites(input.composite_rules);
    report(move |warnings| {
        tracing::trace!("Step 7d/15: Checking for composites suppressed by their own legs");
        let disable_leg_suppression =
            crate::validation_controls::is_validator_disabled("leg-suppression");
        if !disable_leg_suppression && !leg_suppress.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composites are suppressed or downgraded by their own legs",
                leg_suppress.len()
            );
            eprintln!(
                "   An `unless:` entry that covers a required leg -- the same id, or a\n   \
     directory containing it -- is satisfied by every match, so the rule\n   \
     never fires; in `downgrade:` it never reaches its declared tier. Name\n   \
     the specific context to defer to instead of the leg's directory.\n"
            );
            for (rule, suppressor, leg, clause) in &leg_suppress {
                let source_file = input
                    .rule_source_files
                    .get(&rule.id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let location = find_line_number(source_file, &rule.id)
                    .map(|line| format!("{source_file}:{line}"))
                    .unwrap_or_else(|| source_file.to_string());
                eprintln!(
                    "   {location}: Rule '{}' `{clause}:` '{suppressor}' covers its required leg '{leg}'",
                    rule.id
                );
            }
            eprintln!();
            warnings.push_id(
                "leg-suppression",
                format!(
                    "{} composites are suppressed or downgraded by their own legs",
                    leg_suppress.len()
                ),
            );
        }
    })
}

/// Composite references across directories must name a directory some trait
/// or composite lives in.
pub(super) fn unresolved_trait_prefixes<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |_| {
        report_unresolved_trait_prefixes(input.composite_rules, &input.prefix_hierarchy)
    })
}

/// [`unresolved_trait_prefixes`] without the rest of the linter: the one
/// check every load makes.
pub(super) fn report_unresolved_trait_prefixes(
    composite_rules: &[CompositeTrait],
    prefix_hierarchy: &HashSet<&str>,
) {
    tracing::trace!("Step 8/15: Validating trait references in composite rules");
    // Each rule is checked on its own, so the rules are checked in parallel.
    let invalid_refs = composite_rules
        .par_iter()
        .flat_map_iter(collect_trait_refs_from_rule)
        .filter(|(ref_id, _)| {
            // Only validate cross-directory references (those with slashes or ::)
            // Skip validation for metadata/ paths - these are dynamically generated
            let is_cross_dir = ref_id.contains("::") || ref_id.contains('/');
            if !is_cross_dir || is_dynamic_metadata_ref(ref_id) {
                return false;
            }

            // Extract the directory part for validation
            let dir_part = if let Some(idx) = ref_id.find("::") {
                &ref_id[..idx]
            } else if let Some(idx) = ref_id.rfind('/') {
                &ref_id[..idx]
            } else {
                &ref_id[..]
            };

            // Check if this matches any known prefix (O(1) lookup instead of O(n) iteration)
            // Check exact match or any parent path exists in hierarchy
            let matches_prefix = prefix_hierarchy.contains(dir_part)
                || dir_part
                    .match_indices('/')
                    .any(|(i, _)| prefix_hierarchy.contains(&dir_part[..i]));
            !matches_prefix
        })
        .count();

    if invalid_refs > 0 {
        eprintln!(
            "\n❌ ERROR: {} invalid trait references found in composite rules",
            invalid_refs
        );
    }
}

/// Validate that composite rules don't reference the
/// retired `metadata/internal/symbols::*` namespace. The
/// auto-emit was removed because it dominated diff/output
/// noise for binaries with many imports; YAML rules that
/// need to gate on a specific symbol/function call should
/// use inline `type: symbol, exact: <name>` conditions.
pub(super) fn retired_internal_refs<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        tracing::trace!("Step 11/15: Checking for retired internal/symbols references");
        let internal_refs: Vec<_> = input
            .composite_rules
            .par_iter()
            .flat_map_iter(collect_trait_refs_from_rule)
            .filter(|(ref_id, _)| ref_id.starts_with("metadata/internal/"))
            .map(|(ref_id, rule_id)| {
                let source_file = input
                    .rule_source_files
                    .get(&rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                (rule_id, ref_id, source_file)
            })
            .collect();

        if !internal_refs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} composite rules reference the retired metadata/internal/ namespace",
                internal_refs.len()
            );
            eprintln!(
                "   The metadata/internal/symbols::* auto-emit was removed; replace each reference with an inline `type: symbol, exact: <name>` condition.\n"
            );
            for (rule_id, ref_id, source_file) in &internal_refs {
                let line_hint = find_line_number(source_file, ref_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' references retired path: '{}'",
                        source_file, line, rule_id, ref_id
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' references retired path: '{}'",
                        source_file, rule_id, ref_id
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} composite rules reference retired metadata/internal/ paths",
                internal_refs.len()
            ));
        }
    })
}

/// References from composites and traits to ids that no trait or
/// composite defines.
pub(super) fn broken_references<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let file_stem_hints = build_file_stem_reference_hints(
        input.dir_path,
        input.trait_definitions,
        input.composite_rules,
    );
    report(move |warnings| {
        let mut broken_refs = Vec::new();
        // Validate a single `(ref_id, owner_id)` pair. Returns `Some(..)` when the
        // reference resolves to nothing — a `::`-qualified ref with no exactly-matching
        // trait/composite (the runtime requires an exact match for `::` refs; see
        // `eval_trait` / `unless_trait_id_matches`), or a slashed ref under no known
        // directory.
        //
        // `bare_resolves_by_suffix` distinguishes the two ref sources: composite refs are
        // auto-prefixed at load, so a bare same-file ref has already become a full
        // `dir::id` and must resolve exactly. Atomic-trait refs are NOT auto-prefixed, so a
        // bare ref (no `::`, no `/`) resolves at runtime by suffix match across directories
        // — that path is left to the runtime rather than flagged here.
        let check_ref = |ref_id: String,
                         owner_id: &str,
                         bare_resolves_by_suffix: bool|
         -> Option<BrokenTraitReference> {
            // Directory-level references (intentional loose coupling): "discovery/system"
            // matches any trait in that directory; parent refs like "micro-behaviors/fs/write/"
            // match traits in subdirs.
            let ref_without_slash = ref_id.trim_end_matches('/');
            let is_directory_ref = input.prefix_hierarchy.contains(ref_id.as_str())
                || input.prefix_hierarchy.contains(ref_without_slash);

            // Dynamically generated metadata/* references (imports, signatures,
            // entitlements, embedded-language detection) have no static trait
            // definition, so exempt them.
            let is_dynamic_or_internal = is_dynamic_metadata_ref(&ref_id);

            // Bare same-directory reference on an atomic trait — resolves at runtime by
            // suffix match, not validated here.
            let is_bare_suffix_ref =
                bare_resolves_by_suffix && !ref_id.contains("::") && !ref_id.contains('/');

            // Exact-match requirement: references like "micro-behaviors/foo/bar/filename"
            // where "filename" is a YAML file (not a directory) are invalid — filenames are
            // never part of trait IDs, only the directory path is used for prefixing.
            if is_directory_ref
                || is_dynamic_or_internal
                || is_bare_suffix_ref
                || input.valid_trait_ids.contains(&ref_id)
            {
                return None;
            }

            let source_file = input
                .rule_source_files
                .get(owner_id)
                .map(std::string::String::as_str)
                .unwrap_or("unknown");
            let line_hint = find_line_number(source_file, &ref_id);
            // An id in an engine namespace that its emitter can never
            // produce: say why, since there is no YAML file to point at.
            let suggestion =
                match crate::capabilities::validation::emitted::check_emitted_ref(&ref_id) {
                    Some(Err(why)) => Some(why),
                    _ => build_filename_reference_suggestion(&ref_id, &file_stem_hints),
                };
            Some(BrokenTraitReference {
                rule_id: owner_id.to_string(),
                ref_id,
                source_file: source_file.to_string(),
                line_hint,
                suggestion,
            })
        };

        // Each reference is checked on its own, so rules and traits are
        // checked in parallel; `par_extend` keeps their order.
        broken_refs.par_extend(input.composite_rules.par_iter().flat_map_iter(|rule| {
            collect_trait_refs_from_rule(rule)
                .into_iter()
                .filter_map(|(ref_id, rule_id)| check_ref(ref_id, &rule_id, false))
        }));
        // Atomic traits reference other traits in their `if:`, `unless:`, and `downgrade:`
        // clauses; those refs went unvalidated before this loop, so dangling `::` refs
        // (e.g. a YAML-filename-in-ID exemption) silently became no-ops.
        broken_refs.par_extend(
            input
                .trait_definitions
                .par_iter()
                .flat_map_iter(|trait_def| {
                    collect_trait_refs_from_trait_def(trait_def)
                        .into_iter()
                        .filter_map(|(ref_id, owner_id)| check_ref(ref_id, &owner_id, true))
                }),
        );

        if !broken_refs.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} broken trait references found in composite rules",
                broken_refs.len()
            );
            eprintln!("   Composite rules reference trait IDs that don't exist:\n");
            for broken_ref in &broken_refs {
                if let Some(line) = broken_ref.line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' references non-existent trait: '{}'",
                        broken_ref.source_file, line, broken_ref.rule_id, broken_ref.ref_id
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' references non-existent trait: '{}'",
                        broken_ref.source_file, broken_ref.rule_id, broken_ref.ref_id
                    );
                }
                if let Some(suggestion) = &broken_ref.suggestion {
                    eprintln!("      {}", suggestion);
                }
            }
            eprintln!();
            warnings.push_id(
                "broken-reference",
                format!(
                    "{} broken trait references in composite rules",
                    broken_refs.len()
                ),
            );
            for broken_ref in &broken_refs {
                let location = if let Some(line) = broken_ref.line_hint {
                    format!("{}:{}", broken_ref.source_file, line)
                } else {
                    broken_ref.source_file.clone()
                };
                let mut detail = format!(
                    "{location}: Rule '{}' references non-existent trait '{}'",
                    broken_ref.rule_id, broken_ref.ref_id
                );
                if let Some(suggestion) = &broken_ref.suggestion {
                    detail.push_str(&format!(" — {suggestion}"));
                }
                warnings.push(detail);
            }
        }
    })
}

/// Validate metric field references
pub(super) fn unknown_metric_fields<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        let valid_metric_fields: rustc_hash::FxHashSet<String> =
            crate::types::field_paths::all_valid_metric_paths()
                .into_iter()
                .collect();
        let mut invalid_metric_refs = Vec::new();

        for trait_def in input.trait_definitions {
            if let crate::composite_rules::Condition::Metrics(MetricsQuery { field, .. }) =
                &trait_def.r#if
                && !valid_metric_fields.contains(field)
                && !is_open_filefacts_metric_path(field)
            {
                let source_file = input
                    .trait_source_files
                    .get(&trait_def.id)
                    .map(String::as_str)
                    .unwrap_or("unknown");
                invalid_metric_refs.push((
                    trait_def.id.clone(),
                    field.clone(),
                    source_file.to_string(),
                ));
            }
        }

        if !crate::validation_controls::is_validator_disabled("unknown-metric-field")
            && !invalid_metric_refs.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} unknown metric field references found in traits",
                invalid_metric_refs.len()
            );
            eprintln!("   Traits reference metric fields that don't exist:\n");
            for (trait_id, field, source_file) in &invalid_metric_refs {
                let line_hint = find_line_number(source_file, field);
                let suggestion =
                    super::super::helpers::suggest_metric_field(&valid_metric_fields, field);
                if let Some(line) = line_hint {
                    if let Some(suggested) = suggestion {
                        eprintln!(
                            "   {}:{}: Trait '{}' references unknown metric '{}' (did you mean '{}'?)",
                            source_file, line, trait_id, field, suggested
                        );
                    } else {
                        eprintln!(
                            "   {}:{}: Trait '{}' references unknown metric '{}'",
                            source_file, line, trait_id, field
                        );
                    }
                } else if let Some(suggested) = suggestion {
                    eprintln!(
                        "   {}: Trait '{}' references unknown metric '{}' (did you mean '{}'?)",
                        source_file, trait_id, field, suggested
                    );
                } else {
                    eprintln!(
                        "   {}: Trait '{}' references unknown metric '{}'",
                        source_file, trait_id, field
                    );
                }
            }
            eprintln!("\n   Valid metric fields:");
            let mut sorted_fields: Vec<&String> = valid_metric_fields.iter().collect();
            sorted_fields.sort();
            for field in sorted_fields.iter().take(10) {
                eprintln!("     - {}", field);
            }
            if sorted_fields.len() > 10 {
                eprintln!("     ... and {} more", sorted_fields.len() - 10);
            }
            eprintln!();
            warnings.push(format!(
                "{} unknown metric field references in traits",
                invalid_metric_refs.len()
            ));
        }
    })
}

#[derive(Debug, Clone)]
struct FileStemReferenceHint {
    filename_stem: String,
    directory_ref: String,
    available_ids: Vec<String>,
}

#[derive(Debug, Clone)]
struct BrokenTraitReference {
    rule_id: String,
    ref_id: String,
    source_file: String,
    line_hint: Option<usize>,
    suggestion: Option<String>,
}

fn trait_local_id(id: &str) -> &str {
    if let Some((_, local_id)) = id.rsplit_once("::") {
        local_id
    } else {
        id.rsplit('/').next().unwrap_or(id)
    }
}

fn normalize_ref_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Whether a metric path is one of filefacts' *templated* keys — the few
/// whose trailing segment is data read out of the file rather than a fixed
/// name, such as `ast.op.<operator>` or `archive.format.<entry_type>_count`.
///
/// Every other key is checked by exact name against the catalog. This used to
/// wave through 44 whole namespaces, on the grounds that filefacts' key set
/// was open-ended and grew with its extractors. It no longer is: filefacts
/// fails its own build on an undeclared key and enumerates the result. The
/// blanket exemption is exactly what let a batch of renamed metrics keep
/// validating while matching nothing.
fn is_open_filefacts_metric_path(field: &str) -> bool {
    let (_, families) = filefacts::known_metrics();
    families
        .iter()
        .any(|template| matches_metric_family(field, template))
}

/// Match a concrete metric path against a family template.
///
/// A template alternates literal text with a `<placeholder>`. A placeholder
/// stands for one path segment and never spans a `.`, which is what stops
/// `source.query_limited.<query>` from swallowing
/// `source.query_limited.identifiers.match_limit` — that one has its own
/// template, and matching it here would hide a typo in the suffix.
fn matches_metric_family(field: &str, template: &str) -> bool {
    let mut rest = field;
    let mut tmpl = template;
    loop {
        let Some(open) = tmpl.find('<') else {
            return rest == tmpl;
        };
        let Some(r) = rest.strip_prefix(&tmpl[..open]) else {
            return false;
        };
        rest = r;
        let Some(close) = tmpl[open..].find('>') else {
            return false;
        };
        tmpl = &tmpl[open + close + 1..];

        // The placeholder runs up to whatever literal follows it.
        let next_literal = &tmpl[..tmpl.find('<').unwrap_or(tmpl.len())];
        let width = if next_literal.is_empty() {
            rest.len()
        } else {
            match rest.find(next_literal) {
                Some(at) => at,
                None => return false,
            }
        };
        if width == 0 || rest[..width].contains('.') {
            return false;
        }
        rest = &rest[width..];
    }
}

fn format_reference_choices(ids: &[String]) -> String {
    const MAX_CHOICES: usize = 4;
    let mut rendered: Vec<String> = ids
        .iter()
        .take(MAX_CHOICES)
        .map(|id| format!("'{id}'"))
        .collect();
    if ids.len() > MAX_CHOICES {
        rendered.push(format!("... and {} more", ids.len() - MAX_CHOICES));
    }
    rendered.join(", ")
}

fn build_file_stem_reference_hints(
    dir_path: &Path,
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> FxHashMap<String, FileStemReferenceHint> {
    let mut hints = FxHashMap::default();

    let mut register = |id: &str, defined_in: &Path| {
        let Ok(relative_path) = defined_in.strip_prefix(dir_path) else {
            return;
        };
        let file_stem_path = relative_path.with_extension("");
        let file_stem_ref = normalize_ref_path(&file_stem_path);
        if file_stem_ref.is_empty() {
            return;
        }

        let filename_stem = file_stem_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        let directory_ref = relative_path
            .parent()
            .map(normalize_ref_path)
            .unwrap_or_default();

        let entry = hints
            .entry(file_stem_ref)
            .or_insert_with(|| FileStemReferenceHint {
                filename_stem,
                directory_ref,
                available_ids: Vec::new(),
            });
        if !entry.available_ids.iter().any(|existing| existing == id) {
            entry.available_ids.push(id.to_string());
        }
    };

    for trait_def in trait_definitions {
        register(&trait_def.id, &trait_def.defined_in);
    }
    for rule in composite_rules {
        register(&rule.id, &rule.defined_in);
    }

    for hint in hints.values_mut() {
        hint.available_ids.sort();
    }

    hints
}

fn build_filename_reference_suggestion(
    ref_id: &str,
    file_stem_hints: &FxHashMap<String, FileStemReferenceHint>,
) -> Option<String> {
    let (path_part, local_id) = if let Some((path_part, local_id)) = ref_id.split_once("::") {
        (path_part.trim_end_matches('/'), Some(local_id))
    } else {
        (ref_id.trim_end_matches('/'), None)
    };

    let hint = file_stem_hints.get(path_part)?;

    match local_id {
        Some(local_id) => {
            if let Some(suggested) = hint
                .available_ids
                .iter()
                .find(|candidate| trait_local_id(candidate) == local_id)
            {
                Some(format!(
                    "Hint: '{ref_id}' includes YAML filename '{}'. Filenames are never part of trait IDs. Use '{suggested}' instead.",
                    hint.filename_stem
                ))
            } else if !hint.available_ids.is_empty() {
                Some(format!(
                    "Hint: '{ref_id}' includes YAML filename '{}'. Filenames are never part of trait IDs. Drop the filename segment and use one of: {}.",
                    hint.filename_stem,
                    format_reference_choices(&hint.available_ids)
                ))
            } else {
                None
            }
        }
        None => {
            if hint.available_ids.is_empty() {
                return None;
            }

            let specific_rule_hint = if hint.available_ids.len() == 1 {
                format!(
                    "Use {} for the specific rule.",
                    format_reference_choices(&hint.available_ids)
                )
            } else {
                format!(
                    "Use one of {} for specific rules.",
                    format_reference_choices(&hint.available_ids)
                )
            };

            if hint.directory_ref.is_empty() {
                Some(format!(
                    "Hint: '{ref_id}' points to YAML file '{}.yaml', not a trait ID. Filenames are never part of trait IDs. {specific_rule_hint}",
                    hint.filename_stem
                ))
            } else {
                Some(format!(
                    "Hint: '{ref_id}' points to YAML file '{}.yaml', not a trait directory. Filenames are never part of trait IDs. {specific_rule_hint} If you intended a directory reference, use '{}'.",
                    hint.filename_stem, hint.directory_ref
                ))
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{is_open_filefacts_metric_path, matches_metric_family};

    /// Fixed keys are accepted by exact name, not because their namespace is
    /// waved through. The second list is the point of the change: these are
    /// real metric names from before the cleave→filefacts migration, and
    /// under the old namespace exemption every one of them validated while
    /// matching nothing.
    #[test]
    fn fixed_metric_keys_are_checked_by_name() {
        let valid = crate::types::field_paths::all_valid_metric_paths();
        for field in [
            "chm.user_entry_count",
            "archive.member_count",
            "image.width",
            "wasm.import_count",
            "registry.downloads_recent",
            "file.entropy",
        ] {
            assert!(valid.contains(field), "{field} should be a known metric");
        }

        for field in [
            "binary.overall_entropy",
            "text.total_lines",
            "strings.total",
            "pe.has_rich_header",
            "chmx.user_entry_count",
        ] {
            assert!(
                !valid.contains(field) && !is_open_filefacts_metric_path(field),
                "{field} is not emitted and must not validate"
            );
        }
    }

    /// Templated keys are matched by shape, one path segment per placeholder.
    #[test]
    fn templated_metric_keys_match_by_shape() {
        for field in [
            "ast.op.xor",
            "archive.compression.method_counts.deflate",
            "archive.format.regular_count",
            "consistency.extension_content_mismatch.binary_as_text",
            "source.query_limited.identifiers",
            "source.query_limited.identifiers.output_limit",
        ] {
            assert!(
                is_open_filefacts_metric_path(field),
                "{field} should match a family"
            );
        }

        // A placeholder covers one segment, so a template must not swallow a
        // longer path that has a template of its own — otherwise a typo in
        // the suffix would validate against the shorter form.
        assert!(!matches_metric_family(
            "source.query_limited.identifiers.output_limit",
            "source.query_limited.<query>"
        ));
        // An empty placeholder is not a value.
        assert!(!matches_metric_family("ast.op.", "ast.op.<operator>"));
        // Literal text around the placeholder still has to line up.
        assert!(!matches_metric_family("ast.ops.xor", "ast.op.<operator>"));
    }
}
