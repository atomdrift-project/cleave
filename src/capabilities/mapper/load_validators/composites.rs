//! Checks on how composites assemble evidence: escalation, suppression,
//! convictions, orphaned components and oversized directories.

use super::{Report, ValidationInput, enabled, report};
use crate::capabilities::validation::{
    collect_trait_refs_from_rule, find_bare_or_crit_escalations, find_container_name_convictions,
    find_convictions_without_content, find_dangling_directory_refs, find_excessive_file_types,
    find_excessive_skip_conditions, find_hostile_composites_with_too_few_notable_legs,
    find_line_number, find_one_fact_convictions, find_orphaned_components,
    find_oversized_source_directories, find_oversized_trait_directories, find_pure_alias_traits,
    find_short_pattern_warnings, find_subsumed_required_legs, validate_composite_trait_only,
};
use crate::composite_rules::FileType as RuleFileType;
use crate::types::Criticality;
use rustc_hash::FxHashMap;

/// Validate: a bare `any:` composite must agree with its legs about
/// how serious a match is. Without that agreement the tier a file
/// gets depends on which leg happened to match.
pub(super) fn bare_or_crit_escalations<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let or_escalations =
        find_bare_or_crit_escalations(input.trait_definitions, input.composite_rules);
    report(move |warnings| {
        let disable_or_escalation =
            crate::validation_controls::is_validator_disabled("bare-or-crit-escalation");
        if !disable_or_escalation && !or_escalations.is_empty() {
            let legs: usize = or_escalations.iter().map(|(_, _, l)| l.len()).sum();
            eprintln!(
                "\n❌ ERROR: {} bare `any:` composites outrank {legs} leg(s) while adding no filtering",
                or_escalations.len()
            );
            eprintln!(
                "   These composites are nothing but their `any:` list — no all:/unless:/not:/"
            );
            eprintln!(
                "   downgrade:/needs:/size/scope, and a for:/platforms: identical to every leg."
            );
            eprintln!(
                "   They fire exactly where their legs do, on whichever one matched, so a leg"
            );
            eprintln!("   below the composite makes the reported tier depend on which leg it was.");
            eprintln!(
                "   Raise these legs to the composite's crit:, or add the filtering that earns it:\n"
            );
            for (rule_id, crit, under_ranked) in &or_escalations {
                let source = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                match find_line_number(source, rule_id) {
                    Some(line) => eprintln!("   {source}:{line}: '{rule_id}' ({crit:?})"),
                    None => eprintln!("   {source}: '{rule_id}' ({crit:?})"),
                }
                for (leg_id, leg_crit) in under_ranked {
                    eprintln!("      leg {leg_id} is {leg_crit:?}");
                }
            }
            eprintln!();
            warnings.push_id(
                "bare-or-crit-escalation",
                format!(
                    "{} bare `any:` composites outrank {legs} leg(s) while adding no filtering",
                    or_escalations.len()
                ),
            );
        }
    })
}

/// Rules with too many `unless:`/`downgrade:` suppressions, written on the
/// rule or once referenced aggregators are expanded.
pub(super) fn excessive_suppressions<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let excessive_skips =
        find_excessive_skip_conditions(input.trait_definitions, input.composite_rules);
    report(move |warnings| {
        let disable_excessive_suppression_validation =
            crate::validation_controls::is_validator_disabled("excessive-suppression");

        // Validate: excessive unless:/downgrade: suppressions
        // (on the rule itself, or once referenced aggregators are expanded)
        if !disable_excessive_suppression_validation && !excessive_skips.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} rules exceed a suppression limit ({}+ written on the rule, or {}+ after expanding aggregator references)",
                excessive_skips.len(),
                crate::capabilities::validation::MAX_OWN_SUPPRESSIONS,
                crate::capabilities::validation::MAX_AGGREGATE_SUPPRESSIONS
            );
            eprintln!(
                "   A heavy suppression list usually means the rule is fighting its own breadth."
            );
            eprintln!("   In order of preference, try:");
            eprintln!(
                "     • downgrade the parent rule — if it is suppressed this often it is pitched"
            );
            eprintln!(
                "       too high; lowering its `crit:` is usually a one-line fix and needs no carve-outs"
            );
            eprintln!(
                "     • split by file type — a `suspicious` variant for the risky types and a"
            );
            eprintln!(
                "       `notable` variant elsewhere, instead of one rule plus a pile of `unless:`"
            );
            eprintln!(
                "     • group the exceptions — find the broader semantic that the carve-outs share"
            );
            eprintln!(
                "       (e.g. \"test fixture\", \"vendored dependency\") and express it once, not N times"
            );
            eprintln!(
                "     • drop dead downgrades — conditions that can never lower the criticality"
            );
            eprintln!(
                "     • tighten scope — narrow `for:` file types or add `size_min`/`size_max`"
            );
            eprintln!(
                "     • prefer a `dir/` reference over many `::leaf` ones — a directory reference"
            );
            eprintln!("       counts as 1 and does not sum in its members' suppressions");
            eprintln!(
                "   If it still gives no signal to humans or ML pipelines, consider removing it:\n"
            );
            for v in &excessive_skips {
                let source = input
                    .rule_source_files
                    .get(&v.id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, &v.id);
                let kind = if v.is_composite { "composite" } else { "trait" };
                let location = match line_hint {
                    Some(line) => format!("{source}:{line}"),
                    None => source.to_string(),
                };
                eprintln!(
                    "   {location}: {kind} '{}' ({} written; {} after expanding aggregators)",
                    v.id, v.own, v.expanded
                );
                let mut tree = String::new();
                for branch in &v.branches {
                    branch.render(0, &mut tree);
                }
                eprint!("{tree}");
            }
            eprintln!();
            warnings.push_count(
                "excessive-suppression",
                excessive_skips.len(),
                format!(
                    "{} rules have excessive unless:/downgrade: clauses",
                    excessive_skips.len()
                ),
            );
        }
    })
}

/// Validate: traits/rules with 9+ explicit file types (suggest a named group instead)
pub(super) fn excessive_file_types<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let excessive_for = find_excessive_file_types(input.trait_definitions, input.composite_rules);
    report(move |warnings| {
        if !excessive_for.is_empty() {
            eprintln!(
                "\n⚠️  WARNING: {} traits/rules specify 9+ explicit file types",
                excessive_for.len()
            );
            eprintln!(
                "   Enumerating many types is fragile and hard to maintain — use a named group:"
            );
            eprintln!(
                "   binaries, scripts, source, manifests, build, documents, media, or data\n"
            );
            for (id, count, suggestion, is_composite) in &excessive_for {
                let source = input
                    .rule_source_files
                    .get(id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, id);
                let kind = if *is_composite { "composite" } else { "trait" };
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: {} '{}' ({} types — {})",
                        source, line, kind, id, count, suggestion
                    );
                } else {
                    eprintln!(
                        "   {}: {} '{}' ({} types — {})",
                        source, kind, id, count, suggestion
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} traits/rules specify 9+ explicit file types (use a named group)",
                excessive_for.len()
            ));
        }
    })
}

/// Validate: pure alias traits that add no value
pub(super) fn pure_alias_traits<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let pure_aliases = find_pure_alias_traits(input.trait_definitions);
    report(move |warnings| {
        if !crate::validation_controls::is_validator_disabled("pure-alias")
            && !pure_aliases.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} traits are pure aliases with no added value",
                pure_aliases.len()
            );
            eprintln!(
                "   These traits reference another trait via `if: id:` but add no constraints:"
            );
            eprintln!("   - No filtering (count_min, count_max, section, etc.)");
            eprintln!("   - No unless/not/downgrade modifiers");
            eprintln!("   A different `crit:` does not count: the alias matches exactly what its");
            eprintln!("   target matches, so it reports the same evidence twice under two names.");
            eprintln!(
                "   Either add constraints/modifiers or reference the original trait directly:\n"
            );
            for (trait_id, ref_id) in &pure_aliases {
                let source = input
                    .rule_source_files
                    .get(trait_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                let line_hint = find_line_number(source, trait_id);
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: '{}' -> '{}'", source, line, trait_id, ref_id);
                } else {
                    eprintln!("   {}: '{}' -> '{}'", source, trait_id, ref_id);
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} traits are pure aliases with no added value",
                pure_aliases.len()
            ));
        }
    })
}

/// Validate: orphaned component traits not referenced by any rule
pub(super) fn orphaned_components<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let orphaned_components = find_orphaned_components(
        input.trait_definitions,
        input.composite_rules,
        input.rule_source_files,
    );
    report(move |warnings| {
        let disable_orphaned_components_validation =
            crate::validation_controls::is_validator_disabled("orphaned-components");
        if !disable_orphaned_components_validation && !orphaned_components.is_empty() {
            eprintln!(
                "\n⚠️  WARNING: {} component traits are never referenced",
                orphaned_components.len()
            );
            eprintln!(
                "   Component traits (crit: component) are building blocks that should only exist"
            );
            eprintln!("   to be referenced by composite rules or via `if: id:` in other traits.");
            eprintln!("   These components are orphaned and serve no purpose:\n");
            for (trait_id, source_file) in &orphaned_components {
                let line_hint = find_line_number(source_file, trait_id);
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: '{}'", source_file, line, trait_id);
                } else {
                    eprintln!("   {}: '{}'", source_file, trait_id);
                }
            }
            eprintln!();
            eprintln!(
                "   Add it as a dependent trait within a composite rule, or delete the rule."
            );
            eprintln!();
            warnings.push(format!(
                "{} component traits are orphaned (not referenced by any rule)",
                orphaned_components.len()
            ));
        }
    })
}

/// Validate: hostile composites must reference at least two distinct
/// notable-or-higher evidence legs, following nested composites and
/// directory references transitively.
pub(super) fn hostile_too_few_notable_legs<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let hostile_too_few_notable = find_hostile_composites_with_too_few_notable_legs(
        input.trait_definitions,
        input.composite_rules,
    );
    report(move |warnings| {
        let disable_hostile_notable_legs =
            crate::validation_controls::is_validator_disabled("hostile-too-few-notable-legs");
        if !disable_hostile_notable_legs && !hostile_too_few_notable.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} hostile composites reference fewer than two notable-or-higher legs",
                hostile_too_few_notable.len()
            );
            eprintln!("   Every hostile composite must reference at least two distinct");
            eprintln!("   notable/suspicious/hostile evidence legs in its any:/all: tree.");
            eprintln!("   Upgrade purpose-defining legs to notable per TAXONOMY.md, or");
            eprintln!("   delete a low-quality hostile composite:\n");
            for rule_id in &hostile_too_few_notable {
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
                "{} hostile composites reference fewer than two notable-or-higher legs",
                hostile_too_few_notable.len()
            ));
        }
    })
}

/// Validate: a conviction must not require the scanned container's own
/// filename. That name is assigned when a specimen is fetched or filed,
/// so the rule matches one stored copy and nothing the attacker ships.
pub(super) fn container_name_convictions<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let container_name_convictions =
        find_container_name_convictions(input.trait_definitions, input.composite_rules);
    report(move |warnings| {
        let disable_container_name =
            crate::validation_controls::is_validator_disabled("container-name-conviction");
        if !disable_container_name && !container_name_convictions.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} convictions require a filename the attack does not control",
                container_name_convictions.len()
            );
            eprintln!("   A container's name is chosen by whoever downloaded it, so these");
            eprintln!("   rules convict one stored copy and miss the malware everywhere else.");
            eprintln!();
            eprintln!("   Fix, in order of preference:");
            eprintln!("     1. Delete the basename leg. The remaining legs usually already");
            eprintln!("        describe what is inside the artifact, which is the real evidence.");
            eprintln!("     2. If the name is genuine evidence, move it from all: to any: so it");
            eprintln!("        corroborates the content legs instead of gating them.");
            eprintln!("     3. Only a name the FORMAT mandates may be required (SKILL.md,");
            eprintln!("        package.json, AUTOEXEC.BAT) -- state it in metadata/ or");
            eprintln!("        well-known/app/ as a notable format fact and reference that.");
            eprintln!("   See TAXONOMY.md, \"Names an attacker or a collector chose\".\n");
            for (rule_id, trait_id, literal, reason) in &container_name_convictions {
                let source = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                match find_line_number(source, rule_id) {
                    Some(line) => eprintln!("   {source}:{line}: '{rule_id}'"),
                    None => eprintln!("   {source}: '{rule_id}'"),
                }
                eprintln!("      requires '{trait_id}' = \"{literal}\"");
                eprintln!("      {reason}");
            }
            eprintln!();
            warnings.push(format!(
                "{} convictions require a collector-assigned container filename",
                container_name_convictions.len()
            ));
        }
    })
}

/// Validate: an all: leg that another leg already requires. The rule
/// matches the same files without it, but reads as more evidence.
pub(super) fn subsumed_required_legs<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let subsumed = if enabled("subsumed-required-leg") {
        find_subsumed_required_legs(input.trait_definitions, input.composite_rules)
    } else {
        Vec::new()
    };
    report(move |warnings| {
        if !crate::validation_controls::is_validator_disabled("subsumed-required-leg")
            && !subsumed.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} all: legs are already required by another leg",
                subsumed.len()
            );
            eprintln!("   The rule matches exactly the same files without them, so it");
            eprintln!("   counts one fact as several and looks better-evidenced than it is.");
            eprintln!("   Delete the redundant leg. If the two were meant to be different");
            eprintln!("   evidence, one is not matching what its name claims -- look for an");
            eprintln!("   exact and a regex spelling of one value, or a nested composite");
            eprintln!("   that already contains the other leg.\n");
            for (rule_id, redundant, covered_by) in &subsumed {
                let source = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                match find_line_number(source, rule_id) {
                    Some(line) => eprintln!("   {source}:{line}: '{rule_id}'"),
                    None => eprintln!("   {source}: '{rule_id}'"),
                }
                eprintln!("      '{redundant}' adds nothing over '{covered_by}'");
            }
            eprintln!();
            warnings.push(format!(
                "{} all: legs are already required by another leg",
                subsumed.len()
            ));
        }
    })
}

/// Validate: two required legs that one value satisfies at once.
/// The rule claims two pieces of evidence and has one, spelled
/// twice.
pub(super) fn one_fact_convictions<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let one_fact_convictions = enabled("one-fact-conviction")
        .then(|| find_one_fact_convictions(input.trait_definitions, input.composite_rules));
    report(move |warnings| {
        if let Some(one_fact) = one_fact_convictions
            && !one_fact.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} convictions count one fact as two legs",
                one_fact.len()
            );
            eprintln!("   Both legs read the same fact, and a single value satisfies");
            eprintln!("   both -- so the rule rests on one observation while reading");
            eprintln!("   as two. Delete one leg, or replace it with evidence of a");
            eprintln!("   different kind. Legs that require two DIFFERENT values (a");
            eprintln!("   root launcher AND a staged binary) are not reported.\n");
            for (rule_id, first, second, fact) in &one_fact {
                let source = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                match find_line_number(source, rule_id) {
                    Some(line) => eprintln!("   {source}:{line}: '{rule_id}'"),
                    None => eprintln!("   {source}: '{rule_id}'"),
                }
                eprintln!("      '{first}' and '{second}' both read {fact},");
                eprintln!("      and one value satisfies both");
            }
            eprintln!();
            warnings.push(format!(
                "{} convictions count one fact as two legs",
                one_fact.len()
            ));
        }
    })
}

/// Validate: a conviction assembled only from name/size/metric facts
/// fingerprints one artifact rather than detecting the malware.
pub(super) fn convictions_without_content<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let content_free_convictions = enabled("conviction-without-content")
        .then(|| find_convictions_without_content(input.trait_definitions, input.composite_rules));
    report(move |warnings| {
        if let Some(no_content) = content_free_convictions
            && !no_content.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} convictions rest on no content evidence",
                no_content.len()
            );
            eprintln!("   Every leg is a name, a size or a metric count -- what the file is");
            eprintln!("   called, weighs and counts, never what it does. That fingerprints");
            eprintln!("   one artifact and misses the next build of the same malware.\n");
            eprintln!("   Add a leg derived from the contents: a string, symbol, import or");
            eprintln!("   structural match stating what the sample actually does. If no such");
            eprintln!("   evidence exists for this family, it is an identity record and not");
            eprintln!("   a detection -- keep the traits at notable and drop the conviction.\n");
            for (rule_id, resting_on) in &no_content {
                let source = input
                    .rule_source_files
                    .get(rule_id)
                    .map(std::string::String::as_str)
                    .unwrap_or("unknown");
                match find_line_number(source, rule_id) {
                    Some(line) => eprintln!("   {source}:{line}: '{rule_id}'"),
                    None => eprintln!("   {source}: '{rule_id}'"),
                }
                eprintln!("      rests only on: {}", resting_on.join(", "));
            }
            eprintln!();
            warnings.push(format!(
                "{} convictions rest on no content evidence",
                no_content.len()
            ));
        }
    })
}

/// Validate: a directory/short-name reference that matches nothing.
/// The leg contributes silently nothing, so the rule matches on
/// whatever else it lists.
pub(super) fn dangling_directory_refs<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let dangling = if enabled("dangling-directory-ref") {
        find_dangling_directory_refs(input.trait_definitions, input.composite_rules)
    } else {
        Vec::new()
    };
    report(move |warnings| {
        if !crate::validation_controls::is_validator_disabled("dangling-directory-ref")
            && !dangling.is_empty()
        {
            let mut paths: Vec<&str> = dangling.iter().map(|(_, _, r)| r.as_str()).collect();
            paths.sort_unstable();
            paths.dedup();
            eprintln!(
                "\n❌ ERROR: {} legs reference something that does not exist ({} distinct paths)",
                dangling.len(),
                paths.len()
            );
            eprintln!("   These resolve to no traits, so the leg is dropped and the rule");
            eprintln!("   matches on whatever else it lists -- usually far more broadly");
            eprintln!("   than its name and description promise.\n");
            eprintln!("   Point each at a directory that exists, or delete the leg. If a");
            eprintln!("   reference never matched anything, the rule has been running");
            eprintln!("   without that evidence all along: fix the description too.\n");
            for path in &paths {
                let users: Vec<&str> = dangling
                    .iter()
                    .filter(|(_, _, r)| r == path)
                    .map(|(rule, _, _)| rule.as_str())
                    .collect();
                eprintln!("   {} — {} leg(s), e.g. '{}'", path, users.len(), users[0]);
            }
            eprintln!();
            warnings.push(format!(
                "{} legs reference a path that does not exist",
                dangling.len()
            ));
        }
    })
}

/// Validate: short patterns that are likely to produce too many false positives
pub(super) fn short_patterns<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let short_pattern_warnings =
        find_short_pattern_warnings(input.trait_definitions, input.trait_source_files);
    report(move |warnings| {
        if !short_pattern_warnings.is_empty() {
            eprintln!(
                "\n⚠️  WARNING: {} traits have open-ended short patterns",
                short_pattern_warnings.len()
            );
            eprintln!("   Open-ended short patterns are too likely to create false positives.");
            eprintln!("   Try to create a more specific trait; see RULES.md for details.\n");
            for (trait_id, pattern, pattern_type, source_file) in &short_pattern_warnings {
                let line_hint = find_line_number(source_file, pattern);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Trait '{}' uses {} pattern '{}'",
                        source_file, line, trait_id, pattern_type, pattern
                    );
                } else {
                    eprintln!(
                        "   {}: Trait '{}' uses {} pattern '{}'",
                        source_file, trait_id, pattern_type, pattern
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} traits have open-ended short patterns",
                short_pattern_warnings.len()
            ));
        }
    })
}

/// Validate: directories with too many traits (should be split)
pub(super) fn oversized_directories<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let mut oversized_dirs =
        find_oversized_trait_directories(input.trait_definitions, input.composite_rules);
    for (dir, count) in find_oversized_source_directories(input.rule_source_files, input.dir_path) {
        if let Some((_, existing)) = oversized_dirs.iter_mut().find(|(name, _)| *name == dir) {
            *existing = (*existing).max(count);
        } else {
            oversized_dirs.push((dir, count));
        }
    }
    oversized_dirs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    report(move |warnings| {
        if !oversized_dirs.is_empty()
            && !crate::validation_controls::is_validator_disabled("oversized-dir")
        {
            eprintln!(
                "\n❌ ERROR: {} directories exceed their direct-rule budget (atomic + composite)",
                oversized_dirs.len()
            );
            eprintln!(
                "   Why: the ML pipeline sees directory structure, not trait IDs; broad directories hide shared behavior."
            );
            eprintln!(
                "   First audit this directory for duplicate or redundant traits; remove or consolidate those that do not add distinct signal."
            );
            eprintln!(
                "   Then reorganize the remaining traits into meaningful subdirectories only when each child adds precision under TAXONOMY.md."
            );
            eprintln!(
                "   Merely moving the same broad set to another location is not a fix; keep splits technique-based and platform-neutral where possible. Every directory has a configured rule limit; exceptions require explicit approval after a complete relevance audit.\n"
            );
            for (dir_path, count) in &oversized_dirs {
                eprintln!("   {}: {} rules", dir_path, count);
            }
            eprintln!();
            warnings.push_id(
    "oversized-dir",
    format!(
        "{} directories exceed their direct-rule budget (audit duplicates, then reorganize only into TAXONOMY.md-precise subdirectories; relocation alone is not a fix)",
        oversized_dirs.len()
    ),
);
        }
    })
}

/// Validate that composite rules only contain trait references (not inline primitives)
/// Strict mode is the default - composite rules must only reference traits
pub(super) fn composite_inline_primitives<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        let mut inline_errors = Vec::new();
        for rule in input.composite_rules {
            let source = input
                .rule_source_files
                .get(&rule.id)
                .map(std::string::String::as_str)
                .unwrap_or("unknown");
            inline_errors.extend(validate_composite_trait_only(rule, source));
        }

        if !crate::validation_controls::is_validator_disabled("composite-inline-primitive")
            && !inline_errors.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} composite rules have inline primitives\n",
                inline_errors.len()
            );
            for err in &inline_errors {
                eprintln!("   {}", err);
            }
            eprintln!("\n   Composite rules must only reference traits (type: trait).");
            eprintln!(
                "   Convert inline conditions (string, symbol, yara, etc.) to atomic traits.\n"
            );
            warnings.push(format!(
                "{} composite rules have inline primitives",
                inline_errors.len()
            ));
        }
    })
}

/// Validate single-rule composites with identical file types
/// Build map of trait_id -> file_types for quick lookup, borrowed
/// from the definitions rather than copied out of them
pub(super) fn single_trait_composites<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        let mut trait_file_types: FxHashMap<&str, &Vec<RuleFileType>> = FxHashMap::default();
        for trait_def in input.trait_definitions {
            trait_file_types.insert(&trait_def.id, &trait_def.r#for);
        }
        for rule in input.composite_rules {
            trait_file_types.insert(&rule.id, &rule.r#for);
        }

        // Build metadata lookup for traits and composites
        let mut trait_metadata: FxHashMap<
            &str,
            (Criticality, f32, &Option<String>, &Option<String>),
        > = FxHashMap::default();
        for trait_def in input.trait_definitions {
            trait_metadata.insert(
                &trait_def.id,
                (
                    trait_def.crit,
                    trait_def.conf,
                    &trait_def.attack,
                    &trait_def.mbc,
                ),
            );
        }
        for rule in input.composite_rules {
            trait_metadata.insert(&rule.id, (rule.crit, rule.conf, &rule.attack, &rule.mbc));
        }

        let mut redundant_composites = Vec::new();
        let mut unless_only_composites = Vec::new();

        for rule in input.composite_rules {
            // Check if this is a single-rule composite
            let mut total_conditions = 0;
            if let Some(ref all) = rule.all {
                total_conditions += all.len();
            }
            if let Some(ref any) = rule.any {
                total_conditions += any.len();
            }

            // If it's a single-rule composite, check file types
            if total_conditions == 1 {
                let trait_refs = collect_trait_refs_from_rule(rule);
                if trait_refs.len() == 1 {
                    let (ref_id, _) = &trait_refs[0];

                    // Look up the referenced trait's file types
                    if let Some(ref_file_types) = trait_file_types.get(ref_id.as_str()) {
                        // Compare file types - warn if identical
                        if rule.r#for == **ref_file_types {
                            let source_file = input
                                .rule_source_files
                                .get(&rule.id)
                                .map(std::string::String::as_str)
                                .unwrap_or("unknown");

                            // Check if this composite only adds an 'unless' clause
                            // If so, it might be better expressed as a downgrade
                            let has_unless = rule.unless.as_ref().is_some_and(|u| !u.is_empty());
                            let has_downgrade = rule.downgrade.is_some();

                            // Check if metadata is being changed
                            let metadata_changed =
                                if let Some((ref_crit, ref_conf, ref_attack, ref_mbc)) =
                                    trait_metadata.get(ref_id.as_str())
                                {
                                    rule.crit != *ref_crit
                                        || (rule.conf - ref_conf).abs() > 0.001
                                        || rule.attack != **ref_attack
                                        || rule.mbc != **ref_mbc
                                } else {
                                    false
                                };

                            if has_unless && !has_downgrade && !metadata_changed {
                                // Only adds unless, no metadata changes - suggest downgrade pattern
                                unless_only_composites.push((
                                    rule.id.clone(),
                                    ref_id.clone(),
                                    source_file.to_string(),
                                ));
                            } else if !has_unless && !has_downgrade && !metadata_changed {
                                // Truly useless - no unless, no downgrade, no metadata changes, same file types
                                redundant_composites.push((
                                    rule.id.clone(),
                                    ref_id.clone(),
                                    source_file.to_string(),
                                ));
                            }
                            // If metadata_changed is true, this is a legitimate composite
                            // that's creating a distinct finding with different properties
                        }
                    }
                }
            }
        }

        if !crate::validation_controls::is_validator_disabled("single-trait-composite")
            && !redundant_composites.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} single-trait composites add no value",
                redundant_composites.len()
            );
            eprintln!(
                "   These composites only reference one trait with identical file types and no unless/downgrade clauses.\n"
            );
            eprintln!("   Consider removing them or adding more conditions:\n");
            for (rule_id, ref_id, source_file) in &redundant_composites {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Composite '{}' only references '{}'",
                        source_file, line, rule_id, ref_id
                    );
                } else {
                    eprintln!(
                        "   {}: Composite '{}' only references '{}'",
                        source_file, rule_id, ref_id
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} single-trait composites add no value",
                redundant_composites.len()
            ));
        }

        if !crate::validation_controls::is_validator_disabled("unless-only-composite")
            && !unless_only_composites.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} single-trait composites only add 'unless' clauses",
                unless_only_composites.len()
            );
            eprintln!("   Instead of creating a composite with only an unless clause:");
            eprintln!("   1. Increase the criticality of the base trait");
            eprintln!("   2. Add a downgrade clause to the base trait for the unless conditions\n");
            for (rule_id, ref_id, source_file) in &unless_only_composites {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Composite '{}' only adds unless to '{}'",
                        source_file, line, rule_id, ref_id
                    );
                } else {
                    eprintln!(
                        "   {}: Composite '{}' only adds unless to '{}'",
                        source_file, rule_id, ref_id
                    );
                }
            }
            eprintln!();
            warnings.push(format!(
                "{} single-trait composites only add unless clauses",
                unless_only_composites.len()
            ));
        }
    })
}
