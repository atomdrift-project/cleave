//! Checks on what each taxonomy tier may hold and reference: criticality
//! ceilings, well-known/ rules, and the `crit: exception` contract.

use super::{Report, ValidationInput, enabled, report};
use crate::capabilities::validation::{
    ObjectivesWellknownViolation, find_benign_misplaced, find_cap_obj_violations,
    find_cap_wellknown_violations, find_exception_atomic_traits, find_exception_inline_conditions,
    find_exception_non_notable_members, find_exception_positive_refs, find_hostile_cap_rules,
    find_hostile_meta_rules, find_line_number, find_malware_subcategory_violations,
    find_metadata_cross_tier_refs, find_objectives_wellknown_violations,
    find_suppression_only_building_blocks, find_unreferenced_exceptions,
    find_wellknown_baseline_rules, find_wellknown_high_criticality_basenames,
};

/// Validate that micro-behaviors/ rules do not reference objectives/ rules
/// Cap contains micro-behaviors, obj contains larger behaviors
/// Cap rules should be independent of obj rules
pub(super) fn cap_obj_violations<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let cap_obj_violations = find_cap_obj_violations(
        input.trait_definitions,
        input.composite_rules,
        input.rule_source_files,
    );
    report(move |warnings| {
        tracing::trace!("Step 12/15: Checking for micro-behaviors/obj violations");

        if !cap_obj_violations.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} micro-behaviors/ rules reference objectives/ rules",
                cap_obj_violations.len()
            );
            eprintln!(
                "   Cap rules (micro-behaviors) should not depend on obj rules (larger behaviors):\n"
            );
            for (rule_id, ref_id, source_file) in &cap_obj_violations {
                let line_hint = find_line_number(source_file, ref_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' references obj rule: '{}'",
                        source_file, line, rule_id, ref_id
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' references obj rule: '{}'",
                        source_file, rule_id, ref_id
                    );
                }
            }
            eprintln!("\n   Cap rules should only reference other cap rules or meta rules.");
            warnings.push(format!(
"{} micro-behaviors/ rules reference objectives/ rules (cap should not depend on obj)",
cap_obj_violations.len()
));
        }
    })
}

/// Validate that micro-behaviors/ rules are never hostile
/// Hostile criticality requires objective-level evidence and belongs in objectives/
pub(super) fn hostile_cap_rules<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let hostile_cap_rules = find_hostile_cap_rules(
        input.trait_definitions,
        input.composite_rules,
        input.rule_source_files,
    );
    report(move |warnings| {
        tracing::trace!("Step 13/15: Checking for hostile cap rules");

        if !hostile_cap_rules.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} micro-behaviors/ rules have hostile criticality",
                hostile_cap_rules.len()
            );
            eprintln!(
                "   Cap contains micro-behaviors (atomic capabilities) which are generally neutral."
            );
            eprintln!(
                "   Hostile rules require intent inference and should be in objectives/ where they can be"
            );
            eprintln!("   categorized properly by attacker objective (C2, exfil, impact, etc.):\n");
            for (rule_id, source_file) in &hostile_cap_rules {
                let line_hint = find_line_number(source_file, "crit: hostile");
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: Rule '{}'", source_file, line, rule_id);
                } else {
                    eprintln!("   {}: Rule '{}'", source_file, rule_id);
                }
            }
            eprintln!(
                "\n   Cap rules max criticality: suspicious (rarely legitimate but still a capability)"
            );
            eprintln!(
                "   Move hostile rules to objectives/command-and-control/, objectives/exfiltration/, objectives/impact/, etc. based on objective."
            );
            warnings.push(format!(
                "{} micro-behaviors/ rules have hostile criticality (should be in objectives/)",
                hostile_cap_rules.len()
            ));
        }
    })
}

/// Validate that metadata/ rules are never hostile
/// Hostile criticality requires intent inference and belongs in objectives/
pub(super) fn hostile_meta_rules<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let hostile_meta_rules = find_hostile_meta_rules(
        input.trait_definitions,
        input.composite_rules,
        input.rule_source_files,
    );
    report(move |warnings| {
        tracing::trace!("Step 13a/15: Checking for hostile metadata rules");

        if !crate::validation_controls::is_validator_disabled("metadata-hostile-criticality")
            && !hostile_meta_rules.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} metadata/ rules have hostile criticality",
                hostile_meta_rules.len()
            );
            eprintln!("   Metadata rules are purely informational file-level properties.");
            eprintln!("   Hostile rules require intent inference and should be in objectives/:\n");
            for (rule_id, source_file) in &hostile_meta_rules {
                let line_hint = find_line_number(source_file, "crit: hostile");
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: Rule '{}'", source_file, line, rule_id);
                } else {
                    eprintln!("   {}: Rule '{}'", source_file, rule_id);
                }
            }
            eprintln!("\n   Metadata rules should have baseline criticality only.");
            eprintln!(
                "   Move hostile composites to objectives/lateral-movement/supply-chain/ or similar."
            );
            warnings.push(format!(
                "{} metadata/ rules have hostile criticality (should be in objectives/)",
                hostile_meta_rules.len()
            ));
        }
    })
}

/// Validate that metadata/ rules do not reference non-metadata tiers
pub(super) fn metadata_cross_tier_refs<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let meta_cross_tier = find_metadata_cross_tier_refs(
        input.trait_definitions,
        input.composite_rules,
        input.rule_source_files,
    );
    report(move |_| {
        tracing::trace!("Step 13b/15: Checking for metadata cross-tier references");

        if !meta_cross_tier.is_empty() {
            tracing::info!(
                "{} metadata/ rules reference non-metadata tiers (allowed for composite aggregation)",
                meta_cross_tier.len()
            );
        }
    })
}

/// Validate that micro-behaviors/ rules do not improperly reference well-known/ rules.
/// - well-known/malware/ refs are forbidden in any clause.
/// - well-known/{tool,app,lib,game}/ refs are allowed only in unless/downgrade
///   (benign-context suppression), not as positive evidence.
pub(super) fn cap_wellknown_violations<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let cap_wk_violations = find_cap_wellknown_violations(
        input.trait_definitions,
        input.composite_rules,
        input.rule_source_files,
    );
    report(move |warnings| {
        tracing::trace!("Step 13c/15: Checking for micro-behaviors/well-known violations");

        if !cap_wk_violations.is_empty() {
            let malware_count = cap_wk_violations
                .iter()
                .filter(|(_, _, _, r)| *r == ObjectivesWellknownViolation::MalwareRef)
                .count();
            let positive_count = cap_wk_violations.len() - malware_count;
            eprintln!(
                "\n❌ ERROR: {} micro-behaviors/ → well-known/ references violate the tier policy",
                cap_wk_violations.len()
            );
            if malware_count > 0 {
                eprintln!(
                    "   - {} reference well-known/malware/ (never allowed in micro-behaviors/)",
                    malware_count
                );
            }
            if positive_count > 0 {
                eprintln!(
                    "   - {} use well-known/{{tool,app,lib,game}}/ as positive evidence \
         (only allowed inside `unless:` / `downgrade:`)",
                    positive_count
                );
            }
            eprintln!();
            for (rule_id, ref_id, source_file, reason) in &cap_wk_violations {
                let line_hint = find_line_number(source_file, ref_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' references '{}' — micro-behaviors/ {}",
                        source_file,
                        line,
                        rule_id,
                        ref_id,
                        reason.as_str()
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' references '{}' — micro-behaviors/ {}",
                        source_file,
                        rule_id,
                        ref_id,
                        reason.as_str()
                    );
                }
            }
            warnings.push(format!(
                "{} micro-behaviors/ → well-known/ references violate the tier policy",
                cap_wk_violations.len()
            ));
        }
    })
}

/// Validate that objectives/ rules do not improperly reference well-known/ rules.
/// - well-known/malware/ refs are forbidden in any clause.
/// - well-known/{tool,app,lib,game}/ refs are allowed only in unless/downgrade
///   (benign-context suppression), not as positive evidence for hostile intent.
pub(super) fn objectives_wellknown_violations<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let obj_wk_violations = find_objectives_wellknown_violations(
        input.trait_definitions,
        input.composite_rules,
        input.rule_source_files,
    );
    report(move |warnings| {
        tracing::trace!("Step 13d/15: Checking for objectives/well-known violations");

        if !obj_wk_violations.is_empty() {
            let malware_count = obj_wk_violations
                .iter()
                .filter(|(_, _, _, r)| *r == ObjectivesWellknownViolation::MalwareRef)
                .count();
            let positive_count = obj_wk_violations.len() - malware_count;
            eprintln!(
                "\n❌ ERROR: {} objectives/ → well-known/ references violate the tier policy",
                obj_wk_violations.len()
            );
            if malware_count > 0 {
                eprintln!(
                    "   - {} reference well-known/malware/ (never allowed in objectives/)",
                    malware_count
                );
            }
            if positive_count > 0 {
                eprintln!(
                    "   - {} use well-known/{{tool,app,lib,game}}/ as positive evidence \
         (only allowed inside `unless:` / `downgrade:`)",
                    positive_count
                );
            }
            eprintln!();
            for (rule_id, ref_id, source_file, reason) in &obj_wk_violations {
                let line_hint = find_line_number(source_file, ref_id);
                if let Some(line) = line_hint {
                    eprintln!(
                        "   {}:{}: Rule '{}' references '{}' — objectives/ {}",
                        source_file,
                        line,
                        rule_id,
                        ref_id,
                        reason.as_str()
                    );
                } else {
                    eprintln!(
                        "   {}: Rule '{}' references '{}' — objectives/ {}",
                        source_file,
                        rule_id,
                        ref_id,
                        reason.as_str()
                    );
                }
            }
            warnings.push(format!(
                "{} objectives/ → well-known/ references violate the tier policy",
                obj_wk_violations.len()
            ));
        }
    })
}

/// Baseline rules in well-known/.
pub(super) fn wellknown_baseline_rules<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let wellknown_baseline = find_wellknown_baseline_rules(
        input.trait_definitions,
        input.composite_rules,
        input.rule_source_files,
    );
    report(move |warnings| {
        if !wellknown_baseline.is_empty()
            && !crate::validation_controls::is_validator_disabled("wellknown-baseline")
        {
            eprintln!(
                "\n❌ ERROR: {} baseline rules in well-known/",
                wellknown_baseline.len()
            );
            eprintln!(
                "   Review the evidence: use notable for a meaningful identity or filename fact, component for an incomplete fragment, or move a general property to its actual subject.\n"
            );
            for (id, source) in &wellknown_baseline {
                eprintln!("   {source}: '{id}'");
            }
            warnings.push_id(
                "wellknown-baseline",
                format!("{} baseline rules in well-known/", wellknown_baseline.len()),
            );
        }
    })
}

/// well-known/ filename observations above `notable`.
pub(super) fn wellknown_high_criticality_basenames<'a>(
    input: &'a ValidationInput<'a>,
) -> Report<'a> {
    let wellknown_high_basename =
        find_wellknown_high_criticality_basenames(input.trait_definitions, input.rule_source_files);
    report(move |warnings| {
        if !wellknown_high_basename.is_empty()
            && !crate::validation_controls::is_validator_disabled("wellknown-basename-crit")
        {
            eprintln!(
                "\n❌ ERROR: {} well-known filename observations exceed notable",
                wellknown_high_basename.len()
            );
            for (id, source) in &wellknown_high_basename {
                eprintln!("   {source}: '{id}'");
            }
            warnings.push_id(
                "wellknown-basename-crit",
                format!(
                    "{} well-known filename observations exceed notable",
                    wellknown_high_basename.len()
                ),
            );
        }
    })
}

/// Validate that baseline/component building blocks in objectives/ or well-known/
/// are actually used as positive evidence by a notable+ rule, not only suppressed.
pub(super) fn suppression_only_building_blocks<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let suppression_only = find_suppression_only_building_blocks(
        input.trait_definitions,
        input.composite_rules,
        input.rule_source_files,
    );
    report(move |warnings| {
        tracing::trace!("Step 13e/15: Checking for suppression-only building blocks");
        let disable_suppression_only_validation =
            crate::validation_controls::is_validator_disabled("suppression-only-building-block");
        if !disable_suppression_only_validation && !suppression_only.is_empty() {
            eprintln!(
                "\n❌ ERROR: {} baseline/component rules in objectives/ or well-known/ never feed a notable+ detection",
                suppression_only.len()
            );
            eprintln!(
                "   A baseline/component rule in these tiers is a building block: some notable-or-"
            );
            eprintln!(
                "   higher rule must reach it through positive `all:`/`any:`/`if:` references"
            );
            eprintln!(
                "   (transitively — fragments feeding a baseline aggregator that a notable composite"
            );
            eprintln!(
                "   consumes are fine). These appear only in `unless:`/`downgrade:` carve-outs, or"
            );
            eprintln!("   nowhere positive:\n");
            for (rule_id, source_file) in &suppression_only {
                let line_hint = find_line_number(source_file, rule_id);
                if let Some(line) = line_hint {
                    eprintln!("   {}:{}: '{}'", source_file, line, rule_id);
                } else {
                    eprintln!("   {}: '{}'", source_file, rule_id);
                }
            }
            eprintln!();
            eprintln!(
                "   A rule should be named and located by what it searches for. Likely fixes:"
            );
            eprintln!(
                "     • add the missing notable identifier — e.g. a benign well-known/ directory still"
            );
            eprintln!(
                "       needs a notable trait that identifies the software, with these fragments feeding it"
            );
            eprintln!(
                "     • relocate a genuine suppressor to the directory that matches what it detects per TAXONOMY.md"
            );
            eprintln!(
                "     • raise the consuming composite's `crit:` if it actually defines program behavior"
            );
            eprintln!();
            warnings.push_id(
    "suppression-only-building-block",
    format!(
        "{} baseline/component rules in objectives/ or well-known/ are only ever suppressed",
        suppression_only.len()
    ),
);
        }
    })
}

/// The `crit: exception` contract, checked here and in the four validators
/// after this one. A `crit: exception` composite is a benign-context suppressor: composite-only,
/// referenced only from `unless:`/`downgrade:`, assembled from exactly-`notable`
/// named traits, and required to be referenced somewhere. See TAXONOMY.md.
pub(super) fn exception_atomic_traits<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let atomic_exceptions = if enabled("exception-atomic") {
        find_exception_atomic_traits(input.trait_definitions, input.rule_source_files)
    } else {
        Vec::new()
    };
    report(move |warnings| {
        tracing::trace!("Step 13f/15: Checking crit: exception contract");

        // V1: only composites may be crit: exception.
        if !crate::validation_controls::is_validator_disabled("exception-atomic")
            && !atomic_exceptions.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} atomic trait(s) declare `crit: exception` — only composites may",
                atomic_exceptions.len()
            );
            eprintln!(
                "   `crit: exception` marks a benign-context composite that assembles named traits.\n"
            );
            for (id, source_file) in &atomic_exceptions {
                match find_line_number(source_file, id) {
                    Some(l) => eprintln!("   {source_file}:{l}: atomic trait '{id}'"),
                    None => eprintln!("   {source_file}: atomic trait '{id}'"),
                }
            }
            warnings.push_id(
                "exception-atomic",
                format!(
                    "{} atomic trait(s) use crit: exception (composite-only)",
                    atomic_exceptions.len()
                ),
            );
        }
    })
}

/// V5: every condition in an exception composite must be a named trait ref.
pub(super) fn exception_inline_conditions<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let inline = if enabled("exception-inline-condition") {
        find_exception_inline_conditions(input.composite_rules, input.rule_source_files)
    } else {
        Vec::new()
    };
    report(move |warnings| {
        if !crate::validation_controls::is_validator_disabled("exception-inline-condition")
            && !inline.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} inline condition(s) in `crit: exception` composites — named traits only",
                inline.len()
            );
            eprintln!(
                "   An exception is a pure assembly of named, `notable` traits; inline matchers carry"
            );
            eprintln!(
                "   no criticality and would bypass the notable-member guarantee. Promote each to a"
            );
            eprintln!("   named trait and reference it.\n");
            for (id, clause, kind, source_file) in &inline {
                match find_line_number(source_file, id) {
                    Some(l) => eprintln!(
                        "   {source_file}:{l}: '{id}' has an inline `{kind}` in `{clause}:`"
                    ),
                    None => {
                        eprintln!("   {source_file}: '{id}' has an inline `{kind}` in `{clause}:`")
                    }
                }
            }
            warnings.push_id(
                "exception-inline-condition",
                format!(
                    "{} inline condition(s) in crit: exception composites (named traits only)",
                    inline.len()
                ),
            );
        }
    })
}

/// V4: every member of an exception composite must be exactly `notable`.
pub(super) fn exception_non_notable_members<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let exception_members = enabled("exception-member-crit").then(|| {
        find_exception_non_notable_members(
            input.trait_definitions,
            input.composite_rules,
            input.rule_source_files,
        )
    });
    report(move |warnings| {
        if let Some(members) = exception_members
            && !members.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} member(s) of `crit: exception` composites are not `notable`",
                members.len()
            );
            eprintln!(
                "   A benign pattern is assembled from `notable` (\"defines program purpose\") facts."
            );
            eprintln!(
                "   Members that are baseline/component, or suspicious/hostile, do not belong in one.\n"
            );
            for (id, member_id, crit, source_file) in &members {
                let crit = format!("{crit:?}").to_lowercase();
                match find_line_number(source_file, member_id) {
                    Some(l) => eprintln!(
                        "   {source_file}:{l}: '{id}' member '{member_id}' is `{crit}`, not `notable`"
                    ),
                    None => eprintln!(
                        "   {source_file}: '{id}' member '{member_id}' is `{crit}`, not `notable`"
                    ),
                }
            }
            warnings.push_id(
                "exception-member-crit",
                format!(
                    "{} member(s) of crit: exception composites are not notable",
                    members.len()
                ),
            );
        }
    })
}

/// V2: an exception may only be referenced from unless:/downgrade:, never as
/// positive evidence (atomic if:, composite all:/any:).
pub(super) fn exception_positive_refs<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let positive = if enabled("exception-positive-ref") {
        find_exception_positive_refs(
            input.trait_definitions,
            input.composite_rules,
            input.rule_source_files,
        )
    } else {
        Vec::new()
    };
    report(move |warnings| {
        if !crate::validation_controls::is_validator_disabled("exception-positive-ref")
            && !positive.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} positive reference(s) to `crit: exception` composites",
                positive.len()
            );
            eprintln!(
                "   An exception is a benign-context suppressor — reference it only from `unless:`"
            );
            eprintln!(
                "   or `downgrade:`, never as positive evidence (`all:`/`any:`/atomic `if:`).\n"
            );
            for (rule_id, ref_id, source_file) in &positive {
                match find_line_number(source_file, ref_id) {
                    Some(l) => eprintln!(
                        "   {source_file}:{l}: '{rule_id}' references exception '{ref_id}' as positive evidence"
                    ),
                    None => eprintln!(
                        "   {source_file}: '{rule_id}' references exception '{ref_id}' as positive evidence"
                    ),
                }
            }
            warnings.push_id(
    "exception-positive-ref",
    format!(
        "{} positive reference(s) to crit: exception composites (unless:/downgrade: only)",
        positive.len()
    ),
);
        }
    })
}

/// V3: an exception that nothing references is dead weight.
pub(super) fn unreferenced_exceptions<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let unreferenced = if enabled("exception-unreferenced") {
        find_unreferenced_exceptions(
            input.trait_definitions,
            input.composite_rules,
            input.rule_source_files,
        )
    } else {
        Vec::new()
    };
    report(move |warnings| {
        if !crate::validation_controls::is_validator_disabled("exception-unreferenced")
            && !unreferenced.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} `crit: exception` composite(s) are never referenced",
                unreferenced.len()
            );
            eprintln!(
                "   An exception exists only to suppress or downgrade a host detection. Reference it"
            );
            eprintln!("   from some rule's `unless:`/`downgrade:`, or remove it.\n");
            for (id, source_file) in &unreferenced {
                match find_line_number(source_file, id) {
                    Some(l) => eprintln!("   {source_file}:{l}: '{id}'"),
                    None => eprintln!("   {source_file}: '{id}'"),
                }
            }
            warnings.push_id(
                "exception-unreferenced",
                format!(
                    "{} crit: exception composite(s) are never referenced",
                    unreferenced.len()
                ),
            );
        }
    })
}

/// Benign-suppression rules don't belong in objectives/ or well-known/malware/.
/// The sanctioned home is a `crit: exception` composite (which may live anywhere).
pub(super) fn benign_misplaced<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let benign = if enabled("benign-misplaced") {
        find_benign_misplaced(
            input.trait_definitions,
            input.composite_rules,
            input.rule_source_files,
        )
    } else {
        Vec::new()
    };
    report(move |warnings| {
        if !crate::validation_controls::is_validator_disabled("benign-misplaced")
            && !benign.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} rule(s) read as benign suppression but sit in objectives/ or well-known/malware/",
                benign.len()
            );
            eprintln!(
                "   `objectives/` and `well-known/malware/` are for positive detections. A rule whose"
            );
            eprintln!(
                "   id/description reads as suppression (`benign`, `fp-context`, `safety-context`, a"
            );
            eprintln!(
                "   `*-context` / `*-fp` / `*-exceptions` name, `false-positive`, allow/whitelisting) is"
            );
            eprintln!("   almost certainly");
            eprintln!(
                "   misorganized per TAXONOMY.md. If it is a benign suppressor, make it a `crit: exception`"
            );
            eprintln!(
                "   composite (which may live anywhere) referenced from the host's `unless:`/`downgrade:`."
            );
            eprintln!(
                "   If it actually detects something, rename it for what its matcher finds.\n"
            );
            for (id, source_file) in &benign {
                match find_line_number(source_file, id) {
                    Some(l) => eprintln!("   {source_file}:{l}: '{id}'"),
                    None => eprintln!("   {source_file}: '{id}'"),
                }
            }
            warnings.push_id(
    "benign-misplaced",
    format!(
        "{} benign-suppression rule(s) misplaced in objectives/ or well-known/malware/ (see TAXONOMY.md)",
        benign.len()
    ),
);
        }
    })
}

/// Composite descriptions must stay short enough for one-line triage.
/// Atomic traits are length-checked above; composites get a roomier cap.
pub(super) fn long_composite_descriptions<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    report(move |warnings| {
        if !crate::validation_controls::is_validator_disabled("long-description") {
            let mut long_descs: Vec<(String, String)> = Vec::new();
            for rule in input.composite_rules {
                if let Some(warning) = rule.check_description_quality() {
                    let source = input
                        .rule_source_files
                        .get(&rule.id)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());
                    long_descs.push((rule.id.clone(), format!("{source}: {warning}")));
                }
            }
            long_descs.sort_by(|a, b| a.0.cmp(&b.0));
            if !long_descs.is_empty() {
                eprintln!(
                    "\n❌ ERROR: {} composite description(s) are too long for one-line triage",
                    long_descs.len()
                );
                eprintln!(
                    "   A composite `desc:` should be a concise one-line summary a security engineer can"
                );
                eprintln!(
                    "   read at a glance during triage — name the key entities and drop filler.\n"
                );
                for (id, detail) in &long_descs {
                    eprintln!("   {detail} ('{id}')");
                }
                warnings.push_id(
                    "long-description",
                    format!(
                        "{} composite description(s) exceed the one-line triage length cap",
                        long_descs.len()
                    ),
                );
            }
        }
    })
}

/// Validate that malware/ is not used as a subcategory of objectives/ or micro-behaviors/
/// Malware-specific signatures belong in known/malware/ per TAXONOMY.md
pub(super) fn malware_subcategory_violations<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let malware_violations = find_malware_subcategory_violations(
        input.trait_definitions,
        input.composite_rules,
        input.rule_source_files,
    );
    report(move |warnings| {
        tracing::trace!("Step 13b/15: Checking for misplaced malware/ subcategories");

        if !crate::validation_controls::is_validator_disabled("malware-subcategory")
            && !malware_violations.is_empty()
        {
            eprintln!(
                "\n❌ ERROR: {} rules use malware/ as a subcategory of objectives/ or micro-behaviors/",
                malware_violations.len()
            );
            eprintln!(
                "   Malware-specific signatures belong in known/malware/, not objectives/ or micro-behaviors/."
            );
            eprintln!("   See TAXONOMY.md for the correct taxonomy structure:\n");
            for (rule_id, source_file) in &malware_violations {
                eprintln!("   {}: Rule '{}'", source_file, rule_id);
            }
            eprintln!("\n   Move these rules to known/malware/<family>/ instead.");
            warnings.push(format!(
"{} rules misuse malware/ as a subcategory of objectives/ or micro-behaviors/ (see TAXONOMY.md)",
malware_violations.len()
));
        }
    })
}
