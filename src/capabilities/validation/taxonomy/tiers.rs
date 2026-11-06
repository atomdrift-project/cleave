//! Tier boundaries and the `crit: exception` contract.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Find micro-behaviors/ rules with Hostile criticality.
///
/// Hostile rules (like rootkits, privilege escalation exploits) belong in objectives/
/// or well-known/ tiers. Micro-behaviors/ should contain only neutral capability atoms.
///
/// Returns: `Vec<(rule_id, source_file)>` for violations.
#[must_use]
pub(crate) fn find_hostile_cap_rules(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    // Helper to check if rule is in micro-behaviors/
    fn is_cap_rule(id: &str) -> bool {
        if let Some(idx) = id.find("::") {
            let prefix = &id[..idx];
            if let Some(slash_idx) = prefix.find('/') {
                return &prefix[..slash_idx] == "micro-behaviors";
            }
            return prefix == "micro-behaviors";
        } else if let Some(slash_idx) = id.find('/') {
            return &id[..slash_idx] == "micro-behaviors";
        }
        false
    }

    // Check trait definitions
    for trait_def in trait_definitions {
        if is_cap_rule(&trait_def.id) && trait_def.crit == Criticality::Hostile {
            let source = rule_source_files
                .get(&trait_def.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((trait_def.id.clone(), source));
        }
    }

    // Check composite rules
    for rule in composite_rules {
        if is_cap_rule(&rule.id) && rule.crit == Criticality::Hostile {
            let source = rule_source_files
                .get(&rule.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((rule.id.clone(), source));
        }
    }

    violations
}

/// Find metadata/ rules with Hostile criticality.
///
/// Metadata rules are purely informational file-level properties (format, language, quality).
/// They should only have baseline criticality. Hostile criticality requires intent inference
/// which belongs in objectives/ where attacker goals are categorized.
///
/// Returns: `Vec<(rule_id, source_file)>` for violations.
#[must_use]
pub(crate) fn find_hostile_meta_rules(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    // Helper to check if rule is in metadata/
    fn is_meta_rule(id: &str) -> bool {
        if let Some(idx) = id.find("::") {
            let prefix = &id[..idx];
            if let Some(slash_idx) = prefix.find('/') {
                return &prefix[..slash_idx] == "metadata";
            }
            return prefix == "metadata";
        } else if let Some(slash_idx) = id.find('/') {
            return &id[..slash_idx] == "metadata";
        }
        false
    }

    // Check trait definitions
    for trait_def in trait_definitions {
        if is_meta_rule(&trait_def.id) && trait_def.crit == Criticality::Hostile {
            let source = rule_source_files
                .get(&trait_def.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((trait_def.id.clone(), source));
        }
    }

    // Check composite rules
    for rule in composite_rules {
        if is_meta_rule(&rule.id) && rule.crit == Criticality::Hostile {
            let source = rule_source_files
                .get(&rule.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((rule.id.clone(), source));
        }
    }

    violations
}

// NOTE: baseline traits are allowed in objectives/ as composite building blocks.
// The duplicate detector (duplicates.rs) catches identical patterns across tiers.
// TODO: Extend duplicate detection to normalize patterns across match types
// (symbol vs string_value vs raw) to catch semantic duplicates like:
//   objectives/: type: symbol, exact: "chdir"
//   micro-behaviors/: type: text, substr: "chdir"
// These detect the same thing but hash differently.
// See TODO-baseline-trait-review.md for known cases.

/// Find micro-behaviors/ rules that reference objectives/ rules.
///
/// Cap contains micro-behaviors while obj contains larger behaviors.
/// Cap rules should not depend on obj rules.
///
/// Returns `(rule_id, ref_id, source_file)` for violations.
#[must_use]
pub(crate) fn find_cap_obj_violations(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, String)> {
    let mut violations = Vec::new();

    // Helper to extract tier prefix from a rule ID
    fn extract_tier(id: &str) -> Option<&str> {
        if let Some(idx) = id.find("::") {
            let prefix = &id[..idx];
            if let Some(slash_idx) = prefix.find('/') {
                Some(&prefix[..slash_idx])
            } else {
                Some(prefix)
            }
        } else if let Some(slash_idx) = id.find('/') {
            Some(&id[..slash_idx])
        } else {
            None
        }
    }

    // Check trait definitions
    for trait_def in trait_definitions {
        // Only check micro-behaviors/ traits
        if let Some(tier) = extract_tier(&trait_def.id) {
            if tier != "micro-behaviors" {
                continue;
            }

            // Check if the trait condition references other traits
            for ref_id in trait_def
                .r#if
                .trait_references()
                .iter()
                .filter(|id| extract_tier(id) == Some("objectives"))
            {
                let source = rule_source_files
                    .get(&trait_def.id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                violations.push((trait_def.id.clone(), ref_id.clone(), source));
            }
        }
    }

    // Check composite rules
    for rule in composite_rules {
        // Only check micro-behaviors/ rules
        if let Some(tier) = extract_tier(&rule.id) {
            if tier != "micro-behaviors" {
                continue;
            }

            // Collect all trait references from this rule
            let trait_refs = collect_trait_refs_from_rule(rule);
            for (ref_id, _) in trait_refs {
                if let Some(ref_tier) = extract_tier(&ref_id)
                    && ref_tier == "objectives"
                {
                    let source = rule_source_files
                        .get(&rule.id)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());
                    violations.push((rule.id.clone(), ref_id.clone(), source));
                }
            }
        }
    }

    violations
}

/// Find metadata/ rules that reference non-metadata tiers.
///
/// Metadata rules describe file-level properties (format, language, quality) and should
/// only reference other metadata/ rules. Referencing micro-behaviors/, objectives/, or
/// well-known/ rules violates the tier hierarchy — metadata is the leaf layer for
/// neutral structural facts and must not depend on behavior or named entities.
///
/// Returns `(rule_id, ref_id, source_file)` for violations.
#[must_use]
pub(crate) fn find_metadata_cross_tier_refs(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, String)> {
    let mut violations = Vec::new();

    fn extract_tier(id: &str) -> Option<&str> {
        let base = id.find("::").map_or(id, |idx| &id[..idx]);
        base.find('/').map(|i| &base[..i])
    }

    fn is_cross_tier_ref(ref_id: &str) -> bool {
        matches!(
            extract_tier(ref_id),
            Some("micro-behaviors" | "objectives" | "well-known")
        )
    }

    for trait_def in trait_definitions {
        if extract_tier(&trait_def.id) != Some("metadata") {
            continue;
        }
        for ref_id in trait_def
            .r#if
            .trait_references()
            .iter()
            .filter(|id| is_cross_tier_ref(id))
        {
            let source = rule_source_files
                .get(&trait_def.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((trait_def.id.clone(), ref_id.clone(), source));
        }
    }

    for rule in composite_rules {
        if extract_tier(&rule.id) != Some("metadata") {
            continue;
        }
        let trait_refs = collect_trait_refs_from_rule(rule);
        for (ref_id, _) in trait_refs {
            if is_cross_tier_ref(&ref_id) {
                let source = rule_source_files
                    .get(&rule.id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                violations.push((rule.id.clone(), ref_id.clone(), source));
            }
        }
    }

    violations
}

/// Returns the tier prefix (the segment before the first `/`, or before `::`) of a ref/id.
pub(super) fn ref_tier(id: &str) -> Option<&str> {
    let base = id.find("::").map_or(id, |i| &id[..i]);
    base.find('/').map(|i| &base[..i])
}

/// Returns true if `ref_id` points at a trait under `well-known/malware/`.
///
/// References use `<subdirectory>::<local_id>`; the path before `::` is the directory
/// from the traits root, so `well-known/malware/trojan/foo::bar` and `well-known/malware`
/// both qualify, while `well-known/tool/...`, `well-known/app/...`, etc. do not.
pub(super) fn is_wellknown_malware_ref(ref_id: &str) -> bool {
    let path = ref_id.find("::").map_or(ref_id, |i| &ref_id[..i]);
    path == "well-known/malware" || path.starts_with("well-known/malware/")
}

/// Find micro-behaviors/ rules that reference well-known/ rules in disallowed ways.
///
/// Micro-behaviors are tier-0 atoms. Hostile-intent fingerprints inverted from this
/// layer are forbidden:
/// - `well-known/malware/*` is forbidden in any clause — capabilities cannot be
///   gated on a specific malware family.
/// - `well-known/{tool,app,lib,game}/*` is allowed only inside `unless:` /
///   `downgrade:` (benign-context suppression, e.g., "do not flag this capability
///   when the binary is a known signed sandboxie/sysinternals component").
#[must_use]
pub(crate) fn find_cap_wellknown_violations(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, String, ObjectivesWellknownViolation)> {
    find_tier_wellknown_violations(
        "micro-behaviors",
        trait_definitions,
        composite_rules,
        rule_source_files,
    )
}

/// Reason a tier → `well-known/` reference is rejected. Both
/// `objectives/` and `micro-behaviors/` use this enum; the policies
/// diverge inside `find_tier_wellknown_violations`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ObjectivesWellknownViolation {
    /// `well-known/malware/` may never appear in either tier, in any clause.
    /// Malware-family IDs are not prerequisites for generic objectives or
    /// capabilities — pinning them belongs in `well-known/` correlation rules.
    MalwareRef,
    /// `micro-behaviors/` rules at `crit: suspicious` may not pin to
    /// `well-known/{tool,app,lib,game}/` in positive-evidence clauses
    /// (`all:` / `any:` / atomic `if:`). Capabilities should detect via
    /// mechanical evidence, not piggyback on named-entity identification.
    /// Objectives are allowed to use these refs freely — see the policy
    /// comment in `find_tier_wellknown_violations`.
    PositiveWellknownRef,
}

impl ObjectivesWellknownViolation {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::MalwareRef => "may not reference well-known/malware/",
            Self::PositiveWellknownRef => {
                "capabilities at suspicious+ may reference well-known/{tool,app,lib,game}/ only inside `unless:` or `downgrade:` (benign-context), not as positive evidence"
            }
        }
    }
}

/// Find `objectives/` rules whose references into `well-known/` violate the policy.
/// See `find_tier_wellknown_violations` for the policy details.
#[must_use]
pub(crate) fn find_objectives_wellknown_violations(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, String, ObjectivesWellknownViolation)> {
    find_tier_wellknown_violations(
        "objectives",
        trait_definitions,
        composite_rules,
        rule_source_files,
    )
}

/// Shared implementation for `find_cap_wellknown_violations` and
/// `find_objectives_wellknown_violations`. The policies diverge by tier:
/// - `well-known/malware/*` is forbidden in any clause for both tiers.
/// - `well-known/{tool,app,lib,game}/*` rules:
///   - `objectives/`: allowed freely as positive evidence at any criticality.
///     The original ban existed to prevent malware-family attribution from
///     driving objective scoring, but legitimate-software identifiers (open
///     source libraries, sysinternals tools, dual-use tooling fingerprints
///     used as ONE piece of evidence in a multi-evidence composite) are not
///     malware-family attribution. The relationship runs the other way:
///     `well-known/malware/` rules build on `objectives/`.
///   - `micro-behaviors/`: allowed only inside `unless:` / `downgrade:`
///     (benign-context suppression) for rules at `crit: suspicious`+. Lower-
///     crit capabilities can use them freely. Capabilities should detect via
///     mechanical evidence, not piggyback on named-entity identification.
pub(super) fn find_tier_wellknown_violations(
    tier: &str,
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, String, ObjectivesWellknownViolation)> {
    let mut violations = Vec::new();

    let push =
        |id: &str,
         ref_id: &str,
         reason: ObjectivesWellknownViolation,
         out: &mut Vec<(String, String, String, ObjectivesWellknownViolation)>| {
            let source = rule_source_files
                .get(id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            out.push((id.to_string(), ref_id.to_string(), source, reason));
        };

    let claims_hostile_intent = |crit: Criticality| -> bool { crit >= Criticality::Suspicious };

    let classify = |ref_id: &str,
                    in_benign_clause: bool,
                    rule_crit: Criticality|
     -> Option<ObjectivesWellknownViolation> {
        if ref_tier(ref_id) != Some("well-known") {
            return None;
        }
        if is_wellknown_malware_ref(ref_id) {
            return Some(ObjectivesWellknownViolation::MalwareRef);
        }
        if in_benign_clause {
            return None;
        }
        // Objectives may freely use well-known/{tool,app,lib,game} as
        // positive evidence — see the function-level policy comment.
        if tier == "objectives" {
            return None;
        }
        // Capabilities at suspicious+ cannot pin to named-entity refs.
        if claims_hostile_intent(rule_crit) {
            Some(ObjectivesWellknownViolation::PositiveWellknownRef)
        } else {
            None
        }
    };

    let scan_conditions = |conds: &[Condition], in_benign: bool, refs: &mut Vec<(String, bool)>| {
        for cond in conds {
            for id in cond.trait_references() {
                refs.push((id.clone(), in_benign));
            }
        }
    };

    for trait_def in trait_definitions {
        if ref_tier(&trait_def.id) != Some(tier) {
            continue;
        }
        let mut refs: Vec<(String, bool)> = Vec::new();

        // Atomic `if:` is positive evidence.
        for id in trait_def.r#if.trait_references() {
            refs.push((id.clone(), false));
        }
        // `unless:` is benign-context suppression.
        if let Some(unless) = &trait_def.unless {
            scan_conditions(unless, true, &mut refs);
        }
        // Atomic traits also support `downgrade:` with all/any — all benign-context.
        if let Some(downgrade) = &trait_def.downgrade {
            if let Some(c) = &downgrade.all {
                scan_conditions(c, true, &mut refs);
            }
            if let Some(c) = &downgrade.any {
                scan_conditions(c, true, &mut refs);
            }
        }

        for (ref_id, benign) in refs {
            if let Some(reason) = classify(&ref_id, benign, trait_def.crit) {
                push(&trait_def.id, &ref_id, reason, &mut violations);
            }
        }
    }

    for rule in composite_rules {
        if ref_tier(&rule.id) != Some(tier) {
            continue;
        }
        let mut refs: Vec<(String, bool)> = Vec::new();

        if let Some(c) = &rule.all {
            scan_conditions(c, false, &mut refs);
        }
        if let Some(c) = &rule.any {
            scan_conditions(c, false, &mut refs);
        }
        if let Some(c) = &rule.unless {
            scan_conditions(c, true, &mut refs);
        }
        if let Some(downgrade) = &rule.downgrade {
            if let Some(c) = &downgrade.all {
                scan_conditions(c, true, &mut refs);
            }
            if let Some(c) = &downgrade.any {
                scan_conditions(c, true, &mut refs);
            }
        }

        for (ref_id, benign) in refs {
            if let Some(reason) = classify(&ref_id, benign, rule.crit) {
                push(&rule.id, &ref_id, reason, &mut violations);
            }
        }
    }

    violations
}

/// Find `baseline`/`component` rules in `objectives/` or `well-known/` that never appear
/// as positive evidence in a `notable`-or-higher rule — building blocks that exist only
/// to be suppressed.
///
/// A `baseline` or `component` rule in these tiers is a building block: it carries little
/// analytical signal on its own and is meant to feed a real detection. If the only places
/// it is referenced are `unless:`/`downgrade:` carve-outs — or it is unreferenced as
/// positive evidence entirely — it can never raise the criticality of anything. These
/// tiers are not for suppression-only rules: a rule should be named and located by what it
/// searches for, so the right fix is usually to relocate it to the directory that matches
/// what it detects per TAXONOMY.md. Otherwise reference it as positive evidence from a
/// notable+ rule, or raise its `crit:`.
///
/// A candidate is satisfied when a `notable`-or-higher rule reaches it through a chain of
/// *positive* references — an `any:`/`all:` clause of a composite, or an atomic trait's
/// `if:`. Reachability is transitive: a `component` fragment feeding a `baseline` aggregator
/// that a `notable` composite consumes is satisfied, because the notable detection
/// ultimately rests on it. Suppression clauses (`unless:`/`downgrade:`) are not positive
/// references and never satisfy. A bare directory reference (`well-known/tool`) reaches
/// every rule beneath that prefix.
///
/// Returns `(rule_id, source_file)` for each violation, sorted by id.
#[must_use]
pub(crate) fn find_suppression_only_building_blocks<'a>(
    trait_definitions: &'a [TraitDefinition],
    composite_rules: &'a [CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    use std::collections::{HashSet, VecDeque};

    // Every rule id, for expanding bare directory references to the rules beneath them.
    // Sorted, so the rules under a prefix are one contiguous range rather than a scan
    // of the whole tree per reference.
    let mut all_ids: Vec<&str> = trait_definitions
        .iter()
        .map(|t| t.id.as_str())
        .chain(composite_rules.iter().map(|r| r.id.as_str()))
        .collect();
    all_ids.sort_unstable();

    // Positive-reference edges parent → child. A specific `dir::id` reference is one edge;
    // a bare directory reference fans out to every rule beneath the prefix.
    let mut adjacency: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut add_edge = |parent: &'a str, ref_id: &'a str| {
        let children = adjacency.entry(parent).or_default();
        if ref_id.contains("::") {
            children.push(ref_id);
        } else {
            let prefix_new = format!("{ref_id}::");
            let prefix_legacy = format!("{ref_id}/");
            let start = all_ids.partition_point(|c| *c < ref_id);
            for &c in all_ids[start..]
                .iter()
                .take_while(|c| c.starts_with(ref_id))
            {
                if c.starts_with(&prefix_new) || c.starts_with(&prefix_legacy) {
                    children.push(c);
                }
            }
        }
    };

    // Positive evidence: composite `all:`/`any:` and atomic `if:`. Never `unless:`/`downgrade:`.
    for r in composite_rules {
        for conds in [r.all.as_ref(), r.any.as_ref()].into_iter().flatten() {
            for cond in conds {
                for id in cond.trait_references() {
                    add_edge(r.id.as_str(), id.as_str());
                }
            }
        }
    }
    for t in trait_definitions {
        for id in t.r#if.trait_references() {
            add_edge(t.id.as_str(), id.as_str());
        }
    }

    // Forward BFS from every notable+ root over positive edges. Everything reached is
    // backing a real detection, transitively.
    let mut reachable: HashSet<&str> = HashSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    for id in trait_definitions
        .iter()
        .filter(|t| t.crit >= Criticality::Notable)
        .map(|t| t.id.as_str())
        .chain(
            composite_rules
                .iter()
                .filter(|r| r.crit >= Criticality::Notable)
                .map(|r| r.id.as_str()),
        )
    {
        if reachable.insert(id) {
            queue.push_back(id);
        }
    }
    while let Some(node) = queue.pop_front() {
        for &child in adjacency.get(node).into_iter().flatten() {
            if reachable.insert(child) {
                queue.push_back(child);
            }
        }
    }

    // Candidate building blocks: baseline/component rules under objectives/ or well-known/
    // that no notable+ detection reaches. Both tiers are positive-detection trees — even a
    // benign well-known/{app,lib,tool,game} directory should carry at least one notable
    // trait that identifies the software (its identity *is* notable signal, independent of
    // being benign), with the baseline/component fragments feeding it. A directory of only
    // never-surfaced fragments means that notable identifier is missing.
    let is_building_block =
        |crit: Criticality| matches!(crit, Criticality::Baseline | Criticality::Component);
    let is_candidate_tier =
        |id: &str| matches!(ref_tier(id), Some("objectives") | Some("well-known"));

    let mut violations: Vec<(String, String)> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), t.crit))
        .chain(composite_rules.iter().map(|r| (r.id.as_str(), r.crit)))
        .filter(|(id, crit)| {
            is_building_block(*crit) && is_candidate_tier(id) && !reachable.contains(id)
        })
        .map(|(id, _)| {
            let source = rule_source_files
                .get(id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            (id.to_string(), source)
        })
        .collect();

    violations.sort_by(|a, b| a.0.cmp(&b.0));
    violations
}

// ============================================================================
// `crit: exception` validation
//
// An `exception` is a benign-context composite: a known-good pattern assembled
// purely from named `notable` traits, referenced only from `unless:`/`downgrade:`
// clauses to suppress or downgrade a host detection. It is assembly-only and never
// surfaces in output. The validators below enforce that contract:
//   V1 `find_exception_atomic_traits`        — only composites may be `crit: exception`
//   V2 `find_exception_positive_refs`        — never referenced as positive evidence
//   V3 `find_unreferenced_exceptions`        — must be referenced somewhere (else dead)
//   V4 `find_exception_non_notable_members`  — every member must be exactly `notable`
//   V5 `find_exception_inline_conditions`    — every condition must be a named trait ref
// ============================================================================

/// Iterate `(clause_label, conditions)` over every `Condition` list a composite
/// carries: `all:`, `any:`, `unless:`, and each `downgrade:` leg. `not:` is a
/// string-level filter (`NotException`), not a `Condition`, so it is excluded.
pub(super) fn composite_condition_lists(
    rule: &CompositeTrait,
) -> Vec<(&'static str, &[Condition])> {
    let mut lists: Vec<(&'static str, &[Condition])> = Vec::new();
    if let Some(c) = &rule.all {
        lists.push(("all", c));
    }
    if let Some(c) = &rule.any {
        lists.push(("any", c));
    }
    if let Some(c) = &rule.unless {
        lists.push(("unless", c));
    }
    if let Some(d) = &rule.downgrade {
        if let Some(c) = &d.all {
            lists.push(("downgrade.all", c));
        }
        if let Some(c) = &d.any {
            lists.push(("downgrade.any", c));
        }
    }
    lists
}

/// The `type:` name of a condition, for diagnostics. Exhaustive so a new
/// `Condition` variant forces a decision here.
pub(super) fn condition_kind(cond: &Condition) -> &'static str {
    match cond {
        Condition::Trait { .. } => "trait",
        Condition::Symbol(_) => "symbol",
        Condition::Text(_) => "text",
        Condition::Comment(_) => "comment",
        Condition::Literal(_) => "literal",
        Condition::TreeSitter(_) => "tree-sitter",
        Condition::Yara { .. } => "yara",
        Condition::Syscall { .. } => "syscall",
        Condition::Metrics(_) => "metrics",
        Condition::Hex(_) => "hex",
        Condition::Raw(_) => "raw",
        Condition::Section(_) => "section",
        Condition::Encoded(_) => "encoded",
        Condition::Path(_) => "path",
        Condition::Kv(_) => "value",
    }
}

/// The composite ids declared `crit: exception`. Atomic exceptions are a V1
/// violation and are intentionally excluded here — the construct is composite-only.
pub(super) fn exception_composite_ids(
    composite_rules: &[CompositeTrait],
) -> std::collections::HashSet<&str> {
    composite_rules
        .iter()
        .filter(|r| r.crit == Criticality::Exception)
        .map(|r| r.id.as_str())
        .collect()
}

pub(super) fn source_of(rule_source_files: &HashMap<String, String>, id: &str) -> String {
    rule_source_files
        .get(id)
        .cloned()
        .unwrap_or_else(|| "unknown".to_string())
}

/// The `crit: exception` composites a single trait reference reaches at evaluation
/// time, mirroring `eval_trait`'s resolution:
/// - exact (`dir::id`): the exception with that id, if any — reachable from any rule;
/// - short name (no `/`): exceptions whose id ends with that leaf — reachable from any rule;
/// - bare directory: exceptions beneath the prefix, but only when the referencing rule
///   is itself an exception. For every other rule, directory expansion excludes
///   exceptions, which is what keeps `objectives/` directory references safe.
pub(super) fn exceptions_reached_by<'a>(
    ref_id: &str,
    from_is_exception: bool,
    exception_ids: &std::collections::HashSet<&'a str>,
) -> Vec<&'a str> {
    let ref_id = ref_id.trim_end_matches('/');
    if ref_id.contains("::") {
        return exception_ids.get(ref_id).copied().into_iter().collect();
    }
    if !ref_id.contains('/') {
        let suffix_new = format!("::{ref_id}");
        let suffix_legacy = format!("/{ref_id}");
        return exception_ids
            .iter()
            .copied()
            .filter(|e| e.ends_with(&suffix_new) || e.ends_with(&suffix_legacy))
            .collect();
    }
    if !from_is_exception {
        return Vec::new();
    }
    let prefix_new = format!("{ref_id}::");
    let prefix_legacy = format!("{ref_id}/");
    exception_ids
        .iter()
        .copied()
        .filter(|e| e.starts_with(&prefix_new) || e.starts_with(&prefix_legacy))
        .collect()
}

/// V1: `crit: exception` is composite-only. Atomic trait definitions may not use it.
///
/// Returns `(trait_id, source_file)` for each offending atomic trait, sorted by id.
#[must_use]
pub(crate) fn find_exception_atomic_traits(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut violations: Vec<(String, String)> = trait_definitions
        .iter()
        .filter(|t| t.crit == Criticality::Exception)
        .map(|t| (t.id.clone(), source_of(rule_source_files, &t.id)))
        .collect();
    violations.sort_by(|a, b| a.0.cmp(&b.0));
    violations
}

/// V2: an `exception` may only be referenced from a benign-context clause
/// (`unless:`/`downgrade:`), never as positive evidence (atomic `if:`, composite
/// `all:`/`any:`). A positive reference would let a benign pattern drive a
/// detection, which is backwards.
///
/// A reference is flagged when it *reaches* an exception the way evaluation would
/// (exact `dir::id`, or a short-name leaf), since that pulls a benign pattern in as
/// positive evidence. A bare-*directory* reference is **not** flagged — directory
/// expansion excludes exceptions for non-exception rules (see `eval_trait`), so
/// dropping an `objectives/` directory into `all:`/`any:` can never accidentally
/// inherit a suppressor. Exception composites are exempt: they may compose other
/// exceptions, including via a directory of exceptions.
///
/// Returns `(referencing_rule_id, exception_ref_id, source_file)` per violation.
#[must_use]
pub(crate) fn find_exception_positive_refs(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, String)> {
    let exception_ids = exception_composite_ids(composite_rules);
    if exception_ids.is_empty() {
        return Vec::new();
    }

    let mut violations: Vec<(String, String, String)> = Vec::new();

    // Atomic `if:` is positive evidence. Atomics are never exceptions (V1), so they
    // always evaluate as a non-exception parent.
    for t in trait_definitions {
        for id in t
            .r#if
            .trait_references()
            .iter()
            .filter(|id| !exceptions_reached_by(id, false, &exception_ids).is_empty())
        {
            violations.push((
                t.id.clone(),
                id.clone(),
                source_of(rule_source_files, &t.id),
            ));
        }
    }

    // Composite `all:`/`any:` are positive evidence. An exception parent may
    // reference exceptions positively (deliberate composition), so it is exempt.
    for r in composite_rules {
        if r.crit == Criticality::Exception {
            continue;
        }
        for conds in [r.all.as_ref(), r.any.as_ref()].into_iter().flatten() {
            for cond in conds {
                for id in cond
                    .trait_references()
                    .iter()
                    .filter(|id| !exceptions_reached_by(id, false, &exception_ids).is_empty())
                {
                    violations.push((
                        r.id.clone(),
                        id.clone(),
                        source_of(rule_source_files, &r.id),
                    ));
                }
            }
        }
    }

    violations.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));
    violations
}

/// V3: an `exception` exists only to be referenced from some `unless:`/`downgrade:`
/// clause. One that no rule can reach is dead weight. Reachability mirrors
/// evaluation: an exact or short-name reference reaches it from any rule, and a
/// bare-directory reference reaches it only from another exception (directory
/// expansion excludes exceptions for every other rule). Self-references do not count.
///
/// Returns `(exception_id, source_file)` per unreferenced exception, sorted by id.
#[must_use]
pub(crate) fn find_unreferenced_exceptions<'a>(
    trait_definitions: &'a [TraitDefinition],
    composite_rules: &'a [CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    use std::collections::HashSet;

    let exception_ids = exception_composite_ids(composite_rules);
    if exception_ids.is_empty() {
        return Vec::new();
    }

    // Every `(from_is_exception, referencing_rule_id, ref_id)` across all clauses of
    // all rules. Atomics are never exceptions; a composite is one iff its crit says so.
    let mut refs: Vec<(bool, &'a str, &'a str)> = Vec::new();
    for t in trait_definitions {
        for id in t.r#if.trait_references() {
            refs.push((false, &t.id, id));
        }
        if let Some(unless) = &t.unless {
            for cond in unless {
                for id in cond.trait_references() {
                    refs.push((false, &t.id, id));
                }
            }
        }
        if let Some(d) = &t.downgrade {
            for conds in [d.all.as_ref(), d.any.as_ref()].into_iter().flatten() {
                for cond in conds {
                    for id in cond.trait_references() {
                        refs.push((false, &t.id, id));
                    }
                }
            }
        }
    }
    for r in composite_rules {
        let from_is_exception = r.crit == Criticality::Exception;
        for (_, conds) in composite_condition_lists(r) {
            for cond in conds {
                for id in cond.trait_references() {
                    refs.push((from_is_exception, &r.id, id));
                }
            }
        }
    }

    // Mark every exception reached by a reference from some *other* rule, using the
    // same resolution evaluation uses.
    let mut referenced: HashSet<&str> = HashSet::new();
    for (from_is_exception, from_id, ref_id) in refs {
        for reached in exceptions_reached_by(ref_id, from_is_exception, &exception_ids) {
            if reached != from_id {
                referenced.insert(reached);
            }
        }
    }

    let mut violations: Vec<(String, String)> = exception_ids
        .iter()
        .filter(|id| !referenced.contains(*id))
        .map(|id| ((*id).to_string(), source_of(rule_source_files, id)))
        .collect();
    violations.sort_by(|a, b| a.0.cmp(&b.0));
    violations
}

/// V4: every member an `exception` composite asserts (its `all:`/`any:` references)
/// must resolve to a rule that is *exactly* `notable` — or another `exception`, since
/// an exception may compose nested benign patterns. A benign pattern is assembled from
/// "defines program purpose" facts; building it out of baseline noise, component
/// fragments, or — worse — `suspicious`/`hostile` legs is incoherent. A bare-directory
/// member requires every (non-exception) rule beneath the prefix to be `notable`;
/// exceptions beneath it are ignored, since directory expansion excludes them anyway.
///
/// Returns `(exception_id, member_id, member_crit, source_file)` per offending member.
#[must_use]
pub(crate) fn find_exception_non_notable_members(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, Criticality, String)> {
    let exception_ids = exception_composite_ids(composite_rules);
    if exception_ids.is_empty() {
        return Vec::new();
    }

    // id -> crit across every rule, for resolving member references.
    let mut crit_by_id: HashMap<&str, Criticality> = HashMap::new();
    for t in trait_definitions {
        crit_by_id.insert(t.id.as_str(), t.crit);
    }
    for r in composite_rules {
        crit_by_id.insert(r.id.as_str(), r.crit);
    }
    // Sorted, so the ids beneath a directory are one range found by binary
    // search rather than a scan of every id per member.
    let mut all_ids: Vec<&str> = crit_by_id.keys().copied().collect();
    all_ids.sort_unstable();

    let mut violations: Vec<(String, String, Criticality, String)> = Vec::new();
    for rule in composite_rules
        .iter()
        .filter(|r| r.crit == Criticality::Exception)
    {
        let source = source_of(rule_source_files, &rule.id);
        // Members = the traits the exception asserts: its `all:`/`any:` references.
        let members = [rule.all.as_ref(), rule.any.as_ref()]
            .into_iter()
            .flatten()
            .flatten()
            .flat_map(|cond| cond.trait_references().iter().map(String::as_str));
        for member_id in members {
            if member_id.contains("::") {
                // A dangling ref (unknown id) is caught by orphan validation, not here.
                // An exception member is allowed (nested benign composition).
                if let Some(&crit) = crit_by_id.get(member_id)
                    && crit != Criticality::Notable
                    && crit != Criticality::Exception
                {
                    violations.push((rule.id.clone(), member_id.to_string(), crit, source.clone()));
                }
            } else {
                // Bare directory: every concrete non-exception rule beneath the prefix
                // must be notable. Exceptions beneath it are excluded from expansion.
                for prefix in [format!("{member_id}::"), format!("{member_id}/")] {
                    let first = all_ids.partition_point(|&cid| cid < prefix.as_str());
                    for &cid in all_ids[first..]
                        .iter()
                        .take_while(|cid| cid.starts_with(&prefix))
                    {
                        let crit = crit_by_id.get(cid).copied().unwrap_or_default();
                        if crit != Criticality::Notable && crit != Criticality::Exception {
                            violations.push((
                                rule.id.clone(),
                                cid.to_string(),
                                crit,
                                source.clone(),
                            ));
                        }
                    }
                }
            }
        }
    }

    violations.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));
    violations
}

/// V5: an `exception` composite is a pure assembly of named traits — every condition
/// in every clause (`all:`/`any:`/`unless:`/`downgrade:`) must be a `Condition::Trait`
/// reference. Inline matchers (`text`/`symbol`/`raw`/…) are rejected: they carry no
/// criticality, so they would slip past the V4 `notable`-member guarantee.
///
/// Returns `(exception_id, clause, condition_kind, source_file)` per inline condition.
#[must_use]
pub(crate) fn find_exception_inline_conditions(
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, String, String)> {
    let mut violations: Vec<(String, String, String, String)> = Vec::new();
    for rule in composite_rules
        .iter()
        .filter(|r| r.crit == Criticality::Exception)
    {
        let source = source_of(rule_source_files, &rule.id);
        for (clause, conds) in composite_condition_lists(rule) {
            for cond in conds {
                if !cond.is_trait_reference() {
                    violations.push((
                        rule.id.clone(),
                        clause.to_string(),
                        condition_kind(cond).to_string(),
                        source.clone(),
                    ));
                }
            }
        }
    }
    violations.sort_by(|a, b| (a.0.as_str(), a.1.as_str()).cmp(&(b.0.as_str(), b.1.as_str())));
    violations
}

/// A rule whose id or description reads as a benign-suppression / false-positive
/// rule does not belong in `objectives/` or `well-known/malware/` — those tiers are
/// for positive detections. The sanctioned home for a benign pattern is a
/// `crit: exception` composite (which may live anywhere), so such a composite is
/// exempt. The markers are the conventions this corpus uses for suppressors:
/// `benign`, the `<thing>-context` / `fp-context` / `safety-context` family,
/// `false-positive`, the `-fp` / `-soft-fp` / `-known-fp` and `-exceptions` id
/// suffixes, and explicit allow/whitelisting.
///
/// Returns `(rule_id, source_file)` per misplaced rule, sorted by id.
#[must_use]
pub(crate) fn find_benign_misplaced(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    // Unambiguous suppression markers, matched in id or description.
    const MARKERS: &[&str] = &[
        "benign",
        "fp-context",
        "safety-context",
        "false-positive",
        "false positive",
        "allowlist",
        "whitelist",
        "known-good",
    ];
    // Suppression naming conventions, matched on the id suffix only — these read as
    // benign-context / false-positive in an id but appear too freely in prose to key
    // on descriptions. `-fp` covers `-soft-fp` / `-known-fp`; `-exceptions` is an
    // exclusion list.
    const ID_SUFFIXES: &[&str] = &["-context", "-fp", "-fps", "-exceptions"];

    let reads_as_suppression = |id: &str, desc: &str| {
        let id = id.to_ascii_lowercase();
        let desc = desc.to_ascii_lowercase();
        MARKERS.iter().any(|m| id.contains(m) || desc.contains(m))
            || ID_SUFFIXES.iter().any(|s| id.ends_with(s))
    };
    // `objectives/...` or `well-known/malware/...` (the rule's own location).
    let in_forbidden_tier =
        |id: &str| ref_tier(id) == Some("objectives") || is_wellknown_malware_ref(id);

    let mut violations: Vec<(String, String)> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), t.desc.as_str(), t.crit))
        .chain(
            composite_rules
                .iter()
                .map(|r| (r.id.as_str(), r.desc.as_str(), r.crit)),
        )
        .filter(|(id, desc, crit)| {
            *crit != Criticality::Exception
                && in_forbidden_tier(id)
                && reads_as_suppression(id, desc)
        })
        .map(|(id, _, _)| (id.to_string(), source_of(rule_source_files, id)))
        .collect();
    violations.sort_by(|a, b| a.0.cmp(&b.0));
    violations
}

/// Find rules that use `malware/` as a subcategory of `objectives/` or `micro-behaviors/`.
///
/// Malware-specific signatures belong in `well-known/malware/`, not as subcategories
/// of objectives or capabilities. See TAXONOMY.md for the correct structure.
///
/// Returns `(rule_id, source_file)` for violations.
#[must_use]
pub(crate) fn find_malware_subcategory_violations(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    fn is_misplaced(id: &str) -> bool {
        let path = id.find("::").map_or(id, |i| &id[..i]);
        path.starts_with("objectives/malware/") || path.starts_with("micro-behaviors/malware/")
    }

    for trait_def in trait_definitions {
        if is_misplaced(&trait_def.id) {
            let source = rule_source_files
                .get(&trait_def.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((trait_def.id.clone(), source));
        }
    }

    for rule in composite_rules {
        if is_misplaced(&rule.id) {
            let source = rule_source_files
                .get(&rule.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((rule.id.clone(), source));
        }
    }

    violations
}
