//! Taxonomy and directory structure validation.
//!
//! This module validates the consistency and quality of the trait taxonomy hierarchy.
//! It ensures that:
//! - Rules are placed in appropriate tier directories (micro-behaviors/, objectives/, metadata/, well-known/)
//! - Directory names follow semantic naming conventions
//! - No platform or language names appear as directory segments (except in specific contexts)
//! - Trait ID format is valid
//! - Directory depth is appropriate
//! - Directories are not oversized
//!
//! The taxonomy is organized hierarchically to support both ML classification and human navigation.

use super::composite::collect_trait_refs_from_rule;
use super::helpers::is_binary_file_type;
use crate::composite_rules::{
    CommentQuery, EncodedQuery, HexQuery, LiteralQuery, MetricsQuery, PathQuery, RawQuery,
    SectionQuery, SymbolQuery, TextQuery, TreeSitterQuery,
};
use crate::composite_rules::{
    CompositeTrait, Condition, FileType, KvQuery, Platform, TraitDefinition,
};
use crate::types::Criticality;
use std::collections::HashMap;

/// Platform and language names that should not appear as directory segments.
/// These names indicate implementation details rather than behavioral classifications.
const PLATFORM_NAMES: &[&str] = &[
    // Languages
    "python",
    "javascript",
    "typescript",
    "ruby",
    "java",
    "go",
    "rust",
    "cargo",
    "npm",
    "node",
    "golang",
    "pypi",
    "aur",
    "archlinux",
    "rpm",
    "linux",
    "unix",
    "gem",
    "gems",
    "c",
    "php",
    "packagist",
    "r",
    "perl",
    "lua",
    "swift",
    "csharp",
    "powershell",
    "groovy",
    "scala",
    "zig",
    "elixir",
    // Note: "shell" and "batch" excluded - they represent execution categories, not just platforms
    // Note: "dylib", "so", "dll" excluded - they represent library operation categories
    "objectivec",
    "applescript",
    // Binary formats (allowed in metadata/format/)
    "elf",
    "macho",
    "pe",
    // Node.js variants
    "node",
    "nodejs",
    // Common aliases
    "bash",
    "sh",
    "zsh",
    "dotnet",
    // Operating systems / platforms
    "linux",
    "unix",
    "windows",
    "macos",
    "darwin",
    "android",
    "ios",
    "freebsd",
    "openbsd",
];

/// Directory name segments that add no semantic meaning.
/// These make the taxonomy harder to navigate and provide no value for ML classification.
const BANNED_DIRECTORY_SEGMENTS: &[&str] = &[
    "advanced", // subjective
    "api",      // almost everything is an API
    "assorted", // dumping ground
    "atomic",   // vague
    "base",     // too vague
    "basic",    // meaningless
    "behavior",
    "behaviors",
    "canonical", // describes "the textbook example of X", not a technique
    "component",
    "components",
    "commands",
    "context",
    "exceptions",
    "downgrade",
    "unless",
    "downgrades",
    "category",   // dumping ground
    "combos",     // vague
    "code",       // vague
    "identifier", // vague
    "common",     // too vague
    "composite",  // vague
    "composites", // vague
    "default",    // meaningless
    "detection",  // every trait is detection; meaningless modifier
    "fields",
    "field",
    "kind",
    "category",
    "derived",    // yes
    "generic",    // says nothing about what's inside
    "helpers",    // too vague
    "heuristics", // vague
    "heuristic",  // vague
    "hostile",    // dumping ground
    "impl",       // implementation detail
    "general",
    "lexicon",
    "dictionary",
    "word",
    "words",
    "subtechnique",
    "technique",
    "indicator",
    "indicators",
    "kind",   // too vague
    "kinds",  // too vague
    "method", // everything is a method
    "methods",
    "marker",  // says only that a trait is a marker
    "markers", // says only that traits are markers
    "misc",    // dumping ground
    "modes",   // dumping ground
    "new",     // temporal, will rot
    "notable", // dumping ground
    "old",     // temporal, will rot
    "other",   // dumping ground
    "operations",
    "operation",
    "pattern",    // vague
    "patterns",   // vague
    "protocol",   // vague
    "go-runtime", // platform
    "simple",     // meaningless
    "stuff",      // obviously bad
    "signals",
    "words",
    "kinds",
    "suspicious", // dumping ground
    "technique",  // dumping ground
    "techniques", // dumping ground
    "text",
    "things", // obviously bad
    "tools",
    "tool",
    "tooling",
    "type",    // too vague
    "types",   // dumping ground
    "utils",   // too vague
    "various", // dumping ground
    "windows", // generic platform
];

/// Directories that are allowed to have segments that duplicate their parent.
/// These are legitimate cases where the name duplication is intentional and meaningful.
const PARENT_DUPLICATE_EXCEPTIONS: &[&str] = &[
    "micro-behaviors/communications/tunnel/tun", // TUN is a specific tunnel device type
    "micro-behaviors/os/firewall/firewalld",     // firewalld is a specific firewall daemon name
    "objectives/persistence/system/systemd",     // systemd is a specific init system name
];

/// Directories where a normally-vague segment has precise local meaning.
const BANNED_SEGMENT_EXCEPTIONS: &[(&str, &str)] = &[
    (
        "metadata/package/fields/types",
        "types", // package.json `types`/`typings` entry point field
    ),
    (
        "well-known/tool",
        "tool", // `well-known/tool/` is an established tier category, not a vague segment
    ),
    (
        "well-known/tool/detection",
        "detection", // detection tools (cleave's stng, SAST scanners): "detection" is the category
    ),
];

/// Maximum number of traits allowed in a single directory.
/// Directories exceeding this should be split into subdirectories.
pub(crate) const MAX_TRAITS_PER_DIRECTORY: usize = 80;

/// Directories explicitly allowed to exceed `MAX_TRAITS_PER_DIRECTORY`.
/// Use sparingly — splitting by sub-technique is preferred. Listed here
/// when the trait set is per-implementation (one set per supported
/// language) and splitting by language would violate the
/// platform/language directory ban.
pub(crate) const OVERSIZED_DIRECTORY_EXCEPTIONS: &[&str] =
    &["objectives/command-and-control/reverse-shell/dup"];

/// Validate that a trait ID contains only valid characters.
/// Valid characters are: alphanumerics, dashes, and underscores.
/// Returns None if valid, Some(invalid_char) if invalid.
fn validate_trait_id_chars(id: &str) -> Option<char> {
    id.chars()
        .find(|&c| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
}

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
            if let Condition::Trait { id: ref_id } = &trait_def.r#if
                && let Some(ref_tier) = extract_tier(ref_id)
                && ref_tier == "objectives"
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
        if let Condition::Trait { id: ref_id } = &trait_def.r#if
            && is_cross_tier_ref(ref_id)
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
fn ref_tier(id: &str) -> Option<&str> {
    let base = id.find("::").map_or(id, |i| &id[..i]);
    base.find('/').map(|i| &base[..i])
}

/// Returns true if `ref_id` points at a trait under `well-known/malware/`.
///
/// References use `<subdirectory>::<local_id>`; the path before `::` is the directory
/// from the traits root, so `well-known/malware/trojan/foo::bar` and `well-known/malware`
/// both qualify, while `well-known/tool/...`, `well-known/app/...`, etc. do not.
fn is_wellknown_malware_ref(ref_id: &str) -> bool {
    let path = ref_id.find("::").map_or(ref_id, |i| &ref_id[..i]);
    path == "well-known/malware" || path.starts_with("well-known/malware/")
}

/// Returns true if `ref_id` points at a trait under any well-known/ subtree.
fn is_wellknown_ref(ref_id: &str) -> bool {
    ref_tier(ref_id) == Some("well-known")
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
fn find_tier_wellknown_violations(
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
        if !is_wellknown_ref(ref_id) {
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
            if let Condition::Trait { id } = cond {
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
        if let Condition::Trait { id } = &trait_def.r#if {
            refs.push((id.clone(), false));
        }
        // `unless:` is benign-context suppression.
        if let Some(unless) = &trait_def.unless {
            scan_conditions(unless, true, &mut refs);
        }
        // Atomic traits also support `downgrade:` with all/any/none — all benign-context.
        if let Some(downgrade) = &trait_def.downgrade {
            if let Some(c) = &downgrade.all {
                scan_conditions(c, true, &mut refs);
            }
            if let Some(c) = &downgrade.any {
                scan_conditions(c, true, &mut refs);
            }
            if let Some(c) = &downgrade.none {
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
            if let Some(c) = &downgrade.none {
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
    let all_ids: Vec<&str> = trait_definitions
        .iter()
        .map(|t| t.id.as_str())
        .chain(composite_rules.iter().map(|r| r.id.as_str()))
        .collect();

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
            for &c in &all_ids {
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
                if let Condition::Trait { id } = cond {
                    add_edge(r.id.as_str(), id.as_str());
                }
            }
        }
    }
    for t in trait_definitions {
        if let Condition::Trait { id } = &t.r#if {
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
fn composite_condition_lists(rule: &CompositeTrait) -> Vec<(&'static str, &[Condition])> {
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
        if let Some(c) = &d.none {
            lists.push(("downgrade.none", c));
        }
    }
    lists
}

/// The `type:` name of a condition, for diagnostics. Exhaustive so a new
/// `Condition` variant forces a decision here.
fn condition_kind(cond: &Condition) -> &'static str {
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
fn exception_composite_ids(composite_rules: &[CompositeTrait]) -> std::collections::HashSet<&str> {
    composite_rules
        .iter()
        .filter(|r| r.crit == Criticality::Exception)
        .map(|r| r.id.as_str())
        .collect()
}

fn source_of(rule_source_files: &HashMap<String, String>, id: &str) -> String {
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
fn exceptions_reached_by<'a>(
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
        if let Condition::Trait { id } = &t.r#if
            && !exceptions_reached_by(id, false, &exception_ids).is_empty()
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
                if let Condition::Trait { id } = cond
                    && !exceptions_reached_by(id, false, &exception_ids).is_empty()
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
        if let Condition::Trait { id } = &t.r#if {
            refs.push((false, &t.id, id));
        }
        if let Some(unless) = &t.unless {
            for cond in unless {
                if let Condition::Trait { id } = cond {
                    refs.push((false, &t.id, id));
                }
            }
        }
        if let Some(d) = &t.downgrade {
            for conds in [d.all.as_ref(), d.any.as_ref(), d.none.as_ref()]
                .into_iter()
                .flatten()
            {
                for cond in conds {
                    if let Condition::Trait { id } = cond {
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
                if let Condition::Trait { id } = cond {
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
    let all_ids: Vec<&str> = crit_by_id.keys().copied().collect();

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
            .filter_map(|cond| match cond {
                Condition::Trait { id } => Some(id.as_str()),
                _ => None,
            });
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
                let prefix_new = format!("{member_id}::");
                let prefix_legacy = format!("{member_id}/");
                for &cid in &all_ids {
                    if cid.starts_with(&prefix_new) || cid.starts_with(&prefix_legacy) {
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
                if !matches!(cond, Condition::Trait { .. }) {
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

/// Check if a directory path contains platform/language names as directories.
///
/// Returns a list of `(directory_path, platform_name)` violations.
#[must_use]
pub(crate) fn find_platform_named_directories(trait_dirs: &[String]) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    for dir_path in trait_dirs {
        // Skip metadata/format/ paths - binary format names are legitimate there
        if dir_path.starts_with("metadata/format/") {
            continue;
        }

        // Skip interpreter/<language> paths - language names are expected there
        // e.g., objectives/execution/interpreter/powershell, objectives/execution/interpreter/python
        if dir_path.contains("/interpreter/") {
            continue;
        }

        // Split the path and check each component
        for component in dir_path.split('/') {
            let lower = component.to_lowercase();
            if PLATFORM_NAMES.contains(&lower.as_str()) {
                violations.push((dir_path.clone(), component.to_string()));
                break; // Only report first violation per path
            }
        }
    }

    violations
}

/// Check for duplicate second-level directories across metadata/, micro-behaviors/, objectives/, and well-known/.
///
/// This indicates taxonomy violations - directories should not be repeated across namespaces.
/// For example, micro-behaviors/command-and-control/ and objectives/command-and-control/ suggests
/// micro-behaviors/command-and-control/ is misplaced (C2 is an objective, not a capability).
///
/// Returns a list of `(second_level_dir, namespaces_found_in)` violations.
#[must_use]
pub(crate) fn find_duplicate_second_level_directories(
    trait_dirs: &[String],
) -> Vec<(String, Vec<String>)> {
    let mut second_level_map: HashMap<String, Vec<String>> = HashMap::new();

    for dir_path in trait_dirs {
        let parts: Vec<&str> = dir_path.split('/').collect();
        if parts.len() < 2 {
            continue; // Need at least namespace/second-level
        }

        let namespace = parts[0];
        let second_level = parts[1];

        // Only check the four main namespaces
        if !matches!(
            namespace,
            "micro-behaviors" | "objectives" | "well-known" | "metadata"
        ) {
            continue;
        }

        second_level_map
            .entry(second_level.to_string())
            .or_default()
            .push(namespace.to_string());
    }

    // Find second-level directories that appear in multiple namespaces
    let mut violations = Vec::new();
    for (second_level, mut namespaces) in second_level_map {
        // Deduplicate and sort namespaces
        namespaces.sort();
        namespaces.dedup();

        if namespaces.len() > 1 {
            violations.push((second_level, namespaces));
        }
    }

    // Sort by directory name for consistent output
    violations.sort_by(|a, b| a.0.cmp(&b.0));

    violations
}

/// Check if YAML file paths in micro-behaviors/ or objectives/ are at the correct depth.
///
/// Valid depths are 3 or 4 subdirectories: micro-behaviors/a/b/c/x.yaml or micro-behaviors/a/b/c/d/x.yaml
///
/// Returns `(path, depth, "shallow" or "deep")` for violations.
#[must_use]
pub(crate) fn find_depth_violations(yaml_files: &[String]) -> Vec<(String, usize, &'static str)> {
    let mut violations = Vec::new();

    for path in yaml_files {
        // Only check micro-behaviors/ and objectives/ paths
        if !path.starts_with("micro-behaviors/") && !path.starts_with("objectives/") {
            continue;
        }

        // Count directory components (excluding the root micro-behaviors/ or objectives/ and the filename)
        // e.g., "micro-behaviors/communications/http/client/shell.yaml" -> ["cap", "comm", "http", "client", "shell.yaml"]
        let parts: Vec<&str> = path.split('/').collect();
        if parts.len() < 2 {
            continue;
        }

        // Subdirectory count = total parts - 1 (root) - 1 (filename)
        let subdir_count = parts.len() - 2;

        if subdir_count < 2 {
            violations.push((path.clone(), subdir_count, "shallow"));
        } else if subdir_count > 4 {
            violations.push((path.clone(), subdir_count, "deep"));
        }
    }

    violations
}

/// Find trait and composite rule IDs whose local identifier contains invalid
/// characters. Local IDs must match `[a-zA-Z0-9_-]+`.
///
/// The loader prepends `<directory>::` to YAML ids that don't already contain
/// `::` or `/`, so the canonical form here is `path::local_id`. We strip
/// everything before `::` and validate only the local part — the path prefix
/// is loader-generated and always contains `/`.
///
/// (The "user wrote a path-qualified id like `well-known/malware/foo::bar` in
/// the `id:` field" case is enforced at parse time, see parsing.rs.)
///
/// Returns a list of `(id, invalid_char, source_file)` violations.
#[must_use]
pub(crate) fn find_invalid_trait_ids(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, char, String)> {
    let mut violations = Vec::new();

    for trait_def in trait_definitions {
        let local_id = trait_def
            .id
            .rfind("::")
            .map_or(trait_def.id.as_str(), |i| &trait_def.id[i + 2..]);
        if let Some(invalid_char) = validate_trait_id_chars(local_id) {
            let source = rule_source_files
                .get(&trait_def.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((trait_def.id.clone(), invalid_char, source));
        }
    }

    for rule in composite_rules {
        let local_id = rule
            .id
            .rfind("::")
            .map_or(rule.id.as_str(), |i| &rule.id[i + 2..]);
        if let Some(invalid_char) = validate_trait_id_chars(local_id) {
            let source = rule_source_files
                .get(&rule.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((rule.id.clone(), invalid_char, source));
        }
    }

    violations
}

/// Find directories containing banned meaningless segments.
///
/// Returns: `Vec<(directory_path, banned_segment)>`
#[must_use]
pub(crate) fn find_banned_directory_segments(trait_dirs: &[String]) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    for dir_path in trait_dirs {
        for segment in dir_path.split('/') {
            let lower = segment.to_lowercase();
            if BANNED_DIRECTORY_SEGMENTS.contains(&lower.as_str()) {
                if BANNED_SEGMENT_EXCEPTIONS.iter().any(|(path, allowed)| {
                    lower == *allowed
                        && (dir_path == *path || dir_path.starts_with(&format!("{path}/")))
                }) {
                    continue;
                }
                violations.push((dir_path.clone(), segment.to_string()));
                break; // Only report first violation per path
            }
        }
    }

    violations
}

/// Forbid `content/` directories anywhere under `metadata/`.
///
/// `metadata/` holds neutral facts about what a file *is* — its structure,
/// format, and provenance. A `content/` bucket describes what a file
/// *contains or does*, which is behavior: intent belongs in `objectives/`, a
/// neutral observable capability in `micro-behaviors/`. So a `content/`
/// directory under `metadata/` is always a misfiling. (`content/` is fine
/// elsewhere, e.g. `objectives/anti-static/obfuscation/encoding/content/`.)
///
/// Returns the offending directory paths.
#[must_use]
pub(crate) fn find_metadata_content_dirs(trait_dirs: &[String]) -> Vec<String> {
    trait_dirs
        .iter()
        .filter(|d| {
            d.starts_with("metadata/")
                && d.split('/').any(|seg| seg.eq_ignore_ascii_case("content"))
        })
        .cloned()
        .collect()
}

/// Find directories where a segment duplicates its immediate parent.
///
/// e.g., "micro-behaviors/execution/execution/" or "objectives/credential-access/credentials/"
///
/// Returns: `Vec<(directory_path, duplicated_segment)>`
#[must_use]
pub(crate) fn find_parent_duplicate_segments(trait_dirs: &[String]) -> Vec<(String, String)> {
    let mut violations = Vec::new();

    for dir_path in trait_dirs {
        let segments: Vec<&str> = dir_path.split('/').collect();

        for window in segments.windows(2) {
            let parent = window[0].to_lowercase();
            let child = window[1].to_lowercase();

            // Exact duplicate
            if parent == child {
                // Check if this path is in the exceptions list
                if !PARENT_DUPLICATE_EXCEPTIONS
                    .iter()
                    .any(|exc| dir_path.starts_with(exc))
                {
                    violations.push((dir_path.clone(), window[1].to_string()));
                }
                break;
            }

            // Plural/singular variants (simple check)
            if parent.len() >= 3 && child.len() >= 3 {
                // "cred" vs "credential-access" or "credentials"
                let parent_stem = parent.trim_end_matches('s');
                let child_stem = child.trim_end_matches('s');
                if parent_stem == child_stem {
                    // Check if this path is in the exceptions list
                    if !PARENT_DUPLICATE_EXCEPTIONS
                        .iter()
                        .any(|exc| dir_path.starts_with(exc))
                    {
                        violations.push((dir_path.clone(), window[1].to_string()));
                    }
                    break;
                }

                // Check for abbreviations: child is a prefix of parent
                // e.g., "execution" contains "exec", "credential-access" contains "cred"
                if parent.starts_with(&child) || child.starts_with(&parent) {
                    // Check if this path is in the exceptions list
                    if !PARENT_DUPLICATE_EXCEPTIONS
                        .iter()
                        .any(|exc| dir_path.starts_with(exc))
                    {
                        violations.push((dir_path.clone(), window[1].to_string()));
                    }
                    break;
                }
            }
        }
    }

    violations
}

/// Find directories with too many traits (suggests need for subdirectories).
///
/// Returns: `Vec<(directory_path, trait_count)>`
#[must_use]
pub(crate) fn find_oversized_trait_directories(
    trait_definitions: &[TraitDefinition],
) -> Vec<(String, usize)> {
    // Count traits per directory (extract directory from trait ID)
    let mut dir_counts: HashMap<String, usize> = HashMap::new();

    for t in trait_definitions {
        // Extract directory from trait ID (everything before ::)
        let dir = if let Some(idx) = t.id.find("::") {
            t.id[..idx].to_string()
        } else if let Some(idx) = t.id.rfind('/') {
            t.id[..idx].to_string()
        } else {
            continue; // No directory prefix
        };

        *dir_counts.entry(dir).or_insert(0) += 1;
    }

    let mut violations: Vec<_> = dir_counts
        .into_iter()
        .filter(|(dir, count)| {
            *count > MAX_TRAITS_PER_DIRECTORY
                && !OVERSIZED_DIRECTORY_EXCEPTIONS.contains(&dir.as_str())
        })
        .collect();

    violations.sort_by_key(|v| std::cmp::Reverse(v.1)); // Sort by count descending
    violations
}

// ============================================================================
// well-known/ taxonomy enforcement validators
// ============================================================================

/// Allowed second-level categories under `well-known/malware/`.
///
/// These map to broad malware classification families (e.g., backdoor, ransomware).
/// New categories require explicit addition here to prevent taxonomy sprawl.
const WELL_KNOWN_MALWARE_CATEGORIES: &[&str] = &[
    "apt",
    "atm",
    "backdoor",
    "botnet",
    "downloader",
    "dropper",
    "exploit",
    "keylogger",
    "loader",
    "miner",
    "ransomware",
    "rat",
    "rootkit",
    "stealer",
    "supply-chain",
    "trojan",
    "virus",
    "webshell",
    "worm",
];

/// Allowed second-level categories under `well-known/tool/`.
const WELL_KNOWN_TOOL_CATEGORIES: &[&str] = &[
    "browser",
    "detection",
    "development",
    "dual-use",
    "offensive",
    "reverse-engineering",
    "sysadmin",
];

/// Allowed top-level categories under `well-known/`.
///
/// Kept in sync with `ALLOWED_WELL_KNOWN` in directory_whitelist.rs. Anything outside
/// this set is reported by the directory whitelist; this list is reused here to scope
/// second-level subcategory checks.
const WELL_KNOWN_TOP_LEVEL: &[&str] = &["malware", "unwanted", "tool", "app", "lib", "game"];

/// Validate that well-known/<category>/ only contains whitelisted second-level
/// subcategories where one is defined (currently malware/ and tool/). The app/, lib/,
/// game/, and unwanted/ buckets have no fixed subcategory list and are ignored here.
///
/// Returns `(directory_path, unknown_category)` for violations.
#[must_use]
pub(crate) fn find_wellknown_category_violations(trait_dirs: &[String]) -> Vec<(String, String)> {
    let mut violations = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for dir_path in trait_dirs {
        let parts: Vec<&str> = dir_path.split('/').collect();
        if parts.len() < 3 {
            continue;
        }

        if parts[0] != "well-known" {
            continue;
        }

        // Skip top-level categories that are themselves invalid — the directory
        // whitelist reports those. Avoid double-flagging.
        if !WELL_KNOWN_TOP_LEVEL.contains(&parts[1]) {
            continue;
        }

        let (allowed, category) = match parts[1] {
            "malware" => (WELL_KNOWN_MALWARE_CATEGORIES, parts[2]),
            "tool" => (WELL_KNOWN_TOOL_CATEGORIES, parts[2]),
            _ => continue,
        };

        if !allowed.contains(&category) && seen.insert((parts[1].to_string(), category.to_string()))
        {
            violations.push((dir_path.clone(), category.to_string()));
        }
    }

    violations.sort_by(|a, b| a.1.cmp(&b.1));
    violations
}

/// Find well-known/ directories where NO composite has local anchoring.
///
/// A well-known/ directory should identify a *specific* malware family, which means
/// at least one composite in the directory should reference a trait that is either:
/// - Defined locally in the same well-known/ directory (a family-specific fingerprint)
/// - Defined elsewhere in well-known/ (another family-specific indicator)
///
/// If ALL composites in a directory only point to micro-behaviors/ or objectives/,
/// the entire directory is detecting generic behavior patterns and belongs in objectives/.
///
/// Returns `(rule_id, source_file)` for violations (all composites in unanchored dirs).
#[must_use]
pub(crate) fn find_unanchored_wellknown_composites(
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    use std::path::Path;

    // Group composites by their parent directory
    let mut dir_composites: HashMap<String, Vec<&CompositeTrait>> = HashMap::new();

    for rule in composite_rules {
        let rule_path = rule.id.find("::").map_or(&rule.id[..], |i| &rule.id[..i]);
        if !rule_path.starts_with("well-known/") {
            continue;
        }

        let source = rule.defined_in.to_string_lossy().to_string();
        let dir = Path::new(&source)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        dir_composites.entry(dir).or_default().push(rule);
    }

    let mut violations = Vec::new();

    for composites in dir_composites.values() {
        // Check if ANY composite in this directory has well-known/ anchoring
        let dir_is_anchored = composites.iter().any(|rule| {
            let refs = collect_trait_refs_from_rule(rule);
            refs.iter()
                .any(|(ref_id, _)| ref_id.starts_with("well-known/"))
        });

        if dir_is_anchored {
            continue;
        }

        // Entire directory is unanchored - flag all composites in it
        for rule in composites {
            let source = rule_source_files
                .get(&rule.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((rule.id.clone(), source));
        }
    }

    violations
}

/// Generic technique words that should not appear as leaf directory names in well-known/.
///
/// well-known/ leaf directories should be named after specific malware families, tools,
/// or campaigns (e.g., "mirai", "cobalt-strike", "lazarus"), not generic techniques.
const GENERIC_TECHNIQUE_WORDS: &[&str] = &[
    "browser",
    "clipboard",
    "credential",
    "credentials",
    "downloader",
    "evasion",
    "exfiltration",
    "generic",
    "infostealer",
    "keylog",
    "loader",
    "obfuscated",
    "operation",
    "operations",
    "persistence",
    "privilege-escalation",
    "reverse-shell",
    "scanner",
    "screen-capture",
    "shell",
    "signals",
    "stealer",
    "webshell",
];

/// Find well-known/ leaf directories named with generic technique words.
///
/// Leaf directories in well-known/ should be named after specific malware families
/// (e.g., "mirai", "kinsing", "cobalt-strike"), not generic behavioral categories
/// (e.g., "stealer", "loader", "evasion").
///
/// Returns `(directory_path, generic_word)` for violations.
#[must_use]
pub(crate) fn find_generic_wellknown_leaf_dirs(trait_dirs: &[String]) -> Vec<(String, String)> {
    let mut violations = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for dir_path in trait_dirs {
        if !dir_path.starts_with("well-known/") {
            continue;
        }

        let parts: Vec<&str> = dir_path.split('/').collect();
        // Leaf is the last directory segment. For well-known/malware/dropper/nemucod,
        // leaf is "nemucod" (good). For well-known/malware/trojan/generic, leaf is "generic" (bad).
        // Skip the first 3 segments (well-known/malware/<category>) and check remaining.
        if parts.len() < 4 {
            continue;
        }

        // Check segments from position 3 onward (after well-known/<type>/<category>/)
        for &segment in &parts[3..] {
            let lower = segment.to_lowercase();
            if GENERIC_TECHNIQUE_WORDS.contains(&lower.as_str()) && seen.insert(dir_path.clone()) {
                violations.push((dir_path.clone(), segment.to_string()));
                break;
            }
        }
    }

    violations
}

/// Find well-known/ composite-only files whose parent directory has no atomic traits.
///
/// well-known/ should contain family-specific fingerprints (atomic traits with unique
/// strings, patterns, or signatures). A composite-only file is acceptable if sibling
/// files in the same subdirectory define atomic traits (multi-file family definitions
/// like `nemucod/` or `rustdoor/`). But if the entire subdirectory has zero atomic
/// traits, the composites are likely assembling generic behaviors and belong in
/// objectives/ instead — or the family-specific traits are misplaced in another tier
/// (e.g., micro-behaviors/) and should be moved to well-known/.
///
/// Returns `(source_file, composite_count)` for violations.
#[must_use]
pub(crate) fn find_composite_only_wellknown_files(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, usize)> {
    use std::path::Path;

    // Build set of directories that contain atomic traits
    let mut dirs_with_traits: std::collections::HashSet<String> = std::collections::HashSet::new();

    for t in trait_definitions {
        let source = t.defined_in.to_string_lossy().to_string();
        if source.contains("well-known/")
            && let Some(dir) = Path::new(&source).parent()
        {
            dirs_with_traits.insert(dir.to_string_lossy().to_string());
        }
    }

    // Collect composite-only files and their ref info
    let mut file_composite_counts: HashMap<String, usize> = HashMap::new();
    let mut file_composite_refs: HashMap<String, Vec<Vec<String>>> = HashMap::new();

    for rule in composite_rules {
        let source = rule.defined_in.to_string_lossy().to_string();
        if source.contains("well-known/") {
            *file_composite_counts.entry(source.clone()).or_insert(0) += 1;

            let refs: Vec<String> = collect_trait_refs_from_rule(rule)
                .into_iter()
                .map(|(ref_id, _)| ref_id)
                .collect();
            file_composite_refs.entry(source).or_default().push(refs);
        }
    }

    let mut violations = Vec::new();

    for (source_file, composite_count) in &file_composite_counts {
        let dir = Path::new(source_file)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // Skip if this file's directory has atomic traits (in this file or siblings)
        if dirs_with_traits.contains(&dir) {
            continue;
        }

        // Also skip if composites reference well-known/ traits (anchored to another family file)
        let has_wellknown_refs = file_composite_refs
            .get(source_file)
            .map(|ref_groups| {
                ref_groups
                    .iter()
                    .any(|refs| refs.iter().any(|r| r.starts_with("well-known/")))
            })
            .unwrap_or(false);

        if !has_wellknown_refs {
            violations.push((source_file.clone(), *composite_count));
        }
    }

    violations.sort_by(|a, b| a.0.cmp(&b.0));
    violations
}

// ============================================================================
// well-known/ and metadata/ specificity validators
// ============================================================================

/// Returns true if the trait targets binary file types (explicitly or via All).
fn trait_targets_binaries(trait_def: &TraitDefinition) -> bool {
    trait_def.r#for.contains(&FileType::All)
        || trait_def.r#for.iter().any(|ft| is_binary_file_type(*ft))
}

/// Returns true if every effective target file type is binary.
///
/// Mixed traits like `for: [pe, shell]` should not be forced to specify
/// binary section filters because those filters have no meaning for the
/// non-binary half of the target set.
fn trait_targets_only_binaries(trait_def: &TraitDefinition) -> bool {
    !trait_def.r#for.contains(&FileType::All)
        && !trait_def.r#for.is_empty()
        && trait_def.r#for.iter().all(|ft| is_binary_file_type(*ft))
}

/// Returns true if the condition has a section filter or positional constraint applied to it.
/// This includes: section/offset/offset_range/section_offset/section_offset_range fields
/// on string/raw/hex conditions, or a Section type.
fn condition_has_section_filter(cond: &Condition) -> bool {
    match cond {
        Condition::Raw(RawQuery {
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
        }) => {
            section.is_some()
                || offset.is_some()
                || offset_range.is_some()
                || section_offset.is_some()
                || section_offset_range.is_some()
        }
        Condition::Section(SectionQuery { .. }) => true,
        _ => false,
    }
}

/// Returns true if the condition is one where a section filter would be
/// meaningful. Callers should additionally gate on `trait_targets_binaries` —
/// section filters only apply to binary file types.
fn condition_supports_section_filter(cond: &Condition) -> bool {
    matches!(
        cond,
        Condition::Raw(RawQuery { .. })
            | Condition::Text(TextQuery { .. })
            | Condition::Literal(LiteralQuery { .. })
            | Condition::Encoded(EncodedQuery { .. })
            | Condition::Hex(HexQuery { .. })
    )
}

/// Extract tier prefix from a trait ID (everything before the first `::` or `/`-delimited namespace).
fn extract_trait_tier(id: &str) -> &str {
    let base = id.find("::").map_or(id, |i| &id[..i]);
    base.find('/').map_or(base, |i| &base[..i])
}

/// Number of platform variants used when `Platform::All` is expanded.
const CONCRETE_PLATFORM_COUNT: usize = 25;

/// Effective filetype count used when `for: [all]` is set — larger than any threshold.
const ALL_FILETYPES_COUNT: usize = usize::MAX;

/// Threshold for flagging a trait as having too many effective platforms.
///
/// A trait must declare only the platforms and file types it actually needs to
/// fire — and no more. This is a **performance** constraint as much as a
/// correctness one: every declared platform/type widens the set of files the
/// trait is evaluated against, so an over-broad `platforms:`/`for:` makes the
/// engine scan the matcher across inputs it can never legitimately match,
/// wasting CPU on every analysis. Constrain to the minimum necessary to execute.
const BROAD_PLATFORM_THRESHOLD: usize = 4;

/// Maximum effective file types a trait may target, **by matcher (query)
/// type**, before it must narrow `for:` or earn a type-qualified
/// [`BROAD_FILETYPE_ALLOWLIST`] entry.
///
/// Traits should be focused on exactly the filetypes they are designed to fire
/// against — and no more. Beyond accuracy and ML feature hygiene, this is a
/// performance guardrail: a trait runs against every file of every type it
/// declares, so superfluous `for:` entries cost scan time on every input for
/// no possible match.
///
/// The cap depends on the matcher type because breadth means different things
/// per type, in descending order of how language/format-agnostic the matcher
/// is. Content strings (`text`/`literal`/`comment`) are the most agnostic — a
/// string can appear in any host file — so they get the widest cap; whole-file
/// `metrics` and `basename` patterns are nearly as agnostic; `raw`/`encoded`
/// byte scans target progressively narrower sets; `section` is binary-bound;
/// `symbol`/`syscall` and `hex`/`yara` are language/binary-bound; structural
/// `value` paths are format-bound; and an AST (`tree-sitter`) query is written
/// for exactly one grammar. A type-qualified allowlist entry
/// (`"text:<dir-prefix>"`) only lifts the cap for that one matcher type.
const BROAD_FILETYPE_THRESHOLD_PATH: usize = 4; // full-path matchers — start tight; whitelist/narrow case-by-case
// Content-scan caps (text/metrics/encoded) include the macOS-native types
// (applescript/plist/swift/objectivec) that ride into a group expansion now
// that the `unix` umbrella reaches macOS (see resolve_platform_filetype_conflicts).
// They also cover the complete generated manifest and archive families. These
// are the family widths, not arbitrary exceptions for individual traits: adding
// a supported format must not make the shipped taxonomy unloadable.
const BROAD_FILETYPE_THRESHOLD_TEXT: usize = 29; // text / literal / comment
const BROAD_FILETYPE_THRESHOLD_METRICS: usize = 25; // whole-file metrics
// A basename matches the *filename*, which is artifact-specific — a filename
// pattern that fires across many languages is almost always mis-scoped. Kept
// deliberately tight (mirrors PATH): narrow `for:` to the type(s) the filename
// implies, or add a `basename:<dir>` allowlist entry for the rare exception.
const BROAD_FILETYPE_THRESHOLD_BASENAME: usize = 7; // filename patterns
const BROAD_FILETYPE_THRESHOLD_ENCODED: usize = 11; // decoded-content scan
const BROAD_FILETYPE_THRESHOLD_SECTION: usize = 8; // binary section names
const BROAD_FILETYPE_THRESHOLD_YARA: usize = 4; // yara rules (may span container formats)
const BROAD_FILETYPE_THRESHOLD_SYMBOL: usize = 7; // symbol / syscall tables
const BROAD_FILETYPE_THRESHOLD_VALUE: usize = 6; // structural value paths
const BROAD_FILETYPE_THRESHOLD_RAW: usize = 3; // raw byte scan — native binary family (elf/macho/pe)
const BROAD_FILETYPE_THRESHOLD_HEX: usize = 3; // hex byte pattern — native binary family (elf/macho/pe)
const BROAD_FILETYPE_THRESHOLD_AST: usize = 1; // tree-sitter (single grammar)

/// Per-matcher-type file-type cap. See [`BROAD_FILETYPE_THRESHOLD_TEXT`].
fn filetype_cap_for_condition(cond: &Condition) -> usize {
    match cond {
        Condition::Text(TextQuery { .. })
        | Condition::Literal(LiteralQuery { .. })
        | Condition::Comment(CommentQuery { .. }) => BROAD_FILETYPE_THRESHOLD_TEXT,
        // An alias/composite-leg reference (`if: { id: X }`) does no scanning of
        // its own — it delegates to the referenced trait, which is capped per its
        // own matcher. The wrapper's `for:` is only an evaluation gate, so it is
        // exempt from the file-type cap.
        Condition::Trait { .. } => usize::MAX,
        Condition::Metrics(MetricsQuery { .. }) => BROAD_FILETYPE_THRESHOLD_METRICS,
        // Full-path matchers use the dedicated path cap; `basename`/`dirname`-
        // scoped paths are filename-bounded and get the basename cap. A path
        // condition with no string matcher (exact/substr/regex/is) does no
        // scanning at all — it is a trivially-true type/size gate (e.g. the
        // `is-binary` building block), so it is exempt from the file-type cap.
        Condition::Path(PathQuery {
            basename,
            dirname,
            exact,
            substr,
            regex,
            is_check,
            ..
        }) => {
            if exact.is_none() && substr.is_none() && regex.is_none() && is_check.is_none() {
                usize::MAX
            } else if *basename || *dirname {
                BROAD_FILETYPE_THRESHOLD_BASENAME
            } else {
                BROAD_FILETYPE_THRESHOLD_PATH
            }
        }
        Condition::Raw(RawQuery { .. }) => BROAD_FILETYPE_THRESHOLD_RAW,
        Condition::Encoded(EncodedQuery { .. }) => BROAD_FILETYPE_THRESHOLD_ENCODED,
        Condition::Section(SectionQuery { .. }) => BROAD_FILETYPE_THRESHOLD_SECTION,
        Condition::Symbol(SymbolQuery { .. }) | Condition::Syscall { .. } => {
            BROAD_FILETYPE_THRESHOLD_SYMBOL
        }
        Condition::Hex(HexQuery { .. }) => BROAD_FILETYPE_THRESHOLD_HEX,
        Condition::Yara { .. } => BROAD_FILETYPE_THRESHOLD_YARA,
        Condition::Kv(KvQuery { .. }) => BROAD_FILETYPE_THRESHOLD_VALUE,
        Condition::TreeSitter(TreeSitterQuery { .. }) => BROAD_FILETYPE_THRESHOLD_AST,
    }
}

/// Canonical matcher-type label used to match type-qualified
/// [`BROAD_FILETYPE_ALLOWLIST`] entries. Normalizes the obsolete
/// `string_literal` alias to `literal`.
fn broad_filetype_category(cond: &Condition) -> &'static str {
    match cond.type_name() {
        "string_literal" => "literal",
        other => other,
    }
}

/// Trait path prefixes where 4+ effective platforms are permitted.
pub(crate) const BROAD_PLATFORM_ALLOWLIST: &[&str] = &[
    "objectives/supply-chain/",
    // Package-registry record facts (ecosystem, age, adoption, deprecation,
    // listing description) describe a release independent of OS — a package is
    // published once and installed everywhere — so they are inherently
    // all-platform. Narrowing `platforms:` would silently drop coverage.
    "metadata/registry/",
];

/// Trait path prefixes where broad file type coverage is permitted.
///
/// These directories contain patterns (network indicators, encoding schemes, etc.)
/// that legitimately appear across compiled binaries, scripts, source code, and
/// documents — so requiring narrow file type targeting would silently drop coverage.
/// Directory subtrees permitted to exceed the per-type file-type cap, qualified
/// by matcher type: an entry `"<type>:<dir-prefix>"` lifts the cap only for
/// matchers of `<type>` whose source file path contains `<dir-prefix>`. A broad
/// `text` matcher in an allowlisted `text:` directory passes; the same directory
/// does **not** license a broad `value`/`symbol`/etc. matcher.
pub(crate) const BROAD_FILETYPE_ALLOWLIST: &[&str] = &[
    // IP addresses and port numbers are embedded in binaries, scripts, manifests, docs
    "text:micro-behaviors/communications/ip/",
    // URLs and URL fragments appear in any file type
    "text:micro-behaviors/communications/url/",
    // IDN homograph / non-ASCII URL checks are deliberately host-format-agnostic:
    // a spoofed source URL can hide in a PKGBUILD, package manifest, source file,
    // config, or document, so narrowing `for:` would silently drop coverage.
    "text:objectives/supply-chain/impersonation/homograph/",
    // C2 infrastructure indicators (IPs, domains, ports, tunnels) appear in any file
    "text:objectives/command-and-control/infrastructure/",
    // HTTP header names and values appear in binaries, scripts, and documents
    "text:micro-behaviors/communications/http/headers/",
    // Credential access patterns (passwords, tokens, keys, wallets) appear in any file
    "text:objectives/credential-access/",
    // Filesystem path strings (/etc/passwd, ~/.aws/credentials, %APPDATA%\…) are
    // language-agnostic content — the same path literal appears in any source,
    // script, config, doc, or binary that references it.
    "text:micro-behaviors/fs/path/",
    // IP discovery service hostnames are embedded in any executable (scripts, binaries, config)
    "text:micro-behaviors/communications/http/ip-discovery/",
    // Service API hostnames (api.telegram.org, slack.com, …) are host-string
    // literals that appear in any language that talks to the service — script,
    // compiled binary, or source. Narrowing `for:` would silently drop coverage.
    "text:micro-behaviors/communications/http/services/",
    // Shell language markers are intentionally shared across scripts, source, and binaries
    "text:micro-behaviors/process/create/shell/lang/",
    // Download-execute dropper patterns are malicious whether they appear in a
    // shell script, package.json postinstall, setup.py cmdclass, Dockerfile RUN,
    // plist ProgramArguments, systemd ExecStart, etc.
    "text:objectives/command-and-control/dropper/delivery/download-execute/",
    "text:objectives/command-and-control/dropper/delivery/hidden-stage/",
    // Hardcoded C2 URL string literals (IP-pinned URLs, .php panel endpoints)
    // appear in any source language — same rationale as communications/url/.
    // The directory's -encoded and -binary legs are already narrowly scoped.
    "text:micro-behaviors/communications/http/url/",
    // Cross-language file text/format properties (license headers, text
    // profiles, catalog strings, generic string identities) appear broadly.
    "text:metadata/file/catalog/",
    "text:metadata/file/format/",
    "text:metadata/file/profile/",
    "text:metadata/file/string/",
    "text:metadata/file/extension/",
    "text:micro-behaviors/data/encoded/",
    "text:micro-behaviors/data/format/media/",
    "text:micro-behaviors/data/runtime/keywords/",
    "text:micro-behaviors/communications/http/keywords/",
    "text:micro-behaviors/data/parse/vocabulary/",
    "text:micro-behaviors/ui/window/notify/keywords/",
    "text:objectives/command-and-control/backdoor/keywords/",
    "text:objectives/command-and-control/botnet/keywords/",
    "text:objectives/command-and-control/backdoor/rat/keywords/",
    "text:objectives/command-and-control/dropper/keywords/",
    "text:objectives/command-and-control/remote-command/keywords/",
    "text:objectives/command-and-control/remote-command/llm/",
    "text:objectives/collection/clipboard/keywords/",
    "text:objectives/exfiltration/stealer/surveillance/",
    "text:objectives/evasion/kernel-hide/keywords/",
    "text:objectives/evasion/indicator-removal/keywords/",
    "text:objectives/evasion/security-bypass/edr/",
    "text:objectives/evasion/security-bypass/llm/",
    "text:objectives/impact/crypto-manipulation/keywords/",
    "text:objectives/impact/destroy/keywords/",
    "text:objectives/impact/dos/keywords/",
    "text:objectives/impact/ransom/keywords/",
    "text:objectives/privilege-escalation/exploit/keywords/",
    "text:micro-behaviors/hardware/input/keyboard/label/",
    "text:well-known/tool/detection/",
    "text:well-known/app/context/",
    "text:well-known/malware/trojan/family/",
    "text:well-known/tool/offensive/payload-corpus/",
    // Marking a file executable (chmod +x / mode 0o755) is a delivery step that
    // appears across every script, source language, and manifest that drops and
    // launches a payload — so the chmod-executable atoms scan broadly.
    "text:micro-behaviors/fs/chmod/executable/",
    // "Code generated … DO NOT EDIT" markers appear in generated code of every language.
    "text:metadata/lang/source/generated.yaml",
    // The Racket language classifier matches `#lang racket` to identify the
    // language of otherwise-unknown files, so it must scan broadly.
    "text:metadata/lang/scripted/racket.yaml",
    // Cryptographic vocabulary (ciphertext, shared secret, key-material labels)
    // appears in crypto implementations of every language.
    "text:micro-behaviors/crypto/",
    // C2 messaging-channel indicators (e.g. Discord webhook URLs) are string
    // markers embedded in malware written in any language.
    "text:objectives/command-and-control/channel/messaging/",
    // VSS / shadow-copy deletion commands (vssadmin, \\?\GLOBALROOT, robocopy
    // \Device\Harddisk…) can be shelled out from any language.
    "text:objectives/evasion/indicator-removal/shadow-copy/",
    // String *literals* (parser-extracted) for the same cross-language content
    // classes allowlisted for `text:` above: a hardcoded C2 IP/port, URL,
    // credential path, or text marker is written as a quoted literal in source
    // of every language. Same cross-language rationale, different matcher type.
    "literal:micro-behaviors/communications/ip/",
    "literal:micro-behaviors/communications/http/url/",
    "literal:objectives/command-and-control/infrastructure/",
    "literal:micro-behaviors/fs/path/sensitive/credentials/",
    "literal:micro-behaviors/process/create/shell/lang/",
    "literal:metadata/file/catalog/",
    "literal:metadata/file/extension/",
    "literal:metadata/file/format/",
    "literal:metadata/file/profile/",
    "literal:metadata/file/string/",
    "literal:objectives/impact/destroy/keywords/",
    "literal:objectives/command-and-control/remote-command/llm/",
    "literal:objectives/credential-access/theft/keywords/",
    // Archive-member structural matchers (a vim-swap file, go.mod, .go source,
    // or Package.swift shipped inside a package) legitimately span the whole
    // archive family — the same member can appear in an npm tarball, gem, whl,
    // crate, etc. — so these value paths scan broadly.
    "value:metadata/package/files/",
    // README-name-vs-package-name mismatch is checked against the README of
    // every ecosystem's package archive, so the structural readme value paths
    // span the archive family.
    "value:objectives/supply-chain/impersonation/readme-clone/",
    // Test/fixture/example directory layouts (`/tests/`, `/winetests/`,
    // `__fixtures__/`) are detected inside package archives of every ecosystem,
    // so these path matchers legitimately span the archive family.
    "path:metadata/package/testing/presence/harness/",
    // Test-path / embedded-runtime FP-suppression: excluding `…/test/…` and
    // `jruby-complete.jar!…` paths from obfuscation flags applies across every
    // code/archive type the obfuscation composites run on.
    "path:objectives/anti-static/obfuscation/code-metrics/",
    // Whole-file size / "is-binary" filters carry a match-anything path pattern
    // and apply to the entire native+bytecode binary family (elf/macho/pe/
    // class/pyc) and beyond.
    "path:metadata/binary/",
    // Well-known app/library identification by file path (release-archive names,
    // source-tree directories, executable names) is inherently multi-format —
    // an app ships as an exe, a tarball, a zip, and source at once.
    "path:well-known/",
    // Package-registry record facts read the normalized `registry.*` value tree
    // and metrics that fletch materializes from an upstream listing. That record
    // is package-level context, not a property of any one member file, so the
    // matchers run regardless of which file type carries the package.
    "value:metadata/registry/",
    "metrics:metadata/registry/",
];

/// Returns the effective platform count for a trait.
/// `Platform::All` expands to all known platform variants.
fn effective_platform_count(platforms: &[Platform]) -> usize {
    if platforms.contains(&Platform::All) {
        CONCRETE_PLATFORM_COUNT
    } else {
        platforms.len()
    }
}

/// Returns the effective file type count for a trait.
/// `FileType::All` is treated as the maximum possible count.
/// Named groups are already expanded in `t.r#for`, so `len()` gives the real count.
fn effective_filetype_count(t: &TraitDefinition) -> usize {
    if t.r#for.contains(&FileType::All) {
        ALL_FILETYPES_COUNT
    } else {
        t.r#for.len()
    }
}

/// Find atomic traits with 4+ effective platforms outside the broad-platform allowlist.
///
/// `Platform::All` counts as all known platform variants. Traits must be in an allowlisted
/// directory to use 4+ platforms; otherwise they should target a narrower platform set.
///
/// Returns `Vec<(trait_id, source_file, platform_count)>` for violations.
#[must_use]
pub(crate) fn find_broad_platform_traits(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, usize)> {
    trait_definitions
        .iter()
        .filter(|t| {
            let count = effective_platform_count(&t.platforms);
            if count < BROAD_PLATFORM_THRESHOLD {
                return false;
            }
            let source = rule_source_files
                .get(&t.id)
                .map(String::as_str)
                .unwrap_or("");
            !BROAD_PLATFORM_ALLOWLIST
                .iter()
                .any(|prefix| source.contains(prefix))
        })
        .map(|t| {
            let source = rule_source_files
                .get(&t.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            (t.id.clone(), source, effective_platform_count(&t.platforms))
        })
        .collect()
}

/// Find atomic traits that list `unix` alongside `linux` or `macos`, which is redundant.
///
/// `unix` is the superset that covers Linux and macOS (and other Unix-like systems). Listing
/// `unix` together with `linux` or `macos` is redundant — `unix` already implies them.
/// Correct form: use `[unix, windows]` instead of `[linux, macos, unix, windows]`.
///
/// Returns `Vec<(trait_id, source_file, redundant_platform)>` for violations.
#[must_use]
pub(crate) fn find_redundant_unix_platforms(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, String)> {
    trait_definitions
        .iter()
        .filter_map(|t| {
            if !t.platforms.contains(&Platform::Unix) {
                return None;
            }
            let redundant: Vec<&str> = t
                .platforms
                .iter()
                .filter_map(|p| match p {
                    Platform::Linux => Some("linux"),
                    Platform::MacOS => Some("macos"),
                    _ => None,
                })
                .collect();
            if redundant.is_empty() {
                return None;
            }
            let source = rule_source_files
                .get(&t.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            Some((t.id.clone(), source, redundant.join(", ")))
        })
        .collect()
}

/// Find atomic traits whose effective file-type count exceeds the cap for their
/// matcher type (see [`filetype_cap_for_condition`]), excluding those covered by
/// a type-qualified [`BROAD_FILETYPE_ALLOWLIST`] entry.
///
/// `FileType::All` expands to every file type and so exceeds any cap. Named `for:`
/// groups are already expanded in `t.r#for`, so their member count is used directly.
///
/// Returns `Vec<(trait_id, source_file, type_count, matched_types, category, cap)>`
/// for violations.
#[must_use]
pub(crate) fn find_broad_filetype_traits(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, usize, Vec<FileType>, &'static str, usize)> {
    trait_definitions
        .iter()
        .filter_map(|t| {
            let count = effective_filetype_count(t);
            let cap = filetype_cap_for_condition(&t.r#if);
            if count <= cap {
                return None;
            }
            let category = broad_filetype_category(&t.r#if);
            let source = rule_source_files
                .get(&t.id)
                .map(String::as_str)
                .unwrap_or("");
            // A type-qualified allowlist entry ("text:<dir-prefix>") lifts the
            // cap only for matchers of that one type in that directory subtree.
            let allowlisted = BROAD_FILETYPE_ALLOWLIST.iter().any(|entry| {
                entry
                    .split_once(':')
                    .is_some_and(|(ty, prefix)| ty == category && source.contains(prefix))
            });
            if allowlisted {
                return None;
            }
            let matched_types = if t.r#for.contains(&FileType::All) {
                vec![FileType::All]
            } else {
                t.r#for.clone()
            };
            Some((
                t.id.clone(),
                source.to_string(),
                count,
                matched_types,
                category,
                cap,
            ))
        })
        .collect()
}

/// Find well-known/ atomic traits targeting binaries without any file size filter.
///
/// well-known/ traits targeting binary file types (PE, ELF, Mach-O) should include size bounds
/// to avoid false positives. Most malware samples fall within a predictable size range.
/// Script-only traits are excluded since script size is less predictable.
///
/// Returns `Vec<(trait_id, source_file)>` for violations.
#[must_use]
pub(crate) fn find_wellknown_missing_size_filter(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    trait_definitions
        .iter()
        .filter(|t| {
            extract_trait_tier(&t.id) == "well-known"
                && trait_targets_binaries(t)
                && t.size_min.is_none()
                && t.size_max.is_none()
        })
        .map(|t| {
            let source = rule_source_files
                .get(&t.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            (t.id.clone(), source)
        })
        .collect()
}

/// Find well-known/ atomic traits targeting binary file types whose condition lacks a section filter.
///
/// For binary targets (PE, ELF, Mach-O, etc.), section-scoped matching significantly reduces
/// false positives by restricting string/hex/raw matches to specific sections (e.g., `.text`, `.data`).
///
/// Returns `Vec<(trait_id, source_file)>` for violations.
#[must_use]
pub(crate) fn find_wellknown_missing_section_filter(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    trait_definitions
        .iter()
        .filter(|t| {
            extract_trait_tier(&t.id) == "well-known"
                && trait_targets_only_binaries(t)
                && condition_supports_section_filter(&t.r#if)
                && !condition_has_section_filter(&t.r#if)
        })
        .map(|t| {
            let source = rule_source_files
                .get(&t.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            (t.id.clone(), source)
        })
        .collect()
}

/// Find metadata/ atomic traits targeting binary file types whose condition lacks a section filter.
///
/// For binary targets, section-scoped matching improves precision. Unlike well-known/ traits,
/// this is a recommendation rather than a hard requirement, since metadata/ traits often
/// detect structural properties that apply file-wide.
///
/// Returns `Vec<(trait_id, source_file)>` for violations.
#[must_use]
pub(crate) fn find_meta_missing_section_filter(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    trait_definitions
        .iter()
        .filter(|t| {
            extract_trait_tier(&t.id) == "metadata"
                && trait_targets_only_binaries(t)
                && condition_supports_section_filter(&t.r#if)
                && !condition_has_section_filter(&t.r#if)
        })
        .map(|t| {
            let source = rule_source_files
                .get(&t.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            (t.id.clone(), source)
        })
        .collect()
}

#[cfg(test)]
mod content_dir_tests {
    use super::find_metadata_content_dirs;

    fn dirs(v: &[&str]) -> Vec<String> {
        v.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn flags_content_dirs_under_metadata_only() {
        let input = dirs(&[
            "metadata/binary/anomaly/content",
            "metadata/binary/section/content",
            "metadata/binary/section/metrics",
            // content/ outside metadata/ is legitimate and must not be flagged.
            "objectives/anti-static/obfuscation/encoding/content",
            "micro-behaviors/data/embedded/hash-table",
        ]);
        let mut got = find_metadata_content_dirs(&input);
        got.sort();
        assert_eq!(
            got,
            vec![
                "metadata/binary/anomaly/content".to_string(),
                "metadata/binary/section/content".to_string(),
            ]
        );
    }

    #[test]
    fn clean_metadata_tree_has_no_violations() {
        let input = dirs(&[
            "metadata/binary/anomaly/format",
            "metadata/binary/section/metrics",
            "metadata/vendor",
        ]);
        assert!(find_metadata_content_dirs(&input).is_empty());
    }
}
