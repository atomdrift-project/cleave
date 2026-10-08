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
use std::collections::{HashMap, HashSet};

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
    "anomaly",  // a judgment about a value, not a part or a technique: the fact
    //   belongs with the thing it describes and "how unusual" belongs
    //   in `crit:`
    "api",      // almost everything is an API
    "assorted", // dumping ground
    "atomic",   // vague
    "base",     // too vague
    "basic",    // meaningless
    "behavior",
    "behaviors",
    "core",      // catch-all: "the main part" says nothing the siblings do not
    "canonical", // describes "the textbook example of X", not a technique
    // A verdict about what was matched, not a description of it. A directory
    // names what its traits search for; whether that turns out to be fine is
    // `crit:`, and a benign-context suppressor belongs in the directory for
    // the thing it detects (TAXONOMY: "relocate a genuine suppressor to the
    // directory that matches what it detects"). `os/service/legitimate/` held
    // `uv publish` and `curl | sh` installer markers -- neither a service nor
    // a judgment anyone could act on -- until they moved to the package
    // publishing and shell-pipeline directories that actually describe them.
    "legitimate",
    "benign",
    "known-good",
    "harmless",
    "safe",
    "trusted",
    "whitelist",
    "allowlist",
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
    "metrics", // everything here is measured; put the count with the part it
    //   counts and let the threshold live in the trait name
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
    "pattern",  // vague
    "patterns", // vague
    "protocol", // vague
    "quality",  // a judgment, not a subject: "whose quality, by what standard?"
    //   an absent author field is an absent field, not low quality
    "go-runtime", // platform
    "simple",     // meaningless
    "stuff",      // obviously bad
    "signals",
    "words",
    "kinds",
    "suspicious", // dumping ground
    "technique",  // dumping ground
    "techniques", // dumping ground
    // Same failure as `technique`, one word further up the kill chain: every
    // child of an objective directory is a tactic, so the segment restates its
    // parent instead of narrowing it, and in practice collects whatever did not
    // fit the precise siblings. `credential-access/phishing/tactics/` held
    // bundled login-page assets, CVV and ATM-PIN form fields, a Cordova webview
    // wrapper and console poisoning -- four different subjects with existing
    // homes in `lure/`, `credential/`, `kit/` and `anti-analysis/` -- while
    // spending the last ML-visible level to say nothing about any of them.
    "tactic",
    "tactics",
    // The same habit one step further: a rule that chains several steps is
    // still named for the technique it performs, not for the fact that it has
    // steps. Every stealer is a workflow, so `collection/stealer/workflow/`
    // narrowed nothing and grew into that directory's largest child (143
    // traits, more than the `tactics/` it sat beside) while collecting three
    // named malware fingerprints that belong in `well-known/malware/`.
    "workflow",
    "workflows",
    // An adjective partitions by value rather than by subject, so it splits
    // facts that belong together and spends the visible level saying nothing --
    // TAXONOMY names `sparse/`, `dense/` and `structural/` for this. The one
    // `structural/` in the tree held a Mach-O stealer rule whose own
    // description reads "Structural + Behavioral" and most of whose legs are
    // behavioral, so the segment described half the rule's shape rather than
    // what it detects.
    //
    // The noun `structure/` is deliberately NOT banned, and matching here is
    // exact segment equality so it stays untouched: a PDF, an RTF and an ISO
    // image each genuinely have a structure, and it is a part of the format in
    // the same way `header/`, `section/` and `symbols/` are.
    "structural",
    "sparse",
    "dense",
    // Grab-bag wherever the siblings are techniques -- everything a stealer
    // takes is data, so `collection/stealer/data/` collected a bounded file
    // sweep, browser and wallet paths, an award scam and nine credential
    // stealers, and `collection/archive/data/` held the `tar`/`gzip`/`hdiutil`
    // commands that its own `create/` and `compress/` siblings are named for.
    //
    // It is a real subject in one position: as a peer domain classifier, beside
    // `crypto/`, `network/`, `media/`, `finance/`. `well-known/lib/data/` names
    // the data-layer libraries the way `lib/crypto/` names the cryptographic
    // ones. Those cases are listed in BANNED_SEGMENT_EXCEPTIONS below.
    "data",
    "text",
    "things", // obviously bad
    "tools",
    "tool",
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
        // A peer of `crypto/`, `communications/`, `fs/`, `mem/`, `process/`:
        // the domain of encoding, serialization, parsing and databases, not
        // "whatever a rule happens to touch".
        "micro-behaviors/data",
        "data",
    ),
    (
        // A peer of `ai/`, `finance/`, `media/`, `enterprise/`: database and
        // data-platform applications (postgresql, mysql-router).
        "well-known/app/data",
        "data",
    ),
    (
        // A peer of `crypto/`, `network/`, `format/`, `datetime/`: data-layer
        // libraries (redis, mysqlclient, postgrest-js).
        "well-known/lib/data",
        "data",
    ),
    (
        "metadata/package/fields/types",
        "types", // package.json `types`/`typings` entry point field
    ),
    (
        "metadata/binary/code",
        // "code" is vague anywhere else, but under metadata/binary/ it names one
        // of the format's parts -- the executable bytes themselves (basic blocks,
        // functions, complexity, density) -- exactly as ALLOWED_METADATA_BINARY
        // declares it and as the `metrics` migration notes point traits toward.
        "code",
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

/// Maximum number of rules (atomic traits plus composite rules) allowed in a
/// single directory. Composites count because a directory holding 40 atoms and
/// 90 roll-ups is just as flat to an author and to the ML directory feature as
/// one holding 130 atoms. Directories exceeding this should be split into
/// subdirectories.
pub(crate) const MAX_TRAITS_PER_DIRECTORY: usize = 100;

/// Maximum number of immediate subdirectories allowed in one directory.
/// Past this, a level has stopped being a taxonomy and become a flat list:
/// authors can no longer tell whether a sibling already covers their case, and
/// the directory feature the ML pipeline reads degenerates into one bucket per
/// entry. Split with an intermediate grouping layer.
pub(crate) const MAX_SUBDIRECTORIES_PER_DIRECTORY: usize = 150;

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
            for conds in [d.all.as_ref(), d.any.as_ref(), d.none.as_ref()]
                .into_iter()
                .flatten()
            {
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

/// Directory depth above this value produces a soft validation warning.
/// Count directories below the tier; filenames and local rule IDs do not count.
pub(crate) const TAXONOMY_DEPTH_REVIEW_THRESHOLD: usize = 5;

/// Find taxonomy directories deeper than the soft-warning threshold in any tier.
#[must_use]
pub(crate) fn find_deep_taxonomy_directories(trait_dirs: &[String]) -> Vec<(String, usize)> {
    let mut candidates = Vec::new();
    for directory in trait_dirs {
        let mut parts = directory.split('/');
        if !matches!(
            parts.next(),
            Some("micro-behaviors" | "objectives" | "metadata" | "well-known")
        ) {
            continue;
        }
        let depth = parts.count();
        if depth > TAXONOMY_DEPTH_REVIEW_THRESHOLD {
            candidates.push((directory.clone(), depth));
        }
    }
    candidates.sort();
    candidates.dedup();
    candidates
}

// Audited operation boundaries in TAXONOMY.md. These are exact child sets,
// not exemptions for arbitrary future subdivisions under these parents.
const REVIEWED_SPARSE_TAXONOMY_PARTITIONS: &[(&str, &[&str])] = &[
    // Algorithm-specific codec homes remain useful with a small current corpus;
    // do not merge gzip, LZMA, and joint zlib evidence into one bucket.
    ("micro-behaviors/data/codec", &["gzip", "lzma", "zlib"]),
    // Construct a path, canonicalize it, or extract a path component.
    (
        "micro-behaviors/fs/path-ops",
        &["join", "normalize", "parse"],
    ),
    // Enabling and disabling swap are opposite kernel operations.
    ("micro-behaviors/fs/swap", &["off", "on"]),
    // Create a FIFO versus transfer data through a pipe.
    ("micro-behaviors/fs/pipe", &["fifo", "transfer"]),
    // Different SQL Server execution facilities, each corroborated by
    // facility-specific configuration and shell/procedure evidence.
    (
        "objectives/execution/database",
        &["clr-procedure", "ole-automation", "xp-cmdshell"],
    ),
    // Throughput measurement and HTTP request workload testing have
    // distinct subjects, even when both are called benchmarks.
    (
        "micro-behaviors/communications/benchmark",
        &["bandwidth", "http"],
    ),
    // Fixed-width decimal digits versus language character-escape syntax.
    (
        "micro-behaviors/data/decode/char-code",
        &["decimal-triplet", "escape-sequence"],
    ),
    // Pointer coordinate access, event vocabulary, and synthetic input.
    (
        "micro-behaviors/hardware/input/mouse",
        &["message", "position", "simulate"],
    ),
    // Creating a TLS context versus configuring certificate verification.
    (
        "micro-behaviors/communications/tls",
        &["initialize", "verify"],
    ),
    // Installing a validation callback does not imply accepting invalid peers.
    (
        "micro-behaviors/communications/tls/verify",
        &["callback", "disable"],
    ),
    // Different filesystem link kinds, with junctions requiring a mount-point
    // tag or explicit junction-creation command rather than any reparse flag.
    (
        "micro-behaviors/fs/link",
        &["hardlink", "junction", "symlink"],
    ),
    // Callback registration is different from requesting termination.
    ("micro-behaviors/process/exit", &["handler", "terminate"]),
    // Configure/inspect signal disposition versus dispatch a signal.
    ("micro-behaviors/os/signal", &["dispatch", "handler"]),
    // Hive export and LSA secret-key access are distinct credential sources.
    (
        "objectives/credential-access/windows-registry",
        &["hive", "security-keys"],
    ),
    // Hollowing, remote-thread creation, and existing-thread hijack are different injection methods.
    (
        "objectives/command-and-control/dropper/process-inject",
        &["hollow", "remote-thread", "thread-hijack"],
    ),
    // Database configuration-file harvesting is separate from database queries.
    ("objectives/collection/database", &["credentials", "query"]),
    // Blockchain clients speak to chains; name-service clients resolve chain names.
    (
        "micro-behaviors/communications/blockchain",
        &["client", "name-service"],
    ),
    // PowerShell command-line launch options differ from host/runtime operations.
    (
        "micro-behaviors/process/interpreter/powershell",
        &["command", "host"],
    ),
    // Connectivity, API/function, path, pipe, and environment-variable checks are distinct sandbox evidence.
    (
        "objectives/anti-analysis/sandbox-detect/environment",
        &[
            "connectivity",
            "function",
            "native-injector",
            "path",
            "pipe",
            "var",
        ],
    ),
    // Host marker, local platform, and remote gating are separate execution conditions.
    (
        "objectives/execution/condition",
        &["host-marker", "platform", "remote-gate"],
    ),
    // Bind function/API, address structure, and address identity evidence differ.
    (
        "micro-behaviors/communications/socket/bind",
        &["address", "function", "ident"],
    ),
    // DNS and ICMP are distinct exfiltration channels.
    ("objectives/exfiltration/side-channel", &["dns", "icmp"]),
    // COM, library staging, named pipes, preload variables, and services are distinct hijack surfaces.
    (
        "objectives/privilege-escalation/hijack-execution-flow",
        &["com", "library-stage", "named-pipe", "preload", "service"],
    ),
    // Thread configuration, enumeration, grouping, lifecycle, priority, and termination are separate operations.
    (
        "micro-behaviors/process/thread",
        &[
            "config",
            "enumerate",
            "group",
            "lifecycle",
            "priority",
            "terminate",
        ],
    ),
    // Account takeover, stored MFA-secret recovery, and OWA-specific access have distinct evidence.
    (
        "objectives/credential-access/email/webmail",
        &["account-takeover", "mfa-secrets", "owa"],
    ),
    // Linker auditing, loader environment, load paths, and symbol ABI versions are distinct.
    (
        "micro-behaviors/os/linker",
        &["audit", "env", "load-path", "symbol-version"],
    ),
    // Polyglot format collisions, IExpress SED, and ZIP EOCD signatures are separate mechanisms.
    (
        "objectives/anti-static/polyglot",
        &["format", "iexpress", "zip-eocd"],
    ),
    // Process enumeration, target selection, and window-based discovery are different questions.
    (
        "objectives/discovery/process",
        &["enumerate", "targeting", "window"],
    ),
    // Packet socket, libpcap, tcpdump, and WinDivert are distinct capture backends.
    (
        "micro-behaviors/communications/capture",
        &["packet-socket", "pcap", "tcpdump", "windivert"],
    ),
    // Archive integrity and executable/runtime integrity are separate anti-tamper checks.
    (
        "objectives/anti-analysis/anti-tampering",
        &["archive", "integrity"],
    ),
    // ICMP channel use, ping, and route tracing are distinct operations.
    (
        "micro-behaviors/communications/icmp",
        &["channel", "ping", "trace"],
    ),
    // Process census, explicit process lists, and Node SEA gates use different runtime evidence.
    (
        "objectives/anti-analysis/sandbox-detect/process",
        &["census", "list", "node-sea"],
    ),
    // Local quarantine controls and network-appliance quarantine are different security surfaces.
    (
        "objectives/evasion/quarantine-removal",
        &["bypass", "network-appliance"],
    ),
    // Keychain extraction primitives and theft workflows are different levels of evidence.
    (
        "objectives/credential-access/keychain",
        &["extract", "theft"],
    ),
    // TCC bypass APIs, database edits, and Full Disk Access state are separate mechanisms.
    (
        "objectives/evasion/tcc-manipulation",
        &["bypass", "db", "fda"],
    ),
    // Hidden installation, init activation, install-state markers, and hidden paths differ.
    (
        "objectives/persistence/system/daemon",
        &["hidden", "init", "install-state", "path-hidden"],
    ),
    // Block identity, ioctl, loop devices, node creation, network blocks, and device links are separate.
    (
        "micro-behaviors/fs/device",
        &["blkid", "ioctl", "loop", "mknod", "network-block", "query"],
    ),
    // Provider-specific Telegram and WhatsApp stores require different schemas and APIs.
    (
        "objectives/credential-access/messaging",
        &["telegram", "whatsapp"],
    ),
    // Partition operations differ from raw-disk access.
    ("micro-behaviors/fs/disk", &["partition", "raw"]),
    // Arbitrary, cross-process, dump-format, and physical-memory reads are distinct.
    (
        "micro-behaviors/mem/read",
        &["arbitrary", "cross-process", "dump", "physical"],
    ),
    // URL fragments, provider/service construction, and template expansion are different constructors.
    (
        "micro-behaviors/communications/url/construction",
        &["fragment", "service", "template"],
    ),
    // Console, HTTP, inline, JIT, and monitoring hooks instrument different surfaces.
    (
        "objectives/evasion/process/hook",
        &["console", "http", "inline", "jit", "monitor"],
    ),
    // Request-driven shell execution, command injection, and embedded inline commands differ by source.
    (
        "objectives/execution/interpreter/cmd",
        &["http", "injection", "inline"],
    ),
    // DOM access, audio element use, creation, rendering, and tree traversal are separate UI operations.
    (
        "micro-behaviors/ui/window/dom",
        &["access", "audio", "create", "render", "tree"],
    ),
    // Audio, raster, magic validation, and streaming are distinct media operations.
    (
        "micro-behaviors/data/format/media",
        &["audio", "magic", "raster", "streaming"],
    ),
    // Credential-provider integration and Userinit launch replacement are different Winlogon surfaces.
    (
        "objectives/persistence/login/winlogon",
        &["credential-provider", "userinit"],
    ),
];

fn is_reviewed_sparse_taxonomy_partition(parent: &str, children: &[(String, usize)]) -> bool {
    REVIEWED_SPARSE_TAXONOMY_PARTITIONS
        .iter()
        .any(|(reviewed_parent, expected)| {
            parent == *reviewed_parent
                && children.len() == expected.len()
                && children
                    .iter()
                    .all(|(child, _)| expected.contains(&child.as_str()))
        })
}

/// Find sparse sibling cohorts that may be over-fragmented in the taxonomy.
///
/// A cohort produces a soft warning when a parent has at least two rule-bearing child
/// branches and their combined subtree contains fewer than 35 rules.
/// This does not prove the branches should be flattened: the child
/// techniques may be genuinely distinct. It identifies places where cap pressure
/// does not explain the extra branching and a human should check whether breadth
/// could preserve precision with a simpler visible path.
#[must_use]
pub(crate) fn find_sparse_sibling_cohorts(
    direct_rule_counts: &HashMap<String, usize>,
) -> Vec<(String, usize, usize)> {
    const SPARSE_SIBLING_RULE_THRESHOLD: usize = 35;
    let mut subtree_counts: HashMap<String, usize> = HashMap::new();

    for (directory, count) in direct_rule_counts {
        if !directory.starts_with("micro-behaviors/") && !directory.starts_with("objectives/") {
            continue;
        }
        let parts: Vec<&str> = directory.split('/').collect();
        if parts.len() < 3 {
            continue;
        }
        for end in 1..=parts.len() {
            *subtree_counts.entry(parts[..end].join("/")).or_default() += count;
        }
    }

    let mut children_by_parent: HashMap<String, Vec<(String, usize)>> = HashMap::new();
    for (directory, count) in &subtree_counts {
        if let Some((parent, child)) = directory.rsplit_once('/') {
            children_by_parent
                .entry(parent.to_string())
                .or_default()
                .push((child.to_string(), *count));
        }
    }

    let mut candidates = Vec::new();
    for (parent, children) in children_by_parent {
        // Ignore the tier and first category layer; they are too broad to be
        // useful as local organization advice.
        if parent.split('/').count() < 3 {
            continue;
        }
        if children.len() < 2 {
            continue;
        }
        let sibling_rules: usize = children.iter().map(|(_, count)| count).sum();
        if sibling_rules < SPARSE_SIBLING_RULE_THRESHOLD
            && !is_reviewed_sparse_taxonomy_partition(&parent, &children)
        {
            candidates.push((parent, sibling_rules, children.len()));
        }
    }
    candidates.sort_by(|a, b| (a.1, &a.0).cmp(&(b.1, &b.0)));
    candidates
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

/// Existing rule IDs retained during migration. New string-evidence rules must be
/// placed with the subject they support, not under the generic file/string axis.
/// Remove each ID from this grandfather list when its definition leaves that tree.
const LEGACY_METADATA_FILE_STRING_IDS: &[&str] = &[
    "metadata/file/string/account::identity-name-fields",
    "metadata/file/string/account::identity-email-fields",
    "metadata/file/string/account::first-name-field",
    "metadata/file/string/account::last-name-field",
    "metadata/file/string/account::user-name-field",
    "metadata/file/string/account::email-address-field",
    "metadata/file/string/account::primary-email-field",
    "metadata/file/string/account::work-email-field",
    "metadata/file/string/account::account-identity-labels",
    "metadata/file/string/account::user-email-label",
    "metadata/file/string/account::email-domain-label",
    "metadata/file/string/account::customer-email-profile-field",
    "metadata/file/string/account::email-label-vocabulary",
    "metadata/file/string/account::postal-address-field",
    "metadata/file/string/account::customer-contact-field",
    "metadata/file/string/account::account-email-label",
    "metadata/file/string/account::dataset-user-id-text-pair",
    "metadata/file/string/account::account-id-field",
    "metadata/file/string/account::account-created-field",
    "metadata/file/string/account::account-last-seen-field",
    "metadata/file/string/account::account-field-vocabulary",
    "metadata/file/string/account::session-agent-id-label",
    "metadata/file/string/account::quoted-username-label",
    "metadata/file/string/accounting::utmp-header-literal",
    "metadata/file/string/accounting::lastlog-header-literal",
    "metadata/file/string/accounting::acct-header-literal",
    "metadata/file/string/accounting::utmpx-header-literal",
    "metadata/file/string/accounting::lastlog-config-literal",
    "metadata/file/string/accounting::utmpx-config-literal",
    "metadata/file/string/accounting::acct-config-literal",
    "metadata/file/string/accounting::accounting-path-macro-literal",
    "metadata/file/string/accounting::accounting-record-type-literal",
    "metadata/file/string/accounting::accounting-header-literals",
    "metadata/file/string/accounting::accounting-config-literals",
    "metadata/file/string/application-name::chromium-browser-name-literal",
    "metadata/file/string/application-name::chrome-browser-name-literal",
    "metadata/file/string/application-name::firefox-browser-name-literal",
    "metadata/file/string/application-name::safari-browser-name-literal",
    "metadata/file/string/application-name::browser-doc-example-index",
    "metadata/file/string/application-name::edge-name-path",
    "metadata/file/string/application-name::microsoft-edge-name",
    "metadata/file/string/application-name::edge-name-ms",
    "metadata/file/string/application-name::edge-name-other",
    "metadata/file/string/application-name::opera-name-path",
    "metadata/file/string/application-name::opera-name-other",
    "metadata/file/string/application-name::brave-name",
    "metadata/file/string/application-name::yandex-name",
    "metadata/file/string/application-name::iexplore-executable-name",
    "metadata/file/string/application-name::internet-explorer-product-name",
    "metadata/file/string/application-name::edge-name-reference",
    "metadata/file/string/application-name::system-settings-name-reference",
    "metadata/file/string/application-name::system-preferences-name-reference",
    "metadata/file/string/application-name::settings-app-name-reference",
    "metadata/file/string/application-name::star-archive-format-marker",
    "metadata/file/string/application-name::star-default-config-marker",
    "metadata/file/string/application-name::netstat-usage-banner",
    "metadata/file/string/application-name::netstat-source-marker",
    "metadata/file/string/application-name::tool-identity-cpuid",
    "metadata/file/string/application-name::tool-identity-hwinfo",
    "metadata/file/string/application-name::tool-identity-putty",
    "metadata/file/string/application-name::tool-identity-filezilla",
    "metadata/file/string/application-name::tool-identity-wireshark",
    "metadata/file/string/application-name::tool-identity-7zip--rx-1",
    "metadata/file/string/application-name::tool-identity-7zip--rx-2",
    "metadata/file/string/application-name::tool-identity-7zip--rx-3",
    "metadata/file/string/application-name::tool-identity-7zip--rx-4",
    "metadata/file/string/application-name::official-7zip-dll-basename",
    "metadata/file/string/application-name::official-7zip-dll-reference",
    "metadata/file/string/application-name::official-7zip-gui-basename",
    "metadata/file/string/application-name::official-7zip-console-basename",
    "metadata/file/string/application-name::official-7zip-standalone-basename",
    "metadata/file/string/application-name::official-7zip-manager-basename",
    "metadata/file/string/application-name::7zip-gui-official-manifest",
    "metadata/file/string/application-name::pe-product-name-7zip",
    "metadata/file/string/application-name::tool-identity-winrar",
    "metadata/file/string/application-name::tool-identity-notepadplusplus",
    "metadata/file/string/application-name::software-catalog-token-list",
    "metadata/file/string/application-name::tool-identity-intel",
    "metadata/file/string/application-name::tool-identity-7zip-cond-0--inline-573",
    "metadata/file/string/application-name::trusted-tool-impersonator-context",
    "metadata/file/string/application-name::tool-identity-7zip",
    "metadata/file/string/application-name::official-7zip-component",
    "metadata/file/string/application-name::windows-safe-mode-toggle-script",
    "metadata/file/string/application-name::microsoft-activation-tool-script-marker",
    "metadata/file/string/application-name::microsoft-activation-tool-domain-marker",
    "metadata/file/string/application-name::microsoft-activation-tool-obfuscated-domain-marker",
    "metadata/file/string/application-name::microsoft-activation-scripts-title",
    "metadata/file/string/application-name::windows11-defender-disable-tweak",
    "metadata/file/string/application-name::defender-history-clear-title",
    "metadata/file/string/application-name::defender-history-remove-task-default",
    "metadata/file/string/application-name::kms-suite-title",
    "metadata/file/string/application-name::microsoft-activation-script-identity",
    "metadata/file/string/application-name::microsoft-activation-script-benign-context",
    "metadata/file/string/application-name::microsoft-activation-tool-script",
    "metadata/file/string/application-name::defender-history-clear-once-script",
    "metadata/file/string/architecture::mips64-architecture-string",
    "metadata/file/string/architecture::riscv32-architecture-string",
    "metadata/file/string/architecture::power8-architecture-string",
    "metadata/file/string/architecture::sh4aeb-architecture-string",
    "metadata/file/string/architecture::microblazebe-architecture-string",
    "metadata/file/string/artifact::seccomp-syscall-deny-table",
    "metadata/file/string/artifact::bpf-constant-name-table",
    "metadata/file/string/artifact::ptrace-constant-name-table",
    "metadata/file/string/artifact::cddl-spdx-header",
    "metadata/file/string/artifact::btf-vmlinux-header-guard",
    "metadata/file/string/artifact::btf-core-preserve-access-index-pragma",
    "metadata/file/string/artifact::linux-uapi-bpf-func-mapper-macro",
    "metadata/file/string/artifact::linux-btf-vmlinux-type-dump",
    "metadata/file/string/artifact::linux-uapi-bpf-header",
    "metadata/file/string/artifact::demo-prefix-keyword",
    "metadata/file/string/artifact::vagrant-machine-communicate-marker",
    "metadata/file/string/artifact::linux-syscall-note-license",
    "metadata/file/string/artifact::process-word-token",
    "metadata/file/string/artifact::payload-label",
    "metadata/file/string/artifact::embedded-256-bit-hex-digest",
    "metadata/file/string/attribution::author-banner",
    "metadata/file/string/attribution::upstream-project-attribution",
    "metadata/file/string/attribution::jsdoc-author-attribution",
    "metadata/file/string/attribution::spdx-license-identifier",
    "metadata/file/string/attribution::gnu-license-notice",
    "metadata/file/string/attribution::meta-platforms-copyright",
    "metadata/file/string/attribution::attributed-upstream-source",
    "metadata/file/string/charset::standard-base64-alphabet-text",
    "metadata/file/string/charset::standard-base64-alphabet",
    "metadata/file/string/charset::lower-first-base64-alphabet",
    "metadata/file/string/charset::standard-base64-alphabet-table",
    "metadata/file/string/charset::base64-alphabet",
    "metadata/file/string/charset::base62-alphanumeric-charset",
    "metadata/file/string/charset::qwerty-order-alphabet",
    "metadata/file/string/charset::lowercase-hex-alphabet",
    "metadata/file/string/charset::sequential-decimal-lookup-table",
    "metadata/file/string/charset::emoji-library-table-text",
    "metadata/file/string/charset::professional-setup-phrase",
    "metadata/file/string/charset::split-string",
    "metadata/file/string/cicd::github-workflows-path-string",
    "metadata/file/string/cicd::github-workflow-file-path",
    "metadata/file/string/cicd::github-actions-secret-record-marker",
    "metadata/file/string/cicd::cicd-runtime-fingerprint--rx-11",
    "metadata/file/string/cicd::cicd-runtime-fingerprint--rx-13",
    "metadata/file/string/cicd::cicd-runtime-fingerprint--rx-15",
    "metadata/file/string/collection::grabber-word",
    "metadata/file/string/collection::grabber-near-secret",
    "metadata/file/string/collection::secret-near-grabber",
    "metadata/file/string/collection::grabber-secret-word-context",
    "metadata/file/string/command::killprocess-token",
    "metadata/file/string/command::execute-token",
    "metadata/file/string/command::download-token",
    "metadata/file/string/command::disconnect-token",
    "metadata/file/string/command::httpserver-token",
    "metadata/file/string/command::dot-udp-command-text",
    "metadata/file/string/command::download-finished-msg",
    "metadata/file/string/command::execute-completed-msg",
    "metadata/file/string/command::command-status-vocabulary",
    "metadata/file/string/command::powershell-encoded-command-switch",
    "metadata/file/string/command::command-id-field-name",
    "metadata/file/string/command::script-many-shell-command-strings-100",
    "metadata/file/string/command::shell-multiple-local-assignments",
    "metadata/file/string/container::runc-oci-str",
    "metadata/file/string/container::libcontainer-str",
    "metadata/file/string/container::cri-api-str",
    "metadata/file/string/container::runtimeservice-str",
    "metadata/file/string/container::opencontainers-str",
    "metadata/file/string/container::oci-runtime-spec-str",
    "metadata/file/string/container::image-spec-str",
    "metadata/file/string/container::org-opencontainers-str",
    "metadata/file/string/container::prestart-str",
    "metadata/file/string/container::poststart-str",
    "metadata/file/string/container::poststop-str",
    "metadata/file/string/container::cni-github-str",
    "metadata/file/string/container::cni-prefix-str",
    "metadata/file/string/container::cni-libcni-str",
    "metadata/file/string/container::runc-refs",
    "metadata/file/string/container::cri-refs",
    "metadata/file/string/container::oci-refs",
    "metadata/file/string/container::hooks-refs",
    "metadata/file/string/container::hooks-with-config",
    "metadata/file/string/container::oci",
    "metadata/file/string/container::cni-refs",
    "metadata/file/string/corpus::hashed-text-record",
    "metadata/file/string/count::binary-strings-at-most-50",
    "metadata/file/string/count::large-macho-strings-at-most-50",
    "metadata/file/string/count::high-entropy-strings-200",
    "metadata/file/string/count::few-high-entropy-strings-20",
    "metadata/file/string/count::high-entropy-strings-450-plus",
    "metadata/file/string/count::high-entropy-strings-20",
    "metadata/file/string/count::binary-strings-one-to-five",
    "metadata/file/string/count::large-pe-strings-at-most-128",
    "metadata/file/string/count::few-string-literals",
    "metadata/file/string/count::string-count-over-10000",
    "metadata/file/string/count::string-concealment",
    "metadata/file/string/count::no-strings-dup",
    "metadata/file/string/count::string-scarcity-rich-binary",
    "metadata/file/string/count::string-scarcity-soft-noise",
    "metadata/file/string/count::no-strings-soft-noise",
    "metadata/file/string/count::large-macho-high-entropy-string-profile",
    "metadata/file/string/count::twenty-plus-shell-command-strings",
    "metadata/file/string/count::ten-plus-ip-address-strings",
    "metadata/file/string/count::fifty-plus-url-strings",
    "metadata/file/string/count::vbs-many-long-tokens",
    "metadata/file/string/credential::github-fine-grained-pat",
    "metadata/file/string/credential::uppercase-password-identifier",
    "metadata/file/string/credential::cloud-credential-type-name",
    "metadata/file/string/credential::telnetadmin-account-token",
    "metadata/file/string/credential::password-value-text",
    "metadata/file/string/device::data-section-virtual-word",
    "metadata/file/string/device::data-section-bluetooth-word",
    "metadata/file/string/device::plc-keyword",
    "metadata/file/string/device::hmi-keyword",
    "metadata/file/string/device::scada-keyword",
    "metadata/file/string/device::rtu-keyword",
    "metadata/file/string/device::ics-device-keywords",
    "metadata/file/string/device::turbine-speed-field",
    "metadata/file/string/device::reboot-word",
    "metadata/file/string/device::factory-word",
    "metadata/file/string/device::vboxguest-service-registry-path",
    "metadata/file/string/device::virtualbox-sdk-module-name",
    "metadata/file/string/device::windows-usb-hardware-id",
    "metadata/file/string/domain::fake-av-vendor-domain",
    "metadata/file/string/domain::adult-redirect-domain",
    "metadata/file/string/domain::url-with-top-tld",
    "metadata/file/string/domain::long-alphanumeric-third-level-label",
    "metadata/file/string/domain::channel-domain-variable-name",
    "metadata/file/string/domain::structured-remote-url-field",
    "metadata/file/string/file::office-document-extension--docx",
    "metadata/file/string/file::office-document-extension--xlsx",
    "metadata/file/string/file::office-document-extension--pptx",
    "metadata/file/string/file::credential-file-extension--kdbx",
    "metadata/file/string/file::credential-file-extension--ovpn",
    "metadata/file/string/file::office-document-file-pattern--docx",
    "metadata/file/string/file::office-document-file-pattern--xlsx",
    "metadata/file/string/file::office-document-file-pattern--pptx",
    "metadata/file/string/file::credential-file-pattern--kdbx",
    "metadata/file/string/file::credential-file-pattern--psafe3",
    "metadata/file/string/file::credential-file-pattern--ovpn",
    "metadata/file/string/file::office-document-extension",
    "metadata/file/string/file::credential-file-extension",
    "metadata/file/string/file::office-document-file-pattern",
    "metadata/file/string/file::credential-file-pattern",
    "metadata/file/string/file::jvm-dot-cmd-suffix",
    "metadata/file/string/file::jvm-dot-out-suffix",
    "metadata/file/string/file::jvm-active-server-log-name",
    "metadata/file/string/file::jvm-rotated-server-log-prefix",
    "metadata/file/string/file::jvm-derby-log-path",
    "metadata/file/string/file::quoted-lib-path-component",
    "metadata/file/string/file::shell-scripts-dir-context",
    "metadata/file/string/file::shell-benchmark-script-basename",
    "metadata/file/string/file::linux-vmlinux-header-basename",
    "metadata/file/string/file::wine-include-source-path",
    "metadata/file/string/file::wine-lib-archive-member",
    "metadata/file/string/file::token-read-text-reference",
    "metadata/file/string/file::tmp",
    "metadata/file/string/file::manifest-json-filename",
    "metadata/file/string/file::content-js-filename",
    "metadata/file/string/file::error-log-filename",
    "metadata/file/string/file::config-header-filename",
    "metadata/file/string/file::scr-extension-string",
    "metadata/file/string/file::tmpfile-tar-filename",
    "metadata/file/string/file::configuration-word",
    "metadata/file/string/file::desktop-ini-filename",
    "metadata/file/string/file::mscorsvc-dll-filename",
    "metadata/file/string/form-validation::upgrade-required-message",
    "metadata/file/string/form-validation::required-keys-update-string",
    "metadata/file/string/form-validation::required-element-string",
    "metadata/file/string/graphics::opengl-library-token",
    "metadata/file/string/graphics::graphics-backend-tokens",
    "metadata/file/string/graphics::mesa-namespace-fragment",
    "metadata/file/string/graphics::vulkan-text-section-reference",
    "metadata/file/string/graphics::vulkan-rdata-reference",
    "metadata/file/string/graphics::graphics-runtime-library-name",
    "metadata/file/string/graphics::dri-directory-reference",
    "metadata/file/string/graphics::dri-driver-tokens",
    "metadata/file/string/graphics::dri-reference",
    "metadata/file/string/identity::android-aid-platform-marker",
    "metadata/file/string/identity::android-data-app-path",
    "metadata/file/string/identity::android-system-runtime-path",
    "metadata/file/string/identity::android-vendor-runtime-path",
    "metadata/file/string/identity::android-apex-runtime-path",
    "metadata/file/string/identity::android-property-platform-marker",
    "metadata/file/string/identity::android-getprop-platform-marker",
    "metadata/file/string/identity::android-lib-platform-marker",
    "metadata/file/string/identity::android-java-platform-marker",
    "metadata/file/string/identity::android-framework-java-import",
    "metadata/file/string/identity::android-system-path-marker",
    "metadata/file/string/identity::arch-64bit-string",
    "metadata/file/string/identity::multi-architecture-name-set--arm-mips",
    "metadata/file/string/identity::multi-architecture-name-set--other",
    "metadata/file/string/identity::multi-architecture-name-set",
    "metadata/file/string/identity::crackme-string",
    "metadata/file/string/identity::xmrig-product",
    "metadata/file/string/identity::developer-frank-string",
    "metadata/file/string/identity::developer-email-source-harvest--rx-6",
    "metadata/file/string/identity::developer-email-source-harvest--rx-7",
    "metadata/file/string/identity::filename-gvoffoqi",
    "metadata/file/string/identity::fortios-automation-results-placeholder",
    "metadata/file/string/identity::corporate-hostname-word-computer",
    "metadata/file/string/identity::corporate-hostname-word-internal",
    "metadata/file/string/identity::hostname-marker-word-corp",
    "metadata/file/string/identity::hostname-marker-word-fqdn",
    "metadata/file/string/identity::jvm-post-token",
    "metadata/file/string/identity::jvm-activate-constant",
    "metadata/file/string/identity::python3-interpreter-basename",
    "metadata/file/string/identity::chrome-sandbox-basename",
    "metadata/file/string/identity::chrome-crashpad-handler-basename",
    "metadata/file/string/identity::node-pty-native-basename",
    "metadata/file/string/identity::bpf-tool-basename",
    "metadata/file/string/identity::kernel-module-basename",
    "metadata/file/string/identity::pkgbuild-basename",
    "metadata/file/string/identity::jfif-or-jpeg-media-marker",
    "metadata/file/string/identity::cuckoo-typeface-name-token",
    "metadata/file/string/identity::pattern-rules-catalog",
    "metadata/file/string/identity::client-uuid-label",
    "metadata/file/string/identity::code-snippet-identifier",
    "metadata/file/string/identity::flags-identifier",
    "metadata/file/string/identity::applescript-hidden-entry-snippet-path",
    "metadata/file/string/identity::applescript-hidden-entry-secret",
    "metadata/file/string/identity::applescript-hidden-entry-snippet",
    "metadata/file/string/identity::abbreviated-curl-bash-reference",
    "metadata/file/string/identity::cli-posix-shell-common-token",
    "metadata/file/string/identity::cli-posix-shell-alternate-token",
    "metadata/file/string/identity::cli-windows-shell-token",
    "metadata/file/string/identity::argv-posix-shell-common-token",
    "metadata/file/string/identity::argv-posix-shell-alternate-token",
    "metadata/file/string/identity::argv-windows-shell-token",
    "metadata/file/string/identity::hostname-field-token",
    "metadata/file/string/identity::babel-script-mime-type",
    "metadata/file/string/identity::userinfo-token",
    "metadata/file/string/identity::chunk-token",
    "metadata/file/string/identity::source-text-token",
    "metadata/file/string/identity::system-shell-basename",
    "metadata/file/string/identity::shell-loadable-builtin-path",
    "metadata/file/string/identity::freedos-program-basename",
    "metadata/file/string/identity::microsoft-vcredist-context",
    "metadata/file/string/identity::executable-manifest-reference",
    "metadata/file/string/identity::is-windows-named",
    "metadata/file/string/limit::per-page-option-text",
    "metadata/file/string/limit::max-length-63-assignment",
    "metadata/file/string/network/port::port-2375-reference",
    "metadata/file/string/network/port::port-2376-reference",
    "metadata/file/string/network/port::docker-near-2375-text",
    "metadata/file/string/network/port::c-common-service-port-array",
    "metadata/file/string/network/port::ports-2375-and-2376",
    "metadata/file/string/process-name::mobilestored-daemon",
    "metadata/file/string/process-name::backboardd-daemon",
    "metadata/file/string/process-name::lockdownd-daemon",
    "metadata/file/string/process-name::smartd-name",
    "metadata/file/string/process-name::qmgr-name",
    "metadata/file/string/process-name::zabbix-agentd-name",
    "metadata/file/string/process-name::crond-name",
    "metadata/file/string/process-name::xinetd-name",
    "metadata/file/string/process-name::inetd-name",
    "metadata/file/string/process-name::named-name",
    "metadata/file/string/process-name::telnetd-name",
    "metadata/file/string/process-name::telnet-client-name",
    "metadata/file/string/process-name::springboard-daemon",
    "metadata/file/string/process-name::launchd-daemon",
    "metadata/file/string/process-name::configd-daemon",
    "metadata/file/string/process-name::wifid-daemon",
    "metadata/file/string/process-name::securityd-daemon",
    "metadata/file/string/process-name::usereventagent-daemon",
    "metadata/file/string/process-name::native-database-service-names",
    "metadata/file/string/process-name::httpd-name",
    "metadata/file/string/process-name::nginx-name",
    "metadata/file/string/process-name::apache-name",
    "metadata/file/string/process-name::mysql-name",
    "metadata/file/string/process-name::postgres-name",
    "metadata/file/string/process-name::redis-name",
    "metadata/file/string/process-name::mongod-name",
    "metadata/file/string/process-name::tomcat-name",
    "metadata/file/string/process-name::jboss-name",
    "metadata/file/string/process-name::weblogic-name",
    "metadata/file/string/process-name::source-kworker-name-literal",
    "metadata/file/string/process-name::search-filter-host-exe-reference",
    "metadata/file/string/process-name::search-protocol-host-exe-reference",
    "metadata/file/string/process-name::runtime-broker-exe-reference",
    "metadata/file/string/process-name::svchost-exe-reference",
    "metadata/file/string/process-name::windows-system-process-name-reference",
    "metadata/file/string/process-name::system-process-core-name",
    "metadata/file/string/process-name::updater-exe-name",
    "metadata/file/string/process-name::calc-exe-name",
    "metadata/file/string/process-name::notepad-exe-name",
    "metadata/file/string/process-name::iexplore-exe-name",
    "metadata/file/string/security::domain-intel-text",
    "metadata/file/string/security::rot13-reversed-back-connect-label",
    "metadata/file/string/security::rot13-reversed-bind-port-label",
    "metadata/file/string/security::native-rop-format-primitives",
    "metadata/file/string/security::privileged-json-field-text",
    "metadata/file/string/security::privileged-option-text",
    "metadata/file/string/security::privileged-assignment-text",
    "metadata/file/string/security::privileged-field-text",
    "metadata/file/string/security::port-network-scanning-phrase",
    "metadata/file/string/security::scanning-port-target-phrase",
    "metadata/file/string/security::malware-term-in-comment",
    "metadata/file/string/security::backdoor-term-in-comment",
    "metadata/file/string/security::evasion-term-in-comment",
    "metadata/file/string/security::evade-term-in-comment",
    "metadata/file/string/security::malicious-software-term-in-comment",
    "metadata/file/string/security::evasion-term-in-comment-any",
    "metadata/file/string/security::version-target-identifier",
    "metadata/file/string/security::version-service-identifier",
    "metadata/file/string/security::version-scan-identifier",
    "metadata/file/string/security::target-version-identifier",
    "metadata/file/string/security::service-version-identifier",
    "metadata/file/string/security::scan-version-identifier",
    "metadata/file/string/security::cve-identifier",
    "metadata/file/string/security::sqli-acronym",
    "metadata/file/string/security::nosqli-acronym",
    "metadata/file/string/security::xss-acronym",
    "metadata/file/string/security::ssrf-acronym",
    "metadata/file/string/security::lfi-acronym",
    "metadata/file/string/security::rce-acronym",
    "metadata/file/string/security::malicious-traffic-or-payload-phrase",
    "metadata/file/string/security::injection-attack-class-acronyms",
    "metadata/file/string/security::server-attack-class-acronyms",
    "metadata/file/string/security::yara-x-engine-marker",
    "metadata/file/string/security::yara-x-go-module",
    "metadata/file/string/telemetry::telemetry-context-telemetry",
    "metadata/file/string/telemetry::telemetry-context-analytics",
    "metadata/file/string/telemetry::telemetry-context-identify",
    "metadata/file/string/telemetry::browser-identity-field",
    "metadata/file/string/telemetry::network-address-profile-field",
    "metadata/file/string/telemetry::country-profile-field",
    "metadata/file/string/telemetry::geolocation-profile-field",
    "metadata/file/string/telemetry::region-profile-field",
    "metadata/file/string/telemetry::os-profile-field",
    "metadata/file/string/telemetry::platform-profile-field",
    "metadata/file/string/telemetry::extension-os-profile-fields",
    "metadata/file/string/telemetry::extension-runtime-identity-fields",
    "metadata/file/string/telemetry::telemetry-context-markers",
    "metadata/file/string/telemetry::telemetry-user-identity-fields",
    "metadata/file/string/telemetry::geo-system-profile-field",
    "metadata/file/string/telemetry::device-id-field",
    "metadata/file/string/telemetry::device-id-field-python",
    "metadata/file/string/telemetry::os-info-field",
    "metadata/file/string/telemetry::repeated-analytics-term",
    "metadata/file/string/telemetry::repeated-counter-term",
    "metadata/file/string/telemetry::repeated-stats-term",
    "metadata/file/string/telemetry::repeated-track-substring",
    "metadata/file/string/telemetry::session-id-field-js",
    "metadata/file/string/telemetry::device-id-field-js",
    "metadata/file/string/telemetry::repeated-tracking-vocabulary",
    "metadata/file/string/telemetry::clear-all-logs-symbol",
    "metadata/file/string/telemetry::beacon-word",
];

/// Reject any new rule definition under the legacy `metadata/file/string/`
/// namespace, including additions to already-established source directories.
/// References to grandfathered IDs remain valid while their definitions move.
#[must_use]
pub(crate) fn find_new_metadata_file_string_ids(rule_ids: &[String]) -> Vec<String> {
    let mut violations: Vec<String> = rule_ids
        .iter()
        .filter(|id| {
            (id.starts_with("metadata/file/string/") || id.starts_with("metadata/file/string::"))
                && !LEGACY_METADATA_FILE_STRING_IDS.contains(&id.as_str())
        })
        .cloned()
        .collect();
    violations.sort();
    violations.dedup();
    violations
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

        for (segment_index, window) in segments.windows(2).enumerate() {
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

                // Product names naturally begin with their category noun (DataEase,
                // MediaForge, BrowserStack, `lint/linter`, `debug/debugpy`). Exact and
                // plural duplicates above still apply at this boundary; only
                // prefix-abbreviation matching does not.
                //
                // `>= 2` rather than `== 2`: a category may carry a grouping layer
                // (`tool/development/lint/…`), which puts the product one level
                // deeper without changing why its name echoes the category.
                if segments.first() == Some(&"well-known") && segment_index >= 2 {
                    continue;
                }

                // Check short abbreviations: "exec"/"execution", "cred"/"credential-access".
                // A fully spelled category may naturally recur in a product name,
                // such as well-known/app/browser/browserstack.
                let (shorter, longer) = if parent.len() <= child.len() {
                    (&parent, &child)
                } else {
                    (&child, &parent)
                };
                // A child that repeats its parent verbatim and then qualifies it
                // -- `clipboard/clipboard-write`, `registry/registry-run-key` --
                // stutters at any length: the path already said the noun, so the
                // child should carry only what it adds (`clipboard/write`). The
                // separator is what distinguishes this from a name that merely
                // starts with the same letters (`browser/browserstack`), which is
                // why the length-limited prefix rule below cannot see it.
                let restates_parent = longer.starts_with(&format!("{shorter}-"));
                if (restates_parent || shorter.len() <= 5) && longer.starts_with(shorter) {
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

/// Sibling directories whose names say the same thing twice.
///
/// Siblings answer one question, so two names built from one stem are usually
/// that answer written twice. Two shapes carry the signal:
///
/// * **a refinement filed as a sibling** -- `encrypt/` beside `encrypt-dotnet/`,
///   `script/` beside `script-dropper/`. The longer name spells the shorter one
///   and then qualifies it, which is what a *child* is: it belongs under what it
///   refines, not next to it. The separator is the discriminator -- without it,
///   `cloud`/`cloudflare` and `libev`/`libevent` are coincidences, not restatements.
/// * **two word-forms of one noun** -- `header`/`headers`, `check`/`checks`,
///   `encode`/`encoded`, `resolve`/`resolver`. Nothing distinguishes them, so
///   traits land in whichever the author saw first and both fill up.
///
/// Only same-parent siblings are compared, and `well-known/` is exempt: it names
/// products, and a family legitimately shares a stem (`boto`/`boto3`).
///
/// Returns: `Vec<(parent, shorter, longer)>`
#[must_use]
pub(crate) fn find_sibling_name_restatement(
    trait_dirs: &[String],
) -> Vec<(String, String, String)> {
    // Gerunds can name a different subject (account versus accounting), so
    // compare plural/tense endings only.
    const WORD_FORMS: &[&str] = &["s", "es", "d", "ed", "r", "er"];

    let mut by_parent: HashMap<&str, Vec<&str>> = HashMap::new();
    for dir in trait_dirs {
        if let Some(idx) = dir.rfind('/') {
            by_parent
                .entry(&dir[..idx])
                .or_default()
                .push(&dir[idx + 1..]);
        }
    }

    let mut out = Vec::new();
    for (parent, mut names) in by_parent {
        if parent.starts_with("well-known") {
            continue;
        }
        names.sort_unstable();
        names.dedup();
        for i in 0..names.len() {
            for j in (i + 1)..names.len() {
                let (short, long) = if names[i].len() <= names[j].len() {
                    (names[i], names[j])
                } else {
                    (names[j], names[i])
                };
                if short.len() < 4 {
                    continue;
                }
                let restates = long.starts_with(&format!("{short}-"))
                    || long
                        .strip_prefix(short)
                        .is_some_and(|tail| WORD_FORMS.contains(&tail));
                if restates {
                    out.push((parent.to_string(), short.to_string(), long.to_string()));
                }
            }
        }
    }
    out.sort();
    out
}

/// Find directories with too many rules (suggests need for subdirectories).
/// Atomic traits and composite rules are counted together.
///
/// Returns: `Vec<(directory_path, rule_count)>`
#[must_use]
pub(crate) fn find_oversized_trait_directories(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<(String, usize)> {
    // Count rules per directory (extract directory from the rule ID)
    let mut dir_counts: HashMap<&str, usize> = HashMap::new();

    let ids = trait_definitions
        .iter()
        .map(|t| t.id.as_str())
        .chain(composite_rules.iter().map(|r| r.id.as_str()));
    for id in ids {
        // Everything before `::`, else before the last `/`
        let dir = match id.find("::").or_else(|| id.rfind('/')) {
            Some(idx) => &id[..idx],
            None => continue, // No directory prefix
        };

        *dir_counts.entry(dir).or_insert(0) += 1;
    }

    let mut violations: Vec<_> = dir_counts
        .into_iter()
        .filter(|(_, count)| *count > MAX_TRAITS_PER_DIRECTORY)
        .map(|(dir, count)| (dir.to_string(), count))
        .collect();

    violations.sort_by_key(|v| std::cmp::Reverse(v.1)); // Sort by count descending
    violations
}

/// Find directories whose immediate subdirectories exceed
/// [`MAX_SUBDIRECTORIES_PER_DIRECTORY`] and need another grouping layer.
///
/// `trait_dirs` holds the directories that directly contain traits; every
/// ancestor level is derived from those paths, so a wide level is caught
/// wherever it sits in the tree.
///
/// Returns: `Vec<(directory_path, subdirectory_count)>`, widest first.
#[must_use]
pub(crate) fn find_wide_trait_directories(trait_dirs: &[String]) -> Vec<(String, usize)> {
    // Map each ancestor path to the set of its immediate child segments.
    let mut children: HashMap<&str, HashSet<&str>> = HashMap::new();
    for dir in trait_dirs {
        for (sep, _) in dir.match_indices('/') {
            let rest = &dir[sep + 1..];
            let child = rest.split('/').next().unwrap_or(rest);
            children.entry(&dir[..sep]).or_default().insert(child);
        }
    }

    let mut violations: Vec<(String, usize)> = children
        .into_iter()
        .filter(|(_, kids)| kids.len() > MAX_SUBDIRECTORIES_PER_DIRECTORY)
        .map(|(dir, kids)| (dir.to_string(), kids.len()))
        .collect();

    // Widest first, then lexicographic so the report is stable run to run.
    violations.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
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
    "forensics",
    "media",
    "packaging",
    "offensive",
    "reverse-engineering",
    "sysadmin",
];

/// Allowed second-level categories under `well-known/dual-use/`.
const WELL_KNOWN_DUAL_USE_CATEGORIES: &[&str] = &[
    "access-control",
    "credentials",
    "tunnel",
    "packaging",
    "remote-admin",
    "transfer",
];

const WELL_KNOWN_APP_CATEGORIES: &[&str] = &[
    "ai",
    "browser",
    "browser-extension",
    "communication",
    "publishing",
    "data",
    "development",
    "enterprise",
    "finance",
    "infrastructure",
    "media",
    "network",
    "productivity",
    "security",
    "storage",
    "system",
    "utility",
];

const WELL_KNOWN_LIB_CATEGORIES: &[&str] = &[
    "ai",
    "cloud",
    "crypto",
    "data",
    "development",
    "format",
    "media",
    "network",
    "observability",
    "platform",
    "runtime",
    "native",
    "ui",
    "web",
    "concurrency",
    "datetime",
    "stdlib",
    "vendor-sdk",
    "testing",
];

/// Allowed top-level categories under `well-known/`.
///
/// Kept in sync with `ALLOWED_WELL_KNOWN` in directory_whitelist.rs. Anything outside
/// this set is reported by the directory whitelist; this list is reused here to scope
/// second-level subcategory checks.
const WELL_KNOWN_TOP_LEVEL: &[&str] = &[
    "malware", "unwanted", "dual-use", "tool", "app", "lib", "game",
];

/// Validate that well-known/<category>/ only contains whitelisted second-level
/// subcategories where one is defined (malware/, dual-use/, app/, lib/, and tool/).
/// The game/ and unwanted/ buckets have no fixed subcategory list and are ignored here.
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
            "dual-use" => (WELL_KNOWN_DUAL_USE_CATEGORIES, parts[2]),
            "app" => (WELL_KNOWN_APP_CATEGORIES, parts[2]),
            "lib" => (WELL_KNOWN_LIB_CATEGORIES, parts[2]),
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

/// Four or more platform declarations warrant review, not rejection.
/// Platform count alone cannot distinguish an overbroad API rule from a
/// format-defined fact that legitimately holds on every supported OS. Never
/// force duplicate matchers or taxonomy relocation to satisfy this heuristic.
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
/// for one grammar, or for a pair that shares a grammar shape. A type-qualified allowlist entry
/// (`"text:<dir-prefix>"`) only lifts the cap for that one matcher type.
const BROAD_FILETYPE_THRESHOLD_PATH: usize = 4; // full-path matchers — start tight; whitelist/narrow case-by-case
// Content-scan caps (text/metrics/encoded) include the macOS-native types
// (applescript/plist/swift/objectivec) that ride into a group expansion now
// that the `unix` umbrella reaches macOS (see resolve_platform_filetype_conflicts).
// They also cover the complete generated manifest and archive families, including
// mirc and ircii in the scripts group. These are the family widths, not arbitrary
// exceptions for individual traits: adding a supported format must not make the
// shipped taxonomy unloadable.
const BROAD_FILETYPE_THRESHOLD_TEXT: usize = 33; // text / literal / comment
const BROAD_FILETYPE_THRESHOLD_METRICS: usize = 25; // whole-file metrics
// A basename matches the *filename*, which is artifact-specific — a filename
// pattern that fires across many languages is almost always mis-scoped. Kept
// deliberately tight (mirrors PATH): narrow `for:` to the type(s) the filename
// implies, or add a `basename:<dir>` allowlist entry for the rare exception.
const BROAD_FILETYPE_THRESHOLD_BASENAME: usize = 7; // filename patterns
const BROAD_FILETYPE_THRESHOLD_ENCODED: usize = 13; // decoded-content scan
const BROAD_FILETYPE_THRESHOLD_SECTION: usize = 8; // binary section names
const BROAD_FILETYPE_THRESHOLD_YARA: usize = 4; // yara rules (may span container formats)
const BROAD_FILETYPE_THRESHOLD_SYMBOL: usize = 7; // symbol / syscall tables
const BROAD_FILETYPE_THRESHOLD_VALUE: usize = 6; // structural value paths
const BROAD_FILETYPE_THRESHOLD_RAW: usize = 3; // raw byte scan — native binary family (elf/macho/pe)
const BROAD_FILETYPE_THRESHOLD_HEX: usize = 3; // hex byte pattern — native binary family (elf/macho/pe)
// Tree-sitter node types are grammar-specific, so a query is written against a
// specific grammar. Two is the width of the one pairing that genuinely shares a
// grammar shape (javascript/typescript); past that the query cannot compile for
// every type it claims (see the `ast-query-compile` validator).
const BROAD_FILETYPE_THRESHOLD_AST: usize = 2; // tree-sitter (one grammar, or a js/ts pair)

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
    // A declared digest label and hexadecimal value has the same meaning in
    // bootstrap source and manifests. Preserve its existing scope when the
    // declaration moves from hash operations to integrity metadata.
    "text:metadata/package/integrity/digest-value.yaml",
    // The file's own directory components have the same meaning across
    // content formats. Preserve the original scope when this neutral path
    // observations move to naming metadata; their matchers scan no body.
    "path:metadata/file/naming/directory-components.yaml",
    // Browser SQL schemas are shared by source and compiled carriers. These
    // bounded query matchers require specific columns and tables in any format.
    "text:micro-behaviors/data/db/access/chromium-queries.yaml",
    // Referenced application/product names can occur in source, binaries,
    // manifests and embedded markup. Preserve that coverage when name markers
    // move out of artifact/library or objective-keyword categories. This only
    // affects text matcher scope, never the combined per-directory rule cap.
    "text:micro-behaviors/os/application/target/",
    // `media.*` is one fact namespace shared by every passive container that
    // can carry a payload — font, png, jpeg, wav, aiff, mp3, mp4, ico, gif,
    // bmp, webp. The namespace exists precisely so a carrier rule is written
    // once instead of eleven times, and the value paths it reads are emitted
    // only for those types, so breadth here is the design rather than a
    // missing filter. Splitting the rules per format to satisfy the cap would
    // duplicate the same matcher eleven times, which the near-duplicate check
    // rejects anyway.
    "value:metadata/file/format/media/",
    // DOS INT 21h service sequences are the same 16-bit code wherever the
    // infector body sits: a .COM, an untyped dump (`data`), a `.a`-named copy
    // (`static-lib`), or a batch/COM polyglot. Per-type twins of one hex
    // pattern are what the scope-twin check rejects, so the cap yields here.
    "hex:objectives/impact/infect/binary/dos/interrupt/",
    // Preserve the same four carriers when the neutral find-next opcode
    // moves out of infection objectives. This exact source-file exception
    // does not broaden the remaining filesystem-search rules.
    "hex:micro-behaviors/fs/search/dos-find-next.yaml",
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
    "text:micro-behaviors/communications/http/header/",
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
    "text:objectives/command-and-control/dropper/delivery/execute-download/",
    "text:objectives/command-and-control/dropper/delivery/hidden-stage/",
    // The decoded form of the same dropper one-liner. These match the *decoded*
    // string corpus, so the host language is whatever happened to carry the
    // blob: the identical payload has been observed in a Gradle Kotlin task, an
    // Xcode build setting, a Makefile recipe, `build.rs`, and `setup.py`. The
    // encoding is what travels between build systems, so narrowing `for:` here
    // drops whole ecosystems rather than trimming a matcher — the file type is
    // not a property of the technique.
    "encoded:micro-behaviors/communications/http/download/encoded/",
    // Stacked-encoding rules match on the recovered *chain* (`base64+base64`),
    // which is a property of the wrapping and not of the file that carries it.
    // The same doubly-wrapped payload turns up in a git hook, a Makefile recipe
    // and an Xcode build setting, so a narrow `for:` here would scope a rule by
    // the one thing the technique is indifferent to.
    "encoded:micro-behaviors/data/decode/multiple-encoding/",
    // Hardcoded C2 URL string literals (IP-pinned URLs, .php panel endpoints)
    // appear in any source language — same rationale as communications/url/.
    // The directory's -encoded and -binary legs are already narrowly scoped.
    "text:micro-behaviors/communications/http/url/",
    // Cross-language file text/format properties (license headers, text
    // profiles, catalog strings, generic string identities) appear broadly.
    "text:metadata/file/catalog/",
    "text:metadata/file/format/",
    "text:metadata/file/profile/",
    "text:metadata/lang/natural/",
    "text:metadata/lang/locale/",
    "text:metadata/file/string/",
    "text:metadata/file/extension/",
    "text:micro-behaviors/data/encoded/",
    "text:micro-behaviors/data/format/media/",
    "text:micro-behaviors/data/runtime/keywords/",
    "text:micro-behaviors/communications/http/keywords/",
    "text:micro-behaviors/data/parse/vocabulary/",
    "text:micro-behaviors/ui/window/notify/keywords-terms.yaml",
    "text:objectives/command-and-control/backdoor/keywords/",
    "text:objectives/command-and-control/botnet/keywords/",
    "text:objectives/command-and-control/backdoor/rat/keywords/",
    "text:objectives/command-and-control/remote-command/keywords/",
    "text:objectives/command-and-control/remote-command/llm/",
    "text:objectives/exfiltration/stealer/surveillance/",
    "text:objectives/evasion/kernel-hide/keywords/",
    "text:objectives/evasion/indicator-removal/keywords/",
    "text:objectives/evasion/security-bypass/edr/",
    "text:objectives/evasion/security-bypass/llm/",
    "text:objectives/impact/crypto-manipulation/keywords/",
    "text:objectives/impact/destroy/keywords/",
    // Natural-language destructive tasking can be embedded in any source or
    // script language; objective composites require an unattended agent with
    // tool-permission bypass before assigning hostile intent.
    "text:objectives/impact/destroy/agent-directed/",
    "text:objectives/impact/dos/keywords/",
    "text:objectives/impact/ransom/keywords/",
    "text:objectives/privilege-escalation/exploit/keywords/",
    "text:micro-behaviors/hardware/input/keyboard/label/",
    "text:well-known/tool/detection/",
    // The rickroll delimiter moved here when `trojan/family` was split up: a
    // joke token used as a field separator is a packer property, not a family.
    "text:objectives/anti-static/obfuscation/string/delimiter/",
    "text:well-known/tool/offensive/payload-corpus/",
    // Marking a file executable (chmod +x / mode 0o755) is a delivery step that
    // appears across every script, source language, and manifest that drops and
    // launches a payload — so the chmod-executable atoms scan broadly.
    "text:micro-behaviors/fs/chmod/executable/",
    // "Code generated … DO NOT EDIT" markers appear in generated code of every language.
    "text:metadata/lang/generated/generated.yaml",
    // The Racket language classifier matches `#lang racket` to identify the
    // language of otherwise-unknown files, so it must scan broadly.
    "text:metadata/lang/scripted/racket.yaml",
    // Cryptographic vocabulary (ciphertext, shared secret, key-material labels)
    // appears in crypto implementations of every language.
    "text:micro-behaviors/crypto/",
    // C2 messaging-channel indicators (e.g. Discord webhook URLs) are string
    // markers embedded in malware written in any language.
    "text:objectives/command-and-control/channel/messaging/",
    // String *literals* (parser-extracted) for the same cross-language content
    // classes allowlisted for `text:` above: a hardcoded C2 IP/port, URL,
    // credential path, or text marker is written as a quoted literal in source
    // of every language. Same cross-language rationale, different matcher type.
    "literal:micro-behaviors/communications/ip/",
    "literal:micro-behaviors/communications/http/url/",
    "literal:objectives/command-and-control/infrastructure/",
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
    "path:metadata/package/testing/presence/path/",
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

/// Reviewed directory contracts where OS-independent evidence may declare
/// `platforms: [all]`. Permission is not an assertion that every rule in a
/// directory is portable: OS-specific observations still need explicit scopes.
/// Keep this list synchronized with TAXONOMY.md's platform scope contracts.
pub(crate) const ALL_PLATFORM_DIRECTORY_ALLOWLIST: &[&str] = &[
    // Package text/resource facts retain their meaning on every target OS.
    "metadata/package/description/disclosure",
    "metadata/package/documentation/claims",
    "metadata/package/documentation/security-advisory",
    "metadata/package/documentation/source",
    // Scanned filenames and naming measurements are OS-independent properties.
    // OS-specific filename rules still require their own explicit platform scope.
    "metadata/file/naming",
    // Transparent test-indication profiles defer all target-OS and file-type
    // filtering to their referenced metadata/name observations. The OR itself
    // means the same on every OS; it asserts neither purpose nor portability.
    "metadata/file/profile/test-indications",
    // Publication/custody/history describe the registry record, not execution.
    "metadata/registry",
    // Host syntax and spelling do not depend on the OS consuming a URL.
    "micro-behaviors/communications/url/host",
];

fn all_platform_directory_allowed(id: &str) -> bool {
    let Some((directory, _)) = id.split_once("::") else {
        return false;
    };
    ALL_PLATFORM_DIRECTORY_ALLOWLIST.iter().any(|allowed| {
        directory == *allowed
            || directory
                .strip_prefix(allowed)
                .is_some_and(|suffix| suffix.starts_with('/'))
    })
}

/// Review `all` on both atoms and composites, including inherited defaults.
/// Match canonical directory IDs with segment boundaries; source filenames and
/// arbitrary path substrings cannot grant permission.
#[must_use]
pub(crate) fn find_all_platform_rules_outside_allowlist(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut violations: Vec<_> = trait_definitions
        .iter()
        .map(|t| (&t.id, &t.platforms))
        .chain(composite_rules.iter().map(|r| (&r.id, &r.platforms)))
        .filter(|(id, platforms)| {
            platforms.contains(&Platform::All) && !all_platform_directory_allowed(id)
        })
        .map(|(id, _)| {
            (
                id.clone(),
                rule_source_files
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string()),
            )
        })
        .collect();
    violations.sort();
    violations
}

/// Returns the count of explicitly selected platforms for a trait.
/// `Platform::All` is reviewed separately against the directory allowlist.
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

/// Reviewed enumerated scopes, not permission to use `all`. Match the exact
/// atom and platform set; changed scopes return to review. In particular neither
/// wireless configuration nor Swift Foundation is supported on z/OS by these
/// observations. Source-language and matcher changes still receive their normal
/// file-type, duplicate, and condition validation.
const REVIEWED_BROAD_PLATFORM_SCOPES: &[(&str, &[Platform])] = &[
    (
        "micro-behaviors/fs/read/file/full::swift-direct-file-read-api",
        &[
            Platform::Ios,
            Platform::MacOS,
            Platform::Linux,
            Platform::Windows,
        ],
    ),
    (
        "micro-behaviors/fs/read/file/full::swift-data-file-read",
        &[
            Platform::Ios,
            Platform::MacOS,
            Platform::Linux,
            Platform::Windows,
        ],
    ),
    (
        "micro-behaviors/hardware/wireless/network::wifi-ssid-identifier",
        &[
            Platform::Windows,
            Platform::Linux,
            Platform::MacOS,
            Platform::Android,
            Platform::Ios,
        ],
    ),
    (
        "micro-behaviors/hardware/wireless/network::wifi-password-key",
        &[
            Platform::Windows,
            Platform::Linux,
            Platform::MacOS,
            Platform::Android,
            Platform::Ios,
        ],
    ),
];

fn has_reviewed_platform_scope(t: &TraitDefinition) -> bool {
    REVIEWED_BROAD_PLATFORM_SCOPES
        .iter()
        .any(|(id, platforms)| {
            t.id == *id
                && t.platforms.len() == platforms.len()
                && platforms
                    .iter()
                    .all(|platform| t.platforms.contains(platform))
        })
}

/// Find atomic traits whose platform breadth deserves a soft warning.
///
/// Enumerated scopes are reviewed uniformly across tiers. `all` is checked by
/// `find_all_platform_rules_outside_allowlist` for both atoms and composites.
#[must_use]
pub(crate) fn find_broad_platform_traits(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, usize)> {
    let mut candidates: Vec<_> = trait_definitions
        .iter()
        .filter(|t| {
            !t.platforms.contains(&Platform::All)
                && effective_platform_count(&t.platforms) >= BROAD_PLATFORM_THRESHOLD
                && !has_reviewed_platform_scope(t)
        })
        .map(|t| {
            let source = rule_source_files
                .get(&t.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            (t.id.clone(), source, effective_platform_count(&t.platforms))
        })
        .collect();
    candidates.sort();
    candidates
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

/// Find [`BROAD_FILETYPE_ALLOWLIST`] entries that no longer match any trait.
///
/// Entries are matched by directory *prefix*, so renaming or retiring a
/// directory silently strips its exemption: the entry stops matching, every
/// trait it covered starts failing the cap, and nothing points at the entry as
/// the cause. The failure surfaces far from the rename, as a pile of unrelated
/// cap violations.
///
/// An entry matching nothing is either that mistake or a leftover from a
/// directory that is gone. Either way it is dead text pretending to be a
/// policy, so say so.
#[must_use]
pub(crate) fn find_stale_filetype_allowlist_entries(
    rule_source_files: &HashMap<String, String>,
) -> Vec<&'static str> {
    BROAD_FILETYPE_ALLOWLIST
        .iter()
        .filter(|entry| {
            let Some((_, prefix)) = entry.split_once(':') else {
                // A malformed entry can never match; report it too.
                return true;
            };
            !rule_source_files.values().any(|src| src.contains(prefix))
        })
        .copied()
        .collect()
}

#[cfg(test)]
mod media_filetype_allowance_tests {
    use super::{TraitDefinition, find_broad_filetype_traits};
    use std::collections::HashMap;

    #[test]
    fn relocated_media_allowance_stays_matcher_and_directory_scoped() -> anyhow::Result<()> {
        let value: TraitDefinition = serde_yaml::from_str(
            "id: carrier\ndesc: Container signature\ncrit: baseline\nconf: 0.9\nfor: [jpeg, png, svg, wav, aiff, mp3, mp4, ico, gif, bmp, webp, font]\nif:\n  type: value\n  path: media.container\n",
        )?;
        assert_eq!(value.r#for.len(), 12);
        for (path, permitted) in [
            ("/traits/metadata/file/format/media/container.yaml", true),
            (
                "/traits/metadata/file/format/media-extra/container.yaml",
                false,
            ),
            ("/traits/metadata/file/format/structured/traits.yaml", false),
        ] {
            let sources = HashMap::from([(value.id.clone(), path.to_string())]);
            assert_eq!(
                find_broad_filetype_traits(std::slice::from_ref(&value), &sources).is_empty(),
                permitted,
                "{path}"
            );
        }
        let mut raw = value.clone();
        raw.r#if = serde_yaml::from_str("type: raw\nsubstr: RIFF\n")?;
        let sources = HashMap::from([(
            raw.id.clone(),
            "/traits/metadata/file/format/media/container.yaml".to_string(),
        )]);
        assert_eq!(find_broad_filetype_traits(&[raw], &sources).len(), 1);
        Ok(())
    }
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

/// Find well-known/ traits that identify a family by registry metadata alone.
///
/// Two shapes, both blocklist rows rather than signatures:
///
/// * A `value` match on `version` / `npm.version`, anywhere under `well-known/`.
///   It asks only "is this release numbered X", which every package in the
///   registry can answer, so the trait fires on unrelated software that happens
///   to share a version string -- `1.0.0` alone matches every `npm init -y`
///   scaffold and every first publish. The finding still carries the family's
///   name, so innocent software gets reported as that malware.
/// * A `value` match on `name` / `npm.name` under `well-known/malware/supply-chain/`.
///   Naming the package says which artifact was published, not what it did.
///   The tier is for infamous, behaviour-characterised campaigns -- the ones an
///   engineer recognises by technique -- and a per-package name list is the
///   opposite of that. Outside the malware tier a package name *is* a
///   legitimate identity (that is how `well-known/lib/.../jquery` works), so the
///   name check is deliberately limited to the supply-chain malware directory.
///
/// Pinning a known-bad release is real work; it belongs in dependency/advisory
/// analysis, which resolves name and version together and is updated
/// continuously. A trait earns its place by describing behaviour that survives
/// a rename or a repack.
///
/// Binding the name *and* version inside one matcher (a `text` regex over the
/// manifest) is unaffected: such a matcher cannot fire on a different package.
///
/// Returns `Vec<(trait_id, source_file)>` for violations.
#[must_use]
pub(crate) fn find_wellknown_version_path_traits(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    trait_definitions
        .iter()
        .filter(|t| {
            if extract_trait_tier(&t.id) != "well-known" {
                return false;
            }
            let in_supply_chain = t.id.starts_with("well-known/malware/supply-chain");
            condition_keys_on_registry_identity(&t.r#if, in_supply_chain)
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

/// True when a condition selects a bare registry-identity path.
///
/// Matches the key itself (`version`, `npm.name`, …) and the same key reached
/// through a sibling-file prefix (`package.json::version`), while leaving
/// compound paths such as `versions.1_0_0.dist` alone -- those address a
/// specific release record rather than asking what this artifact is called.
fn condition_keys_on_registry_identity(cond: &Condition, include_name: bool) -> bool {
    match cond {
        Condition::Kv(KvQuery { path, .. }) => {
            let key = path.rsplit("::").next().unwrap_or(path).trim();
            matches!(key, "version" | "npm.version")
                || (include_name && matches!(key, "name" | "npm.name"))
        }
        _ => false,
    }
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

/// Find section-claiming binary metadata traits without a section filter.
///
/// Whole-file vocabulary and provenance are valid regardless of which section
/// contains the bytes. A location claim under `metadata/binary/section/` is
/// different: its evidence must be restricted to that section.
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
            (t.id.starts_with("metadata/binary/section/")
                || t.id.starts_with("metadata/binary/section::"))
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

#[cfg(test)]
mod metadata_file_string_tests {
    use super::find_new_metadata_file_string_ids;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn allows_existing_legacy_definitions_and_nonlegacy_ids() {
        let input = ids(&[
            "metadata/file/string/account::first-name-field",
            "metadata/file/string/charset::standard-base64-alphabet-text",
            "metadata/file/string/network/port::docker-near-2375-text",
            "micro-behaviors/communications/http/string::header-reference",
        ]);
        assert!(find_new_metadata_file_string_ids(&input).is_empty());
    }

    #[test]
    fn rejects_new_ids_inside_legacy_leaves_and_new_leaves() {
        let input = ids(&[
            // Adding a rule to an established source leaf is still forbidden.
            "metadata/file/string/account::new-account-string",
            // Creating a new taxonomy leaf is forbidden too.
            "metadata/file/string/software::new-software-name",
            "metadata/file/string/account/credentials::new-secret-label",
            "micro-behaviors/data/string/replace",
            "objectives/credential-access/theft/keywords",
        ]);
        assert_eq!(
            find_new_metadata_file_string_ids(&input),
            vec![
                "metadata/file/string/account/credentials::new-secret-label".to_string(),
                "metadata/file/string/account::new-account-string".to_string(),
                "metadata/file/string/software::new-software-name".to_string(),
            ]
        );
    }
}

#[cfg(test)]
mod parent_duplicate_tests {
    use super::find_parent_duplicate_segments;

    fn dirs(v: &[&str]) -> Vec<String> {
        v.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn flags_exact_plural_and_short_abbreviation_duplicates() {
        let input = dirs(&[
            "micro-behaviors/execution/execution",
            "objectives/credential/credentials",
            "micro-behaviors/process/exec/execution",
        ]);
        assert_eq!(find_parent_duplicate_segments(&input).len(), 3);
    }

    #[test]
    fn allows_full_category_word_in_specific_product_name() {
        let input = dirs(&[
            "well-known/app/browser/browserstack",
            "well-known/app/network/networkmanager",
            "well-known/app/data/dataease",
            "well-known/lib/data/datalevin",
            "well-known/app/media/mediaforge",
        ]);
        assert!(find_parent_duplicate_segments(&input).is_empty());
    }
}

/// Find trait directories whose path segments are the same set in a different
/// order — `fs/write/file/direct` beside `fs/file/write/direct`.
///
/// Independent dimensions (the action, the thing acted on, the manner) have no
/// inherent order, so nesting them lets the same subject be filed two ways.
/// Nobody notices, because each path reads correctly on its own; the traits
/// then diverge in two places that no duplicate check compares, since their
/// matchers are genuinely different. Naming the collision is the only cheap
/// way to catch it — see the orthogonality rule in TAXONOMY.md.
///
/// Returns `(path_a, path_b)` pairs, each reported once.
#[must_use]
pub(crate) fn find_permuted_directory_paths(trait_dirs: &[String]) -> Vec<(String, String)> {
    use std::collections::{BTreeSet, HashMap};

    let mut by_segments: HashMap<BTreeSet<&str>, Vec<&String>> = HashMap::new();
    for dir in trait_dirs {
        let segments: BTreeSet<&str> = dir.split('/').collect();
        // A one-segment path cannot be a permutation of anything else.
        if segments.len() < 2 {
            continue;
        }
        by_segments.entry(segments).or_default().push(dir);
    }

    let mut out = Vec::new();
    for (_, mut paths) in by_segments {
        if paths.len() < 2 {
            continue;
        }
        paths.sort();
        for (i, a) in paths.iter().enumerate() {
            for b in &paths[i + 1..] {
                out.push(((*a).clone(), (*b).clone()));
            }
        }
    }
    out.sort();
    out
}
