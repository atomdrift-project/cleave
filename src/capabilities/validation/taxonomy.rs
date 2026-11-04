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

/// Maximum atomic traits and composite rules combined in any directory.
/// Every directory uses the same limit; there are no path-specific budgets.
pub(crate) const MAX_TRAITS_PER_DIRECTORY: usize = 93;

/// Baseline findings are too broad to represent a named entity. Components are
/// still allowed when they are incomplete evidence for an identity.
#[must_use]
pub(crate) fn find_wellknown_baseline_rules(
    traits: &[TraitDefinition],
    composites: &[CompositeTrait],
    sources: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut violations: Vec<_> = traits
        .iter()
        .map(|r| (&r.id, r.crit))
        .chain(composites.iter().map(|r| (&r.id, r.crit)))
        .filter(|(id, crit)| id.starts_with("well-known/") && *crit == Criticality::Baseline)
        .map(|(id, _)| {
            (
                id.clone(),
                sources
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string()),
            )
        })
        .collect();
    violations.sort_unstable();
    violations
}

/// A basename fact observes the scanned name, not the identity of its owner.
fn is_basename_fact(trait_def: &TraitDefinition) -> bool {
    matches!(&trait_def.r#if, Condition::Path(query) if query.basename && !query.dirname)
}

/// A filename alone cannot establish suspicious or hostile identity.
#[must_use]
pub(crate) fn find_wellknown_high_criticality_basenames(
    traits: &[TraitDefinition],
    sources: &HashMap<String, String>,
) -> Vec<(String, String)> {
    let mut violations: Vec<_> = traits
        .iter()
        .filter(|t| {
            t.id.starts_with("well-known/") && t.crit > Criticality::Notable && is_basename_fact(t)
        })
        .map(|t| {
            (
                t.id.clone(),
                sources
                    .get(&t.id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string()),
            )
        })
        .collect();
    violations.sort_unstable();
    violations
}

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

/// Group directories' subtree rule counts by parent, for the sibling-cohort
/// checks. Only `micro-behaviors/` and `objectives/` are considered, and the
/// tier plus first category layer are skipped: they are too broad to be useful
/// as local organization advice.
fn sibling_cohorts(
    direct_rule_counts: &HashMap<String, usize>,
) -> HashMap<String, Vec<(String, usize)>> {
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
            if parent.split('/').count() < 3 {
                continue;
            }
            children_by_parent
                .entry(parent.to_string())
                .or_default()
                .push((child.to_string(), *count));
        }
    }
    children_by_parent
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
#[cfg(test)]
pub(crate) fn find_sparse_sibling_cohorts(
    direct_rule_counts: &HashMap<String, usize>,
) -> Vec<(String, usize, usize)> {
    const SPARSE_SIBLING_RULE_THRESHOLD: usize = 35;

    let mut candidates = Vec::new();
    for (parent, children) in sibling_cohorts(direct_rule_counts) {
        if children.len() < 2 {
            continue;
        }
        let sibling_rules: usize = children.iter().map(|(_, count)| count).sum();
        if sibling_rules < SPARSE_SIBLING_RULE_THRESHOLD {
            candidates.push((parent, sibling_rules, children.len()));
        }
    }
    candidates.sort_by(|a, b| (a.1, &a.0).cmp(&(b.1, &b.0)));
    candidates
}

/// Find parents with many child directories that are sparse on average.
/// Ten branches indicate a broad directory taxonomy, and an average of eight
/// rules or fewer per branch merits review for needless fragmentation. This
/// is a review signal only: distinct techniques remain separate. Returns
/// `(parent, children, total_rules, average_rules)`, lowest average first.
#[must_use]
pub(crate) fn find_fragmented_sibling_cohorts(
    direct_rule_counts: &HashMap<String, usize>,
) -> Vec<(String, usize, usize, f64)> {
    const MIN_CHILDREN: usize = 10;
    const MAX_AVERAGE_RULES: f64 = 8.0;
    let mut candidates = Vec::new();
    for (parent, children) in sibling_cohorts(direct_rule_counts) {
        if children.len() < MIN_CHILDREN {
            continue;
        }
        let rules: usize = children.iter().map(|(_, count)| count).sum();
        let average = rules as f64 / children.len() as f64;
        if average <= MAX_AVERAGE_RULES {
            candidates.push((parent, children.len(), rules, average));
        }
    }
    candidates.sort_by(|a, b| a.3.total_cmp(&b.3).then_with(|| a.0.cmp(&b.0)));
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

/// Reject definitions under the retired `metadata/file/string/` namespace.
#[must_use]
pub(crate) fn find_new_metadata_file_string_ids(rule_ids: &[String]) -> Vec<String> {
    let mut violations: Vec<String> = rule_ids
        .iter()
        .filter(|id| {
            id.starts_with("metadata/file/string/") || id.starts_with("metadata/file/string::")
        })
        .cloned()
        .collect();
    violations.sort();
    violations.dedup();
    violations
}

/// Reject definitions under the retired `metadata/file/literal` namespace.
#[must_use]
pub(crate) fn find_new_metadata_file_literal_ids(rule_ids: &[String]) -> Vec<String> {
    let mut violations: Vec<String> = rule_ids
        .iter()
        .filter(|id| {
            id.starts_with("metadata/file/literal/") || id.starts_with("metadata/file/literal::")
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
                // Cross-cutting file profiles combine network and process evidence;
                // the general network profile retains other network observations.
                let distinct_cross_cutting_profile = parent == "metadata/file/profile"
                    && short == "network"
                    && long == "network-process";
                // Request-driven execution and captured command output are
                // distinct evidence groups; both need leaf YAML directories.
                let distinct_webshell_output = parent
                    == "objectives/command-and-control/backdoor/webshell/request"
                    && short == "command"
                    && long == "command-output";
                // Hidden target files are a reviewed cross-cutting refinement;
                // the broad fetch leaf retains chains without that requirement.
                let distinct_hidden_fetch = parent
                    == "objectives/execution/payload/file-exec/command"
                    && short == "fetch"
                    && long == "fetch-hidden";
                // User-level systemd services have a distinct persistence scope;
                // the general leaf holds system-wide or unscoped service evidence.
                let distinct_systemd_user = parent == "objectives/persistence/system/service"
                    && short == "systemd"
                    && long == "systemd-user";
                if restates
                    && !distinct_systemd_user
                    && !distinct_cross_cutting_profile
                    && !distinct_webshell_output
                    && !distinct_hidden_fetch
                {
                    out.push((parent.to_string(), short.to_string(), long.to_string()));
                }
            }
        }
    }
    out.sort();
    out
}

#[cfg(test)]
#[test]
fn hidden_fetch_sibling_exception_is_specific_to_the_reviewed_pair() {
    let dirs = [
        "objectives/execution/payload/file-exec/command/fetch",
        "objectives/execution/payload/file-exec/command/fetch-hidden",
        "objectives/execution/payload/file-exec/command/fetch-other",
        "other/command/fetch",
        "other/command/fetch-hidden",
    ]
    .map(str::to_string);
    let findings = find_sibling_name_restatement(&dirs);
    assert!(!findings.contains(&(
        "objectives/execution/payload/file-exec/command".into(),
        "fetch".into(),
        "fetch-hidden".into(),
    )));
    assert!(findings.contains(&(
        "objectives/execution/payload/file-exec/command".into(),
        "fetch".into(),
        "fetch-other".into(),
    )));
    assert!(findings.contains(&(
        "other/command".into(),
        "fetch".into(),
        "fetch-hidden".into(),
    )));
}

#[cfg(test)]
#[test]
fn network_process_profile_is_a_specific_sibling_exception() {
    let dirs = [
        "metadata/file/profile/network",
        "metadata/file/profile/network-process",
        "metadata/file/profile/network-other",
        "other/profile/network",
        "other/profile/network-process",
        "objectives/command-and-control/backdoor/webshell/request/command",
        "objectives/command-and-control/backdoor/webshell/request/command-output",
        "other/request/command",
        "other/request/command-output",
    ]
    .map(str::to_string);
    let findings = find_sibling_name_restatement(&dirs);
    assert!(!findings.contains(&(
        "metadata/file/profile".into(),
        "network".into(),
        "network-process".into()
    )));
    assert!(findings.contains(&(
        "metadata/file/profile".into(),
        "network".into(),
        "network-other".into()
    )));
    assert!(findings.contains(&(
        "other/profile".into(),
        "network".into(),
        "network-process".into()
    )));
    assert!(!findings.contains(&(
        "objectives/command-and-control/backdoor/webshell/request".into(),
        "command".into(),
        "command-output".into()
    )));
    assert!(findings.contains(&(
        "other/request".into(),
        "command".into(),
        "command-output".into()
    )));
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

/// Count physical source directories as well as ID namespaces. Explicitly
/// qualified IDs can otherwise hide an oversized source directory.
pub(crate) fn find_oversized_source_directories(
    sources: &HashMap<String, String>,
    root: &std::path::Path,
) -> Vec<(String, usize)> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for source in sources.values() {
        let path = std::path::Path::new(source);
        let relative = path.strip_prefix(root).unwrap_or(path);
        if let Some(parent) = relative.parent() {
            let name = parent
                .to_string_lossy()
                .trim_start_matches("./")
                .to_string();
            *counts.entry(name).or_default() += 1;
        }
    }
    let mut out: Vec<_> = counts
        .into_iter()
        .filter(|(_, count)| *count > MAX_TRAITS_PER_DIRECTORY)
        .collect();
    out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    out
}

#[cfg(test)]
#[test]
fn physical_directory_budget_counts_qualified_ids() {
    // The qualified IDs all name `well-known/example`, yet the rules live in
    // one physical directory, which is what the budget counts.
    let sources = |n: usize| -> HashMap<String, String> {
        (0..n)
            .map(|i| {
                (
                    format!("well-known/example::rule-{i}"),
                    "./well-known/example/identity/rules.yaml".to_string(),
                )
            })
            .collect()
    };
    let root = std::path::Path::new(".");
    assert!(find_oversized_source_directories(&sources(MAX_TRAITS_PER_DIRECTORY), root).is_empty());
    assert_eq!(
        find_oversized_source_directories(&sources(MAX_TRAITS_PER_DIRECTORY + 1), root),
        vec![(
            "well-known/example/identity".to_string(),
            MAX_TRAITS_PER_DIRECTORY + 1
        )]
    );
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
    // Plex's plugin route is a neutral text reference in every original carrier.
    "text:well-known/app/media/plex/network-function-route.yaml",
    // Raw GitHub URL references apply across source, script, and binary
    // carriers; retain the reviewed scope for this file's text matchers.
    "text:well-known/app/development/code-forge/github/raw.yaml",
    // This literal configuration value is evidence in source and binaries.
    "text:micro-behaviors/communications/socket/port/credential-keyword-review-traits.yaml",
    // These two neutral service-domain references retain the reviewed cross-format
    // scope of the original shared observation, including supported archives.
    "text:well-known/app/storage/filen/cloud-url-references.yaml",
    "text:well-known/app/storage/koofr/cloud-url-references.yaml",
    // An abbreviated command is documentation in every original carrier,
    // including embedded document text. Consolidation must retain that union.
    "text:metadata/package/documentation/source/review-identity-shell-examples.yaml",
    // Directory-shaped references occur across source, script, and binary
    // carriers. Preserve the scope of this single neutral path observation.
    "text:metadata/path/directory/storage-default-reference.yaml",
    // Scanner identifier and rule names are also quoted in security documentation.
    "text:metadata/lang/source/naming/security/query-review-scanner-types-detection-security-scanner-traits.yaml",
    // Shared XOR AST productions are portable across the explicitly scoped
    // grammars. Lua exponentiation and other grammars are excluded; Swift has
    // its own production. One canonical predicate avoids per-language copies.
    "tree-sitter:micro-behaviors/data/bitwise/xor-forms/expression/xor-split-parsed-xor.yaml",
    // Normalized call names describe the same XOR-named helper observation
    // across script/source frontends, without claiming a particular algorithm.
    "symbol:micro-behaviors/data/bitwise/xor-forms/expression/xor-split-parsed-xor.yaml",
    // Named-call references use the normalized call-symbol namespace across
    // script frontends. The printenv reference currently matches 13 script
    // types; narrowing it to seven would discard existing call facts. This
    // exact-file exception applies only to symbol matchers, and changes no
    // parsing, decoding, match predicates, or runtime behavior.
    "symbol:micro-behaviors/os/env/enumerate/enumeration-query.yaml",
    // A declared digest label and hexadecimal value has the same meaning in
    // bootstrap source and manifests. Preserve its existing scope when the
    // declaration moves from hash operations to integrity metadata.
    "text:metadata/package/integrity/digest-value.yaml",
    // The file's own directory components have the same meaning across
    // content formats. Preserve the original scope when this neutral path
    // observations move to naming metadata; their matchers scan no body.
    "path:metadata/path/directory/directory-components.yaml",
    "path:metadata/path/software/directory-components.yaml",
    // Browser SQL schemas are shared by source and compiled carriers. These
    // bounded query matchers require specific columns and tables in any format.
    "text:micro-behaviors/data/db/access/chromium-queries.yaml",
    // The same carrier-independent SQL predicates, relocated to the read operation.
    "text:micro-behaviors/data/db/read/column/migration-read-review-access-chromium-queries.yaml",
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
    // Parsed embedded-PHP call relationships are shared across the same
    // passive carriers. Replacing the former text scan with these values
    // must not discard audio/font carriers or duplicate rules per format.
    // Keep this exception on the reviewed file and value matcher only.
    "value:micro-behaviors/data/embedded/payload/media/php-command-input.yaml",
    // GIF byte-zero magic has the same meaning under a GIF, PHP/ASP, or
    // mistyped source identity. The canonical hex matcher must retain all
    // original header consumers without relying on extracted text offsets.
    "hex:metadata/file/magic/identity/gif.yaml",
    // Opening PHP tags are byte delimiters, including when a newline makes
    // the tag too short for a media string extractor. Only this reviewed
    // marker file may scan the original bytes across passive carriers.
    "raw:micro-behaviors/data/embedded/payload/media/php.yaml",
    // DOS INT 21h service sequences are the same 16-bit code wherever the
    // infector body sits: a .COM, an untyped dump (`data`), a `.a`-named copy
    // (`static-lib`), or a batch/COM polyglot. Per-type twins of one hex
    // pattern are what the scope-twin check rejects, so the cap yields here.
    "hex:objectives/impact/infect/binary/dos/interrupt/",
    // Preserve the same four carriers when the neutral find-next opcode
    // moves out of infection objectives. This exact source-file exception
    // does not broaden the remaining filesystem-search rules.
    "hex:micro-behaviors/fs/search/command/dos-find-next.yaml",
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
    // Recursive configuration values retain their meaning across source and binary carriers.
    // Preserve the former service-leaf scope after moving this generic option to its subject.
    "text:micro-behaviors/data/config/syntax/recursive-option.yaml",
    // IMDS credential-header constants are independent of the source/binary carrier.
    "text:micro-behaviors/communications/http/token-auth/aws-imds-headers.yaml",
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
    // Ordered character alphabets can occur in source or compiled artifacts.
    "text:metadata/lang/encoding/shape/alphabet/review-literal-charset.yaml",
    "text:metadata/lang/natural/",
    "text:metadata/lang/locale/",
    "text:metadata/file/extension/",
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
    "text:objectives/evasion/kernel-hide/keywords/",
    "text:objectives/evasion/indicator-removal/keywords/",
    "text:objectives/evasion/security-bypass/edr/",
    "text:objectives/evasion/security-bypass/llm/",
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
    // Preserve the reviewed cross-carrier scope of this PHP upload URL literal.
    "literal:micro-behaviors/communications/url/http-path/resource/php-upload-url-reference.yaml",
    "literal:micro-behaviors/communications/http/url/",
    "literal:objectives/command-and-control/infrastructure/",
    "literal:metadata/file/catalog/",
    "literal:metadata/file/extension/",
    "literal:metadata/file/format/",
    "literal:metadata/file/profile/",
    "literal:objectives/impact/destroy/keywords/",
    "literal:objectives/command-and-control/remote-command/llm/",
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
    "path:metadata/package/testing/presence/suite/paths.yaml",
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
    // Description claims are metadata; OS-specific rules still need explicit scopes.
    "metadata/package/description/function",
    "metadata/package/documentation/claims",
    "metadata/package/documentation/security-advisory",
    "metadata/package/documentation/source",
    // Scanned filenames and naming measurements are OS-independent properties.
    // OS-specific filename rules still require their own explicit platform scope.
    "metadata/filename",
    "metadata/path",
    // Transparent test-indication profiles defer all target-OS and file-type
    // filtering to their referenced metadata/name observations. The OR itself
    // means the same on every OS; it asserts neither purpose nor portability.
    "metadata/file/profile/test-indications",
    // Source-indication reference profiles retain each named child's OS/type
    // gate. Their OR asserts no execution, benign intent or portability.
    "metadata/file/profile/source-indications",
    // Publication/custody/history describe the registry record, not execution.
    "metadata/registry",
    // Security-held status does not depend on the OS consuming the package.
    "objectives/supply-chain/security-hold",
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

#[cfg(test)]
#[test]
fn package_function_claim_platform_contract_is_scoped() {
    assert!(all_platform_directory_allowed(
        "metadata/package/description/function::pypi-summary-fetch-run-phrase"
    ));
    assert!(!all_platform_directory_allowed(
        "metadata/package/description/functionality::unreviewed"
    ));
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
        "micro-behaviors/fs/read/file/content/unspecified::swift-direct-file-read-api",
        &[
            Platform::Ios,
            Platform::MacOS,
            Platform::Linux,
            Platform::Windows,
        ],
    ),
    (
        "micro-behaviors/fs/read/file/content/unspecified::swift-data-file-read",
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

/// Match a broad-scope policy location. YAML file entries identify a complete
/// source path; directory entries retain their existing subtree behavior.
fn filetype_allowlist_source_matches(source: &str, prefix: &str) -> bool {
    if prefix.ends_with(".yaml") || prefix.ends_with(".yml") {
        source
            .strip_suffix(prefix)
            .is_some_and(|parent| parent.is_empty() || parent.ends_with('/'))
    } else {
        source.contains(prefix)
    }
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
            // One archive producer supplies the same structural member fields
            // for every container format. Scope follows that input contract,
            // not the directory where a rule happens to live. Non-archive types
            // or unrelated fact paths retain the ordinary value-query cap.
            let cap = if matches!(&t.r#if, Condition::Kv(q) if q.path.starts_with("archive."))
                && !t.r#for.is_empty()
                && t.r#for.iter().all(FileType::is_archive)
            {
                FileType::archive_family_types().len()
            } else {
                filetype_cap_for_condition(&t.r#if)
            };
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
                entry.split_once(':').is_some_and(|(ty, prefix)| {
                    ty == category && filetype_allowlist_source_matches(source, prefix)
                })
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
            !rule_source_files
                .values()
                .any(|src| filetype_allowlist_source_matches(src, prefix))
        })
        .copied()
        .collect()
}

#[cfg(test)]
mod media_filetype_allowance_tests {
    use super::{TraitDefinition, find_broad_filetype_traits};
    use std::collections::HashMap;

    #[test]
    fn gif_header_allowance_is_exact_file_and_hex_only() -> anyhow::Result<()> {
        let hex: TraitDefinition = crate::yaml::from_str(
            "id: gif-header\ndesc: GIF signature\ncrit: baseline\nconf: 0.99\nfor: [gif, php, asp, data, javascript, python]\nif:\n  type: hex\n  pattern: 47 49 46 38 (37|39) 61\n  offset: 0\n",
        )?;
        for (path, permitted) in [
            ("/traits/metadata/file/magic/identity/gif.yaml", true),
            ("/traits/metadata/file/magic/identity/gif.yaml-extra", false),
            ("/traits/metadata/file/magic/identity/traits.yaml", false),
        ] {
            let sources = HashMap::from([(hex.id.clone(), path.to_string())]);
            assert_eq!(
                find_broad_filetype_traits(std::slice::from_ref(&hex), &sources).is_empty(),
                permitted,
                "{path}"
            );
        }
        Ok(())
    }

    #[test]
    fn embedded_php_allowance_is_exact_file_and_value_only() -> anyhow::Result<()> {
        let value: TraitDefinition = crate::yaml::from_str(
            "id: request-call\ndesc: Parsed request call\ncrit: suspicious\nconf: 0.99\nfor: [jpeg, png, gif, wav, aiff, mp3, mp4, ico, webp, font]\nif:\n  type: value\n  path: media.php.request_calls[*]\n  exact: system\n",
        )?;
        for (path, permitted) in [
            (
                "/traits/micro-behaviors/data/embedded/payload/media/php-command-input.yaml",
                true,
            ),
            (
                "/traits/micro-behaviors/data/embedded/payload/media/php.yaml",
                false,
            ),
            (
                "/traits/micro-behaviors/data/embedded/payload/media/php-command-input.yaml-extra",
                false,
            ),
        ] {
            let sources = HashMap::from([(value.id.clone(), path.to_string())]);
            assert_eq!(
                find_broad_filetype_traits(std::slice::from_ref(&value), &sources).is_empty(),
                permitted,
                "{path}"
            );
        }
        let mut raw = value.clone();
        raw.r#if = crate::yaml::from_str("type: raw\nsubstr: system\n")?;
        let sources = HashMap::from([(
            raw.id.clone(),
            "/traits/micro-behaviors/data/embedded/payload/media/php-command-input.yaml"
                .to_string(),
        )]);
        assert_eq!(find_broad_filetype_traits(&[raw], &sources).len(), 1);
        Ok(())
    }

    #[test]
    fn relocated_media_allowance_stays_matcher_and_directory_scoped() -> anyhow::Result<()> {
        let value: TraitDefinition = crate::yaml::from_str(
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
        raw.r#if = crate::yaml::from_str("type: raw\nsubstr: RIFF\n")?;
        let sources = HashMap::from([(
            raw.id.clone(),
            "/traits/metadata/file/format/media/container.yaml".to_string(),
        )]);
        assert_eq!(find_broad_filetype_traits(&[raw], &sources).len(), 1);
        Ok(())
    }
}

/// Named fields and resource labels are evidence of a claim, not a verified
/// identity. Like basename facts, low-tier observations do not become more
/// accurate merely because their carrier falls within a chosen size range.
fn is_low_tier_named_binary_fact(t: &TraitDefinition) -> bool {
    if t.id.starts_with("well-known/malware/")
        || !matches!(t.crit, Criticality::Component | Criticality::Notable)
    {
        return false;
    }
    match &t.r#if {
        Condition::Kv(q) => {
            matches!(
                q.path.as_str(),
                "pe.version.company"
                    | "pe.version.product_name"
                    | "pe.version.original_filename"
                    | "pe.version.description"
                    | "pe.manifest.assembly_identity.name"
                    | "pe.signatures[0].subject"
                    | "pe.signatures[*].subject"
            ) && [q.exact.as_deref(), q.substr.as_deref(), q.regex.as_deref()]
                .iter()
                .any(|v| v.is_some_and(|s| !s.is_empty()))
        }
        Condition::Text(q) => {
            let resource_label = q.section.as_deref() == Some(".rsrc")
                && [q.exact.as_deref(), q.substr.as_deref(), q.regex.as_deref()]
                    .iter()
                    .any(|v| v.is_some_and(|s| !s.is_empty()));
            // Reviewed program-specific preference-name observation. Its
            // binary spelling can include accessor prefixes/suffixes and can
            // occur outside PE resources. It reports the name's presence,
            // not ownership or that the artifact is the Plex application.
            // Keep this allowance matcher- and identity-scoped; an arbitrary
            // binary signature still needs its normal relevance constraints.
            let plex_preference_name = t.id
                == "well-known/app/media/plex::plex-transcoder-h264-options-binary"
                && q.substr.as_deref() == Some("TranscoderH264Options")
                && q.exact.is_none()
                && q.regex.is_none()
                && q.word.is_none();
            // A named Schneider Electric product reference is an observed
            // string co-occurrence, not verified ownership of the binary.
            // Its meaning does not change with the containing file's size.
            let schneider_product_reference = t.id
                == "well-known/app/infrastructure/industrial-control/schneider-electric::industrial-product-reference"
                && q.regex.as_deref()
                    == Some(r"(?i)Schneider\s*Electric.{0,30}(Desal|Unity|SoMachine|EcoStruxure)")
                && q.exact.is_none()
                && q.substr.is_none()
                && q.word.is_none();
            // A Netscape name in a code section is a product reference, not
            // an identity claim about the binary that contains the text.
            let netscape_name_reference = t.id
                == "well-known/app/browser/netscape::netscape-name-text-reference"
                && q.regex.as_deref() == Some(r"(?i)(Netscape Navigator|Netscape Communicator)")
                && q.section.as_deref() == Some(".text")
                && q.exact.is_none()
                && q.substr.is_none()
                && q.word.is_none();
            // This product-specific route is a reference, not ownership of
            // the file, and is meaningful regardless of its size.
            let plex_network_route = t.id
                == "well-known/app/media/plex::plex-plugin-network-function-route"
                && q.regex.as_deref()
                    == Some(
                        r"com\.plexapp\.agents\.[\w.]+(/|%2[fF])function(/|%2[fF])GetResultFromNetwork",
                    )
                && q.exact.is_none()
                && q.substr.is_none()
                && q.word.is_none();
            // A name in read-only data is a reference to the utility, not
            // an ownership or execution claim, regardless of carrier size.
            let mshta_name_reference = t.id
                == "well-known/app/system/windows-mshta::mshta-exe-literal"
                && q.section.as_deref() == Some("rdata")
                && q.exact.as_deref() == Some("mshta.exe")
                && q.substr.is_none()
                && q.regex.is_none()
                && q.word.is_none();
            resource_label
                || plex_preference_name
                || plex_network_route
                || schneider_product_reference
                || netscape_name_reference
                || mshta_name_reference
        }
        _ => false,
    }
}

// These family-specific text observations have no evidence for a file-size
// range or section location. Keep the exception tied to both the ID and the
// exact matcher so that changes to either are reviewed again.
fn is_reviewed_linfeng_marker(t: &TraitDefinition) -> bool {
    let expected = match t.id.as_str() {
        "well-known/malware/botnet/linfeng::linfeng-adb-bot-marker" => {
            (Criticality::Notable, ".linfengadbbotmasterchina")
        }
        "well-known/malware/botnet/linfeng::linfeng-bot-telegram-handle" => {
            (Criticality::Component, "t.me/mrrobot764linfengsudoopsec")
        }
        _ => return false,
    };
    t.crit == expected.0
        && matches!(&t.r#if, Condition::Text(q)
            if q.substr.as_deref() == Some(expected.1)
                && q.exact.is_none() && q.regex.is_none() && q.word.is_none())
}

// RedShell's paired operator commands are a named-family observation whose
// bytes may occur in any ELF section and whose meaning is independent of size.
// The exact ID, severity and matcher keep this exception narrowly reviewable.
fn is_reviewed_redshell_injection_menu(t: &TraitDefinition) -> bool {
    t.id == "well-known/malware/backdoor/redc2::redshell-injection-menu"
        && t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.regex.as_deref() == Some(r"/redshell bin -inject <proc> <file\.bin>[\s\S]{0,220}/redshell elf -inject <pid> <file>")
                && !q.case_insensitive && q.exact.is_none() && q.substr.is_none() && q.word.is_none())
}

// These exact ShellObject markers identify encoded family strings wherever
// they occur in a PE. Their meaning does not depend on a section name.
fn is_reviewed_shellobject_marker(t: &TraitDefinition) -> bool {
    let expected = match t.id.as_str() {
        "well-known/malware/trojan/shellobject/hijack::encoded-kvic-jpg-payload-url" => {
            "9/Pz76m8vPT09L349fYAvfnvvAP8APC8+AWvp7357wSf"
        }
        "well-known/malware/trojan/shellobject/hijack::encoded-kvic-probe-path" => {
            "vAP8APC87/H8AQK97/fvnw=="
        }
        "well-known/malware/trojan/shellobject/hijack::encoded-temp-res-file-template" => {
            "0u3+8evyy8Lenw=="
        }
        _ => return false,
    };
    t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.exact.as_deref() == Some(expected)
                && q.substr.is_none() && q.regex.is_none() && q.word.is_none())
}

// These distinctive Stagecomp references are observations independent of file size.
// Tie the exception to the reviewed ID, severity and complete matcher.
fn is_reviewed_stagecomp_marker(t: &TraitDefinition) -> bool {
    let expected = match t.id.as_str() {
        "well-known/malware/backdoor/muddywater-darkcomp::stagecomp-moonzonet-domain" => {
            r"(?i)\bmoonzonet\.com\b"
        }
        "well-known/malware/backdoor/muddywater-darkcomp::stagecomp-visualwincomp-output" => {
            r"(?i)\bvisualwincomp\.txt\b"
        }
        _ => return false,
    };
    t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.regex.as_deref() == Some(expected)
                && q.exact.is_none() && q.substr.is_none() && q.word.is_none())
}

// These installer-tool observations are specific PE section, debug-path, or
// string facts. Their meaning does not change with the containing file size.
// Restrict the allowance to the reviewed ID, severity, and matcher.
fn is_reviewed_installer_tool_fact(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let (kind, expected, section) = match t.id.as_str() {
        // This exact embedded product banner is a reference, not a claim
        // about the size or section layout of its containing binary.
        "well-known/lib/runtime/scripted/python-runtime::python-launcher-banner-marker" => {
            ("whole-exact", "Python Launcher for Windows Version %ls", "")
        }
        // These are embedded product references, not identity claims about
        // the containing binary; keep their original whole-file scope.
        "well-known/app/system/sshtty::sshtty-server-crate-marker" => {
            ("whole-substr", "sshtty::server", "")
        }
        "well-known/app/system/sshtty::sshtty-terminal-banner" => (
            "whole-substr",
            "Browser terminal with groups and tabs that keeps your shells running",
            "",
        ),
        // These are product-specific path references, not claims that the
        // containing binary is the product. Preserve whole-file matching.
        "well-known/app/security/eset::eset-update-manifest-path" => {
            ("whole-regex", r"/eset_upd/[\w./-]{0,64}update\.ver\b", "")
        }
        "well-known/app/security/globalprotect::globalprotect-sslvpn-login-esp" => {
            ("whole-substr", "/ssl-vpn/login.esp", "")
        }
        "well-known/app/development/code-forge/github::github-web-raw-msi-url" => (
            "whole-regex",
            r###"https://github\.com/.{1,40}/.{1,40}/raw/.{1,40}/.{1,80}\.msi"###,
            "",
        ),
        "well-known/app/development/code-forge/github::github-web-raw-url" => (
            "whole-regex",
            r###"https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/raw/(refs/heads/)?"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-web-file" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/.{1,100}\.(html|txt|php)"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-script-file" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/.{1,100}\.(sh|py|ps1|cmd)\b"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-scripting-lang" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/.{1,100}\.(rb|pl|js)\b"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-actions-url" => (
            "whole-regex",
            r###"(?i)raw\.githubusercontent\.com/actions/"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-native-library" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/.{1,140}\.(so(\.[0-9.]+)?|dylib|dll)\b"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-msbuild-project" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/.{1,160}\.(csproj|vbproj|fsproj|sln)\b"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-image-suffix" => (
            "whole-regex",
            r###"(?i)raw\.githubusercontent\.com/[^\s"'`]{1,120}\.(png|jpe?g|gif)\b"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-any" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+/"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-refs" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/.{1,80}/refs/heads/"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-host-string" => {
            ("whole-exact", r###"raw.githubusercontent.com"###, "")
        }
        "well-known/app/development/code-forge/github::gist-githubusercontent-raw-binary-url" => (
            "whole-regex",
            r###"gist\.githubusercontent\.com/[^\s/]{1,80}/[^\s/]{1,80}/raw/"###,
            "",
        ),
        "well-known/lib/ai/tesseract::tesseract-upstream-model-url" => {
            ("whole-substr", "github.com/tesseract-ocr/tessdata", "")
        }
        "well-known/app/storage/mediafire::mediafire-download-url" => (
            "whole-regex",
            r###"mediafire\.com/(file|download)/[a-zA-Z0-9_-]{10,}"###,
            "",
        ),
        "well-known/app/productivity/zoho::zoho-service-url" => (
            "whole-regex",
            r###"https?://(www\.)?(zohoapis|workdrive\.zoho|accounts\.zoho)\.[a-z]{2,3}(\.[a-z]{2})?/"###,
            "",
        ),
        "well-known/app/productivity/zoho::zoho-service-host-reference" => (
            "whole-regex",
            r###"(?i)(^|[^\w.-])(zohoapis|(workdrive|accounts)\.zoho)\.[a-z]{2,3}(\.[a-z]{2})?([^\w.-]|$)"###,
            "",
        ),
        "well-known/app/productivity/zoho::zoho-oauth-token-url" => (
            "whole-regex",
            r###"(?i)(^|[^\w.-])accounts\.zoho\.[a-z]{2,3}(\.[a-z]{2})?/oauth/v2/token\b"###,
            "",
        ),
        "well-known/app/productivity/zoho::workdrive-zoho-host-url" => (
            "whole-regex",
            r###"https?://workdrive\.zoho\.(com|eu|in|jp|ca|sa|com\.[a-z]{2})/"###,
            "",
        ),
        "well-known/app/productivity/zoho::workdrive-zoho-api-url" => (
            "whole-regex",
            r###"https?://([a-z0-9-]+\.)?zohoapis\.(com|eu|in|jp|ca|sa|com\.[a-z]{2})/workdrive/"###,
            "",
        ),
        "well-known/app/storage/dropbox::dropbox-direct-share-url" => (
            "whole-regex",
            r###"(dl\.dropbox\.com|dl\.dropboxusercontent\.com)/s(cl)?/fi/[a-zA-Z0-9_-]{10,}"###,
            "",
        ),
        "well-known/app/storage/dropbox::dropbox-web-share-url" => (
            "whole-regex",
            r###"(www\.dropbox\.com)/s(cl)?/fi/[a-zA-Z0-9_-]{10,}"###,
            "",
        ),
        "well-known/app/storage/dropbox::dropboxusercontent-executable-url" => (
            "whole-regex",
            r###"dl\.dropboxusercontent\.com/[^\s"'<>]{1,240}\.(exe|dll|bat|ps1|msi)\b"###,
            "",
        ),
        "well-known/app/storage/dropbox::dropbox-share-executable-url" => (
            "whole-regex",
            r###"www\.dropbox\.com/s(cl)?/fi/[A-Za-z0-9_-]{10,}[^\s"'<>]{0,240}\.(exe|dll|bat|ps1|msi)\b"###,
            "",
        ),
        "well-known/app/storage/dropbox::dropbox-direct-executable-url" => (
            "whole-regex",
            r###"dl\.dropbox\.com/s(cl)?/fi/[A-Za-z0-9_-]{10,}[^\s"'<>]{0,240}\.(exe|dll|bat|ps1|msi)\b"###,
            "",
        ),
        "well-known/app/storage/dropbox::dropbox-share-url-bytecode" => (
            "whole-regex",
            r###"(dl\.dropbox|www\.dropbox)\.com/s(cl)?/fi/[a-zA-Z0-9_-]{10,}"###,
            "",
        ),
        "well-known/app/storage/google-drive::gdrive-export-download-url" => (
            "whole-regex",
            r###"(drive|docs)\.google\.com/uc\?export=download&id=[a-zA-Z0-9_-]{20,}"###,
            "",
        ),
        "well-known/app/storage/google-drive::gdrive-usercontent-download-reference" => (
            "whole-substr",
            r###"drive.usercontent.google.com/download"###,
            "",
        ),
        "well-known/app/storage/google-drive::gdrive-usercontent-host" => {
            ("whole-exact", r###"drive.usercontent.google.com"###, "")
        }
        "well-known/app/storage/google-drive::gdrive-pe-file-url" => (
            "whole-regex",
            r###"(drive|docs)\.google\.com/(uc|file/d)/[a-zA-Z0-9_-]{20,}[^\s,"'<>]{0,200}\.(exe|dll)\b"###,
            "",
        ),
        "well-known/app/storage/google-drive::gdrive-script-file-url" => (
            "whole-regex",
            r###"(drive|docs)\.google\.com/(uc|file/d)/[a-zA-Z0-9_-]{20,}[^\s,"'<>]{0,200}\.(bat|ps1)\b"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-service-host-reference" => (
            "whole-regex",
            r###"(?i)([A-Za-z0-9-]{1,64}\.oss-(cn|ap|us|eu|me)-[A-Za-z0-9-]{1,32}|oss)\.aliyuncs\.com"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-bucket-host-cn-ap" => (
            "whole-regex",
            r###"[a-z0-9-]{1,64}\.oss-(cn|ap)-[a-z0-9-]{1,32}\.aliyuncs\.com"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-bucket-host-us-eu" => (
            "whole-regex",
            r###"[a-z0-9-]{1,64}\.oss-(us|eu)-[a-z0-9-]{1,32}\.aliyuncs\.com"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-bucket-host-me" => (
            "whole-regex",
            r###"[a-z0-9-]{1,64}\.oss-(me)-[a-z0-9-]{1,32}\.aliyuncs\.com"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-executable-url-cn-ap" => (
            "whole-regex",
            r###"\.oss-(cn|ap)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(exe|dll)\b"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-script-url-cn-ap" => (
            "whole-regex",
            r###"\.oss-(cn|ap)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(bat|ps1)\b"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-executable-url-us-eu" => (
            "whole-regex",
            r###"\.oss-(us|eu)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(exe|dll)\b"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-script-url-us-eu" => (
            "whole-regex",
            r###"\.oss-(us|eu)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(bat|ps1)\b"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-executable-url-me" => (
            "whole-regex",
            r###"\.oss-(me)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(exe|dll|bat|ps1)\b"###,
            "",
        ),
        "well-known/app/storage/tencent-cos::myqcloud-domain-reference" => {
            ("whole-regex", r###"(?i)myqcloud\.com"###, "")
        }
        "well-known/app/storage/tencent-cos::tencent-cos-url" => (
            "whole-regex",
            r###"[a-z0-9-]{1,64}\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com"###,
            "",
        ),
        "well-known/app/storage/tencent-cos::cos-pe-url" => (
            "whole-regex",
            r###"\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com/.{1,200}\.(exe|dll)\b"###,
            "",
        ),
        "well-known/app/storage/tencent-cos::cos-installer-batch-url" => (
            "whole-regex",
            r###"\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com/.{1,200}\.(msi|bat)\b"###,
            "",
        ),
        "well-known/app/storage/tencent-cos::cos-powershell-url" => (
            "whole-regex",
            r###"\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com/.{1,200}\.(ps1)\b"###,
            "",
        ),
        "well-known/app/storage/tencent-cos::tencent-cos-archive-url" => (
            "whole-regex",
            r###"\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com/.{1,200}\.(zip|7z|rar)\b"###,
            "",
        ),
        "well-known/app/storage/digitalocean-spaces::spaces-domain-reference" => {
            ("whole-regex", r###"(?i)digitaloceanspaces\.com"###, "")
        }
        "well-known/app/storage/filen::filen-domain-reference" => {
            ("whole-regex", r###"(?i)\bfilen\.(io|net)\b"###, "")
        }
        "well-known/app/storage/koofr::koofr-domain-reference" => {
            ("whole-regex", r###"(?i)\bkoofr\.(eu|com)\b"###, "")
        }
        "well-known/app/storage/amazon-s3::aws-s3-url" => (
            "whole-regex",
            r###"(?i)https?://([a-z0-9-]+\.)?s3([.-][a-z0-9-]+)?\.amazonaws\.com/"###,
            "",
        ),
        "well-known/app/storage/amazon-s3::s3-bucket-uri" => (
            "whole-regex",
            r###"(?i)\bs3://[a-z0-9][a-z0-9.-]{1,62}(/|$)"###,
            "",
        ),
        "well-known/app/storage/google-cloud-storage::gcs-url" => (
            "whole-regex",
            r###"https?://storage\.googleapis\.com/[a-z0-9-_]+(/|["']|$)"###,
            "",
        ),
        "well-known/app/storage/cloudflare-r2::r2-object-endpoint" => (
            "whole-regex",
            r###"(?i)(^|[^A-Za-z0-9.-])([a-z0-9-]+\.)?r2\.cloudflarestorage\.com([^A-Za-z0-9.-]|$)"###,
            "",
        ),
        "well-known/app/storage/cloudflare-r2::cloudflare-r2-url" => (
            "whole-regex",
            r###"https?://[a-z0-9-]+\.r2\.cloudflarestorage\.com(/|["']|$)"###,
            "",
        ),
        "well-known/app/storage/cloudflare-r2::cloudflare-r2-pub-url" => {
            ("whole-regex", r###"https?://pub-[a-f0-9]+\.r2\.dev/"###, "")
        }
        "well-known/app/storage/digitalocean-spaces::do-spaces-url" => (
            "whole-regex",
            r###"https?://[a-z0-9-]+\.[a-z0-9-]+\.digitaloceanspaces\.com/"###,
            "",
        ),
        "well-known/app/storage/vultr-object-storage::vultr-object-storage-url" => (
            "whole-regex",
            r###"https?://[a-z0-9-]+\.[a-z0-9-]+\.vultrobjects\.com/"###,
            "",
        ),
        "well-known/app/storage/backblaze-b2::backblaze-b2-url" => (
            "whole-regex",
            r###"https?://[a-z0-9-]+\.backblazeb2\.com/"###,
            "",
        ),
        "well-known/app/communication/discord::discord-cdn-shell-script-url" => (
            "whole-regex",
            r##"cdn\.discordapp\.com/attachments/\d+/\d+/[^\s"'<>]{1,80}\.sh\b"##,
            "",
        ),
        "well-known/app/communication/discord::discord-cdn-download-url" => (
            "whole-regex",
            r##"(cdn|media)\.discordapp\.(com|net)/attachments/\d+/\d+/"##,
            "",
        ),
        "well-known/app/communication/discord::discord-cdn-windows-executable-url" => (
            "whole-regex",
            r##"discordapp\.com/attachments/[0-9]{15,}/[0-9]{15,}/.{1,80}\.(exe|dll|bat|ps1)\b"##,
            "",
        ),
        "well-known/app/communication/discord::discord-cdn-archive-url" => (
            "whole-regex",
            r##"discordapp\.com/attachments/[0-9]{15,}/[0-9]{15,}/.{1,80}\.(zip|7z|rar)\b"##,
            "",
        ),
        "well-known/app/storage/mega::mega-file-share-url" => (
            "whole-regex",
            r##"mega\.nz/(file/[a-zA-Z0-9_-]{8,}|#![a-zA-Z0-9_-]{8,})"##,
            "",
        ),
        "well-known/app/infrastructure/content-delivery/jsdelivr::jsdelivr-npm-script-url" => (
            "whole-regex",
            r#"cdn\.jsdelivr\.net/npm/[^"'\s]{0,160}\.js([?#"'`\s<>)\]}]|$)"#,
            "",
        ),
        "well-known/lib/platform/windows-base-api::microsoft-kernel32-version-identity" => {
            ("internal-name-exact", "kernel32", "")
        }
        "well-known/lib/platform/windows-base-api::microsoft-kernelbase-version-identity" => {
            ("internal-name-regex", r"(?i)^kernelbase(\.dll)?$", "")
        }
        "well-known/app/system/windows-sync-center::syncmgr-registry-cluster" => {
            ("substr", r"SyncMgr\Handlers", "rdata")
        }
        "well-known/app/system/windows-sync-center::syncmgr-handler-clsid" => {
            ("exact", "{F897AA24-BDC3-11d1-B85B-00C04FB93981}", "rdata")
        }
        "well-known/app/system/windows-sync-center::mobsync-pdb-path" => {
            ("pdb-inline-regex", r"(?i)(^|[\\/])mobsync\.pdb$", "")
        }
        "well-known/app/system/windows-sync-center::mobsync-version-name" => {
            ("exact", "mobsync.exe", "rdata")
        }
        "well-known/app/security/microsoft-security-essentials::msse-product-name" => {
            ("exact", "Microsoft Security Essentials", "rdata")
        }
        "well-known/lib/native/madexcept::mad-except" => ("substr", "madExcept", "CODE"),
        "well-known/lib/development/halide::halide-hexagon-remote-profiler-symbol" => (
            "export-exact",
            "halide_hexagon_remote_profiler_get_global_instance",
            "",
        ),
        "well-known/lib/development/halide::halide-library-loader-symbol" => {
            ("export-exact", "halide_load_library", "")
        }
        "well-known/lib/runtime/native-platform/qualcomm-hexagon::qdsp6-start-symbol" => {
            ("export-exact", "qdsp6_start_main", "")
        }
        "well-known/lib/runtime/native-platform/qualcomm-hexagon::hexagon-hvx-lock-symbol" => {
            ("export-exact", "qurt_hvx_lock", "")
        }
        "well-known/app/system/drivers/nvidia::nvidia-nvapi-internal-name" => {
            ("internal-name-exact", "nvapi.dll", "")
        }
        "well-known/app/system/firmware/qualcomm-xbl::qcom-xbl-bootloader-marker" => {
            ("raw-substr", "XBL_SC_MINI_CTX", "")
        }
        "well-known/lib/platform/wine::wine-debug-channel-symbol" => {
            ("symbol-regex", r"^__wine_dbg_[a-z_]{3,30}$", "")
        }
        "well-known/lib/platform/wine::wine-builtin-header-text" => {
            ("text-offset-64", "Wine builtin DLL", "")
        }
        "well-known/tool/development/toolchain/edg::edg-modules-path-env" => {
            ("word", "EDG_MODULES_PATH", "rodata")
        }
        "well-known/tool/development/toolchain/edg::edg-front-end-daemon" => {
            ("word", "EDG_FRONT_END_DAEMON", "rodata")
        }
        "well-known/tool/development/toolchain/dotnet-sdk::dotnet-ilasm-coreclr-binary" => (
            "regex",
            r"src[/\\]runtime[/\\]src[/\\]coreclr[/\\]ilasm[/\\]main\.cpp|\.NET IL Assembler version",
            ".rodata",
        ),
        "well-known/lib/platform/atl::atl-module-rtti" => (
            "regex",
            "C(AtlModule|ComModule|AtlException)@ATL@@",
            ".data",
        ),
        "well-known/lib/platform/wtl::wtl-frame-rtti" => (
            "regex",
            "C(FrameWindowImpl|AppModule|AboutDlg|MainFrame).{0,50}WTL@@",
            ".data",
        ),
        "well-known/lib/platform/mfc::mfc-ccmdtarget" => ("exact", "CCmdTarget", ".rdata"),
        "well-known/lib/platform/mfc::mfc-cwinapp" => ("exact", "CWinApp", ".rdata"),
        "well-known/lib/platform/mfc::mfc-afx-window-classes" => (
            "regex",
            "Afx(ControlBar|MDIFrame|FrameOrView|OleControl)",
            ".rdata",
        ),
        "well-known/lib/platform/mfc::mfc-symbols" => ("symbol-substr", "AfxWinMain", ""),
        "well-known/lib/ui/qt::qt-core-runtime-dll" => ("regex", r"Qt\dCore\.dll", "rdata"),
        "well-known/lib/runtime/managed/dotnet-process::dotnet-system-diagnostics-process-resource" => {
            ("substr", "FxResources.System.Diagnostics.Process", "rdata")
        }
        "well-known/lib/runtime/managed/dotnet-process::dotnet-system-diagnostics-process-pdb" => (
            "pdb-inline-regex",
            r"(?i)(^|[\\/])System\.Diagnostics\.Process\.ni\.pdb$",
            "",
        ),
        "well-known/lib/runtime/managed/jvm::jli-launch" => ("symbol-exact", "JLI_Launch", ""),
        "well-known/lib/runtime/managed/jvm::jli-cmd-to-args" => {
            ("symbol-exact", "JLI_CmdToArgs", "")
        }
        "well-known/lib/runtime/managed/jvm::jli-get-std-args" => {
            ("symbol-exact", "JLI_GetStdArgs", "")
        }
        "well-known/lib/runtime/managed/jvm::jli-init-arg-processing" => {
            ("symbol-exact", "JLI_InitArgProcessing", "")
        }
        "well-known/lib/runtime/managed/jvm::jli-mem-alloc" => ("symbol-exact", "JLI_MemAlloc", ""),
        "well-known/lib/runtime/managed/jvm::jli-report-error" => {
            ("symbol-exact", "JLI_ReportErrorMessage", "")
        }
        "well-known/tool/packaging/jsmooth::jsmooth-vm-search-order-string" => (
            "whole-substr",
            "JSmooth will now try to use the VM in the following order:",
            "",
        ),
        "well-known/tool/packaging/jsmooth::jsmooth-native-class-string" => {
            ("whole-substr", "jsmooth.Native", "")
        }
        "well-known/lib/ui/flutter::flutter-windows-dll" => {
            ("exact", "flutter_windows.dll", "rdata")
        }
        "well-known/lib/ui/flutter::flutter-assets-path" => ("exact", r"\flutter_assets", "rdata"),
        "well-known/lib/ui/flutter::flutter-desktop-engine-symbols" => {
            ("symbol-regex", "^FlutterDesktop(Engine|ViewController)", "")
        }
        "well-known/lib/ui/flutter::flutter-linux-desktop-runner" => (
            "symbol-regex",
            "^fl_(dart_project_new|view_new|plugin_registry_get_type)$",
            "",
        ),
        "well-known/app/system/windows-core-utilities::bits-service-name-reference" => {
            ("substr", "Background Intelligent Transfer Service", "rdata")
        }
        "well-known/app/media/windows-media-player::windows-media-player-name-reference" => {
            ("substr", "Microsoft Windows Media Player", "rdata")
        }
        "well-known/app/system/huawei-pc-manager::pc-manager-uninstall-guide-reference" => (
            "substr",
            r"C:\Program Files\Huawei\PCManager\UninstallGuide.exe.FriendlyAppName",
            "rdata",
        ),
        "well-known/game/steam::steam-drivers-archive-title" => {
            ("exact", "Steam Drivers Archive", "rdata")
        }
        "well-known/game/steam::steam-driver-archive-path" => {
            ("substr", "drivers/Windows10/x64/Steam", "rdata")
        }
        "well-known/app/system/mobile/tencent-mobilegamepc::tencent-mobilegamepc-registry" => {
            ("exact", r"SOFTWARE\Tencent\MobileGamePC", "rdata")
        }
        "well-known/app/system/mobile/tencent-mobilegamepc::tencent-tmarketinst-version" => {
            ("exact", "TMarketInst", "rdata")
        }
        "well-known/app/system/mobile/tencent-mobilegamepc::tencent-txmobilegamepc-marker" => {
            ("exact", "TXMobileGamePC", "rdata")
        }
        "well-known/app/system/mobile/tencent-mobilegamepc::tencent-tgbdownloader-marker" => {
            ("exact", "TGBDownloader", "rdata")
        }
        "well-known/tool/packaging/qt-installer-framework::qt-installer-framework" => {
            ("substr", "Built with Qt Installer Framework", ".rdata")
        }
        "well-known/tool/packaging/installshield::installshield-setup-runtime-marker" => (
            "substr",
            "InstallShield setup.exe (Unicode) started",
            ".rdata",
        ),
        "well-known/tool/packaging/squirrel-windows::squirrel-windows-setup-marker" => {
            ("exact", "SquirrelInstall", "rdata")
        }
        "well-known/tool/packaging/squirrel-windows::squirrel-temp-marker" => {
            ("exact", "SQUIRREL_TEMP", "rdata")
        }
        "well-known/tool/packaging/smart-install-maker::smart-install-maker-description" => {
            ("whole-substr", "Smart Install Maker", "")
        }
        "well-known/tool/packaging/nsis::nsis-first-header-specific-build-sizes" => (
            "section-hex",
            "EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74 75 11 00 00 18 27 00 00 5D 00 00 80",
            "overlay",
        ),
        "well-known/lib/platform/advanced-installer::external-ui-started-marker" => (
            "substr",
            "Advanced Installer External UI started.",
            ".rdata",
        ),
        "well-known/lib/platform/advanced-installer::bootstrapper-flag" => {
            ("exact", "AI_BOOTSTRAPPER", ".rdata")
        }
        "well-known/lib/platform/advanced-installer::caphyon-registry-root" => {
            ("exact", r"Software\Caphyon\Advanced Installer\", ".rdata")
        }
        "well-known/lib/platform/advanced-installer::prerequisite-install-marker" => {
            ("substr", "AI_InstallPrerequisite", ".rdata")
        }
        "well-known/tool/packaging/nsis-inetc::inetc-user-agent" => {
            ("exact", "NSIS_Inetc (Mozilla)", "rdata")
        }
        "well-known/tool/packaging/izpack::izpack-package-path" => {
            ("path", r"com[/\\]izforge[/\\]izpack", "")
        }
        "well-known/tool/packaging/inno-setup-runtime::inno-setup-550-data-marker" => {
            ("exact", "Inno Setup Setup Data (5.5.0)", "rdata")
        }
        "well-known/tool/packaging/inno-setup-runtime::inno-password-canary" => {
            ("exact", "sccPasswordTest", "rdata")
        }
        "well-known/tool/packaging/inno-setup-runtime::inno-setup-header-670" => (
            "hex",
            "49 6E 6E 6F 20 53 65 74 75 70 20 53 65 74 75 70 20 44 61 74 61 20 28 36 2E 37 2E 30 29",
            "",
        ),
        "well-known/tool/packaging/nsis::nsis-manifest-identity" => {
            ("manifest-regex", "(?i)^Nullsoft Install System", "")
        }
        "well-known/tool/packaging/nsis::nullsoft-install-system-text" => {
            ("substr", "Nullsoft Install System", ".text")
        }
        "well-known/tool/packaging/nsis::nullsoft-install-system-rdata" => {
            ("substr", "Nullsoft Install System", ".rdata")
        }
        "well-known/tool/packaging/nsis::nsis-error-title-rdata" => {
            ("exact", "NSIS Error", ".rdata")
        }
        "well-known/tool/packaging/nsis::nsis-error-title-data" => ("exact", "NSIS Error", ".data"),
        "well-known/tool/packaging/nsis::nsis-error-url-rdata" => {
            ("substr", "nsis.sf.net/NSIS_Error", ".rdata")
        }
        "well-known/tool/packaging/nsis::nsis-error-url-data" => {
            ("substr", "nsis.sf.net/NSIS_Error", ".data")
        }
        "well-known/tool/packaging/nsis::nsis-uac-ipc" => ("exact", "NSISUACIPC", ".rdata"),
        "well-known/tool/packaging/nsis::nullsoftinst-marker" => {
            ("exact", "NullsoftInst", ".rdata")
        }
        "well-known/tool/packaging/inno-setup-loader::inno-manifest-description" => {
            ("manifest-regex", r"(?i)^Inno Setup\s*$", "")
        }
        "well-known/tool/packaging/inno-setup-loader::inno-setup-data-marker" => {
            ("substr", r"Inno Setup Setup Data (", "rdata")
        }
        "well-known/tool/packaging/inno-setup-loader::inno-setup-data-marker-overlay" => {
            ("substr", r"Inno Setup Setup Data (", "overlay")
        }
        "well-known/tool/packaging/inno-setup-loader::inno-setup-installer-marker" => (
            "substr",
            r"This installation was built with Inno Setup.",
            "rdata",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-setup-installer-text" => {
            ("substr", r"Inno Setup Setup Data (", ".text")
        }
        "well-known/tool/packaging/inno-setup-loader::inno-setup-installer-data" => {
            ("substr", r"Inno Setup Setup Data (", ".data")
        }
        "well-known/tool/packaging/inno-setup-loader::inno-setup-built-with-comment" => (
            "substr",
            r"This installation was built with Inno Setup",
            "rdata",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-uninstaller-marker" => {
            ("exact", r"ISUNINSTALLER", ".text")
        }
        "well-known/tool/packaging/embala::embala-banner-token" => (
            "section-hex",
            "45 4D 42 41 4C 41 5F 42 41 4E 4E 45 52",
            ".rdata",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-loader-magic-legacy-120" => (
            "section-hex",
            "72 44 6C 50 74 53 30 32 87 65 56 78",
            ".rsrc",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-loader-magic-legacy-400" => (
            "section-hex",
            "72 44 6C 50 74 53 30 34 87 65 56 78",
            ".rsrc",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-loader-magic-legacy-403" => (
            "section-hex",
            "72 44 6C 50 74 53 30 35 87 65 56 78",
            ".rsrc",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-loader-magic-legacy-410" => (
            "section-hex",
            "72 44 6C 50 74 53 30 36 87 65 56 78",
            ".rsrc",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-loader-magic-legacy-416" => (
            "section-hex",
            "72 44 6C 50 74 53 30 37 87 65 56 78",
            ".rsrc",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-loader-magic-515" => (
            "section-hex",
            "72 44 6C 50 74 53 CD E6 D7 7B 0B 2A",
            ".rsrc",
        ),
        "well-known/tool/packaging/installaware::installaware-version-comment" => {
            ("version-comment-regex", r"(?i)\bInstallAware\b", "")
        }
        "well-known/tool/packaging/installaware::installaware-sfx-builder-pdb" => (
            "pdb-inline-regex",
            r"(?i)\\InstallAware\\.*\\SFXSetup\.pdb$",
            "",
        ),
        "well-known/tool/packaging/qsetup::qsetup-extraction-banner" => (
            "exact",
            "QSetup will extract files to your Temp Drive (<DRIVE>)<P>",
            "CODE",
        ),
        "well-known/tool/packaging/iexpress::wextract-assembly-name" => {
            ("substr", "Microsoft.Windows.Wextract", "rsrc")
        }
        "well-known/tool/packaging/iexpress::wextract-manifest-description" => (
            "substr",
            "<description>IExpress extraction tool</description>",
            "rsrc",
        ),
        "well-known/tool/packaging/iexpress::wextract-product-description" => {
            ("exact", "Win32 Cabinet Self-Extractor", "rsrc")
        }
        "well-known/tool/packaging/iexpress::wextract-pdb-path" => {
            ("exact", "wextract.pdb", ".rdata")
        }
        "well-known/tool/packaging/iexpress::wextract-cleanup-string" => {
            ("whole-substr", "wextract_cleanup%", "")
        }
        "well-known/tool/packaging/iexpress::wextract-internal-name" => {
            ("internal-name-regex", r"(?i)^wextract(\.exe)?$", "")
        }
        "well-known/tool/sysadmin/winrar-sfx::winrar-sfx-registry-text" => {
            ("exact", r"Software\WinRAR SFX", ".rdata")
        }
        "well-known/tool/sysadmin/7zip::7zip-fm-app-path" => (
            "exact-offset",
            r"Software\Microsoft\Windows\CurrentVersion\App Paths\7zFM.exe",
            ".rdata",
        ),
        "well-known/tool/sysadmin/7zip::7zip-installer-setup-banner" => (
            "regex",
            r"7-Zip [0-9]{1,2}\.[0-9]{2}( \(x(64|86)\))? Setup",
            ".rdata",
        ),
        "well-known/tool/sysadmin/7zip::7zip-registry-key" => {
            ("exact", r"Software\7-Zip", ".rdata")
        }
        "well-known/tool/sysadmin/7zip::7zip-shell-extension-clsid" => (
            "exact",
            r"CLSID\{23170F69-40C1-278A-1000-000100020000}",
            ".rdata",
        ),
        "well-known/tool/sysadmin/7zip::7zip-uninstall-registry-path" => (
            "exact",
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip",
            ".rdata",
        ),
        "well-known/tool/sysadmin/7zip::7zip32-runtime-dll" => {
            ("exact-offset", r"7-zip32.dll", ".rdata")
        }
        "well-known/tool/sysadmin/7zip::7zsfx-runtime-stub" => {
            ("exact-offset", r"7zS.sfx.exe", ".rdata")
        }
        "well-known/tool/packaging/wix::wixburn-section-name" => ("section", ".wixburn", ""),
        "well-known/tool/packaging/wix::wix-bundle-provider-key" => {
            ("exact", "WixBundleProviderKey", "rdata")
        }
        "well-known/tool/packaging/wix::wix-burn-runonce-token" => {
            ("exact", "burn.runonce", "rdata")
        }
        "well-known/tool/sysadmin/alzip::alzip-self-extractor-banner" => {
            ("substr", "ALZip Self-Extractor", "rsrc")
        }
        "well-known/tool/sysadmin/alzip::alzip-self-extractor-banner-packed" => {
            ("substr", "ALZip Self-Extractor", "UPX1")
        }
        "well-known/tool/sysadmin/alzip::alzip-zipsfx-marker" => ("exact", "ZIPSFX", "UPX1"),
        "well-known/tool/sysadmin/alzip::alzip-eggsfx-marker" => {
            ("regex", r"^EGGSFX(\.sfx)?$", "rsrc")
        }
        "well-known/tool/sysadmin/alzip::alzip-eggsfx-pdb" => {
            ("pdb", r"alzip-windows.*EGGSFX\.pdb$", "")
        }
        "well-known/tool/sysadmin/alzip::alzip-egg-format-class" => {
            ("substr", "EggFormatImpr", "UPX1")
        }
        "well-known/tool/sysadmin/alzip::alzip-upgrade-prompt" => (
            "substr",
            "Please upgrade ALZip to the latest version",
            "UPX1",
        ),
        _ => return false,
    };
    match &t.r#if {
        Condition::Symbol(q) => {
            (kind == "export-exact"
                && q.exact.as_deref() == Some(expected)
                && q.regex.is_none()
                && q.substr.is_none()
                && q.kind == Some(crate::composite_rules::condition::SymbolKind::Export)
                && q.is_check.is_none()
                && q.not.is_none())
                || ((kind == "symbol-regex"
                    && q.regex.as_deref() == Some(expected)
                    && q.exact.is_none()
                    && q.substr.is_none())
                    || (kind == "symbol-exact"
                        && q.exact.as_deref() == Some(expected)
                        && q.regex.is_none()
                        && q.substr.is_none())
                    || (kind == "symbol-substr"
                        && q.substr.as_deref() == Some(expected)
                        && q.exact.is_none()
                        && q.regex.is_none()))
                    && q.kind.is_none()
                    && q.is_check.is_none()
                    && q.not.is_none()
        }
        Condition::Raw(q) => {
            kind == "raw-substr"
                && q.substr.as_deref() == Some(expected)
                && q.exact.is_none()
                && q.regex.is_none()
                && q.word.is_none()
                && q.section.is_none()
                && q.offset.is_none()
                && q.offset_range == Some((0, None))
                && q.section_offset.is_none()
                && q.section_offset_range.is_none()
                && !q.case_insensitive
                && q.is_check.is_none()
                && q.not.is_none()
        }
        Condition::Path(q) => {
            kind == "path"
                && q.regex.as_deref() == Some(expected)
                && !q.case_insensitive
                && !q.basename
                && !q.dirname
                && q.exact.is_none()
                && q.substr.is_none()
                && q.is_check.is_none()
        }
        Condition::Hex(q) => {
            q.pattern == expected
                && q.offset.is_none()
                && q.not.is_none()
                && ((kind == "hex"
                    && q.offset_range == Some((800000, None))
                    && q.section.is_none())
                    || (kind == "section-hex"
                        && q.offset_range.is_none()
                        && q.section.as_deref() == Some(section)))
        }
        Condition::Section(q) => {
            kind == "section"
                && !q.case_insensitive
                && q.exact.as_deref() == Some(expected)
                && q.substr.is_none()
                && q.regex.is_none()
                && q.word.is_none()
        }
        Condition::Kv(q) => {
            if kind == "internal-name-exact" {
                return q.path == "pe.version.internal_name"
                    && q.exact.as_deref() == Some(expected)
                    && q.substr.is_none()
                    && q.regex.is_none()
                    && !q.case_insensitive;
            }
            ((kind == "pdb" && q.path == "pe.debug.pdb.path" && q.case_insensitive)
                || (kind == "manifest-regex"
                    && q.path == "pe.manifest.description"
                    && !q.case_insensitive)
                || (kind == "internal-name-regex"
                    && q.path == "pe.version.internal_name"
                    && !q.case_insensitive)
                || (kind == "version-comment-regex"
                    && q.path == "pe.version.comments"
                    && !q.case_insensitive)
                || (kind == "pdb-inline-regex"
                    && q.path == "pe.debug.pdb.path"
                    && !q.case_insensitive))
                && q.regex.as_deref() == Some(expected)
                && q.exact.is_none()
                && q.substr.is_none()
        }
        Condition::Text(q) => {
            ((matches!(
                kind,
                "whole-substr" | "whole-regex" | "whole-exact" | "text-offset-64"
            ) && q.section.is_none())
                || (!matches!(
                    kind,
                    "whole-substr" | "whole-regex" | "whole-exact" | "text-offset-64"
                ) && q.section.as_deref() == Some(section)))
                && !q.case_insensitive
                && (kind == "word" || q.word.is_none())
                && match kind {
                    "word" => {
                        q.word.as_deref() == Some(expected)
                            && q.exact.is_none()
                            && q.substr.is_none()
                            && q.regex.is_none()
                    }
                    "text-offset-64" => {
                        q.offset == Some(64)
                            && q.offset_range.is_none()
                            && q.exact.as_deref() == Some(expected)
                            && q.substr.is_none()
                            && q.regex.is_none()
                    }
                    "exact-offset" => {
                        q.offset_range == Some((6291456, None))
                            && q.offset.is_none()
                            && q.exact.as_deref() == Some(expected)
                            && q.substr.is_none()
                            && q.regex.is_none()
                    }
                    "exact" | "whole-exact" => {
                        q.exact.as_deref() == Some(expected)
                            && q.substr.is_none()
                            && q.regex.is_none()
                    }
                    "substr" | "whole-substr" => {
                        q.substr.as_deref() == Some(expected)
                            && q.exact.is_none()
                            && q.regex.is_none()
                    }
                    "regex" | "whole-regex" => {
                        q.regex.as_deref() == Some(expected)
                            && q.exact.is_none()
                            && q.substr.is_none()
                    }
                    _ => false,
                }
        }
        _ => false,
    }
}

/// Find well-known/ atomic traits targeting binaries without any file size filter.
///
/// Binary identity signatures normally need a size bound. Low-tier basename,
/// named version-field, signer-subject, and section-scoped resource facts are
/// observations, not verified identity, and need no arbitrary size range.
/// Malware, higher-criticality and unscoped binary signatures remain checked.
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
                && !(is_basename_fact(t)
                    && matches!(t.crit, Criticality::Component | Criticality::Notable))
                && !is_low_tier_named_binary_fact(t)
                && !is_reviewed_installer_tool_fact(t)
                && !is_nvidia_nvml_reference(t)
                && !is_poolpartybof_reference(t)
                && !is_mixcloud_warning_reference(t)
                && !is_minicap_path_reference(t)
                && !is_sms_provider_endpoint_reference(t)
                && !is_reviewed_dotnet_tool_name_reference(t)
                && !is_reviewed_remote_tool_reference(t)
                && !is_reviewed_nping_command_reference(t)
                && !is_reviewed_product_registry_reference(t)
                && !is_reviewed_linfeng_marker(t)
                && !is_reviewed_redshell_injection_menu(t)
                && !is_reviewed_stagecomp_marker(t)
                // The Tauri plugin string is a section-scoped product reference,
                // not an identity or a size-bounded signature of the file.
                && !(t.id == "well-known/lib/development/tauri::tauri-shell-open-plugin"
                    && t.crit == Criticality::Notable
                    && matches!(&t.r#if, Condition::Text(q)
                        if q.substr.as_deref() == Some("plugin:shell|open")
                            && q.section.as_deref() == Some(".rdata")))
                // A Go import path is provenance evidence, not a size-bounded identity.
                && t.id != "well-known/tool/detection/titus::titus-secret-scan-implementation"
                // A tool banner is a reference regardless of file size.
                && t.id != "well-known/tool/reverse-engineering/oep-finder::geta-oep-banner-marker"
                // This path names a runtime DLL; file size does not change the path.
                && !(t.id == "well-known/lib/runtime/compiled/msvc-runtime::bin64-msvcr120-path"
                    && matches!(t.crit, Criticality::Component | Criticality::Notable)
                    && matches!(&t.r#if, Condition::Path(q)
                        if q.substr.as_deref() == Some("bin64/msvcr120.dll")))
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

// Section-scoped NVIDIA library and product-name references describe what a
// binary mentions, rather than asserting the identity or size of the binary.
fn is_nvidia_nvml_reference(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let expected = match t.id.as_str() {
        "well-known/lib/runtime/native-platform/nvidia-nvml::nvml-wrapper-rust-crate" => {
            "nvml-wrapper-sys"
        }
        "well-known/lib/runtime/native-platform/nvidia-nvml::nvidia-gpu-classifier-token" => {
            "NvidiaQuadroTeslaNVSGRIDGeForceTitanV"
        }
        _ => return false,
    };
    matches!(&t.r#if, Condition::Text(q)
        if q.substr.as_deref() == Some(expected)
            && q.section.as_deref() == Some("rdata")
            && q.word.is_none() && q.exact.is_none() && q.regex.is_none())
}

// These provider URL references can appear in binaries of any size.
fn is_sms_provider_endpoint_reference(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let expected = match t.id.as_str() {
        "well-known/app/communication/weimi::weimi-cc-api" => "api.weimi.cc/",
        "well-known/app/communication/weimi::weimi-cc-admin" => "www.weimi.cc/sms.html",
        "well-known/app/communication/juhe::juhe-cn-sms-send" => "v.juhe.cn/sms/",
        _ => return false,
    };
    matches!(&t.r#if, Condition::Text(q)
        if q.substr.as_deref() == Some(expected)
            && q.word.is_none() && q.exact.is_none() && q.regex.is_none())
}

// A literal tool-name reference does not identify or bound the enclosing binary.
fn is_poolpartybof_reference(t: &TraitDefinition) -> bool {
    t.id == "well-known/tool/offensive/poolpartybof::poolparty-bof-name"
        && t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.substr.as_deref() == Some("PoolPartyBof")
                && q.word.is_none() && q.exact.is_none() && q.regex.is_none())
}

// A staged minicap path is a tool reference, not an identity or file-size claim.
fn is_minicap_path_reference(t: &TraitDefinition) -> bool {
    t.id == "well-known/tool/development/automation/minicap::android-staged-minicap-path"
        && t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.regex.as_deref() == Some(r"/data/local/tmp/minicap\b")
                && q.word.is_none() && q.exact.is_none() && q.substr.is_none())
}

// A quoted Mixcloud warning is product-related text, not a size-bounded identity.
fn is_mixcloud_warning_reference(t: &TraitDefinition) -> bool {
    t.id == "well-known/app/media/mixcloud::mixcloud-download-warning"
        && t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.substr.as_deref() == Some("IFYOUWANTTHEARTISTSTOGETPAIDDONOTDOWNLOADFROMMIXCLOUD")
                && q.word.is_none() && q.exact.is_none() && q.regex.is_none())
}

// Registry key text refers to another product, not the containing binary.
// Preserve whole-file coverage without arbitrary size or section limits.
fn is_reviewed_product_registry_reference(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let (kind, expected) = match t.id.as_str() {
        "well-known/lib/runtime/managed/java-runtime::java-runtime-home-key-reference" => {
            ("exact", r"SOFTWARE\JavaSoft\Java Runtime Environment")
        }
        "well-known/game/roblox::roblox-studio-registry-key" => (
            "regex",
            r"(?i)SOFTWARE[\\/]Roblox[\\/]RobloxStudioBrowser[\\/]roblox\.com",
        ),
        "well-known/game/steam-registry::steam-path-string" => ("substr", r"Software\Valve\Steam"),
        "well-known/app/productivity/onenote::onenote-options-other-policy-path" => (
            "exact",
            r"Software\Policies\Microsoft\Office\16.0\OneNote\Options\Other",
        ),
        "well-known/app/system/pcanywhere::pcanywhere-data-port-reference" => (
            "substr",
            r"Symantec\pcAnywhere\CurrentVersion\System\TCPIPDataPort",
        ),
        _ => return false,
    };
    matches!(&t.r#if, Condition::Text(q)
    if q.word.is_none() && match kind {
        "exact" => q.exact.as_deref() == Some(expected) && q.substr.is_none() && q.regex.is_none(),
        "substr" => q.substr.as_deref() == Some(expected) && q.exact.is_none() && q.regex.is_none(),
        "regex" => q.regex.as_deref() == Some(expected) && q.exact.is_none() && q.substr.is_none(),
        _ => false,
    })
}

// These exact Nping command references describe text inside another file.
// They do not identify the containing binary or imply a meaningful size bound.
fn is_reviewed_nping_command_reference(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let (kind, expected) = match t.id.as_str() {
        "well-known/tool/offensive/reconnaissance/nping::nping" => ("word", "nping"),
        "well-known/tool/offensive/reconnaissance/nping::source-port" => {
            ("regex", r"(?i)\bnping\b[^\r\n]{0,300}--source-port")
        }
        "well-known/tool/offensive/reconnaissance/nping::payload-data" => {
            ("regex", r"(?i)\bnping\b[^\r\n]{0,300}--data=")
        }
        _ => return false,
    };
    matches!(&t.r#if, Condition::Text(q)
    if q.exact.is_none() && q.substr.is_none()
        && match kind {
            "word" => q.word.as_deref() == Some(expected) && q.regex.is_none(),
            "regex" => q.regex.as_deref() == Some(expected) && q.word.is_none(),
            _ => false,
        })
}

// These are command and script references within another file, not claims
// about that file's own identity or size. Keep the exception matcher-specific.
fn is_reviewed_remote_tool_reference(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let expected = match t.id.as_str() {
        "well-known/tool/offensive/impacket::impacket-psexec-script-reference" => {
            r"(?i)\bpsexec\.py\b"
        }
        "well-known/tool/offensive/impacket::impacket-wmiexec-script-reference" => {
            r"(?i)(impacket[\\/]examples[\\/]wmiexec\.py|wmiexec\.py)\b"
        }
        "well-known/tool/offensive/impacket::impacket-wmiexec-target" => {
            r"(?i)\bwmiexec\.py\b[^\r\n]{0,180}@(\[[^\]\r\n]{1,40}\]|[A-Za-z0-9_.-]+)"
        }
        "well-known/tool/sysadmin/sysinternals::psexec-remote-invocation" => {
            r#"(?i)\bpsexec(64)?(\.exe)?\b[^\r\n]{0,160}\s+["']?\\\\[\w.%${}<>-]{1,80}(\s|["']|$)"#
        }
        _ => return false,
    };
    matches!(&t.r#if, Condition::Text(q)
        if q.regex.as_deref() == Some(expected)
            && q.exact.is_none() && q.substr.is_none() && q.word.is_none())
}

// These low-tier observations report named .NET Framework tools in another
// file; they do not claim that the containing binary is that tool. Restrict
// the exception to the reviewed IDs and matchers, without a file-size cutoff.
fn is_reviewed_dotnet_tool_name_reference(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let (kind, expected) = match t.id.as_str() {
        "well-known/lib/runtime/managed/dotnet-runtime::servicemodelreg-exe-name" => {
            ("regex", r"(?i)\bServiceModelReg\.exe\b")
        }
        "well-known/lib/runtime/managed/dotnet-runtime::addinprocess32-exe-name" => {
            ("regex", r"(?i)\bAddInProcess32\.exe\b")
        }
        "well-known/lib/runtime/managed/dotnet-runtime::regasm-exe-name" => {
            ("regex", r"(?i)\bRegAsm\.exe\b")
        }
        "well-known/lib/runtime/managed/dotnet-runtime::installutil-exe-name" => {
            ("regex", r"(?i)\bInstallUtil\.exe\b")
        }
        "well-known/lib/runtime/managed/dotnet-runtime::mscorsvw-exe-name" => {
            ("regex", r"(?i)\bmscorsvw\.exe\b")
        }
        "well-known/lib/runtime/managed/dotnet-runtime::msbuild-exe-name" => {
            ("word", "MSBuild.exe")
        }
        "well-known/lib/runtime/managed/dotnet-runtime::aspnet-tool-exe-name" => {
            ("regex", r"aspnet_(compiler|regiis|state|wp)\.exe")
        }
        _ => return false,
    };
    matches!(&t.r#if, Condition::Text(q)
    if q.exact.is_none() && q.substr.is_none()
        && match kind {
            "regex" => q.regex.as_deref() == Some(expected) && q.word.is_none(),
            "word" => q.word.as_deref() == Some(expected) && q.regex.is_none(),
            _ => false,
        })
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

// These named-utility text references were reviewed with whole-file scope.
// Limit each exception to the original ID, criticality and matcher.
fn is_reviewed_utility_reference(t: &TraitDefinition) -> bool {
    let (crit, kind, expected) = match t.id.as_str() {
        "well-known/app/utility/hwinfo::hwinfo-name-reference" => {
            (Criticality::Component, "regex", r"(?i)HWiNFO")
        }
        "well-known/app/network/filezilla::filezilla-name-reference" => {
            (Criticality::Component, "regex", r"(?i)FileZilla")
        }
        "well-known/tool/detection/wireshark::wireshark-name-reference" => {
            (Criticality::Component, "regex", r"(?i)Wireshark")
        }
        "well-known/app/productivity/notepad-plus-plus::notepad-plus-plus-name-reference" => {
            (Criticality::Component, "regex", r"(?i)Notepad\+\+")
        }
        "well-known/tool/sysadmin/7zip::sevenzip-setup-label-reference" => (
            Criticality::Notable,
            "regex",
            r"(?i)7-Zip\s+(Setup|Installer)",
        ),
        "well-known/tool/sysadmin/7zip::sevenzip-file-manager-label-reference" => (
            Criticality::Notable,
            "regex",
            r"(?i)7-Zip\s+(File Manager|Standalone)",
        ),
        "well-known/tool/sysadmin/7zip::sevenzip-console-label-reference" => (
            Criticality::Notable,
            "regex",
            r"(?i)7-Zip\s+(Console|Archiver)",
        ),
        "well-known/tool/sysadmin/7zip::sevenzip-extension-label-reference" => {
            (Criticality::Component, "regex", r"(?i)7-Zip\s+(Extension)")
        }
        "well-known/lib/data/sevenzipjbinding::sevenzipjbinding-package-path-reference" => {
            (Criticality::Notable, "substr", r"net/sf/sevenzipjbinding")
        }
        _ => return false,
    };
    t.crit == crit
        && matches!(&t.r#if, Condition::Text(q)
        if q.exact.is_none() && q.word.is_none()
            && match kind {
                "regex" => q.regex.as_deref() == Some(expected) && q.substr.is_none(),
                "substr" => q.substr.as_deref() == Some(expected) && q.regex.is_none(),
                _ => false,
            })
}

// Preserve whole-file matching only for these two specific star references.
fn is_reviewed_star_reference(t: &TraitDefinition) -> bool {
    let expected = match t.id.as_str() {
        "well-known/tool/sysadmin/star::star-archive-format-marker" => {
            "Extended standard tar (star 1994)"
        }
        "well-known/tool/sysadmin/star::star-default-config-marker" => "/etc/default/star",
        _ => return false,
    };
    t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.exact.as_deref() == Some(expected)
                && q.substr.is_none() && q.regex.is_none() && q.word.is_none())
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
                && !is_poolpartybof_reference(t)
                && !is_mixcloud_warning_reference(t)
                && !is_sms_provider_endpoint_reference(t)
                && !(t.id == "well-known/lib/runtime/scripted/python-runtime::python-launcher-banner-marker"
                    && is_reviewed_installer_tool_fact(t))
                && !(matches!(t.id.as_str(),
                    "well-known/app/system/sshtty::sshtty-server-crate-marker"
                    | "well-known/app/system/sshtty::sshtty-terminal-banner")
                    && is_reviewed_installer_tool_fact(t))
                // This reviewed whole-file marker must retain its original scope.
                && !(matches!(t.id.as_str(),
                    "well-known/app/development/code-forge/github::github-web-raw-msi-url"
                    | "well-known/app/development/code-forge/github::github-web-raw-url"
                    | "well-known/app/development/code-forge/github::raw-githubusercontent-web-file"
                    | "well-known/app/development/code-forge/github::raw-githubusercontent-script-file"
                    | "well-known/app/development/code-forge/github::raw-githubusercontent-scripting-lang"
                    | "well-known/app/development/code-forge/github::raw-githubusercontent-actions-url"
                    | "well-known/app/development/code-forge/github::raw-githubusercontent-native-library"
                    | "well-known/app/development/code-forge/github::raw-githubusercontent-msbuild-project"
                    | "well-known/app/development/code-forge/github::raw-githubusercontent-image-suffix"
                    | "well-known/app/development/code-forge/github::raw-githubusercontent-any"
                    | "well-known/app/development/code-forge/github::raw-githubusercontent-refs"
                    | "well-known/app/development/code-forge/github::raw-githubusercontent-host-string"
                    | "well-known/app/development/code-forge/github::gist-githubusercontent-raw-binary-url") && is_reviewed_installer_tool_fact(t))
                && !(t.id == "well-known/lib/ai/tesseract::tesseract-upstream-model-url"
                    && is_reviewed_installer_tool_fact(t))
                && !(t.id == "well-known/app/security/eset::eset-update-manifest-path"
                    && is_reviewed_installer_tool_fact(t))
                && !(matches!(t.id.as_str(),
                    "well-known/app/storage/mediafire::mediafire-download-url"
                    | "well-known/app/productivity/zoho::zoho-service-url"
                    | "well-known/app/productivity/zoho::zoho-service-host-reference"
                    | "well-known/app/productivity/zoho::zoho-oauth-token-url"
                    | "well-known/app/productivity/zoho::workdrive-zoho-host-url"
                    | "well-known/app/productivity/zoho::workdrive-zoho-api-url") && is_reviewed_installer_tool_fact(t))
                && !(matches!(t.id.as_str(),
                    "well-known/app/storage/dropbox::dropbox-direct-share-url"
                    | "well-known/app/storage/dropbox::dropbox-web-share-url"
                    | "well-known/app/storage/dropbox::dropboxusercontent-executable-url"
                    | "well-known/app/storage/dropbox::dropbox-share-executable-url"
                    | "well-known/app/storage/dropbox::dropbox-direct-executable-url"
                    | "well-known/app/storage/dropbox::dropbox-share-url-bytecode"
                    | "well-known/app/storage/google-drive::gdrive-export-download-url"
                    | "well-known/app/storage/google-drive::gdrive-usercontent-download-reference"
                    | "well-known/app/storage/google-drive::gdrive-usercontent-host"
                    | "well-known/app/storage/google-drive::gdrive-pe-file-url"
                    | "well-known/app/storage/google-drive::gdrive-script-file-url"
                    | "well-known/app/storage/alibaba-oss::oss-service-host-reference"
                    | "well-known/app/storage/alibaba-oss::oss-bucket-host-cn-ap"
                    | "well-known/app/storage/alibaba-oss::oss-bucket-host-us-eu"
                    | "well-known/app/storage/alibaba-oss::oss-bucket-host-me"
                    | "well-known/app/storage/alibaba-oss::oss-executable-url-cn-ap"
                    | "well-known/app/storage/alibaba-oss::oss-script-url-cn-ap"
                    | "well-known/app/storage/alibaba-oss::oss-executable-url-us-eu"
                    | "well-known/app/storage/alibaba-oss::oss-script-url-us-eu"
                    | "well-known/app/storage/alibaba-oss::oss-executable-url-me"
                    | "well-known/app/storage/tencent-cos::myqcloud-domain-reference"
                    | "well-known/app/storage/tencent-cos::tencent-cos-url"
                    | "well-known/app/storage/tencent-cos::cos-pe-url"
                    | "well-known/app/storage/tencent-cos::cos-installer-batch-url"
                    | "well-known/app/storage/tencent-cos::cos-powershell-url"
                    | "well-known/app/storage/tencent-cos::tencent-cos-archive-url"
                    | "well-known/app/storage/digitalocean-spaces::spaces-domain-reference"
                    | "well-known/app/storage/filen::filen-domain-reference"
                    | "well-known/app/storage/koofr::koofr-domain-reference") && is_reviewed_installer_tool_fact(t))
                && !(matches!(t.id.as_str(),
                    "well-known/app/storage/amazon-s3::aws-s3-url"
                    | "well-known/app/storage/amazon-s3::s3-bucket-uri"
                    | "well-known/app/storage/google-cloud-storage::gcs-url"
                    | "well-known/app/storage/cloudflare-r2::r2-object-endpoint"
                    | "well-known/app/storage/cloudflare-r2::cloudflare-r2-url"
                    | "well-known/app/storage/cloudflare-r2::cloudflare-r2-pub-url"
                    | "well-known/app/storage/digitalocean-spaces::do-spaces-url"
                    | "well-known/app/storage/vultr-object-storage::vultr-object-storage-url"
                    | "well-known/app/storage/backblaze-b2::backblaze-b2-url") && is_reviewed_installer_tool_fact(t))
                && !(matches!(t.id.as_str(),
                    "well-known/app/communication/discord::discord-cdn-shell-script-url"
                    | "well-known/app/communication/discord::discord-cdn-download-url"
                    | "well-known/app/communication/discord::discord-cdn-windows-executable-url"
                    | "well-known/app/communication/discord::discord-cdn-archive-url"
                    | "well-known/app/storage/mega::mega-file-share-url") && is_reviewed_installer_tool_fact(t))
                && !(t.id == "well-known/app/infrastructure/content-delivery/jsdelivr::jsdelivr-npm-script-url"
                    && is_reviewed_installer_tool_fact(t))
                && !(t.id == "well-known/app/system/firmware/qualcomm-xbl::qcom-xbl-bootloader-marker"
                    && is_reviewed_installer_tool_fact(t))
                && !(t.id == "well-known/lib/platform/wine::wine-builtin-header-text"
                    && is_reviewed_installer_tool_fact(t))
                && t.id != "well-known/app/system/adobe-acrobat-updater::adobe-acrobat-updater-text"
                // Go package paths can be emitted in different binary sections.
                && t.id != "well-known/tool/detection/titus::titus-secret-scan-implementation"
                // The GeTaOEP banner can appear in any section or overlay.
                && t.id != "well-known/tool/reverse-engineering/oep-finder::geta-oep-banner-marker"
                && !is_reviewed_linfeng_marker(t)
                && !is_reviewed_redshell_injection_menu(t)
                && !is_reviewed_shellobject_marker(t)
                && !is_reviewed_utility_reference(t)
                && !(t.id == "well-known/tool/packaging/iexpress::wextract-cleanup-string"
                    && is_reviewed_installer_tool_fact(t))
                && !(t.id == "well-known/tool/packaging/smart-install-maker::smart-install-maker-description"
                    && is_reviewed_installer_tool_fact(t))
                && !(matches!(t.id.as_str(),
                    "well-known/tool/packaging/jsmooth::jsmooth-vm-search-order-string"
                    | "well-known/tool/packaging/jsmooth::jsmooth-native-class-string")
                    && is_reviewed_installer_tool_fact(t))
                // The reviewed star format and config references can occur in
                // different binary sections; preserve their whole-file scope.
                && !is_reviewed_star_reference(t)
                && !is_reviewed_product_registry_reference(t)
                // The Edge product-name reference was reviewed as whole-file
                // text; narrowing it to a PE section would lose its consumers.
                && !(t.id == "well-known/app/browser/microsoft-edge::microsoft-edge-name"
                    && t.crit == Criticality::Notable
                    && matches!(&t.r#if, Condition::Text(q)
                        if q.substr.as_deref() == Some("Microsoft Edge")
                            && q.exact.is_none() && q.regex.is_none() && q.word.is_none()))
                // A named DLL reference can occur outside a PE section, and its
                // established consumer needs the original whole-file coverage.
                && !(t.id == "well-known/lib/runtime/managed/dotnet-runtime::mscorsvc-dll-filename"
                    && t.crit == Criticality::Notable
                    && matches!(&t.r#if, Condition::Text(q)
                        if q.substr.as_deref() == Some("mscorsvc.dll")
                            && q.exact.is_none() && q.regex.is_none() && q.word.is_none()))
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
    fn rejects_former_legacy_definitions() {
        let input = ids(&[
            "metadata/file/string/account::account-id-field",
            "metadata/file/string/account::account-last-seen-field",
            "metadata/file/string/application-name::chrome-browser-name-literal",
            "micro-behaviors/communications/http/string::header-reference",
        ]);
        let mut expected = input[..3].to_vec();
        expected.sort();
        assert_eq!(find_new_metadata_file_string_ids(&input), expected);
    }

    #[test]
    fn rejects_retired_legacy_ids() {
        let input = ids(&[
            "metadata/file/string/account::first-name-field",
            "metadata/file/string/account::last-name-field",
            "metadata/file/string/artifact::process-word-token",
            "metadata/file/string/attribution::author-banner",
            "metadata/file/string/container::poststart-str",
            "metadata/file/string/container::poststop-str",
            "metadata/file/string/container::prestart-str",
            "metadata/file/string/count::binary-strings-at-most-50",
            "metadata/file/string/count::binary-strings-one-to-five",
            "metadata/file/string/count::few-high-entropy-strings-20",
            "metadata/file/string/count::few-string-literals",
            "metadata/file/string/count::fifty-plus-url-strings",
            "metadata/file/string/count::high-entropy-strings-20",
            "metadata/file/string/count::high-entropy-strings-200",
            "metadata/file/string/count::high-entropy-strings-450-plus",
            "metadata/file/string/count::large-macho-high-entropy-string-profile",
            "metadata/file/string/count::large-macho-strings-at-most-50",
            "metadata/file/string/count::large-pe-strings-at-most-128",
            "metadata/file/string/count::string-concealment",
            "metadata/file/string/count::string-count-over-10000",
            "metadata/file/string/count::ten-plus-ip-address-strings",
            "metadata/file/string/count::twenty-plus-shell-command-strings",
            "metadata/file/string/count::vbs-many-long-tokens",
            "metadata/file/string/file::credential-file-extension--kdbx",
            "metadata/file/string/identity::jfif-or-jpeg-media-marker",
            "metadata/file/string/process-name::calc-exe-name",
            "metadata/file/string/process-name::iexplore-exe-name",
            "metadata/file/string/process-name::notepad-exe-name",
            "metadata/file/string/telemetry::device-id-field",
        ]);
        assert_eq!(find_new_metadata_file_string_ids(&input), input);
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
mod metadata_file_literal_tests {
    use super::find_new_metadata_file_literal_ids;

    fn ids(v: &[&str]) -> Vec<String> {
        v.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn rejects_former_exact_legacy_ids() {
        let input = ids(&[
            "metadata/file/literal::lex-word-reference",
            "metadata/file/literal::lowercase-alnum-alphabet",
            "metadata/file/literal::bracket-http-url-prefix",
            "metadata/file/literal::push-string-literal",
            "metadata/file/literal::bracketed-shift-string",
            "metadata/file/literal::c-256-entry-array-declaration",
            "metadata/file/literal::dns-tunnel-phrase",
            "metadata/file/literal::dns-exfil",
            "metadata/file/literal::dns-c2",
            "metadata/file/literal::dns-beacon",
            "metadata/file/literal::hex-byte-token-3f",
            "metadata/file/literal::hex-byte-token-ff",
            "metadata/file/literal::bracket-hex-zero-prefix",
            "metadata/file/literal::hex-number-text",
            "metadata/file/literal::hex-token-length-undefined-cluster",
            "metadata/file/literal::js-long-integer-array-literal",
            "metadata/file/literal::repeated-85-to-95-character-variable-strings",
            "metadata/file/literal::powershell-numeric-array-8-plus",
            "metadata/file/literal::js-numeric-array-64-plus",
            "metadata/file/literal::remote-desktop-feature-word",
            "metadata/file/literal::safety-system-phrase",
            "metadata/file/literal::search-setindex-reference",
            "metadata/file/literal::staging-key-identifier-reference",
            "metadata/file/literal::session-identifier-reference",
            "metadata/file/literal::python-large-numeric-array-literal",
            "metadata/file/literal::cve-pattern-many",
            "metadata/file/literal::lowercase-digits-alphabet",
            "micro-behaviors/data/string::replace",
        ]);
        let mut expected = input[..input.len() - 1].to_vec();
        expected.sort();
        assert_eq!(find_new_metadata_file_literal_ids(&input), expected);
    }

    #[test]
    fn rejects_new_root_and_subleaf_ids() {
        let input = ids(&[
            "metadata/file/literal::new-root-literal",
            "metadata/file/literal::lowercase-alnum-alphabet-v2",
            "metadata/file/literal/new-subject::new-literal",
            "metadata/file/literal/hex::hex-token",
            "micro-behaviors/data/string::replace",
        ]);
        assert_eq!(
            find_new_metadata_file_literal_ids(&input),
            vec![
                "metadata/file/literal/hex::hex-token".to_string(),
                "metadata/file/literal/new-subject::new-literal".to_string(),
                "metadata/file/literal::lowercase-alnum-alphabet-v2".to_string(),
                "metadata/file/literal::new-root-literal".to_string(),
            ]
        );
    }

    #[test]
    fn rejects_retired_legacy_ids() {
        let input = ids(&["metadata/file/literal::retired-literal"]);
        assert_eq!(find_new_metadata_file_literal_ids(&input), input);
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

#[cfg(test)]
mod printenv_filetype_allowance_tests {
    use super::{TraitDefinition, find_broad_filetype_traits};
    use std::collections::HashMap;

    #[test]
    fn named_call_scope_preserves_script_frontends_without_licensing_other_matchers()
    -> anyhow::Result<()> {
        let symbol: TraitDefinition = crate::yaml::from_str(
            "id: printenv\ndesc: Named call reference\ncrit: notable\nconf: 0.6\nfor: [shell, batch, python, javascript, ruby, php, lua, perl, powershell, applescript, vbs, mirc, ircii]\nif:\n  type: symbol\n  kind: call\n  exact: printenv\n",
        )?;
        assert_eq!(symbol.r#for.len(), 13);
        for (path, permitted) in [
            (
                "/traits/micro-behaviors/os/env/enumerate/enumeration-query.yaml",
                true,
            ),
            (
                "/traits/micro-behaviors/os/env/enumerate/enumeration-query-extra.yaml",
                false,
            ),
            (
                "/traits/micro-behaviors/os/env/enumerate-extra/enumeration-query.yaml",
                false,
            ),
        ] {
            let sources = HashMap::from([(symbol.id.clone(), path.to_string())]);
            assert_eq!(
                find_broad_filetype_traits(std::slice::from_ref(&symbol), &sources).is_empty(),
                permitted,
                "{path}"
            );
        }
        for condition in [
            "type: raw\nsubstr: printenv\n",
            "type: value\npath: example.value\n",
        ] {
            let mut other = symbol.clone();
            other.r#if = crate::yaml::from_str(condition)?;
            let sources = HashMap::from([(
                other.id.clone(),
                "/traits/micro-behaviors/os/env/enumerate/enumeration-query.yaml".to_string(),
            )]);
            assert_eq!(find_broad_filetype_traits(&[other], &sources).len(), 1);
        }
        Ok(())
    }

    #[test]
    fn named_call_file_allowance_rejects_path_substring_collisions() -> anyhow::Result<()> {
        let symbol: TraitDefinition = crate::yaml::from_str(
            "id: printenv\ndesc: Named call reference\ncrit: notable\nconf: 0.6\nfor: [shell, batch, python, javascript, ruby, php, lua, perl]\nif:\n  type: symbol\n  kind: call\n  exact: printenv\n",
        )?;
        for path in [
            "/traits/micro-behaviors/os/env/enumerate/enumeration-query.yaml.backup.yaml",
            "/traits/xmicro-behaviors/os/env/enumerate/enumeration-query.yaml",
            "/traits/micro-behaviors/os/env/enumerate/enumeration-query.yaml/child.yaml",
        ] {
            let sources = HashMap::from([(symbol.id.clone(), path.to_string())]);
            assert_eq!(
                find_broad_filetype_traits(std::slice::from_ref(&symbol), &sources).len(),
                1,
                "{path}"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
#[test]
fn systemd_user_sibling_exception_is_scoped() {
    let dirs = [
        "objectives/persistence/system/service/systemd",
        "objectives/persistence/system/service/systemd-user",
        "objectives/persistence/system/service/systemd-other",
        "other/service/systemd",
        "other/service/systemd-user",
    ]
    .map(str::to_string);
    let findings = find_sibling_name_restatement(&dirs);
    assert!(!findings.contains(&(
        "objectives/persistence/system/service".into(),
        "systemd".into(),
        "systemd-user".into(),
    )));
    assert!(findings.contains(&(
        "objectives/persistence/system/service".into(),
        "systemd".into(),
        "systemd-other".into(),
    )));
    assert!(findings.contains(&(
        "other/service".into(),
        "systemd".into(),
        "systemd-user".into(),
    )));
}
