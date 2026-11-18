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
use std::path::Path;

mod allowlists;
#[allow(clippy::wildcard_imports)]
pub(crate) use allowlists::*;

mod directories;
#[allow(clippy::wildcard_imports)]
pub(crate) use directories::*;

mod tiers;
#[allow(clippy::wildcard_imports)]
pub(crate) use tiers::*;

/// Platform and language names that should not appear as directory segments.
/// These names indicate implementation details rather than behavioral classifications.
const LANGUAGE_NAMES: &[&str] = &[
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
    // Node.js variants
    "nodejs",
    // Common aliases
    "bash",
    "sh",
    "zsh",
    "dotnet",
];

const PLATFORM_NAMES: &[&str] = &[
    // Binary formats
    "elf", "macho", "pe", // Operating systems / platforms
    "linux", "unix", "windows", "macos", "darwin", "android", "ios", "freebsd", "openbsd",
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
    "type",        // too vague
    "types",       // dumping ground
    "unspecified", // file by the evidence the rule establishes
    "utils",       // too vague
    "various",     // dumping ground
    "windows",     // generic platform
];

/// Established category names that also occur on the banned segment list.
const BANNED_SEGMENT_EXCEPTIONS: &[&str] = &[
    "micro-behaviors/data", // Encoding, serialization, parsing, and databases
    "well-known/app/data",  // Databases and data-platform applications
    "well-known/lib/data",  // Data-layer libraries
    "metadata/binary/code", // Executable bytes and code structure
    "well-known/tool",      // Named tool catalog
    "well-known/tool/detection",
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
// Content-scan caps (text/metrics/encoded) include the macOS-native types
// (applescript/plist/swift/objectivec) that ride into a group expansion now
// that the `unix` umbrella reaches macOS (see resolve_platform_filetype_conflicts).
// They also cover the complete generated manifest and archive families, including
// mirc and ircii in the scripts group. These are the family widths, not arbitrary
// exceptions for individual traits: adding a supported format must not make the
// shipped taxonomy unloadable.
const BROAD_FILETYPE_THRESHOLD_TEXT: usize = 45; // text / literal / comment
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
        Condition::Metrics(MetricsQuery { .. }) => BROAD_FILETYPE_THRESHOLD_METRICS,
        Condition::Path(PathQuery { basename: true, .. })
        | Condition::Path(PathQuery { dirname: true, .. }) => BROAD_FILETYPE_THRESHOLD_BASENAME,
        // References inherit the underlying matcher's cap. Full paths are
        // evaluated independently of the carrier format.
        Condition::Trait { .. } | Condition::Path(_) => usize::MAX,
        Condition::Raw(RawQuery { .. }) => BROAD_FILETYPE_THRESHOLD_RAW,
        Condition::Encoded(EncodedQuery { .. }) => BROAD_FILETYPE_THRESHOLD_ENCODED,
        Condition::Section(SectionQuery { .. }) => BROAD_FILETYPE_THRESHOLD_SECTION,
        Condition::Symbol(SymbolQuery { .. }) | Condition::Syscall { .. } => {
            BROAD_FILETYPE_THRESHOLD_SYMBOL
        }
        Condition::Hex(HexQuery { .. }) => BROAD_FILETYPE_THRESHOLD_HEX,
        Condition::Yara { .. } => BROAD_FILETYPE_THRESHOLD_YARA,
        // This value reads the file name directly, like the path matcher.
        Condition::Kv(q) if q.path == "file.basename" => usize::MAX,
        Condition::Kv(KvQuery { .. }) => BROAD_FILETYPE_THRESHOLD_VALUE,
        Condition::TreeSitter(TreeSitterQuery { .. }) => BROAD_FILETYPE_THRESHOLD_AST,
    }
}

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

fn has_reviewed_platform_scope(t: &TraitDefinition) -> bool {
    let Some((directory, _)) = t.id.split_once("::") else {
        return false;
    };
    REVIEWED_BROAD_PLATFORM_SCOPES
        .iter()
        .any(|(prefix, platforms)| {
            (directory == *prefix
                || directory
                    .strip_prefix(prefix)
                    .is_some_and(|rest| rest.starts_with('/')))
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

/// Match an exact file or directory subtree, relative to the rules root.
fn filetype_allowlist_source_matches(source: &Path, location: &str) -> bool {
    if location.ends_with('/') {
        source.starts_with(location)
    } else {
        source == Path::new(location)
    }
}

fn exceeded_filetype_cap(t: &TraitDefinition) -> Option<(usize, usize)> {
    let count = effective_filetype_count(t);
    // Archive trees and extraction guards supply the same fields across formats.
    let archive_fact = match &t.r#if {
        Condition::Kv(q) => q.path.starts_with("archive.") || q.path.starts_with("archive_guard."),
        Condition::Metrics(q) => q.field.starts_with("archive.guard."),
        _ => false,
    };
    let cap = if archive_fact && t.r#for.iter().all(FileType::is_archive) {
        FileType::archive_family_types().len()
    } else if matches!(&t.r#if, Condition::Kv(q) if q.path.starts_with("media."))
        && t.r#for.iter().all(|ft| FileType::MEDIA_FAMILY.contains(ft))
    {
        FileType::MEDIA_FAMILY.len()
    } else {
        filetype_cap_for_condition(&t.r#if)
    };
    (count > cap).then_some((count, cap))
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
    root: &Path,
) -> Vec<(String, String, usize, Vec<FileType>, &'static str, usize)> {
    trait_definitions
        .iter()
        .filter_map(|t| {
            let (count, cap) = exceeded_filetype_cap(t)?;
            let category = t.r#if.type_name();
            let source = rule_source_files
                .get(&t.id)
                .map(String::as_str)
                .unwrap_or("");
            let allowlisted = Path::new(source).strip_prefix(root).is_ok_and(|relative| {
                BROAD_FILETYPE_ALLOWLIST.iter().any(|entry| {
                    entry.split_once(':').is_some_and(|(ty, location)| {
                        ty == category && filetype_allowlist_source_matches(relative, location)
                    })
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

/// Find entries that cover no over-cap atomic trait of the specified matcher type.
#[must_use]
pub(crate) fn find_stale_filetype_allowlist_entries(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
    root: &Path,
) -> Vec<&'static str> {
    let mut over_cap: HashMap<&str, HashSet<&Path>> = HashMap::new();
    for t in trait_definitions {
        if exceeded_filetype_cap(t).is_some()
            && let Some(source) = rule_source_files.get(&t.id)
            && let Ok(relative) = Path::new(source).strip_prefix(root)
        {
            over_cap
                .entry(t.r#if.type_name())
                .or_default()
                .insert(relative);
        }
    }
    BROAD_FILETYPE_ALLOWLIST
        .iter()
        .filter(|entry| {
            let Some((category, location)) = entry.split_once(':') else {
                // A malformed entry can never match; report it too.
                return true;
            };
            !over_cap.get(category).is_some_and(|sources| {
                sources
                    .iter()
                    .any(|source| filetype_allowlist_source_matches(source, location))
            })
        })
        .copied()
        .collect()
}

#[cfg(test)]
mod media_filetype_allowance_tests;

/// Size is identity evidence for high-criticality binary fingerprints and
/// open-ended byte signatures. Names, parsed fields, and literal markers used
/// as supporting evidence can occur in artifacts of any size.
fn binary_identity_needs_size(t: &TraitDefinition) -> bool {
    (is_high_criticality_binary_identity(t)
        && !(is_basename_fact(t) && t.crit <= Criticality::Notable))
        || match &t.r#if {
            Condition::Raw(q) => q.regex.is_some(),
            Condition::Hex(_) | Condition::Encoded(_) | Condition::Yara { .. } => true,
            _ => false,
        }
}

fn is_high_criticality_binary_identity(t: &TraitDefinition) -> bool {
    t.crit > Criticality::Notable || t.id.starts_with("well-known/malware/")
}

pub(crate) fn find_wellknown_missing_size_filter(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    trait_definitions
        .iter()
        .filter(|t| {
            extract_trait_tier(&t.id) == "well-known"
                && trait_targets_binaries(t)
                && binary_identity_needs_size(t)
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
                && (is_high_criticality_binary_identity(t)
                    || matches!(
                        t.r#if,
                        Condition::Raw(_) | Condition::Hex(_) | Condition::Encoded(_)
                    ))
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
mod content_dir_tests;

#[cfg(test)]
mod metadata_file_string_tests;

#[cfg(test)]
mod metadata_file_literal_tests;

#[cfg(test)]
mod parent_duplicate_tests;

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
#[test]
fn systemd_scope_names_can_be_siblings_under_the_shared_subject() {
    let dirs = [
        "objectives/persistence/system/service/systemd/unit",
        "objectives/persistence/system/service/systemd/user",
    ]
    .map(str::to_string);
    assert!(find_sibling_name_restatement(&dirs).is_empty());
}
