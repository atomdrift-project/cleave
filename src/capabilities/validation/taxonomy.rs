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

mod reviewed;
#[allow(clippy::wildcard_imports)]
use reviewed::*;

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
        .map(|t| (&t.id, &t.platforms, t.is_exempt("all-platforms-directory")))
        .chain(
            composite_rules
                .iter()
                .map(|r| (&r.id, &r.platforms, r.is_exempt("all-platforms-directory"))),
        )
        .filter(|(id, platforms, exempt)| {
            platforms.contains(&Platform::All) && !exempt && !all_platform_directory_allowed(id)
        })
        .map(|(id, _, _)| {
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
                && !t.is_exempt("broad-platform-scope")
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
            let category = t.r#if.type_name();
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
            if allowlisted || t.is_exempt("broad-filetype-cap") {
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
mod media_filetype_allowance_tests;

pub(crate) fn find_wellknown_missing_size_filter(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    trait_definitions
        .iter()
        .filter(|t| {
            extract_trait_tier(&t.id) == "well-known"
                && !t.is_exempt("wellknown-size-filter")
                && trait_targets_binaries(t)
                && !(is_basename_fact(t)
                    && matches!(t.crit, Criticality::Component | Criticality::Notable))
                && !is_low_tier_named_binary_fact(t)
                && !reviewed_unbounded_reference(t, false)
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
                && !is_go_socks5_library_reference(t)
                && !is_gentee_runtime_reference(t)
                && !is_named_crypter_label_reference(t)
                && !is_ngrok_go_type_reference(t)
                && !is_tunnel_client_reference(t)
                && !is_yamux_library_reference(t)
                && !is_openconnect_command_reference(t)
                && !is_jwe_library_reference(t)
                && !is_apple_cache_service_reference(t)
                && !is_windows_product_name_reference(t)
                && !is_legacy_product_name_reference(t)
                && !is_trezor_name_reference(t)
                && !is_windows_rpc_service_reference(t)
                && !is_sumatrapdf_encryption_claim(t)
                // A GitLab registry path is a service reference regardless of
                // the size of a binary containing it, not a file identity.
                && !(t.id == "well-known/app/development/code-forge/gitlab::gitlab-generic-package-upload"
                    && t.crit == Criticality::Notable
                    && matches!(&t.r#if, Condition::Text(q)
                        if q.regex.as_deref() == Some(r"/api/v4/projects/.{0,160}/packages/generic/")
                            && q.exact.is_none() && q.substr.is_none() && q.word.is_none()))
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
                && !t.is_exempt("binary-section-filter")
                && trait_targets_only_binaries(t)
                && !is_jwe_library_reference(t)
                && !is_windows_product_name_reference(t)
                && !reviewed_unbounded_reference(t, true)
                && !is_poolpartybof_reference(t)
                && !is_mixcloud_warning_reference(t)
                && !is_sms_provider_endpoint_reference(t)
                && !is_go_socks5_library_reference(t)
                && !is_gentee_runtime_reference(t)
                && !is_named_crypter_label_reference(t)
                && !is_ngrok_go_type_reference(t)
                && !is_tunnel_client_reference(t)
                && !is_yamux_library_reference(t)
                && !is_openconnect_command_reference(t)
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
mod printenv_filetype_allowance_tests;

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
