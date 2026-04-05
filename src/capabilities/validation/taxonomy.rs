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
use crate::composite_rules::{CompositeTrait, Condition, FileType, Platform, TraitDefinition};
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
    "c",
    "php",
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
    "advanced",   // subjective
    "api",        // almost everything is an API
    "assorted",   // dumping ground
    "atomic",     // vague
    "base",       // too vague
    "basic",      // meaningless
    "category",   // dumping ground
    "combos",     // vague
    "code",       // vague
    "identifier", // vague
    "common",     // too vague
    "composite",  // vague
    "composites", // vague
    "default",    // meaningless
    "derived",    // yes
    "generic",    // says nothing about what's inside
    "helpers",    // too vague
    "hostile",    // dumping ground
    "impl",       // implementation detail
    "indicator",
    "indicators",
    "kind",   // too vague
    "kinds",  // too vague
    "method", // everything is a method
    "methods",
    "misc",       // dumping ground
    "modes",      // dumping ground
    "new",        // temporal, will rot
    "notable",    // dumping ground
    "old",        // temporal, will rot
    "other",      // dumping ground
    "pattern",    // vague
    "patterns",   // vague
    "go-runtime", // platform
    "simple",     // meaningless
    "stuff",      // obviously bad
    "signals",
    "suspicious", // dumping ground
    "technique",  // dumping ground
    "techniques", // dumping ground
    "things",     // obviously bad
    "type",       // too vague
    "types",      // dumping ground
    "utils",      // too vague
    "various",    // dumping ground
    "windows",    // generic platform
];

/// Directories that are allowed to have segments that duplicate their parent.
/// These are legitimate cases where the name duplication is intentional and meaningful.
const PARENT_DUPLICATE_EXCEPTIONS: &[&str] = &[
    "micro-behaviors/communications/tunnel/tun", // TUN is a specific tunnel device type
    "micro-behaviors/os/firewall/firewalld",     // firewalld is a specific firewall daemon name
    "objectives/persistence/system/systemd",     // systemd is a specific init system name
];

/// Maximum number of traits allowed in a single directory.
/// Directories exceeding this should be split into subdirectories.
pub(crate) const MAX_TRAITS_PER_DIRECTORY: usize = 80;

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
//   micro-behaviors/: type: string_value, substr: "chdir"
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
            if let Condition::Trait { id: ref_id } = &trait_def.r#if {
                if let Some(ref_tier) = extract_tier(ref_id) {
                    if ref_tier == "objectives" {
                        let source = rule_source_files
                            .get(&trait_def.id)
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string());
                        violations.push((trait_def.id.clone(), ref_id.clone(), source));
                    }
                }
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
                if let Some(ref_tier) = extract_tier(&ref_id) {
                    if ref_tier == "objectives" {
                        let source = rule_source_files
                            .get(&rule.id)
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string());
                        violations.push((rule.id.clone(), ref_id.clone(), source));
                    }
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
/// well-known/ rules violates the tier hierarchy.
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
        if let Condition::Trait { id: ref_id } = &trait_def.r#if {
            if is_cross_tier_ref(ref_id) {
                let source = rule_source_files
                    .get(&trait_def.id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                violations.push((trait_def.id.clone(), ref_id.clone(), source));
            }
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

/// Find micro-behaviors/ rules that reference well-known/ rules.
///
/// Micro-behaviors describe observable capabilities and should only reference other
/// micro-behaviors/ or metadata/ rules. Referencing well-known/ (specific malware/tool
/// signatures) creates a dependency on named entities which belongs in objectives/ or
/// well-known/ composites.
///
/// Returns `(rule_id, ref_id, source_file)` for violations.
#[must_use]
pub(crate) fn find_cap_wellknown_violations(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, String)> {
    let mut violations = Vec::new();

    fn extract_tier(id: &str) -> Option<&str> {
        let base = id.find("::").map_or(id, |idx| &id[..idx]);
        base.find('/').map(|i| &base[..i])
    }

    for trait_def in trait_definitions {
        if extract_tier(&trait_def.id) != Some("micro-behaviors") {
            continue;
        }
        if let Condition::Trait { id: ref_id } = &trait_def.r#if {
            if extract_tier(ref_id) == Some("well-known") {
                let source = rule_source_files
                    .get(&trait_def.id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                violations.push((trait_def.id.clone(), ref_id.clone(), source));
            }
        }
    }

    for rule in composite_rules {
        if extract_tier(&rule.id) != Some("micro-behaviors") {
            continue;
        }
        let trait_refs = collect_trait_refs_from_rule(rule);
        for (ref_id, _) in trait_refs {
            if extract_tier(&ref_id) == Some("well-known") {
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

/// Find trait and composite rule IDs that contain invalid characters.
///
/// IDs should only contain alphanumerics, dashes, and underscores (no slashes).
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
        // Extract local ID (after :: delimiter, or the whole ID if no delimiter)
        let local_id = if let Some(idx) = trait_def.id.find("::") {
            &trait_def.id[idx + 2..]
        } else {
            &trait_def.id
        };

        if let Some(invalid_char) = validate_trait_id_chars(local_id) {
            let source = rule_source_files
                .get(&trait_def.id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            violations.push((trait_def.id.clone(), invalid_char, source));
        }
    }

    for rule in composite_rules {
        // Extract local ID (after :: delimiter, or the whole ID if no delimiter)
        let local_id = if let Some(idx) = rule.id.find("::") {
            &rule.id[idx + 2..]
        } else {
            &rule.id
        };

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
                violations.push((dir_path.clone(), segment.to_string()));
                break; // Only report first violation per path
            }
        }
    }

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
        .filter(|(_, count)| *count > MAX_TRAITS_PER_DIRECTORY)
        .collect();

    violations.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by count descending
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

/// Allowed second-level categories under `well-known/tools/`.
const WELL_KNOWN_TOOLS_CATEGORIES: &[&str] = &[
    "breachcore",
    "browser",
    "detection",
    "dual-use",
    "gnulib",
    "keyauth",
    "mercurial",
    "offensive",
    "reverse-engineering",
    "sysadmin",
    "testing",
];

/// Validate that well-known/malware/ and well-known/tools/ only contain whitelisted
/// second-level categories.
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

        // Check well-known/malware/<category> and well-known/tools/<category>
        if parts[0] != "well-known" {
            continue;
        }

        let (allowed, category) = match parts[1] {
            "malware" => (WELL_KNOWN_MALWARE_CATEGORIES, parts[2]),
            "tools" => (WELL_KNOWN_TOOLS_CATEGORIES, parts[2]),
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
        if source.contains("well-known/") {
            if let Some(dir) = Path::new(&source).parent() {
                dirs_with_traits.insert(dir.to_string_lossy().to_string());
            }
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

/// Returns true if the condition has a section filter or positional constraint applied to it.
/// This includes: section/offset/offset_range/section_offset/section_offset_range fields
/// on string/raw/hex conditions, Section type, SectionRatio type.
fn condition_has_section_filter(cond: &Condition) -> bool {
    match cond {
        Condition::StringValue {
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            ..
        }
        | Condition::Raw {
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            ..
        }
        | Condition::Hex {
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            ..
        } => {
            section.is_some()
                || offset.is_some()
                || offset_range.is_some()
                || section_offset.is_some()
                || section_offset_range.is_some()
        }
        Condition::Section { .. } | Condition::SectionRatio { .. } => true,
        _ => false,
    }
}

/// Returns true if the condition is one where a section filter would be meaningful.
fn condition_supports_section_filter(cond: &Condition) -> bool {
    matches!(
        cond,
        Condition::StringValue { .. } | Condition::Raw { .. } | Condition::Hex { .. }
    )
}

/// Extract tier prefix from a trait ID (everything before the first `::` or `/`-delimited namespace).
fn extract_trait_tier(id: &str) -> &str {
    let base = id.find("::").map_or(id, |i| &id[..i]);
    base.find('/').map_or(base, |i| &base[..i])
}

/// Find well-known/ atomic traits that use `for: [all]` (over-broad file type filter).
///
/// well-known/ traits identify specific malware families and must be scoped to concrete
/// file types (e.g., `pe`, `elf`, `python`) rather than the default `all`.
///
/// Returns `Vec<(trait_id, source_file)>` for violations.
#[must_use]
pub(crate) fn find_wellknown_unscoped_filetypes(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    trait_definitions
        .iter()
        .filter(|t| {
            extract_trait_tier(&t.id) == "well-known"
                && t.r#for.contains(&FileType::All)
                && !(t.size_min.is_some() || t.size_max.is_some())
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

/// Find well-known/ atomic traits that use `platforms: [all]` (over-broad platform filter).
///
/// well-known/ traits for specific malware families should be scoped to the platforms
/// that malware targets rather than defaulting to all platforms.
///
/// Returns `Vec<(trait_id, source_file)>` for violations.
#[must_use]
pub(crate) fn find_wellknown_unscoped_platforms(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String)> {
    trait_definitions
        .iter()
        .filter(|t| {
            extract_trait_tier(&t.id) == "well-known" && t.platforms.contains(&Platform::All)
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
                && trait_targets_binaries(t)
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
                && trait_targets_binaries(t)
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
