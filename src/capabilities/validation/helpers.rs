//! Utility functions for validation.
//!
//! This module provides shared utilities used across validation modules,
//! including line number finding and rule conversions.

use crate::composite_rules::{CompositeTrait, Condition, FileType as RuleFileType, Platform};
use crate::types::Criticality;

use super::super::parsing::parse_file_types;

/// Extract tier prefix from a trait/rule ID
///
/// Returns the top-level tier: "micro-behaviors", "objectives", "well-known", "metadata", etc.
///
/// Examples:
/// - "micro-behaviors/fs/file/delete::unlink" → Some("micro-behaviors")
/// - "objectives/collection/metadata::home-env" → Some("objectives")
/// - "invalid-id" → None
#[must_use]
pub(crate) fn extract_tier(id: &str) -> Option<&str> {
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

/// Find the line number of a search string in a file.
///
/// Returns `Some(line_number)` if found (1-indexed), or `None` if not found or file can't be read.
#[must_use]
pub(crate) fn find_line_number(file_path: &str, search_str: &str) -> Option<usize> {
    let content = std::fs::read_to_string(file_path).ok()?;
    for (line_num, line) in content.lines().enumerate() {
        if line.contains(search_str) {
            return Some(line_num + 1); // 1-indexed
        }
    }
    None
}

/// Convert a simple rule with constraints into a composite rule
/// Collects warnings into the provided vector.
#[must_use]
pub(crate) fn simple_rule_to_composite_rule(
    rule: super::super::models::SimpleRule,
    warnings: &mut Vec<String>,
) -> CompositeTrait {
    // Parse platforms
    let platforms = if rule.platforms.is_empty() {
        vec![Platform::All]
    } else {
        rule.platforms
            .iter()
            .filter_map(|p| match p.to_lowercase().as_str() {
                "all" => Some(Platform::All),
                "linux" => Some(Platform::Linux),
                "macos" => Some(Platform::MacOS),
                "windows" => Some(Platform::Windows),
                "unix" => Some(Platform::Unix),
                "android" => Some(Platform::Android),
                "ios" => Some(Platform::Ios),
                _ => None,
            })
            .collect()
    };

    // Parse file types
    let file_types = if rule.file_types.is_empty() {
        vec![RuleFileType::All]
    } else {
        parse_file_types(&rule.file_types, warnings)
    };

    // Create a composite trait with a single symbol condition
    CompositeTrait {
        id: rule.capability,
        desc: rule.desc,
        conf: rule.conf,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms,
        r#for: file_types,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some(rule.symbol),
            platforms: None,
            compiled_regex: None,
        }]),
        any: None,
        needs: None,
        none: None,
        near_lines: None,
        near_bytes: None,
        unless: None,
        not: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("converted_simple_rule"),
        precision: None,
    }
}
