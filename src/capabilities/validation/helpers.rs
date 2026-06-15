//! Utility functions for validation.
//!
//! This module provides shared utilities used across validation modules,
//! including line number finding and rule conversions.

use crate::composite_rules::SymbolQuery;
use crate::composite_rules::{CompositeTrait, Condition, FileType as RuleFileType, Platform};
use crate::types::Criticality;

use super::super::parsing::{parse_file_types, parse_platforms};

/// Returns true if the file type is a compiled binary format with sections.
#[must_use]
pub(super) fn is_binary_file_type(ft: RuleFileType) -> bool {
    matches!(
        ft,
        RuleFileType::Elf | RuleFileType::Macho | RuleFileType::Pe
    )
}

/// Returns true if the file type uses AST-based string extraction (source/script types).
///
/// For these types, `string_value` only searches string literals parsed from source code,
/// NOT arbitrary code expressions. Patterns like `eval(` or `import os` will never match
/// via `string_value` because they're code structure, not string content.
#[must_use]
pub(super) fn is_ast_source_type(ft: RuleFileType) -> bool {
    matches!(
        ft,
        RuleFileType::Python
            | RuleFileType::JavaScript
            | RuleFileType::TypeScript
            | RuleFileType::Shell
            | RuleFileType::Ruby
            | RuleFileType::Php
            | RuleFileType::Perl
            | RuleFileType::Lua
            | RuleFileType::PowerShell
            | RuleFileType::Java
            | RuleFileType::Rust
            | RuleFileType::C
            | RuleFileType::Cpp
            | RuleFileType::Go
            | RuleFileType::CSharp
            | RuleFileType::Swift
            | RuleFileType::ObjectiveC
            | RuleFileType::Groovy
            | RuleFileType::Scala
            | RuleFileType::Elixir
            | RuleFileType::Vbs
            | RuleFileType::Batch
            | RuleFileType::Jcl
            | RuleFileType::AppleScript
    )
}

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
        warnings.push(format!(
            "Rule '{}': missing 'platforms:' declaration. Every rule must specify which \
             platforms it targets. List explicit platforms such as [unix, windows, macos].",
            rule.capability
        ));
        vec![Platform::All]
    } else {
        let parsed = parse_platforms(
            &rule
                .platforms
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>(),
            warnings,
        );
        if parsed.is_empty() {
            vec![Platform::All]
        } else {
            parsed
        }
    };

    // Parse file types
    let file_types = if rule.file_types.is_empty() {
        vec![RuleFileType::All]
    } else {
        parse_file_types(&rule.file_types, warnings).types
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
        arch: vec![crate::composite_rules::types::Arch::All],
        r#for: file_types,
        for_from_groups: false,
        size_min: None,
        size_max: None,
        all: Some(vec![Condition::Symbol(SymbolQuery {
            exact: None,
            substr: None,
            regex: Some(rule.symbol),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        })]),
        any: None,
        needs: None,
        near_lines: None,
        near_bytes: None,
        scope: None,
        unless: None,
        not: None,
        downgrade: None,
        r#ref: None,
        defined_in: std::path::PathBuf::from("converted_simple_rule"),
        precision: None,
        required_trait_indices: Vec::new(),
    }
}
