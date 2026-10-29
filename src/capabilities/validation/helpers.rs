//! Utility functions for validation.
//!
//! This module provides shared utilities used across validation modules,
//! including line-number finding and file-type classification.

use crate::composite_rules::FileType as RuleFileType;

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

/// The 1-indexed line in `file_path` that `search_str` refers to.
///
/// A rule ID (local, or qualified as `dir::id`) resolves to the line that
/// declares it, `id: <name>`, so an ID that prefixes another or appears in a
/// comment does not claim the wrong line. Anything else resolves to the first
/// line containing it.
#[must_use]
pub(crate) fn find_line_number(file_path: &str, search_str: &str) -> Option<usize> {
    let content = std::fs::read_to_string(file_path).ok()?;
    line_number_in(&content, search_str)
}

fn line_number_in(content: &str, search_str: &str) -> Option<usize> {
    let local_id = search_str.rsplit("::").next().unwrap_or(search_str);
    let declares_id = |line: &str| {
        line.trim_start()
            .trim_start_matches("- ")
            .strip_prefix("id:")
            .is_some_and(|v| v.trim().trim_matches(['"', '\'']) == local_id)
    };
    let lines = || content.lines().enumerate();
    lines()
        .find(|(_, line)| declares_id(line))
        .or_else(|| lines().find(|(_, line)| line.contains(search_str)))
        .map(|(i, _)| i + 1)
}

#[cfg(test)]
mod tests {
    use super::line_number_in;

    #[test]
    fn rule_ids_resolve_to_their_declaration() {
        let yaml = "# id: net is mentioned here\ntraits:\n  - id: network\n  - id: net\n";
        assert_eq!(line_number_in(yaml, "net"), Some(4));
        assert_eq!(line_number_in(yaml, "micro-behaviors/x::net"), Some(4));
        assert_eq!(line_number_in(yaml, "network"), Some(3));
        assert_eq!(line_number_in(yaml, "traits:"), Some(2));
    }
}
