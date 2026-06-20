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
