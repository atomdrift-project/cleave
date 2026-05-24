//! Symbol extraction from source code
//!
//! Extracts function calls and references from source files using AST analysis.
//! Populates the imports list so symbol-based rules can match.

use crate::analyzers::FileType;
use crate::types::{AnalysisReport, Import};

/// Ingest the import list filefacts already produced from its
/// per-language tree-sitter queries, then run Python `__import__`
/// alias resolution on top — that pass is cleave-specific (it rewrites
/// symbol references in `report.imports` so trait matchers see the
/// real module name behind a malware-evasion alias).
pub(crate) fn ingest_filefacts_imports(
    parsed: &filefacts::ParsedFile<'_>,
    file_type: &FileType,
    report: &mut AnalysisReport,
) {
    for imp in parsed.imports().iter() {
        if imp.name.len() < 2 {
            continue;
        }
        report.imports.push(Import {
            symbol: imp.name.clone(),
            library: imp.library.clone(),
            source: "import".to_string(),
            offset: imp.offset.map(|o| format!("0x{o:x}")),
        });
    }

    if matches!(file_type, FileType::Python) {
        if let Some(ast) = parsed.source_ast() {
            let mut alias_map = std::collections::HashMap::new();
            let mut alias_cursor = ast.tree.walk();
            collect_dunder_import_aliases(&mut alias_cursor, ast.source.as_bytes(), &mut alias_map);
            if !alias_map.is_empty() {
                for import in &mut report.imports {
                    if let Some(dot_pos) = import.symbol.find('.') {
                        let prefix = &import.symbol[..dot_pos];
                        if let Some(module) = alias_map.get(prefix) {
                            import.symbol =
                                format!("{}.{}", module, &import.symbol[dot_pos + 1..]);
                        }
                    }
                }
            }
        }
    }
}

/// Collect `foo = __import__('module')` alias mappings from Python AST.
/// Builds a map of alias_variable -> module_name so that later symbol resolution
/// can replace `foo.b64decode` with `base64.b64decode`.
fn collect_dunder_import_aliases<'a>(
    cursor: &mut tree_sitter::TreeCursor<'a>,
    source: &[u8],
    alias_map: &mut std::collections::HashMap<String, String>,
) {
    loop {
        let node = cursor.node();

        // Look for: assignment where RHS is __import__('module')
        // Python tree-sitter: assignment node with left (identifier) and right (call)
        if node.kind() == "assignment" || node.kind() == "expression_statement" {
            if let Some(alias) = try_extract_dunder_import_alias(&node, source) {
                alias_map.insert(alias.0, alias.1);
            }
        }

        if cursor.goto_first_child() {
            continue;
        }
        if cursor.goto_next_sibling() {
            continue;
        }
        loop {
            if !cursor.goto_parent() {
                return;
            }
            if cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

/// Try to extract (alias, module) from a node like `foo = __import__('base64')`
fn try_extract_dunder_import_alias<'a>(
    node: &tree_sitter::Node<'a>,
    source: &[u8],
) -> Option<(String, String)> {
    // Handle both direct assignment nodes and expression_statement wrapping assignment
    let assign = if node.kind() == "assignment" {
        *node
    } else if node.kind() == "expression_statement" {
        // expression_statement may wrap an assignment
        let child = node.child(0)?;
        if child.kind() == "assignment" {
            child
        } else {
            return None;
        }
    } else {
        return None;
    };

    // Left side: identifier (the alias variable)
    let left = assign.child_by_field_name("left")?;
    if left.kind() != "identifier" {
        return None;
    }
    let alias_name = left.utf8_text(source).ok()?;

    // Right side: call to __import__
    let right = assign.child_by_field_name("right")?;
    if right.kind() != "call" {
        return None;
    }

    // Function being called must be __import__
    let func = right.child_by_field_name("function")?;
    let func_name = func.utf8_text(source).ok()?;
    if func_name != "__import__" {
        return None;
    }

    // Extract the module name from first string argument
    let args = right.child_by_field_name("arguments")?;
    for i in 0..args.child_count() {
        if let Some(arg) = args.child(i as u32) {
            if arg.kind() == "string" {
                if let Some(module) = extract_string_content(&arg, source) {
                    return Some((alias_name.to_string(), module));
                }
            }
        }
    }

    None
}

/// Extract string content from a string literal node
fn extract_string_content<'a>(node: &tree_sitter::Node<'a>, source: &[u8]) -> Option<String> {
    let text = node.utf8_text(source).ok()?;
    // Strip quotes if present
    let trimmed = text
        .trim_start_matches('"')
        .trim_start_matches('\'')
        .trim_end_matches('"')
        .trim_end_matches('\'');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Extract function calls from source code and add to report.imports.
///
/// Primarily for capability matching, not module imports — use
/// [`ingest_filefacts_imports`] for `require`/`import` statements.
///
/// Each call site emits its own `Import` entry tagged with the node's
/// byte offset, so composite rules with `near_bytes`/`near_lines`
/// proximity constraints can cluster multiple calls (e.g. `exec` +
/// `base64.b64decode` + `zlib.decompress` in a single decoder stub).
/// Entries are capped per-symbol to bound report size on pathological
/// inputs.
pub(crate) fn extract_symbols_from_tree(
    tree: &tree_sitter::Tree,
    source: &str,
    call_types: &[&str],
    report: &mut AnalysisReport,
) {
    let mut call_sites: Vec<(String, u64)> = Vec::new();
    let mut cursor = tree.walk();
    extract_calls(&mut cursor, source.as_bytes(), call_types, &mut call_sites);

    // Cap per-symbol offsets so minified or deeply repetitive files
    // don't explode the imports vector. 32 is enough for proximity
    // (any window that needs more hits than that is pathological).
    const MAX_OFFSETS_PER_SYMBOL: usize = 32;
    let mut per_symbol_count: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for (symbol, offset) in call_sites {
        if symbol.len() < 2 {
            continue;
        }
        let count = per_symbol_count.entry(symbol.clone()).or_insert(0);
        if *count >= MAX_OFFSETS_PER_SYMBOL {
            continue;
        }
        *count += 1;
        report
            .imports
            .push(Import::with_offset(symbol, None, "ast", offset));
    }
}

/// Walk AST iteratively to find function calls (avoids stack overflow on deep nesting).
/// Emits `(symbol, byte_offset)` pairs in source order, one per call site.
fn extract_calls<'a>(
    cursor: &mut tree_sitter::TreeCursor<'a>,
    source: &[u8],
    call_types: &[&str],
    call_sites: &mut Vec<(String, u64)>,
) {
    // Use iterative traversal with explicit depth tracking to avoid stack overflow
    // on maliciously crafted or minified files with extreme nesting
    loop {
        let node = cursor.node();
        let node_type = node.kind();

        // Check if this is a call node type we're interested in
        if call_types.contains(&node_type) {
            if let Some(func_name) = extract_function_name(&node, source) {
                // Clean up the function name
                let clean_name = func_name
                    .trim()
                    .trim_start_matches('_')
                    .trim_start_matches('$');
                if !clean_name.is_empty() && clean_name.len() < 100 {
                    call_sites.push((clean_name.to_string(), node.start_byte() as u64));
                }
            }
        }

        // Iterative tree traversal: try to go deeper, then sideways, then back up
        if cursor.goto_first_child() {
            continue;
        }
        if cursor.goto_next_sibling() {
            continue;
        }
        // Go back up until we can go sideways or reach the root
        loop {
            if !cursor.goto_parent() {
                return; // Reached root, done
            }
            if cursor.goto_next_sibling() {
                break; // Found a sibling, continue outer loop
            }
        }
    }
}

/// Extract the function name or identifier from a call, assignment, or declaration.
/// Public to the crate so the AST evaluator can populate `Evidence.alt_value`
/// for call-kind nodes — without that, `type: ast kind: call exact: <name>`
/// can never match because the cache otherwise compares the pattern against
/// `<name>(<args>)`.
pub(crate) fn extract_function_name<'a>(
    node: &tree_sitter::Node<'a>,
    source: &[u8],
) -> Option<String> {
    let kind = node.kind();

    if kind == "assignment_expression" {
        let left = node.child_by_field_name("left")?;
        return get_full_identifier(&left, source);
    }

    if kind == "variable_declarator" {
        let name = node.child_by_field_name("name")?;
        return get_full_identifier(&name, source);
    }

    // For call expressions, the function being called is usually the first child or
    // named field "function", "callee", or "method".
    let callee = node
        .child_by_field_name("function")
        .or_else(|| node.child_by_field_name("callee"))
        .or_else(|| node.child_by_field_name("method"))
        .or_else(|| node.child(0))?;

    get_full_identifier(&callee, source)
}

/// Recursively extract a full identifier from member expressions (e.g., "os.Open")
fn get_full_identifier<'a>(node: &tree_sitter::Node<'a>, source: &[u8]) -> Option<String> {
    let kind = node.kind();

    // Base case: simple identifiers
    if matches!(
        kind,
        "identifier"
            | "field_identifier"
            | "property_identifier"
            | "attribute"
            | "name"
            | "command_name"
            | "word"
            | "simple_identifier"
            | "string"
            | "string_literal"
    ) {
        return node
            .utf8_text(source)
            .ok()
            .map(std::string::ToString::to_string);
    }

    // Recursive case: member/selector expressions
    if matches!(
        kind,
        "member_expression"
            | "field_expression"
            | "selector_expression"
            | "attribute"
            | "dot_index_expression"
            | "subscript_expression"
    ) {
        // Most member expressions have an object/operand and a property/field
        let object = node
            .child_by_field_name("object")
            .or_else(|| node.child_by_field_name("operand"))
            .or_else(|| node.child(0))?;

        let property = node
            .child_by_field_name("property")
            .or_else(|| node.child_by_field_name("field"))
            .or_else(|| node.child_by_field_name("index"))
            .or_else(|| node.child(node.child_count().saturating_sub(1) as u32))?;

        if let (Some(obj_name), Some(mut prop_name)) = (
            get_full_identifier(&object, source),
            get_full_identifier(&property, source),
        ) {
            // Clean up property name if it's a string literal from a subscript
            if prop_name.starts_with('"') || prop_name.starts_with('\'') {
                prop_name = prop_name[1..prop_name.len() - 1].to_string();
            }
            return Some(format!("{}.{}", obj_name, prop_name));
        }
    }

    // Fallback: if it's a call, try to get the function name
    if kind.contains("call") || kind.contains("invocation") {
        return extract_function_name(node, source);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzers::FileType;
    use crate::types::{AnalysisReport, TargetInfo};

    fn parse_for_test<'a>(code: &'a str, file_type: &FileType) -> filefacts::ParsedFile<'a> {
        let hint = match file_type {
            FileType::Ruby => "test.rb",
            FileType::Python => "test.py",
            FileType::Go => "test.go",
            FileType::CSharp => "test.cs",
            other => panic!("parse_for_test: unsupported language {other:?}"),
        };
        let parsed = filefacts::open_with_path(std::path::Path::new(hint), code.as_bytes())
            .expect("filefacts open");
        let _ = parsed.values();
        parsed
    }

    #[test]
    fn test_ruby_extract_imports_only_require() {
        // Ruby code with require statements AND method calls
        let code = r#"
require 'net/http'
require 'uri'
require 'base64'
require 'resolv'

class Foo
  def self.run()
    system('/bin/sh')
    File.open('/tmp/x', 'wb+') do |f|
      f.write("hello")
      f.chmod(0777)
    end
  end
end
Foo.run()
"#;

        let mut report = AnalysisReport::new(TargetInfo {
            path: "/test/file.rb".to_string(),
            file_type: "ruby".to_string(),
            size_bytes: code.len() as u64,
            sha256: "test".to_string(),
            architectures: None,
        });

        // Extract imports (should only get require statements)
        let parsed = parse_for_test(code, &FileType::Ruby);
        ingest_filefacts_imports(&parsed, &FileType::Ruby, &mut report);

        // Should have exactly 4 imports (the require statements)
        let import_symbols: Vec<&str> = report.imports.iter().map(|i| i.symbol.as_str()).collect();
        assert_eq!(
            import_symbols.len(),
            4,
            "Expected 4 imports, got: {:?}",
            import_symbols
        );

        // Check the specific imports
        assert!(
            import_symbols.contains(&"net/http"),
            "Missing net/http import"
        );
        assert!(import_symbols.contains(&"uri"), "Missing uri import");
        assert!(import_symbols.contains(&"base64"), "Missing base64 import");
        assert!(import_symbols.contains(&"resolv"), "Missing resolv import");

        // Method calls like system, open, write, chmod should NOT be in imports
        assert!(
            !import_symbols.contains(&"system"),
            "system should not be an import"
        );
        assert!(
            !import_symbols.contains(&"open"),
            "open should not be an import"
        );
        assert!(
            !import_symbols.contains(&"write"),
            "write should not be an import"
        );
        assert!(
            !import_symbols.contains(&"chmod"),
            "chmod should not be an import"
        );
        assert!(
            !import_symbols.contains(&"run"),
            "run should not be an import"
        );
    }

    #[test]
    fn test_python_extract_imports() {
        let code = r#"
import socket
import os
from urllib import request
"#;

        let mut report = AnalysisReport::new(TargetInfo {
            path: "/test/file.py".to_string(),
            file_type: "python".to_string(),
            size_bytes: code.len() as u64,
            sha256: "test".to_string(),
            architectures: None,
        });

        let parsed = parse_for_test(code, &FileType::Python);
        ingest_filefacts_imports(&parsed, &FileType::Python, &mut report);

        let import_symbols: Vec<&str> = report.imports.iter().map(|i| i.symbol.as_str()).collect();
        assert!(import_symbols.contains(&"socket"), "Missing socket import");
        assert!(import_symbols.contains(&"os"), "Missing os import");
        assert!(import_symbols.contains(&"urllib"), "Missing urllib import");
    }

    #[test]
    fn test_python_dunder_import_alias_resolution() {
        // Python code using __import__ to alias modules (malware evasion pattern)
        let code = r#"
import streamlit as st
aqgqzxkfjzbdnhz = __import__('base64')
wogyjaaijwqbpxe = __import__('zlib')
data = wogyjaaijwqbpxe.decompress(aqgqzxkfjzbdnhz.b64decode(payload))
exec(compile(data, '<>', 'exec'))
"#;

        let mut report = AnalysisReport::new(TargetInfo {
            path: "/test/app.py".to_string(),
            file_type: "python".to_string(),
            size_bytes: code.len() as u64,
            sha256: "test".to_string(),
            architectures: None,
        });

        // Extract symbols first (call extraction)
        let parsed = parse_for_test(code, &FileType::Python);
        let tree = parsed.source_ast().expect("source_ast").tree;
        extract_symbols_from_tree(tree, code, &["call"], &mut report);

        // Then extract imports (which resolves __import__ aliases)
        ingest_filefacts_imports(&parsed, &FileType::Python, &mut report);

        let all_symbols: Vec<&str> = report.imports.iter().map(|i| i.symbol.as_str()).collect();

        // The aliased calls should be resolved to their real module names
        assert!(
            all_symbols.contains(&"base64.b64decode"),
            "Expected 'base64.b64decode' but got: {:?}",
            all_symbols
        );
        assert!(
            all_symbols.contains(&"zlib.decompress"),
            "Expected 'zlib.decompress' but got: {:?}",
            all_symbols
        );

        // The original alias names should NOT remain
        assert!(
            !all_symbols.contains(&"aqgqzxkfjzbdnhz.b64decode"),
            "Alias should have been resolved: {:?}",
            all_symbols
        );
        assert!(
            !all_symbols.contains(&"wogyjaaijwqbpxe.decompress"),
            "Alias should have been resolved: {:?}",
            all_symbols
        );
    }

    #[test]
    fn test_csharp_extract_imports() {
        let code = r#"
using System;
using System.Net.WebSockets;
using System.Net.NetworkInformation;
using static System.Math;
using Json = System.Text.Json;

namespace Foo
{
    public class Bar
    {
        public void Run() { Console.WriteLine("hi"); }
    }
}
"#;

        let mut report = AnalysisReport::new(TargetInfo {
            path: "/test/file.cs".to_string(),
            file_type: "csharp".to_string(),
            size_bytes: code.len() as u64,
            sha256: "test".to_string(),
            architectures: None,
        });

        let parsed = parse_for_test(code, &FileType::CSharp);
        ingest_filefacts_imports(&parsed, &FileType::CSharp, &mut report);

        let import_symbols: Vec<&str> = report.imports.iter().map(|i| i.symbol.as_str()).collect();
        assert!(
            import_symbols.contains(&"System"),
            "Missing System: {:?}",
            import_symbols
        );
        assert!(
            import_symbols.contains(&"System.Net.WebSockets"),
            "Missing System.Net.WebSockets: {:?}",
            import_symbols
        );
        assert!(
            import_symbols.contains(&"System.Net.NetworkInformation"),
            "Missing System.Net.NetworkInformation: {:?}",
            import_symbols
        );
        // `using static` and aliased imports should also surface their fully-qualified name.
        assert!(
            import_symbols.contains(&"System.Math"),
            "Missing System.Math (using static): {:?}",
            import_symbols
        );
        assert!(
            import_symbols.contains(&"System.Text.Json"),
            "Missing System.Text.Json (aliased): {:?}",
            import_symbols
        );

        // Namespace and class declarations should NOT be imports.
        assert!(
            !import_symbols.contains(&"Foo"),
            "Foo namespace should not be an import"
        );
        assert!(
            !import_symbols.contains(&"Bar"),
            "Bar class should not be an import"
        );
    }

    #[test]
    fn test_go_extract_imports() {
        let code = r#"
package main

import (
    "net"
    "os/exec"
    "fmt"
)

func main() {
    fmt.Println("hello")
}
"#;

        let mut report = AnalysisReport::new(TargetInfo {
            path: "/test/file.go".to_string(),
            file_type: "go".to_string(),
            size_bytes: code.len() as u64,
            sha256: "test".to_string(),
            architectures: None,
        });

        let parsed = parse_for_test(code, &FileType::Go);
        ingest_filefacts_imports(&parsed, &FileType::Go, &mut report);

        let import_symbols: Vec<&str> = report.imports.iter().map(|i| i.symbol.as_str()).collect();
        assert!(import_symbols.contains(&"net"), "Missing net import");
        assert!(
            import_symbols.contains(&"os/exec"),
            "Missing os/exec import"
        );
        assert!(import_symbols.contains(&"fmt"), "Missing fmt import");
    }
}
