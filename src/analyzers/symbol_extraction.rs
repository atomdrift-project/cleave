//! Symbol extraction from source code
//!
//! Extracts function calls and references from source files using AST analysis.
//! Populates the imports list so symbol-based rules can match.

use crate::analyzers::FileType;
use crate::types::{AnalysisReport, Import};

/// Function type for extracting imports from a syntax tree node
type ImportExtractFn = for<'a> fn(&tree_sitter::Node<'a>, &[u8]) -> Option<String>;

/// Extract imports from a pre-parsed tree (avoids re-parsing)
pub(crate) fn extract_imports_from_tree(
    tree: &tree_sitter::Tree,
    source: &str,
    file_type: &FileType,
    report: &mut AnalysisReport,
) {
    let import_fn: ImportExtractFn = match file_type {
        FileType::Ruby => extract_ruby_import,
        FileType::Python => extract_python_import,
        FileType::JavaScript | FileType::TypeScript => extract_js_import,
        FileType::Lua => extract_lua_import,
        FileType::Go => extract_go_import,
        FileType::Perl => extract_perl_import,
        _ => return, // Other languages don't have import extraction yet
    };

    let mut imports = std::collections::HashSet::new();
    let mut cursor = tree.walk();
    walk_for_imports(&mut cursor, source.as_bytes(), import_fn, &mut imports);

    for module in imports {
        if module.len() >= 2 {
            report.imports.push(Import {
                symbol: module,
                library: None,
                source: "import".to_string(),
            });
        }
    }
}

/// Extract actual module imports from source code (e.g., require in Ruby, import in Python)
/// This is separate from function call extraction for capability matching.
/// NOTE: This parses internally - prefer extract_imports_from_tree() if you already have a tree
pub(crate) fn extract_imports(source: &str, file_type: &FileType, report: &mut AnalysisReport) {
    let (lang, import_fn): (tree_sitter::Language, ImportExtractFn) = match file_type {
        FileType::Ruby => (tree_sitter_ruby::LANGUAGE.into(), extract_ruby_import),
        FileType::Python => (tree_sitter_python::LANGUAGE.into(), extract_python_import),
        FileType::JavaScript | FileType::TypeScript => {
            let lang = if matches!(file_type, FileType::TypeScript) {
                tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()
            } else {
                tree_sitter_javascript::LANGUAGE.into()
            };
            (lang, extract_js_import)
        }
        FileType::Lua => (tree_sitter_lua::LANGUAGE.into(), extract_lua_import),
        FileType::Go => (tree_sitter_go::LANGUAGE.into(), extract_go_import),
        FileType::Perl => (tree_sitter_perl::LANGUAGE.into(), extract_perl_import),
        _ => return, // Other languages don't have import extraction yet
    };

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&lang).is_err() {
        return;
    }

    let Some(tree) = parser.parse(source, None) else {
        return;
    };

    let mut imports = std::collections::HashSet::new();
    let mut cursor = tree.walk();
    walk_for_imports(&mut cursor, source.as_bytes(), import_fn, &mut imports);

    for module in imports {
        if module.len() >= 2 {
            report.imports.push(Import {
                symbol: module,
                library: None,
                source: "import".to_string(), // Distinguish from function calls ("ast")
            });
        }
    }
}

/// Walk AST to find import statements
fn walk_for_imports<'a>(
    cursor: &mut tree_sitter::TreeCursor<'a>,
    source: &[u8],
    import_fn: fn(&tree_sitter::Node<'a>, &[u8]) -> Option<String>,
    imports: &mut std::collections::HashSet<String>,
) {
    loop {
        let node = cursor.node();
        if let Some(module) = import_fn(&node, source) {
            imports.insert(module);
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

/// Extract Ruby require/require_relative statements
fn extract_ruby_import<'a>(node: &tree_sitter::Node<'a>, source: &[u8]) -> Option<String> {
    // Ruby require is: call with method name "require" or "require_relative"
    if node.kind() != "call" && node.kind() != "method_call" {
        return None;
    }

    // Get the method name
    let method_node = node.child_by_field_name("method")?;
    let method_name = method_node.utf8_text(source).ok()?;

    if method_name != "require" && method_name != "require_relative" {
        return None;
    }

    // Get the argument (the module name)
    let args = node.child_by_field_name("arguments")?;
    // First child of arguments is the string
    let arg = args.child(0)?;
    extract_string_content(&arg, source)
}

/// Extract Python import statements
fn extract_python_import<'a>(node: &tree_sitter::Node<'a>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "import_statement" => {
            // import foo.bar -> extract "foo.bar"
            let name_node = node.child_by_field_name("name")?;
            name_node
                .utf8_text(source)
                .ok()
                .map(std::string::ToString::to_string)
        }
        "import_from_statement" => {
            // from foo.bar import baz -> extract "foo.bar"
            let module_node = node.child_by_field_name("module_name")?;
            module_node
                .utf8_text(source)
                .ok()
                .map(std::string::ToString::to_string)
        }
        _ => None,
    }
}

/// Extract JavaScript/TypeScript import statements
fn extract_js_import<'a>(node: &tree_sitter::Node<'a>, source: &[u8]) -> Option<String> {
    if node.kind() != "import_statement" && node.kind() != "import_declaration" {
        return None;
    }
    // Find the source/string child
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            if let Some(content) = extract_string_content(&child, source) {
                return Some(content);
            }
        }
    }
    None
}

/// Extract Lua require statements
fn extract_lua_import<'a>(node: &tree_sitter::Node<'a>, source: &[u8]) -> Option<String> {
    if node.kind() != "function_call" {
        return None;
    }
    // Check if it's a require call
    let func = node.child_by_field_name("name")?;
    let func_name = func.utf8_text(source).ok()?;
    if func_name != "require" {
        return None;
    }
    let args = node.child_by_field_name("arguments")?;
    let arg = args.child(0)?;
    extract_string_content(&arg, source)
}

/// Extract Go import declarations
fn extract_go_import<'a>(node: &tree_sitter::Node<'a>, source: &[u8]) -> Option<String> {
    if node.kind() != "import_spec" {
        return None;
    }
    let path = node.child_by_field_name("path")?;
    extract_string_content(&path, source)
}

/// Extract Perl use/require statements
fn extract_perl_import<'a>(node: &tree_sitter::Node<'a>, source: &[u8]) -> Option<String> {
    if node.kind() != "use_statement" && node.kind() != "require_statement" {
        return None;
    }
    // Find the module name
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i as u32) {
            if child.kind() == "package_name" || child.kind() == "bareword" {
                return child
                    .utf8_text(source)
                    .ok()
                    .map(std::string::ToString::to_string);
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

/// Extract function calls from source code and add to report.imports
/// NOTE: This is primarily for capability matching, not module imports.
/// Use extract_imports() for actual module imports like require/import.
/// Extract symbols from a pre-parsed tree (avoids re-parsing)
pub(crate) fn extract_symbols_from_tree(
    tree: &tree_sitter::Tree,
    source: &str,
    call_types: &[&str],
    report: &mut AnalysisReport,
) {
    let mut symbols = std::collections::HashSet::new();
    let mut cursor = tree.walk();
    extract_calls(&mut cursor, source.as_bytes(), call_types, &mut symbols);

    // Add unique symbols to imports
    for symbol in symbols {
        // Skip very short symbols (likely false positives)
        if symbol.len() < 2 {
            continue;
        }
        report.imports.push(Import {
            symbol,
            library: None,
            source: "ast".to_string(),
        });
    }
}

/// Extract symbols from source code by parsing with tree-sitter
/// NOTE: This parses internally - prefer extract_symbols_from_tree() if you already have a tree
pub(crate) fn extract_symbols(
    source: &str,
    lang: &tree_sitter::Language,
    call_types: &[&str],
    report: &mut AnalysisReport,
) {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(lang).is_err() {
        return;
    }

    let Some(tree) = parser.parse(source, None) else {
        return;
    };

    extract_symbols_from_tree(&tree, source, call_types, report);
}

/// Walk AST iteratively to find function calls (avoids stack overflow on deep nesting)
fn extract_calls<'a>(
    cursor: &mut tree_sitter::TreeCursor<'a>,
    source: &[u8],
    call_types: &[&str],
    symbols: &mut std::collections::HashSet<String>,
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
                    symbols.insert(clean_name.to_string());
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

/// Extract the function name or identifier from a call, assignment, or declaration
fn extract_function_name<'a>(node: &tree_sitter::Node<'a>, source: &[u8]) -> Option<String> {
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
        extract_imports(code, &FileType::Ruby, &mut report);

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

        extract_imports(code, &FileType::Python, &mut report);

        let import_symbols: Vec<&str> = report.imports.iter().map(|i| i.symbol.as_str()).collect();
        assert!(import_symbols.contains(&"socket"), "Missing socket import");
        assert!(import_symbols.contains(&"os"), "Missing os import");
        assert!(import_symbols.contains(&"urllib"), "Missing urllib import");
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

        extract_imports(code, &FileType::Go, &mut report);

        let import_symbols: Vec<&str> = report.imports.iter().map(|i| i.symbol.as_str()).collect();
        assert!(import_symbols.contains(&"net"), "Missing net import");
        assert!(
            import_symbols.contains(&"os/exec"),
            "Missing os/exec import"
        );
        assert!(import_symbols.contains(&"fmt"), "Missing fmt import");
    }
}
