//! Abstract AST kind mapping to tree-sitter node types.
//!
//! Maps normalized kind names (like "call", "function", "class") to
//! language-specific tree-sitter node types. This allows rules to be
//! written once and work across multiple languages.

use crate::composite_rules::types::FileType;

/// Map an abstract kind to language-specific tree-sitter node types.
/// Returns multiple node types since some kinds map to several node types per language.
#[must_use]
pub(crate) fn map_kind_to_node_types(kind: &str, file_type: FileType) -> &'static [&'static str] {
    match kind {
        "call" => match file_type {
            FileType::Python | FileType::Elixir => &["call"],
            FileType::JavaScript
            | FileType::TypeScript
            | FileType::Go
            | FileType::C
            | FileType::ObjectiveC
            | FileType::Rust
            | FileType::Swift
            | FileType::Scala
            | FileType::Zig => &["call_expression"],
            FileType::Ruby => &["call", "method_call"],
            FileType::Java => &["method_invocation"],
            FileType::CSharp => &["invocation_expression"],
            FileType::Php => &["function_call_expression", "member_call_expression"],
            FileType::Shell => &["command"],
            FileType::Makefile => &["recipe"],
            FileType::Lua | FileType::Perl => &["function_call"],
            FileType::PowerShell => &["command_expression", "invocation_expression"],
            FileType::Groovy => &["method_call"],
            _ => &[],
        },

        "function" => match file_type {
            FileType::Python
            | FileType::C
            | FileType::ObjectiveC
            | FileType::Shell
            | FileType::Scala => &["function_definition"],
            FileType::JavaScript | FileType::TypeScript => &[
                "function_declaration",
                "arrow_function",
                "function_expression",
            ],
            FileType::Ruby => &["method", "singleton_method"],
            FileType::Go => &["function_declaration", "method_declaration"],
            FileType::Rust => &["function_item"],
            FileType::Java | FileType::CSharp => &["method_declaration"],
            FileType::Php => &["function_definition", "method_declaration"],
            FileType::Lua => &["function_definition", "local_function_definition_statement"],
            FileType::Perl => &["subroutine_declaration_statement"],
            FileType::PowerShell => &["function_statement"],
            FileType::Swift | FileType::Zig => &["function_declaration"],
            FileType::Groovy => &["method_definition"],
            FileType::Elixir => &["call"], // def/defp are function calls in Elixir AST
            FileType::Makefile => &["rule"],
            _ => &[],
        },

        "class" => match file_type {
            FileType::Python | FileType::Groovy | FileType::Scala => &["class_definition"],
            FileType::JavaScript | FileType::TypeScript => &["class_declaration", "class"],
            FileType::Ruby => &["class", "singleton_class"],
            FileType::Go => &["type_declaration"],
            FileType::C => &["struct_specifier"],
            FileType::ObjectiveC => &["class_interface", "class_implementation"],
            FileType::Rust => &["struct_item", "impl_item"],
            FileType::Java | FileType::CSharp | FileType::Php | FileType::Swift => {
                &["class_declaration"]
            }
            FileType::Perl => &["package_statement"],
            FileType::PowerShell => &["class_statement"],
            // Zig has no class construct; containers are the closest
            // declaration-level analogue and are represented by distinct
            // struct/enum/union/opaque nodes in tree-sitter-zig.
            FileType::Zig => &[
                "struct_declaration",
                "enum_declaration",
                "union_declaration",
                "opaque_declaration",
            ],
            FileType::Elixir => &["call"], // defmodule is a function call in Elixir AST
            _ => &[],
        },

        "import" => match file_type {
            FileType::Python => &["import_statement", "import_from_statement"],
            FileType::JavaScript | FileType::TypeScript => {
                &["import_statement", "import_declaration"]
            }
            FileType::Ruby | FileType::Elixir => &["call"],
            FileType::Go
            | FileType::Java
            | FileType::Swift
            | FileType::Groovy
            | FileType::Scala => &["import_declaration"],
            FileType::C | FileType::ObjectiveC => &["preproc_include", "preproc_import"],
            FileType::Rust => &["use_declaration"],
            FileType::CSharp => &["using_directive"],
            FileType::Php => &["use_declaration", "namespace_use_declaration"],
            FileType::Shell => &["command"],     // source/. commands
            FileType::Lua => &["function_call"], // require is a function call
            FileType::Perl => &["use_statement", "require_statement"],
            FileType::PowerShell => &["using_statement"],
            FileType::Zig => &["builtin_function"], // @import
            _ => &[],
        },

        "string" => match file_type {
            FileType::Python => &["string", "concatenated_string"],
            FileType::JavaScript | FileType::TypeScript => &["string", "template_string"],
            FileType::Ruby => &["string", "string_content", "heredoc_body"],
            FileType::Go => &["interpreted_string_literal", "raw_string_literal"],
            FileType::C | FileType::ObjectiveC | FileType::Java => &["string_literal"],
            FileType::Zig => &["string", "multiline_string"],
            FileType::Rust => &["string_literal", "raw_string_literal"],
            FileType::CSharp => &["string_literal", "verbatim_string_literal"],
            FileType::Php => &["string", "encapsed_string"],
            FileType::Shell => &["string", "raw_string"],
            FileType::Lua | FileType::Groovy | FileType::Scala | FileType::Elixir => &["string"],
            FileType::Perl => &["string_literal", "interpolated_string_literal"],
            FileType::PowerShell => &["string_literal", "expandable_string_literal"],
            FileType::Swift => &["line_string_literal"],
            _ => &[],
        },

        "comment" => match file_type {
            FileType::Python
            | FileType::Ruby
            | FileType::Go
            | FileType::JavaScript
            | FileType::TypeScript
            | FileType::C
            | FileType::ObjectiveC
            | FileType::CSharp
            | FileType::Php
            | FileType::Shell
            | FileType::Lua
            | FileType::Perl
            | FileType::PowerShell
            | FileType::Groovy
            | FileType::Scala
            | FileType::Elixir => &["comment"],
            FileType::Rust | FileType::Java => &["line_comment", "block_comment"],
            FileType::Swift => &["comment", "multiline_comment"],
            FileType::Zig => &["line_comment"],
            _ => &[],
        },

        "assignment" => match file_type {
            FileType::Python => &["assignment", "augmented_assignment"],
            FileType::JavaScript | FileType::TypeScript => {
                &["assignment_expression", "variable_declaration"]
            }
            FileType::Ruby => &["assignment"],
            FileType::Go => &["short_var_declaration", "assignment_statement"],
            FileType::C
            | FileType::ObjectiveC
            | FileType::Php
            | FileType::Perl
            | FileType::PowerShell
            | FileType::Groovy => &["assignment_expression"],
            FileType::Rust => &["let_declaration"],
            FileType::Java => &["assignment_expression", "local_variable_declaration"],
            FileType::CSharp => &["assignment_expression", "local_declaration_statement"],
            FileType::Shell => &["variable_assignment"],
            FileType::Lua => &["assignment_statement"],
            FileType::Swift => &["value_binding_pattern"],
            FileType::Scala => &["val_definition", "var_definition"],
            FileType::Zig => &["assignment_expression", "variable_declaration"],
            FileType::Elixir => &["binary_operator"], // = is a binary operator in Elixir
            _ => &[],
        },

        "return" => match file_type {
            FileType::Python
            | FileType::Go
            | FileType::C
            | FileType::ObjectiveC
            | FileType::JavaScript
            | FileType::TypeScript
            | FileType::Java
            | FileType::CSharp
            | FileType::Php
            | FileType::Lua
            | FileType::PowerShell
            | FileType::Swift
            | FileType::Groovy => &["return_statement"],
            FileType::Ruby => &["return"],
            FileType::Rust | FileType::Scala | FileType::Zig | FileType::Perl => {
                &["return_expression"]
            }
            FileType::Shell => &["command"], // return is a command
            // Elixir doesn't have explicit return
            _ => &[],
        },

        "binary_op" => match file_type {
            FileType::Python => &["binary_operator", "comparison_operator", "boolean_operator"],
            FileType::JavaScript
            | FileType::TypeScript
            | FileType::Go
            | FileType::C
            | FileType::ObjectiveC
            | FileType::Rust
            | FileType::Java
            | FileType::CSharp
            | FileType::Php
            | FileType::Shell
            | FileType::Lua
            | FileType::Perl
            | FileType::PowerShell
            | FileType::Groovy
            | FileType::Zig => &["binary_expression"],
            FileType::Ruby => &["binary"],
            FileType::Swift | FileType::Scala => &["infix_expression"],
            FileType::Elixir => &["binary_operator"],
            _ => &[],
        },

        "identifier" => match file_type {
            FileType::Python
            | FileType::Ruby
            | FileType::Go
            | FileType::C
            | FileType::ObjectiveC
            | FileType::JavaScript
            | FileType::TypeScript
            | FileType::Rust
            | FileType::Java
            | FileType::CSharp
            | FileType::Lua
            | FileType::Groovy
            | FileType::Scala
            | FileType::Zig
            | FileType::Elixir => &["identifier"],
            FileType::Php => &["name"],
            FileType::Shell => &["word", "variable_name"],
            FileType::Perl => &["scalar_variable", "array_variable", "hash_variable"],
            FileType::PowerShell => &["variable"],
            FileType::Swift => &["simple_identifier"],
            _ => &[],
        },

        "attribute" => match file_type {
            FileType::Python => &["attribute"],
            FileType::JavaScript
            | FileType::TypeScript
            | FileType::PowerShell
            | FileType::Groovy => &["member_expression"],
            FileType::Ruby => &["call"], // method calls look like attribute access
            FileType::Go => &["selector_expression"],
            FileType::C
            | FileType::ObjectiveC
            | FileType::Rust
            | FileType::Lua
            | FileType::Scala
            | FileType::Zig => &["field_expression"],
            FileType::Java => &["field_access"],
            FileType::CSharp | FileType::Php => &["member_access_expression"],
            // Shell doesn't have attribute access
            FileType::Perl => &["method_call_expression"],
            FileType::Swift => &["navigation_expression"],
            FileType::Elixir => &["access_call"],
            _ => &[],
        },

        "subscript" => match file_type {
            FileType::Python => &["subscript"],
            FileType::JavaScript | FileType::TypeScript => &["subscript_expression"],
            FileType::Ruby => &["element_reference"],
            FileType::Go | FileType::Rust | FileType::PowerShell | FileType::Groovy => {
                &["index_expression"]
            }
            FileType::C | FileType::ObjectiveC | FileType::Php | FileType::Swift => {
                &["subscript_expression"]
            }
            FileType::Java => &["array_access"],
            FileType::Zig => &["index_expression"],
            FileType::CSharp => &["element_access_expression"],
            // Shell uses ${array[index]} syntax
            FileType::Lua => &["bracket_index_expression"],
            FileType::Perl => &["array_element_expression", "hash_element_expression"],
            FileType::Scala => &["call_expression"], // Scala uses apply() for indexing
            FileType::Elixir => &["access_call"],
            _ => &[],
        },

        "conditional" => match file_type {
            FileType::Python
            | FileType::C
            | FileType::ObjectiveC
            | FileType::CSharp
            | FileType::Php => &["if_statement", "conditional_expression"],
            FileType::JavaScript | FileType::TypeScript | FileType::Java | FileType::Swift => {
                &["if_statement", "ternary_expression"]
            }
            FileType::Ruby => &["if", "unless", "if_modifier", "unless_modifier"],
            FileType::Go | FileType::Lua | FileType::PowerShell | FileType::Groovy => {
                &["if_statement"]
            }
            FileType::Rust | FileType::Scala | FileType::Zig => &["if_expression"],
            FileType::Shell => &["if_statement", "case_statement"],
            FileType::Perl => &["if_statement", "unless_statement", "ternary_expression"],
            FileType::Elixir => &["call"], // if/unless are function calls in Elixir
            _ => &[],
        },

        "loop" => match file_type {
            FileType::Python | FileType::Shell | FileType::Groovy => {
                &["for_statement", "while_statement"]
            }
            FileType::JavaScript | FileType::TypeScript => &[
                "for_statement",
                "while_statement",
                "for_in_statement",
                "for_of_statement",
            ],
            FileType::Ruby => &["for", "while", "until", "while_modifier", "until_modifier"],
            FileType::Go => &["for_statement"],
            FileType::C | FileType::ObjectiveC => {
                &["for_statement", "while_statement", "do_statement"]
            }
            FileType::Rust => &["for_expression", "while_expression", "loop_expression"],
            FileType::Java => &[
                "for_statement",
                "enhanced_for_statement",
                "while_statement",
                "do_statement",
            ],
            FileType::CSharp => &[
                "for_statement",
                "foreach_statement",
                "while_statement",
                "do_statement",
            ],
            FileType::Php | FileType::PowerShell => {
                &["for_statement", "foreach_statement", "while_statement"]
            }
            FileType::Lua => &["for_statement", "while_statement", "repeat_statement"],
            FileType::Perl => &[
                "for_statement",
                "foreach_statement",
                "while_statement",
                "until_statement",
            ],
            FileType::Swift => &["for_statement", "while_statement", "repeat_while_statement"],
            FileType::Scala | FileType::Zig => &["for_expression", "while_expression"],
            FileType::Elixir => &["call"], // for/Enum.each are function calls
            _ => &[],
        },

        // If kind is not recognized, return an empty slice
        _ => &[],
    }
}
