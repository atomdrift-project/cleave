//! Abstract AST kind mapping to tree-sitter node types.
//!
//! Maps normalized kind names (like "call", "function", "class") to
//! language-specific tree-sitter node types. This allows rules to be
//! written once and work across multiple languages.

use crate::composite_rules::types::FileType;

/// Map an abstract kind to language-specific tree-sitter node types.
/// Returns multiple node types since some kinds map to several node types per language.
#[must_use]
pub(crate) fn map_kind_to_node_types(kind: &str, file_type: FileType) -> Vec<&'static str> {
    match kind {
        "call" => match file_type {
            FileType::Python | FileType::Elixir => vec!["call"],
            FileType::JavaScript
            | FileType::TypeScript
            | FileType::Go
            | FileType::C
            | FileType::ObjectiveC
            | FileType::Rust
            | FileType::Swift
            | FileType::Scala
            | FileType::Zig => vec!["call_expression"],
            FileType::Ruby => vec!["call", "method_call"],
            FileType::Java => vec!["method_invocation"],
            FileType::CSharp => vec!["invocation_expression"],
            FileType::Php => vec!["function_call_expression", "member_call_expression"],
            FileType::Shell => vec!["command"],
            FileType::Lua | FileType::Perl => vec!["function_call"],
            FileType::PowerShell => vec!["command_expression", "invocation_expression"],
            FileType::Groovy => vec!["method_call"],
            _ => vec![],
        },

        "function" => match file_type {
            FileType::Python
            | FileType::C
            | FileType::ObjectiveC
            | FileType::Shell
            | FileType::Scala => vec!["function_definition"],
            FileType::JavaScript | FileType::TypeScript => {
                vec![
                    "function_declaration",
                    "arrow_function",
                    "function_expression",
                ]
            }
            FileType::Ruby => vec!["method", "singleton_method"],
            FileType::Go => vec!["function_declaration", "method_declaration"],
            FileType::Rust => vec!["function_item"],
            FileType::Java | FileType::CSharp => vec!["method_declaration"],
            FileType::Php => vec!["function_definition", "method_declaration"],
            FileType::Lua => vec!["function_definition", "local_function_definition_statement"],
            FileType::Perl => vec!["subroutine_declaration_statement"],
            FileType::PowerShell => vec!["function_statement"],
            FileType::Swift => vec!["function_declaration"],
            FileType::Groovy => vec!["method_definition"],
            FileType::Zig => vec!["fn_decl"],
            FileType::Elixir => vec!["call"], // def/defp are function calls in Elixir AST
            _ => vec![],
        },

        "class" => match file_type {
            FileType::Python | FileType::Groovy | FileType::Scala => vec!["class_definition"],
            FileType::JavaScript | FileType::TypeScript => vec!["class_declaration", "class"],
            FileType::Ruby => vec!["class", "singleton_class"],
            FileType::Go => vec!["type_declaration"],
            FileType::C => vec!["struct_specifier"],
            FileType::ObjectiveC => vec!["class_interface", "class_implementation"],
            FileType::Rust => vec!["struct_item", "impl_item"],
            FileType::Java | FileType::CSharp | FileType::Php | FileType::Swift => {
                vec!["class_declaration"]
            }
            FileType::Perl => vec!["package_statement"],
            FileType::PowerShell => vec!["class_statement"],
            FileType::Zig => vec!["container_decl"],
            FileType::Elixir => vec!["call"], // defmodule is a function call in Elixir AST
            _ => vec![],
        },

        "import" => match file_type {
            FileType::Python => vec!["import_statement", "import_from_statement"],
            FileType::JavaScript | FileType::TypeScript => {
                vec!["import_statement", "import_declaration"]
            }
            FileType::Ruby | FileType::Elixir => vec!["call"],
            FileType::Go
            | FileType::Java
            | FileType::Swift
            | FileType::Groovy
            | FileType::Scala => {
                vec!["import_declaration"]
            }
            FileType::C | FileType::ObjectiveC => vec!["preproc_include", "preproc_import"],
            FileType::Rust => vec!["use_declaration"],
            FileType::CSharp => vec!["using_directive"],
            FileType::Php => vec!["use_declaration", "namespace_use_declaration"],
            FileType::Shell => vec!["command"], // source/. commands
            FileType::Lua => vec!["function_call"], // require is a function call
            FileType::Perl => vec!["use_statement", "require_statement"],
            FileType::PowerShell => vec!["using_statement"],
            FileType::Zig => vec!["builtin_call_expr"], // @import
            _ => vec![],
        },

        "string" => match file_type {
            FileType::Python => vec!["string", "concatenated_string"],
            FileType::JavaScript | FileType::TypeScript => vec!["string", "template_string"],
            FileType::Ruby => vec!["string", "string_content", "heredoc_body"],
            FileType::Go => vec!["interpreted_string_literal", "raw_string_literal"],
            FileType::C | FileType::ObjectiveC | FileType::Java | FileType::Zig => {
                vec!["string_literal"]
            }
            FileType::Rust => vec!["string_literal", "raw_string_literal"],
            FileType::CSharp => vec!["string_literal", "verbatim_string_literal"],
            FileType::Php => vec!["string", "encapsed_string"],
            FileType::Shell => vec!["string", "raw_string"],
            FileType::Lua | FileType::Groovy | FileType::Scala | FileType::Elixir => vec!["string"],
            FileType::Perl => vec!["string_literal", "interpolated_string_literal"],
            FileType::PowerShell => vec!["string_literal", "expandable_string_literal"],
            FileType::Swift => vec!["line_string_literal"],
            _ => vec![],
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
            | FileType::Elixir => vec!["comment"],
            FileType::Rust | FileType::Java => vec!["line_comment", "block_comment"],
            FileType::Swift => vec!["comment", "multiline_comment"],
            FileType::Zig => vec!["line_comment"],
            _ => vec![],
        },

        "assignment" => match file_type {
            FileType::Python => vec!["assignment", "augmented_assignment"],
            FileType::JavaScript | FileType::TypeScript => {
                vec!["assignment_expression", "variable_declaration"]
            }
            FileType::Ruby => vec!["assignment"],
            FileType::Go => vec!["short_var_declaration", "assignment_statement"],
            FileType::C
            | FileType::ObjectiveC
            | FileType::Php
            | FileType::Perl
            | FileType::PowerShell
            | FileType::Groovy => vec!["assignment_expression"],
            FileType::Rust => vec!["let_declaration"],
            FileType::Java => vec!["assignment_expression", "local_variable_declaration"],
            FileType::CSharp => vec!["assignment_expression", "local_declaration_statement"],
            FileType::Shell => vec!["variable_assignment"],
            FileType::Lua => vec!["assignment_statement"],
            FileType::Swift => vec!["value_binding_pattern"],
            FileType::Scala => vec!["val_definition", "var_definition"],
            FileType::Zig => vec!["var_decl"],
            FileType::Elixir => vec!["binary_operator"], // = is a binary operator in Elixir
            _ => vec![],
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
            | FileType::Groovy => vec!["return_statement"],
            FileType::Ruby => vec!["return"],
            FileType::Rust | FileType::Scala | FileType::Zig | FileType::Perl => {
                vec!["return_expression"]
            }
            FileType::Shell => vec!["command"], // return is a command
            // Elixir doesn't have explicit return
            _ => vec![],
        },

        "binary_op" => match file_type {
            FileType::Python => vec!["binary_operator", "comparison_operator", "boolean_operator"],
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
            | FileType::Zig => vec!["binary_expression"],
            FileType::Ruby => vec!["binary"],
            FileType::Swift | FileType::Scala => vec!["infix_expression"],
            FileType::Elixir => vec!["binary_operator"],
            _ => vec![],
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
            | FileType::Elixir => vec!["identifier"],
            FileType::Php => vec!["name"],
            FileType::Shell => vec!["word", "variable_name"],
            FileType::Perl => vec!["scalar_variable", "array_variable", "hash_variable"],
            FileType::PowerShell => vec!["variable"],
            FileType::Swift => vec!["simple_identifier"],
            _ => vec![],
        },

        "attribute" => match file_type {
            FileType::Python => vec!["attribute"],
            FileType::JavaScript
            | FileType::TypeScript
            | FileType::PowerShell
            | FileType::Groovy => vec!["member_expression"],
            FileType::Ruby => vec!["call"], // method calls look like attribute access
            FileType::Go => vec!["selector_expression"],
            FileType::C
            | FileType::ObjectiveC
            | FileType::Rust
            | FileType::Lua
            | FileType::Scala => {
                vec!["field_expression"]
            }
            FileType::Java | FileType::Zig => vec!["field_access"],
            FileType::CSharp | FileType::Php => vec!["member_access_expression"],
            // Shell doesn't have attribute access
            FileType::Perl => vec!["method_call_expression"],
            FileType::Swift => vec!["navigation_expression"],
            FileType::Elixir => vec!["access_call"],
            _ => vec![],
        },

        "subscript" => match file_type {
            FileType::Python => vec!["subscript"],
            FileType::JavaScript | FileType::TypeScript => vec!["subscript_expression"],
            FileType::Ruby => vec!["element_reference"],
            FileType::Go | FileType::Rust | FileType::PowerShell | FileType::Groovy => {
                vec!["index_expression"]
            }
            FileType::C | FileType::ObjectiveC | FileType::Php | FileType::Swift => {
                vec!["subscript_expression"]
            }
            FileType::Java | FileType::Zig => vec!["array_access"],
            FileType::CSharp => vec!["element_access_expression"],
            // Shell uses ${array[index]} syntax
            FileType::Lua => vec!["bracket_index_expression"],
            FileType::Perl => vec!["array_element_expression", "hash_element_expression"],
            FileType::Scala => vec!["call_expression"], // Scala uses apply() for indexing
            FileType::Elixir => vec!["access_call"],
            _ => vec![],
        },

        "conditional" => match file_type {
            FileType::Python
            | FileType::C
            | FileType::ObjectiveC
            | FileType::CSharp
            | FileType::Php => {
                vec!["if_statement", "conditional_expression"]
            }
            FileType::JavaScript | FileType::TypeScript | FileType::Java | FileType::Swift => {
                vec!["if_statement", "ternary_expression"]
            }
            FileType::Ruby => vec!["if", "unless", "if_modifier", "unless_modifier"],
            FileType::Go | FileType::Lua | FileType::PowerShell | FileType::Groovy => {
                vec!["if_statement"]
            }
            FileType::Rust | FileType::Scala | FileType::Zig => vec!["if_expression"],
            FileType::Shell => vec!["if_statement", "case_statement"],
            FileType::Perl => vec!["if_statement", "unless_statement", "ternary_expression"],
            FileType::Elixir => vec!["call"], // if/unless are function calls in Elixir
            _ => vec![],
        },

        "loop" => match file_type {
            FileType::Python | FileType::Shell | FileType::Groovy => {
                vec!["for_statement", "while_statement"]
            }
            FileType::JavaScript | FileType::TypeScript => {
                vec![
                    "for_statement",
                    "while_statement",
                    "for_in_statement",
                    "for_of_statement",
                ]
            }
            FileType::Ruby => vec!["for", "while", "until", "while_modifier", "until_modifier"],
            FileType::Go => vec!["for_statement"],
            FileType::C | FileType::ObjectiveC => {
                vec!["for_statement", "while_statement", "do_statement"]
            }
            FileType::Rust => vec!["for_expression", "while_expression", "loop_expression"],
            FileType::Java => vec![
                "for_statement",
                "enhanced_for_statement",
                "while_statement",
                "do_statement",
            ],
            FileType::CSharp => {
                vec![
                    "for_statement",
                    "foreach_statement",
                    "while_statement",
                    "do_statement",
                ]
            }
            FileType::Php | FileType::PowerShell => {
                vec!["for_statement", "foreach_statement", "while_statement"]
            }
            FileType::Lua => vec!["for_statement", "while_statement", "repeat_statement"],
            FileType::Perl => vec![
                "for_statement",
                "foreach_statement",
                "while_statement",
                "until_statement",
            ],
            FileType::Swift => vec!["for_statement", "while_statement", "repeat_while_statement"],
            FileType::Scala | FileType::Zig => vec!["for_expression", "while_expression"],
            FileType::Elixir => vec!["call"], // for/Enum.each are function calls
            _ => vec![],
        },

        // If kind is not recognized, return empty vec
        _ => vec![],
    }
}
