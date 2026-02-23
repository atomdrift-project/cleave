//! Dynamic field path validation for metrics
//!
//! Provides a trait-based system for validating metric field references in YAML rules
//! without hardcoding field names.

use std::collections::HashSet;

/// Trait for types that can declare their valid field paths
pub(crate) trait ValidFieldPaths {
    /// Returns all valid field paths for this type
    /// For example, BinaryMetrics might return ["code_to_data_ratio", "string_count", ...]
    fn valid_field_paths() -> Vec<&'static str>;
}

/// Returns all valid metric field paths for use in YAML rules
/// Returns paths like "binary.code_to_data_ratio", "text.line_count", etc.
#[must_use]
pub(crate) fn all_valid_metric_paths() -> HashSet<String> {
    // Import the trait to access its methods
    use super::field_paths::ValidFieldPaths;

    let mut paths = HashSet::new();

    // Import all metrics types
    use super::binary_metrics::{
        BinaryMetrics, ElfMetrics, JavaClassMetrics, MachoMetrics, PeMetrics,
    };
    use super::container_metrics::{ArchiveMetrics, PackageJsonMetrics};
    use super::language_metrics::{
        CMetrics, CSharpMetrics, GoMetrics, JavaScriptMetrics, JavaSourceMetrics, LuaMetrics,
        PerlMetrics, PhpMetrics, PowerShellMetrics, PythonMetrics, RubyMetrics, RustMetrics,
        ShellMetrics,
    };
    use super::scores::{ObfuscationScore, PackingScore, SupplyChainScore};
    use super::text_metrics::{
        CommentMetrics, FunctionMetrics, IdentifierMetrics, ImportMetrics, StatementMetrics,
        StringMetrics, TextMetrics,
    };

    // Add paths for each metrics section
    for field in TextMetrics::valid_field_paths() {
        paths.insert(format!("text.{}", field));
    }
    for field in IdentifierMetrics::valid_field_paths() {
        paths.insert(format!("identifiers.{}", field));
    }
    for field in StringMetrics::valid_field_paths() {
        paths.insert(format!("strings.{}", field));
    }
    for field in CommentMetrics::valid_field_paths() {
        paths.insert(format!("comments.{}", field));
    }
    for field in FunctionMetrics::valid_field_paths() {
        paths.insert(format!("functions.{}", field));
    }
    for field in StatementMetrics::valid_field_paths() {
        paths.insert(format!("statements.{}", field));
    }
    for field in ImportMetrics::valid_field_paths() {
        paths.insert(format!("imports.{}", field));
    }

    // Language-specific metrics
    for field in PythonMetrics::valid_field_paths() {
        paths.insert(format!("python.{}", field));
    }
    for field in JavaScriptMetrics::valid_field_paths() {
        paths.insert(format!("javascript.{}", field));
    }
    for field in PowerShellMetrics::valid_field_paths() {
        paths.insert(format!("powershell.{}", field));
    }
    for field in ShellMetrics::valid_field_paths() {
        paths.insert(format!("shell.{}", field));
    }
    for field in PhpMetrics::valid_field_paths() {
        paths.insert(format!("php.{}", field));
    }
    for field in RubyMetrics::valid_field_paths() {
        paths.insert(format!("ruby.{}", field));
    }
    for field in PerlMetrics::valid_field_paths() {
        paths.insert(format!("perl.{}", field));
    }
    for field in GoMetrics::valid_field_paths() {
        paths.insert(format!("go_metrics.{}", field));
    }
    for field in RustMetrics::valid_field_paths() {
        paths.insert(format!("rust_metrics.{}", field));
    }
    for field in CMetrics::valid_field_paths() {
        paths.insert(format!("c_metrics.{}", field));
    }
    for field in JavaSourceMetrics::valid_field_paths() {
        paths.insert(format!("java.{}", field));
    }
    for field in LuaMetrics::valid_field_paths() {
        paths.insert(format!("lua.{}", field));
    }
    for field in CSharpMetrics::valid_field_paths() {
        paths.insert(format!("csharp.{}", field));
    }

    // Binary-specific metrics
    for field in BinaryMetrics::valid_field_paths() {
        paths.insert(format!("binary.{}", field));
    }
    for field in ElfMetrics::valid_field_paths() {
        paths.insert(format!("elf.{}", field));
    }
    for field in PeMetrics::valid_field_paths() {
        paths.insert(format!("pe.{}", field));
    }
    for field in MachoMetrics::valid_field_paths() {
        paths.insert(format!("macho.{}", field));
    }
    for field in JavaClassMetrics::valid_field_paths() {
        paths.insert(format!("java_class.{}", field));
    }

    // Container/Archive metrics
    for field in ArchiveMetrics::valid_field_paths() {
        paths.insert(format!("archive.{}", field));
    }
    for field in PackageJsonMetrics::valid_field_paths() {
        paths.insert(format!("package_json.{}", field));
    }

    // Composite scores
    for field in ObfuscationScore::valid_field_paths() {
        paths.insert(format!("obfuscation.{}", field));
    }
    for field in PackingScore::valid_field_paths() {
        paths.insert(format!("packing.{}", field));
    }
    for field in SupplyChainScore::valid_field_paths() {
        paths.insert(format!("supply_chain.{}", field));
    }

    paths
}
