//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for import_metrics module
//!
//! Comprehensive test coverage for import analysis functionality.

use super::import_metrics::analyze_imports;
use crate::types::Import;

/// Helper: Create a simple import
fn make_import(symbol: &str) -> Import {
    Import {
        symbol: symbol.to_string(),
        library: None,
        source: "test".to_string(),
    }
}

/// Helper: Create an import with library field
fn make_import_with_lib(symbol: &str, library: &str) -> Import {
    Import {
        symbol: symbol.to_string(),
        library: Some(library.to_string()),
        source: "test".to_string(),
    }
}

#[test]
fn test_analyze_imports_empty() {
    let imports: Vec<Import> = vec![];
    let metrics = analyze_imports(&imports, "python");

    assert_eq!(metrics.total, 0);
    assert_eq!(metrics.unique_modules, 0);
    assert_eq!(metrics.stdlib_count, 0);
    assert_eq!(metrics.third_party_count, 0);
    assert_eq!(metrics.dynamic_imports, 0);
    assert_eq!(metrics.wildcard_imports, 0);
}

#[test]
fn test_analyze_imports_python_stdlib() {
    let imports = vec![
        make_import("os"),
        make_import("sys"),
        make_import("json"),
        make_import("pathlib"),
    ];

    let metrics = analyze_imports(&imports, "python");

    assert_eq!(metrics.total, 4);
    assert_eq!(metrics.unique_modules, 4);
    assert_eq!(metrics.stdlib_count, 4);
    assert_eq!(metrics.third_party_count, 0);
    assert_eq!(metrics.stdlib_ratio, 1.0);
    assert_eq!(metrics.third_party_ratio, 0.0);
}

#[test]
fn test_analyze_imports_python_third_party() {
    let imports = vec![
        make_import("requests"),
        make_import("numpy"),
        make_import("pandas"),
    ];

    let metrics = analyze_imports(&imports, "python");

    assert_eq!(metrics.total, 3);
    assert_eq!(metrics.stdlib_count, 0);
    assert_eq!(metrics.third_party_count, 3);
    assert_eq!(metrics.third_party_ratio, 1.0);
}

#[test]
fn test_analyze_imports_python_mixed() {
    let imports = vec![
        make_import("os"),
        make_import("sys"),
        make_import("requests"),
        make_import("flask"),
    ];

    let metrics = analyze_imports(&imports, "python");

    assert_eq!(metrics.total, 4);
    assert_eq!(metrics.stdlib_count, 2);
    assert_eq!(metrics.third_party_count, 2);
    assert_eq!(metrics.stdlib_ratio, 0.5);
    assert_eq!(metrics.third_party_ratio, 0.5);
}

#[test]
fn test_analyze_imports_python_submodules() {
    let imports = vec![
        make_import("os.path"),
        make_import("collections.abc"),
        make_import("urllib.request"),
    ];

    let metrics = analyze_imports(&imports, "python");

    // All are stdlib (extracts top-level module name)
    assert_eq!(metrics.stdlib_count, 3);
    assert_eq!(metrics.third_party_count, 0);
}

#[test]
fn test_analyze_imports_relative_imports() {
    let imports = vec![
        make_import("./module"),
        make_import("../parent"),
        make_import(".hidden"),
    ];

    let metrics = analyze_imports(&imports, "python");

    assert_eq!(metrics.relative_imports, 3);
    assert_eq!(metrics.relative_ratio, 1.0);
}

#[test]
fn test_analyze_imports_dynamic_imports() {
    let imports = vec![
        make_import("__import__"),
        make_import("importlib.import_module"),
        make_import("require"),
    ];

    let metrics = analyze_imports(&imports, "python");

    assert_eq!(metrics.dynamic_imports, 3);
}

#[test]
fn test_analyze_imports_wildcard_imports() {
    let imports = vec![
        make_import("module.*"),
        make_import("package*"),
    ];

    let metrics = analyze_imports(&imports, "python");

    assert_eq!(metrics.wildcard_imports, 2);
}

#[test]
fn test_analyze_imports_aliased_imports() {
    let imports = vec![
        make_import("module as m"),
        make_import_with_lib("pandas", "pd"),
    ];

    let metrics = analyze_imports(&imports, "python");

    assert_eq!(metrics.aliased_imports, 2);
}

#[test]
fn test_analyze_imports_unique_modules() {
    let imports = vec![
        make_import("os"),
        make_import("os.path"),
        make_import("os.path.join"),
        make_import("sys"),
    ];

    let metrics = analyze_imports(&imports, "python");

    assert_eq!(metrics.total, 4);
    assert_eq!(metrics.unique_modules, 4);
}

#[test]
fn test_analyze_imports_duplicate_modules() {
    let imports = vec![
        make_import("requests"),
        make_import("requests"),
        make_import("requests"),
    ];

    let metrics = analyze_imports(&imports, "python");

    assert_eq!(metrics.total, 3);
    assert_eq!(metrics.unique_modules, 1);
}

#[test]
fn test_analyze_imports_javascript() {
    let imports = vec![
        make_import("fs"),
        make_import("path"),
        make_import("express"),
    ];

    let metrics = analyze_imports(&imports, "javascript");

    assert_eq!(metrics.total, 3);
    assert_eq!(metrics.stdlib_count, 2);
    assert_eq!(metrics.third_party_count, 1);
}

#[test]
fn test_analyze_imports_javascript_with_node_prefix() {
    let imports = vec![
        make_import("node:fs"),
        make_import("node:path"),
        make_import("express"),
    ];

    let metrics = analyze_imports(&imports, "javascript");

    assert_eq!(metrics.stdlib_count, 2);
    assert_eq!(metrics.third_party_count, 1);
}

#[test]
fn test_analyze_imports_go() {
    let imports = vec![
        make_import("fmt"),
        make_import("net/http"),
        make_import("github.com/foo/bar"),
    ];

    let metrics = analyze_imports(&imports, "go");

    assert_eq!(metrics.total, 3);
    assert_eq!(metrics.stdlib_count, 2);
    assert_eq!(metrics.third_party_count, 1);
}

#[test]
fn test_analyze_imports_ruby() {
    let imports = vec![
        make_import("json"),
        make_import("yaml"),
        make_import("rails"),
    ];

    let metrics = analyze_imports(&imports, "ruby");

    assert_eq!(metrics.stdlib_count, 2);
    assert_eq!(metrics.third_party_count, 1);
}

#[test]
fn test_analyze_imports_perl() {
    let imports = vec![
        make_import("strict"),
        make_import("warnings"),
        make_import("File::Path"),
        make_import("Moose"),
    ];

    let metrics = analyze_imports(&imports, "perl");

    assert_eq!(metrics.stdlib_count, 3);
    assert_eq!(metrics.third_party_count, 1);
}

#[test]
fn test_analyze_imports_lua() {
    let imports = vec![
        make_import("io"),
        make_import("os"),
        make_import("luasocket"),
    ];

    let metrics = analyze_imports(&imports, "lua");

    assert_eq!(metrics.stdlib_count, 2);
    assert_eq!(metrics.third_party_count, 1);
}

#[test]
fn test_analyze_imports_unknown_file_type() {
    let imports = vec![
        make_import("some_module"),
    ];

    let metrics = analyze_imports(&imports, "unknown");

    // All should be counted as third-party for unknown file types
    assert_eq!(metrics.stdlib_count, 0);
    assert_eq!(metrics.third_party_count, 1);
}

#[test]
fn test_analyze_imports_complex_scenario() {
    let imports = vec![
        make_import("os"),               // stdlib
        make_import("sys"),              // stdlib
        make_import("requests"),         // third-party
        make_import("./local"),          // relative
        make_import("module.*"),         // wildcard
        make_import("pkg as p"),         // aliased
        make_import("__import__"),       // dynamic
    ];

    let metrics = analyze_imports(&imports, "python");

    assert_eq!(metrics.total, 7);
    assert_eq!(metrics.stdlib_count, 2);
    assert_eq!(metrics.third_party_count, 5);
    assert_eq!(metrics.relative_imports, 1);
    assert_eq!(metrics.wildcard_imports, 1);
    assert_eq!(metrics.aliased_imports, 1);
    assert_eq!(metrics.dynamic_imports, 1);
}

#[test]
fn test_analyze_imports_ratios_precision() {
    let imports = vec![
        make_import("os"),
        make_import("sys"),
        make_import("requests"),
    ];

    let metrics = analyze_imports(&imports, "python");

    // 2 stdlib out of 3 total = 0.666...
    assert!((metrics.stdlib_ratio - 0.666666).abs() < 0.001);
    assert!((metrics.third_party_ratio - 0.333333).abs() < 0.001);
}

#[test]
fn test_analyze_imports_zero_ratio_when_empty() {
    let imports: Vec<Import> = vec![];
    let metrics = analyze_imports(&imports, "python");

    assert_eq!(metrics.stdlib_ratio, 0.0);
    assert_eq!(metrics.third_party_ratio, 0.0);
    assert_eq!(metrics.relative_ratio, 0.0);
}

#[test]
fn test_analyze_imports_all_metrics_combined() {
    let imports = vec![
        make_import("os"),           // stdlib
        make_import("sys"),          // stdlib
        make_import("requests"),     // third-party
        make_import("./utils"),      // relative
        make_import("../config"),    // relative
        make_import("lib.*"),        // wildcard
        make_import("np as numpy"),  // aliased
        make_import("__import__"),   // dynamic
    ];

    let metrics = analyze_imports(&imports, "python");

    assert_eq!(metrics.total, 8);
    assert_eq!(metrics.unique_modules, 8);
    assert_eq!(metrics.stdlib_count, 2);
    assert_eq!(metrics.third_party_count, 6);
    assert_eq!(metrics.relative_imports, 2);
    assert_eq!(metrics.wildcard_imports, 1);
    assert_eq!(metrics.aliased_imports, 1);
    assert_eq!(metrics.dynamic_imports, 1);
}
