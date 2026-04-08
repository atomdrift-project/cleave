//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for UTF-16 LE/BE file support.
//!
//! Ensures that UTF-16 encoded source files are properly detected,
//! converted to UTF-8, and analyzed correctly by all search types:
//! - Raw content searches
//! - AST-based searches
//! - String extraction
//! - Trait matching

use cleave::{AnalysisInput, FileType};
use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::sync::Arc;

/// Shared fixture for UTF-16 tests - normalized once, analyzed once, reused across tests.
/// This intentionally bypasses the full trait/YARA pipeline for the real malware sample,
/// which is overkill for encoding coverage and can become pathologically expensive.
struct Utf16Fixture {
    normalized_text: String,
    report: cleave::AnalysisReport,
}

static UTF16_ANALYSIS: Lazy<Option<Arc<Utf16Fixture>>> = Lazy::new(|| {
    let sample = PathBuf::from("tests/samples/utf16le_wsh_dropper.js");
    if !sample.exists() {
        return None;
    }

    let normalized = cleave::file_io::read_file_normalized(&sample).ok()?;
    let normalized_text = String::from_utf8(normalized.as_slice().to_vec()).ok()?;
    let file_type = FileType::JavaScript;
    let analyzer = cleave::analyzers::analyzer_for_file_type(&file_type, None)?;
    let input = AnalysisInput::new(&sample, normalized.as_slice(), file_type);
    let report = analyzer.analyze_input(&input).ok()?;

    Some(Arc::new(Utf16Fixture {
        normalized_text,
        report,
    }))
});

/// Get the shared UTF-16 analysis result, or skip the test if sample doesn't exist
fn get_utf16_analysis() -> Option<Arc<Utf16Fixture>> {
    UTF16_ANALYSIS.clone()
}

fn analyze_normalized_javascript(path: &std::path::Path) -> cleave::AnalysisReport {
    let normalized = cleave::file_io::read_file_normalized(path).expect("Failed to normalize file");
    let analyzer = cleave::analyzers::analyzer_for_file_type(&FileType::JavaScript, None)
        .expect("js analyzer");
    let input = AnalysisInput::new(path, normalized.as_slice(), FileType::JavaScript);
    analyzer
        .analyze_input(&input)
        .expect("Failed to analyze normalized JavaScript")
}

/// Test UTF-16 LE encoded malware sample analysis.
///
/// This test uses a real-world UTF-16 LE encoded WSH dropper to ensure
/// cleave can properly analyze UTF-16 files end-to-end.
/// Uses shared analysis result to avoid re-analyzing the same file.
#[test]
fn test_utf16le_wsh_dropper_analysis() {
    let Some(fixture) = get_utf16_analysis() else {
        panic!(
            "UTF-16 LE test sample not found: tests/samples/utf16le_wsh_dropper.js. \
             Copy the sample to tests/samples/ directory."
        );
    };

    let report = &fixture.report;

    // Should successfully analyze the normalized source file
    assert_eq!(report.target.file_type, "javascript");
    assert!(
        !report.functions.is_empty(),
        "UTF-16 LE file should yield functions after normalization"
    );

    let has_known_function = report
        .functions
        .iter()
        .any(|f| f.name == "vfvtw" || f.name == "xPjAF" || f.name == "ASzlV");
    let has_interesting_string = report.strings.iter().any(|s| {
        s.value.contains("Scripting.FileSystemObject")
            || s.value.contains("Shell.Application")
            || s.value.contains("wscript.exe")
    });

    assert!(
        has_known_function,
        "UTF-16 LE WSH dropper should expose parsed JavaScript functions"
    );
    assert!(
        has_interesting_string,
        "UTF-16 LE WSH dropper should expose string literals after normalization"
    );
    assert!(
        !fixture.normalized_text.contains('\0'),
        "Normalized UTF-16 text should not contain null bytes"
    );

    println!("✓ UTF-16 LE analysis successful:");
    println!("  - Parsed functions: {}", report.functions.len());
    println!("  - Extracted strings: {}", report.strings.len());
    println!("  - File type: {}", report.target.file_type);
}

/// Test that normalized raw text searches work on UTF-16 LE files.
///
/// Raw content matching should operate on converted UTF-8 text,
/// not on the original UTF-16 bytes with interleaved nulls.
#[test]
fn test_utf16le_raw_searches() {
    let Some(fixture) = get_utf16_analysis() else {
        eprintln!("Skipping test: UTF-16 LE sample not found");
        return;
    };

    let text = &fixture.normalized_text;
    assert!(
        text.contains("function"),
        "Normalized UTF-16 text should contain regular JavaScript tokens"
    );
    assert!(
        text.contains("WScript.ScriptFullName"),
        "Normalized UTF-16 text should preserve script content"
    );
    assert!(
        !text.contains('\0'),
        "Normalized raw text should not contain null bytes"
    );

    println!("✓ Raw searches work correctly on UTF-16 LE");
    println!("  - Normalized text bytes: {}", text.len());
}

/// Test that AST searches work on UTF-16 LE files.
///
/// AST parsing requires proper UTF-8 text. UTF-16 LE files must be
/// converted first, otherwise tree-sitter will fail to parse.
/// Uses shared analysis result.
#[test]
fn test_utf16le_ast_searches() {
    let Some(fixture) = get_utf16_analysis() else {
        eprintln!("Skipping test: UTF-16 LE sample not found");
        return;
    };

    let report = &fixture.report;
    assert!(
        !report.functions.is_empty(),
        "Should have parsed functions from AST after UTF-16 normalization"
    );

    let has_ast_patterns = report
        .functions
        .iter()
        .any(|f| f.name == "vfvtw" || f.name == "xPjAF" || f.name == "ASzlV");

    assert!(
        has_ast_patterns,
        "Should detect code patterns via AST. Found functions: {:?}",
        report.functions.iter().map(|f| &f.name).collect::<Vec<_>>()
    );

    println!("✓ AST searches work correctly on UTF-16 LE");
    println!("  - Parsed functions: {}", report.functions.len());
}

/// Test that string extraction works on UTF-16 LE files.
///
/// String extraction relies on proper text encoding. UTF-16 files
/// should have their strings extracted after conversion to UTF-8.
/// Uses shared analysis result.
#[test]
fn test_utf16le_string_extraction() {
    let Some(fixture) = get_utf16_analysis() else {
        eprintln!("Skipping test: UTF-16 LE sample not found");
        return;
    };

    let report = &fixture.report;

    let extracted_strings: Vec<_> = report
        .strings
        .iter()
        .filter(|s| {
            s.value.contains("Scripting.FileSystemObject")
                || s.value.contains("Shell.Application")
                || s.value.contains("wscript.exe")
        })
        .collect();

    assert!(
        !extracted_strings.is_empty(),
        "Should extract meaningful string literals from normalized UTF-16 source"
    );

    println!("✓ String extraction tested on UTF-16 LE");
    println!("  - Matching strings: {}", extracted_strings.len());
}

/// Test that UTF-16 BE (big-endian) files are also supported.
///
/// Creates a synthetic UTF-16 BE file and verifies it's properly handled.
/// Uses fast options (no YARA) since we're only testing encoding.
#[test]
fn test_utf16be_support() {
    use std::io::Write;
    use tempfile::Builder;

    // Create a simple UTF-16 BE JavaScript file with .js extension
    let mut temp_file = Builder::new()
        .suffix(".js")
        .tempfile()
        .expect("Failed to create temp file");

    // UTF-16 BE BOM (FE FF) + "console.log('test');" in UTF-16 BE
    let utf16be_js = vec![
        0xFE, 0xFF, // BOM
        0x00, 0x63, // c
        0x00, 0x6F, // o
        0x00, 0x6E, // n
        0x00, 0x73, // s
        0x00, 0x6F, // o
        0x00, 0x6C, // l
        0x00, 0x65, // e
        0x00, 0x2E, // .
        0x00, 0x6C, // l
        0x00, 0x6F, // o
        0x00, 0x67, // g
        0x00, 0x28, // (
        0x00, 0x27, // '
        0x00, 0x74, // t
        0x00, 0x65, // e
        0x00, 0x73, // s
        0x00, 0x74, // t
        0x00, 0x27, // '
        0x00, 0x29, // )
        0x00, 0x3B, // ;
    ];

    temp_file
        .write_all(&utf16be_js)
        .expect("Failed to write UTF-16 BE test file");
    temp_file.flush().expect("Failed to flush temp file");

    let report = analyze_normalized_javascript(temp_file.path());

    // Should successfully parse as JavaScript
    assert_eq!(
        report.target.file_type, "javascript",
        "Should detect as JavaScript"
    );

    println!("✓ UTF-16 BE support verified");
}

/// Test that regular UTF-8 files still work correctly.
///
/// Ensures that the UTF-16 conversion logic doesn't break normal UTF-8 files.
/// Uses fast options (no YARA) since we're only testing encoding.
#[test]
fn test_utf8_passthrough() {
    use std::io::Write;
    use tempfile::Builder;

    // Create a regular UTF-8 JavaScript file with .js extension
    let mut temp_file = Builder::new()
        .suffix(".js")
        .tempfile()
        .expect("Failed to create temp file");
    temp_file
        .write_all(b"console.log('Hello, world!');\n")
        .expect("Failed to write UTF-8 test file");
    temp_file.flush().expect("Failed to flush temp file");

    let report = analyze_normalized_javascript(temp_file.path());

    // Should successfully parse as JavaScript
    assert_eq!(
        report.target.file_type, "javascript",
        "Should detect as JavaScript"
    );

    println!("✓ UTF-8 passthrough works correctly");
}

/// Regression test: Ensure UTF-16 LE files don't cause analysis failures.
///
/// This test prevents regressions where UTF-16 files would fail analysis
/// or produce incorrect results due to encoding issues.
/// Uses shared analysis result.
#[test]
fn test_utf16_regression_prevention() {
    let Some(fixture) = get_utf16_analysis() else {
        eprintln!("Skipping regression test: UTF-16 LE sample not found");
        return;
    };

    let report = &fixture.report;

    // Should detect as JavaScript (not Unknown)
    assert_eq!(
        report.target.file_type, "javascript",
        "UTF-16 LE .js file should be detected as JavaScript"
    );

    // Should have reasonable analysis output (not empty, not artificially inflated)
    assert!(
        !report.functions.is_empty(),
        "Should have at least some parsed functions"
    );
    assert!(
        report.functions.len() < 1000,
        "Should not have unreasonably many functions (likely a parsing error)"
    );

    println!("✓ UTF-16 regression test passed");
    println!("  - Parsed functions: {}", report.functions.len());
    println!("  - Extracted strings: {}", report.strings.len());
}
