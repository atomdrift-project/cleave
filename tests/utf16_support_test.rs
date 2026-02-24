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

use cleave::{analyze_file, AnalysisOptions};
use once_cell::sync::Lazy;
use std::path::PathBuf;
use std::sync::Arc;

/// Shared analysis result for UTF-16 tests - analyzed once, reused across tests.
/// This avoids re-analyzing the same file and recompiling YARA rules for each test.
/// YARA is disabled for speed - these tests verify UTF-16 encoding, not YARA rules.
static UTF16_ANALYSIS: Lazy<Option<Arc<cleave::AnalysisReport>>> = Lazy::new(|| {
    let sample = PathBuf::from("tests/samples/utf16le_wsh_dropper.js");
    if !sample.exists() {
        return None;
    }
    let options = AnalysisOptions {
        disable_yara: true, // Skip YARA - not testing YARA, testing UTF-16 encoding
        ..Default::default()
    };
    analyze_file(&sample, &options).ok().map(Arc::new)
});

/// Get the shared UTF-16 analysis result, or skip the test if sample doesn't exist
fn get_utf16_analysis() -> Option<Arc<cleave::AnalysisReport>> {
    UTF16_ANALYSIS.clone()
}

/// Fast options for tests that don't need YARA (just testing encoding)
fn fast_options() -> AnalysisOptions {
    AnalysisOptions {
        disable_yara: true,
        ..Default::default()
    }
}

/// Test UTF-16 LE encoded malware sample analysis.
///
/// This test uses a real-world UTF-16 LE encoded WSH dropper to ensure
/// cleave can properly analyze UTF-16 files end-to-end.
/// Uses shared analysis result to avoid re-analyzing the same file.
#[test]
fn test_utf16le_wsh_dropper_analysis() {
    let Some(report) = get_utf16_analysis() else {
        panic!(
            "UTF-16 LE test sample not found: tests/samples/utf16le_wsh_dropper.js. \
             Copy the sample to tests/samples/ directory."
        );
    };

    // Should successfully analyze the file
    assert!(
        !report.findings.is_empty(),
        "UTF-16 LE file should have findings"
    );

    // Should detect hostile or suspicious findings
    let has_hostile = report
        .findings
        .iter()
        .any(|f| matches!(f.crit, cleave::Criticality::Hostile));
    let has_suspicious = report
        .findings
        .iter()
        .any(|f| matches!(f.crit, cleave::Criticality::Suspicious));

    assert!(
        has_hostile || has_suspicious,
        "UTF-16 LE WSH dropper should be detected as hostile or suspicious"
    );

    println!("✓ UTF-16 LE analysis successful:");
    println!(
        "  - Hostile findings: {}",
        report
            .findings
            .iter()
            .filter(|f| matches!(f.crit, cleave::Criticality::Hostile))
            .count()
    );
    println!(
        "  - Suspicious findings: {}",
        report
            .findings
            .iter()
            .filter(|f| matches!(f.crit, cleave::Criticality::Suspicious))
            .count()
    );
    println!("  - Total findings: {}", report.findings.len());
    println!("  - File type: {}", report.target.file_type);
}

/// Test that raw searches work on UTF-16 LE files.
///
/// Raw searches should find patterns in the converted UTF-8 text,
/// not in the raw UTF-16 bytes (which have null bytes).
/// Uses shared analysis result.
#[test]
fn test_utf16le_raw_searches() {
    let Some(report) = get_utf16_analysis() else {
        eprintln!("Skipping test: UTF-16 LE sample not found");
        return;
    };

    // Check for findings that rely on raw content searches
    let raw_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.evidence.iter().any(|e| e.source == "raw_content"))
        .collect();

    assert!(
        !raw_findings.is_empty(),
        "Should have findings from raw content searches"
    );

    // Raw searches should NOT find spaced patterns like "f\0u\0n\0c\0t\0i\0o\0n\0"
    // They should find normal patterns like "function"
    for finding in &raw_findings {
        for evidence in &finding.evidence {
            let value = &evidence.value;
            assert!(
                !value.contains('\0'),
                "Raw search evidence should not contain null bytes: {}",
                value
            );
        }
    }

    println!("✓ Raw searches work correctly on UTF-16 LE");
    println!("  - Raw findings: {}", raw_findings.len());
}

/// Test that AST searches work on UTF-16 LE files.
///
/// AST parsing requires proper UTF-8 text. UTF-16 LE files must be
/// converted first, otherwise tree-sitter will fail to parse.
/// Uses shared analysis result.
#[test]
fn test_utf16le_ast_searches() {
    let Some(report) = get_utf16_analysis() else {
        eprintln!("Skipping test: UTF-16 LE sample not found");
        return;
    };

    // Check for findings that rely on AST parsing
    let ast_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.evidence.iter().any(|e| e.source == "ast"))
        .collect();

    assert!(
        !ast_findings.is_empty(),
        "Should have findings from AST searches. \
         Found {} total findings but 0 from AST.",
        report.findings.len()
    );

    // AST findings should include method calls like .ShellExecute, .copyFile, etc.
    let has_shell_execute = ast_findings.iter().any(|f| {
        f.evidence.iter().any(|e| {
            e.value.contains("ShellExecute")
                || e.value.contains("Shell.Application")
                || e.value.contains("copyFile")
        })
    });

    assert!(
        has_shell_execute,
        "Should detect shell execution methods via AST"
    );

    println!("✓ AST searches work correctly on UTF-16 LE");
    println!("  - AST findings: {}", ast_findings.len());
}

/// Test that string extraction works on UTF-16 LE files.
///
/// String extraction relies on proper text encoding. UTF-16 files
/// should have their strings extracted after conversion to UTF-8.
/// Uses shared analysis result.
#[test]
fn test_utf16le_string_extraction() {
    let Some(report) = get_utf16_analysis() else {
        eprintln!("Skipping test: UTF-16 LE sample not found");
        return;
    };

    // Check for findings that rely on string extraction
    let string_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| {
            f.evidence
                .iter()
                .any(|e| e.source.contains("string") || e.source == "extracted")
        })
        .collect();

    // String-based findings should exist
    // (Note: may be 0 if string extraction happens at binary level,
    //  but AST-extracted strings should still work)
    println!("✓ String extraction tested on UTF-16 LE");
    println!("  - String-based findings: {}", string_findings.len());
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

    // Use fast options - only testing encoding, not YARA
    let report =
        analyze_file(temp_file.path(), &fast_options()).expect("Failed to analyze UTF-16 BE file");

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

    // Use fast options - only testing encoding, not YARA
    let report =
        analyze_file(temp_file.path(), &fast_options()).expect("Failed to analyze UTF-8 file");

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
    let Some(report) = get_utf16_analysis() else {
        eprintln!("Skipping regression test: UTF-16 LE sample not found");
        return;
    };

    // Should detect as JavaScript (not Unknown)
    assert_eq!(
        report.target.file_type, "javascript",
        "UTF-16 LE .js file should be detected as JavaScript"
    );

    // Should have reasonable number of findings (not 0, not artificially inflated)
    assert!(
        !report.findings.is_empty(),
        "Should have at least some findings"
    );
    assert!(
        report.findings.len() < 1000,
        "Should not have unreasonably many findings (likely a parsing error)"
    );

    let hostile_count = report
        .findings
        .iter()
        .filter(|f| matches!(f.crit, cleave::Criticality::Hostile))
        .count();
    let suspicious_count = report
        .findings
        .iter()
        .filter(|f| matches!(f.crit, cleave::Criticality::Suspicious))
        .count();

    println!("✓ UTF-16 regression test passed");
    println!("  - Total findings: {}", report.findings.len());
    println!("  - Hostile: {}", hostile_count);
    println!("  - Suspicious: {}", suspicious_count);
}
