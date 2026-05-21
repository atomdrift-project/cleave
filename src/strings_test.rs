//! Tests for string extraction.
//!
//! String classification is handled by stng — see stng's own test suite
//! for classification coverage. These tests verify cleave's extraction
//! pipeline and stng integration.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::strings::StringExtractor;

#[test]
fn test_woff2_malware_extraction() {
    let data = std::fs::read("tests/testdata/malware/fa-brands-regular.woff2").unwrap();
    let extractor = StringExtractor::default();
    let strings = extractor.extract_smart(&data);
    assert!(
        !strings.is_empty(),
        "WOFF2 fixture should yield extracted strings"
    );
}

#[test]
fn test_extract_smart_empty() {
    let extractor = StringExtractor::new();
    let strings = extractor.extract_smart(b"");
    assert!(strings.is_empty());
}

#[test]
fn test_extract_smart_basic() {
    let data = b"Hello World\0http://example.com\0/usr/bin/ls\0";
    let extractor = StringExtractor::new();
    let strings = extractor.extract_smart(data);
    assert!(!strings.is_empty());
}

#[test]
fn test_normalize_symbol() {
    assert_eq!(
        StringExtractor::normalize_symbol("sym.imp.malloc"),
        "malloc"
    );
    assert_eq!(StringExtractor::normalize_symbol("fcn.main"), "main");
    assert_eq!(StringExtractor::normalize_symbol("_printf"), "printf");
    assert_eq!(StringExtractor::normalize_symbol("normal"), "normal");
}

#[test]
fn test_symbol_map_enrichment() {
    let mut imports = std::collections::HashSet::new();
    imports.insert("malloc".to_string());
    let extractor = StringExtractor::new().with_imports(&imports);

    // Symbol map should contain the normalized import
    let data = b"malloc\0";
    let strings = extractor.extract_smart(data);
    if let Some(s) = strings.iter().find(|s| s.value == "malloc") {
        assert_eq!(s.string_type, Some(crate::types::StringType::Import));
    }
}
