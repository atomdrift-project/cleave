//! Tests for cleave's string conversion + classification layer.
//!
//! String *extraction* lives in filefacts/stng (see their test suites);
//! cleave converts the resulting `ExtractedString` rows into `StringInfo`
//! and applies symbol-map classification. These tests cover that layer.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::strings::StringExtractor;
use stng::{ExtractedString, StringMethod};

#[test]
fn test_symbol_map_enrichment() {
    let mut imports = std::collections::HashSet::new();
    imports.insert("malloc".to_string());
    let extractor = StringExtractor::new().with_imports(&imports);

    // A string matching a known import is classified as Import by the
    // conversion layer (filefacts/stng supplies the raw row).
    let raw = vec![ExtractedString {
        value: "malloc".to_string(),
        data_offset: 0,
        method: StringMethod::RawScan,
        kind: None,
        ..ExtractedString::default()
    }];
    let strings = extractor.convert_stng_strings(&raw);
    let malloc = strings.iter().find(|s| s.value == "malloc");
    assert_eq!(
        malloc.and_then(|s| s.string_type),
        Some(crate::types::StringType::Import)
    );
}
