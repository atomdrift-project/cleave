//! Common utilities for language analyzers.
//!
//! This module provides shared functionality to ensure consistency across
//! all language analyzers. When implementing a new language analyzer, use
//! these utilities to maintain consistency with existing analyzers.

use crate::types::{Evidence, StructuralFeature};
use sha2::{Digest, Sha256};

/// Calculate SHA256 hash of data.
///
/// All analyzers should use this function to ensure consistent hashing behavior.
///
/// # Examples
///
/// ```ignore
/// let sha256 = calculate_sha256(content.as_bytes());
/// ```
#[must_use]
pub(crate) fn calculate_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Create a structural feature indicating the source code language.
///
/// This ensures all language analyzers create consistent structural features
/// that can be used for filtering and categorization.
///
/// # Arguments
///
/// * `language` - The language identifier (e.g., "python", "ruby", "javascript")
/// * `parser_name` - The parser used (e.g., "tree-sitter-python")
/// * `description` - Human-readable description (e.g., "Python script")
///
/// # Examples
///
/// ```ignore
/// let feature = create_language_feature("python", "tree-sitter-python", "Python script");
/// report.structure.push(feature);
/// ```
#[must_use]
pub(crate) fn create_language_feature(
    language: &str,
    parser_name: &str,
    description: &str,
) -> StructuralFeature {
    StructuralFeature {
        id: format!("source/language/{}", language),
        desc: description.to_string(),
        evidence: vec![Evidence {
            method: "parser".to_string(),
            source: parser_name.to_string(),
            value: language.to_string(),
            location: Some("AST".to_string()),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_sha256() {
        let data = b"test data";
        let hash = calculate_sha256(data);
        assert_eq!(hash.len(), 64); // SHA256 produces 64 hex characters
                                    // SHA256 of "test data"
        assert_eq!(
            hash,
            "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
        );
    }

    #[test]
    fn test_calculate_sha256_empty() {
        let hash = calculate_sha256(b"");
        assert_eq!(hash.len(), 64);
        // SHA256 of empty string
        assert_eq!(
            hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_create_language_feature() {
        let feature = create_language_feature("python", "tree-sitter-python", "Python script");

        assert_eq!(feature.id, "source/language/python");
        assert_eq!(feature.desc, "Python script");
        assert_eq!(feature.evidence.len(), 1);

        let evidence = &feature.evidence[0];
        assert_eq!(evidence.method, "parser");
        assert_eq!(evidence.source, "tree-sitter-python");
        assert_eq!(evidence.value, "python");
        assert_eq!(evidence.location, Some("AST".to_string()));
    }

    #[test]
    fn test_create_language_feature_different_languages() {
        let ruby_feature = create_language_feature("ruby", "tree-sitter-ruby", "Ruby source code");
        assert_eq!(ruby_feature.id, "source/language/ruby");
        assert_eq!(ruby_feature.desc, "Ruby source code");

        let js_feature =
            create_language_feature("javascript", "tree-sitter-javascript", "JavaScript code");
        assert_eq!(js_feature.id, "source/language/javascript");
        assert_eq!(js_feature.desc, "JavaScript code");
    }
}
