//! Analysis input types for unified data flow.
//!
//! This module provides the `AnalysisInput` struct that carries pre-extracted
//! data to analyzers, eliminating redundant file reads and string extraction.

use crate::analyzers::FileType;
use crate::types::ExtractedPayload;
use std::path::Path;
use std::sync::Arc;

/// Pre-extracted data passed to analyzers.
///
/// All analyzers receive the same input, using what they need:
/// - Binary analyzers use `data` for parsing structures
/// - Source analyzers use `strings` for trait matching
/// - Manifest analyzers parse `data` as JSON/XML
///
/// This eliminates:
/// - Multiple file reads (data read once at entry point)
/// - Duplicate string extraction (stng called once)
/// - Duplicate payload extraction (encoded_payload extractor called once)
/// - Inconsistent behavior between entry points
#[derive(Debug)]
#[allow(dead_code)] // Fields intentionally public for library consumers and future use
pub struct AnalysisInput<'a> {
    /// Path to the file (may be virtual for archive entries)
    pub path: &'a Path,

    /// Raw file bytes (already read from disk or extracted from archive)
    pub data: &'a [u8],

    /// Pre-extracted strings from stng library
    pub strings: &'a [stng::ExtractedString],

    /// Pre-extracted encoded payloads
    pub payloads: &'a [ExtractedPayload],

    /// Detected file type
    pub file_type: FileType,

    /// Optional SHA256 hash (memoized if computed during extraction)
    pub sha256: Option<String>,

    /// Nesting depth (0 for top-level, incremented for archives/encoded payloads)
    pub depth: u32,

    /// Per-request cancellation flag. When set to true by the server on timeout, analyzers that
    /// check it should abort long-running loops and return a partial result.
    pub cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
}

#[allow(dead_code)] // Methods intentionally public for library consumers and future use
impl<'a> AnalysisInput<'a> {
    /// Create new input with required fields and empty strings.
    #[must_use]
    pub fn new(path: &'a Path, data: &'a [u8], file_type: FileType) -> Self {
        Self {
            path,
            data,
            strings: &[],
            payloads: &[],
            file_type,
            sha256: None,
            depth: 0,
            cancellation: None,
        }
    }

    /// Create input with all fields specified (except payloads).
    #[must_use]
    pub fn with_strings(
        path: &'a Path,
        data: &'a [u8],
        strings: &'a [stng::ExtractedString],
        file_type: FileType,
    ) -> Self {
        Self {
            path,
            data,
            strings,
            payloads: &[],
            file_type,
            sha256: None,
            depth: 0,
            cancellation: None,
        }
    }

    /// Create input with strings and payloads.
    #[must_use]
    pub fn with_payloads(
        path: &'a Path,
        data: &'a [u8],
        strings: &'a [stng::ExtractedString],
        payloads: &'a [ExtractedPayload],
        file_type: FileType,
    ) -> Self {
        Self {
            path,
            data,
            strings,
            payloads,
            file_type,
            sha256: None,
            depth: 0,
            cancellation: None,
        }
    }

    /// Add memoized SHA256 hash.
    #[must_use]
    pub fn with_sha256(mut self, sha256: String) -> Self {
        self.sha256 = Some(sha256);
        self
    }

    /// Get SHA256 (computes if not already memoized).
    #[must_use]
    pub fn sha256(&self) -> String {
        if let Some(ref hash) = self.sha256 {
            hash.clone()
        } else {
            crate::analyzers::utils::calculate_sha256(self.data)
        }
    }

    /// Set nesting depth (for archive members or encoded payloads).
    #[must_use]
    pub fn at_depth(mut self, depth: u32) -> Self {
        self.depth = depth;
        self
    }

    /// Get file content as UTF-8 string (lossy conversion).
    #[must_use]
    pub fn content_lossy(&self) -> std::borrow::Cow<'a, str> {
        String::from_utf8_lossy(self.data)
    }

    /// Check if strings were provided.
    #[must_use]
    pub fn has_strings(&self) -> bool {
        !self.strings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_analysis_input_new() {
        let path = PathBuf::from("test.py");
        let data = b"print('hello')";
        let input = AnalysisInput::new(&path, data, FileType::Python);

        assert_eq!(input.path, Path::new("test.py"));
        assert_eq!(input.data, b"print('hello')");
        assert!(input.strings.is_empty());
        assert_eq!(input.file_type, FileType::Python);
        assert_eq!(input.depth, 0);
    }

    #[test]
    fn test_analysis_input_at_depth() {
        let path = PathBuf::from("nested.js");
        let data = b"console.log('hi')";
        let input = AnalysisInput::new(&path, data, FileType::JavaScript).at_depth(2);

        assert_eq!(input.depth, 2);
    }

    #[test]
    fn test_content_lossy() {
        let path = PathBuf::from("test.txt");
        let data = b"hello world";
        let input = AnalysisInput::new(&path, data, FileType::Unknown);

        assert_eq!(input.content_lossy(), "hello world");
    }
}
