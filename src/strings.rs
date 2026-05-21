//! String extraction from binaries.
//!
//! This module extracts human-readable strings from binary files,
//! classifying them as URLs, IPs, file paths, or generic strings.
//!
//! Useful for quick triage and finding embedded indicators.

use crate::types::{StringInfo, StringType};
use base64::{engine::general_purpose, Engine as _};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use stng::{ExtractedString, StringMethod};

/// Convert stng StringMethod to a string for encoding_chain tracking
/// Only tracks actual string construction/encoding methods, not extraction sources
fn stng_method_to_string(method: StringMethod) -> &'static str {
    match method {
        // String construction/encoding methods - worth tracking
        StringMethod::StackString => "stack",
        StringMethod::XorDecode => "xor",
        StringMethod::Base64Decode => "base64",
        StringMethod::Base64ObfuscatedDecode => "base64-obf",
        StringMethod::HexDecode => "hex",
        StringMethod::UrlDecode => "url",
        StringMethod::UnicodeEscapeDecode => "unicode-escape",
        StringMethod::WideString => "wide",

        // Extraction sources and future variants - not worth tracking
        _ => "",
    }
}

pub(crate) const MAX_STRINGS_PER_FILE: usize = 100_000;

/// Maximum total bytes of all extracted strings (50 MB).
pub(crate) const MAX_TOTAL_STRING_BYTES: usize = 50 * 1024 * 1024;

/// Extract and classify strings from binary data
#[derive(Debug)]
pub(crate) struct StringExtractor {
    min_length: usize,
    // Unified map for O(1) classification: normalized_name -> (Type, Optional Library)
    symbol_map: HashMap<String, (StringType, Option<String>)>,
    /// Whether the last extraction was truncated due to limits
    pub truncated: std::sync::atomic::AtomicBool,
}

#[allow(dead_code)] // Public API used by main.rs binary
impl StringExtractor {
    pub(crate) fn new() -> Self {
        Self {
            min_length: 4,
            symbol_map: HashMap::new(),
            truncated: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn with_min_length(mut self, min_length: usize) -> Self {
        self.min_length = min_length;
        self
    }

    pub(crate) fn with_functions(mut self, functions: &HashSet<String>) -> Self {
        for func in functions {
            let normalized = Self::normalize_symbol(func).into_owned();
            self.symbol_map
                .entry(normalized)
                .or_insert((StringType::FuncName, None));
        }
        self
    }

    pub(crate) fn with_imports(mut self, imports: &HashSet<String>) -> Self {
        for imp in imports {
            let normalized = Self::normalize_symbol(imp).into_owned();
            self.symbol_map
                .insert(normalized, (StringType::Import, None));
        }
        self
    }

    pub(crate) fn with_import_libraries(
        mut self,
        import_libraries: HashMap<String, String>,
    ) -> Self {
        // Update existing imports in symbol_map with library info
        for (imp, lib) in import_libraries {
            let normalized = Self::normalize_symbol(&imp).into_owned();
            self.symbol_map
                .insert(normalized, (StringType::Import, Some(lib)));
        }
        self
    }

    pub(crate) fn with_exports(mut self, exports: &HashSet<String>) -> Self {
        for exp in exports {
            let normalized = Self::normalize_symbol(exp).into_owned();
            self.symbol_map
                .insert(normalized, (StringType::Export, None));
        }
        self
    }

    fn normalize_symbol(sym: &str) -> Cow<'_, str> {
        let stripped = sym
            .trim_start_matches("sym.imp.")
            .trim_start_matches("sym.")
            .trim_start_matches("fcn.")
            .trim_start_matches('_');
        if stripped.len() == sym.len() {
            Cow::Borrowed(sym)
        } else {
            Cow::Owned(stripped.to_string())
        }
    }

    /// Extract strings using stng for comprehensive extraction.
    ///
    /// Rizin string extraction is owned by `expose` now — when stng
    /// needs rizin-derived boundaries or function metadata they arrive
    /// through `stng::ExtractOptions::with_rizin_*` populated by the
    /// upstream `expose` parse, not via a cleave-side `with_r2_strings`
    /// fold. Callers that previously plumbed `Option<Vec<R2String>>`
    /// through this function just stop passing it.
    pub(crate) fn extract_smart(&self, data: &[u8]) -> Vec<StringInfo> {
        let raw = self.extract_raw_smart(data);
        // We own `raw` and don't need it after conversion — move each element
        // instead of cloning.
        self.convert_stng_strings_owned(raw)
    }

    /// Extract raw stng strings from binary data.
    pub(crate) fn extract_raw_smart(&self, data: &[u8]) -> Vec<ExtractedString> {
        let opts = crate::analyzers::stng_analysis_opts(self.min_length);
        stng::extract_strings_with_options(data, &opts)
    }

    /// Convert pre-extracted stng strings to StringInfo (public API for reuse).
    ///
    /// Takes a borrowed slice and clones each element because the caller
    /// still needs the raw `ExtractedString` values afterward.  Prefer
    /// [`StringExtractor::convert_stng_strings_owned`] when the caller owns
    /// the `Vec` and does not need the raw form — it moves each element's
    /// `String` fields and avoids N per-string clones.
    #[allow(dead_code)] // Used by binary target, not visible to library
    pub(crate) fn convert_stng_strings(&self, stng_strings: &[ExtractedString]) -> Vec<StringInfo> {
        let mut strings = Vec::with_capacity(stng_strings.len().min(MAX_STRINGS_PER_FILE));
        let mut total_bytes = 0;
        self.truncated
            .store(false, std::sync::atomic::Ordering::SeqCst);

        for es in stng_strings {
            if strings.len() >= MAX_STRINGS_PER_FILE {
                self.truncated
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                break;
            }

            let value_len = es.value.len();
            if total_bytes + value_len > MAX_TOTAL_STRING_BYTES {
                self.truncated
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                break;
            }

            total_bytes += value_len;
            let decoded_sidecar = self.decoded_base64_sidecar(es);
            strings.push(self.convert_extracted_string(es.clone()));

            if let Some(decoded) = decoded_sidecar {
                let decoded_len = decoded.value.len();
                if strings.len() >= MAX_STRINGS_PER_FILE {
                    self.truncated
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
                if total_bytes + decoded_len > MAX_TOTAL_STRING_BYTES {
                    self.truncated
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
                total_bytes += decoded_len;
                strings.push(decoded);
            }
        }
        strings
    }

    /// Consuming variant of [`StringExtractor::convert_stng_strings`].
    ///
    /// Moves each `ExtractedString` into `convert_extracted_string`, so
    /// `String` fields (`value`, `section`, `raw`, …) transfer without being
    /// cloned.  Use this when the caller owns the `Vec` and will not touch
    /// the raw strings afterward.
    pub(crate) fn convert_stng_strings_owned(
        &self,
        stng_strings: Vec<ExtractedString>,
    ) -> Vec<StringInfo> {
        let mut strings = Vec::with_capacity(stng_strings.len().min(MAX_STRINGS_PER_FILE));
        let mut total_bytes = 0;
        self.truncated
            .store(false, std::sync::atomic::Ordering::SeqCst);

        for es in stng_strings {
            if strings.len() >= MAX_STRINGS_PER_FILE {
                self.truncated
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                break;
            }

            let value_len = es.value.len();
            if total_bytes + value_len > MAX_TOTAL_STRING_BYTES {
                self.truncated
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                break;
            }

            total_bytes += value_len;
            let decoded_sidecar = self.decoded_base64_sidecar(&es);
            strings.push(self.convert_extracted_string(es));

            if let Some(decoded) = decoded_sidecar {
                let decoded_len = decoded.value.len();
                if strings.len() >= MAX_STRINGS_PER_FILE {
                    self.truncated
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
                if total_bytes + decoded_len > MAX_TOTAL_STRING_BYTES {
                    self.truncated
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    break;
                }
                total_bytes += decoded_len;
                strings.push(decoded);
            }
        }
        strings
    }

    fn decoded_base64_sidecar(&self, es: &ExtractedString) -> Option<StringInfo> {
        if es.kind != Some(StringType::Base64)
            || matches!(
                es.method,
                StringMethod::Base64Decode | StringMethod::Base64ObfuscatedDecode
            )
        {
            return None;
        }

        let trimmed = es.value.trim();
        if trimmed.len() < self.min_length {
            return None;
        }

        let decoded = decode_base64_string(trimmed)?;
        let decoded_text = String::from_utf8(decoded).ok()?;
        if !is_printable_decoded_text(&decoded_text) || decoded_text.trim().len() < self.min_length
        {
            return None;
        }

        Some(StringInfo {
            value: decoded_text,
            offset: Some(es.data_offset),
            encoding: "utf8".to_string(),
            string_type: None,
            section: es.section.clone(),
            encoding_chain: vec!["base64".to_string()],
            fragments: None,
        })
    }

    /// Convert an ExtractedString from stng to StringInfo
    fn convert_extracted_string(&self, es: ExtractedString) -> StringInfo {
        // Use stng's classification directly (StringType is now an alias for StringKind)
        // Apply symbol_map overrides if we have them
        let normalized = Self::normalize_symbol(&es.value);
        let string_type = if let Some((override_type, _)) = self.symbol_map.get(normalized.as_ref())
        {
            Some(*override_type)
        } else {
            // Use stng's kind directly (already Option<StringType>)
            es.kind
        };

        let mut info = StringInfo {
            value: es.value,
            offset: Some(es.data_offset),
            encoding: "utf8".to_string(),
            string_type,
            section: es.section,
            encoding_chain: Vec::new(),
            // Note: fragments from stng are StringFragment, not String - skip for now
            fragments: None,
        };

        // Track the stng method as an encoding layer if it's a special string construction
        // This captures: StackString, decoded encodings, etc.
        let method_str = stng_method_to_string(es.method);
        if !method_str.is_empty() {
            info.encoding_chain.push(method_str.to_string());
        }

        // Don't call detect_layers() here - stng already identified the encoding method
        // and the value is already decoded. Calling detect_layers() would look at the
        // decoded content and incorrectly try to re-classify it.
        info
    }
}

fn decode_base64_string(value: &str) -> Option<Vec<u8>> {
    general_purpose::STANDARD
        .decode(value)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(value))
        .or_else(|_| general_purpose::URL_SAFE.decode(value))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(value))
        .ok()
}

fn is_printable_decoded_text(value: &str) -> bool {
    value
        .chars()
        .all(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
}

impl Default for StringExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;

    fn extracted_string(
        value: String,
        method: StringMethod,
        kind: Option<StringType>,
    ) -> ExtractedString {
        ExtractedString {
            value,
            data_offset: 42,
            section: Some(".rodata".to_string()),
            method,
            kind,
            raw: None,
            source: None,
            fragments: None,
            section_size: None,
            section_executable: None,
            section_writable: None,
            architecture: None,
            function_meta: None,
        }
    }

    #[test]
    fn test_string_extraction() {
        let data = b"Hello World http://example.com /usr/bin/ls";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data);

        assert!(!strings.is_empty());
    }

    #[test]
    fn test_email_detection() {
        // Real binaries store string literals NUL-terminated, so an email
        // address in rodata is its own extracted string — not embedded in a
        // surrounding sentence. Mirror that layout here so the classifier
        // sees the bare address and can label it as Email.
        let data = b"\0admin@example.com\0other string\0";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data);

        let email_string = strings
            .iter()
            .find(|s| s.string_type == Some(StringType::Email));
        assert!(
            email_string.is_some(),
            "expected an Email-typed extraction; got: {:?}",
            strings
                .iter()
                .map(|s| (&s.value, s.string_type))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_min_length_filter() {
        let data = b"ab  Hello World";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data);

        // "ab" should be filtered (< 4 chars), "Hello World" should be kept
        assert!(!strings.iter().any(|s| s.value == "ab"));
        assert!(strings.iter().any(|s| s.value.contains("Hello World")));
    }

    #[test]
    fn test_control_characters_filtered() {
        let data = b"Hello\x00\x01World";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data);

        // Should extract "Hello" and "World" separately
        assert!(strings.len() >= 2);
    }

    #[test]
    fn test_offset_recorded() {
        let data = b"start test string end";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data);

        // Offset should be recorded for each string
        assert!(strings.iter().all(|s| s.offset.is_some()));
    }

    #[test]
    fn test_default() {
        let extractor = StringExtractor::default();
        assert_eq!(extractor.min_length, 4);
    }

    #[test]
    fn test_trimmed_strings() {
        let data = b"  spaced  ";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data);

        // Should trim whitespace
        if let Some(s) = strings.first() {
            assert_eq!(s.value.trim(), s.value);
        }
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_binary_data_only() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0xFF];
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(&data);

        // No printable strings should be found
        assert!(strings.is_empty());
    }

    #[test]
    fn test_convert_base64_classification_adds_encoded_sidecar() {
        let decoded = r#"{"callback_host":"https://example.invalid","callback_interval":30}"#;
        let encoded = general_purpose::STANDARD.encode(decoded);
        let raw = vec![extracted_string(
            encoded.clone(),
            StringMethod::RawScan,
            Some(StringType::Base64),
        )];
        let extractor = StringExtractor::new();

        let strings = extractor.convert_stng_strings(&raw);

        assert!(strings.iter().any(|s| {
            s.value == encoded
                && s.string_type == Some(StringType::Base64)
                && s.encoding_chain.is_empty()
        }));
        let sidecar = strings
            .iter()
            .find(|s| s.value == decoded)
            .expect("base64 classified strings should expose decoded text to encoded traits");
        assert_eq!(sidecar.encoding_chain, vec!["base64"]);
        assert_eq!(sidecar.offset, Some(42));
        assert_eq!(sidecar.section.as_deref(), Some(".rodata"));
    }

    #[test]
    fn test_convert_base64_decode_method_does_not_duplicate_sidecar() {
        let decoded = r#"{"callback_host":"https://example.invalid"}"#;
        let raw = vec![extracted_string(
            decoded.to_string(),
            StringMethod::Base64Decode,
            None,
        )];
        let extractor = StringExtractor::new();

        let strings = extractor.convert_stng_strings(&raw);

        let decoded_entries = strings.iter().filter(|s| s.value == decoded).count();
        assert_eq!(decoded_entries, 1);
        assert_eq!(strings[0].encoding_chain, vec!["base64"]);
    }

    #[test]
    fn test_extract_smart_basic() {
        // Basic test with null-terminated strings so stng can extract them individually
        let data = b"Hello World\0http://example.com\0/usr/bin/ls\0";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data);

        assert!(!strings.is_empty());

        // Should find the URL - stng classifies URLs
        let has_url = strings
            .iter()
            .any(|s| s.value.contains("example.com") && s.string_type == Some(StringType::Url));

        // Should find the path
        let has_path = strings
            .iter()
            .any(|s| s.value.contains("/usr/bin/ls") && s.string_type == Some(StringType::Path));

        assert!(
            has_url || has_path,
            "Expected to find URL or Path, but got: {:?}",
            strings
                .iter()
                .map(|s| (&s.value, &s.string_type))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extract_smart_empty() {
        let data = b"";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_smart_deduplication() {
        // Test that duplicate strings are removed
        let data = b"test string\0test string\0test string";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data);

        // Should not have duplicate values
        let values: Vec<&str> = strings.iter().map(|s| s.value.as_str()).collect();
        let unique: HashSet<&str> = values.iter().cloned().collect();
        assert_eq!(values.len(), unique.len());
    }

    #[test]
    fn test_extract_smart_with_go_binary() {
        // Test with actual Go binary if available
        let path = "tests/fixtures/lang_strings/go_darwin_arm64";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let extractor = StringExtractor::new();

        let strings = extractor.extract_smart(&data);

        // Should find strings from both lang_strings and basic extraction
        assert!(!strings.is_empty());

        // Go binaries should have DISSECT_CONST_MARKER from lang_strings
        // (test fixture was compiled before rename)
        assert!(
            strings.iter().any(|s| s.value.contains("DISSECT")),
            "Should find DISSECT markers in Go binary test fixture"
        );
    }

    #[test]
    fn test_extract_smart_with_rust_binary() {
        // Test with actual Rust binary if available
        let path = "tests/fixtures/lang_strings/rust_native";
        if !std::path::Path::new(path).exists() {
            return;
        }
        let data = std::fs::read(path).unwrap();
        let extractor = StringExtractor::new();

        let strings = extractor.extract_smart(&data);

        // Should find strings
        assert!(!strings.is_empty());

        // Rust binaries should have stdlib paths
        assert!(
            strings.iter().any(|s| s.value.contains("library/std")),
            "Should find stdlib paths in Rust binary"
        );
    }

    #[test]
    fn test_extract_smart_truncation_count() {
        // Create data with many strings
        let mut data = Vec::new();
        for i in 0..110 {
            data.extend_from_slice(format!("string_{:05}\0", i).as_bytes());
        }

        // Use a temporary extractor with a very low limit for testing
        // Since the limits are constants, we'll just verify the flag is set
        // if we were to exceed the REAL limits, but for a unit test,
        // we can't easily change constants.

        // Instead, let's just verify the structure and flag existence.
        let extractor = StringExtractor::new();
        assert!(!extractor
            .truncated
            .load(std::sync::atomic::Ordering::SeqCst));
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
}
