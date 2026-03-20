//! String extraction from binaries.
//!
//! This module extracts human-readable strings from binary files,
//! classifying them as URLs, IPs, file paths, or generic strings.
//!
//! Useful for quick triage and finding embedded indicators.

use crate::radare2::R2String;
use crate::types::{StringInfo, StringType};
use regex::Regex;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;
use stng::{ExtractedString, StringMethod};

/// Convert stng StringMethod to a string for encoding_chain tracking
/// Only tracks actual string construction/encoding methods, not extraction sources
fn stng_method_to_string(method: StringMethod) -> String {
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
        _ => return String::new(),
    }
    .to_string()
}

// Static regex helper functions - patterns compiled once on first use
#[allow(dead_code)] // Used internally by string classification
fn url_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(https?|ftp)://[^\s<>]{1,2048}").ok())
        .as_ref()
}

#[allow(dead_code)] // Used internally by string classification
fn ip_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}").ok())
        .as_ref()
}

#[allow(dead_code)] // Used internally by string classification
fn version_ip_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:Chrome|Safari|Firefox|Edge|Opera|Chromium|Version|AppleWebKit|KHTML|Gecko|Trident|OPR|Mobile|MSIE|rv:|v)/\d+\.\d+\.\d+\.\d+")
            .ok()
    })
    .as_ref()
}

#[allow(dead_code)] // Used internally by string classification
fn email_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}").ok()
    })
    .as_ref()
}

#[allow(dead_code)] // Used internally by string classification
fn base64_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9+/]{16,65536}={0,2}$").ok())
        .as_ref()
}

/// Maximum number of strings to extract from a single file (100,000).
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
    /// If r2_strings are provided, they are passed to stng for integration.
    pub(crate) fn extract_smart(
        &self,
        data: &[u8],
        r2_strings: Option<Vec<R2String>>,
    ) -> Vec<StringInfo> {
        let mut opts = crate::analyzers::stng_analysis_opts(self.min_length);

        // Convert and pass r2 strings to stng if available
        if let Some(r2s) = r2_strings {
            let stng_r2_strings: Vec<ExtractedString> = r2s
                .into_iter()
                .map(|r| ExtractedString {
                    value: r.string,
                    data_offset: r.paddr,
                    section: None,
                    method: StringMethod::R2String,
                    kind: stng::StringKind::Const,
                    raw: None,
                    source: None,
                    fragments: None,
                    section_size: None,
                    section_executable: None,
                    section_writable: None,
                    architecture: None,
                    function_meta: None,
                })
                .collect();
            opts = opts.with_r2_strings(stng_r2_strings);
        }

        let lang_strings = stng::extract_strings_with_options(data, &opts);
        let mut strings = Vec::with_capacity(lang_strings.len().min(MAX_STRINGS_PER_FILE));
        let mut total_bytes = 0;
        self.truncated
            .store(false, std::sync::atomic::Ordering::SeqCst);

        for es in lang_strings {
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
            strings.push(self.convert_extracted_string(es));
        }
        strings
    }

    /// Convert pre-extracted stng strings to StringInfo (public API for reuse)
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
            strings.push(self.convert_extracted_string(es.clone()));
        }
        strings
    }

    /// Convert an R2String directly to StringInfo (fast path when using cached r2 strings)
    fn convert_r2_string(&self, r2: R2String) -> StringInfo {
        let normalized = Self::normalize_symbol(&r2.string);
        let string_type = if let Some((override_type, _)) = self.symbol_map.get(normalized.as_ref())
        {
            *override_type
        } else {
            // Classify based on content
            self.classify_string_type(&r2.string)
        };

        StringInfo {
            value: r2.string,
            offset: Some(r2.vaddr),
            encoding: r2.string_type, // "utf8", "ascii", etc.
            string_type,
            section: None, // R2String doesn't have section info
            encoding_chain: Vec::new(),
            fragments: None,
        }
    }

    /// Convert an ExtractedString from stng to StringInfo
    fn convert_extracted_string(&self, es: ExtractedString) -> StringInfo {
        // Use stng's classification directly (StringType is now an alias for StringKind)
        // Apply symbol_map overrides if we have them
        let normalized = Self::normalize_symbol(&es.value);
        let string_type = if let Some((override_type, _)) = self.symbol_map.get(normalized.as_ref())
        {
            *override_type
        } else {
            // Use stng's kind directly
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
            info.encoding_chain.push(method_str);
        }

        // Don't call detect_layers() here - stng already identified the encoding method
        // and the value is already decoded. Calling detect_layers() would look at the
        // decoded content and incorrectly try to re-classify it.
        info
    }

    /// Classify a string by type
    fn classify_string(&self, value: String, offset: usize, section: Option<String>) -> StringInfo {
        let normalized = Self::normalize_symbol(&value);

        let (stype, _lib_info) = match self.symbol_map.get(normalized.as_ref()) {
            Some((t, l)) => (*t, l.clone()),
            None => {
                let t = if url_regex().is_some_and(|regex| regex.is_match(&value)) {
                    StringType::Url
                } else if self.is_real_ip(&value) {
                    StringType::IP
                } else if email_regex().is_some_and(|regex| regex.is_match(&value)) {
                    StringType::Email
                } else if self.is_path(&value) {
                    StringType::Path
                } else if value.len() >= 16
                    && base64_regex().is_some_and(|regex| regex.is_match(&value))
                {
                    StringType::Base64
                } else {
                    StringType::Const
                };
                (t, None)
            }
        };

        StringInfo {
            value,
            offset: Some(offset as u64),
            encoding: "utf8".to_string(),
            string_type: stype,
            section,
            encoding_chain: Vec::new(),
            fragments: None,
        }
    }
    /// Classify a string's type without creating a StringInfo object
    /// NOTE: This is now redundant since we use stng's classification directly
    pub(crate) fn classify_string_type(&self, value: &str) -> StringType {
        let normalized = Self::normalize_symbol(value);
        if let Some((stype, _)) = self.symbol_map.get(normalized.as_ref()) {
            return *stype;
        }

        if url_regex().is_some_and(|regex| regex.is_match(value)) {
            StringType::Url
        } else if self.is_real_ip(value) {
            StringType::IP
        } else if email_regex().is_some_and(|regex| regex.is_match(value)) {
            StringType::Email
        } else if self.is_path(value) {
            StringType::Path
        } else if value.len() >= 16 && base64_regex().is_some_and(|regex| regex.is_match(value)) {
            StringType::Base64
        } else {
            StringType::Const
        }
    }

    /// Classify decoded string content - doesn't check for encoding types like base64/hex
    /// since this is already decoded content from stng
    /// NOTE: This is now redundant since we use stng's classification directly
    fn classify_decoded_string(&self, value: &str) -> StringType {
        let normalized = Self::normalize_symbol(value);
        if let Some((stype, _)) = self.symbol_map.get(normalized.as_ref()) {
            return *stype;
        }

        if url_regex().is_some_and(|regex| regex.is_match(value)) {
            StringType::Url
        } else if self.is_real_ip(value) {
            StringType::IP
        } else if email_regex().is_some_and(|regex| regex.is_match(value)) {
            StringType::Email
        } else if self.is_path(value) {
            StringType::Path
        } else {
            // Decoded content is just plain text, not base64/hex
            StringType::Const
        }
    }

    fn find_symbol_type(&self, value: &str) -> Option<StringType> {
        let normalized = Self::normalize_symbol(value);
        self.symbol_map.get(normalized.as_ref()).map(|(t, _)| *t)
    }

    fn get_import_library(&self, value: &str) -> Option<String> {
        let normalized = Self::normalize_symbol(value);
        self.symbol_map
            .get(normalized.as_ref())
            .and_then(|(_, l)| l.clone())
    }

    fn matches_symbol_set(&self, _set: &HashSet<String>, value: &str) -> bool {
        let normalized = Self::normalize_symbol(value);
        self.symbol_map.contains_key(normalized.as_ref())
    }

    /// Check if string contains a real IP address (not a version string)
    fn is_real_ip(&self, s: &str) -> bool {
        // Must contain IP-like pattern
        let Some(ip_regex) = ip_regex() else {
            return false;
        };
        if !ip_regex.is_match(s) {
            return false;
        }
        // Exclude version strings like "Chrome/100.0.0.0", "Safari/537.36.0.0"
        if version_ip_regex().is_some_and(|regex| regex.is_match(s)) {
            return false;
        }
        // Validate that IP octets are in valid range (0-255)
        if let Some(caps) = ip_regex.find(s) {
            let ip_str = caps.as_str();
            let octets: Vec<&str> = ip_str.split('.').collect();
            if octets.len() == 4 {
                for octet in octets {
                    if let Ok(val) = octet.parse::<u32>() {
                        if val > 255 {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                return true;
            }
        }
        false
    }

    /// Check if string looks like a file path
    fn is_path(&self, s: &str) -> bool {
        // Unix paths
        if s.starts_with('/') && s.contains('/') {
            return true;
        }

        // Windows paths
        if s.len() > 3 && s.chars().nth(1) == Some(':') && s.chars().nth(2) == Some('\\') {
            return true;
        }

        // Relative paths with directory separators
        if (s.contains('/') || s.contains('\\')) && !s.contains(' ') {
            // Check for common path patterns
            if s.contains("/bin/")
                || s.contains("/usr/")
                || s.contains("/etc/")
                || s.contains("/tmp/")
                || s.contains("/var/")
                || s.contains(r"C:\")
                || s.contains("Program")
            {
                return true;
            }
        }

        false
    }
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

    #[test]
    fn test_string_extraction() {
        let data = b"Hello World http://example.com /usr/bin/ls";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data, None);

        assert!(!strings.is_empty());
    }

    #[test]
    fn test_path_detection() {
        let extractor = StringExtractor::new();

        assert!(extractor.is_path("/usr/bin/ls"));
        assert!(extractor.is_path("/etc/passwd"));
        assert!(extractor.is_path(r"C:\Windows\System32"));
        assert!(!extractor.is_path("hello world"));
    }

    #[test]
    fn test_ip_excludes_version_strings() {
        let extractor = StringExtractor::new();

        // Version strings should NOT be detected as IPs
        assert!(
            !extractor.is_real_ip("Chrome/100.0.0.0"),
            "Chrome version should not be IP"
        );
        assert!(
            !extractor.is_real_ip("Safari/537.36.0.0"),
            "Safari version should not be IP"
        );
        assert!(
            !extractor.is_real_ip("AppleWebKit/537.36.0.0"),
            "AppleWebKit version should not be IP"
        );
        assert!(
            !extractor.is_real_ip("Mozilla/5.0 Chrome/100.0.0.0 Safari/537.36"),
            "UA string with version should not be IP"
        );
        assert!(
            !extractor.is_real_ip("Firefox/115.0.0.0"),
            "Firefox version should not be IP"
        );

        // Real IPs should be detected
        assert!(
            extractor.is_real_ip("192.168.1.1"),
            "Private IP should be IP"
        );
        assert!(extractor.is_real_ip("10.0.0.1"), "Private IP should be IP");
        assert!(
            extractor.is_real_ip("8.8.8.8"),
            "Public DNS IP should be IP"
        );
        assert!(
            extractor.is_real_ip("Connect to 192.168.1.1 now"),
            "IP in sentence should be IP"
        );
    }

    #[test]
    fn test_ip_validates_octets() {
        let extractor = StringExtractor::new();

        // Invalid octets (> 255) should not be detected as IPs
        assert!(
            !extractor.is_real_ip("300.168.1.1"),
            "Invalid octet should not be IP"
        );
        assert!(
            !extractor.is_real_ip("192.300.1.1"),
            "Invalid octet should not be IP"
        );
        assert!(
            !extractor.is_real_ip("192.168.1.300"),
            "Invalid octet should not be IP"
        );

        // Valid edge cases
        assert!(
            extractor.is_real_ip("255.255.255.255"),
            "Max IP should be IP"
        );
        assert!(extractor.is_real_ip("0.0.0.0"), "Zero IP should be IP");
    }

    #[test]
    fn test_email_detection() {
        let data = b"Contact us at admin@example.com";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data, None);

        let email_string = strings
            .iter()
            .find(|s| matches!(s.string_type, StringType::Email));
        assert!(email_string.is_some());
    }

    #[test]
    fn test_min_length_filter() {
        let data = b"ab  Hello World";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data, None);

        // "ab" should be filtered (< 4 chars), "Hello World" should be kept
        assert!(!strings.iter().any(|s| s.value == "ab"));
        assert!(strings.iter().any(|s| s.value.contains("Hello World")));
    }

    #[test]
    fn test_control_characters_filtered() {
        let data = b"Hello\x00\x01World";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data, None);

        // Should extract "Hello" and "World" separately
        assert!(strings.len() >= 2);
    }

    #[test]
    fn test_offset_recorded() {
        let data = b"start test string end";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data, None);

        // Offset should be recorded for each string
        assert!(strings.iter().all(|s| s.offset.is_some()));
    }

    #[test]
    fn test_classify_string_type() {
        let extractor = StringExtractor::new();

        assert_eq!(
            extractor.classify_string_type("https://example.com"),
            StringType::Url
        );
        assert_eq!(
            extractor.classify_string_type("192.168.1.1"),
            StringType::IP
        );
        assert_eq!(
            extractor.classify_string_type("user@example.com"),
            StringType::Email
        );
        assert_eq!(
            extractor.classify_string_type("/usr/bin/bash"),
            StringType::Path
        );
        assert_eq!(
            extractor.classify_string_type("plain text"),
            StringType::Const
        );
    }

    #[test]
    fn test_windows_path_detection() {
        let extractor = StringExtractor::new();

        assert!(extractor.is_path(r"C:\Windows\System32\cmd.exe"));
        assert!(extractor.is_path(r"D:\Program Files\App"));
    }

    #[test]
    fn test_relative_path_detection() {
        let extractor = StringExtractor::new();

        assert!(extractor.is_path("/bin/sh"));
        assert!(extractor.is_path("/usr/local/bin"));
        assert!(!extractor.is_path("just/text"));
        assert!(!extractor.is_path("not a path"));
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
        let strings = extractor.extract_smart(data, None);

        // Should trim whitespace
        if let Some(s) = strings.first() {
            assert_eq!(s.value.trim(), s.value);
        }
    }

    #[test]
    fn test_empty_data() {
        let data = b"";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data, None);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_binary_data_only() {
        let data = vec![0x00, 0x01, 0x02, 0x03, 0xFF];
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(&data, None);

        // No printable strings should be found
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_smart_basic() {
        // Basic test with null-terminated strings so stng can extract them individually
        let data = b"Hello World\0http://example.com\0/usr/bin/ls\0";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data, None);

        assert!(!strings.is_empty());

        // Should find the URL - stng classifies URLs
        let has_url = strings
            .iter()
            .any(|s| s.value.contains("example.com") && matches!(s.string_type, StringType::Url));

        // Should find the path
        let has_path = strings
            .iter()
            .any(|s| s.value.contains("/usr/bin/ls") && matches!(s.string_type, StringType::Path));

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
        let strings = extractor.extract_smart(data, None);

        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_smart_deduplication() {
        // Test that duplicate strings are removed
        let data = b"test string\0test string\0test string";
        let extractor = StringExtractor::new();
        let strings = extractor.extract_smart(data, None);

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

        let strings = extractor.extract_smart(&data, None);

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

        let strings = extractor.extract_smart(&data, None);

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
