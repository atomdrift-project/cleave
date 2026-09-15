//! String extraction from binaries.
//!
//! This module extracts human-readable strings from binary files,
//! classifying them as URLs, IPs, file paths, or generic strings.
//!
//! Useful for quick triage and finding embedded indicators.

use crate::types::{StringInfo, StringType};
use base64::{Engine as _, engine::general_purpose};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use stng::{ExtractedString, StringMethod};

/// Strings from filefacts' text view, plus format-parsed SCPT literals.
/// Byte extraction and literal decoding remain owned by filefacts.
/// Returns empty when filefacts can't open the bytes. Use this at call
/// sites that have a path + bytes but no pre-opened [`AnalysisContext`].
///
/// [`AnalysisContext`]: crate::analysis_context::AnalysisContext
pub(crate) fn strings_from_filefacts(path: &std::path::Path, data: &[u8]) -> Vec<StringInfo> {
    let Ok(ctx) = crate::analysis_context::AnalysisContext::open(path, data) else {
        return Vec::new();
    };
    // Convert straight from the context's `text()` view — no intermediate Vec.
    let text = ctx.parsed.text();
    let mut strings = StringExtractor::new().convert_stng_iter(text.iter(), text.len());
    strings.extend(scpt_literal_strings(&ctx));
    strings
}

/// Convert compiled AppleScript literals without rescanning or decoding them.
/// Decoded rows retain their parent's source anchor and the literal section.
pub(crate) fn scpt_literal_strings(
    ctx: &crate::analysis_context::AnalysisContext<'_>,
) -> Vec<StringInfo> {
    if !scpt::is_scpt(ctx.content) {
        return Vec::new();
    }
    ctx.parsed
        .literals()
        .iter()
        .map(scpt_literal_string)
        .collect()
}

fn scpt_literal_string(literal: &filefacts::ExtractedString) -> StringInfo {
    // Only decoders cleave can name contribute a chain; anything else is a
    // literal the parser read verbatim.
    let encoding_chain = match literal
        .method
        .as_deref()
        .and_then(|m| m.strip_prefix("scpt-"))
    {
        Some("constant") => vec!["scpt".into()],
        Some(
            encoding @ ("base64" | "hex" | "url" | "unicode-escape" | "base32" | "base85"
            | "rot13-base64" | "base64-obf"),
        ) => vec!["scpt".into(), encoding.into()],
        _ => Vec::new(),
    };
    StringInfo {
        value: literal.text.clone().into(),
        offset: Some(literal.offset as u64),
        encoding: literal.encoding.clone().unwrap_or_else(|| "utf8".into()),
        string_type: None,
        section: Some("literal".into()),
        encoding_chain,
        fragments: None,
    }
}

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

    /// Convert filefacts/stng `ExtractedString` rows into cleave's
    /// `StringInfo`, applying symbol-map classification, the per-file
    /// retention caps, and the base64 decoded-sidecar. This is the cleave-side
    /// string layer; extraction itself is owned by filefacts.
    #[allow(dead_code)] // Used by binary target, not visible to library
    pub(crate) fn convert_stng_strings(&self, stng_strings: &[ExtractedString]) -> Vec<StringInfo> {
        self.convert_stng_iter(stng_strings.iter(), stng_strings.len())
    }

    /// Shared conversion core: apply the per-file string + byte retention caps
    /// and the base64 sidecar over any `stng::ExtractedString` source.
    pub(crate) fn convert_stng_iter<'a>(
        &self,
        source: impl Iterator<Item = &'a ExtractedString>,
        len_hint: usize,
    ) -> Vec<StringInfo> {
        let mut strings = Vec::with_capacity(len_hint.min(MAX_STRINGS_PER_FILE));
        let mut total_bytes = 0;
        self.truncated
            .store(false, std::sync::atomic::Ordering::SeqCst);

        for es in source {
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
            value: decoded_text.into(),
            offset: Some(es.data_offset),
            encoding: "utf8".to_string(),
            string_type: None,
            // stng no longer carries a per-string section; cleave derives it
            // from the offset itself where needed.
            section: None,
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
            value: es.value.into(),
            offset: Some(es.data_offset),
            encoding: "utf8".to_string(),
            string_type,
            section: None,
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
            data_len: 0,
            method,
            kind,
            fragments: None,
        }
    }

    #[test]
    fn test_default() {
        let extractor = StringExtractor::default();
        assert_eq!(extractor.min_length, 4);
    }

    #[test]
    fn scpt_literal_methods_preserve_provenance() {
        for suffix in [
            "base64",
            "hex",
            "url",
            "unicode-escape",
            "base32",
            "base85",
            "rot13-base64",
            "base64-obf",
            "constant",
            "literal",
        ] {
            let mut literal = filefacts::ExtractedString::default();
            literal.text = "decoded command".into();
            literal.offset = 73;
            literal.method = Some(format!("scpt-{suffix}"));
            literal.encoding = Some(
                if suffix == "literal" {
                    "utf16be"
                } else {
                    "utf8"
                }
                .into(),
            );
            let row = scpt_literal_string(&literal);
            let expected = match suffix {
                "literal" => vec![],
                "constant" => vec!["scpt"],
                _ => vec!["scpt", suffix],
            };
            assert_eq!(row.encoding_chain, expected, "{suffix}");
            assert_eq!(row.value, literal.text);
            assert_eq!(row.offset, Some(73));
            assert_eq!(row.section.as_deref(), Some("literal"));
            assert_eq!(Some(row.encoding), literal.encoding);
        }
    }

    #[test]
    fn scpt_base64_literals_preserve_parent_and_cached_text() {
        let bytes = include_bytes!("../tests/fixtures/scpt-base64.scpt");
        let path = std::path::Path::new("base64.scpt");
        let ctx = crate::analysis_context::AnalysisContext::open(path, bytes).unwrap();
        let cached = ctx.text_rows();
        let rows = scpt_literal_strings(&ctx);
        assert!(std::sync::Arc::ptr_eq(&cached, &ctx.text_rows()));
        let parent = rows
            .iter()
            .find(|s| s.value == "cHJpbnRmICclc1xuJyAnU0NQVF9CQVNFNjRfT0sn")
            .unwrap();
        let decoded: Vec<_> = rows
            .iter()
            .filter(|s| s.value == r"printf '%s\n' 'SCPT_BASE64_OK'")
            .collect();
        assert_eq!(decoded.len(), 1);
        assert!(parent.encoding_chain.is_empty());
        assert_eq!(parent.encoding, "utf16be");
        assert_eq!(decoded[0].encoding_chain, ["scpt", "base64"]);
        assert_eq!(decoded[0].encoding, "utf8");
        assert_eq!(decoded[0].offset, parent.offset);
        assert_eq!(decoded[0].section.as_deref(), Some("literal"));
        let combined = strings_from_filefacts(path, bytes);
        assert_eq!(
            combined
                .iter()
                .filter(|s| s.section.as_deref() == Some("literal"))
                .count(),
            rows.len()
        );
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
            .expect("base64 classified strings should filefacts decoded text to encoded traits");
        assert_eq!(sidecar.encoding_chain, vec!["base64"]);
        assert_eq!(sidecar.offset, Some(42));
        // section is derived from offset by cleave now, not carried from stng.
        assert_eq!(sidecar.section, None);
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
