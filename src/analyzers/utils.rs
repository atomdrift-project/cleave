//! Common utilities for language analyzers.
//!
//! This module provides shared functionality to ensure consistency across
//! all language analyzers. When implementing a new language analyzer, use
//! these utilities to maintain consistency with existing analyzers.

use crate::analyzers::elf::ElfAnalyzer;
use crate::analyzers::input::AnalysisInput;
use crate::analyzers::pe::PEAnalyzer;
use crate::analyzers::{Analyzer, FileTypeExt};
use crate::capabilities::CapabilityMapper;
use crate::types::{Evidence, StructuralFeature};
use crate::yara_engine::YaraEngine;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;

/// Extract embedded binary bytes to a temp file, analyze with the appropriate analyzer,
/// and return a FileAnalysis suitable for inclusion as a nested child (depth=1).
///
/// Returns `None` if extraction or analysis fails — the parent finding is still emitted.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn analyze_embedded_as_child(
    bytes: &[u8],
    host_name: &str,
    kind_str: &str,
    display_kind: &str,
    offset: usize,
    capability_mapper: Arc<CapabilityMapper>,
    yara_engine: Option<Arc<YaraEngine>>,
    _parent_strings: &[stng::ExtractedString],
) -> Option<Vec<crate::types::FileAnalysis>> {
    let suffix = if kind_str == "pe" { ".exe" } else { "" };
    let temp = tempfile::Builder::new().suffix(suffix).tempfile().ok()?;
    std::fs::write(temp.path(), bytes).ok()?;

    let metadata_name_from_bytes = if kind_str == "pe" {
        embedded_pe_metadata_name_from_bytes(bytes)
    } else {
        None
    };
    let child_name = metadata_name_from_bytes
        .as_deref()
        .map(|name| format!("embedded:{}:{}@{:#x}", display_kind, name, offset))
        .unwrap_or_else(|| format!("embedded:{}@{:#x}", display_kind, offset));
    let child_path = crate::types::file_analysis::encode_archive_path(host_name, &child_name);
    let child_path_buf = PathBuf::from(&child_path);

    let file_type = if kind_str == "pe" {
        crate::analyzers::FileType::Pe
    } else {
        crate::analyzers::FileType::Elf
    };

    // Embedded binaries can be malformed or section-shifted relative to the
    // host's string offsets. Re-extract from the carved bytes so an empty or
    // mismapped parent string slice does not suppress child behavior matches.
    let input = AnalysisInput::new(&child_path_buf, bytes, file_type)
        .with_backing_path(temp.path())
        .at_depth(1);

    let mut report = if file_type == crate::analyzers::FileType::Pe {
        let mut analyzer = PEAnalyzer::new()
            .with_capability_mapper_arc(capability_mapper)
            .without_embedded_scan();
        if let Some(yara) = yara_engine.clone() {
            analyzer = analyzer.with_yara_arc(yara);
        }
        analyzer.analyze_input(&input).ok()?
    } else {
        let mut analyzer = ElfAnalyzer::new()
            .with_capability_mapper_arc(capability_mapper)
            .without_embedded_scan();
        if let Some(ref yara) = yara_engine {
            analyzer = analyzer.with_yara_arc(yara);
        }
        analyzer.analyze_input(&input).ok()?
    };

    if let Some(yara) = yara_engine.as_ref() {
        match yara.scan_bytes_to_findings(bytes, Some(&file_type.yara_filetypes())) {
            Ok((matches, findings)) => {
                report.yara_matches = matches;
                for finding in findings {
                    report.push_finding_capped(finding);
                }
            }
            Err(e) => report
                .metadata
                .errors
                .push(format!("yara(embedded): {e:#}")),
        }
    }

    let temp_path = temp.path().display().to_string();
    let (mut fa, nested, _) = report.into_file_analysis(0);
    let metadata_name = metadata_name_from_bytes.or_else(|| {
        if kind_str == "pe" {
            embedded_pe_metadata_name(&fa)
        } else {
            None
        }
    });
    let child_path = metadata_name
        .as_deref()
        .map(|name| {
            crate::types::file_analysis::encode_archive_path(
                host_name,
                &format!("embedded:{}:{}@{:#x}", display_kind, name, offset),
            )
        })
        .unwrap_or(child_path);
    fa.path = child_path;
    fa.depth = 1;
    let child_prefix = fa.path.clone();

    let mut files = Vec::with_capacity(nested.len().saturating_add(1));
    files.push(fa);
    for mut nested_file in nested {
        nested_file.path =
            normalize_embedded_nested_path(&nested_file.path, &temp_path, &child_prefix);
        nested_file.depth = nested_file.depth.saturating_add(1);
        files.push(nested_file);
    }
    Some(files)
}

fn normalize_embedded_nested_path(path: &str, temp_path: &str, child_prefix: &str) -> String {
    if path.starts_with(child_prefix) {
        return path.to_string();
    }
    if let Some(rest) = path.strip_prefix(temp_path) {
        return format!("{child_prefix}{rest}");
    }
    if let Some((_, member)) = path.split_once(crate::types::file_analysis::ARCHIVE_DELIMITER) {
        return crate::types::file_analysis::encode_archive_path(child_prefix, member);
    }
    crate::types::file_analysis::encode_archive_path(child_prefix, path)
}

fn embedded_pe_metadata_name(file: &crate::types::FileAnalysis) -> Option<String> {
    [
        "pe.version_info.original_filename",
        "pe.version_info.product_name",
        "pe.version_info.file_description",
    ]
    .iter()
    .filter_map(|key| file.kv.get(*key).and_then(serde_json::Value::as_str))
    .find_map(sanitize_child_name)
}

fn embedded_pe_metadata_name_from_bytes(bytes: &[u8]) -> Option<String> {
    let version_info = crate::analyzers::pe_extractors::extract_version_info(bytes);
    ["OriginalFilename", "ProductName", "FileDescription"]
        .iter()
        .filter_map(|key| version_info.get(*key).map(String::as_str))
        .find_map(sanitize_child_name)
}

fn sanitize_child_name(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len().min(64));
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            out.push(ch);
        } else if ch.is_whitespace() && !out.ends_with('_') {
            out.push('_');
        }
        if out.len() >= 64 {
            break;
        }
    }
    let trimmed = out.trim_matches('_').to_string();
    if trimmed.len() >= 3 {
        Some(trimmed)
    } else {
        None
    }
}

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
    hex::encode(hasher.finalize())
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
            ..Default::default()
        }],
    }
}

/// Maximum XML element-nesting depth we will parse.
///
/// `roxmltree`'s recursive-descent parser overflows the native stack on
/// pathologically deep input (a billion-laughs-style nesting bomb), and any
/// recursive tree-to-value conversion does the same. A malicious deeply-nested
/// SVG/plist/manifest or OOXML part is therefore a stack-overflow DoS.
/// Legitimate documents (OOXML, csproj, AndroidManifest, plist) are rarely more
/// than a few dozen levels deep, so this bound is generous.
pub(crate) const MAX_XML_DEPTH: usize = 256;

/// Parse XML, refusing pathologically deep documents before handing them to
/// roxmltree's recursive-descent parser (which would otherwise overflow the
/// stack). Returns `None` for over-deep or malformed input.
pub(crate) fn parse_xml_safe(text: &str) -> Option<roxmltree::Document<'_>> {
    if xml_depth_reaches(text, MAX_XML_DEPTH) {
        return None;
    }
    roxmltree::Document::parse(text).ok()
}

/// Conservatively scan XML markup for its maximum element-nesting depth without
/// building a tree, returning `true` as soon as depth reaches `limit`.
///
/// This is the iterative pre-flight guard behind [`parse_xml_safe`]. It
/// understands comments, CDATA, processing instructions and self-closing tags
/// so that wide-but-shallow documents (e.g. an SVG with thousands of sibling
/// elements) are not falsely rejected.
fn xml_depth_reaches(text: &str, limit: usize) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut depth = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'<' {
            i += 1;
            continue;
        }
        match bytes.get(i + 1) {
            Some(b'/') => {
                // End tag.
                depth = depth.saturating_sub(1);
                i += 2;
            }
            Some(b'?') => {
                // Processing instruction: skip to "?>".
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'?' && bytes[i + 1] == b'>') {
                    i += 1;
                }
                i += 2;
            }
            Some(b'!') if bytes[i + 1..].starts_with(b"!--") => {
                // Comment: skip to "-->".
                i += 4;
                while i < bytes.len() && !bytes[i..].starts_with(b"-->") {
                    i += 1;
                }
                i += 3;
            }
            Some(b'!') if bytes[i + 1..].starts_with(b"![CDATA[") => {
                // CDATA section: skip to "]]>".
                i += 9;
                while i < bytes.len() && !bytes[i..].starts_with(b"]]>") {
                    i += 1;
                }
                i += 3;
            }
            Some(b'!') => {
                // Declaration (e.g. DOCTYPE): skip to '>'.
                i += 2;
                while i < bytes.len() && bytes[i] != b'>' {
                    i += 1;
                }
                i += 1;
            }
            _ => {
                // Start tag: find the matching '>', tracking quoted attribute
                // values, and note whether it self-closes ("/>").
                i += 1;
                let mut quote = 0u8;
                let mut self_closing = false;
                while i < bytes.len() {
                    let c = bytes[i];
                    if quote != 0 {
                        if c == quote {
                            quote = 0;
                        }
                    } else if c == b'"' || c == b'\'' {
                        quote = c;
                    } else if c == b'>' {
                        self_closing = bytes[i - 1] == b'/';
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                if !self_closing {
                    depth += 1;
                    if depth >= limit {
                        return true;
                    }
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nested_xml(depth: usize) -> String {
        let mut xml = String::with_capacity(depth * 8 + 16);
        xml.push_str("<root>");
        for _ in 0..depth {
            xml.push_str("<g>");
        }
        for _ in 0..depth {
            xml.push_str("</g>");
        }
        xml.push_str("</root>");
        xml
    }

    #[test]
    fn test_xml_depth_reaches_counts_nesting() {
        assert!(xml_depth_reaches(&nested_xml(300), 256));
        assert!(!xml_depth_reaches(&nested_xml(10), 256));
        // Wide-but-shallow: many self-closing siblings must not count as depth.
        let wide = format!("<root>{}</root>", "<leaf/>".repeat(5000));
        assert!(!xml_depth_reaches(&wide, 256));
        // Self-closing tag with a '>' inside a quoted attribute stays shallow.
        let tricky = format!("<root>{}</root>", "<n a=\"x>y\"/>".repeat(5000));
        assert!(!xml_depth_reaches(&tricky, 256));
        // Comments and processing instructions do not add depth.
        let noise = format!("<root>{}</root>", "<!-- c --><?pi ?>".repeat(5000));
        assert!(!xml_depth_reaches(&noise, 256));
    }

    #[test]
    fn test_parse_xml_safe_refuses_deep_bomb() {
        // Deep enough to overflow roxmltree's recursive parser if it reached it.
        assert!(parse_xml_safe(&nested_xml(8000)).is_none());
    }

    #[test]
    fn test_parse_xml_safe_allows_shallow() {
        assert!(parse_xml_safe(&nested_xml(MAX_XML_DEPTH / 4)).is_some());
    }

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
