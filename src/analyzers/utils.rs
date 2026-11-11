//! Common utilities for language analyzers.
//!
//! This module provides shared functionality to ensure consistency across
//! all language analyzers. When implementing a new language analyzer, use
//! these utilities to maintain consistency with existing analyzers.

use crate::analyzers::Analyzer;
use crate::analyzers::elf::ElfAnalyzer;
use crate::analyzers::input::AnalysisInput;
use crate::analyzers::pe::PEAnalyzer;
use crate::yara_engine::YaraEngine;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;

/// Extract embedded binary bytes to a temp file, analyze with the appropriate analyzer,
/// and return a FileAnalysis suitable for inclusion as a nested child (depth=1).
///
/// `host_path` is the complete logical parent path, including outer containers.
/// Returns `None` if extraction or analysis fails — the parent finding is still emitted.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn analyze_embedded_as_child(
    bytes: &[u8],
    host_path: &str,
    kind_str: &str,
    display_kind: &str,
    offset: usize,
    engine: crate::Engine,
    yara_engine: Option<Arc<YaraEngine>>,
) -> Option<Vec<crate::types::FileAnalysis>> {
    let suffix = if kind_str == "pe" { ".exe" } else { "" };
    let temp = tempfile::Builder::new().suffix(suffix).tempfile().ok()?;
    std::fs::write(temp.path(), bytes).ok()?;

    let child_path = crate::types::file_analysis::encode_archive_path(
        host_path,
        &format!("embedded:{}@{:#x}", display_kind, offset),
    );
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
            .with_engine(engine.clone())
            .without_embedded_scan();
        if let Some(yara) = yara_engine.clone() {
            analyzer = analyzer.with_yara_arc(yara);
        }
        analyzer.analyze_input(&input).ok()?
    } else {
        let mut analyzer = ElfAnalyzer::new()
            .with_engine(engine.clone())
            .without_embedded_scan();
        if let Some(ref yara) = yara_engine {
            analyzer = analyzer.with_yara_arc(yara);
        }
        analyzer.analyze_input(&input).ok()?
    };

    // Capture render context on the child's own bytes. The per-analyzer path
    // doesn't run capture (the lib/archive orchestration normally does), so
    // without this an embedded binary carries findings but no byte/line context —
    // it would render as bare location-less notes with no hex view. The child's
    // evidence offsets index these carved bytes. Rides up into `files[].context`
    // via `into_file_analysis`, exactly as archive members do.
    report.dedupe_findings();
    // As in the archive-member path: the low-value filter runs at the end of the
    // parent's analysis, after this capture, so exclude what it will delete.
    let doomed = engine.rules().doomed_low_value_ids(&report.findings);
    crate::context::capture(&mut report, bytes, file_type, &doomed);

    // A PE child is named after its own version info once filefacts has read it.
    let metadata_name = if kind_str == "pe" {
        embedded_pe_metadata_name(&report)
    } else {
        None
    };
    let temp_path = temp.path().display().to_string();
    let (mut fa, nested, _) = report.into_file_analysis(0, &engine);
    let child_path = metadata_name
        .as_deref()
        .map(|name| {
            crate::types::file_analysis::encode_archive_path(
                host_path,
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

fn embedded_pe_metadata_name(report: &crate::types::AnalysisReport) -> Option<String> {
    let tree = report.values_tree.as_deref()?;
    [
        "/pe/version/original_filename",
        "/pe/version/product_name",
        "/pe/version/description",
    ]
    .iter()
    .filter_map(|pointer| tree.pointer(pointer).and_then(serde_json::Value::as_str))
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
}
