//! Embedded Code Detector
//!
//! Analyzes strings extracted by stng to detect and analyze embedded code (both plain and encoded).
//! Detects Python, JavaScript, Shell, and PHP code in strings and re-analyzes them with full
//! AST parsing and capability detection.

use crate::analyzers::{FileType, unified::UnifiedSourceAnalyzer};
use crate::types::Evidence;
use crate::types::binary::StringInfo;
use crate::types::file_analysis::{FileAnalysis, encode_decoded_path};
use crate::types::{Criticality, Finding, FindingKind};
use anyhow::{Context, Result};
use regex::Regex;
use rustc_hash::FxHashSet;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

mod layers;
#[allow(clippy::wildcard_imports)]
pub(crate) use layers::*;

mod binary_payloads;
#[allow(clippy::wildcard_imports)]
use binary_payloads::*;

/// Matches an interpreter inline-code invocation, capturing the interpreter
/// name and the opening quote: `python3 -c "..."`, `node -e '...'`,
/// `ruby -e "..."`, `php -r '...'`. Returns `None` only if the compiled
/// pattern ever fails — the same fallible-init pattern as the other regex
/// statics in this crate, so library code never `expect()`s.
fn inline_interp_re() -> Option<&'static Regex> {
    static_regex!(
        r#"(?:^|[\s;&|(])(python3|python|nodejs|node|deno|bun|ruby|perl|php)(?i:\.exe)?\s+(?:-c|-e|-r|--eval)\s+("|')"#
    )
}

/// Extract the inner source of an interpreter inline-code invocation
/// (`python3 -c "<code>"`, `node -e '<code>'`). Returns the language and the
/// code body so the embedded-code detector can analyze it as a real source
/// file — with a clean AST — instead of leaving it as an opaque shell-string
/// argument that pollutes the parse with the `interp -c` prefix.
fn extract_inline_interpreter_code(s: &str) -> Option<(FileType, &str)> {
    let caps = inline_interp_re()?.captures(s)?;
    let interp = caps.get(1)?.as_str();
    let quote_m = caps.get(2)?;
    let quote = quote_m.as_str().as_bytes()[0];
    let open = quote_m.end();
    // The code runs to the matching closing quote on the same line; for these
    // one-liners that is the last occurrence of the same quote char before any
    // newline (so a multi-line host script doesn't over-capture).
    let line_end = s[open..].find('\n').map_or(s.len(), |i| open + i);
    let close = s[open..line_end].rfind(quote as char).map(|i| open + i)?;
    if close <= open {
        return None;
    }
    let code = &s[open..close];
    if code.len() < 8 {
        return None;
    }
    let file_type = match interp {
        "python" | "python3" => FileType::Python,
        "node" | "nodejs" | "deno" | "bun" => FileType::JavaScript,
        "ruby" => FileType::Ruby,
        "perl" => FileType::Perl,
        "php" => FileType::Php,
        _ => return None,
    };
    Some((file_type, code))
}

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
#[must_use]
pub fn detect_language_with_host(
    string_info: &StringInfo,
    is_encoded: bool,
    host_file_type: Option<&FileType>,
) -> Option<FileType> {
    detect_language_value(
        &string_info.value,
        string_info.string_type,
        is_encoded,
        host_file_type,
    )
}

fn detect_language_value(
    value: &str,
    string_type: Option<crate::types::binary::StringType>,
    is_encoded: bool,
    host_file_type: Option<&FileType>,
) -> Option<FileType> {
    let result = detect_language_inner(value, &string_type, is_encoded)?;

    if let Some(host) = host_file_type {
        // Suppress false positives from syntactically similar languages.
        if is_sibling_language(host, &result) {
            tracing::debug!(
                "Suppressing {:?} detection in {:?} host (syntactic sibling)",
                result,
                host
            );
            return None;
        }

        // A curly-brace / C-family host (Go, Rust, C/C++, Java, …) shares heavy
        // syntactic overlap with JavaScript/TypeScript — function bodies, braces,
        // and `recv.Method("arg")` call sites. stng's heuristic classifier readily
        // tags the host's *own* plain source as embedded JS, which then runs
        // JavaScript-only traits against, e.g., Go's `db.Exec(`. Suppress that, but
        // only for PLAIN content: an *encoded* JS payload (base64/hex/xor) inside a
        // C-family host is a genuine hidden-payload signal and must still surface.
        if !is_encoded
            && is_curly_brace_family(host)
            && matches!(result, FileType::JavaScript | FileType::TypeScript)
        {
            tracing::debug!(
                "Suppressing plain {:?} detection in {:?} host (C-family self-match)",
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

/// Curly-brace / C-family source languages whose syntax overlaps JavaScript and
/// TypeScript enough that the embedded-code detector cannot reliably distinguish the
/// host's own plain source from a genuine embedded JS payload.
fn is_curly_brace_family(file_type: &FileType) -> bool {
    matches!(
        file_type,
        // `FileType::C` covers C, C++, headers, Pascal and asm (see filefacts ext map).
        FileType::C
            | FileType::Go
            | FileType::Rust
            | FileType::Java
            | FileType::CSharp
            | FileType::Swift
            | FileType::Kotlin
            | FileType::Scala
            | FileType::Groovy
            | FileType::Zig
            | FileType::ObjectiveC
    )
}

fn detect_language_inner(
    value: &str,
    kind: &Option<crate::types::binary::StringType>,
    is_encoded: bool,
) -> Option<FileType> {
    // Use stng's classification (either from extraction or by calling classify_string)
    use crate::types::binary::StringType;

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
        Some(StringType::ShellCmd) if is_real_shell(value) => {
            return Some(FileType::Shell);
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
    if crate::entropy::shannon(value.as_bytes()) > MAX_CODE_ENTROPY {
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
        Some(StringType::ShellCmd) if is_real_shell(value) => {
            return Some(FileType::Shell);
        }
        _ => {}
    }

    None
}

/// Source-map sidecars often contain a complete original file encoded as one
/// Base64 string. Small configuration modules may be valid JavaScript but too
/// declaration-light for stng's general-purpose classifier; keep that content
/// visible when it came from a decoded `.map` member.
fn looks_like_source_map_javascript(value: &str) -> bool {
    let has_declaration = [
        "const ",
        "let ",
        "var ",
        "function ",
        "class ",
        "module.exports",
        "require(",
        "process.env",
    ]
    .iter()
    .any(|marker| value.contains(marker));
    let has_statement_shape =
        value.contains(';') && (value.contains('{') || value.contains('=') || value.contains('('));
    has_declaration && has_statement_shape
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

fn is_component_source_host(parent_path: &str, host_file_type: Option<&FileType>) -> bool {
    if !matches!(
        host_file_type,
        Some(FileType::JavaScript | FileType::TypeScript | FileType::Html)
    ) {
        return false;
    }

    let host_path = parent_path.split("##").next().unwrap_or(parent_path);
    Path::new(host_path)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "svelte" | "vue" | "astro"
            )
        })
}

fn looks_like_component_source_markup(value: &str) -> bool {
    let trimmed = value.trim_start();
    if !(trimmed.starts_with('<') && value.contains('>')) {
        return false;
    }

    let component_markers = [
        "<script",
        "</script",
        "<style",
        "</style",
        "<template",
        "</template",
        "<svelte:",
        "<slot",
        "<div",
        "</div",
        "<span",
        "</span",
        "<button",
        "</button",
        " class=",
        "class=\"",
        "class='",
        "{#if",
        "{#each",
        "{/if}",
        "{/each}",
        "@click=",
        " v-if=",
        " v-for=",
    ];

    component_markers
        .iter()
        .any(|marker| value.contains(marker))
}

fn should_skip_component_source_markup(
    parent_path: &str,
    string_info: &StringInfo,
    host_file_type: Option<&FileType>,
) -> bool {
    string_info.encoding_chain.is_empty()
        && is_component_source_host(parent_path, host_file_type)
        && looks_like_component_source_markup(&string_info.value)
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

    // Shell syntax that prose does not produce.
    const SYNTAX: &[&str] = &[" | sh", " | bash", "cat <<", "EOF"];
    // Commands that are rare in natural language, but only where a shell
    // would run them: "or chmod +x the file" is an instruction to a reader.
    const COMMANDS: &[&str] = &[
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
        "rm -rf ",
        "mkdir -p ",
        "tail -f ",
    ];

    if SYNTAX.iter().any(|&k| value.contains(k))
        || COMMANDS.iter().any(|&k| has_command_at_position(value, k))
    {
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

/// Whether `command` occurs where a shell would execute it: at the start of
/// the string or a line, after a separator, opening quote, substitution or
/// group, or after a word that runs its argument (`sudo`, `nohup`, `-c`).
fn has_command_at_position(value: &str, command: &str) -> bool {
    const RUNNERS: &[&str] = &[
        "sudo", "nohup", "exec", "env", "time", "timeout", "xargs", "then", "do", "else", "-c",
    ];
    value.match_indices(command).any(|(at, _)| {
        let before = value[..at].trim_end_matches([' ', '\t']);
        before.is_empty()
            || before.ends_with(['\n', ';', '&', '|', '(', '{', '`', '\'', '"'])
            || before
                .rsplit(|c: char| c.is_ascii_whitespace())
                .next()
                .is_some_and(|word| RUNNERS.contains(&word))
    })
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
    is_encoded: bool,
    offset: u64,
    file_type: &FileType,
    host_file_type: Option<&FileType>,
) -> bool {
    if is_encoded || offset != 0 {
        return false;
    }
    // The host's identity is its detected type; a name is never used in its
    // place, so with no detected host there is nothing to call self-detection.
    let Some(host_type) = host_file_type else {
        return false;
    };
    *host_type == *file_type
        || is_sibling_language(host_type, file_type)
        || host_type.is_source_code()
}

/// Convert FileType to language name string
/// Every value [`lang_name`] returns: the leaf of `metadata/lang/embedded::<lang>`.
#[cfg(feature = "lint")]
pub(crate) const EMBEDDED_LANG_NAMES: &[&str] =
    &["python", "javascript", "shell", "php", "unknown"];

pub(crate) fn lang_name(file_type: &FileType) -> &'static str {
    match file_type {
        FileType::Python => "python",
        FileType::JavaScript => "javascript",
        FileType::Shell => "shell",
        FileType::Php => "php",
        _ => "unknown",
    }
}

/// Generate automatic plain embedded-language metadata. The evidence value is
/// the embedded code itself, collapsed to one line and later truncated by the
/// serializer; the offset lives in `location`.
fn generate_embedded_language_trait(detected_lang: &FileType, offset: u64, value: &str) -> Finding {
    Finding {
        precomputed_spans: None,
        src: None,
        id: format!("metadata/lang/embedded::{}", lang_name(detected_lang)).into(),
        kind: crate::types::FindingKind::Capability,
        desc: format!("{} code embedded in string", lang_name(detected_lang)).into(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![Evidence {
            method: "embedded-code-detection".to_string(),
            source: "string-analysis".to_string(),
            value: value.split_whitespace().collect::<Vec<_>>().join(" "),
            location: Some(format!("{:#x}", offset)),
            ..Default::default()
        }],
        match_count: 0,
        source_file: None,
        downgraded: false,
    }
}

/// Trusted provenance for this analysis unit, not a filename convention.
pub(crate) const HEURISTIC_QUOTED_ORIGIN_ID: &str =
    "metadata/lang/source/origin::heuristic-quoted-source";

pub(crate) fn heuristic_quoted_origin_finding() -> Finding {
    let mut finding = Finding::structural(
        HEURISTIC_QUOTED_ORIGIN_ID.into(),
        "Source parsed from heuristic quoted text".into(),
        1.0,
    );
    finding.crit = Criticality::Baseline;
    finding
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
    engine: &crate::Engine,
    current_depth: usize,
    host_file_type: Option<&FileType>,
) -> Result<EmbeddedAnalysisResult> {
    analyze_embedded_haystack(
        parent_path,
        &string_info.value,
        string_info.offset.unwrap_or(0),
        &string_info.encoding_chain,
        string_info.string_type,
        engine,
        current_depth,
        host_file_type,
    )
}

fn analyze_embedded_haystack(
    parent_path: &str,
    value: &str,
    offset: u64,
    encoding_chain: &[String],
    string_type: Option<crate::types::binary::StringType>,
    engine: &crate::Engine,
    current_depth: usize,
    host_file_type: Option<&FileType>,
) -> Result<EmbeddedAnalysisResult> {
    if current_depth >= MAX_DECODE_DEPTH {
        // Encoded code this deep is not analyzed, but it is reported as an
        // incomplete layer: dropping it would let extra encoding layers hide
        // a payload without a trace.
        if encoding_chain.is_empty()
            || detect_language_value(value, string_type, true, host_file_type).is_none()
        {
            anyhow::bail!("Maximum decode depth {} exceeded", MAX_DECODE_DEPTH);
        }
        let mut layer = FileAnalysis::new(
            0,
            encode_decoded_path(parent_path, encoding_chain, offset as usize),
            "unknown".to_string(),
            crate::analyzers::utils::calculate_sha256(value.as_bytes()),
            value.len() as u64,
        );
        layer.depth = (current_depth + 1) as u32;
        layer.encoding = Some(encoding_chain.to_vec());
        layer
            .analysis_gaps
            .record(crate::types::AnalysisGap::EmbeddedSourceIncomplete);
        layer.compute_summary();
        return Ok(EmbeddedAnalysisResult::EncodedLayer(Box::new(layer)));
    }

    // Detect language (uses stng classification, no regex needed)
    let t_detect = std::time::Instant::now();
    let is_encoded = !encoding_chain.is_empty();
    // Interpreter inline-code (`python3 -c "<code>"`, `node -e '<code>'`):
    // unwrap to the inner source and analyze THAT as its real language so the
    // AST/metric rules see clean code, not a shell-string argument. Only for
    // plain (un-encoded) strings.
    let inline_code = if is_encoded {
        None
    } else {
        extract_inline_interpreter_code(value)
    };

    let (file_type, source_to_analyze) = match inline_code {
        Some((lang, code)) => (lang, code),
        None => {
            let ft = detect_language_value(value, string_type, is_encoded, host_file_type)
                .or_else(|| {
                    (is_encoded
                        && parent_path.to_ascii_lowercase().ends_with(".map")
                        && looks_like_source_map_javascript(value))
                    .then_some(FileType::JavaScript)
                })
                .context("No language detected in string")?;
            // Bail before analyzing the host as "embedded". Offset-0 plain
            // source is the host file; `is_source_code` hosts always
            // self-detect. Inline `python3 -c` unwrap above still runs.
            if is_top_level_self_detection(is_encoded, offset, &ft, host_file_type) {
                anyhow::bail!("Top-level source self-detected as embedded code");
            }
            (ft, value)
        }
    };
    let detect_time = t_detect.elapsed();

    // Create virtual path
    let virtual_path = if is_encoded {
        encode_decoded_path(parent_path, encoding_chain, offset as usize)
    } else {
        format!("{}##plain@{:#x}", parent_path, offset)
    };

    // Create analyzer for detected language; disable embedded detection to prevent recursion.
    let mut analyzer = UnifiedSourceAnalyzer::for_file_type(&file_type)
        .context("Failed to create analyzer for language")?
        .with_engine(engine.clone())
        .without_embedded_detection()
        .with_fragment_host(host_file_type.copied());
    if is_encoded {
        analyzer = analyzer.with_encoded_context(encoding_chain.to_vec());
    } else if inline_code.is_none() {
        // A recognized interpreter command supplies an execution context;
        // heuristic origin is reserved for otherwise unbound quoted source.
        analyzer = analyzer.with_heuristic_quoted_context();
    }

    // Analyze in-memory.
    //
    // For an interpreter inline-code invocation (`python3 -c "<code>"`) the
    // language is declared by the interpreter token, so force the parse grammar
    // to it: the virtual path carries no usable extension, and plain
    // `analyze_source` would re-detect the stripped body as Unknown and recover
    // no AST — losing every capability of the payload (a `python3 -c` body's
    // `zlib.decompress` / `open(...,'rb')` calls).
    //
    // For heuristically classified plain embedded code (prose, prompts, doc
    // snippets that stng tagged as shell/python) keep the conservative
    // re-detecting path: forcing a grammar there would promote benign text to
    // full capability analysis and surface intent findings on non-code.
    let t_analyze = std::time::Instant::now();
    let virtual_path_ref = Path::new(&virtual_path);
    let report = if inline_code.is_some() {
        analyzer.analyze_source_as_configured(virtual_path_ref, source_to_analyze)
    } else {
        analyzer.analyze_source(virtual_path_ref, source_to_analyze)
    };
    let analyze_time = t_analyze.elapsed();

    if analyze_time.as_millis() > 100 {
        tracing::debug!(
            "embedded_code_detector: Slow analysis - detect: {:?}, analyze: {:?}, lang: {:?}, size: {}",
            detect_time,
            analyze_time,
            file_type,
            value.len()
        );
    }

    if is_encoded {
        // Encoded code - create a separate layer
        let (mut file_entry, _, _) = report.into_file_analysis(0, engine);
        file_entry.path = virtual_path.clone();
        file_entry.depth = (current_depth + 1) as u32;
        file_entry.encoding = Some(encoding_chain.to_vec());

        // Prefix evidence locations. The decoded layer renders against its own
        // buffer, so offsets stay local (shift 0); preserve them out of
        // `location` before that string is overwritten by the label.
        for finding in &mut file_entry.findings {
            for evidence in &mut finding.evidence {
                evidence.reanchor_offset(0);
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
        // These facts describe the snippet, not its carrier. Promoting an
        // unlocated metric such as its line count to the host lets a later
        // file-scoped composite combine it with unrelated host evidence.
        // Completed snippet composites and located behavior findings remain
        // available to the host.
        findings.retain(|finding| {
            finding.id != HEURISTIC_QUOTED_ORIGIN_ID
                && !(finding.trait_refs.is_empty()
                    && !finding.evidence.is_empty()
                    && finding.evidence.iter().all(|e| e.method == "metrics"))
        });
        findings.push(generate_embedded_language_trait(&file_type, offset, value));

        // Rewrite evidence to be parent-relative so the parent's
        // proximity checks (`near_bytes`/`near_lines`) measure real
        // distance between findings that came from different
        // extracted snippets — e.g. curl in one Dockerfile RUN block
        // and chmod in the next.
        for finding in &mut findings {
            for evidence in &mut finding.evidence {
                // Lift the snippet-local offset into `offsets`, shifted into the
                // parent's byte space, before the location is relabeled — a
                // content match that recorded its offset only in `location`
                // would otherwise be stranded once that string is overwritten.
                evidence.reanchor_offset(offset);
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

/// Process all strings from a file, analyzing detected code
/// Returns (encoded_layers, plain_findings):
/// - encoded_layers: FileAnalysis entries for encoded code (true layers)
/// - plain_findings: Findings for plain embedded code (added to parent)
pub(crate) fn process_all_strings(
    parent_path: &str,
    strings: &[StringInfo],
    engine: &crate::Engine,
    current_depth: usize,
    host_file_type: Option<&FileType>,
    cancelled: Option<&AtomicBool>,
) -> (Vec<FileAnalysis>, Vec<Finding>) {
    process_all_strings_with_host(
        parent_path,
        strings,
        engine,
        current_depth,
        host_file_type,
        cancelled,
        false,
        None,
    )
}

/// Document/prose file types whose fenced code blocks are instructional examples
/// (e.g. a markdown README's ```bash apt-get install …``` block), not executable
/// payloads. We do not promote their embedded code to its own typed sublayer —
/// the raw text is still scanned as a plain "mention", but `for:[shell]`/etc.
/// rules must not fire on documentation. Container/markup types that genuinely
/// carry executable payloads in malware (HTML, XML, JSON, plists) are NOT listed.
///
/// `skip_powershell_encoded_command`: unified source analysis already turned
/// stng `deobfuscate_script` payloads into layers; do not re-decode
/// `-EncodedCommand` on those hosts. Binary/generic callers leave this false.
///
/// `host_plain`: borrowed full-file haystack so unified source analysis can
/// still classify the host without copying `content` and `strings` per member.
enum EmbedCand<'a> {
    Extracted(usize, &'a StringInfo),
    HostPlain(&'a str),
}

impl<'a> EmbedCand<'a> {
    fn value(&self) -> &'a str {
        match self {
            Self::Extracted(_, info) => info.value.as_str(),
            Self::HostPlain(value) => value,
        }
    }

    fn offset(&self) -> u64 {
        match self {
            Self::Extracted(_, info) => info.offset.unwrap_or(0),
            Self::HostPlain(_) => 0,
        }
    }

    fn encoding_chain_empty(&self) -> bool {
        match self {
            Self::Extracted(_, info) => info.encoding_chain.is_empty(),
            Self::HostPlain(_) => true,
        }
    }

    fn has_script_encoding(&self) -> bool {
        match self {
            Self::Extracted(_, info) => info.encoding_chain.iter().any(|step| step == "script"),
            Self::HostPlain(_) => false,
        }
    }

    fn extracted(&self) -> Option<(usize, &'a StringInfo)> {
        match *self {
            Self::Extracted(idx, info) => Some((idx, info)),
            Self::HostPlain(_) => None,
        }
    }

    fn encoding_chain(&self) -> &'a [String] {
        match self {
            Self::Extracted(_, info) => &info.encoding_chain,
            Self::HostPlain(_) => &[],
        }
    }

    fn string_type(&self) -> Option<crate::types::binary::StringType> {
        match self {
            Self::Extracted(_, info) => info.string_type,
            Self::HostPlain(_) => None,
        }
    }

    fn score(&self) -> usize {
        let is_code = |kind: Option<crate::types::binary::StringType>| -> bool {
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
        match self {
            Self::Extracted(_, info) if is_code(info.string_type) => 1_000_000,
            Self::Extracted(_, info) => info.value.len(),
            Self::HostPlain(value) => value.len(),
        }
    }
}

pub(crate) fn process_all_strings_with_host(
    parent_path: &str,
    strings: &[StringInfo],
    engine: &crate::Engine,
    current_depth: usize,
    host_file_type: Option<&FileType>,
    cancelled: Option<&AtomicBool>,
    skip_powershell_encoded_command: bool,
    host_plain: Option<&str>,
) -> (Vec<FileAnalysis>, Vec<Finding>) {
    // A JSON source map is data: its keys and sourcesContent never execute.
    // The host type comes from content sniffing, so a script that merely
    // contains these key names is still analyzed.
    if host_file_type == Some(&FileType::Json) && is_source_map_string_set(strings) {
        tracing::debug!(
            "embedded_code_detector: Skipping source map payload strings for {}",
            parent_path
        );
        return (Vec::new(), Vec::new());
    }

    // Documentation embeds examples; YARA strings are matching predicates.
    // Neither executes the program text inside those strings. Preserve the
    // strings for host-language rules without synthesizing executable layers.
    if let Some(
        host @ (FileType::Markdown
        | FileType::PkgInfo
        | FileType::Rtf
        | FileType::Text
        | FileType::Yara),
    ) = host_file_type
    {
        tracing::debug!(
            "embedded_code_detector: Skipping embedded sublayers for declarative/document type {:?} in {}",
            host,
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
    let host_len = host_plain.map_or(0, str::len);
    let total_string_bytes: usize = strings.iter().map(|s| s.value.len()).sum::<usize>() + host_len;
    let max_string_len = strings
        .iter()
        .map(|s| s.value.len())
        .chain(host_plain.map(str::len))
        .max()
        .unwrap_or(0);
    tracing::trace!(
        "embedded_code_detector: Processing {} strings (total {} bytes, max {} bytes)",
        strings.len() + usize::from(host_plain.is_some()),
        total_string_bytes,
        max_string_len
    );

    let mut sorted: Vec<EmbedCand<'_>> = strings
        .iter()
        .enumerate()
        .map(|(idx, info)| EmbedCand::Extracted(idx, info))
        .collect();
    if let Some(host) = host_plain {
        sorted.push(EmbedCand::HostPlain(host));
    }
    sorted.sort_by_key(|cand| std::cmp::Reverse(cand.score()));

    let mut detection_attempts = 0;
    let max_detection_attempts = sorted.len().min(256);

    for cand in sorted {
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

        let value = cand.value();
        let offset = cand.offset();

        // Strings over 1 MB are a performance trap for the heavyweight
        // detectors (full base64 decode + magic walk + recursive
        // analysis). But they're *also* the exact shape a packed
        // dropper takes — Kong-ingress-controller 2024 carried an
        // 11 MB base64-encoded ELF in a single string. Skip
        // unconditionally only when a cheap head-magic check on the
        // string's first ~256 base64 chars rules out a packed binary;
        // otherwise let the full pipeline run.
        const MAX_STRING_SIZE_FOR_DETECTION: usize = 1024 * 1024; // 1MB
        if value.len() > MAX_STRING_SIZE_FOR_DETECTION {
            let magic = match cand.extracted() {
                Some((_, info)) => head_decodes_to_known_magic(info),
                None => head_decodes_to_known_magic_text(value),
            };
            if !magic {
                continue;
            }
        }

        // Benign XML/HTML/SVG template literals often contain namespace URLs and tags that
        // confuse generic code classifiers. Skip passive markup here before any deeper analysis.
        if cand.encoding_chain_empty() && looks_like_passive_markup(value) {
            continue;
        }

        // Component single-file formats (.svelte/.vue/.astro) are parsed by the
        // source analyzer as JS/TS-like hosts, but their own active markup can
        // look like an embedded second language to string classification. Do not
        // promote plain component markup to an embedded-code layer; encoded
        // content inside the component still flows through the payload checks.
        if match cand.extracted() {
            Some((_, info)) => {
                should_skip_component_source_markup(parent_path, info, host_file_type)
            }
            None => {
                is_component_source_host(parent_path, host_file_type)
                    && looks_like_component_source_markup(value)
            }
        } {
            continue;
        }

        // stng `ScriptDecode` fragments (and the full decoded payload, once
        // ingested) are string-matching material. The typed source layer
        // comes from `analyze_script_deobfuscation_layers`, not a second
        // walk of shredded pieces.
        if cand.has_script_encoding() {
            continue;
        }

        detection_attempts += 1;

        // Check for PowerShell -EncodedCommand blobs first
        if !skip_powershell_encoded_command
            && let Some(ps_layer) =
                detect_powershell_encoded_command(parent_path, value, offset, engine, current_depth)
        {
            detected_count += 1;
            total_bytes += value.len();
            total_analyzed += 1;
            encoded_layers.push(ps_layer);
            continue;
        }

        // Check for base64-encoded binary payloads (PE, ELF, archives).
        // detect_base64_binary returns the carrier-layer FileAnalysis
        // plus any nested files the unified sub-file dispatcher
        // produced from a container payload (tar.gz members,
        // archive contents, sub-sub-files). All entries already
        // carry their final depth.
        let bin_entries = match cand.extracted() {
            Some((_, info)) => {
                detect_base64_binary(parent_path, info, current_depth as u32, engine)
            }
            None => {
                // Host haystack: only copy into a StringInfo if it actually
                // looks like packed base64. Source files almost never do.
                if looks_like_base64(value) {
                    let tmp = StringInfo {
                        value: value.to_string().into(),
                        offset: Some(offset),
                        string_type: None,
                        encoding: "utf-8".to_string(),
                        section: None,
                        encoding_chain: Vec::new(),
                        fragments: None,
                    };
                    detect_base64_binary(parent_path, &tmp, current_depth as u32, engine)
                } else {
                    Vec::new()
                }
            }
        };
        if let Some(bin_layer) = bin_entries.first() {
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
            total_bytes += value.len();
            total_analyzed += 1;
            encoded_layers.extend(bin_entries);
            continue;
        }

        match analyze_embedded_haystack(
            parent_path,
            value,
            offset,
            cand.encoding_chain(),
            cand.string_type(),
            engine,
            current_depth,
            host_file_type,
        ) {
            Ok(EmbeddedAnalysisResult::EncodedLayer(file_analysis)) => {
                detected_count += 1;
                total_bytes += value.len();
                total_analyzed += 1;
                encoded_layers.push(*file_analysis);
            }
            Ok(EmbeddedAnalysisResult::PlainEmbedded(findings)) => {
                detected_count += 1;
                total_bytes += value.len();
                total_analyzed += 1;
                plain_findings.extend(findings);
            }
            Err(error) => {
                // Most strings are simply not code; the reason is diagnostic.
                tracing::trace!(%error, parent_path, offset, "string not analyzed as embedded code");
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
mod tests;

#[cfg(test)]
mod variation_selector_tests;
