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

        // Xcode project files are OpenStep-style plists, which the plist
        // parser reads alongside the XML and binary dialects. Routing them
        // here is what lets a rule address build settings and build-phase
        // scripts by path (`objects[*].shellScript`) instead of scraping the
        // whole file as text.
        if name_lower.ends_with(".pbxproj") {
            return StructuredFormat::Plist;
        }
    }

    // Limited content sniffing for special cases only
    // Check binary magic bytes BEFORE UTF-8 conversion for performance

    // Check for Binary Plist (binary format)
    if content.starts_with(b"bplist") {
        return StructuredFormat::Plist;
    }

    // OpenStep plist written by Xcode. The header comment is the format's only
    // signature, and it is what identifies a `project.pbxproj` copied out of
    // its `.xcodeproj` bundle under another name.
    if content.starts_with(b"// !$*UTF8*$!") {
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
        // A blank line ends the metadata headers. The description body can
        // contain header-shaped examples, which must not become field values.
        if line.is_empty() {
            break;
        }
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
    let parsed = filefacts::OpenOptions::new()
        .file_type(filefacts::FileType::SystemdService)
        .open(content);
    let root = parsed.values().as_json();
    root.as_object()
        .filter(|map| !map.is_empty())
        .map(|_| root.clone())
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
    let parsed = filefacts::OpenOptions::new()
        .file_type(filefacts::FileType::DesktopEntry)
        .open(content);
    let root = parsed.values().as_json();
    root.as_object()
        .filter(|map| !map.is_empty())
        .map(|_| root.clone())
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
        crate::composite_rules::FileType::GithubActions
        | crate::composite_rules::FileType::Yaml => StructuredFormat::Yaml,
        // An Xcode project is an OpenStep property list, which the plist
        // parser reads alongside the XML and binary dialects. Without this arm
        // a `project.pbxproj` reaching the evaluator by file type rather than
        // by filename falls through to Unknown and no `type: value` path
        // resolves against it. A keyed-archive nib is a binary plist too;
        // the NIBArchive layout is not, and simply fails to parse here.
        crate::composite_rules::FileType::Plist
        | crate::composite_rules::FileType::Pbxproj
        | crate::composite_rules::FileType::Nib => StructuredFormat::Plist,
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
        StructuredFormat::Yaml => crate::yaml::from_slice(content).ok()?,
        StructuredFormat::Toml => std::str::from_utf8(content)
            .ok()
            .and_then(|s| toml::from_str(s).ok())?,
        StructuredFormat::Plist => crate::plist_guard::to_json(content)?,
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
    let mut authoritative_flow = false;
    if let Some(synthetic) = ctx.report.values_tree.as_ref() {
        values.extend(navigate(synthetic.as_ref(), &segments));
        // These namespaces are computed from executable command contexts.
        // An empty computed array must not fall back to manifest-supplied
        // lookalike facts. Native fields elsewhere retain parser fallback.
        for (prefix, pointer) in [
            (
                "composer.install_hook_flows",
                "/composer/install_hook_flows",
            ),
            (
                "shell.literal_command_flows",
                "/shell/literal_command_flows",
            ),
        ] {
            if (path == prefix
                || path
                    .strip_prefix(prefix)
                    .is_some_and(|tail| tail.starts_with('.') || tail.starts_with('[')))
                && synthetic.pointer(pointer).is_some()
            {
                authoritative_flow = true;
            }
        }
    }

    let detected_format = ctx
        .cached_kv_format
        .get_or_init(|| detect_format(file_path, content));
    let format = if *detected_format == StructuredFormat::Unknown {
        structured_format_from_file_type(&ctx.file_type)
    } else {
        *detected_format
    };

    if format != StructuredFormat::Unknown && !authoritative_flow {
        let cached = ctx.cached_kv_parsed.get_or_init(|| {
            let parsed_value: Option<Value> = match format {
                StructuredFormat::Json => serde_json::from_slice(content).ok(),
                StructuredFormat::Yaml => crate::yaml::from_slice(content).ok(),
                StructuredFormat::Toml => std::str::from_utf8(content)
                    .ok()
                    .and_then(|s| toml::from_str(s).ok()),
                StructuredFormat::Plist => crate::plist_guard::to_json(content),
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
                .files()
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
mod tests;
