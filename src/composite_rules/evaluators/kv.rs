//! Key-Value condition evaluator: path queries over a file's values tree.
//!
//! The tree is what filefacts parsed and derived -- JSON/YAML/TOML manifests,
//! property lists, PKG-INFO, systemd units, desktop entries, MSBuild projects,
//! binary and document facts -- plus what cleave's analyzers merged into it.
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

use crate::composite_rules::condition::{ArrayQuantifier, Condition, KvQuery};
use crate::composite_rules::context::EvaluationContext;
use crate::composite_rules::types::FileType;
use crate::types::Evidence;
use rustc_hash::FxHashMap;
use serde_json::Value;

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

/// Evaluate a kv condition against the file's values tree -- the document
/// filefacts parsed (manifests, unit files, property lists, MSBuild
/// projects) beside the facts it derived and those cleave's analyzers merged.
///
/// Returns Some(Evidence) if the condition matches, None otherwise.
#[must_use]
pub(crate) fn evaluate_kv(condition: &Condition, ctx: &EvaluationContext<'_>) -> Option<Evidence> {
    let _mp = crate::mem_profile::phase(crate::mem_profile::Phase::EvalKv);
    let Condition::Kv(KvQuery {
        path,
        exact,
        substr,
        regex,
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

    let tree = ctx.report.values_tree.as_ref()?;
    let file_path = std::path::Path::new(&ctx.report.target.path);
    let segments = parse_path(path).ok()?;
    let values = navigate(tree.as_ref(), &segments);

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
    > = regex
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
                location: Some(kv_location(path, &segments, ctx)),
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
fn kv_location(path: &str, segments: &[PathSegment], ctx: &EvaluationContext<'_>) -> String {
    let dotted = segments_dotted(segments);
    let offsets = ctx.cached_kv_offsets.get_or_init(|| {
        // Only JSON is indexed: package.json is the dominant supply-chain
        // workload and the win is measured. Other structured formats fall back
        // to the value-tree companion or the label — no hand-rolled re-scanner
        // per format (see docs/BINARY_METADATA_ANCHORING.md).
        if matches!(
            ctx.file_type,
            FileType::Json
                | FileType::PackageJson
                | FileType::PackageLockJson
                | FileType::ComposerJson
                | FileType::ChromeManifest
        ) {
            std::str::from_utf8(ctx.binary_data)
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
