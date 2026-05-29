//! Condition types for composite rules.
use super::types::Platform;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

fn compile_regex_logged(
    _kind: &str,
    _source_pattern: &str,
    compile_pattern: &str,
    _case_insensitive: bool,
) -> std::result::Result<regex::Regex, regex::Error> {
    regex::Regex::new(compile_pattern)
}

/// Process-global, deduplicated, lazily-compiled regex cache.
///
/// Replaces eager per-condition precompilation. Previously every `word:` /
/// `regex:` condition compiled its own `regex::Regex` at load — a heavyweight
/// meta-engine object (~tens of KB) built for all ~100k conditions, ~1.5 GB
/// total, even though top-level traits match via the capability indexes and
/// most composite sub-conditions never evaluate. Here a pattern is compiled on
/// first evaluation and shared (and leaked — rules live for the whole process)
/// across every condition that uses it, so only patterns that actually fire
/// cost anything, and identical patterns cost once.
pub(crate) fn cached_regex(pattern: &str) -> Option<&'static regex::Regex> {
    use std::sync::{LazyLock, RwLock};
    static CACHE: LazyLock<RwLock<std::collections::HashMap<String, &'static regex::Regex>>> =
        LazyLock::new(|| RwLock::new(std::collections::HashMap::new()));
    // Hot path is a concurrent read lock — only the first compile of each unique
    // pattern takes the write lock, so warmed-up evals never serialize.
    if let Ok(cache) = CACHE.read()
        && let Some(&re) = cache.get(pattern)
    {
        return Some(re);
    }
    let re = regex::Regex::new(pattern).ok()?;
    let leaked: &'static regex::Regex = Box::leak(Box::new(re));
    if let Ok(mut cache) = CACHE.write() {
        // `or_insert` makes the first writer win under a benign build race, so
        // every caller converges on the same shared instance.
        return Some(*cache.entry(pattern.to_string()).or_insert(leaked));
    }
    Some(leaked)
}

/// Resolve a `regex:` pattern through [`cached_regex`], applying the `(?i)`
/// prefix for case-insensitivity. This is the **only** place the extracted-
/// string path builds a `regex::Regex`: `word:`/`substr:`/`exact:` are literal
/// matches (see [`word_match_start`]) and never touch the regex engine.
pub(crate) fn lazy_regex(
    regex: Option<&str>,
    case_insensitive: bool,
) -> Option<&'static regex::Regex> {
    let raw = regex?;
    if case_insensitive {
        cached_regex(&format!("(?i){raw}"))
    } else {
        cached_regex(raw)
    }
}

/// Raw-content matcher's lazy regex source. Like [`lazy_regex`] but also serves
/// `word:` by building `\bword\b` on demand (cached/shared), and enables
/// multi-line mode (`(?m)`) so `^`/`$` anchor per line — matching the byte-regex
/// path's `multi_line(true)` (see `compile_bytes_regex`) so non-ASCII raw
/// patterns honor per-line anchors identically. TODO: make `word:` a literal
/// byte-boundary scan here too so raw content never touches the regex engine for
/// literals; for now it's lazy + deduplicated (no longer the eager per-condition
/// compilation that cost ~1.5 GB).
pub(crate) fn lazy_raw_regex(
    word: Option<&str>,
    regex: Option<&str>,
    case_insensitive: bool,
) -> Option<&'static regex::Regex> {
    let base = match (word, regex) {
        (Some(w), _) => format!(r"\b{}\b", regex::escape(w)),
        (None, Some(r)) => r.to_string(),
        (None, None) => return None,
    };
    if case_insensitive {
        cached_regex(&format!("(?im){base}"))
    } else {
        cached_regex(&format!("(?m){base}"))
    }
}

/// Shared, lazy, leaked case-sensitive substring searcher per unique needle.
/// `memchr::memmem::Finder` (SIMD + Two-Way + prefilter) is the right tool for
/// a single needle; caching it means we build the searcher once and reuse it
/// across evals instead of rebuilding per call, with no per-condition storage.
pub(crate) fn cached_finder(needle: &str) -> &'static memchr::memmem::Finder<'static> {
    use std::sync::{LazyLock, RwLock};
    static CACHE: LazyLock<
        RwLock<std::collections::HashMap<String, &'static memchr::memmem::Finder<'static>>>,
    > = LazyLock::new(|| RwLock::new(std::collections::HashMap::new()));
    // Hot path is a concurrent read lock; only first build of each needle writes.
    if let Ok(cache) = CACHE.read()
        && let Some(&f) = cache.get(needle)
    {
        return f;
    }
    let finder: &'static _ = Box::leak(Box::new(memchr::memmem::Finder::new(needle).into_owned()));
    if let Ok(mut cache) = CACHE.write() {
        return cache.entry(needle.to_string()).or_insert(finder);
    }
    finder
}

/// Shared, lazy, leaked single-pattern ASCII-case-insensitive Aho-Corasick
/// searcher per unique needle. For CI single-needle matching, AC's built-in
/// case folding beats lowercasing the haystack on every eval.
pub(crate) fn cached_ci_searcher(needle: &str) -> Option<&'static aho_corasick::AhoCorasick> {
    use std::sync::{LazyLock, RwLock};
    static CACHE: LazyLock<
        RwLock<std::collections::HashMap<String, &'static aho_corasick::AhoCorasick>>,
    > = LazyLock::new(|| RwLock::new(std::collections::HashMap::new()));
    // Hot path is a concurrent read lock; only first build of each needle writes.
    if let Ok(cache) = CACHE.read()
        && let Some(&ac) = cache.get(needle)
    {
        return Some(ac);
    }
    let ac = aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build([needle])
        .ok()?;
    let ac: &'static _ = Box::leak(Box::new(ac));
    if let Ok(mut cache) = CACHE.write() {
        return Some(*cache.entry(needle.to_string()).or_insert(ac));
    }
    Some(ac)
}

#[inline]
fn is_word_byte(b: u8) -> bool {
    // ASCII word chars plus any non-ASCII byte (UTF-8 lead/continuation bytes
    // of multi-byte chars, ~all of which are Unicode word/letter chars). This
    // approximates the regex crate's Unicode-aware `\b` so a `word:` keyword
    // sitting against a non-ASCII letter (`ñeval`) doesn't spuriously match.
    b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80
}

/// `\bneedle\b` boundary test at `[start, end)` in `haystack`. A `\b` exists
/// where word-ness *transitions*, which depends on whether the needle's own
/// first/last byte is a word char (so punctuation-edged patterns behave like
/// the regex did), and at text start/end `\b` holds iff the adjacent needle
/// byte is a word char.
#[inline]
fn word_boundary_ok(hb: &[u8], nb: &[u8], start: usize, end: usize) -> bool {
    let (Some(&first), Some(&last)) = (nb.first(), nb.last()) else {
        return false;
    };
    let first_word = is_word_byte(first);
    let last_word = is_word_byte(last);
    let left = if start == 0 {
        first_word
    } else {
        is_word_byte(hb[start - 1]) != first_word
    };
    let right = if end == hb.len() {
        last_word
    } else {
        is_word_byte(hb[end]) != last_word
    };
    left && right
}

/// Case-sensitive `word:` match using a pre-resolved `Finder`. Returns the byte
/// offset of the first occurrence whose neighbours satisfy `\bneedle\b`.
#[must_use]
pub(crate) fn word_match_cs(
    haystack: &str,
    needle: &str,
    finder: &memchr::memmem::Finder<'static>,
) -> Option<usize> {
    let hb = haystack.as_bytes();
    let nb = needle.as_bytes();
    let mut from = 0;
    while let Some(rel) = finder.find(&hb[from..]) {
        let start = from + rel;
        if word_boundary_ok(hb, nb, start, start + nb.len()) {
            return Some(start);
        }
        from = start + 1;
    }
    None
}

/// Case-insensitive `word:` match using a pre-resolved Aho-Corasick searcher.
#[must_use]
pub(crate) fn word_match_ci(
    haystack: &str,
    needle: &str,
    ac: &aho_corasick::AhoCorasick,
) -> Option<usize> {
    let hb = haystack.as_bytes();
    let nb = needle.as_bytes();
    ac.find_iter(haystack)
        .find(|m| word_boundary_ok(hb, nb, m.start(), m.end()))
        .map(|m| m.start())
}

/// Literal word-boundary match — the `word:` matcher, **no regex engine**.
/// Resolves the shared searcher then delegates to [`word_match_cs`] /
/// [`word_match_ci`]. Production resolves the searcher once per condition (see
/// `StringMatcher`) and calls those directly; this single-shot convenience is
/// used only by the boundary-semantics unit tests.
#[cfg(test)]
#[must_use]
pub(crate) fn word_match_start(
    haystack: &str,
    needle: &str,
    case_insensitive: bool,
) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    if case_insensitive {
        word_match_ci(haystack, needle, cached_ci_searcher(needle)?)
    } else {
        word_match_cs(haystack, needle, cached_finder(needle))
    }
}

/// Custom serde for offset ranges that accepts/produces ergonomic formats:
/// - `[start, end]` - closed range from start to end
/// - `[start,]` or `[start, null]` or `[start, ~]` - from start to end of file (open-ended end)
/// - `[null, end]` or `[~, end]` - from beginning of file to end (open-ended start, treated as offset 0)
mod offset_range_serde {
    use serde::de::{self, Deserializer, SeqAccess};
    use serde::ser::Serializer;

    pub(crate) fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<Option<(i64, Option<i64>)>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OffsetRangeVisitor;

        impl<'de> de::Visitor<'de> for OffsetRangeVisitor {
            type Value = Option<(i64, Option<i64>)>;

            fn expecting<'a>(&self, formatter: &mut std::fmt::Formatter<'a>) -> std::fmt::Result {
                formatter.write_str("an offset range array like [start, end], [start,], or [, end]")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // Get first element (start)
                let start: Option<i64> = seq.next_element()?.unwrap_or(None);

                // Get second element (end)
                let end: Option<i64> = seq.next_element()?.unwrap_or(None);

                // Both None means empty array - return None
                if start.is_none() && end.is_none() {
                    return Ok(None);
                }

                // Convert to our internal format: (i64, Option<i64>)
                // where the first i64 is start (0 if not specified)
                // and the second Option<i64> is end (None if open-ended)
                Ok(Some((start.unwrap_or(0), end)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(None)
            }
        }

        deserializer.deserialize_any(OffsetRangeVisitor)
    }

    pub(crate) fn serialize<S>(
        value: &Option<(i64, Option<i64>)>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            None => serializer.serialize_none(),
            Some((start, end)) => {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(start)?;
                seq.serialize_element(end)?;
                seq.end()
            }
        }
    }
}

/// Encoding specification for encoded string searches
/// Can be a single encoding, array of encodings (OR), or chain (sequence)
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(untagged)]
pub(crate) enum EncodingSpec {
    /// Single encoding: "base64"
    Single(String),
    /// Multiple encodings (OR): ["base64", "hex"]
    Multiple(Vec<String>),
}

/// Structured not-exception with explicit match type
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NotExceptionStructured {
    /// Require exact string equality to trigger the exception
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    /// Require the value to contain this substring to trigger the exception
    #[serde(skip_serializing_if = "Option::is_none")]
    pub substr: Option<String>,
    /// Require the value to match this regex to trigger the exception
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// Pre-lowered substr for case-insensitive matching
    #[serde(skip)]
    pub lowered_substr: Option<String>,
}

/// String exception specification for `not:` directive
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum NotException {
    /// Shorthand: bare string defaults to substr match
    Shorthand(String),

    /// Structured exception with explicit match type
    Structured(NotExceptionStructured),
}

impl NotException {
    /// Check if a string matches this exception
    #[must_use]
    pub(crate) fn matches(&self, value: &str) -> bool {
        match self {
            NotException::Shorthand(pattern) => {
                // Pattern is pre-lowered during precompile(); only lowercase value
                value.to_lowercase().contains(pattern.as_str())
            }
            NotException::Structured(s) => {
                if let Some(exact_str) = &s.exact {
                    value.eq_ignore_ascii_case(exact_str)
                } else if let Some(regex_str) = &s.regex {
                    // Case-sensitive, resolved via the shared lazy cache rather
                    // than a per-exception precompiled regex.
                    cached_regex(regex_str)
                        .map(|re| re.is_match(value))
                        .unwrap_or(false)
                } else if let Some(lowered) = &s.lowered_substr {
                    value.to_lowercase().contains(lowered.as_str())
                } else if let Some(substr_str) = &s.substr {
                    value.to_lowercase().contains(&substr_str.to_lowercase())
                } else {
                    false
                }
            }
        }
    }

    /// Pre-compile regex and pre-lowercase patterns for faster matching
    pub(crate) fn precompile(&mut self) {
        match self {
            NotException::Shorthand(pattern) => {
                // Pre-lowercase the pattern
                let lowered = pattern.to_lowercase();
                if lowered != *pattern {
                    *pattern = lowered;
                }
            }
            NotException::Structured(s) => {
                if let Some(substr_str) = &s.substr
                    && s.lowered_substr.is_none()
                {
                    s.lowered_substr = Some(substr_str.to_lowercase());
                }
            }
        }
    }
}

/// Strict shorthand: only `id` is allowed — any extra fields (e.g. `count_min`,
/// `needs`, `crit`) cause a deserialization error instead of being silently dropped.
/// Fields that appear unused on condition items are bugs in trait YAML files.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TraitShorthandInner {
    id: String,
}

/// Intermediate type for deserializing conditions with shorthand support.
/// Converts `{ id: my-trait }` to `Condition::Trait { id: "my-trait" }`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ConditionDeser {
    /// Shorthand for trait reference - just `id` field, no `type` needed
    /// Must be listed first so serde tries it before the tagged variants
    TraitShorthand(TraitShorthandInner),

    /// All other condition types require explicit `type` field
    Tagged(Box<ConditionTagged>),
}

/// High-fidelity validation checks for string matches.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash, Copy, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum StringValidator {
    /// Require match to contain a valid external IPv4 address
    ExternalIp,
    /// Require match to contain a valid Bitcoin address (with checksum)
    #[serde(rename = "bitcoin_addr")]
    BitcoinAddr,
}

/// Symbol category filter for `type: symbol` conditions.
///
/// When a rule sets `kind:`, only symbols of that category are matched. The
/// default (field omitted) behaviour preserves the pre-existing semantic of
/// matching across imports, exports, and internal functions.
///
/// `Forward` restricts matching to PE exports whose `forward_to` target is
/// set (re-exports). The pattern is tested against both the export name and
/// the forward target (`KERNEL32.LoadLibraryA`), so rules can filter either
/// the visible symbol or the ultimate resolvee.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SymbolKind {
    Import,
    Export,
    Forward,
    Function,
    /// Call-site records from the source AST walker. Distinct from
    /// `Function` (which is the *declaration*) — `Call` is each
    /// *invocation* with target + arg values from `filefacts::Symbol::Call`.
    Call,
}

/// Filter for matching a single argument at a call site. Used by
/// `Condition::Symbol { kind: Call, arg: ... }`. Each field narrows
/// the match: `kind` filters arg shape (`string`/`number`/`identifier`),
/// the per-shape fields filter content.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArgFilter {
    /// Arg shape to match: `string`, `number`, `identifier`, `bool`,
    /// `template`, `null`, `object`, `array`, `function`, `call`,
    /// `expression`. Omitted → any shape.
    #[serde(default)]
    pub kind: Option<String>,
    /// Numeric value (kind=number). Matches when the arg's parsed
    /// integer equals this.
    #[serde(default)]
    pub value: Option<i64>,
    /// Source-written radix (kind=number): 2 / 8 / 10 / 16. With
    /// `value`, both must match — lets authors distinguish `0o777`
    /// (radix 8) from decimal `511` (radix 10).
    #[serde(default)]
    pub radix: Option<u32>,
    /// String / template value substring match.
    #[serde(default)]
    pub substr: Option<String>,
    /// String / template value exact match.
    #[serde(default)]
    pub exact: Option<String>,
    /// Identifier name exact match (kind=identifier).
    #[serde(default)]
    pub name: Option<String>,
}

/// Internal tagged enum for serializing/deserializing conditions with explicit `type` field
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ConditionTagged {
    Symbol {
        #[serde(default)]
        exact: Option<String>,
        #[serde(default)]
        substr: Option<String>,
        #[serde(default)]
        regex: Option<String>,
        #[serde(default)]
        platforms: Option<Vec<Platform>>,
        /// High-fidelity validator (e.g., is: external_ip)
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        /// Restrict match to a specific symbol category (imports, exports,
        /// forwarded exports, internal functions, or call sites).
        /// When absent, match across imports/exports/functions —
        /// preserving the pre-`kind` semantic.
        #[serde(default)]
        kind: Option<SymbolKind>,
        /// Per-argument filter (kind=call only). Narrows matches to
        /// calls whose argument list contains at least one arg matching
        /// the filter's shape + value constraints. Example: match
        /// `chmod(_, 0o777)` via `kind: call, name: chmod, arg: {
        /// kind: number, value: 511, radix: 8 }`.
        #[serde(default)]
        arg: Option<ArgFilter>,
        /// Exclude individual matches where the symbol name (or surrounding
        /// trait-level evidence) matches any of these patterns.
        #[serde(default)]
        not: Option<Vec<NotException>>,
    },
    Import {
        #[serde(default)]
        exact: Option<String>,
        #[serde(default)]
        substr: Option<String>,
        #[serde(default)]
        regex: Option<String>,
        #[serde(default)]
        platforms: Option<Vec<Platform>>,
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        #[serde(default)]
        not: Option<Vec<NotException>>,
    },
    Export {
        #[serde(default)]
        exact: Option<String>,
        #[serde(default)]
        substr: Option<String>,
        #[serde(default)]
        regex: Option<String>,
        #[serde(default)]
        platforms: Option<Vec<Platform>>,
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        #[serde(default)]
        not: Option<Vec<NotException>>,
    },
    Function {
        #[serde(default)]
        exact: Option<String>,
        #[serde(default)]
        substr: Option<String>,
        #[serde(default)]
        regex: Option<String>,
        #[serde(default)]
        platforms: Option<Vec<Platform>>,
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        #[serde(default)]
        not: Option<Vec<NotException>>,
    },
    Text {
        #[serde(default)]
        exact: Option<String>,
        #[serde(default)]
        substr: Option<String>,
        #[serde(default)]
        regex: Option<String>,
        #[serde(default)]
        word: Option<String>,
        #[serde(default)]
        case_insensitive: bool,
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        #[serde(default)]
        not: Option<Vec<NotException>>,
        #[serde(default)]
        platforms: Option<Vec<Platform>>,
        #[serde(default)]
        section: Option<String>,
        #[serde(default)]
        offset: Option<i64>,
        #[serde(
            default,
            deserialize_with = "offset_range_serde::deserialize",
            serialize_with = "offset_range_serde::serialize"
        )]
        offset_range: Option<(i64, Option<i64>)>,
        #[serde(default)]
        section_offset: Option<i64>,
        #[serde(
            default,
            deserialize_with = "offset_range_serde::deserialize",
            serialize_with = "offset_range_serde::serialize"
        )]
        section_offset_range: Option<(i64, Option<i64>)>,
    },
    #[serde(alias = "string_literal")]
    Literal {
        /// Literal kind to match: `string` (default) or `number`.
        /// Numeric matching is wired through `value` / `radix` fields;
        /// string matching uses the standard exact / substr / regex /
        /// word predicates against the literal's text.
        #[serde(default)]
        kind: Option<String>,
        #[serde(default)]
        exact: Option<String>,
        #[serde(default)]
        substr: Option<String>,
        #[serde(default)]
        regex: Option<String>,
        #[serde(default)]
        word: Option<String>,
        /// Numeric value (kind=number only). Matches a literal whose
        /// parsed integer value equals this.
        #[serde(default)]
        value: Option<i64>,
        /// How a numeric literal was written in source: 2, 8, 10, 16.
        /// When set together with `value`, both must match — lets
        /// authors distinguish "the source said `0o777`" from "the
        /// source said `511`" even though they represent the same
        /// integer.
        #[serde(default)]
        radix: Option<u32>,
        #[serde(default)]
        case_insensitive: bool,
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        #[serde(default)]
        not: Option<Vec<NotException>>,
        #[serde(default)]
        platforms: Option<Vec<Platform>>,
        #[serde(default)]
        section: Option<String>,
        #[serde(default)]
        offset: Option<i64>,
        #[serde(
            default,
            deserialize_with = "offset_range_serde::deserialize",
            serialize_with = "offset_range_serde::serialize"
        )]
        offset_range: Option<(i64, Option<i64>)>,
        #[serde(default)]
        section_offset: Option<i64>,
        #[serde(
            default,
            deserialize_with = "offset_range_serde::deserialize",
            serialize_with = "offset_range_serde::serialize"
        )]
        section_offset_range: Option<(i64, Option<i64>)>,
    },
    Trait {
        id: String,
    },
    /// Live tree-sitter query — escape hatch for structural patterns
    /// the precomputed `Symbol::Call/Member/Bind` projections can't
    /// express. Most rules should reach for `type: call` / `member` /
    /// `bind` / `literal` instead, which match against the
    /// already-walked symbol view without re-parsing.
    ///
    /// Simple mode: kind + exact/substr/regex (or node + exact/substr/regex for raw node types)
    /// Advanced mode: query (tree-sitter S-expression)
    ///
    /// Renamed from the old `type: ast` spelling for honesty: this
    /// evaluator spins up tree-sitter and runs queries live.
    #[serde(rename = "tree-sitter")]
    TreeSitter {
        /// Abstract node category (e.g., "call", "function", "class")
        /// Maps to language-specific tree-sitter node types automatically
        #[serde(default, skip_serializing_if = "Option::is_none")]
        kind: Option<String>,
        /// Raw tree-sitter node type (escape hatch, bypasses kind mapping)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        node: Option<String>,
        /// Full match (entire node text must equal this)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in node text)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex match in node text
        #[serde(default, skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Tree-sitter S-expression query (advanced mode)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        query: Option<String>,
        /// Language hint for query validation
        #[serde(default, skip_serializing_if = "Option::is_none")]
        language: Option<String>,
        /// Case-insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
    },
    Yara {
        source: String,
    },
    Syscall {
        #[serde(default)]
        name: Option<Vec<String>>,
        #[serde(default)]
        number: Option<Vec<u32>>,
        #[serde(default)]
        arch: Option<Vec<String>>,
    },
    Metrics {
        field: String,
        #[serde(default)]
        min: Option<f64>,
        #[serde(default)]
        max: Option<f64>,
        #[serde(default)]
        min_size: Option<u64>,
        #[serde(default)]
        max_size: Option<u64>,
    },
    Hex {
        pattern: String,
        /// Exclude individual matches where evidence matches any of these patterns
        #[serde(default)]
        not: Option<Vec<NotException>>,
        /// Absolute file offset (negative = from end of file)
        #[serde(default)]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end, null = open-ended)
        #[serde(
            default,
            deserialize_with = "offset_range_serde::deserialize",
            serialize_with = "offset_range_serde::serialize"
        )]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(default)]
        section: Option<String>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(default)]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(
            default,
            deserialize_with = "offset_range_serde::deserialize",
            serialize_with = "offset_range_serde::serialize"
        )]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Search raw file content (for source files or when you need to match
    /// across string boundaries in binaries). Unlike `type: text` which only
    /// searches properly extracted/bounded strings, this searches the raw bytes.
    Raw {
        /// Full match (entire content must equal this - rarely useful)
        #[serde(default)]
        exact: Option<String>,
        /// Substring match (appears anywhere in content)
        #[serde(default)]
        substr: Option<String>,
        #[serde(default)]
        regex: Option<String>,
        #[serde(default)]
        word: Option<String>,
        #[serde(default)]
        case_insensitive: bool,
        /// Optional high-fidelity validation check
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        /// Exclude individual matches where evidence matches any of these patterns.
        /// Only valid when `regex` is set — rejected by validation otherwise.
        #[serde(default)]
        not: Option<Vec<NotException>>,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(default)]
        section: Option<String>,
        /// Absolute file offset: only match at this exact byte position (negative = from end)
        #[serde(default)]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end)
        #[serde(
            default,
            deserialize_with = "offset_range_serde::deserialize",
            serialize_with = "offset_range_serde::serialize"
        )]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(default)]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(
            default,
            deserialize_with = "offset_range_serde::deserialize",
            serialize_with = "offset_range_serde::serialize"
        )]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Match section names in binary files (PE, ELF, Mach-O)
    /// Replaces YARA patterns like: `for any section in pe.sections : (section.name matches /^UPX/)`
    /// Example: { type: section, regex: "^UPX" }
    /// Example: { type: section, substr: "upx", case_insensitive: true }
    Section {
        /// Full section name match (entire name must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in section name)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Word boundary match (equivalent to regex "\bword\b")
        #[serde(skip_serializing_if = "Option::is_none")]
        word: Option<String>,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
        /// Minimum section length in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        length_min: Option<u64>,
        /// Maximum section length in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        length_max: Option<u64>,
        /// Minimum section entropy (0.0-8.0)
        #[serde(skip_serializing_if = "Option::is_none")]
        entropy_min: Option<f64>,
        /// Maximum section entropy (0.0-8.0)
        #[serde(skip_serializing_if = "Option::is_none")]
        entropy_max: Option<f64>,
        /// Require section to have read permission (works across PE/ELF/Mach-O)
        #[serde(skip_serializing_if = "Option::is_none")]
        readable: Option<bool>,
        /// Require section to have write permission (works across PE/ELF/Mach-O)
        #[serde(skip_serializing_if = "Option::is_none")]
        writable: Option<bool>,
        /// Require section to have execute permission (works across PE/ELF/Mach-O)
        #[serde(skip_serializing_if = "Option::is_none")]
        executable: Option<bool>,
        /// Reference section (or `"total"` for file size) used as the denominator
        /// for both `size_ratio_*` and `entropy_ratio_*` checks. Defaults to
        /// `"total"` when a size ratio is requested and no pattern is given.
        #[serde(skip_serializing_if = "Option::is_none")]
        compare_to: Option<String>,
        /// Minimum ratio of matched-section size to denominator size.
        #[serde(skip_serializing_if = "Option::is_none")]
        size_ratio_min: Option<f64>,
        /// Maximum ratio of matched-section size to denominator size.
        #[serde(skip_serializing_if = "Option::is_none")]
        size_ratio_max: Option<f64>,
        /// Minimum ratio of matched-section entropy to denominator entropy.
        #[serde(skip_serializing_if = "Option::is_none")]
        entropy_ratio_min: Option<f64>,
        /// Maximum ratio of matched-section entropy to denominator entropy.
        #[serde(skip_serializing_if = "Option::is_none")]
        entropy_ratio_max: Option<f64>,
    },

    /// Match patterns in encoded/decoded strings (unified replacement for base64/xor)
    /// Example: { type: encoded, encoding: base64, regex: "https?://" }
    /// Example: { type: encoded, encoding: [xor, hex], substr: "eval(" }
    /// Example: { type: encoded, word: "password" } - searches ALL encoded strings
    Encoded {
        /// Optional encoding filter - single, multiple, or omit for all
        /// Examples: "base64", ["xor", "hex"], "xor+base64" (chain)
        #[serde(default)]
        encoding: Option<EncodingSpec>,
        /// Full match (entire decoded string must equal this)
        #[serde(default)]
        exact: Option<String>,
        /// Substring match (appears anywhere in decoded string)
        #[serde(default)]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(default)]
        regex: Option<String>,
        /// Word boundary match (equivalent to regex "\bword\b")
        #[serde(default)]
        word: Option<String>,
        /// Case insensitive matching
        #[serde(default)]
        case_insensitive: bool,
        /// Optional high-fidelity validation check
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        /// Exclude individual matches where evidence matches any of these patterns.
        /// Only valid when `regex` is set — rejected by validation otherwise.
        #[serde(default)]
        not: Option<Vec<NotException>>,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(default)]
        section: Option<String>,
        /// Absolute file offset: only match at this exact byte position (negative = from end)
        #[serde(default)]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end)
        #[serde(
            default,
            deserialize_with = "offset_range_serde::deserialize",
            serialize_with = "offset_range_serde::serialize"
        )]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(default)]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(
            default,
            deserialize_with = "offset_range_serde::deserialize",
            serialize_with = "offset_range_serde::serialize"
        )]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Match the basename (final path component, not the full path)
    /// Example: { type: basename, exact: "__init__.py" }
    /// Example: { type: basename, regex: "^setup\\." }
    Basename {
        /// Full basename match (entire basename must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in basename)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
        /// Optional high-fidelity validation check
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
    },

    /// Query structural values using path expressions.
    /// Supports dot notation for nested access and [*] for array iteration.
    /// Example: { type: value, path: "permissions", is: "debugger" }
    /// Example: { type: value, path: "scripts.postinstall", substr: "curl" }
    /// Example: { type: value, path: "content_scripts[*].matches", is: "<all_urls>" }
    /// Example: { type: value, path: "maintainers", size_min: 1, size_max: 1 }
    #[serde(rename = "value")]
    Kv {
        /// Path to navigate using dot notation, [n] for indices, [*] for wildcards
        path: String,
        /// Value/element equals exactly
        #[serde(
            rename = "is",
            alias = "exact",
            skip_serializing_if = "Option::is_none"
        )]
        exact: Option<String>,
        /// Value/element contains substring
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Value/element matches regex pattern
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Right-hand-side value path for cross-fact equality comparison.
        /// When set, the value at `path` must equal the value at `eq`.
        /// Comparison is always case-insensitive and whitespace-trimmed —
        /// if you need strict matching, use `exact:` against a literal.
        /// Path syntax accepts an optional `<filename>::` prefix to
        /// reference a sibling file within the same archive scope.
        #[serde(skip_serializing_if = "Option::is_none")]
        eq: Option<String>,
        /// Right-hand-side value path for cross-fact inequality comparison.
        /// Mirrors `eq` with reversed sense; same normalization applies.
        #[serde(skip_serializing_if = "Option::is_none")]
        ne: Option<String>,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
        /// Explicit existence check (true = must exist, false = must not exist)
        #[serde(skip_serializing_if = "Option::is_none")]
        exists: Option<bool>,
        /// Minimum collection size (array elements or object keys)
        #[serde(skip_serializing_if = "Option::is_none")]
        size_min: Option<usize>,
        /// Maximum collection size (array elements or object keys)
        #[serde(skip_serializing_if = "Option::is_none")]
        size_max: Option<usize>,
    },
}

impl From<ConditionDeser> for Condition {
    fn from(deser: ConditionDeser) -> Self {
        match deser {
            ConditionDeser::TraitShorthand(inner) => Condition::Trait { id: inner.id },
            ConditionDeser::Tagged(tagged) => match *tagged {
                ConditionTagged::Symbol {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    kind,
                    arg,
                    not,
                } => Condition::Symbol {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    kind,
                    arg,
                    not,
                },
                ConditionTagged::Import {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    not,
                } => Condition::Symbol {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    kind: Some(SymbolKind::Import),
                    arg: None,
                    not,
                },
                ConditionTagged::Export {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    not,
                } => Condition::Symbol {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    kind: Some(SymbolKind::Export),
                    arg: None,
                    not,
                },
                ConditionTagged::Function {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    not,
                } => Condition::Symbol {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    kind: Some(SymbolKind::Function),
                    arg: None,
                    not,
                },
                ConditionTagged::Text {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    is_check,
                    not,
                    platforms,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                } => Condition::Text {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    is_check,
                    not,
                    platforms,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                },
                ConditionTagged::Literal {
                    kind,
                    exact,
                    substr,
                    regex,
                    word,
                    value,
                    radix,
                    case_insensitive,
                    is_check,
                    not,
                    platforms,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                } => Condition::Literal {
                    kind,
                    exact,
                    substr,
                    regex,
                    word,
                    value,
                    radix,
                    case_insensitive,
                    is_check,
                    not,
                    platforms,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                },
                ConditionTagged::Trait { id } => Condition::Trait { id },
                ConditionTagged::TreeSitter {
                    kind,
                    node,
                    exact,
                    substr,
                    regex,
                    query,
                    language,
                    case_insensitive,
                } => Condition::TreeSitter {
                    kind,
                    node,
                    exact,
                    substr,
                    regex,
                    query,
                    language,
                    case_insensitive,
                },
                ConditionTagged::Yara { source } => Condition::Yara {
                    source,
                    compiled: None,
                    namespace: None,
                },
                ConditionTagged::Syscall { name, number, arch } => {
                    Condition::Syscall { name, number, arch }
                }
                ConditionTagged::Metrics {
                    field,
                    min,
                    max,
                    min_size,
                    max_size,
                } => Condition::Metrics {
                    field,
                    min,
                    max,
                    min_size,
                    max_size,
                },
                ConditionTagged::Hex {
                    pattern,
                    not,
                    offset,
                    offset_range,
                    section,
                    section_offset,
                    section_offset_range,
                } => Condition::Hex {
                    pattern,
                    not,
                    offset,
                    offset_range,
                    section,
                    section_offset,
                    section_offset_range,
                },
                ConditionTagged::Raw {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    is_check,
                    not,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                } => Condition::Raw {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    is_check,
                    not,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                },
                ConditionTagged::Section {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    length_min,
                    length_max,
                    entropy_min,
                    entropy_max,
                    readable,
                    writable,
                    executable,
                    compare_to,
                    size_ratio_min,
                    size_ratio_max,
                    entropy_ratio_min,
                    entropy_ratio_max,
                } => Condition::Section {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    length_min,
                    length_max,
                    entropy_min,
                    entropy_max,
                    readable,
                    writable,
                    executable,
                    compare_to,
                    size_ratio_min,
                    size_ratio_max,
                    entropy_ratio_min,
                    entropy_ratio_max,
                },
                ConditionTagged::Encoded {
                    encoding,
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    is_check,
                    not,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                } => Condition::Encoded {
                    encoding,
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    is_check,
                    not,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                },
                ConditionTagged::Basename {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                    is_check,
                } => Condition::Basename {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                    is_check,
                },
                ConditionTagged::Kv {
                    path,
                    exact,
                    substr,
                    regex,
                    eq,
                    ne,
                    case_insensitive,
                    exists,
                    size_min,
                    size_max,
                } => Condition::Kv {
                    path,
                    exact,
                    substr,
                    regex,
                    eq,
                    ne,
                    case_insensitive,
                    exists,
                    size_min,
                    size_max,
                },
            },
        }
    }
}

impl From<Condition> for ConditionTagged {
    fn from(cond: Condition) -> Self {
        match cond {
            Condition::Symbol {
                exact,
                substr,
                regex,
                platforms,
                is_check,
                kind,
                arg,
                not,
            } => ConditionTagged::Symbol {
                exact,
                substr,
                regex,
                platforms,
                is_check,
                kind,
                arg,
                not,
            },
            Condition::Text {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not,
                platforms,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            } => ConditionTagged::Text {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not,
                platforms,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            },
            Condition::Literal {
                kind,
                exact,
                substr,
                regex,
                word,
                value,
                radix,
                case_insensitive,
                is_check,
                not,
                platforms,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            } => ConditionTagged::Literal {
                kind,
                exact,
                substr,
                regex,
                word,
                value,
                radix,
                case_insensitive,
                is_check,
                not,
                platforms,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            },
            Condition::Trait { id } => ConditionTagged::Trait { id },
            Condition::TreeSitter {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                language,
                case_insensitive,
            } => ConditionTagged::TreeSitter {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                language,
                case_insensitive,
            },
            Condition::Yara {
                source,
                compiled: _,
                namespace: _,
            } => ConditionTagged::Yara { source },
            Condition::Syscall { name, number, arch } => {
                ConditionTagged::Syscall { name, number, arch }
            }
            Condition::Metrics {
                field,
                min,
                max,
                min_size,
                max_size,
            } => ConditionTagged::Metrics {
                field,
                min,
                max,
                min_size,
                max_size,
            },
            Condition::Hex {
                pattern,
                not,
                offset,
                offset_range,
                section,
                section_offset,
                section_offset_range,
            } => ConditionTagged::Hex {
                pattern,
                not,
                offset,
                offset_range,
                section,
                section_offset,
                section_offset_range,
            },
            Condition::Raw {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            } => ConditionTagged::Raw {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            },
            Condition::Section {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                length_min,
                length_max,
                entropy_min,
                entropy_max,
                readable,
                writable,
                executable,
                compare_to,
                size_ratio_min,
                size_ratio_max,
                entropy_ratio_min,
                entropy_ratio_max,
            } => ConditionTagged::Section {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                length_min,
                length_max,
                entropy_min,
                entropy_max,
                readable,
                writable,
                executable,
                compare_to,
                size_ratio_min,
                size_ratio_max,
                entropy_ratio_min,
                entropy_ratio_max,
            },
            Condition::Encoded {
                encoding,
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            } => ConditionTagged::Encoded {
                encoding,
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            },
            Condition::Basename {
                exact,
                substr,
                regex,
                case_insensitive,
                is_check,
            } => ConditionTagged::Basename {
                exact,
                substr,
                regex,
                case_insensitive,
                is_check,
            },
            Condition::Kv {
                path,
                exact,
                substr,
                regex,
                eq,
                ne,
                case_insensitive,
                exists,
                size_min,
                size_max,
            } => ConditionTagged::Kv {
                path,
                exact,
                substr,
                regex,
                eq,
                ne,
                case_insensitive,
                exists,
                size_min,
                size_max,
            },
        }
    }
}

/// Condition type in composite rules.
///
/// Supports two YAML formats:
/// 1. Tagged: `{ type: text, exact: "foo" }` - explicit type field
/// 2. Shorthand: `{ id: my-trait }` - defaults to Trait when only `id` is present
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(from = "ConditionDeser", into = "ConditionTagged")]
pub(crate) enum Condition {
    /// Match a symbol (import/export/function/forward)
    Symbol {
        /// Full symbol name match (entire symbol must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in symbol name)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match symbol names
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Platform filter - only evaluate this condition for these platforms
        #[serde(skip_serializing_if = "Option::is_none")]
        platforms: Option<Vec<Platform>>,
        /// Optional high-fidelity validation check
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        /// Restrict match to a specific symbol category. `None` matches
        /// across imports, exports, and internal functions.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        kind: Option<SymbolKind>,
        /// Per-argument filter (kind=call only). Narrows matches to
        /// call sites whose argument list contains at least one arg
        /// matching the filter — e.g. `chmod(_, 0o777)` via
        /// `kind: call, name: chmod, arg: { kind: number, value: 511,
        /// radix: 8 }`.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        arg: Option<ArgFilter>,
        /// Exclude individual matches where the symbol name matches any of
        /// these patterns. Combined (OR) with the trait-level `not:` filter.
        #[serde(skip_serializing_if = "Option::is_none", default)]
        not: Option<Vec<NotException>>,
    },

    /// Match human-readable text.
    ///
    /// On binary-like formats this searches extracted strings for speed. On
    /// source and structured text formats it searches raw file text.
    Text {
        /// Full text match (entire string or content slice must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in text)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Match pattern only at word boundaries (convenience for \bpattern\b)
        #[serde(skip_serializing_if = "Option::is_none")]
        word: Option<String>,
        /// If true, matching is case-insensitive
        #[serde(default)]
        case_insensitive: bool,
        /// Optional high-fidelity validation check
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        /// Exclude individual matches where evidence matches any of these patterns
        #[serde(skip_serializing_if = "Option::is_none")]
        not: Option<Vec<NotException>>,
        /// Platform filter - only evaluate this condition for these platforms
        #[serde(skip_serializing_if = "Option::is_none")]
        platforms: Option<Vec<Platform>>,
        /// Section constraint: only match text in this section (supports fuzzy names like "text")
        #[serde(skip_serializing_if = "Option::is_none")]
        section: Option<String>,
        /// Absolute file offset: only match at this exact byte position (negative = from end)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end)
        #[serde(
            skip_serializing_if = "Option::is_none",
            deserialize_with = "offset_range_serde::deserialize"
        )]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(
            skip_serializing_if = "Option::is_none",
            deserialize_with = "offset_range_serde::deserialize"
        )]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Match a language-level literal recovered by the AST walker.
    ///
    /// Defaults to string-literal matching (kind=string) — same precise
    /// tier as the prior `type: string_literal` (which is kept as a
    /// serde alias for backward compat). With `kind: number`, matches
    /// numeric literals by their parsed integer `value` (and optional
    /// source-written `radix`).
    ///
    /// Only works on file types with tree-sitter support; does not
    /// fall back to raw text.
    Literal {
        /// Literal kind to match: `string` (default) or `number`.
        #[serde(skip_serializing_if = "Option::is_none")]
        kind: Option<String>,
        /// Full literal match (string mode) — entire literal text must equal this.
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (string mode) — appears anywhere in the literal.
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern match (string mode).
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Word-boundary substring match (string mode).
        #[serde(skip_serializing_if = "Option::is_none")]
        word: Option<String>,
        /// Numeric value (kind=number) — matches when the literal's
        /// parsed integer equals this.
        #[serde(skip_serializing_if = "Option::is_none")]
        value: Option<i64>,
        /// Source-written radix (kind=number): 2, 8, 10, 16. When set
        /// with `value`, both must match — distinguishes `0o777` from
        /// `511` even though they parse to the same integer.
        #[serde(skip_serializing_if = "Option::is_none")]
        radix: Option<u32>,
        /// Case-insensitive matching (string mode).
        #[serde(default)]
        case_insensitive: bool,
        /// Optional high-fidelity validation check (string mode).
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        /// Exclude individual matches where evidence matches any of these patterns.
        #[serde(skip_serializing_if = "Option::is_none")]
        not: Option<Vec<NotException>>,
        /// Platform filter.
        #[serde(skip_serializing_if = "Option::is_none")]
        platforms: Option<Vec<Platform>>,
        /// Section constraint.
        #[serde(skip_serializing_if = "Option::is_none")]
        section: Option<String>,
        /// Absolute file offset.
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<i64>,
        /// Absolute offset range: [start, end).
        #[serde(
            skip_serializing_if = "Option::is_none",
            deserialize_with = "offset_range_serde::deserialize"
        )]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset.
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end).
        #[serde(
            skip_serializing_if = "Option::is_none",
            deserialize_with = "offset_range_serde::deserialize"
        )]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Reference a previously-defined trait by ID
    Trait {
        /// The ID of the trait to reference
        id: String,
    },

    /// Live tree-sitter query — escape hatch for structural patterns
    /// the precomputed `Symbol::Call/Member/Bind` projections can't
    /// express. Reach for `type: call` / `member` / `bind` / `literal`
    /// first; this evaluator spins up tree-sitter and runs queries live.
    ///
    /// Simple mode (kind + exact/substr/regex):
    /// ```yaml
    /// type: tree-sitter
    /// kind: call              # abstract kind: call, function, class, import, etc.
    /// substr: "eval"          # substring match
    /// ```
    ///
    /// Raw node type mode (node + exact/substr/regex):
    /// ```yaml
    /// type: tree-sitter
    /// node: call_expression   # raw tree-sitter node type (escape hatch)
    /// substr: "eval"
    /// ```
    ///
    /// Advanced mode (query):
    /// ```yaml
    /// type: tree-sitter
    /// query: |
    ///   (call_expression
    ///     function: (identifier) @fn
    ///     (#eq? @fn "eval"))
    /// language: javascript    # optional, for validation
    /// ```
    TreeSitter {
        /// Abstract node category (e.g., "call", "function", "class")
        #[serde(skip_serializing_if = "Option::is_none")]
        kind: Option<String>,
        /// Raw tree-sitter node type (escape hatch, bypasses kind mapping)
        #[serde(skip_serializing_if = "Option::is_none")]
        node: Option<String>,
        /// Full match (entire node text must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in node text)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex match in node text
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Tree-sitter S-expression query (advanced mode)
        #[serde(skip_serializing_if = "Option::is_none")]
        query: Option<String>,
        /// Language hint for query validation
        #[serde(skip_serializing_if = "Option::is_none")]
        language: Option<String>,
        /// Case-insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
    },

    /// Inline YARA rule for pattern matching
    /// Example: { type: yara, source: "rule test { strings: $a = \"test\" if: $a }" }
    Yara {
        /// YARA rule source code
        source: String,
        /// Pre-compiled YARA rules (used for unless/composite conditions not in combined engine)
        #[serde(skip)]
        compiled: Option<Arc<yara_x::Rules>>,
        /// Namespace in the combined YARA engine (e.g. "inline.trait-id").
        /// When set, evaluation uses pre-scanned results from context instead of re-scanning.
        #[serde(skip)]
        namespace: Option<String>,
    },

    /// Match syscalls detected via radare2 binary analysis
    /// For detecting direct syscall usage patterns in ELF/Mach-O binaries
    Syscall {
        /// Syscall name(s) to match (e.g., "socket", "connect", "execve")
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<Vec<String>>,
        /// Syscall number(s) to match (architecture-dependent)
        #[serde(skip_serializing_if = "Option::is_none")]
        number: Option<Vec<u32>>,
        /// Architecture filter (e.g., "mips", "x86_64", "arm")
        #[serde(skip_serializing_if = "Option::is_none")]
        arch: Option<Vec<String>>,
    },

    /// Check computed metrics for obfuscation/anomaly detection
    /// For detecting obfuscation patterns in source code via statistical analysis
    Metrics {
        /// Metric path (e.g., "identifiers.avg_entropy", "functions.density_per_100_lines")
        field: String,
        /// Minimum value threshold
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<f64>,
        /// Maximum value threshold
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<f64>,
        /// Minimum file size in bytes (only apply this rule to files >= this size)
        #[serde(skip_serializing_if = "Option::is_none")]
        min_size: Option<u64>,
        /// Maximum file size in bytes (only apply this rule to files <= this size)
        #[serde(skip_serializing_if = "Option::is_none")]
        max_size: Option<u64>,
    },

    /// Match hex byte patterns in binary data
    /// Supports wildcards (??) and variable-length gaps ([N] or [N-M])
    /// Wildcard bytes are always extracted and included in evidence (consistent with regex behavior)
    /// Example: { type: hex, pattern: "7F 45 4C 46" }  # ELF magic
    /// Example: { type: hex, pattern: "31 ?? 48 83" }  # With wildcards - ?? bytes will be extracted
    /// Example: { type: hex, pattern: "00 03 [4] 00 04" }  # With 4-byte gap
    Hex {
        /// Hex pattern with optional wildcards (??) and gaps ([N] or [N-M])
        /// Format: space-separated hex bytes, ?? for any byte, [N] for N-byte gap
        pattern: String,
        /// Exclude individual matches where evidence matches any of these patterns
        #[serde(skip_serializing_if = "Option::is_none")]
        not: Option<Vec<NotException>>,
        /// Absolute file offset (negative = from end of file)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end, null = open-ended)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(skip_serializing_if = "Option::is_none")]
        section: Option<String>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Search raw file content directly (for source files or matching across
    /// string boundaries in binaries). Unlike `type: text` which only searches
    /// properly extracted/bounded strings, this searches the raw bytes as text.
    /// Use this when you need to match patterns in source code or when string
    /// extraction may not capture what you're looking for.
    /// Example: { type: raw, substr: "eval(" }
    /// Example: { type: raw, exact: "#!/bin/sh" }  # Entire file must equal this
    /// Example: { type: raw, regex: "\\bpassword\\s*=", case_insensitive: true }
    /// Example: { type: raw, word: "socket" }  # Match "socket" as whole word
    Raw {
        /// Full file match (entire file content must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in file)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Match pattern only at word boundaries (convenience for \bpattern\b)
        #[serde(skip_serializing_if = "Option::is_none")]
        word: Option<String>,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
        /// Optional high-fidelity validation check
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        /// Exclude individual matches where evidence matches any of these patterns
        #[serde(skip_serializing_if = "Option::is_none")]
        not: Option<Vec<NotException>>,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(skip_serializing_if = "Option::is_none")]
        section: Option<String>,
        /// Absolute file offset: only match at this exact byte position (negative = from end)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end)
        #[serde(
            skip_serializing_if = "Option::is_none",
            deserialize_with = "offset_range_serde::deserialize"
        )]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(
            skip_serializing_if = "Option::is_none",
            deserialize_with = "offset_range_serde::deserialize"
        )]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Match section names in binary files (PE, ELF, Mach-O)
    /// Replaces YARA patterns like: `for any section in pe.sections : (section.name matches /^UPX/)`
    /// Example: { type: section, regex: "^UPX" }
    /// Example: { type: section, substr: "upx", case_insensitive: true }
    Section {
        /// Full section name match (entire name must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in section name)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Word boundary match (equivalent to regex "\bword\b")
        #[serde(skip_serializing_if = "Option::is_none")]
        word: Option<String>,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
        /// Minimum section length in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        length_min: Option<u64>,
        /// Maximum section length in bytes
        #[serde(skip_serializing_if = "Option::is_none")]
        length_max: Option<u64>,
        /// Minimum section entropy (0.0-8.0)
        #[serde(skip_serializing_if = "Option::is_none")]
        entropy_min: Option<f64>,
        /// Maximum section entropy (0.0-8.0)
        #[serde(skip_serializing_if = "Option::is_none")]
        entropy_max: Option<f64>,
        /// Require section to have read permission (works across PE/ELF/Mach-O)
        #[serde(skip_serializing_if = "Option::is_none")]
        readable: Option<bool>,
        /// Require section to have write permission (works across PE/ELF/Mach-O)
        #[serde(skip_serializing_if = "Option::is_none")]
        writable: Option<bool>,
        /// Require section to have execute permission (works across PE/ELF/Mach-O)
        #[serde(skip_serializing_if = "Option::is_none")]
        executable: Option<bool>,
        /// Reference section (or `"total"` for file size) used as the denominator
        /// for both `size_ratio_*` and `entropy_ratio_*` checks. Defaults to
        /// `"total"` when a size ratio is requested and no pattern is given.
        #[serde(skip_serializing_if = "Option::is_none")]
        compare_to: Option<String>,
        /// Minimum ratio of matched-section size to denominator size.
        #[serde(skip_serializing_if = "Option::is_none")]
        size_ratio_min: Option<f64>,
        /// Maximum ratio of matched-section size to denominator size.
        #[serde(skip_serializing_if = "Option::is_none")]
        size_ratio_max: Option<f64>,
        /// Minimum ratio of matched-section entropy to denominator entropy.
        #[serde(skip_serializing_if = "Option::is_none")]
        entropy_ratio_min: Option<f64>,
        /// Maximum ratio of matched-section entropy to denominator entropy.
        #[serde(skip_serializing_if = "Option::is_none")]
        entropy_ratio_max: Option<f64>,
    },

    /// Match patterns in encoded/decoded strings (unified replacement for base64/xor)
    /// Example: { type: encoded, encoding: base64, regex: "https?://" }
    /// Example: { type: encoded, encoding: [xor, hex], substr: "eval(" }
    /// Example: { type: encoded, word: "password" } - searches ALL encoded strings
    Encoded {
        /// Optional encoding filter - single, multiple, or omit for all
        /// Examples: "base64", ["xor", "hex"], "xor+base64" (chain)
        #[serde(default)]
        encoding: Option<EncodingSpec>,
        /// Full match (entire decoded string must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in decoded string)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Word boundary match (equivalent to regex "\bword\b")
        #[serde(skip_serializing_if = "Option::is_none")]
        word: Option<String>,
        /// Case insensitive matching
        #[serde(default)]
        case_insensitive: bool,
        /// Optional high-fidelity validation check
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        /// Exclude individual matches where evidence matches any of these patterns
        #[serde(skip_serializing_if = "Option::is_none")]
        not: Option<Vec<NotException>>,
        /// Section constraint: only match in this section (supports fuzzy names like "text")
        #[serde(skip_serializing_if = "Option::is_none")]
        section: Option<String>,
        /// Absolute file offset: only match at this exact byte position (negative = from end)
        #[serde(skip_serializing_if = "Option::is_none")]
        offset: Option<i64>,
        /// Absolute offset range: [start, end) (negative values resolved from file end)
        #[serde(
            skip_serializing_if = "Option::is_none",
            deserialize_with = "offset_range_serde::deserialize"
        )]
        offset_range: Option<(i64, Option<i64>)>,
        /// Section-relative offset: only match at this offset within the section
        #[serde(skip_serializing_if = "Option::is_none")]
        section_offset: Option<i64>,
        /// Section-relative offset range: [start, end) within section bounds
        #[serde(
            skip_serializing_if = "Option::is_none",
            deserialize_with = "offset_range_serde::deserialize"
        )]
        section_offset_range: Option<(i64, Option<i64>)>,
    },

    /// Match the basename (final path component, not the full path)
    /// Useful for special files like __init__.py, setup.py, etc.
    /// Example: { type: basename, exact: "__init__.py" }
    /// Example: { type: basename, regex: "^setup\\." }
    Basename {
        /// Full basename match (entire basename must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in basename)
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Regex pattern to match
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
        /// Optional high-fidelity validation check
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
    },

    /// Query structural values using path expressions.
    /// Supports dot notation for nested access and [*] for array iteration.
    /// Example: { type: value, path: "permissions", is: "debugger" }
    /// Example: { type: value, path: "scripts.postinstall", substr: "curl" }
    /// Example: { type: value, path: "content_scripts[*].matches", is: "<all_urls>" }
    /// Example: { type: value, path: "maintainers", size_min: 1, size_max: 1 }
    /// Example: { type: value, path: "file.basename", ne: "pe.version_info.original_filename" }
    Kv {
        /// Path to navigate using dot notation, [n] for indices, [*] for wildcards.
        /// Accepts an optional `<filename>::` prefix to reference a sibling
        /// file's values within the same archive scope.
        path: String,
        /// Value/element equals exactly
        #[serde(
            rename = "is",
            alias = "exact",
            skip_serializing_if = "Option::is_none"
        )]
        exact: Option<String>,
        /// Value/element contains substring
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Value/element matches regex pattern
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Right-hand-side value path for cross-fact equality. When set,
        /// the value at `path` must equal the value at `eq` (case-insensitive,
        /// whitespace-trimmed). Paths accept an optional `<filename>::`
        /// prefix to cross archive entries.
        #[serde(skip_serializing_if = "Option::is_none")]
        eq: Option<String>,
        /// Right-hand-side value path for cross-fact inequality.
        #[serde(skip_serializing_if = "Option::is_none")]
        ne: Option<String>,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
        /// Explicit existence check (true = must exist, false = must not exist)
        #[serde(skip_serializing_if = "Option::is_none")]
        exists: Option<bool>,
        /// Minimum collection size (array elements or object keys)
        #[serde(skip_serializing_if = "Option::is_none")]
        size_min: Option<usize>,
        /// Maximum collection size (array elements or object keys)
        #[serde(skip_serializing_if = "Option::is_none")]
        size_max: Option<usize>,
    },
}

impl Condition {
    /// Returns true if this condition is a trait reference
    #[must_use]
    pub(crate) fn is_trait_reference(&self) -> bool {
        matches!(self, Condition::Trait { .. })
    }

    /// Check if this condition can possibly match for a given file type.
    /// Returns false for conditions that require binary section analysis
    /// when evaluating source/text files.
    #[must_use]
    pub(crate) fn can_match_file_type(&self, file_type: &super::FileType) -> bool {
        use super::FileType;

        // Binary section analysis requires PE/ELF/Mach-O format
        let is_binary = matches!(file_type, FileType::Elf | FileType::Macho | FileType::Pe);

        match self {
            // Section analysis is binary-only
            Condition::Section { .. } => is_binary,

            // AST-backed searches require source code support
            Condition::TreeSitter { .. } | Condition::Literal { .. } => {
                file_type.supports_ast_queries()
            }

            // All other conditions can potentially match any file type
            _ => true,
        }
    }

    /// Returns a description of the condition type for error messages
    #[must_use]
    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Condition::Symbol { .. } => "symbol",
            Condition::Text { .. } => "text",
            Condition::Literal { .. } => "string_literal",
            Condition::Trait { .. } => "trait",
            Condition::TreeSitter { .. } => "tree-sitter",
            Condition::Yara { .. } => "yara",
            Condition::Syscall { .. } => "syscall",
            Condition::Metrics { .. } => "metrics",
            Condition::Hex { .. } => "hex",
            Condition::Raw { .. } => "raw",
            Condition::Section { .. } => "section",
            Condition::Encoded { .. } => "encoded",
            Condition::Basename { .. } => "basename",
            Condition::Kv { .. } => "value",
        }
    }

    /// Validate that condition can be compiled (for YARA/AST rules)
    /// Call this at load time to catch syntax errors early
    pub(crate) fn validate(&self, full: bool) -> Result<()> {
        match self {
            Condition::Yara { source, .. } => {
                // Only validate syntax - add_source catches parse errors
                // Don't call build() here as it triggers expensive JIT compilation
                let mut compiler = yara_x::Compiler::new();
                compiler
                    .add_source(source.as_bytes())
                    .map_err(|e| anyhow::anyhow!("invalid YARA rule: {}", e))?;
                Ok(())
            }
            Condition::TreeSitter {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                language,
                ..
            } => {
                // Validate mode: either (kind/node + exact/substr/regex) or query, not both
                let has_simple_mode = kind.is_some() || node.is_some();
                let has_pattern = exact.is_some() || substr.is_some() || regex.is_some();
                let has_query = query.is_some();

                if has_query && has_simple_mode {
                    return Err(anyhow::anyhow!(
                        "tree-sitter condition cannot have both 'query' and 'kind'/'node'"
                    ));
                }

                if !has_query && !has_simple_mode {
                    return Err(anyhow::anyhow!(
                        "tree-sitter condition must have either 'kind'/'node' or 'query'"
                    ));
                }

                if has_simple_mode && !has_pattern {
                    return Err(anyhow::anyhow!(
                        "tree-sitter condition with 'kind'/'node' must have 'exact', 'substr', or 'regex'"
                    ));
                }

                if kind.is_some() && node.is_some() {
                    return Err(anyhow::anyhow!(
                        "tree-sitter condition cannot have both 'kind' and 'node'"
                    ));
                }

                if exact.is_some() && regex.is_some() {
                    return Err(anyhow::anyhow!(
                        "tree-sitter condition cannot have both 'exact' and 'regex'"
                    ));
                }

                // Validate query if present — skip in fast mode (query compiles at eval time)
                if full && let Some(q) = query {
                    validate_ast_query(q, language.as_deref())?;
                }

                Ok(())
            }
            Condition::Kv {
                path,
                exact,
                substr,
                regex,
                ..
            } => {
                // Path must not be empty
                if path.is_empty() {
                    return Err(anyhow::anyhow!("value condition requires non-empty path"));
                }

                // At most one matcher
                let matchers = [exact.is_some(), substr.is_some(), regex.is_some()];
                if matchers.iter().filter(|&&b| b).count() > 1 {
                    return Err(anyhow::anyhow!(
                        "value condition can only have one of: is, substr, regex"
                    ));
                }

                // Validate regex compiles
                if let Some(re) = regex {
                    regex::Regex::new(re)
                        .map_err(|e| anyhow::anyhow!("invalid regex in value condition: {}", e))?;
                }

                Ok(())
            }
            // Validate location constraints for string/content conditions
            Condition::Text {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            } => validate_location_constraints(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
                "text",
            ),
            Condition::Literal {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            } => validate_location_constraints(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
                "string_literal",
            ),
            Condition::Raw {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            } => validate_location_constraints(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
                "content",
            ),
            Condition::Hex {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            } => {
                // Validate location constraints
                validate_location_constraints(
                    section,
                    *offset,
                    *offset_range,
                    *section_offset,
                    *section_offset_range,
                    "hex",
                )
            }
            // Other conditions don't need compilation validation
            _ => Ok(()),
        }
    }

    /// Pre-compile YARA rules for faster evaluation.
    /// Used for unless/composite conditions that are not in the combined engine.
    pub(crate) fn compile_yara(&mut self) {
        if let Condition::Yara {
            source, compiled, ..
        } = self
            && compiled.is_none()
        {
            let mut compiler = yara_x::Compiler::new();
            compiler.new_namespace("inline");
            if compiler.add_source(source.as_bytes()).is_ok() {
                *compiled = Some(Arc::new(compiler.build()));
            }
        }
    }

    /// Set the combined-engine namespace for this YARA condition.
    /// Called during mapper loading to register that this condition's rule
    /// has been compiled into the main YaraEngine with the given namespace.
    /// Evaluation will then look up pre-scanned results by namespace instead
    /// of re-scanning with the per-condition compiled rules.
    pub(crate) fn set_yara_namespace(&mut self, ns: String) {
        if let Condition::Yara { namespace, .. } = self {
            *namespace = Some(ns);
        }
    }

    /// Check for regex patterns that can cause catastrophic backtracking.
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_greedy_patterns(&self) -> Option<String> {
        let regex_to_check = match self {
            Condition::Text { regex: Some(r), .. }
            | Condition::Raw { regex: Some(r), .. }
            | Condition::TreeSitter { regex: Some(r), .. } => Some(r.as_str()),
            _ => None,
        };

        if let Some(regex) = regex_to_check
            && let Some(issue) = find_backtrack_issue(regex)
        {
            return Some(format!(
                "{} - use bounded pattern like .{{0,50}} instead: {}",
                issue, regex
            ));
        }
        None
    }

    /// Check for regex patterns that are just `\bWORD\b` which should use `type: word` instead.
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_word_boundary_regex(&self) -> Option<String> {
        let regex_to_check = match self {
            Condition::Text { regex: Some(r), .. }
            | Condition::Literal { regex: Some(r), .. }
            | Condition::Raw { regex: Some(r), .. } => Some(r.as_str()),
            _ => None,
        };

        if let Some(regex) = regex_to_check {
            // Check for patterns like \bWORD\b (after YAML parsing, \\b becomes \b)
            // Also handle wrapped patterns like (?:(?:\bWORD\b)) from normalization
            let pattern = regex.trim();
            let unwrapped = pattern
                .strip_prefix("(?:")
                .and_then(|s| s.strip_suffix(")"))
                .map(|s| {
                    s.strip_prefix("(?:")
                        .and_then(|s| s.strip_suffix(")"))
                        .unwrap_or(s)
                })
                .unwrap_or(pattern);

            if unwrapped.starts_with(r"\b") && unwrapped.ends_with(r"\b") && unwrapped.len() > 4 {
                // Extract the word between boundaries
                let word = &unwrapped[2..unwrapped.len() - 2];

                // Check if it's a simple alphanumeric word (no regex metacharacters)
                if !word.is_empty()
                    && word
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
                {
                    return Some(format!(
                        "regex is a simple word boundary pattern - use 'word: \"{}\"' instead",
                        word
                    ));
                }
            }
        }
        None
    }

    /// Check for short case-insensitive patterns that have high collision risk.
    /// Rules:
    /// - 3 or less characters (alphabetic only): always warn
    /// - 4 characters (alphabetic only): only warn if applies to more than 2 file types
    ///
    ///   Mixed alphanumeric strings (like "x509") are exempt - they have fewer variants
    ///   Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_short_case_insensitive(&self, file_type_count: usize) -> Option<String> {
        let check_pattern = |s: &str| -> Option<String> {
            let len = s.len();
            // Only check strings that are entirely alphabetic
            // Mixed alphanumeric like "x509" have fewer collision variants
            if !s.chars().all(char::is_alphabetic) {
                return None;
            }

            if len <= 3 {
                return Some(format!(
                    "case-insensitive match on very short alphabetic string '{}' ({} chars) - high collision risk, use case-sensitive or longer pattern",
                    s, len
                ));
            } else if len == 4 && file_type_count > 2 {
                return Some(format!(
                    "case-insensitive match on short alphabetic string '{}' (4 chars) applies to {} file types - high collision risk, limit to 1-2 types or use case-sensitive",
                    s, file_type_count
                ));
            }
            None
        };

        match self {
            Condition::Text {
                exact: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Literal {
                exact: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Raw {
                exact: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::TreeSitter {
                exact: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Text {
                substr: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Literal {
                substr: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Raw {
                substr: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::TreeSitter {
                substr: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Text {
                word: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Literal {
                word: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Raw {
                word: Some(s),
                case_insensitive: true,
                ..
            } => check_pattern(s),
            _ => None,
        }
    }

    /// Check if count constraints are valid (count_max >= count_min).
    /// Returns a warning message if invalid, None otherwise.
    #[must_use]
    pub(crate) fn check_count_constraints(&self) -> Option<String> {
        // Count constraints are now at trait level (ConditionWithFilters), not per-condition
        None
    }

    /// Check if per-KB density constraints are valid (per_kb_max >= per_kb_min).
    /// Returns a warning message if invalid, None otherwise.
    #[must_use]
    pub(crate) fn check_density_constraints(&self) -> Option<String> {
        // Density constraints are now at trait level (ConditionWithFilters), not per-condition
        None
    }

    /// Check for empty or whitespace-only pattern strings (common LLM mistake).
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_empty_patterns(&self) -> Option<String> {
        let check_empty = |s: &str, field: &str| -> Option<String> {
            if s.trim().is_empty() {
                return Some(format!(
                    "{}: pattern is empty or whitespace-only - specify a non-empty pattern",
                    field
                ));
            }
            None
        };

        match self {
            Condition::Text { exact: Some(s), .. }
            | Condition::Literal { exact: Some(s), .. }
            | Condition::Raw { exact: Some(s), .. }
            | Condition::Symbol { exact: Some(s), .. } => check_empty(s, "exact"),
            Condition::Text {
                substr: Some(s), ..
            }
            | Condition::Literal {
                substr: Some(s), ..
            }
            | Condition::Raw {
                substr: Some(s), ..
            }
            | Condition::Symbol {
                substr: Some(s), ..
            } => check_empty(s, "substr"),
            Condition::Text { regex: Some(s), .. }
            | Condition::Literal { regex: Some(s), .. }
            | Condition::Raw { regex: Some(s), .. }
            | Condition::Symbol { regex: Some(s), .. } => check_empty(s, "regex"),
            Condition::Text { word: Some(s), .. }
            | Condition::Literal { word: Some(s), .. }
            | Condition::Raw { word: Some(s), .. } => check_empty(s, "word"),
            _ => None,
        }
    }

    /// Check for overly short patterns that will match too broadly (common LLM mistake).
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_short_patterns(&self) -> Option<String> {
        let check_short = |s: &str, field: &str, min_len: usize| -> Option<String> {
            if s.len() < min_len {
                return Some(format!(
                    "{}: pattern '{}' is very short ({} chars) and may match too broadly - consider using a longer, more specific pattern",
                    field,
                    s,
                    s.len()
                ));
            }
            None
        };

        match self {
            // For exact matches, warn if less than 2 characters
            Condition::Text {
                exact: Some(s),
                case_insensitive: false,
                ..
            }
            | Condition::Literal {
                exact: Some(s),
                case_insensitive: false,
                ..
            }
            | Condition::Symbol { exact: Some(s), .. } => {
                if s.len() == 1 {
                    return Some(format!(
                        "exact: pattern '{}' is a single character and will rarely be useful - consider if this is intentional",
                        s
                    ));
                }
                None
            }
            // For substr, warn if less than 3 characters (more prone to false positives)
            Condition::Text {
                substr: Some(s),
                case_insensitive: false,
                ..
            }
            | Condition::Literal {
                substr: Some(s),
                case_insensitive: false,
                ..
            }
            | Condition::Symbol {
                substr: Some(s), ..
            } => check_short(s, "substr", 3),
            // For word, warn if less than 2 characters
            Condition::Text {
                word: Some(s),
                case_insensitive: false,
                ..
            }
            | Condition::Literal {
                word: Some(s),
                case_insensitive: false,
                ..
            } => check_short(s, "word", 2),
            _ => None,
        }
    }

    /// Check for regex patterns that are just literal strings (should use substr/exact instead).
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_literal_regex(&self) -> Option<String> {
        let is_literal = |s: &str| -> bool {
            // Check if string contains any regex metacharacters
            !s.chars().any(|c| {
                matches!(
                    c,
                    '.' | '*'
                        | '+'
                        | '?'
                        | '^'
                        | '$'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '|'
                        | '\\'
                )
            })
        };

        match self {
            Condition::Text { regex: Some(r), .. }
            | Condition::Literal { regex: Some(r), .. }
            | Condition::Raw { regex: Some(r), .. }
            | Condition::Symbol { regex: Some(r), .. } => {
                if is_literal(r) {
                    return Some(format!(
                        "regex: pattern '{}' is a literal string with no regex metacharacters - use 'substr' instead for better performance",
                        r
                    ));
                }
                None
            }
            _ => None,
        }
    }

    /// Check if case_insensitive is used with patterns that have no letters.
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_case_insensitive_on_non_alpha(&self) -> Option<String> {
        let check_pattern = |s: &str, field: &str| -> Option<String> {
            if !s.chars().any(char::is_alphabetic) {
                return Some(format!(
                    "case_insensitive: true is set but {}: '{}' contains no letters - case_insensitive has no effect",
                    field, s
                ));
            }
            None
        };

        match self {
            Condition::Text {
                exact: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Literal {
                exact: Some(s),
                case_insensitive: true,
                ..
            } => check_pattern(s, "exact"),
            Condition::Text {
                substr: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Literal {
                substr: Some(s),
                case_insensitive: true,
                ..
            } => check_pattern(s, "substr"),
            Condition::Text {
                word: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Literal {
                word: Some(s),
                case_insensitive: true,
                ..
            } => check_pattern(s, "word"),
            _ => None,
        }
    }

    /// Check for symbol regex patterns that use word boundaries or whitespace.
    /// Symbols don't contain whitespace, so `\b` matches start/end of the symbol string,
    /// meaning `\bfoo\b` is equivalent to `exact: foo`. Whitespace in a symbol regex
    /// will never match anything.
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_symbol_regex_whitespace(&self) -> Option<String> {
        let regex = match self {
            Condition::Symbol { regex: Some(r), .. } => r.as_str(),
            _ => return None,
        };

        // Check for literal whitespace characters (space, tab, \s, \t, etc.)
        // After YAML parsing, these appear as literal chars or escape sequences
        if regex.contains(' ') || regex.contains('\t') {
            return Some(format!(
                "symbol regex '{}' contains whitespace - symbols never contain whitespace, this pattern will never match",
                regex
            ));
        }
        if regex.contains(r"\s") || regex.contains(r"\t") {
            return Some(format!(
                "symbol regex '{}' contains whitespace class (\\s or \\t) - symbols never contain whitespace, this pattern will never match",
                regex
            ));
        }

        // Check for \b word boundary patterns
        if regex.contains(r"\b") {
            // Unwrap optional non-capturing groups from normalization
            let pattern = regex.trim();
            let unwrapped = pattern
                .strip_prefix("(?:")
                .and_then(|s| s.strip_suffix(")"))
                .map(|s| {
                    s.strip_prefix("(?:")
                        .and_then(|s2| s2.strip_suffix(")"))
                        .unwrap_or(s)
                })
                .unwrap_or(pattern);

            // If it's \bWORD\b with a simple word, suggest exact: instead
            if unwrapped.starts_with(r"\b") && unwrapped.ends_with(r"\b") && unwrapped.len() > 4 {
                let word = &unwrapped[2..unwrapped.len() - 2];
                if !word.is_empty()
                    && word
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
                {
                    return Some(format!(
                        "symbol regex '{}' uses word boundaries - symbols don't contain whitespace so \\b matches start/end of symbol, use 'exact: \"{}\"' instead",
                        regex, word
                    ));
                }
            }

            return Some(format!(
                "symbol regex '{}' uses word boundary (\\b) - symbols don't contain whitespace so \\b only matches start/end of symbol, consider using 'exact:' or 'substr:' instead",
                regex
            ));
        }

        None
    }

    /// Check for nonsensical count_min values.
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_count_min_value(&self) -> Option<String> {
        // count_min is now at trait level (ConditionWithFilters), not per-condition
        None
    }

    /// Check if mutually exclusive match types are used together.
    /// Returns a warning message if multiple are set, None otherwise.
    #[must_use]
    pub(crate) fn check_match_exclusivity(&self) -> Option<String> {
        let check_exclusive =
            |exact: bool, substr: bool, regex: bool, word: bool| -> Option<String> {
                let count = [exact, substr, regex, word].iter().filter(|&&x| x).count();
                if count > 1 {
                    let mut types = Vec::new();
                    if exact {
                        types.push("exact");
                    }
                    if substr {
                        types.push("substr");
                    }
                    if regex {
                        types.push("regex");
                    }
                    if word {
                        types.push("word");
                    }
                    return Some(format!(
                        "multiple mutually exclusive match types specified: {} - use only one",
                        types.join(", ")
                    ));
                }
                None
            };

        match self {
            Condition::Text {
                exact,
                substr,
                regex,
                word,
                ..
            }
            | Condition::Literal {
                exact,
                substr,
                regex,
                word,
                ..
            }
            | Condition::Raw {
                exact,
                substr,
                regex,
                word,
                ..
            } => check_exclusive(
                exact.is_some(),
                substr.is_some(),
                regex.is_some(),
                word.is_some(),
            ),
            Condition::Symbol {
                exact,
                substr,
                regex,
                ..
            }
            | Condition::TreeSitter {
                exact,
                substr,
                regex,
                ..
            } => check_exclusive(exact.is_some(), substr.is_some(), regex.is_some(), false),
            _ => None,
        }
    }

    /// Pre-compile regexes in this condition for performance.
    /// Should be called once after deserialization.
    /// Returns an error if any regex pattern is invalid.
    pub(crate) fn precompile_regexes(&mut self) -> anyhow::Result<()> {
        match self {
            Condition::Symbol {
                regex: Some(regex_pattern),
                ..
            } => {
                // Validate only — the compiled regex is resolved lazily and shared
                // process-wide at eval time (see `cached_regex`), so it isn't stored
                // per condition. Compile here purely to surface invalid patterns.
                compile_regex_logged("symbol.regex", regex_pattern, regex_pattern, false).map_err(
                    |e| {
                        anyhow::anyhow!("Failed to compile symbol regex '{}': {}", regex_pattern, e)
                    },
                )?;
            }
            // Text/Literal `word:`/`substr:`/`exact:` are literal matches and
            // `regex:` compiles lazily (shared) on first eval — see
            // `match_value_against_params` + `lazy_regex`/`word_match_start`. So
            // there is nothing to precompile here; eagerly building a
            // `regex::Regex` per condition (the old `\bword\b` etc.) was ~1.5 GB
            // of redundant meta-engine objects, mostly for literal `word:`.
            // Kept as an explicit, documented arm rather than folded into the
            // catch-all below.
            #[allow(clippy::match_same_arms)]
            Condition::Text { .. } | Condition::Literal { .. } => {}
            // Validate only (see Symbol arm). `(?i)` doesn't affect parse
            // validity, so the raw pattern is sufficient to catch errors; eval
            // applies case-insensitivity via `lazy_regex`.
            Condition::Kv {
                regex: Some(regex_pattern),
                ..
            } => {
                compile_regex_logged("value.regex", regex_pattern, regex_pattern, false).map_err(
                    |e| anyhow::anyhow!("Failed to compile value regex '{}': {}", regex_pattern, e),
                )?;
            }
            Condition::Basename {
                regex: Some(regex_pattern),
                ..
            } => {
                compile_regex_logged("basename.regex", regex_pattern, regex_pattern, false)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to compile basename regex '{}': {}",
                            regex_pattern,
                            e
                        )
                    })?;
            }
            _ => {}
        }

        // Substring (`substr:`) matching no longer precompiles a per-condition
        // `Finder`. Boyer-Moore preprocessing is shared process-wide and keyed by
        // needle via `condition::cached_finder` (case-sensitive) /
        // `cached_ci_searcher` (case-insensitive), built once on first eval and
        // reused — so identical needles cost once and only needles that fire cost
        // anything, instead of an owned `Finder` per condition (tens of thousands).
        Ok(())
    }
}

/// Validate a tree-sitter query against the specified language.
///
/// Delegates to filefacts so the grammar registry is owned in one place.
/// When no language is specified, validation is deferred to runtime.
fn validate_ast_query(query: &str, language: Option<&str>) -> Result<()> {
    let Some(name) = language else {
        return Ok(());
    };
    filefacts::validate_source_query(name, query).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Detect regex patterns that cause catastrophic backtracking.
///
/// Returns a short description of the first issue found, or None if the
/// pattern looks safe. Lazy quantifiers (.*?, .+?) and bounded repetitions
/// (.{0,50}) are accepted. Three classes of danger are detected:
///
/// - Unbounded wildcard:  `.*` or `.+`
/// - Negated char class:  `[^x]+` (matches almost anything, equivalent to `.+`)
/// - Nested quantifiers:  `(\w+)+` or `(.+)+` (exponential backtracking)
fn find_backtrack_issue(regex: &str) -> Option<&'static str> {
    let chars: Vec<char> = regex.chars().collect();
    let len = chars.len();
    let mut i = 0;
    // Stack: each entry records whether the group contains a quantified subexpression.
    let mut group_stack: Vec<bool> = Vec::new();

    while i < len {
        match chars[i] {
            '\\' => {
                // Skip the escaped character entirely.
                i += 2;
            }
            '[' => {
                let negated = i + 1 < len && chars[i + 1] == '^';
                i += 1;
                while i < len && chars[i] != ']' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1; // skip ']'
                if i < len && (chars[i] == '*' || chars[i] == '+') {
                    let lazy = i + 1 < len && chars[i + 1] == '?';
                    if !lazy {
                        if negated {
                            return Some("unbounded negated character class (e.g. [^x]+)");
                        }
                        if let Some(top) = group_stack.last_mut() {
                            *top = true;
                        }
                    }
                }
                // Let the next iteration handle the quantifier for group tracking.
            }
            '(' => {
                group_stack.push(false);
                i += 1;
            }
            ')' => {
                let had_inner = group_stack.pop().unwrap_or(false);
                i += 1;
                if i < len && (chars[i] == '*' || chars[i] == '+') {
                    let lazy = i + 1 < len && chars[i + 1] == '?';
                    if !lazy {
                        if had_inner {
                            return Some("nested quantifier (e.g. (\\w+)+ or (.+)+)");
                        }
                        // The group-as-a-whole is now quantified; tell the parent.
                        if let Some(parent) = group_stack.last_mut() {
                            *parent = true;
                        }
                    }
                } else if had_inner {
                    // No quantifier on this group, but it contained quantifiers.
                    // Propagate upward so patterns like ((\w+))+ are caught when
                    // the outer group eventually closes with a quantifier.
                    if let Some(parent) = group_stack.last_mut() {
                        *parent = true;
                    }
                }
            }
            '.' => {
                if i + 1 < len && (chars[i + 1] == '*' || chars[i + 1] == '+') {
                    let lazy = i + 2 < len && chars[i + 2] == '?';
                    if !lazy {
                        return Some("unbounded wildcard (.* or .+)");
                    }
                    // Lazy wildcard still counts as a quantified subexpression.
                    if let Some(top) = group_stack.last_mut() {
                        *top = true;
                    }
                    i += 3;
                    continue;
                }
                // Check for open-ended brace quantifier: .{n,} with no upper bound.
                if i + 1 < len && chars[i + 1] == '{' {
                    let start = i + 2;
                    let mut j = start;
                    while j < len && chars[j] != '}' {
                        j += 1;
                    }
                    if j < len {
                        let inner: String = chars[start..j].iter().collect();
                        // Open-ended: has a comma with nothing after it, e.g. "1," or "0,"
                        if inner.contains(',') && inner.ends_with(',') {
                            return Some(
                                "open-ended range quantifier (.{n,}) — use a bounded range like .{0,50} instead",
                            );
                        }
                    }
                }
                i += 1;
            }
            '*' | '+' => {
                // A bare quantifier on a plain character or escape sequence.
                let lazy = i + 1 < len && chars[i + 1] == '?';
                if !lazy && let Some(top) = group_stack.last_mut() {
                    *top = true;
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    None
}

/// Validate location constraint parameters for consistency.
/// Returns an error if mutually exclusive constraints are specified.
fn validate_location_constraints(
    section: &Option<String>,
    offset: Option<i64>,
    offset_range: Option<(i64, Option<i64>)>,
    section_offset: Option<i64>,
    section_offset_range: Option<(i64, Option<i64>)>,
    condition_type: &str,
) -> Result<()> {
    // offset and offset_range are mutually exclusive
    if offset.is_some() && offset_range.is_some() {
        return Err(anyhow::anyhow!(
            "{} condition cannot have both 'offset' and 'offset_range'",
            condition_type
        ));
    }

    // section_offset and section_offset_range are mutually exclusive
    if section_offset.is_some() && section_offset_range.is_some() {
        return Err(anyhow::anyhow!(
            "{} condition cannot have both 'section_offset' and 'section_offset_range'",
            condition_type
        ));
    }

    // section_offset/section_offset_range require section
    if section.is_none() && (section_offset.is_some() || section_offset_range.is_some()) {
        return Err(anyhow::anyhow!(
            "{} condition with 'section_offset' or 'section_offset_range' requires 'section'",
            condition_type
        ));
    }

    // Validate offset_range format
    if let Some((start, Some(e))) = offset_range
        && start >= 0
        && e >= 0
        && start > e
    {
        return Err(anyhow::anyhow!(
            "{} condition 'offset_range' start ({}) must be <= end ({})",
            condition_type,
            start,
            e
        ));
    }

    // Validate section_offset_range format
    if let Some((start, Some(e))) = section_offset_range
        && start >= 0
        && e >= 0
        && start > e
    {
        return Err(anyhow::anyhow!(
            "{} condition 'section_offset_range' start ({}) must be <= end ({})",
            condition_type,
            start,
            e
        ));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod location_constraint_tests {
    use super::*;

    #[test]
    fn test_validate_location_no_constraints() {
        let result = validate_location_constraints(&None, None, None, None, None, "text");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_section_only() {
        let result = validate_location_constraints(
            &Some(".text".to_string()),
            None,
            None,
            None,
            None,
            "text",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_offset_only() {
        let result = validate_location_constraints(&None, Some(0x1000), None, None, None, "text");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_offset_range_only() {
        let result =
            validate_location_constraints(&None, None, Some((0, Some(0x1000))), None, None, "text");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_offset_and_offset_range_fails() {
        let result = validate_location_constraints(
            &None,
            Some(0x100),
            Some((0, Some(0x1000))),
            None,
            None,
            "text",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("offset"));
    }

    #[test]
    fn test_validate_location_section_offset_without_section_fails() {
        let result = validate_location_constraints(&None, None, None, Some(0x100), None, "content");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("requires 'section'")
        );
    }

    #[test]
    fn test_validate_location_section_offset_range_without_section_fails() {
        let result = validate_location_constraints(
            &None,
            None,
            None,
            None,
            Some((0, Some(0x100))),
            "base64",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_location_section_with_section_offset() {
        let result = validate_location_constraints(
            &Some(".data".to_string()),
            None,
            None,
            Some(0x100),
            None,
            "xor",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_section_offset_and_range_fails() {
        let result = validate_location_constraints(
            &Some(".text".to_string()),
            None,
            None,
            Some(0x100),
            Some((0, Some(0x200))),
            "text",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("section_offset"));
    }

    #[test]
    fn test_validate_location_invalid_offset_range() {
        // start > end should fail
        let result = validate_location_constraints(
            &None,
            None,
            Some((0x1000, Some(0x100))), // 0x1000 > 0x100
            None,
            None,
            "text",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("start"));
    }

    #[test]
    fn test_validate_location_negative_offsets_allowed() {
        // Negative offsets are allowed (means from end)
        let result =
            validate_location_constraints(&None, None, Some((-1024, None)), None, None, "content");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_open_ended_range() {
        // Open-ended range (start, None) is allowed
        let result =
            validate_location_constraints(&None, None, Some((0x1000, None)), None, None, "text");
        assert!(result.is_ok());
    }

    #[test]
    fn test_condition_validate_string_location() {
        // Test that Condition::Text validates location constraints
        let condition = Condition::Text {
            exact: Some("test".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            section: None,
            offset: Some(0x100),
            offset_range: Some((0, Some(0x1000))), // Mutually exclusive with offset
            section_offset: None,
            section_offset_range: None,
            platforms: None,
        };
        assert!(condition.validate(true).is_err());
    }

    #[test]
    fn test_condition_validate_content_location() {
        // Valid content condition with section constraint
        let condition = Condition::Raw {
            exact: Some("test".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            section: Some(".text".to_string()),
            offset: None,
            offset_range: Some((0, Some(0x1000))),
            section_offset: None,
            section_offset_range: None,
        };
        assert!(condition.validate(true).is_ok());
    }

    #[test]
    fn test_offset_range_deser_closed_range() {
        // Test [start, end] format - deserialize as a tuple
        let yaml = "[100, 200]";
        let result: Result<Option<(i64, Option<i64>)>, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Some((100, Some(200))));
    }

    #[test]
    fn test_offset_range_deser_open_end() {
        // Test [start,] format - open-ended to end of file
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct TestStruct {
            #[serde(deserialize_with = "offset_range_serde::deserialize")]
            offset_range: Option<(i64, Option<i64>)>,
        }

        let yaml = "offset_range: [-1024,]";
        let result: Result<TestStruct, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.offset_range, Some((-1024, None)));
    }

    #[test]
    fn test_offset_range_deser_open_start() {
        // Test [~, end] format - open-ended from beginning (YAML null syntax)
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct TestStruct {
            #[serde(deserialize_with = "offset_range_serde::deserialize")]
            offset_range: Option<(i64, Option<i64>)>,
        }

        let yaml = "offset_range: [~, 1024]";
        let result: Result<TestStruct, _> = serde_yaml::from_str(yaml);
        if let Err(ref e) = result {
            eprintln!("Deserialization error: {}", e);
        }
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.offset_range, Some((0, Some(1024))));
    }

    #[test]
    fn test_offset_range_deser_null_end() {
        // Test [start, null] format - compatibility with explicit null
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct TestStruct {
            #[serde(deserialize_with = "offset_range_serde::deserialize")]
            offset_range: Option<(i64, Option<i64>)>,
        }

        let yaml = "offset_range: [100, null]";
        let result: Result<TestStruct, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.offset_range, Some((100, None)));
    }

    #[test]
    fn test_offset_range_deser_tilde_end() {
        // Test [start, ~] format - YAML null syntax (most ergonomic)
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct TestStruct {
            #[serde(deserialize_with = "offset_range_serde::deserialize")]
            offset_range: Option<(i64, Option<i64>)>,
        }

        let yaml = "offset_range: [100, ~]";
        let result: Result<TestStruct, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.offset_range, Some((100, None)));
    }

    #[test]
    fn test_offset_range_deser_null_start() {
        // Test [null, end] format - compatibility with explicit null
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct TestStruct {
            #[serde(deserialize_with = "offset_range_serde::deserialize")]
            offset_range: Option<(i64, Option<i64>)>,
        }

        let yaml = "offset_range: [null, 1024]";
        let result: Result<TestStruct, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.offset_range, Some((0, Some(1024))));
    }

    #[test]
    fn test_offset_range_deser_negative_offset() {
        // Test negative offsets (from end of file)
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct TestStruct {
            #[serde(deserialize_with = "offset_range_serde::deserialize")]
            offset_range: Option<(i64, Option<i64>)>,
        }

        let yaml = "offset_range: [-1024, -512]";
        let result: Result<TestStruct, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.offset_range, Some((-1024, Some(-512))));
    }

    #[test]
    fn test_section_offset_range_deser() {
        // Test section_offset_range with same formats
        #[derive(Debug, serde::Deserialize, PartialEq)]
        struct TestStruct {
            #[serde(deserialize_with = "offset_range_serde::deserialize")]
            section_offset_range: Option<(i64, Option<i64>)>,
        }

        let yaml = "section_offset_range: [100,]";
        let result: Result<TestStruct, _> = serde_yaml::from_str(yaml);
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.section_offset_range, Some((100, None)));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod backtrack_tests {
    use super::find_backtrack_issue;
    use crate::composite_rules::Condition;
    use crate::composite_rules::condition::SymbolKind;

    // ── patterns that MUST be flagged ──────────────────────────────────────

    #[test]
    fn dot_star_caught() {
        assert!(find_backtrack_issue(".*").is_some());
    }

    #[test]
    fn dot_plus_caught() {
        assert!(find_backtrack_issue(".+").is_some());
    }

    #[test]
    fn dot_star_in_middle_caught() {
        assert!(find_backtrack_issue("foo.*bar").is_some());
    }

    #[test]
    fn dot_star_after_flag_group_caught() {
        // (?i).* — the (?i) flag group should not suppress detection
        assert!(find_backtrack_issue("(?i).*").is_some());
    }

    #[test]
    fn negated_class_plus_caught() {
        assert!(find_backtrack_issue("[^)]+").is_some());
    }

    #[test]
    fn negated_class_star_caught() {
        assert!(find_backtrack_issue("[^abc]*").is_some());
    }

    #[test]
    fn negated_class_with_escape_inside_caught() {
        // [^\s]+ — backslash-s inside the class, class still negated
        assert!(find_backtrack_issue(r"[^\s]+").is_some());
    }

    #[test]
    fn nested_quantifier_word_char_caught() {
        // (\w+)+ — the canonical ReDoS pattern
        assert!(find_backtrack_issue(r"(\w+)+").is_some());
    }

    #[test]
    fn nested_quantifier_dot_plus_caught() {
        // (.+)+ — .+ is caught as an unbounded wildcard before the nesting is relevant
        assert!(find_backtrack_issue("(.+)+").is_some());
    }

    #[test]
    fn nested_quantifier_char_class_caught() {
        // ([a-z]+)+ — bounded class, but the outer quantifier creates the danger
        assert!(find_backtrack_issue("([a-z]+)+").is_some());
    }

    #[test]
    fn nested_quantifier_alternation_caught() {
        // (?:a+|b+)+ — quantified branches inside a repeated group
        assert!(find_backtrack_issue("(?:a+|b+)+").is_some());
    }

    #[test]
    fn doubly_nested_quantifier_caught() {
        // ((\w+))+ — inner group propagates its quantifier flag to the outer
        assert!(find_backtrack_issue(r"((\w+))+").is_some());
    }

    #[test]
    fn nested_quantifier_with_star_caught() {
        assert!(find_backtrack_issue(r"(\w+)*").is_some());
    }

    #[test]
    fn real_world_eval_decrypt_pattern_caught() {
        let pat = r"(?i)(\$[a-zA-Z0-9_]+\s*=\s*[a-zA-Z0-9_]*Decrypt.*\(.+\);\s*eval\s*\(\s*\$[a-zA-Z0-9_]+\s*\)|eval\s*\(\s*[a-zA-Z0-9_]*Decrypt.*\(.+\)\s*\))";
        assert!(find_backtrack_issue(pat).is_some());
    }

    #[test]
    fn greedy_pattern_lint_skips_kv_regex() {
        let cond = Condition::Kv {
            path: "debug.pdb_path".to_string(),
            exact: None,
            substr: None,
            regex: Some(r"(?i)PQT_Downloader[\\/].*[\\/]PQT_Downloader\.pdb$".to_string()),
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            size_min: None,
            size_max: None,
        };
        assert!(cond.check_greedy_patterns().is_none());
    }

    #[test]
    fn symbol_family_condition_types_set_kind() {
        let import_cond: Condition = serde_yaml::from_str(
            r#"
type: import
regex: "^CreateFileW$"
"#,
        )
        .unwrap();
        let export_cond: Condition = serde_yaml::from_str(
            r#"
type: export
substr: DllRegisterServer
"#,
        )
        .unwrap();
        let function_cond: Condition = serde_yaml::from_str(
            r#"
type: function
exact: main
"#,
        )
        .unwrap();

        assert!(matches!(
            import_cond,
            Condition::Symbol {
                kind: Some(SymbolKind::Import),
                regex: Some(ref r),
                ..
            } if r == "^CreateFileW$"
        ));
        assert!(matches!(
            export_cond,
            Condition::Symbol {
                kind: Some(SymbolKind::Export),
                substr: Some(ref s),
                ..
            } if s == "DllRegisterServer"
        ));
        assert!(matches!(
            function_cond,
            Condition::Symbol {
                kind: Some(SymbolKind::Function),
                exact: Some(ref s),
                ..
            } if s == "main"
        ));
    }

    #[test]
    fn value_condition_accepts_is() {
        let current: Condition = serde_yaml::from_str(
            r#"
type: value
path: scripts.postinstall
is: curl
"#,
        )
        .unwrap();
        let legacy: Condition = serde_yaml::from_str(
            r#"
type: value
path: scripts.postinstall
exact: curl
"#,
        )
        .unwrap();

        assert_eq!(current.type_name(), "value");
        assert_eq!(legacy.type_name(), "value");
        assert!(matches!(
            current,
            Condition::Kv {
                exact: Some(ref s),
                ..
            } if s == "curl"
        ));
        assert!(matches!(
            legacy,
            Condition::Kv {
                exact: Some(ref s),
                ..
            } if s == "curl"
        ));
    }

    #[test]
    fn literal_yaml_accepts_both_type_literal_and_type_string_literal() {
        // Backward-compat alias: rules authored as `type: string_literal`
        // must continue parsing into Condition::Literal so the existing
        // trait corpus keeps working.
        let new_form: Condition =
            serde_yaml::from_str("type: literal\nsubstr: rm -rf").expect("parse type: literal");
        let old_form: Condition = serde_yaml::from_str("type: string_literal\nsubstr: rm -rf")
            .expect("parse type: string_literal");
        assert!(matches!(new_form, Condition::Literal { .. }));
        assert!(matches!(old_form, Condition::Literal { .. }));
    }

    #[test]
    fn numeric_literal_match_fires_on_chmod_octal_777() {
        // End-to-end: synthesize what the AST walker would produce for
        // an octal literal `0o777`, then exercise the evaluator dispatch
        // for `type: literal, kind: number, value: 511, radix: 8`. The
        // value+radix pair lets authors distinguish `0o777` from
        // decimal `511` even though they represent the same integer.
        use crate::composite_rules::types::Platform;
        use crate::types::binary::StringInfo;
        use crate::types::{AnalysisReport, TargetInfo};

        let mut report = AnalysisReport::new(TargetInfo::default());
        report.strings.push(StringInfo {
            value: "511".to_string(),
            offset: Some(0x40),
            string_type: None,
            encoding: "8".to_string(),
            section: Some("ast-number".to_string()),
            encoding_chain: Vec::new(),
            fragments: None,
        });
        let platforms = vec![Platform::All];
        let ctx = crate::composite_rules::EvaluationContext::new(
            &report,
            b"",
            crate::composite_rules::types::FileType::Python,
            &platforms,
            None,
            None,
        );

        // Right value + right radix → match.
        let res = crate::composite_rules::evaluators::symbol_string::eval_numeric_literal(
            Some(511),
            Some(8),
            &ctx,
        );
        assert!(res.matched, "0o777 (value=511, radix=8) should match");
        assert_eq!(res.match_count, 1);

        // Right value, wrong radix → no match (source wrote octal, not decimal).
        let res = crate::composite_rules::evaluators::symbol_string::eval_numeric_literal(
            Some(511),
            Some(10),
            &ctx,
        );
        assert!(!res.matched, "wrong radix should not match");

        // Wrong value → no match.
        let res = crate::composite_rules::evaluators::symbol_string::eval_numeric_literal(
            Some(777),
            Some(8),
            &ctx,
        );
        assert!(!res.matched, "wrong value should not match");

        // Value-only (no radix constraint) → match.
        let res = crate::composite_rules::evaluators::symbol_string::eval_numeric_literal(
            Some(511),
            None,
            &ctx,
        );
        assert!(res.matched, "value-only filter should match");
    }

    #[test]
    fn literal_yaml_parses_numeric_kind_with_value_and_radix() {
        // The new numeric-matching surface: `kind: number` with
        // `value` + `radix`. The evaluator dispatch is a TODO; this
        // test just locks in that the grammar accepts the shape.
        let cond: Condition =
            serde_yaml::from_str("type: literal\nkind: number\nvalue: 511\nradix: 8")
                .expect("parse numeric literal");
        assert!(matches!(cond, Condition::Literal { .. }));
        if let Condition::Literal {
            kind, value, radix, ..
        } = cond
        {
            assert_eq!(kind.as_deref(), Some("number"));
            assert_eq!(value, Some(511));
            assert_eq!(radix, Some(8));
        }
    }

    #[test]
    fn greedy_pattern_lint_skips_string_literal_regex() {
        let cond = Condition::Literal {
            kind: None,
            exact: None,
            substr: None,
            regex: Some(r"^ssh(d|-.+)?$".to_string()),
            word: None,
            value: None,
            radix: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        };
        assert!(cond.check_greedy_patterns().is_none());
    }

    #[test]
    fn greedy_pattern_lint_skips_symbol_regex() {
        let cond = Condition::Symbol {
            exact: None,
            substr: None,
            regex: Some(r"^libc\.so(\.[0-9]+)*$".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            not: None,
        };
        assert!(cond.check_greedy_patterns().is_none());
    }

    #[test]
    fn greedy_pattern_lint_skips_basename_regex() {
        let cond = Condition::Basename {
            exact: None,
            substr: None,
            regex: Some(r"^ssh(d|-.+)?$".to_string()),
            case_insensitive: false,
            is_check: None,
        };
        assert!(cond.check_greedy_patterns().is_none());
    }

    #[test]
    fn open_ended_range_quantifier_caught() {
        // .{1,} is semantically equivalent to .+ and must be flagged
        assert!(find_backtrack_issue(".{1,}").is_some());
    }

    #[test]
    fn open_ended_range_zero_caught() {
        // .{0,} is semantically equivalent to .* and must be flagged
        assert!(find_backtrack_issue(".{0,}").is_some());
    }

    #[test]
    fn open_ended_range_in_pattern_caught() {
        // .{2,} embedded in a larger pattern must be flagged
        assert!(find_backtrack_issue(r"foo.{2,}bar").is_some());
    }

    // ── patterns that must NOT be flagged ──────────────────────────────────

    #[test]
    fn lazy_dot_star_ok() {
        assert!(find_backtrack_issue(".*?").is_none());
    }

    #[test]
    fn lazy_dot_plus_ok() {
        assert!(find_backtrack_issue(".+?").is_none());
    }

    #[test]
    fn bounded_repetition_ok() {
        assert!(find_backtrack_issue(".{0,50}").is_none());
    }

    #[test]
    fn word_char_plus_alone_ok() {
        // \w+ is not nested and not a wildcard — safe
        assert!(find_backtrack_issue(r"\w+").is_none());
    }

    #[test]
    fn whitespace_star_ok() {
        // \s* is bounded by the whitespace character class — safe on its own
        assert!(find_backtrack_issue(r"\s*").is_none());
    }

    #[test]
    fn non_negated_class_plus_ok() {
        // [a-z]+ is a bounded positive class — safe
        assert!(find_backtrack_issue("[a-z]+").is_none());
    }

    #[test]
    fn escaped_dot_ok() {
        // \. is a literal dot, not a wildcard — \. followed by * is fine
        assert!(find_backtrack_issue(r"\.*").is_none());
    }

    #[test]
    fn dot_inside_class_ok() {
        // [.*]+ — the . inside [] is a literal character, not a wildcard
        assert!(find_backtrack_issue("[.*]+").is_none());
    }

    #[test]
    fn simple_alternation_ok() {
        // (foo|bar)+ — no quantifiers inside the group branches
        assert!(find_backtrack_issue("(foo|bar)+").is_none());
    }

    #[test]
    fn simple_literal_group_repeated_ok() {
        assert!(find_backtrack_issue("(abc)+").is_none());
    }

    #[test]
    fn empty_pattern_ok() {
        assert!(find_backtrack_issue("").is_none());
    }

    #[test]
    fn plain_literal_ok() {
        assert!(find_backtrack_issue("hello world").is_none());
    }

    // ── message content ────────────────────────────────────────────────────

    #[test]
    fn dot_star_message_mentions_wildcard() {
        let msg = find_backtrack_issue(".*").unwrap();
        assert!(msg.contains("wildcard"), "got: {msg}");
    }

    #[test]
    fn negated_class_message_mentions_negated() {
        let msg = find_backtrack_issue("[^x]+").unwrap();
        assert!(msg.contains("negated"), "got: {msg}");
    }

    #[test]
    fn nested_quantifier_message_mentions_nested() {
        let msg = find_backtrack_issue(r"(\w+)+").unwrap();
        assert!(msg.contains("nested"), "got: {msg}");
    }

    // ── word_match_start: literal `word:` matcher equivalence ────────────────

    /// `word_match_start` must agree with the regex `\bneedle\b` it replaced,
    /// including at non-ASCII (Unicode word-char) neighbours.
    #[allow(clippy::expect_used)]
    fn assert_word_matches_regex(haystack: &str, needle: &str) {
        let pat = format!(r"\b{}\b", regex::escape(needle));
        let re = regex::Regex::new(&pat).expect("valid regex");
        let want = re.find(haystack).map(|m| m.start());
        let got = super::word_match_start(haystack, needle, false);
        assert_eq!(
            want, got,
            "needle={needle:?} haystack={haystack:?}: regex={want:?} literal={got:?}"
        );
    }

    #[test]
    fn word_match_agrees_with_regex_word_boundary() {
        for (h, n) in [
            ("run eval here", "eval"),
            ("evaluate", "eval"),   // suffix → no boundary
            ("preeval", "eval"),    // prefix → no boundary
            ("eval", "eval"),       // whole string
            ("(eval)", "eval"),     // punctuation neighbours
            ("a.eval.b", "eval"),   // dotted
            ("ñeval", "eval"),      // leading non-ASCII letter → no boundary
            ("evalé done", "eval"), // trailing non-ASCII letter → no boundary
            ("no match", "eval"),
        ] {
            assert_word_matches_regex(h, n);
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn word_match_returns_matched_slice_preserving_case() {
        // Case-insensitive match still reports the text as it appears in the
        // haystack (not the lowercased needle) — mirrors the old `mat.as_str()`.
        let start = super::word_match_start("call EVAL now", "eval", true).expect("match");
        assert_eq!(&"call EVAL now"[start..start + "eval".len()], "EVAL");
    }

    #[test]
    fn word_match_empty_needle_never_matches() {
        assert_eq!(super::word_match_start("anything", "", false), None);
    }
}
