//! Condition types for composite rules.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::types::Platform;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

/// String exception specification for `not:` directive
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub(crate) enum NotException {
    /// Shorthand: bare string defaults to substr match
    Shorthand(String),

    /// Structured exception with explicit match type
    Structured {
        /// Require exact string equality to trigger the exception
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Require the value to contain this substring to trigger the exception
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Require the value to match this regex to trigger the exception
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
    },
}

impl NotException {
    /// Check if a string matches this exception
    #[must_use]
    pub(crate) fn matches(&self, value: &str) -> bool {
        match self {
            NotException::Shorthand(pattern) => {
                value.to_lowercase().contains(&pattern.to_lowercase())
            }
            NotException::Structured {
                exact,
                substr,
                regex,
            } => {
                if let Some(exact_str) = exact {
                    value.eq_ignore_ascii_case(exact_str)
                } else if let Some(substr_str) = substr {
                    value.to_lowercase().contains(&substr_str.to_lowercase())
                } else if let Some(regex_str) = regex {
                    regex::Regex::new(regex_str)
                        .map(|re| re.is_match(value))
                        .unwrap_or(false)
                } else {
                    false
                }
            }
        }
    }
}

/// Intermediate type for deserializing conditions with shorthand support.
/// Converts `{ id: my-trait }` to `Condition::Trait { id: "my-trait" }`.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ConditionDeser {
    /// Shorthand for trait reference - just `id` field, no `type` needed
    /// Must be listed first so serde tries it before the tagged variants
    TraitShorthand { id: String },

    /// All other condition types require explicit `type` field
    Tagged(Box<ConditionTagged>),
}

/// Internal tagged enum for serializing/deserializing conditions with explicit `type` field
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ConditionTagged {
    Symbol {
        /// Full symbol name match (entire symbol must equal this)
        #[serde(default)]
        exact: Option<String>,
        /// Substring match (appears anywhere in symbol name)
        #[serde(default)]
        substr: Option<String>,
        /// Regex pattern to match symbol names
        #[serde(default)]
        regex: Option<String>,
        #[serde(default)]
        platforms: Option<Vec<Platform>>,
    },
    String {
        /// Full string match (entire string must equal this)
        #[serde(default)]
        exact: Option<String>,
        /// Substring match (appears anywhere in string)
        #[serde(default)]
        substr: Option<String>,
        /// Regex pattern match
        #[serde(default)]
        regex: Option<String>,
        /// Word boundary match (equivalent to regex "\bword\b")
        #[serde(default)]
        word: Option<String>,
        #[serde(default)]
        case_insensitive: bool,
        /// Require match to contain a valid external IP address (not private/loopback/reserved)
        #[serde(default)]
        external_ip: bool,
        /// Section constraint: only match strings in this section (supports fuzzy names like "text")
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
    Structure {
        feature: String,
        #[serde(default)]
        min_sections: Option<usize>,
    },
    ExportsCount {
        #[serde(default)]
        min: Option<usize>,
        #[serde(default)]
        max: Option<usize>,
    },
    Trait {
        id: String,
    },
    /// Unified AST condition type - replaces ast_pattern and ast_query
    /// Simple mode: kind + exact/substr/regex (or node + exact/substr/regex for raw node types)
    /// Advanced mode: query (tree-sitter S-expression)
    Ast {
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
    SectionRatio {
        section: String,
        #[serde(default = "default_compare_to")]
        compare_to: String,
        #[serde(default)]
        min: Option<f64>,
        #[serde(default)]
        max: Option<f64>,
    },
    ImportCombination {
        #[serde(default)]
        required: Option<Vec<String>>,
        #[serde(default)]
        suspicious: Option<Vec<String>>,
        #[serde(default)]
        min_suspicious: Option<usize>,
        #[serde(default)]
        max_total: Option<usize>,
    },
    StringCount {
        #[serde(default)]
        min: Option<usize>,
        #[serde(default)]
        max: Option<usize>,
        #[serde(default)]
        min_length: Option<usize>,
        #[serde(default)]
        regex: Option<String>,
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
    /// across string boundaries in binaries). Unlike `type: string` which only
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
        /// Require match to contain a valid external IP address (not private/loopback/reserved)
        #[serde(default)]
        external_ip: bool,
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
    },

    /// Query structured data in JSON, YAML, and TOML manifests using path expressions.
    /// Supports dot notation for nested access and [*] for array iteration.
    /// Example: { type: kv, path: "permissions", exact: "debugger" }
    /// Example: { type: kv, path: "scripts.postinstall", substr: "curl" }
    /// Example: { type: kv, path: "content_scripts[*].matches", exact: "<all_urls>" }
    /// Example: { type: kv, path: "maintainers", size_min: 1, size_max: 1 }
    Kv {
        /// Path to navigate using dot notation, [n] for indices, [*] for wildcards
        path: String,
        /// Value/element equals exactly
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Value/element contains substring
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Value/element matches regex pattern
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
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
            ConditionDeser::TraitShorthand { id } => Condition::Trait { id },
            ConditionDeser::Tagged(tagged) => match *tagged {
                ConditionTagged::Symbol {
                    exact,
                    substr,
                    regex,
                    platforms,
                } => Condition::Symbol {
                    exact,
                    substr,
                    regex,
                    platforms,
                    compiled_regex: None,
                },
                ConditionTagged::String {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    external_ip,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                } => Condition::String {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    external_ip,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                    compiled_regex: None,
                },
                ConditionTagged::Structure {
                    feature,
                    min_sections,
                } => Condition::Structure {
                    feature,
                    min_sections,
                },
                ConditionTagged::ExportsCount { min, max } => Condition::ExportsCount { min, max },
                ConditionTagged::Trait { id } => Condition::Trait { id },
                ConditionTagged::Ast {
                    kind,
                    node,
                    exact,
                    substr,
                    regex,
                    query,
                    language,
                    case_insensitive,
                } => Condition::Ast {
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
                ConditionTagged::SectionRatio {
                    section,
                    compare_to,
                    min,
                    max,
                } => Condition::SectionRatio {
                    section,
                    compare_to,
                    min,
                    max,
                },
                ConditionTagged::ImportCombination {
                    required,
                    suspicious,
                    min_suspicious,
                    max_total,
                } => Condition::ImportCombination {
                    required,
                    suspicious,
                    min_suspicious,
                    max_total,
                },
                ConditionTagged::StringCount {
                    min,
                    max,
                    min_length,
                    regex,
                } => Condition::StringCount {
                    min,
                    max,
                    min_length,
                    regex,
                    compiled_regex: None,
                },
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
                    offset,
                    offset_range,
                    section,
                    section_offset,
                    section_offset_range,
                } => Condition::Hex {
                    pattern,
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
                    external_ip,
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
                    external_ip,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                    compiled_regex: None,
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
                },
                ConditionTagged::Encoded {
                    encoding,
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
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
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                    compiled_regex: None,
                },
                ConditionTagged::Basename {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                } => Condition::Basename {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                },
                ConditionTagged::Kv {
                    path,
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                    exists,
                    size_min,
                    size_max,
                } => Condition::Kv {
                    path,
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                    exists,
                    size_min,
                    size_max,
                    compiled_regex: None,
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
                compiled_regex: _,
            } => ConditionTagged::Symbol {
                exact,
                substr,
                regex,
                platforms,
            },
            Condition::String {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                external_ip,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                compiled_regex: _,
            } => ConditionTagged::String {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                external_ip,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            },
            Condition::Structure {
                feature,
                min_sections,
            } => ConditionTagged::Structure {
                feature,
                min_sections,
            },
            Condition::ExportsCount { min, max } => ConditionTagged::ExportsCount { min, max },
            Condition::Trait { id } => ConditionTagged::Trait { id },
            Condition::Ast {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                language,
                case_insensitive,
            } => ConditionTagged::Ast {
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
            Condition::SectionRatio {
                section,
                compare_to,
                min,
                max,
            } => ConditionTagged::SectionRatio {
                section,
                compare_to,
                min,
                max,
            },
            Condition::ImportCombination {
                required,
                suspicious,
                min_suspicious,
                max_total,
            } => ConditionTagged::ImportCombination {
                required,
                suspicious,
                min_suspicious,
                max_total,
            },
            Condition::StringCount {
                min,
                max,
                min_length,
                regex,
                compiled_regex: _,
            } => ConditionTagged::StringCount {
                min,
                max,
                min_length,
                regex,
            },
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
                offset,
                offset_range,
                section,
                section_offset,
                section_offset_range,
            } => ConditionTagged::Hex {
                pattern,
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
                external_ip,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                compiled_regex: _,
            } => ConditionTagged::Raw {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                external_ip,
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
            },
            Condition::Encoded {
                encoding,
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                compiled_regex: _,
            } => ConditionTagged::Encoded {
                encoding,
                exact,
                substr,
                regex,
                word,
                case_insensitive,
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
            } => ConditionTagged::Basename {
                exact,
                substr,
                regex,
                case_insensitive,
            },
            Condition::Kv {
                path,
                exact,
                substr,
                regex,
                case_insensitive,
                exists,
                size_min,
                size_max,
                compiled_regex: _,
            } => ConditionTagged::Kv {
                path,
                exact,
                substr,
                regex,
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
/// 1. Tagged: `{ type: string, exact: "foo" }` - explicit type field
/// 2. Shorthand: `{ id: my-trait }` - defaults to Trait when only `id` is present
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(from = "ConditionDeser", into = "ConditionTagged")]
pub(crate) enum Condition {
    /// Match a symbol (import/export)
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
        /// Pre-compiled regex (populated after deserialization, not serialized)
        #[serde(skip)]
        compiled_regex: Option<regex::Regex>,
    },

    /// Match a string in the binary
    String {
        /// Full string match (entire string must equal this)
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Substring match (appears anywhere in string)
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
        /// Require match to contain a valid external IP address (not private/loopback/reserved)
        #[serde(default)]
        external_ip: bool,
        /// Section constraint: only match strings in this section (supports fuzzy names like "text")
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
        /// Pre-compiled regex (populated after deserialization, not serialized)
        #[serde(skip)]
        compiled_regex: Option<regex::Regex>,
    },

    /// Match a structural feature
    Structure {
        /// Feature identifier (e.g., "packed", "stripped", "signed")
        feature: String,
        /// Minimum number of matching sections required
        #[serde(skip_serializing_if = "Option::is_none")]
        min_sections: Option<usize>,
    },

    /// Check export count
    ExportsCount {
        /// Minimum export count required
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<usize>,
        /// Maximum export count allowed
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<usize>,
    },

    /// Reference a previously-defined trait by ID
    Trait {
        /// The ID of the trait to reference
        id: String,
    },

    /// Unified AST condition - search for patterns in AST nodes
    ///
    /// Simple mode (kind + exact/substr/regex):
    /// ```yaml
    /// type: ast
    /// kind: call              # abstract kind: call, function, class, import, etc.
    /// substr: "eval"          # substring match
    /// # OR
    /// exact: "eval"           # full match (entire node text must equal this)
    /// # OR
    /// regex: "eval\\("        # regex match
    /// ```
    ///
    /// Raw node type mode (node + exact/substr/regex):
    /// ```yaml
    /// type: ast
    /// node: call_expression   # raw tree-sitter node type (escape hatch)
    /// substr: "eval"
    /// ```
    ///
    /// Advanced mode (query):
    /// ```yaml
    /// type: ast
    /// query: |
    ///   (call_expression
    ///     function: (identifier) @fn
    ///     (#eq? @fn "eval"))
    /// language: javascript    # optional, for validation
    /// ```
    Ast {
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

    /// Check section size ratio (e.g., __const is 80%+ of binary)
    /// For detecting encrypted payload droppers
    SectionRatio {
        /// Section name pattern (regex)
        section: String,
        /// Compare to "total" binary size or another section pattern
        #[serde(default = "default_compare_to")]
        compare_to: String,
        /// Minimum ratio (0.0-1.0)
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<f64>,
        /// Maximum ratio (0.0-1.0)
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<f64>,
    },

    /// Check import patterns (required + suspicious combination)
    /// For detecting malware import fingerprints
    ImportCombination {
        /// All of these imports must be present
        #[serde(skip_serializing_if = "Option::is_none")]
        required: Option<Vec<String>>,
        /// Count matches from this suspicious list
        #[serde(skip_serializing_if = "Option::is_none")]
        suspicious: Option<Vec<String>>,
        /// Minimum number of suspicious imports required
        #[serde(skip_serializing_if = "Option::is_none")]
        min_suspicious: Option<usize>,
        /// Maximum total import count (low count = suspicious)
        #[serde(skip_serializing_if = "Option::is_none")]
        max_total: Option<usize>,
    },

    /// Check extracted string count
    /// For detecting string concealment (very few visible strings)
    StringCount {
        /// Minimum number of strings
        #[serde(skip_serializing_if = "Option::is_none")]
        min: Option<usize>,
        /// Maximum number of strings (low count = suspicious)
        #[serde(skip_serializing_if = "Option::is_none")]
        max: Option<usize>,
        /// Only count strings of this minimum length
        #[serde(skip_serializing_if = "Option::is_none")]
        min_length: Option<usize>,
        /// Only count strings matching this regex
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        /// Pre-compiled regex
        #[serde(skip)]
        compiled_regex: Option<regex::Regex>,
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
    /// string boundaries in binaries). Unlike `type: string` which only searches
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
        /// Require match to contain a valid external IP address (not private/loopback/reserved)
        #[serde(default)]
        external_ip: bool,
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
        /// Pre-compiled regex (populated after deserialization, not serialized)
        #[serde(skip)]
        compiled_regex: Option<regex::Regex>,
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
        /// Pre-compiled regex (populated after deserialization, not serialized)
        #[serde(skip)]
        compiled_regex: Option<regex::Regex>,
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
    },

    /// Query structured data in JSON, YAML, and TOML manifests using path expressions.
    /// Supports dot notation for nested access and [*] for array iteration.
    /// Example: { type: kv, path: "permissions", exact: "debugger" }
    /// Example: { type: kv, path: "scripts.postinstall", substr: "curl" }
    /// Example: { type: kv, path: "content_scripts[*].matches", exact: "<all_urls>" }
    /// Example: { type: kv, path: "maintainers", size_min: 1, size_max: 1 }
    Kv {
        /// Path to navigate using dot notation, [n] for indices, [*] for wildcards
        path: String,
        /// Value/element equals exactly
        #[serde(skip_serializing_if = "Option::is_none")]
        exact: Option<String>,
        /// Value/element contains substring
        #[serde(skip_serializing_if = "Option::is_none")]
        substr: Option<String>,
        /// Value/element matches regex pattern
        #[serde(skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
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
        /// Pre-compiled regex (populated after deserialization)
        #[serde(skip)]
        compiled_regex: Option<regex::Regex>,
    },
}

fn default_compare_to() -> String {
    "total".to_string()
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
        let is_binary = matches!(
            file_type,
            FileType::Elf
                | FileType::Macho
                | FileType::Pe
                | FileType::Dll
                | FileType::So
                | FileType::Dylib
        );

        match self {
            // Section analysis is binary-only
            Condition::SectionRatio { .. }
            | Condition::Section { .. }
            | Condition::Structure { .. } => is_binary,

            // AST requires source code
            Condition::Ast { .. } => file_type.is_source_code(),

            // All other conditions can potentially match any file type
            _ => true,
        }
    }

    /// Returns a description of the condition type for error messages
    #[must_use]
    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Condition::Symbol { .. } => "symbol",
            Condition::String { .. } => "string",
            Condition::Structure { .. } => "structure",
            Condition::ExportsCount { .. } => "exports_count",
            Condition::Trait { .. } => "trait",
            Condition::Ast { .. } => "ast",
            Condition::Yara { .. } => "yara",
            Condition::Syscall { .. } => "syscall",
            Condition::SectionRatio { .. } => "section_ratio",
            Condition::ImportCombination { .. } => "import_combination",
            Condition::StringCount { .. } => "string_count",
            Condition::Metrics { .. } => "metrics",
            Condition::Hex { .. } => "hex",
            Condition::Raw { .. } => "raw",
            Condition::Section { .. } => "section",
            Condition::Encoded { .. } => "encoded",
            Condition::Basename { .. } => "basename",
            Condition::Kv { .. } => "kv",
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
            Condition::Ast {
                kind,
                node,
                exact,
                regex,
                query,
                language,
                ..
            } => {
                // Validate mode: either (kind/node + exact/regex) or query, not both
                let has_simple_mode = kind.is_some() || node.is_some();
                let has_pattern = exact.is_some() || regex.is_some();
                let has_query = query.is_some();

                if has_query && has_simple_mode {
                    return Err(anyhow::anyhow!(
                        "ast condition cannot have both 'query' and 'kind'/'node'"
                    ));
                }

                if !has_query && !has_simple_mode {
                    return Err(anyhow::anyhow!(
                        "ast condition must have either 'kind'/'node' or 'query'"
                    ));
                }

                if has_simple_mode && !has_pattern {
                    return Err(anyhow::anyhow!(
                        "ast condition with 'kind'/'node' must have 'exact' or 'regex'"
                    ));
                }

                if kind.is_some() && node.is_some() {
                    return Err(anyhow::anyhow!(
                        "ast condition cannot have both 'kind' and 'node'"
                    ));
                }

                if exact.is_some() && regex.is_some() {
                    return Err(anyhow::anyhow!(
                        "ast condition cannot have both 'exact' and 'regex'"
                    ));
                }

                // Validate query if present — skip in fast mode (query compiles at eval time)
                if full {
                    if let Some(q) = query {
                        validate_ast_query(q, language.as_deref())?;
                    }
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
                    return Err(anyhow::anyhow!("kv condition requires non-empty path"));
                }

                // At most one matcher
                let matchers = [exact.is_some(), substr.is_some(), regex.is_some()];
                if matchers.iter().filter(|&&b| b).count() > 1 {
                    return Err(anyhow::anyhow!(
                        "kv condition can only have one of: exact, substr, regex"
                    ));
                }

                // Validate regex compiles
                if let Some(re) = regex {
                    regex::Regex::new(re)
                        .map_err(|e| anyhow::anyhow!("invalid regex in kv condition: {}", e))?;
                }

                Ok(())
            }
            // Validate location constraints for string/content conditions
            Condition::String {
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
                "string",
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
        {
            if compiled.is_none() {
                let mut compiler = yara_x::Compiler::new();
                compiler.new_namespace("inline");
                if compiler.add_source(source.as_bytes()).is_ok() {
                    *compiled = Some(Arc::new(compiler.build()));
                }
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
            Condition::String { regex: Some(r), .. }
            | Condition::Raw { regex: Some(r), .. }
            | Condition::Symbol { regex: Some(r), .. }
            | Condition::Ast { regex: Some(r), .. }
            | Condition::Basename { regex: Some(r), .. }
            | Condition::Kv { regex: Some(r), .. } => Some(r.as_str()),
            _ => None,
        };

        if let Some(regex) = regex_to_check {
            if let Some(issue) = find_backtrack_issue(regex) {
                return Some(format!(
                    "{} - use bounded pattern like .{{0,50}} instead: {}",
                    issue, regex
                ));
            }
        }
        None
    }

    /// Check for regex patterns that are just `\bWORD\b` which should use `type: word` instead.
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_word_boundary_regex(&self) -> Option<String> {
        let regex_to_check = match self {
            Condition::String { regex: Some(r), .. } | Condition::Raw { regex: Some(r), .. } => {
                Some(r.as_str())
            }
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
            Condition::String {
                exact: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Raw {
                exact: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Ast {
                exact: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::String {
                substr: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Raw {
                substr: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::Ast {
                substr: Some(s),
                case_insensitive: true,
                ..
            }
            | Condition::String {
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
            Condition::String { exact: Some(s), .. }
            | Condition::Raw { exact: Some(s), .. }
            | Condition::Symbol { exact: Some(s), .. } => check_empty(s, "exact"),
            Condition::String {
                substr: Some(s), ..
            }
            | Condition::Raw {
                substr: Some(s), ..
            }
            | Condition::Symbol {
                substr: Some(s), ..
            } => check_empty(s, "substr"),
            Condition::String { regex: Some(s), .. }
            | Condition::Raw { regex: Some(s), .. }
            | Condition::Symbol { regex: Some(s), .. } => check_empty(s, "regex"),
            Condition::String { word: Some(s), .. } | Condition::Raw { word: Some(s), .. } => {
                check_empty(s, "word")
            }
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
                    field, s, s.len()
                ));
            }
            None
        };

        match self {
            // For exact matches, warn if less than 2 characters
            Condition::String {
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
            Condition::String {
                substr: Some(s),
                case_insensitive: false,
                ..
            }
            | Condition::Symbol {
                substr: Some(s), ..
            } => check_short(s, "substr", 3),
            // For word, warn if less than 2 characters
            Condition::String {
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
            Condition::String { regex: Some(r), .. }
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
            Condition::String {
                exact: Some(s),
                case_insensitive: true,
                ..
            } => check_pattern(s, "exact"),
            Condition::String {
                substr: Some(s),
                case_insensitive: true,
                ..
            } => check_pattern(s, "substr"),
            Condition::String {
                word: Some(s),
                case_insensitive: true,
                ..
            } => check_pattern(s, "word"),
            _ => None,
        }
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
            Condition::String {
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
            | Condition::Ast {
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
                compiled_regex,
                ..
            } => {
                // Compile symbol regex if present
                *compiled_regex = Some(regex::Regex::new(regex_pattern).map_err(|e| {
                    anyhow::anyhow!("Failed to compile symbol regex '{}': {}", regex_pattern, e)
                })?);
            }
            Condition::String {
                regex,
                word,
                case_insensitive,
                compiled_regex,
                ..
            } => {
                // Compile main regex or word pattern
                if let Some(word_pattern) = word {
                    let regex_pattern = format!(r"\b{}\b", regex::escape(word_pattern));
                    *compiled_regex = Some(if *case_insensitive {
                        regex::Regex::new(&format!("(?i){}", regex_pattern)).map_err(|e| {
                            anyhow::anyhow!(
                                "Failed to compile case-insensitive word pattern '{}': {}",
                                word_pattern,
                                e
                            )
                        })?
                    } else {
                        regex::Regex::new(&regex_pattern).map_err(|e| {
                            anyhow::anyhow!(
                                "Failed to compile word pattern '{}': {}",
                                word_pattern,
                                e
                            )
                        })?
                    });
                } else if let Some(regex_pattern) = regex {
                    *compiled_regex = Some(if *case_insensitive {
                        regex::Regex::new(&format!("(?i){}", regex_pattern)).map_err(|e| {
                            anyhow::anyhow!(
                                "Failed to compile case-insensitive string regex '{}': {}",
                                regex_pattern,
                                e
                            )
                        })?
                    } else {
                        regex::Regex::new(regex_pattern).map_err(|e| {
                            anyhow::anyhow!(
                                "Failed to compile string regex '{}': {}",
                                regex_pattern,
                                e
                            )
                        })?
                    });
                }
            }
            Condition::Raw {
                regex,
                word,
                case_insensitive,
                compiled_regex,
                ..
            } => {
                // Compile main regex or word pattern for content searches
                if let Some(word_pattern) = word {
                    let regex_pattern = format!(r"\b{}\b", regex::escape(word_pattern));
                    *compiled_regex = Some(if *case_insensitive {
                        regex::Regex::new(&format!("(?i){}", regex_pattern)).map_err(|e| {
                            anyhow::anyhow!(
                                "Failed to compile case-insensitive content word pattern '{}': {}",
                                word_pattern,
                                e
                            )
                        })?
                    } else {
                        regex::Regex::new(&regex_pattern).map_err(|e| {
                            anyhow::anyhow!(
                                "Failed to compile content word pattern '{}': {}",
                                word_pattern,
                                e
                            )
                        })?
                    });
                } else if let Some(regex_pattern) = regex {
                    *compiled_regex = Some(if *case_insensitive {
                        regex::Regex::new(&format!("(?i){}", regex_pattern)).map_err(|e| {
                            anyhow::anyhow!(
                                "Failed to compile case-insensitive content regex '{}': {}",
                                regex_pattern,
                                e
                            )
                        })?
                    } else {
                        regex::Regex::new(regex_pattern).map_err(|e| {
                            anyhow::anyhow!(
                                "Failed to compile content regex '{}': {}",
                                regex_pattern,
                                e
                            )
                        })?
                    });
                }
            }
            Condition::Kv {
                regex: Some(regex_pattern),
                case_insensitive,
                compiled_regex,
                ..
            } => {
                // Compile regex pattern for kv searches
                *compiled_regex = Some(if *case_insensitive {
                    regex::Regex::new(&format!("(?i){}", regex_pattern)).map_err(|e| {
                        anyhow::anyhow!(
                            "Failed to compile case-insensitive kv regex '{}': {}",
                            regex_pattern,
                            e
                        )
                    })?
                } else {
                    regex::Regex::new(regex_pattern).map_err(|e| {
                        anyhow::anyhow!("Failed to compile kv regex '{}': {}", regex_pattern, e)
                    })?
                });
            }
            Condition::StringCount {
                regex: Some(regex_pattern),
                compiled_regex,
                ..
            } => {
                // Compile string_count regex if present
                *compiled_regex = Some(regex::Regex::new(regex_pattern).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to compile string_count regex '{}': {}",
                        regex_pattern,
                        e
                    )
                })?);
            }
            _ => {}
        }
        Ok(())
    }
}

/// Validate a tree-sitter query against the specified language
fn validate_ast_query(query: &str, language: Option<&str>) -> Result<()> {
    let lang: tree_sitter::Language = match language {
        Some("c") => tree_sitter_c::LANGUAGE.into(),
        Some("python") => tree_sitter_python::LANGUAGE.into(),
        Some("javascript") | Some("js") => tree_sitter_javascript::LANGUAGE.into(),
        Some("typescript") | Some("ts") => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Some("rust") => tree_sitter_rust::LANGUAGE.into(),
        Some("go") => tree_sitter_go::LANGUAGE.into(),
        Some("java") => tree_sitter_java::LANGUAGE.into(),
        Some("ruby") => tree_sitter_ruby::LANGUAGE.into(),
        Some("shell") | Some("bash") => tree_sitter_bash::LANGUAGE.into(),
        Some("php") => tree_sitter_php::LANGUAGE_PHP.into(),
        Some("csharp") | Some("c#") => tree_sitter_c_sharp::LANGUAGE.into(),
        Some("lua") => tree_sitter_lua::LANGUAGE.into(),
        Some("perl") => tree_sitter_perl::LANGUAGE.into(),
        Some("powershell") | Some("ps1") => tree_sitter_powershell::LANGUAGE.into(),
        Some("swift") => tree_sitter_swift::LANGUAGE.into(),
        Some("objc") | Some("objective-c") => tree_sitter_objc::LANGUAGE.into(),
        Some("groovy") => tree_sitter_groovy::LANGUAGE.into(),
        Some("scala") => tree_sitter_scala::LANGUAGE.into(),
        Some("zig") => tree_sitter_zig::LANGUAGE.into(),
        Some("elixir") => tree_sitter_elixir::LANGUAGE.into(),
        Some(other) => {
            return Err(anyhow::anyhow!(
                "unsupported language for ast query: {}",
                other
            ))
        }
        None => {
            // No language specified - skip validation, will validate at runtime
            return Ok(());
        }
    };
    tree_sitter::Query::new(&lang, query)
        .map_err(|e| anyhow::anyhow!("invalid tree-sitter query: {}", e))?;
    Ok(())
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
                            return Some("open-ended range quantifier (.{n,}) — use a bounded range like .{0,50} instead");
                        }
                    }
                }
                i += 1;
            }
            '*' | '+' => {
                // A bare quantifier on a plain character or escape sequence.
                let lazy = i + 1 < len && chars[i + 1] == '?';
                if !lazy {
                    if let Some(top) = group_stack.last_mut() {
                        *top = true;
                    }
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
    if let Some((start, Some(e))) = offset_range {
        if start >= 0 && e >= 0 && start > e {
            return Err(anyhow::anyhow!(
                "{} condition 'offset_range' start ({}) must be <= end ({})",
                condition_type,
                start,
                e
            ));
        }
    }

    // Validate section_offset_range format
    if let Some((start, Some(e))) = section_offset_range {
        if start >= 0 && e >= 0 && start > e {
            return Err(anyhow::anyhow!(
                "{} condition 'section_offset_range' start ({}) must be <= end ({})",
                condition_type,
                start,
                e
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod location_constraint_tests {
    use super::*;

    #[test]
    fn test_validate_location_no_constraints() {
        let result = validate_location_constraints(&None, None, None, None, None, "string");
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
            "string",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_offset_only() {
        let result = validate_location_constraints(&None, Some(0x1000), None, None, None, "string");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_location_offset_range_only() {
        let result = validate_location_constraints(
            &None,
            None,
            Some((0, Some(0x1000))),
            None,
            None,
            "string",
        );
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
            "string",
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("offset"));
    }

    #[test]
    fn test_validate_location_section_offset_without_section_fails() {
        let result = validate_location_constraints(&None, None, None, Some(0x100), None, "content");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("requires 'section'"));
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
            "string",
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
            "string",
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
            validate_location_constraints(&None, None, Some((0x1000, None)), None, None, "string");
        assert!(result.is_ok());
    }

    #[test]
    fn test_condition_validate_string_location() {
        // Test that Condition::String validates location constraints
        let condition = Condition::String {
            exact: Some("test".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            external_ip: false,
            section: None,
            offset: Some(0x100),
            offset_range: Some((0, Some(0x1000))), // Mutually exclusive with offset
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
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
            external_ip: false,
            section: Some(".text".to_string()),
            offset: None,
            offset_range: Some((0, Some(0x1000))),
            section_offset: None,
            section_offset_range: None,
            compiled_regex: None,
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
mod backtrack_tests {
    use super::find_backtrack_issue;

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
}
