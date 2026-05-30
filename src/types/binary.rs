//! Binary analysis types - functions, strings, sections, imports/exports
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::is_false;
use super::ml_features::{
    CallPatternMetrics, ControlFlowMetrics, EmbeddedConstant, FunctionSignature, NestingMetrics,
    RegisterUsage,
};

/// The body of an extracted string — either a borrowed range into the file's
/// raw bytes (used during analysis to avoid duplicating `file_data`), or an
/// owned `String` (used for decoded/reassembled strings and for any survivor
/// materialized at the end of analysis).
///
/// **Invariant:** by the time analysis returns, every `Slice` variant has been
/// converted to `Owned` (via `materialize`). Post-analysis consumers
/// (serialization, ML, diff, cache) only ever see `Owned`. Calling Deref /
/// AsRef / Hash / PartialEq / Display / Serialize on a `Slice` variant panics —
/// that's an invariant violation, not an expected runtime path.
#[derive(Debug, Clone)]
pub enum StringValue {
    /// A `[start, start+len)` byte range into `file_data`. Resolved on demand
    /// via `as_str(Some(file_data))` while `file_data` is live.
    Slice {
        /// Start byte offset into `file_data`.
        start: u32,
        /// Length in bytes (the string is the raw byte slice; we require
        /// callers to only produce Slice when the slice is valid UTF-8).
        len: u32,
    },
    /// An owned UTF-8 string — decoded/reassembled, or materialized at finalize.
    Owned(String),
}

impl StringValue {
    /// Length in bytes — works for both variants without `file_data`.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            StringValue::Slice { len, .. } => *len as usize,
            StringValue::Owned(s) => s.len(),
        }
    }

    /// True when the value has zero bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the `Owned` `&str`. Panics for `Slice` variants — post-finalize
    /// every value is `Owned`, so this is safe outside the analysis frame.
    /// Inside the analysis frame use [`StringValue::resolve`] with the file's
    /// bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            StringValue::Owned(s) => s.as_str(),
            StringValue::Slice { .. } => panic!(
                "StringValue::Slice::as_str() called without file_data — use .resolve(Some(file_data))"
            ),
        }
    }

    /// Resolve to `&str` using `file_data` for `Slice` variants. Pass `None`
    /// outside the analysis frame (all variants are `Owned` post-finalize).
    /// Panics for `Slice` if `file_data` is missing — that means a consumer
    /// saw a Slice that should have been materialized.
    #[must_use]
    pub fn resolve<'a>(&'a self, file_data: Option<&'a [u8]>) -> &'a str {
        match self {
            StringValue::Slice { start, len } => {
                let data = file_data.expect(
                    "StringValue::Slice accessed without file_data — analysis frame must call materialize before file_data drops",
                );
                let s = *start as usize;
                let e = s + *len as usize;
                // SAFETY: producers (convert_stng_strings_owned) only create
                // Slice when the byte range is valid UTF-8; fall back to "" if
                // that invariant is violated rather than panicking on every
                // matcher iteration.
                std::str::from_utf8(&data[s..e]).unwrap_or("")
            }
            StringValue::Owned(s) => s.as_str(),
        }
    }

    /// Materialize a `Slice` to `Owned` using `file_data`. No-op for `Owned`.
    pub fn materialize(&mut self, file_data: &[u8]) {
        if let StringValue::Slice { start, len } = *self {
            let s = start as usize;
            let e = s + len as usize;
            let bytes = &file_data[s..e];
            let owned = std::str::from_utf8(bytes)
                .map(str::to_owned)
                .unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned());
            *self = StringValue::Owned(owned);
        }
    }
}

// Deref to `str` so the bulk of existing `.value.foo()` call sites keep
// working without an explicit accessor. PANICS for `Slice` — analysis-phase
// consumers that see Slice variants must use `.value.as_str(Some(file_data))`
// instead. Post-analysis, all variants are Owned (invariant), so Deref is safe.
impl std::ops::Deref for StringValue {
    type Target = str;
    fn deref(&self) -> &str {
        match self {
            StringValue::Owned(s) => s.as_str(),
            StringValue::Slice { .. } => panic!(
                "StringValue::Slice cannot Deref without file_data — use .as_str(Some(file_data))"
            ),
        }
    }
}

impl AsRef<str> for StringValue {
    fn as_ref(&self) -> &str {
        self
    }
}

impl std::borrow::Borrow<str> for StringValue {
    fn borrow(&self) -> &str {
        self
    }
}

impl std::fmt::Display for StringValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self)
    }
}

impl PartialEq for StringValue {
    fn eq(&self, other: &Self) -> bool {
        // Owned/Owned is the common case post-materialize; any path comparing
        // Slice variants must Deref first (which panics without file_data — but
        // matchers that compare values do so through accessors, not ==).
        let lhs: &str = self;
        let rhs: &str = other;
        lhs == rhs
    }
}

impl PartialEq<str> for StringValue {
    fn eq(&self, other: &str) -> bool {
        let lhs: &str = self;
        lhs == other
    }
}

impl PartialEq<&str> for StringValue {
    fn eq(&self, other: &&str) -> bool {
        let lhs: &str = self;
        lhs == *other
    }
}

impl PartialEq<String> for StringValue {
    fn eq(&self, other: &String) -> bool {
        let lhs: &str = self;
        lhs == other.as_str()
    }
}

impl Eq for StringValue {}

impl std::hash::Hash for StringValue {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let s: &str = self;
        s.hash(state);
    }
}

impl Default for StringValue {
    fn default() -> Self {
        StringValue::Owned(String::new())
    }
}

impl From<String> for StringValue {
    fn from(s: String) -> Self {
        StringValue::Owned(s)
    }
}

impl From<&str> for StringValue {
    fn from(s: &str) -> Self {
        StringValue::Owned(s.to_string())
    }
}

impl Serialize for StringValue {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        match self {
            StringValue::Owned(s) => serialize_truncated_string(s.as_str(), ser),
            StringValue::Slice { .. } => Err(serde::ser::Error::custom(
                "StringValue::Slice cannot serialize — materialize first",
            )),
        }
    }
}

impl<'de> Deserialize<'de> for StringValue {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        Ok(StringValue::Owned(String::deserialize(de)?))
    }
}

/// A function discovered via static analysis (binary disassembly or source parsing)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Function {
    /// Function name or symbol
    pub name: String,
    /// File offset where the function starts (hex string like "0x1234")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<String>,
    /// Function size in bytes
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size: Option<u64>,
    /// Cyclomatic complexity score
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub complexity: Option<u32>,
    /// Functions called by this function
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub calls: Vec<String>,
    /// Tool that discovered this function (radare2, tree-sitter, etc.)
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub source: String,
    /// Control flow graph metrics
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub control_flow: Option<ControlFlowMetrics>,
    /// Register usage patterns
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub register_usage: Option<RegisterUsage>,
    /// Embedded numeric constants
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub constants: Vec<EmbeddedConstant>,
    /// Function signature (source code languages)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub signature: Option<FunctionSignature>,
    /// Nesting depth metrics
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub nesting: Option<NestingMetrics>,
    /// Call pattern analysis
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub call_patterns: Option<CallPatternMetrics>,
}

/// Returns true for common encodings (utf8, ascii) that don't need to be serialized.
/// Only exotic encodings (utf16le, utf16be, etc.) are included in output.
fn is_common_encoding(encoding: &String) -> bool {
    encoding == "utf8" || encoding == "utf-8" || encoding == "ascii" || encoding.is_empty()
}

/// Maximum size for string values (4KB)
const MAX_STRING_VALUE_SIZE: usize = 4096;

/// Serialize string value, truncating to MAX_STRING_VALUE_SIZE.
/// Strips null bytes (\0) which are common in strings extracted from malware
/// binaries but cannot be stored in PostgreSQL JSONB.
fn serialize_truncated_string<S>(value: &str, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let clean = sanitize_for_json(value);
    let v = clean.as_ref().map_or(value, |s| s.as_str());
    if v.len() <= MAX_STRING_VALUE_SIZE {
        serializer.serialize_str(v)
    } else {
        // Truncate at a valid UTF-8 boundary
        let truncated = truncate_str_at_boundary(v, MAX_STRING_VALUE_SIZE - 12);
        let with_marker = format!("{}...[truncated]", truncated);
        serializer.serialize_str(&with_marker)
    }
}

/// Remove null bytes from a string. Returns None if the string is already clean
/// (avoids allocation in the common case).
fn sanitize_for_json(s: &str) -> Option<String> {
    if s.contains('\0') {
        Some(s.replace('\0', ""))
    } else {
        None
    }
}

/// Truncate a string at a valid UTF-8 char boundary
fn truncate_str_at_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Serialize offset as hex string for JSON output (e.g., "0x1234")
fn serialize_hex_offset<S>(offset: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match offset {
        Some(o) => serializer.serialize_str(&format!("{:#x}", o)),
        None => serializer.serialize_none(),
    }
}

/// Deserialize offset from either hex string or integer
fn deserialize_hex_offset<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};

    struct HexOrIntVisitor;

    impl<'de> Visitor<'de> for HexOrIntVisitor {
        type Value = Option<u64>;

        fn expecting<'a>(&self, formatter: &mut std::fmt::Formatter<'a>) -> std::fmt::Result {
            formatter.write_str("a hex string like '0x1234' or an integer")
        }

        fn visit_none<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_u64<E>(self, v: u64) -> Result<Self::Value, E> {
            Ok(Some(v))
        }

        fn visit_i64<E>(self, v: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v >= 0 {
                Ok(Some(v as u64))
            } else {
                Err(de::Error::custom("offset cannot be negative"))
            }
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            let s = v.trim().trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(s, 16)
                .map(Some)
                .map_err(|e| de::Error::custom(format!("invalid hex offset {v}: {e}")))
        }
    }

    deserializer.deserialize_any(HexOrIntVisitor)
}

/// Decoded string (base64, xor-decoded, etc.)
/// Deprecated: Use StringInfo with encoding_chain instead.
#[allow(dead_code)] // Constructed in tests only
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedString {
    /// The decoded plaintext value
    #[serde(serialize_with = "serialize_truncated_string")]
    pub value: String,
    /// Original encoded value (truncated to 4KB)
    #[serde(serialize_with = "serialize_truncated_string")]
    pub encoded: String,
    /// Encoding method (base64, xor, etc.)
    pub method: String,
    /// Optional: XOR key used (for xor method)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key: Option<String>,
    /// Offset in file where encoded string was found
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<String>,
}

/// A string literal extracted from a binary or source file
#[derive(Debug, Serialize, Deserialize)]
pub struct StringInfo {
    /// The string value (truncated to 4KB on serialization). During analysis
    /// this may be a borrowed range into `file_data`; by the time analysis
    /// returns, every value is materialized to `Owned`.
    pub value: StringValue,
    /// File offset where string was found (serialized as hex, e.g., "0x1234")
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        serialize_with = "serialize_hex_offset",
        deserialize_with = "deserialize_hex_offset"
    )]
    pub offset: Option<u64>,
    /// Character encoding — only serialized for exotic encodings (utf16le, utf16be)
    #[serde(skip_serializing_if = "is_common_encoding", default)]
    pub encoding: String,
    /// String classification — None means unclassified (formerly Const)
    #[serde(rename = "type", skip_serializing_if = "Option::is_none", default)]
    pub string_type: Option<StringType>,
    /// Binary section where found — derivable from offset + sections array, omitted from output
    #[serde(skip_serializing, default)]
    pub section: Option<String>,
    /// Encoding layers applied to this string (e.g., ["base64", "zlib"])
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub encoding_chain: Vec<String>,
    /// Fragments if this is a stack-constructed string
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub fragments: Option<Vec<String>>,
    /// Set by matchers when this string contributed to *any* trait Evidence.
    /// Read at end-of-analyze to drop unmatched strings (survivor-only
    /// materialization). Interior-mutable via `&StringInfo` so matchers can
    /// flag without `&mut` access; `Relaxed` ordering is sufficient because
    /// we only care about "any thread ever set it true," not ordering with
    /// other operations. Skipped from serialization.
    #[serde(skip, default)]
    pub matched: std::sync::atomic::AtomicBool,
}

impl Clone for StringInfo {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            offset: self.offset,
            encoding: self.encoding.clone(),
            string_type: self.string_type,
            section: self.section.clone(),
            encoding_chain: self.encoding_chain.clone(),
            fragments: self.fragments.clone(),
            matched: std::sync::atomic::AtomicBool::new(
                self.matched.load(std::sync::atomic::Ordering::Relaxed),
            ),
        }
    }
}

// Re-export stng's StringKind as StringType for compatibility
// cleave-specific source code types (Literal, Comment, Docstring) map to stng::StringKind::Const
// StackString is detected via StringMethod, not as a separate kind
pub use stng::StringKind as StringType;

/// A binary section (ELF, Mach-O, or PE segment)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    /// Section name (e.g., ".text", ".data", "__TEXT")
    pub name: String,
    /// Virtual memory address of the section
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub address: Option<u64>,
    /// File offset where the section data starts
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<u64>,
    /// Section size in bytes
    pub size: u64,
    /// Shannon entropy of section contents (0.0 to 8.0)
    pub entropy: f64,
    /// Permission flags as a `rwx`-style string (e.g., "r-x", "rw-")
    /// or a comma-joined flag list (e.g., "alloc,executable") when
    /// the source format uses a discrete flag vocabulary. Kept for
    /// backward compat; prefer `flags` membership checks for trait
    /// rules.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub permissions: Option<String>,
    /// Format-native flag tokens (e.g., `["alloc", "executable",
    /// "merge"]` on ELF; `["readable", "writable"]` on PE). Lets
    /// `type: value` rules match by membership without parsing the
    /// `permissions` string. Empty for sections without recognised
    /// flags.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub flags: Vec<String>,
}

/// Normalize a symbol name by stripping leading underscores.
/// This is done at load time for consistent matching.
/// Examples: "_malloc" -> "malloc", "__libc_start_main" -> "libc_start_main"
#[inline]
#[must_use]
pub(crate) fn normalize_symbol(symbol: &str) -> String {
    symbol
        .trim_start_matches('_')
        .trim_start_matches('_')
        .to_string()
}

/// An imported symbol (function or variable from an external library)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Import {
    /// Normalized symbol name (leading underscores stripped)
    pub symbol: String,
    /// Library providing this symbol (e.g., "libc.so.6", "kernel32.dll")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub library: Option<String>,
    /// Tool that discovered this import (goblin, radare2, etc.)
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub source: String,
    /// File offset of the call site for scripting-language imports (hex
    /// string like `"0x1234"`). `None` for compiled-binary imports, which
    /// have no single meaningful offset. Populated by AST extraction so
    /// composite rules can apply `near_bytes`/`near_lines` proximity.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<String>,
}

impl Import {
    /// Create a new Import with normalized symbol name
    pub fn new(
        symbol: impl Into<String>,
        library: Option<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            symbol: normalize_symbol(&symbol.into()),
            library,
            source: source.into(),
            offset: None,
        }
    }

    /// Create a new Import with a call-site byte offset attached.
    #[must_use]
    pub fn with_offset(
        symbol: impl Into<String>,
        library: Option<String>,
        source: impl Into<String>,
        byte_offset: u64,
    ) -> Self {
        Self {
            symbol: normalize_symbol(&symbol.into()),
            library,
            source: source.into(),
            offset: Some(format!("0x{byte_offset:x}")),
        }
    }
}

/// An exported symbol (function or variable exposed by this binary)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Export {
    /// Normalized symbol name (leading underscores stripped)
    pub symbol: String,
    /// File offset of the exported symbol (hex string like "0x1234")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub offset: Option<String>,
    /// Tool that discovered this export (goblin, radare2, etc.)
    #[serde(skip_serializing_if = "String::is_empty", default)]
    pub source: String,
    /// Forwarded target for re-exports (`"KERNEL32.LoadLibraryA"` or
    /// `"NTDLL.#123"`). None for normal exports whose RVA points into the
    /// DLL's own code/data.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub forward_to: Option<String>,
}

impl Export {
    /// Create a new Export with normalized symbol name
    pub fn new(
        symbol: impl Into<String>,
        offset: Option<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            symbol: normalize_symbol(&symbol.into()),
            offset,
            source: source.into(),
            forward_to: None,
        }
    }

    /// Create a forwarded Export (`export → lib.target`).
    pub fn forwarded(
        symbol: impl Into<String>,
        forward_to: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            symbol: normalize_symbol(&symbol.into()),
            offset: None,
            source: source.into(),
            forward_to: Some(forward_to.into()),
        }
    }
}

/// A YARA rule match found in the analyzed file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraMatch {
    /// Name of the matched YARA rule
    pub rule: String,
    /// YARA namespace (typically the rule file name)
    pub namespace: String,
    /// Criticality level from rule metadata
    pub crit: String,
    /// Human-readable description from rule metadata
    pub desc: String,
    /// Specific string patterns that triggered the match
    #[serde(default)]
    pub matched_strings: Vec<MatchedString>,
    /// Whether this match should be upgraded to a capability
    #[serde(default, skip_serializing_if = "is_false")]
    pub is_capability: bool,
    /// Optional MBC code from metadata
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,
    /// Optional ATT&CK technique from metadata
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,
    /// Derived third-party trait ID (e.g., "third_party/elastic/linux/backdoor/bash")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub trait_id: Option<String>,
    /// Raw `arch_context` metadata value from the YARA rule (not serialized).
    /// Used to filter rules at analysis time based on the file's architecture.
    #[serde(skip, default)]
    #[allow(dead_code)] // Read by lib.rs pipeline (process_yara_result)
    pub arch_context: Option<String>,
}

/// A specific string pattern that contributed to a YARA rule match
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchedString {
    /// YARA string identifier (e.g., "$s1", "$hex_pattern")
    pub identifier: String,
    /// File offset where the pattern matched
    pub offset: u64,
    /// Matched bytes as a string (truncated to 4KB on serialization)
    #[serde(serialize_with = "serialize_truncated_string")]
    pub value: String,
}

/// Syscall information extracted from binary
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyscallInfo {
    /// Address where syscall instruction occurs
    pub address: u64,
    /// Syscall number (architecture-dependent)
    pub number: u32,
    /// Resolved syscall name (e.g., "read", "write", "socket")
    pub name: String,
    /// Brief description of what this syscall does
    pub desc: String,
    /// Architecture (e.g., "x86", "x86_64", "mips", "arm")
    pub arch: String,
}

/// Metadata about the analysis run itself
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalysisMetadata {
    /// Total analysis time in milliseconds
    pub analysis_duration_ms: u64,
    /// Names of tools used during analysis
    pub tools_used: Vec<String>,
    /// Non-fatal errors encountered during analysis
    pub errors: Vec<String>,
}

impl AnalysisMetadata {
    /// Returns true when metadata has been cleared (after finalize merged it into summary).
    /// Used by skip_serializing_if to omit the field from output.
    #[must_use]
    pub fn is_cleared(&self) -> bool {
        self.tools_used.is_empty() && self.analysis_duration_ms == 0 && self.errors.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ==================== normalize_symbol Tests ====================

    #[test]
    fn test_normalize_symbol_single_underscore() {
        assert_eq!(normalize_symbol("_malloc"), "malloc");
    }

    #[test]
    fn test_normalize_symbol_double_underscore() {
        assert_eq!(normalize_symbol("__libc_start_main"), "libc_start_main");
    }

    #[test]
    fn test_normalize_symbol_no_underscore() {
        assert_eq!(normalize_symbol("printf"), "printf");
    }

    #[test]
    fn test_normalize_symbol_many_underscores() {
        // trim_start_matches strips ALL leading underscores
        assert_eq!(normalize_symbol("___private"), "private");
    }

    #[test]
    fn test_normalize_symbol_empty() {
        assert_eq!(normalize_symbol(""), "");
    }

    #[test]
    fn test_normalize_symbol_only_underscores() {
        assert_eq!(normalize_symbol("__"), "");
    }

    #[test]
    fn test_normalize_symbol_middle_underscores_preserved() {
        assert_eq!(normalize_symbol("_my_function_name"), "my_function_name");
    }

    #[test]
    fn test_normalize_symbol_trailing_underscore() {
        assert_eq!(normalize_symbol("_foo_"), "foo_");
    }

    // ==================== Import::new Tests ====================

    #[test]
    fn test_import_new_basic() {
        let imp = Import::new("malloc", None, "symbols");
        assert_eq!(imp.symbol, "malloc");
        assert_eq!(imp.library, None);
        assert_eq!(imp.source, "symbols");
    }

    #[test]
    fn test_import_new_with_library() {
        let imp = Import::new("printf", Some("libc.so.6".to_string()), "imports");
        assert_eq!(imp.symbol, "printf");
        assert_eq!(imp.library, Some("libc.so.6".to_string()));
    }

    #[test]
    fn test_import_new_normalizes_symbol() {
        let imp = Import::new("_malloc", None, "symbols");
        assert_eq!(imp.symbol, "malloc");
    }

    #[test]
    fn test_import_new_normalizes_double_underscore() {
        let imp = Import::new("__errno_location", Some("libc.so.6".to_string()), "dynsym");
        assert_eq!(imp.symbol, "errno_location");
    }

    #[test]
    fn test_import_new_string_into() {
        let imp = Import::new(String::from("_read"), None, String::from("dynsym"));
        assert_eq!(imp.symbol, "read");
        assert_eq!(imp.source, "dynsym");
    }

    // ==================== Export::new Tests ====================

    #[test]
    fn test_export_new_basic() {
        let exp = Export::new("my_function", None, "exports");
        assert_eq!(exp.symbol, "my_function");
        assert_eq!(exp.offset, None);
        assert_eq!(exp.source, "exports");
    }

    #[test]
    fn test_export_new_with_offset() {
        let exp = Export::new("init", Some("0x1000".to_string()), "symbols");
        assert_eq!(exp.symbol, "init");
        assert_eq!(exp.offset, Some("0x1000".to_string()));
    }

    #[test]
    fn test_export_new_normalizes_symbol() {
        let exp = Export::new("_start", Some("0x400".to_string()), "entry");
        assert_eq!(exp.symbol, "start");
    }

    #[test]
    fn test_export_new_normalizes_double_underscore() {
        let exp = Export::new("__init_array_start", None, "symbols");
        assert_eq!(exp.symbol, "init_array_start");
    }

    // ==================== truncate_str_at_boundary Tests ====================

    #[test]
    fn test_truncate_str_at_boundary_short_string() {
        let s = "hello";
        assert_eq!(truncate_str_at_boundary(s, 10), "hello");
    }

    #[test]
    fn test_truncate_str_at_boundary_exact_length() {
        let s = "hello";
        assert_eq!(truncate_str_at_boundary(s, 5), "hello");
    }

    #[test]
    fn test_truncate_str_at_boundary_truncates() {
        let s = "hello world";
        assert_eq!(truncate_str_at_boundary(s, 5), "hello");
    }

    #[test]
    fn test_truncate_str_at_boundary_utf8_multibyte() {
        // 'é' is 2 bytes in UTF-8
        let s = "café";
        // Truncating at byte 4 would split 'é', so it backs off
        assert_eq!(truncate_str_at_boundary(s, 4), "caf");
    }

    #[test]
    fn test_truncate_str_at_boundary_utf8_emoji() {
        // '🦀' is 4 bytes in UTF-8
        let s = "hi🦀";
        // "hi" is 2 bytes, emoji is 4, total 6
        // Truncating at 3 would split emoji, backs off to 2
        assert_eq!(truncate_str_at_boundary(s, 3), "hi");
    }

    #[test]
    fn test_truncate_str_at_boundary_empty() {
        assert_eq!(truncate_str_at_boundary("", 10), "");
    }

    #[test]
    fn test_truncate_str_at_boundary_zero_max() {
        assert_eq!(truncate_str_at_boundary("hello", 0), "");
    }

    #[test]
    fn test_truncate_str_at_boundary_chinese() {
        // Each Chinese character is 3 bytes
        let s = "你好世界";
        // Truncate at 6 bytes = exactly 2 characters
        assert_eq!(truncate_str_at_boundary(s, 6), "你好");
    }

    // ==================== StringType Tests ====================

    #[test]
    fn test_string_type_equality() {
        assert_eq!(StringType::Url, StringType::Url);
        assert_ne!(StringType::Url, StringType::IP);
    }

    #[test]
    fn test_string_type_copy() {
        let st = StringType::Url;
        let st2 = st; // Copy
        assert_eq!(st, st2);
    }

    #[test]
    fn test_string_type_all_variants_distinct() {
        // Since StringType is now stng::StringKind, test the common malware-relevant variants
        // Note: Plain, Literal, Comment, Docstring all map to Const
        // StackString is detected via StringMethod, not as a separate kind
        let variants = vec![
            StringType::Url,
            StringType::IP,
            StringType::Path,
            StringType::Email,
            StringType::Base64,
            StringType::Import,
            StringType::Export,
            StringType::FuncName,
            StringType::ShellCmd,
        ];
        for (i, v1) in variants.iter().enumerate() {
            for (j, v2) in variants.iter().enumerate() {
                if i == j {
                    assert_eq!(v1, v2, "Variant at index {} should equal itself", i);
                } else {
                    assert_ne!(
                        v1, v2,
                        "Variants at index {} and {} should be distinct",
                        i, j
                    );
                }
            }
        }
    }

    // ==================== AnalysisMetadata Tests ====================

    #[test]
    fn test_analysis_metadata_default() {
        let meta = AnalysisMetadata::default();
        assert_eq!(meta.analysis_duration_ms, 0);
        assert!(meta.tools_used.is_empty());
        assert!(meta.errors.is_empty());
    }

    #[test]
    fn test_analysis_metadata_creation() {
        let meta = AnalysisMetadata {
            analysis_duration_ms: 1500,
            tools_used: vec!["objdump".to_string(), "strings".to_string()],
            errors: vec![],
        };
        assert_eq!(meta.analysis_duration_ms, 1500);
        assert_eq!(meta.tools_used.len(), 2);
    }

    // ==================== StringInfo Tests ====================

    #[test]
    fn test_string_info_creation() {
        let info = StringInfo {
            value: ("http://example.com".to_string()).into(),
            offset: Some(0x1000),
            encoding: "utf-8".to_string(),
            string_type: Some(StringType::Url),
            section: Some(".rodata".to_string()),
            encoding_chain: vec![],
            fragments: None,
            matched: std::sync::atomic::AtomicBool::new(false),
        };
        assert_eq!(info.value, "http://example.com");
        assert_eq!(info.offset, Some(0x1000));
        assert_eq!(info.string_type, Some(StringType::Url));
    }

    #[test]
    fn test_string_info_with_encoding_chain() {
        let info = StringInfo {
            value: ("decoded text".to_string()).into(),
            offset: None,
            encoding: "utf-8".to_string(),
            string_type: None,
            section: None,
            encoding_chain: vec!["base64".to_string(), "zlib".to_string()],
            fragments: None,
            matched: std::sync::atomic::AtomicBool::new(false),
        };
        assert_eq!(info.encoding_chain.len(), 2);
        assert_eq!(info.encoding_chain[0], "base64");
    }

    #[test]
    fn test_string_info_with_fragments() {
        let info = StringInfo {
            value: ("stacked".to_string()).into(),
            offset: Some(0x2000),
            encoding: "ascii".to_string(),
            string_type: Some(StringType::StackString),
            section: Some(".text".to_string()),
            encoding_chain: vec![],
            fragments: Some(vec!["s".to_string(), "t".to_string(), "a".to_string()]),
            matched: std::sync::atomic::AtomicBool::new(false),
        };
        assert_eq!(info.string_type, Some(StringType::StackString));
        assert!(info.fragments.is_some());
        assert_eq!(info.fragments.unwrap().len(), 3);
    }

    // ==================== Section Tests ====================

    #[test]
    fn test_section_creation() {
        let section = Section {
            name: ".text".to_string(),
            address: None,
            offset: None,
            size: 4096,
            entropy: 6.5,
            permissions: Some("r-x".to_string()),
            flags: Vec::new(),
        };
        assert_eq!(section.name, ".text");
        assert_eq!(section.size, 4096);
        assert!((section.entropy - 6.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_section_without_permissions() {
        let section = Section {
            name: ".data".to_string(),
            address: None,
            offset: None,
            size: 1024,
            entropy: 3.2,
            permissions: None,
            flags: Vec::new(),
        };
        assert!(section.permissions.is_none());
    }

    // ==================== Function Tests ====================

    #[test]
    fn test_function_creation_minimal() {
        let func = Function {
            name: "main".to_string(),
            offset: None,
            size: None,
            complexity: None,
            calls: vec![],
            source: "symbols".to_string(),
            control_flow: None,
            register_usage: None,
            constants: vec![],
            signature: None,
            nesting: None,
            call_patterns: None,
        };
        assert_eq!(func.name, "main");
        assert_eq!(func.source, "symbols");
    }

    #[test]
    fn test_function_with_calls() {
        let func = Function {
            name: "process".to_string(),
            offset: Some("0x1000".to_string()),
            size: Some(256),
            complexity: Some(10),
            calls: vec!["malloc".to_string(), "free".to_string()],
            source: "analysis".to_string(),
            control_flow: None,
            register_usage: None,
            constants: vec![],
            signature: None,
            nesting: None,
            call_patterns: None,
        };
        assert_eq!(func.calls.len(), 2);
        assert_eq!(func.complexity, Some(10));
    }

    // ==================== YaraMatch Tests ====================

    #[test]
    fn test_yara_match_creation() {
        let yara = YaraMatch {
            rule: "malware_generic".to_string(),
            namespace: "malware".to_string(),
            crit: "hostile".to_string(),
            desc: "Generic malware signature".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
            trait_id: None,
            arch_context: None,
        };
        assert_eq!(yara.rule, "malware_generic");
        assert!(!yara.is_capability);
    }

    #[test]
    fn test_yara_match_with_capability() {
        let yara = YaraMatch {
            rule: "network_communication".to_string(),
            namespace: "capabilities".to_string(),
            crit: "suspicious".to_string(),
            desc: "Network communication capability".to_string(),
            matched_strings: vec![],
            is_capability: true,
            mbc: Some("C0021".to_string()),
            attack: Some("T1071".to_string()),
            trait_id: None,
            arch_context: None,
        };
        assert!(yara.is_capability);
        assert_eq!(yara.mbc, Some("C0021".to_string()));
        assert_eq!(yara.attack, Some("T1071".to_string()));
    }

    // ==================== MatchedString Tests ====================

    #[test]
    fn test_matched_string_creation() {
        let ms = MatchedString {
            identifier: "$a".to_string(),
            offset: 0x1234,
            value: "suspicious string".to_string(),
        };
        assert_eq!(ms.identifier, "$a");
        assert_eq!(ms.offset, 0x1234);
    }

    // ==================== DecodedString Tests ====================

    #[test]
    fn test_decoded_string_creation() {
        let ds = DecodedString {
            value: "hello world".to_string(),
            encoded: "aGVsbG8gd29ybGQ=".to_string(),
            method: "base64".to_string(),
            key: None,
            offset: Some("0x1000".to_string()),
        };
        assert_eq!(ds.value, "hello world");
        assert_eq!(ds.method, "base64");
        assert!(ds.key.is_none());
    }

    #[test]
    fn test_decoded_string_with_xor_key() {
        let ds = DecodedString {
            value: "decrypted".to_string(),
            encoded: "encrypted bytes".to_string(),
            method: "xor".to_string(),
            key: Some("0x55".to_string()),
            offset: None,
        };
        assert_eq!(ds.method, "xor");
        assert_eq!(ds.key, Some("0x55".to_string()));
    }
}
