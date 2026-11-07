//! Condition types for composite rules.
use super::types::Platform;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

mod validate;
#[allow(clippy::wildcard_imports)]
use validate::*;

mod regexes;
#[allow(clippy::wildcard_imports)]
pub(crate) use regexes::*;

/// Process-global, deduplicated, lazily-compiled regex cache.
///
/// Replaces eager per-condition precompilation. A pattern is compiled on first
/// evaluation and shared as an `Arc` across every condition that uses it, so
/// only patterns that actually fire cost anything and identical patterns cost
/// once. The cache is a **bounded LRU**: cold patterns evict instead of living
/// for the whole process. The previous design `Box::leak`'d every distinct
/// engine (~95 KB apiece, ~19k of them on member-heavy archives) — an immortal
/// leak that was the dominant steady-state RSS. Cloning the `Arc` (never the
/// `Regex`) hands out the same warm instance the `&'static` did, without leaking.
/// Distinct compiled trait regexes kept warm. The byte budget
/// (`str_budget_bytes`) is the real bound; this count cap only guards the
/// LRU's bookkeeping. It must exceed the rule set's regex count: at 16,384
/// the startup warm (17.5k patterns from the memo, ~244 MB) evicted its own
/// earliest entries, and those were exactly the container `type: path`
/// rules the first job recompiled.
const REGEX_CACHE_CAP: std::num::NonZeroUsize = match std::num::NonZeroUsize::new(65_536) {
    Some(capacity) => capacity,
    None => std::num::NonZeroUsize::MIN,
};

static REGEX_CACHE: std::sync::LazyLock<
    std::sync::RwLock<super::regex_store::BudgetedStore<String, TraitRegex>>,
> = std::sync::LazyLock::new(|| {
    std::sync::RwLock::new(super::regex_store::BudgetedStore::new(
        REGEX_CACHE_CAP,
        super::regex_store::str_budget_bytes(),
    ))
});

/// A compiled trait regex for extracted-string / value matching — the same
/// meta engine `regex::Regex` wraps (match-identical by construction), held
/// directly for the levers the facade hides: the eagerly-compiled onepass DFA
/// is disabled (it serves only capture extraction, and trait evaluation is
/// bounds-only), capture states are implicit-only (smaller NFAs), and scratch
/// lives in the byte-budgeted per-thread pool
/// ([`crate::composite_rules::regex_scratch`]) rather than a per-regex ×
/// per-thread pool retained forever — the pools' eager worst-case-O(NFA)
/// caches measured ~1.5 GB live on the typescript-package reference scan.
/// One compiled meta engine plus its scratch-pool identity.
#[derive(Debug)]
struct Engine {
    re: regex_automata::meta::Regex,
    id: u64,
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

/// Which text layers a `type: text` condition is allowed to match against.
///
/// `type: text` normally scans the raw bytes *and* the decoded string layers
/// (base64/hex/xor chains), so a pattern can match content that only exists
/// after decoding. That is what makes an inline base64 payload searchable,
/// but it also means a matcher describing the file's own markup can fire on
/// bytes that are not markup at all: a run of `7b` in an RTF's embedded hex
/// picture decodes to `{{{{{{{{{`, which is not brace nesting.
///
/// `encoding: none` restricts the condition to the undecoded layer. `type:
/// raw` does the same for file types that already use raw text search, but it
/// is not equivalent on binaries, where `type: text` scans extracted strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TextEncodingScope {
    /// Raw bytes and plain string literals only; decoded layers are skipped.
    None,
    /// The default: undecoded content plus every decoded string layer.
    #[default]
    Any,
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
                // Case-insensitive substring. `precompile` pre-lowers trait-level
                // shorthands, but condition- and composite-level ones never pass
                // through it, and an uppercase pattern can never occur in a
                // lowered value — so lower it here unless it already is.
                let value = value.to_lowercase();
                if pattern.chars().all(|c| c.to_lowercase().eq([c])) {
                    value.contains(pattern.as_str())
                } else {
                    value.contains(&pattern.to_lowercase())
                }
            }
            NotException::Structured(s) => {
                if let Some(exact_str) = &s.exact {
                    // Exact string equality is case-SENSITIVE: a `not: exact:`
                    // negates against the regex's matched span, and casing is
                    // significant (e.g. excluding canonical `PowerShell` must
                    // not also excuse the AMSI-evasion respelling `pOwErShElL`).
                    value == exact_str
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
///
/// The two variants never both accept a map -- one requires `type`, the
/// other allows nothing but `id` -- so their order changes only which one
/// serde tries, and fails, first. Tagged comes first: the mapper cache stores
/// every condition tagged (`into = "ConditionTagged"`), and trying the
/// shorthand first built and discarded an error for each one on every load.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ConditionDeser {
    /// All other condition types require explicit `type` field
    Tagged(Box<ConditionTagged>),

    /// Shorthand for trait reference - just `id` field, no `type` needed
    TraitShorthand(TraitShorthandInner),
}

/// High-fidelity validation checks for string matches.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash, Copy, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum StringValidator {
    /// Require the entire match to be Base64-compatible (standard or URL-safe,
    /// padded or unpadded; ASCII wrapping whitespace is allowed). Validates
    /// canonical trailing bits, not decoded content or execution intent.
    Base64,
    /// Require match to contain a valid external IPv4 address
    ExternalIp,
    /// Require match to contain a structurally valid IPv4 address of any
    /// range, including private/loopback/link-local. Use this to confirm an
    /// IP literal of any kind without the external/C2-quality filtering that
    /// `ExternalIp` applies.
    ValidIp,
    /// Require match to contain a valid Bitcoin address (with checksum)
    #[serde(rename = "bitcoin_addr")]
    BitcoinAddr,
    /// Require the match to read as a generated identifier rather than a
    /// chosen one -- a DGA domain label, a maldoc builder's `Author` field, a
    /// generated mutex or bundle name. Scored against an English bigram
    /// model; see `crate::random_validator`. Strings under six letters are
    /// never called random, so this never fires on `Dell` or `admin`.
    #[serde(rename = "random_like")]
    RandomLike,
}

/// Quantifier for cross-fact `eq`/`ne` when a path resolves to multiple values
/// (a bare array or a `[*]` wildcard path). `Any` (the default) fires when the
/// left and right value sets contain a matching/differing pair; `All` requires
/// the relation to hold for every right-hand value. Disambiguates the otherwise
/// unclear `ne: arr[*]` — "differs from some element" vs "differs from all".
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ArrayQuantifier {
    /// Existential: the relation holds for at least one right-hand value.
    #[default]
    Any,
    /// Universal: the relation holds for every right-hand value.
    All,
}

impl ArrayQuantifier {
    /// True for the default (`Any`) — used to skip it during serialization.
    #[must_use]
    fn is_default(&self) -> bool {
        matches!(self, ArrayQuantifier::Any)
    }
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
    /// Dotted member-access chains (`window.localStorage`,
    /// `chrome.cookies.getAll`) from `filefacts::Symbol::Member` — matched
    /// against the chain path. Replaces tree-sitter `member_expression`
    /// queries that only keyed off the dotted path. `attribute` is accepted
    /// as an alias for migrated tree-sitter `kind: attribute` rules (Python
    /// attribute access is the same dotted-chain fact).
    #[serde(alias = "attribute")]
    Member,
    /// Static assignment targets (`API_URL`, `exports.token`) from
    /// `filefacts::Symbol::Bind` — matched against the bind target.
    /// `assignment` is accepted as an alias for migrated tree-sitter
    /// `kind: assignment` rules (the assignment's bound name).
    #[serde(alias = "assignment")]
    Bind,
    /// Bare identifier appearances (variable/type/function names) from
    /// `filefacts::Symbol::Identifier` — matched against the identifier text.
    Identifier,
}

/// Filter for matching a single argument at a call site. Used by
/// `Condition::Symbol(SymbolQuery { kind: Call, arg: ... })`. Each field narrows
/// the match: `kind` filters arg shape (`string`/`number`/`identifier`),
/// the per-shape fields filter content.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ArgFilter {
    /// Zero-based argument position. Omitted means any argument. This is shared
    /// by every source language and by single- and multi-argument matching.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index: Option<usize>,
    /// Require value provenance from a selected call, using filefacts' graph.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<FlowOriginFilter>,
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
    /// String / template value regex match. Lets a migrated `#match? @arg
    /// "..."` predicate keep its exact discrimination (e.g. require's
    /// `^(node:)?http$` to match `http` but not `https`), which `substr`
    /// cannot express.
    #[serde(default)]
    pub regex: Option<String>,
    /// Identifier name exact match (kind=identifier).
    #[serde(default)]
    pub name: Option<String>,
    /// Regex over an identifier argument's syntactic name, not its value.
    #[serde(default)]
    pub name_regex: Option<String>,
    /// High-fidelity check on the argument's literal text, as on text
    /// conditions: a string or template value, or an identifier's name (shell
    /// words such as a curl URL are recorded as identifiers).
    #[serde(default)]
    pub is: Option<StringValidator>,
}

/// Source-call selection and explicit, policy-owned library transfers.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FlowOriginFilter {
    /// Select a field of an object/keyword argument before following values.
    #[serde(default)]
    pub field: Option<String>,
    /// Regex over the source call's canonical target.
    #[serde(default)]
    pub call: String,
    /// Alternatively, match a literal value contributing to the sink argument.
    /// Mutually exclusive with `call` and its argument/literal constraints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Regex over a proven complete literal, not contributing fragments.
    /// Unknown expressions and unmodeled return values remain opaque.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub whole_value: Option<String>,
    /// A proven complete integer value, not a contributing arithmetic operand.
    /// Uses the same fail-closed complete-value projection as `whole_value`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub whole_number: Option<i64>,
    /// Observe an explicitly present named field, even if its value is opaque.
    #[serde(default)]
    pub field_exists: bool,
    /// A field is absent from a concrete source keyword/attribute map.
    #[serde(default)]
    pub field_absent: bool,
    /// Alternatively, select an actual member-read origin by canonical path.
    /// A string or identifier merely spelling this path is not a member read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<String>,
    /// Position of the source call's literal argument to match (default zero).
    #[serde(default)]
    pub argument: usize,
    /// Optional regex over that literal argument's value.
    #[serde(default)]
    pub literal: Option<String>,
    /// External calls whose return values preserve selected inputs.
    #[serde(default)]
    pub through: Vec<FlowTransferModel>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FlowTransferModel {
    pub call: String,
    #[serde(default)]
    pub arguments: Vec<usize>,
    #[serde(default)]
    pub receiver: bool,
}

/// Filter for a source-language import's local alias — the `sp` in
/// `import subprocess as sp`. Used by `Condition::Symbol(SymbolQuery { kind: import,
/// alias: ... })`. An empty filter (`alias: {}`) matches any aliased import;
/// `exact`/`substr`/`regex` narrow to a specific alias (e.g. a 1–2 char alias
/// as an obfuscation signal). A plain (non-aliased) import never matches when
/// an `alias` filter is present.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AliasFilter {
    #[serde(default)]
    pub exact: Option<String>,
    #[serde(default)]
    pub substr: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
}

impl AliasFilter {
    /// True when `alias` (the import's local alias) satisfies this filter.
    /// A `None` alias (plain import) never matches.
    pub(crate) fn matches(&self, alias: Option<&str>) -> bool {
        let Some(a) = alias else { return false };
        if let Some(e) = &self.exact
            && a != e
        {
            return false;
        }
        if let Some(s) = &self.substr
            && !a.contains(s.as_str())
        {
            return false;
        }
        if let Some(r) = &self.regex
            && !regex::Regex::new(r).is_ok_and(|re| re.is_match(a))
        {
            return false;
        }
        true
    }
}

/// Predicate on one resolved syscall argument (see `Condition::Syscall`). The
/// argument is identified by its syscall-ABI `index` (0 = first arg); a match
/// requires the argument to be a resolved constant satisfying every stated test:
/// `mask` — every bit of `mask` is set (`v & mask == mask`), for flag words like
/// `PROT_EXEC`; `value` — exact equality, for enumerated arguments.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SyscallArg {
    pub index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mask: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
}

impl SyscallArg {
    /// Whether one syscall's resolved argument list satisfies this predicate.
    /// An unresolved argument never matches: absence of a constant is not
    /// evidence of the constant a rule is asking about.
    pub(crate) fn matches(&self, args: &[Option<u64>]) -> bool {
        let Some(&Some(v)) = args.get(self.index) else {
            return false;
        };
        self.mask.is_none_or(|m| v & m == m) && self.value.is_none_or(|want| v == want)
    }
}

/// Condition `type:` spellings that still load but are slated for retirement,
/// each with the spelling that replaces it. `cleave validate` counts their uses
/// (see [`count_retiring_condition_types`]) so the rules can be migrated before
/// support is removed.
#[cfg(feature = "lint")]
pub(crate) const RETIRING_CONDITION_TYPES: &[(&str, &str)] = &[
    ("string_literal", "literal"),
    ("import", "symbol + kind: import"),
    ("export", "symbol + kind: export"),
    ("function", "symbol + kind: function"),
    ("basename", "path + basename: true"),
];

/// Count `type: <spelling>` lines in rule YAML for each entry of
/// [`RETIRING_CONDITION_TYPES`], in that order.
#[must_use]
#[cfg(feature = "lint")]
pub(crate) fn count_retiring_condition_types<'a>(
    yaml_files: impl IntoIterator<Item = &'a [u8]>,
) -> Vec<usize> {
    let mut counts = vec![0; RETIRING_CONDITION_TYPES.len()];
    for bytes in yaml_files {
        for line in bytes.split(|&b| b == b'\n') {
            let Ok(line) = std::str::from_utf8(line) else {
                continue;
            };
            let Some(value) = line
                .trim_start()
                .trim_start_matches("- ")
                .strip_prefix("type:")
                .map(|v| v.trim().trim_matches(['"', '\'']))
            else {
                continue;
            };
            if let Some(i) = RETIRING_CONDITION_TYPES
                .iter()
                .position(|(old, _)| *old == value)
            {
                counts[i] += 1;
            }
        }
    }
    counts
}

/// Payload of the legacy `type: import` / `export` / `function` conditions: a
/// `type: symbol` with its `kind` implied by the type name.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SymbolAliasQuery {
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
}

/// Payload of the legacy `type: basename` condition: a `type: path` scoped to
/// the file name.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BasenameQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    exact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    substr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    regex: Option<String>,
    #[serde(default)]
    case_insensitive: bool,
    #[serde(rename = "is", default)]
    is_check: Option<StringValidator>,
}

/// Internal tagged enum for serializing/deserializing conditions with explicit `type` field
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
enum ConditionTagged {
    Symbol(SymbolQuery),
    Import(SymbolAliasQuery),
    Export(SymbolAliasQuery),
    Function(SymbolAliasQuery),
    Text(TextQuery),
    Comment(CommentQuery),
    #[serde(alias = "string_literal")]
    Literal(LiteralQuery),
    Trait {
        id: String,
    },
    #[serde(rename = "tree-sitter")]
    TreeSitter(TreeSitterQuery),
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
        #[serde(default)]
        args: Vec<SyscallArg>,
    },
    Metrics(MetricsQuery),
    Hex(HexQuery),
    Raw(RawQuery),
    Section(SectionQuery),
    Encoded(EncodedQuery),
    Path(PathQuery),
    Basename(BasenameQuery),
    #[serde(rename = "value")]
    Kv(KvQuery),
}

impl From<ConditionDeser> for Condition {
    fn from(deser: ConditionDeser) -> Self {
        let mut condition = match deser {
            ConditionDeser::TraitShorthand(inner) => Condition::Trait { id: inner.id },
            ConditionDeser::Tagged(tagged) => match *tagged {
                ConditionTagged::Symbol(query) => Condition::Symbol(query),
                ConditionTagged::Text(query) => Condition::Text(query),
                ConditionTagged::Comment(query) => Condition::Comment(query),
                ConditionTagged::Literal(query) => Condition::Literal(query),
                ConditionTagged::TreeSitter(query) => Condition::TreeSitter(query),
                ConditionTagged::Metrics(query) => Condition::Metrics(query),
                ConditionTagged::Hex(query) => Condition::Hex(query),
                ConditionTagged::Raw(query) => Condition::Raw(query),
                ConditionTagged::Section(query) => Condition::Section(query),
                ConditionTagged::Encoded(query) => Condition::Encoded(query),
                ConditionTagged::Path(query) => Condition::Path(query),
                ConditionTagged::Kv(query) => Condition::Kv(query),
                ConditionTagged::Import(query) => query.into_symbol(SymbolKind::Import),
                ConditionTagged::Export(query) => query.into_symbol(SymbolKind::Export),
                ConditionTagged::Function(query) => query.into_symbol(SymbolKind::Function),
                ConditionTagged::Basename(BasenameQuery {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                    is_check,
                }) => Condition::Path(PathQuery {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                    is_check,
                    basename: true,
                    dirname: false,
                }),
                ConditionTagged::Trait { id } => Condition::Trait { id },
                ConditionTagged::Yara { source } => Condition::Yara {
                    source,
                    compiled: None,
                    namespace: None,
                },
                ConditionTagged::Syscall {
                    name,
                    number,
                    arch,
                    args,
                } => Condition::Syscall {
                    name,
                    number,
                    arch,
                    args,
                },
            },
        };
        condition.normalize_legacy_call_targets();
        condition
    }
}

impl SymbolAliasQuery {
    fn into_symbol(self, kind: SymbolKind) -> Condition {
        let Self {
            exact,
            substr,
            regex,
            platforms,
            is_check,
            not,
        } = self;
        Condition::Symbol(SymbolQuery {
            exact,
            substr,
            regex,
            platforms,
            is_check,
            kind: Some(kind),
            arg: None,
            args: None,
            alias: None,
            not,
            module_level: false,
            receiver: None,
        })
    }
}

impl From<Condition> for ConditionTagged {
    fn from(cond: Condition) -> Self {
        match cond {
            Condition::Symbol(query) => ConditionTagged::Symbol(query),
            Condition::Text(query) => ConditionTagged::Text(query),
            Condition::Comment(query) => ConditionTagged::Comment(query),
            Condition::Literal(query) => ConditionTagged::Literal(query),
            Condition::TreeSitter(query) => ConditionTagged::TreeSitter(query),
            Condition::Metrics(query) => ConditionTagged::Metrics(query),
            Condition::Hex(query) => ConditionTagged::Hex(query),
            Condition::Raw(query) => ConditionTagged::Raw(query),
            Condition::Section(query) => ConditionTagged::Section(query),
            Condition::Encoded(query) => ConditionTagged::Encoded(query),
            Condition::Path(query) => ConditionTagged::Path(query),
            Condition::Kv(query) => ConditionTagged::Kv(query),
            Condition::Trait { id } => ConditionTagged::Trait { id },
            Condition::Yara {
                source,
                compiled: _,
                namespace: _,
            } => ConditionTagged::Yara { source },
            Condition::Syscall {
                name,
                number,
                arch,
                args,
            } => ConditionTagged::Syscall {
                name,
                number,
                arch,
                args,
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
#[allow(clippy::large_enum_variant)]
pub(crate) enum Condition {
    /// Match a symbol (import/export/function/forward)
    Symbol(SymbolQuery),

    /// Match human-readable text.
    ///
    /// On binary-like formats this searches extracted strings for speed. On
    /// source and structured text formats it searches raw file text.
    Text(TextQuery),

    /// Match against source-code comment bodies only (`report.comments`).
    /// The lowest-false-positive tier for "keyword mentioned in a comment"
    /// rules — never fires on the same keyword in code or a string literal.
    Comment(CommentQuery),

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
    Literal(LiteralQuery),

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
    TreeSitter(TreeSitterQuery),

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

    /// Match syscalls detected via binform binary analysis
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
        /// Predicates on resolved arguments, ANDed against the *same* syscall
        /// record (e.g. `prot & PROT_EXEC` and `flags & MAP_ANONYMOUS`).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        args: Vec<SyscallArg>,
    },

    /// Check computed metrics for obfuscation/anomaly detection
    /// For detecting obfuscation patterns in source code via statistical analysis
    Metrics(MetricsQuery),

    /// Match hex byte patterns in binary data
    /// Supports wildcards (??) and variable-length gaps ([N] or [N-M])
    /// Wildcard bytes are always extracted and included in evidence (consistent with regex behavior)
    /// Example: { type: hex, pattern: "7F 45 4C 46" }  # ELF magic
    /// Example: { type: hex, pattern: "31 ?? 48 83" }  # With wildcards - ?? bytes will be extracted
    /// Example: { type: hex, pattern: "00 03 [4] 00 04" }  # With 4-byte gap
    Hex(HexQuery),

    /// Search raw file content directly (for source files or matching across
    /// string boundaries in binaries). Unlike `type: text` which only searches
    /// properly extracted/bounded strings, this searches the raw bytes as text.
    /// Use this when you need to match patterns in source code or when string
    /// extraction may not capture what you're looking for.
    /// Example: { type: raw, substr: "eval(" }
    /// Example: { type: raw, exact: "#!/bin/sh" }  # Entire file must equal this
    /// Example: { type: raw, regex: "\\bpassword\\s*=", case_insensitive: true }
    /// Example: { type: raw, word: "socket" }  # Match "socket" as whole word
    Raw(RawQuery),

    /// Match section names in binary files (PE, ELF, Mach-O)
    /// Replaces YARA patterns like: `for any section in pe.sections : (section.name matches /^UPX/)`
    /// Example: { type: section, regex: "^UPX" }
    /// Example: { type: section, substr: "upx", case_insensitive: true }
    Section(SectionQuery),

    /// Match patterns in encoded/decoded strings (unified replacement for base64/xor)
    /// Example: { type: encoded, encoding: base64, regex: "https?://" }
    /// Example: { type: encoded, encoding: [xor, hex], substr: "eval(" }
    /// Example: { type: encoded, word: "password" } - searches ALL encoded strings
    Encoded(EncodedQuery),

    /// Match the file path. Full path by default; `basename`/`dirname` scope it.
    Path(PathQuery),

    /// Query structural values using path expressions.
    /// Supports dot notation for nested access and [*] for array iteration.
    /// Example: { type: value, path: "permissions", is: "debugger" }
    /// Example: { type: value, path: "scripts.postinstall", substr: "curl" }
    /// Example: { type: value, path: "content_scripts[*].matches", is: "<all_urls>" }
    /// Example: { type: value, path: "maintainers", length_min: 1, length_max: 1 }
    /// Example: { type: value, path: "file.basename", ne: "pe.version_info.original_filename" }
    Kv(KvQuery),
}

/// Payload for a `type: value` (kv) condition. A named, `Default`-able struct so
/// call sites build it with `KvQuery { path, ..Default::default() }` and adding a
/// field touches only the sites that set it. The wire format lives in
/// `ConditionTagged::Kv`; this is the internal representation, so it carries no
/// serde attributes.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KvQuery {
    /// Path to navigate using dot notation, `[n]` for indices, `[*]` for
    /// wildcards. Accepts an optional `<filename>::` prefix to reference a
    /// sibling file's values within the same archive scope.
    pub path: String,
    /// Value/element equals exactly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    /// Value/element contains substring.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub substr: Option<String>,
    /// Value/element matches regex pattern.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// Right-hand-side value path for cross-fact equality (case-insensitive,
    /// whitespace-trimmed). Accepts a `<filename>::` sibling prefix.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eq: Option<String>,
    /// Right-hand-side value path for cross-fact inequality.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ne: Option<String>,
    /// Quantifier when `eq`/`ne` resolves to multiple values (`any`/`all`).
    #[serde(
        rename = "match",
        default,
        skip_serializing_if = "ArrayQuantifier::is_default"
    )]
    pub match_mode: ArrayQuantifier,
    /// Case insensitive matching (default: false).
    #[serde(default)]
    pub case_insensitive: bool,
    /// Explicit existence check (true = must exist, false = must not exist).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exists: Option<bool>,
    /// Values to exclude after a match, as for the text conditions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not: Option<Vec<NotException>>,
    /// Minimum len() of the value: string bytes, array elements, or object keys.
    #[serde(alias = "size_min", skip_serializing_if = "Option::is_none")]
    pub length_min: Option<usize>,
    /// Maximum len() of the value (see `length_min`).
    #[serde(alias = "size_max", skip_serializing_if = "Option::is_none")]
    pub length_max: Option<usize>,
    /// Optional high-fidelity validation check applied to the resolved value.
    #[serde(rename = "is", default)]
    pub is_check: Option<StringValidator>,
}

impl Condition {
    /// Rewrite the pre-filefacts call-target spelling in YAML conditions.
    ///
    /// Older filefacts versions represented a chained call such as
    /// `open(...).read()` as `open().read`. Current filefacts emits the
    /// canonical dotted target `open.read`. Keep existing trait YAML working
    /// by applying that compatibility rewrite to call-symbol predicates as
    /// they are deserialized; the facts themselves remain in the new form.
    fn normalize_legacy_call_targets(&mut self) {
        let Condition::Symbol(SymbolQuery {
            kind: Some(SymbolKind::Call),
            exact,
            substr,
            regex,
            arg,
            args,
            ..
        }) = self
        else {
            return;
        };

        // Drop the legacy literal `()` call marker.
        for pattern in exact.iter_mut().chain(substr.iter_mut()) {
            if pattern.contains("()") {
                *pattern = pattern.replace("()", "");
            }
        }
        if let Some(pattern) = regex {
            normalize_legacy_call_regex(pattern);
        }

        let normalize_origin = |origin: &mut FlowOriginFilter| {
            normalize_legacy_call_regex(&mut origin.call);
            for transfer in &mut origin.through {
                normalize_legacy_call_regex(&mut transfer.call);
            }
        };
        if let Some(filter) = arg.as_mut().and_then(|filter| filter.from.as_mut()) {
            normalize_origin(filter);
        }
        if let Some(filters) = args {
            for filter in filters {
                if let Some(origin) = filter.from.as_mut() {
                    normalize_origin(origin);
                }
            }
        }
    }

    /// The direct path inputs of this condition, for
    /// `CapabilityMapper::paths_equivalent`: a `type: path` query, or the
    /// `file.*` value keys a `kv` condition reads.
    pub(crate) fn collect_path_inputs(&self, out: &mut Vec<PathInput>) {
        match self {
            Self::Path(q) => out.push(PathInput::Query(q.clone())),
            Self::Kv(q) => {
                for p in [Some(q.path.as_str()), q.eq.as_deref(), q.ne.as_deref()]
                    .into_iter()
                    .flatten()
                {
                    if p.starts_with("file.") {
                        out.push(PathInput::FileValue(p.to_string()));
                    }
                }
            }
            _ => {}
        }
    }

    pub(crate) fn collect_trait_refs(&self, out: &mut std::collections::BTreeSet<String>) {
        if let Self::Trait { id } = self {
            out.insert(id.trim_end_matches('/').to_string());
        }
    }

    /// Reference selector for conditions that name one trait.
    pub(crate) fn trait_references(&self) -> &[String] {
        match self {
            Self::Trait { id } => std::slice::from_ref(id),
            _ => &[],
        }
    }

    /// Mutable selector for resolving local names during loading.
    pub(crate) fn trait_references_mut(&mut self) -> &mut [String] {
        match self {
            Self::Trait { id } => std::slice::from_mut(id),
            _ => &mut [],
        }
    }

    /// The `query:` string on a live tree-sitter condition, if any.
    pub(crate) fn ast_query_text(&self) -> Option<&str> {
        match self {
            Self::TreeSitter(TreeSitterQuery { query: Some(q), .. }) if !q.is_empty() => {
                Some(q.as_str())
            }
            _ => None,
        }
    }

    pub(crate) fn collect_kv_sibling_basenames(
        &self,
        out: &mut std::collections::BTreeSet<String>,
    ) {
        let Self::Kv(q) = self else { return };
        for path in [Some(q.path.as_str()), q.eq.as_deref(), q.ne.as_deref()]
            .into_iter()
            .flatten()
        {
            if let (Some(name), _) =
                crate::composite_rules::evaluators::kv::split_qualified_path(path)
            {
                out.insert(name.to_ascii_lowercase());
            }
        }
    }
}

/// Payload for `type: text` — byte-scan over extracted strings / raw source text.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TextQuery {
    /// Restrict which text layers may match; see [`TextEncodingScope`].
    #[serde(default)]
    pub encoding: Option<TextEncodingScope>,
    #[serde(default)]
    pub exact: Option<String>,
    #[serde(default)]
    pub substr: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub word: Option<String>,
    #[serde(default)]
    pub case_insensitive: bool,
    /// Byte-length bounds on the regex match span; requires `regex:`.
    /// The cheap way to say "a run of at least N": pair a greedy loop with
    /// `length_min` instead of a counted repetition (`{4000,}`), which
    /// unrolls into one NFA state per rep. Keep a small counted floor for
    /// selectivity (`[A-Za-z0-9]{64,}` + `length_min: 4000`) so the scan
    /// isn't spent visiting every short run on match-dense content.
    #[serde(default)]
    pub length_min: Option<usize>,
    #[serde(default)]
    pub length_max: Option<usize>,
    /// Ignore HTML (`<!-- -->`) and ASP.NET (`<%-- --%>`) comments when
    /// scanning raw source text. Encoded strings are not markup.
    #[serde(default)]
    pub exclude_html_comments: bool,
    /// Ignore source-language comments (filefacts' comment bodies) when
    /// scanning raw source text: commented-out code and prose are not code.
    #[serde(default)]
    pub exclude_comments: bool,
    #[serde(rename = "is", default)]
    pub is_check: Option<StringValidator>,
    #[serde(default)]
    pub not: Option<Vec<NotException>>,
    #[serde(default)]
    pub platforms: Option<Vec<Platform>>,
    #[serde(default)]
    pub section: Option<String>,
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(
        default,
        deserialize_with = "offset_range_serde::deserialize",
        serialize_with = "offset_range_serde::serialize"
    )]
    pub offset_range: Option<(i64, Option<i64>)>,
    #[serde(default)]
    pub section_offset: Option<i64>,
    #[serde(
        default,
        deserialize_with = "offset_range_serde::deserialize",
        serialize_with = "offset_range_serde::serialize"
    )]
    pub section_offset_range: Option<(i64, Option<i64>)>,
}

/// Payload for `type: raw` — substring/regex over the full raw file bytes.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawQuery {
    #[serde(default)]
    pub exact: Option<String>,
    #[serde(default)]
    pub substr: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub word: Option<String>,
    #[serde(default)]
    pub case_insensitive: bool,
    /// Byte-length bounds on the regex match span; requires `regex:` (see
    /// [`TextQuery::length_min`]).
    #[serde(default)]
    pub length_min: Option<usize>,
    #[serde(default)]
    pub length_max: Option<usize>,
    #[serde(rename = "is", default)]
    pub is_check: Option<StringValidator>,
    #[serde(default)]
    pub not: Option<Vec<NotException>>,
    #[serde(default)]
    pub section: Option<String>,
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(
        default,
        deserialize_with = "offset_range_serde::deserialize",
        serialize_with = "offset_range_serde::serialize"
    )]
    pub offset_range: Option<(i64, Option<i64>)>,
    #[serde(default)]
    pub section_offset: Option<i64>,
    #[serde(
        default,
        deserialize_with = "offset_range_serde::deserialize",
        serialize_with = "offset_range_serde::serialize"
    )]
    pub section_offset_range: Option<(i64, Option<i64>)>,
}

/// Payload for `type: encoded` — matches across decoded-string layers.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EncodedQuery {
    #[serde(default)]
    pub encoding: Option<EncodingSpec>,
    #[serde(default)]
    pub exact: Option<String>,
    #[serde(default)]
    pub substr: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub word: Option<String>,
    #[serde(default)]
    pub case_insensitive: bool,
    #[serde(rename = "is", default)]
    pub is_check: Option<StringValidator>,
    #[serde(default)]
    pub not: Option<Vec<NotException>>,
    #[serde(default)]
    pub section: Option<String>,
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(
        default,
        deserialize_with = "offset_range_serde::deserialize",
        serialize_with = "offset_range_serde::serialize"
    )]
    pub offset_range: Option<(i64, Option<i64>)>,
    #[serde(default)]
    pub section_offset: Option<i64>,
    #[serde(
        default,
        deserialize_with = "offset_range_serde::deserialize",
        serialize_with = "offset_range_serde::serialize"
    )]
    pub section_offset_range: Option<(i64, Option<i64>)>,
}

/// Payload for `type: section` — binary section name/size/entropy/permission match.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SectionQuery {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub substr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub word: Option<String>,
    #[serde(default)]
    pub case_insensitive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length_min: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub length_max: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_max: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub writable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compare_to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_ratio_min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_ratio_max: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_ratio_min: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_ratio_max: Option<f64>,
}

/// Payload for `type: symbol` — imports/exports/functions/calls.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SymbolQuery {
    #[serde(default)]
    pub exact: Option<String>,
    #[serde(default)]
    pub substr: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub platforms: Option<Vec<Platform>>,
    #[serde(rename = "is", default)]
    pub is_check: Option<StringValidator>,
    #[serde(default)]
    pub kind: Option<SymbolKind>,
    #[serde(default)]
    pub arg: Option<ArgFilter>,
    #[serde(default)]
    pub args: Option<Vec<ArgFilter>>,
    #[serde(default)]
    pub alias: Option<AliasFilter>,
    #[serde(default)]
    pub not: Option<Vec<NotException>>,
    /// `kind: call` only: the call is evaluated in module-level code, so it
    /// runs when the file loads (Node `require`, Python `import`) rather than
    /// when some function is later called. Requires filefacts' flow graph;
    /// `false` places no constraint.
    #[serde(default)]
    pub module_level: bool,
    /// `kind: call` only: where the receiver comes from — the `cp` in
    /// `cp.execSync()` — traced like `arg.from`.
    #[serde(default)]
    pub receiver: Option<ReceiverFilter>,
}

/// Provenance of a call's receiver, the value a method is called on.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReceiverFilter {
    pub from: FlowOriginFilter,
}

/// Payload for `type: comment` — source comment-body matches.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CommentQuery {
    #[serde(default)]
    pub exact: Option<String>,
    #[serde(default)]
    pub substr: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub word: Option<String>,
    #[serde(default)]
    pub case_insensitive: bool,
    #[serde(rename = "is", default)]
    pub is_check: Option<StringValidator>,
    #[serde(default)]
    pub not: Option<Vec<NotException>>,
    #[serde(default)]
    pub platforms: Option<Vec<Platform>>,
}

/// Payload for `type: literal` — parser-extracted string/number literals.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LiteralQuery {
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub exact: Option<String>,
    #[serde(default)]
    pub substr: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub word: Option<String>,
    #[serde(default)]
    pub value: Option<i64>,
    #[serde(default)]
    pub radix: Option<u32>,
    #[serde(default)]
    pub case_insensitive: bool,
    /// Skip Python module/class/function docstrings while matching source
    /// string literals. Useful for capabilities where a documented URL or
    /// command is not evidence that the program uses it.
    #[serde(default)]
    pub exclude_docstrings: bool,
    #[serde(rename = "is", default)]
    pub is_check: Option<StringValidator>,
    #[serde(default)]
    pub not: Option<Vec<NotException>>,
    #[serde(default)]
    pub platforms: Option<Vec<Platform>>,
    #[serde(default)]
    pub section: Option<String>,
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(
        default,
        deserialize_with = "offset_range_serde::deserialize",
        serialize_with = "offset_range_serde::serialize"
    )]
    pub offset_range: Option<(i64, Option<i64>)>,
    #[serde(default)]
    pub section_offset: Option<i64>,
    #[serde(
        default,
        deserialize_with = "offset_range_serde::deserialize",
        serialize_with = "offset_range_serde::serialize"
    )]
    pub section_offset_range: Option<(i64, Option<i64>)>,
}

/// Payload for `type: tree-sitter` — live tree-sitter query escape hatch.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TreeSitterQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub substr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default)]
    pub case_insensitive: bool,
}

/// Payload for `type: hex` — byte-pattern match with wildcards/gaps.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HexQuery {
    pub pattern: String,
    #[serde(default)]
    pub not: Option<Vec<NotException>>,
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(
        default,
        deserialize_with = "offset_range_serde::deserialize",
        serialize_with = "offset_range_serde::serialize"
    )]
    pub offset_range: Option<(i64, Option<i64>)>,
    #[serde(default)]
    pub section: Option<String>,
    #[serde(default)]
    pub section_offset: Option<i64>,
    #[serde(
        default,
        deserialize_with = "offset_range_serde::deserialize",
        serialize_with = "offset_range_serde::serialize"
    )]
    pub section_offset_range: Option<(i64, Option<i64>)>,
}

/// Payload for `type: path` — file path / basename / dirname match.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PathQuery {
    #[serde(default)]
    pub exact: Option<String>,
    #[serde(default)]
    pub substr: Option<String>,
    #[serde(default)]
    pub regex: Option<String>,
    #[serde(default)]
    pub case_insensitive: bool,
    #[serde(rename = "is", default)]
    pub is_check: Option<StringValidator>,
    #[serde(default)]
    pub basename: bool,
    #[serde(default)]
    pub dirname: bool,
}

/// One direct path input of a rule (see `Condition::collect_path_inputs`).
#[derive(Debug, Clone)]
pub(crate) enum PathInput {
    Query(PathQuery),
    FileValue(String),
}

impl PathInput {
    /// Whether this input reads the same value under `a` and `b`. Conservative:
    /// an input that cannot be settled cheaply reports `false`.
    pub(crate) fn same_under(&self, a: &str, b: &str) -> bool {
        use crate::composite_rules::evaluators::{path_basename, path_dirname};
        match self {
            Self::FileValue(key) => match key.as_str() {
                // Derived from the basename alone (`restamp_path_derived_values`
                // rewrites them); equal basenames make them equal.
                "file.basename" | "file.stem" | "file.extension" => {
                    path_basename(a) == path_basename(b)
                }
                // Derived from the bytes, not the path: identical content
                // reads the same value anywhere.
                "file.size" | "file.size_bytes" | "file.entropy" => true,
                _ => a == b,
            },
            Self::Query(q) => {
                let scope = |p: &str| -> String {
                    if q.basename {
                        path_basename(p).to_string()
                    } else if q.dirname {
                        path_dirname(p).to_string()
                    } else {
                        p.to_string()
                    }
                };
                let (ta, tb) = (scope(a), scope(b));
                if ta == tb {
                    return true;
                }
                // A validator inspects the matched text; only equal targets
                // are known to agree.
                if q.is_check.is_some() {
                    return false;
                }
                // Mirror `eval_path` exactly.
                let matched = |target: &str| -> bool {
                    let cmp_target = if q.case_insensitive {
                        target.to_lowercase()
                    } else {
                        target.to_string()
                    };
                    if let Some(e) = &q.exact {
                        let e = if q.case_insensitive {
                            e.to_lowercase()
                        } else {
                            e.clone()
                        };
                        cmp_target == e
                    } else if let Some(sub) = &q.substr {
                        let sub = if q.case_insensitive {
                            sub.to_lowercase()
                        } else {
                            sub.clone()
                        };
                        cmp_target.contains(sub.as_str())
                    } else if let Some(r) = &q.regex {
                        lazy_regex(Some(r.as_str()), q.case_insensitive)
                            .map(|re| re.is_match(target))
                            .unwrap_or(false)
                    } else {
                        false
                    }
                };
                matched(&ta) == matched(&tb)
            }
        }
    }
}

/// Payload for `type: metrics` — computed metric threshold check.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MetricsQuery {
    pub field: String,
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
    #[serde(default)]
    pub min_size: Option<u64>,
    #[serde(default)]
    pub max_size: Option<u64>,
}

#[cfg(test)]
mod retiring_condition_type_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod location_constraint_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod backtrack_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod can_match_file_type_tests;
