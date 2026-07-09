//! Condition types for composite rules.
use super::types::Platform;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
/// Distinct compiled trait regexes kept warm; sized to the regex-using slice of
/// the corpus (a few thousand), so the working set fits and never thrashes.
const REGEX_CACHE_CAP: std::num::NonZeroUsize = {
    #[allow(clippy::expect_used)]
    std::num::NonZeroUsize::new(16_384).expect("REGEX_CACHE_CAP is non-zero")
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

impl Engine {
    fn new(re: regex_automata::meta::Regex) -> Engine {
        Engine {
            re,
            id: super::regex_scratch::next_regex_id(),
        }
    }
}

/// A compiled trait regex for extracted-string / value matching, held as a
/// **haystack-dispatched engine pair**: for an ASCII pattern, the ASCII-mode
/// and Unicode-mode engines are provably match-identical on any pure-ASCII
/// haystack (every semantic difference — `.`, `\w`-family classes, `(?i)`
/// folding, `\b`, negated classes, empty-match positioning — only manifests
/// when the haystack contains non-ASCII bytes). Extracted strings are almost
/// always pure ASCII, so the small ASCII engine (whose classes avoid the
/// UTF-8 sub-automaton expansion that made Unicode NFAs 5-10× larger and
/// dominated peak RSS) serves nearly every search, and the full Unicode
/// engine is compiled lazily, only for patterns that actually meet a
/// non-ASCII string — where it preserves upstream `regex::Regex` semantics
/// exactly.
#[derive(Debug)]
pub(crate) struct TraitRegex {
    /// ASCII-mode engine, used when the haystack is pure ASCII. `None` when
    /// the pattern itself is not ASCII-compatible (then `eager_unicode` is
    /// set instead).
    ascii: Option<Engine>,
    /// The Unicode engine for patterns that have no ASCII form (non-ASCII
    /// source or `\u`/`\p` escapes — rare and individually cheap). The
    /// Unicode *twins* of ASCII-compatible patterns are NOT stored here: they
    /// live in the process-global budgeted [`UNICODE_ENGINES`] store, so that
    /// content which forces them into existence (JS-heavy inputs where most
    /// strings carry non-ASCII) cannot grow an unaccounted engine population
    /// — a per-`TraitRegex` lazy slot escaped the byte budget and measured
    /// ~1.2 GB on the realworld worker benchmark.
    eager_unicode: Option<std::sync::Arc<Engine>>,
    /// The source pattern, kept for diagnostics (`as_str` parity) and the
    /// lazy Unicode compile.
    pattern: Box<str>,
    /// Minimum haystack length that can possibly match — shorter inputs
    /// return without touching the scratch pool, mirroring the facade's
    /// `is_impossible` pre-check (which it performs before its own pool
    /// access; most candidate strings are shorter than most patterns'
    /// literals, so this skips the majority of pool roundtrips). A property
    /// of the pattern, identical for both engines.
    min_len: usize,
}

/// Process-global, byte-budgeted store of lazily-built Unicode engines for
/// ASCII-compatible patterns (see [`TraitRegex::eager_unicode`]). Keyed by
/// pattern; entries are `Arc`-shared so eviction is always safe (an engine in
/// use stays alive until its search returns; the next non-ASCII haystack just
/// recompiles it).
static UNICODE_ENGINES: std::sync::LazyLock<
    std::sync::RwLock<super::regex_store::BudgetedStore<String, Engine>>,
> = std::sync::LazyLock::new(|| {
    std::sync::RwLock::new(super::regex_store::BudgetedStore::new(
        REGEX_CACHE_CAP,
        super::regex_store::unicode_budget_bytes(),
    ))
});

/// Fetch-or-compile the shared Unicode engine for `pattern`.
fn shared_unicode_engine(pattern: &str) -> Option<std::sync::Arc<Engine>> {
    if let Some(arc) = UNICODE_ENGINES
        .read()
        .ok()
        .and_then(|c| c.peek(pattern).cloned())
    {
        return Some(arc);
    }
    let engine = std::sync::Arc::new(Engine::new(compile_unicode(pattern)?));
    let size = engine.re.memory_usage() + pattern.len();
    if let Ok(mut cache) = UNICODE_ENGINES.write() {
        cache.put(pattern.to_string(), std::sync::Arc::clone(&engine), size);
    }
    Some(engine)
}

/// A borrowed-or-shared engine handle, so the hot ASCII path stays a plain
/// borrow while store-served Unicode engines carry their `Arc`.
enum EngineRef<'a> {
    Borrowed(&'a Engine),
    Shared(std::sync::Arc<Engine>),
}

impl EngineRef<'_> {
    fn get(&self) -> &Engine {
        match self {
            EngineRef::Borrowed(e) => e,
            EngineRef::Shared(a) => a,
        }
    }
}

/// Shared meta-engine options: no onepass DFA (capture extraction only —
/// trait evaluation is bounds-only), implicit-only capture states (smaller
/// NFAs), the facade's 10 MB size limit, and the tunable lazy-DFA budget.
fn engine_config() -> regex_automata::meta::Config {
    regex_automata::meta::Regex::config()
        .onepass(false)
        .which_captures(regex_automata::nfa::thompson::WhichCaptures::Implicit)
        .nfa_size_limit(Some(10 * (1 << 20)))
        .hybrid_cache_capacity(super::evaluators::regex_dfa_cache_bytes())
}

impl TraitRegex {
    /// Compile `pattern` with `regex::Regex::new` semantics. ASCII-compatible
    /// patterns get the small ASCII engine eagerly and defer the Unicode one;
    /// others (non-ASCII source, `\u`/`\p` escapes, or
    /// `CLEAVE_REGEX_UNICODE=1`) compile the Unicode engine eagerly.
    fn compile(pattern: &str) -> Option<TraitRegex> {
        let min_len = regex_syntax::parse(pattern)
            .ok()?
            .properties()
            .minimum_len()
            .unwrap_or(0);
        let ascii = if ascii_compatible(pattern) && !super::evaluators::regex_unicode_override() {
            compile_ascii(pattern).map(Engine::new)
        } else {
            None
        };
        let eager_unicode = if ascii.is_none() {
            // No ASCII engine: the Unicode engine is the only one, so build it
            // now and fail compile() outright if the pattern is invalid.
            Some(std::sync::Arc::new(Engine::new(compile_unicode(pattern)?)))
        } else {
            None
        };
        Some(TraitRegex {
            ascii,
            eager_unicode,
            pattern: pattern.into(),
            min_len,
        })
    }

    /// The engine for `haystack`: ASCII when both pattern and haystack allow
    /// it (the overwhelmingly common case), otherwise the Unicode engine —
    /// inline for Unicode-only patterns, from the budgeted shared store for
    /// ASCII-compatible ones meeting a non-ASCII haystack.
    fn engine_for(&self, haystack: &str) -> Option<EngineRef<'_>> {
        if let Some(ascii) = &self.ascii
            && haystack.is_ascii()
        {
            return Some(EngineRef::Borrowed(ascii));
        }
        if let Some(eager) = &self.eager_unicode {
            return Some(EngineRef::Borrowed(eager));
        }
        shared_unicode_engine(&self.pattern).map(EngineRef::Shared)
    }

    /// The source pattern this regex was compiled from.
    pub(crate) fn as_str(&self) -> &str {
        &self.pattern
    }

    /// Heap footprint of the inline engines, for the byte-budgeted store.
    /// The shared Unicode twins are accounted by [`UNICODE_ENGINES`] itself,
    /// so insert-time measurement here is exact.
    pub(crate) fn heap_bytes(&self) -> usize {
        let ascii = self.ascii.as_ref().map_or(0, |e| e.re.memory_usage());
        let unicode = self
            .eager_unicode
            .as_ref()
            .map_or(0, |e| e.re.memory_usage());
        ascii + unicode + self.pattern.len() + std::mem::size_of::<Self>()
    }

    /// Whether the pattern matches anywhere in `haystack`. `earliest(true)`
    /// mirrors the facade's `is_match`: stop at the first proof of a match
    /// instead of running the leftmost-first match to completion.
    pub(crate) fn is_match(&self, haystack: &str) -> bool {
        if haystack.len() < self.min_len {
            return false;
        }
        let Some(engine) = self.engine_for(haystack) else {
            return false;
        };
        let engine = engine.get();
        super::regex_scratch::with_cache(engine.id, &engine.re, |cache| {
            engine
                .re
                .search_half_with(cache, &regex_automata::Input::new(haystack).earliest(true))
                .is_some()
        })
    }

    /// Leftmost-first match, returned as a borrow of `haystack` (the span the
    /// facade's `find(..).as_str()` would yield). Spans land on char
    /// boundaries: the ASCII engine only ever sees all-boundary ASCII
    /// haystacks, and the Unicode engine's non-empty matches cover whole
    /// codepoints with `utf8_empty(true)` positioning empty matches like the
    /// `regex` crate does.
    pub(crate) fn find_str<'v>(&self, haystack: &'v str) -> Option<&'v str> {
        if haystack.len() < self.min_len {
            return None;
        }
        let engine = self.engine_for(haystack)?;
        let engine = engine.get();
        super::regex_scratch::with_cache(engine.id, &engine.re, |cache| {
            engine
                .re
                .search_with(cache, &regex_automata::Input::new(haystack))
                .map(|m| &haystack[m.start()..m.end()])
        })
    }

    /// Iterate non-overlapping leftmost-first matches, invoking
    /// `f(start_offset, matched_span)`; `f` returns `false` to stop early.
    /// Iteration protocol (including empty-match advancement) matches the
    /// facade's `find_iter` — both are built on `util::iter::Searcher`.
    pub(crate) fn for_each_find<'v>(
        &self,
        haystack: &'v str,
        mut f: impl FnMut(usize, &'v str) -> bool,
    ) {
        if haystack.len() < self.min_len {
            return;
        }
        let Some(engine) = self.engine_for(haystack) else {
            return;
        };
        let engine = engine.get();
        super::regex_scratch::with_cache(engine.id, &engine.re, |cache| {
            let mut it =
                regex_automata::util::iter::Searcher::new(regex_automata::Input::new(haystack));
            loop {
                let m = it.advance(|input| Ok(engine.re.search_with(cache, input)));
                let Some(m) = m else { return };
                if !f(m.start(), &haystack[m.start()..m.end()]) {
                    return;
                }
            }
        });
    }
}

/// The ASCII-mode engine: byte-level classes (`unicode(false)`) avoid the
/// UTF-8 sub-automaton expansion entirely. Only ever searched over pure-ASCII
/// haystacks, where it is match-identical to the Unicode engine.
fn compile_ascii(pattern: &str) -> Option<regex_automata::meta::Regex> {
    regex_automata::meta::Regex::builder()
        .configure(engine_config().utf8_empty(false))
        .syntax(
            regex_automata::util::syntax::Config::new()
                .unicode(false)
                .utf8(false),
        )
        .build(pattern)
        .ok()
}

/// The Unicode engine: exact `regex::Regex::new` semantics.
fn compile_unicode(pattern: &str) -> Option<regex_automata::meta::Regex> {
    regex_automata::meta::Regex::builder()
        .configure(engine_config().utf8_empty(true))
        .build(pattern)
        .ok()
}

/// Whether `pattern` can be compiled as an ASCII-mode engine: pure-ASCII
/// source with no explicit Unicode escapes (the same gate the byte-regex path
/// uses), so pure-ASCII haystacks match identically in either mode.
fn ascii_compatible(pattern: &str) -> bool {
    pattern.is_ascii()
        && !pattern.contains("\\u")
        && !pattern.contains("\\p")
        && !pattern.contains("\\P")
}

pub(crate) fn cached_regex(pattern: &str) -> Option<Arc<TraitRegex>> {
    // Hot path: `peek` under a read lock — it doesn't bump LRU recency, so warm
    // evals never serialize on the write lock (the bytes cache learned this the
    // hard way: `get`'s &mut recency update cost ~25% CPU in lock wait).
    if let Some(arc) = REGEX_CACHE
        .read()
        .ok()
        .and_then(|c| c.peek(pattern).cloned())
    {
        return Some(arc);
    }
    // Compile outside the lock; write-lock only to insert.
    let arc = Arc::new(TraitRegex::compile(pattern)?);
    let size = arc.heap_bytes();
    if let Ok(mut cache) = REGEX_CACHE.write() {
        cache.put(pattern.to_string(), Arc::clone(&arc), size);
    }
    Some(arc)
}

/// Clear the process-global lazy regex cache (see [`cached_regex`]). Shared
/// across all threads; call from a single thread under memory pressure.
pub(crate) fn clear_cached_regex() {
    if let Ok(mut cache) = REGEX_CACHE.write() {
        cache.clear();
    }
    if let Ok(mut cache) = UNICODE_ENGINES.write() {
        cache.clear();
    }
}

/// Resolve a `regex:` pattern through [`cached_regex`], applying the `(?i)`
/// prefix for case-insensitivity. This is the **only** place the extracted-
/// string path builds a `regex::Regex`: `word:`/`substr:`/`exact:` are literal
/// matches (see [`word_match_start`]) and never touch the regex engine.
pub(crate) fn lazy_regex(regex: Option<&str>, case_insensitive: bool) -> Option<Arc<TraitRegex>> {
    let raw = regex?;
    if case_insensitive {
        cached_regex(&format!("(?i){raw}"))
    } else {
        cached_regex(raw)
    }
}

/// Raw-content matcher's regex pattern source. Serves `word:` by building
/// `\bword\b`, and enables multi-line mode (`(?m)`/`(?im)`) so `^`/`$` anchor per
/// line — matching the byte-regex path's `multi_line(true)` (see
/// `compile_bytes_regex`) so non-ASCII raw patterns honor per-line anchors
/// identically.
///
/// Returns the **pattern string** without compiling anything: the raw matcher
/// chooses the byte-vs-unicode engine from the pattern alone, so an ASCII pattern
/// (which matches via a `regex::bytes::Regex`) never pays to compile the unicode
/// `regex::Regex` it would only call `.as_str()` on — that wasted compile
/// dominated peak RSS on member-heavy archives. The unicode engine is built (via
/// [`cached_regex`]) only on the non-ASCII branch, with this exact string.
pub(crate) fn raw_regex_pattern(
    word: Option<&str>,
    regex: Option<&str>,
    case_insensitive: bool,
) -> Option<String> {
    let base = match (word, regex) {
        (Some(w), _) => format!(r"\b{}\b", regex::escape(w)),
        (None, Some(r)) => r.to_string(),
        (None, None) => return None,
    };
    Some(if case_insensitive {
        format!("(?im){base}")
    } else {
        format!("(?m){base}")
    })
}

/// Shared, lazy, leaked case-sensitive substring searcher per unique needle.
/// `memchr::memmem::Finder` (SIMD + Two-Way + prefilter) is the right tool for
/// a single needle; caching it means we build the searcher once and reuse it
/// across evals instead of rebuilding per call, with no per-condition storage.
pub(crate) fn cached_finder(needle: &str) -> &'static memchr::memmem::Finder<'static> {
    use std::sync::{LazyLock, RwLock};
    // FxHashMap: keyed by the needle string and hit on every eval; SipHash on
    // string keys showed up as a hot frame, FxHash is far cheaper.
    static CACHE: LazyLock<
        RwLock<rustc_hash::FxHashMap<String, &'static memchr::memmem::Finder<'static>>>,
    > = LazyLock::new(|| RwLock::new(rustc_hash::FxHashMap::default()));
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
        RwLock<rustc_hash::FxHashMap<String, &'static aho_corasick::AhoCorasick>>,
    > = LazyLock::new(|| RwLock::new(rustc_hash::FxHashMap::default()));
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

/// Byte offsets of every `\bneedle\b` match in raw `haystack` bytes, capped at
/// `cap`. The literal-scan equivalent of the `\bneedle\b` regex the raw content
/// matcher used to compile — memmem (or ASCII-case-insensitive Aho-Corasick) for
/// the literal, then the same `\b` boundary rule (`word_boundary_ok`), so it
/// matches what the regex did without building a regex engine. `\bword\b` matches
/// can't overlap (they're bounded by non-word bytes), so the offsets are the same
/// set the regex's `find_iter` would yield.
#[must_use]
pub(crate) fn raw_word_match_offsets(
    haystack: &[u8],
    needle: &str,
    case_insensitive: bool,
    cap: usize,
) -> Vec<usize> {
    let nb = needle.as_bytes();
    let mut out = Vec::new();
    if nb.is_empty() || nb.len() > haystack.len() {
        return out;
    }
    if case_insensitive {
        let Some(ac) = cached_ci_searcher(needle) else {
            return out;
        };
        for m in ac.find_iter(haystack) {
            if word_boundary_ok(haystack, nb, m.start(), m.end()) {
                out.push(m.start());
                if out.len() >= cap {
                    break;
                }
            }
        }
    } else {
        let finder = cached_finder(needle);
        let mut from = 0;
        while let Some(rel) = finder.find(&haystack[from..]) {
            let start = from + rel;
            if word_boundary_ok(haystack, nb, start, start + nb.len()) {
                out.push(start);
                if out.len() >= cap {
                    break;
                }
            }
            from = start + 1;
        }
    }
    out
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
    /// Require match to contain a structurally valid IPv4 address of any
    /// range, including private/loopback/link-local. Use this to confirm an
    /// IP literal of any kind without the external/C2-quality filtering that
    /// `ExternalIp` applies.
    ValidIp,
    /// Require match to contain a valid Bitcoin address (with checksum)
    #[serde(rename = "bitcoin_addr")]
    BitcoinAddr,
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
        /// Multi-argument filter (kind=call only). Every filter must be
        /// satisfied by a **distinct** arg of the call — for matching a
        /// specific multi-positional shape like `File.rename("a.png",
        /// "b.exe")` via `args: [{kind: string, regex: '\.png$'}, {kind:
        /// string, regex: '\.exe$'}]`. Combined (AND) with `arg` if both set.
        #[serde(default)]
        args: Option<Vec<ArgFilter>>,
        /// Import-alias filter (kind=import only). Matches the local alias of
        /// an aliased import (`import subprocess as sp`). Present → only
        /// aliased imports match.
        #[serde(default)]
        alias: Option<AliasFilter>,
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
        /// Byte-length bounds on the regex match span; requires `regex:`.
        #[serde(default)]
        length_min: Option<usize>,
        #[serde(default)]
        length_max: Option<usize>,
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
    /// Match against source-code comment bodies only (the dedicated
    /// `report.comments` corpus). Lowest false positives for "keyword
    /// mentioned in a comment" rules — never fires on the same keyword
    /// in code or a string literal. Replaces tree-sitter
    /// `kind: comment` queries.
    Comment {
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
        /// Byte-length bounds on the regex match span; requires `regex:`.
        #[serde(default)]
        length_min: Option<usize>,
        #[serde(default)]
        length_max: Option<usize>,
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

    /// Match the file path (full path by default; `basename`/`dirname` scope it).
    Path {
        #[serde(default)]
        exact: Option<String>,
        #[serde(default)]
        substr: Option<String>,
        #[serde(default)]
        regex: Option<String>,
        #[serde(default)]
        case_insensitive: bool,
        #[serde(rename = "is", default)]
        is_check: Option<StringValidator>,
        #[serde(default)]
        basename: bool,
        #[serde(default)]
        dirname: bool,
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
    /// Example: { type: value, path: "maintainers", length_min: 1, length_max: 1 }
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
        /// Quantifier for `eq`/`ne` when a side resolves to multiple values:
        /// `any` (default) or `all`. Disambiguates `ne: arr[*]`.
        #[serde(
            rename = "match",
            default,
            skip_serializing_if = "ArrayQuantifier::is_default"
        )]
        match_mode: ArrayQuantifier,
        /// Case insensitive matching (default: false)
        #[serde(default)]
        case_insensitive: bool,
        /// Explicit existence check (true = must exist, false = must not exist)
        #[serde(skip_serializing_if = "Option::is_none")]
        exists: Option<bool>,
        /// Minimum len() of the value: string bytes, array elements, or
        /// object keys. `size_min` is the deprecated spelling.
        #[serde(alias = "size_min", skip_serializing_if = "Option::is_none")]
        length_min: Option<usize>,
        /// Maximum len() of the value (see `length_min`). `size_max` is the
        /// deprecated spelling.
        #[serde(alias = "size_max", skip_serializing_if = "Option::is_none")]
        length_max: Option<usize>,
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
                    args,
                    alias,
                    not,
                } => Condition::Symbol(SymbolQuery {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    kind,
                    arg,
                    args,
                    alias,
                    not,
                }),
                ConditionTagged::Import {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    not,
                } => Condition::Symbol(SymbolQuery {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    kind: Some(SymbolKind::Import),
                    arg: None,
                    args: None,
                    alias: None,
                    not,
                }),
                ConditionTagged::Export {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    not,
                } => Condition::Symbol(SymbolQuery {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    kind: Some(SymbolKind::Export),
                    arg: None,
                    args: None,
                    alias: None,
                    not,
                }),
                ConditionTagged::Function {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    not,
                } => Condition::Symbol(SymbolQuery {
                    exact,
                    substr,
                    regex,
                    platforms,
                    is_check,
                    kind: Some(SymbolKind::Function),
                    arg: None,
                    args: None,
                    alias: None,
                    not,
                }),
                ConditionTagged::Text {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    length_min,
                    length_max,
                    is_check,
                    not,
                    platforms,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                } => Condition::Text(TextQuery {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    length_min,
                    length_max,
                    is_check,
                    not,
                    platforms,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                }),
                ConditionTagged::Comment {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    is_check,
                    not,
                    platforms,
                } => Condition::Comment(CommentQuery {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    is_check,
                    not,
                    platforms,
                }),
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
                } => Condition::Literal(LiteralQuery {
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
                }),
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
                } => Condition::TreeSitter(TreeSitterQuery {
                    kind,
                    node,
                    exact,
                    substr,
                    regex,
                    query,
                    language,
                    case_insensitive,
                }),
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
                } => Condition::Metrics(MetricsQuery {
                    field,
                    min,
                    max,
                    min_size,
                    max_size,
                }),
                ConditionTagged::Hex {
                    pattern,
                    not,
                    offset,
                    offset_range,
                    section,
                    section_offset,
                    section_offset_range,
                } => Condition::Hex(HexQuery {
                    pattern,
                    not,
                    offset,
                    offset_range,
                    section,
                    section_offset,
                    section_offset_range,
                }),
                ConditionTagged::Raw {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    length_min,
                    length_max,
                    is_check,
                    not,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                } => Condition::Raw(RawQuery {
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                    length_min,
                    length_max,
                    is_check,
                    not,
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                }),
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
                } => Condition::Section(SectionQuery {
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
                }),
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
                } => Condition::Encoded(EncodedQuery {
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
                }),
                // `type: basename` is sugar for a filename-scoped path matcher.
                ConditionTagged::Basename {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                    is_check,
                } => Condition::Path(PathQuery {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                    is_check,
                    basename: true,
                    dirname: false,
                }),
                ConditionTagged::Path {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                    is_check,
                    basename,
                    dirname,
                } => Condition::Path(PathQuery {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                    is_check,
                    basename,
                    dirname,
                }),
                ConditionTagged::Kv {
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
                } => Condition::Kv(KvQuery {
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
                }),
            },
        }
    }
}

impl From<Condition> for ConditionTagged {
    fn from(cond: Condition) -> Self {
        match cond {
            Condition::Symbol(SymbolQuery {
                exact,
                substr,
                regex,
                platforms,
                is_check,
                kind,
                arg,
                args,
                alias,
                not,
            }) => ConditionTagged::Symbol {
                exact,
                substr,
                regex,
                platforms,
                is_check,
                kind,
                arg,
                args,
                alias,
                not,
            },
            Condition::Text(TextQuery {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                length_min,
                length_max,
                is_check,
                not,
                platforms,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            }) => ConditionTagged::Text {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                length_min,
                length_max,
                is_check,
                not,
                platforms,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            },
            Condition::Comment(CommentQuery {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not,
                platforms,
            }) => ConditionTagged::Comment {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not,
                platforms,
            },
            Condition::Literal(LiteralQuery {
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
            }) => ConditionTagged::Literal {
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
            Condition::TreeSitter(TreeSitterQuery {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                language,
                case_insensitive,
            }) => ConditionTagged::TreeSitter {
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
            Condition::Metrics(MetricsQuery {
                field,
                min,
                max,
                min_size,
                max_size,
            }) => ConditionTagged::Metrics {
                field,
                min,
                max,
                min_size,
                max_size,
            },
            Condition::Hex(HexQuery {
                pattern,
                not,
                offset,
                offset_range,
                section,
                section_offset,
                section_offset_range,
            }) => ConditionTagged::Hex {
                pattern,
                not,
                offset,
                offset_range,
                section,
                section_offset,
                section_offset_range,
            },
            Condition::Raw(RawQuery {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                length_min,
                length_max,
                is_check,
                not,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            }) => ConditionTagged::Raw {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                length_min,
                length_max,
                is_check,
                not,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            },
            Condition::Section(SectionQuery {
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
            }) => ConditionTagged::Section {
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
            Condition::Encoded(EncodedQuery {
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
            }) => ConditionTagged::Encoded {
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
            Condition::Path(PathQuery {
                exact,
                substr,
                regex,
                case_insensitive,
                is_check,
                basename,
                dirname,
            }) => ConditionTagged::Path {
                exact,
                substr,
                regex,
                case_insensitive,
                is_check,
                basename,
                dirname,
            },
            Condition::Kv(KvQuery {
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
            }) => ConditionTagged::Kv {
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
#[derive(Debug, Clone, Default)]
pub(crate) struct KvQuery {
    /// Path to navigate using dot notation, `[n]` for indices, `[*]` for
    /// wildcards. Accepts an optional `<filename>::` prefix to reference a
    /// sibling file's values within the same archive scope.
    pub path: String,
    /// Value/element equals exactly.
    pub exact: Option<String>,
    /// Value/element contains substring.
    pub substr: Option<String>,
    /// Value/element matches regex pattern.
    pub regex: Option<String>,
    /// Right-hand-side value path for cross-fact equality (case-insensitive,
    /// whitespace-trimmed). Accepts a `<filename>::` sibling prefix.
    pub eq: Option<String>,
    /// Right-hand-side value path for cross-fact inequality.
    pub ne: Option<String>,
    /// Quantifier when `eq`/`ne` resolves to multiple values (`any`/`all`).
    pub match_mode: ArrayQuantifier,
    /// Case insensitive matching (default: false).
    pub case_insensitive: bool,
    /// Explicit existence check (true = must exist, false = must not exist).
    pub exists: Option<bool>,
    /// Minimum len() of the value: string bytes, array elements, or object keys.
    pub length_min: Option<usize>,
    /// Maximum len() of the value (see `length_min`).
    pub length_max: Option<usize>,
}

/// Payload for `type: text` — byte-scan over extracted strings / raw source text.
#[derive(Debug, Clone, Default)]
pub(crate) struct TextQuery {
    pub exact: Option<String>,
    pub substr: Option<String>,
    pub regex: Option<String>,
    pub word: Option<String>,
    pub case_insensitive: bool,
    /// Byte-length bounds on the regex match span; requires `regex:`.
    /// The cheap way to say "a run of at least N": pair a greedy loop with
    /// `length_min` instead of a counted repetition (`{4000,}`), which
    /// unrolls into one NFA state per rep. Keep a small counted floor for
    /// selectivity (`[A-Za-z0-9]{64,}` + `length_min: 4000`) so the scan
    /// isn't spent visiting every short run on match-dense content.
    pub length_min: Option<usize>,
    pub length_max: Option<usize>,
    pub is_check: Option<StringValidator>,
    pub not: Option<Vec<NotException>>,
    pub platforms: Option<Vec<Platform>>,
    pub section: Option<String>,
    pub offset: Option<i64>,
    pub offset_range: Option<(i64, Option<i64>)>,
    pub section_offset: Option<i64>,
    pub section_offset_range: Option<(i64, Option<i64>)>,
}

/// Payload for `type: raw` — substring/regex over the full raw file bytes.
#[derive(Debug, Clone, Default)]
pub(crate) struct RawQuery {
    pub exact: Option<String>,
    pub substr: Option<String>,
    pub regex: Option<String>,
    pub word: Option<String>,
    pub case_insensitive: bool,
    /// Byte-length bounds on the regex match span; requires `regex:` (see
    /// [`TextQuery::length_min`]).
    pub length_min: Option<usize>,
    pub length_max: Option<usize>,
    pub is_check: Option<StringValidator>,
    pub not: Option<Vec<NotException>>,
    pub section: Option<String>,
    pub offset: Option<i64>,
    pub offset_range: Option<(i64, Option<i64>)>,
    pub section_offset: Option<i64>,
    pub section_offset_range: Option<(i64, Option<i64>)>,
}

/// Payload for `type: encoded` — matches across decoded-string layers.
#[derive(Debug, Clone, Default)]
pub(crate) struct EncodedQuery {
    pub encoding: Option<EncodingSpec>,
    pub exact: Option<String>,
    pub substr: Option<String>,
    pub regex: Option<String>,
    pub word: Option<String>,
    pub case_insensitive: bool,
    pub is_check: Option<StringValidator>,
    pub not: Option<Vec<NotException>>,
    pub section: Option<String>,
    pub offset: Option<i64>,
    pub offset_range: Option<(i64, Option<i64>)>,
    pub section_offset: Option<i64>,
    pub section_offset_range: Option<(i64, Option<i64>)>,
}

/// Payload for `type: section` — binary section name/size/entropy/permission match.
#[derive(Debug, Clone, Default)]
pub(crate) struct SectionQuery {
    pub exact: Option<String>,
    pub substr: Option<String>,
    pub regex: Option<String>,
    pub word: Option<String>,
    pub case_insensitive: bool,
    pub length_min: Option<u64>,
    pub length_max: Option<u64>,
    pub entropy_min: Option<f64>,
    pub entropy_max: Option<f64>,
    pub readable: Option<bool>,
    pub writable: Option<bool>,
    pub executable: Option<bool>,
    pub compare_to: Option<String>,
    pub size_ratio_min: Option<f64>,
    pub size_ratio_max: Option<f64>,
    pub entropy_ratio_min: Option<f64>,
    pub entropy_ratio_max: Option<f64>,
}

/// Payload for `type: symbol` — imports/exports/functions/calls.
#[derive(Debug, Clone, Default)]
pub(crate) struct SymbolQuery {
    pub exact: Option<String>,
    pub substr: Option<String>,
    pub regex: Option<String>,
    pub platforms: Option<Vec<Platform>>,
    pub is_check: Option<StringValidator>,
    pub kind: Option<SymbolKind>,
    pub arg: Option<ArgFilter>,
    pub args: Option<Vec<ArgFilter>>,
    pub alias: Option<AliasFilter>,
    pub not: Option<Vec<NotException>>,
}

/// Payload for `type: comment` — source comment-body matches.
#[derive(Debug, Clone, Default)]
pub(crate) struct CommentQuery {
    pub exact: Option<String>,
    pub substr: Option<String>,
    pub regex: Option<String>,
    pub word: Option<String>,
    pub case_insensitive: bool,
    pub is_check: Option<StringValidator>,
    pub not: Option<Vec<NotException>>,
    pub platforms: Option<Vec<Platform>>,
}

/// Payload for `type: literal` — parser-extracted string/number literals.
#[derive(Debug, Clone, Default)]
pub(crate) struct LiteralQuery {
    pub kind: Option<String>,
    pub exact: Option<String>,
    pub substr: Option<String>,
    pub regex: Option<String>,
    pub word: Option<String>,
    pub value: Option<i64>,
    pub radix: Option<u32>,
    pub case_insensitive: bool,
    pub is_check: Option<StringValidator>,
    pub not: Option<Vec<NotException>>,
    pub platforms: Option<Vec<Platform>>,
    pub section: Option<String>,
    pub offset: Option<i64>,
    pub offset_range: Option<(i64, Option<i64>)>,
    pub section_offset: Option<i64>,
    pub section_offset_range: Option<(i64, Option<i64>)>,
}

/// Payload for `type: tree-sitter` — live tree-sitter query escape hatch.
#[derive(Debug, Clone, Default)]
pub(crate) struct TreeSitterQuery {
    pub kind: Option<String>,
    pub node: Option<String>,
    pub exact: Option<String>,
    pub substr: Option<String>,
    pub regex: Option<String>,
    pub query: Option<String>,
    pub language: Option<String>,
    pub case_insensitive: bool,
}

/// Payload for `type: hex` — byte-pattern match with wildcards/gaps.
#[derive(Debug, Clone, Default)]
pub(crate) struct HexQuery {
    pub pattern: String,
    pub not: Option<Vec<NotException>>,
    pub offset: Option<i64>,
    pub offset_range: Option<(i64, Option<i64>)>,
    pub section: Option<String>,
    pub section_offset: Option<i64>,
    pub section_offset_range: Option<(i64, Option<i64>)>,
}

/// Payload for `type: path` — file path / basename / dirname match.
#[derive(Debug, Clone, Default)]
pub(crate) struct PathQuery {
    pub exact: Option<String>,
    pub substr: Option<String>,
    pub regex: Option<String>,
    pub case_insensitive: bool,
    pub is_check: Option<StringValidator>,
    pub basename: bool,
    pub dirname: bool,
}

/// Payload for `type: metrics` — computed metric threshold check.
#[derive(Debug, Clone, Default)]
pub(crate) struct MetricsQuery {
    pub field: String,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
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
            Condition::Section(SectionQuery { .. }) => is_binary,

            // AST-backed searches require source code support
            Condition::TreeSitter(TreeSitterQuery { .. })
            | Condition::Literal(LiteralQuery { .. }) => file_type.supports_ast_queries(),

            // All other conditions can potentially match any file type
            _ => true,
        }
    }

    /// Returns a description of the condition type for error messages
    #[must_use]
    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Condition::Symbol(SymbolQuery { .. }) => "symbol",
            Condition::Text(TextQuery { .. }) => "text",
            Condition::Comment(CommentQuery { .. }) => "comment",
            Condition::Literal(LiteralQuery { .. }) => "string_literal",
            Condition::Trait { .. } => "trait",
            Condition::TreeSitter(TreeSitterQuery { .. }) => "tree-sitter",
            Condition::Yara { .. } => "yara",
            Condition::Syscall { .. } => "syscall",
            Condition::Metrics(MetricsQuery { .. }) => "metrics",
            Condition::Hex(HexQuery { .. }) => "hex",
            Condition::Raw(RawQuery { .. }) => "raw",
            Condition::Section(SectionQuery { .. }) => "section",
            Condition::Encoded(EncodedQuery { .. }) => "encoded",
            Condition::Path(PathQuery {
                basename, dirname, ..
            }) => {
                if *basename {
                    "basename"
                } else if *dirname {
                    "dirname"
                } else {
                    "path"
                }
            }
            Condition::Kv(KvQuery { .. }) => "value",
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
            Condition::TreeSitter(TreeSitterQuery {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                language,
                ..
            }) => {
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
            Condition::Kv(KvQuery {
                path,
                exact,
                substr,
                regex,
                ..
            }) => {
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
            Condition::Text(TextQuery {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            }) => validate_location_constraints(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
                "text",
            ),
            Condition::Literal(LiteralQuery {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            }) => validate_location_constraints(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
                "string_literal",
            ),
            Condition::Raw(RawQuery {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            }) => validate_location_constraints(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
                "content",
            ),
            Condition::Hex(HexQuery {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            }) => {
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
            Condition::Text(TextQuery { regex: Some(r), .. })
            | Condition::Raw(RawQuery { regex: Some(r), .. })
            | Condition::TreeSitter(TreeSitterQuery { regex: Some(r), .. }) => Some(r.as_str()),
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
            Condition::Text(TextQuery { regex: Some(r), .. })
            | Condition::Literal(LiteralQuery { regex: Some(r), .. })
            | Condition::Raw(RawQuery { regex: Some(r), .. }) => Some(r.as_str()),
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
            Condition::Text(TextQuery {
                exact: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Literal(LiteralQuery {
                exact: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Raw(RawQuery {
                exact: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::TreeSitter(TreeSitterQuery {
                exact: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Text(TextQuery {
                substr: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Literal(LiteralQuery {
                substr: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Raw(RawQuery {
                substr: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::TreeSitter(TreeSitterQuery {
                substr: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Text(TextQuery {
                word: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Literal(LiteralQuery {
                word: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Raw(RawQuery {
                word: Some(s),
                case_insensitive: true,
                ..
            }) => check_pattern(s),
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
            Condition::Text(TextQuery { exact: Some(s), .. })
            | Condition::Literal(LiteralQuery { exact: Some(s), .. })
            | Condition::Raw(RawQuery { exact: Some(s), .. })
            | Condition::Symbol(SymbolQuery { exact: Some(s), .. }) => check_empty(s, "exact"),
            Condition::Text(TextQuery {
                substr: Some(s), ..
            })
            | Condition::Literal(LiteralQuery {
                substr: Some(s), ..
            })
            | Condition::Raw(RawQuery {
                substr: Some(s), ..
            })
            | Condition::Symbol(SymbolQuery {
                substr: Some(s), ..
            }) => check_empty(s, "substr"),
            Condition::Text(TextQuery { regex: Some(s), .. })
            | Condition::Literal(LiteralQuery { regex: Some(s), .. })
            | Condition::Raw(RawQuery { regex: Some(s), .. })
            | Condition::Symbol(SymbolQuery { regex: Some(s), .. }) => check_empty(s, "regex"),
            Condition::Text(TextQuery { word: Some(s), .. })
            | Condition::Literal(LiteralQuery { word: Some(s), .. })
            | Condition::Raw(RawQuery { word: Some(s), .. }) => check_empty(s, "word"),
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
            Condition::Text(TextQuery {
                exact: Some(s),
                case_insensitive: false,
                ..
            })
            | Condition::Literal(LiteralQuery {
                exact: Some(s),
                case_insensitive: false,
                ..
            })
            | Condition::Symbol(SymbolQuery { exact: Some(s), .. }) => {
                if s.len() == 1 {
                    return Some(format!(
                        "exact: pattern '{}' is a single character and will rarely be useful - consider if this is intentional",
                        s
                    ));
                }
                None
            }
            // For substr, warn if less than 3 characters (more prone to false positives)
            Condition::Text(TextQuery {
                substr: Some(s),
                case_insensitive: false,
                ..
            })
            | Condition::Literal(LiteralQuery {
                substr: Some(s),
                case_insensitive: false,
                ..
            })
            | Condition::Symbol(SymbolQuery {
                substr: Some(s), ..
            }) => check_short(s, "substr", 3),
            // For word, warn if less than 2 characters
            Condition::Text(TextQuery {
                word: Some(s),
                case_insensitive: false,
                ..
            })
            | Condition::Literal(LiteralQuery {
                word: Some(s),
                case_insensitive: false,
                ..
            }) => check_short(s, "word", 2),
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
            Condition::Text(TextQuery { regex: Some(r), .. })
            | Condition::Literal(LiteralQuery { regex: Some(r), .. })
            | Condition::Raw(RawQuery { regex: Some(r), .. })
            | Condition::Symbol(SymbolQuery { regex: Some(r), .. }) => {
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
            Condition::Text(TextQuery {
                exact: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Literal(LiteralQuery {
                exact: Some(s),
                case_insensitive: true,
                ..
            }) => check_pattern(s, "exact"),
            Condition::Text(TextQuery {
                substr: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Literal(LiteralQuery {
                substr: Some(s),
                case_insensitive: true,
                ..
            }) => check_pattern(s, "substr"),
            Condition::Text(TextQuery {
                word: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Literal(LiteralQuery {
                word: Some(s),
                case_insensitive: true,
                ..
            }) => check_pattern(s, "word"),
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
            Condition::Symbol(SymbolQuery { regex: Some(r), .. }) => r.as_str(),
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
            Condition::Text(TextQuery {
                exact,
                substr,
                regex,
                word,
                ..
            })
            | Condition::Literal(LiteralQuery {
                exact,
                substr,
                regex,
                word,
                ..
            })
            | Condition::Raw(RawQuery {
                exact,
                substr,
                regex,
                word,
                ..
            }) => check_exclusive(
                exact.is_some(),
                substr.is_some(),
                regex.is_some(),
                word.is_some(),
            ),
            Condition::Symbol(SymbolQuery {
                exact,
                substr,
                regex,
                ..
            })
            | Condition::TreeSitter(TreeSitterQuery {
                exact,
                substr,
                regex,
                ..
            }) => check_exclusive(exact.is_some(), substr.is_some(), regex.is_some(), false),
            _ => None,
        }
    }

    /// Pre-compile regexes in this condition for performance.
    /// Should be called once after deserialization.
    /// Returns an error if any regex pattern is invalid.
    pub(crate) fn precompile_regexes(&mut self) -> anyhow::Result<()> {
        match self {
            Condition::Symbol(SymbolQuery {
                regex: Some(regex_pattern),
                ..
            }) => {
                // Validate only — the compiled regex is resolved lazily and shared
                // process-wide at eval time (see `cached_regex`), so it isn't stored
                // per condition. Compile here purely to surface invalid patterns.
                regex::Regex::new(regex_pattern).map_err(|e| {
                    anyhow::anyhow!("Failed to compile symbol regex '{}': {}", regex_pattern, e)
                })?;
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
            Condition::Text(TextQuery { .. }) | Condition::Literal(LiteralQuery { .. }) => {}
            // Validate only (see Symbol arm). `(?i)` doesn't affect parse
            // validity, so the raw pattern is sufficient to catch errors; eval
            // applies case-insensitivity via `lazy_regex`.
            Condition::Kv(KvQuery {
                regex: Some(regex_pattern),
                ..
            }) => {
                regex::Regex::new(regex_pattern).map_err(|e| {
                    anyhow::anyhow!("Failed to compile value regex '{}': {}", regex_pattern, e)
                })?;
            }
            Condition::Path(PathQuery {
                regex: Some(regex_pattern),
                ..
            }) => {
                regex::Regex::new(regex_pattern).map_err(|e| {
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
        let condition = Condition::Text(TextQuery {
            length_min: None,
            length_max: None,
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
        });
        assert!(condition.validate(true).is_err());
    }

    #[test]
    fn test_condition_validate_content_location() {
        // Valid content condition with section constraint
        let condition = Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
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
        });
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
    fn kv_length_bounds_accept_both_spellings() {
        // Canonical `length_min`/`length_max` and the deprecated `size_min`/
        // `size_max` aliases parse to the same fields.
        for yaml in [
            "type: value\npath: maintainers\nlength_min: 2\nlength_max: 5",
            "type: value\npath: maintainers\nsize_min: 2\nsize_max: 5",
        ] {
            let result: Result<Condition, _> = serde_yaml::from_str(yaml);
            assert!(result.is_ok(), "failed to parse: {yaml}");
            assert!(matches!(
                result.unwrap(),
                Condition::Kv(KvQuery {
                    length_min: Some(2),
                    length_max: Some(5),
                    ..
                })
            ));
        }
    }

    #[test]
    fn text_length_bounds_parse() {
        let result: Result<Condition, _> =
            serde_yaml::from_str("type: text\nregex: '[A-Za-z0-9]+'\nlength_min: 4000");
        assert!(result.is_ok());
        assert!(matches!(
            result.unwrap(),
            Condition::Text(TextQuery {
                length_min: Some(4000),
                length_max: None,
                ..
            })
        ));
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
    use crate::composite_rules::condition::SymbolKind;
    use crate::composite_rules::{Condition, KvQuery, LiteralQuery, PathQuery, SymbolQuery};

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
        let cond = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: "debug.pdb_path".to_string(),
            exact: None,
            substr: None,
            regex: Some(r"(?i)PQT_Downloader[\\/].*[\\/]PQT_Downloader\.pdb$".to_string()),
            eq: None,
            ne: None,
            case_insensitive: false,
            exists: None,
            length_min: None,
            length_max: None,
        });
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
            Condition::Symbol(SymbolQuery {
                kind: Some(SymbolKind::Import),
                regex: Some(ref r),
                ..
            }) if r == "^CreateFileW$"
        ));
        assert!(matches!(
            export_cond,
            Condition::Symbol(SymbolQuery {
                kind: Some(SymbolKind::Export),
                substr: Some(ref s),
                ..
            }) if s == "DllRegisterServer"
        ));
        assert!(matches!(
            function_cond,
            Condition::Symbol(SymbolQuery {
                kind: Some(SymbolKind::Function),
                exact: Some(ref s),
                ..
            }) if s == "main"
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
            Condition::Kv(KvQuery {
                exact: Some(ref s),
                ..
            }) if s == "curl"
        ));
        assert!(matches!(
            legacy,
            Condition::Kv(KvQuery {
                exact: Some(ref s),
                ..
            }) if s == "curl"
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
        assert!(matches!(new_form, Condition::Literal(LiteralQuery { .. })));
        assert!(matches!(old_form, Condition::Literal(LiteralQuery { .. })));
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
            value: ("511".to_string()).into(),
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
        assert!(matches!(cond, Condition::Literal(LiteralQuery { .. })));
        if let Condition::Literal(LiteralQuery {
            kind, value, radix, ..
        }) = cond
        {
            assert_eq!(kind.as_deref(), Some("number"));
            assert_eq!(value, Some(511));
            assert_eq!(radix, Some(8));
        }
    }

    #[test]
    fn greedy_pattern_lint_skips_string_literal_regex() {
        let cond = Condition::Literal(LiteralQuery {
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
        });
        assert!(cond.check_greedy_patterns().is_none());
    }

    #[test]
    fn greedy_pattern_lint_skips_symbol_regex() {
        let cond = Condition::Symbol(SymbolQuery {
            exact: None,
            substr: None,
            regex: Some(r"^libc\.so(\.[0-9]+)*$".to_string()),
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
        });
        assert!(cond.check_greedy_patterns().is_none());
    }

    #[test]
    fn greedy_pattern_lint_skips_basename_regex() {
        let cond = Condition::Path(PathQuery {
            exact: None,
            substr: None,
            regex: Some(r"^ssh(d|-.+)?$".to_string()),
            case_insensitive: false,
            is_check: None,
            basename: true,
            dirname: false,
        });
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

    /// `raw_word_match_offsets` (the raw-content `word:` scan) must return the
    /// SAME match offsets the `\bneedle\b` regex `find_iter` yields — this is the
    /// parity the byte-scan replacement of the compiled raw regex relies on.
    #[allow(clippy::expect_used)]
    fn assert_raw_word_offsets_match_regex(haystack: &str, needle: &str, ci: bool) {
        let pat = format!(r"\b{}\b", regex::escape(needle));
        let re = regex::RegexBuilder::new(&pat)
            .case_insensitive(ci)
            .build()
            .expect("valid regex");
        let want: Vec<usize> = re.find_iter(haystack).map(|m| m.start()).collect();
        let got = super::raw_word_match_offsets(haystack.as_bytes(), needle, ci, 4096);
        assert_eq!(
            want, got,
            "needle={needle:?} ci={ci} haystack={haystack:?}: regex={want:?} scan={got:?}"
        );
    }

    #[test]
    fn raw_word_offsets_agree_with_regex_find_iter() {
        let cases = [
            ("zsh ~/.zshrc and /etc/zshrc plus zshrc.bak", "zshrc"),
            ("zshrcbak myzshrc nope", "zshrc"), // both have a word-char neighbour → no match
            ("eval eval eval", "eval"),         // repeated, non-overlapping
            ("(eval) [eval] {eval}", "eval"),   // punctuation neighbours
            ("a.eval.b eval", "eval"),
            ("ñeval evalé", "eval"), // non-ASCII letter neighbours → no match
            ("no hits here", "eval"),
        ];
        for (h, n) in cases {
            assert_raw_word_offsets_match_regex(h, n, false);
            assert_raw_word_offsets_match_regex(h, n, true);
        }
        // case-insensitive: content case varies, boundaries still hold
        assert_raw_word_offsets_match_regex("ZSHRC zshrc ZsHrC", "zshrc", true);
    }

    #[test]
    fn raw_word_offsets_respect_cap() {
        let hay = "x ".repeat(10); // 10 word-`x` occurrences, all boundary-valid
        let got = super::raw_word_match_offsets(hay.as_bytes(), "x", false, 3);
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn word_match_empty_needle_never_matches() {
        assert_eq!(super::word_match_start("anything", "", false), None);
    }

    /// Haystack-dispatched engines: ASCII haystacks use the small ASCII-mode
    /// engine; non-ASCII haystacks get exact `regex::Regex` Unicode semantics
    /// from the lazily-built Unicode engine.
    #[test]
    fn trait_regex_engine_dispatch() {
        // Unicode semantics preserved on non-ASCII haystacks (lazy engine).
        let re = super::TraitRegex::compile(r"user\w+").unwrap();
        assert_eq!(re.find_str("userñx"), Some("userñx"));
        assert_eq!(re.find_str("userabc"), Some("userabc"));
        let re = super::TraitRegex::compile(r"a.b").unwrap();
        assert_eq!(re.find_str("aéb"), Some("aéb"));
        assert_eq!(re.find_str("axb"), Some("axb"));
        let re = super::TraitRegex::compile(r#"x[^"]+y"#).unwrap();
        assert_eq!(re.find_str("xéñy"), Some("xéñy"));
        // ASCII-haystack parity across a semantics-sensitive pattern zoo:
        // both engines must agree exactly on pure-ASCII input.
        for pat in [
            r"user\w+",
            r"[\w .-]{3,}",
            r"a.b",
            r#"x[^"]+y"#,
            r"q[\s\S]{2}r",
            r"(?i)PoWeR\s+shell",
            r"\btoken\b",
            r"^start.*end$",
        ] {
            let re = super::TraitRegex::compile(pat).unwrap();
            let uni = super::compile_unicode(pat).unwrap();
            let mut cache = uni.create_cache();
            for hay in ["user_x a b-c 4", "x'y start token end", "POWER  SHELL", ""] {
                let ascii_hit = re.find_str(hay);
                let uni_hit = uni
                    .search_with(&mut cache, &regex_automata::Input::new(hay))
                    .map(|m| &hay[m.start()..m.end()]);
                assert_eq!(ascii_hit, uni_hit, "pattern {pat:?} on {hay:?}");
            }
        }
        // Non-ASCII pattern source: no ASCII engine, Unicode eager.
        let re = super::TraitRegex::compile(r"ñ\w+").unwrap();
        assert!(re.is_match("ñé"));
        // min_len is engine-independent.
        let re = super::TraitRegex::compile(r"abc\w{2}").unwrap();
        assert_eq!(re.min_len, 5);
        assert!(!re.is_match("abcd"));
    }
}
