//! Compiled trait regexes, word matching and their process-wide caches.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

impl Engine {
    pub(super) fn new(re: regex_automata::meta::Regex) -> Engine {
        Engine {
            re,
            id: super::super::regex_scratch::next_regex_id(),
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // The scratch pool keys parked caches by this id; once the engine is
        // gone nothing can take them again, so return their bytes now rather
        // than at the next pressure-driven `clear_parked`.
        super::super::regex_scratch::forget(self.id);
    }
}

/// A compiled trait regex, held as a **single byte-searching engine**.
///
/// `regex_automata` always searches bytes; `unicode` is a parse-time flag, not
/// a second implementation. So one engine serves every haystack and there is no
/// per-search dispatch — [`Self::compile`] picks the syntax config once.
///
/// Byte semantics are the default, matching YARA (yara-x parses every rule with
/// `unicode(false).utf8(false)`): the automata skip UTF-8 sub-automaton
/// expansion, which made Unicode NFAs 5-10x larger and dominated peak RSS. The
/// cost is that `\w`, `.`, `\s` and `\b` are ASCII-only against non-ASCII
/// content — a deliberate trade, and the one YARA rules have
/// always lived with.
#[derive(Debug)]
pub(crate) struct TraitRegex {
    /// The one compiled engine, byte-searching in either syntax mode.
    pub(super) engine: Engine,
    /// The source pattern, kept for diagnostics (`as_str` parity).
    pub(super) pattern: Box<str>,
    /// Minimum haystack length that can possibly match — shorter inputs
    /// return without touching the scratch pool, mirroring the facade's
    /// `is_impossible` pre-check (which it performs before its own pool
    /// access; most candidate strings are shorter than most patterns'
    /// literals, so this skips the majority of pool roundtrips). A property
    /// of the pattern, identical for both engines.
    pub(super) min_len: usize,
}

/// Shared meta-engine options: no onepass DFA (capture extraction only —
/// trait evaluation is bounds-only), implicit-only capture states (smaller
/// NFAs), the shared `REGEX_SIZE_LIMIT`, and the tunable lazy-DFA budget.
pub(super) fn engine_config() -> regex_automata::meta::Config {
    regex_automata::meta::Regex::config()
        .onepass(false)
        // No fully compiled DFA: see `compile_bytes_regex` for the
        // regex-automata 0.4.18 missed-match bug it triggers.
        .dfa(false)
        .which_captures(regex_automata::nfa::thompson::WhichCaptures::Implicit)
        .nfa_size_limit(Some(super::super::evaluators::REGEX_SIZE_LIMIT))
        .hybrid_cache_capacity(super::super::evaluators::REGEX_DFA_CACHE_BYTES)
}

impl TraitRegex {
    /// Compile `pattern` into one byte-searching engine.
    ///
    /// Byte semantics first: those automata are far smaller, and non-ASCII
    /// literals still work because `unicode(false)` compiles them to their
    /// UTF-8 bytes. `unicode(true)` is the fallback for the patterns that
    /// genuinely need codepoint semantics — `\p{..}` classes and non-ASCII
    /// ranges, which fail to parse in byte mode — and it also yields a
    /// byte-searching engine, so nothing downstream changes.
    pub(super) fn compile(pattern: &str) -> Option<TraitRegex> {
        let min_len = regex_syntax::parse(pattern)
            .ok()?
            .properties()
            .minimum_len()
            .unwrap_or(0);
        // Non-ASCII patterns keep codepoint semantics. Byte mode matches their
        // literals fine (they compile to UTF-8 bytes) but silently stops folding
        // their case under `(?i)`, and the corpus relies on that for
        // impersonation traits — `(?i)…Майкрософт` must still match
        // `майкрософт`. At 69 of 30,817 patterns this is free: one flag at
        // compile time, no runtime branch, no second engine.
        //
        // The `\p{..}`-and-ranges patterns are ASCII *source* but cannot parse
        // in byte mode at all, so they take the same fallback via `or_else`.
        let engine = if !pattern.is_ascii() {
            compile_codepoint(pattern)?
        } else {
            match compile_bytes(pattern) {
                Some(re) => re,
                None => compile_codepoint(pattern)?,
            }
        };
        Some(TraitRegex {
            engine: Engine::new(engine),
            pattern: pattern.into(),
            min_len,
        })
    }

    /// Heap footprint of the engine, for the byte-budgeted store.
    pub(crate) fn heap_bytes(&self) -> usize {
        self.engine.re.memory_usage() + self.pattern.len() + std::mem::size_of::<Self>()
    }

    /// Whether the pattern matches anywhere in `haystack`. `earliest(true)`
    /// mirrors the facade's `is_match`: stop at the first proof of a match
    /// instead of running the leftmost-first match to completion.
    pub(crate) fn is_match(&self, haystack: &str) -> bool {
        if haystack.len() < self.min_len {
            return false;
        }
        let engine = &self.engine;
        super::super::regex_scratch::with_cache(engine.id, &engine.re, |cache| {
            engine
                .re
                .search_half_with(cache, &regex_automata::Input::new(haystack).earliest(true))
                .is_some()
        })
    }

    /// [`Self::is_match`] with caller-held scratch (see [`Self::with_scratch`]):
    /// batch callers verify many haystacks against one regex without the
    /// per-call scratch checkout.
    pub(crate) fn is_match_cached(
        &self,
        haystack: &str,
        cache: &mut regex_automata::meta::Cache,
    ) -> bool {
        if haystack.len() < self.min_len {
            return false;
        }
        self.engine
            .re
            .search_half_with(cache, &regex_automata::Input::new(haystack).earliest(true))
            .is_some()
    }

    /// Leftmost-first match, returned as a borrow of `haystack`.
    ///
    /// A byte-mode engine can in principle end a match mid-codepoint (`.` and
    /// negated classes match single bytes), so the span is taken with `get`
    /// rather than indexing: a match that does not land on char boundaries
    /// yields `None` instead of panicking. Pure-ASCII haystacks — nearly all
    /// extracted strings — can never hit that case.
    pub(crate) fn find_str<'v>(&self, haystack: &'v str) -> Option<&'v str> {
        if haystack.len() < self.min_len {
            return None;
        }
        let engine = &self.engine;
        super::super::regex_scratch::with_cache(engine.id, &engine.re, |cache| {
            self.find_str_cached(haystack, cache)
        })
    }

    /// Batch callers keep this engine's scratch storage across independent inputs.
    pub(crate) fn with_scratch<R>(
        &self,
        f: impl FnOnce(&mut regex_automata::meta::Cache) -> R,
    ) -> R {
        super::super::regex_scratch::with_batch_cache(self.engine.id, &self.engine.re, f)
    }

    pub(crate) fn find_str_cached<'v>(
        &self,
        haystack: &'v str,
        cache: &mut regex_automata::meta::Cache,
    ) -> Option<&'v str> {
        if haystack.len() < self.min_len {
            return None;
        }
        self.engine
            .re
            .search_with(cache, &regex_automata::Input::new(haystack))
            .and_then(|m| haystack.get(m.start()..m.end()))
    }

    /// Iterate non-overlapping leftmost-first matches, invoking
    /// `f(start_offset, matched_span)`; `f` returns `false` to stop early.
    /// Iteration protocol (including empty-match advancement) matches the
    /// facade's `find_iter` — both are built on `util::iter::Searcher`.
    ///
    /// Spans are taken with `get`; see [`Self::find_str`] on char boundaries.
    pub(crate) fn for_each_find<'v>(
        &self,
        haystack: &'v str,
        mut f: impl FnMut(usize, &'v str) -> bool,
    ) {
        if haystack.len() < self.min_len {
            return;
        }
        let engine = &self.engine;
        super::super::regex_scratch::with_cache(engine.id, &engine.re, |cache| {
            self.for_each_find_cached(haystack, cache, &mut f)
        });
    }

    pub(crate) fn for_each_find_cached<'v>(
        &self,
        haystack: &'v str,
        cache: &mut regex_automata::meta::Cache,
        mut f: impl FnMut(usize, &'v str) -> bool,
    ) {
        if haystack.len() < self.min_len {
            return;
        }
        let mut it =
            regex_automata::util::iter::Searcher::new(regex_automata::Input::new(haystack));
        loop {
            let m = it.advance(|input| Ok(self.engine.re.search_with(cache, input)));
            let Some(m) = m else { return };
            let Some(span) = haystack.get(m.start()..m.end()) else {
                continue;
            };
            if !f(m.start(), span) {
                return;
            }
        }
    }
}

/// Byte-mode compile: byte-level classes (`unicode(false)`) avoid the UTF-8
/// sub-automaton expansion entirely. Nearly every pattern gets this, and it is
/// the semantics YARA itself uses. `None` means the pattern cannot be expressed
/// in byte mode (`\p{..}` classes, non-ASCII ranges) — the signal for
/// [`TraitRegex::compile`] to fall back to [`compile_codepoint`].
pub(super) fn compile_bytes(pattern: &str) -> Option<regex_automata::meta::Regex> {
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

/// Codepoint-mode compile: exact `regex::Regex::new` semantics. Still searches
/// bytes — only the *parsing* differs — so callers are identical either way.
pub(super) fn compile_codepoint(pattern: &str) -> Option<regex_automata::meta::Regex> {
    regex_automata::meta::Regex::builder()
        .configure(engine_config().utf8_empty(true))
        .build(pattern)
        .ok()
}

/// Per-thread memo in front of [`REGEX_CACHE`].
///
/// [`cached_regex`] runs once per regex condition per evaluation, and the store
/// behind it is a single `RwLock`. Even the read path is a shared atomic RMW on
/// one cache line, so on a 128-core host the uncontended CAS keeps losing and
/// readers fall through to the futex path. Measured on uruk-hai analyzing one
/// 112 MB PE with a flat profile: 664k of ~1.15M samples in
/// `RwLock::read_contended` and another 337k inside this function, against
/// 7.2k in the actual substring searcher — the pool spent roughly 87% of its
/// cycles arbitrating access to a cache instead of matching bytes.
///
/// A thread re-evaluates the same rule set against member after member, so a
/// small per-thread memo answers nearly every call without touching the global
/// lock. Direct-mapped rather than an LRU: one probe, no recency bookkeeping
/// (the global store already learned that recency updates dominate under
/// contention), and a colliding pattern just replaces the slot. The stored
/// pattern is compared on hit, so a hash collision cannot return the wrong
/// regex — only cost a miss.
///
/// Entries hold an `Arc` clone, so a pattern evicted from the global store
/// stays alive while some thread's slot still references it. That is bounded by
/// `LOCAL_REGEX_SLOTS` per thread and is the deliberate trade for dropping the
/// lock traffic.
pub(super) const LOCAL_REGEX_SLOTS: usize = 4096;

thread_local! {
    static LOCAL_REGEX: std::cell::RefCell<Vec<Option<(Box<str>, bool, Arc<TraitRegex>)>>> =
        std::cell::RefCell::new(vec![None; LOCAL_REGEX_SLOTS]);
}

/// Direct-mapped slot for `pattern` under `case_insensitive`. The flag is
/// part of the key so [`lazy_regex`] can answer from the memo without first
/// building the `(?i)`-prefixed pattern string.
pub(super) fn local_regex_slot(pattern: &str, case_insensitive: bool) -> usize {
    use std::hash::{Hash, Hasher};
    let mut hasher = rustc_hash::FxHasher::default();
    pattern.hash(&mut hasher);
    case_insensitive.hash(&mut hasher);
    (hasher.finish() as usize) % LOCAL_REGEX_SLOTS
}

/// Look up `pattern` in this thread's memo, verifying the stored key.
pub(super) fn local_regex_get(
    slot: usize,
    pattern: &str,
    case_insensitive: bool,
) -> Option<Arc<TraitRegex>> {
    LOCAL_REGEX.with(|cache| {
        let cache = cache.borrow();
        match cache.get(slot) {
            Some(Some((key, ci, regex))) if *ci == case_insensitive && &**key == pattern => {
                Some(Arc::clone(regex))
            }
            _ => None,
        }
    })
}

/// Publish `regex` into this thread's memo, replacing any colliding entry.
pub(super) fn local_regex_put(
    slot: usize,
    pattern: &str,
    case_insensitive: bool,
    regex: &Arc<TraitRegex>,
) {
    LOCAL_REGEX.with(|cache| {
        if let Some(entry) = cache.borrow_mut().get_mut(slot) {
            *entry = Some((Box::from(pattern), case_insensitive, Arc::clone(regex)));
        }
    });
}

pub(crate) fn cached_regex(pattern: &str) -> Option<Arc<TraitRegex>> {
    // Hottest path: this thread's own memo, no shared state touched at all.
    let slot = local_regex_slot(pattern, false);
    if let Some(arc) = local_regex_get(slot, pattern, false) {
        return Some(arc);
    }
    // Warm path: `peek` under a read lock — it doesn't bump LRU recency, so warm
    // evals never serialize on the write lock (the bytes cache learned this the
    // hard way: `get`'s &mut recency update cost ~25% CPU in lock wait).
    if let Some(arc) = REGEX_CACHE
        .read()
        .ok()
        .and_then(|c| c.peek(pattern).cloned())
    {
        local_regex_put(slot, pattern, false, &arc);
        return Some(arc);
    }
    // Miss: claim the key so racing workers pick up one compile instead of
    // each duplicating it; bounded fallback compiles independently if the
    // claimant is slow (see `compile_claim`).
    static CLAIMS: super::super::compile_claim::ClaimSet =
        super::super::compile_claim::ClaimSet::new();
    let compile_and_put = || {
        let arc = Arc::new(TraitRegex::compile(pattern)?);
        let size = arc.heap_bytes();
        if let Ok(mut cache) = REGEX_CACHE.write() {
            cache.put(pattern.to_string(), Arc::clone(&arc), size);
        }
        Some(arc)
    };
    let kh = super::super::compile_claim::ClaimSet::hash_key(&pattern);
    let compiled = if let Some(_guard) = CLAIMS.try_claim(kh) {
        // Another compiler may have published between our first lookup and
        // claiming the key. Recheck before doing that work again.
        let hit = REGEX_CACHE
            .read()
            .ok()
            .and_then(|c| c.peek(pattern).cloned());
        hit.or_else(compile_and_put)
    } else if let Some(hit) = CLAIMS.wait_for(kh, || {
        REGEX_CACHE
            .read()
            .ok()
            .and_then(|c| c.peek(pattern).cloned())
    }) {
        Some(hit)
    } else {
        compile_and_put()
    };
    if let Some(arc) = compiled.as_ref() {
        local_regex_put(slot, pattern, false, arc);
    }
    compiled
}

/// Occupancy and churn stats for the condition-level `TraitRegex` store, for
/// the end-of-scan cache log: (entries, bytes, inserts, evictions,
/// replacements, budget).
pub(crate) fn regex_store_stats() -> (usize, usize, u64, u64, u64, usize) {
    REGEX_CACHE
        .read()
        .map(|c| {
            (
                c.len(),
                c.bytes(),
                c.inserts(),
                c.evictions(),
                c.replacements(),
                c.budget(),
            )
        })
        .unwrap_or_default()
}

/// Clear the process-global lazy regex cache (see [`cached_regex`]). Shared
/// across all threads; call from a single thread under memory pressure.
pub(crate) fn clear_cached_regex() {
    if let Ok(mut cache) = REGEX_CACHE.write() {
        cache.clear();
    }
}

/// Resolve a `regex:` pattern through [`cached_regex`], applying the `(?i)`
/// prefix for case-insensitivity. This is the **only** place the extracted-
/// string path builds a `regex::Regex`: `word:`/`substr:`/`exact:` are literal
/// matches (see [`word_match_start`]) and never touch the regex engine.
pub(crate) fn lazy_regex(regex: Option<&str>, case_insensitive: bool) -> Option<Arc<TraitRegex>> {
    let raw = regex?;
    if !case_insensitive {
        return cached_regex(raw);
    }
    // Memo on the *raw* pattern plus the flag, so a warm case-insensitive
    // condition never rebuilds its `(?i)`-prefixed key: that `format!` ran
    // once per evaluation of every CI regex condition.
    let slot = local_regex_slot(raw, true);
    if let Some(arc) = local_regex_get(slot, raw, true) {
        return Some(arc);
    }
    let compiled = cached_regex(&format!("(?i){raw}"));
    if let Some(ref arc) = compiled {
        local_regex_put(slot, raw, true, arc);
    }
    compiled
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
    // Thread-local front cache of the leaked `'static` refs. The global map
    // below is one RwLock cache line shared by every worker, probed once per
    // (condition x member) — measured as a hot leaf on member-heavy archives
    // purely from cross-core contention. Needles are a bounded set (the trait
    // corpus), so each thread converges to an uncontended local hit.
    thread_local! {
        static TLS_FINDERS: std::cell::RefCell<
            rustc_hash::FxHashMap<Box<str>, &'static memchr::memmem::Finder<'static>>,
        > = std::cell::RefCell::new(rustc_hash::FxHashMap::default());
    }
    if let Some(f) = TLS_FINDERS.with(|m| m.borrow().get(needle).copied()) {
        return f;
    }
    let resolved = cached_finder_shared(needle);
    TLS_FINDERS.with(|m| m.borrow_mut().insert(Box::from(needle), resolved));
    resolved
}

pub(super) fn cached_finder_shared(needle: &str) -> &'static memchr::memmem::Finder<'static> {
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
    // Same thread-local front as `cached_finder` — see the rationale there.
    // Build failures (`None`) are cached too so a bad needle doesn't retry.
    thread_local! {
        static TLS_CI: std::cell::RefCell<
            rustc_hash::FxHashMap<Box<str>, Option<&'static aho_corasick::AhoCorasick>>,
        > = std::cell::RefCell::new(rustc_hash::FxHashMap::default());
    }
    if let Some(hit) = TLS_CI.with(|m| m.borrow().get(needle).copied()) {
        return hit;
    }
    let resolved = cached_ci_searcher_shared(needle);
    TLS_CI.with(|m| m.borrow_mut().insert(Box::from(needle), resolved));
    resolved
}

pub(super) fn cached_ci_searcher_shared(
    needle: &str,
) -> Option<&'static aho_corasick::AhoCorasick> {
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
pub(super) fn is_word_byte(b: u8) -> bool {
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
pub(super) fn word_boundary_ok(hb: &[u8], nb: &[u8], start: usize, end: usize) -> bool {
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
