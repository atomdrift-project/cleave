//! Condition evaluators for composite rules.
//!
//! This module contains evaluation functions for different condition types:
//! - **symbol_string**: Symbol and string matching (imports, exports, strings, decoded content)
//! - **binary**: Binary analysis (sections, imports, syscalls)
//! - **ast**: AST pattern and query evaluation for source code
//! - **metrics**: Metric-based thresholds (code metrics, binary metrics)
//! - **yara**: YARA rules and hex patterns
//! - **misc**: Miscellaneous evaluators (structure, traits, filesize)
//!
//! ## Performance Optimizations
//! - Regex patterns are cached globally to avoid recompilation
//! - YARA scanners are cached thread-locally for ~5x speedup
//! - Hex pattern matching uses atom extraction for efficient searching

use parking_lot::RwLock;
use regex::Regex;
use std::num::NonZeroUsize;
use std::sync::OnceLock;

// Re-export all evaluator modules
pub(crate) mod ast;
pub(crate) mod binary;
pub(crate) mod kv;
pub(crate) mod metrics;
pub(crate) mod misc;
pub(crate) mod symbol_string;
pub(crate) mod yara;

pub(crate) use ast::*;
pub(crate) use binary::*;
pub(crate) use kv::*;
pub(crate) use metrics::*;
pub(crate) use misc::*;
pub(crate) use symbol_string::*;
pub(crate) use yara::*;

// Test modules
#[cfg(test)]
mod ast_tests;
#[cfg(test)]
mod binary_tests;
#[cfg(test)]
mod metrics_tests;
#[cfg(test)]
mod misc_tests;
#[cfg(test)]
mod symbol_string_tests;
#[cfg(test)]
mod yara_tests;

// =============================================================================
// Shared Utilities
// =============================================================================

/// Maximum number of regex patterns to cache (sized for ~128K rules, not all use regex)
const REGEX_CACHE_MAX_SIZE: usize = 16_384;

/// Per-regex lazy-DFA scratch budget in bytes (`RegexBuilder::dfa_size_limit`,
/// i.e. regex-automata's `hybrid_cache_capacity`). The default is 2 MiB per
/// compiled regex *per thread that searches with it*; scanning one large
/// high-entropy input (a 24 MB Go binary) fills thousands of trait-regex
/// caches to that budget, and because the compiled regexes live in the LRU
/// caches above, the scratch never shrinks — measured at ~4.2 GB live heap of
/// a ~5 GB peak RSS. The lazy DFA is purely an optimization: when its cache is
/// too small it evicts states or the meta engine falls back to another
/// match-equivalent engine, so results are identical by construction — only
/// speed is at stake. 256 KiB measured wall-neutral on the trait corpus.
/// Override with `CLEAVE_REGEX_DFA_KB` (KiB) for tuning experiments.
pub(crate) fn regex_dfa_cache_bytes() -> usize {
    static BYTES: OnceLock<usize> = OnceLock::new();
    *BYTES.get_or_init(|| {
        std::env::var("CLEAVE_REGEX_DFA_KB")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map_or(256 * 1024, |kb| kb * 1024)
    })
}

/// Global bounded LRU cache for compiled regex patterns to avoid repeated compilation.
/// Key is (pattern, case_insensitive), value is compiled Regex.
/// Bounded to prevent unbounded memory growth in long-running processes.
static REGEX_CACHE: OnceLock<
    RwLock<lru::LruCache<(String, bool), Regex, rustc_hash::FxBuildHasher>>,
> = OnceLock::new();

// SAFETY: REGEX_CACHE_MAX_SIZE is a compile-time constant > 0
const REGEX_CACHE_SIZE: NonZeroUsize = {
    #[allow(clippy::expect_used)]
    NonZeroUsize::new(REGEX_CACHE_MAX_SIZE).expect("REGEX_CACHE_MAX_SIZE is non-zero")
};

/// Access the global regex cache, initializing it on first call
fn regex_cache() -> &'static RwLock<lru::LruCache<(String, bool), Regex, rustc_hash::FxBuildHasher>>
{
    REGEX_CACHE.get_or_init(|| {
        RwLock::new(lru::LruCache::with_hasher(
            REGEX_CACHE_SIZE,
            rustc_hash::FxBuildHasher,
        ))
    })
}

/// A compiled ASCII byte-regex — the `regex` crate meta-engine (SIMD literal
/// prefilter + lazy DFA), matched directly against raw file bytes with no UTF-8
/// validation. Multi-line is enabled so `^`/`$` anchor per-line in raw-text mode
/// (trait authors writing `regex: '^namespace '` expect line, not whole-file,
/// anchoring). Wrapped in a newtype so the cache value type is stable and all
/// raw-content matching funnels through one entry point.
///
/// (A lean `PikeVM`-plus-atom-window engine was prototyped here to cut the ~12 GB
/// cache to ~0.3 GB; it was parity-exact but ~1.85× slower per pattern — the meta
/// engine is already a near-optimal prefilter+DFA — so wall-clock priority kept
/// the meta engine. See `RESOURCE_ROADMAP.md`.)
pub(crate) struct LeanRegex {
    /// The meta engine, held directly rather than through `regex::bytes::Regex`
    /// so scratch lives in the byte-budgeted per-thread pool
    /// ([`crate::composite_rules::regex_scratch`]) instead of a per-regex ×
    /// per-thread pool retained for the process lifetime, and so the eagerly
    /// compiled onepass DFA (capture extraction only — never used here) is
    /// disabled. Match semantics are identical to the facade by construction:
    /// the `regex` crate is a thin wrapper over this same engine.
    meta: regex_automata::meta::Regex,
    /// Scratch-pool identity (see [`crate::composite_rules::regex_scratch`]).
    id: u64,
}

impl LeanRegex {
    /// Iterate non-overlapping leftmost-first matches over `haystack`, invoking
    /// `f(start, end)` (byte offsets); `f` returns `false` to stop early.
    pub(crate) fn for_each_match(&self, haystack: &[u8], mut f: impl FnMut(usize, usize) -> bool) {
        crate::composite_rules::regex_scratch::with_cache(self.id, &self.meta, |cache| {
            // `Searcher` reproduces `find_iter`'s exact iteration protocol,
            // including the empty-match advancement rules.
            let mut it =
                regex_automata::util::iter::Searcher::new(regex_automata::Input::new(haystack));
            loop {
                let m = it.advance(|input| Ok(self.meta.search_with(cache, input)));
                let Some(m) = m else { return };
                if !f(m.start(), m.end()) {
                    return;
                }
            }
        });
    }

    /// Whether the pattern matches anywhere in `haystack`. Test-only primitive.
    #[cfg(test)]
    pub(crate) fn is_match(&self, haystack: &[u8]) -> bool {
        crate::composite_rules::regex_scratch::with_cache(self.id, &self.meta, |cache| {
            self.meta
                .search_half_with(cache, &regex_automata::Input::new(haystack).earliest(true))
                .is_some()
        })
    }
}

/// Bounded LRU cache for ASCII byte-regex engines ([`LeanRegex`]) — matches
/// directly against raw file bytes, skipping UTF-8 validation. Only ASCII callers
/// populate it; callers gate on `can_use_byte_matching` before requesting one.
type BytesRegexCache =
    lru::LruCache<(String, bool), std::sync::Arc<LeanRegex>, rustc_hash::FxBuildHasher>;
static BYTES_REGEX_CACHE: OnceLock<RwLock<BytesRegexCache>> = OnceLock::new();

/// Access the bytes regex cache.
pub(crate) fn bytes_regex_cache() -> &'static RwLock<BytesRegexCache> {
    BYTES_REGEX_CACHE.get_or_init(|| {
        RwLock::new(lru::LruCache::with_hasher(
            REGEX_CACHE_SIZE,
            rustc_hash::FxBuildHasher,
        ))
    })
}

/// Compile an ASCII-only pattern into a lean [`LeanRegex`] for
/// zero-UTF-8-validation matching against raw file bytes. Returns `None` if the
/// pattern uses features both engines reject (e.g. backreferences) — callers must
/// gate on `can_use_byte_matching` first.
pub(crate) fn compile_bytes_regex(pattern: &str, case_insensitive: bool) -> Option<LeanRegex> {
    // Meta-engine for everyone: it is a near-optimal SIMD-prefilter + lazy DFA,
    // faster per-pattern than a hand-rolled PikeVM window. The per-pattern lean
    // engine was measured ~1.85x slower on wall; wall is the priority. The
    // separate `type: text` atom-gating (index side) is what reduces how *often*
    // this runs — the real wall lever — and is engine-independent.
    // ASCII class semantics (`unicode(false)`): callers gate on
    // `can_use_byte_matching`, so every pattern here is pure ASCII with no
    // `\u`/`\p` — but in Unicode mode its `\w`/`\s`/`\d`/`(?i)` classes still
    // compile into UTF-8 byte sub-automata (hundreds of NFA states apiece,
    // multiplied inside `{m,n}` repetitions). Those NFAs measured 5.6× larger,
    // forced the meta engine off the lazy DFA onto the PikeVM (whose scratch is
    // O(NFA states) per regex per thread — ~2.3 GB live on one 24 MB Go binary),
    // and searched ~3× slower. On raw bytes, ASCII classes are also the honest
    // semantic: Unicode mode's `.`/`\w` presume UTF-8-encoded text, which raw
    // binary content is not. The Unicode fallback is defensive only.
    let build = |unicode: bool| {
        // Mirrors `regex::bytes::RegexBuilder` defaults exactly (utf8(false)
        // syntax, utf8_empty(false), 10 MB nfa size limit), plus the two
        // bounds-only levers the facade doesn't expose: no onepass DFA and
        // implicit-only capture states.
        regex_automata::meta::Regex::builder()
            .configure(
                regex_automata::meta::Regex::config()
                    .utf8_empty(false)
                    .onepass(false)
                    .which_captures(regex_automata::nfa::thompson::WhichCaptures::Implicit)
                    .nfa_size_limit(Some(10 * (1 << 20)))
                    .hybrid_cache_capacity(regex_dfa_cache_bytes()),
            )
            .syntax(
                regex_automata::util::syntax::Config::new()
                    .case_insensitive(case_insensitive)
                    .multi_line(true)
                    .unicode(unicode)
                    .utf8(false),
            )
            .build(pattern)
            .ok()
    };
    let meta = build(regex_unicode_override()).or_else(|| build(true))?;
    Some(LeanRegex {
        meta,
        id: crate::composite_rules::regex_scratch::next_regex_id(),
    })
}

/// Whether trait regexes keep full Unicode class semantics (`\w`, `.`, `(?i)`
/// spanning UTF-8 sequences): restores byte-regex Unicode mode and disables
/// the string path's ASCII class demotion (see `compile_bytes_regex` and
/// `condition::demote_perl_classes_to_ascii`). `CLEAVE_REGEX_UNICODE=1`
/// restores the old Unicode behavior for A/B benchmarking.
pub(crate) fn regex_unicode_override() -> bool {
    static UNICODE: OnceLock<bool> = OnceLock::new();
    *UNICODE.get_or_init(|| std::env::var("CLEAVE_REGEX_UNICODE").is_ok_and(|v| v == "1"))
}

/// Smallest atom length worth using as a prefilter. Shorter literals occur too
/// often to be selective (too many candidate verifications). 3 is the floor the
/// symbol- and text-index gates already used.
const MIN_ATOM_LEN: usize = 3;

/// Extract the longest **mandatory** literal anywhere in `pattern` — one that must
/// appear in every match (a direct `Concat` child, or inside a `min>=1` repetition
/// or a capture). Returns `None` when no literal of at least [`MIN_ATOM_LEN`] is
/// guaranteed (e.g. alternations without a shared literal, leading `.*`, pure
/// character classes).
///
/// Used by `RawContentRegexIndex` and `SymbolMatchIndex` to route patterns to a
/// cheap Aho-Corasick prefilter instead of the per-item `RegexSet` PikeVM scan. A
/// *prefix*-only extractor leaves ~half of `type: text` and many `type: symbol`
/// regexes atomless (`\s*foo`, `.*token`, `(get|set)Value`); finding the literal
/// *anywhere* shrinks that slow no-literal residue dramatically (profiled win).
pub(crate) fn best_mandatory_atom(pattern: &str) -> Option<Vec<u8>> {
    fn walk(hir: &regex_syntax::hir::Hir, best: &mut Vec<u8>) {
        use regex_syntax::hir::HirKind;
        match hir.kind() {
            HirKind::Literal(lit) if lit.0.len() > best.len() => {
                *best = lit.0.to_vec();
            }
            HirKind::Concat(subs) => {
                for s in subs {
                    walk(s, best);
                }
            }
            HirKind::Capture(c) => walk(&c.sub, best),
            // A repetition that runs at least once still guarantees its sub-literal.
            HirKind::Repetition(r) if r.min >= 1 => walk(&r.sub, best),
            // Alternation / optional / class / look-around: no single guaranteed literal.
            _ => {}
        }
    }
    let hir = regex_syntax::parse(pattern).ok()?;
    let mut best = Vec::new();
    walk(&hir, &mut best);
    (best.len() >= MIN_ATOM_LEN).then_some(best)
}

/// Log compiled-regex cache occupancy (unicode meta-engine cache + bytes cache).
#[allow(dead_code)] // called from lib.rs end-of-scan path
pub(crate) fn log_regex_cache_stats() {
    let uni = REGEX_CACHE.get().map_or(0, |c| c.read().len());
    let bytes = BYTES_REGEX_CACHE.get().map_or(0, |c| c.read().len());
    tracing::info!(
        unicode_cache_entries = uni,
        bytes_cache_entries = bytes,
        "regex cache stats"
    );
}

/// Create a Scanner for the given Rules.
#[must_use]
pub(crate) fn get_or_create_scanner(rules: &yara_x::Rules) -> yara_x::Scanner<'_> {
    yara_x::Scanner::new(rules)
}

/// Borrow `binary_data[range]` as a UTF-8 `str` with **zero copy** when the
/// bytes are valid UTF-8 (the common case for source/text), allocating only for
/// genuinely invalid UTF-8 (lossy replacement, rare for raw-matched content).
///
/// This keeps a **single copy of the file in memory** — the raw bytes — instead
/// of also materializing an owned UTF-8 duplicate (and previously caching up to
/// 32 such duplicates per thread). `std::str::from_utf8` validation is SIMD-fast
/// and re-run per call; the borrow avoids the allocation that dominated peak RSS
/// on large files.
#[must_use]
pub(crate) fn utf8_view(binary_data: &[u8], range: (usize, usize)) -> std::borrow::Cow<'_, str> {
    let slice = &binary_data[range.0..range.1];
    match std::str::from_utf8(slice) {
        Ok(s) => std::borrow::Cow::Borrowed(s),
        Err(_) => std::borrow::Cow::Owned(String::from_utf8_lossy(slice).into_owned()),
    }
}

/// Reset per-file thread-local state between files.
///
/// Called once per file/archive member on the current thread (so under rayon it
/// must run inside the parallel context). Today this just clears the IP
/// validator's current-file id; it is intentionally cheap.
///
/// Does NOT touch the thread-local YARA scanner cache. That cache is a bounded
/// `LruCache` whose `Rules` live for the whole process, so its scanners never go
/// stale and it cannot grow past its bound. Clearing it per member forced a full
/// `Scanner::new()` (a wasmtime VM instantiation over ~500 rules) on the next
/// member and dominated archive scan time — the same mistake the AST query cache
/// note below records. Keep the scanners warm.
///
/// Does NOT touch the process-wide AST query cache. Those `tree_sitter::Query`
/// entries are keyed by `(FileType, query_str)` and never become stale — wiping
/// them between archive members forced every rayon worker to recompile the
/// same queries on the next member, which was the dominant hotspot after the
/// symbol-batch/UTF-8 experiments.
///
/// Does NOT touch the process-global regex caches — those are shared across all
/// threads and clearing them here would invalidate other workers' entries. Use
/// `clear_regex_caches()` from a single thread when memory pressure demands it.
#[allow(dead_code)] // Exported via lib.rs, false positive from lib/bin split
pub fn clear_thread_local_caches() {
    crate::ip_validator::clear_current_file_id();
}

/// Clear the process-global regex caches.
///
/// These caches are shared across all threads and can grow up to
/// `REGEX_CACHE_MAX_SIZE` entries each (compiled `Regex` / `regex::bytes::Regex`
/// values can run several MB apiece for complex patterns, putting the cap in the
/// tens of GB range). Once populated by a diverse pattern set they stay at the
/// cap indefinitely, which is the dominant steady-state leak for long-running
/// workers.
///
/// Call this from a single thread under memory pressure — other workers will
/// simply repopulate entries they still need on their next access.
#[allow(dead_code)] // Exported via lib.rs, false positive from lib/bin split
pub fn clear_regex_caches() {
    if let Some(cache) = REGEX_CACHE.get() {
        cache.write().clear();
    }
    if let Some(cache) = BYTES_REGEX_CACHE.get() {
        cache.write().clear();
    }
    crate::composite_rules::condition::clear_cached_regex();
}

/// Check if a symbol matches a pattern (supports exact match or regex).
/// Uses cached regex compilation for patterns with metacharacters.
/// Note: Symbols are normalized (leading underscores stripped) at load time.
#[must_use]
pub(crate) fn symbol_matches(symbol: &str, pattern: &str) -> bool {
    // Try exact match first
    if symbol == pattern {
        return true;
    }

    // Try as regex if pattern contains regex metacharacters
    if (pattern.contains('|') || pattern.contains('*') || pattern.contains('['))
        && let Ok(re) = build_regex(pattern, false)
    {
        return re.is_match(symbol);
    }

    false
}

/// Build a regex with optional case insensitivity.
/// Results are cached globally for reuse across files.
pub(crate) fn build_regex(pattern: &str, case_insensitive: bool) -> anyhow::Result<Regex> {
    let cache = regex_cache();
    let key = (pattern.to_string(), case_insensitive);

    // Check cache with read lock using peek (no LRU promotion, no write needed)
    {
        let cache_guard = cache.read();
        if let Some(re) = cache_guard.peek(&key) {
            return Ok(re.clone());
        }
    }

    // Compile outside the lock. Multi-line is enabled so `^` / `$` line-anchor in
    // raw-text mode (source/manifests), matching the per-line semantic of
    // `text exact:`. Strings extracted from binaries contain no `\n`, so the
    // alternate anchors have nothing extra to match — behavior is unchanged there.
    let regex = {
        let mut builder = regex::RegexBuilder::new(pattern);
        builder.case_insensitive(case_insensitive);
        builder.multi_line(true);
        builder.dfa_size_limit(regex_dfa_cache_bytes());
        builder.build()?
    };

    // Insert with write lock (LRU will evict oldest if at capacity)
    {
        let mut cache_guard = cache.write();
        cache_guard.put(key, regex.clone());
    }
    Ok(regex)
}

/// Truncate evidence string to max length for display.
#[must_use]
pub(crate) fn truncate_evidence(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        format!("{}...", s.chars().take(max_len).collect::<String>())
    }
}

/// Render evidence for a substring match inside a containing string.
///
/// When the containing string is short, return it as-is. Otherwise return a
/// window of `context` chars on each side of the match, with leading/trailing
/// `…` to mark truncation. Byte offsets are snapped to UTF-8 char boundaries.
#[must_use]
pub(crate) fn match_window(
    source: &str,
    mat_start: usize,
    mat_end: usize,
    context: usize,
) -> String {
    // Short enough to show in full — no windowing needed.
    if source.chars().count() <= context * 2 + 40 {
        return source.to_string();
    }

    // Snap match bounds to char boundaries (Aho-Corasick gives byte offsets).
    let mut start = mat_start.min(source.len());
    while start > 0 && !source.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = mat_end.min(source.len());
    while end < source.len() && !source.is_char_boundary(end) {
        end += 1;
    }

    // Walk back `context` chars from the match start.
    let prefix_start = source[..start]
        .char_indices()
        .rev()
        .take(context)
        .last()
        .map(|(i, _)| i)
        .unwrap_or(start);
    let prefix_truncated = prefix_start > 0;

    // Walk forward `context` chars past the match end.
    let suffix_end = source[end..]
        .char_indices()
        .nth(context)
        .map(|(i, _)| end + i)
        .unwrap_or(source.len());
    let suffix_truncated = suffix_end < source.len();

    let mut out = String::with_capacity(suffix_end - prefix_start + 6);
    if prefix_truncated {
        out.push('…');
    }
    out.push_str(&source[prefix_start..suffix_end]);
    if suffix_truncated {
        out.push('…');
    }
    out
}

/// Parameters for location-constrained content evaluation.
#[derive(Debug, Clone, Default)]
pub(crate) struct ContentLocationParams {
    /// Binary section name constraint (e.g., ".text", "TEXT")
    pub section: Option<String>,
    /// Absolute file offset constraint (negative = from end of file)
    pub offset: Option<i64>,
    /// Absolute file offset range [start, end)
    pub offset_range: Option<(i64, Option<i64>)>,
    /// Offset relative to the section start
    pub section_offset: Option<i64>,
    /// Offset range relative to the section start
    pub section_offset_range: Option<(i64, Option<i64>)>,
    /// Architecture clamp range for fat/universal binaries.
    /// When set, the search is restricted to this byte range.
    pub arch_clamp: Option<(usize, usize)>,
}

/// Resolve the effective byte range for content search based on location constraints.
/// Returns (start, end) as absolute offsets into binary data.
/// When `arch_clamp` is set (fat/universal binaries), the result is intersected
/// with the architecture's byte range to prevent cross-slice false positives.
#[must_use]
pub(crate) fn resolve_effective_range<'a>(
    location: &ContentLocationParams,
    ctx: &crate::composite_rules::context::EvaluationContext<'a>,
) -> (usize, usize) {
    let file_size = ctx.binary_data.len();

    // Compute base range from location constraints
    let (base_start, base_end) = if location.section.is_none()
        && location.offset.is_none()
        && location.offset_range.is_none()
        && location.section_offset.is_none()
        && location.section_offset_range.is_none()
    {
        (0, file_size)
    } else if let Some(section_map) = ctx.section_map {
        if let Some((start, end)) = section_map.resolve_range(
            location.section.as_deref(),
            location.offset,
            location.offset_range,
            location.section_offset,
            location.section_offset_range,
        ) {
            (start as usize, end as usize)
        } else if location.section.is_some()
            || location.section_offset.is_some()
            || location.section_offset_range.is_some()
        {
            resolve_report_section_constraints(location, &ctx.report.sections)
        } else {
            resolve_offset_constraints(location, file_size)
        }
    } else if location.section.is_some()
        || location.section_offset.is_some()
        || location.section_offset_range.is_some()
    {
        resolve_report_section_constraints(location, &ctx.report.sections)
    } else {
        resolve_offset_constraints(location, file_size)
    };

    // Apply architecture clamp for fat/universal binaries
    if let Some((clamp_start, clamp_end)) = location.arch_clamp {
        (base_start.max(clamp_start), base_end.min(clamp_end))
    } else {
        (base_start, base_end)
    }
}

fn resolve_report_section_constraints(
    location: &ContentLocationParams,
    sections: &[crate::types::Section],
) -> (usize, usize) {
    let Some(section_name) = location.section.as_deref() else {
        return (0, 0);
    };

    let Some(section) = sections.iter().find(|section| {
        crate::composite_rules::section_map::SectionMap::section_matches(
            section.name.as_str(),
            section_name,
        )
    }) else {
        return (0, 0);
    };

    let Some(base_start) = section.offset.or(section.address).map(|v| v as usize) else {
        return (0, 0);
    };
    let base_end = base_start.saturating_add(section.size as usize);

    if let Some(sec_off) = location.section_offset {
        let start = resolve_relative_offset(sec_off, base_start, base_end, false);
        return start
            .map(|start| (start, start.saturating_add(1)))
            .unwrap_or((0, 0));
    }

    if let Some((rel_start, rel_end)) = location.section_offset_range {
        let Some(start) = resolve_relative_offset(rel_start, base_start, base_end, false) else {
            return (0, 0);
        };
        let end = match rel_end {
            Some(rel_end) => {
                let Some(end) = resolve_relative_offset(rel_end, base_start, base_end, true) else {
                    return (0, 0);
                };
                end
            }
            None => base_end,
        };
        return if start < end { (start, end) } else { (0, 0) };
    }

    (base_start, base_end)
}

/// Resolve absolute offset constraints without SectionMap.
fn resolve_offset_constraints(
    location: &ContentLocationParams,
    file_size: usize,
) -> (usize, usize) {
    if location.section.is_some()
        || location.section_offset.is_some()
        || location.section_offset_range.is_some()
    {
        return (0, 0);
    }

    match (location.offset, &location.offset_range) {
        (Some(off), None) => {
            let resolved = if off < 0 {
                (file_size as i64 + off).max(0) as usize
            } else {
                off as usize
            };
            (resolved, (resolved + 1).min(file_size))
        }
        (None, Some((start, end_opt))) => {
            let file_size_i64 = file_size as i64;
            let resolved_start = if *start < 0 {
                (file_size_i64 + *start).max(0) as usize
            } else {
                *start as usize
            };
            let resolved_end = match end_opt {
                Some(end) if *end < 0 => (file_size_i64 + *end).max(0) as usize,
                Some(end) => *end as usize,
                None => file_size,
            };
            (resolved_start, resolved_end)
        }
        _ => (0, file_size),
    }
}

fn resolve_relative_offset(
    offset: i64,
    base_start: usize,
    base_end: usize,
    allow_end: bool,
) -> Option<usize> {
    let base_size = base_end.saturating_sub(base_start);
    let abs_rel_offset = if offset >= 0 {
        offset as usize
    } else {
        base_size.checked_sub(offset.unsigned_abs() as usize)?
    };

    if allow_end {
        (abs_rel_offset <= base_size).then_some(base_start + abs_rel_offset)
    } else if abs_rel_offset < base_size {
        Some(base_start + abs_rel_offset)
    } else {
        None
    }
}

/// Resolve effective range as Option for string offset filtering.
/// Returns None if no location constraints (no filtering needed).
#[must_use]
pub(crate) fn resolve_effective_range_opt<'a>(
    location: &ContentLocationParams,
    ctx: &crate::composite_rules::context::EvaluationContext<'a>,
) -> Option<(u64, u64)> {
    // If no location constraints, return None (no filtering)
    if location.section.is_none()
        && location.offset.is_none()
        && location.offset_range.is_none()
        && location.section_offset.is_none()
        && location.section_offset_range.is_none()
    {
        return None;
    }

    let (start, end) = resolve_effective_range(location, ctx);
    Some((start as u64, end as u64))
}
