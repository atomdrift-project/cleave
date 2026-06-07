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

/// Global bounded LRU cache for compiled regex patterns to avoid repeated compilation.
/// Key is (pattern, case_insensitive), value is compiled Regex.
/// Bounded to prevent unbounded memory growth in long-running processes.
static REGEX_CACHE: OnceLock<RwLock<lru::LruCache<(String, bool), Regex>>> = OnceLock::new();

// SAFETY: REGEX_CACHE_MAX_SIZE is a compile-time constant > 0
const REGEX_CACHE_SIZE: NonZeroUsize = {
    #[allow(clippy::expect_used)]
    NonZeroUsize::new(REGEX_CACHE_MAX_SIZE).expect("REGEX_CACHE_MAX_SIZE is non-zero")
};

/// Access the global regex cache, initializing it on first call
fn regex_cache() -> &'static RwLock<lru::LruCache<(String, bool), Regex>> {
    REGEX_CACHE.get_or_init(|| RwLock::new(lru::LruCache::new(REGEX_CACHE_SIZE)))
}

/// A lean byte-regex engine: a `PikeVM` (Thompson NFA + on-stack simulation) with
/// a thread-safe pool of reusable search caches.
///
/// **Why not `regex::bytes::Regex`?** The meta-engine bundles forward+reverse NFA,
/// one-pass DFA, bounded backtracker, lazy DFA and literal prefilters — ~745 KB
/// resident per compiled pattern after its lazy-DFA cache fills. At ~10k cached
/// `raw`/`text` patterns that measured **~12 GB / a permanent process floor**.
/// A `PikeVM` keeps only the Thompson NFA (avg ~23 KB; measured 238 MB total for
/// the same 10,434 patterns — a ~50× cut, matching YARA-X's footprint).
///
/// **Parity:** `PikeVM` defaults to [`MatchKind::LeftmostFirst`], the exact match
/// semantics the `regex` crate exposes (it is built on these same `regex-automata`
/// components). With `multi_line` + Unicode + `utf8(false)` (allow byte matches),
/// `find_iter` returns the identical leftmost, non-overlapping match set.
///
/// **Multi-line is enabled** — see the historical note: trait authors writing
/// `regex: '^namespace '` against source expect per-line anchoring, not
/// whole-file anchoring. `^`/`$` match at every `\n`.
/// Max bytes a windowed verify reads forward from an atom occurrence. Mirrors
/// YARA-X's `DEFAULT_SCAN_LIMIT` (4096): a match that extends beyond this from its
/// prefix atom is intentionally not found — an accepted, bounded correctness cap
/// that keeps the per-hit cost constant. Anchored verification of bounded patterns
/// stops well before this; the cap only bounds unbounded patterns (`.*`).
const WINDOW_LIMIT: usize = 4096;

/// A lean byte-regex engine. Two variants, chosen by whether a usable mandatory
/// atom could be extracted:
///
/// * [`LeanRegex::Windowed`] — the common case (~62% of patterns). A `PikeVM`
///   (Thompson NFA, ~23 KB) plus an Aho-Corasick over the pattern's longest
///   mandatory literal. Matching finds atom occurrences and verifies the pattern
///   only on a bounded window around each (YARA-X style): tiny RAM, and PikeVM's
///   slow-per-byte cost applies to ≤`WINDOW_LIMIT` bytes, not the whole file.
/// * [`LeanRegex::Whole`] — the literal-free residue (`[A-Za-z0-9+/]{40,}`, hex
///   blobs, entropy shapes): no atom to anchor a window, so it keeps the fast
///   meta-engine (lazy DFA) for whole-content scanning. ~745 KB each, but this
///   set is small, and a DFA is the only thing fast enough for whole-file scans.
pub(crate) enum LeanRegex {
    Windowed {
        pikevm: std::sync::Arc<regex_automata::nfa::thompson::pikevm::PikeVM>,
        pool: regex_automata::util::pool::Pool<
            regex_automata::nfa::thompson::pikevm::Cache,
            Box<dyn Fn() -> regex_automata::nfa::thompson::pikevm::Cache + Send + Sync>,
        >,
        atom: aho_corasick::AhoCorasick,
    },
    Whole {
        meta: regex::bytes::Regex,
    },
}

impl LeanRegex {
    /// Iterate non-overlapping leftmost-first matches over `haystack`, invoking
    /// `f(start, end)` (byte offsets); `f` returns `false` to stop early.
    pub(crate) fn for_each_match(&self, haystack: &[u8], mut f: impl FnMut(usize, usize) -> bool) {
        match self {
            LeanRegex::Whole { meta } => {
                for m in meta.find_iter(haystack) {
                    if !f(m.start(), m.end()) {
                        return;
                    }
                }
            }
            LeanRegex::Windowed { pikevm, pool, atom } => {
                let mut cache = pool.get();
                // Atom-windowed verify. The atom is a *mandatory* literal that may
                // sit anywhere in a match, so for each occurrence verify the pattern
                // (unanchored) over a bounded window on both sides — `multi_line`
                // and `\b` anchors resolve against the full haystack (test-verified).
                // Matches are deduped by start and re-linearised to non-overlapping
                // leftmost-first, matching `find_iter` semantics.
                let mut matches: Vec<(usize, usize)> = Vec::new();
                let mut seen: rustc_hash::FxHashSet<usize> = rustc_hash::FxHashSet::default();
                for hit in atom.find_overlapping_iter(haystack) {
                    let lo = hit.start().saturating_sub(WINDOW_LIMIT);
                    let hi = (hit.end() + WINDOW_LIMIT).min(haystack.len());
                    for m in
                        pikevm.find_iter(&mut cache, regex_automata::Input::new(haystack).span(lo..hi))
                    {
                        // Only matches covering this atom occurrence belong to it;
                        // ones starting after it are found via their own occurrence.
                        if m.start() <= hit.start() && hit.end() <= m.end() && seen.insert(m.start())
                        {
                            matches.push((m.start(), m.end()));
                        }
                        if m.start() > hit.start() {
                            break;
                        }
                    }
                }
                matches.sort_unstable();
                let mut last_end = 0usize;
                for (s, e) in matches {
                    if s < last_end {
                        continue;
                    }
                    last_end = e.max(s + 1);
                    if !f(s, e) {
                        return;
                    }
                }
            }
        }
    }

    /// Whether the pattern matches anywhere in `haystack`. Test-only primitive.
    #[cfg(test)]
    pub(crate) fn is_match(&self, haystack: &[u8]) -> bool {
        let mut hit = false;
        self.for_each_match(haystack, |_, _| {
            hit = true;
            false
        });
        hit
    }

    /// Resident NFA/engine memory (per-search caches are pooled/transient and
    /// excluded). Meta-engine size isn't directly queryable, so the literal-free
    /// residue is reported via the separate `Whole` count in cache stats.
    pub(crate) fn nfa_memory(&self) -> usize {
        match self {
            LeanRegex::Windowed { pikevm, .. } => pikevm.get_nfa().memory_usage(),
            LeanRegex::Whole { .. } => 0,
        }
    }

    /// True for the literal-free residue (whole-content meta-engine).
    pub(crate) fn is_whole(&self) -> bool {
        matches!(self, LeanRegex::Whole { .. })
    }
}

/// Bounded LRU cache for ASCII byte-regex engines ([`LeanRegex`]) — matches
/// directly against raw file bytes, skipping UTF-8 validation. Only ASCII callers
/// populate it; callers gate on `can_use_byte_matching` before requesting one.
static BYTES_REGEX_CACHE: OnceLock<
    RwLock<lru::LruCache<(String, bool), std::sync::Arc<LeanRegex>>>,
> = OnceLock::new();

/// Access the bytes regex cache.
pub(crate) fn bytes_regex_cache()
-> &'static RwLock<lru::LruCache<(String, bool), std::sync::Arc<LeanRegex>>> {
    BYTES_REGEX_CACHE.get_or_init(|| RwLock::new(lru::LruCache::new(REGEX_CACHE_SIZE)))
}

/// Compile an ASCII-only pattern into a lean [`LeanRegex`] for
/// zero-UTF-8-validation matching against raw file bytes. Returns `None` if the
/// pattern uses features both engines reject (e.g. backreferences) — callers must
/// gate on `can_use_byte_matching` first.
pub(crate) fn compile_bytes_regex(pattern: &str, case_insensitive: bool) -> Option<LeanRegex> {
    // The longest *mandatory* literal anywhere in the pattern (not just the
    // prefix). Its presence decides the engine: a usable atom → lean windowed
    // PikeVM; none → fast meta-engine whole-content scan.
    let atom = best_mandatory_atom(pattern).and_then(|lit| {
        aho_corasick::AhoCorasick::builder()
            .ascii_case_insensitive(case_insensitive)
            .build([&lit])
            .ok()
    });

    let Some(atom) = atom else {
        // Literal-free residue: keep the fast lazy-DFA meta-engine for whole
        // content. Mirrors the previous `regex::bytes::Regex` config exactly.
        let mut builder = regex::bytes::RegexBuilder::new(pattern);
        builder.case_insensitive(case_insensitive);
        builder.multi_line(true);
        return Some(LeanRegex::Whole {
            meta: builder.build().ok()?,
        });
    };

    use regex_automata::nfa::thompson;
    use regex_automata::util::syntax;
    let pikevm = thompson::pikevm::PikeVM::builder()
        .syntax(
            syntax::Config::new()
                .case_insensitive(case_insensitive)
                .multi_line(true)
                // Allow matching arbitrary (possibly invalid-UTF-8) bytes, mirroring
                // `regex::bytes::Regex`. Unicode classes stay enabled (the default).
                .utf8(false),
        )
        .thompson(thompson::Config::new().utf8(false))
        .build(pattern)
        .ok()?;
    let pikevm = std::sync::Arc::new(pikevm);
    // Pool create-closure holds an `Arc` clone so it can mint caches without
    // borrowing the engine; the closure is `Send + Sync` as the pool requires.
    let pv = std::sync::Arc::clone(&pikevm);
    let pool = regex_automata::util::pool::Pool::new(Box::new(move || pv.create_cache())
        as Box<dyn Fn() -> thompson::pikevm::Cache + Send + Sync>);
    Some(LeanRegex::Windowed { pikevm, pool, atom })
}

/// Smallest atom length worth searching for. Shorter literals occur too often to
/// be useful prefilters (every occurrence forces a windowed verify). Measured: 3
/// beats 2 on wall (fewer false-positive windows) at a negligible residue cost.
const MIN_ATOM_LEN: usize = 3;

/// Extract the longest **mandatory** literal anywhere in `pattern` — one that must
/// appear in every match (a direct `Concat` child, or inside a `min>=1` repetition
/// or a capture). Returns `None` when no literal of at least [`MIN_ATOM_LEN`] is
/// guaranteed (e.g. alternations without a shared literal, leading `.*`, pure
/// character classes) — those patterns fall back to a full PikeVM scan.
///
/// This is the key to keeping the whole-content residue tiny: a prefix-only
/// extractor leaves ~half of `type: text` patterns atomless (`\s*foo`, `.*token`).
///
/// Shared with `RawContentRegexIndex` so the *gate* and the *verify* key on the
/// same atom: a pattern gated by atom X is windowed by atom X.
pub(crate) fn best_mandatory_atom(pattern: &str) -> Option<Vec<u8>> {
    fn walk(hir: &regex_syntax::hir::Hir, best: &mut Vec<u8>) {
        use regex_syntax::hir::HirKind;
        match hir.kind() {
            HirKind::Literal(lit) => {
                if lit.0.len() > best.len() {
                    *best = lit.0.to_vec();
                }
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
pub fn log_regex_cache_stats() {
    let uni = REGEX_CACHE.get().map_or(0, |c| c.read().len());
    let bytes = BYTES_REGEX_CACHE.get().map_or(0, |c| c.read().len());
    tracing::info!(
        unicode_cache_entries = uni,
        bytes_cache_entries = bytes,
        "regex cache stats"
    );

    // Sum the resident NFA memory of the lean byte-regex cache (per-search caches
    // are pooled/transient and excluded).
    if let Some(cache) = BYTES_REGEX_CACHE.get() {
        let guard = cache.read();
        let mut total: usize = 0;
        let mut max: usize = 0;
        let mut whole = 0usize;
        let n = guard.len();
        for (_, lean) in guard.iter() {
            let m = lean.nfa_memory();
            total += m;
            max = max.max(m);
            if lean.is_whole() {
                whole += 1;
            }
        }
        tracing::info!(
            entries = n,
            whole_meta = whole,
            nfa_total_mb = total / (1024 * 1024),
            nfa_avg_kb = if n > 0 { total / n / 1024 } else { 0 },
            nfa_max_kb = max / 1024,
            "lean byte-regex cache NFA memory"
        );
    }
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

/// Clear thread-local caches to free memory.
///
/// This should be called periodically during long-running scans to prevent
/// memory growth from accumulating cache entries across many files.
///
/// Clears:
/// - UTF8_CACHE: Thread-local LRU cache of UTF-8 conversions (can hold large strings)
/// - SCANNER_CACHE: Thread-local YARA scanner cache
///
/// Note: This only clears the cache for the CURRENT thread. When using rayon,
/// call this from within a parallel context to clear caches on worker threads.
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
    crate::yara_engine::clear_engine_scanner_cache();
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
