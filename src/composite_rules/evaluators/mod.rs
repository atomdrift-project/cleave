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
use std::cell::RefCell;
use std::hash::Hash;
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

/// Cached compiled regex - either string-based or bytes-based for performance.
/// ASCII-only patterns use bytes::Regex to avoid UTF-8 conversion overhead.
#[derive(Clone)]
pub(crate) enum CachedRegex {
    /// String-based regex for Unicode patterns (fallback for non-ASCII patterns)
    #[allow(dead_code)]
    String(Regex),
    /// Bytes-based regex for ASCII-only patterns (much faster, no UTF-8 conversion)
    Bytes(regex::bytes::Regex),
}

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

const UTF8_CACHE_DEFAULT_SIZE: NonZeroUsize = {
    #[allow(clippy::expect_used)]
    NonZeroUsize::new(8).expect("Constant 8 is non-zero")
};

fn cache_size_from_env(var_name: &str, default: NonZeroUsize) -> NonZeroUsize {
    std::env::var(var_name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .and_then(NonZeroUsize::new)
        .unwrap_or(default)
}

/// Access the global regex cache, initializing it on first call
fn regex_cache() -> &'static RwLock<lru::LruCache<(String, bool), Regex>> {
    REGEX_CACHE.get_or_init(|| RwLock::new(lru::LruCache::new(REGEX_CACHE_SIZE)))
}

/// V2 bounded LRU cache for optimized regex (supports both string and bytes variants)
static REGEX_CACHE_V2: OnceLock<RwLock<lru::LruCache<(String, bool), CachedRegex>>> =
    OnceLock::new();

/// Access the V2 regex cache (supports both string and bytes regex)
pub(crate) fn regex_cache_v2() -> &'static RwLock<lru::LruCache<(String, bool), CachedRegex>> {
    REGEX_CACHE_V2.get_or_init(|| RwLock::new(lru::LruCache::new(REGEX_CACHE_SIZE)))
}

/// Compile regex choosing optimal variant (bytes for ASCII, string for Unicode).
/// This is a critical optimization: ASCII patterns can use bytes::Regex which operates
/// directly on bytes without UTF-8 validation, providing massive speedup.
pub(crate) fn compile_regex_optimal(
    pattern: &str,
    case_insensitive: bool,
) -> Result<CachedRegex, regex::Error> {
    // Check if pattern is ASCII-only and doesn't use Unicode features
    if pattern.is_ascii()
        && !pattern.contains("\\u")
        && !pattern.contains("\\p")
        && !pattern.contains("\\P")
    {
        // ASCII-only pattern - use bytes regex for performance
        let mut builder = regex::bytes::RegexBuilder::new(pattern);
        builder.case_insensitive(case_insensitive);
        Ok(CachedRegex::Bytes(builder.build()?))
    } else {
        // Unicode pattern - use string regex
        let mut builder = regex::RegexBuilder::new(pattern);
        builder.case_insensitive(case_insensitive);
        Ok(CachedRegex::String(builder.build()?))
    }
}

/// Log scanner cache statistics for debugging memory issues.
///
/// The lifetime-extended scanner cache was removed because it relied on
/// transmuting `yara_x::Scanner` lifetimes across rule reloads. Keep this as a
/// no-op helper so existing call sites do not need conditional compilation.
#[allow(dead_code)]
pub(crate) fn log_scanner_cache_stats() {
    tracing::debug!("YARA scanner cache statistics unavailable (cache removed for soundness)");
}

/// Clear the scanner cache for this thread.
///
/// This is a no-op because the scanner cache was removed for soundness.
#[allow(dead_code)] // Used by lib.rs via shared_resources; binary crate can't see the usage
pub(crate) fn clear_scanner_cache() {}

/// Create a Scanner for the given Rules.
#[must_use]
pub(crate) fn get_or_create_scanner(rules: &yara_x::Rules) -> yara_x::Scanner<'_> {
    yara_x::Scanner::new(rules)
}

// Thread-local cache for UTF-8 conversions to avoid repeated String::from_utf8_lossy calls.
// This is the #1 performance bottleneck - eval_raw was spending 92% of time on UTF-8 validation.
// Cache size: 32 entries provides good hit rate without excessive memory (max ~480MB for 15MB files).
thread_local! {
    /// Thread-local UTF-8 conversion cache with LRU eviction
    static UTF8_CACHE: RefCell<lru::LruCache<Utf8CacheKey, std::sync::Arc<str>>> = {
        let size = cache_size_from_env("CLEAVE_UTF8_CACHE_SIZE", UTF8_CACHE_DEFAULT_SIZE);
        RefCell::new(lru::LruCache::new(size))
    };
}

/// Cache key for UTF-8 conversion results.
/// Uses file identity (SHA256 hash) and range to uniquely identify cached conversions.
#[derive(Hash, Eq, PartialEq, Clone)]
struct Utf8CacheKey {
    /// Unique identifier for the file (u64 hash of SHA256)
    file_id: u64,
    /// Range within the file (start, end)
    range: (usize, usize),
}

/// Get cached UTF-8 conversion or perform and cache it.
/// This function is the key optimization for eval_raw performance.
///
/// # Arguments
/// * `binary_data` - The full binary data slice
/// * `range` - The (start, end) range to convert
/// * `file_id` - Unique ID for the file (hash of SHA256)
///
/// # Returns
/// Arc<str> containing the UTF-8 lossy conversion (reference counted for cheap cloning)
#[must_use]
pub(crate) fn get_utf8_cached(
    binary_data: &[u8],
    range: (usize, usize),
    file_id: u64,
) -> std::sync::Arc<str> {
    let key = Utf8CacheKey { file_id, range };

    UTF8_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();

        // Check if already in cache
        if let Some(cached) = cache.get(&key) {
            return std::sync::Arc::clone(cached);
        }

        // Not in cache - perform conversion
        let slice = &binary_data[range.0..range.1];
        let converted: std::sync::Arc<str> = String::from_utf8_lossy(slice).to_string().into();
        cache.put(key, std::sync::Arc::clone(&converted));
        converted
    })
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
#[allow(dead_code)] // Exported via lib.rs, false positive from lib/bin split
pub fn clear_thread_local_caches() {
    UTF8_CACHE.with(|cache| {
        cache.borrow_mut().clear();
    });
    crate::yara_engine::clear_engine_scanner_cache();
    ast::clear_ast_query_cache();
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
    if pattern.contains('|') || pattern.contains('*') || pattern.contains('[') {
        if let Ok(re) = build_regex(pattern, false) {
            return re.is_match(symbol);
        }
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

    // Compile outside the lock
    let regex = if case_insensitive {
        Regex::new(&format!("(?i){}", pattern))?
    } else {
        Regex::new(pattern)?
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
    } else if let Some(ref section_map) = ctx.section_map {
        if let Some((start, end)) = section_map.resolve_range(
            location.section.as_deref(),
            location.offset,
            location.offset_range,
            location.section_offset,
            location.section_offset_range,
        ) {
            (start as usize, end as usize)
        } else {
            resolve_offset_constraints(location, file_size)
        }
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

/// Resolve absolute offset constraints without SectionMap.
fn resolve_offset_constraints(
    location: &ContentLocationParams,
    file_size: usize,
) -> (usize, usize) {
    match (location.offset, &location.offset_range) {
        (Some(off), None) => {
            let resolved = if off < 0 {
                (file_size as i64 + off).max(0) as usize
            } else {
                off as usize
            };
            (resolved, file_size)
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
