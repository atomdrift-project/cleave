//! Symbol and string-based condition evaluators.
//!
//! This module handles evaluation of:
//! - Symbol matching (imports, exports)
//! - String content matching (extracted strings, raw content)
//! - Decoded string matching (Base64, XOR)
//! - String count analysis

use super::{
    ContentLocationParams, TextPattern, build_regex, match_window, resolve_effective_range,
    resolve_effective_range_opt, symbol_matches, truncate_evidence,
};
use crate::composite_rules::condition::{
    NotException, StringValidator, SymbolKind, cached_ci_searcher,
};
use crate::composite_rules::context::{ConditionResult, EvaluationContext, StringParams};
use crate::composite_rules::types::Platform;
use crate::ip_validator::{contains_external_ip_cached, contains_valid_ip};
use cleave::bitcoin_validator::contains_bitcoin_address;
use cleave::random_validator::is_random_like;
use rustc_hash::FxHashSet;
use std::sync::LazyLock;

mod raw;
#[allow(clippy::wildcard_imports)]
pub(crate) use raw::*;

mod calls;
#[allow(clippy::wildcard_imports)]
pub(crate) use calls::*;

/// Resolved once at startup. `std::env::var` calls libc `getenv`, which takes a
/// process-wide mutex on macOS — hitting that on every rule evaluation was ~3.6%
/// of total CPU as lock-wait samples across 24 rayon workers.
static PROFILE_TIMING_ENABLED: LazyLock<bool> =
    LazyLock::new(|| crate::env::flag("CLEAVE_PROFILE"));

fn section_start_location(
    report: &crate::types::AnalysisReport,
    section_name: Option<&str>,
) -> Option<String> {
    let section_name = section_name?;
    report
        .sections
        .iter()
        .find(|section| section.name == section_name)
        .and_then(|section| section.offset.or(section.address))
        .map(|offset| format!("{:#x}", offset))
}

fn string_info_location(
    report: &crate::types::AnalysisReport,
    string_info: &crate::types::StringInfo,
) -> String {
    string_info.offset.map_or_else(
        || {
            section_start_location(report, string_info.section.as_deref())
                .unwrap_or_else(|| "0x0".to_string())
        },
        |o| format!("{o:#x}"),
    )
}

/// ASCII-CI substring hits in `haystack` without allocating a lowercased copy.
/// `overlapping` matches the old `pos + 1` memmem walk used when a validator
/// or `not:` needs every start; otherwise this is non-overlapping like
/// `memchr::memmem::find_iter`.
fn for_each_ascii_ci_substr(
    haystack: &[u8],
    needle: &str,
    overlapping: bool,
    mut visit: impl FnMut(usize, usize) -> bool,
) {
    let Some(ac) = cached_ci_searcher(needle) else {
        return;
    };
    if overlapping {
        for m in ac.find_overlapping_iter(haystack) {
            if !visit(m.start(), m.end() - m.start()) {
                break;
            }
        }
    } else {
        for m in ac.find_iter(haystack) {
            if !visit(m.start(), m.end() - m.start()) {
                break;
            }
        }
    }
}

/// Helper to apply high-fidelity validation checks to a string match.
pub(crate) fn validate_match(s: &str, validator: Option<StringValidator>) -> bool {
    match validator {
        None => true,
        Some(StringValidator::Base64) => crate::base64_validator::is_base64(s),
        Some(StringValidator::ExternalIp) => contains_external_ip_cached(s),
        Some(StringValidator::ValidIp) => contains_valid_ip(s),
        Some(StringValidator::BitcoinAddr) => contains_bitcoin_address(s),
        Some(StringValidator::RandomLike) => is_random_like(s),
    }
}
use crate::types::binary::normalize_symbol;
use crate::types::{Evidence, MAX_EVIDENCE_PER_TRAIT, truncate_evidence_value};

/// Maximum number of matches to process from regex find_iter() to prevent DoS on pattern-dense files
const MAX_MATCHES_TO_PROCESS: usize = 10_000;

/// Keep locations attached to the text and source span they actually matched.
/// A regex can match different values and lengths; borrowing the first value
/// for every offset produces incorrect evidence after proximity filtering.
fn record_raw_match(evidence: &mut Vec<Evidence>, value: &str, offset: usize, length: usize) {
    let match_len = (length != value.len()).then_some(length as u64);
    if let Some(existing) = evidence
        .iter_mut()
        .find(|item| item.value == value && item.match_len == match_len)
    {
        existing.offsets.push(offset as u64);
        existing.count += 1;
    } else if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
        evidence.push(Evidence {
            method: "raw".to_string(),
            source: "raw_content".to_string(),
            value: value.to_string(),
            location: Some(format!("0x{offset:x}")),
            offsets: vec![offset as u64],
            count: 1,
            match_len,
            ..Default::default()
        });
    }
}

thread_local! {
    /// Per-thread flag: does the trait currently being evaluated need the exact
    /// `match_count`? Set by [`MatchCountGuard`] at the top of each trait's
    /// evaluation. Default `true` = safe (full count) for any direct caller
    /// (tests, `cleave test-rules`) that doesn't install a guard. When `false`,
    /// `eval_raw` stops at the first passing match (the dominant RSS lever).
    static NEEDS_MATCH_COUNT: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
    static NEEDS_MATCH_LOCATIONS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    /// How many matches the current trait's count/density filters can
    /// distinguish: `usize::MAX` when it has a ceiling (exact count needed),
    /// otherwise the largest floor. Set by [`MatchCountBoundGuard`].
    static MATCH_COUNT_BOUND: std::cell::Cell<usize> = const { std::cell::Cell::new(usize::MAX) };
}

/// Matches past this many cannot change the current trait's verdict: its
/// filters are floors (`count_min`, `per_kb_min`) and every floor is met.
/// `usize::MAX` means every match counts (a ceiling filter, a proximity
/// consumer that reads locations, or no guard installed). An evaluator may
/// stop enumerating once the count reaches this bound AND its evidence list
/// is full, so the finding it produces is identical to the exhaustive one:
/// the count is read only by those filters and the evidence is the same
/// first `MAX_EVIDENCE_PER_TRAIT` entries. A rule such as
/// `(array (string) (string) (string))` with `count_min: 3` enumerates every
/// ordered triple of a minified bundle's string table otherwise: cubic
/// matches that burned the whole 5 s AST budget on 87 KB files.
pub(crate) fn match_count_bound() -> usize {
    if NEEDS_MATCH_LOCATIONS.with(std::cell::Cell::get) {
        return usize::MAX;
    }
    MATCH_COUNT_BOUND.with(std::cell::Cell::get)
}

/// RAII guard for [`match_count_bound`], restored on drop like
/// [`MatchCountGuard`].
#[must_use]
pub(crate) struct MatchCountBoundGuard(usize);

impl MatchCountBoundGuard {
    pub(crate) fn set(bound: usize) -> Self {
        Self(MATCH_COUNT_BOUND.with(|c| c.replace(bound)))
    }
}

impl Drop for MatchCountBoundGuard {
    fn drop(&mut self) {
        MATCH_COUNT_BOUND.with(|c| c.set(self.0));
    }
}

/// Preserve locations for proximity consumers, including nested trait refs.
/// Unlike counts, this requirement must survive inner evaluation guards.
#[must_use]
pub(crate) struct MatchLocationsGuard(bool);

impl MatchLocationsGuard {
    pub(crate) fn set(needs: bool) -> Self {
        Self(NEEDS_MATCH_LOCATIONS.with(|cell| cell.replace(cell.get() || needs)))
    }
}

impl Drop for MatchLocationsGuard {
    fn drop(&mut self) {
        NEEDS_MATCH_LOCATIONS.with(|cell| cell.set(self.0));
    }
}

/// Read the per-thread "needs exact match_count" flag.
pub(crate) fn match_count_needed() -> bool {
    NEEDS_MATCH_COUNT.with(std::cell::Cell::get) || NEEDS_MATCH_LOCATIONS.with(std::cell::Cell::get)
}

/// RAII guard that sets the per-thread `NEEDS_MATCH_COUNT` flag for the duration
/// of a trait's evaluation and restores the previous value on drop — so a nested
/// trait reference (`Condition::Trait`) can't clobber the outer trait's setting.
#[must_use]
pub(crate) struct MatchCountGuard(bool);

impl MatchCountGuard {
    pub(crate) fn set(needs: bool) -> Self {
        Self(NEEDS_MATCH_COUNT.with(|c| c.replace(needs)))
    }
}

impl Drop for MatchCountGuard {
    fn drop(&mut self) {
        NEEDS_MATCH_COUNT.with(|c| c.set(self.0));
    }
}

/// Parse a hex-prefixed byte offset string like `"0x1234"`. Accepts
/// decimal too for robustness. Returns `None` on malformed input so the
/// caller can safely fall through to evidence without offsets.
#[inline]
fn parse_hex_offset(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Check if an offset falls within an effective range.
/// Returns true if no range is specified (no constraint) or if offset is within range.
#[inline]
fn offset_in_range(offset: Option<u64>, range: Option<(u64, u64)>) -> bool {
    match (offset, range) {
        (_, None) => true,        // No range constraint - all offsets match
        (None, Some(_)) => false, // Range specified but string has no offset - skip
        (Some(off), Some((start, end))) => off >= start && off < end,
    }
}

// Helper functions moved to mod.rs

/// Evaluate symbol condition - matches symbols in imports/exports/functions.
///
/// When `kind` is set, only that category is searched. When `kind` is
/// `SymbolKind::Forward`, matching is restricted to exports that carry a
/// `forward_to` target, and the pattern is tested against both the export
/// name *and* the forward target (`KERNEL32.LoadLibraryA`).
// Each parameter encodes a distinct matching mode (exact, substr, pattern, platform guard,
// validator, category filter, pre-compiled regex/finder, negation exceptions) — no
// meaningful grouping exists.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub(crate) fn eval_symbol<'a>(
    exact: Option<&String>,
    substr: Option<&String>,
    pattern: Option<&String>,
    platforms: Option<&Vec<Platform>>,
    is_check: Option<StringValidator>,
    kind: Option<SymbolKind>,
    not: Option<&Vec<NotException>>,
    alias: Option<&crate::composite_rules::condition::AliasFilter>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let _mp = crate::mem_profile::phase(crate::mem_profile::Phase::EvalSymbol);
    // Check platform constraint
    // Match if: trait allows All platforms, OR context includes All (no platform filter),
    // OR trait's platforms intersect with context's platforms
    if let Some(plats) = platforms {
        let platform_match = crate::composite_rules::platforms_intersect(plats, ctx.platforms);
        if !platform_match {
            return ConditionResult::no_match();
        }
    }

    let mut evidence = Vec::new();
    let mut match_count: usize = 0;

    // FAST PATH 0: Use pre-computed evidence from indexed matching if available.
    // Safe only when no exclusion filters, validators, or category filters narrow
    // what the index resolved — the index is built from unrestricted lookups.
    if not.is_none()
        && is_check.is_none()
        && kind.is_none()
        && let Some(trait_idx) = ctx.current_trait_idx
        && let Some(cached) = ctx.cached_evidence.and_then(|m| m.get(&trait_idx))
        && !cached.is_empty()
    {
        return ConditionResult {
            matched: true,
            evidence: cached.clone(),
            match_count: cached.len(),
            warnings: Vec::new(),
            precision: 2.0, // Symbols are high-precision by default
            matched_trait_ids: Vec::new(),
        };
    }

    // Normalize exact/substr patterns the same way symbols are normalized at load time,
    // so rule authors can write `exact: "__libc_start_main"` and it matches.
    let norm_exact = exact.map(|s| normalize_symbol(s));
    let norm_exact_ref = norm_exact.as_ref();
    let norm_substr = substr.map(|s| normalize_symbol(s));
    let norm_substr_ref = norm_substr.as_ref();

    // Resolve the substring searcher once (before the symbol loops) from the
    // process-wide shared, leaked Finder cache — built once per unique normalized
    // needle, avoiding both per-symbol `StrSearcher::new` and per-condition storage.
    let effective_finder: Option<&memchr::memmem::Finder<'static>> =
        norm_substr_ref.map(|s| crate::composite_rules::condition::cached_finder(s.as_str()));

    // Resolve the symbol regex once. Symbol regex is case-sensitive (no `(?i)`);
    // it's compiled lazily + shared via `cached_regex` rather than stored per
    // condition.
    let effective_regex_owned: Option<
        std::sync::Arc<crate::composite_rules::condition::TraitRegex>,
    > = pattern.and_then(|p| crate::composite_rules::condition::cached_regex(p.as_str()));
    let effective_regex: Option<&crate::composite_rules::condition::TraitRegex> =
        effective_regex_owned.as_deref();

    // Decide which symbol categories to walk.  `None` preserves the historical
    // behaviour of matching across all of imports/exports/functions.
    let want_imports = matches!(kind, None | Some(SymbolKind::Import));
    let want_exports = matches!(
        kind,
        None | Some(SymbolKind::Export) | Some(SymbolKind::Forward)
    );
    let forwards_only = matches!(kind, Some(SymbolKind::Forward));
    let want_functions = matches!(kind, None | Some(SymbolKind::Function));

    // Search in imports
    if want_imports {
        for import in &ctx.report.imports {
            if symbol_matches_condition(
                &import.symbol,
                norm_exact_ref,
                norm_substr_ref,
                pattern,
                effective_regex,
                effective_finder,
            ) {
                // Check if this symbol should be excluded by not: or is: filters
                let excluded_by_not = not
                    .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&import.symbol)))
                    .unwrap_or(false);
                let excluded_by_is = !validate_match(&import.symbol, is_check);
                // An `alias:` filter narrows to aliased imports (and, when it
                // carries exact/substr/regex, to a specific alias). A plain
                // import never matches when an alias filter is present.
                let alias_ok = alias.is_none_or(|af| af.matches(import.alias.as_deref()));

                if !excluded_by_not && !excluded_by_is && alias_ok {
                    match_count += 1;
                    if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                        // Call-site imports (tree-sitter extraction) carry a
                        // byte offset like "0x1234"; keep that as the location
                        // and populate `offsets` so proximity constraints
                        // (near_bytes/near_lines) can resolve a real position.
                        // Compiled-binary imports have no offset — fall back
                        // to the semantic label "import".
                        let (location, offsets) = match import.offset.as_deref() {
                            Some(off) => (
                                Some(off.to_string()),
                                parse_hex_offset(off).map_or_else(Vec::new, |o| vec![o]),
                            ),
                            None => (Some("import".to_string()), Vec::new()),
                        };
                        evidence.push(Evidence {
                            method: "symbol".to_string(),
                            value: import.symbol.clone(),
                            location,
                            offsets,
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    // Search in exports. `Forward` narrows the walk to re-exports only and
    // allows the pattern to match either side of the `export → target` edge.
    if want_exports {
        for export in &ctx.report.exports {
            if forwards_only && export.forward_to.is_none() {
                continue;
            }
            let candidates: [Option<&str>; 2] =
                [Some(export.symbol.as_str()), export.forward_to.as_deref()];
            let mut hit_value: Option<&str> = None;
            for candidate in candidates.into_iter().flatten() {
                if symbol_matches_condition(
                    candidate,
                    norm_exact_ref,
                    norm_substr_ref,
                    pattern,
                    effective_regex,
                    effective_finder,
                ) {
                    hit_value = Some(candidate);
                    break;
                }
            }
            let Some(hit) = hit_value else {
                continue;
            };

            let excluded_by_not = not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(hit)))
                .unwrap_or(false);
            let excluded_by_is = !validate_match(hit, is_check);

            if !excluded_by_not && !excluded_by_is {
                match_count += 1;
                if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    // Evidence carries the export name so operators can trace
                    // back to the row; the forward target (if any) is shown in
                    // the location column.
                    let location = match export.forward_to.as_deref() {
                        Some(target) => Some(format!("forward → {target}")),
                        None => export.offset.clone(),
                    };
                    evidence.push(Evidence {
                        method: "symbol".to_string(),
                        value: export.symbol.clone(),
                        location,
                        ..Default::default()
                    });
                }
            }
        }
    }

    // Search in internal functions (important for statically linked Go binaries)
    if want_functions {
        for func in &ctx.report.functions {
            if symbol_matches_condition(
                &func.name,
                norm_exact_ref,
                norm_substr_ref,
                pattern,
                effective_regex,
                effective_finder,
            ) {
                // Check if this symbol should be excluded by not: filters
                let excluded_by_not = not
                    .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&func.name)))
                    .unwrap_or(false);
                // `is:` applies here as it does to imports and exports; without
                // it a `kind: function` + `is: random_like` rule counted every
                // name its regex admitted.
                let excluded_by_is = !validate_match(&func.name, is_check);

                if !excluded_by_not && !excluded_by_is {
                    match_count += 1;
                    if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                        evidence.push(Evidence {
                            method: "symbol".to_string(),
                            value: func.name.clone(),
                            location: func.offset.clone(),
                            ..Default::default()
                        });
                    }
                }
            }
        }
    }

    // Calculate precision based on pattern type
    let mut precision = 0.0f32;

    if exact.is_some() {
        precision = 2.0; // Exact match
    } else if pattern.is_some() {
        precision = 1.5; // Regex pattern
    } else if substr.is_some() {
        precision = 1.0; // Substring match
    }

    // count/density constraints are now checked at trait level
    let matched = match_count > 0;

    ConditionResult {
        matched,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision,
        matched_trait_ids: Vec::new(),
    }
}

/// Check if a symbol matches an exact name, substring, or pattern.
fn symbol_matches_condition(
    symbol: &str,
    exact: Option<&String>,
    substr: Option<&String>,
    pattern: Option<&String>,
    compiled_regex: Option<&crate::composite_rules::condition::TraitRegex>,
    compiled_finder: Option<&memchr::memmem::Finder<'static>>,
) -> bool {
    // If exact is specified, do strict equality match
    if let Some(exact_val) = exact {
        return symbol == exact_val;
    }

    // If substr is specified, do substring match using the pre-compiled finder when available
    if let Some(substr_val) = substr {
        return if let Some(finder) = compiled_finder {
            finder.find(symbol.as_bytes()).is_some()
        } else {
            memchr::memmem::find(symbol.as_bytes(), substr_val.as_bytes()).is_some()
        };
    }

    // If pattern is specified, use precompiled regex if available
    if pattern.is_some() {
        if let Some(re) = compiled_regex {
            return re.is_match(symbol);
        } else if let Some(pattern_val) = pattern {
            // Fallback: use the existing pattern matching logic if not pre-compiled
            return symbol_matches(symbol, pattern_val);
        }
    }

    // Neither exact nor substr nor pattern specified - no match
    false
}

/// Whether a matched span's byte length satisfies the condition's
/// `length_min`/`length_max` bounds (always true when neither is set).
#[inline]
fn span_length_ok(len: usize, (min, max): (Option<usize>, Option<usize>)) -> bool {
    min.is_none_or(|min| len >= min) && max.is_none_or(|max| len <= max)
}

#[inline]
fn has_string_location_constraint(params: &StringParams<'_>) -> bool {
    params.section.is_some()
        || params.offset.is_some()
        || params.offset_range.is_some()
        || params.section_offset.is_some()
        || params.section_offset_range.is_some()
        || params.arch_clamp.is_some()
}

fn resolve_string_effective_range<'a>(
    params: &StringParams<'a>,
    ctx: &EvaluationContext<'_>,
) -> Option<(u64, u64)> {
    if has_string_location_constraint(params) {
        let location = ContentLocationParams {
            section: params.section.cloned(),
            offset: params.offset,
            offset_range: params.offset_range,
            section_offset: params.section_offset,
            section_offset_range: params.section_offset_range,
            arch_clamp: params.arch_clamp,
        };
        let (start, end) = resolve_effective_range(&location, ctx);
        Some((start as u64, end as u64))
    } else {
        None
    }
}

fn string_match_precision(params: &StringParams<'_>) -> f32 {
    let mut precision = 0.0f32;

    if params.exact.is_some() {
        precision += 2.0;
    } else if params.regex.is_some() || params.word.is_some() {
        precision += 1.5;
    } else if params.substr.is_some() {
        precision += 1.0;
    }

    if params.section.is_some() {
        precision += 1.0;
    }
    if params.offset.is_some() {
        precision += 1.5;
    } else if params.offset_range.is_some()
        || params.section_offset.is_some()
        || params.section_offset_range.is_some()
    {
        precision += 1.0;
    }

    if params.case_insensitive {
        precision *= 0.5;
    }

    precision
}

/// A `Text`/`Literal` value matcher resolved **once per condition**, holding
/// process-wide shared (`&'static`) searchers so the per-string inner loop does
/// zero cache lookups and takes no locks — preserving the old precompiled
/// path's hot-loop cost while keeping the matchers out of per-condition storage.
enum StringMatcher<'p> {
    Exact {
        needle: &'p str,
        ci: bool,
    },
    SubstrCs(&'static memchr::memmem::Finder<'static>),
    SubstrCi(&'static aho_corasick::AhoCorasick),
    WordCs {
        needle: &'p str,
        finder: &'static memchr::memmem::Finder<'static>,
    },
    WordCi {
        needle: &'p str,
        ac: &'static aho_corasick::AhoCorasick,
    },
    Regex(std::sync::Arc<crate::composite_rules::condition::TraitRegex>),
    /// Pattern couldn't be resolved (e.g. AC/regex build failed) — never matches.
    Never,
}

impl<'p> StringMatcher<'p> {
    fn with_batch<R>(&self, count: usize, f: impl FnOnce(&mut StringMatchBatch<'_, 'p>) -> R) -> R {
        if count > 1
            && let Self::Regex(re) = self
        {
            return re.with_scratch(|cache| {
                f(&mut StringMatchBatch {
                    matcher: self,
                    cache: Some(cache),
                })
            });
        }
        f(&mut StringMatchBatch {
            matcher: self,
            cache: None,
        })
    }

    /// Resolve the shared searcher for this condition's pattern. Takes the cache
    /// lock at most once per condition (the only `substr`/`word`/`regex` field
    /// set wins, in the historical precedence order).
    fn resolve(params: &StringParams<'p>) -> Self {
        use crate::composite_rules::condition::{cached_ci_searcher, cached_finder, lazy_regex};

        if let Some(e) = params.exact {
            return Self::Exact {
                needle: e.as_str(),
                ci: params.case_insensitive,
            };
        }
        if let Some(s) = params.substr {
            return if params.case_insensitive {
                cached_ci_searcher(s).map_or(Self::Never, Self::SubstrCi)
            } else {
                Self::SubstrCs(cached_finder(s))
            };
        }
        if let Some(w) = params.word {
            if w.is_empty() {
                return Self::Never;
            }
            return if params.case_insensitive {
                cached_ci_searcher(w).map_or(Self::Never, |ac| Self::WordCi {
                    needle: w.as_str(),
                    ac,
                })
            } else {
                Self::WordCs {
                    needle: w.as_str(),
                    finder: cached_finder(w),
                }
            };
        }
        lazy_regex(params.regex.map(String::as_str), params.case_insensitive)
            .map_or(Self::Never, Self::Regex)
    }

    /// Match `value`, returning the matched text as a **borrow into `value`** for
    /// evidence — no allocation. `word:`/`regex:` return the matched span; `substr:`
    /// and `exact:` return the whole value. Callers clone only when actually storing
    /// evidence (≤ `MAX_EVIDENCE_PER_TRAIT`), so match-counting and `not:`/`is:`
    /// filtering on non-stored matches cost zero allocations.
    fn match_value_ref<'v>(&self, value: &'v str) -> Option<&'v str> {
        use crate::composite_rules::condition::{word_match_ci, word_match_cs};
        match self {
            Self::Exact { needle, ci } => {
                let matched = if *ci {
                    value.eq_ignore_ascii_case(needle)
                } else {
                    value == *needle
                };
                matched.then_some(value)
            }
            Self::SubstrCs(finder) => finder.find(value.as_bytes()).is_some().then_some(value),
            Self::SubstrCi(ac) => ac.is_match(value).then_some(value),
            Self::WordCs { needle, finder } => {
                word_match_cs(value, needle, finder).map(|s| &value[s..s + needle.len()])
            }
            Self::WordCi { needle, ac } => {
                word_match_ci(value, needle, ac).map(|s| &value[s..s + needle.len()])
            }
            Self::Regex(re) => re.find_str(value),
            Self::Never => None,
        }
    }

    /// [`Self::match_value_ref`] under `length_min`/`length_max` bounds:
    /// returns the first match whose span satisfies them. For regex matchers
    /// this scans past non-qualifying spans — a first-match-only check would
    /// miss a qualifying run appearing later in the same string (e.g. `[a-z]+`
    /// finds a 2-char word before the 5000-char run `length_min` wants).
    fn match_value_bounded<'v>(
        &self,
        value: &'v str,
        bounds: (Option<usize>, Option<usize>),
    ) -> Option<&'v str> {
        if bounds == (None, None) {
            return self.match_value_ref(value);
        }
        match self {
            Self::Regex(re) => {
                let mut found = None;
                re.for_each_find(value, |_, span| {
                    if span_length_ok(span.len(), bounds) {
                        found = Some(span);
                        false
                    } else {
                        true
                    }
                });
                found
            }
            _ => self
                .match_value_ref(value)
                .filter(|span| span_length_ok(span.len(), bounds)),
        }
    }
}

/// The scratch lease belongs to exactly the regex in `matcher`. Searches still
/// receive separate inputs, so anchors and matches cannot cross string boundaries.
struct StringMatchBatch<'m, 'p> {
    matcher: &'m StringMatcher<'p>,
    cache: Option<&'m mut regex_automata::meta::Cache>,
}

impl StringMatchBatch<'_, '_> {
    fn match_value_bounded<'v>(
        &mut self,
        value: &'v str,
        bounds: (Option<usize>, Option<usize>),
    ) -> Option<&'v str> {
        let (StringMatcher::Regex(re), Some(cache)) = (self.matcher, self.cache.as_deref_mut())
        else {
            return self.matcher.match_value_bounded(value, bounds);
        };
        if bounds == (None, None) {
            return re.find_str_cached(value, cache);
        }
        let mut found = None;
        re.for_each_find_cached(value, cache, |_, span| {
            if span_length_ok(span.len(), bounds) {
                found = Some(span);
                false
            } else {
                true
            }
        });
        found
    }
}

fn cached_text_evidence(cached: &[Evidence]) -> Vec<Evidence> {
    cached
        .iter()
        .filter(|ev| ev.source == "string_extractor")
        .map(|ev| {
            let mut ev = ev.clone();
            ev.method = "text".to_string();
            ev
        })
        .collect()
}

/// Evaluate a `type: comment` condition against the dedicated comment
/// corpus (`report.comments`). This is the lowest-false-positive string
/// tier: comment bodies never contain code or string-literal content, so
/// a keyword match here means the keyword genuinely appears in a comment
/// — not in a variable name, a call, or a string. Replaces tree-sitter
/// `kind: comment` queries without a per-rule parse.
pub(crate) fn eval_comment<'a, 'b>(
    params: &StringParams<'a>,
    trait_not: Option<&Vec<NotException>>,
    ctx: &EvaluationContext<'b>,
) -> ConditionResult {
    let regex = params
        .regex
        .and_then(|r| build_regex(r, params.case_insensitive).ok());
    let word_regex = params.word.and_then(|w| {
        build_regex(
            &format!(r"\b{}\b", regex::escape(w)),
            params.case_insensitive,
        )
        .ok()
    });
    let mut evidence = Vec::new();
    let mut match_count = 0usize;
    for c in &ctx.report.comments {
        let v = c.value.as_str();
        let hit = if let Some(e) = params.exact {
            if params.case_insensitive {
                v.eq_ignore_ascii_case(e)
            } else {
                v == e
            }
        } else if let Some(s) = params.substr {
            if params.case_insensitive {
                v.to_lowercase().contains(&s.to_lowercase())
            } else {
                v.contains(s)
            }
        } else if let Some(re) = &regex {
            re.is_match(v)
        } else if let Some(re) = &word_regex {
            re.is_match(v)
        } else {
            false
        };
        if !hit || !validate_match(v, params.is_check) {
            continue;
        }
        if trait_not.is_some_and(|ex| ex.iter().any(|e| e.matches(v))) {
            continue;
        }
        match_count += 1;
        if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
            evidence.push(Evidence {
                method: "comment".to_string(),
                source: "comment".to_string(),
                value: truncate_evidence(v, 100),
                location: Some(
                    c.offset
                        .map(|o| format!("@{o}"))
                        .unwrap_or_else(|| "0x0".to_string()),
                ),
                offsets: c.offset.map(|o| vec![o]).unwrap_or_default(),
                // Span the whole comment by its true byte length — `value` above
                // is truncated for display (char-capped, with an ellipsis), so
                // its length is not the comment's.
                match_len: Some(v.len() as u64),
                ..Default::default()
            });
        }
    }
    if match_count == 0 {
        return ConditionResult::no_match();
    }
    ConditionResult {
        matched: true,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision: 2.0,
        matched_trait_ids: Vec::new(),
    }
}

/// Evaluate string condition - searches in properly extracted/bounded strings,
/// as well as imports and exports if they match the string criteria.
///
/// For searching raw file content, use `eval_raw()` instead.
#[must_use]
/// Evaluate text condition.
///
/// On source and structured text formats this delegates to raw-content search.
/// On binary-like formats it searches extracted strings only.
pub(crate) fn eval_text<'a, 'b>(
    params: &StringParams<'a>,
    trait_not: Option<&Vec<NotException>>,
    ctx: &EvaluationContext<'b>,
    trait_id: Option<&str>,
) -> ConditionResult {
    let _mp = crate::mem_profile::phase(crate::mem_profile::Phase::EvalText);
    if ctx.file_type.uses_raw_text_search_for(ctx.binary_data) {
        let comment_free_context = if params.exclude_html_comments {
            ctx.html_comment_free_source().map(|source| {
                let mut masked = ctx.clone();
                masked.binary_data = source;
                masked
            })
        } else {
            None
        };
        let raw_context = comment_free_context.as_ref().unwrap_or(ctx);
        let location = ContentLocationParams {
            section: params.section.cloned(),
            offset: params.offset,
            offset_range: params.offset_range,
            section_offset: params.section_offset,
            section_offset_range: params.section_offset_range,
            arch_clamp: params.arch_clamp,
        };
        let raw = eval_raw(
            TextPattern {
                exact: params.exact,
                substr: params.substr,
                regex: params.regex,
                word: params.word,
                case_insensitive: params.case_insensitive,
            },
            (params.length_min, params.length_max),
            params.is_check,
            trait_not,
            &location,
            raw_context,
            trait_id,
        );
        // Second pass over decoded string layers (base64/xor/…). The raw pass
        // above already covers plain text and plain string literals, so this
        // scans only strings carrying an `encoding_chain` — content the raw bytes
        // can't reveal, e.g. a `jsonkeeper.com` URL hidden in a base64 literal.
        // The two passes are disjoint by construction (decoded values aren't
        // present verbatim in the raw bytes), so results union with no dedup.
        // Gated on the file actually having decoded layers, so the >99% of files
        // with none pay only this `is_empty()` check.
        if ctx.encoded_strings().is_empty() {
            return raw;
        }
        // `encoding: none` opts the condition out of the decoded pass. A
        // matcher that describes the file's own markup must not fire on bytes
        // that only look like markup once decoded -- an RTF's embedded hex
        // picture holding a run of `7b` decodes to `{{{{{{{{{`, which is not
        // brace nesting.
        if matches!(
            params.encoding,
            Some(crate::composite_rules::condition::TextEncodingScope::None)
        ) {
            return raw;
        }
        // The raw-content gate swept the decoded values for atoms: when this
        // very `if:` pattern's atoms are absent there, the per-string pass
        // cannot match and is skipped (`decoded_skip` is keyed on the pattern
        // text so an `unless:` sharing the trait index still runs).
        if let Some(idx) = ctx.current_trait_idx
            && let Some(skip) = ctx.decoded_skip
            && let Some(&indexed) = skip.get(&idx)
            && params
                .regex
                .map(String::as_str)
                .or(params.word.map(String::as_str))
                == Some(indexed)
        {
            super::raw_window_stats::bump(&super::raw_window_stats::DECODED_SKIPPED);
            return raw;
        }
        super::raw_window_stats::bump(&super::raw_window_stats::DECODED_SWEPT);
        return merge_text_passes(raw, eval_text_encoded(params, trait_not, ctx));
    }

    // Past this point the scan runs over `report.strings`, which holds the
    // decoded layers alongside the literal ones, so `encoding: none` has to be
    // honoured here too -- the early return above only covers file types that
    // use raw text search. An RTF is not one of them: its embedded picture hex
    // is extracted and decoded, and a run of 0x7B decodes to a brace run that
    // never appears in the markup.
    let skip_decoded = matches!(
        params.encoding,
        Some(crate::composite_rules::condition::TextEncodingScope::None)
    );
    let effective_range = resolve_string_effective_range(params, ctx);
    let has_location_constraint = has_string_location_constraint(params);

    // The precomputed evidence cache does not record which layer each hit came
    // from, so a condition that has opted out of the decoded layers cannot be
    // answered from it. Skipping the cache keeps `analyze` agreeing with
    // `test-rules` and `test match`, which have no cache and always walk the
    // strings below.
    if !skip_decoded
        && !has_location_constraint
        && trait_not.is_none()
        && params.is_check.is_none()
        && params.length_min.is_none()
        && params.length_max.is_none()
        && let Some(trait_idx) = ctx.current_trait_idx
        && let Some(cached) = ctx.cached_evidence.and_then(|m| m.get(&trait_idx))
    {
        let evidence = cached_text_evidence(cached);
        if !evidence.is_empty() {
            return ConditionResult {
                matched: true,
                match_count: evidence.len(),
                evidence,
                warnings: Vec::new(),
                precision: string_match_precision(params),
                matched_trait_ids: Vec::new(),
            };
        }
    }

    if let Some(exact_str) = params.exact
        && effective_range.is_none()
    {
        let mut evidence = Vec::new();

        if params.case_insensitive {
            if let Some(match_list) = ctx.string_exact_index_ci().get(&exact_str.to_lowercase()) {
                for &idx in match_list.iter().take(MAX_EVIDENCE_PER_TRAIT) {
                    let s = &ctx.report.strings[idx as usize];
                    if skip_decoded && !s.encoding_chain.is_empty() {
                        continue;
                    }
                    let original_value = s.value.as_str();
                    let excluded_by_not = trait_not
                        .map(|exceptions| exceptions.iter().any(|exc| exc.matches(original_value)))
                        .unwrap_or(false);
                    let excluded_by_is = !validate_match(original_value, params.is_check);

                    if !excluded_by_not && !excluded_by_is {
                        evidence.push(Evidence {
                            method: "text".to_string(),
                            source: "string_extractor".to_string(),
                            value: truncate_evidence_value(original_value),
                            location: Some(string_info_location(ctx.report, s)),
                            ..Default::default()
                        });
                    }
                }
            }
        } else if let Some(match_list) = ctx.string_exact_index().get(exact_str.as_str()) {
            for &idx in match_list.iter().take(MAX_EVIDENCE_PER_TRAIT) {
                let s = &ctx.report.strings[idx as usize];
                if skip_decoded && !s.encoding_chain.is_empty() {
                    continue;
                }
                let excluded_by_not = trait_not
                    .map(|exceptions| exceptions.iter().any(|exc| exc.matches(exact_str)))
                    .unwrap_or(false);
                let excluded_by_is = !validate_match(exact_str, params.is_check);

                if !excluded_by_not && !excluded_by_is {
                    evidence.push(Evidence {
                        method: "text".to_string(),
                        source: "string_extractor".to_string(),
                        value: truncate_evidence_value(exact_str),
                        location: Some(string_info_location(ctx.report, s)),
                        ..Default::default()
                    });
                }
            }
        }

        return ConditionResult {
            matched: !evidence.is_empty(),
            match_count: evidence.len(),
            evidence,
            warnings: Vec::new(),
            precision: string_match_precision(params),
            matched_trait_ids: Vec::new(),
        };
    }

    // Resolve the shared matcher once, then match every string with no further
    // cache lookups or locks in the hot loop.
    let matcher = StringMatcher::resolve(params);

    let mut evidence = Vec::new();
    let mut match_count = 0usize;
    let needs_count = match_count_needed();
    let count_bound = match_count_bound();

    // A `word:`/`regex:` `if:` can only match inside a string that holds one
    // of its mandatory atoms; the prefilter recorded those strings' indices
    // (see `EvaluationContext::regex_candidate_strings`). Sweep just those,
    // in order, so evidence, count and the early break are unchanged. The
    // key is the pattern `StringMatcher::resolve` picks, so an `unless:`
    // or a differently-shaped condition on the same trait never borrows it.
    let candidate_strings: Option<&[u32]> = match ctx.current_trait_idx {
        Some(idx) if params.exact.is_none() && params.substr.is_none() => params
            .word
            .map(String::as_str)
            .or(params.regex.map(String::as_str))
            .and_then(|key| {
                ctx.regex_candidate_strings
                    .and_then(|m| m.get(&idx))
                    .filter(|(pattern, _)| *pattern == key)
                    .map(|(_, list)| *list)
            }),
        _ => None,
    };

    matcher.with_batch(ctx.report.strings.len(), |matcher| {
        let mut visit = |string_info: &crate::types::StringInfo| -> bool {
            if skip_decoded && !string_info.encoding_chain.is_empty() {
                return true;
            }
            if !offset_in_range(string_info.offset, effective_range) {
                return true;
            }

            if let Some(match_value) = matcher
                .match_value_bounded(&string_info.value, (params.length_min, params.length_max))
            {
                let excluded_by_not = trait_not
                    .map(|exceptions| exceptions.iter().any(|exc| exc.matches(match_value)))
                    .unwrap_or(false);
                let excluded_by_is = !validate_match(match_value, params.is_check);

                if !excluded_by_not && !excluded_by_is {
                    match_count += 1;
                    // Allocate the evidence string only when actually storing it.
                    if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                        // `match_value` is a subslice of the string for word/regex
                        // matches (e.g. `.dll` inside `name.dll`); offset it within
                        // the string so the location points at the match, not the
                        // enclosing string's start. A string that carries no offset
                        // (version-resource/derived entries) still anchors via
                        // `string_info_location` (its section start, else `0x0`) —
                        // mirrors the exact-match branch above and `eval_string_literal`,
                        // so a content match never reaches `report_unanchored` locationless.
                        // A parsed literal may be reconstructed or UTF-16, so a
                        // decoded substring index is not a file displacement at
                        // all; those keep the parser's own anchor.
                        let within = if string_info.section.as_deref() == Some("literal") {
                            0
                        } else {
                            (match_value.as_ptr() as usize)
                                .saturating_sub(string_info.value.as_ptr() as usize)
                                as u64
                        };
                        let location = match string_info.offset {
                            Some(o) => format!("{:#x}", o.saturating_add(within)),
                            None => string_info_location(ctx.report, string_info),
                        };
                        evidence.push(Evidence {
                            method: "text".to_string(),
                            source: "string_extractor".to_string(),
                            value: truncate_evidence_value(match_value),
                            location: Some(location),
                            ..Default::default()
                        });
                    }
                    // Boolean consumers cannot use the remaining count. Keep
                    // the exact same capped evidence (including exclusions and
                    // offsets), then avoid sweeping every native string after
                    // enough accepted hits have already filled that evidence.
                    // A floor-only count filter already met is the same
                    // case: see `match_count_bound`.
                    if (!needs_count || match_count >= count_bound)
                        && evidence.len() >= MAX_EVIDENCE_PER_TRAIT
                    {
                        return false;
                    }
                }
            }
            true
        };
        match candidate_strings {
            Some(list) => {
                for &i in list {
                    let Some(string_info) = ctx.report.strings.get(i as usize) else {
                        break;
                    };
                    if !visit(string_info) {
                        break;
                    }
                }
            }
            None => {
                for string_info in &ctx.report.strings {
                    if !visit(string_info) {
                        break;
                    }
                }
            }
        }
    });

    ConditionResult {
        matched: match_count > 0,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision: string_match_precision(params),
        matched_trait_ids: Vec::new(),
    }
}

/// Byte length of the *encoded* source that produced a `decoded_len`-byte string
/// through `encoding_chain`. A `type: text` match on decoded content must span
/// the encoded bytes in the source, not the shorter decoded length — e.g. the 34
/// decoded bytes of a `jsonkeeper.com` URL occupy 48 base64 bytes. Returns
/// `None` for chains we can't size precisely (multi-layer, or encodings that
/// aren't a fixed expansion), so callers fall back to the decoded length.
#[must_use]
pub(crate) fn encoded_source_len(decoded_len: usize, encoding_chain: &[String]) -> Option<u64> {
    match encoding_chain {
        // Standard base64 packs 3 source bytes into 4 padded chars.
        [layer] if layer == "base64" => Some((decoded_len.div_ceil(3) * 4) as u64),
        _ => None,
    }
}

/// Second `type: text` pass: match `params` against decoded string layers only
/// — entries with a non-empty `encoding_chain` (base64/xor/…). The raw pass in
/// [`eval_text`] handles plain text and literals, so this surfaces patterns that
/// appear only after decoding. Scans [`EvaluationContext::encoded_strings`], so
/// cost scales with the (usually zero) number of decoded strings, not the whole
/// haystack.
#[must_use]
fn eval_text_encoded<'a, 'b>(
    params: &StringParams<'a>,
    trait_not: Option<&Vec<NotException>>,
    ctx: &EvaluationContext<'b>,
) -> ConditionResult {
    let effective_range = resolve_string_effective_range(params, ctx);
    let matcher = StringMatcher::resolve(params);

    let mut evidence = Vec::new();
    let mut match_count = 0usize;

    matcher.with_batch(ctx.encoded_strings().len(), |matcher| {
        for &idx in ctx.encoded_strings() {
            let string_info = &ctx.report.strings[idx as usize];
            if !offset_in_range(string_info.offset, effective_range) {
                continue;
            }

            let Some(match_value) = matcher
                .match_value_bounded(&string_info.value, (params.length_min, params.length_max))
            else {
                continue;
            };
            let excluded_by_not = trait_not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(match_value)))
                .unwrap_or(false);
            let excluded_by_is = !validate_match(match_value, params.is_check);
            if excluded_by_not || excluded_by_is {
                continue;
            }

            match_count += 1;
            if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                // The match lives inside an encoded blob: a sub-offset into the
                // decoded value has no meaning in the source byte space, so anchor at
                // the string's offset and span the *encoded* source bytes — not the
                // shorter decoded length (see `encoded_source_len`). An offset-less
                // entry still anchors via `string_info_location` (section start, else
                // `0x0`), so the match never reaches `report_unanchored` locationless.
                //
                // Proximity (`near_bytes`/`near_lines`) reads `offsets`, not the
                // anchor: without them every hit in one decoded layer tags as the
                // layer's start, so two matches thousands of bytes apart inside a
                // single layer (e.g. an `unicode-escape` layer spanning a whole
                // minified file) look adjacent. Record where the match sits within
                // the layer — exact to the base64 quad for base64, decoded bytes
                // otherwise — clamped to the file so it stays a real offset.
                let offsets = string_info.offset.map_or_else(Vec::new, |anchor| {
                    let within = (match_value.as_ptr() as usize)
                        .saturating_sub(string_info.value.as_ptr() as usize);
                    let within = match string_info.encoding_chain.as_slice() {
                        [layer] if layer == "base64" => within / 3 * 4,
                        _ => within,
                    } as u64;
                    let last = (ctx.binary_data.len() as u64).saturating_sub(1);
                    vec![anchor.saturating_add(within).min(last.max(anchor))]
                });
                evidence.push(Evidence {
                    method: "text".to_string(),
                    source: "string_extractor".to_string(),
                    value: truncate_evidence_value(match_value),
                    location: Some(string_info_location(ctx.report, string_info)),
                    offsets,
                    match_len: encoded_source_len(
                        string_info.value.len(),
                        &string_info.encoding_chain,
                    ),
                    ..Default::default()
                });
            }
        }
    });

    ConditionResult {
        matched: match_count > 0,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision: string_match_precision(params),
        matched_trait_ids: Vec::new(),
    }
}

/// Union the raw and encoded `type: text` passes. Evidence concatenates (capped
/// at `MAX_EVIDENCE_PER_TRAIT`), match counts sum, and precision takes the higher
/// of the two so an encoded-layer hit isn't penalised by the raw pass's miss.
/// The passes never match the same content (one searches raw bytes, the other
/// decoded layers), so no deduplication is needed.
#[must_use]
fn merge_text_passes(mut raw: ConditionResult, mut encoded: ConditionResult) -> ConditionResult {
    if !encoded.matched {
        return raw;
    }
    if !raw.matched {
        return encoded;
    }
    raw.match_count += encoded.match_count;
    let room = MAX_EVIDENCE_PER_TRAIT.saturating_sub(raw.evidence.len());
    if room > 0 {
        encoded.evidence.truncate(room);
        raw.evidence.append(&mut encoded.evidence);
    }
    raw.precision = raw.precision.max(encoded.precision);
    raw.warnings.append(&mut encoded.warnings);
    raw.matched_trait_ids.append(&mut encoded.matched_trait_ids);
    raw
}

/// Evaluate string literals from source ASTs or format parsers.
#[must_use]
#[cfg(feature = "lint")]
pub(crate) fn eval_string_literal<'a, 'b>(
    params: &StringParams<'a>,
    trait_not: Option<&Vec<NotException>>,
    ctx: &EvaluationContext<'b>,
) -> ConditionResult {
    eval_string_literal_with_options(params, trait_not, ctx, false)
}

/// Evaluate source and format literals, optionally excluding Python
/// docstrings where a documented value is not evidence of program behavior.
#[must_use]
pub(crate) fn eval_string_literal_with_options<'a, 'b>(
    params: &StringParams<'a>,
    trait_not: Option<&Vec<NotException>>,
    ctx: &EvaluationContext<'b>,
    exclude_docstrings: bool,
) -> ConditionResult {
    let effective_range = resolve_string_effective_range(params, ctx);
    let matcher = StringMatcher::resolve(params);

    let mut evidence = Vec::new();
    let mut match_count = 0usize;
    // Tree-sitter grammars can expose both an enclosing string node and a
    // nested string-content node. Count a source match once by its concrete
    // byte span, regardless of how many parser projections reported it.
    let mut seen_match_spans: FxHashSet<(u64, usize)> = FxHashSet::default();

    let literals = ctx.literal_strings();
    matcher.with_batch(literals.len(), |matcher| {
        for &index in literals {
            let string_info = &ctx.report.strings[index as usize];
            if exclude_docstrings && string_info.section.as_deref() == Some("ast-docstring") {
                continue;
            }
            if !offset_in_range(string_info.offset, effective_range) {
                continue;
            }

            if let Some(match_value) = matcher
                .match_value_bounded(&string_info.value, (params.length_min, params.length_max))
            {
                let excluded_by_not = trait_not
                    .map(|exceptions| exceptions.iter().any(|exc| exc.matches(match_value)))
                    .unwrap_or(false);
                let excluded_by_is = !validate_match(match_value, params.is_check);

                if !excluded_by_not && !excluded_by_is {
                    let within = (match_value.as_ptr() as usize)
                        .saturating_sub(string_info.value.as_ptr() as usize)
                        as u64;
                    // A compiled literal may be UTF-16 or reconstructed from many
                    // instructions. Its decoded substring index is not a byte
                    // displacement in the file; preserve the parser's anchor.
                    let match_offset = if string_info.section.as_deref() == Some("literal") {
                        string_info.offset
                    } else {
                        string_info.offset.map(|o| o.saturating_add(within))
                    };
                    if let Some(offset) = match_offset
                        && !seen_match_spans.insert((offset, match_value.len()))
                    {
                        continue;
                    }
                    match_count += 1;
                    // Allocate the evidence string only when actually storing it.
                    if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                        // `match_value` is a subslice for word/regex matches; offset
                        // it within the literal so the location points at the match,
                        // not the enclosing literal's start (mirrors `eval_text`).
                        let location = match match_offset {
                            Some(o) => format!("{:#x}", o),
                            None => string_info_location(ctx.report, string_info),
                        };
                        evidence.push(Evidence {
                            method: "string_literal".to_string(),
                            source: string_info.section.clone().unwrap_or_default(),
                            value: truncate_evidence_value(match_value),
                            location: Some(location),
                            ..Default::default()
                        });
                    }
                    // Count/density and proximity consumers retain the full
                    // enumeration; a boolean literal condition is settled.
                    if !match_count_needed() {
                        break;
                    }
                }
            }
        }
    });

    ConditionResult {
        matched: match_count > 0,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision: string_match_precision(params),
        matched_trait_ids: Vec::new(),
    }
}

/// Evaluate raw content condition - searches directly in file bytes as text.
///
/// Determines if a pattern can be matched on raw bytes (ASCII-only, no Unicode features).
/// Returns true if the pattern contains only ASCII characters and doesn't use Unicode escapes.
#[inline]
fn can_use_byte_matching(pattern: &str) -> bool {
    pattern.is_ascii()
        && (!pattern.contains('\\')
            || (!pattern.contains("\\u") && !pattern.contains("\\p") && !pattern.contains("\\P")))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cloned_ref_to_slice_refs
)]
mod multi_arg_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod validator_wiring_tests;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod batch_match_tests;
