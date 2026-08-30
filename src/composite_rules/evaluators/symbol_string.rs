//! Symbol and string-based condition evaluators.
//!
//! This module handles evaluation of:
//! - Symbol matching (imports, exports)
//! - String content matching (extracted strings, raw content)
//! - Decoded string matching (Base64, XOR)
//! - String count analysis

use super::{
    ContentLocationParams, build_regex, match_window, resolve_effective_range,
    resolve_effective_range_opt, symbol_matches, truncate_evidence,
};
use crate::composite_rules::condition::{
    NotException, StringValidator, SymbolKind, cached_ci_searcher,
};
use crate::composite_rules::context::{ConditionResult, EvaluationContext, StringParams};
use crate::composite_rules::types::Platform;
use crate::ip_validator::{contains_external_ip_cached, contains_valid_ip};
use cleave::bitcoin_validator::contains_bitcoin_address;
use rustc_hash::FxHashSet;
use std::sync::LazyLock;

/// Resolved once at startup. `std::env::var` calls libc `getenv`, which takes a
/// process-wide mutex on macOS — hitting that on every rule evaluation was ~3.6%
/// of total CPU as lock-wait samples across 24 rayon workers.
static PROFILE_TIMING_ENABLED: LazyLock<bool> =
    LazyLock::new(|| std::env::var("CLEAVE_PROFILE").is_ok());

fn offset_location(offset: Option<u64>, fallback: impl FnOnce() -> String) -> String {
    offset.map(|o| format!("{:#x}", o)).unwrap_or_else(fallback)
}

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
    offset_location(string_info.offset, || {
        section_start_location(report, string_info.section.as_deref())
            .unwrap_or_else(|| "0x0".to_string())
    })
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
        Some(StringValidator::ExternalIp) => contains_external_ip_cached(s),
        Some(StringValidator::ValidIp) => contains_valid_ip(s),
        Some(StringValidator::BitcoinAddr) => contains_bitcoin_address(s),
    }
}
use crate::types::binary::normalize_symbol;
use crate::types::{Evidence, MAX_EVIDENCE_PER_TRAIT, truncate_evidence_value};

/// Maximum number of matches to process from regex find_iter() to prevent DoS on pattern-dense files
const MAX_MATCHES_TO_PROCESS: usize = 10_000;

thread_local! {
    /// Per-thread flag: does the trait currently being evaluated need the exact
    /// `match_count`? Set by [`MatchCountGuard`] at the top of each trait's
    /// evaluation. Default `true` = safe (full count) for any direct caller
    /// (tests, `cleave test-rules`) that doesn't install a guard. When `false`,
    /// `eval_raw` stops at the first passing match (the dominant RSS lever).
    static NEEDS_MATCH_COUNT: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// Read the per-thread "needs exact match_count" flag.
fn match_count_needed() -> bool {
    NEEDS_MATCH_COUNT.with(std::cell::Cell::get)
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
    // Match if: trait allows All platforms, OR context includes All (no --platforms filter),
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

                if !excluded_by_not {
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
    if ctx.file_type.uses_raw_text_search() {
        let location = ContentLocationParams {
            section: params.section.cloned(),
            offset: params.offset,
            offset_range: params.offset_range,
            section_offset: params.section_offset,
            section_offset_range: params.section_offset_range,
            arch_clamp: params.arch_clamp,
        };
        let raw = eval_raw(
            params.exact,
            params.substr,
            params.regex,
            params.word,
            params.case_insensitive,
            (params.length_min, params.length_max),
            params.is_check,
            trait_not,
            &location,
            ctx,
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
        return merge_text_passes(raw, eval_text_encoded(params, trait_not, ctx));
    }

    let effective_range = resolve_string_effective_range(params, ctx);
    let has_location_constraint = has_string_location_constraint(params);

    if !has_location_constraint
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
            if let Some(match_list) = ctx
                .get_string_exact_index_ci()
                .get(&exact_str.to_lowercase())
            {
                for &idx in match_list.iter().take(MAX_EVIDENCE_PER_TRAIT) {
                    let s = &ctx.report.strings[idx as usize];
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
        } else if let Some(match_list) = ctx.get_string_exact_index().get(exact_str.as_str()) {
            for &idx in match_list.iter().take(MAX_EVIDENCE_PER_TRAIT) {
                let s = &ctx.report.strings[idx as usize];
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

    for string_info in &ctx.report.strings {
        if !offset_in_range(string_info.offset, effective_range) {
            continue;
        }

        if let Some(match_value) =
            matcher.match_value_bounded(&string_info.value, (params.length_min, params.length_max))
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
                    // so a content match never reaches `fallback_anchor` locationless.
                    let within = (match_value.as_ptr() as usize)
                        .saturating_sub(string_info.value.as_ptr() as usize)
                        as u64;
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
            }
        }
    }

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

    for &idx in ctx.encoded_strings() {
        let string_info = &ctx.report.strings[idx as usize];
        if !offset_in_range(string_info.offset, effective_range) {
            continue;
        }

        let Some(match_value) =
            matcher.match_value_bounded(&string_info.value, (params.length_min, params.length_max))
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
            // `0x0`), so the match never reaches `fallback_anchor` locationless.
            evidence.push(Evidence {
                method: "text".to_string(),
                source: "string_extractor".to_string(),
                value: truncate_evidence_value(match_value),
                location: Some(string_info_location(ctx.report, string_info)),
                match_len: encoded_source_len(string_info.value.len(), &string_info.encoding_chain),
                ..Default::default()
            });
        }
    }

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

/// Evaluate string-literal condition using AST-derived string entries only.
#[must_use]
pub(crate) fn eval_string_literal<'a, 'b>(
    params: &StringParams<'a>,
    trait_not: Option<&Vec<NotException>>,
    ctx: &EvaluationContext<'b>,
) -> ConditionResult {
    if !ctx.file_type.supports_ast_queries() {
        return ConditionResult::no_match();
    }

    let effective_range = resolve_string_effective_range(params, ctx);
    let matcher = StringMatcher::resolve(params);

    let mut evidence = Vec::new();
    let mut match_count = 0usize;
    // Tree-sitter grammars can expose both an enclosing string node and a
    // nested string-content node. Count a source match once by its concrete
    // byte span, regardless of how many parser projections reported it.
    let mut seen_match_spans: FxHashSet<(u64, usize)> = FxHashSet::default();

    for string_info in &ctx.report.strings {
        if string_info.section.as_deref() != Some("ast") {
            continue;
        }
        if !offset_in_range(string_info.offset, effective_range) {
            continue;
        }

        if let Some(match_value) =
            matcher.match_value_bounded(&string_info.value, (params.length_min, params.length_max))
        {
            let excluded_by_not = trait_not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(match_value)))
                .unwrap_or(false);
            let excluded_by_is = !validate_match(match_value, params.is_check);

            if !excluded_by_not && !excluded_by_is {
                let within = (match_value.as_ptr() as usize)
                    .saturating_sub(string_info.value.as_ptr() as usize)
                    as u64;
                let match_offset = string_info.offset.map(|o| o.saturating_add(within));
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
                        source: "ast".to_string(),
                        value: truncate_evidence_value(match_value),
                        location: Some(location),
                        ..Default::default()
                    });
                }
            }
        }
    }

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
        && !pattern.contains("\\u")
        && !pattern.contains("\\p")
        && !pattern.contains("\\P")
}

/// Evaluate `type: symbol, kind: call [+ arg: ...]` — match call
/// sites from filefacts's unified `Symbol::Call` records, optionally
/// narrowing by an arg-position filter that matches against the
/// per-arg shape+value carried on each call.
///
/// Iterates `ctx.report.filefacts.symbols` (the raw filefacts JSON
/// mirror), filters to entries with `kind: "call"`, matches `target`
/// against the rule's name predicates, and — when `arg` is set —
/// requires at least one of the call's `args[]` to match the arg
/// filter on shape + value.
#[must_use]
pub(crate) fn eval_call<'a>(
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    arg_filter: Option<&crate::composite_rules::condition::ArgFilter>,
    args_filters: Option<&[crate::composite_rules::condition::ArgFilter]>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let Some(view) = ctx.report.filefacts.as_ref() else {
        return ConditionResult::no_match();
    };
    let mut evidence = Vec::new();
    let mut match_count = 0usize;
    let compiled_regex = regex.and_then(|r| crate::composite_rules::condition::cached_regex(r));

    for sym in &view.symbols {
        let filefacts::Symbol::Call {
            target,
            args,
            offset,
            ..
        } = sym
        else {
            continue;
        };
        let target = target.as_deref().unwrap_or("");

        // Match the target name against any name predicate.
        let name_matches = match (exact, substr, compiled_regex.as_ref()) {
            (None, None, None) => true, // no name filter — every call qualifies
            (Some(e), _, _) => target == e,
            (_, Some(s), _) => target.contains(s.as_str()),
            (_, _, Some(re)) => re.is_match(target),
        };
        if !name_matches {
            continue;
        }

        // If an arg filter is set, require at least one arg to match it.
        if let Some(filter) = arg_filter
            && !args.iter().any(|a| arg_matches(a, filter))
        {
            continue;
        }

        // If a multi-arg filter is set, require every filter to be satisfied by
        // a *distinct* arg (greedy assignment) — for matching a specific
        // multi-positional shape like `File.rename("a.png", "b.exe")`.
        if let Some(filters) = args_filters
            && !all_filters_match_distinct(args, filters)
        {
            continue;
        }

        match_count += 1;
        if evidence.len() < MAX_EVIDENCE_PER_TRAIT
            && let Some(location) = offset.map(|o| format!("{:#x}", o))
        {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: "call".to_string(),
                value: target.to_string(),
                location: Some(location),
                ..Default::default()
            });
        }
    }

    ConditionResult {
        matched: match_count > 0,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision: 2.0,
        matched_trait_ids: Vec::new(),
    }
}

/// Evaluate `type: symbol, kind: member|bind|identifier` — match the
/// pre-extracted member-access chains, static bindings, and bare
/// identifiers from filefacts's `Symbol::{Member,Bind,Identifier}`
/// records against the rule's name predicates.
///
/// These projections replace per-member tree-sitter cursor walks for
/// `query:` traits that only keyed off a dotted path (`process.env`), an
/// assignment target, or an identifier name — the fact is extracted once
/// per file and matched here without re-walking the AST per rule.
#[must_use]
pub(crate) fn eval_symbol_fact<'a>(
    kind: crate::composite_rules::condition::SymbolKind,
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    use crate::composite_rules::condition::SymbolKind;
    let Some(view) = ctx.report.filefacts.as_ref() else {
        return ConditionResult::no_match();
    };
    let mut evidence = Vec::new();
    let mut match_count = 0usize;
    let compiled_regex = regex.and_then(|r| crate::composite_rules::condition::cached_regex(r));

    for sym in &view.symbols {
        // Project each fact to its matchable name + evidence location,
        // skipping symbols whose kind the rule didn't ask for.
        let (name, source_tag, offset): (&str, &str, Option<u64>) = match (kind, sym) {
            (SymbolKind::Member, filefacts::Symbol::Member { path, offset, .. }) => {
                (path.as_str(), "member", *offset)
            }
            (SymbolKind::Bind, filefacts::Symbol::Bind { target, offset, .. }) => {
                (target.as_str(), "bind", Some(*offset))
            }
            (SymbolKind::Identifier, filefacts::Symbol::Identifier { name, offset, .. }) => {
                (name.as_str(), "identifier", *offset)
            }
            _ => continue,
        };

        let name_matches = match (exact, substr, compiled_regex.as_ref()) {
            (None, None, None) => true,
            (Some(e), _, _) => name == e.as_str(),
            (_, Some(s), _) => name.contains(s.as_str()),
            (_, _, Some(re)) => re.is_match(name),
        };
        if !name_matches {
            continue;
        }

        match_count += 1;
        if evidence.len() < MAX_EVIDENCE_PER_TRAIT
            && let Some(location) = offset.map(|o| format!("{:#x}", o))
        {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: source_tag.to_string(),
                value: name.to_string(),
                location: Some(location),
                ..Default::default()
            });
        }
    }

    ConditionResult {
        matched: match_count > 0,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision: 2.0,
        matched_trait_ids: Vec::new(),
    }
}

/// True when every filter in `filters` can be matched to a **distinct** arg in
/// `args` (a bipartite matching). Used by the multi-arg `args:` filter to match
/// a specific multi-positional call shape like `File.rename("a.png", "b.exe")`
/// without letting one arg satisfy two filters. Backtracks so a greedy
/// mis-assignment can't produce a false negative; inputs are tiny (a handful of
/// args and filters).
fn all_filters_match_distinct(
    args: &[filefacts::Arg],
    filters: &[crate::composite_rules::condition::ArgFilter],
) -> bool {
    if filters.len() > args.len() {
        return false;
    }
    fn assign(
        fi: usize,
        args: &[filefacts::Arg],
        filters: &[crate::composite_rules::condition::ArgFilter],
        used: &mut [bool],
    ) -> bool {
        if fi == filters.len() {
            return true;
        }
        for (ai, a) in args.iter().enumerate() {
            if !used[ai] && arg_matches(a, &filters[fi]) {
                used[ai] = true;
                if assign(fi + 1, args, filters, used) {
                    return true;
                }
                used[ai] = false;
            }
        }
        false
    }
    let mut used = vec![false; args.len()];
    assign(0, args, filters, &mut used)
}

/// Match one arg JSON value against an [`ArgFilter`]. Argstring/number/
/// identifier are tagged `{"shape": ...}` in filefacts's serialization.
fn arg_matches(
    arg: &filefacts::Arg,
    filter: &crate::composite_rules::condition::ArgFilter,
) -> bool {
    use filefacts::Arg;
    if let Some(want_kind) = filter.kind.as_deref()
        && arg_shape(arg) != want_kind
    {
        return false;
    }
    match arg {
        Arg::Number { value, radix, .. } => {
            if let Some(want_value) = filter.value
                && *value != want_value
            {
                return false;
            }
            if let Some(want_radix) = filter.radix
                && *radix != want_radix
            {
                return false;
            }
        }
        Arg::String { value } | Arg::Template { value } => {
            if let Some(want_exact) = filter.exact.as_deref()
                && value != want_exact
            {
                return false;
            }
            if let Some(want_substr) = filter.substr.as_deref()
                && !value.contains(want_substr)
            {
                return false;
            }
            if let Some(want_regex) = filter.regex.as_deref()
                && !crate::composite_rules::condition::cached_regex(want_regex)
                    .is_some_and(|re| re.is_match(value))
            {
                return false;
            }
        }
        Arg::Identifier { name } => {
            if let Some(want_name) = filter.name.as_deref()
                && name != want_name
            {
                return false;
            }
        }
        // Other shapes (null, object, array, function, call, expression)
        // carry no matchable value — a shape match alone (checked above) is
        // sufficient.
        _ => {}
    }
    true
}

/// Lowercase shape tag for an [`filefacts::Arg`], matching the `shape:` /
/// `kind:` values rule authors write (mirrors filefacts's `#[serde(tag =
/// "shape", rename_all = "lowercase")]`).
fn arg_shape(arg: &filefacts::Arg) -> &'static str {
    use filefacts::Arg;
    match arg {
        Arg::String { .. } => "string",
        Arg::Number { .. } => "number",
        Arg::Bool { .. } => "bool",
        Arg::Null => "null",
        Arg::Identifier { .. } => "identifier",
        Arg::Object => "object",
        Arg::Array => "array",
        Arg::Function => "function",
        Arg::Template { .. } => "template",
        Arg::Call => "call",
        Arg::Expression => "expression",
        _ => "",
    }
}

/// Evaluate `type: literal, kind: number` — match against numeric
/// literals extracted by the AST walker into `ctx.report.strings` with
/// `section: Some("ast-number")`. The string row encodes:
///   - `value`    = decimal-rendered parsed integer (e.g., `"511"`)
///   - `encoding` = source-written radix as string (`"2" / "8" / "10" / "16"`)
///
/// When `want_value` is set, the literal's parsed value must equal it.
/// When `want_radix` is set, the source-written radix must match —
/// lets authors distinguish `0o777` from `511`.
#[must_use]
pub(crate) fn eval_numeric_literal<'a>(
    want_value: Option<i64>,
    want_radix: Option<u32>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let mut evidence = Vec::new();
    let mut match_count = 0usize;

    for string_info in &ctx.report.strings {
        if string_info.section.as_deref() != Some("ast-number") {
            continue;
        }
        let Ok(parsed_value) = string_info.value.parse::<i64>() else {
            continue;
        };
        let Ok(parsed_radix) = string_info.encoding.parse::<u32>() else {
            continue;
        };
        if let Some(v) = want_value
            && parsed_value != v
        {
            continue;
        }
        if let Some(r) = want_radix
            && parsed_radix != r
        {
            continue;
        }
        match_count += 1;
        if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
            evidence.push(Evidence {
                method: "literal".to_string(),
                source: "ast-number".to_string(),
                value: format!("{} (radix {})", parsed_value, parsed_radix),
                location: Some(string_info_location(ctx.report, string_info)),
                ..Default::default()
            });
        }
    }

    ConditionResult {
        matched: match_count > 0,
        evidence,
        match_count,
        warnings: Vec::new(),
        // High precision — numeric literal matches are unambiguous.
        precision: 2.0,
        matched_trait_ids: Vec::new(),
    }
}

/// Windows around gate-supplied atom hits for source `eval_raw`. `None` means
/// full-scan: PE/extracted-string types, gate did not run, trait has no
/// recorded offsets, the pattern is cross-line unbounded (`(?s).*` /
/// `[\s\S]*`), or `\A`/`\z`. Line-local `.*` / `[^\n]*` and whitespace `\s*`
/// (capped at `UNBOUNDED_WS_CAP`) window.
fn source_raw_windows(
    ctx: &EvaluationContext<'_>,
    pattern: &str,
    search_start: usize,
    search_end: usize,
) -> Option<Vec<(usize, usize)>> {
    if !ctx.file_type.uses_raw_text_search() {
        return None;
    }
    let idx = ctx.current_trait_idx?;
    let hits = ctx.raw_atom_offsets?.get(&idx)?;
    // Offsets were recorded for this trait's *indexed* regex (usually `if:`).
    // `unless:` / extra `type: text` regexes share `current_trait_idx` but not
    // those atoms — windowing them around the `if` hits is a false-negative
    // machine (B1n: extra `loopback-http-url-reference` / `bearer-token`).
    if !super::hits_are_pattern_atoms(ctx.binary_data, hits, pattern) {
        return None;
    }
    super::windows_from_atom_hits(ctx.binary_data, hits, pattern, search_start, search_end)
}

/// Used by `type: raw` conditions to search raw file content rather than extracted strings.
/// Use for cross-boundary patterns or when string extraction is insufficient.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub(crate) fn eval_raw<'a>(
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    word: Option<&String>,
    case_insensitive: bool,
    length_bounds: (Option<usize>, Option<usize>),
    is_check: Option<StringValidator>,
    not: Option<&Vec<NotException>>,
    location: &ContentLocationParams,
    ctx: &EvaluationContext<'a>,
    trait_id: Option<&str>,
) -> ConditionResult {
    let _mp = crate::mem_profile::phase(crate::mem_profile::Phase::EvalRaw);
    // When the active trait has no count/density filter and no consumer reads the
    // exact `match_count` (set per-trait via `MatchCountGuard`; default true =
    // safe full count), raw matching may stop at the first passing match instead
    // of scanning the whole file. The full `find_iter` scan is the dominant RSS
    // lever — it grows each `regex::bytes::Regex` lazy-DFA cache to ~778 KB
    // (~7.7 GB at 10k patterns). Parity-exact on finding id+level + evidence (the
    // first match is identical); only the unused `match_count` value is truncated.
    let needs_count = match_count_needed();
    // `word:` is a literal byte-boundary scan (no regex engine) — see the word
    // branch below. Only `regex:` resolves to a pattern string here, and even
    // then the engine is chosen from the string alone (ASCII → bytes engine,
    // else unicode), so an ASCII pattern never compiles the unicode
    // `regex::Regex` it would only read `.as_str()` off of — that wasted compile
    // dominated peak RSS on archives.
    let raw_pattern = crate::composite_rules::condition::raw_regex_pattern(
        None,
        regex.map(String::as_str),
        case_insensitive,
    );
    // Reject short raw patterns unless search space is bounded (~1KB).
    // Acceptable: offset/offset_range, or section + section_offset*.
    // Density constraints (count_min, per_kb_min) are checked at trait level, not here.
    {
        const MIN_PATTERN_LEN: usize = 3;
        let has_pinpoint = location.offset.is_some() || location.offset_range.is_some();
        let has_section_pinpoint = location.section.is_some()
            && (location.section_offset.is_some() || location.section_offset_range.is_some());
        if !has_pinpoint && !has_section_pinpoint {
            if let Some(s) = exact
                && s.len() < MIN_PATTERN_LEN
            {
                return ConditionResult::no_match();
            }
            if let Some(s) = substr
                && s.len() < MIN_PATTERN_LEN
            {
                return ConditionResult::no_match();
            }
        }
    }

    let profile = *PROFILE_TIMING_ENABLED;
    let t_start = if profile {
        Some(std::time::Instant::now())
    } else {
        None
    };

    let mut evidence = Vec::new();

    // Resolve effective range from location constraints
    let (search_start, search_end): (usize, usize) = resolve_effective_range(location, ctx);

    // Ensure we don't exceed binary data bounds
    let search_start = search_start.min(ctx.binary_data.len());
    let search_end = search_end.min(ctx.binary_data.len());

    if search_start >= search_end {
        return ConditionResult::no_match();
    }

    // Get the slice of binary data to search
    let search_data = &ctx.binary_data[search_start..search_end];

    // Track match count for constraint checking
    let mut match_count = 0usize;

    // `word:` — literal byte-boundary scan over raw bytes, no regex engine. The
    // boundary rule mirrors the `\bword\b` regex this used to compile (see
    // `raw_word_match_offsets`); `\bword\b` matches can't overlap, so the offset
    // set equals the regex's.
    if let Some(w) = word.map(String::as_str) {
        let needle_len = w.len();
        let offsets = crate::composite_rules::condition::raw_word_match_offsets(
            search_data,
            w,
            case_insensitive,
            MAX_MATCHES_TO_PROCESS,
        );
        let mut first_match = None;
        let mut first_offset = None;
        for start in offsets {
            let match_bytes = &search_data[start..start + needle_len];
            if is_check.is_some() || not.is_some() {
                let match_str = String::from_utf8_lossy(match_bytes);
                if !validate_match(&match_str, is_check) {
                    continue;
                }
                if let Some(not_filters) = not
                    && not_filters.iter().any(|filter| filter.matches(&match_str))
                {
                    continue;
                }
                if first_match.is_none() {
                    first_match = Some(match_str.to_string());
                    first_offset = Some((search_start + start) as u64);
                }
            } else if first_match.is_none() {
                first_match = Some(String::from_utf8_lossy(match_bytes).to_string());
                first_offset = Some((search_start + start) as u64);
            }
            match_count += 1;
        }
        if match_count > 0
            && evidence.len() < MAX_EVIDENCE_PER_TRAIT
            && let Some(matched) = first_match
        {
            evidence.push(Evidence {
                method: "raw".to_string(),
                source: "raw_content".to_string(),
                value: matched,
                location: Some(format!("0x{:x}", first_offset.unwrap_or(0))),
                offsets: first_offset.into_iter().collect(),
                ..Default::default()
            });
        }
    } else if let Some(pattern_str) = raw_pattern.as_deref() {
        let use_bytes_regex = can_use_byte_matching(pattern_str);

        if use_bytes_regex {
            // FAST PATH: Use bytes::Regex on raw binary data (no UTF-8 conversion!)
            // Get or compile bytes regex from bounded LRU cache.
            //
            // Read via `peek` under a read-lock — `LruCache::get` needs &mut and was
            // forcing every rayon worker to serialize through the cache's write lock
            // even on cache hit. That single bottleneck accounted for ~25 % of total
            // CPU as `parking_lot::lock_exclusive_slow` wait time on the slow dataset.
            //
            // On a miss we compile outside the lock and `put`. Two workers can race
            // to compile the same pattern, but those compiles run in PARALLEL —
            // measured wall-faster than serializing on a per-key `OnceLock`, which
            // idles cores during the compile-heavy warmup (compile-once cut CPU but
            // raised wall ~35 %). Wall is the priority, so the parallel race stays.
            let key = (pattern_str.to_string(), case_insensitive);
            let cache = super::bytes_regex_cache();
            // Clone the `Arc`, never the `Regex`: a `Regex` clone gets a cold
            // lazy-DFA cache and rebuilds every DFA state on first search; the
            // shared `Arc` reuses the warm instance across members/threads.
            // On a miss, claim the key so racing workers pick up this compile
            // instead of duplicating it (see `compile_claim`); the bounded
            // fallback still compiles independently if the claimant is slow.
            static CLAIMS: crate::composite_rules::compile_claim::ClaimSet =
                crate::composite_rules::compile_claim::ClaimSet::new();
            let compile_and_put = |key: (String, bool)| {
                super::compile_bytes_regex(pattern_str, case_insensitive).map(|re| {
                    crate::composite_rules::regex_warm::record_bytes(pattern_str, case_insensitive);
                    let arc = std::sync::Arc::new(re);
                    let size = arc.heap_bytes();
                    cache.write().put(key, std::sync::Arc::clone(&arc), size);
                    arc
                })
            };
            let lean: Option<std::sync::Arc<super::LeanRegex>> = {
                let cached = cache.read().peek(&key).cloned();
                if cached.is_some() {
                    cached
                } else {
                    let kh = crate::composite_rules::compile_claim::ClaimSet::hash_key(&key);
                    if let Some(_guard) = CLAIMS.try_claim(kh) {
                        compile_and_put(key)
                    } else if let Some(hit) = CLAIMS.wait_for(|| cache.read().peek(&key).cloned()) {
                        Some(hit)
                    } else {
                        compile_and_put(key)
                    }
                }
            };

            if let Some(ref lean) = lean {
                let mut first_match = None;
                let mut first_offset = None;
                let mut idx = 0usize;
                let mut visit = |abs_start: usize, abs_end: usize| -> bool {
                    if idx >= MAX_MATCHES_TO_PROCESS {
                        if let Some(trait_id_val) = trait_id {
                            tracing::info!(
                                trait_id = %trait_id_val,
                                pattern = %pattern_str,
                                limit = MAX_MATCHES_TO_PROCESS,
                                "Hit regex-pattern match limit; stopping early"
                            );
                        } else {
                            tracing::info!(
                                pattern = %pattern_str,
                                limit = MAX_MATCHES_TO_PROCESS,
                                "Hit regex-pattern match limit; stopping early"
                            );
                        }
                        return false;
                    }
                    idx += 1;
                    if !span_length_ok(abs_end - abs_start, length_bounds) {
                        return true;
                    }
                    let match_bytes = &ctx.binary_data[abs_start..abs_end];

                    // For validators or not filters, convert only the match to string
                    if is_check.is_some() || not.is_some() {
                        let match_str = String::from_utf8_lossy(match_bytes);
                        if !validate_match(&match_str, is_check) {
                            return true;
                        }
                        if let Some(not_filters) = not
                            && not_filters.iter().any(|filter| filter.matches(&match_str))
                        {
                            return true;
                        }
                        if first_match.is_none() {
                            first_match = Some(match_str.to_string());
                            first_offset = Some(abs_start as u64);
                        }
                    } else if first_match.is_none() {
                        // No filters, just count
                        first_match = Some(String::from_utf8_lossy(match_bytes).to_string());
                        first_offset = Some(abs_start as u64);
                    }

                    match_count += 1;
                    // No density constraint and nobody reads the exact count:
                    // stop at the first passing match instead of scanning the
                    // whole file.
                    needs_count
                };
                // Reuse atom offsets the raw-content gate already paid for.
                // No second memmem. Missing offsets / unbounded / PE → full scan.
                if let Some(spans) = source_raw_windows(ctx, pattern_str, search_start, search_end)
                {
                    lean.for_each_match_spans(ctx.binary_data, &spans, visit);
                } else {
                    lean.for_each_match(search_data, |start, end| {
                        visit(search_start + start, search_start + end)
                    });
                }
                if match_count > 0
                    && evidence.len() < MAX_EVIDENCE_PER_TRAIT
                    && let Some(matched) = first_match
                {
                    evidence.push(Evidence {
                        method: "raw".to_string(),
                        source: "raw_content".to_string(),
                        value: matched,
                        location: Some(format!("0x{:x}", first_offset.unwrap_or(0))),
                        offsets: first_offset.into_iter().collect(),
                        ..Default::default()
                    });
                }
            }
        } else {
            // UNICODE PATH: compile the unicode engine now — only non-ASCII
            // patterns reach here. A compile failure (unreachable for corpus
            // patterns, which compiled before) simply yields no matches.
            if let Some(re) = crate::composite_rules::condition::cached_regex(pattern_str) {
                // Reuse the whole-file UTF-8 view built once at ctx construction
                // (source types) or on first use (everything else); only
                // re-validate for sub-ranges.
                let content: std::borrow::Cow<'_, str> =
                    if search_start == 0 && search_end == ctx.binary_data.len() {
                        std::borrow::Cow::Borrowed(ctx.full_utf8())
                    } else {
                        super::utf8_view(ctx.binary_data, (search_start, search_end))
                    };
                let mut first_match = None;
                let mut first_offset = None;
                let mut idx = 0usize;
                re.for_each_find(&content, |mat_start, match_str| {
                    // Limit match processing to prevent DoS on pattern-dense files
                    if idx >= MAX_MATCHES_TO_PROCESS {
                        if let Some(trait_id_val) = trait_id {
                            tracing::info!(
                                trait_id = %trait_id_val,
                                pattern = %re.as_str(),
                                limit = MAX_MATCHES_TO_PROCESS,
                                "Hit regex-pattern match limit; stopping early"
                            );
                        } else {
                            tracing::info!(
                                pattern = %re.as_str(),
                                limit = MAX_MATCHES_TO_PROCESS,
                                "Hit regex-pattern match limit; stopping early"
                            );
                        }
                        return false;
                    }
                    idx += 1;
                    if !span_length_ok(match_str.len(), length_bounds) {
                        return true;
                    }
                    // Skip matches that don't pass validation
                    if !validate_match(match_str, is_check) {
                        return true;
                    }
                    // Skip matches that trigger 'not' filters
                    if let Some(not_filters) = not
                        && not_filters.iter().any(|filter| filter.matches(match_str))
                    {
                        return true;
                    }
                    match_count += 1;
                    if first_match.is_none() {
                        first_match = Some(match_str.to_string());
                        first_offset = Some((search_start + mat_start) as u64);
                    }
                    // See bytes branch: stop at first match when the count is
                    // unneeded, to avoid scanning the whole file.
                    needs_count
                });
                if match_count > 0
                    && evidence.len() < MAX_EVIDENCE_PER_TRAIT
                    && let Some(matched) = first_match
                {
                    evidence.push(Evidence {
                        method: "raw".to_string(),
                        source: "raw_content".to_string(),
                        value: matched,
                        location: Some(format!("0x{:x}", first_offset.unwrap_or(0))),
                        offsets: first_offset.into_iter().collect(),
                        ..Default::default()
                    });
                }
            }
        }
    } else if let Some(exact_str) = exact {
        // Per-line equality: the pattern must equal some trimmed line in `search_data`.
        //
        // This mirrors extracted-strings mode (where `exact` compares against a complete
        // extracted string) by treating each line as the unit of equality for raw text.
        // Pattern-as-substring within a line is `substr:`; pattern-as-token is regex.
        //
        // ASCII-only patterns can be compared byte-wise without UTF-8 conversion. The
        // line splitter walks `search_data` directly and yields each line's (start, end)
        // byte range so trimmed comparison stays allocation-free in the ASCII fast path.
        let case_i = case_insensitive;
        let ascii_path = can_use_byte_matching(exact_str);
        let pat_bytes = exact_str.as_bytes();
        let mut first_offset: Option<u64> = None;
        let mut first_value: Option<String> = None;

        let mut line_start = 0usize;
        while line_start <= search_data.len() {
            let line_end = memchr::memchr(b'\n', &search_data[line_start..])
                .map(|p| line_start + p)
                .unwrap_or(search_data.len());

            // Strip trailing \r (CRLF) and surrounding ASCII whitespace.
            let mut s = line_start;
            let mut e = line_end;
            if e > s && search_data[e - 1] == b'\r' {
                e -= 1;
            }
            while s < e && (search_data[s] as char).is_ascii_whitespace() {
                s += 1;
            }
            while e > s && (search_data[e - 1] as char).is_ascii_whitespace() {
                e -= 1;
            }
            let line_bytes = &search_data[s..e];

            let line_matches = if ascii_path {
                if case_i {
                    line_bytes.eq_ignore_ascii_case(pat_bytes)
                } else {
                    line_bytes == pat_bytes
                }
            } else {
                // Unicode pattern: convert this line only.
                match std::str::from_utf8(line_bytes) {
                    Ok(line_str) => {
                        if case_i {
                            line_str.eq_ignore_ascii_case(exact_str)
                        } else {
                            line_str == exact_str
                        }
                    }
                    Err(_) => false,
                }
            };

            if line_matches {
                let line_value = String::from_utf8_lossy(line_bytes).to_string();
                let is_ok = validate_match(&line_value, is_check);
                let excluded_by_not = not
                    .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&line_value)))
                    .unwrap_or(false);
                if is_ok && !excluded_by_not {
                    match_count += 1;
                    if first_offset.is_none() {
                        first_offset = Some((search_start + s) as u64);
                        first_value = Some(line_value);
                    }
                }
            }

            if line_end == search_data.len() {
                break;
            }
            line_start = line_end + 1;
        }

        if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
            evidence.push(Evidence {
                method: "raw".to_string(),
                source: "raw_content".to_string(),
                value: first_value.unwrap_or_else(|| exact_str.clone()),
                location: Some(format!("0x{:x}", first_offset.unwrap_or(0))),
                offsets: first_offset.into_iter().collect(),
                ..Default::default()
            });
        }
    } else if let Some(substr_str) = substr {
        // Substring match - OPTIMIZED: use byte-level search for ASCII patterns
        if can_use_byte_matching(substr_str) {
            // Fast path: Byte-level substring search (avoids UTF-8 conversion)
            if is_check.is_some() {
                // Need to check each match context for validator
                let mut first_match_offset = None;
                if case_insensitive {
                    for_each_ascii_ci_substr(
                        search_data,
                        substr_str,
                        true,
                        |abs_pos, needle_len| {
                            let ctx_start = abs_pos.saturating_sub(50);
                            let ctx_end = (abs_pos + needle_len + 50).min(search_data.len());
                            let context = String::from_utf8_lossy(&search_data[ctx_start..ctx_end]);

                            if validate_match(&context, is_check) {
                                let excluded = not
                                    .map(|excs| excs.iter().any(|e| e.matches(&context)))
                                    .unwrap_or(false);
                                if !excluded {
                                    if first_match_offset.is_none() {
                                        first_match_offset = Some((search_start + abs_pos) as u64);
                                    }
                                    match_count += 1;
                                }
                            }
                            true
                        },
                    );
                } else {
                    let needle = substr_str.as_bytes();
                    let finder = memchr::memmem::Finder::new(needle);

                    let mut pos = 0;
                    while let Some(offset) = finder.find(&search_data[pos..]) {
                        let abs_pos = pos + offset;
                        let ctx_start = abs_pos.saturating_sub(50);
                        let ctx_end = (abs_pos + needle.len() + 50).min(search_data.len());
                        let context = String::from_utf8_lossy(&search_data[ctx_start..ctx_end]);

                        if validate_match(&context, is_check) {
                            let excluded = not
                                .map(|excs| excs.iter().any(|e| e.matches(&context)))
                                .unwrap_or(false);
                            if !excluded {
                                if first_match_offset.is_none() {
                                    first_match_offset = Some((search_start + abs_pos) as u64);
                                }
                                match_count += 1;
                            }
                        }
                        pos = abs_pos + 1;
                    }
                }

                if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "raw".to_string(),
                        source: "raw_content".to_string(),
                        value: substr_str.to_string(),
                        location: Some(format!("0x{:x}", first_match_offset.unwrap_or(0))),
                        offsets: first_match_offset.into_iter().collect(),
                        ..Default::default()
                    });
                }
            } else if not.is_some() {
                // Per-match not: filtering — extract context per match
                let mut first_match_offset = None;
                if case_insensitive {
                    for_each_ascii_ci_substr(
                        search_data,
                        substr_str,
                        true,
                        |abs_pos, needle_len| {
                            let ctx_start = abs_pos.saturating_sub(50);
                            let ctx_end = (abs_pos + needle_len + 50).min(search_data.len());
                            let context = String::from_utf8_lossy(&search_data[ctx_start..ctx_end]);
                            let excluded = not
                                .map(|excs| excs.iter().any(|e| e.matches(&context)))
                                .unwrap_or(false);
                            if !excluded {
                                if first_match_offset.is_none() {
                                    first_match_offset = Some((search_start + abs_pos) as u64);
                                }
                                match_count += 1;
                            }
                            true
                        },
                    );
                } else {
                    let needle = substr_str.as_bytes();
                    let finder = memchr::memmem::Finder::new(needle);
                    let mut pos = 0;
                    while let Some(offset) = finder.find(&search_data[pos..]) {
                        let abs_pos = pos + offset;
                        let ctx_start = abs_pos.saturating_sub(50);
                        let ctx_end = (abs_pos + needle.len() + 50).min(search_data.len());
                        let context = String::from_utf8_lossy(&search_data[ctx_start..ctx_end]);
                        let excluded = not
                            .map(|excs| excs.iter().any(|e| e.matches(&context)))
                            .unwrap_or(false);
                        if !excluded {
                            if first_match_offset.is_none() {
                                first_match_offset = Some((search_start + abs_pos) as u64);
                            }
                            match_count += 1;
                        }
                        pos = abs_pos + 1;
                    }
                }
                if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "raw".to_string(),
                        source: "raw_content".to_string(),
                        value: substr_str.to_string(),
                        location: Some(format!("0x{:x}", first_match_offset.unwrap_or(0))),
                        offsets: first_match_offset.into_iter().collect(),
                        ..Default::default()
                    });
                }
            } else {
                // Simple count - just count byte occurrences (fastest path, no not: filter)
                let mut first_offset = None;
                if case_insensitive {
                    match_count = 0;
                    for_each_ascii_ci_substr(search_data, substr_str, false, |abs_pos, _len| {
                        if first_offset.is_none() {
                            first_offset = Some((search_start + abs_pos) as u64);
                        }
                        match_count += 1;
                        true
                    });
                } else {
                    let needle = substr_str.as_bytes();
                    let iter = memchr::memmem::find_iter(search_data, needle);
                    first_offset = iter.clone().next().map(|o| (search_start + o) as u64);
                    match_count = iter.count();
                }

                if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "raw".to_string(),
                        source: "raw_content".to_string(),
                        value: substr_str.to_string(),
                        location: Some(format!("0x{:x}", first_offset.unwrap_or(0))),
                        offsets: first_offset.into_iter().collect(),
                        ..Default::default()
                    });
                }
            }
        } else {
            // Unicode pattern - fall back to cached UTF-8 conversion
            // Reuse the whole-file UTF-8 view built once at ctx construction
            // (source types) or on first use (everything else); only
            // re-validate for sub-ranges.
            let content: std::borrow::Cow<'_, str> =
                if search_start == 0 && search_end == ctx.binary_data.len() {
                    std::borrow::Cow::Borrowed(ctx.full_utf8())
                } else {
                    super::utf8_view(ctx.binary_data, (search_start, search_end))
                };

            if is_check.is_some() {
                // For validator validation, we need to find actual match positions
                // Case-sensitive borrows the cached UTF-8 view (no per-eval copy);
                // case-insensitive still folds case into an owned buffer.
                let search_content: std::borrow::Cow<'_, str> = if case_insensitive {
                    std::borrow::Cow::Owned(content.to_lowercase())
                } else {
                    std::borrow::Cow::Borrowed(&content)
                };
                let search_pattern: std::borrow::Cow<'_, str> = if case_insensitive {
                    std::borrow::Cow::Owned(substr_str.to_lowercase())
                } else {
                    std::borrow::Cow::Borrowed(substr_str)
                };
                let mut first_match_offset = None;
                let mut start = 0;
                while let Some(pos) = search_content[start..].find(search_pattern.as_ref()) {
                    let abs_pos = start + pos;
                    // Get some context around the match to check for validator
                    let context_start = abs_pos.saturating_sub(50);
                    let context_end = (abs_pos + search_pattern.len() + 50).min(content.len());
                    let context = &content[context_start..context_end];
                    if validate_match(context, is_check) {
                        let excluded_by_not = not
                            .map(|exceptions| exceptions.iter().any(|exc| exc.matches(context)))
                            .unwrap_or(false);
                        if !excluded_by_not {
                            if first_match_offset.is_none() {
                                first_match_offset = Some((search_start + abs_pos) as u64);
                            }
                            match_count += 1;
                        }
                    }
                    start = search_content[abs_pos..]
                        .char_indices()
                        .nth(1)
                        .map(|(next, _)| abs_pos + next)
                        .unwrap_or_else(|| search_content.len());
                }
                if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "raw".to_string(),
                        source: "raw_content".to_string(),
                        value: substr_str.to_string(),
                        location: Some(format!("0x{:x}", first_match_offset.unwrap_or(0))),
                        offsets: first_match_offset.into_iter().collect(),
                        ..Default::default()
                    });
                }
            } else if not.is_some() {
                // Per-match not: filtering on Unicode content
                // Case-sensitive borrows the cached UTF-8 view (no per-eval copy);
                // case-insensitive still folds case into an owned buffer.
                let search_content: std::borrow::Cow<'_, str> = if case_insensitive {
                    std::borrow::Cow::Owned(content.to_lowercase())
                } else {
                    std::borrow::Cow::Borrowed(&content)
                };
                let search_pattern: std::borrow::Cow<'_, str> = if case_insensitive {
                    std::borrow::Cow::Owned(substr_str.to_lowercase())
                } else {
                    std::borrow::Cow::Borrowed(substr_str)
                };
                let mut first_match_offset = None;
                let mut start = 0;
                while let Some(pos) = search_content[start..].find(search_pattern.as_ref()) {
                    let abs_pos = start + pos;
                    let match_context =
                        match_window(&content, abs_pos, abs_pos + search_pattern.len(), 50);
                    let excluded = not
                        .map(|excs| excs.iter().any(|e| e.matches(&match_context)))
                        .unwrap_or(false);
                    if !excluded {
                        if first_match_offset.is_none() {
                            first_match_offset = Some((search_start + abs_pos) as u64);
                        }
                        match_count += 1;
                    }
                    start = search_content[abs_pos..]
                        .char_indices()
                        .nth(1)
                        .map(|(next, _)| abs_pos + next)
                        .unwrap_or_else(|| search_content.len());
                }
                if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "raw".to_string(),
                        source: "raw_content".to_string(),
                        value: substr_str.to_string(),
                        location: Some(format!("0x{:x}", first_match_offset.unwrap_or(0))),
                        offsets: first_match_offset.into_iter().collect(),
                        ..Default::default()
                    });
                }
            } else {
                // Simple count - no not: filter (fastest path)
                // Case-sensitive borrows the cached UTF-8 view (no per-eval copy);
                // case-insensitive still folds case into an owned buffer.
                let search_content: std::borrow::Cow<'_, str> = if case_insensitive {
                    std::borrow::Cow::Owned(content.to_lowercase())
                } else {
                    std::borrow::Cow::Borrowed(&content)
                };
                let search_pattern: std::borrow::Cow<'_, str> = if case_insensitive {
                    std::borrow::Cow::Owned(substr_str.to_lowercase())
                } else {
                    std::borrow::Cow::Borrowed(substr_str)
                };
                let first_offset = search_content
                    .find(search_pattern.as_ref())
                    .map(|o| (search_start + o) as u64);
                match_count = search_content.matches(search_pattern.as_ref()).count();
                if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "raw".to_string(),
                        source: "raw_content".to_string(),
                        value: substr_str.to_string(),
                        location: Some(format!("0x{:x}", first_offset.unwrap_or(0))),
                        offsets: first_offset.into_iter().collect(),
                        ..Default::default()
                    });
                }
            }
        }
    }

    if let Some(t) = t_start
        && profile
    {
        eprintln!("[PROFILE]   eval_raw: {}ms", t.elapsed().as_millis());
    }

    // Calculate precision
    let mut precision = 0.0f32;

    if exact.is_some() {
        precision = 2.0;
    } else if word.is_some() || raw_pattern.is_some() {
        precision = 1.5;
    } else if substr.is_some() {
        precision = 1.0;
    }

    if case_insensitive {
        precision *= 0.5;
    }

    // count/density constraints are now scored at trait level

    if is_check.is_some() {
        precision += 0.5; // Higher precision when requiring high-fidelity validator
    }

    // Location constraints add precision
    if location.section.is_some() {
        precision += 1.0;
    }
    if location.offset.is_some() {
        precision += 1.5;
    } else if location.offset_range.is_some()
        || location.section_offset.is_some()
        || location.section_offset_range.is_some()
    {
        precision += 1.0;
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

/// Search encoded/decoded strings for patterns with optional encoding filter.
/// Unified replacement for eval_base64 and eval_xor with additional features.
///
/// # Encoding Filter
/// - `Some(Single("base64"))` - Only search base64-decoded strings
/// - `Some(Multiple(vec!["base64", "hex"]))` - Search base64 OR hex decoded strings
/// - `None` - Search ALL encoded strings (any non-empty encoding_chain)
///
/// # Pattern Matching
/// Supports exact, substr, regex, and word boundary matching
#[allow(clippy::too_many_arguments)]
#[must_use]
pub(crate) fn eval_encoded<'a>(
    encoding: Option<&crate::composite_rules::condition::EncodingSpec>,
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    word: Option<&String>,
    case_insensitive: bool,
    location: &ContentLocationParams,
    is_check: Option<StringValidator>,
    not: Option<&Vec<crate::composite_rules::condition::NotException>>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    use crate::composite_rules::condition::EncodingSpec;

    // Resolve effective range for offset filtering
    let effective_range = resolve_effective_range_opt(location, ctx);

    let mut evidence = Vec::new();
    let mut match_count = 0;

    // Build regex if needed
    let regex_matcher = if let Some(pattern) = regex {
        match super::build_regex(pattern, case_insensitive) {
            Ok(re) => Some(re),
            Err(_) => return ConditionResult::no_match(),
        }
    } else if let Some(word_pattern) = word {
        // Build word boundary regex from word parameter
        let pattern = format!(r"\b{}\b", regex::escape(word_pattern));
        match super::build_regex(&pattern, case_insensitive) {
            Ok(re) => Some(re),
            Err(_) => return ConditionResult::no_match(),
        }
    } else {
        None
    };

    // Determine encoding filter function
    let matches_encoding = |enc_chain: &[String]| -> bool {
        match encoding {
            None => {
                // No filter: match ANY encoded string (non-empty encoding_chain)
                !enc_chain.is_empty()
            }
            Some(EncodingSpec::Single(enc)) => {
                // Single encoding: must be in the chain
                enc_chain.contains(enc)
            }
            Some(EncodingSpec::Multiple(encodings)) => {
                // Multiple encodings: match if ANY encoding is in the chain (OR logic)
                encodings.iter().any(|enc| enc_chain.contains(enc))
            }
        }
    };

    // Filter and match strings
    for string_info in &ctx.report.strings {
        // Apply encoding filter
        if !matches_encoding(&string_info.encoding_chain) {
            continue;
        }

        // Skip strings outside the effective range (if location constraints specified)
        if !offset_in_range(string_info.offset, effective_range) {
            continue;
        }

        let mut matches = false;

        // Check exact match (full string equality)
        if let Some(exact_str) = exact {
            matches = if case_insensitive {
                string_info.value.eq_ignore_ascii_case(exact_str)
            } else {
                string_info.value == *exact_str
            };
        }

        // Check substring match
        if !matches && let Some(substr_str) = substr {
            matches = if case_insensitive {
                string_info
                    .value
                    .to_lowercase()
                    .contains(&substr_str.to_lowercase())
            } else {
                string_info.value.contains(substr_str.as_str())
            };
        }

        // Check regex or word match
        if !matches && let Some(ref re) = regex_matcher {
            matches = re.is_match(&string_info.value);
        }

        if matches {
            // Apply not: exclusions
            let excluded_by_not = not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&string_info.value)))
                .unwrap_or(false);
            // Apply validator: filter
            let excluded_by_is = !validate_match(&string_info.value, is_check);

            if !excluded_by_not && !excluded_by_is {
                match_count += 1;
                if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    let value_preview = if string_info.value.len() > 100 {
                        format!(
                            "{}...",
                            &string_info.value[..string_info.value.floor_char_boundary(100)]
                        )
                    } else {
                        string_info.value.as_str().to_string()
                    };

                    evidence.push(Evidence {
                        method: "encoded_string".to_string(),
                        source: format!("encoding_chain:{}", string_info.encoding_chain.join("+")),
                        value: value_preview,
                        location: Some(string_info_location(ctx.report, string_info)),
                        ..Default::default()
                    });
                }
            }
        }
    }

    // Calculate precision based on match type and constraints
    let mut precision = 0.0f32;

    if exact.is_some() {
        precision = 2.0;
    } else if regex.is_some() || word.is_some() {
        precision = 1.5;
    } else if substr.is_some() {
        precision = 1.0;
    }

    if case_insensitive {
        precision *= 0.5;
    }

    // Location constraints add precision
    if location.section.is_some() {
        precision += 1.0;
    }
    if location.offset.is_some() {
        precision += 1.5;
    } else if location.offset_range.is_some()
        || location.section_offset.is_some()
        || location.section_offset_range.is_some()
    {
        precision += 1.0;
    }

    // count/density constraints are now scored and checked at trait level
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

#[cfg(test)]
mod multi_arg_tests {
    use super::all_filters_match_distinct;
    use crate::composite_rules::condition::ArgFilter;

    fn s(v: &str) -> filefacts::Arg {
        filefacts::Arg::String {
            value: v.to_string(),
        }
    }
    fn rx(pat: &str) -> ArgFilter {
        ArgFilter {
            kind: Some("string".to_string()),
            regex: Some(pat.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn matches_distinct_positions() {
        // File.rename("a.png", "b.exe") — img arg + exe arg, distinct.
        let args = [s("a.png"), s("b.exe")];
        let filters = [rx(r"\.png$"), rx(r"\.exe$")];
        assert!(all_filters_match_distinct(&args, &filters));
    }

    #[test]
    fn order_independent_via_backtracking() {
        // Args in the opposite order still match — and a greedy first-fit that
        // grabbed the wrong arg would fail, so this exercises the backtracking.
        let args = [s("b.exe"), s("a.png")];
        let filters = [rx(r"\.png$"), rx(r"\.exe$")];
        assert!(all_filters_match_distinct(&args, &filters));
    }

    #[test]
    fn one_arg_cannot_satisfy_two_filters() {
        // A single ".exe" arg must not satisfy both an img and an exe filter.
        let args = [s("only.exe")];
        let filters = [rx(r"\.png$"), rx(r"\.exe$")];
        assert!(!all_filters_match_distinct(&args, &filters));
    }

    #[test]
    fn distinct_required_for_same_filter_twice() {
        // Two ".exe" filters need two distinct ".exe" args.
        assert!(!all_filters_match_distinct(
            &[s("a.exe")],
            &[rx(r"\.exe$"), rx(r"\.exe$")]
        ));
        assert!(all_filters_match_distinct(
            &[s("a.exe"), s("b.exe")],
            &[rx(r"\.exe$"), rx(r"\.exe$")]
        ));
    }
}
