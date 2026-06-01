//! Symbol and string-based condition evaluators.
//!
//! This module handles evaluation of:
//! - Symbol matching (imports, exports)
//! - String content matching (extracted strings, raw content)
//! - Decoded string matching (Base64, XOR)
//! - String count analysis

use super::{
    ContentLocationParams, build_regex, resolve_effective_range, resolve_effective_range_opt,
    symbol_matches, truncate_evidence,
};
use crate::composite_rules::condition::{NotException, StringValidator, SymbolKind};
use crate::composite_rules::context::{ConditionResult, EvaluationContext, StringParams};
use crate::composite_rules::types::Platform;
use crate::ip_validator::{contains_external_ip_cached, contains_valid_ip};
use cleave::bitcoin_validator::contains_bitcoin_address;
use std::sync::LazyLock;

/// Resolved once at startup. `std::env::var` calls libc `getenv`, which takes a
/// process-wide mutex on macOS — hitting that on every rule evaluation was ~3.6%
/// of total CPU as lock-wait samples across 24 rayon workers.
static PROFILE_TIMING_ENABLED: LazyLock<bool> =
    LazyLock::new(|| std::env::var("CLEAVE_PROFILE").is_ok());

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
        let platform_match = plats.contains(&Platform::All)
            || ctx.platforms.contains(&Platform::All)
            || plats.iter().any(|p| ctx.platforms.contains(p));
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
    let effective_regex: Option<&regex::Regex> =
        pattern.and_then(|p| crate::composite_rules::condition::cached_regex(p.as_str()));

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
                            source: import.source.clone(),
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
                        source: export.source.clone(),
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
                            source: func.source.clone(),
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
    compiled_regex: Option<&regex::Regex>,
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
    Regex(&'static regex::Regex),
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
            Self::Regex(re) => re.find(value).map(|mat| mat.as_str()),
            Self::Never => None,
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
        build_regex(&format!(r"\b{}\b", regex::escape(w)), params.case_insensitive).ok()
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
                location: c.offset.map(|o| format!("@{o}")),
                offsets: c.offset.map(|o| vec![o]).unwrap_or_default(),
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
        return eval_raw(
            params.exact,
            params.substr,
            params.regex,
            params.word,
            params.case_insensitive,
            params.is_check,
            trait_not,
            &location,
            ctx,
            trait_id,
        );
    }

    let effective_range = resolve_string_effective_range(params, ctx);
    let has_location_constraint = has_string_location_constraint(params);

    if !has_location_constraint
        && trait_not.is_none()
        && params.is_check.is_none()
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
                        s.matched.store(true, std::sync::atomic::Ordering::Relaxed);
                        evidence.push(Evidence {
                            method: "text".to_string(),
                            source: "string_extractor".to_string(),
                            value: truncate_evidence_value(original_value),
                            location: s.offset.map(|o| format!("{:#x}", o)),
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
                    s.matched.store(true, std::sync::atomic::Ordering::Relaxed);
                    evidence.push(Evidence {
                        method: "text".to_string(),
                        source: "string_extractor".to_string(),
                        value: truncate_evidence_value(exact_str),
                        location: s.offset.map(|o| format!("{:#x}", o)),
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

        if let Some(match_value) = matcher.match_value_ref(&string_info.value) {
            let excluded_by_not = trait_not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(match_value)))
                .unwrap_or(false);
            let excluded_by_is = !validate_match(match_value, params.is_check);

            if !excluded_by_not && !excluded_by_is {
                match_count += 1;
                string_info
                    .matched
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                // Allocate the evidence string only when actually storing it.
                if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "text".to_string(),
                        source: "string_extractor".to_string(),
                        value: truncate_evidence_value(match_value),
                        location: string_info.offset.map(|o| format!("{:#x}", o)),
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

    for string_info in &ctx.report.strings {
        if string_info.section.as_deref() != Some("ast") {
            continue;
        }
        if !offset_in_range(string_info.offset, effective_range) {
            continue;
        }

        if let Some(match_value) = matcher.match_value_ref(&string_info.value) {
            let excluded_by_not = trait_not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(match_value)))
                .unwrap_or(false);
            let excluded_by_is = !validate_match(match_value, params.is_check);

            if !excluded_by_not && !excluded_by_is {
                match_count += 1;
                string_info
                    .matched
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                // Allocate the evidence string only when actually storing it.
                if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "string_literal".to_string(),
                        source: "ast".to_string(),
                        value: truncate_evidence_value(match_value),
                        location: string_info.offset.map(|o| format!("{:#x}", o)),
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
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let Some(view) = ctx.report.filefacts.as_ref() else {
        return ConditionResult::no_match();
    };
    let mut evidence = Vec::new();
    let mut match_count = 0usize;
    let compiled_regex = regex.and_then(|r| regex::Regex::new(r).ok());

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

        match_count += 1;
        if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: "call".to_string(),
                value: target.to_string(),
                location: offset.map(|o| format!("{:#x}", o)),
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
    let compiled_regex = regex.and_then(|r| regex::Regex::new(r).ok());

    for sym in &view.symbols {
        // Project each fact to its matchable name + evidence location,
        // skipping symbols whose kind the rule didn't ask for.
        let (name, source_tag, offset): (&str, &str, Option<u64>) = match (kind, sym) {
            (SymbolKind::Member, filefacts::Symbol::Member { path, .. }) => {
                (path.as_str(), "member", None)
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
        if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: source_tag.to_string(),
                value: name.to_string(),
                location: offset.map(|o| format!("{:#x}", o)),
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
                && !regex::Regex::new(want_regex).is_ok_and(|re| re.is_match(value))
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
        string_info
            .matched
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
            evidence.push(Evidence {
                method: "literal".to_string(),
                source: "ast-number".to_string(),
                value: format!("{} (radix {})", parsed_value, parsed_radix),
                location: string_info.offset.map(|o| format!("{:#x}", o)),
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
    is_check: Option<StringValidator>,
    not: Option<&Vec<NotException>>,
    location: &ContentLocationParams,
    ctx: &EvaluationContext<'a>,
    trait_id: Option<&str>,
) -> ConditionResult {
    let _mp = crate::mem_profile::phase(crate::mem_profile::Phase::EvalRaw);
    // Regexes are not precompiled per condition; resolve `word:`/`regex:` through
    // the shared lazy cache.
    let compiled_regex = crate::composite_rules::condition::lazy_raw_regex(
        word.map(String::as_str),
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

    // Use pre-compiled regex (handles both word and regex patterns)
    // OPTIMIZATION: Try bytes regex first for ASCII patterns to avoid UTF-8 conversion
    if let Some(re) = compiled_regex {
        // Check if the original pattern is ASCII-only to use bytes regex
        let pattern_str = re.as_str();
        let use_bytes_regex = can_use_byte_matching(pattern_str);

        if use_bytes_regex {
            // FAST PATH: Use bytes::Regex on raw binary data (no UTF-8 conversion!)
            // Get or compile bytes regex from bounded LRU cache.
            //
            // Read via `peek` under a read-lock — `LruCache::get` needs &mut and was
            // forcing every rayon worker to serialize through the cache's write lock
            // even on cache hit. That single bottleneck accounted for ~25 % of total
            // CPU as `parking_lot::lock_exclusive_slow` wait time on the slow dataset.
            let key = (pattern_str.to_string(), case_insensitive);
            let cache = super::bytes_regex_cache();
            // Clone the `Arc`, never the `Regex`: a `Regex` clone gets a cold
            // lazy-DFA cache and rebuilds every DFA state on first search; the
            // shared `Arc` reuses the warm instance across members/threads.
            let bytes_re: Option<std::sync::Arc<regex::bytes::Regex>> = {
                let cached = cache.read().peek(&key).cloned();
                if cached.is_some() {
                    cached
                } else {
                    // Compile outside the lock; write-lock only to insert.
                    match super::compile_bytes_regex(pattern_str, case_insensitive) {
                        Ok(re) => {
                            let arc = std::sync::Arc::new(re);
                            cache.write().put(key, std::sync::Arc::clone(&arc));
                            Some(arc)
                        }
                        Err(_) => None,
                    }
                }
            };

            if let Some(ref bytes_re) = bytes_re {
                let mut first_match = None;
                let mut first_offset = None;
                for (idx, mat) in bytes_re.find_iter(search_data).enumerate() {
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
                        break;
                    }
                    let match_bytes = mat.as_bytes();

                    // For validators or not filters, convert only the match to string
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
                            first_offset = Some((search_start + mat.start()) as u64);
                        }
                    } else {
                        // No filters, just count
                        if first_match.is_none() {
                            first_match = Some(String::from_utf8_lossy(match_bytes).to_string());
                            first_offset = Some((search_start + mat.start()) as u64);
                        }
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
                        location: None,
                        offsets: first_offset.into_iter().collect(),
                        ..Default::default()
                    });
                }
            }
        } else {
            // UNICODE PATH: Use cached UTF-8 conversion for Unicode regex
            // Reuse the per-member UTF-8 view validated once at ctx construction
            // (source types); only re-validate for sub-ranges or non-source members.
            let content: std::borrow::Cow<'_, str> = match ctx.cached_source_utf8 {
                Some(s) if search_start == 0 && search_end == ctx.binary_data.len() => {
                    std::borrow::Cow::Borrowed(s)
                }
                _ => super::utf8_view(ctx.binary_data, (search_start, search_end)),
            };
            let mut first_match = None;
            let mut first_offset = None;
            for (idx, mat) in re.find_iter(&content).enumerate() {
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
                    break;
                }
                let match_str = mat.as_str();
                // Skip matches that don't pass validation
                if !validate_match(match_str, is_check) {
                    continue;
                }
                // Skip matches that trigger 'not' filters
                if let Some(not_filters) = not
                    && not_filters.iter().any(|filter| filter.matches(match_str))
                {
                    continue;
                }
                match_count += 1;
                if first_match.is_none() {
                    first_match = Some(match_str.to_string());
                    first_offset = Some((search_start + mat.start()) as u64);
                }
            }
            if match_count > 0
                && evidence.len() < MAX_EVIDENCE_PER_TRAIT
                && let Some(matched) = first_match
            {
                evidence.push(Evidence {
                    method: "raw".to_string(),
                    source: "raw_content".to_string(),
                    value: matched,
                    location: None,
                    offsets: first_offset.into_iter().collect(),
                    ..Default::default()
                });
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
                location: None,
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
                    let pattern_lower = substr_str.to_ascii_lowercase();
                    let needle = pattern_lower.as_bytes();
                    let finder = memchr::memmem::Finder::new(needle);

                    // Pre-lowercase entire search data ONCE (not per-iteration!)
                    let search_lower = search_data.to_ascii_lowercase();
                    let mut pos = 0;
                    while let Some(offset) = finder.find(&search_lower[pos..]) {
                        let abs_pos = pos + offset;
                        // Convert only context window for validation check (not entire file!)
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
                        location: None,
                        offsets: first_match_offset.into_iter().collect(),
                        ..Default::default()
                    });
                }
            } else if not.is_some() {
                // Per-match not: filtering — extract context per match
                let mut first_match_offset = None;
                if case_insensitive {
                    let pattern_lower = substr_str.to_ascii_lowercase();
                    let needle = pattern_lower.as_bytes();
                    let search_lower = search_data.to_ascii_lowercase();
                    let finder = memchr::memmem::Finder::new(needle);
                    let mut pos = 0;
                    while let Some(offset) = finder.find(&search_lower[pos..]) {
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
                        location: None,
                        offsets: first_match_offset.into_iter().collect(),
                        ..Default::default()
                    });
                }
            } else {
                // Simple count - just count byte occurrences (fastest path, no not: filter)
                let first_offset;
                if case_insensitive {
                    let pattern_lower = substr_str.to_ascii_lowercase();
                    let needle = pattern_lower.as_bytes();
                    let search_lower = search_data.to_ascii_lowercase();
                    let iter = memchr::memmem::find_iter(&search_lower, needle);
                    first_offset = iter.clone().next().map(|o| (search_start + o) as u64);
                    match_count = iter.count();
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
                        location: None,
                        offsets: first_offset.into_iter().collect(),
                        ..Default::default()
                    });
                }
            }
        } else {
            // Unicode pattern - fall back to cached UTF-8 conversion
            // Reuse the per-member UTF-8 view validated once at ctx construction
            // (source types); only re-validate for sub-ranges or non-source members.
            let content: std::borrow::Cow<'_, str> = match ctx.cached_source_utf8 {
                Some(s) if search_start == 0 && search_end == ctx.binary_data.len() => {
                    std::borrow::Cow::Borrowed(s)
                }
                _ => super::utf8_view(ctx.binary_data, (search_start, search_end)),
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
                    start = abs_pos + 1;
                }
                if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "raw".to_string(),
                        source: "raw_content".to_string(),
                        value: substr_str.to_string(),
                        location: None,
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
                    let context_start = abs_pos.saturating_sub(50);
                    let context_end = (abs_pos + search_pattern.len() + 50).min(content.len());
                    let match_context = &content[context_start..context_end];
                    let excluded = not
                        .map(|excs| excs.iter().any(|e| e.matches(match_context)))
                        .unwrap_or(false);
                    if !excluded {
                        if first_match_offset.is_none() {
                            first_match_offset = Some((search_start + abs_pos) as u64);
                        }
                        match_count += 1;
                    }
                    start = abs_pos + 1;
                }
                if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "raw".to_string(),
                        source: "raw_content".to_string(),
                        value: substr_str.to_string(),
                        location: None,
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
                        location: None,
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
    } else if compiled_regex.is_some() {
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
                string_info
                    .matched
                    .store(true, std::sync::atomic::Ordering::Relaxed);
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
                        location: string_info.offset.map(|o| format!("{:#x}", o)),
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
