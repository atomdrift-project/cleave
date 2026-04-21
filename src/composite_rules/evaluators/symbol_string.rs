//! Symbol and string-based condition evaluators.
//!
//! This module handles evaluation of:
//! - Symbol matching (imports, exports)
//! - String content matching (extracted strings, raw content)
//! - Decoded string matching (Base64, XOR)
//! - String count analysis

use super::{
    resolve_effective_range, resolve_effective_range_opt, symbol_matches, ContentLocationParams,
};
use crate::composite_rules::condition::{NotException, StringValidator, SymbolKind};
use crate::composite_rules::context::{ConditionResult, EvaluationContext, StringParams};
use crate::composite_rules::types::Platform;
use crate::ip_validator::contains_external_ip_cached;
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
        Some(StringValidator::BitcoinAddr) => contains_bitcoin_address(s),
    }
}
use crate::types::binary::normalize_symbol;
use crate::types::{Evidence, MAX_EVIDENCE_PER_TRAIT};

/// Maximum number of matches to process from regex find_iter() to prevent DoS on pattern-dense files
const MAX_MATCHES_TO_PROCESS: usize = 10_000;

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
    compiled_regex: Option<&regex::Regex>,
    compiled_finder: Option<&memchr::memmem::Finder<'static>>,
    not: Option<&Vec<NotException>>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
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
    if not.is_none() && is_check.is_none() && kind.is_none() {
        if let Some(trait_idx) = ctx.current_trait_idx {
            if let Some(cached) = ctx.cached_evidence.and_then(|m| m.get(&trait_idx)) {
                if !cached.is_empty() {
                    return ConditionResult {
                        matched: true,
                        evidence: cached.clone(),
                        match_count: cached.len(),
                        warnings: Vec::new(),
                        precision: 2.0, // Symbols are high-precision by default
                        matched_trait_ids: Vec::new(),
                    };
                }
            }
        }
    }

    // Normalize exact/substr patterns the same way symbols are normalized at load time,
    // so rule authors can write `exact: "__libc_start_main"` and it matches.
    let norm_exact = exact.map(|s| normalize_symbol(s));
    let norm_exact_ref = norm_exact.as_ref();
    let norm_substr = substr.map(|s| normalize_symbol(s));
    let norm_substr_ref = norm_substr.as_ref();

    // Use the pre-compiled Finder from the Condition when available (built from the
    // normalized pattern at trait load time).  Fall back to building a local one from
    // norm_substr so we still avoid per-symbol StrSearcher::new when the Condition
    // wasn't precompiled (e.g. in tests).
    let local_finder;
    let effective_finder: Option<&memchr::memmem::Finder<'static>> = if compiled_finder.is_some() {
        compiled_finder
    } else if let Some(s) = norm_substr_ref {
        local_finder = memchr::memmem::Finder::new(s.as_bytes()).into_owned();
        Some(&local_finder)
    } else {
        None
    };

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
                compiled_regex,
                effective_finder,
            ) {
                // Check if this symbol should be excluded by not: or is: filters
                let excluded_by_not = not
                    .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&import.symbol)))
                    .unwrap_or(false);
                let excluded_by_is = !validate_match(&import.symbol, is_check);

                if !excluded_by_not && !excluded_by_is {
                    match_count += 1;
                    if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                        evidence.push(Evidence {
                            method: "symbol".to_string(),
                            source: import.source.clone(),
                            value: import.symbol.clone(),
                            location: Some("import".to_string()),
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
                    compiled_regex,
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
                compiled_regex,
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

fn match_value_against_params(
    value: &str,
    params: &StringParams<'_>,
    substr_lower: Option<&String>,
) -> Option<String> {
    if let Some(exact_str) = params.exact {
        let matched = if params.case_insensitive {
            value.eq_ignore_ascii_case(exact_str)
        } else {
            value == exact_str
        };
        return matched.then(|| exact_str.clone());
    }

    if let Some(contains_str) = params.substr {
        let matched = if params.case_insensitive {
            // For CI: lowercase the value and search with the pre-lowercased finder/pattern.
            // Use to_ascii_lowercase (faster, correct for ASCII patterns used in traits).
            let value_lower = value.to_ascii_lowercase();
            if let Some(finder) = params.compiled_finder {
                finder.find(value_lower.as_bytes()).is_some()
            } else if let Some(pattern_lower) = substr_lower {
                value_lower.contains(pattern_lower.as_str())
            } else {
                value_lower.contains(contains_str.to_ascii_lowercase().as_str())
            }
        } else if let Some(finder) = params.compiled_finder {
            finder.find(value.as_bytes()).is_some()
        } else {
            memchr::memmem::find(value.as_bytes(), contains_str.as_bytes()).is_some()
        };
        return matched.then(|| value.to_string());
    }

    if let Some(re) = params.compiled_regex {
        return re.find(value).map(|mat| mat.as_str().to_string());
    }

    if let Some(regex_pattern) = params.regex {
        if let Ok(re) = super::build_regex(regex_pattern, params.case_insensitive) {
            return re.find(value).map(|mat| mat.as_str().to_string());
        }
    }

    None
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

/// Evaluate string condition - searches in properly extracted/bounded strings,
/// as well as imports and exports if they match the string criteria.
///
/// For searching raw file content, use `eval_raw()` instead.
#[must_use]
pub(crate) fn eval_string<'a, 'b>(
    params: &StringParams<'a>,
    trait_not: Option<&Vec<NotException>>,
    ctx: &EvaluationContext<'b>,
) -> ConditionResult {
    let profile = *PROFILE_TIMING_ENABLED;
    let t_start = if profile {
        Some(std::time::Instant::now())
    } else {
        None
    };

    let mut evidence = Vec::new();

    // Resolve effective range from location constraints
    let has_location_constraint = params.section.is_some()
        || params.offset.is_some()
        || params.offset_range.is_some()
        || params.section_offset.is_some()
        || params.section_offset_range.is_some()
        || params.arch_clamp.is_some();
    let effective_range: Option<(u64, u64)> = if has_location_constraint {
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
    };

    // Use pre-compiled regex from trait definition (compiled at startup)
    let compiled_regex = params.compiled_regex;

    // FAST PATH 0: Use pre-computed evidence from indexed matching if available.
    // This is only safe when there are no location constraints (offset, section)
    // because the indexer does not currently handle those.
    if !has_location_constraint && trait_not.is_none() && params.is_check.is_none() {
        if let Some(trait_idx) = ctx.current_trait_idx {
            if let Some(cached) = ctx.cached_evidence.and_then(|m| m.get(&trait_idx)) {
                if !cached.is_empty() {
                    return ConditionResult {
                        matched: true,
                        evidence: cached.clone(),
                        match_count: cached.len(), // Approximation, but correct for most traits
                        warnings: Vec::new(),
                        precision: if params.case_insensitive { 1.0 } else { 2.0 },
                        matched_trait_ids: Vec::new(),
                    };
                }
            }
        }
    }

    // FAST PATH 1: Use indexed lookup for exact matches (O(1) instead of O(n))
    if let Some(exact_str) = params.exact {
        if effective_range.is_none() {
            // No offset constraints - can use the index directly
            let mut evidence = Vec::new();

            if params.case_insensitive {
                if let Some(match_list) = ctx
                    .get_string_exact_index_ci()
                    .get(&exact_str.to_lowercase())
                {
                    for (i, (original_value, source, offset)) in match_list.iter().enumerate() {
                        if i >= MAX_EVIDENCE_PER_TRAIT {
                            break;
                        }

                        // Apply not: exclusion filter
                        let excluded_by_not = trait_not
                            .map(|exceptions| {
                                exceptions.iter().any(|exc| exc.matches(original_value))
                            })
                            .unwrap_or(false);
                        let excluded_by_is = !validate_match(original_value, params.is_check);

                        if !excluded_by_not && !excluded_by_is {
                            let method = if *source == "string_extractor" {
                                "string"
                            } else if ctx.report.imports.iter().any(|i| i.source == *source) {
                                "import_symbol"
                            } else {
                                "export_symbol"
                            };

                            evidence.push(Evidence {
                                method: method.to_string(),
                                source: source.to_string(),
                                value: original_value.to_string(),
                                location: offset.map(|o| format!("{:#x}", o)),
                                ..Default::default()
                            });
                        }
                    }
                }
            } else if let Some(match_list) = ctx.get_string_exact_index().get(exact_str.as_str()) {
                for (i, (source, offset)) in match_list.iter().enumerate() {
                    let original_value = exact_str;
                    if i >= MAX_EVIDENCE_PER_TRAIT {
                        break;
                    }

                    // Apply not: exclusion filter
                    let excluded_by_not = trait_not
                        .map(|exceptions| exceptions.iter().any(|exc| exc.matches(original_value)))
                        .unwrap_or(false);
                    let excluded_by_is = !validate_match(original_value, params.is_check);

                    if !excluded_by_not && !excluded_by_is {
                        let method = if *source == "string_extractor" {
                            "string"
                        } else if ctx.report.imports.iter().any(|i| i.source == *source) {
                            "import_symbol"
                        } else {
                            "export_symbol"
                        };
                        evidence.push(Evidence {
                            method: method.to_string(),
                            source: source.to_string(),
                            value: original_value.to_string(),
                            location: offset.map(|o| format!("{:#x}", o)),
                            ..Default::default()
                        });
                    }
                }
            }

            // Early return for indexed exact match
            if let Some(t) = t_start {
                if profile {
                    eprintln!(
                        "[PROFILE]   eval_string (indexed): {}ms",
                        t.elapsed().as_millis()
                    );
                }
            }

            let matched = !evidence.is_empty();
            let match_count = evidence.len();
            let precision = if params.case_insensitive { 1.0 } else { 2.0 };

            return ConditionResult {
                matched,
                evidence,
                match_count,
                warnings: Vec::new(),
                precision,
                matched_trait_ids: Vec::new(),
            };
        }
    }

    // SLOW PATH: Fall back to iteration for substr/regex/offset-constrained matches

    // Pre-compute lowercase pattern once (avoids allocation per string checked)
    let substr_lower: Option<String> = if params.case_insensitive {
        params.substr.map(|s| s.to_lowercase())
    } else {
        None
    };

    // Separate match counter — not capped by MAX_EVIDENCE_PER_TRAIT
    let mut match_count: usize = 0;

    // Helper to check if a value matches and add to evidence
    let check_and_add_evidence = |value: &str,
                                  source: &str,
                                  method: &str,
                                  location: Option<String>,
                                  evidence: &mut Vec<Evidence>,
                                  match_count: &mut usize| {
        let mut matched = false;
        let mut match_value = String::new();

        if let Some(exact_str) = params.exact {
            matched = if params.case_insensitive {
                value.eq_ignore_ascii_case(exact_str)
            } else {
                value == *exact_str
            };
            if matched {
                match_value = exact_str.clone();
            }
        } else if let Some(contains_str) = params.substr {
            matched = if params.case_insensitive {
                if let Some(ref pattern_lower) = substr_lower {
                    // Note: This still allocates via to_lowercase().
                    // Most CI substr matches should have been caught by FAST PATH 0.
                    value.to_lowercase().contains(pattern_lower.as_str())
                } else {
                    // Fallback for unexpected state
                    value.to_lowercase().contains(&contains_str.to_lowercase())
                }
            } else {
                value.contains(contains_str)
            };
            if matched {
                // Use the full string value for not: filtering, not just the substr pattern
                match_value = value.to_string();
            }
        } else if let Some(re) = compiled_regex {
            if let Some(mat) = re.find(value) {
                matched = true;
                match_value = mat.as_str().to_string();
            }
        } else if let Some(regex_pattern) = params.regex {
            if let Ok(re) = super::build_regex(regex_pattern, params.case_insensitive) {
                if let Some(mat) = re.find(value) {
                    matched = true;
                    match_value = mat.as_str().to_string();
                }
            }
        }

        if matched {
            let excluded_by_not = trait_not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&match_value)))
                .unwrap_or(false);
            // When is: validator is set, require match to pass validation
            let excluded_by_is = !validate_match(&match_value, params.is_check);

            if !excluded_by_not && !excluded_by_is {
                *match_count += 1;
                if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: method.to_string(),
                        source: source.to_string(),
                        value: match_value,
                        location,
                        ..Default::default()
                    });
                }
            }
        }
    };

    // 1. Check in extracted strings from report (for binaries)
    for string_info in &ctx.report.strings {
        // Skip strings outside the effective range (if location constraints are specified)
        if !offset_in_range(string_info.offset, effective_range) {
            continue;
        }
        check_and_add_evidence(
            &string_info.value,
            "string_extractor",
            "string",
            string_info.offset.map(|o| format!("{:#x}", o)),
            &mut evidence,
            &mut match_count,
        );
    }

    // 2. Check in imports and exports — but skip when location constraints are set,
    // since imports/exports have no meaningful file offset or section.
    let has_location_constraint = params.section.is_some()
        || params.offset.is_some()
        || params.offset_range.is_some()
        || params.section_offset.is_some()
        || params.section_offset_range.is_some();

    if !has_location_constraint {
        for import in &ctx.report.imports {
            check_and_add_evidence(
                &import.symbol,
                &import.source,
                "import_symbol",
                None,
                &mut evidence,
                &mut match_count,
            );
        }

        for export in &ctx.report.exports {
            check_and_add_evidence(
                &export.symbol,
                &export.source,
                "export_symbol",
                export.offset.clone(),
                &mut evidence,
                &mut match_count,
            );
        }
    }

    if let Some(t) = t_start {
        if profile {
            eprintln!("[PROFILE]   eval_string: {}ms", t.elapsed().as_millis());
        }
    }

    // Calculate precision based on constraint specificity
    let mut precision = 0.0f32;

    // Pattern type scoring: exact > regex/word > substr
    if params.exact.is_some() {
        precision += 2.0; // Exact match: most specific
    } else if params.regex.is_some() || params.word.is_some() {
        precision += 1.5; // Pattern matching or word boundaries
    } else if params.substr.is_some() {
        precision += 1.0; // Substring match: least specific
    }

    // Modifiers (additive)
    // count/density constraints are now scored at trait level
    // Location constraints add precision (section/offset filtering is very specific)
    if params.section.is_some() {
        precision += 1.0; // Section constraint
    }
    if params.offset.is_some() {
        precision += 1.5; // Exact offset is very specific
    } else if params.offset_range.is_some()
        || params.section_offset.is_some()
        || params.section_offset_range.is_some()
    {
        precision += 1.0; // Range constraints
    }

    // case_insensitive penalty (multiplicative)
    if params.case_insensitive {
        precision *= 0.5;
    }

    // count/density constraints are now checked at trait level
    let matched = !evidence.is_empty();

    ConditionResult {
        matched,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision,
        matched_trait_ids: Vec::new(),
    }
}

/// Evaluate text condition.
///
/// On source and structured text formats this delegates to raw-content search.
/// On binary-like formats it searches extracted strings only.
#[must_use]
pub(crate) fn eval_text<'a, 'b>(
    params: &StringParams<'a>,
    trait_not: Option<&Vec<NotException>>,
    ctx: &EvaluationContext<'b>,
    trait_id: Option<&str>,
) -> ConditionResult {
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
            params.compiled_regex,
            trait_not,
            &location,
            ctx,
            trait_id,
        );
    }

    let effective_range = resolve_string_effective_range(params, ctx);
    let has_location_constraint = has_string_location_constraint(params);

    if !has_location_constraint && trait_not.is_none() && params.is_check.is_none() {
        if let Some(trait_idx) = ctx.current_trait_idx {
            if let Some(cached) = ctx.cached_evidence.and_then(|m| m.get(&trait_idx)) {
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
        }
    }

    if let Some(exact_str) = params.exact {
        if effective_range.is_none() {
            let mut evidence = Vec::new();

            if params.case_insensitive {
                if let Some(match_list) = ctx
                    .get_string_exact_index_ci()
                    .get(&exact_str.to_lowercase())
                {
                    for (i, (original_value, source, offset)) in match_list.iter().enumerate() {
                        if *source != "string_extractor" || i >= MAX_EVIDENCE_PER_TRAIT {
                            continue;
                        }
                        let excluded_by_not = trait_not
                            .map(|exceptions| {
                                exceptions.iter().any(|exc| exc.matches(original_value))
                            })
                            .unwrap_or(false);
                        let excluded_by_is = !validate_match(original_value, params.is_check);

                        if !excluded_by_not && !excluded_by_is {
                            evidence.push(Evidence {
                                method: "text".to_string(),
                                source: source.to_string(),
                                value: original_value.to_string(),
                                location: offset.map(|o| format!("{:#x}", o)),
                                ..Default::default()
                            });
                        }
                    }
                }
            } else if let Some(match_list) = ctx.get_string_exact_index().get(exact_str.as_str()) {
                for (i, (source, offset)) in match_list.iter().enumerate() {
                    if *source != "string_extractor" || i >= MAX_EVIDENCE_PER_TRAIT {
                        continue;
                    }
                    let excluded_by_not = trait_not
                        .map(|exceptions| exceptions.iter().any(|exc| exc.matches(exact_str)))
                        .unwrap_or(false);
                    let excluded_by_is = !validate_match(exact_str, params.is_check);

                    if !excluded_by_not && !excluded_by_is {
                        evidence.push(Evidence {
                            method: "text".to_string(),
                            source: source.to_string(),
                            value: exact_str.to_string(),
                            location: offset.map(|o| format!("{:#x}", o)),
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
    }

    let substr_lower = if params.case_insensitive {
        params.substr.map(|s| s.to_lowercase())
    } else {
        None
    };

    let mut evidence = Vec::new();
    let mut match_count = 0usize;

    for string_info in &ctx.report.strings {
        if !offset_in_range(string_info.offset, effective_range) {
            continue;
        }

        if let Some(match_value) =
            match_value_against_params(&string_info.value, params, substr_lower.as_ref())
        {
            let excluded_by_not = trait_not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&match_value)))
                .unwrap_or(false);
            let excluded_by_is = !validate_match(&match_value, params.is_check);

            if !excluded_by_not && !excluded_by_is {
                match_count += 1;
                if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "text".to_string(),
                        source: "string_extractor".to_string(),
                        value: match_value,
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
    let substr_lower = if params.case_insensitive {
        params.substr.map(|s| s.to_lowercase())
    } else {
        None
    };

    let mut evidence = Vec::new();
    let mut match_count = 0usize;

    for string_info in &ctx.report.strings {
        if string_info.section.as_deref() != Some("ast") {
            continue;
        }
        if !offset_in_range(string_info.offset, effective_range) {
            continue;
        }

        if let Some(match_value) =
            match_value_against_params(&string_info.value, params, substr_lower.as_ref())
        {
            let excluded_by_not = trait_not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&match_value)))
                .unwrap_or(false);
            let excluded_by_is = !validate_match(&match_value, params.is_check);

            if !excluded_by_not && !excluded_by_is {
                match_count += 1;
                if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "string_literal".to_string(),
                        source: "ast".to_string(),
                        value: match_value,
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

/// Used by `type: raw` conditions to search raw file content rather than extracted strings.
/// Use for cross-boundary patterns or when string extraction is insufficient.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub(crate) fn eval_raw<'a>(
    exact: Option<&String>,
    substr: Option<&String>,
    _regex: Option<&String>,
    _word: Option<&String>,
    case_insensitive: bool,
    is_check: Option<StringValidator>,
    compiled_regex: Option<&regex::Regex>,
    not: Option<&Vec<NotException>>,
    location: &ContentLocationParams,
    ctx: &EvaluationContext<'a>,
    trait_id: Option<&str>,
) -> ConditionResult {
    // Reject short raw patterns unless search space is bounded (~1KB).
    // Acceptable: offset/offset_range, or section + section_offset*.
    // Density constraints (count_min, per_kb_min) are checked at trait level, not here.
    {
        const MIN_PATTERN_LEN: usize = 3;
        let has_pinpoint = location.offset.is_some() || location.offset_range.is_some();
        let has_section_pinpoint = location.section.is_some()
            && (location.section_offset.is_some() || location.section_offset_range.is_some());
        if !has_pinpoint && !has_section_pinpoint {
            if let Some(s) = exact {
                if s.len() < MIN_PATTERN_LEN {
                    return ConditionResult::no_match();
                }
            }
            if let Some(s) = substr {
                if s.len() < MIN_PATTERN_LEN {
                    return ConditionResult::no_match();
                }
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
            let bytes_re: Option<regex::bytes::Regex> = {
                let cached = cache.read().peek(&key).cloned();
                if cached.is_some() {
                    cached
                } else {
                    // Compile outside the lock; write-lock only to insert.
                    match super::compile_bytes_regex(pattern_str, case_insensitive) {
                        Ok(re) => {
                            cache.write().put(key, re.clone());
                            Some(re)
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
                        if let Some(not_filters) = not {
                            if not_filters.iter().any(|filter| filter.matches(&match_str)) {
                                continue;
                            }
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
                if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    if let Some(matched) = first_match {
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
            }
        } else {
            // UNICODE PATH: Use cached UTF-8 conversion for Unicode regex
            let content =
                super::get_utf8_cached(ctx.binary_data, (search_start, search_end), ctx.file_id());
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
                if let Some(not_filters) = not {
                    if not_filters.iter().any(|filter| filter.matches(match_str)) {
                        continue;
                    }
                }
                match_count += 1;
                if first_match.is_none() {
                    first_match = Some(match_str.to_string());
                    first_offset = Some((search_start + mat.start()) as u64);
                }
            }
            if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                if let Some(matched) = first_match {
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
        }
    } else if let Some(exact_str) = exact {
        // Full string match - OPTIMIZED: byte-level comparison for ASCII
        if can_use_byte_matching(exact_str) {
            // Fast path: Byte-level exact match (no UTF-8 conversion needed!)
            let matched = if case_insensitive {
                search_data.eq_ignore_ascii_case(exact_str.as_bytes())
            } else {
                search_data == exact_str.as_bytes()
            };

            // When is: validator is set, only convert to string for validation if needed
            let is_ok = validate_match(&String::from_utf8_lossy(search_data), is_check);

            let excluded_by_not = not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(exact_str)))
                .unwrap_or(false);

            if matched && is_ok && !excluded_by_not && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                match_count = 1;
                evidence.push(Evidence {
                    method: "raw".to_string(),
                    source: "raw_content".to_string(),
                    value: format!("Exact match: {}", exact_str),
                    location: None,
                    offsets: vec![search_start as u64],
                    ..Default::default()
                });
            }
        } else {
            // Unicode pattern - use cached UTF-8 conversion
            let content =
                super::get_utf8_cached(ctx.binary_data, (search_start, search_end), ctx.file_id());

            let matched = if case_insensitive {
                content.eq_ignore_ascii_case(exact_str)
            } else {
                content.as_ref() == exact_str
            };

            let is_ok = validate_match(&content, is_check);
            let excluded_by_not = not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(exact_str)))
                .unwrap_or(false);

            if matched && is_ok && !excluded_by_not && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                match_count = 1;
                evidence.push(Evidence {
                    method: "raw".to_string(),
                    source: "raw_content".to_string(),
                    value: format!("Exact match: {}", exact_str),
                    location: None,
                    offsets: vec![search_start as u64],
                    ..Default::default()
                });
            }
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
            let content =
                super::get_utf8_cached(ctx.binary_data, (search_start, search_end), ctx.file_id());

            if is_check.is_some() {
                // For validator validation, we need to find actual match positions
                let search_content = if case_insensitive {
                    content.to_lowercase()
                } else {
                    content.to_string()
                };
                let search_pattern = if case_insensitive {
                    substr_str.to_lowercase()
                } else {
                    substr_str.clone()
                };
                let mut first_match_offset = None;
                let mut start = 0;
                while let Some(pos) = search_content[start..].find(&search_pattern) {
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
                let search_content = if case_insensitive {
                    content.to_lowercase()
                } else {
                    content.to_string()
                };
                let search_pattern = if case_insensitive {
                    substr_str.to_lowercase()
                } else {
                    substr_str.clone()
                };
                let mut first_match_offset = None;
                let mut start = 0;
                while let Some(pos) = search_content[start..].find(&search_pattern) {
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
                let search_content = if case_insensitive {
                    content.to_lowercase()
                } else {
                    content.to_string()
                };
                let search_pattern = if case_insensitive {
                    substr_str.to_lowercase()
                } else {
                    substr_str.clone()
                };
                let first_offset = search_content
                    .find(&search_pattern)
                    .map(|o| (search_start + o) as u64);
                match_count = search_content.matches(&search_pattern).count();
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

    if let Some(t) = t_start {
        if profile {
            eprintln!("[PROFILE]   eval_raw: {}ms", t.elapsed().as_millis());
        }
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
    compiled_regex: Option<&regex::Regex>,
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

    // Build regex if needed (prefer compiled_regex if available)
    let regex_matcher = if let Some(compiled) = compiled_regex {
        Some(compiled.clone())
    } else if let Some(pattern) = regex {
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
        if !matches {
            if let Some(substr_str) = substr {
                matches = if case_insensitive {
                    string_info
                        .value
                        .to_lowercase()
                        .contains(&substr_str.to_lowercase())
                } else {
                    string_info.value.contains(substr_str.as_str())
                };
            }
        }

        // Check regex or word match
        if !matches {
            if let Some(ref re) = regex_matcher {
                matches = re.is_match(&string_info.value);
            }
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
                        string_info.value.clone()
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

