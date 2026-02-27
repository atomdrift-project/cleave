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
use crate::composite_rules::condition::NotException;
use crate::composite_rules::context::{ConditionResult, EvaluationContext, StringParams};
use crate::composite_rules::types::Platform;
use crate::ip_validator::contains_external_ip;
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

/// Evaluate symbol condition - matches symbols in imports/exports.
#[must_use]
pub(crate) fn eval_symbol<'a>(
    exact: Option<&String>,
    substr: Option<&String>,
    pattern: Option<&String>,
    platforms: Option<&Vec<Platform>>,
    compiled_regex: Option<&regex::Regex>,
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

    // Search in imports
    for import in &ctx.report.imports {
        if symbol_matches_condition(&import.symbol, exact, substr, pattern, compiled_regex) {
            // Check if this symbol should be excluded by not: filters
            let excluded_by_not = not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&import.symbol)))
                .unwrap_or(false);

            if !excluded_by_not && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
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

    // Search in exports
    for export in &ctx.report.exports {
        if symbol_matches_condition(&export.symbol, exact, substr, pattern, compiled_regex) {
            // Check if this symbol should be excluded by not: filters
            let excluded_by_not = not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&export.symbol)))
                .unwrap_or(false);

            if !excluded_by_not && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                evidence.push(Evidence {
                    method: "symbol".to_string(),
                    source: export.source.clone(),
                    value: export.symbol.clone(),
                    location: export.offset.clone(),
                    ..Default::default()
                });
            }
        }
    }

    // Search in internal functions (important for statically linked Go binaries)
    for func in &ctx.report.functions {
        if symbol_matches_condition(&func.name, exact, substr, pattern, compiled_regex) {
            // Check if this symbol should be excluded by not: filters
            let excluded_by_not = not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&func.name)))
                .unwrap_or(false);

            if !excluded_by_not && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
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
    let matched = !evidence.is_empty();
    let match_count = evidence.len();

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
) -> bool {
    // If exact is specified, do strict equality match
    if let Some(exact_val) = exact {
        return symbol == exact_val;
    }

    // If substr is specified, do substring match
    if let Some(substr_val) = substr {
        return symbol.contains(substr_val.as_str());
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
    let profile = std::env::var("CLEAVE_PROFILE").is_ok();
    let t_start = if profile {
        Some(std::time::Instant::now())
    } else {
        None
    };

    let mut evidence = Vec::new();

    // Resolve effective range from location constraints
    let effective_range: Option<(u64, u64)> = if params.section.is_some()
        || params.offset.is_some()
        || params.offset_range.is_some()
        || params.section_offset.is_some()
        || params.section_offset_range.is_some()
    {
        // Use SectionMap to resolve the range if available
        if let Some(ref section_map) = ctx.section_map {
            section_map.resolve_range(
                params.section.map(std::string::String::as_str),
                params.offset,
                params.offset_range,
                params.section_offset,
                params.section_offset_range,
            )
        } else {
            // No SectionMap available - use absolute offset constraints only
            match (params.offset, params.offset_range) {
                (Some(off), None) => {
                    // Single offset - resolve to single byte range
                    let file_size = ctx.binary_data.len() as i64;
                    let resolved = if off < 0 {
                        (file_size + off).max(0) as u64
                    } else {
                        off as u64
                    };
                    Some((resolved, resolved + 1))
                }
                (None, Some((start, end_opt))) => {
                    let file_size = ctx.binary_data.len() as i64;
                    let resolved_start = if start < 0 {
                        (file_size + start).max(0) as u64
                    } else {
                        start as u64
                    };
                    let resolved_end = match end_opt {
                        Some(end) if end < 0 => (file_size + end).max(0) as u64,
                        Some(end) => end as u64,
                        None => file_size as u64,
                    };
                    Some((resolved_start, resolved_end))
                }
                _ => None, // Section constraints without SectionMap - no filtering
            }
        }
    } else {
        None // No location constraints
    };

    // Use pre-compiled regex from trait definition (compiled at startup)
    let compiled_regex = params.compiled_regex;

    // FAST PATH: Use indexed lookup for exact matches (O(1) instead of O(n))
    if let Some(exact_str) = params.exact {
        if effective_range.is_none() {
            // No offset constraints - can use the index directly
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
                        let excluded_by_ip =
                            params.external_ip && !contains_external_ip(original_value);

                        if !excluded_by_not && !excluded_by_ip {
                            let method = if source == "string_extractor" {
                                "string"
                            } else if ctx.report.imports.iter().any(|i| i.source == *source) {
                                "import_symbol"
                            } else {
                                "export_symbol"
                            };
                            evidence.push(Evidence {
                                method: method.to_string(),
                                source: source.clone(),
                                value: original_value.clone(),
                                location: offset.map(|o| format!("{:#x}", o)),
                                ..Default::default()
                            });
                        }
                    }
                }
            } else if let Some(match_list) = ctx
                .get_string_exact_index()
                .get(exact_str.as_str())
            {
                for (i, (source, offset)) in match_list.iter().enumerate() {
                    if i >= MAX_EVIDENCE_PER_TRAIT {
                        break;
                    }

                    // Apply not: exclusion filter
                    let excluded_by_not = trait_not
                        .map(|exceptions| exceptions.iter().any(|exc| exc.matches(exact_str)))
                        .unwrap_or(false);
                    let excluded_by_ip =
                        params.external_ip && !contains_external_ip(exact_str);

                    if !excluded_by_not && !excluded_by_ip {
                        let method = if source == "string_extractor" {
                            "string"
                        } else if ctx.report.imports.iter().any(|i| i.source == *source) {
                            "import_symbol"
                        } else {
                            "export_symbol"
                        };
                        evidence.push(Evidence {
                            method: method.to_string(),
                            source: source.clone(),
                            value: exact_str.clone(),
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

    // Helper to check if a value matches and add to evidence
    let check_and_add_evidence = |value: &str,
                                  source: &str,
                                  method: &str,
                                  location: Option<String>,
                                  evidence: &mut Vec<Evidence>| {
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
            matched = if let Some(ref pattern_lower) = substr_lower {
                // Use pre-computed lowercase pattern (avoids allocation per iteration)
                value.to_lowercase().contains(pattern_lower.as_str())
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
            // When external_ip is set, require match to contain a valid external IP
            let excluded_by_ip = params.external_ip && !contains_external_ip(&match_value);

            if !excluded_by_not && !excluded_by_ip && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                evidence.push(Evidence {
                    method: method.to_string(),
                    source: source.to_string(),
                    value: match_value,
                    location,
                    ..Default::default()
                });
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
        );
    }

    // 2. Check in imports (symbols are strings too!)
    for import in &ctx.report.imports {
        check_and_add_evidence(
            &import.symbol,
            &import.source,
            "import_symbol",
            None,
            &mut evidence,
        );
    }

    // 3. Check in exports
    for export in &ctx.report.exports {
        check_and_add_evidence(
            &export.symbol,
            &export.source,
            "export_symbol",
            export.offset.clone(),
            &mut evidence,
        );
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
    let match_count = evidence.len();

    ConditionResult {
        matched,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision,
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
    external_ip: bool,
    compiled_regex: Option<&regex::Regex>,
    not: Option<&Vec<NotException>>,
    location: &ContentLocationParams,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let profile = std::env::var("CLEAVE_PROFILE").is_ok();
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
            // Get or compile bytes regex from bounded LRU cache
            let key = (pattern_str.to_string(), case_insensitive);
            let bytes_re: Option<super::CachedRegex> = {
                let cache = super::regex_cache_v2();
                // Try to get from cache first
                let cached = {
                    let mut guard = cache.write();
                    guard.get(&key).cloned()
                };
                if let Some(re) = cached {
                    Some(re)
                } else {
                    // Compile and insert
                    match super::compile_regex_optimal(pattern_str, case_insensitive) {
                        Ok(re) => {
                            let mut guard = cache.write();
                            guard.put(key, re.clone());
                            Some(re)
                        }
                        Err(_) => None,
                    }
                }
            };

            if let Some(super::CachedRegex::Bytes(ref bytes_re)) = bytes_re {
                let mut first_match = None;
                for (idx, mat) in bytes_re.find_iter(search_data).enumerate() {
                    if idx >= MAX_MATCHES_TO_PROCESS {
                        eprintln!(
                            "WARNING: Hit match limit of {} matches for regex pattern, stopping early",
                            MAX_MATCHES_TO_PROCESS
                        );
                        break;
                    }
                    let match_bytes = mat.as_bytes();

                    // For external_ip or not filters, convert only the match to string
                    if external_ip || not.is_some() {
                        let match_str = String::from_utf8_lossy(match_bytes);
                        if external_ip && !contains_external_ip(&match_str) {
                            continue;
                        }
                        if let Some(not_filters) = not {
                            if not_filters.iter().any(|filter| filter.matches(&match_str)) {
                                continue;
                            }
                        }
                        if first_match.is_none() {
                            first_match = Some(match_str.to_string());
                        }
                    } else {
                        // No filters, just count
                        if first_match.is_none() {
                            first_match = Some(String::from_utf8_lossy(match_bytes).to_string());
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
                            location: Some("file".to_string()),
                            ..Default::default()
                        });
                    }
                }
            }
        } else {
            // UNICODE PATH: Use cached UTF-8 conversion for Unicode regex
            let content = super::get_utf8_cached(ctx.binary_data, (search_start, search_end));

            let mut first_match = None;
            for (idx, mat) in re.find_iter(&content).enumerate() {
                // Limit match processing to prevent DoS on pattern-dense files
                if idx >= MAX_MATCHES_TO_PROCESS {
                    eprintln!(
                        "WARNING: Hit match limit of {} matches for regex pattern, stopping early",
                        MAX_MATCHES_TO_PROCESS
                    );
                    break;
                }
                let match_str = mat.as_str();
                // Skip matches without external IP when external_ip is required
                if external_ip && !contains_external_ip(match_str) {
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
                }
            }
            if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                if let Some(matched) = first_match {
                    evidence.push(Evidence {
                        method: "raw".to_string(),
                        source: "raw_content".to_string(),
                        value: matched,
                        location: Some("file".to_string()),
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

            // When external_ip is set, only convert to string for IP check if needed
            let ip_ok = !external_ip || {
                let content = String::from_utf8_lossy(search_data);
                contains_external_ip(&content)
            };

            let excluded_by_not = not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(exact_str)))
                .unwrap_or(false);

            if matched && ip_ok && !excluded_by_not && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                match_count = 1;
                evidence.push(Evidence {
                    method: "raw".to_string(),
                    source: "raw_content".to_string(),
                    value: format!("Exact match: {}", exact_str),
                    location: Some("file".to_string()),
                    ..Default::default()
                });
            }
        } else {
            // Unicode pattern - use cached UTF-8 conversion
            let content = super::get_utf8_cached(ctx.binary_data, (search_start, search_end));

            let matched = if case_insensitive {
                content.eq_ignore_ascii_case(exact_str)
            } else {
                content.as_ref() == exact_str
            };

            let ip_ok = !external_ip || contains_external_ip(&content);
            let excluded_by_not = not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(exact_str)))
                .unwrap_or(false);

            if matched && ip_ok && !excluded_by_not && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                match_count = 1;
                evidence.push(Evidence {
                    method: "raw".to_string(),
                    source: "raw_content".to_string(),
                    value: format!("Exact match: {}", exact_str),
                    location: Some("file".to_string()),
                    ..Default::default()
                });
            }
        }
    } else if let Some(substr_str) = substr {
        // Substring match - OPTIMIZED: use byte-level search for ASCII patterns
        if can_use_byte_matching(substr_str) {
            // Fast path: Byte-level substring search (avoids UTF-8 conversion)
            if external_ip {
                // Need to check each match context for external IP
                if case_insensitive {
                    let pattern_lower = substr_str.to_ascii_lowercase();
                    let needle = pattern_lower.as_bytes();
                    let finder = memchr::memmem::Finder::new(needle);

                    // Pre-lowercase entire search data ONCE (not per-iteration!)
                    let search_lower = search_data.to_ascii_lowercase();
                    let mut pos = 0;
                    while let Some(offset) = finder.find(&search_lower[pos..]) {
                        let abs_pos = pos + offset;
                        // Convert only context window for IP check (not entire file!)
                        let ctx_start = abs_pos.saturating_sub(50);
                        let ctx_end = (abs_pos + needle.len() + 50).min(search_data.len());
                        let context = String::from_utf8_lossy(&search_data[ctx_start..ctx_end]);

                        if contains_external_ip(&context) {
                            let excluded = not
                                .map(|excs| excs.iter().any(|e| e.matches(substr_str)))
                                .unwrap_or(false);
                            if !excluded {
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

                        if contains_external_ip(&context) {
                            let excluded = not
                                .map(|excs| excs.iter().any(|e| e.matches(substr_str)))
                                .unwrap_or(false);
                            if !excluded {
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
                        location: Some("file".to_string()),
                        ..Default::default()
                    });
                }
            } else {
                // Simple count - just count byte occurrences (fastest path!)
                let excluded = not
                    .map(|excs| excs.iter().any(|e| e.matches(substr_str)))
                    .unwrap_or(false);

                if !excluded {
                    if case_insensitive {
                        let pattern_lower = substr_str.to_ascii_lowercase();
                        let needle = pattern_lower.as_bytes();
                        // Pre-lowercase once, not inside find_iter (avoids O(file_size) allocation per call)
                        let search_lower = search_data.to_ascii_lowercase();
                        match_count = memchr::memmem::find_iter(&search_lower, needle).count();
                    } else {
                        let needle = substr_str.as_bytes();
                        match_count = memchr::memmem::find_iter(search_data, needle).count();
                    }

                    if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                        evidence.push(Evidence {
                            method: "raw".to_string(),
                            source: "raw_content".to_string(),
                            value: substr_str.to_string(),
                            location: Some("file".to_string()),
                            ..Default::default()
                        });
                    }
                }
            }
        } else {
            // Unicode pattern - fall back to cached UTF-8 conversion
            let content = super::get_utf8_cached(ctx.binary_data, (search_start, search_end));

            if external_ip {
                // For external_ip validation, we need to find actual match positions
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
                let mut start = 0;
                while let Some(pos) = search_content[start..].find(&search_pattern) {
                    let abs_pos = start + pos;
                    // Get some context around the match to check for IP
                    let context_start = abs_pos.saturating_sub(50);
                    let context_end = (abs_pos + search_pattern.len() + 50).min(content.len());
                    let context = &content[context_start..context_end];
                    if contains_external_ip(context) {
                        let excluded_by_not = not
                            .map(|exceptions| exceptions.iter().any(|exc| exc.matches(substr_str)))
                            .unwrap_or(false);
                        if !excluded_by_not {
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
                        location: Some("file".to_string()),
                        ..Default::default()
                    });
                }
            } else {
                // Skip matches that trigger 'not' filters
                let excluded_by_not = not
                    .map(|exceptions| exceptions.iter().any(|exc| exc.matches(substr_str)))
                    .unwrap_or(false);

                if !excluded_by_not {
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
                    match_count = search_content.matches(&search_pattern).count();
                    if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                        evidence.push(Evidence {
                            method: "raw".to_string(),
                            source: "raw_content".to_string(),
                            value: substr_str.to_string(),
                            location: Some("file".to_string()),
                            ..Default::default()
                        });
                    }
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

    if external_ip {
        precision += 0.5; // Higher precision when requiring external IP
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
        let pattern_with_flags = if case_insensitive {
            format!("(?i){}", pattern)
        } else {
            pattern.clone()
        };
        match regex::Regex::new(&pattern_with_flags) {
            Ok(re) => Some(re),
            Err(_) => return ConditionResult::no_match(),
        }
    } else if let Some(word_pattern) = word {
        // Build word boundary regex from word parameter
        let pattern = format!(r"\b{}\b", regex::escape(word_pattern));
        let pattern_with_flags = if case_insensitive {
            format!("(?i){}", pattern)
        } else {
            pattern
        };
        match regex::Regex::new(&pattern_with_flags) {
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
            match_count += 1;
            if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                let value_preview = if string_info.value.len() > 100 {
                    format!("{}...", &string_info.value[..100])
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

/// Helper to search encoded strings (with given encoding in chain) for patterns.
#[allow(clippy::too_many_arguments)]
/// Evaluate string count condition - check if string count is within bounds.
#[must_use]
pub(crate) fn eval_string_count<'a>(
    min: Option<usize>,
    max: Option<usize>,
    min_length: Option<usize>,
    _regex: Option<&String>,
    compiled_regex: Option<&regex::Regex>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let min_len = min_length.unwrap_or(0);
    let matching_strings: Vec<&str> = ctx
        .report
        .strings
        .iter()
        .filter(|s| {
            if s.value.len() < min_len {
                return false;
            }
            if let Some(re) = compiled_regex {
                return re.is_match(&s.value);
            }
            true
        })
        .map(|s| s.value.as_str())
        .collect();

    let count = matching_strings.len();
    let min_ok = min.is_none_or(|m| count >= m);
    let max_ok = max.is_none_or(|m| count <= m);
    let matched = min_ok && max_ok;

    let evidence = if matched {
        // Deduplicate and take first few for display
        let mut unique: Vec<&str> = matching_strings;
        unique.sort();
        unique.dedup();
        let sample: Vec<&str> = unique.into_iter().take(5).collect();
        vec![Evidence {
            method: "string_count".to_string(),
            source: "binary".to_string(),
            value: format!("({}) {}", count, sample.join(", ")),
            location: None,
            ..Default::default()
        }]
    } else {
        Vec::new()
    };
    ConditionResult {
        matched,
        evidence,
        match_count: count,
        warnings: Vec::new(),
        precision: 0.0,
        matched_trait_ids: Vec::new(),
    }
}
