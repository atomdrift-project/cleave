//! Binary analysis condition evaluators.
//!
//! This module handles evaluation of binary-specific conditions:
//! - Import/export counting and filtering
//! - Section analysis (entropy, ratios, names)
//! - Syscall detection
//! - Import combinations (required + suspicious patterns)

use super::build_regex;
use crate::composite_rules::context::{ConditionResult, EvaluationContext};
use crate::types::{Evidence, MAX_EVIDENCE_PER_TRAIT};
use regex::RegexSet;

/// Evaluate exports count condition
#[must_use]
pub(crate) fn eval_exports_count<'a>(
    min: Option<usize>,
    max: Option<usize>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let count = ctx.report.exports.len();
    let matched = min.is_none_or(|m| count >= m) && max.is_none_or(|m| count <= m);

    // Calculate precision: base 1.0 + 0.5 each for min/max
    let mut precision = 1.0f32;
    if min.is_some() {
        precision += 0.5;
    }
    if max.is_some() {
        precision += 0.5;
    }

    let evidence = if matched {
        // Deduplicate and take first few for display
        let mut symbols: Vec<&str> = ctx
            .report
            .exports
            .iter()
            .map(|exp| exp.symbol.as_str())
            .collect();
        symbols.sort_unstable();
        symbols.dedup();
        let sample: Vec<&str> = symbols.into_iter().take(5).collect();
        vec![Evidence {
            method: "exports_count".to_string(),
            source: "analysis".to_string(),
            value: format!("({}) {}", count, sample.join(", ")),
            location: None,
            ..Default::default()
        }]
    } else {
        Vec::new()
    };
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

/// Evaluate section ratio condition - check if section size is within ratio bounds
#[must_use]
pub(crate) fn eval_section_ratio<'a>(
    section_pattern: &str,
    compare_to: &str,
    min_ratio: Option<f64>,
    max_ratio: Option<f64>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let Ok(section_re) = build_regex(section_pattern, false) else {
        return ConditionResult::no_match();
    };

    // Find matching section(s) and sum their sizes
    let mut section_size: u64 = 0;
    let mut matched_sections = Vec::new();
    for section in &ctx.report.sections {
        if section_re.is_match(&section.name) {
            section_size += section.size;
            matched_sections.push(section.name.clone());
        }
    }

    if matched_sections.is_empty() {
        return ConditionResult::no_match();
    }

    // Calculate comparison size
    let compare_size: u64 = if compare_to == "total" {
        ctx.report.sections.iter().map(|s| s.size).sum()
    } else {
        let Ok(compare_re) = build_regex(compare_to, false) else {
            return ConditionResult::no_match();
        };
        ctx.report
            .sections
            .iter()
            .filter(|s| compare_re.is_match(&s.name))
            .map(|s| s.size)
            .sum()
    };

    if compare_size == 0 {
        return ConditionResult::no_match();
    }

    let ratio = section_size as f64 / compare_size as f64;
    let min_ok = min_ratio.is_none_or(|min| ratio >= min);
    let max_ok = max_ratio.is_none_or(|max| ratio <= max);
    let matched = min_ok && max_ok;

    // Calculate precision: base 1.0 + 1.0 for pattern + 0.5 each for min/max ratios
    let mut precision = 1.0f32;
    precision += 1.0; // section pattern always present
    if min_ratio.is_some() {
        precision += 0.5;
    }
    if max_ratio.is_some() {
        precision += 0.5;
    }

    let evidence = if matched {
        vec![Evidence {
            method: "section_ratio".to_string(),
            source: "binary".to_string(),
            value: format!(
                "{} = {:.1}% of {} ({} / {} bytes)",
                matched_sections.join("+"),
                ratio * 100.0,
                compare_to,
                section_size,
                compare_size
            ),
            location: None,
            ..Default::default()
        }]
    } else {
        Vec::new()
    };
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

/// Evaluate section condition - match sections by name, size, and entropy
/// Replaces YARA patterns like: `for any section in pe.sections : (section.name matches /^UPX/)`
#[allow(clippy::too_many_arguments)]
#[must_use]
pub(crate) fn eval_section<'a>(
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    word: Option<&String>,
    case_insensitive: bool,
    length_min: Option<u64>,
    length_max: Option<u64>,
    entropy_min: Option<f64>,
    entropy_max: Option<f64>,
    readable: Option<bool>,
    writable: Option<bool>,
    executable: Option<bool>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let mut evidence = Vec::new();

    for section in &ctx.report.sections {
        // Apply case sensitivity transformation
        let (compare_name, compare_exact, compare_substr) = if case_insensitive {
            (
                section.name.to_lowercase(),
                exact.map(|s| s.to_lowercase()),
                substr.map(|s| s.to_lowercase()),
            )
        } else {
            (section.name.clone(), exact.cloned(), substr.cloned())
        };

        let name_matched = if let Some(exact_str) = &compare_exact {
            compare_name == *exact_str
        } else if let Some(substr_str) = &compare_substr {
            compare_name.contains(substr_str.as_str())
        } else if let Some(regex_str) = regex {
            let pattern = if case_insensitive {
                format!("(?i){}", regex_str)
            } else {
                regex_str.clone()
            };
            match build_regex(&pattern, false) {
                Ok(re) => re.is_match(&section.name),
                Err(_) => false,
            }
        } else if let Some(word_str) = word {
            let pattern = if case_insensitive {
                format!(r"(?i)\b{}\b", regex::escape(word_str))
            } else {
                format!(r"\b{}\b", regex::escape(word_str))
            };
            match build_regex(&pattern, false) {
                Ok(re) => re.is_match(&section.name),
                Err(_) => false,
            }
        } else {
            // No name pattern specified - match all sections
            true
        };

        // Check size constraints
        let size_ok = if let Some(min) = length_min {
            section.size >= min
        } else {
            true
        } && if let Some(max) = length_max {
            section.size <= max
        } else {
            true
        };

        // Check entropy constraints
        let entropy_ok = if let Some(min) = entropy_min {
            section.entropy >= min
        } else {
            true
        } && if let Some(max) = entropy_max {
            section.entropy <= max
        } else {
            true
        };

        // Check permission constraints
        let permissions_ok = {
            let mut ok = true;
            if let Some(perms) = &section.permissions {
                if let Some(r) = readable {
                    ok = ok && (perms.contains('r') == r);
                }
                if let Some(w) = writable {
                    ok = ok && (perms.contains('w') == w);
                }
                if let Some(x) = executable {
                    ok = ok && (perms.contains('x') == x);
                }
            } else {
                // If no permissions info, fail strict checks
                if readable.is_some() || writable.is_some() || executable.is_some() {
                    ok = false;
                }
            }
            ok
        };

        let matched = name_matched && size_ok && entropy_ok && permissions_ok;

        if matched {
            let mut details = vec![];
            if length_min.is_some() || length_max.is_some() {
                details.push(format!("size: {}", section.size));
            }
            if entropy_min.is_some() || entropy_max.is_some() {
                details.push(format!("entropy: {:.2}", section.entropy));
            }
            if readable.is_some() || writable.is_some() || executable.is_some() {
                if let Some(perms) = &section.permissions {
                    details.push(format!("perms: {}", perms));
                }
            }

            let value = if details.is_empty() {
                section.name.clone()
            } else {
                format!("{} ({})", section.name, details.join(", "))
            };

            if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                evidence.push(Evidence {
                    method: "section".to_string(),
                    source: "binary".to_string(),
                    value,
                    location: None,
                    ..Default::default()
                });
            }
        }
    }

    // Calculate precision matching other evaluators
    let mut precision = if exact.is_some() {
        2.0
    } else if regex.is_some() || word.is_some() {
        1.5
    } else if substr.is_some() {
        1.0
    } else if length_min.is_some() || length_max.is_some() {
        // Size constraints alone (no name pattern)
        1.0
    } else {
        0.0
    };

    // Add precision for size constraints
    if length_min.is_some() {
        precision += 0.5;
    }
    if length_max.is_some() {
        precision += 0.5;
    }

    // Add precision for entropy constraints
    if entropy_min.is_some() {
        precision += 0.5;
    }
    if entropy_max.is_some() {
        precision += 0.5;
    }

    // Add precision for permission constraints
    if readable.is_some() {
        precision += 0.5;
    }
    if writable.is_some() {
        precision += 0.5;
    }
    if executable.is_some() {
        precision += 0.5;
    }

    if case_insensitive {
        precision *= 0.5;
    }

    let match_count = evidence.len();
    ConditionResult {
        matched: match_count > 0,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision,
        matched_trait_ids: Vec::new(),
    }
}

/// Evaluate import combination condition - check for required + suspicious import patterns
#[must_use]
pub(crate) fn eval_import_combination<'a>(
    required: Option<&Vec<String>>,
    suspicious: Option<&Vec<String>>,
    min_suspicious: Option<usize>,
    max_total: Option<usize>,
    compiled_required: Option<&RegexSet>,
    compiled_suspicious: Option<&RegexSet>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    // EARLY OUT: max_total is the cheapest possible filter (imports.len() is O(1)).
    // Do it before touching the imports list so huge-import binaries don't pay for
    // the regex work that would be discarded anyway.
    if let Some(max) = max_total {
        if ctx.report.imports.len() > max {
            return ConditionResult::no_match();
        }
    }

    let import_symbols: Vec<&str> = ctx
        .report
        .imports
        .iter()
        .map(|i| i.symbol.as_str())
        .collect();
    let mut evidence = Vec::new();

    // Check required imports: every pattern must match at least one symbol.
    // Use RegexSet to match all patterns in a single pass per symbol instead of
    // N_patterns × N_imports independent regex passes. Prefer the pre-compiled
    // RegexSet populated at trait-load time so we don't rebuild the DFA per file.
    if let Some(req) = required {
        let owned_req: Option<RegexSet> = if compiled_required.is_none() {
            match RegexSet::new(req.iter()) {
                Ok(s) => Some(s),
                Err(_) => return ConditionResult::no_match(),
            }
        } else {
            None
        };
        let set = compiled_required.unwrap_or_else(|| owned_req.as_ref().unwrap());
        let mut pattern_hits = vec![false; req.len()];
        let mut remaining = req.len();
        for sym in &import_symbols {
            if remaining == 0 {
                break;
            }
            for idx in set.matches(sym) {
                if !pattern_hits[idx] {
                    pattern_hits[idx] = true;
                    remaining -= 1;
                }
            }
        }
        if pattern_hits.iter().any(|hit| !hit) {
            return ConditionResult::no_match();
        }
        for (pattern, _) in req.iter().zip(pattern_hits.iter()) {
            if evidence.len() >= MAX_EVIDENCE_PER_TRAIT {
                break;
            }
            evidence.push(Evidence {
                method: "import".to_string(),
                source: "required".to_string(),
                value: pattern.clone(),
                location: None,
                ..Default::default()
            });
        }
    }

    // Count suspicious imports: each symbol counted at most once if it matches any
    // suspicious pattern. RegexSet does all alternatives in a single DFA pass.
    let mut suspicious_count = 0;
    if let Some(susp) = suspicious {
        let owned_susp: Option<RegexSet> = if compiled_suspicious.is_none() {
            match RegexSet::new(susp.iter()) {
                Ok(s) => Some(s),
                Err(_) => return ConditionResult::no_match(),
            }
        } else {
            None
        };
        let set = compiled_suspicious.unwrap_or_else(|| owned_susp.as_ref().unwrap());
        for sym in &import_symbols {
            if set.is_match(sym) {
                suspicious_count += 1;
                if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    evidence.push(Evidence {
                        method: "import".to_string(),
                        source: "suspicious".to_string(),
                        value: (*sym).to_string(),
                        location: None,
                        ..Default::default()
                    });
                }
            }
        }
    }

    // Check minimum suspicious count
    if let Some(min) = min_suspicious {
        if suspicious_count < min {
            return ConditionResult::no_match();
        }
    }

    // Add the max_total evidence line (we already validated it at the top)
    if let Some(max) = max_total {
        if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
            evidence.push(Evidence {
                method: "import_count".to_string(),
                source: "binary".to_string(),
                value: format!("{} imports (max {})", ctx.report.imports.len(), max),
                location: None,
                ..Default::default()
            });
        }
    }

    // Calculate precision: base 2.0 + 0.5 per required item + 0.3 per suspicious item
    let mut precision = 2.0f32;
    if let Some(req) = required {
        precision += (req.len() as f32) * 0.5;
    }
    if let Some(susp) = suspicious {
        precision += (susp.len() as f32) * 0.3;
    }

    let match_count = evidence.len();
    ConditionResult {
        matched: !evidence.is_empty(),
        evidence,
        match_count,
        warnings: Vec::new(),
        precision,
        matched_trait_ids: Vec::new(),
    }
}

/// Evaluate syscall condition - matches syscalls detected via radare2 analysis
#[must_use]
pub(crate) fn eval_syscall<'a>(
    name: Option<&Vec<String>>,
    number: Option<&Vec<u32>>,
    arch: Option<&Vec<String>>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let mut evidence = Vec::new();
    let mut match_count = 0;

    for syscall in &ctx.report.syscalls {
        let name_match = name.is_none_or(|names| names.contains(&syscall.name));
        let number_match = number.is_none_or(|nums| nums.contains(&syscall.number));
        let arch_match = arch.is_none_or(|archs| {
            archs
                .iter()
                .any(|a| syscall.arch.to_lowercase() == a.to_lowercase())
        });

        if name_match && number_match && arch_match {
            match_count += 1;
            if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                evidence.push(Evidence {
                    method: "syscall".to_string(),
                    source: "radare2".to_string(),
                    value: format!(
                        "{}({}) at 0x{:x}",
                        syscall.name, syscall.number, syscall.address
                    ),
                    location: Some(format!("0x{:x}", syscall.address)),
                    ..Default::default()
                });
            }
        }
    }

    // count/density constraints are now checked at trait level
    let matched = match_count > 0;

    // Calculate precision: base 2.0 + 0.5 for name/number/arch
    let mut precision = 2.0f32;
    if name.is_some() {
        precision += 0.5;
    }
    if number.is_some() {
        precision += 0.5;
    }
    if arch.is_some() {
        precision += 0.5;
    }

    ConditionResult {
        matched,
        evidence: if matched { evidence } else { Vec::new() },
        match_count,
        warnings: Vec::new(),
        precision,
        matched_trait_ids: Vec::new(),
    }
}
