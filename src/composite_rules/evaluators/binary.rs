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

/// Parameters for a `type: section` condition evaluation.
#[derive(Default)]
pub(crate) struct SectionParams<'p> {
    pub exact: Option<&'p String>,
    pub substr: Option<&'p String>,
    pub regex: Option<&'p String>,
    pub word: Option<&'p String>,
    pub case_insensitive: bool,
    pub length_min: Option<u64>,
    pub length_max: Option<u64>,
    pub entropy_min: Option<f64>,
    pub entropy_max: Option<f64>,
    pub readable: Option<bool>,
    pub writable: Option<bool>,
    pub executable: Option<bool>,
    /// Reference section (or `"total"`) for both size and entropy ratio checks.
    pub compare_to: Option<&'p String>,
    pub size_ratio_min: Option<f64>,
    pub size_ratio_max: Option<f64>,
    pub entropy_ratio_min: Option<f64>,
    pub entropy_ratio_max: Option<f64>,
}

/// Evaluate section condition - match sections by name, size, and entropy.
#[must_use]
pub(crate) fn eval_section<'a>(
    p: &SectionParams<'_>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let mut evidence = Vec::new();
    let mut matched_total_size: u64 = 0;
    let mut matched_section_names: Vec<String> = Vec::new();
    let mut matched_entropies: Vec<f64> = Vec::new();

    for section in &ctx.report.sections {
        let (compare_name, compare_exact, compare_substr) = if p.case_insensitive {
            (
                section.name.to_lowercase(),
                p.exact.map(|s| s.to_lowercase()),
                p.substr.map(|s| s.to_lowercase()),
            )
        } else {
            (section.name.clone(), p.exact.cloned(), p.substr.cloned())
        };

        let name_matched = if let Some(exact_str) = &compare_exact {
            compare_name == *exact_str
        } else if let Some(substr_str) = &compare_substr {
            compare_name.contains(substr_str.as_str())
        } else if let Some(regex_str) = p.regex {
            let pattern = if p.case_insensitive {
                format!("(?i){}", regex_str)
            } else {
                regex_str.clone()
            };
            build_regex(&pattern, false).is_ok_and(|re| re.is_match(&section.name))
        } else if let Some(word_str) = p.word {
            let pattern = if p.case_insensitive {
                format!(r"(?i)\b{}\b", regex::escape(word_str))
            } else {
                format!(r"\b{}\b", regex::escape(word_str))
            };
            build_regex(&pattern, false).is_ok_and(|re| re.is_match(&section.name))
        } else {
            true
        };

        let size_ok = p.length_min.is_none_or(|min| section.size >= min)
            && p.length_max.is_none_or(|max| section.size <= max);

        let entropy_ok = p.entropy_min.is_none_or(|min| section.entropy >= min)
            && p.entropy_max.is_none_or(|max| section.entropy <= max);

        let permissions_ok = {
            let mut ok = true;
            if let Some(perms) = &section.permissions {
                if let Some(r) = p.readable {
                    ok = ok && (perms.contains('r') == r);
                }
                if let Some(w) = p.writable {
                    ok = ok && (perms.contains('w') == w);
                }
                if let Some(x) = p.executable {
                    ok = ok && (perms.contains('x') == x);
                }
            } else if p.readable.is_some() || p.writable.is_some() || p.executable.is_some() {
                ok = false;
            }
            ok
        };

        if name_matched && size_ok && entropy_ok && permissions_ok {
            matched_total_size = matched_total_size.saturating_add(section.size);
            matched_section_names.push(section.name.clone());
            matched_entropies.push(section.entropy);
            let mut details = vec![];
            if p.length_min.is_some() || p.length_max.is_some() {
                details.push(format!("size: {}", section.size));
            }
            if p.entropy_min.is_some() || p.entropy_max.is_some() {
                details.push(format!("entropy: {:.2}", section.entropy));
            }
            if (p.readable.is_some() || p.writable.is_some() || p.executable.is_some())
                && let Some(perms) = &section.permissions
            {
                details.push(format!("perms: {}", perms));
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
                    // Anchor at the section's file offset (header offset 0 when
                    // the format doesn't record one) so scope/proximity
                    // bucketing always has a location.
                    location: Some(format!("0x{:x}", section.offset.unwrap_or(0))),
                    ..Default::default()
                });
            }
        }
    }

    let mut precision = if p.exact.is_some() {
        2.0
    } else if p.regex.is_some() || p.word.is_some() {
        1.5
    } else if p.substr.is_some() || p.length_min.is_some() || p.length_max.is_some() {
        1.0
    } else {
        0.0
    };
    if p.length_min.is_some() {
        precision += 0.5;
    }
    if p.length_max.is_some() {
        precision += 0.5;
    }
    if p.entropy_min.is_some() {
        precision += 0.5;
    }
    if p.entropy_max.is_some() {
        precision += 0.5;
    }
    if p.readable.is_some() {
        precision += 0.5;
    }
    if p.writable.is_some() {
        precision += 0.5;
    }
    if p.executable.is_some() {
        precision += 0.5;
    }
    if p.case_insensitive {
        precision *= 0.5;
    }

    // Size-ratio check.
    let ratio_ok = if p.size_ratio_min.is_some() || p.size_ratio_max.is_some() {
        let denom: u64 = match p.compare_to.map(String::as_str) {
            None | Some("total") => ctx.report.target.size_bytes,
            Some(pattern) => match build_regex(pattern, false) {
                Ok(re) => ctx
                    .report
                    .sections
                    .iter()
                    .filter(|s| re.is_match(&s.name))
                    .map(|s| s.size)
                    .sum(),
                Err(_) => 0,
            },
        };
        if denom == 0 {
            false
        } else {
            let ratio = matched_total_size as f64 / denom as f64;
            let ok = p.size_ratio_min.is_none_or(|m| ratio >= m)
                && p.size_ratio_max.is_none_or(|m| ratio <= m);
            if ok {
                precision += 1.0;
                if p.size_ratio_min.is_some() {
                    precision += 0.5;
                }
                if p.size_ratio_max.is_some() {
                    precision += 0.5;
                }
                let denom_desc = p.compare_to.map_or("total", String::as_str);
                evidence.push(Evidence {
                    method: "section_ratio".to_string(),
                    source: "binary".to_string(),
                    value: format!(
                        "{} = {:.1}% of {} ({} / {} bytes)",
                        matched_section_names.join("+"),
                        ratio * 100.0,
                        denom_desc,
                        matched_total_size,
                        denom,
                    ),
                    // Aggregate over several sections — anchor at the header.
                    location: Some("0x0".to_string()),
                    ..Default::default()
                });
            }
            ok
        }
    } else {
        true
    };

    // Entropy-ratio check.
    let entropy_ratio_ok = if p.entropy_ratio_min.is_some() || p.entropy_ratio_max.is_some() {
        if matched_entropies.is_empty() {
            return ConditionResult::no_match();
        }
        let matched_mean = matched_entropies.iter().sum::<f64>() / matched_entropies.len() as f64;

        let denom_entropies: Vec<f64> = if let Some(pattern) = p.compare_to {
            match build_regex(pattern, false) {
                Ok(re) => ctx
                    .report
                    .sections
                    .iter()
                    .filter(|s| re.is_match(&s.name) && s.entropy > 0.0)
                    .map(|s| s.entropy)
                    .collect(),
                Err(_) => return ConditionResult::no_match(),
            }
        } else {
            ctx.report
                .sections
                .iter()
                .filter(|s| !matched_section_names.contains(&s.name) && s.entropy > 0.0)
                .map(|s| s.entropy)
                .collect()
        };

        if denom_entropies.is_empty() {
            false
        } else {
            let denom_mean = denom_entropies.iter().sum::<f64>() / denom_entropies.len() as f64;
            if denom_mean == 0.0 {
                false
            } else {
                let ratio = matched_mean / denom_mean;
                let ok = p.entropy_ratio_min.is_none_or(|m| ratio >= m)
                    && p.entropy_ratio_max.is_none_or(|m| ratio <= m);
                if ok {
                    precision += 1.0;
                    if p.entropy_ratio_min.is_some() {
                        precision += 0.5;
                    }
                    if p.entropy_ratio_max.is_some() {
                        precision += 0.5;
                    }
                    let denom_desc = p.compare_to.map_or("other sections", String::as_str);
                    evidence.push(Evidence {
                        method: "section_entropy_ratio".to_string(),
                        source: "binary".to_string(),
                        value: format!(
                            "{} entropy {:.2} = {:.2}x {} mean entropy {:.2}",
                            matched_section_names.join("+"),
                            matched_mean,
                            ratio,
                            denom_desc,
                            denom_mean,
                        ),
                        // Aggregate over several sections — anchor at the header.
                        location: Some("0x0".to_string()),
                        ..Default::default()
                    });
                }
                ok
            }
        }
    } else {
        true
    };

    let match_count = evidence.len();
    ConditionResult {
        matched: match_count > 0 && ratio_ok && entropy_ratio_ok,
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
