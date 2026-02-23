//! Miscellaneous condition evaluators.
//!
//! This module handles evaluation of various other condition types:
//! - Structure detection (e.g., PE headers, ELF signatures)
//! - Trait references (cross-trait dependencies)
//! - File size constraints
//! - Trait glob patterns (matching multiple traits)

use crate::composite_rules::context::{ConditionResult, EvaluationContext};
use crate::types::Evidence;

/// Evaluate structure condition
#[must_use]
pub(crate) fn eval_structure<'a>(
    feature: &str,
    min_sections: Option<usize>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let mut count = 0;
    let mut evidence = Vec::new();

    for structural_feature in &ctx.report.structure {
        if structural_feature.id == feature
            || structural_feature.id.starts_with(&format!("{}/", feature))
        {
            count += 1;
            evidence.extend(structural_feature.evidence.clone());
        }
    }

    let matched = if let Some(min) = min_sections {
        count >= min
    } else {
        count > 0
    };

    // Calculate precision: base 1.0 + 0.5 for feature + 0.5 for min_sections
    let mut precision = 1.0f32;
    precision += 0.5; // feature is always present
    if min_sections.is_some() {
        precision += 0.5;
    }

    ConditionResult {
        matched,
        evidence,
        warnings: Vec::new(),
        precision,
        matched_trait_ids: Vec::new(),
    }
}

/// Evaluate trait reference condition - check if a trait has already been matched
///
/// Reference formats:
/// - Specific trait (contains `::`): exact match only
///   e.g., "micro-behaviors/communications/http::curl-download" matches exactly that trait
/// - Short names (no `/` or `::`): suffix match within same directory
///   e.g., "terminate" matches "execution/process::terminate"
/// - Directory paths (contains `/` but no `::`): matches ANY trait within that directory
///   e.g., "anti-static/obfuscation" matches "anti-static/obfuscation::python-hex"
#[must_use]
pub(crate) fn eval_trait<'a>(id: &str, ctx: &EvaluationContext<'a>) -> ConditionResult {
    // Check if this is a specific trait reference (contains ::)
    let is_specific = id.contains("::");

    // Fast path: exact match using O(1) index lookup
    if ctx.has_finding_exact(id) {
        let evidence: Vec<_> = ctx
            .report
            .findings
            .iter()
            .chain(ctx.additional_findings.into_iter().flatten())
            .filter(|f| f.id == id)
            .flat_map(|f| f.evidence.iter().cloned())
            .collect();

        return ConditionResult {
            matched: true,
            evidence,
            warnings: Vec::new(),
            precision: 1.0,
            matched_trait_ids: vec![id.to_string()],
        };
    }

    // Specific trait references (with ::) only match exactly - no fallback
    if is_specific {
        return ConditionResult {
            matched: false,
            evidence: Vec::new(),
            warnings: Vec::new(),
            precision: 0.0,
            matched_trait_ids: Vec::new(),
        };
    }

    // Slow path: prefix/suffix matching for non-specific references
    let slash_count = id.matches('/').count();
    if slash_count == 0 {
        // Short name: suffix match for same-directory relative reference
        // e.g., "terminate" matches "execution/process::terminate" or legacy "execution/process/terminate"
        let suffix_new = format!("::{}", id);
        let suffix_legacy = format!("/{}", id);
        let matching: Vec<_> = ctx
            .report
            .findings
            .iter()
            .chain(ctx.additional_findings.into_iter().flatten())
            .filter(|f| f.id.ends_with(&suffix_new) || f.id.ends_with(&suffix_legacy))
            .collect();

        if !matching.is_empty() {
            let evidence = matching
                .iter()
                .flat_map(|f| f.evidence.iter().cloned())
                .collect();
            let matched_ids: Vec<String> = matching.iter().map(|f| f.id.clone()).collect();

            return ConditionResult {
                matched: true,
                evidence,
                warnings: Vec::new(),
                precision: 1.0,
                matched_trait_ids: matched_ids,
            };
        }
    } else {
        // Directory path: prefix match (any trait within that directory)
        // e.g., "anti-static/obfuscation" matches:
        //   - "anti-static/obfuscation::python-hex" (new format)
        //   - "anti-static/obfuscation/python-hex" (legacy format)
        let prefix_new = format!("{}::", id);
        let prefix_legacy = format!("{}/", id);
        let matching: Vec<_> = ctx
            .report
            .findings
            .iter()
            .chain(ctx.additional_findings.into_iter().flatten())
            .filter(|f| f.id.starts_with(&prefix_new) || f.id.starts_with(&prefix_legacy))
            .collect();

        if !matching.is_empty() {
            let evidence = matching
                .iter()
                .flat_map(|f| f.evidence.iter().cloned())
                .collect();
            let matched_ids: Vec<String> = matching.iter().map(|f| f.id.clone()).collect();

            return ConditionResult {
                matched: true,
                evidence,
                warnings: Vec::new(),
                precision: 1.0,
                matched_trait_ids: matched_ids,
            };
        }
    }

    ConditionResult {
        matched: false,
        evidence: Vec::new(),
        warnings: Vec::new(),
        precision: 0.0,
        matched_trait_ids: Vec::new(),
    }
}

/// Evaluate a basename condition - match against the final path component
#[must_use]
pub(crate) fn eval_basename<'a>(
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    case_insensitive: bool,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    // Extract basename from path
    let path = &ctx.report.target.path;
    let basename = std::path::Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    // Match against the basename
    let (compare_basename, compare_exact, compare_substr) = if case_insensitive {
        (
            basename.to_lowercase(),
            exact.map(|s| s.to_lowercase()),
            substr.map(|s| s.to_lowercase()),
        )
    } else {
        (basename.to_string(), exact.cloned(), substr.cloned())
    };

    let matched = if let Some(exact_str) = &compare_exact {
        compare_basename == *exact_str
    } else if let Some(substr_str) = &compare_substr {
        compare_basename.contains(substr_str.as_str())
    } else if let Some(regex_str) = regex {
        let pattern = if case_insensitive {
            format!("(?i){}", regex_str)
        } else {
            regex_str.clone()
        };
        regex::Regex::new(&pattern)
            .map(|re| re.is_match(basename))
            .unwrap_or(false)
    } else {
        false
    };

    // Calculate precision
    let mut precision = 0.0f32;

    if exact.is_some() {
        precision = 2.0;
    } else if regex.is_some() {
        precision = 1.5;
    } else if substr.is_some() {
        precision = 1.0;
    }

    if case_insensitive {
        precision *= 0.5;
    }

    ConditionResult {
        matched,
        evidence: if matched {
            vec![Evidence {
                method: "basename".to_string(),
                source: "target".to_string(),
                value: basename.to_string(),
                location: None,
            }]
        } else {
            Vec::new()
        },
        warnings: Vec::new(),
        precision,
        matched_trait_ids: Vec::new(),
    }
}
