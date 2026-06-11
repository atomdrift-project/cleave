//! Miscellaneous condition evaluators.
//!
//! This module handles evaluation of various other condition types:
//! - Structure detection (e.g., PE headers, ELF signatures)
//! - Trait references (cross-trait dependencies)
//! - File size constraints
//! - Trait glob patterns (matching multiple traits)

use super::symbol_string::validate_match;
use crate::composite_rules::condition::StringValidator;
use crate::composite_rules::context::{ConditionResult, EvaluationContext};
use crate::types::{Evidence, MAX_EVIDENCE_PER_TRAIT};

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
    let id = id.trim_end_matches('/');

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
            .take(MAX_EVIDENCE_PER_TRAIT)
            .collect();

        let match_count = evidence.len();
        return ConditionResult {
            matched: true,
            evidence,
            match_count,
            warnings: Vec::new(),
            precision: 1.0,
            matched_trait_ids: vec![id.to_string()],
        };
    }

    // Specific trait references (with ::) only match exactly - no fallback
    if is_specific {
        return ConditionResult::no_match();
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
            let evidence: Vec<_> = matching
                .iter()
                .flat_map(|f| f.evidence.iter().cloned())
                .take(MAX_EVIDENCE_PER_TRAIT)
                .collect();
            let matched_ids: Vec<String> = matching.iter().map(|f| f.id.clone()).collect();
            let match_count = evidence.len();

            return ConditionResult {
                matched: true,
                evidence,
                match_count,
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
            let evidence: Vec<_> = matching
                .iter()
                .flat_map(|f| f.evidence.iter().cloned())
                .take(MAX_EVIDENCE_PER_TRAIT)
                .collect();
            let matched_ids: Vec<String> = matching.iter().map(|f| f.id.clone()).collect();
            let match_count = evidence.len();

            return ConditionResult {
                matched: true,
                evidence,
                match_count,
                warnings: Vec::new(),
                precision: 1.0,
                matched_trait_ids: matched_ids,
            };
        }
    }

    ConditionResult {
        matched: false,
        evidence: Vec::new(),
        match_count: 0,
        warnings: Vec::new(),
        precision: 0.0,
        matched_trait_ids: Vec::new(),
    }
}

/// Test-only alias: `basename` is now a filename-scoped `path` match. The real
/// implementation lives in [`eval_path`]; this shim keeps the basename tests.
#[cfg(test)]
#[must_use]
pub(crate) fn eval_basename(
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    case_insensitive: bool,
    is_check: Option<StringValidator>,
    ctx: &EvaluationContext<'_>,
) -> ConditionResult {
    eval_path(
        exact,
        substr,
        regex,
        case_insensitive,
        is_check,
        true,
        false,
        ctx,
    )
}

/// Evaluate a `type: path` condition against the file path. Matches the full
/// path by default; `basename` scopes to the final component, `dirname` to the
/// directory portion.
pub(crate) fn eval_path(
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    case_insensitive: bool,
    is_check: Option<StringValidator>,
    basename: bool,
    dirname: bool,
    ctx: &EvaluationContext<'_>,
) -> ConditionResult {
    let full = ctx.report.target.path.as_str();
    let p = std::path::Path::new(full);
    let target: &str = if basename {
        p.file_name().and_then(|s| s.to_str()).unwrap_or("")
    } else if dirname {
        p.parent().and_then(|s| s.to_str()).unwrap_or("")
    } else {
        full
    };

    let (cmp_target, cmp_exact, cmp_substr) = if case_insensitive {
        (
            target.to_lowercase(),
            exact.map(|s| s.to_lowercase()),
            substr.map(|s| s.to_lowercase()),
        )
    } else {
        (target.to_string(), exact.cloned(), substr.cloned())
    };

    let matched = if let Some(e) = &cmp_exact {
        cmp_target == *e
    } else if let Some(s) = &cmp_substr {
        cmp_target.contains(s.as_str())
    } else if let Some(r) = regex {
        crate::composite_rules::condition::lazy_regex(Some(r.as_str()), case_insensitive)
            .map(|re| re.is_match(target))
            .unwrap_or(false)
    } else {
        false
    };

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
    if is_check.is_some() {
        precision += 0.5;
    }

    let matched = matched && validate_match(target, is_check);

    ConditionResult {
        matched,
        evidence: if matched {
            vec![Evidence {
                method: "path".to_string(),
                source: "target".to_string(),
                value: target.to_string(),
                // A path/filename match describes the file as a whole, not a
                // byte range. Anchor it at the header (offset 0) so scope and
                // proximity bucketing always have a location to key on.
                location: Some("0x0".to_string()),
                ..Default::default()
            }]
        } else {
            Vec::new()
        },
        match_count: if matched { 1 } else { 0 },
        warnings: Vec::new(),
        precision,
        matched_trait_ids: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composite_rules::types::FileType;
    use crate::types::{AnalysisReport, TargetInfo};

    fn create_test_context_with_path<'a>(
        report: &'a AnalysisReport,
        data: &'a [u8],
    ) -> EvaluationContext<'a> {
        EvaluationContext::test_only_new(report, data, FileType::All)
    }

    #[test]
    fn test_eval_basename_invalid_regex_no_panic() {
        let target = TargetInfo {
            path: "/test/malware.exe".to_string(),
            file_type: "pe".to_string(),
            size_bytes: 1024,
            sha256: "abc".to_string(),
            architectures: None,
        };
        let report = AnalysisReport::new(target);
        let data = vec![];
        let ctx = create_test_context_with_path(&report, &data);

        // Invalid regex should not panic, should return no match
        let bad_regex = "[invalid(".to_string();
        let result = eval_basename(None, None, Some(&bad_regex), false, None, &ctx);
        assert!(!result.matched, "Invalid regex should not match");
    }
}
