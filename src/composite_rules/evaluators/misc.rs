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
use crate::types::{Criticality, Evidence, MAX_EVIDENCE_PER_TRAIT};

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

    // Fast path: exact match using O(1) index lookup. `origin_allows` is the
    // `for:` filter: at container level a finding only counts when it came
    // from a file type the composite declared, so a rule about a vsix manifest
    // and its bundled script is not satisfied by a README three members over.
    if ctx.has_finding_exact(id) && ctx.origin_allows(id) {
        let evidence: Vec<_> = ctx
            .findings
            .iter()
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
            matched_trait_ids: vec![id.to_string().into()],
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
        // Alloc-free suffix test: `f.id` ends with `id` preceded by `::` or
        // `/`. This runs per (rule x member) and usually misses; the old
        // `format!` pair allocated two Strings per call.
        let ends_with_ref = |fid: &str| -> bool {
            if fid.len() <= id.len() || !fid.ends_with(id) {
                return false;
            }
            let head = &fid[..fid.len() - id.len()];
            head.ends_with("::") || head.ends_with('/')
        };
        let matching: Vec<_> = ctx
            .findings
            .iter()
            .filter(|f| ends_with_ref(&f.id))
            .filter(|f| ctx.origin_allows(&f.id))
            .collect();

        if !matching.is_empty() {
            let evidence: Vec<_> = matching
                .iter()
                .flat_map(|f| f.evidence.iter().cloned())
                .take(MAX_EVIDENCE_PER_TRAIT)
                .collect();
            let matched_ids: Vec<crate::types::Istr> =
                matching.iter().map(|f| f.id.clone()).collect();
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
        //
        // `crit: exception` composites are excluded from directory expansion: a
        // directory reference is a broad "any trait under here" match, and an
        // exception is a benign suppressor that must never be inherited as positive
        // (or any) evidence by accident. For non-exception rules, exceptions are
        // reachable only by an exact `dir::id` reference (the fast path above) — how
        // `unless:`/`downgrade:` target them — which is what makes it safe to drop
        // an `objectives/` directory into an `all:`/`any:` clause. An exception
        // composite, however, may assemble a directory of exceptions, so it
        // re-includes them (`parent_is_exception`).
        // Alloc-free prefix test: `f.id` starts with `id` followed by `::`
        // or `/` (same semantics as the old formatted prefixes).
        let starts_with_ref = |fid: &str| -> bool {
            fid.len() > id.len()
                && fid.starts_with(id)
                && (fid[id.len()..].starts_with("::") || fid[id.len()..].starts_with('/'))
        };
        let matching: Vec<_> = ctx
            .findings
            .iter()
            .filter(|f| starts_with_ref(&f.id))
            .filter(|f| ctx.parent_is_exception || f.crit != Criticality::Exception)
            .filter(|f| ctx.origin_allows(&f.id))
            .collect();

        if !matching.is_empty() {
            let evidence: Vec<_> = matching
                .iter()
                .flat_map(|f| f.evidence.iter().cloned())
                .take(MAX_EVIDENCE_PER_TRAIT)
                .collect();
            let matched_ids: Vec<crate::types::Istr> =
                matching.iter().map(|f| f.id.clone()).collect();
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

/// Final path component, treating `/`, `\`, and the archive-member separator
/// `!` as boundaries.
///
/// Archive members carry synthetic paths like `outer.zip!inner/file` (and, for
/// a member at a nested archive's root, `outer.jar!Main.class`). Splitting on
/// `!` keeps a `basename` match consistent whether the member is scanned
/// in-archive or after extraction to disk — `basename` of `foo.jar!Main.class`
/// is `Main.class`, the same as the extracted `Main.class`.
pub(crate) fn path_basename(path: &str) -> &str {
    match path.rfind(['/', '\\', '!']) {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

/// Directory portion of a path, treating `/`, `\`, and `!` as boundaries.
/// The complement of [`path_basename`]; empty when there is no separator.
pub(crate) fn path_dirname(path: &str) -> &str {
    match path.rfind(['/', '\\', '!']) {
        Some(i) => &path[..i],
        None => "",
    }
}

/// The member-relative tail of a nested archive path: everything after the
/// last `!`. A member of an archive inside an archive carries the accumulated
/// chain (`outer.tar!inner/x.xls!vba/m.vbs`); a rule anchored at `^` was
/// written against the path the innermost archive sees (`vba/m.vbs`).
fn member_relative_tail(path: &str) -> Option<&str> {
    path.rsplit_once('!').map(|(_, tail)| tail)
}

/// The host file a derived fragment was carved out of, or `None` when this
/// node is a file in its own right (a root file, or an archive member).
///
/// A fragment is a run of bytes the analyzer lifted out of a host and analyzed
/// separately -- a decoded base64 payload, an unicode-unescaped layer, a string
/// literal that sniffed as source. It is reported under its host's path with a
/// `##<codec>@<offset>` suffix (`bundle.js.map##unicode-escape@1854094`).
///
/// A fragment has no name of its own, so `type: path` reads its host's. That is
/// what callers want for an identity question -- a decoded layer of `x.js` IS
/// JavaScript -- and it is the reason `$`-anchored identities such as the
/// source-map `\.[cm]?js\.map$` keep matching inside a layer. See
/// [`TraitDefinition::constrains_whole_file`] for the case where it is not
/// enough on its own.
pub(crate) fn fragment_host_path(path: &str) -> Option<&str> {
    path.split_once(crate::types::file_analysis::ENCODING_DELIMITER)
        .map(|(host, _)| host)
}

/// Evaluate a `type: path` condition against the file path. Matches the full
/// path by default; `basename` scopes to the final component, `dirname` to the
/// directory portion.
///
/// A nested archive member is matched under **both** spellings of its path:
/// the accumulated chain and the member-relative tail after the last `!`.
/// Only the tail used to be visible, which quietly put every outer directory
/// out of reach of `type: path` rules one level down -- a fixture under
/// `sc/qa/extras/testdocuments/X.xls` was matched as `vba/TestMacros.vbs`, so
/// `test-directory-path` and every other `qa/`-style carve-out stopped at the
/// archive boundary while the finding still rolled up to the container.
/// Matching both keeps the `^`-anchored rules written against the tail
/// (`^(usr|etc|var)/`, `^([^/]+/)?setup\.py$`) working unchanged.
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
    // A named fn, not a closure: closure lifetime elision gives the return a
    // fresh lifetime rather than tying it to the argument.
    fn scope_of(p: &str, basename: bool, dirname: bool) -> &str {
        if basename {
            path_basename(p)
        } else if dirname {
            path_dirname(p)
        } else {
            p
        }
    }

    let full = ctx.report.target.path.as_str();

    // `basename` already collapses to the last component, which is identical
    // for both spellings, so only the full/dirname scopes need the second try.
    let mut candidates: Vec<&str> = vec![scope_of(full, basename, dirname)];
    if let Some(base) = fragment_host_path(full) {
        let scoped = scope_of(base, basename, dirname);
        if !candidates.contains(&scoped) {
            candidates.push(scoped);
        }
        if !basename && let Some(tail) = member_relative_tail(base) {
            let scoped = scope_of(tail, basename, dirname);
            if !candidates.contains(&scoped) {
                candidates.push(scoped);
            }
        }
    }
    if !basename && let Some(tail) = member_relative_tail(full) {
        let scoped = scope_of(tail, basename, dirname);
        if !candidates.contains(&scoped) {
            candidates.push(scoped);
        }
    }

    let eval_one = |target: &str| -> bool {
        if target.is_empty() {
            return false;
        }
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

        matched && validate_match(target, is_check)
    };

    // Report the spelling that actually matched, so the evidence names the
    // path the rule was reasoning about.
    let hit: Option<&str> = candidates.into_iter().find(|c| eval_one(c));

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

    ConditionResult {
        matched: hit.is_some(),
        evidence: match hit {
            Some(target) => vec![Evidence {
                method: "path".to_string(),
                source: "target".to_string(),
                value: target.to_string(),
                // A path/filename match is metadata about the target path, not
                // bytes in the file. It has no honest file offset.
                location: None,
                ..Default::default()
            }],
            None => Vec::new(),
        },
        match_count: usize::from(hit.is_some()),
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
