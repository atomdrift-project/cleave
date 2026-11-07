//! Trait definitions for composite rules.
//!
//! This module contains TraitDefinition (atomic traits) and CompositeTrait
//! (boolean combinations of conditions).

use super::condition::{
    CommentQuery, Condition, EncodedQuery, HexQuery, LiteralQuery, MetricsQuery, NotException,
    NotExceptionStructured, PathQuery, RawQuery, SectionQuery, SymbolQuery, TextQuery,
    TreeSitterQuery,
};
use super::context::{ConditionResult, EvaluationContext, StringParams};
use super::evaluators::{
    ContentLocationParams, MatchCountGuard, MatchLocationsGuard, SectionParams, TextPattern,
    eval_ast, eval_encoded, eval_hex, eval_metrics, eval_path, eval_raw, eval_section, eval_symbol,
    eval_syscall, eval_text, eval_trait, eval_yara_inline,
};
use super::types::{
    Arch, FileType, Platform, TypeMask, default_architectures, default_file_types,
    default_platforms,
};
use crate::types::{
    Criticality, Evidence, Finding, FindingKind, MAX_EVIDENCE_PER_TRAIT, deduplicate_evidence,
};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::time::Duration;

mod composite_eval;

mod scope;
#[allow(clippy::wildcard_imports)]
pub(crate) use scope::*;

mod trait_eval;

/// Hard deadline for a single rule evaluation (90 seconds).
/// When exceeded, evaluation is incomplete; this is not evidence of an attack.
const MAX_RULE_EVAL_DURATION: Duration = Duration::from_secs(90);

// A deadline belongs to this analysis run, not to the artifact's threat
// taxonomy. Mark it transient so an overloaded run cannot poison the cache.
fn record_rule_timeout(report: &crate::types::AnalysisReport, elapsed: Duration) -> bool {
    if elapsed <= MAX_RULE_EVAL_DURATION {
        return false;
    }
    report
        .analysis_gaps
        .record(crate::types::AnalysisGap::EvaluationDeadline);
    true
}

/// Debug log threshold for rule evaluation (500ms).
/// Rules exceeding this emit an info-level log.
const RULE_EVAL_DEBUG_DURATION: Duration = Duration::from_millis(600);

/// Upper bound on a trait `desc`. Descriptions are shown in the terminal UI and
/// version diffs where a tight cap keeps rows scannable; 48 leaves room for a few
/// genuinely useful longer phrasings without inviting sentence-length blurbs.
const MAX_DESCRIPTION_CHARS: usize = 48;

/// Composite descriptions get more room than atomic traits (48): a composite
/// summarizes a combination, so it legitimately names a few entities. 80 keeps it
/// to one scannable triage line while still ruling out sentence-length blurbs.
#[cfg(feature = "lint")]
const MAX_COMPOSITE_DESCRIPTION_CHARS: usize = 80;

/// Lower a criticality by one level when a downgrade condition fires. Hostile →
/// Suspicious → Notable → Baseline; anything already at or below Baseline floors
/// at Component.
/// Reduce a rule's criticality by one level for a `downgrade:` that fired.
///
/// A `Notable` behavior lands on `Baseline` here, which is a de-emphasis, not a
/// deletion — but `strip_unmatched_traits` treats `Baseline`/`Component`
/// findings as strippable unless a fired composite references them. A notable
/// trait downgraded to `Baseline` therefore used to vanish from the report
/// entirely (and from `--format=json`) when nothing referenced it, while an
/// otherwise identical trait that *was* referenced survived at the lower tier.
/// Findings that reach a low tier by downgrade are now flagged via
/// [`Finding::downgraded`] and exempted from that strip, so the tier a
/// `downgrade:` asks for is the tier the analyst actually sees.
pub(crate) fn downgrade_crit(c: Criticality) -> Criticality {
    match c {
        Criticality::Hostile => Criticality::Suspicious,
        Criticality::Suspicious => Criticality::Notable,
        Criticality::Notable => Criticality::Baseline,
        Criticality::Baseline
        | Criticality::Component
        | Criticality::Exception
        | Criticality::Filtered => Criticality::Component,
    }
}

fn condition_count_weight(condition: &Condition, result: &ConditionResult) -> usize {
    if !result.matched {
        return 0;
    }

    if let Condition::Trait { id } = condition
        && !id.contains("::")
        && id.contains('/')
    {
        let distinct: rustc_hash::FxHashSet<&str> = result
            .matched_trait_ids
            .iter()
            .map(crate::types::Istr::as_str)
            .collect();
        return distinct.len().max(1);
    }

    1
}

/// Dispatch a condition's evaluation. The first argument is a static label kept
/// at call sites for readability; it carries no runtime cost.
macro_rules! timed_eval {
    ($name:expr, $eval:expr) => {{
        let _ = $name;
        $eval
    }};
}

fn default_confidence() -> f32 {
    1.0
}

/// Combine the condition-level and trait-level `not:` exception lists into a
/// single owned vector, preserving ordering. Returns `None` when both inputs
/// are empty so call sites can keep the no-exception fast paths.
fn merge_not_exceptions(
    cond: Option<&Vec<NotException>>,
    trait_level: Option<&Vec<NotException>>,
) -> Option<Vec<NotException>> {
    match (cond, trait_level) {
        (None, None) => None,
        (Some(c), None) => Some(c.clone()),
        (None, Some(t)) => Some(t.clone()),
        (Some(c), Some(t)) => {
            let mut merged = Vec::with_capacity(c.len() + t.len());
            merged.extend_from_slice(c);
            merged.extend_from_slice(t);
            Some(merged)
        }
    }
}

/// What [`eval_condition`] needs from the rule holding a condition: its id (for
/// diagnostics), its rule-level `not:` exceptions (merged with each
/// condition's own) and its architectures (to clamp byte searches).
#[derive(Clone, Copy)]
struct ConditionRule<'r> {
    id: &'r str,
    not: Option<&'r Vec<NotException>>,
    arch: &'r [Arch],
}

/// Evaluate one condition of a trait's `if:` or a composite's clauses.
///
/// Traits and composites share this one dispatcher: two hand-kept copies
/// drifted apart (`kind: number` and condition-level `not:` once worked in
/// only one of them).
fn eval_condition(
    rule: ConditionRule<'_>,
    condition: &Condition,
    ctx: &EvaluationContext<'_>,
) -> ConditionResult {
    let arch_clamp = ctx.arch_clamp_range(rule.arch);
    // Rule-performance validation is off in scans: one flag check, and no
    // walk of `condition` or `ctx` for its arguments.
    let measuring = crate::validation_performance::active();
    let _query_performance = if measuring {
        condition
            .ast_query_text()
            .and_then(|query| crate::validation_performance::QueryTimer::start(rule.id, query, ctx))
    } else {
        None
    };

    let result = match condition {
        Condition::Symbol(SymbolQuery {
            exact,
            substr,
            regex,
            platforms,
            is_check,
            kind,
            arg,
            args,
            alias,
            not,
            module_level,
            receiver,
        }) => {
            let merged_not = merge_not_exceptions(not.as_ref(), rule.not);
            // Source-AST projection kinds (call/member/bind/identifier)
            // dispatch to the filefacts-fact evaluators — pre-extracted
            // records matched without re-walking the AST per rule. All
            // other kinds (Import/Export/Function/Forward/None) go through
            // the legacy declared-symbol path.
            use crate::composite_rules::condition::SymbolKind;
            match kind {
                Some(SymbolKind::Call) => timed_eval!(
                    "symbol",
                    crate::composite_rules::evaluators::symbol_string::eval_call(
                        exact.as_ref(),
                        substr.as_ref(),
                        regex.as_ref(),
                        arg.as_ref(),
                        args.as_deref(),
                        crate::composite_rules::evaluators::symbol_string::CallSite {
                            module_level: *module_level,
                            receiver: receiver.as_ref().map(|r| &r.from),
                        },
                        ctx,
                    )
                ),
                Some(
                    fact_kind @ (SymbolKind::Member | SymbolKind::Bind | SymbolKind::Identifier),
                ) => {
                    timed_eval!(
                        "symbol",
                        crate::composite_rules::evaluators::symbol_string::eval_symbol_fact(
                            *fact_kind,
                            exact.as_ref(),
                            substr.as_ref(),
                            regex.as_ref(),
                            arg.as_ref(),
                            ctx,
                        )
                    )
                }
                _ => timed_eval!(
                    "symbol",
                    eval_symbol(
                        exact.as_ref(),
                        substr.as_ref(),
                        regex.as_ref(),
                        platforms.as_ref(),
                        *is_check,
                        *kind,
                        merged_not.as_ref(),
                        alias.as_ref(),
                        ctx,
                    )
                ),
            }
        }
        Condition::Text(TextQuery {
            encoding,
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            length_min,
            length_max,
            exclude_html_comments,
            exclude_comments,
            is_check,
            not,
            platforms: _,
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
        }) => {
            let params = StringParams {
                encoding: *encoding,
                exact: exact.as_ref(),
                substr: substr.as_ref(),
                regex: regex.as_ref(),
                word: word.as_ref(),
                case_insensitive: *case_insensitive,
                length_min: *length_min,
                length_max: *length_max,
                exclude_html_comments: *exclude_html_comments,
                exclude_comments: *exclude_comments,
                is_check: *is_check,
                section: section.as_ref(),
                offset: *offset,
                offset_range: *offset_range,
                section_offset: *section_offset,
                section_offset_range: *section_offset_range,
                arch_clamp,
            };
            // Honor both condition-level (`if: ... not:`) and trait-level
            // `not:` exception lists; condition-level was previously dropped.
            let merged_not = merge_not_exceptions(not.as_ref(), rule.not);
            timed_eval!(
                "text",
                eval_text(&params, merged_not.as_ref(), ctx, Some(rule.id))
            )
        }
        Condition::Comment(CommentQuery {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            is_check,
            not,
            platforms: _,
        }) => {
            let params = StringParams {
                encoding: None,
                exact: exact.as_ref(),
                substr: substr.as_ref(),
                regex: regex.as_ref(),
                word: word.as_ref(),
                case_insensitive: *case_insensitive,
                length_min: None,
                length_max: None,
                exclude_html_comments: false,
                exclude_comments: false,
                is_check: *is_check,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                arch_clamp,
            };
            let merged_not = merge_not_exceptions(not.as_ref(), rule.not);
            timed_eval!(
                "comment",
                crate::composite_rules::evaluators::symbol_string::eval_comment(
                    &params,
                    merged_not.as_ref(),
                    ctx,
                )
            )
        }
        Condition::Literal(LiteralQuery {
            kind,
            exact,
            substr,
            regex,
            word,
            value,
            radix,
            case_insensitive,
            exclude_docstrings,
            is_check,
            not,
            platforms: _,
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
        }) => {
            // kind=number dispatches to numeric matching against
            // literals extracted into report.strings with
            // section="ast-number" (where value is the decimal
            // integer text and encoding is the source radix). kind
            // omitted or "string" uses the standard string-literal
            // path — backward-compatible with the prior
            // `type: string_literal`.
            if kind.as_deref() == Some("number") {
                timed_eval!(
                    "literal",
                    crate::composite_rules::evaluators::symbol_string::eval_numeric_literal(
                        *value, *radix, ctx,
                    )
                )
            } else {
                let params = StringParams {
                    encoding: None,
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    length_min: None,
                    length_max: None,
                    exclude_html_comments: false,
                    exclude_comments: false,
                    is_check: *is_check,
                    section: section.as_ref(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                    arch_clamp,
                };
                let merged_not = merge_not_exceptions(not.as_ref(), rule.not);
                timed_eval!(
                    "literal",
                    crate::composite_rules::evaluators::symbol_string::eval_string_literal_with_options(
                        &params,
                        merged_not.as_ref(),
                        ctx,
                        *exclude_docstrings,
                    )
                )
            }
        }
        Condition::Trait { id } => timed_eval!("trait", eval_trait(id, ctx)),
        Condition::TreeSitter(TreeSitterQuery {
            kind,
            node,
            exact,
            substr,
            regex,
            query,
            case_insensitive,
            ..
        }) => timed_eval!(
            "ast",
            eval_ast(
                kind.as_deref(),
                node.as_deref(),
                exact.as_deref(),
                substr.as_deref(),
                regex.as_deref(),
                query.as_deref(),
                *case_insensitive,
                ctx,
            )
        ),
        Condition::Yara {
            source,
            namespace,
            compiled,
        } => {
            timed_eval!(
                "yara",
                eval_yara_inline(source, namespace.as_deref(), compiled.as_ref(), ctx)
            )
        }
        Condition::Syscall {
            name,
            number,
            arch,
            args,
        } => {
            timed_eval!(
                "syscall",
                eval_syscall(
                    name.as_deref(),
                    number.as_deref(),
                    arch.as_deref(),
                    args,
                    ctx
                )
            )
        }
        Condition::Metrics(MetricsQuery {
            field,
            min,
            max,
            min_size,
            max_size,
        }) => timed_eval!(
            "metrics",
            eval_metrics(field, *min, *max, *min_size, *max_size, ctx)
        ),
        Condition::Hex(HexQuery {
            pattern,
            not,
            offset,
            offset_range,
            section,
            section_offset,
            section_offset_range,
        }) => {
            let merged_not = merge_not_exceptions(not.as_ref(), rule.not);
            timed_eval!(
                "hex",
                eval_hex(
                    pattern,
                    merged_not.as_ref(),
                    &ContentLocationParams {
                        section: section.clone(),
                        offset: *offset,
                        offset_range: *offset_range,
                        section_offset: *section_offset,
                        section_offset_range: *section_offset_range,
                        arch_clamp,
                    },
                    ctx,
                    Some(rule.id),
                )
            )
        }
        Condition::Raw(RawQuery {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            length_min,
            length_max,
            is_check,
            not,
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
        }) => {
            use super::evaluators::ContentLocationParams;
            let location = ContentLocationParams {
                section: section.clone(),
                offset: *offset,
                offset_range: *offset_range,
                section_offset: *section_offset,
                section_offset_range: *section_offset_range,
                arch_clamp,
            };
            let merged_not = merge_not_exceptions(not.as_ref(), rule.not);
            timed_eval!(
                "raw",
                eval_raw(
                    TextPattern {
                        exact: exact.as_ref(),
                        substr: substr.as_ref(),
                        regex: regex.as_ref(),
                        word: word.as_ref(),
                        case_insensitive: *case_insensitive,
                    },
                    (*length_min, *length_max),
                    *is_check,
                    merged_not.as_ref(),
                    &location,
                    ctx,
                    Some(rule.id),
                )
            )
        }
        Condition::Section(SectionQuery {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            length_min,
            length_max,
            entropy_min,
            entropy_max,
            readable,
            writable,
            executable,
            compare_to,
            size_ratio_min,
            size_ratio_max,
            entropy_ratio_min,
            entropy_ratio_max,
        }) => timed_eval!(
            "section",
            eval_section(
                &SectionParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    length_min: *length_min,
                    length_max: *length_max,
                    entropy_min: *entropy_min,
                    entropy_max: *entropy_max,
                    readable: *readable,
                    writable: *writable,
                    executable: *executable,
                    compare_to: compare_to.as_ref(),
                    size_ratio_min: *size_ratio_min,
                    size_ratio_max: *size_ratio_max,
                    entropy_ratio_min: *entropy_ratio_min,
                    entropy_ratio_max: *entropy_ratio_max,
                },
                ctx,
            )
        ),
        Condition::Encoded(EncodedQuery {
            encoding,
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            is_check,
            not,
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
        }) => {
            use super::evaluators::ContentLocationParams;
            let location = ContentLocationParams {
                section: section.clone(),
                offset: *offset,
                offset_range: *offset_range,
                section_offset: *section_offset,
                section_offset_range: *section_offset_range,
                arch_clamp,
            };
            timed_eval!(
                "encoded",
                eval_encoded(
                    encoding.as_ref(),
                    TextPattern {
                        exact: exact.as_ref(),
                        substr: substr.as_ref(),
                        regex: regex.as_ref(),
                        word: word.as_ref(),
                        case_insensitive: *case_insensitive,
                    },
                    &location,
                    *is_check,
                    not.as_ref(),
                    ctx,
                )
            )
        }
        Condition::Path(PathQuery {
            exact,
            substr,
            regex,
            case_insensitive,
            is_check,
            basename,
            dirname,
        }) => timed_eval!(
            "path",
            eval_path(
                exact.as_ref(),
                substr.as_ref(),
                regex.as_ref(),
                *case_insensitive,
                *is_check,
                *basename,
                *dirname,
                ctx,
            )
        ),
        Condition::Kv(query) => {
            timed_eval!("value", {
                // Trait-level `not:` filters value matches exactly as it
                // does every other matcher's. This arm used to hand the
                // bare condition to the evaluator, so a `not:` written
                // beside `if:` on a value trait was parsed, validated and
                // then silently never applied.
                let merged;
                let condition = match rule.not {
                    Some(trait_level) if !trait_level.is_empty() => {
                        let mut query = query.clone();
                        query.not = merge_not_exceptions(query.not.as_ref(), Some(trait_level));
                        merged = Condition::Kv(query);
                        &merged
                    }
                    _ => condition,
                };
                if let Some(evidence) = super::evaluators::evaluate_kv(condition, ctx) {
                    ConditionResult::matched_with(vec![evidence])
                } else {
                    ConditionResult::no_match()
                }
            })
        }
    };
    if measuring {
        crate::validation_performance::observe_result(rule.id, &ctx.report.target.path, &result);
    }
    result
}

/// Extract relative path from full path (relative to traits directory)
/// Returns None if path conversion fails
/// The rule file `path` relative to the traits directory in use (`/`
/// separators), or just its file name when it lies outside that directory.
pub(crate) fn rule_source_file(path: &std::path::Path) -> Option<String> {
    let root = crate::cache::traits_path();
    path.strip_prefix(&root)
        .ok()
        .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        .or_else(|| path.file_name().map(|n| n.to_string_lossy().into_owned()))
}

/// Report evidence that carries no `location`.
///
/// Every match must record where it was found: downstream composite
/// scope/proximity filtering buckets evidence by `Evidence.location`, and a
/// `None` location keys to the empty scope. When a composite mixes such
/// locationless evidence (e.g. a symbol-type leg) with located evidence (e.g.
/// a text-type leg), the located legs each form their own scope bucket while
/// the locationless legs share the empty bucket — so no single bucket covers
/// the required distinct conditions and the rule silently fails to fire even
/// though every leg matched. A missing location is thus an evaluator bug.
///
/// For now this only logs an error (one line per offending evidence item) so
/// the responsible trait and evaluator can be found. The intent is to promote
/// it to a hard/fatal error once every evaluator populates a location.
fn report_locationless_evidence(trait_id: &str, evidence: &[crate::types::Evidence]) {
    for ev in evidence {
        if ev.location.is_none() {
            let content_match = matches!(
                ev.method.as_str(),
                "string"
                    | "symbol"
                    | "symbols"
                    | "raw"
                    | "text"
                    | "literal"
                    | "string_literal"
                    | "ast"
                    | "ast_query"
                    | "encoded_string"
                    | "hex"
                    | "xor"
            );
            if content_match {
                tracing::error!(
                    trait_id,
                    method = %ev.method,
                    source = %ev.source,
                    "content match has no file offset — evaluator should record its byte span"
                );
            } else {
                tracing::debug!(
                    trait_id,
                    method = %ev.method,
                    source = %ev.source,
                    "file-global evidence has no single byte offset"
                );
            }
        }
    }
}

// NOTE: ConditionWithFilters was removed. Filter fields (count_min, count_max,
// per_kb_min, per_kb_max, entropy_min, entropy_max, size_min, size_max) now
// live directly on TraitDefinition. The `if:` field is now a plain Condition,
// which enables `deny_unknown_fields` on it (serde's flatten prevented this).

/// Conditions for a downgrade level (supports composite syntax)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DowngradeConditions {
    /// At least one of these conditions must match to trigger the downgrade
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub any: Option<Vec<Condition>>,
    /// All of these conditions must match to trigger the downgrade
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub all: Option<Vec<Condition>>,
    /// Minimum number of `any` conditions that must match
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub needs: Option<usize>,
    /// Where this downgrade's conditions may find their evidence.
    ///
    /// Defaults to [`Scope::File`], matching `unless:`: a suppressor resolves
    /// against the file the rule matched in. Anything broader must be asked for
    /// explicitly, because an archive-scoped suppressor lets one member silence
    /// a rule in a completely unrelated member — a vendored `tests/` tree four
    /// directories deep used to cancel a `pkill` call in first-party code, and
    /// nothing in the rule text hinted that could happen.
    ///
    /// `scope: archive` opts back in, for the cases that genuinely want
    /// container context — a signed installer whose signature legitimately
    /// covers the members it carries, for instance. `scope: parent` admits
    /// only the immediate analyzed parent; `scope: file-or-parent` admits the
    /// matched file plus that parent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scope: Option<Scope>,
}

impl DowngradeConditions {
    /// Forward to every held condition — see
    /// [`Condition::collect_kv_sibling_basenames`].
    pub(crate) fn collect_kv_sibling_basenames(
        &self,
        out: &mut std::collections::BTreeSet<String>,
    ) {
        for c in self.any.iter().flatten().chain(self.all.iter().flatten()) {
            c.collect_kv_sibling_basenames(out);
        }
    }

    /// Forward to every held condition — see [`Condition::collect_trait_refs`].
    pub(crate) fn collect_trait_refs(&self, out: &mut std::collections::BTreeSet<String>) {
        for c in self.any.iter().flatten().chain(self.all.iter().flatten()) {
            c.collect_trait_refs(out);
        }
    }
}

/// Definition of an atomic observable trait
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TraitDefinition {
    /// Unique identifier for this trait (e.g., "net/socket", "execution/eval")
    pub id: String,
    /// Human-readable description of what this trait detects
    pub desc: String,
    /// Shared `Istr` of `id`/`desc`, built lazily: every finding this
    /// definition produces clones the `Arc` instead of allocating a fresh
    /// copy — per-finding id/desc allocations were the largest retained
    /// memory class on member-heavy archives (2M findings held through a
    /// 54k-member archive's fold). `serde(skip)`: derived state only.
    #[serde(skip)]
    pub(crate) id_shared: std::sync::OnceLock<crate::types::Istr>,
    #[serde(skip)]
    pub(crate) desc_shared: std::sync::OnceLock<crate::types::Istr>,
    /// Memo for [`Self::requires_non_ascii`]. `serde(skip)`: derived state only.
    #[serde(skip)]
    pub(crate) requires_non_ascii: std::sync::OnceLock<bool>,
    /// Confidence score (0.5 = heuristic, 1.0 = definitive)
    #[serde(default = "default_confidence")]
    pub conf: f32,

    /// Criticality level (defaults to None = internal only)
    #[serde(default)]
    pub crit: Criticality,

    /// MBC (Malware Behavior Catalog) ID - most specific available (e.g., "B0015.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,

    /// MITRE ATT&CK Technique ID (e.g., "T1056.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,

    /// Reference that inspired this trait: a source URL or "sha256:<hash>" of a
    /// motivating sample. Provenance only; not used during matching.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub r#ref: Option<String>,

    /// Platforms this trait targets (defaults to all)
    #[serde(default = "default_platforms")]
    pub platforms: Vec<Platform>,

    /// CPU architectures this trait targets (defaults to all)
    #[serde(default = "default_architectures")]
    pub arch: Vec<Arch>,

    /// File types this trait applies to (defaults to all)
    #[serde(default = "default_file_types")]
    pub r#for: Vec<FileType>,

    /// True if `for:` was specified using named groups (binaries, scripts, etc.)
    #[serde(skip, default)]
    #[cfg_attr(not(feature = "lint"), allow(dead_code))]
    pub for_from_groups: bool,

    /// The detection condition (plain Condition — no flatten, enables deny_unknown_fields)
    pub r#if: Condition,

    /// Minimum file size in bytes — checked before evaluating condition
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_min: Option<usize>,

    /// Maximum file size in bytes — checked before evaluating condition
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_max: Option<usize>,

    /// Minimum match count — trait matches only if condition matches at least this many times
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub count_min: Option<usize>,

    /// Maximum match count — trait fails if condition matches more than this many times
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub count_max: Option<usize>,

    /// Minimum matches per kilobyte of file size (density threshold)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub per_kb_min: Option<f64>,

    /// Maximum matches per kilobyte of file size (density ceiling)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub per_kb_max: Option<f64>,

    /// Minimum file entropy (0.0–8.0) — checked before evaluating condition
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub entropy_min: Option<f64>,

    /// Maximum file entropy (0.0–8.0) — checked before evaluating condition
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub entropy_max: Option<f64>,

    /// String-level exceptions — filter matched strings
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub not: Option<Vec<NotException>>,

    /// File-level skip conditions — composite rule that skips trait if matched
    /// Default semantics: skip if ANY condition matches (unless: [list])
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub unless: Option<Vec<Condition>>,

    /// Criticality downgrade rules — map of target criticality to conditions
    /// Only levels LOWER than base `crit` are allowed (validated at load time)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub downgrade: Option<DowngradeConditions>,
    /// Validators this rule is exempt from (`exempt:` in YAML, keyed by
    /// validator id with a reason). Only validation reads it.
    #[serde(skip_serializing_if = "<[_]>::is_empty", default)]
    pub exempt: Box<[Box<str>]>,
    /// Path to the YAML file this trait was loaded from
    #[serde(skip)]
    pub defined_in: std::path::PathBuf,
    /// Precision score (calculated during loading, not from YAML)
    #[serde(skip)]
    pub precision: Option<f32>,
}

impl Default for TraitDefinition {
    /// Mirrors the serde field defaults so `TraitDefinition { id, desc, r#if, ..Default::default() }`
    /// construction (used widely in tests) yields the same values the YAML loader would.
    /// `r#if` has no natural default, so it gets an inert trait reference to an
    /// empty id (matches nothing); real constructions always override it.
    fn default() -> Self {
        Self {
            id_shared: std::sync::OnceLock::new(),
            desc_shared: std::sync::OnceLock::new(),
            requires_non_ascii: std::sync::OnceLock::new(),
            id: String::new(),
            desc: String::new(),
            conf: default_confidence(),
            crit: Criticality::default(),
            mbc: None,
            attack: None,
            r#ref: None,
            platforms: default_platforms(),
            arch: default_architectures(),
            r#for: default_file_types(),
            for_from_groups: false,
            r#if: Condition::Trait { id: String::new() },
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            not: None,
            unless: None,
            downgrade: None,
            exempt: Box::default(),
            defined_in: std::path::PathBuf::new(),
            precision: None,
        }
    }
}

/// Boolean logic for combining conditions/traits
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CompositeTrait {
    /// Unique identifier for this composite rule
    pub id: String,
    /// Human-readable description of what this rule detects
    pub desc: String,
    /// Shared `Istr` of `id`/`desc`, built lazily: every finding this
    /// definition produces clones the `Arc` instead of allocating a fresh
    /// copy — per-finding id/desc allocations were the largest retained
    /// memory class on member-heavy archives (2M findings held through a
    /// 54k-member archive's fold). `serde(skip)`: derived state only.
    #[serde(skip)]
    pub(crate) id_shared: std::sync::OnceLock<crate::types::Istr>,
    #[serde(skip)]
    pub(crate) desc_shared: std::sync::OnceLock<crate::types::Istr>,
    /// `for:` as a type mask, built once on first use. Intersected
    /// against the type of the file a candidate finding came from, so a leg is
    /// satisfied only by evidence from a file this rule declared. `serde(skip)`:
    /// derived from `for:`.
    #[serde(skip)]
    pub(crate) for_mask_cache: std::sync::OnceLock<TypeMask>,
    /// Derived from the immutable loaded `for:` list, like `for_mask_cache`.
    /// Explicit scope remains authoritative and is never cached.
    #[serde(skip)]
    pub(crate) default_scope_cache: std::sync::OnceLock<Scope>,
    /// Confidence score for the generated finding
    pub conf: f32,

    /// Criticality level (defaults to None)
    #[serde(default)]
    pub crit: Criticality,

    /// MBC (Malware Behavior Catalog) ID - most specific available (e.g., "B0015.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mbc: Option<String>,

    /// MITRE ATT&CK Technique ID (e.g., "T1056.001")
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub attack: Option<String>,

    /// Reference that inspired this rule: a source URL or "sha256:<hash>".
    /// Provenance only; not used during matching.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub r#ref: Option<String>,

    /// Platforms this rule targets (defaults to all)
    #[serde(default = "default_platforms")]
    pub platforms: Vec<Platform>,

    /// CPU architectures this rule targets (defaults to all)
    #[serde(default = "default_architectures")]
    pub arch: Vec<Arch>,

    /// File types this rule applies to (defaults to all)
    #[serde(default = "default_file_types")]
    pub r#for: Vec<FileType>,

    /// True if `for:` was specified using named groups (binaries, scripts, etc.)
    #[serde(skip, default)]
    #[cfg_attr(not(feature = "lint"), allow(dead_code))]
    pub for_from_groups: bool,

    /// Minimum file size in bytes
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_min: Option<usize>,

    /// Maximum file size in bytes
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_max: Option<usize>,

    // Boolean operators
    /// All of these conditions must match
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all: Option<Vec<Condition>>,

    /// List of conditions - use `needs` to control how many must match
    #[serde(skip_serializing_if = "Option::is_none")]
    pub any: Option<Vec<Condition>>,

    /// Minimum number of conditions from `any` that must match
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs: Option<usize>,

    /// Proximity constraint: at least count_min findings must be within N lines
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub near_lines: Option<usize>,

    /// Proximity constraint: at least count_min findings must be within N bytes/characters
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub near_bytes: Option<usize>,

    /// Scope of evidence co-occurrence (see [`Scope`]). When omitted,
    /// defaults to [`Scope::File`] — evidence must share the same
    /// leaf-file (decoded payload layers pool with the file).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scope: Option<Scope>,

    /// File-level skip conditions - skip entire rule if ANY condition matches
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub unless: Option<Vec<Condition>>,

    /// String-level exceptions - filter matched strings
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub not: Option<Vec<NotException>>,

    /// Criticality downgrade rules - map of target criticality to conditions
    /// Only levels LOWER than base `crit` are allowed (validated at load time)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub downgrade: Option<DowngradeConditions>,
    /// Validators this rule is exempt from (`exempt:` in YAML, keyed by
    /// validator id with a reason). Only validation reads it.
    #[serde(skip_serializing_if = "<[_]>::is_empty", default)]
    pub exempt: Box<[Box<str>]>,
    /// Source file path where this composite rule was defined
    #[serde(skip)]
    pub defined_in: std::path::PathBuf,
    /// Precision score (calculated during loading, not from YAML)
    #[serde(skip)]
    pub precision: Option<f32>,

    /// Indices of atomic traits this composite rule depends on (for pruning)
    #[serde(skip)]
    pub required_trait_indices: Vec<usize>,
}

impl Default for CompositeTrait {
    /// Mirrors the serde field defaults so `CompositeTrait { id, desc, conf, ..Default::default() }`
    /// construction (used widely in tests) matches what the YAML loader produces.
    fn default() -> Self {
        Self {
            for_mask_cache: std::sync::OnceLock::new(),
            default_scope_cache: std::sync::OnceLock::new(),
            id: String::new(),
            desc: String::new(),
            id_shared: std::sync::OnceLock::new(),
            desc_shared: std::sync::OnceLock::new(),
            conf: default_confidence(),
            crit: Criticality::default(),
            mbc: None,
            attack: None,
            r#ref: None,
            platforms: default_platforms(),
            arch: default_architectures(),
            r#for: default_file_types(),
            for_from_groups: false,
            size_min: None,
            size_max: None,
            all: None,
            any: None,
            needs: None,
            near_lines: None,
            near_bytes: None,
            scope: None,
            unless: None,
            not: None,
            downgrade: None,
            exempt: Box::default(),
            defined_in: std::path::PathBuf::new(),
            precision: None,
            required_trait_indices: Vec::new(),
        }
    }
}

/// Build an index of byte offsets for the start of each line (0-indexed line numbers).
/// Line 0 starts at byte 0, line 1 starts after the first `\n`, etc.
/// Location info tagged with its originating condition index, for cross-condition proximity checks.
pub(super) struct TaggedLocation {
    /// First byte offset from evidence (if available)
    pub byte_offset: Option<u64>,
    /// Location string from evidence (if available, e.g. "42:5" or "0x1234")
    pub location: Option<String>,
    /// Index of the condition that produced this evidence
    pub condition_index: usize,
}

/// Extract a line number from a TaggedLocation.
fn tagged_to_line(tagged: &TaggedLocation, line_starts: &[usize]) -> Option<usize> {
    // Try "line:column" format first
    if let Some(ref loc) = tagged.location
        && let Some(colon_pos) = loc.find(':')
        && let Ok(line) = loc[..colon_pos].parse::<usize>()
        && line > 0
    {
        return Some(line);
    }

    // Try byte offset
    if let Some(offset) = tagged.byte_offset {
        return Some(byte_offset_to_line(line_starts, offset as usize));
    }

    // Try hex offset from location
    if let Some(ref loc) = tagged.location
        && let Some(offset) = parse_location_as_byte_offset(loc)
    {
        return Some(byte_offset_to_line(line_starts, offset as usize));
    }

    None
}

/// Extract a byte offset from a TaggedLocation.
fn tagged_to_byte_offset(tagged: &TaggedLocation) -> Option<u64> {
    if let Some(offset) = tagged.byte_offset {
        return Some(offset);
    }

    if let Some(ref loc) = tagged.location {
        return parse_location_as_byte_offset(loc);
    }

    None
}

/// Extract TaggedLocations from a condition's evidence items.
///
/// One evidence item can hold several occurrences of the same match, and
/// proximity needs each of them, so an item with `offsets` expands to one tag
/// per offset. Every expanded tag keeps the item's `location`: the offset says
/// *where inside* the analyzed unit the match sits, while the location names
/// the unit itself (archive member, decoded layer, `row:col`) and is what
/// [`Scope::key`] buckets on. Dropping it collapses every scope key to the
/// empty string, which silently degrades `scope: leaf`/`file`/`archive` to
/// `outer` for all offset-carrying evidence.
fn tag_evidence(evidence: &[Evidence], condition_index: usize) -> Vec<TaggedLocation> {
    let mut tags = Vec::new();
    for ev in evidence {
        if ev.offsets.is_empty() {
            tags.push(TaggedLocation {
                byte_offset: None,
                location: ev.location.clone(),
                condition_index,
            });
        } else {
            for offset in &ev.offsets {
                tags.push(TaggedLocation {
                    byte_offset: Some(*offset),
                    location: ev.location.clone(),
                    condition_index,
                });
            }
        }
    }
    tags
}

pub(super) fn build_line_index(data: &[u8]) -> Vec<usize> {
    let mut starts = vec![0];
    for (i, &b) in data.iter().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

/// Convert a byte offset to a 1-indexed line number using the precomputed line index.
pub(super) fn byte_offset_to_line(line_starts: &[usize], offset: usize) -> usize {
    match line_starts.binary_search(&offset) {
        Ok(idx) => idx + 1, // Exact start of a line
        Err(idx) => idx,    // Falls within line (idx-1), but 1-indexed → idx
    }
}

/// Extract a line number from an evidence item.
///
/// Tries in priority order:
/// 1. Parse `location` as "line:column" (e.g., "42:5") — produced by AST evidence
/// 2. Use first byte offset from `offsets` vec — produced by string/yara evidence
/// 3. Parse `location` as hex byte offset (e.g., "0x1234") — older string evidence
pub(super) fn evidence_to_line(evidence: &Evidence, line_starts: &[usize]) -> Option<usize> {
    // Try "line:column" format first
    if let Some(ref loc) = evidence.location
        && let Some(colon_pos) = loc.find(':')
        && let Ok(line) = loc[..colon_pos].parse::<usize>()
    {
        // Sanity check: line numbers from AST are positive integers, not hex
        if line > 0 {
            return Some(line);
        }
    }

    // Try byte offsets from the offsets vec
    if let Some(&first_offset) = evidence.offsets.first() {
        return Some(byte_offset_to_line(line_starts, first_offset as usize));
    }

    // Try hex offset from location (e.g., "0x1234", "offset:0x1234")
    if let Some(ref loc) = evidence.location
        && let Some(offset) = parse_location_as_byte_offset(loc)
    {
        return Some(byte_offset_to_line(line_starts, offset as usize));
    }

    None
}

/// Extract a byte offset from an evidence item.
///
/// Tries in priority order:
/// 1. First byte offset from `offsets` vec
/// 2. Parse `location` as hex byte offset (e.g., "0x1234", "offset:0x1234")
pub(super) fn evidence_to_byte_offset(evidence: &Evidence) -> Option<u64> {
    if let Some(&first_offset) = evidence.offsets.first() {
        return Some(first_offset);
    }

    if let Some(ref loc) = evidence.location {
        return parse_location_as_byte_offset(loc);
    }

    None
}

/// Parse a location string as a byte offset.
/// Handles "0x1234", "offset:0x1234", "offset:1234", and embedded-code
/// parent offsets such as "embedded@0x1234:1:5".
fn parse_location_as_byte_offset(loc: &str) -> Option<u64> {
    if let Some(offset) = parse_embedded_location_offset(loc) {
        return Some(offset);
    }
    if let Some(rest) = loc.strip_prefix("offset:") {
        return parse_hex_or_dec_offset(rest);
    }
    if loc.starts_with("0x") || loc.starts_with("0X") {
        return parse_hex_or_dec_offset(loc);
    }
    None
}

fn parse_embedded_location_offset(loc: &str) -> Option<u64> {
    if let Some(rest) = loc.strip_prefix("embedded@") {
        let offset = rest.split_once(':').map_or(rest, |(offset, _)| offset);
        return parse_hex_or_dec_offset(offset);
    }

    if let Some(rest) = loc.strip_prefix("embedded:") {
        let (_, offset_and_tail) = rest.rsplit_once('@')?;
        let offset = offset_and_tail
            .split_once(':')
            .map_or(offset_and_tail, |(offset, _)| offset);
        return parse_hex_or_dec_offset(offset);
    }

    None
}

fn parse_hex_or_dec_offset(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Check if at least `min_required` evidence items have line numbers within `max_line_span`.
/// The distinct condition count a window must cover.
///
/// `min_distinct` counts every positive leg, but some legs can never appear in
/// a window: a `type: path` match is a fact about the file's name, so it
/// carries no byte offset or line. Requiring it to sit inside the span makes
/// the constraint unsatisfiable no matter what the file contains --
/// `chocolatey-install-remote-powershell-eval` paired a filename leg with a
/// download and an `iex` under `near_bytes: 1024` and stopped firing entirely,
/// including on a specimen whose whole script is six lines.
///
/// `required_all` already holds only the located `all:` legs, so the honest
/// floor is those plus the `any:` quota. Never raises the caller's figure.
fn effective_min_distinct(
    required_all: &rustc_hash::FxHashSet<usize>,
    any_required: usize,
    min_distinct: usize,
) -> usize {
    min_distinct.min(required_all.len() + any_required).max(2)
}

/// Returns the (start_line, end_line) of the first qualifying window, or None.
fn evidence_within_line_range(
    evidence: &[Evidence],
    max_line_span: usize,
    min_required: usize,
    line_starts: &[usize],
) -> Option<(usize, usize)> {
    let mut line_numbers: SmallVec<[usize; MAX_EVIDENCE_PER_TRAIT]> = evidence
        .iter()
        .filter_map(|e| evidence_to_line(e, line_starts))
        .collect();

    if line_numbers.len() < min_required {
        return None;
    }

    line_numbers.sort_unstable();

    // Sliding window: find any window of max_line_span that contains min_required items
    for (i, &start_line) in line_numbers.iter().enumerate() {
        let mut count = 0;
        for &line in &line_numbers[i..] {
            if line - start_line <= max_line_span {
                count += 1;
                if count >= min_required {
                    return Some((start_line, line));
                }
            } else {
                break;
            }
        }
    }

    None
}

/// Returns the (start_offset, end_offset) of the first qualifying window, or None.
fn evidence_within_byte_range(
    evidence: &[Evidence],
    max_byte_span: usize,
    min_required: usize,
) -> Option<(u64, u64)> {
    let mut byte_offsets: SmallVec<[u64; MAX_EVIDENCE_PER_TRAIT]> = evidence
        .iter()
        .filter_map(evidence_to_byte_offset)
        .collect();

    if byte_offsets.len() < min_required {
        return None;
    }

    byte_offsets.sort_unstable();

    for (i, &start) in byte_offsets.iter().enumerate() {
        let mut count = 0;
        for &offset in &byte_offsets[i..] {
            if (offset - start) <= max_byte_span as u64 {
                count += 1;
                if count >= min_required {
                    return Some((start, offset));
                }
            } else {
                break;
            }
        }
    }

    None
}

/// A proximity window is satisfying only when it independently reproduces the
/// rule's condition structure: it must contain every `all:` condition that
/// produced a locatable finding (indices `< all_count`) **and** at least
/// `any_required` distinct `any:` conditions (indices `>= all_count`).
///
/// Counting total distinct indices is not sufficient. An `any:` group with
/// more legs than `needs:` can otherwise supply the whole `min_distinct` count
/// on its own — two co-located `any:` matches would satisfy proximity while a
/// far-away `all:` leg escapes the constraint entirely (the "fetch here, hidden
/// path 60 lines below" false-positive). We only require `all:` legs that
/// actually produced a location: a position-less `all:` leg (e.g. a file-level
/// metadata fact) cannot be proximity-constrained and must not block matching.
fn window_satisfies_groups(
    seen: &rustc_hash::FxHashSet<usize>,
    required_all: &rustc_hash::FxHashSet<usize>,
    all_count: usize,
    any_required: usize,
    min_distinct: usize,
) -> bool {
    seen.len() >= min_distinct
        && required_all.iter().all(|idx| seen.contains(idx))
        && seen.iter().filter(|&&idx| idx >= all_count).count() >= any_required
}

/// The distinct `all:` condition indices (`< all_count`) that produced a
/// locatable finding — the legs a proximity window is required to co-locate.
fn located_all_indices(
    indices: impl Iterator<Item = usize>,
    all_count: usize,
) -> rustc_hash::FxHashSet<usize> {
    indices.filter(|&idx| idx < all_count).collect()
}

/// Returns the (start_line, end_line) of the first qualifying window, or None.
fn evidence_within_line_range_grouped(
    items: &[(usize, usize)], // (line_number, condition_index)
    max_line_span: usize,
    all_count: usize,
    any_required: usize,
    min_distinct: usize,
) -> Option<(usize, usize)> {
    let required_all = located_all_indices(items.iter().map(|&(_, idx)| idx), all_count);
    let min_distinct = effective_min_distinct(&required_all, any_required, min_distinct);
    if items.len() < min_distinct {
        return None;
    }

    let mut sorted: SmallVec<[(usize, usize); MAX_EVIDENCE_PER_TRAIT]> = items.into();
    sorted.sort_unstable_by_key(|&(line, _)| line);

    // Sliding window: find any window of max_line_span that reproduces the
    // rule's condition structure (all `all:` legs + enough `any:` legs).
    for (i, &(start_line, _)) in sorted.iter().enumerate() {
        let mut seen = rustc_hash::FxHashSet::default();
        for &(line, cond_idx) in &sorted[i..] {
            if line - start_line <= max_line_span {
                seen.insert(cond_idx);
                if window_satisfies_groups(
                    &seen,
                    &required_all,
                    all_count,
                    any_required,
                    min_distinct,
                ) {
                    return Some((start_line, line));
                }
            } else {
                break;
            }
        }
    }

    None
}

/// Returns the (start_offset, end_offset) of the first qualifying window, or None.
fn evidence_within_byte_range_grouped(
    items: &[(u64, usize)], // (byte_offset, condition_index)
    max_byte_span: usize,
    all_count: usize,
    any_required: usize,
    min_distinct: usize,
) -> Option<(u64, u64)> {
    let required_all = located_all_indices(items.iter().map(|&(_, idx)| idx), all_count);
    let min_distinct = effective_min_distinct(&required_all, any_required, min_distinct);
    if items.len() < min_distinct {
        return None;
    }

    let mut sorted: SmallVec<[(u64, usize); MAX_EVIDENCE_PER_TRAIT]> = items.into();
    sorted.sort_unstable_by_key(|&(offset, _)| offset);

    for (i, &(start, _)) in sorted.iter().enumerate() {
        let mut seen = rustc_hash::FxHashSet::default();
        for &(offset, cond_idx) in &sorted[i..] {
            if (offset - start) <= max_byte_span as u64 {
                seen.insert(cond_idx);
                if window_satisfies_groups(
                    &seen,
                    &required_all,
                    all_count,
                    any_required,
                    min_distinct,
                ) {
                    return Some((start, offset));
                }
            } else {
                break;
            }
        }
    }

    None
}

/// The legs behind one fired `unless:`/`downgrade:` condition, with the bytes
/// they matched.
///
/// A `Condition::Trait` (the overwhelmingly common suppressor) names the
/// concrete traits it resolved to, so a directory-prefix leg like
/// `metadata/package/testing/harness/runtime/` reports the trait that actually
/// fired rather than echoing the prefix. Any other condition kind has no trait
/// identity, so it reports its own shape.
fn suppression_legs(
    condition: &Condition,
    result: &crate::composite_rules::context::ConditionResult,
) -> Vec<crate::types::SuppressionLeg> {
    let spans = || {
        let mut s = crate::types::traits_findings::evidence_spans(&result.evidence);
        crate::types::traits_findings::sort_dedup_spans_by_offset(&mut s);
        s.truncate(crate::types::traits_findings::MAX_EV_LOCS);
        s
    };
    if result.matched_trait_ids.is_empty() {
        return vec![crate::types::SuppressionLeg {
            id: condition.type_name().into(),
            spans: spans(),
        }];
    }
    // One shared span set: the evidence a `Trait` condition returns is the
    // union across the traits it resolved to, not attributable per id.
    let spans = spans();
    result
        .matched_trait_ids
        .iter()
        .map(|id| crate::types::SuppressionLeg {
            id: id.clone(),
            spans: spans.clone(),
        })
        .collect()
}

/// The legs that fired a `downgrade:`.
///
/// Re-evaluates the positive blocks, which is why it is reached only through
/// [`EvaluationContext::record_suppression`]'s closure: the hot path asks
/// `eval_downgrade_conditions` a yes/no question and must not pay to remember
/// which legs answered it.
fn downgrade_legs(
    conditions: &DowngradeConditions,
    mut eval: impl FnMut(&Condition) -> crate::composite_rules::context::ConditionResult,
) -> Vec<crate::types::SuppressionLeg> {
    let mut legs = Vec::new();
    for cond in conditions
        .all
        .iter()
        .flatten()
        .chain(conditions.any.iter().flatten())
    {
        let result = eval(cond);
        if result.matched {
            legs.extend(suppression_legs(cond, &result));
        }
    }
    legs
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod scope_tests;

#[cfg(test)]
mod match_count_bound_tests;

#[cfg(test)]
mod timeout_diagnostic_tests;
