//! Trait definitions for composite rules.
//!
//! This module contains TraitDefinition (atomic traits) and CompositeTrait
//! (boolean combinations of conditions).

use super::condition::{
    CommentQuery, Condition, EncodedQuery, HexQuery, KvQuery, LiteralQuery, MetricsQuery,
    NotException, NotExceptionStructured, PathQuery, RawQuery, SectionQuery, StringValidator,
    SymbolKind, SymbolQuery, TextQuery, TreeSitterQuery,
};
use super::context::{ConditionResult, EvaluationContext, StringParams};
use super::evaluators::{
    ContentLocationParams, MatchCountGuard, SectionParams, eval_ast, eval_encoded, eval_hex,
    eval_metrics, eval_path, eval_raw, eval_section, eval_string_literal, eval_symbol,
    eval_syscall, eval_text, eval_trait, eval_yara_inline,
};
use super::types::{
    Arch, FileType, Platform, default_architectures, default_file_types, default_platforms,
};
use crate::types::{
    Criticality, Evidence, Finding, FindingKind, MAX_EVIDENCE_PER_TRAIT, deduplicate_evidence,
};
use anyhow::Context;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::time::{Duration, Instant};

/// Hard deadline for a single rule evaluation (90 seconds).
/// When exceeded, evaluation is interrupted and a timeout finding is emitted.
const MAX_RULE_EVAL_DURATION: Duration = Duration::from_secs(90);

/// Debug log threshold for rule evaluation (500ms).
/// Rules exceeding this emit an info-level log.
const RULE_EVAL_DEBUG_DURATION: Duration = Duration::from_millis(600);

/// Upper bound on a trait `desc`. Descriptions are shown in the terminal UI and
/// version diffs where a tight cap keeps rows scannable; 48 leaves room for a few
/// genuinely useful longer phrasings without inviting sentence-length blurbs.
const MAX_DESCRIPTION_CHARS: usize = 48;

/// Lower a criticality by one level when a downgrade condition fires. Hostile →
/// Suspicious → Notable → Baseline; anything already at or below Baseline floors
/// at Component.
pub(crate) fn downgrade_crit(c: Criticality) -> Criticality {
    match c {
        Criticality::Hostile => Criticality::Suspicious,
        Criticality::Suspicious => Criticality::Notable,
        Criticality::Notable => Criticality::Baseline,
        Criticality::Baseline | Criticality::Component | Criticality::Filtered => {
            Criticality::Component
        }
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
            .map(String::as_str)
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

/// Extract relative path from full path (relative to traits directory)
/// Returns None if path conversion fails
fn get_relative_source_file(path: &std::path::Path) -> Option<String> {
    // Try to find "traits/" in the path and return everything after it
    let path_str = path.to_string_lossy();
    if let Some(pos) = path_str.find("traits/") {
        let relative = &path_str[pos + 7..]; // Skip "traits/" prefix
        return Some(relative.to_string());
    }
    // Fallback: return the file name only if we can't find "traits/"
    path.file_name()
        .and_then(|n| n.to_str())
        .map(std::string::ToString::to_string)
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
            tracing::error!(
                trait_id,
                method = %ev.method,
                source = %ev.source,
                "evidence has no location — evaluator bug; locationless evidence \
                 breaks composite scope bucketing and is slated to become fatal"
            );
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
    /// None of these conditions may match to trigger the downgrade
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub none: Option<Vec<Condition>>,
    /// Minimum number of `any` conditions that must match
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub needs: Option<usize>,
}

/// Definition of an atomic observable trait
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TraitDefinition {
    /// Unique identifier for this trait (e.g., "net/socket", "execution/eval")
    pub id: String,
    /// Human-readable description of what this trait detects
    pub desc: String,
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
            defined_in: std::path::PathBuf::new(),
            precision: None,
        }
    }
}

impl TraitDefinition {
    /// Pre-compile all regexes in this trait's conditions for performance.
    /// Returns an error if any regex pattern is invalid.
    pub(crate) fn precompile_regexes(&mut self) -> anyhow::Result<()> {
        self.r#if
            .precompile_regexes()
            .with_context(|| format!("in trait '{}' main condition", self.id))?;
        // Pre-compile not-exception patterns
        if let Some(ref mut exceptions) = self.not {
            for exc in exceptions.iter_mut() {
                exc.precompile();
            }
        }
        if let Some(ref mut conds) = self.unless {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes().with_context(|| {
                    format!("in trait '{}' unless condition #{}", self.id, idx + 1)
                })?;
            }
        }
        if let Some(ref mut downgrade) = self.downgrade {
            if let Some(ref mut any) = downgrade.any {
                for (idx, cond) in any.iter_mut().enumerate() {
                    cond.precompile_regexes().with_context(|| {
                        format!(
                            "in trait '{}' downgrade.any condition #{}",
                            self.id,
                            idx + 1
                        )
                    })?;
                }
            }
            if let Some(ref mut all) = downgrade.all {
                for (idx, cond) in all.iter_mut().enumerate() {
                    cond.precompile_regexes().with_context(|| {
                        format!(
                            "in trait '{}' downgrade.all condition #{}",
                            self.id,
                            idx + 1
                        )
                    })?;
                }
            }
            if let Some(ref mut none) = downgrade.none {
                for (idx, cond) in none.iter_mut().enumerate() {
                    cond.precompile_regexes().with_context(|| {
                        format!(
                            "in trait '{}' downgrade.none condition #{}",
                            self.id,
                            idx + 1
                        )
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Register the combined-engine namespace for the top-level `if` condition.
    /// Sets `Condition::Yara { namespace }` to `"inline.{trait_id}"` so evaluation
    /// uses the pre-scanned combined engine results instead of re-compiling.
    /// Also compiles any `unless` YARA conditions independently (they are rare).
    pub(crate) fn set_yara_if_namespace(&mut self) {
        let ns = format!("inline.{}", self.id);
        self.r#if.set_yara_namespace(ns);
        // Still compile unless conditions the old way — they are rare and not in the combined engine
        if let Some(ref mut conds) = self.unless {
            for cond in conds.iter_mut() {
                cond.compile_yara();
            }
        }
    }

    /// Check if criticality level is valid for user-defined traits.
    /// Returns an error message if invalid, None otherwise.
    #[must_use]
    pub(crate) fn check_criticality(&self) -> Option<String> {
        use crate::types::Criticality;

        // Check if criticality is "Filtered" which is internal-only
        if self.crit == Criticality::Filtered {
            return Some(
                "crit: 'filtered' is an internal-only criticality level. Use one of: 'baseline' (informational), 'notable' (interesting behavior), 'suspicious' (potentially malicious), or 'hostile' (clearly malicious)".to_string()
            );
        }

        None
    }

    /// Check if confidence value is in valid range.
    /// Returns an error message if invalid, None otherwise.
    #[must_use]
    pub(crate) fn check_confidence(&self) -> Option<String> {
        if self.conf < 0.0 || self.conf > 1.0 {
            return Some(format!(
                "conf: {} is outside valid range [0.0, 1.0]",
                self.conf
            ));
        }
        None
    }

    /// Check if size constraints are valid.
    /// Returns an error message if invalid, None otherwise.
    #[must_use]
    pub(crate) fn check_size_constraints(&self) -> Option<String> {
        // Skip validation for Section conditions - they have their own size_min/size_max
        // for section sizes, which are separate from file size constraints
        if matches!(self.r#if, Condition::Section(SectionQuery { .. })) {
            return None;
        }

        if let (Some(min), Some(max)) = (self.size_min, self.size_max)
            && max < min
        {
            return Some(format!(
                "size_max ({}) cannot be less than size_min ({})",
                max, min
            ));
        }
        None
    }

    /// Check if entropy constraints are valid.
    /// Returns an error message if invalid, None otherwise.
    #[must_use]
    pub(crate) fn check_entropy_constraints(&self) -> Option<String> {
        // Validate entropy range (0.0-8.0)
        if let Some(min) = self.entropy_min
            && !(0.0..=8.0).contains(&min)
        {
            return Some(format!(
                "entropy_min ({:.2}) must be between 0.0 and 8.0",
                min
            ));
        }
        if let Some(max) = self.entropy_max
            && !(0.0..=8.0).contains(&max)
        {
            return Some(format!(
                "entropy_max ({:.2}) must be between 0.0 and 8.0",
                max
            ));
        }
        if let (Some(min), Some(max)) = (self.entropy_min, self.entropy_max)
            && max < min
        {
            return Some(format!(
                "entropy_max ({:.2}) cannot be less than entropy_min ({:.2})",
                max, min
            ));
        }
        None
    }

    /// Check if count constraints are valid.
    #[must_use]
    pub(crate) fn check_count_constraints(&self) -> Option<String> {
        if let (Some(min), Some(max)) = (self.count_min, self.count_max)
            && max < min
        {
            return Some(format!(
                "count_max ({}) is less than count_min ({})",
                max, min
            ));
        }
        self.r#if.check_count_constraints()
    }

    /// Check if density constraints are valid.
    #[must_use]
    pub(crate) fn check_density_constraints(&self) -> Option<String> {
        if let (Some(min), Some(max)) = (self.per_kb_min, self.per_kb_max)
            && max < min
        {
            return Some(format!(
                "per_kb_max ({}) is less than per_kb_min ({})",
                max, min
            ));
        }
        self.r#if.check_density_constraints()
    }

    /// Check for meaningless count_min: 0.
    #[must_use]
    pub(crate) fn check_count_min_value(&self) -> Option<String> {
        if let Some(0) = self.count_min {
            return Some("count_min: 0 is meaningless (default is 1)".to_string());
        }
        self.r#if.check_count_min_value()
    }

    /// Check for empty, too-short, or too-long descriptions.
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_description_quality(&self) -> Option<String> {
        let desc = self.desc.trim();

        if desc.is_empty() {
            return Some(
                "desc: field is empty. Write a clear, concise description of what this trait detects. Examples: 'XOR decryption loop' or 'Detects SSH key theft attempts'".to_string()
            );
        }

        if desc.len() < 5 {
            return Some(format!(
                "desc: '{}' is too short ({} chars). Write a clear description. Examples: 'JOIN command for IRC' or 'Detects IRC communication patterns'",
                desc,
                desc.len()
            ));
        }

        let desc_len = desc.chars().count();
        if desc_len > MAX_DESCRIPTION_CHARS {
            return Some(format!(
                "desc: '{}' is too long ({} chars). Keep descriptions at {} characters or less.",
                desc, desc_len, MAX_DESCRIPTION_CHARS
            ));
        }

        None
    }

    /// Check for empty not: arrays (common LLM mistake).
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_empty_not_array(&self) -> Option<String> {
        if let Some(not_exceptions) = &self.not
            && not_exceptions.is_empty()
        {
            return Some(
                "not: array is empty - either remove the not: field or add exception patterns"
                    .to_string(),
            );
        }
        None
    }

    /// Check for empty unless: arrays (common LLM mistake).
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_empty_unless_array(&self) -> Option<String> {
        if let Some(unless_conditions) = &self.unless
            && unless_conditions.is_empty()
        {
            return Some(
                "unless: array is empty - either remove the unless: field or add skip conditions"
                    .to_string(),
            );
        }
        None
    }

    /// Check if `not:` field is used appropriately based on match type.
    /// Returns a warning message if misused, None otherwise.
    #[must_use]
    pub(crate) fn check_not_field_usage(&self) -> Option<String> {
        let not_exceptions = self.not.as_ref()?;

        // Helper to check if a pattern could match a literal string
        fn pattern_could_match(pattern: &str, literal: &str) -> bool {
            if let Ok(re) = regex::Regex::new(pattern) {
                re.is_match(literal)
            } else {
                false
            }
        }

        // Helper to check if a string contains a substring (case-sensitive or insensitive)
        fn contains_substr(haystack: &str, needle: &str, case_insensitive: bool) -> bool {
            if case_insensitive {
                haystack.to_lowercase().contains(&needle.to_lowercase())
            } else {
                haystack.contains(needle)
            }
        }

        match &self.r#if {
            // Symbol conditions with not: - validate exceptions match the pattern
            Condition::Symbol(SymbolQuery {
                exact: Some(_),
                regex: None,
                ..
            }) => {
                return Some(
                    "not: field used with symbol exact match - consider using 'unless:' instead for deterministic patterns".to_string()
                );
            }
            Condition::Symbol(SymbolQuery {
                substr: Some(search_substr),
                regex: None,
                ..
            }) => {
                // For symbol substr, validate not: exceptions contain the search substr
                for exc in not_exceptions {
                    match exc {
                        NotException::Shorthand(exc_str) if !exc_str.contains(search_substr) => {
                            return Some(format!(
                                "not: exception '{}' does not contain the search substr '{}' - symbols matching the substr won't contain this exception, so it will never be applied",
                                exc_str, search_substr
                            ));
                        }
                        NotException::Structured(NotExceptionStructured {
                            exact: Some(exc_str),
                            ..
                        }) if !exc_str.contains(search_substr) => {
                            return Some(format!(
                                "not: exception (exact) '{}' does not contain the search substr '{}' - symbols matching the substr won't match this exception, so it will never be applied",
                                exc_str, search_substr
                            ));
                        }
                        NotException::Structured(NotExceptionStructured {
                            substr: Some(exc_substr),
                            ..
                        }) if !exc_substr.contains(search_substr)
                            && !search_substr.contains(exc_substr) =>
                        {
                            return Some(format!(
                                "not: exception (substr) '{}' has no overlap with search substr '{}' - they won't match the same symbols, so the exception will never be applied",
                                exc_substr, search_substr
                            ));
                        }
                        _ => {}
                    }
                }
            }
            Condition::Symbol(SymbolQuery {
                regex: Some(pattern),
                ..
            }) => {
                // For symbol regex, validate that exceptions could potentially match
                for exc in not_exceptions {
                    match exc {
                        // Validate shorthand (substr) exceptions - check if the substr matches the regex
                        NotException::Shorthand(exc_str)
                            if !pattern_could_match(pattern, exc_str) =>
                        {
                            return Some(format!(
                                "not: exception '{}' does not match the search regex '{}' - symbols matching the regex won't contain this exception, so it will never be applied",
                                exc_str, pattern
                            ));
                        }
                        // Validate exact exceptions - check if the exact string matches the regex
                        NotException::Structured(NotExceptionStructured {
                            exact: Some(exc_str),
                            ..
                        }) if !pattern_could_match(pattern, exc_str) => {
                            return Some(format!(
                                "not: exception (exact) '{}' does not match the search regex '{}' - it will never be applied",
                                exc_str, pattern
                            ));
                        }
                        // For substr and regex exceptions, validation is complex - allow them
                        _ => {}
                    }
                }
            }
            // Exact matches should use `unless:` instead of `not:`
            Condition::Text(TextQuery {
                exact: Some(_),
                regex: None,
                word: None,
                ..
            })
            | Condition::Literal(LiteralQuery {
                exact: Some(_),
                regex: None,
                word: None,
                ..
            }) => {
                return Some(
                    "not: field used with exact match - consider using 'unless:' instead for deterministic patterns".to_string()
                );
            }
            // For Content exact matches, not: doesn't make sense
            Condition::Raw(RawQuery {
                exact: Some(_),
                regex: None,
                word: None,
                ..
            }) => {
                return Some(
                    "not: field used with content/exact match - this doesn't make sense. Content exact matches the entire file content.".to_string()
                );
            }
            // For String substr matches, validate that not: exceptions could match strings containing the substr
            Condition::Text(TextQuery {
                substr: Some(search_substr),
                regex: None,
                word: None,
                case_insensitive,
                ..
            })
            | Condition::Literal(LiteralQuery {
                substr: Some(search_substr),
                regex: None,
                word: None,
                case_insensitive,
                ..
            }) => {
                let case_insensitive = *case_insensitive;

                for exc in not_exceptions {
                    match exc {
                        // For shorthand (substr match in not:), check if the exception contains the search substr
                        NotException::Shorthand(exc_str)
                            if !contains_substr(exc_str, search_substr, case_insensitive) =>
                        {
                            return Some(format!(
                                "not: exception '{}' does not contain the search substr '{}' - strings matching the substr won't contain this exception, so it will never be applied",
                                exc_str, search_substr
                            ));
                        }
                        // Exception is exact match - it should contain the search substr.
                        NotException::Structured(NotExceptionStructured {
                            exact: Some(exc_str),
                            ..
                        }) if !contains_substr(exc_str, search_substr, case_insensitive) => {
                            return Some(format!(
                                "not: exception (exact) '{}' does not contain the search substr '{}' - strings matching the substr won't match this exception, so it will never be applied",
                                exc_str, search_substr
                            ));
                        }
                        // Exception is substr - it should contain the search substr or vice versa.
                        NotException::Structured(NotExceptionStructured {
                            substr: Some(exc_substr),
                            ..
                        }) if !contains_substr(exc_substr, search_substr, case_insensitive)
                            && !contains_substr(search_substr, exc_substr, case_insensitive) =>
                        {
                            return Some(format!(
                                "not: exception (substr) '{}' has no overlap with search substr '{}' - they won't match the same strings, so the exception will never be applied",
                                exc_substr, search_substr
                            ));
                        }
                        // Regex exceptions with substr searches can't be validated cheaply.
                        _ => {}
                    }
                }
            }
            // For Content substr matches, not: is unclear - content searches don't extract individual strings
            Condition::Raw(RawQuery {
                substr: Some(_),
                regex: None,
                word: None,
                ..
            }) => {
                return Some(
                    "not: field used with content/substr match - behavior is unclear because content searches on binary data don't extract individual strings for filtering. Use regex instead, or use 'string' type with substr.".to_string()
                );
            }
            // For regex matches, validate that exceptions could potentially match
            Condition::Text(TextQuery {
                regex: Some(pattern),
                ..
            })
            | Condition::Literal(LiteralQuery {
                regex: Some(pattern),
                ..
            })
            | Condition::Raw(RawQuery {
                regex: Some(pattern),
                ..
            }) => {
                for exc in not_exceptions {
                    match exc {
                        // Validate shorthand (substr) exceptions — check if the substr matches the regex
                        NotException::Shorthand(exc_str)
                            if !pattern_could_match(pattern, exc_str) =>
                        {
                            return Some(format!(
                                "not: exception '{}' does not match the search regex '{}' - strings matching the regex won't contain this exception, so it will never be applied",
                                exc_str, pattern
                            ));
                        }
                        // Validate exact exceptions — check if the exact string matches the regex
                        NotException::Structured(NotExceptionStructured {
                            exact: Some(exc_str),
                            ..
                        }) if !pattern_could_match(pattern, exc_str) => {
                            return Some(format!(
                                "not: exception (exact) '{}' does not match the search regex '{}' - it will never be applied",
                                exc_str, pattern
                            ));
                        }
                        // For substr and regex exceptions, validation is complex — allow them.
                        _ => {}
                    }
                }
            }
            // For hex patterns, validate exceptions match
            Condition::Hex(HexQuery { pattern: _, .. }) => {
                // For hex patterns, we should validate that not: exceptions make sense
                // Since hex matching is complex, we'll do a basic check
                // Hex patterns match byte sequences, so not: exceptions should be regex-based
                for exc in not_exceptions {
                    let _ = exc; // All exception types are allowed for hex patterns
                }
            }
            _ => {}
        }

        None
    }

    /// Check if this trait has any dependencies on other traits via `trait:` conditions.
    /// Used to determine evaluation order - traits with dependencies must be evaluated
    /// after their dependencies have been resolved.
    #[must_use]
    pub(crate) fn has_trait_dependency(&self) -> bool {
        // Check main condition
        if self.r#if.is_trait_reference() {
            return true;
        }

        // Check unless conditions
        if let Some(ref unless) = self.unless {
            for cond in unless {
                if cond.is_trait_reference() {
                    return true;
                }
            }
        }

        // Check downgrade conditions
        if let Some(ref downgrade) = self.downgrade {
            if let Some(ref any) = downgrade.any {
                for cond in any {
                    if cond.is_trait_reference() {
                        return true;
                    }
                }
            }
            if let Some(ref all) = downgrade.all {
                for cond in all {
                    if cond.is_trait_reference() {
                        return true;
                    }
                }
            }
            if let Some(ref none) = downgrade.none {
                for cond in none {
                    if cond.is_trait_reference() {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// Whether this trait's evaluation needs the exact `match_count` — i.e. it
    /// has a count/density filter. When false, raw/text matching may stop at the
    /// first match (the dominant RSS lever; see `eval_raw`'s `needs_count`). The
    /// exact count is consumed only by these filters: no other consumer reads it
    /// and the ML pipeline (collimator) does not feature on `match_count`.
    pub(crate) fn needs_match_count(&self) -> bool {
        self.count_min.is_some()
            || self.count_max.is_some()
            || self.per_kb_min.is_some()
            || self.per_kb_max.is_some()
    }

    /// Evaluate this trait definition against the analysis context
    pub(crate) fn evaluate<'a>(&self, ctx: &EvaluationContext<'a>) -> Option<Finding> {
        use super::debug::{ConditionDebug, DowngradeDebug, SkipReason};

        // Let raw/text matching stop at the first match unless this trait needs
        // the exact `match_count` (count/density filter). Restored on drop so
        // nested `Condition::Trait` evaluations don't clobber it.
        let _mcg = MatchCountGuard::set(self.needs_match_count());

        // Check platform match
        let platform_match = super::types::platforms_intersect(&self.platforms, ctx.platforms);

        if !platform_match {
            ctx.record_skip(SkipReason::PlatformMismatch {
                rule: self.platforms.clone(),
                context: ctx.platforms.to_vec(),
            });
            return None;
        }

        // Check architecture match
        let arch_match = self.arch.contains(&Arch::All)
            || ctx.arch.contains(&Arch::All)
            || self.arch.iter().any(|a| ctx.arch.contains(a));

        if !arch_match {
            ctx.record_skip(SkipReason::ArchMismatch {
                rule: self.arch.clone(),
                context: ctx.arch.to_vec(),
            });
            return None;
        }

        // Check file type match.
        // Container-level evaluation may collapse archive parents to FileType::All.
        // In that case, allow only archive-family rules to match rather than treating
        // All as a universal wildcard for every script/source/binary rule.
        let wants_archive_family = self.r#for.iter().any(super::types::FileType::is_archive);
        let file_type_match = self.r#for.contains(&FileType::All)
            || self.r#for.contains(&ctx.file_type)
            || ((ctx.file_type == FileType::All || ctx.file_type.is_archive())
                && wants_archive_family);

        if !file_type_match {
            ctx.record_skip(SkipReason::FileTypeMismatch {
                rule: self.r#for.clone(),
                context: ctx.file_type,
            });
            return None;
        }

        // Check size constraints (from if: block)
        let file_size = ctx.report.target.size_bytes as usize;
        if let Some(min) = self.size_min
            && file_size < min
        {
            ctx.record_skip(SkipReason::SizeTooSmall {
                actual: file_size,
                min,
            });
            return None;
        }
        if let Some(max) = self.size_max
            && file_size > max
        {
            ctx.record_skip(SkipReason::SizeTooLarge {
                actual: file_size,
                max,
            });
            return None;
        }

        // Check entropy constraints (from if: block)
        // Uses binary.overall_entropy for binaries, text.char_entropy for scripts
        if self.entropy_min.is_some() || self.entropy_max.is_some() {
            // Both `binary.overall_entropy` and `text.char_entropy`
            // flow through the flat `filefacts_metrics` map now.
            let binary_entropy = ctx
                .report
                .filefacts_metrics
                .as_ref()
                .and_then(|m| m.get("binary.overall_entropy").copied());
            let text_entropy = ctx
                .report
                .filefacts_metrics
                .as_ref()
                .and_then(|m| m.get("text.char_entropy").copied());
            let file_entropy = binary_entropy.or(text_entropy).unwrap_or(0.0);

            if let Some(min) = self.entropy_min
                && file_entropy < min
            {
                ctx.record_skip(SkipReason::EntropyTooLow {
                    actual: file_entropy,
                    min,
                });
                return None;
            }
            if let Some(max) = self.entropy_max
                && file_entropy > max
            {
                ctx.record_skip(SkipReason::EntropyTooHigh {
                    actual: file_entropy,
                    max,
                });
                return None;
            }
        }

        // Start timing for timeout detection (covers all evaluation phases)
        let start = Instant::now();

        // Check unless conditions (file-level skip)
        if let Some(unless_conds) = &self.unless {
            // Default 'any' semantics: skip if ANY condition matches
            for condition in unless_conds {
                let result = self.eval_condition(condition, ctx);
                if result.matched {
                    // For a directory-prefix unless (e.g. `metadata/binary/resource/`),
                    // the bare pattern alone is rarely actionable — surface the concrete
                    // trait(s) that actually matched the prefix so `test-rules` names the
                    // real suppressor instead of echoing the prefix back.
                    let concrete = if result.matched_trait_ids.is_empty() {
                        String::new()
                    } else {
                        format!(" [matched: {}]", result.matched_trait_ids.join(", "))
                    };
                    ctx.record_skip(SkipReason::UnlessConditionMatched {
                        condition_desc: format!("{:?}{}", condition, concrete),
                    });
                    return None;
                }
            }
        }

        // Evaluate the condition (traits only have one atomic condition)
        let result = self.eval_condition(&self.r#if, ctx);
        let duration = start.elapsed();

        // Hard timeout: emit a timeout finding and skip the actual result
        if duration > MAX_RULE_EVAL_DURATION {
            eprintln!(
                "WARN: Rule {} exceeded hard timeout: {}ms > {}ms",
                self.id,
                duration.as_millis(),
                MAX_RULE_EVAL_DURATION.as_millis()
            );

            let timeout_warning = Finding {
                src: None,
                id: "objectives/anti-analysis/analysis-bomb/rule-timeout".to_string(),
                desc: format!(
                    "Rule evaluation timeout: {} took {}ms (limit: {}ms)",
                    self.id,
                    duration.as_millis(),
                    MAX_RULE_EVAL_DURATION.as_millis()
                ),
                crit: Criticality::Suspicious,
                kind: FindingKind::Indicator,
                conf: 0.9,
                mbc: Some("B0003.005".to_string()), // Obfuscated Files or Information: Analysis Evasion
                attack: None,
                trait_refs: vec![],
                evidence: vec![crate::types::Evidence {
                    method: "timeout-detection".to_string(),
                    source: "cleave-evaluator".to_string(),
                    value: format!(
                        "Rule '{}' exceeded {}ms hard timeout, took {}ms",
                        self.id,
                        MAX_RULE_EVAL_DURATION.as_millis(),
                        duration.as_millis()
                    ),
                    location: Some("0x0".to_string()),
                    ..Default::default()
                }],
                match_count: 0,
                source_file: get_relative_source_file(&self.defined_in),
            };

            return Some(timeout_warning);
        }

        // Info log: rules taking >500ms
        if duration > RULE_EVAL_DEBUG_DURATION {
            tracing::info!("slow rule: {} took {}ms", self.id, duration.as_millis(),);
        }

        // Warn log: rules exceeding the user-configurable slow_rule_ms threshold
        let warn_threshold = Duration::from_millis(ctx.slow_rule_ms);
        if duration > warn_threshold {
            tracing::warn!(
                "slow rule: {} took {}ms (threshold: {}ms)",
                self.id,
                duration.as_millis(),
                ctx.slow_rule_ms,
            );
        }

        // Record condition result if debug collector is present
        ctx.with_debug(|debug| {
            let cond_debug = ConditionDebug::default()
                .with_matched(result.matched)
                .with_evidence(result.evidence.clone())
                .with_precision(result.precision);
            debug.add_condition(cond_debug);
        });

        if result.matched {
            // Apply count and density filters (centralized for all condition types)
            // Use match_count which may exceed evidence.len() for high-frequency patterns
            let match_count = result.match_count;
            let file_kb = (file_size as f64) / 1024.0;

            // Check count_min constraint
            if let Some(min) = self.count_min
                && match_count < min
            {
                ctx.record_skip(SkipReason::CountBelowMinimum {
                    actual: match_count,
                    min,
                });
                return None;
            }

            // Check count_max constraint
            if let Some(max) = self.count_max
                && match_count > max
            {
                ctx.record_skip(SkipReason::CountAboveMaximum {
                    actual: match_count,
                    max,
                });
                return None;
            }

            // Check per_kb_min constraint (density threshold).
            // Zero-byte files have infinite density — trivially satisfy any minimum.
            if let Some(min_density) = self.per_kb_min
                && file_kb > 0.0
            {
                let actual_density = (match_count as f64) / file_kb;
                if actual_density < min_density {
                    ctx.record_skip(SkipReason::DensityBelowMinimum {
                        actual: actual_density,
                        min: min_density,
                    });
                    return None;
                }
            }

            // Check per_kb_max constraint (density ceiling).
            // A zero-byte file with matches has infinite density — always fails the ceiling.
            if let Some(max_density) = self.per_kb_max {
                let actual_density = if file_kb > 0.0 {
                    (match_count as f64) / file_kb
                } else {
                    f64::INFINITY
                };
                if actual_density > max_density {
                    ctx.record_skip(SkipReason::DensityAboveMaximum {
                        actual: actual_density,
                        max: max_density,
                    });
                    return None;
                }
            }

            let mut final_crit = self.crit;

            // Check downgrade conditions
            if let Some(downgrade_conds) = &self.downgrade {
                let triggered = self.eval_downgrade_conditions(downgrade_conds, ctx);
                if triggered {
                    final_crit = downgrade_crit(self.crit);
                    if final_crit != self.crit {
                        tracing::debug!(
                            "Downgrade applied: trait '{}' from {:?} → {:?}",
                            self.id,
                            self.crit,
                            final_crit
                        );
                    }
                }

                // Record downgrade debug if collector is present
                ctx.with_debug(|debug| {
                    debug.set_downgrade(DowngradeDebug {
                        original_crit: self.crit,
                        final_crit,
                        triggered,
                    });
                });
            }

            // Record match in debug collector
            ctx.with_debug(|debug| {
                debug.matched = true;
                debug.precision = result.precision;
            });

            // Guardrail: every piece of evidence must carry a `location`.
            // Locationless evidence silently breaks composite scope/proximity
            // bucketing — it keys to the empty scope and can split a single-file
            // rule into unsatisfiable singleton buckets (a symbol-type leg with
            // no location never pools with a text-type leg that has one). A
            // missing location is therefore an evaluator bug, not a valid state.
            // For now we log; this is slated to become a hard error once every
            // evaluator populates a location.
            report_locationless_evidence(&self.id, &result.evidence);

            Some(Finding {
                src: None,
                id: self.id.clone(),
                kind: FindingKind::Capability,
                desc: self.desc.clone(),
                conf: self.conf,
                crit: final_crit,
                mbc: self.mbc.clone(),
                attack: self.attack.clone(),
                trait_refs: vec![],
                evidence: result.evidence,
                match_count: result.match_count,
                source_file: get_relative_source_file(&self.defined_in),
            })
        } else {
            None
        }
    }

    /// Re-evaluate this trait's downgrade clause against a (possibly richer)
    /// evaluation context, returning the new criticality that should be applied.
    ///
    /// Used by the cross-scope downgrade pass: a per-file trait that references
    /// a container-level finding (e.g. `metadata/signed/platform::mozilla-extension`)
    /// gets a second chance to apply its downgrade once container composites
    /// have been evaluated and merged into the report.
    ///
    /// `base_crit` should be the trait's *declared* criticality (`self.crit`),
    /// not the finding's current crit, so the pass is idempotent: calling it
    /// twice yields the same result as calling it once.
    pub(crate) fn evaluate_downgrade<'a>(
        &self,
        conditions: &DowngradeConditions,
        base_crit: &Criticality,
        ctx: &EvaluationContext<'a>,
    ) -> Criticality {
        if self.eval_downgrade_conditions(conditions, ctx) {
            downgrade_crit(*base_crit)
        } else {
            *base_crit
        }
    }

    /// Evaluate a single downgrade condition set.
    /// All specified blocks (all/any/none) must pass for the downgrade to trigger.
    fn eval_downgrade_conditions<'a>(
        &self,
        conditions: &DowngradeConditions,
        ctx: &EvaluationContext<'a>,
    ) -> bool {
        let mut has_any_block = false;

        // If 'all' is specified, every condition must match
        if let Some(all_conds) = &conditions.all {
            has_any_block = true;
            for cond in all_conds {
                if !self.eval_condition(cond, ctx).matched {
                    return false;
                }
            }
        }

        // If 'any' is specified, at least `needs` conditions must match (default 1)
        if let Some(any_conds) = &conditions.any {
            has_any_block = true;
            let threshold = conditions.needs.unwrap_or(1);
            let mut matched_count = 0;
            for cond in any_conds {
                let result = self.eval_condition(cond, ctx);
                matched_count += condition_count_weight(cond, &result);
            }
            if matched_count < threshold {
                return false;
            }
        }

        // If 'none' is specified, none may match
        if let Some(none_conds) = &conditions.none {
            has_any_block = true;
            for cond in none_conds {
                if self.eval_condition(cond, ctx).matched {
                    return false;
                }
            }
        }

        has_any_block
    }

    /// Evaluate a single condition
    fn eval_condition<'a>(
        &self,
        condition: &Condition,
        ctx: &EvaluationContext<'a>,
    ) -> ConditionResult {
        let arch_clamp = ctx.arch_clamp_range(&self.arch);

        match condition {
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
            }) => {
                let merged_not = merge_not_exceptions(not.as_ref(), self.not.as_ref());
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
                            ctx,
                        )
                    ),
                    Some(
                        fact_kind
                        @ (SymbolKind::Member | SymbolKind::Bind | SymbolKind::Identifier),
                    ) => {
                        timed_eval!(
                            "symbol",
                            crate::composite_rules::evaluators::symbol_string::eval_symbol_fact(
                                *fact_kind,
                                exact.as_ref(),
                                substr.as_ref(),
                                regex.as_ref(),
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
                exact,
                substr,
                regex,
                word,
                case_insensitive,
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
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
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
                let merged_not = merge_not_exceptions(not.as_ref(), self.not.as_ref());
                timed_eval!(
                    "text",
                    eval_text(&params, merged_not.as_ref(), ctx, Some(self.id.as_str()))
                )
            }
            Condition::Comment(CommentQuery {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not: _,
                platforms: _,
            }) => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    is_check: *is_check,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    arch_clamp,
                };
                timed_eval!(
                    "comment",
                    crate::composite_rules::evaluators::symbol_string::eval_comment(
                        &params,
                        self.not.as_ref(),
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
                is_check,
                not: _,
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
                        exact: exact.as_ref(),
                        substr: substr.as_ref(),
                        regex: regex.as_ref(),
                        word: word.as_ref(),
                        case_insensitive: *case_insensitive,
                        is_check: *is_check,
                        section: section.as_ref(),
                        offset: *offset,
                        offset_range: *offset_range,
                        section_offset: *section_offset,
                        section_offset_range: *section_offset_range,
                        arch_clamp,
                    };
                    timed_eval!(
                        "literal",
                        eval_string_literal(&params, self.not.as_ref(), ctx)
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
            Condition::Syscall { name, number, arch } => {
                timed_eval!(
                    "syscall",
                    eval_syscall(name.as_ref(), number.as_ref(), arch.as_ref(), ctx)
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
                not: _,
                offset,
                offset_range,
                section,
                section_offset,
                section_offset_range,
            }) => timed_eval!(
                "hex",
                eval_hex(
                    pattern,
                    &ContentLocationParams {
                        section: section.clone(),
                        offset: *offset,
                        offset_range: *offset_range,
                        section_offset: *section_offset,
                        section_offset_range: *section_offset_range,
                        arch_clamp,
                    },
                    ctx,
                    Some(self.id.as_str()),
                )
            ),
            Condition::Raw(RawQuery {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not: _,
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
                    "raw",
                    eval_raw(
                        exact.as_ref(),
                        substr.as_ref(),
                        regex.as_ref(),
                        word.as_ref(),
                        *case_insensitive,
                        *is_check,
                        self.not.as_ref(),
                        &location,
                        ctx,
                        Some(self.id.as_str()),
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
                        exact.as_ref(),
                        substr.as_ref(),
                        regex.as_ref(),
                        word.as_ref(),
                        *case_insensitive,
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
            Condition::Kv(KvQuery { .. }) => {
                timed_eval!("value", {
                    // Delegate to value evaluator with caching
                    if let Some(evidence) = super::evaluators::evaluate_kv(condition, ctx) {
                        ConditionResult::matched_with(vec![evidence])
                    } else {
                        ConditionResult::no_match()
                    }
                })
            }
        }
    }
}

/// Scope of evidence co-occurrence for a composite rule.
///
/// A composite's conditions can match in different parts of the analysis
/// tree. `Scope` controls how tightly evidence from distinct conditions
/// must share an analysis-tree ancestor before the composite is allowed
/// to fire. Lower variants are more permissive; higher variants are more
/// strict.
///
/// The default (omitted from YAML) is [`Scope::File`]: evidence must
/// share the same leaf-file (the deepest file-shaped unit, e.g. a PE
/// extracted from a zip). Decoded payload layers below the file are
/// pooled together at the file level.
///
/// ```text
/// Outer    →  anywhere within the input given to cleave
/// Archive  →  same nearest enclosing archive entry
///             (degrades to Outer when no archive is in the path)
/// File     →  same leaf-file (the deepest file-shaped unit, e.g. a
///             PE inside a zip; ignores decoded payload layers below)
///             (default)
/// Leaf     →  same exact analyzed unit, including decoded payload layers
/// ```
///
/// Two pieces of evidence share scope iff their scope keys are equal,
/// where the key is computed by [`Scope::key`] from each evidence's
/// `Evidence.location`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Scope {
    /// Anywhere within the input given to cleave.
    Outer,
    /// A fetched package artifact together with its registry metadata
    /// (`*.registry.json`). Like [`Scope::Outer`] it pools by presence
    /// (empty key), but it is only ever evaluated on the fetch-driven
    /// package pass that unions an artifact's findings with its
    /// registry record's findings — so a `scope: package` composite is
    /// a no-op on a bare local scan and fires only under `--fetch` /
    /// `pkg:`. Authored for rules that correlate registry facts
    /// (deprecated, low downloads, fresh publish) with artifact
    /// behavior.
    Package,
    /// Same nearest enclosing archive entry. For evidence that is not
    /// inside an archive, degrades to [`Scope::Outer`] (empty key —
    /// same key as every other non-archive evidence in the input).
    Archive,
    /// Same leaf-file. The deepest file-shaped unit (e.g. a PE
    /// extracted from a zip). Decoded payload layers below the
    /// file are pooled together at the file level. Default.
    #[default]
    File,
    /// Same exact analyzed unit, including decoded payload layers.
    Leaf,
}

impl Scope {
    /// Compute the scope key for a piece of evidence given its
    /// `Evidence.location`. Two evidence items share scope iff their
    /// scope keys are equal.
    ///
    /// The key is a borrowed substring of `location` (or the empty
    /// string), so this is allocation-free.
    fn key(self, location: Option<&str>) -> &str {
        match (self, location) {
            // Outer/Package scope or no location info — all evidence shares one
            // key. Package pools by presence; the artifact↔registry boundary it
            // spans is two separate analyses with no shared location to key on.
            (Scope::Outer | Scope::Package, _) | (_, None) => "",
            // Leaf: exact location match required.
            (Scope::Leaf, Some(loc)) => strip_byte_offset_location(loc),
            // File: strip any decoded-payload suffix; what remains is
            // the leaf-file identifier.
            (Scope::File, Some(loc)) => strip_byte_offset_location(strip_decode_suffix(loc)),
            // Archive: nearest enclosing archive entry path.
            (Scope::Archive, Some(loc)) => parent_archive(loc),
        }
    }
}

/// Strip cleave's decoded-payload suffix from a location, returning
/// the leaf-file portion. Decoded payload locations carry the
/// `encoding_chain:` prefix; for those the file-level key collapses
/// to the empty string (same input). Pure positional locations of
/// the form `row:col` (or `row:col:tail`) — produced by the AST
/// evaluator, which has no file path to prefix — also collapse to
/// the empty string so AST evidence pools with non-AST evidence in
/// the same analyzed unit under `scope: file`. Otherwise composites
/// that mix AST conditions with text/symbol/encoded conditions can
/// never satisfy `min_distinct_conditions` because every AST match
/// buckets to its own `row:col` key while sibling evidence buckets to
/// the empty key.
///
/// For archive entry locations like `archive:foo.zip!bar.so`, no
/// decode suffix is present and the input is returned unchanged.
fn strip_decode_suffix(location: &str) -> &str {
    if location.starts_with("encoding_chain:") {
        // Decoded layer with no associated file path. Collapse to
        // input-wide key so file-scoped composites still pool input
        // evidence with decoded evidence from the same input.
        ""
    } else if location.starts_with("value:") {
        // KV evidence carries the kv-path in `location` for display;
        // it identifies a field within a single file, not a leaf-file
        // boundary. Collapse to the input-wide key so file-scoped
        // composites pool kv evidence with non-kv evidence in the
        // same file.
        ""
    } else if location.starts_with("embedded@") || location.starts_with("embedded:") {
        // Embedded-code findings (e.g. shell extracted from a
        // Dockerfile RUN block, or a YAML `run:` step) carry a
        // `embedded@<offset>:<inner>` prefix to record where in the
        // parent file they came from. The parent is still one
        // analyzed unit, so pool sibling embedded-code findings — and
        // host-file findings — under the same file-scope key.
        ""
    } else if is_positional_only(location) {
        ""
    } else {
        location
    }
}

/// Strip byte-offset-only evidence detail from a scope location.
///
/// Byte offsets (`0x1234`, `offset:1234`) identify where evidence was
/// found inside an analyzed unit; they do not identify a different
/// analysis-tree leaf. Scope filtering should use the containing unit
/// as the bucket and leave byte distance to `near_bytes`.
///
/// Archive aggregation prefixes nested evidence as
/// `archive:path/to/member:<inner-location>`, so preserve the archive
/// member key while dropping a trailing byte offset.
fn strip_byte_offset_location(location: &str) -> &str {
    if parse_location_as_byte_offset(location).is_some() {
        return "";
    }

    if let Some((prefix, suffix)) = location.rsplit_once(":offset:")
        && parse_hex_or_dec_offset(suffix).is_some()
    {
        return prefix;
    }

    if let Some((prefix, suffix)) = location.rsplit_once(':')
        && (suffix.starts_with("0x")
            || suffix.starts_with("0X")
            || suffix.bytes().all(|b| b.is_ascii_digit()))
        && parse_location_as_byte_offset(suffix).is_some()
    {
        return prefix;
    }

    location
}

/// True if `location` is a pure `row:col` (or `row:col:...`) string
/// with no leading file path, archive prefix, or scheme. Such
/// locations carry no file-identity information so they should
/// collapse to the input-wide key under `scope: file`.
fn is_positional_only(location: &str) -> bool {
    let mut parts = location.split(':');
    let Some(first) = parts.next() else {
        return false;
    };
    let Some(second) = parts.next() else {
        return false;
    };
    // Both leading components must be all-digit, non-empty. Any
    // remaining trailing components are tolerated (some evaluators
    // may extend the position with a third coordinate).
    !first.is_empty()
        && first.bytes().all(|b| b.is_ascii_digit())
        && !second.is_empty()
        && second.bytes().all(|b| b.is_ascii_digit())
}

/// For an archive entry location, return the path of its nearest
/// enclosing archive (i.e. the path with the trailing `!`-separated
/// component stripped). For non-archive locations, return the empty
/// string — `archive` scope degrades to `outer` in that case.
///
/// Archive paths have the shape `archive:<path>` where `<path>` may
/// contain `!` separators for nested archives:
///   archive:foo.so                    → "archive:"          (single-level)
///   archive:foo.zip!bar.so            → "archive:foo.zip"   (parent zip)
///   archive:outer.zip!inner.zip!x.so  → "archive:outer.zip!inner.zip"
fn parent_archive(location: &str) -> &str {
    let Some(after_prefix) = location.strip_prefix("archive:") else {
        return "";
    };
    // Drop any encoded-payload suffix that may follow the entry path.
    let entry_path = match after_prefix.find("::") {
        Some(idx) => &after_prefix[..idx],
        None => after_prefix,
    };
    match entry_path.rfind('!') {
        // Nested entry: keep `archive:<path-up-to-last-!>`.
        Some(idx) => &location[.."archive:".len() + idx],
        // Single-level entry: all peers in this archive share the bare
        // prefix as their key.
        None => "archive:",
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
            defined_in: std::path::PathBuf::new(),
            precision: None,
            required_trait_indices: Vec::new(),
        }
    }
}

impl CompositeTrait {
    /// Collect the subset of dependent trait IDs that are individually mandatory.
    ///
    /// These IDs are used only for fast prefiltering before full composite evaluation,
    /// so they must be a sound lower bound:
    /// - every `all:` trait reference is mandatory
    /// - `any:` references are only mandatory when the rule requires all of them
    fn get_required_trait_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();

        if let Some(conds) = &self.all {
            for cond in conds {
                if let Condition::Trait { id } = cond {
                    ids.push(id.clone());
                }
            }
        }

        if let Some(conds) = &self.any {
            let required_from_any = self.needs.unwrap_or(1);
            if required_from_any >= conds.len() {
                for cond in conds {
                    if let Condition::Trait { id } = cond {
                        ids.push(id.clone());
                    }
                }
            }
        }

        ids
    }

    /// Populate required_trait_indices using a map of trait ID -> index.
    ///
    /// This is a pruning hint for composite evaluation, not a full encoding of the
    /// rule. It must never require more matched traits than the composite actually
    /// needs to run, or valid `any:` + `needs:` rules get skipped before evaluation.
    pub(crate) fn populate_required_traits(
        &mut self,
        trait_id_map: &std::collections::HashMap<String, usize>,
    ) {
        let dependent_ids = self.get_required_trait_ids();
        self.required_trait_indices = dependent_ids
            .into_iter()
            .filter_map(|id| trait_id_map.get(&id).copied())
            .collect();
        self.required_trait_indices.sort_unstable();
        self.required_trait_indices.dedup();
    }

    /// Pre-compile all regexes in this rule's conditions for performance.
    /// Returns an error if any regex pattern is invalid.
    pub(crate) fn precompile_regexes(&mut self) -> anyhow::Result<()> {
        if let Some(ref mut conds) = self.all {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes().with_context(|| {
                    format!("in composite rule '{}' all condition #{}", self.id, idx + 1)
                })?;
            }
        }
        if let Some(ref mut conds) = self.any {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes().with_context(|| {
                    format!("in composite rule '{}' any condition #{}", self.id, idx + 1)
                })?;
            }
        }
        if let Some(ref mut conds) = self.unless {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes().with_context(|| {
                    format!(
                        "in composite rule '{}' unless condition #{}",
                        self.id,
                        idx + 1
                    )
                })?;
            }
        }
        if let Some(ref mut downgrade) = self.downgrade {
            if let Some(ref mut any) = downgrade.any {
                for (idx, cond) in any.iter_mut().enumerate() {
                    cond.precompile_regexes().with_context(|| {
                        format!(
                            "in composite rule '{}' downgrade.any condition #{}",
                            self.id,
                            idx + 1
                        )
                    })?;
                }
            }
            if let Some(ref mut all) = downgrade.all {
                for (idx, cond) in all.iter_mut().enumerate() {
                    cond.precompile_regexes().with_context(|| {
                        format!(
                            "in composite rule '{}' downgrade.all condition #{}",
                            self.id,
                            idx + 1
                        )
                    })?;
                }
            }
            if let Some(ref mut none) = downgrade.none {
                for (idx, cond) in none.iter_mut().enumerate() {
                    cond.precompile_regexes().with_context(|| {
                        format!(
                            "in composite rule '{}' downgrade.none condition #{}",
                            self.id,
                            idx + 1
                        )
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Pre-compile YARA rules in all conditions
    pub(crate) fn compile_yara(&mut self) {
        if let Some(ref mut conds) = self.all {
            for cond in conds.iter_mut() {
                cond.compile_yara();
            }
        }
        if let Some(ref mut conds) = self.any {
            for cond in conds.iter_mut() {
                cond.compile_yara();
            }
        }
        if let Some(ref mut conds) = self.unless {
            for cond in conds.iter_mut() {
                cond.compile_yara();
            }
        }
    }

    /// Composite traits carry no count/density filters, so raw/text matching in
    /// their conditions never needs the exact `match_count` (see `eval_raw`).
    pub(crate) fn needs_match_count(&self) -> bool {
        false
    }

    /// Evaluate this rule against the analysis context
    #[must_use]
    pub(crate) fn evaluate<'a>(&self, ctx: &EvaluationContext<'a>) -> Option<Finding> {
        use super::debug::{DowngradeDebug, ProximityDebug, SkipReason};

        // Composite traits have no count/density filter, so raw/text matching in
        // their conditions can stop at the first match. Restored on drop.
        let _mcg = MatchCountGuard::set(self.needs_match_count());

        // Check platform match
        let platform_match = super::types::platforms_intersect(&self.platforms, ctx.platforms);

        if !platform_match {
            ctx.record_skip(SkipReason::PlatformMismatch {
                rule: self.platforms.clone(),
                context: ctx.platforms.to_vec(),
            });
            return None;
        }

        // Check architecture match
        let arch_match = self.arch.contains(&Arch::All)
            || ctx.arch.contains(&Arch::All)
            || self.arch.iter().any(|a| ctx.arch.contains(a));

        if !arch_match {
            ctx.record_skip(SkipReason::ArchMismatch {
                rule: self.arch.clone(),
                context: ctx.arch.to_vec(),
            });
            return None;
        }

        // Check file type match.
        // Container-level evaluation may collapse archive parents to FileType::All.
        // In that case, allow only archive-family rules to match rather than treating
        // All as a universal wildcard for every script/source/binary rule.
        let wants_archive_family = self.r#for.iter().any(super::types::FileType::is_archive);
        // A composite scoped to the whole input (`outer`) or to the enclosing
        // archive (`archive`) explicitly intends to pool evidence across archive
        // entries, so it must be allowed to run at the container/archive level
        // even when its `for:` lists only leaf types (e.g. a browser-extension
        // rule `for: [javascript]` whose evidence is split across the CRX's
        // content script and its manifest/rules JSON). Without this, such a rule
        // would only ever evaluate on a single leaf and never see the pooled
        // cross-entry findings it was written for.
        let pools_across_archive = matches!(
            self.scope,
            Some(Scope::Outer | Scope::Archive | Scope::Package)
        );
        let file_type_match = self.r#for.contains(&FileType::All)
            || self.r#for.contains(&ctx.file_type)
            || ((ctx.file_type == FileType::All || ctx.file_type.is_archive())
                && (wants_archive_family || pools_across_archive));

        if !file_type_match {
            ctx.record_skip(SkipReason::FileTypeMismatch {
                rule: self.r#for.clone(),
                context: ctx.file_type,
            });
            return None;
        }

        // Check size constraints
        let file_size = ctx.report.target.size_bytes as usize;
        if let Some(min) = self.size_min
            && file_size < min
        {
            ctx.record_skip(SkipReason::SizeTooSmall {
                actual: file_size,
                min,
            });
            return None;
        }
        if let Some(max) = self.size_max
            && file_size > max
        {
            ctx.record_skip(SkipReason::SizeTooLarge {
                actual: file_size,
                max,
            });
            return None;
        }

        // Start timing for timeout detection (covers all evaluation phases)
        let start = Instant::now();

        // Check unless conditions (file-level skip)
        if let Some(unless_conds) = &self.unless {
            // Default 'any' semantics: skip if ANY condition matches
            for condition in unless_conds {
                let result = self.eval_condition(condition, ctx);
                if result.matched {
                    // For a directory-prefix unless (e.g. `metadata/binary/resource/`),
                    // the bare pattern alone is rarely actionable — surface the concrete
                    // trait(s) that actually matched the prefix so `test-rules` names the
                    // real suppressor instead of echoing the prefix back.
                    let concrete = if result.matched_trait_ids.is_empty() {
                        String::new()
                    } else {
                        format!(" [matched: {}]", result.matched_trait_ids.join(", "))
                    };
                    ctx.record_skip(SkipReason::UnlessConditionMatched {
                        condition_desc: format!("{:?}{}", condition, concrete),
                    });
                    return None;
                }
            }
        }

        // Evaluate positive conditions based on the boolean operator(s)
        let (positive_result, proximity_tags) = match (&self.all, &self.any) {
            (Some(all), Some(any)) => {
                // Both all AND any: all must match AND any must match (respecting `needs`)
                let (all_result, all_tags) = self.eval_requires_all(all, ctx);
                if !all_result.matched {
                    return None;
                }
                let (any_result, any_tags) = if let Some(required_count) = self.needs {
                    self.eval_count_constraints(any, None, Some(required_count), None, ctx)
                } else {
                    self.eval_requires_any(any, ctx)
                }; // both branches return (ConditionResult, Vec<TaggedLocation>)
                if !any_result.matched {
                    return None;
                }
                // Merge tags, offsetting any-condition indices past all-conditions
                let all_count = all.len();
                let mut tags = all_tags;
                for mut t in any_tags {
                    t.condition_index += all_count;
                    tags.push(t);
                }
                // Combine evidence and trait IDs from both (limited to MAX_EVIDENCE_PER_TRAIT)
                let mut combined_evidence = all_result.evidence;
                combined_evidence.extend(any_result.evidence);
                let combined_evidence = deduplicate_evidence(combined_evidence);
                let match_count = combined_evidence.len();
                let mut combined_evidence = combined_evidence;
                combined_evidence.truncate(MAX_EVIDENCE_PER_TRAIT);
                let mut combined_trait_ids = all_result.matched_trait_ids;
                combined_trait_ids.extend(any_result.matched_trait_ids);
                (
                    ConditionResult {
                        matched: true,
                        evidence: combined_evidence,
                        match_count,
                        warnings: Vec::new(),
                        precision: 0.0,
                        matched_trait_ids: combined_trait_ids,
                    },
                    tags,
                )
            }
            (Some(conds), None) => self.eval_requires_all(conds, ctx),
            (None, Some(conds)) => {
                if let Some(required_count) = self.needs {
                    self.eval_count_constraints(conds, None, Some(required_count), None, ctx)
                } else {
                    self.eval_requires_any(conds, ctx)
                }
            }
            (None, None) => {
                // No positive conditions - invalid rule
                return None;
            }
        };

        if !positive_result.matched {
            return None;
        }

        let mut result = positive_result;

        // Apply scope filter (e.g. `scope: leaf` for archive-FP suppression).
        // When the filter rejects all scope buckets, the rule does not fire.
        let proximity_tags = match self.apply_scope_filter(result.evidence, proximity_tags) {
            Some((ev, tags)) => {
                result.evidence = ev;
                tags
            }
            None => return None,
        };

        if result.matched {
            // Check proximity constraints (near_lines, near_bytes)
            let proximity_result = self.check_proximity_constraints(
                result.evidence.clone(),
                &proximity_tags,
                ctx.binary_data,
            );

            // Record proximity debug if applicable
            if self.near_lines.is_some() || self.near_bytes.is_some() {
                let constraint_type = if self.near_lines.is_some() {
                    "near_lines"
                } else {
                    "near_bytes"
                };
                let max_span = self.near_lines.or(self.near_bytes).unwrap_or(0);
                let satisfied = proximity_result.is_some();
                ctx.with_debug(|debug| {
                    debug.set_proximity(ProximityDebug {
                        constraint_type: constraint_type.to_string(),
                        max_span,
                        satisfied,
                    });
                });
            }

            let evidence = proximity_result?;

            // Boost precision if proximity constraints were applied
            let mut precision_boost = 0.0;
            if self.near_lines.is_some() || self.near_bytes.is_some() {
                precision_boost = 1.0;
            }

            let mut final_crit = self.crit;

            // Check downgrade conditions
            if let Some(downgrade_conds) = &self.downgrade {
                let triggered = self.eval_downgrade_conditions(downgrade_conds, ctx);
                if triggered {
                    final_crit = downgrade_crit(self.crit);
                }

                // Record downgrade debug
                ctx.with_debug(|debug| {
                    debug.set_downgrade(DowngradeDebug {
                        original_crit: self.crit,
                        final_crit,
                        triggered,
                    });
                });
            }

            // Record match in debug collector
            let final_precision = result.precision + precision_boost;
            ctx.with_debug(|debug| {
                debug.matched = true;
                debug.precision = final_precision;
            });

            // Check for timeout violations before returning
            let duration = start.elapsed();
            if duration > MAX_RULE_EVAL_DURATION {
                eprintln!(
                    "WARN: Composite rule {} exceeded timeout: {}ms > {}ms",
                    self.id,
                    duration.as_millis(),
                    MAX_RULE_EVAL_DURATION.as_millis()
                );

                return Some(Finding {
                    src: None,
                    id: "objectives/anti-analysis/analysis-bomb/rule-timeout".to_string(),
                    desc: format!(
                        "Composite rule evaluation timeout: {} took {}ms (limit: {}ms)",
                        self.id,
                        duration.as_millis(),
                        MAX_RULE_EVAL_DURATION.as_millis()
                    ),
                    crit: Criticality::Suspicious,
                    kind: FindingKind::Indicator,
                    conf: 0.9,
                    mbc: Some("B0003.005".to_string()), // Obfuscated Files or Information: Analysis Evasion
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![crate::types::Evidence {
                        method: "timeout-detection".to_string(),
                        source: "cleave-evaluator".to_string(),
                        value: format!(
                            "Composite rule '{}' exceeded {}ms timeout, took {}ms",
                            self.id,
                            MAX_RULE_EVAL_DURATION.as_millis(),
                            duration.as_millis()
                        ),
                        location: Some("0x0".to_string()),
                        ..Default::default()
                    }],
                    match_count: 0,
                    source_file: get_relative_source_file(&self.defined_in),
                });
            }

            Some(Finding {
                src: None,
                id: self.id.clone(),
                kind: FindingKind::Capability,
                desc: self.desc.clone(),
                conf: self.conf,
                crit: final_crit,
                mbc: self.mbc.clone(),
                attack: self.attack.clone(),
                trait_refs: result.matched_trait_ids.clone(),
                evidence,
                match_count: 0, // not meaningful for composites
                source_file: get_relative_source_file(&self.defined_in),
            })
        } else {
            None
        }
    }

    /// Evaluate downgrade conditions and return final criticality.
    /// Public so that mapper can re-evaluate downgrades after all findings are collected.
    /// When matched, drops one level: hostile→suspicious→notable→baseline
    #[must_use]
    pub(crate) fn evaluate_downgrade<'a>(
        &self,
        conditions: &DowngradeConditions,
        base_crit: &Criticality,
        ctx: &EvaluationContext<'a>,
    ) -> Criticality {
        if self.eval_downgrade_conditions(conditions, ctx) {
            return downgrade_crit(*base_crit);
        }
        *base_crit
    }

    /// Evaluate a single downgrade condition set.
    /// All specified blocks (all/any/none) must pass for the downgrade to trigger.
    fn eval_downgrade_conditions<'a>(
        &self,
        conditions: &DowngradeConditions,
        ctx: &EvaluationContext<'a>,
    ) -> bool {
        let mut has_any_block = false;

        // If 'all' is specified, every condition must match
        if let Some(all_conds) = &conditions.all {
            has_any_block = true;
            for cond in all_conds {
                if !self.eval_condition(cond, ctx).matched {
                    return false;
                }
            }
        }

        // If 'any' is specified, at least `needs` conditions must match (default 1)
        if let Some(any_conds) = &conditions.any {
            has_any_block = true;
            let threshold = conditions.needs.unwrap_or(1);
            let mut matched_count = 0;
            for cond in any_conds {
                let result = self.eval_condition(cond, ctx);
                matched_count += condition_count_weight(cond, &result);
            }
            if matched_count < threshold {
                return false;
            }
        }

        // If 'none' is specified, none may match
        if let Some(none_conds) = &conditions.none {
            has_any_block = true;
            for cond in none_conds {
                if self.eval_condition(cond, ctx).matched {
                    return false;
                }
            }
        }

        has_any_block
    }

    /// Evaluate ALL conditions must match (AND)
    /// Returns (result, tagged_locations) where tagged_locations maps evidence to condition indices.
    fn eval_requires_all<'a>(
        &self,
        conds: &[Condition],
        ctx: &EvaluationContext<'a>,
    ) -> (ConditionResult, Vec<TaggedLocation>) {
        let mut all_evidence = Vec::new();
        let mut total_precision = 0.0f32;
        let mut all_trait_ids = Vec::new();
        let mut tags = Vec::new();

        for (i, condition) in conds.iter().enumerate() {
            let result = self.eval_condition(condition, ctx);
            if !result.matched {
                return (ConditionResult::no_match(), Vec::new());
            }
            // Tag evidence locations before merging
            tags.extend(tag_evidence(&result.evidence, i));
            // Limit evidence to prevent explosion
            if all_evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                let remaining = MAX_EVIDENCE_PER_TRAIT - all_evidence.len();
                all_evidence.extend(result.evidence.into_iter().take(remaining));
            }
            all_trait_ids.extend(result.matched_trait_ids);
            total_precision += result.precision; // SUM for 'all'
        }

        // Deduplicate evidence before returning
        let all_evidence = deduplicate_evidence(all_evidence);
        let match_count = all_evidence.len();
        (
            ConditionResult {
                matched: true,
                evidence: all_evidence,
                match_count,
                warnings: Vec::new(),
                precision: total_precision,
                matched_trait_ids: all_trait_ids,
            },
            tags,
        )
    }

    /// Evaluate at least ONE condition must match (OR)
    /// Collects evidence from ALL matching conditions, not just the first.
    /// Returns (result, tagged_locations) where tagged_locations maps evidence to condition indices.
    fn eval_requires_any<'a>(
        &self,
        conds: &[Condition],
        ctx: &EvaluationContext<'a>,
    ) -> (ConditionResult, Vec<TaggedLocation>) {
        let mut any_matched = false;
        let mut all_evidence = Vec::new();
        let mut all_trait_ids = Vec::new();
        let mut min_precision = f32::MAX;
        let mut tags = Vec::new();

        for (i, condition) in conds.iter().enumerate() {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                any_matched = true;
                // Tag evidence locations before merging
                tags.extend(tag_evidence(&result.evidence, i));
                // Limit evidence to prevent explosion
                if all_evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    let remaining = MAX_EVIDENCE_PER_TRAIT - all_evidence.len();
                    all_evidence.extend(result.evidence.into_iter().take(remaining));
                }
                all_trait_ids.extend(result.matched_trait_ids);
                min_precision = min_precision.min(result.precision); // MIN for 'any'
            }
        }

        let precision = if any_matched { min_precision } else { 0.0 };

        // Deduplicate evidence before returning
        let all_evidence = deduplicate_evidence(all_evidence);
        let match_count = all_evidence.len();
        (
            ConditionResult {
                matched: any_matched,
                evidence: all_evidence,
                match_count,
                warnings: Vec::new(),
                precision,
                matched_trait_ids: all_trait_ids,
            },
            tags,
        )
    }

    /// Evaluate with count constraints: exact count, min_count, max_count.
    /// Returns (result, tagged_locations) where tagged_locations maps evidence to condition indices.
    fn eval_count_constraints<'a>(
        &self,
        conds: &[Condition],
        exact: Option<usize>,
        min: Option<usize>,
        max: Option<usize>,
        ctx: &EvaluationContext<'a>,
    ) -> (ConditionResult, Vec<TaggedLocation>) {
        let mut matched_count = 0;
        let mut all_evidence = Vec::new();
        let mut all_trait_ids = Vec::new();
        let mut precision_sum = 0.0f32;
        let mut tags = Vec::new();

        for (i, condition) in conds.iter().enumerate() {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                let count_weight = condition_count_weight(condition, &result);
                matched_count += count_weight;
                // Tag evidence locations before merging
                tags.extend(tag_evidence(&result.evidence, i));
                // Limit evidence to prevent explosion
                if all_evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    let remaining = MAX_EVIDENCE_PER_TRAIT - all_evidence.len();
                    all_evidence.extend(result.evidence.into_iter().take(remaining));
                }
                all_trait_ids.extend(result.matched_trait_ids);
                precision_sum += result.precision * count_weight as f32;
            }
        }

        let matched = if let Some(exact_count) = exact {
            // Exact match required
            matched_count == exact_count
        } else {
            // Range check
            let min_ok = min.is_none_or(|m| matched_count >= m);
            let max_ok = max.is_none_or(|m| matched_count <= m);
            min_ok && max_ok
        };

        // Calculate precision: average + 0.5 bonus for count constraint
        let avg_precision = if matched_count > 0 {
            (precision_sum / matched_count as f32) + 0.5 // +0.5 bonus for count constraint
        } else {
            0.0
        };

        // Deduplicate evidence before returning
        let all_evidence = deduplicate_evidence(all_evidence);
        let evidence_for_result = if matched { all_evidence } else { Vec::new() };
        let match_count_for_result = evidence_for_result.len();
        (
            ConditionResult {
                matched,
                evidence: evidence_for_result,
                match_count: match_count_for_result,
                warnings: Vec::new(),
                precision: avg_precision,
                matched_trait_ids: if matched { all_trait_ids } else { Vec::new() },
            },
            if matched { tags } else { Vec::new() },
        )
    }

    /// Evaluate a single condition
    fn eval_condition<'a>(
        &self,
        condition: &Condition,
        ctx: &EvaluationContext<'a>,
    ) -> ConditionResult {
        let arch_clamp = ctx.arch_clamp_range(&self.arch);

        match condition {
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
            }) => {
                let merged_not = merge_not_exceptions(not.as_ref(), self.not.as_ref());
                use crate::composite_rules::condition::SymbolKind;
                match kind {
                    Some(SymbolKind::Call) => {
                        crate::composite_rules::evaluators::symbol_string::eval_call(
                            exact.as_ref(),
                            substr.as_ref(),
                            regex.as_ref(),
                            arg.as_ref(),
                            args.as_deref(),
                            ctx,
                        )
                    }
                    Some(
                        fact_kind
                        @ (SymbolKind::Member | SymbolKind::Bind | SymbolKind::Identifier),
                    ) => crate::composite_rules::evaluators::symbol_string::eval_symbol_fact(
                        *fact_kind,
                        exact.as_ref(),
                        substr.as_ref(),
                        regex.as_ref(),
                        ctx,
                    ),
                    _ => self.eval_symbol(
                        exact.as_ref(),
                        substr.as_ref(),
                        regex.as_ref(),
                        platforms.as_ref(),
                        *is_check,
                        *kind,
                        merged_not.as_ref(),
                        alias.as_ref(),
                        ctx,
                    ),
                }
            }
            Condition::Text(TextQuery {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
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
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
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
                let merged_not = merge_not_exceptions(not.as_ref(), self.not.as_ref());
                eval_text(&params, merged_not.as_ref(), ctx, Some(self.id.as_str()))
            }
            Condition::Comment(CommentQuery {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not: _,
                platforms: _,
            }) => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    is_check: *is_check,
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    arch_clamp,
                };
                crate::composite_rules::evaluators::symbol_string::eval_comment(
                    &params,
                    self.not.as_ref(),
                    ctx,
                )
            }
            Condition::Literal(LiteralQuery {
                kind: _,
                exact,
                substr,
                regex,
                word,
                value: _,
                radix: _,
                case_insensitive,
                is_check,
                not: _,
                platforms: _,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            }) => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    is_check: *is_check,
                    section: section.as_ref(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                    arch_clamp,
                };
                eval_string_literal(&params, self.not.as_ref(), ctx)
            }
            Condition::Trait { id } => eval_trait(id, ctx),
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
            Condition::Syscall { name, number, arch } => {
                timed_eval!(
                    "syscall",
                    eval_syscall(name.as_ref(), number.as_ref(), arch.as_ref(), ctx)
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
                not: _,
                offset,
                offset_range,
                section,
                section_offset,
                section_offset_range,
            }) => timed_eval!(
                "hex",
                eval_hex(
                    pattern,
                    &ContentLocationParams {
                        section: section.clone(),
                        offset: *offset,
                        offset_range: *offset_range,
                        section_offset: *section_offset,
                        section_offset_range: *section_offset_range,
                        arch_clamp,
                    },
                    ctx,
                    Some(self.id.as_str()),
                )
            ),
            Condition::Raw(RawQuery {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not: _,
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
                    "raw",
                    eval_raw(
                        exact.as_ref(),
                        substr.as_ref(),
                        regex.as_ref(),
                        word.as_ref(),
                        *case_insensitive,
                        *is_check,
                        self.not.as_ref(),
                        &location,
                        ctx,
                        Some(self.id.as_str()),
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
                        exact.as_ref(),
                        substr.as_ref(),
                        regex.as_ref(),
                        word.as_ref(),
                        *case_insensitive,
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
            Condition::Kv(KvQuery { .. }) => {
                timed_eval!("value", {
                    // Delegate to value evaluator with caching
                    if let Some(evidence) = super::evaluators::evaluate_kv(condition, ctx) {
                        ConditionResult::matched_with(vec![evidence])
                    } else {
                        ConditionResult::no_match()
                    }
                })
            }
        }
    }

    /// Evaluate symbol condition
    #[allow(clippy::too_many_arguments)]
    fn eval_symbol<'a>(
        &self,
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
        // Check platform constraint
        // Match if: trait allows All platforms, OR context includes All (no --platforms filter),
        // OR trait's platforms intersect with context's platforms
        if let Some(plats) = platforms {
            let platform_match = super::types::platforms_intersect(plats, ctx.platforms);
            if !platform_match {
                return ConditionResult::no_match();
            }
        }

        eval_symbol(
            exact, substr, pattern, None, is_check, kind, not, alias, ctx,
        )
    }

    /// Number of distinct conditions a co-occurrence check (scope, proximity)
    /// must see represented before the rule is allowed to fire. Used by
    /// both [`Self::apply_scope_filter`] and proximity checks.
    fn min_distinct_conditions(&self) -> usize {
        let all_count = self.all.as_ref().map_or(0, Vec::len);
        let any_required = if let Some(any) = &self.any {
            // Cap at the number of `any:` entries. A single entry (e.g. a
            // directory-prefix reference) can satisfy a higher `needs:` through
            // multiple matched member traits, but every one of those matches
            // carries the *same* condition index. Scope/proximity filters count
            // distinct condition indices, so requiring more distinct conditions
            // than there are entries is unsatisfiable and would wrongly drop the
            // finding (e.g. `any: [dir-ref]` + `needs: 2`).
            self.needs.unwrap_or(1).min(any.len())
        } else {
            0
        };
        all_count + any_required
    }

    /// Restrict evidence to a single scope bucket, per the rule's
    /// `scope:` field.
    ///
    /// Each piece of evidence is keyed by [`Scope::key`] applied to its
    /// `Evidence.location`. Two evidence items share scope iff their keys
    /// are equal. The filter chooses the first scope key whose tagged
    /// evidence covers enough distinct condition indices to satisfy the
    /// rule's positive structure (`all` + `needs`-of-`any`), and drops
    /// every evidence item from other scope buckets.
    ///
    /// Returns `None` if no single scope bucket meets the rule's
    /// minimum-distinct-conditions threshold; otherwise returns the
    /// filtered (`evidence`, `tagged_locations`) pair.
    ///
    /// `Scope::Outer` is a no-op fast path: every key is the empty
    /// string, so all evidence is in one bucket.
    fn apply_scope_filter(
        &self,
        evidence: Vec<Evidence>,
        tagged_locations: Vec<TaggedLocation>,
    ) -> Option<(Vec<Evidence>, Vec<TaggedLocation>)> {
        let scope = self.scope.unwrap_or_default();
        if matches!(scope, Scope::Outer | Scope::Package) {
            // Both pool by presence (empty key) — every item is in one bucket.
            return Some((evidence, tagged_locations));
        }
        let min_distinct = self.min_distinct_conditions();
        if min_distinct == 0 {
            // Vacuous rule (no positive conditions) — scope is moot.
            return Some((evidence, tagged_locations));
        }
        // Collect the unique scope keys appearing in tagged_locations,
        // then for each key count how many distinct condition indices
        // it covers. The first key meeting the threshold wins.
        // BTreeSet for deterministic iteration order — useful for
        // tests and reproducibility.
        let unique_keys: std::collections::BTreeSet<&str> = tagged_locations
            .iter()
            .map(|t| scope.key(t.location.as_deref()))
            .collect();

        if unique_keys.iter().all(|k| k.is_empty()) {
            // No location info to bucket on — every tag's scope key is
            // empty (e.g. evidence from metric-derived findings, or
            // AST/positional-only matches that don't carry a file
            // path). Scope can't meaningfully filter, so pass through
            // rather than reject.
            return Some((evidence, tagged_locations));
        }

        let winning_key = unique_keys
            .into_iter()
            .find(|key| {
                let conds: std::collections::BTreeSet<usize> = tagged_locations
                    .iter()
                    .filter(|t| scope.key(t.location.as_deref()) == *key)
                    .map(|t| t.condition_index)
                    .collect();
                conds.len() >= min_distinct
            })?
            .to_string();

        let filtered_tags: Vec<TaggedLocation> = tagged_locations
            .into_iter()
            .filter(|t| scope.key(t.location.as_deref()) == winning_key)
            .collect();
        let filtered_evidence: Vec<Evidence> = evidence
            .into_iter()
            .filter(|ev| scope.key(ev.location.as_deref()) == winning_key)
            .collect();
        Some((filtered_evidence, filtered_tags))
    }

    /// Check if evidence satisfies proximity constraints.
    /// Returns None if constraints fail, otherwise returns the evidence unchanged.
    ///
    /// When `tagged_locations` is non-empty, proximity requires that a window contains
    /// evidence from distinct conditions (cross-condition proximity). When empty,
    /// falls back to counting individual evidence items.
    fn check_proximity_constraints(
        &self,
        evidence: Vec<Evidence>,
        tagged_locations: &[TaggedLocation],
        binary_data: &[u8],
    ) -> Option<Vec<Evidence>> {
        if self.near_lines.is_none() && self.near_bytes.is_none() {
            return Some(evidence);
        }

        // Proximity needs at least 2 distinct conditions to be meaningful
        // — a single item is vacuously close to itself. (Scope uses the
        // same count without the `.max(2)` floor.)
        let min_distinct = self.min_distinct_conditions().max(2);

        // Track the winning window range for evidence filtering
        let mut line_window: Option<(usize, usize)> = None;
        let mut byte_window: Option<(u64, u64)> = None;
        let mut line_starts_cache: Option<Vec<usize>> = None;

        if !tagged_locations.is_empty() {
            // Cross-condition proximity: require distinct condition indices in window
            if let Some(max_line_span) = self.near_lines {
                let line_starts = build_line_index(binary_data);
                let items: Vec<(usize, usize)> = tagged_locations
                    .iter()
                    .filter_map(|t| {
                        tagged_to_line(t, &line_starts).map(|line| (line, t.condition_index))
                    })
                    .collect();
                match evidence_within_line_range_grouped(&items, max_line_span, min_distinct) {
                    Some(window) => line_window = Some(window),
                    None => return None,
                }
                line_starts_cache = Some(line_starts);
            }

            if let Some(max_byte_span) = self.near_bytes {
                let items: Vec<(u64, usize)> = tagged_locations
                    .iter()
                    .filter_map(|t| tagged_to_byte_offset(t).map(|off| (off, t.condition_index)))
                    .collect();
                match evidence_within_byte_range_grouped(&items, max_byte_span, min_distinct) {
                    Some(window) => byte_window = Some(window),
                    None => return None,
                }
            }
        } else {
            // Fallback: no condition tags (shouldn't happen for composites, but safe default)
            if let Some(max_line_span) = self.near_lines {
                let line_starts = build_line_index(binary_data);
                match evidence_within_line_range(
                    &evidence,
                    max_line_span,
                    min_distinct,
                    &line_starts,
                ) {
                    Some(window) => line_window = Some(window),
                    None => return None,
                }
                line_starts_cache = Some(line_starts);
            }

            if let Some(max_byte_span) = self.near_bytes {
                match evidence_within_byte_range(&evidence, max_byte_span, min_distinct) {
                    Some(window) => byte_window = Some(window),
                    None => return None,
                }
            }
        }

        // Filter evidence to only items within the winning proximity window
        let filtered: Vec<Evidence> = evidence
            .into_iter()
            .filter(|ev| {
                if let (Some((start, end)), Some(ls)) = (line_window, &line_starts_cache)
                    && let Some(line) = evidence_to_line(ev, ls)
                {
                    return line >= start && line <= end;
                }
                if let Some((start, end)) = byte_window
                    && let Some(offset) = evidence_to_byte_offset(ev)
                {
                    return offset >= start && offset <= end;
                }
                // Evidence without location info: keep (e.g., exclusion sentinels from none:)
                true
            })
            .collect();

        Some(filtered)
    }

    /// Returns true if this rule has unless (skip) conditions
    #[must_use]
    pub(crate) fn has_negative_conditions(&self) -> bool {
        self.unless.as_ref().map(|n| !n.is_empty()).unwrap_or(false)
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
fn tag_evidence(evidence: &[Evidence], condition_index: usize) -> Vec<TaggedLocation> {
    evidence
        .iter()
        .map(|ev| TaggedLocation {
            byte_offset: ev.offsets.first().copied(),
            location: ev.location.clone(),
            condition_index,
        })
        .collect()
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

/// Returns the (start_line, end_line) of the first qualifying window, or None.
fn evidence_within_line_range_grouped(
    items: &[(usize, usize)], // (line_number, condition_index)
    max_line_span: usize,
    min_distinct: usize,
) -> Option<(usize, usize)> {
    if items.len() < min_distinct {
        return None;
    }

    let mut sorted: SmallVec<[(usize, usize); MAX_EVIDENCE_PER_TRAIT]> = items.into();
    sorted.sort_unstable_by_key(|&(line, _)| line);

    // Sliding window: find any window of max_line_span with min_distinct condition indices
    for (i, &(start_line, _)) in sorted.iter().enumerate() {
        let mut seen = rustc_hash::FxHashSet::default();
        for &(line, cond_idx) in &sorted[i..] {
            if line - start_line <= max_line_span {
                seen.insert(cond_idx);
                if seen.len() >= min_distinct {
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
    min_distinct: usize,
) -> Option<(u64, u64)> {
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
                if seen.len() >= min_distinct {
                    return Some((start, offset));
                }
            } else {
                break;
            }
        }
    }

    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod scope_tests {
    //! Unit tests for the composite-rule `scope:` field.
    //!
    //! Two layers are exercised:
    //!
    //! 1. [`Scope::key`] — pure function; covers every value × every
    //!    `Evidence.location` shape cleave produces today.
    //! 2. [`CompositeTrait::apply_scope_filter`] — given fixture
    //!    evidence + tagged_locations, asserts which scope bucket the
    //!    filter selects and that evidence outside that bucket is
    //!    dropped.

    use super::*;

    fn tag(condition_index: usize, location: &str) -> TaggedLocation {
        TaggedLocation {
            byte_offset: None,
            location: Some(location.to_string()),
            condition_index,
        }
    }

    fn ev(location: &str) -> Evidence {
        Evidence {
            method: "test".to_string(),
            source: String::new(),
            value: String::new(),
            location: Some(location.to_string()),
            offsets: Vec::new(),
            count: 0,
            match_len: None,
            alt_value: None,
        }
    }

    /// Build a minimal CompositeTrait fixture for filter tests. The
    /// dummy `all:` slot of length `n_conditions` ensures
    /// `min_distinct_conditions()` returns `n_conditions`.
    fn composite_with(n_conditions: usize, scope: Option<Scope>) -> CompositeTrait {
        let conds = (0..n_conditions)
            .map(|_| {
                Condition::Symbol(SymbolQuery {
                    exact: Some("x".to_string()),
                    substr: None,
                    regex: None,
                    platforms: None,
                    is_check: None,
                    kind: None,
                    arg: None,
                    args: None,
                    alias: None,
                    not: None,
                })
            })
            .collect();
        CompositeTrait {
            id: "t".to_string(),
            desc: String::new(),
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            platforms: default_platforms(),
            arch: default_architectures(),
            r#for: default_file_types(),
            for_from_groups: false,
            size_min: None,
            size_max: None,
            all: Some(conds),
            any: None,
            needs: None,
            near_lines: None,
            near_bytes: None,
            scope,
            unless: None,
            not: None,
            downgrade: None,
            defined_in: std::path::PathBuf::new(),
            precision: None,
            required_trait_indices: Vec::new(),
            ..Default::default()
        }
    }

    // ----- Scope::key -------------------------------------------------------

    #[test]
    fn outer_collapses_every_location_to_empty_string() {
        for loc in [
            None,
            Some("archive:foo.zip!bar.so"),
            Some("encoding_chain:base64+zlib"),
            Some("0x1234"),
        ] {
            assert_eq!(Scope::Outer.key(loc), "");
        }
    }

    #[test]
    fn package_collapses_every_location_to_empty_string() {
        // Package pools by presence, exactly like Outer — the artifact↔registry
        // boundary it spans is two separate analyses with no shared location.
        for loc in [
            None,
            Some("archive:foo.zip!bar.so"),
            Some("encoding_chain:base64+zlib"),
            Some("0x1234"),
        ] {
            assert_eq!(Scope::Package.key(loc), "");
        }
    }

    #[test]
    fn package_scope_round_trips_through_yaml() {
        // `scope: package` parses via the serde rename, alongside the other
        // variants, and serializes back to the same lowercase token.
        let scope: Scope = serde_yaml::from_str("package").expect("parse scope");
        assert_eq!(scope, Scope::Package);
        let token = serde_yaml::to_string(&Scope::Package).expect("serialize scope");
        assert_eq!(token.trim(), "package");
    }

    #[test]
    fn leaf_returns_exact_location() {
        assert_eq!(Scope::Leaf.key(None), "");
        assert_eq!(Scope::Leaf.key(Some("archive:foo.so")), "archive:foo.so");
        assert_eq!(
            Scope::Leaf.key(Some("encoding_chain:base64+zlib")),
            "encoding_chain:base64+zlib"
        );
    }

    #[test]
    fn leaf_collapses_byte_offset_locations_to_containing_unit() {
        // Byte offsets identify where evidence was found inside the
        // leaf; they are not separate analysis-tree leaves.
        assert_eq!(Scope::Leaf.key(Some("0x10")), "");
        assert_eq!(Scope::Leaf.key(Some("offset:16")), "");
        assert_eq!(
            Scope::Leaf.key(Some("archive:pkg.zip!bin/payload:0x10")),
            "archive:pkg.zip!bin/payload"
        );
        assert_eq!(
            Scope::Leaf.key(Some("archive:pkg.zip!bin/payload:offset:16")),
            "archive:pkg.zip!bin/payload"
        );
    }

    #[test]
    fn file_keeps_archive_path_drops_decoded_layers() {
        // Archive entry: file-level == leaf-level.
        assert_eq!(Scope::File.key(Some("archive:foo.so")), "archive:foo.so");
        assert_eq!(
            Scope::File.key(Some("archive:foo.so:0x10")),
            "archive:foo.so"
        );
        // Encoded payloads collapse to the input-wide key.
        assert_eq!(Scope::File.key(Some("encoding_chain:base64+zlib")), "");
        assert_eq!(Scope::File.key(None), "");
    }

    #[test]
    fn file_collapses_positional_only_locations() {
        // AST evidence carries pure "row:col" strings. Under
        // `scope: file` these must collapse to the input-wide key so
        // AST evidence pools with text/symbol/encoded evidence in
        // the same analyzed unit. Regression for the bug where every
        // AST match landed in its own bucket and composites with
        // `scope: file` never satisfied `min_distinct_conditions`.
        assert_eq!(Scope::File.key(Some("6:14")), "");
        assert_eq!(Scope::File.key(Some("1:1")), "");
        assert_eq!(Scope::File.key(Some("123:456")), "");
        // Three-coord form (some evaluators may extend with a third
        // numeric coordinate) also collapses.
        assert_eq!(Scope::File.key(Some("7:1:42")), "");
    }

    #[test]
    fn file_keeps_file_prefixed_locations() {
        // Anything that carries actual file identity (path + position
        // or just a path) must be preserved so two unrelated files in
        // an archive don't get pooled. Only the empty/positional/decoded
        // cases collapse.
        assert_eq!(
            Scope::File.key(Some("Analytics.php:10:5")),
            "Analytics.php:10:5"
        );
        assert_eq!(
            Scope::File.key(Some("src/main.rs:42:1")),
            "src/main.rs:42:1"
        );
        assert_eq!(Scope::File.key(Some("file:foo")), "file:foo");
        // Edge cases that look numeric but aren't `row:col`.
        assert_eq!(Scope::File.key(Some("1:")), "1:");
        assert_eq!(Scope::File.key(Some(":")), ":");
        assert_eq!(Scope::File.key(Some("1:abc")), "1:abc");
        assert_eq!(Scope::File.key(Some("abc:1")), "abc:1");
        assert_eq!(Scope::File.key(Some("")), "");
    }

    #[test]
    fn file_pools_embedded_code_findings_in_same_parent() {
        // Embedded-code findings (shell extracted from a Dockerfile
        // RUN block, a YAML `run:` step, etc.) prefix evidence
        // locations with `embedded@<parent-offset>:<inner>`. Under
        // `scope: file`, all such evidence within the same parent
        // file must pool — otherwise composites like
        // `chmod-arms-hidden-stage` and `stealth-fetch-hidden-stage`
        // never fire on Dockerfile/GitHub Actions fixtures where
        // each shell command lands in its own extracted snippet.
        assert_eq!(Scope::File.key(Some("embedded@0x3f:1:5")), "");
        assert_eq!(Scope::File.key(Some("embedded@0xd2:2:10")), "");
        // Offset-only inner location (no row:col).
        assert_eq!(Scope::File.key(Some("embedded@0x3f:0x10")), "");
        // Older `embedded:<kind>@<offset>` form (used by base64 binary
        // payload detection and office/ole extractors) also pools.
        assert_eq!(Scope::File.key(Some("embedded:base64@0x100")), "");
    }

    #[test]
    fn embedded_parent_offsets_map_to_parent_lines() {
        let line_starts = build_line_index(b"zero\none\ntwo\n");

        let embedded = ev("embedded@0x6:unknown");
        assert_eq!(evidence_to_byte_offset(&embedded), Some(0x6));
        assert_eq!(evidence_to_line(&embedded, &line_starts), Some(2));

        let legacy = ev("embedded:shell@0xb:1:5");
        assert_eq!(evidence_to_byte_offset(&legacy), Some(0xb));
        assert_eq!(evidence_to_line(&legacy, &line_starts), Some(3));

        let tagged = tag(0, "embedded@0x6:unknown");
        assert_eq!(tagged_to_line(&tagged, &line_starts), Some(2));
        assert_eq!(tagged_to_byte_offset(&tagged), Some(0x6));
    }

    #[test]
    fn near_lines_accepts_embedded_findings_in_same_parent_window() {
        let mut rule = composite_with(2, None);
        rule.near_lines = Some(1);

        let evidence = vec![ev("embedded@0x1:unknown"), ev("embedded@0x6:unknown")];
        let tags = vec![
            tag(0, "embedded@0x1:unknown"),
            tag(1, "embedded@0x6:unknown"),
        ];

        let filtered = rule
            .check_proximity_constraints(evidence, &tags, b"aaaa\nbbbb\ncccc\n")
            .expect("embedded findings are on adjacent parent lines");
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn near_lines_rejects_embedded_findings_outside_parent_window() {
        let mut rule = composite_with(2, None);
        rule.near_lines = Some(1);

        let evidence = vec![ev("embedded@0x1:unknown"), ev("embedded@0xb:unknown")];
        let tags = vec![
            tag(0, "embedded@0x1:unknown"),
            tag(1, "embedded@0xb:unknown"),
        ];

        assert!(
            rule.check_proximity_constraints(evidence, &tags, b"aaaa\nbbbb\ncccc\n")
                .is_none()
        );
    }

    #[test]
    fn leaf_does_not_collapse_positional_locations() {
        // `scope: leaf` is the strictest scope — every evidence must
        // share the EXACT location. We must NOT widen leaf semantics
        // when fixing the file-scope bug.
        assert_eq!(Scope::Leaf.key(Some("6:14")), "6:14");
        assert_eq!(Scope::Leaf.key(Some("7:1")), "7:1");
        assert_eq!(
            Scope::Leaf.key(Some("Analytics.php:10:5")),
            "Analytics.php:10:5"
        );
    }

    #[test]
    fn is_positional_only_edge_cases() {
        // Two-component all-digit forms are positional.
        assert!(is_positional_only("1:2"));
        assert!(is_positional_only("0:0"));
        assert!(is_positional_only("123:456"));
        // Trailing components are tolerated as long as the first two
        // are all-digit.
        assert!(is_positional_only("1:2:3"));
        assert!(is_positional_only("10:20:trailing"));
        // Anything with a non-digit component in the first or second
        // position is not positional-only.
        assert!(!is_positional_only(""));
        assert!(!is_positional_only(":"));
        assert!(!is_positional_only("1:"));
        assert!(!is_positional_only(":1"));
        assert!(!is_positional_only("1:abc"));
        assert!(!is_positional_only("abc:1"));
        assert!(!is_positional_only("Analytics.php:10:5"));
        assert!(!is_positional_only("archive:foo.zip"));
        assert!(!is_positional_only("encoding_chain:base64"));
    }

    #[test]
    fn archive_returns_parent_archive_for_nested() {
        assert_eq!(
            Scope::Archive.key(Some("archive:outer.zip!inner.zip!bar.so")),
            "archive:outer.zip!inner.zip"
        );
        assert_eq!(
            Scope::Archive.key(Some("archive:outer.zip!bar.so")),
            "archive:outer.zip"
        );
    }

    #[test]
    fn archive_returns_bare_prefix_for_single_level() {
        assert_eq!(Scope::Archive.key(Some("archive:foo.so")), "archive:");
        assert_eq!(Scope::Archive.key(Some("archive:bar.so")), "archive:");
    }

    #[test]
    fn archive_degrades_to_empty_for_non_archive_locations() {
        assert_eq!(Scope::Archive.key(Some("encoding_chain:base64+zlib")), "");
        assert_eq!(Scope::Archive.key(Some("0x1234")), "");
        assert_eq!(Scope::Archive.key(None), "");
    }

    // ----- apply_scope_filter -----------------------------------------------

    #[test]
    fn outer_scope_is_a_no_op_passthrough() {
        let rule = composite_with(2, Some(Scope::Outer));
        let evidence = vec![ev("archive:a.so"), ev("archive:b.so")];
        let tags = vec![tag(0, "archive:a.so"), tag(1, "archive:b.so")];

        let (filtered_ev, filtered_tags) = rule
            .apply_scope_filter(evidence, tags)
            .expect("outer never rejects");
        assert_eq!(filtered_ev.len(), 2);
        assert_eq!(filtered_tags.len(), 2);
    }

    #[test]
    fn leaf_scope_rejects_when_conditions_span_two_leaves() {
        let rule = composite_with(2, Some(Scope::Leaf));
        let evidence = vec![ev("archive:a.so"), ev("archive:b.so")];
        let tags = vec![tag(0, "archive:a.so"), tag(1, "archive:b.so")];

        assert!(rule.apply_scope_filter(evidence, tags).is_none());
    }

    #[test]
    fn leaf_scope_accepts_when_both_conditions_in_one_leaf() {
        let rule = composite_with(2, Some(Scope::Leaf));
        let evidence = vec![ev("archive:a.so"), ev("archive:a.so")];
        let tags = vec![tag(0, "archive:a.so"), tag(1, "archive:a.so")];

        let (filtered_ev, _) = rule
            .apply_scope_filter(evidence, tags)
            .expect("both in same leaf");
        assert_eq!(filtered_ev.len(), 2);
    }

    #[test]
    fn leaf_scope_pools_byte_offsets_in_same_raw_input() {
        let rule = composite_with(2, Some(Scope::Leaf));
        let evidence = vec![ev("0x10"), ev("0x30")];
        let tags = vec![tag(0, "0x10"), tag(1, "0x30")];

        let (filtered_ev, _) = rule
            .apply_scope_filter(evidence, tags)
            .expect("byte offsets share the raw input leaf");
        assert_eq!(filtered_ev.len(), 2);
    }

    #[test]
    fn leaf_scope_keeps_archive_member_identity_for_byte_offsets() {
        let rule = composite_with(2, Some(Scope::Leaf));
        let evidence = vec![ev("archive:a.bin:0x10"), ev("archive:b.bin:0x30")];
        let tags = vec![tag(0, "archive:a.bin:0x10"), tag(1, "archive:b.bin:0x30")];

        assert!(rule.apply_scope_filter(evidence, tags).is_none());
    }

    #[test]
    fn leaf_scope_drops_evidence_from_losing_buckets() {
        // Condition 0 has evidence in two leaves; condition 1 has
        // evidence only in `a.so`. Only the `a.so` bucket has both
        // conditions; evidence in `b.so` is dropped.
        let rule = composite_with(2, Some(Scope::Leaf));
        let evidence = vec![ev("archive:a.so"), ev("archive:b.so"), ev("archive:a.so")];
        let tags = vec![
            tag(0, "archive:a.so"),
            tag(0, "archive:b.so"),
            tag(1, "archive:a.so"),
        ];

        let (filtered_ev, filtered_tags) = rule
            .apply_scope_filter(evidence, tags)
            .expect("a.so bucket wins");
        assert_eq!(filtered_ev.len(), 2);
        assert!(
            filtered_ev
                .iter()
                .all(|e| e.location.as_deref() == Some("archive:a.so"))
        );
        assert_eq!(filtered_tags.len(), 2);
    }

    #[test]
    fn archive_scope_accepts_two_entries_in_same_archive() {
        let rule = composite_with(2, Some(Scope::Archive));
        let evidence = vec![ev("archive:a.so"), ev("archive:b.so")];
        let tags = vec![tag(0, "archive:a.so"), tag(1, "archive:b.so")];

        let (filtered_ev, _) = rule
            .apply_scope_filter(evidence, tags)
            .expect("same archive");
        assert_eq!(filtered_ev.len(), 2);
    }

    #[test]
    fn archive_scope_rejects_two_entries_in_different_nested_archives() {
        let rule = composite_with(2, Some(Scope::Archive));
        let evidence = vec![
            ev("archive:outer.zip!inner1.zip!a.so"),
            ev("archive:outer.zip!inner2.zip!b.so"),
        ];
        let tags = vec![
            tag(0, "archive:outer.zip!inner1.zip!a.so"),
            tag(1, "archive:outer.zip!inner2.zip!b.so"),
        ];

        assert!(rule.apply_scope_filter(evidence, tags).is_none());
    }

    #[test]
    fn archive_scope_pools_entries_in_same_nested_archive() {
        let rule = composite_with(2, Some(Scope::Archive));
        let evidence = vec![
            ev("archive:outer.zip!inner.zip!a.so"),
            ev("archive:outer.zip!inner.zip!b.so"),
        ];
        let tags = vec![
            tag(0, "archive:outer.zip!inner.zip!a.so"),
            tag(1, "archive:outer.zip!inner.zip!b.so"),
        ];

        let (filtered_ev, _) = rule
            .apply_scope_filter(evidence, tags)
            .expect("same nested archive");
        assert_eq!(filtered_ev.len(), 2);
    }

    #[test]
    fn file_scope_pools_decoded_layers_with_their_input() {
        // `scope: file` collapses encoded-payload layers down to the
        // input level, so two decoded-layer pieces of evidence pool
        // together under the same file-level key.
        let rule = composite_with(2, Some(Scope::File));
        let evidence = vec![
            ev("encoding_chain:base64"),
            ev("encoding_chain:base64+zlib"),
        ];
        let tags = vec![
            tag(0, "encoding_chain:base64"),
            tag(1, "encoding_chain:base64+zlib"),
        ];

        let (filtered_ev, _) = rule
            .apply_scope_filter(evidence, tags)
            .expect("file scope pools input + decoded layers");
        assert_eq!(filtered_ev.len(), 2);
    }

    #[test]
    fn leaf_scope_separates_decoded_layers_from_each_other() {
        let rule = composite_with(2, Some(Scope::Leaf));
        let evidence = vec![
            ev("encoding_chain:base64"),
            ev("encoding_chain:base64+zlib"),
        ];
        let tags = vec![
            tag(0, "encoding_chain:base64"),
            tag(1, "encoding_chain:base64+zlib"),
        ];

        assert!(rule.apply_scope_filter(evidence, tags).is_none());
    }

    #[test]
    fn single_condition_rule_satisfies_any_scope() {
        // 1 condition → min_distinct == 1 → any single bucket
        // satisfies, but the filter still pins to exactly one bucket.
        let rule = composite_with(1, Some(Scope::Leaf));
        let evidence = vec![ev("archive:a.so"), ev("archive:b.so")];
        let tags = vec![tag(0, "archive:a.so"), tag(0, "archive:b.so")];

        let (filtered_ev, _) = rule
            .apply_scope_filter(evidence, tags)
            .expect("single condition is trivially in-scope");
        assert_eq!(filtered_ev.len(), 1);
    }
}
