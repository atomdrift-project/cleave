//! Trait definitions for composite rules.
//!
//! This module contains TraitDefinition (atomic traits) and CompositeTrait
//! (boolean combinations of conditions).

use super::condition::{Condition, NotException, NotExceptionStructured, StringValidator};
use super::context::{ConditionResult, EvaluationContext, StringParams};
use super::evaluators::{
    eval_ast, eval_basename, eval_encoded, eval_exports_count, eval_hex, eval_import_combination,
    eval_metrics, eval_raw, eval_section, eval_section_ratio, eval_string, eval_string_count,
    eval_string_literal, eval_structure, eval_symbol, eval_syscall, eval_text, eval_trait,
    eval_yara_inline, ContentLocationParams,
};
use super::types::{
    default_architectures, default_file_types, default_platforms, Arch, FileType, Platform,
};
use crate::types::{
    deduplicate_evidence, Criticality, Evidence, Finding, FindingKind, MAX_EVIDENCE_PER_TRAIT,
};
use anyhow::Context;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Global concurrent statistics for condition evaluation timing
static CONDITION_STATS: OnceLock<DashMap<&'static str, (AtomicU64, AtomicU64)>> = OnceLock::new();

fn stats_map() -> &'static DashMap<&'static str, (AtomicU64, AtomicU64)> {
    CONDITION_STATS.get_or_init(DashMap::new)
}

/// Reset condition statistics.
/// Can be called periodically in long-running processes to prevent stats accumulation.
/// Note: CONDITION_STATS is keyed by static condition type names (~20 entries max),
/// so memory growth is bounded, but clearing is still useful for accurate per-batch stats.
#[allow(dead_code)] // Called via public API wrapper in mod.rs
pub(crate) fn clear_condition_stats() {
    stats_map().clear();
}

/// Hard deadline for a single rule evaluation (30 seconds).
/// When exceeded, evaluation is interrupted and a timeout finding is emitted.
const MAX_RULE_EVAL_DURATION: Duration = Duration::from_secs(30);

/// Debug log threshold for rule evaluation (500ms).
/// Rules exceeding this emit an info-level log.
const RULE_EVAL_DEBUG_DURATION: Duration = Duration::from_millis(600);

/// Macro to time condition evaluation
macro_rules! timed_eval {
    ($name:expr, $eval:expr) => {{
        let _start = std::time::Instant::now();
        let result = $eval;
        let _elapsed = _start.elapsed();

        // Prefer the read-lock `get` path: after the first insert per condition type
        // (~20 keys across the whole run) every eval is a hit, and `entry()` would
        // otherwise take a shard write lock on every call. The AtomicU64 counters
        // are internally synchronized so a shared ref is all we need.
        let stats = stats_map();
        if let Some(entry) = stats.get(&$name) {
            entry.0.fetch_add(1, Ordering::Relaxed);
            entry
                .1
                .fetch_add(_elapsed.as_nanos() as u64, Ordering::Relaxed);
        } else {
            let entry = stats
                .entry($name)
                .or_insert_with(|| (AtomicU64::new(0), AtomicU64::new(0)));
            entry.0.fetch_add(1, Ordering::Relaxed);
            entry
                .1
                .fetch_add(_elapsed.as_nanos() as u64, Ordering::Relaxed);
        }

        result
    }};
}

fn default_confidence() -> f32 {
    1.0
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
        if matches!(self.r#if, Condition::Section { .. }) {
            return None;
        }

        if let (Some(min), Some(max)) = (self.size_min, self.size_max) {
            if max < min {
                return Some(format!(
                    "size_max ({}) cannot be less than size_min ({})",
                    max, min
                ));
            }
        }
        None
    }

    /// Check if entropy constraints are valid.
    /// Returns an error message if invalid, None otherwise.
    #[must_use]
    pub(crate) fn check_entropy_constraints(&self) -> Option<String> {
        // Validate entropy range (0.0-8.0)
        if let Some(min) = self.entropy_min {
            if !(0.0..=8.0).contains(&min) {
                return Some(format!(
                    "entropy_min ({:.2}) must be between 0.0 and 8.0",
                    min
                ));
            }
        }
        if let Some(max) = self.entropy_max {
            if !(0.0..=8.0).contains(&max) {
                return Some(format!(
                    "entropy_max ({:.2}) must be between 0.0 and 8.0",
                    max
                ));
            }
        }
        if let (Some(min), Some(max)) = (self.entropy_min, self.entropy_max) {
            if max < min {
                return Some(format!(
                    "entropy_max ({:.2}) cannot be less than entropy_min ({:.2})",
                    max, min
                ));
            }
        }
        None
    }

    /// Check if count constraints are valid.
    #[must_use]
    pub(crate) fn check_count_constraints(&self) -> Option<String> {
        if let (Some(min), Some(max)) = (self.count_min, self.count_max) {
            if max < min {
                return Some(format!(
                    "count_max ({}) is less than count_min ({})",
                    max, min
                ));
            }
        }
        self.r#if.check_count_constraints()
    }

    /// Check if density constraints are valid.
    #[must_use]
    pub(crate) fn check_density_constraints(&self) -> Option<String> {
        if let (Some(min), Some(max)) = (self.per_kb_min, self.per_kb_max) {
            if max < min {
                return Some(format!(
                    "per_kb_max ({}) is less than per_kb_min ({})",
                    max, min
                ));
            }
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

    /// Check for empty or very short descriptions (common LLM mistake).
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
                desc, desc.len()
            ));
        }

        None
    }

    /// Check for empty not: arrays (common LLM mistake).
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_empty_not_array(&self) -> Option<String> {
        if let Some(not_exceptions) = &self.not {
            if not_exceptions.is_empty() {
                return Some(
                    "not: array is empty - either remove the not: field or add exception patterns"
                        .to_string(),
                );
            }
        }
        None
    }

    /// Check for empty unless: arrays (common LLM mistake).
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_empty_unless_array(&self) -> Option<String> {
        if let Some(unless_conditions) = &self.unless {
            if unless_conditions.is_empty() {
                return Some(
                    "unless: array is empty - either remove the unless: field or add skip conditions".to_string()
                );
            }
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
            Condition::Symbol {
                exact: Some(_),
                regex: None,
                ..
            } => {
                return Some(
                    "not: field used with symbol exact match - consider using 'unless:' instead for deterministic patterns".to_string()
                );
            }
            Condition::Symbol {
                substr: Some(search_substr),
                regex: None,
                ..
            } => {
                // For symbol substr, validate not: exceptions contain the search substr
                for exc in not_exceptions {
                    match exc {
                        NotException::Shorthand(exc_str) => {
                            if !exc_str.contains(search_substr) {
                                return Some(format!(
                                    "not: exception '{}' does not contain the search substr '{}' - symbols matching the substr won't contain this exception, so it will never be applied",
                                    exc_str, search_substr
                                ));
                            }
                        }
                        NotException::Structured(NotExceptionStructured {
                            exact: Some(exc_str),
                            ..
                        }) => {
                            if !exc_str.contains(search_substr) {
                                return Some(format!(
                                    "not: exception (exact) '{}' does not contain the search substr '{}' - symbols matching the substr won't match this exception, so it will never be applied",
                                    exc_str, search_substr
                                ));
                            }
                        }
                        NotException::Structured(NotExceptionStructured {
                            substr: Some(exc_substr),
                            ..
                        }) => {
                            if !exc_substr.contains(search_substr)
                                && !search_substr.contains(exc_substr)
                            {
                                return Some(format!(
                                    "not: exception (substr) '{}' has no overlap with search substr '{}' - they won't match the same symbols, so the exception will never be applied",
                                    exc_substr, search_substr
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }
            Condition::Symbol {
                regex: Some(pattern),
                ..
            } => {
                // For symbol regex, validate that exceptions could potentially match
                for exc in not_exceptions {
                    match exc {
                        // Validate shorthand (substr) exceptions - check if the substr matches the regex
                        NotException::Shorthand(exc_str) => {
                            if !pattern_could_match(pattern, exc_str) {
                                return Some(format!(
                                    "not: exception '{}' does not match the search regex '{}' - symbols matching the regex won't contain this exception, so it will never be applied",
                                    exc_str, pattern
                                ));
                            }
                        }
                        // Validate exact exceptions - check if the exact string matches the regex
                        NotException::Structured(NotExceptionStructured {
                            exact: Some(exc_str),
                            ..
                        }) => {
                            if !pattern_could_match(pattern, exc_str) {
                                return Some(format!(
                                    "not: exception (exact) '{}' does not match the search regex '{}' - it will never be applied",
                                    exc_str, pattern
                                ));
                            }
                        }
                        // For substr and regex exceptions, validation is complex - allow them
                        _ => {}
                    }
                }
            }
            // Exact matches should use `unless:` instead of `not:`
            Condition::StringValue {
                exact: Some(_),
                regex: None,
                word: None,
                ..
            }
            | Condition::Text {
                exact: Some(_),
                regex: None,
                word: None,
                ..
            }
            | Condition::StringLiteral {
                exact: Some(_),
                regex: None,
                word: None,
                ..
            } => {
                return Some(
                    "not: field used with exact match - consider using 'unless:' instead for deterministic patterns".to_string()
                );
            }
            // For Content exact matches, not: doesn't make sense
            Condition::Raw {
                exact: Some(_),
                regex: None,
                word: None,
                ..
            } => {
                return Some(
                    "not: field used with content/exact match - this doesn't make sense. Content exact matches the entire file content.".to_string()
                );
            }
            // For String substr matches, validate that not: exceptions could match strings containing the substr
            Condition::StringValue {
                substr: Some(search_substr),
                regex: None,
                word: None,
                case_insensitive,
                ..
            }
            | Condition::Text {
                substr: Some(search_substr),
                regex: None,
                word: None,
                case_insensitive,
                ..
            }
            | Condition::StringLiteral {
                substr: Some(search_substr),
                regex: None,
                word: None,
                case_insensitive,
                ..
            } => {
                let case_insensitive = *case_insensitive;

                for exc in not_exceptions {
                    match exc {
                        // For shorthand (substr match in not:), check if the exception contains the search substr
                        NotException::Shorthand(exc_str) => {
                            if !contains_substr(exc_str, search_substr, case_insensitive) {
                                return Some(format!(
                                    "not: exception '{}' does not contain the search substr '{}' - strings matching the substr won't contain this exception, so it will never be applied",
                                    exc_str, search_substr
                                ));
                            }
                        }
                        NotException::Structured(NotExceptionStructured {
                            exact: Some(exc_str),
                            ..
                        }) => {
                            // Exception is exact match - it should contain the search substr
                            if !contains_substr(exc_str, search_substr, case_insensitive) {
                                return Some(format!(
                                    "not: exception (exact) '{}' does not contain the search substr '{}' - strings matching the substr won't match this exception, so it will never be applied",
                                    exc_str, search_substr
                                ));
                            }
                        }
                        NotException::Structured(NotExceptionStructured {
                            substr: Some(exc_substr),
                            ..
                        }) => {
                            // Exception is substr - it should contain the search substr or vice versa
                            // Either the exception contains the search, or the search contains the exception
                            if !contains_substr(exc_substr, search_substr, case_insensitive)
                                && !contains_substr(search_substr, exc_substr, case_insensitive)
                            {
                                return Some(format!(
                                    "not: exception (substr) '{}' has no overlap with search substr '{}' - they won't match the same strings, so the exception will never be applied",
                                    exc_substr, search_substr
                                ));
                            }
                        }
                        NotException::Structured(NotExceptionStructured {
                            regex: Some(_exc_regex),
                            ..
                        }) => {
                            // For regex exceptions with substr search, we can't easily validate
                            // The regex might match strings containing the substr
                            // We'll allow this without validation
                        }
                        _ => {}
                    }
                }
            }
            // For Content substr matches, not: is unclear - content searches don't extract individual strings
            Condition::Raw {
                substr: Some(_),
                regex: None,
                word: None,
                ..
            } => {
                return Some(
                    "not: field used with content/substr match - behavior is unclear because content searches on binary data don't extract individual strings for filtering. Use regex instead, or use 'string' type with substr.".to_string()
                );
            }
            // For regex matches, validate that exceptions could potentially match
            Condition::StringValue {
                regex: Some(pattern),
                ..
            }
            | Condition::Text {
                regex: Some(pattern),
                ..
            }
            | Condition::StringLiteral {
                regex: Some(pattern),
                ..
            }
            | Condition::Raw {
                regex: Some(pattern),
                ..
            } => {
                for exc in not_exceptions {
                    match exc {
                        // Validate shorthand (substr) exceptions - check if the substr matches the regex
                        NotException::Shorthand(exc_str) => {
                            if !pattern_could_match(pattern, exc_str) {
                                return Some(format!(
                                    "not: exception '{}' does not match the search regex '{}' - strings matching the regex won't contain this exception, so it will never be applied",
                                    exc_str, pattern
                                ));
                            }
                        }
                        // Validate exact exceptions - check if the exact string matches the regex
                        NotException::Structured(NotExceptionStructured {
                            exact: Some(exc_str),
                            ..
                        }) => {
                            if !pattern_could_match(pattern, exc_str) {
                                return Some(format!(
                                    "not: exception (exact) '{}' does not match the search regex '{}' - it will never be applied",
                                    exc_str, pattern
                                ));
                            }
                        }
                        // For substr and regex exceptions, validation is complex - allow them
                        _ => {}
                    }
                }
            }
            // For hex patterns, validate exceptions match
            Condition::Hex { pattern: _, .. } => {
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

    /// Evaluate this trait definition against the analysis context
    pub(crate) fn evaluate<'a>(&self, ctx: &EvaluationContext<'a>) -> Option<Finding> {
        use super::debug::{ConditionDebug, DowngradeDebug, SkipReason};

        // Check platform match
        let platform_match = self.platforms.contains(&Platform::All)
            || ctx.platforms.contains(&Platform::All)
            || self.platforms.iter().any(|p| ctx.platforms.contains(p));

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
        if let Some(min) = self.size_min {
            if file_size < min {
                ctx.record_skip(SkipReason::SizeTooSmall {
                    actual: file_size,
                    min,
                });
                return None;
            }
        }
        if let Some(max) = self.size_max {
            if file_size > max {
                ctx.record_skip(SkipReason::SizeTooLarge {
                    actual: file_size,
                    max,
                });
                return None;
            }
        }

        // Check entropy constraints (from if: block)
        // Uses binary.overall_entropy for binaries, text.char_entropy for scripts
        if self.entropy_min.is_some() || self.entropy_max.is_some() {
            let file_entropy = ctx
                .report
                .metrics
                .as_ref()
                .and_then(|m| {
                    // Try binary entropy first, fall back to text char entropy
                    m.binary
                        .as_ref()
                        .map(|b| f64::from(b.overall_entropy))
                        .or_else(|| m.text.as_ref().map(|t| f64::from(t.char_entropy)))
                })
                .unwrap_or(0.0);

            if let Some(min) = self.entropy_min {
                if file_entropy < min {
                    ctx.record_skip(SkipReason::EntropyTooLow {
                        actual: file_entropy,
                        min,
                    });
                    return None;
                }
            }
            if let Some(max) = self.entropy_max {
                if file_entropy > max {
                    ctx.record_skip(SkipReason::EntropyTooHigh {
                        actual: file_entropy,
                        max,
                    });
                    return None;
                }
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
                    ctx.record_skip(SkipReason::UnlessConditionMatched {
                        condition_desc: format!("{:?}", condition),
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
                    location: None,
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
            let cond_debug = ConditionDebug::new(format!("{:?}", self.r#if))
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
            if let Some(min) = self.count_min {
                if match_count < min {
                    ctx.record_skip(SkipReason::CountBelowMinimum {
                        actual: match_count,
                        min,
                    });
                    return None;
                }
            }

            // Check count_max constraint
            if let Some(max) = self.count_max {
                if match_count > max {
                    ctx.record_skip(SkipReason::CountAboveMaximum {
                        actual: match_count,
                        max,
                    });
                    return None;
                }
            }

            // Check per_kb_min constraint (density threshold).
            // Zero-byte files have infinite density — trivially satisfy any minimum.
            if let Some(min_density) = self.per_kb_min {
                if file_kb > 0.0 {
                    let actual_density = (match_count as f64) / file_kb;
                    if actual_density < min_density {
                        ctx.record_skip(SkipReason::DensityBelowMinimum {
                            actual: actual_density,
                            min: min_density,
                        });
                        return None;
                    }
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
                    final_crit = match self.crit {
                        Criticality::Hostile => Criticality::Suspicious,
                        Criticality::Suspicious => Criticality::Notable,
                        Criticality::Notable => Criticality::Baseline,
                        Criticality::Baseline | Criticality::Component | Criticality::Filtered => {
                            Criticality::Component
                        }
                    };
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

            Some(Finding {
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
                if self.eval_condition(cond, ctx).matched {
                    matched_count += 1;
                }
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
            Condition::Symbol {
                exact,
                substr,
                regex,
                platforms,
                is_check,
                compiled_regex,
                compiled_finder,
            } => timed_eval!(
                "symbol",
                eval_symbol(
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    platforms.as_ref(),
                    *is_check,
                    compiled_regex.as_ref(),
                    compiled_finder.as_ref(),
                    self.not.as_ref(),
                    ctx,
                )
            ),
            Condition::StringValue {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not: _,
                platforms: _,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                compiled_regex,
                compiled_finder,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    is_check: *is_check,
                    compiled_regex: compiled_regex.as_ref(),
                    compiled_finder: compiled_finder.as_ref(),
                    section: section.as_ref(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                    arch_clamp,
                };
                timed_eval!("string_value", eval_string(&params, self.not.as_ref(), ctx))
            }
            Condition::Text {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not: _,
                platforms: _,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                compiled_regex,
                compiled_finder,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    is_check: *is_check,
                    compiled_regex: compiled_regex.as_ref(),
                    compiled_finder: compiled_finder.as_ref(),
                    section: section.as_ref(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                    arch_clamp,
                };
                timed_eval!(
                    "text",
                    eval_text(&params, self.not.as_ref(), ctx, Some(self.id.as_str()))
                )
            }
            Condition::StringLiteral {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not: _,
                platforms: _,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                compiled_regex,
                compiled_finder,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    is_check: *is_check,
                    compiled_regex: compiled_regex.as_ref(),
                    compiled_finder: compiled_finder.as_ref(),
                    section: section.as_ref(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                    arch_clamp,
                };
                timed_eval!(
                    "string_literal",
                    eval_string_literal(&params, self.not.as_ref(), ctx)
                )
            }
            Condition::Structure {
                feature,
                min_sections,
            } => timed_eval!("structure", eval_structure(feature, *min_sections, ctx)),
            Condition::ExportsCount { min, max } => {
                timed_eval!("exports_count", eval_exports_count(*min, *max, ctx))
            }
            Condition::Trait { id } => timed_eval!("trait", eval_trait(id, ctx)),
            Condition::Ast {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                case_insensitive,
                ..
            } => timed_eval!(
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
            Condition::SectionRatio {
                section,
                compare_to,
                min,
                max,
            } => timed_eval!(
                "section_ratio",
                eval_section_ratio(section, compare_to, *min, *max, ctx)
            ),
            Condition::ImportCombination {
                required,
                suspicious,
                min_suspicious,
                max_total,
                compiled_required,
                compiled_suspicious,
            } => timed_eval!(
                "import_combo",
                eval_import_combination(
                    required.as_ref(),
                    suspicious.as_ref(),
                    *min_suspicious,
                    *max_total,
                    compiled_required.as_ref(),
                    compiled_suspicious.as_ref(),
                    ctx,
                )
            ),
            Condition::StringValueCount {
                min,
                max,
                min_length,
                regex,
                compiled_regex,
            } => timed_eval!(
                "string_count",
                eval_string_count(
                    *min,
                    *max,
                    *min_length,
                    regex.as_ref(),
                    compiled_regex.as_ref(),
                    ctx,
                )
            ),
            Condition::Metrics {
                field,
                min,
                max,
                min_size,
                max_size,
            } => timed_eval!(
                "metrics",
                eval_metrics(field, *min, *max, *min_size, *max_size, ctx)
            ),
            Condition::Hex {
                pattern,
                not: _,
                offset,
                offset_range,
                section,
                section_offset,
                section_offset_range,
            } => timed_eval!(
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
            Condition::Raw {
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
                compiled_regex,
                compiled_finder: _,
            } => {
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
                        compiled_regex.as_ref(),
                        self.not.as_ref(),
                        &location,
                        ctx,
                        Some(self.id.as_str()),
                    )
                )
            }
            Condition::Section {
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
            } => timed_eval!(
                "section",
                eval_section(
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    word.as_ref(),
                    *case_insensitive,
                    *length_min,
                    *length_max,
                    *entropy_min,
                    *entropy_max,
                    *readable,
                    *writable,
                    *executable,
                    ctx,
                )
            ),
            Condition::Encoded {
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
                compiled_regex,
            } => {
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
                        compiled_regex.as_ref(),
                        &location,
                        *is_check,
                        not.as_ref(),
                        ctx,
                    )
                )
            }
            Condition::Basename {
                exact,
                substr,
                regex,
                case_insensitive,
                is_check,
                compiled_regex,
            } => timed_eval!(
                "basename",
                eval_basename(
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    *case_insensitive,
                    *is_check,
                    compiled_regex.as_ref(),
                    ctx,
                )
            ),
            Condition::Kv { .. } => {
                timed_eval!("kv", {
                    // Delegate to kv evaluator with caching
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

impl CompositeTrait {
    /// Collect the subset of dependent trait IDs that are individually mandatory.
    ///
    /// These IDs are used only for fast prefiltering before full composite evaluation,
    /// so they must be a sound lower bound:
    /// - every `all:` trait reference is mandatory
    /// - `any:` references are only mandatory when the rule requires all of them
    fn get_required_trait_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();

        if let Some(ref conds) = self.all {
            for cond in conds {
                if let Condition::Trait { ref id } = cond {
                    ids.push(id.clone());
                }
            }
        }

        if let Some(ref conds) = self.any {
            let required_from_any = self.needs.unwrap_or(1);
            if required_from_any >= conds.len() {
                for cond in conds {
                    if let Condition::Trait { ref id } = cond {
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

    /// Evaluate this rule against the analysis context
    #[must_use]
    pub(crate) fn evaluate<'a>(&self, ctx: &EvaluationContext<'a>) -> Option<Finding> {
        use super::debug::{DowngradeDebug, ProximityDebug, SkipReason};

        // Check platform match
        let platform_match = self.platforms.contains(&Platform::All)
            || ctx.platforms.contains(&Platform::All)
            || self.platforms.iter().any(|p| ctx.platforms.contains(p));

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

        // Check size constraints
        let file_size = ctx.report.target.size_bytes as usize;
        if let Some(min) = self.size_min {
            if file_size < min {
                ctx.record_skip(SkipReason::SizeTooSmall {
                    actual: file_size,
                    min,
                });
                return None;
            }
        }
        if let Some(max) = self.size_max {
            if file_size > max {
                ctx.record_skip(SkipReason::SizeTooLarge {
                    actual: file_size,
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
                    ctx.record_skip(SkipReason::UnlessConditionMatched {
                        condition_desc: format!("{:?}", condition),
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

        let result = positive_result;

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
                    final_crit = match self.crit {
                        Criticality::Hostile => Criticality::Suspicious,
                        Criticality::Suspicious => Criticality::Notable,
                        Criticality::Notable => Criticality::Baseline,
                        Criticality::Baseline | Criticality::Component | Criticality::Filtered => {
                            Criticality::Component
                        }
                    };
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
                        location: None,
                        ..Default::default()
                    }],
                    match_count: 0,
                    source_file: get_relative_source_file(&self.defined_in),
                });
            }

            Some(Finding {
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
            return match base_crit {
                Criticality::Hostile => Criticality::Suspicious,
                Criticality::Suspicious => Criticality::Notable,
                Criticality::Notable => Criticality::Baseline,
                Criticality::Baseline | Criticality::Component | Criticality::Filtered => {
                    Criticality::Component
                }
            };
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
                if self.eval_condition(cond, ctx).matched {
                    matched_count += 1;
                }
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
                matched_count += 1;
                // Tag evidence locations before merging
                tags.extend(tag_evidence(&result.evidence, i));
                // Limit evidence to prevent explosion
                if all_evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    let remaining = MAX_EVIDENCE_PER_TRAIT - all_evidence.len();
                    all_evidence.extend(result.evidence.into_iter().take(remaining));
                }
                all_trait_ids.extend(result.matched_trait_ids);
                precision_sum += result.precision;
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
            Condition::Symbol {
                exact,
                substr,
                regex,
                platforms,
                is_check,
                compiled_regex,
                compiled_finder,
            } => self.eval_symbol(
                exact.as_ref(),
                substr.as_ref(),
                regex.as_ref(),
                platforms.as_ref(),
                *is_check,
                compiled_regex.as_ref(),
                compiled_finder.as_ref(),
                self.not.as_ref(),
                ctx,
            ),
            Condition::StringValue {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not: _,
                platforms: _,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                compiled_regex,
                compiled_finder,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    is_check: *is_check,
                    compiled_regex: compiled_regex.as_ref(),
                    compiled_finder: compiled_finder.as_ref(),
                    section: section.as_ref(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                    arch_clamp,
                };
                eval_string(&params, self.not.as_ref(), ctx)
            }
            Condition::Text {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not: _,
                platforms: _,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                compiled_regex,
                compiled_finder,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    is_check: *is_check,
                    compiled_regex: compiled_regex.as_ref(),
                    compiled_finder: compiled_finder.as_ref(),
                    section: section.as_ref(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                    arch_clamp,
                };
                eval_text(&params, self.not.as_ref(), ctx, Some(self.id.as_str()))
            }
            Condition::StringLiteral {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                is_check,
                not: _,
                platforms: _,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                compiled_regex,
                compiled_finder,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    is_check: *is_check,
                    compiled_regex: compiled_regex.as_ref(),
                    compiled_finder: compiled_finder.as_ref(),
                    section: section.as_ref(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                    arch_clamp,
                };
                eval_string_literal(&params, self.not.as_ref(), ctx)
            }
            Condition::Structure {
                feature,
                min_sections,
            } => self.eval_structure(feature, *min_sections, ctx),
            Condition::ExportsCount { min, max } => self.eval_exports_count(*min, *max, ctx),
            Condition::Trait { id } => eval_trait(id, ctx),
            Condition::Ast {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                case_insensitive,
                ..
            } => timed_eval!(
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
            Condition::SectionRatio {
                section,
                compare_to,
                min,
                max,
            } => timed_eval!(
                "section_ratio",
                eval_section_ratio(section, compare_to, *min, *max, ctx)
            ),
            Condition::ImportCombination {
                required,
                suspicious,
                min_suspicious,
                max_total,
                compiled_required,
                compiled_suspicious,
            } => timed_eval!(
                "import_combo",
                eval_import_combination(
                    required.as_ref(),
                    suspicious.as_ref(),
                    *min_suspicious,
                    *max_total,
                    compiled_required.as_ref(),
                    compiled_suspicious.as_ref(),
                    ctx,
                )
            ),
            Condition::StringValueCount {
                min,
                max,
                min_length,
                regex,
                compiled_regex,
            } => timed_eval!(
                "string_count",
                eval_string_count(
                    *min,
                    *max,
                    *min_length,
                    regex.as_ref(),
                    compiled_regex.as_ref(),
                    ctx,
                )
            ),
            Condition::Metrics {
                field,
                min,
                max,
                min_size,
                max_size,
            } => timed_eval!(
                "metrics",
                eval_metrics(field, *min, *max, *min_size, *max_size, ctx)
            ),
            Condition::Hex {
                pattern,
                not: _,
                offset,
                offset_range,
                section,
                section_offset,
                section_offset_range,
            } => timed_eval!(
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
            Condition::Raw {
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
                compiled_regex,
                compiled_finder: _,
            } => {
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
                        compiled_regex.as_ref(),
                        self.not.as_ref(),
                        &location,
                        ctx,
                        Some(self.id.as_str()),
                    )
                )
            }
            Condition::Section {
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
            } => timed_eval!(
                "section",
                eval_section(
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    word.as_ref(),
                    *case_insensitive,
                    *length_min,
                    *length_max,
                    *entropy_min,
                    *entropy_max,
                    *readable,
                    *writable,
                    *executable,
                    ctx,
                )
            ),
            Condition::Encoded {
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
                compiled_regex,
            } => {
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
                        compiled_regex.as_ref(),
                        &location,
                        *is_check,
                        not.as_ref(),
                        ctx,
                    )
                )
            }
            Condition::Basename {
                exact,
                substr,
                regex,
                case_insensitive,
                is_check,
                compiled_regex,
            } => timed_eval!(
                "basename",
                eval_basename(
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    *case_insensitive,
                    *is_check,
                    compiled_regex.as_ref(),
                    ctx,
                )
            ),
            Condition::Kv { .. } => {
                timed_eval!("kv", {
                    // Delegate to kv evaluator with caching
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

        eval_symbol(
            exact,
            substr,
            pattern,
            None,
            is_check,
            compiled_regex,
            compiled_finder,
            not,
            ctx,
        )
    }

    /// Evaluate structure condition
    fn eval_structure<'a>(
        &self,
        feature: &str,
        min_sections: Option<usize>,
        ctx: &EvaluationContext<'a>,
    ) -> ConditionResult {
        eval_structure(feature, min_sections, ctx)
    }

    /// Evaluate exports count condition
    fn eval_exports_count<'a>(
        &self,
        min: Option<usize>,
        max: Option<usize>,
        ctx: &EvaluationContext<'a>,
    ) -> ConditionResult {
        let count = ctx.report.exports.len();
        let matched = min.is_none_or(|m| count >= m) && max.is_none_or(|m| count <= m);

        let evidence = if matched {
            vec![Evidence {
                method: "export_count".to_string(),
                source: "composite_rule".to_string(),
                value: count.to_string(),
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
            precision: 0.0,
            matched_trait_ids: Vec::new(),
        }
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

        // Derive min_distinct from rule structure.
        // For `all`: every condition must contribute nearby evidence.
        // For `any` with `needs`: that many conditions must contribute nearby evidence.
        // Always at least 2 — proximity with a single item is vacuously true.
        let min_distinct = {
            let all_count = self.all.as_ref().map_or(0, Vec::len);
            let any_required = if self.any.is_some() {
                self.needs.unwrap_or(1)
            } else {
                0
            };
            (all_count + any_required).max(2)
        };

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
                if let (Some((start, end)), Some(ref ls)) = (line_window, &line_starts_cache) {
                    if let Some(line) = evidence_to_line(ev, ls) {
                        return line >= start && line <= end;
                    }
                }
                if let Some((start, end)) = byte_window {
                    if let Some(offset) = evidence_to_byte_offset(ev) {
                        return offset >= start && offset <= end;
                    }
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
    if let Some(ref loc) = tagged.location {
        if let Some(colon_pos) = loc.find(':') {
            if let Ok(line) = loc[..colon_pos].parse::<usize>() {
                if line > 0 {
                    return Some(line);
                }
            }
        }
    }

    // Try byte offset
    if let Some(offset) = tagged.byte_offset {
        return Some(byte_offset_to_line(line_starts, offset as usize));
    }

    // Try hex offset from location
    if let Some(ref loc) = tagged.location {
        if let Some(offset) = parse_location_as_byte_offset(loc) {
            return Some(byte_offset_to_line(line_starts, offset as usize));
        }
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
    if let Some(ref loc) = evidence.location {
        if let Some(colon_pos) = loc.find(':') {
            if let Ok(line) = loc[..colon_pos].parse::<usize>() {
                // Sanity check: line numbers from AST are positive integers, not hex
                if line > 0 {
                    return Some(line);
                }
            }
        }
    }

    // Try byte offsets from the offsets vec
    if let Some(&first_offset) = evidence.offsets.first() {
        return Some(byte_offset_to_line(line_starts, first_offset as usize));
    }

    // Try hex offset from location (e.g., "0x1234", "offset:0x1234")
    if let Some(ref loc) = evidence.location {
        if let Some(offset) = parse_location_as_byte_offset(loc) {
            return Some(byte_offset_to_line(line_starts, offset as usize));
        }
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
/// Handles "0x1234", "offset:0x1234", "offset:1234".
fn parse_location_as_byte_offset(loc: &str) -> Option<u64> {
    if let Some(rest) = loc.strip_prefix("offset:") {
        return parse_hex_or_dec_offset(rest);
    }
    if loc.starts_with("0x") || loc.starts_with("0X") {
        return parse_hex_or_dec_offset(loc);
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
