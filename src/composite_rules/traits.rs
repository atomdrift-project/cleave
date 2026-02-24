//! Trait definitions for composite rules.
//!
//! This module contains TraitDefinition (atomic traits) and CompositeTrait
//! (boolean combinations of conditions).

use super::condition::{Condition, NotException};
use super::context::{ConditionResult, EvaluationContext, StringParams};
use super::evaluators::{
    eval_ast, eval_basename, eval_encoded, eval_exports_count, eval_hex, eval_import_combination,
    eval_metrics, eval_raw, eval_section, eval_section_ratio, eval_string, eval_string_count,
    eval_structure, eval_symbol, eval_syscall, eval_trait, eval_yara_inline, ContentLocationParams,
};
use super::types::{default_file_types, default_platforms, FileType, Platform};
use crate::types::{Criticality, Evidence, Finding, FindingKind, MAX_EVIDENCE_PER_TRAIT};
use anyhow::Context;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Global concurrent statistics for condition evaluation timing
static CONDITION_STATS: OnceLock<DashMap<&'static str, (AtomicU64, AtomicU64)>> = OnceLock::new();

fn stats_map() -> &'static DashMap<&'static str, (AtomicU64, AtomicU64)> {
    CONDITION_STATS.get_or_init(DashMap::new)
}

/// Print condition evaluation statistics
pub(crate) fn print_condition_stats() {
    if std::env::var("FLAYER_VERBOSE").as_deref() != Ok("1") {
        return;
    }

    let stats = stats_map();
    if stats.is_empty() {
        return;
    }

    let mut sorted: Vec<_> = stats
        .iter()
        .map(|entry| {
            let name = *entry.key();
            let (count, total_nanos) = entry.value();
            let count_val = count.load(Ordering::Relaxed);
            let duration = Duration::from_nanos(total_nanos.load(Ordering::Relaxed));
            (name, count_val, duration)
        })
        .collect();
    sorted.sort_by_key(|(_, _, duration)| std::cmp::Reverse(*duration));

    eprintln!("\n⏱️  Condition Evaluation Statistics:");
    eprintln!(
        "  {:20} {:>10} {:>12} {:>10}",
        "Type", "Count", "Total (ms)", "Avg (µs)"
    );
    eprintln!("  {}", "-".repeat(54));

    for (name, count, duration) in sorted.iter().take(20) {
        let avg_micros = duration.as_micros() / (*count as u128).max(1);
        eprintln!(
            "  {:20} {:>10} {:>12} {:>10}",
            name,
            count,
            duration.as_millis(),
            avg_micros
        );
    }
    eprintln!();
}

/// Reset condition statistics.
/// Can be called periodically in long-running processes to prevent stats accumulation.
/// Note: CONDITION_STATS is keyed by static condition type names (~20 entries max),
/// so memory growth is bounded, but clearing is still useful for accurate per-batch stats.
#[allow(dead_code)] // Called via public API wrapper in mod.rs
pub(crate) fn clear_condition_stats() {
    stats_map().clear();
}

/// Maximum time allowed for a single rule evaluation (2 seconds)
const MAX_RULE_EVAL_DURATION: Duration = Duration::from_secs(2);

/// Macro to time condition evaluation
macro_rules! timed_eval {
    ($name:expr, $eval:expr) => {{
        let _start = std::time::Instant::now();
        let result = $eval;
        let _elapsed = _start.elapsed();

        let stats = stats_map();
        let entry = stats
            .entry($name)
            .or_insert_with(|| (AtomicU64::new(0), AtomicU64::new(0)));
        entry.0.fetch_add(1, Ordering::Relaxed);
        entry
            .1
            .fetch_add(_elapsed.as_nanos() as u64, Ordering::Relaxed);

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

/// Wrapper for conditions with common filters applied at trait level.
/// Uses #[serde(flatten)] to merge filters into the if: block ergonomically.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct ConditionWithFilters {
    /// The actual condition (symbol, string, raw, etc.)
    #[serde(flatten)]
    pub condition: Condition,

    /// Minimum file size in bytes - checked before evaluating condition
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_min: Option<usize>,

    /// Maximum file size in bytes - checked before evaluating condition
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub size_max: Option<usize>,

    /// Minimum match count - trait matches only if condition matches at least this many times
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub count_min: Option<usize>,

    /// Maximum match count - trait fails if condition matches more than this many times
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub count_max: Option<usize>,

    /// Minimum matches per kilobyte of file size (density threshold)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub per_kb_min: Option<f64>,

    /// Maximum matches per kilobyte of file size (density ceiling)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub per_kb_max: Option<f64>,
}

impl ConditionWithFilters {
    /// Delegate method calls to the underlying condition
    pub(crate) fn precompile_regexes(&mut self) -> anyhow::Result<()> {
        self.condition.precompile_regexes()
    }

    #[must_use]
    pub(crate) fn can_match_file_type(&self, file_type: &FileType) -> bool {
        self.condition.can_match_file_type(file_type)
    }

    pub(crate) fn validate(&self, _trait_id: &str, full: bool) -> Result<(), String> {
        self.condition.validate(full).map_err(|e| e.to_string())
    }

    #[must_use]
    pub(crate) fn check_greedy_patterns(&self, _trait_id: &str) -> Option<String> {
        self.condition.check_greedy_patterns()
    }

    #[must_use]
    pub(crate) fn check_word_boundary_regex(&self, _trait_id: &str) -> Option<String> {
        self.condition.check_word_boundary_regex()
    }

    #[must_use]
    pub(crate) fn check_short_case_insensitive(&self, file_type_count: usize) -> Option<String> {
        self.condition.check_short_case_insensitive(file_type_count)
    }

    #[must_use]
    pub(crate) fn check_count_constraints(&self, _trait_id: &str) -> Option<String> {
        // Check count_min and count_max on ConditionWithFilters
        if let (Some(min), Some(max)) = (self.count_min, self.count_max) {
            if max < min {
                return Some(format!(
                    "count_max ({}) is less than count_min ({})",
                    max, min
                ));
            }
        }
        // Also check condition-level constraints
        self.condition.check_count_constraints()
    }

    #[must_use]
    pub(crate) fn check_density_constraints(&self, _trait_id: &str) -> Option<String> {
        // Check per_kb_min and per_kb_max on ConditionWithFilters
        if let (Some(min), Some(max)) = (self.per_kb_min, self.per_kb_max) {
            if max < min {
                return Some(format!(
                    "per_kb_max ({}) is less than per_kb_min ({})",
                    max, min
                ));
            }
        }
        // Also check condition-level constraints
        self.condition.check_density_constraints()
    }

    #[must_use]
    pub(crate) fn check_match_exclusivity(&self, _trait_id: &str) -> Option<String> {
        self.condition.check_match_exclusivity()
    }

    #[must_use]
    pub(crate) fn check_empty_patterns(&self, _trait_id: &str) -> Option<String> {
        self.condition.check_empty_patterns()
    }

    #[must_use]
    pub(crate) fn check_short_patterns(&self, _trait_id: &str) -> Option<String> {
        self.condition.check_short_patterns()
    }

    #[must_use]
    pub(crate) fn check_literal_regex(&self, _trait_id: &str) -> Option<String> {
        self.condition.check_literal_regex()
    }

    #[must_use]
    pub(crate) fn check_case_insensitive_on_non_alpha(&self, _trait_id: &str) -> Option<String> {
        self.condition.check_case_insensitive_on_non_alpha()
    }

    #[must_use]
    pub(crate) fn check_count_min_value(&self, _trait_id: &str) -> Option<String> {
        // Check count_min on ConditionWithFilters
        if let Some(0) = self.count_min {
            return Some("count_min: 0 is meaningless (default is 1)".to_string());
        }
        // Also check condition-level validation
        self.condition.check_count_min_value()
    }
}

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

    /// File types this trait applies to (defaults to all)
    #[serde(default = "default_file_types")]
    pub r#for: Vec<FileType>,

    // Detection condition with filters - all matching logic in one place
    /// The detection condition with optional filters
    pub r#if: ConditionWithFilters,

    /// String-level exceptions - filter matched strings
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub not: Option<Vec<NotException>>,

    /// File-level skip conditions - composite rule that skips trait if matched
    /// Default semantics: skip if ANY condition matches (unless: [list])
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub unless: Option<Vec<Condition>>,

    /// Criticality downgrade rules - map of target criticality to conditions
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
        self.r#if.condition.set_yara_namespace(ns);
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
        if matches!(self.r#if.condition, Condition::Section { .. }) {
            return None;
        }

        if let (Some(min), Some(max)) = (self.r#if.size_min, self.r#if.size_max) {
            if max < min {
                return Some(format!(
                    "size_max ({}) cannot be less than size_min ({})",
                    max, min
                ));
            }
        }
        None
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

        match &self.r#if.condition {
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
                        NotException::Structured {
                            exact: Some(exc_str),
                            ..
                        } => {
                            if !exc_str.contains(search_substr) {
                                return Some(format!(
                                    "not: exception (exact) '{}' does not contain the search substr '{}' - symbols matching the substr won't match this exception, so it will never be applied",
                                    exc_str, search_substr
                                ));
                            }
                        }
                        NotException::Structured {
                            substr: Some(exc_substr),
                            ..
                        } => {
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
                        NotException::Structured {
                            exact: Some(exc_str),
                            ..
                        } => {
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
            Condition::String {
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
            Condition::String {
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
                        NotException::Structured {
                            exact: Some(exc_str),
                            ..
                        } => {
                            // Exception is exact match - it should contain the search substr
                            if !contains_substr(exc_str, search_substr, case_insensitive) {
                                return Some(format!(
                                    "not: exception (exact) '{}' does not contain the search substr '{}' - strings matching the substr won't match this exception, so it will never be applied",
                                    exc_str, search_substr
                                ));
                            }
                        }
                        NotException::Structured {
                            substr: Some(exc_substr),
                            ..
                        } => {
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
                        NotException::Structured {
                            regex: Some(_exc_regex),
                            ..
                        } => {
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
            Condition::String {
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
                        NotException::Structured {
                            exact: Some(exc_str),
                            ..
                        } => {
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

    /// Evaluate this trait definition against the analysis context
    pub(crate) fn evaluate<'a>(&self, ctx: &EvaluationContext<'a>) -> Option<Finding> {
        use super::debug::{ConditionDebug, DowngradeDebug, SkipReason};

        // Check platform match
        let platform_match = self.platforms.contains(&Platform::All)
            || ctx.platforms.contains(&Platform::All)
            || self.platforms.iter().any(|p| ctx.platforms.contains(p));

        if !platform_match {
            if let Some(collector) = &ctx.debug_collector {
                if let Ok(mut debug) = collector.write() {
                    debug.record_skip(SkipReason::PlatformMismatch {
                        rule: self.platforms.clone(),
                        context: ctx.platforms.clone(),
                    });
                }
            }
            return None;
        }

        // Check file type match
        let file_type_match = self.r#for.contains(&FileType::All)
            || ctx.file_type == FileType::All
            || self.r#for.contains(&ctx.file_type);

        if !file_type_match {
            if let Some(collector) = &ctx.debug_collector {
                if let Ok(mut debug) = collector.write() {
                    debug.record_skip(SkipReason::FileTypeMismatch {
                        rule: self.r#for.clone(),
                        context: ctx.file_type,
                    });
                }
            }
            return None;
        }

        // Check size constraints (from if: block)
        let file_size = ctx.report.target.size_bytes as usize;
        if let Some(min) = self.r#if.size_min {
            if file_size < min {
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        debug.record_skip(SkipReason::SizeTooSmall {
                            actual: file_size,
                            min,
                        });
                    }
                }
                return None;
            }
        }
        if let Some(max) = self.r#if.size_max {
            if file_size > max {
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        debug.record_skip(SkipReason::SizeTooLarge {
                            actual: file_size,
                            max,
                        });
                    }
                }
                return None;
            }
        }

        // Check unless conditions (file-level skip)
        if let Some(unless_conds) = &self.unless {
            // Default 'any' semantics: skip if ANY condition matches
            for condition in unless_conds {
                let result = self.eval_condition(condition, ctx);
                if result.matched {
                    // Record skip reason if debug collector is present
                    if let Some(collector) = &ctx.debug_collector {
                        if let Ok(mut debug) = collector.write() {
                            debug.record_skip(SkipReason::UnlessConditionMatched {
                                condition_desc: format!("{:?}", condition),
                            });
                        }
                    }
                    return None;
                }
            }
        }

        // Evaluate the condition (traits only have one atomic condition) with timeout protection
        let start = Instant::now();
        let result = self.eval_condition(&self.r#if.condition, ctx);
        let duration = start.elapsed();

        // Check for timeout violations (potential anti-analysis technique)
        if duration > MAX_RULE_EVAL_DURATION {
            eprintln!(
                "WARN: Rule {} exceeded timeout: {}ms > {}ms",
                self.id,
                duration.as_millis(),
                MAX_RULE_EVAL_DURATION.as_millis()
            );

            // Return a timeout warning finding instead of the actual result
            // This flags the file as suspicious for causing analysis slowdown
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
                    source: "flayer-evaluator".to_string(),
                    value: format!(
                        "Rule '{}' exceeded {}ms timeout, took {}ms",
                        self.id,
                        MAX_RULE_EVAL_DURATION.as_millis(),
                        duration.as_millis()
                    ),
                    location: None,
                }],
                match_count: 0,
                source_file: get_relative_source_file(&self.defined_in),
            };

            return Some(timeout_warning);
        }

        // Record condition result if debug collector is present
        if let Some(collector) = &ctx.debug_collector {
            if let Ok(mut debug) = collector.write() {
                let cond_debug = ConditionDebug::new(format!("{:?}", self.r#if))
                    .with_matched(result.matched)
                    .with_evidence(result.evidence.clone())
                    .with_precision(result.precision);
                debug.add_condition(cond_debug);
            }
        }

        // Debug: trace evaluation result for eco/npm traits
        if self.id.contains("eco/npm/metadata/vscode") {
            eprintln!(
                "DEBUG evaluate: {} result.matched={} evidence_count={}",
                self.id,
                result.matched,
                result.evidence.len()
            );
        }

        if result.matched {
            // Apply count and density filters (centralized for all condition types)
            // Use match_count which may exceed evidence.len() for high-frequency patterns
            let match_count = result.match_count;
            let file_kb = (file_size as f64) / 1024.0;

            // Check count_min constraint
            if let Some(min) = self.r#if.count_min {
                if match_count < min {
                    if let Some(collector) = &ctx.debug_collector {
                        if let Ok(mut debug) = collector.write() {
                            debug.record_skip(SkipReason::CountBelowMinimum {
                                actual: match_count,
                                min,
                            });
                        }
                    }
                    return None;
                }
            }

            // Check count_max constraint
            if let Some(max) = self.r#if.count_max {
                if match_count > max {
                    if let Some(collector) = &ctx.debug_collector {
                        if let Ok(mut debug) = collector.write() {
                            debug.record_skip(SkipReason::CountAboveMaximum {
                                actual: match_count,
                                max,
                            });
                        }
                    }
                    return None;
                }
            }

            // Check per_kb_min constraint (density threshold)
            if let Some(min_density) = self.r#if.per_kb_min {
                if file_kb > 0.0 {
                    let actual_density = (match_count as f64) / file_kb;
                    if actual_density < min_density {
                        if let Some(collector) = &ctx.debug_collector {
                            if let Ok(mut debug) = collector.write() {
                                debug.record_skip(SkipReason::DensityBelowMinimum {
                                    actual: actual_density,
                                    min: min_density,
                                });
                            }
                        }
                        return None;
                    }
                }
            }

            // Check per_kb_max constraint (density ceiling)
            if let Some(max_density) = self.r#if.per_kb_max {
                if file_kb > 0.0 {
                    let actual_density = (match_count as f64) / file_kb;
                    if actual_density > max_density {
                        if let Some(collector) = &ctx.debug_collector {
                            if let Ok(mut debug) = collector.write() {
                                debug.record_skip(SkipReason::DensityAboveMaximum {
                                    actual: actual_density,
                                    max: max_density,
                                });
                            }
                        }
                        return None;
                    }
                }
            }

            let mut final_crit = self.crit;

            // Check downgrade conditions
            if let Some(downgrade_conds) = &self.downgrade {
                let debug_downgrade = std::env::var("DEBUG_DOWNGRADE").is_ok();
                if debug_downgrade {
                    eprintln!(
                        "DEBUG: Evaluating downgrade for trait '{}' (current: {:?})",
                        self.id, self.crit
                    );
                }
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
                    tracing::debug!(
                        "Downgrade applied: trait '{}' from {:?} → {:?}",
                        self.id,
                        self.crit,
                        final_crit
                    );
                } else {
                    tracing::trace!(
                        "Downgrade NOT applied: trait '{}' downgrade conditions not met",
                        self.id
                    );
                }

                // Record downgrade debug if collector is present
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        debug.set_downgrade(DowngradeDebug {
                            original_crit: self.crit,
                            final_crit,
                            triggered,
                        });
                    }
                }

                if debug_downgrade {
                    eprintln!(
                        "DEBUG: Final criticality for '{}': {:?}",
                        self.id, final_crit
                    );
                }
            }

            // Record match in debug collector
            if let Some(collector) = &ctx.debug_collector {
                if let Ok(mut debug) = collector.write() {
                    debug.matched = true;
                    debug.precision = result.precision;
                }
            }

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

    /// Evaluate a single downgrade condition set
    fn eval_downgrade_conditions<'a>(
        &self,
        conditions: &DowngradeConditions,
        ctx: &EvaluationContext<'a>,
    ) -> bool {
        let debug_downgrade = std::env::var("DEBUG_DOWNGRADE").is_ok();

        // If 'all' is specified, all must match
        if let Some(all_conds) = &conditions.all {
            for cond in all_conds {
                if !self.eval_condition(cond, ctx).matched {
                    return false;
                }
            }
            return true;
        }

        // If 'any' is specified, at least one must match
        if let Some(any_conds) = &conditions.any {
            for (i, cond) in any_conds.iter().enumerate() {
                let result = self.eval_condition(cond, ctx);
                if debug_downgrade {
                    eprintln!(
                        "DEBUG TraitDef: downgrade any[{}] cond={:?} matched={}",
                        i, cond, result.matched
                    );
                }
                if result.matched {
                    return true;
                }
            }
            return false;
        }

        // If 'none' is specified, none can match
        if let Some(none_conds) = &conditions.none {
            for cond in none_conds {
                if self.eval_condition(cond, ctx).matched {
                    return false;
                }
            }
            return true;
        }

        false
    }

    /// Evaluate a single condition
    fn eval_condition<'a>(
        &self,
        condition: &Condition,
        ctx: &EvaluationContext<'a>,
    ) -> ConditionResult {
        match condition {
            Condition::Symbol {
                exact,
                substr,
                regex,
                platforms,
                compiled_regex,
            } => timed_eval!(
                "symbol",
                eval_symbol(
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    platforms.as_ref(),
                    compiled_regex.as_ref(),
                    self.not.as_ref(),
                    ctx,
                )
            ),
            Condition::String {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                external_ip,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                compiled_regex,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    external_ip: *external_ip,
                    compiled_regex: compiled_regex.as_ref(),
                    section: section.as_ref(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                };
                timed_eval!("string", eval_string(&params, self.not.as_ref(), ctx))
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
            } => timed_eval!(
                "import_combo",
                eval_import_combination(
                    required.as_ref(),
                    suspicious.as_ref(),
                    *min_suspicious,
                    *max_total,
                    ctx,
                )
            ),
            Condition::StringCount {
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
                    },
                    ctx,
                )
            ),
            Condition::Raw {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                external_ip,
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
                };
                timed_eval!(
                    "raw",
                    eval_raw(
                        exact.as_ref(),
                        substr.as_ref(),
                        regex.as_ref(),
                        word.as_ref(),
                        *case_insensitive,
                        *external_ip,
                        compiled_regex.as_ref(),
                        self.not.as_ref(),
                        &location,
                        ctx,
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
                        ctx,
                    )
                )
            }
            Condition::Basename {
                exact,
                substr,
                regex,
                case_insensitive,
            } => timed_eval!(
                "basename",
                eval_basename(
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    *case_insensitive,
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

    /// File types this rule applies to (defaults to all)
    #[serde(default = "default_file_types")]
    pub r#for: Vec<FileType>,

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

    /// None of these conditions may match
    #[serde(skip_serializing_if = "Option::is_none")]
    pub none: Option<Vec<Condition>>,

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
}

impl CompositeTrait {
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
        if let Some(ref mut conds) = self.none {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes().with_context(|| {
                    format!(
                        "in composite rule '{}' none condition #{}",
                        self.id,
                        idx + 1
                    )
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
        if let Some(ref mut conds) = self.none {
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
            if let Some(collector) = &ctx.debug_collector {
                if let Ok(mut debug) = collector.write() {
                    debug.record_skip(SkipReason::PlatformMismatch {
                        rule: self.platforms.clone(),
                        context: ctx.platforms.clone(),
                    });
                }
            }
            return None;
        }

        // Check file type match
        let file_type_match = self.r#for.contains(&FileType::All)
            || ctx.file_type == FileType::All
            || self.r#for.contains(&ctx.file_type);

        if !file_type_match {
            if let Some(collector) = &ctx.debug_collector {
                if let Ok(mut debug) = collector.write() {
                    debug.record_skip(SkipReason::FileTypeMismatch {
                        rule: self.r#for.clone(),
                        context: ctx.file_type,
                    });
                }
            }
            return None;
        }

        // Check size constraints
        let file_size = ctx.report.target.size_bytes as usize;
        if let Some(min) = self.size_min {
            if file_size < min {
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        debug.record_skip(SkipReason::SizeTooSmall {
                            actual: file_size,
                            min,
                        });
                    }
                }
                return None;
            }
        }
        if let Some(max) = self.size_max {
            if file_size > max {
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        debug.record_skip(SkipReason::SizeTooLarge {
                            actual: file_size,
                            max,
                        });
                    }
                }
                return None;
            }
        }

        // Check unless conditions (file-level skip)
        if let Some(unless_conds) = &self.unless {
            // Default 'any' semantics: skip if ANY condition matches
            for condition in unless_conds {
                let result = self.eval_condition(condition, ctx);
                if result.matched {
                    if let Some(collector) = &ctx.debug_collector {
                        if let Ok(mut debug) = collector.write() {
                            debug.record_skip(SkipReason::UnlessConditionMatched {
                                condition_desc: format!("{:?}", condition),
                            });
                        }
                    }
                    return None;
                }
            }
        }

        // Start timing for timeout detection
        let start = Instant::now();

        // Evaluate positive conditions based on the boolean operator(s)
        let has_positive = self.all.is_some() || self.any.is_some();

        let positive_result = match (&self.all, &self.any) {
            (Some(all), Some(any)) => {
                // Both all AND any: all must match AND any must match (respecting `needs`)
                let all_result = self.eval_requires_all(all, ctx);
                if !all_result.matched {
                    return None;
                }
                // Handle needs constraint on `any` conditions (same as any-only case)
                let any_result = if let Some(required_count) = self.needs {
                    self.eval_count_constraints(any, None, Some(required_count), None, ctx)
                } else {
                    self.eval_requires_any(any, ctx)
                };
                if !any_result.matched {
                    return None;
                }
                // Combine evidence and trait IDs from both (limited to MAX_EVIDENCE_PER_TRAIT)
                let mut combined_evidence = all_result.evidence;
                combined_evidence.extend(any_result.evidence);
                combined_evidence.truncate(MAX_EVIDENCE_PER_TRAIT);
                let mut combined_trait_ids = all_result.matched_trait_ids;
                combined_trait_ids.extend(any_result.matched_trait_ids);
                let match_count = combined_evidence.len();
                ConditionResult {
                    matched: true,
                    evidence: combined_evidence,
                    match_count,
                    warnings: Vec::new(),
                    precision: 0.0,
                    matched_trait_ids: combined_trait_ids,
                }
            }
            (Some(conds), None) => self.eval_requires_all(conds, ctx),
            (None, Some(conds)) => {
                // Handle needs constraint on `any` conditions
                if let Some(required_count) = self.needs {
                    self.eval_count_constraints(conds, None, Some(required_count), None, ctx)
                } else {
                    self.eval_requires_any(conds, ctx)
                }
            }
            (None, None) => {
                // No positive conditions - will check none below
                ConditionResult {
                    matched: true,
                    evidence: Vec::new(),
                    match_count: 0,
                    warnings: Vec::new(),
                    precision: 0.0,
                    matched_trait_ids: Vec::new(),
                }
            }
        };

        if !positive_result.matched {
            return None;
        }

        // Evaluate none (can be combined with positive conditions)
        // If none is present, none of its conditions can match
        let result = if let Some(ref none_conds) = self.none {
            let none_result = self.eval_requires_none(none_conds, ctx);
            if !none_result.matched {
                return None; // A "none" condition matched, so rule fails
            }
            // Combine evidence (trait_ids come from positive only - none doesn't add refs)
            let mut combined_evidence = positive_result.evidence;
            combined_evidence.extend(none_result.evidence);
            combined_evidence.truncate(MAX_EVIDENCE_PER_TRAIT);
            let match_count = combined_evidence.len();
            ConditionResult {
                matched: true,
                evidence: combined_evidence,
                match_count,
                warnings: Vec::new(),
                precision: 0.0,
                matched_trait_ids: positive_result.matched_trait_ids,
            }
        } else if !has_positive {
            // No positive conditions and no none - invalid rule
            return None;
        } else {
            positive_result
        };

        if result.matched {
            // Check proximity constraints (near_lines, near_bytes)
            let proximity_result = self.check_proximity_constraints(result.evidence.clone());

            // Record proximity debug if applicable
            if self.near_lines.is_some() || self.near_bytes.is_some() {
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        let constraint_type = if self.near_lines.is_some() {
                            "near_lines"
                        } else {
                            "near_bytes"
                        };
                        let max_span = self.near_lines.or(self.near_bytes).unwrap_or(0);
                        debug.set_proximity(ProximityDebug {
                            constraint_type: constraint_type.to_string(),
                            max_span,
                            satisfied: proximity_result.is_some(),
                        });
                    }
                }
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
                let debug_downgrade = std::env::var("DEBUG_DOWNGRADE").is_ok();
                if debug_downgrade {
                    eprintln!(
                        "DEBUG: Evaluating downgrade for composite '{}' (current: {:?})",
                        self.id, self.crit
                    );
                }
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
                if let Some(collector) = &ctx.debug_collector {
                    if let Ok(mut debug) = collector.write() {
                        debug.set_downgrade(DowngradeDebug {
                            original_crit: self.crit,
                            final_crit,
                            triggered,
                        });
                    }
                }

                if debug_downgrade {
                    eprintln!(
                        "DEBUG: Final criticality for composite '{}': {:?}",
                        self.id, final_crit
                    );
                }
            }

            // Record match in debug collector
            if let Some(collector) = &ctx.debug_collector {
                if let Ok(mut debug) = collector.write() {
                    debug.matched = true;
                    debug.precision = result.precision + precision_boost;
                }
            }

            let boosted_conf = (self.conf + precision_boost).min(1.0);

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
                        source: "flayer-evaluator".to_string(),
                        value: format!(
                            "Composite rule '{}' exceeded {}ms timeout, took {}ms",
                            self.id,
                            MAX_RULE_EVAL_DURATION.as_millis(),
                            duration.as_millis()
                        ),
                        location: None,
                    }],
                    match_count: 0,
                source_file: get_relative_source_file(&self.defined_in),
                });
            }

            Some(Finding {
                id: self.id.clone(),
                kind: FindingKind::Capability,
                desc: self.desc.clone(),
                conf: boosted_conf,
                crit: final_crit,
                mbc: self.mbc.clone(),
                attack: self.attack.clone(),
                trait_refs: result.matched_trait_ids.clone(),
                evidence,
                match_count: result.match_count,
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

    /// Evaluate a single downgrade condition set
    fn eval_downgrade_conditions<'a>(
        &self,
        conditions: &DowngradeConditions,
        ctx: &EvaluationContext<'a>,
    ) -> bool {
        let debug_downgrade = std::env::var("DEBUG_DOWNGRADE").is_ok();

        // If 'all' is specified, all must match
        if let Some(all_conds) = &conditions.all {
            for cond in all_conds {
                if !self.eval_condition(cond, ctx).matched {
                    return false;
                }
            }
            return true;
        }

        // If 'any' is specified, at least one must match
        if let Some(any_conds) = &conditions.any {
            for (i, cond) in any_conds.iter().enumerate() {
                let result = self.eval_condition(cond, ctx);
                if debug_downgrade {
                    eprintln!(
                        "DEBUG CompositeTrait: downgrade any[{}] cond={:?} matched={}",
                        i, cond, result.matched
                    );
                }
                if result.matched {
                    return true;
                }
            }
            return false;
        }

        // If 'none' is specified, none can match
        if let Some(none_conds) = &conditions.none {
            for cond in none_conds {
                if self.eval_condition(cond, ctx).matched {
                    return false;
                }
            }
            return true;
        }

        false
    }

    /// Evaluate ALL conditions must match (AND)
    fn eval_requires_all<'a>(
        &self,
        conds: &[Condition],
        ctx: &EvaluationContext<'a>,
    ) -> ConditionResult {
        let mut all_evidence = Vec::new();
        let mut total_precision = 0.0f32;
        let mut all_trait_ids = Vec::new();

        for condition in conds {
            let result = self.eval_condition(condition, ctx);
            if !result.matched {
                return ConditionResult::no_match();
            }
            // Limit evidence to prevent explosion
            if all_evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                let remaining = MAX_EVIDENCE_PER_TRAIT - all_evidence.len();
                all_evidence.extend(result.evidence.into_iter().take(remaining));
            }
            all_trait_ids.extend(result.matched_trait_ids);
            total_precision += result.precision; // SUM for 'all'
        }

        let match_count = all_evidence.len();
        ConditionResult {
            matched: true,
            evidence: all_evidence,
            match_count,
            warnings: Vec::new(),
            precision: total_precision,
            matched_trait_ids: all_trait_ids,
        }
    }

    /// Evaluate at least ONE condition must match (OR)
    /// Collects evidence from ALL matching conditions, not just the first
    fn eval_requires_any<'a>(
        &self,
        conds: &[Condition],
        ctx: &EvaluationContext<'a>,
    ) -> ConditionResult {
        let mut any_matched = false;
        let mut all_evidence = Vec::new();
        let mut all_trait_ids = Vec::new();
        let mut min_precision = f32::MAX;

        for condition in conds {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                any_matched = true;
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

        let match_count = all_evidence.len();
        ConditionResult {
            matched: any_matched,
            evidence: all_evidence,
            match_count,
            warnings: Vec::new(),
            precision,
            matched_trait_ids: all_trait_ids,
        }
    }

    /// Evaluate with count constraints: exact count, min_count, max_count
    fn eval_count_constraints<'a>(
        &self,
        conds: &[Condition],
        exact: Option<usize>,
        min: Option<usize>,
        max: Option<usize>,
        ctx: &EvaluationContext<'a>,
    ) -> ConditionResult {
        let mut matched_count = 0;
        let mut all_evidence = Vec::new();
        let mut all_trait_ids = Vec::new();
        let mut precision_sum = 0.0f32;

        for condition in conds.iter() {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                matched_count += 1;
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

        let evidence_for_result = if matched { all_evidence } else { Vec::new() };
        let match_count_for_result = evidence_for_result.len();
        ConditionResult {
            matched,
            evidence: evidence_for_result,
            match_count: match_count_for_result,
            warnings: Vec::new(),
            precision: avg_precision,
            matched_trait_ids: if matched { all_trait_ids } else { Vec::new() },
        }
    }

    /// Evaluate NONE of the conditions can match (NOT)
    fn eval_requires_none<'a>(
        &self,
        conds: &[Condition],
        ctx: &EvaluationContext<'a>,
    ) -> ConditionResult {
        for condition in conds {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                return ConditionResult::no_match();
            }
        }

        ConditionResult {
            matched: true,
            evidence: vec![Evidence {
                method: "exclusion".to_string(),
                source: "composite_rule".to_string(),
                value: "negative_conditions_not_found".to_string(),
                location: None,
            }],
            match_count: 1,
            warnings: Vec::new(),
            precision: 0.5, // Fixed +0.5 for exclusion logic (negative conditions)
            matched_trait_ids: Vec::new(), // Negative conditions don't contribute trait refs
        }
    }

    /// Evaluate a single condition
    fn eval_condition<'a>(
        &self,
        condition: &Condition,
        ctx: &EvaluationContext<'a>,
    ) -> ConditionResult {
        match condition {
            Condition::Symbol {
                exact,
                substr,
                regex,
                platforms,
                compiled_regex,
            } => self.eval_symbol(
                exact.as_ref(),
                substr.as_ref(),
                regex.as_ref(),
                platforms.as_ref(),
                compiled_regex.as_ref(),
                ctx,
            ),
            Condition::String {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                external_ip,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                compiled_regex,
            } => {
                let params = StringParams {
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    external_ip: *external_ip,
                    compiled_regex: compiled_regex.as_ref(),
                    section: section.as_ref(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                };
                eval_string(&params, self.not.as_ref(), ctx)
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
            } => timed_eval!(
                "import_combo",
                eval_import_combination(
                    required.as_ref(),
                    suspicious.as_ref(),
                    *min_suspicious,
                    *max_total,
                    ctx,
                )
            ),
            Condition::StringCount {
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
                    },
                    ctx,
                )
            ),
            Condition::Raw {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                external_ip,
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
                };
                timed_eval!(
                    "raw",
                    eval_raw(
                        exact.as_ref(),
                        substr.as_ref(),
                        regex.as_ref(),
                        word.as_ref(),
                        *case_insensitive,
                        *external_ip,
                        compiled_regex.as_ref(),
                        self.not.as_ref(),
                        &location,
                        ctx,
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
                        ctx,
                    )
                )
            }
            Condition::Basename {
                exact,
                substr,
                regex,
                case_insensitive,
            } => timed_eval!(
                "basename",
                eval_basename(
                    exact.as_ref(),
                    substr.as_ref(),
                    regex.as_ref(),
                    *case_insensitive,
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
    fn eval_symbol<'a>(
        &self,
        exact: Option<&String>,
        substr: Option<&String>,
        pattern: Option<&String>,
        platforms: Option<&Vec<Platform>>,
        compiled_regex: Option<&regex::Regex>,
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

        eval_symbol(exact, substr, pattern, None, compiled_regex, None, ctx)
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

    /// Check if evidence satisfies proximity constraints
    /// Returns None if constraints fail, otherwise returns the filtered evidence
    fn check_proximity_constraints(&self, evidence: Vec<Evidence>) -> Option<Vec<Evidence>> {
        // If no proximity constraints, pass through
        if self.near_lines.is_none() && self.near_bytes.is_none() {
            return Some(evidence);
        }

        // Get the minimum required matches (needs or 1)
        let min_required = self.needs.unwrap_or(1).max(1);

        // Check near_lines constraint
        if let Some(max_line_span) = self.near_lines {
            if !self.evidence_within_line_range(&evidence, max_line_span, min_required) {
                return None;
            }
        }

        // Check near_bytes constraint
        if let Some(max_byte_span) = self.near_bytes {
            if !self.evidence_within_byte_range(&evidence, max_byte_span, min_required) {
                return None;
            }
        }

        Some(evidence)
    }

    /// Check if at least min_required evidence items have line numbers within max_line_span
    /// Location format is "line:column" (e.g., "42:5")
    fn evidence_within_line_range(
        &self,
        evidence: &[Evidence],
        max_line_span: usize,
        min_required: usize,
    ) -> bool {
        // Extract line numbers from evidence
        let mut line_numbers: Vec<usize> = evidence
            .iter()
            .filter_map(|e| {
                e.location.as_ref().and_then(|loc| {
                    loc.split(':')
                        .next()
                        .and_then(|line_str| line_str.parse::<usize>().ok())
                })
            })
            .collect();

        if line_numbers.len() < min_required {
            return false; // Not enough evidence with line numbers
        }

        // Sort to find the smallest window
        line_numbers.sort_unstable();

        // Check all possible windows of size max_line_span to see if we can fit min_required items
        for i in 0..line_numbers.len() {
            let start_line = line_numbers[i];
            let mut count = 0;
            for &line in line_numbers[i..].iter() {
                if line - start_line <= max_line_span {
                    count += 1;
                    if count >= min_required {
                        return true;
                    }
                } else {
                    break;
                }
            }
        }

        false
    }

    /// Check if at least min_required evidence items have byte offsets within max_byte_span
    /// Location format can be "line:column" where we extract the byte offset, or direct byte offsets
    fn evidence_within_byte_range(
        &self,
        evidence: &[Evidence],
        max_byte_span: usize,
        min_required: usize,
    ) -> bool {
        // Extract byte offsets from evidence
        let mut byte_offsets: Vec<usize> = evidence
            .iter()
            .filter_map(|e| {
                e.location.as_ref().and_then(|loc| {
                    // Try to parse as direct byte offset first
                    if let Ok(offset) = loc.parse::<usize>() {
                        return Some(offset);
                    }
                    // Otherwise try "line:column" format - column is often byte position within line
                    loc.split(':')
                        .nth(1)
                        .and_then(|col_str| col_str.parse::<usize>().ok())
                })
            })
            .collect();

        if byte_offsets.len() < min_required {
            return false; // Not enough evidence with byte offsets
        }

        // Sort to find the smallest window
        byte_offsets.sort_unstable();

        // Check all possible windows of size max_byte_span
        for i in 0..byte_offsets.len() {
            let start_offset = byte_offsets[i];
            let mut count = 0;
            for &offset in byte_offsets[i..].iter() {
                if offset - start_offset <= max_byte_span {
                    count += 1;
                    if count >= min_required {
                        return true;
                    }
                } else {
                    break;
                }
            }
        }

        false
    }

    /// Returns true if this rule has negative (none) conditions
    #[must_use]
    pub(crate) fn has_negative_conditions(&self) -> bool {
        self.none.as_ref().map(|n| !n.is_empty()).unwrap_or(false)
    }
}
