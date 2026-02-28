//! Evaluation context and result types for composite rules.

use super::debug::DebugCollector;
use super::evaluators::kv::StructuredFormat;
use super::section_map::SectionMap;
use super::types::{FileType, Platform};
use crate::types::{AnalysisReport, Evidence, Finding};
use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use serde_json::Value;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::OnceLock;

/// Compute a fast hash of a string for deduplication.
#[inline]
fn hash_str(s: &str) -> u64 {
    let mut hasher = FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}

/// Context for evaluating composite rules
#[derive(Debug)]
pub(crate) struct EvaluationContext<'a> {
    /// The analysis report produced for this file
    pub report: &'a AnalysisReport,
    /// Raw binary data of the file being analyzed
    pub binary_data: &'a [u8],
    /// Detected file type
    pub file_type: FileType,
    /// Platform filter(s) from CLI - rules match if their platforms intersect with these
    pub platforms: Vec<Platform>,
    /// Additional findings from previous evaluation iterations (for composite chaining)
    pub additional_findings: Option<&'a [Finding]>,
    /// Cached parsed AST (to avoid re-parsing for each ast_pattern trait)
    pub cached_ast: Option<&'a tree_sitter::Tree>,
    /// Cached index of finding ID hashes for fast O(1) trait lookups.
    /// Stores u64 hashes instead of String to avoid cloning finding IDs.
    pub finding_id_index: Option<FxHashSet<u64>>,
    /// Optional debug collector - None for hot path, Some during test-rules
    /// When present, evaluation records detailed debug info
    pub debug_collector: Option<&'a DebugCollector>,
    /// Section map for location-constrained matching (lazy-initialized)
    pub section_map: Option<SectionMap>,
    /// Pre-scanned inline YARA results from the combined engine, keyed by namespace
    /// (`"inline.{trait_id}"`). When present, YARA condition evaluation uses this
    /// map instead of re-scanning with per-condition compiled rules.
    pub inline_yara_results: Option<&'a HashMap<String, Vec<Evidence>>>,
    /// Cached detected format for KV evaluations (detect once per file)
    pub cached_kv_format: OnceLock<StructuredFormat>,
    /// Cached parsed KV data (parse once per file, reuse for all KV conditions)
    pub cached_kv_parsed: OnceLock<Box<Value>>,
    /// Current trait being evaluated (for warning/error context)
    pub current_trait: Option<&'a str>,
    /// Source file of the current trait (for warning/error context)
    #[allow(dead_code)] // Populated during eval, intended for future logging
    pub current_source: Option<&'a str>,
    /// Index for O(1) exact string lookups: string value -> vec of (source, offset)
    /// Includes report.strings, imports, and exports. Lazy-initialized on first use.
    pub string_exact_index: OnceLock<FxHashMap<String, Vec<(String, Option<u64>)>>>,
    /// Index for O(1) case-insensitive exact lookups: lowercased value -> vec of (original, source, offset)
    /// Lazy-initialized on first use.
    pub string_exact_index_ci: OnceLock<FxHashMap<String, Vec<(String, String, Option<u64>)>>>,
}

impl<'a> EvaluationContext<'a> {
    /// Create a new evaluation context
    #[must_use]
    pub(crate) fn new(
        report: &'a AnalysisReport,
        binary_data: &'a [u8],
        file_type: FileType,
        platforms: Vec<Platform>,
        additional_findings: Option<&'a [Finding]>,
        cached_ast: Option<&'a tree_sitter::Tree>,
    ) -> Self {
        // Build finding ID hash index for fast O(1) trait lookups.
        // We store hashes instead of cloning the full ID strings.
        let mut index = FxHashSet::default();
        for finding in &report.findings {
            index.insert(hash_str(&finding.id));
        }
        if let Some(additional) = additional_findings {
            for finding in additional {
                index.insert(hash_str(&finding.id));
            }
        }

        Self {
            report,
            binary_data,
            file_type,
            platforms,
            additional_findings,
            cached_ast,
            finding_id_index: Some(index),
            debug_collector: None,
            section_map: None,
            inline_yara_results: None,
            cached_kv_format: OnceLock::new(),
            cached_kv_parsed: OnceLock::new(),
            current_trait: None,
            current_source: None,
            string_exact_index: OnceLock::new(),
            string_exact_index_ci: OnceLock::new(),
        }
    }

    /// Get or build the exact string index for O(1) lookups
    pub(crate) fn get_string_exact_index(&self) -> &FxHashMap<String, Vec<(String, Option<u64>)>> {
        self.string_exact_index.get_or_init(|| {
            let mut index: FxHashMap<String, Vec<(String, Option<u64>)>> = FxHashMap::default();

            // Index strings from report
            for s in &self.report.strings {
                index
                    .entry(s.value.clone())
                    .or_default()
                    .push(("string_extractor".to_string(), s.offset));
            }

            // Index imports
            for import in &self.report.imports {
                index
                    .entry(import.symbol.clone())
                    .or_default()
                    .push((import.source.clone(), None));
            }

            // Index exports
            for export in &self.report.exports {
                let offset = export.offset.as_ref().and_then(|s| {
                    s.strip_prefix("0x")
                        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                });
                index
                    .entry(export.symbol.clone())
                    .or_default()
                    .push((export.source.clone(), offset));
            }

            index
        })
    }

    /// Get or build the case-insensitive exact string index for O(1) lookups
    pub(crate) fn get_string_exact_index_ci(
        &self,
    ) -> &FxHashMap<String, Vec<(String, String, Option<u64>)>> {
        self.string_exact_index_ci.get_or_init(|| {
            let mut index: FxHashMap<String, Vec<(String, String, Option<u64>)>> =
                FxHashMap::default();

            // Index strings from report
            for s in &self.report.strings {
                index.entry(s.value.to_lowercase()).or_default().push((
                    s.value.clone(),
                    "string_extractor".to_string(),
                    s.offset,
                ));
            }

            // Index imports
            for import in &self.report.imports {
                index
                    .entry(import.symbol.to_lowercase())
                    .or_default()
                    .push((import.symbol.clone(), import.source.clone(), None));
            }

            // Index exports
            for export in &self.report.exports {
                let offset = export.offset.as_ref().and_then(|s| {
                    s.strip_prefix("0x")
                        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
                });
                index
                    .entry(export.symbol.to_lowercase())
                    .or_default()
                    .push((export.symbol.clone(), export.source.clone(), offset));
            }

            index
        })
    }

    /// Set section map for location-constrained matching
    #[must_use]
    pub(crate) fn with_section_map(mut self, section_map: SectionMap) -> Self {
        self.section_map = Some(section_map);
        self
    }

    /// Attach pre-scanned inline YARA results from the combined engine.
    /// Keyed by namespace (`"inline.{trait_id}"`); maps to matched evidence.
    #[must_use]
    pub(crate) fn with_inline_yara(mut self, results: &'a HashMap<String, Vec<Evidence>>) -> Self {
        self.inline_yara_results = Some(results);
        self
    }

    /// Check if a finding ID exists (exact match only, O(1))
    #[must_use]
    pub(crate) fn has_finding_exact(&self, id: &str) -> bool {
        if let Some(ref index) = self.finding_id_index {
            index.contains(&hash_str(id))
        } else {
            // Fallback to linear search if index not built
            self.report.findings.iter().any(|f| f.id == id)
                || self
                    .additional_findings
                    .map(|af| af.iter().any(|f| f.id == id))
                    .unwrap_or(false)
        }
    }
}

/// Warning types for anti-analysis detection
#[derive(Debug, Clone)]
pub(crate) enum AnalysisWarning {
    /// AST depth limit hit - potential recursion bomb
    AstTooDeep {
        /// Maximum depth that was configured
        max_depth: usize,
    },
    /// Pattern had excessive matches - truncated to prevent memory exhaustion
    PatternTruncated {
        /// The pattern that was truncated
        pattern: String,
        /// Maximum matches allowed
        limit: usize,
    },
}

impl std::fmt::Display for AnalysisWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AstTooDeep { max_depth } => {
                write!(f, "AST nesting limit hit (depth: {})", max_depth)
            }
            Self::PatternTruncated { pattern, limit } => {
                write!(
                    f,
                    "Pattern '{}' matched {}+ times, truncated",
                    pattern, limit
                )
            }
        }
    }
}

/// Result of evaluating a condition
#[derive(Debug)]
pub(crate) struct ConditionResult {
    /// Whether the condition matched the file
    pub matched: bool,
    /// Evidence items collected when condition matched (capped at 128 for memory)
    pub evidence: Vec<Evidence>,
    /// Total match count for density/count constraints (may exceed evidence.len())
    pub match_count: usize,
    /// Anti-analysis warnings (recursion bombs, etc.)
    #[allow(dead_code)] // Populated during rule evaluation, read by binary target
    pub warnings: Vec<AnalysisWarning>,
    /// Precision points contributed by this condition (higher = more specific)
    pub precision: f32,
    /// IDs of traits that matched (for populating Finding::trait_refs)
    pub matched_trait_ids: Vec<String>,
}

impl Default for ConditionResult {
    fn default() -> Self {
        Self {
            matched: false,
            evidence: Vec::new(),
            match_count: 0,
            warnings: Vec::new(),
            precision: 0.0,
            matched_trait_ids: Vec::new(),
        }
    }
}

impl ConditionResult {
    /// Create a non-matching result with no evidence
    #[must_use]
    pub(crate) fn no_match() -> Self {
        Self {
            matched: false,
            evidence: Vec::new(),
            match_count: 0,
            warnings: Vec::new(),
            precision: 0.0,
            matched_trait_ids: Vec::new(),
        }
    }

    /// Create a matching result with the given evidence
    #[must_use]
    pub(crate) fn matched_with(evidence: Vec<Evidence>) -> Self {
        let count = evidence.len();
        Self {
            matched: true,
            evidence,
            match_count: count,
            warnings: Vec::new(),
            precision: 0.0,
            matched_trait_ids: Vec::new(),
        }
    }

    /// Create a matching result with separate count (for high-frequency patterns)
    #[allow(dead_code)] // Available for evaluators that track count separately
    #[must_use]
    pub(crate) fn matched_with_count(evidence: Vec<Evidence>, match_count: usize) -> Self {
        Self {
            matched: true,
            evidence,
            match_count,
            warnings: Vec::new(),
            precision: 0.0,
            matched_trait_ids: Vec::new(),
        }
    }
}

/// Parameters for string condition evaluation (reduces argument count)
#[derive(Debug)]
pub(crate) struct StringParams<'a> {
    /// Require exact string equality
    pub exact: Option<&'a String>,
    /// Require the string to contain this substring
    pub substr: Option<&'a String>,
    /// Require the string to match this regex pattern
    pub regex: Option<&'a String>,
    /// Require the string to match this whole-word pattern
    pub word: Option<&'a String>,
    /// If true, perform case-insensitive matching
    pub case_insensitive: bool,
    /// Pre-compiled regex from the `regex` field
    pub compiled_regex: Option<&'a regex::Regex>,
    /// When true, require matched string to contain a valid external IP address
    pub external_ip: bool,
    /// Section constraint: only match strings in this section (supports fuzzy names)
    pub section: Option<&'a String>,
    /// Absolute file offset: only match at this exact byte position (negative = from end)
    pub offset: Option<i64>,
    /// Absolute offset range: [start, end) (negative values resolved from file end)
    pub offset_range: Option<(i64, Option<i64>)>,
    /// Section-relative offset: only match at this offset within the section
    pub section_offset: Option<i64>,
    /// Section-relative offset range: [start, end) within section bounds
    pub section_offset_range: Option<(i64, Option<i64>)>,
}
