//! Evaluation context and result types for composite rules.

use super::condition::StringValidator;
use super::debug::{DebugCollector, EvaluationDebug, SkipReason};
use super::evaluators::kv::StructuredFormat;
use super::section_map::SectionMap;
use super::types::{Arch, FileType, Platform};
use crate::types::{AnalysisReport, Evidence, Finding};
use rustc_hash::{FxHashMap, FxHashSet};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use crate::hash_str;

/// Context for evaluating composite rules
#[derive(Debug, Clone)]
pub(crate) struct EvaluationContext<'a> {
    /// The analysis report produced for this file
    pub report: &'a AnalysisReport,
    /// Raw binary data of the file being analyzed
    pub binary_data: &'a [u8],
    /// Detected file type
    pub file_type: FileType,
    /// Platform filter(s) from CLI - rules match if their platforms intersect with these
    pub platforms: &'a [Platform],
    /// CPU architecture(s) of the file being analyzed (derived from report.target.architectures)
    pub arch: Arc<[Arch]>,
    /// Additional findings from previous evaluation iterations (for composite chaining)
    pub additional_findings: Option<&'a [Finding]>,
    /// Cached parsed AST (to avoid re-parsing for each ast_pattern trait)
    pub cached_ast: Option<&'a tree_sitter::Tree>,
    /// Cached index of finding ID hashes for fast O(1) trait lookups.
    pub finding_id_index: Option<Arc<FxHashSet<u64>>>,
    /// Optional debug collector - None for hot path, Some during test-rules
    pub debug_collector: Option<&'a DebugCollector>,
    /// Section map for location-constrained matching (lazy-initialized)
    pub section_map: Option<&'a SectionMap>,
    /// Pre-scanned inline YARA results from the combined engine
    pub inline_yara_results: Option<&'a HashMap<String, Vec<Evidence>>>,
    /// Cached detected format for KV evaluations (detect once per file)
    pub cached_kv_format: Arc<OnceLock<StructuredFormat>>,
    /// Cached parsed KV data (parse once per file, reuse for all KV conditions)
    pub cached_kv_parsed: Arc<OnceLock<Box<Value>>>,
    /// Cached map of structured-key dotted path → byte offset in the raw file,
    /// built once per file (lazily, only when a KV match needs to anchor) so
    /// value-match findings carry a real location instead of re-scanning the
    /// content per match. Empty for formats without an offset indexer.
    pub cached_kv_offsets: Arc<OnceLock<FxHashMap<String, u64>>>,
    /// Cached AST nodes by kind (for batch evaluation)
    pub ast_kind_cache: Option<&'a FxHashMap<String, Vec<Evidence>>>,
    /// Index for O(1) exact string lookups. Values are indices into
    /// `report.strings` (not cloned strings) — the source is always
    /// `string_extractor` and the value/offset are looked up from the entry, so
    /// we don't duplicate every extracted string into the index.
    pub string_exact_index: Arc<OnceLock<FxHashMap<String, Vec<u32>>>>,
    /// Index for O(1) case-insensitive exact lookups (key = lowercased value,
    /// values = `report.strings` indices).
    pub string_exact_index_ci: Arc<OnceLock<FxHashMap<String, Vec<u32>>>>,
    /// Lazily-built list of `report.strings` indices whose value is a decoded
    /// layer (non-empty `encoding_chain`). `type: text`'s second pass scans only
    /// these so a pattern can match content that appears only after base64/xor/…
    /// decoding — e.g. a `jsonkeeper.com` URL hidden in a base64 literal —
    /// without the raw pass ever seeing it. Built once per file; empty (the
    /// common case) makes the encoded pass a single is-empty check.
    pub encoded_string_indices: Arc<OnceLock<Vec<u32>>>,
    /// Hard deadline for rule evaluation.
    pub deadline: Option<Instant>,
    /// Cooperative cancellation flag (set by litmus timeout).
    pub cancellation: Option<&'a std::sync::atomic::AtomicBool>,
    /// Per-architecture byte ranges for fat/universal binaries.
    pub arch_ranges: Option<&'a [(Arch, std::ops::Range<usize>)]>,
    /// Warn threshold for slow rule evaluation in milliseconds
    pub slow_rule_ms: u64,
    /// Pre-computed evidence from indexed string/symbol matching
    pub cached_evidence: Option<&'a FxHashMap<usize, Vec<Evidence>>>,
    /// Current trait index being evaluated
    pub current_trait_idx: Option<usize>,
    /// Validated UTF-8 view of `binary_data`, populated once per file for source-code
    /// file types. Lets AST/text evaluators skip the per-rule O(N) `from_utf8` check.
    pub cached_source_utf8: Option<&'a str>,
    /// Whole-`binary_data` ASCII-lowercased once and shared (via the `Arc`)
    /// across every case-insensitive raw/text condition on this file. ASCII
    /// lowercasing is byte-position-preserving, so any search sub-range maps to
    /// the same range of this buffer (see [`Self::lower_binary`]).
    pub cached_lower_binary: Arc<OnceLock<Vec<u8>>>,
    /// True while evaluating a `crit: exception` composite. A directory trait
    /// reference normally excludes `crit: exception` members (so dropping an
    /// `objectives/` directory into `all:`/`any:` can't inherit a suppressor), but
    /// an exception composite is allowed to assemble a directory of exceptions, so
    /// this re-includes them for that case. See [`super::evaluators::misc::eval_trait`].
    pub parent_is_exception: bool,
}

impl<'a> EvaluationContext<'a> {
    /// Create a new evaluation context
    #[must_use]
    pub(crate) fn new(
        report: &'a AnalysisReport,
        binary_data: &'a [u8],
        file_type: FileType,
        platforms: &'a [Platform],
        additional_findings: Option<&'a [Finding]>,
        cached_ast: Option<&'a tree_sitter::Tree>,
    ) -> Self {
        let mut index = FxHashSet::default();
        for finding in &report.findings {
            index.insert(hash_str(&finding.id));
        }
        if let Some(additional) = additional_findings {
            for finding in additional {
                index.insert(hash_str(&finding.id));
            }
        }

        let arch: Arc<[Arch]> = report
            .target
            .architectures
            .as_ref()
            .map(|archs| {
                archs
                    .iter()
                    .map(|a| Arch::from_report_str(a))
                    .collect::<Vec<_>>()
                    .into()
            })
            .unwrap_or_else(|| vec![Arch::All].into());

        // Pre-validate UTF-8 once for source-code file types. AST/text evaluators
        // otherwise re-run from_utf8 on the full file for every rule they touch,
        // which dominates CPU time on large source archives.
        let cached_source_utf8 = if file_type.uses_raw_text_search() {
            std::str::from_utf8(binary_data).ok()
        } else {
            None
        };

        Self {
            report,
            binary_data,
            file_type,
            platforms,
            arch,
            additional_findings,
            cached_ast,
            finding_id_index: Some(Arc::new(index)),
            debug_collector: None,
            section_map: None,
            inline_yara_results: None,
            cached_kv_format: Arc::new(OnceLock::new()),
            cached_kv_parsed: Arc::new(OnceLock::new()),
            cached_kv_offsets: Arc::new(OnceLock::new()),
            cached_lower_binary: Arc::new(OnceLock::new()),
            ast_kind_cache: None,
            string_exact_index: Arc::new(OnceLock::new()),
            string_exact_index_ci: Arc::new(OnceLock::new()),
            encoded_string_indices: Arc::new(OnceLock::new()),
            deadline: None,
            cancellation: None,
            arch_ranges: None,
            slow_rule_ms: 4000,
            cached_evidence: None,
            current_trait_idx: None,
            cached_source_utf8,
            parent_is_exception: false,
        }
    }

    /// Set the slow rule threshold
    pub(crate) fn with_slow_rule_ms(mut self, slow_rule_ms: u64) -> Self {
        self.slow_rule_ms = slow_rule_ms;
        self
    }

    /// Mark (or unmark) that the rule currently being evaluated is a
    /// `crit: exception` composite, so directory references may reach exceptions.
    pub(crate) fn with_parent_exception(mut self, parent_is_exception: bool) -> Self {
        self.parent_is_exception = parent_is_exception;
        self
    }

    /// Set the AST kind cache
    pub(crate) fn with_ast_kind_cache(
        mut self,
        cache: &'a FxHashMap<String, Vec<Evidence>>,
    ) -> Self {
        self.ast_kind_cache = Some(cache);
        self
    }

    /// Set the deadline
    pub(crate) fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Set the cooperative cancellation flag.
    pub(crate) fn with_cancellation(mut self, flag: &'a std::sync::atomic::AtomicBool) -> Self {
        self.cancellation = Some(flag);
        self
    }

    /// Returns true if cancellation has been requested.
    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancellation
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Set the inline YARA results
    pub(crate) fn with_inline_yara(mut self, results: &'a HashMap<String, Vec<Evidence>>) -> Self {
        self.inline_yara_results = Some(results);
        self
    }

    /// Set the section map
    pub(crate) fn with_section_map(mut self, section_map: &'a SectionMap) -> Self {
        self.section_map = Some(section_map);
        self
    }

    /// Attach per-architecture byte ranges for fat/universal binary evaluation.
    #[must_use]
    pub(crate) fn with_arch_ranges(mut self, ranges: &'a [(Arch, std::ops::Range<usize>)]) -> Self {
        self.arch_ranges = Some(ranges);
        self
    }

    /// Set the cached evidence from indexed matching
    #[must_use]
    pub(crate) fn with_cached_evidence(
        mut self,
        evidence: Option<&'a FxHashMap<usize, Vec<Evidence>>>,
    ) -> Self {
        self.cached_evidence = evidence;
        self
    }

    /// Set the current trait index being evaluated
    #[must_use]
    pub(crate) fn with_trait_idx(mut self, idx: usize) -> Self {
        self.current_trait_idx = Some(idx);
        self
    }

    /// Set additional findings and rebuild index
    #[must_use]
    #[cfg(test)]
    pub(crate) fn with_additional_findings(mut self, findings: &'a [Finding]) -> Self {
        self.additional_findings = Some(findings);
        let mut index = FxHashSet::default();
        for finding in &self.report.findings {
            index.insert(hash_str(&finding.id));
        }
        for finding in findings {
            index.insert(hash_str(&finding.id));
        }
        self.finding_id_index = Some(Arc::new(index));
        self
    }

    /// Compute the search clamp range for a trait with a specific arch restriction.
    #[must_use]
    pub(crate) fn arch_clamp_range(&self, trait_arch: &[Arch]) -> Option<(usize, usize)> {
        let ranges = self.arch_ranges.as_ref()?;
        if trait_arch.contains(&Arch::All) {
            return None;
        }
        let mut clamp_start = usize::MAX;
        let mut clamp_end = 0usize;
        for (arch, range) in *ranges {
            if trait_arch.contains(arch) {
                clamp_start = clamp_start.min(range.start);
                clamp_end = clamp_end.max(range.end);
            }
        }
        if clamp_start < clamp_end {
            Some((clamp_start, clamp_end))
        } else {
            None
        }
    }

    /// Get or build the exact string index for O(1) lookups. Only `report.strings`
    /// is indexed (the only consumer, `eval_text` exact, ignores import/export
    /// entries); values are `report.strings` indices, not cloned strings.
    /// The whole `binary_data` ASCII-lowercased, built once and shared across
    /// every case-insensitive raw/text condition. Because ASCII lowercasing
    /// preserves byte positions, callers slice this by the same `[start..end]`
    /// they would have applied to `binary_data`.
    pub(crate) fn lower_binary(&self) -> &[u8] {
        self.cached_lower_binary
            .get_or_init(|| self.binary_data.to_ascii_lowercase())
    }

    pub(crate) fn get_string_exact_index(&self) -> &FxHashMap<String, Vec<u32>> {
        self.string_exact_index.get_or_init(|| {
            let mut index: FxHashMap<String, Vec<u32>> = FxHashMap::default();
            for (i, s) in self.report.strings.iter().enumerate() {
                index
                    .entry(s.value.as_str().to_string())
                    .or_default()
                    .push(i as u32);
            }
            index
        })
    }

    /// Get or build the case-insensitive exact string index (key = lowercased
    /// value, values = `report.strings` indices).
    pub(crate) fn get_string_exact_index_ci(&self) -> &FxHashMap<String, Vec<u32>> {
        self.string_exact_index_ci.get_or_init(|| {
            let mut index: FxHashMap<String, Vec<u32>> = FxHashMap::default();
            for (i, s) in self.report.strings.iter().enumerate() {
                index
                    .entry(s.value.to_lowercase())
                    .or_default()
                    .push(i as u32);
            }
            index
        })
    }

    /// Get or build the list of `report.strings` indices that carry a decoded
    /// encoding layer (non-empty `encoding_chain`). `type: text`'s encoded pass
    /// scans only these; see [`Self::encoded_string_indices`]. The result is
    /// usually empty, so callers should gate on `is_empty()` before resolving a
    /// matcher.
    pub(crate) fn encoded_strings(&self) -> &[u32] {
        self.encoded_string_indices.get_or_init(|| {
            self.report
                .strings
                .iter()
                .enumerate()
                .filter(|(_, s)| !s.encoding_chain.is_empty())
                .map(|(i, _)| i as u32)
                .collect()
        })
    }

    /// Run a closure against the debug collector if one is present.
    pub(crate) fn with_debug(&self, f: impl FnOnce(&mut EvaluationDebug)) {
        if let Some(collector) = self.debug_collector
            && let Ok(mut debug) = collector.write()
        {
            f(&mut debug);
        }
    }

    /// Record a skip reason to the debug collector if one is present.
    pub(crate) fn record_skip(&self, reason: SkipReason) {
        self.with_debug(|debug| debug.record_skip(reason));
    }

    /// Check if a finding ID exists (exact match only)
    #[must_use]
    pub(crate) fn has_finding_exact(&self, id: &str) -> bool {
        if let Some(ref index) = self.finding_id_index
            && !index.contains(&hash_str(id))
        {
            return false;
        }
        self.report.findings.iter().any(|f| f.id == id)
            || self
                .additional_findings
                .map(|af| af.iter().any(|f| f.id == id))
                .unwrap_or(false)
    }

    /// Create a dummy context for tests
    #[cfg(test)]
    #[must_use]
    pub(crate) fn test_only_new(
        report: &'a AnalysisReport,
        binary_data: &'a [u8],
        file_type: FileType,
    ) -> Self {
        Self {
            report,
            binary_data,
            file_type,
            platforms: &[],
            arch: vec![Arch::All].into(),
            additional_findings: None,
            cached_ast: None,
            finding_id_index: None,
            debug_collector: None,
            section_map: None,
            inline_yara_results: None,
            cached_kv_format: Arc::new(OnceLock::new()),
            cached_kv_parsed: Arc::new(OnceLock::new()),
            cached_kv_offsets: Arc::new(OnceLock::new()),
            cached_lower_binary: Arc::new(OnceLock::new()),
            ast_kind_cache: None,
            string_exact_index: Arc::new(OnceLock::new()),
            string_exact_index_ci: Arc::new(OnceLock::new()),
            encoded_string_indices: Arc::new(OnceLock::new()),
            deadline: None,
            cancellation: None,
            arch_ranges: None,
            slow_rule_ms: 4000,
            cached_evidence: None,
            current_trait_idx: None,
            cached_source_utf8: None,
            parent_is_exception: false,
        }
    }
}

/// Warning types for anti-analysis detection
#[derive(Debug, Clone)]
pub(crate) enum AnalysisWarning {
    AstTooDeep { max_depth: usize },
    AstParseError,
    AstQueryLimited { limit: usize },
    PatternTruncated { pattern: String, limit: usize },
}

impl std::fmt::Display for AnalysisWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AstTooDeep { max_depth } => {
                write!(f, "AST nesting limit hit (depth: {})", max_depth)
            }
            Self::AstParseError => {
                write!(f, "AST has parse errors (results may be incomplete)")
            }
            Self::AstQueryLimited { limit } => {
                write!(f, "AST query match limit hit (limit: {})", limit)
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
#[derive(Debug, Clone, Default)]
pub(crate) struct ConditionResult {
    pub matched: bool,
    pub evidence: Vec<Evidence>,
    pub match_count: usize,
    pub warnings: Vec<AnalysisWarning>,
    pub precision: f32,
    pub matched_trait_ids: Vec<String>,
}

impl ConditionResult {
    #[must_use]
    pub(crate) fn no_match() -> Self {
        Self::default()
    }

    #[must_use]
    pub(crate) fn matched_with(evidence: Vec<Evidence>) -> Self {
        let count = evidence.len();
        Self {
            matched: true,
            evidence,
            match_count: count,
            ..Default::default()
        }
    }
}

/// Parameters for string condition evaluation
#[derive(Debug)]
pub(crate) struct StringParams<'a> {
    pub exact: Option<&'a String>,
    pub substr: Option<&'a String>,
    pub regex: Option<&'a String>,
    pub word: Option<&'a String>,
    pub case_insensitive: bool,
    /// For CI conditions this finder was built from the lowercased pattern.
    pub is_check: Option<StringValidator>,
    pub section: Option<&'a String>,
    pub offset: Option<i64>,
    pub offset_range: Option<(i64, Option<i64>)>,
    pub section_offset: Option<i64>,
    pub section_offset_range: Option<(i64, Option<i64>)>,
    pub arch_clamp: Option<(usize, usize)>,
}
