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

/// Every finding an evaluation may match against, as one value.
///
/// Two sources feed it: the report's own findings, and findings that are not on
/// the report — the output of an earlier fixed-point iteration, or an archive's
/// member findings raised into container scope. Consumers only ever want the
/// union, so the union is what this hands out. As two separate fields, every
/// read site re-derived that union by hand; a site that forgot the second half
/// produced a silent detection miss in precisely the cases hardest to notice
/// (container and fixed-point evaluation, never a plain single-file scan).
#[derive(Debug, Clone)]
pub(crate) struct FindingScope<'a> {
    own: &'a [Finding],
    /// Findings inserted between `own` and `extra` in scope order. Used by the
    /// container cross-scope reeval, where each member's own findings join a
    /// scope whose other two halves are shared across all members — carrying
    /// them as a third borrowed slice replaces a per-member deep clone of the
    /// container snapshot (Finding + Evidence vectors × member count).
    mid: &'a [Finding],
    extra: &'a [Finding],
    /// Hashed ids of all halves, so a lookup for an id nothing produced costs
    /// one hash instead of a full scan. `None` means always scan.
    id_hashes: Option<Arc<FxHashSet<u64>>>,
}

impl<'a> FindingScope<'a> {
    /// Scope over `own` plus `extra`, indexed for fast negative lookups.
    pub(crate) fn new(own: &'a [Finding], extra: Option<&'a [Finding]>) -> Self {
        let extra = extra.unwrap_or(&[]);
        let mut id_hashes = FxHashSet::default();
        for finding in own.iter().chain(extra) {
            id_hashes.insert(hash_str(&finding.id));
        }
        Self {
            own,
            mid: &[],
            extra,
            id_hashes: Some(Arc::new(id_hashes)),
        }
    }

    /// Scope with a caller-supplied index — or `None` to skip the shortcut and
    /// scan every lookup, which is what the rule-authoring tools want.
    pub(crate) fn with_index(
        own: &'a [Finding],
        extra: Option<&'a [Finding]>,
        id_hashes: Option<Arc<FxHashSet<u64>>>,
    ) -> Self {
        Self {
            own,
            mid: &[],
            extra: extra.unwrap_or(&[]),
            id_hashes,
        }
    }

    /// The same scope with `mid` spliced in between `own` and `extra`,
    /// its ids folded into the index. The id-set clone is a flat `u64` copy —
    /// the cheap alternative to cloning the findings themselves.
    pub(crate) fn with_mid_findings(mut self, mid: &'a [Finding]) -> Self {
        debug_assert!(self.mid.is_empty(), "mid findings already set");
        self.mid = mid;
        if let Some(hashes) = self.id_hashes.take() {
            let mut owned = (*hashes).clone();
            for finding in mid {
                owned.insert(hash_str(&finding.id));
            }
            self.id_hashes = Some(Arc::new(owned));
        }
        self
    }

    /// Every finding in scope, all halves, in report-then-mid-then-extra order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Finding> {
        self.own.iter().chain(self.mid).chain(self.extra)
    }

    /// Whether any finding in scope has exactly this id.
    pub(crate) fn contains_id(&self, id: &str) -> bool {
        if let Some(ref hashes) = self.id_hashes
            && !hashes.contains(&hash_str(id))
        {
            return false;
        }
        self.iter().any(|f| f.id == id)
    }
}

/// Per-file lazy caches shared by every [`EvaluationContext`] built for one
/// member. A member's evaluation constructs several contexts (the trait pass,
/// then each composite fixed-point iteration, then downgrade re-evaluation);
/// each used to start with fresh `OnceLock`s, so the string exact indexes, KV
/// parse, lowercased binary, and lossy-UTF-8 projections were rebuilt per
/// context even though the underlying bytes and `report.strings` are fixed
/// for the member's lifetime. One `FileEvalCaches` per member makes every
/// later context a cache hit.
#[derive(Debug, Default, Clone)]
pub(crate) struct FileEvalCaches {
    kv_format: Arc<OnceLock<StructuredFormat>>,
    kv_parsed: Arc<OnceLock<Box<Value>>>,
    kv_offsets: Arc<OnceLock<FxHashMap<String, u64>>>,
    lower_binary: Arc<OnceLock<Vec<u8>>>,
    lossy_utf8: Arc<OnceLock<String>>,
    string_exact_index: Arc<OnceLock<FxHashMap<String, Vec<u32>>>>,
    string_exact_index_ci: Arc<OnceLock<FxHashMap<String, Vec<u32>>>>,
    encoded_string_indices: Arc<OnceLock<Vec<u32>>>,
}

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
    /// Every finding in scope for this evaluation — the report's own plus any
    /// not stored on it. Read through this, never `report.findings`.
    pub findings: FindingScope<'a>,
    /// Cached parsed AST (to avoid re-parsing for each ast_pattern trait)
    pub cached_ast: Option<&'a tree_sitter::Tree>,
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
    /// Precomputed `query:` results for this file (one combined QueryCursor).
    /// Keyed by the original query string. Missing key → `eval_ast_query`
    /// runs that pattern itself (compile fail, or the batch was declined).
    pub ast_query_cache: Option<&'a FxHashMap<String, ConditionResult>>,
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
    /// Atom-hit offsets from the raw-content gate, keyed by trait index.
    /// Present only when that gate ran (source members ≤3 MiB). `eval_raw`
    /// windows bounded regexes around these; it must not memmem the haystack
    /// again. Missing key → full scan (no-literal / overflow / ungated).
    pub raw_atom_offsets: Option<&'a rustc_hash::FxHashMap<usize, Vec<u32>>>,
    /// Indexed `type: text` traits (by index, with their `if:` pattern text)
    /// whose atoms are absent from every decoded string layer of this member.
    /// `eval_text` skips its decoded-layer pass for exactly that pattern.
    pub decoded_skip: Option<&'a rustc_hash::FxHashMap<usize, &'a str>>,
    /// Validated UTF-8 view of `binary_data`, populated once per file for source-code
    /// file types. Lets AST/text evaluators skip the per-rule O(N) `from_utf8` check.
    pub cached_source_utf8: Option<&'a str>,
    /// Whole-`binary_data` ASCII-lowercased once. Production CI search now
    /// uses `cached_ci_searcher` on the original bytes; this slot remains so
    /// existing `EvaluationContext` constructors stay source-compatible.
    #[allow(dead_code)]
    pub cached_lower_binary: Arc<OnceLock<Vec<u8>>>,
    /// Lossy UTF-8 view of the *whole* `binary_data`, built at most once per
    /// file and shared across every full-range Unicode condition. Only used
    /// where `cached_source_utf8` is absent — i.e. non-source content, which is
    /// where `from_utf8_lossy` actually allocates. Rebuilding it per rule cost
    /// both CPU (a 487 MB disk image spent ~185 CPU-s re-transcoding) and peak
    /// RSS (one transient copy per concurrent rule instead of one shared).
    pub cached_lossy_utf8: Arc<OnceLock<String>>,
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
            findings: FindingScope::new(&report.findings, additional_findings),
            cached_ast,
            debug_collector: None,
            section_map: None,
            inline_yara_results: None,
            cached_kv_format: Arc::new(OnceLock::new()),
            cached_kv_parsed: Arc::new(OnceLock::new()),
            cached_kv_offsets: Arc::new(OnceLock::new()),
            cached_lower_binary: Arc::new(OnceLock::new()),
            cached_lossy_utf8: Arc::new(OnceLock::new()),
            ast_kind_cache: None,
            ast_query_cache: None,
            string_exact_index: Arc::new(OnceLock::new()),
            string_exact_index_ci: Arc::new(OnceLock::new()),
            encoded_string_indices: Arc::new(OnceLock::new()),
            deadline: None,
            cancellation: None,
            arch_ranges: None,
            slow_rule_ms: 4000,
            cached_evidence: None,
            current_trait_idx: None,
            raw_atom_offsets: None,
            decoded_skip: None,
            cached_source_utf8,
            parent_is_exception: false,
        }
    }

    /// Share one member's lazy per-file caches across every context built
    /// for it (see [`FileEvalCaches`]). Must only be used for contexts over
    /// the same `binary_data` / `report.strings`.
    pub(crate) fn with_file_caches(mut self, caches: &FileEvalCaches) -> Self {
        self.cached_kv_format = Arc::clone(&caches.kv_format);
        self.cached_kv_parsed = Arc::clone(&caches.kv_parsed);
        self.cached_kv_offsets = Arc::clone(&caches.kv_offsets);
        self.cached_lower_binary = Arc::clone(&caches.lower_binary);
        self.cached_lossy_utf8 = Arc::clone(&caches.lossy_utf8);
        self.string_exact_index = Arc::clone(&caches.string_exact_index);
        self.string_exact_index_ci = Arc::clone(&caches.string_exact_index_ci);
        self.encoded_string_indices = Arc::clone(&caches.encoded_string_indices);
        self
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

    /// Set the batched `query:` result cache
    pub(crate) fn with_ast_query_cache(
        mut self,
        cache: &'a FxHashMap<String, ConditionResult>,
    ) -> Self {
        self.ast_query_cache = Some(cache);
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

    /// Set additional findings and rebuild index
    #[must_use]
    #[cfg(test)]
    pub(crate) fn with_additional_findings(mut self, findings: &'a [Finding]) -> Self {
        self.findings = FindingScope::new(&self.report.findings, Some(findings));
        self
    }

    /// Splice `mid` between the report's findings and the additional slice in
    /// scope order (see [`FindingScope::with_mid_findings`]).
    #[must_use]
    pub(crate) fn with_mid_findings(mut self, mid: &'a [Finding]) -> Self {
        self.findings = self.findings.with_mid_findings(mid);
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

    /// Unused production helper: ASCII-lowercase the whole haystack.
    /// eval_raw CI now searches original bytes via `cached_ci_searcher`.
    #[allow(dead_code)]
    pub(crate) fn lower_binary(&self) -> &[u8] {
        self.cached_lower_binary
            .get_or_init(|| self.binary_data.to_ascii_lowercase())
    }

    /// UTF-8 view of the entire `binary_data`, built at most once per file.
    ///
    /// Byte-identical to `evaluators::utf8_view(binary_data, (0, len))`: valid
    /// UTF-8 borrows, invalid bytes get the same U+FFFD substitutions, so match
    /// spans and offsets are unchanged — only the number of times the
    /// conversion runs differs. Sub-ranges must keep calling `utf8_view`: a
    /// lossy conversion of a slice is not in general a slice of the lossy
    /// conversion (an invalid sequence straddling the boundary transcodes
    /// differently).
    pub(crate) fn full_utf8(&self) -> &str {
        if let Some(s) = self.cached_source_utf8 {
            return s;
        }
        self.cached_lossy_utf8
            .get_or_init(|| String::from_utf8_lossy(self.binary_data).into_owned())
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
    ///
    /// Takes a closure so the reason — which typically clones platform/type
    /// vectors — is only built when a debug collector is attached. These fire
    /// for most (rule x member) pairs on big archives; eager construction was
    /// a measurable allocation tax on scans that never collect debug info.
    pub(crate) fn record_skip(&self, reason: impl FnOnce() -> SkipReason) {
        self.with_debug(|debug| debug.record_skip(reason()));
    }

    /// Check if a finding ID exists (exact match only)
    #[must_use]
    pub(crate) fn has_finding_exact(&self, id: &str) -> bool {
        self.findings.contains_id(id)
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
            findings: FindingScope::with_index(&report.findings, None, None),
            cached_ast: None,
            debug_collector: None,
            section_map: None,
            inline_yara_results: None,
            cached_kv_format: Arc::new(OnceLock::new()),
            cached_kv_parsed: Arc::new(OnceLock::new()),
            cached_kv_offsets: Arc::new(OnceLock::new()),
            cached_lower_binary: Arc::new(OnceLock::new()),
            cached_lossy_utf8: Arc::new(OnceLock::new()),
            ast_kind_cache: None,
            ast_query_cache: None,
            string_exact_index: Arc::new(OnceLock::new()),
            string_exact_index_ci: Arc::new(OnceLock::new()),
            encoded_string_indices: Arc::new(OnceLock::new()),
            deadline: None,
            cancellation: None,
            arch_ranges: None,
            slow_rule_ms: 4000,
            cached_evidence: None,
            current_trait_idx: None,
            raw_atom_offsets: None,
            decoded_skip: None,
            cached_source_utf8: None,
            parent_is_exception: false,
        }
    }

    /// Attach the decoded-layer skip map (see `decoded_skip`).
    #[must_use]
    pub(crate) fn with_decoded_skip(
        mut self,
        skip: Option<&'a rustc_hash::FxHashMap<usize, &'a str>>,
    ) -> Self {
        self.decoded_skip = skip;
        self
    }

    /// Attach gate-supplied atom offsets for windowed `eval_raw` on source.
    #[must_use]
    pub(crate) fn with_raw_atom_offsets(
        mut self,
        offsets: Option<&'a rustc_hash::FxHashMap<usize, Vec<u32>>>,
    ) -> Self {
        self.raw_atom_offsets = offsets;
        self
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
    pub matched_trait_ids: Vec<crate::types::Istr>,
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
    /// Byte-length bounds on the matched span; requires `regex:`.
    pub length_min: Option<usize>,
    pub length_max: Option<usize>,
    /// For CI conditions this finder was built from the lowercased pattern.
    pub is_check: Option<StringValidator>,
    pub section: Option<&'a String>,
    pub offset: Option<i64>,
    pub offset_range: Option<(i64, Option<i64>)>,
    pub section_offset: Option<i64>,
    pub section_offset_range: Option<(i64, Option<i64>)>,
    pub arch_clamp: Option<(usize, usize)>,
}
