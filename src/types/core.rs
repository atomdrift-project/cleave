//! Core analysis types - the foundation of cleave reports
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::binary::{
    AnalysisMetadata, Export, Function, Import, Section, StringInfo, SyscallInfo, YaraMatch,
};
use super::diff::DiffReportV1;
use super::file_analysis::{FileAnalysis, ReportSummary};
use super::filefacts_view::FilefactsView;
use super::is_false;
use super::paths_env::{DirectoryAccess, EnvVarInfo, PathInfo};
use super::traits_findings::{ContextLine, Finding, StructuralFeature, Suppression, Trait};
use crate::analyzers::FileType;

mod archive_kv;

mod finalize;

/// How many low-tier (component/baseline) traits to keep for a file that would
/// otherwise be stripped down to no findings, so it still carries a minimal clue
/// for downstream LLM consumers. See [`AnalysisReport::strip_unmatched_traits`].
const RESCUE_LOW_TIER_KEEP: usize = 3;

/// Represents an extracted payload (e.g., base64, hex, XOR)
#[derive(Debug)]
pub struct ExtractedPayload {
    /// In-memory decoded content
    pub data: Vec<u8>,
    /// Chain of encodings (e.g., ["base64", "zlib"])
    pub encoding_chain: Vec<String>,
    /// Preview of content (first 40 chars, printable only)
    pub preview: String,
    /// Detected type of payload
    pub detected_type: FileType,
    /// Byte offset in original file
    pub original_offset: usize,
}

/// Criticality level for traits and capabilities
/// - Filtered: Matched but wrong file type, preserved for ML analysis
/// - Exception: Benign-context composite, used only in `unless:`/`downgrade:`; assembly-only, never emitted
/// - Component: Building block for composites, hidden unless composite fires
/// - Baseline: Universal baseline noise, low analytical signal
/// - Notable: Defines program purpose, flag in diffs for supply chain security
/// - Suspicious: Unusual/evasive behavior, investigate immediately
/// - Hostile: Almost certainly malicious, very rare
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    // Discriminants are pinned explicitly. `Exception` was inserted between
    // `Filtered` and `Component`; pinning keeps the signal criticalities at the
    // values they have always had (`Notable=3`, `Suspicious=4`, `Hostile=5`), so
    // any code that compares a `crit as u8` against a literal threshold (e.g.
    // "> 2 is real signal") keeps working. Only `Filtered` moved — to -1, the
    // floor it already occupied semantically. Declaration order still ascends with
    // the discriminants, so derived `Ord` is unchanged:
    // `Filtered < Exception < Component < Baseline < Notable < Suspicious < Hostile`.
    /// Matched but wrong file type - preserved for ML analysis
    Filtered = -1,
    /// Benign-context composite — may only be referenced from `unless:`/`downgrade:`
    /// clauses and exists purely to assemble a known-good pattern from named
    /// `notable` traits. Never emitted to output; consumed during matching only.
    Exception = 0,
    /// Building block for composites - only shown when referenced by a matched composite
    Component = 1,
    /// Universal baseline noise - low analytical signal
    #[default]
    Baseline = 2,
    /// Defines program purpose - flag in diffs for supply chain security
    Notable = 3,
    /// Unusual/evasive behavior - investigate immediately
    Suspicious = 4,
    /// Almost certainly malicious - very rare
    Hostile = 5,
}

/// Parses a criticality name, case-insensitively. `malicious` is accepted as
/// a synonym for `hostile`, the spelling some third-party rule sets use.
impl std::str::FromStr for Criticality {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "filtered" => Ok(Self::Filtered),
            "exception" => Ok(Self::Exception),
            "component" => Ok(Self::Component),
            "baseline" => Ok(Self::Baseline),
            "notable" => Ok(Self::Notable),
            "suspicious" => Ok(Self::Suspicious),
            "hostile" | "malicious" => Ok(Self::Hostile),
            _ => Err(format!(
                "invalid criticality '{s}': expected one of filtered, exception, component, \
                 baseline, notable, suspicious, hostile"
            )),
        }
    }
}

impl Criticality {
    /// Single-letter tag used in compact/LLM output:
    /// `H`ostile, `S`uspicious, `N`otable, `B`aseline, `C`omponent, `F`iltered,
    /// `E`xception (assembly-only; not normally emitted).
    #[must_use]
    pub fn letter(self) -> char {
        match self {
            Self::Hostile => 'H',
            Self::Suspicious => 'S',
            Self::Notable => 'N',
            Self::Baseline => 'B',
            Self::Component => 'C',
            Self::Exception => 'E',
            Self::Filtered => 'F',
        }
    }

    /// Score weight for risk scoring: notable=1, suspicious=40, hostile=120
    #[must_use]
    pub fn score_weight(self) -> u32 {
        match self {
            Self::Hostile => 120,
            Self::Suspicious => 40,
            Self::Notable => 1,
            _ => 0,
        }
    }

    /// Dense 0..=5 rank used only to break ties when several findings annotate the
    /// same spot (highest `conf × rank` wins). This is deliberately *not* the enum
    /// discriminant: a `crit as u8` here would silently shift the moment a variant
    /// is inserted. `Filtered` and the assembly-only `Exception` both rank 0, the
    /// floor; the rest keep the original linear ladder.
    #[must_use]
    pub fn rank(self) -> u8 {
        match self {
            Self::Filtered | Self::Exception => 0,
            Self::Component => 1,
            Self::Baseline => 2,
            Self::Notable => 3,
            Self::Suspicious => 4,
            Self::Hostile => 5,
        }
    }

    /// Per-side source-line context radius: how many lines above and below a hit
    /// render around it, so a window is `[hit - radius, hit + radius]`. The
    /// strongest findings earn the widest window — a hostile hit's verdict most
    /// depends on the code surrounding it, a baseline's least. This is the single
    /// source of truth shared by context capture (which reserves this many lines)
    /// and the LLM/tiny render (which draws them); the two must not drift. A bare
    /// `Component`/`Exception`/`Filtered` renders as a single line regardless
    /// (radius 0) — a component a composite drew on instead inherits that
    /// composite's radius at the call site.
    #[must_use]
    pub fn context_radius(self) -> u64 {
        match self {
            Self::Hostile => 5,
            Self::Suspicious => 4,
            Self::Notable => 3,
            Self::Component => 2,
            Self::Baseline => 1,
            Self::Exception | Self::Filtered => 0,
        }
    }

    /// Bytes of context `(before, after)` a binary/hex match reserves and renders
    /// around itself. The binary analogue of [`Self::context_radius`], but asymmetric:
    /// far more trailing than leading context, since a payload (shellcode, an
    /// unpacked stub, a config blob) runs *forward* from the match. As with the
    /// source path the strongest findings earn the widest window; the single
    /// source of truth for both capture (which reserves the bytes) and the LLM
    /// render (which clips to them). `Exception`/`Filtered` never reach the binary
    /// view, so they carry no margin.
    #[must_use]
    pub fn hex_context(self) -> (u64, u64) {
        match self {
            Self::Hostile => (128, 256),
            Self::Suspicious => (96, 192),
            Self::Notable => (64, 128),
            Self::Baseline => (48, 96),
            Self::Component => (32, 64),
            Self::Exception | Self::Filtered => (0, 0),
        }
    }
}

/// Main analysis output structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// Incomplete analysis is not a malware finding or a clean verdict.
    #[serde(default, skip_serializing_if = "super::AnalysisGaps::is_empty")]
    pub analysis_gaps: super::AnalysisGaps,
    /// Schema version ("3" after finalize, "3.0" pre-finalize/cached).
    /// v3.0 adds the `filefacts` field mirroring filefacts's typed views.
    #[serde(alias = "schema_version")]
    pub version: String,
    /// Timestamp when analysis was performed (cleared after finalize)
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        alias = "analysis_timestamp"
    )]
    pub analysis_timestamp: Option<DateTime<Utc>>,
    /// Information about the target file (cleared after finalize — data lives in `files[0]`)
    #[serde(skip_serializing_if = "TargetInfo::is_cleared", default)]
    pub target: TargetInfo,

    // ========================================================================
    // Traits + Findings model
    // ========================================================================
    /// Observable characteristics (strings, paths, symbols, IPs, etc.)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub traits: Vec<Trait>,
    /// Findings - interpretive conclusions based on traits (capabilities, threats, etc.)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub findings: Vec<Finding>,
    /// Notable-or-above traits that matched but were withheld or demoted by
    /// their own `unless:`/`downgrade:` legs, with the bytes those legs fired
    /// on. What the engine decided *not* to report — so a reader can weigh that
    /// call instead of reading silence as absence.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub suppressions: Vec<Suppression>,
    /// Merged, render-ready context: matched content shown once, in file order,
    /// annotated with the findings that touch it. The output surface that
    /// replaces raw per-finding evidence. Populated by the context-capture pass.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub context: Vec<ContextLine>,

    /// Structural features (binary format properties, obfuscation markers)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub structure: Vec<StructuralFeature>,
    /// Functions discovered via disassembly or source parsing
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub functions: Vec<Function>,
    /// String literals extracted from the file
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub strings: Vec<StringInfo>,
    /// Source-code comment bodies (separate from `strings` so comment text
    /// never bleeds into string/byte matchers). Matched only by
    /// `type: comment` — the lowest-false-positive tier for "keyword
    /// mentioned in a comment" rules.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub comments: Vec<StringInfo>,
    /// Binary sections (ELF, Mach-O, or PE)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sections: Vec<Section>,
    /// Symbols imported from external libraries
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub imports: Vec<Import>,
    /// Symbols exported by this file
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub exports: Vec<Export>,
    /// YARA rule matches
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub yara_matches: Vec<YaraMatch>,
    /// Syscalls detected via binary analysis (ELF, Mach-O)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub syscalls: Vec<SyscallInfo>,
    /// Report-side mirror of filefacts's typed views — `values`,
    /// `metrics`, `sections`, `imports`, `exports`, `functions`,
    /// `errors`. Populated at every binary analyzer entry that runs
    /// through `AnalysisContext`. Schema v3.0 ships this verbatim so
    /// downstream consumers can navigate `filefacts.values.pe.machine`
    /// directly.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub filefacts: Option<FilefactsView>,
    /// Normalized identity claims from filefacts: who and what the file
    /// says it is (name, identifier, project, signer, trust tier,
    /// authors, document title, build path, unique ids), each tagged
    /// claimed-vs-verified. Attached only when filefacts found a
    /// non-empty identity, so most files omit it. Rendered as a headline
    /// in terminal/tiny output and diffed as a high-signal change.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identity: Option<filefacts::Identity>,
    /// Synthetic key-value tree for `type: value` matchers on file
    /// formats whose metadata isn't natively a manifest (e.g.,
    /// office documents). Populated by analyzers; consumed by the
    /// value evaluator. The schema is the public trait-base API for
    /// each format that opts in. Serialized so external consumers
    /// (and the upcoming `cleave value` extension) can introspect the
    /// same path map trait authors target.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub values_tree: Option<Box<serde_json::Value>>,
    /// Whether this report was replayed from the analysis cache instead of
    /// produced by a fresh pass.
    ///
    /// Transient: never serialized, so a report stored in the cache and read
    /// back deserializes with this `false` and the lookup that returned it sets
    /// it. Callers use it to report where an answer came from — a cache hit and
    /// a fresh analysis are otherwise distinguishable only by how long they
    /// took, which is exactly the thing an operator is trying to explain.
    #[serde(skip)]
    pub cache_hit: bool,
    /// Already-flattened member kv, carried only across the compact per-member
    /// cache round-trip. A member cached as a [`FileAnalysis`] keeps its folded
    /// facts as flat `kv`; the nested `values_tree` was dropped to save space,
    /// so [`crate::report_from_file_analysis`] stashes the flat map here and
    /// [`Self::into_file_analysis`] restores it. Without this a cached member
    /// returns with empty kv and reads as spuriously *changed* against the
    /// freshly-analyzed side of a diff. Transient: never serialized, and not
    /// part of any cache key.
    #[serde(skip)]
    pub(crate) cached_member_kv: Option<std::collections::BTreeMap<String, serde_json::Value>>,
    /// The engine this report was analyzed under, so [`Self::finalize`] folds
    /// the root file under the same rules and settings as its members.
    /// Transient: never serialized, and absent on a report read back from the
    /// cache by an entry point that never built an engine.
    #[serde(skip)]
    pub(crate) engine: Option<crate::Engine>,
    /// Filefacts's flat metric map (`{ "lnk.arguments_max_whitespace_run":
    /// 100.0, "pdf.action_count": 4.0, … }`) attached verbatim so
    /// trait-rule resolution for `type: metrics, field: …` reads
    /// filefacts-emitted values directly. This is the sole numeric
    /// metric surface — typed projection structs were retired.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub filefacts_metrics: Option<std::collections::BTreeMap<String, f64>>,
    /// Byte-span provenance for *located* metrics — the spans a metric was
    /// measured from (e.g. `binary.peak_region_entropy` → the high-entropy
    /// runs). Keyed by the same metric name as `filefacts_metrics`; populated
    /// only for metrics that carry spans. The value store keeps its `f64` map
    /// (and `MetricsExt` helpers); the producer's `Fact{value, spans}` is split
    /// into the two at the single `merge_filefacts_context` bridge so a metrics
    /// match can attach the location to its finding for downstream (a report viewer).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub filefacts_metric_spans: Option<std::collections::BTreeMap<String, Vec<filefacts::Span>>>,
    /// Raw paths discovered (complete list)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub paths: Vec<PathInfo>,
    /// Paths grouped by directory (analysis view)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub directories: Vec<DirectoryAccess>,
    /// Environment variables accessed
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub env_vars: Vec<EnvVarInfo>,
    /// Files contained within archives (for archive targets only)
    /// Paths match those used in Evidence.location fields (without "archive:" prefix)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub archive_contents: Vec<ArchiveEntry>,

    // ========================================================================
    // V2 Schema fields (flat file-centric structure)
    // ========================================================================
    /// Path that was scanned (for directory scans)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub scanned_path: Option<String>,

    /// Flat array of all analyzed files (v2 schema)
    /// Includes root file, archive members, and decoded payloads
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub files: Vec<FileAnalysis>,

    /// Report-level summary (v2 schema)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub summary: Option<ReportSummary>,

    /// Analysis metadata (tool versions, timing, errors) — merged into summary after finalize
    #[serde(skip_serializing_if = "AnalysisMetadata::is_cleared", default)]
    pub metadata: AnalysisMetadata,

    /// Differential analysis result, present only on the output of `cleave diff`.
    /// Embedded in the v3 envelope so embedders can consume diff and
    /// per-file analysis from one document. See [`DiffReportV1`].
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub diff: Option<DiffReportV1>,
}

/// Convenience writes / reads into the flat `metrics` map. Cast-from-f64
/// boilerplate stays here so callers don't repeat it at every emit site.
pub trait MetricsExt {
    /// Insert `value` cast to `f64`. The flat `metrics` map stores
    /// everything as `f64`; this hides the cast at the call site.
    fn set_u(&mut self, key: impl Into<String>, value: u64);
    /// Insert an `f64` verbatim.
    fn set_f(&mut self, key: impl Into<String>, value: f64);
    /// Insert a boolean as `0.0` / `1.0`.
    fn set_b(&mut self, key: impl Into<String>, value: bool);
    /// Read a stored value back as `u64` (returns `None` when absent).
    fn as_u64(&self, key: &str) -> Option<u64>;
    /// Read a stored boolean back (returns `None` when absent;
    /// `1.0` → `Some(true)`, anything else stored → `Some(false)`).
    fn as_bool(&self, key: &str) -> Option<bool>;
}

impl MetricsExt for std::collections::BTreeMap<String, f64> {
    fn set_u(&mut self, key: impl Into<String>, value: u64) {
        self.insert(key.into(), value as f64);
    }
    fn set_f(&mut self, key: impl Into<String>, value: f64) {
        self.insert(key.into(), value);
    }
    fn set_b(&mut self, key: impl Into<String>, value: bool) {
        self.insert(key.into(), if value { 1.0 } else { 0.0 });
    }
    fn as_u64(&self, key: &str) -> Option<u64> {
        self.get(key).map(|v| *v as u64)
    }
    fn as_bool(&self, key: &str) -> Option<bool> {
        self.get(key).map(|v| *v != 0.0)
    }
}

/// Set a value at a dotted path inside an `Option<Box<serde_json::Value>>`
/// kv tree, creating intermediate objects as needed. `serde_json::Value`
/// becomes the canonical home for any metric-shaped data that doesn't
/// fit `f64` (strings, arrays, structured records).
pub fn kv_set_path(
    tree: &mut Option<Box<serde_json::Value>>,
    dotted: &str,
    value: serde_json::Value,
) {
    let root = tree.get_or_insert_with(|| Box::new(serde_json::Value::Object(Default::default())));
    let mut current = root.as_mut();
    if !matches!(current, serde_json::Value::Object(_)) {
        *current = serde_json::Value::Object(Default::default());
    }
    let parts: Vec<&str> = dotted.split('.').collect();
    let Some((last, parents)) = parts.split_last() else {
        return;
    };
    for part in parents {
        // The match on line 289 above + the `entry → Object` rewrite at
        // the loop tail (304-306) keep `current` an Object on every
        // iteration, so the `as_object_mut` cannot return None. The
        // `else return` is a belt-and-braces guard in case future
        // edits break the invariant.
        let Some(map) = current.as_object_mut() else {
            return;
        };
        let entry = map
            .entry(part.to_string())
            .or_insert_with(|| serde_json::Value::Object(Default::default()));
        if !matches!(entry, serde_json::Value::Object(_)) {
            *entry = serde_json::Value::Object(Default::default());
        }
        current = entry;
    }
    if let Some(obj) = current.as_object_mut() {
        obj.insert((*last).to_string(), value);
    }
}

impl AnalysisReport {
    /// Create a new analysis report for the given target, timestamped now
    #[must_use]
    pub fn new(target: TargetInfo) -> Self {
        Self::new_with_timestamp(target, Utc::now())
    }

    /// Create a new analysis report with an explicit timestamp (useful for testing)
    #[must_use]
    pub fn new_with_timestamp(target: TargetInfo, timestamp: chrono::DateTime<Utc>) -> Self {
        Self {
            version: "3.0".to_string(),
            analysis_gaps: super::AnalysisGaps::default(),
            analysis_timestamp: Some(timestamp),
            target,
            traits: Vec::new(),
            findings: Vec::new(),
            suppressions: Vec::new(),
            context: Vec::new(),
            structure: Vec::new(),
            functions: Vec::new(),
            strings: Vec::new(),
            comments: Vec::new(),
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            yara_matches: Vec::new(),
            syscalls: Vec::new(),
            filefacts: None,
            identity: None,
            values_tree: None,
            cache_hit: false,
            cached_member_kv: None,
            engine: None,
            filefacts_metrics: None,
            filefacts_metric_spans: None,
            paths: Vec::new(),
            directories: Vec::new(),
            env_vars: Vec::new(),
            archive_contents: Vec::new(),
            scanned_path: None,
            files: Vec::new(),
            summary: None,
            metadata: AnalysisMetadata::default(),
            diff: None,
        }
    }

    fn refresh_formula(file: &mut FileAnalysis) {
        file.formula = crate::formula::of(&file.findings);
    }

    /// Append `findings` to the already-finalized node whose `sha256` matches
    /// `target_sha`, deduping by finding id, then refresh that node's formula
    /// and summary (and the report summary) so the additions are reflected
    /// everywhere a finalized report is read. Returns how many were added.
    ///
    /// This is the graft point for the fetch-driven package pass: composite
    /// findings that correlate a fetched artifact with its registry metadata are
    /// produced after [`Self::finalize`] and must land on the artifact node
    /// without re-running the whole finalize. Because each composite carries its
    /// members in `trait_refs`, [`Self::strip_unmatched_traits`] (which unions
    /// `trait_refs` across every node) keeps the building-block traits it fired
    /// on, wherever they live.
    pub fn graft_findings(&mut self, target_sha: &str, findings: Vec<Finding>) -> usize {
        let added = self.graft_findings_deferred(target_sha, findings);
        if added > 0 {
            self.refresh_grafted_findings();
        }
        added
    }

    // Batched follow evaluation updates file-local formulas immediately, but
    // defers the report-wide summary and source index until all files land.
    pub(crate) fn graft_findings_deferred(
        &mut self,
        target_sha: &str,
        findings: Vec<Finding>,
    ) -> usize {
        let Some(index) = self.files.iter().position(|f| f.sha256 == target_sha) else {
            return 0;
        };
        self.graft_file_findings_deferred(index, findings)
    }

    pub(crate) fn graft_file_findings_deferred(
        &mut self,
        index: usize,
        findings: Vec<Finding>,
    ) -> usize {
        let mut added = 0;
        if let Some(file) = self.files.get_mut(index) {
            for finding in findings {
                if !file
                    .findings
                    .iter()
                    .any(|existing| existing.id == finding.id)
                {
                    file.findings.push(finding);
                    added += 1;
                }
            }
            if added > 0 {
                Self::refresh_formula(file);
                file.compute_summary();
            }
        }
        added
    }

    pub(crate) fn refresh_grafted_findings(&mut self) {
        self.summary = Some(ReportSummary::from_files(&self.files));
        Self::attach_composite_sources(&mut self.files);
    }

    /// Add a finding
    pub fn add_finding(&mut self, finding: Finding) {
        if !self.findings.iter().any(|f| f.id == finding.id) {
            self.push_finding_capped(finding);
        }
    }

    /// Collapse duplicate findings (same `id`) into one entry, both at the
    /// report top level and inside every `files[]` entry. Some analyzers
    /// emit multiple findings for the same trait — once per match site, or
    /// once per evidence shard — and downstream consumers (the diff
    /// renderer in particular) want one logical finding per id.
    ///
    /// When merging duplicates the surviving entry takes the *max*
    /// criticality and confidence, *sums* `match_count`, and *concatenates*
    /// `evidence` (capped at `MAX_EVIDENCE_PER_TRAIT`) and `trait_refs`
    /// (deduplicated). Order of first appearance is preserved.
    pub fn dedupe_findings(&mut self) {
        dedupe_finding_list(&mut self.findings);
        for file in &mut self.files {
            dedupe_finding_list(&mut file.findings);
        }
    }

    /// Push a finding to the report, enforcing a hard limit of 8192 findings.
    ///
    /// If the limit is reached, the finding is discarded and a final warning
    /// finding is appended (once) to indicate the report was truncated.
    pub fn push_finding_capped(&mut self, finding: Finding) {
        const MAX_FINDINGS: usize = 8192;

        if self.findings.len() < MAX_FINDINGS {
            self.findings.push(finding);
            return;
        }

        if self.findings.len() == MAX_FINDINGS {
            let mut truncate_finding = Finding::new(
                "metadata/analysis/findings-limit-exceeded".to_string(),
                crate::types::FindingKind::Indicator,
                format!(
                    "Analysis produced more than {MAX_FINDINGS} findings; \
                     truncated to prevent downstream performance degradation"
                ),
                1.0,
            );
            truncate_finding.crit = crate::types::Criticality::Notable;
            self.findings.push(truncate_finding);
        }
    }

    /// Drop the third-party YARA hits on a file that is itself a defensive
    /// scanner carrying a YARA rule catalog. The catalog contains the strings
    /// those rules look for, so the scanner is reported as every family it
    /// knows.
    ///
    /// Only `third_party/` hits go: those are the rules whose own text the
    /// catalog holds. The context is three strings anyone can embed, so it
    /// must not excuse native findings too; a native trait that also fires on
    /// the catalog answers for that itself, with an `unless:` naming the
    /// context, where the exception stays reviewable. Other files in the same
    /// archive keep their own hits: this only looks at the findings of the
    /// report it is called on.
    pub fn suppress_scanner_catalog_self_hits(&mut self) {
        const CTX: &str =
            "well-known/tool/detection/malcontent::malcontent-defensive-scanner-context";
        if self.findings.iter().any(|f| f.id.as_str() == CTX) {
            self.findings.retain(|f| !f.id.starts_with("third_party/"));
        }
    }

    /// Filter findings using a predicate function.
    /// Applies the filter to both the top-level findings and findings within files.
    /// Returns the number of findings removed.
    pub fn filter_findings<F>(&mut self, predicate: F) -> usize
    where
        F: Fn(&Finding) -> bool + Sync,
    {
        self.filter_findings_by_file(|_| &predicate)
    }

    /// [`Self::filter_findings`] with a predicate made for each list: `make`
    /// receives the file's path, or `None` for the top-level findings, so a
    /// filter can judge a finding by what is visible from where it sits.
    pub(crate) fn filter_findings_by_file<M, P>(&mut self, make: M) -> usize
    where
        M: Fn(Option<&str>) -> P + Sync,
        P: Fn(&Finding) -> bool,
    {
        use rayon::prelude::*;

        let initial_count =
            self.findings.len() + self.files.iter().map(|f| f.findings.len()).sum::<usize>();

        // Filter top-level findings
        self.findings.retain(make(None));

        // Filter findings in files array (v2 schema). Each file's findings and
        // its derived formula/summary depend only on that file, so both passes
        // fan out. Archive containers carry tens of thousands of members, and
        // walking them twice single-threaded — once to retain, once to refresh —
        // showed up as half the remaining finalize tail (stack
        // sampling, 3 of 6 in-tail samples across this retain and the
        // `filter_findings_for_formula` call inside `refresh_formula`). Below
        // that size the fan-out costs more than the walk.
        let parallel = self.files.len() >= 32 && crate::rayon_nest::inner_work_parallel();
        if parallel {
            self.files
                .par_iter_mut()
                .for_each(|file| file.findings.retain(make(Some(file.path.as_str()))));
        } else {
            for file in &mut self.files {
                file.findings.retain(make(Some(file.path.as_str())));
            }
        }

        let final_count =
            self.findings.len() + self.files.iter().map(|f| f.findings.len()).sum::<usize>();

        let removed = initial_count - final_count;

        // Recompute per-file summaries and report summary after filtering
        if removed > 0 {
            if parallel {
                self.files.par_iter_mut().for_each(|file| {
                    Self::refresh_formula(file);
                    file.compute_summary();
                });
            } else {
                for file in &mut self.files {
                    Self::refresh_formula(file);
                    file.compute_summary();
                }
            }
            self.summary = Some(ReportSummary::from_files(&self.files));
        }

        removed
    }

    /// Create a FileAnalysis from this report's data
    ///
    /// This is used internally by finalize() and by archive analyzers
    /// to convert per-file reports into the flat files array structure.
    /// `engine` is the one the report was analyzed under: its rules and
    /// settings decide which folded fields are kept.
    #[must_use]
    pub fn to_file_analysis(&self, id: u32, engine: &crate::Engine) -> FileAnalysis {
        // Exhaustive on purpose: a new report field is a compile error here
        // until someone decides whether it belongs on the per-file entry. A
        // hand-kept copy of this list once dropped `suppressions`.
        let Self {
            target,
            traits,
            findings,
            suppressions,
            analysis_gaps,
            context,
            filefacts,
            identity,
            filefacts_metrics,
            structure,
            functions,
            strings,
            imports,
            exports,
            sections,
            yara_matches,
            syscalls,
            paths,
            directories,
            env_vars,
            values_tree,
            // Report-level only: not part of a per-file entry.
            version: _,
            analysis_timestamp: _,
            comments: _,
            cache_hit: _,
            cached_member_kv: _,
            engine: _,
            filefacts_metric_spans: _,
            archive_contents: _,
            scanned_path: _,
            files: _,
            summary: _,
            metadata: _,
            diff: _,
        } = self;
        let mut file = FileAnalysis::from_report_parts(
            id,
            ReportFileParts {
                target: target.clone(),
                traits: traits.clone(),
                findings: findings.clone(),
                suppressions: suppressions.clone(),
                analysis_gaps: analysis_gaps.clone(),
                context: context.clone(),
                filefacts: filefacts.clone(),
                identity: identity.clone(),
                filefacts_metrics: filefacts_metrics.clone(),
                structure: structure.clone(),
                functions: functions.clone(),
                strings: strings.clone(),
                imports: imports.clone(),
                exports: exports.clone(),
                sections: sections.clone(),
                yara_matches: yara_matches.clone(),
                syscalls: syscalls.clone(),
                paths: paths.clone(),
                directories: directories.clone(),
                env_vars: env_vars.clone(),
            },
        );

        // Flatten the values tree into `kv` (the serialized form). The nested
        // tree itself is NOT retained on the file: `kv` is the single output
        // representation, and the only structural reader (`type: value` sibling
        // lookups, diff) now reads `kv`. In compact-member mode the flatten is
        // skipped entirely for files no rule can reach — see `retain_folded_kv`.
        if let Some(tree) = values_tree.as_deref()
            && retain_folded_kv(&file.path, engine)
        {
            flatten_kv_for_output(tree, &mut file.kv);
        } else if let Some(tree) = values_tree.as_deref() {
            retain_cargo_context_values(&file.path, tree, &mut file.kv);
        }
        drop_unread_folded_fields(&mut file, engine);
        file
    }

    /// Consuming version of `to_file_analysis` that moves data instead of cloning.
    ///
    /// Returns `(file_analysis, nested_files, archive_contents)` — the nested files
    /// and archive contents are returned separately since archive callers need them.
    /// This avoids the temporary doubling of memory from cloning large reports.
    #[must_use]
    pub fn into_file_analysis(
        self,
        id: u32,
        engine: &crate::Engine,
    ) -> (FileAnalysis, Vec<FileAnalysis>, Vec<ArchiveEntry>) {
        let Self {
            target,
            traits,
            findings,
            suppressions,
            analysis_gaps,
            context,
            filefacts,
            identity,
            filefacts_metrics,
            structure,
            functions,
            strings,
            imports,
            exports,
            sections,
            yara_matches,
            syscalls,
            paths,
            directories,
            env_vars,
            values_tree,
            cached_member_kv,
            engine: _,
            files: nested_files,
            archive_contents,
            // Report-level only: not part of a per-file entry.
            version: _,
            analysis_timestamp: _,
            comments: _,
            cache_hit: _,
            filefacts_metric_spans: _,
            scanned_path: _,
            summary: _,
            metadata: _,
            diff: _,
        } = self;
        let mut file = FileAnalysis::from_report_parts(
            id,
            ReportFileParts {
                target,
                traits,
                findings,
                suppressions,
                analysis_gaps,
                context,
                filefacts,
                identity,
                filefacts_metrics,
                structure,
                functions,
                strings,
                imports,
                exports,
                sections,
                yara_matches,
                syscalls,
                paths,
                directories,
                env_vars,
            },
        );

        // `kv` is the single retained representation — see `to_file_analysis`.
        // A freshly-analyzed report carries the nested `values_tree` and flattens
        // it here; a member restored from the compact cache has no tree, only its
        // already-flattened `kv` (stashed on `cached_member_kv`), so use that
        // directly. Both paths land the same map, so the two sides of a diff
        // agree on an unchanged member instead of reporting phantom kv deltas.
        if let Some(tree) = values_tree.as_deref()
            && retain_folded_kv(&file.path, engine)
        {
            flatten_kv_for_output(tree, &mut file.kv);
        } else if let Some(kv) = cached_member_kv {
            file.kv = kv;
        } else if let Some(tree) = values_tree.as_deref() {
            retain_cargo_context_values(&file.path, tree, &mut file.kv);
        }
        drop_unread_folded_fields(&mut file, engine);
        precompact_member_facts(&mut file, engine);
        early_strip_member_findings(&mut file, engine);
        shrink_member_capacity(&mut file, engine);
        (file, nested_files, archive_contents)
    }
}

/// Put a finished file's findings and suppressions in their output order:
/// most severe first, then by id. Analysis appends them as its producers
/// finish (parallel passes, member folds), so without a fixed order two runs
/// over the same file list them differently, and every index into the list
/// (the compact `uses`) shifts with it.
fn sort_for_output(file: &mut FileAnalysis) {
    file.findings
        .sort_by(|a, b| b.crit.cmp(&a.crit).then_with(|| a.id.cmp(&b.id)));
    for suppression in &mut file.suppressions {
        suppression.by.sort_by(|a, b| a.id.cmp(&b.id));
    }
    file.suppressions.sort_by(|a, b| a.id.cmp(&b.id));
}

/// The per-file fields a report carries into its `FileAnalysis` entry. Filled
/// by both conversions from an exhaustive destructure of the report.
struct ReportFileParts {
    target: TargetInfo,
    traits: Vec<Trait>,
    findings: Vec<Finding>,
    suppressions: Vec<Suppression>,
    analysis_gaps: super::AnalysisGaps,
    context: Vec<ContextLine>,
    filefacts: Option<FilefactsView>,
    identity: Option<filefacts::Identity>,
    filefacts_metrics: Option<std::collections::BTreeMap<String, f64>>,
    structure: Vec<StructuralFeature>,
    functions: Vec<Function>,
    strings: Vec<StringInfo>,
    imports: Vec<Import>,
    exports: Vec<Export>,
    sections: Vec<Section>,
    yara_matches: Vec<YaraMatch>,
    syscalls: Vec<SyscallInfo>,
    paths: Vec<PathInfo>,
    directories: Vec<DirectoryAccess>,
    env_vars: Vec<EnvVarInfo>,
}

impl FileAnalysis {
    /// A file entry from a report's per-file fields, with metrics populated.
    /// Every `FileAnalysis` field is named, so a new one is a compile error
    /// here until someone decides how a report fills it.
    fn from_report_parts(id: u32, parts: ReportFileParts) -> Self {
        let ReportFileParts {
            target,
            traits,
            findings,
            suppressions,
            analysis_gaps,
            context,
            filefacts,
            identity,
            filefacts_metrics,
            structure,
            functions,
            strings,
            imports,
            exports,
            sections,
            yara_matches,
            syscalls,
            paths,
            directories,
            env_vars,
        } = parts;
        let TargetInfo {
            path,
            file_type,
            size_bytes,
            sha256,
            architectures,
        } = target;
        let mut file = Self {
            analysis_gaps,
            id,
            path,
            parent_id: None,
            depth: 0,
            rel: super::Rel::Member,
            via: None,
            role: super::Role::Content,
            file_type,
            arch: architectures.and_then(|archs| archs.into_iter().next()),
            sha256,
            size: size_bytes,
            score: 0,
            counts: None,
            encoding: None,
            findings,
            suppressions,
            context,
            traits,
            structure,
            functions,
            strings,
            sections,
            imports,
            exports,
            yara_matches,
            syscalls,
            filefacts,
            identity,
            filefacts_metrics,
            paths,
            directories,
            env_vars,
            formula: None,
            composite_sources: std::collections::BTreeMap::new(),
            kv: std::collections::BTreeMap::new(),
            precompact_facts: None,
            precompact_refs: None,
        };
        file.populate_file_metrics();
        file
    }
}

/// In compact-member mode, drop a folded member's baseline/filtered findings
/// that nothing can ever read again — the fold-time version of the
/// end-of-scan `strip_unmatched_traits`, which otherwise retains them across
/// the entire archive ramp only to delete them at output.
///
/// Output-identical by keeping a superset of every later consumer's read set:
/// - **notable+ and component/exception findings**: kept wholesale (component
///   reachability via `for_from_groups` grouping is not indexable here — v1
///   strips only `Baseline`/`Filtered`).
/// - **anything a loaded rule could reference** (`TraitRefIndex`): kept, so
///   container composites, `unless:`/`downgrade:` and the end-strip's
///   `referenced` set see everything they see today.
/// - **each 3-level group's max score contributor**: kept, so
///   `compute_summary`'s per-group-max risk score recomputes to the same
///   value at finalize (baselines score `0.2 × conf` through a group max).
/// - **the file's top-3 sub-notables by `rank × conf`**: kept, so
///   `rescue_low_tier` (which rescues exactly that top-3 when a file has no
///   notable findings) selects the same set.
///
/// The end-strip still runs and removes whatever this kept conservatively.
fn early_strip_member_findings(file: &mut FileAnalysis, engine: &crate::Engine) {
    if !engine.compact_members() {
        return;
    }
    let refs = engine.rules().trait_ref_index();
    early_strip_impl(file, |id| refs.possibly_referenced(id));
}

/// The pure strip behind [`early_strip_member_findings`], parameterized on
/// the reference oracle so tests exercise the keep-set logic without touching
/// process-global state.
fn early_strip_impl(file: &mut FileAnalysis, possibly_referenced: impl Fn(&str) -> bool) {
    // Mirrors `strip_unmatched_traits`: a finding demoted into a low tier by its
    // own `downgrade:` is kept, since the author asked to de-emphasize it rather
    // than remove it.
    let strippable = |f: &Finding| {
        matches!(f.crit, Criticality::Baseline | Criticality::Filtered)
            && !f.downgraded
            && !(f.crit == Criticality::Baseline
                && crate::capabilities::is_dynamic_import_ref(&f.id))
    };
    if !file.findings.iter().any(&strippable) {
        return;
    }
    // Group-max representatives, by the same contribution compute_summary
    // uses for baselines (0.2 × conf, max per 3-level group). Filtered
    // findings contribute nothing to score; the shared rule keeps at most
    // one extra per group, which is harmless.
    let mut group_max: rustc_hash::FxHashMap<String, (usize, f32)> =
        rustc_hash::FxHashMap::default();
    // Rescue's ordering among strippables, to mirror `rescue_low_tier`.
    let mut top: Vec<(usize, f32)> = Vec::new();
    for (i, f) in file.findings.iter().enumerate() {
        if !strippable(f) {
            continue;
        }
        let contribution = 0.2 * f.conf;
        let base = f.id.split("::").next().unwrap_or(&f.id);
        let group = base.split('/').take(3).collect::<Vec<_>>().join("/");
        let e = group_max.entry(group).or_insert((i, f32::MIN));
        if contribution > e.1 {
            *e = (i, contribution);
        }
        top.push((i, f32::from(f.crit.rank()) * f.conf));
    }
    top.sort_by(|a, b| b.1.total_cmp(&a.1));
    top.truncate(3);
    let mut keep: rustc_hash::FxHashSet<usize> = group_max.values().map(|&(i, _)| i).collect();
    keep.extend(top.iter().map(|&(i, _)| i));

    let mut idx = 0;
    file.findings.retain(|f| {
        let i = idx;
        idx += 1;
        !strippable(f) || keep.contains(&i) || possibly_referenced(&f.id)
    });
}

/// In compact-member mode, release the Vec slack a folded member still
/// carries. The strip above `retain`s findings in place — capacity stays at
/// the pre-strip count — and the eval-time Vecs grew by doubling; measured on
/// a 54k-member archive the findings/evidence arrays held ~30% dead capacity
/// (~0.3 GB) through the whole archive ramp. Shrinking reallocates into
/// right-sized blocks, so the abandoned pages become purgeable instead of
/// pinned by live tails.
fn shrink_member_capacity(file: &mut FileAnalysis, engine: &crate::Engine) {
    if !engine.compact_members() {
        return;
    }
    file.findings.shrink_to_fit();
    for finding in &mut file.findings {
        finding.evidence.shrink_to_fit();
        finding.trait_refs.shrink_to_fit();
        for ev in &mut finding.evidence {
            ev.offsets.shrink_to_fit();
        }
    }
    file.context.shrink_to_fit();
    file.strings.shrink_to_fit();
    file.structure.shrink_to_fit();
}

/// In compact-member mode, project a folded member's fact vectors into their
/// compact form now and drop the sources. Nothing between the fold and compact
/// conversion reads them — finalize's cross-file passes consume findings,
/// identity and `filefacts.references`, all of which stay — and holding tens
/// of thousands of members' symbol tables through the archive ramp measured
/// ~0.4 GB of the benchmark peak. Module-load and downloader calls are retained for
/// dependency discovery; other `filefacts.symbols` are consumed into the
/// `tgt`/`mbr` sets by the same projection. `references` are kept for
/// `link_flagged_references`. Root files never come through this path (they
/// fold via `to_file_analysis`), so full-fidelity output is unaffected.
fn precompact_member_facts(file: &mut FileAnalysis, engine: &crate::Engine) {
    if !engine.compact_members() {
        return;
    }
    // Metrics stay flat: precompacting them was measured a regression — the
    // nested 2dp-rounded `Value` tree costs ~4× the flat `BTreeMap<String,f64>`
    // per member (537 MB of retained trees on the benchmark peak), so the
    // rounding happens at convert time as it always did.
    file.precompact_facts = Some(super::compact::compact_facts_from_parts(file, false));
    file.imports = Vec::new();
    file.exports = Vec::new();
    file.functions = Vec::new();
    file.sections = Vec::new();
    if let Some(view) = file.filefacts.as_mut() {
        retain_dependency_symbols(&mut view.symbols, &file.file_type);
    }
}

/// Keep the load and downloader calls the dependency hunter can use, without
/// retaining the full AST symbol table for every archive member.
fn retain_dependency_symbols(symbols: &mut Vec<filefacts::Symbol>, file_type: &str) {
    symbols.retain(|symbol| match symbol {
        filefacts::Symbol::Call {
            target: Some(name),
            args,
            ..
        } => {
            (matches!(
                name.as_str(),
                "require" | "import" | "__import__" | "importlib.import_module"
            ) && matches!(args.first(), Some(filefacts::Arg::String { .. })))
                || matches!(
                    name.rsplit(['/', '\\']).next(),
                    Some("curl" | "wget" | "curl.exe" | "wget.exe")
                )
                // GLib can write a stylesheet that imports an external asset.
                // The dependency reader needs the complete body argument after
                // archive folding; unrelated writes need no retained symbols.
                || (matches!(file_type, "javascript" | "typescript")
                    && name == "GLib.file_set_contents"
                    && matches!(args.get(1), Some(filefacts::Arg::String { value })
                        if value.len() <= 16_384 && value.contains("@import")))
                || (file_type == "ruby"
                    && matches!(
                        name.as_str(),
                        "system"
                            | "exec"
                            | "Kernel.system"
                            | "Kernel.exec"
                            | "::Kernel.system"
                            | "::Kernel.exec"
                    ))
        }
        filefacts::Symbol::Import { .. } => file_type == "python",
        filefacts::Symbol::Function { name, .. } => {
            file_type == "ruby" && matches!(name.as_str(), "system" | "exec")
        }
        filefacts::Symbol::Bind { target, .. } => {
            file_type == "ruby" && target.strip_prefix("::").unwrap_or(target) == "Kernel"
        }
        _ => false,
    });
    symbols.shrink_to_fit();
}

/// Drop folded-file payloads that have no reader in compact-member mode.
/// `filefacts.values` is a full clone of the structural value tree; its
/// Most consumers run during the file's own evaluation. Retain only the npm
/// identity and lifecycle scripts needed by dependency discovery after archive
/// members fold. No-op in full-retention mode: the v3 schema serializes it.
fn drop_unread_folded_fields(file: &mut FileAnalysis, engine: &crate::Engine) {
    if !engine.compact_members() {
        return;
    }
    if let Some(view) = file.filefacts.as_mut() {
        view.retain_compact_values();
        view.flow = None;
    }
    // Sub-notable findings never render as finding rows on any compact-path
    // surface (terminal focus starts at notable; compact traits carry no
    // evidence text — spans come from offsets), so their evidence values are
    // ballast once matching is done. Notable+ values are kept: the terminal
    // evidence column reads them. Baseline/component noise dominates finding
    // counts on member-heavy archives, so this is most of the weight.
    for f in &mut file.findings {
        if f.crit < Criticality::Notable {
            for e in &mut f.evidence {
                e.value = String::new();
            }
        }
    }
}

#[cfg(test)]
mod dependency_compact_retention_tests;

/// Cargo graph analysis runs after members fold. Compact mode may discard the
/// rest of the value tree, but not these bounded parser facts. Keep only the
/// graph inputs rather than retaining every Rust member's complete values.
fn retain_cargo_context_values(
    path: &str,
    tree: &serde_json::Value,
    out: &mut std::collections::BTreeMap<String, serde_json::Value>,
) {
    let basename = path.rsplit(['/', '\\', '!']).next().unwrap_or(path);
    if basename.eq_ignore_ascii_case("Cargo.toml") {
        flatten_kv_for_output(
            &serde_json::json!({
                "cargo": tree.get("cargo"),
                "package": {"build": tree.pointer("/package/build")},
                "lib": tree.get("lib"),
            }),
            out,
        );
    }
    if tree.pointer("/source/rust").is_some() {
        flatten_kv_for_output(
            &serde_json::json!({
                "source": {
                    "rust": tree.pointer("/source/rust"),
                    "payload_flow": tree.pointer("/source/payload_flow"),
                }
            }),
            out,
        );
    }
}

#[cfg(test)]
mod module_load_retention_tests;

#[cfg(test)]
mod cargo_compact_retention_tests;

/// Whether `path`'s flattened `kv` can ever be read again once this file
/// folds into its container. Always true in full-retention mode (the v3
/// schema serializes `kv`); in compact mode, true only when a loaded rule
/// reaches this file by basename via a `<filename>::` sibling kv path.
fn retain_folded_kv(path: &str, engine: &crate::Engine) -> bool {
    if !engine.compact_members() {
        return true;
    }
    // Mirror `sibling_path_matches`: the final `/`, `\`, or `!` component.
    let basename = path.rsplit(['/', '\\', '!']).next().unwrap_or(path);
    // Rules are not the only consumer. `compute_unused_runtime_deps` reads a
    // package.json member's flattened kv at *container* scope, after the member
    // has folded, to list declared runtime dependencies — and it is the only
    // reader that does so, which is why no `package.json::` sibling reference
    // exists to keep this alive. Dropping the kv left `declared` empty, so the
    // metric silently returned `None` and never emitted
    // `consistency.unused_runtime_deps`. The phantom-dependency trait that
    // reads it then could not fire in compact mode, taking the hostile
    // `npm-readme-clone-with-phantom-dependencies` composite down with it:
    // present under `cleave`, absent under any caller that enables compact
    // retention.
    //
    // `compute_self_dependency` reads the same way, and additionally needs the
    // Python distribution metadata member (`Name:` + `Requires-Dist:`), which
    // has no sibling reference keeping it alive either.
    if basename.eq_ignore_ascii_case("package.json")
        || basename.eq_ignore_ascii_case("PKG-INFO")
        || basename.eq_ignore_ascii_case("METADATA")
    {
        return true;
    }
    engine
        .rules()
        .kv_sibling_basenames()
        .iter()
        .any(|n| n.eq_ignore_ascii_case(basename))
}

/// Flatten a JSON kv tree into the per-file output map. Nested
/// objects become `parent.child`, arrays become `parent[0]`, leaves
/// land as their underlying value. Type-default leaves are skipped
/// because the output schema already omits other zero/empty/false
/// fields via `skip_serializing_if` — keeping kv consistent halves
/// the JSON payload on stripped binaries without losing signal
/// (consumers treat absent features as default).
pub(crate) fn flatten_kv_for_output(
    value: &serde_json::Value,
    out: &mut std::collections::BTreeMap<String, serde_json::Value>,
) {
    fn walk(
        value: &serde_json::Value,
        prefix: &str,
        out: &mut std::collections::BTreeMap<String, serde_json::Value>,
    ) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, v) in map {
                    let child = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    walk(v, &child, out);
                }
            }
            serde_json::Value::Array(arr) => {
                for (i, v) in arr.iter().enumerate() {
                    let child = format!("{prefix}[{i}]");
                    walk(v, &child, out);
                }
            }
            serde_json::Value::Null | serde_json::Value::Bool(false) => {}
            serde_json::Value::String(s) if s.is_empty() => {}
            // Skip every numeric zero in one arm: `as_f64` returns
            // `Some(0.0)` for both integer and float zeros, so this
            // covers `0`, `0.0`, and `-0.0` without two guards.
            serde_json::Value::Number(n) if n.as_f64() == Some(0.0) => {}
            _ => {
                if !prefix.is_empty() {
                    out.insert(prefix.to_string(), value.clone());
                }
            }
        }
    }
    walk(value, "", out);
}

/// Read a path out of a map produced by [`flatten_kv_for_output`], returning
/// every value it denotes.
///
/// The inverse of the flattening above, and deliberately its neighbour: the
/// encoding is not self-describing, so any reader has to know that an array at
/// `a.b` was written as `a.b[0]`, `a.b[1]`, … Keeping the writer and the reader
/// in one place is the only thing that stops the two drifting — the sibling-kv
/// evaluator previously open-coded an exact `get`, which silently resolved
/// scalar facts and missed every array one.
///
/// Returns the single value for a scalar leaf, or the elements in index order
/// for an array. Nested leaves below an element (`a.b[0].c`) belong to that
/// element, not to `a.b`, and are not returned.
pub(crate) fn kv_lookup_flattened<'a>(
    map: &'a std::collections::BTreeMap<String, serde_json::Value>,
    path: &str,
) -> Vec<&'a serde_json::Value> {
    if let Some(v) = map.get(path) {
        return vec![v];
    }
    let prefix = format!("{path}[");
    map.range(prefix.clone()..)
        .take_while(|(k, _)| k.starts_with(&prefix))
        .filter(|(k, _)| {
            k[prefix.len()..]
                .strip_suffix(']')
                .is_some_and(|i| !i.is_empty() && i.bytes().all(|b| b.is_ascii_digit()))
        })
        .map(|(_, v)| v)
        .collect()
}

/// Recursively merge two JSON objects. Object children are unioned
/// (with the right-hand-side winning on leaf collisions); non-object
/// leaves are replaced by the right-hand value. Used by
/// [`AnalysisReport::merge_kv_subtree`] so multiple writers under the
/// same top-level namespace coexist instead of clobbering each other.
fn deep_merge_objects(
    mut existing: serde_json::Map<String, serde_json::Value>,
    incoming: serde_json::Map<String, serde_json::Value>,
) -> serde_json::Map<String, serde_json::Value> {
    for (k, v) in incoming {
        let merged = match (existing.remove(&k), v) {
            (Some(serde_json::Value::Object(a)), serde_json::Value::Object(b)) => {
                serde_json::Value::Object(deep_merge_objects(a, b))
            }
            (_, b) => b,
        };
        existing.insert(k, merged);
    }
    existing
}

/// Collapse duplicate findings in-place by `id`. The surviving entry takes
/// the max criticality and confidence; `match_count` is summed; `evidence`
/// is concatenated and re-deduplicated through
/// [`super::traits_findings::deduplicate_evidence`]; `trait_refs` is unioned.
/// First appearance order is preserved.
fn dedupe_finding_list(findings: &mut Vec<Finding>) {
    use rustc_hash::FxHashMap;
    if findings.len() <= 1 {
        return;
    }
    let original = std::mem::take(findings);
    let mut id_to_index: FxHashMap<String, usize> = FxHashMap::default();
    for f in original {
        match id_to_index.get(f.id.as_str()) {
            None => {
                id_to_index.insert(f.id.clone().to_string(), findings.len());
                findings.push(f);
            }
            Some(&idx) => merge_finding(&mut findings[idx], f),
        }
    }
    // After concatenation each surviving finding may carry redundant evidence;
    // run the existing evidence dedup pass once.
    for f in findings {
        if f.evidence.len() > 1 {
            let ev = std::mem::take(&mut f.evidence);
            f.evidence = super::traits_findings::deduplicate_evidence(ev);
            if f.evidence.len() > super::traits_findings::MAX_EVIDENCE_PER_TRAIT {
                f.evidence
                    .truncate(super::traits_findings::MAX_EVIDENCE_PER_TRAIT);
            }
        }
    }
}

fn merge_finding(existing: &mut Finding, new: Finding) {
    if new.crit > existing.crit {
        existing.crit = new.crit;
    }
    if new.conf > existing.conf {
        existing.conf = new.conf;
    }
    existing.match_count = existing.match_count.saturating_add(new.match_count);
    // If either side carries precomputed emission spans (compact-retained
    // member whose evidence strings were released at fold), the merged
    // finding's spans are the union under the same offset-dedup rules the
    // convert-time derivation applies — otherwise merged evidence would be
    // silently dropped from the emitted spans.
    if existing.precomputed_spans.is_some() || new.precomputed_spans.is_some() {
        let mut spans = crate::types::traits_findings::finding_spans(existing);
        spans.extend(crate::types::traits_findings::finding_spans(&new));
        crate::types::traits_findings::sort_dedup_spans_by_offset(&mut spans);
        spans.truncate(crate::types::traits_findings::MAX_EV_LOCS);
        existing.precomputed_spans = Some(spans);
    }
    existing.evidence.extend(new.evidence);
    for r in new.trait_refs {
        if !existing.trait_refs.contains(&r) {
            existing.trait_refs.push(r);
        }
    }
    if existing.desc.is_empty() && !new.desc.is_empty() {
        existing.desc = new.desc;
    }
}

/// Where finding `id`'s evidence sits in `file`, as `(line, offset)`: its
/// first matched byte, and the 1-based source line when a textual window holds
/// that byte. `None` when the finding matched no byte of this file — e.g. a
/// metric or manifest-field-presence trait.
fn evidence_location(file: &FileAnalysis, id: &str) -> Option<(Option<u64>, Option<u64>)> {
    let finding = file
        .findings
        .iter()
        .find(|f| f.id == id && f.src.is_none())?;
    let [off, _] = *crate::types::traits_findings::finding_spans(finding).first()?;
    let line = file.context.iter().find_map(|w| {
        let rel = usize::try_from(off.checked_sub(w.loc)?).ok()?;
        let before = w.data.get(..rel).filter(|_| rel < w.data.len())?;
        Some(w.line? + before.iter().filter(|&&b| b == b'\n').count() as u64)
    });
    Some((line, Some(off)))
}

/// Stable ordering for representative composite-source locations. Prefer the
/// earliest concrete byte offset, then the source line; unanchored notes sort
/// after located evidence.
fn source_location_order(location: (Option<u64>, Option<u64>)) -> (u64, u64) {
    (
        location.1.unwrap_or(u64::MAX),
        location.0.unwrap_or(u64::MAX),
    )
}

/// The leaf member name of an archive-member file path: the segment after the
/// last archive delimiter (`a.zip!!dir/b.so` → `dir/b.so`).
pub(crate) fn leaf_member(path: &str) -> &str {
    use super::file_analysis::ARCHIVE_DELIMITER;
    path.rsplit(ARCHIVE_DELIMITER).next().unwrap_or(path)
}

/// The archive member an evidence location points at, or `None` when the
/// location isn't archive-scoped. Strips the `archive:` scheme, any trailing
/// `:0x<offset>` the matcher appended, and any wrapper prefix, leaving the leaf
/// member name to match against [`leaf_member`].
fn located_member(location: &str) -> Option<&str> {
    use super::file_analysis::ARCHIVE_DELIMITER;
    let rel = location.strip_prefix("archive:")?;
    // Drop a trailing offset suffix (e.g. `…:0x1126`); member names don't carry one.
    let rel = match rel.rfind(":0x") {
        Some(i) if rel[i + 3..].bytes().all(|b| b.is_ascii_hexdigit()) => &rel[..i],
        _ => rel,
    };
    Some(rel.rsplit(ARCHIVE_DELIMITER).next().unwrap_or(rel))
}

fn immediate_wrapper_path(path: &str) -> Option<&str> {
    use super::file_analysis::{ARCHIVE_DELIMITER, ENCODING_DELIMITER};

    let archive_pos = path.rfind(ARCHIVE_DELIMITER);
    let encoding_pos = path.rfind(ENCODING_DELIMITER);
    match (archive_pos, encoding_pos) {
        (Some(a), Some(e)) => Some(&path[..a.max(e)]),
        (Some(a), None) => Some(&path[..a]),
        (None, Some(e)) => Some(&path[..e]),
        (None, None) => None,
    }
}

fn wrapper_delimiter_count(path: &str) -> usize {
    use super::file_analysis::{ARCHIVE_DELIMITER, ENCODING_DELIMITER};

    path.matches(ARCHIVE_DELIMITER).count() + path.matches(ENCODING_DELIMITER).count()
}

/// Information about the file being analyzed
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TargetInfo {
    /// Absolute path to the analyzed file
    pub path: String,
    /// Detected file type (e.g., "elf", "python", "zip")
    #[serde(rename = "type")]
    pub file_type: String,
    /// File size in bytes
    pub size_bytes: u64,
    /// SHA256 hash of the file contents
    pub sha256: String,
    /// CPU architectures (for fat/universal binaries)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub architectures: Option<Vec<String>>,
}

impl TargetInfo {
    /// Returns true when target has been cleared (after finalize).
    /// Used by skip_serializing_if to omit the field from output.
    fn is_cleared(&self) -> bool {
        self.path.is_empty()
    }
}

/// Metadata about a file contained within an archive
/// The path field matches Evidence.location without the "archive:" prefix.
/// For nested archives, uses `!` separator: "inner.tar.gz!path/to/file.txt"
///
/// The optional fields below are populated by format-aware extractors (zip,
/// tar): timestamps, POSIX ownership/mode, compression choice, entry type,
/// link targets.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ArchiveEntry {
    /// Path within the archive. For nested archives, uses `!` separator.
    /// Examples: "lib/utils.so", "inner.tar.gz!malware/script.sh"
    pub path: String,
    /// Detected file type (e.g., "java-class", "shell", "elf")
    #[serde(rename = "type")]
    pub file_type: String,
    /// SHA256 hash of the file contents
    pub sha256: String,
    /// File size in bytes (uncompressed)
    pub size_bytes: u64,
    /// Container-specific member kind, for example a PyInstaller entry kind.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub container_kind: Option<String>,

    /// Compressed size in bytes; the zip-bomb ratio guard reads it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub compressed_size: Option<u64>,
    /// Compression method: "stored", "deflate", "lzma", "zstd", "bzip2", etc.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub compression_method: Option<String>,
    /// Entry type: "regular", "symlink", "hardlink", "dir", "char-dev",
    /// "block-dev", "fifo", "pax-header", "gnu-longname", etc.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub entry_type: Option<String>,
    /// ZIP compressed payload offset, when filefacts indexed the container.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data_offset: Option<u64>,
    /// Symlink target; the symlink-escape guard reads it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub linkname: Option<String>,
    /// CRC-32 the archive records for the member; extraction verifies the
    /// bytes it reads against it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub crc32: Option<u32>,
    /// True when the archive entry is encrypted.
    #[serde(skip_serializing_if = "is_false", default)]
    pub encrypted: bool,
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod early_strip_tests;
