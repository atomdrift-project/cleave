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
use super::traits_findings::{ContextLine, Finding, StructuralFeature, Trait};
use crate::analyzers::FileType;
use crate::malecule_bridge;

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
    /// around itself. The binary analogue of [`context_radius`], but asymmetric:
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
    /// Filefacts's flat metric map (`{ "lnk.args_max_whitespace_run":
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
    /// match can attach the location to its finding for downstream (prism).
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
    /// Embedded in the v3 envelope so prism/litmus can consume diff and
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
    /// Insert a signed integer (cast to `f64`).
    fn set_i(&mut self, key: impl Into<String>, value: i64);
    /// Insert an `f64` verbatim.
    fn set_f(&mut self, key: impl Into<String>, value: f64);
    /// Insert a boolean as `0.0` / `1.0`.
    fn set_b(&mut self, key: impl Into<String>, value: bool);
    /// Insert an `Option<bool>` — `None` leaves the map unchanged.
    fn set_b_opt(&mut self, key: impl Into<String>, value: Option<bool>);
    /// Read a stored value back as `u64` (returns `None` when absent).
    fn get_u(&self, key: &str) -> Option<u64>;
    /// Read a stored boolean back (returns `None` when absent;
    /// `1.0` → `Some(true)`, anything else stored → `Some(false)`).
    fn get_b(&self, key: &str) -> Option<bool>;
}

impl MetricsExt for std::collections::BTreeMap<String, f64> {
    fn set_u(&mut self, key: impl Into<String>, value: u64) {
        self.insert(key.into(), value as f64);
    }
    fn set_i(&mut self, key: impl Into<String>, value: i64) {
        self.insert(key.into(), value as f64);
    }
    fn set_f(&mut self, key: impl Into<String>, value: f64) {
        self.insert(key.into(), value);
    }
    fn set_b(&mut self, key: impl Into<String>, value: bool) {
        self.insert(key.into(), if value { 1.0 } else { 0.0 });
    }
    fn set_b_opt(&mut self, key: impl Into<String>, value: Option<bool>) {
        if let Some(v) = value {
            self.set_b(key, v);
        }
    }
    fn get_u(&self, key: &str) -> Option<u64> {
        self.get(key).map(|v| *v as u64)
    }
    fn get_b(&self, key: &str) -> Option<bool> {
        self.get(key).map(|v| *v != 0.0)
    }
}

/// Flatten any `Serialize` value into the flat metric map under
/// dotted keys prefixed with `prefix`. Numbers become `f64`; bools
/// become `1.0` / `0.0`; nested objects recurse; strings and arrays
/// are skipped (they belong in `values_tree`, not `metrics`). The
/// transitional path during #41 — producers that still build typed
/// structs internally can dump them into `filefacts_metrics` in one
/// call instead of writing N `metrics.insert(...)` lines by hand.
pub fn flatten_into_metrics<T: serde::Serialize>(
    value: &T,
    prefix: &str,
    out: &mut std::collections::BTreeMap<String, f64>,
) {
    if let Ok(json) = serde_json::to_value(value) {
        flatten_json_into_metrics(&json, prefix, out);
    }
}

fn flatten_json_into_metrics(
    value: &serde_json::Value,
    prefix: &str,
    out: &mut std::collections::BTreeMap<String, f64>,
) {
    if let serde_json::Value::Object(map) = value {
        for (k, v) in map {
            let key = if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            };
            match v {
                serde_json::Value::Number(n) => {
                    if let Some(f) = n.as_f64() {
                        out.insert(key, f);
                    }
                }
                serde_json::Value::Bool(b) => {
                    out.insert(key, if *b { 1.0 } else { 0.0 });
                }
                serde_json::Value::Object(_) => flatten_json_into_metrics(v, &key, out),
                _ => {}
            }
        }
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
            analysis_timestamp: Some(timestamp),
            target,
            traits: Vec::new(),
            findings: Vec::new(),
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
        let filtered = crate::output::filter_findings_for_formula(&file.findings);
        let formula = malecule_bridge::formula_from_findings(&filtered);
        file.formula = (!formula.is_empty()).then_some(formula);
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
        let mut added = 0;
        if let Some(file) = self.files.iter_mut().find(|f| f.sha256 == target_sha) {
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
        if added > 0 {
            self.summary = Some(ReportSummary::from_files(&self.files));
            // `finalize()` resolved composite source trails before this graft, so
            // the just-added package composites have none. Re-run the attribution
            // (merge, not replace — see `attach_composite_sources`) so each picks
            // up the `↳ member:line` provenance of the legs it fired on, including
            // a registry/provenance child linked to this node. Cheap: graft runs
            // once per correlated artifact, before `strip` drops the legs it reads.
            Self::attach_composite_sources(&mut self.files);
        }
        added
    }

    /// Merge a per-format kv subtree into `values_tree` under `namespace`.
    /// Preserves existing namespaces; pre-existing non-object trees
    /// are stashed under `_legacy` so we never lose data. Used by
    /// every per-format kv attacher (`png`, `jpeg`, `class`, `pyc`,
    /// `pickle`, `jar`, `rpm`, …).
    /// Materialize an `archive.*` kv subtree from `archive_contents`.
    ///
    /// Emits one entry per member (with all forensic fields the extractors
    /// captured) plus aggregate subtrees that traits can match on without
    /// iterating the array themselves:
    ///
    /// - `archive.members[]` — full per-member objects (paths, sha256,
    ///   sizes, mode bits, mtime, uid/gid/uname/gname, link targets).
    /// - `archive.member_count` — total entries surfaced.
    /// - `archive.compression.{methods, method_counts, ratio}` — choice of
    ///   compressor across members and the aggregate ratio.
    /// - `archive.timing.{mtime_min, mtime_max, mtime_spread_seconds,
    ///   mtime_unique_count}` — temporal fingerprint useful for supply-chain
    ///   triage (genuine builds cluster, replays smear, reproducible builds
    ///   pin to one or two epochs).
    /// - `archive.security.{setuid_count, setgid_count, sticky_count,
    ///   world_writable_count, symlink_count, external_symlink_count}` —
    ///   permission/symlink shapes that gate supply-chain risk traits.
    /// - `archive.format.{entry_types, regular_count, directory_count,
    ///   symlink_count}` — entry-type histogram.
    /// - `archive.builder.{unames, gnames}` — POSIX ownership strings tar
    ///   often leaks (real usernames frequently appear in supply-chain samples).
    ///
    /// Idempotent: callers may invoke this multiple times; the last call
    /// wins. No-op when `archive_contents` is empty.
    pub(crate) fn seal_archive_metadata_kv(&mut self) {
        if self.archive_contents.is_empty() {
            return;
        }

        use std::collections::BTreeMap;
        let mut method_counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut entry_type_counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut unames: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut gnames: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut mtimes: Vec<i64> = Vec::new();
        let mut total_uncompressed: u64 = 0;
        let mut total_compressed: u64 = 0;
        let mut setuid_count: u64 = 0;
        let mut setgid_count: u64 = 0;
        let mut sticky_count: u64 = 0;
        let mut world_writable_count: u64 = 0;
        let mut symlink_count: u64 = 0;
        let mut external_symlink_count: u64 = 0;

        let mut members = Vec::with_capacity(self.archive_contents.len());
        for entry in &self.archive_contents {
            let mut obj = serde_json::Map::new();
            obj.insert("path".into(), serde_json::Value::String(entry.path.clone()));
            obj.insert(
                "type".into(),
                serde_json::Value::String(entry.file_type.clone()),
            );
            obj.insert(
                "sha256".into(),
                serde_json::Value::String(entry.sha256.clone()),
            );
            obj.insert(
                "size_bytes".into(),
                serde_json::Value::Number(entry.size_bytes.into()),
            );
            if let Some(ref declared) = entry.declared_type {
                obj.insert(
                    "declared_type".into(),
                    serde_json::Value::String(declared.clone()),
                );
            }
            if entry.extension_type_mismatch {
                obj.insert(
                    "extension_type_mismatch".into(),
                    serde_json::Value::Bool(true),
                );
            }
            if let Some(entropy) = entry.entropy
                && let Some(number) = serde_json::Number::from_f64(entropy)
            {
                obj.insert("entropy".into(), serde_json::Value::Number(number));
            }
            if let Some(ref magic) = entry.magic_prefix {
                obj.insert(
                    "magic_prefix".into(),
                    serde_json::Value::String(magic.clone()),
                );
            }
            if let Some(ref kind) = entry.container_kind {
                obj.insert(
                    "container_kind".into(),
                    serde_json::Value::String(kind.clone()),
                );
            }
            if let Some(v) = entry.compressed_size {
                obj.insert(
                    "compressed_size".into(),
                    serde_json::Value::Number(v.into()),
                );
                total_compressed = total_compressed.saturating_add(v);
            }
            total_uncompressed = total_uncompressed.saturating_add(entry.size_bytes);
            if let Some(ref m) = entry.compression_method {
                obj.insert(
                    "compression_method".into(),
                    serde_json::Value::String(m.clone()),
                );
                *method_counts.entry(m.clone()).or_insert(0) += 1;
            }
            if let Some(t) = entry.mtime_unix {
                obj.insert("mtime_unix".into(), serde_json::Value::Number(t.into()));
                mtimes.push(t);
            }
            if let Some(m) = entry.mode_octal {
                obj.insert("mode_octal".into(), serde_json::Value::Number(m.into()));
                if m & 0o4000 != 0 {
                    setuid_count += 1;
                }
                if m & 0o2000 != 0 {
                    setgid_count += 1;
                }
                if m & 0o1000 != 0 {
                    sticky_count += 1;
                }
                if m & 0o002 != 0 {
                    world_writable_count += 1;
                }
            }
            if let Some(u) = entry.uid {
                obj.insert("uid".into(), serde_json::Value::Number(u.into()));
            }
            if let Some(g) = entry.gid {
                obj.insert("gid".into(), serde_json::Value::Number(g.into()));
            }
            if let Some(ref u) = entry.uname {
                obj.insert("uname".into(), serde_json::Value::String(u.clone()));
                unames.insert(u.clone());
            }
            if let Some(ref g) = entry.gname {
                obj.insert("gname".into(), serde_json::Value::String(g.clone()));
                gnames.insert(g.clone());
            }
            if let Some(ref t) = entry.entry_type {
                obj.insert("entry_type".into(), serde_json::Value::String(t.clone()));
                *entry_type_counts.entry(t.clone()).or_insert(0) += 1;
                if t == "symlink" {
                    symlink_count += 1;
                    if let Some(ref link) = entry.linkname
                        && (link.starts_with('/') || link.contains(".."))
                    {
                        external_symlink_count += 1;
                    }
                }
            }
            if let Some(ref link) = entry.linkname {
                obj.insert("linkname".into(), serde_json::Value::String(link.clone()));
            }
            if let Some(ref os) = entry.host_os {
                obj.insert("host_os".into(), serde_json::Value::String(os.clone()));
            }
            if let Some(v) = entry.header_offset {
                obj.insert("header_offset".into(), serde_json::Value::Number(v.into()));
            }
            if let Some(v) = entry.data_offset {
                obj.insert("data_offset".into(), serde_json::Value::Number(v.into()));
            }
            if let Some(v) = entry.central_header_offset {
                obj.insert(
                    "central_header_offset".into(),
                    serde_json::Value::Number(v.into()),
                );
            }
            if let Some(v) = entry.crc32 {
                obj.insert(
                    "crc32".into(),
                    serde_json::Value::Number(u64::from(v).into()),
                );
            }
            if entry.encrypted {
                obj.insert("encrypted".into(), serde_json::Value::Bool(true));
            }
            members.push(serde_json::Value::Object(obj));
        }

        let mut root = serde_json::Map::new();
        root.insert("members".into(), serde_json::Value::Array(members));
        root.insert(
            "member_count".into(),
            serde_json::Value::Number((self.archive_contents.len() as u64).into()),
        );

        if !method_counts.is_empty() || total_compressed > 0 {
            let mut comp = serde_json::Map::new();
            let methods: Vec<serde_json::Value> = method_counts
                .keys()
                .map(|k| serde_json::Value::String(k.clone()))
                .collect();
            let counts: serde_json::Map<String, serde_json::Value> = method_counts
                .iter()
                .map(|(k, v)| (k.clone(), serde_json::Value::Number((*v).into())))
                .collect();
            comp.insert("methods".into(), serde_json::Value::Array(methods));
            comp.insert("method_counts".into(), serde_json::Value::Object(counts));
            if total_uncompressed > 0 && total_compressed > 0 {
                let ratio = total_compressed as f64 / total_uncompressed as f64;
                if let Some(n) = serde_json::Number::from_f64(ratio) {
                    comp.insert("ratio".into(), serde_json::Value::Number(n));
                }
            }
            root.insert("compression".into(), serde_json::Value::Object(comp));
        }

        if !mtimes.is_empty() {
            let mut timing = serde_json::Map::new();
            let min = *mtimes.iter().min().unwrap_or(&0);
            let max = *mtimes.iter().max().unwrap_or(&0);
            let unique: std::collections::BTreeSet<i64> = mtimes.iter().copied().collect();
            timing.insert("mtime_min".into(), serde_json::Value::Number(min.into()));
            timing.insert("mtime_max".into(), serde_json::Value::Number(max.into()));
            timing.insert(
                "mtime_spread_seconds".into(),
                serde_json::Value::Number((max - min).into()),
            );
            timing.insert(
                "mtime_unique_count".into(),
                serde_json::Value::Number((unique.len() as u64).into()),
            );
            root.insert("timing".into(), serde_json::Value::Object(timing));
        }

        let mut security = serde_json::Map::new();
        security.insert(
            "setuid_count".into(),
            serde_json::Value::Number(setuid_count.into()),
        );
        security.insert(
            "setgid_count".into(),
            serde_json::Value::Number(setgid_count.into()),
        );
        security.insert(
            "sticky_count".into(),
            serde_json::Value::Number(sticky_count.into()),
        );
        security.insert(
            "world_writable_count".into(),
            serde_json::Value::Number(world_writable_count.into()),
        );
        security.insert(
            "symlink_count".into(),
            serde_json::Value::Number(symlink_count.into()),
        );
        security.insert(
            "external_symlink_count".into(),
            serde_json::Value::Number(external_symlink_count.into()),
        );
        root.insert("security".into(), serde_json::Value::Object(security));

        if !entry_type_counts.is_empty() {
            let mut fmt = serde_json::Map::new();
            let types: Vec<serde_json::Value> = entry_type_counts
                .keys()
                .map(|k| serde_json::Value::String(k.clone()))
                .collect();
            fmt.insert("entry_types".into(), serde_json::Value::Array(types));
            for (k, v) in &entry_type_counts {
                fmt.insert(
                    format!("{}_count", k.replace('-', "_")),
                    serde_json::Value::Number((*v).into()),
                );
            }
            root.insert("format".into(), serde_json::Value::Object(fmt));
        }

        if !unames.is_empty() || !gnames.is_empty() {
            let mut builder = serde_json::Map::new();
            if !unames.is_empty() {
                builder.insert(
                    "unames".into(),
                    serde_json::Value::Array(
                        unames
                            .iter()
                            .map(|s| serde_json::Value::String(s.clone()))
                            .collect(),
                    ),
                );
            }
            if !gnames.is_empty() {
                builder.insert(
                    "gnames".into(),
                    serde_json::Value::Array(
                        gnames
                            .iter()
                            .map(|s| serde_json::Value::String(s.clone()))
                            .collect(),
                    ),
                );
            }
            root.insert("builder".into(), serde_json::Value::Object(builder));
        }

        self.merge_kv_subtree("archive", serde_json::Value::Object(root));
    }

    pub(crate) fn merge_kv_subtree(&mut self, namespace: &str, value: serde_json::Value) {
        let mut root = match self.values_tree.take().map(|b| *b) {
            Some(serde_json::Value::Object(m)) => m,
            Some(other) => {
                let mut m = serde_json::Map::new();
                m.insert("_legacy".into(), other);
                m
            }
            None => serde_json::Map::new(),
        };
        // Deep-merge into any existing namespace value when both
        // sides are objects, so multiple contributors (e.g. filefacts
        // adds `build.toolchain.*` while cleave's binary_extractors
        // adds `build.username`) coexist instead of clobbering.
        // Falls back to outright replace for non-object values.
        let merged = match (root.remove(namespace), value) {
            (Some(serde_json::Value::Object(existing)), serde_json::Value::Object(incoming)) => {
                serde_json::Value::Object(deep_merge_objects(existing, incoming))
            }
            (_, v) => v,
        };
        root.insert(namespace.into(), merged);
        self.values_tree = Some(Box::new(serde_json::Value::Object(root)));
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

    /// Filter findings using a predicate function.
    /// Applies the filter to both the top-level findings and findings within files.
    /// Returns the number of findings removed.
    pub fn filter_findings<F>(&mut self, predicate: F) -> usize
    where
        F: Fn(&Finding) -> bool,
    {
        let initial_count =
            self.findings.len() + self.files.iter().map(|f| f.findings.len()).sum::<usize>();

        // Filter top-level findings
        self.findings.retain(&predicate);

        // Filter findings in files array (v2 schema)
        for file in &mut self.files {
            file.findings.retain(&predicate);
        }

        let final_count =
            self.findings.len() + self.files.iter().map(|f| f.findings.len()).sum::<usize>();

        let removed = initial_count - final_count;

        // Recompute per-file summaries and report summary after filtering
        if removed > 0 {
            for file in &mut self.files {
                Self::refresh_formula(file);
                file.compute_summary();
            }
            self.summary = Some(ReportSummary::from_files(&self.files));
        }

        removed
    }

    /// Strip Component- and Baseline-criticality findings that no fired composite
    /// references, then recompute summaries. Component traits are composite
    /// building blocks and baseline traits are universal noise; both are only
    /// worth keeping in the output once a composite that uses them has fired (its
    /// id appears in some finding's `trait_refs`). Dropping the rest is the bulk
    /// of what shrinks large archive reports.
    ///
    /// MUST run only after every up-the-chain composite recomputation (archive and
    /// encoding-layer inheritance, container re-evaluation): those parent
    /// composites consume the component/baseline findings as inputs, so stripping
    /// earlier would stop them firing. See `Self::attach_composite_sources`,
    /// which deliberately records each composite→member tie *before* this strip
    /// removes the low-tier traits.
    ///
    /// As an exception, a file that would otherwise be left with no
    /// notable-or-higher finding keeps its `RESCUE_LOW_TIER_KEEP` best
    /// low-tier traits. An empty findings list tells a downstream LLM consumer
    /// nothing about the file; a few weak traits at least give it a clue.
    ///
    /// Returns `(components_removed, baselines_removed)`.
    pub fn strip_unmatched_traits(&mut self) -> (usize, usize) {
        use std::collections::HashSet;

        // `crit: exception` composites are assembly-only: they drive `unless:` /
        // `downgrade:` suppression while composites are evaluated, and by the time
        // we finalize a report that work is already baked into the surviving
        // findings' criticalities. They must never surface in output, so drop them
        // unconditionally here — before the component/baseline strip and its
        // low-tier rescue, so an exception can never be referenced-rescued or
        // low-tier-rescued back into the rendered findings.
        self.findings.retain(|f| f.crit != Criticality::Exception);
        for file in &mut self.files {
            file.findings.retain(|f| f.crit != Criticality::Exception);
        }

        // Ids referenced by a fired composite, unioned across every file: a trait
        // is kept regardless of its own criticality if any composite uses it.
        let mut referenced: HashSet<String> = HashSet::new();
        for finding in &self.findings {
            referenced.extend(finding.trait_refs.iter().cloned());
        }
        for file in &self.files {
            for finding in &file.findings {
                referenced.extend(finding.trait_refs.iter().cloned());
            }
        }

        // A component/baseline finding is strippable unless a fired composite
        // references it.
        let strippable = |f: &Finding| {
            matches!(f.crit, Criticality::Component | Criticality::Baseline)
                && !referenced.contains(&f.id)
        };

        let mut components = 0usize;
        let mut baselines = 0usize;
        let mut tally = |f: &Finding| match f.crit {
            Criticality::Component => components += 1,
            Criticality::Baseline => baselines += 1,
            _ => {}
        };

        // Top-level findings are cleared at finalize and never serve as the
        // per-file LLM clue, so they follow the base rule with no rescue.
        self.findings.retain(|f| {
            let keep = !strippable(f);
            if !keep {
                tally(f);
            }
            keep
        });

        // Per file: rescue the best low-tier traits when nothing else survives.
        for file in &mut self.files {
            let rescued = Self::rescue_low_tier(&file.findings, &strippable);
            file.findings.retain(|f| {
                let keep = !strippable(f) || rescued.contains(&f.id);
                if !keep {
                    tally(f);
                }
                keep
            });
        }

        if components + baselines > 0 {
            for file in &mut self.files {
                Self::refresh_formula(file);
                file.compute_summary();
            }
            self.summary = Some(ReportSummary::from_files(&self.files));
            tracing::debug!(
                components_removed = components,
                baselines_removed = baselines,
                "stripped unmatched component and baseline traits before render",
            );
        }

        (components, baselines)
    }

    /// Pick the ids of the low-tier traits to keep for a file that carries no
    /// notable-or-higher signal, so its findings list is never empty. Returns an
    /// empty set when the file already has real signal (no rescue needed) or has
    /// no strippable traits to offer.
    ///
    /// Candidates rank best-first by score (criticality × confidence), with the
    /// trait id as a deterministic final tiebreak.
    fn rescue_low_tier<F>(findings: &[Finding], strippable: &F) -> std::collections::HashSet<String>
    where
        F: Fn(&Finding) -> bool,
    {
        if findings.iter().any(|f| f.crit >= Criticality::Notable) {
            return std::collections::HashSet::new();
        }

        let score = |f: &Finding| f32::from(f.crit.rank()) * f.conf;
        let mut candidates: Vec<&Finding> = findings.iter().filter(|f| strippable(f)).collect();
        candidates.sort_by(|a, b| score(b).total_cmp(&score(a)).then(a.id.cmp(&b.id)));
        candidates
            .into_iter()
            .take(RESCUE_LOW_TIER_KEEP)
            .map(|f| f.id.clone())
            .collect()
    }

    /// Merge encoding layers (files with `##` in their path) into their parent files.
    ///
    /// Each encoding layer's findings are merged into the parent file, deduplicating
    /// by finding ID (keeping the highest criticality). The layer entries are removed
    /// from the files array.
    ///
    /// Returns the indices (in the post-merge files array) of files that had layers merged,
    /// so callers can recalculate composites on those files.
    pub fn merge_encoding_layers(&mut self) -> Vec<usize> {
        use super::file_analysis::ENCODING_DELIMITER;

        // Identify which files are encoding layers and map them to their parent path
        // A layer path looks like: "parent_path##encoding@offset"
        // The parent is everything before the first "##"
        let mut layer_findings: std::collections::HashMap<String, Vec<Finding>> =
            std::collections::HashMap::new();

        let mut layer_indices = Vec::new();
        for (i, file) in self.files.iter().enumerate() {
            if let Some(pos) = file.path.find(ENCODING_DELIMITER) {
                let parent_path = &file.path[..pos];
                layer_findings
                    .entry(parent_path.to_string())
                    .or_default()
                    .extend(file.findings.clone());
                layer_indices.push(i);
            }
        }

        if layer_indices.is_empty() {
            return Vec::new();
        }

        // Remove layer entries from files (in reverse order to preserve indices)
        for &i in layer_indices.iter().rev() {
            self.files.remove(i);
        }

        // Merge layer findings into their parent files
        let mut merged_file_indices = Vec::new();
        for (i, file) in self.files.iter_mut().enumerate() {
            if let Some(findings) = layer_findings.remove(&file.path) {
                // Merge findings, deduplicating by ID (keep highest criticality)
                for finding in findings {
                    if let Some(existing) = file.findings.iter_mut().find(|f| f.id == finding.id) {
                        if finding.crit > existing.crit {
                            *existing = finding;
                        }
                    } else {
                        file.findings.push(finding);
                    }
                }
                Self::refresh_formula(file);
                file.compute_summary();
                merged_file_indices.push(i);
            }
        }

        merged_file_indices
    }

    /// Add child-file findings to their containing wrapper while preserving the
    /// child entries. This keeps archive members, embedded binaries, and UPX
    /// layers attributable as separate files, but ensures filtering and root
    /// summaries still reflect behavior hidden behind the wrapper.
    pub fn inherit_child_findings_into_wrappers(&mut self) -> Vec<usize> {
        use rustc_hash::{FxHashMap, FxHashSet};

        if self.files.len() <= 1 {
            return Vec::new();
        }

        let path_to_index: FxHashMap<String, usize> = self
            .files
            .iter()
            .enumerate()
            .map(|(idx, file)| (file.path.clone(), idx))
            .collect();

        let mut child_indices: Vec<usize> = self
            .files
            .iter()
            .enumerate()
            .filter_map(|(idx, file)| immediate_wrapper_path(&file.path).map(|_| idx))
            .collect();
        child_indices.sort_by_key(|&idx| {
            std::cmp::Reverse((
                self.files[idx].depth,
                wrapper_delimiter_count(&self.files[idx].path),
            ))
        });

        let mut changed = FxHashSet::default();
        for child_idx in child_indices {
            let Some(parent_path) = immediate_wrapper_path(&self.files[child_idx].path) else {
                continue;
            };
            let Some(&parent_idx) = path_to_index.get(parent_path) else {
                continue;
            };
            if parent_idx == child_idx || self.files[child_idx].findings.is_empty() {
                continue;
            }

            // Stamp the inherited copies with the child's file id so consumers
            // can tell a wrapper finding bubbled up from a member (and from which
            // one), and de-duplicate the view by attributing it to its origin.
            // Preserve any deeper `src` already set (a finding inherited through
            // several wrapper layers keeps pointing at where it was located).
            let child_id = self.files[child_idx].id;
            let child_findings: Vec<Finding> = self.files[child_idx]
                .findings
                .iter()
                .cloned()
                .map(|mut f| {
                    f.src.get_or_insert(child_id);
                    f
                })
                .collect();
            let parent = &mut self.files[parent_idx];
            parent.findings.extend(child_findings);
            dedupe_finding_list(&mut parent.findings);
            Self::refresh_formula(parent);
            parent.compute_summary();
            changed.insert(parent_idx);
        }

        let mut changed: Vec<usize> = changed.into_iter().collect();
        changed.sort_unstable();
        changed
    }

    /// Resolve, for every cross-file composite finding, the archive members it
    /// drew components from — recording each as a [`CompositeSource`] (member
    /// file id plus the component's location when a context note pins it). The
    /// composite's `trait_refs` name its component traits; a member contributed
    /// if it carries a finding with one of those ids. Stored on the container
    /// file's `composite_sources`, keyed by composite finding id.
    ///
    /// Runs during `finalize`, before component findings are filtered from the
    /// output: the low-tier traits that link a composite to a member (e.g. an
    /// install-hook presence trait on a package.json) are gone by render/compact
    /// time, so this is the one point where the tie is recoverable.
    fn attach_composite_sources(files: &mut [FileAnalysis]) {
        use super::file_analysis::{ARCHIVE_DELIMITER, CompositeSource};
        use rustc_hash::FxHashMap;
        use std::collections::BTreeMap;

        // A composite spanning more members than this is treated as a ubiquitous
        // pattern, not targeted provenance — its sources are dropped (see below).
        const MAX_COMPOSITE_SOURCES: usize = 8;

        // Component finding id → file indices carrying it (skip synthetic
        // embedded-binary extractions; their carrier member stands in for them).
        let mut id_to_files: FxHashMap<&str, Vec<usize>> = FxHashMap::default();
        for (i, f) in files.iter().enumerate() {
            if f.path.contains("embedded:") {
                continue;
            }
            for finding in &f.findings {
                id_to_files.entry(finding.id.as_str()).or_default().push(i);
            }
        }

        // Borrow `files` immutably to resolve, collect owned results, then write
        // back — the resolution reads every file while we build per-container maps.
        let mut resolved: Vec<(usize, BTreeMap<String, Vec<CompositeSource>>)> = Vec::new();
        for (ci, container) in files.iter().enumerate() {
            let prefix = format!("{}{}", container.path, ARCHIVE_DELIMITER);
            let mut per_finding: BTreeMap<String, Vec<CompositeSource>> = BTreeMap::new();
            for finding in &container.findings {
                if finding.trait_refs.is_empty() {
                    continue;
                }
                // member file id → source (dedup per member, first location wins).
                let mut by_member: BTreeMap<u32, CompositeSource> = BTreeMap::new();
                let mut ubiquitous = false;
                'refs: for trait_ref in &finding.trait_refs {
                    let Some(idxs) = id_to_files.get(trait_ref.as_str()) else {
                        continue;
                    };
                    for &mi in idxs {
                        let member = &files[mi];
                        // A source is either an archive member nested under this
                        // container's path, or a grafted direct child (linked by
                        // `parent_id`, not path) — e.g. the `*.registry.json`
                        // provenance node the fetch pass hangs off the artifact.
                        // A package-scoped composite's registry leg lives on the
                        // latter, so path-prefix alone would drop it.
                        let is_member = member.path.starts_with(&prefix);
                        let is_child = member.parent_id == Some(container.id);
                        if mi == ci || (!is_member && !is_child) {
                            continue; // neither a nested member nor a direct child
                        }
                        let entry = by_member
                            .entry(member.id)
                            .or_insert_with(|| CompositeSource {
                                file: member.id,
                                ..Default::default()
                            });
                        if entry.offset.is_none()
                            && entry.line.is_none()
                            && let Some((line, offset)) = note_location(member, trait_ref)
                        {
                            entry.line = line;
                            entry.offset = offset;
                        }
                        // A composite that spans most of the archive isn't *based
                        // on* particular files — it's a ubiquitous pattern (a
                        // sourcemap reference, a language sigil). Recording every
                        // member as a "source" is noise and bloats the output, so
                        // drop the provenance once it stops being a targeted set.
                        if by_member.len() > MAX_COMPOSITE_SOURCES {
                            ubiquitous = true;
                            break 'refs;
                        }
                    }
                }
                if !ubiquitous && !by_member.is_empty() {
                    per_finding.insert(finding.id.clone(), by_member.into_values().collect());
                }
            }
            if !per_finding.is_empty() {
                resolved.push((ci, per_finding));
            }
        }

        // Merge, don't replace: `link_flagged_references` also records
        // `composite_sources` (for flagged-reference findings, which carry no
        // `trait_refs` and are skipped above), and a re-run after the fetch graft
        // (`refresh_composite_sources`) must not clobber those. Keys are finding
        // ids, so extend refreshes each composite's own entry in place.
        for (ci, map) in resolved {
            files[ci].composite_sources.extend(map);
        }
    }

    /// Shrink all Vec fields to fit their contents, freeing excess capacity.
    /// Call this after analysis is complete to reduce memory footprint.
    pub fn shrink_to_fit(&mut self) {
        self.traits.shrink_to_fit();
        self.findings.shrink_to_fit();
        self.structure.shrink_to_fit();
        self.functions.shrink_to_fit();
        self.strings.shrink_to_fit();
        self.sections.shrink_to_fit();
        self.imports.shrink_to_fit();
        self.exports.shrink_to_fit();
        self.yara_matches.shrink_to_fit();
        self.syscalls.shrink_to_fit();
        self.paths.shrink_to_fit();
        self.directories.shrink_to_fit();
        self.env_vars.shrink_to_fit();
        self.archive_contents.shrink_to_fit();
        self.files.shrink_to_fit();
    }

    /// Drop the analysis fields that nothing downstream consumes, the moment a
    /// member's analysis (matching) is complete.
    ///
    /// `traits`, `structure`, `yara_matches`, `syscalls`, `paths`,
    /// `directories`, and `env_vars` are produced by analyzers and matched
    /// against during trait evaluation, but the compact output
    /// (`compact::convert_file`) never serializes them and `finalize()` drops
    /// the top-level copies. On an archive with thousands of members, retaining
    /// them per member until the end accumulates multiple GB of live, unused
    /// memory. Clearing them here — right after the member's matching finishes,
    /// before the result is collected — keeps the compact output identical
    /// (yara findings are already folded into `findings` during analysis).
    pub(crate) fn clear_unserialized_member_fields(&mut self) {
        self.traits = Vec::new();
        self.structure = Vec::new();
        self.yara_matches = Vec::new();
        self.syscalls = Vec::new();
        self.paths = Vec::new();
        self.directories = Vec::new();
        self.env_vars = Vec::new();
        for file in &mut self.files {
            file.clear_unserialized_fields();
        }
    }

    /// Tie a file to the report's other files it references, and flag any
    /// reference to a file that was itself detected hostile/suspicious.
    ///
    /// Each [`filefacts`] reference is resolved against the report's files (see
    /// [`super::reference_graph`]): an external dependency (PURL) matches a
    /// file whose declared identity carries that package name, a relative path
    /// matches a sibling member by full path. When a resolved target's verdict
    /// is suspicious or hostile, the referrer gains a finding:
    /// - an **external** dependency raises one
    ///   `objectives/supply-chain/malicious-dependency` finding, one
    ///   criticality below the target (a hostile dep → a suspicious referrer);
    /// - an **internal** sibling raises one neutral `metadata/relationship`
    ///   fact — the bundle's hostility already lives on the bad member, so the
    ///   referrer is recorded, not re-scored.
    ///
    /// The general (benign-included) file→file edge is filled separately on the
    /// compact `refs` (`compact::link_reference_targets`); this pass adds only
    /// the flagged-target findings, whose `composite_sources` name the targets.
    fn link_flagged_references(files: &mut [FileAnalysis]) {
        use super::file_analysis::CompositeSource;
        use super::reference_graph as rg;
        use super::traits_findings::FindingKind;
        use std::collections::HashMap;

        // Index the report once: declared identity name → file id (external),
        // full path → file id (internal), and each file's own verdict (its
        // strongest native finding). Owned keys so the mutable pass is free of
        // the index's borrow.
        let mut by_name: HashMap<String, u32> = HashMap::new();
        let mut by_path: HashMap<String, u32> = HashMap::new();
        let mut verdict: HashMap<u32, Criticality> = HashMap::new();
        for f in files.iter() {
            by_path.entry(f.path.clone()).or_insert(f.id);
            if let Some(identity) = &f.identity {
                for name in rg::identity_names(identity) {
                    by_name.entry(name.to_string()).or_insert(f.id);
                }
            }
            let v = f
                .findings
                .iter()
                .filter(|fd| fd.src.is_none())
                .map(|fd| fd.crit)
                .max()
                .unwrap_or(Criticality::Baseline);
            verdict.insert(f.id, v);
        }

        for f in files.iter_mut() {
            let own_id = f.id;
            let own_path = f.path.clone();
            // Snapshot the locators, dropping the immutable `filefacts` borrow
            // before mutating `findings`.
            let refs: Vec<(filefacts::RefLocator, u64)> = match &f.filefacts {
                Some(ff) => ff
                    .references
                    .iter()
                    .map(|r| (r.locator.clone(), r.offset))
                    .collect(),
                None => continue,
            };

            // Flagged targets, deduped, split by edge kind.
            let mut ext: Vec<(u32, u64, String, Criticality)> = Vec::new();
            let mut int: Vec<(u32, u64)> = Vec::new();
            for (locator, offset) in &refs {
                let (target, external, label) = match locator {
                    filefacts::RefLocator::Purl(p) => match rg::package_name_from_purl(p) {
                        Some(name) => (by_name.get(&name).copied(), true, name),
                        None => continue,
                    },
                    filefacts::RefLocator::Path(p) => {
                        let target = rg::resolve_local_target(&own_path, p, |path| {
                            by_path.get(path).copied()
                        });
                        (target, false, String::new())
                    }
                    filefacts::RefLocator::Url(_) => continue,
                };
                let Some(tid) = target else { continue };
                if tid == own_id {
                    continue;
                }
                let tv = verdict.get(&tid).copied().unwrap_or(Criticality::Baseline);
                if tv < Criticality::Suspicious {
                    continue;
                }
                if external {
                    if !ext.iter().any(|(id, ..)| *id == tid) {
                        ext.push((tid, *offset, label, tv));
                    }
                } else if !int.iter().any(|(id, _)| *id == tid) {
                    int.push((tid, *offset));
                }
            }

            // External: one supply-chain finding, crit one-below the worst target.
            if let Some(worst) = ext.iter().map(|(.., v)| *v).max()
                && let Some(crit) = rg::one_below(worst)
            {
                let names = ext
                    .iter()
                    .map(|(.., n, _)| n.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                let sources = ext
                    .iter()
                    .map(|(tid, off, ..)| CompositeSource {
                        file: *tid,
                        line: None,
                        offset: Some(*off),
                    })
                    .collect();
                Self::push_reference_finding(
                    f,
                    "objectives/supply-chain/malicious-dependency::references-malicious-component",
                    FindingKind::Indicator,
                    crit,
                    format!("References a flagged dependency: {names}"),
                    sources,
                );
            }
            // Internal: one neutral metadata fact naming the flagged sibling(s).
            if !int.is_empty() {
                let sources = int
                    .iter()
                    .map(|(tid, off)| CompositeSource {
                        file: *tid,
                        line: None,
                        offset: Some(*off),
                    })
                    .collect();
                Self::push_reference_finding(
                    f,
                    "metadata/relationship::references-flagged-component",
                    FindingKind::Structural,
                    Criticality::Baseline,
                    "References a flagged file in this bundle".to_string(),
                    sources,
                );
            }
        }
    }

    /// Add a synthesized reference finding to `file` (idempotent on the id), with
    /// the flagged targets recorded as its `composite_sources` trail.
    fn push_reference_finding(
        file: &mut FileAnalysis,
        id: &str,
        kind: super::traits_findings::FindingKind,
        crit: Criticality,
        desc: String,
        sources: Vec<super::file_analysis::CompositeSource>,
    ) {
        if file.findings.iter().any(|fd| fd.id == id) {
            return; // already linked (e.g. a re-finalize)
        }
        file.findings.push(Finding {
            id: id.to_string(),
            kind,
            desc,
            conf: 0.9,
            crit,
            trait_refs: Vec::new(),
            src: None,
            mbc: None,
            attack: None,
            evidence: Vec::new(),
            match_count: 0,
            source_file: None,
        });
        file.composite_sources.insert(id.to_string(), sources);
    }

    /// Finalize the report for output: populate files[], clear top-level duplicates,
    /// merge metadata into summary, filter internal symbols findings.
    ///
    /// After this call, `files[]` is the single source of truth and `version` is "3".
    pub fn finalize(&mut self) {
        // Create the root file entry
        let mut root_file = self.to_file_analysis(0);
        root_file.path = self.target.path.clone();
        root_file.depth = 0;
        root_file.parent_id = None;
        root_file.compute_summary();

        if self.files.is_empty() {
            // Simple case: just the root file
            self.files.push(root_file);
        } else {
            // Files were pre-populated by archive/payload analyzers
            // Renumber IDs and insert root file at position 0
            let root_path = self.target.path.clone();
            for (idx, file) in self.files.iter_mut().enumerate() {
                file.id = (idx + 1) as u32; // Shift IDs to make room for root
                if file.depth == 1 && file.parent_id.is_none() {
                    file.parent_id = Some(0); // Point to root
                }
                // Ensure paths have proper archive prefix (!! for archives, ## for decoded)
                if !file.path.contains("!!")
                    && !file.path.contains("##")
                    && !file.path.starts_with(&root_path)
                {
                    file.path = super::file_analysis::encode_archive_path(&root_path, &file.path);
                }
            }
            self.files.insert(0, root_file);
        }

        self.inherit_child_findings_into_wrappers();

        // Attribute findings that arrived via the archive *aggregate* (their
        // evidence carries an `archive:<member>` location but no `src` yet — the
        // aggregate copy predates `inherit`'s id-stamping and wins de-dup). Map
        // the member name back to its file id so every inherited finding can be
        // traced to where it was located. Runs before evidence is stripped, since
        // the location lives on the (transient) evidence.
        {
            use rustc_hash::FxHashMap;
            let member_to_id: FxHashMap<String, u32> = self
                .files
                .iter()
                .filter(|f| f.path.contains(super::file_analysis::ARCHIVE_DELIMITER))
                .map(|f| (leaf_member(&f.path).to_string(), f.id))
                .collect();
            for file in &mut self.files {
                let own_id = file.id;
                for finding in &mut file.findings {
                    if finding.src.is_some() {
                        continue;
                    }
                    let src = finding.evidence.iter().find_map(|e| {
                        let member = located_member(e.location.as_deref()?)?;
                        member_to_id.get(member).copied()
                    });
                    // Only mark when it points at a *different* file — a member's
                    // own finding listed on the member itself stays native.
                    if let Some(id) = src
                        && id != own_id
                    {
                        finding.src = Some(id);
                    }
                }
            }
        }
        let fixture_file_ids: Vec<u32> = self
            .files
            .iter()
            .filter_map(|file| fixture_path_component(&file.path).then_some(file.id))
            .collect();
        for file in &mut self.files {
            file.findings.retain(|finding| {
                finding.id != "anti-analysis/archive/symlink-escape"
                    || !finding
                        .src
                        .is_some_and(|src| fixture_file_ids.contains(&src))
            });
        }

        // Tie each cross-file composite to the members it fired on, while the
        // per-member component findings/notes are still present (the compact
        // output and the terminal component-filter drop the low-tier ones that
        // link a composite to a member, e.g. an install-hook trait on a
        // package.json). Must run before those drops.
        Self::attach_composite_sources(&mut self.files);

        // Flag references to a file that was itself detected hostile/suspicious,
        // before the score is recomputed so a referrer's verdict reflects it.
        Self::link_flagged_references(&mut self.files);

        for file in &mut self.files {
            file.strip_source_fields();
            Self::refresh_formula(file);
            file.compute_summary();
        }

        // Compute report summary and merge metadata into it
        let mut summary = ReportSummary::from_files(&self.files);
        summary.duration_ms = self.metadata.analysis_duration_ms;
        summary.tools = std::mem::take(&mut self.metadata.tools_used);
        summary.errors = std::mem::take(&mut self.metadata.errors);
        self.summary = Some(summary);

        // Clear top-level arrays — data now lives exclusively in files[]
        // Existing skip_serializing_if = "Vec::is_empty" prevents these from appearing in output
        let _ = std::mem::take(&mut self.traits);
        let _ = std::mem::take(&mut self.findings);
        let _ = std::mem::take(&mut self.structure);
        let _ = std::mem::take(&mut self.functions);
        let _ = std::mem::take(&mut self.strings);
        let _ = std::mem::take(&mut self.sections);
        let _ = std::mem::take(&mut self.imports);
        let _ = std::mem::take(&mut self.exports);
        let _ = std::mem::take(&mut self.yara_matches);
        let _ = std::mem::take(&mut self.syscalls);
        let _ = std::mem::take(&mut self.paths);
        let _ = std::mem::take(&mut self.directories);
        let _ = std::mem::take(&mut self.env_vars);
        let _ = std::mem::take(&mut self.archive_contents);

        // Clear fields that are redundant with files[0] / summary
        self.target = TargetInfo::default();
        self.analysis_timestamp = None;
        self.metadata = AnalysisMetadata::default();
        self.scanned_path = None;

        // Set version to v3
        self.version = "3".to_string();
    }

    /// Create a FileAnalysis from this report's data
    ///
    /// This is used internally by finalize() and by archive analyzers
    /// to convert per-file reports into the flat files array structure.
    #[must_use]
    pub fn to_file_analysis(&self, id: u32) -> FileAnalysis {
        let mut file = FileAnalysis::new(
            id,
            self.target.path.clone(),
            self.target.file_type.clone(),
            self.target.sha256.clone(),
            self.target.size_bytes,
        );

        file.arch = self
            .target
            .architectures
            .as_ref()
            .and_then(|a| a.first().cloned());
        file.findings = self.findings.clone();
        file.context = self.context.clone();
        file.filefacts = self.filefacts.clone();
        file.identity = self.identity.clone();
        file.filefacts_metrics = self.filefacts_metrics.clone();
        file.structure = self.structure.clone();
        file.strings = self.strings.clone();
        file.imports = self.imports.clone();
        file.exports = self.exports.clone();
        file.sections = self.sections.clone();

        file.populate_file_metrics();
        // Flatten the values tree into `kv` (the serialized form). The nested
        // tree itself is NOT retained on the file: `kv` is the single output
        // representation, and the only structural reader (`type: value` sibling
        // lookups, diff) now reads `kv`.
        if let Some(tree) = self.values_tree.as_deref() {
            flatten_kv_for_output(tree, &mut file.kv);
        }
        file
    }

    /// Consuming version of `to_file_analysis` that moves data instead of cloning.
    ///
    /// Returns `(file_analysis, nested_files, archive_contents)` — the nested files
    /// and archive contents are returned separately since archive callers need them.
    /// This avoids the temporary doubling of memory from cloning large reports.
    #[must_use]
    pub fn into_file_analysis(
        mut self,
        id: u32,
    ) -> (FileAnalysis, Vec<FileAnalysis>, Vec<ArchiveEntry>) {
        let nested_files = std::mem::take(&mut self.files);
        let archive_contents = std::mem::take(&mut self.archive_contents);
        let arch = self
            .target
            .architectures
            .as_ref()
            .and_then(|a| a.first().cloned());

        let mut file = FileAnalysis::new(
            id,
            self.target.path,
            self.target.file_type,
            self.target.sha256,
            self.target.size_bytes,
        );

        file.arch = arch;
        file.findings = self.findings;
        file.context = self.context;
        file.filefacts = self.filefacts;
        file.identity = self.identity;
        file.filefacts_metrics = self.filefacts_metrics;
        file.structure = self.structure;
        file.strings = self.strings;
        file.imports = self.imports;
        file.exports = self.exports;
        file.sections = self.sections;

        file.populate_file_metrics();
        // `kv` is the single retained representation — see `to_file_analysis`.
        if let Some(tree) = self.values_tree.as_deref() {
            flatten_kv_for_output(tree, &mut file.kv);
        }
        (file, nested_files, archive_contents)
    }
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

/// Recursively merge two JSON objects. Object children are unioned
/// (with the right-hand-side winning on leaf collisions); non-object
/// leaves are replaced by the right-hand value. Used by
/// [`AnalysisReport::merge_kv_subtree`] so multiple writers under the
/// same top-level namespace coexist (e.g. filefacts populates
/// `build.toolchain.*` while cleave's `binary_extractors` populates
/// `build.username`).
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
        match id_to_index.get(&f.id) {
            None => {
                id_to_index.insert(f.id.clone(), findings.len());
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

/// Location of the first context note for finding `id` in `file`, as
/// `(line, offset)`. `line` is the 1-based source line for textual chunks (those
/// carrying a `line`), advanced from the chunk's start past any newlines before
/// the match; `offset` is the match's byte offset. Returns `None` when no note
/// pins the finding — e.g. a metric or manifest-field-presence trait.
fn note_location(file: &FileAnalysis, id: &str) -> Option<(Option<u64>, Option<u64>)> {
    for line in &file.context {
        for note in &line.notes {
            if note.id == id {
                let src_line = line.line.map(|start| {
                    let rel = usize::try_from(note.off.saturating_sub(line.loc))
                        .unwrap_or(usize::MAX)
                        .min(line.data.len());
                    let extra = line.data[..rel].iter().filter(|&&b| b == b'\n').count() as u64;
                    start + extra
                });
                return Some((src_line, Some(note.off)));
            }
        }
    }
    None
}

/// The leaf member name of an archive-member file path: the segment after the
/// last archive delimiter (`a.zip!!dir/b.so` → `dir/b.so`).
fn leaf_member(path: &str) -> &str {
    use super::file_analysis::ARCHIVE_DELIMITER;
    path.rsplit(ARCHIVE_DELIMITER).next().unwrap_or(path)
}

fn fixture_path_component(path: &str) -> bool {
    path.split(['/', '\\', '!'])
        .any(|component| matches!(component, "testdata" | "fixture" | "fixtures"))
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
/// tar). They surface forensically-useful header data that the archive
/// carries: timestamps, POSIX ownership/mode, compression choice, entry
/// type, link targets. Traits at the archive root query these via the
/// `archive.members[]` kv subtree materialized by `seal_archive_metadata_kv`.
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
    /// File type implied by the archive member path/extension, before content validation.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub declared_type: Option<String>,
    /// True when the path-implied type differs from the content-derived type.
    #[serde(skip_serializing_if = "is_false", default)]
    pub extension_type_mismatch: bool,
    /// Shannon entropy of the uncompressed entry bytes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub entropy: Option<f64>,
    /// First bytes of the uncompressed entry as lowercase hex.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub magic_prefix: Option<String>,
    /// Container-specific member kind, for example a PyInstaller entry kind.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub container_kind: Option<String>,

    /// Compressed size in bytes (zip per-entry; tar entries are uncompressed so this matches size_bytes).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub compressed_size: Option<u64>,
    /// Compression method: "stored", "deflate", "lzma", "zstd", "bzip2", etc.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub compression_method: Option<String>,
    /// Modification time as Unix epoch seconds. Zip stores 2-second-resolution
    /// DOS time by default; the UT extra-field carries real Unix timestamps.
    /// Tar carries native Unix time.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mtime_unix: Option<i64>,
    /// POSIX mode bits (12 low bits standard; setuid/setgid/sticky included).
    /// Zip provides this only when version_made_by indicates a Unix host;
    /// tar always provides it. Format: decimal of the 16-bit mode value.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mode_octal: Option<u32>,
    /// Numeric user id (tar only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub uid: Option<u64>,
    /// Numeric group id (tar only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub gid: Option<u64>,
    /// User name string (tar only — surprisingly often the real username).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub uname: Option<String>,
    /// Group name string (tar only).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub gname: Option<String>,
    /// Entry type: "regular", "symlink", "hardlink", "dir", "char-dev",
    /// "block-dev", "fifo", "pax-header", "gnu-longname", etc.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub entry_type: Option<String>,
    /// Link target for symlinks and hardlinks.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub linkname: Option<String>,
    /// Host OS that created the entry (zip version_made_by upper byte).
    /// Values: "msdos", "unix", "macintosh", "ntfs", "vfat", "amiga", etc.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub host_os: Option<String>,
    /// ZIP local-header offset, when filefacts indexed the container.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub header_offset: Option<u64>,
    /// ZIP compressed payload offset, when filefacts indexed the container.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub data_offset: Option<u64>,
    /// ZIP central-directory header offset, when available.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub central_header_offset: Option<u64>,
    /// ZIP CRC32 of the uncompressed entry payload.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub crc32: Option<u32>,
    /// True when the archive entry is encrypted.
    #[serde(skip_serializing_if = "is_false", default)]
    pub encrypted: bool,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::types::traits_findings::FindingKind;

    fn test_target() -> TargetInfo {
        TargetInfo {
            path: "/test/sample.bin".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 1024,
            sha256: "abc123".to_string(),
            architectures: Some(vec!["x86_64".to_string()]),
        }
    }

    fn test_finding(id: &str, crit: Criticality) -> Finding {
        Finding {
            src: None,
            id: id.to_string(),
            kind: FindingKind::Capability,
            desc: format!("Test finding {}", id),
            conf: 0.9,
            crit,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![],
            match_count: 0,
            source_file: None,
        }
    }

    fn local_ref(path: &str) -> filefacts::Reference {
        filefacts::Reference {
            locator: filefacts::RefLocator::Path(path.to_string()),
            kind: filefacts::RefKind::Local,
            source: "package.json:main".to_string(),
            evidence: path.to_string(),
            offset: 10,
            pinned_hash: None,
            content_sha256: None,
        }
    }

    fn dep_ref(purl: &str) -> filefacts::Reference {
        filefacts::Reference {
            locator: filefacts::RefLocator::Purl(purl.to_string()),
            kind: filefacts::RefKind::Dependency,
            source: "package.json".to_string(),
            evidence: purl.to_string(),
            offset: 20,
            pinned_hash: None,
            content_sha256: None,
        }
    }

    fn file_with_refs(id: u32, path: &str, refs: Vec<filefacts::Reference>) -> FileAnalysis {
        let mut f = FileAnalysis::new(id, path.to_string(), "json".into(), format!("sha{id}"), 100);
        f.filefacts = Some(FilefactsView {
            references: refs,
            ..Default::default()
        });
        f
    }

    fn named_identity(name: &str) -> filefacts::Identity {
        filefacts::Identity {
            name: Some(filefacts::Claim {
                value: name.to_string(),
                source: "test".to_string(),
                verified: false,
            }),
            ..Default::default()
        }
    }

    #[test]
    fn internal_reference_to_hostile_sibling_raises_neutral_metadata_fact() {
        let referrer = file_with_refs(
            0,
            "pkg.zip!!a/package.json",
            vec![local_ref("./payload.js")],
        );
        let mut payload = FileAnalysis::new(
            1,
            "pkg.zip!!a/payload.js".into(),
            "js".into(),
            "sha1".into(),
            50,
        );
        payload.findings = vec![test_finding("objectives/evil::x", Criticality::Hostile)];
        let mut files = vec![referrer, payload];

        AnalysisReport::link_flagged_references(&mut files);

        let f = &files[0];
        let linked = f
            .findings
            .iter()
            .find(|fd| fd.id == "metadata/relationship::references-flagged-component")
            .expect("internal edge finding");
        // Neutral — references the bad sibling, doesn't inherit its severity.
        assert_eq!(linked.crit, Criticality::Baseline);
        assert_eq!(
            f.composite_sources[&linked.id][0].file, 1,
            "trail names the sibling"
        );
    }

    #[test]
    fn external_dependency_on_hostile_vendored_member_propagates_one_below() {
        let referrer = file_with_refs(
            0,
            "pkg.zip!!package.json",
            vec![dep_ref("pkg:npm/evil@1.0.0")],
        );
        // The dependency is vendored in the bundle and scored hostile.
        let mut vendored = file_with_refs(1, "pkg.zip!!node_modules/evil/index.js", vec![]);
        vendored.identity = Some(named_identity("evil"));
        vendored.findings = vec![test_finding(
            "well-known/malware/x::y",
            Criticality::Hostile,
        )];
        let mut files = vec![referrer, vendored];

        AnalysisReport::link_flagged_references(&mut files);

        let f = &files[0];
        let linked = f
            .findings
            .iter()
            .find(|fd| {
                fd.id == "objectives/supply-chain/malicious-dependency::references-malicious-component"
            })
            .expect("supply-chain finding");
        // Hostile target → suspicious referrer (one criticality below).
        assert_eq!(linked.crit, Criticality::Suspicious);
        assert!(
            linked.desc.contains("evil"),
            "names the dependency: {}",
            linked.desc
        );
        assert_eq!(f.composite_sources[&linked.id][0].file, 1);
    }

    #[test]
    fn reference_to_benign_file_raises_nothing() {
        let referrer = file_with_refs(0, "pkg.zip!!a/package.json", vec![local_ref("./helper.js")]);
        let mut helper = FileAnalysis::new(
            1,
            "pkg.zip!!a/helper.js".into(),
            "js".into(),
            "sha1".into(),
            50,
        );
        helper.findings = vec![test_finding("net/socket", Criticality::Notable)]; // below suspicious
        let mut files = vec![referrer, helper];

        AnalysisReport::link_flagged_references(&mut files);

        assert!(
            files[0].findings.is_empty(),
            "a notable target is not flagged, so no reference finding"
        );
    }

    #[test]
    fn strip_unmatched_traits_drops_only_unreferenced_components_and_baselines() {
        let mut report = AnalysisReport::new(test_target());
        let mut file =
            FileAnalysis::new(0, "/sample.bin".into(), "elf".into(), "abc123".into(), 1024);

        // A fired composite names one component and one baseline by id; those two
        // are kept despite their low criticality, the unreferenced twins are not,
        // and the notable is untouched regardless of references.
        let mut composite = test_finding("objectives/x::y", Criticality::Hostile);
        composite.trait_refs = vec!["comp/used".into(), "base/used".into()];
        file.findings = vec![
            composite,
            test_finding("comp/used", Criticality::Component),
            test_finding("comp/orphan", Criticality::Component),
            test_finding("base/used", Criticality::Baseline),
            test_finding("base/orphan", Criticality::Baseline),
            test_finding("note/keep", Criticality::Notable),
        ];
        report.files = vec![file];

        let (components, baselines) = report.strip_unmatched_traits();
        assert_eq!(components, 1, "one unreferenced component dropped");
        assert_eq!(baselines, 1, "one unreferenced baseline dropped");

        let kept: Vec<&str> = report.files[0]
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        assert_eq!(kept.len(), 4);
        for id in ["objectives/x::y", "comp/used", "base/used", "note/keep"] {
            assert!(kept.contains(&id), "{id} should be kept");
        }
        for id in ["comp/orphan", "base/orphan"] {
            assert!(!kept.contains(&id), "{id} should be stripped");
        }

        // Idempotent: a second pass removes nothing.
        assert_eq!(report.strip_unmatched_traits(), (0, 0));
    }

    #[test]
    fn strip_unmatched_traits_rescues_best_low_tier_when_no_signal() {
        let mut report = AnalysisReport::new(test_target());
        let mut file =
            FileAnalysis::new(0, "/quiet.bin".into(), "elf".into(), "abc123".into(), 1024);

        // No notable-or-higher finding: every trait would normally be stripped.
        // Confidence orders the rescue, so the three highest-confidence survive.
        let mut findings = Vec::new();
        for (i, conf) in [0.1f32, 0.9, 0.5, 0.7, 0.3].iter().enumerate() {
            let mut f = test_finding(&format!("base/t{i}"), Criticality::Baseline);
            f.conf = *conf;
            findings.push(f);
        }
        file.findings = findings;
        report.files = vec![file];

        let (components, baselines) = report.strip_unmatched_traits();
        assert_eq!(components, 0);
        assert_eq!(baselines, 2, "five low-tier traits, three rescued");

        let kept: Vec<&str> = report.files[0]
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        assert_eq!(kept.len(), RESCUE_LOW_TIER_KEEP);
        // t1 (0.9), t3 (0.7), t2 (0.5) win; t4 (0.3) and t0 (0.1) drop.
        for id in ["base/t1", "base/t3", "base/t2"] {
            assert!(kept.contains(&id), "{id} should be rescued");
        }
        for id in ["base/t0", "base/t4"] {
            assert!(!kept.contains(&id), "{id} should be stripped");
        }
    }

    #[test]
    fn strip_unmatched_traits_no_rescue_when_signal_present() {
        let mut report = AnalysisReport::new(test_target());
        let mut file =
            FileAnalysis::new(0, "/loud.bin".into(), "elf".into(), "abc123".into(), 1024);

        // A lone notable counts as signal, so the low-tier traits strip in full.
        file.findings = vec![
            test_finding("note/keep", Criticality::Notable),
            test_finding("base/a", Criticality::Baseline),
            test_finding("comp/b", Criticality::Component),
        ];
        report.files = vec![file];

        let (components, baselines) = report.strip_unmatched_traits();
        assert_eq!((components, baselines), (1, 1));
        let kept: Vec<&str> = report.files[0]
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        assert_eq!(kept, vec!["note/keep"]);
    }

    #[test]
    fn graft_findings_places_on_target_and_strip_preserves_cross_node_members() {
        // The fetch-driven package pass: a composite correlating a fetched
        // artifact with its registry metadata is grafted onto the artifact node,
        // but its building-block traits live on two *different* nodes (the
        // native-addon trait on the artifact, the deprecated trait on the
        // registry document). `strip_unmatched_traits` unions `trait_refs`
        // across every node, so both survive even though neither shares a node
        // with the grafted composite. This is the step that silently breaks if
        // graft attribution regresses.
        let mut report = AnalysisReport::new(test_target());
        let mut artifact = FileAnalysis::new(
            0,
            "/pkg.whl".into(),
            "zip".into(),
            "artifactsha".into(),
            2048,
        );
        artifact.findings = vec![test_finding(
            "test/pkg::native-addon",
            Criticality::Component,
        )];
        let mut registry = FileAnalysis::new(
            1,
            "/pkg.registry.json".into(),
            "registry".into(),
            "registrysha".into(),
            256,
        );
        registry.findings = vec![test_finding("test/pkg::deprecated", Criticality::Component)];
        report.files = vec![artifact, registry];

        // Graft the package composite onto the artifact node, carrying both
        // members in `trait_refs` (as `CompositeTrait::evaluate` does).
        let mut composite =
            test_finding("test/pkg::deprecated-with-addon", Criticality::Suspicious);
        composite.trait_refs = vec![
            "test/pkg::native-addon".into(),
            "test/pkg::deprecated".into(),
        ];
        assert_eq!(report.graft_findings("artifactsha", vec![composite]), 1);
        // Landed on the artifact node, not the registry node.
        assert!(
            report.files[0]
                .findings
                .iter()
                .any(|f| f.id == "test/pkg::deprecated-with-addon"),
            "composite should graft onto the artifact node"
        );

        let (components, baselines) = report.strip_unmatched_traits();
        assert_eq!(
            (components, baselines),
            (0, 0),
            "both component members are referenced by the grafted composite, so none strip"
        );
        assert!(
            report.files[1]
                .findings
                .iter()
                .any(|f| f.id == "test/pkg::deprecated"),
            "the registry building-block trait must survive on its own node"
        );

        // A second graft of the same id is deduped (returns 0).
        let dup = test_finding("test/pkg::deprecated-with-addon", Criticality::Suspicious);
        assert_eq!(report.graft_findings("artifactsha", vec![dup]), 0);
        // Grafting onto a sha that isn't present is a no-op.
        assert_eq!(
            report.graft_findings(
                "nosuchsha",
                vec![test_finding("x::y", Criticality::Notable)]
            ),
            0
        );
    }

    #[test]
    fn attach_composite_sources_ties_composite_to_members_with_locations() {
        use super::super::file_analysis::ARCHIVE_DELIMITER;
        use super::super::traits_findings::{ContextLine, Note};

        // Container with a cross-file composite referencing two components.
        let mut container =
            FileAnalysis::new(0, "/x.tgz".into(), "tar.gz".into(), "s0".into(), 100);
        let mut composite = test_finding(
            "objectives/supply-chain/dropper::implant",
            Criticality::Hostile,
        );
        composite.trait_refs = vec!["comp/manifest".into(), "comp/payload".into()];
        container.findings = vec![composite];

        // Member 1: a manifest carrying comp/manifest, anchored to a source line.
        let mut m1 = FileAnalysis::new(
            1,
            format!("/x.tgz{ARCHIVE_DELIMITER}pkg/manifest.json"),
            "json".into(),
            "s1".into(),
            10,
        );
        m1.depth = 1;
        m1.findings = vec![test_finding("comp/manifest", Criticality::Component)];
        m1.context = vec![ContextLine {
            loc: 40, // byte offset of the chunk start
            line: Some(3),
            col: Some(1),
            data: b"  \"preinstall\": \"node x\"".to_vec(),
            notes: vec![Note {
                crit: Criticality::Component,
                id: "comp/manifest".into(),
                desc: String::new(),
                off: 40,
                len: 5,
                conf: 0.9,
            }],
        }];

        // Member 2: a binary carrying comp/payload, anchored to a byte offset.
        let mut m2 = FileAnalysis::new(
            2,
            format!("/x.tgz{ARCHIVE_DELIMITER}pkg/bin"),
            "elf".into(),
            "s2".into(),
            20,
        );
        m2.depth = 1;
        m2.findings = vec![test_finding("comp/payload", Criticality::Suspicious)];
        m2.context = vec![ContextLine {
            loc: 0x1234,
            line: None, // byte-addressed (binary) → no source line/col
            col: None,
            data: vec![0u8; 4],
            notes: vec![Note {
                crit: Criticality::Suspicious,
                id: "comp/payload".into(),
                desc: String::new(),
                off: 0x1234,
                len: 4,
                conf: 0.9,
            }],
        }];

        let mut files = vec![container, m1, m2];
        AnalysisReport::attach_composite_sources(&mut files);

        let sources = files[0]
            .composite_sources
            .get("objectives/supply-chain/dropper::implant")
            .expect("composite resolved to sources");
        assert_eq!(sources.len(), 2, "both contributing members tracked");
        let s1 = sources
            .iter()
            .find(|s| s.file == 1)
            .expect("manifest member");
        assert_eq!(s1.line, Some(3), "source component carries its line");
        assert_eq!(s1.offset, Some(40));
        let s2 = sources.iter().find(|s| s.file == 2).expect("binary member");
        assert_eq!(s2.line, None, "binary component has no source line");
        assert_eq!(
            s2.offset,
            Some(0x1234),
            "binary component carries its offset"
        );
    }

    #[test]
    fn graft_reattaches_sources_across_member_and_registry_child() {
        // The fetch pass shape: a package-scoped composite grafted onto the
        // artifact node after finalize, whose legs live on (a) an archive member
        // and (b) a grafted `registry` child that is NOT under the container's
        // archive path (linked by `parent_id`). Grafting must re-resolve sources
        // so both legs surface — the member by path, the registry leg by parent.
        use super::super::file_analysis::ARCHIVE_DELIMITER;
        use super::super::traits_findings::{ContextLine, Note};

        let mut report = AnalysisReport::new(test_target());

        // Artifact/container node (the graft target).
        let mut artifact = FileAnalysis::new(
            0,
            "/pkg.tgz".into(),
            "tar.gz".into(),
            "artifactsha".into(),
            100,
        );
        artifact.findings = vec![];

        // Archive member carrying the code leg, anchored to a source line.
        let mut member = FileAnalysis::new(
            1,
            format!("/pkg.tgz{ARCHIVE_DELIMITER}pkg/install.js"),
            "javascript".into(),
            "membersha".into(),
            20,
        );
        member.parent_id = Some(0);
        member.depth = 1;
        member.findings = vec![test_finding(
            "objectives/exfiltration::post",
            Criticality::Component,
        )];
        member.context = vec![ContextLine {
            loc: 200,
            line: Some(12),
            col: Some(1),
            data: b"fetch(url, {method:'POST'})".to_vec(),
            notes: vec![Note {
                crit: Criticality::Component,
                id: "objectives/exfiltration::post".into(),
                desc: String::new(),
                off: 200,
                len: 5,
                conf: 0.9,
            }],
        }];

        // Registry provenance child: a direct child of the artifact by parent_id,
        // path is the synthetic registry doc name (NOT under the archive prefix).
        let mut registry = FileAnalysis::new(
            2,
            "be5invis_iosevka.registry.json".into(),
            "registry".into(),
            "regsha".into(),
            64,
        );
        registry.parent_id = Some(0);
        registry.depth = 1;
        registry.findings = vec![test_finding(
            "metadata/registry::freshly-published",
            Criticality::Notable,
        )];

        report.files = vec![artifact, member, registry];

        // Graft the package composite carrying both legs in trait_refs.
        let mut composite = test_finding("supply-chain::obfuscated-exfil", Criticality::Hostile);
        composite.trait_refs = vec![
            "objectives/exfiltration::post".into(),
            "metadata/registry::freshly-published".into(),
        ];
        assert_eq!(report.graft_findings("artifactsha", vec![composite]), 1);

        // The graft must have re-run source attribution: the composite now trails
        // both its member (code) leg and its registry (provenance) child.
        let sources = report.files[0]
            .composite_sources
            .get("supply-chain::obfuscated-exfil")
            .expect("graft re-attached composite sources");
        assert!(
            sources.iter().any(|s| s.file == 1 && s.line == Some(12)),
            "archive-member code leg tracked with its line, got: {sources:?}"
        );
        assert!(
            sources.iter().any(|s| s.file == 2),
            "registry provenance child tracked via parent_id, got: {sources:?}"
        );
    }

    // ==================== Criticality Tests ====================

    #[test]
    fn test_criticality_ordering() {
        assert!(Criticality::Filtered < Criticality::Exception);
        assert!(Criticality::Exception < Criticality::Component);
        assert!(Criticality::Component < Criticality::Baseline);
        assert!(Criticality::Baseline < Criticality::Notable);
        assert!(Criticality::Notable < Criticality::Suspicious);
        assert!(Criticality::Suspicious < Criticality::Hostile);
        // The load-bearing invariant: an exception is never positive signal, so
        // every `crit >= Notable` gate excludes it.
        assert!(Criticality::Exception < Criticality::Notable);
    }

    #[test]
    fn test_criticality_exception_serde_roundtrip() {
        // serde uses the lowercase variant name; `crit: exception` must parse.
        let json = serde_json::to_string(&Criticality::Exception).unwrap();
        assert_eq!(json, "\"exception\"");
        let parsed: Criticality = serde_json::from_str("\"exception\"").unwrap();
        assert_eq!(parsed, Criticality::Exception);
    }

    #[test]
    fn test_criticality_max() {
        let crits = vec![
            Criticality::Baseline,
            Criticality::Hostile,
            Criticality::Notable,
        ];
        assert_eq!(crits.into_iter().max(), Some(Criticality::Hostile));
    }

    #[test]
    fn test_criticality_default() {
        assert_eq!(Criticality::default(), Criticality::Baseline);
    }

    #[test]
    fn test_criticality_equality() {
        assert_eq!(Criticality::Hostile, Criticality::Hostile);
        assert_ne!(Criticality::Hostile, Criticality::Suspicious);
    }

    // ==================== AnalysisReport::new Tests ====================

    #[test]
    fn test_analysis_report_new() {
        let report = AnalysisReport::new(test_target());

        assert_eq!(report.version, "3.0");
        assert_eq!(report.target.path, "/test/sample.bin");
        assert!(report.findings.is_empty());
        assert!(report.traits.is_empty());
        assert!(report.strings.is_empty());
    }

    #[test]
    fn test_analysis_report_new_with_timestamp() {
        use chrono::TimeZone;
        let ts = Utc.with_ymd_and_hms(2024, 1, 15, 12, 0, 0).unwrap();
        let report = AnalysisReport::new_with_timestamp(test_target(), ts);

        assert_eq!(report.analysis_timestamp, Some(ts));
    }

    // ==================== add_finding Tests ====================

    #[test]
    fn test_add_finding_basic() {
        let mut report = AnalysisReport::new(test_target());
        let finding = test_finding("test/cap1", Criticality::Notable);

        report.add_finding(finding);

        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].id, "test/cap1");
    }

    #[test]
    fn test_add_finding_dedup() {
        let mut report = AnalysisReport::new(test_target());

        report.add_finding(test_finding("test/cap1", Criticality::Notable));
        report.add_finding(test_finding("test/cap1", Criticality::Hostile)); // Same ID

        // Should deduplicate - only one finding
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn test_add_finding_different_ids() {
        let mut report = AnalysisReport::new(test_target());

        report.add_finding(test_finding("test/cap1", Criticality::Notable));
        report.add_finding(test_finding("test/cap2", Criticality::Hostile));

        assert_eq!(report.findings.len(), 2);
    }

    // ==================== highest_criticality Tests ====================

    // ==================== TargetInfo Tests ====================

    #[test]
    fn test_target_info_creation() {
        let target = TargetInfo {
            path: "/path/to/file".to_string(),
            file_type: "macho".to_string(),
            size_bytes: 2048,
            sha256: "deadbeef".to_string(),
            architectures: Some(vec!["arm64".to_string(), "x86_64".to_string()]),
        };

        assert_eq!(target.path, "/path/to/file");
        assert_eq!(target.file_type, "macho");
        assert_eq!(target.size_bytes, 2048);
        assert_eq!(target.architectures.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn test_target_info_no_architectures() {
        let target = TargetInfo {
            path: "/path/to/script.py".to_string(),
            file_type: "python".to_string(),
            size_bytes: 512,
            sha256: "abc123".to_string(),
            architectures: None,
        };

        assert!(target.architectures.is_none());
    }

    // ==================== ArchiveEntry Tests ====================

    #[test]
    fn test_archive_entry_simple_path() {
        let entry = ArchiveEntry {
            path: "lib/utils.so".to_string(),
            file_type: "elf".to_string(),
            sha256: "abc123".to_string(),
            size_bytes: 4096,
            ..ArchiveEntry::default()
        };

        assert_eq!(entry.path, "lib/utils.so");
        assert!(!entry.path.contains('!'));
    }

    #[test]
    fn test_archive_entry_nested_path() {
        let entry = ArchiveEntry {
            path: "inner.tar.gz!malware/script.sh".to_string(),
            file_type: "shell".to_string(),
            sha256: "def456".to_string(),
            size_bytes: 256,
            ..ArchiveEntry::default()
        };

        assert!(entry.path.contains('!'));
    }

    // ==================== merge_encoding_layers Tests ====================

    fn test_file(path: &str, findings: Vec<Finding>) -> FileAnalysis {
        let mut fa = FileAnalysis::new(
            0,
            path.to_string(),
            "macho".to_string(),
            "sha256hash".to_string(),
            1024,
        );
        fa.findings = findings;
        fa.compute_summary();
        fa
    }

    #[test]
    fn test_merge_no_layers() {
        let mut report = AnalysisReport::new(test_target());
        report.files = vec![test_file(
            "/bin/sample",
            vec![test_finding("cap/a", Criticality::Notable)],
        )];

        let merged = report.merge_encoding_layers();

        assert!(merged.is_empty());
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].findings.len(), 1);
    }

    #[test]
    fn test_merge_single_root_with_layers() {
        let mut report = AnalysisReport::new(test_target());
        report.files = vec![
            test_file(
                "/bin/sample",
                vec![test_finding("cap/a", Criticality::Notable)],
            ),
            test_file(
                "/bin/sample##xor@100",
                vec![test_finding("cap/b", Criticality::Suspicious)],
            ),
            test_file(
                "/bin/sample##xor@200",
                vec![test_finding("cap/c", Criticality::Notable)],
            ),
        ];

        let merged = report.merge_encoding_layers();

        assert_eq!(merged, vec![0]);
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, "/bin/sample");
        assert_eq!(report.files[0].findings.len(), 3);

        let ids: Vec<&str> = report.files[0]
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        assert!(ids.contains(&"cap/a"));
        assert!(ids.contains(&"cap/b"));
        assert!(ids.contains(&"cap/c"));
    }

    #[test]
    fn test_merge_dedup_keeps_highest_criticality() {
        let mut report = AnalysisReport::new(test_target());
        report.files = vec![
            test_file(
                "/bin/sample",
                vec![test_finding("cap/a", Criticality::Notable)],
            ),
            test_file(
                "/bin/sample##xor@100",
                vec![test_finding("cap/a", Criticality::Hostile)],
            ),
        ];

        report.merge_encoding_layers();

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].findings.len(), 1);
        assert_eq!(report.files[0].findings[0].crit, Criticality::Hostile);
    }

    #[test]
    fn test_merge_dedup_keeps_existing_when_higher() {
        let mut report = AnalysisReport::new(test_target());
        report.files = vec![
            test_file(
                "/bin/sample",
                vec![test_finding("cap/a", Criticality::Hostile)],
            ),
            test_file(
                "/bin/sample##xor@100",
                vec![test_finding("cap/a", Criticality::Notable)],
            ),
        ];

        report.merge_encoding_layers();

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].findings.len(), 1);
        assert_eq!(report.files[0].findings[0].crit, Criticality::Hostile);
    }

    #[test]
    fn test_merge_archive_members_preserved() {
        let mut report = AnalysisReport::new(test_target());
        report.files = vec![
            test_file(
                "/archive.zip",
                vec![test_finding("cap/a", Criticality::Notable)],
            ),
            test_file(
                "/archive.zip!!member.py",
                vec![test_finding("cap/b", Criticality::Suspicious)],
            ),
        ];

        let merged = report.merge_encoding_layers();

        assert!(merged.is_empty());
        assert_eq!(report.files.len(), 2);
    }

    #[test]
    fn test_merge_archive_member_with_layers() {
        let mut report = AnalysisReport::new(test_target());
        report.files = vec![
            test_file(
                "/archive.zip!!member.py",
                vec![test_finding("cap/a", Criticality::Notable)],
            ),
            test_file(
                "/archive.zip!!member.py##base64@0",
                vec![test_finding("cap/b", Criticality::Hostile)],
            ),
        ];

        let merged = report.merge_encoding_layers();

        assert_eq!(merged, vec![0]);
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, "/archive.zip!!member.py");
        assert_eq!(report.files[0].findings.len(), 2);
    }

    #[test]
    fn test_merge_layer_only_findings_appear() {
        let mut report = AnalysisReport::new(test_target());
        report.files = vec![
            test_file("/bin/sample", vec![]),
            test_file(
                "/bin/sample##xor@100",
                vec![test_finding("cap/layer_only", Criticality::Suspicious)],
            ),
        ];

        report.merge_encoding_layers();

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].findings.len(), 1);
        assert_eq!(report.files[0].findings[0].id, "cap/layer_only");
    }

    #[test]
    fn test_merge_recomputes_summary() {
        let mut report = AnalysisReport::new(test_target());
        report.files = vec![
            test_file(
                "/bin/sample",
                vec![test_finding("cap/a", Criticality::Notable)],
            ),
            test_file(
                "/bin/sample##xor@100",
                vec![test_finding("cap/b", Criticality::Hostile)],
            ),
        ];

        report.merge_encoding_layers();

        // ceil(hostile(120)*0.9) + ceil(notable(1)*0.9) = 108+1 = 109
        assert_eq!(report.files[0].score, 109);
        let counts = report.files[0].counts.as_ref().unwrap();
        assert_eq!(counts.hostile, 1);
        assert_eq!(counts.notable, 1);
    }

    #[test]
    fn test_inherit_archive_child_findings_preserves_child() {
        let mut report = AnalysisReport::new(test_target());
        report.files = vec![
            test_file(
                "/archive.zip",
                vec![test_finding("cap/archive", Criticality::Notable)],
            ),
            test_file(
                "/archive.zip!!member.py",
                vec![test_finding("cap/member", Criticality::Suspicious)],
            ),
        ];

        report.files[1].id = 1;

        let changed = report.inherit_child_findings_into_wrappers();

        assert_eq!(changed, vec![0]);
        assert_eq!(report.files.len(), 2);
        // The wrapper's own finding stays native; the bubbled-up one is tagged
        // with the member's file id so it can be attributed back to its origin.
        let archive = report.files[0]
            .findings
            .iter()
            .find(|f| f.id == "cap/archive")
            .expect("wrapper keeps its own finding");
        assert_eq!(archive.src, None, "native finding is not tagged");
        let inherited = report.files[0]
            .findings
            .iter()
            .find(|f| f.id == "cap/member")
            .expect("member finding bubbled up");
        assert_eq!(inherited.src, Some(1), "inherited finding points at member");
        // The child entry is preserved and its own copy stays native.
        assert_eq!(report.files[1].findings.len(), 1);
        assert_eq!(report.files[1].findings[0].id, "cap/member");
        assert_eq!(report.files[1].findings[0].src, None);
    }

    #[test]
    fn located_member_matches_leaf_member() {
        // Evidence locations carry the bare member name (plus an optional offset),
        // while file paths carry the full archive chain — both reduce to the same
        // leaf member, which is how provenance is matched in `finalize`.
        assert_eq!(located_member("archive:embedded_ls"), Some("embedded_ls"));
        assert_eq!(
            located_member("archive:embedded_ls:0x1126"),
            Some("embedded_ls")
        );
        assert_eq!(located_member("archive:lib/foo.so"), Some("lib/foo.so"));
        assert_eq!(located_member("offset:0x40"), None);
        assert_eq!(located_member("import"), None);
        assert_eq!(leaf_member("/tmp/a.zip!!embedded_ls"), "embedded_ls");
        assert_eq!(leaf_member("/tmp/a.zip!!inner.zip!!deep"), "deep");
        assert_eq!(leaf_member("/bin/ls"), "/bin/ls");
    }

    #[test]
    fn test_inherit_nested_child_findings_to_each_wrapper() {
        let mut report = AnalysisReport::new(test_target());
        report.files = vec![
            test_file(
                "/outer.zip",
                vec![test_finding("cap/outer", Criticality::Notable)],
            ),
            test_file(
                "/outer.zip!!inner.tar",
                vec![test_finding("cap/inner", Criticality::Notable)],
            ),
            test_file(
                "/outer.zip!!inner.tar!!payload",
                vec![test_finding("cap/payload", Criticality::Hostile)],
            ),
        ];
        report.files[1].depth = 1;
        report.files[2].depth = 2;

        let changed = report.inherit_child_findings_into_wrappers();

        assert_eq!(changed, vec![0, 1]);
        assert!(
            report.files[1]
                .findings
                .iter()
                .any(|f| f.id == "cap/payload")
        );
        assert!(
            report.files[0]
                .findings
                .iter()
                .any(|f| f.id == "cap/payload")
        );
    }

    #[test]
    fn test_finalize_inherits_upx_child_findings_into_root() {
        let mut report = AnalysisReport::new(TargetInfo {
            path: "/bin/sample".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 10,
            sha256: "rootsha".to_string(),
            architectures: None,
        });
        report.findings = vec![test_finding("anti-static/packer/upx", Criticality::Notable)];
        let mut child = test_file(
            "/bin/sample!!upx@0",
            vec![test_finding("cap/unpacked", Criticality::Suspicious)],
        );
        child.depth = 1;
        report.files.push(child);

        report.finalize();

        assert_eq!(report.files.len(), 2);
        assert_eq!(report.files[0].path, "/bin/sample");
        assert!(
            report.files[0]
                .findings
                .iter()
                .any(|f| f.id == "anti-static/packer/upx")
        );
        assert!(
            report.files[0]
                .findings
                .iter()
                .any(|f| f.id == "cap/unpacked")
        );
        assert!(
            report.files[1]
                .findings
                .iter()
                .any(|f| f.id == "cap/unpacked")
        );
    }

    // ==================== seal_archive_metadata_kv Tests ====================

    fn archive_report_with_entries(entries: Vec<ArchiveEntry>) -> AnalysisReport {
        let target = TargetInfo {
            path: "test.zip".to_string(),
            file_type: "zip".to_string(),
            size_bytes: 1024,
            sha256: "abc".to_string(),
            architectures: None,
        };
        let mut report = AnalysisReport::new(target);
        report.archive_contents = entries;
        report
    }

    #[test]
    fn test_seal_archive_metadata_kv_empty_is_noop() {
        let mut report = archive_report_with_entries(Vec::new());
        report.seal_archive_metadata_kv();
        assert!(
            report.values_tree.is_none(),
            "Empty archive_contents should not produce a kv tree"
        );
    }

    #[test]
    fn test_seal_archive_metadata_kv_emits_members_and_aggregates() {
        let entries = vec![
            ArchiveEntry {
                path: "manifest.json".to_string(),
                file_type: "json".to_string(),
                sha256: "h1".to_string(),
                size_bytes: 4108,
                compressed_size: Some(926),
                compression_method: Some("deflate".to_string()),
                mtime_unix: Some(1_700_000_000),
                mode_octal: Some(0o755),
                uid: Some(1000),
                gid: Some(1000),
                uname: Some("alice".to_string()),
                gname: Some("staff".to_string()),
                entry_type: Some("regular".to_string()),
                linkname: None,
                host_os: None,
                ..ArchiveEntry::default()
            },
            ArchiveEntry {
                path: "lib/setuid-bin".to_string(),
                file_type: "elf".to_string(),
                sha256: "h2".to_string(),
                size_bytes: 8000,
                compressed_size: Some(4000),
                compression_method: Some("stored".to_string()),
                mtime_unix: Some(1_700_000_300),
                // setuid + world-writable bits set, exercising both decompositions.
                mode_octal: Some(0o4757),
                uid: None,
                gid: None,
                uname: None,
                gname: None,
                entry_type: Some("regular".to_string()),
                linkname: None,
                host_os: None,
                ..ArchiveEntry::default()
            },
            ArchiveEntry {
                path: "external".to_string(),
                file_type: "symlink".to_string(),
                sha256: String::new(),
                size_bytes: 0,
                compressed_size: Some(0),
                compression_method: Some("stored".to_string()),
                mtime_unix: Some(1_700_000_100),
                mode_octal: Some(0o120777),
                uid: None,
                gid: None,
                uname: None,
                gname: None,
                entry_type: Some("symlink".to_string()),
                linkname: Some("/etc/passwd".to_string()),
                host_os: None,
                ..ArchiveEntry::default()
            },
        ];
        let mut report = archive_report_with_entries(entries);
        report.seal_archive_metadata_kv();

        let kv = report.values_tree.expect("values_tree should be populated");
        let archive = kv
            .get("archive")
            .expect("archive subtree should be present");

        // Per-member objects survive verbatim with their forensic fields.
        let members = archive
            .get("members")
            .and_then(|v| v.as_array())
            .expect("archive.members should be an array");
        assert_eq!(members.len(), 3);
        let first = &members[0];
        assert_eq!(
            first.get("path").and_then(|v| v.as_str()),
            Some("manifest.json")
        );
        assert_eq!(first.get("uname").and_then(|v| v.as_str()), Some("alice"));
        assert_eq!(
            first.get("mode_octal").and_then(serde_json::Value::as_u64),
            Some(0o755)
        );
        assert_eq!(
            first.get("compression_method").and_then(|v| v.as_str()),
            Some("deflate")
        );

        // Member count + aggregates.
        assert_eq!(
            archive
                .get("member_count")
                .and_then(serde_json::Value::as_u64),
            Some(3)
        );

        // Compression aggregate: deflate + stored present.
        let comp = archive
            .get("compression")
            .expect("archive.compression should be present");
        let methods: Vec<&str> = comp
            .get("methods")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        assert!(methods.contains(&"deflate"));
        assert!(methods.contains(&"stored"));
        // method_counts.deflate = 1, method_counts.stored = 2
        assert_eq!(
            comp.get("method_counts")
                .and_then(|v| v.get("stored"))
                .and_then(serde_json::Value::as_u64),
            Some(2)
        );

        // Timing aggregates emit when at least one mtime is present.
        let timing = archive
            .get("timing")
            .expect("archive.timing should be present when mtimes exist");
        assert_eq!(
            timing.get("mtime_min").and_then(serde_json::Value::as_i64),
            Some(1_700_000_000)
        );
        assert_eq!(
            timing.get("mtime_max").and_then(serde_json::Value::as_i64),
            Some(1_700_000_300)
        );
        assert_eq!(
            timing
                .get("mtime_spread_seconds")
                .and_then(serde_json::Value::as_i64),
            Some(300)
        );
        assert_eq!(
            timing
                .get("mtime_unique_count")
                .and_then(serde_json::Value::as_u64),
            Some(3)
        );

        // Security decomposition: setuid bit on the elf, world-writable on
        // elf + symlink, one external symlink with absolute target.
        let security = archive
            .get("security")
            .expect("archive.security should be present");
        assert_eq!(
            security
                .get("setuid_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            security
                .get("symlink_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            security
                .get("external_symlink_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );

        // Builder names lifted from POSIX ownership strings.
        let builder = archive
            .get("builder")
            .expect("archive.builder should be present");
        let unames: Vec<&str> = builder
            .get("unames")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        assert_eq!(unames, vec!["alice"]);
    }

    #[test]
    fn test_seal_archive_metadata_kv_omits_timing_when_no_mtimes() {
        // Mozilla web-ext zeroes timestamps; the sentinel (1980, 0, 0) is
        // rejected by the extractor, so all mtime_unix fields are None.
        // The seal should omit `archive.timing` entirely rather than emit a
        // misleading 0/0/0 block.
        let entries = vec![ArchiveEntry {
            path: "manifest.json".to_string(),
            file_type: "json".to_string(),
            sha256: "h1".to_string(),
            size_bytes: 100,
            compressed_size: Some(50),
            compression_method: Some("deflate".to_string()),
            mtime_unix: None,
            mode_octal: None,
            uid: None,
            gid: None,
            uname: None,
            gname: None,
            entry_type: Some("regular".to_string()),
            linkname: None,
            host_os: None,
            ..ArchiveEntry::default()
        }];
        let mut report = archive_report_with_entries(entries);
        report.seal_archive_metadata_kv();

        let kv = report.values_tree.expect("values_tree present");
        let archive = kv.get("archive").expect("archive subtree present");
        assert!(
            archive.get("timing").is_none(),
            "timing block should be absent when no mtimes were captured"
        );
    }
}
