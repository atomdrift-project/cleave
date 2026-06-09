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
/// - Component: Building block for composites, hidden unless composite fires
/// - Baseline: Universal baseline noise, low analytical signal
/// - Notable: Defines program purpose, flag in diffs for supply chain security
/// - Suspicious: Unusual/evasive behavior, investigate immediately
/// - Hostile: Almost certainly malicious, very rare
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    /// Matched but wrong file type - preserved for ML analysis
    Filtered,
    /// Building block for composites - only shown when referenced by a matched composite
    Component,
    /// Universal baseline noise - low analytical signal
    #[default]
    Baseline,
    /// Defines program purpose - flag in diffs for supply chain security
    Notable,
    /// Unusual/evasive behavior - investigate immediately
    Suspicious,
    /// Almost certainly malicious - very rare
    Hostile,
}

impl Criticality {
    /// Single-letter tag used in compact/LLM output:
    /// `H`ostile, `S`uspicious, `N`otable, `B`aseline, `C`omponent, `F`iltered.
    #[must_use]
    pub fn letter(self) -> char {
        match self {
            Self::Hostile => 'H',
            Self::Suspicious => 'S',
            Self::Notable => 'N',
            Self::Baseline => 'B',
            Self::Component => 'C',
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
    /// Information about the target file (cleared after finalize — data lives in files[0])
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
            values_tree: None,
            filefacts_metrics: None,
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
    /// `evidence` (capped at [`MAX_EVIDENCE_PER_TRAIT`]) and `trait_refs`
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

    /// Filter out component-criticality findings that aren't referenced by any composite.
    /// Component traits are building blocks that should only appear in output when a
    /// composite rule that uses them has fired.
    /// Returns the number of findings removed.
    pub fn filter_unmatched_components(&mut self) -> usize {
        use std::collections::HashSet;

        // Collect all trait_refs from all findings (these are the traits referenced by composites)
        let mut referenced_traits: HashSet<String> = HashSet::new();

        // From top-level findings
        for finding in &self.findings {
            for trait_ref in &finding.trait_refs {
                referenced_traits.insert(trait_ref.clone());
            }
        }

        // From files array (v2 schema)
        for file in &self.files {
            for finding in &file.findings {
                for trait_ref in &finding.trait_refs {
                    referenced_traits.insert(trait_ref.clone());
                }
            }
        }

        // Filter out Component findings that aren't referenced
        self.filter_findings(|f| {
            if f.crit == Criticality::Component {
                // Keep only if this finding's ID is in the referenced set
                referenced_traits.contains(&f.id)
            } else {
                // Keep all non-Component findings
                true
            }
        })
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

            let child_findings = self.files[child_idx].findings.clone();
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
        file.filefacts_metrics = self.filefacts_metrics.clone();
        file.structure = self.structure.clone();
        file.strings = self.strings.clone();
        file.imports = self.imports.clone();
        file.exports = self.exports.clone();
        file.sections = self.sections.clone();

        file.populate_file_metrics();
        if let Some(tree) = self.values_tree.as_deref() {
            flatten_kv_for_output(tree, &mut file.kv);
        }
        file.values_tree = self.values_tree.clone();
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
        file.filefacts_metrics = self.filefacts_metrics;
        file.structure = self.structure;
        file.strings = self.strings;
        file.imports = self.imports;
        file.exports = self.exports;
        file.sections = self.sections;

        file.populate_file_metrics();
        if let Some(tree) = self.values_tree.as_deref() {
            flatten_kv_for_output(tree, &mut file.kv);
        }
        file.values_tree = self.values_tree;
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
fn flatten_kv_for_output(
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

    // ==================== Criticality Tests ====================

    #[test]
    fn test_criticality_ordering() {
        assert!(Criticality::Filtered < Criticality::Component);
        assert!(Criticality::Component < Criticality::Baseline);
        assert!(Criticality::Baseline < Criticality::Notable);
        assert!(Criticality::Notable < Criticality::Suspicious);
        assert!(Criticality::Suspicious < Criticality::Hostile);
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

        let changed = report.inherit_child_findings_into_wrappers();

        assert_eq!(changed, vec![0]);
        assert_eq!(report.files.len(), 2);
        assert!(
            report.files[0]
                .findings
                .iter()
                .any(|f| f.id == "cap/archive")
        );
        assert!(
            report.files[0]
                .findings
                .iter()
                .any(|f| f.id == "cap/member")
        );
        assert_eq!(report.files[1].findings.len(), 1);
        assert_eq!(report.files[1].findings[0].id, "cap/member");
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
