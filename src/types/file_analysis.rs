//! File analysis types for JSON v2 schema
//!
//! This module provides the flat file-centric output structure that replaces
//! the nested sub_reports approach. Each file (including archive members and
//! decoded payloads) gets its own FileAnalysis entry.

use rustc_hash::{FxHashMap, FxHashSet};
use serde::{Deserialize, Serialize};

use super::binary::{Export, Function, Import, Section, StringInfo, SyscallInfo, YaraMatch};
use super::core::Criticality;
use super::filefacts_view::FilefactsView;
use super::paths_env::{DirectoryAccess, EnvVarInfo, PathInfo};
use super::traits_findings::{ContextLine, Finding, StructuralFeature, Trait};

/// Path delimiter for archive members (e.g., "archive.zip!!inner/file.py")
pub(crate) const ARCHIVE_DELIMITER: &str = "!!";

/// Path delimiter for decoded content (e.g., "file.py##base64+gzip@1234")
pub(crate) const ENCODING_DELIMITER: &str = "##";

/// One member that a cross-file composite drew a component from. Ties the
/// composite to the file it was based on, with the component's location when a
/// context note pins it (`line` for source files, `offset` for binaries). A
/// component with no anchorable location — e.g. a metric or a manifest-field
/// presence trait — contributes the file alone.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct CompositeSource {
    /// `FileAnalysis::id` of the contributing archive member.
    pub file: u32,
    /// 1-based source line of the component match, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    /// Byte offset of the component match, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
}

/// How a file relates to its structural parent (`parent_id`). The compact
/// output omits the ordinary containment case (`Member`); a root file is
/// identified by an absent `pid`, not by a `rel`. Orthogonal to [`Role`]: a
/// `.SRCINFO` is `Member` (physically in the archive) yet `Role::Sidecar`
/// (package metadata), while a fetched tarball is `Fetched` yet `Role::Content`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Rel {
    /// Ordinary archive/container member. Default; omitted from output.
    #[default]
    Member,
    /// Fetched over the network from a reference in the parent (e.g. a PKGBUILD
    /// `source=()` URL). The resolved locator rides in [`FileAnalysis::via`].
    Fetched,
    /// Unpacked or decoded from the parent by a transform (UPX, base64, …).
    Unpacked,
    /// A registry/provenance record looked up for the parent package.
    Registry,
}

impl Rel {
    /// Whether this is the default containment edge (omitted from output).
    pub(crate) fn is_member(&self) -> bool {
        matches!(self, Rel::Member)
    }
}

/// How analysis, ML, and presentation should treat a file. The compact output
/// omits the ordinary `Content` case. Orthogonal to [`Rel`] — see its note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Real extracted bytes: fully analyzed and byte-scored. Default; omitted.
    #[default]
    Content,
    /// Metadata about its `pid` (registry/provenance/manifest). Analyzed from
    /// its own canonical bytes — its traits feed the sample's ML features — but
    /// it is not byte-scored as standalone content.
    Sidecar,
}

impl Role {
    /// Whether this is the default content role (omitted from output).
    pub(crate) fn is_content(&self) -> bool {
        matches!(self, Role::Content)
    }
}

/// Per-file analysis - the core unit in v2 schema
///
/// Each file (root, archive member, or decoded payload) gets its own entry.
/// This replaces the recursive sub_reports structure with a flat array.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FileAnalysis {
    /// Unique ID within this report (sequential, 0-based)
    pub id: u32,

    /// Full path including archive/encoding context
    /// Format: "root.zip!!inner/file.py##base64+gzip@1234"
    pub path: String,

    /// Parent file ID (null for root files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<u32>,

    /// Nesting depth (0 = root, 1 = archive member, 2 = decoded content, etc.)
    pub depth: u32,

    /// Edge type to `parent_id`: how this file was obtained. Omitted for the
    /// default containment case. See [`Rel`].
    #[serde(default, skip_serializing_if = "Rel::is_member")]
    pub rel: Rel,

    /// For `rel = Fetched`, the resolved locator (URL/PURL) it came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,

    /// Analysis participation. Omitted for `Content`. See [`Role`].
    #[serde(default, skip_serializing_if = "Role::is_content")]
    pub role: Role,

    /// Detected file type (e.g., "python", "elf", "archive")
    pub file_type: String,

    /// CPU architecture (e.g., "x86_64", "m68k", "aarch64")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,

    /// SHA256 hash of file contents
    pub sha256: String,

    /// File size in bytes
    pub size: u64,

    // === Per-file summary (for easy filtering) ===
    /// Weighted risk score: sum(ceil(criticality_weight * confidence)) across findings
    #[serde(rename = "x", default, skip_serializing_if = "is_zero")]
    pub score: u32,

    /// Finding counts by criticality
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counts: Option<FindingCounts>,

    // === Layer info (for decoded content) ===
    /// Encoding chain for decoded content (e.g., ["base64", "gzip"])
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<Vec<String>>,

    // === Analysis results ===
    /// Findings for this file
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub findings: Vec<Finding>,

    /// Merged, render-ready context: matched content shown once, in file
    /// order, annotated with the findings that touch it. Replaces raw
    /// per-finding evidence as the output surface.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub context: Vec<ContextLine>,

    // === Verbose fields (omitted in minimal mode) ===
    /// Traits discovered in this file
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub traits: Vec<Trait>,

    /// Structural features
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub structure: Vec<StructuralFeature>,

    /// Functions defined in this file
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub functions: Vec<Function>,

    /// Strings extracted from this file
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub strings: Vec<StringInfo>,

    /// Sections (for binaries)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub sections: Vec<Section>,

    /// Imports
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub imports: Vec<Import>,

    /// Exports
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub exports: Vec<Export>,

    /// YARA matches
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub yara_matches: Vec<YaraMatch>,

    /// Syscalls (for binaries)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub syscalls: Vec<SyscallInfo>,

    /// Report-side mirror of filefacts's typed views. Schema v3.0
    /// ships this verbatim under `filefacts: ...`. See
    /// `crate::types::FilefactsView` for the field shape.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub filefacts: Option<FilefactsView>,

    /// Normalized identity claims (filefacts `Identity`): who/what the
    /// file claims to be, signer, trust tier, build path, unique ids —
    /// each tagged claimed-vs-verified. Present only when non-empty.
    /// The headline surface for "is this what it says it is?".
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub identity: Option<filefacts::Identity>,

    /// Flat metric map mirroring filefacts's emission convention.
    /// Sole numeric metric surface — typed projection structs retired.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub filefacts_metrics: Option<std::collections::BTreeMap<String, f64>>,

    /// Paths discovered
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub paths: Vec<PathInfo>,

    /// Directories accessed
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub directories: Vec<DirectoryAccess>,

    /// Environment variables accessed
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub env_vars: Vec<EnvVarInfo>,

    /// Path to extracted sample file on disk (set when --sample-dir is used)
    /// Allows external tools (radare2, objdump, strings) to analyze the file directly
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extracted_path: Option<String>,

    /// Molecular formula representing the file's behavioral fingerprint
    /// Generated from findings using the malecule library
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formula: Option<String>,

    /// Provenance for this file's cross-file (container) composites: each
    /// composite finding id → the archive members whose components it fired on,
    /// with a location where one is known. Computed in `finalize` while the
    /// per-member component findings/notes are still present (they're filtered
    /// from the output later). Surfaced into the compact output as the
    /// composite's `from` (member + line/offset) and rendered as the `↳` member
    /// trail. Serialized (omitted when empty) so a cached report round-trips
    /// losslessly: a cache hit skips `finalize`, so without this the compact
    /// `from` loses its line/offset provenance and the trail disappears.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub composite_sources: std::collections::BTreeMap<String, Vec<CompositeSource>>,

    /// Flat structural-kv map. Path → leaf value, using the same
    /// `a.b[0].c` notation as `cleave value`. Auto-populated at
    /// `finalize()` time from the analyzer's `values_tree`. Type-default
    /// leaves (`false` / `0` / `""` / `null` / empty containers) are
    /// skipped — collimator-style ML pipelines treat absent features
    /// as default, so omitting them halves the per-file payload
    /// without losing signal.
    #[serde(
        rename = "k",
        default,
        skip_serializing_if = "std::collections::BTreeMap::is_empty"
    )]
    pub kv: std::collections::BTreeMap<String, serde_json::Value>,
}

impl FileAnalysis {
    /// Create a new FileAnalysis with minimal required fields
    #[must_use]
    pub(crate) fn new(id: u32, path: String, file_type: String, sha256: String, size: u64) -> Self {
        Self {
            id,
            path,
            parent_id: None,
            depth: 0,
            rel: Rel::Member,
            via: None,
            role: Role::Content,
            file_type,
            arch: None,
            sha256,
            size,
            score: 0,
            counts: None,
            encoding: None,
            findings: Vec::new(),
            context: Vec::new(),
            traits: Vec::new(),
            structure: Vec::new(),
            functions: Vec::new(),
            strings: Vec::new(),
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            yara_matches: Vec::new(),
            syscalls: Vec::new(),
            filefacts: None,
            identity: None,
            filefacts_metrics: None,
            paths: Vec::new(),
            directories: Vec::new(),
            env_vars: Vec::new(),
            extracted_path: None,
            formula: None,
            composite_sources: std::collections::BTreeMap::new(),
            kv: std::collections::BTreeMap::new(),
        }
    }

    /// Compute score and counts from findings
    pub(crate) fn compute_summary(&mut self) {
        if self.findings.is_empty() {
            self.score = 0;
            self.counts = None;
            return;
        }

        let mut counts = FindingCounts::default();
        let mut scores_by_group: FxHashMap<String, f32> = FxHashMap::default();

        // Build set of component IDs referenced by composite findings so that
        // only components that contributed to a composite are scored.
        let referenced_components: FxHashSet<&str> = self
            .findings
            .iter()
            .flat_map(|f| f.trait_refs.iter().map(String::as_str))
            .collect();

        for finding in &self.findings {
            match finding.crit {
                Criticality::Hostile => counts.hostile += 1,
                Criticality::Suspicious => counts.suspicious += 1,
                Criticality::Notable => counts.notable += 1,
                _ => {}
            }

            let score = match finding.crit {
                Criticality::Baseline => 0.2 * finding.conf,
                Criticality::Component => {
                    if referenced_components.contains(finding.id.as_str()) {
                        0.3 * finding.conf
                    } else {
                        0.0
                    }
                }
                _ => finding.crit.score_weight() as f32 * finding.conf,
            };

            // Group by top 3 directory components
            // e.g., "objectives/well-known/malware/trickbot" -> "objectives/well-known/malware"
            let base = finding.id.split("::").next().unwrap_or(&finding.id);
            let group_id = base.split('/').take(3).collect::<Vec<_>>().join("/");

            let entry = scores_by_group.entry(group_id).or_insert(0.0);
            if score > *entry {
                *entry = score;
            }
        }

        let total_score: f32 = scores_by_group.values().sum();
        self.score = total_score.ceil() as u32;

        self.counts = if counts.hostile > 0 || counts.suspicious > 0 || counts.notable > 0 {
            Some(counts)
        } else {
            None
        };
    }

    /// Clear `source` fields from all nested types — internal metadata not needed in output
    /// Drop fields that the compact output (`compact::convert_file`) never
    /// reads. Every report consumer — the CLI, the cleave server, and litmus's
    /// feature extractor — serializes through `compact_from_files`, which pulls
    /// only findings, imports, exports, functions, sections, metrics, kv, and
    /// the already-rendered context. The fields cleared here are populated
    /// during analysis but never serialized, so on a member-heavy archive
    /// (thousands of members) they accumulate into multiple GB of live, unused
    /// memory. Clearing them per member, after matching has materialized
    /// findings and context, leaves the compact output byte-for-byte identical.
    pub(crate) fn clear_unserialized_fields(&mut self) {
        self.traits = Vec::new();
        self.structure = Vec::new();
        self.strings = Vec::new();
        self.yara_matches = Vec::new();
        self.syscalls = Vec::new();
        self.paths = Vec::new();
        self.directories = Vec::new();
        self.env_vars = Vec::new();
    }

    pub(crate) fn strip_source_fields(&mut self) {
        for t in &mut self.traits {
            t.source.clear();
        }
        for f in &mut self.findings {
            for e in &mut f.evidence {
                e.source.clear();
            }
        }
        for p in &mut self.paths {
            p.source.clear();
            for e in &mut p.evidence {
                e.source.clear();
            }
        }
        for ev in &mut self.env_vars {
            ev.source.clear();
            for e in &mut ev.evidence {
                e.source.clear();
            }
        }
    }

    /// Ensure `metrics.file.size` is set from `self.size`. Called by the
    /// analysis pipeline post-analyzer so every file type carries this
    /// universal metric, regardless of which analyzer ran. Writes the
    /// flat-map carrier directly — the typed `FileMetrics` struct is
    /// retired (#41).
    pub(crate) fn populate_file_metrics(&mut self) {
        use super::MetricsExt;
        let size = self.size;
        self.filefacts_metrics
            .get_or_insert_with(Default::default)
            .set_u("file.size", size);
    }
}

/// Finding counts by criticality
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FindingCounts {
    /// Number of hostile findings
    #[serde(default, skip_serializing_if = "is_zero")]
    pub hostile: u32,
    /// Number of suspicious findings
    #[serde(default, skip_serializing_if = "is_zero")]
    pub suspicious: u32,
    /// Number of notable findings
    #[serde(default, skip_serializing_if = "is_zero")]
    pub notable: u32,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

/// Report-level summary
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReportSummary {
    /// Number of files analyzed
    pub files_analyzed: u32,
    /// Aggregate finding counts
    pub counts: FindingCounts,
    /// Aggregate weighted risk score across all files
    #[serde(rename = "x", default, skip_serializing_if = "is_zero")]
    pub score: u32,
    /// Total analysis duration in milliseconds
    #[serde(skip_serializing_if = "is_zero_u64", default)]
    pub duration_ms: u64,
    /// Tools used during analysis
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tools: Vec<String>,
    /// Non-fatal errors encountered
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub errors: Vec<String>,
}

impl ReportSummary {
    /// Compute summary from files array
    #[must_use]
    pub(crate) fn from_files(files: &[FileAnalysis]) -> Self {
        let mut summary = Self {
            files_analyzed: files.len() as u32,
            counts: FindingCounts::default(),
            ..Default::default()
        };

        for file in files {
            if let Some(counts) = &file.counts {
                summary.counts.hostile += counts.hostile;
                summary.counts.suspicious += counts.suspicious;
                summary.counts.notable += counts.notable;
            }
            summary.score += file.score;
        }

        summary
    }
}

// =============================================================================
// Path encoding utilities
// =============================================================================

/// Encode an archive member path
///
/// Example: encode_archive_path("foo.zip", "inner/file.py") -> "foo.zip!!inner/file.py"
#[must_use]
pub(crate) fn encode_archive_path(parent: &str, member: &str) -> String {
    format!("{}{}{}", parent, ARCHIVE_DELIMITER, member)
}

/// Encode a decoded content path
///
/// Example: encode_decoded_path("file.py", &["base64", "gzip"], 1234) -> "file.py##base64+gzip@1234"
#[must_use]
pub(crate) fn encode_decoded_path(parent: &str, encoding: &[String], offset: usize) -> String {
    let encoding_str = encoding.join("+");
    format!(
        "{}{}{}@{}",
        parent, ENCODING_DELIMITER, encoding_str, offset
    )
}

/// Encode a UPX-unpacked content path.
///
/// Uses the archive delimiter (`!!`) so the unpacked binary is treated as a
/// child file entry (like a zip member) rather than an encoding layer that
/// gets merged back into the parent.
///
/// Example: encode_upx_path("sample.exe") -> "sample.exe!!upx@0"
#[must_use]
pub(crate) fn encode_upx_path(parent: &str) -> String {
    format!("{}{}upx@0", parent, ARCHIVE_DELIMITER)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ==================== Constants Tests ====================

    #[test]
    fn test_archive_delimiter() {
        assert_eq!(ARCHIVE_DELIMITER, "!!");
    }

    #[test]
    fn test_encoding_delimiter() {
        assert_eq!(ENCODING_DELIMITER, "##");
    }

    // ==================== FileAnalysis Tests ====================

    #[test]
    fn test_file_analysis_new() {
        let fa = FileAnalysis::new(
            0,
            "test.py".to_string(),
            "python".to_string(),
            "abc123def".to_string(),
            1024,
        );
        assert_eq!(fa.id, 0);
        assert_eq!(fa.path, "test.py");
        assert_eq!(fa.file_type, "python");
        assert_eq!(fa.sha256, "abc123def");
        assert_eq!(fa.size, 1024);
        assert_eq!(fa.depth, 0);
        assert!(fa.parent_id.is_none());
    }

    #[test]
    fn test_file_analysis_new_all_collections_empty() {
        let fa = FileAnalysis::new(
            0,
            "test.py".to_string(),
            "python".to_string(),
            "abc".to_string(),
            100,
        );
        assert!(fa.findings.is_empty());
        assert!(fa.traits.is_empty());
        assert!(fa.structure.is_empty());
        assert!(fa.functions.is_empty());
        assert!(fa.strings.is_empty());
        assert!(fa.sections.is_empty());
        assert!(fa.imports.is_empty());
        assert!(fa.exports.is_empty());
        assert!(fa.yara_matches.is_empty());
        assert!(fa.syscalls.is_empty());
        assert!(fa.paths.is_empty());
        assert!(fa.directories.is_empty());
        assert!(fa.env_vars.is_empty());
    }

    #[test]
    fn test_file_analysis_new_all_options_none() {
        let fa = FileAnalysis::new(
            0,
            "test.py".to_string(),
            "python".to_string(),
            "abc".to_string(),
            100,
        );
        assert_eq!(fa.score, 0);
        assert!(fa.counts.is_none());
        assert!(fa.encoding.is_none());
        assert!(fa.extracted_path.is_none());
    }

    #[test]
    fn test_file_analysis_compute_summary_empty() {
        let mut fa = FileAnalysis::new(
            0,
            "test.py".to_string(),
            "python".to_string(),
            "abc".to_string(),
            100,
        );
        fa.compute_summary();
        assert_eq!(fa.score, 0);
        assert!(fa.counts.is_none());
    }

    #[test]
    fn test_file_analysis_compute_summary_notable_only() {
        let mut fa = FileAnalysis::new(
            0,
            "test.py".to_string(),
            "python".to_string(),
            "abc".to_string(),
            100,
        );
        fa.findings.push(
            Finding::capability("test/notable".to_string(), "Test".to_string(), 0.5)
                .with_criticality(Criticality::Notable),
        );
        fa.compute_summary();
        // ceil(notable(1) * conf(0.5)) = ceil(0.5) = 1
        assert_eq!(fa.score, 1);
        let counts = fa.counts.unwrap();
        assert_eq!(counts.notable, 1);
        assert_eq!(counts.suspicious, 0);
        assert_eq!(counts.hostile, 0);
    }

    #[test]
    fn test_file_analysis_compute_summary_baseline_only() {
        let mut fa = FileAnalysis::new(
            0,
            "test.py".to_string(),
            "python".to_string(),
            "abc".to_string(),
            100,
        );
        fa.findings.push(
            Finding::capability("test/baseline".to_string(), "Test".to_string(), 0.1)
                .with_criticality(Criticality::Baseline),
        );
        fa.compute_summary();
        // baseline findings contribute 0.2 * conf; ceil(0.2 * 0.1) = 1
        assert_eq!(fa.score, 1);
        assert!(fa.counts.is_none());
    }

    // ==================== FindingCounts Tests ====================

    #[test]
    fn test_finding_counts_default() {
        let counts = FindingCounts::default();
        assert_eq!(counts.hostile, 0);
        assert_eq!(counts.suspicious, 0);
        assert_eq!(counts.notable, 0);
    }

    #[test]
    fn test_finding_counts_with_values() {
        let counts = FindingCounts {
            hostile: 5,
            suspicious: 10,
            notable: 15,
        };
        assert_eq!(counts.hostile, 5);
        assert_eq!(counts.suspicious, 10);
        assert_eq!(counts.notable, 15);
    }

    // ==================== ReportSummary Tests ====================

    #[test]
    fn test_report_summary_default() {
        let summary = ReportSummary::default();
        assert_eq!(summary.files_analyzed, 0);
        assert_eq!(summary.counts.hostile, 0);
        assert_eq!(summary.counts.hostile, 0);
        assert_eq!(summary.counts.suspicious, 0);
        assert_eq!(summary.counts.notable, 0);
    }

    #[test]
    fn test_report_summary_from_empty_files() {
        let summary = ReportSummary::from_files(&[]);
        assert_eq!(summary.files_analyzed, 0);
        assert_eq!(summary.counts.hostile, 0);
    }

    #[test]
    fn test_report_summary_from_single_file() {
        let mut file = FileAnalysis::new(
            0,
            "a.py".to_string(),
            "python".to_string(),
            "abc".to_string(),
            100,
        );
        file.depth = 0;

        let summary = ReportSummary::from_files(&[file]);
        assert_eq!(summary.files_analyzed, 1);
        assert_eq!(summary.counts.hostile, 0);
    }

    #[test]
    fn test_report_summary_multiple_files() {
        let file1 = FileAnalysis::new(
            0,
            "a.py".to_string(),
            "python".to_string(),
            "abc".to_string(),
            100,
        );

        let file2 = FileAnalysis::new(
            1,
            "b.py".to_string(),
            "python".to_string(),
            "def".to_string(),
            200,
        );

        let file3 = FileAnalysis::new(
            2,
            "c.py".to_string(),
            "python".to_string(),
            "ghi".to_string(),
            300,
        );

        let summary = ReportSummary::from_files(&[file1, file2, file3]);
        assert_eq!(summary.files_analyzed, 3);
    }

    // ==================== is_zero helper Tests ====================

    #[test]
    fn test_is_zero_true() {
        assert!(is_zero(&0));
    }

    #[test]
    fn test_is_zero_false() {
        assert!(!is_zero(&1));
        assert!(!is_zero(&100));
    }

    // ==================== Path Encoding Tests ====================

    #[test]
    fn test_encode_archive_path() {
        assert_eq!(
            encode_archive_path("foo.zip", "inner/file.py"),
            "foo.zip!!inner/file.py"
        );
    }

    #[test]
    fn test_encode_archive_path_nested() {
        let p1 = encode_archive_path("a.zip", "b.tar");
        let p2 = encode_archive_path(&p1, "c.py");
        assert_eq!(p2, "a.zip!!b.tar!!c.py");
    }

    #[test]
    fn test_encode_decoded_path() {
        assert_eq!(
            encode_decoded_path("file.py", &["base64".to_string(), "gzip".to_string()], 1234),
            "file.py##base64+gzip@1234"
        );
    }

    #[test]
    fn test_encode_upx_path() {
        assert_eq!(encode_upx_path("sample.elf"), "sample.elf!!upx@0");
    }

    #[test]
    fn test_encode_upx_path_with_directory() {
        assert_eq!(encode_upx_path("/tmp/sample.elf"), "/tmp/sample.elf!!upx@0");
    }

    #[test]
    fn test_finding_counts() {
        let mut file = FileAnalysis::new(
            0,
            "test.py".to_string(),
            "python".to_string(),
            "abc123".to_string(),
            100,
        );

        file.findings.push(
            Finding::capability("test/hostile/a".to_string(), "Test".to_string(), 0.9)
                .with_criticality(Criticality::Hostile),
        );

        file.findings.push(
            Finding::capability("test/suspicious/b".to_string(), "Test".to_string(), 0.8)
                .with_criticality(Criticality::Suspicious),
        );

        file.compute_summary();

        // Different top-3 paths: "test/hostile/a" and "test/suspicious/b"
        // Both contribute: ceil(120*0.9) + ceil(40*0.8) = 108 + 32 = 140
        assert_eq!(file.score, 140);
        let counts = file.counts.unwrap();
        assert_eq!(counts.hostile, 1);
        assert_eq!(counts.suspicious, 1);
        assert_eq!(counts.notable, 0);
    }

    #[test]
    fn test_score_grouping() {
        let mut file = FileAnalysis::new(
            0,
            "test.py".to_string(),
            "python".to_string(),
            "abc123".to_string(),
            100,
        );

        // Same top-3 path: "test/foo/bar"
        file.findings.push(
            Finding::capability("test/foo/bar/a".to_string(), "Test".to_string(), 0.9)
                .with_criticality(Criticality::Hostile),
        );

        file.findings.push(
            Finding::capability("test/foo/bar/b".to_string(), "Test".to_string(), 0.8)
                .with_criticality(Criticality::Suspicious),
        );

        file.compute_summary();

        // Same top-3 path: only the highest contributes
        // ceil(120*0.9) = 108
        assert_eq!(file.score, 108);
        let counts = file.counts.unwrap();
        assert_eq!(counts.hostile, 1);
        assert_eq!(counts.suspicious, 1);
    }

    #[test]
    fn test_report_summary() {
        let mut file1 = FileAnalysis::new(
            0,
            "a.py".to_string(),
            "python".to_string(),
            "abc".to_string(),
            100,
        );
        file1.depth = 0;
        file1.counts = Some(FindingCounts {
            hostile: 1,
            suspicious: 2,
            notable: 0,
        });

        let mut file2 = FileAnalysis::new(
            1,
            "b.py".to_string(),
            "python".to_string(),
            "def".to_string(),
            200,
        );
        file2.depth = 2;
        file2.counts = Some(FindingCounts {
            hostile: 0,
            suspicious: 1,
            notable: 3,
        });

        let summary = ReportSummary::from_files(&[file1, file2]);
        assert_eq!(summary.files_analyzed, 2);
        assert_eq!(summary.counts.hostile, 1);
        assert_eq!(summary.counts.suspicious, 3);
        assert_eq!(summary.counts.notable, 3);
    }
}
