//! File analysis types for JSON v2 schema
//!
//! This module provides the flat file-centric output structure that replaces
//! the nested sub_reports approach. Each file (including archive members and
//! decoded payloads) gets its own FileAnalysis entry.

use rustc_hash::FxHashMap;
use serde::{Deserialize, Serialize};

use super::binary::{Export, Function, Import, Section, StringInfo, SyscallInfo, YaraMatch};
use super::code_structure::{BinaryProperties, CodeMetrics, OverlayMetrics, SourceCodeMetrics};
use super::core::Criticality;
use super::paths_env::{DirectoryAccess, EnvVarInfo, PathInfo};
use super::scores::Metrics;
use super::traits_findings::{Finding, StructuralFeature, Trait};

/// Path delimiter for archive members (e.g., "archive.zip!!inner/file.py")
pub(crate) const ARCHIVE_DELIMITER: &str = "!!";

/// Path delimiter for decoded content (e.g., "file.py##base64+gzip@1234")
pub(crate) const ENCODING_DELIMITER: &str = "##";

/// Per-file analysis - the core unit in v2 schema
///
/// Each file (root, archive member, or decoded payload) gets its own entry.
/// This replaces the recursive sub_reports structure with a flat array.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Binary properties
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub binary_properties: Option<BinaryProperties>,

    /// Code complexity metrics (cyclomatic complexity, nesting)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub code_metrics: Option<CodeMetrics>,

    /// Source code metrics
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source_code_metrics: Option<SourceCodeMetrics>,

    /// Overlay data metrics (appended data after the binary)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub overlay_metrics: Option<OverlayMetrics>,

    /// Unified metrics container
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metrics: Option<Metrics>,

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
            file_type,
            arch: None,
            sha256,
            size,
            score: 0,
            counts: None,
            encoding: None,
            findings: Vec::new(),
            traits: Vec::new(),
            structure: Vec::new(),
            functions: Vec::new(),
            strings: Vec::new(),
            sections: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            yara_matches: Vec::new(),
            syscalls: Vec::new(),
            binary_properties: None,
            code_metrics: None,
            source_code_metrics: None,
            overlay_metrics: None,
            metrics: None,
            paths: Vec::new(),
            directories: Vec::new(),
            env_vars: Vec::new(),
            extracted_path: None,
            formula: None,
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

        for finding in &self.findings {
            match finding.crit {
                Criticality::Hostile => counts.hostile += 1,
                Criticality::Suspicious => counts.suspicious += 1,
                Criticality::Notable => counts.notable += 1,
                _ => {}
            }

            let score = finding.crit.score_weight() as f32 * finding.conf;

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
    pub(crate) fn strip_source_fields(&mut self) {
        for t in &mut self.traits {
            t.source.clear();
        }
        for f in &mut self.findings {
            for e in &mut f.evidence {
                e.source.clear();
            }
        }
        for f in &mut self.functions {
            f.source.clear();
        }
        for i in &mut self.imports {
            i.source.clear();
        }
        for e in &mut self.exports {
            e.source.clear();
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
        assert!(fa.binary_properties.is_none());
        assert!(fa.code_metrics.is_none());
        assert!(fa.source_code_metrics.is_none());
        assert!(fa.overlay_metrics.is_none());
        assert!(fa.metrics.is_none());
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
        // baseline findings don't contribute to score
        assert_eq!(fa.score, 0);
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
