//! Core analysis types - the foundation of cleave reports
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::binary::{
    AnalysisMetadata, Export, Function, Import, Section, StringInfo, SyscallInfo, YaraMatch,
};
use super::code_structure::{BinaryProperties, CodeMetrics, OverlayMetrics, SourceCodeMetrics};
use super::diff::DiffReportV1;
use super::file_analysis::{FileAnalysis, ReportSummary};
use super::paths_env::{DirectoryAccess, EnvVarInfo, PathInfo};
use super::scores::Metrics;
use super::traits_findings::{Finding, StructuralFeature, Trait};
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
    /// Schema version ("3" after finalize, "2.0" pre-finalize/cached)
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

    /// Structural features (binary format properties, obfuscation markers)
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub structure: Vec<StructuralFeature>,
    /// Functions discovered via disassembly or source parsing
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub functions: Vec<Function>,
    /// String literals extracted from the file
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub strings: Vec<StringInfo>,
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
    /// Binary format-specific properties (security features, packing indicators)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub binary_properties: Option<BinaryProperties>,
    /// Code complexity metrics (cyclomatic complexity, nesting)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub code_metrics: Option<CodeMetrics>,
    /// Source code-specific metrics (imports, class count, etc.)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub source_code_metrics: Option<SourceCodeMetrics>,
    /// Overlay data metrics (appended data after the binary)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub overlay_metrics: Option<OverlayMetrics>,
    /// Unified metrics container for ML analysis
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub metrics: Option<Metrics>,
    /// Synthetic key-value tree for `type: kv` matchers on file
    /// formats whose metadata isn't natively a manifest (e.g.,
    /// office documents). Populated by analyzers; consumed by the
    /// kv evaluator. The schema is the public trait-base API for
    /// each format that opts in. Serialized so external consumers
    /// (and the upcoming `cleave kv` extension) can introspect the
    /// same path map trait authors target.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kv_tree: Option<Box<serde_json::Value>>,
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
            version: "2.0".to_string(),
            analysis_timestamp: Some(timestamp),
            target,
            traits: Vec::new(),
            findings: Vec::new(),
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
            kv_tree: None,
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
        let aggregated = crate::output::aggregate_findings_by_directory(&file.findings);
        let filtered: Vec<_> = aggregated
            .into_iter()
            .filter(|f| f.crit != Criticality::Baseline && f.conf >= 0.5)
            .collect();
        let formula = malecule_bridge::formula_from_findings(&filtered);
        file.formula = (!formula.is_empty()).then_some(formula);
    }

    /// Add a finding
    pub fn add_finding(&mut self, finding: Finding) {
        if !self.findings.iter().any(|f| f.id == finding.id) {
            self.push_finding_capped(finding);
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

        // Remove structural symbol findings — they restate imports and no consumer reads them
        for file in &mut self.files {
            file.findings
                .retain(|f| !f.id.starts_with("metadata/internal/symbols::"));
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
        self.binary_properties = None;
        self.code_metrics = None;
        self.source_code_metrics = None;
        self.overlay_metrics = None;
        self.metrics = None;

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
        file.metrics = self.metrics.clone();
        file.structure = self.structure.clone();
        file.strings = self.strings.clone();
        file.imports = self.imports.clone();
        file.exports = self.exports.clone();
        file.sections = self.sections.clone();
        file.binary_properties = self.binary_properties.clone();
        file.code_metrics = self.code_metrics.clone();
        file.source_code_metrics = self.source_code_metrics.clone();
        file.overlay_metrics = self.overlay_metrics.clone();

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
        file.metrics = self.metrics;
        file.structure = self.structure;
        file.strings = self.strings;
        file.imports = self.imports;
        file.exports = self.exports;
        file.sections = self.sections;
        file.binary_properties = self.binary_properties;
        file.code_metrics = self.code_metrics;
        file.source_code_metrics = self.source_code_metrics;
        file.overlay_metrics = self.overlay_metrics;

        (file, nested_files, archive_contents)
    }
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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ArchiveEntry {
    /// Path within the archive. For nested archives, uses `!` separator.
    /// Examples: "lib/utils.so", "inner.tar.gz!malware/script.sh"
    pub path: String,
    /// Detected file type (e.g., "java-class", "shell", "elf")
    #[serde(rename = "type")]
    pub file_type: String,
    /// SHA256 hash of the file contents
    pub sha256: String,
    /// File size in bytes
    pub size_bytes: u64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
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

        assert_eq!(report.version, "2.0");
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
}
