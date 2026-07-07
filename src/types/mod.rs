//! Type definitions for cleave analysis reports
//!
//! This module provides all the type definitions used throughout cleave for
//! representing analysis results, metrics, and findings.

// Helper functions for serde skip_serializing_if (like Go's omitempty)
pub(crate) fn is_false(b: &bool) -> bool {
    !*b
}

pub(crate) fn is_zero_u32(n: &u32) -> bool {
    *n == 0
}

pub(crate) fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

pub(crate) fn is_zero_f32(n: &f32) -> bool {
    *n == 0.0
}

#[allow(dead_code)] // Used by binary target
pub(crate) fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

#[allow(dead_code)] // Used by binary target
pub(crate) fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

// Module declarations
pub mod binary;
pub(crate) mod code_structure;
pub mod compact;
pub(crate) mod core;
pub(crate) mod diff;
pub mod field_paths;
pub(crate) mod file_analysis;
pub mod filefacts_view;
// Retired with the cleave→filefacts migration (now sourced from filefacts's
// flat metric map under their respective namespaces — `file.*`,
// `image.*`/`jpeg.*`/`png.*`, `lnk.*`, `pdf.*`, `text.*`/
// `identifiers.*`/`strings.*`/`comments.*`/`functions.*`/`imports.*`):
// file_metrics, image_metrics, jpeg_metrics, png_metrics, lnk_metrics,
// pdf_metrics, text_metrics, language_metrics.
pub(crate) mod ml_features;
pub(crate) mod office_metrics;
pub(crate) mod paths_env;
pub(crate) mod reference_graph;
pub(crate) mod scores;
pub(crate) mod traits_findings;
pub(crate) mod z85;

// Re-export all public types to maintain API compatibility
// These re-exports are part of the public library API even if not used directly in the binary
#[allow(unused_imports)]
pub use compact::{CompactReport, compact_from_files};
#[allow(unused_imports)]
pub use core::{
    AnalysisReport, ArchiveEntry, Criticality, ExtractedPayload, MetricsExt, TargetInfo,
    flatten_into_metrics, kv_set_path,
};

pub use filefacts_view::FilefactsView;

#[allow(unused_imports)]
pub(crate) use file_analysis::{
    ARCHIVE_DELIMITER, ENCODING_DELIMITER, FindingCounts, ReportSummary, encode_archive_path,
    encode_decoded_path,
};
pub use file_analysis::{FileAnalysis, Rel, Role};

#[allow(unused_imports)]
pub use traits_findings::{
    ContextLine, Evidence, Finding, FindingKind, Note, StructuralFeature, Trait, TraitKind,
};
pub(crate) use traits_findings::{
    MAX_EVIDENCE_PER_TRAIT, deduplicate_evidence, truncate_evidence_value,
};

#[allow(unused_imports)]
pub(crate) use paths_env::{
    DirectoryAccess, DirectoryAccessPattern, EnvVarAccessType, EnvVarCategory, EnvVarInfo,
    PathAccessType, PathCategory, PathInfo, PathType,
};

#[allow(unused_imports)]
pub use binary::{
    AnalysisMetadata, DecodedString, Export, Function, Import, MatchedString, Section, StringInfo,
    StringType, SyscallInfo, YaraMatch,
};

#[allow(unused_imports)]
pub use diff::{
    Changed, DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, IdentityDiff, KvChange,
    MetricChange, Scope, ScopeDiff, ScopeDiffs, ScopeRocs, ScopeView, SectionChange, StringChange,
    SymbolChange, SymbolKind, TraitChange,
};

#[allow(unused_imports)]
pub(crate) use ml_features::{
    CallPatternMetrics, ControlFlowMetrics, DecodedValue, EmbeddedConstant, FunctionSignature,
    NestingMetrics,
};

#[allow(unused_imports)]
pub(crate) use code_structure::{
    BinaryAnomaly, BinaryProperties, GoIdioms, JavaScriptIdioms, LinkingInfo, SecurityFeatures,
    ShellIdioms, SourceCodeMetrics,
};

#[allow(unused_imports)]
pub(crate) use scores::EncodedMetrics;

use std::path::PathBuf;

/// Configuration for file extraction (--extract-dir flag)
///
/// When configured, all analyzed files are written to disk for external tools
/// (radare2, objdump, trait-basher) to access. Files are organized as:
/// `<extract_dir>/<sha256[0:6]>/<relative_path>` preserving original structure.
///
/// For archives, the archive's SHA256 is used (via `archive_sha256`) so all
/// files from the same archive are grouped together in one directory.
#[derive(Debug, Clone)]
pub struct SampleExtractionConfig {
    /// Base directory for extracted files
    #[allow(dead_code)] // Used by binary target
    pub extract_dir: PathBuf,
    /// Optional archive SHA256 to use instead of individual file SHA256.
    /// When set, all extracted files use this hash for the directory,
    /// grouping archive members together.
    #[allow(dead_code)] // Used by binary target
    pub archive_sha256: Option<String>,
}

impl SampleExtractionConfig {
    /// Create a new extraction config
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub fn new(extract_dir: PathBuf) -> Self {
        Self {
            extract_dir,
            archive_sha256: None,
        }
    }

    /// Create a copy with the archive SHA256 set
    #[must_use]
    pub(crate) fn with_archive_sha256(&self, sha256: String) -> Self {
        Self {
            extract_dir: self.extract_dir.clone(),
            archive_sha256: Some(sha256),
        }
    }

    /// Extract file data, returning the path if successful.
    ///
    /// Files are written to `<extract_dir>/<sha256[0:6]>/<relative_path>` where:
    /// - `sha256[0:6]` is first 6 chars of `archive_sha256` if set, otherwise from the file content
    /// - `relative_path` preserves original structure (e.g., "inner/lib/file.py")
    ///
    /// For archive members like "archive.zip!!inner/lib/file.py", pass
    /// "inner/lib/file.py" as relative_path.
    ///
    /// For standalone files, pass just the basename (e.g., "script.py").
    ///
    /// Skips writing if file already exists with correct size (optimization for
    /// repeated scans with the same extract directory).
    pub(crate) fn extract(
        &self,
        file_sha256: &str,
        relative_path: &str,
        data: &[u8],
    ) -> Option<PathBuf> {
        // Use archive SHA256 if set, otherwise use the individual file's SHA256
        let sha256 = self.archive_sha256.as_deref().unwrap_or(file_sha256);

        // Build path: <extract_dir>/<short_sha>/<relative_path>
        // Use first 6 chars of SHA256 to keep paths shorter while avoiding collisions
        let short_sha = if sha256.len() >= 6 {
            &sha256[..6]
        } else {
            sha256
        };
        let sha_dir = self.extract_dir.join(short_sha);
        let full_path = sha_dir.join(relative_path);

        // Reject path traversal attempts — full_path must stay inside extract_dir.
        // This is defence-in-depth: archive entry names are already sanitized upstream,
        // but an absolute or ../-containing relative_path must never escape extract_dir.
        if !full_path.starts_with(&self.extract_dir) {
            tracing::warn!(
                "Rejecting extract_dir path traversal attempt: {}",
                full_path.display()
            );
            return None;
        }

        // Skip if file already exists with correct size (same sha256 + size = same content)
        if let Ok(metadata) = std::fs::metadata(&full_path)
            && metadata.len() == data.len() as u64
        {
            return Some(full_path);
        }

        // Create parent directories if needed
        if let Some(parent) = full_path.parent()
            && let Err(e) = std::fs::create_dir_all(parent)
        {
            tracing::warn!("Failed to create directory {:?}: {}", parent, e);
            return None;
        }

        if let Err(e) = std::fs::write(&full_path, data) {
            tracing::warn!("Failed to extract {}: {}", full_path.display(), e);
            return None;
        }

        Some(full_path)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod field_paths_test;
