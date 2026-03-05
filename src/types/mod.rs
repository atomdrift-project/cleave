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

pub(crate) fn is_zero_f64(n: &f64) -> bool {
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
pub(crate) mod binary_metrics;
pub(crate) mod code_structure;
pub(crate) mod container_metrics;
pub(crate) mod core;
pub(crate) mod diff;
pub(crate) mod field_paths;
pub(crate) mod file_analysis;
pub(crate) mod language_metrics;
pub(crate) mod ml_features;
pub(crate) mod paths_env;
pub(crate) mod png_metrics;
pub(crate) mod scores;
pub(crate) mod text_metrics;
pub(crate) mod traits_findings;

// Re-export all public types to maintain API compatibility
// These re-exports are part of the public library API even if not used directly in the binary
#[allow(unused_imports)]
pub use core::{AnalysisReport, ArchiveEntry, Criticality, ExtractedPayload, TargetInfo};

#[allow(unused_imports)]
pub(crate) use file_analysis::{
    encode_archive_path, encode_decoded_path, FileAnalysis, FindingCounts, ReportSummary,
    ARCHIVE_DELIMITER, ENCODING_DELIMITER,
};

pub(crate) use traits_findings::{deduplicate_evidence, MAX_EVIDENCE_PER_TRAIT};
#[allow(unused_imports)]
pub use traits_findings::{Evidence, Finding, FindingKind, StructuralFeature, Trait, TraitKind};

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

pub(crate) use diff::{
    DiffCounts, DiffReport, FileChanges, FileDiff, FileRenameInfo, FullDiffReport, MetricsDelta,
    ModifiedFileAnalysis,
};

#[allow(unused_imports)]
pub(crate) use ml_features::{
    CallPatternMetrics, ControlFlowMetrics, DecodedValue, EmbeddedConstant, FunctionProperties,
    FunctionSignature, InstructionAnalysis, InstructionCategories, NestingMetrics,
};

#[allow(unused_imports)]
pub(crate) use code_structure::{
    BinaryAnomaly, BinaryProperties, CodeMetrics, GoIdioms, JavaScriptIdioms, LinkingInfo,
    SecurityFeatures, ShellIdioms, SourceCodeMetrics,
};

pub(crate) use text_metrics::{
    CommentMetrics, FunctionMetrics, IdentifierMetrics, ImportMetrics, StringMetrics, TextMetrics,
};

#[allow(unused_imports)]
pub(crate) use language_metrics::{
    GoMetrics, JavaScriptMetrics, PythonMetrics, RustMetrics, ShellMetrics,
};

pub(crate) use binary_metrics::{BinaryMetrics, MachoMetrics};
pub(crate) use png_metrics::PngMetrics;

pub(crate) use scores::Metrics;

use std::path::PathBuf;

/// Configuration for file extraction (--extract-dir flag)
///
/// When configured, all analyzed files are written to disk for external tools
/// (radare2, objdump, trait-basher) to access. Files are organized as:
/// `<extract_dir>/<sha256[0:6]>/<relative_path>` preserving original structure.
///
/// For archives, the archive's SHA256 is used (via `archive_sha256`) so all
/// files from the same archive are grouped together in one directory.
#[allow(dead_code)] // Used by binary target
#[derive(Debug, Clone)]
pub(crate) struct SampleExtractionConfig {
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
    pub(crate) fn new(extract_dir: PathBuf) -> Self {
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

        // Skip if file already exists with correct size (same sha256 + size = same content)
        if let Ok(metadata) = std::fs::metadata(&full_path) {
            if metadata.len() == data.len() as u64 {
                return Some(full_path);
            }
        }

        // Create parent directories if needed
        if let Some(parent) = full_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                tracing::warn!("Failed to create directory {:?}: {}", parent, e);
                return None;
            }
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
