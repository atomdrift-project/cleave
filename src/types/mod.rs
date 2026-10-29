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

pub(crate) fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

// Module declarations
mod analysis_gaps;
pub use analysis_gaps::{AnalysisGap, AnalysisGaps};
pub mod binary;
pub(crate) mod code_structure;
pub mod compact;
pub(crate) mod core;
pub(crate) mod diff;
pub mod field_paths;
pub(crate) mod file_analysis;
pub mod filefacts_view;
pub mod istr;
// Retired with the cleave→filefacts migration (now sourced from filefacts's
// flat metric map under their respective namespaces — `file.*`,
// `image.*`/`jpeg.*`/`png.*`, `lnk.*`, `pdf.*`, `text.*`/
// `identifiers.*`/`strings.*`/`comments.*`/`functions.*`/`imports.*`):
// file_metrics, image_metrics, jpeg_metrics, png_metrics, lnk_metrics,
// pdf_metrics, text_metrics, language_metrics.
pub(crate) mod byte_text;
pub(crate) mod ml_features;
pub(crate) mod office_metrics;
pub(crate) mod paths_env;
pub(crate) mod reference_graph;
pub(crate) mod scores;
pub(crate) mod traits_findings;
pub(crate) mod z85;

// Re-export all public types to maintain API compatibility
// These re-exports are part of the public library API even if not used directly in the binary
pub use compact::{
    CompactDep, CompactExport, CompactFacts, CompactFile, CompactFunction, CompactImport,
    CompactReport, CompactSection, CompactTrait, Facts, RoundedMetrics, compact_from_files,
};
#[allow(unused_imports)]
pub use core::{
    AnalysisReport, ArchiveEntry, Criticality, ExtractedPayload, MetricsExt, TargetInfo,
    flatten_into_metrics, kv_set_path,
};
#[allow(unused_imports)]
pub use istr::Istr;

pub use filefacts_view::FilefactsView;

#[allow(unused_imports)]
pub(crate) use file_analysis::{
    ARCHIVE_DELIMITER, ENCODING_DELIMITER, FindingCounts, ReportSummary, encode_archive_path,
    encode_decoded_path,
};
pub use file_analysis::{FileAnalysis, Rel, Role};

#[allow(unused_imports)]
pub use traits_findings::{
    ContextLine, Evidence, Finding, FindingKind, Note, StructuralFeature, Suppression,
    SuppressionKind, SuppressionLeg, Trait, TraitKind,
};
pub(crate) use traits_findings::{
    MAX_EVIDENCE_PER_TRAIT, MIN_RECORDED_SUPPRESSION, SuppressionSink, deduplicate_evidence,
    truncate_evidence_value,
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

#[cfg(test)]
mod tests;

#[cfg(test)]
mod field_paths_test;
