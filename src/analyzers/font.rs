//! Font analyzer entry point.
//!
//! All font parsing (signature classification, table-directory walk,
//! coverage accounting for stowaway bytes) lives in filefacts. This module
//! is a thin shell that runs the trait engine — filefacts's dual-emission
//! step in `evaluate_and_merge_findings` populates `report.filefacts_metrics`
//! with every `font.*` / `file.entropy` field that the trait rules consume.

use super::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::strings::StringExtractor;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// Font analyzer — defers extraction to filefacts and runs trait
/// evaluation against the merged metric set.
#[derive(Debug)]
pub(crate) struct FontAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    string_extractor: StringExtractor,
}

impl FontAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
            string_extractor: StringExtractor::new(),
        }
    }

    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(mapper);
        self
    }

    #[must_use]
    pub(crate) fn with_capability_mapper_arc(mut self, mapper: Arc<CapabilityMapper>) -> Self {
        self.capability_mapper = mapper;
        self
    }

    fn analyze_font(
        &self,
        file_path: &Path,
        data: &[u8],
        stng_strings: Option<&[stng::ExtractedString]>,
        source_ctx: Option<&crate::analysis_context::AnalysisContext<'_>>,
    ) -> AnalysisReport {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = hex::encode(hasher.finalize());

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "font".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        report.metadata.tools_used.push("font-analyzer".to_string());

        if let Some(strings) = stng_strings {
            report.strings = self.string_extractor.convert_stng_strings(strings);
        }

        // Filefacts's dual-emission inside `evaluate_and_merge_findings`
        // populates every `font.*` / `file.entropy` metric onto
        // `report.filefacts_metrics` for the trait engine.
        // `source_ctx` is resolved by the caller (threaded or freshly opened).
        self.capability_mapper
            .evaluate_and_merge_findings_with_precomputed(
                &mut report,
                data,
                crate::capabilities::AnalysisBorrow::with_filefacts(None, source_ctx),
                None,
                None,
                None,
                None,
            );

        report
    }
}

impl Default for FontAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for FontAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Reuse the threaded context, else open one on the same `input.data`.
        let fallback = input.open_ctx_fallback();
        let source_ctx = input.parsed_ctx.as_ref().or(fallback.as_ref());
        Ok(self.analyze_font(input.path, input.data, Some(input.strings), source_ctx))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        let ctx = crate::analysis_context::AnalysisContext::open(file_path, &data).ok();
        Ok(self.analyze_font(file_path, &data, None, ctx.as_ref()))
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path.extension().is_some_and(|ext| {
            matches!(
                ext.to_string_lossy().to_lowercase().as_str(),
                "ttf" | "otf" | "ttc" | "otc" | "woff" | "woff2" | "eot"
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_every_font_container_extension() {
        let analyzer = FontAnalyzer::new();
        for name in [
            "/tmp/x.ttf",
            "/tmp/x.otf",
            "/tmp/x.ttc",
            "/tmp/x.otc",
            "/tmp/x.woff",
            "/tmp/x.woff2",
            "/tmp/x.eot",
            "/tmp/x.WOFF2",
        ] {
            assert!(analyzer.can_analyze(Path::new(name)), "{name}");
        }
    }

    /// The masquerade path routes on the *extension*, so neighbouring asset
    /// types must not be swept in — a `.png` is the PNG analyzer's job.
    #[test]
    fn ignores_non_font_extensions() {
        let analyzer = FontAnalyzer::new();
        for name in ["/tmp/x.png", "/tmp/x.jpg", "/tmp/x.js", "/tmp/x"] {
            assert!(!analyzer.can_analyze(Path::new(name)), "{name}");
        }
    }
}
