//! JPEG analyzer entry point.
//!
//! All JPEG metric extraction (marker walk, EXIF parsing, pixel-stat
//! decode for steganography signals) lives in filefacts. This module is
//! now a thin shell that runs the trait engine — filefacts's
//! dual-emission step in `evaluate_and_merge_findings` populates
//! `report.filefacts_metrics` with every `jpeg.*` / `image.*` /
//! `binary.overall_entropy` field that the trait rules consume.

use super::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::strings::StringExtractor;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// JPEG analyzer — defers extraction to filefacts and runs trait
/// evaluation against the merged metric set.
#[derive(Debug)]
pub(crate) struct JpegAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    string_extractor: StringExtractor,
}

impl JpegAnalyzer {
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

    fn analyze_jpeg(
        &self,
        file_path: &Path,
        data: &[u8],
        stng_strings: Option<&[stng::ExtractedString]>,
        source_ctx: Option<&crate::analysis_context::AnalysisContext<'_>>,
    ) -> AnalysisReport {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = format!("{:x}", hasher.finalize());

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "jpeg".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        report.metadata.tools_used.push("jpeg-analyzer".to_string());

        if let Some(strings) = stng_strings {
            report.strings = self.string_extractor.convert_stng_strings(strings);
        }

        // Filefacts's dual-emission inside `evaluate_and_merge_findings`
        // populates every `jpeg.*` / `image.*` / `binary.overall_entropy`
        // metric onto `report.filefacts_metrics` for the trait engine.
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

impl Default for JpegAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for JpegAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Reuse the threaded context, else open one on `input.data` so both
        // branches yield a context over the same bytes (matching lifetimes).
        let owned_ctx;
        let source_ctx = match input.parsed_ctx.as_ref() {
            Some(ctx) => Some(ctx),
            None => {
                owned_ctx =
                    crate::analysis_context::AnalysisContext::open(input.path, input.data).ok();
                owned_ctx.as_ref()
            }
        };
        Ok(self.analyze_jpeg(input.path, input.data, Some(input.strings), source_ctx))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        let ctx = crate::analysis_context::AnalysisContext::open(file_path, &data).ok();
        Ok(self.analyze_jpeg(file_path, &data, None, ctx.as_ref()))
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            matches!(
                ext.to_string_lossy().to_lowercase().as_str(),
                "jpg" | "jpeg"
            )
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_can_analyze() {
        let analyzer = JpegAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("/tmp/test.jpg")));
        assert!(analyzer.can_analyze(Path::new("/tmp/test.jpeg")));
        assert!(analyzer.can_analyze(Path::new("/tmp/test.JPG")));
        assert!(!analyzer.can_analyze(Path::new("/tmp/test.png")));
    }
}
