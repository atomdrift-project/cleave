//! PDF analyzer entry point.
//!
//! All PDF metric extraction (lenient byte-scan parser, stream
//! anomaly detection, form-field overlap analysis, action/embedded
//! file/info dict surfacing) lives in expose. This module is now a
//! thin shell that runs the trait engine — expose's dual-emission
//! step in `evaluate_and_merge_findings` populates
//! `report.expose_metrics` and `report.kv_tree` with every `pdf.*`
//! field that the trait rules consume.

use super::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// PDF analyzer — defers extraction to expose and runs trait
/// evaluation against the merged metric set.
#[derive(Debug)]
pub(crate) struct PdfAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
}

impl PdfAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
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

    fn analyze_pdf(&self, file_path: &Path, data: &[u8]) -> AnalysisReport {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = format!("{:x}", hasher.finalize());

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "pdf".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };
        let mut report = AnalysisReport::new(target);
        report.metadata.tools_used.push("pdf-analyzer".to_string());

        // Expose's dual-emission inside `evaluate_and_merge_findings`
        // populates every `pdf.*` metric onto `report.expose_metrics`
        // and merges the structured kv view onto `report.kv_tree`
        // for the trait engine.
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, data, None, None);

        report
    }
}

impl Default for PdfAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PdfAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        Ok(self.analyze_pdf(input.path, input.data))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        Ok(self.analyze_pdf(file_path, &data))
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("pdf"))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_analyze_pdf_extension() {
        let analyzer = PdfAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("/tmp/test.pdf")));
        assert!(analyzer.can_analyze(Path::new("/tmp/test.PDF")));
        assert!(!analyzer.can_analyze(Path::new("/tmp/test.png")));
    }
}
