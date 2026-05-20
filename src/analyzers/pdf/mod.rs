//! PDF document analyzer (lenient byte-scan extractor).
//!
//! cleave handles PDF detection through a thin byte-scan that
//! recovers structural and action-surface signals without relying on
//! a strict PDF parser — malicious PDFs deliberately break xref
//! tables, encryption, and linearization to evade strict parsers.
//! See `parser.rs` for the design rationale.
//!
//! The analyzer flow mirrors office and RTF:
//! 1. Run [`parser::parse`] over the file bytes.
//! 2. Build the kv tree via [`pdf_kv::build_pdf_kv`] and stash it on
//!    `report.kv_tree` so `type: kv` traits resolve.
//! 3. Hand off to the capability mapper for trait-driven detection.

pub(crate) mod parser;
pub(crate) mod pdf_kv;
pub(crate) mod types;

use crate::analyzers::input::AnalysisInput;
use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

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
        report.metadata.tools_used.push("pdf-parser".to_string());

        // Lenient parse → kv tree. Documents without a `%PDF-` header
        // produce an empty parse result; we leave `kv_tree` unset in
        // that case so `cleave kv` falls through to the manifest path.
        let parsed = parser::parse(data);
        if !parsed.headers.is_empty() {
            let kv = pdf_kv::build_pdf_kv(&parsed);
            if kv.as_object().is_some_and(|m| !m.is_empty()) {
                report.kv_tree = Some(Box::new(kv));
            }
            let metrics = report.expose_metrics.get_or_insert_with(Default::default);
            pdf_kv::populate_pdf_metrics(&parsed, metrics);
        }

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
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn analyze_minimal_pdf_populates_kv_tree() {
        let pdf = b"%PDF-1.4\n\
1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n\
2 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert\\(1\\)) >>\nendobj\n\
3 0 obj\n<< /Author (Test) >>\nendobj\n\
trailer\n<< /Root 1 0 R /Info 3 0 R >>\nstartxref\n0\n%%EOF\n";
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.pdf");
        std::fs::write(&path, pdf).unwrap();
        let analyzer = PdfAnalyzer::new();
        let report = analyzer.analyze(&path).unwrap();
        let kv = report.kv_tree.as_ref().expect("kv tree populated");
        assert_eq!(kv["info"]["author"], "Test");
        assert_eq!(kv["catalog"]["has_openaction"], true);
    }

    #[test]
    fn analyze_non_pdf_leaves_kv_tree_unset() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("not.pdf");
        std::fs::write(&path, b"random bytes\n").unwrap();
        let analyzer = PdfAnalyzer::new();
        let report = analyzer.analyze(&path).unwrap();
        assert!(report.kv_tree.is_none());
    }
}
