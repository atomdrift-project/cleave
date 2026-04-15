//! Java bytecode (.class) analyzer.

use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, Evidence, StructuralFeature, TargetInfo};
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;

mod capabilities;
mod helpers;
mod parsing;
mod tests;

#[derive(Debug)]
pub(crate) struct JavaClassAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
}

impl JavaClassAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
        }
    }

    /// Create analyzer with pre-existing capability mapper (wraps in Arc)
    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(capability_mapper);
        self
    }

    /// Create analyzer with shared capability mapper (avoids cloning)
    #[must_use]
    pub(crate) fn with_capability_mapper_arc(
        mut self,
        capability_mapper: Arc<CapabilityMapper>,
    ) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    /// Analyze class file structure only, without trait evaluation.
    /// Use this when you want to run YARA in parallel and evaluate traits after.
    pub(crate) fn analyze_structural(
        &self,
        file_path: &Path,
        data: &[u8],
        precomputed_sha256: Option<String>,
    ) -> Result<AnalysisReport> {
        let class_info = self.parse_class_file(data)?;

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "java_class".to_string(),
            size_bytes: data.len() as u64,
            sha256: precomputed_sha256
                .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(data)),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        report.structure.push(StructuralFeature {
            id: "source/language/java".to_string(),
            desc: "Java bytecode".to_string(),
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "class-parser".to_string(),
                value: "CAFEBABE".to_string(),
                location: Some("0x0".to_string()),
                ..Default::default()
            }],
        });

        self.detect_capabilities(&class_info, &mut report);

        Ok(report)
    }
}

impl Analyzer for JavaClassAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();
        let mut report = self.analyze_structural(input.path, input.data, input.sha256.clone())?;

        // Evaluate all rules (atomic + composite) and merge into report
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, input.data, None, None);

        let elapsed = start.elapsed().as_millis() as u64;
        report.metadata.analysis_duration_ms = elapsed;

        Ok(report)
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        let start = std::time::Instant::now();
        let mut report = self.analyze_structural(file_path, &data, None)?;

        // Evaluate all rules (atomic + composite) and merge into report
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, &data, None, None);

        let elapsed = start.elapsed().as_millis() as u64;
        report.metadata.analysis_duration_ms = elapsed;

        Ok(report)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            ext == "class"
        } else {
            false
        }
    }
}

impl Default for JavaClassAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
