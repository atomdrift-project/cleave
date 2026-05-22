//! VS Code / Visual Studio extension manifest analyzer.
//!
//! Parsing (Identity / DisplayName / Properties / Dependencies /
//! Assets) lives in `filefacts::formats::vsix`; this module is a thin
//! dispatcher that drives the capability mapper. The dual-emission
//! step in `evaluate_and_merge_findings` merges filefacts's `vsix.*`
//! kv subtree into `report.values_tree` before trait evaluation runs.

use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct VsixManifestAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
}

impl VsixManifestAnalyzer {
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

    fn analyze_manifest(&self, file_path: &Path, data: &[u8]) -> AnalysisReport {
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "vsix_manifest".to_string(),
            size_bytes: data.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(data),
            architectures: None,
        };
        let mut report = AnalysisReport::new(target);
        report
            .metadata
            .tools_used
            .push("filefacts-vsix".to_string());
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, data, None, None);
        report
    }
}

impl Default for VsixManifestAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for VsixManifestAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        Ok(self.analyze_manifest(input.path, input.data))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read .vsixmanifest file")?;
        Ok(self.analyze_manifest(file_path, &bytes))
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path
            .file_name()
            .map(|n| {
                n.to_string_lossy()
                    .to_lowercase()
                    .ends_with(".vsixmanifest")
            })
            .unwrap_or(false)
    }
}
