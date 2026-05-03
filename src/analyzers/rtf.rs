//! RTF (Rich Text Format) document analyzer for cleave
//!
//! This analyzer uses the standalone RTF parser to perform structural analysis
//! on RTF documents. Pattern detection (OLE objects, exploits, etc.) is handled
//! by YAML trait rules in the capabilities system for maintainability and
//! flexibility.

use super::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

use crate::rtf::RtfParser;

/// RTF document analyzer
#[derive(Debug)]
pub(crate) struct RtfAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    rtf_parser: RtfParser,
}

impl RtfAnalyzer {
    /// Create a new RTF analyzer with an empty capability mapper
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
            rtf_parser: RtfParser::new(),
        }
    }

    /// Create analyzer with pre-existing capability mapper (wraps in Arc)
    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(mapper);
        self
    }

    /// Create analyzer with shared capability mapper (avoids cloning)
    #[must_use]
    pub(crate) fn with_capability_mapper_arc(mut self, mapper: Arc<CapabilityMapper>) -> Self {
        self.capability_mapper = mapper;
        self
    }

    fn analyze_rtf(&self, file_path: &Path, data: &[u8]) -> AnalysisReport {
        // Calculate hash
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = format!("{:x}", hasher.finalize());

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "rtf".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Parse RTF document for structural analysis. Stash the
        // synthesized kv tree on `report.kv_tree` BEFORE the
        // capability mapper runs so `type: kv` traits resolve
        // (see `rtf::rtf_kv` for the schema — `info.*`,
        // `info_numeric.*`, `objects[]`, `fields[]`, `header.*`,
        // `shape.*`).
        match self.rtf_parser.parse(data) {
            Ok(rtf_doc) => {
                report.metadata.tools_used.push("rtf-parser".to_string());
                let kv = crate::rtf::rtf_kv::build_rtf_kv(&rtf_doc);
                if kv.as_object().is_some_and(|m| !m.is_empty()) {
                    report.kv_tree = Some(Box::new(kv));
                }
            }
            Err(_e) => {
                // Parser failures still let YAML traits run against
                // the raw content; the kv tree is just unavailable.
                report.metadata.tools_used.push("rtf-parser".to_string());
            }
        }

        // All pattern detection is delegated to capability mapper
        // which evaluates YAML traits against the file content
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, data, None, None);

        report
    }
}

impl Default for RtfAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for RtfAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        Ok(self.analyze_rtf(input.path, input.data))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        Ok(self.analyze_rtf(file_path, &data))
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            ext.to_string_lossy().to_lowercase() == "rtf"
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_rtf_analysis() {
        let analyzer = RtfAnalyzer::new();
        let data = b"{\\rtf1\\ansi\\ansicpg1252}";
        let path = Path::new("/tmp/test.rtf");

        let report = analyzer.analyze_rtf(path, data);
        assert_eq!(report.target.file_type, "rtf");
        assert_eq!(report.metadata.tools_used, vec!["rtf-parser"]);
    }
}
