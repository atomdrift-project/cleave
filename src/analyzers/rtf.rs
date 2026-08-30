//! RTF document analyzer.
//!
//! Parsing of the RTF structure (info group, fields, objects,
//! features) lives in `filefacts::formats::rtf`; this module is a
//! thin dispatcher that drives the capability mapper. The capability
//! mapper's dual-emission step merges filefacts's `rtf.*` kv subtree
//! into `report.values_tree` before trait evaluation runs.

use super::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// RTF document analyzer — dispatcher only.
#[derive(Debug)]
pub(crate) struct RtfAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
}

impl RtfAnalyzer {
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

    fn analyze_rtf(&self, file_path: &Path, data: &[u8]) -> AnalysisReport {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = hex::encode(hasher.finalize());

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "rtf".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };
        let mut report = AnalysisReport::new(target);
        report.metadata.tools_used.push("filefacts-rtf".to_string());
        // filefacts extracts the document's text, but nothing was carrying it
        // onto the report -- so `type: text` traits scoped to rtf evaluated
        // against an empty corpus and could never match.
        report.strings = crate::strings::strings_from_filefacts(file_path, data);
        let filefacts_ctx = crate::analysis_context::AnalysisContext::open(file_path, data).ok();
        self.capability_mapper
            .evaluate_and_merge_findings_with_precomputed(
                &mut report,
                data,
                crate::capabilities::AnalysisBorrow::with_filefacts(None, filefacts_ctx.as_ref()),
                None,
                None,
                None,
                None,
            );
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
        file_path
            .extension()
            .is_some_and(|ext| ext.to_string_lossy().eq_ignore_ascii_case("rtf"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_minimal_rtf_returns_report() {
        let analyzer = RtfAnalyzer::new();
        let data = b"{\\rtf1\\ansi\\ansicpg1252}";
        let report = analyzer.analyze_rtf(Path::new("/tmp/test.rtf"), data);
        assert_eq!(report.target.file_type, "rtf");
    }

    #[test]
    fn report_carries_the_documents_text() {
        // Every other analyzer sources its strings from filefacts; this one
        // did not, so `type: text` rules scoped to rtf were evaluated against
        // an empty corpus and could never match -- silently, because an
        // absent corpus reads the same as a corpus with no hit in it.
        let analyzer = RtfAnalyzer::new();
        let data = b"{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0\\fnil Arial;}}\
\\pard\\f0\\fs22 This is DHL courier Delivery Company\\par\n}";
        let report = analyzer.analyze_rtf(Path::new("/tmp/letter.rtf"), data);
        assert!(!report.strings.is_empty(), "no text extracted from an RTF");
        assert!(
            report
                .strings
                .iter()
                .any(|s| s.value.contains("DHL courier")),
            "document text missing: {:?}",
            report.strings.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
    }

    #[test]
    fn long_single_line_rtf_still_yields_text() {
        // These documents run to megabytes on one line. That shape is what
        // made the gap invisible: the few strings that did come back were
        // truncated well before anything worth matching.
        let mut data = b"{\\rtf1\\ansi{\\object\\objdata ".to_vec();
        data.extend(std::iter::repeat_n(b'A', 300_000));
        data.extend_from_slice(b"}\\objupdate}");
        let report = RtfAnalyzer::new().analyze_rtf(Path::new("/tmp/big.rtf"), &data);
        assert!(!report.strings.is_empty(), "no text from a one-line RTF");
    }
}
