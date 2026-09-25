//! AppleScript analyzer.
//!
//! Analyzes AppleScript files for macOS-specific threats.

use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::strings::StringExtractor;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;
use std::fs;
use std::path::Path;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct AppleScriptAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    string_extractor: StringExtractor,
}

impl AppleScriptAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
            string_extractor: StringExtractor::new(),
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

    /// Add parsed events and recovered strings to the report and embedded scan.
    fn add_scpt_facts(
        ctx: &crate::analysis_context::AnalysisContext<'_>,
        report: &mut AnalysisReport,
    ) {
        if !scpt::is_scpt(ctx.content) {
            return;
        }
        report.imports = ctx.imports_from_filefacts();
        report.filefacts = Some(crate::types::FilefactsView::from_ctx(ctx));
        report
            .strings
            .extend(crate::strings::scpt_literal_strings(ctx));
    }
}

impl Default for AppleScriptAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for AppleScriptAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        let target = TargetInfo {
            path: input.path.display().to_string(),
            file_type: "applescript".to_string(),
            size_bytes: input.data.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(input.data),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Reuse the threaded context, else open one on the same `input.data`.
        let fallback = input.open_ctx_fallback();
        let filefacts_ctx = input.parsed_ctx.as_ref().or(fallback.as_ref());

        // Use pre-extracted strings if available, otherwise source them from
        // filefacts (the string-extraction authority).
        if !input.strings.is_empty() {
            report.strings = self.string_extractor.convert_stng_strings(input.strings);
        } else if let Some(ctx) = filefacts_ctx {
            let text = ctx.parsed.text();
            report.strings = self
                .string_extractor
                .convert_stng_iter(text.iter(), text.len());
        }
        if let Some(ctx) = filefacts_ctx {
            Self::add_scpt_facts(ctx, &mut report);
        }

        // Analyze embedded code in strings
        let (encoded_layers, plain_findings) =
            crate::analyzers::embedded_code_detector::process_all_strings(
                &input.path.display().to_string(),
                &report.strings,
                &self.capability_mapper,
                0,
                Some(&crate::FileType::AppleScript),
                input.cancellation.as_deref(),
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);

        // Evaluate all rules (atomic + composite) and merge into report
        self.capability_mapper
            .evaluate_and_merge_findings_with_precomputed(
                &mut report,
                input.data,
                crate::capabilities::AnalysisBorrow::with_filefacts(None, filefacts_ctx),
                None,
                None,
                None,
                None,
            );

        Ok(report)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Ok(metadata) = fs::metadata(file_path)
            && metadata.is_file()
        {
            // Check for compiled AppleScript magic bytes "Fasd" or file extension
            if let Ok(mut file) = fs::File::open(file_path) {
                use std::io::Read;
                let mut magic = [0u8; 4];
                if file.read_exact(&mut magic).is_ok() && &magic == b"Fasd" {
                    return true;
                }
            }

            if let Some(ext) = file_path.extension() {
                return ext == "scpt";
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    #[test]
    fn scpt_base64_facts_use_shared_literal_rows_once() {
        let bytes = include_bytes!("../../tests/fixtures/scpt-base64.scpt");
        let ctx = crate::analysis_context::AnalysisContext::open(Path::new("base64.scpt"), bytes)
            .unwrap();
        let mut report = AnalysisReport::new(TargetInfo {
            path: "base64.scpt".into(),
            file_type: "applescript".into(),
            size_bytes: bytes.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        let text = ctx.parsed.text();
        report.strings = StringExtractor::new().convert_stng_iter(text.iter(), text.len());
        AppleScriptAnalyzer::add_scpt_facts(&ctx, &mut report);
        let rows: Vec<_> = report
            .strings
            .iter()
            .filter(|s| {
                s.section.as_deref() == Some("literal")
                    && s.value == r"printf '%s\n' 'SCPT_BASE64_OK'"
            })
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].encoding_chain, ["scpt", "base64"]);
        assert_eq!(
            report
                .strings
                .iter()
                .filter(|s| s.section.as_deref() == Some("literal"))
                .count(),
            ctx.parsed.literals().iter().count()
        );
    }

    #[test]
    fn compiled_facts_reach_rule_inputs() {
        let bytes = include_bytes!("../../crates/scpt/tests/fixtures/shell_script.scpt");
        let ctx =
            crate::analysis_context::AnalysisContext::open(Path::new("shell_script.scpt"), bytes)
                .unwrap();
        let mut report = AnalysisReport::new(TargetInfo {
            path: "shell_script.scpt".into(),
            file_type: "applescript".into(),
            size_bytes: bytes.len() as u64,
            sha256: String::new(),
            architectures: None,
        });
        AppleScriptAnalyzer::add_scpt_facts(&ctx, &mut report);
        assert!(
            report
                .strings
                .iter()
                .any(|s| s.value == "whoami" && s.section.as_deref() == Some("literal"))
        );
        assert!(
            report
                .filefacts
                .as_ref()
                .unwrap()
                .symbols
                .iter()
                .any(|s| matches!(s,
                    filefacts::Symbol::Call { target: Some(target), args, .. }
                    if target == "syso.exec" && matches!(args.first(),
                        Some(filefacts::Arg::String { value }) if value == "whoami")
                ))
        );
    }
}
