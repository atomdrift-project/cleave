//! Media-container analyzer entry point.
//!
//! Serves every passive container that is not a font or a raster image with
//! its own analyzer: WAV, AIFF, MP3, MP4/M4A/MOV, ICO/CUR, GIF, BMP and WebP.
//! All parsing (structure walk, coverage accounting, payload classification of
//! the unaccounted-for bytes) lives in filefacts; this module is a thin shell
//! that runs the trait engine over the resulting `media.*` facts.

use super::{AnalysisInput, Analyzer};
use crate::strings::StringExtractor;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;

/// Media analyzer — defers extraction to filefacts and runs trait
/// evaluation against the merged metric set.
#[derive(Debug)]
pub(crate) struct MediaAnalyzer {
    engine: crate::Engine,
    string_extractor: StringExtractor,
}

impl MediaAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            engine: crate::Engine::empty(),
            string_extractor: StringExtractor::new(),
        }
    }

    #[must_use]
    pub(crate) fn with_engine(mut self, engine: crate::Engine) -> Self {
        self.engine = engine;
        self
    }

    fn analyze_media(
        &self,
        file_path: &Path,
        data: &[u8],
        label: &str,
        stng_strings: Option<&[stng::ExtractedString]>,
        source_ctx: Option<&crate::analysis_context::AnalysisContext<'_>>,
    ) -> AnalysisReport {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = hex::encode(hasher.finalize());

        let target = TargetInfo {
            path: file_path.display().to_string(),
            // The concrete container, not the generic bucket: one analyzer
            // serves eight formats and a report that says "media" tells a
            // responder less than "ico" does.
            file_type: label.to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        report
            .metadata
            .tools_used
            .push("media-analyzer".to_string());

        if let Some(strings) = stng_strings {
            report.strings = self.string_extractor.convert_stng_strings(strings);
        }

        // Filefacts's dual-emission inside `evaluate_and_merge_findings`
        // populates every `media.*` / `file.entropy` metric onto
        // `report.filefacts_metrics` for the trait engine.
        // `source_ctx` is resolved by the caller (threaded or freshly opened).
        self.engine.evaluate_and_merge_findings_with_precomputed(
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

impl Default for MediaAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for MediaAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Reuse the threaded context, else open one on the same `input.data`.
        let fallback = input.open_ctx_fallback();
        let source_ctx = input.parsed_ctx.or(fallback.as_ref());
        Ok(self.analyze_media(
            input.path,
            input.data,
            input.file_type.label(),
            Some(input.strings),
            source_ctx,
        ))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        let ctx = Some(crate::analysis_context::AnalysisContext::open(
            file_path, &data,
        ));
        // Standalone entry point: identify the container from the bytes, the
        // same detection a scan runs, never from the extension.
        let file_type = crate::analyzers::detect_file_type_from_data(file_path, &data);
        Ok(self.analyze_media(file_path, &data, file_type.label(), None, ctx.as_ref()))
    }
}
