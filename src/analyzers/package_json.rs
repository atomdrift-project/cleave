//! package.json analyzer for npm packages.
//!
//! filefacts reads the manifest -- strictly, then with comments and trailing
//! commas forgiven, then by salvage -- and records what it says: the parse
//! stage, dependencies as imports, lifecycle scripts, and name, dependency
//! and script judgements. YAML traits read those facts. This analyzer
//! evaluates the traits and analyzes JavaScript appended past the manifest
//! object as an embedded layer.
use crate::analysis_context::AnalysisContext;
use crate::analyzers::unified::UnifiedSourceAnalyzer;
use crate::analyzers::{AnalysisInput, Analyzer, FileType};
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// npm package.json analyzer for detecting supply chain attacks
#[derive(Debug)]
pub(crate) struct PackageJsonAnalyzer {
    engine: crate::Engine,
}

impl PackageJsonAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            engine: crate::Engine::empty(),
        }
    }

    /// Analyze under `engine`: its rules and settings.
    #[must_use]
    pub(crate) fn with_engine(mut self, engine: crate::Engine) -> Self {
        self.engine = engine;
        self
    }

    fn analyze_package(&self, file_path: &Path, data: &[u8]) -> AnalysisReport {
        let start = std::time::Instant::now();
        let mut report = AnalysisReport::new(TargetInfo {
            path: file_path.display().to_string(),
            file_type: "package.json".to_string(),
            size_bytes: data.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(data),
            architectures: None,
        });
        let ctx = AnalysisContext::open(file_path, data);
        report.imports = ctx.imports_from_filefacts();
        if let Some(offset) = trailing_code_offset(&ctx) {
            self.analyze_trailing_code(file_path, data, offset, &mut report);
        }
        self.engine.evaluate_and_merge_findings_with_precomputed(
            &mut report,
            data,
            crate::capabilities::AnalysisBorrow::with_filefacts(None, Some(&ctx)),
            None,
            None,
            None,
            None,
        );
        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["filefacts".to_string()];
        report
    }

    /// Analyze JavaScript appended past the manifest object at `offset` as
    /// an embedded layer, with the full source pipeline: AST, capabilities,
    /// YARA.
    fn analyze_trailing_code(
        &self,
        file_path: &Path,
        data: &[u8],
        offset: usize,
        report: &mut AnalysisReport,
    ) {
        let Some(trailer) = data.get(offset..) else {
            return;
        };
        let Some(analyzer) = UnifiedSourceAnalyzer::for_file_type(&FileType::JavaScript) else {
            return;
        };
        let trailer = String::from_utf8_lossy(trailer);
        let virtual_path = format!("{}##trailing@{offset:#x}", file_path.display());
        let js_report = analyzer
            .with_engine(self.engine.clone())
            .without_embedded_detection()
            .analyze_source(Path::new(&virtual_path), trailer.trim());
        let (mut layer, _, _) = js_report.into_file_analysis(0, &self.engine);
        layer.path = virtual_path;
        layer.depth = 1;
        layer.compute_summary();
        report.files.push(layer);
    }
}

/// Where JavaScript appended past the manifest object begins, when
/// filefacts found code there.
fn trailing_code_offset(ctx: &AnalysisContext<'_>) -> Option<usize> {
    ctx.parsed
        .metrics()
        .get("npm.manifest.trailing_code")
        .filter(|&present| present > 0.0)?;
    ctx.parsed
        .values()
        .get("npm.manifest.trailing_offset")?
        .as_u64()
        .and_then(|offset| usize::try_from(offset).ok())
}

impl Default for PackageJsonAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PackageJsonAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        Ok(self.analyze_package(input.path, input.data))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes =
            fs::read(file_path).context(format!("Failed to read file: {}", file_path.display()))?;
        Ok(self.analyze_package(file_path, &bytes))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
