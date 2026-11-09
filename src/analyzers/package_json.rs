//! package.json analyzer for npm packages.
//!
//! filefacts reads the manifest -- strictly, then with comments and trailing
//! commas forgiven, then by salvage -- and records what it says: the parse
//! stage, dependencies as imports, lifecycle scripts, and name, dependency
//! and script judgements. YAML traits read those facts. This analyzer
//! evaluates the traits and analyzes JavaScript appended past the manifest
//! object as an embedded layer.
use crate::analysis_context::AnalysisContext;
use crate::analyzers::{AnalysisInput, Analyzer};
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
        // Code appended past the manifest object is an embedded source.
        crate::analyzers::embedded_layers::attach(
            &mut report,
            &file_path.display().to_string(),
            &ctx,
            &self.engine,
        );
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
