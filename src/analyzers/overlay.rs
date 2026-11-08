//! Archives appended to a program as its overlay.
//!
//! Many self-extracting archives work by appending a ZIP/7z/RAR archive to a
//! PE/ELF/Mach-O stub. filefacts names the archive an overlay starts with
//! (`binary.overlay_archive`); this module unpacks and analyzes it.

use crate::analyzers::Analyzer;
use crate::analyzers::archive::{ArchiveAnalyzer, ArchiveAnalyzerConfig};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind, TargetInfo};
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use std::sync::Arc;

/// Unpack and analyze the `archive_type` archive (as filefacts named it)
/// that `overlay_data`, appended to `binary_path`, starts with.
pub(crate) fn analyze_overlay(
    overlay_data: &[u8],
    archive_type: &str,
    binary_path: &str,
    engine: &crate::Engine,
    yara_engine: Option<Arc<YaraEngine>>,
    archive_config: Option<&ArchiveAnalyzerConfig>,
) -> Result<OverlayAnalysis> {
    tracing::info!(
        archive_type,
        overlay_bytes = overlay_data.len(),
        "Detected archive in overlay"
    );

    // Write overlay to temporary file with correct extension for ArchiveAnalyzer
    // The ArchiveAnalyzer uses file extension to determine archive type
    let temp_file = tempfile::Builder::new()
        .suffix(&format!(".{}", archive_type))
        .tempfile()
        .context("Failed to create temp file for overlay")?;

    std::fs::write(temp_file.path(), overlay_data)
        .context("Failed to write overlay to temp file")?;

    // Analyze the archive
    let mut analyzer = ArchiveAnalyzer::new();
    if let Some(config) = archive_config {
        analyzer = config.apply(analyzer);
    }

    analyzer = analyzer.with_engine(engine.clone());

    if let Some(engine) = yara_engine {
        analyzer = analyzer.with_yara_arc(engine);
    }

    match analyzer.analyze(temp_file.path()) {
        Ok(archive_report) => Ok(OverlayAnalysis {
            extraction_failure: None,
            archive_report,
        }),
        Err(e) => {
            // Archive extraction failed - still emit a finding about the SFX
            tracing::warn!(error = %e, binary_path, archive_type, "Failed to extract overlay archive");

            let failure = Finding {
                precomputed_spans: None,
                src: None,
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: format!(
                    "file/archive/self-extracting/{}/extraction-failed",
                    archive_type
                )
                .into(),
                desc: format!(
                    "Self-extracting archive ({}) - extraction failed",
                    archive_type.to_uppercase()
                )
                .into(),
                conf: 0.9,
                crit: Criticality::Notable,
                mbc: None,
                attack: None,
                evidence: vec![
                    Evidence {
                        method: "magic_bytes".to_string(),
                        source: "overlay_analyzer".to_string(),
                        value: format!("archive_type:{}", archive_type),
                        location: Some(format!("overlay:{}bytes", overlay_data.len())),
                        ..Default::default()
                    },
                    Evidence {
                        method: "extraction_error".to_string(),
                        source: "overlay_analyzer".to_string(),
                        value: format!("{}", e),
                        location: None,
                        ..Default::default()
                    },
                ],
                match_count: 1,
                source_file: Some(binary_path.to_string()),
                downgraded: false,
            };

            Ok(OverlayAnalysis {
                extraction_failure: Some(failure),
                archive_report: AnalysisReport::new(TargetInfo {
                    path: format!("{}:overlay", binary_path),
                    file_type: archive_type.to_string(),
                    size_bytes: overlay_data.len() as u64,
                    sha256: crate::analyzers::utils::calculate_sha256(overlay_data),
                    architectures: None,
                }),
            })
        }
    }
}

/// Result of overlay analysis
#[derive(Debug)]
pub(crate) struct OverlayAnalysis {
    /// The archive could not be unpacked.
    pub extraction_failure: Option<Finding>,
    /// Full analysis report from the embedded archive
    pub archive_report: AnalysisReport,
}
