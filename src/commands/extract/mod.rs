//! Extraction subcommands for cleave.
//!
//! This module provides various extraction utilities for analyzing files:
//!
//! - **strings**: Extract strings from binaries and source files
//! - **symbols**: Extract imports, exports, and functions from binaries and source files
//! - **sections**: Extract section information from binary files (ELF, PE, Mach-O)
//! - **metrics**: Extract all computed metrics from a file
//!
//! Each subcommand supports both JSONL and terminal output formats.

use crate::analyzers::{
    detect_file_type, elf::ElfAnalyzer, macho::MachOAnalyzer, pe::PEAnalyzer, Analyzer, FileType,
};
use crate::types::{file_analysis::ENCODING_DELIMITER, AnalysisReport, FileAnalysis};
use anyhow::Result;
use std::fs;
use std::path::Path;

pub(crate) mod metrics;
pub(crate) mod sections;
pub(crate) mod strings;
pub(crate) mod symbols;

pub(crate) fn analyze_binary_report(path: &Path, file_type: &FileType) -> Result<AnalysisReport> {
    let capability_mapper = crate::capabilities::CapabilityMapper::empty();

    match file_type {
        FileType::Elf => ElfAnalyzer::new()
            .with_capability_mapper(capability_mapper)
            .analyze(path),
        FileType::Pe => PEAnalyzer::new()
            .with_capability_mapper(capability_mapper)
            .analyze(path),
        FileType::MachO => MachOAnalyzer::new()
            .with_capability_mapper(capability_mapper)
            .analyze(path),
        _ => anyhow::bail!("unsupported binary file type: {:?}", file_type),
    }
}

pub(crate) fn extract_layer_file_analysis(target: &str, layer: &str) -> Result<FileAnalysis> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    let data = fs::read(path)?;
    let file_type = detect_file_type(path)?;

    let capability_mapper = crate::capabilities::CapabilityMapper::empty();
    let mut report = match file_type {
        FileType::Elf => ElfAnalyzer::new()
            .with_capability_mapper(capability_mapper)
            .analyze_structural(path, &data, None),
        FileType::Pe => PEAnalyzer::new()
            .with_capability_mapper(capability_mapper)
            .analyze_structural(path, &data, None),
        FileType::MachO => MachOAnalyzer::new()
            .with_capability_mapper(capability_mapper)
            .analyze_structural(path, &data, None),
        _ => anyhow::bail!("Layer filtering only supported for binary files (ELF, PE, Mach-O)"),
    };

    report.finalize();

    let layer_suffix = format!("{}{}", ENCODING_DELIMITER, layer);
    report
        .files
        .iter()
        .find(|f| f.path.ends_with(&layer_suffix))
        .cloned()
        .ok_or_else(|| {
            let available: Vec<_> = report
                .files
                .iter()
                .filter_map(|f| {
                    f.path
                        .rfind(ENCODING_DELIMITER)
                        .map(|idx| &f.path[idx + ENCODING_DELIMITER.len()..])
                })
                .collect();
            if available.is_empty() {
                anyhow::anyhow!(
                    "Layer '{}' not found. No encoded layers in this file.",
                    layer
                )
            } else {
                anyhow::anyhow!(
                    "Layer '{}' not found. Available layers: {}",
                    layer,
                    available.join(", ")
                )
            }
        })
}
