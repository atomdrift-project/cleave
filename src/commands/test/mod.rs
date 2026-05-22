//! Test commands for cleave CLI.
//!
//! This module provides testing and debugging commands for rule development
//! and pattern matching validation.
//!
//! # Commands
//!
//! ## test-rules
//!
//! Debug and validate composite rules and micro-behaviors against sample files.
//! Shows detailed evaluation traces for understanding why rules match or don't match.
//!
//! **Usage:**
//! ```text
//! cleave test-rules <file> --rules <rule-id>[,<rule-id>...]
//! ```
//!
//! **Features:**
//! - Evaluates specified rules against a target file
//! - Shows detailed condition evaluation with pass/fail status
//! - Displays evidence and match locations
//! - Suggests similar rules if specified rule is not found
//! - Supports directory prefixes to test all rules under a path
//!
//! ## test-match
//!
//! Test pattern matching conditions against files with detailed diagnostics.
//! Validates search patterns, count constraints, and location filters.
//!
//! **Usage:**
//! ```text
//! cleave test-match <file> --type <string-value|symbol|raw|value|hex|encoded|section|metrics> \
//!   --pattern <pattern> [--method <exact|contains|regex|word>] [options...]
//! ```
//!
//! **Search Types:**
//! - `string-value`: Search extracted string literals
//! - `symbol`: Search function/import/export symbols
//! - `raw`: Search raw file content (bytes)
//! - `value`: Search structural values by path
//! - `hex`: Search for hex byte patterns
//! - `encoded`: Search decoded/encoded strings (base64, hex, xor)
//! - `section`: Search binary sections by name/size/entropy
//! - `metrics`: Test computed metrics against thresholds
//!
//! **Match Methods:**
//! - `exact`: Exact string match
//! - `contains`: Substring match
//! - `regex`: Regular expression match
//! - `word`: Word boundary match
//!
//! **Constraints:**
//! - `--count-min/max`: Match count thresholds
//! - `--per-kb-min/max`: Density thresholds (matches per KB)
//! - `--length-min/max`: String/section length constraints
//! - `--entropy-min/max`: Entropy constraints (sections)
//! - `--value-min/max`: Metric value thresholds
//! - `--is <external_ip|bitcoin_addr>`: Apply high-fidelity validators
//!
//! **Location Filters:**
//! - `--section <name>`: Limit search to specific section
//! - `--offset <bytes>`: Search at specific file offset
//! - `--offset-range <start:end>`: Search within offset range
//! - `--section-offset <bytes>`: Offset relative to section
//! - `--section-offset-range <start:end>`: Range relative to section
//!
//! **Features:**
//! - Shows matched content and context
//! - Provides suggestions for alternative search types
//! - Displays available sections, keys, and metrics
//! - Tests constraints and shows which failed
//! - Supports case-insensitive matching

pub mod match_cmd;
pub mod rules;

use crate::analyzers::{macho::MachOAnalyzer, FileType};
use crate::commands::shared::create_analysis_report;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub(crate) struct PreparedTestTarget {
    pub(crate) preferred_binary_data: Vec<u8>,
    pub(crate) is_fat_macho: bool,
    pub(crate) arch_count: Option<usize>,
}

pub(crate) struct PreparedTestAnalysis {
    pub(crate) file_type: FileType,
    pub(crate) full_data: Vec<u8>,
    pub(crate) preferred_binary_data: Vec<u8>,
    pub(crate) report: crate::types::AnalysisReport,
    pub(crate) is_fat_macho: bool,
    pub(crate) arch_count: Option<usize>,
}

pub(crate) fn build_test_capability_mapper(
    platforms: Vec<crate::composite_rules::Platform>,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
) -> crate::capabilities::CapabilityMapper {
    if std::env::var("CLEAVE_SKIP_TRAITS").is_ok() {
        tracing::info!("Traits skipped (CLEAVE_SKIP_TRAITS set)");
        crate::capabilities::CapabilityMapper::empty()
    } else {
        crate::capabilities::CapabilityMapper::new_with_load_options(
            min_hostile_precision,
            min_suspicious_precision,
            false,
            false,
        )
        .with_platforms(platforms)
    }
}

pub(crate) fn prepare_test_target(file_type: &FileType, full_data: &[u8]) -> PreparedTestTarget {
    if *file_type == FileType::MachO {
        let analyzer = MachOAnalyzer::new();
        let preferred_range = analyzer.preferred_arch_range(full_data);
        let arch_count = analyzer.all_arch_ranges(full_data).len();

        return PreparedTestTarget {
            preferred_binary_data: full_data[preferred_range].to_vec(),
            is_fat_macho: arch_count > 1,
            arch_count: Some(arch_count),
        };
    }

    PreparedTestTarget {
        preferred_binary_data: full_data.to_vec(),
        is_fat_macho: false,
        arch_count: None,
    }
}

pub(crate) fn evaluation_data<'a>(
    full_data: &'a [u8],
    preferred_binary_data: &'a [u8],
    is_fat_macho: bool,
) -> &'a [u8] {
    if is_fat_macho {
        full_data
    } else {
        preferred_binary_data
    }
}

pub(crate) fn prepare_test_analysis(
    path: &Path,
    file_type: FileType,
    capability_mapper: &crate::capabilities::CapabilityMapper,
) -> Result<PreparedTestAnalysis> {
    let full_data = fs::read(path)?;
    let prepared_target = prepare_test_target(&file_type, &full_data);
    let mut report = create_analysis_report(
        path,
        &file_type,
        &prepared_target.preferred_binary_data,
        capability_mapper,
    )?;

    // For FAT binaries, re-extract strings from the full file so offsets are file-relative.
    if prepared_target.is_fat_macho {
        let string_extractor = crate::strings::StringExtractor::default();
        report.strings = string_extractor.extract_smart(&full_data);
    }

    // Attach the binary values tree so value-sourced traits (`type: value,
    // path: …`) evaluate the same way as the production analyze
    // pipeline. Without this, value conditions silently fail and rules
    // like `metadata/binary/linking::ifunc` show NOT MATCHED in
    // test-rules even when they fire in `cleave analyze`.
    // Mirrors `lib.rs::analyze_file_with_resources`: trait authors
    // read cross-format facts from `report.filefacts.values.*`; cleave
    // only layers on raw extractors here (ELF .comment, DWARF,
    // ifunc_symbols, init_array entries, …).
    crate::analyzers::binary_extractors::augment_report(&mut report, &full_data);

    Ok(PreparedTestAnalysis {
        file_type,
        full_data,
        preferred_binary_data: prepared_target.preferred_binary_data,
        report,
        is_fat_macho: prepared_target.is_fat_macho,
        arch_count: prepared_target.arch_count,
    })
}

// Re-export command functions
pub use match_cmd::run as test_match;
pub use rules::run as test_rules;
