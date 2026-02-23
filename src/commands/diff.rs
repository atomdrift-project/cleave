//! Diff command for comparing analysis results between two files.
//!
//! The diff command analyzes two binary files and produces a detailed comparison
//! of their differences in terms of capabilities, traits, and other analysis metrics.
//!
//! # Output Formats
//!
//! - **JSONL**: Comprehensive ML-ready output with full differential analysis
//! - **Terminal**: Human-readable diff summary optimized for terminal display

use crate::cli;
use crate::diff;
use anyhow::Result;

/// Run the diff analysis command.
///
/// Compares two binary files and generates a differential analysis report.
/// The output format determines whether to generate comprehensive or simple diff output.
///
/// # Arguments
///
/// * `old` - Path to the original/old file to compare
/// * `new` - Path to the new file to compare
/// * `format` - Output format (Jsonl for comprehensive, Terminal for simple)
///
/// # Returns
///
/// A string containing the formatted diff analysis results.
pub(crate) fn run(old: &str, new: &str, format: &cli::OutputFormat) -> Result<String> {
    let diff_analyzer = diff::DiffAnalyzer::new(old, new);

    match format {
        cli::OutputFormat::Jsonl => {
            // Use full diff for JSONL - comprehensive ML-ready output
            let report = diff_analyzer.analyze_full()?;
            Ok(serde_json::to_string_pretty(&report)?)
        }
        cli::OutputFormat::Terminal => {
            // Use simple diff for terminal display
            let report = diff_analyzer.analyze()?;
            Ok(diff::format_diff_terminal(&report))
        }
    }
}
