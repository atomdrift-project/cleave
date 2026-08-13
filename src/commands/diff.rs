//! `cleave diff` — differential analysis for supply-chain attack detection.
//!
//! Both inputs run through the cached analyze pipeline, so a re-diff after a
//! fresh analyze is effectively free. The output envelope is the v3
//! [`cleave::AnalysisReport`] with `diff` populated; JSON consumers
//! (prism, litmus) read `diff.scopes` and `diff.files` directly, terminal
//! consumers go through [`cleave::diff::format::format_terminal`].
use std::path::Path;

use anyhow::Result;

use crate::cli;

/// Run the diff subcommand.
///
/// `old` and `new` may each be a file or a directory. `scope_spec` is a
/// comma-separated list parsed by [`cleave::diff::ScopeMask::parse`];
/// `limit_changes` caps the per-scope item lists for legibility
/// (`0` disables the cap).
pub fn run(
    old: &str,
    new: &str,
    scope_spec: &str,
    limit_changes: usize,
    format: &cli::OutputFormat,
) -> Result<String> {
    let mask = cleave::diff::ScopeMask::parse(scope_spec)?;
    let options = cleave::AnalysisOptions::default();
    let report = cleave::diff::diff_paths(
        Path::new(old),
        Path::new(new),
        &options,
        mask,
        limit_changes,
        cleave::diff::UnchangedMembers::Skip,
    )?;

    match format {
        cli::OutputFormat::Json | cli::OutputFormat::Jsonl => Ok(serde_json::to_string(&report)?),
        cli::OutputFormat::Terminal | cli::OutputFormat::Tiny => {
            Ok(cleave::diff::format::format_terminal(&report))
        }
    }
}
