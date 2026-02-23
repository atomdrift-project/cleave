//! Terminal output formatting for diff reports.
//!
//! Provides human-readable formatting of differential analysis results with:
//! - Risk indicators (emoji-based)
//! - Aggregated findings by directory
//! - File change summaries
//! - Change statistics

use crate::output::aggregate_findings_by_directory;
use crate::types::DiffReport;
use std::path::Path;

/// Format diff report as human-readable terminal output
#[allow(dead_code)] // Used by binary target
#[must_use]
pub(crate) fn format_diff_terminal(report: &DiffReport) -> String {
    let mut output = String::new();

    // Header with version comparison
    let baseline_name = Path::new(&report.baseline)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&report.baseline);
    let target_name = Path::new(&report.target)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&report.target);

    output.push_str(&format!("📦 {} → {}\n", baseline_name, target_name));
    output.push_str(&format!("   {}\n   {}\n\n", report.baseline, report.target));

    let total_changes = report.changes.added.len()
        + report.changes.removed.len()
        + report.changes.modified.len()
        + report.changes.renamed.len();

    if total_changes == 0 && report.modified_analysis.is_empty() {
        output.push_str("✅ No capability changes detected\n");
        return output;
    }

    // Risk assessment upfront
    let high_risk_changes = report
        .modified_analysis
        .iter()
        .filter(|a| a.risk_increase)
        .count();

    if high_risk_changes > 0 {
        output.push_str(&format!(
            "🚨 {} file(s) with increased risk\n\n",
            high_risk_changes
        ));
    }

    // Sort modified files: high risk first, then by filename
    let mut sorted_analysis = report.modified_analysis.clone();
    sorted_analysis.sort_by(|a, b| {
        b.risk_increase
            .cmp(&a.risk_increase)
            .then_with(|| a.file.cmp(&b.file))
    });

    // Modified files with capability changes (most important)
    for analysis in &sorted_analysis {
        let risk_icon = if analysis.risk_increase {
            "⚠️ "
        } else {
            ""
        };
        output.push_str(&format!("{}📄 {}\n", risk_icon, analysis.file));

        // Aggregate findings by directory path for cleaner display
        let mut aggregated_new = aggregate_findings_by_directory(&analysis.new_capabilities);

        // Sort by criticality (highest first), then by name
        aggregated_new.sort_by(|a, b| b.crit.cmp(&a.crit).then_with(|| a.id.cmp(&b.id)));

        // Show new capabilities (one line each, aggregated by directory)
        for cap in &aggregated_new {
            let risk_icon = match cap.crit {
                crate::types::Criticality::Hostile => "🔴",
                crate::types::Criticality::Suspicious => "🟠",
                crate::types::Criticality::Notable => "🟡",
                _ => "🟢",
            };

            // Get best evidence (prefer one with a line number)
            let evidence_str = cap
                .evidence
                .iter()
                .find(|e| {
                    e.location
                        .as_ref()
                        .is_some_and(|l: &String| l.starts_with("line:"))
                })
                .or(cap.evidence.first())
                .map(|ev| {
                    let loc = ev
                        .location
                        .as_ref()
                        .filter(|l: &&String| l.as_str() != "file" && !l.is_empty())
                        .map(|l: &String| format!(":{}", l.trim_start_matches("line:")))
                        .unwrap_or_default();
                    format!(" [{}{}]", ev.value, loc)
                })
                .unwrap_or_default();

            output.push_str(&format!(
                "   + {} {}: {}{}\n",
                risk_icon, cap.id, cap.desc, evidence_str
            ));
        }

        // Aggregate removed capabilities by directory path too
        let mut aggregated_removed =
            aggregate_findings_by_directory(&analysis.removed_capabilities);

        // Sort by criticality (highest first), then by name
        aggregated_removed.sort_by(|a, b| b.crit.cmp(&a.crit).then_with(|| a.id.cmp(&b.id)));

        // Show removed capabilities
        for cap in &aggregated_removed {
            output.push_str(&format!("   - {}\n", cap.id));
        }
        output.push('\n');
    }

    // File-level changes section
    let file_changes =
        report.changes.added.len() + report.changes.removed.len() + report.changes.renamed.len();
    if file_changes > 0 {
        output.push_str("📁 File changes:\n");

        // Added files
        for file in &report.changes.added {
            output.push_str(&format!("   + {}\n", file));
        }

        // Removed files
        for file in &report.changes.removed {
            output.push_str(&format!("   - {}\n", file));
        }

        // Renamed files
        for rename in &report.changes.renamed {
            if rename.similarity < 1.0 {
                output.push_str(&format!(
                    "   → {} → {} ({:.0}%)\n",
                    rename.from,
                    rename.to,
                    rename.similarity * 100.0
                ));
            } else {
                output.push_str(&format!("   → {} → {}\n", rename.from, rename.to));
            }
        }
        output.push('\n');
    }

    // Summary line
    let mut summary_parts = Vec::new();
    if !report.changes.added.is_empty() {
        summary_parts.push(format!("+{} files", report.changes.added.len()));
    }
    if !report.changes.removed.is_empty() {
        summary_parts.push(format!("-{} files", report.changes.removed.len()));
    }
    if !report.modified_analysis.is_empty() {
        let total_new: usize = report
            .modified_analysis
            .iter()
            .map(|a| a.new_capabilities.len())
            .sum();
        let total_removed: usize = report
            .modified_analysis
            .iter()
            .map(|a| a.removed_capabilities.len())
            .sum();
        if total_new > 0 {
            summary_parts.push(format!("+{} capabilities", total_new));
        }
        if total_removed > 0 {
            summary_parts.push(format!("-{} capabilities", total_removed));
        }
    }
    if !summary_parts.is_empty() {
        output.push_str(&format!("Summary: {}\n", summary_parts.join(", ")));
    }

    output
}

// Note: Integration tests for format_diff_terminal are in tests/diff_formatting_test.rs
// Unit tests here would require constructing complex DiffReport structures with many fields
