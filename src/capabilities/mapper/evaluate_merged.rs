//! Unified evaluation API combining atomic traits and composite rules.
//!
//! This module provides the high-level API for evaluating all capability rules
//! and merging results into analysis reports. It ensures proper ordering:
//! 1. Atomic traits are evaluated first
//! 2. Import metadata findings are generated
//! 3. Composite rules are evaluated (can reference both traits and imports)
//! 4. All findings are deduplicated and merged

use crate::types::{AnalysisReport, Evidence};
use rustc_hash::FxHashSet;
use std::collections::HashMap;

impl super::CapabilityMapper {
    /// Evaluate all rules (atomic traits + composite rules) and merge findings into the report.
    /// This is the correct, foolproof way to evaluate traits that ensures evidence propagates
    /// from atomic traits to composite rules. Analyzers should use this method instead of
    /// calling evaluate_traits() and evaluate_composite_rules() separately.
    ///
    /// Platform filtering is controlled by the `platform` field set via `with_platform()`.
    /// Default is `Platform::All` which matches all rules regardless of platform.
    ///
    /// # Arguments
    /// * `report` - Mutable reference to the analysis report to merge findings into
    /// * `binary_data` - Raw file data for content-based matching
    /// * `cached_ast` - Optional cached tree-sitter AST for performance
    ///
    /// Evaluate all traits and composite rules and merge findings into the report.
    ///
    /// `inline_yara` supplies pre-scanned results from the combined YARA engine (keyed by
    /// `"inline.{trait_id}"`). Pass `None` when YARA is disabled or when called outside
    /// of a binary analysis context.
    ///
    /// # Example
    /// ```ignore
    /// // In an analyzer, after scanning:
    /// let (yara_matches, inline_yara) = engine.scan_bytes_with_inline(data, filter)?;
    /// self.capability_mapper.evaluate_and_merge_findings(&mut report, data, None, Some(&inline_yara));
    /// ```
    pub fn evaluate_and_merge_findings(
        &self,
        report: &mut AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
    ) {
        // Step 1: Evaluate atomic trait definitions
        let trait_findings =
            self.evaluate_traits_with_ast(report, binary_data, cached_ast, inline_yara);

        // Build a seen-IDs set once from existing report findings, then keep it up-to-date
        // as we merge — O(1) per lookup instead of O(n) linear scan.
        let mut seen: FxHashSet<String> = report.findings.iter().map(|f| f.id.clone()).collect();

        // Step 2: Merge atomic trait findings into report (so composites can reference them)
        for finding in trait_findings {
            if !seen.contains(finding.id.as_str()) {
                seen.insert(finding.id.clone());
                report.findings.push(finding);
            }
        }

        // Step 2.5: Generate synthetic metadata/import findings from discovered imports
        // This MUST happen before Step 3 so composite rules can reference them
        Self::generate_import_findings(report);

        // Step 3: Evaluate composite rules (which can now access atomic traits AND metadata/import findings)
        let composite_findings =
            self.evaluate_composite_rules(report, binary_data, cached_ast, inline_yara);

        // Step 4: Merge composite findings into report.
        // Rebuild seen to include metadata/import findings added in step 2.5.
        let mut seen: FxHashSet<String> = report.findings.iter().map(|f| f.id.clone()).collect();
        for finding in composite_findings {
            if !seen.contains(finding.id.as_str()) {
                seen.insert(finding.id.clone());
                report.findings.push(finding);
            }
        }
    }
}
