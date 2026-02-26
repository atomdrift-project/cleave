//! Unified evaluation API combining atomic traits and composite rules.
//!
//! This module provides the high-level API for evaluating all capability rules
//! and merging results into analysis reports. It ensures proper ordering:
//! 1. Independent atomic traits (no trait: dependencies) are evaluated first
//! 2. Dependent atomic traits (with trait: conditions) are evaluated iteratively
//! 3. Import metadata findings are generated
//! 4. Composite rules are evaluated (can reference both traits and imports)
//! 5. All findings are deduplicated and merged

use crate::composite_rules::FileType as RuleFileType;
use crate::types::{AnalysisReport, Evidence};
use rustc_hash::FxHashSet;
use std::collections::HashMap;

impl super::CapabilityMapper {
    /// Pre-compute raw content regex matches once for the binary.
    /// This is expensive (converts entire binary to string and runs regex set)
    /// so we do it once and pass to all trait evaluation calls.
    ///
    /// For files > 1MB, skip this optimization as the cost of running 2500+ regexes
    /// against a multi-MB string exceeds the benefit. Individual trait evaluation
    /// will still work, just without pre-filtering.
    fn precompute_raw_regex_matches(
        &self,
        binary_data: &[u8],
        file_type: &RuleFileType,
    ) -> FxHashSet<usize> {
        // Skip for large files - the regex matching is O(patterns * size) and becomes
        // a bottleneck for multi-MB binaries. Empty result means no pre-filtering;
        // traits will evaluate their conditions individually.
        const MAX_SIZE_FOR_REGEX_PREFILTER: usize = 1024 * 1024; // 1MB
        if binary_data.len() > MAX_SIZE_FOR_REGEX_PREFILTER {
            tracing::debug!(
                "Skipping raw regex pre-filter for large file ({} bytes > {} threshold)",
                binary_data.len(),
                MAX_SIZE_FOR_REGEX_PREFILTER
            );
            return FxHashSet::default();
        }

        let t_start = std::time::Instant::now();
        let result = if self.raw_content_regex_index.has_patterns() {
            self.raw_content_regex_index.find_matches(binary_data, file_type)
        } else {
            FxHashSet::default()
        };
        let elapsed = t_start.elapsed();
        tracing::debug!(
            "Precomputed raw regex matches in {:?}, found {} matches",
            elapsed,
            result.len()
        );
        result
    }
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
        // Detect file type once
        let file_type = self.detect_file_type(&report.target.file_type);

        // Pre-compute raw regex matches ONCE (expensive: converts binary to string, runs regex set)
        // This is passed to all trait evaluation calls to avoid recomputing
        let raw_regex_matches = self.precompute_raw_regex_matches(binary_data, &file_type);

        // Build a seen-IDs set once from existing report findings, then keep it up-to-date
        // as we merge — O(1) per lookup instead of O(n) linear scan.
        let mut seen: FxHashSet<String> = report.findings.iter().map(|f| f.id.clone()).collect();

        // Step 1: Evaluate independent atomic traits (no trait: dependencies)
        // These can be evaluated in parallel without worrying about order
        let independent_findings = self.evaluate_traits_filtered_with_cache(
            report,
            binary_data,
            cached_ast,
            inline_yara,
            false,
            &raw_regex_matches,
        );

        // Merge independent findings into report
        for finding in independent_findings {
            if !seen.contains(finding.id.as_str()) {
                seen.insert(finding.id.clone());
                report.findings.push(finding);
            }
        }

        // Step 2: Evaluate dependent atomic traits (with trait: conditions)
        // These need to see the independent traits' results, so evaluate iteratively
        // until no new findings are produced (handles chained dependencies: A -> B -> C)
        const MAX_ITERATIONS: usize = 10; // Prevent infinite loops
        for _ in 0..MAX_ITERATIONS {
            let dependent_findings = self.evaluate_traits_filtered_with_cache(
                report,
                binary_data,
                cached_ast,
                inline_yara,
                true,
                &raw_regex_matches,
            );

            if dependent_findings.is_empty() {
                break;
            }

            let mut added_any = false;
            for finding in dependent_findings {
                if !seen.contains(finding.id.as_str()) {
                    seen.insert(finding.id.clone());
                    report.findings.push(finding);
                    added_any = true;
                }
            }

            // If no new findings were added, we've reached a fixed point
            if !added_any {
                break;
            }
        }

        // Step 3: Generate synthetic metadata/import findings from discovered imports
        // This MUST happen before Step 4 so composite rules can reference them
        Self::generate_import_findings(report);

        // Step 4: Evaluate composite rules (which can now access atomic traits AND metadata/import findings)
        let composite_findings =
            self.evaluate_composite_rules(report, binary_data, cached_ast, inline_yara);

        // Step 5: Merge composite findings into report.
        // Rebuild seen to include metadata/import findings added in step 3.
        let mut seen: FxHashSet<String> = report.findings.iter().map(|f| f.id.clone()).collect();
        for finding in composite_findings {
            if !seen.contains(finding.id.as_str()) {
                seen.insert(finding.id.clone());
                report.findings.push(finding);
            }
        }
    }

}
