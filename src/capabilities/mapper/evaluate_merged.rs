//! Unified evaluation API combining atomic traits and composite rules.
//!
//! This module provides the high-level API for evaluating all capability rules
//! and merging results into analysis reports. It ensures proper ordering:
//! 1. Independent atomic traits (no trait: dependencies) are evaluated first
//! 2. Dependent atomic traits (with trait: conditions) are evaluated iteratively
//! 3. Import metadata findings are generated
//! 4. Composite rules are evaluated (can reference both traits and imports)
//! 5. All findings are deduplicated and merged

use crate::composite_rules::{FileType as RuleFileType, SectionMap};
use crate::types::{AnalysisReport, Evidence};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::HashMap;

impl super::CapabilityMapper {
    /// Pre-compute raw content regex matches once for the binary.
    /// This is expensive (converts entire binary to string and runs regex set)
    /// so we do it once and pass to all trait evaluation calls.
    ///
    /// Returns `Some(matches)` if prefilter was run (even if empty - means nothing matched).
    /// Returns `None` if prefilter was skipped (e.g., file too large).
    ///
    /// For files > 1MB, skip this optimization as the cost of running 2500+ regexes
    /// against a multi-MB string exceeds the benefit.
    fn precompute_raw_regex_matches(
        &self,
        binary_data: &[u8],
        file_type: &RuleFileType,
    ) -> Option<FxHashSet<usize>> {
        // Skip for large files - the regex matching is O(patterns * size) and becomes
        // a bottleneck for multi-MB binaries. None means prefilter skipped;
        // traits will evaluate their conditions individually.
        const MAX_SIZE_FOR_REGEX_PREFILTER: usize = 1024 * 1024; // 1MB
        if binary_data.len() > MAX_SIZE_FOR_REGEX_PREFILTER {
            tracing::debug!(
                "Skipping raw regex pre-filter for large file ({} bytes > {} threshold)",
                binary_data.len(),
                MAX_SIZE_FOR_REGEX_PREFILTER
            );
            return None;
        }

        let t_start = std::time::Instant::now();
        let result = if self.raw_content_regex_index.has_patterns() {
            self.raw_content_regex_index
                .find_matches(binary_data, file_type)
        } else {
            FxHashSet::default()
        };
        let elapsed = t_start.elapsed();
        tracing::debug!(
            "Precomputed raw regex matches in {:?}, found {} matches",
            elapsed,
            result.len()
        );
        Some(result)
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

        // Build section map ONCE for location-constrained matching
        let section_map = SectionMap::from_binary(binary_data);

        // Pre-compute raw regex matches ONCE (expensive: converts binary to string, runs regex set)
        // This is passed to all trait evaluation calls to avoid recomputing
        // Returns Some(matches) if run, None if skipped (file too large)
        let raw_regex_matches = self.precompute_raw_regex_matches(binary_data, &file_type);
        let raw_regex_matches_ref = raw_regex_matches.as_ref();

        // Build all_strings ONCE — combines report strings, imports, and exports
        let all_strings = super::build_all_strings(report);

        // Run string matching ONCE
        let (string_matched_traits, cached_evidence) = if self.string_match_index.has_patterns() {
            self.string_match_index
                .find_matches_with_evidence(&all_strings)
        } else {
            (FxHashSet::default(), FxHashMap::default())
        };
        let regex_candidates = self.string_match_index.find_regex_candidates(&all_strings);
        drop(all_strings);

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
            raw_regex_matches_ref,
            &section_map,
            &string_matched_traits,
            &cached_evidence,
            &regex_candidates,
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
                raw_regex_matches_ref,
                &section_map,
                &string_matched_traits,
                &cached_evidence,
                &regex_candidates,
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
        let pre_import_count = report.findings.len();
        Self::generate_import_findings(report);
        // Update seen with any newly added import findings
        for f in &report.findings[pre_import_count..] {
            seen.insert(f.id.clone());
        }

        // Step 4: Evaluate composite rules (which can now access atomic traits AND metadata/import findings)
        let composite_findings = self.evaluate_composite_rules(
            report,
            binary_data,
            cached_ast,
            inline_yara,
            &section_map,
        );

        // Step 5: Merge composite findings into report.
        for finding in composite_findings {
            if !seen.contains(finding.id.as_str()) {
                seen.insert(finding.id.clone());
                report.findings.push(finding);
            }
        }
    }
}
