//! Unified evaluation API combining atomic traits and composite rules.
//!
//! This module provides the high-level API for evaluating all capability rules
//! and merging results into analysis reports. It ensures proper ordering:
//! 1. Independent atomic traits (no trait: dependencies) are evaluated first
//! 2. Dependent atomic traits (with trait: conditions) are evaluated iteratively
//! 3. Import metadata findings are generated
//! 4. Composite rules are evaluated (can reference both traits and imports)
//! 5. All findings are deduplicated and merged
//! 6. Retroactive unless-suppression: atomic findings whose `unless:` conditions
//!    referenced composites (not yet evaluated in Steps 1-2) are re-checked and
//!    removed if their conditions are now satisfied.

use crate::composite_rules::{Arch, Condition, FileType as RuleFileType, SectionMap};
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
    pub(crate) fn precompute_raw_regex_matches(
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
        self.evaluate_and_merge_findings_with_precomputed(
            report,
            binary_data,
            cached_ast,
            inline_yara,
            None,
            None,
        )
    }

    /// Like `evaluate_and_merge_findings`, but accepts precomputed raw regex matches
    /// and optional architecture byte ranges for fat/universal binary arch clamping.
    pub(crate) fn evaluate_and_merge_findings_with_precomputed(
        &self,
        report: &mut AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
        precomputed_raw_regex: Option<Option<FxHashSet<usize>>>,
        arch_ranges: Option<&[(Arch, std::ops::Range<usize>)]>,
    ) {
        // Detect file type once
        let file_type = self.detect_file_type(&report.target.file_type);

        // Build section map ONCE for location-constrained matching
        let section_map = SectionMap::from_binary(binary_data);

        // Use precomputed regex matches if provided, otherwise compute now
        let raw_regex_matches = precomputed_raw_regex
            .unwrap_or_else(|| self.precompute_raw_regex_matches(binary_data, &file_type));
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
            arch_ranges,
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
                arch_ranges,
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
            arch_ranges,
        );

        // Step 5: Merge composite findings into report.
        for finding in composite_findings {
            if !seen.contains(finding.id.as_str()) {
                seen.insert(finding.id.clone());
                report.findings.push(finding);
            }
        }

        // Step 6: Retroactive unless-suppression.
        //
        // Atomic traits (Steps 1-2) can declare `unless: [{id: some-composite}]`, but
        // composite rules only fire in Step 4. When an atomic is evaluated in Step 2,
        // the composite isn't in `report.findings` yet, so the `unless:` check always
        // returns false — the trait fires even though it should be suppressed.
        //
        // After all findings are merged, re-check `unless:` Condition::Trait references
        // for every atomic finding and remove any that are now satisfied. The loop runs
        // until no further suppressions occur (handles chained unless: dependencies).
        self.apply_retroactive_unless_suppression(report);
    }

    /// Re-evaluate `unless:` Trait conditions for all findings after the full evaluation
    /// pipeline (Steps 1-5) has completed.
    ///
    /// Two ordering constraints prevent `unless:` from working correctly at eval time:
    ///
    /// 1. **Atomic → composite**: Atomic traits (Steps 1-2) cannot check `unless:` conditions
    ///    that reference composites, because composites fire in Step 4.
    ///
    /// 2. **Composite → composite**: Composites evaluated in Pass 1 of Step 4 are run in
    ///    parallel and deduplicated by ID, so a composite with `unless: [other-composite]`
    ///    may fire before the referenced composite is in `all_findings`. Subsequent
    ///    iterations see the deduplication guard and skip re-evaluation.
    ///
    /// This method corrects both cases: after all findings are merged, it re-checks every
    /// finding's `unless:` Trait conditions against the complete finding set and removes
    /// any that should have been suppressed. It loops to a fixed point so cascading
    /// suppressions (A suppresses B which suppresses C) are fully resolved.
    fn apply_retroactive_unless_suppression(&self, report: &mut AnalysisReport) {
        // Build lookup from qualified ID → Option<&[Condition]> (the unless: list, if any).
        // Covers both atomic traits and composite rules.
        // Trait/composite IDs are qualified at load time (e.g. "well-known/foo::bar-id").
        let mut unless_by_id: HashMap<&str, &[Condition]> = HashMap::new();
        for t in &self.trait_definitions {
            if let Some(conds) = t.unless.as_deref() {
                unless_by_id.insert(t.id.as_str(), conds);
            }
        }
        for r in &self.composite_rules {
            if let Some(conds) = r.unless.as_deref() {
                unless_by_id.insert(r.id.as_str(), conds);
            }
        }

        if unless_by_id.is_empty() {
            return;
        }

        // Iterate to fixed point: removing a finding can expose further suppressions
        // in rules whose `unless:` referenced the just-removed finding.
        loop {
            let all_ids: FxHashSet<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();

            let suppressed: FxHashSet<String> = report
                .findings
                .iter()
                .filter_map(|finding| {
                    let unless_conds = unless_by_id.get(finding.id.as_str())?;
                    let should_suppress = unless_conds.iter().any(|cond| {
                        if let Condition::Trait { id } = cond {
                            self.unless_trait_id_matches(id, &all_ids)
                        } else {
                            false // non-Trait conditions are evaluated correctly at eval time
                        }
                    });
                    should_suppress.then(|| finding.id.clone())
                })
                .collect();

            if suppressed.is_empty() {
                break;
            }

            tracing::debug!(
                "Retroactive unless-suppression: removing {} findings suppressed by post-eval conditions",
                suppressed.len()
            );

            report.findings.retain(|f| !suppressed.contains(&f.id));
        }
    }

    /// Check whether a trait ID from an `unless:` condition matches any finding in the set.
    ///
    /// Mirrors the ID-matching logic used in `eval_trait` so that retroactive suppression
    /// behaves identically to runtime evaluation.
    fn unless_trait_id_matches(&self, id: &str, all_ids: &FxHashSet<&str>) -> bool {
        // Specific reference (contains `::`): exact match only.
        if id.contains("::") {
            return all_ids.contains(id);
        }

        // No slashes: suffix match (short name, same-directory style).
        // e.g. "terminate" matches "execution/process::terminate"
        if !id.contains('/') {
            let suffix_new = format!("::{id}");
            let suffix_legacy = format!("/{id}");
            return all_ids
                .iter()
                .any(|fid| fid.ends_with(&suffix_new) || fid.ends_with(&suffix_legacy));
        }

        // Has slashes but no `::`: directory-prefix match.
        // e.g. "micro-behaviors/fs" matches any finding under that path.
        all_ids
            .iter()
            .any(|fid| *fid == id || fid.starts_with(&format!("{id}/")))
    }
}
