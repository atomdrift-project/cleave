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
    /// Pre-compute raw content regex matches once for the binary.
    ///
    /// Benchmarking shows the batched approach (Aho-Corasick + RegexSet over all 5285
    /// patterns) costs ~400ms/MB — needing ~4100 trait skips to break even, but only
    /// 2249 indexed traits exist. Individual per-trait `bytes::Regex` evaluation is
    /// consistently cheaper, so this is disabled. Returns `None` to let each trait
    /// evaluate its own regex individually.
    pub(crate) fn precompute_raw_regex_matches(
        &self,
        _binary_data: &[u8],
        _file_type: &RuleFileType,
    ) -> Option<FxHashSet<usize>> {
        None
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
        cancellation: Option<&std::sync::atomic::AtomicBool>,
    ) {
        let t_total = std::time::Instant::now();
        // Detect file type once
        let file_type = self.detect_file_type(&report.target.file_type);

        // Build section map ONCE for location-constrained matching.
        // Skip parsing for files that don't have sections (saves ~100ms per file).
        let section_map = if file_type.has_sections() {
            SectionMap::from_binary(binary_data)
        } else {
            SectionMap::empty(binary_data.len() as u64)
        };

        // Use precomputed regex matches if provided, otherwise compute now
        let raw_regex_matches = precomputed_raw_regex
            .unwrap_or_else(|| self.precompute_raw_regex_matches(binary_data, &file_type));
        let raw_regex_matches_ref = raw_regex_matches.as_ref();

        // Use trait index to only evaluate applicable traits
        let applicable_indices: Vec<usize> = self
            .trait_index
            .get_applicable(&file_type)
            .into_indices_static()
            .collect();

        // Idea 9: Batch AST node collection
        let mut ast_kind_cache = None;
        if let Some(tree) = cached_ast {
            if let Ok(source) = std::str::from_utf8(binary_data) {
                let mut required_node_types = FxHashSet::default();
                for &idx in &applicable_indices {
                    let trait_def = &self.trait_definitions[idx];
                    if let Condition::Ast { kind, node, .. } = &trait_def.r#if {
                        if let Some(k) = kind {
                            for nt in crate::composite_rules::ast_kinds::map_kind_to_node_types(
                                k, file_type,
                            ) {
                                required_node_types.insert(nt);
                            }
                        } else if let Some(n) = node {
                            required_node_types.insert(n.as_str());
                        }
                    }
                }

                if !required_node_types.is_empty() {
                    let mut cache = FxHashMap::default();
                    let mut cursor = tree.walk();
                    crate::analyzers::ast_walker::walk_tree_with_stats(
                        &mut cursor,
                        None,
                        |node, _| {
                            let kind = node.kind();
                            if required_node_types.contains(kind) {
                                if let Ok(text) = node.utf8_text(source.as_bytes()) {
                                    cache
                                        .entry(kind.to_string())
                                        .or_insert_with(Vec::new)
                                        .push(Evidence {
                                        method: "ast".to_string(),
                                        source: "tree-sitter".to_string(),
                                        value:
                                            crate::composite_rules::evaluators::truncate_evidence(
                                                text, 100,
                                            ),
                                        location: Some(format!(
                                            "{}:{}",
                                            node.start_position().row + 1,
                                            node.start_position().column + 1
                                        )),
                                        offsets: vec![node.start_byte() as u64],
                                        ..Default::default()
                                    });
                                }
                            }
                            true
                        },
                    );
                    ast_kind_cache = Some(cache);
                }
            }
        }
        // Build all_strings ONCE — combines report strings, imports, and exports
        let t_strings = std::time::Instant::now();

        // Only build and match strings if there is something to match against
        let (string_matched_traits, cached_evidence, regex_candidates) =
            if !report.strings.is_empty()
                || !report.imports.is_empty()
                || !report.exports.is_empty()
            {
                let all_strings = super::build_all_strings(report);

                // Run string matching ONCE
                let (traits, evidence) = if self.string_match_index.has_patterns() {
                    self.string_match_index
                        .find_matches_with_evidence(&all_strings)
                } else {
                    (FxHashSet::default(), FxHashMap::default())
                };

                let candidates = self.string_match_index.find_regex_candidates(&all_strings);
                (traits, evidence, candidates)
            } else {
                (
                    FxHashSet::default(),
                    FxHashMap::default(),
                    FxHashSet::default(),
                )
            };

        // Run symbol matching ONCE
        let symbol_matched_traits = if !report.imports.is_empty() || !report.exports.is_empty() {
            let all_symbols: Vec<String> = report
                .imports
                .iter()
                .map(|i| i.symbol.clone())
                .chain(report.exports.iter().map(|e| e.symbol.clone()))
                .collect();
            self.symbol_match_index.find_matches(&all_symbols)
        } else {
            FxHashSet::default()
        };

        let _d_strings = t_strings.elapsed();

        // Build a seen-IDs set once from existing report findings, then keep it up-to-date
        // as we merge — O(1) per lookup instead of O(n) linear scan.
        let mut seen: FxHashSet<String> = report.findings.iter().map(|f| f.id.clone()).collect();

        // Step 1: Evaluate independent atomic traits (no trait: dependencies)
        // These can be evaluated in parallel without worrying about order
        let t_eval1 = std::time::Instant::now();
        let cache = super::evaluate_traits::TraitEvalCache {
            raw_regex_matches: raw_regex_matches_ref,
            section_map: &section_map,
            string_matched_traits: &string_matched_traits,
            symbol_matched_traits: &symbol_matched_traits,
            cached_evidence: &cached_evidence,
            regex_candidates: &regex_candidates,
            arch_ranges,
            ast_kind_cache,
        };

        if cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
            tracing::warn!(
                path = %report.target.path,
                "skipping trait evaluation: analysis cancelled"
            );
            return;
        }

        let independent_findings = self.evaluate_traits_filtered_with_cache(
            report,
            binary_data,
            cached_ast,
            inline_yara,
            false,
            &cache,
            cancellation,
        );

        // Merge independent findings into report
        for finding in independent_findings {
            if !seen.contains(finding.id.as_str()) {
                seen.insert(finding.id.clone());
                report.push_finding_capped(finding);
            }
        }
        let _d_eval1 = t_eval1.elapsed();

        // Step 2: Evaluate dependent atomic traits (with trait: conditions)
        // These need to see the independent traits' results, so evaluate iteratively
        // until no new findings are produced (handles chained dependencies: A -> B -> C)
        let t_eval2 = std::time::Instant::now();
        const MAX_ITERATIONS: usize = 10; // Prevent infinite loops
        for _ in 0..MAX_ITERATIONS {
            if cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
                break;
            }
            let dependent_findings = self.evaluate_traits_filtered_with_cache(
                report,
                binary_data,
                cached_ast,
                inline_yara,
                true,
                &cache,
                cancellation,
            );

            if dependent_findings.is_empty() {
                break;
            }

            let mut added_any = false;
            for finding in dependent_findings {
                if !seen.contains(finding.id.as_str()) {
                    seen.insert(finding.id.clone());
                    report.push_finding_capped(finding);
                    added_any = true;
                }
            }

            // If no new findings were added, we've reached a fixed point
            if !added_any {
                break;
            }
        }
        let _d_eval2 = t_eval2.elapsed();

        // Step 3: Generate synthetic metadata/import findings from discovered imports
        // This MUST happen before Step 4 so composite rules can reference them
        let t_imports = std::time::Instant::now();
        let pre_import_count = report.findings.len();
        Self::generate_import_findings(report);
        // Update seen with any newly added import findings
        for f in &report.findings[pre_import_count..] {
            seen.insert(f.id.clone());
        }
        let _d_imports = t_imports.elapsed();

        // Step 4: Evaluate composite rules (which can now access atomic traits AND metadata/import findings)
        let t_comp = std::time::Instant::now();
        let composite_findings = self.evaluate_composite_rules(
            report,
            binary_data,
            cached_ast,
            inline_yara,
            &section_map,
            arch_ranges,
        );

        // Merge composite findings into report
        for finding in composite_findings {
            if !seen.contains(finding.id.as_str()) {
                seen.insert(finding.id.clone());
                report.push_finding_capped(finding);
            }
        }
        let _d_comp = t_comp.elapsed();
        let _d_total = t_total.elapsed();

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
