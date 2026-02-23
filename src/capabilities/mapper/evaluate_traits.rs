//! Atomic trait evaluation against analysis reports.
//!
//! This module handles the evaluation of atomic trait definitions, which are the building
//! blocks of the capability detection system. It includes optimizations like:
//! - Index-based filtering by file type
//! - Batched Aho-Corasick string matching with evidence caching
//! - Parallel evaluation of applicable traits
//! - Early termination for empty files

use crate::composite_rules::{Condition, EvaluationContext, SectionMap};
use crate::types::{AnalysisReport, Evidence, Finding, FindingKind};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::HashMap;

use super::get_relative_source_file;

impl super::CapabilityMapper {
    /// Evaluate trait definitions against an analysis report with optional cached AST.
    /// `inline_yara` supplies pre-scanned results from the combined YARA engine, keyed by
    /// namespace (`"inline.{trait_id}"`), enabling fast lookup in `eval_yara_inline`.
    ///
    /// Platform filtering is controlled by the `platform` field set via `with_platform()`.
    #[must_use]
    pub(crate) fn evaluate_traits_with_ast(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
    ) -> Vec<Finding> {
        // Determine file type from report (platform comes from self.platform)
        let file_type = self.detect_file_type(&report.target.file_type);

        // Build section map for location-constrained matching
        let section_map = SectionMap::from_binary(binary_data);

        let mut ctx = EvaluationContext::new(
            report,
            binary_data,
            file_type,
            self.platforms.clone(),
            None,
            cached_ast,
        )
        .with_section_map(section_map);
        if let Some(results) = inline_yara {
            ctx = ctx.with_inline_yara(results);
        }

        // Use trait index to only evaluate applicable traits
        // This dramatically reduces work for specific file types
        let applicable_indices: Vec<usize> = self.trait_index.get_applicable(&file_type).collect();

        // Pre-filter using batched Aho-Corasick string matching WITH evidence caching
        // This identifies which traits match AND caches the evidence to avoid re-iteration
        let _t_prematch = std::time::Instant::now();

        // Combine strings and symbols for pre-filtering
        // Pre-allocate capacity to avoid reallocations
        let total_capacity = report.strings.len() + report.imports.len() + report.exports.len();
        let mut all_strings = Vec::with_capacity(total_capacity);

        // Add existing strings (move instead of clone to avoid copy)
        all_strings.extend_from_slice(&report.strings);

        // Add imports as strings
        for imp in &report.imports {
            all_strings.push(crate::types::StringInfo {
                value: imp.symbol.clone(),
                offset: None,
                encoding: "symbol".to_string(),
                string_type: crate::types::StringType::Import,
                section: None,
                encoding_chain: Vec::new(),
                fragments: None,
            });
        }

        // Add exports as strings
        for exp in &report.exports {
            // Parse export offset from hex string to u64
            let offset = exp.offset.as_ref().and_then(|s| {
                let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
                u64::from_str_radix(s, 16).ok()
            });
            all_strings.push(crate::types::StringInfo {
                value: exp.symbol.clone(),
                offset,
                encoding: "symbol".to_string(),
                string_type: crate::types::StringType::Export,
                section: None,
                encoding_chain: Vec::new(),
                fragments: None,
            });
        }

        let (string_matched_traits, cached_evidence) = if self.string_match_index.has_patterns() {
            self.string_match_index
                .find_matches_with_evidence(&all_strings)
        } else {
            (FxHashSet::default(), FxHashMap::default())
        };

        // Also find regex candidates based on literal prefix matching
        let regex_candidates = self.string_match_index.find_regex_candidates(&all_strings);

        // Pre-filter using batched regex matching for Content conditions
        // Only run if any applicable traits have content regex patterns
        let _t_raw_regex = std::time::Instant::now();
        let raw_regex_prefilter_enabled = self.raw_content_regex_index.has_patterns()
            && self
                .raw_content_regex_index
                .has_applicable_patterns(&applicable_indices);
        let (raw_regex_matched_traits, _has_excessive_line_length) = if raw_regex_prefilter_enabled
        {
            self.raw_content_regex_index
                .find_matches(binary_data, &file_type)
        } else {
            (FxHashSet::default(), false)
        };

        // Evaluate only applicable traits in parallel
        // For exact string traits with cached evidence, use that directly instead of re-evaluating
        let _t_eval = std::time::Instant::now();

        // Early termination: if no strings and no pre-matched traits, skip evaluation
        let has_any_matches = !string_matched_traits.is_empty()
            || !raw_regex_matched_traits.is_empty()
            || !regex_candidates.is_empty();

        if !has_any_matches && all_strings.is_empty() && binary_data.len() < 100 {
            return vec![];
        }

        // Free all_strings memory immediately - no longer needed after this point
        drop(all_strings);

        let eval_count = std::sync::atomic::AtomicUsize::new(0);
        let skip_count = std::sync::atomic::AtomicUsize::new(0);

        let all_findings: Vec<Finding> = applicable_indices
            .par_iter()
            .with_min_len(64)
            .filter_map(|&idx| {
                let trait_def = &self.trait_definitions[idx];

                // Check if this is an exact string trait (no excludes, count_min=1, no downgrade)
                // Works for both case-sensitive and case-insensitive
                // NOTE: Cannot use fast path for traits with downgrade rules - they need full evaluation
                let is_simple_exact_string = trait_def.downgrade.is_none()
                    && matches!(
                        &trait_def.r#if.condition,
                        Condition::String { exact: Some(_), .. }
                    )
                    && trait_def.r#if.count_min.unwrap_or(1) == 1
                    && trait_def.r#if.count_max.is_none()
                    && trait_def.r#if.per_kb_min.is_none()
                    && trait_def.r#if.per_kb_max.is_none();

                if is_simple_exact_string {
                    // Use cached evidence directly - skip full evaluation
                    if let Some(evidence) = cached_evidence.get(&idx) {
                        if !evidence.is_empty() {
                            return Some(Finding {
                                id: trait_def.id.clone(),
                                desc: trait_def.desc.clone(),
                                conf: trait_def.conf,
                                crit: trait_def.crit,
                                mbc: trait_def.mbc.clone(),
                                attack: trait_def.attack.clone(),
                                evidence: evidence.clone(),
                                kind: FindingKind::Capability,
                                trait_refs: vec![],
                                source_file: get_relative_source_file(&trait_def.defined_in),
                            });
                        }
                    }
                    return None;
                }

                // Check if this trait has an exact string pattern that wasn't matched
                let has_exact_string = matches!(
                    trait_def.r#if.condition,
                    Condition::String { exact: Some(_), .. }
                );

                // If trait has an exact string pattern and it wasn't matched, skip it
                if has_exact_string && !string_matched_traits.contains(&idx) {
                    skip_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return None;
                }

                // If trait has a regex string pattern and its literal wasn't found, skip it
                if self.string_match_index.is_regex_trait(idx) && !regex_candidates.contains(&idx) {
                    skip_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return None;
                }

                // Check if this trait has a content-based regex/word pattern that wasn't matched
                let has_content_regex = matches!(
                    trait_def.r#if.condition,
                    Condition::Raw { regex: Some(_), .. } | Condition::Raw { word: Some(_), .. }
                );

                // Skip only when pre-filtering is enabled and this trait is indexed there.
                // Unindexed traits must still be evaluated normally.
                if has_content_regex
                    && raw_regex_prefilter_enabled
                    && self.raw_content_regex_index.is_indexed_trait(idx)
                    && !raw_regex_matched_traits.contains(&idx)
                {
                    skip_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return None;
                }

                // Skip conditions that can never match this file type
                // (e.g., binary-only conditions on source files)
                if !trait_def.r#if.can_match_file_type(&file_type) {
                    skip_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return None;
                }

                eval_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                trait_def.evaluate(&ctx)
            })
            .collect();

        // Deduplicate findings (keep first occurrence of each ID)
        let mut seen = std::collections::HashSet::new();
        let mut unique_findings: Vec<Finding> = all_findings
            .into_iter()
            .filter(|f| seen.insert(f.id.clone()))
            .collect();

        // Free excess capacity to reduce memory footprint
        unique_findings.shrink_to_fit();

        // Limit to reasonable maximum to prevent unbounded memory growth
        const MAX_FINDINGS_PER_FILE: usize = 500;
        if unique_findings.len() > MAX_FINDINGS_PER_FILE {
            // Keep highest priority findings (by criticality, then confidence)
            unique_findings.sort_by(|a, b| {
                b.crit.cmp(&a.crit).then_with(|| {
                    let conf_a = (a.conf * 100.0) as i32;
                    let conf_b = (b.conf * 100.0) as i32;
                    conf_b.cmp(&conf_a)
                })
            });
            unique_findings.truncate(MAX_FINDINGS_PER_FILE);
            unique_findings.shrink_to_fit();
        }

        unique_findings
    }

    /// Evaluate trait definitions against an analysis report (without cached AST)
    /// Wrapper for evaluate_traits_with_ast
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn evaluate_traits(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
    ) -> Vec<Finding> {
        self.evaluate_traits_with_ast(report, binary_data, None, None)
    }
}
