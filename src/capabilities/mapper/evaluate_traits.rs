//! Atomic trait evaluation against analysis reports.
//!
//! This module handles the evaluation of atomic trait definitions, which are the building
//! blocks of the capability detection system. It includes optimizations like:
//! - Index-based filtering by file type
//! - Batched Aho-Corasick string matching with evidence caching
//! - Parallel evaluation of applicable traits
//! - Early termination for empty files

use crate::composite_rules::{Arch, Condition, EvaluationContext, SectionMap};
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
        .with_section_map(section_map)
        .with_deadline(std::time::Instant::now() + std::time::Duration::from_secs(30))
        .with_slow_rule_ms(self.slow_rule_ms);
        if let Some(results) = inline_yara {
            ctx = ctx.with_inline_yara(results);
        }

        // Use trait index to only evaluate applicable traits
        // This dramatically reduces work for specific file types
        let applicable_indices: Vec<usize> = self.trait_index.get_applicable(&file_type).collect();

        // Pre-filter using batched Aho-Corasick string matching WITH evidence caching
        let _t_prematch = std::time::Instant::now();
        let all_strings = super::build_all_strings(report);

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
        let raw_regex_matches = if raw_regex_prefilter_enabled {
            self.raw_content_regex_index
                .find_matches(binary_data, &file_type)
        } else {
            FxHashSet::default()
        };

        // Evaluate only applicable traits in parallel
        // For exact string traits with cached evidence, use that directly instead of re-evaluating
        let _t_eval = std::time::Instant::now();

        // Early termination: if no strings and no pre-matched traits, skip evaluation
        let has_any_matches = !string_matched_traits.is_empty()
            || !raw_regex_matches.is_empty()
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
                    && matches!(&trait_def.r#if, Condition::String { exact: Some(_), .. })
                    && trait_def.count_min.unwrap_or(1) == 1
                    && trait_def.count_max.is_none()
                    && trait_def.per_kb_min.is_none()
                    && trait_def.per_kb_max.is_none();

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
                                match_count: 0,
                                kind: FindingKind::Capability,
                                trait_refs: vec![],
                                source_file: get_relative_source_file(&trait_def.defined_in),
                            });
                        }
                    }
                    return None;
                }

                // Fast path for simple substr patterns (no location constraints, no filters)
                let is_simple_substr_string = trait_def.downgrade.is_none()
                    && matches!(
                        &trait_def.r#if,
                        Condition::String {
                            substr: Some(_),
                            section: None,
                            offset: None,
                            offset_range: None,
                            section_offset: None,
                            section_offset_range: None,
                            ..
                        }
                    )
                    && trait_def.count_min.unwrap_or(1) == 1
                    && trait_def.count_max.is_none()
                    && trait_def.per_kb_min.is_none()
                    && trait_def.per_kb_max.is_none();

                if is_simple_substr_string {
                    // Use cached evidence from Aho-Corasick index
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
                                match_count: 0,
                                kind: FindingKind::Capability,
                                trait_refs: vec![],
                                source_file: get_relative_source_file(&trait_def.defined_in),
                            });
                        }
                    }
                    return None;
                }

                // Check if this trait has an exact string pattern that wasn't matched
                let has_exact_string =
                    matches!(trait_def.r#if, Condition::String { exact: Some(_), .. });

                // If trait has an exact string pattern and it wasn't matched, skip it
                if has_exact_string && !string_matched_traits.contains(&idx) {
                    skip_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return None;
                }

                // If trait has a substr string pattern that's indexed and wasn't matched, skip it
                if self.string_match_index.is_substr_trait(idx)
                    && !string_matched_traits.contains(&idx)
                {
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
                    trait_def.r#if,
                    Condition::Raw { regex: Some(_), .. } | Condition::Raw { word: Some(_), .. }
                );

                // Skip only when pre-filtering is enabled and this trait is indexed there.
                // Unindexed traits must still be evaluated normally.
                if has_content_regex
                    && raw_regex_prefilter_enabled
                    && self.raw_content_regex_index.is_indexed_trait(idx)
                    && !raw_regex_matches.contains(&idx)
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

    /// Evaluate traits filtered by dependency status.
    /// When `dependent_only` is false, evaluates only traits WITHOUT trait: dependencies.
    /// When `dependent_only` is true, evaluates only traits WITH trait: dependencies.
    ///
    /// This enables proper ordering: independent traits are evaluated first, then
    /// dependent traits can see their results via `report.findings`.
    #[must_use]
    #[allow(dead_code)] // May be used by tests or binary
    pub(crate) fn evaluate_traits_filtered(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
        dependent_only: bool,
    ) -> Vec<Finding> {
        // Compute raw regex matches (this is expensive but necessary if no cache provided)
        let file_type = self.detect_file_type(&report.target.file_type);
        let raw_regex_matches = if self.raw_content_regex_index.has_patterns() {
            self.raw_content_regex_index
                .find_matches(binary_data, &file_type)
        } else {
            FxHashSet::default()
        };
        let section_map = SectionMap::from_binary(binary_data);

        // Build all_strings
        let all_strings = super::build_all_strings(report);
        let (string_matched_traits, cached_evidence) = if self.string_match_index.has_patterns() {
            self.string_match_index
                .find_matches_with_evidence(&all_strings)
        } else {
            (FxHashSet::default(), FxHashMap::default())
        };
        let regex_candidates = self.string_match_index.find_regex_candidates(&all_strings);
        drop(all_strings);

        self.evaluate_traits_filtered_with_cache(
            report,
            binary_data,
            cached_ast,
            inline_yara,
            dependent_only,
            Some(&raw_regex_matches),
            &section_map,
            &string_matched_traits,
            &cached_evidence,
            &regex_candidates,
            None,
        )
    }

    /// Evaluate traits filtered by dependency status, with pre-computed raw regex matches.
    /// This is the optimized version that avoids recomputing regex matches on each call.
    #[must_use]
    pub(crate) fn evaluate_traits_filtered_with_cache(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
        dependent_only: bool,
        raw_regex_matches: Option<&FxHashSet<usize>>,
        section_map: &SectionMap,
        string_matched_traits: &FxHashSet<usize>,
        cached_evidence: &FxHashMap<usize, Vec<Evidence>>,
        regex_candidates: &FxHashSet<usize>,
        arch_ranges: Option<&[(Arch, std::ops::Range<usize>)]>,
    ) -> Vec<Finding> {
        // Determine file type from report
        let file_type = self.detect_file_type(&report.target.file_type);

        let mut ctx = EvaluationContext::new(
            report,
            binary_data,
            file_type,
            self.platforms.clone(),
            None,
            cached_ast,
        )
        .with_section_map(section_map.clone())
        .with_slow_rule_ms(self.slow_rule_ms);
        if let Some(results) = inline_yara {
            ctx = ctx.with_inline_yara(results);
        }
        if let Some(ranges) = arch_ranges {
            ctx = ctx.with_arch_ranges(ranges.to_vec());
        }

        // Get applicable traits filtered by file type
        let applicable_indices: Vec<usize> = self.trait_index.get_applicable(&file_type).collect();

        // Further filter by dependency status
        let filtered_indices: Vec<usize> = applicable_indices
            .into_iter()
            .filter(|&idx| {
                let trait_def = &self.trait_definitions[idx];
                trait_def.has_trait_dependency() == dependent_only
            })
            .collect();

        if filtered_indices.is_empty() {
            return vec![];
        }

        // Use pre-computed raw regex matches (passed in from caller)
        let raw_regex_prefilter_enabled = raw_regex_matches.is_some();

        let has_any_matches = !string_matched_traits.is_empty()
            || raw_regex_matches.is_some_and(|s| !s.is_empty())
            || !regex_candidates.is_empty();

        // For dependent traits, we can't skip based on string matches alone
        // because the trait: condition might match even if strings don't
        let has_strings =
            !report.strings.is_empty() || !report.imports.is_empty() || !report.exports.is_empty();
        if !dependent_only && !has_any_matches && !has_strings && binary_data.len() < 100 {
            return vec![];
        }

        let all_findings: Vec<Finding> = filtered_indices
            .par_iter()
            .with_min_len(64)
            .filter_map(|&idx| {
                let trait_def = &self.trait_definitions[idx];

                // For dependent traits, skip string-based optimizations since
                // we're matching on trait: conditions, not strings
                if !dependent_only {
                    // Check if this is an exact string trait with cached evidence
                    let is_simple_exact_string = trait_def.downgrade.is_none()
                        && matches!(&trait_def.r#if, Condition::String { exact: Some(_), .. })
                        && trait_def.count_min.unwrap_or(1) == 1
                        && trait_def.count_max.is_none()
                        && trait_def.per_kb_min.is_none()
                        && trait_def.per_kb_max.is_none();

                    if is_simple_exact_string {
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
                                    match_count: 0,
                                    kind: FindingKind::Capability,
                                    trait_refs: vec![],
                                    source_file: get_relative_source_file(&trait_def.defined_in),
                                });
                            }
                        }
                        return None;
                    }

                    // Fast path for simple substr patterns
                    let is_simple_substr_string = trait_def.downgrade.is_none()
                        && matches!(
                            &trait_def.r#if,
                            Condition::String {
                                substr: Some(_),
                                section: None,
                                offset: None,
                                offset_range: None,
                                section_offset: None,
                                section_offset_range: None,
                                ..
                            }
                        )
                        && trait_def.count_min.unwrap_or(1) == 1
                        && trait_def.count_max.is_none()
                        && trait_def.per_kb_min.is_none()
                        && trait_def.per_kb_max.is_none();

                    if is_simple_substr_string {
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
                                    match_count: 0,
                                    kind: FindingKind::Capability,
                                    trait_refs: vec![],
                                    source_file: get_relative_source_file(&trait_def.defined_in),
                                });
                            }
                        }
                        return None;
                    }

                    // String-based pre-filtering
                    let has_exact_string =
                        matches!(trait_def.r#if, Condition::String { exact: Some(_), .. });
                    if has_exact_string && !string_matched_traits.contains(&idx) {
                        return None;
                    }

                    // Skip indexed substr traits that weren't matched
                    if self.string_match_index.is_substr_trait(idx)
                        && !string_matched_traits.contains(&idx)
                    {
                        return None;
                    }

                    if self.string_match_index.is_regex_trait(idx)
                        && !regex_candidates.contains(&idx)
                    {
                        return None;
                    }

                    let has_content_regex = matches!(
                        trait_def.r#if,
                        Condition::Raw { regex: Some(_), .. }
                            | Condition::Raw { word: Some(_), .. }
                    );
                    if has_content_regex
                        && raw_regex_prefilter_enabled
                        && self.raw_content_regex_index.is_indexed_trait(idx)
                        && raw_regex_matches.is_some_and(|s| !s.contains(&idx))
                    {
                        return None;
                    }
                }

                if !trait_def.r#if.can_match_file_type(&file_type) {
                    return None;
                }

                trait_def.evaluate(&ctx)
            })
            .collect();

        // Deduplicate findings
        let mut seen = std::collections::HashSet::new();
        let mut unique_findings: Vec<Finding> = all_findings
            .into_iter()
            .filter(|f| seen.insert(f.id.clone()))
            .collect();

        unique_findings.shrink_to_fit();

        const MAX_FINDINGS_PER_FILE: usize = 500;
        if unique_findings.len() > MAX_FINDINGS_PER_FILE {
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
}
