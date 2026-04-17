//! Atomic trait evaluation against analysis reports.
//!
//! This module handles the evaluation of atomic trait definitions, which are the building
//! blocks of the capability detection system. It includes optimizations like:
//! - Index-based filtering by file type
//! - Batched Aho-Corasick string matching with evidence caching
//! - Parallel evaluation of applicable traits
//! - Early termination for empty files

use crate::composite_rules::ast_kinds::map_kind_to_node_types;
use crate::composite_rules::{Arch, Condition, EvaluationContext, SectionMap};
use crate::types::{AnalysisReport, Evidence, Finding, FindingKind};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::HashMap;
use std::path::Path;

/// Pre-computed caches passed to trait evaluation to avoid redundant work.
pub(crate) struct TraitEvalCache<'a> {
    pub raw_regex_matches: Option<&'a FxHashSet<usize>>,
    pub section_map: &'a SectionMap,
    pub string_matched_traits: &'a FxHashSet<usize>,
    pub symbol_matched_traits: &'a FxHashSet<usize>,
    pub cached_evidence: &'a FxHashMap<usize, Vec<Evidence>>,
    pub regex_candidates: &'a FxHashSet<usize>,
    pub arch_ranges: Option<&'a [(Arch, std::ops::Range<usize>)]>,
    pub ast_kind_cache: Option<FxHashMap<String, Vec<Evidence>>>,
}

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

        // Build section map for location-constrained matching.
        // Skip parsing for files that don't have sections (saves ~100ms per file).
        let section_map = if file_type.has_sections() {
            SectionMap::from_binary(binary_data)
        } else {
            SectionMap::empty(binary_data.len() as u64)
        };

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
                            for nt in map_kind_to_node_types(k, file_type) {
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

        // Pre-filter using batched Aho-Corasick string matching WITH evidence caching
        let all_strings = super::build_all_strings(report);

        let (string_matched_traits, mut cached_evidence) = if self.string_match_index.has_patterns()
        {
            self.string_match_index
                .find_matches_with_evidence(&all_strings)
        } else {
            (FxHashSet::default(), FxHashMap::default())
        };

        // Run symbol matching ONCE across exact, substr, and regex patterns.
        // Evidence flows into cached_evidence so eval_symbol's FAST PATH 0 can
        // skip the per-symbol iteration on repeat trait evaluation.
        let all_symbols: Vec<String> = report
            .imports
            .iter()
            .map(|i| i.symbol.clone())
            .chain(report.exports.iter().map(|e| e.symbol.clone()))
            .collect();
        let (symbol_matched_traits, symbol_evidence) = self
            .symbol_match_index
            .find_matches_with_evidence(&all_symbols);
        for (trait_idx, mut ev) in symbol_evidence {
            cached_evidence
                .entry(trait_idx)
                .or_default()
                .append(&mut ev);
        }

        // Also find regex candidates based on literal prefix matching
        let regex_candidates = self.string_match_index.find_regex_candidates(&all_strings);

        // Pre-filter using batched regex matching for Content conditions
        let raw_regex_matches = self
            .raw_content_regex_index
            .find_matches(binary_data, &file_type);

        let cache = TraitEvalCache {
            raw_regex_matches: Some(&raw_regex_matches),
            section_map: &section_map,
            string_matched_traits: &string_matched_traits,
            symbol_matched_traits: &symbol_matched_traits,
            cached_evidence: &cached_evidence,
            regex_candidates: &regex_candidates,
            arch_ranges: None,
            ast_kind_cache,
        };

        // Pass 1: Evaluate independent traits
        let mut findings = self.evaluate_traits_filtered_with_cache(
            report,
            binary_data,
            cached_ast,
            inline_yara,
            false,
            &cache,
            None,
        );

        // Pass 2: Evaluate dependent traits (iteratively until fixed point)
        let mut report_with_findings = report.clone();
        report_with_findings
            .findings
            .extend(findings.iter().cloned());

        const MAX_ITERATIONS: usize = 10;
        for _ in 0..MAX_ITERATIONS {
            let dep_findings = self.evaluate_traits_filtered_with_cache(
                &report_with_findings,
                binary_data,
                cached_ast,
                inline_yara,
                true,
                &cache,
                None,
            );

            if dep_findings.is_empty() {
                break;
            }

            let mut new_added = false;
            for f in dep_findings {
                if !report_with_findings
                    .findings
                    .iter()
                    .any(|existing| existing.id == f.id)
                {
                    report_with_findings.findings.push(f.clone());
                    findings.push(f);
                    new_added = true;
                }
            }

            if !new_added {
                break;
            }
        }

        findings
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
        // Build section map
        // Skip parsing for files that don't have sections (saves ~100ms per file).
        let section_map = if file_type.has_sections() {
            SectionMap::from_binary(binary_data)
        } else {
            SectionMap::empty(binary_data.len() as u64)
        };

        // Build all_strings
        let all_strings = super::build_all_strings(report);
        let (string_matched_traits, mut cached_evidence) = if self.string_match_index.has_patterns()
        {
            self.string_match_index
                .find_matches_with_evidence(&all_strings)
        } else {
            (FxHashSet::default(), FxHashMap::default())
        };
        // Run symbol matching ONCE across exact, substr, and regex patterns.
        let all_symbols: Vec<String> = report
            .imports
            .iter()
            .map(|i| i.symbol.clone())
            .chain(report.exports.iter().map(|e| e.symbol.clone()))
            .collect();
        let (symbol_matched_traits, symbol_evidence) = self
            .symbol_match_index
            .find_matches_with_evidence(&all_symbols);
        for (trait_idx, mut ev) in symbol_evidence {
            cached_evidence
                .entry(trait_idx)
                .or_default()
                .append(&mut ev);
        }

        let regex_candidates = self.string_match_index.find_regex_candidates(&all_strings);
        drop(all_strings);

        self.evaluate_traits_filtered_with_cache(
            report,
            binary_data,
            cached_ast,
            inline_yara,
            dependent_only,
            &TraitEvalCache {
                raw_regex_matches: Some(&raw_regex_matches),
                section_map: &section_map,
                string_matched_traits: &string_matched_traits,
                symbol_matched_traits: &symbol_matched_traits,
                cached_evidence: &cached_evidence,
                regex_candidates: &regex_candidates,
                arch_ranges: None,
                ast_kind_cache: None,
            },
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
        cache: &TraitEvalCache<'_>,
        cancellation: Option<&std::sync::atomic::AtomicBool>,
    ) -> Vec<Finding> {
        // Determine file type from report
        let file_type = self.detect_file_type(&report.target.file_type);

        let mut ctx = EvaluationContext::new(
            report,
            binary_data,
            file_type,
            &self.platforms,
            None,
            cached_ast,
        )
        .with_section_map(cache.section_map)
        .with_cached_evidence(Some(cache.cached_evidence))
        .with_deadline(std::time::Instant::now() + std::time::Duration::from_secs(30))
        .with_slow_rule_ms(self.slow_rule_ms);

        if let Some(flag) = cancellation {
            ctx = ctx.with_cancellation(flag);
        }

        if let Some(ref ast_cache) = cache.ast_kind_cache {
            ctx = ctx.with_ast_kind_cache(ast_cache);
        }

        if let Some(results) = inline_yara {
            ctx = ctx.with_inline_yara(results);
        }
        if let Some(ranges) = cache.arch_ranges {
            ctx = ctx.with_arch_ranges(ranges);
        }

        // Use trait index to only evaluate applicable traits
        // This dramatically reduces work for specific file types
        let mut applicable_indices: Vec<usize> = self
            .trait_index
            .get_applicable(&file_type)
            .into_indices_static()
            .collect();

        let is_tiny_dos_com_candidate = file_type == crate::composite_rules::FileType::Unknown
            && binary_data.len() <= 4096
            && Path::new(&report.target.path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("com"));

        if is_tiny_dos_com_candidate {
            applicable_indices.retain(|&idx| {
                let trait_def = &self.trait_definitions[idx];
                let source = trait_def.defined_in.to_string_lossy();
                source.ends_with("/metadata/binary/layout/msdos.yaml")
                    || source.ends_with("/micro-behaviors/os/msdos/internal/signatures.yaml")
                    || source.ends_with("/micro-behaviors/os/msdos/interrupt/file_management.yaml")
                    || source.ends_with("/micro-behaviors/time/schedule/calendar/msdos.yaml")
                    || source.ends_with("/well-known/malware/virus/friday_the_13th/msdos.yaml")
            });
        }

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
        let raw_regex_prefilter_enabled = cache.raw_regex_matches.is_some();

        let has_any_matches = !cache.string_matched_traits.is_empty()
            || cache.raw_regex_matches.is_some_and(|s| !s.is_empty())
            || !cache.regex_candidates.is_empty();

        // For dependent traits, we can't skip based on string matches alone
        // because the trait: condition might match even if strings don't
        let has_strings =
            !report.strings.is_empty() || !report.imports.is_empty() || !report.exports.is_empty();
        if !dependent_only && !has_any_matches && !has_strings && binary_data.len() < 100 {
            return vec![];
        }

        let eval_trait = |&idx: &usize| {
            // Check cancellation before each trait — this is the innermost
            // loop that processes ~9000 traits per file, and is the main reason
            // analysis can't be interrupted once it enters trait evaluation.
            if ctx.is_cancelled() {
                return None;
            }

            let trait_def = &self.trait_definitions[idx];
            // For dependent traits, skip string-based optimizations since
            // we're matching on trait: conditions, not strings
            if !dependent_only {
                // Check if this is an exact string trait with cached evidence
                let is_simple_exact_string = trait_def.downgrade.is_none()
                    && matches!(
                        &trait_def.r#if,
                        Condition::StringValue { exact: Some(_), .. }
                    )
                    && trait_def.count_min.unwrap_or(1) == 1
                    && trait_def.count_max.is_none()
                    && trait_def.per_kb_min.is_none()
                    && trait_def.per_kb_max.is_none();

                if is_simple_exact_string {
                    if let Some(evidence) = cache.cached_evidence.get(&idx) {
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
                        Condition::StringValue {
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
                    if let Some(evidence) = cache.cached_evidence.get(&idx) {
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

                // Skip indexed exact traits that weren't matched
                if self.string_match_index.is_exact_trait(idx)
                    && !cache.string_matched_traits.contains(&idx)
                {
                    return None;
                }

                // Skip indexed substr traits that weren't matched
                if self.string_match_index.is_substr_trait(idx)
                    && !cache.string_matched_traits.contains(&idx)
                {
                    return None;
                }

                // Skip indexed symbol traits that weren't matched
                if self.symbol_match_index.is_symbol_trait(idx)
                    && !cache.symbol_matched_traits.contains(&idx)
                {
                    return None;
                }

                // Skip indexed symbol traits that weren't matched
                if self.symbol_match_index.is_symbol_trait(idx)
                    && !cache.symbol_matched_traits.contains(&idx)
                {
                    return None;
                }

                if self.string_match_index.is_regex_trait(idx)
                    && !cache.regex_candidates.contains(&idx)
                {
                    return None;
                }

                let has_content_regex = matches!(
                    trait_def.r#if,
                    Condition::Raw { regex: Some(_), .. } | Condition::Raw { word: Some(_), .. }
                );
                if has_content_regex
                    && raw_regex_prefilter_enabled
                    && self.raw_content_regex_index.is_indexed_trait(idx)
                    && cache.raw_regex_matches.is_some_and(|s| !s.contains(&idx))
                {
                    return None;
                }
            }

            if !trait_def.r#if.can_match_file_type(&file_type) {
                return None;
            }

            let mut trait_ctx = ctx.clone().with_trait_idx(idx);
            if trait_def.count_min.is_some()
                || trait_def.count_max.is_some()
                || trait_def.per_kb_min.is_some()
                || trait_def.per_kb_max.is_some()
            {
                trait_ctx.cached_evidence = None;
            }

            trait_def.evaluate(&trait_ctx)
        };

        let all_findings: Vec<Finding> = if std::env::var_os("CLEAVE_SERIAL_TRAITS").is_some() {
            filtered_indices.iter().filter_map(eval_trait).collect()
        } else {
            filtered_indices.par_iter().filter_map(eval_trait).collect()
        };

        // Deduplicate findings
        let mut seen = std::collections::HashSet::new();
        let mut unique_findings: Vec<Finding> = all_findings
            .into_iter()
            .filter(|f| seen.insert(f.id.clone()))
            .collect();

        unique_findings.shrink_to_fit();

        const MAX_FINDINGS_PER_FILE: usize = 500;
        if unique_findings.len() > MAX_FINDINGS_PER_FILE {
            unique_findings.sort_unstable_by(|a, b| {
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
