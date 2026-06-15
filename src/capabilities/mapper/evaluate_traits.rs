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
use crate::composite_rules::{RawQuery, TextQuery, TreeSitterQuery};
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
    /// Pre-walk the cached AST once, collecting every node whose kind some
    /// applicable `kind:`/`node:` trait needs into a `kind → evidence` map (Idea
    /// 9). Call-expression nodes also carry the extracted function name in
    /// `alt_value` so `kind: call, exact: <name>` rules match `name(args)`.
    ///
    /// Returns `None` when there's no tree, the bytes aren't UTF-8, or no
    /// applicable trait asks for an AST node — the same conditions under which
    /// the per-trait path falls back to walking the tree itself. Shared by
    /// `evaluate_traits_with_ast` and the merged evaluation path so the two can't
    /// drift (a drift here silently drops `kind: call` matches on one path).
    pub(crate) fn build_ast_kind_cache(
        &self,
        cached_ast: Option<&tree_sitter::Tree>,
        binary_data: &[u8],
        applicable_indices: &[usize],
        file_type: crate::composite_rules::FileType,
    ) -> Option<FxHashMap<String, Vec<Evidence>>> {
        let tree = cached_ast?;
        let source = std::str::from_utf8(binary_data).ok()?;

        let mut required_node_types = FxHashSet::default();
        for &idx in applicable_indices {
            if let Condition::TreeSitter(TreeSitterQuery { kind, node, .. }) =
                &self.trait_definitions[idx].r#if
            {
                if let Some(k) = kind {
                    for nt in map_kind_to_node_types(k, file_type) {
                        required_node_types.insert(nt);
                    }
                } else if let Some(n) = node {
                    required_node_types.insert(n.as_str());
                }
            }
        }
        if required_node_types.is_empty() {
            return None;
        }

        // Call-node kinds for this file type get their function name lifted into
        // `alt_value` so natural `exact: foo` patterns match `foo(args)`.
        let call_node_types: FxHashSet<&'static str> = map_kind_to_node_types("call", file_type)
            .into_iter()
            .collect();
        let mut cache: FxHashMap<String, Vec<Evidence>> = FxHashMap::default();
        let mut cursor = tree.walk();
        crate::analyzers::ast_walker::walk_tree_with_stats(&mut cursor, None, |node, _| {
            let kind = node.kind();
            if required_node_types.contains(kind)
                && let Ok(text) = node.utf8_text(source.as_bytes())
            {
                let alt_value = if call_node_types.contains(kind) {
                    crate::analyzers::symbol_extraction::extract_function_name(
                        &node,
                        source.as_bytes(),
                    )
                } else {
                    None
                };
                cache.entry(kind.to_string()).or_default().push(Evidence {
                    method: "ast".to_string(),
                    source: "tree-sitter".to_string(),
                    value: crate::composite_rules::evaluators::truncate_evidence(text, 100),
                    location: Some(format!(
                        "{}:{}",
                        node.start_position().row + 1,
                        node.start_position().column + 1
                    )),
                    offsets: vec![node.start_byte() as u64],
                    alt_value,
                    ..Default::default()
                });
            }
            true
        });
        Some(cache)
    }

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

        // Build section map for location-constrained matching from the report's
        // already-populated sections. Standalone trait evaluation should not
        // parse file bytes just to rebuild data the analyzer already owns.
        let section_map = if file_type.has_sections() && !report.sections.is_empty() {
            SectionMap::from_report_sections(&report.sections, binary_data.len() as u64)
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
        let ast_kind_cache =
            self.build_ast_kind_cache(cached_ast, binary_data, &applicable_indices, file_type);

        // Pre-filter using batched Aho-Corasick string matching WITH evidence
        // caching. The haystack borrows `report.strings` and only owns the small
        // import/export pseudo-entries, avoiding a deep copy of every string.
        let pseudo_strings = super::build_string_pseudo_entries(report);
        let all_strings: Vec<&crate::types::StringInfo> =
            report.strings.iter().chain(pseudo_strings.iter()).collect();

        let (string_matched_traits, mut cached_evidence) = if self.string_match_index.has_patterns()
        {
            self.string_match_index
                .find_matches_with_evidence(&all_strings)
        } else {
            (FxHashSet::default(), FxHashMap::default())
        };

        // Run symbol matching ONCE across exact, substr, and regex patterns.
        // Evidence flows into cached_evidence so eval_symbol's FAST PATH 0 can
        // skip the per-symbol iteration on repeat trait evaluation. The
        // haystack spans imports/exports plus filefacts call/member/bind/
        // identifier names (see `build_all_symbols`).
        let all_symbols = super::build_all_symbols(report);
        let (symbol_matched_traits, symbol_evidence) = self
            .symbol_match_index
            .find_matches_with_evidence(&all_symbols);
        let symbol_offsets = super::build_symbol_offset_map(report);
        for (trait_idx, mut ev) in symbol_evidence {
            super::fill_symbol_evidence_locations(&mut ev, &symbol_offsets);
            ev.retain(|item| item.location.is_some());
            if !ev.is_empty() {
                cached_evidence
                    .entry(trait_idx)
                    .or_default()
                    .append(&mut ev);
            }
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
        // Build section map from existing report sections. This keeps the
        // standalone API parse-free; callers that need section constraints must
        // provide a report populated by the structural analyzer.
        let section_map = if file_type.has_sections() && !report.sections.is_empty() {
            SectionMap::from_report_sections(&report.sections, binary_data.len() as u64)
        } else {
            SectionMap::empty(binary_data.len() as u64)
        };

        // Build the string haystack — borrow report.strings, own only pseudo-entries.
        let pseudo_strings = super::build_string_pseudo_entries(report);
        let all_strings: Vec<&crate::types::StringInfo> =
            report.strings.iter().chain(pseudo_strings.iter()).collect();
        let (string_matched_traits, mut cached_evidence) = if self.string_match_index.has_patterns()
        {
            self.string_match_index
                .find_matches_with_evidence(&all_strings)
        } else {
            (FxHashSet::default(), FxHashMap::default())
        };
        // Run symbol matching ONCE across exact, substr, and regex patterns.
        // Haystack spans imports/exports plus filefacts call/member/bind/
        // identifier names (see `build_all_symbols`).
        let all_symbols = super::build_all_symbols(report);
        let (symbol_matched_traits, symbol_evidence) = self
            .symbol_match_index
            .find_matches_with_evidence(&all_symbols);
        let symbol_offsets = super::build_symbol_offset_map(report);
        for (trait_idx, mut ev) in symbol_evidence {
            super::fill_symbol_evidence_locations(&mut ev, &symbol_offsets);
            ev.retain(|item| item.location.is_some());
            if !ev.is_empty() {
                cached_evidence
                    .entry(trait_idx)
                    .or_default()
                    .append(&mut ev);
            }
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
        let use_string_prefilters = !file_type.uses_raw_text_search();

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
        .with_deadline(std::time::Instant::now() + std::time::Duration::from_secs(90))
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
        // because the trait: condition might match even if strings don't.
        // Source-AST facts (calls/members/binds/identifiers) also count: a
        // tiny source file like `process.env` carries no extracted strings or
        // imports but does carry member facts that `kind: member` traits match.
        let has_strings = !report.strings.is_empty()
            || !report.imports.is_empty()
            || !report.exports.is_empty()
            || report
                .filefacts
                .as_ref()
                .is_some_and(|v| !v.symbols.is_empty());
        // Structured manifests carry their signal as parsed KV fields, not
        // extracted strings: a 94-byte skeleton `package.json`
        // (`{"name","version","license"}`) has zero strings yet `value:`/kv
        // traits match its fields by reparsing the content. Skipping it would
        // blind us to sub-100-byte namespace-squatting manifests — exactly the
        // supply-chain shape worth flagging — so never short-circuit them.
        let is_structured_manifest =
            crate::composite_rules::evaluators::kv::structured_format_from_file_type(&file_type)
                != crate::composite_rules::evaluators::kv::StructuredFormat::Unknown;
        if !dependent_only
            && !has_any_matches
            && !has_strings
            && !is_structured_manifest
            && binary_data.len() < 100
        {
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
            // we're matching on trait: conditions, not strings.
            //
            // Also skip them for raw-text source files. The string index is built from
            // extracted string literals/imports/exports, but `type: text` on source
            // files matches against the full source text. Using the extracted-string
            // index as a prefilter is therefore unsound and can drop true positives
            // for patterns that span syntax, such as `require('./prebuilt/addon.node')`
            // or `module.exports = { version: require('./package.json').version }`.
            if !dependent_only && use_string_prefilters {
                // Check if this is an exact string trait with cached evidence
                let is_simple_exact_string = trait_def.downgrade.is_none()
                    && matches!(
                        &trait_def.r#if,
                        Condition::Text(TextQuery {
                            exact: Some(_),
                            section: None,
                            offset: None,
                            offset_range: None,
                            section_offset: None,
                            section_offset_range: None,
                            ..
                        })
                    )
                    && trait_def.count_min.unwrap_or(1) == 1
                    && trait_def.count_max.is_none()
                    && trait_def.per_kb_min.is_none()
                    && trait_def.per_kb_max.is_none();

                if is_simple_exact_string {
                    if let Some(evidence) = cache.cached_evidence.get(&idx)
                        && !evidence.is_empty()
                    {
                        return Some(Finding {
                            src: None,
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
                    return None;
                }

                // Fast path for simple substr patterns
                let is_simple_substr_string = trait_def.downgrade.is_none()
                    && matches!(
                        &trait_def.r#if,
                        Condition::Text(TextQuery {
                            substr: Some(_),
                            section: None,
                            offset: None,
                            offset_range: None,
                            section_offset: None,
                            section_offset_range: None,
                            ..
                        })
                    )
                    && trait_def.count_min.unwrap_or(1) == 1
                    && trait_def.count_max.is_none()
                    && trait_def.per_kb_min.is_none()
                    && trait_def.per_kb_max.is_none();

                if is_simple_substr_string {
                    if let Some(evidence) = cache.cached_evidence.get(&idx)
                        && !evidence.is_empty()
                    {
                        return Some(Finding {
                            src: None,
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

                if self.string_match_index.is_regex_trait(idx)
                    && !cache.regex_candidates.contains(&idx)
                {
                    return None;
                }

                // `type: raw` always searches raw content; `type: text` searches
                // raw content only on `uses_raw_text_search` files (else it reads
                // extracted strings, which this raw-content prefilter can't gate).
                // Both are gated by the raw-content atom prefilter (text via the
                // candidate-only substring/word path — see `RawContentRegexIndex`).
                let has_content_regex = match &trait_def.r#if {
                    Condition::Raw(RawQuery { regex: Some(_), .. })
                    | Condition::Raw(RawQuery { word: Some(_), .. }) => true,
                    Condition::Text(TextQuery { regex: Some(_), .. })
                    | Condition::Text(TextQuery { word: Some(_), .. }) => {
                        file_type.uses_raw_text_search()
                    }
                    _ => false,
                };
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
