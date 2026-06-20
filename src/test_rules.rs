//! Debug/test rule evaluation module.
//!
//! This module provides detailed tracing of rule evaluation for debugging purposes.
//! It uses the debug collector pattern to capture evaluation details from the real
//! evaluation code path, ensuring consistency between test-rules and production.
//!
//! It shows exactly why rules match or fail, including:
//! - For composites: which conditions matched and which didn't
//! - What values were actually matched against
//! - Regex patterns being used
//! - Context about available data (strings, symbols, etc.)
//! - Size constraints, downgrade evaluation, proximity constraints

use crate::capabilities::CapabilityMapper;
use crate::capabilities::validation::{
    atomic_calibrated_max, calculate_composite_precision, composite_calibrated_max,
    composite_inflation_warning_threshold, file_type_precision_penalty, platform_precision_penalty,
};
use crate::composite_rules::debug::{DebugCollector, EvaluationDebug, RuleType};
use crate::composite_rules::{
    Arch, CompositeTrait, Condition, EvaluationContext, FileType as RuleFileType, KvQuery,
    Platform, SectionMap, TraitDefinition,
};
use crate::composite_rules::{
    HexQuery, MetricsQuery, PathQuery, RawQuery, SectionQuery, SymbolQuery, TextQuery,
    TreeSitterQuery,
};
use crate::types::{AnalysisReport, Evidence};
use colored::Colorize;
use rustc_hash::FxHashSet;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::hash_str;

/// Result of debugging a single condition
#[derive(Debug)]
pub(crate) struct ConditionDebugResult {
    pub condition_desc: String,
    pub matched: bool,
    pub evidence: Vec<Evidence>,
    pub details: Vec<String>,
    pub sub_results: Vec<ConditionDebugResult>,
}

impl ConditionDebugResult {
    fn new(condition_desc: String, matched: bool) -> Self {
        Self {
            condition_desc,
            matched,
            evidence: Vec::new(),
            details: Vec::new(),
            sub_results: Vec::new(),
        }
    }

    fn with_evidence(mut self, evidence: Vec<Evidence>) -> Self {
        self.evidence = evidence;
        self
    }
}

/// Result of debugging an entire rule
#[derive(Debug)]
pub(crate) struct RuleDebugResult {
    pub rule_id: String,
    pub rule_type: String, // "trait" or "composite"
    pub description: String,
    pub matched: bool,
    pub skipped_reason: Option<String>,
    pub requirements: String,
    pub condition_results: Vec<ConditionDebugResult>,
    pub context_info: ContextInfo,
    pub precision: Option<f32>,
    pub precision_details: Vec<String>,
}

/// Information about the analysis context
#[derive(Debug, Default)]
pub(crate) struct ContextInfo {
    pub file_type: String,
    pub platforms: String,
    pub string_count: usize,
    pub symbol_count: usize,
    pub finding_count: usize,
}

/// Debug evaluator that traces through rule matching
pub(crate) struct RuleDebugger<'a> {
    mapper: &'a CapabilityMapper,
    report: &'a AnalysisReport,
    binary_data: &'a [u8],
    file_type: RuleFileType,
    platforms: Vec<Platform>,
    composites: &'a [CompositeTrait],
    traits: &'a [TraitDefinition],
    section_map: SectionMap,
    inline_yara_results: Option<&'a HashMap<String, Vec<Evidence>>>,
    parsed: Option<filefacts::ParsedFile<'a>>,
}

impl<'a> RuleDebugger<'a> {
    /// Create a new rule debugger.
    ///
    /// # Arguments
    /// * `mapper` - The capability mapper with rule definitions
    /// * `report` - The analysis report for the target file
    /// * `binary_data` - Raw file contents
    /// * `platforms` - Platform filter from CLI (use vec![Platform::All] to show all)
    /// * `inline_yara_results` - Pre-scanned inline YARA results (matches production path)
    pub(crate) fn new(
        mapper: &'a CapabilityMapper,
        report: &'a AnalysisReport,
        binary_data: &'a [u8],
        platforms: Vec<Platform>,
        inline_yara_results: Option<&'a HashMap<String, Vec<Evidence>>>,
    ) -> Self {
        let file_type = detect_file_type(&report.target.file_type);
        let section_map = SectionMap::from_binary(binary_data);

        // Parse via filefacts so AST conditions have a real tree to walk.
        // `values()` primes the parse so `source_ast()` returns Some.
        let parsed =
            filefacts::open_with_path(std::path::Path::new(&report.target.path), binary_data).ok();
        if let Some(ref p) = parsed {
            let _ = p.values();
        }

        Self {
            mapper,
            report,
            binary_data,
            file_type,
            platforms,
            composites: mapper.composite_rules(),
            traits: mapper.trait_definitions(),
            section_map,
            inline_yara_results,
            parsed,
        }
    }

    /// Get context information about the analysis
    pub(crate) fn context_info(&self) -> ContextInfo {
        ContextInfo {
            file_type: format!("{:?}", self.file_type),
            platforms: format!("{:?}", self.platforms),
            string_count: self.report.strings.len(),
            symbol_count: self.report.imports.len() + self.report.exports.len(),
            finding_count: self.report.findings.len(),
        }
    }

    /// Build a finding ID index for the context
    fn build_finding_index(&self) -> FxHashSet<u64> {
        let mut index = FxHashSet::default();
        for finding in &self.report.findings {
            index.insert(hash_str(&finding.id));
        }
        index
    }

    /// Resolve location constraints to an effective byte range for searching.
    /// Returns (start, end) where the search should occur.
    fn resolve_search_range(
        &self,
        section: Option<&String>,
        offset: Option<i64>,
        offset_range: Option<&(i64, Option<i64>)>,
        section_offset: Option<i64>,
        section_offset_range: Option<&(i64, Option<i64>)>,
        file_size: usize,
    ) -> (usize, usize) {
        let file_size_i64 = file_size as i64;

        // First, try using SectionMap if we have section constraints
        if let Some(sec_name) = section
            && let Some((sec_start, sec_end)) = self.section_map.bounds(sec_name)
        {
            let sec_start = sec_start as usize;
            let sec_end = sec_end as usize;
            let sec_len = sec_end - sec_start;
            // Apply section-relative constraints
            if let Some(sec_off) = section_offset {
                let resolved = if sec_off < 0 {
                    (sec_len as i64 + sec_off).max(0) as usize
                } else {
                    (sec_off as usize).min(sec_len)
                };
                return (sec_start + resolved, sec_end);
            }
            if let Some((start, end_opt)) = section_offset_range {
                let start_resolved = if *start < 0 {
                    (sec_len as i64 + *start).max(0) as usize
                } else {
                    (*start as usize).min(sec_len)
                };
                let end_resolved = match end_opt {
                    None => sec_len,
                    Some(e) if *e < 0 => (sec_len as i64 + *e).max(0) as usize,
                    Some(e) => (*e as usize).min(sec_len),
                };
                return (sec_start + start_resolved, sec_start + end_resolved);
            }
            // Just section constraint, no offset within it
            return (sec_start, sec_end);
        }

        // Handle absolute offset constraints
        if let Some(off) = offset {
            let resolved = if off < 0 {
                (file_size_i64 + off).max(0) as usize
            } else {
                (off as usize).min(file_size)
            };
            return (resolved, file_size);
        }

        if let Some((start, end_opt)) = offset_range {
            let start_resolved = if *start < 0 {
                (file_size_i64 + *start).max(0) as usize
            } else {
                (*start as usize).min(file_size)
            };
            let end_resolved = match end_opt {
                None => file_size,
                Some(e) if *e < 0 => (file_size_i64 + *e).max(0) as usize,
                Some(e) => (*e as usize).min(file_size),
            };
            return (start_resolved, end_resolved);
        }

        // No constraints - search entire file
        (0, file_size)
    }

    /// Create an evaluation context with an optional debug collector.
    /// Uses the same inline YARA results as production for consistent evaluation.
    fn create_eval_context<'b>(
        &'b self,
        debug_collector: Option<&'b DebugCollector>,
    ) -> EvaluationContext<'b>
    where
        'a: 'b,
    {
        EvaluationContext {
            report: self.report,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platforms: &self.platforms,
            arch: vec![Arch::All].into(),
            arch_ranges: None,
            additional_findings: None,
            cached_ast: self
                .parsed
                .as_ref()
                .and_then(filefacts::ParsedFile::source_ast)
                .map(|a| a.tree),
            ast_kind_cache: None,
            finding_id_index: Some(std::sync::Arc::new(self.build_finding_index())),
            debug_collector,
            section_map: Some(&self.section_map),
            inline_yara_results: self.inline_yara_results,
            cached_kv_format: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_kv_parsed: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_kv_offsets: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_lower_binary: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index_ci: std::sync::Arc::new(std::sync::OnceLock::new()),
            encoded_string_indices: std::sync::Arc::new(std::sync::OnceLock::new()),
            deadline: None,
            slow_rule_ms: 4000,
            cached_evidence: None,
            current_trait_idx: None,
            cached_source_utf8: std::str::from_utf8(self.binary_data).ok(),
            cancellation: None,
        }
    }

    /// Debug a trait by running real evaluation with debug collector
    fn debug_trait_via_evaluation(&self, trait_def: &TraitDefinition) -> RuleDebugResult {
        // Create debug collector
        let debug = RwLock::new(EvaluationDebug::new(&trait_def.id, RuleType::Trait));

        // Create context with debug collector
        let ctx = self.create_eval_context(Some(&debug));

        // Run real evaluation
        let finding = trait_def.evaluate(&ctx);

        // Extract debug info
        let eval_debug = debug
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Convert to RuleDebugResult
        let mut result = self.convert_eval_debug_to_result(
            eval_debug,
            trait_def,
            finding.is_some(),
            &trait_def.r#if,
        );

        // Add warning about trait-level `not` exclusions
        if let Some(not_exceptions) = &trait_def.not
            && !not_exceptions.is_empty()
            && !result.condition_results.is_empty()
        {
            let not_warning = ConditionDebugResult::new(
                format!(
                    "⚠️  {} trait-level not: exclusion(s) may filter matches in production",
                    not_exceptions.len()
                ),
                true, // just informational
            );
            result.condition_results.push(not_warning);
        }

        result
    }

    /// Debug a composite by running real evaluation with debug collector
    fn debug_composite_via_evaluation(&self, composite: &CompositeTrait) -> RuleDebugResult {
        // Create debug collector
        let debug = RwLock::new(EvaluationDebug::new(&composite.id, RuleType::Composite));

        // Create context with debug collector
        let ctx = self.create_eval_context(Some(&debug));

        // Run real evaluation
        let finding = composite.evaluate(&ctx);

        // Extract debug info
        let eval_debug = debug
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Convert to RuleDebugResult, using composite requirements
        let requirements = build_composite_requirements(composite);
        self.convert_composite_debug_to_result(
            eval_debug,
            composite,
            finding.is_some(),
            &requirements,
        )
    }

    /// Convert EvaluationDebug to RuleDebugResult for traits
    fn convert_eval_debug_to_result(
        &self,
        eval_debug: EvaluationDebug,
        trait_def: &TraitDefinition,
        matched: bool,
        condition: &Condition,
    ) -> RuleDebugResult {
        // Calculate precision
        let mut cache = HashMap::new();
        let mut visiting = HashSet::new();
        // Build lookup tables for O(1) access
        let composite_lookup: HashMap<&str, &CompositeTrait> =
            self.composites.iter().map(|r| (r.id.as_str(), r)).collect();
        let trait_lookup: HashMap<&str, &TraitDefinition> =
            self.traits.iter().map(|t| (t.id.as_str(), t)).collect();
        let precision_value = calculate_composite_precision(
            &trait_def.id,
            &composite_lookup,
            &trait_lookup,
            &mut cache,
            &mut visiting,
        );

        let skipped_reason = eval_debug.skip_reason.map(|r| r.to_string());

        // If skipped, return early with skip reason
        if skipped_reason.is_some() {
            return RuleDebugResult {
                rule_id: trait_def.id.to_string(),
                rule_type: "trait".to_string(),
                description: trait_def.desc.to_string(),
                matched: false,
                skipped_reason,
                requirements: format!("Condition: {:?}", describe_condition(condition)),
                condition_results: Vec::new(),
                context_info: self.context_info(),
                precision: Some(precision_value),
                precision_details: precision_detail_lines(None, Some(trait_def)),
            };
        }

        // For matched/unmatched, still use debug_condition for detailed condition info.
        // Short-circuit self-referencing traits — `if: type: trait, id: <self>`
        // would otherwise loop through `debug_trait_reference` →
        // `debug_trait_via_evaluation` → here forever and overflow the stack.
        let cond_result = if let Condition::Trait { id } = condition {
            if id == &trait_def.id {
                ConditionDebugResult::new(
                    format!("trait: {id} (self-reference — never fires)"),
                    false,
                )
            } else {
                self.debug_condition(condition)
            }
        } else {
            self.debug_condition(condition)
        };

        RuleDebugResult {
            rule_id: trait_def.id.to_string(),
            rule_type: "trait".to_string(),
            description: trait_def.desc.to_string(),
            matched,
            skipped_reason: None,
            requirements: format!("Condition: {:?}", describe_condition(condition)),
            condition_results: vec![cond_result],
            context_info: self.context_info(),
            precision: Some(precision_value),
            precision_details: precision_detail_lines(None, Some(trait_def)),
        }
    }

    /// Convert EvaluationDebug to RuleDebugResult for composites
    fn convert_composite_debug_to_result(
        &self,
        eval_debug: EvaluationDebug,
        composite: &CompositeTrait,
        matched: bool,
        requirements: &str,
    ) -> RuleDebugResult {
        // Use stored precision if available, otherwise calculate
        let precision_value = if let Some(cached) = composite.precision {
            cached
        } else {
            let mut cache = HashMap::new();
            let mut visiting = HashSet::new();
            // Build lookup tables for O(1) access
            let composite_lookup: HashMap<&str, &CompositeTrait> =
                self.composites.iter().map(|r| (r.id.as_str(), r)).collect();
            let trait_lookup: HashMap<&str, &TraitDefinition> =
                self.traits.iter().map(|t| (t.id.as_str(), t)).collect();
            calculate_composite_precision(
                &composite.id,
                &composite_lookup,
                &trait_lookup,
                &mut cache,
                &mut visiting,
            )
        };

        let skipped_reason = eval_debug.skip_reason.map(|r| r.to_string());

        // If skipped, return early with skip reason
        if skipped_reason.is_some() {
            return RuleDebugResult {
                rule_id: composite.id.clone(),
                rule_type: "composite".to_string(),
                description: composite.desc.clone(),
                matched: false,
                skipped_reason,
                requirements: requirements.to_string(),
                condition_results: Vec::new(),
                context_info: self.context_info(),
                precision: Some(precision_value),
                precision_details: precision_detail_lines(Some(composite), None),
            };
        }

        // Build detailed condition results using existing debug logic
        let mut condition_results = Vec::new();

        // Evaluate 'all' conditions
        if let Some(all_conds) = &composite.all {
            let mut all_results = Vec::new();
            let mut all_matched_count = 0;
            for cond in all_conds {
                let cond_result = self.debug_condition(cond);
                if cond_result.matched {
                    all_matched_count += 1;
                }
                all_results.push(cond_result);
            }
            let all_matched = all_matched_count == all_conds.len();
            let mut group = ConditionDebugResult::new(
                format!("all: ({}/{})", all_matched_count, all_conds.len()),
                all_matched,
            );
            group.sub_results = all_results;
            condition_results.push(group);
        }

        // Evaluate 'any' conditions
        if let Some(any_conds) = &composite.any {
            let mut any_results = Vec::new();
            let mut any_matched_count = 0;
            for cond in any_conds {
                let cond_result = self.debug_condition(cond);
                if cond_result.matched {
                    // Mirror the engine's `condition_count_weight`: a matched
                    // directory-prefix trait reference contributes the number of
                    // distinct member traits it matched, not 1. Otherwise `needs:`
                    // over a single dir-ref displays a misleading "1/1 needed: 2"
                    // next to an overall MATCHED verdict.
                    any_matched_count += self.condition_match_weight(cond);
                }
                any_results.push(cond_result);
            }
            let needs = composite.needs.unwrap_or(1);
            let any_satisfied = any_matched_count >= needs;
            let mut group = ConditionDebugResult::new(
                format!(
                    "any: ({}/{} needed: {})",
                    any_matched_count,
                    any_conds.len(),
                    needs
                ),
                any_satisfied,
            );
            group.sub_results = any_results;
            condition_results.push(group);
        }

        // Add downgrade info if present
        if let Some(downgrade) = eval_debug.downgrade {
            let downgrade_desc = if downgrade.triggered {
                format!(
                    "Downgrade: {:?} -> {:?} (triggered)",
                    downgrade.original_crit, downgrade.final_crit
                )
            } else {
                format!(
                    "Downgrade: not triggered (stays {:?})",
                    downgrade.original_crit
                )
            };
            condition_results.push(ConditionDebugResult::new(
                downgrade_desc,
                downgrade.triggered,
            ));
        }

        // Add proximity info if present
        if let Some(proximity) = eval_debug.proximity {
            let proximity_desc = format!(
                "Proximity ({}): max_span={}, satisfied={}",
                proximity.constraint_type, proximity.max_span, proximity.satisfied
            );
            condition_results.push(ConditionDebugResult::new(
                proximity_desc,
                proximity.satisfied,
            ));
        }

        RuleDebugResult {
            rule_id: composite.id.clone(),
            rule_type: "composite".to_string(),
            description: composite.desc.clone(),
            matched,
            skipped_reason: None,
            requirements: requirements.to_string(),
            condition_results,
            context_info: self.context_info(),
            precision: Some(precision_value),
            precision_details: precision_detail_lines(Some(composite), None),
        }
    }

    /// Debug a specific rule by ID
    pub(crate) fn debug_rule(&self, rule_id: &str) -> Option<RuleDebugResult> {
        // First try to find as a trait definition
        if let Some(trait_def) = self.find_trait_definition(rule_id) {
            return Some(self.debug_trait_via_evaluation(trait_def));
        }

        // Then try as a composite rule
        if let Some(composite) = self.find_composite_rule(rule_id) {
            return Some(self.debug_composite_via_evaluation(composite));
        }

        None
    }

    /// Display-side mirror of the engine's `condition_count_weight`: a matched
    /// directory-prefix trait reference (`a/b/c`, no `::`) counts as the number
    /// of distinct member findings it matched; every other condition counts as 1.
    fn condition_match_weight(&self, condition: &Condition) -> usize {
        if let Condition::Trait { id } = condition {
            let id = id.trim_end_matches('/');
            if !id.contains("::") && id.contains('/') {
                let prefix_new = format!("{}::", id);
                let prefix_legacy = format!("{}/", id);
                let n = self
                    .report
                    .findings
                    .iter()
                    .filter(|f| f.id.starts_with(&prefix_new) || f.id.starts_with(&prefix_legacy))
                    .count();
                return n.max(1);
            }
        }
        1
    }

    /// Debug a single condition
    fn debug_condition(&self, condition: &Condition) -> ConditionDebugResult {
        let ctx = EvaluationContext {
            report: self.report,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platforms: &self.platforms,
            arch: vec![Arch::All].into(),
            arch_ranges: None,
            additional_findings: None,
            cached_ast: None,
            ast_kind_cache: None,
            finding_id_index: None,
            debug_collector: None,
            section_map: Some(&self.section_map),
            inline_yara_results: None,
            cached_kv_format: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_kv_parsed: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_kv_offsets: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_lower_binary: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index_ci: std::sync::Arc::new(std::sync::OnceLock::new()),
            encoded_string_indices: std::sync::Arc::new(std::sync::OnceLock::new()),
            deadline: None,
            slow_rule_ms: 4000,
            cached_evidence: None,
            current_trait_idx: None,
            cached_source_utf8: None,
            cancellation: None,
        };

        match condition {
            Condition::Trait { id } => self.debug_trait_reference(id),
            Condition::Symbol(SymbolQuery {
                exact,
                substr,
                regex,
                ..
            }) => self.debug_symbol_condition(exact, substr, regex),
            Condition::Metrics(MetricsQuery {
                field, min, max, ..
            }) => self.debug_metrics_condition(field, *min, *max),
            Condition::Yara { source, .. } => self.debug_yara_inline_condition(source),
            Condition::Raw(RawQuery {
                regex,
                substr,
                exact,
                word,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            }) => self.debug_raw_condition(
                exact,
                substr,
                regex,
                word,
                section.as_ref(),
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
            ),
            Condition::TreeSitter(TreeSitterQuery {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                case_insensitive,
                ..
            }) => {
                self.debug_ast_condition(kind, node, exact, substr, regex, query, *case_insensitive)
            }
            Condition::Kv(KvQuery {
                path,
                exact,
                substr,
                regex,
                case_insensitive,
                exists,
                size_min,
                size_max,
                ..
            }) => self.debug_kv_condition(
                path,
                exact,
                substr,
                regex,
                *case_insensitive,
                *exists,
                *size_min,
                *size_max,
            ),
            Condition::Hex(HexQuery {
                pattern,
                offset,
                offset_range,
                section,
                section_offset,
                section_offset_range,
                ..
            }) => self.debug_hex_condition(
                pattern,
                *offset,
                *offset_range,
                section.as_deref(),
                *section_offset,
                *section_offset_range,
            ),
            Condition::Text(TextQuery {
                exact,
                substr,
                regex,
                case_insensitive,
                ..
            }) => {
                let desc = describe_condition(condition);
                let result = evaluate_condition_simple(condition, &ctx);
                let mut debug =
                    ConditionDebugResult::new(desc, result.matched).with_evidence(result.evidence);
                // When a raw-text-mode file fails `text exact:` but the pattern is present as
                // substring, surface the per-line semantic explicitly. Authors hit this when
                // they expect `exact:` to find an identifier anywhere in source code.
                if !result.matched
                    && self.file_type.uses_raw_text_search()
                    && exact.is_some()
                    && substr.is_none()
                    && regex.is_none()
                    && let Some(pat) = exact
                {
                    let hit = if *case_insensitive {
                        String::from_utf8_lossy(self.binary_data)
                            .to_ascii_lowercase()
                            .contains(&pat.to_ascii_lowercase())
                    } else {
                        String::from_utf8_lossy(self.binary_data).contains(pat.as_str())
                    };
                    if hit {
                        debug.details.push(format!(
                            "💡 '{pat}' appears as substring but never as a standalone line."
                        ));
                        debug.details.push(
                                "   In raw-text mode (source/manifests), `text exact:` matches a complete trimmed line.".to_string(),
                            );
                        debug.details.push(
                                "   Use `substr:` to match anywhere in the file, or `regex: '\\b<pat>\\b'` for word-boundary match.".to_string(),
                            );
                    }
                }
                debug
            }
            _ => {
                // Generic fallback for other condition types
                let desc = describe_condition(condition);
                let result = evaluate_condition_simple(condition, &ctx);
                ConditionDebugResult::new(desc, result.matched).with_evidence(result.evidence)
            }
        }
    }

    fn debug_trait_reference(&self, id: &str) -> ConditionDebugResult {
        let id = id.trim_end_matches('/');
        let desc = format!("trait: {}", id);

        // Mirror eval_trait() logic: check findings FIRST, then re-evaluate if needed
        // This ensures debug output matches actual evaluation behavior

        // Step 1: Check exact match in findings (like eval_trait fast path)
        let exact_match: Vec<_> = self.report.findings.iter().filter(|f| f.id == id).collect();

        if !exact_match.is_empty() {
            let mut result = ConditionDebugResult::new(desc, true);
            result.details.push(format!(
                "✓ Found exact match in findings: {}",
                exact_match[0].id
            ));
            result.evidence = exact_match
                .iter()
                .flat_map(|f| f.evidence.iter().cloned())
                .collect();
            return result;
        }

        // Step 2: Check prefix/suffix matching (like eval_trait slow path)
        let slash_count = id.matches('/').count();

        // Mirror eval_trait()'s slow path: both `::` (current trait id
        // separator) and `/` (legacy form) must be checked. Earlier
        // this only checked `/`, so directory-prefix references like
        // `micro-behaviors/dylib/library/libc` reported "not found"
        // even when `…/libc::libc-version-string` was firing — yielding
        // MATCHED-header / 0-of-N-body divergence.
        if slash_count == 0 {
            // Short name: suffix match for same-directory relative reference.
            let suffix_new = format!("::{}", id);
            let suffix_legacy = format!("/{}", id);
            let matching_findings: Vec<_> = self
                .report
                .findings
                .iter()
                .filter(|f| f.id.ends_with(&suffix_new) || f.id.ends_with(&suffix_legacy))
                .collect();

            if !matching_findings.is_empty() {
                let mut result = ConditionDebugResult::new(desc, true);
                result.details.push(format!(
                    "✓ {} finding(s) matched suffix '{}' in findings:",
                    matching_findings.len(),
                    id
                ));
                for finding in matching_findings.iter().take(5) {
                    result.details.push(format!("  - {}", finding.id));
                }
                if matching_findings.len() > 5 {
                    result
                        .details
                        .push(format!("  ... and {} more", matching_findings.len() - 5));
                }
                result.evidence = matching_findings
                    .iter()
                    .flat_map(|f| f.evidence.iter().cloned())
                    .collect();
                return result;
            }
        } else {
            // Directory path: prefix match (any trait within that directory).
            let prefix_new = format!("{}::", id);
            let prefix_legacy = format!("{}/", id);
            let matching_findings: Vec<_> = self
                .report
                .findings
                .iter()
                .filter(|f| f.id.starts_with(&prefix_new) || f.id.starts_with(&prefix_legacy))
                .collect();

            if !matching_findings.is_empty() {
                let mut result = ConditionDebugResult::new(desc.clone(), true);
                result.details.push(format!(
                    "✓ {} finding(s) matched prefix '{}' in findings:",
                    matching_findings.len(),
                    id
                ));
                for finding in matching_findings.iter().take(5) {
                    result.details.push(format!("  - {}", finding.id));
                }
                if matching_findings.len() > 5 {
                    result
                        .details
                        .push(format!("  ... and {} more", matching_findings.len() - 5));
                }
                result.evidence = matching_findings
                    .iter()
                    .flat_map(|f| f.evidence.iter().cloned())
                    .collect();
                return result;
            }
        }

        // Step 3: Not found in findings - check if it's a composite rule
        if let Some(_composite) = self.find_composite_rule(id) {
            let mut result = ConditionDebugResult::new(desc, false);
            result
                .details
                .push(format!("✗ Composite rule '{}' not found in findings", id));
            result
                .details
                .push("  (Composites are evaluated separately from traits)".to_string());
            return result;
        }

        // Step 4: Try to re-evaluate the trait definition to explain WHY it didn't match
        // Use the evaluation-based debug to ensure filters (count_min, per_kb_min, etc.) are checked
        if let Some(trait_def) = self.find_trait_definition(id) {
            let trait_debug_result = self.debug_trait_via_evaluation(trait_def);
            let mut result = ConditionDebugResult::new(desc, false);

            if trait_debug_result.matched {
                // The primary condition matched, yet the trait is absent from the
                // final findings. The cause is almost always an `unless:` skip or a
                // `downgrade:` that resolved against a sibling finding in the full
                // run; attribute it precisely instead of emitting a bare warning.
                let attribution = self.explain_unless_downgrade(trait_def);
                if attribution.is_empty() {
                    result.details.push(
                        "⚠ Trait re-evaluates as matched but not in findings (cause unattributed)"
                            .to_string(),
                    );
                } else {
                    result.details.extend(attribution);
                }
            } else if let Some(reason) = &trait_debug_result.skipped_reason {
                result
                    .details
                    .push(format!("✗ Not in findings ({})", reason));
            } else {
                result
                    .details
                    .push("✗ Not in findings (trait condition not satisfied)".to_string());
            }

            // Include the condition results to show WHY it didn't match
            result.sub_results = trait_debug_result.condition_results;
            return result;
        }

        // Step 5: Trait definition not found at all
        let mut result = ConditionDebugResult::new(desc, false);
        result.details.push(format!(
            "✗ Trait '{}' not found in findings or definitions",
            id
        ));

        // Show available trait prefixes for debugging
        if slash_count > 0 {
            let available_prefixes: std::collections::HashSet<_> = self
                .report
                .findings
                .iter()
                .filter_map(|f| f.id.rfind('/').map(|i| &f.id[..i]))
                .collect();
            if !available_prefixes.is_empty() {
                let mut prefixes: Vec<_> = available_prefixes.into_iter().collect();
                prefixes.sort();
                result.details.push(format!(
                    "  Available trait directories in findings: {}",
                    prefixes.join(", ")
                ));
            }
        }

        result
    }

    /// Attribute why a trait that matched its primary condition is nonetheless
    /// absent from (or de-emphasized in) the final findings. The cause is almost
    /// always an `unless:` skip or a `downgrade:` that resolved against a sibling
    /// finding in the full run — so re-check those clauses against the real
    /// report and name the responsible clause and what triggered it. This turns
    /// the old bare "discrepancy" note into a direct readout of unless/downgrade
    /// manipulation.
    fn explain_unless_downgrade(&self, trait_def: &TraitDefinition) -> Vec<String> {
        let mut out = Vec::new();

        // `unless:` — default semantics skip the trait if ANY clause matches.
        if let Some(unless_conds) = &trait_def.unless {
            for (idx, cond) in unless_conds.iter().enumerate() {
                if let Some(trigger) = self.unless_clause_satisfied(cond) {
                    out.push(format!(
                        "✗ SUPPRESSED by `unless:` clause #{} → {}",
                        idx + 1,
                        describe_condition(cond)
                    ));
                    out.push(format!("      ↳ matched by: {}", trigger));
                }
            }
        }

        // `downgrade:` — every present block (all/any/none) must pass to fire.
        if let Some(downgrade) = &trait_def.downgrade
            && let Some(reason) = self.explain_downgrade(downgrade)
        {
            out.push(format!(
                "↓ DOWNGRADED {:?} → {:?} by `downgrade:` ({})",
                trait_def.crit,
                crate::composite_rules::traits::downgrade_crit(trait_def.crit),
                reason
            ));
        }

        out
    }

    /// Decide whether a single `unless:`/`downgrade:` clause is satisfied against
    /// the analyzed file, returning the triggering trait id when it is. Tries the
    /// findings-based view first (covers inline matchers and single-trait refs,
    /// which `debug_condition` already re-evaluates when absent from findings).
    /// Falls back to re-evaluating each member of a *directory* trait-reference —
    /// the case that the findings view misses when those members were themselves
    /// suppressed in the same run (mutual annihilation), which is exactly how a
    /// pair of same-directory clauses can each silence the other.
    fn unless_clause_satisfied(&self, cond: &Condition) -> Option<String> {
        let res = self.debug_condition(cond);
        if res.matched {
            let trigger = res
                .details
                .iter()
                .find_map(|d| d.trim().strip_prefix("- ").map(str::to_string))
                .unwrap_or_else(|| describe_condition(cond));
            return Some(trigger);
        }

        // Directory trait-reference fallback: re-evaluate each member's matcher.
        if let Condition::Trait { id } = cond {
            let id = id.trim_end_matches('/');
            let pfx_new = format!("{id}::");
            let pfx_legacy = format!("{id}/");
            for t in self.traits {
                if (t.id == id || t.id.starts_with(&pfx_new) || t.id.starts_with(&pfx_legacy))
                    && self.debug_trait_via_evaluation(t).matched
                {
                    return Some(t.id.clone());
                }
            }
        }
        None
    }

    /// Mirror of the engine's downgrade evaluation: every specified block must
    /// pass for the downgrade to fire. Returns a reason string naming the
    /// matched clause when it would trigger, else `None`.
    fn explain_downgrade(
        &self,
        dg: &crate::composite_rules::traits::DowngradeConditions,
    ) -> Option<String> {
        let mut reasons = Vec::new();

        if let Some(all) = &dg.all {
            if !all
                .iter()
                .all(|c| self.unless_clause_satisfied(c).is_some())
            {
                return None;
            }
            reasons.push("all: satisfied".to_string());
        }
        if let Some(any) = &dg.any {
            let matched = any
                .iter()
                .filter(|c| self.unless_clause_satisfied(c).is_some())
                .count();
            if matched < dg.needs.unwrap_or(1) {
                return None;
            }
            if let Some(c) = any
                .iter()
                .find(|c| self.unless_clause_satisfied(c).is_some())
            {
                reasons.push(format!("any: {}", describe_condition(c)));
            }
        }
        if let Some(none) = &dg.none {
            if none
                .iter()
                .any(|c| self.unless_clause_satisfied(c).is_some())
            {
                return None;
            }
            reasons.push("none: satisfied".to_string());
        }

        if reasons.is_empty() {
            None
        } else {
            Some(reasons.join("; "))
        }
    }

    fn debug_symbol_condition(
        &self,
        exact: &Option<String>,
        substr: &Option<String>,
        regex: &Option<String>,
    ) -> ConditionDebugResult {
        let pattern_desc = if let Some(e) = exact {
            format!("exact: \"{}\"", e)
        } else if let Some(c) = substr {
            format!("substr: \"{}\"", c)
        } else if let Some(r) = regex {
            format!("regex: /{}/", r)
        } else {
            "unknown".to_string()
        };

        let desc = format!("symbol: {}", pattern_desc);

        let symbols: Vec<&str> = self
            .report
            .imports
            .iter()
            .map(|i| i.symbol.as_str())
            .chain(self.report.exports.iter().map(|e| e.symbol.as_str()))
            .chain(self.report.functions.iter().map(|f| f.name.as_str()))
            .collect();

        let matched_symbols = find_matching_symbols(&symbols, exact, substr, regex, false);
        let matched = !matched_symbols.is_empty();

        let mut result = ConditionDebugResult::new(desc, matched);

        result.details.push(format!(
            "Total symbols: {} ({} imports, {} exports)",
            symbols.len(),
            self.report.imports.len(),
            self.report.exports.len()
        ));
        result
            .details
            .push(format!("Matching symbols: {}", matched_symbols.len()));

        if !matched_symbols.is_empty() {
            let display_count = matched_symbols.len().min(10);
            for s in matched_symbols.iter().take(display_count) {
                result.details.push(format!("  Matched: \"{}\"", s));
            }
            if matched_symbols.len() > display_count {
                result.details.push(format!(
                    "  ... and {} more",
                    matched_symbols.len() - display_count
                ));
            }
        } else if symbols.len() <= 20 {
            result.details.push("All symbols:".to_string());
            for s in &symbols {
                result.details.push(format!("  \"{}\"", s));
            }
        }

        // Check alternatives if no symbol match
        if !matched {
            // Check strings
            let string_values: Vec<&str> = self
                .report
                .strings
                .iter()
                .map(|s| s.value.as_str())
                .collect();
            let string_matches =
                find_matching_strings(&string_values, exact, &None, regex, &None, false);
            if !string_matches.is_empty() {
                result.details.push(format!(
                    "💡 Found in strings ({} matches) - try `string:` instead",
                    string_matches.len()
                ));
            }

            // Check content
            let content = String::from_utf8_lossy(self.binary_data);
            let content_matched = if let Some(e) = exact {
                content.contains(e)
            } else if let Some(r) = regex {
                regex::Regex::new(r).is_ok_and(|re| re.is_match(&content))
            } else {
                false
            };
            if content_matched {
                result
                    .details
                    .push("💡 Found in raw bytes - try `type: raw` instead".to_string());
            }
        }

        result
    }

    fn debug_metrics_condition(
        &self,
        field: &str,
        min: Option<f64>,
        max: Option<f64>,
    ) -> ConditionDebugResult {
        let desc = format!("metrics: {} (min: {:?}, max: {:?})", field, min, max);

        let value = crate::types::scores::get_metric_value(self.report, field);
        let matched =
            value.is_some_and(|v| min.is_none_or(|m| v >= m) && max.is_none_or(|m| v <= m));

        let mut result = ConditionDebugResult::new(desc, matched);

        if let Some(v) = value {
            result.details.push(format!("Actual value: {:.4}", v));
        } else {
            result
                .details
                .push(format!("Metric '{}' not found in report", field));
            if let Some(flat) = &self.report.filefacts_metrics {
                for key in [
                    "text.total_lines",
                    "functions.total",
                    "identifiers.single_char_ratio",
                    "identifiers.avg_length",
                    "identifiers.total",
                    "identifiers.unique_count",
                ] {
                    if let Some(v) = flat.get(key) {
                        result.details.push(format!("  {key}: {v}"));
                    }
                }
            }
        }

        result
    }

    fn debug_yara_inline_condition(&self, source: &str) -> ConditionDebugResult {
        use crate::composite_rules::evaluators::eval_yara_inline;

        // Extract rule name from YARA source
        let rule_name = source
            .lines()
            .find(|l| l.trim().starts_with("rule "))
            .and_then(|l| l.trim().strip_prefix("rule "))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or("inline");

        let desc = format!("yara: {} ({} chars)", rule_name, source.len());

        // Create evaluation context
        let ctx = EvaluationContext {
            report: self.report,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platforms: &self.platforms,
            arch: vec![Arch::All].into(),
            arch_ranges: None,
            additional_findings: None,
            cached_ast: None,
            ast_kind_cache: None,
            finding_id_index: None,
            debug_collector: None,
            section_map: None,
            inline_yara_results: None,
            cached_kv_format: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_kv_parsed: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_kv_offsets: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_lower_binary: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index_ci: std::sync::Arc::new(std::sync::OnceLock::new()),
            encoded_string_indices: std::sync::Arc::new(std::sync::OnceLock::new()),
            deadline: None,
            slow_rule_ms: 4000,
            cached_evidence: None,
            current_trait_idx: None,
            cached_source_utf8: None,
            cancellation: None,
        };

        // Actually evaluate the inline YARA rule
        let eval_result = eval_yara_inline(source, None, None, &ctx);

        let mut result = ConditionDebugResult::new(desc, eval_result.matched);
        result.evidence = eval_result.evidence;

        if eval_result.matched {
            result
                .details
                .push("✓ Inline YARA rule matched".to_string());
        } else {
            result
                .details
                .push("✗ Inline YARA rule did not match".to_string());
        }

        result.details.push(format!(
            "Rule source preview: {}...",
            truncate_string(source, 100)
        ));

        result
    }

    #[allow(clippy::too_many_arguments)]
    fn debug_raw_condition(
        &self,
        exact: &Option<String>,
        substr: &Option<String>,
        regex: &Option<String>,
        word: &Option<String>,
        section_constraint: Option<&String>,
        offset: Option<i64>,
        offset_range: Option<(i64, Option<i64>)>,
        section_offset: Option<i64>,
        section_offset_range: Option<(i64, Option<i64>)>,
    ) -> ConditionDebugResult {
        let pattern_desc = if let Some(e) = exact {
            format!("exact: \"{}\"", truncate_string(e, 40))
        } else if let Some(c) = substr {
            format!("substr: \"{}\"", truncate_string(c, 40))
        } else if let Some(r) = regex {
            format!("regex: /{}/", truncate_string(r, 40))
        } else if let Some(w) = word {
            format!("word: \"{}\"", w)
        } else {
            "unknown".to_string()
        };

        // Build location constraint description
        let mut location_parts = Vec::new();
        if let Some(sec) = section_constraint {
            location_parts.push(format!("section={}", sec));
        }
        if let Some(off) = offset {
            location_parts.push(format!("offset={}", off));
        }
        if let Some((start, end)) = &offset_range {
            let end_str = end.map_or("EOF".to_string(), |e| e.to_string());
            location_parts.push(format!("range=[{},{})", start, end_str));
        }
        if let Some(off) = section_offset {
            location_parts.push(format!("section_offset={}", off));
        }
        if let Some((start, end)) = &section_offset_range {
            let end_str = end.map_or("end".to_string(), |e| e.to_string());
            location_parts.push(format!("section_range=[{},{})", start, end_str));
        }

        let location_desc = if location_parts.is_empty() {
            String::new()
        } else {
            format!(" @{{{}}}", location_parts.join(", "))
        };

        let desc = format!("raw: {}{}", pattern_desc, location_desc);

        // Resolve the effective search range
        let file_size = self.binary_data.len();
        let (search_start, search_end) = self.resolve_search_range(
            section_constraint,
            offset,
            offset_range.as_ref(),
            section_offset,
            section_offset_range.as_ref(),
            file_size,
        );

        // Search only within the resolved range
        let search_data = if search_start < search_end && search_end <= file_size {
            &self.binary_data[search_start..search_end]
        } else {
            // Invalid range - no data to search
            &self.binary_data[0..0]
        };
        let content = String::from_utf8_lossy(search_data);

        let matched = if let Some(e) = exact {
            &content == e
        } else if let Some(c) = substr {
            content.contains(c)
        } else if let Some(r) = regex {
            regex::Regex::new(r).is_ok_and(|re| re.is_match(&content))
        } else if let Some(w) = word {
            let pattern = format!(r"\b{}\b", regex::escape(w));
            regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(&content))
        } else {
            false
        };

        let mut result = ConditionDebugResult::new(desc, matched);

        // Show search range details
        if search_start != 0 || search_end != file_size {
            result.details.push(format!(
                "Search range: [{}, {}) of {} bytes ({} bytes searched)",
                search_start,
                search_end,
                file_size,
                search_end.saturating_sub(search_start)
            ));
        } else {
            result
                .details
                .push(format!("File size: {} bytes", file_size));
        }

        // Check alternatives if content didn't match
        if !matched {
            // Check if pattern exists outside the constrained range
            if search_start != 0 || search_end != file_size {
                let full_content = String::from_utf8_lossy(self.binary_data);
                let found_outside = if let Some(c) = substr {
                    full_content.contains(c)
                } else if let Some(r) = regex {
                    regex::Regex::new(r).is_ok_and(|re| re.is_match(&full_content))
                } else if let Some(w) = word {
                    let pattern = format!(r"\b{}\b", regex::escape(w));
                    regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(&full_content))
                } else {
                    false
                };
                if found_outside {
                    result.details.push(
                        "💡 Pattern exists in file but outside the specified range".to_string(),
                    );
                }
            }

            // Check symbols (only for exact or regex patterns)
            if exact.is_some() || regex.is_some() {
                let symbols: Vec<&str> = self
                    .report
                    .imports
                    .iter()
                    .map(|i| i.symbol.as_str())
                    .chain(self.report.exports.iter().map(|e| e.symbol.as_str()))
                    .chain(self.report.functions.iter().map(|f| f.name.as_str()))
                    .collect();
                let symbol_matches = find_matching_symbols(&symbols, exact, &None, regex, false);
                if !symbol_matches.is_empty() {
                    result.details.push(format!(
                        "💡 Found in symbols ({} matches) - try `symbol:` instead",
                        symbol_matches.len()
                    ));
                }
            }

            // Check strings
            let strings: Vec<&str> = self
                .report
                .strings
                .iter()
                .map(|s| s.value.as_str())
                .collect();
            let string_matches = find_matching_strings(&strings, exact, substr, regex, word, false);
            if !string_matches.is_empty() {
                result.details.push(format!(
                    "💡 Found in strings ({} matches) - try `string:` instead",
                    string_matches.len()
                ));
            }
        }

        // Section suggestions for binaries
        if self.section_map.has_sections() && matched {
            // List available sections
            let sections = self.section_map.section_names();
            if !sections.is_empty() && section_constraint.is_none() {
                result.details.push(format!(
                    "📍 Binary has sections: {} - consider section filtering for precision",
                    sections.join(", ")
                ));
            }
        } else if section_constraint.is_some() && !self.section_map.has_sections() {
            result.details.push(
                "⚠️  Section constraint specified but file has no binary sections".to_string(),
            );
        }

        result
    }

    // Mirrors the full set of value-condition operators a trait can
    // declare; bundling into a struct here would just push the
    // boilerplate one layer over.
    #[allow(clippy::too_many_arguments)]
    fn debug_kv_condition(
        &self,
        path: &str,
        exact: &Option<String>,
        substr: &Option<String>,
        regex: &Option<String>,
        case_insensitive: bool,
        exists: Option<bool>,
        size_min: Option<usize>,
        size_max: Option<usize>,
    ) -> ConditionDebugResult {
        let pattern_desc = if let Some(e) = exact {
            format!("exact: \"{}\"", truncate_string(e, 40))
        } else if let Some(c) = substr {
            format!("substr: \"{}\"", truncate_string(c, 40))
        } else if let Some(r) = regex {
            format!("regex: /{}/", truncate_string(r, 40))
        } else if exists == Some(true) {
            "exists".to_string()
        } else if let (Some(min), Some(max)) = (size_min, size_max) {
            format!("size {}..{}", min, max)
        } else if let Some(min) = size_min {
            format!("size_min {}", min)
        } else if let Some(max) = size_max {
            format!("size_max {}", max)
        } else {
            "(no constraint)".to_string()
        };

        let desc = format!("value: path=\"{}\" {}", path, pattern_desc);

        // Use the actual value evaluator. Earlier this discarded `exists`,
        // `size_min`, and `size_max` from the parent condition, so a
        // YAML trait like `type: value, path: …, exists: true, size_min: 1`
        // was rebuilt as a no-op match — every value-only trait reported
        // NOT MATCHED in test-rules even when it fired in production.
        let condition = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: path.to_string(),
            exact: exact.clone(),
            substr: substr.clone(),
            regex: regex.clone(),
            eq: None,
            ne: None,
            case_insensitive,
            exists,
            size_min,
            size_max,
        });

        // Create evaluation context
        let ctx = EvaluationContext::new(
            self.report,
            self.binary_data,
            self.file_type,
            &self.platforms,
            None,
            None,
        );

        if let Some(evidence) = crate::composite_rules::evaluators::evaluate_kv(&condition, &ctx) {
            let mut result = ConditionDebugResult::new(desc, true);
            result.details.push(format!("Matched: {}", evidence.value));
            if let Some(loc) = &evidence.location {
                result.details.push(format!("Location: {}", loc));
            }
            result.evidence = vec![evidence];
            result
        } else {
            let mut result = ConditionDebugResult::new(desc, false);

            // Try to parse the file and show what's available
            if let Ok(content) = std::str::from_utf8(self.binary_data) {
                // Try to detect format and show available paths
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
                    if let Some(obj) = json.as_object() {
                        let top_keys: Vec<_> = obj.keys().take(10).collect();
                        result
                            .details
                            .push(format!("Available top-level keys: {:?}", top_keys));
                    }
                } else if let Ok(yaml) = serde_yaml::from_str::<serde_json::Value>(content)
                    && let Some(obj) = yaml.as_object()
                {
                    let top_keys: Vec<_> = obj.keys().take(10).collect();
                    result
                        .details
                        .push(format!("Available top-level keys: {:?}", top_keys));
                }
            }

            result
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn debug_ast_condition(
        &self,
        kind: &Option<String>,
        node: &Option<String>,
        exact: &Option<String>,
        substr: &Option<String>,
        regex: &Option<String>,
        query: &Option<String>,
        case_insensitive: bool,
    ) -> ConditionDebugResult {
        // Build description based on mode
        let desc = if let Some(q) = query {
            format!("tree-sitter: query={}", truncate_string(q, 50))
        } else {
            let node_spec = kind
                .as_ref()
                .map(|k| format!("kind={}", k))
                .or_else(|| node.as_ref().map(|n| format!("node={}", n)))
                .unwrap_or_else(|| "unknown".to_string());
            let pattern_spec = exact
                .as_ref()
                .map(|e| format!("exact=\"{}\"", truncate_string(e, 30)))
                .or_else(|| {
                    substr
                        .as_ref()
                        .map(|s| format!("substr=\"{}\"", truncate_string(s, 30)))
                })
                .or_else(|| {
                    regex
                        .as_ref()
                        .map(|r| format!("regex=/{}/", truncate_string(r, 30)))
                })
                .unwrap_or_default();
            format!(
                "tree-sitter: {} {} (case_insensitive: {})",
                node_spec, pattern_spec, case_insensitive
            )
        };

        // For query mode, show simplified debug info
        if query.is_some() {
            let mut result = ConditionDebugResult::new(desc, false);
            result
                .details
                .push("AST query debugging not yet implemented".to_string());
            return result;
        }

        // Without `cached_ast`, every kind/node match short-circuits to
        // no-match; reuse the filefacts parse we did at construction.
        let cached_ast = self
            .parsed
            .as_ref()
            .and_then(filefacts::ParsedFile::source_ast)
            .map(|a| a.tree);
        let cached_source_utf8 = std::str::from_utf8(self.binary_data).ok();

        // For simple mode, use eval_ast directly
        let ctx = EvaluationContext {
            report: self.report,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platforms: &self.platforms,
            arch: vec![Arch::All].into(),
            arch_ranges: None,
            additional_findings: None,
            cached_ast,
            ast_kind_cache: None,
            finding_id_index: None,
            debug_collector: None,
            section_map: None,
            inline_yara_results: None,
            cached_kv_format: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_kv_parsed: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_kv_offsets: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_lower_binary: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index_ci: std::sync::Arc::new(std::sync::OnceLock::new()),
            encoded_string_indices: std::sync::Arc::new(std::sync::OnceLock::new()),
            deadline: None,
            slow_rule_ms: 4000,
            cached_evidence: None,
            current_trait_idx: None,
            cached_source_utf8,
            cancellation: None,
        };

        let eval_result = crate::composite_rules::evaluators::eval_ast(
            kind.as_deref(),
            node.as_deref(),
            exact.as_deref(),
            substr.as_deref(),
            regex.as_deref(),
            query.as_deref(),
            case_insensitive,
            &ctx,
        );

        let mut result = ConditionDebugResult::new(desc, eval_result.matched);
        if eval_result.matched {
            result.details.push(format!(
                "Found {} matching AST node(s)",
                eval_result.evidence.len()
            ));
            for ev in eval_result.evidence.iter().take(10) {
                if let Some(loc) = &ev.location {
                    result
                        .details
                        .push(format!("  {}: {}", loc, truncate_string(&ev.value, 60)));
                } else {
                    result
                        .details
                        .push(format!("  {}", truncate_string(&ev.value, 60)));
                }
            }
        } else {
            result
                .details
                .push("No matching AST nodes found".to_string());

            // Hint: the most common `kind: call exact: <bare-name>` mistake.
            // The AST evaluator compares the pattern against the full call
            // expression text (`name(args)`), so `exact: name` never
            // matches. Detect the pattern and suggest the canonical
            // workarounds, preferring `type: symbol` when the name is
            // already extracted by the symbol pass.
            if kind.as_deref() == Some("call")
                && let Some(name) = exact.as_deref()
            {
                let looks_like_bare_name = !name.is_empty()
                    && !name.contains('(')
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':');
                if looks_like_bare_name {
                    let found_as_symbol = self.report.imports.iter().any(|i| i.symbol == name)
                        || self.report.exports.iter().any(|e| e.symbol == name)
                        || self.report.functions.iter().any(|f| f.name == name);
                    result.details.push(format!(
                        "  hint: `ast kind=call exact: {n}` compares against the full \
                             call expression text (e.g. `{n}(args)`), not just the name, so \
                             it never matches.",
                        n = name
                    ));
                    if found_as_symbol {
                        result.details.push(format!(
                            "        the symbol extractor sees `{n}` — switch this \
                                 condition to `type: symbol exact: {n}`.",
                            n = name
                        ));
                    } else {
                        result.details.push(format!(
                            "        switch to `type: symbol exact: {n}`, or stay on \
                                 AST with `substr: \"{n}(\"` or `regex: \"^{n}\\\\b\"`.",
                            n = name
                        ));
                    }
                }
            }
        }

        result
    }

    fn debug_hex_condition(
        &self,
        pattern: &str,
        offset: Option<i64>,
        offset_range: Option<(i64, Option<i64>)>,
        section: Option<&str>,
        section_offset: Option<i64>,
        section_offset_range: Option<(i64, Option<i64>)>,
    ) -> ConditionDebugResult {
        use crate::composite_rules::evaluators::{ContentLocationParams, eval_hex};

        let mut desc = format!("hex: \"{}\"", truncate_string(pattern, 40));
        if let Some(sec) = section {
            desc.push_str(&format!(" in section: {}", sec));
        }
        if let Some(off) = offset {
            desc.push_str(&format!(" @{:#x}", off));
        }
        if let Some((start, end)) = offset_range {
            match end {
                Some(e) => desc.push_str(&format!(" @[{:#x},{:#x})", start, e)),
                None => desc.push_str(&format!(" @[{:#x},)", start)),
            }
        }

        let ctx = EvaluationContext {
            report: self.report,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platforms: &self.platforms,
            arch: vec![Arch::All].into(),
            arch_ranges: None,
            additional_findings: None,
            cached_ast: None,
            ast_kind_cache: None,
            finding_id_index: None,
            debug_collector: None,
            section_map: Some(&self.section_map),
            inline_yara_results: None,
            cached_kv_format: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_kv_parsed: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_kv_offsets: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_lower_binary: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index_ci: std::sync::Arc::new(std::sync::OnceLock::new()),
            encoded_string_indices: std::sync::Arc::new(std::sync::OnceLock::new()),
            deadline: None,
            slow_rule_ms: 4000,
            cached_evidence: None,
            current_trait_idx: None,
            cached_source_utf8: None,
            cancellation: None,
        };

        let eval_result = eval_hex(
            pattern,
            &ContentLocationParams {
                section: section.map(std::borrow::ToOwned::to_owned),
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                arch_clamp: None,
            },
            &ctx,
            None,
        );

        let mut result = ConditionDebugResult::new(desc, eval_result.matched);

        result
            .details
            .push(format!("File size: {} bytes", self.binary_data.len()));
        result
            .details
            .push(format!("Found {} matches", eval_result.evidence.len()));

        for ev in eval_result.evidence.iter().take(5) {
            if let Some(loc) = &ev.location {
                result.details.push(format!("  {} @ {}", ev.value, loc));
            } else {
                result.details.push(format!("  {}", ev.value));
            }
        }
        if eval_result.evidence.len() > 5 {
            result
                .details
                .push(format!("  ... and {} more", eval_result.evidence.len() - 5));
        }

        result.evidence = eval_result.evidence;
        result
    }

    // Helper to find trait definition by ID
    fn find_trait_definition(&self, id: &str) -> Option<&crate::composite_rules::TraitDefinition> {
        self.mapper.find_trait(id)
    }

    // Helper to find composite rule by ID
    fn find_composite_rule(&self, id: &str) -> Option<&crate::composite_rules::CompositeTrait> {
        self.mapper.composite_rules().iter().find(|r| r.id == id)
    }
}

// Helper functions

/// Format location constraints for display
fn format_location_suffix(
    section: &Option<String>,
    offset: Option<i64>,
    offset_range: Option<(i64, Option<i64>)>,
    section_offset: Option<i64>,
    section_offset_range: Option<(i64, Option<i64>)>,
) -> String {
    let mut parts = Vec::new();

    if let Some(sec) = section {
        parts.push(format!("section={}", sec));
    }
    if let Some(off) = offset {
        parts.push(format!("offset={:#x}", off));
    }
    if let Some((start, end)) = offset_range {
        match end {
            Some(e) => parts.push(format!("offset_range=[{:#x},{:#x}]", start, e)),
            None => parts.push(format!("offset_range=[{:#x},]", start)),
        }
    }
    if let Some(off) = section_offset {
        parts.push(format!("section_offset={:#x}", off));
    }
    if let Some((start, end)) = section_offset_range {
        match end {
            Some(e) => parts.push(format!("section_offset_range=[{:#x},{:#x}]", start, e)),
            None => parts.push(format!("section_offset_range=[{:#x},]", start)),
        }
    }

    if parts.is_empty() {
        String::new()
    } else {
        format!(" @{{{}}}", parts.join(","))
    }
}

fn describe_condition(condition: &Condition) -> String {
    match condition {
        Condition::Trait { id } => format!("trait: {}", id),
        Condition::Symbol(SymbolQuery {
            exact,
            substr,
            regex,
            ..
        }) => {
            if let Some(e) = exact {
                format!("symbol[exact]: \"{}\"", e)
            } else if let Some(c) = substr {
                format!("symbol[substr]: \"{}\"", c)
            } else if let Some(r) = regex {
                format!("symbol[regex]: /{}/", r)
            } else {
                "symbol[?]".to_string()
            }
        }
        Condition::Metrics(MetricsQuery {
            field, min, max, ..
        }) => {
            format!("metrics: {} [{:?}, {:?}]", field, min, max)
        }
        Condition::Yara { .. } => "yara[inline]".to_string(),
        Condition::Raw(RawQuery {
            exact,
            substr,
            regex,
            word,
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            ..
        }) => {
            let loc = format_location_suffix(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
            );
            if exact.is_some() {
                format!("raw[exact]{}", loc)
            } else if substr.is_some() {
                format!("raw[substr]{}", loc)
            } else if regex.is_some() {
                format!("raw[regex]{}", loc)
            } else if word.is_some() {
                format!("raw[word]{}", loc)
            } else {
                format!("raw[?]{}", loc)
            }
        }
        Condition::Kv(KvQuery {
            path,
            exact,
            substr,
            regex,
            ..
        }) => {
            let matcher = if exact.is_some() {
                "exact"
            } else if substr.is_some() {
                "substr"
            } else if regex.is_some() {
                "regex"
            } else {
                "exists"
            };
            format!("value[{}]: path=\"{}\"", matcher, truncate_string(path, 30))
        }
        Condition::Hex(HexQuery {
            pattern,
            offset,
            offset_range,
            ..
        }) => {
            let mut desc = format!("hex: \"{}\"", truncate_string(pattern, 30));
            if let Some(off) = offset {
                desc.push_str(&format!(" @{:#x}", off));
            } else if let Some((start, _)) = offset_range {
                desc.push_str(&format!(" @{:#x}+", start));
            }
            desc
        }
        _ => format!("{:?}", condition).chars().take(50).collect(),
    }
}

fn build_composite_requirements(composite: &crate::composite_rules::CompositeTrait) -> String {
    let mut parts = Vec::new();

    if let Some(all) = &composite.all {
        parts.push(format!("all: {} conditions", all.len()));
    }

    if let Some(any) = &composite.any {
        let needed = composite.needs.unwrap_or(1);
        parts.push(format!("any: needs {} of {} conditions", needed, any.len()));
    }

    parts.join(", ")
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

pub(crate) fn find_matching_strings<'a>(
    strings: &[&'a str],
    exact: &Option<String>,
    substr: &Option<String>,
    regex_pat: &Option<String>,
    word: &Option<String>,
    case_insensitive: bool,
) -> Vec<&'a str> {
    strings
        .iter()
        .filter(|s| {
            if let Some(e) = exact {
                if case_insensitive {
                    s.eq_ignore_ascii_case(e)
                } else {
                    *s == e
                }
            } else if let Some(c) = substr {
                if case_insensitive {
                    s.to_lowercase().contains(&c.to_lowercase())
                } else {
                    s.contains(c.as_str())
                }
            } else if let Some(r) = regex_pat {
                let pattern = if case_insensitive {
                    format!("(?i){}", r)
                } else {
                    r.clone()
                };
                regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(s))
            } else if let Some(w) = word {
                let pattern = if case_insensitive {
                    format!(r"(?i)\b{}\b", regex::escape(w))
                } else {
                    format!(r"\b{}\b", regex::escape(w))
                };
                regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(s))
            } else {
                false
            }
        })
        .copied()
        .collect()
}

pub(crate) fn find_matching_symbols<'a>(
    symbols: &[&'a str],
    exact: &Option<String>,
    substr: &Option<String>,
    regex: &Option<String>,
    case_insensitive: bool,
) -> Vec<&'a str> {
    // Note: symbols are normalized (leading underscores stripped) at load time,
    // so we don't need to strip them here during matching
    symbols
        .iter()
        .filter(|s| {
            if let Some(e) = exact {
                return if case_insensitive {
                    s.eq_ignore_ascii_case(e)
                } else {
                    *s == e
                };
            }
            if let Some(c) = substr {
                return if case_insensitive {
                    s.to_lowercase().contains(&c.to_lowercase())
                } else {
                    s.contains(c.as_str())
                };
            }
            if let Some(r) = regex {
                let pattern = if case_insensitive {
                    format!("(?i){}", r)
                } else {
                    r.clone()
                };
                if let Ok(re) = regex::Regex::new(&pattern) {
                    return re.is_match(s);
                }
            }
            false
        })
        .copied()
        .collect()
}

fn evaluate_condition_simple(
    condition: &Condition,
    ctx: &EvaluationContext<'_>,
) -> crate::composite_rules::context::ConditionResult {
    use crate::composite_rules::evaluators::{
        SectionParams, eval_path, eval_section, eval_syscall,
    };

    // Evaluate conditions that fall through to the _ => case in debug_condition
    match condition {
        Condition::Section(SectionQuery {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            length_min,
            length_max,
            entropy_min,
            entropy_max,
            readable,
            writable,
            executable,
            compare_to,
            size_ratio_min,
            size_ratio_max,
            entropy_ratio_min,
            entropy_ratio_max,
        }) => eval_section(
            &SectionParams {
                exact: exact.as_ref(),
                substr: substr.as_ref(),
                regex: regex.as_ref(),
                word: word.as_ref(),
                case_insensitive: *case_insensitive,
                length_min: *length_min,
                length_max: *length_max,
                entropy_min: *entropy_min,
                entropy_max: *entropy_max,
                readable: *readable,
                writable: *writable,
                executable: *executable,
                compare_to: compare_to.as_ref(),
                size_ratio_min: *size_ratio_min,
                size_ratio_max: *size_ratio_max,
                entropy_ratio_min: *entropy_ratio_min,
                entropy_ratio_max: *entropy_ratio_max,
            },
            ctx,
        ),
        Condition::Syscall { name, number, arch } => {
            eval_syscall(name.as_ref(), number.as_ref(), arch.as_ref(), ctx)
        }
        Condition::Path(PathQuery {
            exact,
            substr,
            regex,
            case_insensitive,
            is_check,
            basename,
            dirname,
        }) => eval_path(
            exact.as_ref(),
            substr.as_ref(),
            regex.as_ref(),
            *case_insensitive,
            *is_check,
            *basename,
            *dirname,
            ctx,
        ),
        _ => crate::composite_rules::context::ConditionResult::no_match(),
    }
}

fn detect_file_type(file_type: &str) -> RuleFileType {
    RuleFileType::from_str(file_type)
}

fn precision_detail_lines(
    composite: Option<&CompositeTrait>,
    trait_def: Option<&TraitDefinition>,
) -> Vec<String> {
    let (file_types, platforms, kind) = if let Some(composite) = composite {
        (&composite.r#for, &composite.platforms, "composite")
    } else if let Some(trait_def) = trait_def {
        (&trait_def.r#for, &trait_def.platforms, "trait")
    } else {
        return Vec::new();
    };

    let mut details = Vec::new();
    let concrete_count = file_types
        .iter()
        .filter(|f| !matches!(f, RuleFileType::All))
        .count();
    let penalty = file_type_precision_penalty(file_types);

    if concrete_count > 1 && penalty > 0.0 {
        details.push(format!(
            "file_type breadth penalty: -{:.1} ({} computed file types)",
            penalty, concrete_count
        ));
    }

    let platform_count = platforms
        .iter()
        .filter(|p| !matches!(p, Platform::All))
        .count();
    let platform_penalty = platform_precision_penalty(platforms);
    if platform_count > 1 && platform_penalty > 0.0 {
        details.push(format!(
            "platform breadth penalty: -{:.1} ({} platforms)",
            platform_penalty, platform_count
        ));
    }

    let calibrated_max = if kind == "trait" {
        atomic_calibrated_max()
    } else {
        composite_calibrated_max()
    };
    details.push(format!(
        "calibrated {} range target: <= {:.1}",
        kind, calibrated_max
    ));
    if kind == "composite" {
        details.push(format!(
            "strong inflation warning threshold: > {:.1}",
            composite_inflation_warning_threshold()
        ));
    }

    details
}

/// Format the debug results for terminal output
pub(crate) fn format_debug_output(results: &[RuleDebugResult]) -> String {
    let mut output = String::new();
    let mut matched_count = 0;
    let mut not_matched_count = 0;

    for result in results {
        if result.matched {
            matched_count += 1;
        } else {
            not_matched_count += 1;
        }

        // Rule header
        let status = if result.matched {
            "MATCHED".green().bold()
        } else {
            "NOT MATCHED".red().bold()
        };

        output.push_str(&format!(
            "\n{} {} ({})",
            status,
            result.rule_id.cyan().bold(),
            result.rule_type.dimmed()
        ));
        output.push_str(&format!("  {}\n", result.description.dimmed()));
        output.push_str(&format!("  Requires: {}\n", result.requirements));

        if let Some(precision) = result.precision {
            output.push_str(&format!("  Precision: {:.1}\n", precision));
            for detail in &result.precision_details {
                output.push_str(&format!("  Precision detail: {}\n", detail));
            }
            let calibrated_max = if result.rule_type == "trait" {
                atomic_calibrated_max()
            } else {
                composite_calibrated_max()
            };
            if precision > calibrated_max {
                if result.rule_type == "composite"
                    && precision <= composite_inflation_warning_threshold()
                {
                    output.push_str(&format!(
                        "  Precision note: score {:.1} exceeds normal composite range (>{:.1})\n",
                        precision, calibrated_max
                    ));
                } else {
                    output.push_str(&format!(
                        "  Precision warning: score {:.1} exceeds calibrated {} range (>{:.1})\n",
                        precision, result.rule_type, calibrated_max
                    ));
                }
            }
            if result.rule_type == "composite"
                && precision > composite_inflation_warning_threshold()
            {
                output.push_str(&format!(
                    "  Precision warning: score {:.1} exceeds strong inflation threshold (>{:.1})\n",
                    precision,
                    composite_inflation_warning_threshold()
                ));
            }
        }

        if let Some(reason) = &result.skipped_reason {
            output.push_str(&format!("  {} {}\n", "Skipped:".yellow(), reason));
        }

        // Context info
        output.push_str(&format!(
            "  Context: file_type={}, platforms={}, strings={}, symbols={}, findings={}\n",
            result.context_info.file_type,
            result.context_info.platforms,
            result.context_info.string_count,
            result.context_info.symbol_count,
            result.context_info.finding_count
        ));

        // Condition results
        if !result.condition_results.is_empty() {
            output.push_str("  Conditions:\n");
            for cond_result in &result.condition_results {
                format_condition_result(&mut output, cond_result, 2);
            }
        }

        output.push('\n');
    }

    // Summary line
    if !results.is_empty() {
        output.push_str(&format!(
            "Summary: {} matched, {} not matched ({} total)\n",
            matched_count,
            not_matched_count,
            results.len()
        ));
    }

    output
}

fn format_condition_result(output: &mut String, result: &ConditionDebugResult, indent: usize) {
    let indent_str = "  ".repeat(indent);
    let icon = if result.matched {
        "✓".green()
    } else {
        "✗".red()
    };

    output.push_str(&format!(
        "{}{} {}\n",
        indent_str, icon, result.condition_desc
    ));

    for detail in &result.details {
        output.push_str(&format!("{}  {}\n", indent_str, detail.dimmed()));
    }

    // Special case: if regex matched but condition shows not matched, explain possible causes
    if result.matched
        && result.condition_desc.contains("regex")
        && !result.evidence.is_empty()
        && result.details.iter().any(|d| d.contains("Matched:"))
    {
        // Check if there's a parent condition result that might have exclusion filters
        if result.sub_results.is_empty() {
            output.push_str(&format!(
                "{}  💡 Regex matched string(s) above. If parent trait doesn't match,\n",
                indent_str
            ));
            output.push_str(&format!(
                "{}     check if 'not:' exclusion filters in the trait definition rejected them.\n",
                indent_str
            ));
        }
    }

    for sub in &result.sub_results {
        format_condition_result(output, sub, indent + 1);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::types::{AnalysisReport, Finding, FindingKind, TargetInfo};
    use tempfile::TempDir;

    fn create_test_yaml(content: &str) -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("test.yaml");
        std::fs::write(&file_path, content).unwrap();
        (dir, file_path)
    }

    fn create_debug_test_mapper() -> CapabilityMapper {
        let yaml = r#"
defaults:
  for: [all]

traits:
  - id: "micro-behaviors/data/embedded/zstd-magic"
    desc: "Detect zstd magic"
    crit: notable
    conf: 0.9
    for: [elf]
    if:
      type: text
      exact: "ZSTD"

  - id: "known/malware/botnet/mirai/detected"
    desc: "Detect Mirai marker"
    crit: hostile
    conf: 0.9
    for: [elf]
    size_min: 30000
    if:
      type: text
      exact: "mirai"

composite_rules:
  - id: "objectives/command-and-control/webshell/backdoor/php-rce"
    desc: "PHP webshell RCE behavior"
    crit: hostile
    conf: 0.9
    for: [php]
    any:
      - type: trait
        id: "objectives/anti-static/obfuscation"
      - type: trait
        id: "micro-behaviors/data/user-input/request/get"
    needs: 1

  - id: "objectives/lateral-movement/trojanize/app/objc-app-hook"
    desc: "Objective-C app hooking behavior"
    crit: notable
    conf: 0.9
    platforms: [macos]
    for: [macho]
    all:
      - type: trait
        id: "micro-behaviors/execution/dylib/load/objc-method-swizzle"
      - type: trait
        id: "micro-behaviors/execution/dylib/load/nsbundle"
    any:
      - type: trait
        id: "micro-behaviors/communications/socket/send/send"
    needs: 1
"#;
        let (_dir, path) = create_test_yaml(yaml);
        CapabilityMapper::from_yaml(&path).unwrap()
    }

    fn create_test_report_with_findings(findings: Vec<Finding>) -> AnalysisReport {
        let target = TargetInfo {
            path: "/test/file.php".to_string(),
            file_type: "php".to_string(),
            size_bytes: 100,
            sha256: "test".to_string(),
            architectures: None,
        };
        let mut report = AnalysisReport::new(target);
        report.findings = findings;
        report
    }

    fn create_test_finding(id: &str) -> Finding {
        Finding {
            src: None,
            id: id.to_string(),
            kind: FindingKind::Capability,
            desc: format!("Test finding: {}", id),
            conf: 0.9,
            crit: crate::types::Criticality::Notable,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![],
            source_file: None,
            match_count: 0,
        }
    }

    /// Test that match status from real evaluation is consistent with debug output
    #[test]
    fn test_debug_rule_match_consistency_with_real_evaluation() {
        // Create a report with findings that should match certain rules
        let findings = vec![
            create_test_finding("objectives/anti-static/obfuscation/encoding/test"),
            create_test_finding("micro-behaviors/data/user-input/request/get"),
        ];
        let report = create_test_report_with_findings(findings);
        let binary_data = b"<?php test ?>";

        let mapper = create_debug_test_mapper();
        let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

        // Test a composite rule that references traits by prefix
        // The rule should match if the findings contain matching prefixes
        let result = debugger
            .debug_rule("objectives/command-and-control/webshell/backdoor/php-rce")
            .expect("expected local php-rce composite fixture");

        // Verify consistency: if matched is true, at least one condition should show as matched
        if result.matched {
            let has_matched_condition = result.condition_results.iter().any(|c| c.matched);
            assert!(
                has_matched_condition,
                "Rule marked as matched but no conditions show as matched"
            );
        }
    }

    /// Test that skip reasons are correctly captured
    #[test]
    fn test_debug_rule_skip_reason_file_type_mismatch() {
        // Create a PHP report but test a rule that requires ELF
        let report = create_test_report_with_findings(vec![]);
        let binary_data = b"<?php test ?>";

        let mapper = create_debug_test_mapper();
        let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

        // Test a rule that requires ELF file type (zstd-magic is for binaries)
        let result = debugger
            .debug_rule("micro-behaviors/data/embedded/zstd-magic")
            .expect("expected local zstd trait fixture");
        assert!(!result.matched, "Rule should not match for PHP file");
        assert!(
            result.skipped_reason.is_some(),
            "Should have a skip reason for file type mismatch"
        );
        let reason = result.skipped_reason.as_ref().unwrap();
        assert!(
            reason.contains("File type mismatch"),
            "Skip reason should mention file type mismatch, got: {}",
            reason
        );
    }

    /// Test that size constraints are reported as skip reasons
    #[test]
    fn test_debug_rule_skip_reason_size_constraint() {
        // Create a tiny report (5 bytes)
        let target = TargetInfo {
            path: "/test/tiny.elf".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 5, // Very small
            sha256: "test".to_string(),
            architectures: None,
        };
        let report = AnalysisReport::new(target);
        let binary_data = b"\x7fELF\x00";

        let mapper = create_debug_test_mapper();
        let debugger =
            RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::Linux], None);

        // Test mirai detection which has size_min: 30000
        let result = debugger
            .debug_rule("known/malware/botnet/mirai/detected")
            .expect("expected local mirai trait fixture");
        assert!(!result.matched, "Rule should not match for tiny file");
        assert!(
            result.skipped_reason.is_some(),
            "Should have a skip reason for size constraint"
        );
        let reason = result.skipped_reason.as_ref().unwrap();
        assert!(
            reason.contains("Size too small"),
            "Skip reason should mention size constraint, got: {}",
            reason
        );
    }

    /// Test that prefix matching works correctly in condition debugging
    #[test]
    fn test_debug_condition_prefix_matching() {
        // Create findings with specific prefixes
        let findings = vec![
            create_test_finding("objectives/anti-static/obfuscation/encoding/test"),
            create_test_finding("objectives/anti-static/obfuscation/code-metrics/test2"),
        ];
        let report = create_test_report_with_findings(findings);
        let binary_data = b"test";

        let mapper = CapabilityMapper::empty();
        let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

        // Directly test the prefix matching in debug_condition
        let condition = Condition::Trait {
            id: "objectives/anti-static/obfuscation".to_string(),
        };
        let result = debugger.debug_condition(&condition);

        assert!(
            result.matched,
            "Prefix 'objectives/anti-static/obfuscation' should match findings with that prefix"
        );
        assert!(
            !result.details.is_empty(),
            "Should have details about matched findings"
        );
    }

    /// Test that non-matching prefix returns false
    #[test]
    fn test_debug_condition_prefix_no_match() {
        let findings = vec![create_test_finding(
            "micro-behaviors/data/user-input/request/get",
        )];
        let report = create_test_report_with_findings(findings);
        let binary_data = b"test";

        let mapper = CapabilityMapper::empty();
        let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

        // Test a prefix that doesn't match any findings
        let condition = Condition::Trait {
            id: "objectives/anti-static/obfuscation".to_string(),
        };
        let result = debugger.debug_condition(&condition);

        assert!(
            !result.matched,
            "Prefix should not match when no findings have that prefix"
        );
    }

    /// Test that the match count in condition group matches the actual matched conditions
    #[test]
    fn test_debug_composite_condition_count_consistency() {
        let findings = vec![
            create_test_finding("objectives/anti-static/obfuscation/encoding/test"),
            create_test_finding("micro-behaviors/data/user-input/request/get"),
        ];
        let report = create_test_report_with_findings(findings);
        let binary_data = b"<?php test ?>";

        let mapper = create_debug_test_mapper();
        let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

        // Find and debug a composite rule
        let result = debugger
            .debug_rule("objectives/command-and-control/webshell/backdoor/php-rce")
            .expect("expected local php-rce composite fixture");
        // For each condition group (all/any/none), verify count matches
        for cond_result in &result.condition_results {
            // Parse the condition description to get claimed count
            // e.g., "any: (1/2 needed: 1)"
            if cond_result.condition_desc.contains("(") {
                let matched_in_sub = cond_result.sub_results.iter().filter(|r| r.matched).count();

                // The description should contain the correct count
                if let Some(start) = cond_result.condition_desc.find('(')
                    && let Some(slash) = cond_result.condition_desc.find('/')
                {
                    let claimed_count: usize = cond_result.condition_desc[start + 1..slash]
                        .parse()
                        .unwrap_or(999);
                    assert_eq!(
                        claimed_count, matched_in_sub,
                        "Claimed match count {} doesn't match actual {}",
                        claimed_count, matched_in_sub
                    );
                }
            }
        }
    }

    /// Test that exact trait ID match in findings is detected
    #[test]
    fn test_debug_trait_reference_exact_match_in_findings() {
        let findings = vec![create_test_finding(
            "micro-behaviors/communications/socket/send/send",
        )];
        let report = create_test_report_with_findings(findings);
        let binary_data = b"test";

        let mapper = CapabilityMapper::empty();
        let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

        // Test exact match - should find the finding directly
        let condition = Condition::Trait {
            id: "micro-behaviors/communications/socket/send/send".to_string(),
        };
        let result = debugger.debug_condition(&condition);

        assert!(
            result.matched,
            "Exact trait ID match should be found in findings"
        );
        assert!(
            result.details.iter().any(|d| d.contains("exact match")),
            "Details should mention exact match, got: {:?}",
            result.details
        );
    }

    /// Test that suffix matching works for short trait names
    #[test]
    fn test_debug_trait_reference_suffix_match() {
        let findings = vec![create_test_finding(
            "micro-behaviors/execution/process/terminate",
        )];
        let report = create_test_report_with_findings(findings);
        let binary_data = b"test";

        let mapper = CapabilityMapper::empty();
        let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

        // Test suffix match with short name
        let condition = Condition::Trait {
            id: "terminate".to_string(),
        };
        let result = debugger.debug_condition(&condition);

        assert!(
            result.matched,
            "Short trait name 'terminate' should match via suffix '/terminate'"
        );
        assert!(
            result.details.iter().any(|d| d.contains("suffix")),
            "Details should mention suffix match, got: {:?}",
            result.details
        );
    }

    /// Test that condition match status is consistent with overall match status
    /// This is the core test for the mismatch bug we fixed
    #[test]
    fn test_debug_composite_no_condition_overall_mismatch() {
        // Create findings that should satisfy a composite's conditions
        let findings = vec![
            create_test_finding("micro-behaviors/execution/dylib/load/objc-method-swizzle"),
            create_test_finding("micro-behaviors/execution/dylib/load/nsbundle"),
            create_test_finding("micro-behaviors/communications/socket/send/send"),
        ];

        // Create a MachO file type report
        let target = TargetInfo {
            path: "/test/app.macho".to_string(),
            file_type: "macho".to_string(),
            size_bytes: 50000,
            sha256: "test".to_string(),
            architectures: Some(vec!["arm64".to_string()]),
        };
        let mut report = AnalysisReport::new(target);
        report.findings = findings;
        let binary_data = b"\xCF\xFA\xED\xFE"; // MachO magic

        let mapper = create_debug_test_mapper();
        let debugger =
            RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::MacOS], None);

        // Test the objc-app-hook composite if it exists
        let result = debugger
            .debug_rule("objectives/lateral-movement/trojanize/app/objc-app-hook")
            .expect("expected local objc-app-hook composite fixture");
        // KEY INVARIANT: If all condition groups show matched, overall should be matched
        // (unless there's a skip reason or other constraint that explains the difference)
        let all_condition_groups_matched = result
            .condition_results
            .iter()
            .filter(|c| {
                c.condition_desc.starts_with("all:")
                    || c.condition_desc.starts_with("any:")
                    || c.condition_desc.starts_with("none:")
            })
            .all(|c| c.matched);

        if all_condition_groups_matched && result.skipped_reason.is_none() {
            // If all groups match and no skip reason, overall should match
            assert!(
                result.matched,
                "All condition groups show matched but overall is NOT MATCHED - this is the mismatch bug!\n\
                 Condition results: {:?}",
                result
                    .condition_results
                    .iter()
                    .map(|c| format!("{}: {}", c.condition_desc, c.matched))
                    .collect::<Vec<_>>()
            );
        }

        // Also verify: if overall matched, at least one condition group should match
        if result.matched {
            let has_matched_condition = result.condition_results.iter().any(|c| c.matched);
            assert!(
                has_matched_condition,
                "Overall matched but no condition groups show matched"
            );
        }
    }

    /// Test that trait not in findings shows as not matched even if re-evaluation would succeed
    #[test]
    fn test_debug_trait_reference_not_in_findings() {
        // Create an empty findings list
        let report = create_test_report_with_findings(vec![]);
        let binary_data = b"test data with some content";

        let mapper = CapabilityMapper::empty();
        let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

        // Test a trait that exists in definitions but not in findings
        let condition = Condition::Trait {
            id: "micro-behaviors/execution/process/terminate".to_string(),
        };
        let result = debugger.debug_condition(&condition);

        // The trait is not in findings, so it should NOT match
        // (regardless of whether re-evaluation would succeed)
        assert!(
            !result.matched,
            "Trait not in findings should show as not matched"
        );
    }

    /// Test that prefix directory matching mirrors eval_trait behavior
    #[test]
    fn test_debug_trait_reference_prefix_match_mirrors_eval() {
        // Create findings with a specific path
        let findings = vec![
            create_test_finding("micro-behaviors/communications/socket/send/unix"),
            create_test_finding("micro-behaviors/communications/socket/send/windows"),
        ];
        let report = create_test_report_with_findings(findings);
        let binary_data = b"test";

        let mapper = CapabilityMapper::empty();
        let debugger = RuleDebugger::new(&mapper, &report, binary_data, vec![Platform::All], None);

        // Test prefix match - should find both findings
        let condition = Condition::Trait {
            id: "micro-behaviors/communications/socket/send".to_string(),
        };
        let result = debugger.debug_condition(&condition);

        assert!(
            result.matched,
            "Prefix 'micro-behaviors/communications/socket/send' should match findings with that prefix"
        );
        // Should mention both matched findings
        let detail_text = result.details.join(" ");
        assert!(
            detail_text.contains("2 finding"),
            "Should mention 2 findings matched, got: {}",
            detail_text
        );
    }
}
