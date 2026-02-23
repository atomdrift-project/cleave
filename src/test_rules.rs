//! Debug/test rule evaluation module.
#![allow(clippy::unwrap_used, clippy::expect_used)]
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

use crate::capabilities::validation::calculate_composite_precision;
use crate::capabilities::CapabilityMapper;
use crate::composite_rules::debug::{DebugCollector, EvaluationDebug, RuleType};
use crate::composite_rules::{
    CompositeTrait, Condition, EvaluationContext, FileType as RuleFileType, Platform, SectionMap,
    TraitDefinition,
};
use crate::types::{AnalysisReport, Evidence};
use colored::Colorize;
use rustc_hash::{FxHashSet, FxHasher};
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::RwLock;

/// Compute a fast hash of a string for deduplication.
#[inline]
fn hash_str(s: &str) -> u64 {
    let mut hasher = FxHasher::default();
    s.hash(&mut hasher);
    hasher.finish()
}

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
}

impl<'a> RuleDebugger<'a> {
    /// Create a new rule debugger.
    ///
    /// # Arguments
    /// * `mapper` - The capability mapper with rule definitions
    /// * `report` - The analysis report for the target file
    /// * `binary_data` - Raw file contents
    /// * `composites` - Composite rule definitions
    /// * `traits` - Trait definitions
    /// * `platforms` - Platform filter from CLI (use vec![Platform::All] to show all)
    /// * `inline_yara_results` - Pre-scanned inline YARA results (matches production path)
    pub(crate) fn new(
        mapper: &'a CapabilityMapper,
        report: &'a AnalysisReport,
        binary_data: &'a [u8],
        composites: &'a [CompositeTrait],
        traits: &'a [TraitDefinition],
        platforms: Vec<Platform>,
        inline_yara_results: Option<&'a HashMap<String, Vec<Evidence>>>,
    ) -> Self {
        let file_type = detect_file_type(&report.target.file_type);
        let section_map = SectionMap::from_binary(binary_data);

        Self {
            mapper,
            report,
            binary_data,
            file_type,
            platforms,
            composites,
            traits,
            section_map,
            inline_yara_results,
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
        if let Some(sec_name) = section {
            if let Some((sec_start, sec_end)) = self.section_map.bounds(sec_name) {
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
            platforms: self.platforms.clone(),
            additional_findings: None,
            cached_ast: None,
            finding_id_index: Some(self.build_finding_index()),
            debug_collector,
            section_map: Some(self.section_map.clone()),
            inline_yara_results: self.inline_yara_results,
            cached_kv_format: std::sync::OnceLock::new(),
            cached_kv_parsed: std::sync::OnceLock::new(),
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
            &trait_def.id,
            "trait",
            &trait_def.desc,
            finding.is_some(),
            &trait_def.r#if.condition,
        );

        // Add warning about trait-level `not` exclusions
        if let Some(not_exceptions) = &trait_def.not {
            if !not_exceptions.is_empty() && !result.condition_results.is_empty() {
                let not_warning = ConditionDebugResult::new(
                    format!(
                        "⚠️  {} trait-level not: exclusion(s) may filter matches in production",
                        not_exceptions.len()
                    ),
                    true, // just informational
                );
                result.condition_results.push(not_warning);
            }
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
        rule_id: &str,
        rule_type: &str,
        desc: &str,
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
            rule_id,
            &composite_lookup,
            &trait_lookup,
            &mut cache,
            &mut visiting,
        );

        let skipped_reason = eval_debug.skip_reason.map(|r| r.to_string());

        // If skipped, return early with skip reason
        if skipped_reason.is_some() {
            return RuleDebugResult {
                rule_id: rule_id.to_string(),
                rule_type: rule_type.to_string(),
                description: desc.to_string(),
                matched: false,
                skipped_reason,
                requirements: format!("Condition: {:?}", describe_condition(condition)),
                condition_results: Vec::new(),
                context_info: self.context_info(),
                precision: Some(precision_value),
            };
        }

        // For matched/unmatched, still use debug_condition for detailed condition info
        let cond_result = self.debug_condition(condition);

        RuleDebugResult {
            rule_id: rule_id.to_string(),
            rule_type: rule_type.to_string(),
            description: desc.to_string(),
            matched,
            skipped_reason: None,
            requirements: format!("Condition: {:?}", describe_condition(condition)),
            condition_results: vec![cond_result],
            context_info: self.context_info(),
            precision: Some(precision_value),
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
                    any_matched_count += 1;
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

        // Evaluate 'none' conditions
        if let Some(none_conds) = &composite.none {
            let mut none_results = Vec::new();
            let mut none_matched_count = 0;
            for cond in none_conds {
                let cond_result = self.debug_condition(cond);
                if cond_result.matched {
                    none_matched_count += 1;
                }
                none_results.push(cond_result);
            }
            let none_passed = none_matched_count == 0;
            let mut group = ConditionDebugResult::new(
                format!("none: ({} matched, need 0)", none_matched_count),
                none_passed,
            );
            group.sub_results = none_results;
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

    /// Debug a single condition
    fn debug_condition(&self, condition: &Condition) -> ConditionDebugResult {
        let ctx = EvaluationContext {
            report: self.report,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platforms: self.platforms.clone(),
            additional_findings: None,
            cached_ast: None,
            finding_id_index: None,
            debug_collector: None,
            section_map: Some(self.section_map.clone()),
            inline_yara_results: None,
            cached_kv_format: std::sync::OnceLock::new(),
            cached_kv_parsed: std::sync::OnceLock::new(),
        };

        match condition {
            Condition::Trait { id } => self.debug_trait_reference(id),
            Condition::String {
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            } => self.debug_string_condition(
                exact,
                substr,
                regex,
                word,
                *case_insensitive,
                section.as_ref(),
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
            ),
            Condition::Symbol {
                exact,
                substr,
                regex,
                ..
            } => self.debug_symbol_condition(exact, substr, regex),
            Condition::Metrics {
                field, min, max, ..
            } => self.debug_metrics_condition(field, *min, *max),
            Condition::Yara { source, .. } => self.debug_yara_inline_condition(source),
            Condition::Structure { feature, .. } => self.debug_structure_condition(feature),
            Condition::Raw {
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
            } => self.debug_raw_condition(
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
            Condition::Ast {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                case_insensitive,
                ..
            } => {
                self.debug_ast_condition(kind, node, exact, substr, regex, query, *case_insensitive)
            }
            Condition::Kv {
                path,
                exact,
                substr,
                regex,
                case_insensitive,
                ..
            } => self.debug_kv_condition(path, exact, substr, regex, *case_insensitive),
            Condition::Hex {
                pattern,
                offset,
                offset_range,
                section,
                section_offset,
                section_offset_range,
                ..
            } => self.debug_hex_condition(
                pattern,
                *offset,
                *offset_range,
                section.as_deref(),
                *section_offset,
                *section_offset_range,
            ),
            Condition::SectionRatio {
                section,
                compare_to,
                min,
                max,
            } => self.debug_section_ratio_condition(section, compare_to, *min, *max),
            Condition::ImportCombination {
                required,
                suspicious,
                min_suspicious,
                max_total,
            } => self.debug_import_combination_condition(
                required.as_ref(),
                suspicious.as_ref(),
                *min_suspicious,
                *max_total,
            ),
            _ => {
                // Generic fallback for other condition types
                let desc = describe_condition(condition);
                let result = evaluate_condition_simple(condition, &ctx);
                ConditionDebugResult::new(desc, result.matched).with_evidence(result.evidence)
            }
        }
    }

    fn debug_trait_reference(&self, id: &str) -> ConditionDebugResult {
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

        if slash_count == 0 {
            // Short name: suffix match (e.g., "terminate" matches "execution/process/terminate")
            let suffix = format!("/{}", id);
            let matching_findings: Vec<_> = self
                .report
                .findings
                .iter()
                .filter(|f| f.id.ends_with(&suffix))
                .collect();

            if !matching_findings.is_empty() {
                let mut result = ConditionDebugResult::new(desc, true);
                result.details.push(format!(
                    "✓ {} finding(s) matched suffix '/{}' in findings:",
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
            // Directory path: prefix match (any trait within that directory)
            let prefix = format!("{}/", id);
            let matching_findings: Vec<_> = self
                .report
                .findings
                .iter()
                .filter(|f| f.id.starts_with(&prefix))
                .collect();

            if !matching_findings.is_empty() {
                let mut result = ConditionDebugResult::new(desc.clone(), true);
                result.details.push(format!(
                    "✓ {} finding(s) matched prefix '{}/' in findings:",
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
                // Trait re-evaluates as matched but wasn't in findings - this is a bug!
                result
                    .details
                    .push("⚠ Trait re-evaluates as matched but not in findings!".to_string());
                result
                    .details
                    .push("  This indicates a discrepancy in evaluation".to_string());
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

    #[allow(clippy::too_many_arguments)]
    fn debug_string_condition(
        &self,
        exact: &Option<String>,
        substr: &Option<String>,
        regex: &Option<String>,
        word: &Option<String>,
        case_insensitive: bool,
        section_constraint: Option<&String>,
        offset: Option<i64>,
        offset_range: Option<(i64, Option<i64>)>,
        section_offset: Option<i64>,
        section_offset_range: Option<(i64, Option<i64>)>,
    ) -> ConditionDebugResult {
        let pattern_desc = if let Some(e) = exact {
            format!("exact: \"{}\"", e)
        } else if let Some(c) = substr {
            format!("substr: \"{}\"", c)
        } else if let Some(r) = regex {
            format!("regex: /{}/", r)
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

        let desc = format!(
            "string: {}{}{}",
            pattern_desc,
            if case_insensitive {
                " (case_insensitive)"
            } else {
                ""
            },
            location_desc
        );

        // Resolve effective search range for location filtering
        let file_size = self.binary_data.len();
        let (search_start, search_end) = self.resolve_search_range(
            section_constraint,
            offset,
            offset_range.as_ref(),
            section_offset,
            section_offset_range.as_ref(),
            file_size,
        );
        let has_location_constraints = search_start != 0 || search_end != file_size;

        // Filter strings by location if constraints are specified
        let strings_in_range: Vec<&str> = if has_location_constraints {
            self.report
                .strings
                .iter()
                .filter(|s| {
                    if let Some(off) = s.offset {
                        let off_usize = off as usize;
                        off_usize >= search_start && off_usize < search_end
                    } else {
                        // If string has no offset info, include it (conservative)
                        true
                    }
                })
                .map(|s| s.value.as_str())
                .collect()
        } else {
            self.report
                .strings
                .iter()
                .map(|s| s.value.as_str())
                .collect()
        };

        let matched_strings = find_matching_strings(
            &strings_in_range,
            exact,
            substr,
            regex,
            word,
            case_insensitive,
        );

        // count_min is now checked at trait level, so condition matches if there are any matches
        let matched = !matched_strings.is_empty();

        let mut result = ConditionDebugResult::new(desc, matched);

        // Show search range details if location constraints are active
        if has_location_constraints {
            result.details.push(format!(
                "Search range: [{}, {}) of {} bytes",
                search_start, search_end, file_size
            ));
            result.details.push(format!(
                "Strings in range: {} of {} total",
                strings_in_range.len(),
                self.report.strings.len()
            ));
        } else {
            result
                .details
                .push(format!("Total strings in file: {}", strings_in_range.len()));
        }
        result
            .details
            .push(format!("Matching strings: {}", matched_strings.len()));

        if !matched_strings.is_empty() {
            let display_count = matched_strings.len().min(10);
            for s in matched_strings.iter().take(display_count) {
                result
                    .details
                    .push(format!("  Matched: \"{}\"", truncate_string(s, 80)));
            }
            if matched_strings.len() > display_count {
                result.details.push(format!(
                    "  ... and {} more",
                    matched_strings.len() - display_count
                ));
            }

            result.evidence = matched_strings
                .iter()
                .take(5)
                .map(|s| Evidence {
                    method: "string".to_string(),
                    source: "test_rules".to_string(),
                    value: s.to_string(),
                    location: None,
                })
                .collect();

            // Suggest better match types
            if let Some(s) = substr {
                // Check if exact would work: all matched strings equal the pattern
                if matched_strings.iter().all(|m| {
                    if case_insensitive {
                        m.eq_ignore_ascii_case(s)
                    } else {
                        *m == s
                    }
                }) {
                    result.details.push(format!(
                        "💡 All matches are exact - consider using `exact: \"{}\"` instead of `substr:`",
                        s
                    ));
                } else {
                    // Check if word would be a better fit
                    let word_pattern = if case_insensitive {
                        format!(r"(?i)\b{}\b", regex::escape(s))
                    } else {
                        format!(r"\b{}\b", regex::escape(s))
                    };
                    if let Ok(re) = regex::Regex::new(&word_pattern) {
                        let word_matches: Vec<_> =
                            matched_strings.iter().filter(|m| re.is_match(m)).collect();
                        if word_matches.len() == matched_strings.len() {
                            result.details.push(format!(
                                "💡 All matches appear as whole words - consider using `word: \"{}\"` for precision",
                                s
                            ));
                        }
                    }
                }
            } else if let Some(r) = regex {
                // Check if regex could be simplified to exact or substr
                let simple_pattern = r
                    .replace(r"\.", ".")
                    .replace(r"\-", "-")
                    .replace(r"\_", "_");
                if !simple_pattern.contains(|c: char| "^$.*+?[](){}|\\".contains(c)) {
                    // Pattern has no regex metacharacters after unescaping common ones
                    if matched_strings.iter().all(|m| {
                        if case_insensitive {
                            m.eq_ignore_ascii_case(&simple_pattern)
                        } else {
                            *m == simple_pattern
                        }
                    }) {
                        result.details.push(format!(
                            "💡 Regex matches exact string - consider using `exact: \"{}\"` instead",
                            simple_pattern
                        ));
                    } else if matched_strings.iter().all(|m| m.contains(&simple_pattern)) {
                        result.details.push(format!(
                            "💡 Regex matches substring - consider using `substr: \"{}\"` instead",
                            simple_pattern
                        ));
                    }
                }
            }
        } else if strings_in_range.len() <= 20 {
            result.details.push("All strings in range:".to_string());
            for s in &strings_in_range {
                result
                    .details
                    .push(format!("  \"{}\"", truncate_string(s, 60)));
            }
        }

        // Check alternatives if string condition didn't match
        if !matched {
            // If location constraints are active, check if pattern exists outside the range
            if has_location_constraints {
                let all_strings: Vec<&str> = self
                    .report
                    .strings
                    .iter()
                    .map(|s| s.value.as_str())
                    .collect();
                let all_matched = find_matching_strings(
                    &all_strings,
                    exact,
                    substr,
                    regex,
                    word,
                    case_insensitive,
                );
                if all_matched.len() > matched_strings.len() {
                    result.details.push(format!(
                        "💡 {} match(es) exist outside the specified range",
                        all_matched.len() - matched_strings.len()
                    ));
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

            // Check content
            let content = String::from_utf8_lossy(self.binary_data);
            let content_matched = if let Some(e) = exact {
                &content == e
            } else if let Some(c) = substr {
                content.contains(c)
            } else if let Some(r) = regex {
                let pattern = if case_insensitive {
                    format!("(?i){}", r)
                } else {
                    r.clone()
                };
                regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(&content))
            } else if let Some(w) = word {
                let pattern = if case_insensitive {
                    format!(r"(?i)\b{}\b", regex::escape(w))
                } else {
                    format!(r"\b{}\b", regex::escape(w))
                };
                regex::Regex::new(&pattern).is_ok_and(|re| re.is_match(&content))
            } else {
                false
            };
            if content_matched {
                result
                    .details
                    .push("💡 Found in raw bytes - try `type: raw` instead".to_string());
            }
        }

        // Section-related suggestions
        if self.section_map.has_sections() {
            // Track which sections contain matched strings
            let mut sections_with_matches: HashMap<String, usize> = HashMap::new();
            for string_info in &self.report.strings {
                // Check if this string matches our pattern
                let s = &string_info.value;
                let string_matched = if let Some(e) = exact {
                    if case_insensitive {
                        s.eq_ignore_ascii_case(e)
                    } else {
                        s == e
                    }
                } else if let Some(c) = substr {
                    if case_insensitive {
                        s.to_lowercase().contains(&c.to_lowercase())
                    } else {
                        s.contains(c.as_str())
                    }
                } else if let Some(r) = regex {
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
                };

                if string_matched {
                    // Get section for this string's offset
                    if let Some(offset) = string_info.offset {
                        if let Some(section) = self.section_map.section_for_offset(offset) {
                            *sections_with_matches
                                .entry(section.to_string())
                                .or_insert(0) += 1;
                        }
                    }
                }
            }

            if !sections_with_matches.is_empty() {
                // If section constraint was specified but didn't match, suggest alternatives
                if let Some(req_section) = section_constraint {
                    // Check if the required section has matches
                    let has_match_in_required = sections_with_matches
                        .keys()
                        .any(|sec| SectionMap::section_matches(sec, req_section));

                    if !has_match_in_required && !sections_with_matches.is_empty() {
                        let alt_sections: Vec<_> = sections_with_matches
                            .iter()
                            .map(|(s, c)| format!("{} ({} matches)", s, c))
                            .collect();
                        result.details.push(format!(
                            "💡 Pattern not found in section '{}', but found in: {}",
                            req_section,
                            alt_sections.join(", ")
                        ));
                    }
                } else if matched {
                    // No section constraint, but matches found - suggest using section filter
                    let section_summary: Vec<_> = sections_with_matches
                        .iter()
                        .map(|(s, c)| format!("{}: {}", s, c))
                        .collect();
                    result.details.push(format!(
                        "📍 Matches by section: {}",
                        section_summary.join(", ")
                    ));
                    if let (1, Some(section)) = (
                        sections_with_matches.len(),
                        sections_with_matches.keys().next(),
                    ) {
                        result.details.push(format!(
                            "💡 All matches in '{}' - consider `section: \"{}\"` for precision",
                            section, section
                        ));
                    }
                }
            }
        } else if section_constraint.is_some() {
            // Section constraint specified but file has no sections
            result.details.push(
                "⚠️  Section constraint specified but file has no binary sections".to_string(),
            );
        }

        result
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

        let value = self
            .report
            .metrics
            .as_ref()
            .and_then(|m| crate::types::scores::get_metric_value(m, field));
        let matched =
            value.is_some_and(|v| min.is_none_or(|m| v >= m) && max.is_none_or(|m| v <= m));

        let mut result = ConditionDebugResult::new(desc, matched);

        if let Some(v) = value {
            result.details.push(format!("Actual value: {:.4}", v));
        } else {
            result
                .details
                .push(format!("Metric '{}' not found in report", field));
            if let Some(metrics) = &self.report.metrics {
                result.details.push("Available metrics:".to_string());
                if let Some(binary) = &metrics.binary {
                    result.details.push(format!(
                        "  binary.code_to_data_ratio: {:.2}",
                        binary.code_to_data_ratio
                    ));
                    result
                        .details
                        .push(format!("  binary.string_count: {}", binary.string_count));
                    result.details.push(format!(
                        "  binary.function_count: {}",
                        binary.function_count
                    ));
                    result.details.push(format!(
                        "  binary.avg_complexity: {:.2}",
                        binary.avg_complexity
                    ));
                    result
                        .details
                        .push(format!("  binary.file_size: {}", binary.file_size));
                }
                if let Some(text) = &metrics.text {
                    result
                        .details
                        .push(format!("  text.total_lines: {}", text.total_lines));
                }
                if let Some(funcs) = &metrics.functions {
                    result
                        .details
                        .push(format!("  functions.count: {}", funcs.total));
                }
                if let Some(ids) = &metrics.identifiers {
                    result.details.push(format!(
                        "  identifiers.single_char_ratio: {:.4}",
                        ids.single_char_ratio
                    ));
                    result
                        .details
                        .push(format!("  identifiers.avg_length: {:.4}", ids.avg_length));
                    result
                        .details
                        .push(format!("  identifiers.total: {}", ids.total));
                    result
                        .details
                        .push(format!("  identifiers.unique: {}", ids.unique_count));
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
            platforms: self.platforms.clone(),
            additional_findings: None,
            cached_ast: None,
            finding_id_index: None,
            debug_collector: None,
            section_map: None,
            inline_yara_results: None,
            cached_kv_format: std::sync::OnceLock::new(),
            cached_kv_parsed: std::sync::OnceLock::new(),
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

    fn debug_structure_condition(&self, feature: &str) -> ConditionDebugResult {
        let desc = format!("structure: {}", feature);

        let matched = self.report.structure.iter().any(|s| s.id == feature);

        let mut result = ConditionDebugResult::new(desc, matched);

        result.details.push(format!(
            "Structures in file: {}",
            self.report.structure.len()
        ));
        if self.report.structure.len() <= 20 {
            for s in &self.report.structure {
                result.details.push(format!("  {}", s.id));
            }
        }

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

    fn debug_kv_condition(
        &self,
        path: &str,
        exact: &Option<String>,
        substr: &Option<String>,
        regex: &Option<String>,
        case_insensitive: bool,
    ) -> ConditionDebugResult {
        let pattern_desc = if let Some(e) = exact {
            format!("exact: \"{}\"", truncate_string(e, 40))
        } else if let Some(c) = substr {
            format!("substr: \"{}\"", truncate_string(c, 40))
        } else if let Some(r) = regex {
            format!("regex: /{}/", truncate_string(r, 40))
        } else {
            "exists".to_string()
        };

        let desc = format!("kv: path=\"{}\" {}", path, pattern_desc);

        // Use the actual kv evaluator
        let condition = Condition::Kv {
            path: path.to_string(),
            exact: exact.clone(),
            substr: substr.clone(),
            regex: regex.clone(),
            case_insensitive,
            exists: None,
            size_min: None,
            size_max: None,
            compiled_regex: regex.as_ref().and_then(|r| regex::Regex::new(r).ok()),
        };

        // Create evaluation context
        let ctx = EvaluationContext::new(
            self.report,
            self.binary_data,
            self.file_type,
            self.platforms.clone(),
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
                } else if let Ok(yaml) = serde_yaml::from_str::<serde_json::Value>(content) {
                    if let Some(obj) = yaml.as_object() {
                        let top_keys: Vec<_> = obj.keys().take(10).collect();
                        result
                            .details
                            .push(format!("Available top-level keys: {:?}", top_keys));
                    }
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
            format!("ast: query={}", truncate_string(q, 50))
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
                "ast: {} {} (case_insensitive: {})",
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

        // For simple mode, use eval_ast directly
        let ctx = EvaluationContext {
            report: self.report,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platforms: self.platforms.clone(),
            additional_findings: None,
            cached_ast: None,
            finding_id_index: None,
            debug_collector: None,
            section_map: None,
            inline_yara_results: None,
            cached_kv_format: std::sync::OnceLock::new(),
            cached_kv_parsed: std::sync::OnceLock::new(),
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
        }

        result
    }

    #[allow(clippy::too_many_arguments)]
    fn debug_hex_condition(
        &self,
        pattern: &str,
        offset: Option<i64>,
        offset_range: Option<(i64, Option<i64>)>,
        section: Option<&str>,
        section_offset: Option<i64>,
        section_offset_range: Option<(i64, Option<i64>)>,
    ) -> ConditionDebugResult {
        use crate::composite_rules::evaluators::{eval_hex, ContentLocationParams};

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
            platforms: self.platforms.clone(),
            additional_findings: None,
            cached_ast: None,
            finding_id_index: None,
            debug_collector: None,
            section_map: Some(self.section_map.clone()),
            inline_yara_results: None,
            cached_kv_format: std::sync::OnceLock::new(),
            cached_kv_parsed: std::sync::OnceLock::new(),
        };

        let eval_result = eval_hex(
            pattern,
            &ContentLocationParams {
                section: section.map(std::borrow::ToOwned::to_owned),
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            },
            &ctx,
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

    fn debug_section_ratio_condition(
        &self,
        section: &str,
        compare_to: &str,
        min_ratio: Option<f64>,
        max_ratio: Option<f64>,
    ) -> ConditionDebugResult {
        let desc = format!(
            "section_ratio: {} vs {} [{:?}, {:?}]",
            section, compare_to, min_ratio, max_ratio
        );

        // Get section bounds
        let section_size = self
            .section_map
            .bounds(section)
            .map(|bounds| bounds.1 - bounds.0);

        let total_size = self.binary_data.len() as u64;

        let (ratio, matched) = if let Some(sec_size) = section_size {
            let compare_size = if compare_to == "total" {
                total_size
            } else if let Some(bounds) = self.section_map.bounds(compare_to) {
                bounds.1 - bounds.0
            } else {
                total_size
            };

            let r = if compare_size > 0 {
                sec_size as f64 / compare_size as f64
            } else {
                0.0
            };

            let min_ok = min_ratio.is_none_or(|min| r >= min);
            let max_ok = max_ratio.is_none_or(|max| r <= max);
            (Some(r), min_ok && max_ok)
        } else {
            (None, false)
        };

        let mut result = ConditionDebugResult::new(desc, matched);

        if self.section_map.has_sections() {
            result.details.push(format!(
                "Available sections: {}",
                self.section_map.section_names().join(", ")
            ));
        } else {
            result
                .details
                .push("No sections found in binary".to_string());
        }

        if let Some(r) = ratio {
            result.details.push(format!(
                "Ratio: {:.4} ({} / {})",
                r,
                section_size.unwrap_or(0),
                if compare_to == "total" {
                    total_size
                } else {
                    self.section_map
                        .bounds(compare_to)
                        .map(|b| b.1 - b.0)
                        .unwrap_or(0)
                }
            ));
        } else {
            result
                .details
                .push(format!("Section '{}' not found", section));
        }

        result
    }

    fn debug_import_combination_condition(
        &self,
        required: Option<&Vec<String>>,
        suspicious: Option<&Vec<String>>,
        min_suspicious: Option<usize>,
        max_total: Option<usize>,
    ) -> ConditionDebugResult {
        let desc = format!(
            "import_combination: required={}, suspicious={}, min_suspicious={:?}, max_total={:?}",
            required.map(std::vec::Vec::len).unwrap_or(0),
            suspicious.map(std::vec::Vec::len).unwrap_or(0),
            min_suspicious,
            max_total
        );

        let imports: Vec<&str> = self
            .report
            .imports
            .iter()
            .map(|i| i.symbol.as_str())
            .collect();
        let total_imports = imports.len();

        // Check required imports
        let required_ok = required
            .map(|req| req.iter().all(|r| imports.iter().any(|i| i.contains(r))))
            .unwrap_or(true);

        // Count suspicious imports
        let suspicious_count = suspicious
            .map(|susp| {
                susp.iter()
                    .filter(|s| imports.iter().any(|i| i.contains(*s)))
                    .count()
            })
            .unwrap_or(0);

        let suspicious_ok = min_suspicious.is_none_or(|min| suspicious_count >= min);
        let total_ok = max_total.is_none_or(|max| total_imports <= max);

        let matched = required_ok && suspicious_ok && total_ok;

        let mut result = ConditionDebugResult::new(desc, matched);

        result
            .details
            .push(format!("Total imports: {}", total_imports));

        if let Some(req) = required {
            let found: Vec<&String> = req
                .iter()
                .filter(|r| imports.iter().any(|i| i.contains(*r)))
                .collect();
            result.details.push(format!(
                "Required imports found: {}/{}",
                found.len(),
                req.len()
            ));
            if found.len() < req.len() {
                let missing: Vec<&String> = req
                    .iter()
                    .filter(|r| !imports.iter().any(|i| i.contains(*r)))
                    .collect();
                for m in missing.iter().take(5) {
                    result.details.push(format!("  Missing: {}", m));
                }
            }
        }

        if let Some(susp) = suspicious {
            let found: Vec<&String> = susp
                .iter()
                .filter(|s| imports.iter().any(|i| i.contains(*s)))
                .collect();
            result.details.push(format!(
                "Suspicious imports found: {}/{}",
                found.len(),
                susp.len()
            ));
            for f in found.iter().take(5) {
                result.details.push(format!("  Found: {}", f));
            }
        }

        result
    }

    // Helper to find trait definition by ID
    fn find_trait_definition(&self, id: &str) -> Option<&crate::composite_rules::TraitDefinition> {
        self.mapper.find_trait(id)
    }

    // Helper to find composite rule by ID
    fn find_composite_rule(&self, id: &str) -> Option<&crate::composite_rules::CompositeTrait> {
        self.mapper.composite_rules.iter().find(|r| r.id == id)
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
        Condition::String {
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
        } => {
            let loc = format_location_suffix(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
            );
            if let Some(e) = exact {
                format!("string[exact]: \"{}\"{}", truncate_string(e, 30), loc)
            } else if let Some(c) = substr {
                format!("string[substr]: \"{}\"{}", truncate_string(c, 30), loc)
            } else if let Some(r) = regex {
                format!("string[regex]: /{}/{}", truncate_string(r, 30), loc)
            } else if let Some(w) = word {
                format!("string[word]: \"{}\"{}", w, loc)
            } else {
                format!("string[?]{}", loc)
            }
        }
        Condition::Symbol {
            exact,
            substr,
            regex,
            ..
        } => {
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
        Condition::Metrics {
            field, min, max, ..
        } => {
            format!("metrics: {} [{:?}, {:?}]", field, min, max)
        }
        Condition::Yara { .. } => "yara[inline]".to_string(),
        Condition::Structure { feature, .. } => format!("structure: {}", feature),
        Condition::Raw {
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
        } => {
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
        Condition::Kv {
            path,
            exact,
            substr,
            regex,
            ..
        } => {
            let matcher = if exact.is_some() {
                "exact"
            } else if substr.is_some() {
                "substr"
            } else if regex.is_some() {
                "regex"
            } else {
                "exists"
            };
            format!("kv[{}]: path=\"{}\"", matcher, truncate_string(path, 30))
        }
        Condition::Hex {
            pattern,
            offset,
            offset_range,
            ..
        } => {
            let mut desc = format!("hex: \"{}\"", truncate_string(pattern, 30));
            if let Some(off) = offset {
                desc.push_str(&format!(" @{:#x}", off));
            } else if let Some((start, _)) = offset_range {
                desc.push_str(&format!(" @{:#x}+", start));
            }
            desc
        }
        Condition::SectionRatio {
            section,
            compare_to,
            min,
            max,
        } => {
            format!(
                "section_ratio: {} vs {} [{:?}-{:?}]",
                section,
                compare_to,
                min.unwrap_or(0.0),
                max.unwrap_or(1.0)
            )
        }
        Condition::ImportCombination {
            required,
            suspicious,
            min_suspicious,
            ..
        } => {
            format!(
                "import_combination: req={}, susp={}, min={}",
                required.as_ref().map(std::vec::Vec::len).unwrap_or(0),
                suspicious.as_ref().map(std::vec::Vec::len).unwrap_or(0),
                min_suspicious.unwrap_or(0)
            )
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

    if let Some(none) = &composite.none {
        parts.push(format!("none: {} exclusions", none.len()));
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
        eval_basename, eval_exports_count, eval_section, eval_string_count, eval_syscall,
    };

    // Evaluate conditions that fall through to the _ => case in debug_condition
    match condition {
        Condition::Section {
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
        } => eval_section(
            exact.as_ref(),
            substr.as_ref(),
            regex.as_ref(),
            word.as_ref(),
            *case_insensitive,
            *length_min,
            *length_max,
            *entropy_min,
            *entropy_max,
            *readable,
            *writable,
            *executable,
            ctx,
        ),
        Condition::Syscall { name, number, arch } => {
            eval_syscall(name.as_ref(), number.as_ref(), arch.as_ref(), ctx)
        }
        Condition::ExportsCount { min, max } => eval_exports_count(*min, *max, ctx),
        Condition::StringCount {
            min,
            max,
            min_length,
            regex,
            compiled_regex,
        } => eval_string_count(
            *min,
            *max,
            *min_length,
            regex.as_ref(),
            compiled_regex.as_ref(),
            ctx,
        ),
        Condition::Basename {
            exact,
            substr,
            regex,
            case_insensitive,
            ..
        } => eval_basename(
            exact.as_ref(),
            substr.as_ref(),
            regex.as_ref(),
            *case_insensitive,
            ctx,
        ),
        _ => crate::composite_rules::context::ConditionResult::no_match(),
    }
}

fn detect_file_type(file_type: &str) -> RuleFileType {
    RuleFileType::from_str(file_type)
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
mod tests {
    use super::*;
    use crate::types::{AnalysisReport, Finding, FindingKind, TargetInfo};

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

        let mapper = CapabilityMapper::new_without_validation();
        let composites = &mapper.composite_rules;
        let traits = mapper.trait_definitions();

        let debugger = RuleDebugger::new(
            &mapper,
            &report,
            binary_data,
            composites,
            traits,
            vec![Platform::All],
            None,
        );

        // Test a composite rule that references traits by prefix
        // The rule should match if the findings contain matching prefixes
        if let Some(result) =
            debugger.debug_rule("objectives/command-and-control/webshell/backdoor/php-rce")
        {
            // Verify consistency: if matched is true, at least one condition should show as matched
            if result.matched {
                let has_matched_condition = result.condition_results.iter().any(|c| c.matched);
                assert!(
                    has_matched_condition,
                    "Rule marked as matched but no conditions show as matched"
                );
            }
        }
    }

    /// Test that skip reasons are correctly captured
    #[test]
    fn test_debug_rule_skip_reason_file_type_mismatch() {
        // Create a PHP report but test a rule that requires ELF
        let report = create_test_report_with_findings(vec![]);
        let binary_data = b"<?php test ?>";

        let mapper = CapabilityMapper::new_without_validation();
        let composites = &mapper.composite_rules;
        let traits = mapper.trait_definitions();

        let debugger = RuleDebugger::new(
            &mapper,
            &report,
            binary_data,
            composites,
            traits,
            vec![Platform::All],
            None,
        );

        // Test a rule that requires ELF file type (zstd-magic is for binaries)
        if let Some(result) = debugger.debug_rule("micro-behaviors/data/embedded/zstd-magic") {
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

        let mapper = CapabilityMapper::new_without_validation();
        let composites = &mapper.composite_rules;
        let traits = mapper.trait_definitions();

        let debugger = RuleDebugger::new(
            &mapper,
            &report,
            binary_data,
            composites,
            traits,
            vec![Platform::Linux],
            None,
        );

        // Test mirai detection which has size_min: 30000
        if let Some(result) = debugger.debug_rule("known/malware/botnet/mirai/detected") {
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

        let mapper = CapabilityMapper::new_without_validation();
        let composites = &mapper.composite_rules;
        let traits = mapper.trait_definitions();

        let debugger = RuleDebugger::new(
            &mapper,
            &report,
            binary_data,
            composites,
            traits,
            vec![Platform::All],
            None,
        );

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

        let mapper = CapabilityMapper::new_without_validation();
        let composites = &mapper.composite_rules;
        let traits = mapper.trait_definitions();

        let debugger = RuleDebugger::new(
            &mapper,
            &report,
            binary_data,
            composites,
            traits,
            vec![Platform::All],
            None,
        );

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

        let mapper = CapabilityMapper::new_without_validation();
        let composites = &mapper.composite_rules;
        let traits = mapper.trait_definitions();

        let debugger = RuleDebugger::new(
            &mapper,
            &report,
            binary_data,
            composites,
            traits,
            vec![Platform::All],
            None,
        );

        // Find and debug a composite rule
        if let Some(result) =
            debugger.debug_rule("objectives/command-and-control/webshell/backdoor/php-rce")
        {
            // For each condition group (all/any/none), verify count matches
            for cond_result in &result.condition_results {
                // Parse the condition description to get claimed count
                // e.g., "any: (4/5 needed: 1)"
                if cond_result.condition_desc.contains("(") {
                    let matched_in_sub =
                        cond_result.sub_results.iter().filter(|r| r.matched).count();

                    // The description should contain the correct count
                    if let Some(start) = cond_result.condition_desc.find('(') {
                        if let Some(slash) = cond_result.condition_desc.find('/') {
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

        let mapper = CapabilityMapper::new_without_validation();
        let composites = &mapper.composite_rules;
        let traits = mapper.trait_definitions();

        let debugger = RuleDebugger::new(
            &mapper,
            &report,
            binary_data,
            composites,
            traits,
            vec![Platform::All],
            None,
        );

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

        let mapper = CapabilityMapper::new_without_validation();
        let composites = &mapper.composite_rules;
        let traits = mapper.trait_definitions();

        let debugger = RuleDebugger::new(
            &mapper,
            &report,
            binary_data,
            composites,
            traits,
            vec![Platform::All],
            None,
        );

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

        let mapper = CapabilityMapper::new_without_validation();
        let composites = &mapper.composite_rules;
        let traits = mapper.trait_definitions();

        let debugger = RuleDebugger::new(
            &mapper,
            &report,
            binary_data,
            composites,
            traits,
            vec![Platform::MacOS],
            None,
        );

        // Test the objc-app-hook composite if it exists
        if let Some(result) =
            debugger.debug_rule("objectives/lateral-movement/trojanize/app/objc-app-hook")
        {
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
                    result.condition_results.iter()
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
    }

    /// Test that trait not in findings shows as not matched even if re-evaluation would succeed
    #[test]
    fn test_debug_trait_reference_not_in_findings() {
        // Create an empty findings list
        let report = create_test_report_with_findings(vec![]);
        let binary_data = b"test data with some content";

        let mapper = CapabilityMapper::new_without_validation();
        let composites = &mapper.composite_rules;
        let traits = mapper.trait_definitions();

        let debugger = RuleDebugger::new(
            &mapper,
            &report,
            binary_data,
            composites,
            traits,
            vec![Platform::All],
            None,
        );

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

        let mapper = CapabilityMapper::new_without_validation();
        let composites = &mapper.composite_rules;
        let traits = mapper.trait_definitions();

        let debugger = RuleDebugger::new(
            &mapper,
            &report,
            binary_data,
            composites,
            traits,
            vec![Platform::All],
            None,
        );

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
