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
use crate::capabilities::precision::{
    atomic_calibrated_max, calculate_composite_precision, composite_calibrated_max,
    composite_inflation_warning_threshold, file_type_precision_penalty, platform_precision_penalty,
};
use crate::composite_rules::debug::{DebugCollector, EvaluationDebug, RuleType};
use crate::composite_rules::{
    Arch, CompositeTrait, Condition, EvaluationContext, FileType as RuleFileType, KvQuery,
    Platform, SectionMap, TraitDefinition, TypeMask,
};
use crate::composite_rules::{
    HexQuery, MetricsQuery, PathQuery, RawQuery, SectionQuery, SymbolQuery, TextQuery,
    TreeSitterQuery,
};
use crate::types::{AnalysisReport, Evidence};
use colored::Colorize;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

mod conditions;

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
    /// True when this composite is a bare OR (`any:` with `needs <= 1`, no
    /// `all:`) that the real mapper filters from output as low-value. Such a
    /// rule can MATCH here yet never appear in a production scan, so the report
    /// flags it (see `CapabilityMapper::is_low_value_any_rule`).
    pub low_value_any: bool,
    /// Why a rule that matched its conditions here is nonetheless absent from
    /// (or emitted at a different criticality than) the real scan's findings.
    ///
    /// `test-rules` evaluates a rule in isolation, so it reports the raw match.
    /// The scan then applies `unless:`, `downgrade:` and the low-tier strip, any
    /// of which can change or remove the finding — and a bare "MATCHED" with no
    /// trace of that is the most misleading output this command can produce.
    pub emission_notes: Vec<String>,
}

/// Mirror of `CapabilityMapper::is_low_value_any_rule` for a single rule: a
/// composite with only an `any:` clause and `needs <= 1` (or a single `any:`
/// entry) is a plain OR that adds no signal over its matched leg, so the mapper
/// drops it from findings. test-rules evaluates rules in isolation and does not,
/// so it surfaces the discrepancy explicitly.
fn composite_is_low_value_any(composite: &CompositeTrait) -> bool {
    if composite.all.is_some() {
        return false;
    }
    composite
        .any
        .as_ref()
        .is_some_and(|any| any.len() == 1 || composite.needs.unwrap_or(1) <= 1)
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
    /// Finding id → type mask of the members that produced it, built the way
    /// the archive analyzer builds it for container composites. `None` for a
    /// plain file, where production evaluation passes no origins either.
    finding_origins: Option<rustc_hash::FxHashMap<String, TypeMask>>,
    /// `for:` mask of the composite whose legs are being traced, so a leg the
    /// origin filter drops is shown as ✗ rather than "found in findings".
    leg_for_mask: std::cell::Cell<TypeMask>,
}

/// Origin masks for a container report, mirroring
/// `analyzers::archive` (member findings carry their member's type bit;
/// anything no member produced belongs to the container itself).
///
/// Without this, test-rules evaluated container composites with every origin
/// allowed and reported MATCHED for correlators whose legs a real scan drops
/// because the leg's member type is missing from the rule's `for:`.
///
/// What the container node finds itself -- its own atomic pass over its
/// bytes, and the path traits run over its entry list -- carries the
/// container's bit even when a member found the same id, as it does in the
/// scan. Both are recomputed here rather than read off `report.findings`,
/// where they sit beside the members' rolled-up findings. Leaving the bit off
/// reported such a leg as dropped by the origin filter when it was not.
fn container_finding_origins(
    report: &AnalysisReport,
    mapper: &CapabilityMapper,
    container_data: &[u8],
) -> Option<rustc_hash::FxHashMap<String, TypeMask>> {
    if report.files.is_empty() {
        return None;
    }
    let mut origins: rustc_hash::FxHashMap<String, TypeMask> = rustc_hash::FxHashMap::default();
    for member in &report.files {
        let bit = RuleFileType::from_str(&member.file_type).type_bit();
        for finding in &member.findings {
            *origins.entry(finding.id.to_string()).or_default() |= bit;
        }
    }
    let container_bit = RuleFileType::from_str(&report.target.file_type).type_bit();
    for finding in &report.findings {
        origins
            .entry(finding.id.to_string())
            .or_insert(container_bit);
    }
    for finding in mapper.evaluate_traits_with_ast(report, container_data, None, None) {
        *origins.entry(finding.id.to_string()).or_default() |= container_bit;
    }
    let entry_names: Vec<String> = report
        .archive_contents
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    if !entry_names.is_empty() {
        for finding in mapper.evaluate_basename_traits_for_entries(&entry_names) {
            *origins.entry(finding.id.to_string()).or_default() |= container_bit;
        }
    }
    Some(origins)
}

impl<'a> RuleDebugger<'a> {
    /// Create a new rule debugger, parsing `binary_data` with filefacts'
    /// default options.
    #[cfg(test)]
    pub(crate) fn new(
        mapper: &'a CapabilityMapper,
        report: &'a AnalysisReport,
        binary_data: &'a [u8],
        platforms: Vec<Platform>,
        inline_yara_results: Option<&'a HashMap<String, Vec<Evidence>>>,
    ) -> Self {
        let parsed = filefacts::OpenOptions::new()
            .path(std::path::Path::new(&report.target.path))
            .open(binary_data);
        Self::with_parsed(
            mapper,
            report,
            binary_data,
            platforms,
            inline_yara_results,
            parsed,
        )
    }

    /// Create a new rule debugger.
    ///
    /// # Arguments
    /// * `mapper` - The capability mapper with rule definitions
    /// * `report` - The analysis report for the target file
    /// * `binary_data` - Raw file contents
    /// * `platforms` - Platform filter from CLI (use vec![Platform::All] to show all)
    /// * `inline_yara_results` - Pre-scanned inline YARA results (matches production path)
    /// * `parsed` - The filefacts parse of `binary_data`, so AST conditions
    ///   have a real tree to walk
    pub(crate) fn with_parsed(
        mapper: &'a CapabilityMapper,
        report: &'a AnalysisReport,
        binary_data: &'a [u8],
        platforms: Vec<Platform>,
        inline_yara_results: Option<&'a HashMap<String, Vec<Evidence>>>,
        parsed: filefacts::ParsedFile<'a>,
    ) -> Self {
        let file_type = detect_file_type(&report.target.file_type);
        let section_map = SectionMap::from_binary(binary_data);

        // `values()` primes the parse so `source_ast()` returns Some.
        let _ = parsed.values();
        let parsed = Some(parsed);

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
            finding_origins: container_finding_origins(report, mapper, binary_data),
            leg_for_mask: std::cell::Cell::new(TypeMask::ALL),
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
    fn build_finding_index(&self) -> rustc_hash::FxHashMap<u64, smallvec::SmallVec<[u32; 2]>> {
        crate::composite_rules::FindingScope::own_index(&self.report.findings)
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
            target_path_override: None,
            member_files: None,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platforms: &self.platforms,
            arch: vec![Arch::All].into(),
            arch_ranges: None,
            findings: crate::composite_rules::FindingScope::with_index(
                &self.report.findings,
                None,
                Some(std::sync::Arc::new(self.build_finding_index())),
            ),
            cached_ast: self
                .parsed
                .as_ref()
                .and_then(filefacts::ParsedFile::source_ast)
                .map(|a| a.tree),
            ast_kind_cache: None,
            ast_query_cache: None,
            measured_ast_queries: None,
            ast_node_text: None,
            debug_collector,
            suppressions: None,
            section_map: Some(&self.section_map),
            inline_yara_results: self.inline_yara_results,
            cached_kv_offsets: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_lossy_utf8: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_ast_source_utf8: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index_ci: std::sync::Arc::new(std::sync::OnceLock::new()),
            encoded_string_indices: std::sync::Arc::new(std::sync::OnceLock::new()),
            literal_string_indices: std::sync::Arc::new(std::sync::OnceLock::new()),
            flow_call_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            flow_targets: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_html_comment_free_source: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_comment_free_source: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_commentless_ast: std::sync::Arc::new(std::sync::OnceLock::new()),
            deadline: None,
            slow_rule_ms: 4000,
            cached_evidence: None,
            current_trait_idx: None,
            finding_origins: self.finding_origins.as_ref(),
            for_mask: TypeMask::ALL,
            raw_atom_offsets: None,
            decoded_skip: None,
            regex_candidate_strings: None,
            cached_source_utf8: std::str::from_utf8(self.binary_data).ok(),
            parent_is_exception: false,
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

        // Create context with debug collector. `for_mask` is per rule, as in
        // `evaluate_container_composites`: with origins stamped, a leg counts
        // only when it came from a member type the rule declared.
        let mut ctx = self.create_eval_context(Some(&debug));
        ctx.for_mask = composite.for_mask();

        // Run real evaluation
        let finding = composite.evaluate(&ctx);

        // Extract debug info
        let eval_debug = debug
            .into_inner()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        // Convert to RuleDebugResult, using composite requirements. The leg
        // trace runs under this composite's `for:` mask, like the evaluation.
        let requirements = build_composite_requirements(composite);
        self.leg_for_mask.set(composite.for_mask());
        let result = self.convert_composite_debug_to_result(
            eval_debug,
            composite,
            finding.is_some(),
            &requirements,
        );
        self.leg_for_mask.set(TypeMask::ALL);
        result
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
                low_value_any: false,
                emission_notes: Vec::new(),
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
            low_value_any: false,
            emission_notes: Vec::new(),
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
                low_value_any: composite_is_low_value_any(composite),
                emission_notes: Vec::new(),
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

        // Add proximity info if present. The detail line names where each
        // condition group landed and what the window must contain, so an author
        // can see at a glance whether the `all:`/`any:` legs are truly adjacent
        // (a far-apart `all:` leg no longer slips through on `any:` count alone).
        if let Some(proximity) = eval_debug.proximity {
            let proximity_desc = if proximity.detail.is_empty() {
                format!(
                    "Proximity ({}): max_span={}, satisfied={}",
                    proximity.constraint_type, proximity.max_span, proximity.satisfied
                )
            } else {
                format!(
                    "Proximity ({}): max_span={}, satisfied={}\n        {}",
                    proximity.constraint_type,
                    proximity.max_span,
                    proximity.satisfied,
                    proximity.detail
                )
            };
            condition_results.push(ConditionDebugResult::new(
                proximity_desc,
                proximity.satisfied,
            ));
        }

        // Add scope info if the rule's scope buckets its evidence. Without it
        // a rule rejected for spanning two buckets showed every leg matched.
        if let Some(scope) = eval_debug.scope {
            condition_results.push(ConditionDebugResult::new(
                format!(
                    "Scope {}: satisfied={}\n        {}",
                    scope.scope, scope.satisfied, scope.detail
                ),
                scope.satisfied,
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
            low_value_any: composite_is_low_value_any(composite),
            emission_notes: Vec::new(),
        }
    }

    /// Debug a specific rule by ID
    pub(crate) fn debug_rule(&self, rule_id: &str) -> Option<RuleDebugResult> {
        // First try to find as a trait definition
        if let Some(trait_def) = self.find_trait_definition(rule_id) {
            let mut result = self.debug_trait_via_evaluation(trait_def);
            result.emission_notes = self.explain_emission(trait_def, result.matched);
            return Some(result);
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
            target_path_override: None,
            member_files: None,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platforms: &self.platforms,
            arch: vec![Arch::All].into(),
            arch_ranges: None,
            findings: crate::composite_rules::FindingScope::with_index(
                &self.report.findings,
                None,
                None,
            ),
            cached_ast: None,
            ast_kind_cache: None,
            ast_query_cache: None,
            measured_ast_queries: None,
            ast_node_text: None,
            debug_collector: None,
            suppressions: None,
            section_map: Some(&self.section_map),
            inline_yara_results: None,
            cached_kv_offsets: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_lossy_utf8: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_ast_source_utf8: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index_ci: std::sync::Arc::new(std::sync::OnceLock::new()),
            encoded_string_indices: std::sync::Arc::new(std::sync::OnceLock::new()),
            literal_string_indices: std::sync::Arc::new(std::sync::OnceLock::new()),
            flow_call_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            flow_targets: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_html_comment_free_source: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_comment_free_source: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_commentless_ast: std::sync::Arc::new(std::sync::OnceLock::new()),
            deadline: None,
            slow_rule_ms: 4000,
            cached_evidence: None,
            current_trait_idx: None,
            finding_origins: None,
            for_mask: TypeMask::ALL,
            raw_atom_offsets: None,
            decoded_skip: None,
            regex_candidate_strings: None,
            cached_source_utf8: None,
            parent_is_exception: false,
            cancellation: None,
        };

        match condition {
            Condition::Trait { id } => self.debug_trait_reference(id),
            Condition::Symbol(query) => Self::debug_symbol_condition(query, &ctx),
            Condition::Metrics(MetricsQuery {
                field, min, max, ..
            }) => self.debug_metrics_condition(field, *min, *max),
            Condition::Yara {
                source,
                namespace,
                compiled,
            } => self.debug_yara_inline_condition(source, namespace.as_deref(), compiled.as_ref()),
            Condition::Raw(query) => self.debug_raw_condition(query, &ctx),
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
                length_min,
                length_max,
                is_check,
                not,
                ..
            }) => self.debug_kv_condition(
                path,
                exact,
                substr,
                regex,
                *case_insensitive,
                *exists,
                *length_min,
                *length_max,
                *is_check,
                not,
            ),
            Condition::Hex(HexQuery {
                pattern,
                not,
                offset,
                offset_range,
                section,
                section_offset,
                section_offset_range,
            }) => self.debug_hex_condition(
                pattern,
                not.as_ref(),
                *offset,
                *offset_range,
                section.as_deref(),
                *section_offset,
                *section_offset_range,
            ),
            Condition::Text(TextQuery {
                encoding,
                exact,
                substr,
                regex,
                word,
                case_insensitive,
                length_min,
                length_max,
                exclude_html_comments,
                exclude_comments,
                is_check,
                not,
                platforms: _,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
            }) => {
                let desc = describe_condition(condition);
                let params = crate::composite_rules::context::StringParams {
                    encoding: *encoding,
                    exact: exact.as_ref(),
                    substr: substr.as_ref(),
                    regex: regex.as_ref(),
                    word: word.as_ref(),
                    case_insensitive: *case_insensitive,
                    length_min: *length_min,
                    length_max: *length_max,
                    exclude_html_comments: *exclude_html_comments,
                    exclude_comments: *exclude_comments,
                    is_check: *is_check,
                    section: section.as_ref(),
                    offset: *offset,
                    offset_range: *offset_range,
                    section_offset: *section_offset,
                    section_offset_range: *section_offset_range,
                    arch_clamp: None,
                };
                let result = crate::composite_rules::evaluators::eval_text(
                    &params,
                    not.as_ref(),
                    &ctx,
                    None,
                );
                let mut debug =
                    ConditionDebugResult::new(desc, result.matched).with_evidence(result.evidence);
                // When a raw-text-mode file fails `text exact:` but the pattern is present as
                // substring, surface the per-line semantic explicitly. Authors hit this when
                // they expect `exact:` to find an identifier anywhere in source code.
                if !result.matched
                    && self.file_type.uses_raw_text_search_in(self.report)
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
            // Same gate as `EvaluationContext::origin_allows`: inside a
            // container, a finding counts only if some member that produced it
            // has a type the composite lists in `for:`.
            let mask = self.leg_for_mask.get();
            if mask != TypeMask::ALL
                && let Some(origins) = &self.finding_origins
                && !origins.get(id).is_some_and(|m| m.intersects(mask))
            {
                let mut result = ConditionDebugResult::new(desc, false);
                result.details.push(format!(
                    "✗ In findings ({id}), but only from member types this rule's `for:` does not list -- the origin filter drops it"
                ));
                return result;
            }
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

    /// Reconcile a raw `test-rules` match against what the scan actually
    /// emitted, and say what changed it.
    ///
    /// A rule can match its conditions here and still be absent from a scan, or
    /// present at a lower criticality. Three things do that, and all three used
    /// to be invisible — the command printed a bare `MATCHED` either way:
    ///
    /// 1. `unless:` skipped it outright.
    /// 2. `downgrade:` lowered its criticality.
    /// 3. `strip_unmatched_traits` dropped it as a low-tier finding that no
    ///    fired composite references.
    ///
    /// Cause 3 is the one nobody guesses: a trait declared `baseline`/`component`
    /// simply disappears unless some composite that fired names it, which makes
    /// the same trait look present in one scan and missing in another for
    /// reasons that have nothing to do with its own matcher.
    fn explain_emission(&self, trait_def: &TraitDefinition, matched: bool) -> Vec<String> {
        if !matched {
            return Vec::new();
        }
        let id = trait_def.id.as_str();
        let mut out = Vec::new();

        // `test-rules` evaluates in isolation, so its own report holds the trait
        // at its declared criticality even when a scan would change or drop it.
        // Re-derive each transform rather than reading it back off the report.
        let emitted = self.report.findings.iter().find(|f| f.id.as_str() == id);
        if let Some(f) = emitted
            && f.crit != trait_def.crit
        {
            out.push(format!(
                "\u{2193} emitted at {:?}, not the declared {:?}",
                f.crit, trait_def.crit
            ));
        }

        out.extend(self.explain_unless_downgrade(trait_def));

        // The low-tier strip: `strip_unmatched_traits` drops a
        // `baseline`/`component` finding unless a fired composite names it. This
        // is the cause nobody guesses, because it depends on what *else* matched
        // — the same trait survives in one scan and vanishes in another.
        let effective_crit = trait_def.downgrade.as_ref().map_or(trait_def.crit, |_| {
            crate::composite_rules::traits::downgrade_crit(trait_def.crit)
        });
        if matches!(
            effective_crit,
            crate::types::Criticality::Baseline | crate::types::Criticality::Component
        ) {
            // Only a citation the scan keeps protects the trait: the scan drops
            // low-value bare-`any:` wrappers and `exception` composites before
            // the strip, so a citation from one of those rescues nothing.
            let mut emitted = self.report.clone();
            self.mapper.filter_low_value(&mut emitted);
            let referenced = emitted
                .findings
                .iter()
                .chain(emitted.files.iter().flat_map(|file| file.findings.iter()))
                .filter(|f| f.crit != crate::types::Criticality::Exception)
                .any(|f| f.trait_refs.iter().any(|r| r.as_str() == id));
            if !referenced && trait_def.downgrade.is_none() {
                out.push(format!(
                    "\u{2717} would be stripped from scan output: {:?} and no fired composite \
                     references it (strip_unmatched_traits)",
                    effective_crit
                ));
            }
        }
        out
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

        // `downgrade:` — every present block (all/any) must pass to fire.
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

        if reasons.is_empty() {
            None
        } else {
            Some(reasons.join("; "))
        }
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
        return s.to_string();
    }
    // `max_len` is a byte budget, and rule patterns are not all ASCII -- a
    // vendor-identity regex holding CJK company names put a char boundary in
    // the middle of the cut and panicked the whole command. Walk back to the
    // nearest boundary instead.
    let mut end = max_len;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// The regex an exact/substr/regex/word query compiles to, built once per
/// search rather than once per candidate. `None` when none of `regex` and
/// `word` is set, or the pattern does not compile.
fn query_regex(
    regex: Option<&str>,
    word: Option<&str>,
    case_insensitive: bool,
) -> Option<regex::Regex> {
    let flags = if case_insensitive { "(?i)" } else { "" };
    let pattern = match (regex, word) {
        (Some(r), _) => format!("{flags}{r}"),
        (None, Some(w)) => format!(r"{flags}\b{}\b", regex::escape(w)),
        (None, None) => return None,
    };
    regex::Regex::new(&pattern).ok()
}

fn query_matches(
    s: &str,
    exact: Option<&str>,
    substr: Option<&str>,
    compiled: Option<&regex::Regex>,
    case_insensitive: bool,
) -> bool {
    if let Some(e) = exact {
        return if case_insensitive {
            s.eq_ignore_ascii_case(e)
        } else {
            s == e
        };
    }
    if let Some(c) = substr {
        return if case_insensitive {
            s.to_lowercase().contains(&c.to_lowercase())
        } else {
            s.contains(c)
        };
    }
    compiled.is_some_and(|re| re.is_match(s))
}

pub(crate) fn find_matching_strings<'a>(
    strings: &[&'a str],
    exact: Option<&str>,
    substr: Option<&str>,
    regex_pat: Option<&str>,
    word: Option<&str>,
    case_insensitive: bool,
) -> Vec<&'a str> {
    let compiled = query_regex(regex_pat, word, case_insensitive);
    strings
        .iter()
        .filter(|s| query_matches(s, exact, substr, compiled.as_ref(), case_insensitive))
        .copied()
        .collect()
}

pub(crate) fn find_matching_symbols<'a>(
    symbols: &[&'a str],
    exact: Option<&str>,
    substr: Option<&str>,
    regex: Option<&str>,
    case_insensitive: bool,
) -> Vec<&'a str> {
    // Symbols are normalized (leading underscores stripped) at load time.
    let compiled = query_regex(regex, None, case_insensitive);
    symbols
        .iter()
        .filter(|s| query_matches(s, exact, substr, compiled.as_ref(), case_insensitive))
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
        Condition::Syscall {
            name,
            number,
            arch,
            args,
        } => eval_syscall(
            name.as_deref(),
            number.as_deref(),
            arch.as_deref(),
            args,
            ctx,
        ),
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

        // A bare-OR composite (`any:` with `needs <= 1`, no `all:`) can MATCH
        // here but is filtered from real scan output as low-value — flag it so a
        // "matches in test-rules, absent in production" discrepancy is obvious.
        if result.low_value_any {
            output.push_str(&format!(
                "  {} low-value `any:`/`needs<=1` rule — filtered from scan output; \
                 add an `all:` leg or raise `needs` to keep it\n",
                "Note:".yellow().bold()
            ));
        }

        // What the scan actually did with this match: a bare MATCHED is
        // misleading when `unless:`, `downgrade:` or the low-tier strip changed
        // or removed the finding.
        for note in &result.emission_notes {
            output.push_str(&format!("  {} {}\n", "Emission:".yellow().bold(), note));
        }

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
mod tests;
