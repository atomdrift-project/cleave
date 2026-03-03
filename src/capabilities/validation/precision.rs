//! Precision calculation for trait definitions and composite rules.
//!
//! Precision is a measure of how specific/constrained a rule is - how many
//! filters/constraints it has. This module provides functions to calculate
//! precision for atomic traits and recursively for composite rules.

use crate::composite_rules::{
    condition::NotExceptionStructured, CompositeTrait, Condition, FileType as RuleFileType,
    Platform, TraitDefinition,
};
use crate::types::Criticality;
use std::collections::{HashMap, HashSet};

const BASE_TRAIT_PRECISION: f32 = 1.0;
const PARAM_UNIT: f32 = 0.3;
const CASE_INSENSITIVE_MULTIPLIER: f32 = 0.25;

fn score_string_value(value: &str) -> f32 {
    let len = value.chars().count();
    if len == 0 {
        return 0.0;
    }
    let buckets = len.div_ceil(5) as f32;
    buckets * PARAM_UNIT
}

fn score_word_value(value: &str) -> f32 {
    // Word matching implies delimiter boundaries around the token.
    let len = value.chars().count() + 2;
    let buckets = len.div_ceil(5) as f32;
    buckets * PARAM_UNIT
}

fn score_regex_value(value: &str) -> f32 {
    let normalized_len = value.chars().filter(|c| *c != '\\').count();
    if normalized_len == 0 {
        return 0.0;
    }
    let buckets = normalized_len.div_ceil(5) as f32;
    buckets * PARAM_UNIT
}

fn score_presence<T>(value: Option<&T>) -> f32 {
    if value.is_some() {
        PARAM_UNIT
    } else {
        0.0
    }
}

fn score_condition(condition: &Condition) -> f32 {
    let mut score = 0.0f32;

    match condition {
        Condition::Symbol {
            exact,
            substr,
            regex,
            platforms,
            ..
        } => {
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            if let Some(p) = platforms {
                for platform in p.iter().filter(|p| **p != Platform::All) {
                    score += score_string_value(&format!("{:?}", platform).to_lowercase());
                }
            }
        }
        Condition::String {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            external_ip,
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            ..
        }
        | Condition::Raw {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            external_ip,
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            ..
        } => {
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            score += word.as_deref().map(score_word_value).unwrap_or(0.0);
            // count_min, count_max, per_kb_min, per_kb_max now scored at trait level
            if *external_ip {
                score += PARAM_UNIT;
            }
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
        }
        Condition::Structure {
            feature,
            min_sections,
        } => {
            score += score_string_value(feature);
            score += score_presence(min_sections.as_ref());
        }
        Condition::ExportsCount { min, max } => {
            score += score_presence(min.as_ref());
            score += score_presence(max.as_ref());
        }
        Condition::Trait { id } => {
            score += score_string_value(id);
        }
        Condition::Ast {
            kind,
            node,
            exact,
            substr,
            regex,
            query,
            language,
            case_insensitive,
        } => {
            score += kind.as_deref().map(score_string_value).unwrap_or(0.0);
            score += node.as_deref().map(score_string_value).unwrap_or(0.0);
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            score += query.as_deref().map(score_regex_value).unwrap_or(0.0);
            score += language.as_deref().map(score_string_value).unwrap_or(0.0);
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
        }
        Condition::Yara { source, .. } => {
            score += score_regex_value(source);
        }
        Condition::Syscall { name, number, arch } => {
            if let Some(names) = name {
                for value in names {
                    score += score_string_value(value);
                }
            }
            if let Some(values) = number {
                score += PARAM_UNIT * (values.len() as f32);
            }
            if let Some(values) = arch {
                for value in values {
                    score += score_string_value(value);
                }
            }
            // count_min, count_max, per_kb_min, per_kb_max now scored at trait level
        }
        Condition::SectionRatio {
            section,
            compare_to,
            min,
            max,
        } => {
            score += score_regex_value(section);
            score += score_regex_value(compare_to);
            score += score_presence(min.as_ref());
            score += score_presence(max.as_ref());
        }
        Condition::ImportCombination {
            required,
            suspicious,
            min_suspicious,
            max_total,
        } => {
            if let Some(values) = required {
                for value in values {
                    score += score_string_value(value);
                }
            }
            if let Some(values) = suspicious {
                for value in values {
                    score += score_string_value(value);
                }
            }
            score += score_presence(min_suspicious.as_ref());
            score += score_presence(max_total.as_ref());
        }
        Condition::StringCount {
            min,
            max,
            min_length,
            ..
        } => {
            score += score_presence(min.as_ref());
            score += score_presence(max.as_ref());
            score += score_presence(min_length.as_ref());
        }
        Condition::Metrics {
            field,
            min,
            max,
            min_size,
            max_size,
        } => {
            score += score_string_value(field);
            score += score_presence(min.as_ref());
            score += score_presence(max.as_ref());
            score += score_presence(min_size.as_ref());
            score += score_presence(max_size.as_ref());
        }
        Condition::Hex {
            pattern,
            not: _,
            offset,
            offset_range,
            section,
            section_offset,
            section_offset_range,
        } => {
            score += score_string_value(pattern);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            // count_min, count_max, per_kb_min, per_kb_max now scored at trait level
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
        }
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
        } => {
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            score += word.as_deref().map(score_word_value).unwrap_or(0.0);
            if *case_insensitive {
                score += PARAM_UNIT;
            }
            if length_min.is_some() {
                score += PARAM_UNIT;
            }
            if readable.is_some() {
                score += PARAM_UNIT;
            }
            if writable.is_some() {
                score += PARAM_UNIT;
            }
            if executable.is_some() {
                score += PARAM_UNIT;
            }
            if length_max.is_some() {
                score += PARAM_UNIT;
            }
            if entropy_min.is_some() {
                score += PARAM_UNIT;
            }
            if entropy_max.is_some() {
                score += PARAM_UNIT;
            }
        }
        Condition::Encoded {
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
        } => {
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            score += word.as_deref().map(score_word_value).unwrap_or(0.0);
            // count_min, count_max, per_kb_min, per_kb_max now scored at trait level
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
        }
        Condition::Basename {
            exact,
            substr,
            regex,
            case_insensitive,
        }
        | Condition::Kv {
            exact,
            substr,
            regex,
            case_insensitive,
            ..
        } => {
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
        }
    }

    score
}

fn score_not_exceptions(exceptions: &[crate::composite_rules::condition::NotException]) -> f32 {
    let mut score = 0.0f32;
    for exception in exceptions {
        match exception {
            crate::composite_rules::condition::NotException::Shorthand(value) => {
                score += score_string_value(value);
            }
            crate::composite_rules::condition::NotException::Structured(
                NotExceptionStructured {
                    exact,
                    substr,
                    regex,
                },
            ) => {
                score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
                score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
                score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            }
        }
    }
    score
}

fn sum_weakest(mut values: Vec<f32>, count: usize) -> f32 {
    if values.is_empty() || count == 0 {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let len = values.len();
    values.into_iter().take(count.min(len)).sum()
}

/// Calculate trait-level precision (static rule precision).
///
/// This is rule-definition precision, not runtime match precision.
/// It counts structural constraints that make a trait more specific.
#[must_use]
pub(crate) fn calculate_trait_precision(trait_def: &TraitDefinition) -> f32 {
    let mut precision = BASE_TRAIT_PRECISION;

    precision += score_presence(trait_def.size_min.as_ref());
    precision += score_presence(trait_def.size_max.as_ref());

    for platform in trait_def.platforms.iter().filter(|p| **p != Platform::All) {
        precision += score_string_value(&format!("{:?}", platform).to_lowercase());
    }

    for file_type in trait_def
        .r#for
        .iter()
        .filter(|f| !matches!(f, RuleFileType::All))
    {
        precision += score_string_value(&format!("{:?}", file_type).to_lowercase());
    }

    precision += score_condition(&trait_def.r#if);

    // Count/density constraints (scored at trait level, not condition level)
    precision += score_presence(trait_def.count_min.as_ref());
    precision += score_presence(trait_def.count_max.as_ref());
    precision += score_presence(trait_def.per_kb_min.as_ref());
    precision += score_presence(trait_def.per_kb_max.as_ref());

    if let Some(exceptions) = trait_def.not.as_ref() {
        precision += PARAM_UNIT;
        precision += score_not_exceptions(exceptions);
    }

    if let Some(unless_conds) = trait_def.unless.as_ref() {
        precision += PARAM_UNIT;
        let unless_scores: Vec<f32> = unless_conds.iter().map(score_condition).collect();
        precision += sum_weakest(unless_scores, 1);
    }

    if trait_def.downgrade.is_some() {
        precision += PARAM_UNIT;
    }

    precision
}

/// Calculate the precision of a composite rule or trait
///
/// Precision is a measure of how specific/constrained the rule is - how many filters/constraints it has.
/// This RECURSIVELY counts ALL filters across the entire rule tree:
/// - Base trait: pattern + size_min + size_max + platform + file_type + not + unless
/// - Composite: file_type + recursively expanded all/any/none/unless clauses
///
/// IMPORTANT: This is the ONLY place in the codebase for measuring rule precision.
/// Do not duplicate this logic elsewhere.
pub(crate) fn calculate_composite_precision(
    rule_id: &str,
    composite_lookup: &HashMap<&str, &CompositeTrait>,
    trait_lookup: &HashMap<&str, &TraitDefinition>,
    cache: &mut HashMap<String, f32>,
    visiting: &mut HashSet<String>,
) -> f32 {
    if let Some(&precision) = cache.get(rule_id) {
        return precision;
    }

    // Debug output controlled by CLEAVE_DEBUG environment variable
    let debug = std::env::var("CLEAVE_DEBUG").is_ok();

    // Detect cycles
    if !visiting.insert(rule_id.to_string()) {
        return BASE_TRAIT_PRECISION;
    }

    // Try to find as composite rule first
    // Support both new format (dir::name) and legacy format (dir/name)
    let rule = composite_lookup.get(rule_id).copied().or_else(|| {
        if rule_id.contains("::") {
            let legacy_id = rule_id.replace("::", "/");
            composite_lookup.get(legacy_id.as_str()).copied()
        } else if rule_id.contains('/') {
            if let Some(idx) = rule_id.rfind('/') {
                let new_id = format!("{}::{}", &rule_id[..idx], &rule_id[idx + 1..]);
                composite_lookup.get(new_id.as_str()).copied()
            } else {
                None
            }
        } else {
            None
        }
    });
    if let Some(rule) = rule {
        let mut precision = 0.0f32;

        for file_type in rule
            .r#for
            .iter()
            .filter(|f| !matches!(f, RuleFileType::All))
        {
            let score = score_string_value(&format!("{:?}", file_type).to_lowercase());
            precision += score;
            if debug {
                eprintln!("  [DEBUG] {} file_type score: {:.2}", rule_id, score);
            }
        }

        // `all` clause: recursively sum all elements
        if let Some(ref conditions) = rule.all {
            for cond in conditions {
                let _before = precision;
                match cond {
                    Condition::Trait { id } => {
                        // Recursively calculate trait/composite precision
                        let score = calculate_composite_precision(
                            id,
                            composite_lookup,
                            trait_lookup,
                            cache,
                            visiting,
                        );
                        precision += score;
                        if debug {
                            eprintln!(
                                "  [DEBUG] {} all trait '{}' score: {:.2}",
                                rule_id, id, score
                            );
                        }
                    }
                    _ => {
                        let score = score_condition(cond);
                        precision += score;
                        if debug {
                            eprintln!("  [DEBUG] {} all condition score: {:.2}", rule_id, score);
                        }
                    }
                }
            }
        }

        // `any` clause: sum the N weakest required branches
        if let Some(ref conditions) = rule.any {
            let branch_scores: Vec<f32> = conditions
                .iter()
                .enumerate()
                .map(|(i, cond)| {
                    let score = match cond {
                        Condition::Trait { id } => {
                            let s = calculate_composite_precision(
                                id,
                                composite_lookup,
                                trait_lookup,
                                cache,
                                visiting,
                            );
                            if debug {
                                eprintln!(
                                    "  [DEBUG] {} any[{}] trait '{}' score: {:.2}",
                                    rule_id, i, id, s
                                );
                            }
                            s
                        }
                        _ => {
                            let s = score_condition(cond);
                            if debug {
                                eprintln!(
                                    "  [DEBUG] {} any[{}] condition score: {:.2}",
                                    rule_id, i, s
                                );
                            }
                            s
                        }
                    };
                    score
                })
                .collect();

            if !branch_scores.is_empty() {
                let required = rule.needs.unwrap_or(1).max(1);
                if debug {
                    eprintln!(
                        "  [DEBUG] {} any clause: needs={}, scores={:?}",
                        rule_id, required, branch_scores
                    );
                }
                let weakest_sum = sum_weakest(branch_scores, required);
                if debug {
                    eprintln!(
                        "  [DEBUG] {} any clause: sum_weakest={:.2}",
                        rule_id, weakest_sum
                    );
                }
                precision += weakest_sum;
            }
        }

        if let Some(ref none_conds) = rule.none {
            precision += PARAM_UNIT;
            let scores: Vec<f32> = none_conds
                .iter()
                .map(|cond| match cond {
                    Condition::Trait { id } => calculate_composite_precision(
                        id,
                        composite_lookup,
                        trait_lookup,
                        cache,
                        visiting,
                    ),
                    _ => score_condition(cond),
                })
                .collect();
            precision += scores.into_iter().sum::<f32>();
        }
        if let Some(ref unless_conds) = rule.unless {
            precision += PARAM_UNIT;
            let scores: Vec<f32> = unless_conds
                .iter()
                .map(|cond| match cond {
                    Condition::Trait { id } => calculate_composite_precision(
                        id,
                        composite_lookup,
                        trait_lookup,
                        cache,
                        visiting,
                    ),
                    _ => score_condition(cond),
                })
                .collect();
            precision += sum_weakest(scores, 1);
        }

        visiting.remove(rule_id);
        cache.insert(rule_id.to_string(), precision);
        if debug {
            eprintln!("  [DEBUG] {} TOTAL PRECISION: {:.2}", rule_id, precision);
        }
        return precision;
    }

    // Not a composite - try to find as a trait definition
    // Support both new format (dir::name) and legacy format (dir/name)
    if debug {
        eprintln!("  [DEBUG] Looking up trait: '{}'", rule_id);
    }
    let trait_def = trait_lookup.get(rule_id).copied().or_else(|| {
        // Try converting legacy format to new format or vice versa
        if rule_id.contains("::") {
            // Reference uses new format, trait might use legacy
            let legacy_id = rule_id.replace("::", "/");
            if debug {
                eprintln!("  [DEBUG]   Trying legacy conversion: '{}'", legacy_id);
            }
            trait_lookup.get(legacy_id.as_str()).copied()
        } else if rule_id.contains('/') {
            // Reference uses legacy format, trait might use new format
            // Convert last '/' to '::'
            if let Some(idx) = rule_id.rfind('/') {
                let new_id = format!("{}::{}", &rule_id[..idx], &rule_id[idx + 1..]);
                if debug {
                    eprintln!("  [DEBUG]   Trying new format conversion: '{}'", new_id);
                }
                trait_lookup.get(new_id.as_str()).copied()
            } else {
                None
            }
        } else {
            None
        }
    });

    if let Some(trait_def) = trait_def {
        let precision = calculate_trait_precision(trait_def);
        if debug {
            eprintln!(
                "  [DEBUG]   FOUND trait '{}' with stored ID '{}', precision: {:.2}",
                rule_id, trait_def.id, precision
            );
        }
        visiting.remove(rule_id);
        cache.insert(rule_id.to_string(), precision);
        return precision;
    }

    // Not found - treat as external/unknown trait
    if debug {
        eprintln!(
            "  [DEBUG]   NOT FOUND - returning BASE_TRAIT_PRECISION: {:.2}",
            BASE_TRAIT_PRECISION
        );
        eprintln!("  [DEBUG]   Available trait IDs (first 20):");
        for (i, id) in trait_lookup.keys().take(20).enumerate() {
            eprintln!("  [DEBUG]     [{}] '{}'", i, id);
        }
    }
    visiting.remove(rule_id);
    cache.insert(rule_id.to_string(), BASE_TRAIT_PRECISION);
    BASE_TRAIT_PRECISION
}

/// Pre-calculate precision for ALL composite rules and store in their precision field.
/// This should be called once after all traits and composites are loaded,
/// before any validation. After this runs, precision will be cached and never recalculated.
pub(crate) fn precalculate_all_composite_precisions(
    composite_rules: &mut [CompositeTrait],
    trait_definitions: &[TraitDefinition],
) {
    let mut cache: HashMap<String, f32> = HashMap::new();

    // Pre-seed cache with all atomic trait precisions
    for trait_def in trait_definitions {
        if let Some(precision) = trait_def.precision {
            cache.insert(trait_def.id.clone(), precision);
        }
    }

    // Build lookup tables (immutable borrow)
    let composite_lookup: HashMap<&str, &CompositeTrait> =
        composite_rules.iter().map(|r| (r.id.as_str(), r)).collect();
    let trait_lookup: HashMap<&str, &TraitDefinition> = trait_definitions
        .iter()
        .map(|t| (t.id.as_str(), t))
        .collect();

    // First pass: Calculate precisions for rules that don't have them (immutable borrow)
    let calculated_precisions: Vec<(String, f32)> = composite_rules
        .iter()
        .filter(|rule| rule.precision.is_none())
        .map(|rule| {
            let mut visiting = std::collections::HashSet::new();
            let precision = calculate_composite_precision(
                &rule.id,
                &composite_lookup,
                &trait_lookup,
                &mut cache,
                &mut visiting,
            );
            (rule.id.clone(), precision)
        })
        .collect();

    // Second pass: Store the calculated precisions (mutable borrow)
    for (rule_id, precision) in calculated_precisions {
        if let Some(rule) = composite_rules.iter_mut().find(|r| r.id == rule_id) {
            rule.precision = Some(precision);
        }
    }
}

/// Validate and downgrade composite rules that don't meet precision requirements.
///
/// - HOSTILE must have precision >= min_hostile_precision, else downgraded to SUSPICIOUS.
/// - SUSPICIOUS must have precision >= min_suspicious_precision, else downgraded to NOTABLE.
///
/// Warnings are logged but NOT fatal - rules are silently downgraded to maintain safety.
///
/// IMPORTANT: Call precalculate_all_composite_precisions() first!
/// This function expects all precisions to already be calculated and stored.
pub(crate) fn validate_hostile_composite_precision(
    composite_rules: &mut [CompositeTrait],
    _trait_definitions: &[TraitDefinition],
    _warnings: &mut Vec<String>,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
) {
    // Check HOSTILE/SUSPICIOUS composite rules and downgrade if precision is too low
    for rule in composite_rules.iter_mut() {
        if !matches!(rule.crit, Criticality::Hostile | Criticality::Suspicious) {
            continue;
        }

        // Precision should already be calculated - if not, that's a bug
        let precision = rule.precision.unwrap_or_else(|| {
            tracing::warn!("Composite rule '{}' has no precision calculated!", rule.id);
            0.0
        });

        match rule.crit {
            Criticality::Hostile if precision < min_hostile_precision => {
                // Log non-fatal warning and downgrade
                tracing::debug!(
                    "Downgrading '{}' from HOSTILE to SUSPICIOUS (precision {:.1} < {:.1})",
                    rule.id,
                    precision,
                    min_hostile_precision
                );
                rule.crit = Criticality::Suspicious;
            }
            Criticality::Suspicious if precision < min_suspicious_precision => {
                // Log non-fatal warning and downgrade
                tracing::debug!(
                    "Downgrading '{}' from SUSPICIOUS to NOTABLE (precision {:.1} < {:.1})",
                    rule.id,
                    precision,
                    min_suspicious_precision
                );
                rule.crit = Criticality::Notable;
            }
            _ => {}
        }
    }
}
