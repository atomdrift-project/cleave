//! Precision calculation for trait definitions and composite rules.
//!
//! Precision is a measure of how specific/constrained a rule is - how many
//! filters/constraints it has. This module provides functions to calculate
//! precision for atomic traits and recursively for composite rules.

use crate::composite_rules::{
    condition::{EncodingSpec, NotExceptionStructured},
    CompositeTrait, Condition, FileType as RuleFileType, Platform, TraitDefinition,
};
use crate::types::Criticality;
use std::collections::{HashMap, HashSet};

const BASE_TRAIT_PRECISION: f32 = 1.0;
const PARAM_UNIT: f32 = 0.2;
const CASE_INSENSITIVE_MULTIPLIER: f32 = 0.25;
const EXTRA_FILE_TYPE_PENALTY: f32 = 0.1;
const EXTRA_PLATFORM_PENALTY: f32 = 0.1;
const RAW_MATCH_MULTIPLIER: f32 = 0.6;
const STRING_VALUE_MATCH_MULTIPLIER: f32 = 1.0;
const ENCODED_MATCH_MULTIPLIER: f32 = 1.0;
const HEX_MATCH_MULTIPLIER: f32 = 1.0;
const KV_MATCH_MULTIPLIER: f32 = 1.05;
const SYMBOL_MATCH_MULTIPLIER: f32 = 1.1;
const AST_MATCH_MULTIPLIER: f32 = 1.2;
const SECTION_FILTER_BONUS: f32 = 0.25;
const SECTION_PERMISSION_BONUS: f32 = 0.35;
const CHILD_DIMINISHING_MULTIPLIER: f32 = 0.6;
const ANY_BRANCH_PENALTY: f32 = 0.15;
const INHERITED_COMPOSITE_SOFT_MAX: f32 = 4.0;
const INHERITED_COMPOSITE_COMPRESS_MULTIPLIER: f32 = 0.2;
const ATOMIC_CALIBRATED_MAX: f32 = 4.0;
const COMPOSITE_CALIBRATED_MAX: f32 = 10.0;
const COMPOSITE_INFLATION_WARNING_THRESHOLD: f32 = 16.0;
const IS_CHECK_BONUS: f32 = 0.25;
const COMPOSITE_SCOPE_PENALTY_MULTIPLIER: f32 = 0.35;

fn length_bonus(len: usize, max_bonus: f32) -> f32 {
    match len {
        0 => 0.0,
        1..=4 => max_bonus * 0.2,
        5..=8 => max_bonus * 0.4,
        9..=16 => max_bonus * 0.6,
        17..=32 => max_bonus * 0.8,
        _ => max_bonus,
    }
}

fn score_string_value(value: &str) -> f32 {
    let len = value.chars().count();
    if len == 0 {
        return 0.0;
    }
    0.2 + length_bonus(len, 0.6)
}

fn score_word_value(value: &str) -> f32 {
    0.35 + length_bonus(value.chars().count() + 2, 0.45)
}

fn score_regex_value(value: &str) -> f32 {
    let normalized_len = value.chars().filter(|c| *c != '\\').count();
    if normalized_len == 0 {
        return 0.0;
    }
    let anchor_bonus =
        value.starts_with('^') as u8 as f32 * 0.1 + value.ends_with('$') as u8 as f32 * 0.1;
    let boundary_bonus = (value.matches("\\b").count().min(2) as f32) * 0.08;
    let quantifier_bonus = (value.matches('{').count().min(2) as f32) * 0.08
        + (value.matches('+').count().min(2) as f32) * 0.04;
    let wildcard_penalty = if value.contains(".*") || value.contains(".{") {
        0.12
    } else {
        0.0
    };
    let alternation_penalty = (value.matches('|').count().min(3) as f32) * 0.05;

    (0.45 + length_bonus(normalized_len, 0.35) + anchor_bonus + boundary_bonus + quantifier_bonus
        - wildcard_penalty
        - alternation_penalty)
        .clamp(0.25, 1.0)
}

fn regex_structural_bonus(value: &str) -> f32 {
    let has_http_scheme =
        value.contains("http://") || value.contains("https://") || value.contains("https?://");
    let has_ipv4_octets =
        value.matches("[0-9]{1,3}").count() >= 4 && value.matches("\\.").count() >= 3;

    if has_http_scheme && has_ipv4_octets {
        0.3
    } else {
        0.0
    }
}

fn score_presence<T>(value: Option<&T>) -> f32 {
    if value.is_some() {
        PARAM_UNIT
    } else {
        0.0
    }
}

fn scope_bonus(concrete_count: usize, single_bonus: f32, multi_bonus: f32) -> f32 {
    match concrete_count {
        0 => 0.0,
        1 => single_bonus,
        _ => multi_bonus,
    }
}

fn platform_scope_bonus(platforms: &[Platform]) -> f32 {
    let concrete_count = platforms
        .iter()
        .filter(|p| !matches!(p, Platform::All))
        .count();
    scope_bonus(concrete_count, 0.25, 0.15)
}

fn file_type_scope_bonus(file_types: &[RuleFileType]) -> f32 {
    let concrete: Vec<_> = file_types
        .iter()
        .filter(|f| !matches!(f, RuleFileType::All))
        .collect();
    let mut bonus = scope_bonus(concrete.len(), 0.35, 0.2);
    if concrete.len() == 1 && matches!(concrete[0], RuleFileType::Pickle) {
        bonus += 0.5;
    }
    bonus
}

#[must_use]
pub(crate) fn file_type_precision_penalty(file_types: &[RuleFileType]) -> f32 {
    let concrete_count = file_types
        .iter()
        .filter(|f| !matches!(f, RuleFileType::All))
        .count();
    (concrete_count.saturating_sub(1) as f32 * EXTRA_FILE_TYPE_PENALTY).min(0.8)
}

#[must_use]
pub(crate) fn platform_precision_penalty(platforms: &[Platform]) -> f32 {
    let concrete_count = platforms
        .iter()
        .filter(|p| !matches!(p, Platform::All))
        .count();
    (concrete_count.saturating_sub(1) as f32 * EXTRA_PLATFORM_PENALTY).min(0.4)
}

#[must_use]
pub(crate) fn atomic_calibrated_max() -> f32 {
    ATOMIC_CALIBRATED_MAX
}

#[must_use]
pub(crate) fn composite_calibrated_max() -> f32 {
    COMPOSITE_CALIBRATED_MAX
}

#[must_use]
pub(crate) fn composite_inflation_warning_threshold() -> f32 {
    COMPOSITE_INFLATION_WARNING_THRESHOLD
}

fn canonical_rule_id(id: &str) -> String {
    id.to_string()
}

pub(crate) struct ReferenceIndex<'a> {
    exact: HashMap<String, Vec<&'a str>>,
    prefix: HashMap<String, Vec<&'a str>>,
}

pub(crate) fn build_reference_index<'a>(
    composite_lookup: &HashMap<&'a str, &'a CompositeTrait>,
    trait_lookup: &HashMap<&'a str, &'a TraitDefinition>,
) -> ReferenceIndex<'a> {
    let mut exact = HashMap::<String, Vec<&'a str>>::new();
    let mut prefix = HashMap::<String, Vec<&'a str>>::new();

    for key in composite_lookup.keys().chain(trait_lookup.keys()) {
        let canonical = canonical_rule_id(key);
        exact.entry(canonical.clone()).or_default().push(*key);

        let mut split_positions: Vec<usize> =
            canonical.match_indices('/').map(|(idx, _)| idx).collect();
        split_positions.sort_unstable();
        split_positions.dedup();
        for idx in split_positions {
            if idx == 0 {
                continue;
            }
            prefix
                .entry(canonical[..idx].to_string())
                .or_default()
                .push(*key);
        }
    }

    for matches in exact.values_mut().chain(prefix.values_mut()) {
        matches.sort_unstable();
        matches.dedup();
    }

    ReferenceIndex { exact, prefix }
}

fn exact_reference_candidates<'a>(
    id: &str,
    reference_index: &'a ReferenceIndex<'a>,
) -> Vec<&'a str> {
    reference_index
        .exact
        .get(&canonical_rule_id(id))
        .cloned()
        .unwrap_or_default()
}

fn prefix_reference_candidates<'a>(
    id: &str,
    reference_index: &'a ReferenceIndex<'a>,
) -> Vec<&'a str> {
    reference_index
        .prefix
        .get(&canonical_rule_id(id))
        .cloned()
        .unwrap_or_default()
}

fn resolve_rule_id<'a, T>(rule_id: &str, lookup: &'a HashMap<&'a str, T>) -> Option<&'a T> {
    lookup.get(rule_id)
}

fn hex_specificity_bonus(pattern: &str) -> f32 {
    let wildcard_pairs = pattern.matches("??").count() as f32;
    let nibble_wildcards = pattern.matches('?').count() as f32 - (wildcard_pairs * 2.0);
    let fixed_skips = pattern.matches('[').count() as f32;
    let alternations = pattern.matches('|').count() as f32;
    let exact_hex_pairs = pattern
        .split_whitespace()
        .filter(|tok| tok.len() == 2 && tok.chars().all(|c| c.is_ascii_hexdigit()))
        .count() as f32;
    (exact_hex_pairs * 0.08) + (fixed_skips * 0.15)
        - (wildcard_pairs * 0.08)
        - (nibble_wildcards * 0.03)
        - (alternations * 0.05)
}

fn encoding_specificity_bonus(encoding: &Option<EncodingSpec>) -> f32 {
    match encoding {
        Some(EncodingSpec::Single(_)) => 0.35,
        Some(EncodingSpec::Multiple(v)) => 0.2 / (v.len().max(1) as f32),
        None => 0.0,
    }
}

fn diminishing_sum(mut values: Vec<f32>) -> f32 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
    let mut total = 0.0;
    let mut factor = 1.0;
    for value in values {
        total += value * factor;
        factor *= CHILD_DIMINISHING_MULTIPLIER;
    }
    total
}

fn average_weakest(mut values: Vec<f32>, count: usize) -> f32 {
    if values.is_empty() || count == 0 {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let take = count.min(values.len());
    values.into_iter().take(take).sum::<f32>() / (take as f32)
}

fn any_breadth_penalty(total_branches: usize, required: usize) -> f32 {
    let extras = total_branches.saturating_sub(required);
    if extras == 0 {
        return 0.0;
    }
    let base = extras as f32 * ANY_BRANCH_PENALTY;
    let additional = extras.saturating_sub(3) as f32 * 0.1;
    base + additional
}

fn compress_inherited_precision(score: f32) -> f32 {
    if score <= INHERITED_COMPOSITE_SOFT_MAX {
        score
    } else {
        INHERITED_COMPOSITE_SOFT_MAX
            + (score - INHERITED_COMPOSITE_SOFT_MAX) * INHERITED_COMPOSITE_COMPRESS_MULTIPLIER
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
            score *= SYMBOL_MATCH_MULTIPLIER;
        }
        Condition::StringValue {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            is_check,
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
            if is_check.is_some() {
                score += IS_CHECK_BONUS;
            }
            score += regex.as_deref().map(regex_structural_bonus).unwrap_or(0.0);
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
            if section.is_some() {
                score += SECTION_FILTER_BONUS;
            }
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
            score *= STRING_VALUE_MATCH_MULTIPLIER;
        }
        Condition::Text {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            is_check,
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
            if is_check.is_some() {
                score += IS_CHECK_BONUS;
            }
            score += regex.as_deref().map(regex_structural_bonus).unwrap_or(0.0);
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
            if section.is_some() {
                score += SECTION_FILTER_BONUS;
            }
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
            score *= STRING_VALUE_MATCH_MULTIPLIER;
        }
        Condition::StringLiteral {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            is_check,
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
            if is_check.is_some() {
                score += IS_CHECK_BONUS;
            }
            score += regex.as_deref().map(regex_structural_bonus).unwrap_or(0.0);
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
            if section.is_some() {
                score += SECTION_FILTER_BONUS;
            }
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
            score *= AST_MATCH_MULTIPLIER;
        }
        Condition::Raw {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            is_check,
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
            if is_check.is_some() {
                score += IS_CHECK_BONUS;
            }
            score += regex.as_deref().map(regex_structural_bonus).unwrap_or(0.0);
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
            if section.is_some() {
                score += SECTION_FILTER_BONUS;
            }
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
            score *= RAW_MATCH_MULTIPLIER;
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
            score *= AST_MATCH_MULTIPLIER;
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
        Condition::StringValueCount {
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
            score += hex_specificity_bonus(pattern);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            // count_min, count_max, per_kb_min, per_kb_max now scored at trait level
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
            if section.is_some() {
                score += SECTION_FILTER_BONUS;
            }
            score *= HEX_MATCH_MULTIPLIER;
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
                score += SECTION_PERMISSION_BONUS;
            }
            if writable.is_some() {
                score += SECTION_PERMISSION_BONUS;
            }
            if executable.is_some() {
                score += SECTION_PERMISSION_BONUS;
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
            encoding,
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            is_check,
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
            score += encoding_specificity_bonus(encoding);
            if is_check.is_some() {
                score += IS_CHECK_BONUS;
            }
            score += regex.as_deref().map(regex_structural_bonus).unwrap_or(0.0);
            // count_min, count_max, per_kb_min, per_kb_max now scored at trait level
            score += section.as_deref().map(score_string_value).unwrap_or(0.0);
            score += score_presence(offset.as_ref());
            score += score_presence(offset_range.as_ref());
            score += score_presence(section_offset.as_ref());
            score += score_presence(section_offset_range.as_ref());
            if section.is_some() {
                score += SECTION_FILTER_BONUS;
            }
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
            score *= ENCODED_MATCH_MULTIPLIER;
        }
        Condition::Basename {
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
        Condition::Kv {
            path,
            exact,
            substr,
            regex,
            case_insensitive,
            exists,
            size_min,
            size_max,
            ..
        } => {
            score += score_string_value(path);
            score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
            score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
            score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
            score += score_presence(exists.as_ref());
            score += score_presence(size_min.as_ref());
            score += score_presence(size_max.as_ref());
            if *case_insensitive {
                score *= CASE_INSENSITIVE_MULTIPLIER;
            }
            score *= KV_MATCH_MULTIPLIER;
        }
    }

    score
}

fn score_not_exceptions(exceptions: &[crate::composite_rules::condition::NotException]) -> f32 {
    let mut scores = Vec::new();
    for exception in exceptions {
        match exception {
            crate::composite_rules::condition::NotException::Shorthand(value) => {
                scores.push(score_string_value(value));
            }
            crate::composite_rules::condition::NotException::Structured(
                NotExceptionStructured {
                    exact,
                    substr,
                    regex,
                    ..
                },
            ) => {
                let mut score = 0.0;
                score += exact.as_deref().map(score_string_value).unwrap_or(0.0);
                score += substr.as_deref().map(score_string_value).unwrap_or(0.0);
                score += regex.as_deref().map(score_regex_value).unwrap_or(0.0);
                if score > 0.0 {
                    scores.push(score.min(0.6));
                }
            }
        }
    }
    let total = diminishing_sum(scores);
    total.min(0.6)
}

fn sum_weakest(mut values: Vec<f32>, count: usize) -> f32 {
    if values.is_empty() || count == 0 {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let len = values.len();
    values.into_iter().take(count.min(len)).sum()
}

fn referenced_precision(
    id: &str,
    composite_lookup: &HashMap<&str, &CompositeTrait>,
    trait_lookup: &HashMap<&str, &TraitDefinition>,
    reference_index: &ReferenceIndex<'_>,
    cache: &mut HashMap<String, f32>,
    visiting: &mut HashSet<String>,
) -> f32 {
    let exact_matches = exact_reference_candidates(id, reference_index);
    if !exact_matches.is_empty() {
        let scores: Vec<f32> = exact_matches
            .into_iter()
            .map(|candidate| {
                calculate_composite_precision_indexed(
                    candidate,
                    composite_lookup,
                    trait_lookup,
                    reference_index,
                    cache,
                    visiting,
                )
            })
            .collect();
        return reference_set_precision(scores, 1);
    }

    let prefix_matches = prefix_reference_candidates(id, reference_index);
    if !prefix_matches.is_empty() {
        let scores: Vec<f32> = prefix_matches
            .into_iter()
            .map(|candidate| {
                calculate_composite_precision_indexed(
                    candidate,
                    composite_lookup,
                    trait_lookup,
                    reference_index,
                    cache,
                    visiting,
                )
            })
            .collect();
        return reference_set_precision(scores, 1);
    }

    BASE_TRAIT_PRECISION
}

fn reference_set_precision(mut scores: Vec<f32>, required: usize) -> f32 {
    if scores.is_empty() {
        return BASE_TRAIT_PRECISION;
    }

    for score in &mut scores {
        *score = compress_inherited_precision(*score);
    }

    let required = required.max(1).min(scores.len());
    let mut precision = average_weakest(scores.clone(), required);
    precision -= any_breadth_penalty(scores.len(), required);
    precision.max(BASE_TRAIT_PRECISION)
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
    precision += platform_scope_bonus(&trait_def.platforms);
    precision -= platform_precision_penalty(&trait_def.platforms);
    precision += file_type_scope_bonus(&trait_def.r#for);
    precision -= file_type_precision_penalty(&trait_def.r#for);

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

    precision.max(BASE_TRAIT_PRECISION)
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
fn calculate_composite_precision_indexed(
    rule_id: &str,
    composite_lookup: &HashMap<&str, &CompositeTrait>,
    trait_lookup: &HashMap<&str, &TraitDefinition>,
    reference_index: &ReferenceIndex<'_>,
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

    // Try to find as composite rule first.
    let rule = resolve_rule_id(rule_id, composite_lookup);
    if let Some(rule) = rule {
        let mut precision = 0.0f32;

        precision += platform_scope_bonus(&rule.platforms);
        precision -=
            platform_precision_penalty(&rule.platforms) * COMPOSITE_SCOPE_PENALTY_MULTIPLIER;

        let file_type_score = file_type_scope_bonus(&rule.r#for);
        precision += file_type_score;
        if debug && file_type_score > 0.0 {
            eprintln!(
                "  [DEBUG] {} file_type scope bonus: {:.2}",
                rule_id, file_type_score
            );
        }
        precision -= file_type_precision_penalty(&rule.r#for) * COMPOSITE_SCOPE_PENALTY_MULTIPLIER;
        if debug {
            eprintln!(
                "  [DEBUG] {} file_type breadth penalty: -{:.2}",
                rule_id,
                file_type_precision_penalty(&rule.r#for) * COMPOSITE_SCOPE_PENALTY_MULTIPLIER
            );
        }

        // `all` clause: recursively sum all elements
        if let Some(ref conditions) = rule.all {
            let mut all_scores = Vec::new();
            for cond in conditions {
                let score = match cond {
                    Condition::Trait { id } => {
                        let inherited = referenced_precision(
                            id,
                            composite_lookup,
                            trait_lookup,
                            reference_index,
                            cache,
                            visiting,
                        );
                        if debug {
                            eprintln!(
                                "  [DEBUG] {} all trait '{}' inherited score: {:.2}",
                                rule_id, id, inherited
                            );
                        }
                        inherited
                    }
                    _ => {
                        let score = score_condition(cond);
                        if debug {
                            eprintln!("  [DEBUG] {} all condition score: {:.2}", rule_id, score);
                        }
                        score
                    }
                };
                all_scores.push(score);
            }
            precision += diminishing_sum(all_scores);
        }

        // `any` clause: score from the weakest required branches with a breadth penalty
        if let Some(ref conditions) = rule.any {
            let branch_scores: Vec<f32> = conditions
                .iter()
                .enumerate()
                .map(|(i, cond)| {
                    let score = match cond {
                        Condition::Trait { id } => {
                            let s = referenced_precision(
                                id,
                                composite_lookup,
                                trait_lookup,
                                reference_index,
                                cache,
                                visiting,
                            );
                            if debug {
                                eprintln!(
                                    "  [DEBUG] {} any[{}] trait '{}' inherited score: {:.2}",
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
                let weakest_average = average_weakest(branch_scores, required);
                if debug {
                    eprintln!(
                        "  [DEBUG] {} any clause: weakest_average={:.2}",
                        rule_id, weakest_average
                    );
                }
                precision += weakest_average;
                precision -= any_breadth_penalty(conditions.len(), required);
            }
        }

        if let Some(ref unless_conds) = rule.unless {
            precision += PARAM_UNIT;
            let scores: Vec<f32> = unless_conds
                .iter()
                .map(|cond| match cond {
                    Condition::Trait { id } => referenced_precision(
                        id,
                        composite_lookup,
                        trait_lookup,
                        reference_index,
                        cache,
                        visiting,
                    ),
                    _ => score_condition(cond),
                })
                .collect();
            precision += sum_weakest(scores, 1);
        }

        visiting.remove(rule_id);
        let precision = precision.max(BASE_TRAIT_PRECISION);
        cache.insert(rule_id.to_string(), precision);
        if debug {
            eprintln!("  [DEBUG] {} TOTAL PRECISION: {:.2}", rule_id, precision);
        }
        return precision;
    }

    // Not a composite - try to find as a trait definition.
    if debug {
        eprintln!("  [DEBUG] Looking up trait: '{}'", rule_id);
    }
    let trait_def = resolve_rule_id(rule_id, trait_lookup);

    if let Some(trait_def) = trait_def {
        let precision = trait_def
            .precision
            .unwrap_or_else(|| calculate_trait_precision(trait_def));
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

pub(crate) fn calculate_composite_precision(
    rule_id: &str,
    composite_lookup: &HashMap<&str, &CompositeTrait>,
    trait_lookup: &HashMap<&str, &TraitDefinition>,
    cache: &mut HashMap<String, f32>,
    visiting: &mut HashSet<String>,
) -> f32 {
    let reference_index = build_reference_index(composite_lookup, trait_lookup);
    calculate_composite_precision_indexed(
        rule_id,
        composite_lookup,
        trait_lookup,
        &reference_index,
        cache,
        visiting,
    )
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
    let reference_index = build_reference_index(&composite_lookup, &trait_lookup);

    // First pass: Calculate precisions for rules that don't have them (immutable borrow)
    let calculated_precisions: Vec<(String, f32)> = composite_rules
        .iter()
        .filter(|rule| rule.precision.is_none())
        .map(|rule| {
            let mut visiting = std::collections::HashSet::new();
            let precision = calculate_composite_precision_indexed(
                &rule.id,
                &composite_lookup,
                &trait_lookup,
                &reference_index,
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

/// Validate composite rules that don't meet precision requirements and emit warnings.
///
/// - HOSTILE must have precision >= min_hostile_precision, else a warning is emitted.
/// - SUSPICIOUS must have precision >= min_suspicious_precision, else a warning is emitted.
///
/// IMPORTANT: Call precalculate_all_composite_precisions() first!
/// This function expects all precisions to already be calculated and stored.
pub(crate) fn validate_hostile_composite_precision(
    composite_rules: &mut [CompositeTrait],
    _trait_definitions: &[TraitDefinition],
    warnings: &mut Vec<String>,
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
                tracing::debug!(
                    "Low-precision composite '{}' at HOSTILE (precision {:.1} < {:.1})",
                    rule.id,
                    precision,
                    min_hostile_precision
                );
                warnings.push(format!(
                    "precision warning: composite '{}' HOSTILE score {:.1} < {:.1}",
                    rule.id, precision, min_hostile_precision
                ));
            }
            Criticality::Suspicious if precision < min_suspicious_precision => {
                tracing::debug!(
                    "Low-precision composite '{}' at SUSPICIOUS (precision {:.1} < {:.1})",
                    rule.id,
                    precision,
                    min_suspicious_precision
                );
                warnings.push(format!(
                    "precision warning: composite '{}' SUSPICIOUS score {:.1} < {:.1}",
                    rule.id, precision, min_suspicious_precision
                ));
            }
            _ => {}
        }
    }
}

/// Validate atomic traits that don't meet precision requirements and emit warnings.
///
/// - HOSTILE must have precision >= min_hostile_precision, else a warning is emitted.
/// - SUSPICIOUS must have precision >= min_suspicious_precision, else a warning is emitted.
pub(crate) fn validate_hostile_trait_precision(
    trait_definitions: &mut [TraitDefinition],
    warnings: &mut Vec<String>,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
) {
    for trait_def in trait_definitions.iter_mut() {
        if !matches!(
            trait_def.crit,
            Criticality::Hostile | Criticality::Suspicious
        ) {
            continue;
        }

        let precision = trait_def.precision.unwrap_or_else(|| {
            tracing::warn!(
                "Atomic trait '{}' has no precision calculated!",
                trait_def.id
            );
            0.0
        });

        match trait_def.crit {
            Criticality::Hostile if precision < min_hostile_precision => {
                tracing::debug!(
                    "Low-precision atomic '{}' at HOSTILE (precision {:.1} < {:.1})",
                    trait_def.id,
                    precision,
                    min_hostile_precision
                );
                warnings.push(format!(
                    "precision warning: atomic '{}' HOSTILE score {:.1} < {:.1}",
                    trait_def.id, precision, min_hostile_precision
                ));
            }
            Criticality::Suspicious if precision < min_suspicious_precision => {
                tracing::debug!(
                    "Low-precision atomic '{}' at SUSPICIOUS (precision {:.1} < {:.1})",
                    trait_def.id,
                    precision,
                    min_suspicious_precision
                );
                warnings.push(format!(
                    "precision warning: atomic '{}' SUSPICIOUS score {:.1} < {:.1}",
                    trait_def.id, precision, min_suspicious_precision
                ));
            }
            _ => {}
        }
    }
}
