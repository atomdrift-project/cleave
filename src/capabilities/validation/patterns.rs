//! Pattern Quality and Performance Analysis
//!
//! This module provides validation and analysis of regex and substring patterns used in trait definitions.
//! It identifies patterns that are likely to cause performance issues or false positives due to:
//!
//! - **Short patterns**: Patterns with insufficient literal content that match too broadly
//! - **Regex cost**: Patterns that force broad raw/text scans or unusually large NFA programs
//!
//! Pattern analysis helps maintain rule quality by ensuring patterns have adequate specificity
//! for their target domain.

use super::helpers::{find_line_number, is_ast_source_type, is_binary_file_type};
use crate::composite_rules::{Condition, FileType, TraitDefinition};
use std::collections::HashMap;
use std::sync::OnceLock;

/// Extract `(substr, regex, type_label)` from any condition that has them.
///
/// Returns `None` for conditions that do not carry both fields (e.g. `Hex`,
/// `Yara`, `Metrics`, `Trait`, `Syscall`). Use this helper instead of matching
/// individual variants so checks apply uniformly across the regex-bearing
/// condition types.
fn substr_regex_fields(
    condition: &Condition,
) -> Option<(Option<&str>, Option<&str>, &'static str)> {
    match condition {
        Condition::Symbol { substr, regex, .. } => {
            Some((substr.as_deref(), regex.as_deref(), "symbol"))
        }
        Condition::Text { substr, regex, .. } => {
            Some((substr.as_deref(), regex.as_deref(), "text"))
        }
        Condition::Literal { substr, regex, .. } => {
            Some((substr.as_deref(), regex.as_deref(), "string_literal"))
        }
        Condition::Raw { substr, regex, .. } => Some((substr.as_deref(), regex.as_deref(), "raw")),
        Condition::TreeSitter { substr, regex, .. } => {
            Some((substr.as_deref(), regex.as_deref(), "tree-sitter"))
        }
        Condition::Section { substr, regex, .. } => {
            Some((substr.as_deref(), regex.as_deref(), "section"))
        }
        Condition::Encoded { substr, regex, .. } => {
            Some((substr.as_deref(), regex.as_deref(), "encoded"))
        }
        Condition::Path { substr, regex, .. } => {
            Some((substr.as_deref(), regex.as_deref(), "basename"))
        }
        Condition::Kv { substr, regex, .. } => Some((substr.as_deref(), regex.as_deref(), "value")),
        _ => None,
    }
}

/// Count the minimum number of literal characters that MUST match in a regex pattern.
///
/// This counts characters that are not optional or quantified, helping identify
/// patterns that are too loose and likely to produce false positives.
///
/// # Examples
///
/// - `abc` → 3 (all literal)
/// - `a.b` → 2 (the dot matches anything)
/// - `a*bc` → 2 (the `a` is optional)
/// - `[abc]def` → 4 (character class counts as 1)
fn count_regex_min_literals(pattern: &str) -> usize {
    let mut count: usize = 0;
    let mut chars = pattern.chars().peekable();
    let mut in_bracket = false; // Track character classes [...]
    let mut bracket_depth: usize = 0;

    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                // Escape sequence - peek ahead
                if let Some(&next) = chars.peek() {
                    chars.next(); // Consume the next character
                    // Special escape sequences that match variable content don't count as literals
                    if !matches!(
                        next,
                        'w' | 'W' | 'd' | 'D' | 's' | 'S' | 'b' | 'B' | 'A' | 'Z'
                    ) {
                        // \n, \t, \x.., \u.., etc. are literals
                        count += 1;
                        // For \x.. and similar, consume additional hex digits
                        if next == 'x' {
                            // Consume up to 2 hex digits
                            for _ in 0..2 {
                                if chars.peek().is_some_and(char::is_ascii_hexdigit) {
                                    chars.next();
                                }
                            }
                        }
                    }
                }
            }
            '[' => {
                in_bracket = true;
                bracket_depth += 1;
                // Character class counts as 1 potential character
                count += 1;
            }
            ']' if in_bracket => {
                bracket_depth = bracket_depth.saturating_sub(1);
                if bracket_depth == 0 {
                    in_bracket = false;
                }
                // Don't count the closing bracket
            }
            '*' | '?' if !in_bracket => {
                // Quantifiers * and ? make the previous character optional; + keeps at least 1.
                count = count.saturating_sub(1);
            }
            '+' | '(' | ')' | '|' | '^' | '$' | '.' if !in_bracket => {
                // '+' keeps at least 1 of the previous — no adjustment to count.
                // Other metacharacters don't contribute literal content.
                // '.' matches any char but isn't counted as a specific literal.
            }
            '{' if !in_bracket => {
                // Quantifier like {n,m} - skip until closing }
                for c in chars.by_ref() {
                    if c == '}' {
                        break;
                    }
                }
                // Quantifiers can make previous optional
                count = count.saturating_sub(1);
            }
            _ if !in_bracket => {
                // Regular literal character
                count += 1;
            }
            _ => {
                // Inside character class, don't count individual chars
            }
        }
    }

    count
}

fn overlapping_alternations_regex() -> Option<&'static regex::Regex> {
    static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\([^)]*\.\*\|[^)]*\.\*\)").ok())
        .as_ref()
}

fn broad_counted_repeat_regex() -> Option<&'static regex::Regex> {
    static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?:\.|\\[sSwWdD]|\[\^?[^\]]+\])\{([0-9]+),([0-9]+)\}").ok()
    })
    .as_ref()
}

fn unbounded_broad_span_regex() -> Option<&'static regex::Regex> {
    static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?:\.\*|\.\+|\[\^[^\]]+\][*+]|\[\\s\\S\][*+])").ok())
        .as_ref()
}

fn leading_broad_span_regex() -> Option<&'static regex::Regex> {
    static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"^(?:\^|\(\?[-a-zA-Z:]+\))*(?:\.\*|\.\+|\[\^[^\]]+\][*+]|\[\\s\\S\][*+])",
        )
        .ok()
    })
    .as_ref()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegexSearchScope {
    Broad,
    Bounded,
}

#[derive(Debug)]
struct RegexFacts<'a> {
    pattern: &'a str,
    type_label: &'static str,
    scope: RegexSearchScope,
    literal_count: usize,
    alternation_count: usize,
    largest_broad_repeat: Option<usize>,
    has_unbounded_broad_span: bool,
    has_leading_broad_span: bool,
    has_overlapping_wildcard_alternation: bool,
}

impl<'a> RegexFacts<'a> {
    fn analyze(pattern: &'a str, type_label: &'static str) -> Self {
        Self {
            pattern,
            type_label,
            scope: regex_search_scope(type_label),
            literal_count: count_regex_min_literals(pattern),
            alternation_count: count_regex_alternations(pattern),
            largest_broad_repeat: largest_broad_counted_repeat(pattern),
            has_unbounded_broad_span: unbounded_broad_span_regex()
                .is_some_and(|regex| regex.is_match(pattern)),
            has_leading_broad_span: leading_broad_span_regex()
                .is_some_and(|regex| regex.is_match(pattern)),
            has_overlapping_wildcard_alternation: overlapping_alternations_regex()
                .is_some_and(|regex| regex.is_match(pattern)),
        }
    }
}

fn regex_search_scope(type_label: &str) -> RegexSearchScope {
    match type_label {
        "value" | "symbol" | "string_literal" | "basename" | "tree-sitter" | "section" => {
            RegexSearchScope::Bounded
        }
        _ => RegexSearchScope::Broad,
    }
}

fn count_regex_alternations(pattern: &str) -> usize {
    let mut count = 0;
    let mut escaped = false;
    let mut in_class = false;
    for ch in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '|' if !in_class => count += 1,
            _ => {}
        }
    }
    count
}

fn largest_broad_counted_repeat(pattern: &str) -> Option<usize> {
    let mut largest = None;
    let Some(regex) = broad_counted_repeat_regex() else {
        return largest;
    };
    for caps in regex.captures_iter(pattern) {
        let Ok(upper) = caps[2].parse::<usize>() else {
            continue;
        };
        largest = Some(largest.map_or(upper, |current: usize| current.max(upper)));
    }
    largest
}

fn regex_performance_issues(facts: &RegexFacts<'_>) -> Vec<String> {
    let mut issues = Vec::new();

    let repeat_limit = match facts.scope {
        RegexSearchScope::Broad => 1000,
        RegexSearchScope::Bounded => 4096,
    };
    if let Some(upper) = facts.largest_broad_repeat
        && upper > repeat_limit
    {
        issues.push(format!(
                "`{}` regex has a broad counted repeat up to {}; keep broad repeats under {} or use a structured matcher",
                facts.type_label, upper, repeat_limit
            ));
    }

    if facts.scope == RegexSearchScope::Broad {
        if facts.has_leading_broad_span && facts.literal_count < 5 {
            issues.push(
                "leading broad span on raw/text-like input with little literal content; add a literal prefix or use a narrower matcher"
                    .to_string(),
            );
        }

        if facts.has_overlapping_wildcard_alternation {
            issues.push(
                "wildcard-heavy alternation on raw/text-like input; split into focused traits or require a literal prefilter"
                    .to_string(),
            );
        }

        if facts.alternation_count > 40 && facts.has_unbounded_broad_span {
            issues.push(format!(
                "large alternation chain ({}) combined with broad spans; split the regex or use shared traits",
                facts.alternation_count + 1
            ));
        }
    }

    issues
}

/// Find traits with short patterns that are likely to produce too many false positives.
///
/// Short patterns (3 chars or less for substr/regex, 2 bytes or less for hex) are flagged
/// unless the trait uses specificity constraints like count_min, section, or offset.
///
/// Returns `(trait_id, pattern, pattern_type, source_file)` for warnings.
#[must_use]
pub(crate) fn find_short_pattern_warnings(
    trait_definitions: &[TraitDefinition],
    rule_source_files: &HashMap<String, String>,
) -> Vec<(String, String, String, String)> {
    let mut warnings = Vec::new();

    for trait_def in trait_definitions {
        // Check if trait has specificity constraints on TraitDefinition
        // count_min: 1 is not meaningful (it's the default), require count_min >= 2
        let has_meaningful_count = trait_def.count_min.is_some_and(|c| c >= 2)
            || trait_def.count_max.is_some()
            || trait_def.per_kb_min.is_some()
            || trait_def.per_kb_max.is_some();

        // Specific file type constraints provide specificity (not matching all file types)
        // For 3-char patterns, require no more than 3 specific file types
        use crate::composite_rules::types::FileType;

        // Count actual file types after expanding meta-types
        let actual_type_count = if trait_def.r#for.is_empty() {
            // Empty means "all" (default behavior)
            usize::MAX
        } else if trait_def.r#for.iter().any(|ft| matches!(ft, FileType::All)) {
            // FileType::All means all file types
            usize::MAX
        } else {
            // Count specific types (no meta-types to expand in current FileType enum)
            trait_def.r#for.len()
        };

        let has_specific_file_types = actual_type_count <= 3;

        // Helper to check if condition has location constraints
        let has_location_constraints = |condition: &Condition| -> bool {
            match condition {
                Condition::Raw {
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                    ..
                }
                | Condition::Text {
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                    ..
                }
                | Condition::Literal {
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                    ..
                }
                | Condition::Encoded {
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                    ..
                }
                | Condition::Hex {
                    section,
                    offset,
                    offset_range,
                    section_offset,
                    section_offset_range,
                    ..
                } => {
                    section.is_some()
                        || offset.is_some()
                        || offset_range.is_some()
                        || section_offset.is_some()
                        || section_offset_range.is_some()
                }
                _ => false,
            }
        };

        // Skip if trait has any specificity constraints
        if has_meaningful_count
            || has_specific_file_types
            || has_location_constraints(&trait_def.r#if)
        {
            continue;
        }

        // Check the condition
        if let Some((substr, regex, type_label)) = substr_regex_fields(&trait_def.r#if) {
            // Check substr length
            if let Some(pattern) = substr
                && pattern.len() <= 3
            {
                let source = rule_source_files
                    .get(&trait_def.id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                warnings.push((
                    trait_def.id.clone(),
                    pattern.to_string(),
                    format!("{} substr", type_label),
                    source,
                ));
            }
            // Check regex minimum literal content
            // Count characters that MUST appear (not quantified or optional)
            if let Some(pattern) = regex {
                let literal_count = count_regex_min_literals(pattern);
                if literal_count <= 3 && literal_count > 0 {
                    let source = rule_source_files
                        .get(&trait_def.id)
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string());
                    warnings.push((
                        trait_def.id.clone(),
                        pattern.to_string(),
                        format!("{} regex", type_label),
                        source,
                    ));
                }
            }
        }
        if let Condition::Hex { pattern, .. } = &trait_def.r#if {
            // Count effective hex bytes (excluding ?? wildcards and [N] gaps,
            // but counting nibble wildcards like 4? or ?F)
            let effective_bytes = pattern
                .split_whitespace()
                .filter(|p| {
                    !p.starts_with('[')
                        && *p != "??"
                        && p.len() == 2
                        && p.chars().all(|c| c.is_ascii_hexdigit() || c == '?')
                })
                .count();
            if effective_bytes <= 2 && effective_bytes > 0 {
                let source = rule_source_files
                    .get(&trait_def.id)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                warnings.push((
                    trait_def.id.clone(),
                    pattern.clone(),
                    "hex pattern".to_string(),
                    source,
                ));
            }
        }
    }

    warnings
}

/// Detect regex patterns that use non-capturing groups `(?:...)`.
///
/// Non-capturing groups are unnecessary in cleave because we preserve the entire
/// matched line for evidence, not individual capture groups. Using `(?:` adds
/// syntactic noise without benefit and may indicate copy-pasted patterns that
/// weren't adapted for this codebase.
pub(crate) fn find_non_capturing_groups(traits: &[TraitDefinition], warnings: &mut Vec<String>) {
    for trait_def in traits {
        let pattern_opt = substr_regex_fields(&trait_def.r#if).and_then(|(_, r, _)| r);

        if let Some(pattern) = pattern_opt
            && pattern.contains("(?:")
        {
            let source_file = trait_def
                .defined_in
                .to_str()
                .unwrap_or("unknown")
                .to_string();
            let line_hint = find_line_number(&source_file, &trait_def.id);
            let location = if let Some(line) = line_hint {
                format!("{}:{}", source_file, line)
            } else {
                source_file
            };

            warnings.push(format!(
                    "Unnecessary non-capturing group: trait '{}' in {} uses '(?:' — \
                     cleave preserves entire matched lines, not capture groups. \
                     Replace (?:...) with plain (...) or remove grouping if only used for alternation.",
                    trait_def.id, location
                ));
        }
    }
}

/// Detect regex patterns that are likely to be expensive with Rust's regex engine.
///
/// Rust regex does not suffer catastrophic backtracking, so this policy focuses
/// on broad raw/text scans and unusually large counted repetitions. Bounded
/// structured fields such as `kv`, `symbol`, `string_literal`, and `basename`
/// are intentionally much more permissive.
pub(crate) fn find_slow_regex_patterns(traits: &[TraitDefinition], warnings: &mut Vec<String>) {
    for trait_def in traits {
        // Extract regex pattern from any regex-bearing condition variant
        let pattern_opt = substr_regex_fields(&trait_def.r#if)
            .and_then(|(_, r, type_label)| r.map(|pattern| (pattern, type_label)));

        if let Some((pattern, type_label)) = pattern_opt {
            let facts = RegexFacts::analyze(pattern, type_label);
            let issues = regex_performance_issues(&facts);

            if !issues.is_empty() {
                let source_file = trait_def
                    .defined_in
                    .to_str()
                    .unwrap_or("unknown")
                    .to_string();

                let line_hint = find_line_number(&source_file, &trait_def.id);
                let location = if let Some(line) = line_hint {
                    format!("{}:{}", source_file, line)
                } else {
                    source_file
                };

                warnings.push(format!(
                    "Regex performance: trait '{}' in {} has potentially slow pattern '{}': {}",
                    trait_def.id,
                    location,
                    facts.pattern,
                    issues.join(", ")
                ));
            }
        }
    }
}

/// Minimum literal length to recommend `text` over `raw` for binary types.
/// Shorter substrings are too common in binary data to reliably match via extracted strings.
const RAW_TO_TEXT_MIN_LITERAL_LEN: usize = 5;

/// Minimum length for the plain-extractable-text `raw` misuse check. Matches the
/// string-extractor's min length (4): any plain-text literal this long is surfaced
/// as an extracted string for EVERY file type (flat strings extraction over the
/// whole file), so `type: text` reaches it and `raw` is the wrong surface.
const RAW_PLAIN_TEXT_MIN_LEN: usize = 4;

/// True when a literal is plain printable ASCII text containing at least one
/// letter — exactly the content `type: text` (string extraction) captures.
/// Such a literal must never be a `raw` search: `raw` is reserved for byte
/// patterns text extraction can't reach (sub-4-char runs, embedded NULs,
/// high/non-UTF8 bytes). Escaped byte sequences (`\xNN`) are treated as
/// intentional byte patterns and left alone.
fn is_plain_extractable_text(s: &str) -> bool {
    !s.contains("\\x")
        && s.bytes().all(|b| (0x20..=0x7e).contains(&b))
        && s.chars().any(|c| c.is_ascii_alphabetic())
}

/// Returns true if a regex pattern contains no meaningful metacharacters —
/// i.e., it could be expressed as a simple `substr` match.
///
/// Escaped dots (`\.`) are treated as literals. Bare dots, character classes,
/// quantifiers, anchors, and alternation all disqualify.
fn regex_is_effectively_literal(pattern: &str) -> bool {
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            // `\<x>` escapes a literal; a trailing backslash is malformed.
            '\\' if chars.next().is_none() => return false,
            '\\' => continue,
            '.' | '*' | '+' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|' | '^' | '$' => {
                return false;
            }
            _ => {}
        }
    }
    true
}

fn condition_has_position_constraints(condition: &Condition) -> bool {
    match condition {
        Condition::Raw {
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            ..
        } => {
            section.is_some()
                || offset.is_some()
                || offset_range.is_some()
                || section_offset.is_some()
                || section_offset_range.is_some()
        }
        _ => false,
    }
}

fn pattern_targets_code_structure(condition: &Condition) -> Option<(&str, &str)> {
    // Regex for function call pattern: identifier (with optional dots/parens) followed by (
    static FUNC_CALL_RE: OnceLock<regex::Regex> = OnceLock::new();
    #[allow(clippy::expect_used)]
    let func_call_re = FUNC_CALL_RE
        .get_or_init(|| regex::Regex::new(r"[a-zA-Z_][a-zA-Z0-9_.]*\(").expect("valid regex"));

    // Import statement pattern: starts with import/from...import
    static IMPORT_RE: OnceLock<regex::Regex> = OnceLock::new();
    #[allow(clippy::expect_used)]
    let import_re = IMPORT_RE.get_or_init(|| {
        regex::Regex::new(r"^(import\s+\w|from\s+\w+\s+import\b)").expect("valid regex")
    });

    // Regex-mode patterns that search for code structure
    static REGEX_CODE_RE: OnceLock<regex::Regex> = OnceLock::new();
    #[allow(clippy::expect_used)]
    let regex_code_re = REGEX_CODE_RE.get_or_init(|| {
        regex::Regex::new(
            r"(?:require\b|\\brequire|exec\(|execSync|eval\(|shell_exec\(|child_process\\?\.|from\\s|import\\s|\\bimport\\b)",
        )
        .expect("valid regex")
    });

    match condition {
        Condition::Literal {
            substr: Some(s), ..
        } => {
            if func_call_re.is_match(s) || import_re.is_match(s) {
                Some((s.as_str(), "substr"))
            } else {
                None
            }
        }
        Condition::Literal { exact: Some(s), .. } => {
            if func_call_re.is_match(s) || import_re.is_match(s) {
                Some((s.as_str(), "exact"))
            } else {
                None
            }
        }
        Condition::Literal { regex: Some(s), .. } => {
            if regex_code_re.is_match(s) {
                Some((s.as_str(), "regex"))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn targets_binary_only(file_types: &[FileType]) -> bool {
    if file_types.is_empty() || file_types.iter().any(|ft| matches!(ft, FileType::All)) {
        return false;
    }
    file_types.iter().all(|ft| is_binary_file_type(*ft))
}

fn targets_raw_text_only(file_types: &[FileType]) -> bool {
    if file_types.is_empty() || file_types.iter().any(|ft| matches!(ft, FileType::All)) {
        return false;
    }
    file_types.iter().all(FileType::uses_raw_text_search)
}

/// Detect `type: string_literal` conditions on AST-backed source file types where
/// the pattern is clearly code structure and should use `type: text`.
pub(crate) fn find_string_literal_should_use_text(
    traits: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    for trait_def in traits {
        let targets_source = trait_def.r#for.iter().any(|ft| is_ast_source_type(*ft));
        if !targets_source {
            continue;
        }

        let (pattern_value, pattern_kind) = match &trait_def.r#if {
            Condition::Literal { .. } => {
                if let Some(match_info) = pattern_targets_code_structure(&trait_def.r#if) {
                    match_info
                } else {
                    continue;
                }
            }
            _ => continue,
        };

        let source_file = trait_def
            .defined_in
            .to_str()
            .unwrap_or("unknown")
            .to_string();
        let line_hint = find_line_number(&source_file, &trait_def.id);
        let location = if let Some(line) = line_hint {
            format!("{}:{}", source_file, line)
        } else {
            source_file
        };

        warnings.push(format!(
            "Wrong type: trait '{}' in {} uses `type: string_literal` with {} '{}' on source types — \
             this pattern matches code structure, not string literals. Use `type: text` instead",
            trait_def.id, location, pattern_kind, pattern_value
        ));
    }
}

/// Detect `type: raw` conditions that should use `type: text`.
///
/// Binary-only traits are flagged when the raw search is really looking for string-like
/// content, which `text` can satisfy much faster via extracted strings.
///
/// Source/text-only traits are flagged whenever `text` has the same semantics as
/// `raw` for the given file types.
pub(crate) fn find_raw_should_use_text(traits: &[TraitDefinition], warnings: &mut Vec<String>) {
    for trait_def in traits {
        let (exact, substr, regex, word) = match &trait_def.r#if {
            Condition::Raw {
                exact,
                substr,
                regex,
                word,
                ..
            } => (
                exact.as_deref(),
                substr.as_deref(),
                regex.as_deref(),
                word.as_deref(),
            ),
            _ => continue,
        };

        if condition_has_position_constraints(&trait_def.r#if) {
            continue;
        }

        // A `raw` literal that is plain extractable ASCII text is misusing
        // `raw`: flat string extraction surfaces it for EVERY file type (incl.
        // OLE/MSI/PDF/RTF containers — verified: cleave runs `strings` over the
        // whole file), so `type: text` reaches it. This holds for ANY `for:`,
        // which is why it is not gated on file type like the heuristics below.
        if let Some(lit) = exact.or(substr).or(word) {
            if lit.len() >= RAW_PLAIN_TEXT_MIN_LEN && is_plain_extractable_text(lit) {
                let source_file = trait_def
                    .defined_in
                    .to_str()
                    .unwrap_or("unknown")
                    .to_string();
                let location = match find_line_number(&source_file, &trait_def.id) {
                    Some(line) => format!("{}:{}", source_file, line),
                    None => source_file,
                };
                warnings.push(format!(
                    "Wrong type: trait '{}' in {} uses `type: raw` for plain text '{}' — \
                     use `type: text` (raw is reserved for bytes text extraction can't reach)",
                    trait_def.id, location, lit
                ));
                continue;
            }
        }

        let targets_binary = targets_binary_only(&trait_def.r#for);
        let targets_text_like = targets_raw_text_only(&trait_def.r#for);
        if !targets_binary && !targets_text_like {
            continue;
        }

        let suggestion = if targets_binary {
            let has_density = trait_def.count_min.is_some_and(|c| c >= 2)
                || trait_def.per_kb_min.is_some()
                || trait_def.per_kb_max.is_some();
            if has_density {
                continue;
            }

            if let Some(pattern) = exact.or(substr).or(word) {
                if pattern.len() >= RAW_TO_TEXT_MIN_LITERAL_LEN {
                    let kind = if exact.is_some() {
                        "exact"
                    } else if substr.is_some() {
                        "substr"
                    } else {
                        "word"
                    };
                    Some((pattern, kind))
                } else {
                    None
                }
            } else if let Some(pattern) = regex {
                if regex_is_effectively_literal(pattern)
                    && pattern.len() >= RAW_TO_TEXT_MIN_LITERAL_LEN
                {
                    Some((pattern, "regex (literal)"))
                } else {
                    None
                }
            } else {
                None
            }
        } else if let Some(pattern) = exact.or(substr).or(regex).or(word) {
            let kind = if exact.is_some() {
                "exact"
            } else if substr.is_some() {
                "substr"
            } else if regex.is_some() {
                "regex"
            } else {
                "word"
            };
            Some((pattern, kind))
        } else {
            None
        };

        if let Some((pattern, kind)) = suggestion {
            let source_file = trait_def
                .defined_in
                .to_str()
                .unwrap_or("unknown")
                .to_string();
            let line_hint = find_line_number(&source_file, &trait_def.id);
            let location = if let Some(line) = line_hint {
                format!("{}:{}", source_file, line)
            } else {
                source_file
            };

            warnings.push(format!(
                "{}: trait '{}' in {} uses `type: raw` with {} '{}' — use `type: text` instead",
                if targets_binary {
                    "Performance"
                } else {
                    "Wrong type"
                },
                trait_def.id,
                location,
                kind,
                pattern
            ));
        }
    }
}

#[allow(dead_code)]
pub(crate) fn find_raw_should_use_string_value(
    traits: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    find_raw_should_use_text(traits, warnings);
}

/// If `pattern` is structurally equivalent to a bare function call `NAME(`,
/// return `NAME`. Method calls (`obj.fn(`) and patterns with arguments are
/// rejected — those depend on call-site shape that `type: symbol` can't replace.
fn extract_simple_function_call_name(pattern: &str, is_regex: bool) -> Option<String> {
    if is_regex {
        // Strip a trivial leading boundary guard (\b, ^, (^|X), (?:^|X)).
        static LEAD_RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
        let lead_re = LEAD_RE
            .get_or_init(|| {
                regex::Regex::new(r"^(?:\\b|\^|\(\?:\^\|[^()]{1,8}\)|\(\^\|[^()]{1,8}\))").ok()
            })
            .as_ref()?;
        let body = if let Some(m) = lead_re.find(pattern) {
            &pattern[m.end()..]
        } else {
            pattern
        };

        // Body must be NAME, optional \s*/\s+, then literal \( and optionally \)
        // or trailing \b. Anything else (arg-shape matching) is out of scope.
        static BODY_RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
        let body_re = BODY_RE
            .get_or_init(|| {
                regex::Regex::new(r"^([a-zA-Z_][a-zA-Z0-9_]+)(?:\\s[*+])?\\\((?:\\\))?(?:\\b)?$")
                    .ok()
            })
            .as_ref()?;
        let caps = body_re.captures(body)?;
        Some(caps.get(1)?.as_str().to_string())
    } else {
        // substr / exact — must be a bare `NAME(` or `NAME ( )` pattern. No
        // dots in the name (those are method calls), no arguments, no trailing
        // content beyond an empty arg list.
        static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
        let re = RE
            .get_or_init(|| regex::Regex::new(r"^\s*([a-zA-Z_][a-zA-Z0-9_]+)\s*\(\s*\)?\s*$").ok())
            .as_ref()?;
        let caps = re.captures(pattern)?;
        Some(caps.get(1)?.as_str().to_string())
    }
}

/// Detect `type: text` (or `type: raw`) function-call patterns whose every
/// `for:` target supports tree-sitter symbol resolution. For these languages,
/// `type: symbol` is both faster (a hash lookup against the extracted symbol
/// table) and more accurate (no spurious matches on the same identifier inside
/// comments, string literals, or unrelated context).
///
/// Example: a trait with `for: [javascript, typescript]` and `if: { type: text,
/// substr: "eval(" }` should be `if: { type: symbol, exact: eval }`.
pub(crate) fn find_ast_function_call_should_use_symbol(
    traits: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    for trait_def in traits {
        // Every for-type must be an AST-source language. An empty for-list
        // means "all" — that includes binary types where `symbol` has very
        // different semantics, so skip.
        if trait_def.r#for.is_empty() || !trait_def.r#for.iter().all(|ft| is_ast_source_type(*ft)) {
            continue;
        }
        // Symbol conditions are capped at 4 file types (see constraints.rs).
        // Don't recommend a conversion that would immediately exceed the cap.
        if trait_def.r#for.len() > 4 {
            continue;
        }
        // Section / offset filters target binary structure — leave alone.
        if condition_has_position_constraints(&trait_def.r#if) {
            continue;
        }

        let (Condition::Text {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            is_check,
            ..
        }
        | Condition::Raw {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            is_check,
            ..
        }) = &trait_def.r#if
        else {
            continue;
        };
        // Only convertible conditions are in scope. Symbol matches are
        // deterministic, so case folding and is_check validators don't apply.
        // Inline `not:` clauses inside the condition usually exist to
        // disambiguate text-mode false matches that symbol mode can't make
        // anyway — flag the trait and let the conversion drop the `not:`.
        if word.is_some() || *case_insensitive || is_check.is_some() {
            continue;
        }
        let (kind, value, name) = if let Some(v) = exact {
            if substr.is_some() || regex.is_some() {
                continue;
            }
            let Some(name) = extract_simple_function_call_name(v, false) else {
                continue;
            };
            ("exact", v.as_str(), name)
        } else if let Some(v) = substr {
            if regex.is_some() {
                continue;
            }
            let Some(name) = extract_simple_function_call_name(v, false) else {
                continue;
            };
            ("substr", v.as_str(), name)
        } else if let Some(v) = regex {
            let Some(name) = extract_simple_function_call_name(v, true) else {
                continue;
            };
            ("regex", v.as_str(), name)
        } else {
            continue;
        };

        let source_file = trait_def
            .defined_in
            .to_str()
            .unwrap_or("unknown")
            .to_string();
        let line_hint = find_line_number(&source_file, &trait_def.id);
        let location = if let Some(line) = line_hint {
            format!("{}:{}", source_file, line)
        } else {
            source_file
        };

        warnings.push(format!(
            "Performance: trait '{}' in {} uses `type: text` with {} '{}' to match a function call on AST source types — \
             use `type: symbol` with `exact: {}` instead (faster, no false positives on the name inside comments or string literals)",
            trait_def.id, location, kind, value, name
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::{RegexFacts, regex_performance_issues};

    fn issues(pattern: &str, type_label: &'static str) -> Vec<String> {
        regex_performance_issues(&RegexFacts::analyze(pattern, type_label))
    }

    #[test]
    fn regex_perf_allows_moderate_bounded_spans() {
        assert!(issues(r"\S{1,80}", "text").is_empty());
        assert!(issues(r"https?://\S{1,200}\.ps1\b", "text").is_empty());
    }

    #[test]
    fn regex_perf_flags_large_broad_text_spans() {
        let warnings = issues(r"^.{0,2000}Invoke-Expression", "text");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("broad counted repeat"));
    }

    #[test]
    fn regex_perf_is_lenient_for_bounded_fields() {
        assert!(issues(r".{0,2000}Invoke-Expression", "value").is_empty());

        let warnings = issues(r".{0,5000}Invoke-Expression", "value");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("broad counted repeat"));
    }

    #[test]
    fn regex_perf_flags_unanchored_broad_scans_only_when_too_loose() {
        let warnings = issues(r".*\w+.*", "raw");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("leading broad span"));

        assert!(issues(r".*BackdoorConfig", "raw").is_empty());
    }
}
