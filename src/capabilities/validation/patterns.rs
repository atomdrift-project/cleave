//! Pattern Quality and Performance Analysis
//!
//! This module provides validation and analysis of regex and substring patterns used in trait definitions.
//! It identifies patterns that are likely to cause performance issues or false positives due to:
//!
//! - **Short patterns**: Patterns with insufficient literal content that match too broadly
//! - **Regex backtracking**: Patterns with catastrophic backtracking potential, including:
//!   - Overlapping alternations with wildcard patterns
//!   - Unbounded quantifiers (e.g., `.{n,}`)
//!   - Very large range quantifiers
//!
//! Pattern analysis helps maintain rule quality by ensuring patterns have adequate specificity
//! for their target domain.

use super::helpers::{find_line_number, is_ast_source_type, is_binary_file_type};
use crate::composite_rules::{Condition, FileType, TraitDefinition};
use std::collections::HashMap;
use std::sync::OnceLock;

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
            '*' | '+' | '?' if !in_bracket => {
                // Quantifiers reduce the count for the previous character
                // * and ? make previous optional (reduce by 1), + keeps at least 1
                if ch == '*' || ch == '?' {
                    count = count.saturating_sub(1);
                }
            }
            '(' | ')' | '|' | '^' | '$' | '.' if !in_bracket => {
                // Metacharacters that don't add literal content (except '.' which matches anything)
                if ch == '.' {
                    // '.' matches any char, but we don't count it as a specific literal
                }
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

fn unrolled_quantifier_regex() -> Option<&'static regex::Regex> {
    static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
    // Capture bounded quantifiers on shorthand classes: \s{n,m}, \w{n,m}, etc.
    // We extract the upper bound to only flag large unrolls (m > 20).
    // Small bounds like \d{1,3} or \w{5,15} are fine — the unroll cost is negligible.
    // Large bounds like \s{1,65} compile to 65 distinct NFA states instead of a
    // 2-state loop (\s+), and explode when nested inside repeated groups.
    //
    // Note: open-ended quantifiers {n,} are NOT flagged — Rust's NFA compiles them
    // to a 2-state loop, same as + or *. Bounding them (e.g. \s{1,65}) is actually
    // WORSE because it unrolls into N states.
    RE.get_or_init(|| regex::Regex::new(r"\\[swdSWD]\{([0-9]+),([0-9]+)\}").ok())
        .as_ref()
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
        match &trait_def.r#if {
            Condition::Raw { substr, regex, .. } => {
                // Check substr length
                if let Some(pattern) = substr {
                    if pattern.len() <= 3 {
                        let source = rule_source_files
                            .get(&trait_def.id)
                            .cloned()
                            .unwrap_or_else(|| "unknown".to_string());
                        warnings.push((
                            trait_def.id.clone(),
                            pattern.clone(),
                            "raw substr".to_string(),
                            source,
                        ));
                    }
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
                            pattern.clone(),
                            "raw regex".to_string(),
                            source,
                        ));
                    }
                }
            }
            Condition::Hex { pattern, .. } => {
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
            _ => {}
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
        let pattern_opt = match &trait_def.r#if {
            Condition::Raw {
                regex: Some(ref regex_str),
                ..
            } => Some(regex_str.as_str()),
            _ => None,
        };

        if let Some(pattern) = pattern_opt {
            if pattern.contains("(?:") {
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
}

/// Detect regex patterns that may cause catastrophic backtracking.
///
/// Patterns with nested quantifiers or alternations with overlapping prefixes
/// can cause exponential runtime on certain inputs. This validates patterns
/// for common backtracking pitfalls.
pub(crate) fn find_slow_regex_patterns(traits: &[TraitDefinition], warnings: &mut Vec<String>) {
    for trait_def in traits {
        // Extract regex pattern from any condition type that has one
        let pattern_opt = match &trait_def.r#if {
            Condition::Raw {
                regex: Some(ref regex_str),
                ..
            }
            | Condition::Ast {
                regex: Some(ref regex_str),
                ..
            }
            | Condition::StringValue {
                regex: Some(ref regex_str),
                ..
            }
            | Condition::Symbol {
                regex: Some(ref regex_str),
                ..
            } => Some(regex_str.clone()),
            _ => None,
        };

        if let Some(pattern) = pattern_opt {
            let mut issues = Vec::new();

            // Check for overlapping alternations with wildcards like (a.*|ab.*)
            if overlapping_alternations_regex().is_some_and(|regex| regex.is_match(&pattern)) {
                issues.push("alternation with multiple .* patterns may cause backtracking");
            }

            // Check for unrolled bounded quantifiers like \s{1,65} that should be \s+ or \s*
            // Only flag when upper bound > 20 — small unrolls like \d{1,3} or \w{5,15} are fine.
            // Note: open-ended {n,} is NOT flagged — NFA compiles it to a 2-state loop.
            if let Some(caps) =
                unrolled_quantifier_regex().and_then(|regex| regex.captures(&pattern))
            {
                if let Ok(upper) = caps[2].parse::<usize>() {
                    if upper > 20 {
                        issues.push(
                            "unrolled bounded quantifier (e.g. \\s{1,65}) — use \\s+, \\s*, or \\s? instead (loop vs chain)",
                        );
                    }
                }
            }

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
                    pattern,
                    issues.join(", ")
                ));
            }
        }
    }
}

/// Minimum substr length to recommend `string_value` over `raw` for binary types.
/// Shorter substrings are too common in binary data to reliably match via extracted strings.
const RAW_TO_STRING_MIN_SUBSTR_LEN: usize = 6;

/// Returns true if a regex pattern contains no meaningful metacharacters —
/// i.e., it could be expressed as a simple `substr` match.
///
/// Escaped dots (`\.`) are treated as literals. Bare dots, character classes,
/// quantifiers, anchors, and alternation all disqualify.
fn regex_is_effectively_literal(pattern: &str) -> bool {
    let mut chars = pattern.chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                // Consume the escaped character — it's a literal
                if chars.next().is_none() {
                    return false; // trailing backslash
                }
            }
            '.' | '*' | '+' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '|' | '^' | '$' => {
                return false;
            }
            _ => {}
        }
    }
    true
}

/// Detect `type: raw` conditions on binary file types that would be faster as
/// `type: string_value`.
///
/// For compiled binaries (ELF, PE, Mach-O, etc.), `raw` searches the entire file
/// content as a byte stream, while `string_value` searches only pre-extracted
/// strings — a much smaller corpus.
///
/// This flags:
/// - `raw` with `regex:` where the pattern is effectively a literal string
///   (no metacharacters besides escaped dots)
/// - `raw` with `substr:` where the pattern is >= 6 characters
///
/// Skips traits that have positional constraints (offset, section, etc.) since
/// those legitimately need `raw` to pin matches to specific file locations.
/// Detect `type: string_value` conditions on source file types where the pattern
/// is clearly code structure (function calls, import statements) that will never
/// appear as an extracted string literal.
///
/// For source files, string_value only searches AST-extracted string literals —
/// the content inside quotes. A pattern like `eval(` or `import os` matches code
/// syntax, not string values, and should use `type: raw` instead.
///
/// High-certainty heuristics only:
/// - `substr`/`exact` containing `identifier(` (function call syntax)
/// - `substr`/`exact` starting with `import ` or `from X import`
/// - `regex` patterns matching `require\(`, `exec\(`, `import\s`, etc.
pub(crate) fn find_string_value_should_use_raw(
    traits: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    // Regex for function call pattern: identifier (with optional dots/parens) followed by (
    // e.g. eval(, os.popen(, Runtime.getRuntime().exec, require('foo')
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

    for trait_def in traits {
        // Only applies to traits targeting source/script file types
        let targets_source = trait_def.r#for.iter().any(|ft| is_ast_source_type(*ft));

        if !targets_source {
            continue;
        }

        let (pattern_value, pattern_kind) = match &trait_def.r#if {
            Condition::StringValue {
                substr: Some(s), ..
            } => {
                if func_call_re.is_match(s) || import_re.is_match(s) {
                    (s.as_str(), "substr")
                } else {
                    continue;
                }
            }
            Condition::StringValue { exact: Some(s), .. } => {
                if func_call_re.is_match(s) || import_re.is_match(s) {
                    (s.as_str(), "exact")
                } else {
                    continue;
                }
            }
            Condition::StringValue { regex: Some(s), .. } => {
                if regex_code_re.is_match(s) {
                    (s.as_str(), "regex")
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
            "Wrong type: trait '{}' in {} uses `type: string_value` with {} '{}' on source types — \
             this pattern matches code structure, not string literals. Use `type: raw` instead",
            trait_def.id, location, pattern_kind, pattern_value
        ));
    }
}

/// Detect `type: raw` conditions on binary file types that would be faster as
/// `type: string_value`.
///
/// For compiled binaries (ELF, PE, Mach-O, etc.), `raw` searches the entire file
/// content as a byte stream, while `string_value` searches only pre-extracted
/// strings — a much smaller corpus.
///
/// This flags:
/// - `raw` with `regex:` where the pattern is effectively a literal string
///   (no metacharacters besides escaped dots)
/// - `raw` with `substr:` where the pattern is >= 6 characters
///
/// Skips traits that have positional constraints (offset, section, etc.) since
/// those legitimately need `raw` to pin matches to specific file locations.
pub(crate) fn find_raw_should_use_string_value(
    traits: &[TraitDefinition],
    warnings: &mut Vec<String>,
) {
    for trait_def in traits {
        // Only applies to binary file types
        let targets_binary = if trait_def.r#for.is_empty()
            || trait_def.r#for.iter().any(|ft| matches!(ft, FileType::All))
        {
            false // "all" types includes scripts — skip
        } else {
            trait_def.r#for.iter().all(|ft| is_binary_file_type(*ft))
        };

        if !targets_binary {
            continue;
        }

        // Skip if condition has positional constraints (legitimate raw use)
        let (has_position, substr, regex) = match &trait_def.r#if {
            Condition::Raw {
                substr,
                regex,
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            } => {
                let pinned = offset.is_some()
                    || offset_range.is_some()
                    || section_offset.is_some()
                    || section_offset_range.is_some()
                    || section.is_some();
                (pinned, substr.as_deref(), regex.as_deref())
            }
            _ => continue,
        };

        if has_position {
            continue;
        }

        // Skip traits with density constraints (per_kb_min, count_min >= 2) —
        // these rely on counting occurrences across the full binary, which
        // string_value can't reproduce.
        let has_density = trait_def.count_min.is_some_and(|c| c >= 2)
            || trait_def.per_kb_min.is_some()
            || trait_def.per_kb_max.is_some();
        if has_density {
            continue;
        }

        let suggestion = if let Some(pattern) = regex {
            if regex_is_effectively_literal(pattern)
                && pattern.len() >= RAW_TO_STRING_MIN_SUBSTR_LEN
            {
                Some((pattern, "regex (literal)"))
            } else {
                None
            }
        } else if let Some(pattern) = substr {
            if pattern.len() >= RAW_TO_STRING_MIN_SUBSTR_LEN {
                Some((pattern, "substr"))
            } else {
                None
            }
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
                "Performance: trait '{}' in {} uses `type: raw` with {} '{}' on binary-only types — \
                 `type: string_value` searches only extracted strings and is much faster",
                trait_def.id, location, kind, pattern
            ));
        }
    }
}
