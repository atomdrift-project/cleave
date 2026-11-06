//! Regex alternation parsing and pattern extraction for the duplicate checks.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Split a regex pattern on top-level `|` only — not inside parentheses or brackets.
/// This avoids false positives from patterns like `(?:foo|bar)baz` being split into
/// `(?:foo` and `bar)baz`.
pub(super) fn split_top_level_alternation(pattern: &str) -> Vec<&str> {
    // Check if the entire pattern is wrapped in a single group like (a|b|c)
    // If so, unwrap it first
    let unwrapped =
        if pattern.starts_with('(') && pattern.ends_with(')') && !pattern.starts_with("(?") {
            // Check if the opening paren matches the closing paren
            let mut depth = 0;
            let mut in_char_class = false;
            let bytes = pattern.as_bytes();
            let mut matches_at_end = false;
            let mut closes_before_end = false;

            for (i, &byte) in bytes.iter().enumerate() {
                // Count consecutive preceding backslashes; odd count means escaped
                let mut backslash_count = 0;
                let mut j = i;
                while j > 0 && bytes[j - 1] == b'\\' {
                    backslash_count += 1;
                    j -= 1;
                }
                if backslash_count % 2 != 0 {
                    continue; // escaped character
                }
                match byte {
                    b'[' if !in_char_class => in_char_class = true,
                    b']' if in_char_class => in_char_class = false,
                    b'(' if !in_char_class => {
                        depth += 1;
                        if i == 0 {
                            // This is the opening paren
                            continue;
                        }
                    }
                    b')' if !in_char_class => {
                        depth -= 1;
                        if depth == 0 && i == bytes.len() - 1 {
                            matches_at_end = true;
                        } else if depth == 0 {
                            closes_before_end = true;
                        }
                    }
                    _ => {}
                }
            }

            if matches_at_end && !closes_before_end {
                let mut start = 1;
                // Also skip non-capturing group prefix (?:)
                if pattern[start..].starts_with("?:") {
                    start += 2;
                }
                &pattern[start..pattern.len() - 1]
            } else {
                pattern
            }
        } else {
            pattern
        };

    let mut depth = 0i32;
    let mut in_char_class = false;
    let mut last = 0;
    let mut result = Vec::new();
    let bytes = unwrapped.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 2; // skip escaped character
                continue;
            }
            b'[' if !in_char_class => {
                in_char_class = true;
            }
            b']' if in_char_class => {
                in_char_class = false;
            }
            b'(' if !in_char_class => {
                depth += 1;
            }
            b')' if !in_char_class => {
                depth -= 1;
            }
            b'|' if !in_char_class && depth == 0 => {
                result.push(&unwrapped[last..i]);
                last = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    result.push(&unwrapped[last..]);
    result
}

pub(super) fn meaningful_regex_alternative(alternative: &str) -> bool {
    let alt = alternative.trim();
    if alt.len() < 4 {
        return false;
    }

    // Pure regex framing is not a semantic overlap. These pieces occur in many
    // unrelated patterns and should not create reuse pressure by themselves.
    let mut semantic_chars = 0usize;
    for ch in alt.chars() {
        if ch.is_alphanumeric() || ch == '_' || ch == '-' || ch == '/' || ch == '\\' || ch == '.' {
            semantic_chars += 1;
        }
    }

    semantic_chars >= 3
}

pub(super) fn extract_single_group_alternation(
    pattern: &str,
) -> Option<(String, Vec<String>, String)> {
    let mut unwrapped = pattern;
    if unwrapped.starts_with("(?i)") {
        unwrapped = &unwrapped[4..];
    }

    let mut escape = false;
    let mut in_char_class = false;
    let mut depth = 0usize;
    let mut group_start = None;
    let mut group_end = None;

    for (idx, ch) in unwrapped.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        match ch {
            '\\' => escape = true,
            '[' if !in_char_class => in_char_class = true,
            ']' if in_char_class => in_char_class = false,
            '(' if !in_char_class => {
                if depth == 0 {
                    if group_start.is_some() {
                        return None;
                    }
                    group_start = Some(idx);
                }
                depth += 1;
            }
            ')' if !in_char_class => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    group_end = Some(idx);
                }
            }
            '|' if !in_char_class && depth == 0 => return None,
            _ => {}
        }
    }

    let (start, end) = (group_start?, group_end?);
    if depth != 0 || end <= start + 1 {
        return None;
    }

    let prefix = normalize_regex(&unwrapped[..start]);
    let suffix = normalize_regex(&unwrapped[end + 1..]);
    let inside = &unwrapped[start + 1..end];
    let alternatives = split_top_level_alternation(inside);
    if alternatives.len() <= 1 {
        return None;
    }

    Some((
        prefix,
        alternatives.into_iter().map(decode_hex_escapes).collect(),
        suffix,
    ))
}

/// Decode common hex escapes in patterns (\xNN → character)
/// This allows detecting duplicates like '\x27' vs "'"
pub(in super::super) fn decode_hex_escapes(pattern: &str) -> String {
    let mut result = String::new();
    let mut chars = pattern.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(&'x') = chars.peek() {
                chars.next(); // consume 'x'

                // Try to read 2 hex digits
                let hex_str: String = chars.by_ref().take(2).collect();
                if hex_str.len() == 2
                    && let Ok(byte) = u8::from_str_radix(&hex_str, 16)
                {
                    // Valid hex escape - decode it
                    result.push(byte as char);
                    continue;
                }
                // Invalid hex escape - keep original
                result.push('\\');
                result.push('x');
                result.push_str(&hex_str);
            } else {
                // Other escape sequence - keep it
                result.push(ch);
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// Normalize a regex pattern by stripping anchors (^ and $)
pub(super) fn normalize_regex(pattern: &str) -> String {
    let mut normalized = pattern.to_string();
    if normalized.starts_with('^') {
        normalized = normalized[1..].to_string();
    }
    if normalized.ends_with('$') && !normalized.ends_with("\\$") {
        normalized.truncate(normalized.len() - 1);
    }
    normalized
}

/// Canonicalize a regex into a stable string derived from its parsed HIR, so
/// that two patterns describing the same language collapse to one key even when
/// written differently: `[0-9]{3}` and `\d{3}` both become `[0-9]{3}`, and
/// `gr[ae]y` and `gr[ea]y` both sort their class to `gr[ae]y`. The HIR
/// representation merges adjacent literals and stores classes as sorted,
/// non-overlapping ranges, so its `Display` is a normal form.
///
/// Unicode mode is disabled so the ASCII shorthands (`\d`, `\w`, `\s`) fold to
/// their byte-class equivalents — matching how trait regexes scan extracted
/// bytes — and `utf8(false)` lets those byte classes parse without requiring
/// valid-UTF-8 boundaries (we only want the structural form, never a matcher).
///
/// Returns `None` for fragments that do not parse as a standalone regex (e.g. a
/// single branch carved out of a larger group), letting callers fall back to
/// textual normalization.
///
/// The form depends on the pattern alone, so a full validation keeps it across
/// runs (see `facts_cache`): parsing every regex and branch again cost ~0.7
/// CPU-s of each warm run.
pub(super) fn canonical_regex_form(pattern: &str) -> Option<String> {
    super::super::facts_cache::fact("regex-canonical", pattern, || {
        let hir = regex_syntax::ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build()
            .parse(pattern)
            .ok()?;
        Some(hir.to_string())
    })
}

/// If `pattern` is a regex that contains no actual regex metacharacters
/// (only literal text plus simple `\<punct>` escapes), return the substr-
/// equivalent literal. Otherwise return `None`.
///
/// This makes a regex like `\.aws/credentials` compare equal to the substr
/// `.aws/credentials` during duplicate detection — the two match identical
/// byte sequences, so they are semantic duplicates regardless of `match_type`.
///
/// Returns `None` for any pattern containing real metacharacters (`.`, `*`,
/// `+`, `?`, `|`, `(`, `)`, `[`, `]`, `{`, `}`) or regex shorthand escapes
/// (`\w`, `\d`, `\s`, `\b`, `\B`, `\A`, `\Z`, `\n`, `\t`, `\r`, `\x..`,
/// `\u{..}`). Anchors (`^`, `$`) at start/end are assumed already stripped
/// by `normalize_regex`.
pub(in super::super) fn extract_pure_literal_from_regex(pattern: &str) -> Option<String> {
    let mut result = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let Some(&next) = chars.peek() else {
                    // Trailing backslash — not a clean literal.
                    return None;
                };
                // Accept escape sequences whose only effect is to suppress a
                // regex metacharacter so it matches itself. Reject regex
                // shorthand classes (`\w`, `\d`, …) because those are not
                // expressible as a substr.
                match next {
                    '.' | '/' | '-' | '_' | '\\' | '"' | '\'' | ':' | ',' | '=' | '@' | '#'
                    | '~' | ' ' | '|' | '(' | ')' | '[' | ']' | '{' | '}' | '?' | '*' | '+'
                    | '^' | '$' | '<' | '>' | '!' | '%' | '&' | ';' | '`' => {
                        result.push(next);
                        chars.next();
                    }
                    _ => return None,
                }
            }
            // Real regex metacharacters mean the pattern is not purely literal.
            '.' | '*' | '+' | '?' | '|' | '(' | ')' | '[' | ']' | '{' | '}' => {
                return None;
            }
            // Anchors at non-edge positions are real regex syntax.
            '^' | '$' => return None,
            other => result.push(other),
        }
    }
    Some(result)
}

/// Normalize pattern for duplicate detection
/// - Decode hex escapes: \x27 → '
/// - For regex: strip anchors, then decode purely-literal regexes (e.g.
///   `\.aws/credentials`) to their substr-equivalent so they compare equal
///   to substr matches of the same content.
pub(in super::super) fn normalize_pattern_for_comparison(pattern: &str, is_regex: bool) -> String {
    let mut normalized = decode_hex_escapes(pattern);

    if is_regex {
        normalized = normalize_regex(&normalized);
        if let Some(literal) = extract_pure_literal_from_regex(&normalized) {
            return literal;
        }
    }

    normalized
}

/// Extract all searchable patterns from a trait definition
/// Returns: Vec<(normalized_value, PatternLocation)>
pub(super) fn symbol_argument_discriminator(
    arg: Option<&crate::composite_rules::condition::ArgFilter>,
    args: Option<&[crate::composite_rules::condition::ArgFilter]>,
) -> String {
    fn serialize<T: serde::Serialize + std::fmt::Debug>(value: &T) -> String {
        serde_json::to_string(value).unwrap_or_else(|_| format!("{value:?}"))
    }

    // Preserve the whole predicate, including positions and provenance. A
    // first-literal shortcut collapses distinct body/header and source rules.
    let mut key = String::new();
    if let Some(arg) = arg {
        key.push_str("#arg:");
        key.push_str(&serialize(arg));
    }
    if let Some(args) = args.filter(|args| !args.is_empty()) {
        let mut predicates: Vec<_> = args.iter().map(serialize).collect();
        // `args` is a conjunction over distinct positions, not an ordered
        // sequence. Keep multiplicity, but ignore YAML list ordering.
        predicates.sort();
        key.push_str("#args:");
        key.push_str(&serialize(&predicates));
    }
    key
}

/// Whether a symbol discriminator changes which fact the literal names, rather
/// than only which syntactic position it was found in.
pub(super) fn discriminator_narrows_the_fact(discriminator: &str) -> bool {
    // `kind: export`/`forward` reverse the direction of the relationship: the
    // file *provides* the API instead of calling it. A Wine or ReactOS
    // reimplementation of kernel32 exports `VirtualAllocEx` precisely because
    // it is the provider, which is the opposite of the malware that imports it
    // — see metadata/binary/vendor/wine.yaml, where that direction is the whole
    // point of the trait. Treating those as one fact read twice would invite an
    // author to collapse a discriminator into the thing it discriminates.
    [
        "#arg:",
        "#args:",
        "#alias:",
        // Defining a function is not calling or merely mentioning its name.
        // Shell shadowing guards rely on exactly this distinction.
        "#kind:Function",
        "#kind:Export",
        "#kind:Forward",
    ]
    .iter()
    .any(|marker| discriminator.contains(marker))
}

/// Every trait's searchable patterns as `(normalized value, location)`, in
/// trait order: extracted once for all the checks that compare patterns,
/// rather than once by each of them.
pub(crate) struct ExtractedPatterns(pub(super) Vec<(String, PatternLocation)>);

impl ExtractedPatterns {
    pub(crate) fn of(trait_definitions: &[TraitDefinition]) -> Self {
        use rayon::prelude::*;

        Self(
            trait_definitions
                .par_iter()
                .flat_map_iter(extract_patterns)
                .collect(),
        )
    }
}

pub(super) fn extract_patterns(trait_def: &TraitDefinition) -> Vec<(String, PatternLocation)> {
    let mut patterns = Vec::new();

    let for_types: HashSet<String> = trait_def
        .r#for
        .iter()
        .map(|ft| ft.label().to_string())
        .collect();

    let file_path = trait_def.defined_in.to_string_lossy().to_string();

    // `unless:` legs that name another trait. A trait carrying one is scoped to
    // "this pattern, except where that trait already explains it", which is a
    // different question from the same pattern unscoped.
    let suppressed_by: Vec<String> = trait_def
        .unless
        .iter()
        .flatten()
        .flat_map(|cond| cond.trait_references().iter().cloned())
        .collect();

    // Helper to add a pattern
    let mut add_pattern = |condition_type: &str,
                           match_type: &str,
                           value: String,
                           discriminator: &str,
                           section: Option<String>,
                           encoding: Option<Vec<String>>| {
        let is_regex = match_type == "regex";
        let keyed = format!("{value}{discriminator}");
        let plain_normalized = normalize_pattern_for_comparison(&value, is_regex);
        let normalized = format!("{plain_normalized}{discriminator}");
        // Reference/call kinds may be dropped when comparing search surfaces.
        // Definition/export kinds instead identify a provider, not a use.
        // Arguments and aliases also change the fact: require('fs') is not
        // require('dns'). Keep these discriminators when comparing with a
        // bare token on another surface.
        let bare_normalized =
            if discriminator.is_empty() || discriminator_narrows_the_fact(discriminator) {
                normalized.clone()
            } else {
                normalize_pattern_for_comparison(&value, is_regex)
            };
        if is_non_reusable_atom(condition_type, match_type, &normalized) {
            return;
        }
        // If the regex contained only literal text (after stripping anchors
        // and decoding `\<punct>` escapes), `normalize_pattern_for_comparison`
        // returned the substr-equivalent literal. Treat the trait as if it
        // were authored as a substr match so cross-matcher duplicates are
        // surfaced by `matcher_context_reusable_as_is`.
        let effective_match_type = if is_regex && plain_normalized != normalize_regex(&value) {
            "substr"
        } else {
            match_type
        };

        patterns.push((
            normalized,
            PatternLocation {
                trait_id: trait_def.id.clone(),
                file_path: file_path.clone(),
                condition_type: condition_type.to_string(),
                match_type: effective_match_type.to_string(),
                encoding,
                original_value: keyed,
                discriminator: discriminator.to_owned(),
                bare_normalized,
                suppressed_by: suppressed_by.clone(),
                for_types: for_types.clone(),
                section,
                count_min: trait_def.count_min,
                count_max: trait_def.count_max,
                per_kb_min: trait_def.per_kb_min,
                per_kb_max: trait_def.per_kb_max,
                confidence: trait_def.conf,
                criticality: trait_def.crit,
            },
        ));
    };

    // Extract patterns from all string-pattern condition variants. Callers
    // can filter on `condition_type` after extraction if they need to scope
    // their check to a subset of types.
    match &trait_def.r#if {
        Condition::Symbol(SymbolQuery {
            exact,
            substr,
            regex,
            arg,
            args,
            kind,
            alias,
            ..
        }) => {
            // The symbol `kind` discriminates the fact being matched: a call to
            // `exec` (`kind: call`) is a different atom from a function *named*
            // `exec` (`kind: function`) — they match distinct symbol facts. Fold
            // it into the pattern key, alongside the `arg:` discriminator below,
            // so the dedup checker doesn't collapse a call and a definition into
            // one "reusable atom".
            let kind_disc = kind
                .as_ref()
                .map(|k| format!("#kind:{k:?}"))
                .unwrap_or_default();
            // A call's `arg:` discriminator makes same-named calls distinct
            // atoms — `require('fs')` ≠ `require('dns')`. Fold it into the
            // pattern key so the dedup checker doesn't collapse them into one
            // "reusable atom". (Same name AND same arg still collide.)
            let disc = {
                let arg_disc = symbol_argument_discriminator(arg.as_ref(), args.as_deref());
                // An `alias:` filter narrows to *aliased* imports
                // (`import base64 as x`) — a different atom from the plain
                // import (`import base64`). Fold its presence/value in so the
                // aliased and plain forms aren't collapsed.
                let alias_disc = alias
                    .as_ref()
                    .map(|a| {
                        let v = a
                            .exact
                            .as_deref()
                            .or(a.substr.as_deref())
                            .or(a.regex.as_deref())
                            .unwrap_or("*");
                        format!("#alias:{v}")
                    })
                    .unwrap_or_default();
                format!("{kind_disc}{arg_disc}{alias_disc}")
            };
            if let Some(v) = exact {
                add_pattern("symbol", "exact", v.clone(), &disc, None, None);
            }
            if let Some(v) = substr {
                add_pattern("symbol", "substr", v.clone(), &disc, None, None);
            }
            if let Some(v) = regex {
                add_pattern("symbol", "regex", v.clone(), &disc, None, None);
            }
        }
        Condition::Raw(RawQuery {
            exact,
            substr,
            word,
            regex,
            section,
            ..
        }) => {
            let sec = section.clone();
            if let Some(v) = exact {
                add_pattern("raw", "exact", v.clone(), "", sec.clone(), None);
            }
            if let Some(v) = substr {
                add_pattern("raw", "substr", v.clone(), "", sec.clone(), None);
            }
            if let Some(v) = word {
                add_pattern("raw", "word", v.clone(), "", sec.clone(), None);
            }
            if let Some(v) = regex {
                add_pattern("raw", "regex", v.clone(), "", sec.clone(), None);
            }
        }
        Condition::Text(TextQuery {
            exact,
            substr,
            word,
            regex,
            section,
            ..
        }) => {
            let sec = section.clone();
            if let Some(v) = exact {
                add_pattern("text", "exact", v.clone(), "", sec.clone(), None);
            }
            if let Some(v) = substr {
                add_pattern("text", "substr", v.clone(), "", sec.clone(), None);
            }
            if let Some(v) = word {
                add_pattern("text", "word", v.clone(), "", sec.clone(), None);
            }
            if let Some(v) = regex {
                add_pattern("text", "regex", v.clone(), "", sec.clone(), None);
            }
        }
        Condition::Literal(LiteralQuery {
            exact,
            substr,
            word,
            regex,
            section,
            ..
        }) => {
            let sec = section.clone();
            if let Some(v) = exact {
                add_pattern("string_literal", "exact", v.clone(), "", sec.clone(), None);
            }
            if let Some(v) = substr {
                add_pattern("string_literal", "substr", v.clone(), "", sec.clone(), None);
            }
            if let Some(v) = word {
                add_pattern("string_literal", "word", v.clone(), "", sec.clone(), None);
            }
            if let Some(v) = regex {
                add_pattern("string_literal", "regex", v.clone(), "", sec.clone(), None);
            }
        }
        Condition::Path(PathQuery {
            exact,
            substr,
            regex,
            ..
        }) => {
            if let Some(v) = exact {
                add_pattern("basename", "exact", v.clone(), "", None, None);
            }
            if let Some(v) = substr {
                add_pattern("basename", "substr", v.clone(), "", None, None);
            }
            if let Some(v) = regex {
                add_pattern("basename", "regex", v.clone(), "", None, None);
            }
        }
        Condition::Encoded(EncodedQuery {
            exact,
            substr,
            word,
            regex,
            section,
            encoding,
            ..
        }) => {
            let sec = section.clone();
            let enc = canonical_encoding_scope(encoding);
            if let Some(v) = exact {
                add_pattern("encoded", "exact", v.clone(), "", sec.clone(), enc.clone());
            }
            if let Some(v) = substr {
                add_pattern("encoded", "substr", v.clone(), "", sec.clone(), enc.clone());
            }
            if let Some(v) = word {
                add_pattern("encoded", "word", v.clone(), "", sec.clone(), enc.clone());
            }
            if let Some(v) = regex {
                add_pattern("encoded", "regex", v.clone(), "", sec.clone(), enc.clone());
            }
        }
        _ => {} // Skip Yara, Hex, Trait, Syscall, Metrics, Section, Kv, Ast.
    }

    patterns
}
