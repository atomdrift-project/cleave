//! Condition accessors, load-time validation and regex compilation.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

impl Condition {
    /// Returns true if this condition is a trait reference
    #[must_use]
    pub(crate) fn is_trait_reference(&self) -> bool {
        matches!(self, Condition::Trait { .. })
    }

    /// Check if this condition can possibly match for a given file type.
    /// Returns false for conditions that require binary section analysis
    /// when evaluating source/text files.
    #[must_use]
    pub(crate) fn can_match_file_type(&self, file_type: &super::super::FileType) -> bool {
        use super::super::FileType;

        // Binary section analysis requires PE/ELF/Mach-O format
        let is_binary = matches!(file_type, FileType::Elf | FileType::Macho | FileType::Pe);

        match self {
            // Section analysis and syscalls are binary-only. Filefacts
            // resolves syscalls from raw `syscall`/`svc` sites on
            // PE/ELF/Mach-O; source members never populate `report.syscalls`.
            Condition::Section(SectionQuery { .. }) | Condition::Syscall { .. } => is_binary,

            // AST-backed searches require source code support. `type: literal`
            // does not: format parsers also emit literals (compiled AppleScript
            // among them), so it falls through to the permissive wildcard.
            Condition::TreeSitter(TreeSitterQuery { .. }) => file_type.supports_ast_queries(),

            // `section:` / `section_offset:` need a PE/ELF/Mach-O section
            // map. On `uses_raw_text_search` files the map is empty, so
            // `eval_raw` already returns no_match — drop them before
            // `eval_trait`. File-absolute `offset:` / `offset_range:` still
            // apply (they clip `binary_data`).
            Condition::Text(TextQuery {
                section,
                section_offset,
                section_offset_range,
                ..
            })
            | Condition::Raw(RawQuery {
                section,
                section_offset,
                section_offset_range,
                ..
            })
            | Condition::Hex(HexQuery {
                section,
                section_offset,
                section_offset_range,
                ..
            }) => {
                let needs_sections =
                    section.is_some() || section_offset.is_some() || section_offset_range.is_some();
                !needs_sections || !file_type.uses_raw_text_search()
            }

            // All other conditions can potentially match any file type
            _ => true,
        }
    }

    /// Returns a description of the condition type for error messages
    #[must_use]
    pub(crate) fn type_name(&self) -> &'static str {
        match self {
            Condition::Symbol(SymbolQuery { .. }) => "symbol",
            Condition::Text(TextQuery { .. }) => "text",
            Condition::Comment(CommentQuery { .. }) => "comment",
            Condition::Literal(LiteralQuery { .. }) => "literal",
            Condition::Trait { .. } => "trait",
            Condition::TreeSitter(TreeSitterQuery { .. }) => "tree-sitter",
            Condition::Yara { .. } => "yara",
            Condition::Syscall { .. } => "syscall",
            Condition::Metrics(MetricsQuery { .. }) => "metrics",
            Condition::Hex(HexQuery { .. }) => "hex",
            Condition::Raw(RawQuery { .. }) => "raw",
            Condition::Section(SectionQuery { .. }) => "section",
            Condition::Encoded(EncodedQuery { .. }) => "encoded",
            Condition::Path(PathQuery {
                basename, dirname, ..
            }) => {
                if *basename {
                    "basename"
                } else if *dirname {
                    "dirname"
                } else {
                    "path"
                }
            }
            Condition::Kv(KvQuery { .. }) => "value",
        }
    }

    /// Validate that a condition is structurally well-formed and that its
    /// inline YARA source compiles. Called at load time to catch authoring
    /// errors early.
    ///
    /// Tree-sitter `query:` compilation is *not* checked here — that needs the
    /// owning rule's `for:` list to know which grammars apply, so it lives in
    /// the `ast-query-compile` validator.
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Condition::Symbol(query) => {
                if matches!(query.kind, Some(SymbolKind::Bind)) {
                    if query.args.is_some() {
                        anyhow::bail!("bind accepts only one arg.kind shape filter");
                    }
                    if let Some(arg) = &query.arg
                        && (!matches!(
                            arg.kind.as_deref(),
                            Some(
                                "string"
                                    | "number"
                                    | "bool"
                                    | "null"
                                    | "identifier"
                                    | "object"
                                    | "array"
                                    | "function"
                                    | "template"
                                    | "call"
                                    | "expression"
                            )
                        ) || arg.index.is_some()
                            || arg.from.is_some()
                            || arg.value.is_some()
                            || arg.radix.is_some()
                            || arg.substr.is_some()
                            || arg.exact.is_some()
                            || arg.regex.is_some()
                            || arg.name.is_some()
                            || arg.name_regex.is_some())
                    {
                        anyhow::bail!(
                            "bind accepts only arg.kind to select the assigned expression shape"
                        );
                    }
                }
                for arg in query.arg.iter().chain(query.args.iter().flatten()) {
                    if let Some(pattern) = &arg.name_regex {
                        if !matches!(query.kind, Some(SymbolKind::Call)) {
                            anyhow::bail!("identifier-name argument regex requires kind: call");
                        }
                        if let Some(error) = regex_compile_error(pattern) {
                            anyhow::bail!("invalid identifier-name regex: {error}");
                        }
                    }
                    if (arg.index.is_some() || arg.from.is_some())
                        && !matches!(query.kind, Some(SymbolKind::Call))
                    {
                        return Err(anyhow::anyhow!(
                            "argument positions/provenance require kind: call"
                        ));
                    }
                    if let Some(origin) = &arg.from {
                        validate_origin(origin)?;
                    }
                }
                if (query.module_level || query.receiver.is_some())
                    && !matches!(query.kind, Some(SymbolKind::Call))
                {
                    anyhow::bail!("module_level/receiver require kind: call");
                }
                if let Some(receiver) = &query.receiver {
                    validate_origin(&receiver.from)?;
                }
                Ok(())
            }
            Condition::Yara { source, .. } => {
                // Only validate syntax - add_source catches parse errors
                // Don't call build() here as it triggers expensive JIT compilation.
                // The verdict depends on the source alone, so a full validation
                // keeps it across runs (see `facts_cache`).
                let parse_error = || {
                    yara_x::Compiler::new()
                        .add_source(source.as_bytes())
                        .err()
                        .map(|e| e.to_string())
                };
                if let Some(e) = cached_fact("yara-parse", source, parse_error) {
                    anyhow::bail!("invalid YARA rule: {e}");
                }
                Ok(())
            }
            Condition::TreeSitter(TreeSitterQuery {
                kind,
                node,
                exact,
                substr,
                regex,
                query,
                ..
            }) => {
                // Validate mode: either (kind/node + exact/substr/regex) or query, not both
                let has_simple_mode = kind.is_some() || node.is_some();
                let has_pattern = exact.is_some() || substr.is_some() || regex.is_some();
                let has_query = query.is_some();

                if has_query && has_simple_mode {
                    return Err(anyhow::anyhow!(
                        "tree-sitter condition cannot have both 'query' and 'kind'/'node'"
                    ));
                }

                if !has_query && !has_simple_mode {
                    return Err(anyhow::anyhow!(
                        "tree-sitter condition must have either 'kind'/'node' or 'query'"
                    ));
                }

                if has_simple_mode && !has_pattern {
                    return Err(anyhow::anyhow!(
                        "tree-sitter condition with 'kind'/'node' must have 'exact', 'substr', or 'regex'"
                    ));
                }

                if kind.is_some() && node.is_some() {
                    return Err(anyhow::anyhow!(
                        "tree-sitter condition cannot have both 'kind' and 'node'"
                    ));
                }

                if exact.is_some() && regex.is_some() {
                    return Err(anyhow::anyhow!(
                        "tree-sitter condition cannot have both 'exact' and 'regex'"
                    ));
                }

                // Query compilation is checked by the `ast-query-compile`
                // validator, which knows the rule's `for:` list and so can pick
                // the grammars to compile against even when `language:` is
                // absent. Doing it here too would double-report.
                Ok(())
            }
            Condition::Kv(KvQuery {
                path,
                exact,
                substr,
                regex,
                ..
            }) => {
                // Path must not be empty
                if path.is_empty() {
                    return Err(anyhow::anyhow!("value condition requires non-empty path"));
                }

                // At most one matcher
                let matchers = [exact.is_some(), substr.is_some(), regex.is_some()];
                if matchers.iter().filter(|&&b| b).count() > 1 {
                    return Err(anyhow::anyhow!(
                        "value condition can only have one of: is, substr, regex"
                    ));
                }

                // Validate regex compiles
                if let Some(e) = regex.as_deref().and_then(regex_compile_error) {
                    anyhow::bail!("invalid regex in value condition: {e}");
                }

                Ok(())
            }
            // Validate location constraints for string/content conditions
            Condition::Text(TextQuery {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            }) => validate_location_constraints(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
                "text",
            ),
            Condition::Literal(LiteralQuery {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            }) => validate_location_constraints(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
                "string_literal",
            ),
            Condition::Raw(RawQuery {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            }) => validate_location_constraints(
                section,
                *offset,
                *offset_range,
                *section_offset,
                *section_offset_range,
                "content",
            ),
            Condition::Hex(HexQuery {
                section,
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                ..
            }) => {
                // Validate location constraints
                validate_location_constraints(
                    section,
                    *offset,
                    *offset_range,
                    *section_offset,
                    *section_offset_range,
                    "hex",
                )
            }
            // Other conditions don't need compilation validation
            _ => Ok(()),
        }
    }

    /// Pre-compile YARA rules for faster evaluation.
    /// Used for unless/composite conditions that are not in the combined engine.
    pub(crate) fn compile_yara(&mut self) {
        if let Condition::Yara {
            source, compiled, ..
        } = self
            && compiled.is_none()
        {
            let mut compiler = yara_x::Compiler::new();
            compiler.new_namespace("inline");
            if compiler.add_source(source.as_bytes()).is_ok() {
                *compiled = Some(Arc::new(compiler.build()));
            }
        }
    }

    /// Check for regex patterns that can cause catastrophic backtracking.
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_greedy_patterns(&self) -> Option<String> {
        let regex_to_check = match self {
            Condition::Text(TextQuery { regex: Some(r), .. })
            | Condition::Raw(RawQuery { regex: Some(r), .. })
            | Condition::TreeSitter(TreeSitterQuery { regex: Some(r), .. }) => Some(r.as_str()),
            _ => None,
        };

        if let Some(regex) = regex_to_check
            && let Some(issue) = find_backtrack_issue(regex)
        {
            return Some(format!(
                "{} - use bounded pattern like .{{0,50}} instead: {}",
                issue, regex
            ));
        }
        None
    }

    /// Check for regex patterns that are just `\bWORD\b` which should use `type: word` instead.
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_word_boundary_regex(&self) -> Option<String> {
        let regex_to_check = match self {
            Condition::Text(TextQuery { regex: Some(r), .. })
            | Condition::Literal(LiteralQuery { regex: Some(r), .. })
            | Condition::Raw(RawQuery { regex: Some(r), .. }) => Some(r.as_str()),
            _ => None,
        };

        if let Some(regex) = regex_to_check {
            // Check for patterns like \bWORD\b (after YAML parsing, \\b becomes \b)
            // Also handle wrapped patterns like (?:(?:\bWORD\b)) from normalization
            let pattern = regex.trim();
            let unwrapped = pattern
                .strip_prefix("(?:")
                .and_then(|s| s.strip_suffix(")"))
                .map(|s| {
                    s.strip_prefix("(?:")
                        .and_then(|s| s.strip_suffix(")"))
                        .unwrap_or(s)
                })
                .unwrap_or(pattern);

            if unwrapped.starts_with(r"\b") && unwrapped.ends_with(r"\b") && unwrapped.len() > 4 {
                // Extract the word between boundaries
                let word = &unwrapped[2..unwrapped.len() - 2];

                // Check if it's a simple alphanumeric word (no regex metacharacters)
                if !word.is_empty()
                    && word
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
                {
                    return Some(format!(
                        "regex is a simple word boundary pattern - use 'word: \"{}\"' instead",
                        word
                    ));
                }
            }
        }
        None
    }

    /// Check for short case-insensitive patterns that have high collision risk.
    /// Rules:
    /// - 3 or less characters (alphabetic only): always warn
    /// - 4 characters (alphabetic only): only warn if applies to more than 2 file types
    ///
    ///   Mixed alphanumeric strings (like "x509") are exempt - they have fewer variants
    ///   Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_short_case_insensitive(&self, file_type_count: usize) -> Option<String> {
        let check_pattern = |s: &str| -> Option<String> {
            let len = s.len();
            // Only check strings that are entirely alphabetic
            // Mixed alphanumeric like "x509" have fewer collision variants
            if !s.chars().all(char::is_alphabetic) {
                return None;
            }

            if len <= 3 {
                return Some(format!(
                    "case-insensitive match on very short alphabetic string '{}' ({} chars) - high collision risk, use case-sensitive or longer pattern",
                    s, len
                ));
            } else if len == 4 && file_type_count > 2 {
                return Some(format!(
                    "case-insensitive match on short alphabetic string '{}' (4 chars) applies to {} file types - high collision risk, limit to 1-2 types or use case-sensitive",
                    s, file_type_count
                ));
            }
            None
        };

        match self {
            Condition::Text(TextQuery {
                exact: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Literal(LiteralQuery {
                exact: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Raw(RawQuery {
                exact: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::TreeSitter(TreeSitterQuery {
                exact: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Text(TextQuery {
                substr: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Literal(LiteralQuery {
                substr: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Raw(RawQuery {
                substr: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::TreeSitter(TreeSitterQuery {
                substr: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Text(TextQuery {
                word: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Literal(LiteralQuery {
                word: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Raw(RawQuery {
                word: Some(s),
                case_insensitive: true,
                ..
            }) => check_pattern(s),
            _ => None,
        }
    }

    /// Check if count constraints are valid (count_max >= count_min).
    /// Returns a warning message if invalid, None otherwise.
    #[must_use]
    pub(crate) fn check_count_constraints(&self) -> Option<String> {
        // Count constraints are now at trait level (ConditionWithFilters), not per-condition
        None
    }

    /// Check if per-KB density constraints are valid (per_kb_max >= per_kb_min).
    /// Returns a warning message if invalid, None otherwise.
    #[must_use]
    pub(crate) fn check_density_constraints(&self) -> Option<String> {
        // Density constraints are now at trait level (ConditionWithFilters), not per-condition
        None
    }

    /// Check for empty or whitespace-only pattern strings (common LLM mistake).
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_empty_patterns(&self) -> Option<String> {
        let check_empty = |s: &str, field: &str| -> Option<String> {
            if s.trim().is_empty() {
                return Some(format!(
                    "{}: pattern is empty or whitespace-only - specify a non-empty pattern",
                    field
                ));
            }
            None
        };

        match self {
            Condition::Text(TextQuery { exact: Some(s), .. })
            | Condition::Literal(LiteralQuery { exact: Some(s), .. })
            | Condition::Raw(RawQuery { exact: Some(s), .. })
            | Condition::Symbol(SymbolQuery { exact: Some(s), .. }) => check_empty(s, "exact"),
            Condition::Text(TextQuery {
                substr: Some(s), ..
            })
            | Condition::Literal(LiteralQuery {
                substr: Some(s), ..
            })
            | Condition::Raw(RawQuery {
                substr: Some(s), ..
            })
            | Condition::Symbol(SymbolQuery {
                substr: Some(s), ..
            }) => check_empty(s, "substr"),
            Condition::Text(TextQuery { regex: Some(s), .. })
            | Condition::Literal(LiteralQuery { regex: Some(s), .. })
            | Condition::Raw(RawQuery { regex: Some(s), .. })
            | Condition::Symbol(SymbolQuery { regex: Some(s), .. }) => check_empty(s, "regex"),
            Condition::Text(TextQuery { word: Some(s), .. })
            | Condition::Literal(LiteralQuery { word: Some(s), .. })
            | Condition::Raw(RawQuery { word: Some(s), .. }) => check_empty(s, "word"),
            _ => None,
        }
    }

    /// Check for overly short patterns that will match too broadly (common LLM mistake).
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_short_patterns(&self) -> Option<String> {
        let check_short = |s: &str, field: &str, min_len: usize| -> Option<String> {
            if s.len() < min_len {
                return Some(format!(
                    "{}: pattern '{}' is very short ({} chars) and may match too broadly - consider using a longer, more specific pattern",
                    field,
                    s,
                    s.len()
                ));
            }
            None
        };

        match self {
            // For exact matches, warn if less than 2 characters
            Condition::Text(TextQuery {
                exact: Some(s),
                case_insensitive: false,
                ..
            })
            | Condition::Literal(LiteralQuery {
                exact: Some(s),
                case_insensitive: false,
                ..
            })
            | Condition::Symbol(SymbolQuery { exact: Some(s), .. }) => {
                if s.len() == 1 {
                    return Some(format!(
                        "exact: pattern '{}' is a single character and will rarely be useful - consider if this is intentional",
                        s
                    ));
                }
                None
            }
            // For substr, warn if less than 3 characters (more prone to false positives)
            Condition::Text(TextQuery {
                substr: Some(s),
                case_insensitive: false,
                ..
            })
            | Condition::Literal(LiteralQuery {
                substr: Some(s),
                case_insensitive: false,
                ..
            })
            | Condition::Symbol(SymbolQuery {
                substr: Some(s), ..
            }) => check_short(s, "substr", 3),
            // For word, warn if less than 2 characters
            Condition::Text(TextQuery {
                word: Some(s),
                case_insensitive: false,
                ..
            })
            | Condition::Literal(LiteralQuery {
                word: Some(s),
                case_insensitive: false,
                ..
            }) => check_short(s, "word", 2),
            _ => None,
        }
    }

    /// Check for regex patterns that are just literal strings (should use substr/exact instead).
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_literal_regex(&self) -> Option<String> {
        let is_literal = |s: &str| -> bool {
            // Check if string contains any regex metacharacters
            !s.chars().any(|c| {
                matches!(
                    c,
                    '.' | '*'
                        | '+'
                        | '?'
                        | '^'
                        | '$'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '|'
                        | '\\'
                )
            })
        };

        match self {
            Condition::Text(TextQuery { regex: Some(r), .. })
            | Condition::Literal(LiteralQuery { regex: Some(r), .. })
            | Condition::Raw(RawQuery { regex: Some(r), .. })
            | Condition::Symbol(SymbolQuery { regex: Some(r), .. }) => {
                if is_literal(r) {
                    return Some(format!(
                        "regex: pattern '{}' is a literal string with no regex metacharacters - use 'substr' instead for better performance",
                        r
                    ));
                }
                None
            }
            _ => None,
        }
    }

    /// Check if case_insensitive is used with patterns that have no letters.
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_case_insensitive_on_non_alpha(&self) -> Option<String> {
        let check_pattern = |s: &str, field: &str| -> Option<String> {
            if !s.chars().any(char::is_alphabetic) {
                return Some(format!(
                    "case_insensitive: true is set but {}: '{}' contains no letters - case_insensitive has no effect",
                    field, s
                ));
            }
            None
        };

        match self {
            Condition::Text(TextQuery {
                exact: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Literal(LiteralQuery {
                exact: Some(s),
                case_insensitive: true,
                ..
            }) => check_pattern(s, "exact"),
            Condition::Text(TextQuery {
                substr: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Literal(LiteralQuery {
                substr: Some(s),
                case_insensitive: true,
                ..
            }) => check_pattern(s, "substr"),
            Condition::Text(TextQuery {
                word: Some(s),
                case_insensitive: true,
                ..
            })
            | Condition::Literal(LiteralQuery {
                word: Some(s),
                case_insensitive: true,
                ..
            }) => check_pattern(s, "word"),
            _ => None,
        }
    }

    /// Check for symbol regex patterns that use word boundaries or whitespace.
    /// Symbols don't contain whitespace, so `\b` matches start/end of the symbol string,
    /// meaning `\bfoo\b` is equivalent to `exact: foo`. Whitespace in a symbol regex
    /// will never match anything.
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_symbol_regex_whitespace(&self) -> Option<String> {
        let regex = match self {
            Condition::Symbol(SymbolQuery { regex: Some(r), .. }) => r.as_str(),
            _ => return None,
        };

        // Check for literal whitespace characters (space, tab, \s, \t, etc.)
        // After YAML parsing, these appear as literal chars or escape sequences
        if regex.contains(' ') || regex.contains('\t') {
            return Some(format!(
                "symbol regex '{}' contains whitespace - symbols never contain whitespace, this pattern will never match",
                regex
            ));
        }
        if regex.contains(r"\s") || regex.contains(r"\t") {
            return Some(format!(
                "symbol regex '{}' contains whitespace class (\\s or \\t) - symbols never contain whitespace, this pattern will never match",
                regex
            ));
        }

        // Check for \b word boundary patterns
        if regex.contains(r"\b") {
            // Unwrap optional non-capturing groups from normalization
            let pattern = regex.trim();
            let unwrapped = pattern
                .strip_prefix("(?:")
                .and_then(|s| s.strip_suffix(")"))
                .map(|s| {
                    s.strip_prefix("(?:")
                        .and_then(|s2| s2.strip_suffix(")"))
                        .unwrap_or(s)
                })
                .unwrap_or(pattern);

            // If it's \bWORD\b with a simple word, suggest exact: instead
            if unwrapped.starts_with(r"\b") && unwrapped.ends_with(r"\b") && unwrapped.len() > 4 {
                let word = &unwrapped[2..unwrapped.len() - 2];
                if !word.is_empty()
                    && word
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
                {
                    return Some(format!(
                        "symbol regex '{}' uses word boundaries - symbols don't contain whitespace so \\b matches start/end of symbol, use 'exact: \"{}\"' instead",
                        regex, word
                    ));
                }
            }

            return Some(format!(
                "symbol regex '{}' uses word boundary (\\b) - symbols don't contain whitespace so \\b only matches start/end of symbol, consider using 'exact:' or 'substr:' instead",
                regex
            ));
        }

        None
    }

    /// Check for nonsensical count_min values.
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_count_min_value(&self) -> Option<String> {
        // count_min is now at trait level (ConditionWithFilters), not per-condition
        None
    }

    /// Check if mutually exclusive match types are used together.
    /// Returns a warning message if multiple are set, None otherwise.
    #[must_use]
    pub(crate) fn check_match_exclusivity(&self) -> Option<String> {
        let check_exclusive =
            |exact: bool, substr: bool, regex: bool, word: bool| -> Option<String> {
                let count = [exact, substr, regex, word].iter().filter(|&&x| x).count();
                if count > 1 {
                    let mut types = Vec::new();
                    if exact {
                        types.push("exact");
                    }
                    if substr {
                        types.push("substr");
                    }
                    if regex {
                        types.push("regex");
                    }
                    if word {
                        types.push("word");
                    }
                    return Some(format!(
                        "multiple mutually exclusive match types specified: {} - use only one",
                        types.join(", ")
                    ));
                }
                None
            };

        match self {
            Condition::Text(TextQuery {
                exact,
                substr,
                regex,
                word,
                ..
            })
            | Condition::Literal(LiteralQuery {
                exact,
                substr,
                regex,
                word,
                ..
            })
            | Condition::Raw(RawQuery {
                exact,
                substr,
                regex,
                word,
                ..
            }) => check_exclusive(
                exact.is_some(),
                substr.is_some(),
                regex.is_some(),
                word.is_some(),
            ),
            Condition::Symbol(SymbolQuery {
                exact,
                substr,
                regex,
                ..
            })
            | Condition::TreeSitter(TreeSitterQuery {
                exact,
                substr,
                regex,
                ..
            }) => check_exclusive(exact.is_some(), substr.is_some(), regex.is_some(), false),
            _ => None,
        }
    }

    /// Pre-compile regexes in this condition for performance.
    /// Should be called once after deserialization.
    /// Returns an error if any regex pattern is invalid.
    pub(crate) fn precompile_regexes(&mut self) -> anyhow::Result<()> {
        match self {
            Condition::Symbol(SymbolQuery {
                regex: Some(regex_pattern),
                ..
            }) => {
                // Validate only — the compiled regex is resolved lazily and shared
                // process-wide at eval time (see `cached_regex`), so it isn't stored
                // per condition. Compile here purely to surface invalid patterns.
                if let Some(e) = regex_compile_error(regex_pattern) {
                    anyhow::bail!("Failed to compile symbol regex '{}': {}", regex_pattern, e);
                }
            }
            // Text/Literal `word:`/`substr:`/`exact:` are literal matches and
            // `regex:` compiles lazily (shared) on first eval — see
            // `match_value_against_params` + `lazy_regex`/`word_match_start`. So
            // there is nothing to precompile here; eagerly building a
            // `regex::Regex` per condition (the old `\bword\b` etc.) was ~1.5 GB
            // of redundant meta-engine objects, mostly for literal `word:`.
            // Kept as an explicit, documented arm rather than folded into the
            // catch-all below.
            #[allow(clippy::match_same_arms)]
            Condition::Text(TextQuery { .. }) | Condition::Literal(LiteralQuery { .. }) => {}
            // Validate only (see Symbol arm). `(?i)` doesn't affect parse
            // validity, so the raw pattern is sufficient to catch errors; eval
            // applies case-insensitivity via `lazy_regex`.
            Condition::Kv(KvQuery {
                regex: Some(regex_pattern),
                ..
            }) => {
                if let Some(e) = regex_compile_error(regex_pattern) {
                    anyhow::bail!("Failed to compile value regex '{}': {}", regex_pattern, e);
                }
            }
            Condition::Path(PathQuery {
                regex: Some(regex_pattern),
                ..
            }) => {
                if let Some(e) = regex_compile_error(regex_pattern) {
                    anyhow::bail!(
                        "Failed to compile basename regex '{}': {}",
                        regex_pattern,
                        e
                    );
                }
            }
            _ => {}
        }

        // Substring (`substr:`) matching no longer precompiles a per-condition
        // `Finder`. Boyer-Moore preprocessing is shared process-wide and keyed by
        // needle via `condition::cached_finder` (case-sensitive) /
        // `cached_ci_searcher` (case-insensitive), built once on first eval and
        // reused — so identical needles cost once and only needles that fire cost
        // anything, instead of an owned `Finder` per condition (tens of thousands).
        Ok(())
    }
}

/// A verdict a full validation keeps across runs (see `facts_cache`); without
/// the linter there is no validation run to keep it for, so it is computed.
#[cfg(feature = "lint")]
use crate::capabilities::validation::facts_cache::fact as cached_fact;
#[cfg(not(feature = "lint"))]
pub(super) fn cached_fact<T>(_kind: &str, _input: &str, compute: impl FnOnce() -> T) -> T {
    compute()
}

/// Why `pattern` does not compile, in `regex::Regex::new`'s words, or `None`
/// when it does. Loading compiles only to validate -- `validate` and
/// `precompile_regexes` both ask, of the same patterns -- so during a full
/// validation the verdict is kept across runs (see `facts_cache`): an
/// unchanged pattern is not recompiled, by either.
pub(super) fn regex_compile_error(pattern: &str) -> Option<String> {
    cached_fact("regex-compile", pattern, || {
        regex::Regex::new(pattern).err().map(|e| e.to_string())
    })
}

/// Remove escaped literal `()` call markers from a symbol regex. Unescaped
/// parentheses retain their regex meaning and are intentionally untouched.
pub(super) fn normalize_legacy_call_regex(pattern: &mut String) {
    if pattern.contains(r"\(\)") {
        *pattern = pattern.replace(r"\(\)", "");
    }
}

/// Detect regex patterns that cause catastrophic backtracking.
///
/// Returns a short description of the first issue found, or None if the
/// pattern looks safe. Lazy quantifiers (.*?, .+?) and bounded repetitions
/// (.{0,50}) are accepted. Three classes of danger are detected:
///
/// - Unbounded wildcard:  `.*` or `.+`
/// - Negated char class:  `[^x]+` (matches almost anything, equivalent to `.+`)
/// - Nested quantifiers:  `(\w+)+` or `(.+)+` (exponential backtracking)
pub(super) fn find_backtrack_issue(regex: &str) -> Option<&'static str> {
    let chars: Vec<char> = regex.chars().collect();
    let len = chars.len();
    let mut i = 0;
    // Stack: each entry records whether the group contains a quantified subexpression.
    let mut group_stack: Vec<bool> = Vec::new();

    while i < len {
        match chars[i] {
            '\\' => {
                // Skip the escaped character entirely.
                i += 2;
            }
            '[' => {
                let negated = i + 1 < len && chars[i + 1] == '^';
                i += 1;
                while i < len && chars[i] != ']' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i += 1; // skip ']'
                if i < len && (chars[i] == '*' || chars[i] == '+') {
                    let lazy = i + 1 < len && chars[i + 1] == '?';
                    if !lazy {
                        if negated {
                            return Some("unbounded negated character class (e.g. [^x]+)");
                        }
                        if let Some(top) = group_stack.last_mut() {
                            *top = true;
                        }
                    }
                }
                // Let the next iteration handle the quantifier for group tracking.
            }
            '(' => {
                group_stack.push(false);
                i += 1;
            }
            ')' => {
                let had_inner = group_stack.pop().unwrap_or(false);
                i += 1;
                if i < len && (chars[i] == '*' || chars[i] == '+') {
                    let lazy = i + 1 < len && chars[i + 1] == '?';
                    if !lazy {
                        if had_inner {
                            return Some("nested quantifier (e.g. (\\w+)+ or (.+)+)");
                        }
                        // The group-as-a-whole is now quantified; tell the parent.
                        if let Some(parent) = group_stack.last_mut() {
                            *parent = true;
                        }
                    }
                } else if had_inner {
                    // No quantifier on this group, but it contained quantifiers.
                    // Propagate upward so patterns like ((\w+))+ are caught when
                    // the outer group eventually closes with a quantifier.
                    if let Some(parent) = group_stack.last_mut() {
                        *parent = true;
                    }
                }
            }
            '.' => {
                if i + 1 < len && (chars[i + 1] == '*' || chars[i + 1] == '+') {
                    let lazy = i + 2 < len && chars[i + 2] == '?';
                    if !lazy {
                        return Some("unbounded wildcard (.* or .+)");
                    }
                    // Lazy wildcard still counts as a quantified subexpression.
                    if let Some(top) = group_stack.last_mut() {
                        *top = true;
                    }
                    i += 3;
                    continue;
                }
                // Check for open-ended brace quantifier: .{n,} with no upper bound.
                if i + 1 < len && chars[i + 1] == '{' {
                    let start = i + 2;
                    let mut j = start;
                    while j < len && chars[j] != '}' {
                        j += 1;
                    }
                    if j < len {
                        let inner: String = chars[start..j].iter().collect();
                        // Open-ended: has a comma with nothing after it, e.g. "1," or "0,"
                        if inner.contains(',') && inner.ends_with(',') {
                            return Some(
                                "open-ended range quantifier (.{n,}) — use a bounded range like .{0,50} instead",
                            );
                        }
                    }
                }
                i += 1;
            }
            '*' | '+' => {
                // A bare quantifier on a plain character or escape sequence.
                let lazy = i + 1 < len && chars[i + 1] == '?';
                if !lazy && let Some(top) = group_stack.last_mut() {
                    *top = true;
                }
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    None
}

/// Validate location constraint parameters for consistency.
/// Returns an error if mutually exclusive constraints are specified.
pub(super) fn validate_location_constraints(
    section: &Option<String>,
    offset: Option<i64>,
    offset_range: Option<(i64, Option<i64>)>,
    section_offset: Option<i64>,
    section_offset_range: Option<(i64, Option<i64>)>,
    condition_type: &str,
) -> Result<()> {
    // offset and offset_range are mutually exclusive
    if offset.is_some() && offset_range.is_some() {
        return Err(anyhow::anyhow!(
            "{} condition cannot have both 'offset' and 'offset_range'",
            condition_type
        ));
    }

    // section_offset and section_offset_range are mutually exclusive
    if section_offset.is_some() && section_offset_range.is_some() {
        return Err(anyhow::anyhow!(
            "{} condition cannot have both 'section_offset' and 'section_offset_range'",
            condition_type
        ));
    }

    // section_offset/section_offset_range require section
    if section.is_none() && (section_offset.is_some() || section_offset_range.is_some()) {
        return Err(anyhow::anyhow!(
            "{} condition with 'section_offset' or 'section_offset_range' requires 'section'",
            condition_type
        ));
    }

    // Validate offset_range format
    if let Some((start, Some(e))) = offset_range
        && start >= 0
        && e >= 0
        && start > e
    {
        return Err(anyhow::anyhow!(
            "{} condition 'offset_range' start ({}) must be <= end ({})",
            condition_type,
            start,
            e
        ));
    }

    // Validate section_offset_range format
    if let Some((start, Some(e))) = section_offset_range
        && start >= 0
        && e >= 0
        && start > e
    {
        return Err(anyhow::anyhow!(
            "{} condition 'section_offset_range' start ({}) must be <= end ({})",
            condition_type,
            start,
            e
        ));
    }

    Ok(())
}

/// Structural checks shared by every provenance filter (`arg.from`,
/// `receiver.from`).
pub(super) fn validate_origin(origin: &FlowOriginFilter) -> Result<()> {
    let has_call = !origin.call.trim().is_empty();
    if usize::from(has_call)
        + usize::from(origin.value.is_some())
        + usize::from(origin.member.is_some())
        + usize::from(origin.whole_value.is_some())
        + usize::from(origin.whole_number.is_some())
        + usize::from(origin.field_exists)
        + usize::from(origin.field_absent)
        != 1
        || origin.member.as_ref().is_some_and(|p| p.trim().is_empty())
        || origin.through.len() > 32
    {
        return Err(anyhow::anyhow!(
            "provenance requires exactly one of call/value/member/whole_value/whole_number/field_exists/field_absent and at most 32 transfer models"
        ));
    }
    if (origin.field_exists || origin.field_absent)
        && (origin.field.as_ref().is_none_or(|s| s.trim().is_empty()) || !origin.through.is_empty())
    {
        anyhow::bail!("field presence/absence requires a nonempty field and no transfer models");
    }
    if (origin.whole_value.is_some() || origin.whole_number.is_some()) && !origin.through.is_empty()
    {
        anyhow::bail!("complete-value selection does not accept provenance transfer models");
    }
    if !has_call && (origin.literal.is_some() || origin.argument != 0) {
        return Err(anyhow::anyhow!(
            "literal/argument constraints require a source call"
        ));
    }
    for pattern in std::iter::once(&origin.call)
        .filter(|s| !s.is_empty())
        .chain(origin.value.iter())
        .chain(origin.whole_value.iter())
        .chain(origin.member.iter())
        .chain(origin.literal.iter())
        .chain(origin.through.iter().map(|m| &m.call))
    {
        if let Some(e) = regex_compile_error(pattern) {
            anyhow::bail!("invalid provenance regex: {e}");
        }
    }
    for model in &origin.through {
        if model.call.trim().is_empty()
            || model.arguments.len() > 32
            || model.arguments.is_empty() && !model.receiver
        {
            return Err(anyhow::anyhow!(
                "transfer model requires a call and contributing arguments or receiver"
            ));
        }
    }
    Ok(())
}
