//! Evaluation of atomic traits.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

impl TraitDefinition {
    /// Whether this rule was written without an `if:`: it tunes an
    /// engine-emitted finding of the same id (`unless:`, `downgrade:`) and
    /// never matches anything itself.
    pub(crate) fn is_override(&self) -> bool {
        matches!(&self.r#if, Condition::Trait { id } if id.is_empty())
    }

    /// Whether the rule's `exempt:` names `validator`.
    #[cfg(feature = "lint")]
    pub(crate) fn is_exempt(&self, validator: &str) -> bool {
        self.exempt.iter().any(|v| &**v == validator)
    }

    /// Pre-compile all regexes in this trait's conditions for performance.
    /// Returns an error if any regex pattern is invalid.
    pub(crate) fn precompile_regexes(&mut self) -> anyhow::Result<()> {
        self.r#if
            .precompile_regexes()
            .with_context(|| format!("in trait '{}' main condition", self.id))?;
        // Pre-compile not-exception patterns
        if let Some(ref mut exceptions) = self.not {
            for exc in exceptions.iter_mut() {
                exc.precompile();
            }
        }
        if let Some(ref mut conds) = self.unless {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes().with_context(|| {
                    format!("in trait '{}' unless condition #{}", self.id, idx + 1)
                })?;
            }
        }
        if let Some(ref mut downgrade) = self.downgrade {
            if let Some(ref mut any) = downgrade.any {
                for (idx, cond) in any.iter_mut().enumerate() {
                    cond.precompile_regexes().with_context(|| {
                        format!(
                            "in trait '{}' downgrade.any condition #{}",
                            self.id,
                            idx + 1
                        )
                    })?;
                }
            }
            if let Some(ref mut all) = downgrade.all {
                for (idx, cond) in all.iter_mut().enumerate() {
                    cond.precompile_regexes().with_context(|| {
                        format!(
                            "in trait '{}' downgrade.all condition #{}",
                            self.id,
                            idx + 1
                        )
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Register the combined-engine namespace for the top-level `if` condition.
    /// Sets `Condition::Yara { namespace }` to `"inline.{trait_id}"` so evaluation
    /// uses the pre-scanned combined engine results instead of re-compiling.
    /// Also compiles any `unless` YARA conditions independently (they are rare).
    pub(crate) fn set_yara_if_namespace(&mut self) {
        if let Condition::Yara { namespace, .. } = &mut self.r#if {
            *namespace = Some(format!("inline.{}", self.id));
        }
        // Still compile unless conditions the old way — they are rare and not in the combined engine
        if let Some(ref mut conds) = self.unless {
            for cond in conds.iter_mut() {
                cond.compile_yara();
            }
        }
    }

    /// Check if criticality level is valid for user-defined traits.
    /// Returns an error message if invalid, None otherwise.
    #[must_use]
    pub(crate) fn check_criticality(&self) -> Option<String> {
        use crate::types::Criticality;

        // Check if criticality is "Filtered" which is internal-only
        if self.crit == Criticality::Filtered {
            return Some(
                "crit: 'filtered' is an internal-only criticality level. Use one of: 'baseline' (informational), 'notable' (interesting behavior), 'suspicious' (potentially malicious), or 'hostile' (clearly malicious)".to_string()
            );
        }

        None
    }

    /// Check if confidence value is in valid range.
    /// Returns an error message if invalid, None otherwise.
    #[must_use]
    pub(crate) fn check_confidence(&self) -> Option<String> {
        if self.conf < 0.0 || self.conf > 1.0 {
            return Some(format!(
                "conf: {} is outside valid range [0.0, 1.0]",
                self.conf
            ));
        }
        None
    }

    /// Check if size constraints are valid.
    /// Returns an error message if invalid, None otherwise.
    #[must_use]
    pub(crate) fn check_size_constraints(&self) -> Option<String> {
        // Skip validation for Section conditions - they have their own size_min/size_max
        // for section sizes, which are separate from file size constraints
        if matches!(self.r#if, Condition::Section(SectionQuery { .. })) {
            return None;
        }

        if let (Some(min), Some(max)) = (self.size_min, self.size_max)
            && max < min
        {
            return Some(format!(
                "size_max ({}) cannot be less than size_min ({})",
                max, min
            ));
        }
        None
    }

    /// Check if entropy constraints are valid.
    /// Returns an error message if invalid, None otherwise.
    #[must_use]
    pub(crate) fn check_entropy_constraints(&self) -> Option<String> {
        // Validate entropy range (0.0-8.0)
        if let Some(min) = self.entropy_min
            && !(0.0..=8.0).contains(&min)
        {
            return Some(format!(
                "entropy_min ({:.2}) must be between 0.0 and 8.0",
                min
            ));
        }
        if let Some(max) = self.entropy_max
            && !(0.0..=8.0).contains(&max)
        {
            return Some(format!(
                "entropy_max ({:.2}) must be between 0.0 and 8.0",
                max
            ));
        }
        if let (Some(min), Some(max)) = (self.entropy_min, self.entropy_max)
            && max < min
        {
            return Some(format!(
                "entropy_max ({:.2}) cannot be less than entropy_min ({:.2})",
                max, min
            ));
        }
        None
    }

    /// Check if count constraints are valid.
    #[must_use]
    pub(crate) fn check_count_constraints(&self) -> Option<String> {
        if let (Some(min), Some(max)) = (self.count_min, self.count_max)
            && max < min
        {
            return Some(format!(
                "count_max ({}) is less than count_min ({})",
                max, min
            ));
        }
        self.r#if.check_count_constraints()
    }

    /// Check if density constraints are valid.
    #[must_use]
    pub(crate) fn check_density_constraints(&self) -> Option<String> {
        if let (Some(min), Some(max)) = (self.per_kb_min, self.per_kb_max)
            && max < min
        {
            return Some(format!(
                "per_kb_max ({}) is less than per_kb_min ({})",
                max, min
            ));
        }
        self.r#if.check_density_constraints()
    }

    /// Check for meaningless count_min: 0.
    #[must_use]
    pub(crate) fn check_count_min_value(&self) -> Option<String> {
        if let Some(0) = self.count_min {
            return Some("count_min: 0 is meaningless (default is 1)".to_string());
        }
        self.r#if.check_count_min_value()
    }

    /// Check for empty, too-short, or too-long descriptions.
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_description_quality(&self) -> Option<String> {
        let desc = self.desc.trim();

        if desc.is_empty() {
            return Some(
                "desc: field is empty. Write a clear, concise description of what this trait detects. Examples: 'XOR decryption loop' or 'Detects SSH key theft attempts'".to_string()
            );
        }

        if desc.len() < 5 {
            return Some(format!(
                "desc: '{}' is too short ({} chars). Write a clear description. Examples: 'JOIN command for IRC' or 'Detects IRC communication patterns'",
                desc,
                desc.len()
            ));
        }

        let desc_len = desc.chars().count();
        if desc_len > MAX_DESCRIPTION_CHARS {
            return Some(format!(
                "desc: '{}' is too long ({} chars). Keep descriptions at {} characters or less.",
                desc, desc_len, MAX_DESCRIPTION_CHARS
            ));
        }

        None
    }

    /// Check for empty not: arrays (common LLM mistake).
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_empty_not_array(&self) -> Option<String> {
        if let Some(not_exceptions) = &self.not
            && not_exceptions.is_empty()
        {
            return Some(
                "not: array is empty - either remove the not: field or add exception patterns"
                    .to_string(),
            );
        }
        None
    }

    /// Check for empty unless: arrays (common LLM mistake).
    /// Returns a warning message if found, None otherwise.
    #[must_use]
    pub(crate) fn check_empty_unless_array(&self) -> Option<String> {
        if let Some(unless_conditions) = &self.unless
            && unless_conditions.is_empty()
        {
            return Some(
                "unless: array is empty - either remove the unless: field or add skip conditions"
                    .to_string(),
            );
        }
        None
    }

    /// Check if `not:` field is used appropriately based on match type.
    /// Returns a warning message if misused, None otherwise.
    #[must_use]
    pub(crate) fn check_not_field_usage(&self) -> Option<String> {
        let not_exceptions = self.not.as_ref()?;

        // Helper to check if a pattern could match a literal string
        fn pattern_could_match(pattern: &str, literal: &str) -> bool {
            if let Ok(re) = regex::Regex::new(pattern) {
                re.is_match(literal)
            } else {
                false
            }
        }

        // Helper to check if a string contains a substring (case-sensitive or insensitive)
        fn contains_substr(haystack: &str, needle: &str, case_insensitive: bool) -> bool {
            if case_insensitive {
                haystack.to_lowercase().contains(&needle.to_lowercase())
            } else {
                haystack.contains(needle)
            }
        }

        match &self.r#if {
            // Symbol conditions with not: - validate exceptions match the pattern
            Condition::Symbol(SymbolQuery {
                exact: Some(_),
                regex: None,
                ..
            }) => {
                return Some(
                    "not: field used with symbol exact match - consider using 'unless:' instead for deterministic patterns".to_string()
                );
            }
            Condition::Symbol(SymbolQuery {
                substr: Some(search_substr),
                regex: None,
                ..
            }) => {
                // For symbol substr, validate not: exceptions contain the search substr
                for exc in not_exceptions {
                    match exc {
                        NotException::Shorthand(exc_str) if !exc_str.contains(search_substr) => {
                            return Some(format!(
                                "not: exception '{}' does not contain the search substr '{}' - symbols matching the substr won't contain this exception, so it will never be applied",
                                exc_str, search_substr
                            ));
                        }
                        NotException::Structured(NotExceptionStructured {
                            exact: Some(exc_str),
                            ..
                        }) if !exc_str.contains(search_substr) => {
                            return Some(format!(
                                "not: exception (exact) '{}' does not contain the search substr '{}' - symbols matching the substr won't match this exception, so it will never be applied",
                                exc_str, search_substr
                            ));
                        }
                        NotException::Structured(NotExceptionStructured {
                            substr: Some(exc_substr),
                            ..
                        }) if !exc_substr.contains(search_substr)
                            && !search_substr.contains(exc_substr) =>
                        {
                            return Some(format!(
                                "not: exception (substr) '{}' has no overlap with search substr '{}' - they won't match the same symbols, so the exception will never be applied",
                                exc_substr, search_substr
                            ));
                        }
                        _ => {}
                    }
                }
            }
            Condition::Symbol(SymbolQuery {
                regex: Some(pattern),
                ..
            }) => {
                // For symbol regex, validate that exceptions could potentially match
                for exc in not_exceptions {
                    match exc {
                        // Validate shorthand (substr) exceptions - check if the substr matches the regex
                        NotException::Shorthand(exc_str)
                            if !pattern_could_match(pattern, exc_str) =>
                        {
                            return Some(format!(
                                "not: exception '{}' does not match the search regex '{}' - symbols matching the regex won't contain this exception, so it will never be applied",
                                exc_str, pattern
                            ));
                        }
                        // Validate exact exceptions - check if the exact string matches the regex
                        NotException::Structured(NotExceptionStructured {
                            exact: Some(exc_str),
                            ..
                        }) if !pattern_could_match(pattern, exc_str) => {
                            return Some(format!(
                                "not: exception (exact) '{}' does not match the search regex '{}' - it will never be applied",
                                exc_str, pattern
                            ));
                        }
                        // For substr and regex exceptions, validation is complex - allow them
                        _ => {}
                    }
                }
            }
            // Exact matches should use `unless:` instead of `not:`
            Condition::Text(TextQuery {
                exact: Some(_),
                regex: None,
                word: None,
                ..
            })
            | Condition::Literal(LiteralQuery {
                exact: Some(_),
                regex: None,
                word: None,
                ..
            }) => {
                return Some(
                    "not: field used with exact match - consider using 'unless:' instead for deterministic patterns".to_string()
                );
            }
            // For Content exact matches, not: doesn't make sense
            Condition::Raw(RawQuery {
                exact: Some(_),
                regex: None,
                word: None,
                ..
            }) => {
                return Some(
                    "not: field used with content/exact match - this doesn't make sense. Content exact matches the entire file content.".to_string()
                );
            }
            // For String substr matches, validate that not: exceptions could match strings containing the substr
            Condition::Text(TextQuery {
                substr: Some(search_substr),
                regex: None,
                word: None,
                case_insensitive,
                ..
            })
            | Condition::Literal(LiteralQuery {
                substr: Some(search_substr),
                regex: None,
                word: None,
                case_insensitive,
                ..
            }) => {
                let case_insensitive = *case_insensitive;

                for exc in not_exceptions {
                    match exc {
                        // For shorthand (substr match in not:), check if the exception contains the search substr
                        NotException::Shorthand(exc_str)
                            if !contains_substr(exc_str, search_substr, case_insensitive) =>
                        {
                            return Some(format!(
                                "not: exception '{}' does not contain the search substr '{}' - strings matching the substr won't contain this exception, so it will never be applied",
                                exc_str, search_substr
                            ));
                        }
                        // Exception is exact match - it should contain the search substr.
                        NotException::Structured(NotExceptionStructured {
                            exact: Some(exc_str),
                            ..
                        }) if !contains_substr(exc_str, search_substr, case_insensitive) => {
                            return Some(format!(
                                "not: exception (exact) '{}' does not contain the search substr '{}' - strings matching the substr won't match this exception, so it will never be applied",
                                exc_str, search_substr
                            ));
                        }
                        // Exception is substr - it should contain the search substr or vice versa.
                        NotException::Structured(NotExceptionStructured {
                            substr: Some(exc_substr),
                            ..
                        }) if !contains_substr(exc_substr, search_substr, case_insensitive)
                            && !contains_substr(search_substr, exc_substr, case_insensitive) =>
                        {
                            return Some(format!(
                                "not: exception (substr) '{}' has no overlap with search substr '{}' - they won't match the same strings, so the exception will never be applied",
                                exc_substr, search_substr
                            ));
                        }
                        // Regex exceptions with substr searches can't be validated cheaply.
                        _ => {}
                    }
                }
            }
            // For Content substr matches, not: is unclear - content searches don't extract individual strings
            Condition::Raw(RawQuery {
                substr: Some(_),
                regex: None,
                word: None,
                ..
            }) => {
                return Some(
                    "not: field used with content/substr match - behavior is unclear because content searches on binary data don't extract individual strings for filtering. Use regex instead, or use 'string' type with substr.".to_string()
                );
            }
            // For regex matches, validate that exceptions could potentially match
            Condition::Text(TextQuery {
                regex: Some(pattern),
                ..
            })
            | Condition::Literal(LiteralQuery {
                regex: Some(pattern),
                ..
            })
            | Condition::Raw(RawQuery {
                regex: Some(pattern),
                ..
            }) => {
                for exc in not_exceptions {
                    match exc {
                        // Validate shorthand (substr) exceptions — check if the substr matches the regex
                        NotException::Shorthand(exc_str)
                            if !pattern_could_match(pattern, exc_str) =>
                        {
                            return Some(format!(
                                "not: exception '{}' does not match the search regex '{}' - strings matching the regex won't contain this exception, so it will never be applied",
                                exc_str, pattern
                            ));
                        }
                        // Validate exact exceptions — check if the exact string matches the regex
                        NotException::Structured(NotExceptionStructured {
                            exact: Some(exc_str),
                            ..
                        }) if !pattern_could_match(pattern, exc_str) => {
                            return Some(format!(
                                "not: exception (exact) '{}' does not match the search regex '{}' - it will never be applied",
                                exc_str, pattern
                            ));
                        }
                        // For substr and regex exceptions, validation is complex — allow them.
                        _ => {}
                    }
                }
            }
            // For hex patterns, validate exceptions match
            Condition::Hex(HexQuery { .. }) => {
                // For hex patterns, we should validate that not: exceptions make sense
                // Since hex matching is complex, we'll do a basic check
                // Hex patterns match byte sequences, so not: exceptions should be regex-based
                for exc in not_exceptions {
                    let _ = exc; // All exception types are allowed for hex patterns
                }
            }
            _ => {}
        }

        None
    }

    /// The shared `Istr` for this definition's id (see `id_shared`).
    pub(crate) fn shared_id(&self) -> crate::types::Istr {
        self.id_shared
            .get_or_init(|| self.id.as_str().into())
            .clone()
    }

    /// The shared `Istr` for this definition's description.
    pub(crate) fn shared_desc(&self) -> crate::types::Istr {
        self.desc_shared
            .get_or_init(|| self.desc.as_str().into())
            .clone()
    }

    /// Whether every match of this trait's `if:` regex needs a byte >= 0x80
    /// (`\p{Arabic}{3,}`, `[ąćę]`, box-drawing runs), so it cannot match
    /// ASCII-only content. Decided on first use rather than for every trait
    /// when the mapper's flags are built: deciding means parsing the regex
    /// (Unicode case folding included), which over the whole trait set cost
    /// ~0.26 s, serially, in every process, though a file only ever asks for
    /// the content-regex traits of its own type, and only when it is ASCII.
    pub(crate) fn requires_non_ascii(&self) -> bool {
        *self.requires_non_ascii.get_or_init(|| {
            matches!(&self.r#if,
                Condition::Raw(RawQuery { regex: Some(r), .. })
                | Condition::Text(TextQuery { regex: Some(r), .. })
                    if super::super::evaluators::requires_non_ascii(r))
        })
    }

    /// Check if this trait has any dependencies on other traits via `trait:` conditions.
    /// Used to determine evaluation order - traits with dependencies must be evaluated
    /// after their dependencies have been resolved.
    #[must_use]
    pub(crate) fn has_trait_dependency(&self) -> bool {
        // Check main condition
        if self.r#if.is_trait_reference() {
            return true;
        }

        // Check unless conditions
        if let Some(ref unless) = self.unless {
            for cond in unless {
                if cond.is_trait_reference() {
                    return true;
                }
            }
        }

        // Check downgrade conditions
        if let Some(ref downgrade) = self.downgrade {
            if let Some(ref any) = downgrade.any {
                for cond in any {
                    if cond.is_trait_reference() {
                        return true;
                    }
                }
            }
            if let Some(ref all) = downgrade.all {
                for cond in all {
                    if cond.is_trait_reference() {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// The bare `trait:` reference ids this definition's evaluation reads —
    /// the same coverage [`Self::has_trait_dependency`] classifies on (top-level
    /// `if`, `unless`, and `downgrade` lists; nested conditions are not
    /// classified as dependencies there either). Used by the dependent-pass
    /// worklist to skip re-evaluating traits whose referenced findings did not
    /// change in the previous iteration.
    pub(crate) fn trait_ref_ids(&self) -> Vec<&str> {
        let mut refs = Vec::new();
        fn add<'a>(cond: &'a Condition, refs: &mut Vec<&'a str>) {
            if let Condition::Trait { id } = cond {
                refs.push(id.as_str());
            }
        }
        add(&self.r#if, &mut refs);
        if let Some(ref unless) = self.unless {
            for cond in unless {
                add(cond, &mut refs);
            }
        }
        if let Some(ref downgrade) = self.downgrade {
            for conds in [&downgrade.any, &downgrade.all].into_iter().flatten() {
                for cond in conds {
                    add(cond, &mut refs);
                }
            }
        }
        refs
    }

    /// Whether this trait's evaluation needs the exact `match_count` — i.e. it
    /// has a count/density filter. When false, raw/text matching may stop at the
    /// first match (the dominant RSS lever; see `eval_raw`'s `needs_count`). The
    /// exact count is consumed only by these filters: no other consumer reads it
    /// and the ML pipeline does not feature on `match_count`.
    pub(crate) fn needs_match_count(&self) -> bool {
        self.count_min.is_some()
            || self.count_max.is_some()
            || self.per_kb_min.is_some()
            || self.per_kb_max.is_some()
    }

    /// The match count past which this trait's filters cannot change their
    /// answer on a file of `file_size` bytes (see
    /// `symbol_string::match_count_bound`): exact when a ceiling filter
    /// exists, otherwise the largest floor. The density floor is converted
    /// with the same arithmetic the filter applies, so the bound is the
    /// smallest count that passes it.
    pub(crate) fn match_count_bound(&self, file_size: usize) -> usize {
        if self.count_max.is_some() || self.per_kb_max.is_some() {
            return usize::MAX;
        }
        let mut bound = self.count_min.unwrap_or(0);
        if let Some(min_density) = self.per_kb_min {
            let file_kb = (file_size as f64) / 1024.0;
            if file_kb > 0.0 {
                let mut needed = (min_density * file_kb).ceil().max(0.0) as usize;
                while (needed as f64) / file_kb < min_density {
                    needed += 1;
                }
                bound = bound.max(needed);
            }
        }
        bound
    }

    /// Whether this trait says anything about the file as a whole, on top of
    /// whatever its `if:` matches.
    ///
    /// A size or entropy bound measures a file; an `unless:` guard reads one
    /// ("...unless the file also mentions `node-gyp-build`"). Both are written
    /// by an author who has a single file in mind.
    pub(super) fn constrains_whole_file(&self) -> bool {
        self.size_min.is_some()
            || self.size_max.is_some()
            || self.entropy_min.is_some()
            || self.entropy_max.is_some()
            || self.unless.is_some()
    }

    /// Evaluate this trait definition against the analysis context
    pub(crate) fn evaluate<'a>(&self, ctx: &EvaluationContext<'a>) -> Option<Finding> {
        self.evaluate_with_gates(ctx, false)
    }

    /// [`Self::evaluate`] for callers whose work list already applied the
    /// static platform and file-type gates (`CapabilityMapper::trait_worklist`);
    /// dynamic gates (arch, size, entropy) still run.
    pub(crate) fn evaluate_pregated<'a>(&self, ctx: &EvaluationContext<'a>) -> Option<Finding> {
        self.evaluate_with_gates(ctx, true)
    }

    pub(super) fn evaluate_with_gates<'a>(
        &self,
        ctx: &EvaluationContext<'a>,
        static_gates_prechecked: bool,
    ) -> Option<Finding> {
        use super::super::debug::{DowngradeDebug, SkipReason};

        // Let raw/text matching stop at the first match unless this trait needs
        // the exact `match_count` (count/density filter). Restored on drop so
        // nested `Condition::Trait` evaluations don't clobber it.
        let _mcg = MatchCountGuard::set(self.needs_match_count());
        let _mcb = super::super::evaluators::MatchCountBoundGuard::set(
            self.match_count_bound(ctx.report.target.size_bytes as usize),
        );

        // Check platform match (skipped when the caller's work list proved it)
        if !static_gates_prechecked
            && !super::super::types::platforms_intersect(&self.platforms, ctx.platforms)
        {
            ctx.record_skip(|| SkipReason::PlatformMismatch {
                rule: self.platforms.clone(),
                context: ctx.platforms.to_vec(),
            });
            return None;
        }

        // Check architecture match
        // `ctx.arch` first: it is hot, while `self.arch` is a per-rule heap
        // Vec that is usually cold here; for non-binary members the context
        // is `All` and the rule's Vec is never touched.
        let arch_match = ctx.arch.contains(&Arch::All)
            || self.arch.contains(&Arch::All)
            || self.arch.iter().any(|a| ctx.arch.contains(a));

        if !arch_match {
            ctx.record_skip(|| SkipReason::ArchMismatch {
                rule: self.arch.clone(),
                context: ctx.arch.to_vec(),
            });
            return None;
        }

        // Check file type match: the node's own type, or the generic
        // container it is built on (a JAR admits `for: [zip]`, not
        // `for: [android_apk]`). A container collapsed to FileType::All
        // admits only archive-typed rules, not every script/binary rule.
        if !static_gates_prechecked && !FileType::rule_applies_to(&self.r#for, ctx.file_type) {
            ctx.record_skip(|| SkipReason::FileTypeMismatch {
                rule: self.r#for.clone(),
                context: ctx.file_type,
            });
            return None;
        }

        // A fragment -- a decoded layer, an unescaped layer, a string literal
        // that sniffed as source -- has no name of its own, so `type: path`
        // reads its host's (see `fragment_host_path`). For a bare identity that
        // is what we want, and 34 path patterns across the rule tree depend on
        // it: a decoded layer of `x.js` IS JavaScript.
        //
        // It stops being what we want as soon as the trait says anything more.
        // `size_max: 500` would then measure the fragment while the name came
        // from the host; `unless: {text: node-gyp-build}` would read the
        // fragment while the name came from the host. One rule, two subjects --
        // which is how `install.js` kept its installer finding after the
        // carve-out text was added to the file.
        //
        // Standing down here costs nothing in practice: a trait that identifies
        // a file by its name matches that name on the host, and the host is a
        // node in its own right, judged against its own size and its own text.
        if self.constrains_whole_file()
            && matches!(self.r#if, Condition::Path(_))
            && let Some(host) =
                super::super::evaluators::fragment_host_path(&ctx.report.target.path)
        {
            ctx.record_skip(|| SkipReason::InheritedIdentityOnFragment {
                host: host.to_string(),
            });
            return None;
        }
        // The same split between subjects applies to `for:`: the gate above
        // admitted the fragment's type, but the name belongs to the host. A
        // shell snippet carved out of an ELF must not let a `for: [shell]`
        // path rule match the ELF's location, so the host has to qualify too.
        if matches!(self.r#if, Condition::Path(_))
            && let Some(host_type) = ctx.report.fragment_host_type
            && !FileType::rule_applies_to(&self.r#for, host_type)
        {
            ctx.record_skip(|| SkipReason::FileTypeMismatch {
                rule: self.r#for.clone(),
                context: host_type,
            });
            return None;
        }

        // Check size constraints (from if: block)
        let file_size = ctx.report.target.size_bytes as usize;
        if let Some(min) = self.size_min
            && file_size < min
        {
            ctx.record_skip(|| SkipReason::SizeTooSmall {
                actual: file_size,
                min,
            });
            return None;
        }
        if let Some(max) = self.size_max
            && file_size > max
        {
            ctx.record_skip(|| SkipReason::SizeTooLarge {
                actual: file_size,
                max,
            });
            return None;
        }

        // Check entropy constraints (from if: block)
        // Uses file.entropy for binaries, text.char_entropy for scripts
        if self.entropy_min.is_some() || self.entropy_max.is_some() {
            // Both `file.entropy` and `text.char_entropy`
            // flow through the flat `filefacts_metrics` map now.
            let binary_entropy = ctx
                .report
                .filefacts_metrics
                .as_ref()
                .and_then(|m| m.get("file.entropy").copied());
            let text_entropy = ctx
                .report
                .filefacts_metrics
                .as_ref()
                .and_then(|m| m.get("text.char_entropy").copied());
            let file_entropy = binary_entropy.or(text_entropy).unwrap_or(0.0);

            if let Some(min) = self.entropy_min
                && file_entropy < min
            {
                ctx.record_skip(|| SkipReason::EntropyTooLow {
                    actual: file_entropy,
                    min,
                });
                return None;
            }
            if let Some(max) = self.entropy_max
                && file_entropy > max
            {
                ctx.record_skip(|| SkipReason::EntropyTooHigh {
                    actual: file_entropy,
                    max,
                });
                return None;
            }
        }

        // Start timing for timeout detection (covers all evaluation phases)
        let start = crate::composite_rules::trait_timing::EvalTimer::start();
        let _performance =
            crate::validation_performance::RuleTimer::start(&self.id, &self.defined_in, ctx);

        // The positive condition runs before `unless:`, which is consulted only
        // when it matched: a trait whose condition fails produces nothing
        // whatever its exceptions say. Exceptions are rarely cheaper than the
        // condition they guard: a tree-sitter `unless:` has to walk the whole
        // tree, often with no literal to gate on, while the condition's own
        // literal gate answers "no" without a walk on most files (a 2.3 MB
        // bundle without `execFile` walked three exception queries for a rule
        // keyed on it). Under an explain collector the old order is kept, so
        // `test-rules` still names a matching exception on a non-matching rule.
        let early = (self.unless.is_some() && ctx.debug_collector.is_none())
            .then(|| self.eval_condition(&self.r#if, ctx));
        let unless_needed = early.as_ref().is_none_or(|result| result.matched);

        // Check unless conditions (file-level skip).
        //
        // A matched `unless:` ends the evaluation. With a suppression sink
        // attached and the trait worth reporting, the early-out is deferred —
        // "withheld" is only true of a trait that would otherwise have matched,
        // and the overwhelming majority of `unless:` hits are on rules whose
        // positive side never comes close. Recording those would fill the report
        // with detections that were never in prospect.
        let mut withheld_by: Option<(&Condition, ConditionResult)> = None;
        if let Some(unless_conds) = self.unless.as_ref().filter(|_| unless_needed) {
            // Default 'any' semantics: skip if ANY condition matches
            for condition in unless_conds {
                let result = self.eval_condition(condition, ctx);
                if result.matched {
                    // For a directory-prefix unless (e.g. `metadata/binary/resource/`),
                    // the bare pattern alone is rarely actionable — surface the concrete
                    // trait(s) that actually matched the prefix so `test-rules` names the
                    // real suppressor instead of echoing the prefix back.
                    let concrete = if result.matched_trait_ids.is_empty() {
                        String::new()
                    } else {
                        format!(" [matched: {}]", result.matched_trait_ids.join(", "))
                    };
                    ctx.record_skip(|| SkipReason::UnlessConditionMatched {
                        condition_desc: format!("{:?}{}", condition, concrete),
                    });
                    if ctx.suppressions.is_some()
                        && self.crit >= crate::types::MIN_RECORDED_SUPPRESSION
                    {
                        withheld_by = Some((condition, result));
                        break;
                    }
                    return None;
                }
            }
        }

        // Evaluate the condition (traits only have one atomic condition)
        let result = early.unwrap_or_else(|| self.eval_condition(&self.r#if, ctx));
        let duration = start.elapsed();

        // A timeout is incomplete analysis, not an analysis-evasion finding.
        // A completed match is still a match; the gap tells readers that
        // conditions evaluated after the deadline may be missing.
        if record_rule_timeout(ctx.report, duration) {
            tracing::warn!(
                rule = %self.id,
                path = %ctx.report.target.path,
                elapsed_ms = duration.as_millis(),
                limit_ms = MAX_RULE_EVAL_DURATION.as_millis(),
                "rule evaluation exceeded its deadline"
            );
        }

        // Info log: rules taking >500ms
        if duration > RULE_EVAL_DEBUG_DURATION {
            tracing::info!("slow rule: {} took {}ms", self.id, duration.as_millis(),);
        }

        // Aggregate per-trait time across the whole scan (env-gated: a map
        // update per evaluation). A single per-eval duration under the slow
        // thresholds is invisible, but 10 ms × thousands of archive members is
        // where archive wall time actually goes — `CLEAVE_TRAIT_TIMING=1`
        // surfaces the top offenders at end of scan.
        crate::composite_rules::trait_timing::record(&self.id, duration);

        // Warn log: rules exceeding the user-configurable slow_rule_ms threshold
        let warn_threshold = Duration::from_millis(ctx.slow_rule_ms);
        if duration > warn_threshold {
            tracing::warn!(
                "slow rule: {} took {}ms (threshold: {}ms)",
                self.id,
                duration.as_millis(),
                ctx.slow_rule_ms,
            );
        }

        // A deferred `unless:` hit: the positive side has now run, so the
        // suppression is recorded only when there was really something to
        // suppress. Either way the trait produces no finding.
        if let Some((condition, unless_result)) = withheld_by {
            if result.matched {
                ctx.record_suppression(|| crate::types::Suppression {
                    id: self.shared_id(),
                    crit: self.crit,
                    kind: crate::types::SuppressionKind::Unless,
                    by: suppression_legs(condition, &unless_result),
                });
            }
            return None;
        }

        if result.matched {
            // Apply count and density filters (centralized for all condition types)
            // Use match_count which may exceed evidence.len() for high-frequency patterns
            let match_count = result.match_count;
            let file_kb = (file_size as f64) / 1024.0;

            // Check count_min constraint
            if let Some(min) = self.count_min
                && match_count < min
            {
                ctx.record_skip(|| SkipReason::CountBelowMinimum {
                    actual: match_count,
                    min,
                });
                return None;
            }

            // Check count_max constraint
            if let Some(max) = self.count_max
                && match_count > max
            {
                ctx.record_skip(|| SkipReason::CountAboveMaximum {
                    actual: match_count,
                    max,
                });
                return None;
            }

            // Check per_kb_min constraint (density threshold).
            // Zero-byte files have infinite density — trivially satisfy any minimum.
            if let Some(min_density) = self.per_kb_min
                && file_kb > 0.0
            {
                let actual_density = (match_count as f64) / file_kb;
                if actual_density < min_density {
                    ctx.record_skip(|| SkipReason::DensityBelowMinimum {
                        actual: actual_density,
                        min: min_density,
                    });
                    return None;
                }
            }

            // Check per_kb_max constraint (density ceiling).
            // A zero-byte file with matches has infinite density — always fails the ceiling.
            if let Some(max_density) = self.per_kb_max {
                let actual_density = if file_kb > 0.0 {
                    (match_count as f64) / file_kb
                } else {
                    f64::INFINITY
                };
                if actual_density > max_density {
                    ctx.record_skip(|| SkipReason::DensityAboveMaximum {
                        actual: actual_density,
                        max: max_density,
                    });
                    return None;
                }
            }

            let mut final_crit = self.crit;

            // Check downgrade conditions
            if let Some(downgrade_conds) = &self.downgrade
                && downgrade_conds.scope != Some(Scope::Parent)
            {
                let triggered = self.eval_downgrade_conditions(downgrade_conds, ctx);
                if triggered {
                    final_crit = downgrade_crit(self.crit);
                    tracing::debug!(
                        "Downgrade applied: trait '{}' from {:?} → {:?}{}",
                        self.id,
                        self.crit,
                        final_crit,
                        if final_crit == self.crit {
                            " (floored at notable)"
                        } else {
                            ""
                        }
                    );
                    // Record on `triggered`, not on a criticality change: a
                    // downgrade floored at notable still fired, and the analyst
                    // needs to see that a clause is trying to suppress this
                    // finding. Keying the record to `final_crit != self.crit`
                    // would make every floored downgrade invisible.
                    if self.crit >= crate::types::MIN_RECORDED_SUPPRESSION {
                        ctx.record_suppression(|| crate::types::Suppression {
                            id: self.shared_id(),
                            crit: self.crit,
                            kind: crate::types::SuppressionKind::Downgrade,
                            by: downgrade_legs(downgrade_conds, |c| self.eval_condition(c, ctx)),
                        });
                    }
                }

                // Record downgrade debug if collector is present
                ctx.with_debug(|debug| {
                    debug.downgrade = Some(DowngradeDebug {
                        original_crit: self.crit,
                        final_crit,
                        triggered,
                    });
                });
            }

            // Record match in debug collector
            ctx.with_debug(|debug| {
                debug.matched = true;
                debug.precision = result.precision;
            });

            // Guardrail: every piece of evidence must carry a `location`.
            // Locationless evidence silently breaks composite scope/proximity
            // bucketing — it keys to the empty scope and can split a single-file
            // rule into unsatisfiable singleton buckets (a symbol-type leg with
            // no location never pools with a text-type leg that has one). A
            // missing location is therefore an evaluator bug, not a valid state.
            // For now we log; this is slated to become a hard error once every
            // evaluator populates a location.
            report_locationless_evidence(&self.id, &result.evidence);

            Some(Finding {
                precomputed_spans: None,
                src: None,
                id: self.shared_id(),
                kind: FindingKind::Capability,
                desc: self.shared_desc(),
                conf: self.conf,
                crit: final_crit,
                downgraded: final_crit != self.crit,
                mbc: self.mbc.as_deref().map(Into::into),
                attack: self.attack.as_deref().map(Into::into),
                trait_refs: vec![],
                evidence: result.evidence,
                match_count: result.match_count,
                source_file: rule_source_file(&self.defined_in),
            })
        } else {
            None
        }
    }

    /// Re-evaluate this trait's downgrade clause against a (possibly richer)
    /// evaluation context, returning the new criticality that should be applied.
    ///
    /// Used by the cross-scope downgrade pass: a per-file trait that references
    /// a container-level finding (e.g. `metadata/file/format/browser-extension::mozilla-extension`)
    /// gets a second chance to apply its downgrade once container composites
    /// have been evaluated and merged into the report.
    ///
    /// `base_crit` should be the trait's *declared* criticality (`self.crit`),
    /// not the finding's current crit, so the pass is idempotent: calling it
    /// twice yields the same result as calling it once.
    pub(crate) fn evaluate_downgrade<'a>(
        &self,
        conditions: &DowngradeConditions,
        base_crit: &Criticality,
        ctx: &EvaluationContext<'a>,
    ) -> Criticality {
        self.evaluate_downgrade_of(&self.shared_id(), conditions, base_crit, ctx)
    }

    /// [`evaluate_downgrade`](Self::evaluate_downgrade) for the finding
    /// `finding_id`, which this trait's `downgrade:` governs but did not
    /// produce: the hook carrier of an engine-emitted finding. The recorded
    /// suppression names that finding, as it would name a YAML trait's own.
    pub(crate) fn evaluate_downgrade_of<'a>(
        &self,
        finding_id: &crate::types::Istr,
        conditions: &DowngradeConditions,
        base_crit: &Criticality,
        ctx: &EvaluationContext<'a>,
    ) -> Criticality {
        if self.eval_downgrade_conditions(conditions, ctx) {
            if *base_crit >= crate::types::MIN_RECORDED_SUPPRESSION {
                ctx.record_suppression(|| crate::types::Suppression {
                    id: finding_id.clone(),
                    crit: *base_crit,
                    kind: crate::types::SuppressionKind::Downgrade,
                    by: downgrade_legs(conditions, |c| self.eval_condition(c, ctx)),
                });
            }
            downgrade_crit(*base_crit)
        } else {
            *base_crit
        }
    }

    /// Evaluate a single downgrade condition set.
    /// All specified blocks (all/any) must pass for the downgrade to trigger.
    pub(super) fn eval_downgrade_conditions<'a>(
        &self,
        conditions: &DowngradeConditions,
        ctx: &EvaluationContext<'a>,
    ) -> bool {
        let mut has_any_block = false;

        // If 'all' is specified, every condition must match
        if let Some(all_conds) = &conditions.all {
            has_any_block = true;
            for cond in all_conds {
                if !self.eval_condition(cond, ctx).matched {
                    return false;
                }
            }
        }

        // If 'any' is specified, at least `needs` conditions must match (default 1)
        if let Some(any_conds) = &conditions.any {
            has_any_block = true;
            let threshold = conditions.needs.unwrap_or(1);
            let mut matched_count = 0;
            for cond in any_conds {
                let result = self.eval_condition(cond, ctx);
                matched_count += condition_count_weight(cond, &result);
            }
            if matched_count < threshold {
                return false;
            }
        }

        has_any_block
    }

    /// Evaluate a single condition
    pub(super) fn eval_condition<'a>(
        &self,
        condition: &Condition,
        ctx: &EvaluationContext<'a>,
    ) -> ConditionResult {
        eval_condition(
            ConditionRule {
                id: &self.id,
                not: self.not.as_ref(),
                arch: &self.arch,
            },
            condition,
            ctx,
        )
    }
}
