//! Evaluation of composite rules.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

impl CompositeTrait {
    /// Whether the rule's `exempt:` names `validator`.
    #[cfg(feature = "lint")]
    pub(crate) fn is_exempt(&self, validator: &str) -> bool {
        self.exempt.iter().any(|v| &**v == validator)
    }

    /// The scope this composite runs under when it omits `scope:`, chosen
    /// from `for:` rather than a single fixed default:
    ///
    /// - An ecosystem package type (`#[package]`-tagged: npm/deb/rpm/whl/
    ///   vsix/...) → [`Scope::Package`]. A rule about a package means the
    ///   package boundary, not whatever generic wrapper happens to sit closer
    ///   to the evidence: for `pkg.tgz!vendor.zip!x.js`, `archive` keys to
    ///   `vendor.zip` and `package` to `pkg.tgz`. Package wins the tie against
    ///   archive for the types that are both, which is all of them.
    /// - A generic container (`#[archive]`-tagged but not `#[package]`:
    ///   zip/tar/iso/...) → [`Scope::Archive`]. The bug this replaces was a
    ///   composite whose author forgot `scope: archive` on a container type,
    ///   silently getting `Scope::File` and never seeing a member.
    /// - [`FileType::Registry`] → [`Scope::Outer`]. Registry metadata is
    ///   fetched beside the artifact, not from inside it, so its findings
    ///   carry no location and every location-keyed scope collapses to the
    ///   empty key. `outer` is the only scope that joins the two.
    /// - Everything else → [`Scope::File`].
    ///
    /// Always explicit-overridable via `scope:`; this is only consulted when
    /// that field is omitted.
    pub(super) fn default_scope(&self) -> Scope {
        if self.r#for.iter().any(FileType::is_package) {
            Scope::Package
        } else if self.r#for.iter().any(FileType::is_archive) {
            Scope::Archive
        } else if self.r#for.contains(&FileType::Registry) {
            Scope::Outer
        } else {
            Scope::File
        }
    }

    /// The scope actually used for evaluation: the explicit `scope:` if
    /// given, otherwise [`Self::default_scope`].
    pub(crate) fn effective_scope(&self) -> Scope {
        self.scope.unwrap_or_else(|| {
            *self
                .default_scope_cache
                .get_or_init(|| self.default_scope())
        })
    }

    /// `for:` as a type mask: which files' findings may satisfy this rule's
    /// legs. `for: [all]` is every bit set, which disables the filter.
    ///
    /// `for:` names the file types the rule is about -- the container it
    /// reports on *and* the members whose evidence it may mix. A rule that
    /// ties a vsix manifest to its bundled script says
    /// `for: [vsix, javascript, json]`; one that says only `for: [vsix]`
    /// pools nothing, because no member of a vsix is itself a vsix.
    ///
    /// Same admission as the node gate (`FileType::rule_applies_to`): a
    /// `for: [zip]` rule also takes evidence from a nested JAR, which is a zip.
    pub(crate) fn for_mask(&self) -> TypeMask {
        *self.for_mask_cache.get_or_init(|| {
            if self.r#for.contains(&FileType::All) || self.r#for.is_empty() {
                TypeMask::ALL
            } else {
                FileType::all_concrete_variants()
                    .into_iter()
                    .filter(|ft| FileType::rule_applies_to(&self.r#for, *ft))
                    .fold(TypeMask::EMPTY, |acc, ft| acc | ft.type_bit())
            }
        })
    }

    /// Check for empty, too-short, or too-long descriptions. Composites get a
    /// roomier cap than atomic traits ([`MAX_COMPOSITE_DESCRIPTION_CHARS`]) because
    /// they summarize a combination, but the description must still fit one
    /// triage line. Returns a warning message if found, `None` otherwise.
    #[must_use]
    #[cfg(feature = "lint")]
    pub(crate) fn check_description_quality(&self) -> Option<String> {
        let desc = self.desc.trim();

        if desc.is_empty() {
            return Some(
                "desc: field is empty. Write a clear, concise summary of what this composite detects".to_string()
            );
        }

        if desc.len() < 5 {
            return Some(format!(
                "desc: '{}' is too short ({} chars). Write a clear description.",
                desc,
                desc.len()
            ));
        }

        let desc_len = desc.chars().count();
        if desc_len > MAX_COMPOSITE_DESCRIPTION_CHARS {
            return Some(format!(
                "desc: '{}' is too long ({} chars) for one-line triage. Keep composite descriptions at {} characters or less.",
                desc, desc_len, MAX_COMPOSITE_DESCRIPTION_CHARS
            ));
        }

        None
    }

    /// Collect the subset of dependent trait IDs that are individually mandatory.
    ///
    /// These IDs are used only for fast prefiltering before full composite evaluation,
    /// so they must be a sound lower bound:
    /// - every `all:` trait reference is mandatory
    /// - `any:` references are only mandatory when the rule requires all of them
    pub(super) fn required_trait_ids(&self) -> Vec<String> {
        let mut ids = Vec::new();

        if let Some(conds) = &self.all {
            for cond in conds {
                if let Condition::Trait { id } = cond {
                    ids.push(id.clone());
                }
            }
        }

        if let Some(conds) = &self.any {
            let required_from_any = self.needs.unwrap_or(1);
            if required_from_any >= conds.len()
                && !conds.iter().any(|c| {
                    matches!(c,
                    Condition::Trait { id } if id.contains('/') && !id.contains("::"))
                })
            {
                for cond in conds {
                    if let Condition::Trait { id } = cond {
                        ids.push(id.clone());
                    }
                }
            }
        }

        ids
    }

    /// Populate required_trait_indices using a map of trait ID -> index.
    ///
    /// This is a pruning hint for composite evaluation, not a full encoding of the
    /// rule. It must never require more matched traits than the composite actually
    /// needs to run, or valid `any:` + `needs:` rules get skipped before evaluation.
    pub(crate) fn populate_required_traits(
        &mut self,
        trait_id_map: &crate::capabilities::TraitIdMap,
    ) {
        let dependent_ids = self.required_trait_ids();
        self.required_trait_indices = dependent_ids
            .into_iter()
            .filter_map(|id| trait_id_map.get(&id).copied())
            .collect();
        self.required_trait_indices.sort_unstable();
        self.required_trait_indices.dedup();
    }

    /// Pre-compile all regexes in this rule's conditions for performance.
    /// Returns an error if any regex pattern is invalid.
    pub(crate) fn precompile_regexes(&mut self) -> anyhow::Result<()> {
        if let Some(ref mut conds) = self.all {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes().with_context(|| {
                    format!("in composite rule '{}' all condition #{}", self.id, idx + 1)
                })?;
            }
        }
        if let Some(ref mut conds) = self.any {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes().with_context(|| {
                    format!("in composite rule '{}' any condition #{}", self.id, idx + 1)
                })?;
            }
        }
        if let Some(ref mut conds) = self.unless {
            for (idx, cond) in conds.iter_mut().enumerate() {
                cond.precompile_regexes().with_context(|| {
                    format!(
                        "in composite rule '{}' unless condition #{}",
                        self.id,
                        idx + 1
                    )
                })?;
            }
        }
        if let Some(ref mut downgrade) = self.downgrade {
            if let Some(ref mut any) = downgrade.any {
                for (idx, cond) in any.iter_mut().enumerate() {
                    cond.precompile_regexes().with_context(|| {
                        format!(
                            "in composite rule '{}' downgrade.any condition #{}",
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
                            "in composite rule '{}' downgrade.all condition #{}",
                            self.id,
                            idx + 1
                        )
                    })?;
                }
            }
        }
        Ok(())
    }

    /// Pre-compile YARA rules in all conditions
    pub(crate) fn compile_yara(&mut self) {
        if let Some(ref mut conds) = self.all {
            for cond in conds.iter_mut() {
                cond.compile_yara();
            }
        }
        if let Some(ref mut conds) = self.any {
            for cond in conds.iter_mut() {
                cond.compile_yara();
            }
        }
        if let Some(ref mut conds) = self.unless {
            for cond in conds.iter_mut() {
                cond.compile_yara();
            }
        }
    }

    /// Composite traits carry no count/density filters, so raw/text matching in
    /// their conditions never needs the exact `match_count` (see `eval_raw`).
    pub(crate) fn needs_match_count(&self) -> bool {
        false
    }

    /// Evaluate this rule against the analysis context
    #[must_use]
    pub(crate) fn evaluate<'a>(&self, ctx: &EvaluationContext<'a>) -> Option<Finding> {
        self.evaluate_with_gates(ctx, false)
    }

    /// [`Self::evaluate`] for callers that already applied the static
    /// platform / file-type gates via `CapabilityMapper::composite_worklists`
    /// — those two checks are skipped; the dynamic gates (arch, size,
    /// conditions) still run. Must only be called with rules drawn from the
    /// matching work list, or platform/file-type filtering is silently lost.
    pub(crate) fn evaluate_pregated<'a>(&self, ctx: &EvaluationContext<'a>) -> Option<Finding> {
        self.evaluate_with_gates(ctx, true)
    }

    pub(super) fn evaluate_with_gates<'a>(
        &self,
        ctx: &EvaluationContext<'a>,
        static_gates_prechecked: bool,
    ) -> Option<Finding> {
        use super::super::debug::{DowngradeDebug, ProximityDebug, ScopeDebug, SkipReason};

        // A `crit: exception` composite may assemble a directory of exceptions, so
        // re-include exception members in its directory references. Only exceptions
        // (rare) pay the context clone; every other rule uses `ctx` as-is.
        let exc_ctx;
        let ctx = if self.crit == Criticality::Exception {
            exc_ctx = ctx.clone().with_parent_exception(true);
            &exc_ctx
        } else {
            ctx
        };

        // Composite traits have no count/density filter, so raw/text matching in
        // their conditions can stop early unless proximity needs later hits.
        let _locations =
            MatchLocationsGuard::set(self.near_bytes.is_some() || self.near_lines.is_some());
        let _mcg = MatchCountGuard::set(self.needs_match_count());

        // Check platform match
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

        // Check file type match.
        // Container-level evaluation may collapse archive parents to FileType::All.
        // In that case, allow only archive-family rules to match rather than treating
        // All as a universal wildcard for every script/source/binary rule.
        // Skipped when the caller's work list already proved it for this type.
        if !static_gates_prechecked {
            // `for:` names the node this rule is evaluated on -- nothing more.
            // A cross-archive scope (`archive`/`outer`/`package`) says which
            // *evidence* may be pooled once the rule runs; it is not also a
            // licence to run on archive formats the rule never declared. The
            // container inherits every member finding, so a rule that wants to
            // tie a CRX's content script to its manifest declares `for: [crx]`
            // (the node it runs on) and still sees both.
            //
            // This previously carried two carve-outs -- `wants_archive_family`
            // (the `for:` names any archive type) and `pools_across_archive`
            // (the rule is archive-scoped) -- either of which admitted the rule
            // on *any* archive container. `for:` therefore meant nothing on 546
            // of the tree's 2287 archive-scoped composites:
            // `vscode-activated-curl-shell` (`for: [vsix]`) scored hostile on
            // the Rust crate agentdiff-0.1.26, tying a VS Code extension marker
            // in one member to a `curl | sh` README line in another.
            //
            // A node still admits the generic container it is built on: a JAR
            // is a zip, so a `for: [zip]` composite runs on it, exactly as a
            // `for: [zip]` atomic trait does (`FileType::rule_applies_to`).
            if !FileType::rule_applies_to(&self.r#for, ctx.file_type) {
                ctx.record_skip(|| SkipReason::FileTypeMismatch {
                    rule: self.r#for.clone(),
                    context: ctx.file_type,
                });
                return None;
            }
        }

        // Check size constraints
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

        // Start timing for timeout detection (covers all evaluation phases)
        let start = crate::composite_rules::trait_timing::EvalTimer::start();
        // Every exit counts toward the aggregate, not just a match.
        let _timing = crate::composite_rules::trait_timing::Recorder::start(&self.id);
        let _performance =
            crate::validation_performance::RuleTimer::start(&self.id, &self.defined_in, ctx);

        // Check unless conditions (file-level skip). Deferred when recording —
        // see the identical note on `TraitDefinition::evaluate_with_gates`.
        let mut withheld_by: Option<(&Condition, ConditionResult)> = None;
        if let Some(unless_conds) = &self.unless {
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

        // Evaluate positive conditions based on the boolean operator(s).
        // The `return None`s below are all "the positive side did not match",
        // so a deferred `unless:` hit needs no record on any of those paths.
        let (positive_result, proximity_tags) = match (&self.all, &self.any) {
            (Some(all), Some(any)) => {
                // Both all AND any: all must match AND any must match (respecting `needs`)
                let (all_result, all_tags) = self.eval_requires_all(all, ctx);
                if !all_result.matched {
                    return None;
                }
                let (any_result, any_tags) = if let Some(required_count) = self.needs {
                    self.eval_count_constraints(any, None, Some(required_count), None, ctx)
                } else {
                    self.eval_requires_any(any, ctx)
                }; // both branches return (ConditionResult, Vec<TaggedLocation>)
                if !any_result.matched {
                    return None;
                }
                // Merge tags, offsetting any-condition indices past all-conditions
                let all_count = all.len();
                let mut tags = all_tags;
                for mut t in any_tags {
                    t.condition_index += all_count;
                    tags.push(t);
                }
                // Combine evidence and trait IDs from both (limited to MAX_EVIDENCE_PER_TRAIT)
                let mut combined_evidence = all_result.evidence;
                combined_evidence.extend(any_result.evidence);
                let combined_evidence = deduplicate_evidence(combined_evidence);
                let match_count = combined_evidence.len();
                let mut combined_evidence = combined_evidence;
                combined_evidence.truncate(MAX_EVIDENCE_PER_TRAIT);
                let mut combined_trait_ids = all_result.matched_trait_ids;
                combined_trait_ids.extend(any_result.matched_trait_ids);
                (
                    ConditionResult {
                        matched: true,
                        evidence: combined_evidence,
                        match_count,
                        warnings: Vec::new(),
                        precision: 0.0,
                        matched_trait_ids: combined_trait_ids,
                    },
                    tags,
                )
            }
            (Some(conds), None) => self.eval_requires_all(conds, ctx),
            (None, Some(conds)) => {
                if let Some(required_count) = self.needs {
                    self.eval_count_constraints(conds, None, Some(required_count), None, ctx)
                } else {
                    self.eval_requires_any(conds, ctx)
                }
            }
            (None, None) => {
                // No positive conditions - invalid rule
                return None;
            }
        };

        if !positive_result.matched {
            return None;
        }

        // The positive side held, so a deferred `unless:` hit really did
        // withhold a composite that would otherwise have fired.
        if let Some((condition, unless_result)) = withheld_by {
            ctx.record_suppression(|| crate::types::Suppression {
                id: self.shared_id(),
                crit: self.crit,
                kind: crate::types::SuppressionKind::Unless,
                by: suppression_legs(condition, &unless_result),
            });
            return None;
        }

        let mut result = positive_result;

        // Apply scope filter (e.g. `scope: leaf` for archive-FP suppression).
        // When the filter rejects all scope buckets, the rule does not fire.
        // Record where each leg's evidence was bucketed first: a rejected
        // rule otherwise shows every leg matched and still does not fire.
        let scope = self.effective_scope();
        if result.matched && !matches!(scope, Scope::Outer) {
            ctx.with_debug(|debug| {
                debug.scope = Some(ScopeDebug {
                    scope: format!("{scope:?}").to_lowercase(),
                    satisfied: false,
                    detail: self.scope_debug_detail(
                        &proximity_tags,
                        &ctx.report.archive_contents,
                        &ctx.report.target.file_type,
                    ),
                });
            });
        }
        let proximity_tags = match self.apply_scope_filter(
            result.evidence,
            proximity_tags,
            &ctx.report.archive_contents,
            &ctx.report.target.file_type,
        ) {
            Some((ev, tags)) => {
                result.evidence = ev;
                ctx.with_debug(|debug| {
                    if let Some(scope) = debug.scope.as_mut() {
                        scope.satisfied = true;
                    }
                });
                tags
            }
            None => return None,
        };

        if result.matched {
            // Check proximity constraints (near_lines, near_bytes)
            let proximity_result = self.check_proximity_constraints(
                result.evidence.clone(),
                &proximity_tags,
                ctx.binary_data,
            );

            // Record proximity debug if applicable
            if self.near_lines.is_some() || self.near_bytes.is_some() {
                let constraint_type = if self.near_lines.is_some() {
                    "near_lines"
                } else {
                    "near_bytes"
                };
                let max_span = self.near_lines.or(self.near_bytes).unwrap_or(0);
                let satisfied = proximity_result.is_some();
                let binary_data = ctx.binary_data;
                ctx.with_debug(|debug| {
                    // Computed inside the closure so the file-sized line-index
                    // build only happens when debug output is actually collected.
                    let detail = self.proximity_debug_detail(&proximity_tags, binary_data);
                    debug.proximity = Some(ProximityDebug {
                        constraint_type: constraint_type.to_string(),
                        max_span,
                        satisfied,
                        detail,
                    });
                });
            }

            let evidence = proximity_result?;

            // Boost precision if proximity constraints were applied
            let mut precision_boost = 0.0;
            if self.near_lines.is_some() || self.near_bytes.is_some() {
                precision_boost = 1.0;
            }

            let mut final_crit = self.crit;

            // Check downgrade conditions
            if let Some(downgrade_conds) = &self.downgrade
                && downgrade_conds.scope != Some(Scope::Parent)
            {
                let triggered = self.eval_downgrade_conditions(downgrade_conds, ctx);
                if triggered {
                    final_crit = downgrade_crit(self.crit);
                    // Recorded whenever the clause fires, including when
                    // `downgrade_crit` floors it at notable — see that function.
                    if self.crit >= crate::types::MIN_RECORDED_SUPPRESSION {
                        ctx.record_suppression(|| crate::types::Suppression {
                            id: self.shared_id(),
                            crit: self.crit,
                            kind: crate::types::SuppressionKind::Downgrade,
                            by: downgrade_legs(downgrade_conds, |c| self.eval_condition(c, ctx)),
                        });
                    }
                }

                // Record downgrade debug
                ctx.with_debug(|debug| {
                    debug.downgrade = Some(DowngradeDebug {
                        original_crit: self.crit,
                        final_crit,
                        triggered,
                    });
                });
            }

            // Record match in debug collector
            let final_precision = result.precision + precision_boost;
            ctx.with_debug(|debug| {
                debug.matched = true;
                debug.precision = final_precision;
            });

            // Check for timeout violations before returning
            let duration = start.elapsed();
            // A completed match is still a match; the gap tells readers that
            // conditions evaluated after the deadline may be missing.
            if record_rule_timeout(ctx.report, duration) {
                tracing::warn!(
                    rule = %self.id,
                    path = %ctx.report.target.path,
                    elapsed_ms = duration.as_millis(),
                    limit_ms = MAX_RULE_EVAL_DURATION.as_millis(),
                    "composite rule evaluation exceeded its deadline"
                );
            }

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
                trait_refs: result.matched_trait_ids.clone(),
                evidence,
                match_count: 0, // not meaningful for composites
                source_file: rule_source_file(&self.defined_in),
            })
        } else {
            None
        }
    }

    /// Evaluate downgrade conditions and return final criticality.
    /// Public so that mapper can re-evaluate downgrades after all findings are collected.
    /// When matched, drops one level: hostile→suspicious→notable→baseline
    #[must_use]
    pub(crate) fn evaluate_downgrade<'a>(
        &self,
        conditions: &DowngradeConditions,
        base_crit: &Criticality,
        ctx: &EvaluationContext<'a>,
    ) -> Criticality {
        if self.eval_downgrade_conditions(conditions, ctx) {
            if *base_crit >= crate::types::MIN_RECORDED_SUPPRESSION {
                ctx.record_suppression(|| crate::types::Suppression {
                    id: self.shared_id(),
                    crit: *base_crit,
                    kind: crate::types::SuppressionKind::Downgrade,
                    by: downgrade_legs(conditions, |c| self.eval_condition(c, ctx)),
                });
            }
            return downgrade_crit(*base_crit);
        }
        *base_crit
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

    /// Evaluate ALL conditions must match (AND)
    /// Returns (result, tagged_locations) where tagged_locations maps evidence to condition indices.
    pub(super) fn eval_requires_all<'a>(
        &self,
        conds: &[Condition],
        ctx: &EvaluationContext<'a>,
    ) -> (ConditionResult, Vec<TaggedLocation>) {
        let mut all_evidence = Vec::new();
        let mut total_precision = 0.0f32;
        let mut all_trait_ids = Vec::new();
        let mut tags = Vec::new();

        for (i, condition) in conds.iter().enumerate() {
            let result = self.eval_condition(condition, ctx);
            if !result.matched {
                return (ConditionResult::no_match(), Vec::new());
            }
            // Tag evidence locations before merging
            tags.extend(tag_evidence(&result.evidence, i));
            // Limit evidence to prevent explosion
            if all_evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                let remaining = MAX_EVIDENCE_PER_TRAIT - all_evidence.len();
                all_evidence.extend(result.evidence.into_iter().take(remaining));
            }
            all_trait_ids.extend(result.matched_trait_ids);
            total_precision += result.precision; // SUM for 'all'
        }

        // Deduplicate evidence before returning
        let all_evidence = deduplicate_evidence(all_evidence);
        let match_count = all_evidence.len();
        (
            ConditionResult {
                matched: true,
                evidence: all_evidence,
                match_count,
                warnings: Vec::new(),
                precision: total_precision,
                matched_trait_ids: all_trait_ids,
            },
            tags,
        )
    }

    /// Evaluate at least ONE condition must match (OR)
    /// Collects evidence from ALL matching conditions, not just the first.
    /// Returns (result, tagged_locations) where tagged_locations maps evidence to condition indices.
    pub(super) fn eval_requires_any<'a>(
        &self,
        conds: &[Condition],
        ctx: &EvaluationContext<'a>,
    ) -> (ConditionResult, Vec<TaggedLocation>) {
        let mut any_matched = false;
        let mut all_evidence = Vec::new();
        let mut all_trait_ids = Vec::new();
        let mut min_precision = f32::MAX;
        let mut tags = Vec::new();

        for (i, condition) in conds.iter().enumerate() {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                any_matched = true;
                // Tag evidence locations before merging
                tags.extend(tag_evidence(&result.evidence, i));
                // Limit evidence to prevent explosion
                if all_evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    let remaining = MAX_EVIDENCE_PER_TRAIT - all_evidence.len();
                    all_evidence.extend(result.evidence.into_iter().take(remaining));
                }
                all_trait_ids.extend(result.matched_trait_ids);
                min_precision = min_precision.min(result.precision); // MIN for 'any'
            }
        }

        let precision = if any_matched { min_precision } else { 0.0 };

        // Deduplicate evidence before returning
        let all_evidence = deduplicate_evidence(all_evidence);
        let match_count = all_evidence.len();
        (
            ConditionResult {
                matched: any_matched,
                evidence: all_evidence,
                match_count,
                warnings: Vec::new(),
                precision,
                matched_trait_ids: all_trait_ids,
            },
            tags,
        )
    }

    /// Evaluate with count constraints: exact count, min_count, max_count.
    /// Returns (result, tagged_locations) where tagged_locations maps evidence to condition indices.
    pub(super) fn eval_count_constraints<'a>(
        &self,
        conds: &[Condition],
        exact: Option<usize>,
        min: Option<usize>,
        max: Option<usize>,
        ctx: &EvaluationContext<'a>,
    ) -> (ConditionResult, Vec<TaggedLocation>) {
        let mut matched_count = 0;
        let mut all_evidence = Vec::new();
        let mut all_trait_ids = Vec::new();
        let mut precision_sum = 0.0f32;
        let mut tags = Vec::new();

        for (i, condition) in conds.iter().enumerate() {
            let result = self.eval_condition(condition, ctx);
            if result.matched {
                let count_weight = condition_count_weight(condition, &result);
                matched_count += count_weight;
                // Tag evidence locations before merging
                tags.extend(tag_evidence(&result.evidence, i));
                // Limit evidence to prevent explosion
                if all_evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    let remaining = MAX_EVIDENCE_PER_TRAIT - all_evidence.len();
                    all_evidence.extend(result.evidence.into_iter().take(remaining));
                }
                all_trait_ids.extend(result.matched_trait_ids);
                precision_sum += result.precision * count_weight as f32;
            }
        }

        let matched = if let Some(exact_count) = exact {
            // Exact match required
            matched_count == exact_count
        } else {
            // Range check
            let min_ok = min.is_none_or(|m| matched_count >= m);
            let max_ok = max.is_none_or(|m| matched_count <= m);
            min_ok && max_ok
        };

        // Calculate precision: average + 0.5 bonus for count constraint
        let avg_precision = if matched_count > 0 {
            (precision_sum / matched_count as f32) + 0.5 // +0.5 bonus for count constraint
        } else {
            0.0
        };

        // Deduplicate evidence before returning
        let all_evidence = deduplicate_evidence(all_evidence);
        let evidence_for_result = if matched { all_evidence } else { Vec::new() };
        let match_count_for_result = evidence_for_result.len();
        (
            ConditionResult {
                matched,
                evidence: evidence_for_result,
                match_count: match_count_for_result,
                warnings: Vec::new(),
                precision: avg_precision,
                matched_trait_ids: if matched { all_trait_ids } else { Vec::new() },
            },
            if matched { tags } else { Vec::new() },
        )
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

    /// Number of distinct conditions a co-occurrence check (scope, proximity)
    /// must see represented before the rule is allowed to fire. Used by
    /// both [`Self::apply_scope_filter`] and proximity checks.
    pub(super) fn min_distinct_conditions(&self) -> usize {
        let all_count = self.all.as_ref().map_or(0, Vec::len);
        let any_required = if let Some(any) = &self.any {
            // Cap at the number of `any:` entries. A single entry (e.g. a
            // directory-prefix reference) can satisfy a higher `needs:` through
            // multiple matched member traits, but every one of those matches
            // carries the *same* condition index. Scope/proximity filters count
            // distinct condition indices, so requiring more distinct conditions
            // than there are entries is unsatisfiable and would wrongly drop the
            // finding (e.g. `any: [dir-ref]` + `needs: 2`).
            self.needs.unwrap_or(1).min(any.len())
        } else {
            0
        };
        all_count + any_required
    }

    /// A scope bucket must contain every required `all:` condition as well as
    /// enough distinct `any:` conditions. A single distinct-count threshold
    /// is insufficient: with two `all:` legs and two `any:` legs, a bucket
    /// containing one `all:` leg plus both `any:` legs reaches the numeric
    /// threshold while still missing a mandatory condition.
    pub(super) fn scope_bucket_satisfies(
        &self,
        condition_indices: &std::collections::BTreeSet<usize>,
    ) -> bool {
        let all_count = self.all.as_ref().map_or(0, Vec::len);
        if !(0..all_count).all(|index| condition_indices.contains(&index)) {
            return false;
        }

        let any_required = self
            .any
            .as_ref()
            .map_or(0, |any| self.needs.unwrap_or(1).min(any.len()));
        condition_indices
            .range(all_count..all_count + self.any.as_ref().map_or(0, Vec::len))
            .count()
            >= any_required
    }

    /// Restrict evidence to a single scope bucket, per the rule's
    /// `scope:` field.
    ///
    /// Each piece of evidence is keyed by [`Scope::key`] applied to its
    /// `Evidence.location`. Two evidence items share scope iff their keys
    /// are equal. The filter chooses the first scope key whose tagged
    /// evidence covers enough distinct condition indices to satisfy the
    /// rule's positive structure (`all` + `needs`-of-`any`), and drops
    /// every evidence item from other scope buckets.
    ///
    /// Returns `None` if no single scope bucket meets the rule's
    /// minimum-distinct-conditions threshold; otherwise returns the
    /// filtered (`evidence`, `tagged_locations`) pair.
    ///
    /// `archive_contents` and `top_level_file_type` come from the current
    /// `AnalysisReport` and are passed straight through to [`Scope::key`],
    /// which is the only place that reads them (for [`Scope::Package`] and
    /// [`Scope::Archive`]).
    ///
    /// `Scope::Outer` is a no-op fast path: every key is the empty
    /// string, so all evidence is in one bucket.
    pub(super) fn apply_scope_filter(
        &self,
        evidence: Vec<Evidence>,
        tagged_locations: Vec<TaggedLocation>,
        archive_contents: &[crate::types::ArchiveEntry],
        top_level_file_type: &str,
    ) -> Option<(Vec<Evidence>, Vec<TaggedLocation>)> {
        let scope = self.effective_scope();
        if matches!(scope, Scope::Outer) {
            // Pools by presence (empty key) — every item is in one bucket.
            return Some((evidence, tagged_locations));
        }
        let min_distinct = self.min_distinct_conditions();
        if min_distinct == 0 {
            // Vacuous rule (no positive conditions) — scope is moot.
            return Some((evidence, tagged_locations));
        }
        // Collect the unique scope keys appearing in tagged_locations,
        // then for each key count how many distinct condition indices
        // it covers. The first key meeting the threshold wins.
        // BTreeSet for deterministic iteration order — useful for
        // tests and reproducibility.
        let unique_keys: std::collections::BTreeSet<&str> = tagged_locations
            .iter()
            .map(|t| scope.key(t.location.as_deref(), archive_contents, top_level_file_type))
            .collect();
        if unique_keys.iter().all(|k| k.is_empty()) {
            // No location info to bucket on — every tag's scope key is
            // empty (e.g. evidence from metric-derived findings, or
            // AST/positional-only matches that don't carry a file
            // path). Scope can't meaningfully filter, so pass through
            // rather than reject.
            return Some((evidence, tagged_locations));
        }

        // In the container pass a member's findings arrive twice: once with
        // an `archive:<member>` location and once bare (`value:…`, `0x…`,
        // none). Bare evidence keys to "", which spans every member. For
        // `nest` that bucket would join a class with any other class in the
        // JAR -- exactly the pooling the scope exists to prevent -- so an
        // unlocated key never wins a nest.
        let winning_key = unique_keys
            .into_iter()
            .filter(|k| !(matches!(scope, Scope::Nest) && k.is_empty()))
            .find(|k| {
                let conds: std::collections::BTreeSet<usize> = tagged_locations
                    .iter()
                    .filter(|t| {
                        scope.key(t.location.as_deref(), archive_contents, top_level_file_type)
                            == *k
                    })
                    .map(|t| t.condition_index)
                    .collect();
                self.scope_bucket_satisfies(&conds)
            });
        let winning_key = winning_key?.to_string();

        let filtered_tags: Vec<TaggedLocation> = tagged_locations
            .into_iter()
            .filter(|t| {
                scope.key(t.location.as_deref(), archive_contents, top_level_file_type)
                    == winning_key
            })
            .collect();
        let filtered_evidence: Vec<Evidence> = evidence
            .into_iter()
            .filter(|ev| {
                scope.key(
                    ev.location.as_deref(),
                    archive_contents,
                    top_level_file_type,
                ) == winning_key
            })
            .collect();
        Some((filtered_evidence, filtered_tags))
    }

    /// Build the human-readable scope explanation surfaced by `test-rules`:
    /// what one scope bucket must hold, and which legs landed in each bucket,
    /// e.g. `one bucket must hold every all-leg [2] plus 1 of 1 any-legs;
    /// "archive:" {all[0] plugin-descriptor}; "archive:lib/p.jar" {all[1]
    /// ps1, any[0] url}`. Authoring/debug aid only.
    pub(super) fn scope_debug_detail(
        &self,
        tagged_locations: &[TaggedLocation],
        archive_contents: &[crate::types::ArchiveEntry],
        top_level_file_type: &str,
    ) -> String {
        let scope = self.effective_scope();
        let all = self.all.as_deref().unwrap_or_default();
        let any = self.any.as_deref().unwrap_or_default();
        let any_required = if any.is_empty() {
            0
        } else {
            self.needs.unwrap_or(1).min(any.len())
        };
        let label = |index: usize| {
            let (group, position, condition) = if index < all.len() {
                ("all", index, all.get(index))
            } else {
                ("any", index - all.len(), any.get(index - all.len()))
            };
            match condition {
                Some(Condition::Trait { id }) => {
                    let leaf = id.rsplit_once("::").map_or(id.as_str(), |(_, leaf)| leaf);
                    format!("{group}[{position}] {leaf}")
                }
                _ => format!("{group}[{position}]"),
            }
        };
        let mut buckets: std::collections::BTreeMap<&str, std::collections::BTreeSet<usize>> =
            std::collections::BTreeMap::new();
        for tag in tagged_locations {
            buckets
                .entry(scope.key(
                    tag.location.as_deref(),
                    archive_contents,
                    top_level_file_type,
                ))
                .or_default()
                .insert(tag.condition_index);
        }
        let held: Vec<String> = buckets
            .iter()
            .map(|(key, conditions)| {
                let legs: Vec<String> = conditions.iter().map(|&i| label(i)).collect();
                format!("{key:?} {{{}}}", legs.join(", "))
            })
            .collect();
        format!(
            "one bucket must hold every all-leg [{}] plus {any_required} of {} any-legs; {}",
            all.len(),
            any.len(),
            held.join("; ")
        )
    }

    /// Build the human-readable proximity explanation surfaced by `test-rules`:
    /// where each condition group's evidence actually landed and what the
    /// winning window must contain. This makes the pass/fail self-explanatory —
    /// e.g. `all: @ line(s) [106]; any: @ line(s) [38] — window must hold every
    /// all-leg (1) + 1/2 any-leg(s) within 1 line(s)` immediately shows an
    /// author that a fetch and a hidden path 68 lines apart are *not* adjacent.
    /// Authoring/debug aid only; never called on the scan hot path.
    pub(super) fn proximity_debug_detail(
        &self,
        tagged_locations: &[TaggedLocation],
        binary_data: &[u8],
    ) -> String {
        let all_count = self.all.as_ref().map_or(0, Vec::len);
        let any_total = self.any.as_ref().map_or(0, Vec::len);
        let any_required = self
            .any
            .as_ref()
            .map_or(0, |any| self.needs.unwrap_or(1).min(any.len()));

        let line_starts = build_line_index(binary_data);
        let mut all_lines = Vec::new();
        let mut any_lines = Vec::new();
        for t in tagged_locations {
            if let Some(line) = tagged_to_line(t, &line_starts) {
                if t.condition_index < all_count {
                    all_lines.push(line);
                } else {
                    any_lines.push(line);
                }
            }
        }
        all_lines.sort_unstable();
        all_lines.dedup();
        any_lines.sort_unstable();
        any_lines.dedup();

        let (unit, span) = self
            .near_lines
            .map_or_else(|| ("byte", self.near_bytes.unwrap_or(0)), |n| ("line", n));
        let mut req = Vec::new();
        if all_count > 0 {
            req.push(format!("every all-leg ({all_count})"));
        }
        if any_required > 0 {
            req.push(format!("{any_required}/{any_total} any-leg(s)"));
        }
        format!(
            "all: @ line(s) {all_lines:?}; any: @ line(s) {any_lines:?} — window must hold {} within {span} {unit}(s)",
            req.join(" + ")
        )
    }

    /// Check if evidence satisfies proximity constraints.
    /// Returns None if constraints fail, otherwise returns the evidence unchanged.
    ///
    /// When `tagged_locations` is non-empty, proximity requires a window that
    /// reproduces the rule's condition structure: every located `all:` leg plus
    /// at least `needs` distinct `any:` legs (see `window_satisfies_groups`).
    /// When empty, falls back to counting individual evidence items.
    pub(super) fn check_proximity_constraints(
        &self,
        evidence: Vec<Evidence>,
        tagged_locations: &[TaggedLocation],
        binary_data: &[u8],
    ) -> Option<Vec<Evidence>> {
        if self.near_lines.is_none() && self.near_bytes.is_none() {
            return Some(evidence);
        }

        // Proximity needs at least 2 distinct conditions to be meaningful
        // — a single item is vacuously close to itself. (Scope uses the
        // same count without the `.max(2)` floor.)
        let min_distinct = self.min_distinct_conditions().max(2);

        // Condition indices `< all_count` are `all:` legs (each must fall inside
        // the winning window); `>= all_count` are `any:` legs (at least
        // `any_required` distinct ones must). See `window_satisfies_groups`.
        let all_count = self.all.as_ref().map_or(0, Vec::len);
        let any_required = self
            .any
            .as_ref()
            .map_or(0, |any| self.needs.unwrap_or(1).min(any.len()));

        // Track the winning window range for evidence filtering
        let mut line_window: Option<(usize, usize)> = None;
        let mut byte_window: Option<(u64, u64)> = None;
        let mut line_starts_cache: Option<Vec<usize>> = None;

        if !tagged_locations.is_empty() {
            // Cross-condition proximity: the window must reproduce the rule's
            // condition structure (all `all:` legs + enough `any:` legs).
            if let Some(max_line_span) = self.near_lines {
                let line_starts = build_line_index(binary_data);
                let items: Vec<(usize, usize)> = tagged_locations
                    .iter()
                    .filter_map(|t| {
                        tagged_to_line(t, &line_starts).map(|line| (line, t.condition_index))
                    })
                    .collect();
                line_window = Some(evidence_within_line_range_grouped(
                    &items,
                    max_line_span,
                    all_count,
                    any_required,
                    min_distinct,
                )?);
                line_starts_cache = Some(line_starts);
            }

            if let Some(max_byte_span) = self.near_bytes {
                let items: Vec<(u64, usize)> = tagged_locations
                    .iter()
                    .filter_map(|t| tagged_to_byte_offset(t).map(|off| (off, t.condition_index)))
                    .collect();
                byte_window = Some(evidence_within_byte_range_grouped(
                    &items,
                    max_byte_span,
                    all_count,
                    any_required,
                    min_distinct,
                )?);
            }
        } else {
            // Fallback: no condition tags (shouldn't happen for composites, but safe default)
            if let Some(max_line_span) = self.near_lines {
                let line_starts = build_line_index(binary_data);
                line_window = Some(evidence_within_line_range(
                    &evidence,
                    max_line_span,
                    min_distinct,
                    &line_starts,
                )?);
                line_starts_cache = Some(line_starts);
            }

            if let Some(max_byte_span) = self.near_bytes {
                byte_window = Some(evidence_within_byte_range(
                    &evidence,
                    max_byte_span,
                    min_distinct,
                )?);
            }
        }

        // Filter evidence to only items within the winning proximity window
        let filtered: Vec<Evidence> = evidence
            .into_iter()
            .filter_map(|mut ev| {
                if !ev.offsets.is_empty() {
                    ev.offsets.retain(|offset| {
                        if let (Some((start, end)), Some(ls)) = (line_window, &line_starts_cache) {
                            let line = byte_offset_to_line(ls, *offset as usize);
                            return line >= start && line <= end;
                        }
                        byte_window.is_none_or(|(start, end)| *offset >= start && *offset <= end)
                    });
                    let first = *ev.offsets.first()?;
                    ev.count = ev.offsets.len();
                    ev.location = Some(format!("0x{first:x}"));
                    return Some(ev);
                }
                if let (Some((start, end)), Some(ls)) = (line_window, &line_starts_cache)
                    && let Some(line) = evidence_to_line(&ev, ls)
                {
                    return (line >= start && line <= end).then_some(ev);
                }
                if let Some((start, end)) = byte_window
                    && let Some(offset) = evidence_to_byte_offset(&ev)
                {
                    return (offset >= start && offset <= end).then_some(ev);
                }
                // Evidence without location info: keep
                Some(ev)
            })
            .collect();

        Some(filtered)
    }

    /// Returns true if this rule has unless (skip) conditions
    #[must_use]
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

    pub(crate) fn has_negative_conditions(&self) -> bool {
        self.unless.as_ref().map(|n| !n.is_empty()).unwrap_or(false)
    }
}
