//! Composite rule evaluation against analysis reports.
//!
//! This module handles the evaluation of composite rules, which combine multiple
//! atomic traits using logical operators (all, any, none, unless). Features:
//! - Two-pass evaluation (positive rules, then negative rules)
//! - Fixed-point iteration for cascading dependencies
//! - Downgrade re-evaluation with complete finding context

use crate::capabilities::indexes::TraitBitSet;
use crate::composite_rules::PathQuery;
use crate::composite_rules::{
    Arch, EvaluationContext, FileType as RuleFileType, SectionMap, TypeMask,
};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use std::collections::HashMap;

fn immediate_parent_path(path: &str) -> Option<&str> {
    match (path.rfind("!!"), path.rfind("##")) {
        (Some(archive), Some(encoding)) => Some(&path[..archive.max(encoding)]),
        (Some(archive), None) => Some(&path[..archive]),
        (None, Some(encoding)) => Some(&path[..encoding]),
        (None, None) => None,
    }
}

impl super::CapabilityMapper {
    /// Re-evaluate explicit parent-aware downgrades throughout the flat file
    /// tree. Root children use the root report; deeper children use only their
    /// immediate parent's findings. Process parents before children so a
    /// parent's own downgrade is reflected in the context seen below it.
    pub(crate) fn reeval_parent_scope_in_file_tree(
        &self,
        report: &mut AnalysisReport,
        root_bytes: &[u8],
        root_type: RuleFileType,
    ) {
        if report.files.is_empty() {
            return;
        }

        let mut order: Vec<usize> = (0..report.files.len()).collect();
        order.sort_by_key(|&idx| (report.files[idx].depth, report.files[idx].id));
        let file_indices: HashMap<u32, usize> = report
            .files
            .iter()
            .enumerate()
            .map(|(idx, file)| (file.id, idx))
            .collect();
        let mut path_order: Vec<usize> = (0..report.files.len()).collect();
        path_order.sort_unstable_by(|&left, &right| {
            report.files[left].path.cmp(&report.files[right].path)
        });
        // Parent findings and type are supplied separately; retain the root
        // report's other metadata for the evaluation context. Clear root
        // findings from nested contexts because EvaluationContext combines
        // report findings with additional findings.
        let root_report = report.clone();
        let mut nested_parent_report = report.clone();
        nested_parent_report.findings.clear();
        let section_map = SectionMap::default();

        for idx in order {
            let (parent_id, depth) = {
                let child = &report.files[idx];
                (child.parent_id, child.depth)
            };
            if depth == 0 {
                continue;
            }

            let (parent_findings, parent_bytes, parent_type, parent_report) = if depth == 1 {
                (report.findings.clone(), root_bytes, root_type, &root_report)
            } else {
                let parent_idx = parent_id
                    .and_then(|id| file_indices.get(&id).copied())
                    .or_else(|| {
                        let parent_path = immediate_parent_path(&report.files[idx].path)?;
                        path_order
                            .binary_search_by(|&candidate| {
                                report.files[candidate].path.as_str().cmp(parent_path)
                            })
                            .ok()
                            .map(|position| path_order[position])
                    });
                let Some(parent_idx) = parent_idx else {
                    continue;
                };
                let parent = &report.files[parent_idx];
                (
                    parent.findings.clone(),
                    &[][..],
                    RuleFileType::from_str(&parent.file_type),
                    &nested_parent_report,
                )
            };

            self.reeval_downgrades_parent_scope(
                &mut report.files[idx].findings,
                &parent_findings,
                parent_report,
                parent_bytes,
                parent_type,
                &section_map,
            );
        }
    }

    /// Evaluate composite rules against an analysis report.
    /// `inline_yara` supplies pre-scanned results from the combined YARA engine.
    ///
    /// `layer_findings` are the findings of the file's decoded layers (the
    /// `##` records: an escaped or encoded blob the file carries, analyzed as
    /// code). They are inputs only: a composite may take a leg from them, and
    /// one a layer already fired is not fired again, but none of them is
    /// returned. A decoded layer is part of its file, so a rule gated on the
    /// file's type has to see what was decoded out of it; the layer, analyzed
    /// on its own, is not of that type.
    ///
    /// Platform filtering is controlled by the `platform` field set via `with_platform()`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn evaluate_composite_rules(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
        section_map: &SectionMap,
        arch_ranges: Option<&[(Arch, std::ops::Range<usize>)]>,
        suppressions: Option<&crate::types::SuppressionSink>,
        layer_findings: &[Finding],
    ) -> Vec<Finding> {
        // Determine file type from report (platform comes from self.platform)
        let file_type = self.evaluation_file_type(report, binary_data.len());

        // A container report aggregates tens of thousands of members' strings,
        // kv, and evidence, and evaluating the rule set over that value pool is
        // the dominant single-threaded finalize cost — 2026-07-24: ~330 s of a
        // 1,870 s DefinitelyTyped archive scan sat here, stack-attributed to
        // TraitRegex::find_str under eval_string_literal. Rules within one
        // fixed-point iteration are independent (each sees the same immutable
        // ctx snapshot; new findings land only after the collect), so large
        // reports fan the rule loop across the pool. Small files stay
        // sequential: their per-rule work is microseconds and rayon's fan-out
        // overhead would dominate — which is the regime the old always-serial
        // loop was written for.
        let parallel_rules = report.files.len() >= 32 || report.strings.len() >= 20_000;
        // Bitset filter first: it excludes most rules on small files with one
        // dense-index probe, so the string-hash `seen_ids` check only runs for
        // the survivors. This pair ran per rule per fixed-point pass per file
        // and the hash probe was a measured leaf on many-member archives.
        let eval_rules = |rules: &[&crate::composite_rules::CompositeTrait],
                          seen_ids: &rustc_hash::FxHashSet<String>,
                          matched_bits: &TraitBitSet,
                          ctx: &EvaluationContext<'_>|
         -> Vec<Finding> {
            use rayon::prelude::*;
            if parallel_rules && crate::rayon_nest::inner_work_parallel() {
                rules
                    .par_iter()
                    .filter(|rule| matched_bits.contains_all(&rule.required_trait_indices))
                    .filter(|rule| !seen_ids.contains(rule.id.as_str()))
                    .filter_map(|rule| rule.evaluate_pregated(ctx))
                    .filter(|f| !seen_ids.contains(f.id.as_str()))
                    .collect()
            } else {
                rules
                    .iter()
                    .filter(|rule| matched_bits.contains_all(&rule.required_trait_indices))
                    .filter(|rule| !seen_ids.contains(rule.id.as_str()))
                    .filter_map(|rule| rule.evaluate_pregated(ctx))
                    .filter(|f| !seen_ids.contains(f.id.as_str()))
                    .collect()
            }
        };

        // The layer findings lead the accumulated set, so every context below
        // sees them alongside the composites found so far; they are split off
        // again before returning.
        let layer_count = layer_findings.len();
        let mut all_findings: Vec<Finding> = Vec::with_capacity(layer_count + 100);
        all_findings.extend_from_slice(layer_findings);
        let mut seen_ids: rustc_hash::FxHashSet<String> = rustc_hash::FxHashSet::default();

        // Track which composite IDs have already matched (including original findings)
        let mut matched_bits = TraitBitSet::with_capacity(self.trait_definitions.len());
        for finding in report.findings.iter().chain(layer_findings) {
            seen_ids.insert(finding.id.clone().to_string());
            if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                matched_bits.insert(idx);
            }
        }

        // One set of per-file lazy caches for every context this call builds
        // (fixed-point iterations re-create the context to refresh the finding
        // scope, but the file's bytes and strings never change).
        let file_caches = crate::composite_rules::context::FileEvalCaches::default();
        // Work lists prefiltered by the static gates (platform, file type,
        // positive/negative split) — memoized per file type on the mapper.
        // `CompositeTrait::evaluate` still runs its own gates for the dynamic
        // ones (arch, size); the static ones it re-checks are already known
        // to pass. Skip-reason debug info is unaffected: contexts built here
        // never carry a debug collector.
        let worklists = self.composite_worklists(file_type);
        let positive_rules: Vec<&crate::composite_rules::CompositeTrait> = worklists
            .positive
            .iter()
            .map(|&i| &self.composite_rules[i as usize])
            .collect();
        let negative_rules: Vec<&crate::composite_rules::CompositeTrait> = worklists
            .negative
            .iter()
            .map(|&i| &self.composite_rules[i as usize])
            .collect();

        // Pass 1: Iterative evaluation of positive rules to reach a stable fixed-point
        const MAX_ITERATIONS: usize = 10;
        for _ in 0..MAX_ITERATIONS {
            let mut ctx = EvaluationContext::new(
                report,
                binary_data,
                file_type,
                &self.platforms,
                if all_findings.is_empty() {
                    None
                } else {
                    Some(&all_findings)
                },
                cached_ast,
            )
            .with_suppressions(suppressions)
            .with_section_map(section_map)
            .with_file_caches(&file_caches);
            if let Some(results) = inline_yara {
                ctx = ctx.with_inline_yara(results);
            }
            if let Some(ranges) = arch_ranges {
                ctx = ctx.with_arch_ranges(ranges);
            }

            // Evaluate positive rules (parallel only for container-scale reports)
            let new_findings: Vec<Finding> =
                eval_rules(&positive_rules, &seen_ids, &matched_bits, &ctx);

            if new_findings.is_empty() {
                break;
            }

            // Add new findings to the accumulated set
            for finding in new_findings {
                seen_ids.insert(finding.id.clone().to_string());
                if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                    matched_bits.insert(idx);
                }
                all_findings.push(finding);
            }
        }

        // Pass 2: Iteratively evaluate negative rules and re-run positive rules until fixed point.
        //
        // Negative rules (those with `unless:`) are deferred from Pass 1 so their exclusions see
        // the complete positive set. But once a negative rule fires, a downstream positive rule
        // may depend on it — so after each negative pass we re-run positive rules, and vice
        // versa, until no new findings appear.
        for _ in 0..MAX_ITERATIONS {
            let mut ctx = EvaluationContext::new(
                report,
                binary_data,
                file_type,
                &self.platforms,
                if all_findings.is_empty() {
                    None
                } else {
                    Some(&all_findings)
                },
                cached_ast,
            )
            .with_suppressions(suppressions)
            .with_section_map(section_map)
            .with_file_caches(&file_caches);
            if let Some(results) = inline_yara {
                ctx = ctx.with_inline_yara(results);
            }
            if let Some(ranges) = arch_ranges {
                ctx = ctx.with_arch_ranges(ranges);
            }

            let negative_findings: Vec<Finding> =
                eval_rules(&negative_rules, &seen_ids, &matched_bits, &ctx);

            if negative_findings.is_empty() {
                break;
            }
            drop(ctx);
            for finding in negative_findings {
                seen_ids.insert(finding.id.clone().to_string());
                if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                    matched_bits.insert(idx);
                }
                all_findings.push(finding);
            }

            // Re-run positive rules to a fixed point against the enriched findings
            for _ in 0..MAX_ITERATIONS {
                let mut ctx = EvaluationContext::new(
                    report,
                    binary_data,
                    file_type,
                    &self.platforms,
                    Some(&all_findings),
                    cached_ast,
                )
                .with_suppressions(suppressions)
                .with_section_map(section_map)
                .with_file_caches(&file_caches);
                if let Some(results) = inline_yara {
                    ctx = ctx.with_inline_yara(results);
                }
                if let Some(ranges) = arch_ranges {
                    ctx = ctx.with_arch_ranges(ranges);
                }

                let new_findings: Vec<Finding> =
                    eval_rules(&positive_rules, &seen_ids, &matched_bits, &ctx);

                if new_findings.is_empty() {
                    break;
                }
                drop(ctx);
                for finding in new_findings {
                    seen_ids.insert(finding.id.clone().to_string());
                    if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                        matched_bits.insert(idx);
                    }
                    all_findings.push(finding);
                }
            }
        }

        // Pass 3: Re-evaluate downgrades for all findings now that the full context is available.
        // This handles cases where a finding's downgrade depends on another composite that
        // wasn't available when it was first evaluated.
        self.reeval_downgrades(
            &mut all_findings,
            layer_count,
            report,
            binary_data,
            cached_ast,
            file_type,
            section_map,
            suppressions,
        );
        // Excessive-line-length detection (>1MB single line) is emitted by YAML
        // traits, not here: the only input is the `text.max_line_length` metric.
        // JS/TS megabyte lines → line-shape::js-megabyte-single-line (notable);
        // other scripts/source → line-length::excessive-line-length (suspicious).
        // Both carry the binary-blob / minified-bundle carve-outs as `unless:`.

        all_findings.split_off(layer_count)
    }

    /// Re-evaluate downgrade conditions for all findings using the complete finding set.
    /// This handles ordering issues where a composite's downgrade depends on another composite.
    /// `findings[..first]` are context only (a file's decoded-layer findings):
    /// they can satisfy a downgrade condition but are not themselves re-evaluated.
    #[allow(clippy::too_many_arguments)]
    fn reeval_downgrades(
        &self,
        findings: &mut [Finding],
        first: usize,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        file_type: RuleFileType,
        section_map: &SectionMap,
        suppressions: Option<&crate::types::SuppressionSink>,
    ) {
        // Shared lazy rule-ID index: this runs once per analyzed file, so a
        // per-call map build dominated small-member archive corpora.
        let composite_map = self.composite_id_index();
        let file_caches = crate::composite_rules::context::FileEvalCaches::default();

        // First pass: collect new criticalities (can't mutate while borrowing for context)
        let updates: Vec<(usize, Criticality)> = {
            // Create final context with all findings (immutable borrow)
            let ctx = EvaluationContext::new(
                report,
                binary_data,
                file_type,
                &self.platforms,
                Some(findings),
                cached_ast,
            )
            .with_suppressions(suppressions)
            .with_section_map(section_map)
            .with_file_caches(&file_caches);

            findings
                .iter()
                .enumerate()
                .skip(first)
                .filter_map(|(i, finding)| {
                    // Every downgrade, whatever its scope: this context holds
                    // only this file's findings, so a file-scoped downgrade
                    // cannot reach another member here. (The scope filter
                    // belongs to `reeval_downgrades_cross_scope`, whose context
                    // adds container findings.) Evaluated from the declared
                    // tier and applied only when lower, so a downgrade that
                    // already fired at match time is not applied twice.
                    let rule = composite_map
                        .get(finding.id.as_str())
                        .map(|&i| &self.composite_rules[i])?;
                    let downgrade_rules = rule.downgrade.as_ref()?;
                    if downgrade_rules.scope == Some(crate::composite_rules::Scope::Parent) {
                        return None;
                    }
                    let new_crit = rule.evaluate_downgrade(downgrade_rules, &rule.crit, &ctx);
                    (new_crit < finding.crit).then_some((i, new_crit))
                })
                .collect()
        };

        // Second pass: apply updates
        for (idx, new_crit) in updates {
            // Mark the demotion so `strip_unmatched_traits` keeps the finding at
            // the tier the downgrade asked for instead of dropping it as an
            // unreferenced low-tier finding.
            findings[idx].downgraded = true;
            findings[idx].crit = new_crit;
        }
    }

    /// Re-evaluate downgrades on `target_findings` with `extra_findings` mixed
    /// into the evaluation context.
    ///
    /// Used after container-level composites have been added to the report:
    /// per-file findings get a second chance to apply downgrades that
    /// reference container-level traits (e.g. a per-file `cookies-get-all`
    /// trait whose downgrade clause references the container-level
    /// `metadata/signed/platform::mozilla-extension` composite).
    ///
    /// Idempotent: each finding's downgrade is re-evaluated starting from
    /// the trait/composite's *declared* criticality (looked up in
    /// `trait_definitions` / `composite_rules`), not from the finding's
    /// current crit. Calling this twice yields the same result as calling
    /// it once.
    pub(crate) fn reeval_downgrades_cross_scope(
        &self,
        target_findings: &mut [crate::types::Finding],
        extra_findings: &[crate::types::Finding],
        report: &AnalysisReport,
        binary_data: &[u8],
        file_type: RuleFileType,
        section_map: &SectionMap,
    ) {
        if target_findings.is_empty() {
            return;
        }

        // The evaluator must see both the target's own findings (which
        // trait-reference conditions check against) and the container-level
        // extras. Only the target's few findings are cloned (they are mutated
        // below while the context still needs their pre-pass values); the
        // extras — invariant across the per-member fan-out — stay borrowed.
        // Scope order (report, target, extras) matches the old combined-slice
        // shape exactly.
        let target_snapshot: Vec<crate::types::Finding> = target_findings.to_vec();
        let file_caches = crate::composite_rules::context::FileEvalCaches::default();
        let ctx = EvaluationContext::new(
            report,
            binary_data,
            file_type,
            &self.platforms,
            Some(extra_findings),
            None,
        )
        .with_mid_findings(&target_snapshot)
        .with_section_map(section_map)
        .with_file_caches(&file_caches);

        // Shared lazy rule-ID index: this runs once per archive member in the
        // container phase, so a per-call map build dominated small-member
        // corpora.
        let composite_by_id = self.composite_id_index();

        for finding in target_findings.iter_mut() {
            // Atomic traits first: look up the TraitDefinition by id and
            // re-evaluate its downgrade clause if any.
            if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                let trait_def = &self.trait_definitions[idx];
                if let Some(downgrade) = &trait_def.downgrade
                    && downgrade_spans_container(downgrade)
                {
                    let new_crit = trait_def.evaluate_downgrade(downgrade, &trait_def.crit, &ctx);
                    if new_crit != finding.crit {
                        finding.downgraded = true;
                        finding.crit = new_crit;
                    }
                    continue;
                }
            }

            // Composite rules: same dance, but against composite_rules.
            if let Some(rule) = composite_by_id
                .get(finding.id.as_str())
                .map(|&i| &self.composite_rules[i])
                && let Some(downgrade) = &rule.downgrade
                && downgrade_spans_container(downgrade)
            {
                let new_crit = rule.evaluate_downgrade(downgrade, &rule.crit, &ctx);
                if new_crit != finding.crit {
                    finding.downgraded = true;
                    finding.crit = new_crit;
                }
            }
        }
    }

    /// Re-evaluate explicit parent-aware downgrades for an analyzed child.
    /// `scope: parent` sees only the immediate parent's findings;
    /// `scope: file-or-parent` sees both the child and its immediate parent.
    /// This is separate from archive pooling, so siblings and more distant
    /// ancestors are never admitted to either context.
    pub(crate) fn reeval_downgrades_parent_scope(
        &self,
        target_findings: &mut [crate::types::Finding],
        parent_findings: &[crate::types::Finding],
        parent_report: &AnalysisReport,
        parent_bytes: &[u8],
        parent_type: RuleFileType,
        section_map: &SectionMap,
    ) {
        if target_findings.is_empty() {
            return;
        }

        let file_caches = crate::composite_rules::context::FileEvalCaches::default();
        let parent_ctx = EvaluationContext::new(
            parent_report,
            parent_bytes,
            parent_type,
            &self.platforms,
            Some(parent_findings),
            None,
        )
        .with_section_map(section_map)
        .with_file_caches(&file_caches);
        let target_snapshot: Vec<crate::types::Finding> = target_findings.to_vec();
        let file_or_parent_ctx = EvaluationContext::new(
            parent_report,
            parent_bytes,
            parent_type,
            &self.platforms,
            Some(parent_findings),
            None,
        )
        .with_mid_findings(&target_snapshot)
        .with_section_map(section_map)
        .with_file_caches(&file_caches);
        let composite_by_id = self.composite_id_index();

        for finding in target_findings.iter_mut() {
            let downgrade = self
                .trait_id_map
                .get(finding.id.as_str())
                .and_then(|&idx| self.trait_definitions[idx].downgrade.as_ref())
                .or_else(|| {
                    composite_by_id
                        .get(finding.id.as_str())
                        .and_then(|&idx| self.composite_rules[idx].downgrade.as_ref())
                });
            if let Some(downgrade) = downgrade
                && matches!(
                    downgrade.scope,
                    Some(
                        crate::composite_rules::Scope::Parent
                            | crate::composite_rules::Scope::FileOrParent
                    )
                )
            {
                let ctx = if downgrade.scope == Some(crate::composite_rules::Scope::Parent) {
                    &parent_ctx
                } else {
                    &file_or_parent_ctx
                };
                let new_crit = if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                    let rule = &self.trait_definitions[idx];
                    rule.evaluate_downgrade(downgrade, &rule.crit, ctx)
                } else if let Some(rule) = composite_by_id
                    .get(finding.id.as_str())
                    .map(|&idx| &self.composite_rules[idx])
                {
                    rule.evaluate_downgrade(downgrade, &rule.crit, ctx)
                } else {
                    finding.crit
                };
                if new_crit < finding.crit {
                    finding.downgraded = true;
                    finding.crit = new_crit;
                }
            }
        }
    }

    /// Evaluate composite rules at the container level using findings from all nested files.
    ///
    /// This enables cross-file composite rules that can detect patterns spanning multiple
    /// files within an archive. For example:
    /// - "npm package with suspicious DLL" (package.json in one file + .dll in another)
    /// - "Python package with compiled binary" (setup.py + .so/.pyd files)
    ///
    /// # Arguments
    /// * `container_report` - The container/archive report to add findings to
    /// * `nested_findings` - All findings from nested files within the container
    /// * `file_type` - File type of the container (e.g., "archive", "zip")
    ///
    /// # Returns
    /// New findings that should be added to the container report
    #[must_use]
    /// Evaluate `type: basename` traits against a list of archive entry names.
    ///
    /// Archive members are extracted to temp paths, so per-file analyzers see
    /// basenames like `.tmpXXXXX` instead of the original entry names. This
    /// method evaluates basename traits using the real entry names and returns
    /// component-level findings that container composites can then reference.
    pub(crate) fn evaluate_basename_traits_for_entries(
        &self,
        entry_names: &[String],
    ) -> Vec<Finding> {
        use crate::composite_rules::Condition;
        use rayon::prelude::*;

        #[derive(Clone, Copy)]
        enum Scope {
            Base,
            Dir,
            Full,
        }

        // Hoist the per-trait constants (lowercased patterns, resolved regex)
        // out of the entry loop: the previous shape recomputed them — plus two
        // allocations — for every (trait × entry) pair, which on a 13k-member
        // archive was a measurable single-threaded tail.
        struct PathTrait<'a> {
            trait_def: &'a crate::composite_rules::TraitDefinition,
            /// Lowercased when `case_insensitive`, matching the target's casing.
            exact: Option<String>,
            substr: Option<String>,
            regex: Option<std::sync::Arc<crate::composite_rules::condition::TraitRegex>>,
            case_insensitive: bool,
            scope: Scope,
        }

        let path_traits: Vec<PathTrait<'_>> = self
            .trait_definitions
            .iter()
            .filter_map(|trait_def| {
                // `basename` matches the final path component; `path` matches the
                // full entry path (or its dir/base when scoped). Archive members
                // carry their real entry path, so `path` traits detect member
                // layouts (`node_modules/X/package.json`, nested `*.jar!…`, …).
                let Condition::Path(PathQuery {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                    basename,
                    dirname,
                    ..
                }) = &trait_def.r#if
                else {
                    return None;
                };
                let case_insensitive = *case_insensitive;
                let lower = |s: &String| {
                    if case_insensitive {
                        s.to_lowercase()
                    } else {
                        s.clone()
                    }
                };
                Some(PathTrait {
                    trait_def,
                    exact: exact.as_ref().map(lower),
                    substr: substr.as_ref().map(lower),
                    // Resolve the regex lazily + shared via `lazy_regex` (applies
                    // `(?i)` when case-insensitive) rather than storing it per
                    // condition.
                    regex: regex.as_deref().and_then(|r| {
                        crate::composite_rules::condition::lazy_regex(Some(r), case_insensitive)
                    }),
                    case_insensitive,
                    scope: if *basename {
                        Scope::Base
                    } else if *dirname {
                        Scope::Dir
                    } else {
                        Scope::Full
                    },
                })
            })
            .collect();

        // Each trait yields at most one finding (first matching entry), so the
        // collected order — and therefore the output — stays trait-definition
        // order exactly as the serial loop produced it.
        let evaluate = |pt: &PathTrait<'_>| {
            let matched_entry = entry_names.iter().find(|entry_name| {
                let target: &str = match pt.scope {
                    Scope::Base => {
                        crate::composite_rules::evaluators::misc::path_basename(entry_name)
                    }
                    Scope::Dir => {
                        crate::composite_rules::evaluators::misc::path_dirname(entry_name)
                    }
                    Scope::Full => entry_name.as_str(),
                };
                if target.is_empty() {
                    return false;
                }
                if pt.exact.is_some() || pt.substr.is_some() {
                    let cmp_target = if pt.case_insensitive {
                        std::borrow::Cow::Owned(target.to_lowercase())
                    } else {
                        std::borrow::Cow::Borrowed(target)
                    };
                    if let Some(e) = &pt.exact {
                        cmp_target.as_ref() == e
                    } else {
                        // substr is Some by the branch condition above.
                        pt.substr.as_deref().is_some_and(|s| cmp_target.contains(s))
                    }
                } else if let Some(re) = &pt.regex {
                    re.is_match(target)
                } else {
                    false
                }
            })?;
            let trait_def = pt.trait_def;
            Some(Finding {
                precomputed_spans: None,
                src: None,
                id: trait_def.shared_id(),
                kind: FindingKind::Indicator,
                desc: trait_def.shared_desc(),
                conf: trait_def.conf,
                crit: trait_def.crit,
                mbc: trait_def.mbc.as_deref().map(Into::into),
                attack: trait_def.attack.as_deref().map(Into::into),
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "basename".to_string(),
                    source: "archive-entry".to_string(),
                    value: matched_entry.clone(),
                    // Archive-entry name match describes the whole entry.
                    location: Some("0x0".to_string()),
                    ..Default::default()
                }],
                match_count: 0,
                source_file: None,
                downgraded: false,
            })
        };
        if crate::rayon_nest::inner_work_parallel() {
            path_traits.par_iter().filter_map(evaluate).collect()
        } else {
            path_traits.iter().filter_map(evaluate).collect()
        }
    }

    /// Evaluate full-path and basename traits for one decoded file after an
    /// archive analyzer has rebased its virtual path to the real member path.
    /// Member analyzers may run against temporary extraction paths, so path
    /// traits need this final pass to see the provenance-bearing `!!` / `##`
    /// path. Unlike archive-inventory matching, a file-type gate is available
    /// here and is applied before returning findings.
    pub(crate) fn evaluate_path_traits_for_file(
        &self,
        path: &str,
        file_type: &str,
    ) -> Vec<Finding> {
        let mut findings = self.evaluate_basename_traits_for_entries(&[path.to_string()]);
        let rule_file_type = self.detect_file_type(file_type);
        findings.retain(|finding| {
            self.trait_id_map
                .get(finding.id.as_str())
                .and_then(|&idx| self.trait_definitions.get(idx))
                .is_some_and(|definition| {
                    crate::composite_rules::FileType::rule_applies_to(
                        &definition.r#for,
                        rule_file_type,
                    )
                })
        });
        findings
    }

    /// `finding_origins` maps a finding id to the OR of the `type_bit`s of the
    /// files it was found in, and drives the `for:` filter (see
    /// `EvaluationContext::origin_allows`). `None` disables the filter for this
    /// container -- the honest option for a call site that cannot say where its
    /// findings came from, since the alternative is every composite here
    /// silently losing its legs.
    pub(crate) fn evaluate_container_composites(
        &self,
        container_report: &AnalysisReport,
        nested_findings: &[Finding],
        file_type: &str,
        finding_origins: Option<&rustc_hash::FxHashMap<String, TypeMask>>,
    ) -> Vec<Finding> {
        // Detect file type for the container
        let rule_file_type = self.detect_file_type(file_type);

        // Container-level rules may need the parent archive bytes themselves
        // (for ZIP headers, member names, encrypted-entry markers, etc.).
        let container_bytes =
            std::fs::read(&container_report.target.path).unwrap_or_else(|_| Vec::new());

        // Track which composite IDs have already matched
        let mut seen_ids: rustc_hash::FxHashSet<String> = rustc_hash::FxHashSet::default();
        let mut matched_bits = TraitBitSet::with_capacity(self.trait_definitions.len());
        for finding in &container_report.findings {
            seen_ids.insert(finding.id.clone().to_string());
            if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                matched_bits.insert(idx);
            }
        }
        for finding in nested_findings {
            if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                matched_bits.insert(idx);
            }
        }

        // Evaluate parent/container atomic traits against the container bytes first.
        // This allows archive-focused atomics (raw, yara, basename-derived, etc.)
        // to seed findings for later container-level composites.
        let parent_trait_ctx = EvaluationContext::new(
            container_report,
            &container_bytes,
            rule_file_type,
            &self.platforms,
            Some(nested_findings),
            None, // No AST for container
        );
        // Pre-apply `evaluate_with_gates`' file-type gate: of ~70k traits only
        // the container-capable ones (`for: all`, the container's own type, or
        // the generic container it is built on) can match, and paying the
        // evaluate prelude for the rest cost ~0.5 s of the calling thread per
        // archive.
        let mut container_findings: Vec<Finding> = self
            .trait_definitions
            .iter()
            .filter(|t| crate::composite_rules::FileType::rule_applies_to(&t.r#for, rule_file_type))
            .filter_map(|trait_def| trait_def.evaluate(&parent_trait_ctx))
            .filter(|f| !seen_ids.contains(f.id.as_str()))
            .collect();

        for finding in &container_findings {
            seen_ids.insert(finding.id.clone().to_string());
            if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                matched_bits.insert(idx);
            }
        }

        // The container's own `scope: file` composites (see
        // `evaluate_container_self_scope`) run first, so that a pooling
        // composite below can use one as a leg: `scope: outer` over an
        // APK-layout composite whose legs are the APK's own member list.
        self.evaluate_container_self_scope(
            container_report,
            &container_bytes,
            rule_file_type,
            &mut container_findings,
            &mut seen_ids,
        );

        let mut combined_findings = nested_findings.to_vec();
        combined_findings.extend(container_findings.iter().cloned());

        // `finding_origins` is built by the caller before this pass, so it
        // cannot know the composites this pass produces. Without an origin a
        // finding fails every restricted `for:` mask (`origin_allows`), which
        // made a container-level composite unusable as a leg of another: the
        // chain resolved in `test-rules` (no origins) and never in a scan. A
        // composite produced here is a finding *of the container node*, so it
        // is stamped with the container's own type, exactly like the
        // container's atomics.
        let container_bit = rule_file_type.type_bit();
        let mut origins: Option<rustc_hash::FxHashMap<String, TypeMask>> = finding_origins.cloned();
        let stamp = |origins: &mut Option<rustc_hash::FxHashMap<String, TypeMask>>, id: &str| {
            if let Some(map) = origins.as_mut() {
                *map.entry(id.to_string()).or_default() |= container_bit;
            }
        };
        for finding in &container_findings {
            stamp(&mut origins, finding.id.as_str());
        }

        // Evaluate all composite rules at container level. Rules can match on:
        // - nested file findings across the container
        // - parent/container atomics evaluated above
        // This enables cross-file patterns like "npm package with .dll" and
        // parent-byte patterns like encrypted ZIP/APK members.

        // Reach a fixed point before finishing the negative-condition pass.
        // A fixed five-round budget can be consumed entirely by positive
        // dependencies, starving every rule with `unless:`. Each productive
        // round inserts at least one previously unseen composite ID, so the
        // rule count bounds productive rounds; one final round proves stability.
        for _ in 0..=self.composite_rules.len() {
            let mut ctx = EvaluationContext::new(
                container_report,
                &container_bytes,
                rule_file_type,
                &self.platforms,
                Some(&combined_findings),
                None, // No AST for container
            );
            ctx.finding_origins = origins.as_ref();
            // Rules are evaluated one at a time so `for_mask` can be set per
            // rule: it is the only piece of per-rule state the condition
            // evaluators need, and threading it through every evaluator
            // signature would touch dozens of call sites to say one thing.
            // Same shape as `current_trait_idx` in the atomic pass.
            let candidates: Vec<&crate::composite_rules::CompositeTrait> = self
                .composite_rules
                .iter()
                .filter(|rule| !seen_ids.contains(rule.id.as_str()))
                // Only cross-file scopes may pool here. Nested findings arrive
                // without per-member evidence locations, so `Scope::key` maps
                // them all to the empty key: a `scope: file` (the default) or
                // `scope: leaf` composite would then treat two legs found in
                // two unrelated archive members as same-file evidence and fire.
                // That is the same hazard `evaluate_package_composites` below
                // already documents and excludes for.
                //
                // Nothing is lost by skipping them: file/leaf composites are
                // evaluated per member in the ordinary per-file pass, and
                // against the container itself when the archive is analyzed as
                // a file. Worked example: a source tarball carrying an HTML doc
                // with a `function foo(` and, in a different member, a `.js`
                // that calls `String.fromCharCode` satisfied
                // `noncode-container-selfdecoding-script` -- a hostile verdict
                // on OpenSSH, Caddy and llama_index, despite the rule declaring
                // `for: [chm, oledoc, ooxml, rtf, pdf]` and `scope: file`.
                .filter(|rule| {
                    // `scope:` omitted resolves to `Scope::File`: it is the
                    // enum's `#[default]`, and `apply_scope_filter` reads it
                    // through `unwrap_or_default`. Matching the raw `Option`
                    // here exempted only *explicit* `scope: file`, so the ~98%
                    // of composites that omit `scope:` pooled across unrelated
                    // archive members — the hazard described above, reached via
                    // the default instead of an explicit scope. Worked example:
                    // `perl-packed-hex-command-loader` (`for: [perl]`, hostile)
                    // fired on a Fedora source RPM with its four legs coming
                    // from four unrelated vendored files. Resolve the default
                    // via `effective_scope` (which also picks up the new
                    // archive/package `for:`-based defaults), so only rules
                    // that opt in to cross-file pooling are evaluated here.
                    !matches!(
                        rule.effective_scope(),
                        crate::composite_rules::Scope::File | crate::composite_rules::Scope::Leaf
                    )
                })
                .collect();
            let positive_candidates: Vec<_> = candidates
                .iter()
                .copied()
                .filter(|rule| !rule.has_negative_conditions())
                .collect();
            let negative_candidates: Vec<_> = candidates
                .into_iter()
                .filter(|rule| rule.has_negative_conditions())
                .collect();
            let mut new_findings: Vec<Finding> = Vec::new();
            for rule in positive_candidates {
                ctx.for_mask = rule.for_mask();
                if let Some(finding) = rule.evaluate(&ctx)
                    && !seen_ids.contains(finding.id.as_str())
                {
                    new_findings.push(finding);
                }
            }
            ctx.for_mask = TypeMask::ALL;

            if !new_findings.is_empty() {
                drop(ctx);
                for finding in new_findings {
                    stamp(&mut origins, finding.id.as_str());
                    seen_ids.insert(finding.id.clone().to_string());
                    combined_findings.push(finding.clone());
                    container_findings.push(finding);
                }
                let self_new = self.evaluate_container_self_scope(
                    container_report,
                    &container_bytes,
                    rule_file_type,
                    &mut container_findings,
                    &mut seen_ids,
                );
                for finding in &self_new {
                    stamp(&mut origins, finding.id.as_str());
                }
                combined_findings.extend(self_new);
                continue;
            }

            // The positive set is stable, so `unless:` composites can now
            // observe any matching exception composites before they emit host
            // findings. Keep them in their own pass just as the ordinary
            // per-file evaluator does.
            let mut negative_findings: Vec<Finding> = Vec::new();
            for rule in negative_candidates {
                ctx.for_mask = rule.for_mask();
                if let Some(finding) = rule.evaluate(&ctx)
                    && !seen_ids.contains(finding.id.as_str())
                {
                    negative_findings.push(finding);
                }
            }
            ctx.for_mask = TypeMask::ALL;
            drop(ctx);

            if negative_findings.is_empty() {
                break;
            }

            for finding in negative_findings {
                stamp(&mut origins, finding.id.as_str());
                seen_ids.insert(finding.id.clone().to_string());
                combined_findings.push(finding.clone());
                container_findings.push(finding);
            }
        }

        // The loop above deliberately skips `scope: file` and `scope: leaf`
        // composites, because nested findings arrive without a member location
        // and pooling two unrelated members' legs into one "file" is how
        // OpenSSH and a Fedora source RPM earned hostile verdicts.
        //
        // That exclusion also caught a case with nothing to pool. A container's
        // *own* traits -- `chm.html_entry_count`, `rpm.*`, `vsix.*`, the parent
        // atomics evaluated above -- all describe one object: the container
        // file itself. A `scope: file` composite over those is asking exactly
        // what `scope: file` means, and the answer is unambiguous.
        //
        // So run the skipped rules once more against container-level findings
        // alone. Nested findings are not in scope here, which is what makes it
        // safe: there is only one file in this set, so nothing can pool.
        //
        // Symptom this fixes: fifteen abuse.ch CHM droppers scored four
        // notables and nothing else, while `chm-tiny-payload`,
        // `chm-single-entry-active-container` and two *hostile* rules written
        // for exactly that shape never fired. `test-rules` resolved them all,
        // which is the tell -- it evaluates a rule directly and never applies
        // this filter.
        self.evaluate_container_self_scope(
            container_report,
            &container_bytes,
            rule_file_type,
            &mut container_findings,
            &mut seen_ids,
        );

        tracing::debug!(
            findings = ?container_findings.iter().map(|finding| finding.id.as_str()).collect::<Vec<_>>(),
            "Container composites evaluated"
        );

        // Mark container-level findings with source context
        for finding in &mut container_findings {
            if finding.evidence.is_empty() {
                finding.evidence.push(Evidence {
                    method: "container-composite".to_string(),
                    source: "cross-file-analysis".to_string(),
                    value: "Finding spans multiple files in container".to_string(),
                    // Cross-file container finding — anchor at the container head.
                    location: Some("0x0".to_string()),
                    ..Default::default()
                });
            }
        }

        container_findings
    }

    /// Run the container's own `scope: file` / `scope: leaf` composites to a
    /// fixed point, over container-level findings only (never nested member
    /// findings, so nothing can pool across members). Appends new findings to
    /// `container_findings`, records them in `seen_ids`, and returns them so
    /// the caller can feed them to the pooling pass.
    ///
    /// This was a single pass, so only the first level of a composite chain
    /// resolved: `android-apk-archive-layout` (three member-path atoms) fired,
    /// but every composite built on it -- at any crit, in any scope -- stayed
    /// dark in a scan while `test-rules`, which evaluates rules directly,
    /// reported them all matched.
    fn evaluate_container_self_scope(
        &self,
        container_report: &AnalysisReport,
        container_bytes: &[u8],
        rule_file_type: RuleFileType,
        container_findings: &mut Vec<Finding>,
        seen_ids: &mut rustc_hash::FxHashSet<String>,
    ) -> Vec<Finding> {
        let self_rules: Vec<&crate::composite_rules::CompositeTrait> = self
            .composite_rules
            .iter()
            .filter(|rule| {
                matches!(
                    rule.effective_scope(),
                    crate::composite_rules::Scope::File | crate::composite_rules::Scope::Leaf
                )
            })
            .collect();
        let mut added: Vec<Finding> = Vec::new();
        // Each productive round adds at least one unseen rule id, so the rule
        // count bounds the rounds; the last round proves stability.
        for _ in 0..=self_rules.len() {
            let container_only: Vec<Finding> = container_report
                .findings
                .iter()
                .chain(container_findings.iter())
                .cloned()
                .collect();
            let self_ctx = EvaluationContext::new(
                container_report,
                container_bytes,
                rule_file_type,
                &self.platforms,
                Some(&container_only),
                None, // No AST for container
            );
            let round: Vec<Finding> = self_rules
                .iter()
                .filter(|rule| !seen_ids.contains(rule.id.as_str()))
                .filter_map(|rule| rule.evaluate(&self_ctx))
                .filter(|f| !seen_ids.contains(f.id.as_str()))
                .collect();
            if round.is_empty() {
                break;
            }
            for finding in round {
                seen_ids.insert(finding.id.clone().to_string());
                container_findings.push(finding.clone());
                added.push(finding);
            }
        }
        added
    }

    /// Evaluate package-scoped composites over the union of a fetched
    /// artifact's findings and its registry metadata's findings.
    ///
    /// This is the fetch-driven counterpart to
    /// [`Self::evaluate_container_composites`]: it lets a composite correlate a
    /// registry fact (deprecated, low downloads, fresh publish) with a behavior
    /// in the artifact bytes, even though the two were analyzed separately and
    /// never share an archive. The "package" is a synthetic, byte-less
    /// container — there is no on-disk file for the pair — so only
    /// finding-based composites pool here.
    ///
    /// Only composites with `scope: outer` participate. `scope: package` no
    /// longer means "pool by presence" — it now means "nearest enclosing
    /// package-ecosystem archive," a real location-keyed scope evaluated
    /// through the normal per-node pass, same as `archive`. `outer` is the
    /// one scope left that pools by presence (empty scope key), which is what
    /// this synthetic pass needs: by the time the artifact and registry
    /// reports meet they are both finalized, so their evidence locations are
    /// gone, and a location-keyed scope would collapse every item to the
    /// empty key and fire spuriously. `file`/`archive`/`leaf`/`package` are
    /// excluded for that reason. Returns only newly-matched composite
    /// findings (none of the `seed_findings` are echoed back).
    #[must_use]
    pub(crate) fn evaluate_package_composites(&self, seed_findings: &[Finding]) -> Vec<Finding> {
        use crate::composite_rules::Scope;

        // Composites that pool across the artifact↔registry boundary.
        let package_rules: Vec<&crate::composite_rules::CompositeTrait> = self
            .composite_rules
            .iter()
            .filter(|r| matches!(r.scope, Some(Scope::Outer)))
            .collect();
        if package_rules.is_empty() {
            return Vec::new();
        }

        // A synthetic node with no bytes of its own, typed `registry`: this is
        // the registry-joined view of the artifact, and `for:` gates it like
        // any other node. It used to be typed `all`, which worked only while
        // the gate treated a node of type `All` as a wildcard admitting every
        // rule. That carve-out is gone (see `evaluate_with_gates`), so a rule
        // that wants to run here says so: `for: [registry, <what it mixes>]`.
        let report = AnalysisReport::new(crate::types::TargetInfo {
            path: String::new(),
            file_type: "registry".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });
        let no_bytes: &[u8] = &[];

        let mut combined = seed_findings.to_vec();
        let mut seen_ids: std::collections::HashSet<crate::types::Istr> =
            combined.iter().map(|f| f.id.clone()).collect();
        let mut new_findings: Vec<Finding> = Vec::new();

        // Fixed-point loop so a package composite can feed another.
        const MAX_ITERATIONS: usize = 5;
        for _ in 0..MAX_ITERATIONS {
            // No `finding_origins` here: by the time the artifact and registry
            // reports meet, both are finalized and merged into one seed list
            // with no side marked, so nothing can be stamped. `for:` still
            // gates the node (it must name `registry`); it just cannot also
            // filter which side a leg came from. See SCOPE_PLAN.md ("Open").
            let ctx = EvaluationContext::new(
                &report,
                no_bytes,
                RuleFileType::Registry,
                &self.platforms,
                Some(&combined),
                None,
            );
            let matched: Vec<Finding> = package_rules
                .iter()
                .filter(|rule| !seen_ids.contains(rule.id.as_str()))
                .filter_map(|rule| rule.evaluate(&ctx))
                .filter(|f| !seen_ids.contains(f.id.as_str()))
                .collect();
            if matched.is_empty() {
                break;
            }
            for finding in matched {
                seen_ids.insert(finding.id.clone().to_string().into());
                combined.push(finding.clone());
                new_findings.push(finding);
            }
        }
        new_findings
    }
}

/// Whether a `downgrade:` asked to see evidence from outside its own file.
///
/// The default is [`Scope::File`], which is what `unless:` has always done: a
/// suppressor resolves against the file the rule matched in. Only a block that
/// explicitly widens its scope takes part in the container pass below, so one
/// archive member can no longer silence a rule in an unrelated member unless
/// the rule author asked for exactly that.
fn downgrade_spans_container(downgrade: &crate::composite_rules::DowngradeConditions) -> bool {
    downgrade.scope.unwrap_or_default().pools_members()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use crate::capabilities::mapper::RuleFileType;
    use crate::composite_rules::TypeMask;
    use crate::types::{AnalysisReport, Criticality, Finding, TargetInfo};

    fn make_test_report() -> AnalysisReport {
        AnalysisReport::new(TargetInfo {
            path: "test.zip".to_string(),
            file_type: "zip".to_string(),
            size_bytes: 1000,
            sha256: "abc123".to_string(),
            architectures: None,
        })
    }

    fn make_test_finding(id: &str, crit: Criticality) -> Finding {
        Finding::capability(id.to_string(), format!("Test finding: {}", id), 0.9)
            .with_criticality(crit)
    }

    #[allow(clippy::expect_used)]
    fn write_test_traits(yaml: &str) -> tempfile::NamedTempFile {
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().expect("create temp yaml");
        file.write_all(yaml.as_bytes()).expect("write temp yaml");
        file
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn selected_container_suppression_rechecks_parent_aware_member_findings() {
        let yaml = r#"
defaults:
  platforms: [windows, unix]
traits:
  - id: "test/context::published-tool"
    desc: "Published tool identity"
    crit: notable
    for: [zip]
    if:
      type: basename
      exact: "unused-parent-marker"
  - id: "test/leg::remote-command"
    desc: "Remote command behavior"
    crit: notable
    for: [python]
    if:
      type: basename
      exact: "unused-member-marker"
composite_rules:
  - id: "test/member::known-remote-tool"
    desc: "Known remote tool with command behavior"
    crit: hostile
    for: [python, zip]
    scope: archive
    all:
      - id: "test/leg::remote-command"
    unless:
      - id: "test/context::published-tool"
    downgrade:
      scope: parent
      any:
        - id: "test/context::published-tool"
  - id: "test/member::local-only"
    desc: "Member-local command behavior"
    crit: hostile
    for: [python]
    all:
      - id: "test/leg::remote-command"
    unless:
      - id: "test/context::published-tool"
"#;
        let file = write_test_traits(yaml);
        let mapper = super::super::CapabilityMapper::from_yaml(file.path()).expect("load mapper");
        let report = make_test_report();
        let parent = vec![make_test_finding(
            "test/context::published-tool",
            Criticality::Notable,
        )];

        let mut child = vec![make_test_finding(
            "test/member::known-remote-tool",
            Criticality::Hostile,
        )];
        mapper.reeval_downgrades_parent_scope(
            &mut child,
            &parent,
            &report,
            &[],
            RuleFileType::Zip,
            &crate::composite_rules::SectionMap::default(),
        );
        assert_eq!(child[0].crit, Criticality::Suspicious);

        let mut container = vec![
            make_test_finding("test/context::published-tool", Criticality::Notable),
            make_test_finding("test/member::known-remote-tool", Criticality::Hostile),
            make_test_finding("test/member::local-only", Criticality::Hostile),
        ];
        mapper.apply_retroactive_unless_suppression_to_selected_findings(
            &mut container,
            &rustc_hash::FxHashSet::default(),
        );
        let ids: Vec<_> = container
            .iter()
            .map(|finding| finding.id.as_str())
            .collect();
        assert!(
            !ids.contains(&"test/member::known-remote-tool"),
            "the inherited copy should be removed by its matched parent exception"
        );
        assert!(
            ids.contains(&"test/member::local-only"),
            "a sibling exception must not erase findings without an explicit parent scope"
        );
    }

    /// The per-file composite work list is the gate a scan actually applies
    /// (`evaluate_pregated` skips its own `for:` check), so it must admit
    /// exactly what `CompositeTrait::evaluate` admits. It had drifted back to
    /// the any-archive-for-any-archive carve-out: a `for: [android_apk]`
    /// composite ran on JARs and a `for: [jar]` one on CRXs during a scan,
    /// while `test-rules` (which runs the strict gate) said they could not.
    /// A composite over a container-level composite must resolve in a scan,
    /// not only in `test-rules`: file-scoped chains need a fixed point, and a
    /// pooling (`scope: outer`) rule must be able to use a container-level
    /// file-scoped composite as a leg.
    #[test]
    #[allow(clippy::expect_used)]
    fn container_self_scope_composites_chain() {
        let yaml = r#"
defaults:
  platforms: [windows, unix]
traits:
  - id: "test/leg::a"
    desc: "a"
    crit: notable
    for: [zip]
    if:
      type: basename
      exact: "never-a"
  - id: "test/leg::b"
    desc: "b"
    crit: notable
    for: [zip]
    if:
      type: basename
      exact: "never-b"
composite_rules:
  - id: "test/c::layout"
    desc: "layout"
    crit: baseline
    for: [zip]
    all:
      - id: "test/leg::a"
      - id: "test/leg::b"
  - id: "test/c::over-layout"
    desc: "over layout"
    crit: notable
    for: [zip]
    all:
      - id: "test/c::layout"
      - id: "test/leg::a"
  - id: "test/c::over-over-layout"
    desc: "two levels up"
    crit: notable
    for: [zip]
    all:
      - id: "test/c::over-layout"
      - id: "test/leg::b"
  - id: "test/c::outer-over-layout"
    desc: "pooled over layout"
    crit: notable
    for: [zip]
    scope: outer
    all:
      - id: "test/c::layout"
      - id: "test/leg::b"
"#;
        let file = write_test_traits(yaml);
        let mapper = super::super::CapabilityMapper::from_yaml(file.path()).expect("load mapper");
        let mut report = make_test_report();
        report
            .findings
            .push(make_test_finding("test/leg::a", Criticality::Notable));
        report
            .findings
            .push(make_test_finding("test/leg::b", Criticality::Notable));
        // Stamp the legs the way the archive analyzer does: a scan always
        // passes origins, and that is the condition the chain failed under.
        let zip_bit = RuleFileType::Zip.type_bit();
        let mut origins: rustc_hash::FxHashMap<String, TypeMask> = rustc_hash::FxHashMap::default();
        origins.insert("test/leg::a".to_string(), zip_bit);
        origins.insert("test/leg::b".to_string(), zip_bit);
        let found = mapper.evaluate_container_composites(&report, &[], "zip", Some(&origins));
        let mut ids: Vec<&str> = found.iter().map(|f| f.id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(
            ids,
            vec![
                "test/c::layout",
                "test/c::outer-over-layout",
                "test/c::over-layout",
                "test/c::over-over-layout",
            ]
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn composite_worklist_admits_only_the_declared_container() {
        let yaml = r#"
traits:
  - id: "test/leg::leg"
    desc: "leg"
    crit: baseline
    for: [all]
    if:
      type: basename
      exact: "x"
composite_rules:
  - id: "test/c::jar-rule"
    desc: "jar"
    crit: notable
    for: [jar]
    scope: archive
    all:
      - id: "test/leg::leg"
  - id: "test/c::apk-rule"
    desc: "apk"
    crit: notable
    for: [android_apk]
    all:
      - id: "test/leg::leg"
  - id: "test/c::zip-rule"
    desc: "zip"
    crit: notable
    for: [zip]
    scope: archive
    all:
      - id: "test/leg::leg"
  - id: "test/c::js-pool-rule"
    desc: "js pooled"
    crit: notable
    for: [javascript]
    scope: archive
    all:
      - id: "test/leg::leg"
"#;
        let file = write_test_traits(yaml);
        let mapper = super::super::CapabilityMapper::from_yaml(file.path()).expect("load mapper");
        let ids = |ft: RuleFileType| -> Vec<String> {
            let lists = mapper.composite_worklists(ft);
            let mut v: Vec<String> = lists
                .positive
                .iter()
                .chain(lists.negative.iter())
                .map(|&i| {
                    mapper.composite_rules[i as usize]
                        .id
                        .rsplit("::")
                        .next()
                        .unwrap_or_default()
                        .to_string()
                })
                .collect();
            v.sort();
            v
        };
        assert_eq!(ids(RuleFileType::Jar), vec!["jar-rule", "zip-rule"]);
        assert_eq!(ids(RuleFileType::AndroidApk), vec!["apk-rule", "zip-rule"]);
        assert_eq!(ids(RuleFileType::Zip), vec!["zip-rule"]);
        assert_eq!(ids(RuleFileType::Crx), vec!["zip-rule"]);
        assert!(ids(RuleFileType::Npm).is_empty());
        assert_eq!(ids(RuleFileType::JavaScript), vec!["js-pool-rule"]);
        // A container with no type of its own admits archive-typed rules only.
        assert_eq!(
            ids(RuleFileType::All),
            vec!["apk-rule", "jar-rule", "zip-rule"]
        );

        // The work list and the evaluate-time gate agree rule by rule.
        let (report, data) = (make_test_report(), Vec::<u8>::new());
        for ft in [
            RuleFileType::Jar,
            RuleFileType::Zip,
            RuleFileType::AndroidApk,
        ] {
            let listed = ids(ft);
            for rule in &mapper.composite_rules {
                use crate::composite_rules::debug::{EvaluationDebug, RuleType, SkipReason};
                let collector =
                    std::sync::RwLock::new(EvaluationDebug::new(&rule.id, RuleType::Composite));
                let mut ctx = crate::composite_rules::EvaluationContext::new(
                    &report,
                    &data,
                    ft,
                    &[crate::composite_rules::Platform::All],
                    None,
                    None,
                );
                ctx.debug_collector = Some(&collector);
                let _ = rule.evaluate(&ctx);
                let gated_out = matches!(
                    collector.read().expect("debug lock").skip_reason,
                    Some(SkipReason::FileTypeMismatch { .. })
                );
                let short = rule.id.rsplit("::").next().unwrap_or_default();
                assert_eq!(
                    listed.iter().any(|l| l == short),
                    !gated_out,
                    "{short} on {ft:?}: work list and evaluate() disagree"
                );
            }
        }
    }

    #[allow(clippy::expect_used)]
    fn make_basename_mapper() -> super::super::CapabilityMapper {
        let yaml = r#"
traits:
  - id: "test/archive::package-json-basename"
    desc: "package.json basename"
    crit: baseline
    if:
      type: basename
      exact: "package.json"

  - id: "test/archive::exe-extension-basename"
    desc: "exe basename"
    crit: baseline
    if:
      type: basename
      regex: "\\.exe$"
"#;
        let file = write_test_traits(yaml);
        super::super::CapabilityMapper::from_yaml(file.path()).expect("load basename mapper")
    }

    #[allow(clippy::expect_used)]
    fn make_self_scope_mapper() -> super::super::CapabilityMapper {
        // Basename matchers that cannot match anything, so the only findings in
        // play are the ones each test supplies explicitly.
        let yaml = r#"
traits:
  - id: "test/container::alpha"
    desc: "alpha"
    crit: baseline
    if:
      type: basename
      exact: "zz-never-alpha"
  - id: "test/container::beta"
    desc: "beta"
    crit: baseline
    if:
      type: basename
      exact: "zz-never-beta"

composite_rules:
  - id: "test/container::self-pair"
    desc: "Two container-level legs"
    crit: suspicious
    conf: 0.9
    all:
      - id: "test/container::alpha"
      - id: "test/container::beta"
"#;
        let file = write_test_traits(yaml);
        super::super::CapabilityMapper::from_yaml(file.path()).expect("load self-scope mapper")
    }

    /// A composite with no `scope:` resolves to `Scope::File`, and the
    /// cross-file pass skips those so two unrelated members cannot pool into
    /// one "file". A container's *own* traits are not two members, though --
    /// `chm.html_entry_count` and friends describe the single container file --
    /// so a file-scoped composite over them must still fire.
    ///
    /// Regression: fifteen abuse.ch CHM droppers scored four notables and no
    /// composite at all, including two hostile rules written for that shape.
    #[test]
    #[allow(clippy::expect_used)]
    fn container_own_findings_satisfy_file_scoped_composite() {
        let mapper = make_self_scope_mapper();
        let mut report = make_test_report();
        report.findings.push(make_test_finding(
            "test/container::alpha",
            Criticality::Baseline,
        ));
        report.findings.push(make_test_finding(
            "test/container::beta",
            Criticality::Baseline,
        ));

        let found = mapper.evaluate_container_composites(&report, &[], "zip", None);
        assert!(
            found
                .iter()
                .any(|f| f.id.as_str() == "test/container::self-pair"),
            "file-scoped composite over the container's own findings should fire, got {:?}",
            found.iter().map(|f| f.id.as_str()).collect::<Vec<_>>()
        );
    }

    /// The other half: legs coming from *nested* members must still not pool
    /// into a file-scoped composite. Nested findings carry no member location,
    /// so treating them as same-file evidence is what gave OpenSSH, Caddy and a
    /// Fedora source RPM hostile verdicts.
    #[test]
    #[allow(clippy::expect_used)]
    fn nested_member_findings_do_not_pool_into_file_scoped_composite() {
        let mapper = make_self_scope_mapper();
        let report = make_test_report();
        let nested = vec![
            make_test_finding("test/container::alpha", Criticality::Baseline),
            make_test_finding("test/container::beta", Criticality::Baseline),
        ];

        let found = mapper.evaluate_container_composites(&report, &nested, "zip", None);
        assert!(
            !found
                .iter()
                .any(|f| f.id.as_str() == "test/container::self-pair"),
            "legs from two nested members must not satisfy a file-scoped composite"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn container_positive_chain_does_not_starve_negative_rules() {
        let mut yaml = String::from(
            "defaults:\n  for: [zip]\n  platforms: [windows, unix]\ntraits:\n  - id: test/chain::seed\n    desc: Seed\n    crit: baseline\n    if: {type: basename, exact: zz-never-seed}\n  - id: test/chain::absent\n    desc: Absent\n    crit: baseline\n    if: {type: basename, exact: zz-never-absent}\ncomposite_rules:\n",
        );
        let mut previous = String::from("seed");
        for i in 0..7 {
            yaml.push_str(&format!(
                "  - id: test/chain::step-{i}\n    desc: Chain step\n    crit: notable\n    scope: archive\n    all: [{{id: test/chain::{previous}}}]\n",
            ));
            previous = format!("step-{i}");
        }
        for (name, suppressor) in [
            ("unguarded-result", "absent"),
            ("late-suppressed", "step-6"),
        ] {
            yaml.push_str(&format!(
                "  - id: test/chain::{name}\n    desc: Guarded result\n    crit: suspicious\n    scope: archive\n    all: [{{id: test/chain::seed}}]\n    unless: [{{id: test/chain::{suppressor}}}]\n",
            ));
        }
        let file = write_test_traits(&yaml);
        let mapper =
            super::super::CapabilityMapper::from_yaml(file.path()).expect("load chain mapper");
        let report = make_test_report();
        let nested = vec![make_test_finding("test/chain::seed", Criticality::Baseline)];
        let found = mapper.evaluate_container_composites(&report, &nested, "zip", None);
        let ids: Vec<_> = found.iter().map(|f| f.id.as_str()).collect();
        assert!(
            ids.contains(&"test/chain::step-6"),
            "positive chain truncated: {ids:?}"
        );
        assert!(
            ids.contains(&"test/chain::unguarded-result"),
            "negative pass starved: {ids:?}"
        );
        assert!(
            !ids.contains(&"test/chain::late-suppressed"),
            "late suppressor ignored: {ids:?}"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn container_suppression_preserves_member_local_evidence() {
        let yaml = r#"
defaults:
  for: [zip]
  platforms: [windows, unix]
traits:
  - id: test/scope::payload
    desc: Member payload
    crit: notable
    if: {type: basename, exact: zz-never-payload}
    unless: [{id: test/scope::build-marker}]
  - id: test/scope::build-marker
    desc: Sibling build marker
    crit: notable
    if: {type: basename, exact: zz-never-build}
composite_rules:
  - id: test/scope::payload-package
    desc: Package with payload
    crit: hostile
    scope: archive
    all: [{id: test/scope::payload}]
  - id: test/scope::guarded-package
    desc: Guarded package
    crit: suspicious
    scope: archive
    all: [{id: test/scope::payload}]
    unless: [{id: test/scope::build-marker}]
"#;
        let file = write_test_traits(yaml);
        let mapper = super::super::CapabilityMapper::from_yaml(file.path())
            .expect("load suppression mapper");
        let mut dependent = make_test_finding("test/scope::payload-package", Criticality::Hostile);
        dependent.trait_refs.push("test/scope::payload".into());
        let mut findings = vec![
            make_test_finding("test/scope::payload", Criticality::Notable),
            make_test_finding("test/scope::build-marker", Criticality::Notable),
            dependent,
            make_test_finding("test/scope::guarded-package", Criticality::Suspicious),
        ];
        let targets = ["test/scope::payload-package", "test/scope::guarded-package"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        mapper.apply_retroactive_unless_suppression_to_selected_findings(&mut findings, &targets);
        let ids: Vec<_> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"test/scope::payload"));
        assert!(ids.contains(&"test/scope::payload-package"));
        assert!(!ids.contains(&"test/scope::guarded-package"));
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_evaluate_container_composites_empty_findings() {
        let mapper = super::super::CapabilityMapper::empty();
        let report = make_test_report();

        // With no nested findings, should return empty
        let container_findings = mapper.evaluate_container_composites(&report, &[], "zip", None);
        // Either empty or only rules that match on file type alone
        // (depends on the rules in traits directory)
        assert!(
            container_findings.len() < 100,
            "Should not have excessive findings"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_evaluate_container_composites_deduplication() {
        let mapper = super::super::CapabilityMapper::empty();
        let mut report = make_test_report();

        // Pre-populate report with a finding
        let preexisting = make_test_finding("test/preexisting", Criticality::Notable);
        report.findings.push(preexisting);

        // Evaluate with nested findings
        let nested = vec![make_test_finding("nested/finding", Criticality::Suspicious)];
        let container_findings =
            mapper.evaluate_container_composites(&report, &nested, "zip", None);

        // Should not include preexisting finding IDs
        assert!(
            !container_findings
                .iter()
                .any(|f| f.id == "test/preexisting"),
            "Should not duplicate preexisting findings"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_evaluate_container_composites_evidence_marking() {
        let mapper = super::super::CapabilityMapper::empty();
        let report = make_test_report();

        // Create nested findings that might trigger a composite
        let nested = vec![
            make_test_finding("metadata/builder/npm::package-json", Criticality::Baseline),
            make_test_finding(
                "micro-behaviors/fs/file/dll::dll-file",
                Criticality::Notable,
            ),
        ];

        let container_findings =
            mapper.evaluate_container_composites(&report, &nested, "zip", None);

        // Any findings without evidence should get the container-composite marker
        for finding in &container_findings {
            if !finding.evidence.is_empty() {
                // Verify the evidence is properly marked
                let has_container_marker = finding
                    .evidence
                    .iter()
                    .any(|e| e.method == "container-composite" || e.source.contains("cross-file"));
                // Either has container marker or has other evidence from the rule
                assert!(
                    has_container_marker || finding.evidence.iter().any(|e| !e.method.is_empty()),
                    "Finding should have evidence: {:?}",
                    finding.id
                );
            }
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_evaluate_container_composites_file_type_detection() {
        let mapper = super::super::CapabilityMapper::empty();

        // Test with various archive types
        for file_type in &["zip", "tar", "7z", "archive", "jar", "deb", "rpm"] {
            let report = make_test_report();
            let nested = vec![make_test_finding("test/nested", Criticality::Notable)];

            // Should not panic for any archive type
            let _ = mapper.evaluate_container_composites(&report, &nested, file_type, None);
        }
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_evaluate_basename_traits_for_entries() {
        let mapper = make_basename_mapper();

        // Test with archive entry names that should match basename traits
        let entry_names = vec![
            "package/package.json".to_string(),
            "package/evil.exe".to_string(),
            "package/lib/helper.js".to_string(),
        ];

        let findings = mapper.evaluate_basename_traits_for_entries(&entry_names);

        // Should find at least package-json-basename and exe-extension-basename
        let has_package_json = findings
            .iter()
            .any(|f| f.id.contains("package-json-basename"));
        let has_exe = findings
            .iter()
            .any(|f| f.id.contains("exe-extension-basename"));

        assert!(
            has_package_json,
            "Should match package-json-basename trait, got: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
        assert!(
            has_exe,
            "Should match exe-extension-basename trait, got: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );

        // Evidence should contain the entry name
        for finding in &findings {
            assert!(
                finding.evidence.iter().any(|e| e.source == "archive-entry"),
                "basename findings should have archive-entry source"
            );
        }
    }

    #[test]
    fn decoded_file_path_traits_respect_file_type() {
        let yaml = r#"
defaults:
  platforms: [windows, unix]
traits:
  - id: test/corpus::release-member
    desc: Recognized corpus member
    crit: notable
    for: [php]
    if:
      type: path
      regex: 'PayloadsAllTheThings-[0-9.]+[\\/]'
"#;
        let file = write_test_traits(yaml);
        let mapper =
            super::super::CapabilityMapper::from_yaml(file.path()).expect("load path-trait mapper");
        let path = "bundle.tar.gz!!PayloadsAllTheThings-4.2/payload.php##base64@12";
        assert!(
            mapper
                .evaluate_path_traits_for_file(path, "php")
                .iter()
                .any(|finding| finding.id == "test/corpus::release-member")
        );
        assert!(
            mapper
                .evaluate_path_traits_for_file(path, "python")
                .is_empty()
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_evaluate_basename_traits_matches_entry_path_regex() {
        // Rule mirrors `macos-temp-staging-path` from
        // objectives/supply-chain/metadata-anomaly/archive. Inlined so the
        // test does not depend on the installed trait set (which lives in
        // a separate repo that can drift or carry parse errors).
        let yaml = r#"
traits:
  - id: "test/archive::macos-temp-staging-path"
    desc: "Archive preserves macOS temp staging path"
    crit: suspicious
    conf: 0.96
    if:
      type: path
      regex: 'var/folders/[a-z]{2}/[A-Za-z0-9_]+/T/tmp[a-z0-9]+/.{1,80}/package/'
"#;
        let file = write_test_traits(yaml);
        let mapper = super::super::CapabilityMapper::from_yaml(file.path())
            .expect("load staging-path mapper");

        let entry_names = vec![String::from(
            "var/folders/rs/52vst_5924nc0zz5ccww9tl80000gp/T/tmpn885gmk9/snore-log/package/lib/private/prepare-writer.js",
        )];

        let findings = mapper.evaluate_basename_traits_for_entries(&entry_names);

        assert!(
            findings
                .iter()
                .any(|f| f.id.contains("macos-temp-staging-path")),
            "full entry path regex should match archive member path, got: {:?}",
            findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_evaluate_basename_traits_empty_entries() {
        let mapper = make_basename_mapper();
        let findings = mapper.evaluate_basename_traits_for_entries(&[]);
        assert!(findings.is_empty());
    }

    /// Cross-scope downgrade pass — the central behavior used to demote
    /// per-file findings (e.g. `cookies-get-all`) when a container-level
    /// gate (e.g. `metadata/signed/platform::mozilla-extension`) is in
    /// scope. The mapper builds findings from per-file evaluation only;
    /// the gate lives in `extra_findings`.
    #[allow(clippy::expect_used)]
    fn make_cross_scope_mapper() -> super::super::CapabilityMapper {
        let yaml = r#"
traits:
  - id: "test/target::target-trait"
    desc: "target trait that should downgrade in presence of gate"
    crit: suspicious
    if:
      type: basename
      exact: "target.js"
    downgrade:
      # Container scope is opt-in: without this the downgrade resolves within
      # the file, like `unless:`, and the cross-scope pass skips it.
      scope: archive
      any:
      - id: "test/gate::gate-trait"

  - id: "test/gate::gate-trait"
    desc: "gate trait — container-level marker"
    crit: baseline
    if:
      type: basename
      exact: "gate.json"
"#;
        let file = write_test_traits(yaml);
        super::super::CapabilityMapper::from_yaml(file.path()).expect("load cross-scope mapper")
    }

    /// Same rule as `make_cross_scope_mapper`, minus the `scope: archive`
    /// opt-in — i.e. the default.
    #[allow(clippy::expect_used)]
    fn make_file_scoped_mapper() -> super::super::CapabilityMapper {
        let yaml = r#"
traits:
  - id: "test/target::target-trait"
    desc: "target trait with a default-scoped downgrade"
    crit: suspicious
    if:
      type: basename
      exact: "target.js"
    downgrade:
      any:
      - id: "test/gate::gate-trait"

  - id: "test/gate::gate-trait"
    desc: "gate trait — container-level marker"
    crit: baseline
    if:
      type: basename
      exact: "gate.json"
"#;
        let file = write_test_traits(yaml);
        super::super::CapabilityMapper::from_yaml(file.path()).expect("load file-scoped mapper")
    }

    /// A file-scoped composite downgrade whose condition resolves after the
    /// composite matched must still apply once every finding is in.
    ///
    /// Regression guard: pass 3 only re-evaluated container-scoped downgrades,
    /// so when `metadata/signed/platform::microsoft` resolved late (its own
    /// `unless:` waits on a retroactively-suppressed atom), a hostile
    /// `av-product-killer` on a Microsoft installer kept its declared tier.
    #[test]
    #[allow(clippy::expect_used)]
    fn test_pass3_applies_late_file_scoped_composite_downgrade() {
        use crate::composite_rules::{FileType as RuleFileType, SectionMap};

        let yaml = r#"
traits:
  - id: "test/leg::leg-trait"
    desc: "leg"
    crit: notable
    if:
      type: basename
      exact: "x"
  - id: "test/gate::gate-trait"
    desc: "gate"
    crit: baseline
    if:
      type: basename
      exact: "y"
composite_rules:
  - id: "test/target::target-rule"
    desc: "target composite with a file-scoped downgrade"
    crit: hostile
    all:
      - id: "test/leg::leg-trait"
    downgrade:
      any:
        - id: "test/gate::gate-trait"
"#;
        let file = write_test_traits(yaml);
        let mapper = super::super::CapabilityMapper::from_yaml(file.path()).expect("load mapper");
        let report = make_test_report();

        // As matched: the gate was not yet present, so the target kept its
        // declared tier. The gate arrives before pass 3.
        let mut findings = vec![
            make_test_finding("test/target::target-rule", Criticality::Hostile),
            make_test_finding("test/gate::gate-trait", Criticality::Baseline),
        ];
        let reeval = |findings: &mut Vec<Finding>| {
            mapper.reeval_downgrades(
                findings,
                0,
                &report,
                &[],
                None,
                RuleFileType::All,
                &SectionMap::default(),
                None,
            );
        };
        reeval(&mut findings);
        assert_eq!(findings[0].crit, Criticality::Suspicious);
        assert!(findings[0].downgraded);

        // Idempotent: a second pass (or a downgrade already applied at match
        // time) must not lower it again.
        reeval(&mut findings);
        assert_eq!(findings[0].crit, Criticality::Suspicious);
    }

    /// Pass 3 changes nothing it has no reason to: no gate, no downgrade, or
    /// a finding already at or below the downgraded tier.
    #[test]
    #[allow(clippy::expect_used)]
    fn test_pass3_leaves_unconditioned_findings_alone() {
        use crate::composite_rules::{FileType as RuleFileType, SectionMap};

        let yaml = r#"
traits:
  - id: "test/leg::leg-trait"
    desc: "leg"
    crit: notable
    if:
      type: basename
      exact: "x"
  - id: "test/gate::gate-trait"
    desc: "gate"
    crit: baseline
    if:
      type: basename
      exact: "y"
composite_rules:
  - id: "test/target::target-rule"
    desc: "target composite with a file-scoped downgrade"
    crit: hostile
    all:
      - id: "test/leg::leg-trait"
    downgrade:
      any:
        - id: "test/gate::gate-trait"
  - id: "test/plain::plain-rule"
    desc: "composite without a downgrade"
    crit: suspicious
    all:
      - id: "test/leg::leg-trait"
"#;
        let file = write_test_traits(yaml);
        let mapper = super::super::CapabilityMapper::from_yaml(file.path()).expect("load mapper");
        let report = make_test_report();
        let reeval = |findings: &mut Vec<Finding>| {
            mapper.reeval_downgrades(
                findings,
                0,
                &report,
                &[],
                None,
                RuleFileType::All,
                &SectionMap::default(),
                None,
            );
        };

        // Gate absent: the target keeps its declared tier and is not flagged.
        let mut findings = vec![
            make_test_finding("test/target::target-rule", Criticality::Hostile),
            make_test_finding("test/plain::plain-rule", Criticality::Suspicious),
        ];
        reeval(&mut findings);
        assert_eq!(findings[0].crit, Criticality::Hostile);
        assert!(!findings[0].downgraded);
        assert_eq!(findings[1].crit, Criticality::Suspicious);
        assert!(!findings[1].downgraded);

        // Gate present, but the finding already sits below what the downgrade
        // would give (lowered by something else): never raised back up.
        let mut findings = vec![
            make_test_finding("test/target::target-rule", Criticality::Notable),
            make_test_finding("test/gate::gate-trait", Criticality::Baseline),
        ];
        reeval(&mut findings);
        assert_eq!(findings[0].crit, Criticality::Notable);
        assert!(!findings[0].downgraded);
    }

    /// A `downgrade:` with no `scope:` must not reach across archive members.
    ///
    /// This is the regression guard for the bug that motivated the default: a
    /// vendored `tests/` tree in one member silently downgraded — and, before
    /// the strip fix, deleted — an unrelated trait in another member, with
    /// nothing in the rule text suggesting it could.
    #[test]
    #[allow(clippy::expect_used)]
    fn test_default_scoped_downgrade_ignores_container_findings() {
        use crate::composite_rules::{FileType as RuleFileType, SectionMap};

        let mapper = make_file_scoped_mapper();
        let report = make_test_report();

        let mut target_findings = vec![make_test_finding(
            "test/target::target-trait",
            Criticality::Suspicious,
        )];
        // The gate fires only at container level — a sibling member, not this file.
        let extras = vec![make_test_finding(
            "test/gate::gate-trait",
            Criticality::Baseline,
        )];

        mapper.reeval_downgrades_cross_scope(
            &mut target_findings,
            &extras,
            &report,
            &[],
            RuleFileType::All,
            &SectionMap::default(),
        );

        assert_eq!(
            target_findings[0].crit,
            Criticality::Suspicious,
            "a default-scoped downgrade must ignore findings from other members"
        );
        assert!(
            !target_findings[0].downgraded,
            "no downgrade fired, so the finding must not be flagged as demoted"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_cross_scope_downgrade_fires_with_gate_in_extras() {
        use crate::composite_rules::{FileType as RuleFileType, SectionMap};

        let mapper = make_cross_scope_mapper();
        let report = make_test_report();

        // Per-file findings: just the target trait at its original Suspicious crit.
        let mut target_findings = vec![make_test_finding(
            "test/target::target-trait",
            Criticality::Suspicious,
        )];
        // Container-level findings (extras): the gate trait fires here.
        let extras = vec![make_test_finding(
            "test/gate::gate-trait",
            Criticality::Baseline,
        )];

        mapper.reeval_downgrades_cross_scope(
            &mut target_findings,
            &extras,
            &report,
            &[],
            RuleFileType::All,
            &SectionMap::default(),
        );

        assert_eq!(
            target_findings[0].crit,
            Criticality::Notable,
            "Suspicious target trait should downgrade to Notable when gate is in extras"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_cross_scope_downgrade_noop_without_gate() {
        use crate::composite_rules::{FileType as RuleFileType, SectionMap};

        let mapper = make_cross_scope_mapper();
        let report = make_test_report();

        let mut target_findings = vec![make_test_finding(
            "test/target::target-trait",
            Criticality::Suspicious,
        )];
        // No gate in extras — downgrade conditions don't match.
        let extras: Vec<crate::types::Finding> = Vec::new();

        mapper.reeval_downgrades_cross_scope(
            &mut target_findings,
            &extras,
            &report,
            &[],
            RuleFileType::All,
            &SectionMap::default(),
        );

        assert_eq!(
            target_findings[0].crit,
            Criticality::Suspicious,
            "Without gate in extras, target trait keeps original crit"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_cross_scope_downgrade_is_idempotent() {
        use crate::composite_rules::{FileType as RuleFileType, SectionMap};

        let mapper = make_cross_scope_mapper();
        let report = make_test_report();

        // Start at Suspicious; the gate is present in extras.
        let mut target_findings = vec![make_test_finding(
            "test/target::target-trait",
            Criticality::Suspicious,
        )];
        let extras = vec![make_test_finding(
            "test/gate::gate-trait",
            Criticality::Baseline,
        )];

        // First pass: Suspicious → Notable.
        mapper.reeval_downgrades_cross_scope(
            &mut target_findings,
            &extras,
            &report,
            &[],
            RuleFileType::All,
            &SectionMap::default(),
        );
        assert_eq!(target_findings[0].crit, Criticality::Notable);

        // Second pass: must stay at Notable, not slide to Baseline. The reeval
        // starts from the trait's declared crit (Suspicious), not the
        // finding's current crit, so the result is the same regardless of
        // how many times the pass runs.
        mapper.reeval_downgrades_cross_scope(
            &mut target_findings,
            &extras,
            &report,
            &[],
            RuleFileType::All,
            &SectionMap::default(),
        );
        assert_eq!(
            target_findings[0].crit,
            Criticality::Notable,
            "Repeated reeval must not stack downgrades"
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_parent_scope_downgrade_uses_only_explicit_parent_context() {
        use crate::composite_rules::{FileType as RuleFileType, SectionMap};

        let yaml = r#"
defaults:
  for: [pe]
  platforms: [windows]
traits:
  - id: "test/target::injection-api"
    desc: "remote injection API behavior"
    crit: notable
    if:
      type: basename
      exact: "helper.exe"
  - id: "test/context::known-tool"
    desc: "known parent program identity"
    crit: notable
    if:
      type: basename
      exact: "known.exe"
composite_rules:
  - id: "test/target::injection"
    desc: "remote injection behavior"
    crit: hostile
    all:
      - id: "test/target::injection-api"
    downgrade:
      scope: parent
      any:
        - id: "test/context::known-tool"
"#;
        let source = write_test_traits(yaml);
        let mapper =
            super::super::CapabilityMapper::from_yaml(source.path()).expect("load parent mapper");
        let report = make_test_report();
        let parent = vec![make_test_finding(
            "test/context::known-tool",
            Criticality::Notable,
        )];

        // The parent pass demotes the child finding by one tier.
        let mut child = vec![make_test_finding(
            "test/target::injection",
            Criticality::Hostile,
        )];
        mapper.reeval_downgrades_parent_scope(
            &mut child,
            &parent,
            &report,
            &[],
            RuleFileType::All,
            &SectionMap::default(),
        );
        assert_eq!(child[0].crit, Criticality::Suspicious);
        assert!(child[0].downgraded);

        // Missing parent identity leaves it hostile. The ordinary archive
        // cross-scope pass must not reinterpret `parent` as permission to use
        // arbitrary container or sibling findings.
        let mut unrelated_child = vec![
            make_test_finding("test/target::injection", Criticality::Hostile),
            make_test_finding("test/context::known-tool", Criticality::Notable),
        ];
        mapper.reeval_downgrades_parent_scope(
            &mut unrelated_child,
            &[],
            &report,
            &[],
            RuleFileType::All,
            &SectionMap::default(),
        );
        assert_eq!(unrelated_child[0].crit, Criticality::Hostile);
        assert!(!unrelated_child[0].downgraded);

        mapper.reeval_downgrades_cross_scope(
            &mut unrelated_child,
            &parent,
            &report,
            &[],
            RuleFileType::All,
            &SectionMap::default(),
        );
        assert_eq!(unrelated_child[0].crit, Criticality::Hostile);

        // A matching identity finding inside the child is still not parent
        // evidence; ordinary per-file evaluation ignores this scoped clause.
        let mut child_local_gate = vec![
            make_test_finding("test/target::injection", Criticality::Hostile),
            make_test_finding("test/context::known-tool", Criticality::Notable),
        ];
        mapper.reeval_downgrades(
            &mut child_local_gate,
            0,
            &report,
            &[],
            None,
            RuleFileType::All,
            &SectionMap::default(),
            None,
        );
        assert_eq!(child_local_gate[0].crit, Criticality::Hostile);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn parent_scope_downgrade_uses_immediate_parent_at_every_depth() {
        use crate::composite_rules::FileType as RuleFileType;

        let yaml = r#"
defaults:
  for: [pe]
traits:
  - id: "test/target::api"
    desc: "Target behavior"
    crit: notable
    if:
      type: basename
      exact: "target.exe"
  - id: "test/context::known-tool"
    desc: "Known parent tool"
    crit: notable
    if:
      type: basename
      exact: "known.exe"
composite_rules:
  - id: "test/target::behavior"
    desc: "Target behavior"
    crit: hostile
    all:
      - id: "test/target::api"
    downgrade:
      scope: parent
      any:
        - id: "test/context::known-tool"
"#;
        let source = write_test_traits(yaml);
        let mapper = super::super::CapabilityMapper::from_yaml(source.path())
            .expect("load tree parent-scope mapper");
        let mut report = make_test_report();
        report.findings = vec![make_test_finding(
            "test/context::known-tool",
            Criticality::Notable,
        )];

        let direct_parent = crate::types::FileAnalysis {
            id: 1,
            path: "root.zip!!tests/data/bcj_3.bin".to_string(),
            depth: 1,
            file_type: "pe".to_string(),
            findings: vec![make_test_finding(
                "test/context::known-tool",
                Criticality::Notable,
            )],
            ..Default::default()
        };
        // Parent has the marker, so the depth-two child must be downgraded.
        let child = crate::types::FileAnalysis {
            id: 2,
            path: "root.zip!!tests/data/bcj_3.bin##embedded:pe@0x1000".to_string(),
            depth: 2,
            file_type: "pe".to_string(),
            findings: vec![make_test_finding(
                "test/target::behavior",
                Criticality::Hostile,
            )],
            ..Default::default()
        };
        // The archive root and sibling both have the marker, but neither may
        // downgrade this child because its immediate parent does not.
        let no_marker_parent = crate::types::FileAnalysis {
            id: 3,
            path: "root.zip!!tests/data/plain.exe".to_string(),
            depth: 1,
            file_type: "pe".to_string(),
            ..Default::default()
        };
        let sibling = crate::types::FileAnalysis {
            id: 4,
            path: "root.zip!!tests/data/x86_3.bin".to_string(),
            depth: 1,
            file_type: "pe".to_string(),
            findings: vec![make_test_finding(
                "test/context::known-tool",
                Criticality::Notable,
            )],
            ..Default::default()
        };
        let unaffected_child = crate::types::FileAnalysis {
            id: 5,
            path: "root.zip!!tests/data/plain.exe##embedded:pe@0x2000".to_string(),
            depth: 2,
            file_type: "pe".to_string(),
            findings: vec![make_test_finding(
                "test/target::behavior",
                Criticality::Hostile,
            )],
            ..Default::default()
        };
        report.files = vec![
            direct_parent,
            child,
            no_marker_parent,
            sibling,
            unaffected_child,
        ];

        mapper.reeval_parent_scope_in_file_tree(&mut report, &[], RuleFileType::All);

        assert_eq!(report.files[1].findings[0].crit, Criticality::Suspicious);
        assert!(report.files[1].findings[0].downgraded);
        assert_eq!(report.files[4].findings[0].crit, Criticality::Hostile);
        assert!(!report.files[4].findings[0].downgraded);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_cross_scope_downgrade_handles_unknown_trait_id() {
        use crate::composite_rules::{FileType as RuleFileType, SectionMap};

        let mapper = make_cross_scope_mapper();
        let report = make_test_report();

        // A finding whose id is in neither trait_definitions nor
        // composite_rules should be left untouched (no panic, no crit change).
        let mut target_findings = vec![make_test_finding(
            "test/unknown::never-defined",
            Criticality::Suspicious,
        )];
        let extras: Vec<crate::types::Finding> = Vec::new();

        mapper.reeval_downgrades_cross_scope(
            &mut target_findings,
            &extras,
            &report,
            &[],
            RuleFileType::All,
            &SectionMap::default(),
        );

        assert_eq!(target_findings[0].crit, Criticality::Suspicious);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_scope_outer_composite_evaluates_at_archive_level() {
        // `scope: outer`/`archive` pools evidence across archive entries, and
        // the container inherits every member finding -- so a composite that
        // ties a CRX's content script to its manifest sees both. What it must
        // declare is the node it runs on: `for: [crx]`, the container.
        //
        // It used to be allowed to declare `for: [javascript]` and still run
        // here, because the gate admitted any archive-scoped rule on any
        // archive container. That made `for:` meaningless on 546 of the tree's
        // 2287 archive-scoped composites -- `vscode-activated-curl-shell`
        // (`for: [vsix]`) scored hostile on a Rust crate. The leaf-typed rule
        // below is now the negative control.
        //
        // A plain file-scoped composite must stay gated out either way.
        let yaml = r#"
defaults:
  platforms: [all]

traits:
  - id: "test/ext::scrape"
    desc: "AI chat scrape"
    crit: suspicious
    for: [javascript]
    if:
      type: text
      substr: "SCRAPE_MARKER"
  - id: "test/ext::cors"
    desc: "CORS rewrite"
    crit: suspicious
    for: [javascript]
    if:
      type: text
      substr: "CORS_MARKER"

composite_rules:
  - id: "test/ext::outer-exfil"
    desc: "Outer-scoped cross-entry exfil"
    crit: hostile
    conf: 0.95
    for: [crx]
    scope: outer
    all:
      - id: "test/ext::scrape"
      - id: "test/ext::cors"
  - id: "test/ext::leaf-typed-outer"
    desc: "Outer-scoped but leaf-typed control"
    crit: hostile
    conf: 0.95
    for: [javascript]
    scope: outer
    all:
      - id: "test/ext::scrape"
      - id: "test/ext::cors"
  - id: "test/ext::file-exfil"
    desc: "File-scoped exfil (control)"
    crit: hostile
    conf: 0.95
    for: [crx]
    all:
      - id: "test/ext::scrape"
      - id: "test/ext::cors"
"#;
        let file = write_test_traits(yaml);
        let mapper =
            super::super::CapabilityMapper::from_yaml(file.path()).expect("load scope mapper");

        // Simulate two leaf findings firing in *different* entries of a CRX.
        let finding_in_entry = |id: &str, entry: &str| {
            Finding::capability(id.to_string(), format!("test {id}"), 0.9)
                .with_criticality(Criticality::Suspicious)
                .with_evidence(vec![crate::types::Evidence {
                    method: "text".to_string(),
                    source: "test".to_string(),
                    value: "marker".to_string(),
                    location: Some(entry.to_string()),
                    ..Default::default()
                }])
        };
        let report = make_test_report();
        let nested = vec![
            finding_in_entry("test/ext::scrape", "ext.crx!content_script.js"),
            finding_in_entry("test/ext::cors", "ext.crx!rules.json"),
        ];

        let container_findings =
            mapper.evaluate_container_composites(&report, &nested, "crx", None);

        // The scope: outer composite must fire at the archive container level
        // despite its `for: [javascript]` not matching the crx container type.
        assert!(
            container_findings
                .iter()
                .any(|f| f.id == "test/ext::outer-exfil"),
            "scope: outer composite should evaluate at archive container level, got: {:?}",
            container_findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );

        // Declared `for: [javascript]`, it does not run on a crx node, however
        // it is scoped. Scope selects which evidence may pool, not which nodes
        // the rule runs on.
        assert!(
            !container_findings
                .iter()
                .any(|f| f.id == "test/ext::leaf-typed-outer"),
            "leaf-typed outer composite must not fire on a crx container, got: {:?}",
            container_findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );

        // A file-scoped composite must stay gated out of the container pass
        // regardless of its `for:`, because nested findings carry no per-member
        // location and would pool as same-file evidence.
        assert!(
            !container_findings
                .iter()
                .any(|f| f.id == "test/ext::file-exfil"),
            "file-scoped composite must not fire at archive container level, got: {:?}",
            container_findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    /// A `scope: package` composite must fire when one member matches a finding
    /// from the artifact and the other a finding from its registry metadata —
    /// the two finding sets the package pass unions. A `scope: file` control
    /// over the same members must NOT fire, proving the pass is filtered to the
    /// boundary-spanning scopes and that location-stripped findings don't leak
    /// a file-scoped match.
    #[allow(clippy::expect_used)]
    fn package_scope_mapper() -> super::super::CapabilityMapper {
        let yaml = r#"
defaults:
  platforms: [unix, windows, macos]

traits:
  - id: "test/pkg::deprecated"
    desc: "Registry marks package deprecated"
    crit: notable
    if:
      type: text
      substr: "DEPRECATED_MARKER"
  - id: "test/pkg::native-addon"
    desc: "Artifact ships a native addon"
    crit: notable
    if:
      type: text
      substr: "NATIVE_ADDON_MARKER"

composite_rules:
  - id: "test/pkg::deprecated-with-addon"
    desc: "Deprecated package shipping a native addon"
    crit: suspicious
    conf: 0.9
    scope: outer
    all:
      - id: "test/pkg::deprecated"
      - id: "test/pkg::native-addon"
  - id: "test/pkg::file-control"
    desc: "Same members, file scope (must not span the boundary)"
    crit: suspicious
    conf: 0.9
    for: [registry, javascript]
    all:
      - id: "test/pkg::deprecated"
      - id: "test/pkg::native-addon"
"#;
        let file = write_test_traits(yaml);
        super::super::CapabilityMapper::from_yaml(file.path()).expect("load package-scope mapper")
    }

    /// A mapper whose one composite ties a manifest fact to a script fact,
    /// declaring both member types plus the container it reports on -- the
    /// shape SCOPE_PLAN.md asks authors to write.
    #[allow(clippy::expect_used)]
    fn make_origin_filter_mapper(for_list: &str) -> super::super::CapabilityMapper {
        let yaml = format!(
            r#"
defaults:
  platforms: [unix, windows, macos]

traits:
  - id: "test/origin::manifest-marker"
    desc: "Manifest marker"
    crit: notable
    if:
      type: text
      substr: "MANIFEST_MARKER"
  - id: "test/origin::script-marker"
    desc: "Script marker"
    crit: notable
    if:
      type: text
      substr: "SCRIPT_MARKER"

composite_rules:
  - id: "test/origin::manifest-plus-script"
    desc: "Manifest fact tied to a script fact"
    crit: suspicious
    conf: 0.9
    for: [{for_list}]
    scope: archive
    all:
      - id: "test/origin::manifest-marker"
      - id: "test/origin::script-marker"
"#
        );
        let file = write_test_traits(&yaml);
        super::super::CapabilityMapper::from_yaml(file.path()).expect("load origin-filter mapper")
    }

    /// `for:` names the file types the rule is about. A leg satisfied by a
    /// member type the rule never declared does not count -- this is the
    /// `vscode-activated-curl-shell` class, where a rule about an extension
    /// manifest was satisfied by a README in an unrelated member.
    #[test]
    fn a_leg_from_an_undeclared_member_type_does_not_satisfy_the_rule() {
        let mapper = make_origin_filter_mapper("zip, packagejson");
        let report = make_test_report();
        let nested = vec![
            make_test_finding("test/origin::manifest-marker", Criticality::Notable),
            make_test_finding("test/origin::script-marker", Criticality::Notable),
        ];
        // The script leg came from a markdown member, which `for:` does not name.
        let mut origins: rustc_hash::FxHashMap<String, TypeMask> = rustc_hash::FxHashMap::default();
        origins.insert(
            "test/origin::manifest-marker".to_string(),
            RuleFileType::PackageJson.type_bit(),
        );
        origins.insert(
            "test/origin::script-marker".to_string(),
            RuleFileType::Markdown.type_bit(),
        );

        let found = mapper.evaluate_container_composites(&report, &nested, "zip", Some(&origins));
        assert!(
            !found
                .iter()
                .any(|f| f.id.as_str() == "test/origin::manifest-plus-script"),
            "a leg from an undeclared member type must not satisfy the rule, got {:?}",
            found.iter().map(|f| f.id.as_str()).collect::<Vec<_>>()
        );
    }

    /// The same evidence, with the member type declared, fires. Declaring what
    /// you mix is the whole contract.
    #[test]
    fn declaring_the_member_type_lets_the_leg_count() {
        let mapper = make_origin_filter_mapper("zip, packagejson, markdown");
        let report = make_test_report();
        let nested = vec![
            make_test_finding("test/origin::manifest-marker", Criticality::Notable),
            make_test_finding("test/origin::script-marker", Criticality::Notable),
        ];
        let mut origins: rustc_hash::FxHashMap<String, TypeMask> = rustc_hash::FxHashMap::default();
        origins.insert(
            "test/origin::manifest-marker".to_string(),
            RuleFileType::PackageJson.type_bit(),
        );
        origins.insert(
            "test/origin::script-marker".to_string(),
            RuleFileType::Markdown.type_bit(),
        );

        let found = mapper.evaluate_container_composites(&report, &nested, "zip", Some(&origins));
        assert!(
            found
                .iter()
                .any(|f| f.id.as_str() == "test/origin::manifest-plus-script"),
            "declared member types must satisfy the rule, got {:?}",
            found.iter().map(|f| f.id.as_str()).collect::<Vec<_>>()
        );
    }

    /// `for: [all]` opts out of the filter -- the sanctioned way to say "any
    /// file". Without this, `all` would be the most restrictive setting there
    /// is, since it names no concrete type to match an origin against.
    #[test]
    fn for_all_disables_the_origin_filter() {
        let mapper = make_origin_filter_mapper("all");
        let report = make_test_report();
        let nested = vec![
            make_test_finding("test/origin::manifest-marker", Criticality::Notable),
            make_test_finding("test/origin::script-marker", Criticality::Notable),
        ];
        let mut origins: rustc_hash::FxHashMap<String, TypeMask> = rustc_hash::FxHashMap::default();
        origins.insert(
            "test/origin::manifest-marker".to_string(),
            RuleFileType::Elf.type_bit(),
        );
        origins.insert(
            "test/origin::script-marker".to_string(),
            RuleFileType::Markdown.type_bit(),
        );

        let found = mapper.evaluate_container_composites(&report, &nested, "zip", Some(&origins));
        assert!(
            found
                .iter()
                .any(|f| f.id.as_str() == "test/origin::manifest-plus-script"),
            "for: [all] must not be filtered, got {:?}",
            found.iter().map(|f| f.id.as_str()).collect::<Vec<_>>()
        );
    }

    /// An unstamped finding is excluded, not admitted: a call site that forgets
    /// to stamp shows up as a rule that stops firing, which is noticed, rather
    /// than one that fires on anything, which is not.
    #[test]
    fn an_unstamped_finding_does_not_satisfy_a_filtered_rule() {
        let mapper = make_origin_filter_mapper("zip, packagejson, markdown");
        let report = make_test_report();
        let nested = vec![
            make_test_finding("test/origin::manifest-marker", Criticality::Notable),
            make_test_finding("test/origin::script-marker", Criticality::Notable),
        ];
        let mut origins: rustc_hash::FxHashMap<String, TypeMask> = rustc_hash::FxHashMap::default();
        origins.insert(
            "test/origin::manifest-marker".to_string(),
            RuleFileType::PackageJson.type_bit(),
        );
        // script-marker deliberately left unstamped.

        let found = mapper.evaluate_container_composites(&report, &nested, "zip", Some(&origins));
        assert!(
            !found
                .iter()
                .any(|f| f.id.as_str() == "test/origin::manifest-plus-script"),
            "an unstamped finding must not satisfy a filtered leg, got {:?}",
            found.iter().map(|f| f.id.as_str()).collect::<Vec<_>>()
        );
    }

    /// Passing no origin map at all disables the filter for that call site --
    /// the documented opt-out for office/pdf, which cannot stamp yet.
    #[test]
    fn no_origin_map_disables_the_filter() {
        let mapper = make_origin_filter_mapper("zip, packagejson");
        let report = make_test_report();
        let nested = vec![
            make_test_finding("test/origin::manifest-marker", Criticality::Notable),
            make_test_finding("test/origin::script-marker", Criticality::Notable),
        ];
        let found = mapper.evaluate_container_composites(&report, &nested, "zip", None);
        assert!(
            found
                .iter()
                .any(|f| f.id.as_str() == "test/origin::manifest-plus-script"),
            "an unstamped call site must keep its legs, got {:?}",
            found.iter().map(|f| f.id.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn package_composite_spans_artifact_and_registry() {
        let mapper = package_scope_mapper();
        // One finding from the registry metadata report, one from the artifact
        // report — the union this pass evaluates over. Evidence carries no
        // shared location (both reports are finalized), which is why `outer`,
        // the one scope that pools by presence, is the only one that can join
        // them. `scope: package` cannot: it keys on the nearest enclosing
        // package archive, and registry findings have no location at all.
        let seed = vec![
            make_test_finding("test/pkg::deprecated", Criticality::Notable),
            make_test_finding("test/pkg::native-addon", Criticality::Notable),
        ];

        let new_findings = mapper.evaluate_package_composites(&seed);

        assert!(
            new_findings
                .iter()
                .any(|f| f.id == "test/pkg::deprecated-with-addon"),
            "scope: outer composite should fire across the artifact↔registry union, got: {:?}",
            new_findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
        // The file-scoped control must be excluded by the scope filter — it is
        // never even evaluated in the package pass.
        assert!(
            !new_findings
                .iter()
                .any(|f| f.id == "test/pkg::file-control"),
            "file-scoped composite must not participate in the package pass, got: {:?}",
            new_findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
        // Seed findings are not echoed back — only newly-matched composites.
        assert!(
            !new_findings
                .iter()
                .any(|f| f.id == "test/pkg::deprecated" || f.id == "test/pkg::native-addon"),
            "package pass must return only new composite findings"
        );
    }

    #[test]
    fn package_pass_is_a_no_op_without_both_members() {
        let mapper = package_scope_mapper();
        // Only the registry side present — the artifact member is missing, so
        // the `all:` composite cannot fire and nothing is returned.
        let seed = vec![make_test_finding(
            "test/pkg::deprecated",
            Criticality::Notable,
        )];
        assert!(
            mapper.evaluate_package_composites(&seed).is_empty(),
            "package composite must not fire with only one member present"
        );
    }

    /// The sibling-basename walk that drives compact-member kv retention:
    /// `<filename>::` prefixes anywhere in a kv path (main, eq, ne) are
    /// collected lowercased; rules with no sibling reference contribute
    /// nothing, so the empty set is the common case.
    #[test]
    #[allow(clippy::expect_used)]
    fn kv_sibling_basenames_collects_referenced_files_only() {
        let yaml = r#"
traits:
  - id: "test/kv::plain-value"
    desc: "no sibling reference"
    crit: baseline
    if:
      type: value
      path: "scripts.postinstall"
      exists: true

composite_rules:
  - id: "test/kv::sibling-eq"
    desc: "cross-file identity check"
    crit: notable
    all:
      - type: value
        path: "markdown.first_heading"
        eq: "Package.JSON::name"
"#;
        let file = write_test_traits(yaml);
        let mapper =
            super::super::CapabilityMapper::from_yaml(file.path()).expect("load kv mapper");
        let names = mapper.kv_sibling_basenames();
        assert_eq!(
            names.iter().cloned().collect::<Vec<_>>(),
            vec!["package.json".to_string()],
            "eq sibling prefix collected lowercased; plain paths contribute nothing"
        );
    }

    /// `TraitRefIndex` must be a superset of `eval_trait`'s matching: exact
    /// ids, short-name suffix matches, and directory-prefix matches all count
    /// as "possibly referenced".
    #[test]
    fn trait_ref_index_mirrors_eval_trait_matching() {
        use crate::capabilities::mapper::TraitRefIndex;
        let raw: std::collections::BTreeSet<String> = [
            "a/b::exact",       // exact only
            "terminate",        // short: matches final segment
            "anti/obfuscation", // directory: matches boundary prefixes
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let idx = TraitRefIndex::build(raw);

        assert!(idx.possibly_referenced("a/b::exact"));
        assert!(!idx.possibly_referenced("a/b::other"));

        assert!(idx.possibly_referenced("execution/process::terminate"));
        assert!(idx.possibly_referenced("execution/process/terminate"));
        assert!(!idx.possibly_referenced("execution/process::terminated"));

        assert!(idx.possibly_referenced("anti/obfuscation::python-hex"));
        assert!(idx.possibly_referenced("anti/obfuscation/python-hex"));
        assert!(idx.possibly_referenced("anti/obfuscation"));
        assert!(!idx.possibly_referenced("anti/obfuscation-extra::x"));
    }
}
