//! Composite rule evaluation against analysis reports.
//!
//! This module handles the evaluation of composite rules, which combine multiple
//! atomic traits using logical operators (all, any, none, unless). Features:
//! - Two-pass evaluation (positive rules, then negative rules)
//! - Fixed-point iteration for cascading dependencies
//! - Downgrade re-evaluation with complete finding context

use crate::capabilities::indexes::TraitBitSet;
use crate::composite_rules::PathQuery;
use crate::composite_rules::{Arch, EvaluationContext, FileType as RuleFileType, SectionMap};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use std::collections::HashMap;
use std::path::Path;

impl super::CapabilityMapper {
    /// Evaluate composite rules against an analysis report.
    /// `inline_yara` supplies pre-scanned results from the combined YARA engine.
    ///
    /// Platform filtering is controlled by the `platform` field set via `with_platform()`.
    #[must_use]
    pub(crate) fn evaluate_composite_rules(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
        section_map: &SectionMap,
        arch_ranges: Option<&[(Arch, std::ops::Range<usize>)]>,
    ) -> Vec<Finding> {
        // Determine file type from report (platform comes from self.platform)
        let file_type = self.detect_file_type(&report.target.file_type);

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

        // Pre-allocate capacity for findings to reduce reallocations
        let mut all_findings: Vec<Finding> = Vec::with_capacity(100);
        let mut seen_ids: rustc_hash::FxHashSet<String> = rustc_hash::FxHashSet::default();

        // Track which composite IDs have already matched (including original findings)
        let mut matched_bits = TraitBitSet::with_capacity(self.trait_definitions.len());
        for finding in &report.findings {
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
        let mut positive_rules: Vec<&crate::composite_rules::CompositeTrait> = worklists
            .positive
            .iter()
            .map(|&i| &self.composite_rules[i as usize])
            .collect();
        let mut negative_rules: Vec<&crate::composite_rules::CompositeTrait> = worklists
            .negative
            .iter()
            .map(|&i| &self.composite_rules[i as usize])
            .collect();

        let is_tiny_dos_com_candidate = file_type == RuleFileType::Unknown
            && binary_data.len() <= 4096
            && Path::new(&report.target.path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("com"));

        if is_tiny_dos_com_candidate {
            let allow_rule = |rule: &&crate::composite_rules::CompositeTrait| {
                let source = rule.defined_in.to_string_lossy();
                source.ends_with("/metadata/binary/layout/msdos.yaml")
                    || source.ends_with("/micro-behaviors/os/msdos/interrupt/file_management.yaml")
                    || source.ends_with("/micro-behaviors/time/schedule/calendar/msdos.yaml")
                    || source.ends_with("/objectives/evasion/self-delete/file/msdos.yaml")
                    || source.ends_with("/objectives/impact/infect/virus/msdos-binary.yaml")
                    || source.ends_with("/well-known/malware/virus/friday_the_13th/msdos.yaml")
            };
            positive_rules.retain(allow_rule);
            negative_rules.retain(allow_rule);
        }

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
            report,
            binary_data,
            cached_ast,
            file_type,
            section_map,
        );
        // Excessive-line-length detection (>1MB single line) is emitted by YAML
        // traits, not here: the only input is the `text.max_line_length` metric.
        // JS/TS megabyte lines → line-shape::js-megabyte-single-line (notable);
        // other scripts/source → line-length::excessive-line-length (suspicious).
        // Both carry the binary-blob / minified-bundle carve-outs as `unless:`.

        all_findings
    }

    /// Re-evaluate downgrade conditions for all findings using the complete finding set.
    /// This handles ordering issues where a composite's downgrade depends on another composite.
    fn reeval_downgrades(
        &self,
        findings: &mut [Finding],
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        file_type: RuleFileType,
        section_map: &SectionMap,
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
            .with_section_map(section_map)
            .with_file_caches(&file_caches);

            findings
                .iter()
                .enumerate()
                .filter_map(|(i, finding)| {
                    if let Some(rule) = composite_map
                        .get(finding.id.as_str())
                        .map(|&i| &self.composite_rules[i])
                        && let Some(downgrade_rules) = &rule.downgrade
                    {
                        let new_crit =
                            rule.evaluate_downgrade(downgrade_rules, &finding.crit, &ctx);
                        if new_crit != finding.crit {
                            return Some((i, new_crit));
                        }
                    }
                    None
                })
                .collect()
        };

        // Second pass: apply updates
        for (idx, new_crit) in updates {
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
                if let Some(downgrade) = &trait_def.downgrade {
                    let new_crit = trait_def.evaluate_downgrade(downgrade, &trait_def.crit, &ctx);
                    if new_crit != finding.crit {
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
            {
                let new_crit = rule.evaluate_downgrade(downgrade, &rule.crit, &ctx);
                if new_crit != finding.crit {
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
            })
        };
        if crate::rayon_nest::inner_work_parallel() {
            path_traits.par_iter().filter_map(evaluate).collect()
        } else {
            path_traits.iter().filter_map(evaluate).collect()
        }
    }

    pub(crate) fn evaluate_container_composites(
        &self,
        container_report: &AnalysisReport,
        nested_findings: &[Finding],
        file_type: &str,
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
        let mut container_findings: Vec<Finding> = self
            .trait_definitions
            .iter()
            .filter_map(|trait_def| trait_def.evaluate(&parent_trait_ctx))
            .filter(|f| !seen_ids.contains(f.id.as_str()))
            .collect();

        for finding in &container_findings {
            seen_ids.insert(finding.id.clone().to_string());
            if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                matched_bits.insert(idx);
            }
        }

        let mut combined_findings = nested_findings.to_vec();
        combined_findings.extend(container_findings.iter().cloned());

        // Evaluate all composite rules at container level. Rules can match on:
        // - nested file findings across the container
        // - parent/container atomics evaluated above
        // This enables cross-file patterns like "npm package with .dll" and
        // parent-byte patterns like encrypted ZIP/APK members.

        // Iterative evaluation to handle chained dependencies
        const MAX_ITERATIONS: usize = 5;
        for _ in 0..MAX_ITERATIONS {
            let ctx = EvaluationContext::new(
                container_report,
                &container_bytes,
                rule_file_type,
                &self.platforms,
                Some(&combined_findings),
                None, // No AST for container
            );
            let new_findings: Vec<Finding> = self
                .composite_rules
                .iter()
                .filter_map(|rule| rule.evaluate(&ctx))
                .filter(|f| !seen_ids.contains(f.id.as_str()))
                .collect();

            if new_findings.is_empty() {
                break;
            }

            for finding in new_findings {
                seen_ids.insert(finding.id.clone().to_string());
                combined_findings.push(finding.clone());
                container_findings.push(finding);
            }
        }

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
    /// Only composites with `scope: package` or `scope: outer` participate.
    /// Both pool by presence (empty scope key). `file`/`archive`/`leaf`
    /// composites are excluded on purpose: by the time the artifact and
    /// registry reports meet they are both finalized, so their evidence
    /// locations are gone — a location-keyed scope would collapse every item to
    /// the empty key and fire spuriously. Returns only newly-matched composite
    /// findings (none of the `seed_findings` are echoed back).
    #[must_use]
    pub(crate) fn evaluate_package_composites(&self, seed_findings: &[Finding]) -> Vec<Finding> {
        use crate::composite_rules::Scope;

        // Composites that explicitly pool across the artifact↔registry boundary.
        let package_rules: Vec<&crate::composite_rules::CompositeTrait> = self
            .composite_rules
            .iter()
            .filter(|r| matches!(r.scope, Some(Scope::Package | Scope::Outer)))
            .collect();
        if package_rules.is_empty() {
            return Vec::new();
        }

        // A synthetic container with no bytes of its own. `FileType::All` lets a
        // package rule whose `for:` lists leaf types (e.g. `registry`,
        // `package_json`) still evaluate at this pooled level.
        let report = AnalysisReport::new(crate::types::TargetInfo {
            path: String::new(),
            file_type: "all".to_string(),
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
            let ctx = EvaluationContext::new(
                &report,
                no_bytes,
                RuleFileType::All,
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

#[cfg(test)]
mod tests {
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

    #[test]
    #[allow(clippy::expect_used)]
    fn test_evaluate_container_composites_empty_findings() {
        let mapper = super::super::CapabilityMapper::empty();
        let report = make_test_report();

        // With no nested findings, should return empty
        let container_findings = mapper.evaluate_container_composites(&report, &[], "zip");
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
        let container_findings = mapper.evaluate_container_composites(&report, &nested, "zip");

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

        let container_findings = mapper.evaluate_container_composites(&report, &nested, "zip");

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
            let _ = mapper.evaluate_container_composites(&report, &nested, file_type);
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
        // A composite with `for: [javascript]` is normally gated out at the
        // container/archive level (the container's file_type is the archive
        // type, not javascript). But `scope: outer`/`archive` explicitly pools
        // evidence across archive entries, so such a composite MUST be allowed
        // to run at the container level — otherwise it can never see the
        // cross-entry findings it was written for (e.g. a browser-extension
        // rule whose content-script and manifest evidence live in different
        // CRX entries). A plain file-scoped composite must stay gated out.
        let yaml = r#"
defaults:
  for: [javascript]
  platforms: [all]

traits:
  - id: "test/ext::scrape"
    desc: "AI chat scrape"
    crit: suspicious
    if:
      type: text
      substr: "SCRAPE_MARKER"
  - id: "test/ext::cors"
    desc: "CORS rewrite"
    crit: suspicious
    if:
      type: text
      substr: "CORS_MARKER"

composite_rules:
  - id: "test/ext::outer-exfil"
    desc: "Outer-scoped cross-entry exfil"
    crit: hostile
    conf: 0.95
    scope: outer
    all:
      - id: "test/ext::scrape"
      - id: "test/ext::cors"
  - id: "test/ext::file-exfil"
    desc: "File-scoped exfil (control)"
    crit: hostile
    conf: 0.95
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

        let container_findings = mapper.evaluate_container_composites(&report, &nested, "crx");

        // The scope: outer composite must fire at the archive container level
        // despite its `for: [javascript]` not matching the crx container type.
        assert!(
            container_findings
                .iter()
                .any(|f| f.id == "test/ext::outer-exfil"),
            "scope: outer composite should evaluate at archive container level, got: {:?}",
            container_findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );

        // The file-scoped (default) composite with for: [javascript] must stay
        // gated out at the archive container level — the relaxation is specific
        // to outer/archive scope and must not turn every leaf-typed composite
        // into a container-level rule.
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
    scope: package
    all:
      - id: "test/pkg::deprecated"
      - id: "test/pkg::native-addon"
  - id: "test/pkg::file-control"
    desc: "Same members, file scope (must not span the boundary)"
    crit: suspicious
    conf: 0.9
    all:
      - id: "test/pkg::deprecated"
      - id: "test/pkg::native-addon"
"#;
        let file = write_test_traits(yaml);
        super::super::CapabilityMapper::from_yaml(file.path()).expect("load package-scope mapper")
    }

    #[test]
    fn package_composite_spans_artifact_and_registry() {
        let mapper = package_scope_mapper();
        // One finding from the registry metadata report, one from the artifact
        // report — the union the package pass evaluates over. Evidence carries
        // no shared location (both reports are finalized), which is exactly the
        // condition package scope is designed to tolerate.
        let seed = vec![
            make_test_finding("test/pkg::deprecated", Criticality::Notable),
            make_test_finding("test/pkg::native-addon", Criticality::Notable),
        ];

        let new_findings = mapper.evaluate_package_composites(&seed);

        assert!(
            new_findings
                .iter()
                .any(|f| f.id == "test/pkg::deprecated-with-addon"),
            "scope: package composite should fire across the artifact↔registry union, got: {:?}",
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
