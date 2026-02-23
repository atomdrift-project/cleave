//! Composite rule evaluation against analysis reports.
//!
//! This module handles the evaluation of composite rules, which combine multiple
//! atomic traits using logical operators (all, any, none, unless). Features:
//! - Two-pass evaluation (positive rules, then negative rules)
//! - Fixed-point iteration for cascading dependencies
//! - Downgrade re-evaluation with complete finding context

use crate::composite_rules::{EvaluationContext, FileType as RuleFileType, SectionMap};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::collections::HashMap;

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
    ) -> Vec<Finding> {
        // Determine file type from report (platform comes from self.platform)
        let file_type = self.detect_file_type(&report.target.file_type);

        // Pre-allocate capacity for findings to reduce reallocations
        let mut all_findings: Vec<Finding> = Vec::with_capacity(100);
        let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Track which composite IDs have already matched (including original findings)
        for finding in &report.findings {
            seen_ids.insert(finding.id.clone());
        }

        // Split rules into two groups: those with negative conditions and those without
        let (negative_rules, positive_rules): (Vec<_>, Vec<_>) = self
            .composite_rules
            .iter()
            .partition(|r| r.has_negative_conditions());

        // Build section map once for location-constrained matching
        let section_map = SectionMap::from_binary(binary_data);

        // Pass 1: Iterative evaluation of positive rules to reach a stable fixed-point
        const MAX_ITERATIONS: usize = 10;
        for _ in 0..MAX_ITERATIONS {
            let mut ctx = EvaluationContext::new(
                report,
                binary_data,
                file_type,
                self.platforms.clone(),
                if all_findings.is_empty() {
                    None
                } else {
                    Some(&all_findings)
                },
                cached_ast,
            )
            .with_section_map(section_map.clone());
            if let Some(results) = inline_yara {
                ctx = ctx.with_inline_yara(results);
            }

            // Evaluate positive rules (parallel for large sets, sequential for small)
            let new_findings: Vec<Finding> = if positive_rules.len() > 50 {
                positive_rules
                    .par_iter()
                    .filter_map(|rule| rule.evaluate(&ctx))
                    .filter(|f| !seen_ids.contains(&f.id))
                    .collect()
            } else {
                positive_rules
                    .iter()
                    .filter_map(|rule| rule.evaluate(&ctx))
                    .filter(|f| !seen_ids.contains(&f.id))
                    .collect()
            };

            if new_findings.is_empty() {
                break;
            }

            // Add new findings to the accumulated set
            for finding in new_findings {
                seen_ids.insert(finding.id.clone());
                all_findings.push(finding);
            }
        }

        // Pass 2: Final evaluation of rules with negative conditions (exclusions)
        // These are only checked AFTER all positive indicators have reached a stable state.
        let mut ctx = EvaluationContext::new(
            report,
            binary_data,
            file_type,
            self.platforms.clone(),
            if all_findings.is_empty() {
                None
            } else {
                Some(&all_findings)
            },
            cached_ast,
        )
        .with_section_map(section_map.clone());
        if let Some(results) = inline_yara {
            ctx = ctx.with_inline_yara(results);
        }

        let negative_findings: Vec<Finding> = if negative_rules.len() > 50 {
            negative_rules
                .par_iter()
                .filter_map(|rule| rule.evaluate(&ctx))
                .filter(|f| !seen_ids.contains(&f.id))
                .collect()
        } else {
            negative_rules
                .iter()
                .filter_map(|rule| rule.evaluate(&ctx))
                .filter(|f| !seen_ids.contains(&f.id))
                .collect()
        };

        for finding in negative_findings {
            all_findings.push(finding);
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
        );

        // Add finding for excessive line length (anti-analysis technique)
        // Check here as well in case composite rules are evaluated without traits
        const MAX_LINE_LENGTH: usize = 1_000_000;
        let content = String::from_utf8_lossy(binary_data);
        let has_excessive_line = content.lines().any(|line| line.len() > MAX_LINE_LENGTH);

        if has_excessive_line {
            all_findings.push(Finding {
                id: "objectives/anti-static/excessive-line-length".to_string(),
                kind: FindingKind::Structural,
                desc:
                    "File contains excessively long lines (>1MB) that may cause regex backtracking"
                        .to_string(),
                conf: 0.9,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: Some("T1027".to_string()), // Obfuscated Files or Information
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "line-length-analysis".to_string(),
                    source: "flayer".to_string(),
                    value: "Detected line(s) exceeding 1MB (potential anti-analysis technique)"
                        .to_string(),
                    location: None,
                }],
                source_file: None,
            });
        }

        // Print condition evaluation statistics
        crate::composite_rules::traits::print_condition_stats();

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
    ) {
        // Build a map of rule ID to rule for quick lookup
        let composite_map: FxHashMap<&str, _> = self
            .composite_rules
            .iter()
            .map(|r| (r.id.as_str(), r))
            .collect();

        // First pass: collect new criticalities (can't mutate while borrowing for context)
        let updates: Vec<(usize, Criticality)> = {
            // Build section map for location-constrained matching
            let section_map = SectionMap::from_binary(binary_data);

            // Create final context with all findings (immutable borrow)
            let ctx = EvaluationContext::new(
                report,
                binary_data,
                file_type,
                self.platforms.clone(),
                Some(findings),
                cached_ast,
            )
            .with_section_map(section_map);

            findings
                .iter()
                .enumerate()
                .filter_map(|(i, finding)| {
                    if let Some(rule) = composite_map.get(finding.id.as_str()) {
                        if let Some(downgrade_rules) = &rule.downgrade {
                            let new_crit =
                                rule.evaluate_downgrade(downgrade_rules, &rule.crit, &ctx);
                            if new_crit != finding.crit {
                                return Some((i, new_crit));
                            }
                        }
                    }
                    None
                })
                .collect()
        };

        // Second pass: apply updates
        let debug_downgrade = std::env::var("DEBUG_DOWNGRADE").is_ok();
        for (idx, new_crit) in updates {
            if debug_downgrade {
                eprintln!(
                    "DEBUG: Re-eval downgrade for '{}': {:?} -> {:?}",
                    findings[idx].id, findings[idx].crit, new_crit
                );
            }
            findings[idx].crit = new_crit;
        }
    }
}
