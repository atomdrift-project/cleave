//! Composite rule evaluation against analysis reports.
//!
//! This module handles the evaluation of composite rules, which combine multiple
//! atomic traits using logical operators (all, any, none, unless). Features:
//! - Two-pass evaluation (positive rules, then negative rules)
//! - Fixed-point iteration for cascading dependencies
//! - Downgrade re-evaluation with complete finding context

use crate::capabilities::indexes::TraitBitSet;
use crate::composite_rules::{Arch, EvaluationContext, FileType as RuleFileType, SectionMap};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use rustc_hash::FxHashMap;
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

        // Pre-allocate capacity for findings to reduce reallocations
        let mut all_findings: Vec<Finding> = Vec::with_capacity(100);
        let mut seen_ids: rustc_hash::FxHashSet<String> = rustc_hash::FxHashSet::default();

        // Track which composite IDs have already matched (including original findings)
        let mut matched_bits = TraitBitSet::with_capacity(self.trait_definitions.len());
        for finding in &report.findings {
            seen_ids.insert(finding.id.clone());
            if let Some(&idx) = self.trait_id_map.get(&finding.id) {
                matched_bits.insert(idx);
            }
        }

        // Split rules into two groups: those with negative conditions and those without
        let (mut negative_rules, mut positive_rules): (Vec<_>, Vec<_>) = self
            .composite_rules
            .iter()
            .partition(|r| r.has_negative_conditions());

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
            .with_section_map(section_map);
            if let Some(results) = inline_yara {
                ctx = ctx.with_inline_yara(results);
            }
            if let Some(ranges) = arch_ranges {
                ctx = ctx.with_arch_ranges(ranges);
            }

            // Evaluate positive rules (sequential to avoid nested rayon overhead for small files)
            let new_findings: Vec<Finding> = positive_rules
                .iter()
                .filter(|rule| !seen_ids.contains(&rule.id))
                .filter(|rule| matched_bits.contains_all(&rule.required_trait_indices))
                .filter_map(|rule| rule.evaluate(&ctx))
                .filter(|f| !seen_ids.contains(&f.id))
                .collect();

            if new_findings.is_empty() {
                break;
            }

            // Add new findings to the accumulated set
            for finding in new_findings {
                seen_ids.insert(finding.id.clone());
                if let Some(&idx) = self.trait_id_map.get(&finding.id) {
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
            .with_section_map(section_map);
            if let Some(results) = inline_yara {
                ctx = ctx.with_inline_yara(results);
            }
            if let Some(ranges) = arch_ranges {
                ctx = ctx.with_arch_ranges(ranges);
            }

            let negative_findings: Vec<Finding> = negative_rules
                .iter()
                .filter(|rule| !seen_ids.contains(&rule.id))
                .filter(|rule| matched_bits.contains_all(&rule.required_trait_indices))
                .filter_map(|rule| rule.evaluate(&ctx))
                .filter(|f| !seen_ids.contains(&f.id))
                .collect();

            if negative_findings.is_empty() {
                break;
            }
            drop(ctx);
            for finding in negative_findings {
                seen_ids.insert(finding.id.clone());
                if let Some(&idx) = self.trait_id_map.get(&finding.id) {
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
                .with_section_map(section_map);
                if let Some(results) = inline_yara {
                    ctx = ctx.with_inline_yara(results);
                }
                if let Some(ranges) = arch_ranges {
                    ctx = ctx.with_arch_ranges(ranges);
                }

                let new_findings: Vec<Finding> = positive_rules
                    .iter()
                    .filter(|rule| !seen_ids.contains(&rule.id))
                    .filter(|rule| matched_bits.contains_all(&rule.required_trait_indices))
                    .filter_map(|rule| rule.evaluate(&ctx))
                    .filter(|f| !seen_ids.contains(&f.id))
                    .collect();

                if new_findings.is_empty() {
                    break;
                }
                drop(ctx);
                for finding in new_findings {
                    seen_ids.insert(finding.id.clone());
                    if let Some(&idx) = self.trait_id_map.get(&finding.id) {
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

        // Add finding for excessive line length (anti-analysis technique)
        // Only check text-based files — binary formats naturally lack newlines
        const MAX_LINE_LENGTH: usize = 1_000_000;
        let target_path = report.target.path.to_ascii_lowercase();
        let is_installer_oledoc = target_path.ends_with(".msi") || target_path.ends_with(".msp");
        let is_binary_format = is_installer_oledoc
            || matches!(
                file_type,
                RuleFileType::Elf
                    | RuleFileType::Macho
                    | RuleFileType::Pe
                    | RuleFileType::Jpeg
                    | RuleFileType::Png
                    | RuleFileType::Pdf
            );
        let m = |key: &str| -> Option<f64> {
            report
                .filefacts_metrics
                .as_ref()
                .and_then(|fm| fm.get(key).copied())
        };
        let binary_like_text_blob = {
            let null_bytes = m("text.null_byte_count").unwrap_or(0.0) as u32;
            let non_printable_ratio = m("text.non_printable_ratio").unwrap_or(0.0) as f32;
            let max_line_length = m("text.max_line_length").unwrap_or(0.0) as u32;
            let most_common_is_null = m("text.most_common_char_is_null").unwrap_or(0.0) > 0.0;
            let most_common_ratio = m("text.most_common_ratio").unwrap_or(0.0) as f32;
            null_bytes >= 4_096
                || (non_printable_ratio >= 0.30 && max_line_length > MAX_LINE_LENGTH as u32)
                || (most_common_is_null && most_common_ratio >= 0.80)
        };
        let escaped_tensor_text_blob = {
            let max_line_length = m("text.max_line_length").unwrap_or(0.0) as u32;
            let lines_over_1000 = m("text.lines_over_1000").unwrap_or(0.0) as u32;
            let char_entropy = m("text.char_entropy").unwrap_or(0.0) as f32;
            let octal_escape_count = m("text.octal_escape_count").unwrap_or(0.0) as u32;
            let escape_density = m("text.escape_density").unwrap_or(0.0) as f32;
            let digit_ratio = m("text.digit_ratio").unwrap_or(0.0) as f32;
            report.target.file_type.eq_ignore_ascii_case("unknown")
                && max_line_length > MAX_LINE_LENGTH as u32
                && lines_over_1000 <= 8
                && char_entropy <= 2.0
                && octal_escape_count >= 100_000
                && escape_density >= 5.0
                && digit_ratio >= 0.90
        };

        let has_excessive_line = if is_binary_format
            || binary_like_text_blob
            // Large protobuf text tensors serialize as low-entropy octal-escaped blobs.
            // They can produce 1MB+ lines without conveying anti-analysis intent.
            || escaped_tensor_text_blob
        {
            false
        } else {
            let content = String::from_utf8_lossy(binary_data);
            content.lines().any(|line| line.len() > MAX_LINE_LENGTH)
        };

        if has_excessive_line {
            // Downgrade to notable for large JS/TS files — minified/bundled code
            // naturally produces very long lines without anti-analysis intent.
            // Source maps are also commonly emitted as single-line JSON blobs.
            let is_source_map = report.target.path.ends_with(".map")
                || (binary_data.starts_with(br#"{"version":"#)
                    && binary_data.windows(10).any(|w| w == br#""sources":["#));
            // Downgrade JSON data files — minified/serialized JSON commonly
            // produces single-line megabyte blobs without anti-analysis intent.
            let is_json_data = report.target.path.ends_with(".json")
                || report.target.path.ends_with(".json.zst")
                || report.target.path.ends_with(".json.gz")
                || report.target.path.ends_with(".json.br")
                || report.target.path.ends_with(".json.xz");
            // Also downgrade any file with very few lines (≤5) — these are
            // typically serialized data, not obfuscated code.
            let is_few_lines = report
                .filefacts_metrics
                .as_ref()
                .and_then(|m| m.get("text.total_lines").copied())
                .is_some_and(|v| v as u32 <= 5);
            let is_likely_bundle = is_source_map
                || is_json_data
                || is_few_lines
                || (matches!(
                    file_type,
                    RuleFileType::JavaScript | RuleFileType::TypeScript
                ) && binary_data.len() > 500_000);
            let crit = if is_likely_bundle {
                Criticality::Notable
            } else {
                Criticality::Suspicious
            };
            all_findings.push(Finding {
                id: "objectives/anti-static/excessive-line-length".to_string(),
                kind: FindingKind::Structural,
                desc: "Excessively long lines (>1MB)".to_string(),
                conf: 0.9,
                crit,
                mbc: None,
                attack: Some("T1027".to_string()), // Obfuscated Files or Information
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "line-length-analysis".to_string(),
                    source: "cleave".to_string(),
                    value: "Detected line(s) exceeding 1MB (potential anti-analysis technique)"
                        .to_string(),
                    location: None,
                    ..Default::default()
                }],
                match_count: 0,
                source_file: None,
            });
        }

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
        // Build a map of rule ID to rule for quick lookup
        let composite_map: FxHashMap<&str, _> = self
            .composite_rules
            .iter()
            .map(|r| (r.id.as_str(), r))
            .collect();

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
            .with_section_map(section_map);

            findings
                .iter()
                .enumerate()
                .filter_map(|(i, finding)| {
                    if let Some(rule) = composite_map.get(finding.id.as_str()) {
                        if let Some(downgrade_rules) = &rule.downgrade {
                            let new_crit =
                                rule.evaluate_downgrade(downgrade_rules, &finding.crit, &ctx);
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

        // Build a combined slice so the evaluator sees both the target's own
        // findings (which trait-reference conditions check against) and the
        // container-level extras.
        let mut combined: Vec<crate::types::Finding> =
            Vec::with_capacity(target_findings.len() + extra_findings.len());
        combined.extend_from_slice(target_findings);
        combined.extend_from_slice(extra_findings);

        let ctx = EvaluationContext::new(
            report,
            binary_data,
            file_type,
            &self.platforms,
            Some(&combined),
            None,
        )
        .with_section_map(section_map);

        let composite_by_id: rustc_hash::FxHashMap<&str, &crate::composite_rules::CompositeTrait> =
            self.composite_rules
                .iter()
                .map(|r| (r.id.as_str(), r))
                .collect();

        let debug_downgrade = std::env::var("DEBUG_DOWNGRADE").is_ok();

        for finding in target_findings.iter_mut() {
            // Atomic traits first: look up the TraitDefinition by id and
            // re-evaluate its downgrade clause if any.
            if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                let trait_def = &self.trait_definitions[idx];
                if let Some(downgrade) = &trait_def.downgrade {
                    let new_crit = trait_def.evaluate_downgrade(downgrade, &trait_def.crit, &ctx);
                    if new_crit != finding.crit {
                        if debug_downgrade {
                            eprintln!(
                                "DEBUG: Cross-scope downgrade for trait '{}': {:?} -> {:?}",
                                finding.id, finding.crit, new_crit
                            );
                        }
                        finding.crit = new_crit;
                    }
                    continue;
                }
            }

            // Composite rules: same dance, but against composite_rules.
            if let Some(rule) = composite_by_id.get(finding.id.as_str()) {
                if let Some(downgrade) = &rule.downgrade {
                    let new_crit = rule.evaluate_downgrade(downgrade, &rule.crit, &ctx);
                    if new_crit != finding.crit {
                        if debug_downgrade {
                            eprintln!(
                                "DEBUG: Cross-scope downgrade for composite '{}': {:?} -> {:?}",
                                finding.id, finding.crit, new_crit
                            );
                        }
                        finding.crit = new_crit;
                    }
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

        let mut findings = Vec::new();
        for trait_def in &self.trait_definitions {
            // Only evaluate traits with Basename conditions
            let Condition::Basename {
                ref exact,
                ref substr,
                regex: _,
                case_insensitive,
                is_check: _,
                ref compiled_regex,
            } = trait_def.r#if
            else {
                continue;
            };

            for entry_name in entry_names {
                let basename = std::path::Path::new(entry_name)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                if basename.is_empty() {
                    continue;
                }

                let (cmp_base, cmp_entry, cmp_exact, cmp_substr) = if case_insensitive {
                    (
                        basename.to_lowercase(),
                        entry_name.to_lowercase(),
                        exact.as_ref().map(|s| s.to_lowercase()),
                        substr.as_ref().map(|s| s.to_lowercase()),
                    )
                } else {
                    (
                        basename.to_string(),
                        entry_name.clone(),
                        exact.clone(),
                        substr.clone(),
                    )
                };

                let matched = if let Some(ref e) = cmp_exact {
                    cmp_base == *e || cmp_entry == *e
                } else if let Some(ref s) = cmp_substr {
                    cmp_base.contains(s.as_str()) || cmp_entry.contains(s.as_str())
                } else if let Some(re) = compiled_regex {
                    re.is_match(basename) || re.is_match(entry_name)
                } else {
                    false
                };

                if matched {
                    findings.push(Finding {
                        id: trait_def.id.clone(),
                        kind: FindingKind::Indicator,
                        desc: trait_def.desc.clone(),
                        conf: trait_def.conf,
                        crit: trait_def.crit,
                        mbc: trait_def.mbc.clone(),
                        attack: trait_def.attack.clone(),
                        trait_refs: vec![],
                        evidence: vec![Evidence {
                            method: "basename".to_string(),
                            source: "archive-entry".to_string(),
                            value: entry_name.clone(),
                            location: None,
                            ..Default::default()
                        }],
                        match_count: 0,
                        source_file: None,
                    });
                    break; // One match per trait is enough
                }
            }
        }
        findings
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
        let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut matched_bits = TraitBitSet::with_capacity(self.trait_definitions.len());
        for finding in &container_report.findings {
            seen_ids.insert(finding.id.clone());
            if let Some(&idx) = self.trait_id_map.get(&finding.id) {
                matched_bits.insert(idx);
            }
        }
        for finding in nested_findings {
            if let Some(&idx) = self.trait_id_map.get(&finding.id) {
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
            .filter(|f| !seen_ids.contains(&f.id))
            .collect();

        for finding in &container_findings {
            seen_ids.insert(finding.id.clone());
            if let Some(&idx) = self.trait_id_map.get(&finding.id) {
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
                .filter(|f| !seen_ids.contains(&f.id))
                .collect();

            if new_findings.is_empty() {
                break;
            }

            for finding in new_findings {
                seen_ids.insert(finding.id.clone());
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
                    location: None,
                    ..Default::default()
                });
            }
        }

        container_findings
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
defaults:
  for: [all]

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
defaults:
  for: [all]

traits:
  - id: "test/archive::macos-temp-staging-path"
    desc: "Archive preserves macOS temp staging path"
    crit: suspicious
    conf: 0.96
    if:
      type: basename
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
defaults:
  for: [all]

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
}
