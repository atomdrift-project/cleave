//! Composite rule evaluation against analysis reports.
//!
//! This module handles the evaluation of composite rules, which combine multiple
//! atomic traits using logical operators (all, any, none, unless). Features:
//! - Two-pass evaluation (positive rules, then negative rules)
//! - Fixed-point iteration for cascading dependencies
//! - Downgrade re-evaluation with complete finding context

use crate::composite_rules::{Arch, EvaluationContext, FileType as RuleFileType, SectionMap};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
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
        section_map: &SectionMap,
        arch_ranges: Option<&[(Arch, std::ops::Range<usize>)]>,
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
            if let Some(ranges) = arch_ranges {
                ctx = ctx.with_arch_ranges(ranges.to_vec());
            }

            // Evaluate positive rules (sequential to avoid nested rayon overhead for small files)
            let new_findings: Vec<Finding> = positive_rules
                .iter()
                .filter_map(|rule| rule.evaluate(&ctx))
                .filter(|f| !seen_ids.contains(&f.id))
                .collect();

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
        if let Some(ranges) = arch_ranges {
            ctx = ctx.with_arch_ranges(ranges.to_vec());
        }

        let negative_findings: Vec<Finding> = negative_rules
            .iter()
            .filter_map(|rule| rule.evaluate(&ctx))
            .filter(|f| !seen_ids.contains(&f.id))
            .collect();

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
            section_map,
        );

        // Add finding for excessive line length (anti-analysis technique)
        // Only check text-based files — binary formats naturally lack newlines
        const MAX_LINE_LENGTH: usize = 1_000_000;
        let is_binary_format = matches!(
            file_type,
            RuleFileType::Elf
                | RuleFileType::Macho
                | RuleFileType::Pe
                | RuleFileType::Dll
                | RuleFileType::So
                | RuleFileType::Dylib
                | RuleFileType::Jpeg
                | RuleFileType::Png
                | RuleFileType::Pdf
        );
        let binary_like_text_blob = report
            .metrics
            .as_ref()
            .and_then(|metrics| metrics.text.as_ref())
            .is_some_and(|text| {
                text.null_byte_count >= 4_096
                    || (text.non_printable_ratio >= 0.30
                        && text.max_line_length > MAX_LINE_LENGTH as u32)
                    || (text.most_common_char == Some('\0') && text.most_common_ratio >= 0.80)
            });

        let has_excessive_line = if is_binary_format || binary_like_text_blob {
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
            let is_likely_bundle = is_source_map
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
                desc:
                    "File contains excessively long lines (>1MB) that may cause regex backtracking"
                        .to_string(),
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
                self.platforms.clone(),
                Some(findings),
                cached_ast,
            )
            .with_section_map(section_map.clone());

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

                let (cmp_base, cmp_exact, cmp_substr) = if case_insensitive {
                    (
                        basename.to_lowercase(),
                        exact.as_ref().map(|s| s.to_lowercase()),
                        substr.as_ref().map(|s| s.to_lowercase()),
                    )
                } else {
                    (basename.to_string(), exact.clone(), substr.clone())
                };

                let matched = if let Some(ref e) = cmp_exact {
                    cmp_base == *e
                } else if let Some(ref s) = cmp_substr {
                    cmp_base.contains(s.as_str())
                } else if let Some(re) = compiled_regex {
                    re.is_match(basename)
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

        // Track which composite IDs have already matched
        let mut seen_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        for finding in &container_report.findings {
            seen_ids.insert(finding.id.clone());
        }

        // Create evaluation context with nested findings as additional_findings
        // This allows composite rules to "see" findings from all nested files
        let ctx = EvaluationContext::new(
            container_report,
            &[], // No binary data for container-level evaluation
            rule_file_type,
            self.platforms.clone(),
            Some(nested_findings),
            None, // No AST for container
        );

        // Evaluate all composite rules at container level - rules will only match if their
        // conditions are met by findings from nested files. This enables cross-file patterns
        // like "npm package with .dll" where package.json is in one file and .dll in another.
        let mut container_findings: Vec<Finding> = Vec::new();

        // Iterative evaluation to handle chained dependencies
        const MAX_ITERATIONS: usize = 5;
        for _ in 0..MAX_ITERATIONS {
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
    fn test_evaluate_basename_traits_empty_entries() {
        let mapper = make_basename_mapper();
        let findings = mapper.evaluate_basename_traits_for_entries(&[]);
        assert!(findings.is_empty());
    }
}
