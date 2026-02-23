//! Binary and package version comparison.
//!
//! This module performs differential analysis between two versions of a file,
//! identifying added/removed/modified capabilities, functions, and metrics.
//!
//! # Architecture
//! - `utils`: Rename detection and file similarity scoring
//! - `formatting`: Terminal output formatting
//! - `risk`: Risk assessment for capability changes
//!
//! # Use Cases
//! - Supply chain attack detection (xz-utils scenario)
//! - Version comparison for packages
//! - Security regression analysis

mod formatting;
mod risk;
mod utils;

// Re-export for binary use (main.rs)
#[allow(unused_imports)]
pub(crate) use formatting::format_diff_terminal;

// Internal imports
use utils::{compute_added_removed, detect_renames};

use crate::analyzers::{archive::ArchiveAnalyzer, detect_file_type, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Diff analyzer for detecting supply chain attacks (xz-utils scenario)
#[derive(Debug)]
pub struct DiffAnalyzer {
    baseline_path: PathBuf,
    target_path: PathBuf,
    capability_mapper: CapabilityMapper,
}
impl DiffAnalyzer {
    /// Create a new diff analyzer comparing baseline to target
    pub fn new(baseline: impl AsRef<Path>, target: impl AsRef<Path>) -> Self {
        Self {
            baseline_path: baseline.as_ref().to_path_buf(),
            target_path: target.as_ref().to_path_buf(),
            capability_mapper: CapabilityMapper::new(),
        }
    }

    /// Create a new diff analyzer for testing (without validation)
    #[cfg(test)]
    pub(crate) fn new_for_test(baseline: impl AsRef<Path>, target: impl AsRef<Path>) -> Self {
        Self {
            baseline_path: baseline.as_ref().to_path_buf(),
            target_path: target.as_ref().to_path_buf(),
            capability_mapper: CapabilityMapper::new_without_validation(),
        }
    }

    /// Run the diff analysis and return a DiffReport
    pub fn analyze(&self) -> Result<DiffReport> {
        // Determine if we're comparing files or directories
        let is_baseline_dir = self.baseline_path.is_dir();
        let is_target_dir = self.target_path.is_dir();

        let diff_report = if is_baseline_dir && is_target_dir {
            self.analyze_directories()?
        } else if !is_baseline_dir && !is_target_dir {
            self.analyze_files()?
        } else {
            anyhow::bail!("Baseline and target must both be files or both be directories");
        };

        Ok(diff_report)
    }

    fn analyze_files(&self) -> Result<DiffReport> {
        // Analyze both files
        let baseline_report = self.analyze_single_file(&self.baseline_path)?;
        let target_report = self.analyze_single_file(&self.target_path)?;

        // Compare
        let analysis = self.compare_reports(
            &self.baseline_path.display().to_string(),
            &baseline_report,
            &target_report,
        );

        let mut modified_analysis = Vec::new();
        if !analysis.new_capabilities.is_empty() || !analysis.removed_capabilities.is_empty() {
            modified_analysis.push(analysis);
        }

        Ok(DiffReport {
            schema_version: "1.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: self.baseline_path.display().to_string(),
            target: self.target_path.display().to_string(),
            changes: FileChanges {
                added: vec![],
                removed: vec![],
                modified: if modified_analysis.is_empty() {
                    vec![]
                } else {
                    vec![self.target_path.display().to_string()]
                },
                renamed: vec![],
            },
            modified_analysis,
            metadata: AnalysisMetadata {
                analysis_duration_ms: 0,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        })
    }

    fn analyze_directories(&self) -> Result<DiffReport> {
        // Get all files in both directories
        let baseline_files = self.collect_files(&self.baseline_path)?;
        let target_files = self.collect_files(&self.target_path)?;

        // Determine what changed
        let baseline_set: HashSet<_> = baseline_files.keys().collect();
        let target_set: HashSet<_> = target_files.keys().collect();

        let mut added: Vec<String> = target_set
            .difference(&baseline_set)
            .map(std::string::ToString::to_string)
            .collect();
        let mut removed: Vec<String> = baseline_set
            .difference(&target_set)
            .map(std::string::ToString::to_string)
            .collect();
        let modified_candidates: Vec<String> = baseline_set
            .intersection(&target_set)
            .map(std::string::ToString::to_string)
            .collect();

        // Detect renames using similarity scoring
        let renames = detect_renames(&removed, &added);

        if !renames.is_empty() {
            // Remove renamed files from added/removed lists
            let renamed_baseline: HashSet<String> =
                renames.iter().map(|r| r.baseline_path.clone()).collect();
            let renamed_target: HashSet<String> =
                renames.iter().map(|r| r.target_path.clone()).collect();

            removed.retain(|f| !renamed_baseline.contains(f));
            added.retain(|f| !renamed_target.contains(f));
        }

        // Analyze modified files
        let mut modified_analysis = Vec::new();
        let mut actually_modified = Vec::new();

        for relative_path in modified_candidates {
            let (Some(baseline_file), Some(target_file)) = (
                baseline_files.get(&relative_path),
                target_files.get(&relative_path),
            ) else {
                continue; // Should not happen since these are from intersection
            };

            // Quick check: if sizes match and content matches, skip
            if let (Ok(baseline_meta), Ok(target_meta)) =
                (fs::metadata(baseline_file), fs::metadata(target_file))
            {
                if baseline_meta.len() == target_meta.len() {
                    if let (Ok(baseline_content), Ok(target_content)) =
                        (fs::read(baseline_file), fs::read(target_file))
                    {
                        if baseline_content == target_content {
                            continue; // Files are identical
                        }
                    }
                }
            }

            // Files differ - analyze both
            match (
                self.analyze_single_file(baseline_file),
                self.analyze_single_file(target_file),
            ) {
                (Ok(baseline_report), Ok(target_report)) => {
                    let analysis =
                        self.compare_reports(&relative_path, &baseline_report, &target_report);

                    if !analysis.new_capabilities.is_empty()
                        || !analysis.removed_capabilities.is_empty()
                    {
                        actually_modified.push(relative_path.clone());
                        modified_analysis.push(analysis);
                    }
                }
                _ => {
                    // Failed to analyze, skip
                }
            }
        }

        // Convert renames to FileRenameInfo
        let renamed_files: Vec<FileRenameInfo> = renames
            .iter()
            .map(|r| FileRenameInfo {
                from: r.baseline_path.clone(),
                to: r.target_path.clone(),
                similarity: r.similarity_score,
            })
            .collect();

        Ok(DiffReport {
            schema_version: "1.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: self.baseline_path.display().to_string(),
            target: self.target_path.display().to_string(),
            changes: FileChanges {
                added,
                removed,
                modified: actually_modified,
                renamed: renamed_files,
            },
            modified_analysis,
            metadata: AnalysisMetadata {
                analysis_duration_ms: 0,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        })
    }

    fn collect_files(&self, dir: &Path) -> Result<HashMap<String, PathBuf>> {
        let mut files = HashMap::new();

        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let relative = path
                .strip_prefix(dir)
                .context("Failed to get relative path")?
                .to_string_lossy()
                .to_string();

            files.insert(relative, path.to_path_buf());
        }

        Ok(files)
    }

    fn analyze_single_file(&self, path: &Path) -> Result<AnalysisReport> {
        let file_type = detect_file_type(path)?;

        // Handle archives specially since they need ArchiveAnalyzer with depth config
        if file_type == crate::analyzers::FileType::Archive {
            let analyzer =
                ArchiveAnalyzer::new().with_capability_mapper(self.capability_mapper.clone());
            return analyzer.analyze(path);
        }

        // Use the centralized factory for all other file types
        if let Some(analyzer) = crate::analyzers::analyzer_for_file_type(
            &file_type,
            Some(self.capability_mapper.clone()),
        ) {
            analyzer.analyze(path)
        } else {
            anyhow::bail!("Unsupported file type for diff analysis: {:?}", file_type)
        }
    }

    fn compare_reports(
        &self,
        file_path: &str,
        baseline: &AnalysisReport,
        target: &AnalysisReport,
    ) -> ModifiedFileAnalysis {
        let baseline_cap_ids: HashSet<String> =
            baseline.findings.iter().map(|c| c.id.clone()).collect();

        let target_cap_ids: HashSet<String> =
            target.findings.iter().map(|c| c.id.clone()).collect();

        // Get IDs of new and removed capabilities
        let new_cap_ids: HashSet<&String> = target_cap_ids.difference(&baseline_cap_ids).collect();
        let removed_cap_ids: HashSet<&String> =
            baseline_cap_ids.difference(&target_cap_ids).collect();

        // Get full capability objects for new capabilities (from target)
        let new_capabilities: Vec<Finding> = target
            .findings
            .iter()
            .filter(|c| new_cap_ids.contains(&c.id))
            .cloned()
            .collect();

        // Get full capability objects for removed capabilities (from baseline)
        let removed_capabilities: Vec<Finding> = baseline
            .findings
            .iter()
            .filter(|c| removed_cap_ids.contains(&c.id))
            .cloned()
            .collect();

        // Risk assessment
        let risk_increase = self.assess_risk_increase(&new_capabilities, &removed_capabilities);

        ModifiedFileAnalysis {
            file: file_path.to_string(),
            new_capabilities,
            removed_capabilities,
            capability_delta: target_cap_ids.len() as i32 - baseline_cap_ids.len() as i32,
            risk_increase,
        }
    }

    /// Create a comprehensive diff suitable for ML analysis
    /// Treats the delta as a "virtual program" with all field differences
    #[allow(dead_code)] // Used by binary target
    fn create_full_diff(
        &self,
        file_path: &str,
        baseline: &AnalysisReport,
        target: &AnalysisReport,
    ) -> FileDiff {
        // Compute all collection deltas
        let (added_findings, removed_findings) =
            compute_added_removed(&baseline.findings, &target.findings, |f| f.id.clone());

        let (added_traits, removed_traits) =
            compute_added_removed(&baseline.traits, &target.traits, |t| {
                format!("{:?}:{}", t.kind, t.value)
            });

        let (added_strings, removed_strings) =
            compute_added_removed(&baseline.strings, &target.strings, |s| s.value.clone());

        let (added_imports, removed_imports) =
            compute_added_removed(&baseline.imports, &target.imports, |i| {
                format!("{}:{}", i.source, i.symbol)
            });

        let (added_exports, removed_exports) =
            compute_added_removed(&baseline.exports, &target.exports, |e| e.symbol.clone());

        let (added_functions, removed_functions) =
            compute_added_removed(&baseline.functions, &target.functions, |f| f.name.clone());

        let (added_syscalls, removed_syscalls) =
            compute_added_removed(&baseline.syscalls, &target.syscalls, |s| s.name.clone());

        let (added_paths, removed_paths) =
            compute_added_removed(&baseline.paths, &target.paths, |p| p.path.clone());

        let (added_env_vars, removed_env_vars) =
            compute_added_removed(&baseline.env_vars, &target.env_vars, |e| e.name.clone());

        let (added_yara_matches, removed_yara_matches) =
            compute_added_removed(&baseline.yara_matches, &target.yara_matches, |y| {
                format!("{}:{}", y.namespace, y.rule)
            });

        // Compute metrics deltas
        let metrics_delta = self.compute_metrics_delta(baseline, target);

        // Compute counts summary
        let counts = DiffCounts {
            findings_added: added_findings.len() as i32,
            findings_removed: removed_findings.len() as i32,
            traits_added: added_traits.len() as i32,
            traits_removed: removed_traits.len() as i32,
            strings_added: added_strings.len() as i32,
            strings_removed: removed_strings.len() as i32,
            imports_added: added_imports.len() as i32,
            imports_removed: removed_imports.len() as i32,
            exports_added: added_exports.len() as i32,
            exports_removed: removed_exports.len() as i32,
            functions_added: added_functions.len() as i32,
            functions_removed: removed_functions.len() as i32,
            syscalls_added: added_syscalls.len() as i32,
            syscalls_removed: removed_syscalls.len() as i32,
            paths_added: added_paths.len() as i32,
            paths_removed: removed_paths.len() as i32,
            env_vars_added: added_env_vars.len() as i32,
            env_vars_removed: removed_env_vars.len() as i32,
        };

        // Risk assessment
        let risk_increase = self.assess_risk_increase(&added_findings, &removed_findings);

        FileDiff {
            file: file_path.to_string(),
            added_findings,
            removed_findings,
            added_traits,
            removed_traits,
            added_strings,
            removed_strings,
            added_imports,
            removed_imports,
            added_exports,
            removed_exports,
            added_functions,
            removed_functions,
            added_syscalls,
            removed_syscalls,
            added_paths,
            removed_paths,
            added_env_vars,
            removed_env_vars,
            added_yara_matches,
            removed_yara_matches,
            metrics_delta: Some(metrics_delta),
            counts: Some(counts),
            risk_increase,
            risk_score_delta: None, // TODO: implement risk scoring
        }
    }

    /// Compute numeric deltas between baseline and target metrics
    #[allow(dead_code)] // Used by binary target
    fn compute_metrics_delta(
        &self,
        baseline: &AnalysisReport,
        target: &AnalysisReport,
    ) -> MetricsDelta {
        let mut delta = MetricsDelta {
            size_bytes: target.target.size_bytes as i64 - baseline.target.size_bytes as i64,
            ..Default::default()
        };

        // Source code metrics
        if let (Some(b), Some(t)) = (&baseline.source_code_metrics, &target.source_code_metrics) {
            delta.total_lines = t.total_lines as i32 - b.total_lines as i32;
            delta.code_lines = t.code_lines as i32 - b.code_lines as i32;
            delta.comment_lines = t.comment_lines as i32 - b.comment_lines as i32;
            delta.blank_lines = t.blank_lines as i32 - b.blank_lines as i32;
            delta.string_count = t.string_count as i32 - b.string_count as i32;
            delta.avg_string_length = t.avg_string_length - b.avg_string_length;
            delta.avg_string_entropy = t.avg_string_entropy - b.avg_string_entropy;
        }

        // Binary code metrics
        if let (Some(b), Some(t)) = (&baseline.code_metrics, &target.code_metrics) {
            delta.total_functions = t.total_functions as i32 - b.total_functions as i32;
            delta.total_basic_blocks = t.total_basic_blocks as i32 - b.total_basic_blocks as i32;
            delta.avg_complexity = t.avg_complexity - b.avg_complexity;
            delta.max_complexity = t.max_complexity as i32 - b.max_complexity as i32;
            delta.total_instructions = t.total_instructions as i32 - b.total_instructions as i32;
            delta.code_density = t.code_density - b.code_density;
        }

        // Unified metrics
        if let (Some(b_metrics), Some(t_metrics)) = (&baseline.metrics, &target.metrics) {
            if let (Some(b), Some(t)) = (&b_metrics.text, &t_metrics.text) {
                delta.total_lines = t.total_lines as i32 - b.total_lines as i32;
            }
            if let (Some(b), Some(t)) = (&b_metrics.comments, &t_metrics.comments) {
                delta.comment_lines = t.lines as i32 - b.lines as i32;
            }
            if let (Some(b), Some(t)) = (&b_metrics.identifiers, &t_metrics.identifiers) {
                delta.unique_identifiers = t.unique_count as i32 - b.unique_count as i32;
                delta.avg_identifier_length = t.avg_length - b.avg_length;
            }
            if let (Some(b), Some(t)) = (&b_metrics.strings, &t_metrics.strings) {
                delta.string_count = t.total as i32 - b.total as i32;
                delta.avg_string_length = t.avg_length - b.avg_length;
                delta.avg_string_entropy = t.avg_entropy - b.avg_entropy;
            }
            if let (Some(b), Some(t)) = (&b_metrics.functions, &t_metrics.functions) {
                delta.total_functions = t.total as i32 - b.total as i32;
            }
        }

        delta
    }

    /// Create a full diff report with comprehensive analysis for ML pipelines
    #[allow(dead_code)] // Used by binary target
    pub(crate) fn analyze_full(&self) -> Result<FullDiffReport> {
        let is_baseline_dir = self.baseline_path.is_dir();
        let is_target_dir = self.target_path.is_dir();

        if is_baseline_dir && is_target_dir {
            self.analyze_directories_full()
        } else if !is_baseline_dir && !is_target_dir {
            self.analyze_files_full()
        } else {
            anyhow::bail!("Baseline and target must both be files or both be directories");
        }
    }

    #[allow(dead_code)] // Used by binary target
    fn analyze_files_full(&self) -> Result<FullDiffReport> {
        let baseline_report = self.analyze_single_file(&self.baseline_path)?;
        let target_report = self.analyze_single_file(&self.target_path)?;

        let file_diff = self.create_full_diff(
            &self.target_path.display().to_string(),
            &baseline_report,
            &target_report,
        );

        let modified_analysis = self.compare_reports(
            &self.baseline_path.display().to_string(),
            &baseline_report,
            &target_report,
        );

        let aggregate_counts = file_diff.counts.clone();
        let mut file_diffs = Vec::new();
        let mut modified_analysis_vec = Vec::new();

        if file_diff.added_findings.len() + file_diff.removed_findings.len() > 0
            || file_diff.added_strings.len() + file_diff.removed_strings.len() > 0
            || file_diff.added_imports.len() + file_diff.removed_imports.len() > 0
        {
            file_diffs.push(file_diff);
            modified_analysis_vec.push(modified_analysis);
        }

        Ok(FullDiffReport {
            schema_version: "2.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: self.baseline_path.display().to_string(),
            target: self.target_path.display().to_string(),
            changes: FileChanges {
                added: vec![],
                removed: vec![],
                modified: if file_diffs.is_empty() {
                    vec![]
                } else {
                    vec![self.target_path.display().to_string()]
                },
                renamed: vec![],
            },
            file_diffs,
            modified_analysis: modified_analysis_vec,
            aggregate_counts,
            metadata: AnalysisMetadata {
                analysis_duration_ms: 0,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        })
    }

    #[allow(dead_code)] // Used by binary target
    fn analyze_directories_full(&self) -> Result<FullDiffReport> {
        let baseline_files = self.collect_files(&self.baseline_path)?;
        let target_files = self.collect_files(&self.target_path)?;

        let baseline_set: HashSet<_> = baseline_files.keys().collect();
        let target_set: HashSet<_> = target_files.keys().collect();

        let mut added: Vec<String> = target_set
            .difference(&baseline_set)
            .map(std::string::ToString::to_string)
            .collect();
        let mut removed: Vec<String> = baseline_set
            .difference(&target_set)
            .map(std::string::ToString::to_string)
            .collect();
        let modified_candidates: Vec<String> = baseline_set
            .intersection(&target_set)
            .map(std::string::ToString::to_string)
            .collect();

        let renames = detect_renames(&removed, &added);

        if !renames.is_empty() {
            let renamed_baseline: HashSet<String> =
                renames.iter().map(|r| r.baseline_path.clone()).collect();
            let renamed_target: HashSet<String> =
                renames.iter().map(|r| r.target_path.clone()).collect();

            removed.retain(|f| !renamed_baseline.contains(f));
            added.retain(|f| !renamed_target.contains(f));
        }

        let mut file_diffs = Vec::new();
        let mut modified_analysis = Vec::new();
        let mut actually_modified = Vec::new();

        // Aggregate counts
        let mut aggregate = DiffCounts::default();

        for relative_path in modified_candidates {
            let (Some(baseline_file), Some(target_file)) = (
                baseline_files.get(&relative_path),
                target_files.get(&relative_path),
            ) else {
                continue; // Should not happen since these are from intersection
            };

            if let (Ok(baseline_meta), Ok(target_meta)) =
                (fs::metadata(baseline_file), fs::metadata(target_file))
            {
                if baseline_meta.len() == target_meta.len() {
                    if let (Ok(baseline_content), Ok(target_content)) =
                        (fs::read(baseline_file), fs::read(target_file))
                    {
                        if baseline_content == target_content {
                            continue;
                        }
                    }
                }
            }

            if let (Ok(baseline_report), Ok(target_report)) = (
                self.analyze_single_file(baseline_file),
                self.analyze_single_file(target_file),
            ) {
                let file_diff =
                    self.create_full_diff(&relative_path, &baseline_report, &target_report);

                // Only include if there are actual changes
                if let Some(ref counts) = file_diff.counts {
                    if counts.findings_added != 0
                        || counts.findings_removed != 0
                        || counts.strings_added != 0
                        || counts.strings_removed != 0
                        || counts.imports_added != 0
                        || counts.imports_removed != 0
                    {
                        // Accumulate aggregate counts
                        aggregate.findings_added += counts.findings_added;
                        aggregate.findings_removed += counts.findings_removed;
                        aggregate.traits_added += counts.traits_added;
                        aggregate.traits_removed += counts.traits_removed;
                        aggregate.strings_added += counts.strings_added;
                        aggregate.strings_removed += counts.strings_removed;
                        aggregate.imports_added += counts.imports_added;
                        aggregate.imports_removed += counts.imports_removed;
                        aggregate.exports_added += counts.exports_added;
                        aggregate.exports_removed += counts.exports_removed;
                        aggregate.functions_added += counts.functions_added;
                        aggregate.functions_removed += counts.functions_removed;
                        aggregate.syscalls_added += counts.syscalls_added;
                        aggregate.syscalls_removed += counts.syscalls_removed;
                        aggregate.paths_added += counts.paths_added;
                        aggregate.paths_removed += counts.paths_removed;
                        aggregate.env_vars_added += counts.env_vars_added;
                        aggregate.env_vars_removed += counts.env_vars_removed;

                        actually_modified.push(relative_path.clone());
                        file_diffs.push(file_diff);

                        let analysis =
                            self.compare_reports(&relative_path, &baseline_report, &target_report);
                        modified_analysis.push(analysis);
                    }
                }
            }
        }

        let renamed_files: Vec<FileRenameInfo> = renames
            .iter()
            .map(|r| FileRenameInfo {
                from: r.baseline_path.clone(),
                to: r.target_path.clone(),
                similarity: r.similarity_score,
            })
            .collect();

        Ok(FullDiffReport {
            schema_version: "2.0".to_string(),
            analysis_timestamp: Utc::now(),
            diff_mode: true,
            baseline: self.baseline_path.display().to_string(),
            target: self.target_path.display().to_string(),
            changes: FileChanges {
                added,
                removed,
                modified: actually_modified,
                renamed: renamed_files,
            },
            file_diffs,
            modified_analysis,
            aggregate_counts: Some(aggregate),
            metadata: AnalysisMetadata {
                analysis_duration_ms: 0,
                tools_used: vec!["diff_analyzer".to_string()],
                errors: vec![],
            },
        })
    }

    fn assess_risk_increase(&self, new_caps: &[Finding], removed_caps: &[Finding]) -> bool {
        // High-risk capability categories
        let high_risk_prefixes = [
            "execution/",
            "anti-analysis/",
            "privilege/",
            "persistence/",
            "injection/",
            "registry/write",
            "registry/delete",
            "service/create",
        ];

        // Check if new capabilities are high-risk
        let new_high_risk_count = new_caps
            .iter()
            .filter(|cap| {
                high_risk_prefixes
                    .iter()
                    .any(|prefix| cap.id.starts_with(prefix))
            })
            .count();

        // Check if removed capabilities were high-risk
        let removed_high_risk_count = removed_caps
            .iter()
            .filter(|cap| {
                high_risk_prefixes
                    .iter()
                    .any(|prefix| cap.id.starts_with(prefix))
            })
            .count();

        // Risk increases if:
        // 1. New high-risk capabilities added
        // 2. More high-risk capabilities than were removed
        new_high_risk_count > 0 && new_high_risk_count > removed_high_risk_count
    }
}

/// Format diff report as human-readable output
#[cfg(test)]
mod tests;
