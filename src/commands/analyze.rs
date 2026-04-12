//! Single file analysis command.
//!
//! This module implements the core file analysis functionality for cleave.
//! It performs comprehensive analysis of a single file or directory, including:
//!
//! - File type detection via magic bytes
//! - Format-specific structural analysis (ELF, PE, Mach-O, scripts, archives, etc.)
//! - YARA rule scanning with parallel loading
//! - Capability mapping and trait evaluation
//! - Composite rule evaluation
//! - Criticality assessment and filtering
//!
//! # Architecture
//!
//! The analysis process follows these steps:
//!
//! 1. **File Type Detection**: Fast magic byte inspection to determine file format
//! 2. **Parallel Initialization**: YARA rules and capability mapper load concurrently
//! 3. **Format Routing**: Files are routed to specialized analyzers based on type
//! 4. **Trait Evaluation**: Capability mapper processes findings and assigns traits
//! 5. **Output Formatting**: Results are formatted as Terminal or JSONL
//!
//! # Performance
//!
//! - YARA loading happens in parallel with capability mapper initialization
//! - Binary formats (ELF/PE/Mach-O) run structural analysis and YARA scans in parallel
//! - Archives support streaming JSONL output for progressive results
//! - Directory traversal loads YARA rules once and reuses for all files
//!
//! # Output Formats
//!
//! - **Terminal**: Human-readable summary with findings and metadata
//! - **JSONL**: Machine-readable JSON Lines format (one JSON object per line)

use crate::cli;
use crate::composite_rules;
use crate::output;
use crate::types;
use anyhow::Result;
use std::io::Write;
use std::path::Path;

/// All parameters needed by the analyze command.
#[derive(Debug)]
pub struct AnalyzeConfig<'a> {
    /// File or directory to analyze.
    pub target: &'a str,
    /// Whether third-party YARA rules should be enabled.
    pub enable_third_party: bool,
    /// Output format for rendered results.
    pub format: &'a cli::OutputFormat,
    /// Archive passwords to try when analyzing encrypted archives.
    pub zip_passwords: &'a [String],
    /// Component-level feature disables from the CLI.
    pub disabled: &'a cli::DisabledComponents,
    /// Whether to analyze all files instead of only known-interesting ones.
    pub all_files: bool,
    /// Optional sample extraction configuration for nested payloads.
    pub sample_extraction: Option<&'a types::SampleExtractionConfig>,
    /// Platform filters applied during rule evaluation.
    pub platforms: &'a [composite_rules::Platform],
    /// Minimum hostile precision threshold for composite evaluation.
    pub min_hostile_precision: f32,
    /// Minimum suspicious precision threshold for composite evaluation.
    pub min_suspicious_precision: f32,
    /// Maximum file size eligible for in-memory analysis.
    pub max_memory_file_size: u64,
    /// Whether full validation should run when loading rule data.
    pub enable_full_validation: bool,
    /// Threshold for reporting slow rule evaluations.
    pub slow_rule_ms: u64,
    /// Whether output is being redirected to a file.
    pub output_to_file: bool,
    /// Maximum file size eligible for YARA scanning.
    pub max_scan_file_size: u64,
    /// Number of threads to use for directory scans.
    pub scan_threads: usize,
    /// Minimum finding criticality to emit.
    pub min_crit: Option<types::Criticality>,
    /// Maximum finding criticality to emit.
    pub max_crit: Option<types::Criticality>,
    /// Minimum file-level criticality to emit.
    pub min_file_crit: Option<types::Criticality>,
    /// Maximum file-level criticality to emit.
    pub max_file_crit: Option<types::Criticality>,
}

/// Analyze a single file or directory and render the result in the requested format.
pub fn run(config: &AnalyzeConfig<'_>) -> Result<String> {
    let path = Path::new(config.target);

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", config.target);
    }

    let platforms_lib: Vec<cleave::Platform> = if config.platforms.is_empty() {
        vec![cleave::Platform::All]
    } else {
        config.platforms.to_vec()
    };
    let sample_lib: Option<cleave::SampleExtractionConfig> =
        config
            .sample_extraction
            .map(|s| cleave::SampleExtractionConfig {
                extract_dir: s.extract_dir.clone(),
                archive_sha256: s.archive_sha256.clone(),
            });
    let options = cleave::AnalysisOptions {
        enable_third_party_yara: config.enable_third_party && !config.disabled.third_party,
        zip_passwords: config.zip_passwords.to_vec(),
        disable_yara: config.disabled.yara,
        disable_radare2: config.disabled.radare2,
        disable_upx: config.disabled.upx,
        all_files: config.all_files,
        platforms: platforms_lib,
        min_hostile_precision: config.min_hostile_precision,
        min_suspicious_precision: config.min_suspicious_precision,
        enable_precision_scoring: false,
        enable_full_validation: config.enable_full_validation,
        max_memory_file_size: config.max_memory_file_size,
        sample_extraction: sample_lib,
        slow_rule_ms: config.slow_rule_ms,
        max_scan_file_size: config.max_scan_file_size,
        scan_threads: config.scan_threads,
        cancellation: None,
        phase: None,
    };

    // If target is a directory, process files recursively
    if path.is_dir() {
        let options_arc = std::sync::Arc::new(options);
        let results = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let results_clone = results.clone();
        let format_val = *config.format;
        let stream_stdout = !config.output_to_file;
        let min_crit = config.min_crit;
        let max_crit = config.max_crit;
        let min_file_crit = config.min_file_crit;
        let max_file_crit = config.max_file_crit;

        cleave::scan_directory(path, &options_arc, move |event| match event {
            cleave::ScanEvent::Start { total } => {
                tracing::info!(total = total, "Starting directory scan");
            }
            cleave::ScanEvent::File {
                path: file_path,
                result,
            } => {
                let file_path_str = file_path.to_string_lossy().to_string();
                let formatted = match result.as_ref() {
                    Ok(lib_report) => {
                        let mut report = prepare_output_report(lib_report);
                        let Ok(res) = format_report_output(
                            &mut report,
                            &format_val,
                            min_crit,
                            max_crit,
                            min_file_crit,
                            max_file_crit,
                        ) else {
                            return;
                        };
                        if stream_stdout && !res.is_empty() {
                            print!("{}", res);
                            let _ = std::io::stdout().flush();
                        }
                        res
                    }
                    Err(e) => {
                        tracing::error!(path = %file_path_str, error = %e, "Analysis failed");
                        String::new()
                    }
                };
                if !stream_stdout && !formatted.is_empty() {
                    if let Ok(mut guard) = results_clone.lock() {
                        guard.push(formatted);
                    }
                }
            }
        })?;

        if config.output_to_file {
            let final_results = results
                .lock()
                .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
            return Ok(final_results.join(""));
        }
        // Results already streamed to stdout in the callback.
        return Ok(String::new());
    }

    // Single file analysis
    analyze_and_format(
        config.target,
        &options,
        config.format,
        config.min_crit,
        config.max_crit,
        config.min_file_crit,
        config.max_file_crit,
    )
}

/// Analyze a single file and format the output.
///
/// Uses `cleave::analyze_file()` for the core analysis pipeline (with caching),
/// then applies CLI-specific post-processing (encoding layer merging, filtering,
/// output formatting).
fn analyze_and_format(
    target: &str,
    options: &cleave::AnalysisOptions,
    format: &cli::OutputFormat,
    min_crit: Option<types::Criticality>,
    max_crit: Option<types::Criticality>,
    min_file_crit: Option<types::Criticality>,
    max_file_crit: Option<types::Criticality>,
) -> Result<String> {
    let path = Path::new(target);

    // Core analysis — single pipeline in lib.rs, with caching
    let lib_report = cleave::analyze_file(path, options)?;

    let mut report = prepare_output_report(&lib_report);

    // Merge encoding layers and recalculate composites.
    // The mapper is only needed when encoding layers are actually merged (rare for single files),
    // so we defer its expensive initialization to avoid ~800ms overhead on the common path.
    let merged_indices = report.merge_encoding_layers();
    if !merged_indices.is_empty() {
        let capability_mapper =
            crate::capabilities::CapabilityMapper::new_with_precision_thresholds(
                options.min_hostile_precision,
                options.min_suspicious_precision,
                options.enable_full_validation,
            );
        for &idx in &merged_indices {
            let file = &report.files[idx];
            let mut temp_report = types::AnalysisReport::new(types::TargetInfo {
                path: file.path.clone(),
                file_type: file.file_type.clone(),
                sha256: file.sha256.clone(),
                size_bytes: file.size,
                architectures: None,
            });
            temp_report.findings = file.findings.clone();

            let new_composites = capability_mapper.evaluate_container_composites(
                &temp_report,
                &file.findings,
                &file.file_type,
            );
            if !new_composites.is_empty() {
                let file = &mut report.files[idx];
                for finding in new_composites {
                    if !file.findings.iter().any(|f| f.id == finding.id) {
                        file.findings.push(finding);
                    }
                }
                file.compute_summary();
            }
        }
        tracing::debug!(
            "Merged encoding layers into {} parent file(s)",
            merged_indices.len()
        );
    }

    // Filter unmatched component traits for terminal output
    if *format == cli::OutputFormat::Terminal {
        let removed = report.filter_unmatched_components();
        if removed > 0 {
            tracing::debug!(
                "Filtered {} unmatched component traits from terminal output",
                removed
            );
        }
    }

    format_report_output(
        &mut report,
        format,
        min_crit,
        max_crit,
        min_file_crit,
        max_file_crit,
    )
}

fn format_report_output(
    report: &mut types::AnalysisReport,
    format: &cli::OutputFormat,
    min_crit: Option<types::Criticality>,
    max_crit: Option<types::Criticality>,
    min_file_crit: Option<types::Criticality>,
    max_file_crit: Option<types::Criticality>,
) -> Result<String> {
    if min_file_crit.is_some() || max_file_crit.is_some() {
        apply_file_criticality_filter(report, min_file_crit, max_file_crit);
    }

    if min_crit.is_some() || max_crit.is_some() {
        apply_criticality_filter(report, min_crit, max_crit);
    }

    match format {
        cli::OutputFormat::Json | cli::OutputFormat::Jsonl => {
            let compact = types::compact_from_files(&report.files);
            Ok(serde_json::to_string(&compact)?)
        }
        cli::OutputFormat::Terminal => Ok(output::format_terminal(report)),
        cli::OutputFormat::Tiny => Ok(output::format_tiny(report)),
    }
}

fn prepare_output_report(lib_report: &cleave::AnalysisReport) -> types::AnalysisReport {
    let mut report = lib_report.clone();
    report.shrink_to_fit();
    report.finalize();
    report
}

/// Filter findings by criticality range, then remove files with no remaining findings.
fn apply_criticality_filter(
    report: &mut types::AnalysisReport,
    min_crit: Option<types::Criticality>,
    max_crit: Option<types::Criticality>,
) {
    let removed = report.filter_findings(|f| {
        if let Some(min) = min_crit {
            if f.crit < min {
                return false;
            }
        }
        if let Some(max) = max_crit {
            if f.crit > max {
                return false;
            }
        }
        true
    });

    if removed > 0 {
        // Remove files that have no findings after filtering
        report.files.retain(|f| !f.findings.is_empty());
        tracing::debug!("Criticality filter removed {} findings", removed);
    }
}

/// Filter entire files based on their highest-criticality trait.
/// Unlike `apply_criticality_filter`, this does not remove individual traits —
/// it removes or keeps files wholesale based on max(finding.crit) per file.
///
/// Filtering is applied at the containing-file level: if a parent file does not
/// meet the criticality threshold, all of its embedded/child files are also removed,
/// regardless of the children's own criticality.
fn apply_file_criticality_filter(
    report: &mut types::AnalysisReport,
    min_file_crit: Option<types::Criticality>,
    max_file_crit: Option<types::Criticality>,
) {
    use std::collections::HashSet;

    let before = report.files.len();

    // First pass: determine which files fail the criticality filter on their own merits
    let mut rejected_ids: HashSet<u32> = HashSet::new();
    for file in &report.files {
        let max_crit = file
            .findings
            .iter()
            .map(|f| f.crit)
            .max()
            .unwrap_or(types::Criticality::Baseline);

        let passes = min_file_crit.is_none_or(|min| max_crit >= min)
            && max_file_crit.is_none_or(|max| max_crit <= max);

        if !passes {
            rejected_ids.insert(file.id);
        }
    }

    // Second pass: propagate rejection down — if any ancestor is rejected, reject the child.
    // Build a quick id→parent_id lookup.
    let parent_map: std::collections::HashMap<u32, Option<u32>> =
        report.files.iter().map(|f| (f.id, f.parent_id)).collect();

    let ancestor_rejected = |file_id: u32| -> bool {
        let mut cur = parent_map.get(&file_id).copied().flatten();
        while let Some(pid) = cur {
            if rejected_ids.contains(&pid) {
                return true;
            }
            cur = parent_map.get(&pid).copied().flatten();
        }
        false
    };

    report
        .files
        .retain(|file| !rejected_ids.contains(&file.id) && !ancestor_rejected(file.id));

    let removed = before - report.files.len();
    if removed > 0 {
        tracing::debug!("File criticality filter removed {} files", removed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::file_analysis::FileAnalysis;
    use types::traits_findings::{Finding, FindingKind};
    use types::{AnalysisReport, Criticality, TargetInfo};

    fn make_finding(id: &str, crit: Criticality) -> Finding {
        Finding {
            id: id.to_string(),
            kind: FindingKind::Capability,
            desc: format!("test {id}"),
            conf: 0.9,
            crit,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![],
            match_count: 0,
            source_file: None,
        }
    }

    fn make_file(path: &str, findings: Vec<Finding>) -> FileAnalysis {
        let mut fa = FileAnalysis::new(
            0,
            path.to_string(),
            "elf".to_string(),
            "sha256".to_string(),
            1024,
        );
        fa.findings = findings;
        fa.compute_summary();
        fa
    }

    fn make_report(mut files: Vec<FileAnalysis>) -> AnalysisReport {
        // Assign unique sequential IDs to files that still have the default id=0,
        // unless the caller already set explicit IDs (for parent/child tests).
        let has_explicit_ids = files.iter().any(|f| f.id != 0);
        if !has_explicit_ids {
            for (i, file) in files.iter_mut().enumerate() {
                file.id = i as u32;
            }
        }
        let mut report = AnalysisReport::new(TargetInfo {
            path: "/test".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 1024,
            sha256: "abc".to_string(),
            architectures: None,
        });
        report.files = files;
        report
    }

    #[test]
    fn test_min_crit_filters_below() {
        let mut report = make_report(vec![make_file(
            "/bin/sample",
            vec![
                make_finding("a", Criticality::Baseline),
                make_finding("b", Criticality::Notable),
                make_finding("c", Criticality::Suspicious),
            ],
        )]);

        apply_criticality_filter(&mut report, Some(Criticality::Notable), None);

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].findings.len(), 2);
        let ids: Vec<&str> = report.files[0]
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        assert!(ids.contains(&"b"));
        assert!(ids.contains(&"c"));
    }

    #[test]
    fn test_max_crit_filters_above() {
        let mut report = make_report(vec![make_file(
            "/bin/sample",
            vec![
                make_finding("a", Criticality::Notable),
                make_finding("b", Criticality::Suspicious),
                make_finding("c", Criticality::Hostile),
            ],
        )]);

        apply_criticality_filter(&mut report, None, Some(Criticality::Suspicious));

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].findings.len(), 2);
        let ids: Vec<&str> = report.files[0]
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        assert!(ids.contains(&"a"));
        assert!(ids.contains(&"b"));
    }

    #[test]
    fn test_min_and_max_crit_range() {
        let mut report = make_report(vec![make_file(
            "/bin/sample",
            vec![
                make_finding("a", Criticality::Baseline),
                make_finding("b", Criticality::Notable),
                make_finding("c", Criticality::Suspicious),
                make_finding("d", Criticality::Hostile),
            ],
        )]);

        apply_criticality_filter(
            &mut report,
            Some(Criticality::Notable),
            Some(Criticality::Suspicious),
        );

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].findings.len(), 2);
        let ids: Vec<&str> = report.files[0]
            .findings
            .iter()
            .map(|f| f.id.as_str())
            .collect();
        assert!(ids.contains(&"b"));
        assert!(ids.contains(&"c"));
    }

    #[test]
    fn test_crit_filter_removes_empty_files() {
        let mut report = make_report(vec![
            make_file("/bin/clean", vec![make_finding("a", Criticality::Baseline)]),
            make_file(
                "/bin/suspicious",
                vec![make_finding("b", Criticality::Suspicious)],
            ),
        ]);

        apply_criticality_filter(&mut report, Some(Criticality::Notable), None);

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, "/bin/suspicious");
    }

    #[test]
    fn test_crit_filter_no_flags_keeps_all() {
        let mut report = make_report(vec![make_file(
            "/bin/sample",
            vec![
                make_finding("a", Criticality::Baseline),
                make_finding("b", Criticality::Hostile),
            ],
        )]);

        apply_criticality_filter(&mut report, None, None);

        assert_eq!(report.files[0].findings.len(), 2);
    }

    #[test]
    fn test_crit_filter_exact_level() {
        let mut report = make_report(vec![make_file(
            "/bin/sample",
            vec![
                make_finding("a", Criticality::Notable),
                make_finding("b", Criticality::Suspicious),
            ],
        )]);

        // min=suspicious, max=suspicious → only suspicious
        apply_criticality_filter(
            &mut report,
            Some(Criticality::Suspicious),
            Some(Criticality::Suspicious),
        );

        assert_eq!(report.files[0].findings.len(), 1);
        assert_eq!(report.files[0].findings[0].id, "b");
    }

    #[test]
    fn test_min_file_crit_filters_files() {
        let mut report = make_report(vec![
            make_file(
                "/bin/low",
                vec![
                    make_finding("a", Criticality::Baseline),
                    make_finding("b", Criticality::Notable),
                ],
            ),
            make_file(
                "/bin/high",
                vec![
                    make_finding("c", Criticality::Baseline),
                    make_finding("d", Criticality::Suspicious),
                ],
            ),
        ]);

        // Only keep files whose highest trait is >= Suspicious
        apply_file_criticality_filter(&mut report, Some(Criticality::Suspicious), None);

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, "/bin/high");
        // All traits in the surviving file are preserved
        assert_eq!(report.files[0].findings.len(), 2);
    }

    #[test]
    fn test_max_file_crit_filters_files() {
        let mut report = make_report(vec![
            make_file("/bin/low", vec![make_finding("a", Criticality::Notable)]),
            make_file("/bin/high", vec![make_finding("b", Criticality::Hostile)]),
        ]);

        // Only keep files whose highest trait is <= Notable
        apply_file_criticality_filter(&mut report, None, Some(Criticality::Notable));

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, "/bin/low");
    }

    #[test]
    fn test_file_crit_range() {
        let mut report = make_report(vec![
            make_file(
                "/bin/baseline",
                vec![make_finding("a", Criticality::Baseline)],
            ),
            make_file(
                "/bin/notable",
                vec![
                    make_finding("b", Criticality::Baseline),
                    make_finding("c", Criticality::Notable),
                ],
            ),
            make_file(
                "/bin/hostile",
                vec![make_finding("d", Criticality::Hostile)],
            ),
        ]);

        // Only files whose max crit is Notable..=Suspicious
        apply_file_criticality_filter(
            &mut report,
            Some(Criticality::Notable),
            Some(Criticality::Suspicious),
        );

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, "/bin/notable");
        // All traits preserved (including baseline)
        assert_eq!(report.files[0].findings.len(), 2);
    }

    #[test]
    fn test_file_crit_with_trait_crit_combined() {
        let mut report = make_report(vec![
            make_file(
                "/bin/notable",
                vec![
                    make_finding("a", Criticality::Baseline),
                    make_finding("b", Criticality::Notable),
                ],
            ),
            make_file(
                "/bin/hostile",
                vec![
                    make_finding("c", Criticality::Baseline),
                    make_finding("d", Criticality::Hostile),
                ],
            ),
        ]);

        // File filter: only files with max crit <= Notable
        apply_file_criticality_filter(&mut report, None, Some(Criticality::Notable));
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, "/bin/notable");

        // Then trait filter: only traits >= Notable
        apply_criticality_filter(&mut report, Some(Criticality::Notable), None);
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].findings.len(), 1);
        assert_eq!(report.files[0].findings[0].id, "b");
    }

    #[test]
    fn test_file_crit_empty_findings_uses_baseline() {
        let mut report = make_report(vec![make_file("/bin/empty", vec![])]);

        // A file with no findings has effective max crit of Baseline
        apply_file_criticality_filter(&mut report, Some(Criticality::Notable), None);

        assert_eq!(report.files.len(), 0);
    }

    #[test]
    fn test_min_file_crit_cascades_to_embedded_children() {
        // Container file (depth 0, id 0) has low criticality
        let mut container = make_file(
            "/tmp/installer.pkg",
            vec![make_finding("a", Criticality::Baseline)],
        );
        container.id = 0;
        container.depth = 0;

        // Embedded file (depth 1, id 1) has high criticality but parent doesn't qualify
        let mut embedded_high = make_file(
            "/tmp/installer.pkg!!/payload.elf",
            vec![make_finding("b", Criticality::Hostile)],
        );
        embedded_high.id = 1;
        embedded_high.depth = 1;
        embedded_high.parent_id = Some(0);

        // Deeply nested file (depth 2, id 2) also high criticality
        let mut nested = make_file(
            "/tmp/installer.pkg!!/payload.elf!!/dropper",
            vec![make_finding("c", Criticality::Suspicious)],
        );
        nested.id = 2;
        nested.depth = 2;
        nested.parent_id = Some(1);

        // Unrelated standalone file (depth 0, id 3) that qualifies on its own
        let mut standalone = make_file(
            "/bin/malware",
            vec![make_finding("d", Criticality::Hostile)],
        );
        standalone.id = 3;
        standalone.depth = 0;

        let mut report = make_report(vec![container, embedded_high, nested, standalone]);

        // Filter: only files with max crit >= Suspicious
        // Container (Baseline) fails → its children should also be removed
        // Standalone (Hostile) passes
        apply_file_criticality_filter(&mut report, Some(Criticality::Suspicious), None);

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, "/bin/malware");
    }

    #[test]
    fn test_file_crit_keeps_qualifying_parent_and_children() {
        let mut parent = make_file(
            "/tmp/archive.tar",
            vec![make_finding("a", Criticality::Suspicious)],
        );
        parent.id = 0;
        parent.depth = 0;

        let mut child = make_file(
            "/tmp/archive.tar!!/inner.elf",
            vec![make_finding("b", Criticality::Hostile)],
        );
        child.id = 1;
        child.depth = 1;
        child.parent_id = Some(0);

        let mut report = make_report(vec![parent, child]);

        // Both parent and child meet the threshold — both should survive
        apply_file_criticality_filter(&mut report, Some(Criticality::Suspicious), None);

        assert_eq!(report.files.len(), 2);
    }
}
