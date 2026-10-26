//! Trait validation command.
//!
//! Runs the full suite of trait definition validation checks and reports any
//! errors or quality issues found. Exits with a non-zero status if validation fails.

use crate::cli::OutputFormat;
use crate::commands::validate_testdata;
use crate::types::file_analysis::{ARCHIVE_DELIMITER, ENCODING_DELIMITER};

/// Render a fixture path for a terminal, escaping control characters.
///
/// Fixture names mirror real sample names, and a name carrying an escape
/// sequence would rewrite the validation output on the operator's screen.
fn safe_path(path: &std::path::Path) -> String {
    let display = path.display().to_string();
    crate::output::escape_control_chars(&display).into_owned()
}
use anyhow::{Context, Result};
use cleave::{AnalysisReport, CapabilityMapper, Criticality, FileAnalysis, validation_controls};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

#[path = "validate_cache.rs"]
mod result_cache;

/// Every fixture derives its sole expectation from its top-level directory.
struct Target {
    path: PathBuf,
    expected: Criticality,
}

impl Target {
    fn path(&self) -> &Path {
        &self.path
    }
}

/// Print the score-contributing findings for a file, filtering out Component/Filtered noise.
fn print_contributing_findings(file: &FileAnalysis, indent: &str) {
    for finding in &file.findings {
        if finding.crit == Criticality::Component || finding.crit == Criticality::Filtered {
            continue;
        }
        let rendered = format!(
            "{indent}{:10} {}  {}",
            format!("{:?}", finding.crit).to_lowercase(),
            finding.id,
            finding.desc
        );
        eprintln!("{}", crate::output::escape_control_chars(&rendered));
    }
}

/// Run trait validation and exact-severity fixture checks.
///
/// All fixture analyses run in a
/// single rayon parallel pool; judgement happens serially afterwards by
/// scanning the collected reports. On success, prints a single summary line.
/// On failure, prints only the failing files with their contributing findings.
///
/// The testdata trait-overlap diagnostic is informational (overlaps are not
/// failures), so it is emitted only under `verbose` to keep a passing run to a
/// single line.
pub fn run(format: &OutputFormat, exclude: Option<&str>, verbose: bool) -> Result<String> {
    run_with_options(
        format,
        exclude,
        verbose,
        false,
        CapabilityMapper::DEFAULT_SLOW_RULE_MS,
    )
}

/// Run trait validation in **soft** mode: fail only on `Hard` problems — those
/// where a rule won't load or won't fire (unparseable YAML, uncompilable regex,
/// invalid file types, duplicate trait ids, broken references, impossible
/// constraints, malformed/empty conditions, self-references), plus the testdata
/// fixture scoring. Authoring-hygiene issues (taxonomy, size, dedup/reuse, regex
/// style, precision) and forward-compat cases (unknown file types or metric
/// fields on an older engine) are reported only, never fatal.
///
/// Intended for trait-bundle gates — `make publish-traits`, the scan worker,
/// and hopper's local scanner — that must tolerate hygiene debt but reject a
/// bundle that won't load or won't detect on this engine. The hard set is
/// defined in one place: `validation_controls::HARD_VALIDATOR_IDS`.
pub fn run_soft(format: &OutputFormat, exclude: Option<&str>, verbose: bool) -> Result<String> {
    run_with_options(
        format,
        exclude,
        verbose,
        true,
        CapabilityMapper::DEFAULT_SLOW_RULE_MS,
    )
}

/// Run validation with the CLI's slow-rule threshold. The environment soft-mode
/// toggle also applies to callers using the default (strict) mode.
pub fn run_with_options(
    format: &OutputFormat,
    exclude: Option<&str>,
    verbose: bool,
    soft: bool,
    slow_rule_ms: u64,
) -> Result<String> {
    let started = Instant::now();
    let soft = soft
        || matches!(
            std::env::var("CLEAVE_VALIDATE_SOFT").ok().as_deref(),
            Some("1" | "true" | "yes" | "on")
        );
    // `--exclude` silences specific validators (the only suppression knob);
    // `--soft` downgrades every Soft-severity problem to advisory, leaving only
    // Hard problems (won't load / won't fire) fatal.
    validation_controls::set_disabled_validators_override(exclude)?;
    validation_controls::set_soft_validation_mode(soft);
    let targets = collect_targets()?;
    let traits_dir = cleave::traits_repo::try_resolve().map_err(anyhow::Error::msg)?;
    let result_cache = result_cache::ResultCache::new(
        &traits_dir,
        &targets,
        "severity-directories-v1",
        soft,
        verbose,
        slow_rule_ms,
    );
    if let Some(outcome) = result_cache
        .as_ref()
        .and_then(result_cache::ResultCache::load)
    {
        match outcome {
            result_cache::Outcome::Passed(fixtures) => {
                return Ok(format_validate_output(&validation_output(fixtures), format));
            }
            result_cache::Outcome::PerformanceRejected(issues) => {
                let issues: Vec<_> = issues
                    .into_iter()
                    .map(result_cache::PerformanceIssue::restore)
                    .collect();
                print_performance_issues(&issues, format);
                anyhow::bail!(
                    "{} rule performance validation check(s) failed",
                    issues.len()
                );
            }
        }
    }
    // Fixtures are analyzed from outside the traits repo, so no path
    // exemption can match their location; see `NeutralStage`.
    let stage =
        NeutralStage::new(&cleave::traits_repo::try_resolve().map_err(anyhow::Error::msg)?)?;

    // A verified full-validation cache hit above can reuse a measured pass.
    // Fresh performance validation bypasses analysis reports and shared AST
    // batches so each rule's cost is measured, not hidden by previously computed
    // answers. Compiled-rule caches remain available. Route validation issues
    // through the chosen output format.
    cleave::validation_controls::set_validation_output_format(Some(match format {
        OutputFormat::Tiny => cleave::validation_controls::ValidationOutputFormat::Tiny,
        OutputFormat::Json | OutputFormat::Jsonl | OutputFormat::Snapshot => {
            cleave::validation_controls::ValidationOutputFormat::Json
        }
        OutputFormat::Terminal => cleave::validation_controls::ValidationOutputFormat::Terminal,
    }));
    let options = cleave::AnalysisOptions {
        disable_yara: false,
        disable_radare2: true,
        disable_upx: true,
        all_files: true,
        slow_rule_ms,
        ..Default::default()
    };

    // Load the mapper once with full validation enabled. This replaces the
    // separate `validate_traits()` call — validation errors surface here — and
    // every analysis worker below reuses this same Arc, so the trait set is
    // parsed from disk exactly once per run.
    let setup_ms = started.elapsed().as_millis();
    let mapper_started = Instant::now();
    let mapper = Arc::new(
        CapabilityMapper::try_new_with_load_options(
            CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
            CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            true,
            false,
        )?
        .with_slow_rule_ms(slow_rule_ms),
    );
    let mapper_and_lint_ms = mapper_started.elapsed().as_millis();
    let index_started = Instant::now();

    // When the cache holds nothing for these traits, as after an edit, every
    // fixture is about to miss: build the match indexes once, here, before
    // fanning out. Left lazy, every worker that reaches trait matching before
    // the first build finishes builds its own copy and all but one are thrown
    // away, which held the whole pool for ~7 s and doubled peak memory. When
    // the cache does hold them, fixtures hit and never need the indexes. This
    // is a performance heuristic only: if it skips the warm-up and a fixture
    // misses anyway, the lazy build still runs and the output is identical.
    if cleave::analysis_cache::has_reports_for_current_traits() {
        tracing::debug!("analysis cache holds these traits; match indexes stay lazy");
    } else {
        mapper.warm_indexes();
    }

    let index_ms = index_started.elapsed().as_millis();
    // A cold YARA singleton reached on a fixture worker must collect sources
    // serially to avoid nested-pool deadlocks. Initialize it off the pool first
    // so rule collection can use the whole pool, before any fixture waits on it.
    // The full-validation cache hit above still avoids engine loading entirely.
    let yara_started = Instant::now();
    cleave::prefetch_yara_engine(options.enable_third_party_yara);
    let yara_ms = yara_started.elapsed().as_millis();
    let performance = crate::validation_performance::Session::begin();
    let analysis_started = Instant::now();

    // One lane per pool thread, each pulling the next fixture, so that every
    // fixture analysis begins on an idle worker stack. As `into_par_iter`
    // jobs, fixtures were also taken up by threads waiting inside another
    // analysis's rayon join, on top of the half that analysis was waiting
    // for. A member of such a fixture that then waited on a busy single-flight
    // could be waiting on the very owner blocked in that join, and nothing
    // moved until the flight's 180 s deadline (one validate in twenty,
    // 2026-09-26). A worker takes its broadcast job before it steals
    // anything, so no lane starts on top of another analysis's work.
    // Start large fixtures early so a bundled source file does not begin near
    // the end of the queue and leave every other lane idle. Keep report slots
    // in original order so diagnostics and expectation checks stay stable.
    let mut work: Vec<_> = targets
        .iter()
        .enumerate()
        .map(|(i, t)| (i, std::fs::metadata(t.path()).map_or(0, |m| m.len())))
        .collect();
    work.sort_unstable_by_key(|&(i, size)| (std::cmp::Reverse(size), i));
    let next = AtomicUsize::new(0);
    let reports: Vec<OnceLock<Result<AnalysisReport>>> =
        targets.iter().map(|_| OnceLock::new()).collect();
    rayon::broadcast(|_| {
        loop {
            let job = next.fetch_add(1, Ordering::Relaxed);
            let Some(&(i, _)) = work.get(job) else { break };
            let t = &targets[i];
            let fixture_started = Instant::now();
            let report = stage.analyze(t.path(), |p| {
                cleave::analyze_file_with_mapper(p, &options, &mapper)
            });
            let elapsed_ms = fixture_started.elapsed().as_millis();
            if elapsed_ms >= 500 {
                tracing::info!(path = %t.path().display(), elapsed_ms, "slow validation fixture");
            }
            let _ = reports[i].set(report);
        }
    });
    tracing::info!(
        setup_ms,
        mapper_and_lint_ms,
        index_ms,
        yara_ms,
        analysis_ms = analysis_started.elapsed().as_millis(),
        fixtures = targets.len(),
        "validation phase timings"
    );
    // Include aggregate trait costs (CLEAVE_TRAIT_TIMING=1) on validation runs,
    // including runs whose fixture expectations fail below.
    cleave::log_scan_stats();
    let results: Vec<(Target, Result<AnalysisReport>)> = targets
        .into_iter()
        .zip(reports)
        .map(|(t, report)| {
            let report = report
                .into_inner()
                .unwrap_or_else(|| Err(anyhow::anyhow!("fixture was not analyzed")));
            (t, report)
        })
        .collect();

    // Check for overlapping traits in the analyzed findings. This is a
    // diagnostic, not a pass/fail signal, so only compute it when verbose.
    let overlap_findings = if verbose {
        collect_overlap_findings(&results)
    } else {
        Vec::new()
    };

    let cacheable = results.iter().all(|(_, result)| {
        result
            .as_ref()
            .is_ok_and(|report| !crate::analysis_cache::evaluation_incomplete(report))
    }) && crate::yara_engine::yara_degradation().is_none();
    let mut performance_issues = performance.issues();
    stage.relabel_issues(&mut performance_issues);
    print_performance_issues(&performance_issues, format);
    let fixtures = evaluate(results)?;
    if performance_issues
        .iter()
        .any(|p| p.severity >= validation_controls::fatal_severity_threshold())
    {
        if crate::yara_engine::yara_degradation().is_none()
            && let Some(cache) = &result_cache
        {
            cache.store_rejection_if_unchanged(&performance_issues);
        }
        anyhow::bail!(
            "{} rule performance validation check(s) failed",
            performance_issues.len()
        );
    }

    // Report overlapping traits if found
    if !overlap_findings.is_empty() {
        eprintln!(
            "\n{}",
            validate_testdata::format_overlaps(&overlap_findings)
        );
    }

    let report = validation_output(fixtures);
    if cacheable
        && performance_issues.is_empty()
        && let Some(cache) = result_cache
    {
        cache.store_if_unchanged(&report.fixtures);
    }

    Ok(format_validate_output(&report, format))
}

fn print_performance_issues(
    issues: &[validation_controls::ValidationIssue],
    format: &OutputFormat,
) {
    if issues.is_empty() {
        return;
    }
    let rendered = match format {
        OutputFormat::Tiny => validation_controls::format_validation_issues_tiny(issues),
        OutputFormat::Json | OutputFormat::Jsonl | OutputFormat::Snapshot => {
            validation_controls::format_validation_issues_json(issues)
        }
        OutputFormat::Terminal => validation_controls::format_validation_issues_terminal(issues),
    };
    eprintln!("{rendered}");
}

fn validation_output(fixtures: FixtureSummary) -> ValidateOutput {
    ValidateOutput {
        ok: true,
        traits_version: cleave::traits_repo::version(),
        traits_dir: cleave::traits_repo::try_resolve()
            .ok()
            .map(|p| p.display().to_string()),
        disabled_validators: validation_controls::disabled_validators_by_category(),
        fixtures,
    }
}

#[derive(Debug, Serialize)]
struct ValidateOutput {
    ok: bool,
    traits_version: Option<String>,
    traits_dir: Option<String>,
    disabled_validators:
        std::collections::BTreeMap<&'static str, Vec<validation_controls::DisabledValidatorView>>,
    fixtures: FixtureSummary,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FixtureSummary {
    hostile: FixtureCount,
    suspicious: FixtureCount,
    notable: FixtureCount,
    baseline: FixtureCount,
}

impl FixtureSummary {
    fn count_mut(&mut self, severity: Criticality) -> &mut FixtureCount {
        match severity {
            Criticality::Hostile => &mut self.hostile,
            Criticality::Suspicious => &mut self.suspicious,
            Criticality::Notable => &mut self.notable,
            _ => &mut self.baseline,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FixtureCount {
    passed: usize,
    total: usize,
}

fn format_validate_output(report: &ValidateOutput, format: &OutputFormat) -> String {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl | OutputFormat::Snapshot => {
            let json = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string());
            format!(
                "{json}
"
            )
        }
        OutputFormat::Tiny => format_validate_tiny(report),
        OutputFormat::Terminal => format_validate_terminal(report),
    }
}

fn fixture_counts(fixtures: &FixtureSummary) -> String {
    [
        ("hostile", &fixtures.hostile),
        ("suspicious", &fixtures.suspicious),
        ("notable", &fixtures.notable),
        ("baseline", &fixtures.baseline),
    ]
    .into_iter()
    .map(|(name, count)| format!("{name} {}/{}", count.passed, count.total))
    .collect::<Vec<_>>()
    .join("  ")
}

fn format_validate_terminal(report: &ValidateOutput) -> String {
    format!(
        "{}validate ok: {}\n",
        validation_controls::format_disabled_validators_terminal(),
        fixture_counts(&report.fixtures)
    )
}

fn format_validate_tiny(report: &ValidateOutput) -> String {
    let mut out = String::from("validate ok\n");
    for (category, validators) in &report.disabled_validators {
        let labels = validators
            .iter()
            .map(|validator| validator.display_id)
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&format!("disabled {category}={labels}\n"));
    }
    out.push_str(&format!("fixtures {}\n", fixture_counts(&report.fixtures)));
    out
}

/// Discover every file, including dotfiles, without reading fixture contents.
/// This runs before cache lookup: an unrecognized file can never hide behind
/// a previously passing validation result. Subdirectories carry no semantics.
fn collect_targets() -> Result<Vec<Target>> {
    let traits_dir = cleave::traits_repo::try_resolve().map_err(anyhow::Error::msg)?;
    discover_targets(&traits_dir.join("testdata"))
}

fn discover_targets(root: &Path) -> Result<Vec<Target>> {
    if !root.is_dir() {
        anyhow::bail!("missing validation fixture directory: {}", safe_path(root));
    }
    let mut targets = Vec::new();
    let mut unused = Vec::new();
    for entry in walkdir::WalkDir::new(root).min_depth(1).follow_links(false) {
        let entry = entry.with_context(|| format!("walking {}", safe_path(root)))?;
        if entry.file_type().is_dir() {
            continue;
        }
        let relative = entry.path().strip_prefix(root)?;
        let expected = match relative
            .components()
            .next()
            .and_then(|c| c.as_os_str().to_str())
        {
            Some("hostile") => Some(Criticality::Hostile),
            Some("suspicious") => Some(Criticality::Suspicious),
            Some("notable") => Some(Criticality::Notable),
            Some("baseline") => Some(Criticality::Baseline),
            _ => None,
        };
        // Symlinks (including directory links) are rejected rather than silently
        // skipped or followed outside the fixture tree.
        if let Some(expected) = expected.filter(|_| {
            entry.file_type().is_file()
                && relative
                    .parent()
                    .is_some_and(|parent| !parent.as_os_str().is_empty())
        }) {
            let exempt = relative.components().nth(2).is_some()
                && relative
                    .components()
                    .nth(1)
                    .is_some_and(|c| c.as_os_str() == "does-nothing");
            let size = entry.metadata()?.len();
            if !exempt && size > 500 * 1024 {
                unused.push(format!(
                    "{}: {size} bytes exceeds the 500 KiB fixture limit",
                    safe_path(relative)
                ));
                continue;
            }
            if !exempt && size > 20 * 1024 && entry.path().extension().is_none_or(|ext| ext != "xz")
            {
                unused.push(format!(
                    "{}: {size} bytes; fixtures above 20 KiB must use xz storage compression",
                    safe_path(relative)
                ));
                continue;
            }
            targets.push(Target {
                path: entry.into_path(),
                expected,
            });
        } else {
            unused.push(safe_path(relative));
        }
    }
    if !unused.is_empty() {
        unused.sort_unstable();
        let shown = unused
            .iter()
            .take(20)
            .map(|p| format!("  {p}"))
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::bail!(
            "{} unused or unsupported testdata file(s); every file must be a regular fixture under hostile/, suspicious/, notable/, or baseline/:\n{}{}",
            unused.len(),
            shown,
            if unused.len() > 20 {
                format!("\n  ... {} more", unused.len() - 20)
            } else {
                String::new()
            }
        );
    }
    if targets.is_empty() {
        anyhow::bail!("no validation fixtures in {}", safe_path(root));
    }
    targets.sort_unstable_by(|a, b| a.path.cmp(&b.path));
    Ok(targets)
}

fn report_severity(report: &AnalysisReport) -> Result<Criticality> {
    if report.files.is_empty() {
        anyhow::bail!("analysis produced no files");
    }
    Ok(report
        .files
        .iter()
        .flat_map(|file| &file.findings)
        .map(|finding| finding.crit)
        .max()
        .unwrap_or(Criticality::Baseline)
        .max(Criticality::Baseline))
}

fn evaluate(results: Vec<(Target, Result<AnalysisReport>)>) -> Result<FixtureSummary> {
    let mut summary = FixtureSummary::default();
    let mut failures = 0;
    for (target, result) in results {
        let count = summary.count_mut(target.expected);
        count.total += 1;
        match result.and_then(|report| report_severity(&report).map(|severity| (report, severity)))
        {
            Ok((_, actual)) if actual == target.expected => count.passed += 1,
            Ok((report, actual)) => {
                eprintln!(
                    "❌ {}: expected {}, found {}",
                    safe_path(target.path()),
                    target.expected.letter(),
                    actual.letter()
                );
                for file in &report.files {
                    if file.findings.iter().any(|f| f.crit >= Criticality::Notable) {
                        eprintln!("  {}", safe_path(Path::new(&file.path)));
                        print_contributing_findings(file, "     ");
                    }
                }
                failures += 1;
            }
            Err(error) => {
                eprintln!(
                    "❌ {}: analysis failed: {error:#}",
                    safe_path(target.path())
                );
                failures += 1;
            }
        }
    }
    if failures > 0 {
        anyhow::bail!("{failures} validation fixture check(s) failed");
    }
    Ok(summary)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod severity_fixture_tests {
    use super::*;

    fn write(root: &Path, name: &str) {
        let path = root.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, "fixture").unwrap();
    }

    #[test]
    fn discovery_uses_only_first_directory_and_includes_hidden_inputs() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "hostile/generated/baseline/.payload.js");
        write(root.path(), "baseline/.github/action.yml");
        write(root.path(), "notable/scripts/build.py");
        let targets = discover_targets(root.path()).unwrap();
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0].expected, Criticality::Baseline);
        assert_eq!(targets[1].expected, Criticality::Hostile);
        assert_eq!(targets[2].expected, Criticality::Notable);
        // Gitignore, extensions and script directory names never exclude data.
        write(root.path(), "notable/.gitignore");
        assert_eq!(discover_targets(root.path()).unwrap().len(), 4);
    }

    #[test]
    fn fresh_unknown_files_and_legacy_manifests_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "hostile/sample.js");
        assert!(discover_targets(root.path()).is_ok());
        write(root.path(), "triage/receipt.json");
        let error = discover_targets(root.path()).err().unwrap().to_string();
        assert!(error.contains("triage/receipt.json"), "{error}");
        std::fs::remove_file(root.path().join("triage/receipt.json")).unwrap();
        write(root.path(), "expectations.toml");
        assert!(
            discover_targets(root.path())
                .err()
                .unwrap()
                .to_string()
                .contains("expectations.toml")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_errors_and_never_followed() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        write(root.path(), "baseline/real.txt");
        std::os::unix::fs::symlink(outside.path(), root.path().join("baseline/link")).unwrap();
        assert!(
            discover_targets(root.path())
                .err()
                .unwrap()
                .to_string()
                .contains("baseline/link")
        );
    }

    #[test]
    fn empty_fixture_tree_is_not_a_passing_test_suite() {
        let root = tempfile::tempdir().unwrap();
        assert!(discover_targets(root.path()).is_err());
    }

    #[test]
    fn size_limits_have_exact_boundaries_and_only_noop_subtrees_are_exempt() {
        let root = tempfile::tempdir().unwrap();
        write(root.path(), "baseline/input.bin");
        let input = root.path().join("baseline/input.bin");
        std::fs::write(&input, vec![0; 20 * 1024]).unwrap();
        assert!(discover_targets(root.path()).is_ok());
        std::fs::write(&input, vec![0; 20 * 1024 + 1]).unwrap();
        assert!(
            discover_targets(root.path())
                .err()
                .unwrap()
                .to_string()
                .contains("20 KiB")
        );
        let compressed = root.path().join("baseline/input.bin.xz");
        std::fs::rename(&input, &compressed).unwrap();
        std::fs::write(&compressed, vec![0; 500 * 1024]).unwrap();
        assert!(discover_targets(root.path()).is_ok());
        std::fs::write(&compressed, vec![0; 500 * 1024 + 1]).unwrap();
        assert!(
            discover_targets(root.path())
                .err()
                .unwrap()
                .to_string()
                .contains("500 KiB")
        );
        let exempt = root.path().join("baseline/does-nothing/input.bin");
        std::fs::create_dir_all(exempt.parent().unwrap()).unwrap();
        std::fs::rename(&compressed, exempt).unwrap();
        assert!(discover_targets(root.path()).is_ok());
    }

    #[test]
    fn storage_compression_preserves_bytes_and_original_basename() {
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let stage = NeutralStage::new(root.path()).unwrap();
        let path = root.path().join("package.json.xz");
        let input = b"{\"name\":\"fixture\"}";
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
        encoder.write_all(input).unwrap();
        std::fs::write(&path, encoder.finish().unwrap()).unwrap();
        let staged = stage.stage(&path).unwrap();
        assert_eq!(staged.file_name().unwrap(), "package.json");
        assert_eq!(std::fs::read(staged).unwrap(), input);
        std::fs::write(&path, b"invalid xz").unwrap();
        assert!(stage.stage(&path).is_err());
    }

    #[test]
    fn severity_uses_members_and_ignores_scores_and_filtered_findings() {
        let mut report = AnalysisReport::new(cleave::TargetInfo {
            path: "bundle.zip".into(),
            file_type: "zip".into(),
            size_bytes: 1,
            sha256: "abc".into(),
            architectures: None,
        });
        report.finalize();
        assert_eq!(report_severity(&report).unwrap(), Criticality::Baseline);
        let mut member = report.files[0].clone();
        member.path = "bundle.zip!!member.js##base64@1".into();
        let mut finding = cleave::types::Finding::new("test", Default::default(), "test", 1.0);
        finding.crit = Criticality::Hostile;
        member.findings.push(finding);
        report.files.push(member);
        assert_eq!(report_severity(&report).unwrap(), Criticality::Hostile);
        let target = Target {
            path: "sample".into(),
            expected: Criticality::Suspicious,
        };
        assert!(evaluate(vec![(target, Ok(report))]).is_err());
    }
}

/// Substring that no path-derived value of a staged fixture may contain.
const TESTDATA: &str = "testdata";

/// A per-run directory from which fixtures are analyzed, so that no trait can
/// tell a fixture by where it lives.
///
/// Traits keep `type: path` exemptions for real-world test directories
/// (`testdata/`, `src/test/`, …). Analyzed in place, every fixture sits under
/// `<traits>/testdata/`, and a benign fixture could pass only because its
/// location suppressed a hostile rule. Each fixture is therefore linked (or
/// copied) to `<stage>/<16 hex of its SHA-256>/<basename>`: the basename stays,
/// since manifests such as `package.json` or `action.yml` are identified by
/// name, but no directory of the fixture's own path survives. Archive members
/// keep their internal paths; those are content.
///
/// The directory is removed when the stage is dropped.
struct NeutralStage {
    dir: tempfile::TempDir,
    /// Lowercased substrings that must not appear in any path-derived value.
    forbidden: Vec<String>,
    paths: parking_lot::Mutex<std::collections::BTreeMap<String, String>>,
}

impl NeutralStage {
    fn new(traits_dir: &Path) -> Result<Self> {
        let traits_dir = std::fs::canonicalize(traits_dir)
            .with_context(|| format!("resolving traits dir {}", traits_dir.display()))?;
        let forbidden = vec![
            TESTDATA.to_string(),
            traits_dir.to_string_lossy().to_lowercase(),
        ];
        let dir = tempfile::Builder::new()
            .prefix("cleave-validate-")
            .tempdir()
            .context("creating neutral fixture directory")?;
        // A stage that is itself tainted would trip the guard on every fixture.
        let root = dir.path().to_string_lossy().to_lowercase();
        if let Some(bad) = forbidden.iter().find(|f| root.contains(f.as_str())) {
            anyhow::bail!(
                "neutral fixture directory {} contains {bad:?}; point TMPDIR elsewhere",
                dir.path().display()
            );
        }
        tracing::debug!(dir = %dir.path().display(), "neutral fixture stage created");
        Ok(Self {
            dir,
            forbidden,
            paths: parking_lot::Mutex::default(),
        })
    }

    /// Place `fixture` at its neutral path and return that path.
    fn stage(&self, fixture: &Path) -> Result<PathBuf> {
        // Resolve symlinks first: a hard link to a relative symlink would dangle.
        let source = std::fs::canonicalize(fixture)
            .with_context(|| format!("resolving fixture {}", fixture.display()))?;
        let stored = std::fs::read(&source)
            .with_context(|| format!("reading fixture {}", fixture.display()))?;
        // A final .xz suffix is storage, not part of the sample's format.
        // An XZ-format sample is therefore stored as name.xz.xz. Decode only
        // one layer, retaining its logical basename for filename-sensitive rules.
        let compressed = fixture.extension().is_some_and(|ext| ext == "xz");
        let logical = if compressed {
            fixture.with_extension("")
        } else {
            fixture.to_path_buf()
        };
        let data = if compressed {
            let stream = xz2::stream::Stream::new_stream_decoder(
                128 * 1024 * 1024,
                xz2::stream::CONCATENATED,
            )?;
            let mut decoder = xz2::read::XzDecoder::new_stream(stored.as_slice(), stream)
                .take(512 * 1024 * 1024 + 1);
            let mut decoded = Vec::new();
            decoder
                .read_to_end(&mut decoded)
                .with_context(|| format!("decoding fixture storage {}", safe_path(fixture)))?;
            if decoded.len() > 512 * 1024 * 1024 {
                anyhow::bail!("decoded fixture exceeds 512 MiB: {}", safe_path(fixture));
            }
            decoded
        } else {
            stored
        };
        let dest = self
            .dir
            .path()
            .join(neutral_relative_path(&logical, &data)?);
        let Some(parent) = dest.parent() else {
            anyhow::bail!("neutral path has no parent: {}", dest.display());
        };
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
        let placed = if compressed {
            Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
        } else {
            std::fs::hard_link(&source, &dest)
        };
        match placed {
            // Identical bytes under an identical name: another lane staged it.
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => {
                tracing::debug!(fixture = %fixture.display(), error = %e, "hard link failed; copying");
                // Write aside and rename, so a lane staging the same file never
                // analyzes a half-written copy.
                let mut tmp = tempfile::NamedTempFile::new_in(parent)
                    .with_context(|| format!("creating temp file in {}", parent.display()))?;
                std::io::Write::write_all(&mut tmp, &data)
                    .with_context(|| format!("copying fixture {}", fixture.display()))?;
                tmp.persist(&dest)
                    .with_context(|| format!("placing {}", dest.display()))?;
            }
        }
        tracing::debug!(
            fixture = %fixture.display(),
            neutral = %dest.display(),
            "fixture staged at neutral path"
        );
        Ok(dest)
    }

    /// Analyze `fixture` from its neutral path and return the finalized
    /// report, re-labelled under the fixture's real path. Fails if any
    /// path-derived value still names the fixture's location.
    fn analyze(
        &self,
        fixture: &Path,
        analyze: impl FnOnce(&Path) -> Result<AnalysisReport>,
    ) -> Result<AnalysisReport> {
        let neutral = self.stage(fixture)?;
        self.paths.lock().insert(
            neutral.to_string_lossy().into_owned(),
            fixture.to_string_lossy().into_owned(),
        );
        let mut report = analyze(&neutral)?;
        report.finalize();
        let leaks = path_leaks(&report, &self.forbidden);
        if !leaks.is_empty() {
            anyhow::bail!(
                "path-derived values still name the fixture's location, so path exemptions could apply: {}",
                leaks.join("; ")
            );
        }
        relabel_paths(
            &mut report,
            &neutral.to_string_lossy(),
            &fixture.to_string_lossy(),
        );
        Ok(report)
    }

    /// Diagnostics survive the temporary stage, including when a rejected
    /// outcome is replayed later. Name the original fixture in those messages.
    fn relabel_issues(&self, issues: &mut [validation_controls::ValidationIssue]) {
        let paths = self.paths.lock();
        for issue in issues {
            for (neutral, original) in paths.iter() {
                if issue.message.contains(neutral) {
                    issue.message = issue.message.replace(neutral, original);
                }
            }
        }
    }
}

/// `<first 16 hex of SHA-256(content)>/<basename>`: the only path a fixture
/// is analyzed under, relative to the stage.
fn neutral_relative_path(fixture: &Path, content: &[u8]) -> Result<PathBuf> {
    use sha2::Digest;
    let name = fixture
        .file_name()
        .with_context(|| format!("fixture has no file name: {}", fixture.display()))?;
    let digest = sha2::Sha256::digest(content);
    Ok(Path::new(&hex::encode(&digest[..8])).join(name))
}

/// The file an archive member or decoded fragment path belongs to: everything
/// before the first `!!` (archive member) or `##` (decoded layer) delimiter.
fn host_path(path: &str) -> &str {
    let end = [ARCHIVE_DELIMITER, ENCODING_DELIMITER]
        .into_iter()
        .filter_map(|d| path.find(d))
        .min()
        .unwrap_or(path.len());
    &path[..end]
}

/// Every path-derived value in a finalized `report` that contains one of the
/// lowercased `forbidden` substrings, described for an error message.
///
/// `finalize` moves the target path into `files[0]`, so checked are: the host
/// portion of every file path, and the root file's `file.*` values (in the
/// values tree `type: kv` rules read and in the flattened kv, which also
/// carries cache-restored values). Member paths inside an archive and
/// members' own `file.*` values are content and are not checked.
fn path_leaks(report: &AnalysisReport, forbidden: &[String]) -> Vec<String> {
    let mut leaks = Vec::new();
    let mut check = |what: &str, value: &str| {
        let lower = value.to_lowercase();
        if let Some(bad) = forbidden.iter().find(|f| lower.contains(f.as_str())) {
            leaks.push(format!("{what} {value:?} contains {bad:?}"));
        }
    };

    for file in &report.files {
        check("file path", host_path(&file.path));
    }
    if let Some(root) = report.files.first() {
        for (key, value) in &root.kv {
            if key.starts_with("file.")
                && let Some(s) = value.as_str()
            {
                check(key, s);
            }
        }
    }
    if let Some(values) = report
        .values_tree
        .as_deref()
        .and_then(|tree| tree.get("file"))
        .and_then(serde_json::Value::as_object)
    {
        for (key, value) in values {
            if let Some(s) = value.as_str() {
                check(&format!("file.{key}"), s);
            }
        }
    }
    leaks
}

/// Rewrite paths rooted at `neutral` to be rooted at `original`, so that
/// scores and failures are reported under the fixture's real name.
fn relabel_paths(report: &mut AnalysisReport, neutral: &str, original: &str) {
    let relabel = |path: &mut String| {
        if let Some(rest) = path.strip_prefix(neutral)
            && (rest.is_empty()
                || rest.starts_with(ARCHIVE_DELIMITER)
                || rest.starts_with(ENCODING_DELIMITER))
        {
            *path = format!("{original}{rest}");
        }
    };
    // `finalize` has already cleared the target and archive listing.
    for file in &mut report.files {
        relabel(&mut file.path);
    }
}

/// Collect findings from all analyzed test files and check for overlapping traits
fn collect_overlap_findings(
    results: &[(Target, Result<AnalysisReport>)],
) -> Vec<validate_testdata::OverlapFinding> {
    use std::collections::{BTreeMap, BTreeSet};

    // Helper struct to track trait ranges
    struct TraitRange {
        offset: u64,
        length: u64,
        trait_id: String,
    }

    // Collect all trait ranges from all analysis results
    let mut all_ranges: BTreeMap<String, Vec<TraitRange>> = BTreeMap::new();

    for (_, report_result) in results {
        if let Ok(report) = report_result {
            for file_analysis in &report.files {
                let file_key = report
                    .target
                    .path
                    .strip_prefix("testdata/")
                    .unwrap_or(&report.target.path)
                    .to_string();

                for finding in &file_analysis.findings {
                    // Skip composite rules — we want atomic trait overlaps
                    if finding.id.matches("::").count() > 2 {
                        continue;
                    }

                    // Collect all ranges where this trait fired
                    for evidence in &finding.evidence {
                        let length = evidence.value.len() as u64;
                        for &offset in &evidence.offsets {
                            all_ranges
                                .entry(file_key.to_string())
                                .or_default()
                                .push(TraitRange {
                                    offset,
                                    length,
                                    trait_id: finding.id.clone().to_string(),
                                });
                        }
                    }
                }
            }
        }
    }

    // Find overlapping ranges for each file
    let mut overlaps = Vec::new();
    for (file_path, ranges) in all_ranges {
        let mut found_overlaps: BTreeMap<(u64, u64), BTreeSet<String>> = BTreeMap::new();

        for i in 0..ranges.len() {
            for j in (i + 1)..ranges.len() {
                let a = &ranges[i];
                let b = &ranges[j];

                let a_end = a.offset + a.length;
                let b_end = b.offset + b.length;

                let overlap_start = a.offset.max(b.offset);
                let overlap_end = a_end.min(b_end);

                if overlap_start < overlap_end {
                    found_overlaps
                        .entry((overlap_start, overlap_end))
                        .or_default()
                        .insert(a.trait_id.clone());
                    found_overlaps
                        .entry((overlap_start, overlap_end))
                        .or_default()
                        .insert(b.trait_id.clone());
                }
            }
        }

        for (range, trait_set) in found_overlaps {
            let trait_ids = trait_set.into_iter().collect::<Vec<_>>();
            overlaps.push(validate_testdata::OverlapFinding {
                file_path: file_path.clone(),
                range,
                overlap_count: trait_ids.len(),
                trait_ids,
            });
        }
    }

    // Sort by file, then by range start
    overlaps.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then(a.range.0.cmp(&b.range.0))
    });

    overlaps
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod neutral_stage_tests {
    use super::{
        AnalysisReport, NeutralStage, Path, TESTDATA, neutral_relative_path, path_leaks,
        relabel_paths,
    };

    fn report_at(path: &str, basename: &str) -> AnalysisReport {
        let mut report = AnalysisReport::new(cleave::TargetInfo {
            path: path.to_string(),
            file_type: "javascript".to_string(),
            size_bytes: 1,
            sha256: "abc".to_string(),
            architectures: None,
        });
        report.values_tree = Some(Box::new(serde_json::json!({
            "file": { "basename": basename, "size": 1 },
        })));
        report
    }

    fn forbidden(traits_dir: &str) -> Vec<String> {
        vec![TESTDATA.to_string(), traits_dir.to_lowercase()]
    }

    #[test]
    fn neutral_path_is_content_hash_and_basename_only() {
        let fixture = Path::new("/r/traits/testdata/benign/gh-controls/.github/action.yml");
        let rel = neutral_relative_path(fixture, b"on: push\n").unwrap();
        let parts: Vec<_> = rel.iter().map(|c| c.to_str().unwrap()).collect();
        assert_eq!(parts.len(), 2, "{rel:?}");
        assert_eq!(parts[0].len(), 16);
        assert!(parts[0].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(parts[1], "action.yml");
        for dir in [
            "testdata",
            "benign",
            "gh-controls",
            ".github",
            "traits",
            "/r",
        ] {
            assert!(!rel.to_str().unwrap().contains(dir), "{rel:?} names {dir}");
        }
        // Same bytes share a directory; different bytes never do.
        assert_eq!(
            rel,
            neutral_relative_path(Path::new("elsewhere/action.yml"), b"on: push\n").unwrap()
        );
        assert_ne!(
            rel,
            neutral_relative_path(fixture, b"on: pull_request\n").unwrap()
        );
    }

    #[test]
    fn stage_places_fixture_outside_traits_dir_and_cleans_up() {
        let traits = tempfile::tempdir().unwrap();
        let dir = traits
            .path()
            .join("testdata")
            .join("benign")
            .join("npm-pkg");
        std::fs::create_dir_all(&dir).unwrap();
        let fixture = dir.join("package.json");
        std::fs::write(&fixture, br#"{"name":"x"}"#).unwrap();

        let stage = NeutralStage::new(traits.path()).unwrap();
        let root = stage.dir.path().to_path_buf();
        let neutral = stage.stage(&fixture).unwrap();
        // Staging the same fixture twice (two lanes) is harmless.
        assert_eq!(neutral, stage.stage(&fixture).unwrap());

        assert!(neutral.starts_with(&root));
        assert_eq!(neutral.file_name().unwrap(), "package.json");
        assert_eq!(std::fs::read(&neutral).unwrap(), br#"{"name":"x"}"#);
        let shown = neutral.to_string_lossy().to_lowercase();
        let canonical = std::fs::canonicalize(traits.path()).unwrap();
        for bad in [
            TESTDATA.to_string(),
            "npm-pkg".to_string(),
            "benign".to_string(),
            canonical.to_string_lossy().to_lowercase(),
            traits.path().to_string_lossy().to_lowercase(),
        ] {
            assert!(!shown.contains(&bad), "{shown} contains {bad}");
        }

        drop(stage);
        assert!(!root.exists(), "stage directory must be removed");
        assert!(fixture.exists(), "the fixture itself must survive");
    }

    #[test]
    fn analyze_reports_under_fixture_path_and_rejects_leaks() {
        let traits = tempfile::tempdir().unwrap();
        let dir = traits.path().join("testdata").join("benign");
        std::fs::create_dir_all(&dir).unwrap();
        let fixture = dir.join("index.js");
        std::fs::write(&fixture, b"1").unwrap();
        let stage = NeutralStage::new(traits.path()).unwrap();

        let report = stage
            .analyze(&fixture, |p| {
                Ok(report_at(&p.to_string_lossy(), "index.js"))
            })
            .unwrap();
        let original = fixture.to_string_lossy();
        assert_eq!(report.files[0].path, original);

        let neutral = stage.stage(&fixture).unwrap();
        let mut issues = vec![crate::validation_controls::ValidationIssue::new(
            "rule-performance",
            format!("cost exceeded on '{}!!/member.js'", neutral.display()),
        )];
        stage.relabel_issues(&mut issues);
        assert_eq!(
            issues[0].message,
            format!("cost exceeded on '{original}!!/member.js'")
        );

        // An engine path that bypasses the stage must fail loudly.
        let err = stage
            .analyze(&fixture, |_| Ok(report_at(&original, "index.js")))
            .unwrap_err();
        assert!(err.to_string().contains("testdata"), "{err:#}");
    }

    #[test]
    fn guard_flags_every_path_derived_value() {
        let traits = "/Users/x/traits-dev";
        let clean = "/tmp/cleave-validate-a/0123456789abcdef/index.js";

        let mut ok = report_at(clean, "index.js");
        ok.finalize();
        assert!(path_leaks(&ok, &forbidden(traits)).is_empty());

        let mut in_testdata = report_at("/w/TestData/benign/index.js", "index.js");
        in_testdata.finalize();
        assert!(!path_leaks(&in_testdata, &forbidden(traits)).is_empty());

        let mut in_traits = report_at(&format!("{traits}/benign/index.js"), "index.js");
        in_traits.finalize();
        assert!(!path_leaks(&in_traits, &forbidden(traits)).is_empty());

        // A basename is path-derived even when the path is clean.
        let mut basename = report_at(clean, "testdata-index.js");
        basename.finalize();
        let leaks = path_leaks(&basename, &forbidden(traits));
        assert!(
            leaks.iter().any(|l| l.starts_with("file.basename")),
            "{leaks:?}"
        );

        // Only the flattened kv (e.g. restored from cache) carries it.
        let mut kv_only = report_at(clean, "index.js");
        kv_only.finalize();
        kv_only.values_tree = None;
        kv_only.files[0]
            .kv
            .insert("file.stem".into(), serde_json::json!("testdata"));
        assert!(!path_leaks(&kv_only, &forbidden(traits)).is_empty());

        // A member file whose host path escaped the stage.
        let mut member = report_at(clean, "index.js");
        member.finalize();
        let mut escaped = member.files[0].clone();
        escaped.path = format!("{traits}/x.zip!!a.js");
        member.files.push(escaped);
        assert!(!path_leaks(&member, &forbidden(traits)).is_empty());
    }

    #[test]
    fn guard_ignores_archive_member_paths() {
        let clean = "/tmp/cleave-validate-a/0123456789abcdef/pkg.zip";
        let mut report = report_at(clean, "pkg.zip");
        report.finalize();
        let mut member = report.files[0].clone();
        member.path = format!("{clean}!!go/src/testdata/x.go##base64@3");
        member
            .kv
            .insert("file.basename".into(), serde_json::json!("testdata"));
        report.files.push(member);
        assert!(path_leaks(&report, &forbidden("/Users/x/traits-dev")).is_empty());
    }

    #[test]
    fn relabel_rewrites_only_the_staged_root() {
        let neutral = "/t/h/a.js";
        let mut report = report_at(neutral, "a.js");
        report.finalize();
        let mut member = report.files[0].clone();
        member.path = format!("{neutral}##base64@4");
        report.files.push(member);
        let mut sibling = report.files[0].clone();
        sibling.path = "/t/h/a.jsx".into();
        report.files.push(sibling);

        relabel_paths(&mut report, neutral, "/fix/a.js");
        assert_eq!(report.files[0].path, "/fix/a.js");
        assert_eq!(report.files[1].path, "/fix/a.js##base64@4");
        assert_eq!(report.files[2].path, "/t/h/a.jsx");
    }
}
