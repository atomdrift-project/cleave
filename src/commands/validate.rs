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

#[path = "validate_state.rs"]
mod fixture_state;
#[path = "validate_cache.rs"]
mod result_cache;
#[path = "validate_slow_rules.rs"]
mod slow_rules;

/// Every fixture derives its sole expectation from its top-level directory.
struct Target {
    path: PathBuf,
    expected: Criticality,
    /// What the discovery walk read about the file, for the result cache's
    /// walk stamp; `None` only for targets built outside discovery (tests).
    metadata: Option<std::fs::Metadata>,
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
        None,
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
/// and a report store's local scanner — that must tolerate hygiene debt but reject a
/// bundle that won't load or won't detect on this engine. The hard set is
/// defined in one place: `validation_controls::HARD_VALIDATOR_IDS`.
pub fn run_soft(format: &OutputFormat, exclude: Option<&str>, verbose: bool) -> Result<String> {
    run_with_options(
        format,
        exclude,
        verbose,
        true,
        CapabilityMapper::DEFAULT_SLOW_RULE_MS,
        None,
    )
}

/// Note, without failing, how many conditions use a `type:` spelling slated for
/// retirement, so the rule set can move off them before support is removed.
fn report_retiring_condition_types(traits_dir: &Path) {
    use crate::composite_rules::condition::{
        RETIRING_CONDITION_TYPES, count_retiring_condition_types,
    };
    let Ok(sources) = crate::rule_sources::shared(traits_dir) else {
        return;
    };
    let yaml = sources
        .files()
        .iter()
        .filter(|f| {
            f.relative_path
                .extension()
                .is_some_and(|e| e == "yaml" || e == "yml")
        })
        .map(|f| &f.bytes[..]);
    let counts = count_retiring_condition_types(yaml);
    let uses: Vec<String> = RETIRING_CONDITION_TYPES
        .iter()
        .zip(&counts)
        .filter(|(_, n)| **n > 0)
        .map(|((old, new), n)| format!("type: {old} ({n}) -> {new}"))
        .collect();
    if !uses.is_empty() {
        eprintln!(
            "note: condition spellings slated for retirement: {}",
            uses.join("; ")
        );
    }
}

/// Run validation with the CLI's slow-rule threshold. The environment soft-mode
/// toggle also applies to callers using the default (strict) mode.
///
/// `slow_rules` asks for the slow-rule audit: every fixture is analyzed with
/// no result or per-fixture cache, every rule evaluation is timed, and the
/// top `n` rules by total time are printed before the verdict.
pub fn run_with_options(
    format: &OutputFormat,
    exclude: Option<&str>,
    verbose: bool,
    soft: bool,
    slow_rule_ms: u64,
    slow_rules: Option<usize>,
) -> Result<String> {
    let started = Instant::now();
    if slow_rules.is_some() {
        crate::composite_rules::trait_timing::enable();
    }
    let soft = soft || crate::env::flag("CLEAVE_VALIDATE_SOFT");
    // `--exclude` silences specific validators (the only suppression knob);
    // `--soft` downgrades every Soft-severity problem to advisory, leaving only
    // Hard problems (won't load / won't fire) fatal.
    validation_controls::set_disabled_validators_override(exclude)?;
    validation_controls::set_soft_validation_mode(soft);
    let traits_dir = std::fs::canonicalize(cleave::traits_repo::try_resolve()?)?;
    // The two walks that decide a cache hit, side by side.
    let discovery_started = Instant::now();
    let (targets, rule_tree) = rayon::join(collect_targets, || {
        result_cache::stamp_rule_tree(&traits_dir)
    });
    let targets = targets?;
    tracing::info!(
        fixtures = targets.len(),
        elapsed_ms = discovery_started.elapsed().as_millis(),
        "fixtures discovered and rule tree digested"
    );
    // The audit measures every rule on every fixture: no cached verdict, no
    // per-fixture reuse (both hang off the result cache).
    let result_cache = if slow_rules.is_some() {
        None
    } else {
        result_cache::ResultCache::new(
            &traits_dir,
            rule_tree,
            &targets,
            "severity-directories-v1",
            soft,
            verbose,
            slow_rule_ms,
        )
    };
    // Everything before this point must get by without reading a rule file:
    // a cache hit on an unchanged tree is decided from the directory walk
    // alone, and the first source read costs more than the whole hit.
    if let Some(hit) = result_cache
        .as_ref()
        .and_then(result_cache::ResultCache::load)
    {
        match hit.outcome {
            result_cache::Outcome::Passed(fixtures) => {
                return Ok(format_validate_output(
                    &validation_output(fixtures, hit.traits_version),
                    format,
                ));
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
    report_retiring_condition_types(&traits_dir);
    // Fixtures are analyzed from outside the traits repo, so no path
    // exemption can match their location; see `NeutralStage`.
    let stage = NeutralStage::new(&traits_dir)?;

    // A verified full-validation cache hit above can reuse a measured pass.
    // Fresh performance validation bypasses analysis reports and shared AST
    // batches so each rule's cost is measured, not hidden by previously computed
    // answers. Compiled-rule caches remain available. Route validation issues
    // through the chosen output format.
    cleave::validation_controls::set_validation_output_format(Some(match format {
        OutputFormat::Json => cleave::validation_controls::ValidationOutputFormat::Json,
        OutputFormat::Annotate | OutputFormat::Index => {
            cleave::validation_controls::ValidationOutputFormat::Terminal
        }
    }));
    let options = cleave::AnalysisOptions {
        yara: true,
        upx: false,
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
        CapabilityMapper::load(cleave::LoadOptions {
            full_validation: true,
            ..cleave::LoadOptions::default()
        })?
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
    cleave::prefetch_yara_engine(options.third_party_yara);
    let yara_ms = yara_started.elapsed().as_millis();

    // Which fixtures this edit can have changed. The last run's per-fixture
    // state is kept under the same gate as the result cache; without it,
    // every fixture is analyzed.
    let plan_started = Instant::now();
    const EXPECTATIONS: &str = "severity-directories-v1";
    let engine = cleave::traits_fingerprint::binary_identity();
    let state_path = result_cache
        .as_ref()
        .and_then(|_| fixture_state::FixtureState::path(&traits_dir));
    let settings: Vec<u8> = result_cache
        .as_ref()
        .map(|cache| cache.settings().to_vec())
        .unwrap_or_default();
    let digests = fixture_state::fixture_digests(&targets);
    let incremental = match (&state_path, crate::rule_sources::shared(&traits_dir)) {
        (Some(path), Ok(sources)) => {
            let previous = fixture_state::FixtureState::load(path, engine, &settings, EXPECTATIONS);
            let scopes = mapper.rule_file_scopes();
            let current = fixture_state::CurrentRules::of(&sources);
            Some((previous, scopes, current))
        }
        _ => None,
    };
    let plan = match &incremental {
        Some((previous, scopes, current)) => fixture_state::FixtureState::plan(
            previous.as_ref(),
            &traits_dir,
            &targets,
            &digests,
            current,
            scopes,
        ),
        None => fixture_state::Plan::full(targets.len()),
    };
    let plan_ms = plan_started.elapsed().as_millis();

    let performance = crate::validation_performance::Session::begin();
    let analysis_started = Instant::now();
    let selected: Vec<usize> = (0..targets.len()).filter(|&i| plan.run[i]).collect();
    // Time rules where an edit can have changed their cost: every rule on a
    // fixture that runs for its own sake, only the edited rules on one that
    // runs because an edited rule reaches it. Their other queries share the
    // AST batch a scan uses, which is half the cost of timing each alone.
    let edited_only = plan
        .edited_rules()
        .filter(|_| selected.iter().any(|&i| !plan.fixture_changed(i)))
        .map(|files| Arc::new(mapper.measuring_only(files)));

    // A fixture whose last analysis alone outlasted this run's balanced
    // share of the pool is analyzed first, by itself, with the whole pool
    // fanned out inside it: in a lane it would finish long after every other
    // lane ran dry. In a full run nothing qualifies, since the balanced share
    // is the run itself.
    let threads = rayon::current_num_threads().max(1) as u64;
    let known_work: u64 = selected
        .iter()
        .filter_map(|&i| plan.previous_elapsed_ms(i))
        .sum();
    let balanced_ms = known_work / threads;
    let mut whales: Vec<usize> = selected
        .iter()
        .copied()
        .filter(|&i| {
            plan.previous_elapsed_ms(i)
                .is_some_and(|ms| ms > 5_000 && ms > balanced_ms.saturating_mul(3) / 2)
        })
        .collect();
    whales.sort_by_key(|&i| std::cmp::Reverse(plan.previous_elapsed_ms(i)));
    let mut reports: Vec<OnceLock<Result<AnalysisReport>>> =
        targets.iter().map(|_| OnceLock::new()).collect();
    let elapsed: Vec<std::sync::atomic::AtomicU64> = targets
        .iter()
        .map(|_| std::sync::atomic::AtomicU64::new(0))
        .collect();
    let analyze_one = |i: usize| {
        let t = &targets[i];
        let fixture_started = Instant::now();
        let rules = match &edited_only {
            Some(scoped) if !plan.fixture_changed(i) => scoped,
            _ => &mapper,
        };
        let report = stage.analyze(t.path(), |p| {
            cleave::analyze_file_with_mapper(p, &options, rules)
        });
        let elapsed_ms = fixture_started.elapsed().as_millis();
        if elapsed_ms >= 500 {
            tracing::info!(path = %t.path().display(), elapsed_ms, "slow validation fixture");
        }
        elapsed[i].store(elapsed_ms as u64, Ordering::Relaxed);
        let _ = reports[i].set(report);
    };
    for &i in &whales {
        tracing::info!(path = %targets[i].path().display(),
            previous_ms = plan.previous_elapsed_ms(i).unwrap_or(0),
            "analyzing an oversized fixture ahead of the lanes");
        analyze_one(i);
    }

    // One lane per pool thread, each pulling the next fixture, so that every
    // fixture analysis begins on an idle worker stack. As `into_par_iter`
    // jobs, fixtures were also taken up by threads waiting inside another
    // analysis's rayon join, on top of the half that analysis was waiting
    // for. A member of such a fixture that then waited on a busy single-flight
    // could be waiting on the very owner blocked in that join, and nothing
    // moved until the flight's 180 s deadline. A worker takes its broadcast job before it steals
    // anything, so no lane starts on top of another analysis's work.
    // Start large fixtures early so a bundled source file does not begin near
    // the end of the queue and leave every other lane idle. Keep report slots
    // in original order so diagnostics and expectation checks stay stable.
    let mut work: Vec<_> = selected
        .iter()
        .filter(|i| !whales.contains(i))
        .map(|&i| {
            (
                i,
                targets[i]
                    .metadata
                    .as_ref()
                    .map_or(0, std::fs::Metadata::len),
            )
        })
        .collect();
    work.sort_unstable_by_key(|&(i, size)| (std::cmp::Reverse(size), i));
    let next = AtomicUsize::new(0);
    rayon::broadcast(|lane| {
        let mut analyzed = 0usize;
        loop {
            let job = next.fetch_add(1, Ordering::Relaxed);
            let Some(&(i, _)) = work.get(job) else {
                // When each lane ran dry says how long the pool idled behind
                // the last fixtures: the tail no fixture ordering can hide.
                tracing::info!(
                    lane = lane.index(),
                    analyzed,
                    at_ms = analysis_started.elapsed().as_millis(),
                    "validation lane finished"
                );
                break;
            };
            analyzed += 1;
            analyze_one(i);
        }
    });
    tracing::info!(
        setup_ms,
        mapper_and_lint_ms,
        index_ms,
        yara_ms,
        plan_ms,
        analysis_ms = analysis_started.elapsed().as_millis(),
        fixtures = targets.len(),
        analyzed = selected.len(),
        reused = plan.reused(),
        whales = whales.len(),
        "validation phase timings"
    );
    // Include aggregate trait costs (CLEAVE_TRAIT_TIMING=1) on validation runs,
    // including runs whose fixture expectations fail below.
    cleave::log_scan_stats();
    if let Some(n) = slow_rules {
        print_slow_rules(&slow_rules::audit(&mapper, n), format);
    }
    let results: Vec<(usize, Result<AnalysisReport>)> = selected
        .iter()
        .map(|&i| {
            let report = reports[i]
                .take()
                .unwrap_or_else(|| Err(anyhow::anyhow!("fixture was not analyzed")));
            (i, report)
        })
        .collect();

    // Check for overlapping traits in the analyzed findings. This is a
    // diagnostic, not a pass/fail signal, so only compute it when verbose.
    let overlap_findings = if verbose {
        collect_overlap_findings(&targets, &results)
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
    let judged = judge(&targets, &results, &plan);

    // Record what this run learned about each fixture before judging the
    // run: a failing edit loop still narrows the next run to what changed.
    if let (Some(path), Some((_, scopes, current))) = (&state_path, incremental)
        && performance_issues.is_empty()
        && crate::yara_engine::yara_degradation().is_none()
    {
        let mut outcomes: Vec<Option<fixture_state::FixtureOutcome>> =
            targets.iter().map(|_| None).collect();
        for (i, result) in &results {
            if let Ok(report) = result {
                outcomes[*i] = Some(fixture_state::FixtureOutcome {
                    types: fixture_state::report_types(report),
                    passed: judged.passed[*i]
                        && !crate::analysis_cache::evaluation_incomplete(report),
                    elapsed_ms: elapsed[*i].load(Ordering::Relaxed),
                });
            }
        }
        fixture_state::FixtureState::record(
            &traits_dir,
            engine,
            &settings,
            EXPECTATIONS,
            current,
            &scopes,
            &targets,
            &digests,
            &plan,
            &outcomes,
        )
        .store(path);
    }
    if judged.failures > 0 {
        anyhow::bail!("{} validation fixture check(s) failed", judged.failures);
    }
    let fixtures = judged.summary;
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

    let report = validation_output(fixtures, cleave::traits_repo::version());
    if cacheable
        && performance_issues.is_empty()
        && let Some(cache) = result_cache
    {
        cache.store_if_unchanged(&report.fixtures);
    }

    Ok(format_validate_output(&report, format))
}

/// The slow-rule audit, as a table on the terminal or one JSON document on
/// stdout, ahead of the verdict so a failing tree is audited too.
fn print_slow_rules(audit: &slow_rules::Audit, format: &OutputFormat) {
    match format {
        OutputFormat::Json => match serde_json::to_string(audit) {
            Ok(json) => println!("{json}"),
            Err(error) => eprintln!("slow-rule audit not encoded: {error}"),
        },
        OutputFormat::Annotate | OutputFormat::Index => print!("{}", audit.table()),
    }
}

fn print_performance_issues(
    issues: &[validation_controls::ValidationIssue],
    format: &OutputFormat,
) {
    if issues.is_empty() {
        return;
    }
    let rendered = match format {
        OutputFormat::Json => validation_controls::format_validation_issues_json(issues),
        OutputFormat::Annotate | OutputFormat::Index => {
            validation_controls::format_validation_issues_terminal(issues)
        }
    };
    eprintln!("{rendered}");
}

fn validation_output(fixtures: FixtureSummary, traits_version: Option<String>) -> ValidateOutput {
    ValidateOutput {
        ok: true,
        traits_version,
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
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string());
            format!(
                "{json}
"
            )
        }
        OutputFormat::Annotate | OutputFormat::Index => format_validate_terminal(report),
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

/// Discover every file, including dotfiles, without reading fixture contents.
/// This runs before cache lookup: an unrecognized file can never hide behind
/// a previously passing validation result. Subdirectories carry no semantics.
fn collect_targets() -> Result<Vec<Target>> {
    let traits_dir = cleave::traits_repo::try_resolve()?;
    discover_targets(&traits_dir.join("testdata"))
}

fn discover_targets(root: &Path) -> Result<Vec<Target>> {
    if !root.is_dir() {
        anyhow::bail!("missing validation fixture directory: {}", safe_path(root));
    }
    // Each directory is read once and its subdirectories are read on the
    // pool: one `readdir` at a time over fourteen thousand fixtures is a
    // tenth of a second the no-change path cannot spare. Entries come back
    // in name order at every level, so the result is deterministic.
    let mut targets = Vec::new();
    let mut unused = Vec::new();
    for entry in walk_fixture_dir(root, root, 0)? {
        classify_fixture(root, entry, &mut targets, &mut unused)?;
    }
    if !unused.is_empty() {
        unused.sort_unstable();
        let shown = unused
            .iter()
            .take(20)
            .map(|p| format!("  {p}"))
            .collect::<Vec<_>>()
            .join(
                "
",
            );
        anyhow::bail!(
            "{} unused or unsupported testdata file(s); every file must be a regular fixture under hostile/, suspicious/, notable/, or baseline/:
{}{}",
            unused.len(),
            shown,
            if unused.len() > 20 {
                format!("
  ... {} more", unused.len() - 20)
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

/// One non-directory entry of the fixture tree, as its directory listed it.
struct FixtureEntry {
    path: PathBuf,
    is_file: bool,
    metadata: std::fs::Metadata,
}

/// Every non-directory entry below `dir`, links not followed.
fn walk_fixture_dir(root: &Path, dir: &Path, depth: usize) -> Result<Vec<FixtureEntry>> {
    use rayon::prelude::*;
    let mut entries: Vec<(std::ffi::OsString, std::fs::DirEntry)> = std::fs::read_dir(dir)
        .and_then(|entries| {
            entries
                .map(|entry| entry.map(|entry| (entry.file_name(), entry)))
                .collect()
        })
        .with_context(|| format!("walking {}", safe_path(root)))?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut found = Vec::new();
    let mut subdirs = Vec::new();
    for (_, entry) in entries {
        let file_type = entry
            .file_type()
            .with_context(|| format!("walking {}", safe_path(root)))?;
        if file_type.is_dir() {
            if depth < 64 {
                subdirs.push(entry.path());
            }
            continue;
        }
        let metadata = entry
            .metadata()
            .with_context(|| format!("walking {}", safe_path(root)))?;
        found.push(FixtureEntry {
            path: entry.path(),
            is_file: file_type.is_file(),
            metadata,
        });
    }
    let below: Vec<Result<Vec<FixtureEntry>>> = subdirs
        .par_iter()
        .map(|subdir| walk_fixture_dir(root, subdir, depth + 1))
        .collect();
    for entries in below {
        found.extend(entries?);
    }
    Ok(found)
}

/// File `entry` of the fixture tree is a fixture, or is listed as unused.
fn classify_fixture(
    root: &Path,
    entry: FixtureEntry,
    targets: &mut Vec<Target>,
    unused: &mut Vec<String>,
) -> Result<()> {
    let relative = entry.path.strip_prefix(root)?;
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
        entry.is_file
            && relative
                .parent()
                .is_some_and(|parent| !parent.as_os_str().is_empty())
    }) {
        let exempt = relative.components().nth(2).is_some()
            && relative
                .components()
                .nth(1)
                .is_some_and(|c| c.as_os_str() == "does-nothing");
        let size = entry.metadata.len();
        if !exempt && size > 500 * 1024 {
            unused.push(format!(
                "{}: {size} bytes exceeds the 500 KiB fixture limit",
                safe_path(relative)
            ));
            return Ok(());
        }
        if !exempt && size > 20 * 1024 && entry.path.extension().is_none_or(|ext| ext != "xz") {
            unused.push(format!(
                "{}: {size} bytes; fixtures above 20 KiB must use xz storage compression",
                safe_path(relative)
            ));
            return Ok(());
        }
        targets.push(Target {
            path: entry.path,
            expected,
            metadata: Some(entry.metadata),
        });
    } else {
        unused.push(safe_path(relative));
    }
    Ok(())
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

/// Every fixture's verdict against its expectation.
struct Judged {
    summary: FixtureSummary,
    /// Per target, whether it passed: analyzed fixtures by their report,
    /// reused ones by their recorded pass.
    passed: Vec<bool>,
    failures: usize,
}

/// Judge the analyzed fixtures and count the reused ones as the passes they
/// were recorded as. Failures are printed here; the caller decides when to
/// stop.
fn judge(
    targets: &[Target],
    results: &[(usize, Result<AnalysisReport>)],
    plan: &fixture_state::Plan,
) -> Judged {
    let mut summary = FixtureSummary::default();
    let mut passed = vec![false; targets.len()];
    let mut failures = 0;
    for (i, target) in targets.iter().enumerate() {
        if !plan.run[i] {
            let count = summary.count_mut(target.expected);
            count.total += 1;
            count.passed += 1;
            passed[i] = true;
        }
    }
    for (i, result) in results {
        let target = &targets[*i];
        let count = summary.count_mut(target.expected);
        count.total += 1;
        match result
            .as_ref()
            .map_err(|e| anyhow::anyhow!("{e:#}"))
            .and_then(|report| report_severity(report).map(|severity| (report, severity)))
        {
            Ok((_, actual)) if actual == target.expected => {
                count.passed += 1;
                passed[*i] = true;
            }
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
    Judged {
        summary,
        passed,
        failures,
    }
}

#[cfg(test)]
fn evaluate(results: Vec<(Target, Result<AnalysisReport>)>) -> Result<FixtureSummary> {
    let (targets, reports): (Vec<Target>, Vec<Result<AnalysisReport>>) =
        results.into_iter().unzip();
    let results: Vec<(usize, Result<AnalysisReport>)> = reports.into_iter().enumerate().collect();
    let judged = judge(
        &targets,
        &results,
        &fixture_state::Plan::full(targets.len()),
    );
    if judged.failures > 0 {
        anyhow::bail!("{} validation fixture check(s) failed", judged.failures);
    }
    Ok(judged.summary)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod severity_fixture_tests;

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
    /// Per staged content directory, the analyses using it. The last one out
    /// removes it, so the stage empties during the run instead of in one
    /// serial removal of every fixture after the verdict is known.
    users: parking_lot::Mutex<std::collections::HashMap<PathBuf, usize>>,
}

impl NeutralStage {
    fn new(traits_dir: &Path) -> Result<Self> {
        let traits_dir = std::fs::canonicalize(traits_dir)
            .with_context(|| format!("resolving traits dir {}", traits_dir.display()))?;
        let forbidden = vec![
            TESTDATA.to_string(),
            traits_dir.to_string_lossy().to_lowercase(),
        ];
        // The random suffix can itself contain `qa` or another test-path
        // marker. Such a stage suppresses unrelated findings in every fixture.
        let mut dir = None;
        for _ in 0..64 {
            let candidate = tempfile::Builder::new()
                .prefix("cleave-validate-")
                .tempdir()
                .context("creating neutral fixture directory")?;
            if !neutral_test_path(candidate.path())? {
                dir = Some(candidate);
                break;
            }
        }
        let dir =
            dir.context("could not create a fixture stage without a test-directory marker")?;
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
            users: parking_lot::Mutex::default(),
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
        // Claimed before it is created, so the last user of the directory
        // never removes it under a lane that is about to place a file there.
        *self.users.lock().entry(parent.to_path_buf()).or_insert(0) += 1;
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
        let analyzed = analyze(&neutral);
        self.release(&neutral);
        let mut report = analyzed?;
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

    /// Done with `neutral`: the last analysis using its content directory
    /// removes it. A directory left behind goes with the stage.
    fn release(&self, neutral: &Path) {
        let Some(parent) = neutral.parent() else {
            return;
        };
        let mut users = self.users.lock();
        let Some(count) = users.get_mut(parent) else {
            return;
        };
        *count -= 1;
        if *count > 0 {
            return;
        }
        users.remove(parent);
        // Removed under the lock: a lane staging this content again claims
        // the directory only once it is gone.
        let removed = std::fs::remove_dir_all(parent);
        drop(users);
        if let Err(error) = removed {
            tracing::debug!(dir = %parent.display(), %error, "staged fixture not removed");
        }
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

/// `<escaped first 16 hex of SHA-256(content)>/<basename>`: the only path a fixture
/// is analyzed under, relative to the stage.
fn neutral_relative_path(fixture: &Path, content: &[u8]) -> Result<PathBuf> {
    use sha2::Digest;
    let name = fixture
        .file_name()
        .with_context(|| format!("fixture has no file name: {}", fixture.display()))?;
    let digest = sha2::Sha256::digest(content);
    // `e2e` is a test-directory marker but also valid hexadecimal. Replace
    // it with a spelling that cannot occur in a hex digest; this stays
    // deterministic and collision-free for the same truncated digest.
    let directory = hex::encode(&digest[..8]).replace("e2e", "e2g");
    Ok(Path::new(&directory).join(name))
}

fn neutral_test_path(path: &Path) -> Result<bool> {
    static RE: std::sync::OnceLock<std::result::Result<regex::Regex, regex::Error>> =
        std::sync::OnceLock::new();
    let pattern = RE.get_or_init(|| {
        regex::Regex::new(r"(?i)(^|\W)\w*?(test|spec|e2e|qa|mock|fuzz|harness|vector)[-\w]*[\\/]")
    });
    let pattern = pattern.as_ref().context("compiling test-directory regex")?;
    Ok(pattern.is_match(&format!("{}/", path.display())))
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
    _targets: &[Target],
    results: &[(usize, Result<AnalysisReport>)],
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
mod neutral_stage_tests;
