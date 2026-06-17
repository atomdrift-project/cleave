//! Trait validation command.
//!
//! Runs the full suite of trait definition validation checks and reports any
//! errors or quality issues found. Exits with a non-zero status if validation fails.

use crate::cli::OutputFormat;
use crate::commands::validate_testdata;
use anyhow::{Context, Result};
use cleave::{AnalysisReport, CapabilityMapper, Criticality, FileAnalysis, validation_controls};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A single file to analyze during validation and how to judge its score.
enum Target {
    /// Known-hostile sample whose root-file score and severe finding counts
    /// must stay above a per-file floor.
    Hostile {
        path: PathBuf,
        min_score: u32,
        min_hostile: usize,
        min_suspicious: usize,
    },
    /// Known-benign sample whose root-file score must stay under a per-file cap.
    Benign { path: PathBuf, cap: u32 },
    /// Walked-hostile sample (e.g. `testdata/drop-exec/`, `testdata/reverse-shell/`).
    /// Every file under the corpus directory must satisfy the configured score
    /// and/or hostile-finding floors — like the inverse of the does-nothing walk.
    WalkedHostile {
        path: PathBuf,
        corpus: String,
        min_score: u32,
        min_hostile: usize,
    },
    /// Does-nothing sample. Its (and any archive-member) score must stay
    /// within the cap returned by [`does_nothing_cap`].
    DoesNothing {
        path: PathBuf,
        /// Root of the does-nothing directory (for resolving per-file caps).
        dir: PathBuf,
    },
}

impl Target {
    fn path(&self) -> &Path {
        match self {
            Self::Hostile { path, .. }
            | Self::Benign { path, .. }
            | Self::WalkedHostile { path, .. }
            | Self::DoesNothing { path, .. } => path,
        }
    }
}

/// Print the score-contributing findings for a file, filtering out Component/Filtered noise.
fn print_contributing_findings(file: &FileAnalysis, indent: &str) {
    for finding in &file.findings {
        if finding.crit == Criticality::Component || finding.crit == Criticality::Filtered {
            continue;
        }
        eprintln!(
            "{indent}{:10} {}  {}",
            format!("{:?}", finding.crit).to_lowercase(),
            finding.id,
            finding.desc
        );
    }
}

/// Run full trait validation: trait defs + hostile/benign fixtures + does-nothing checks.
///
/// All sample analyses (fixture files and the does-nothing corpus) run in a
/// single rayon parallel pool; judgement happens serially afterwards by
/// scanning the collected reports. On success, prints a single summary line.
/// On failure, prints only the failing files with their contributing findings.
///
/// The testdata trait-overlap diagnostic is informational (overlaps are not
/// failures), so it is emitted only under `verbose` to keep a passing run to a
/// single line.
pub fn run(format: &OutputFormat, exclude: Option<&str>, verbose: bool) -> Result<String> {
    validation_controls::set_disabled_validators_override(exclude)?;
    let (targets, expectations) = collect_targets()?;

    // Skip the analysis cache so every run reflects the current trait set,
    // and route validation-issue rendering through the chosen output format.
    cleave::cache::set_skip_cache_override(Some(true));
    cleave::validation_controls::set_validation_output_format(Some(match format {
        OutputFormat::Tiny => cleave::validation_controls::ValidationOutputFormat::Tiny,
        OutputFormat::Json | OutputFormat::Jsonl => {
            cleave::validation_controls::ValidationOutputFormat::Json
        }
        OutputFormat::Terminal => cleave::validation_controls::ValidationOutputFormat::Terminal,
    }));
    let options = cleave::AnalysisOptions {
        disable_yara: true,
        disable_radare2: true,
        disable_upx: true,
        ..Default::default()
    };

    // Load the mapper once with full validation enabled. This replaces the
    // separate `validate_traits()` call — validation errors surface here — and
    // every analysis worker below reuses this same Arc, so the trait set is
    // parsed from disk exactly once per run.
    let mapper = Arc::new(CapabilityMapper::try_new_with_load_options(
        CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
        CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
        true,
        false,
    )?);

    let results: Vec<(Target, Result<AnalysisReport>)> = targets
        .into_par_iter()
        .map(|t| {
            let report = cleave::analyze_file_with_mapper(t.path(), &options, &mapper);
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

    let stats = evaluate(results, &expectations.does_nothing)?;

    let traits_ver = cleave::traits_repo::version()
        .map(|v| format!(" (traits: {v})"))
        .unwrap_or_default();
    let traits_dir = cleave::traits_repo::try_resolve()
        .map(|p| format!(" traits_dir={}", p.display()))
        .unwrap_or_default();
    // Report overlapping traits if found
    if !overlap_findings.is_empty() {
        eprintln!(
            "\n{}",
            validate_testdata::format_overlaps(&overlap_findings)
        );
    }

    let report = ValidateOutput {
        ok: true,
        traits_version: traits_ver
            .trim()
            .strip_prefix("(traits: ")
            .and_then(|s| s.strip_suffix(')'))
            .map(str::to_string),
        traits_dir: traits_dir
            .trim()
            .strip_prefix("traits_dir=")
            .map(str::to_string),
        disabled_validators: validation_controls::disabled_validators_by_category(),
        fixtures: FixtureSummary {
            hostile: FixtureCount {
                passed: stats.hostile_passed,
                total: stats.hostile_total,
            },
            benign: FixtureCount {
                passed: stats.benign_passed,
                total: stats.benign_total,
            },
            does_nothing: FixtureCount {
                passed: stats.does_nothing_passed,
                total: stats.does_nothing_total,
            },
            walked_hostile: stats
                .walked_hostile
                .iter()
                .map(|(corpus, count)| WalkedCorpusCount {
                    corpus: (*corpus).to_string(),
                    passed: count.passed,
                    total: count.total,
                })
                .collect(),
        },
    };

    Ok(format_validate_output(&report, format))
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

#[derive(Debug, Serialize)]
struct FixtureSummary {
    hostile: FixtureCount,
    benign: FixtureCount,
    does_nothing: FixtureCount,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    walked_hostile: Vec<WalkedCorpusCount>,
}

#[derive(Debug, Serialize)]
struct FixtureCount {
    passed: usize,
    total: usize,
}

#[derive(Debug, Serialize)]
struct WalkedCorpusCount {
    corpus: String,
    passed: usize,
    total: usize,
}

fn format_validate_output(report: &ValidateOutput, format: &OutputFormat) -> String {
    match format {
        OutputFormat::Json | OutputFormat::Jsonl => {
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

fn format_validate_terminal(report: &ValidateOutput) -> String {
    let mut out = String::new();
    out.push_str(&validation_controls::format_disabled_validators_terminal());
    out.push_str(&format!(
        "validate ok: hostile {}/{}  benign {}/{}  does-nothing {}/{}",
        report.fixtures.hostile.passed,
        report.fixtures.hostile.total,
        report.fixtures.benign.passed,
        report.fixtures.benign.total,
        report.fixtures.does_nothing.passed,
        report.fixtures.does_nothing.total
    ));
    for c in &report.fixtures.walked_hostile {
        out.push_str(&format!("  {} {}/{}", c.corpus, c.passed, c.total));
    }
    out.push('\n');
    out
}

fn format_validate_tiny(report: &ValidateOutput) -> String {
    let mut out = String::new();
    out.push_str(
        "validate ok
",
    );
    for (category, validators) in &report.disabled_validators {
        let labels = validators
            .iter()
            .map(|validator| validator.display_id)
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&format!(
            "disabled {category}={labels}
"
        ));
    }
    out.push_str(&format!(
        "fixtures hostile={}/{} benign={}/{} does-nothing={}/{}",
        report.fixtures.hostile.passed,
        report.fixtures.hostile.total,
        report.fixtures.benign.passed,
        report.fixtures.benign.total,
        report.fixtures.does_nothing.passed,
        report.fixtures.does_nothing.total
    ));
    for c in &report.fixtures.walked_hostile {
        out.push_str(&format!(" {}={}/{}", c.corpus, c.passed, c.total));
    }
    out.push('\n');
    out
}

/// Build the full target list: hostile/benign fixtures + walked does-nothing corpus.
///
/// Returns the loaded [`Expectations`] alongside the targets so the evaluator can
/// consult the does-nothing caps. Expectations live in the traits repo (not the
/// engine), so any build validates the exact fixture set a traits commit defines.
fn collect_targets() -> Result<(Vec<Target>, Expectations)> {
    let mut targets = Vec::new();

    let traits_dir = cleave::traits_repo::try_resolve().map_err(anyhow::Error::msg)?;
    let exp = load_expectations(&traits_dir)?;

    collect_hostile_fixtures(
        &traits_dir.join("testdata").join("hostile"),
        &exp.hostile,
        &mut targets,
    )?;
    collect_benign_fixtures(
        &traits_dir.join("testdata").join("benign"),
        &exp.benign,
        &mut targets,
    )?;

    let dn_dir = traits_dir.join("testdata").join("does-nothing");
    if dn_dir.is_dir() {
        walk_does_nothing(&dn_dir, &mut targets)?;
    }

    for corpus in &exp.walked_hostile {
        let dir = traits_dir.join("testdata").join(&corpus.corpus);
        if dir.is_dir() {
            walk_hostile_corpus(
                &dir,
                &corpus.corpus,
                corpus.min_score,
                corpus.min_hostile,
                &mut targets,
            )?;
        }
    }

    Ok((targets, exp))
}

/// Read fixture expectations from `<traits>/testdata/expectations.toml`.
fn load_expectations(traits_dir: &Path) -> Result<Expectations> {
    let path = traits_dir.join("testdata").join("expectations.toml");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading validation expectations: {}", path.display()))?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Every direct file in `testdata/hostile/` must have an expectation entry.
fn collect_hostile_fixtures(
    dir: &Path,
    expectations: &[HostileExpectation],
    out: &mut Vec<Target>,
) -> Result<()> {
    for expected in expectations {
        out.push(Target::Hostile {
            path: dir.join(&expected.name),
            min_score: expected.min_score,
            min_hostile: expected.min_hostile,
            min_suspicious: expected.min_suspicious,
        });
    }
    validate_fixture_table(
        dir,
        expectations.iter().map(|expected| expected.name.as_str()),
        "hostile",
    )
}

/// Every direct file in `testdata/benign/` must have a cap entry.
fn collect_benign_fixtures(dir: &Path, caps: &[BenignCap], out: &mut Vec<Target>) -> Result<()> {
    for entry in caps {
        out.push(Target::Benign {
            path: dir.join(&entry.name),
            cap: entry.cap,
        });
    }
    validate_fixture_table(dir, caps.iter().map(|entry| entry.name.as_str()), "benign")
}

fn validate_fixture_table<'a>(
    dir: &Path,
    configured: impl Iterator<Item = &'a str>,
    label: &str,
) -> Result<()> {
    if !dir.is_dir() {
        anyhow::bail!("missing {label} fixture directory: {}", dir.display());
    }

    let configured: HashSet<&str> = configured.collect();
    let mut seen = HashSet::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !configured.contains(name.as_ref()) {
            anyhow::bail!(
                "missing validation threshold for {label} fixture: {}",
                entry.path().display()
            );
        }
        seen.insert(name.into_owned());
    }

    for name in configured {
        if !seen.contains(name) {
            anyhow::bail!(
                "configured {label} fixture is missing: {}",
                dir.join(name).display()
            );
        }
    }
    Ok(())
}

/// Walk the does-nothing directory, collecting every analyzable file.
fn walk_does_nothing(dir: &Path, out: &mut Vec<Target>) -> Result<()> {
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            let name = e.file_name().to_string_lossy();
            // Skip VCS metadata and the fixture-generator scripts. The latter are
            // build tooling that legitimately imports pickle/gzip/tar to assemble
            // the artifacts — they are not do-nothing samples and were only ever
            // swept in accidentally by the recursive walk.
            !name.starts_with(".git") && name != "scripts"
        })
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        out.push(Target::DoesNothing {
            path: entry.path().to_path_buf(),
            dir: dir.to_path_buf(),
        });
    }
    Ok(())
}

/// Walk a hostile-floor corpus directory (e.g. `testdata/drop-exec/`).
fn walk_hostile_corpus(
    dir: &Path,
    corpus: &str,
    min_score: u32,
    min_hostile: usize,
    out: &mut Vec<Target>,
) -> Result<()> {
    for entry in walkdir::WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !e.file_name().to_string_lossy().starts_with(".git"))
    {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        out.push(Target::WalkedHostile {
            path: entry.path().to_path_buf(),
            corpus: corpus.to_string(),
            min_score,
            min_hostile,
        });
    }
    Ok(())
}

/// Walk the collected analysis results, emitting failures inline and tallying totals.
struct ValidationStats {
    hostile_passed: usize,
    hostile_total: usize,
    benign_passed: usize,
    benign_total: usize,
    does_nothing_passed: usize,
    does_nothing_total: usize,
    walked_hostile: std::collections::BTreeMap<String, WalkedCorpusStats>,
}

#[derive(Default)]
struct WalkedCorpusStats {
    passed: usize,
    total: usize,
}

/// Walk the collected analysis results, emitting failures inline and tallying totals.
fn evaluate(
    results: Vec<(Target, Result<AnalysisReport>)>,
    does_nothing: &DoesNothing,
) -> Result<ValidationStats> {
    let disable_score_caps = validation_controls::is_validator_disabled("score-caps");

    let mut stats = ValidationStats {
        hostile_passed: 0,
        hostile_total: 0,
        benign_passed: 0,
        benign_total: 0,
        does_nothing_passed: 0,
        does_nothing_total: 0,
        walked_hostile: std::collections::BTreeMap::new(),
    };
    let mut failed = 0usize;

    for (target, result) in results {
        let mut report = match result {
            Ok(r) => r,
            Err(e) => {
                eprintln!("❌ {}: analysis failed: {e:#}", target.path().display());
                failed += 1;
                match target {
                    Target::Hostile { .. } => stats.hostile_total += 1,
                    Target::Benign { .. } => stats.benign_total += 1,
                    Target::DoesNothing { .. } => stats.does_nothing_total += 1,
                    Target::WalkedHostile { corpus, .. } => {
                        stats.walked_hostile.entry(corpus).or_default().total += 1;
                    }
                }
                continue;
            }
        };
        report.finalize();

        match target {
            Target::Hostile {
                path,
                min_score,
                min_hostile,
                min_suspicious,
            } => {
                stats.hostile_total += 1;
                if judge_hostile(&path, min_score, min_hostile, min_suspicious, &report) {
                    stats.hostile_passed += 1;
                } else {
                    failed += 1;
                }
            }
            Target::Benign { path, cap } => {
                stats.benign_total += 1;
                if disable_score_caps || judge_benign(&path, cap, &report) {
                    stats.benign_passed += 1;
                } else {
                    failed += 1;
                }
            }
            Target::DoesNothing { dir, .. } => {
                for file in &report.files {
                    stats.does_nothing_total += 1;
                    // Boring-by-definition invariant (always enforced,
                    // independent of the bypassable, version-sensitive score
                    // caps): a do-nothing benign binary must carry
                    //   1. NO intent — zero objectives/ or well-known/ findings
                    //      at ANY criticality (e.g. a crypto/rsa import read as
                    //      ransomware, or a log-rotation helper read as
                    //      mass-delete), and
                    //   2. nothing NOTABLE — these samples are the opposite of
                    //      notable, so every finding must be component/baseline;
                    //      a notable/suspicious/hostile trait firing here is a
                    //      false positive.
                    // These fixtures exist precisely to keep both classes
                    // regression-free.
                    let disallowed: Vec<String> = file
                        .findings
                        .iter()
                        .filter(|f| {
                            // Intent and malware-family findings are never
                            // acceptable on a do-nothing fixture, at any crit.
                            if f.id.starts_with("objectives/") || f.id.starts_with("well-known/") {
                                return true;
                            }
                            // Inherent code-signing trust state is a legitimate
                            // file property, not a behavior. Ad-hoc signing in
                            // particular is unusual-but-real and notable by
                            // design (and is the default for every `go build`
                            // macOS binary), so a notable metadata/signed/*
                            // finding is not a do-nothing false positive.
                            // Higher tiers (suspicious/hostile) are still caught.
                            if f.id.starts_with("metadata/signed/")
                                && f.crit == Criticality::Notable
                            {
                                return false;
                            }
                            matches!(
                                f.crit,
                                Criticality::Notable
                                    | Criticality::Suspicious
                                    | Criticality::Hostile
                            )
                        })
                        .map(|f| format!("{} ({:?})", f.id, f.crit))
                        .collect();
                    if !disallowed.is_empty() {
                        eprintln!(
                            "❌ {}: {} disallowed finding(s) on a does-nothing fixture (intent or >= notable): {disallowed:?}",
                            file.path,
                            disallowed.len(),
                        );
                        print_contributing_findings(file, "     ");
                        failed += 1;
                        continue;
                    }
                    if disable_score_caps {
                        stats.does_nothing_passed += 1;
                        continue;
                    }
                    let cap = does_nothing_cap(&file.path, &dir, does_nothing);
                    if file.score > cap {
                        eprintln!("❌ {}: score {} > cap {cap}", file.path, file.score);
                        print_contributing_findings(file, "     ");
                        failed += 1;
                    } else {
                        stats.does_nothing_passed += 1;
                    }
                }
            }
            Target::WalkedHostile {
                path,
                corpus,
                min_score,
                min_hostile,
            } => {
                let entry = stats.walked_hostile.entry(corpus.clone()).or_default();
                entry.total += 1;
                if judge_walked_hostile(&path, &corpus, min_score, min_hostile, &report) {
                    entry.passed += 1;
                } else {
                    failed += 1;
                }
            }
        }
    }

    if failed > 0 {
        anyhow::bail!("{failed} validation check(s) failed");
    }
    Ok(stats)
}

/// Judge a walked-hostile sample. Returns `true` if it passes the `min_hostile` floor.
fn judge_walked_hostile(
    path: &Path,
    corpus: &str,
    min_score: u32,
    min_hostile: usize,
    report: &AnalysisReport,
) -> bool {
    let Some(file) = report.files.first() else {
        eprintln!("❌ {}: analysis produced no files", path.display());
        return false;
    };
    let hostile = count_findings(file, Criticality::Hostile);
    if file.score >= min_score && hostile >= min_hostile {
        return true;
    }
    if file.score < min_score {
        eprintln!(
            "❌ {} [{corpus}]: score {} < minimum {min_score}",
            path.display(),
            file.score
        );
    }
    if hostile < min_hostile {
        eprintln!(
            "❌ {} [{corpus}]: hostile findings {hostile} < minimum {min_hostile}",
            path.display()
        );
    }
    print_contributing_findings(file, "     ");
    false
}

/// Judge a known-hostile fixture root file. Returns `true` if it passes.
fn judge_hostile(
    path: &Path,
    min_score: u32,
    min_hostile: usize,
    min_suspicious: usize,
    report: &AnalysisReport,
) -> bool {
    let Some(file) = report.files.first() else {
        eprintln!("❌ {}: analysis produced no files", path.display());
        return false;
    };
    let display = path.display();
    let hostile = count_findings(file, Criticality::Hostile);
    let suspicious = count_findings(file, Criticality::Suspicious);

    let score_too_low = file.score < min_score;
    let hostile_too_low = hostile < min_hostile;
    let suspicious_too_low = suspicious < min_suspicious;
    if !score_too_low && !hostile_too_low && !suspicious_too_low {
        return true;
    }

    if score_too_low {
        eprintln!("❌ {display}: score {} < minimum {min_score}", file.score);
    }
    if hostile_too_low {
        eprintln!("❌ {display}: hostile findings {hostile} < minimum {min_hostile}");
    }
    if suspicious_too_low {
        eprintln!("❌ {display}: suspicious findings {suspicious} < minimum {min_suspicious}");
    }
    print_contributing_findings(file, "     ");
    false
}

/// Judge a known-benign fixture root file. Returns `true` if it passes.
fn judge_benign(path: &Path, cap: u32, report: &AnalysisReport) -> bool {
    let Some(file) = report.files.first() else {
        eprintln!("❌ {}: analysis produced no files", path.display());
        return false;
    };
    let misleading = misleading_benign_findings(report);
    if file.score <= cap
        && file.score < Criticality::Suspicious.score_weight()
        && misleading.is_empty()
    {
        return true;
    }

    if file.score > cap {
        eprintln!("❌ {}: score {} > cap {cap}", path.display(), file.score);
    }
    if file.score >= Criticality::Suspicious.score_weight() {
        eprintln!(
            "❌ {}: score {} >= one suspicious trait ({})",
            path.display(),
            file.score,
            Criticality::Suspicious.score_weight()
        );
    }
    for (file_path, finding) in misleading {
        eprintln!(
            "❌ {file_path}: suspicious/hostile intent or campaign trait on benign fixture: {} ({:?})",
            finding.id, finding.crit
        );
    }
    print_contributing_findings(file, "     ");
    false
}

fn count_findings(file: &FileAnalysis, crit: Criticality) -> usize {
    file.findings.iter().filter(|f| f.crit == crit).count()
}

fn misleading_benign_findings(
    report: &AnalysisReport,
) -> Vec<(&str, &cleave::types::traits_findings::Finding)> {
    report
        .files
        .iter()
        .flat_map(|file| {
            file.findings
                .iter()
                .filter(|finding| {
                    matches!(finding.crit, Criticality::Hostile | Criticality::Suspicious)
                        && (finding.id.starts_with("objectives/")
                            || finding.id.starts_with("well-known/"))
                })
                .map(move |finding| (file.path.as_str(), finding))
        })
        .collect()
}

/// Fixture expectations, loaded from `<traits>/testdata/expectations.toml`.
///
/// These travel with the traits (not the engine) so any build validates the
/// exact fixture set + thresholds a given traits commit defines — the basis for
/// meaningful cross-version validation.
#[derive(Debug, Deserialize)]
struct Expectations {
    /// Per-file floors for direct files in `testdata/hostile/`.
    hostile: Vec<HostileExpectation>,
    /// Per-file score ceilings for direct files in `testdata/benign/`.
    benign: Vec<BenignCap>,
    /// Corpora whose every file must hit `min_hostile` hostile findings — the
    /// inverse of does-nothing: floor scores from below rather than cap them.
    walked_hostile: Vec<WalkedCorpus>,
    /// Score caps for `testdata/does-nothing/` samples.
    does_nothing: DoesNothing,
}

#[derive(Debug, Deserialize)]
struct HostileExpectation {
    name: String,
    min_score: u32,
    min_hostile: usize,
    min_suspicious: usize,
}

#[derive(Debug, Deserialize)]
struct BenignCap {
    name: String,
    cap: u32,
}

#[derive(Debug, Deserialize)]
struct WalkedCorpus {
    corpus: String,
    #[serde(default)]
    min_score: u32,
    min_hostile: usize,
}

#[derive(Debug, Deserialize)]
struct DoesNothing {
    /// Cap applied to any does-nothing sample without a specific override.
    default_cap: u32,
    /// Per-file caps, keyed by path relative to the does-nothing dir (may carry
    /// an archive suffix, e.g. `"sample.ipa!!Payload/..."`).
    #[serde(default)]
    overrides: Vec<DoesNothingCap>,
}

#[derive(Debug, Deserialize)]
struct DoesNothingCap {
    path: String,
    cap: u32,
}

/// Look up the cap for a file whose `path` may be either absolute (root file)
/// or include an archive suffix (e.g. `"...sample.ipa!!Payload/..."`).
fn does_nothing_cap(file_path: &str, dir: &Path, does_nothing: &DoesNothing) -> u32 {
    let dir_str = dir.to_string_lossy();
    let rel = file_path
        .strip_prefix(dir_str.as_ref())
        .and_then(|s| s.strip_prefix('/'))
        .unwrap_or(file_path);
    does_nothing
        .overrides
        .iter()
        .find_map(|o| (o.path == rel).then_some(o.cap))
        .unwrap_or(does_nothing.default_cap)
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
                                    trait_id: finding.id.clone(),
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
