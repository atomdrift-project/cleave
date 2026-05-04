//! Trait validation command.
//!
//! Runs the full suite of trait definition validation checks and reports any
//! errors or quality issues found. Exits with a non-zero status if validation fails.

use anyhow::Result;
use cleave::{AnalysisReport, CapabilityMapper, Criticality, FileAnalysis};
use rayon::prelude::*;
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
pub fn run() -> Result<()> {
    let targets = collect_targets()?;

    // Skip the analysis cache so every run reflects the current trait set.
    std::env::set_var("CLEAVE_SKIP_CACHE", "1");
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

    let stats = evaluate(results)?;

    let traits_ver = cleave::traits_repo::version()
        .map(|v| format!(" (traits: {v})"))
        .unwrap_or_default();
    let traits_dir = cleave::traits_repo::try_resolve()
        .map(|p| format!(" traits_dir={}", p.display()))
        .unwrap_or_default();
    eprintln!(
        "✅ validate{traits_ver}{traits_dir}: traits + hostile ({}/{}) + benign ({}/{}) + does-nothing ({}/{})",
        stats.hostile_passed,
        stats.hostile_total,
        stats.benign_passed,
        stats.benign_total,
        stats.does_nothing_passed,
        stats.does_nothing_total
    );
    Ok(())
}

/// Build the full target list: hostile/benign fixtures + walked does-nothing corpus.
fn collect_targets() -> Result<Vec<Target>> {
    let mut targets = Vec::new();

    let traits_dir = cleave::traits_repo::try_resolve().map_err(anyhow::Error::msg)?;

    collect_hostile_fixtures(&traits_dir.join("testdata").join("hostile"), &mut targets)?;
    collect_benign_fixtures(&traits_dir.join("testdata").join("benign"), &mut targets)?;

    let dn_dir = traits_dir.join("testdata").join("does-nothing");
    if dn_dir.is_dir() {
        walk_does_nothing(&dn_dir, &mut targets)?;
    }

    Ok(targets)
}

/// Every direct file in `testdata/hostile/` must have a hardcoded threshold.
fn collect_hostile_fixtures(dir: &Path, out: &mut Vec<Target>) -> Result<()> {
    const MIN_HOSTILE_FINDINGS: usize = 1;
    const MIN_SUSPICIOUS_FINDINGS: usize = 2;

    for (name, min_score) in HOSTILE_MIN_SCORES {
        out.push(Target::Hostile {
            path: dir.join(name),
            min_score: *min_score,
            min_hostile: MIN_HOSTILE_FINDINGS,
            min_suspicious: MIN_SUSPICIOUS_FINDINGS,
        });
    }
    validate_fixture_table(
        dir,
        HOSTILE_MIN_SCORES.iter().map(|(name, _)| *name),
        "hostile",
    )
}

/// Every direct file in `testdata/benign/` must have a hardcoded cap.
fn collect_benign_fixtures(dir: &Path, out: &mut Vec<Target>) -> Result<()> {
    for (name, cap) in BENIGN_SCORE_CAPS {
        out.push(Target::Benign {
            path: dir.join(name),
            cap: *cap,
        });
    }
    validate_fixture_table(
        dir,
        BENIGN_SCORE_CAPS.iter().map(|(name, _)| *name),
        "benign",
    )
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
        .filter_entry(|e| !e.file_name().to_string_lossy().starts_with(".git"))
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

/// Walk the collected analysis results, emitting failures inline and tallying totals.
struct ValidationStats {
    hostile_passed: usize,
    hostile_total: usize,
    benign_passed: usize,
    benign_total: usize,
    does_nothing_passed: usize,
    does_nothing_total: usize,
}

/// Walk the collected analysis results, emitting failures inline and tallying totals.
fn evaluate(results: Vec<(Target, Result<AnalysisReport>)>) -> Result<ValidationStats> {
    let mut stats = ValidationStats {
        hostile_passed: 0,
        hostile_total: 0,
        benign_passed: 0,
        benign_total: 0,
        does_nothing_passed: 0,
        does_nothing_total: 0,
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
                if judge_benign(&path, cap, &report) {
                    stats.benign_passed += 1;
                } else {
                    failed += 1;
                }
            }
            Target::DoesNothing { dir, .. } => {
                for file in &report.files {
                    stats.does_nothing_total += 1;
                    let cap = does_nothing_cap(&file.path, &dir);
                    if file.score > cap {
                        eprintln!("❌ {}: score {} > cap {cap}", file.path, file.score);
                        print_contributing_findings(file, "     ");
                        failed += 1;
                    } else {
                        stats.does_nothing_passed += 1;
                    }
                }
            }
        }
    }

    if failed > 0 {
        anyhow::bail!("{failed} validation check(s) failed");
    }
    Ok(stats)
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
            "❌ {file_path}: intent/campaign trait on benign fixture: {} ({:?})",
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
                    finding.id.starts_with("objectives/") || finding.id.starts_with("well-known/")
                })
                .map(move |finding| (file.path.as_str(), finding))
        })
        .collect()
}

/// Per-file minimum score for direct files in `testdata/hostile/`.
///
/// Finding-count floors are applied uniformly in [`collect_hostile_fixtures`]:
/// each hostile fixture must produce at least one Hostile and two Suspicious
/// findings. Scores are the current observed root-file score floors for these
/// stable fixtures, hardcoded so drift is intentional and reviewable.
const HOSTILE_MIN_SCORES: &[(&str, u32)] = &[
    ("LInux_Perl_ClickFix.pl.xz", 122),
    ("Spisok_na_Zakupivlyu_INIT.xlsx.lnk.xz", 156),
    ("donutloader.bat.xz", 336),
    ("dropper.sh.xz", 39),
    ("index.applescript.xz", 554),
    ("memdump.py.xz", 73),
    ("pondrat.xz", 106),
    ("rand-user-agent.js.xz", 150),
    ("reverse-shell.cpp.xz", 121),
    ("shady.php.xz", 1),
    ("terminal.go.xz", 230),
];

/// Per-file score caps for direct files in `testdata/benign/`.
///
/// Each cap is roughly current observed score + 10%, but never reaches the
/// score of one full-confidence Suspicious finding (40).
const BENIGN_SCORE_CAPS: &[(&str, u32)] = &[
    ("IddController.c.xz", 3),
    ("find_git_conflicts.sh.xz", 3),
    ("liblzma.so.5.4.5.xz", 5),
    ("ls.macOS.xz", 9),
    ("rand-user-agent.js.xz", 39),
    ("run.bat.xz", 19),
    ("test_cli.py.xz", 3),
];

/// Default per-file score cap for `testdata/does-nothing/` samples.
const DOES_NOTHING_DEFAULT_CAP: u32 = 1;

/// Per-file score caps for does-nothing samples that can't hit the default cap.
///
/// Each entry is `(relative_path_from_does_nothing_dir, cap)`. `cap` is set to
/// `current_observed_score + 1` — a regression fires if any trait change pushes
/// the score past this ceiling. Update when trait improvements legitimately
/// reduce a score, or when a new sample is added to the corpus.
const DOES_NOTHING_CAPS: &[(&str, u32)] = &[
    ("artifacts/sample.apk", 5),
    ("artifacts/sample.apk!!lib/x86/libsample.so", 5),
    ("artifacts/sample.ipa", 8),
    ("artifacts/sample.ipa!!Payload/Sample.app/Sample", 8),
    ("artifacts/sample.mk", 1),
    ("artifacts/sample.zsh", 3),
    ("main.go", 3),
    ("out/does-nothing-darwin-arm64.xz", 8),
    (
        "out/does-nothing-darwin-arm64.xz!!does-nothing-darwin-arm64",
        8,
    ),
    ("out/does-nothing-linux-386.xz", 5),
    ("out/does-nothing-linux-386.xz!!does-nothing-linux-386", 5),
    ("out/does-nothing-openbsd-arm64.xz", 7),
    (
        "out/does-nothing-openbsd-arm64.xz!!does-nothing-openbsd-arm64",
        7,
    ),
    ("out/does-nothing-windows-amd64.exe.xz", 9),
    (
        "out/does-nothing-windows-amd64.exe.xz!!does-nothing-windows-amd64.exe",
        9,
    ),
    ("scripts/make_crate.py", 3),
    ("scripts/make_crx.py", 3),
    ("scripts/make_gem.py", 3),
    ("scripts/make_jpg.py", 4),
    ("scripts/make_pdf.py", 3),
    ("scripts/make_pickle.py", 3),
    ("scripts/make_png.py", 3),
    ("scripts/make_xlsx.py", 3),
    // Build scripts under does-nothing/scripts/: these legitimately
    // trigger `py-tiny-comment-ratio-small-file` (no docstrings) and
    // `py-many-zero-param-helpers` (each is a no-arg artifact builder).
    // Both atoms are weak `notable` signals; the hostile composite that
    // combines them requires additional obfuscation primitives that
    // these scripts don't carry, so bumping the cap to 3 is safe.
    ("scripts/make_zip_bundle.py", 3),
    ("scripts/make_pptx.py", 3),
    ("scripts/make_deb.py", 3),
    // Single-line "imports X / python code embedded in string" samples
    // for various languages — same pair of new metric atoms as above.
    ("artifacts/sample.swift", 3),
    ("artifacts/sample.scala", 3),
    ("artifacts/sample.java", 3),
    // Empty PyPI metadata-only packages — `pkginfo-no-author-email` +
    // `pkginfo-no-homepage` (or similar pair) total to 2; cap at 3 to
    // leave one slot of headroom.
    ("artifacts/sample.egg", 3),
    ("artifacts/sample.whl", 3),
];

/// Look up the cap for a file whose `path` may be either absolute (root file)
/// or include an archive suffix (e.g. `"...sample.ipa!!Payload/..."`).
fn does_nothing_cap(file_path: &str, dir: &Path) -> u32 {
    let dir_str = dir.to_string_lossy();
    let rel = file_path
        .strip_prefix(dir_str.as_ref())
        .and_then(|s| s.strip_prefix('/'))
        .unwrap_or(file_path);
    DOES_NOTHING_CAPS
        .iter()
        .find_map(|(p, cap)| (*p == rel).then_some(*cap))
        .unwrap_or(DOES_NOTHING_DEFAULT_CAP)
}
