//! Trait validation command.
//!
//! Runs the full suite of trait definition validation checks and reports any
//! errors or quality issues found. Exits with a non-zero status if validation fails.

use crate::cli::OutputFormat;
use anyhow::Result;
use cleave::{AnalysisReport, CapabilityMapper, Criticality, FileAnalysis, validation_controls};
use rayon::prelude::*;
use serde::Serialize;
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
    /// Every file under the corpus directory must surface at least `min_hostile`
    /// hostile findings — like the inverse of the does-nothing walk.
    WalkedHostile {
        path: PathBuf,
        corpus: &'static str,
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
pub fn run(format: &OutputFormat, exclude: Option<&str>) -> Result<String> {
    validation_controls::set_disabled_validators_override(exclude)?;
    let targets = collect_targets()?;

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

    let stats = evaluate(results)?;

    let traits_ver = cleave::traits_repo::version()
        .map(|v| format!(" (traits: {v})"))
        .unwrap_or_default();
    let traits_dir = cleave::traits_repo::try_resolve()
        .map(|p| format!(" traits_dir={}", p.display()))
        .unwrap_or_default();
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
fn collect_targets() -> Result<Vec<Target>> {
    let mut targets = Vec::new();

    let traits_dir = cleave::traits_repo::try_resolve().map_err(anyhow::Error::msg)?;

    collect_hostile_fixtures(&traits_dir.join("testdata").join("hostile"), &mut targets)?;
    collect_benign_fixtures(&traits_dir.join("testdata").join("benign"), &mut targets)?;

    let dn_dir = traits_dir.join("testdata").join("does-nothing");
    if dn_dir.is_dir() {
        walk_does_nothing(&dn_dir, &mut targets)?;
    }

    for (corpus, min_hostile) in WALKED_HOSTILE_CORPORA {
        let dir = traits_dir.join("testdata").join(corpus);
        if dir.is_dir() {
            walk_hostile_corpus(&dir, corpus, *min_hostile, &mut targets)?;
        }
    }

    Ok(targets)
}

/// Corpora whose every file must hit `min_hostile` hostile findings.
///
/// Each corpus is the inverse of does-nothing: instead of capping scores from
/// above we floor them from below. Use this for idiom-per-language attack
/// samples (one drop-exec implant per language, one reverse-shell per
/// language) — regressions show up as a single file dropping below the floor.
const WALKED_HOSTILE_CORPORA: &[(&str, usize)] = &[("drop-exec", 3), ("reverse-shell", 3)];

/// Every direct file in `testdata/hostile/` must have a hardcoded threshold.
fn collect_hostile_fixtures(dir: &Path, out: &mut Vec<Target>) -> Result<()> {
    for expected in HOSTILE_EXPECTATIONS {
        out.push(Target::Hostile {
            path: dir.join(expected.name),
            min_score: expected.min_score,
            min_hostile: expected.min_hostile,
            min_suspicious: expected.min_suspicious,
        });
    }
    validate_fixture_table(
        dir,
        HOSTILE_EXPECTATIONS.iter().map(|expected| expected.name),
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

/// Walk a hostile-floor corpus directory (e.g. `testdata/drop-exec/`).
fn walk_hostile_corpus(
    dir: &Path,
    corpus: &'static str,
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
            corpus,
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
    walked_hostile: std::collections::BTreeMap<&'static str, WalkedCorpusStats>,
}

#[derive(Default)]
struct WalkedCorpusStats {
    passed: usize,
    total: usize,
}

/// Walk the collected analysis results, emitting failures inline and tallying totals.
fn evaluate(results: Vec<(Target, Result<AnalysisReport>)>) -> Result<ValidationStats> {
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
                    if disable_score_caps {
                        stats.does_nothing_passed += 1;
                        continue;
                    }
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
            Target::WalkedHostile {
                path,
                corpus,
                min_hostile,
            } => {
                let entry = stats.walked_hostile.entry(corpus).or_default();
                entry.total += 1;
                if judge_walked_hostile(&path, corpus, min_hostile, &report) {
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
    min_hostile: usize,
    report: &AnalysisReport,
) -> bool {
    let Some(file) = report.files.first() else {
        eprintln!("❌ {}: analysis produced no files", path.display());
        return false;
    };
    let hostile = count_findings(file, Criticality::Hostile);
    if hostile >= min_hostile {
        return true;
    }
    eprintln!(
        "❌ {} [{corpus}]: hostile findings {hostile} < minimum {min_hostile}",
        path.display()
    );
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

struct HostileExpectation {
    name: &'static str,
    min_score: u32,
    min_hostile: usize,
    min_suspicious: usize,
}

/// Per-file minimums for direct files in `testdata/hostile/`.
///
/// Scores are the current observed root-file score floors for these stable
/// fixtures. Finding-count floors are also explicit per fixture so samples that
/// need a higher bar, such as the fake meeting-app dropper, stay reviewable.
const HOSTILE_EXPECTATIONS: &[HostileExpectation] = &[
    HostileExpectation {
        name: "LInux_Perl_ClickFix.pl.xz",
        min_score: 122,
        min_hostile: 2,
        min_suspicious: 2,
    },
    HostileExpectation {
        name: "Spisok_na_Zakupivlyu_INIT.xlsx.lnk.xz",
        min_score: 156,
        min_hostile: 2,
        min_suspicious: 2,
    },
    HostileExpectation {
        name: "donutloader.bat.xz",
        min_score: 415,
        min_hostile: 2,
        min_suspicious: 2,
    },
    HostileExpectation {
        name: "dropper.sh.xz",
        min_score: 120,
        min_hostile: 2,
        min_suspicious: 2,
    },
    HostileExpectation {
        name: "fake-zoom.macho.xz",
        min_score: 305,
        min_hostile: 2,
        min_suspicious: 4,
    },
    HostileExpectation {
        name: "index.applescript.xz",
        min_score: 554,
        min_hostile: 2,
        min_suspicious: 2,
    },
    HostileExpectation {
        name: "memdump.py.xz",
        min_score: 153,
        min_hostile: 2,
        min_suspicious: 2,
    },
    HostileExpectation {
        name: "package.json.xz",
        min_score: 193,
        min_hostile: 2,
        min_suspicious: 2,
    },
    HostileExpectation {
        name: "pondrat.elf.xz",
        min_score: 296,
        min_hostile: 2,
        min_suspicious: 2,
    },
    HostileExpectation {
        name: "rand-user-agent.js.xz",
        min_score: 309,
        min_hostile: 2,
        min_suspicious: 2,
    },
    HostileExpectation {
        name: "reverse-shell.cpp.xz",
        min_score: 121,
        min_hostile: 2,
        min_suspicious: 2,
    },
    HostileExpectation {
        name: "shady.php.xz",
        min_score: 116,
        min_hostile: 2,
        min_suspicious: 2,
    },
    HostileExpectation {
        name: "terminal.go.xz",
        min_score: 230,
        min_hostile: 2,
        min_suspicious: 2,
    },
    // UTF-16LE obfuscated VBScript loader: Array() lookup-table + ChrW
    // reassembly feeding ExecuteGlobal. Doubles as the regression guard for
    // UTF-16 text normalization — pre-fix this produced zero findings.
    HostileExpectation {
        name: "utf16-vbs-loader.vbs.xz",
        min_score: 143,
        min_hostile: 3,
        min_suspicious: 2,
    },
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
    ("package.json.xz", 5),
    ("php-wundii-flowcrafter.tar.xz", 14),
    // pyaigis is the canonical "defensive scanner whose pattern database
    // looks like its targets" test case. After the scanner-context audit
    // landed it scores 35; cap is 38 (current + 3 headroom). A regression
    // that takes pyaigis above 38 means a credential/jailbreak/exploit
    // trait stopped honoring `unless: llm-scanner-context`.
    ("pyaigis-top10.tar.xz", 38),
    ("rand-user-agent.js.xz", 3),
    ("run.bat.xz", 2),
];

/// Default per-file score cap for `testdata/does-nothing/` samples.
const DOES_NOTHING_DEFAULT_CAP: u32 = 1;

/// Per-file score caps for does-nothing samples that can't hit the default cap.
///
/// Each entry is `(relative_path_from_does_nothing_dir, cap)`. `cap` is set to
/// the current observed score — a regression fires if any trait change pushes
/// the score past this ceiling. Update when trait improvements legitimately
/// reduce a score, or when a new sample is added to the corpus.
const DOES_NOTHING_CAPS: &[(&str, u32)] = &[
    ("artifacts/sample.apk", 7),
    ("artifacts/sample.apk!!lib/x86/libsample.so", 7),
    ("artifacts/sample.ipa", 9),
    ("artifacts/sample.ipa!!Payload/Sample.app/Sample", 9),
    ("artifacts/sample.mk", 1),
    // Shell/perl scripts: their shebang traits fire at notable since
    // a shebang declares interpreter execution per TAXONOMY.md. The
    // does-nothing samples are otherwise empty.
    ("artifacts/sample.bash", 2),
    ("artifacts/sample.sh", 2),
    ("artifacts/sample.pl", 2),
    ("artifacts/sample.zsh", 3),
    ("main.go", 3),
    ("out/does-nothing-darwin-arm64.xz", 9),
    (
        "out/does-nothing-darwin-arm64.xz!!does-nothing-darwin-arm64",
        9,
    ),
    ("out/does-nothing-linux-386.xz", 7),
    ("out/does-nothing-linux-386.xz!!does-nothing-linux-386", 7),
    ("out/does-nothing-openbsd-arm64.xz", 8),
    (
        "out/does-nothing-openbsd-arm64.xz!!does-nothing-openbsd-arm64",
        8,
    ),
    ("out/does-nothing-windows-amd64.exe.xz", 9),
    (
        "out/does-nothing-windows-amd64.exe.xz!!does-nothing-windows-amd64.exe",
        9,
    ),
    ("scripts/make_crate.py", 3),
    ("scripts/make_crx.py", 3),
    ("scripts/make_docx.py", 2),
    ("scripts/make_gem.py", 3),
    ("scripts/make_jpg.py", 4),
    ("scripts/make_lnk.py", 2),
    ("scripts/make_odf.py", 2),
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
