//! Trait validation command.
//!
//! Runs the full suite of trait definition validation checks and reports any
//! errors or quality issues found. Exits with a non-zero status if validation fails.

use anyhow::Result;
use cleave::{AnalysisReport, CapabilityMapper, Criticality, FileAnalysis};
use rayon::prelude::*;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A single file to analyze during validation and how to judge its score.
enum Target {
    /// Platform utility whose score must fall within `[min, max]`.
    /// Also rejects any `objectives/*` or `well-known/*` finding.
    GroundTruth { path: PathBuf, min: u32, max: u32 },
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
            Self::GroundTruth { path, .. } | Self::DoesNothing { path, .. } => path,
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

/// Run full trait validation: trait defs + ground-truth + does-nothing checks.
///
/// All sample analyses (system utilities and the does-nothing corpus) run in a
/// single rayon parallel pool; judgement happens serially afterwards by
/// scanning the collected reports. On success, prints a single summary line.
/// On failure, prints only the failing files with their contributing findings.
pub fn run() -> Result<()> {
    let targets = collect_targets()?;

    // Skip the analysis cache so every run reflects the current trait set.
    std::env::set_var("CLEAVE_SKIP_CACHE", "1");
    let options = cleave::AnalysisOptions {
        disable_yara: true,
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

    let (gt_stats, dn_stats) = evaluate(results)?;

    let traits_ver = cleave::traits_repo::version()
        .map(|v| format!(" (traits: {v})"))
        .unwrap_or_default();
    eprintln!(
        "✅ validate{traits_ver}: traits + ground-truth ({}/{}) + does-nothing ({}/{})",
        gt_stats.0, gt_stats.1, dn_stats.0, dn_stats.1
    );
    Ok(())
}

/// Build the full target list: ground-truth binaries + walked does-nothing corpus.
fn collect_targets() -> Result<Vec<Target>> {
    let mut targets = Vec::new();

    // Ground-truth binaries: expected score ranges reflect each tool's capability surface.
    // /bin/ls — xattr/stat/symlink/group-lookup/ACL.
    // /bin/cp — chmod/chown/fts/mknod/xattr/ACL.
    // /bin/sh — fork/setsid/exec/signal/pty.
    // /usr/bin/curl — HTTP/SOCKS/OAuth/TLS/crypto.
    for (path, min, max) in [
        ("/bin/ls", 1, 8),
        ("/bin/cp", 1, 10),
        ("/bin/sh", 1, 8),
        ("/usr/bin/curl", 5, 12),
    ] {
        let p = PathBuf::from(path);
        if p.exists() {
            targets.push(Target::GroundTruth { path: p, min, max });
        }
    }

    if let Ok(traits_dir) = cleave::traits_repo::try_resolve() {
        let dn_dir = traits_dir.join("testdata").join("does-nothing");
        if dn_dir.is_dir() {
            walk_does_nothing(&dn_dir, &mut targets)?;
        }
    }

    Ok(targets)
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
fn evaluate(
    results: Vec<(Target, Result<AnalysisReport>)>,
) -> Result<((usize, usize), (usize, usize))> {
    let mut gt_passed = 0;
    let mut gt_total = 0;
    let mut dn_passed = 0;
    let mut dn_total = 0;
    let mut failed = 0usize;

    for (target, result) in results {
        let mut report = match result {
            Ok(r) => r,
            Err(e) => {
                eprintln!("❌ {}: analysis failed: {e:#}", target.path().display());
                failed += 1;
                match target {
                    Target::GroundTruth { .. } => gt_total += 1,
                    Target::DoesNothing { .. } => dn_total += 1,
                }
                continue;
            }
        };
        report.finalize();

        match target {
            Target::GroundTruth { path, min, max } => {
                gt_total += 1;
                if judge_ground_truth(&path, min, max, &report) {
                    gt_passed += 1;
                } else {
                    failed += 1;
                }
            }
            Target::DoesNothing { dir, .. } => {
                for file in &report.files {
                    dn_total += 1;
                    let cap = does_nothing_cap(&file.path, &dir);
                    if file.score > cap {
                        eprintln!("❌ {}: score {} > cap {cap}", file.path, file.score);
                        print_contributing_findings(file, "     ");
                        failed += 1;
                    } else {
                        dn_passed += 1;
                    }
                }
            }
        }
    }

    if failed > 0 {
        anyhow::bail!("{failed} validation check(s) failed");
    }
    Ok(((gt_passed, gt_total), (dn_passed, dn_total)))
}

/// Judge a ground-truth binary. Returns `true` if it passes.
fn judge_ground_truth(path: &Path, min: u32, max: u32, report: &AnalysisReport) -> bool {
    let Some(file) = report.files.first() else {
        return true;
    };
    let score = file.score;
    let display = path.display();

    // Flag objectives/* or well-known/* traits firing on a benign platform utility.
    let misplaced: Vec<_> = file
        .findings
        .iter()
        .filter(|f| f.id.starts_with("objectives/") || f.id.starts_with("well-known/"))
        .collect();

    let out_of_range = score < min || score > max;
    if !out_of_range && misplaced.is_empty() {
        return true;
    }

    if out_of_range {
        eprintln!("❌ {display}: score {score} not in [{min},{max}]");
        print_contributing_findings(file, "     ");
    }
    for f in &misplaced {
        eprintln!(
            "❌ {display}: intent trait on benign binary: {} ({:?})",
            f.id, f.crit
        );
    }
    false
}

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
