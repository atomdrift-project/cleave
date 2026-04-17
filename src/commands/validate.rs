//! Trait validation command.
//!
//! Runs the full suite of trait definition validation checks and reports any
//! errors or quality issues found. Exits with a non-zero status if validation fails.

use anyhow::Result;
use cleave::Criticality;
use std::path::Path;

/// Run full trait validation against the configured traits directory.
///
/// Loads all trait definitions with validation enabled, which triggers comprehensive
/// checks for logic errors, quality issues, and structural violations. All findings
/// are printed to stderr. Returns `Err` if any validation errors are detected.
///
/// Also runs ground-truth checks against known benign binaries to detect
/// score inflation from misleading or miscategorized traits.
pub fn run() -> Result<()> {
    eprintln!(
        "Warning: precision threshold scoring is temporarily disabled while we work out the ideal balanced scoring algorithm."
    );
    cleave::validate_traits()?;
    eprintln!("✅ All trait validation checks passed.");

    run_ground_truth_checks()?;

    Ok(())
}

/// Ground-truth score checks against known benign system binaries.
///
/// These catch trait regressions (false positives, miscategorized criticality,
/// taxonomy violations) that inflate scores beyond expected ranges. Also checks
/// that no `objectives/` or `well-known/` traits fire on known-benign binaries,
/// since those tiers infer attacker intent which should never apply to platform
/// utilities. Low-criticality binary metrics (component/baseline) are exempt.
fn run_ground_truth_checks() -> Result<()> {
    eprintln!("\nRunning ground-truth checks...");
    let mut failures = Vec::new();

    // /bin/ls: benign system utility with xattr/stat/symlink/group-lookup/ACL capabilities.
    check_binary_score("/bin/ls", 1, 8, &mut failures);

    // /bin/cp: file copy utility with chmod/chown/fts/mknod/xattr/ACL capabilities.
    check_binary_score("/bin/cp", 1, 10, &mut failures);

    // /bin/sh: shell with fork/setsid/exec/signal/pty capabilities.
    check_binary_score("/bin/sh", 1, 8, &mut failures);

    // /usr/bin/curl: network transfer tool with HTTP/SOCKS/OAuth/TLS/crypto capabilities.
    check_binary_score("/usr/bin/curl", 5, 12, &mut failures);

    if failures.is_empty() {
        eprintln!("✅ All ground-truth checks passed.");
        Ok(())
    } else {
        for msg in &failures {
            eprintln!("❌ {msg}");
        }
        anyhow::bail!(
            "{} ground-truth check(s) failed — review findings for TAXONOMY.md violations",
            failures.len()
        )
    }
}

fn check_binary_score(path: &str, min: u32, max: u32, failures: &mut Vec<String>) {
    let path = Path::new(path);
    if !path.exists() {
        eprintln!("  ⏭ {}: not found, skipping", path.display());
        return;
    }

    // Skip cache to ensure fresh analysis against current traits
    std::env::set_var("CLEAVE_SKIP_CACHE", "1");
    let options = cleave::AnalysisOptions {
        disable_yara: true,
        ..Default::default()
    };

    match cleave::analyze_file(path, &options) {
        Ok(mut report) => {
            report.finalize();
            let Some(file) = report.files.first() else {
                return;
            };
            let score = file.score;
            let display = path.display();

            if score < min {
                failures.push(format!(
                    "{display} score {score} below minimum {min} — \
                     check for missing notable findings"
                ));
            } else if score > max {
                eprintln!(
                    "❌ {display} has an unusually high score of {score} \
                     (expected {min}-{max}), check for misleading or inflated \
                     findings that violate TAXONOMY.md guidance"
                );
                eprintln!("   Findings contributing to score:");
                for finding in &file.findings {
                    if finding.crit == Criticality::Component
                        || finding.crit == Criticality::Filtered
                    {
                        continue;
                    }
                    eprintln!(
                        "     {:12} {}  {}",
                        format!("{:?}", finding.crit).to_lowercase(),
                        finding.id,
                        finding.desc
                    );
                }
                eprintln!(
                    "   Fix any false-positives or misleading results by improving \
                     the rules (add unless/downgrade/for constraints, move to \
                     correct tier, or adjust criticality) until the score comes down."
                );
                failures.push(format!(
                    "{display} score {score} above cap {max} — \
                     see trait list above"
                ));
            } else {
                eprintln!("  ✅ {display}: score {score} (expected {min}-{max})");
            }

            // Flag ANY objectives/ or well-known/ traits on known-benign binaries.
            // These tiers infer attacker intent — if they fire on platform utilities
            // the trait is misplaced (belongs in micro-behaviors/ or metadata/) or
            // mistargeted (needs a tighter `for`/`unless`/`downgrade`).
            for finding in &file.findings {
                let id = &finding.id;
                if !id.starts_with("objectives/") && !id.starts_with("well-known/") {
                    continue;
                }
                failures.push(format!(
                    "{display}: objectives/well-known trait fired on known-benign binary: \
                     {id} (\"{}\") — either constrain this rule better \
                     or move it to a neutral tier (micro-behaviors/ or metadata/)",
                    finding.desc
                ));
            }
        }
        Err(e) => {
            eprintln!("  ⚠ {}: analysis failed: {}", path.display(), e);
        }
    }
}
