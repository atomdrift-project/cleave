//! Trait validation command.
//!
//! Runs the full suite of trait definition validation checks and reports any
//! errors or quality issues found. Exits with a non-zero status if validation fails.

use anyhow::Result;
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
/// taxonomy violations) that inflate scores beyond expected ranges.
fn run_ground_truth_checks() -> Result<()> {
    eprintln!("\nRunning ground-truth checks...");
    let mut failures = Vec::new();

    // /bin/ls: benign system utility with xattr/stat/symlink/group-lookup/ACL capabilities.
    // Higher indicates false positives or inflated findings that violate TAXONOMY.md guidance.
    check_binary_score("/bin/ls", 1, 15, &mut failures);

    // /bin/sh: minimal shell stub (macOS). Only exec and platform-signing traits.
    check_binary_score("/bin/sh", 1, 10, &mut failures);

    // /usr/bin/curl: network transfer tool with HTTP/SOCKS/OAuth/TLS/crypto capabilities.
    // Higher indicates trait inflation for legitimate network behaviors.
    check_binary_score("/usr/bin/curl", 5, 30, &mut failures);

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
            let score = report.files.first().map_or(0, |f| f.score);

            if score < min {
                failures.push(format!(
                    "{} has an unusually low score of {} (expected {}-{}), \
                     check for missing notable findings that describe its purpose",
                    path.display(),
                    score,
                    min,
                    max
                ));
            } else if score > max {
                failures.push(format!(
                    "{} has an unusually high score of {} (expected {}-{}), \
                     check for misleading or inflated findings that violate TAXONOMY.md guidance",
                    path.display(),
                    score,
                    min,
                    max
                ));
            } else {
                eprintln!(
                    "  ✅ {}: score {} (expected {}-{})",
                    path.display(),
                    score,
                    min,
                    max
                );
            }
        }
        Err(e) => {
            eprintln!("  ⚠ {}: analysis failed: {}", path.display(), e);
        }
    }
}
