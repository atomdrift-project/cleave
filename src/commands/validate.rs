//! Trait validation command.
//!
//! Runs the full suite of trait definition validation checks and reports any
//! errors or quality issues found. Exits with a non-zero status if validation fails.

use crate::capabilities::CapabilityMapper;
use anyhow::Result;

/// Run full trait validation against the configured traits directory.
///
/// Loads all trait definitions with validation enabled, which triggers comprehensive
/// checks for logic errors, quality issues, and structural violations. All findings
/// are printed to stderr. Returns `Err` if any validation errors are detected.
pub(crate) fn run() -> Result<()> {
    let resolved = crate::traits_repo::resolve_and_ensure();

    CapabilityMapper::from_directory_with_precision_thresholds(
        resolved.as_path(),
        CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
        CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
        true,
    )?;

    eprintln!("✅ All trait validation checks passed.");
    Ok(())
}
