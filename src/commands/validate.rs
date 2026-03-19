//! Trait validation command.
//!
//! Runs the full suite of trait definition validation checks and reports any
//! errors or quality issues found. Exits with a non-zero status if validation fails.

use anyhow::Result;

/// Run full trait validation against the configured traits directory.
///
/// Loads all trait definitions with validation enabled, which triggers comprehensive
/// checks for logic errors, quality issues, and structural violations. All findings
/// are printed to stderr. Returns `Err` if any validation errors are detected.
pub fn run() -> Result<()> {
    cleave::validate_traits()?;
    eprintln!("✅ All trait validation checks passed.");
    Ok(())
}
