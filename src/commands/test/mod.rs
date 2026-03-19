//! Test commands for cleave CLI.
//!
//! This module provides testing and debugging commands for rule development
//! and pattern matching validation.
//!
//! # Commands
//!
//! ## test-rules
//!
//! Debug and validate composite rules and micro-behaviors against sample files.
//! Shows detailed evaluation traces for understanding why rules match or don't match.
//!
//! **Usage:**
//! ```text
//! cleave test-rules <file> --rules <rule-id>[,<rule-id>...]
//! ```
//!
//! **Features:**
//! - Evaluates specified rules against a target file
//! - Shows detailed condition evaluation with pass/fail status
//! - Displays evidence and match locations
//! - Suggests similar rules if specified rule is not found
//! - Supports directory prefixes to test all rules under a path
//!
//! ## test-match
//!
//! Test pattern matching conditions against files with detailed diagnostics.
//! Validates search patterns, count constraints, and location filters.
//!
//! **Usage:**
//! ```text
//! cleave test-match <file> --type <string-value|symbol|raw|kv|hex|encoded|section|metrics> \
//!   --pattern <pattern> [--method <exact|contains|regex|word>] [options...]
//! ```
//!
//! **Search Types:**
//! - `string-value`: Search extracted string literals
//! - `symbol`: Search function/import/export symbols
//! - `raw`: Search raw file content (bytes)
//! - `kv`: Search structured data (JSON/YAML) by key path
//! - `hex`: Search for hex byte patterns
//! - `encoded`: Search decoded/encoded strings (base64, hex, xor)
//! - `section`: Search binary sections by name/size/entropy
//! - `metrics`: Test computed metrics against thresholds
//!
//! **Match Methods:**
//! - `exact`: Exact string match
//! - `contains`: Substring match
//! - `regex`: Regular expression match
//! - `word`: Word boundary match
//!
//! **Constraints:**
//! - `--count-min/max`: Match count thresholds
//! - `--per-kb-min/max`: Density thresholds (matches per KB)
//! - `--length-min/max`: String/section length constraints
//! - `--entropy-min/max`: Entropy constraints (sections)
//! - `--value-min/max`: Metric value thresholds
//! - `--is <external_ip|bitcoin_addr>`: Apply high-fidelity validators
//!
//! **Location Filters:**
//! - `--section <name>`: Limit search to specific section
//! - `--offset <bytes>`: Search at specific file offset
//! - `--offset-range <start:end>`: Search within offset range
//! - `--section-offset <bytes>`: Offset relative to section
//! - `--section-offset-range <start:end>`: Range relative to section
//!
//! **Features:**
//! - Shows matched content and context
//! - Provides suggestions for alternative search types
//! - Displays available sections, keys, and metrics
//! - Tests constraints and shows which failed
//! - Supports case-insensitive matching

pub(crate) mod match_cmd;
pub(crate) mod rules;

pub(crate) fn build_test_capability_mapper(
    platforms: Vec<crate::composite_rules::Platform>,
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
) -> crate::capabilities::CapabilityMapper {
    if std::env::var("CLEAVE_SKIP_TRAITS").is_ok() || std::env::var("cleave_SKIP_TRAITS").is_ok()
    {
        tracing::info!("Traits skipped (CLEAVE_SKIP_TRAITS set)");
        crate::capabilities::CapabilityMapper::empty()
    } else {
        crate::capabilities::CapabilityMapper::new_with_precision_thresholds(
            min_hostile_precision,
            min_suspicious_precision,
            true,
        )
        .with_platforms(platforms)
    }
}

// Re-export command functions
pub(crate) use match_cmd::run as test_match;
pub(crate) use rules::run as test_rules;
