//! Constructor methods for CapabilityMapper.
//!
//! This module provides various factory methods for creating CapabilityMapper instances,
//! including empty mappers for testing, mappers with custom precision thresholds, and
//! the main production constructor.

use crate::capabilities::indexes::{RawContentRegexIndex, StringMatchIndex, TraitIndex};
use crate::composite_rules::Platform;
use std::collections::HashMap;

impl super::CapabilityMapper {
    /// Default minimum precision for hostile composite rules
    pub const DEFAULT_MIN_HOSTILE_PRECISION: f32 = 3.5;
    /// Default minimum precision for suspicious composite rules
    pub const DEFAULT_MIN_SUSPICIOUS_PRECISION: f32 = 2.0;

    /// Default slow rule warning threshold in milliseconds.
    pub const DEFAULT_SLOW_RULE_MS: u64 = 4000;

    /// Create an empty capability mapper for testing
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self {
            symbol_map: HashMap::new(),
            trait_definitions: Vec::new(),
            composite_rules: Vec::new(),
            trait_index: TraitIndex::new(),
            string_match_index: StringMatchIndex::default(),
            raw_content_regex_index: RawContentRegexIndex::default(),
            platforms: vec![Platform::All],
            slow_rule_ms: Self::DEFAULT_SLOW_RULE_MS,
        }
    }

    /// Set the slow rule warning threshold in milliseconds.
    /// Rules that take longer than this to evaluate emit a warning.
    #[must_use]
    #[allow(dead_code)] // used by shared_resources.rs (library only, not binary)
    pub fn with_slow_rule_ms(mut self, ms: u64) -> Self {
        self.slow_rule_ms = ms;
        self
    }

    /// Create a new mapper for testing without validation
    /// This allows tests to load trait files even if they have validation warnings
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_without_validation() -> Self {
        Self::new_with_precision_thresholds(
            Self::DEFAULT_MIN_HOSTILE_PRECISION,
            Self::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            false, // Disable validation for tests
        )
    }

    /// Set the platform filter(s) for rule evaluation
    /// Pass vec![Platform::All] to match all platforms (default)
    #[must_use]
    pub fn with_platforms(mut self, platforms: Vec<Platform>) -> Self {
        self.platforms = if platforms.is_empty() {
            vec![Platform::All]
        } else {
            platforms
        };
        self
    }

    /// Create a new mapper loading traits from the default capabilities directory or YAML file
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_precision_thresholds(
            Self::DEFAULT_MIN_HOSTILE_PRECISION,
            Self::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            false, // Disable full validation by default to avoid blocking on warnings
        )
    }

    /// Create a new mapper with custom precision thresholds
    ///
    /// Precision thresholds control which composite rules are loaded based on their
    /// calculated precision score. Rules with precision below the threshold for their
    /// criticality level are filtered out during loading.
    ///
    /// # Arguments
    /// * `min_hostile_precision` - Minimum precision for HOSTILE rules (recommended: 3.5)
    /// * `min_suspicious_precision` - Minimum precision for SUSPICIOUS rules (recommended: 2.0)
    /// * `enable_full_validation` - If true, run all validation checks and exit on errors
    #[must_use]
    pub fn new_with_precision_thresholds(
        min_hostile_precision: f32,
        min_suspicious_precision: f32,
        enable_full_validation: bool,
    ) -> Self {
        let resolved = crate::traits_repo::resolve_and_ensure();
        let path = resolved.as_path();

        if path.is_dir() {
            // Load from directory (production mode)
            Self::from_directory_with_precision_thresholds(
                path,
                min_hostile_precision,
                min_suspicious_precision,
                enable_full_validation,
            )
            .unwrap_or_else(|e| {
                eprintln!("Failed to load traits from {}: {:#}", resolved.display(), e);
                std::process::exit(1);
            })
        } else if path.is_file() {
            // Load from single YAML file (testing mode)
            Self::from_yaml_with_precision_thresholds(
                path,
                min_hostile_precision,
                min_suspicious_precision,
                enable_full_validation,
            )
            .unwrap_or_else(|e| {
                eprintln!("Failed to load capabilities from YAML file: {:#}", e);
                std::process::exit(1);
            })
        } else {
            eprintln!("Error: Traits path does not exist: {}", resolved.display());
            eprintln!("Set CLEAVE_TRAITS_DIR to point to a valid traits directory or YAML file");
            std::process::exit(1);
        }
    }
}
