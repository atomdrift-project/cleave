//! Constructor methods for CapabilityMapper.
//!
//! This module provides various factory methods for creating CapabilityMapper instances,
//! including empty mappers for testing, mappers with custom precision thresholds, and
//! the main production constructor.

use crate::capabilities::indexes::{RawContentRegexIndex, StringMatchIndex, TraitIndex};
use crate::composite_rules::Platform;
use anyhow::Context;
use std::collections::HashMap;

fn log_mapper_init_error(err: &anyhow::Error) {
    tracing::error!(error = %err, "Failed to initialize CapabilityMapper; returning empty mapper");
}

impl super::CapabilityMapper {
    fn skip_traits_requested() -> bool {
        std::env::var("CLEAVE_SKIP_TRAITS").is_ok() || std::env::var("cleave_SKIP_TRAITS").is_ok()
    }

    /// Default minimum precision for hostile composite rules
    pub const DEFAULT_MIN_HOSTILE_PRECISION: f32 = 3.5;
    /// Default minimum precision for suspicious composite rules
    pub const DEFAULT_MIN_SUSPICIOUS_PRECISION: f32 = 1.9;

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
        // Keep unit tests hermetic by default. Tests that need real trait data should
        // provide it explicitly via CLEAVE_TRAITS_DIR or use from_yaml/from_directory.
        if std::env::var_os("CLEAVE_TRAITS_DIR").is_none()
            && std::env::var_os("cleave_TRAITS_DIR").is_none()
            && !Self::skip_traits_requested()
        {
            return Self::empty();
        }

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

    /// Create a new mapper loading traits from the default capabilities directory or YAML file.
    ///
    /// This is a best-effort convenience constructor. If trait loading fails, it
    /// logs the error and returns an empty mapper. Call [`Self::try_new`] if you
    /// need failure to propagate.
    #[must_use]
    pub fn new() -> Self {
        Self::try_new_with_precision_thresholds(
            Self::DEFAULT_MIN_HOSTILE_PRECISION,
            Self::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            false, // Disable full validation by default to avoid blocking on warnings
        )
        .unwrap_or_else(|err| {
            log_mapper_init_error(&err);
            Self::empty()
        })
    }

    /// Create a new mapper loading traits from the default capabilities directory or YAML file.
    pub fn try_new() -> anyhow::Result<Self> {
        Self::try_new_with_precision_thresholds(
            Self::DEFAULT_MIN_HOSTILE_PRECISION,
            Self::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            false,
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
    /// * `min_suspicious_precision` - Minimum precision for SUSPICIOUS rules (recommended: 1.9)
    /// * `enable_full_validation` - If true, run all validation checks
    ///
    /// This is a best-effort convenience constructor. If trait loading fails, it
    /// logs the error and returns an empty mapper. Call
    /// [`Self::try_new_with_precision_thresholds`] if you need failure to
    /// propagate.
    #[must_use]
    pub fn new_with_precision_thresholds(
        min_hostile_precision: f32,
        min_suspicious_precision: f32,
        enable_full_validation: bool,
    ) -> Self {
        Self::try_new_with_precision_thresholds(
            min_hostile_precision,
            min_suspicious_precision,
            enable_full_validation,
        )
        .unwrap_or_else(|err| {
            log_mapper_init_error(&err);
            Self::empty()
        })
    }

    /// Create a new mapper with custom precision thresholds.
    pub fn try_new_with_precision_thresholds(
        min_hostile_precision: f32,
        min_suspicious_precision: f32,
        enable_full_validation: bool,
    ) -> anyhow::Result<Self> {
        if Self::skip_traits_requested() {
            return Ok(Self::empty());
        }

        let resolved = cleave::traits_repo::resolve_and_ensure()
            .map_err(anyhow::Error::msg)
            .context("resolve traits path")?;
        let path = resolved.as_path();

        if path.is_dir() {
            // Load from directory (production mode)
            Self::from_directory_with_precision_thresholds(
                path,
                min_hostile_precision,
                min_suspicious_precision,
                enable_full_validation,
            )
            .with_context(|| format!("Failed to load traits from {}", resolved.display()))
        } else if path.is_file() {
            // Load from single YAML file (testing mode)
            Self::from_yaml_with_precision_thresholds(
                path,
                min_hostile_precision,
                min_suspicious_precision,
                enable_full_validation,
            )
            .context("Failed to load capabilities from YAML file")
        } else {
            anyhow::bail!(
                "Traits path does not exist: {}. Set CLEAVE_TRAITS_DIR to a valid traits directory or YAML file",
                resolved.display()
            );
        }
    }
}
