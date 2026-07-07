//! Constructor methods for CapabilityMapper.
//!
//! This module provides various factory methods for creating CapabilityMapper instances,
//! including empty mappers for testing, mappers with custom precision thresholds, and
//! the main production constructor.

use crate::composite_rules::{Platform, platforms_intersect};
use anyhow::Context;

fn log_mapper_init_error(err: &anyhow::Error) {
    tracing::error!(error = %err, "Failed to initialize CapabilityMapper; returning empty mapper");
}

impl super::CapabilityMapper {
    fn skip_traits_requested() -> bool {
        crate::shared_resources::skip_traits_requested()
    }

    /// Default minimum precision for hostile rules.
    /// Calibrated on 2026-03-26 to downgrade roughly the lowest 5% of hostile scores.
    pub const DEFAULT_MIN_HOSTILE_PRECISION: f32 = 1.6;
    /// Default minimum precision for suspicious rules.
    /// Suspicious scores currently floor at 1.0, so 0.0 disables broad low-end downgrades.
    pub const DEFAULT_MIN_SUSPICIOUS_PRECISION: f32 = 0.0;

    /// Default slow rule warning threshold in milliseconds.
    pub const DEFAULT_SLOW_RULE_MS: u64 = 4000;

    /// Create an empty capability mapper for testing
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self {
            trait_definitions: Vec::new(),
            composite_rules: Vec::new(),
            indexes: std::sync::Arc::new(std::sync::OnceLock::new()),
            trait_id_map: std::collections::HashMap::new(),
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
        // provide it explicitly via the traits-dir override / CLEAVE_TRAITS_DIR
        // or by calling from_yaml/from_directory directly.
        if crate::traits_repo::override_dir().is_none()
            && std::env::var_os("CLEAVE_TRAITS_DIR").is_none()
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

    /// Set the platform filter(s) for rule evaluation.
    ///
    /// Pass `vec![Platform::All]` (or an empty vec) to match all platforms — the
    /// default, which leaves the fully-populated indexes untouched. For any other
    /// selection the four match indexes are rebuilt so off-platform traits'
    /// patterns are excluded from the automata, keeping per-file matching cheap
    /// (a Linux scan no longer pays the cost of Windows-only patterns).
    ///
    /// `trait_definitions` and `trait_id_map` are left whole, so composites that
    /// reference an off-platform trait by id still resolve and the per-rule
    /// platform gate in evaluation stays correct.
    #[must_use]
    pub fn with_platforms(mut self, platforms: Vec<Platform>) -> Self {
        self.platforms = if platforms.is_empty() {
            vec![Platform::All]
        } else {
            platforms
        };

        // `All` intersects every rule, so there is nothing to prune — the lazy
        // indexes will build the full set on first use.
        if self.platforms.contains(&Platform::All) {
            return self;
        }

        // Discard any indexes already built for a different platform set; the
        // next `match_indexes()` rebuilds them filtered to `self.platforms`. The
        // reduction the filter buys is logged when that build runs.
        self.indexes = std::sync::Arc::new(std::sync::OnceLock::new());

        let traits_total = self.trait_definitions.len();
        let traits_kept = self
            .trait_definitions
            .iter()
            .filter(|t| platforms_intersect(&t.platforms, &self.platforms))
            .count();
        tracing::debug!(
            platforms = ?self.platforms,
            traits_kept,
            traits_total,
            traits_dropped = traits_total - traits_kept,
            "platform filter set: off-platform trait patterns will be trimmed when indexes build"
        );

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
    /// Precision thresholds control which rules emit low-precision warnings when
    /// precision scoring is enabled during loading.
    ///
    /// # Arguments
    /// * `min_hostile_precision` - Minimum precision for HOSTILE rules (recommended: 1.6)
    /// * `min_suspicious_precision` - Minimum precision for SUSPICIOUS rules (recommended: 0.0)
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
        Self::new_with_load_options(
            min_hostile_precision,
            min_suspicious_precision,
            enable_full_validation,
            false,
        )
    }

    /// Create a new mapper with custom load options.
    #[must_use]
    pub fn new_with_load_options(
        min_hostile_precision: f32,
        min_suspicious_precision: f32,
        enable_full_validation: bool,
        enable_precision_scoring: bool,
    ) -> Self {
        Self::try_new_with_load_options(
            min_hostile_precision,
            min_suspicious_precision,
            enable_full_validation,
            enable_precision_scoring,
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
        Self::try_new_with_load_options(
            min_hostile_precision,
            min_suspicious_precision,
            enable_full_validation,
            false,
        )
    }

    /// Create a new mapper with custom load options.
    pub fn try_new_with_load_options(
        min_hostile_precision: f32,
        min_suspicious_precision: f32,
        enable_full_validation: bool,
        enable_precision_scoring: bool,
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
            Self::from_directory_with_options(
                path,
                min_hostile_precision,
                min_suspicious_precision,
                enable_full_validation,
                enable_precision_scoring,
            )
            .with_context(|| format!("Failed to load traits from {}", resolved.display()))
        } else if path.is_file() {
            // Load from single YAML file (testing mode)
            Self::from_yaml_with_options(
                path,
                min_hostile_precision,
                min_suspicious_precision,
                enable_full_validation,
                enable_precision_scoring,
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
