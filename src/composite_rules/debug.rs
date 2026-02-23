//! Debug types for rule evaluation tracing.
//!
//! This module provides types for collecting debug information during rule evaluation.
//! When a debug collector is present in `EvaluationContext`, evaluation records detailed
//! information about why rules matched or failed. When absent (production), there is
//! zero overhead.

use super::types::{FileType, Platform};
use crate::types::{Criticality, Evidence};
use std::sync::RwLock;

/// Why a rule was skipped before condition evaluation
#[derive(Debug, Clone)]
pub(crate) enum SkipReason {
    /// Rule requires different platform(s) than current context
    PlatformMismatch {
        /// Platforms the rule requires
        rule: Vec<Platform>,
        /// Platforms present in the current evaluation context
        context: Vec<Platform>,
    },
    /// Rule requires different file type(s) than current context
    FileTypeMismatch {
        /// File types the rule targets
        rule: Vec<FileType>,
        /// File type of the file being evaluated
        context: FileType,
    },
    /// File is smaller than rule's minimum size
    SizeTooSmall {
        /// Actual file size in bytes
        actual: usize,
        /// Minimum required size in bytes
        min: usize,
    },
    /// File is larger than rule's maximum size
    SizeTooLarge {
        /// Actual file size in bytes
        actual: usize,
        /// Maximum allowed size in bytes
        max: usize,
    },
    /// An 'unless' condition matched, skipping the rule
    UnlessConditionMatched {
        /// Human-readable description of the matching unless condition
        condition_desc: String,
    },
    /// Match count is below minimum threshold
    CountBelowMinimum {
        /// Actual match count
        actual: usize,
        /// Required minimum match count
        min: usize,
    },
    /// Match count is above maximum threshold
    CountAboveMaximum {
        /// Actual match count
        actual: usize,
        /// Maximum allowed match count
        max: usize,
    },
    /// Match density (per KB) is below minimum threshold
    DensityBelowMinimum {
        /// Actual density (matches per KB)
        actual: f64,
        /// Minimum required density
        min: f64,
    },
    /// Match density (per KB) is above maximum threshold
    DensityAboveMaximum {
        /// Actual density (matches per KB)
        actual: f64,
        /// Maximum allowed density
        max: f64,
    },
}

impl std::fmt::Display for SkipReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SkipReason::PlatformMismatch { rule, context } => {
                write!(
                    f,
                    "Platform mismatch: rule requires {:?}, context has {:?}",
                    rule, context
                )
            }
            SkipReason::FileTypeMismatch { rule, context } => {
                write!(
                    f,
                    "File type mismatch: rule requires {:?}, file is {:?}",
                    rule, context
                )
            }
            SkipReason::SizeTooSmall { actual, min } => {
                write!(
                    f,
                    "Size too small (actual: {} bytes, min: {} bytes)",
                    actual, min
                )
            }
            SkipReason::SizeTooLarge { actual, max } => {
                write!(
                    f,
                    "Size too large (actual: {} bytes, max: {} bytes)",
                    actual, max
                )
            }
            SkipReason::UnlessConditionMatched { condition_desc } => {
                write!(f, "Skipped by 'unless' condition: {}", condition_desc)
            }
            SkipReason::CountBelowMinimum { actual, min } => {
                write!(f, "Match count too low (actual: {}, min: {})", actual, min)
            }
            SkipReason::CountAboveMaximum { actual, max } => {
                write!(f, "Match count too high (actual: {}, max: {})", actual, max)
            }
            SkipReason::DensityBelowMinimum { actual, min } => {
                write!(
                    f,
                    "Match density too low (actual: {:.2}/KB, min: {:.2}/KB)",
                    actual, min
                )
            }
            SkipReason::DensityAboveMaximum { actual, max } => {
                write!(
                    f,
                    "Match density too high (actual: {:.2}/KB, max: {:.2}/KB)",
                    actual, max
                )
            }
        }
    }
}

/// Debug info for a single condition evaluation
#[derive(Debug, Clone, Default)]
pub(crate) struct ConditionDebug {
    /// Whether the condition matched
    pub matched: bool,
    /// Evidence collected if matched
    pub evidence: Vec<Evidence>,
    /// Precision score for this condition
    pub precision: f32,
}

impl ConditionDebug {
    /// Create a new condition debug
    pub(crate) fn new(_desc: impl Into<String>) -> Self {
        Self::default()
    }

    /// Set the matched flag
    #[must_use]
    pub(crate) fn with_matched(mut self, matched: bool) -> Self {
        self.matched = matched;
        self
    }

    /// Set evidence
    #[must_use]
    pub(crate) fn with_evidence(mut self, evidence: Vec<Evidence>) -> Self {
        self.evidence = evidence;
        self
    }

    /// Set precision
    #[must_use]
    pub(crate) fn with_precision(mut self, precision: f32) -> Self {
        self.precision = precision;
        self
    }
}

/// Debug info for proximity constraint evaluation
#[allow(dead_code)] // Used by binary target for rule debugging
#[derive(Debug, Clone)]
pub(crate) struct ProximityDebug {
    /// Type of constraint: "near_lines" or "near_bytes"
    pub constraint_type: String,
    /// Maximum span allowed
    pub max_span: usize,
    /// Whether the constraint was satisfied
    pub satisfied: bool,
}

/// Debug info for downgrade evaluation
#[allow(dead_code)] // Used by binary target for rule debugging
#[derive(Debug, Clone)]
pub(crate) struct DowngradeDebug {
    /// Original criticality before downgrade
    pub original_crit: Criticality,
    /// Final criticality after downgrade (may be same if not triggered)
    pub final_crit: Criticality,
    /// Whether the downgrade was triggered
    pub triggered: bool,
}

/// Type of rule being evaluated
#[allow(dead_code)] // Used by binary target for rule debugging
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleType {
    /// Atomic trait definition
    Trait,
    /// Composite rule (boolean combination)
    Composite,
}

impl std::fmt::Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuleType::Trait => write!(f, "trait"),
            RuleType::Composite => write!(f, "composite"),
        }
    }
}

/// Complete debug output for a rule evaluation
#[derive(Debug, Clone)]
pub(crate) struct EvaluationDebug {
    /// Whether the rule matched
    pub matched: bool,
    /// Reason the rule was skipped (if applicable)
    pub skip_reason: Option<SkipReason>,
    /// Results from condition evaluations
    pub condition_results: Vec<ConditionDebug>,
    /// Proximity constraint debug (if applicable)
    pub proximity: Option<ProximityDebug>,
    /// Downgrade debug (if applicable)
    pub downgrade: Option<DowngradeDebug>,
    /// Final precision score
    pub precision: f32,
}

impl EvaluationDebug {
    /// Create a new evaluation debug for a rule
    #[allow(dead_code)] // Used by binary target for rule debugging
    pub(crate) fn new(_rule_id: impl Into<String>, _rule_type: RuleType) -> Self {
        Self {
            matched: false,
            skip_reason: None,
            condition_results: Vec::new(),
            proximity: None,
            downgrade: None,
            precision: 0.0,
        }
    }

    /// Record a skip reason
    pub(crate) fn record_skip(&mut self, reason: SkipReason) {
        self.skip_reason = Some(reason);
    }

    /// Add a condition result
    pub(crate) fn add_condition(&mut self, condition: ConditionDebug) {
        self.condition_results.push(condition);
    }

    /// Set the proximity debug info
    pub(crate) fn set_proximity(&mut self, proximity: ProximityDebug) {
        self.proximity = Some(proximity);
    }

    /// Set the downgrade debug info
    pub(crate) fn set_downgrade(&mut self, downgrade: DowngradeDebug) {
        self.downgrade = Some(downgrade);
    }
}

/// Debug collector that can be optionally attached to EvaluationContext.
/// When present, evaluation records debug info. When absent, zero overhead.
/// Uses RwLock for thread-safety with rayon parallel evaluation.
pub(crate) type DebugCollector = RwLock<EvaluationDebug>;
