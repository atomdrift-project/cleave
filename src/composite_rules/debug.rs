//! Debug types for rule evaluation tracing.
//!
//! This module provides types for collecting debug information during rule evaluation.
//! When a debug collector is present in `EvaluationContext`, evaluation records detailed
//! information about why rules matched or failed. When absent (production), there is
//! zero overhead.

use super::types::{Arch, FileType, Platform};
use crate::types::Criticality;
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
    /// Rule requires different architecture(s) than current context
    ArchMismatch {
        /// Architectures the rule targets
        rule: Vec<Arch>,
        /// Architectures of the file being evaluated
        context: Vec<Arch>,
    },
    /// Rule requires different file type(s) than current context
    FileTypeMismatch {
        /// File types the rule targets
        rule: Vec<FileType>,
        /// File type of the file being evaluated
        context: FileType,
    },
    /// The trait's identity came from the host file, but the trait also
    /// constrains the whole file, and this node is only a piece of one.
    /// See `TraitDefinition::constrains_whole_file`.
    InheritedIdentityOnFragment {
        /// Path of the host the fragment was carved from
        host: String,
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
    /// File entropy is below minimum threshold
    EntropyTooLow {
        /// Actual entropy (0.0-8.0)
        actual: f64,
        /// Minimum required entropy
        min: f64,
    },
    /// File entropy is above maximum threshold
    EntropyTooHigh {
        /// Actual entropy (0.0-8.0)
        actual: f64,
        /// Maximum allowed entropy
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
            SkipReason::ArchMismatch { rule, context } => {
                write!(
                    f,
                    "Arch mismatch: rule requires {:?}, file is {:?}",
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
            SkipReason::InheritedIdentityOnFragment { host } => {
                write!(
                    f,
                    "Identity is the host's ({host}); trait also constrains the whole file, and this node is a fragment of one"
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
            SkipReason::EntropyTooLow { actual, min } => {
                write!(
                    f,
                    "File entropy too low (actual: {:.2}, min: {:.2})",
                    actual, min
                )
            }
            SkipReason::EntropyTooHigh { actual, max } => {
                write!(
                    f,
                    "File entropy too high (actual: {:.2}, max: {:.2})",
                    actual, max
                )
            }
        }
    }
}

/// Debug info for proximity constraint evaluation
#[derive(Debug, Clone)]
pub(crate) struct ProximityDebug {
    /// Type of constraint: "near_lines" or "near_bytes"
    #[cfg_attr(not(feature = "lint"), allow(dead_code))]
    pub constraint_type: String,
    /// Maximum span allowed
    #[cfg_attr(not(feature = "lint"), allow(dead_code))]
    pub max_span: usize,
    /// Whether the constraint was satisfied
    #[cfg_attr(not(feature = "lint"), allow(dead_code))]
    pub satisfied: bool,
    /// Human-readable explanation of the group requirement and where each
    /// condition group's evidence actually landed, so an author can see why
    /// proximity passed or failed (e.g. `all: @ line(s) [106]; any: @ line(s)
    /// [38] — need every all-leg + 1 any-leg within 1 line`).
    #[cfg_attr(not(feature = "lint"), allow(dead_code))]
    pub detail: String,
}

/// Debug info for the `scope:` filter: which scope bucket each leg's
/// evidence landed in, and whether one bucket held enough of them.
#[derive(Debug, Clone)]
pub(crate) struct ScopeDebug {
    /// The rule's effective scope (`file`, `leaf`, `archive`, ...).
    #[cfg_attr(not(feature = "lint"), allow(dead_code))]
    pub scope: String,
    /// Whether a single bucket satisfied the rule.
    pub satisfied: bool,
    /// What one bucket must hold, and what each bucket holds.
    #[cfg_attr(not(feature = "lint"), allow(dead_code))]
    pub detail: String,
}

/// Debug info for downgrade evaluation
#[derive(Debug, Clone)]
pub(crate) struct DowngradeDebug {
    /// Original criticality before downgrade
    #[cfg_attr(not(feature = "lint"), allow(dead_code))]
    pub original_crit: Criticality,
    /// Final criticality after downgrade (may be same if not triggered)
    #[cfg_attr(not(feature = "lint"), allow(dead_code))]
    pub final_crit: Criticality,
    /// Whether the downgrade was triggered
    #[cfg_attr(not(feature = "lint"), allow(dead_code))]
    pub triggered: bool,
}

/// Type of rule being evaluated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "lint")]
pub(crate) enum RuleType {
    /// Atomic trait definition
    Trait,
    /// Composite rule (boolean combination)
    Composite,
}

#[cfg(feature = "lint")]
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
    /// Proximity constraint debug (if applicable)
    pub proximity: Option<ProximityDebug>,
    /// Scope filter debug (if the rule's scope buckets its evidence)
    pub scope: Option<ScopeDebug>,
    /// Downgrade debug (if applicable)
    pub downgrade: Option<DowngradeDebug>,
    /// Final precision score
    pub precision: f32,
}

impl EvaluationDebug {
    /// Create a new evaluation debug for a rule
    #[cfg(feature = "lint")]
    pub(crate) fn new(_rule_id: impl Into<String>, _rule_type: RuleType) -> Self {
        Self {
            matched: false,
            skip_reason: None,
            proximity: None,
            scope: None,
            downgrade: None,
            precision: 0.0,
        }
    }
}

/// Debug collector that can be optionally attached to EvaluationContext.
/// When present, evaluation records debug info. When absent, zero overhead.
/// Uses RwLock for thread-safety with rayon parallel evaluation.
pub(crate) type DebugCollector = RwLock<EvaluationDebug>;
