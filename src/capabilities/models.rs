//! Data structures for YAML parsing and capability definitions.
//!
//! This module defines the structures used to parse trait and composite rule
//! definitions from YAML files. These include:
//! - File-level defaults
//! - Raw trait definitions (before default application)
//! - Raw composite rules (before default application)
//! - Simple symbol mappings

use serde::{Deserialize, Serialize};

/// Internal trait information for symbol lookups
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct TraitInfo {
    pub(crate) id: String,
    pub(crate) desc: String,
    pub(crate) conf: f32,
    pub(crate) crit: crate::types::Criticality,
    pub(crate) mbc: Option<String>,
    pub(crate) attack: Option<String>,
}

/// File-level defaults that apply to all traits in a file
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub(crate) struct TraitDefaults {
    #[serde(default, alias = "for", alias = "file_types")]
    pub(crate) r#for: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) platforms: Option<Vec<String>>,
    #[serde(default, alias = "criticality")]
    pub(crate) crit: Option<String>,
    #[serde(default, alias = "confidence")]
    pub(crate) conf: Option<f32>,
    #[serde(default)]
    pub(crate) mbc: Option<String>,
    #[serde(default)]
    pub(crate) attack: Option<String>,
}

/// Raw trait definition for parsing (fields can be absent to inherit defaults)
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawTraitDefinition {
    pub(crate) id: String,
    #[serde(alias = "description")]
    pub(crate) desc: String,
    #[serde(default, alias = "confidence")]
    pub(crate) conf: Option<f32>,
    #[serde(default, alias = "criticality")]
    pub(crate) crit: Option<String>,
    #[serde(default)]
    pub(crate) mbc: Option<String>,
    #[serde(default)]
    pub(crate) attack: Option<String>,
    #[serde(default)]
    pub(crate) platforms: Option<Vec<String>>,
    #[serde(default, alias = "for", alias = "files")]
    pub(crate) file_types: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) size_min: Option<usize>,
    #[serde(default)]
    pub(crate) size_max: Option<usize>,
    #[serde(default, alias = "if")]
    pub(crate) condition: Option<crate::composite_rules::ConditionWithFilters>,
    #[serde(default)]
    pub(crate) not: Option<Vec<crate::composite_rules::condition::NotException>>,
    #[serde(default)]
    pub(crate) unless: Option<Vec<crate::composite_rules::Condition>>,
    #[serde(default)]
    pub(crate) downgrade: Option<crate::composite_rules::DowngradeConditions>,
}

/// Raw composite rule for parsing (fields can be absent to inherit defaults)
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawCompositeRule {
    #[serde(alias = "capability")]
    pub(crate) id: String,
    #[serde(alias = "description")]
    pub(crate) desc: String,
    #[serde(default, alias = "confidence")]
    pub(crate) conf: Option<f32>,
    #[serde(default, alias = "criticality")]
    pub(crate) crit: Option<String>,
    #[serde(default)]
    pub(crate) mbc: Option<String>,
    #[serde(default)]
    pub(crate) attack: Option<String>,
    #[serde(default)]
    pub(crate) platforms: Option<Vec<String>>,
    #[serde(default, alias = "for", alias = "files")]
    pub(crate) file_types: Option<Vec<String>>,
    #[serde(default)]
    pub(crate) size_min: Option<usize>,
    #[serde(default)]
    pub(crate) size_max: Option<usize>,
    // Boolean operators
    #[serde(default, alias = "requires_all")]
    pub(crate) all: Option<Vec<crate::composite_rules::Condition>>,
    #[serde(default, alias = "requires_any", alias = "conditions")]
    pub(crate) any: Option<Vec<crate::composite_rules::Condition>>,
    /// Minimum number of conditions that must match (for `any` lists)
    #[serde(default)]
    pub(crate) needs: Option<usize>,
    #[serde(default, alias = "requires_none")]
    pub(crate) none: Option<Vec<crate::composite_rules::Condition>>,
    // Single condition (for simple composite rules)
    #[serde(default, alias = "if")]
    pub(crate) condition: Option<crate::composite_rules::Condition>,
    // Proximity constraint: all evidence must be within N lines
    #[serde(default)]
    pub(crate) near_lines: Option<usize>,
    // Proximity constraint: all evidence must be within N bytes/characters
    #[serde(default)]
    pub(crate) near_bytes: Option<usize>,
    // File-level skip conditions
    #[serde(default)]
    pub(crate) unless: Option<Vec<crate::composite_rules::Condition>>,
    #[serde(default)]
    pub(crate) not: Option<Vec<crate::composite_rules::condition::NotException>>,
    /// Criticality downgrade rules - map of target criticality to conditions
    #[serde(default)]
    pub(crate) downgrade: Option<crate::composite_rules::DowngradeConditions>,
}

/// YAML file structure
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TraitMappings {
    #[serde(default)]
    pub(crate) defaults: TraitDefaults,

    #[serde(default)]
    pub(crate) symbols: Vec<SymbolMapping>,

    #[serde(default)]
    pub(crate) simple_rules: Vec<SimpleRule>,

    #[serde(default)]
    pub(crate) traits: Vec<RawTraitDefinition>,

    #[serde(default, alias = "capabilities")]
    pub(crate) composite_rules: Vec<RawCompositeRule>,
}

/// Simple rule with platform/file type constraints
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SimpleRule {
    pub(crate) symbol: String,
    pub(crate) capability: String,
    #[serde(alias = "description")]
    pub(crate) desc: String,
    #[serde(alias = "confidence")]
    pub(crate) conf: f32,
    #[serde(default)]
    pub(crate) platforms: Vec<String>,
    #[serde(default, alias = "for")]
    pub(crate) file_types: Vec<String>,
}

/// Legacy symbol mapping format
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SymbolMapping {
    pub(crate) symbol: String,
    pub(crate) capability: String,
    #[serde(alias = "description")]
    pub(crate) desc: String,
    #[serde(alias = "confidence")]
    pub(crate) conf: f32,
}
