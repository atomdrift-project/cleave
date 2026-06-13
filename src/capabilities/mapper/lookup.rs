//! Query methods for finding traits and getting counts.
//!
//! This module provides accessor methods for querying the loaded capabilities,
//! including symbol lookups and trait/composite rule queries.

use crate::composite_rules::{CompositeTrait, TraitDefinition};
use crate::types::{Evidence, Finding, FindingKind};

impl super::CapabilityMapper {
    /// Look up a symbol and return its capability finding if known.
    ///
    /// `offset` is the symbol's file offset (hex string like `"0x1234"`, e.g.
    /// an import's `.dynstr` name offset) so the evidence can be anchored where
    /// the symbol sits. Pass `None` only when the caller genuinely has no
    /// offset; the evidence then falls back to the header (`0x0`).
    #[must_use]
    pub(crate) fn lookup(&self, symbol: &str, offset: Option<&str>) -> Option<Finding> {
        // Strip common prefixes for matching
        let clean_symbol = symbol
            .trim_start_matches('_') // C symbols often have leading underscore
            .trim_start_matches("__"); // Some have double underscore

        if let Some(info) = self.symbol_map.get(clean_symbol) {
            return Some(Finding {
                src: None,
                id: info.id.clone(),
                kind: FindingKind::Capability,
                desc: info.desc.clone(),
                conf: info.conf,
                crit: info.crit,
                mbc: info.mbc.clone(),
                attack: info.attack.clone(),
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "symbol".to_string(),
                    value: symbol.to_string(),
                    location: Some(offset.map_or_else(|| "0x0".to_string(), str::to_string)),
                    ..Default::default()
                }],

                match_count: 0,
                source_file: None,
            });
        }

        None
    }

    /// Get the number of loaded symbol mappings
    #[allow(dead_code)] // Used in tests
    #[must_use]
    pub(crate) fn mapping_count(&self) -> usize {
        self.symbol_map.len()
    }

    /// Get the number of loaded composite rules
    #[allow(dead_code)] // Used in tests
    #[must_use]
    pub(crate) fn composite_rules_count(&self) -> usize {
        self.composite_rules.len()
    }

    /// Get a reference to the composite rules (for graph generation and analysis)
    #[allow(dead_code)] // Used in tests
    #[must_use]
    pub(crate) fn composite_rules(&self) -> &[CompositeTrait] {
        &self.composite_rules
    }

    /// Get the number of loaded trait definitions
    #[allow(dead_code)] // Used in tests
    #[must_use]
    pub(crate) fn trait_definitions_count(&self) -> usize {
        self.trait_definitions.len()
    }

    /// Get a reference to the trait definitions (for debugging/testing)
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn trait_definitions(&self) -> &[TraitDefinition] {
        &self.trait_definitions
    }

    /// Find a trait definition by ID
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn find_trait(&self, id: &str) -> Option<&TraitDefinition> {
        self.trait_definitions.iter().find(|t| t.id == id)
    }
}
