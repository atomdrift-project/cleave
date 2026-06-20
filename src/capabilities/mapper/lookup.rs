//! Query methods for finding traits and getting counts.
//!
//! This module provides accessor methods for querying the loaded capabilities,
//! including trait/composite rule queries.

use crate::composite_rules::{CompositeTrait, TraitDefinition};

impl super::CapabilityMapper {
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
