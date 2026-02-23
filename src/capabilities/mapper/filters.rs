//! Low-value rule filtering for composite findings.
//!
//! This module provides filtering for composite rules that provide minimal additional
//! value over their constituent traits. Specifically, it filters out "any" rules where
//! needs=1, which are equivalent to simple OR operations.

#[cfg(test)]
use crate::types::Finding;

impl super::CapabilityMapper {
    /// Check if a finding is a low-value composite rule.
    ///
    /// These are composite rules with `any` conditions where `needs` is 1 or unset.
    /// Such rules add no value over the underlying matched trait since they
    /// just match if ANY ONE of their conditions is true.
    ///
    /// Returns true if the finding should be filtered out (is low-value).
    #[must_use]
    pub fn is_low_value_any_rule(&self, finding_id: &str) -> bool {
        // Find the composite rule with this ID
        if let Some(rule) = self.composite_rules.iter().find(|r| r.id == finding_id) {
            // Check if it has an `any` clause
            if let Some(any_conditions) = &rule.any {
                // If there's only 1 condition in `any`, it's always low-value
                // (equivalent to just that one condition)
                if any_conditions.len() == 1 {
                    return true;
                }

                // Check the `needs` value
                let needs = rule.needs.unwrap_or(1);

                // If needs is 1 (or implicitly 1), this is low-value
                // because it just matches if ANY ONE condition is true
                if needs <= 1 {
                    return true;
                }
            }
        }
        false
    }

    /// Filter out low-value composite "any" rules from findings.
    /// These rules match when needs=1 (or unset with `any`), providing no
    /// additional value over the underlying trait that matched.
    /// Keeps rules with needs >= 2 which provide meaningful signal combination.
    #[must_use]
    #[cfg(test)]
    pub fn filter_low_value_any_rules(&self, findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|finding| !self.is_low_value_any_rule(&finding.id))
            .collect()
    }
}
