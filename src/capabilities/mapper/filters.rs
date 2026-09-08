//! Low-value rule filtering for composite findings.
//!
//! This module provides filtering for composite rules that provide minimal
//! additional value over their constituent traits: `any:` rules with `needs`
//! of 1, which are equivalent to a simple OR over their legs.
//!
//! Structural redundancy is necessary but not sufficient. A bare OR whose
//! criticality exceeds the leg it fired on is an *escalation*, not a
//! pass-through, and dropping it deletes the verdict rather than a duplicate —
//! see [`CapabilityMapper::drops_as_low_value`].
//!
//! [`CapabilityMapper::drops_as_low_value`]: super::CapabilityMapper::drops_as_low_value

use crate::types::{Criticality, Finding, Istr};
use rustc_hash::{FxHashMap, FxHashSet};

impl super::CapabilityMapper {
    /// Check if a finding is a low-value composite rule.
    ///
    /// These are composite rules with `any` conditions where `needs` is 1 or unset.
    /// Such rules add no value over the underlying matched trait since they
    /// just match if ANY ONE of their conditions is true.
    ///
    /// Returns true if the finding should be filtered out (is low-value).
    #[allow(dead_code)] // Used by library target (lib.rs), not visible to binary crate
    #[must_use]
    pub fn is_low_value_any_rule(&self, finding_id: &str) -> bool {
        // O(1) id lookup: this runs per finding inside the end-of-analysis
        // retain, and the previous linear scan over every composite rule was
        // a serial tail on many-finding container reports.
        if let Some(rule) = self
            .composite_id_index()
            .get(finding_id)
            .map(|&i| &self.composite_rules[i])
        {
            // A rule is only low-value if it's a simple OR (any: with needs: 1)
            // and has no other positive conditions (all:).
            if rule.all.is_some() {
                return false;
            }

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

    /// Whether the end-of-analysis low-value filter deletes `finding`.
    ///
    /// [`Self::is_low_value_any_rule`] asks only whether the *rule* is a bare
    /// OR. That is not enough on its own: a wrapper is redundant only when it
    /// says nothing the leg it fired on already said. When its criticality is
    /// higher than every matched leg it is not a pass-through but a severity
    /// escalation, and deleting it silently downgrades the file —
    /// `direct-http-c2` (suspicious) fires over `direct-http-c2-ip-url`
    /// (component), whose own tier is then stripped as low-tier noise, so the
    /// C2 detection left the report entirely instead of being demoted.
    ///
    /// `leg_crit` resolves a leg id to its criticality in the surviving pool
    /// and `cited` reports whether some composite references this finding.
    /// An unresolved leg counts as an escalation: nothing proves the wrapper
    /// is a pass-through, and keeping a finding errs the right way.
    #[allow(dead_code)] // Used by library target (lib.rs), not visible to binary crate
    pub(crate) fn drops_as_low_value(
        &self,
        finding: &Finding,
        leg_crit: impl Fn(&str) -> Option<Criticality>,
        cited: impl Fn(&str) -> bool,
    ) -> bool {
        if !self.is_low_value_any_rule(&finding.id) || cited(&finding.id) {
            return false;
        }
        // `all` over an empty leg list is `true` — a fired composite with no
        // recorded leg is unexplained, so treat it as escalating and keep it.
        let escalates = finding
            .trait_refs
            .iter()
            .all(|leg| leg_crit(leg.as_str()).is_none_or(|c| c < finding.crit));
        !escalates
    }

    /// Ids in `findings` that [`Self::drops_as_low_value`] will delete.
    ///
    /// Context capture skips these. `dedup_notes` keeps only the strongest
    /// note per byte span, so a finding deleted *after* capture takes the
    /// annotations it outranked down with it and the location renders bare.
    /// The standalone path filters before it captures; the archive-member and
    /// embedded-payload paths capture first, so they resolve the set here.
    #[allow(dead_code)] // Used by library target, not visible to binary crate
    #[must_use]
    pub(crate) fn doomed_low_value_ids(&self, findings: &[Finding]) -> FxHashSet<Istr> {
        let mut crit_by_id: FxHashMap<&str, Criticality> = FxHashMap::default();
        for f in findings {
            crit_by_id
                .entry(f.id.as_str())
                .and_modify(|c| *c = (*c).max(f.crit))
                .or_insert(f.crit);
        }
        let cited: FxHashSet<&str> = findings
            .iter()
            .flat_map(|f| f.trait_refs.iter().map(Istr::as_str))
            .collect();
        findings
            .iter()
            .filter(|f| {
                self.drops_as_low_value(
                    f,
                    |id| crit_by_id.get(id).copied(),
                    |id| cited.contains(id),
                )
            })
            .map(|f| f.id.clone())
            .collect()
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
