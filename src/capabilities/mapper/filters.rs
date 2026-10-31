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

use crate::types::{AnalysisReport, Criticality, Finding, Istr};
use rustc_hash::{FxHashMap, FxHashSet};

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

    /// Delete the low-value wrappers from `report`, top level and members,
    /// and return how many went.
    ///
    /// A wrapper is kept when a composite that fired with it in scope cites
    /// it ([`Citations`]). Its legs are read where it is listed: a member's
    /// from that member, since a sibling's tier for the same id says nothing
    /// about this wrapper; a top-level wrapper's from the whole report, since a
    /// member and its container can carry one id at different tiers and the
    /// strongest is what a container wrapper has to beat.
    ///
    /// Repeated until nothing changes: dropping a wrapper can orphan another
    /// that only it cited. A single pass was not idempotent, so a decoded
    /// payload's findings, already filtered by their own analysis, lost such
    /// wrappers when the file that carried them was filtered again.
    pub(crate) fn filter_low_value(&self, report: &mut AnalysisReport) -> usize {
        let raise = |tiers: &mut FxHashMap<Istr, Criticality>, f: &Finding| {
            tiers
                .entry(f.id.clone())
                .and_modify(|c| *c = (*c).max(f.crit))
                .or_insert(f.crit);
        };
        let mut total = 0;
        loop {
            let citations = Citations::of(self, report);
            let mut everywhere = FxHashMap::default();
            let mut by_file: FxHashMap<String, FxHashMap<Istr, Criticality>> = FxHashMap::default();
            for f in &report.findings {
                raise(&mut everywhere, f);
            }
            for file in &report.files {
                let own = by_file.entry(file.path.clone()).or_default();
                for f in &file.findings {
                    raise(own, f);
                    raise(&mut everywhere, f);
                }
            }
            let none = FxHashMap::default();
            let removed = report.filter_findings_by_file(|path: Option<&str>| {
                let legs = path.map_or(&everywhere, |p| by_file.get(p).unwrap_or(&none));
                let cited = citations.for_path(path);
                move |f: &Finding| {
                    !self.drops_as_low_value(
                        f,
                        |id| legs.get(id).copied(),
                        |id| cited.iter().any(|c| c.contains(id)),
                    )
                }
            });
            if removed == 0 {
                return total;
            }
            total += removed;
        }
    }

    /// Ids in `findings` that [`Self::drops_as_low_value`] will delete.
    ///
    /// Context capture skips these. `dedup_notes` keeps only the strongest
    /// note per byte span, so a finding deleted *after* capture takes the
    /// annotations it outranked down with it and the location renders bare.
    /// The standalone path filters before it captures; the archive-member and
    /// embedded-payload paths capture first, so they resolve the set here.
    #[must_use]
    pub(crate) fn doomed_low_value_ids(&self, findings: &[Finding]) -> FxHashSet<Istr> {
        // The same fixed point the final filter reaches: a wrapper cited only
        // by doomed findings is doomed too.
        let mut doomed: FxHashSet<Istr> = FxHashSet::default();
        loop {
            let live = || findings.iter().filter(|f| !doomed.contains(&f.id));
            let mut crit_by_id: FxHashMap<&str, Criticality> = FxHashMap::default();
            for f in live() {
                crit_by_id
                    .entry(f.id.as_str())
                    .and_modify(|c| *c = (*c).max(f.crit))
                    .or_insert(f.crit);
            }
            let cited: FxHashSet<&str> = live()
                .flat_map(|f| f.trait_refs.iter().map(Istr::as_str))
                .collect();
            let newly: Vec<Istr> = live()
                .filter(|f| {
                    self.drops_as_low_value(
                        f,
                        |id| crit_by_id.get(id).copied(),
                        |id| cited.contains(id),
                    )
                })
                .map(|f| f.id.clone())
                .collect();
            if newly.is_empty() {
                return doomed;
            }
            doomed.extend(newly);
        }
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

/// Which fired composites vouch for each file's findings.
///
/// A composite vouches for what it had in scope when it fired, by its
/// `scope:` ([`crate::composite_rules::Scope`]):
///
/// * a file's own composites, for that file;
/// * a host's composites that pool its decoded layers (`file` and wider,
///   not `leaf`), for the views carved from it (`host##encoding@offset`);
/// * an archive's composites that pool across files (wider than `file`),
///   for its members (`archive!!member`), the report's top level included.
///
/// A sibling member is never in scope. Counting every citation in the report
/// made the same member bytes keep or lose a trait depending on what shipped
/// beside them — and hopper stores one analysis per member SHA-256. An
/// archive's findings also carry copies of its members' own composites; those
/// are `file`-scoped, so they vouch for nothing beyond the member they fired
/// in.
///
/// Citations name trait ids, not locations: an archive composite that cites
/// a trait vouches for it in every member that carries it.
pub(crate) struct Citations {
    /// Every citation in the report: what a top-level finding sees.
    everywhere: FxHashSet<Istr>,
    /// By the path of the file holding them; the top level under the
    /// report's target path.
    by_holder: FxHashMap<String, Held>,
    /// The report's target path, when it has top-level findings to place.
    root: Option<String>,
    none: FxHashSet<Istr>,
}

/// What one file's fired composites cite, by how far they reach.
#[derive(Default)]
struct Held {
    own: FxHashSet<Istr>,
    /// For the decoded views below it.
    layers: FxHashSet<Istr>,
    /// For the archive members below it.
    members: FxHashSet<Istr>,
}

impl Held {
    fn add(&mut self, mapper: &super::CapabilityMapper, finding: &Finding) {
        use crate::composite_rules::Scope;
        if finding.trait_refs.is_empty() {
            return;
        }
        let scope = mapper
            .composite_id_index()
            .get(finding.id.as_str())
            .map_or(Scope::File, |&i| {
                mapper.composite_rules[i].effective_scope()
            });
        let refs = finding.trait_refs.iter().cloned();
        self.own.extend(refs.clone());
        if scope != Scope::Leaf {
            self.layers.extend(refs.clone());
        }
        if !matches!(scope, Scope::File | Scope::Leaf) {
            self.members.extend(refs);
        }
    }
}

impl Citations {
    pub(crate) fn of(mapper: &super::CapabilityMapper, report: &AnalysisReport) -> Self {
        // Before `finalize` the top level is the target's own findings, and
        // archive members are listed relative to it; after, it is the depth-0
        // entry and the top level is empty. An archive may list one path
        // twice; both entries hold for it.
        let root = (!report.findings.is_empty() && !report.target.path.is_empty())
            .then(|| report.target.path.clone());
        let mut by_holder: FxHashMap<String, Held> = FxHashMap::default();
        let lists = report
            .files
            .iter()
            .map(|f| (&f.path, &f.findings))
            .chain(root.as_ref().map(|root| (root, &report.findings)));
        for (path, findings) in lists {
            let held = by_holder.entry(path.clone()).or_default();
            for f in findings {
                held.add(mapper, f);
            }
        }
        Self {
            everywhere: report
                .findings
                .iter()
                .chain(report.files.iter().flat_map(|f| f.findings.iter()))
                .flat_map(|f| f.trait_refs.iter().cloned())
                .collect(),
            by_holder,
            root,
            none: FxHashSet::default(),
        }
    }

    /// The citation sets vouching for a finding listed at `path`; `None` is
    /// the top level.
    pub(crate) fn for_path(&self, path: Option<&str>) -> Vec<&FxHashSet<Istr>> {
        use crate::types::{ARCHIVE_DELIMITER, ENCODING_DELIMITER};
        let Some(path) = path else {
            return vec![&self.everywhere];
        };
        let mut sets = vec![self.by_holder.get(path).map_or(&self.none, |h| &h.own)];
        for (at, boundary) in path
            .match_indices(ARCHIVE_DELIMITER)
            .chain(path.match_indices(ENCODING_DELIMITER))
        {
            let Some(holder) = path.get(..at).and_then(|p| self.by_holder.get(p)) else {
                continue;
            };
            sets.push(if boundary == ARCHIVE_DELIMITER {
                &holder.members
            } else {
                &holder.layers
            });
        }
        // A member listed relative to the target, before `finalize` roots it.
        if let Some(root) = &self.root
            && !path.starts_with(root.as_str())
            && let Some(holder) = self.by_holder.get(root)
        {
            sets.push(&holder.members);
        }
        sets
    }
}
