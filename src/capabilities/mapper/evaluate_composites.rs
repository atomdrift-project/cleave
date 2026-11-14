//! Composite rule evaluation against analysis reports.
//!
//! This module handles the evaluation of composite rules, which combine multiple
//! atomic traits using logical operators (all, any, none, unless). Features:
//! - Two-pass evaluation (positive rules, then negative rules)
//! - Fixed-point iteration for cascading dependencies
//! - Downgrade re-evaluation with complete finding context

use crate::capabilities::indexes::TraitBitSet;
use crate::composite_rules::PathQuery;
use crate::composite_rules::{
    Arch, EvaluationContext, FileType as RuleFileType, FindingScope, SectionMap, TypeMask,
};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use std::borrow::Cow;
use std::collections::HashMap;

// Parent re-evaluation changes only these fields. Keep the report borrowed as
// the original metadata snapshot, retaining only scalar edits between files.
struct FindingDowngrade {
    index: usize,
    crit: Criticality,
    downgraded: bool,
}

impl FindingDowngrade {
    fn apply(&self, findings: &mut [Finding]) {
        findings[self.index].crit = self.crit;
        findings[self.index].downgraded = self.downgraded;
    }
}

fn immediate_parent_path(path: &str) -> Option<&str> {
    match (path.rfind("!!"), path.rfind("##")) {
        (Some(archive), Some(encoding)) => Some(&path[..archive.max(encoding)]),
        (Some(archive), None) => Some(&path[..archive]),
        (None, Some(encoding)) => Some(&path[..encoding]),
        (None, None) => None,
    }
}

/// A container copy pooled from several members keeps its crit while each
/// member is downgraded one at a time, since another member might still carry
/// the finding undowngraded. Once every member edit is in, lower such a copy
/// to the strongest crit any descendant still holds for that id. Only rollup
/// copies are touched -- no `src`, and every located evidence item points into
/// the archive (`archive:<member>`) -- so a container's own detection with the
/// same id keeps its tier. Crits are only ever lowered here.
fn lower_pooled_rollups(report: &mut AnalysisReport, touched: &rustc_hash::FxHashSet<String>) {
    use crate::types::file_analysis::{ARCHIVE_DELIMITER, ENCODING_DELIMITER};
    // A member's own archive-root evidence (`archive:value:<path>`, e.g. a
    // nested layer's `archive_guard`) rolls up without naming the member. It
    // can only be the root container's own observation if the root's value
    // tree holds that path; otherwise it came from a descendant.
    let root_lacks_value = |path: &str| {
        let pointer = format!("/{}", path.replace('.', "/"));
        report
            .values_tree
            .as_deref()
            .is_none_or(|tree| tree.pointer(&pointer).is_none())
    };
    // Members named by a rollup's evidence (`archive:<rel>[:<inner>]`), with
    // `None` entries for descendant-root evidence; `None` overall when the
    // copy is not a pure rollup of member evidence.
    let named_members = |copy: &Finding, at_root: bool| -> Option<Vec<Option<String>>> {
        if copy.src.is_some() || !touched.contains(copy.id.as_str()) {
            return None;
        }
        let mut members = Vec::new();
        for location in copy.evidence.iter().filter_map(|e| e.location.as_deref()) {
            let rel = location.strip_prefix("archive:")?;
            if let Some(path) = rel.strip_prefix("value:") {
                if !at_root || !root_lacks_value(path) {
                    return None;
                }
                members.push(None);
                continue;
            }
            members.push(Some(rel.rsplit('!').next().unwrap_or(rel).to_owned()));
        }
        (!members.is_empty()).then_some(members)
    };
    // The strongest crit for `id` among descendants of `under` (all files for
    // the root), provided every named member is one of them and still carries
    // the finding. A member that was not retained may hold it undowngraded.
    let strongest = |id: &str, members: &[Option<String>], under: Option<&str>| {
        let descendants: Vec<(&str, Criticality)> = report
            .files
            .iter()
            .filter(|file| {
                under.is_none_or(|container| {
                    file.path.strip_prefix(container).is_some_and(|rest| {
                        rest.starts_with(ARCHIVE_DELIMITER) || rest.starts_with(ENCODING_DELIMITER)
                    })
                })
            })
            .flat_map(|file| {
                let leaf = crate::types::core::leaf_member(&file.path);
                file.findings
                    .iter()
                    .filter(move |finding| finding.id.as_str() == id)
                    .map(move |finding| (leaf, finding.crit))
            })
            .collect();
        // Evidence names a member relative to the archive that rolled it up,
        // optionally followed by `:<inner location>`; a file path may carry
        // more (or fewer) leading directories than that name.
        let same_member = |name: &str, leaf: &str| {
            name == leaf
                || leaf
                    .strip_suffix(name)
                    .is_some_and(|head| head.ends_with('/'))
                || name
                    .strip_suffix(leaf)
                    .is_some_and(|head| head.ends_with('/'))
        };
        let all_named = members.iter().all(|member| match member {
            Some(member) => {
                let name = member.split(':').next().unwrap_or(member);
                descendants.iter().any(|(leaf, _)| same_member(name, leaf))
            }
            None => !descendants.is_empty(),
        });
        all_named
            .then(|| descendants.iter().map(|(_, crit)| *crit).max())
            .flatten()
    };
    let mut edits: Vec<(Option<usize>, usize, Criticality)> = Vec::new();
    for (index, copy) in report.findings.iter().enumerate() {
        if let Some(members) = named_members(copy, true)
            && let Some(crit) = strongest(copy.id.as_str(), &members, None)
            && crit < copy.crit
        {
            edits.push((None, index, crit));
        }
    }
    for (file_idx, file) in report.files.iter().enumerate() {
        for (index, copy) in file.findings.iter().enumerate() {
            if let Some(members) = named_members(copy, false)
                && let Some(crit) = strongest(copy.id.as_str(), &members, Some(file.path.as_str()))
                && crit < copy.crit
            {
                edits.push((Some(file_idx), index, crit));
            }
        }
    }
    for (file_idx, index, crit) in edits {
        let copy = match file_idx {
            None => &mut report.findings[index],
            Some(file_idx) => &mut report.files[file_idx].findings[index],
        };
        copy.crit = crit;
        copy.downgraded = true;
    }
}

/// Which part of an archive entry name a path trait matches.
#[derive(Clone, Copy, Debug)]
pub(crate) enum PathScope {
    Base,
    Dir,
    Full,
}

impl PathScope {
    fn of(self, entry_name: &str) -> &str {
        match self {
            Self::Base => crate::composite_rules::evaluators::misc::path_basename(entry_name),
            Self::Dir => crate::composite_rules::evaluators::misc::path_dirname(entry_name),
            Self::Full => entry_name,
        }
    }
}

/// One `type: path` trait with its per-trait constants hoisted out of the
/// entry loop (lowercased needles, resolved regex).
#[derive(Debug)]
pub(crate) struct PathTrait {
    trait_idx: usize,
    /// Lowercased when `case_insensitive`, matching the target's casing.
    exact: Option<String>,
    substr: Option<String>,
    regex: Option<std::sync::Arc<crate::composite_rules::condition::TraitRegex>>,
    case_insensitive: bool,
    scope: PathScope,
}

/// Every path trait of a mapper, plus an any-of atom gate for the regex-only
/// ones (`mandatory_atom_set`: every match contains one of the atoms). Built
/// once per mapper: `evaluate_path_traits_for_file` runs this pass for every
/// member file, and rebuilding the list (a regex lookup per trait) and running
/// every path regex on every path was a measured cost.
#[derive(Debug, Default)]
pub(crate) struct PathTraitIndex {
    traits: Vec<PathTrait>,
    /// `gated[i]`: trait `i` only runs on entries the atom sweep nominated.
    gated: Vec<bool>,
    /// `[case-sensitive, ASCII-case-insensitive]` atom automata.
    automata: [Option<aho_corasick::AhoCorasick>; 2],
    atom_to_traits: [Vec<Vec<u32>>; 2],
}

impl PathTraitIndex {
    fn build(trait_definitions: &[crate::composite_rules::TraitDefinition]) -> Self {
        use crate::composite_rules::Condition;
        let traits: Vec<PathTrait> = trait_definitions
            .iter()
            .enumerate()
            .filter_map(|(trait_idx, trait_def)| {
                // `basename` matches the final path component; `path` matches the
                // full entry path (or its dir/base when scoped). Archive members
                // carry their real entry path, so `path` traits detect member
                // layouts (`node_modules/X/package.json`, nested `*.jar!…`, …).
                let Condition::Path(PathQuery {
                    exact,
                    substr,
                    regex,
                    case_insensitive,
                    basename,
                    dirname,
                    ..
                }) = &trait_def.r#if
                else {
                    return None;
                };
                let case_insensitive = *case_insensitive;
                let lower = |s: &String| {
                    if case_insensitive {
                        s.to_lowercase()
                    } else {
                        s.clone()
                    }
                };
                Some(PathTrait {
                    trait_idx,
                    exact: exact.as_ref().map(lower),
                    substr: substr.as_ref().map(lower),
                    // Resolved via `lazy_regex` (applies `(?i)` when
                    // case-insensitive), as the per-entry path did.
                    regex: regex.as_deref().and_then(|r| {
                        crate::composite_rules::condition::lazy_regex(Some(r), case_insensitive)
                    }),
                    case_insensitive,
                    scope: if *basename {
                        PathScope::Base
                    } else if *dirname {
                        PathScope::Dir
                    } else {
                        PathScope::Full
                    },
                })
            })
            .collect();

        let mut gated = vec![false; traits.len()];
        let mut patterns: [Vec<String>; 2] = [Vec::new(), Vec::new()];
        let mut slots: [rustc_hash::FxHashMap<String, usize>; 2] = Default::default();
        let mut atom_to_traits: [Vec<Vec<u32>>; 2] = [Vec::new(), Vec::new()];
        for (ti, pt) in traits.iter().enumerate() {
            if pt.exact.is_some() || pt.substr.is_some() || pt.regex.is_none() {
                continue;
            }
            let Condition::Path(PathQuery {
                regex: Some(raw), ..
            }) = &trait_definitions[pt.trait_idx].r#if
            else {
                continue;
            };
            // Atoms of the pattern `lazy_regex` actually compiled.
            let atoms = if pt.case_insensitive {
                crate::capabilities::derivation_memo::mandatory_atom_set(&format!("(?i){raw}"))
            } else {
                crate::capabilities::derivation_memo::mandatory_atom_set(raw)
            };
            let Some(atoms) = atoms else { continue };
            if atoms.is_empty() || atoms.iter().any(|(a, _)| a.is_empty()) {
                continue;
            }
            gated[ti] = true;
            for (atom, ci) in &atoms {
                let k = usize::from(*ci);
                let key = if *ci {
                    atom.to_ascii_lowercase()
                } else {
                    atom.clone()
                };
                let slot = *slots[k].entry(key.clone()).or_insert_with(|| {
                    patterns[k].push(key);
                    atom_to_traits[k].push(Vec::new());
                    patterns[k].len() - 1
                });
                atom_to_traits[k][slot].push(ti as u32);
            }
        }
        let build = |pats: &[String], ci: bool| {
            if pats.is_empty() {
                return Ok(None);
            }
            aho_corasick::AhoCorasick::builder()
                .ascii_case_insensitive(ci)
                .build(pats)
                .map(Some)
        };
        match (build(&patterns[0], false), build(&patterns[1], true)) {
            (Ok(cs), Ok(ci)) => Self {
                traits,
                gated,
                automata: [cs, ci],
                atom_to_traits,
            },
            // A gate that failed to build must never hide a match.
            _ => Self {
                gated: vec![false; traits.len()],
                traits,
                automata: [None, None],
                atom_to_traits: [Vec::new(), Vec::new()],
            },
        }
    }
}

impl super::CapabilityMapper {
    /// A decoded layer belongs to its source file for file-scoped exclusions.
    /// Never import context through an archive-member edge: reference data in
    /// one member must not suppress executable code in another member.
    fn recheck_decoded_file_exclusions(&self, report: &mut AnalysisReport) {
        use rustc_hash::FxHashSet;
        let mut order: Vec<usize> = (0..report.files.len()).collect();
        order.sort_by_key(|&idx| report.files[idx].depth);
        let mut path_order: Vec<usize> = (0..report.files.len()).collect();
        path_order.sort_unstable_by(|&a, &b| report.files[a].path.cmp(&report.files[b].path));
        for idx in order {
            let child_path = &report.files[idx].path;
            let Some(split) = child_path.rfind("##") else {
                continue;
            };
            // The last edge must be a decoding, not a member of a decoded archive.
            if child_path.rfind("!!").is_some_and(|member| member > split) {
                continue;
            }
            let parent_path = &child_path[..split];
            let parent_findings = if parent_path == report.target.path {
                report.findings.clone()
            } else if let Ok(position) =
                path_order.binary_search_by(|&i| report.files[i].path.as_str().cmp(parent_path))
            {
                report.files[path_order[position]].findings.clone()
            } else {
                continue;
            };
            let original: FxHashSet<_> = report.files[idx]
                .findings
                .iter()
                .map(|f| f.id.clone())
                .collect();
            let mut context: Vec<_> = report.files[idx]
                .findings
                .iter()
                .chain(&parent_findings)
                .map(|f| {
                    let mut slim = Finding::new(f.id.clone(), f.kind.clone(), "", f.conf);
                    slim.crit = f.crit;
                    slim
                })
                .collect();
            self.apply_retroactive_unless_suppression_to_findings(&mut context, None);
            let surviving: FxHashSet<_> = context.iter().map(|f| f.id.clone()).collect();
            let removed: FxHashSet<_> = original.difference(&surviving).cloned().collect();
            if removed.is_empty() {
                continue;
            }
            let child_id = report.files[idx].id;
            report.files[idx]
                .findings
                .retain(|f| !removed.contains(&f.id));
            // Remove only copies explicitly attributed to this decoded child.
            report
                .findings
                .retain(|f| f.src != Some(child_id) || !removed.contains(&f.id));
            for file in &mut report.files {
                file.findings
                    .retain(|f| f.src != Some(child_id) || !removed.contains(&f.id));
            }
        }
    }

    /// Re-evaluate explicit parent-aware downgrades throughout the flat file
    /// tree. Root children use the root report; deeper children use only their
    /// immediate parent's findings. Process parents before children so a
    /// parent's own downgrade is reflected in the context seen below it.
    pub(crate) fn reeval_parent_scope_in_file_tree(
        &self,
        report: &mut AnalysisReport,
        root_bytes: &[u8],
        root_type: RuleFileType,
    ) {
        if report.files.is_empty() {
            return;
        }
        self.recheck_decoded_file_exclusions(report);

        // Most members have no explicit parent-aware downgrade at all. Avoid
        // evaluating every archive member just to discover there is nothing
        // to re-evaluate. Retain parent-before-child order
        // for the affected files so descendants see any parent downgrades.
        let composite_by_id = self.composite_id_index();
        let has_parent_downgrade = |finding: &Finding| {
            self.trait_id_map
                .get(finding.id.as_str())
                .and_then(|&idx| self.trait_definitions[idx].downgrade.as_ref())
                .or_else(|| {
                    composite_by_id
                        .get(finding.id.as_str())
                        .and_then(|&idx| self.composite_rules[idx].downgrade.as_ref())
                })
                .is_some_and(|downgrade| {
                    matches!(
                        downgrade.scope,
                        Some(
                            crate::composite_rules::Scope::Parent
                                | crate::composite_rules::Scope::FileOrParent
                        )
                    )
                })
        };
        let mut order: Vec<usize> = report
            .files
            .iter()
            .enumerate()
            .filter(|(_, file)| file.depth > 0 && file.findings.iter().any(has_parent_downgrade))
            .map(|(idx, _)| idx)
            .collect();
        if order.is_empty() {
            return;
        }
        order.sort_by_key(|&idx| (report.files[idx].depth, report.files[idx].id));
        let file_indices: HashMap<u32, usize> = report
            .files
            .iter()
            .enumerate()
            .map(|(idx, file)| (file.id, idx))
            .collect();
        let mut path_order: Vec<usize> = (0..report.files.len()).collect();
        path_order.sort_unstable_by(|&left, &right| {
            report.files[left].path.cmp(&report.files[right].path)
        });
        // Context metadata must see the initial report, while immediate-parent
        // findings must include earlier downgrades. Defer writes to the report
        // and overlay only those scalar edits on the immediate parent. This
        // avoids retaining two deep copies of the entire archive report.
        let mut updates: HashMap<usize, Vec<FindingDowngrade>> = HashMap::new();
        let section_map = SectionMap::default();

        for idx in order {
            let (parent_id, depth) = {
                let child = &report.files[idx];
                (child.parent_id, child.depth)
            };
            let (parent_findings, parent_bytes, parent_type) = if depth == 1 {
                (
                    Cow::Borrowed(report.findings.as_slice()),
                    root_bytes,
                    root_type,
                )
            } else {
                let parent_idx = parent_id
                    .and_then(|id| file_indices.get(&id).copied())
                    .or_else(|| {
                        let parent_path = immediate_parent_path(&report.files[idx].path)?;
                        path_order
                            .binary_search_by(|&candidate| {
                                report.files[candidate].path.as_str().cmp(parent_path)
                            })
                            .ok()
                            .map(|position| path_order[position])
                    });
                let Some(parent_idx) = parent_idx else {
                    continue;
                };
                let parent = &report.files[parent_idx];
                let mut parent_findings = Cow::Borrowed(parent.findings.as_slice());
                if let Some(edits) = updates.get(&parent_idx) {
                    for edit in edits {
                        edit.apply(parent_findings.to_mut());
                    }
                }
                (
                    parent_findings,
                    &[][..],
                    RuleFileType::from_str(&parent.file_type),
                )
            };
            // Root contexts retain their original own+extra finding order;
            // nested contexts exclude all more distant ancestor findings.
            let own_findings = if depth == 1 {
                report.findings.as_slice()
            } else {
                &[]
            };
            let parent_ctx = EvaluationContext::new_with_findings(
                report,
                parent_bytes,
                parent_type,
                &self.platforms,
                FindingScope::new(own_findings, Some(&parent_findings)),
                None,
            )
            .with_section_map(&section_map);
            let edits = self.parent_scope_downgrades(&report.files[idx].findings, &parent_ctx);
            if !edits.is_empty() {
                updates.insert(idx, edits);
            }
        }
        let mut touched: rustc_hash::FxHashSet<String> = rustc_hash::FxHashSet::default();
        for (idx, edits) in updates {
            let child_id = report.files[idx].id;
            for edit in edits {
                edit.apply(&mut report.files[idx].findings);
                touched.insert(report.files[idx].findings[edit.index].id.to_string());
                // The member's finding was already rolled up into its
                // containers (root and nested archives) before this pass, so
                // lower the copies attributed to this child too, or the
                // container keeps reporting the pre-downgrade crit. Before
                // finalize a copy names its member only through evidence
                // located `archive:<member>[:<inner location>]`; one pooled
                // from several members keeps its crit, since another member
                // may still carry it undowngraded.
                let finding_id = report.files[idx].findings[edit.index].id.clone();
                let child_leaf =
                    crate::types::core::leaf_member(&report.files[idx].path).to_owned();
                let names_child = |location: &str| {
                    location.strip_prefix("archive:").is_some_and(|rel| {
                        let member = rel.rsplit('!').next().unwrap_or(rel);
                        member
                            .strip_prefix(child_leaf.as_str())
                            .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
                    })
                };
                let from_child = |copy: &Finding| {
                    if copy.src.is_some() {
                        return copy.src == Some(child_id);
                    }
                    let mut located = copy
                        .evidence
                        .iter()
                        .filter_map(|e| e.location.as_deref())
                        .filter(|l| l.starts_with("archive:"))
                        .peekable();
                    located.peek().is_some() && located.all(names_child)
                };
                let lower = |copy: &mut Finding| {
                    if copy.id == finding_id && copy.crit > edit.crit && from_child(copy) {
                        copy.crit = edit.crit;
                        copy.downgraded = edit.downgraded;
                    }
                };
                report.findings.iter_mut().for_each(lower);
                for (other, file) in report.files.iter_mut().enumerate() {
                    if other != idx {
                        file.findings.iter_mut().for_each(lower);
                    }
                }
            }
        }
        if !touched.is_empty() {
            lower_pooled_rollups(report, &touched);
        }
    }

    /// Evaluate composite rules against an analysis report.
    /// `inline_yara` supplies pre-scanned results from the combined YARA engine.
    ///
    /// `layer_findings` are the findings of the file's decoded layers (the
    /// `##` records: an escaped or encoded blob the file carries, analyzed as
    /// code). They are inputs only: a composite may take a leg from them, and
    /// one a layer already fired is not fired again, but none of them is
    /// returned. A decoded layer is part of its file, so a rule gated on the
    /// file's type has to see what was decoded out of it; the layer, analyzed
    /// on its own, is not of that type.
    ///
    /// `view_findings` are the findings of the file's plaintext views (`##`
    /// records with no encoding chain: a page's inline scripts, a PHP block in
    /// JavaScript). They supply legs the same way, but a composite a view
    /// fired is still evaluated here: a view is the file's own text, so the
    /// file may hold closer or different evidence for the same rule (a
    /// password field in the page's markup, not only in its script), and a
    /// composite taking the view's copy as a leg would lose it.
    ///
    /// Platform filtering is controlled by the `platform` field set via `with_platform()`.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn evaluate_composite_rules(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
        section_map: &SectionMap,
        arch_ranges: Option<&[(Arch, std::ops::Range<usize>)]>,
        suppressions: Option<&crate::types::SuppressionSink>,
        layer_findings: &[Finding],
        view_findings: &[Finding],
    ) -> Vec<Finding> {
        // Determine file type from report (platform comes from self.platform)
        let file_type = self.evaluation_file_type(report, binary_data.len());

        // A container report aggregates tens of thousands of members' strings,
        // kv, and evidence, and evaluating the rule set over that value pool is
        // the dominant single-threaded finalize cost on large package archives.
        // Rules within one
        // fixed-point iteration are independent (each sees the same immutable
        // ctx snapshot; new findings land only after the collect), so large
        // reports fan the rule loop across the pool. Small files stay
        // sequential: their per-rule work is microseconds and rayon's fan-out
        // overhead would dominate — which is the regime the old always-serial
        // loop was written for.
        let parallel_rules = report.files.len() >= 32 || report.strings.len() >= 20_000;
        // Bitset filter first: it excludes most rules on small files with one
        // dense-index probe. Rules travel with their position in
        // `composite_rules`, and "already produced" is a flag per position:
        // composite ids are unique (the loader keys them by id) and a
        // composite's finding carries its own id, so the flag is exactly the
        // former string-set membership without hashing a rule id per rule per
        // fixed-point round (a measured leaf on many-member archives).
        let eval_rules = |rules: &[(usize, &crate::composite_rules::CompositeTrait)],
                          seen_rules: &[bool],
                          matched_bits: &TraitBitSet,
                          ctx: &EvaluationContext<'_>|
         -> Vec<(usize, Finding)> {
            use rayon::prelude::*;
            if parallel_rules && crate::rayon_nest::inner_work_parallel() {
                rules
                    .par_iter()
                    .filter(|(_, rule)| matched_bits.contains_all(&rule.required_trait_indices))
                    .filter(|(pos, _)| !seen_rules[*pos])
                    .filter_map(|(pos, rule)| rule.evaluate_pregated(ctx).map(|f| (*pos, f)))
                    .collect()
            } else {
                rules
                    .iter()
                    .filter(|(_, rule)| matched_bits.contains_all(&rule.required_trait_indices))
                    .filter(|(pos, _)| !seen_rules[*pos])
                    .filter_map(|(pos, rule)| rule.evaluate_pregated(ctx).map(|f| (*pos, f)))
                    .collect()
            }
        };

        // The layer findings lead the accumulated set, so every context below
        // sees them alongside the composites found so far; they are split off
        // again before returning.
        let layer_count = layer_findings.len() + view_findings.len();
        let mut all_findings: Vec<Finding> = Vec::with_capacity(layer_count + 100);
        all_findings.extend_from_slice(layer_findings);
        all_findings.extend_from_slice(view_findings);

        // Track which composite IDs have already matched (including original findings)
        let mut matched_bits = TraitBitSet::with_capacity(self.trait_definitions.len());
        // Seeded from the findings already present (one probe per finding,
        // never a pass over the rule set: that pass, per archive member, cost
        // more than the string-set checks it replaced).
        let composite_by_id = self.composite_id_index();
        let mut seen_rules: Vec<bool> = vec![false; self.composite_rules.len()];
        for finding in report.findings.iter().chain(layer_findings) {
            if let Some(&pos) = composite_by_id.get(finding.id.as_str()) {
                seen_rules[pos] = true;
            }
            if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                matched_bits.insert(idx);
            }
        }
        // A view's findings gate rules in, but do not mark them produced.
        for finding in view_findings {
            if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                matched_bits.insert(idx);
            }
        }

        // One set of per-file lazy caches for every context this call builds
        // (fixed-point iterations re-create the context to refresh the finding
        // scope, but the file's bytes and strings never change).
        let file_caches = crate::composite_rules::context::FileEvalCaches::default();
        // Work lists prefiltered by the static gates (platform, file type,
        // positive/negative split) — memoized per file type on the mapper.
        // `CompositeTrait::evaluate` still runs its own gates for the dynamic
        // ones (arch, size); the static ones it re-checks are already known
        // to pass. Skip-reason debug info is unaffected: contexts built here
        // never carry a debug collector.
        let worklists = self.composite_worklists(file_type);
        let positive_rules: Vec<(usize, &crate::composite_rules::CompositeTrait)> = worklists
            .positive
            .iter()
            .map(|&i| (i as usize, &self.composite_rules[i as usize]))
            .collect();
        let negative_rules: Vec<(usize, &crate::composite_rules::CompositeTrait)> = worklists
            .negative
            .iter()
            .map(|&i| (i as usize, &self.composite_rules[i as usize]))
            .collect();

        // Pass 1: Iterative evaluation of positive rules to reach a stable fixed-point
        const MAX_ITERATIONS: usize = 10;
        for _ in 0..MAX_ITERATIONS {
            let mut ctx = EvaluationContext::new(
                report,
                binary_data,
                file_type,
                &self.platforms,
                if all_findings.is_empty() {
                    None
                } else {
                    Some(&all_findings)
                },
                cached_ast,
            )
            .with_suppressions(suppressions)
            .with_section_map(section_map)
            .with_file_caches(&file_caches);
            if let Some(results) = inline_yara {
                ctx = ctx.with_inline_yara(results);
            }
            if let Some(ranges) = arch_ranges {
                ctx = ctx.with_arch_ranges(ranges);
            }

            // Evaluate positive rules (parallel only for container-scale reports)
            let new_findings: Vec<(usize, Finding)> =
                eval_rules(&positive_rules, &seen_rules, &matched_bits, &ctx);

            if new_findings.is_empty() {
                break;
            }

            // Add new findings to the accumulated set
            for (pos, finding) in new_findings {
                seen_rules[pos] = true;
                if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                    matched_bits.insert(idx);
                }
                all_findings.push(finding);
            }
        }

        // Pass 2: Iteratively evaluate negative rules and re-run positive rules until fixed point.
        //
        // Negative rules (those with `unless:`) are deferred from Pass 1 so their exclusions see
        // the complete positive set. But once a negative rule fires, a downstream positive rule
        // may depend on it — so after each negative pass we re-run positive rules, and vice
        // versa, until no new findings appear.
        for _ in 0..MAX_ITERATIONS {
            let mut ctx = EvaluationContext::new(
                report,
                binary_data,
                file_type,
                &self.platforms,
                if all_findings.is_empty() {
                    None
                } else {
                    Some(&all_findings)
                },
                cached_ast,
            )
            .with_suppressions(suppressions)
            .with_section_map(section_map)
            .with_file_caches(&file_caches);
            if let Some(results) = inline_yara {
                ctx = ctx.with_inline_yara(results);
            }
            if let Some(ranges) = arch_ranges {
                ctx = ctx.with_arch_ranges(ranges);
            }

            let negative_findings: Vec<(usize, Finding)> =
                eval_rules(&negative_rules, &seen_rules, &matched_bits, &ctx);

            if negative_findings.is_empty() {
                break;
            }
            drop(ctx);
            for (pos, finding) in negative_findings {
                seen_rules[pos] = true;
                if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                    matched_bits.insert(idx);
                }
                all_findings.push(finding);
            }

            // Re-run positive rules to a fixed point against the enriched findings
            for _ in 0..MAX_ITERATIONS {
                let mut ctx = EvaluationContext::new(
                    report,
                    binary_data,
                    file_type,
                    &self.platforms,
                    Some(&all_findings),
                    cached_ast,
                )
                .with_suppressions(suppressions)
                .with_section_map(section_map)
                .with_file_caches(&file_caches);
                if let Some(results) = inline_yara {
                    ctx = ctx.with_inline_yara(results);
                }
                if let Some(ranges) = arch_ranges {
                    ctx = ctx.with_arch_ranges(ranges);
                }

                let new_findings: Vec<(usize, Finding)> =
                    eval_rules(&positive_rules, &seen_rules, &matched_bits, &ctx);

                if new_findings.is_empty() {
                    break;
                }
                drop(ctx);
                for (pos, finding) in new_findings {
                    seen_rules[pos] = true;
                    if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                        matched_bits.insert(idx);
                    }
                    all_findings.push(finding);
                }
            }
        }

        // Pass 3: Re-evaluate downgrades for all findings now that the full context is available.
        // This handles cases where a finding's downgrade depends on another composite that
        // wasn't available when it was first evaluated.
        self.reeval_downgrades(
            &mut all_findings,
            layer_count,
            report,
            binary_data,
            cached_ast,
            file_type,
            section_map,
            suppressions,
        );
        // Excessive-line-length detection (>1MB single line) is emitted by YAML
        // traits, not here: the only input is the `text.max_line_length` metric.
        // JS/TS megabyte lines → line-shape::js-megabyte-single-line (notable);
        // other scripts/source → line-length::excessive-line-length (suspicious).
        // Both carry the binary-blob / minified-bundle carve-outs as `unless:`.

        all_findings.split_off(layer_count)
    }

    /// Re-evaluate downgrade conditions for all findings using the complete finding set.
    /// This handles ordering issues where a composite's downgrade depends on another composite.
    /// `findings[..first]` are context only (a file's decoded-layer findings):
    /// they can satisfy a downgrade condition but are not themselves re-evaluated.
    #[allow(clippy::too_many_arguments)]
    fn reeval_downgrades(
        &self,
        findings: &mut [Finding],
        first: usize,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        file_type: RuleFileType,
        section_map: &SectionMap,
        suppressions: Option<&crate::types::SuppressionSink>,
    ) {
        // Shared lazy rule-ID index: this runs once per analyzed file, so a
        // per-call map build dominated small-member archive corpora.
        let composite_map = self.composite_id_index();
        let file_caches = crate::composite_rules::context::FileEvalCaches::default();

        // First pass: collect new criticalities (can't mutate while borrowing for context)
        let updates: Vec<(usize, Criticality)> = {
            // Create final context with all findings (immutable borrow)
            let ctx = EvaluationContext::new(
                report,
                binary_data,
                file_type,
                &self.platforms,
                Some(findings),
                cached_ast,
            )
            .with_suppressions(suppressions)
            .with_section_map(section_map)
            .with_file_caches(&file_caches);

            findings
                .iter()
                .enumerate()
                .skip(first)
                .filter_map(|(i, finding)| {
                    // Every downgrade, whatever its scope: this context holds
                    // only this file's findings, so a file-scoped downgrade
                    // cannot reach another member here. (The scope filter
                    // belongs to `reeval_downgrades_cross_scope`, whose context
                    // adds container findings.) Evaluated from the declared
                    // tier and applied only when lower, so a downgrade that
                    // already fired at match time is not applied twice.
                    let rule = composite_map
                        .get(finding.id.as_str())
                        .map(|&i| &self.composite_rules[i])?;
                    let downgrade_rules = rule.downgrade.as_ref()?;
                    if downgrade_rules.scope == Some(crate::composite_rules::Scope::Parent) {
                        return None;
                    }
                    let new_crit = rule.evaluate_downgrade(downgrade_rules, &rule.crit, &ctx);
                    (new_crit < finding.crit).then_some((i, new_crit))
                })
                .collect()
        };

        // Second pass: apply updates
        for (idx, new_crit) in updates {
            // Mark the demotion so `strip_unmatched_traits` keeps the finding at
            // the tier the downgrade asked for instead of dropping it as an
            // unreferenced low-tier finding.
            findings[idx].downgraded = true;
            findings[idx].crit = new_crit;
        }
    }

    /// Re-evaluate downgrades on `target_findings` with `extra_findings` mixed
    /// into the evaluation context.
    ///
    /// Used after container-level composites have been added to the report:
    /// per-file findings get a second chance to apply downgrades that
    /// reference container-level traits (e.g. a per-file `cookies-get-all`
    /// trait whose downgrade clause references the container-level
    /// `metadata/file/format/browser-extension::mozilla-extension` composite).
    ///
    /// Idempotent: each finding's downgrade is re-evaluated starting from
    /// the trait/composite's *declared* criticality (looked up in
    /// `trait_definitions` / `composite_rules`), not from the finding's
    /// current crit. Calling this twice yields the same result as calling
    /// it once.
    pub(crate) fn reeval_downgrades_cross_scope(
        &self,
        target_findings: &mut [crate::types::Finding],
        extra_findings: &[crate::types::Finding],
        report: &AnalysisReport,
        binary_data: &[u8],
        file_type: RuleFileType,
        section_map: &SectionMap,
    ) {
        self.reeval_downgrades_cross_scope_at_path(
            target_findings,
            extra_findings,
            report,
            binary_data,
            file_type,
            section_map,
            None,
        );
    }

    /// Container findings may gate a downgrade, but inline path conditions
    /// still describe the member whose finding is being reconsidered.
    pub(crate) fn reeval_downgrades_cross_scope_at_path(
        &self,
        target_findings: &mut [crate::types::Finding],
        extra_findings: &[crate::types::Finding],
        report: &AnalysisReport,
        binary_data: &[u8],
        file_type: RuleFileType,
        section_map: &SectionMap,
        target_path: Option<&str>,
    ) {
        if target_findings.is_empty() {
            return;
        }

        // The evaluator must see both the target's own findings (which
        // trait-reference conditions check against) and the container-level
        // extras. Only the target's few findings are cloned (they are mutated
        // below while the context still needs their pre-pass values); the
        // extras — invariant across the per-member fan-out — stay borrowed.
        // Scope order (report, target, extras) matches the old combined-slice
        // shape exactly.
        let target_snapshot: Vec<crate::types::Finding> = target_findings.to_vec();
        let file_caches = crate::composite_rules::context::FileEvalCaches::default();
        let mut ctx = EvaluationContext::new(
            report,
            binary_data,
            file_type,
            &self.platforms,
            Some(extra_findings),
            None,
        )
        .with_mid_findings(&target_snapshot)
        .with_section_map(section_map)
        .with_file_caches(&file_caches);
        ctx.target_path_override = target_path;

        // Shared lazy rule-ID index: this runs once per archive member in the
        // container phase, so a per-call map build dominated small-member
        // corpora.
        let composite_by_id = self.composite_id_index();

        for finding in target_findings.iter_mut() {
            // Atomic traits first: look up the TraitDefinition by id and
            // re-evaluate its downgrade clause if any.
            if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                let trait_def = &self.trait_definitions[idx];
                if let Some(downgrade) = &trait_def.downgrade
                    && downgrade_spans_container(downgrade)
                {
                    let new_crit = trait_def.evaluate_downgrade(downgrade, &trait_def.crit, &ctx);
                    if new_crit != finding.crit {
                        finding.downgraded = true;
                        finding.crit = new_crit;
                    }
                    continue;
                }
            }

            // Composite rules: same dance, but against composite_rules.
            if let Some(rule) = composite_by_id
                .get(finding.id.as_str())
                .map(|&i| &self.composite_rules[i])
                && let Some(downgrade) = &rule.downgrade
                && downgrade_spans_container(downgrade)
            {
                let new_crit = rule.evaluate_downgrade(downgrade, &rule.crit, &ctx);
                if new_crit != finding.crit {
                    finding.downgraded = true;
                    finding.crit = new_crit;
                }
            }
        }
    }

    /// Re-evaluate explicit parent-aware downgrades for an analyzed child.
    /// `scope: parent` sees only the immediate parent's findings;
    /// `scope: file-or-parent` sees both the child and its immediate parent.
    /// This is separate from archive pooling, so siblings and more distant
    /// ancestors are never admitted to either context.
    #[cfg(test)]
    pub(crate) fn reeval_downgrades_parent_scope(
        &self,
        target_findings: &mut [crate::types::Finding],
        parent_findings: &[crate::types::Finding],
        parent_report: &AnalysisReport,
        parent_bytes: &[u8],
        parent_type: RuleFileType,
        section_map: &SectionMap,
    ) {
        if target_findings.is_empty() {
            return;
        }

        let parent_ctx = EvaluationContext::new(
            parent_report,
            parent_bytes,
            parent_type,
            &self.platforms,
            Some(parent_findings),
            None,
        )
        .with_section_map(section_map);
        for edit in self.parent_scope_downgrades(target_findings, &parent_ctx) {
            edit.apply(target_findings);
        }
    }

    fn parent_scope_downgrades(
        &self,
        target_findings: &[Finding],
        parent_ctx: &EvaluationContext<'_>,
    ) -> Vec<FindingDowngrade> {
        let file_or_parent_ctx = parent_ctx.clone().with_mid_findings(target_findings);
        let mut edits = Vec::new();
        let composite_by_id = self.composite_id_index();

        for (index, finding) in target_findings.iter().enumerate() {
            let downgrade = self
                .trait_id_map
                .get(finding.id.as_str())
                .and_then(|&idx| self.trait_definitions[idx].downgrade.as_ref())
                .or_else(|| {
                    composite_by_id
                        .get(finding.id.as_str())
                        .and_then(|&idx| self.composite_rules[idx].downgrade.as_ref())
                });
            if let Some(downgrade) = downgrade
                && matches!(
                    downgrade.scope,
                    Some(
                        crate::composite_rules::Scope::Parent
                            | crate::composite_rules::Scope::FileOrParent
                    )
                )
            {
                let ctx = if downgrade.scope == Some(crate::composite_rules::Scope::Parent) {
                    parent_ctx
                } else {
                    &file_or_parent_ctx
                };
                let new_crit = if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                    let rule = &self.trait_definitions[idx];
                    rule.evaluate_downgrade(downgrade, &rule.crit, ctx)
                } else if let Some(rule) = composite_by_id
                    .get(finding.id.as_str())
                    .map(|&idx| &self.composite_rules[idx])
                {
                    rule.evaluate_downgrade(downgrade, &rule.crit, ctx)
                } else {
                    finding.crit
                };
                if new_crit < finding.crit {
                    edits.push(FindingDowngrade {
                        index,
                        crit: new_crit,
                        downgraded: true,
                    });
                }
            }
        }
        edits
    }

    /// Evaluate composite rules at the container level using findings from all nested files.
    ///
    /// This enables cross-file composite rules that can detect patterns spanning multiple
    /// files within an archive. For example:
    /// - "npm package with suspicious DLL" (package.json in one file + .dll in another)
    /// - "Python package with compiled binary" (setup.py + .so/.pyd files)
    ///
    /// # Arguments
    /// * `container_report` - The container/archive report to add findings to
    /// * `nested_findings` - All findings from nested files within the container
    /// * `file_type` - File type of the container (e.g., "archive", "zip")
    ///
    /// # Returns
    /// New findings that should be added to the container report
    #[must_use]
    /// Evaluate `type: basename` traits against a list of archive entry names.
    ///
    /// Archive members are extracted to temp paths, so per-file analyzers see
    /// basenames like `.tmpXXXXX` instead of the original entry names. This
    /// method evaluates basename traits using the real entry names and returns
    /// component-level findings that container composites can then reference.
    pub(crate) fn evaluate_basename_traits_for_entries(
        &self,
        entry_names: &[String],
    ) -> Vec<Finding> {
        use rayon::prelude::*;

        let index = self
            .path_trait_index
            .get_or_init(|| PathTraitIndex::build(&self.trait_definitions));

        // One atom sweep over the entry names nominates (trait, entry) pairs
        // for the gated regex traits. Scoped targets (basename / dirname) are
        // substrings of the full name, so a sweep of the full name sees every
        // atom a scoped match needs.
        let mut nominated: Vec<(u32, u32)> = Vec::new();
        if index.automata.iter().any(Option::is_some) {
            let mut seen: rustc_hash::FxHashSet<u32> = rustc_hash::FxHashSet::default();
            for (ei, name) in entry_names.iter().enumerate() {
                seen.clear();
                for (k, ac) in index.automata.iter().enumerate() {
                    let Some(ac) = ac else { continue };
                    for mat in ac.find_overlapping_iter(name.as_str()) {
                        for &ti in &index.atom_to_traits[k][mat.pattern().as_usize()] {
                            if seen.insert(ti) {
                                nominated.push((ti, ei as u32));
                            }
                        }
                    }
                }
            }
            // Stable: each trait's entries stay in entry order, so the first
            // nominated entry that matches is the first matching entry.
            nominated.sort_by_key(|&(ti, _)| ti);
        }

        // Each trait yields at most one finding (first matching entry), so the
        // collected order — and therefore the output — stays trait-definition
        // order exactly as the serial loop produced it.
        let evaluate = |(ti, pt): (usize, &PathTrait)| {
            let regex_only = pt.exact.is_none() && pt.substr.is_none();
            let matched_entry = if let (true, Some(re)) = (regex_only, &pt.regex) {
                // A regex-only trait leases its scratch cache once for all
                // entries; a checkout per entry was ~31 s of a benign run.
                re.with_scratch(|cache| {
                    let hit = |entry_name: &&String| {
                        let target = pt.scope.of(entry_name);
                        !target.is_empty() && re.is_match_cached(target, cache)
                    };
                    if index.gated[ti] {
                        let start = nominated.partition_point(|&(t, _)| (t as usize) < ti);
                        let end = nominated.partition_point(|&(t, _)| (t as usize) <= ti);
                        nominated[start..end]
                            .iter()
                            .map(|&(_, ei)| &entry_names[ei as usize])
                            .find(hit)
                    } else {
                        entry_names.iter().find(hit)
                    }
                })
            } else {
                entry_names.iter().find(|entry_name| {
                    let target: &str = pt.scope.of(entry_name);
                    if target.is_empty() {
                        return false;
                    }
                    if pt.exact.is_some() || pt.substr.is_some() {
                        let cmp_target = if pt.case_insensitive {
                            std::borrow::Cow::Owned(target.to_lowercase())
                        } else {
                            std::borrow::Cow::Borrowed(target)
                        };
                        if let Some(e) = &pt.exact {
                            cmp_target.as_ref() == e
                        } else {
                            // substr is Some by the branch condition above.
                            pt.substr.as_deref().is_some_and(|s| cmp_target.contains(s))
                        }
                    } else {
                        false
                    }
                })
            }?;
            let trait_def = &self.trait_definitions[pt.trait_idx];
            Some(Finding {
                precomputed_spans: None,
                src: None,
                id: trait_def.shared_id(),
                kind: FindingKind::Indicator,
                desc: trait_def.shared_desc(),
                conf: trait_def.conf,
                crit: trait_def.crit,
                mbc: trait_def.mbc.as_deref().map(Into::into),
                attack: trait_def.attack.as_deref().map(Into::into),
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "basename".to_string(),
                    source: "archive-entry".to_string(),
                    value: matched_entry.clone(),
                    // Archive-entry name match describes the whole entry.
                    location: Some("0x0".to_string()),
                    ..Default::default()
                }],
                match_count: 0,
                source_file: None,
                downgraded: false,
            })
        };
        if crate::rayon_nest::inner_work_parallel() {
            index
                .traits
                .par_iter()
                .enumerate()
                .filter_map(evaluate)
                .collect()
        } else {
            index
                .traits
                .iter()
                .enumerate()
                .filter_map(evaluate)
                .collect()
        }
    }

    /// Evaluate full-path and basename traits for one decoded file after an
    /// archive analyzer has rebased its virtual path to the real member path.
    /// Member analyzers may run against temporary extraction paths, so path
    /// traits need this final pass to see the provenance-bearing `!!` / `##`
    /// path. Unlike archive-inventory matching, a file-type gate is available
    /// here and is applied before returning findings.
    ///
    /// A decoded file has no name of its own: the path names its host, whose
    /// type is `host_file_type` when known. A trait must then admit the host
    /// as well as the decoded file, so a shell layer inside an ELF does not
    /// let a `for: [shell]` path rule match the ELF's location.
    pub(crate) fn evaluate_path_traits_for_file(
        &self,
        path: &str,
        file_type: &str,
        host_file_type: Option<&str>,
    ) -> Vec<Finding> {
        let mut findings = self.evaluate_basename_traits_for_entries(&[path.to_string()]);
        let rule_file_types: Vec<_> = std::iter::once(file_type)
            .chain(host_file_type)
            .map(|ft| self.detect_file_type(ft))
            .collect();
        findings.retain(|finding| {
            self.trait_id_map
                .get(finding.id.as_str())
                .and_then(|&idx| self.trait_definitions.get(idx))
                .is_some_and(|definition| {
                    rule_file_types.iter().all(|&ft| {
                        crate::composite_rules::FileType::rule_applies_to(&definition.r#for, ft)
                    })
                })
        });
        findings
    }

    /// `finding_origins` maps a finding id to the OR of the `type_bit`s of the
    /// files it was found in, and drives the `for:` filter (see
    /// `EvaluationContext::origin_allows`). `None` disables the filter for this
    /// container -- the honest option for a call site that cannot say where its
    /// findings came from, since the alternative is every composite here
    /// silently losing its legs.
    pub(crate) fn evaluate_container_composites<'a>(
        &self,
        container_report: &'a AnalysisReport,
        container_bytes: &[u8],
        nested_findings: impl IntoIterator<Item = &'a Finding>,
        file_type: &str,
        finding_origins: Option<&rustc_hash::FxHashMap<String, TypeMask>>,
    ) -> Vec<Finding> {
        self.evaluate_container_composites_with_members(
            container_report,
            container_bytes,
            nested_findings,
            file_type,
            finding_origins,
            None,
        )
    }

    /// Evaluate a synthetic container over borrowed immediate members. Their
    /// complete nodes remain available to sibling-value rules without making
    /// report-sized copies for every declaring member in the fetch phase.
    ///
    /// `container_bytes` are the container's own bytes, for rules that read
    /// headers or member names; they come from the caller, which already
    /// holds them, never from re-reading `target.path`.
    pub(crate) fn evaluate_container_composites_with_members<'a>(
        &self,
        container_report: &'a AnalysisReport,
        container_bytes: &[u8],
        nested_findings: impl IntoIterator<Item = &'a Finding>,
        file_type: &str,
        finding_origins: Option<&rustc_hash::FxHashMap<String, TypeMask>>,
        member_files: Option<&'a [&'a crate::types::FileAnalysis]>,
    ) -> Vec<Finding> {
        let nested_findings: Vec<&Finding> = nested_findings.into_iter().collect();
        // Detect file type for the container
        let rule_file_type = self.detect_file_type(file_type);

        // Track which composite IDs have already matched
        let mut seen_ids: rustc_hash::FxHashSet<String> = rustc_hash::FxHashSet::default();
        let mut matched_bits = TraitBitSet::with_capacity(self.trait_definitions.len());
        // Per-position mirror of `seen_ids` for the composite rules (see
        // `evaluate_composite_rules`): seeded here, then kept in step with
        // every composite finding this call records.
        let composite_by_id = self.composite_id_index();
        let mut seen_rules: Vec<bool> = vec![false; self.composite_rules.len()];
        for finding in &container_report.findings {
            seen_ids.insert(finding.id.clone().to_string());
            if let Some(&pos) = composite_by_id.get(finding.id.as_str()) {
                seen_rules[pos] = true;
            }
            if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                matched_bits.insert(idx);
            }
        }
        for finding in &nested_findings {
            if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                matched_bits.insert(idx);
            }
        }

        // Evaluate parent/container atomic traits against the container bytes first.
        // This allows archive-focused atomics (raw, yara, basename-derived, etc.)
        // to seed findings for later container-level composites.
        let mut parent_trait_ctx = EvaluationContext::new(
            container_report,
            container_bytes,
            rule_file_type,
            &self.platforms,
            None,
            None, // No AST for container
        );
        parent_trait_ctx.findings = crate::composite_rules::FindingScope::with_pooled(
            &container_report.findings,
            &nested_findings,
            &[],
        );
        parent_trait_ctx.member_files = member_files;
        // The index already encodes the same file-type and platform gates as
        // evaluate(). Reuse its cached bitset instead of walking every loaded
        // trait for each archive; retain index order and the dynamic gates.
        let mut container_findings: Vec<Finding> = self
            .match_indexes()
            .trait_index
            .applicable(&rule_file_type)
            .into_indices_static()
            .filter_map(|idx| self.trait_definitions[idx].evaluate(&parent_trait_ctx))
            .filter(|f| !seen_ids.contains(f.id.as_str()))
            .collect();

        for finding in &container_findings {
            seen_ids.insert(finding.id.clone().to_string());
            if let Some(&idx) = self.trait_id_map.get(finding.id.as_str()) {
                matched_bits.insert(idx);
            }
        }

        // The container's own `scope: file` composites (see
        // `evaluate_container_self_scope`) run first, so that a pooling
        // composite below can use one as a leg: `scope: outer` over an
        // APK-layout composite whose legs are the APK's own member list.
        self.evaluate_container_self_scope(
            container_report,
            member_files,
            container_bytes,
            rule_file_type,
            &mut container_findings,
            &mut seen_ids,
            &mut seen_rules,
        );

        // `finding_origins` is built by the caller before this pass, so it
        // cannot know the composites this pass produces. Without an origin a
        // finding fails every restricted `for:` mask (`origin_allows`), which
        // made a container-level composite unusable as a leg of another: the
        // chain resolved in `test-rules` (no origins) and never in a scan. A
        // composite produced here is a finding *of the container node*, so it
        // is stamped with the container's own type, exactly like the
        // container's atomics.
        let container_bit = rule_file_type.type_bit();
        let mut origins: Option<rustc_hash::FxHashMap<String, TypeMask>> = finding_origins.cloned();
        let stamp = |origins: &mut Option<rustc_hash::FxHashMap<String, TypeMask>>, id: &str| {
            if let Some(map) = origins.as_mut() {
                *map.entry(id.to_string()).or_default() |= container_bit;
            }
        };
        for finding in &container_findings {
            stamp(&mut origins, finding.id.as_str());
        }

        // Evaluate all composite rules at container level. Rules can match on:
        // - nested file findings across the container
        // - parent/container atomics evaluated above
        // This enables cross-file patterns like "npm package with .dll" and
        // parent-byte patterns like encrypted ZIP/APK members.

        // Reach a fixed point before finishing the negative-condition pass.
        // A fixed five-round budget can be consumed entirely by positive
        // dependencies, starving every rule with `unless:`. Each productive
        // round inserts at least one previously unseen composite ID, so the
        // rule count bounds productive rounds; one final round proves stability.
        for _ in 0..=self.composite_rules.len() {
            let mut ctx = EvaluationContext::new(
                container_report,
                container_bytes,
                rule_file_type,
                &self.platforms,
                None,
                None, // No AST for container
            );
            ctx.findings = crate::composite_rules::FindingScope::with_pooled(
                &container_report.findings,
                &nested_findings,
                &container_findings,
            );
            ctx.member_files = member_files;
            ctx.finding_origins = origins.as_ref();
            // Rules are evaluated one at a time so `for_mask` can be set per
            // rule: it is the only piece of per-rule state the condition
            // evaluators need, and threading it through every evaluator
            // signature would touch dozens of call sites to say one thing.
            // Same shape as `current_trait_idx` in the atomic pass.
            let candidates: Vec<(usize, &crate::composite_rules::CompositeTrait)> = self
                .composite_rules
                .iter()
                .enumerate()
                .filter(|(pos, _)| !seen_rules[*pos])
                // Only cross-file scopes may pool here. Nested findings arrive
                // without per-member evidence locations, so `Scope::key` maps
                // them all to the empty key: a `scope: file` (the default) or
                // `scope: leaf` composite would then treat two legs found in
                // two unrelated archive members as same-file evidence and fire.
                // That is the same hazard `evaluate_package_composites` below
                // already documents and excludes for.
                //
                // Nothing is lost by skipping them: file/leaf composites are
                // evaluated per member in the ordinary per-file pass, and
                // against the container itself when the archive is analyzed as
                // a file. Worked example: a source tarball carrying an HTML doc
                // with a `function foo(` and, in a different member, a `.js`
                // that calls `String.fromCharCode` satisfied
                // `noncode-container-selfdecoding-script` -- a hostile verdict
                // on OpenSSH, Caddy and llama_index, despite the rule declaring
                // `for: [chm, oledoc, ooxml, rtf, pdf]` and `scope: file`.
                .filter(|(_, rule)| {
                    // `scope:` omitted resolves to `Scope::File`: it is the
                    // enum's `#[default]`, and `apply_scope_filter` reads it
                    // through `unwrap_or_default`. Matching the raw `Option`
                    // here exempted only *explicit* `scope: file`, so the ~98%
                    // of composites that omit `scope:` pooled across unrelated
                    // archive members — the hazard described above, reached via
                    // the default instead of an explicit scope. Worked example:
                    // `perl-packed-hex-command-loader` (`for: [perl]`, hostile)
                    // fired on a Fedora source RPM with its four legs coming
                    // from four unrelated vendored files. Resolve the default
                    // via `effective_scope` (which also picks up the new
                    // archive/package `for:`-based defaults), so only rules
                    // that opt in to cross-file pooling are evaluated here.
                    !matches!(
                        rule.effective_scope(),
                        crate::composite_rules::Scope::File | crate::composite_rules::Scope::Leaf
                    )
                })
                .collect();
            let positive_candidates: Vec<_> = candidates
                .iter()
                .copied()
                .filter(|(_, rule)| !rule.has_negative_conditions())
                .collect();
            let negative_candidates: Vec<_> = candidates
                .into_iter()
                .filter(|(_, rule)| rule.has_negative_conditions())
                .collect();
            let mut new_findings: Vec<(usize, Finding)> = Vec::new();
            for (pos, rule) in positive_candidates {
                ctx.for_mask = rule.for_mask();
                if let Some(finding) = rule.evaluate(&ctx)
                    && !seen_ids.contains(finding.id.as_str())
                {
                    new_findings.push((pos, finding));
                }
            }
            ctx.for_mask = TypeMask::ALL;

            if !new_findings.is_empty() {
                drop(ctx);
                for (pos, finding) in new_findings {
                    stamp(&mut origins, finding.id.as_str());
                    seen_ids.insert(finding.id.clone().to_string());
                    seen_rules[pos] = true;
                    container_findings.push(finding);
                }
                let self_new = self.evaluate_container_self_scope(
                    container_report,
                    member_files,
                    container_bytes,
                    rule_file_type,
                    &mut container_findings,
                    &mut seen_ids,
                    &mut seen_rules,
                );
                for finding in &container_findings[self_new] {
                    stamp(&mut origins, finding.id.as_str());
                }
                continue;
            }

            // The positive set is stable, so `unless:` composites can now
            // observe any matching exception composites before they emit host
            // findings. Keep them in their own pass just as the ordinary
            // per-file evaluator does.
            let mut negative_findings: Vec<(usize, Finding)> = Vec::new();
            for (pos, rule) in negative_candidates {
                ctx.for_mask = rule.for_mask();
                if let Some(finding) = rule.evaluate(&ctx)
                    && !seen_ids.contains(finding.id.as_str())
                {
                    negative_findings.push((pos, finding));
                }
            }
            ctx.for_mask = TypeMask::ALL;
            drop(ctx);

            if negative_findings.is_empty() {
                break;
            }

            for (pos, finding) in negative_findings {
                stamp(&mut origins, finding.id.as_str());
                seen_ids.insert(finding.id.clone().to_string());
                seen_rules[pos] = true;
                container_findings.push(finding);
            }
        }

        // The loop above deliberately skips `scope: file` and `scope: leaf`
        // composites, because nested findings arrive without a member location
        // and pooling two unrelated members' legs into one "file" is how
        // OpenSSH and a Fedora source RPM earned hostile verdicts.
        //
        // That exclusion also caught a case with nothing to pool. A container's
        // *own* traits -- `chm.html_entry_count`, `rpm.*`, `vsix.*`, the parent
        // atomics evaluated above -- all describe one object: the container
        // file itself. A `scope: file` composite over those is asking exactly
        // what `scope: file` means, and the answer is unambiguous.
        //
        // So run the skipped rules once more against container-level findings
        // alone. Nested findings are not in scope here, which is what makes it
        // safe: there is only one file in this set, so nothing can pool.
        //
        // Symptom this fixes: fifteen abuse.ch CHM droppers scored four
        // notables and nothing else, while `chm-tiny-payload`,
        // `chm-single-entry-active-container` and two *hostile* rules written
        // for exactly that shape never fired. `test-rules` resolved them all,
        // which is the tell -- it evaluates a rule directly and never applies
        // this filter.
        self.evaluate_container_self_scope(
            container_report,
            member_files,
            container_bytes,
            rule_file_type,
            &mut container_findings,
            &mut seen_ids,
            &mut seen_rules,
        );

        tracing::debug!(
            findings = ?container_findings.iter().map(|finding| finding.id.as_str()).collect::<Vec<_>>(),
            "Container composites evaluated"
        );

        // Mark container-level findings with source context
        for finding in &mut container_findings {
            if finding.evidence.is_empty() {
                finding.evidence.push(Evidence {
                    method: "container-composite".to_string(),
                    source: "cross-file-analysis".to_string(),
                    value: "Finding spans multiple files in container".to_string(),
                    // Cross-file container finding — anchor at the container head.
                    location: Some("0x0".to_string()),
                    ..Default::default()
                });
            }
        }

        container_findings
    }

    /// Run the container's own `scope: file` / `scope: leaf` composites to a
    /// fixed point, over container-level findings only (never nested member
    /// findings, so nothing can pool across members). Appends new findings to
    /// `container_findings`, records them in `seen_ids`, and returns their range
    /// so the caller can stamp their origins without copying the findings.
    ///
    /// This was a single pass, so only the first level of a composite chain
    /// resolved: `android-apk-archive-layout` (three member-path atoms) fired,
    /// but every composite built on it -- at any crit, in any scope -- stayed
    /// dark in a scan while `test-rules`, which evaluates rules directly,
    /// reported them all matched.
    fn evaluate_container_self_scope<'a>(
        &self,
        container_report: &'a AnalysisReport,
        member_files: Option<&'a [&'a crate::types::FileAnalysis]>,
        container_bytes: &[u8],
        rule_file_type: RuleFileType,
        container_findings: &mut Vec<Finding>,
        seen_ids: &mut rustc_hash::FxHashSet<String>,
        seen_rules: &mut [bool],
    ) -> std::ops::Range<usize> {
        let self_rules: Vec<(usize, &crate::composite_rules::CompositeTrait)> = self
            .composite_rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| {
                matches!(
                    rule.effective_scope(),
                    crate::composite_rules::Scope::File | crate::composite_rules::Scope::Leaf
                )
            })
            .collect();
        let start = container_findings.len();
        // Each productive round adds at least one unseen rule id, so the rule
        // count bounds the rounds; the last round proves stability.
        for _ in 0..=self_rules.len() {
            let mut self_ctx = EvaluationContext::new(
                container_report,
                container_bytes,
                rule_file_type,
                &self.platforms,
                Some(container_findings),
                None, // No AST for container
            );
            self_ctx.member_files = member_files;
            // The old concatenation included the report's findings a second
            // time in the additional scope. Preserve its order and duplicate
            // semantics while borrowing both slices.
            self_ctx.findings = self_ctx
                .findings
                .with_mid_findings(&container_report.findings);
            let round: Vec<(usize, Finding)> = self_rules
                .iter()
                .filter(|(pos, _)| !seen_rules[*pos])
                .filter_map(|(pos, rule)| rule.evaluate(&self_ctx).map(|f| (*pos, f)))
                .collect();
            if round.is_empty() {
                break;
            }
            for (pos, finding) in round {
                seen_ids.insert(finding.id.clone().to_string());
                seen_rules[pos] = true;
                container_findings.push(finding);
            }
        }
        start..container_findings.len()
    }

    /// Evaluate package-scoped composites over the union of a fetched
    /// artifact's findings and its registry metadata's findings.
    ///
    /// This is the fetch-driven counterpart to
    /// [`Self::evaluate_container_composites`]: it lets a composite correlate a
    /// registry fact (deprecated, low downloads, fresh publish) with a behavior
    /// in the artifact bytes, even though the two were analyzed separately and
    /// never share an archive. The "package" is a synthetic, byte-less
    /// container — there is no on-disk file for the pair — so only
    /// finding-based composites pool here.
    ///
    /// Only composites with `scope: outer` participate. `scope: package` no
    /// longer means "pool by presence" — it now means "nearest enclosing
    /// package-ecosystem archive," a real location-keyed scope evaluated
    /// through the normal per-node pass, same as `archive`. `outer` is the
    /// one scope left that pools by presence (empty scope key), which is what
    /// this synthetic pass needs: by the time the artifact and registry
    /// reports meet they are both finalized, so their evidence locations are
    /// gone, and a location-keyed scope would collapse every item to the
    /// empty key and fire spuriously. `file`/`archive`/`leaf`/`package` are
    /// excluded for that reason. Returns only newly-matched composite
    /// findings (none of the `seed_findings` are echoed back).
    #[must_use]
    pub(crate) fn evaluate_package_composites<'a>(
        &self,
        seed_findings: impl IntoIterator<Item = &'a Finding>,
    ) -> Vec<Finding> {
        use crate::composite_rules::Scope;

        // Composites that pool across the artifact↔registry boundary.
        let package_rules: Vec<(usize, &crate::composite_rules::CompositeTrait)> = self
            .composite_rules
            .iter()
            .enumerate()
            .filter(|(_, r)| matches!(r.scope, Some(Scope::Outer)))
            .collect();
        if package_rules.is_empty() {
            return Vec::new();
        }

        // A synthetic node with no bytes of its own, typed `registry`: this is
        // the registry-joined view of the artifact, and `for:` gates it like
        // any other node. It used to be typed `all`, which worked only while
        // the gate treated a node of type `All` as a wildcard admitting every
        // rule. That carve-out is gone (see `evaluate_with_gates`), so a rule
        // that wants to run here says so: `for: [registry, <what it mixes>]`.
        let report = AnalysisReport::new(crate::types::TargetInfo {
            path: String::new(),
            file_type: "registry".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });
        let no_bytes: &[u8] = &[];

        // The seed may span many archive members. Borrow it through every
        // fixed-point iteration instead of cloning its findings and evidence
        // for every declaring member in the follow phase.
        let seed: Vec<&Finding> = seed_findings.into_iter().collect();
        let composite_by_id = self.composite_id_index();
        let mut seen_rules: Vec<bool> = vec![false; self.composite_rules.len()];
        for finding in &seed {
            if let Some(&pos) = composite_by_id.get(finding.id.as_str()) {
                seen_rules[pos] = true;
            }
        }
        let mut new_findings: Vec<Finding> = Vec::new();

        // Fixed-point loop so a package composite can feed another.
        const MAX_ITERATIONS: usize = 5;
        for _ in 0..MAX_ITERATIONS {
            // No `finding_origins` here: by the time the artifact and registry
            // reports meet, both are finalized and merged into one seed list
            // with no side marked, so nothing can be stamped. `for:` still
            // gates the node (it must name `registry`); it just cannot also
            // filter which side a leg came from. See SCOPE_PLAN.md ("Open").
            let mut ctx = EvaluationContext::new(
                &report,
                no_bytes,
                RuleFileType::Registry,
                &self.platforms,
                None,
                None,
            );
            ctx.findings = crate::composite_rules::FindingScope::from_pooled(&seed, &new_findings);
            let matched: Vec<(usize, Finding)> = package_rules
                .iter()
                .filter(|(pos, _)| !seen_rules[*pos])
                .filter_map(|(pos, rule)| rule.evaluate(&ctx).map(|f| (*pos, f)))
                .collect();
            if matched.is_empty() {
                break;
            }
            for (pos, finding) in matched {
                seen_rules[pos] = true;
                new_findings.push(finding);
            }
        }
        new_findings
    }
}

/// Whether a `downgrade:` asked to see evidence from outside its own file.
///
/// The default is [`Scope::File`], which is what `unless:` has always done: a
/// suppressor resolves against the file the rule matched in. Only a block that
/// explicitly widens its scope takes part in the container pass below, so one
/// archive member can no longer silence a rule in an unrelated member unless
/// the rule author asked for exactly that.
fn downgrade_spans_container(downgrade: &crate::composite_rules::DowngradeConditions) -> bool {
    downgrade.scope.unwrap_or_default().pools_members()
}

#[cfg(test)]
mod tests;
