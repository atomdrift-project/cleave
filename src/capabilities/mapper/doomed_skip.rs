//! Skip `eval_raw` for a component/baseline whose every consumer composite
//! is already unsatisfiable on this file.
//!
//! A component that matches but is never named by a *local* fired composite
//! is not evidence on that file. Official `strip_unmatched_traits` still
//! unions `trait_refs` across the report, so evaluating the regex just to
//! leave a copy for a sibling's composite is wasted work. This skip drops
//! those sibling-rescued copies; container-scoped composites are never
//! skipped (partners may live on another member).
//!
//! Never skip:
//! - notable+ traits
//! - `unless:` / `downgrade:` targets
//! - `any:` legs that can satisfy a composite alone
//! - traits required by `scope: outer|archive|package` composites
//! - directory-prefix / ambiguous short refs used as the only partner
//!
//! Rescue: if the file still has no notable+ after the non-doomed pass,
//! evaluate the doomed traits anyway so `rescue_low_tier` is unchanged.

use crate::composite_rules::{
    CompositeTrait, Condition, FileType, Platform, RawQuery, Scope, TextQuery, TraitDefinition,
    platforms_intersect,
};
use rustc_hash::FxHashMap;

use super::MatchIndexes;
use super::evaluate_traits::TraitEvalCache;

#[derive(Debug, Clone)]
struct AllConsumer {
    composite_idx: usize,
    other_partners: Vec<usize>,
}

#[derive(Debug, Default)]
pub(crate) struct DoomedSkipIndex {
    consumers: Vec<Vec<AllConsumer>>,
    never_skip: Vec<bool>,
}

impl DoomedSkipIndex {
    pub(super) fn build(
        traits: &[TraitDefinition],
        composites: &[CompositeTrait],
        trait_id_map: &std::collections::HashMap<String, usize>,
    ) -> Self {
        let n = traits.len();
        let mut never_skip = vec![false; n];
        let mut consumers = vec![Vec::new(); n];

        let mut leaf_hits: FxHashMap<&str, Vec<usize>> = FxHashMap::default();
        for (idx, def) in traits.iter().enumerate() {
            leaf_hits.entry(trait_leaf(&def.id)).or_default().push(idx);
        }
        let ids = IdIndex::new(traits, &leaf_hits);
        let short_unique: FxHashMap<&str, usize> = leaf_hits
            .iter()
            .filter_map(|(leaf, idxs)| {
                if idxs.len() == 1 {
                    Some((*leaf, idxs[0]))
                } else {
                    None
                }
            })
            .collect();

        let mut mark_never = |raw: &str| {
            for idx in ids.resolve_all(raw, trait_id_map) {
                if idx < n {
                    never_skip[idx] = true;
                }
            }
        };

        for def in traits {
            if let Some(unless) = &def.unless {
                for cond in unless {
                    collect_top_trait_ids(cond, &mut mark_never);
                }
            }
            if let Some(downgrade) = &def.downgrade {
                let mut ids = std::collections::BTreeSet::new();
                downgrade.collect_trait_refs(&mut ids);
                for id in ids {
                    mark_never(&id);
                }
            }
        }

        for (composite_idx, rule) in composites.iter().enumerate() {
            if let Some(unless) = &rule.unless {
                for cond in unless {
                    collect_top_trait_ids(cond, &mut mark_never);
                }
            }
            if let Some(downgrade) = &rule.downgrade {
                let mut ids = std::collections::BTreeSet::new();
                downgrade.collect_trait_refs(&mut ids);
                for id in ids {
                    mark_never(&id);
                }
            }

            let pools_across_members = matches!(
                rule.scope,
                Some(Scope::Outer | Scope::Archive | Scope::Package)
            );
            if pools_across_members {
                for id in all_trait_ids_in_all_any(rule) {
                    mark_never(&id);
                }
                continue;
            }

            if let Some(conds) = &rule.any {
                let required_from_any = rule.needs.unwrap_or(1);
                if required_from_any < conds.len() {
                    for cond in conds {
                        if let Condition::Trait { id } = cond {
                            mark_never(id);
                        }
                    }
                }
            }

            let mut required: Vec<usize> = Vec::new();
            if let Some(conds) = &rule.all {
                for cond in conds {
                    if let Condition::Trait { id } = cond
                        && let Some(idx) = resolve_unique(id, trait_id_map, &short_unique)
                    {
                        required.push(idx);
                    }
                }
            }
            if let Some(conds) = &rule.any {
                let required_from_any = rule.needs.unwrap_or(1);
                if required_from_any >= conds.len() {
                    for cond in conds {
                        if let Condition::Trait { id } = cond
                            && let Some(idx) = resolve_unique(id, trait_id_map, &short_unique)
                        {
                            required.push(idx);
                        }
                    }
                }
            }

            let partner_idxs = required;
            for &t_idx in &partner_idxs {
                let other_partners: Vec<usize> = partner_idxs
                    .iter()
                    .copied()
                    .filter(|&p| p != t_idx)
                    .collect();
                consumers[t_idx].push(AllConsumer {
                    composite_idx,
                    other_partners,
                });
            }
        }

        Self {
            consumers,
            never_skip,
        }
    }

    pub(super) fn should_skip(
        &self,
        trait_idx: usize,
        traits: &[TraitDefinition],
        composites: &[CompositeTrait],
        mapper_platforms: &[Platform],
        file_type: FileType,
        indexes: &MatchIndexes,
        cache: &TraitEvalCache<'_>,
    ) -> bool {
        if trait_idx >= self.never_skip.len() || self.never_skip[trait_idx] {
            return false;
        }
        let Some(def) = traits.get(trait_idx) else {
            return false;
        };
        if !matches!(
            def.crit,
            crate::types::Criticality::Component | crate::types::Criticality::Baseline
        ) {
            return false;
        }
        let list = &self.consumers[trait_idx];
        if list.is_empty() {
            return false;
        }
        let applicable: Vec<&AllConsumer> = list
            .iter()
            .filter(|c| {
                composites
                    .get(c.composite_idx)
                    .is_some_and(|rule| composite_applies(rule, mapper_platforms, file_type))
            })
            .collect();
        if applicable.is_empty() {
            return false;
        }
        applicable.iter().all(|c| {
            c.other_partners.iter().any(|&p| {
                partner_cannot_match(p, traits, mapper_platforms, file_type, indexes, cache)
            })
        })
    }
}

fn collect_top_trait_ids(cond: &Condition, mark: &mut impl FnMut(&str)) {
    if let Condition::Trait { id } = cond {
        mark(id);
    }
}

fn all_trait_ids_in_all_any(rule: &CompositeTrait) -> Vec<String> {
    let mut ids = Vec::new();
    for conds in [rule.all.as_deref(), rule.any.as_deref()]
        .into_iter()
        .flatten()
    {
        for cond in conds {
            if let Condition::Trait { id } = cond {
                ids.push(id.clone());
            }
        }
    }
    ids
}

fn trait_leaf(id: &str) -> &str {
    id.rsplit_once("::")
        .map_or(id, |(_, v)| v)
        .rsplit('/')
        .next()
        .unwrap_or(id)
}

fn resolve_unique(
    id: &str,
    exact: &std::collections::HashMap<String, usize>,
    short_unique: &FxHashMap<&str, usize>,
) -> Option<usize> {
    let id = id.trim_end_matches('/');
    if id.contains("::") {
        return exact.get(id).copied();
    }
    if id.contains('/') {
        return None;
    }
    short_unique.get(id).copied()
}

/// Sorted trait ids for directory-prefix lookups, plus the leaf map for bare
/// short refs. `unless:`/`downgrade:` refs are resolved for every trait and
/// composite at build time; the previous resolver walked all ~71k trait ids
/// with `starts_with`/`ends_with` per ref, which made this index cost ~5 s of
/// one thread on the first analysis of every process (memcmp-bound). Two
/// binary searches per prefix and one hash probe per leaf make the build a
/// few milliseconds.
struct IdIndex<'a> {
    /// `(id, index into traits)`, sorted by id.
    sorted: Vec<(&'a str, usize)>,
    leaf_hits: &'a FxHashMap<&'a str, Vec<usize>>,
}

impl<'a> IdIndex<'a> {
    fn new(traits: &'a [TraitDefinition], leaf_hits: &'a FxHashMap<&'a str, Vec<usize>>) -> Self {
        let mut sorted: Vec<(&str, usize)> = traits
            .iter()
            .enumerate()
            .map(|(idx, def)| (def.id.as_str(), idx))
            .collect();
        sorted.sort_unstable();
        Self { sorted, leaf_hits }
    }

    /// Indices of every id that starts with `prefix`, in id order.
    fn with_prefix<'p>(&'p self, prefix: &'p str) -> impl Iterator<Item = usize> + 'p {
        let start = self.sorted.partition_point(|(id, _)| *id < prefix);
        self.sorted[start..]
            .iter()
            .take_while(move |(id, _)| id.starts_with(prefix))
            .map(|(_, idx)| *idx)
    }

    /// Same contract as the old `resolve_all`: an exact `ns::leaf` id, a
    /// directory prefix (`ns/` — itself, `ns/…` legacy ids and `ns::…`), or a
    /// bare short name matching by leaf.
    fn resolve_all(
        &self,
        id: &str,
        exact: &std::collections::HashMap<String, usize>,
    ) -> Vec<usize> {
        let id = id.trim_end_matches('/');
        if id.contains("::") {
            return exact.get(id).copied().into_iter().collect();
        }
        if id.contains('/') {
            let mut out: Vec<usize> = exact.get(id).copied().into_iter().collect();
            out.extend(self.with_prefix(&format!("{id}::")));
            out.extend(self.with_prefix(&format!("{id}/")));
            out.sort_unstable();
            out.dedup();
            return out;
        }
        // A bare name matches every trait whose leaf is that name, which is
        // exactly the `::name` / `/name` suffix test the linear scan did.
        self.leaf_hits.get(id).cloned().unwrap_or_default()
    }
}

fn composite_applies(
    rule: &CompositeTrait,
    mapper_platforms: &[Platform],
    file_type: FileType,
) -> bool {
    if !platforms_intersect(&rule.platforms, mapper_platforms) {
        return false;
    }
    let wants_archive_family = rule.r#for.iter().any(FileType::is_archive);
    let pools_across_archive = matches!(
        rule.scope,
        Some(Scope::Outer | Scope::Archive | Scope::Package)
    );
    rule.r#for.contains(&FileType::All)
        || rule.r#for.contains(&file_type)
        || ((file_type == FileType::All || file_type.is_archive())
            && (wants_archive_family || pools_across_archive))
}

fn trait_applies_to_file(
    def: &TraitDefinition,
    mapper_platforms: &[Platform],
    file_type: FileType,
) -> bool {
    if !platforms_intersect(&def.platforms, mapper_platforms) {
        return false;
    }
    let wants_archive_family = def.r#for.iter().any(FileType::is_archive);
    let file_type_match = def.r#for.contains(&FileType::All)
        || def.r#for.contains(&file_type)
        || ((file_type == FileType::All || file_type.is_archive()) && wants_archive_family);
    file_type_match && def.r#if.can_match_file_type(&file_type)
}

fn partner_cannot_match(
    partner_idx: usize,
    traits: &[TraitDefinition],
    mapper_platforms: &[Platform],
    file_type: FileType,
    indexes: &MatchIndexes,
    cache: &TraitEvalCache<'_>,
) -> bool {
    let Some(def) = traits.get(partner_idx) else {
        return true;
    };
    if !trait_applies_to_file(def, mapper_platforms, file_type) {
        return true;
    }
    if indexes.symbol_match_index.is_symbol_trait(partner_idx)
        && !cache.symbol_matched_traits.contains(&partner_idx)
    {
        return true;
    }
    let has_content_regex = match &def.r#if {
        Condition::Raw(RawQuery { regex: Some(_), .. })
        | Condition::Raw(RawQuery { word: Some(_), .. }) => true,
        Condition::Text(TextQuery { regex: Some(_), .. })
        | Condition::Text(TextQuery { word: Some(_), .. }) => file_type.uses_raw_text_search(),
        _ => false,
    };
    if has_content_regex
        && cache.raw_regex_matches.is_some()
        && indexes
            .raw_content_regex_index
            .is_indexed_trait(partner_idx)
        && cache
            .raw_regex_matches
            .is_some_and(|s| !s.contains(&partner_idx))
    {
        return true;
    }
    let use_string_index = cache.source_text_prefiltered || !file_type.uses_raw_text_search();
    if use_string_index
        && indexes.string_match_index.is_exact_trait(partner_idx)
        && !cache.string_matched_traits.contains(&partner_idx)
    {
        return true;
    }
    if !file_type.uses_raw_text_search()
        && indexes.string_match_index.is_substr_trait(partner_idx)
        && !cache.string_matched_traits.contains(&partner_idx)
    {
        return true;
    }
    false
}
