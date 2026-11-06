//! Reference-graph checks: leg counts and orphaned components.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Find component traits that are never referenced by any composite rule or atomic trait.
///
/// Component traits (`crit: component`) are building blocks that should only exist to be
/// referenced by composite rules or by other traits via `if: id:` form. If a component
/// isn't referenced anywhere, it's "orphaned" and serves no purpose.
///
/// Returns: `Vec<(trait_id, source_file)>`
#[must_use]
/// Collect a composite's positive (`all:`/`any:`) trait references.
///
/// `unless:` and `downgrade:` are exclusions and deliberately ignored —
/// they suppress a match, they never supply the purpose-defining evidence.
pub(super) fn positive_trait_refs(rule: &CompositeTrait) -> Vec<String> {
    let mut refs = Vec::new();
    for conditions in [rule.all.as_ref(), rule.any.as_ref()].into_iter().flatten() {
        for cond in conditions {
            for id in cond.trait_references() {
                refs.push(id.clone());
            }
        }
    }
    refs
}

/// Every id a reference can name, indexed so that resolving one is a lookup.
///
/// Resolution used to scan every id in the tree for each distinct reference.
/// With ~40,000 ids and the tens of thousands of references the conviction
/// checks follow, that scan was over a minute of `cleave validate`, all of it
/// on the main thread.
pub(in super::super) struct ReferenceIndex<'a> {
    pub(super) ids: Vec<&'a str>,
    /// Positions into `ids`, ordered by id: exact and directory references
    /// are prefix ranges of it.
    pub(super) sorted: Vec<usize>,
    /// Positions into `ids`, keyed by the text after each id's last `:` or
    /// `/`, which is where a short-name reference must match.
    pub(super) by_tail: HashMap<&'a str, Vec<usize>>,
}

/// The text after the last `:` or `/`, or all of `id` when it has neither.
pub(super) fn tail(id: &str) -> &str {
    id.rsplit([':', '/']).next().unwrap_or(id)
}

impl<'a> ReferenceIndex<'a> {
    pub(in super::super) fn new(ids: Vec<&'a str>) -> Self {
        let mut sorted: Vec<usize> = (0..ids.len()).collect();
        sorted.sort_unstable_by_key(|&i| ids[i]);
        let mut by_tail: HashMap<&'a str, Vec<usize>> = HashMap::new();
        for (i, id) in ids.iter().enumerate() {
            by_tail.entry(tail(id)).or_default().push(i);
        }
        Self {
            ids,
            sorted,
            by_tail,
        }
    }

    /// Resolve a reference to the concrete ids it matches, mirroring the
    /// runtime resolver in `evaluate_merged`: an exact `::` reference matches
    /// one id; a bare short name (no `/`) suffix-matches `::name`/`/name`; a
    /// directory reference (has `/`, no `::`) prefix-matches the id itself,
    /// `dir::*`, and the whole `dir/*` subtree. A trailing slash is trimmed
    /// first. Matches come back in the order the ids were given.
    pub(in super::super) fn resolve(&self, reference: &str) -> Vec<&'a str> {
        let id = reference.trim_end_matches('/');
        let mut hits: Vec<usize> = if id.contains("::") {
            self.starting_with(id)
                .filter(|&i| self.ids[i] == id)
                .collect()
        } else if !id.contains('/') {
            let (suffix_new, suffix_legacy) = (format!("::{id}"), format!("/{id}"));
            self.by_tail
                .get(tail(id))
                .into_iter()
                .flatten()
                .copied()
                .filter(|&i| {
                    let f = self.ids[i];
                    f.ends_with(&suffix_new) || f.ends_with(&suffix_legacy)
                })
                .collect()
        } else {
            let (prefix_new, prefix_legacy) = (format!("{id}::"), format!("{id}/"));
            self.starting_with(id)
                .filter(|&i| {
                    let f = self.ids[i];
                    f == id || f.starts_with(&prefix_new) || f.starts_with(&prefix_legacy)
                })
                .collect()
        };
        hits.sort_unstable();
        hits.into_iter().map(|i| self.ids[i]).collect()
    }

    /// Positions of the ids that begin with `prefix`.
    pub(super) fn starting_with<'s>(&'s self, prefix: &'s str) -> impl Iterator<Item = usize> + 's {
        let start = self.sorted.partition_point(|&i| self.ids[i] < prefix);
        self.sorted[start..]
            .iter()
            .copied()
            .take_while(move |&i| self.ids[i].starts_with(prefix))
    }
}

/// Find `crit: hostile` composites that reference fewer than two distinct
/// notable-or-higher evidence legs anywhere in their positive (`all:`/`any:`)
/// reference tree.
///
/// Every genuine hostile pattern should rest on at least two legs an analyst would
/// want surfaced on their own — communications, code-execution, crypto, encoding,
/// privilege-escalation, sensitive-file, registry, or persistence capabilities
/// (the behaviours that earn at least `notable` per TAXONOMY.md). A hostile
/// composite assembled from fewer than two such legs signals that purpose-defining
/// capability has been buried at the wrong tier, or that the rule is low quality.
///
/// Resolution mirrors the loader: trait ids are fully qualified (`dir::id`),
/// directory references (`dir/path`, no `::`) expand to every id under that prefix,
/// and a leg that is itself a composite is followed transitively.
///
/// Returns the ids of the offending hostile composites.
#[must_use]
pub(crate) fn find_hostile_composites_with_too_few_notable_legs(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
) -> Vec<String> {
    use crate::types::Criticality;

    // Effective criticality (defaults already applied at load) for every trait and
    // composite, keyed by full id.
    let mut crit_by_id: HashMap<&str, Criticality> = HashMap::new();
    for t in trait_definitions {
        crit_by_id.insert(t.id.as_str(), t.crit);
    }
    for c in composite_rules {
        crit_by_id.insert(c.id.as_str(), c.crit);
    }
    // This exact analyzer-owned fact is emitted as Notable. Count it by its
    // declared criticality just like YAML evidence; unknown runtime ids remain
    // absent rather than receiving a namespace-wide validation exemption.
    crit_by_id.insert(
        crate::analyzers::ci_secret_file_flow::FACT_ID,
        Criticality::Notable,
    );
    crit_by_id.insert(
        crate::analyzers::ci_secret_file_flow::COLLECTOR_FACT_ID,
        Criticality::Notable,
    );
    let index = ReferenceIndex::new(crit_by_id.keys().copied().collect());
    let composite_by_id: HashMap<&str, &CompositeTrait> =
        composite_rules.iter().map(|c| (c.id.as_str(), c)).collect();

    fn add_limited(out: &mut Vec<String>, values: impl IntoIterator<Item = String>) {
        for value in values {
            if !out.contains(&value) {
                out.push(value);
                if out.len() == 2 {
                    break;
                }
            }
        }
    }

    fn collect_notable_for_id(
        id: &str,
        crit_by_id: &HashMap<&str, Criticality>,
        index: &ReferenceIndex<'_>,
        composite_by_id: &HashMap<&str, &CompositeTrait>,
        reference_cache: &mut HashMap<String, Vec<String>>,
        terminal_cache: &mut HashMap<String, Vec<String>>,
        visiting: &mut HashSet<String>,
    ) -> Vec<String> {
        if let Some(cached) = terminal_cache.get(id) {
            return cached.clone();
        }
        if !visiting.insert(id.to_string()) {
            return Vec::new();
        }

        let mut terminals = Vec::new();
        if let Some(sub) = composite_by_id.get(id) {
            for child in positive_trait_refs(sub) {
                let child_terms = collect_notable_for_reference(
                    &child,
                    crit_by_id,
                    index,
                    composite_by_id,
                    reference_cache,
                    terminal_cache,
                    visiting,
                );
                add_limited(&mut terminals, child_terms);
                if terminals.len() == 2 {
                    break;
                }
            }
            // A named notable composite with no notable terminal children is
            // itself the strongest honest evidence available.
            if terminals.is_empty()
                && crit_by_id
                    .get(id)
                    .is_some_and(|crit| *crit >= Criticality::Notable)
            {
                terminals.push(id.to_string());
            }
        } else if crit_by_id
            .get(id)
            .is_some_and(|crit| *crit >= Criticality::Notable)
        {
            terminals.push(id.to_string());
        }

        visiting.remove(id);
        terminal_cache.insert(id.to_string(), terminals.clone());
        terminals
    }

    fn collect_notable_for_reference(
        reference: &str,
        crit_by_id: &HashMap<&str, Criticality>,
        index: &ReferenceIndex<'_>,
        composite_by_id: &HashMap<&str, &CompositeTrait>,
        reference_cache: &mut HashMap<String, Vec<String>>,
        terminal_cache: &mut HashMap<String, Vec<String>>,
        visiting: &mut HashSet<String>,
    ) -> Vec<String> {
        let key = reference.trim_end_matches('/').to_string();
        let resolved = if let Some(cached) = reference_cache.get(&key) {
            cached.clone()
        } else {
            let ids = if key.contains("::") {
                crit_by_id
                    .contains_key(key.as_str())
                    .then_some(vec![key.clone()])
                    .unwrap_or_default()
            } else {
                index.resolve(&key).into_iter().map(str::to_owned).collect()
            };
            reference_cache.insert(key, ids.clone());
            ids
        };

        let mut terminals = Vec::new();
        for id in resolved {
            add_limited(
                &mut terminals,
                collect_notable_for_id(
                    &id,
                    crit_by_id,
                    index,
                    composite_by_id,
                    reference_cache,
                    terminal_cache,
                    visiting,
                ),
            );
            if terminals.len() == 2 {
                break;
            }
        }
        terminals
    }

    let mut violations = Vec::new();
    let mut reference_cache = HashMap::new();
    let mut terminal_cache = HashMap::new();
    for rule in composite_rules {
        if rule.crit != Criticality::Hostile
            || crate::capabilities::parsing::is_registry_security_hold_policy(
                &rule.id,
                rule.any.as_deref(),
                &rule.r#for,
                rule.scope,
            )
            || crate::capabilities::parsing::is_declared_dependency_security_hold_policy(
                &rule.id,
                rule.all.as_deref(),
                &rule.r#for,
                rule.scope,
            )
        {
            continue;
        }
        if super::super::composite::is_dependency_security_hold_policy(rule) {
            continue;
        }

        let mut terminals = Vec::new();
        let mut visiting = HashSet::new();
        for reference in positive_trait_refs(rule) {
            add_limited(
                &mut terminals,
                collect_notable_for_reference(
                    &reference,
                    &crit_by_id,
                    &index,
                    &composite_by_id,
                    &mut reference_cache,
                    &mut terminal_cache,
                    &mut visiting,
                ),
            );
            if terminals.len() == 2 {
                break;
            }
        }

        if terminals.len() < 2 {
            violations.push(rule.id.clone());
        }
    }
    violations
}

/// Does directory reference `dir` cover trait id `trait_id`?
///
/// Two details the naive `format!("{dir}::")` prefix missed, both of which made
/// a referenced component look orphaned:
/// * the reference is usually written with a trailing slash
///   (`metadata/file/catalog/identity/`), which turned the prefix into
///   `.../identity/::` and matched nothing;
/// * a directory also covers traits in its *sub*directories, which a `::`-only
///   prefix never matched.
pub(super) fn directory_covers(dir: &str, trait_id: &str) -> bool {
    let dir = dir.trim_end_matches('/');
    trait_id
        .strip_prefix(dir)
        .is_some_and(|rest| rest.starts_with("::") || rest.starts_with('/'))
}

pub(crate) fn find_orphaned_components(
    trait_definitions: &[TraitDefinition],
    composite_rules: &[CompositeTrait],
    trait_source_files: &std::collections::HashMap<String, String>,
) -> Vec<(String, String)> {
    use crate::types::Criticality;
    use std::collections::HashSet;

    // Collect all component trait IDs, sorted so the ones under a directory
    // are a single run found by binary search rather than a scan of all.
    let mut component_ids: Vec<&str> = trait_definitions
        .iter()
        .filter(|t| t.crit == Criticality::Component)
        .map(|t| t.id.as_str())
        .collect();

    if component_ids.is_empty() {
        return Vec::new();
    }
    component_ids.sort_unstable();
    let starting_with = |prefix: &str| {
        let run = &component_ids[component_ids.partition_point(|id| *id < prefix)..];
        run[..run.partition_point(|id| id.starts_with(prefix))].to_vec()
    };

    // Collect all trait references from composite rules
    let mut referenced_ids: HashSet<String> = HashSet::new();

    for rule in composite_rules {
        // Check all:, any:, unless: clauses
        for conditions in [rule.all.as_ref(), rule.any.as_ref(), rule.unless.as_ref()]
            .into_iter()
            .flatten()
        {
            for condition in conditions {
                for id in condition.trait_references() {
                    // Handle both specific references (with ::) and directory references
                    if id.contains("::") {
                        referenced_ids.insert(id.clone());
                    } else {
                        // Directory reference - mark all traits in that directory as referenced
                        for component_id in starting_with(id.trim_end_matches('/')) {
                            if directory_covers(id, component_id) {
                                referenced_ids.insert(component_id.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Also check unless: and downgrade: conditions
        if let Some(unless_conditions) = &rule.unless {
            for condition in unless_conditions {
                for id in condition.trait_references() {
                    if id.contains("::") {
                        referenced_ids.insert(id.clone());
                    } else {
                        for component_id in starting_with(id.trim_end_matches('/')) {
                            if directory_covers(id, component_id) {
                                referenced_ids.insert(component_id.to_string());
                            }
                        }
                    }
                }
            }
        }

        if let Some(downgrade) = &rule.downgrade {
            for conditions in [downgrade.any.as_ref(), downgrade.all.as_ref()]
                .into_iter()
                .flatten()
            {
                for condition in conditions {
                    for id in condition.trait_references() {
                        if id.contains("::") {
                            referenced_ids.insert(id.clone());
                        } else {
                            let prefix = format!("{}::", id);
                            for component_id in starting_with(&prefix) {
                                referenced_ids.insert(component_id.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Collect trait references from atomic traits (if: id: form)
    for trait_def in trait_definitions {
        for id in trait_def.r#if.trait_references() {
            if id.contains("::") {
                referenced_ids.insert(id.clone());
            } else if id.contains('/') {
                // Directory reference
                let prefix = format!("{}::", id);
                for component_id in starting_with(&prefix) {
                    referenced_ids.insert(component_id.to_string());
                }
            }
        }

        // Also check unless: and downgrade: conditions on atomic traits
        if let Some(unless_conditions) = &trait_def.unless {
            for condition in unless_conditions {
                for id in condition.trait_references() {
                    if id.contains("::") {
                        referenced_ids.insert(id.clone());
                    } else {
                        for component_id in starting_with(id.trim_end_matches('/')) {
                            if directory_covers(id, component_id) {
                                referenced_ids.insert(component_id.to_string());
                            }
                        }
                    }
                }
            }
        }

        if let Some(downgrade) = &trait_def.downgrade {
            for conditions in [downgrade.any.as_ref(), downgrade.all.as_ref()]
                .into_iter()
                .flatten()
            {
                for condition in conditions {
                    for id in condition.trait_references() {
                        if id.contains("::") {
                            referenced_ids.insert(id.clone());
                        } else {
                            let prefix = format!("{}::", id);
                            for component_id in starting_with(&prefix) {
                                referenced_ids.insert(component_id.to_string());
                            }
                        }
                    }
                }
            }
        }
    }

    // Find orphaned components (not in referenced set)
    let mut orphans: Vec<(String, String)> = component_ids
        .into_iter()
        .filter(|id| !referenced_ids.contains(*id))
        .map(|id| {
            let source = trait_source_files
                .get(id)
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            (id.to_string(), source)
        })
        .collect();

    // Sort for deterministic output
    orphans.sort_by(|a, b| a.0.cmp(&b.0));

    orphans
}
