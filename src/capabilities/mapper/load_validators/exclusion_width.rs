//! Limit the distinct rules a suppression can select, including directory members.
use super::{Report, ValidationInput, enabled, report};
use crate::composite_rules::condition::Condition;
use crate::composite_rules::{CompositeTrait, DowngradeConditions, TraitDefinition};
use crate::types::Criticality;
use std::collections::{HashMap, HashSet};

const MAX_EXCLUSION_RULES: usize = 64;
const MAX_DOWNGRADE_RULES: usize = 256;

struct Audit<'a> {
    composites: HashMap<&'a str, &'a CompositeTrait>,
    rules: HashSet<&'a str>,
    by_short_name: HashMap<&'a str, Vec<&'a str>>,
    directories: HashMap<String, Vec<&'a str>>,
    directories_with_exceptions: HashMap<String, Vec<&'a str>>,
}

impl<'a> Audit<'a> {
    fn new(traits: &'a [TraitDefinition], composites: &'a [CompositeTrait]) -> Self {
        let mut audit = Self {
            composites: composites
                .iter()
                .map(|rule| (rule.id.as_str(), rule))
                .collect(),
            rules: HashSet::new(),
            by_short_name: HashMap::new(),
            directories: HashMap::new(),
            directories_with_exceptions: HashMap::new(),
        };
        for (id, crit) in traits
            .iter()
            .map(|r| (r.id.as_str(), r.crit))
            .chain(composites.iter().map(|r| (r.id.as_str(), r.crit)))
        {
            audit.rules.insert(id);
            let Some((dir, name)) = id.split_once("::") else {
                continue;
            };
            audit.by_short_name.entry(name).or_default().push(id);
            for prefix in dir
                .match_indices('/')
                .map(|(index, _)| &dir[..index])
                .chain(std::iter::once(dir))
            {
                audit
                    .directories_with_exceptions
                    .entry(prefix.to_owned())
                    .or_default()
                    .push(id);
                if crit != Criticality::Exception {
                    audit
                        .directories
                        .entry(prefix.to_owned())
                        .or_default()
                        .push(id);
                }
            }
        }
        audit
    }

    fn expand_rule(
        &self,
        id: &'a str,
        selected: &mut HashSet<String>,
        visited: &mut HashSet<&'a str>,
    ) {
        selected.insert(id.to_owned());
        if !visited.insert(id) {
            return;
        }
        if let Some(rule) = self.composites.get(id) {
            for conditions in [rule.all.as_ref(), rule.any.as_ref()].into_iter().flatten() {
                self.expand(
                    conditions,
                    rule.crit == Criticality::Exception,
                    selected,
                    visited,
                );
            }
        }
    }

    fn expand(
        &self,
        conditions: &[Condition],
        parent_exception: bool,
        selected: &mut HashSet<String>,
        visited: &mut HashSet<&'a str>,
    ) {
        for condition in conditions {
            match condition {
                Condition::Trait { id } if id.contains('/') && !id.contains("::") => {
                    let table = if parent_exception {
                        &self.directories_with_exceptions
                    } else {
                        &self.directories
                    };
                    if let Some(members) = table.get(id.trim_end_matches('/')) {
                        // A directory selects its members directly. Do not expand
                        // each member's own evidence: it is not selected by the prefix.
                        selected.extend(members.iter().map(|member| (*member).to_owned()));
                    }
                }
                Condition::Trait { id } if id.contains("::") => {
                    if let Some(&resolved) = self.rules.get(id.as_str()) {
                        self.expand_rule(resolved, selected, visited);
                    }
                }
                Condition::Trait { id } => {
                    if let Some(matches) = self.by_short_name.get(id.as_str()) {
                        for &resolved in matches {
                            self.expand_rule(resolved, selected, visited);
                        }
                    }
                }
                // An inline condition is one additional suppression predicate.
                other => {
                    selected.insert(format!("inline:{other:?}"));
                }
            }
        }
    }

    fn count(
        &self,
        conditions: impl IntoIterator<Item = &'a Condition>,
        parent_exception: bool,
    ) -> usize {
        let conditions: Vec<Condition> = conditions.into_iter().cloned().collect();
        let mut selected = HashSet::new();
        self.expand(
            &conditions,
            parent_exception,
            &mut selected,
            &mut HashSet::new(),
        );
        selected.len()
    }
}

#[derive(Debug)]
struct Violation {
    rule: String,
    role: &'static str,
    count: usize,
    limit: usize,
}

pub(super) fn exclusion_directory_width<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    if !enabled("exclusion-directory-width") {
        return report(|_| {});
    }
    let audit = Audit::new(input.trait_definitions, input.composite_rules);
    let mut violations = Vec::new();
    let mut check = |id: &str,
                     crit: Criticality,
                     unless: Option<&'a Vec<Condition>>,
                     downgrade: Option<&'a DowngradeConditions>| {
        if let Some(conditions) = unless {
            let count = audit.count(conditions.iter(), crit == Criticality::Exception);
            if count > MAX_EXCLUSION_RULES {
                violations.push(Violation {
                    rule: id.to_owned(),
                    role: "unless",
                    count,
                    limit: MAX_EXCLUSION_RULES,
                });
            }
        }
        if let Some(d) = downgrade {
            let count = audit.count(
                d.all.iter().flatten().chain(d.any.iter().flatten()),
                crit == Criticality::Exception,
            );
            if count > MAX_DOWNGRADE_RULES {
                violations.push(Violation {
                    rule: id.to_owned(),
                    role: "downgrade",
                    count,
                    limit: MAX_DOWNGRADE_RULES,
                });
            }
        }
    };
    for r in input.trait_definitions {
        check(&r.id, r.crit, r.unless.as_ref(), r.downgrade.as_ref());
    }
    for r in input.composite_rules {
        check(&r.id, r.crit, r.unless.as_ref(), r.downgrade.as_ref());
    }
    violations.sort_by(|a, b| (&a.rule, a.role).cmp(&(&b.rule, b.role)));
    report(move |warnings| {
        if violations.is_empty() {
            return;
        }
        let rules = violations
            .iter()
            .map(|v| &v.rule)
            .collect::<HashSet<_>>()
            .len();
        eprintln!(
            "\n❌ ERROR: {} expanded suppressions exceed their rule limits in {rules} rules",
            violations.len()
        );
        eprintln!(
            "   Each unless: may select at most {MAX_EXCLUSION_RULES} distinct rules; each downgrade: at most {MAX_DOWNGRADE_RULES}."
        );
        eprintln!(
            "   Counts include directory members, referenced composites and inline predicates; duplicate references count once.\n"
        );
        for v in &violations {
            let source = input
                .rule_source_files
                .get(&v.rule)
                .map(String::as_str)
                .unwrap_or("unknown");
            eprintln!(
                "   {source}: '{}' {} expands to {} rules (limit {})",
                v.rule, v.role, v.count, v.limit
            );
        }
        warnings.push_id(
            "exclusion-directory-width",
            format!(
                "{} expanded suppressions exceed their limits in {rules} rules",
                violations.len()
            ),
        );
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expanded_limits_count_unique_members_and_follow_composites() {
        let traits: Vec<TraitDefinition> = (0..257)
            .map(|i| TraitDefinition {
                id: format!("metadata/wide/child::item-{i}"),
                ..Default::default()
            })
            .collect();
        let composite = CompositeTrait {
            id: "metadata/wrapper::context".into(),
            any: Some(vec![Condition::Trait {
                id: "metadata/wide/".into(),
            }]),
            ..Default::default()
        };
        let composites = vec![composite];
        let reference = Condition::Trait {
            id: "metadata/wide/".into(),
        };
        let duplicate = vec![reference.clone(), reference];
        let audit = Audit::new(&traits, &composites);
        assert_eq!(audit.count(duplicate.iter(), false), 257);
        let exact = vec![Condition::Trait {
            id: "metadata/wrapper::context".into(),
        }];
        assert_eq!(audit.count(exact.iter(), false), 258);
        assert_eq!(
            Audit::new(&traits[..64], &composites).count(duplicate.iter(), false),
            MAX_EXCLUSION_RULES
        );
        assert_eq!(
            Audit::new(&traits[..256], &composites).count(duplicate.iter(), false),
            MAX_DOWNGRADE_RULES
        );
    }
    #[test]
    fn directories_exclude_exception_members_unless_parent_is_exception() {
        let traits = vec![TraitDefinition {
            id: "metadata/example::normal".into(),
            crit: Criticality::Notable,
            ..Default::default()
        }];
        let composites = vec![CompositeTrait {
            id: "metadata/example::suppressor".into(),
            crit: Criticality::Exception,
            ..Default::default()
        }];
        let audit = Audit::new(&traits, &composites);
        let reference = vec![Condition::Trait {
            id: "metadata/example/".into(),
        }];
        assert_eq!(audit.count(reference.iter(), false), 1);
        assert_eq!(audit.count(reference.iter(), true), 2);
    }
}
