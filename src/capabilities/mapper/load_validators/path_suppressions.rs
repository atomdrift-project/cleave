//! Bound suppressions that can be triggered on the scanned path alone.
use super::{Report, ValidationInput, enabled, report};
use crate::composite_rules::condition::Condition;
use crate::composite_rules::{CompositeTrait, DowngradeConditions};
use crate::types::Criticality;
use std::collections::{HashMap, HashSet};

const MAX_PATH_EXCLUSIONS: usize = 1;
const MAX_PATH_DOWNGRADES: usize = 8;

#[derive(Default)]
struct PathOnly<'a> {
    ids: HashSet<String>,
    atomic: HashSet<String>,
    directories: HashMap<String, HashSet<String>>,
    directories_with_exceptions: HashMap<String, HashSet<String>>,
    short_names: HashMap<String, HashSet<String>>,
    composites: HashMap<&'a str, &'a CompositeTrait>,
}

impl<'a> PathOnly<'a> {
    fn path_condition(condition: &Condition) -> bool {
        match condition {
            Condition::Path(_) => true,
            Condition::Kv(q) => matches!(
                q.path.as_str(),
                "file.basename" | "file.filename" | "file.path" | "file.stem" | "file.extension"
            ),
            _ => false,
        }
    }
    fn insert(&mut self, id: &str, crit: Criticality) -> bool {
        if !self.ids.insert(id.to_owned()) {
            return false;
        }
        let Some((directory, name)) = id.split_once("::") else {
            return true;
        };
        self.short_names
            .entry(name.to_owned())
            .or_default()
            .insert(id.to_owned());
        for prefix in directory
            .match_indices('/')
            .map(|(offset, _)| &directory[..offset])
            .chain(std::iter::once(directory))
        {
            self.directories_with_exceptions
                .entry(prefix.to_owned())
                .or_default()
                .insert(id.to_owned());
            if crit != Criticality::Exception {
                self.directories
                    .entry(prefix.to_owned())
                    .or_default()
                    .insert(id.to_owned());
            }
        }
        true
    }
    fn weight(&self, condition: &Condition, parent_exception: bool) -> usize {
        match condition {
            c if Self::path_condition(c) => 1,
            Condition::Trait { id } if id.contains("::") => usize::from(self.ids.contains(id)),
            Condition::Trait { id } if id.contains('/') => {
                let dirs = if parent_exception {
                    &self.directories_with_exceptions
                } else {
                    &self.directories
                };
                dirs.get(id.trim_end_matches('/')).map_or(0, HashSet::len)
            }
            Condition::Trait { id } => self.short_names.get(id).map_or(0, HashSet::len),
            _ => 0,
        }
    }
    fn clauses(
        &self,
        all: Option<&Vec<Condition>>,
        any: Option<&Vec<Condition>>,
        needs: Option<usize>,
        parent_exception: bool,
    ) -> bool {
        let all = all.map(Vec::as_slice).unwrap_or_default();
        let any = any.map(Vec::as_slice).unwrap_or_default();
        (!all.is_empty() || !any.is_empty())
            && all.iter().all(|c| self.weight(c, parent_exception) > 0)
            && (any.is_empty()
                || any
                    .iter()
                    .map(|c| self.weight(c, parent_exception))
                    .sum::<usize>()
                    >= needs.unwrap_or(1))
    }
    fn collect_id(&self, id: &str, out: &mut HashSet<String>, visited: &mut HashSet<String>) {
        if !self.ids.contains(id) || !visited.insert(id.to_owned()) {
            return;
        }
        if self.atomic.contains(id) {
            out.insert(id.to_owned());
            return;
        }
        if let Some(rule) = self.composites.get(id) {
            for cond in rule.all.iter().flatten().chain(rule.any.iter().flatten()) {
                self.collect(cond, rule.crit == Criticality::Exception, out, visited);
            }
        }
    }
    fn collect(
        &self,
        condition: &Condition,
        parent_exception: bool,
        out: &mut HashSet<String>,
        visited: &mut HashSet<String>,
    ) {
        if Self::path_condition(condition) {
            out.insert(format!("inline:{condition:?}"));
            return;
        }
        let Condition::Trait { id } = condition else {
            return;
        };
        if id.contains("::") {
            self.collect_id(id, out, visited);
        } else if id.contains('/') {
            let dirs = if parent_exception {
                &self.directories_with_exceptions
            } else {
                &self.directories
            };
            if let Some(ids) = dirs.get(id.trim_end_matches('/')) {
                for id in ids {
                    self.collect_id(id, out, visited);
                }
            }
        } else if let Some(ids) = self.short_names.get(id) {
            for id in ids {
                self.collect_id(id, out, visited);
            }
        }
    }
    fn count<'b>(
        &self,
        conditions: impl IntoIterator<Item = &'b Condition>,
        parent_exception: bool,
    ) -> usize {
        let mut out = HashSet::new();
        let mut visited = HashSet::new();
        for condition in conditions {
            self.collect(condition, parent_exception, &mut out, &mut visited);
        }
        out.len()
    }
}

pub(super) fn path_only_suppressions<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    if !enabled("path-only-suppression") {
        return report(|_| {});
    }
    let mut paths = PathOnly {
        composites: input
            .composite_rules
            .iter()
            .map(|r| (r.id.as_str(), r))
            .collect(),
        ..Default::default()
    };
    for rule in input.trait_definitions {
        if PathOnly::path_condition(&rule.r#if) {
            paths.atomic.insert(rule.id.clone());
            paths.insert(&rule.id, rule.crit);
        }
    }
    loop {
        let mut changed = false;
        for rule in input.composite_rules {
            if !paths.ids.contains(&rule.id)
                && paths.clauses(
                    rule.all.as_ref(),
                    rule.any.as_ref(),
                    rule.needs,
                    rule.crit == Criticality::Exception,
                )
            {
                changed |= paths.insert(&rule.id, rule.crit);
            }
        }
        if !changed {
            break;
        }
    }
    let mut violations = Vec::new();
    let mut check = |id: &str,
                     crit: Criticality,
                     unless: Option<&Vec<Condition>>,
                     downgrade: Option<&DowngradeConditions>| {
        let parent_exception = crit == Criticality::Exception;
        if let Some(conditions) = unless {
            let count = paths.count(conditions.iter(), parent_exception);
            if count > MAX_PATH_EXCLUSIONS {
                violations.push((id.to_owned(), "unless", count, MAX_PATH_EXCLUSIONS));
            }
        }
        if let Some(d) = downgrade {
            let count = paths.count(
                d.all.iter().flatten().chain(d.any.iter().flatten()),
                parent_exception,
            );
            if count > MAX_PATH_DOWNGRADES {
                violations.push((id.to_owned(), "downgrade", count, MAX_PATH_DOWNGRADES));
            }
        }
    };
    for r in input.trait_definitions {
        check(&r.id, r.crit, r.unless.as_ref(), r.downgrade.as_ref());
    }
    for r in input.composite_rules {
        check(&r.id, r.crit, r.unless.as_ref(), r.downgrade.as_ref());
    }
    violations.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));
    report(move |warnings| {
        if violations.is_empty() {
            return;
        }
        let rules = violations
            .iter()
            .map(|v| &v.0)
            .collect::<HashSet<_>>()
            .len();
        eprintln!(
            "\n❌ ERROR: {} filename-based suppressions exceed their limits in {rules} rules",
            violations.len()
        );
        eprintln!(
            "   Each unless: permits at most {MAX_PATH_EXCLUSIONS} filename/path-only trait; each downgrade: at most {MAX_PATH_DOWNGRADES}."
        );
        eprintln!(
            "   Counts expand directory and path-only composite references; duplicate facts count once.\n"
        );
        for (id, role, count, limit) in &violations {
            let source = input
                .rule_source_files
                .get(id)
                .map(String::as_str)
                .unwrap_or("unknown");
            eprintln!(
                "   {source}: '{id}' {role} references {count} path-only traits (limit {limit})"
            );
        }
        warnings.push_id(
            "path-only-suppression",
            format!(
                "{} filename-based suppressions exceed their limits in {rules} rules",
                violations.len()
            ),
        );
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composite_rules::{PathQuery, TraitDefinition};
    #[test]
    fn counts_unique_path_facts_through_directories_and_composites() {
        let first = TraitDefinition {
            id: "metadata/path::one".into(),
            r#if: Condition::Path(PathQuery {
                basename: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let second = TraitDefinition {
            id: "metadata/path::two".into(),
            r#if: Condition::Path(PathQuery {
                dirname: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let wrapper = CompositeTrait {
            id: "metadata/context::path-choice".into(),
            any: Some(vec![
                Condition::Trait {
                    id: first.id.clone(),
                },
                Condition::Trait {
                    id: second.id.clone(),
                },
            ]),
            ..Default::default()
        };
        let mut paths = PathOnly::default();
        paths.atomic.extend([first.id.clone(), second.id.clone()]);
        paths.insert(&first.id, first.crit);
        paths.insert(&second.id, second.crit);
        paths.composites.insert(&wrapper.id, &wrapper);
        paths.insert(&wrapper.id, wrapper.crit);
        let inputs = vec![
            Condition::Trait {
                id: wrapper.id.clone(),
            },
            Condition::Trait {
                id: "metadata/path/".into(),
            },
            Condition::Trait {
                id: first.id.clone(),
            },
        ];
        assert_eq!(paths.count(inputs.iter(), false), 2);
        assert_eq!(paths.count(inputs[..1].iter(), false), 2);
    }
    #[test]
    fn composite_requiring_content_is_not_path_only() {
        let mut paths = PathOnly::default();
        let path_id = "metadata/path::one";
        paths.atomic.insert(path_id.to_owned());
        paths.insert(path_id, Criticality::Notable);
        let all = vec![
            Condition::Trait {
                id: path_id.to_owned(),
            },
            Condition::Text(crate::composite_rules::TextQuery {
                substr: Some("content".into()),
                ..Default::default()
            }),
        ];
        assert!(!paths.clauses(Some(&all), None, None, false));
    }
    #[test]
    fn path_limits_count_distinct_facts() {
        let mut paths = PathOnly::default();
        let mut conditions = Vec::new();
        for i in 0..9 {
            let id = format!("metadata/path::item-{i}");
            paths.atomic.insert(id.clone());
            paths.insert(&id, Criticality::Notable);
            conditions.push(Condition::Trait { id });
        }
        assert_eq!(
            paths.count(conditions[..1].iter(), false),
            MAX_PATH_EXCLUSIONS
        );
        assert!(paths.count(conditions[..2].iter(), false) > MAX_PATH_EXCLUSIONS);
        assert_eq!(
            paths.count(conditions[..8].iter(), false),
            MAX_PATH_DOWNGRADES
        );
        assert!(paths.count(conditions.iter(), false) > MAX_PATH_DOWNGRADES);
    }
}
