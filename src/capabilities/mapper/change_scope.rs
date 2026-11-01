//! Which file types each rule file can influence, for `cleave validate` to
//! decide which fixtures an edit can have changed.
//!
//! A rule produces findings only on files whose type its `for:` admits, so a
//! fixture holding no file of those types cannot change verdict when the rule
//! does. That covers the rules that reference the edited one too: a composite
//! leg, an `unless:` or a downgrade changes its mind only where the edited
//! rule's own findings changed, on that file or on a sibling member of the
//! same fixture, and the fixture holds that file's type. The scope of a rule
//! file is therefore the union of its rules' admitted types. Every
//! approximation here widens the scope, never narrows it: a rule without
//! `for:` applies everywhere, and a composite without `for:` applies wherever
//! any of its positive legs can.

use super::CapabilityMapper;
use crate::composite_rules::{FileType, TypeMask};
use rustc_hash::FxHashMap;
use std::collections::BTreeMap;
use std::path::Path;

/// A rule file path as the scope map keys it: from its rule source directory
/// (`objectives/...`, `metadata/...`) on, with `/` separators. `defined_in`
/// carries whatever prefix the traits directory was named by on the command
/// line; the snapshot's relative paths carry none.
#[must_use]
pub(crate) fn scope_key(path: &Path) -> String {
    // Scope keys accept either separator regardless of the host OS. On Unix,
    // `Path::components` otherwise treats backslashes as ordinary characters.
    let normalized = path.to_string_lossy().replace('\\', "/");
    let parts: Vec<String> = Path::new(&normalized)
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let start = parts
        .iter()
        .position(|part| crate::traits_repo::RULE_SOURCE_DIRS.contains(&part.as_str()))
        .unwrap_or(0);
    parts[start..].join("/")
}

impl CapabilityMapper {
    /// The types each rule file can influence: for every file, the union of
    /// its rules' admitted types.
    #[must_use]
    pub(crate) fn rule_file_scopes(&self) -> BTreeMap<String, TypeMask> {
        let concrete = FileType::all_concrete_variants();
        let mask_of = |r#for: &[FileType]| -> TypeMask {
            if r#for.is_empty() || r#for.contains(&FileType::All) {
                TypeMask::ALL
            } else {
                concrete
                    .iter()
                    .filter(|ft| FileType::rule_applies_to(r#for, **ft))
                    .fold(TypeMask::EMPTY, |acc, ft| acc | ft.type_bit())
            }
        };
        // Rules in one numbering: traits first, then composites.
        let traits = self.trait_definitions.len();
        let total = traits + self.composite_rules.len();
        let mut ids: Vec<&str> = Vec::with_capacity(total);
        let mut files: Vec<String> = Vec::with_capacity(total);
        for t in &self.trait_definitions {
            ids.push(&t.id);
            files.push(scope_key(&t.defined_in));
        }
        for c in &self.composite_rules {
            ids.push(&c.id);
            files.push(scope_key(&c.defined_in));
        }

        // Rules by id, by the directories their ids lie under, and by their
        // unqualified name, so a reference of any form resolves in one lookup.
        let mut by_id: FxHashMap<&str, Vec<usize>> = FxHashMap::default();
        let mut by_dir: FxHashMap<&str, Vec<usize>> = FxHashMap::default();
        let mut by_short: FxHashMap<&str, Vec<usize>> = FxHashMap::default();
        for (i, id) in ids.iter().enumerate() {
            by_id.entry(*id).or_default().push(i);
            let (dir, short) = match id.find("::") {
                Some(at) => (&id[..at], &id[at + 2..]),
                None => match id.rfind('/') {
                    Some(at) => (&id[..at], &id[at + 1..]),
                    None => ("", *id),
                },
            };
            by_short.entry(short).or_default().push(i);
            for (end, _) in dir.match_indices('/') {
                by_dir.entry(&dir[..end]).or_default().push(i);
            }
            if !dir.is_empty() {
                by_dir.entry(dir).or_default().push(i);
            }
        }
        // The rules a leg names: a rule id, a directory whose rules it all
        // means, or an unqualified name. One that names no loaded rule can
        // match nothing and resolves to no rule.
        let resolve = |target: &str| -> Vec<usize> {
            let target = target.trim_end_matches('/');
            [by_id.get(target), by_dir.get(target), by_short.get(target)]
                .into_iter()
                .flatten()
                .flat_map(|found| found.iter().copied())
                .collect()
        };
        fn conditions_of(
            conditions: Option<&Vec<crate::composite_rules::Condition>>,
        ) -> impl Iterator<Item = &crate::composite_rules::Condition> {
            conditions.into_iter().flatten()
        }

        // Each rule's own types. A trait's are what its `for:` admits. A
        // composite with a `for:` likewise; one without can still only fire
        // where a positive leg (`all:`/`any:`) fires, so its types are the
        // union of those legs': a referenced rule's types, or everything for
        // an inline condition. Composites reference composites, so this runs
        // to a fixpoint from nothing.
        let mut masks: Vec<TypeMask> = Vec::with_capacity(total);
        for t in &self.trait_definitions {
            masks.push(mask_of(&t.r#for));
        }
        let mut open_legs: Vec<Option<(bool, Vec<usize>)>> = Vec::with_capacity(total - traits);
        for c in &self.composite_rules {
            if c.r#for.is_empty() || c.r#for.contains(&FileType::All) {
                let mut inline = false;
                let mut targets = Vec::new();
                for condition in conditions_of(c.all.as_ref()).chain(conditions_of(c.any.as_ref()))
                {
                    let refs = condition.trait_references();
                    if refs.is_empty() {
                        inline = true;
                    }
                    for target in refs {
                        targets.extend(resolve(target));
                    }
                }
                if c.all.is_none() && c.any.is_none() {
                    inline = true;
                }
                open_legs.push(Some((inline, targets)));
                masks.push(if inline {
                    TypeMask::ALL
                } else {
                    TypeMask::EMPTY
                });
            } else {
                open_legs.push(None);
                masks.push(mask_of(&c.r#for));
            }
        }
        let mut changed = true;
        while changed {
            changed = false;
            for (j, legs) in open_legs.iter().enumerate() {
                let Some((false, targets)) = legs else {
                    continue;
                };
                let mut widened = masks[traits + j];
                for &t in targets {
                    widened |= masks[t];
                }
                if widened != masks[traits + j] {
                    masks[traits + j] = widened;
                    changed = true;
                }
            }
        }

        let scopes = masks;

        let mut by_file: BTreeMap<String, TypeMask> = BTreeMap::new();
        for (i, file) in files.into_iter().enumerate() {
            let entry = by_file.entry(file).or_insert(TypeMask::EMPTY);
            *entry |= scopes[i];
        }
        tracing::info!(
            rules = total,
            files = by_file.len(),
            everywhere = by_file.values().filter(|m| **m == TypeMask::ALL).count(),
            "rule file scopes"
        );
        by_file
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn scope_keys_are_root_relative_with_forward_slashes() {
        for (path, expected) in [
            (r".\objectives\a\b.yaml", "objectives/a/b.yaml"),
            ("./objectives/a/b.yaml", "objectives/a/b.yaml"),
            ("/repo/traits/objectives/a/b.yaml", "objectives/a/b.yaml"),
            (r"C:\repo\traits\objectives\a\b.yaml", "objectives/a/b.yaml"),
            (r"traits\objectives/a\b.yaml", "objectives/a/b.yaml"),
            (r"traits\metadata\a.yaml", "metadata/a.yaml"),
            ("./x/y.yaml", "x/y.yaml"),
            (r".\x\y.yaml", "x/y.yaml"),
            ("x/y.yaml", "x/y.yaml"),
            (r"x\y.yaml", "x/y.yaml"),
        ] {
            assert_eq!(scope_key(Path::new(path)), expected, "path: {path}");
        }
    }

    #[test]
    fn scopes_follow_for_lists_and_open_composites_follow_their_legs() {
        let mut mapper = CapabilityMapper::empty();
        let mut leg: crate::composite_rules::TraitDefinition = crate::yaml::from_str(
            "id: objectives/a::leg
desc: Leg
conf: 1.0
for: [javascript]
if:
  type: text
  substr: abc
",
        )
        .unwrap();
        leg.defined_in = "objectives/a/leg.yaml".into();
        let mut other: crate::composite_rules::TraitDefinition = crate::yaml::from_str(
            "id: objectives/b::other
desc: Other
conf: 1.0
for: [python]
if:
  type: text
  substr: def
",
        )
        .unwrap();
        other.defined_in = "objectives/b/other.yaml".into();
        mapper.trait_definitions.push(leg);
        mapper.trait_definitions.push(other);
        let mut composite: crate::composite_rules::CompositeTrait = crate::yaml::from_str(
            "id: objectives/c::both
desc: Both
conf: 1.0
for: [zip]
all:
  - id: objectives/a::leg
",
        )
        .unwrap();
        composite.defined_in = "objectives/c/both.yaml".into();
        mapper.composite_rules.push(composite);
        // No `for:`: wherever a positive leg can fire, so the legs' types.
        let mut open: crate::composite_rules::CompositeTrait = crate::yaml::from_str(
            "id: objectives/d::either
desc: Either
conf: 1.0
any:
  - id: objectives/a::leg
  - id: objectives/b/
",
        )
        .unwrap();
        open.defined_in = "objectives/d/either.yaml".into();
        mapper.composite_rules.push(open);
        // No `for:` and an inline leg: everywhere.
        let mut inline: crate::composite_rules::CompositeTrait = crate::yaml::from_str(
            "id: objectives/e::inline
desc: Inline
conf: 1.0
any:
  - id: objectives/a::leg
  - type: text
    substr: xyz
",
        )
        .unwrap();
        inline.defined_in = "objectives/e/inline.yaml".into();
        mapper.composite_rules.push(inline);

        let scopes = mapper.rule_file_scopes();
        let js = FileType::JavaScript.type_bit();
        let py = FileType::Python.type_bit();
        let zip = FileType::Zip.type_bit();
        // A referenced leg's scope is its own types: a composite that uses
        // it can only change where the leg's findings do.
        let leg_scope = scopes["objectives/a/leg.yaml"];
        assert!(
            leg_scope.intersects(js) && !leg_scope.intersects(zip) && !leg_scope.intersects(py)
        );
        let other_scope = scopes["objectives/b/other.yaml"];
        assert!(other_scope.intersects(py) && !other_scope.intersects(js));
        let both_scope = scopes["objectives/c/both.yaml"];
        assert!(both_scope.intersects(zip) && !both_scope.intersects(js));
        let either_scope = scopes["objectives/d/either.yaml"];
        assert!(either_scope.intersects(js) && either_scope.intersects(py));
        assert!(!either_scope.intersects(zip));
        assert_eq!(scopes["objectives/e/inline.yaml"], TypeMask::ALL);
    }
}
