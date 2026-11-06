use crate::capabilities::validation::find_dead_composites;
use crate::composite_rules::{
    Arch, CompositeTrait, Condition, FileType, Platform, Scope, TextQuery, TraitDefinition,
};
use std::path::PathBuf;

fn leg(id: &str, types: Vec<FileType>) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "leg".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        r#if: Condition::Text(TextQuery {
            substr: Some("X".to_string()),
            ..Default::default()
        }),
        r#for: types,
        platforms: vec![Platform::Unix],
        arch: vec![Arch::All],
        defined_in: PathBuf::from("t.yml"),
        ..Default::default()
    }
}

fn comp(id: &str, types: Vec<FileType>, legs: Vec<&str>) -> CompositeTrait {
    CompositeTrait {
        id: id.to_string(),
        desc: "comp".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        r#for: types,
        platforms: vec![Platform::Unix],
        arch: vec![Arch::All],
        all: Some(
            legs.into_iter()
                .map(|l| Condition::Trait { id: l.to_string() })
                .collect(),
        ),
        defined_in: PathBuf::from("t.yml"),
        ..Default::default()
    }
}

#[test]
fn a_composite_whose_every_declared_type_is_unreachable_is_dead() {
    // The `lua-http-post-request` shape: two Lua legs, but the composite
    // inherited a file default that never mentions Lua, so it could not
    // fire anywhere.
    let traits = vec![
        leg("t::lua-a", vec![FileType::Lua]),
        leg("t::lua-b", vec![FileType::Lua]),
    ];
    let comps = vec![comp(
        "t::lua-rule",
        vec![FileType::Python, FileType::Shell],
        vec!["t::lua-a", "t::lua-b"],
    )];
    assert_eq!(find_dead_composites(&traits, &comps), vec!["t::lua-rule"]);
}

#[test]
fn a_composite_with_one_reachable_type_is_not_dead() {
    let traits = vec![leg("t::lua-a", vec![FileType::Lua])];
    let comps = vec![comp(
        "t::mixed",
        vec![FileType::Python, FileType::Lua],
        vec!["t::lua-a"],
    )];
    assert!(find_dead_composites(&traits, &comps).is_empty());
}

#[test]
fn a_container_type_keeps_a_pooling_composite_alive() {
    // On an archive the legs arrive as inherited member findings, so a
    // declared container type is always reachable and the rule is not dead.
    let traits = vec![leg("t::js", vec![FileType::JavaScript])];
    let comps = vec![comp("t::pkg", vec![FileType::Npm], vec!["t::js"])];
    assert!(find_dead_composites(&traits, &comps).is_empty());
}

#[test]
fn a_pooling_scope_keeps_a_non_archive_container_alive() {
    // A self-extracting PE (PyInstaller onefile) pools its extracted
    // members' findings under `scope: outer`/`archive`/`package` the same
    // way an archive-tagged container does, even though `Pe` itself
    // carries no `#[archive]` marker. `pyinstaller-pyarmor-xor-sidecar-
    // stage` (for: [pe], scope: outer) requiring a Python-only leg is the
    // real-world shape this covers.
    let traits = vec![leg("t::py", vec![FileType::Python])];
    let mut rule = comp("t::pyinstaller", vec![FileType::Pe], vec!["t::py"]);
    rule.scope = Some(Scope::Outer);
    assert!(find_dead_composites(&traits, &[rule]).is_empty());
}
