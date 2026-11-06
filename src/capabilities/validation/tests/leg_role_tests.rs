use crate::capabilities::validation::{LegRole, find_dead_any_alternatives, find_legs_outside_for};
use crate::composite_rules::condition::TextQuery;
use crate::composite_rules::{
    Arch, CompositeTrait, Condition, FileType, Platform, Scope, TraitDefinition,
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

fn refs(ids: &[&str]) -> Vec<Condition> {
    ids.iter()
        .map(|i| Condition::Trait { id: i.to_string() })
        .collect()
}

fn comp(types: Vec<FileType>) -> CompositeTrait {
    CompositeTrait {
        id: "t::rule".to_string(),
        desc: "comp".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        r#for: types,
        scope: Some(Scope::Package),
        platforms: vec![Platform::Unix],
        arch: vec![Arch::All],
        defined_in: PathBuf::from("t.yml"),
        ..Default::default()
    }
}

/// An `unless:` leg outside `for:` does NOT kill the rule -- it kills the
/// carve-out, so the rule keeps firing where the author excluded it. That
/// costs false positives rather than detections, which is the opposite
/// urgency from a dead `all:` leg, so it is reported with its own role.
///
/// Found by review of the live tree: `readme-clone-foreign-npm-links`
/// suppresses on `archive-cargo-toml-entry` (`for: [tar, crate]`) while the
/// rule itself was narrowed to `[npm]`.
#[test]
fn a_suppressor_leg_outside_for_is_reported_as_a_false_positive_risk() {
    let traits = vec![
        leg("t::manifest", vec![FileType::PackageJson]),
        leg("t::cargo", vec![FileType::Tar, FileType::Crate]),
    ];
    let mut rule = comp(vec![FileType::Npm, FileType::PackageJson]);
    rule.all = Some(refs(&["t::manifest"]));
    rule.unless = Some(refs(&["t::cargo"]));

    let found = find_legs_outside_for(&traits, &[rule]);
    assert_eq!(found.len(), 1, "the suppressor leg must be reported");
    assert_eq!(found[0].role, LegRole::Suppressor);
    assert_eq!(found[0].leg, "t::cargo");
}

/// A directory leg stands for the union of the definitions under it --
/// subdirectories included, a sibling that shares its name as a prefix
/// not -- so it is outside `for:` only when all of those are. The union
/// is reported in id order, so the message is the same on every run.
#[test]
fn a_directory_leg_is_the_union_of_its_own_definitions() {
    let traits = vec![
        leg("t/dir::a", vec![FileType::Tar]),
        leg("t/dir/sub::b", vec![FileType::Crate]),
        leg("t/dirx::c", vec![FileType::PackageJson]),
    ];
    let mut rule = comp(vec![FileType::PackageJson]);
    rule.all = Some(refs(&["t/dir"]));

    let found = find_legs_outside_for(&traits, &[rule]);
    assert_eq!(found.len(), 1, "the directory leg must be reported");
    assert_eq!(found[0].role, LegRole::Required);
    // `t/dir/sub::b` sorts before `t/dir::a`.
    assert_eq!(found[0].leg_types, [FileType::Crate, FileType::Tar]);
}

/// One reachable `any:` branch is enough, so a partially-excluded `any:`
/// clause is working as written and must stay silent -- otherwise the
/// validator buries its real findings in noise.
#[test]
fn a_partially_reachable_any_clause_is_silent() {
    let traits = vec![
        leg("t::js", vec![FileType::JavaScript]),
        leg("t::elf", vec![FileType::Elf]),
    ];
    let mut rule = comp(vec![FileType::Npm, FileType::JavaScript]);
    rule.any = Some(refs(&["t::js", "t::elf"]));
    assert!(find_legs_outside_for(&traits, &[rule]).is_empty());
}

/// The same clause is still worth a warning: its ELF branch is dead code.
/// A release-zip correlator with `for: [zip, tar, go]` fired on source
/// tarballs through its Go branch and never on the ELF it was written for.
#[test]
fn a_dead_any_alternative_is_warned_per_leg() {
    let traits = vec![
        leg("t::js", vec![FileType::JavaScript]),
        leg("t::elf", vec![FileType::Elf]),
    ];
    let mut rule = comp(vec![FileType::Npm, FileType::JavaScript]);
    rule.any = Some(refs(&["t::js", "t::elf"]));

    let found = find_dead_any_alternatives(&traits, std::slice::from_ref(&rule));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].role, LegRole::DeadAlternative);
    assert_eq!(found[0].leg, "t::elf");

    rule.r#for.push(FileType::Elf);
    assert!(find_dead_any_alternatives(&traits, &[rule]).is_empty());
}

/// When every alternative is excluded the clause can never be satisfied,
/// so the rule is dead and is reported once for the clause, not per leg.
#[test]
fn an_entirely_excluded_any_clause_is_reported_once() {
    let traits = vec![
        leg("t::elf", vec![FileType::Elf]),
        leg("t::macho", vec![FileType::Macho]),
    ];
    let mut rule = comp(vec![FileType::Npm, FileType::JavaScript]);
    rule.any = Some(refs(&["t::elf", "t::macho"]));

    let found = find_legs_outside_for(&traits, &[rule]);
    assert_eq!(found.len(), 1, "one finding per dead clause, not per leg");
    assert_eq!(found[0].role, LegRole::EveryAlternative);
}

/// An `all:` leg keeps its own role, so the message can say "can never
/// fire" rather than the suppressor wording.
#[test]
fn a_required_leg_keeps_the_required_role() {
    let traits = vec![leg("t::js", vec![FileType::JavaScript])];
    let mut rule = comp(vec![FileType::Npm]);
    rule.all = Some(refs(&["t::js"]));

    let found = find_legs_outside_for(&traits, &[rule]);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].role, LegRole::Required);
}
