use crate::capabilities::validation::find_legs_outside_for;
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

fn comp(id: &str, types: Vec<FileType>, scope: Option<Scope>, legs: Vec<&str>) -> CompositeTrait {
    CompositeTrait {
        id: id.to_string(),
        desc: "comp".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        r#for: types,
        scope,
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

fn path_leg(id: &str, types: Vec<FileType>) -> TraitDefinition {
    TraitDefinition {
        r#if: Condition::Path(crate::composite_rules::condition::PathQuery {
            basename: true,
            exact: Some("package.json".to_string()),
            ..Default::default()
        }),
        ..leg(id, types)
    }
}

/// A `type: path` leg is not subject to the origin filter at all:
/// `evaluate_basename_traits_for_entries` runs every path trait against
/// the archive's entry list with no `for:` gate, and the finding is
/// stamped with the *container's* type. So a rule naming only its
/// container really can satisfy it, and flagging it is a false positive.
/// `runtime-shipped-without-publish-manifest` is the live shape: its
/// `unless: npm-publish-root-manifest` (`for: [package.json]`,
/// `type: path`) does fire on the npm node.
#[test]
fn a_path_leg_is_not_subject_to_the_origin_filter() {
    let legs = vec![path_leg("t::manifest", vec![FileType::PackageJson])];
    let rule = comp(
        "t::npm-rule",
        vec![FileType::Npm],
        Some(Scope::Archive),
        vec!["t::manifest"],
    );
    assert!(find_legs_outside_for(&legs, &[rule]).is_empty());
}

/// ...but a content leg in the same position stays reported, because that
/// one really is filtered by origin.
#[test]
fn a_content_leg_in_the_same_position_is_still_reported() {
    let legs = vec![leg("t::script", vec![FileType::JavaScript])];
    let rule = comp(
        "t::npm-rule",
        vec![FileType::Npm],
        Some(Scope::Archive),
        vec!["t::script"],
    );
    assert_eq!(find_legs_outside_for(&legs, &[rule]).len(), 1);
}

/// The `vscode-activated-curl-shell` shape: a rule naming only its
/// container, whose legs live in members. Before the origin filter this
/// rule was satisfied by any member at all; now it is dead, and the fix is
/// to say which members it is about.
#[test]
fn a_container_only_for_with_member_legs_is_flagged() {
    let traits = vec![
        leg("t::manifest", vec![FileType::Json]),
        leg("t::script", vec![FileType::JavaScript]),
    ];
    let rule = comp(
        "t::vsix-rule",
        vec![FileType::VsixArchive],
        Some(Scope::Archive),
        vec!["t::manifest", "t::script"],
    );
    let bad = find_legs_outside_for(&traits, &[rule]);
    assert_eq!(bad.len(), 2, "both member legs are outside for:");
    // The message has to name the types to add, or the author is left
    // guessing which of 127 file types the leg wanted.
    assert_eq!(bad[0].leg_types, vec![FileType::Json]);
    assert_eq!(bad[1].leg_types, vec![FileType::JavaScript]);
}

/// Declaring the member types is the fix.
#[test]
fn declaring_the_member_types_clears_it() {
    let traits = vec![
        leg("t::manifest", vec![FileType::Json]),
        leg("t::script", vec![FileType::JavaScript]),
    ];
    let rule = comp(
        "t::vsix-rule",
        vec![FileType::VsixArchive, FileType::Json, FileType::JavaScript],
        Some(Scope::Archive),
        vec!["t::manifest", "t::script"],
    );
    assert!(find_legs_outside_for(&traits, &[rule]).is_empty());
}

/// A leg only needs *one* of its types declared: a trait that fires on
/// javascript or typescript is satisfiable by a rule that names only
/// javascript, and `for:` is allowed to be stricter than its children.
#[test]
fn one_overlapping_type_is_enough() {
    let traits = vec![leg(
        "t::script",
        vec![FileType::JavaScript, FileType::TypeScript],
    )];
    let rule = comp(
        "t::rule",
        vec![FileType::Npm, FileType::JavaScript],
        Some(Scope::Package),
        vec!["t::script"],
    );
    assert!(find_legs_outside_for(&traits, &[rule]).is_empty());
}

/// File-scoped composites match within one node; they are
/// `find_impossible_composite_filetypes`'s business, not this check's.
#[test]
fn file_scoped_composites_are_not_this_checks_business() {
    let traits = vec![leg("t::script", vec![FileType::JavaScript])];
    let rule = comp(
        "t::rule",
        vec![FileType::PackageJson],
        Some(Scope::File),
        vec!["t::script"],
    );
    assert!(find_legs_outside_for(&traits, &[rule]).is_empty());
}

/// `for: [all]` opts out of the origin filter, so it cannot exclude
/// anything; a leg declared `for: [all]` fires anywhere, so it is never
/// excluded. Neither is a mistake.
#[test]
fn all_on_either_side_is_exempt() {
    let traits = vec![leg("t::anywhere", vec![FileType::All])];
    let rule = comp(
        "t::rule",
        vec![FileType::Npm],
        Some(Scope::Package),
        vec!["t::anywhere"],
    );
    assert!(find_legs_outside_for(&traits, &[rule]).is_empty());

    let traits2 = vec![leg("t::script", vec![FileType::JavaScript])];
    let rule2 = comp(
        "t::rule2",
        vec![FileType::All],
        Some(Scope::Package),
        vec!["t::script"],
    );
    assert!(find_legs_outside_for(&traits2, &[rule2]).is_empty());
}

/// A directory reference resolves to every definition under it, so the
/// union of their types is what must overlap -- one member is enough.
#[test]
fn a_directory_reference_unions_its_members_types() {
    let traits = vec![
        leg("objectives/exfil/http::a", vec![FileType::Python]),
        leg("objectives/exfil/http::b", vec![FileType::JavaScript]),
    ];
    let ok = comp(
        "t::ok",
        vec![FileType::Npm, FileType::JavaScript],
        Some(Scope::Package),
        vec!["objectives/exfil/http/"],
    );
    assert!(find_legs_outside_for(&traits, &[ok]).is_empty());

    let bad = comp(
        "t::bad",
        vec![FileType::Npm, FileType::Elf],
        Some(Scope::Package),
        vec!["objectives/exfil/http/"],
    );
    assert_eq!(find_legs_outside_for(&traits, &[bad]).len(), 1);
}

/// An unresolvable leg proves nothing -- dangling references are a
/// different validator's error, and reporting them here would send the
/// author to the wrong fix.
#[test]
fn an_unresolvable_leg_is_ignored() {
    let traits = vec![leg("t::script", vec![FileType::JavaScript])];
    let rule = comp(
        "t::rule",
        vec![FileType::Npm, FileType::JavaScript],
        Some(Scope::Package),
        vec!["t::script", "t::nowhere"],
    );
    assert!(find_legs_outside_for(&traits, &[rule]).is_empty());
}

/// The default scope counts: `for: [npm]` with no `scope:` is
/// package-scoped, so its legs are filtered and this check applies.
#[test]
fn the_default_scope_brings_a_rule_into_scope() {
    let traits = vec![leg("t::script", vec![FileType::JavaScript])];
    let rule = comp("t::rule", vec![FileType::Npm], None, vec!["t::script"]);
    assert_eq!(
        find_legs_outside_for(&traits, &[rule]).len(),
        1,
        "for: [npm] defaults to package scope, so the filter applies"
    );
}

#[test]
fn the_validator_id_is_registered() {
    assert!(
        crate::validation_controls::validator_spec("leg-outside-for").is_some(),
        "leg-outside-for must be in VALIDATOR_SPECS"
    );
}
