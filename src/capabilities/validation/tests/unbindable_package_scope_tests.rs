use crate::capabilities::validation::find_scope_without_valid_container;
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

fn comp(id: &str, types: Vec<FileType>, legs: Vec<&str>) -> CompositeTrait {
    CompositeTrait {
        id: id.to_string(),
        desc: "comp".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        r#for: types,
        scope: Some(Scope::Package),
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

/// Shape 1: `for: [registry]` names the one node type no package archive
/// can contain. This is the live `fresh-package-outbound-exfil-channel`
/// family in the trait tree -- ten rules under
/// `objectives/supply-chain/...` that all want `scope: outer`.
#[test]
fn registry_only_for_is_flagged() {
    let traits = vec![leg("t::reg", vec![FileType::Registry])];
    let rule = comp("t::bad", vec![FileType::Registry], vec!["t::reg"]);
    let bad = find_scope_without_valid_container(&traits, &[rule]);
    assert_eq!(bad.len(), 1);
    assert_eq!(bad[0].id, "t::bad");
    assert!(
        bad[0].reason.contains("registry nodes"),
        "unexpected reason: {}",
        bad[0].reason
    );
}

/// Shape 2: `for:` is fine, but the required legs straddle the boundary --
/// a registry-only leg can never share a package key with a leg that only
/// ever fires on a real file. This is `removed-inflated-node-hook`
/// (`for:` defaulted to `all`, so shape 1 misses it).
#[test]
fn registry_leg_mixed_with_a_file_leg_is_flagged() {
    let traits = vec![
        leg("t::reg", vec![FileType::Registry]),
        leg("t::manifest", vec![FileType::PackageJson]),
    ];
    let rule = comp("t::bad", vec![FileType::All], vec!["t::reg", "t::manifest"]);
    let bad = find_scope_without_valid_container(&traits, &[rule]);
    assert_eq!(bad.len(), 1);
    assert!(
        bad[0].reason.contains("t::reg") && bad[0].reason.contains("t::manifest"),
        "reason should name both legs, got: {}",
        bad[0].reason
    );
}

/// A registry-only leg resolved through a *composite* counts the same --
/// `removed-inflated-node-hook`'s registry leg is itself a composite.
#[test]
fn a_registry_only_composite_leg_counts() {
    let traits = vec![leg("t::manifest", vec![FileType::PackageJson])];
    let mut registry_comp = comp("t::reg-comp", vec![FileType::Registry], vec!["t::none"]);
    registry_comp.scope = None;
    let rule = comp(
        "t::bad",
        vec![FileType::All],
        vec!["t::reg-comp", "t::manifest"],
    );
    let bad = find_scope_without_valid_container(&traits, &[registry_comp, rule]);
    assert_eq!(bad.len(), 1);
    assert_eq!(bad[0].id, "t::bad");
}

/// A bare same-directory leg name resolves against the rule's own
/// directory, the way the loader resolves it -- otherwise shape 2 is blind
/// to the most common way legs are written.
#[test]
fn bare_same_directory_leg_names_resolve() {
    let traits = vec![
        leg("t::reg", vec![FileType::Registry]),
        leg("t::manifest", vec![FileType::PackageJson]),
    ];
    let rule = comp("t::bad", vec![FileType::All], vec!["reg", "manifest"]);
    assert_eq!(
        find_scope_without_valid_container(&traits, &[rule]).len(),
        1
    );
}

/// All legs on the registry side pool fine: every key is the empty string,
/// so the rule still fires. Pointless, but not broken -- and a validator
/// that cannot distinguish the two is the one that gets disabled.
#[test]
fn an_all_registry_composite_is_not_flagged() {
    let traits = vec![
        leg("t::reg-a", vec![FileType::Registry]),
        leg("t::reg-b", vec![FileType::Registry]),
    ];
    let rule = comp("t::ok", vec![FileType::All], vec!["t::reg-a", "t::reg-b"]);
    assert!(find_scope_without_valid_container(&traits, &[rule]).is_empty());
}

/// The canonical, correct use: a leaf file inside an npm tarball pooling
/// with its manifest. Flagging this was the false positive that got the
/// previous, broader version of this validator pulled.
#[test]
fn a_leaf_type_inside_a_package_is_never_flagged() {
    let traits = vec![
        leg("t::js", vec![FileType::JavaScript]),
        leg("t::manifest", vec![FileType::PackageJson]),
    ];
    let rule = comp(
        "t::ok",
        vec![FileType::JavaScript, FileType::TypeScript],
        vec!["t::js", "t::manifest"],
    );
    assert!(find_scope_without_valid_container(&traits, &[rule]).is_empty());
}

/// A plain container type degrades to `scope: file` when nothing packages
/// it, which is harmless -- and a `.zip` nested in an npm tarball binds
/// for real. Not our business either way.
#[test]
fn a_non_package_archive_type_is_not_flagged() {
    let traits = vec![leg("t::js", vec![FileType::JavaScript])];
    let rule = comp("t::ok", vec![FileType::Zip], vec!["t::js"]);
    assert!(find_scope_without_valid_container(&traits, &[rule]).is_empty());
}

/// An unresolvable leg, a directory reference, and a leg that runs on both
/// registry and file nodes all prove nothing. This check fires on
/// certainty only.
#[test]
fn unprovable_legs_are_left_alone() {
    let traits = vec![
        leg("t::reg", vec![FileType::Registry]),
        leg("t::both", vec![FileType::Registry, FileType::PackageJson]),
    ];

    let dangling = comp("t::a", vec![FileType::All], vec!["t::reg", "t::nowhere"]);
    assert!(find_scope_without_valid_container(&traits, &[dangling]).is_empty());

    let dir_ref = comp(
        "t::b",
        vec![FileType::All],
        vec!["t::reg", "metadata/package/"],
    );
    assert!(find_scope_without_valid_container(&traits, &[dir_ref]).is_empty());

    let ambiguous = comp("t::c", vec![FileType::All], vec!["t::reg", "t::both"]);
    assert!(find_scope_without_valid_container(&traits, &[ambiguous]).is_empty());
}

/// Only an explicit `scope: package` is checked. The `for:`-derived
/// default is the engine's own choice (`CompositeTrait::default_scope`)
/// and cannot be wrong in this way, and every other scope is out of
/// bounds -- `outer` is the fix this validator recommends.
#[test]
fn other_scopes_and_the_default_are_exempt() {
    let traits = vec![
        leg("t::reg", vec![FileType::Registry]),
        leg("t::manifest", vec![FileType::PackageJson]),
    ];
    for scope in [
        None,
        Some(Scope::Outer),
        Some(Scope::Archive),
        Some(Scope::File),
    ] {
        let mut rule = comp(
            "t::ok",
            vec![FileType::Registry],
            vec!["t::reg", "t::manifest"],
        );
        rule.scope = scope;
        assert!(
            find_scope_without_valid_container(&traits, &[rule]).is_empty(),
            "scope {scope:?} must not be flagged"
        );
    }
}

/// A composite with no `all:` legs cannot be proven broken by shape 2, and
/// a non-registry `for:` keeps shape 1 quiet.
#[test]
fn a_composite_without_required_legs_is_exempt() {
    let traits = vec![leg("t::reg", vec![FileType::Registry])];
    let mut rule = comp("t::ok", vec![FileType::Npm], vec![]);
    rule.all = None;
    rule.any = Some(vec![Condition::Trait {
        id: "t::reg".to_string(),
    }]);
    assert!(find_scope_without_valid_container(&traits, &[rule]).is_empty());
}

/// The validator is registered, so `--disable-validator` can name it and
/// its findings carry a real label instead of the `unknown` fallback.
#[test]
fn the_validator_id_is_registered() {
    assert!(
        crate::validation_controls::validator_spec("unbindable-package-scope").is_some(),
        "unbindable-package-scope must be in VALIDATOR_SPECS"
    );
    assert!(
        crate::validation_controls::validator_spec("exhaustive-suppressor").is_some(),
        "exhaustive-suppressor must be in VALIDATOR_SPECS"
    );
    assert!(
        crate::validation_controls::validator_spec("leg-suppression").is_some(),
        "leg-suppression must be in VALIDATOR_SPECS"
    );
}
