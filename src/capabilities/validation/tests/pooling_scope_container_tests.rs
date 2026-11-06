use crate::capabilities::validation::find_pooling_scope_without_container;
use crate::composite_rules::{Arch, CompositeTrait, Condition, FileType, Platform, Scope};
use std::path::PathBuf;

fn comp(id: &str, types: Vec<FileType>, scope: Option<Scope>) -> CompositeTrait {
    CompositeTrait {
        id: id.to_string(),
        desc: "comp".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        r#for: types,
        scope,
        platforms: vec![Platform::Unix],
        arch: vec![Arch::All],
        all: Some(vec![Condition::Trait {
            id: "t::leg".to_string(),
        }]),
        defined_in: PathBuf::from("t.yml"),
        ..Default::default()
    }
}

/// MSI, OLE compound documents and OOXML hold more than one stream and
/// cleave pools their members' findings (the office analyser calls
/// `evaluate_container_composites` exactly as the archive analyser does).
/// They carry no `#[archive]` marker only because the *archive* analyser
/// is not what opens them. Without this, `find_impossible_composite_filetypes`
/// and this check deadlock: the first tells an MSI rule to declare its
/// container and take a pooling scope, and this one then rejects it.
#[test]
fn office_and_installer_containers_satisfy_the_pooling_requirement() {
    for ft in [FileType::Msi, FileType::OleDoc, FileType::Ooxml] {
        for scope in [Scope::Archive, Scope::Package, Scope::Outer] {
            let rule = comp("t::office", vec![ft], Some(scope));
            assert!(
                find_pooling_scope_without_container(&[rule]).is_empty(),
                "{ft:?} at {scope:?} is a container and must be accepted"
            );
        }
    }
}

/// The dead shape: pooling scopes are evaluated on the container node, so a
/// leaf-only `for:` means the rule is never handed a node it declared.
#[test]
fn a_leaf_only_for_with_a_pooling_scope_is_flagged() {
    for scope in [Scope::Archive, Scope::Package, Scope::Outer] {
        let rule = comp("t::bad", vec![FileType::JavaScript], Some(scope));
        let bad = find_pooling_scope_without_container(&[rule]);
        assert_eq!(bad.len(), 1, "scope {scope:?} should be flagged");
        assert_eq!(bad[0].0, "t::bad");
    }
}

/// Naming the container is the fix -- and the member types may stay in the
/// list, since `for:` also says what evidence may be mixed in.
#[test]
fn naming_a_container_clears_it() {
    let rule = comp(
        "t::ok",
        vec![FileType::Npm, FileType::JavaScript],
        Some(Scope::Package),
    );
    assert!(find_pooling_scope_without_container(&[rule]).is_empty());
}

/// `registry` is the container for `scope: outer` -- the synthetic
/// artifact↔registry node is typed `registry` -- but it is not an archive,
/// so it does not license `archive`/`package`.
#[test]
fn registry_is_a_container_only_for_outer() {
    let ok = comp(
        "t::ok",
        vec![FileType::Registry, FileType::JavaScript],
        Some(Scope::Outer),
    );
    assert!(find_pooling_scope_without_container(&[ok]).is_empty());

    for scope in [Scope::Archive, Scope::Package] {
        let bad = comp("t::bad", vec![FileType::Registry], Some(scope));
        assert_eq!(
            find_pooling_scope_without_container(&[bad]).len(),
            1,
            "registry is not an archive ancestor, so scope {scope:?} cannot bind"
        );
    }
}

/// The default scope counts: `for: [npm]` with no `scope:` resolves to
/// `package`, and `for: [javascript]` to `file`. Neither is a violation,
/// but the check must read `effective_scope`, not the raw field.
#[test]
fn the_default_scope_is_evaluated_not_the_raw_field() {
    assert!(
        find_pooling_scope_without_container(&[comp("t::ok-npm", vec![FileType::Npm], None)])
            .is_empty()
    );
    assert!(
        find_pooling_scope_without_container(&[comp("t::ok-js", vec![FileType::JavaScript], None)])
            .is_empty()
    );
    // ...and a registry default (outer) is satisfied by registry itself.
    assert!(
        find_pooling_scope_without_container(&[comp("t::ok-reg", vec![FileType::Registry], None)])
            .is_empty()
    );
}

/// File-scoped composites run per node and are none of this check's
/// business, whatever they declare.
#[test]
fn file_and_leaf_scopes_are_exempt() {
    for scope in [Scope::File, Scope::Leaf] {
        let rule = comp("t::ok", vec![FileType::JavaScript], Some(scope));
        assert!(find_pooling_scope_without_container(&[rule]).is_empty());
    }
}

/// `for: [all]` runs everywhere by definition, and a group-derived list is
/// not what the author wrote -- neither is evidence of a mistake.
#[test]
fn all_and_group_derived_lists_are_exempt() {
    let rule = comp("t::ok", vec![FileType::All], Some(Scope::Archive));
    assert!(find_pooling_scope_without_container(&[rule]).is_empty());

    let mut grouped = comp("t::ok2", vec![FileType::JavaScript], Some(Scope::Archive));
    grouped.for_from_groups = true;
    assert!(find_pooling_scope_without_container(&[grouped]).is_empty());
}

#[test]
fn the_validator_id_is_registered() {
    assert!(
        crate::validation_controls::validator_spec("pooling-scope-no-container").is_some(),
        "pooling-scope-no-container must be in VALIDATOR_SPECS"
    );
}

/// `Pe` is the established non-archive exception -- same precedent as
/// `find_dead_composites`'s `a_pooling_scope_keeps_a_non_archive_container_alive`.
/// A self-extracting PE (PyInstaller onefile) pools its children the same
/// way an archive does without carrying the `#[archive]` marker; the live
/// shape is `known-nondeployed-filename-context` (`for: [pe]`,
/// `scope: outer`), joining a PE's own version-resource fact with an
/// identity marker that may live in an embedded MSI/CAB member.
#[test]
fn pe_is_an_accepted_non_archive_pooling_container() {
    for scope in [Scope::Outer, Scope::Archive, Scope::Package] {
        let rule = comp("t::pe-pool", vec![FileType::Pe], Some(scope));
        assert!(
            find_pooling_scope_without_container(&[rule]).is_empty(),
            "scope {scope:?} with for: [pe] must not be flagged"
        );
    }
}
