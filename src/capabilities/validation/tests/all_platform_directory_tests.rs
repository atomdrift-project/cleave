use crate::capabilities::validation::find_all_platform_rules_outside_allowlist;
use crate::composite_rules::{CompositeTrait, Platform, TraitDefinition};
use std::collections::HashMap;

#[test]
fn all_scope_checks_atoms_and_composites_with_directory_boundaries() {
    let make_trait = |id: &str, platforms: Vec<Platform>| TraitDefinition {
        id: id.to_string(),
        platforms,
        ..Default::default()
    };
    let traits = vec![
        make_trait("metadata/registry::age", vec![Platform::All]),
        make_trait(
            "metadata/package/documentation/source::readme",
            vec![Platform::All],
        ),
        make_trait(
            "micro-behaviors/communications/url/host/nested::syntax",
            vec![Platform::All],
        ),
        make_trait("metadata/filename::readme-basename", vec![Platform::All]),
        make_trait("metadata/filename/subdir::shape", vec![Platform::All]),
        make_trait("metadata/filename-impostor::shape", vec![Platform::All]),
        make_trait("metadata/registry-impostor::age", vec![Platform::All]),
        make_trait("well-known/lib/crypto/ece::api", vec![Platform::All]),
        make_trait(
            "micro-behaviors/ui/controls/credential::wifi",
            vec![Platform::Linux],
        ),
        make_trait("age", vec![Platform::All]),
    ];
    let rules = vec![
        CompositeTrait {
            id: "metadata/file/profile/source-indications::alternatives".to_string(),
            platforms: vec![Platform::All],
            ..Default::default()
        },
        CompositeTrait {
            id: "metadata/file/profile/source-indications-impostor::alternatives".to_string(),
            platforms: vec![Platform::All],
            ..Default::default()
        },
        CompositeTrait {
            id: "metadata/registry::withdrawal".to_string(),
            platforms: vec![Platform::All],
            ..Default::default()
        },
        CompositeTrait {
            id: "objectives/supply-chain/security-hold::registry-security-held-package".into(),
            platforms: vec![Platform::All],
            ..Default::default()
        },
        CompositeTrait {
            id: "objectives/supply-chain/security-hold-impostor::entry".into(),
            platforms: vec![Platform::All],
            ..Default::default()
        },
        CompositeTrait {
            id: "objectives/persistence/login::entry".to_string(),
            platforms: vec![Platform::All],
            ..Default::default()
        },
    ];
    // A misleading source path cannot grant permission to a canonical ID.
    let sources = HashMap::from([(
        "well-known/lib/crypto/ece::api".to_string(),
        "/tmp/metadata/registry/fake.yaml".to_string(),
    )]);
    let found = find_all_platform_rules_outside_allowlist(&traits, &rules, &sources);
    let ids: Vec<_> = found.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "age",
            "metadata/file/profile/source-indications-impostor::alternatives",
            "metadata/filename-impostor::shape",
            "metadata/registry-impostor::age",
            "objectives/persistence/login::entry",
            "objectives/supply-chain/security-hold-impostor::entry",
            "well-known/lib/crypto/ece::api",
        ]
    );
    assert_eq!(found.last().unwrap().1, "/tmp/metadata/registry/fake.yaml");
}
