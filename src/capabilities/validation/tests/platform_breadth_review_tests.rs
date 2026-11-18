use crate::capabilities::validation::find_broad_platform_traits;
use crate::composite_rules::{Platform, TraitDefinition};
use std::collections::HashMap;

#[test]
fn reviewed_platform_scope_requires_directory_and_platform_set() {
    let scope = vec![
        Platform::Ios,
        Platform::MacOS,
        Platform::Linux,
        Platform::Windows,
        Platform::Android,
    ];
    let mut traits = vec![TraitDefinition {
        id: "micro-behaviors/hardware/wireless/network::wifi-ssid-identifier".to_string(),
        platforms: scope.clone(),
        ..Default::default()
    }];
    assert!(find_broad_platform_traits(&traits, &HashMap::new()).is_empty());
    traits[0].platforms.reverse();
    assert!(find_broad_platform_traits(&traits, &HashMap::new()).is_empty());
    traits[0].platforms.push(Platform::Zos);
    assert_eq!(
        find_broad_platform_traits(&traits, &HashMap::new()).len(),
        1
    );
    traits[0].platforms = scope;
    traits[0].id = "micro-behaviors/fs/read/file::other-api".to_string();
    assert_eq!(
        find_broad_platform_traits(&traits, &HashMap::new()).len(),
        1
    );
}

#[test]
fn platform_review_has_one_threshold_outside_reviewed_directories() {
    let mut traits = Vec::new();
    let mut sources = HashMap::new();
    for directory in [
        "metadata/package/documentation/claims",
        "metadata/registry/description",
        "objectives/supply-chain/impersonation",
        "micro-behaviors/process/create",
        "well-known/tool/example",
    ] {
        for count in [3, 4] {
            let id = format!("{directory}::scope-{count}");
            sources.insert(id.clone(), format!("traits/{directory}/traits.yaml"));
            traits.push(TraitDefinition {
                id,
                platforms: vec![
                    Platform::Unix,
                    Platform::Windows,
                    Platform::Android,
                    Platform::Ios,
                ][..count]
                    .to_vec(),
                ..Default::default()
            });
        }
    }
    // All is checked by the directory-contract validator, not by the
    // enumerated platform-count reviewer.
    traits.push(TraitDefinition {
        id: "metadata/registry::platform-neutral".to_string(),
        platforms: vec![Platform::All],
        ..Default::default()
    });
    let reviews = find_broad_platform_traits(&traits, &sources);
    assert_eq!(reviews.len(), 5);
    assert!(
        reviews
            .iter()
            .all(|(id, _, count)| id.ends_with("::scope-4") && *count == 4)
    );
    traits.reverse();
    assert_eq!(reviews, find_broad_platform_traits(&traits, &sources));
}

#[test]
fn browser_scope_review_inherits_within_directory_boundaries() {
    let scope = vec![
        Platform::Unix,
        Platform::Windows,
        Platform::Android,
        Platform::Ios,
    ];
    for directory in [
        "objectives/exfiltration/oob/callback",
        "objectives/exfiltration/oob/callback/http-get",
        "objectives/exfiltration/oob/oast",
        "objectives/impact/degrade/process",
        "objectives/impact/degrade/process/browser",
        "objectives/impact/degrade/browser-access",
        "objectives/exfiltration/oob/tunnel",
    ] {
        let atom = TraitDefinition {
            id: format!("{directory}::future-observation"),
            platforms: scope.clone(),
            ..Default::default()
        };
        assert!(
            find_broad_platform_traits(std::slice::from_ref(&atom), &HashMap::new()).is_empty()
        );
        let mut expanded = atom;
        expanded.platforms.push(Platform::Zos);
        assert_eq!(
            find_broad_platform_traits(&[expanded], &HashMap::new()).len(),
            1
        );
    }
    for directory in [
        "objectives/exfiltration/oob-extra",
        "objectives/exfiltration/http",
        "objectives/impact/degrade-extra",
        "objectives/impact/destroy",
    ] {
        let atom = TraitDefinition {
            id: format!("{directory}::unreviewed-observation"),
            platforms: scope.clone(),
            ..Default::default()
        };
        assert_eq!(
            find_broad_platform_traits(&[atom], &HashMap::new()).len(),
            1
        );
    }
}
